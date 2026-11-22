//! Explicit authenticated delegated-use request retrieval and proof ingress.
//! Flow retains the original request-signing claim before external work. Only
//! this owner can turn its frozen Flow request into the retained request result;
//! proof storage never establishes proof validity or delegated authority.

#[path = "delegation_use_wallet.rs"]
mod wallet;
pub use wallet::delegated_use_wallet_router;

use std::{fmt, sync::Arc, time::Duration as Timeout};

use axum::{
    body::to_bytes,
    extract::{Path, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use marty_delegated_authority::{
    use_http::{AuthenticatedDelegationUseContext, DelegationUseHttpAuthenticator, UseHttpError},
    DelegationCommandCaller, DelegationUseCommandError, DelegationUseIngressAuthorizer,
    DelegationUseIngressOperation, VerifiedDelegationCommandAccess, MAX_DELEGATE_PROOF_BYTES,
};
use marty_verification::flow::FlowInstanceStatus;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool, Row};
use uuid::Uuid;

use crate::{
    delegation_challenge::challenge_from_records,
    delegation_start::validate_delegation_snapshot,
    delegation_use::same_delegated_authority_snapshot,
    postgres::{definition_from_row, instance_from_row},
    prepare_verification_request, FlowDefinitionRecord, FlowDelegatedProofSubmission,
    FlowInstanceRecord, FlowProviderRegistry, Oid4vpClientIdScheme, PostgresFlowRepository,
    PreparedVerificationRequest, RequestObjectCompatibility, RequestObjectOptions,
    RequestObjectTransport, VerificationRequestRetrievalOptions,
};

type Result<T> = std::result::Result<T, DelegationUseCommandError>;
const READ_TIMEOUT: Timeout = Timeout::from_secs(5);
const MAX_REQUEST_BYTES: usize = 65_536;

fn unavailable(_: impl fmt::Debug) -> DelegationUseCommandError {
    DelegationUseCommandError::Unavailable
}
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn precision(time: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp_micros(time.timestamp_micros()).expect("existing timestamp")
}
async fn database_now(connection: &mut PgConnection) -> Result<DateTime<Utc>> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(connection)
        .await
        .map_err(unavailable)
}
async fn bounded_transaction(pool: &PgPool) -> Result<sqlx::Transaction<'static, sqlx::Postgres>> {
    let mut transaction = tokio::time::timeout(READ_TIMEOUT, pool.begin())
        .await
        .map_err(unavailable)?
        .map_err(unavailable)?;
    sqlx::raw_sql("SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='5s'")
        .execute(&mut *transaction)
        .await
        .map_err(unavailable)?;
    Ok(transaction)
}
async fn commit(transaction: sqlx::Transaction<'static, sqlx::Postgres>) -> Result<()> {
    // Cancellation cannot be mistaken for rollback after COMMIT has begun. The
    // detached narrow commit creates no returned proof/result or signing retry.
    tokio::spawn(async move { transaction.commit().await })
        .await
        .map_err(unavailable)?
        .map_err(unavailable)
}

#[derive(Clone)]
struct Bounds {
    authentication_observed_at: DateTime<Utc>,
    authentication_valid_until: DateTime<Utc>,
    authorization_observed_at: DateTime<Utc>,
    authorization_valid_until: DateTime<Utc>,
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
}
impl Bounds {
    fn new(context: &AuthenticatedDelegationUseContext, now: DateTime<Utc>) -> Result<Self> {
        context
            .check(now)
            .map_err(|_| DelegationUseCommandError::AccessDenied)?;
        Ok(Self {
            authentication_observed_at: precision(context.observed_at()),
            authentication_valid_until: precision(context.valid_until()),
            authorization_observed_at: precision(now),
            authorization_valid_until: precision(now),
            observed_at: precision(context.observed_at()),
            valid_until: precision(context.valid_until()),
        })
    }
    fn check(&self, now: DateTime<Utc>) -> Result<()> {
        if now < self.observed_at || now >= self.valid_until {
            return Err(DelegationUseCommandError::Expired);
        }
        Ok(())
    }
    fn observe(
        &mut self,
        source: VerifiedDelegationCommandAccess,
        started: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<()> {
        // Validate the source before clamping to a shorter transport lifetime.
        if now < started
            || source.observed_at < started
            || source.observed_at > now
            || source.valid_until <= now
            || source
                .observed_at
                .checked_add_signed(Duration::seconds(30))
                .is_none_or(|limit| source.valid_until > limit)
        {
            return Err(DelegationUseCommandError::AccessDenied);
        }
        self.authorization_observed_at = precision(source.observed_at);
        self.authorization_valid_until = precision(source.valid_until);
        self.observed_at = self.observed_at.max(self.authorization_observed_at);
        self.valid_until = self.valid_until.min(self.authorization_valid_until);
        self.check(now)
    }
}

/// Current access to the exact original request. Its JWS and original Flow
/// expiry remain unchanged across authorized reads; access time is not a new
/// request issuance time. Debug deliberately excludes the request object.
#[derive(Clone, Serialize)]
pub struct FlowDelegatedUseRequest {
    pub challenge_id: Uuid,
    pub request_digest: String,
    pub request_expires_at: DateTime<Utc>,
    pub retained_at: DateTime<Utc>,
    pub recovered: bool,
    compact_request_jws: String,
}
impl FlowDelegatedUseRequest {
    pub fn compact_request_jws(&self) -> &str {
        &self.compact_request_jws
    }
}
impl fmt::Debug for FlowDelegatedUseRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlowDelegatedUseRequest")
            .field("challenge_id", &self.challenge_id)
            .field("request_digest", &self.request_digest)
            .field("recovered", &self.recovered)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct FlowDelegatedUseIngress {
    repository: PostgresFlowRepository,
    providers: FlowProviderRegistry,
    access: Arc<dyn DelegationUseIngressAuthorizer>,
    public_base_url: String,
    options: RequestObjectOptions,
    configuration_digest: String,
    storage_id: Uuid,
}

impl FlowDelegatedUseIngress {
    pub async fn new(
        repository: PostgresFlowRepository,
        providers: FlowProviderRegistry,
        access: Arc<dyn DelegationUseIngressAuthorizer>,
        public_base_url: String,
        options: RequestObjectOptions,
    ) -> Result<Self> {
        let base = url::Url::parse(&public_base_url).map_err(unavailable)?;
        if base.scheme() != "https"
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || public_base_url.ends_with('/')
            || options.client_id_scheme != Oid4vpClientIdScheme::DecentralizedIdentifier
            || options.compatibility != RequestObjectCompatibility::Standard
            || options.transport != RequestObjectTransport::RequestUri
            || options.wallet_nonce.is_some()
            || !options.expected_origins.is_empty()
            || options.x509_certificate_bundle.is_some()
        {
            return Err(DelegationUseCommandError::InvalidCommand);
        }
        let configuration_digest = digest(
            &serde_json::to_vec(&json!({
                "profile":"marty.flow/delegated-use-request-configuration/v1",
                "public_base_url":public_base_url,
                "verifier_client_id":options.verifier_client_id,
                "verifier_did_method":format!("{:?}",options.verifier_did_method),
                "strict_client_metadata":options.strict_client_metadata,
                "verifier_display_name":options.verifier_display_name,
                "verifier_logo_uri":options.verifier_logo_uri
            }))
            .map_err(unavailable)?,
        );
        let storage_id = sqlx::query_scalar(
            "SELECT storage_id FROM flow_service.delegated_use_storage_identity WHERE singleton",
        )
        .fetch_one(repository.pool())
        .await
        .map_err(unavailable)?;
        let value = Self {
            repository,
            providers,
            access,
            public_base_url,
            options,
            configuration_digest,
            storage_id,
        };
        value.readiness().await?;
        Ok(value)
    }

    pub async fn readiness(&self) -> Result<()> {
        tokio::time::timeout(READ_TIMEOUT, async {
            validate_delegated_use_ingress_schema(self.repository.pool()).await?;
            validate_ingress_role(self.repository.pool()).await
        })
        .await
        .map_err(unavailable)?
    }

    async fn authorize(
        &self,
        context: &AuthenticatedDelegationUseContext,
        challenge_id: Uuid,
        operation: DelegationUseIngressOperation,
        bounds: &mut Bounds,
    ) -> Result<()> {
        let started = Utc::now();
        bounds.check(started)?;
        let source = tokio::time::timeout(
            READ_TIMEOUT,
            self.access
                .authorize_ingress(context.caller(), challenge_id, operation, started),
        )
        .await
        .map_err(unavailable)??;
        bounds.observe(source, started, Utc::now())
    }

    async fn require_storage(&self, connection: &mut PgConnection) -> Result<()> {
        let actual: Uuid = sqlx::query_scalar(
            "SELECT storage_id FROM flow_service.delegated_use_storage_identity WHERE singleton",
        )
        .fetch_one(connection)
        .await
        .map_err(unavailable)?;
        if actual != self.storage_id {
            return Err(DelegationUseCommandError::Conflict);
        }
        Ok(())
    }

    async fn bound_instance(
        &self,
        connection: &mut PgConnection,
        caller: &DelegationCommandCaller,
        challenge_id: Uuid,
    ) -> Result<(FlowInstanceRecord, FlowDefinitionRecord)> {
        self.require_storage(connection).await?;
        // Definition precedes instance in the shared finalization lock order.
        let definition_row =
            sqlx::query("SELECT * FROM flow_service.lock_delegated_ingress_definition($1,$2)")
                .bind(caller.organization_id())
                .bind(challenge_id)
                .fetch_optional(&mut *connection)
                .await
                .map_err(unavailable)?
                .ok_or(DelegationUseCommandError::AccessDenied)?;
        let definition = definition_from_row(&definition_row).map_err(unavailable)?;
        let row=sqlx::query("SELECT f.*,b.instance_snapshot AS original_snapshot FROM flow_service.flow_instances f JOIN flow_service.delegated_challenge_bindings b ON b.challenge_id::TEXT=f.id AND b.organization_id::TEXT=f.organization_id WHERE f.id=$1 AND f.organization_id=$2 FOR UPDATE OF f")
            .bind(challenge_id.to_string()).bind(caller.organization_id().to_string())
            .fetch_optional(&mut *connection).await.map_err(unavailable)?
            .ok_or(DelegationUseCommandError::AccessDenied)?;
        let instance = instance_from_row(&row).map_err(unavailable)?;
        let original: FlowInstanceRecord =
            serde_json::from_value(row.try_get("original_snapshot").map_err(unavailable)?)
                .map_err(unavailable)?;
        let binding = validate_delegation_snapshot(&original).map_err(unavailable)?;
        if binding.binding.actor != *caller.actor()
            || binding.binding.organization_id != caller.organization_id()
            || original.flow_definition_id != definition.id
            || instance.flow_definition_id != definition.id
        {
            return Err(DelegationUseCommandError::AccessDenied);
        }
        // Terminal history remains available only through exact proof recovery;
        // all fresh request/proof paths additionally call require_active below.
        let current_binding = validate_delegation_snapshot(&instance).map_err(unavailable)?;
        if current_binding.binding != binding.binding
            || current_binding.nonce != binding.nonce
            || current_binding.verifier_client_id != binding.verifier_client_id
            || current_binding.expires_at != binding.expires_at
        {
            return Err(DelegationUseCommandError::Conflict);
        }
        if matches!(instance.status, FlowInstanceStatus::AwaitingWallet)
            && !same_delegated_authority_snapshot(&original, &instance)?
        {
            return Err(DelegationUseCommandError::Conflict);
        }
        Ok((instance, definition))
    }

    fn require_active(
        &self,
        instance: &FlowInstanceRecord,
        definition: &FlowDefinitionRecord,
        now: DateTime<Utc>,
        bounds: &mut Bounds,
    ) -> Result<()> {
        let original = validate_delegation_snapshot(instance).map_err(unavailable)?;
        let current = challenge_from_records(
            original.binding.organization_id,
            original.binding.grant_id,
            original.binding.challenge_id,
            instance,
            definition,
            now,
        )
        .map_err(unavailable)?;
        if instance.status != FlowInstanceStatus::AwaitingWallet
            || instance.completed_at.is_some()
            || instance.result.is_some()
            || instance.error.is_some()
            || instance.updated_at > now
            || instance.context["request_uri"].as_str()
                != Some(
                    format!(
                        "{}/v1/flows/instances/{}/request",
                        self.public_base_url, instance.id
                    )
                    .as_str(),
                )
        {
            return Err(DelegationUseCommandError::Conflict);
        }
        bounds.valid_until = bounds.valid_until.min(current.expires_at);
        bounds.observed_at = bounds.observed_at.max(instance.created_at);
        bounds.check(now)
    }

    pub async fn retrieve_request(
        &self,
        context: &AuthenticatedDelegationUseContext,
        challenge_id: Uuid,
    ) -> Result<FlowDelegatedUseRequest> {
        if challenge_id.is_nil() {
            return Err(DelegationUseCommandError::InvalidCommand);
        }
        let mut bounds = Bounds::new(context, Utc::now())?;
        self.readiness().await?;
        self.authorize(
            context,
            challenge_id,
            DelegationUseIngressOperation::RequestRead,
            &mut bounds,
        )
        .await?;
        let caller = context.caller();
        let mut tx = bounded_transaction(self.repository.pool()).await?;
        let (original, definition) = self.bound_instance(&mut tx, caller, challenge_id).await?;
        let now = database_now(&mut tx).await?;
        self.require_active(&original, &definition, now, &mut bounds)?;
        self.authorize(
            context,
            challenge_id,
            DelegationUseIngressOperation::RequestRead,
            &mut bounds,
        )
        .await?;
        bounds.check(database_now(&mut tx).await?)?;
        if let Some(row)=sqlx::query("SELECT request_bytes,request_digest,configuration_digest,recorded_at FROM flow_service.delegated_request_results WHERE challenge_id=$1 AND organization_id=$2")
            .bind(challenge_id).bind(caller.organization_id()).fetch_optional(&mut *tx).await.map_err(unavailable)? {
            if row.try_get::<String,_>("configuration_digest").map_err(unavailable)? != self.configuration_digest {
                return Err(DelegationUseCommandError::Conflict);
            }
            let bytes:Vec<u8>=row.try_get("request_bytes").map_err(unavailable)?;
            let request_digest:String=row.try_get("request_digest").map_err(unavailable)?;
            if digest(&bytes)!=request_digest { return Err(DelegationUseCommandError::Conflict); }
            let result=FlowDelegatedUseRequest { challenge_id,request_digest,
                request_expires_at:original.expires_at.ok_or(DelegationUseCommandError::Conflict)?,
                retained_at:row.try_get("recorded_at").map_err(unavailable)?,recovered:true,
                compact_request_jws:String::from_utf8(bytes).map_err(unavailable)? };
            commit(tx).await?;
            bounds.check(Utc::now())?;
            return Ok(result);
        }
        // No resumed, expired or recovered claim ever invokes the signer again.
        let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM flow_service.delegated_request_claims WHERE challenge_id=$1)")
            .bind(challenge_id).fetch_one(&mut *tx).await.map_err(unavailable)?;
        if pending {
            return Err(DelegationUseCommandError::PreparationPending);
        }
        if original
            .context
            .get("paired_wallet_signed_request_v1")
            .is_some()
        {
            return Err(DelegationUseCommandError::Conflict);
        }
        let actor_type = actor_type(caller)?;
        let claimed_at = database_now(&mut tx).await?;
        bounds.check(claimed_at)?;
        sqlx::query("INSERT INTO flow_service.delegated_request_claims (challenge_id,organization_id,actor_type,actor_id,configuration_digest,instance_snapshot,authentication_observed_at,authentication_valid_until,authorization_observed_at,authorization_valid_until,observed_at,valid_until,recorded_at) SELECT $1,$2,$3,$4,$5,to_jsonb(f),$6,$7,$8,$9,$10,$11,$12 FROM flow_service.flow_instances f WHERE f.id=$1::TEXT AND f.organization_id=$2::TEXT")
            .bind(challenge_id).bind(caller.organization_id()).bind(&actor_type).bind(&caller.actor().id)
            .bind(&self.configuration_digest).bind(bounds.authentication_observed_at).bind(bounds.authentication_valid_until)
            .bind(bounds.authorization_observed_at).bind(bounds.authorization_valid_until)
            .bind(bounds.observed_at).bind(bounds.valid_until).bind(claimed_at)
            .execute(&mut *tx).await.map_err(unavailable)?;
        commit(tx).await?;
        bounds.check(Utc::now())?;
        // Frozen query/nonce/verifier state goes through the existing Flow
        // request owner. Callers supply neither request claims nor signing data.
        let prepared = tokio::time::timeout(
            READ_TIMEOUT,
            prepare_verification_request(
                &self.providers,
                original.clone(),
                &self.public_base_url,
                &VerificationRequestRetrievalOptions {
                    request_object: self.options.clone(),
                    ..Default::default()
                },
                Utc::now(),
            ),
        )
        .await
        .map_err(unavailable)?
        .map_err(unavailable)?;
        let PreparedVerificationRequest::Ready(mut ready) = prepared else {
            return Err(DelegationUseCommandError::Expired);
        };
        bounds.check(Utc::now())?;
        if ready.compact_jwt.is_empty()
            || ready.compact_jwt.len() > MAX_REQUEST_BYTES
            || !same_delegated_authority_snapshot(&original, &ready.instance)?
        {
            return Err(DelegationUseCommandError::Conflict);
        }
        self.authorize(
            context,
            challenge_id,
            DelegationUseIngressOperation::RequestRead,
            &mut bounds,
        )
        .await?;
        let mut tx = bounded_transaction(self.repository.pool()).await?;
        let (current, current_definition) =
            self.bound_instance(&mut tx, caller, challenge_id).await?;
        // A concurrent ordinary writer cannot replace the newly signed request
        // snapshot. A conflict leaves its original claim unresolved.
        if serde_json::to_value(&current).map_err(unavailable)?
            != serde_json::to_value(&original).map_err(unavailable)?
            || current_definition != definition
        {
            return Err(DelegationUseCommandError::Conflict);
        }
        let now = database_now(&mut tx).await?;
        self.require_active(&current, &current_definition, now, &mut bounds)?;
        self.authorize(
            context,
            challenge_id,
            DelegationUseIngressOperation::RequestRead,
            &mut bounds,
        )
        .await?;
        let recorded_at = database_now(&mut tx).await?;
        bounds.check(recorded_at)?;
        ready.instance.updated_at = recorded_at;
        // Preserve all existing history and add only the existing owner's newly
        // prepared progress. This instance is still the exact locked preimage.
        sqlx::query("UPDATE flow_service.flow_instances SET current_step_id=$1,context=$2,step_history=$3,state_history=$4,updated_at=$5 WHERE id=$6 AND organization_id=$7")
            .bind(&ready.instance.current_step_id).bind(&ready.instance.context)
            .bind(json!(ready.instance.step_history)).bind(json!(ready.instance.state_history))
            .bind(recorded_at).bind(&ready.instance.id).bind(&ready.instance.organization_id)
            .execute(&mut *tx).await.map_err(unavailable)?;
        let request_digest = digest(ready.compact_jwt.as_bytes());
        sqlx::query("INSERT INTO flow_service.delegated_request_results (challenge_id,organization_id,actor_type,actor_id,configuration_digest,request_bytes,request_digest,instance_snapshot,authentication_observed_at,authentication_valid_until,authorization_observed_at,authorization_valid_until,observed_at,valid_until,recorded_at) SELECT $1,$2,$3,$4,$5,$6,$7,to_jsonb(f),$8,$9,$10,$11,$12,$13,$14 FROM flow_service.flow_instances f WHERE f.id=$1::TEXT AND f.organization_id=$2::TEXT")
            .bind(challenge_id).bind(caller.organization_id()).bind(&actor_type).bind(&caller.actor().id)
            .bind(&self.configuration_digest).bind(ready.compact_jwt.as_bytes()).bind(&request_digest)
            .bind(bounds.authentication_observed_at).bind(bounds.authentication_valid_until)
            .bind(bounds.authorization_observed_at).bind(bounds.authorization_valid_until)
            .bind(bounds.observed_at).bind(bounds.valid_until).bind(recorded_at)
            .execute(&mut *tx).await.map_err(unavailable)?;
        let bytes:Vec<u8>=sqlx::query_scalar("SELECT request_bytes FROM flow_service.delegated_request_results WHERE challenge_id=$1 AND organization_id=$2")
            .bind(challenge_id).bind(caller.organization_id()).fetch_one(&mut *tx).await.map_err(unavailable)?;
        if bytes != ready.compact_jwt.as_bytes() {
            return Err(DelegationUseCommandError::Conflict);
        }
        bounds.check(database_now(&mut tx).await?)?;
        commit(tx).await?;
        bounds.check(Utc::now())?;
        Ok(FlowDelegatedUseRequest {
            challenge_id,
            request_digest,
            request_expires_at: original
                .expires_at
                .ok_or(DelegationUseCommandError::Conflict)?,
            retained_at: recorded_at,
            recovered: false,
            compact_request_jws: ready.compact_jwt,
        })
    }

    pub async fn submit_proof(
        &self,
        context: &AuthenticatedDelegationUseContext,
        challenge_id: Uuid,
        proof: &[u8],
    ) -> Result<FlowDelegatedProofSubmission> {
        self.submit_input(context, challenge_id, wallet::ProofInput::Original(proof))
            .await
    }

    async fn submit_input(
        &self,
        context: &AuthenticatedDelegationUseContext,
        challenge_id: Uuid,
        input: wallet::ProofInput<'_>,
    ) -> Result<FlowDelegatedProofSubmission> {
        if challenge_id.is_nil() || !input.has_valid_size() {
            return Err(DelegationUseCommandError::InvalidCommand);
        }
        let mut bounds = Bounds::new(context, Utc::now())?;
        self.readiness().await?;
        self.authorize(
            context,
            challenge_id,
            DelegationUseIngressOperation::ProofSubmit,
            &mut bounds,
        )
        .await?;
        let caller = context.caller();
        let actor_type = actor_type(caller)?;
        let mut tx = bounded_transaction(self.repository.pool()).await?;
        let (current, definition) = self.bound_instance(&mut tx, caller, challenge_id).await?;
        bounds.check(database_now(&mut tx).await?)?;
        self.authorize(
            context,
            challenge_id,
            DelegationUseIngressOperation::ProofSubmit,
            &mut bounds,
        )
        .await?;
        bounds.check(database_now(&mut tx).await?)?;
        // Direct-post association uses this exact locked Flow and its retained
        // request. It cannot choose a query or race a second, unguarded read.
        let proof = match input {
            wallet::ProofInput::Original(bytes) => std::borrow::Cow::Borrowed(bytes),
            wallet::ProofInput::DirectPost(form) => {
                std::borrow::Cow::Owned(self.direct_post_proof(&mut tx, &current, &form).await?)
            }
        };
        let proof = proof.as_ref();
        let proof_digest = digest(proof);
        bounds.check(database_now(&mut tx).await?)?;
        if let Some(row)=sqlx::query("SELECT submission_id,received_at,proof,actor_type,actor_id FROM flow_service.delegated_proof_submissions WHERE challenge_id=$1 AND organization_id=$2 AND proof_digest=$3")
            .bind(challenge_id).bind(caller.organization_id()).bind(&proof_digest)
            .fetch_optional(&mut *tx).await.map_err(unavailable)? {
            if row.try_get::<Vec<u8>,_>("proof").map_err(unavailable)?!=proof
                || row.try_get::<String,_>("actor_type").map_err(unavailable)?!=actor_type
                || row.try_get::<String,_>("actor_id").map_err(unavailable)?!=caller.actor().id
            { return Err(DelegationUseCommandError::Conflict); }
            let result=FlowDelegatedProofSubmission { submission_id:row.try_get("submission_id").map_err(unavailable)?,
                challenge_id,proof_digest,received_at:row.try_get("received_at").map_err(unavailable)?,recovered:true };
            commit(tx).await?;
            bounds.check(Utc::now())?;
            return Ok(result);
        }
        let received_at = database_now(&mut tx).await?;
        self.require_active(&current, &definition, received_at, &mut bounds)?;
        let submission_id = Uuid::new_v4();
        sqlx::query("INSERT INTO flow_service.delegated_proof_submissions (submission_id,challenge_id,organization_id,actor_type,actor_id,proof,proof_digest,received_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(submission_id).bind(challenge_id).bind(caller.organization_id()).bind(&actor_type)
            .bind(&caller.actor().id).bind(proof).bind(&proof_digest).bind(received_at)
            .execute(&mut *tx).await.map_err(unavailable)?;
        let retained: Vec<u8> = sqlx::query_scalar(
            "SELECT proof FROM flow_service.delegated_proof_submissions WHERE submission_id=$1",
        )
        .bind(submission_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(unavailable)?;
        if retained != proof {
            return Err(DelegationUseCommandError::Conflict);
        }
        let recorded_at = database_now(&mut tx).await?;
        bounds.check(recorded_at)?;
        sqlx::query("INSERT INTO flow_service.delegated_proof_ingress (submission_id,challenge_id,organization_id,actor_type,actor_id,proof_digest,authentication_observed_at,authentication_valid_until,authorization_observed_at,authorization_valid_until,observed_at,valid_until,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
            .bind(submission_id).bind(challenge_id).bind(caller.organization_id()).bind(&actor_type)
            .bind(&caller.actor().id).bind(&proof_digest)
            .bind(bounds.authentication_observed_at).bind(bounds.authentication_valid_until)
            .bind(bounds.authorization_observed_at).bind(bounds.authorization_valid_until)
            .bind(bounds.observed_at).bind(bounds.valid_until).bind(recorded_at)
            .execute(&mut *tx).await.map_err(unavailable)?;
        bounds.check(database_now(&mut tx).await?)?;
        commit(tx).await?;
        bounds.check(Utc::now())?;
        Ok(FlowDelegatedProofSubmission {
            submission_id,
            challenge_id,
            proof_digest,
            received_at,
            recovered: false,
        })
    }
}

fn actor_type(caller: &DelegationCommandCaller) -> Result<String> {
    let value = serde_json::to_value(caller.actor()).map_err(unavailable)?;
    match value["type"].as_str() {
        Some(value @ ("SERVICE_ACCOUNT" | "MACHINE_IDENTITY")) => Ok(value.to_owned()),
        _ => Err(DelegationUseCommandError::AccessDenied),
    }
}

/// Validate the named additive ingress schema without changing any stored data.
pub async fn validate_delegated_use_ingress_schema(pool: &PgPool) -> Result<()> {
    let mut connection = pool.acquire().await.map_err(unavailable)?;
    validate_delegated_use_ingress_connection(&mut connection).await
}

pub(crate) async fn validate_delegated_use_ingress_connection(
    connection: &mut PgConnection,
) -> Result<()> {
    let version:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM flow_service.rust_schema_versions WHERE version='rust_flow_delegated_use_ingress_0006')")
        .fetch_one(&mut *connection).await.map_err(unavailable)?;
    if !version {
        return Err(DelegationUseCommandError::Unavailable);
    }
    let guards:i64=sqlx::query_scalar("WITH expected AS (
      SELECT name,name||'_immutable' AS trigger_name,'reject_delegated_use_mutation' AS function_name,27 AS kind,false AS deferred
      FROM unnest(ARRAY['delegated_use_storage_identity','delegated_challenge_bindings','delegated_proof_submissions','delegated_use_consumptions','delegated_request_claims','delegated_request_results','delegated_proof_ingress']) name
      UNION ALL SELECT name,name||'_no_truncate','reject_delegated_use_mutation',34,false FROM unnest(ARRAY['delegated_use_storage_identity','delegated_challenge_bindings','delegated_proof_submissions','delegated_use_consumptions','delegated_request_claims','delegated_request_results','delegated_proof_ingress']) name
      UNION ALL SELECT name,name||'_binding','guard_delegated_ingress',7,false FROM unnest(ARRAY['delegated_request_claims','delegated_request_results','delegated_proof_ingress']) name
      UNION ALL SELECT name,name||'_commit','guard_delegated_ingress',5,true FROM unnest(ARRAY['delegated_request_claims','delegated_request_results','delegated_proof_ingress']) name
      UNION ALL SELECT * FROM (VALUES
        ('delegated_challenge_bindings','delegated_challenge_binding_guard','guard_delegated_challenge_binding',7,false),
        ('delegated_proof_submissions','delegated_proof_submission_guard','guard_delegated_proof_submission',7,false),
        ('delegated_challenge_bindings','delegated_challenge_commit','check_delegated_use_commit',5,true),
        ('delegated_use_consumptions','delegated_consumption_commit','check_delegated_use_commit',5,true),
        ('flow_instances','delegated_flow_mutation_guard','guard_delegated_flow_mutation',25,true)) AS original)
      SELECT count(*) FROM expected e JOIN pg_namespace n ON n.nspname='flow_service'
      JOIN pg_class c ON c.relnamespace=n.oid AND c.relname=e.name AND c.relkind='r'
      JOIN pg_trigger t ON t.tgrelid=c.oid AND t.tgname=e.trigger_name AND NOT t.tgisinternal
      JOIN pg_proc p ON p.oid=t.tgfoid AND p.pronamespace=n.oid AND p.proname=e.function_name
      WHERE t.tgenabled='O' AND t.tgtype=e.kind AND t.tgdeferrable=e.deferred AND t.tginitdeferred=e.deferred
        AND t.tgqual IS NULL AND t.tgnargs=0 AND NOT p.prosecdef
        AND p.proconfig=ARRAY['search_path=pg_catalog']::TEXT[]")
        .fetch_one(&mut *connection).await.map_err(unavailable)?;
    if guards != 25 {
        return Err(DelegationUseCommandError::Unavailable);
    }
    for (name, column) in [
        ("delegated_request_claims", "challenge_id"),
        ("delegated_request_results", "challenge_id"),
        ("delegated_proof_ingress", "submission_id"),
    ] {
        let okay:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_constraint k JOIN pg_class t ON t.oid=k.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='flow_service' AND t.relname=$1 AND k.contype='p' AND k.convalidated AND NOT k.condeferrable AND pg_get_constraintdef(k.oid)='PRIMARY KEY ('||$2::TEXT||')')")
            .bind(name).bind(column).fetch_one(&mut *connection).await.map_err(unavailable)?;
        if !okay {
            return Err(DelegationUseCommandError::Unavailable);
        }
    }
    for (name, sql, arguments, security_definer) in [
        (
            "reject_delegated_use_mutation",
            include_str!("../migrations/0005_delegated_use_retention.sql"),
            "",
            false,
        ),
        (
            "guard_delegated_challenge_binding",
            include_str!("../migrations/0005_delegated_use_retention.sql"),
            "",
            false,
        ),
        (
            "guard_delegated_proof_submission",
            include_str!("../migrations/0005_delegated_use_retention.sql"),
            "",
            false,
        ),
        (
            "check_delegated_use_commit",
            include_str!("../migrations/0005_delegated_use_retention.sql"),
            "",
            false,
        ),
        (
            "guard_delegated_flow_mutation",
            include_str!("../migrations/0005_delegated_use_retention.sql"),
            "",
            false,
        ),
        (
            "guard_delegated_ingress",
            include_str!("../migrations/0006_delegated_use_ingress.sql"),
            "",
            false,
        ),
        (
            "lock_delegated_ingress_definition",
            include_str!("../migrations/0006_delegated_use_ingress.sql"),
            "uuid,uuid",
            true,
        ),
    ] {
        let expected = sql
            .split_once(&format!("CREATE OR REPLACE FUNCTION flow_service.{name}("))
            .and_then(|(_, tail)| tail.split_once("AS $$"))
            .and_then(|(_, tail)| tail.split_once("$$;"))
            .map(|(body, _)| body)
            .ok_or(DelegationUseCommandError::Unavailable)?;
        let actual:String=sqlx::query_scalar("SELECT p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_class owner_table ON owner_table.relnamespace=n.oid AND owner_table.relname='flow_definitions' WHERE p.oid=to_regprocedure($1) AND p.prosecdef=$2 AND p.proconfig=ARRAY['search_path=pg_catalog']::TEXT[] AND p.proowner=n.nspowner AND p.proowner=owner_table.relowner AND ((NOT $2 AND p.prorettype='trigger'::regtype AND NOT p.proretset) OR ($2 AND p.prorettype=owner_table.reltype AND p.proretset))")
            .bind(format!("flow_service.{name}({arguments})")).bind(security_definer)
            .fetch_one(&mut *connection).await.map_err(unavailable)?;
        if expected != actual {
            return Err(DelegationUseCommandError::Unavailable);
        }
    }
    Ok(())
}

async fn validate_ingress_role(pool: &PgPool) -> Result<()> {
    let safe:bool=sqlx::query_scalar("SELECT current_user=session_user AND NOT pg_is_in_recovery() AND NOT EXISTS (
      SELECT 1 FROM pg_roles r WHERE (r.rolname=current_user OR pg_has_role(current_user,r.oid,'MEMBER')) AND (
        r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR left(r.rolname::TEXT,3)='pg_'
        OR EXISTS(SELECT 1 FROM pg_auth_members a WHERE a.member=r.oid AND a.admin_option)
        OR EXISTS(SELECT 1 FROM pg_database d WHERE d.datname=current_database() AND d.datdba=r.oid)
        OR has_database_privilege(r.oid,current_database(),'CREATE,CREATE WITH GRANT OPTION,CONNECT WITH GRANT OPTION,TEMPORARY WITH GRANT OPTION')
        OR EXISTS(SELECT 1 FROM pg_namespace n WHERE left(n.nspname::TEXT,3)<>'pg_' AND n.nspname<>'information_schema'
          AND (n.nspowner=r.oid OR has_schema_privilege(r.oid,n.oid,'CREATE,CREATE WITH GRANT OPTION,USAGE WITH GRANT OPTION')))
        OR EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
          WHERE left(n.nspname::TEXT,3)<>'pg_' AND n.nspname<>'information_schema' AND t.relkind IN ('r','p','v','m','f','S') AND (
            t.relowner=r.oid OR has_table_privilege(r.oid,t.oid,'DELETE,TRUNCATE,TRIGGER,REFERENCES,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION,DELETE WITH GRANT OPTION,TRUNCATE WITH GRANT OPTION,TRIGGER WITH GRANT OPTION,REFERENCES WITH GRANT OPTION')
            OR CASE WHEN current_setting('server_version_num')::INTEGER>=170000 THEN has_table_privilege(r.oid,t.oid,'MAINTAIN,MAINTAIN WITH GRANT OPTION') ELSE false END
            OR has_any_column_privilege(r.oid,t.oid,'REFERENCES,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION,REFERENCES WITH GRANT OPTION')
            OR ((has_table_privilege(r.oid,t.oid,'SELECT') OR has_any_column_privilege(r.oid,t.oid,'SELECT'))
              AND NOT (n.nspname='flow_service' AND t.relname=ANY($1::TEXT[])))
            OR ((has_table_privilege(r.oid,t.oid,'INSERT') OR has_any_column_privilege(r.oid,t.oid,'INSERT'))
              AND NOT (n.nspname='flow_service' AND t.relname=ANY($2::TEXT[])))
            OR has_table_privilege(r.oid,t.oid,'UPDATE')
            OR EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped
              AND has_column_privilege(r.oid,t.oid,a.attnum,'UPDATE')
              AND NOT (n.nspname='flow_service' AND t.relname='flow_instances' AND a.attname=ANY($3::TEXT[])))))
        OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
          WHERE left(n.nspname::TEXT,3)<>'pg_' AND n.nspname<>'information_schema' AND (
            p.proowner=r.oid OR has_function_privilege(r.oid,p.oid,'EXECUTE WITH GRANT OPTION')
            OR (p.prosecdef AND p.oid<>'flow_service.lock_delegated_ingress_definition(uuid,uuid)'::regprocedure AND has_function_privilege(r.oid,p.oid,'EXECUTE'))))))")
        .bind(["rust_schema_versions","delegated_use_storage_identity","flow_definitions","flow_instances","delegated_challenge_bindings","delegated_proof_submissions","delegated_use_consumptions","delegated_request_claims","delegated_request_results","delegated_proof_ingress"])
        .bind(["delegated_proof_submissions","delegated_request_claims","delegated_request_results","delegated_proof_ingress"])
        .bind(["current_step_id","context","step_history","state_history","updated_at"])
        .fetch_one(pool).await.map_err(unavailable)?;
    if !safe {
        return Err(DelegationUseCommandError::Unavailable);
    }
    let required:bool=sqlx::query_scalar("SELECT has_schema_privilege(current_user,'flow_service','USAGE')
      AND has_function_privilege(current_user,'flow_service.lock_delegated_ingress_definition(uuid,uuid)','EXECUTE')
      AND NOT EXISTS(SELECT 1 FROM unnest($1::TEXT[]) t WHERE NOT has_table_privilege(current_user,format('flow_service.%I',t),'SELECT'))
      AND NOT EXISTS(SELECT 1 FROM unnest($2::TEXT[]) t WHERE NOT has_table_privilege(current_user,format('flow_service.%I',t),'INSERT'))
      AND NOT EXISTS(SELECT 1 FROM unnest($3::TEXT[]) c WHERE NOT has_column_privilege(current_user,'flow_service.flow_instances',c,'UPDATE'))")
        .bind(["rust_schema_versions","delegated_use_storage_identity","flow_definitions","flow_instances","delegated_challenge_bindings","delegated_proof_submissions","delegated_use_consumptions","delegated_request_claims","delegated_request_results","delegated_proof_ingress"])
        .bind(["delegated_proof_submissions","delegated_request_claims","delegated_request_results","delegated_proof_ingress"])
        .bind(["current_step_id","context","step_history","state_history","updated_at"])
        .fetch_one(pool).await.map_err(unavailable)?;
    if !required {
        return Err(DelegationUseCommandError::Unavailable);
    }
    Ok(())
}

#[derive(Clone)]
pub struct FlowDelegatedUseHttpState {
    application: Arc<FlowDelegatedUseIngress>,
    authenticator: Arc<DelegationUseHttpAuthenticator>,
}
impl FlowDelegatedUseHttpState {
    pub fn new(
        application: Arc<FlowDelegatedUseIngress>,
        authenticator: Arc<DelegationUseHttpAuthenticator>,
    ) -> Self {
        Self {
            application,
            authenticator,
        }
    }
}

/// Explicit internal composition. No existing Flow executable or public route
/// table installs this router by gaining the library module.
pub fn delegated_use_flow_router(state: FlowDelegatedUseHttpState) -> Router {
    Router::new()
        .route("/internal/v1/organizations/{organization_id}/delegated-use/challenges/{challenge_id}/request",get(retrieve_http))
        .route("/internal/v1/organizations/{organization_id}/delegated-use/challenges/{challenge_id}/proof",post(submit_http))
        .with_state(state).layer(middleware::from_fn(no_store))
}
async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}
fn challenge_id(value: &str) -> std::result::Result<Uuid, UseHttpError> {
    Uuid::parse_str(value)
        .ok()
        .filter(|id| !id.is_nil() && id.to_string() == value)
        .ok_or_else(|| UseHttpError::new(StatusCode::BAD_REQUEST, "invalid_delegated_flow_request"))
}
async fn retrieve_http(
    State(state): State<FlowDelegatedUseHttpState>,
    Path((organization, challenge)): Path<(String, String)>,
    request: Request,
) -> std::result::Result<Response, UseHttpError> {
    let context = state.authenticator.authenticate(&organization, &request)?;
    let challenge_id = challenge_id(&challenge)?;
    retrieve_authenticated(&state.application, context, challenge_id, request).await
}

async fn retrieve_authenticated(
    application: &FlowDelegatedUseIngress,
    context: AuthenticatedDelegationUseContext,
    challenge_id: Uuid,
    request: Request,
) -> std::result::Result<Response, UseHttpError> {
    if request.uri().query().is_some() {
        return Err(UseHttpError::new(
            StatusCode::BAD_REQUEST,
            "invalid_delegated_flow_request",
        ));
    }
    let body = tokio::time::timeout(READ_TIMEOUT, to_bytes(request.into_body(), 0))
        .await
        .map_err(|_| UseHttpError::new(StatusCode::REQUEST_TIMEOUT, "delegated_flow_body_timeout"))?
        .map_err(|_| {
            UseHttpError::new(
                StatusCode::BAD_REQUEST,
                "delegated_flow_request_body_forbidden",
            )
        })?;
    if !body.is_empty() {
        return Err(UseHttpError::new(
            StatusCode::BAD_REQUEST,
            "delegated_flow_request_body_forbidden",
        ));
    }
    context.check(Utc::now())?;
    let result = application.retrieve_request(&context, challenge_id).await?;
    let mut response = result.compact_request_jws.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/oauth-authz-req+jwt"),
    );
    Ok(response)
}
async fn submit_http(
    State(state): State<FlowDelegatedUseHttpState>,
    Path((organization, challenge)): Path<(String, String)>,
    request: Request,
) -> std::result::Result<Json<FlowDelegatedProofSubmission>, UseHttpError> {
    let context = state.authenticator.authenticate(&organization, &request)?;
    let challenge_id = challenge_id(&challenge)?;
    if request.uri().query().is_some() {
        return Err(UseHttpError::new(
            StatusCode::BAD_REQUEST,
            "invalid_delegated_flow_request",
        ));
    }
    let types: Vec<_> = request
        .headers()
        .get_all(header::CONTENT_TYPE)
        .iter()
        .collect();
    if types.len() != 1 || types[0].to_str().ok() != Some("application/octet-stream") {
        return Err(UseHttpError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "delegated_flow_proof_bytes_required",
        ));
    }
    let raw = tokio::time::timeout(
        READ_TIMEOUT,
        to_bytes(request.into_body(), MAX_DELEGATE_PROOF_BYTES.min(262_144)),
    )
    .await
    .map_err(|_| UseHttpError::new(StatusCode::REQUEST_TIMEOUT, "delegated_flow_body_timeout"))?
    .map_err(|_| {
        UseHttpError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "delegated_flow_body_too_large",
        )
    })?;
    context.check(Utc::now())?;
    Ok(Json(
        state
            .application
            .submit_proof(&context, challenge_id, &raw)
            .await?,
    ))
}
