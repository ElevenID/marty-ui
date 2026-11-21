//! Concrete Flow owner for retained delegated-use commands.
//!
//! Every authoritative start/consumption uses the connection supplied by the
//! delegated-use transaction. The independently loaded Flow storage identity
//! must match it. This adapter exposes no network authentication shortcut.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use marty_delegated_authority::{
    delegated_use_receipt_ref, DelegationChallengeAdmission, DelegationCommandCaller,
    DelegationOid4vpChallenge, DelegationUseCommandError, DelegationUseEvaluation,
    DelegationUseFlowOwner, IssuedDelegatedDecisionReceipt, PreparedUseChallenge,
    PreparedUseChallengeSnapshot, PreparedUseFinalization, ResolvedUseProofSubmission,
    RetainedUseChallenge, MAX_DELEGATE_PROOF_BYTES,
};
use marty_verification::flow::FlowInstanceStatus;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use crate::{
    delegation_challenge::challenge_from_records,
    delegation_start::{validate_delegation_snapshot, PreparedDelegatedVerificationStart},
    postgres::{definition_from_row, instance_from_row},
    DelegatedVerificationStartConfiguration, FlowDefinitionRecord,
    FlowDelegatedVerificationStarter, FlowInstanceRecord, FlowProviderRegistry,
    PostgresFlowRepository,
};

type UseResult<T> = Result<T, DelegationUseCommandError>;
const MAX_RETAINED_PROOF_BYTES: usize = 262_144;

fn unavailable(_: impl std::fmt::Debug) -> DelegationUseCommandError {
    DelegationUseCommandError::Unavailable
}
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn db_precision(time: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp_micros(time.timestamp_micros()).expect("existing bounded timestamp")
}
async fn database_now(connection: &mut PgConnection) -> UseResult<DateTime<Utc>> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(connection)
        .await
        .map_err(unavailable)
}
async fn storage_identity(connection: &mut PgConnection) -> UseResult<Uuid> {
    sqlx::query_scalar(
        "SELECT storage_id FROM flow_service.delegated_use_storage_identity WHERE singleton",
    )
    .fetch_one(connection)
    .await
    .map_err(unavailable)
}
async fn require_storage(connection: &mut PgConnection, expected: Uuid) -> UseResult<()> {
    if storage_identity(connection).await? != expected {
        return Err(DelegationUseCommandError::Conflict);
    }
    Ok(())
}

fn prepared_snapshot(
    prepared: &PreparedDelegatedVerificationStart,
) -> UseResult<PreparedUseChallengeSnapshot> {
    let instance = prepared.instance();
    let challenge = validate_delegation_snapshot(instance).map_err(unavailable)?;
    Ok(PreparedUseChallengeSnapshot {
        organization_id: challenge.binding.organization_id,
        challenge_id: challenge.binding.challenge_id,
        verifier_id: challenge.verifier_client_id,
        nonce: challenge.nonce,
        created_at: db_precision(instance.created_at),
        expires_at: db_precision(challenge.expires_at),
    })
}

/// Shared by the earlier internal starter and the retained command bridge.
/// Nonces remain reserved after expiry/consumption; ordinary verification nonce
/// cleanup does not operate on this table.
pub(crate) async fn retain_started_challenge(
    transaction: &mut PgConnection,
    prepared: &PreparedDelegatedVerificationStart,
) -> UseResult<()> {
    let snapshot = prepared_snapshot(prepared)?;
    let inserted = sqlx::query(
        "INSERT INTO flow_service.delegated_challenge_bindings \
         (challenge_id,organization_id,verifier_id,nonce,nonce_digest,instance_snapshot,created_at,expires_at) \
         SELECT $1,$2,$3,$4,encode(sha256(convert_to($4,'UTF8')),'hex'),to_jsonb(source),source.created_at,source.expires_at \
         FROM flow_service.flow_instances AS source WHERE source.id=$5 AND source.organization_id=$6",
    ).bind(snapshot.challenge_id).bind(snapshot.organization_id).bind(&snapshot.verifier_id)
        .bind(&snapshot.nonce).bind(&prepared.instance().id).bind(&prepared.instance().organization_id)
        .execute(&mut *transaction).await.map_err(unavailable)?;
    if inserted.rows_affected() != 1 {
        return Err(DelegationUseCommandError::Conflict);
    }
    Ok(())
}

#[derive(Clone)]
pub struct FlowDelegatedUseOwner {
    repository: PostgresFlowRepository,
    starter: FlowDelegatedVerificationStarter,
    storage_id: Uuid,
}

/// Immutable submission identity. Raw proofs are retained only in the restricted
/// Flow source table and are not projected into this response or Debug output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FlowDelegatedProofSubmission {
    pub submission_id: Uuid,
    pub challenge_id: Uuid,
    pub proof_digest: String,
    pub received_at: DateTime<Utc>,
    pub recovered: bool,
}

impl FlowDelegatedUseOwner {
    pub async fn new(
        repository: PostgresFlowRepository,
        providers: FlowProviderRegistry,
        configuration: DelegatedVerificationStartConfiguration,
    ) -> UseResult<Self> {
        let mut connection = repository.pool().acquire().await.map_err(unavailable)?;
        let storage_id = storage_identity(&mut connection).await?;
        drop(connection);
        let starter =
            FlowDelegatedVerificationStarter::new(repository.clone(), providers, configuration);
        Ok(Self {
            repository,
            starter,
            storage_id,
        })
    }

    /// Called only by a separately authenticated and authorized proof ingress.
    /// `DelegationCommandCaller` checks shape; this method does not authenticate
    /// a network request. Storing submitted bytes does not verify their signature
    /// or produce authority. Finalization always invokes the configured verifier.
    /// Repeating exact proof bytes recovers the same retained submission ID.
    pub async fn record_proof_submission(
        &self,
        caller: &DelegationCommandCaller,
        challenge_id: Uuid,
        proof: &[u8],
    ) -> UseResult<FlowDelegatedProofSubmission> {
        if challenge_id.is_nil()
            || proof.is_empty()
            || proof.len() > MAX_RETAINED_PROOF_BYTES.min(MAX_DELEGATE_PROOF_BYTES)
        {
            return Err(DelegationUseCommandError::InvalidCommand);
        }
        let mut transaction = self.repository.pool().begin().await.map_err(unavailable)?;
        require_storage(&mut transaction, self.storage_id).await?;
        let row = sqlx::query("SELECT * FROM flow_service.flow_instances WHERE id=$1 AND organization_id=$2 FOR SHARE")
            .bind(challenge_id.to_string()).bind(caller.organization_id().to_string())
            .fetch_optional(&mut *transaction).await.map_err(unavailable)?
            .ok_or(DelegationUseCommandError::AccessDenied)?;
        let instance = instance_from_row(&row).map_err(unavailable)?;
        let challenge = validate_delegation_snapshot(&instance).map_err(unavailable)?;
        if challenge.binding.actor != *caller.actor()
            || challenge.binding.organization_id != caller.organization_id()
        {
            return Err(DelegationUseCommandError::AccessDenied);
        }
        let proof_digest = digest(proof);
        if let Some(row) = sqlx::query("SELECT submission_id,proof_digest,received_at FROM flow_service.delegated_proof_submissions WHERE challenge_id=$1 AND organization_id=$2 AND proof_digest=$3")
            .bind(challenge_id).bind(caller.organization_id()).bind(&proof_digest)
            .fetch_optional(&mut *transaction).await.map_err(unavailable)? {
            let result = FlowDelegatedProofSubmission { submission_id:row.try_get("submission_id").map_err(unavailable)?,
                challenge_id,proof_digest,received_at:row.try_get("received_at").map_err(unavailable)?,recovered:true };
            transaction.commit().await.map_err(unavailable)?;
            return Ok(result);
        }
        let now = database_now(&mut transaction).await?;
        if instance.status != FlowInstanceStatus::AwaitingWallet
            || instance.completed_at.is_some()
            || instance.result.is_some()
            || instance.error.is_some()
            || now >= challenge.expires_at
        {
            return Err(DelegationUseCommandError::Expired);
        }
        let actor_type = serde_json::to_value(caller.actor()).map_err(unavailable)?["type"]
            .as_str()
            .ok_or(DelegationUseCommandError::AccessDenied)?
            .to_owned();
        let submission_id = Uuid::new_v4();
        let inserted = sqlx::query("INSERT INTO flow_service.delegated_proof_submissions \
            (submission_id,challenge_id,organization_id,actor_type,actor_id,proof,proof_digest,received_at) \
            VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(challenge_id,proof_digest) DO NOTHING")
            .bind(submission_id).bind(challenge_id).bind(caller.organization_id()).bind(actor_type)
            .bind(&caller.actor().id).bind(proof).bind(&proof_digest).bind(now)
            .execute(&mut *transaction).await.map_err(unavailable)?;
        let row = sqlx::query("SELECT submission_id,received_at FROM flow_service.delegated_proof_submissions WHERE challenge_id=$1 AND organization_id=$2 AND proof_digest=$3")
            .bind(challenge_id).bind(caller.organization_id()).bind(&proof_digest)
            .fetch_one(&mut *transaction).await.map_err(unavailable)?;
        let result = FlowDelegatedProofSubmission {
            submission_id: row.try_get("submission_id").map_err(unavailable)?,
            challenge_id,
            proof_digest,
            received_at: row.try_get("received_at").map_err(unavailable)?,
            recovered: inserted.rows_affected() == 0,
        };
        transaction.commit().await.map_err(unavailable)?;
        Ok(result)
    }

    async fn original_records(
        &self,
        retained: &RetainedUseChallenge,
    ) -> UseResult<(FlowInstanceRecord, FlowDefinitionRecord)> {
        let instance = self
            .repository
            .instance(&retained.challenge_id.to_string())
            .await
            .map_err(unavailable)?
            .filter(|record| record.organization_id == retained.organization_id.to_string())
            .ok_or(DelegationUseCommandError::Conflict)?;
        let definition = self
            .repository
            .definition(&instance.flow_definition_id)
            .await
            .map_err(unavailable)?
            .ok_or(DelegationUseCommandError::Conflict)?;
        let challenge = challenge_from_records(
            retained.organization_id,
            retained.grant.id,
            retained.challenge_id,
            &instance,
            &definition,
            Utc::now(),
        )
        .map_err(unavailable)?;
        match_retained(retained, &instance, &challenge)?;
        Ok((instance, definition))
    }
}

fn match_retained(
    retained: &RetainedUseChallenge,
    instance: &FlowInstanceRecord,
    actual: &DelegationOid4vpChallenge,
) -> UseResult<()> {
    let binding = &actual.binding;
    if retained.organization_id != retained.grant.organization_id
        || binding.organization_id != retained.organization_id
        || binding.challenge_id != retained.challenge_id
        || binding.grant_id != retained.grant.id
        || binding.grant_revision != retained.grant.revision
        || binding.actor != retained.grant.terms.delegate
        || binding.action != retained.operation.action
        || binding.resource != retained.operation.resource_id
        || binding.audience != retained.operation.audience
        || binding.operation_profile != retained.operation.request_profile
        || binding.operation_digest != retained.operation.request_digest
        || actual.nonce != retained.nonce
        || actual.verifier_client_id != retained.verifier_id
        || db_precision(instance.created_at) != db_precision(retained.created_at)
        || db_precision(actual.expires_at) != db_precision(retained.expires_at)
    {
        return Err(DelegationUseCommandError::Conflict);
    }
    Ok(())
}

struct FlowPreparedUseChallenge {
    prepared: PreparedDelegatedVerificationStart,
    snapshot: PreparedUseChallengeSnapshot,
    storage_id: Uuid,
}

#[async_trait]
impl PreparedUseChallenge for FlowPreparedUseChallenge {
    fn snapshot(&self) -> &PreparedUseChallengeSnapshot {
        &self.snapshot
    }
    async fn revalidate(&mut self) -> UseResult<()> {
        self.prepared.revalidate().await.map_err(unavailable)?;
        let current = prepared_snapshot(&self.prepared)?;
        if current.organization_id != self.snapshot.organization_id
            || current.challenge_id != self.snapshot.challenge_id
            || current.verifier_id != self.snapshot.verifier_id
            || current.nonce != self.snapshot.nonce
            || current.created_at != self.snapshot.created_at
            || current.expires_at > self.snapshot.expires_at
        {
            return Err(DelegationUseCommandError::Conflict);
        }
        self.snapshot = current;
        Ok(())
    }
    async fn commit(
        self: Box<Self>,
        transaction: &mut PgConnection,
        now: DateTime<Utc>,
    ) -> UseResult<()> {
        require_storage(transaction, self.storage_id).await?;
        let expected = self.prepared.definition();
        let row = sqlx::query("SELECT * FROM flow_service.flow_definitions WHERE id=$1 AND organization_id=$2 FOR SHARE")
            .bind(&expected.id).bind(&expected.organization_id).fetch_optional(&mut *transaction).await.map_err(unavailable)?
            .ok_or(DelegationUseCommandError::Conflict)?;
        let definition = definition_from_row(&row).map_err(unavailable)?;
        if &definition != expected {
            return Err(DelegationUseCommandError::Conflict);
        }
        let fresh = database_now(transaction).await?;
        if fresh < now {
            return Err(DelegationUseCommandError::Expired);
        }
        self.prepared.check_live_at(fresh).map_err(unavailable)?;
        let instance = self.prepared.instance();
        let inserted = sqlx::query(
            "INSERT INTO flow_service.flow_instances (id,flow_definition_id,organization_id,status,current_step_id,context,step_history,state_history,subject_id,subject_type,external_reference,application_flow_key_hash,started_at,completed_at,expires_at,result,error,created_at,updated_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) ON CONFLICT DO NOTHING")
            .bind(&instance.id).bind(&instance.flow_definition_id).bind(&instance.organization_id)
            .bind(instance.status.to_string()).bind(&instance.current_step_id).bind(&instance.context)
            .bind(json!(&instance.step_history)).bind(json!(&instance.state_history)).bind(&instance.subject_id)
            .bind(&instance.subject_type).bind(&instance.external_reference).bind(&instance.application_flow_key_hash)
            .bind(instance.started_at).bind(instance.completed_at).bind(instance.expires_at).bind(&instance.result)
            .bind(&instance.error).bind(instance.created_at).bind(instance.updated_at)
            .execute(&mut *transaction).await.map_err(unavailable)?;
        if inserted.rows_affected() != 1 {
            return Err(DelegationUseCommandError::Conflict);
        }
        retain_started_challenge(transaction, &self.prepared).await?;
        self.prepared
            .check_live_at(database_now(transaction).await?)
            .map_err(unavailable)?;
        Ok(())
    }
}

struct FlowPreparedUseFinalization {
    retained: RetainedUseChallenge,
    instance: FlowInstanceRecord,
    definition: FlowDefinitionRecord,
    submission_id: Uuid,
    proof_digest: String,
    storage_id: Uuid,
}

/// Request retrieval can advance progress after proof evaluation or while the
/// signer is awaiting its provider. Compare the complete immutable source scope
/// while preserving the latest progress/history under the existing row lock.
/// This allowlist matches migration0005; no historical migration is rewritten.
pub(crate) fn same_delegated_authority_snapshot(
    prepared: &FlowInstanceRecord,
    current: &FlowInstanceRecord,
) -> UseResult<bool> {
    let derived = [
        "request_retrieved",
        "mip_messages",
        "oid4vp_response_uri",
        "oid4vp_response_encryption_jwk",
        "oid4vp_expected_state",
        "verification_audience",
        "oid4vp_verifier_context",
        "paired_wallet_signed_request_v1",
    ];
    let context = &current.context;
    let response_uri = prepared
        .context
        .get("request_uri")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_suffix("/request"))
        .map(|base| format!("{base}/submit"));
    if context
        .get("request_retrieved")
        .is_some_and(|v| v != &json!(true))
        || context
            .get("oid4vp_response_uri")
            .is_some_and(|v| v.as_str() != response_uri.as_deref())
        || context
            .get("oid4vp_response_encryption_jwk")
            .is_some_and(|v| !v.is_null())
        || context
            .get("oid4vp_expected_state")
            .is_some_and(|v| v.as_str() != Some(prepared.id.as_str()))
        || context
            .get("verification_audience")
            .is_some_and(|v| Some(v) != prepared.context.get("oid4vp_client_id"))
        || context
            .get("oid4vp_verifier_context")
            .is_some_and(|v| v != &json!(true))
        || prepared
            .context
            .get("paired_wallet_signed_request_v1")
            .is_some_and(|v| context.get("paired_wallet_signed_request_v1") != Some(v))
    {
        return Ok(false);
    }
    let project = |instance: &FlowInstanceRecord| -> UseResult<Value> {
        let mut value = serde_json::to_value(instance).map_err(unavailable)?;
        let object = value
            .as_object_mut()
            .ok_or(DelegationUseCommandError::Conflict)?;
        for name in [
            "current_step_id",
            "step_history",
            "state_history",
            "updated_at",
        ] {
            object.remove(name);
        }
        let context = object
            .get_mut("context")
            .and_then(Value::as_object_mut)
            .ok_or(DelegationUseCommandError::Conflict)?;
        for name in derived {
            context.remove(name);
        }
        Ok(value)
    };
    Ok(current.updated_at >= prepared.updated_at && project(prepared)? == project(current)?)
}

#[async_trait]
impl PreparedUseFinalization for FlowPreparedUseFinalization {
    async fn commit(
        self: Box<Self>,
        transaction: &mut PgConnection,
        evaluation: &DelegationUseEvaluation,
        receipt: &IssuedDelegatedDecisionReceipt,
        now: DateTime<Utc>,
    ) -> UseResult<()> {
        require_storage(transaction, self.storage_id).await?;
        let definition = sqlx::query("SELECT * FROM flow_service.flow_definitions WHERE id=$1 AND organization_id=$2 FOR SHARE")
            .bind(&self.definition.id).bind(&self.definition.organization_id).fetch_optional(&mut *transaction).await.map_err(unavailable)?
            .ok_or(DelegationUseCommandError::Conflict)?;
        if definition_from_row(&definition).map_err(unavailable)? != self.definition {
            return Err(DelegationUseCommandError::Conflict);
        }
        let row = sqlx::query("SELECT * FROM flow_service.flow_instances WHERE id=$1 AND organization_id=$2 FOR UPDATE")
            .bind(&self.instance.id).bind(&self.instance.organization_id).fetch_optional(&mut *transaction).await.map_err(unavailable)?
            .ok_or(DelegationUseCommandError::Conflict)?;
        let stored = instance_from_row(&row).map_err(unavailable)?;
        if !same_delegated_authority_snapshot(&self.instance, &stored)? {
            return Err(DelegationUseCommandError::Conflict);
        }
        let fresh = database_now(transaction).await?;
        if stored.updated_at > fresh {
            return Err(DelegationUseCommandError::Conflict);
        }
        let challenge = challenge_from_records(
            self.retained.organization_id,
            self.retained.grant.id,
            self.retained.challenge_id,
            &stored,
            &self.definition,
            fresh,
        )
        .map_err(unavailable)?;
        match_retained(&self.retained, &stored, &challenge)?;
        if fresh < now
            || now < evaluation.evaluated_at()
            || fresh >= evaluation.valid_until()
            || fresh >= receipt.payload().expires_at
            || receipt.payload().issued_at > now
            || receipt.payload().expires_at > evaluation.valid_until()
            || evaluation.organization_id() != self.retained.organization_id
            || evaluation.challenge_id() != self.retained.challenge_id
            || evaluation.grant_id() != self.retained.grant.id
            || evaluation.grant_revision() != self.retained.grant.revision
            || evaluation.terms_digest() != self.retained.grant.terms_digest
            || evaluation.actor() != &self.retained.grant.terms.delegate
            || evaluation.action() != self.retained.operation.action
            || evaluation.audience() != self.retained.operation.audience
            || evaluation.resource() != self.retained.operation.resource_id
            || evaluation.operation_profile() != self.retained.operation.request_profile
            || evaluation.operation_digest() != self.retained.operation.request_digest
            || receipt.payload().evaluation.challenge != self.retained.nonce
        {
            return Err(DelegationUseCommandError::Expired);
        }
        let proof = sqlx::query("SELECT proof_digest,received_at,actor_type,actor_id FROM flow_service.delegated_proof_submissions WHERE submission_id=$1 AND challenge_id=$2 AND organization_id=$3 FOR SHARE")
            .bind(self.submission_id).bind(self.retained.challenge_id).bind(self.retained.organization_id)
            .fetch_optional(&mut *transaction).await.map_err(unavailable)?
            .ok_or(DelegationUseCommandError::Conflict)?;
        let actor = serde_json::to_value(evaluation.actor()).map_err(unavailable)?;
        if proof
            .try_get::<String, _>("proof_digest")
            .map_err(unavailable)?
            != self.proof_digest
            || proof
                .try_get::<String, _>("actor_type")
                .map_err(unavailable)?
                != actor["type"].as_str().unwrap_or_default()
            || proof
                .try_get::<String, _>("actor_id")
                .map_err(unavailable)?
                != evaluation.actor().id
            || proof
                .try_get::<DateTime<Utc>, _>("received_at")
                .map_err(unavailable)?
                > now
        {
            return Err(DelegationUseCommandError::Conflict);
        }
        let receipt_ref = delegated_use_receipt_ref(receipt);
        let receipt_digest = digest(receipt.compact_jws().as_bytes());
        let result = json!({"kind":"DELEGATED_USE","semantics":"EVIDENCE_ONLY","decision":receipt.payload().decision,
            "receipt_ref":receipt_ref,"receipt_digest":receipt_digest});
        let mut history = stored.state_history.clone();
        history.push(
            json!({"prior_state":stored.status,"new_state":"completed","timestamp":fresh,
            "actor":evaluation.actor().id,"event":"delegated_use_evidence_recorded"}),
        );
        let updated = sqlx::query("UPDATE flow_service.flow_instances SET status='completed',current_step_id=NULL,completed_at=$3,updated_at=$3,result=$4,state_history=$5 WHERE id=$1 AND organization_id=$2 AND status='awaiting_wallet'")
            .bind(&stored.id).bind(&stored.organization_id).bind(fresh).bind(result).bind(Value::Array(history))
            .execute(&mut *transaction).await.map_err(unavailable)?;
        if updated.rows_affected() != 1 {
            return Err(DelegationUseCommandError::Conflict);
        }
        sqlx::query("INSERT INTO flow_service.delegated_use_consumptions(challenge_id,organization_id,proof_submission_id,proof_digest,receipt_ref,receipt_digest,decision,recorded_at,authorization_expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(self.retained.challenge_id).bind(self.retained.organization_id).bind(self.submission_id)
            .bind(&self.proof_digest).bind(&receipt_ref).bind(&receipt_digest).bind(receipt.payload().decision)
            .bind(fresh).bind(receipt.payload().expires_at.min(self.retained.expires_at))
            .execute(&mut *transaction).await.map_err(unavailable)?;
        let after = database_now(transaction).await?;
        if after < fresh
            || after >= receipt.payload().expires_at
            || after >= evaluation.valid_until()
            || after >= self.retained.expires_at
        {
            return Err(DelegationUseCommandError::Expired);
        }
        Ok(())
    }
}

#[async_trait]
impl DelegationUseFlowOwner for FlowDelegatedUseOwner {
    async fn prepare_start(
        &self,
        admission: DelegationChallengeAdmission,
    ) -> UseResult<Box<dyn PreparedUseChallenge>> {
        let prepared = self.starter.prepare(admission).await.map_err(unavailable)?;
        let snapshot = prepared_snapshot(&prepared)?;
        Ok(Box::new(FlowPreparedUseChallenge {
            prepared,
            snapshot,
            storage_id: self.storage_id,
        }))
    }
    async fn resolve_submission(
        &self,
        retained: &RetainedUseChallenge,
        submission_id: Uuid,
    ) -> UseResult<ResolvedUseProofSubmission> {
        self.original_records(retained).await?;
        let row = sqlx::query("SELECT actor_type,actor_id,received_at,proof,proof_digest FROM flow_service.delegated_proof_submissions WHERE submission_id=$1 AND challenge_id=$2 AND organization_id=$3")
            .bind(submission_id).bind(retained.challenge_id).bind(retained.organization_id)
            .fetch_optional(self.repository.pool()).await.map_err(unavailable)?
            .ok_or(DelegationUseCommandError::Conflict)?;
        let actor = serde_json::to_value(&retained.grant.terms.delegate).map_err(unavailable)?;
        let proof: Vec<u8> = row.try_get("proof").map_err(unavailable)?;
        if row
            .try_get::<String, _>("actor_type")
            .map_err(unavailable)?
            != actor["type"].as_str().unwrap_or_default()
            || row.try_get::<String, _>("actor_id").map_err(unavailable)?
                != retained.grant.terms.delegate.id
            || row
                .try_get::<String, _>("proof_digest")
                .map_err(unavailable)?
                != digest(&proof)
        {
            return Err(DelegationUseCommandError::Conflict);
        }
        Ok(ResolvedUseProofSubmission {
            organization_id: retained.organization_id,
            challenge_id: retained.challenge_id,
            proof_submission_id: submission_id,
            actor: retained.grant.terms.delegate.clone(),
            received_at: row.try_get("received_at").map_err(unavailable)?,
            proof,
        })
    }
    async fn prepare_finalization(
        &self,
        retained: &RetainedUseChallenge,
        submission_id: Uuid,
        proof_digest: &str,
    ) -> UseResult<Box<dyn PreparedUseFinalization>> {
        let (instance, definition) = self.original_records(retained).await?;
        let submission = self.resolve_submission(retained, submission_id).await?;
        if digest(&submission.proof) != proof_digest {
            return Err(DelegationUseCommandError::Conflict);
        }
        Ok(Box::new(FlowPreparedUseFinalization {
            retained: retained.clone(),
            instance,
            definition,
            submission_id,
            proof_digest: proof_digest.into(),
            storage_id: self.storage_id,
        }))
    }
}
