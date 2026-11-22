use chrono::{DateTime, Utc};
use marty_principal_runtime_binding::TypedThumbprint;
use serde_json::{json, Value};
use sqlx::{PgConnection, Postgres, Row, Transaction};
use uuid::Uuid;

use super::{
    database_error,
    domain::{public_key, valid_metadata, valid_revision, valid_uri, validate_snapshot},
    *,
};
use crate::{
    authorize_forwarded_principal, postgres::PostgresOrganizationStore, AuditEvent,
    ForwardedPrincipal,
};

#[derive(Clone)]
pub struct AgentDirectoryService {
    pub(super) store: PostgresOrganizationStore,
    pub(super) request_id: Option<Uuid>,
    pub(super) enrollment: Option<AgentEnrollmentConfiguration>,
}

enum Mutation {
    Register(RegisterAgentRequest),
    Metadata(UpdateAgentMetadataRequest),
    Transition(AgentLifecycleAction, AgentLifecycleRequest),
    Rotate(RotateAgentKeyRequest),
}
impl Mutation {
    fn permission(&self) -> &'static str {
        match self {
            Self::Register(_) => "agent-identity:create",
            Self::Metadata(_) => "agent-identity:update",
            Self::Transition(action, _) => action.permission(),
            Self::Rotate(_) => "agent-identity:rotate-key",
        }
    }
    fn action(&self) -> &'static str {
        match self {
            Self::Register(_) => "REGISTER",
            Self::Metadata(_) => "UPDATE_METADATA",
            Self::Transition(action, _) => action.event(),
            Self::Rotate(_) => "ROTATE_KEY",
        }
    }
    fn revision(&self) -> Option<u64> {
        match self {
            Self::Register(_) => None,
            Self::Metadata(value) => Some(value.expected_revision),
            Self::Transition(_, value) => Some(value.expected_revision),
            Self::Rotate(value) => Some(value.expected_revision),
        }
    }
}

impl AgentDirectoryService {
    pub fn new(store: PostgresOrganizationStore) -> Self {
        Self {
            store,
            request_id: None,
            enrollment: None,
        }
    }
    /// Correlation only: this does not authenticate a caller or deduplicate work.
    pub fn with_request_id(mut self, request_id: Uuid) -> Self {
        self.request_id = Some(request_id);
        self
    }
    /// Explicit local selection; enrollment remains unavailable by default.
    pub fn with_enrollment(mut self, configuration: AgentEnrollmentConfiguration) -> Self {
        self.enrollment = Some(configuration);
        self
    }
    pub fn enrollment_enabled(&self) -> bool {
        self.enrollment.is_some()
    }

    pub async fn register(
        &self,
        organization_id: Uuid,
        principal: &ForwardedPrincipal,
        request: RegisterAgentRequest,
    ) -> Result<AgentIdentity, AgentDirectoryError> {
        valid_metadata(
            &request.display_name,
            request.description.as_deref(),
            &request.logical_application_ref,
        )?;
        if !valid_uri(&request.issuer)
            || !valid_uri(&request.runtime_instance_ref)
            || request.subject.is_empty()
            || request.subject.len() > 512
            || request.subject.chars().any(char::is_control)
        {
            return Err(AgentDirectoryError::InvalidRequest);
        }
        self.mutate(
            organization_id,
            principal,
            None,
            Mutation::Register(request),
        )
        .await
    }
    pub async fn update_metadata(
        &self,
        organization_id: Uuid,
        principal: &ForwardedPrincipal,
        id: Uuid,
        request: UpdateAgentMetadataRequest,
    ) -> Result<AgentIdentity, AgentDirectoryError> {
        valid_metadata(
            &request.display_name,
            request.description.as_deref(),
            &request.logical_application_ref,
        )?;
        self.mutate(
            organization_id,
            principal,
            Some(id),
            Mutation::Metadata(request),
        )
        .await
    }
    pub async fn transition(
        &self,
        organization_id: Uuid,
        principal: &ForwardedPrincipal,
        id: Uuid,
        action: AgentLifecycleAction,
        request: AgentLifecycleRequest,
    ) -> Result<AgentIdentity, AgentDirectoryError> {
        self.mutate(
            organization_id,
            principal,
            Some(id),
            Mutation::Transition(action, request),
        )
        .await
    }
    pub async fn rotate_key(
        &self,
        organization_id: Uuid,
        principal: &ForwardedPrincipal,
        id: Uuid,
        request: RotateAgentKeyRequest,
    ) -> Result<AgentIdentity, AgentDirectoryError> {
        self.mutate(
            organization_id,
            principal,
            Some(id),
            Mutation::Rotate(request),
        )
        .await
    }

    pub async fn inspect(
        &self,
        organization_id: Uuid,
        principal: &ForwardedPrincipal,
        id: Uuid,
    ) -> Result<AgentIdentity, AgentDirectoryError> {
        let mut tx = self.begin().await?;
        self.authorize(&mut tx, organization_id, principal, "agent-identity:view")
            .await?;
        let result = load(&mut tx, organization_id, id, false).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(result)
    }
    pub async fn list(
        &self,
        organization_id: Uuid,
        principal: &ForwardedPrincipal,
        limit: u32,
        offset: u32,
    ) -> Result<AgentIdentityPage, AgentDirectoryError> {
        paging(limit, offset)?;
        let mut tx = self.begin().await?;
        self.authorize(&mut tx, organization_id, principal, "agent-identity:view")
            .await?;
        let rows=sqlx::query("SELECT id,organization_id,kind,status,revision,issuer,subject,runtime_instance_ref,created_at,updated_at,document FROM organization_service.agent_identities WHERE organization_id=$1 ORDER BY created_at DESC,id LIMIT $2 OFFSET $3")
            .bind(organization_id).bind(i64::from(limit)).bind(i64::from(offset)).fetch_all(&mut *tx).await.map_err(database_error)?;
        let items = rows
            .into_iter()
            .map(decode_row)
            .collect::<Result<Vec<_>, _>>()?;
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM organization_service.agent_identities WHERE organization_id=$1",
        )
        .bind(organization_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(AgentIdentityPage {
            items,
            total: count
                .try_into()
                .map_err(|_| AgentDirectoryError::CorruptData)?,
            limit,
            offset,
        })
    }
    pub async fn history(
        &self,
        organization_id: Uuid,
        principal: &ForwardedPrincipal,
        id: Uuid,
        limit: u32,
        offset: u32,
    ) -> Result<AgentHistoryPage, AgentDirectoryError> {
        paging(limit, offset)?;
        let mut tx = self.begin().await?;
        self.authorize(&mut tx, organization_id, principal, "agent-identity:view")
            .await?;
        // A revision and its complete history must be read from one stable
        // identity state even when a concurrent administrator is mutating it.
        let current = load(&mut tx, organization_id, id, true).await?;
        let rows=sqlx::query("SELECT revision,action,actor_user_id,request_id,occurred_at,snapshot FROM organization_service.agent_identity_history WHERE organization_id=$1 AND agent_id=$2 ORDER BY revision DESC LIMIT $3 OFFSET $4")
            .bind(organization_id).bind(id).bind(i64::from(limit)).bind(i64::from(offset)).fetch_all(&mut *tx).await.map_err(database_error)?;
        let mut items = Vec::new();
        for row in rows {
            let snapshot: AgentIdentity = serde_json::from_value(
                row.try_get::<Value, _>("snapshot")
                    .map_err(|_| AgentDirectoryError::CorruptData)?,
            )
            .map_err(|_| AgentDirectoryError::CorruptData)?;
            validate_snapshot(&snapshot)?;
            let revision: i64 = row
                .try_get("revision")
                .map_err(|_| AgentDirectoryError::CorruptData)?;
            let occurred_at: DateTime<Utc> = row
                .try_get("occurred_at")
                .map_err(|_| AgentDirectoryError::CorruptData)?;
            if snapshot.organization_id != organization_id
                || snapshot.id != id
                || snapshot.revision != revision as u64
                || snapshot.updated_at != occurred_at
            {
                return Err(AgentDirectoryError::CorruptData);
            }
            items.push(AgentHistoryEvent {
                revision: snapshot.revision,
                action: row
                    .try_get("action")
                    .map_err(|_| AgentDirectoryError::CorruptData)?,
                actor_user_id: row
                    .try_get("actor_user_id")
                    .map_err(|_| AgentDirectoryError::CorruptData)?,
                request_id: row
                    .try_get("request_id")
                    .map_err(|_| AgentDirectoryError::CorruptData)?,
                occurred_at,
                snapshot,
            });
        }
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM organization_service.agent_identity_history WHERE organization_id=$1 AND agent_id=$2").bind(organization_id).bind(id).fetch_one(&mut *tx).await.map_err(database_error)?;
        if count as u64 != current.revision {
            return Err(AgentDirectoryError::CorruptData);
        }
        tx.commit().await.map_err(database_error)?;
        Ok(AgentHistoryPage {
            items,
            total: current.revision,
            limit,
            offset,
        })
    }

    /// Internal current inventory lookup. The caller must separately authenticate
    /// issuer/subject/runtime/proof, apply MAP and current delegated authority.
    /// Neither a matching fingerprint nor administrative ACTIVE is that proof.
    pub async fn lookup_current(
        &self,
        organization_id: Uuid,
        id: Uuid,
        fingerprint: &TypedThumbprint,
    ) -> Result<CurrentAgentBinding, AgentDirectoryError> {
        let mut tx = self.begin().await?;
        let status: Option<String> = sqlx::query_scalar(
            "SELECT status FROM organization_service.organizations WHERE id=$1 FOR SHARE",
        )
        .bind(organization_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(database_error)?;
        if status.as_deref() != Some("active") {
            return Err(AgentDirectoryError::AccessDenied);
        }
        let identity = load(&mut tx, organization_id, id, true).await?;
        if identity.status != AgentIdentityStatus::Active
            || (identity.kind == AgentKind::Managed
                && identity.provenance.managed_enrollment != "KEY_CONTROL_VERIFIED")
        {
            return Err(AgentDirectoryError::AccessDenied);
        }
        let current = identity
            .keys
            .first()
            .ok_or(AgentDirectoryError::CorruptData)?;
        if !current.fingerprint.typed()?.same_binding(fingerprint) {
            return Err(AgentDirectoryError::AccessDenied);
        }
        let active:Vec<(Uuid,String)>=sqlx::query_as("SELECT key_id,key_thumbprint FROM organization_service.agent_identity_keys WHERE organization_id=$1 AND agent_id=$2 AND status='ACTIVE' FOR SHARE")
            .bind(organization_id).bind(id).fetch_all(&mut *tx).await.map_err(database_error)?;
        if active != [(current.key_id, current.fingerprint.value.clone())] {
            return Err(AgentDirectoryError::CorruptData);
        }
        let observed_at = now(&mut tx).await?;
        if observed_at < identity.updated_at {
            return Err(AgentDirectoryError::Unavailable);
        }
        tx.commit().await.map_err(database_error)?;
        Ok(CurrentAgentBinding {
            identity,
            observed_at,
        })
    }

    pub(super) async fn begin(&self) -> Result<Transaction<'_, Postgres>, AgentDirectoryError> {
        let mut tx = self.store.pool().begin().await.map_err(database_error)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        sqlx::query("SET LOCAL lock_timeout='5s'")
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        sqlx::query("SET LOCAL statement_timeout='10s'")
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        Ok(tx)
    }

    /// Use existing membership/RBAC and hold the consulted rows through commit.
    /// No caller-created AuthorizationContext or cached permission list is used.
    pub(super) async fn authorize(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        organization_id: Uuid,
        principal: &ForwardedPrincipal,
        permission: &str,
    ) -> Result<String, AgentDirectoryError> {
        let ForwardedPrincipal::User { user_id } = principal else {
            return Err(AgentDirectoryError::AccessDenied);
        };
        if organization_id.is_nil() || user_id.is_empty() {
            return Err(AgentDirectoryError::AccessDenied);
        }
        let organization = sqlx::query(
            "SELECT status,owner_id FROM organization_service.organizations WHERE id=$1 FOR SHARE",
        )
        .bind(organization_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(database_error)?
        .ok_or(AgentDirectoryError::AccessDenied)?;
        if organization
            .try_get::<String, _>("status")
            .map_err(|_| AgentDirectoryError::CorruptData)?
            != "active"
        {
            return Err(AgentDirectoryError::AccessDenied);
        }
        let owner: Option<String> = organization
            .try_get("owner_id")
            .map_err(|_| AgentDirectoryError::CorruptData)?;
        let owner = owner
            .filter(|value| !value.is_empty())
            .ok_or(AgentDirectoryError::AccessDenied)?;
        let member = crate::locked_membership::load(&self.store, tx, user_id, organization_id)
            .await
            .map_err(|error| match error {
                crate::locked_membership::Error::MemberRead => AgentDirectoryError::Unavailable,
                crate::locked_membership::Error::RoleLock(error) => database_error(error),
            })?
            .ok_or(AgentDirectoryError::AccessDenied)?;
        authorize_forwarded_principal(organization_id, principal, permission, false, Some(&member))
            .map_err(|_| AgentDirectoryError::AccessDenied)?;
        Ok(owner)
    }

    async fn mutate(
        &self,
        organization_id: Uuid,
        principal: &ForwardedPrincipal,
        id: Option<Uuid>,
        mutation: Mutation,
    ) -> Result<AgentIdentity, AgentDirectoryError> {
        let ForwardedPrincipal::User { user_id } = principal else {
            return Err(AgentDirectoryError::AccessDenied);
        };
        if let Some(revision) = mutation.revision() {
            valid_revision(revision)?;
        }
        let mut tx = self.begin().await?;
        let owner = self
            .authorize(&mut tx, organization_id, principal, mutation.permission())
            .await?;
        let previous = match id {
            Some(id) => Some(load(&mut tx, organization_id, id, true).await?),
            None => None,
        };
        // Current auth is checked again after waiting for the identity row.
        self.authorize(&mut tx, organization_id, principal, mutation.permission())
            .await?;
        if let Some(previous) = &previous {
            if mutation.revision() != Some(previous.revision) {
                return Err(AgentDirectoryError::Conflict);
            }
        }
        let observed = now(&mut tx).await?;
        if previous
            .as_ref()
            .is_some_and(|old| observed <= old.updated_at)
        {
            return Err(AgentDirectoryError::Unavailable);
        }
        let mut next = if let Mutation::Register(request) = &mutation {
            let id = Uuid::new_v4();
            AgentIdentity {
                id,
                organization_id,
                owner_user_id: owner,
                created_by: user_id.clone(),
                kind: request.kind,
                status: match request.kind {
                    AgentKind::External => AgentIdentityStatus::Active,
                    AgentKind::Managed => AgentIdentityStatus::Provisioned,
                },
                revision: 1,
                metadata: AgentMetadata {
                    display_name: request.display_name.clone(),
                    description: request.description.clone(),
                    logical_application_ref: request.logical_application_ref.clone(),
                },
                principal: AgentPrincipal {
                    principal_type: match request.kind {
                        AgentKind::External => "EXTERNAL",
                        AgentKind::Managed => "SERVICE_ACCOUNT",
                    }
                    .into(),
                    id: format!("urn:marty:agent:{id}"),
                },
                issuer: request.issuer.clone(),
                subject: request.subject.clone(),
                runtime_instance_ref: request.runtime_instance_ref.clone(),
                keys: vec![public_key(&request.public_key_jwk, observed)?],
                provenance: AgentProvenance {
                    kind: "OPERATOR_DECLARATION".into(),
                    registered_by: user_id.clone(),
                    registration_ref: format!("urn:marty:agent-registration:{id}"),
                    managed_enrollment: "NOT_ASSESSED".into(),
                    external_authentication: "NOT_ASSESSED".into(),
                },
                authority_status: "NOT_ASSESSED".into(),
                created_at: observed,
                updated_at: observed,
            }
        } else {
            previous
                .clone()
                .ok_or(AgentDirectoryError::InvalidRequest)?
        };
        match &mutation {
            Mutation::Register(_) => {}
            Mutation::Metadata(request) => {
                if next.status.terminal() {
                    return Err(AgentDirectoryError::InvalidTransition);
                }
                next.metadata = AgentMetadata {
                    display_name: request.display_name.clone(),
                    description: request.description.clone(),
                    logical_application_ref: request.logical_application_ref.clone(),
                };
            }
            Mutation::Transition(action, _) => {
                next.status = action.apply(next.status)?;
                if next.status.terminal() {
                    next.keys.clear();
                }
            }
            Mutation::Rotate(request) => {
                if next.status.terminal() {
                    return Err(AgentDirectoryError::InvalidTransition);
                }
                let replacement = public_key(&request.public_key_jwk, observed)?;
                let reused:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organization_service.agent_identity_keys WHERE organization_id=$1 AND agent_id=$2 AND key_thumbprint=$3)")
                    .bind(organization_id).bind(next.id).bind(&replacement.fingerprint.value).fetch_one(&mut *tx).await.map_err(database_error)?;
                if reused {
                    return Err(AgentDirectoryError::Conflict);
                }
                next.keys = vec![replacement];
                if next.kind == AgentKind::Managed {
                    next.provenance.managed_enrollment = "NOT_ASSESSED".into();
                    if next.status == AgentIdentityStatus::Active {
                        next.status = AgentIdentityStatus::Provisioned;
                    }
                }
            }
        }
        if previous.is_some() {
            next.revision += 1;
            next.updated_at = observed;
        }
        if previous.is_some() {
            super::enrollment_store::invalidate_pending(
                &mut tx,
                organization_id,
                next.id,
                observed,
                "REVISION_CHANGED",
            )
            .await?;
        }
        validate_snapshot(&next)?;
        let document = serde_json::to_value(&next).map_err(|_| AgentDirectoryError::CorruptData)?;
        if let Some(previous) = &previous {
            let updated=sqlx::query("UPDATE organization_service.agent_identities SET status=$1,revision=$2,document=$3,updated_at=$4 WHERE organization_id=$5 AND id=$6 AND revision=$7")
                .bind(next.status.as_str()).bind(next.revision as i64).bind(&document).bind(observed).bind(organization_id).bind(next.id).bind(previous.revision as i64).execute(&mut *tx).await.map_err(database_error)?;
            if updated.rows_affected() != 1 {
                return Err(AgentDirectoryError::Conflict);
            }
        } else {
            sqlx::query("INSERT INTO organization_service.agent_identities (id,organization_id,kind,status,revision,issuer,subject,runtime_instance_ref,document,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10)")
                .bind(next.id).bind(organization_id).bind(next.kind.as_str()).bind(next.status.as_str()).bind(next.revision as i64).bind(&next.issuer).bind(&next.subject).bind(&next.runtime_instance_ref).bind(&document).bind(observed).execute(&mut *tx).await.map_err(database_error)?;
        }
        if matches!(mutation, Mutation::Rotate(_)) || next.status.terminal() {
            sqlx::query("UPDATE organization_service.agent_identity_keys SET status=$1,ended_at=$2 WHERE organization_id=$3 AND agent_id=$4 AND status='ACTIVE'")
                .bind(if next.status==AgentIdentityStatus::Revoked { "REVOKED" } else { "RETIRED" }).bind(observed).bind(organization_id).bind(next.id).execute(&mut *tx).await.map_err(database_error)?;
        }
        if matches!(mutation, Mutation::Register(_) | Mutation::Rotate(_)) {
            let key = next.keys.first().ok_or(AgentDirectoryError::CorruptData)?;
            sqlx::query("INSERT INTO organization_service.agent_identity_keys (key_id,organization_id,agent_id,algorithm,status,key_thumbprint,public_key_jwk,created_at) VALUES ($1,$2,$3,$4,'ACTIVE',$5,$6,$7)")
                .bind(key.key_id).bind(organization_id).bind(next.id).bind(&key.algorithm).bind(&key.fingerprint.value).bind(&key.public_key_jwk).bind(observed).execute(&mut *tx).await.map_err(database_error)?;
        }
        let request_id = self.request_id.unwrap_or_else(Uuid::new_v4);
        sqlx::query("INSERT INTO organization_service.agent_identity_history (organization_id,agent_id,revision,action,actor_user_id,request_id,occurred_at,snapshot) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(organization_id).bind(next.id).bind(next.revision as i64).bind(mutation.action()).bind(user_id).bind(request_id).bind(observed).bind(&document).execute(&mut *tx).await.map_err(database_error)?;
        self.store.save_audit_event_in_transaction(&mut tx,&AuditEvent {
            id:Uuid::new_v4(),organization_id,event_type:"agent_identity.changed".into(),action:mutation.action().into(),category:"identity".into(),resource_type:"agent-identity".into(),resource_id:Some(next.id.to_string()),resource_name:Some(next.metadata.display_name.clone()),actor_id:Some(user_id.clone()),actor_type:"USER".into(),severity:"INFO".into(),message:"Agent identity directory changed".into(),changes:None,metadata:json!({"revision":next.revision,"request_id":request_id,"authority_status":"NOT_ASSESSED"}),timestamp:observed,
        }).await.map_err(|_|AgentDirectoryError::Unavailable)?;
        self.authorize(&mut tx, organization_id, principal, mutation.permission())
            .await?;
        if now(&mut tx).await? < observed {
            return Err(AgentDirectoryError::Unavailable);
        }
        tx.commit().await.map_err(database_error)?;
        Ok(next)
    }
}

fn paging(limit: u32, offset: u32) -> Result<(), AgentDirectoryError> {
    if limit == 0 || limit > 200 || offset > 1_000_000 {
        return Err(AgentDirectoryError::InvalidRequest);
    }
    Ok(())
}
pub(super) async fn now(
    connection: &mut PgConnection,
) -> Result<DateTime<Utc>, AgentDirectoryError> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(connection)
        .await
        .map_err(database_error)
}
pub(super) async fn load(
    connection: &mut PgConnection,
    organization: Uuid,
    id: Uuid,
    lock: bool,
) -> Result<AgentIdentity, AgentDirectoryError> {
    let query = if lock {
        "SELECT id,organization_id,kind,status,revision,issuer,subject,runtime_instance_ref,created_at,updated_at,document FROM organization_service.agent_identities WHERE organization_id=$1 AND id=$2 FOR UPDATE"
    } else {
        "SELECT id,organization_id,kind,status,revision,issuer,subject,runtime_instance_ref,created_at,updated_at,document FROM organization_service.agent_identities WHERE organization_id=$1 AND id=$2"
    };
    let row = sqlx::query(query)
        .bind(organization)
        .bind(id)
        .fetch_optional(connection)
        .await
        .map_err(database_error)?
        .ok_or(AgentDirectoryError::NotFound)?;
    decode_row(row)
}
fn decode_row(row: sqlx::postgres::PgRow) -> Result<AgentIdentity, AgentDirectoryError> {
    let invalid = || AgentDirectoryError::CorruptData;
    let result: AgentIdentity =
        serde_json::from_value(row.try_get("document").map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
    validate_snapshot(&result)?;
    if result.id != row.try_get::<Uuid, _>("id").map_err(|_| invalid())?
        || result.organization_id
            != row
                .try_get::<Uuid, _>("organization_id")
                .map_err(|_| invalid())?
        || result.kind.as_str() != row.try_get::<String, _>("kind").map_err(|_| invalid())?
        || result.status.as_str() != row.try_get::<String, _>("status").map_err(|_| invalid())?
        || result.revision as i64 != row.try_get::<i64, _>("revision").map_err(|_| invalid())?
        || result.issuer != row.try_get::<String, _>("issuer").map_err(|_| invalid())?
        || result.subject != row.try_get::<String, _>("subject").map_err(|_| invalid())?
        || result.runtime_instance_ref
            != row
                .try_get::<String, _>("runtime_instance_ref")
                .map_err(|_| invalid())?
        || result.created_at
            != row
                .try_get::<DateTime<Utc>, _>("created_at")
                .map_err(|_| invalid())?
        || result.updated_at
            != row
                .try_get::<DateTime<Utc>, _>("updated_at")
                .map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    Ok(result)
}
