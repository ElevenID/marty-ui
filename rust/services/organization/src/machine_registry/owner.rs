use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::{postgres::PgRow, PgConnection, Postgres, Row, Transaction};
use uuid::Uuid;

use super::{
    database_error,
    domain::{digest, valid_revision, Projection, ValidatedDocuments},
    MachineRegistryDocuments, MachineRegistryError as Error, MachineRegistryLifecycle,
    MachineRegistryRecord,
};
use crate::{
    authorize_forwarded_principal, postgres::PostgresOrganizationStore, AuditEvent,
    ForwardedPrincipal,
};

#[derive(Clone)]
pub struct MachineRegistryService {
    store: PostgresOrganizationStore,
}

impl MachineRegistryService {
    pub fn new(store: PostgresOrganizationStore) -> Self {
        Self { store }
    }

    /// Publish a distinct full machine and deployment selection. Requires a
    /// current human identity administrator and MAP assignment permission.
    /// Nothing is copied from agent inventory or enrollment.
    pub async fn register(
        &self,
        organization: Uuid,
        principal: &ForwardedPrincipal,
        documents: MachineRegistryDocuments,
    ) -> Result<MachineRegistryRecord, Error> {
        let mut tx = self.begin().await?;
        let actor = self
            .authorize_publication(&mut tx, organization, principal, "machine-identity:create")
            .await?;
        let now = database_now(&mut tx).await?;
        let validated = documents.validate(organization, now)?;
        let p = &validated.projection;
        sqlx::query("INSERT INTO organization_service.machine_registry_entries
            (organization_id,machine_identity_id,deployment_profile_id,principal_id,runtime_instance_ref,
             key_id,key_thumbprint,policy_id,policy_digest,status,revision,documents,document_bytes,document_digest,
             documents_recorded_at,created_by,created_at,updated_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'ACTIVE',1,$10,$11,$12,$13,$14,$13,$13)")
            .bind(organization).bind(p.machine_identity_id).bind(p.deployment_profile_id)
            .bind(&p.principal_id).bind(&p.runtime_instance_ref).bind(&p.key_id).bind(&p.key_thumbprint)
            .bind(p.policy_id).bind(&p.policy_digest).bind(&validated.document).bind(&validated.bytes)
            .bind(&validated.digest).bind(now).bind(&actor).execute(&mut *tx).await.map_err(database_error)?;
        let result = load(&mut tx, organization, p.machine_identity_id, false).await?;
        self.history_and_audit(&mut tx, &result, &actor, "REGISTER")
            .await?;
        self.authorize_publication(&mut tx, organization, principal, "machine-identity:create")
            .await?;
        ensure_clock(&mut tx, now).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(result)
    }

    /// Explicitly replace current key/registered credentials/MAP selection.
    /// Identity, authentication source, runtime, deployment and creation
    /// provenance stay fixed. An old grant is never retargeted to a new key.
    pub async fn replace(
        &self,
        organization: Uuid,
        principal: &ForwardedPrincipal,
        machine: Uuid,
        expected_revision: u64,
        documents: MachineRegistryDocuments,
    ) -> Result<MachineRegistryRecord, Error> {
        if !valid_revision(expected_revision) {
            return Err(Error::InvalidRequest);
        }
        let mut tx = self.begin().await?;
        let actor = self
            .authorize_publication(&mut tx, organization, principal, "machine-identity:update")
            .await?;
        let previous = load(&mut tx, organization, machine, true).await?;
        // Rehydrate the current permission decision after every possible row wait.
        self.authorize_publication(&mut tx, organization, principal, "machine-identity:update")
            .await?;
        if previous.revision != expected_revision {
            return Err(Error::Conflict);
        }
        if previous.status != "ACTIVE" {
            return Err(Error::InvalidTransition);
        }
        let now = database_now(&mut tx).await?;
        if now <= previous.updated_at {
            return Err(Error::Unavailable);
        }
        let next = documents.validate(organization, now)?;
        validate_replacement(&previous, &next)?;
        let p = &next.projection;
        let changed = sqlx::query(
            "UPDATE organization_service.machine_registry_entries SET
            key_id=$1,key_thumbprint=$2,policy_id=$3,policy_digest=$4,revision=revision+1,
            documents=$5,document_bytes=$6,document_digest=$7,documents_recorded_at=$8,updated_at=$8
            WHERE organization_id=$9 AND machine_identity_id=$10 AND revision=$11",
        )
        .bind(&p.key_id)
        .bind(&p.key_thumbprint)
        .bind(p.policy_id)
        .bind(&p.policy_digest)
        .bind(&next.document)
        .bind(&next.bytes)
        .bind(&next.digest)
        .bind(now)
        .bind(organization)
        .bind(machine)
        .bind(expected_revision as i64)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        if changed.rows_affected() != 1 {
            return Err(Error::Conflict);
        }
        let result = load(&mut tx, organization, machine, false).await?;
        self.history_and_audit(&mut tx, &result, &actor, "REPLACE")
            .await?;
        self.authorize_publication(&mut tx, organization, principal, "machine-identity:update")
            .await?;
        ensure_clock(&mut tx, now).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(result)
    }

    pub async fn transition(
        &self,
        organization: Uuid,
        principal: &ForwardedPrincipal,
        machine: Uuid,
        expected_revision: u64,
        action: MachineRegistryLifecycle,
    ) -> Result<MachineRegistryRecord, Error> {
        if !valid_revision(expected_revision) {
            return Err(Error::InvalidRequest);
        }
        let mut tx = self.begin().await?;
        let actor = self
            .authorize(&mut tx, organization, principal, action.permission())
            .await?;
        let previous = load(&mut tx, organization, machine, true).await?;
        self.authorize(&mut tx, organization, principal, action.permission())
            .await?;
        if previous.revision != expected_revision {
            return Err(Error::Conflict);
        }
        if !action.allowed(&previous.status) {
            return Err(Error::InvalidTransition);
        }
        let now = database_now(&mut tx).await?;
        if now <= previous.updated_at {
            return Err(Error::Unavailable);
        }
        sqlx::query("UPDATE organization_service.machine_registry_entries SET status=$1,revision=revision+1,updated_at=$2
            WHERE organization_id=$3 AND machine_identity_id=$4 AND revision=$5")
            .bind(action.status()).bind(now).bind(organization).bind(machine).bind(expected_revision as i64)
            .execute(&mut *tx).await.map_err(database_error)?;
        let result = load(&mut tx, organization, machine, false).await?;
        self.history_and_audit(&mut tx, &result, &actor, action.action())
            .await?;
        self.authorize(&mut tx, organization, principal, action.permission())
            .await?;
        ensure_clock(&mut tx, now).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(result)
    }

    pub async fn inspect(
        &self,
        organization: Uuid,
        principal: &ForwardedPrincipal,
        machine: Uuid,
    ) -> Result<MachineRegistryRecord, Error> {
        let mut tx = self.begin().await?;
        self.authorize(&mut tx, organization, principal, "machine-identity:view")
            .await?;
        let result = load(&mut tx, organization, machine, false).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(result)
    }

    async fn begin(&self) -> Result<Transaction<'_, Postgres>, Error> {
        let mut tx = self.store.pool().begin().await.map_err(database_error)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        sqlx::query("SET LOCAL TIME ZONE 'UTC'")
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

    async fn authorize_publication(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        organization: Uuid,
        principal: &ForwardedPrincipal,
        permission: &str,
    ) -> Result<String, Error> {
        let actor = self
            .authorize(tx, organization, principal, permission)
            .await?;
        self.authorize(
            tx,
            organization,
            principal,
            "machine-authentication-policy:assign",
        )
        .await?;
        Ok(actor)
    }

    /// Organization/member/role/permission rows remain locked through commit.
    /// This uses the real current owner, not caller-supplied role names.
    async fn authorize(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        organization: Uuid,
        principal: &ForwardedPrincipal,
        permission: &str,
    ) -> Result<String, Error> {
        let ForwardedPrincipal::User { user_id } = principal else {
            return Err(Error::AccessDenied);
        };
        if organization.is_nil()
            || user_id.is_empty()
            || user_id.len() > 255
            || user_id.chars().any(char::is_control)
        {
            return Err(Error::AccessDenied);
        }
        let organization_status: Option<String> = sqlx::query_scalar(
            "SELECT status FROM organization_service.organizations WHERE id=$1 FOR SHARE",
        )
        .bind(organization)
        .fetch_optional(&mut **tx)
        .await
        .map_err(database_error)?;
        if organization_status.as_deref() != Some("active") {
            return Err(Error::AccessDenied);
        }
        let member = crate::locked_membership::load(&self.store, tx, user_id, organization)
            .await
            .map_err(|error| match error {
                crate::locked_membership::Error::MemberRead => Error::Unavailable,
                crate::locked_membership::Error::RoleLock(error) => database_error(error),
            })?
            .ok_or(Error::AccessDenied)?;
        authorize_forwarded_principal(organization, principal, permission, false, Some(&member))
            .map_err(|_| Error::AccessDenied)?;
        Ok(user_id.clone())
    }

    async fn history_and_audit(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        record: &MachineRegistryRecord,
        actor: &str,
        action: &str,
    ) -> Result<(), Error> {
        let request_id = Uuid::new_v4();
        sqlx::query("INSERT INTO organization_service.machine_registry_history
            (organization_id,machine_identity_id,revision,action,actor_user_id,request_id,occurred_at,snapshot)
            SELECT organization_id,machine_identity_id,revision,$3,$4,$5,updated_at,to_jsonb(r)
            FROM organization_service.machine_registry_entries r WHERE organization_id=$1 AND machine_identity_id=$2")
            .bind(record.organization_id()).bind(record.machine_identity_id()).bind(action).bind(actor).bind(request_id)
            .execute(&mut **tx).await.map_err(database_error)?;
        self.store.save_audit_event_in_transaction(tx, &AuditEvent {
            id: Uuid::new_v4(), organization_id: record.organization_id(), event_type: "machine_registry.changed".into(),
            action: action.into(), category: "identity".into(), resource_type: "machine-identity".into(),
            resource_id: Some(record.machine_identity_id().to_string()), resource_name: None,
            actor_id: Some(actor.into()), actor_type: "USER".into(), severity: "INFO".into(),
            message: "Full machine registry selection changed".into(), changes: None,
            metadata: json!({"revision":record.revision,"request_id":request_id,
                "document_digest":record.document_digest,"authentication":"NOT_ESTABLISHED","authority":"NOT_ASSESSED"}),
            timestamp: record.updated_at,
        }).await.map_err(|_| Error::Unavailable)?;
        Ok(())
    }
}

fn validate_replacement(
    previous: &MachineRegistryRecord,
    next: &ValidatedDocuments,
) -> Result<(), Error> {
    let old = &previous.projection;
    let p = &next.projection;
    if p.organization_id != old.organization_id
        || p.machine_identity_id != old.machine_identity_id
        || p.deployment_profile_id != old.deployment_profile_id
        || p.principal_id != old.principal_id
        || p.runtime_instance_ref != old.runtime_instance_ref
        || previous.documents["machine_identity"]["machine_id"]
            != next.document["machine_identity"]["machine_id"]
        || previous.documents["machine_identity"]["created_at"]
            != next.document["machine_identity"]["created_at"]
        || (p.key_id == old.key_id && p.key_thumbprint != old.key_thumbprint)
        || previous.document_digest == next.digest
    {
        return Err(Error::InvalidRequest);
    }
    Ok(())
}

pub(crate) async fn database_now(connection: &mut PgConnection) -> Result<DateTime<Utc>, Error> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(connection)
        .await
        .map_err(database_error)
}
async fn ensure_clock(connection: &mut PgConnection, original: DateTime<Utc>) -> Result<(), Error> {
    if database_now(connection).await? < original {
        return Err(Error::Unavailable);
    }
    Ok(())
}
pub(crate) async fn load(
    connection: &mut PgConnection,
    organization: Uuid,
    machine: Uuid,
    lock: bool,
) -> Result<MachineRegistryRecord, Error> {
    let sql = if lock {
        "SELECT * FROM organization_service.machine_registry_entries WHERE organization_id=$1 AND machine_identity_id=$2 FOR UPDATE"
    } else {
        "SELECT * FROM organization_service.machine_registry_entries WHERE organization_id=$1 AND machine_identity_id=$2"
    };
    decode(
        sqlx::query(sql)
            .bind(organization)
            .bind(machine)
            .fetch_optional(connection)
            .await
            .map_err(database_error)?
            .ok_or(Error::NotFound)?,
    )
}

pub(crate) fn decode(row: PgRow) -> Result<MachineRegistryRecord, Error> {
    let invalid = |_| Error::CorruptData;
    let projection = Projection {
        organization_id: row.try_get("organization_id").map_err(invalid)?,
        machine_identity_id: row.try_get("machine_identity_id").map_err(invalid)?,
        deployment_profile_id: row.try_get("deployment_profile_id").map_err(invalid)?,
        principal_id: row.try_get("principal_id").map_err(invalid)?,
        runtime_instance_ref: row.try_get("runtime_instance_ref").map_err(invalid)?,
        key_id: row.try_get("key_id").map_err(invalid)?,
        key_thumbprint: row.try_get("key_thumbprint").map_err(invalid)?,
        policy_id: row.try_get("policy_id").map_err(invalid)?,
        policy_digest: row.try_get("policy_digest").map_err(invalid)?,
    };
    let document: Value = row.try_get("documents").map_err(invalid)?;
    let bytes: Vec<u8> = row.try_get("document_bytes").map_err(invalid)?;
    let document_digest: String = row.try_get("document_digest").map_err(invalid)?;
    let documents_recorded_at = row.try_get("documents_recorded_at").map_err(invalid)?;
    let validated = MachineRegistryDocuments::from_document(&document)?
        .validate(projection.organization_id, documents_recorded_at)
        .map_err(|_| Error::CorruptData)?;
    let revision: i64 = row.try_get("revision").map_err(invalid)?;
    let status: String = row.try_get("status").map_err(invalid)?;
    let created_at = row.try_get("created_at").map_err(invalid)?;
    let updated_at = row.try_get("updated_at").map_err(invalid)?;
    if validated.projection != projection
        || validated.document != document
        || digest(&bytes) != document_digest
        || serde_json::from_slice::<Value>(&bytes).map_err(|_| Error::CorruptData)? != document
        || revision <= 0
        || !valid_revision(revision as u64)
        || !matches!(
            status.as_str(),
            "ACTIVE" | "SUSPENDED" | "REVOKED" | "RETIRED"
        )
        || created_at > documents_recorded_at
        || documents_recorded_at > updated_at
    {
        return Err(Error::CorruptData);
    }
    Ok(MachineRegistryRecord {
        projection,
        status,
        revision: revision as u64,
        documents: document,
        document_bytes: bytes,
        document_digest,
        documents_recorded_at,
        created_by: row.try_get("created_by").map_err(invalid)?,
        created_at,
        updated_at,
    })
}
