use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::{PgConnection, Postgres, Row, Transaction};
use uuid::Uuid;

use super::{
    database_error, digest, unavailable, valid_revision, Error, MachineUseAccessInput,
    MachineUseAccessRecord,
};
use crate::{
    authorize_forwarded_principal, postgres::PostgresOrganizationStore, AuditEvent,
    ForwardedPrincipal,
};

#[derive(Clone)]
pub struct MachineUseAccessOwner {
    store: PostgresOrganizationStore,
}
impl MachineUseAccessOwner {
    pub fn new(store: PostgresOrganizationStore) -> Self {
        Self { store }
    }

    pub async fn grant(
        &self,
        organization: Uuid,
        principal: &ForwardedPrincipal,
        machine: Uuid,
        input: MachineUseAccessInput,
    ) -> Result<MachineUseAccessRecord, Error> {
        input.validate()?;
        if machine.is_nil() {
            return Err(Error::Invalid);
        }
        let mut tx = self.begin().await?;
        let actor = self
            .authorize(
                &mut tx,
                organization,
                principal,
                "machine-use-access:create",
            )
            .await?;
        let registry=sqlx::query("SELECT principal_id,deployment_profile_id,status FROM organization_service.machine_registry_entries WHERE organization_id=$1 AND machine_identity_id=$2 FOR SHARE")
            .bind(organization).bind(machine).fetch_optional(&mut *tx).await.map_err(database_error)?.ok_or(Error::AccessDenied)?;
        self.authorize(
            &mut tx,
            organization,
            principal,
            "machine-use-access:create",
        )
        .await?;
        if registry
            .try_get::<String, _>("status")
            .map_err(unavailable)?
            != "ACTIVE"
        {
            return Err(Error::AccessDenied);
        }
        let now = database_now(&mut tx).await?;
        if input.valid_until <= now {
            return Err(Error::Invalid);
        }
        let mut permissions = input.permissions;
        permissions.sort();
        let record = MachineUseAccessRecord {
            organization_id: organization,
            machine_identity_id: machine,
            deployment_profile_id: registry
                .try_get("deployment_profile_id")
                .map_err(unavailable)?,
            principal_id: registry.try_get("principal_id").map_err(unavailable)?,
            revision: 1,
            status: "ACTIVE".into(),
            permissions,
            valid_from: input.valid_from,
            valid_until: input.valid_until,
            created_by: actor.clone(),
            created_at: now,
            updated_at: now,
        };
        self.write(&mut tx, &record, true).await?;
        self.history_and_audit(&mut tx, &record, &actor, "GRANT")
            .await?;
        self.authorize(
            &mut tx,
            organization,
            principal,
            "machine-use-access:create",
        )
        .await?;
        if database_now(&mut tx).await? < now {
            return Err(Error::Unavailable);
        }
        tx.commit().await.map_err(database_error)?;
        Ok(record)
    }

    pub async fn replace(
        &self,
        organization: Uuid,
        principal: &ForwardedPrincipal,
        machine: Uuid,
        expected_revision: u64,
        input: MachineUseAccessInput,
    ) -> Result<MachineUseAccessRecord, Error> {
        input.validate()?;
        self.mutate(
            organization,
            principal,
            machine,
            expected_revision,
            Some(input),
        )
        .await
    }
    pub async fn revoke(
        &self,
        organization: Uuid,
        principal: &ForwardedPrincipal,
        machine: Uuid,
        expected_revision: u64,
    ) -> Result<MachineUseAccessRecord, Error> {
        self.mutate(organization, principal, machine, expected_revision, None)
            .await
    }
    async fn mutate(
        &self,
        organization: Uuid,
        principal: &ForwardedPrincipal,
        machine: Uuid,
        expected_revision: u64,
        input: Option<MachineUseAccessInput>,
    ) -> Result<MachineUseAccessRecord, Error> {
        if machine.is_nil()
            || !valid_revision(expected_revision)
            || expected_revision == 9_007_199_254_740_991
        {
            return Err(Error::Invalid);
        }
        let permission = if input.is_some() {
            "machine-use-access:update"
        } else {
            "machine-use-access:revoke"
        };
        let mut tx = self.begin().await?;
        let actor = self
            .authorize(&mut tx, organization, principal, permission)
            .await?;
        // Registry precedes access-row locks, matching creation and DB guard order.
        let status:Option<String>=sqlx::query_scalar("SELECT status FROM organization_service.machine_registry_entries WHERE organization_id=$1 AND machine_identity_id=$2 FOR SHARE")
            .bind(organization).bind(machine).fetch_optional(&mut *tx).await.map_err(database_error)?;
        if status.is_none() || (input.is_some() && status.as_deref() != Some("ACTIVE")) {
            return Err(Error::AccessDenied);
        }
        let (mut record, _, _) = load(&mut tx, organization, machine, true).await?;
        self.authorize(&mut tx, organization, principal, permission)
            .await?;
        if record.revision != expected_revision || record.status != "ACTIVE" {
            return Err(Error::Conflict);
        }
        let now = database_now(&mut tx).await?;
        if now <= record.updated_at {
            return Err(Error::Unavailable);
        }
        let action = if let Some(input) = input {
            if input.valid_until <= now {
                return Err(Error::Invalid);
            }
            record.permissions = input.permissions;
            record.permissions.sort();
            record.valid_from = input.valid_from;
            record.valid_until = input.valid_until;
            "REPLACE"
        } else {
            record.status = "REVOKED".into();
            "REVOKE"
        };
        record.revision += 1;
        record.updated_at = now;
        self.write(&mut tx, &record, false).await?;
        self.history_and_audit(&mut tx, &record, &actor, action)
            .await?;
        self.authorize(&mut tx, organization, principal, permission)
            .await?;
        if database_now(&mut tx).await? < now {
            return Err(Error::Unavailable);
        }
        tx.commit().await.map_err(database_error)?;
        Ok(record)
    }

    pub async fn inspect(
        &self,
        organization: Uuid,
        principal: &ForwardedPrincipal,
        machine: Uuid,
    ) -> Result<MachineUseAccessRecord, Error> {
        let mut tx = self.begin().await?;
        self.authorize(&mut tx, organization, principal, "machine-use-access:view")
            .await?;
        let (record, _, _) = load(&mut tx, organization, machine, false).await?;
        self.authorize(&mut tx, organization, principal, "machine-use-access:view")
            .await?;
        tx.commit().await.map_err(database_error)?;
        Ok(record)
    }
    async fn begin(&self) -> Result<Transaction<'_, Postgres>, Error> {
        let mut tx = self.store.pool().begin().await.map_err(database_error)?;
        sqlx::raw_sql("SET TRANSACTION ISOLATION LEVEL READ COMMITTED; SET LOCAL TIME ZONE 'UTC'; SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='10s'")
            .execute(&mut *tx).await.map_err(database_error)?;
        Ok(tx)
    }
    async fn write(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        r: &MachineUseAccessRecord,
        create: bool,
    ) -> Result<(), Error> {
        r.validate()?;
        let bytes = serde_json::to_vec(r).map_err(unavailable)?;
        let snapshot = serde_json::to_value(r).map_err(unavailable)?;
        let digest = digest(&bytes);
        let permissions: Vec<&str> = r.permissions.iter().map(|p| p.as_str()).collect();
        let sql = if create {
            "INSERT INTO organization_service.machine_use_access (organization_id,machine_identity_id,deployment_profile_id,principal_id,revision,status,permissions,valid_from,valid_until,snapshot,snapshot_bytes,snapshot_digest,created_by,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)"
        } else {
            "UPDATE organization_service.machine_use_access SET deployment_profile_id=$3,principal_id=$4,revision=$5,status=$6,permissions=$7,valid_from=$8,valid_until=$9,snapshot=$10,snapshot_bytes=$11,snapshot_digest=$12,created_by=$13,created_at=$14,updated_at=$15 WHERE organization_id=$1 AND machine_identity_id=$2 AND revision=$5-1"
        };
        let outcome = sqlx::query(sql)
            .bind(r.organization_id)
            .bind(r.machine_identity_id)
            .bind(r.deployment_profile_id)
            .bind(&r.principal_id)
            .bind(r.revision as i64)
            .bind(&r.status)
            .bind(permissions)
            .bind(r.valid_from)
            .bind(r.valid_until)
            .bind(snapshot)
            .bind(bytes)
            .bind(digest)
            .bind(&r.created_by)
            .bind(r.created_at)
            .bind(r.updated_at)
            .execute(&mut **tx)
            .await
            .map_err(database_error)?;
        if outcome.rows_affected() != 1 {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    async fn history_and_audit(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        r: &MachineUseAccessRecord,
        actor: &str,
        action: &str,
    ) -> Result<(), Error> {
        let request_id = Uuid::new_v4();
        sqlx::query("INSERT INTO organization_service.machine_use_access_history (organization_id,machine_identity_id,revision,action,actor_user_id,request_id,occurred_at,snapshot,snapshot_bytes,snapshot_digest) SELECT organization_id,machine_identity_id,revision,$3,$4,$5,updated_at,snapshot,snapshot_bytes,snapshot_digest FROM organization_service.machine_use_access WHERE organization_id=$1 AND machine_identity_id=$2")
            .bind(r.organization_id).bind(r.machine_identity_id).bind(action).bind(actor).bind(request_id).execute(&mut **tx).await.map_err(database_error)?;
        self.store.save_audit_event_in_transaction(tx,&AuditEvent {
            id:Uuid::new_v4(),organization_id:r.organization_id,event_type:"machine_use_access.changed".into(),action:action.into(),category:"access".into(),
            resource_type:"machine-use-access".into(),resource_id:Some(r.machine_identity_id.to_string()),resource_name:None,
            actor_id:Some(actor.into()),actor_type:"USER".into(),severity:"INFO".into(),message:"Full machine use access changed".into(),changes:None,
            metadata:json!({"request_id":request_id,"revision":r.revision,"snapshot_digest":digest(&serde_json::to_vec(r).map_err(unavailable)?),"domain_authorization":"NOT_ESTABLISHED"}),timestamp:r.updated_at,
        }).await.map_err(unavailable)?;
        Ok(())
    }
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
}

pub(super) async fn database_now(connection: &mut PgConnection) -> Result<DateTime<Utc>, Error> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(connection)
        .await
        .map_err(database_error)
}
pub(super) async fn load(
    connection: &mut PgConnection,
    organization: Uuid,
    machine: Uuid,
    lock: bool,
) -> Result<(MachineUseAccessRecord, Vec<u8>, String), Error> {
    let query = if lock {
        "SELECT * FROM organization_service.machine_use_access WHERE organization_id=$1 AND machine_identity_id=$2 FOR UPDATE"
    } else {
        "SELECT * FROM organization_service.machine_use_access WHERE organization_id=$1 AND machine_identity_id=$2"
    };
    let row = sqlx::query(query)
        .bind(organization)
        .bind(machine)
        .fetch_optional(connection)
        .await
        .map_err(database_error)?
        .ok_or(Error::AccessDenied)?;
    decode(&row)
}
pub(super) fn decode(
    row: &sqlx::postgres::PgRow,
) -> Result<(MachineUseAccessRecord, Vec<u8>, String), Error> {
    let bytes: Vec<u8> = row.try_get("snapshot_bytes").map_err(unavailable)?;
    let r: MachineUseAccessRecord = serde_json::from_slice(&bytes).map_err(unavailable)?;
    r.validate()?;
    let stored_digest: String = row.try_get("snapshot_digest").map_err(unavailable)?;
    let stored: Value = row.try_get("snapshot").map_err(unavailable)?;
    let permissions: Vec<String> = row.try_get("permissions").map_err(unavailable)?;
    if digest(&bytes) != stored_digest
        || serde_json::to_value(&r).map_err(unavailable)? != stored
        || row
            .try_get::<Uuid, _>("organization_id")
            .map_err(unavailable)?
            != r.organization_id
        || row
            .try_get::<Uuid, _>("machine_identity_id")
            .map_err(unavailable)?
            != r.machine_identity_id
        || row
            .try_get::<Uuid, _>("deployment_profile_id")
            .map_err(unavailable)?
            != r.deployment_profile_id
        || row
            .try_get::<String, _>("principal_id")
            .map_err(unavailable)?
            != r.principal_id
        || row.try_get::<i64, _>("revision").map_err(unavailable)? != r.revision as i64
        || row.try_get::<String, _>("status").map_err(unavailable)? != r.status
        || permissions
            != r.permissions
                .iter()
                .map(|p| p.as_str().to_owned())
                .collect::<Vec<_>>()
        || row
            .try_get::<DateTime<Utc>, _>("valid_from")
            .map_err(unavailable)?
            != r.valid_from
        || row
            .try_get::<DateTime<Utc>, _>("valid_until")
            .map_err(unavailable)?
            != r.valid_until
        || row
            .try_get::<String, _>("created_by")
            .map_err(unavailable)?
            != r.created_by
        || row
            .try_get::<DateTime<Utc>, _>("created_at")
            .map_err(unavailable)?
            != r.created_at
        || row
            .try_get::<DateTime<Utc>, _>("updated_at")
            .map_err(unavailable)?
            != r.updated_at
    {
        return Err(Error::Unavailable);
    }
    Ok((r, bytes, stored_digest))
}
