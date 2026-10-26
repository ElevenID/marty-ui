//! Transactional cancellation and immutable administrative history.

use super::*;
use crate::passport_cancellation::{cancellable, CancellationAudit, CancellationCommand};

#[derive(Debug, thiserror::Error)]
pub(crate) enum CancellationError {
    #[error("physical document repository failed")]
    Storage(#[from] sqlx::Error),
    #[error("physical document job not found")]
    NotFound,
    #[error("physical document cannot be administratively cancelled in its current state")]
    StateConflict,
    #[error("physical document cancellation key is bound to another request")]
    ReplayConflict,
}

pub(crate) struct CancellationOutcome {
    pub job: PassportJob,
    pub audit: CancellationAudit,
    pub replayed: bool,
}

fn audit(row: &PgRow) -> Result<CancellationAudit, sqlx::Error> {
    Ok(CancellationAudit {
        event_id: row.try_get("event_id")?,
        job_id: row.try_get("job_id")?,
        organization_id: row.try_get("organization_id")?,
        prior_status: row.try_get("prior_status")?,
        reason_code: row.try_get("reason_code")?,
        reason: row.try_get("reason")?,
        actor_kind: row.try_get("actor_kind")?,
        actor_organization_id: row.try_get("actor_organization_id")?,
        recorded_at: row.try_get("recorded_at")?,
        bureau_cancellation_requested: row.try_get("bureau_cancellation_requested")?,
        key_hash: row.try_get("idempotency_key_hash")?,
        request_hash: row.try_get("request_hash")?,
    })
}

impl PostgresPassportRepository {
    pub(crate) async fn cancel_administratively(
        &self,
        principal: &PassportTenantPrincipal,
        application_id: &str,
        command: &CancellationCommand,
        now: DateTime<Utc>,
    ) -> Result<CancellationOutcome, CancellationError> {
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT * FROM issuance_service.physical_document_jobs
             WHERE organization_id=$1 AND application_id=$2 AND id=$3 FOR UPDATE",
        )
        .bind(principal.organization_id())
        .bind(application_id)
        .bind(&command.job_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(CancellationError::NotFound)?;
        let job = row_to_job(&row)?;
        let existing = sqlx::query(
            "SELECT * FROM issuance_service.passport_job_administrative_cancellations
             WHERE organization_id=$1 AND job_id=$2",
        )
        .bind(principal.organization_id())
        .bind(&job.id)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(existing) = existing {
            let audit = audit(&existing)?;
            if job.status != "CANCELLED"
                || audit.key_hash != command.key_hash
                || audit.request_hash != command.request_hash
            {
                return Err(CancellationError::ReplayConflict);
            }
            transaction.commit().await?;
            return Ok(CancellationOutcome {
                job,
                audit,
                replayed: true,
            });
        }
        // Do not clear an unresolved wire-send reservation. The existing intent
        // trigger also refuses that mutation; its reconciliation remains separate.
        if !cancellable(&job.status) || job.submission_intent_id.is_some() {
            return Err(CancellationError::StateConflict);
        }
        let record = sqlx::query(
            "INSERT INTO issuance_service.passport_job_administrative_cancellations
             (event_id,job_id,organization_id,prior_status,reason_code,reason,
              actor_kind,actor_organization_id,recorded_at,idempotency_key_hash,
              request_hash,bureau_cancellation_requested)
             VALUES ($1,$2,$3,$4,'ADMINISTRATIVE_ABANDONMENT',$5,
                     'AUTHENTICATED_PASSPORT_TENANT',$3,$6,$7,$8,false) RETURNING *",
        )
        .bind(Uuid::new_v4())
        .bind(&job.id)
        .bind(principal.organization_id())
        .bind(&job.status)
        .bind(&command.reason)
        .bind(now)
        .bind(&command.key_hash)
        .bind(&command.request_hash)
        .fetch_one(&mut *transaction)
        .await?;
        // These are the only job columns modified. Neither completed_at nor any
        // quality, bureau, material or reservation field is fabricated/cleared.
        let row = sqlx::query(
            "UPDATE issuance_service.physical_document_jobs
             SET status='CANCELLED',updated_at=$4
             WHERE organization_id=$1 AND application_id=$2 AND id=$3
               AND status=$5 AND submission_intent_id IS NULL RETURNING *",
        )
        .bind(principal.organization_id())
        .bind(application_id)
        .bind(&job.id)
        .bind(now)
        .bind(&job.status)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(CancellationError::StateConflict)?;
        let outcome = CancellationOutcome {
            job: row_to_job(&row)?,
            audit: audit(&record)?,
            replayed: false,
        };
        transaction.commit().await?;
        Ok(outcome)
    }
}

pub(crate) async fn validate_schema(connection: &mut PgConnection) -> Result<(), sqlx::Error> {
    let columns = sqlx::query(
        "SELECT column_name,udt_name,is_nullable FROM information_schema.columns
         WHERE table_schema='issuance_service'
           AND table_name='passport_job_administrative_cancellations'",
    )
    .fetch_all(&mut *connection)
    .await?;
    for (column, udt) in [
        ("job_id", "text"),
        ("organization_id", "text"),
        ("event_id", "uuid"),
        ("prior_status", "varchar"),
        ("reason_code", "varchar"),
        ("reason", "text"),
        ("actor_kind", "varchar"),
        ("actor_organization_id", "text"),
        ("recorded_at", "timestamptz"),
        ("idempotency_key_hash", "varchar"),
        ("request_hash", "varchar"),
        ("bureau_cancellation_requested", "bool"),
    ] {
        if !columns.iter().any(|row| {
            row.try_get::<String, _>("column_name").ok().as_deref() == Some(column)
                && row.try_get::<String, _>("udt_name").ok().as_deref() == Some(udt)
                && row.try_get::<String, _>("is_nullable").ok().as_deref() == Some("NO")
        }) {
            return Err(sqlx::Error::Protocol(format!(
                "passport cancellation schema lacks compatible {column}"
            )));
        }
    }
    let allowed: bool = sqlx::query_scalar(
        "SELECT has_table_privilege(current_user,
          'issuance_service.passport_job_administrative_cancellations','SELECT')
          AND has_table_privilege(current_user,
          'issuance_service.passport_job_administrative_cancellations','INSERT')",
    )
    .fetch_one(&mut *connection)
    .await?;
    if !allowed {
        return Err(sqlx::Error::Protocol(
            "passport cancellation audit lacks read/append privileges".into(),
        ));
    }
    let checks = sqlx::query_as::<_, (String, String)>(
        "SELECT conname,pg_get_constraintdef(oid) FROM pg_constraint
         WHERE conrelid='issuance_service.passport_job_administrative_cancellations'::regclass
           AND convalidated",
    )
    .fetch_all(&mut *connection)
    .await?;
    let normalize = crate::migration::normalize_catalog_expression;
    for (name, definition) in [
        ("pk_passport_administrative_cancellation", "PRIMARY KEY (job_id)"),
        ("ux_passport_cancellation_event", "UNIQUE (event_id)"),
        ("fk_passport_cancel_owned_job", "FOREIGN KEY (job_id, organization_id) REFERENCES issuance_service.physical_document_jobs(id, organization_id) ON DELETE RESTRICT"),
        ("ck_passport_cancel_reason_code", "CHECK (reason_code = 'ADMINISTRATIVE_ABANDONMENT')"),
        ("ck_passport_cancel_reason_length", "CHECK (octet_length(reason) >= 1 AND octet_length(reason) <= 512)"),
        ("ck_passport_cancel_actor_kind", "CHECK (actor_kind = 'AUTHENTICATED_PASSPORT_TENANT')"),
        ("ck_passport_cancel_actor_tenant", "CHECK (actor_organization_id = organization_id)"),
        ("ck_passport_cancel_key_hash", "CHECK (idempotency_key_hash ~ '^[0-9a-f]{64}$')"),
        ("ck_passport_cancel_request_hash", "CHECK (request_hash ~ '^[0-9a-f]{64}$')"),
        ("ck_passport_cancel_not_physical", "CHECK (NOT bureau_cancellation_requested)"),
    ] {
        if !checks.iter().any(|(actual_name, actual)| actual_name == name && normalize(actual) == normalize(definition)) {
            return Err(sqlx::Error::Protocol(format!("passport cancellation constraint {name} is missing or incompatible")));
        }
    }
    // Validate actual trigger operations and actual function bodies against the
    // same migration source, rather than trusting a matching trigger name.
    let migration = include_str!("../migrations/0011_passport_administrative_cancellation.sql");
    for (table, trigger, function, delimiter, operations) in [
        (
            "passport_job_administrative_cancellations",
            "trg_passport_cancellation_history",
            "guard_passport_cancellation_history",
            "$cancellation_history_guard$",
            27,
        ),
        (
            "passport_job_administrative_cancellations",
            "trg_passport_cancellation_history_truncate",
            "guard_passport_cancellation_history",
            "$cancellation_history_guard$",
            34,
        ),
        (
            "physical_document_jobs",
            "trg_administratively_cancelled_passport_job",
            "guard_administratively_cancelled_passport_job",
            "$cancelled_job_guard$",
            27,
        ),
    ] {
        let row = sqlx::query(
            "SELECT trg.tgtype::int AS operations, trg.tgenabled::text AS enabled,
                    proc.prosrc AS body, proc.proname AS function_name,
                    trg.tgqual IS NULL AS unconditional, trg.tgnargs::int AS arguments,
                    function_namespace.nspname AS function_schema
             FROM pg_trigger AS trg
             JOIN pg_class AS relation ON relation.oid=trg.tgrelid
             JOIN pg_namespace AS namespace ON namespace.oid=relation.relnamespace
             JOIN pg_proc AS proc ON proc.oid=trg.tgfoid
             JOIN pg_namespace AS function_namespace ON function_namespace.oid=proc.pronamespace
             WHERE namespace.nspname='issuance_service' AND relation.relname=$1
               AND trg.tgname=$2 AND NOT trg.tgisinternal",
        )
        .bind(table)
        .bind(trigger)
        .fetch_optional(&mut *connection)
        .await?;
        let expected = migration
            .split(delimiter)
            .nth(1)
            .expect("embedded guard body");
        let valid = row.as_ref().is_some_and(|row| {
            row.try_get::<i32, _>("operations").ok() == Some(operations)
                && row.try_get::<bool, _>("unconditional").ok() == Some(true)
                && row.try_get::<i32, _>("arguments").ok() == Some(0)
                && matches!(
                    row.try_get::<String, _>("enabled").ok().as_deref(),
                    Some("O" | "A")
                )
                && row.try_get::<String, _>("function_name").ok().as_deref() == Some(function)
                && row.try_get::<String, _>("function_schema").ok().as_deref()
                    == Some("issuance_service")
                && row.try_get::<String, _>("body").ok().is_some_and(|body| {
                    body.replace("\r\n", "\n") == expected.replace("\r\n", "\n")
                })
        });
        if !valid {
            return Err(sqlx::Error::Protocol(format!(
                "passport cancellation guard {trigger} is missing or incompatible"
            )));
        }
    }
    let acl_body: Option<String> = sqlx::query_scalar(
        "SELECT proc.prosrc FROM pg_proc AS proc
         JOIN pg_namespace AS namespace ON namespace.oid=proc.pronamespace
         JOIN pg_language AS language ON language.oid=proc.prolang
         WHERE namespace.nspname='issuance_service'
           AND proc.proname='passport_cancellation_acl_ready' AND proc.pronargs=0
           AND proc.prorettype='boolean'::regtype AND proc.provolatile='s'
           AND NOT proc.prosecdef AND language.lanname='sql'",
    )
    .fetch_optional(&mut *connection)
    .await?;
    let expected_acl = migration
        .split("$cancellation_acl_guard$")
        .nth(1)
        .expect("embedded cancellation ACL contract");
    if !acl_body
        .is_some_and(|body| body.replace("\r\n", "\n") == expected_acl.replace("\r\n", "\n"))
    {
        return Err(sqlx::Error::Protocol(
            "passport cancellation ACL contract is incompatible".into(),
        ));
    }
    Ok(())
}
