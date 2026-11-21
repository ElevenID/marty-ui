use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgRow, PgPool, Row};
use uuid::Uuid;

use crate::{
    decode_delegation_command, decode_grant_snapshot,
    repository::{check_activation_guard, validate_initial},
    validate_transition, ActivationCommitGuard, CommittedDelegationCommand,
    DecodedDelegationCommand, DelegationCommandIdentity, DelegationGrant,
    DelegationGrantRepository, GrantAuditEvent, GrantStatus, PreparedDelegationCommand, Principal,
    RepositoryError, StoredDelegationCommandResult,
};

const MIGRATIONS: &[(i32, &str)] = &[
    (1, include_str!("../migrations/0001_delegation_grants.sql")),
    (
        2,
        include_str!("../migrations/0002_atomic_lifecycle_journal.sql"),
    ),
    (
        3,
        include_str!("../migrations/0003_trusted_consent_evidence.sql"),
    ),
    (4, include_str!("../migrations/0004_command_results.sql")),
    (
        5,
        include_str!("../migrations/0005_organization_approval.sql"),
    ),
    (
        6,
        include_str!("../migrations/0006_retained_use_commands.sql"),
    ),
];
// A service-specific transaction advisory lock serializes concurrent startup.
const MIGRATION_LOCK: i64 = 0x4d41_5254_5944_4101;

// These tests share a schema and exercise table-wide TRUNCATE guards. Keep
// those DDL locks separate from other tests' FK checks; each test still runs
// its own concurrent compare-and-swap operations without serialization.
#[cfg(test)]
pub(crate) static POSTGRES_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Clone)]
pub struct PgDelegationGrantRepository {
    pool: PgPool,
}

impl PgDelegationGrantRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Applies the bundled migrations transactionally under a database lock.
    /// Existing migration checksums must match; a changed migration is not replayed.
    /// Run with the migration role, before handing a restricted pool to the service.
    pub async fn migrate(&self) -> Result<(), RepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(map_database)?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(MIGRATION_LOCK)
            .execute(&mut *transaction)
            .await
            .map_err(map_database)?;
        sqlx::raw_sql(
            "CREATE SCHEMA IF NOT EXISTS delegated_authority_service;
             CREATE TABLE IF NOT EXISTS delegated_authority_service.schema_migrations (
                 version INTEGER PRIMARY KEY,
                 checksum TEXT NOT NULL,
                 applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
             );",
        )
        .execute(&mut *transaction)
        .await
        .map_err(map_database)?;
        // A legacy 0001 writer does not participate in the migration advisory
        // lock. Drain it before 0002's empty-table check, then hold this table
        // lock until every guard and migration checksum commits. Do not change
        // the historical migration bytes or manufacture a missing journal.
        let grant_table_exists: bool = sqlx::query_scalar(
            "SELECT to_regclass('delegated_authority_service.delegation_grants') IS NOT NULL",
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_database)?;
        if grant_table_exists {
            sqlx::query("SET LOCAL lock_timeout = '5s'")
                .execute(&mut *transaction)
                .await
                .map_err(map_database)?;
            sqlx::query(
                "LOCK TABLE delegated_authority_service.delegation_grants IN ACCESS EXCLUSIVE MODE",
            )
            .execute(&mut *transaction)
            .await
            .map_err(map_database)?;
        }
        for (version, sql) in MIGRATIONS {
            let expected_checksum = checksum(sql);
            let stored = sqlx::query_scalar::<_, String>(
                "SELECT checksum FROM delegated_authority_service.schema_migrations WHERE version=$1",
            )
            .bind(version)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(map_database)?;
            match stored {
                Some(actual) if actual != expected_checksum => {
                    return Err(RepositoryError::MigrationMismatch);
                }
                Some(_) => {}
                None => {
                    sqlx::raw_sql(*sql)
                        .execute(&mut *transaction)
                        .await
                        .map_err(map_database)?;
                    sqlx::query(
                        "INSERT INTO delegated_authority_service.schema_migrations (version,checksum)
                         VALUES ($1,$2)",
                    )
                    .bind(version)
                    .bind(expected_checksum)
                    .execute(&mut *transaction)
                    .await
                    .map_err(map_database)?;
                }
            }
        }
        transaction.commit().await.map_err(map_database)
    }

    /// Checks schema version/checksums and required tables and enabled journal
    /// triggers. It does not imply that consent, authorization, or signing is ready.
    pub async fn readiness(&self) -> Result<(), RepositoryError> {
        let tables = sqlx::query_scalar::<_, bool>(
            "SELECT to_regclass('delegated_authority_service.schema_migrations') IS NOT NULL
                 AND to_regclass('delegated_authority_service.delegation_grants') IS NOT NULL
                 AND to_regclass('delegated_authority_service.grant_lifecycle_events') IS NOT NULL
                 AND to_regclass('delegated_authority_service.consent_confirmations') IS NOT NULL
                 AND to_regclass('delegated_authority_service.consent_withdrawals') IS NOT NULL
                 AND to_regclass('delegated_authority_service.representation_authority_sources') IS NOT NULL
                 AND to_regclass('delegated_authority_service.representation_authority_assertions') IS NOT NULL
                 AND to_regclass('delegated_authority_service.command_results') IS NOT NULL
                 AND to_regclass('delegated_authority_service.approval_storage_identity') IS NOT NULL
                 AND to_regclass('delegated_authority_service.approval_reviews') IS NOT NULL
                 AND to_regclass('delegated_authority_service.approval_confirmation_bindings') IS NOT NULL
                 AND to_regclass('delegated_authority_service.organization_authority_observations') IS NOT NULL",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_database)?;
        if !tables {
            return Err(RepositoryError::SchemaNotReady);
        }
        let rows = sqlx::query(
            "SELECT version,checksum FROM delegated_authority_service.schema_migrations ORDER BY version",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_database)?;
        if rows.len() != MIGRATIONS.len() {
            return Err(RepositoryError::SchemaNotReady);
        }
        for (row, (expected_version, sql)) in rows.iter().zip(MIGRATIONS) {
            if row.try_get::<i32, _>("version").map_err(corrupt)? != *expected_version
                || row.try_get::<String, _>("checksum").map_err(corrupt)? != checksum(sql)
            {
                return Err(RepositoryError::MigrationMismatch);
            }
        }
        let triggers = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM pg_trigger
             WHERE NOT tgisinternal AND tgenabled = 'O' AND (
                 (tgrelid = 'delegated_authority_service.delegation_grants'::regclass
                  AND tgname IN ('delegation_grants_guard','delegation_grants_journal','delegation_grants_no_truncate'))
                 OR (tgrelid = 'delegated_authority_service.grant_lifecycle_events'::regclass
                     AND tgname IN ('grant_lifecycle_events_append_only','grant_lifecycle_events_no_truncate'))
                 OR (tgrelid = 'delegated_authority_service.consent_confirmations'::regclass
                     AND tgname IN ('consent_confirmations_binding','consent_confirmations_immutable','consent_confirmations_no_truncate'))
                 OR (tgrelid = 'delegated_authority_service.consent_withdrawals'::regclass
                     AND tgname IN ('consent_withdrawals_stamp','consent_withdrawals_immutable','consent_withdrawals_no_truncate'))
                 OR (tgrelid = 'delegated_authority_service.representation_authority_sources'::regclass
                     AND tgname IN ('representation_authority_sources_binding','representation_authority_sources_immutable','representation_authority_sources_no_truncate'))
                 OR (tgrelid = 'delegated_authority_service.representation_authority_assertions'::regclass
                     AND tgname IN ('representation_authority_assertions_guard','representation_authority_assertions_immutable','representation_authority_assertions_no_truncate'))
                 OR (tgrelid = 'delegated_authority_service.command_results'::regclass
                     AND tgname IN ('command_results_binding','command_results_immutable','command_results_no_truncate'))
                 OR (tgrelid = 'delegated_authority_service.approval_storage_identity'::regclass
                     AND tgname IN ('approval_storage_identity_immutable','approval_storage_identity_no_truncate'))
                 OR (tgrelid = 'delegated_authority_service.approval_reviews'::regclass
                     AND tgname IN ('approval_reviews_binding','approval_reviews_immutable','approval_reviews_no_truncate'))
                 OR (tgrelid = 'delegated_authority_service.approval_confirmation_bindings'::regclass
                     AND tgname IN ('approval_confirmation_bindings_guard','approval_confirmation_bindings_immutable','approval_confirmation_bindings_no_truncate'))
                 OR (tgrelid = 'delegated_authority_service.organization_authority_observations'::regclass
                     AND tgname IN ('organization_authority_observations_guard','organization_authority_observations_immutable','organization_authority_observations_no_truncate')))",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_database)?;
        if triggers != 31 {
            return Err(RepositoryError::SchemaNotReady);
        }
        crate::use_postgres::verify_use_schema(&self.pool).await?;
        Ok(())
    }
}

#[async_trait]
impl DelegationGrantRepository for PgDelegationGrantRepository {
    async fn command_result(
        &self,
        identity: &DelegationCommandIdentity,
    ) -> Result<Option<StoredDelegationCommandResult>, RepositoryError> {
        load_command_result(&self.pool, identity).await
    }

    async fn commit_command(
        &self,
        mut prepared: PreparedDelegationCommand,
    ) -> Result<CommittedDelegationCommand, RepositoryError> {
        prepared.result.validate()?;
        if prepared.result.grant != prepared.mutation.grant {
            return Err(RepositoryError::CorruptData);
        }
        let identity = prepared.result.identity.clone();
        let mut transaction = self.pool.begin().await.map_err(map_database)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            .execute(&mut *transaction)
            .await
            .map_err(map_database)?;
        // A hash collision serializes unrelated keys; exact typed identity still
        // selects the row. Every command path takes this lock before grant locks.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(identity.lock_key()?)
            .execute(&mut *transaction)
            .await
            .map_err(map_database)?;
        if let Some(original) = load_command_result(&mut *transaction, &identity).await? {
            if original.command.digest() != prepared.result.command.digest() {
                return Err(RepositoryError::CommandConflict);
            }
            transaction.commit().await.map_err(map_database)?;
            return Ok(CommittedDelegationCommand {
                result: original,
                recovered: true,
            });
        }
        let identity_claimed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM delegated_authority_service.command_identities
             WHERE organization_id=$1 AND actor_type=$2 AND actor_id=$3 AND command_id=$4)",
        )
        .bind(identity.organization_id)
        .bind(actor_type(&identity)?)
        .bind(&identity.actor.id)
        .bind(identity.command_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_database)?;
        if identity_claimed {
            return Err(RepositoryError::CommandConflict);
        }
        if let Some(previous) = &prepared.mutation.previous {
            let row = sqlx::query(
                "SELECT id,organization_id,status,revision,terms_digest,grant_document,
                 (created_at = (grant_document ->> 'created_at')::TIMESTAMPTZ
                  AND updated_at = (grant_document ->> 'updated_at')::TIMESTAMPTZ) AS timestamp_columns_match
                 FROM delegated_authority_service.delegation_grants WHERE organization_id=$1 AND id=$2 FOR UPDATE")
                .bind(previous.organization_id).bind(previous.id).fetch_optional(&mut *transaction)
                .await.map_err(map_database)?.ok_or(RepositoryError::NotFound)?;
            let current = decode(row)?;
            if &current != previous {
                return Err(RepositoryError::RevisionConflict);
            }
            validate_transition(&current, &prepared.mutation.grant)?;
            check_activation_guard(
                &prepared.mutation.grant,
                prepared.mutation.activation.as_ref(),
                None,
            )?;
        } else {
            validate_initial(&prepared.mutation.grant)?;
        }
        let database_now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_database)?;
        prepared.recheck_access(Some(database_now)).await?;
        let mutation = &prepared.mutation;
        let grant = &mutation.grant;
        if let Some(previous) = &mutation.previous {
            let updated = sqlx::query(
                "UPDATE delegated_authority_service.delegation_grants
                 SET status=$1,revision=$2,grant_document=$3,updated_at=($4::text)::TIMESTAMPTZ
                 WHERE organization_id=$5 AND id=$6 AND revision=$7",
            )
            .bind(grant.status.as_str())
            .bind(revision(grant.revision)?)
            .bind(encode(grant)?)
            .bind(grant.updated_at.to_rfc3339())
            .bind(grant.organization_id)
            .bind(grant.id)
            .bind(revision(previous.revision)?)
            .execute(&mut *transaction)
            .await
            .map_err(map_database)?;
            if updated.rows_affected() != 1 {
                return Err(RepositoryError::RevisionConflict);
            }
        } else {
            sqlx::query(
                "INSERT INTO delegated_authority_service.delegation_grants
                 (id,organization_id,status,revision,terms_digest,grant_document,created_at,updated_at)
                 VALUES ($1,$2,$3,$4,$5,$6,($7::text)::TIMESTAMPTZ,($8::text)::TIMESTAMPTZ)")
                .bind(grant.id).bind(grant.organization_id).bind(grant.status.as_str())
                .bind(revision(grant.revision)?).bind(&grant.terms_digest).bind(encode(grant)?)
                .bind(grant.created_at.to_rfc3339()).bind(grant.updated_at.to_rfc3339())
                .execute(&mut *transaction).await.map_err(map_insert)?;
        }
        sqlx::query(
            "INSERT INTO delegated_authority_service.command_results
             (organization_id,actor_type,actor_id,command_id,command_digest,command_document,grant_id,grant_revision,result_document)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(identity.organization_id).bind(actor_type(&identity)?).bind(&identity.actor.id)
            .bind(identity.command_id).bind(prepared.result.command.digest()).bind(&prepared.result.command.document)
            .bind(grant.id).bind(revision(grant.revision)?).bind(encode(grant)?)
            .execute(&mut *transaction).await.map_err(map_database)?;
        // Includes waits and both lifecycle/command-result triggers. This is a
        // final precommit observation, not an assertion of COMMIT's timestamp.
        let database_now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_database)?;
        prepared.check_access(Some(database_now))?;
        if mutation.activation.is_some() {
            check_activation_guard(grant, mutation.activation.as_ref(), Some(database_now))?;
        }
        transaction.commit().await.map_err(map_database)?;
        Ok(CommittedDelegationCommand {
            result: prepared.result,
            recovered: false,
        })
    }

    async fn insert(&self, grant: DelegationGrant) -> Result<(), RepositoryError> {
        validate_initial(&grant)?;
        let document = encode(&grant)?;
        // The AFTER trigger journals this insertion in the same transaction.
        sqlx::query(
            "INSERT INTO delegated_authority_service.delegation_grants
             (id, organization_id, status, revision, terms_digest, grant_document, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,($7::text)::TIMESTAMPTZ,($8::text)::TIMESTAMPTZ)",
        )
        .bind(grant.id)
        .bind(grant.organization_id)
        .bind(grant.status.as_str())
        .bind(revision(grant.revision)?)
        .bind(&grant.terms_digest)
        .bind(document)
        .bind(grant.created_at.to_rfc3339())
        .bind(grant.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(map_insert)?;
        Ok(())
    }

    async fn get(
        &self,
        organization_id: Uuid,
        grant_id: Uuid,
    ) -> Result<Option<DelegationGrant>, RepositoryError> {
        let row = sqlx::query(
            "SELECT id, organization_id, status, revision, terms_digest, grant_document,
     (created_at = (grant_document ->> 'created_at')::TIMESTAMPTZ
      AND updated_at = (grant_document ->> 'updated_at')::TIMESTAMPTZ) AS timestamp_columns_match FROM delegated_authority_service.delegation_grants
             WHERE organization_id=$1 AND id=$2",
        )
        .bind(organization_id)
        .bind(grant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_database)?;
        row.map(decode).transpose()
    }

    async fn compare_and_swap_guarded(
        &self,
        organization_id: Uuid,
        grant_id: Uuid,
        expected_revision: u64,
        replacement: DelegationGrant,
        activation: Option<ActivationCommitGuard>,
    ) -> Result<DelegationGrant, RepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(map_database)?;
        let row = sqlx::query(
            "SELECT id, organization_id, status, revision, terms_digest, grant_document,
     (created_at = (grant_document ->> 'created_at')::TIMESTAMPTZ
      AND updated_at = (grant_document ->> 'updated_at')::TIMESTAMPTZ) AS timestamp_columns_match FROM delegated_authority_service.delegation_grants
             WHERE organization_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(organization_id)
        .bind(grant_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_database)?
        .ok_or(RepositoryError::NotFound)?;
        let current = decode(row)?;
        if current.revision != expected_revision {
            return Err(RepositoryError::RevisionConflict);
        }
        validate_transition(&current, &replacement)?;
        // Pool acquisition and row-lock waits must not reuse an earlier clock.
        check_activation_guard(&replacement, activation.as_ref(), None)?;
        let document = encode(&replacement)?;
        let row = sqlx::query(
            "UPDATE delegated_authority_service.delegation_grants
             SET status=$1, revision=$2, grant_document=$3, updated_at=($4::text)::TIMESTAMPTZ
             WHERE organization_id=$5 AND id=$6 AND revision=$7
             RETURNING id, organization_id, status, revision, terms_digest, grant_document,
     (created_at = (grant_document ->> 'created_at')::TIMESTAMPTZ
      AND updated_at = (grant_document ->> 'updated_at')::TIMESTAMPTZ) AS timestamp_columns_match",
        )
        .bind(replacement.status.as_str())
        .bind(revision(replacement.revision)?)
        .bind(document)
        .bind(replacement.updated_at.to_rfc3339())
        .bind(organization_id)
        .bind(grant_id)
        .bind(revision(expected_revision)?)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_database)?
        .ok_or(RepositoryError::RevisionConflict)?;
        let result = decode(row)?;
        if activation.is_some() {
            // The UPDATE and its journal trigger have completed. Read a fresh
            // database clock (not transaction-start CURRENT_TIMESTAMP) just
            // before commit. Failure rolls back both grant and journal writes.
            let database_now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(&mut *transaction)
                .await
                .map_err(map_database)?;
            check_activation_guard(&result, activation.as_ref(), Some(database_now))?;
        }
        // The trigger's journal write and grant state are committed together.
        transaction.commit().await.map_err(map_database)?;
        Ok(result)
    }

    async fn list(
        &self,
        organization_id: Uuid,
        status: Option<GrantStatus>,
    ) -> Result<Vec<DelegationGrant>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT id, organization_id, status, revision, terms_digest, grant_document,
     (created_at = (grant_document ->> 'created_at')::TIMESTAMPTZ
      AND updated_at = (grant_document ->> 'updated_at')::TIMESTAMPTZ) AS timestamp_columns_match FROM delegated_authority_service.delegation_grants
             WHERE organization_id=$1 AND ($2::text IS NULL OR status=$2) ORDER BY created_at,id",
        )
        .bind(organization_id)
        .bind(status.map(GrantStatus::as_str))
        .fetch_all(&self.pool)
        .await
        .map_err(map_database)?;
        rows.into_iter().map(decode).collect()
    }

    async fn audit(
        &self,
        organization_id: Uuid,
        grant_id: Uuid,
    ) -> Result<Vec<GrantAuditEvent>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT organization_id,grant_id,revision,previous_status,status,terms_digest,occurred_at
             FROM delegated_authority_service.grant_lifecycle_events
             WHERE organization_id=$1 AND grant_id=$2 ORDER BY revision",
        )
        .bind(organization_id)
        .bind(grant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(map_database)?;
        rows.into_iter().map(decode_event).collect()
    }
}

fn actor_type(identity: &DelegationCommandIdentity) -> Result<String, RepositoryError> {
    serde_json::to_value(identity.actor.principal_type)
        .map_err(|_| RepositoryError::CorruptData)?
        .as_str()
        .map(str::to_owned)
        .ok_or(RepositoryError::CorruptData)
}

async fn load_command_result<'e, E>(
    executor: E,
    identity: &DelegationCommandIdentity,
) -> Result<Option<StoredDelegationCommandResult>, RepositoryError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let row = sqlx::query(
        "SELECT organization_id,actor_type,actor_id,command_id,command_digest,command_document,
                grant_id,grant_revision,result_document FROM delegated_authority_service.command_results
         WHERE organization_id=$1 AND actor_type=$2 AND actor_id=$3 AND command_id=$4")
        .bind(identity.organization_id).bind(actor_type(identity)?).bind(&identity.actor.id)
        .bind(identity.command_id).fetch_optional(executor).await.map_err(map_database)?;
    row.map(|row| {
        let document: Value = row.try_get("command_document").map_err(corrupt)?;
        let raw = serde_json::to_vec(&document).map_err(|_| RepositoryError::CorruptData)?;
        let DecodedDelegationCommand::Mutation(command) =
            decode_delegation_command(&raw).map_err(|_| RepositoryError::CorruptData)?
        else {
            return Err(RepositoryError::CorruptData);
        };
        if command.digest()
            != row
                .try_get::<String, _>("command_digest")
                .map_err(corrupt)?
        {
            return Err(RepositoryError::CorruptData);
        }
        let grant_document: Value = row.try_get("result_document").map_err(corrupt)?;
        let grant = decode_grant_snapshot(
            &serde_json::to_vec(&grant_document).map_err(|_| RepositoryError::CorruptData)?,
        )
        .map_err(|_| RepositoryError::CorruptData)?;
        if grant.id != row.try_get::<Uuid, _>("grant_id").map_err(corrupt)?
            || revision(grant.revision)?
                != row.try_get::<i64, _>("grant_revision").map_err(corrupt)?
        {
            return Err(RepositoryError::CorruptData);
        }
        let result = StoredDelegationCommandResult {
            identity: DelegationCommandIdentity {
                organization_id: row.try_get("organization_id").map_err(corrupt)?,
                actor: Principal {
                    principal_type: serde_json::from_value(Value::String(
                        row.try_get("actor_type").map_err(corrupt)?,
                    ))
                    .map_err(|_| RepositoryError::CorruptData)?,
                    id: row.try_get("actor_id").map_err(corrupt)?,
                },
                command_id: row.try_get("command_id").map_err(corrupt)?,
            },
            command,
            grant,
        };
        if &result.identity != identity {
            return Err(RepositoryError::CorruptData);
        }
        result.validate()?;
        Ok(result)
    })
    .transpose()
}

fn checksum(sql: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(sql.as_bytes()))
}

fn revision(value: u64) -> Result<i64, RepositoryError> {
    i64::try_from(value).map_err(|_| RepositoryError::CorruptData)
}

fn encode(grant: &DelegationGrant) -> Result<Value, RepositoryError> {
    serde_json::to_value(grant).map_err(|_| RepositoryError::CorruptData)
}

fn decode(row: PgRow) -> Result<DelegationGrant, RepositoryError> {
    let value: Value = row.try_get("grant_document").map_err(corrupt)?;
    let raw = serde_json::to_vec(&value).map_err(|_| RepositoryError::CorruptData)?;
    let grant = decode_grant_snapshot(&raw).map_err(|_| RepositoryError::CorruptData)?;
    if grant.id != row.try_get::<Uuid, _>("id").map_err(corrupt)?
        || grant.organization_id != row.try_get::<Uuid, _>("organization_id").map_err(corrupt)?
        || grant.status.as_str() != row.try_get::<String, _>("status").map_err(corrupt)?
        || revision(grant.revision)? != row.try_get::<i64, _>("revision").map_err(corrupt)?
        || grant.terms_digest != row.try_get::<String, _>("terms_digest").map_err(corrupt)?
        // Compare against the database's own timestamp conversion rather than
        // silently truncating the original JSON's nanoseconds in Rust.
        || !row.try_get::<bool, _>("timestamp_columns_match").map_err(corrupt)?
    {
        return Err(RepositoryError::CorruptData);
    }
    Ok(grant)
}

fn decode_event(row: PgRow) -> Result<GrantAuditEvent, RepositoryError> {
    let previous: Option<String> = row.try_get("previous_status").map_err(corrupt)?;
    let revision: i64 = row.try_get("revision").map_err(corrupt)?;
    Ok(GrantAuditEvent {
        organization_id: row.try_get("organization_id").map_err(corrupt)?,
        grant_id: row.try_get("grant_id").map_err(corrupt)?,
        revision: u64::try_from(revision).map_err(|_| RepositoryError::CorruptData)?,
        previous_status: previous.map(|value| parse_status(&value)).transpose()?,
        status: parse_status(&row.try_get::<String, _>("status").map_err(corrupt)?)?,
        terms_digest: row.try_get("terms_digest").map_err(corrupt)?,
        occurred_at: DateTime::parse_from_rfc3339(
            &row.try_get::<String, _>("occurred_at").map_err(corrupt)?,
        )
        .map_err(|_| RepositoryError::CorruptData)?
        .with_timezone(&Utc),
    })
}

fn parse_status(value: &str) -> Result<GrantStatus, RepositoryError> {
    match value {
        "PENDING" => Ok(GrantStatus::Pending),
        "ACTIVE" => Ok(GrantStatus::Active),
        "SUSPENDED" => Ok(GrantStatus::Suspended),
        "REVOKED" => Ok(GrantStatus::Revoked),
        "EXPIRED" => Ok(GrantStatus::Expired),
        _ => Err(RepositoryError::CorruptData),
    }
}

fn corrupt(_: sqlx::Error) -> RepositoryError {
    RepositoryError::CorruptData
}

fn map_database(_: sqlx::Error) -> RepositoryError {
    // Database messages can contain connection strings, documents, or bind values.
    RepositoryError::DatabaseFailure
}

fn map_insert(error: sqlx::Error) -> RepositoryError {
    if let sqlx::Error::Database(database) = &error {
        if database.code().as_deref() == Some("23505") {
            return RepositoryError::AlreadyExists;
        }
    }
    map_database(error)
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Timelike};
    use sqlx::postgres::PgPoolOptions;

    use super::*;
    use crate::{test_support::pending_grant, GrantValidationError};

    fn revoked(grant: &DelegationGrant) -> DelegationGrant {
        let mut next = grant.clone();
        next.status = GrantStatus::Revoked;
        next.revision += 1;
        next.updated_at += Duration::seconds(1);
        next
    }

    /// Opt in with an isolated test database. If configured, connection/migration
    /// errors fail the test; they are never silently converted to a skipped test.
    #[tokio::test]
    async fn postgres_atomic_lifecycle_and_isolation() {
        let Ok(database_url) = std::env::var("DELEGATED_AUTHORITY_TEST_DATABASE_URL") else {
            return;
        };
        let _test_guard = POSTGRES_TEST_LOCK.lock().await;
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("configured delegation test database must be available");
        let repository = PgDelegationGrantRepository::new(pool.clone());
        repository.migrate().await.unwrap();
        repository.migrate().await.unwrap();
        repository.readiness().await.unwrap();

        let grant = pending_grant();
        repository.insert(grant.clone()).await.unwrap();
        assert_eq!(
            repository.insert(grant.clone()).await,
            Err(RepositoryError::AlreadyExists)
        );
        assert_eq!(
            repository
                .get(grant.organization_id, grant.id)
                .await
                .unwrap(),
            Some(grant.clone())
        );
        assert_eq!(
            repository
                .audit(grant.organization_id, grant.id)
                .await
                .unwrap()
                .len(),
            1
        );
        let outsider = Uuid::new_v4();
        assert!(repository.get(outsider, grant.id).await.unwrap().is_none());
        assert!(repository.list(outsider, None).await.unwrap().is_empty());
        assert!(repository
            .audit(outsider, grant.id)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            repository
                .compare_and_swap(outsider, grant.id, 1, revoked(&grant))
                .await,
            Err(RepositoryError::NotFound)
        );

        let mut tampered = revoked(&grant);
        tampered.terms.resources = vec!["urn:example:substituted".into()];
        tampered.terms_digest = tampered.calculate_terms_digest().unwrap();
        assert_eq!(
            repository
                .compare_and_swap(grant.organization_id, grant.id, 1, tampered)
                .await,
            Err(RepositoryError::InvalidGrant(
                GrantValidationError::ImmutableGrantDataChanged
            ))
        );

        // Simulate a journal write failure entirely inside an uncommitted test
        // transaction. The grant update must roll back, with no orphan event.
        let next = revoked(&grant);
        let mut transaction = pool.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO delegated_authority_service.grant_lifecycle_events
             (organization_id,grant_id,revision,previous_status,status,terms_digest,occurred_at)
             VALUES ($1,$2,2,'PENDING','REVOKED',$3,$4)",
        )
        .bind(grant.organization_id)
        .bind(grant.id)
        .bind(&grant.terms_digest)
        .bind(
            next.updated_at
                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        )
        .execute(&mut *transaction)
        .await
        .unwrap();
        let failed = sqlx::query(
            "UPDATE delegated_authority_service.delegation_grants
             SET status='REVOKED',revision=2,grant_document=$1,updated_at=($2::text)::TIMESTAMPTZ
             WHERE organization_id=$3 AND id=$4",
        )
        .bind(encode(&next).unwrap())
        .bind(
            next.updated_at
                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        )
        .bind(grant.organization_id)
        .bind(grant.id)
        .execute(&mut *transaction)
        .await;
        assert!(failed.is_err());
        transaction.rollback().await.unwrap();
        assert_eq!(
            repository
                .get(grant.organization_id, grant.id)
                .await
                .unwrap(),
            Some(grant.clone())
        );
        assert_eq!(
            repository
                .audit(grant.organization_id, grant.id)
                .await
                .unwrap()
                .len(),
            1
        );

        let (left, right) = tokio::join!(
            repository.compare_and_swap(grant.organization_id, grant.id, 1, next.clone()),
            repository.compare_and_swap(grant.organization_id, grant.id, 1, next.clone()),
        );
        assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
        let loser = if left.is_err() { left } else { right };
        assert_eq!(loser, Err(RepositoryError::RevisionConflict));
        assert_eq!(
            repository
                .get(grant.organization_id, grant.id)
                .await
                .unwrap(),
            Some(next.clone())
        );
        let events = repository
            .audit(grant.organization_id, grant.id)
            .await
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].previous_status, None);
        assert_eq!(events[1].previous_status, Some(GrantStatus::Pending));
        assert_eq!(events[1].status, GrantStatus::Revoked);
        assert_eq!(events[1].occurred_at, next.updated_at);
        assert_eq!(
            repository
                .list(grant.organization_id, Some(GrantStatus::Revoked))
                .await
                .unwrap(),
            vec![next.clone()]
        );

        let mut terminal_edit = next.clone();
        terminal_edit.revision += 1;
        terminal_edit.updated_at += Duration::seconds(1);
        assert_eq!(
            repository
                .compare_and_swap(grant.organization_id, grant.id, 2, terminal_edit)
                .await,
            Err(RepositoryError::InvalidGrant(
                GrantValidationError::InvalidStatusTransition
            ))
        );
        assert!(sqlx::query(
            "UPDATE delegated_authority_service.grant_lifecycle_events SET status='ACTIVE'
             WHERE organization_id=$1 AND grant_id=$2",
        )
        .bind(grant.organization_id)
        .bind(grant.id)
        .execute(&pool)
        .await
        .is_err());
        assert!(sqlx::query(
            "UPDATE delegated_authority_service.delegation_grants SET status='ACTIVE'
             WHERE organization_id=$1 AND id=$2",
        )
        .bind(grant.organization_id)
        .bind(grant.id)
        .execute(&pool)
        .await
        .is_err());
        assert_eq!(
            repository
                .audit(grant.organization_id, grant.id)
                .await
                .unwrap(),
            events
        );
        // The database does not reimplement RFC 8785. A corrupted snapshot
        // introduced outside this adapter must still fail closed on every read.
        let corrupt_grant = pending_grant();
        let mut corrupt_document = encode(&corrupt_grant).unwrap();
        corrupt_document["terms"]["resources"] = serde_json::json!(["urn:example:tampered"]);
        sqlx::query(
            "INSERT INTO delegated_authority_service.delegation_grants
             (id,organization_id,status,revision,terms_digest,grant_document,created_at,updated_at)
             VALUES ($1,$2,'PENDING',1,$3,$4,($5::text)::TIMESTAMPTZ,($5::text)::TIMESTAMPTZ)",
        )
        .bind(corrupt_grant.id)
        .bind(corrupt_grant.organization_id)
        .bind(&corrupt_grant.terms_digest)
        .bind(corrupt_document)
        .bind(corrupt_grant.created_at.to_rfc3339())
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            repository
                .get(corrupt_grant.organization_id, corrupt_grant.id)
                .await,
            Err(RepositoryError::CorruptData)
        );
        assert_eq!(
            repository.list(corrupt_grant.organization_id, None).await,
            Err(RepositoryError::CorruptData)
        );

        // TRUNCATE bypasses row triggers. Test the statement guards inside a
        // transaction and always roll back before asserting, even if a guard broke.
        for sql in [
            // Command results reference historical lifecycle rows. CASCADE
            // reaches the statement guard instead of stopping at the FK check.
            "TRUNCATE delegated_authority_service.grant_lifecycle_events CASCADE",
            "TRUNCATE delegated_authority_service.delegation_grants, delegated_authority_service.grant_lifecycle_events CASCADE",
        ] {
            let mut transaction = pool.begin().await.unwrap();
            let result = sqlx::query(sql).execute(&mut *transaction).await;
            transaction.rollback().await.unwrap();
            assert!(
                matches!(&result, Err(sqlx::Error::Database(error))
                    if error.code().as_deref() == Some("P0001")),
                "unexpected TRUNCATE guard result for {sql}: {result:?}"
            );
        }

        // Provision a temporary least-privilege runtime role and its fixtures
        // transactionally. Rollback removes the role and all test rows. This
        // qualification database therefore requires CREATEROLE (CI uses postgres).
        let runtime_grant = pending_grant();
        let mut transaction = pool.begin().await.unwrap();
        sqlx::query("SELECT set_config('marty.delegation_test_role',$1,true)")
            .bind(format!("delegation_test_{}", Uuid::new_v4().simple()))
            .execute(&mut *transaction)
            .await
            .unwrap();
        sqlx::raw_sql(
            "DO $role$
             DECLARE runtime_role TEXT := current_setting('marty.delegation_test_role');
             BEGIN
                 EXECUTE format('CREATE ROLE %I NOLOGIN', runtime_role);
                 EXECUTE format('GRANT USAGE ON SCHEMA delegated_authority_service TO %I', runtime_role);
                 EXECUTE format('GRANT SELECT,INSERT,UPDATE ON delegated_authority_service.delegation_grants TO %I', runtime_role);
                 EXECUTE format('GRANT SELECT ON delegated_authority_service.grant_lifecycle_events,delegated_authority_service.schema_migrations TO %I', runtime_role);
                 EXECUTE format('GRANT EXECUTE ON FUNCTION delegated_authority_service.grant_instant(TEXT) TO %I', runtime_role);
                 EXECUTE format('SET LOCAL ROLE %I', runtime_role);
             END
             $role$;",
        ).execute(&mut *transaction).await.unwrap();
        sqlx::query(
            "INSERT INTO delegated_authority_service.delegation_grants
             (id,organization_id,status,revision,terms_digest,grant_document,created_at,updated_at)
             VALUES ($1,$2,'PENDING',1,$3,$4,($5::text)::TIMESTAMPTZ,($5::text)::TIMESTAMPTZ)",
        )
        .bind(runtime_grant.id)
        .bind(runtime_grant.organization_id)
        .bind(&runtime_grant.terms_digest)
        .bind(encode(&runtime_grant).unwrap())
        .bind(runtime_grant.created_at.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .unwrap();
        let journal_count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM delegated_authority_service.grant_lifecycle_events
             WHERE organization_id=$1 AND grant_id=$2",
        )
        .bind(runtime_grant.organization_id)
        .bind(runtime_grant.id)
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
        assert_eq!(journal_count, 1);
        sqlx::query("SAVEPOINT denied_journal_write")
            .execute(&mut *transaction)
            .await
            .unwrap();
        let fabricated = sqlx::query(
            "INSERT INTO delegated_authority_service.grant_lifecycle_events
             (organization_id,grant_id,revision,previous_status,status,terms_digest,occurred_at)
             VALUES ($1,$2,2,'PENDING','REVOKED',$3,$4)",
        )
        .bind(runtime_grant.organization_id)
        .bind(runtime_grant.id)
        .bind(&runtime_grant.terms_digest)
        .bind(
            runtime_grant
                .updated_at
                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        )
        .execute(&mut *transaction)
        .await;
        sqlx::query("ROLLBACK TO SAVEPOINT denied_journal_write")
            .execute(&mut *transaction)
            .await
            .unwrap();
        transaction.rollback().await.unwrap();
        assert!(matches!(fabricated, Err(sqlx::Error::Database(error))
            if error.code().as_deref() == Some("42501")));

        // Preserve exact JSON/journal instants across both rounding directions
        // and permit distinct transitions within one PostgreSQL microsecond.
        for nanos in [123_456_700, 999_999_499, 999_999_500] {
            let mut precise = pending_grant();
            precise.created_at = precise.created_at.with_nanosecond(nanos).unwrap();
            precise.updated_at = precise.created_at;
            repository.insert(precise.clone()).await.unwrap();
            assert_eq!(
                repository
                    .get(precise.organization_id, precise.id)
                    .await
                    .unwrap(),
                Some(precise.clone())
            );
            let mut precise_next = revoked(&precise);
            precise_next.updated_at = precise.updated_at + Duration::nanoseconds(1);
            assert_eq!(
                repository
                    .compare_and_swap(precise.organization_id, precise.id, 1, precise_next.clone())
                    .await
                    .unwrap(),
                precise_next
            );
            let events = repository
                .audit(precise.organization_id, precise.id)
                .await
                .unwrap();
            assert_eq!(events[0].occurred_at, precise.updated_at);
            assert_eq!(events[1].occurred_at, precise_next.updated_at);
        }
        pool.close().await;
    }

    #[tokio::test]
    async fn activation_expiry_after_database_write_rolls_back_state_and_journal() {
        let Ok(url) = std::env::var("DELEGATED_AUTHORITY_TEST_DATABASE_URL") else {
            return;
        };
        let _test_guard = POSTGRES_TEST_LOCK.lock().await;
        let pool = PgPool::connect(&url).await.unwrap();
        let repository = PgDelegationGrantRepository::new(pool.clone());
        repository.migrate().await.unwrap();
        let mut grant = pending_grant();
        let created = Utc::now() - Duration::seconds(1);
        grant.created_at = created;
        grant.updated_at = created;
        grant.terms.valid_from = created;
        grant.terms.valid_until = created + Duration::hours(1);
        grant.terms_digest = grant.calculate_terms_digest().unwrap();
        repository.insert(grant.clone()).await.unwrap();
        let mut active = grant.clone();
        active.status = GrantStatus::Active;
        active.revision = 2;
        active.updated_at = Utc::now();
        active.approval = Some(crate::GrantApproval {
            profile: "urn:example:consent:v1".into(),
            grant_id: grant.id,
            approver: grant.terms.grantor.clone(),
            evidence_ref: "urn:example:consent:1".into(),
            authority_evidence_ref: "urn:example:authority:1".into(),
            terms_digest: grant.terms_digest.clone(),
            approved_at: active.updated_at,
        });
        struct ExpiringClock {
            calls: std::sync::atomic::AtomicUsize,
            start: DateTime<Utc>,
            end: DateTime<Utc>,
        }
        impl crate::DelegationClock for ExpiringClock {
            fn now(&self) -> DateTime<Utc> {
                if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    self.start
                } else {
                    self.end
                }
            }
        }
        let deadline = active.updated_at + Duration::minutes(1);
        let clock = std::sync::Arc::new(ExpiringClock {
            calls: std::sync::atomic::AtomicUsize::new(0),
            start: active.updated_at,
            end: deadline,
        });
        let guard = ActivationCommitGuard::for_verified(
            &active,
            crate::VerifiedConsent {
                valid_until: deadline,
            },
            clock.clone(),
        );
        assert_eq!(
            repository
                .compare_and_swap_guarded(grant.organization_id, grant.id, 1, active, Some(guard))
                .await,
            Err(RepositoryError::ActivationEvidenceExpired)
        );
        // The second clock read is after UPDATE and its journal trigger.
        assert_eq!(clock.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(
            repository
                .get(grant.organization_id, grant.id)
                .await
                .unwrap(),
            Some(grant.clone())
        );
        assert_eq!(
            repository
                .audit(grant.organization_id, grant.id)
                .await
                .unwrap()
                .len(),
            1
        );
        pool.close().await;
    }

    #[tokio::test]
    async fn database_clock_rejects_activation_from_a_frozen_application_clock() {
        let Ok(url) = std::env::var("DELEGATED_AUTHORITY_TEST_DATABASE_URL") else {
            return;
        };
        let _test_guard = POSTGRES_TEST_LOCK.lock().await;
        let pool = PgPool::connect(&url).await.unwrap();
        let repository = PgDelegationGrantRepository::new(pool.clone());
        repository.migrate().await.unwrap();
        let mut grant = pending_grant();
        let created = Utc::now() - Duration::hours(2);
        grant.created_at = created;
        grant.updated_at = created;
        grant.terms.valid_from = created;
        grant.terms.valid_until = created + Duration::hours(1);
        grant.terms_digest = grant.calculate_terms_digest().unwrap();
        repository.insert(grant.clone()).await.unwrap();
        let mut active = grant.clone();
        active.status = GrantStatus::Active;
        active.revision = 2;
        active.updated_at = created + Duration::seconds(1);
        active.approval = Some(crate::GrantApproval {
            profile: "urn:example:consent:v1".into(),
            grant_id: grant.id,
            approver: grant.terms.grantor.clone(),
            evidence_ref: "urn:example:consent:1".into(),
            authority_evidence_ref: "urn:example:authority:1".into(),
            terms_digest: grant.terms_digest.clone(),
            approved_at: active.updated_at,
        });
        struct FrozenClock(DateTime<Utc>);
        impl crate::DelegationClock for FrozenClock {
            fn now(&self) -> DateTime<Utc> {
                self.0
            }
        }
        let clock = std::sync::Arc::new(FrozenClock(active.updated_at));
        let guard = ActivationCommitGuard::for_verified(
            &active,
            crate::VerifiedConsent {
                valid_until: grant.terms.valid_until,
            },
            clock,
        );
        assert_eq!(
            repository
                .compare_and_swap_guarded(grant.organization_id, grant.id, 1, active, Some(guard))
                .await,
            Err(RepositoryError::ActivationEvidenceExpired)
        );
        assert_eq!(
            repository
                .get(grant.organization_id, grant.id)
                .await
                .unwrap(),
            Some(grant.clone())
        );
        assert_eq!(
            repository
                .audit(grant.organization_id, grant.id)
                .await
                .unwrap()
                .len(),
            1
        );
        pool.close().await;
    }
}
