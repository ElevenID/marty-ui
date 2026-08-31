use std::collections::BTreeMap;

use sqlx::{PgPool, Postgres, Row, Transaction};
use thiserror::Error;

const ADVISORY_LOCK_ID: i64 = 800_620_260_809;
const BASE_REVISION: &str = "202608081900";
const HEAD_REVISION: &str = "202608091200";
const REQUIRED_CONSTRAINTS: [&str; 5] = [
    "ck_verification_nonce_length",
    "ck_verification_submission_digest",
    "ck_verification_processing_token_digest",
    "ck_verification_processing_lease",
    "ck_verification_atomic_state",
];

#[derive(Debug, Error)]
pub enum SessionMigrationError {
    #[error("VERIFICATION.MIGRATION_DATABASE: database operation failed")]
    Database(#[source] sqlx::Error),
    #[error("VERIFICATION.MIGRATION_INCOMPATIBLE: {0}")]
    Incompatible(String),
}

impl From<sqlx::Error> for SessionMigrationError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

/// Continue the released Alembic chain under Rust ownership.
///
/// This deliberately uses `verification_service.alembic_version` rather than
/// starting a second SQLx history. It is forward-only because the atomic nonce
/// fencing and presentation redaction cannot be safely downgraded.
pub async fn migrate_session_schema(pool: &PgPool) -> Result<(), SessionMigrationError> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(ADVISORY_LOCK_ID)
        .execute(&mut *transaction)
        .await?;
    ensure_history(&mut transaction).await?;

    let versions = migration_versions(&mut transaction).await?;
    if versions.len() > 1 {
        return Err(SessionMigrationError::Incompatible(
            "verification migration history has multiple heads".into(),
        ));
    }
    match versions.first().map(String::as_str) {
        Some(HEAD_REVISION) => {}
        Some(BASE_REVISION) => {
            sqlx::raw_sql(include_str!(
                "../../migrations/verification/202608081900_base.sql"
            ))
            .execute(&mut *transaction)
            .await?;
            sqlx::raw_sql(include_str!(
                "../../migrations/verification/202608091200_atomic.sql"
            ))
            .execute(&mut *transaction)
            .await?;
            write_head(&mut transaction).await?;
        }
        Some(version) => {
            return Err(SessionMigrationError::Incompatible(format!(
                "unknown verification migration revision {version}"
            )));
        }
        None => {
            let table_existed = table_exists(&mut transaction).await?;
            if table_existed && has_atomic_guards(&mut transaction).await? {
                // An already-upgraded database whose Alembic row was lost can
                // be adopted only after the complete final schema validates.
                validate_connection(&mut transaction, false).await?;
            } else {
                sqlx::raw_sql(include_str!(
                    "../../migrations/verification/202608081900_base.sql"
                ))
                .execute(&mut *transaction)
                .await?;
                sqlx::raw_sql(include_str!(
                    "../../migrations/verification/202608091200_atomic.sql"
                ))
                .execute(&mut *transaction)
                .await?;
            }
            write_head(&mut transaction).await?;
        }
    }

    // Preserve the irreversible privacy boundary even when adopting a Python
    // database already at head.
    sqlx::query(
        "UPDATE public.verification_sessions SET presentation_data=NULL
         WHERE presentation_data IS NOT NULL",
    )
    .execute(&mut *transaction)
    .await?;
    validate_connection(&mut transaction, true).await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn validate_session_schema(pool: &PgPool) -> Result<(), SessionMigrationError> {
    let mut connection = pool.begin().await?;
    validate_connection(&mut connection, true).await?;
    connection.rollback().await?;
    Ok(())
}

async fn ensure_history(transaction: &mut Transaction<'_, Postgres>) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(
        "CREATE SCHEMA IF NOT EXISTS verification_service;
         CREATE TABLE IF NOT EXISTS verification_service.alembic_version (
             version_num VARCHAR(32) NOT NULL,
             CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
         );
         DO $$ BEGIN
             IF NOT EXISTS (
                 SELECT 1 FROM pg_constraint
                 WHERE conrelid='verification_service.alembic_version'::regclass
                   AND conname='alembic_version_pkc' AND contype='p'
             ) THEN
                 ALTER TABLE verification_service.alembic_version
                     ADD CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num);
             END IF;
         END $$;",
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn migration_versions(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT version_num FROM verification_service.alembic_version ORDER BY version_num",
    )
    .fetch_all(&mut **transaction)
    .await
}

async fn write_head(transaction: &mut Transaction<'_, Postgres>) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM verification_service.alembic_version")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("INSERT INTO verification_service.alembic_version(version_num) VALUES($1)")
        .bind(HEAD_REVISION)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn table_exists(transaction: &mut Transaction<'_, Postgres>) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT to_regclass('public.verification_sessions') IS NOT NULL")
        .fetch_one(&mut **transaction)
        .await
}

async fn has_atomic_guards(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<bool, sqlx::Error> {
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_constraint
         WHERE conrelid='public.verification_sessions'::regclass
           AND conname=ANY($1::text[]) AND convalidated",
    )
    .bind(REQUIRED_CONSTRAINTS.as_slice())
    .fetch_one(&mut **transaction)
    .await?;
    Ok(count == i64::try_from(REQUIRED_CONSTRAINTS.len()).unwrap_or_default())
}

async fn validate_connection(
    transaction: &mut Transaction<'_, Postgres>,
    require_head: bool,
) -> Result<(), SessionMigrationError> {
    if !table_exists(transaction).await? {
        return Err(SessionMigrationError::Incompatible(
            "verification_sessions table is missing".into(),
        ));
    }
    let definitions = sqlx::query(
        "SELECT conname, pg_get_constraintdef(oid) AS definition
         FROM pg_constraint
         WHERE conrelid='public.verification_sessions'::regclass
           AND conname=ANY($1::text[]) AND convalidated",
    )
    .bind(REQUIRED_CONSTRAINTS.as_slice())
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|row| Ok((row.try_get("conname")?, row.try_get("definition")?)))
    .collect::<Result<BTreeMap<String, String>, sqlx::Error>>()?;
    validate_constraint_definitions(&definitions)?;

    let index = sqlx::query(
        "SELECT i.indisunique, i.indisvalid, i.indisready,
                pg_get_expr(i.indpred, i.indrelid) AS predicate,
                ARRAY(
                    SELECT attribute.attname
                    FROM unnest(i.indkey) WITH ORDINALITY AS key(attnum, position)
                    JOIN pg_attribute AS attribute
                      ON attribute.attrelid=i.indrelid AND attribute.attnum=key.attnum
                    ORDER BY key.position
                ) AS keys
         FROM pg_index AS i
         WHERE i.indexrelid=to_regclass('public.ux_verification_sessions_live_nonce')",
    )
    .fetch_optional(&mut **transaction)
    .await?;
    let valid_index = index.is_some_and(|row| {
        row.try_get::<bool, _>("indisunique").unwrap_or(false)
            && row.try_get::<bool, _>("indisvalid").unwrap_or(false)
            && row.try_get::<bool, _>("indisready").unwrap_or(false)
            && row.try_get::<Vec<String>, _>("keys").ok().as_deref() == Some(&["nonce".into()])
            && row
                .try_get::<Option<String>, _>("predicate")
                .ok()
                .flatten()
                .is_some_and(|predicate| normalized(&predicate) == "(nonce is not null)")
    });
    if !valid_index {
        return Err(SessionMigrationError::Incompatible(
            "live nonce unique index is missing or incompatible".into(),
        ));
    }

    let history_primary_key: Option<Vec<String>> = sqlx::query_scalar(
        "SELECT ARRAY(
             SELECT attribute.attname
             FROM unnest(constraint_row.conkey) WITH ORDINALITY AS key(attnum, position)
             JOIN pg_attribute AS attribute
               ON attribute.attrelid=constraint_row.conrelid
              AND attribute.attnum=key.attnum
             ORDER BY key.position
         )
         FROM pg_constraint AS constraint_row
         WHERE constraint_row.conrelid='verification_service.alembic_version'::regclass
           AND constraint_row.conname='alembic_version_pkc'
           AND constraint_row.contype='p'",
    )
    .fetch_optional(&mut **transaction)
    .await?
    .flatten();
    if history_primary_key.as_deref() != Some(&["version_num".into()]) {
        return Err(SessionMigrationError::Incompatible(
            "Alembic history primary key is missing or incompatible".into(),
        ));
    }

    validate_guard_behavior(transaction).await?;

    if require_head && migration_versions(transaction).await? != [HEAD_REVISION] {
        return Err(SessionMigrationError::Incompatible(
            "verification migration history is not at the released head".into(),
        ));
    }
    Ok(())
}

async fn validate_guard_behavior(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), SessionMigrationError> {
    let probe_id_collision: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM public.verification_sessions
             WHERE id LIKE '\\_\\_verification\\_schema\\_probe\\_%' ESCAPE '\\'
         )",
    )
    .fetch_one(&mut **transaction)
    .await?;
    if probe_id_collision {
        return Err(SessionMigrationError::Incompatible(
            "verification schema probe identifier is already in use".into(),
        ));
    }
    let probes = [
        (
            "nonce length",
            "INSERT INTO public.verification_sessions
             (id,organization_id,verifier_did,presentation_definition,status,
              verification_evidence,created_at,updated_at,nonce)
             VALUES('__verification_schema_probe_nonce','probe','did:web:probe','{}','PENDING',
                    '{}',clock_timestamp(),clock_timestamp(),'short')",
        ),
        (
            "submission digest",
            "INSERT INTO public.verification_sessions
             (id,organization_id,verifier_did,presentation_definition,status,
              verification_evidence,created_at,updated_at,nonce,submission_sha256)
             VALUES('__verification_schema_probe_submission','probe','did:web:probe','{}','EXPIRED',
                    '{}',clock_timestamp(),clock_timestamp(),NULL,
                    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')",
        ),
        (
            "processing token digest",
            "INSERT INTO public.verification_sessions
             (id,organization_id,verifier_did,presentation_definition,status,
              verification_evidence,created_at,updated_at,expires_at,nonce,
              submission_sha256,processing_token_sha256,processing_started_at,processing_expires_at)
             VALUES('__verification_schema_probe_token','probe','did:web:probe','{}','IN_PROGRESS',
                    '{}',clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '1 hour',
                    'nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn',
                    repeat('a',64),repeat('A',64),clock_timestamp(),clock_timestamp()+interval '1 minute')",
        ),
        (
            "strict processing lease",
            "INSERT INTO public.verification_sessions
             (id,organization_id,verifier_did,presentation_definition,status,
              verification_evidence,created_at,updated_at,expires_at,nonce,
              submission_sha256,processing_token_sha256,processing_started_at,processing_expires_at)
             SELECT '__verification_schema_probe_lease','probe','did:web:probe','{}','IN_PROGRESS',
                    '{}',clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '1 hour',
                    'lllllllllllllllllllllllllllllllllllllllllll',repeat('a',64),repeat('b',64),now_value,now_value
             FROM (SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now_value) AS clock",
        ),
        (
            "pending atomic state",
            "INSERT INTO public.verification_sessions
             (id,organization_id,verifier_did,presentation_definition,status,
              verification_evidence,created_at,updated_at,nonce)
             VALUES('__verification_schema_probe_pending','probe','did:web:probe','{}','PENDING',
                    '{}',clock_timestamp(),clock_timestamp(),NULL)",
        ),
        (
            "terminal atomic state",
            "INSERT INTO public.verification_sessions
             (id,organization_id,verifier_did,presentation_definition,status,
              verification_evidence,created_at,updated_at,nonce)
             VALUES('__verification_schema_probe_terminal','probe','did:web:probe','{}','VERIFIED',
                    '{}',clock_timestamp(),clock_timestamp(),
                    'ttttttttttttttttttttttttttttttttttttttttttt')",
        ),
        (
            "expired atomic state",
            "INSERT INTO public.verification_sessions
             (id,organization_id,verifier_did,presentation_definition,status,
              verification_evidence,created_at,updated_at,nonce,
              processing_token_sha256,processing_started_at,processing_expires_at)
             VALUES('__verification_schema_probe_expired','probe','did:web:probe','{}','EXPIRED',
                    '{}',clock_timestamp(),clock_timestamp(),NULL,repeat('b',64),
                    clock_timestamp(),clock_timestamp()+interval '1 minute')",
        ),
    ];
    for (name, sql) in probes {
        expect_rejected(transaction, name, "23514", sql).await?;
    }
    expect_rejected(
        transaction,
        "live nonce uniqueness",
        "23505",
        "INSERT INTO public.verification_sessions
         (id,organization_id,verifier_did,presentation_definition,status,
          verification_evidence,created_at,updated_at,nonce)
         VALUES
         ('__verification_schema_probe_unique_a','probe','did:web:probe','{}','PENDING',
          '{}',clock_timestamp(),clock_timestamp(),'uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu'),
         ('__verification_schema_probe_unique_b','probe','did:web:probe','{}','PENDING',
          '{}',clock_timestamp(),clock_timestamp(),'uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu')",
    )
    .await
}

async fn expect_rejected(
    transaction: &mut Transaction<'_, Postgres>,
    name: &str,
    expected_sqlstate: &str,
    sql: &'static str,
) -> Result<(), SessionMigrationError> {
    sqlx::query("SAVEPOINT verification_schema_probe")
        .execute(&mut **transaction)
        .await?;
    let result = sqlx::raw_sql(sql).execute(&mut **transaction).await;
    let rejected_as_expected = result
        .as_ref()
        .err()
        .and_then(sqlx::Error::as_database_error)
        .and_then(|error| error.code())
        .is_some_and(|code| code == expected_sqlstate);
    sqlx::query("ROLLBACK TO SAVEPOINT verification_schema_probe")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("RELEASE SAVEPOINT verification_schema_probe")
        .execute(&mut **transaction)
        .await?;
    if !rejected_as_expected {
        return Err(SessionMigrationError::Incompatible(format!(
            "verification schema did not reject invalid {name} with SQLSTATE {expected_sqlstate}"
        )));
    }
    Ok(())
}

fn validate_constraint_definitions(
    definitions: &BTreeMap<String, String>,
) -> Result<(), SessionMigrationError> {
    let requirements = [
        (
            "ck_verification_nonce_length",
            ["nonce", "length", "43"].as_slice(),
        ),
        (
            "ck_verification_submission_digest",
            ["submission_sha256", "[0-9a-f]{64}"].as_slice(),
        ),
        (
            "ck_verification_processing_token_digest",
            ["processing_token_sha256", "[0-9a-f]{64}"].as_slice(),
        ),
        (
            "ck_verification_processing_lease",
            ["processing_expires_at", "processing_started_at", ">"].as_slice(),
        ),
        (
            "ck_verification_atomic_state",
            [
                "pending",
                "in_progress",
                "verified",
                "failed",
                "expired",
                "nonce",
            ]
            .as_slice(),
        ),
    ];
    for (name, fragments) in requirements {
        let Some(definition) = definitions.get(name).map(|value| normalized(value)) else {
            return Err(SessionMigrationError::Incompatible(format!(
                "required verification constraint {name} is missing"
            )));
        };
        if fragments
            .iter()
            .any(|fragment| !definition.contains(fragment))
        {
            return Err(SessionMigrationError::Incompatible(format!(
                "verification constraint {name} is incompatible"
            )));
        }
    }
    Ok(())
}

fn normalized(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_continues_the_exact_released_alembic_chain() {
        assert_eq!(BASE_REVISION, "202608081900");
        assert_eq!(HEAD_REVISION, "202608091200");
        let source = include_str!("migration.rs");
        assert!(source.contains("verification_service.alembic_version"));
        assert!(!source.contains(concat!("_sqlx", "_migrations")));
    }

    #[test]
    fn atomic_migration_is_forward_only_and_retains_every_database_guard() {
        let base = include_str!("../../migrations/verification/202608081900_base.sql");
        let atomic = include_str!("../../migrations/verification/202608091200_atomic.sql");
        assert!(base.contains("SET presentation_data = NULL"));
        assert!(atomic.contains("clock_timestamp() AT TIME ZONE 'UTC'"));
        assert!(atomic.contains("Verification interrupted before atomic session migration"));
        for guard in REQUIRED_CONSTRAINTS {
            assert!(atomic.contains(guard), "missing {guard}");
        }
        assert!(atomic.contains("CREATE UNIQUE INDEX IF NOT EXISTS"));
        assert!(!atomic.to_ascii_lowercase().contains("drop constraint"));
        assert!(!atomic.to_ascii_lowercase().contains("drop table"));
    }

    #[test]
    fn constraint_validation_rejects_a_name_only_spoof() {
        let definitions = REQUIRED_CONSTRAINTS
            .into_iter()
            .map(|name| (name.into(), "CHECK (true)".into()))
            .collect();
        assert!(validate_constraint_definitions(&definitions).is_err());
    }

    #[test]
    fn migration_errors_do_not_render_driver_details() {
        let error = SessionMigrationError::Database(sqlx::Error::RowNotFound);
        assert_eq!(
            error.to_string(),
            "VERIFICATION.MIGRATION_DATABASE: database operation failed"
        );
    }
}
