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
             version_num VARCHAR(32) NOT NULL
         );",
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

    let index_definition: Option<String> = sqlx::query_scalar(
        "SELECT indexdef FROM pg_indexes
         WHERE schemaname='public' AND tablename='verification_sessions'
           AND indexname='ux_verification_sessions_live_nonce'",
    )
    .fetch_optional(&mut **transaction)
    .await?;
    if index_definition.as_deref().is_none_or(|definition| {
        let definition = normalized(definition);
        !definition.contains("create unique index")
            || !definition.contains("where (nonce is not null)")
    }) {
        return Err(SessionMigrationError::Incompatible(
            "live nonce unique index is missing or incompatible".into(),
        ));
    }

    if require_head && migration_versions(transaction).await? != [HEAD_REVISION] {
        return Err(SessionMigrationError::Incompatible(
            "verification migration history is not at the released head".into(),
        ));
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
