use sqlx::{PgConnection, PgPool, Row as _};
use thiserror::Error;

const MIGRATION_VERSION: &str = "rust_auth_0001";
const ADVISORY_LOCK_ID: i64 = 718_431_214;

#[derive(Debug, Error)]
pub enum AuthMigrationError {
    #[error("AUTH.MIGRATION_DATABASE: {0}")]
    Database(#[from] sqlx::Error),
    #[error("AUTH.MIGRATION_INCOMPATIBLE: {0}")]
    Incompatible(String),
}

pub async fn migrate_auth_schema(pool: &PgPool) -> Result<(), AuthMigrationError> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(ADVISORY_LOCK_ID)
        .execute(&mut *transaction)
        .await?;
    sqlx::raw_sql(include_str!("../migrations/0001_auth_schema.sql"))
        .execute(&mut *transaction)
        .await?;
    validate_owned_schema(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn validate_auth_schema(pool: &PgPool) -> Result<(), AuthMigrationError> {
    let mut connection = pool.acquire().await?;
    validate_owned_schema(&mut connection).await?;
    validate_applicant_dependency(&mut connection).await
}

async fn validate_owned_schema(connection: &mut PgConnection) -> Result<(), AuthMigrationError> {
    let version: Option<String> = sqlx::query_scalar(
        "SELECT version FROM auth_service.rust_schema_versions WHERE version=$1",
    )
    .bind(MIGRATION_VERSION)
    .fetch_optional(&mut *connection)
    .await?;
    if version.as_deref() != Some(MIGRATION_VERSION) {
        return Err(incompatible("Rust migration head is missing"));
    }
    let tables = sqlx::query(
        "SELECT table_name FROM information_schema.tables WHERE table_schema='auth_service'",
    )
    .fetch_all(&mut *connection)
    .await?;
    for expected in ["audit_logs", "session_history"] {
        if !tables
            .iter()
            .any(|row| row.get::<String, _>("table_name") == expected)
        {
            return Err(incompatible(&format!(
                "table auth_service.{expected} is missing"
            )));
        }
    }
    validate_columns(
        connection,
        "auth_service",
        "audit_logs",
        &[
            "id",
            "event_type",
            "user_id",
            "email",
            "organization_id",
            "session_id",
            "authentication_method",
            "success",
            "ip_address",
            "user_agent",
            "event_metadata",
            "created_at",
        ],
    )
    .await?;
    validate_columns(
        connection,
        "auth_service",
        "session_history",
        &[
            "id",
            "session_id",
            "user_id",
            "email",
            "organization_id",
            "user_type",
            "created_at",
            "expires_at",
            "expired_at",
            "revoked_at",
            "revocation_reason",
            "ip_address",
            "user_agent",
            "device_info",
            "last_activity",
        ],
    )
    .await?;
    Ok(())
}

async fn validate_applicant_dependency(
    connection: &mut PgConnection,
) -> Result<(), AuthMigrationError> {
    validate_columns(
        connection,
        "public",
        "applicants",
        &[
            "id",
            "account_id",
            "email",
            "surname",
            "given_names",
            "date_of_birth",
            "nationality",
            "identity_proofing_completed",
            "identity_proofing_date",
            "active",
            "suspended",
            "extra_data",
            "created_at",
            "updated_at",
            "deleted_at",
        ],
    )
    .await
}

async fn validate_columns(
    connection: &mut PgConnection,
    schema: &str,
    table: &str,
    required: &[&str],
) -> Result<(), AuthMigrationError> {
    let columns = sqlx::query(
        "SELECT column_name FROM information_schema.columns
         WHERE table_schema=$1 AND table_name=$2",
    )
    .bind(schema)
    .bind(table)
    .fetch_all(&mut *connection)
    .await?;
    for expected in required {
        if !columns
            .iter()
            .any(|row| row.get::<String, _>("column_name") == *expected)
        {
            return Err(incompatible(&format!(
                "{schema}.{table}.{expected} dependency is missing"
            )));
        }
    }
    Ok(())
}

fn incompatible(message: &str) -> AuthMigrationError {
    AuthMigrationError::Incompatible(message.to_owned())
}
