use sqlx::{PgPool, Row};
use thiserror::Error;

const MIGRATION_VERSION: &str = "rust_flow_0001";
const ADVISORY_LOCK_ID: i64 = 718_431_211;

#[derive(Debug, Error)]
pub enum FlowMigrationError {
    #[error("FLOW.MIGRATION_DATABASE: {0}")]
    Database(#[from] sqlx::Error),
    #[error("FLOW.MIGRATION_INCOMPATIBLE: {0}")]
    Incompatible(String),
}

pub async fn migrate_flow_schema(pool: &PgPool) -> Result<(), FlowMigrationError> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(ADVISORY_LOCK_ID)
        .execute(&mut *transaction)
        .await?;
    sqlx::raw_sql(include_str!("../migrations/0001_flow_schema.sql"))
        .execute(&mut *transaction)
        .await?;
    validate_connection(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn validate_flow_schema(pool: &PgPool) -> Result<(), FlowMigrationError> {
    let mut connection = pool.acquire().await?;
    validate_connection(&mut connection).await
}

async fn validate_connection(
    connection: &mut sqlx::PgConnection,
) -> Result<(), FlowMigrationError> {
    let version: Option<String> = sqlx::query_scalar(
        "SELECT version FROM flow_service.rust_schema_versions WHERE version=$1",
    )
    .bind(MIGRATION_VERSION)
    .fetch_optional(&mut *connection)
    .await?;
    if version.as_deref() != Some(MIGRATION_VERSION) {
        return Err(incompatible("Rust migration head is missing"));
    }

    let expected = [
        ("flow_definitions", "retry_cooldown_minutes"),
        ("flow_instances", "state_history"),
        ("flow_instance_artifacts", "credential_offer_uris"),
        ("flow_callback_outbox", "lease_token"),
        ("flow_application_event_receipts", "payload_sha256"),
    ];
    let rows = sqlx::query(
        "SELECT table_name, column_name FROM information_schema.columns \
         WHERE table_schema='flow_service'",
    )
    .fetch_all(&mut *connection)
    .await?;
    for (table, column) in expected {
        if !rows.iter().any(|row| {
            row.get::<String, _>("table_name") == table
                && row.get::<String, _>("column_name") == column
        }) {
            return Err(incompatible(&format!("{table}.{column} is missing")));
        }
    }
    Ok(())
}

fn incompatible(message: &str) -> FlowMigrationError {
    FlowMigrationError::Incompatible(message.into())
}
