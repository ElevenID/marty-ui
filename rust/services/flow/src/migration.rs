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
    sqlx::raw_sql(include_str!("../migrations/0002_builtin_flows.sql"))
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
    let seed: Option<String> = sqlx::query_scalar(
        "SELECT version FROM flow_service.rust_seed_versions \
         WHERE version='rust_flow_seed_0001'",
    )
    .fetch_optional(&mut *connection)
    .await?;
    if seed.as_deref() != Some("rust_flow_seed_0001") {
        return Err(incompatible("Rust seed head is missing"));
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
    for (name, table, first, second) in [
        (
            "ux_flow_instances_org_application_flow_key",
            "flow_instances",
            "organization_id",
            Some("application_flow_key_hash"),
        ),
        (
            "ux_flow_instance_artifacts_issuance_transaction_id",
            "flow_instance_artifacts",
            "issuance_transaction_id",
            None,
        ),
    ] {
        let index = sqlx::query(
            "SELECT index.indisunique, index.indisvalid, index.indisready,
                    index.indnkeyatts, index.indnatts,
                    index.indpred IS NULL AS unfiltered,
                    index.indexprs IS NULL AS plain_columns,
                    pg_get_indexdef(index.indexrelid, 1, false) AS first_key,
                    pg_get_indexdef(index.indexrelid, 2, false) AS second_key
             FROM pg_index AS index
             JOIN pg_class AS relation ON relation.oid = index.indrelid
             JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
             WHERE namespace.nspname = 'flow_service'
               AND relation.relname = $1
               AND index.indexrelid = to_regclass($2)",
        )
        .bind(table)
        .bind(format!("flow_service.{name}"))
        .fetch_optional(&mut *connection)
        .await?;
        let Some(index) = index else {
            return Err(incompatible(&format!("{name} is missing")));
        };
        let first_key = index.try_get::<String, _>("first_key")?;
        let second_key = index
            .try_get::<Option<String>, _>("second_key")?
            .filter(|value| !value.is_empty());
        let key_count = if second.is_some() { 2 } else { 1 };
        if !index.try_get::<bool, _>("indisunique")?
            || !index.try_get::<bool, _>("indisvalid")?
            || !index.try_get::<bool, _>("indisready")?
            || !index.try_get::<bool, _>("unfiltered")?
            || !index.try_get::<bool, _>("plain_columns")?
            || index.try_get::<i16, _>("indnkeyatts")? != key_count
            || index.try_get::<i16, _>("indnatts")? != key_count
            || first_key != first
            || second_key.as_deref() != second
        {
            return Err(incompatible(&format!("{name} is incompatible")));
        }
    }
    Ok(())
}

fn incompatible(message: &str) -> FlowMigrationError {
    FlowMigrationError::Incompatible(message.into())
}
