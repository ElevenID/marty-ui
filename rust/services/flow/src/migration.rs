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
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *transaction)
        .await?;
    validate_connection(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
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
    let seeded_definitions = sqlx::query_scalar::<_, String>(
        "SELECT id FROM flow_service.flow_definitions WHERE id IN (
           '71000000-0000-0000-0000-000000000001',
           '72000000-0000-0000-0000-000000000010',
           '72000000-0000-0000-0000-000000000040')",
    )
    .fetch_all(&mut *connection)
    .await?;
    for expected in [
        "71000000-0000-0000-0000-000000000001",
        "72000000-0000-0000-0000-000000000010",
        "72000000-0000-0000-0000-000000000040",
    ] {
        if !seeded_definitions.iter().any(|id| id == expected) {
            return Err(incompatible("Rust seeded flow definition is missing"));
        }
    }
    let bootstrap: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM flow_service.flow_instances
         WHERE id='71000000-0000-0000-0000-000000000101'
           AND flow_definition_id='71000000-0000-0000-0000-000000000001')",
    )
    .fetch_one(&mut *connection)
    .await?;
    if !bootstrap {
        return Err(incompatible("Rust bootstrap flow instance is missing"));
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
    for (table, key) in [
        ("flow_service.flow_nonce_consumptions", "nonce_digest"),
        (
            "flow_service.flow_application_event_receipts",
            "event_id_sha256",
        ),
    ] {
        let definition: Option<String> = sqlx::query_scalar(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint
             WHERE conrelid=to_regclass($1) AND contype='p' AND convalidated",
        )
        .bind(table)
        .fetch_optional(&mut *connection)
        .await?;
        let expected_definition = format!("PRIMARY KEY ({key})");
        if definition.as_deref() != Some(expected_definition.as_str()) {
            return Err(incompatible("Rust Flow replay primary key is missing"));
        }
    }
    for (index, table, first_key, second_key) in [
        (
            "flow_service.ux_flow_instances_org_application_flow_key",
            "flow_service.flow_instances",
            "organization_id",
            Some("application_flow_key_hash"),
        ),
        (
            "flow_service.ux_flow_instance_artifacts_issuance_transaction_id",
            "flow_service.flow_instance_artifacts",
            "issuance_transaction_id",
            None,
        ),
    ] {
        let shape = sqlx::query(
            "SELECT indisunique, indisvalid, indisready, indnkeyatts, indnatts,
                    pg_get_indexdef(indexrelid, 1, false) AS first_key,
                    pg_get_indexdef(indexrelid, 2, false) AS second_key,
                    pg_get_expr(indpred, indrelid) AS predicate
             FROM pg_index
             WHERE indexrelid=to_regclass($1) AND indrelid=to_regclass($2)",
        )
        .bind(index)
        .bind(table)
        .fetch_optional(&mut *connection)
        .await?;
        let Some(shape) = shape else {
            return Err(incompatible("Rust Flow unique index is missing"));
        };
        if !shape.try_get::<bool, _>("indisunique")?
            || !shape.try_get::<bool, _>("indisvalid")?
            || !shape.try_get::<bool, _>("indisready")?
            || shape.try_get::<i16, _>("indnkeyatts")? != if second_key.is_some() { 2 } else { 1 }
            || shape.try_get::<i16, _>("indnatts")? != if second_key.is_some() { 2 } else { 1 }
            || shape.try_get::<String, _>("first_key")? != first_key
            || shape
                .try_get::<Option<String>, _>("second_key")?
                .as_deref()
                .filter(|value| !value.is_empty())
                != second_key
            || shape.try_get::<Option<String>, _>("predicate")?.is_some()
        {
            return Err(incompatible("Rust Flow unique index is incompatible"));
        }
    }
    Ok(())
}

fn incompatible(message: &str) -> FlowMigrationError {
    FlowMigrationError::Incompatible(message.into())
}
