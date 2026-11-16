use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

const MIGRATION_VERSION: &str = "rust_flow_0002";
const ADVISORY_LOCK_ID: i64 = 718_431_211;
const DEFAULT_ORGANIZATION_ID: Uuid = Uuid::from_u128(1);
const BUILTIN_DEFINITION_IDS: &[&str] = &[
    "71000000-0000-0000-0000-000000000001",
    "72000000-0000-0000-0000-000000000010",
    "72000000-0000-0000-0000-000000000040",
];

#[derive(Debug, Error)]
pub enum FlowMigrationError {
    #[error("FLOW.MIGRATION_DATABASE: {0}")]
    Database(#[from] sqlx::Error),
    #[error("FLOW.MIGRATION_INCOMPATIBLE: {0}")]
    Incompatible(String),
}

/// Schema commands load the configured tenant without service or Redis secrets.
pub fn flow_seed_organization_id(value: Option<&str>) -> Result<Uuid, FlowMigrationError> {
    marty_service_runtime::config::trimmed_nonempty(value)
        .map(str::parse)
        .transpose()
        .map_err(|_| incompatible("MARTY_ORG_ID is invalid"))
        .map(|value| value.unwrap_or(DEFAULT_ORGANIZATION_ID))
}

pub async fn migrate_flow_schema(pool: &PgPool) -> Result<(), FlowMigrationError> {
    migrate_flow_schema_for_organization(pool, DEFAULT_ORGANIZATION_ID).await
}

pub async fn migrate_flow_schema_for_organization(
    pool: &PgPool,
    organization_id: Uuid,
) -> Result<(), FlowMigrationError> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(ADVISORY_LOCK_ID)
        .execute(&mut *transaction)
        .await?;
    sqlx::raw_sql(include_str!("../migrations/0001_flow_schema.sql"))
        .execute(&mut *transaction)
        .await?;
    // Preserve the historical seed file. Its fixed tenant slots become a
    // transaction-local, bound value; no operator text is interpolated as SQL.
    sqlx::query("SELECT set_config('marty.flow_seed_organization_id', $1, true)")
        .bind(organization_id.to_string())
        .execute(&mut *transaction)
        .await?;
    // Audited: this transformation accepts no arguments and only combines
    // checked-in SQL with fixed SQL literals. The tenant remains a bind value.
    sqlx::raw_sql(sqlx::AssertSqlSafe(configured_builtin_seed_sql()?))
        .execute(&mut *transaction)
        .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0003_physical_start_intents.sql"
    ))
    .execute(&mut *transaction)
    .await?;
    validate_connection(&mut transaction).await?;
    validate_builtin_ownership(&mut transaction, organization_id).await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn validate_flow_schema(pool: &PgPool) -> Result<(), FlowMigrationError> {
    validate_flow_schema_for_organization(pool, DEFAULT_ORGANIZATION_ID).await
}

pub async fn validate_flow_schema_for_organization(
    pool: &PgPool,
    organization_id: Uuid,
) -> Result<(), FlowMigrationError> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *transaction)
        .await?;
    validate_connection(&mut transaction).await?;
    validate_builtin_ownership(&mut transaction, organization_id).await?;
    transaction.commit().await?;
    Ok(())
}

fn configured_builtin_seed_sql() -> Result<String, FlowMigrationError> {
    let historical = include_str!("../migrations/0002_builtin_flows.sql");
    let tenant = "'00000000-0000-0000-0000-000000000001'";
    let deployment = "WHERE id = '70000000-0000-0000-0000-000000000001';";
    if historical.matches(tenant).count() != 3 || historical.matches(deployment).count() != 1 {
        return Err(incompatible("historical Flow seed parameter slots changed"));
    }
    Ok(historical
        .replace(tenant, "current_setting('marty.flow_seed_organization_id')")
        .replace(
            deployment,
            "WHERE id = '70000000-0000-0000-0000-000000000001'
               AND organization_id = current_setting('marty.flow_seed_organization_id');",
        ))
}

async fn validate_builtin_ownership(
    connection: &mut sqlx::PgConnection,
    organization_id: Uuid,
) -> Result<(), FlowMigrationError> {
    let organization_id = organization_id.to_string();
    let owners: Vec<String> = sqlx::query_scalar(
        "SELECT organization_id FROM flow_service.flow_definitions WHERE id=ANY($1::text[])",
    )
    .bind(BUILTIN_DEFINITION_IDS)
    .fetch_all(&mut *connection)
    .await?;
    if owners.len() != BUILTIN_DEFINITION_IDS.len()
        || owners.iter().any(|owner| owner != &organization_id)
    {
        return Err(incompatible(
            "built-in Flow definition belongs to a different organization",
        ));
    }
    let bootstrap_owner: String = sqlx::query_scalar(
        "SELECT organization_id FROM flow_service.flow_instances
         WHERE id='71000000-0000-0000-0000-000000000101'
           AND flow_definition_id='71000000-0000-0000-0000-000000000001'",
    )
    .fetch_one(&mut *connection)
    .await?;
    if bootstrap_owner != organization_id {
        return Err(incompatible(
            "bootstrap Flow instance belongs to a different organization",
        ));
    }
    let deployment_table_exists: bool = sqlx::query_scalar(
        "SELECT to_regclass('deployment_profile_service.deployment_profiles') IS NOT NULL",
    )
    .fetch_one(&mut *connection)
    .await?;
    if deployment_table_exists {
        let deployment_owner: Option<String> = sqlx::query_scalar(
            "SELECT organization_id FROM deployment_profile_service.deployment_profiles
             WHERE id='70000000-0000-0000-0000-000000000001'",
        )
        .fetch_optional(&mut *connection)
        .await?;
        if deployment_owner.is_some_and(|owner| owner != organization_id) {
            return Err(incompatible(
                "login Flow deployment belongs to a different organization",
            ));
        }
    }
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
        ("physical_start_intents", "request_hash"),
        ("physical_start_intents", "definition_snapshot"),
        ("physical_start_intents", "initial_actor"),
        ("physical_start_intents", "original_deadline_at"),
        ("physical_start_intents", "key_source"),
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
    let acl_guard_shape: bool = sqlx::query_scalar(
        "SELECT EXISTS (
           SELECT 1 FROM pg_proc AS procedure
           JOIN pg_namespace AS namespace ON namespace.oid=procedure.pronamespace
           JOIN pg_language AS language ON language.oid=procedure.prolang
           WHERE namespace.nspname='flow_service'
             AND procedure.proname='physical_start_acl_ready'
             AND procedure.pronargs=0 AND procedure.prorettype='boolean'::regtype
             AND language.lanname='sql' AND NOT procedure.prosecdef)",
    )
    .fetch_one(&mut *connection)
    .await?;
    if !acl_guard_shape {
        return Err(incompatible("Physical start ACL guard is missing"));
    }
    let fenced_app: bool = sqlx::query_scalar(
        "SELECT current_user='marty' AND EXISTS (
           SELECT 1 FROM pg_namespace WHERE nspname='passport_cutover')",
    )
    .fetch_one(&mut *connection)
    .await?;
    if fenced_app {
        let acl_ready: bool = sqlx::query_scalar("SELECT flow_service.physical_start_acl_ready()")
            .fetch_one(&mut *connection)
            .await?;
        if !acl_ready {
            return Err(incompatible(
                "Fenced physical start intent access is incomplete",
            ));
        }
    }
    for (table, key) in [
        ("flow_service.flow_nonce_consumptions", "nonce_digest"),
        (
            "flow_service.physical_start_intents",
            "organization_id, key_hash",
        ),
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
