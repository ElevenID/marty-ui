use sqlx::{PgConnection, PgPool, Row};
use thiserror::Error;

const MIGRATION_VERSION: &str = "rust_organization_0001";
const ADVISORY_LOCK_ID: i64 = 718_431_212;

#[derive(Debug, Error)]
pub enum OrganizationMigrationError {
    #[error("ORGANIZATION.MIGRATION_DATABASE: {0}")]
    Database(#[from] sqlx::Error),
    #[error("ORGANIZATION.MIGRATION_INCOMPATIBLE: {0}")]
    Incompatible(String),
}

pub async fn migrate_organization_schema(pool: &PgPool) -> Result<(), OrganizationMigrationError> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(ADVISORY_LOCK_ID)
        .execute(&mut *transaction)
        .await?;
    sqlx::raw_sql(include_str!("../migrations/0001_organization_schema.sql"))
        .execute(&mut *transaction)
        .await?;
    validate_connection(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn validate_organization_schema(pool: &PgPool) -> Result<(), OrganizationMigrationError> {
    let mut connection = pool.acquire().await?;
    validate_connection(&mut connection).await
}

async fn validate_connection(
    connection: &mut PgConnection,
) -> Result<(), OrganizationMigrationError> {
    let version: Option<String> = sqlx::query_scalar(
        "SELECT version FROM organization_service.rust_schema_versions WHERE version=$1",
    )
    .bind(MIGRATION_VERSION)
    .fetch_optional(&mut *connection)
    .await?;
    if version.as_deref() != Some(MIGRATION_VERSION) {
        return Err(incompatible("Rust migration head is missing"));
    }

    let expected_tables = [
        "organizations",
        "members",
        "api_keys",
        "console_context_preferences",
        "join_codes",
        "permissions",
        "roles",
        "role_permissions",
        "member_roles",
        "policy_sets",
        "audit_events",
    ];
    let table_rows = sqlx::query(
        "SELECT table_name FROM information_schema.tables WHERE table_schema='organization_service'",
    )
    .fetch_all(&mut *connection)
    .await?;
    for table in expected_tables {
        if !table_rows
            .iter()
            .any(|row| row.get::<String, _>("table_name") == table)
        {
            return Err(incompatible(&format!("table {table} is missing")));
        }
    }

    let expected_columns = [
        ("organizations", "owner_id"),
        ("organizations", "join_mechanism"),
        ("organizations", "plan"),
        ("members", "user_id"),
        ("api_keys", "scope_type"),
        ("api_keys", "deployment_profile_id"),
        ("api_keys", "enabled"),
        ("api_keys", "updated_at"),
        ("roles", "is_default_for_new_members"),
        ("policy_sets", "cedar_schema_version"),
        ("audit_events", "metadata"),
    ];
    let column_rows = sqlx::query(
        "SELECT table_name, column_name FROM information_schema.columns \
         WHERE table_schema='organization_service'",
    )
    .fetch_all(&mut *connection)
    .await?;
    for (table, column) in expected_columns {
        if !column_rows.iter().any(|row| {
            row.get::<String, _>("table_name") == table
                && row.get::<String, _>("column_name") == column
        }) {
            return Err(incompatible(&format!("{table}.{column} is missing")));
        }
    }
    Ok(())
}

fn incompatible(message: &str) -> OrganizationMigrationError {
    OrganizationMigrationError::Incompatible(message.to_owned())
}
