use sqlx::{PgConnection, PgPool, Row};
use thiserror::Error;

const MIGRATION_VERSION: &str = "rust_credential_template_0001";
const ADVISORY_LOCK_ID: i64 = 718_431_214;

#[derive(Debug, Error)]
pub enum CredentialTemplateMigrationError {
    #[error("CREDENTIAL_TEMPLATE.MIGRATION_DATABASE: {0}")]
    Database(#[from] sqlx::Error),
    #[error("CREDENTIAL_TEMPLATE.MIGRATION_INCOMPATIBLE: {0}")]
    Incompatible(String),
}

pub async fn migrate_credential_template_schema(
    pool: &PgPool,
) -> Result<(), CredentialTemplateMigrationError> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(ADVISORY_LOCK_ID)
        .execute(&mut *transaction)
        .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0001_credential_template_schema.sql"
    ))
    .execute(&mut *transaction)
    .await?;
    validate_connection(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn validate_credential_template_schema(
    pool: &PgPool,
) -> Result<(), CredentialTemplateMigrationError> {
    let mut connection = pool.acquire().await?;
    validate_connection(&mut connection).await
}

async fn validate_connection(
    connection: &mut PgConnection,
) -> Result<(), CredentialTemplateMigrationError> {
    let version: Option<String> = sqlx::query_scalar(
        "SELECT version FROM credential_template_service.rust_schema_versions WHERE version=$1",
    )
    .bind(MIGRATION_VERSION)
    .fetch_optional(&mut *connection)
    .await?;
    if version.as_deref() != Some(MIGRATION_VERSION) {
        return Err(incompatible("Rust migration head is missing"));
    }

    let expected_tables = [
        "credential_templates",
        "wallet_registry",
        "delivery_destinations",
        "rust_schema_versions",
    ];
    let table_rows = sqlx::query(
        "SELECT table_name FROM information_schema.tables WHERE table_schema='credential_template_service'",
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
        ("credential_templates", "zk_predicate_claims"),
        ("credential_templates", "credential_payload_format"),
        ("credential_templates", "wallet_configs"),
        ("credential_templates", "compliance_profile"),
        ("credential_templates", "compliance_profile_id"),
        ("credential_templates", "application_template_id"),
        ("credential_templates", "trust_profile_id"),
        ("credential_templates", "revocation_profile_id"),
        ("credential_templates", "issuer_algorithm"),
        ("credential_templates", "issuer_did"),
        ("credential_templates", "issuance_protocol"),
        ("wallet_registry", "routing_templates"),
        ("wallet_registry", "install_urls"),
        ("wallet_registry", "supports_digital_credentials"),
        ("wallet_registry", "supports_haip"),
    ];
    let column_rows = sqlx::query(
        "SELECT table_name, column_name FROM information_schema.columns \
         WHERE table_schema='credential_template_service'",
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

fn incompatible(message: &str) -> CredentialTemplateMigrationError {
    CredentialTemplateMigrationError::Incompatible(message.to_owned())
}
