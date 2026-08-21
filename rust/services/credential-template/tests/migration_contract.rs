use std::collections::BTreeSet;

use marty_credential_template::migration::{
    migrate_credential_template_schema, validate_credential_template_schema,
};
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;

fn fixture() -> Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/credential-template-persistence-behavior.json"
    )))
    .expect("credential-template persistence fixture must be valid JSON")
}

#[test]
fn migration_source_owns_the_complete_non_destructive_schema() {
    let fixture = fixture();
    let migration = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/migrations/0001_credential_template_schema.sql"
    ));
    let uppercase = migration.to_uppercase();
    assert!(!uppercase.contains("DROP TABLE"));
    assert!(!uppercase.contains("DROP SCHEMA"));
    assert!(!migration.contains("pg_advisory"));
    assert!(
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/migration.rs"))
            .contains("pg_advisory_xact_lock")
    );
    assert!(migration.contains(
        fixture["migration_head"]
            .as_str()
            .expect("migration head must be a string")
    ));
    let reconciliation = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/migrations/0002_legacy_data_reconciliation.sql"
    ));
    assert!(reconciliation.contains("rust_credential_template_0002"));
    assert!(reconciliation.contains("Legacy mDL Issuance Prototype"));
    assert!(reconciliation.contains("Legacy ePassport Prototype"));
    assert!(reconciliation.contains("ALTER COLUMN compliance_profile_id SET NOT NULL"));
    assert!(reconciliation.contains("OpenBadgeCredential#jwt-vc"));
    for retired in [
        "auto_generate_artifacts",
        "issuer_certificate_chain_pem",
        "remote_signing_config",
        "issuer_key_id",
        "key_access_mode",
        "issuer_profile_id",
    ] {
        assert!(migration.contains(&format!("DROP COLUMN IF EXISTS {retired}")));
    }

    let expected_tables: BTreeSet<_> = fixture["tables"]
        .as_array()
        .expect("tables must be an array")
        .iter()
        .map(|table| table.as_str().expect("table must be a string"))
        .collect();
    for table in expected_tables {
        assert!(
            migration.contains(&format!("credential_template_service.{table}")),
            "migration is missing {table}"
        );
    }
    for column in fixture["required_compatibility_columns"]
        .as_array()
        .expect("compatibility columns must be an array")
    {
        let (_, column) = column
            .as_str()
            .expect("column must be a string")
            .split_once('.')
            .expect("column must use table.column form");
        assert!(migration.contains(column), "migration is missing {column}");
    }
}

#[tokio::test]
async fn live_postgres_migration_is_idempotent_when_configured() {
    let Ok(database_url) = std::env::var("CREDENTIAL_TEMPLATE_POSTGRES_TEST_URL") else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("credential-template PostgreSQL contract database must connect");
    migrate_credential_template_schema(&pool)
        .await
        .expect("first Credential Template migration must pass");
    migrate_credential_template_schema(&pool)
        .await
        .expect("second Credential Template migration must be idempotent");
    validate_credential_template_schema(&pool)
        .await
        .expect("Credential Template schema validation must pass");
}
