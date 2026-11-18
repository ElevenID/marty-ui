use std::collections::BTreeSet;

use marty_organization::migration::{migrate_organization_schema, validate_organization_schema};
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;

fn fixture() -> Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/organization-persistence-behavior.json"
    )))
    .expect("organization persistence fixture must be valid JSON")
}

#[test]
fn migration_source_owns_the_complete_non_destructive_schema() {
    let fixture = fixture();
    let migration = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/migrations/0001_organization_schema.sql"
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

    let expected_tables: BTreeSet<_> = fixture["tables"]
        .as_array()
        .expect("tables must be an array")
        .iter()
        .map(|table| table.as_str().expect("table must be a string"))
        .collect();
    for table in expected_tables {
        assert!(
            migration.contains(&format!("organization_service.{table}")),
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
    let Ok(database_url) = std::env::var("ORGANIZATION_POSTGRES_TEST_URL") else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("organization PostgreSQL contract database must connect");
    migrate_organization_schema(&pool)
        .await
        .expect("first Organization migration must pass");
    migrate_organization_schema(&pool)
        .await
        .expect("second Organization migration must be idempotent");
    validate_organization_schema(&pool)
        .await
        .expect("Organization schema validation must pass");
}
