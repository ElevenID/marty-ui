use marty_revocation_profile::{
    migrate_and_seed, DEFAULT_ORGANIZATION_ID, DEFAULT_REVOCATION_PROFILE_ID,
};
use sqlx::PgPool;
use std::process::Command;

const DEFAULT_DISPOSABLE_DATABASE: &str = "marty_revocation_migration_test";

#[tokio::test]
#[ignore = "requires MARTY_TEST_REVOCATION_MIGRATION_DATABASE_URL for the named disposable database"]
async fn rust_migrations_bootstrap_and_upgrade_the_released_schema() {
    let database_url = std::env::var("MARTY_TEST_REVOCATION_MIGRATION_DATABASE_URL")
        .expect("disposable test PostgreSQL URL");
    let pool = PgPool::connect(&database_url).await.unwrap();
    let database = sqlx::query_scalar::<_, String>("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let expected_database = std::env::var("MARTY_TEST_REVOCATION_MIGRATION_DATABASE_NAME")
        .unwrap_or_else(|_| DEFAULT_DISPOSABLE_DATABASE.into());
    assert_eq!(database, expected_database);

    sqlx::raw_sql("DROP SCHEMA IF EXISTS revocation_profile_service CASCADE")
        .execute(&pool)
        .await
        .unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_marty-revocation-profile"))
        .env("RP_MIGRATE_ONLY", "true")
        .env("ENVIRONMENT", "beta")
        .env("DATABASE_URL", &database_url)
        .env("PUBLIC_API_URL", "https://issuer.test")
        .env_remove("REDIS_URL")
        .env_remove("ORG_GRPC_TARGET")
        .env_remove("GRPC_SERVICE_TOKEN")
        .env_remove("GRPC_SERVICE_TOKEN_FILE")
        .status()
        .expect("run migration-only binary");
    assert!(status.success());
    migrate_and_seed(&pool, DEFAULT_ORGANIZATION_ID, "https://changed.test")
        .await
        .unwrap();

    let migration_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM revocation_profile_service.rust_schema_migrations",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(migration_count, 4);

    let profile = sqlx::query_as::<_, (String, String, String, serde_json::Value)>(
        r#"
        SELECT organization_id, name, status, issuer_config::jsonb
        FROM revocation_profile_service.revocation_profiles
        WHERE id = $1
        "#,
    )
    .bind(DEFAULT_REVOCATION_PROFILE_ID)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(profile.0, DEFAULT_ORGANIZATION_ID);
    assert_eq!(profile.1, "Marty Default Revocation");
    assert_eq!(profile.2, "active");
    assert_eq!(
        profile.3["status_list_base_url"],
        "https://issuer.test/v1/organizations/00000000-0000-0000-0000-000000000001/revocation-profiles/70000000-0000-0000-0000-000000000001/status-lists/{mechanism}/{purpose}"
    );

    sqlx::query(
        "UPDATE revocation_profile_service.revocation_profiles SET name = 'Customized' WHERE id = $1",
    )
    .bind(DEFAULT_REVOCATION_PROFILE_ID)
    .execute(&pool)
    .await
    .unwrap();
    migrate_and_seed(&pool, DEFAULT_ORGANIZATION_ID, "https://overwrite.test")
        .await
        .unwrap();
    let preserved_name = sqlx::query_scalar::<_, String>(
        "SELECT name FROM revocation_profile_service.revocation_profiles WHERE id = $1",
    )
    .bind(DEFAULT_REVOCATION_PROFILE_ID)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(preserved_name, "Customized");

    sqlx::raw_sql("DROP SCHEMA revocation_profile_service CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql(
        r#"
        DROP SCHEMA IF EXISTS issuance_service CASCADE;
        CREATE SCHEMA issuance_service;
        CREATE SCHEMA revocation_profile_service;
        CREATE TABLE revocation_profile_service.revocation_profiles (
            id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft',
            issuer_config JSON NOT NULL DEFAULT '{}',
            verifier_config JSON NOT NULL DEFAULT '{}',
            automation_config JSON NOT NULL DEFAULT '{}',
            supported_formats JSON NOT NULL DEFAULT '[]',
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL
        );
        INSERT INTO revocation_profile_service.revocation_profiles (
            id, organization_id, name, status, issuer_config, verifier_config,
            automation_config, supported_formats, created_at, updated_at
        ) VALUES (
            '70000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-000000000001',
            'Legacy Customized',
            'active',
            '{"status_list_base_url":"https://legacy.test/lists"}',
            '{}', '{}', '[]', NOW(), NOW()
        );
        CREATE TABLE issuance_service.issued_credentials (
            id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            revocation_profile_id TEXT,
            status_list_entries JSON NOT NULL DEFAULT '[]',
            issued_at TIMESTAMPTZ
        );
        INSERT INTO issuance_service.issued_credentials (
            id, organization_id, revocation_profile_id, status_list_entries, issued_at
        ) VALUES (
            'credential-before-rust-allocation',
            '00000000-0000-0000-0000-000000000001',
            '70000000-0000-0000-0000-000000000001',
            '[{"type":"BitstringStatusListEntry","index":7,"status_purpose":"revocation"}]',
            NOW()
        );
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    migrate_and_seed(&pool, DEFAULT_ORGANIZATION_ID, "https://unused.test")
        .await
        .unwrap();
    let upgraded = sqlx::query_as::<_, (String, serde_json::Value)>(
        r#"
        SELECT name, issuer_config::jsonb
        FROM revocation_profile_service.revocation_profiles
        WHERE id = $1
        "#,
    )
    .bind(DEFAULT_REVOCATION_PROFILE_ID)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(upgraded.0, "Legacy Customized");
    assert_eq!(
        upgraded.1["status_list_base_url"],
        "https://legacy.test/v1/organizations/00000000-0000-0000-0000-000000000001/revocation-profiles/70000000-0000-0000-0000-000000000001/status-lists/{mechanism}/{purpose}"
    );
    let backfilled = sqlx::query_as::<_, (String, i64)>(
        r#"
        SELECT credential_id, status_list_index
        FROM revocation_profile_service.status_list_allocations
        WHERE credential_id = 'credential-before-rust-allocation'
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(backfilled, ("credential-before-rust-allocation".into(), 7));
    let next_index = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT next_index
        FROM revocation_profile_service.status_list_allocation_counters
        WHERE organization_id = '00000000-0000-0000-0000-000000000001'
          AND profile_id = '70000000-0000-0000-0000-000000000001'
          AND status_list_format = 'bitstring'
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(next_index, 8);
    for table in [
        "cascade_revocation_operations",
        "revocation_batches",
        "status_list_allocations",
        "status_list_allocation_counters",
    ] {
        let present = sqlx::query_scalar::<_, bool>(
            "SELECT to_regclass('revocation_profile_service.' || $1) IS NOT NULL",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(present, "{table} was not created");
    }
}
