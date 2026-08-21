use marty_trust_profile::run_migrations;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;

#[tokio::test]
async fn native_migration_is_additive_idempotent_and_scrubs_private_custody_metadata() {
    let Some(database_url) = std::env::var("TEST_POSTGRES_URL").ok() else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .unwrap();
    sqlx::raw_sql("DROP SCHEMA IF EXISTS trust_profile_service CASCADE")
        .execute(&pool)
        .await
        .unwrap();

    let first = run_migrations(&pool).await.unwrap();
    assert_eq!(first.metadata_rows_sanitized, 0);
    sqlx::query(
        "INSERT INTO trust_profile_service.organization_trust_profiles
         (id,organization_id,framework_id,name,compliance_status,metadata)
         VALUES('11111111-1111-4111-8111-111111111111','org-a',
                '22222222-2222-4222-8222-222222222222','Legacy','SETUP_REQUIRED',$1)",
    )
    .bind(json!({
        "public": "kept",
        "nested": {"kms_provider": "vault", "jwk": {"kty": "EC", "x": "x", "d": "private"}}
    }))
    .execute(&pool)
    .await
    .unwrap();

    let upgraded = run_migrations(&pool).await.unwrap();
    assert_eq!(upgraded.metadata_rows_sanitized, 1);
    let metadata: Value = sqlx::query_scalar(
        "SELECT metadata FROM trust_profile_service.organization_trust_profiles
         WHERE id='11111111-1111-4111-8111-111111111111'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        metadata,
        json!({"public": "kept", "nested": {"jwk": {"kty": "EC", "x": "x"}}})
    );
    let idempotent = run_migrations(&pool).await.unwrap();
    assert_eq!(idempotent.metadata_rows_sanitized, 0);

    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/trust-profile-service-behavior.json"
    ))
    .unwrap();
    for table in contract["persistence_tables"].as_array().unwrap() {
        let present: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(format!("trust_profile_service.{}", table.as_str().unwrap()))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(present);
    }

    sqlx::raw_sql("DROP SCHEMA trust_profile_service CASCADE")
        .execute(&pool)
        .await
        .unwrap();
}
