//! Execute the actual fresh migration with a non-default customer tenant.
use marty_issuance_service::migration::{migrate_owned_schema, seed_organization_id};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, Row};

#[tokio::test]
async fn fresh_customer_migration_seeds_only_its_active_catalog_when_configured() {
    let Ok(database_url) = std::env::var("ISSUANCE_CUSTOMER_POSTGRES_TEST_URL") else {
        return;
    };
    assert!(url::Url::parse(&database_url)
        .unwrap()
        .path()
        .ends_with("_test"));
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .unwrap();
    let existing: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema IN ('issuance_service','credential_template_service','organization_service')",
    ).fetch_one(&pool).await.unwrap();
    assert_eq!(existing, 0, "Use a fresh dedicated customer test database");
    for migration in [
        include_str!("../../organization/migrations/0001_organization_schema.sql"),
        include_str!("../../credential-template/migrations/0001_credential_template_schema.sql"),
        include_str!("../../credential-template/migrations/0002_legacy_data_reconciliation.sql"),
    ] {
        sqlx::raw_sql(migration).execute(&pool).await.unwrap();
    }
    let organization_id =
        seed_organization_id(Some("750e8400-e29b-41d4-a716-446655440001")).unwrap();
    sqlx::query(
        "INSERT INTO organization_service.organizations (id,name,slug,status,created_at,updated_at)
         VALUES ($1,'Canyon Skills Academy','canyon-skills','active',NOW(),NOW())",
    )
    .bind(organization_id)
    .execute(&pool)
    .await
    .unwrap();
    for (id, organization, status) in [
        (
            "50000000-0000-0000-0000-000000000040",
            organization_id.to_string(),
            "active",
        ),
        (
            "50000000-0000-0000-0000-000000000041",
            "00000000-0000-0000-0000-000000000001".into(),
            "active",
        ),
        (
            "50000000-0000-0000-0000-000000000042",
            organization_id.to_string(),
            "draft",
        ),
    ] {
        sqlx::query(
            "INSERT INTO credential_template_service.credential_templates
             (id,organization_id,name,status,credential_type,vct,claims,compliance_profile_id,created_at,updated_at)
             VALUES ($1,$2,'Course Completion Badge',$3,'OpenBadgeCredential','https://academy.example.test/badge',$4,'customer-badge-profile',NOW(),NOW())",
        ).bind(id).bind(organization).bind(status).bind(json!([
            {"name":"organization_name","claim_type":"string"},
            {"name":"learner_name","claim_type":"string"},
        ])).execute(&pool).await.unwrap();
    }
    migrate_owned_schema(&pool, organization_id).await.unwrap();
    migrate_owned_schema(&pool, organization_id).await.unwrap();
    let rows = sqlx::query(
        "SELECT id,organization_id,credential_template_id,claim_collection_rules
         FROM issuance_service.application_templates",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get::<String, _>("id"),
        "95cab1cf-911b-5b98-8951-5f7668dbe879"
    );
    assert_eq!(
        rows[0].get::<String, _>("organization_id"),
        organization_id.to_string()
    );
    assert_eq!(
        rows[0].get::<String, _>("credential_template_id"),
        "50000000-0000-0000-0000-000000000040"
    );
    let rules: Value = rows[0].get("claim_collection_rules");
    assert!(rules.as_array().unwrap().contains(&json!({
        "claim_name":"organization_name", "source":"SYSTEM",
        "source_config":{"system_field":"constant","value":"Canyon Skills Academy"},
    })));
    pool.close().await;
}
