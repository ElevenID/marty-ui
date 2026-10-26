//! Actual SQL migration/index/repository controls; no wallet result is claimed.
use marty_issuance_service::{
    credential_management::{CredentialManagementRepository, ManagedCredentialStatus},
    credential_management_postgres::PostgresCredentialManagementRepository,
};
use marty_mdoc_status_binding::MdocStatusReference;
use sqlx::postgres::PgPoolOptions;

#[tokio::test]
async fn tenant_mdoc_reference_index_resolves_actual_state_without_adopting_foreign_or_unknown_rows_when_configured(
) {
    let Ok(database_url) = std::env::var("ISSUANCE_POSTGRES_TEST_URL") else {
        return;
    };
    let name = url::Url::parse(&database_url)
        .unwrap()
        .path()
        .trim_start_matches('/')
        .to_owned();
    assert!(
        name.ends_with("_test"),
        "Use only an owned dedicated test database"
    );
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .unwrap();
    let existing: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema IN ('issuance_service','credential_template_service','organization_service')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        existing, 0,
        "Preserve existing fixtures; this contract requires a fresh owned database"
    );
    // Install the actual prerequisite catalogs in the production bootstrap
    // order. Empty catalogs deliberately avoid unrelated tenant seed data.
    for migration in [
        include_str!("../../organization/migrations/0001_organization_schema.sql"),
        include_str!("../../credential-template/migrations/0001_credential_template_schema.sql"),
        include_str!("../../credential-template/migrations/0002_legacy_data_reconciliation.sql"),
    ] {
        sqlx::raw_sql(migration).execute(&pool).await.unwrap();
    }
    // Exercise the real production migration owner and read-only startup
    // validator against PostgreSQL, rather than a hand-maintained table copy.
    marty_issuance_service::migration::migrate_owned_schema(&pool)
        .await
        .unwrap();
    marty_issuance_service::migration::validate(&pool)
        .await
        .unwrap();
    let migration = include_str!("../migrations/0009_authenticated_mdoc_status_binding.sql");
    sqlx::raw_sql(migration).execute(&pool).await.unwrap();
    let reference = MdocStatusReference::parse(&format!(
        "urn:mdoc-status:v1:{}:{}",
        "a".repeat(64),
        "b".repeat(64)
    ))
    .unwrap();
    let insert="INSERT INTO issuance_service.issued_credentials(
        id,transaction_id,organization_id,credential_template_id,issuer_did,status,mdoc_status_reference,
        credential_jwt,credential_hash,status_updated_at,revoked,issued_at)
        VALUES ($1,$1,$2,'template','did:web:controlled.test','active',$3,
        'public-contract-input','controlled-hash',NOW(),false,NOW())";
    sqlx::query(insert)
        .bind("owned")
        .bind("org-a")
        .bind(reference.to_string())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(insert)
        .bind("other-tenant")
        .bind("org-b")
        .bind(reference.to_string())
        .execute(&pool)
        .await
        .unwrap();
    let duplicate = sqlx::query(insert)
        .bind("duplicate")
        .bind("org-a")
        .bind(reference.to_string())
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(
        duplicate.as_database_error().unwrap().code().as_deref(),
        Some("23505")
    );
    let invalid = sqlx::query(insert)
        .bind("malformed")
        .bind("org-a")
        .bind("urn:mdoc-status:v1:invalid")
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(
        invalid.as_database_error().unwrap().code().as_deref(),
        Some("23514")
    );
    sqlx::query(insert)
        .bind("legacy")
        .bind("org-a")
        .bind(Option::<String>::None)
        .execute(&pool)
        .await
        .unwrap();
    let repository = PostgresCredentialManagementRepository::new(pool.clone());
    let active = repository
        .get_by_mdoc_reference("org-a", &reference)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.id, "owned");
    assert_eq!(active.status, ManagedCredentialStatus::Active);
    assert_eq!(
        repository
            .get_by_mdoc_reference("org-b", &reference)
            .await
            .unwrap()
            .unwrap()
            .id,
        "other-tenant"
    );
    assert!(repository
        .get_by_mdoc_reference("foreign", &reference)
        .await
        .unwrap()
        .is_none());
    let wrong = MdocStatusReference::parse(
        &reference
            .to_string()
            .replace(&"a".repeat(64), &"c".repeat(64)),
    )
    .unwrap();
    assert!(repository
        .get_by_mdoc_reference("org-a", &wrong)
        .await
        .unwrap()
        .is_none());
    sqlx::query("UPDATE issuance_service.issued_credentials SET status='revoked',revoked=true WHERE id='owned'")
        .execute(&pool).await.unwrap();
    let revoked = repository
        .get_by_mdoc_reference("org-a", &reference)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(revoked.id, "owned");
    assert_eq!(revoked.status, ManagedCredentialStatus::Revoked);
    assert_eq!(
        repository
            .get_by_mdoc_reference("org-b", &reference)
            .await
            .unwrap()
            .unwrap()
            .status,
        ManagedCredentialStatus::Active
    );
    pool.close().await;
}
