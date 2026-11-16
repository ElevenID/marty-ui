use chrono::Utc;
use marty_organization::{
    migration::migrate_organization_schema, postgres::PostgresOrganizationStore,
    reconcile_organization_startup,
};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[tokio::test]
async fn customer_bootstrap_preserves_configured_and_existing_identity_when_configured() {
    let Ok(database_url) = std::env::var("ORGANIZATION_CUSTOMER_POSTGRES_TEST_URL") else {
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
    let existing: bool =
        sqlx::query_scalar("SELECT to_regclass('organization_service.organizations') IS NOT NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!existing, "Use a fresh dedicated customer test database");
    migrate_organization_schema(&pool).await.unwrap();
    let store = PostgresOrganizationStore::new(pool.clone());
    let id = Uuid::parse_str("750e8400-e29b-41d4-a716-446655440001").unwrap();
    let admin_email = "admin@canyon-skills.example";
    let result = reconcile_organization_startup(
        &store,
        id,
        "Canyon Skills Academy",
        "canyon-skills",
        Some(admin_email),
        None,
        Utc::now(),
    )
    .await
    .unwrap();
    assert!(result.default_organization_created);
    assert_eq!(result.bootstrap_memberships_reconciled, 1);
    let first = store.organization_by_id(id).await.unwrap().unwrap();
    assert_eq!(first.name, "Canyon Skills Academy");
    assert_eq!(first.slug, "canyon-skills");
    assert_eq!(first.display_name.as_deref(), Some("Canyon Skills Academy"));
    assert!(first.contact_email.is_none());
    assert!(first.website.is_none());
    let admin = store
        .member_by_email_and_organization(admin_email, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(admin.organization_id, id);
    assert_eq!(admin.roles.len(), 1);
    assert_eq!(admin.roles[0].name, "admin");
    assert_eq!(admin.roles[0].organization_id, id);
    assert!(store
        .member_by_email_and_organization(admin_email, Uuid::from_u128(1))
        .await
        .unwrap()
        .is_none());
    let repeated = reconcile_organization_startup(
        &store,
        id,
        "Changed Configuration",
        "changed-config",
        Some(admin_email),
        None,
        Utc::now(),
    )
    .await
    .unwrap();
    assert!(!repeated.default_organization_created);
    assert_eq!(repeated.bootstrap_memberships_reconciled, 1);
    let repeated_admin = store
        .member_by_email_and_organization(admin_email, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(repeated_admin.id, admin.id);
    assert_eq!(repeated_admin.roles.len(), 1);
    assert_eq!(repeated_admin.roles[0].id, admin.roles[0].id);
    assert_eq!(repeated_admin.roles[0].name, "admin");
    assert_eq!(repeated_admin.roles[0].organization_id, id);
    assert_eq!(
        repeated_admin.roles[0].created_at,
        admin.roles[0].created_at
    );
    let preserved = store.organization_by_id(id).await.unwrap().unwrap();
    assert_eq!(preserved.name, first.name);
    assert_eq!(preserved.slug, first.slug);
    assert_eq!(preserved.created_at, first.created_at);
    assert!(reconcile_organization_startup(
        &store,
        Uuid::new_v4(),
        "Another Academy",
        "canyon-skills",
        None,
        None,
        Utc::now(),
    )
    .await
    .is_err());
    pool.close().await;
}
