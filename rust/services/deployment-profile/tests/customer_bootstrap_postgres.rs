use marty_deployment_profile::run_migrations;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[tokio::test]
async fn login_deployment_uses_customer_identity_and_refuses_reassignment_when_configured() {
    let Ok(database_url) = std::env::var("DEPLOYMENT_CUSTOMER_POSTGRES_TEST_URL") else {
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
    let existing: bool = sqlx::query_scalar(
        "SELECT to_regclass('deployment_profile_service.deployment_profiles') IS NOT NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!existing, "Use a fresh dedicated customer test database");
    let customer = Uuid::parse_str("750e8400-e29b-41d4-a716-446655440001").unwrap();
    let other = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    run_migrations(&pool, customer).await.unwrap();
    run_migrations(&pool, customer).await.unwrap();
    assert!(run_migrations(&pool, other).await.is_err());
    let organizations: Vec<String> = sqlx::query_scalar(
        "SELECT organization_id FROM deployment_profile_service.deployment_profiles",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(organizations, [customer.to_string()]);
    pool.close().await;
}
