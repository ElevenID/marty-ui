//! Actual configured seed SQL, ownership refusal and retained-data checks.
use marty_flow::{
    flow_seed_organization_id, migrate_flow_schema_for_organization,
    validate_flow_schema_for_organization,
};
use serde_json::{json, Value};
use sqlx::{postgres::PgConnectOptions, PgPool};
use uuid::Uuid;

const CUSTOMER: &str = "750e8400-e29b-41d4-a716-446655440001";
const LOGIN_FLOW: &str = "71000000-0000-0000-0000-000000000001";
const DEPLOYMENT: &str = "70000000-0000-0000-0000-000000000001";

#[test]
fn migration_configuration_validates_customer_uuid_before_database_access() {
    assert_eq!(flow_seed_organization_id(None).unwrap(), Uuid::from_u128(1));
    assert_eq!(
        flow_seed_organization_id(Some(&format!(" {CUSTOMER} ")))
            .unwrap()
            .to_string(),
        CUSTOMER,
    );
    assert!(flow_seed_organization_id(Some("invalid-tenant")).is_err());
}

async fn snapshot(pool: &PgPool) -> Value {
    sqlx::query_scalar(
        "SELECT jsonb_build_object(
            'definitions', (SELECT jsonb_agg(to_jsonb(d) ORDER BY id) FROM flow_service.flow_definitions d),
            'instances', (SELECT jsonb_agg(to_jsonb(i) ORDER BY id) FROM flow_service.flow_instances i),
            'deployments', (SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM deployment_profile_service.deployment_profiles p))",
    ).fetch_one(pool).await.unwrap()
}

#[tokio::test]
async fn customer_seed_owns_its_graph_and_refuses_existing_foreign_records_when_configured() {
    let Ok(database_url) = std::env::var("FLOW_CUSTOMER_POSTGRES_TEST_URL") else {
        eprintln!("FLOW_CUSTOMER_POSTGRES_TEST_URL is not configured; customer PostgreSQL contract skipped");
        return;
    };
    let options: PgConnectOptions = database_url.parse().unwrap();
    assert!(matches!(options.get_host(), "127.0.0.1" | "localhost"));
    assert_eq!(options.get_database(), Some("flow_customer_test"));
    let pool = PgPool::connect_with(options).await.unwrap();
    let existing: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables
         WHERE table_schema IN ('flow_service','deployment_profile_service')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(existing, 0, "Use a fresh dedicated customer test database");
    sqlx::raw_sql(
        "CREATE SCHEMA deployment_profile_service;
         CREATE TABLE deployment_profile_service.deployment_profiles (
             id text PRIMARY KEY, organization_id text NOT NULL,
             enabled_flow_ids jsonb NOT NULL DEFAULT '[]'::jsonb);",
    )
    .execute(&pool)
    .await
    .unwrap();
    let customer = flow_seed_organization_id(Some(CUSTOMER)).unwrap();
    let other = Uuid::from_u128(1);
    sqlx::query(
        "INSERT INTO deployment_profile_service.deployment_profiles(id,organization_id,enabled_flow_ids)
         VALUES($1,$2,$3)",
    ).bind(DEPLOYMENT).bind(other.to_string()).bind(json!(["operator-flow"]))
        .execute(&pool).await.unwrap();

    // Refuse attachment to a foreign retained deployment. All fresh Flow DDL
    // and seeds must roll back with the failure.
    assert!(migrate_flow_schema_for_organization(&pool, customer)
        .await
        .is_err());
    let absent: bool =
        sqlx::query_scalar("SELECT to_regclass('flow_service.flow_definitions') IS NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(absent);
    let retained: Value = sqlx::query_scalar(
        "SELECT enabled_flow_ids FROM deployment_profile_service.deployment_profiles WHERE id=$1",
    )
    .bind(DEPLOYMENT)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(retained, json!(["operator-flow"]));

    // Test setup now supplies the intended customer-owned deployment.
    sqlx::query(
        "UPDATE deployment_profile_service.deployment_profiles SET organization_id=$1 WHERE id=$2",
    )
    .bind(CUSTOMER)
    .bind(DEPLOYMENT)
    .execute(&pool)
    .await
    .unwrap();
    migrate_flow_schema_for_organization(&pool, customer)
        .await
        .unwrap();
    validate_flow_schema_for_organization(&pool, customer)
        .await
        .unwrap();
    let initial = snapshot(&pool).await;
    let definitions = initial["definitions"].as_array().unwrap();
    assert_eq!(definitions.len(), 3);
    assert!(definitions
        .iter()
        .all(|definition| definition["organization_id"] == CUSTOMER));
    assert_eq!(initial["instances"].as_array().unwrap().len(), 1);
    assert_eq!(initial["instances"][0]["organization_id"], CUSTOMER);
    assert_eq!(
        initial["deployments"][0]["enabled_flow_ids"],
        json!(["operator-flow", LOGIN_FLOW])
    );

    // Repeated startup preserves operator edits and does not append duplicate
    // references or silently move a record to another installation tenant.
    sqlx::query(
        "UPDATE flow_service.flow_definitions SET name='Customer-managed login' WHERE id=$1",
    )
    .bind(LOGIN_FLOW)
    .execute(&pool)
    .await
    .unwrap();
    let before = snapshot(&pool).await;
    migrate_flow_schema_for_organization(&pool, customer)
        .await
        .unwrap();
    assert_eq!(snapshot(&pool).await, before);
    assert!(migrate_flow_schema_for_organization(&pool, other)
        .await
        .is_err());
    assert!(validate_flow_schema_for_organization(&pool, other)
        .await
        .is_err());
    assert_eq!(snapshot(&pool).await, before);

    for (table, change, id) in [
        (
            "definitions",
            "UPDATE flow_service.flow_definitions SET organization_id=$1 WHERE id=$2",
            LOGIN_FLOW,
        ),
        (
            "instances",
            "UPDATE flow_service.flow_instances SET organization_id=$1 WHERE id=$2",
            "71000000-0000-0000-0000-000000000101",
        ),
        (
            "deployments",
            "UPDATE deployment_profile_service.deployment_profiles SET organization_id=$1 WHERE id=$2",
            DEPLOYMENT,
        ),
    ] {
        sqlx::query(change)
            .bind(other.to_string())
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        let before_refusal = snapshot(&pool).await;
        assert!(
            migrate_flow_schema_for_organization(&pool, customer)
                .await
                .is_err(),
            "{table}"
        );
        assert!(
            validate_flow_schema_for_organization(&pool, customer)
                .await
                .is_err(),
            "{table}"
        );
        assert_eq!(snapshot(&pool).await, before_refusal, "{table}");
        sqlx::query(change)
            .bind(CUSTOMER)
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
    }
    validate_flow_schema_for_organization(&pool, customer)
        .await
        .unwrap();
    pool.close().await;
}
