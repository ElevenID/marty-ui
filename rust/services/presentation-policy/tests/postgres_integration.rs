use chrono::Utc;
use marty_presentation_policy::{
    migrate_presentation_policy_schema, reconcile_builtin_policies,
    validate_presentation_policy_schema, PolicyStatus, PostgresPolicyStore, PresentationPolicy,
};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

fn policy(id: Uuid, organization_id: Uuid) -> PresentationPolicy {
    let now = Utc::now();
    serde_json::from_value(json!({
        "id":id, "organization_id":organization_id, "name":"PostgreSQL contract", "description":"Lossless policy", "status":"draft",
        "display_metadata":{"title":"Login","description":"","purpose":"identity_verification","purpose_description":null,"verifier_name":"Marty","verifier_logo_url":null,"privacy_policy_url":null,"terms_of_service_url":null},
        "required_claims":[], "accepted_credential_types":[], "credential_requirements":[], "alternative_requirements":[], "presentation_proof_required":true,
        "trust_profile_id":null, "holder_binding":{"required":true,"binding_methods":["DEVICE_KEY"],"proof_profiles":["OID4VP_VERIFIABLE_PRESENTATION"],"proof_freshness":{"challenge_required":true,"audience_binding_required":true}},
        "freshness":null, "issuer_constraints":null, "credential_ranking_strategy":"CUSTOM", "credential_ranking_weights":{"freshness":1.0}, "purpose":"Login",
        "compliance_profile_id":null, "prefer_predicates":true, "fallback_policy":"require_predicate", "supported_circuits":["age_over_21"], "version":1,
        "created_at":now, "updated_at":now
    }))
    .unwrap()
}

#[tokio::test]
async fn migration_and_complete_repository_round_trip_when_configured() {
    let Ok(database_url) = std::env::var("PRESENTATION_POLICY_POSTGRES_TEST_URL") else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("Presentation Policy PostgreSQL contract database must connect");
    migrate_presentation_policy_schema(&pool).await.unwrap();
    migrate_presentation_policy_schema(&pool).await.unwrap();
    validate_presentation_policy_schema(&pool).await.unwrap();
    let store = PostgresPolicyStore::new(pool);
    assert_eq!(
        reconcile_builtin_policies(&store, Uuid::from_u128(1))
            .await
            .unwrap(),
        5
    );
    assert_eq!(
        reconcile_builtin_policies(&store, Uuid::from_u128(1))
            .await
            .unwrap(),
        5
    );
    assert!(store
        .policy_by_id("50000000-0000-0000-0000-000000000005".parse().unwrap())
        .await
        .unwrap()
        .is_some());
    let id = Uuid::new_v4();
    let organization_id = Uuid::new_v4();
    let other_organization_id = Uuid::new_v4();
    let expected = policy(id, organization_id);
    store.delete_policy(id).await.unwrap();
    store.save_policy(&expected).await.unwrap();
    let actual = store.policy_by_id(id).await.unwrap().unwrap();
    assert_eq!(actual, expected);
    assert_eq!(actual.status, PolicyStatus::Draft);
    assert!(store
        .policies_by_organization(organization_id)
        .await
        .unwrap()
        .iter()
        .any(|policy| policy.id == id));
    assert!(!store
        .policies_by_organization(other_organization_id)
        .await
        .unwrap()
        .iter()
        .any(|policy| policy.id == id));
    store.delete_policy(id).await.unwrap();
    assert!(store.policy_by_id(id).await.unwrap().is_none());
}

#[tokio::test]
async fn customer_login_policies_remain_tenant_owned_when_configured() {
    let Ok(database_url) = std::env::var("PRESENTATION_POLICY_CUSTOMER_POSTGRES_TEST_URL") else {
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
        "SELECT to_regclass('presentation_policy_service.presentation_policies') IS NOT NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!existing, "Use a fresh dedicated customer test database");
    migrate_presentation_policy_schema(&pool).await.unwrap();
    let store = PostgresPolicyStore::new(pool.clone());
    let customer = Uuid::parse_str("750e8400-e29b-41d4-a716-446655440001").unwrap();
    assert_eq!(
        reconcile_builtin_policies(&store, customer).await.unwrap(),
        5
    );
    assert_eq!(
        reconcile_builtin_policies(&store, customer).await.unwrap(),
        5
    );
    assert_eq!(
        store
            .policies_by_organization(customer)
            .await
            .unwrap()
            .len(),
        4
    );
    let login_id = Uuid::parse_str("50000000-0000-0000-0000-000000000004").unwrap();
    let login = store.policy_by_id(login_id).await.unwrap().unwrap();
    assert_eq!(login.organization_id, customer);
    assert!(reconcile_builtin_policies(&store, Uuid::from_u128(1))
        .await
        .is_err());
    let mut foreign = login.clone();
    foreign.organization_id = Uuid::from_u128(1);
    assert!(store.save_policy(&foreign).await.is_err());
    assert_eq!(store.policy_by_id(login_id).await.unwrap().unwrap(), login);
    let demo = store
        .policy_by_id(Uuid::parse_str("50000000-0000-0000-0000-000000000001").unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        demo.organization_id.to_string(),
        "22222222-2222-2222-2222-222222222222"
    );
    pool.close().await;
}
