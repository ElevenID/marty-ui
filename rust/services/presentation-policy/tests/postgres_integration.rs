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
    assert_eq!(reconcile_builtin_policies(&store).await.unwrap(), 5);
    assert_eq!(reconcile_builtin_policies(&store).await.unwrap(), 5);
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
