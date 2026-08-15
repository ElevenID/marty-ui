use marty_signing_keys::profiles::{
    storage_key, DuplicateProfileRequest, FindProfilesRequest, ProfileError, ProfileStore,
};
use marty_signing_keys::registry::RegistryStore;
use redis::AsyncCommands;
use serde_json::Value;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires MARTY_TEST_REDIS_URL"]
async fn redis_round_trip_preserves_profile_crud_selection_and_tenant_scope() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("test Redis URL");
    let organization_id = format!("rust-signing-profiles-{}", Uuid::new_v4().simple());
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/issuer_profile_vectors.json")).unwrap();
    let mut profile = fixture["normalize"]["expected"].clone();
    profile["organization_id"] = Value::String(organization_id.clone());
    let profile_id = profile["id"].as_str().unwrap().to_string();
    let registry = RegistryStore::connect(&redis_url).await.unwrap();
    let store = ProfileStore::from_connection(registry.connection());

    assert!(store.list(&organization_id).await.unwrap()["profiles"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        store
            .put(&organization_id, &profile_id, profile.clone())
            .await
            .unwrap(),
        profile
    );
    assert_eq!(
        store.get(&organization_id, &profile_id).await.unwrap(),
        profile
    );
    let bound_registry = registry
        .bind_profile(&organization_id, &profile)
        .await
        .unwrap();
    assert_eq!(
        bound_registry["key_reference_purposes"]["svc-a"]["key-a"],
        serde_json::json!(["vc_jwt_issuer"])
    );
    assert_eq!(bound_registry["type_defaults"]["vc_jwt_issuer"], "svc-a");
    assert_eq!(bound_registry["format_defaults"]["dc+sd-jwt"], "svc-a");
    let mut conflicting_profile = profile.clone();
    conflicting_profile["key_purpose"] = Value::String("lti_tool_signing".to_string());
    assert!(matches!(
        registry
            .bind_profile(&organization_id, &conflicting_profile)
            .await
            .unwrap_err(),
        marty_signing_keys::registry::RegistryError::Invalid(_)
    ));
    let matches = store
        .find(
            &organization_id,
            FindProfilesRequest {
                active_only: true,
                issuer_did: profile["issuer_did"].as_str().map(str::to_string),
                key_purpose: Some("vc_jwt_issuer".to_string()),
                credential_format: Some("SD_JWT_VC".to_string()),
                algorithm: Some("ES256".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(matches, vec![profile.clone()]);
    let duplicate = store
        .find_duplicate(
            &organization_id,
            DuplicateProfileRequest {
                profile: profile.clone(),
                service_key_reference: Some("key-a".to_string()),
            },
        )
        .await
        .unwrap();
    assert!(duplicate.found);
    assert_eq!(duplicate.profile, Some(profile.clone()));

    let mut cross_tenant = profile.clone();
    cross_tenant["organization_id"] = Value::String("other-org".to_string());
    assert!(matches!(
        store
            .put(&organization_id, &profile_id, cross_tenant)
            .await
            .unwrap_err(),
        ProfileError::Invalid(_)
    ));

    let mut raw_connection = registry.connection();
    let corrupt_document = serde_json::json!({
        "profiles": [{
            "id": "cross-tenant",
            "organization_id": "other-org"
        }]
    });
    let _: () = raw_connection
        .set(
            storage_key(&organization_id),
            serde_json::to_string(&corrupt_document).unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        store.list(&organization_id).await.unwrap_err(),
        ProfileError::Corrupt(_)
    ));
    let _: () = raw_connection
        .set(
            storage_key(&organization_id),
            serde_json::to_string(&serde_json::json!({"profiles": [profile.clone()]})).unwrap(),
        )
        .await
        .unwrap();

    store.delete(&organization_id, &profile_id).await.unwrap();
    assert!(matches!(
        store.get(&organization_id, &profile_id).await.unwrap_err(),
        ProfileError::NotFound(_)
    ));

    let client = redis::Client::open(redis_url).unwrap();
    let mut connection = client.get_connection_manager().await.unwrap();
    let _: () = connection.del(storage_key(&organization_id)).await.unwrap();
    let _: () = connection
        .del(marty_signing_keys::registry::storage_key(&organization_id))
        .await
        .unwrap();
}
