use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::routing::any;
use axum::Router;
use marty_signing_keys::documents::{
    did_storage_key, slug_storage_key, DocumentStore, LoadDidRequest,
};
use marty_signing_keys::profiles::{
    storage_key, DuplicateProfileRequest, FindProfilesRequest, ProfileError, ProfileStore,
};
use marty_signing_keys::registry::RegistryStore;
use redis::AsyncCommands;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tower::ServiceExt;
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

async fn transit_public_key(request: Request<Body>) -> Response {
    let key = request.uri().path().rsplit('/').next().unwrap_or_default();
    let material = match key {
        "issuer-a" => "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        "issuer-b" => "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
        _ => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from(r#"{"errors":["key not found"]}"#))
                .unwrap();
        }
    };
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "data": {
                    "latest_version": 1,
                    "type": "ed25519",
                    "keys": {"1": {"name": "ed25519", "public_key": material}}
                }
            })
            .to_string(),
        ))
        .unwrap()
}

#[tokio::test]
#[ignore = "requires MARTY_TEST_REDIS_URL"]
async fn provider_rebind_publishes_before_cutover_and_preserves_the_prior_method() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("test Redis URL");
    let suffix = Uuid::new_v4().simple().to_string();
    let organization_id = format!("rust-issuer-rebind-{suffix}");
    let slug = format!("rebind-{suffix}");
    let issuer_did = format!("did:web:issuer.example:orgs:{slug}");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, Router::new().fallback(any(transit_public_key)))
            .await
            .unwrap();
    });
    let endpoint = format!("http://{address}");
    let signing_service = |id: &str, key_reference: &str| {
        json!({
            "id": id,
            "name": id,
            "service_type": "custom-transit-compatible",
            "provider": "openbao",
            "endpoint": endpoint.clone(),
            "mount": "transit",
            "auth_mode": "token",
            "auth_reference": "test-token",
            "key_reference": key_reference,
            "algorithms": ["EdDSA"],
            "key_purposes": ["vc_jwt_issuer"],
            "credential_formats": ["dc+sd-jwt"]
        })
    };
    let registry = RegistryStore::connect(&redis_url).await.unwrap();
    let profiles = ProfileStore::from_connection(registry.connection());
    let documents = DocumentStore::from_connection(registry.connection());
    let app = marty_signing_keys::http::router_with_dependencies(
        "internal-test-key".into(),
        Some(registry.clone()),
        Some(documents.clone()),
        None,
        Some(profiles.clone()),
        None,
        Some("issuer.example".into()),
    );
    let services = vec![
        signing_service("provider-a", "issuer-a"),
        signing_service("provider-b", "issuer-b"),
    ];
    registry
        .save(
            &organization_id,
            &json!({"services": services, "default_service_id": "provider-a"}),
        )
        .await
        .unwrap();
    let identity_request = json!({
        "organization_id": organization_id,
        "issuer_did": issuer_did,
        "key_purpose": "vc_jwt_issuer",
        "credential_format": "SD_JWT_VC",
        "algorithm": "EdDSA"
    });
    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/signing-keys/issuer-identities?organization_id={organization_id}"
                ))
                .header("content-type", "application/json")
                .body(Body::from(identity_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let created: Value =
        serde_json::from_slice(&to_bytes(created.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(created["created"], true);
    assert!(created["identity"].get("signing_service_id").is_none());
    let stored = profiles
        .find(
            &organization_id,
            FindProfilesRequest {
                issuer_did: Some(issuer_did.clone()),
                ..FindProfilesRequest::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    let profile_id = stored[0]["id"].as_str().unwrap().to_string();
    assert_eq!(stored[0]["signing_service_id"], "provider-a");

    registry
        .save(
            &organization_id,
            &json!({"services": services, "default_service_id": "provider-b"}),
        )
        .await
        .unwrap();
    let rebound = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/v1/signing-keys/issuer-identities?organization_id={organization_id}"
                ))
                .header("content-type", "application/json")
                .body(Body::from(identity_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rebound.status(), StatusCode::OK);
    let rebound: Value =
        serde_json::from_slice(&to_bytes(rebound.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(rebound["changed"], true);
    assert_eq!(rebound["identity"]["issuer_did"], issuer_did);
    assert!(rebound["identity"].get("signing_service_id").is_none());
    assert_eq!(
        profiles.get(&organization_id, &profile_id).await.unwrap()["signing_service_id"],
        "provider-b"
    );
    let did = documents
        .load_did(
            &organization_id,
            LoadDidRequest {
                did_id: Some(issuer_did.clone()),
                fallback_did: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        did.document["verificationMethod"].as_array().unwrap().len(),
        2
    );
    assert_eq!(did.document["assertionMethod"].as_array().unwrap().len(), 2);

    let unavailable = signing_service("provider-unavailable", "issuer-missing");
    registry
        .save(
            &organization_id,
            &json!({
                "services": [services[0].clone(), services[1].clone(), unavailable],
                "default_service_id": "provider-unavailable"
            }),
        )
        .await
        .unwrap();
    let unavailable = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/v1/signing-keys/issuer-identities?organization_id={organization_id}"
                ))
                .header("content-type", "application/json")
                .body(Body::from(identity_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        profiles.get(&organization_id, &profile_id).await.unwrap()["signing_service_id"],
        "provider-b",
        "failed publication must not change active custody"
    );

    let mut connection = registry.connection();
    let keys = [
        storage_key(&organization_id),
        marty_signing_keys::registry::storage_key(&organization_id),
        did_storage_key(&organization_id, None),
        did_storage_key(&organization_id, Some(&issuer_did)),
        slug_storage_key(&slug),
    ];
    let _: () = connection.del(&keys).await.unwrap();
}
