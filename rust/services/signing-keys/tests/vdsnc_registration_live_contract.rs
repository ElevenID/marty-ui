//! Opt-in public VDS-NC registration route against disposable Redis.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use marty_signing_keys::{
    http::router_with_dependencies,
    registry::{storage_key, RegistryStore},
};
use redis::AsyncCommands;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

async fn register(app: &Router, organization_id: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/v1/signing-keys/services/vdsnc/register?organization_id={organization_id}"
            ))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
#[ignore = "requires disposable MARTY_TEST_REDIS_URL"]
async fn public_vdsnc_registration_preserves_registry_and_never_returns_provider_secret() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
    let organization_id = format!("rust-vdsnc-{}", Uuid::new_v4().simple());
    let other_organization_id = format!("rust-vdsnc-other-{}", Uuid::new_v4().simple());
    let registry = RegistryStore::connect(&redis_url).await.unwrap();
    registry
        .save(
            &organization_id,
            &json!({
                "services": [{
                    "id": "existing-service", "service_type": "custom-transit-compatible",
                    "key_reference": "existing-key", "algorithms": ["ES256"]
                }],
                "default_service_id": "existing-service"
            }),
        )
        .await
        .unwrap();
    let app = router_with_dependencies(
        "test-internal-key".into(),
        Some(registry.clone()),
        None,
        None,
        None,
        None,
        None,
    );
    let body = json!({
        "organization_id": organization_id,
        "country_code": " usa ",
        "authority_name": "  Test Bureau  ",
        "auth_reference": "provider-secret-never-echo",
        "endpoint": "https://kms.example.invalid",
        "generation": 2,
        "role": " DSC "
    });
    let (status, response) = register(&app, &organization_id, body).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["ok"], true);
    assert_eq!(response["service"]["country_code"], "USA");
    assert_eq!(response["service"]["authority_name"], "Test Bureau");
    assert_eq!(response["service"]["key_reference"], "cred:vdsnc:USA:dsc:2");
    assert_eq!(response["service"]["auth_reference"], "");
    assert_eq!(response["service"]["auth_configured"], true);
    assert_eq!(
        response["service"]["key_purposes"],
        json!(["vdsnc_signing"])
    );
    assert_eq!(
        response["service"]["credential_formats"],
        json!(["mso_mdoc", "vds_nc"])
    );
    assert!(response["service"]["id"]
        .as_str()
        .unwrap()
        .starts_with("svc-vdsnc-usa-"));
    assert!(response["registered_at"].as_str().is_some());
    assert!(!response.to_string().contains("provider-secret-never-echo"));

    let stored = registry.load(&organization_id).await.unwrap();
    assert_eq!(stored["default_service_id"], "existing-service");
    assert_eq!(stored["services"].as_array().unwrap().len(), 2);
    let registered = stored["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["id"] == response["service"]["id"])
        .unwrap();
    assert_eq!(registered["auth_reference"], "provider-secret-never-echo");
    assert_eq!(
        registered["discovered_capabilities"]["vdsnc_namespaced_key_reference"],
        "cred:vdsnc:USA:dsc:2"
    );
    assert_eq!(registered["discovered_capabilities"]["vdsnc_generation"], 2);
    assert!(
        registry.load(&other_organization_id).await.unwrap()["services"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let (status, other) = register(
        &app,
        &other_organization_id,
        json!({
            "country_code": "CAN", "authority_name": "Other Bureau",
            "key_reference": "kms-existing-can-dsc"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{other}");
    assert_eq!(other["service"]["key_reference"], "kms-existing-can-dsc");
    let other_registry = registry.load(&other_organization_id).await.unwrap();
    assert_eq!(other_registry["default_service_id"], other["service"]["id"]);
    assert_eq!(other_registry["services"].as_array().unwrap().len(), 1);

    let before = stored;
    for invalid in [
        json!({"country_code": "U$", "authority_name": "Bureau"}),
        json!({"country_code": "USA", "authority_name": " ", "generation": -1}),
        json!({"country_code": "USA", "authority_name": "Bureau", "private_key": "forged"}),
        json!({"country_code": "USA", "authority_name": "Bureau", "organization_id": other_organization_id}),
    ] {
        let (status, response) = register(&app, &organization_id, invalid).await;
        assert!(status.is_client_error(), "{status}: {response}");
        assert!(!response.to_string().contains("forged"));
    }
    assert_eq!(registry.load(&organization_id).await.unwrap(), before);

    let mut redis = registry.connection();
    for tenant in [&organization_id, &other_organization_id] {
        let _: () = redis.del(storage_key(tenant)).await.unwrap();
    }
}
