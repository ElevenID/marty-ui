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

#[path = "support/disposable_backends.rs"]
mod disposable_backends;

const EXTERNAL_KMS_ENDPOINT: &str = "https://kms.example.invalid";

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
#[ignore = "requires disposable Redis and OpenBao credential envelope"]
async fn public_vdsnc_registration_preserves_registry_and_never_returns_provider_secret() {
    let redis_url = disposable_backends::disposable_redis_url().await;
    let envelope = disposable_backends::disposable_openbao_envelope().await;
    let organization_id = format!("rust-vdsnc-{}", Uuid::new_v4().simple());
    let other_organization_id = format!("rust-vdsnc-other-{}", Uuid::new_v4().simple());
    let registry = RegistryStore::connect(&redis_url)
        .await
        .unwrap()
        .with_auth_envelopes(Some(envelope));
    registry
        .save(
            &organization_id,
            &json!({
                "services": [{
                    "id": "existing-service", "service_type": "custom-transit-compatible",
                    "key_reference": "existing-key", "algorithms": ["ES256"],
                    "endpoint": EXTERNAL_KMS_ENDPOINT,
                    "auth_reference": "existing-fixture-token"
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
        "endpoint": EXTERNAL_KMS_ENDPOINT,
        "generation": 2,
        "role": " DSC "
    });
    let (status, response) = register(&app, &organization_id, body).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let tenant = Uuid::new_v5(&Uuid::NAMESPACE_URL, organization_id.as_bytes()).simple();
    assert_eq!(response["ok"], true);
    assert_eq!(response["service"]["country_code"], "USA");
    assert_eq!(response["service"]["authority_name"], "Test Bureau");
    assert_eq!(
        response["service"]["key_reference"],
        format!("cred:vdsnc:{tenant}:USA:dsc:2")
    );
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
    let raw: String = registry
        .connection()
        .get(storage_key(&organization_id))
        .await
        .unwrap();
    assert!(!raw.contains("provider-secret-never-echo"));
    assert!(!raw.contains("existing-fixture-token"));
    assert!(raw.contains("auth_reference_envelope"));
    assert_eq!(
        registered["discovered_capabilities"]["vdsnc_namespaced_key_reference"],
        format!("cred:vdsnc:{tenant}:USA:dsc:2")
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
            "key_reference": "kms-existing-can-dsc", "endpoint": EXTERNAL_KMS_ENDPOINT,
            "auth_reference": "other-fixture-token"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{other}");
    assert_eq!(other["service"]["key_reference"], "kms-existing-can-dsc");
    let other_registry = registry.load(&other_organization_id).await.unwrap();
    assert_eq!(other_registry["default_service_id"], other["service"]["id"]);
    assert_eq!(other_registry["services"].as_array().unwrap().len(), 1);
    let other_raw: String = registry
        .connection()
        .get(storage_key(&other_organization_id))
        .await
        .unwrap();
    assert!(!other_raw.contains("other-fixture-token"));
    assert!(other_raw.contains("auth_reference_envelope"));

    let (status, other_generated) = register(
        &app,
        &other_organization_id,
        json!({"country_code": "USA", "authority_name": "Test Bureau", "generation": 2,
            "endpoint": EXTERNAL_KMS_ENDPOINT, "auth_reference": "other-fixture-token"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{other_generated}");
    assert_ne!(
        other_generated["service"]["key_reference"],
        response["service"]["key_reference"]
    );

    let before = stored;
    for invalid in [
        json!({"country_code": "U$", "authority_name": "Bureau"}),
        json!({"country_code": "USA", "authority_name": "Bureau"}),
        json!({"country_code": "USA", "authority_name": " ", "generation": -1}),
        json!({"country_code": "USA", "authority_name": "Bureau", "private_key": "forged"}),
        json!({"country_code": "USA", "authority_name": "Bureau", "organization_id": other_organization_id}),
        json!({"country_code": "USA", "authority_name": "Bureau", "service_type": "openbao-transit", "auth_mode": "service_token", "key_reference": "foreign-key"}),
        json!({"country_code": "USA", "authority_name": "Bureau", "service_type": "openbao-transit", "auth_mode": "invalid-mode", "key_reference": "foreign-key"}),
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

#[tokio::test]
#[ignore = "requires disposable Redis and OpenBao credential envelope"]
async fn concurrent_vdsnc_registration_retains_both_services() {
    let redis_url = disposable_backends::disposable_redis_url().await;
    let envelope = disposable_backends::disposable_openbao_envelope().await;
    let organization_id = format!("rust-vdsnc-race-{}", Uuid::new_v4().simple());
    let registry = RegistryStore::connect(&redis_url)
        .await
        .unwrap()
        .with_auth_envelopes(Some(envelope));
    let app = router_with_dependencies(
        "test-internal-key".into(),
        Some(registry.clone()),
        None,
        None,
        None,
        None,
        None,
    );
    let first = json!({"country_code": "USA", "authority_name": "First Bureau",
        "endpoint": EXTERNAL_KMS_ENDPOINT, "auth_reference": "first-fixture-token"});
    let second = json!({"country_code": "CAN", "authority_name": "Second Bureau",
        "endpoint": EXTERNAL_KMS_ENDPOINT, "auth_reference": "second-fixture-token"});
    let (mut first_result, mut second_result) = tokio::join!(
        register(&app, &organization_id, first.clone()),
        register(&app, &organization_id, second.clone())
    );
    for _ in 0..20 {
        if first_result.0 == StatusCode::CONFLICT {
            first_result = register(&app, &organization_id, first.clone()).await;
        }
        if second_result.0 == StatusCode::CONFLICT {
            second_result = register(&app, &organization_id, second.clone()).await;
        }
        if first_result.0 == StatusCode::OK && second_result.0 == StatusCode::OK {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(first_result.0, StatusCode::OK, "{}", first_result.1);
    assert_eq!(second_result.0, StatusCode::OK, "{}", second_result.1);
    let stored = registry.load(&organization_id).await.unwrap();
    let services = stored["services"].as_array().unwrap();
    assert_eq!(services.len(), 2);
    for id in [
        &first_result.1["service"]["id"],
        &second_result.1["service"]["id"],
    ] {
        assert!(services.iter().any(|service| &service["id"] == id));
    }
    let mut redis = registry.connection();
    let _: () = redis.del(storage_key(&organization_id)).await.unwrap();
}
