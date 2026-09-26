//! Opt-in public-route contract against disposable Redis and OpenBao.
//! Transit creates and retains the private signing key; this test sees only a signature.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use marty_signing_keys::{
    documents::DocumentStore,
    profiles::{storage_key as profile_storage_key, ProfileStore},
    registry::{storage_key, RegistryStore},
};
use redis::AsyncCommands;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

async fn sign(app: &Router, organization_id: &str, payload: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/v1/signing-keys/services/service-a/sign?organization_id={organization_id}"
            ))
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!(
            "sign route returned non-JSON status={status} parse={error} body={}",
            String::from_utf8_lossy(&bytes)
        )
    });
    (status, body)
}

#[tokio::test]
#[ignore = "requires disposable MARTY_TEST_REDIS_URL, MARTY_TEST_OPENBAO_URL, and MARTY_TEST_OPENBAO_TOKEN"]
async fn public_service_sign_uses_registered_kms_key_and_rejects_unbound_selection() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
    let bao_url = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
    let bao_token = std::env::var("MARTY_TEST_OPENBAO_TOKEN").expect("disposable OpenBao token");
    let suffix = Uuid::new_v4().simple().to_string();
    let key_name = format!("marty-public-sign-{suffix}");
    let profile_key_name = format!("marty-public-sign-profile-{suffix}");
    let organization_id = format!("test-public-sign-{suffix}");
    let client = reqwest::Client::new();
    let mount = client
        .get(format!("{bao_url}/v1/sys/mounts/transit"))
        .header("X-Vault-Token", &bao_token)
        .send()
        .await
        .unwrap();
    if !mount.status().is_success() {
        let enabled = client
            .post(format!("{bao_url}/v1/sys/mounts/transit"))
            .header("X-Vault-Token", &bao_token)
            .json(&json!({"type":"transit"}))
            .send()
            .await
            .unwrap();
        assert!(enabled.status().is_success());
    }
    let created = client
        .post(format!("{bao_url}/v1/transit/keys/{key_name}"))
        .header("X-Vault-Token", &bao_token)
        .json(&json!({"type":"ecdsa-p256"}))
        .send()
        .await
        .unwrap();
    assert!(created.status().is_success());
    let profile_key_created = client
        .post(format!("{bao_url}/v1/transit/keys/{profile_key_name}"))
        .header("X-Vault-Token", &bao_token)
        .json(&json!({"type":"ecdsa-p256"}))
        .send()
        .await
        .unwrap();
    assert!(profile_key_created.status().is_success());
    let registry = RegistryStore::connect(&redis_url).await.unwrap();
    registry
        .save(
            &organization_id,
            &json!({
                "services": [{
                    "id": "service-a", "name": "Test KMS signer",
                    "service_type": "openbao-transit", "endpoint": bao_url,
                    "mount": "transit", "auth_mode": "token", "auth_reference": bao_token,
                    "key_reference": key_name, "algorithms": ["ES256"],
                    "key_purposes": ["vc_jwt_issuer"]
                }],
                "default_service_id": "service-a"
            }),
        )
        .await
        .unwrap();
    let documents = DocumentStore::from_connection(registry.connection());
    let profiles = ProfileStore::from_connection(registry.connection());
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/issuer_profile_vectors.json")).unwrap();
    let mut profile = fixture["normalize"]["expected"].clone();
    profile["organization_id"] = json!(organization_id);
    profile["signing_service_id"] = json!("service-a");
    profile["signing_key_reference"] = json!(profile_key_name);
    profiles
        .put(&organization_id, "ip-vector", profile)
        .await
        .unwrap();
    let app = marty_signing_keys::http::router_with_dependencies(
        "test-internal-key".to_string(),
        Some(registry.clone()),
        Some(documents),
        None,
        Some(profiles.clone()),
        None,
        None,
    );
    let request = json!({
        "payload_b64": "cGF5bG9hZA",
        "algorithm": "ES256",
        "key_purpose": "vc_jwt_issuer",
    });
    let (status, signed) = sign(&app, &organization_id, request.clone()).await;
    assert_eq!(status, StatusCode::OK, "{signed}");
    assert_eq!(signed["ok"], true);
    assert_eq!(signed["service_id"], "service-a");
    assert_eq!(signed["algorithm"], "ES256");
    assert_eq!(signed["payload_length"], 7);
    assert!(!signed["signature_b64"].as_str().unwrap().is_empty());
    assert!(!signed["signature_hex"].as_str().unwrap().is_empty());
    assert!(!signed.to_string().contains(&bao_token));
    assert!(!signed.to_string().contains(&key_name));

    let mut legacy_profile_selection = request.clone();
    legacy_profile_selection["key_reference"] = json!(profile_key_name);
    let (status, profile_signed) = sign(&app, &organization_id, legacy_profile_selection).await;
    assert_eq!(status, StatusCode::OK, "{profile_signed}");
    assert!(!profile_signed["signature_b64"].as_str().unwrap().is_empty());

    let mut unbound = request.clone();
    unbound["key_reference"] = json!("other-tenant-key");
    assert_eq!(
        sign(&app, &organization_id, unbound).await.0,
        StatusCode::CONFLICT
    );
    let mut mismatch = request.clone();
    mismatch["organization_id"] = json!("other-tenant");
    assert_eq!(
        sign(&app, &organization_id, mismatch).await.0,
        StatusCode::FORBIDDEN
    );
    let mut private = request.clone();
    private["private_key"] = json!("not-allowed");
    assert_eq!(
        sign(&app, &organization_id, private).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        sign(&app, &organization_id, json!({})).await.0,
        StatusCode::BAD_REQUEST
    );
    let missing = app
        .oneshot(
            Request::post(format!(
                "/v1/signing-keys/services/missing/sign?organization_id={organization_id}"
            ))
            .header("content-type", "application/json")
            .body(Body::from(request.to_string()))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    let mut connection = registry.connection();
    let _: () = connection.del(storage_key(&organization_id)).await.unwrap();
    let _: () = connection
        .del(profile_storage_key(&organization_id))
        .await
        .unwrap();
}
