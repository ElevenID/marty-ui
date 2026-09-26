//! Opt-in public-route contract against disposable Redis and OpenBao.
//! Transit creates and retains the private signing key; this test sees only a signature.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use marty_signing_keys::{
    documents::DocumentStore,
    profiles::{storage_key as profile_storage_key, ProfileStore},
    registry::{storage_key, RegistryStore},
};
use redis::AsyncCommands;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tower::ServiceExt;
use uuid::Uuid;

async fn sign(app: &Router, organization_id: &str, payload: Value) -> (StatusCode, Value) {
    sign_service(app, organization_id, "service-a", payload).await
}

async fn sign_service(
    app: &Router,
    organization_id: &str,
    service_id: &str,
    payload: Value,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/v1/signing-keys/services/{service_id}/sign?organization_id={organization_id}"
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
#[ignore = "requires disposable MARTY_TEST_REDIS_URL"]
async fn stale_managed_profile_binding_cannot_select_a_kms_key() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
    let calls = Arc::new(AtomicUsize::new(0));
    let kms = Router::new().route(
        "/v1/transit/sign/{reference}",
        post({
            let calls = Arc::clone(&calls);
            move || {
                let calls = Arc::clone(&calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, kms).await.unwrap() });
    let organization_id = format!("test-managed-stale-{}", Uuid::new_v4().simple());
    let stale_reference = "cred-issuer-0123456789abcdefabcd-es256";
    let foreign_namespace = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"other-tenant")
        .simple()
        .to_string();
    let foreign_reference = format!("cred-issuer-{foreign_namespace}-foreign-es256");
    let registry = RegistryStore::connect(&redis_url).await.unwrap();
    registry
        .save(
            &organization_id,
            &json!({
                "services": [],
                "key_reference_purposes": {
                    "managed-openbao-transit": {
                        (stale_reference): ["vc_jwt_issuer", "jwks_signing"],
                        (foreign_reference.clone()): ["vc_jwt_issuer"]
                    }
                }
            }),
        )
        .await
        .unwrap();
    let managed = registry.clone().with_managed_openbao(Some(endpoint));
    let profiles = ProfileStore::from_connection(registry.connection());
    let app = marty_signing_keys::http::router_with_dependencies(
        "test-internal-key".to_string(),
        Some(managed),
        Some(DocumentStore::from_connection(registry.connection())),
        None,
        Some(profiles.clone()),
        None,
        None,
    );
    let (status, body) = sign_service(
        &app,
        &organization_id,
        "managed-openbao-transit",
        json!({
            "payload_b64": "cGF5bG9hZA",
            "algorithm": "ES256",
            "key_purpose": "vc_jwt_issuer",
            "key_reference": stale_reference
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (status, foreign) = sign_service(
        &app,
        &organization_id,
        "managed-openbao-transit",
        json!({
            "payload_b64": "cGF5bG9hZA",
            "algorithm": "ES256",
            "key_purpose": "vc_jwt_issuer",
            "key_reference": foreign_reference
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{foreign}");
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/issuer_profile_vectors.json")).unwrap();
    let mut profile = fixture["normalize"]["expected"].clone();
    profile["organization_id"] = json!(organization_id);
    profile["signing_service_id"] = json!("managed-openbao-transit");
    profile["signing_key_reference"] = json!(stale_reference);
    profile["key_purpose"] = json!("vc_jwt_issuer");
    profile["algorithm"] = json!("ES256");
    profile["status"] = json!("active");
    profiles
        .put(&organization_id, "ip-vector", profile)
        .await
        .unwrap();
    let (status, mismatched) = sign_service(
        &app,
        &organization_id,
        "managed-openbao-transit",
        json!({
            "payload_b64": "cGF5bG9hZA",
            "algorithm": "ES256",
            "key_purpose": "jwks_signing",
            "key_reference": stale_reference
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{mismatched}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let mut connection = registry.connection();
    let _: () = connection.del(storage_key(&organization_id)).await.unwrap();
    let _: () = connection
        .del(profile_storage_key(&organization_id))
        .await
        .unwrap();
    server.abort();
}

#[tokio::test]
#[ignore = "requires disposable MARTY_TEST_REDIS_URL"]
async fn public_config_cannot_replace_managed_kms_purpose_bindings() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
    let organization_id = format!("test-managed-config-{}", Uuid::new_v4().simple());
    let registry = RegistryStore::connect(&redis_url).await.unwrap();
    registry
        .save(
            &organization_id,
            &json!({
                "services": [],
                "key_reference_purposes": {
                    "managed-openbao-transit": {"approved-key": ["vc_jwt_issuer"]}
                }
            }),
        )
        .await
        .unwrap();
    let app = marty_signing_keys::http::router_with_dependencies(
        "test-internal-key".to_string(),
        Some(registry.clone()),
        None,
        None,
        None,
        None,
        None,
    );
    for body in [
        json!({
            "services": [],
            "key_reference_purposes": {
                "managed-openbao-transit": {"foreign-key": ["vc_jwt_issuer"]}
            }
        }),
        json!({}),
        json!({"hsm_enabled": false}),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::patch(format!(
                    "/v1/signing-keys/config?organization_id={organization_id}"
                ))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let stored = registry.load(&organization_id).await.unwrap();
        let managed = &stored["key_reference_purposes"]["managed-openbao-transit"];
        assert_eq!(managed["approved-key"], json!(["vc_jwt_issuer"]));
        assert!(managed.get("foreign-key").is_none());
    }
    for body in [json!([]), Value::Null, json!("invalid"), json!(1)] {
        let response = app
            .clone()
            .oneshot(
                Request::patch(format!(
                    "/v1/signing-keys/config?organization_id={organization_id}"
                ))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let stored = registry.load(&organization_id).await.unwrap();
        assert_eq!(
            stored["key_reference_purposes"]["managed-openbao-transit"]["approved-key"],
            json!(["vc_jwt_issuer"])
        );
    }
    let mut connection = registry.connection();
    let _: () = connection.del(storage_key(&organization_id)).await.unwrap();
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
