//! Opt-in managed-key creation route against disposable Redis and mock Transit KMS.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use axum::{
    body::{to_bytes, Body},
    extract::{Path, State},
    http::{HeaderMap, Request, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use marty_signing_keys::{
    http::router_with_dependencies,
    registry::{storage_key, RegistryStore},
};
use redis::AsyncCommands;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

const ES256_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt\n6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==\n-----END PUBLIC KEY-----\n";
// Public-only vectors from marty-core/marty-verification/tests/fixtures/public_key_jwk_vectors.json.
const ES384_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEqofKIr6LBTeOscce8yCtdG4dO2KLp5uY\nWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3NhfeSpYmLG9dnpi/kpLcKfj0Hb0omhR8\n6doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5f\n-----END PUBLIC KEY-----\n";
const RS256_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxZrSKXzXy4gpAp6iFW/B\nXWnIOL377WmFDT/H3IpLN7rg9rIS/FKyBtWFUICfDVwfoCMElc3nz+Pedl2Dw2b4\nFLomW89q2op6RVfuXK1QTgVfrvfF/30feNti6iemScKBibXkPLfCLZL0k8DU+PIC\nIHASwNCjmv3OTFIlv4am7/DemiOHqezP8JAK3Yc2n3kWZFeMnFomq3jFzjKABNHX\nN10EwkWLy7PFxhmdoZnRF4chIgIqT+YRyFt5r1f9n9OtW9uoQ0P+lBP3y3sv67Ng\nlAqxySz2siHm2Q87ZLAgMJztoncChb7ea6VRamaPR0qcfGmoeK5HPhPUZRBptMFF\nTwIDAQAB\n-----END PUBLIC KEY-----\n";
const ED25519_PUBLIC_B64: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

type Keys = Arc<Mutex<BTreeMap<String, String>>>;

async fn create_key(
    State(keys): State<Keys>,
    Path(reference): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if headers
        .get("x-vault-token")
        .and_then(|value| value.to_str().ok())
        != Some("test-only")
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"errors": ["test token required"]})),
        );
    }
    if reference.contains("fail") {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"errors": ["mock outage"]})),
        );
    }
    let key_type = body.get("type").and_then(Value::as_str).unwrap_or_default();
    let mut keys = keys.lock().unwrap();
    if keys.contains_key(&reference) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"errors": ["key already exists"]})),
        );
    }
    keys.insert(
        reference.clone(),
        if reference.contains("wrong") {
            "ed25519"
        } else {
            key_type
        }
        .to_owned(),
    );
    (StatusCode::NO_CONTENT, Json(Value::Null))
}

async fn read_key(
    State(keys): State<Keys>,
    Path(reference): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if headers
        .get("x-vault-token")
        .and_then(|value| value.to_str().ok())
        != Some("test-only")
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"errors": ["test token required"]})),
        );
    }
    let key_type = keys.lock().unwrap().get(&reference).cloned();
    let Some(key_type) = key_type else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"errors": ["not found"]})),
        );
    };
    let public_key = match key_type.as_str() {
        "ed25519" => ED25519_PUBLIC_B64,
        "ecdsa-p384" => ES384_PUBLIC_PEM,
        "rsa-2048" => RS256_PUBLIC_PEM,
        _ => ES256_PUBLIC_PEM,
    };
    (
        StatusCode::OK,
        Json(json!({"data": {
            "latest_version": 1,
            "type": key_type,
            "supports_signing": true,
            "soft_deleted": false,
            "keys": {"1": {"name": key_type, "public_key": public_key, "creation_time": "2026-09-26T00:00:00Z"}}
        }})),
    )
}

async fn request(app: &Router, organization_id: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/v1/signing-keys?organization_id={organization_id}"
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
#[ignore = "requires disposable MARTY_TEST_REDIS_URL and BAO_TOKEN=test-only"]
async fn managed_key_creation_stays_in_kms_and_binds_only_after_verified_success() {
    assert_eq!(std::env::var("BAO_TOKEN").as_deref(), Ok("test-only"));
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
    let keys: Keys = Arc::new(Mutex::new(BTreeMap::new()));
    let kms = Router::new()
        .route(
            "/v1/transit/keys/{reference}",
            get(read_key).post(create_key),
        )
        .with_state(Arc::clone(&keys));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, kms).await.unwrap() });
    let registry = RegistryStore::connect(&redis_url)
        .await
        .unwrap()
        .with_managed_openbao(Some(endpoint));
    let organization_id = format!("rust-managed-{}", Uuid::new_v4().simple());
    let other_organization_id = format!("rust-managed-other-{}", Uuid::new_v4().simple());
    let app = router_with_dependencies(
        "test-internal-key".into(),
        Some(registry.clone()),
        None,
        None,
        None,
        None,
        None,
    );
    let defaults_before_create = registry.load(&organization_id).await.unwrap();

    let (status, first) = request(&app, &organization_id, json!({"name": "Shared Name"})).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let reference = first["provider_key_name"].as_str().unwrap();
    assert!(reference.starts_with("cred-issuer-"));
    assert_eq!(first["key"]["algorithm"], "ES256");
    assert_eq!(first["key"]["key_purpose"], "vc_jwt_issuer");
    assert_eq!(first["key"]["public_jwk"]["crv"], "P-256");
    assert_eq!(first["key"]["latest_version"], 1);
    assert!(!first.to_string().contains("test-only"));
    assert!(!first.to_string().contains("private_key"));
    let bound = registry.load(&organization_id).await.unwrap();
    assert_eq!(
        bound["key_reference_purposes"]["managed-openbao-transit"][reference],
        json!(["vc_jwt_issuer"])
    );
    for field in ["default_service_id", "type_defaults", "format_defaults"] {
        assert_eq!(bound[field], defaults_before_create[field]);
    }
    let inventory = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/v1/signing-keys?organization_id={organization_id}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(inventory.status(), StatusCode::OK);
    let inventory: Value =
        serde_json::from_slice(&to_bytes(inventory.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert!(inventory["keys"]
        .as_array()
        .unwrap()
        .iter()
        .any(|key| key["id"] == reference && key["public_jwk"]["crv"] == "P-256"));

    let (status, other) =
        request(&app, &other_organization_id, json!({"name": "Shared Name"})).await;
    assert_eq!(status, StatusCode::OK, "{other}");
    assert_ne!(other["provider_key_name"], first["provider_key_name"]);
    assert!(
        registry.load(&other_organization_id).await.unwrap()["key_reference_purposes"]
            ["managed-openbao-transit"][other["provider_key_name"].as_str().unwrap()]
        .is_array()
    );

    let (status, ed) = request(
        &app,
        &organization_id,
        json!({"name": "Ed Key", "algorithm": "EdDSA"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{ed}");
    assert_eq!(ed["key"]["public_jwk"]["crv"], "Ed25519");
    let (status, p384) = request(
        &app,
        &organization_id,
        json!({"name": "P384 Key", "algorithm": "ES384"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{p384}");
    assert_eq!(p384["key"]["public_jwk"]["crv"], "P-384");
    let (status, rsa) = request(
        &app,
        &organization_id,
        json!({"name": "LTI Key", "algorithm": "RS256", "key_purpose": "lti_tool_signing"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{rsa}");
    assert_eq!(rsa["key"]["public_jwk"]["kty"], "RSA");
    assert!(rsa["provider_key_name"]
        .as_str()
        .unwrap()
        .starts_with("lti-tool-"));
    // Missing legacy bindings must not starve later entries in the bounded KMS reader.
    for index in 0..10 {
        registry
            .bind_key_purpose(
                &organization_id,
                "managed-openbao-transit",
                &format!("a-missing-{index:02}"),
                "vc_jwt_issuer",
            )
            .await
            .unwrap();
    }
    let listed = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/v1/signing-keys?organization_id={organization_id}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let listed: Value =
        serde_json::from_slice(&to_bytes(listed.into_body(), usize::MAX).await.unwrap()).unwrap();
    for (created, algorithm) in [
        (&first, "ES256"),
        (&ed, "EdDSA"),
        (&p384, "ES384"),
        (&rsa, "RS256"),
    ] {
        assert!(listed["keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|key| key["id"] == created["provider_key_name"] && key["algorithm"] == algorithm));
    }
    let key_detail = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/v1/signing-keys/{}?organization_id={organization_id}",
                rsa["provider_key_name"].as_str().unwrap()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(key_detail.status(), StatusCode::OK);
    let key_detail: Value =
        serde_json::from_slice(&to_bytes(key_detail.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(key_detail["algorithm"], "RS256");
    let (status, repeated) = request(&app, &organization_id, json!({"name": "Shared Name"})).await;
    assert_eq!(status, StatusCode::OK, "{repeated}");
    assert_eq!(repeated["provider_key_name"], first["provider_key_name"]);
    let before = registry.load(&organization_id).await.unwrap();
    for (body, expected) in [
        (
            json!({"name": "force-wrong", "algorithm": "ES256"}),
            StatusCode::CONFLICT,
        ),
        (
            json!({"name": "force-fail", "algorithm": "ES256"}),
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            json!({"name": "LTI key", "key_purpose": "lti_tool_signing", "algorithm": "ES256"}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            json!({"name": "private", "private_key": "forged"}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            json!({"name": "wrong org", "organization_id": other_organization_id}),
            StatusCode::FORBIDDEN,
        ),
    ] {
        let (status, response) = request(&app, &organization_id, body).await;
        assert_eq!(status, expected, "{response}");
    }
    assert_eq!(registry.load(&organization_id).await.unwrap(), before);

    let mut redis = registry.connection();
    for tenant in [&organization_id, &other_organization_id] {
        let _: () = redis.del(storage_key(tenant)).await.unwrap();
    }
    server.abort();
}
