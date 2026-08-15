use axum::body::{to_bytes, Body};
use http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

async fn get_json(path: &str) -> Value {
    let response = marty_signing_keys::http::router()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{path}");
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
}

#[tokio::test]
async fn public_catalog_matches_language_neutral_contract() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/catalog.json")).unwrap();
    assert_eq!(
        get_json("/v1/signing-keys/config/purposes").await,
        fixture["purposes"]
    );
    assert_eq!(
        get_json("/v1/signing-keys/config/service-capabilities").await,
        fixture["service_capabilities"]
    );
}

#[tokio::test]
async fn health_and_extraction_status_preserve_the_service_contract() {
    assert_eq!(
        get_json("/health").await,
        serde_json::json!({"status": "healthy", "service": "signing-keys-service"})
    );
    let status = get_json("/v1/signing-keys/service-status").await;
    assert_eq!(status["phase"], "provider-integration");
    assert_eq!(status["service_name"], "signing-keys-service");
    assert!(status["migrated_capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .any(|capability| capability == "kms-adapter-integration"));
}

#[tokio::test]
async fn internal_kms_routes_require_the_service_api_key() {
    let body = serde_json::json!({
        "service_config": {"service_type": "unknown"}
    })
    .to_string();
    let unauthorized = marty_signing_keys::http::router()
        .oneshot(
            Request::post("/internal/kms/verify")
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let authorized = marty_signing_keys::http::router()
        .oneshot(
            Request::post("/internal/kms/verify")
                .header("content-type", "application/json")
                .header("x-api-key", "dev-signing-keys-internal-api-key")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::BAD_REQUEST);
}
