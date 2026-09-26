//! Opt-in public key-detail and JWKS-only metadata lifecycle against disposable Redis.

use axum::{
    body::{to_bytes, Body},
    http::{Method, Request, StatusCode},
    Router,
};
use marty_signing_keys::{
    documents::{jwks_storage_key, DocumentStore},
    http::router_with_dependencies,
    registry::{storage_key, RegistryStore},
};
use redis::AsyncCommands;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

async fn request(
    app: &Router,
    method: Method,
    organization_id: &str,
    key_id: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(format!(
        "/v1/signing-keys/{key_id}?organization_id={organization_id}"
    ));
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let response = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(
                    body.map_or_else(String::new, |body| body.to_string()),
                ))
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
async fn public_key_detail_and_jwks_metadata_do_not_mutate_kms_registration() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
    let organization_id = format!("rust-key-meta-{}", Uuid::new_v4().simple());
    let other_organization_id = format!("rust-key-meta-other-{}", Uuid::new_v4().simple());
    let registry = RegistryStore::connect(&redis_url).await.unwrap();
    registry
        .save(
            &organization_id,
            &json!({
                "services": [{
                    "id": "service-a", "service_type": "custom-transit-compatible",
                    "provider": "custom", "key_reference": "kms-held-key",
                    "algorithms": ["ES256"]
                }],
                "default_service_id": "service-a"
            }),
        )
        .await
        .unwrap();
    let original_registry = registry.load(&organization_id).await.unwrap();
    let documents = DocumentStore::from_connection(registry.connection());
    let mut redis = registry.connection();
    let _: () = redis
        .set(
            jwks_storage_key(&organization_id),
            json!({"keys": [{
                "kid": "public-id", "provider_key_name": "kms-held-key",
                "kty": "EC", "crv": "P-256", "x": "public-x", "y": "public-y",
                "name": "Old name", "status": "active"
            }]})
            .to_string(),
        )
        .await
        .unwrap();
    let app = router_with_dependencies(
        "test-internal-key".into(),
        Some(registry.clone()),
        Some(documents.clone()),
        None,
        None,
        None,
        None,
    );

    let (status, key) = request(&app, Method::GET, &organization_id, "kms-held-key", None).await;
    assert_eq!(status, StatusCode::OK, "{key}");
    assert_eq!(key["id"], "kms-held-key");
    assert_eq!(key["service_id"], "service-a");
    assert!(key.get("d").is_none());
    assert!(key.get("auth_reference").is_none());
    let (status, _) = request(
        &app,
        Method::GET,
        &other_organization_id,
        "kms-held-key",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, updated) = request(
        &app,
        Method::PATCH,
        &organization_id,
        "kms-held-key",
        Some(json!({"name": "New name", "aliases": ["dsc-current"]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["ok"], true);
    assert_eq!(updated["key_id"], "kms-held-key");
    assert_eq!(updated["updated"], json!(["aliases", "name"]));
    assert_eq!(
        documents.jwks(&organization_id).await.unwrap()["keys"][0]["name"],
        "New name"
    );
    for invalid in [
        json!({"d": "private-scalar"}),
        json!({"provider_key_name": "attacker-selected"}),
        json!({"aliases": ["valid", {"d": "private"}]}),
    ] {
        let (status, response) = request(
            &app,
            Method::PATCH,
            &organization_id,
            "kms-held-key",
            Some(invalid),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{response}");
        assert!(!response.to_string().contains("private-scalar"));
    }
    let (status, _) = request(
        &app,
        Method::PATCH,
        &other_organization_id,
        "kms-held-key",
        Some(json!({"name": "wrong tenant"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, deleted) =
        request(&app, Method::DELETE, &organization_id, "public-id", None).await;
    assert_eq!(status, StatusCode::OK, "{deleted}");
    assert_eq!(
        deleted,
        json!({"ok": true, "key_id": "public-id", "removed": true})
    );
    assert!(documents.jwks(&organization_id).await.unwrap()["keys"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        registry.load(&organization_id).await.unwrap(),
        original_registry
    );
    let (status, still_registered) =
        request(&app, Method::GET, &organization_id, "kms-held-key", None).await;
    assert_eq!(status, StatusCode::OK, "{still_registered}");
    let (status, _) = request(&app, Method::DELETE, &organization_id, "public-id", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    for tenant in [&organization_id, &other_organization_id] {
        let _: () = redis.del(storage_key(tenant)).await.unwrap();
        let _: () = redis.del(jwks_storage_key(tenant)).await.unwrap();
    }
}
