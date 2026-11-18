use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use marty_signing_keys::{
    documents::{holder_keys_storage_key, DocumentStore},
    registry::RegistryStore,
};
use redis::AsyncCommands;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires MARTY_TEST_REDIS_URL"]
async fn holder_key_routes_preserve_tenant_storage_and_public_only_responses() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("test Redis URL");
    let organization_id = format!("rust-holder-{}", Uuid::new_v4().simple());
    let other_organization_id = format!("rust-holder-other-{}", Uuid::new_v4().simple());
    let registry = RegistryStore::connect(&redis_url).await.unwrap();
    let documents = DocumentStore::from_connection(registry.connection());
    let app = marty_signing_keys::http::router_with_dependencies(
        "test-internal-key".to_string(),
        Some(registry.clone()),
        Some(documents),
        None,
        None,
        None,
        None,
    );
    let path = format!("/v1/signing-keys/holder-keys?organization_id={organization_id}");
    let body = json!({
        "device_id": "device-a",
        "credential_id": "credential-a",
        "public_jwk": {"kty": "OKP", "crv": "Ed25519", "x": "public"}
    });
    let registered = app
        .clone()
        .oneshot(
            Request::post(&path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(registered.status(), StatusCode::OK);
    let registered: Value =
        serde_json::from_slice(&to_bytes(registered.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(
        registered["record_id"],
        "holder:device-a:credential-a:holder_binding"
    );

    let listed = app
        .clone()
        .oneshot(
            Request::get(format!("{path}&device_id=device-a"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let listed: Value =
        serde_json::from_slice(&to_bytes(listed.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(listed["keys"].as_array().unwrap().len(), 1);
    assert_eq!(listed["keys"][0]["public_jwk"], body["public_jwk"]);

    let other = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/v1/signing-keys/holder-keys?organization_id={other_organization_id}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    let other: Value =
        serde_json::from_slice(&to_bytes(other.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert!(other["keys"].as_array().unwrap().is_empty());

    let mut forbidden = body;
    forbidden["public_jwk"]["d"] = json!("private-key-material");
    let rejected = app
        .clone()
        .oneshot(
            Request::post(&path)
                .header("content-type", "application/json")
                .body(Body::from(forbidden.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let key = holder_keys_storage_key(&organization_id);
    let mut connection = registry.connection();
    let stored: String = connection.get(&key).await.unwrap();
    assert!(!stored.contains("private-key-material"));
    let _: () = connection.del(&key).await.unwrap();
}
