//! Opt-in public rotation route against disposable Redis and a mock Transit KMS.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    routing::get,
    Json, Router,
};
use marty_signing_keys::{
    http::router_with_dependencies,
    registry::{storage_key, RegistryStore},
};
use redis::AsyncCommands;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use tower::ServiceExt;

async fn rotate(
    app: &Router,
    organization_id: &str,
    service_id: &str,
    body: Value,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/v1/signing-keys/services/{service_id}/rotate?organization_id={organization_id}"
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
async fn public_rotation_updates_state_only_after_kms_success() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
    let rotations = Arc::new(AtomicUsize::new(0));
    let fail = Arc::new(AtomicBool::new(false));
    let kms = Router::new()
        .route(
            "/v1/transit/keys/signing-key",
            get(|| async { Json(json!({"data": {"latest_version": 2}})) }),
        )
        .route(
            "/v1/transit/keys/signing-key/rotate",
            axum::routing::post({
                let rotations = Arc::clone(&rotations);
                let fail = Arc::clone(&fail);
                move || {
                    let rotations = Arc::clone(&rotations);
                    let fail = Arc::clone(&fail);
                    async move {
                        rotations.fetch_add(1, Ordering::SeqCst);
                        if fail.load(Ordering::SeqCst) {
                            StatusCode::SERVICE_UNAVAILABLE
                        } else {
                            StatusCode::NO_CONTENT
                        }
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, kms).await.unwrap() });

    let organization_id = format!("test-rotation-{}", uuid::Uuid::new_v4().simple());
    let store = RegistryStore::connect(&redis_url).await.unwrap();
    store
        .save(
            &organization_id,
            &json!({
                "services": [{
                    "id": "service-a", "name": "Test signing service",
                    "service_type": "openbao-transit", "endpoint": endpoint,
                    "mount": "transit", "auth_mode": "token", "auth_reference": "fixture-token",
                    "key_reference": "signing-key", "algorithms": ["ES256"],
                    "key_purposes": ["vc_jwt_issuer"]
                }],
                "default_service_id": "service-a"
            }),
        )
        .await
        .unwrap();
    let app = router_with_dependencies(
        "test-internal-key".into(),
        Some(store.clone()),
        None,
        None,
        None,
        None,
        None,
    );
    assert_eq!(
        rotate(&app, &organization_id, "missing", json!({})).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        rotate(&app, "another-tenant", "service-a", json!({}))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert!(!rotate(
        &app,
        &organization_id,
        "service-a",
        json!({"key_reference": "attacker"})
    )
    .await
    .0
    .is_success());
    assert_eq!(
        rotate(
            &app,
            &organization_id,
            "service-a",
            json!({"activate_at": "2099-01-01T00:00:00Z"}),
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(rotations.load(Ordering::SeqCst), 0);

    let (status, completed) = rotate(
        &app,
        &organization_id,
        "service-a",
        json!({
            "overlap_days": 14, "publish_updates": false
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{completed}");
    assert_eq!(completed["ok"], true);
    assert_eq!(
        completed["rotation_state"]["provider_rotation"]["version"],
        2
    );
    assert_eq!(completed["rotation_state"]["overlap_days"], 14);
    assert_eq!(
        completed["rotation_state"]["previous_versions"][0]["key_reference"],
        "signing-key"
    );
    assert_eq!(
        completed["publication"],
        json!({"jwks": false, "did": false})
    );
    assert!(!completed.to_string().contains("fixture-token"));
    let stored = store.load(&organization_id).await.unwrap();
    assert_eq!(
        stored["services"][0]["rotation_state"]["last_rotated_at"],
        completed["rotated_at"]
    );

    fail.store(true, Ordering::SeqCst);
    let (status, failed) = rotate(&app, &organization_id, "service-a", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{failed}");
    assert_eq!(failed["ok"], false);
    assert!(failed["rotated_at"].is_null());
    assert_eq!(failed["rotation_state"]["provider_rotation"]["ok"], false);
    assert!(!failed.to_string().contains("fixture-token"));
    let unchanged = store.load(&organization_id).await.unwrap();
    assert_eq!(
        unchanged["services"][0]["rotation_state"],
        stored["services"][0]["rotation_state"]
    );
    assert_eq!(rotations.load(Ordering::SeqCst), 2);

    let mut connection = store.connection();
    let _: () = connection.del(storage_key(&organization_id)).await.unwrap();
    server.abort();
}
