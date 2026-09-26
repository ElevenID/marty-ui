//! Opt-in public rotation route against disposable Redis and a mock Transit KMS.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    routing::get,
    Json, Router,
};
use marty_signing_keys::{
    http::router_with_dependencies,
    registry::{storage_key, RegistryError, RegistryStore},
};
use redis::AsyncCommands;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use tokio::sync::oneshot;
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

async fn public_config_request(
    app: &Router,
    organization_id: &str,
    method: &str,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(format!(
            "/v1/signing-keys/config?organization_id={organization_id}"
        ))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
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
    let deny = Arc::new(AtomicBool::new(false));
    let rotation_gate = Arc::new(Mutex::new(
        None::<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
    ));
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
                let deny = Arc::clone(&deny);
                let rotation_gate = Arc::clone(&rotation_gate);
                move || {
                    let rotations = Arc::clone(&rotations);
                    let fail = Arc::clone(&fail);
                    let deny = Arc::clone(&deny);
                    let rotation_gate = Arc::clone(&rotation_gate);
                    async move {
                        rotations.fetch_add(1, Ordering::SeqCst);
                        let gated = { rotation_gate.lock().unwrap().take() };
                        if let Some((entered, release)) = gated {
                            entered.send(()).unwrap();
                            let _ = release.await;
                        }
                        if deny.load(Ordering::SeqCst) {
                            StatusCode::FORBIDDEN
                        } else if fail.load(Ordering::SeqCst) {
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
                }, {
                    "id": "service-b", "name": "Second signing service",
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
    let managed_app = router_with_dependencies(
        "test-internal-key".into(),
        Some(store.clone().with_managed_openbao(Some(endpoint.clone()))),
        None,
        None,
        None,
        None,
        None,
    );
    let (status, denied) = rotate(
        &managed_app,
        &organization_id,
        "managed-openbao-transit",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
    assert_eq!(rotations.load(Ordering::SeqCst), 0);
    let app = router_with_dependencies(
        "test-internal-key".into(),
        Some(store.clone()),
        None,
        None,
        None,
        None,
        None,
    );
    let competing_app = router_with_dependencies(
        "test-internal-key".into(),
        Some(RegistryStore::connect(&redis_url).await.unwrap()),
        None,
        None,
        None,
        None,
        None,
    );
    let (status, mut stale_config) =
        public_config_request(&app, &organization_id, "GET", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    stale_config["services"][0]["name"] = json!("Renamed during rotation");
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

    let (entered, entered_rx) = oneshot::channel();
    let (release_tx, release) = oneshot::channel();
    *rotation_gate.lock().unwrap() = Some((entered, release));
    let first_app = app.clone();
    let first_organization = organization_id.clone();
    let first = tokio::spawn(async move {
        rotate(
            &first_app,
            &first_organization,
            "service-a",
            json!({"overlap_days": 14, "publish_updates": false}),
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered_rx)
        .await
        .unwrap()
        .unwrap();
    let (busy_status, busy) =
        rotate(&competing_app, &organization_id, "service-a", json!({})).await;
    assert_eq!(busy_status, StatusCode::CONFLICT, "{busy}");
    let (other_service_status, other_service_busy) =
        rotate(&competing_app, &organization_id, "service-b", json!({})).await;
    assert_eq!(
        other_service_status,
        StatusCode::CONFLICT,
        "{other_service_busy}"
    );
    let (config_busy_status, _) = public_config_request(
        &competing_app,
        &organization_id,
        "PATCH",
        stale_config.clone(),
    )
    .await;
    assert_eq!(config_busy_status, StatusCode::CONFLICT);
    assert_eq!(rotations.load(Ordering::SeqCst), 1);
    release_tx.send(()).unwrap();
    let (status, completed) = first.await.unwrap();
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
    let (config_status, _) =
        public_config_request(&competing_app, &organization_id, "PATCH", stale_config).await;
    assert_eq!(config_status, StatusCode::OK);
    let merged = store.load(&organization_id).await.unwrap();
    assert_eq!(merged["services"][0]["name"], "Renamed during rotation");
    assert_eq!(
        merged["services"][0]["rotation_state"],
        stored["services"][0]["rotation_state"]
    );
    assert_eq!(
        merged["services"][0]["rotation_policy"],
        stored["services"][0]["rotation_policy"]
    );

    let (entered, entered_rx) = oneshot::channel();
    let (release_tx, release) = oneshot::channel();
    *rotation_gate.lock().unwrap() = Some((entered, release));
    let cancelled_app = app.clone();
    let cancelled_organization = organization_id.clone();
    let cancelled = tokio::spawn(async move {
        rotate(
            &cancelled_app,
            &cancelled_organization,
            "service-a",
            json!({}),
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered_rx)
        .await
        .unwrap()
        .unwrap();
    cancelled.abort();
    let _ = cancelled.await;
    let (busy_status, _) = rotate(&competing_app, &organization_id, "service-a", json!({})).await;
    assert_eq!(busy_status, StatusCode::CONFLICT);
    assert_eq!(rotations.load(Ordering::SeqCst), 2);
    release_tx.send(()).unwrap();
    let mut persisted_after_cancellation = false;
    for _ in 0..100 {
        let current = store.load(&organization_id).await.unwrap();
        if current["services"][0]["rotation_state"]["previous_versions"]
            .as_array()
            .is_some_and(|versions| versions.len() == 2)
            && current["services"][0]["rotation_state"]["reconcile_required"].is_null()
        {
            persisted_after_cancellation = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        persisted_after_cancellation,
        "cancelled waiter lost KMS rotation state"
    );
    let mut released_after_cancellation = false;
    for _ in 0..50 {
        if let Some(lease) = store
            .acquire_rotation_lease(&organization_id)
            .await
            .unwrap()
        {
            lease.release().await.unwrap();
            released_after_cancellation = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(released_after_cancellation);

    deny.store(true, Ordering::SeqCst);
    let before_denial = store.load(&organization_id).await.unwrap();
    let (status, denied) = rotate(&app, &organization_id, "service-a", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{denied}");
    assert_eq!(denied["ok"], false);
    let after_denial = store.load(&organization_id).await.unwrap();
    assert_eq!(
        after_denial["services"][0]["rotation_state"],
        before_denial["services"][0]["rotation_state"]
    );
    deny.store(false, Ordering::SeqCst);

    fail.store(true, Ordering::SeqCst);
    let (status, uncertain) = rotate(&app, &organization_id, "service-a", json!({})).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{uncertain}");
    let needs_reconcile = store.load(&organization_id).await.unwrap();
    assert!(needs_reconcile["services"][0]["rotation_state"]["reconcile_required"].is_object());
    let rotations_before_block = rotations.load(Ordering::SeqCst);
    assert_eq!(
        rotate(&app, &organization_id, "service-a", json!({}))
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(rotations.load(Ordering::SeqCst), rotations_before_block);

    let (status, mut rebound_config) =
        public_config_request(&app, &organization_id, "GET", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    rebound_config["services"][0]["key_reference"] = json!("replacement-key");
    let (status, _) = public_config_request(&app, &organization_id, "PATCH", rebound_config).await;
    assert_eq!(status, StatusCode::OK);
    let rebound = store.load(&organization_id).await.unwrap();
    assert_eq!(rebound["services"][0]["rotation_state"], json!({}));
    let (status, mut missing_token_config) =
        public_config_request(&app, &organization_id, "GET", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    missing_token_config["services"][0]["auth_reference"] = Value::Null;
    assert_eq!(
        public_config_request(&app, &organization_id, "PATCH", missing_token_config)
            .await
            .0,
        StatusCode::OK
    );
    let rotations_before_invalid = rotations.load(Ordering::SeqCst);
    let (status, invalid) = rotate(&app, &organization_id, "service-a", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{invalid}");
    assert_eq!(invalid["ok"], false);
    assert_eq!(rotations.load(Ordering::SeqCst), rotations_before_invalid);
    assert_eq!(
        store.load(&organization_id).await.unwrap()["services"][0]["rotation_state"],
        json!({})
    );

    let old_lease = store
        .acquire_rotation_lease(&organization_id)
        .await
        .unwrap()
        .unwrap();
    let lease_key = format!(
        "signing-service:rotation-lease:{}:{}",
        organization_id.len(),
        organization_id
    );
    let mut connection = store.connection();
    let ttl: i64 = redis::cmd("PTTL")
        .arg(&lease_key)
        .query_async(&mut connection)
        .await
        .unwrap();
    assert!((1..=120_000).contains(&ttl));
    let _: () = redis::cmd("SET")
        .arg(&lease_key)
        .arg("replacement-owner")
        .arg("PX")
        .arg(5_000)
        .query_async(&mut connection)
        .await
        .unwrap();
    assert!(matches!(
        store
            .save_with_rotation_lease(&organization_id, &needs_reconcile, &old_lease)
            .await,
        Err(RegistryError::Conflict)
    ));
    old_lease.release().await.unwrap();
    let owner: String = connection.get(&lease_key).await.unwrap();
    assert_eq!(owner, "replacement-owner");
    let _: () = connection.del(&lease_key).await.unwrap();
    let _: () = connection.del(storage_key(&organization_id)).await.unwrap();
    server.abort();
}
