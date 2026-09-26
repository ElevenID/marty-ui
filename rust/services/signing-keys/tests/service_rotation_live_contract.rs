//! Opt-in public rotation route against disposable Redis and a mock Transit KMS.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    routing::get,
    Json, Router,
};
use marty_signing_keys::{
    documents::{did_storage_key, DocumentStore, PublishDidRequest, PublishJwkRequest},
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

async fn reconcile(
    app: &Router,
    organization_id: &str,
    service_id: &str,
    operation_id: &str,
    authorized: bool,
) -> (StatusCode, Value) {
    let mut request = Request::post(format!(
        "/internal/registry/{organization_id}/services/{service_id}/rotation-reconcile"
    ))
    .header("content-type", "application/json");
    if authorized {
        request = request.header("x-api-key", "test-internal-key");
    }
    let response = app
        .clone()
        .oneshot(
            request
                .body(Body::from(
                    json!({"operation_id": operation_id}).to_string(),
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
async fn public_rotation_updates_state_only_after_kms_success() {
    const PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt\n6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==\n-----END PUBLIC KEY-----\n";
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
    let rotations = Arc::new(AtomicUsize::new(0));
    let latest_version = Arc::new(AtomicUsize::new(2));
    let fail = Arc::new(AtomicBool::new(false));
    let deny = Arc::new(AtomicBool::new(false));
    let rotation_gate = Arc::new(Mutex::new(
        None::<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
    ));
    let public_key_gate = Arc::new(Mutex::new(
        None::<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
    ));
    let kms = Router::new()
        .route(
            "/v1/transit/keys/signing-key",
            get({
                let latest_version = Arc::clone(&latest_version);
                let public_key_gate = Arc::clone(&public_key_gate);
                move || {
                    let latest_version = Arc::clone(&latest_version);
                    let public_key_gate = Arc::clone(&public_key_gate);
                    async move {
                        let gated = { public_key_gate.lock().unwrap().take() };
                        if let Some((entered, release)) = gated {
                            entered.send(()).unwrap();
                            let _ = release.await;
                        }
                        let version = latest_version.load(Ordering::SeqCst);
                        Json(json!({"data": {
                            "latest_version": version, "type": "ecdsa-p256",
                            "keys": {
                                "2": {"public_key": PUBLIC_KEY_PEM},
                                "3": {"public_key": PUBLIC_KEY_PEM},
                                "4": {"public_key": PUBLIC_KEY_PEM},
                                "5": {"public_key": PUBLIC_KEY_PEM},
                                "6": {"public_key": PUBLIC_KEY_PEM}
                            }
                        }}))
                    }
                }
            }),
        )
        .route(
            "/v1/transit/keys/signing-key/rotate",
            axum::routing::post({
                let rotations = Arc::clone(&rotations);
                let fail = Arc::clone(&fail);
                let deny = Arc::clone(&deny);
                let latest_version = Arc::clone(&latest_version);
                let rotation_gate = Arc::clone(&rotation_gate);
                move || {
                    let rotations = Arc::clone(&rotations);
                    let fail = Arc::clone(&fail);
                    let deny = Arc::clone(&deny);
                    let latest_version = Arc::clone(&latest_version);
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
                            latest_version.fetch_add(1, Ordering::SeqCst);
                            StatusCode::SERVICE_UNAVAILABLE
                        } else {
                            latest_version.fetch_add(1, Ordering::SeqCst);
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
    let publication_documents = DocumentStore::from_connection(store.connection());
    let publication_app = router_with_dependencies(
        "test-internal-key".into(),
        Some(store.clone()),
        Some(publication_documents.clone()),
        None,
        None,
        None,
        Some("example.test".into()),
    );
    let (entered, entered_rx) = oneshot::channel();
    let (release_tx, release) = oneshot::channel();
    *public_key_gate.lock().unwrap() = Some((entered, release));
    let publishing_app = publication_app.clone();
    let publishing_organization = organization_id.clone();
    let publishing = tokio::spawn(async move {
        publishing_app
            .oneshot(
                Request::post(format!(
                    "/v1/signing-keys/services/service-a/publish-jwks?organization_id={publishing_organization}"
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap()
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered_rx)
        .await
        .unwrap()
        .unwrap();
    let rotations_before_publication = rotations.load(Ordering::SeqCst);
    assert_eq!(
        rotate(&competing_app, &organization_id, "service-a", json!({}))
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        rotations.load(Ordering::SeqCst),
        rotations_before_publication
    );
    release_tx.send(()).unwrap();
    let published = publishing.await.unwrap();
    assert_eq!(published.status(), StatusCode::OK);
    assert_eq!(
        publication_documents.jwks(&organization_id).await.unwrap()["keys"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let (entered, entered_rx) = oneshot::channel();
    let (release_tx, release) = oneshot::channel();
    *public_key_gate.lock().unwrap() = Some((entered, release));
    let did_app = publication_app.clone();
    let did_organization = organization_id.clone();
    let did_publication = tokio::spawn(async move {
        did_app
            .oneshot(
                Request::post(format!(
                    "/v1/signing-keys/services/service-a/publish-did-vm?organization_id={did_organization}"
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap()
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        rotate(&competing_app, &organization_id, "service-a", json!({}))
            .await
            .0,
        StatusCode::CONFLICT
    );
    release_tx.send(()).unwrap();
    assert_eq!(did_publication.await.unwrap().status(), StatusCode::OK);
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
        3
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
    let (config_status, saved_response) =
        public_config_request(&competing_app, &organization_id, "PATCH", stale_config).await;
    assert_eq!(config_status, StatusCode::OK);
    assert_eq!(
        saved_response["services"][0]["name"],
        "Renamed during rotation"
    );
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

    let (status, mut stale_binding_config) =
        public_config_request(&app, &organization_id, "GET", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    stale_binding_config["services"][0]["name"] = json!("Preserve managed binding");
    let binding_lease = store
        .acquire_rotation_lease(&organization_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        public_config_request(
            &competing_app,
            &organization_id,
            "PATCH",
            stale_binding_config.clone(),
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    binding_lease.release().await.unwrap();
    store
        .bind_profile(
            &organization_id,
            &json!({
                "signing_service_id": "managed-openbao-transit",
                "signing_key_reference": "managed-issuer-key",
                "key_purpose": "vc_jwt_issuer"
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        public_config_request(
            &competing_app,
            &organization_id,
            "PATCH",
            stale_binding_config,
        )
        .await
        .0,
        StatusCode::OK
    );
    let bound = store.load(&organization_id).await.unwrap();
    assert_eq!(bound["services"][0]["name"], "Preserve managed binding");
    assert_eq!(
        bound["key_reference_purposes"]["managed-openbao-transit"]["managed-issuer-key"],
        json!(["vc_jwt_issuer"])
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
    assert_eq!(denied["rotation_state"]["provider_rotation"]["ok"], false);
    assert_eq!(
        denied["rotation_state"]["previous_versions"],
        before_denial["services"][0]["rotation_state"]["previous_versions"]
    );
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
    assert_eq!(
        rotate(&app, &organization_id, "service-b", json!({}))
            .await
            .0,
        StatusCode::CONFLICT
    );

    let (status, mut rebound_config) =
        public_config_request(&app, &organization_id, "GET", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    rebound_config["services"][0]["key_reference"] = json!("replacement-key");
    let (status, _) = public_config_request(&app, &organization_id, "PATCH", rebound_config).await;
    assert_eq!(status, StatusCode::OK);
    let rebound = store.load(&organization_id).await.unwrap();
    assert_eq!(rebound["services"][0]["rotation_state"], json!({}));
    let unresolved_operation = needs_reconcile["services"][0]["rotation_state"]
        ["reconcile_required"]["operation_id"]
        .as_str()
        .unwrap();
    let status_response = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/internal/registry/{organization_id}/services/service-a/rotation-reconcile"
            ))
            .header("x-api-key", "test-internal-key")
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status_response.status(), StatusCode::OK);
    let status_body: Value = serde_json::from_slice(
        &to_bytes(status_response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status_body["reconcile_required"], true);
    assert_eq!(status_body["operation_id"], unresolved_operation);
    let replacement_marker = json!({
        "operation_id": uuid::Uuid::new_v4().to_string(),
        "service_id": "service-a",
        "key_reference": "replacement-key",
        "started_at": chrono::Utc::now().to_rfc3339(),
        "baseline_version": 1,
    });
    let lease = store
        .acquire_rotation_lease(&organization_id)
        .await
        .unwrap()
        .unwrap();
    store
        .create_rotation_marker(
            &organization_id,
            &rebound["services"][0],
            &replacement_marker,
            &lease,
        )
        .await
        .unwrap();
    lease.release().await.unwrap();
    assert_eq!(
        store
            .rotation_markers_for_service(&organization_id, "service-a")
            .await
            .unwrap()
            .len(),
        2
    );
    let lease = store
        .acquire_rotation_lease(&organization_id)
        .await
        .unwrap()
        .unwrap();
    store
        .clear_rotation_marker(
            &organization_id,
            &rebound["services"][0],
            &replacement_marker,
            &lease,
        )
        .await
        .unwrap();
    lease.release().await.unwrap();
    assert_eq!(
        reconcile(
            &app,
            &organization_id,
            "service-a",
            unresolved_operation,
            true,
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (status, mut rebound_to_original) =
        public_config_request(&app, &organization_id, "GET", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    rebound_to_original["services"][0]["key_reference"] = json!("signing-key");
    assert_eq!(
        public_config_request(&app, &organization_id, "PATCH", rebound_to_original)
            .await
            .0,
        StatusCode::OK
    );
    let rotations_before_rebind = rotations.load(Ordering::SeqCst);
    assert_eq!(
        rotate(&app, &organization_id, "service-a", json!({}))
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(rotations.load(Ordering::SeqCst), rotations_before_rebind);
    let rebound_to_original = store.load(&organization_id).await.unwrap();
    let current_service = &rebound_to_original["services"][0];
    let marker = store
        .rotation_marker(&organization_id, current_service)
        .await
        .unwrap()
        .unwrap();
    let operation_id = marker["operation_id"].as_str().unwrap();
    let status_response = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/internal/registry/{organization_id}/services/service-a/rotation-reconcile"
            ))
            .header("x-api-key", "test-internal-key")
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status_response.status(), StatusCode::OK);
    let status_body: Value = serde_json::from_slice(
        &to_bytes(status_response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status_body["operation_id"], operation_id);
    assert_eq!(status_body["baseline_version"], marker["baseline_version"]);
    assert_eq!(
        reconcile(&app, &organization_id, "service-a", operation_id, false)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        reconcile(&app, &organization_id, "service-a", operation_id, true)
            .await
            .0,
        StatusCode::CONFLICT
    );
    let lease = store
        .acquire_rotation_lease(&organization_id)
        .await
        .unwrap()
        .unwrap();
    store
        .clear_rotation_marker(&organization_id, current_service, &marker, &lease)
        .await
        .unwrap();
    let mut settled_marker = marker.clone();
    settled_marker["started_at"] =
        json!((chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339());
    store
        .create_rotation_marker(&organization_id, current_service, &settled_marker, &lease)
        .await
        .unwrap();
    lease.release().await.unwrap();
    let (reconciled_status, reconciled) =
        reconcile(&app, &organization_id, "service-a", operation_id, true).await;
    assert_eq!(reconciled_status, StatusCode::OK, "{reconciled}");
    assert_eq!(reconciled["republication_required"], true);
    assert_eq!(
        reconciled["rotation_state"]["provider_rotation"]["version"],
        5
    );
    assert!(store
        .rotation_marker(&organization_id, current_service)
        .await
        .unwrap()
        .is_none());
    let current = store.load(&organization_id).await.unwrap();
    let service_b = &current["services"][1];
    let unchanged_operation = uuid::Uuid::new_v4().to_string();
    let unchanged_marker = json!({
        "operation_id": unchanged_operation,
        "started_at": (chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339(),
        "service_id": "service-b",
        "key_reference": "signing-key",
        "baseline_version": latest_version.load(Ordering::SeqCst),
        "prior_rotation_state": {},
        "overlap_days": 7,
        "activate_at": chrono::Utc::now().to_rfc3339(),
        "publish_updates": false,
    });
    let lease = store
        .acquire_rotation_lease(&organization_id)
        .await
        .unwrap()
        .unwrap();
    store
        .create_rotation_marker(&organization_id, service_b, &unchanged_marker, &lease)
        .await
        .unwrap();
    lease.release().await.unwrap();
    let (unchanged_status, unchanged) = reconcile(
        &app,
        &organization_id,
        "service-b",
        &unchanged_operation,
        true,
    )
    .await;
    assert_eq!(unchanged_status, StatusCode::CONFLICT, "{unchanged}");
    assert!(store
        .rotation_marker(&organization_id, service_b)
        .await
        .unwrap()
        .is_some());
    let lease = store
        .acquire_rotation_lease(&organization_id)
        .await
        .unwrap()
        .unwrap();
    store
        .clear_rotation_marker(&organization_id, service_b, &unchanged_marker, &lease)
        .await
        .unwrap();
    lease.release().await.unwrap();
    let (status, mut rebound_again) =
        public_config_request(&app, &organization_id, "GET", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    rebound_again["services"][0]["key_reference"] = json!("replacement-key");
    assert_eq!(
        public_config_request(&app, &organization_id, "PATCH", rebound_again)
            .await
            .0,
        StatusCode::OK
    );
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
    assert!(matches!(
        store
            .create_rotation_marker(
                &organization_id,
                &needs_reconcile["services"][0],
                &needs_reconcile["services"][0]["rotation_state"]["reconcile_required"],
                &old_lease,
            )
            .await,
        Err(RegistryError::Conflict)
    ));
    let before_jwks = publication_documents.jwks(&organization_id).await.unwrap();
    let stale_jwk = json!({
        "kty": "EC", "crv": "P-256",
        "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
        "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
    });
    assert!(publication_documents
        .publish_jwk_with_lease(
            &organization_id,
            "service-a",
            PublishJwkRequest {
                jwk: stale_jwk.clone(),
                key_reference: Some("stale-key".into()),
                cert_pem: None,
                cert_chain_pem: None,
            },
            &old_lease,
        )
        .await
        .is_err());
    assert_eq!(
        publication_documents.jwks(&organization_id).await.unwrap(),
        before_jwks
    );
    let did_key = did_storage_key(&organization_id, None);
    let before_did: Option<String> = connection.get(&did_key).await.unwrap();
    assert!(publication_documents
        .publish_did_with_lease(
            &organization_id,
            "service-a",
            PublishDidRequest {
                jwk: stale_jwk,
                public_domain: "example.test".into(),
                did_id: None,
                org_slug: Some(organization_id.to_lowercase()),
                fragment: Some("stale-after-lease".into()),
                key_reference: Some("signing-key".into()),
                cert_pem: None,
                cert_chain_pem: None,
                relationship: Default::default(),
            },
            &old_lease,
        )
        .await
        .is_err());
    let after_did: Option<String> = connection.get(&did_key).await.unwrap();
    assert_eq!(after_did, before_did);
    old_lease.release().await.unwrap();
    let owner: String = connection.get(&lease_key).await.unwrap();
    assert_eq!(owner, "replacement-owner");
    let _: () = connection.del(&lease_key).await.unwrap();
    let _: () = connection.del(storage_key(&organization_id)).await.unwrap();
    server.abort();
}

#[tokio::test]
#[ignore = "requires disposable MARTY_TEST_REDIS_URL"]
async fn lost_pending_write_response_keeps_registry_and_marker_together() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
    let organization_id = format!("test-pending-{}", uuid::Uuid::new_v4().simple());
    let store = RegistryStore::connect(&redis_url).await.unwrap();
    let initial = store
        .save(
            &organization_id,
            &json!({"services": [{
                "id": "service-a", "service_type": "openbao-transit",
                "endpoint": "https://kms.example.test", "mount": "transit",
                "key_reference": "signing-key", "algorithms": ["ES256"]
            }]}),
        )
        .await
        .unwrap();
    let service = &initial["services"][0];
    let marker = json!({
        "operation_id": uuid::Uuid::new_v4().to_string(),
        "service_id": "service-a",
        "key_reference": "signing-key",
        "started_at": chrono::Utc::now().to_rfc3339(),
        "baseline_version": 3,
        "prior_rotation_state": {},
        "overlap_days": 7,
        "activate_at": chrono::Utc::now().to_rfc3339(),
        "publish_updates": false,
    });
    let mut pending = initial.clone();
    pending["services"][0]["rotation_state"]["reconcile_required"] = marker.clone();
    let lease = store
        .acquire_rotation_lease(&organization_id)
        .await
        .unwrap()
        .unwrap();
    let _lost_response = store
        .save_pending_rotation_with_marker(&organization_id, service, &pending, &marker, &lease)
        .await
        .unwrap();
    lease.release().await.unwrap();
    let persisted = store.load(&organization_id).await.unwrap();
    assert_eq!(
        persisted["services"][0]["rotation_state"]["reconcile_required"],
        marker
    );
    assert_eq!(
        store
            .rotation_markers_for_service(&organization_id, "service-a")
            .await
            .unwrap(),
        vec![marker.clone()]
    );
    let lease = store
        .acquire_rotation_lease(&organization_id)
        .await
        .unwrap()
        .unwrap();
    store
        .clear_rotation_marker(&organization_id, service, &marker, &lease)
        .await
        .unwrap();
    lease.release().await.unwrap();
    let mut connection = store.connection();
    let _: () = connection.del(storage_key(&organization_id)).await.unwrap();
}
