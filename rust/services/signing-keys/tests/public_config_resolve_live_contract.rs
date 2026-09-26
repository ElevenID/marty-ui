//! Opt-in public-route test against disposable Redis and a read-only mock KMS.

use axum::{
    body::{to_bytes, Body},
    extract::Path,
    http::{Request, StatusCode},
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
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tower::ServiceExt;

async fn resolve(app: &Router, organization_id: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/v1/signing-keys/config/resolve?organization_id={organization_id}"
            ))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
#[ignore = "requires disposable MARTY_TEST_REDIS_URL"]
async fn public_config_resolve_preserves_selection_and_redacts_kms_credentials() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
    let writes = Arc::new(AtomicUsize::new(0));
    let kms = Router::new().route(
        "/v1/transit/keys/{reference}",
        get(|Path(reference): Path<String>| async move {
            if reference != "dsc-ed" {
                return (StatusCode::NOT_FOUND, Json(json!({}))).into_response();
            }
            (StatusCode::OK, Json(json!({"data": {
                "latest_version": 1, "type": "ed25519",
                "keys": {"1": {"name": "ed25519", "public_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}}
            }}))).into_response()
        }).post({
            let writes = Arc::clone(&writes);
            move || {
                let writes = Arc::clone(&writes);
                async move {
                    writes.fetch_add(1, Ordering::SeqCst);
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, kms).await.unwrap() });

    let organization_id = format!("test-config-resolve-{}", uuid::Uuid::new_v4().simple());
    let other_organization_id = format!("{organization_id}-other");
    let store = RegistryStore::connect(&redis_url).await.unwrap();
    store
        .save(
            &organization_id,
            &json!({
                "services": [{
                "id": "service-a", "name": "Passport signing",
                    "service_type": "openbao-transit", "endpoint": endpoint,
                    "mount": "transit", "auth_mode": "token", "auth_reference": "fixture-token",
                    "key_reference": "vc-key", "key_aliases": ["dsc-ed"],
                    "algorithms": ["EdDSA"], "key_purposes": ["mdoc_dsc"]
                }],
            "default_service_id": "service-a",
            "key_reference_purposes": {
                "service-a": {"dsc-ed": ["mdoc_dsc"]}
                }
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

    let (status, selected) = resolve(
        &app,
        &organization_id,
        json!({
            "credential_format": "mso_mdoc", "key_purpose": "mdoc_dsc", "algorithm": "EdDSA"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{selected}");
    assert_eq!(selected["service"]["key_reference"], "dsc-ed");
    assert_eq!(
        selected["resolved_by"],
        json!({
            "credential_format": "mso_mdoc", "key_purpose": "mdoc_dsc", "algorithm": "EdDSA"
        })
    );
    assert!(selected["mdoc_signing_hints"].is_null());
    assert!(!selected.to_string().contains("fixture-token"));
    assert_eq!(selected["service"]["auth_configured"], true);
    assert_eq!(
        resolve(
            &app,
            &organization_id,
            json!({
                "key_purpose": "mdoc_dsc", "algorithm": "ES256"
            })
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        resolve(&app, &other_organization_id, json!({})).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(writes.load(Ordering::SeqCst), 0);

    let mut connection = store.connection();
    let _: () = connection.del(storage_key(&organization_id)).await.unwrap();
    server.abort();
}
