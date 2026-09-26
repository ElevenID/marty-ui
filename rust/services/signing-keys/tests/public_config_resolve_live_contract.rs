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
    profiles::ProfileStore,
    registry::{storage_key, RegistryStore},
};
use redis::AsyncCommands;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
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
    let unavailable = Arc::new(AtomicBool::new(false));
    let kms = Router::new().route(
        "/v1/transit/keys/{reference}",
        get({
            let unavailable = Arc::clone(&unavailable);
            move |Path(reference): Path<String>| {
                let unavailable = Arc::clone(&unavailable);
                async move {
                    if unavailable.load(Ordering::SeqCst) {
                        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({}))).into_response();
                    }
                    if reference != "dsc-ed" {
                        return (StatusCode::NOT_FOUND, Json(json!({}))).into_response();
                    }
                    (StatusCode::OK, Json(json!({"data": {
                        "latest_version": 1, "type": "ed25519",
                        "keys": {"1": {"name": "ed25519", "public_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}}
                    }}))).into_response()
                }
            }
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
    let mut bad_certificate = store.load(&organization_id).await.unwrap();
    bad_certificate["services"][0]["cert_pem"] = json!("not a certificate");
    store
        .save(&organization_id, &bad_certificate)
        .await
        .unwrap();
    assert_eq!(
        resolve(
            &app,
            &organization_id,
            json!({
                "credential_format": "mso_mdoc", "key_purpose": "mdoc_dsc", "algorithm": "EdDSA"
            })
        )
        .await
        .0,
        StatusCode::BAD_GATEWAY
    );
    unavailable.store(true, Ordering::SeqCst);
    assert_eq!(
        resolve(
            &app,
            &organization_id,
            json!({
                "key_purpose": "mdoc_dsc", "algorithm": "EdDSA"
            })
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(writes.load(Ordering::SeqCst), 0);

    let mut connection = store.connection();
    let _: () = connection.del(storage_key(&organization_id)).await.unwrap();
    server.abort();
}

#[tokio::test]
#[ignore = "requires disposable MARTY_TEST_REDIS_URL"]
async fn managed_config_resolve_does_not_revive_retired_tuple_binding() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
    let reads = Arc::new(AtomicUsize::new(0));
    let kms = Router::new()
        .route(
            "/v1/transit/keys",
            get(|| async { Json(json!({"data": {"keys": []}})) }),
        )
        .route(
            "/v1/transit/keys/{reference}",
            get({
                let reads = Arc::clone(&reads);
                move || {
                    let reads = Arc::clone(&reads);
                    async move {
                        reads.fetch_add(1, Ordering::SeqCst);
                        Json(json!({"data": {
                            "latest_version": 1,
                            "type": "ecdsa-p256",
                            "keys": {"1": {"public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt\n6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==\n-----END PUBLIC KEY-----\n"}}
                        }}))
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, kms).await.unwrap() });
    let previous_token = std::env::var("BAO_TOKEN").ok();
    std::env::set_var("BAO_TOKEN", "test-only");

    let organization_id = format!("test-managed-resolve-{}", uuid::Uuid::new_v4().simple());
    let stale = "cred-issuer-0123456789abcdef0123-es256";
    let store = RegistryStore::connect(&redis_url)
        .await
        .unwrap()
        .with_managed_openbao(Some(endpoint));
    store
        .save(
            &organization_id,
            &json!({
                "services": [],
                "key_reference_purposes": {
                    "managed-openbao-transit": {stale: ["vc_jwt_issuer"]}
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
    for request in [
        json!({"key_purpose": "vc_jwt_issuer"}),
        json!({"algorithm": "ES256"}),
        json!({"key_purpose": "vc_jwt_issuer", "algorithm": "ES256"}),
    ] {
        let (status, body) = resolve(&app, &organization_id, request).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    }
    assert_eq!(reads.load(Ordering::SeqCst), 0);

    let lti_organization_id = format!("{organization_id}-lti");
    store
        .save(&lti_organization_id, &json!({"services": []}))
        .await
        .unwrap();
    let profiles = ProfileStore::from_connection(store.connection());
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/issuer_profile_vectors.json")).unwrap();
    let mut lti_profile = fixture["normalize"]["expected"].clone();
    lti_profile["organization_id"] = json!(lti_organization_id);
    lti_profile["signing_service_id"] = json!("managed-openbao-transit");
    lti_profile["signing_key_reference"] = json!("legacy-shared-key");
    lti_profile["key_purpose"] = json!("lti_tool_signing");
    let profile_id = lti_profile["id"].as_str().unwrap();
    profiles
        .put(&lti_organization_id, profile_id, lti_profile.clone())
        .await
        .unwrap();
    let (status, body) = resolve(&app, &lti_organization_id, json!({"algorithm": "ES256"})).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = resolve(
        &app,
        &lti_organization_id,
        json!({"key_purpose": "vc_jwt_issuer", "algorithm": "ES256"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = resolve(
        &app,
        &lti_organization_id,
        json!({"key_purpose": "lti_tool_signing", "algorithm": "ES256"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["service"]["key_reference"], "legacy-shared-key");

    let mut connection = store.connection();
    let _: () = redis::cmd("DEL")
        .arg(storage_key(&organization_id))
        .arg(storage_key(&lti_organization_id))
        .arg(marty_signing_keys::profiles::storage_key(
            &lti_organization_id,
        ))
        .query_async(&mut connection)
        .await
        .unwrap();
    match previous_token {
        Some(token) => std::env::set_var("BAO_TOKEN", token),
        None => std::env::remove_var("BAO_TOKEN"),
    }
    server.abort();
}
