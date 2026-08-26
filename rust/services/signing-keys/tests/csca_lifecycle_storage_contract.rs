use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use chrono::Utc;
use marty_crypto::jwk::certificate_pem_to_jwk;
use marty_signing_keys::{
    csca_lifecycle::{
        csca_lifecycle_storage_key, CscaLifecycleError, CscaLifecycleStore,
        ImportCscaCertificateRequest, ListCscaOutboxQuery,
    },
    registry::RegistryStore,
};
use marty_verification::issuance::CscaAuthority;
use redis::AsyncCommands;
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

fn request(label: &str) -> ImportCscaCertificateRequest {
    let authority = CscaAuthority::new("USA", label, 30).unwrap();
    let cert_pem = authority.cert_pem().unwrap();
    ImportCscaCertificateRequest {
        expected_public_jwk: serde_json::to_value(certificate_pem_to_jwk(&cert_pem).unwrap())
            .unwrap(),
        cert_pem,
        cert_chain_pem: String::new(),
        key_reference: "hsm://csca/usa".to_string(),
        metadata: Value::Null,
    }
}

#[tokio::test]
#[ignore = "requires MARTY_TEST_REDIS_URL"]
async fn redis_round_trip_is_tenant_scoped_and_rejects_lost_updates() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("test Redis URL");
    let organization_id = format!("rust-csca-lifecycle-{}", Uuid::new_v4().simple());
    let registry = RegistryStore::connect(&redis_url).await.unwrap();
    let store = CscaLifecycleStore::from_connection(registry.connection());
    let now = Utc::now();
    let mut first = store.load(&organization_id, now).await.unwrap();
    let mut stale = store.load(&organization_id, now).await.unwrap();

    first.import("csca-1", request("US CSCA 1"), now).unwrap();
    store.save(&first).await.unwrap();
    let mut loaded = store.load(&organization_id, now).await.unwrap();
    assert_eq!(loaded.revision, 1);
    assert!(loaded.certificates.contains_key("csca-1"));
    let event = loaded
        .pending_outbox(&ListCscaOutboxQuery::default())
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    assert_eq!(event.topic, "certificate.issued");
    loaded.acknowledge_outbox(&event.event_id, now).unwrap();
    store.save(&loaded).await.unwrap();
    let acknowledged = store.load(&organization_id, now).await.unwrap();
    assert!(acknowledged
        .pending_outbox(&ListCscaOutboxQuery::default())
        .unwrap()
        .is_empty());
    assert!(acknowledged.outbox[&event.event_id].published_at.is_some());

    stale.import("csca-2", request("US CSCA 2"), now).unwrap();
    assert_eq!(
        store.save(&stale).await.unwrap_err(),
        CscaLifecycleError::ConcurrentModification
    );

    let key = csca_lifecycle_storage_key(&organization_id);
    let mut connection = registry.connection();
    let _: () = connection.set(&key, "not-json").await.unwrap();
    assert!(matches!(
        store.load(&organization_id, now).await,
        Err(CscaLifecycleError::Corrupt(_))
    ));
    let _: () = connection.del(&key).await.unwrap();
}

#[tokio::test]
#[ignore = "requires MARTY_TEST_REDIS_URL"]
async fn redis_backed_http_routes_complete_the_authenticated_lifecycle() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("test Redis URL");
    let organization_id = format!("rust-csca-http-{}", Uuid::new_v4().simple());
    let registry = RegistryStore::connect(&redis_url).await.unwrap();
    let store = CscaLifecycleStore::from_connection(registry.connection());
    let app = marty_signing_keys::http::router_with_dependencies(
        "test-internal-key".to_string(),
        Some(registry.clone()),
        None,
        Some(store),
        None,
        None,
        None,
    );
    let import = request("HTTP CSCA");
    let import_body = serde_json::json!({
        "cert_pem": import.cert_pem,
        "cert_chain_pem": import.cert_chain_pem,
        "key_reference": import.key_reference,
        "expected_public_jwk": import.expected_public_jwk,
        "metadata": import.metadata,
    })
    .to_string();
    let certificate_path =
        format!("/internal/documents/{organization_id}/csca-certificates/csca-http-1");

    let imported = app
        .clone()
        .oneshot(
            Request::put(&certificate_path)
                .header("content-type", "application/json")
                .header("x-api-key", "test-internal-key")
                .body(Body::from(import_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(imported.status(), StatusCode::OK);

    let listed = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/internal/documents/{organization_id}/csca-certificates?status=VALID&subject=HTTP"
            ))
            .header("x-api-key", "test-internal-key")
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let listed: Value =
        serde_json::from_slice(&to_bytes(listed.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1);

    let outbox_path = format!("/internal/documents/{organization_id}/csca-outbox");
    let outbox = app
        .clone()
        .oneshot(
            Request::get(&outbox_path)
                .header("x-api-key", "test-internal-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(outbox.status(), StatusCode::OK);
    let outbox: Value =
        serde_json::from_slice(&to_bytes(outbox.into_body(), usize::MAX).await.unwrap()).unwrap();
    let event_id = outbox[0]["event_id"].as_str().unwrap();
    let acknowledged = app
        .clone()
        .oneshot(
            Request::post(format!("{outbox_path}/{event_id}/acknowledge"))
                .header("x-api-key", "test-internal-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(acknowledged.status(), StatusCode::OK);

    let revoked = app
        .clone()
        .oneshot(
            Request::post(format!("{certificate_path}/revoke"))
                .header("content-type", "application/json")
                .header("x-api-key", "test-internal-key")
                .body(Body::from(r#"{"reason":"KEY_COMPROMISE"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::OK);

    let data = app
        .oneshot(
            Request::get(format!("{certificate_path}/data"))
                .header("x-api-key", "test-internal-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(data.status(), StatusCode::GONE);

    let mut connection = registry.connection();
    let _: () = connection
        .del(csca_lifecycle_storage_key(&organization_id))
        .await
        .unwrap();
}
