use std::{sync::Arc, time::Duration};

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use marty_organization::{
    organization_core_router, postgres::PostgresOrganizationStore, OrganizationApplication,
    OrganizationCache, OrganizationHttpState,
};
use mmf_data::MemoryCache;
use mmf_security::ServiceTokenAuthenticator;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use uuid::Uuid;

const TOKEN: &str = "offline-audit-test-service-token-0001";

fn router() -> axum::Router {
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(100))
        .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
        .unwrap();
    let cache = OrganizationCache::new(
        Arc::new(MemoryCache::default()),
        Arc::new(MemoryCache::default()),
        Arc::new(MemoryCache::default()),
    );
    let application =
        OrganizationApplication::new(PostgresOrganizationStore::new(pool), cache).unwrap();
    organization_core_router(OrganizationHttpState {
        application: Arc::new(application),
        service_authenticator: Arc::new(
            ServiceTokenAuthenticator::new(Some(TOKEN.into()), true).unwrap(),
        ),
        organization_creation_enabled: false,
        marty_organization_id: None,
    })
}

fn body() -> Value {
    let mut body = serde_json::from_str::<Value>(include_str!(
        "../../../../contracts/offline-verification-ingest.json"
    ))
    .unwrap()["native_request"]
        .clone();
    body["events"][0]["timestamp"] = json!(chrono::Utc::now());
    body
}

fn request(
    method: &str,
    path: &str,
    body: Value,
    key: Uuid,
    org: Uuid,
    permission: &str,
    trusted: bool,
) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("x-user-id", format!("api_key:{key}"))
        .header("x-api-key-id", key.to_string())
        .header("x-organization-id", org.to_string())
        .header("x-required-permission", permission);
    if trusted {
        request = request.header("x-service-token", TOKEN);
    }
    request.body(Body::from(body.to_string())).unwrap()
}

#[tokio::test]
async fn offline_audit_http_rejects_untrusted_or_wrong_tenant_authority_before_storage() {
    let org = Uuid::new_v4();
    let path = format!("/v1/organizations/{org}/offline-verification-events");
    for (trusted, claimed_org, permission, expected) in [
        (false, org, "audit:ingest", StatusCode::UNAUTHORIZED),
        (true, Uuid::new_v4(), "audit:ingest", StatusCode::FORBIDDEN),
        (true, org, "audit:view", StatusCode::FORBIDDEN),
    ] {
        let response = router()
            .oneshot(request(
                "POST",
                &path,
                body(),
                Uuid::new_v4(),
                claimed_org,
                permission,
                trusted,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
}

#[tokio::test]
async fn offline_audit_http_rejects_unwhitelisted_data_without_connecting_to_storage() {
    let org = Uuid::new_v4();
    let path = format!("/v1/organizations/{org}/offline-verification-events");
    let mut value = body();
    value["events"][0]["payload"]["credential"] = json!("private-data-must-not-echo");
    let response = router()
        .oneshot(request(
            "POST",
            &path,
            value,
            Uuid::new_v4(),
            org,
            "audit:ingest",
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = to_bytes(response.into_body(), 2048).await.unwrap();
    assert!(!String::from_utf8_lossy(&response).contains("private-data"));
}

#[tokio::test]
async fn offline_audit_http_never_acknowledges_unavailable_persistence() {
    let org = Uuid::new_v4();
    let base = format!("/v1/organizations/{org}/offline-verification-events");
    for (method, path) in [
        ("POST", base.clone()),
        ("GET", base.clone()),
        ("GET", format!("{base}/{}", Uuid::new_v4())),
    ] {
        let response = router()
            .oneshot(request(
                method,
                &path,
                body(),
                Uuid::new_v4(),
                org,
                "audit:ingest",
                true,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 2048).await.unwrap()).unwrap();
        assert_eq!(value["detail"], "OFFLINE_AUDIT.PERSISTENCE_UNAVAILABLE");
    }
}
