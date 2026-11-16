// SPDX-License-Identifier: AGPL-3.0-only
use super::Fixture;
use crate::{
    external_observation_authority_postgres::PostgresObservationAuthority,
    external_observation_http::{observation_router, OBSERVATION_PATH},
    external_observation_postgres::PostgresObservationJournal,
};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use std::sync::Arc;
use tower::ServiceExt;
const KEY: &str = "synthetic-gateway-service-key-for-http-contract";

async fn setup() -> (Fixture, Router) {
    let fixture = Fixture::new().await;
    super::authority_tests::seed_authority(&fixture).await;
    let journal = Arc::new(PostgresObservationJournal::new(
        fixture.pool.clone(),
        Arc::new(PostgresObservationAuthority),
    ));
    let router = observation_router(journal, KEY.as_bytes()).unwrap();
    (fixture, router)
}
fn request(body: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(OBSERVATION_PATH)
        .header("x-api-key", KEY)
        .header("x-api-key-id", "10000000-0000-4000-8000-000000000001")
        .header("x-organization-id", "20000000-0000-4000-8000-000000000001")
        .header("content-type", "application/json")
        .header("idempotency-key", "observation-one")
        .body(Body::from(body))
        .unwrap()
}
fn payload(fixture: &Fixture) -> Vec<u8> {
    serde_json::to_vec(
        &serde_json::json!({"binding_id":"binding-one","binding_revision":1,
        "observation_id":"observation-one","sequence":1,"observed_at_ms":fixture.now,
        "effective_at_ms":fixture.now,"claims":{"completed":false,"score":null}}),
    )
    .unwrap()
}
#[tokio::test]
async fn http_to_canonical_journal_retries_reauthorize_after_grant_revocation() {
    let (fixture, router) = setup().await;
    let first = router
        .clone()
        .oneshot(request(payload(&fixture)))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(first.headers()["cache-control"], "no-store");
    let first: serde_json::Value =
        serde_json::from_slice(&to_bytes(first.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(first["replayed"], false);
    let retry = router
        .clone()
        .oneshot(request(payload(&fixture)))
        .await
        .unwrap();
    assert_eq!(retry.status(), StatusCode::OK);
    let retry: serde_json::Value =
        serde_json::from_slice(&to_bytes(retry.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(first["receipt_id"], retry["receipt_id"]);
    assert_eq!(retry["replayed"], true);
    sqlx::query("UPDATE issuance_service.external_observation_producer_grants SET active=false")
        .execute(&fixture.pool)
        .await
        .unwrap();
    let rejected = router.oneshot(request(payload(&fixture))).await.unwrap();
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM issuance_service.external_observation_receipts")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
    fixture.pool.close().await;
}
#[tokio::test]
async fn http_rejects_untrusted_identity_oversize_and_duplicate_original_bytes_without_writes() {
    let (fixture, router) = setup().await;
    let mut missing = request(payload(&fixture));
    missing.headers_mut().remove("x-api-key");
    assert_eq!(
        router.clone().oneshot(missing).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let mut duplicate_identity = request(payload(&fixture));
    duplicate_identity
        .headers_mut()
        .append("x-organization-id", "spoofed".parse().unwrap());
    assert_eq!(
        router
            .clone()
            .oneshot(duplicate_identity)
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let mut wrong_tenant = request(payload(&fixture));
    wrong_tenant.headers_mut().insert(
        "x-organization-id",
        "20000000-0000-4000-8000-000000000002".parse().unwrap(),
    );
    assert_eq!(
        router.clone().oneshot(wrong_tenant).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        router
            .clone()
            .oneshot(request(vec![b' '; 65537]))
            .await
            .unwrap()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let invalid = br#"{"binding_id":"binding-one","binding_id":"other"}"#.to_vec();
    assert_eq!(
        router
            .clone()
            .oneshot(request(invalid))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut duplicate_key = request(payload(&fixture));
    duplicate_key
        .headers_mut()
        .append("idempotency-key", "observation-one".parse().unwrap());
    assert_eq!(
        router.oneshot(duplicate_key).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM issuance_service.external_observation_receipts")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    fixture.pool.close().await;
}

#[tokio::test]
async fn observation_startup_is_explicit_and_requires_current_storage() {
    use crate::external_observation_startup::prepare_observation_router;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
        .unwrap();
    assert!(prepare_observation_router(&pool, false, None)
        .await
        .unwrap()
        .is_none());
    assert!(prepare_observation_router(&pool, true, None).await.is_err());
    let fixture = super::admin_tests::setup().await;
    assert!(prepare_observation_router(&fixture.pool, true, Some(KEY))
        .await
        .unwrap()
        .is_some());
    sqlx::query("ALTER TABLE issuance_service.external_observation_bindings DISABLE TRIGGER external_observation_bindings_revision")
        .execute(&fixture.pool).await.unwrap();
    assert!(prepare_observation_router(&fixture.pool, true, Some(KEY))
        .await
        .is_err());
    sqlx::query("ALTER TABLE issuance_service.external_observation_bindings ENABLE TRIGGER external_observation_bindings_revision")
        .execute(&fixture.pool).await.unwrap();
    sqlx::query("ALTER TABLE issuance_service.external_observation_audit RENAME TO external_observation_audit_unavailable")
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert!(prepare_observation_router(&fixture.pool, true, Some(KEY))
        .await
        .is_err());
    fixture.pool.close().await;
}
