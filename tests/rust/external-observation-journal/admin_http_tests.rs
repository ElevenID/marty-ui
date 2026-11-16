// SPDX-License-Identifier: AGPL-3.0-only
use crate::external_observation_startup::prepare_observation_router;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use tower::ServiceExt;
const KEY: &str = "synthetic-gateway-service-key-for-admin-contract";
const PATH: &str="/v1/organizations/20000000-0000-4000-8000-000000000001/external-observation-producers/30000000-0000-4000-8000-000000000001/revoke";
fn request(body: &[u8]) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(PATH)
        .header("x-api-key", KEY)
        .header("x-user-id", "admin-one")
        .header("x-organization-id", "20000000-0000-4000-8000-000000000001")
        .header("content-type", "application/json")
        .body(Body::from(body.to_vec()))
        .unwrap()
}
#[tokio::test]
async fn trusted_admin_http_revokes_only_after_canonical_permission_and_revision_checks() {
    let fixture = super::admin_tests::setup().await;
    let router = prepare_observation_router(&fixture.pool, true, Some(KEY))
        .await
        .unwrap()
        .unwrap();
    let valid = br#"{"expected_revision":2}"#;
    let mut api_key = request(valid);
    api_key.headers_mut().insert(
        "x-api-key-id",
        "10000000-0000-4000-8000-000000000001".parse().unwrap(),
    );
    assert_eq!(
        router.clone().oneshot(api_key).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let mut missing_service = request(valid);
    missing_service.headers_mut().remove("x-api-key");
    assert_eq!(
        router
            .clone()
            .oneshot(missing_service)
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let mut wrong_actor = request(valid);
    wrong_actor
        .headers_mut()
        .insert("x-user-id", "producer-not-admin".parse().unwrap());
    assert_eq!(
        router.clone().oneshot(wrong_actor).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    for invalid in [
        br#"{"expected_revision":2,"organization_id":"spoofed"}"#.as_slice(),
        br#"{"expected_revision":2,"expected_revision":3}"#.as_slice(),
    ] {
        assert_eq!(
            router
                .clone()
                .oneshot(request(invalid))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        router
            .clone()
            .oneshot(request(br#"{"expected_revision":1}"#))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    let response = router.clone().oneshot(request(valid)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body["revision"], 3);
    assert!(body["audit_id"].as_str().is_some());
    assert_eq!(
        router.oneshot(request(valid)).await.unwrap().status(),
        StatusCode::CONFLICT
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM organization_service.audit_events")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    fixture.pool.close().await;
}
