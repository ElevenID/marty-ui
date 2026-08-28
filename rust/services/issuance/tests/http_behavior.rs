use axum::{body::Body, http::Request};
use marty_issuance_service::{http::router, IssuanceRuntime, IssuanceServiceConfig};
use serde_json::Value;
use tower::ServiceExt;

async fn json_body(response: axum::response::Response) -> Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&body).expect("json")
}

#[tokio::test]
async fn native_health_preserves_the_legacy_body_and_mmf_readiness() {
    let coverage: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-native-coverage.json"
    ))
    .expect("coverage");
    let expected = &coverage["native_http"][0]["response"];
    let config =
        IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>()).expect("config");
    let runtime = IssuanceRuntime::new(&config).expect("runtime");
    let app = router(runtime.state());

    let health = app
        .clone()
        .oneshot(
            Request::get("/health")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(health.status().as_u16(), expected["status_code"]);
    assert_eq!(json_body(health).await, expected["body"]);

    let not_ready = app
        .clone()
        .oneshot(Request::get("/ready").body(Body::empty()).expect("request"))
        .await
        .expect("response");
    assert_eq!(not_ready.status(), 503);

    runtime.mark_listener_healthy().expect("listener");
    runtime.activate().expect("active");
    let ready = app
        .oneshot(Request::get("/ready").body(Body::empty()).expect("request"))
        .await
        .expect("response");
    assert_eq!(ready.status(), 200);
    assert_eq!(json_body(ready).await["ready"], true);
}
