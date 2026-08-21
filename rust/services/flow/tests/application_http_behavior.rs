use std::sync::Arc;

use axum::{body::Body, http::Request};
use marty_flow::{
    flow_read_router, FlowHttpApplicationApprovalOptions, FlowHttpState,
    FlowHttpVerificationOptions, FlowProviderRegistry, PostgresFlowRepository,
};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

fn router() -> axum::Router {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/marty_flow_http_contract")
        .unwrap();
    flow_read_router(FlowHttpState {
        repository: PostgresFlowRepository::new(pool),
        providers: Arc::new(FlowProviderRegistry::default()),
        public_base_url: "https://issuer.example".into(),
        verification: FlowHttpVerificationOptions::default(),
        application_approval: FlowHttpApplicationApprovalOptions::default(),
    })
}

#[tokio::test]
async fn application_webhook_is_registered_and_native_backend_absence_fails_closed() {
    let invalid = router()
        .oneshot(
            Request::post("/v1/flows/webhooks/application-approved")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid.status(), 400);

    let unavailable = router()
        .oneshot(
            Request::post("/v1/flows/webhooks/application-approved")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{
                      "event_type":"application.approved",
                      "aggregate_id":"application-1",
                      "aggregate_type":"application",
                      "organization_id":"org-1",
                      "data":{"applicant_id":"applicant-1"},
                      "timestamp":"2026-08-09T12:00:00+00:00"
                    }"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unavailable.status(), 503);
}
