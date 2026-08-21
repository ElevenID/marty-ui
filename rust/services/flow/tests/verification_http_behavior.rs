use std::sync::Arc;

use axum::{body::Body, http::Request};
use marty_flow::{
    flow_read_router, FlowHttpState, FlowHttpVerificationOptions, FlowProviderRegistry,
    PostgresFlowRepository,
};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

fn router() -> axum::Router {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/flow")
        .expect("lazy pool");
    flow_read_router(FlowHttpState {
        repository: PostgresFlowRepository::new(pool),
        providers: Arc::new(FlowProviderRegistry::default()),
        public_base_url: "https://verifier.example".into(),
        verification: FlowHttpVerificationOptions::default(),
        application_approval: marty_flow::FlowHttpApplicationApprovalOptions::default(),
    })
}

#[tokio::test]
async fn language_neutral_verification_http_contract_is_registered_fail_closed() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/flow-verification-http-behavior.json"
    ))
    .unwrap();
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["routes"].as_array().unwrap().len(), 7);
    assert_eq!(contract["python_fallback"], "forbidden");
    assert_eq!(
        contract["standalone_siop_start_response"],
        json!([
            "instance_id",
            "request_uri",
            "siop_uri",
            "nonce",
            "expires_at"
        ])
    );
    assert_eq!(
        contract["terminal_persistence"],
        "nonce_result_subject_and_callback_atomic"
    );

    for path in [
        "/v1/flows/verify",
        "/v1/flows/siop",
        "/v1/flows/instances/instance-1/request",
        "/v1/flows/instances/instance-1/submit",
        "/v1/flows/instances/instance-1/submit/dc-api",
        "/v1/flows/siop/submit",
    ] {
        let response = router()
            .oneshot(Request::delete(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), 405, "route {path}");
    }

    let response = router()
        .oneshot(
            Request::post("/v1/flows/verify")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "presentation_policy_id": "policy-1",
                        "organization_id": "org-1",
                        "issuer_did": "did:web:verifier.example"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
}
