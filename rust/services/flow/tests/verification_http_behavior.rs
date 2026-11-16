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
    router_with_auth(None)
}

fn router_with_auth(
    service_authenticator: Option<Arc<mmf_security::ServiceTokenAuthenticator>>,
) -> axum::Router {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/flow")
        .expect("lazy pool");
    flow_read_router(FlowHttpState {
        service_authenticator,
        repository: PostgresFlowRepository::new(pool),
        providers: Arc::new(FlowProviderRegistry::default()),
        public_base_url: "https://verifier.example".into(),
        verification: FlowHttpVerificationOptions::default(),
        application_approval: marty_flow::FlowHttpApplicationApprovalOptions::default(),
    })
}

#[tokio::test]
async fn wallet_request_owner_requires_workload_auth_before_storage_or_signing() {
    for gateway_headers in [false, true] {
        let mut request = Request::post(
            "/internal/v1/wallet-verifier-requests/00000000-0000-4000-8000-000000000001",
        )
        .header("x-service-token", "untrusted-caller-token")
        .header("x-organization-id", "caller-controlled-tenant");
        if gateway_headers {
            request = request.header("x-api-key-id", "caller-key");
        }
        let response = router()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), 401);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "service_authentication_required");
    }
}

#[tokio::test]
async fn wallet_request_owner_refuses_unconfigured_missing_wrong_and_duplicate_tokens() {
    let valid = "s".repeat(32);
    for configured in [false, true] {
        for tokens in [
            vec![],
            vec!["wrong"],
            vec![valid.as_str(), valid.as_str()],
            vec![valid.as_str(), "wrong"],
            vec!["wrong", valid.as_str()],
        ] {
            let auth = mmf_security::ServiceTokenAuthenticator::new(
                configured.then(|| valid.clone()),
                configured,
            )
            .unwrap();
            let mut request = Request::post(
                "/internal/v1/wallet-verifier-requests/00000000-0000-4000-8000-000000000001",
            );
            for token in tokens {
                request = request.header("x-service-token", token);
            }
            let response = router_with_auth(Some(Arc::new(auth)))
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), 401);
        }
        if !configured {
            let auth = mmf_security::ServiceTokenAuthenticator::new(None, false).unwrap();
            let response = router_with_auth(Some(Arc::new(auth)))
                .oneshot(Request::post(
                    "/internal/v1/wallet-verifier-requests/00000000-0000-4000-8000-000000000001",
                ).header("x-service-token", valid.as_str()).body(Body::empty()).unwrap())
                .await.unwrap();
            assert_eq!(response.status(), 401);
        }
    }
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
