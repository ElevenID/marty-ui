//! Six base review cases: actual gateway -> HTTP -> native operations/resolver
//! -> owned PostgreSQL, with the ORIGINAL CONTROLLED lifecycle (not main's real
//! publisher). All 46 original cases retain their order: 37 direct, six gateway,
//! three direct. Successful gateway manual actors persist into later snapshots;
//! the internal evidence-recovery actor is never rewritten.
//!
//! Corrected oracle source revision: 0301814f037e538a33af586902dcd56a1b9c7b79.
//! Git blob: a7ac869ce8ca3c993479c2824b8660611af73e4a.
//! SHA256: 84db4b9cc4d560138c8329a3a641b78cda82a52d7db200c883be32e0a28d7b6f.
//! Raw native text/plain 500 remains independently asserted against that oracle;
//! pinned MMF b4376cd projects it to a generic JSON MIP error at the public edge.
//! This gate does not claim real-main publication/signing/mirror qualification.

use std::{sync::Arc, time::Duration};

use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::Request,
    middleware::{from_fn_with_state, Next},
    response::Response,
    Router,
};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use super::{
    canvas_operations_gateway_replay::{candidate_router, request, CountedHttp, RequestBoundary},
    canvas_operations_read_replay::timestamps,
    issuance_process::reserve_port,
};

type NativeResponse = (u16, String, Value);
type Observations = Arc<Mutex<Vec<NativeResponse>>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum GatewayCase {
    Suspend,
    Revoke,
    Failed,
    RecoveredFailure,
    RecoveredSuccess,
    Concurrent,
}

impl GatewayCase {
    pub(super) const ALL: [Self; 6] = [
        Self::Suspend,
        Self::Revoke,
        Self::Failed,
        Self::RecoveredFailure,
        Self::RecoveredSuccess,
        Self::Concurrent,
    ];

    pub(super) fn from_case(case: &Value) -> Option<Self> {
        match case["name"].as_str().unwrap() {
            "review_suspend" => Some(Self::Suspend),
            "review_revoke" => Some(Self::Revoke),
            "review_failed" => Some(Self::Failed),
            "review_recovered_failure" => Some(Self::RecoveredFailure),
            "review_recovered_success" => Some(Self::RecoveredSuccess),
            "review_concurrent" => Some(Self::Concurrent),
            _ => None,
        }
    }
}

// Observe the actual native response BEFORE MMF normalization, then return its
// original parts/bytes unchanged. This never manufactures an upstream response.
async fn observe_native(
    State(observations): State<Observations>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let (parts, body) = next.run(request).await.into_parts();
    let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!(std::str::from_utf8(&bytes).unwrap()));
    observations.lock().await.push((
        parts.status.as_u16(),
        parts.headers["content-type"].to_str().unwrap().to_owned(),
        value,
    ));
    Response::from_parts(parts, Body::from(bytes))
}

pub(super) struct GatewayEndpoint {
    router: Router,
    http: Arc<CountedHttp>,
    observations: Observations,
    // Keep the unserved legacy reservation alive: counters independently reject
    // ANY legacy selection, not merely a successful fallback response.
    _legacy: std::net::TcpListener,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl GatewayEndpoint {
    pub(super) async fn start(native: Router, case: &Value) -> Self {
        assert!(GatewayCase::from_case(case).is_some());
        assert_eq!(case["method"], "POST");
        let observations = Observations::default();
        let native = native.layer(from_fn_with_state(observations.clone(), observe_native));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (legacy, legacy_port) = reserve_port();
        let (router, http) = candidate_router(port, legacy_port);
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, native)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
        });
        let endpoint = Self {
            router,
            http,
            observations,
            _legacy: legacy,
            stop: Some(stop),
            task,
        };
        // Genuine gateway authentication/tenant denials must not reach native,
        // acquire a review claim, or invoke the controlled lifecycle.
        let (status, content_type, body) = request(
            &endpoint.router,
            case,
            None,
            "org-review",
            RequestBoundary::DeniedBeforeProxy,
        )
        .await;
        assert_eq!((status, content_type.as_str()), (401, "application/json"));
        assert!(uuid::Uuid::parse_str(body["message_id"].as_str().unwrap()).is_ok());
        assert_eq!(
            body,
            json!({"error":"unauthorized","error_description":"Authentication required","message_id":body["message_id"]})
        );
        let denied = request(
            &endpoint.router,
            case,
            Some(("cookie", "sessionId=actor-primary")),
            "org-other",
            RequestBoundary::DeniedBeforeProxy,
        )
        .await;
        assert_eq!(
            denied,
            (
                403,
                "application/json".into(),
                json!({"detail":"Not a member of this organization"})
            )
        );
        assert_eq!(endpoint.http.counts(), (0, 0));
        assert!(endpoint.observations.lock().await.is_empty());
        endpoint
    }

    pub(super) async fn request(&self, case: &Value, frozen: &Value) -> NativeResponse {
        let (status, content_type, mut body) = request(
            &self.router,
            case,
            Some(("cookie", "sessionId=actor-primary")),
            "org-review",
            RequestBoundary::Forwarded,
        )
        .await;
        assert_eq!(status, frozen["status"].as_u64().unwrap() as u16);
        assert_eq!(content_type, "application/json");
        timestamps(&mut body);
        let expected = public_body(frozen);
        if status >= 400 {
            assert!(uuid::Uuid::parse_str(body["message_id"].as_str().unwrap()).is_ok());
            body["message_id"] = json!("$message-id");
        }
        assert_eq!(
            body, expected,
            "complete public gateway response: {}",
            case["name"]
        );
        // The concurrent primary/competitor have distinct 200/409 statuses. All
        // other scenarios are single-request; no arrival-order assumption.
        let mut observations = self.observations.lock().await;
        let index = observations
            .iter()
            .position(|response| response.0 == status)
            .expect("public response must have an actual observed native response");
        assert_eq!(
            observations
                .iter()
                .filter(|response| response.0 == status)
                .count(),
            1
        );
        observations.remove(index)
    }

    pub(super) async fn close(mut self, expected_native_requests: usize) {
        assert_eq!(self.http.counts(), (expected_native_requests, 0));
        assert!(self.observations.lock().await.is_empty());
        self.stop.take().unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), &mut self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

impl Drop for GatewayEndpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn public_body(frozen: &Value) -> Value {
    match frozen["status"].as_u64().unwrap() {
        200 => {
            assert_eq!(frozen["content_type"], "application/json");
            frozen["body"].clone()
        }
        500 => {
            assert_eq!(frozen["content_type"], "text/plain; charset=utf-8");
            assert_eq!(frozen["body"], "Internal Server Error");
            json!({"error":"service_error","error_description":"Downstream service request failed","message_id":"$message-id"})
        }
        409 => {
            assert_eq!(frozen["content_type"], "application/json");
            assert_eq!(
                frozen["body"],
                json!({"detail":{"code":"canvas_review_already_resolved","message":"Canvas evidence correction review is already claimed or resolved"}})
            );
            json!({"error":"service_error","error_description":"Canvas evidence correction review is already claimed or resolved","details":{"code":"canvas_review_already_resolved"},"message_id":"$message-id"})
        }
        _ => panic!("unreviewed base gateway response projection"),
    }
}

#[test]
fn six_cases_keep_original_order_and_corrected_recovery_oracle() {
    let scenarios = &super::canvas_operations_read_replay::fixtures()[1];
    let selected: Vec<_> = scenarios["cases"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .filter_map(|(index, case)| GatewayCase::from_case(case).map(|case| (index, case)))
        .collect();
    assert_eq!(selected, (37..43).zip(GatewayCase::ALL).collect::<Vec<_>>());
    let frozen: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-operations-recovery-oracle.json"
    ))
    .unwrap();
    let cases = frozen["observations"].as_array().unwrap();
    assert_eq!(cases.len(), 46);
    let recovered = &cases[40];
    assert_eq!(recovered["name"], "review_recovered_failure");
    assert_eq!(
        recovered["snapshot"]["reviews"],
        json!([{"id":"review-recovered_failure","status":"resolved","action":"evidence_recovered","actor":"canvas-evidence-sync","claim_active":false,"recovery_pending":false}])
    );
    assert_eq!(
        public_body(recovered),
        json!({"error":"service_error","error_description":"Downstream service request failed","message_id":"$message-id"})
    );
    assert_eq!(
        public_body(&cases[42]["competing_response"])["details"],
        json!({"code":"canvas_review_already_resolved"})
    );
}
