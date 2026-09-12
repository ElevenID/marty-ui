//! Candidate gateway -> actual issuance main -> real HTTP publication and mirror.
//! Reuses the existing process/dependency owner and its eight lifecycle cases.
//! Identity ports are controlled; production route selection is unchanged. This
//! does not equate cancellation of an HTTP client with cancellation of a handler.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, OnceLock,
};

use async_trait::async_trait;
use axum::Router;
use serde_json::{json, Value};
use sqlx::PgPool;

use super::{
    canvas_operations_gateway_replay::{candidate_router, request, CountedHttp, RequestBoundary},
    canvas_status_runtime_contract::{
        run_review_operations_main_with_transport, ReviewExpectedResponse, ReviewMessageIdPolicy,
        ReviewRequestTransport, ReviewResponse, ReviewResponseExpectations, ReviewResponsePhase,
        REVIEW_MESSAGE_ID_SENTINEL,
    },
    issuance_process::reserve_port,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestIdentity {
    Member,
    InvalidSession,
    ForeignApiKey,
}

fn request_identity(case: &Value) -> RequestIdentity {
    match case.get("headers") {
        None => RequestIdentity::Member,
        Some(headers) if *headers == json!({"X-API-Key":"wrong-synthetic-key"}) => {
            // This fixture's denied operation is now rejected by the public
            // gateway session owner, not the downstream service-key owner.
            RequestIdentity::InvalidSession
        }
        Some(headers) if *headers == json!({"X-Organization-ID":"foreign"}) => {
            RequestIdentity::ForeignApiKey
        }
        _ => panic!("unreviewed lifecycle request identity"),
    }
}

struct GatewayTransport {
    router: Router,
    http: Arc<CountedHttp>,
    requests: AtomicUsize,
    denied: AtomicUsize,
    foreign: AtomicUsize,
}

#[async_trait]
impl ReviewRequestTransport for GatewayTransport {
    async fn request(&self, case: &Value) -> ReviewResponse {
        assert_eq!(case["method"], "POST");
        assert_eq!(
            case["path"],
            "/v1/integrations/canvas/evidence-policy-reviews/review-lifecycle/resolve"
        );
        let (auth, tenant, boundary) = match request_identity(case) {
            RequestIdentity::Member => (
                ("cookie", "sessionId=actor-primary"),
                "org-review",
                RequestBoundary::Forwarded,
            ),
            RequestIdentity::InvalidSession => {
                self.denied.fetch_add(1, Ordering::SeqCst);
                (
                    ("cookie", "sessionId=invalid"),
                    "org-review",
                    RequestBoundary::DeniedBeforeProxy,
                )
            }
            RequestIdentity::ForeignApiKey => {
                self.foreign.fetch_add(1, Ordering::SeqCst);
                // A matching authorized query reaches native tenant hiding;
                // an outer gateway tenant mismatch/403 cannot satisfy this.
                (
                    ("x-api-key", "actor-key-wrong-org"),
                    "org-other",
                    RequestBoundary::Forwarded,
                )
            }
        };
        self.requests.fetch_add(1, Ordering::SeqCst);
        // Shared request owner retains forged-header probes, bounded body/time,
        // CORS and independently generated request-header UUID assertions.
        request(&self.router, case, Some(auth), tenant, boundary).await
    }
}

struct GatewayExpectations;

fn mip_expected(
    status: u16,
    error: &str,
    description: &str,
    code: Option<&str>,
) -> ReviewExpectedResponse {
    let mut body = json!({"error":error, "error_description":description,
        "message_id":REVIEW_MESSAGE_ID_SENTINEL});
    if let Some(code) = code {
        body["details"] = json!({"code":code});
    }
    ReviewExpectedResponse {
        status,
        content_type: "application/json".into(),
        body,
        message_id: ReviewMessageIdPolicy::RequireUuid,
    }
}

fn assert_direct(expected: &Value, status: u16, detail: Value) {
    assert_eq!(expected["status"], status);
    assert_eq!(expected["content_type"], "application/json");
    assert_eq!(expected["body"], json!({"detail":detail}));
}

impl ReviewResponseExpectations for GatewayExpectations {
    fn response(
        &self,
        phase: ReviewResponsePhase,
        case: &Value,
        frozen: &Value,
    ) -> ReviewExpectedResponse {
        // Closed, expected-only source projections. No actual response is
        // available here. Downstream detail.code becomes MIP details.code under
        // pinned MMF b4376cda59b3921598e1749f550595d7293e4624 proxy.rs.
        match phase {
            ReviewResponsePhase::AuthenticationDenied => {
                assert_eq!(request_identity(case), RequestIdentity::InvalidSession);
                assert_direct(frozen, 401, json!("Invalid API Key"));
                // gateway middleware::authenticate returns this exact error;
                // do not pretend this is the direct service-key 401 contract.
                mip_expected(401, "unauthorized", "Invalid session", None)
            }
            ReviewResponsePhase::ForeignTenant => {
                assert_eq!(request_identity(case), RequestIdentity::ForeignApiKey);
                let message = "Canvas evidence correction review not found";
                let code = "canvas_review_not_found";
                assert_direct(frozen, 404, json!({"code":code,"message":message}));
                mip_expected(404, "service_error", message, Some(code))
            }
            ReviewResponsePhase::ConcurrentClaim | ReviewResponsePhase::DuplicateResolved => {
                assert_eq!(request_identity(case), RequestIdentity::Member);
                let message = if phase == ReviewResponsePhase::ConcurrentClaim {
                    "Canvas evidence correction review is already claimed or resolved"
                } else {
                    "Canvas evidence correction review is already resolved"
                };
                let code = "canvas_review_already_resolved";
                assert_direct(frozen, 409, json!({"code":code,"message":message}));
                mip_expected(409, "service_error", message, Some(code))
            }
            ReviewResponsePhase::Outcome => {
                assert_eq!(request_identity(case), RequestIdentity::Member);
                match case["name"].as_str().unwrap() {
                    "publication_failure" => {
                        assert_direct(frozen, 503, json!("Revocation service unavailable"));
                        mip_expected(503, "service_error", "Revocation service unavailable", None)
                    }
                    "suspend_delivered" | "revoke_delivered" | "mirror_failure" | "no_delivery"
                    | "pending_delivery" | "failed_delivery" | "wallet_delivery" => {
                        assert_eq!(frozen["status"], 200);
                        assert_eq!(frozen["content_type"], "application/json");
                        // The shared fixture alone substitutes expected actor
                        // fields and compares raw persistence. Return every DTO
                        // field unchanged; no public success normalization.
                        assert_eq!(frozen["body"]["resolved_by"], "actor-primary");
                        ReviewExpectedResponse {
                            status: 200,
                            content_type: "application/json".into(),
                            body: frozen["body"].clone(),
                            message_id: ReviewMessageIdPolicy::None,
                        }
                    }
                    _ => panic!("unreviewed lifecycle outcome"),
                }
            }
        }
    }

    fn trusted_actor(&self) -> Option<&str> {
        Some("actor-primary")
    }
}

/// Caller owns the configured disposable database and outer timeout. The shared
/// fixture owns the real main process, publication hold and external HTTP peers.
pub async fn run(pool: &PgPool, database_url: &str) {
    // Keep a distinct owned legacy reservation for the full run. No server or
    // alias can turn an accidental legacy selection into native success; the
    // shared proxy's bounded requests and final counts remain mandatory.
    let (_legacy_reservation, legacy_port) = reserve_port();
    let retained = OnceLock::new();
    run_review_operations_main_with_transport(pool, database_url, |native_port, _client| {
        let (router, http) = candidate_router(native_port, legacy_port);
        let transport = Arc::new(GatewayTransport {
            router,
            http,
            requests: AtomicUsize::new(0),
            denied: AtomicUsize::new(0),
            foreign: AtomicUsize::new(0),
        });
        assert!(retained.set(transport.clone()).is_ok());
        (transport, Arc::new(GatewayExpectations))
    })
    .await;
    let transport = retained
        .get()
        .expect("gateway transport created after readiness");
    assert_eq!(transport.requests.load(Ordering::SeqCst), 18);
    assert_eq!(transport.denied.load(Ordering::SeqCst), 1);
    assert_eq!(transport.foreign.load(Ordering::SeqCst), 1);
    // Suspend: foreign + outcome + held competitor + duplicate; revoke/mirror:
    // outcome + duplicate each; publication failure: outcome only. Invalid
    // session must never reach either upstream. Four non-mirroring delivery
    // cases add one outcome and one duplicate each, with no legacy selection.
    assert_eq!(transport.http.counts(), (17, 0));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_request_identity_mapping_is_closed() {
        assert_eq!(request_identity(&json!({})), RequestIdentity::Member);
        assert_eq!(
            request_identity(&json!({"headers":{"X-API-Key":"wrong-synthetic-key"}})),
            RequestIdentity::InvalidSession
        );
        assert_eq!(
            request_identity(&json!({"headers":{"X-Organization-ID":"foreign"}})),
            RequestIdentity::ForeignApiKey
        );
        for headers in [
            Value::Null,
            json!({}),
            json!({"X-API-Key":"different"}),
            json!({"X-Organization-ID":"foreign","extra":"unreviewed"}),
        ] {
            assert!(
                std::panic::catch_unwind(|| request_identity(&json!({"headers":headers}))).is_err()
            );
        }
    }

    #[test]
    fn lifecycle_expected_ports_preserve_frozen_success_and_explicit_public_errors() {
        let frozen: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-review-lifecycle-oracle.json"
        ))
        .unwrap();
        for name in [
            "suspend_delivered",
            "revoke_delivered",
            "mirror_failure",
            "publication_failure",
            "no_delivery",
            "pending_delivery",
            "failed_delivery",
            "wallet_delivery",
        ] {
            let mut expected = frozen["observations"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["name"] == name)
                .unwrap()
                .clone();
            if name != "publication_failure" {
                assert!(expected["body"]["resolved_by"].is_null());
                // Emulate only the already-tested shared owner's expected actor
                // substitution; no observed HTTP response enters this port.
                expected["body"]["resolved_by"] = json!("actor-primary");
            }
            let retained = expected.clone();
            let public = GatewayExpectations.response(
                ReviewResponsePhase::Outcome,
                &json!({"name":name}),
                &expected,
            );
            assert_eq!(expected, retained);
            assert_eq!(public.content_type, "application/json");
            if name == "publication_failure" {
                assert_eq!(public.status, 503);
                assert_eq!(public.message_id, ReviewMessageIdPolicy::RequireUuid);
                assert_eq!(
                    public.body,
                    json!({"error":"service_error","error_description":"Revocation service unavailable","message_id":REVIEW_MESSAGE_ID_SENTINEL})
                );
            } else {
                assert_eq!(public.status, 200);
                assert_eq!(public.message_id, ReviewMessageIdPolicy::None);
                assert_eq!(public.body, expected["body"]);
            }
        }
        let cases = [
            (
                ReviewResponsePhase::AuthenticationDenied,
                json!({"headers":{"X-API-Key":"wrong-synthetic-key"}}),
                401,
                json!("Invalid API Key"),
                "unauthorized",
                "Invalid session",
                None,
            ),
            (
                ReviewResponsePhase::ForeignTenant,
                json!({"headers":{"X-Organization-ID":"foreign"}}),
                404,
                json!({"code":"canvas_review_not_found","message":"Canvas evidence correction review not found"}),
                "service_error",
                "Canvas evidence correction review not found",
                Some("canvas_review_not_found"),
            ),
            (
                ReviewResponsePhase::ConcurrentClaim,
                json!({}),
                409,
                json!({"code":"canvas_review_already_resolved","message":"Canvas evidence correction review is already claimed or resolved"}),
                "service_error",
                "Canvas evidence correction review is already claimed or resolved",
                Some("canvas_review_already_resolved"),
            ),
            (
                ReviewResponsePhase::DuplicateResolved,
                json!({}),
                409,
                json!({"code":"canvas_review_already_resolved","message":"Canvas evidence correction review is already resolved"}),
                "service_error",
                "Canvas evidence correction review is already resolved",
                Some("canvas_review_already_resolved"),
            ),
        ];
        for (phase, case, status, detail, error, description, code) in cases {
            let direct =
                json!({"status":status,"content_type":"application/json","body":{"detail":detail}});
            let public = GatewayExpectations.response(phase, &case, &direct);
            let expected = mip_expected(status, error, description, code);
            assert_eq!(public.status, status);
            assert_eq!(public.body, expected.body);
            assert_eq!(public.message_id, ReviewMessageIdPolicy::RequireUuid);
            let mut changed = direct.clone();
            changed["body"]["detail"] = json!("unreviewed");
            assert!(std::panic::catch_unwind(
                || GatewayExpectations.response(phase, &case, &changed)
            )
            .is_err());
        }
    }
}
