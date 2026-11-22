//! Transport fixtures establish only the explicit trusted-forwarder boundary.
//! Actual receipt construction and database/current-owner qualification are
//! exercised by PostgreSQL service and delegated-use host acceptance tests.
use super::*;
use axum::{
    body::Body,
    http::{HeaderValue, Request},
};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use tower::ServiceExt;
use uuid::Uuid;

const ORG: &str = "9d23ceca-cd3f-4ef9-955b-cdca59348865";
const ACTOR: &str = "urn:example:receipt-reader";
const TOKEN: &str = "synthetic-protected-receipt-service-hop-token";

#[test]
fn caller_receipt_router_cannot_select_internal_service_forwarding() {
    let application = Arc::new(Application {
        calls: AtomicUsize::new(0),
        requests: Mutex::new(Vec::new()),
        actors: Mutex::new(Vec::new()),
        error: DelegationUseCommandError::AccessDenied,
    });
    let authenticator = Arc::new(
        DelegationUseHttpAuthenticator::trusted_forwarder(TOKEN.into(), ORG.parse().unwrap())
            .unwrap(),
    );
    assert!(delegated_use_public_receipt_router(
        DelegationUseReceiptHttpState::with_authenticator(application.clone(), authenticator)
    )
    .is_err());
    assert_eq!(application.calls.load(Ordering::SeqCst), 0);
}

struct Application {
    calls: AtomicUsize,
    requests: Mutex<Vec<Vec<u8>>>,
    actors: Mutex<Vec<crate::Principal>>,
    error: DelegationUseCommandError,
}
#[async_trait]
impl DelegationUseReceiptHttpApplication for Application {
    async fn recover_receipt(
        &self,
        context: &AuthenticatedDelegationUseContext,
        raw: &[u8],
    ) -> Result<RecoveredDelegatedUseReceipt, DelegationUseCommandError> {
        assert_eq!(context.caller().organization_id().to_string(), ORG);
        assert_eq!(context.caller().actor().id, ACTOR);
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests.lock().unwrap().push(raw.to_vec());
        self.actors
            .lock()
            .unwrap()
            .push(context.caller().actor().clone());
        Err(self.error)
    }
}
fn setup(error: DelegationUseCommandError) -> (Router, Arc<Application>) {
    let application = Arc::new(Application {
        calls: AtomicUsize::new(0),
        requests: Mutex::new(Vec::new()),
        actors: Mutex::new(Vec::new()),
        error,
    });
    let authenticator = Arc::new(
        DelegationUseHttpAuthenticator::trusted_forwarder(TOKEN.into(), ORG.parse().unwrap())
            .unwrap(),
    );
    (
        delegated_use_receipt_router(DelegationUseReceiptHttpState::with_authenticator(
            application.clone(),
            authenticator,
        )),
        application,
    )
}
fn recovery() -> Vec<u8> {
    serde_json::to_vec_pretty(&json!({"profile":crate::DELEGATION_COMMAND_PROFILE,
        "command":"RECOVER_RESULT","original_command_id":Uuid::new_v4(),
        "expected_command_digest":format!("sha256:{}","a".repeat(64))}))
    .unwrap()
}
fn request(body: &[u8]) -> Request<Body> {
    let now = Utc::now();
    Request::builder()
        .method("POST")
        .uri(format!(
            "/internal/v1/organizations/{ORG}/delegated-use/receipts/recover"
        ))
        .header("content-type", "application/json")
        .header("x-service-token", TOKEN)
        .header("x-marty-use-organization-id", ORG)
        .header("x-marty-use-principal-type", "SERVICE_ACCOUNT")
        .header("x-marty-use-principal-id", ACTOR)
        .header(
            "x-marty-use-observed-at",
            now.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        )
        .header(
            "x-marty-use-valid-until",
            (now + chrono::Duration::seconds(25))
                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        )
        .body(Body::from(body.to_vec()))
        .unwrap()
}
fn assert_private(response: &axum::response::Response) {
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
}

#[tokio::test]
async fn exact_recovery_bytes_and_full_typed_actor_dispatch_once() {
    for principal_type in ["SERVICE_ACCOUNT", "MACHINE_IDENTITY"] {
        let (router, application) = setup(DelegationUseCommandError::PreparationPending);
        let raw = recovery();
        let mut req = request(&raw);
        req.headers_mut().insert(
            "x-marty-use-principal-type",
            HeaderValue::from_static(principal_type),
        );
        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_private(&response);
        assert_eq!(
            serde_json::from_slice::<Value>(&to_bytes(response.into_body(), 1024).await.unwrap())
                .unwrap(),
            json!({"detail":"delegation_use_preparation_pending"})
        );
        assert_eq!(application.calls.load(Ordering::SeqCst), 1);
        assert_eq!(application.requests.lock().unwrap().as_slice(), &[raw]);
        assert_eq!(
            serde_json::to_value(&application.actors.lock().unwrap()[0]).unwrap()["type"],
            principal_type
        );
    }
}

#[tokio::test]
async fn anonymous_foreign_human_ambiguous_and_expired_callers_never_dispatch() {
    for case in 0..10 {
        let (router, application) = setup(DelegationUseCommandError::Unavailable);
        let mut req = request(&recovery());
        match case {
            0 => {
                req.headers_mut().remove("x-service-token");
            }
            1 => {
                req.headers_mut()
                    .append("x-service-token", HeaderValue::from_static(TOKEN));
            }
            2 => {
                req.headers_mut()
                    .insert("x-service-token", HeaderValue::from_static("wrong"));
            }
            3 => {
                req.headers_mut().insert(
                    "x-marty-use-organization-id",
                    HeaderValue::from_str(&Uuid::new_v4().to_string()).unwrap(),
                );
            }
            4 => {
                req.headers_mut().insert(
                    "x-marty-use-principal-type",
                    HeaderValue::from_static("USER"),
                );
            }
            5 => {
                req.headers_mut()
                    .append("x-marty-use-principal-id", HeaderValue::from_static(ACTOR));
            }
            6 => {
                req.headers_mut().insert(
                    "x-marty-use-valid-until",
                    HeaderValue::from_static("2020-01-01T00:00:00Z"),
                );
            }
            7 => {
                req.headers_mut().insert(
                    "authorization",
                    HeaderValue::from_static("Bearer unrelated"),
                );
            }
            8 => {
                req.headers_mut()
                    .insert("cookie", HeaderValue::from_static("session=unrelated"));
            }
            9 => {
                req.headers_mut()
                    .insert("x-user-id", HeaderValue::from_static(ORG));
            }
            _ => unreachable!(),
        }
        let response = router.oneshot(req).await.unwrap();
        assert!(
            matches!(
                response.status(),
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::BAD_REQUEST
            ),
            "case {case}"
        );
        assert_private(&response);
        assert_eq!(application.calls.load(Ordering::SeqCst), 0, "case {case}");
    }
}

#[tokio::test]
async fn recovery_only_wire_has_no_query_or_mutation_or_discovery_mode() {
    let valid = String::from_utf8(recovery()).unwrap();
    let finalization = json!({"profile":crate::DELEGATION_COMMAND_PROFILE,"command":"FINALIZE_USE",
        "command_id":Uuid::new_v4(),"challenge_id":Uuid::new_v4(),"proof_submission_id":Uuid::new_v4()});
    let cases = [
        valid.replacen('{', "{\"command\":\"RECOVER_RESULT\",", 1),
        valid.replacen('{', "{\"receipt_ref\":\"urn:example:guess\",", 1),
        valid.replace("RECOVER_RESULT", "LIST_RECEIPTS"),
        serde_json::to_string(&finalization).unwrap(),
        "[]".into(),
        format!("{valid}{{}}"),
    ];
    for body in cases {
        let (router, application) = setup(DelegationUseCommandError::Unavailable);
        let response = router.oneshot(request(body.as_bytes())).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_private(&response);
        assert_eq!(application.calls.load(Ordering::SeqCst), 0);
    }
    for case in 0..6 {
        let (router, application) = setup(DelegationUseCommandError::Unavailable);
        let mut req = request(valid.as_bytes());
        match case {
            0 => {
                *req.uri_mut() = format!("{}?receipt_ref=urn:example:guess", req.uri())
                    .parse()
                    .unwrap();
            }
            1 => {
                req.headers_mut()
                    .insert("content-type", HeaderValue::from_static("text/plain"));
            }
            2 => {
                req.headers_mut()
                    .append("content-type", HeaderValue::from_static("application/json"));
            }
            3 => {
                *req.body_mut() = Body::from(vec![b' '; crate::wire::MAX_GRANT_WIRE_BYTES + 1]);
            }
            4 => {
                *req.method_mut() = axum::http::Method::GET;
            }
            5 => {
                *req.uri_mut() = format!("/internal/v1/organizations/{ORG}/delegated-use/receipts")
                    .parse()
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let response = router.oneshot(req).await.unwrap();
        assert!(response.status().is_client_error(), "case {case}");
        assert_private(&response);
        assert_eq!(application.calls.load(Ordering::SeqCst), 0, "case {case}");
    }
}

#[tokio::test]
async fn receipt_route_is_not_added_to_the_existing_command_router() {
    struct Commands;
    #[async_trait]
    impl crate::use_http::DelegationUseHttpApplication for Commands {
        async fn execute(
            &self,
            _: &AuthenticatedDelegationUseContext,
            _: &[u8],
        ) -> Result<crate::DelegationUseCommandResponse, DelegationUseCommandError> {
            panic!("receipt routing must never widen the command application");
        }
    }
    let state = crate::use_http::DelegationUseHttpState::new(
        Arc::new(Commands),
        TOKEN.into(),
        ORG.parse().unwrap(),
    )
    .unwrap();
    let response = crate::use_http::delegated_use_command_router(state)
        .oneshot(request(&recovery()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_private(&response);
}
