use super::*;
use axum::{body::Body, http::Request};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use tower::ServiceExt;

const ORG: &str = "9d23ceca-cd3f-4ef9-955b-cdca59348865";
const ACTOR: &str = "urn:example:authenticated-agent";
const TOKEN: &str = "synthetic-delegated-use-service-hop-token";

fn caller_authenticator() -> Arc<DelegationUseHttpAuthenticator> {
    Arc::new(
        DelegationUseHttpAuthenticator::mutual_tls(
            ORG.parse().unwrap(),
            crate::use_mtls::DelegatedUseWorkloadBindings::new(vec![
                crate::use_mtls::DelegatedUseWorkloadBinding::new(
                    "spiffe://caller.example/machine/one".into(),
                    format!("sha256:{}", "a".repeat(64)),
                    ACTOR.into(),
                )
                .unwrap(),
            ])
            .unwrap(),
        )
        .unwrap(),
    )
}

fn caller_application() -> Arc<CountingApplication> {
    Arc::new(CountingApplication {
        calls: AtomicUsize::new(0),
        requests: Mutex::new(Vec::new()),
        actors: Mutex::new(Vec::new()),
        error: DelegationUseCommandError::AccessDenied,
    })
}

#[tokio::test]
async fn caller_commands_reject_forwarding_auth_and_require_authenticated_peer() {
    let application = caller_application();
    let forwarded =
        DelegationUseHttpState::new(application.clone(), TOKEN.into(), ORG.parse().unwrap())
            .unwrap();
    assert!(delegated_use_public_command_router(forwarded, "https://caller.example").is_err());
    let state =
        DelegationUseHttpState::with_authenticator(application.clone(), caller_authenticator());
    let router = delegated_use_public_command_router(state, "https://caller.example").unwrap();
    for forwarded in [false, true] {
        let mut req = Request::builder()
            .method("POST")
            .uri(format!("/v1/organizations/{ORG}/delegated-use-commands"))
            .header("content-type", "application/json")
            .body(Body::from(recover()))
            .unwrap();
        if forwarded {
            req.headers_mut()
                .insert("x-service-token", HeaderValue::from_static(TOKEN));
        }
        let response = router.clone().oneshot(req).await.unwrap();
        assert_eq!(
            response.status(),
            if forwarded {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::UNAUTHORIZED
            }
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(!response.headers().contains_key(header::LINK));
    }
    assert_eq!(application.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn caller_request_origin_cannot_redirect_or_inject_link_metadata() {
    for origin in [
        "http://caller.example",
        "https://caller.example/",
        "https://caller.example/prefix",
        "https://caller.example?request=elsewhere",
        "https://caller.example#fragment",
        "https://user@caller.example",
        "https://CALLER.example",
        "https://caller.example:443",
        "https://caller.example\r\nLink: <https://foreign.example>",
    ] {
        let state = DelegationUseHttpState::with_authenticator(
            caller_application(),
            caller_authenticator(),
        );
        assert!(delegated_use_public_command_router(state, origin).is_err());
    }
}

#[tokio::test]
async fn caller_request_link_keeps_retained_response_document_unchanged() {
    let mut state =
        DelegationUseHttpState::with_authenticator(caller_application(), caller_authenticator());
    let challenge_id = Uuid::new_v4();
    let now = Utc::now();
    let mut retained = DelegationUseCommandResponse {
        profile: crate::DELEGATION_COMMAND_RESPONSE_PROFILE.into(),
        original_command_id: Uuid::new_v4(),
        command_digest: format!("sha256:{}", "b".repeat(64)),
        recovered: false,
        result: crate::DelegationUseCommandResult::Challenge {
            challenge_id,
            grant: crate::CommandGrantReference {
                id: Uuid::new_v4(),
                revision: 1,
                terms_digest: format!("sha256:{}", "c".repeat(64)),
            },
            operation: crate::DelegationUseOperation {
                action: "urn:example:action".into(),
                resource_id: "urn:example:resource".into(),
                audience: "urn:example:audience".into(),
                request_profile: "urn:example:operation:v1".into(),
                request_digest: format!("sha256:{}", "d".repeat(64)),
            },
            created_at: now,
            expires_at: now + chrono::Duration::seconds(60),
        },
    };
    assert!(!command_response(&state, retained.clone())
        .unwrap()
        .headers()
        .contains_key(header::LINK));
    state.public_request_origin = Some("https://caller.example".into());
    for recovered in [false, true] {
        retained.recovered = recovered;
        let original = serde_json::to_vec(&retained).unwrap();
        let response = command_response(&state, retained.clone()).unwrap();
        assert_eq!(response.headers()[header::LINK], format!(
            "<https://caller.example/v1/flows/instances/{challenge_id}/request>; rel=\"urn:marty:delegated-use:request\""
        ));
        assert_eq!(
            to_bytes(response.into_body(), 16_384)
                .await
                .unwrap()
                .as_ref(),
            original.as_slice()
        );
    }
    retained.result = crate::DelegationUseCommandResult::FinalUse {
        challenge_id,
        decision: "PERMIT".into(),
        receipt_ref: "urn:marty:delegated-receipt:fixture".into(),
        receipt_digest: format!("sha256:{}", "e".repeat(64)),
        recorded_at: now,
        authorization_expires_at: now + chrono::Duration::seconds(30),
        semantics: "EVIDENCE_ONLY".into(),
    };
    assert!(!command_response(&state, retained)
        .unwrap()
        .headers()
        .contains_key(header::LINK));
}

struct CountingApplication {
    calls: AtomicUsize,
    requests: Mutex<Vec<Vec<u8>>>,
    actors: Mutex<Vec<Principal>>,
    error: DelegationUseCommandError,
}
#[async_trait]
impl DelegationUseHttpApplication for CountingApplication {
    async fn execute(
        &self,
        context: &AuthenticatedDelegationUseContext,
        raw: &[u8],
    ) -> Result<DelegationUseCommandResponse, DelegationUseCommandError> {
        assert_eq!(context.caller().organization_id().to_string(), ORG);
        assert_eq!(context.caller().actor().id, ACTOR);
        assert!(context.valid_until() > context.observed_at());
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests.lock().unwrap().push(raw.to_vec());
        self.actors
            .lock()
            .unwrap()
            .push(context.caller().actor().clone());
        Err(self.error)
    }
}
fn setup(error: DelegationUseCommandError) -> (Router, Arc<CountingApplication>) {
    let application = Arc::new(CountingApplication {
        calls: AtomicUsize::new(0),
        requests: Mutex::new(Vec::new()),
        actors: Mutex::new(Vec::new()),
        error,
    });
    let state =
        DelegationUseHttpState::new(application.clone(), TOKEN.into(), ORG.parse().unwrap())
            .unwrap();
    (delegated_use_command_router(state), application)
}
fn recover() -> Vec<u8> {
    serde_json::to_vec_pretty(&json!({"profile":crate::DELEGATION_COMMAND_PROFILE,"command":"RECOVER_RESULT",
        "original_command_id":Uuid::new_v4(),"expected_command_digest":format!("sha256:{}","a".repeat(64))})).unwrap()
}
fn request(body: &[u8]) -> Request<Body> {
    let now = Utc::now();
    Request::builder()
        .method("POST")
        .uri(format!(
            "/internal/v1/organizations/{ORG}/delegated-use-commands"
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

#[tokio::test]
async fn authenticated_typed_context_preserves_original_bytes_and_never_retries() {
    for principal_type in ["SERVICE_ACCOUNT", "MACHINE_IDENTITY"] {
        let (router, application) = setup(DelegationUseCommandError::PreparationPending);
        let bytes = recover();
        let mut req = request(&bytes);
        req.headers_mut().insert(
            "x-marty-use-principal-type",
            HeaderValue::from_static(principal_type),
        );
        let response = router.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["pragma"], "no-cache");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            json!({"detail":"delegation_use_preparation_pending"})
        );
        assert_eq!(application.calls.load(Ordering::SeqCst), 1);
        assert_eq!(application.requests.lock().unwrap().as_slice(), &[bytes]);
        assert_eq!(
            serde_json::to_value(&application.actors.lock().unwrap()[0]).unwrap()["type"],
            principal_type
        );
    }
}

#[tokio::test]
async fn anonymous_duplicate_foreign_human_and_expired_metadata_never_dispatch() {
    for case in 0..19 {
        let (router, application) = setup(DelegationUseCommandError::ResultNotFound);
        let mut req = request(&recover());
        match case {
            0 => {
                req.headers_mut().remove("x-service-token");
            }
            1 => {
                req.headers_mut()
                    .insert("x-service-token", HeaderValue::from_static("wrong"));
            }
            2 => {
                req.headers_mut()
                    .append("x-service-token", HeaderValue::from_static(TOKEN));
            }
            3 => {
                req.headers_mut()
                    .append("x-marty-use-principal-id", HeaderValue::from_static(ACTOR));
            }
            4 => {
                req.headers_mut().insert(
                    "x-marty-use-organization-id",
                    HeaderValue::from_str(&Uuid::new_v4().to_string()).unwrap(),
                );
            }
            5 => {
                req.headers_mut().insert(
                    "x-marty-use-principal-type",
                    HeaderValue::from_static("USER"),
                );
            }
            6 => {
                req.headers_mut().insert(
                    "x-marty-use-principal-type",
                    HeaderValue::from_static("machine_identity"),
                );
            }
            7 => {
                req.headers_mut().insert(
                    "x-marty-use-principal-id",
                    HeaderValue::from_static("https://broken host.example"),
                );
            }
            8 => {
                req.headers_mut().insert(
                    "authorization",
                    HeaderValue::from_static("Bearer caller-token"),
                );
            }
            9 => {
                req.headers_mut()
                    .insert("cookie", HeaderValue::from_static("session=caller-session"));
            }
            10 => {
                req.headers_mut()
                    .insert("x-api-key-id", HeaderValue::from_static("caller-key"));
            }
            11 => {
                req.headers_mut()
                    .insert("x-marty-command-user-id", HeaderValue::from_static(ORG));
            }
            12 => {
                req.headers_mut().insert(
                    "x-marty-use-valid-until",
                    HeaderValue::from_static("2020-01-01T00:00:00Z"),
                );
            }
            13 => {
                req.headers_mut().insert(
                    "x-marty-use-valid-until",
                    HeaderValue::from_str(
                        &(Utc::now() + chrono::Duration::hours(1))
                            .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
                    )
                    .unwrap(),
                );
            }
            14 => {
                req.headers_mut().insert(
                    "x-marty-use-observed-at",
                    HeaderValue::from_str(
                        &(Utc::now() + chrono::Duration::seconds(5))
                            .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
                    )
                    .unwrap(),
                );
            }
            15 => {
                req.headers_mut().append(
                    "x-marty-use-observed-at",
                    HeaderValue::from_static("2020-01-01T00:00:00Z"),
                );
            }
            16 => {
                req.headers_mut().insert(
                    "x-marty-use-valid-until",
                    HeaderValue::from_static("2026-11-21T12:00:00+00:00"),
                );
            }
            17 => {
                *req.uri_mut() = format!(
                    "/internal/v1/organizations/{}/delegated-use-commands",
                    Uuid::new_v4()
                )
                .parse()
                .unwrap();
            }
            18 => {
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
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(application.calls.load(Ordering::SeqCst), 0, "case {case}");
    }
}

#[tokio::test]
async fn closed_command_wire_and_transport_limits_fail_before_dispatch() {
    let valid = String::from_utf8(recover()).unwrap();
    let malformed = [
        valid.replacen('{', "{\"command\":\"RECOVER_RESULT\",", 1),
        valid.replacen('{', "{\"nonce\":\"caller-authored\",", 1),
        valid.replace("RECOVER_RESULT", "CREATE_GRANT"),
        valid.replacen('{', "{\"verified\":true,", 1),
        "null".into(),
        "[]".into(),
    ];
    for body in malformed {
        let (router, application) = setup(DelegationUseCommandError::ResultNotFound);
        let response = router.oneshot(request(body.as_bytes())).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(application.calls.load(Ordering::SeqCst), 0);
    }
    for case in 0..4 {
        let (router, application) = setup(DelegationUseCommandError::ResultNotFound);
        let mut req = request(&recover());
        let expected = match case {
            0 => {
                *req.uri_mut() =
                    format!("/internal/v1/organizations/{ORG}/delegated-use-commands?actor=other")
                        .parse()
                        .unwrap();
                StatusCode::BAD_REQUEST
            }
            1 => {
                req.headers_mut()
                    .insert("content-type", HeaderValue::from_static("text/plain"));
                StatusCode::UNSUPPORTED_MEDIA_TYPE
            }
            2 => {
                req.headers_mut()
                    .append("content-type", HeaderValue::from_static("application/json"));
                StatusCode::BAD_REQUEST
            }
            3 => {
                *req.body_mut() = Body::from(vec![b' '; crate::wire::MAX_GRANT_WIRE_BYTES + 1]);
                StatusCode::PAYLOAD_TOO_LARGE
            }
            _ => unreachable!(),
        };
        assert_eq!(router.oneshot(req).await.unwrap().status(), expected);
        assert_eq!(application.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn authentication_expiring_during_actual_http_body_read_never_dispatches() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (router, application) = setup(DelegationUseCommandError::ResultNotFound);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    let bytes = recover();
    let now = Utc::now();
    let until = now + chrono::Duration::milliseconds(200);
    let headers=format!("POST /internal/v1/organizations/{ORG}/delegated-use-commands HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\nx-service-token: {TOKEN}\r\nx-marty-use-organization-id: {ORG}\r\nx-marty-use-principal-type: SERVICE_ACCOUNT\r\nx-marty-use-principal-id: {ACTOR}\r\nx-marty-use-observed-at: {}\r\nx-marty-use-valid-until: {}\r\n\r\n",bytes.len(),now.to_rfc3339_opts(chrono::SecondsFormat::AutoSi,true),until.to_rfc3339_opts(chrono::SecondsFormat::AutoSi,true));
    socket.write_all(headers.as_bytes()).await.unwrap();
    socket.write_all(&bytes[..1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    socket.write_all(&bytes[1..]).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), socket.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    server.abort();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert!(response
        .to_ascii_lowercase()
        .contains("cache-control: no-store"));
    assert_eq!(application.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn configuration_has_no_anonymous_or_weak_credential_mode() {
    let (_, application) = setup(DelegationUseCommandError::ResultNotFound);
    for token in [
        "".to_owned(),
        "short".into(),
        format!("{}\n", TOKEN),
        "x".repeat(1025),
    ] {
        assert!(
            DelegationUseHttpState::new(application.clone(), token, ORG.parse().unwrap()).is_err()
        );
    }
    assert!(DelegationUseHttpState::new(application, TOKEN.into(), Uuid::nil()).is_err());
}
