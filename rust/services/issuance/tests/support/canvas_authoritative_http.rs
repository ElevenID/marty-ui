//! Real HTTP authoritative-provider calls, reusing the OAuth suite's fixtures.
//! OAuth persistence/vault are in-memory; this is not whole-worker parity.
use super::{fixture, install_connected_token_fixture, MemoryRepository};
use async_trait::async_trait;
use axum::{
    body::Body,
    extract::State,
    http::{Request, Response, StatusCode},
    Router,
};
use chrono::Utc;
use marty_issuance_service::{
    canvas_lti_tool_signing::{CanvasLtiToolJwtSigner, CanvasLtiToolSigningError},
    canvas_provider_http::CanvasHttpClientPolicy,
    canvas_sync_processor::{
        CanvasAuthoritativeProvider, CanvasProviderReadError, CanvasSyncPlatformSnapshot,
        CanvasSyncResources,
    },
    canvas_sync_provider_http::HttpCanvasAuthoritativeProvider,
    canvas_sync_worker::{CanvasSyncTarget, CanvasSyncTargetType},
};
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

struct NoSigner;

#[async_trait]
impl CanvasLtiToolJwtSigner for NoSigner {
    async fn sign_jwt(&self, _: &Value) -> Result<String, CanvasLtiToolSigningError> {
        panic!("REST evidence must not invoke LTI signing")
    }
    async fn public_jwks(&self) -> Result<Value, CanvasLtiToolSigningError> {
        panic!("REST evidence must not resolve LTI keys")
    }
}

#[derive(Default)]
struct ServerState {
    status: AtomicU16,
    retry_after: Mutex<Option<String>>,
    requests: Mutex<Vec<(String, String, String)>>,
}

struct Server {
    origin: String,
    state: Arc<ServerState>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(State(state): State<Arc<ServerState>>, request: Request<Body>) -> Response<Body> {
    let uri = request.uri().to_string();
    state.requests.lock().unwrap().push((
        uri.clone(),
        request
            .headers()
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        request
            .headers()
            .get("accept")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
    ));
    let status = state.status.load(Ordering::SeqCst);
    if status != 0 {
        return Response::builder()
            .status(StatusCode::from_u16(status).unwrap())
            .header(
                "retry-after",
                state.retry_after.lock().unwrap().as_deref().unwrap_or("37"),
            )
            .header("www-authenticate", "Bearer")
            .body(Body::from("{}"))
            .unwrap();
    }
    let path = request.uri().path();
    let mut response = Response::builder().header("content-type", "application/json");
    let payload = if path.ends_with("/users") {
        if request.uri().query().unwrap_or_default().contains("page=2") {
            json!([{"id":8,"name":"SYNTHETIC_NO_RETENTION","email":"synthetic@example.invalid"}])
        } else {
            let host = request.headers().get("host").unwrap().to_str().unwrap();
            response = response.header(
                "link",
                format!("<http://{host}{path}?page=2>; rel=\"next\""),
            );
            json!([{"id":7,"name":"SYNTHETIC_NO_RETENTION","email":"synthetic@example.invalid"}])
        }
    } else if path.ends_with("/bulk_user_progress") {
        json!([{"user_id":7,"requirement_count":2,"requirement_completed_count":2,"name":"SYNTHETIC_NO_RETENTION"}])
    } else if path.ends_with("/progress") {
        json!({"requirement_count":2,"requirement_completed_count":2,"updated_at":"2026-09-01T00:00:00Z"})
    } else if path.contains("/modules/") {
        json!({"id":3,"state":"completed","completed_at":"2026-09-01T00:00:00Z"})
    } else if path.contains("/submissions/") {
        json!({"id":11,"assignment_id":9,"score":90,"workflow_state":"graded","assignment":{"points_possible":100},"updated_at":"2026-09-01T00:00:00Z","name":"SYNTHETIC_NO_RETENTION"})
    } else {
        panic!("Unexpected synthetic Canvas path: {path}")
    };
    response.body(Body::from(payload.to_string())).unwrap()
}

async fn setup() -> (
    Server,
    HttpCanvasAuthoritativeProvider,
    CanvasSyncResources,
    MemoryRepository,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let state = Arc::new(ServerState::default());
    let app = Router::new().fallback(serve).with_state(state.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let server = Server {
        origin: origin.clone(),
        state,
        task,
    };
    let (oauth, repository, vault, _) = fixture();
    install_connected_token_fixture(&repository, &vault, None);
    {
        let mut state = repository.state.lock().unwrap();
        state
            .platforms
            .get_mut("platform-1")
            .unwrap()
            .canvas_base_url = Some(origin.clone());
        state
            .connections
            .get_mut(&("org-1".into(), "platform-1".into()))
            .unwrap()
            .canvas_base_url = origin.clone();
    }
    let provider = HttpCanvasAuthoritativeProvider::new(
        Arc::new(oauth),
        "management-key",
        Arc::new(NoSigner),
        CanvasHttpClientPolicy {
            timeout: Duration::from_secs(5),
            private_origin_allowlist: vec![origin.clone()],
            allow_private_networks: false,
            allow_http_localhost: true,
        },
        Vec::new(),
    );
    let resources = CanvasSyncResources {
        platform: CanvasSyncPlatformSnapshot {
            id: "platform-1".into(),
            organization_id: "org-1".into(),
            canvas_base_url: origin,
            lti_trust_profile: String::new(),
            lti_issuer: String::new(),
            lti_client_id: String::new(),
            lti_deployment_id: "deployment".into(),
            lti_auth_token_url: String::new(),
            config_version: 1,
        },
        binding: json!({"id":"binding-1","config_version":1})
            .as_object()
            .unwrap()
            .clone(),
        application: None,
        application_template: None,
    };
    (server, provider, resources, repository)
}

fn requirement(kind: &str) -> Value {
    json!({"requirement_id":kind,"source":"canvas_rest","fact_type":format!("canvas.{kind}"),
        "scope":{"course_id":"42","activity_id":"9","module_id":"3"},"required":true})
}

fn target() -> CanvasSyncTarget {
    CanvasSyncTarget {
        id: "target".into(),
        organization_id: "org-1".into(),
        platform_id: "platform-1".into(),
        binding_id: "binding-1".into(),
        target_type: CanvasSyncTargetType::BackgroundRoster,
        logical_key: "roster".into(),
        application_id: None,
        candidate_id: None,
        enabled: true,
        schedule_seconds: 900,
        config_version: 1,
        metadata: Default::default(),
        created_at: Utc::now(),
    }
}

#[tokio::test]
async fn actual_rest_provider_reads_all_four_fact_types_with_typed_paths() {
    let (server, provider, resources, _) = setup().await;
    for kind in [
        "assignment_score",
        "quiz_score",
        "module_completion",
        "course_completion",
    ] {
        let observation = provider
            .read_requirement(&resources, &requirement(kind), Some("7"), None)
            .await
            .unwrap();
        assert_eq!(observation.verification_method, "CANVAS_OAUTH_API_READ");
        assert_eq!(observation.assertion["completed"], true);
        if kind.ends_with("_score") {
            assert_eq!(observation.assertion["score_percent"], 90.0);
        }
        assert_eq!(
            observation.effective_at.unwrap().to_rfc3339(),
            "2026-09-01T00:00:00+00:00"
        );
        assert!(!serde_json::to_string(&observation.source_payload)
            .unwrap()
            .contains("SYNTHETIC_NO_RETENTION"));
    }
    let requests = server.state.requests.lock().unwrap();
    assert_eq!(
        requests.iter().map(|r| r.0.as_str()).collect::<Vec<_>>(),
        [
            "/api/v1/courses/42/assignments/9/submissions/7?include%5B%5D=assignment",
            "/api/v1/courses/42/assignments/9/submissions/7?include%5B%5D=assignment",
            "/api/v1/courses/42/modules/3?student_id=7",
            "/api/v1/courses/42/users/7/progress",
        ]
    );
    assert!(requests
        .iter()
        .all(|r| r.1 == "Bearer current-access-token" && r.2 == "application/json"));
    assert!(server.origin.starts_with("http://127.0.0.1:"));
}

#[tokio::test]
async fn actual_rest_roster_pages_and_preloads_verified_negative_missing_progress() {
    let (server, provider, resources, _) = setup().await;
    let roster = provider
        .roster(
            &target(),
            &resources,
            &[requirement("course_completion")],
            10,
        )
        .await
        .unwrap();
    assert_eq!(roster.canvas_user_ids, ["7", "8"]);
    assert!(roster.lti_subjects.is_empty());
    assert_eq!(roster.preloaded_observations.len(), 2);
    for (user, complete) in [("7", true), ("8", false)] {
        let observation =
            &roster.preloaded_observations[&("course_completion".into(), user.into())];
        assert_eq!(observation.assertion["completed"], complete);
        assert!(!serde_json::to_string(&observation.source_payload)
            .unwrap()
            .contains("SYNTHETIC_NO_RETENTION"));
    }
    assert_eq!(server.state.requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn actual_rest_provider_preserves_frozen_oversized_retry_after() {
    let (server, provider, resources, _) = setup().await;
    let scenarios: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-retry-after-scenarios.json"
    ))
    .unwrap();
    let case = scenarios["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "huge_integer")
        .unwrap();
    *server.state.retry_after.lock().unwrap() =
        Some(case["headers"]["Retry-After"].as_str().unwrap().into());
    server.state.status.store(429, Ordering::SeqCst);
    match provider
        .read_requirement(
            &resources,
            &requirement("assignment_score"),
            Some("7"),
            None,
        )
        .await
    {
        Err(CanvasProviderReadError::RateLimited {
            retry_after_seconds,
        }) => {
            assert_eq!(Some(retry_after_seconds), case["delay_bounds"][0].as_u64());
        }
        _ => panic!("oversized Retry-After must retain its rate-limit category"),
    }
    let requests = server.state.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].1, "Bearer current-access-token");
    assert_eq!(requests[0].2, "application/json");
}

#[tokio::test]
async fn actual_rest_provider_preserves_rate_limit_and_reauthorization_categories() {
    let (server, provider, resources, repository) = setup().await;
    server.state.status.store(429, Ordering::SeqCst);
    assert!(matches!(
        provider
            .read_requirement(
                &resources,
                &requirement("assignment_score"),
                Some("7"),
                None
            )
            .await,
        Err(CanvasProviderReadError::RateLimited {
            retry_after_seconds: 37
        })
    ));
    server.state.status.store(401, Ordering::SeqCst);
    assert!(matches!(
        provider
            .read_requirement(
                &resources,
                &requirement("assignment_score"),
                Some("7"),
                None
            )
            .await,
        Err(CanvasProviderReadError::ReauthorizationRequired)
    ));
    assert_eq!(
        repository.state.lock().unwrap().connections[&("org-1".into(), "platform-1".into())].status,
        "reauthorization_required"
    );
    let before = server.state.requests.lock().unwrap().len();
    assert!(matches!(
        provider
            .read_requirement(
                &resources,
                &requirement("assignment_score"),
                Some("7"),
                None
            )
            .await,
        Err(CanvasProviderReadError::ReauthorizationRequired)
    ));
    assert_eq!(server.state.requests.lock().unwrap().len(), before);
}
