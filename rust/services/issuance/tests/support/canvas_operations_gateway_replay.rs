//! Candidate-only gateway -> real HTTP -> packaged issuance -> owned PostgreSQL.
//! Production coverage is not changed. Identity/membership are controlled ports;
//! persistence, gateway middleware/proxy, HTTP transport and issuance are real.
//! Suspend/revoke/publication/recovery through the gateway remain separate gates.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use marty_gateway::{
    authorization::{OrganizationMembership, OrganizationMembershipProvider},
    contract::GatewayContract,
    discovery::ReleaseIdentity,
    middleware::{ApiKeyIdentity, GatewayIdentityProvider, GatewayRateLimiter, SessionIdentity},
    registry::StaticServiceRegistry,
    runtime::{
        gateway_router, EventStreamProvider, EventStreamSubscription, GatewayDomainEventStream,
        GatewayRuntimeState, ReadinessProvider, ReadinessServiceStatus, ResourceOwnerContext,
        ResourceOwnerProvider,
    },
    transport::ReqwestUpstream,
};
use mmf_platform::{
    GatewayProxy, GatewayRequest, GatewayResponse, HttpMethod, InMemoryIdempotencyStore,
    PlatformError, ProxyConfig, RouteTable, ServiceInstance, UpstreamClient,
};
use mmf_security::{InMemoryRateLimiter, SecurityError};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

use super::{
    canvas_operations_read_replay::{fixtures, generated_ids, insert_review, seed, timestamps},
    issuance_process::{
        bounded_http_client, isolated_smoke_command, reserve_port, wait_for_health_with_client,
        ChildGuard,
    },
};

const LIMIT: usize = 1024 * 1024;
const ORIGIN: &str = "https://wallet.example";
const NON_MANUAL_CASES: [&str; 7] = [
    "jobs_list",
    "candidates_list",
    "reviews_list",
    "job_get",
    "retry_dead_letter",
    "resolve_dead_letter",
    "enqueue",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Routing {
    PublishedLegacy,
    CandidateNative,
}

fn operation_routes() -> BTreeSet<(HttpMethod, String)> {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/issuance-canvas-operations.json"
    ))
    .unwrap();
    let routes: BTreeSet<_> = contract["routes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|route| {
            let method = match route["method"].as_str().unwrap() {
                "GET" => HttpMethod::Get,
                "POST" => HttpMethod::Post,
                _ => panic!("closed operation method"),
            };
            (
                method,
                format!(
                    "{}{}",
                    contract["route_prefix"].as_str().unwrap(),
                    route["path"].as_str().unwrap()
                ),
            )
        })
        .collect();
    assert_eq!(routes.len(), 8);
    routes
}

fn select_routes(original: RouteTable, routing: Routing) -> RouteTable {
    let expected = operation_routes();
    let mut found = BTreeSet::new();
    let mut selected = RouteTable::default();
    for route in original.routes() {
        let mut candidate = route.clone();
        for method in &route.methods {
            let key = (*method, route.pattern.clone());
            if expected.contains(&key) {
                assert!(found.insert(key), "duplicate operation route");
                assert_eq!(
                    route.upstream_service, "issuance",
                    "published coverage changed"
                );
                assert_eq!(route.methods.len(), 1);
                assert!(route.auth_required);
                if routing == Routing::CandidateNative {
                    candidate.upstream_service = "issuance-native".into();
                }
            }
        }
        selected.add(candidate).unwrap();
    }
    assert_eq!(found, expected);
    assert_eq!(selected.routes().len(), original.routes().len());
    let mut differences = 0;
    for (before, after) in original.routes().iter().zip(selected.routes()) {
        let mut restored = after.clone();
        if before != after {
            differences += 1;
        }
        restored
            .upstream_service
            .clone_from(&before.upstream_service);
        assert_eq!(
            &restored, before,
            "candidate changed non-selection route policy"
        );
    }
    assert_eq!(
        differences,
        if routing == Routing::CandidateNative {
            8
        } else {
            0
        }
    );
    selected
}

struct Identities;

#[async_trait]
impl GatewayIdentityProvider for Identities {
    async fn validate_session(
        &self,
        session: &str,
    ) -> Result<Option<SessionIdentity>, SecurityError> {
        Ok(
            matches!(session, "actor-primary" | "actor-denied").then(|| SessionIdentity {
                user_id: session.into(),
                organization_id: Some("org-review".into()),
                ..SessionIdentity::default()
            }),
        )
    }

    async fn validate_api_key(&self, key: &str) -> Result<Option<ApiKeyIdentity>, SecurityError> {
        Ok(matches!(
            key,
            "actor-key" | "actor-key-no-scope" | "actor-key-wrong-org"
        )
        .then(|| ApiKeyIdentity {
            api_key_id: "trusted-key-id".into(),
            organization_id: Some(
                if key == "actor-key-wrong-org" {
                    "org-other"
                } else {
                    "org-review"
                }
                .into(),
            ),
            key_prefix: Some("synthetic-prefix".into()),
            scopes: if key == "actor-key-no-scope" {
                vec![]
            } else {
                vec!["integrations:read".into(), "integrations:write".into()]
            },
        }))
    }
}

#[async_trait]
impl OrganizationMembershipProvider for Identities {
    async fn get_membership(
        &self,
        user: &str,
        organization: &str,
    ) -> Result<Option<OrganizationMembership>, SecurityError> {
        Ok(
            (user == "actor-primary" && organization == "org-review").then(|| {
                OrganizationMembership {
                    user_id: user.into(),
                    organization_id: organization.into(),
                    status: "active".into(),
                    role_names: BTreeSet::new(),
                    is_owner: false,
                    permissions: [
                        "integration-connector:view".into(),
                        "integration-connector:edit".into(),
                    ]
                    .into(),
                }
            }),
        )
    }
}

struct UnusedProviders;

#[async_trait]
impl ResourceOwnerProvider for UnusedProviders {
    async fn resolve_organization(
        &self,
        _: &str,
        _: &str,
        _: &ResourceOwnerContext,
    ) -> Result<Option<String>, SecurityError> {
        panic!("operation unexpectedly invoked resource-owner service")
    }
}

#[async_trait]
impl ReadinessProvider for UnusedProviders {
    async fn check_services(&self, _: &[String]) -> BTreeMap<String, ReadinessServiceStatus> {
        panic!("operation unexpectedly invoked readiness service")
    }
    fn all_services(&self) -> Vec<String> {
        vec![]
    }
}

#[async_trait]
impl EventStreamProvider for UnusedProviders {
    async fn subscribe(
        &self,
        _: EventStreamSubscription,
    ) -> Result<GatewayDomainEventStream, SecurityError> {
        panic!("operation unexpectedly subscribed to event stream")
    }
}

struct CountedHttp {
    http: ReqwestUpstream,
    native: AtomicUsize,
    legacy: AtomicUsize,
}

#[async_trait]
impl UpstreamClient for CountedHttp {
    async fn send(
        &self,
        instance: &ServiceInstance,
        request: GatewayRequest,
    ) -> Result<GatewayResponse, PlatformError> {
        let counter = match instance.service_name.as_str() {
            "issuance-native" => &self.native,
            "issuance" => &self.legacy,
            _ => panic!("unregistered operation upstream"),
        };
        counter.fetch_add(1, Ordering::SeqCst);
        assert!(request.header("x-authenticated-user-id").is_none());
        assert!(
            request.headers.values().all(|v| !v.contains("forged-")),
            "untrusted actor survived gateway"
        );
        assert_eq!(
            request.header("x-api-key"),
            Some("synthetic-operations-key")
        );
        self.http.send(instance, request).await
    }
}

impl CountedHttp {
    fn counts(&self) -> (usize, usize) {
        (
            self.native.load(Ordering::SeqCst),
            self.legacy.load(Ordering::SeqCst),
        )
    }
}

fn router(native_port: u16, legacy_port: u16, routing: Routing) -> (Router, Arc<CountedHttp>) {
    assert_ne!(
        native_port, legacy_port,
        "legacy trap must not alias native service"
    );
    let contract = GatewayContract::load().unwrap();
    let routes = select_routes(contract.runtime_route_table().unwrap(), routing);
    let proxy_routes = select_routes(contract.proxy_route_table().unwrap(), routing);
    let registry = StaticServiceRegistry::from_urls(&BTreeMap::from([
        ("issuance".into(), format!("http://127.0.0.1:{legacy_port}")),
        (
            "issuance-native".into(),
            format!("http://127.0.0.1:{native_port}"),
        ),
    ]))
    .unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let counted = Arc::new(CountedHttp {
        http: ReqwestUpstream::with_client(LIMIT, client).unwrap(),
        native: AtomicUsize::new(0),
        legacy: AtomicUsize::new(0),
    });
    let proxy = GatewayProxy::new(
        proxy_routes,
        Arc::new(registry),
        counted.clone(),
        ProxyConfig::default(),
    )
    .unwrap();
    let state = GatewayRuntimeState::new(
        routes,
        proxy,
        Arc::new(Identities),
        Arc::new(Identities),
        Arc::new(UnusedProviders),
        Arc::new(UnusedProviders),
        Arc::new(UnusedProviders),
        vec![],
        GatewayRateLimiter::new(Arc::new(InMemoryRateLimiter::default()), 120).unwrap(),
        Arc::new(InMemoryIdempotencyStore::new(60_000, 5_000).unwrap()),
        [ORIGIN.into()],
        "https://issuer.example",
        "https://issuer.example",
        "issuer.example",
        None,
        "synthetic-signing-key",
        "synthetic-operations-key",
        ReleaseIdentity::default(),
    )
    .unwrap()
    .with_service_token(Some("s".repeat(32)))
    .unwrap();
    (gateway_router(Arc::new(state)), counted)
}

struct LegacyTrap {
    port: u16,
    calls: Arc<AtomicUsize>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}

fn legacy_trap_body() -> Value {
    // Complete MIP errors pass through the actual proxy normalizer unchanged.
    json!({"error":"owned_legacy_trap", "error_description":"Owned legacy selection control",
        "message_id":"11111111-1111-4111-8111-111111111111"})
}

impl LegacyTrap {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let app = Router::new().fallback(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            async { (StatusCode::IM_A_TEAPOT, axum::Json(legacy_trap_body())) }
        });
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
        });
        Self {
            port,
            calls,
            stop: Some(stop),
            task: Some(task),
        }
    }

    async fn close(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(3), self.task.as_mut().unwrap())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        self.task.take();
    }
}

impl Drop for LegacyTrap {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

#[derive(Clone, Copy)]
enum RequestBoundary {
    Forwarded,
    DeniedBeforeProxy,
}

fn check_response_headers(headers: &axum::http::HeaderMap, boundary: RequestBoundary) {
    match boundary {
        RequestBoundary::Forwarded => {
            assert_eq!(headers["access-control-allow-origin"], ORIGIN);
            let request_id = headers["x-request-id"].to_str().unwrap();
            assert_ne!(request_id, "synthetic-gateway-operations");
            assert!(
                uuid::Uuid::parse_str(request_id).is_ok(),
                "gateway must issue a correlation UUID"
            );
        }
        RequestBoundary::DeniedBeforeProxy => {
            // Authentication and tenant denial happen outside inner CORS and
            // proxy_handler; do not silently impose the downstream contract.
            assert!(!headers.contains_key("access-control-allow-origin"));
            assert!(!headers.contains_key("x-request-id"));
        }
    }
}

async fn request(
    router: &Router,
    case: &Value,
    auth: Option<(&str, &str)>,
    boundary: RequestBoundary,
) -> (u16, String, Value) {
    let path = case["path"].as_str().unwrap();
    let path = format!(
        "{path}{}organization_id=org-review",
        if path.contains('?') { "&" } else { "?" }
    );
    let mut builder = Request::builder()
        .method(case["method"].as_str().unwrap_or("GET"))
        .uri(path)
        .header("content-type", "application/json")
        .header("origin", ORIGIN)
        .header("x-request-id", "synthetic-gateway-operations")
        .header("x-user-id", "forged-user")
        .header("x-api-key-id", "forged-key")
        .header("x-organization-id", "forged-org");
    if let Some((name, value)) = auth {
        builder = builder.header(name, value);
    }
    let mut request = builder
        .body(Body::from(
            case.get("body").cloned().unwrap_or(json!({})).to_string(),
        ))
        .unwrap();
    for value in ["forged-priority-one", "forged-priority-two"] {
        request
            .headers_mut()
            .append("x-authenticated-user-id", value.parse().unwrap());
    }
    let response = tokio::time::timeout(Duration::from_secs(10), router.clone().oneshot(request))
        .await
        .unwrap()
        .unwrap();
    check_response_headers(response.headers(), boundary);
    let status = response.status().as_u16();
    let content_type = response.headers()["content-type"]
        .to_str()
        .unwrap()
        .to_owned();
    let bytes = to_bytes(response.into_body(), LIMIT).await.unwrap();
    let body =
        serde_json::from_slice(&bytes).unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes)));
    (status, content_type, body)
}

async fn raw_state(pool: &PgPool) -> Value {
    sqlx::query_scalar("SELECT jsonb_build_object(\
        'jobs',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM issuance_service.canvas_evidence_sync_jobs r),\
        'targets',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM issuance_service.canvas_evidence_sync_targets r),\
        'candidates',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM issuance_service.canvas_award_candidates r),\
        'reviews',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM issuance_service.evidence_policy_reviews r),\
        'events',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM issuance_service.issuance_events r),\
        'credentials',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM issuance_service.issued_credentials r),\
        'transactions',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM issuance_service.issuance_transactions r),\
        'deliveries',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM issuance_service.credential_delivery_records r),\
        'secrets',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM issuance_service.organization_integration_secrets r))")
        .fetch_one(pool).await.unwrap()
}

fn frozen_case(name: &str) -> (&'static Value, &'static Value) {
    let [_, scenarios, frozen] = fixtures();
    let case = scenarios["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap();
    let expected = frozen["observations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap();
    (case, expected)
}

async fn frozen_matrix(pool: &PgPool, router: &Router) {
    let [shared, scenarios, _] = fixtures();
    let preserved: Value = sqlx::query_scalar(shared["preserved_rows_sql"].as_str().unwrap())
        .fetch_one(pool)
        .await
        .unwrap();
    let initial: Value = sqlx::query_scalar(scenarios["snapshot_sql"].as_str().unwrap())
        .fetch_one(pool)
        .await
        .unwrap();
    let mut aliases = BTreeMap::new();
    for name in NON_MANUAL_CASES {
        let (case, expected) = frozen_case(name);
        for sql in case["sql"].as_array().into_iter().flatten() {
            sqlx::query(sql.as_str().unwrap())
                .execute(pool)
                .await
                .unwrap();
        }
        let (status, content_type, mut body) = request(
            router,
            case,
            Some(("cookie", "sessionId=actor-primary")),
            RequestBoundary::Forwarded,
        )
        .await;
        timestamps(&mut body);
        generated_ids(&mut body, &mut aliases);
        assert_eq!(
            json!({"status":status,"content_type":content_type,"body":body}),
            json!({"status":expected["status"],"content_type":expected["content_type"],"body":expected["body"]}),
            "frozen gateway case {name}"
        );
        let mut state: Value = sqlx::query_scalar(scenarios["snapshot_sql"].as_str().unwrap())
            .fetch_one(pool)
            .await
            .unwrap();
        generated_ids(&mut state, &mut aliases);
        for key in ["jobs", "targets"] {
            assert_eq!(state[key], expected["snapshot"][key], "{name}: {key}");
        }
        for key in ["reviews", "resolved_events"] {
            assert_eq!(state[key], initial[key]);
        }
        let current: Value = sqlx::query_scalar(shared["preserved_rows_sql"].as_str().unwrap())
            .fetch_one(pool)
            .await
            .unwrap();
        assert!(
            current == preserved,
            "gateway job/read changed protected rows"
        );
        assert_eq!(expected["lifecycle_calls"], json!([]));
    }
}

async fn actor_cases(pool: &PgPool, router: &Router, http: &CountedHttp) {
    let (dismiss, expected) = frozen_case("review_dismiss");
    for (auth, status) in [
        (None, 401),
        (Some(("cookie", "sessionId=invalid")), 401),
        (Some(("x-api-key", "invalid")), 401),
        (Some(("cookie", "sessionId=actor-denied")), 403),
        (Some(("x-api-key", "actor-key-no-scope")), 403),
        (Some(("x-api-key", "actor-key-wrong-org")), 403),
    ] {
        let before = raw_state(pool).await;
        let calls = http.counts();
        assert_eq!(
            request(router, dismiss, auth, RequestBoundary::DeniedBeforeProxy)
                .await
                .0,
            status
        );
        assert_eq!(http.counts(), calls, "denied request reached upstream");
        assert!(
            raw_state(pool).await == before,
            "denied request changed durable state"
        );
    }
    for (id, auth, actor) in [
        (
            "review-dismiss",
            ("cookie", "sessionId=actor-primary"),
            "actor-primary",
        ),
        (
            "review-gateway-api",
            ("x-api-key", "actor-key"),
            "api_key:trusted-key-id",
        ),
    ] {
        if id != "review-dismiss" {
            insert_review(pool, id).await;
        }
        let before = raw_state(pool).await;
        let case = json!({"method":"POST", "path":format!("/v1/integrations/canvas/evidence-policy-reviews/{id}/resolve"), "body":dismiss["body"]});
        let (status, content_type, mut body) =
            request(router, &case, Some(auth), RequestBoundary::Forwarded).await;
        timestamps(&mut body);
        let mut expected_body = expected["body"].clone();
        // API identity and the second fixture ID are intentional gateway-input
        // adaptations; every other frozen response field remains exact.
        expected_body["id"] = json!(id);
        expected_body["resolved_by"] = json!(actor);
        assert_eq!(status, expected["status"].as_u64().unwrap() as u16);
        assert_eq!(content_type, expected["content_type"].as_str().unwrap());
        assert_eq!(body, expected_body);
        let after = raw_state(pool).await;
        for key in [
            "jobs",
            "targets",
            "candidates",
            "credentials",
            "transactions",
            "deliveries",
            "secrets",
        ] {
            assert!(before[key] == after[key], "dismiss changed unrelated state");
        }
        for key in ["reviews", "events"] {
            let before_rows: Vec<_> = before[key]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|row| key != "reviews" || row["id"] != id)
                .collect();
            let after_rows: Vec<_> = after[key]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|row| {
                    if key == "reviews" {
                        row["id"] != id
                    } else {
                        row["event_type"] != "evidence_policy_review_resolved"
                            || row["metadata"]["review_id"] != id
                    }
                })
                .collect();
            assert!(
                before_rows == after_rows,
                "dismiss changed existing unrelated review/audit rows"
            );
        }
        let review = after["reviews"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .unwrap();
        assert_eq!(review["resolved_by"], actor);
        assert_eq!(review["status"], "dismissed");
        assert!(review["resolution_claim_token"].is_null());
        assert!(review["resolution_claim_action"].is_null());
        assert!(review["resolution_claimed_at"].is_null());
        assert_eq!(review["resolution_recovery_pending"], false);
        let events: Vec<_> = after["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| {
                e["event_type"] == "evidence_policy_review_resolved"
                    && e["metadata"]["review_id"] == id
            })
            .collect();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["application_id"], "application-review");
        assert_eq!(
            events[0]["metadata"],
            json!({"organization_id":"org-review", "review_id":id,
            "credential_id":"credential-review", "resolution_action":"dismiss", "resolved_by":actor})
        );
        let duplicate = request(router, &case, Some(auth), RequestBoundary::Forwarded).await;
        assert_eq!(duplicate.0, 409);
        assert!(
            raw_state(pool).await == after,
            "duplicate resolution changed raw state"
        );
    }
}

/// The registered caller owns the exact disposable DB, outer timeout and cleanup.
pub async fn run(pool: &PgPool, database_url: &str) {
    seed(pool).await;
    let trap = LegacyTrap::start().await;
    let (http_reservation, http_port) = reserve_port();
    let (_grpc_reservation, grpc_port) = reserve_port();
    let mut command = isolated_smoke_command(http_port, grpc_port);
    command
        .env("DATABASE_URL", database_url)
        .env("ISSUANCE_API_KEY", "synthetic-operations-key")
        .env(
            "GRPC_SERVICE_TOKEN",
            "synthetic-gateway-service-token-at-least-32-characters",
        )
        .env("CANVAS_PORTABLE_INTEGRATION_ENABLED", "true")
        .env("CANVAS_PILOT_ORGANIZATION_IDS", "org-review");
    drop(http_reservation);
    let mut child = ChildGuard(command.spawn().unwrap());
    let client = bounded_http_client(Duration::from_secs(2));
    let health = tokio::time::timeout(
        Duration::from_secs(10),
        wait_for_health_with_client(http_port, &client),
    )
    .await
    .unwrap();
    assert_eq!(
        health,
        Some(json!({"status":"healthy","service":"issuance-service"}))
    );

    let (published, published_http) = router(http_port, trap.port, Routing::PublishedLegacy);
    let before = raw_state(pool).await;
    for name in NON_MANUAL_CASES.into_iter().chain(["review_dismiss"]) {
        let (case, _) = frozen_case(name);
        let response = request(
            &published,
            case,
            Some(("cookie", "sessionId=actor-primary")),
            RequestBoundary::Forwarded,
        )
        .await;
        assert_eq!(response.0, 418);
        assert_eq!(response.2, legacy_trap_body());
    }
    assert_eq!(published_http.counts(), (0, 8));
    assert!(
        raw_state(pool).await == before,
        "published legacy control reached native state"
    );

    let (candidate, candidate_http) = router(http_port, trap.port, Routing::CandidateNative);
    frozen_matrix(pool, &candidate).await;
    actor_cases(pool, &candidate, &candidate_http).await;
    assert_eq!(candidate_http.counts(), (11, 0)); // 7 routes + 2 dismiss + 2 duplicates.
    assert_eq!(trap.calls.load(Ordering::SeqCst), 8);
    assert!(
        child.0.try_wait().unwrap().is_none(),
        "issuance exited before fixture shutdown"
    );
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    trap.close().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_selection_changes_only_eight_real_route_destinations() {
        for candidate in [Routing::PublishedLegacy, Routing::CandidateNative] {
            let contract = GatewayContract::load().unwrap();
            select_routes(contract.runtime_route_table().unwrap(), candidate);
            select_routes(contract.proxy_route_table().unwrap(), candidate);
        }
        let table = GatewayContract::load()
            .unwrap()
            .runtime_route_table()
            .unwrap();
        let actual: BTreeSet<_> = NON_MANUAL_CASES
            .into_iter()
            .chain(["review_dismiss"])
            .map(|name| {
                let (case, _) = frozen_case(name);
                let method = if case["method"] == "POST" {
                    HttpMethod::Post
                } else {
                    HttpMethod::Get
                };
                let matched = table
                    .find(&GatewayRequest::new(
                        method,
                        case["path"].as_str().unwrap(),
                        0,
                    ))
                    .unwrap();
                (method, matched.route.pattern)
            })
            .collect();
        assert_eq!(
            actual,
            operation_routes(),
            "selected frozen cases must cover all eight operations"
        );
    }
}
