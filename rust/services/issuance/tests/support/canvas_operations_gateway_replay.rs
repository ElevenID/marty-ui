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
    canvas_operations_read_replay::{
        fixtures, generated_ids, insert_review, request_body, seed, timestamps,
    },
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
// Additional read cases are not route exemplars: keep the eight-route legacy
// trap proof independent from the number of frozen behaviors replayed.
const READ_FILTER_CASES: [&str; 6] = [
    "jobs_filtered",
    "jobs_unmatched_binding",
    "candidates_filtered",
    "candidates_unmatched_binding",
    "reviews_filtered",
    "reviews_unmatched_binding",
];
const READ_VALIDATION_CASES: [&str; 8] = [
    "jobs_zero_limit",
    "jobs_excess_limit",
    "candidates_invalid_status",
    "candidates_zero_limit",
    "candidates_excess_limit",
    "reviews_invalid_status",
    "reviews_zero_limit",
    "reviews_excess_limit",
];
const JOB_STATE_CASES: [&str; 6] = [
    "retry_foreign",
    "retry_again",
    "resolve_queued",
    "resolve_again",
    "enqueue_duplicate",
    "enqueue_foreign",
];
// Preserve the frozen transitions: queued conflicts precede the fixture's
// explicit dead-letter reset, and duplicate enqueue follows the original job.
const JOB_SEQUENCE_CASES: [&str; 13] = [
    "jobs_list",
    "candidates_list",
    "reviews_list",
    "job_get",
    "retry_foreign",
    "retry_dead_letter",
    "retry_again",
    "resolve_queued",
    "resolve_dead_letter",
    "resolve_again",
    "enqueue",
    "enqueue_duplicate",
    "enqueue_foreign",
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
        Ok(matches!(
            session,
            "actor-primary" | "actor-denied" | "actor-no-tenant"
        )
        .then(|| SessionIdentity {
            user_id: session.into(),
            organization_id: (session != "actor-no-tenant").then(|| "org-review".into()),
            ..SessionIdentity::default()
        }))
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

#[derive(Clone, Copy)]
enum UpstreamTenant {
    ExplicitQuery,
    SessionFallback,
    ApiKeyFallback,
    Absent,
}

impl UpstreamTenant {
    fn assert_request(self, request: &GatewayRequest) {
        match self {
            Self::ExplicitQuery => {
                let tenants = request.query.get("organization_id").unwrap();
                assert_eq!(tenants.len(), 1);
                assert_eq!(
                    request.header("x-organization-id"),
                    Some(tenants[0].as_str())
                );
                if tenants[0] == "org-other" {
                    assert_eq!(request.header("x-api-key-id"), Some("trusted-key-id"));
                    assert_eq!(request.header("x-user-id"), Some("api_key:trusted-key-id"));
                }
            }
            Self::SessionFallback | Self::ApiKeyFallback | Self::Absent => {
                assert!(!request.query.contains_key("organization_id"));
                let (organization, user, key) = match self {
                    Self::SessionFallback => (Some("org-review"), "actor-primary", None),
                    Self::ApiKeyFallback => (
                        Some("org-review"),
                        "api_key:trusted-key-id",
                        Some("trusted-key-id"),
                    ),
                    Self::Absent => (None, "actor-no-tenant", None),
                    Self::ExplicitQuery => unreachable!(),
                };
                assert_eq!(request.header("x-organization-id"), organization);
                assert_eq!(request.header("x-user-id"), Some(user));
                assert_eq!(request.header("x-api-key-id"), key);
            }
        }
    }
}

pub(super) struct CountedHttp {
    http: ReqwestUpstream,
    native: AtomicUsize,
    legacy: AtomicUsize,
    tenant: UpstreamTenant,
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
        self.tenant.assert_request(&request);
        self.http.send(instance, request).await
    }
}

impl CountedHttp {
    pub(super) fn counts(&self) -> (usize, usize) {
        (
            self.native.load(Ordering::SeqCst),
            self.legacy.load(Ordering::SeqCst),
        )
    }
}

pub(super) fn candidate_router(native_port: u16, legacy_port: u16) -> (Router, Arc<CountedHttp>) {
    router(native_port, legacy_port, Routing::CandidateNative)
}

fn router(native_port: u16, legacy_port: u16, routing: Routing) -> (Router, Arc<CountedHttp>) {
    router_with_tenant(
        native_port,
        legacy_port,
        routing,
        UpstreamTenant::ExplicitQuery,
    )
}

fn router_with_tenant(
    native_port: u16,
    legacy_port: u16,
    routing: Routing,
    tenant: UpstreamTenant,
) -> (Router, Arc<CountedHttp>) {
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
        tenant,
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
pub(super) enum RequestBoundary {
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

pub(super) async fn request(
    router: &Router,
    case: &Value,
    auth: Option<(&str, &str)>,
    tenant: &str,
    boundary: RequestBoundary,
) -> (u16, String, Value) {
    let path = tenant_path(case["path"].as_str().unwrap(), tenant);
    request_at_path(router, case, auth, &path, Some("forged-org"), boundary).await
}

// Explicit seam for public authentication/tenant controls only. The default
// request() still rejects existing tenant queries and injects all spoof probes.
async fn request_at_path(
    router: &Router,
    case: &Value,
    auth: Option<(&str, &str)>,
    path: &str,
    client_tenant: Option<&str>,
    boundary: RequestBoundary,
) -> (u16, String, Value) {
    assert!(
        case.get("content_type").is_none(),
        "alternate media types require an explicit gateway request adapter"
    );
    let mut builder = Request::builder()
        .method(case["method"].as_str().unwrap_or("GET"))
        .uri(path)
        .header("content-type", "application/json")
        .header("origin", ORIGIN)
        .header("x-request-id", "synthetic-gateway-operations")
        .header("x-user-id", "forged-user")
        .header("x-api-key-id", "forged-key");
    if let Some(tenant) = client_tenant {
        builder = builder.header("x-organization-id", tenant);
    }
    if let Some((name, value)) = auth {
        builder = builder.header(name, value);
    }
    let mut request = builder.body(Body::from(request_body(case))).unwrap();
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

fn tenant_path(path: &str, tenant: &str) -> String {
    assert!(matches!(tenant, "org-review" | "org-other"));
    assert!(!path.contains('#'));
    let query = path.split_once('?').map_or("", |(_, query)| query);
    assert!(
        url::form_urlencoded::parse(query.as_bytes()).all(|(key, _)| key != "organization_id"),
        "request must have exactly one explicit tenant query parameter"
    );
    format!(
        "{path}{}organization_id={tenant}",
        if path.contains('?') { "&" } else { "?" }
    )
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

const MESSAGE_ID_SENTINEL: &str = "$gateway-message-id";

fn public_error_expected(name: &str) -> (u16, Value) {
    // Closed source-derived PUBLIC expectations, not a second generic normalizer.
    // MMF b4376cda59b3921598e1749f550595d7293e4624 proxy.rs normalizes
    // detail strings/objects, retaining detail.code under details. Array detail
    // currently becomes the generic description with no details; this does not
    // claim the public gateway preserves the direct Pydantic validation array.
    let (status, description, code) = match name {
        "job_foreign" | "job_missing" | "retry_foreign" => {
            (404, "Canvas synchronization job not found", None)
        }
        "retry_rollout_closed" => (
            409,
            "Portable Canvas integration is disabled for this organization",
            None,
        ),
        "retry_again" => (
            409,
            "Only dead-letter Canvas sync jobs can be retried",
            None,
        ),
        "resolve_queued" | "resolve_again" => (
            409,
            "Only dead-letter Canvas sync jobs can be resolved",
            None,
        ),
        "enqueue_foreign" => (
            404,
            "Canvas application not found",
            Some("canvas_application_not_found"),
        ),
        "missing_tenant" => (
            400,
            "X-Organization-ID is required for Canvas management",
            None,
        ),
        "review_foreign" => (
            404,
            "Canvas evidence correction review not found",
            Some("canvas_review_not_found"),
        ),
        "review_dismiss_again" => (
            409,
            "Canvas evidence correction review is already resolved",
            Some("canvas_review_already_resolved"),
        ),
        "jobs_invalid_status" => (422, "Invalid Canvas sync job status", None),
        "candidates_invalid_status" => (422, "Invalid Canvas award candidate status", None),
        "reviews_invalid_status" => (422, "Invalid evidence policy review status", None),
        "jobs_zero_limit"
        | "jobs_excess_limit"
        | "candidates_zero_limit"
        | "candidates_excess_limit"
        | "reviews_zero_limit"
        | "reviews_excess_limit" => (422, "Downstream service request failed", None),
        "review_invalid_action" | "review_note_limit" => {
            (422, "Downstream service request failed", None)
        }
        _ => panic!("unreviewed public error case"),
    };
    let (_, frozen) = frozen_case(name);
    assert_eq!(frozen["status"], status);
    assert_eq!(frozen["content_type"], "application/json");
    if name == "review_note_limit" {
        let (case, _) = frozen_case(name);
        assert_eq!(case["note_length"], 2001);
        assert_eq!(case["body"], json!({"action":"dismiss"}));
        assert_eq!(
            frozen["body"],
            json!({"detail":[{"ctx":{"max_length":2000},"input":"n".repeat(2001),
                "loc":["body","note"],"msg":"String should have at most 2000 characters",
                "type":"string_too_long","url":"https://errors.pydantic.dev/2.11/v/string_too_long"}]})
        );
    } else if name == "review_invalid_action" {
        assert!(frozen["body"]["detail"].is_array());
    } else if READ_VALIDATION_CASES.contains(&name) && name.ends_with("_limit") {
        // Check the complete source observation before applying the pinned
        // public array-detail projection. Do not manufacture public details
        // that the actual MMF normalizer does not preserve.
        let (input, context, kind, message) = if name.ends_with("_zero_limit") {
            (
                "0",
                json!({"ge":1}),
                "greater_than_equal",
                "Input should be greater than or equal to 1",
            )
        } else {
            (
                "501",
                json!({"le":500}),
                "less_than_equal",
                "Input should be less than or equal to 500",
            )
        };
        assert_eq!(
            frozen["body"],
            json!({"detail":[{"ctx":context,"input":input,"loc":["query","limit"],
                "msg":message,"type":kind,
                "url":format!("https://errors.pydantic.dev/2.11/v/{kind}")} ]})
        );
    } else if let Some(code) = code {
        assert_eq!(
            frozen["body"],
            json!({"detail":{"code":code,"message":description}})
        );
    } else {
        assert_eq!(frozen["body"], json!({"detail":description}));
    }
    let mut expected = json!({"error":"service_error", "error_description":description,
        "message_id":MESSAGE_ID_SENTINEL});
    if let Some(code) = code {
        expected["details"] = json!({"code":code});
    }
    (status, expected)
}

fn assert_public_error(actual: (u16, String, Value), name: &str) -> Value {
    let (status, content_type, mut body) = actual;
    let (expected_status, expected) = public_error_expected(name);
    assert_eq!(status, expected_status);
    assert_eq!(content_type, "application/json");
    let message_id = body["message_id"].as_str().expect("public MIP message_id");
    assert!(
        uuid::Uuid::parse_str(message_id).is_ok(),
        "public MIP message_id must be a UUID"
    );
    // The MIP UUID and the separately validated gateway request-header UUID
    // have independent owners. Never require them to match or strip other data.
    body["message_id"] = json!(MESSAGE_ID_SENTINEL);
    assert!(
        body == expected,
        "public error differs from reviewed MIP envelope"
    );
    body
}

async fn unchanged_public_error(
    pool: &PgPool,
    router: &Router,
    http: &CountedHttp,
    case: &Value,
    tenant: &str,
    expected_name: &str,
) -> Value {
    let before = raw_state(pool).await;
    let calls = http.counts();
    assert_eq!(calls.1, 0);
    let key = if tenant == "org-other" {
        "actor-key-wrong-org"
    } else {
        "actor-key"
    };
    let actual = request(
        router,
        case,
        Some(("x-api-key", key)),
        tenant,
        RequestBoundary::Forwarded,
    )
    .await;
    let body = assert_public_error(actual, expected_name);
    assert_eq!(
        http.counts(),
        (calls.0 + 1, 0),
        "public error must reach native exactly once"
    );
    assert!(
        raw_state(pool).await == before,
        "public error changed durable state"
    );
    body
}

async fn public_error_cases(pool: &PgPool, router: &Router, http: &CountedHttp) {
    // The query matches the authenticated foreign tenant; a gateway 403 cannot
    // satisfy these controls. Seeded foreign and missing IDs must be publicly
    // indistinguishable after validating their independent generated UUIDs.
    let (foreign_job, _) = frozen_case("job_foreign");
    let (missing_job, _) = frozen_case("job_missing");
    let foreign =
        unchanged_public_error(pool, router, http, foreign_job, "org-other", "job_foreign").await;
    let missing =
        unchanged_public_error(pool, router, http, missing_job, "org-other", "job_missing").await;
    assert_eq!(foreign, missing);

    let (foreign_review, _) = frozen_case("review_foreign");
    let mut missing_review = foreign_review.clone();
    // Only the object ID is changed; this is a missing-object counterpart, not
    // an invented additional frozen observation or a different tenant contract.
    missing_review["path"] =
        json!("/v1/integrations/canvas/evidence-policy-reviews/missing/resolve");
    let foreign = unchanged_public_error(
        pool,
        router,
        http,
        foreign_review,
        "org-other",
        "review_foreign",
    )
    .await;
    let missing = unchanged_public_error(
        pool,
        router,
        http,
        &missing_review,
        "org-other",
        "review_foreign",
    )
    .await;
    assert_eq!(foreign, missing);

    for name in [
        "jobs_invalid_status",
        "review_invalid_action",
        "review_note_limit",
    ]
    .into_iter()
    .chain(READ_VALIDATION_CASES)
    {
        unchanged_public_error(pool, router, http, frozen_case(name).0, "org-review", name).await;
    }
}

fn assert_duplicate_enqueue(before: &Value, after: &Value, body: &Value) {
    let job = before["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|job| job["id"] == body["id"])
        .expect("duplicate must return the existing job");
    assert_eq!(job["status"], "queued");
    assert_eq!(job["target_id"], body["target_id"]);
    let mut expected = before.clone();
    let target = expected["targets"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|target| target["id"] == body["target_id"])
        .expect("duplicate must retain the original target");
    let actual = after["targets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|target| target["id"] == body["target_id"])
        .unwrap();
    // The real enqueue_application_sync upsert refreshes exactly these two
    // timestamps and records the request source. No whole-row normalization:
    // unknown target fields, every job and every unrelated table stay exact.
    for key in ["updated_at", "last_enqueued_at"] {
        let old = chrono::DateTime::parse_from_rfc3339(target[key].as_str().unwrap()).unwrap();
        let new = chrono::DateTime::parse_from_rfc3339(actual[key].as_str().unwrap()).unwrap();
        assert!(new >= old, "duplicate enqueue timestamp went backwards");
        target[key] = actual[key].clone();
    }
    assert!(target["metadata"].is_object());
    target["metadata"]["last_requested_from"] = json!("application_sync_api");
    assert!(
        after == &expected,
        "duplicate enqueue changed unexpected raw state"
    );
}

fn assert_auth_reference_inputs() {
    // These remain DIRECT-service obligations, not invented frozen gateway
    // observations. Public authentication replaces the client's management key,
    // and authenticated organization state replaces an omitted client header.
    for (name, status, detail) in [
        ("missing_management_key", 401, "X-API-Key header is missing"),
        ("wrong_management_key", 401, "Invalid API Key"),
        (
            "missing_tenant",
            400,
            "X-Organization-ID is required for Canvas management",
        ),
        ("foreign_query", 404, "Canvas resource not found"),
    ] {
        let (case, expected) = frozen_case(name);
        assert_eq!(case["method"], "GET");
        assert_eq!(expected["status"], status);
        assert_eq!(expected["content_type"], "application/json");
        assert_eq!(expected["body"], json!({"detail":detail}));
        assert_eq!(expected["snapshot"], frozen_case("jobs_list").1["snapshot"]);
        assert_eq!(expected["lifecycle_calls"], json!([]));
    }
    assert_eq!(
        frozen_case("missing_management_key").0["omit_headers"],
        json!(["X-API-Key"])
    );
    assert_eq!(
        frozen_case("wrong_management_key").0["headers"],
        json!({"X-API-Key":"synthetic-wrong-key"})
    );
    assert_eq!(
        frozen_case("missing_tenant").0["omit_headers"],
        json!(["X-Organization-ID"])
    );
    assert_eq!(
        frozen_case("foreign_query").0["path"],
        "/v1/integrations/canvas/canvas-sync-jobs?organization_id=org-foreign"
    );
}

fn public_auth_expected(name: &str) -> (u16, Value) {
    match name {
        "no_public_auth" => (
            401,
            json!({"error":"unauthorized","error_description":"Authentication required","message_id":MESSAGE_ID_SENTINEL}),
        ),
        "invalid_public_key" => (
            401,
            json!({"error":"unauthorized","error_description":"Invalid or expired API key","message_id":MESSAGE_ID_SENTINEL}),
        ),
        "foreign_session_query" => (403, json!({"detail":"Not a member of this organization"})),
        "foreign_api_key_query" => (
            403,
            json!({"detail":"API key does not have access to this organization"}),
        ),
        _ => panic!("unreviewed public authentication boundary"),
    }
}

fn assert_public_auth_error(actual: (u16, String, Value), name: &str) {
    let (status, content_type, mut body) = actual;
    let (expected_status, expected) = public_auth_expected(name);
    assert_eq!(status, expected_status);
    assert_eq!(content_type, "application/json");
    if expected.get("message_id").is_some() {
        assert!(uuid::Uuid::parse_str(body["message_id"].as_str().unwrap()).is_ok());
        body["message_id"] = json!(MESSAGE_ID_SENTINEL);
    }
    // Tenant middleware's detail object is deliberately not a MIP projection.
    // No arbitrary extra fields or synthetic message IDs are accepted there.
    assert!(
        body == expected,
        "public authentication response differs from its owner"
    );
}

async fn public_auth_boundaries(pool: &PgPool, native_port: u16, legacy_port: u16) -> usize {
    assert_auth_reference_inputs();
    let before = raw_state(pool).await;
    let (denied, denied_http) = candidate_router(native_port, legacy_port);
    let mut requests = 0;
    for (source, name, auth) in [
        ("missing_management_key", "no_public_auth", None),
        (
            "wrong_management_key",
            "invalid_public_key",
            Some(("x-api-key", "synthetic-wrong-key")),
        ),
    ] {
        let case = frozen_case(source).0;
        let response = request_at_path(
            &denied,
            case,
            auth,
            case["path"].as_str().unwrap(),
            None,
            RequestBoundary::DeniedBeforeProxy,
        )
        .await;
        assert_public_auth_error(response, name);
        assert_eq!(denied_http.counts(), (0, 0));
        assert!(
            raw_state(pool).await == before,
            "authentication denial changed raw state"
        );
        requests += 1;
    }

    let (missing_tenant, _) = frozen_case("missing_tenant");
    let (_, expected_read) = frozen_case("jobs_list");
    let mut native_calls = 0;
    for (tenant, auth) in [
        (
            UpstreamTenant::SessionFallback,
            ("cookie", "sessionId=actor-primary"),
        ),
        (UpstreamTenant::ApiKeyFallback, ("x-api-key", "actor-key")),
    ] {
        let (router, http) =
            router_with_tenant(native_port, legacy_port, Routing::CandidateNative, tenant);
        // No tenant header/query and no service management key from the client.
        // CountedHttp proves the independently authenticated tenant/identity and
        // the gateway-owned service key on the actual prepared HTTP request.
        let (status, content_type, mut body) = request_at_path(
            &router,
            missing_tenant,
            Some(auth),
            missing_tenant["path"].as_str().unwrap(),
            None,
            RequestBoundary::Forwarded,
        )
        .await;
        timestamps(&mut body);
        assert_eq!(
            json!({"status":status,"content_type":content_type,"body":body}),
            json!({"status":expected_read["status"],"content_type":expected_read["content_type"],"body":expected_read["body"]})
        );
        assert_eq!(http.counts(), (1, 0));
        assert!(
            raw_state(pool).await == before,
            "tenant fallback read changed raw state"
        );
        native_calls += http.counts().0;
        requests += 1;
    }

    let (unscoped, unscoped_http) = router_with_tenant(
        native_port,
        legacy_port,
        Routing::CandidateNative,
        UpstreamTenant::Absent,
    );
    let response = request_at_path(
        &unscoped,
        missing_tenant,
        Some(("cookie", "sessionId=actor-no-tenant")),
        missing_tenant["path"].as_str().unwrap(),
        None,
        RequestBoundary::Forwarded,
    )
    .await;
    assert_public_error(response, "missing_tenant");
    assert_eq!(unscoped_http.counts(), (1, 0));
    assert!(
        raw_state(pool).await == before,
        "missing trusted tenant changed raw state"
    );
    native_calls += unscoped_http.counts().0;
    requests += 1;

    let foreign = frozen_case("foreign_query").0;
    for (name, auth) in [
        (
            "foreign_session_query",
            ("cookie", "sessionId=actor-primary"),
        ),
        ("foreign_api_key_query", ("x-api-key", "actor-key")),
    ] {
        // Preserve the actual frozen foreign query. Do not replace it with a
        // matching foreign principal or turn this into the direct-service 404.
        let response = request_at_path(
            &denied,
            foreign,
            Some(auth),
            foreign["path"].as_str().unwrap(),
            Some("org-review"),
            RequestBoundary::DeniedBeforeProxy,
        )
        .await;
        assert_public_auth_error(response, name);
        assert_eq!(denied_http.counts(), (0, 0));
        assert!(
            raw_state(pool).await == before,
            "foreign query denial changed raw state"
        );
        requests += 1;
    }
    assert_eq!(requests, 7);
    assert_eq!(native_calls, 3);
    native_calls
}

async fn frozen_matrix(pool: &PgPool, router: &Router, http: &CountedHttp) {
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
    // The frozen filtered reads observe the seed before retry/resolve/enqueue
    // mutate it. Reuse the same DTO/snapshot comparator, not another fixture.
    for name in READ_FILTER_CASES.into_iter().chain(JOB_SEQUENCE_CASES) {
        let (case, expected) = frozen_case(name);
        for sql in case["sql"].as_array().into_iter().flatten() {
            sqlx::query(sql.as_str().unwrap())
                .execute(pool)
                .await
                .unwrap();
        }
        let before = raw_state(pool).await;
        let foreign = matches!(name, "retry_foreign" | "enqueue_foreign");
        if foreign {
            assert_eq!(case["headers"], json!({"X-Organization-ID":"org-foreign"}));
        }
        let calls = http.counts();
        assert_eq!(calls.1, 0);
        let (status, content_type, mut body) = request(
            router,
            case,
            Some(if foreign {
                ("x-api-key", "actor-key-wrong-org")
            } else {
                ("cookie", "sessionId=actor-primary")
            }),
            if foreign { "org-other" } else { "org-review" },
            RequestBoundary::Forwarded,
        )
        .await;
        assert_eq!(
            http.counts(),
            (calls.0 + 1, 0),
            "{name}: native request count"
        );
        if case["method"] == "GET" || expected["status"].as_u64().unwrap() >= 400 {
            assert!(
                raw_state(pool).await == before,
                "{name}: read or rejected transition changed raw state"
            );
        }
        if name == "enqueue_duplicate" {
            assert_duplicate_enqueue(&before, &raw_state(pool).await, &body);
        }
        timestamps(&mut body);
        generated_ids(&mut body, &mut aliases);
        if expected["status"].as_u64().unwrap() >= 400 {
            assert_public_error((status, content_type, body), name);
        } else {
            assert_eq!(
                json!({"status":status,"content_type":content_type,"body":body}),
                json!({"status":expected["status"],"content_type":expected["content_type"],"body":expected["body"]}),
                "frozen gateway case {name}"
            );
        }
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
            request(
                router,
                dismiss,
                auth,
                "org-review",
                RequestBoundary::DeniedBeforeProxy
            )
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
        let (status, content_type, mut body) = request(
            router,
            &case,
            Some(auth),
            "org-review",
            RequestBoundary::Forwarded,
        )
        .await;
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
        let calls = http.counts();
        let duplicate = request(
            router,
            &case,
            Some(auth),
            "org-review",
            RequestBoundary::Forwarded,
        )
        .await;
        assert_public_error(duplicate, "review_dismiss_again");
        assert_eq!(http.counts(), (calls.0 + 1, calls.1));
        assert!(
            raw_state(pool).await == after,
            "duplicate resolution changed raw state"
        );
    }
}

async fn start_native(database_url: &str, enabled: bool) -> (ChildGuard, u16) {
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
        .env(
            "CANVAS_PORTABLE_INTEGRATION_ENABLED",
            if enabled { "true" } else { "false" },
        )
        .env("CANVAS_PILOT_ORGANIZATION_IDS", "org-review");
    drop(http_reservation);
    let child = ChildGuard(command.spawn().unwrap());
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
    (child, http_port)
}

fn finish_native(mut child: ChildGuard) {
    assert!(
        child.0.try_wait().unwrap().is_none(),
        "issuance exited before fixture shutdown"
    );
    child.0.kill().unwrap();
    child.0.wait().unwrap();
}

/// The registered caller owns the exact disposable DB, outer timeout and cleanup.
pub async fn run(pool: &PgPool, database_url: &str) {
    seed(pool).await;
    let trap = LegacyTrap::start().await;
    // Rollout is an actual-main startup input, not an HTTP-layer stub. Run the
    // closed control before any frozen job transition and reap it before the
    // enabled process starts; both use the same untouched seed and process owner.
    let (closed_child, closed_port) = start_native(database_url, false).await;
    let (closed, closed_http) = candidate_router(closed_port, trap.port);
    let (case, expected) = frozen_case("retry_rollout_closed");
    assert_eq!(case["rollout"], false);
    unchanged_public_error(
        pool,
        &closed,
        &closed_http,
        case,
        "org-review",
        "retry_rollout_closed",
    )
    .await;
    let state: Value = sqlx::query_scalar(fixtures()[1]["snapshot_sql"].as_str().unwrap())
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(state, expected["snapshot"]);
    assert_eq!(expected["lifecycle_calls"], json!([]));
    assert_eq!(closed_http.counts(), (1, 0));
    assert_eq!(trap.calls.load(Ordering::SeqCst), 0);
    finish_native(closed_child);

    let (child, http_port) = start_native(database_url, true).await;
    let auth_native_calls = public_auth_boundaries(pool, http_port, trap.port).await;

    let (published, published_http) = router(http_port, trap.port, Routing::PublishedLegacy);
    let before = raw_state(pool).await;
    for name in NON_MANUAL_CASES.into_iter().chain(["review_dismiss"]) {
        let (case, _) = frozen_case(name);
        let response = request(
            &published,
            case,
            Some(("cookie", "sessionId=actor-primary")),
            "org-review",
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
    frozen_matrix(pool, &candidate, &candidate_http).await;
    public_error_cases(pool, &candidate, &candidate_http).await;
    actor_cases(pool, &candidate, &candidate_http).await;
    // Retain the 37 earlier enabled requests and the real oversized-note denial.
    assert_eq!(candidate_http.counts(), (38, 0));
    assert_eq!(closed_http.counts().0 + candidate_http.counts().0, 39);
    assert_eq!(
        auth_native_calls + closed_http.counts().0 + candidate_http.counts().0,
        42
    );
    assert_eq!(trap.calls.load(Ordering::SeqCst), 8);
    finish_native(child);
    trap.close().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_body_recipe_preserves_frozen_note_and_raw_bytes_without_mutation() {
        let (case, _) = frozen_case("review_note_limit");
        let before = case.clone();
        let generated: Value = serde_json::from_str(&request_body(case)).unwrap();
        assert_eq!(
            generated,
            json!({"action":"dismiss","note":"n".repeat(2001)})
        );
        assert_eq!(case, &before);
        assert_eq!(request_body(&json!({})), "{}");
        let literal = json!({"body":{"note":"existing note","action":"dismiss"}});
        assert_eq!(
            serde_json::from_str::<Value>(&request_body(&literal)).unwrap(),
            literal["body"]
        );
        let raw = " {\"action\": \"dismiss\",\"action\":";
        assert_eq!(
            request_body(&json!({"body":{"action":"revoke"},"note_length":2001,"raw_body":raw})),
            raw
        );
    }

    #[tokio::test]
    async fn gateway_requests_reject_unadapted_content_type_fields() {
        for content_type in [Value::Null, json!("text/plain"), json!("application/json")] {
            let failure = tokio::spawn(async move {
                request_at_path(
                    &Router::new(),
                    &json!({"method":"POST","content_type":content_type}),
                    None,
                    "/unused",
                    None,
                    RequestBoundary::Forwarded,
                )
                .await;
            })
            .await
            .expect_err("unadapted content_type must be rejected before dispatch");
            assert!(failure.is_panic());
            let panic = failure.into_panic();
            let message = panic
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| panic.downcast_ref::<String>().map(String::as_str));
            assert_eq!(
                message,
                Some("alternate media types require an explicit gateway request adapter"),
                "a later router/header failure must not satisfy the guard regression"
            );
        }
    }

    #[test]
    fn tenant_query_is_explicit_unique_and_preserves_other_parameters() {
        assert_eq!(
            tenant_path("/jobs", "org-other"),
            "/jobs?organization_id=org-other"
        );
        assert_eq!(
            tenant_path("/jobs?status=invalid", "org-review"),
            "/jobs?status=invalid&organization_id=org-review"
        );
        for path in [
            "/jobs?organization_id=org-review",
            "/jobs?organization_id=org-other&organization_id=org-review",
            "/jobs?organization%5Fid=org-other",
            "/jobs#fragment",
        ] {
            assert!(std::panic::catch_unwind(|| tenant_path(path, "org-other")).is_err());
        }
        assert!(std::panic::catch_unwind(|| tenant_path("/jobs", "unreviewed")).is_err());
    }

    #[test]
    fn public_error_comparison_validates_uuid_and_preserves_exact_envelope() {
        for name in [
            "job_foreign",
            "job_missing",
            "review_foreign",
            "review_dismiss_again",
            "jobs_invalid_status",
            "review_invalid_action",
        ]
        .into_iter()
        .chain(READ_VALIDATION_CASES)
        .chain([
            "retry_rollout_closed",
            "retry_foreign",
            "retry_again",
            "resolve_queued",
            "resolve_again",
            "enqueue_foreign",
            "missing_tenant",
            "review_note_limit",
        ]) {
            let (status, expected) = public_error_expected(name);
            let mut actual = expected.clone();
            actual["message_id"] = json!("11111111-1111-4111-8111-111111111111");
            assert_eq!(
                assert_public_error((status, "application/json".into(), actual.clone()), name),
                expected
            );
            let mut mutations = Vec::new();
            for id in [
                Value::Null,
                json!(1),
                json!("invalid"),
                json!(MESSAGE_ID_SENTINEL),
            ] {
                let mut changed = actual.clone();
                changed["message_id"] = id;
                mutations.push(changed);
            }
            let mut missing_id = actual.clone();
            missing_id.as_object_mut().unwrap().remove("message_id");
            mutations.push(missing_id);
            let mut extra = actual.clone();
            extra["unexpected"] = json!(true);
            mutations.push(extra);
            let mut description = actual.clone();
            description["error_description"] = json!("different");
            mutations.push(description);
            let mut details = actual.clone();
            if details.get("details").is_some() {
                details.as_object_mut().unwrap().remove("details");
            } else {
                details["details"] = json!({"unexpected":true});
            }
            mutations.push(details);
            for changed in mutations {
                assert!(std::panic::catch_unwind(|| assert_public_error(
                    (status, "application/json".into(), changed),
                    name
                ))
                .is_err());
            }
            assert!(std::panic::catch_unwind(|| assert_public_error(
                (200, "application/json".into(), actual.clone()),
                name
            ))
            .is_err());
            assert!(std::panic::catch_unwind(|| assert_public_error(
                (status, "text/plain".into(), actual),
                name
            ))
            .is_err());
        }
        assert_eq!(
            public_error_expected("job_foreign"),
            public_error_expected("job_missing")
        );
        assert!(public_error_expected("review_invalid_action")
            .1
            .get("details")
            .is_none());
    }

    #[test]
    fn additional_read_cases_are_closed_and_do_not_replace_route_exemplars() {
        let names: BTreeSet<_> = READ_FILTER_CASES
            .into_iter()
            .chain(READ_VALIDATION_CASES)
            .collect();
        assert_eq!(names.len(), 14);
        for name in names {
            assert!(!NON_MANUAL_CASES.contains(&name));
            let (case, expected) = frozen_case(name);
            assert_eq!(case["method"], "GET");
            assert!(case.get("sql").is_none());
            assert!(case.get("body").is_none());
            assert!(case.get("headers").is_none());
            assert_eq!(expected["lifecycle_calls"], json!([]));
            if READ_FILTER_CASES.contains(&name) {
                assert_eq!(expected["status"], 200);
                assert!(case["path"].as_str().unwrap().contains("binding_id="));
                assert_eq!(expected["snapshot"], frozen_case("jobs_list").1["snapshot"]);
            } else {
                assert_eq!(public_error_expected(name).0, 422);
            }
        }
    }

    #[test]
    fn public_auth_adaptations_retain_direct_frozen_obligations() {
        assert_auth_reference_inputs();
        for (direct, public) in [
            ("missing_management_key", "no_public_auth"),
            ("wrong_management_key", "invalid_public_key"),
            ("foreign_query", "foreign_session_query"),
            ("foreign_query", "foreign_api_key_query"),
        ] {
            assert_ne!(
                frozen_case(direct).1["body"],
                public_auth_expected(public).1
            );
        }
        assert_eq!(frozen_case("foreign_query").1["status"], 404);
        assert_eq!(public_auth_expected("foreign_session_query").0, 403);
        assert_eq!(public_error_expected("missing_tenant").0, 400);
        assert!(
            std::panic::catch_unwind(|| public_auth_expected("missing_management_key")).is_err()
        );
    }

    #[test]
    fn public_auth_error_comparison_is_closed_and_owner_specific() {
        for name in [
            "no_public_auth",
            "invalid_public_key",
            "foreign_session_query",
            "foreign_api_key_query",
        ] {
            let (status, mut expected) = public_auth_expected(name);
            if expected.get("message_id").is_some() {
                expected["message_id"] = json!("11111111-1111-4111-8111-111111111111");
            }
            assert_public_auth_error((status, "application/json".into(), expected.clone()), name);
            for mutation in ["extra", "message", "wrong-description", "drop-field"] {
                let mut changed = expected.clone();
                match mutation {
                    "extra" => changed["unexpected"] = json!(true),
                    "message" => changed["message_id"] = json!(MESSAGE_ID_SENTINEL),
                    "wrong-description" => {
                        let field = if changed.get("detail").is_some() {
                            "detail"
                        } else {
                            "error_description"
                        };
                        changed[field] = json!("different");
                    }
                    "drop-field" => {
                        let field = if changed.get("detail").is_some() {
                            "detail"
                        } else {
                            "error"
                        };
                        changed.as_object_mut().unwrap().remove(field);
                    }
                    _ => unreachable!(),
                }
                assert!(std::panic::catch_unwind(|| assert_public_auth_error(
                    (status, "application/json".into(), changed),
                    name
                ))
                .is_err());
            }
            assert!(std::panic::catch_unwind(|| assert_public_auth_error(
                (200, "application/json".into(), expected.clone()),
                name
            ))
            .is_err());
            assert!(std::panic::catch_unwind(|| assert_public_auth_error(
                (status, "text/plain".into(), expected),
                name
            ))
            .is_err());
        }
    }

    #[test]
    fn tenant_expectations_do_not_relax_default_explicit_query_contract() {
        let mut explicit = GatewayRequest::new(
            HttpMethod::Get,
            "/v1/integrations/canvas/canvas-sync-jobs",
            0,
        );
        explicit
            .query
            .insert("organization_id".into(), vec!["org-review".into()]);
        explicit
            .headers
            .insert("x-organization-id".into(), "org-review".into());
        UpstreamTenant::ExplicitQuery.assert_request(&explicit);
        let mut duplicate = explicit.clone();
        duplicate
            .query
            .get_mut("organization_id")
            .unwrap()
            .push("org-review".into());
        assert!(std::panic::catch_unwind(
            || UpstreamTenant::ExplicitQuery.assert_request(&duplicate)
        )
        .is_err());
        for (tenant, organization, user, key) in [
            (
                UpstreamTenant::SessionFallback,
                Some("org-review"),
                "actor-primary",
                None,
            ),
            (
                UpstreamTenant::ApiKeyFallback,
                Some("org-review"),
                "api_key:trusted-key-id",
                Some("trusted-key-id"),
            ),
            (UpstreamTenant::Absent, None, "actor-no-tenant", None),
        ] {
            let mut request = GatewayRequest::new(
                HttpMethod::Get,
                "/v1/integrations/canvas/canvas-sync-jobs",
                0,
            );
            request.headers.insert("x-user-id".into(), user.into());
            if let Some(organization) = organization {
                request
                    .headers
                    .insert("x-organization-id".into(), organization.into());
            }
            if let Some(key) = key {
                request.headers.insert("x-api-key-id".into(), key.into());
            }
            tenant.assert_request(&request);
            assert!(std::panic::catch_unwind(
                || UpstreamTenant::ExplicitQuery.assert_request(&request)
            )
            .is_err());
            for field in ["x-organization-id", "x-user-id", "x-api-key-id"] {
                let mut changed = request.clone();
                changed.headers.insert(field.into(), "forged-value".into());
                assert!(std::panic::catch_unwind(|| tenant.assert_request(&changed)).is_err());
            }
            request
                .query
                .insert("organization_id".into(), vec!["org-review".into()]);
            assert!(std::panic::catch_unwind(|| tenant.assert_request(&request)).is_err());
        }
    }

    #[test]
    fn job_state_cases_preserve_exact_frozen_order_and_setup() {
        let selected: BTreeSet<_> = NON_MANUAL_CASES
            .into_iter()
            .chain(JOB_STATE_CASES)
            .collect();
        assert_eq!(selected.len(), 13);
        let from_frozen: Vec<_> = fixtures()[1]["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|case| {
                let name = case["name"].as_str().unwrap();
                selected.contains(name).then_some(name)
            })
            .collect();
        assert_eq!(from_frozen, JOB_SEQUENCE_CASES);
        let (closed, closed_expected) = frozen_case("retry_rollout_closed");
        assert_eq!(closed["rollout"], false);
        assert_eq!(
            closed_expected["snapshot"],
            frozen_case("jobs_list").1["snapshot"]
        );
        for name in JOB_STATE_CASES {
            let (case, expected) = frozen_case(name);
            assert_eq!(case["method"], "POST");
            assert!(case.get("sql").is_none());
            assert!(case.get("body").is_none());
            assert!(case.get("rollout").is_none());
            assert_eq!(expected["lifecycle_calls"], json!([]));
            if matches!(name, "retry_foreign" | "enqueue_foreign") {
                assert_eq!(case["headers"], json!({"X-Organization-ID":"org-foreign"}));
            } else {
                assert!(case.get("headers").is_none());
            }
            if name == "enqueue_duplicate" {
                assert_eq!(expected["body"], frozen_case("enqueue").1["body"]);
                assert_eq!(expected["snapshot"], frozen_case("enqueue").1["snapshot"]);
            } else {
                assert!(matches!(public_error_expected(name).0, 404 | 409));
            }
        }
        assert_eq!(
            frozen_case("retry_again").1["snapshot"],
            frozen_case("retry_dead_letter").1["snapshot"]
        );
        assert_eq!(
            frozen_case("resolve_queued").1["snapshot"],
            frozen_case("retry_again").1["snapshot"]
        );
        assert_eq!(
            frozen_case("resolve_again").1["snapshot"],
            frozen_case("resolve_dead_letter").1["snapshot"]
        );
    }

    #[test]
    fn duplicate_enqueue_allows_only_owned_target_refresh() {
        let before = json!({
            "jobs":[{"id":"job-owned","target_id":"target-owned","status":"queued","result":{}}],
            "targets":[{"id":"target-owned","updated_at":"2026-09-08T12:00:00Z",
                "last_enqueued_at":"2026-09-08T12:00:00Z","enabled":true,
                "metadata":{"created_from":"application_sync_api"}},
                {"id":"target-unrelated","metadata":{}}],
            "events":[],"credentials":[{"id":"credential-preserved"}]
        });
        let body = json!({"id":"job-owned","target_id":"target-owned"});
        let mut after = before.clone();
        after["targets"][0]["updated_at"] = json!("2026-09-08T12:00:01Z");
        after["targets"][0]["last_enqueued_at"] = json!("2026-09-08T12:00:01Z");
        after["targets"][0]["metadata"]["last_requested_from"] = json!("application_sync_api");
        assert_duplicate_enqueue(&before, &after, &body);
        for mutation in [
            "job",
            "new-job",
            "unrelated-target",
            "target-field",
            "metadata",
            "event",
            "credential",
            "old-time",
            "invalid-time",
        ] {
            let mut changed = after.clone();
            match mutation {
                "job" => changed["jobs"][0]["result"] = json!({"unexpected":true}),
                "new-job" => changed["jobs"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"id":"extra"})),
                "unrelated-target" => {
                    changed["targets"][1]["metadata"] = json!({"unexpected":true})
                }
                "target-field" => changed["targets"][0]["enabled"] = json!(false),
                "metadata" => changed["targets"][0]["metadata"]["unexpected"] = json!(true),
                "event" => changed["events"] = json!([{"id":"extra"}]),
                "credential" => changed["credentials"] = json!([]),
                "old-time" => changed["targets"][0]["updated_at"] = json!("2026-09-08T11:59:59Z"),
                "invalid-time" => changed["targets"][0]["last_enqueued_at"] = json!("invalid"),
                _ => unreachable!(),
            }
            assert!(std::panic::catch_unwind(|| assert_duplicate_enqueue(
                &before, &changed, &body
            ))
            .is_err());
        }
        let wrong_job = json!({"id":"different-job","target_id":"target-owned"});
        assert!(
            std::panic::catch_unwind(|| assert_duplicate_enqueue(&before, &after, &wrong_job))
                .is_err()
        );
    }

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
