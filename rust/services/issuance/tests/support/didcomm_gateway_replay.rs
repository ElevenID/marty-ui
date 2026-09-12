//! Direct selected-route and initiation candidate qualification share one gateway
//! fixture. Gateway middleware/proxy and issuance upstream HTTP are real; identity
//! and initiation control-plane preflights are controlled. Only the exact consumer
//! owner may differ; direct native routing is already selected in the contract.
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
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tower::ServiceExt;

pub(super) const CLIENT_KEY: &str = "synthetic-didcomm-caller-key";
const PATH: &str = "/v1/issuance/didcomm/deliver";
const INITIATION_PATH: &str = "/v1/issuance";
const LIMIT: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Consumer {
    Direct,
    Initiation,
}

impl Consumer {
    fn path(self) -> &'static str {
        match self {
            Self::Direct => PATH,
            Self::Initiation => INITIATION_PATH,
        }
    }
}

pub(super) fn assert_service_error_projection(body: Value) -> Value {
    let id = body["message_id"].as_str().expect("MIP error UUID");
    assert!(uuid::Uuid::parse_str(id).is_ok());
    let description = body["error_description"]
        .as_str()
        .expect("MIP error description");
    // Validate every gateway field before comparing shared native string-detail
    // expectations. This is the pinned MMF proxy envelope, not a new normalizer.
    assert_eq!(
        body,
        json!({"error":"service_error","error_description":description,"message_id":id})
    );
    json!({"detail":description})
}

fn select_direct(original: RouteTable, candidate: bool) -> RouteTable {
    select_consumer(original, candidate, Consumer::Direct)
}

fn select_consumer(original: RouteTable, candidate: bool, consumer: Consumer) -> RouteTable {
    let mut selected = RouteTable::default();
    let mut found = 0;
    for before in original.routes() {
        let mut after = before.clone();
        if before.pattern == consumer.path() && before.methods.contains(&HttpMethod::Post) {
            found += 1;
            assert_eq!(before.methods.len(), 1);
            assert_eq!(
                before.upstream_service,
                if consumer == Consumer::Direct {
                    "issuance-native"
                } else {
                    "issuance"
                },
                "only direct delivery has already been selected in the embedded contract"
            );
            assert!(before.auth_required);
            after.upstream_service = if candidate {
                "issuance-native"
            } else {
                "issuance"
            }
            .into();
            if consumer == Consumer::Initiation {
                assert_eq!(
                    before.rewrite_path.as_deref(),
                    Some("/v1/issuance/initiate")
                );
            }
        }
        let mut restored = after.clone();
        restored
            .upstream_service
            .clone_from(&before.upstream_service);
        assert_eq!(
            &restored, before,
            "no non-selection route policy may change"
        );
        selected.add(after).unwrap();
    }
    assert_eq!(found, 1);
    assert_eq!(selected.routes().len(), original.routes().len());
    assert_eq!(
        original
            .routes()
            .iter()
            .zip(selected.routes())
            .filter(|(a, b)| a != b)
            .count(),
        usize::from(if consumer == Consumer::Direct {
            !candidate
        } else {
            candidate
        }),
        "only the exact consumer owner can differ from the embedded contract"
    );
    selected
}

struct Identities {
    organization: String,
}
#[async_trait]
impl GatewayIdentityProvider for Identities {
    async fn validate_session(&self, _: &str) -> Result<Option<SessionIdentity>, SecurityError> {
        Ok(None)
    }
    async fn validate_api_key(&self, key: &str) -> Result<Option<ApiKeyIdentity>, SecurityError> {
        Ok((key == CLIENT_KEY).then(|| ApiKeyIdentity {
            api_key_id: "synthetic-didcomm-caller".into(),
            organization_id: Some(self.organization.clone()),
            key_prefix: Some("synthetic".into()),
            scopes: vec!["credentials:issue".into()],
        }))
    }
}
#[async_trait]
impl OrganizationMembershipProvider for Identities {
    async fn get_membership(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<OrganizationMembership>, SecurityError> {
        panic!("API-key fixture must not request session membership")
    }
}
struct Unused;
#[async_trait]
impl ResourceOwnerProvider for Unused {
    async fn resolve_organization(
        &self,
        _: &str,
        _: &str,
        _: &ResourceOwnerContext,
    ) -> Result<Option<String>, SecurityError> {
        panic!("DIDComm must validate its body tenant without a resource-owner lookup")
    }
}
#[async_trait]
impl ReadinessProvider for Unused {
    async fn check_services(&self, _: &[String]) -> BTreeMap<String, ReadinessServiceStatus> {
        panic!("unexpected readiness")
    }
    fn all_services(&self) -> Vec<String> {
        vec![]
    }
}
#[async_trait]
impl EventStreamProvider for Unused {
    async fn subscribe(
        &self,
        _: EventStreamSubscription,
    ) -> Result<GatewayDomainEventStream, SecurityError> {
        panic!("unexpected event stream")
    }
}

struct CountedHttp {
    transport: ReqwestUpstream,
    native: AtomicUsize,
    legacy: AtomicUsize,
    organization: String,
    management_key: String,
    issuer: Option<String>,
    ancillary: AtomicUsize,
    last_native_response: Mutex<Option<Value>>,
}
#[async_trait]
impl UpstreamClient for CountedHttp {
    async fn send(
        &self,
        instance: &ServiceInstance,
        request: GatewayRequest,
    ) -> Result<GatewayResponse, PlatformError> {
        // Only control-plane dependencies are controlled. The actual issuance
        // request always traverses ReqwestUpstream into the native HTTP router.
        if matches!(
            instance.service_name.as_str(),
            "credential-templates" | "signing-keys"
        ) {
            let issuer = self
                .issuer
                .as_ref()
                .expect("direct delivery has no admission preflight");
            self.ancillary.fetch_add(1, Ordering::SeqCst);
            let body = if instance.service_name == "credential-templates" {
                assert_eq!(request.method, HttpMethod::Get);
                assert_eq!(request.path, "/v1/credential-templates/didcomm%2Dtemplate");
                assert_eq!(
                    request.header("x-organization-id"),
                    Some(self.organization.as_str())
                );
                json!({"id":"didcomm-template", "organization_id":self.organization,
                    "issuer_did":issuer, "credential_payload_format":"w3c_vcdm_v2_sd_jwt"})
            } else {
                assert_eq!(request.method, HttpMethod::Post);
                assert_eq!(request.path, "/internal/compat/resolve-issuer-did");
                assert_eq!(request.header("x-api-key"), Some("synthetic-signing-key"));
                let body: Value = serde_json::from_slice(request.body.as_ref().unwrap()).unwrap();
                assert_eq!(
                    body,
                    json!({"organization_id":self.organization, "issuer_did":issuer,
                    "credential_format":"dc+sd-jwt", "key_purpose":"vc_jwt_issuer"})
                );
                json!({"ok":true,"organization_id":self.organization,"issuer_did":issuer,
                    "key_purpose":"vc_jwt_issuer","verification_method_id":format!("{issuer}#signing"),
                    "public_jwk":{"kty":"OKP","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}})
            };
            return Ok(GatewayResponse {
                status_code: 200,
                headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
                body: Some(serde_json::to_vec(&body).unwrap()),
                response_time_ms: None,
                upstream_service: None,
            });
        }
        match instance.service_name.as_str() {
            "issuance-native" => &self.native,
            "issuance" => &self.legacy,
            _ => panic!("unexpected DIDComm upstream"),
        }
        .fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            request.header("x-api-key"),
            Some(self.management_key.as_str())
        );
        assert_ne!(request.header("x-api-key"), Some(CLIENT_KEY));
        assert_eq!(
            request.header("x-organization-id"),
            Some(self.organization.as_str())
        );
        assert_eq!(
            request.header("x-api-key-id"),
            Some("synthetic-didcomm-caller")
        );
        assert!(request.header("x-authenticated-user-id").is_none());
        assert!(request
            .headers
            .values()
            .all(|value| !value.contains("forged-")));
        if self.issuer.is_some() {
            assert_eq!(request.path, "/v1/issuance/initiate");
        }
        let response = self.transport.send(instance, request).await?;
        if instance.service_name == "issuance-native" && self.issuer.is_some() {
            *self.last_native_response.lock().unwrap() =
                Some(serde_json::from_slice(response.body.as_ref().unwrap()).unwrap());
        }
        Ok(response)
    }
}

struct OwnedHttp {
    port: u16,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}
impl OwnedHttp {
    async fn start(router: Router) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
        });
        Self {
            port,
            stop: Some(stop),
            task,
        }
    }
    async fn close(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), &mut self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
impl Drop for OwnedHttp {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(super) struct GatewayFixture {
    pub(super) router: Router,
    legacy_control: Router,
    native: Option<OwnedHttp>,
    legacy: OwnedHttp,
    counted: Arc<CountedHttp>,
    legacy_requests: Arc<AtomicUsize>,
    consumer: Consumer,
}

impl GatewayFixture {
    pub(super) async fn start(
        native_router: Router,
        organization: &str,
        management_key: &str,
    ) -> Self {
        Self::start_consumer(
            native_router,
            organization,
            management_key,
            Consumer::Direct,
            None,
        )
        .await
    }

    pub(super) async fn start_initiation(
        native_router: Router,
        organization: &str,
        management_key: &str,
        issuer: &str,
    ) -> Self {
        Self::start_consumer(
            native_router,
            organization,
            management_key,
            Consumer::Initiation,
            Some(issuer.into()),
        )
        .await
    }

    async fn start_consumer(
        native_router: Router,
        organization: &str,
        management_key: &str,
        consumer: Consumer,
        issuer: Option<String>,
    ) -> Self {
        let native = OwnedHttp::start(native_router).await;
        let legacy_requests = Arc::new(AtomicUsize::new(0));
        let observed = legacy_requests.clone();
        let legacy = OwnedHttp::start(Router::new().fallback(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            async { (StatusCode::IM_A_TEAPOT, axum::Json(json!({
                "error":"owned_legacy_trap", "error_description":"Owned legacy selection control",
                "message_id":"11111111-1111-4111-8111-111111111111"
            }))) }
        })).await;
        assert_ne!(native.port, legacy.port);
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let counted = Arc::new(CountedHttp {
            transport: ReqwestUpstream::with_client(LIMIT, client).unwrap(),
            native: AtomicUsize::new(0),
            legacy: AtomicUsize::new(0),
            organization: organization.into(),
            management_key: management_key.into(),
            issuer,
            ancillary: AtomicUsize::new(0),
            last_native_response: Mutex::new(None),
        });
        let build = |candidate| {
            let contract = GatewayContract::load().unwrap();
            let routes =
                select_consumer(contract.runtime_route_table().unwrap(), candidate, consumer);
            let proxy_routes =
                select_consumer(contract.proxy_route_table().unwrap(), candidate, consumer);
            let registry = StaticServiceRegistry::from_urls(&BTreeMap::from([
                (
                    "issuance".into(),
                    format!("http://127.0.0.1:{}", legacy.port),
                ),
                (
                    "issuance-native".into(),
                    format!("http://127.0.0.1:{}", native.port),
                ),
                (
                    "credential-templates".into(),
                    format!("http://127.0.0.1:{}", native.port),
                ),
                (
                    "signing-keys".into(),
                    format!("http://127.0.0.1:{}", native.port),
                ),
            ]))
            .unwrap();
            let proxy = GatewayProxy::new(
                proxy_routes,
                Arc::new(registry),
                counted.clone(),
                ProxyConfig::default(),
            )
            .unwrap();
            let identities = Arc::new(Identities {
                organization: organization.into(),
            });
            let state = GatewayRuntimeState::new(
                routes,
                proxy,
                identities.clone(),
                identities,
                Arc::new(Unused),
                Arc::new(Unused),
                Arc::new(Unused),
                vec![],
                GatewayRateLimiter::new(Arc::new(InMemoryRateLimiter::default()), 120).unwrap(),
                Arc::new(InMemoryIdempotencyStore::new(60_000, 5_000).unwrap()),
                ["https://wallet.example".into()],
                "https://issuer.example",
                "https://issuer.example",
                "issuer.example",
                None,
                "synthetic-signing-key",
                management_key,
                ReleaseIdentity::default(),
            )
            .unwrap()
            .with_service_token(Some("s".repeat(32)))
            .unwrap();
            gateway_router(Arc::new(state))
        };
        Self {
            router: build(true),
            legacy_control: build(false),
            native: Some(native),
            legacy,
            counted,
            legacy_requests,
            consumer,
        }
    }

    pub(super) fn counts(&self) -> (usize, usize) {
        (
            self.counted.native.load(Ordering::SeqCst),
            self.counted.legacy.load(Ordering::SeqCst),
        )
    }

    pub(super) async fn assert_selection_and_denials(&self, body: &Value) {
        assert_eq!(self.consumer, Consumer::Direct);
        let (status, legacy_body) =
            request(&self.legacy_control, body.clone(), Some(CLIENT_KEY)).await;
        assert_eq!(status, StatusCode::IM_A_TEAPOT);
        assert_eq!(
            legacy_body,
            json!({"error":"owned_legacy_trap", "error_description":"Owned legacy selection control", "message_id":"11111111-1111-4111-8111-111111111111"})
        );
        assert_eq!(self.counts(), (0, 1));
        assert_eq!(self.legacy_requests.load(Ordering::SeqCst), 1);
        for (key, changed, expected) in [
            (None, body.clone(), StatusCode::UNAUTHORIZED),
            (Some("bad-key"), body.clone(), StatusCode::UNAUTHORIZED),
            (
                Some(CLIENT_KEY),
                {
                    let mut changed = body.clone();
                    changed["organization_id"] = json!("foreign-organization");
                    changed
                },
                StatusCode::FORBIDDEN,
            ),
        ] {
            let (status, response) = request(&self.router, changed, key).await;
            assert_eq!(status, expected);
            if status == StatusCode::UNAUTHORIZED {
                let id = response["message_id"].as_str().unwrap();
                assert!(uuid::Uuid::parse_str(id).is_ok());
                assert_eq!(
                    response,
                    json!({"error":"unauthorized", "error_description":if key.is_none() { "Authentication required" } else { "Invalid or expired API key" }, "message_id":id})
                );
            } else {
                assert_eq!(
                    response,
                    json!({"detail":"API key does not have access to this organization"})
                );
            }
            assert_eq!(self.counts(), (0, 1), "denial precedes either upstream");
        }
        for changed in [
            {
                let mut changed = body.clone();
                changed["sender_private_key"] = json!("synthetic-rejected-selector");
                changed
            },
            {
                let mut changed = body.clone();
                changed["holder_did"] = json!("not-a-did");
                changed
            },
            {
                let mut changed = body.clone();
                changed["transaction_id"] = json!("");
                changed
            },
        ] {
            assert_eq!(
                request(&self.router, changed, Some(CLIENT_KEY)).await,
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    json!({"detail":"DIDComm delivery request is outside the public contract"})
                )
            );
            assert_eq!(self.counts(), (0, 1), "validation precedes either upstream");
        }
    }

    pub(super) async fn assert_unreachable_without_legacy_fallback(&mut self, body: &Value) {
        self.native.take().unwrap().close().await;
        let before = self.counts();
        let (status, _) = request_at(
            &self.router,
            self.consumer.path(),
            body.clone(),
            Some(CLIENT_KEY),
        )
        .await;
        assert!(status.is_server_error());
        let after = self.counts();
        assert!(after.0 > before.0);
        assert_eq!(after.1, before.1);
        assert_eq!(self.legacy_requests.load(Ordering::SeqCst), 1);
    }

    pub(super) async fn initiate(&self, body: &Value) -> (StatusCode, Value) {
        assert_eq!(self.consumer, Consumer::Initiation);
        request_at(
            &self.router,
            INITIATION_PATH,
            body.clone(),
            Some(CLIENT_KEY),
        )
        .await
    }

    pub(super) fn assert_public_offer_projection(&self, public: &Value) -> Value {
        assert_eq!(
            self.counted.ancillary.load(Ordering::SeqCst),
            4,
            "one template and signing-identity preflight per legacy/candidate request"
        );
        let native = self
            .counted
            .last_native_response
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(native.as_object().unwrap().len(), 9);
        assert!(native["pre_auth_code"].is_string());
        let mut expected = native.clone();
        expected.as_object_mut().unwrap().remove("pre_auth_code");
        assert_eq!(
            public, &expected,
            "exact eight-field public response must omit only the top-level internal code"
        );
        assert_eq!(public.as_object().unwrap().len(), 8);
        native
    }

    pub(super) async fn assert_initiation_selection_and_denials(&self, body: &Value) {
        assert_eq!(self.consumer, Consumer::Initiation);
        let (status, response) = request_at(
            &self.legacy_control,
            INITIATION_PATH,
            body.clone(),
            Some(CLIENT_KEY),
        )
        .await;
        assert_eq!(status, StatusCode::IM_A_TEAPOT);
        assert_eq!(
            response,
            json!({"error":"owned_legacy_trap", "error_description":"Owned legacy selection control", "message_id":"11111111-1111-4111-8111-111111111111"})
        );
        assert_eq!(self.counts(), (0, 1));
        assert_eq!(self.legacy_requests.load(Ordering::SeqCst), 1);
        assert_eq!(self.counted.ancillary.load(Ordering::SeqCst), 2);
        for (key, changed, expected) in [
            (None, body.clone(), StatusCode::UNAUTHORIZED),
            (Some("bad-key"), body.clone(), StatusCode::UNAUTHORIZED),
            (
                Some(CLIENT_KEY),
                {
                    let mut changed = body.clone();
                    changed["organization_id"] = json!("foreign-organization");
                    changed
                },
                StatusCode::FORBIDDEN,
            ),
            (
                Some(CLIENT_KEY),
                {
                    let mut changed = body.clone();
                    changed["sender_private_key"] = json!("synthetic-rejected-selector");
                    changed
                },
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ] {
            let (status, response) = request_at(&self.router, INITIATION_PATH, changed, key).await;
            assert_eq!(status, expected);
            match expected {
                StatusCode::UNAUTHORIZED => {
                    let id = response["message_id"].as_str().unwrap();
                    assert!(uuid::Uuid::parse_str(id).is_ok());
                    assert_eq!(
                        response,
                        json!({"error":"unauthorized","error_description":if key.is_none() {"Authentication required"} else {"Invalid or expired API key"},"message_id":id})
                    );
                }
                StatusCode::FORBIDDEN => assert_eq!(
                    response,
                    json!({"detail":"API key does not have access to this organization"})
                ),
                _ => assert_eq!(
                    response,
                    json!({"detail":"Issuance request is outside the public contract"})
                ),
            }
            assert_eq!(self.counts(), (0, 1));
            assert_eq!(
                self.counted.ancillary.load(Ordering::SeqCst),
                2,
                "denial precedes even control-plane preflights"
            );
        }
    }

    pub(super) async fn close(self) {
        if let Some(native) = self.native {
            native.close().await;
        }
        self.legacy.close().await;
    }
}

async fn request(router: &Router, body: Value, key: Option<&str>) -> (StatusCode, Value) {
    request_at(router, PATH, body, key).await
}

async fn request_at(
    router: &Router,
    path: &str,
    body: Value,
    key: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::post(path)
        .header("content-type", "application/json")
        .header("x-organization-id", "forged-organization")
        .header("x-user-id", "forged-user")
        .header("x-api-key-id", "forged-key")
        .header("x-authenticated-user-id", "forged-actor");
    if let Some(key) = key {
        request = request.header("x-api-key", key);
    }
    let response = tokio::time::timeout(
        Duration::from_secs(15),
        router
            .clone()
            .oneshot(request.body(Body::from(body.to_string())).unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    let status = response.status();
    assert_eq!(
        response.headers()["content-type"]
            .to_str()
            .unwrap()
            .split(';')
            .next(),
        Some("application/json")
    );
    let body =
        serde_json::from_slice(&to_bytes(response.into_body(), LIMIT).await.unwrap()).unwrap();
    (status, body)
}

#[test]
fn native_selection_is_unchanged_and_legacy_control_changes_only_direct_owner() {
    let contract = GatewayContract::load().unwrap();
    for candidate in [true, false] {
        select_direct(contract.runtime_route_table().unwrap(), candidate);
        select_direct(contract.proxy_route_table().unwrap(), candidate);
    }
}

#[test]
fn initiation_candidate_changes_only_the_existing_rewritten_post_owner() {
    let contract = GatewayContract::load().unwrap();
    for candidate in [true, false] {
        select_consumer(
            contract.runtime_route_table().unwrap(),
            candidate,
            Consumer::Initiation,
        );
        select_consumer(
            contract.proxy_route_table().unwrap(),
            candidate,
            Consumer::Initiation,
        );
    }
}
