//! Real gateway proxy and resource-owner HTTP. The legacy owner GET remains a
//! required dependency; only the exact renewal POST is selected natively.
use super::didcomm_gateway_replay::{OwnedHttp, CLIENT_KEY};
use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use marty_gateway::{
    authorization::{OrganizationMembership, OrganizationMembershipProvider},
    contract::{route_for, GatewayContract},
    discovery::ReleaseIdentity,
    middleware::{ApiKeyIdentity, GatewayIdentityProvider, GatewayRateLimiter, SessionIdentity},
    providers::HttpGatewayProvider,
    registry::StaticServiceRegistry,
    runtime::{
        gateway_router, EventStreamProvider, EventStreamSubscription, GatewayDomainEventStream,
        GatewayRuntimeState,
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

const PATTERN: &str = "/v1/issued-credentials/{credential_id}/renew";
const LIMIT: usize = 1024 * 1024;
const FOREIGN_KEY: &str = "synthetic-renewal-foreign-key";
const SERVICE_TOKEN: &str = "synthetic-renewal-service-token-32";

fn select(original: &RouteTable, native: bool) -> RouteTable {
    let mut selected = RouteTable::default();
    let mut found = 0;
    for before in original.routes() {
        let mut after = before.clone();
        if before.pattern == PATTERN && before.methods.contains(&HttpMethod::Post) {
            found += 1;
            assert_eq!(before.methods.len(), 1);
            assert_eq!(before.upstream_service, "issuance-native");
            assert!(before.auth_required);
            assert!(before.rewrite_path.is_none());
            if !native {
                after.upstream_service = "issuance".into();
            }
        }
        let mut restored = after.clone();
        restored
            .upstream_service
            .clone_from(&before.upstream_service);
        assert_eq!(&restored, before, "no other route policy may change");
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
        usize::from(!native)
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
        Ok(
            matches!(key, CLIENT_KEY | FOREIGN_KEY).then(|| ApiKeyIdentity {
                api_key_id: "synthetic-renewal-caller".into(),
                organization_id: Some(if key == FOREIGN_KEY {
                    "foreign-organization".into()
                } else {
                    self.organization.clone()
                }),
                key_prefix: Some("synthetic".into()),
                scopes: vec!["credentials:issue".into()],
            }),
        )
    }
}
#[async_trait]
impl OrganizationMembershipProvider for Identities {
    async fn get_membership(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<OrganizationMembership>, SecurityError> {
        panic!("API-key renewal must not request session membership")
    }
}
struct UnusedEvents;
#[async_trait]
impl EventStreamProvider for UnusedEvents {
    async fn subscribe(
        &self,
        _: EventStreamSubscription,
    ) -> Result<GatewayDomainEventStream, SecurityError> {
        panic!("unexpected renewal event stream")
    }
}

#[derive(Clone, Copy)]
enum OwnerResponse {
    Found,
    NotFound,
    Unavailable,
}

#[derive(Default)]
struct LegacyCounts {
    attempts: AtomicUsize,
    owners: AtomicUsize,
    posts: AtomicUsize,
    owner_response: AtomicUsize,
}

struct CountedHttp {
    transport: ReqwestUpstream,
    native: AtomicUsize,
    legacy: AtomicUsize,
    organization: String,
    management_key: String,
    path: String,
    last_native_response: Mutex<Option<Value>>,
}
#[async_trait]
impl UpstreamClient for CountedHttp {
    async fn send(
        &self,
        instance: &ServiceInstance,
        request: GatewayRequest,
    ) -> Result<GatewayResponse, PlatformError> {
        match instance.service_name.as_str() {
            "issuance-native" => &self.native,
            "issuance" => &self.legacy,
            _ => panic!("unexpected renewal upstream"),
        }
        .fetch_add(1, Ordering::SeqCst);
        assert_eq!(request.method, HttpMethod::Post);
        assert_eq!(request.path, self.path);
        assert!(
            request.header("x-api-key") == Some(self.management_key.as_str()),
            "management credential must replace caller key"
        );
        assert_eq!(
            request.header("x-organization-id"),
            Some(self.organization.as_str())
        );
        assert_eq!(
            request.header("x-api-key-id"),
            Some("synthetic-renewal-caller")
        );
        assert!(request.header("x-authenticated-user-id").is_none());
        assert!(request
            .headers
            .values()
            .all(|value| !value.contains("forged-")));
        let response = self.transport.send(instance, request).await?;
        if instance.service_name == "issuance-native" {
            *self.last_native_response.lock().unwrap() =
                Some(serde_json::from_slice(response.body.as_ref().unwrap()).unwrap());
        }
        Ok(response)
    }
}

pub(super) struct GatewayFixture {
    router: Router,
    legacy_control: Router,
    native: Option<OwnedHttp>,
    legacy: OwnedHttp,
    counted: Arc<CountedHttp>,
    legacy_counts: Arc<LegacyCounts>,
    path: String,
}
impl GatewayFixture {
    pub(super) async fn start(
        native_router: Router,
        organization: &str,
        management_key: &str,
        source_id: &str,
    ) -> Self {
        let path = format!("/v1/issued-credentials/{source_id}/renew");
        let owner_path = format!("/internal/v1/resource-owners/issued-credentials/{source_id}");
        let native = OwnedHttp::start(native_router).await;
        let legacy_counts = Arc::new(LegacyCounts::default());
        let observed = legacy_counts.clone();
        let expected_path = path.clone();
        let expected_key = management_key.to_owned();
        let expected_org = organization.to_owned();
        let legacy = OwnedHttp::start(Router::new().fallback(move |request: Request<Body>| {
            let observed = observed.clone();
            let owner_path = owner_path.clone();
            let expected_path = expected_path.clone();
            let expected_key = expected_key.clone();
            let expected_org = expected_org.clone();
            async move {
                // Count before inspecting method, path or credentials: malformed
                // requests must not masquerade as zero network attempts.
                observed.attempts.fetch_add(1, Ordering::SeqCst);
                assert!(request.headers().get("x-api-key").is_some_and(|value| value == expected_key.as_str()), "legacy request requires management authentication");
                assert!(request.headers().values().all(|value| !value.to_str().unwrap().contains("forged-")));
                if request.method() == axum::http::Method::GET && request.uri().path() == owner_path {
                    assert!(request.headers().get("x-service-token").is_some_and(|value| value == SERVICE_TOKEN), "owner provider requires service authentication");
                    assert_eq!(request.headers()["x-api-key-id"], "synthetic-renewal-caller");
                    observed.owners.fetch_add(1, Ordering::SeqCst);
                    match observed.owner_response.load(Ordering::SeqCst) {
                        value if value == OwnerResponse::Found as usize =>
                            (StatusCode::OK, axum::Json(json!({"organization_id": expected_org}))),
                        value if value == OwnerResponse::NotFound as usize =>
                            (StatusCode::NOT_FOUND, axum::Json(json!({"detail":"Resource not found"}))),
                        value if value == OwnerResponse::Unavailable as usize =>
                            (StatusCode::SERVICE_UNAVAILABLE, axum::Json(json!({"detail":"Synthetic owner unavailable"}))),
                        _ => panic!("unknown controlled owner response"),
                    }
                } else {
                    assert_eq!(request.method(), axum::http::Method::POST);
                    assert_eq!(request.uri().path(), expected_path);
                    // Ordinary issuance proxy uses its management key; the
                    // owner provider independently injects its service token.
                    assert!(request.headers().get("x-service-token").is_none());
                    observed.posts.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::IM_A_TEAPOT, axum::Json(json!({
                        "error":"owned_legacy_trap", "error_description":"Owned renewal legacy selection control",
                        "message_id":"11111111-1111-4111-8111-111111111111"
                    })))
                }
            }
        })).await;
        assert_ne!(native.port, legacy.port);
        let urls = BTreeMap::from([
            (
                "issuance".into(),
                format!("http://127.0.0.1:{}", legacy.port),
            ),
            (
                "issuance-native".into(),
                format!("http://127.0.0.1:{}", native.port),
            ),
        ]);
        let owners = Arc::new(
            HttpGatewayProvider::new(
                urls.clone(),
                "synthetic-internal-key",
                Some(management_key.into()),
                Some(SERVICE_TOKEN.into()),
                Some(LIMIT),
            )
            .unwrap(),
        );
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
            path: path.clone(),
            last_native_response: Mutex::new(None),
        });
        let build = |candidate| {
            let contract = GatewayContract::load().unwrap();
            let proxy = GatewayProxy::new(
                select(&contract.proxy_route_table().unwrap(), candidate),
                Arc::new(StaticServiceRegistry::from_urls(&urls).unwrap()),
                counted.clone(),
                ProxyConfig::default(),
            )
            .unwrap();
            let identities = Arc::new(Identities {
                organization: organization.into(),
            });
            let state = GatewayRuntimeState::new(
                select(&contract.runtime_route_table().unwrap(), candidate),
                proxy,
                identities.clone(),
                identities,
                owners.clone(),
                owners.clone(),
                Arc::new(UnusedEvents),
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
            .with_service_token(Some(SERVICE_TOKEN.into()))
            .unwrap();
            gateway_router(Arc::new(state))
        };
        Self {
            router: build(true),
            legacy_control: build(false),
            native: Some(native),
            legacy,
            counted,
            legacy_counts,
            path,
        }
    }

    /// Issuance POST attempts only; required owner GETs are measured separately.
    pub(super) fn counts(&self) -> (usize, usize) {
        (
            self.counted.native.load(Ordering::SeqCst),
            self.counted.legacy.load(Ordering::SeqCst),
        )
    }
    pub(super) fn owner_count(&self) -> usize {
        self.legacy_counts.owners.load(Ordering::SeqCst)
    }

    fn assert_no_unexpected_legacy_requests(&self) {
        assert_eq!(
            self.legacy_counts.attempts.load(Ordering::SeqCst),
            self.owner_count() + self.legacy_counts.posts.load(Ordering::SeqCst)
        );
        assert_eq!(
            self.legacy_counts.posts.load(Ordering::SeqCst),
            self.counts().1
        );
    }

    pub(super) async fn assert_selection_and_denials(&self) {
        let (status, body) = request(&self.legacy_control, &self.path, Some(CLIENT_KEY)).await;
        assert_eq!(status, StatusCode::IM_A_TEAPOT);
        assert_eq!(
            body,
            json!({"error":"owned_legacy_trap", "error_description":"Owned renewal legacy selection control", "message_id":"11111111-1111-4111-8111-111111111111"})
        );
        assert_eq!(self.counts(), (0, 1));
        assert_eq!(
            self.owner_count(),
            1,
            "authenticated owner GET remains required before selected POST"
        );
        for key in [None, Some("invalid-key")] {
            let (status, body) = request(&self.router, &self.path, key).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            let id = body["message_id"].as_str().unwrap();
            assert!(uuid::Uuid::parse_str(id).is_ok());
            assert_eq!(
                body,
                json!({"error":"unauthorized", "error_description": if key.is_none() { "Authentication required" } else { "Invalid or expired API key" }, "message_id":id})
            );
            assert_eq!(self.counts(), (0, 1));
            assert_eq!(
                self.owner_count(),
                1,
                "authentication must precede owner lookup"
            );
        }
        assert_eq!(
            request(&self.router, &self.path, Some(FOREIGN_KEY)).await,
            (
                StatusCode::FORBIDDEN,
                json!({"detail":"API key does not have access to this organization"})
            )
        );
        assert_eq!(self.counts(), (0, 1), "foreign tenant cannot call renewal");
        assert_eq!(
            self.owner_count(),
            2,
            "foreign tenant is checked against actual owner result"
        );
        self.legacy_counts
            .owner_response
            .store(OwnerResponse::Unavailable as usize, Ordering::SeqCst);
        assert_eq!(
            request(&self.router, &self.path, Some(CLIENT_KEY)).await,
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"detail":"Authorization service unavailable"})
            )
        );
        assert_eq!(
            self.counts(),
            (0, 1),
            "owner outage must fail before either renewal POST"
        );
        assert_eq!(self.owner_count(), 3);
        self.legacy_counts
            .owner_response
            .store(OwnerResponse::Found as usize, Ordering::SeqCst);
        self.assert_no_unexpected_legacy_requests();
    }

    /// Invoke on a separate fixture whose source ID is genuinely absent in its
    /// real native repository. Existing gateway policy falls back to the trusted
    /// caller tenant on owner 404; the actual native source lookup must still 404.
    pub(super) async fn assert_missing_owner_uses_native_source_check(&self) {
        assert_eq!(self.counts(), (0, 0));
        assert_eq!(self.owner_count(), 0);
        self.legacy_counts
            .owner_response
            .store(OwnerResponse::NotFound as usize, Ordering::SeqCst);
        let (status, body) = request(&self.router, &self.path, Some(CLIENT_KEY)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            super::didcomm_gateway_replay::assert_service_error_projection(body),
            json!({"detail":"Issued credential not found"})
        );
        assert_eq!(
            self.counts(),
            (1, 0),
            "404 owner fallback retains exactly one authoritative native source check"
        );
        assert_eq!(self.owner_count(), 1);
        assert_eq!(
            self.counted.last_native_response.lock().unwrap().as_ref(),
            Some(&json!({"detail":"Issued credential not found"}))
        );
        self.legacy_counts
            .owner_response
            .store(OwnerResponse::Found as usize, Ordering::SeqCst);
        self.assert_no_unexpected_legacy_requests();
    }

    pub(super) async fn renew(&self) -> (StatusCode, Value) {
        let before = self.counts();
        let owners = self.owner_count();
        let response = request(&self.router, &self.path, Some(CLIENT_KEY)).await;
        assert_eq!(self.counts(), (before.0 + 1, before.1));
        assert_eq!(self.owner_count(), owners + 1);
        self.assert_no_unexpected_legacy_requests();
        if response.0.is_success() {
            self.assert_public_offer_projection(&response.1);
        }
        response
    }

    pub(super) fn assert_public_offer_projection(&self, public: &Value) {
        let native = self.counted.last_native_response.lock().unwrap();
        assert_eq!(
            Some(public),
            native.as_ref(),
            "gateway must preserve full renewal response"
        );
        let mut keys: Vec<_> = public
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "credential_offer_labels",
                "credential_offer_uri",
                "credential_offer_uris",
                "expires_at",
                "source_credential_id",
                "transaction_id"
            ]
        );
    }

    pub(super) async fn assert_unreachable_without_legacy_fallback(&mut self) {
        self.native.take().unwrap().close().await;
        let before = self.counts();
        let owners = self.owner_count();
        let (status, _) = request(&self.router, &self.path, Some(CLIENT_KEY)).await;
        assert!(status.is_server_error());
        assert!(self.counts().0 > before.0);
        assert_eq!(self.counts().1, before.1);
        assert_eq!(self.owner_count(), owners + 1);
        self.assert_no_unexpected_legacy_requests();
    }

    pub(super) async fn close(self) {
        self.assert_no_unexpected_legacy_requests();
        if let Some(native) = self.native {
            native.close().await;
        }
        self.legacy.close().await;
    }
}

async fn request(router: &Router, path: &str, key: Option<&str>) -> (StatusCode, Value) {
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
            .oneshot(request.body(Body::from("{}")).unwrap()),
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
    (
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), LIMIT).await.unwrap()).unwrap(),
    )
}

#[test]
fn renewal_selection_preserves_all_other_routes_and_rejects_lookalikes() {
    let contract = GatewayContract::load().unwrap();
    for original in [
        contract.runtime_route_table().unwrap(),
        contract.proxy_route_table().unwrap(),
    ] {
        for candidate in [true, false] {
            select(&original, candidate);
        }
        for (method, path) in [
            (HttpMethod::Get, "/v1/issued-credentials/credential-1/renew"),
            (
                HttpMethod::Post,
                "/v1/issued-credentials/credential-1/renew/extra",
            ),
            (
                HttpMethod::Post,
                "/v1/issued-credentials/credential-1/renewal",
            ),
            (
                HttpMethod::Post,
                "/v1/issued-credentials/credential-1/revoke",
            ),
            (HttpMethod::Get, "/v1/issued-credentials/credential-1"),
        ] {
            if let Ok(found) = route_for(&original, method, path) {
                assert_ne!(
                    found.route.pattern, PATTERN,
                    "lookalike or sibling must not select renewal"
                );
            }
        }
    }
}
