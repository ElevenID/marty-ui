//! Production Gateway and HTTP upstream around the actual Flow router.
use async_trait::async_trait;
use axum::{
    extract::Request,
    middleware::{self, Next},
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
use mmf_platform::{GatewayProxy, InMemoryIdempotencyStore, ProxyConfig};
use mmf_security::{InMemoryRateLimiter, SecurityError};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

const WORKLOAD: &str = "public-demo-gateway-workload-credential-0001";
struct NoVisitorAuthority;
#[async_trait]
impl GatewayIdentityProvider for NoVisitorAuthority {
    async fn validate_session(&self, _: &str) -> Result<Option<SessionIdentity>, SecurityError> {
        Ok(None)
    }
    async fn validate_api_key(&self, _: &str) -> Result<Option<ApiKeyIdentity>, SecurityError> {
        Ok(None)
    }
}
#[async_trait]
impl OrganizationMembershipProvider for NoVisitorAuthority {
    async fn get_membership(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<OrganizationMembership>, SecurityError> {
        panic!("anonymous verification has no visitor membership")
    }
}
#[async_trait]
impl ResourceOwnerProvider for NoVisitorAuthority {
    async fn resolve_organization(
        &self,
        _: &str,
        _: &str,
        _: &ResourceOwnerContext,
    ) -> Result<Option<String>, SecurityError> {
        panic!("public catalog owns the tenant")
    }
}
#[async_trait]
impl EventStreamProvider for NoVisitorAuthority {
    async fn subscribe(
        &self,
        _: EventStreamSubscription,
    ) -> Result<GatewayDomainEventStream, SecurityError> {
        panic!("verification uses no management stream")
    }
}
#[async_trait]
impl ReadinessProvider for NoVisitorAuthority {
    async fn check_services(&self, _: &[String]) -> BTreeMap<String, ReadinessServiceStatus> {
        BTreeMap::new()
    }
    fn all_services(&self) -> Vec<String> {
        vec![]
    }
}

pub struct PublicGateway {
    pub router: Router,
    pub observed: Arc<AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
    public_server: Option<tokio::task::JoinHandle<()>>,
}
impl Drop for PublicGateway {
    fn drop(&mut self) {
        self.server.abort();
        if let Some(server) = &self.public_server {
            server.abort();
        }
    }
}

pub async fn wrap(
    flow: Router,
    origin: &str,
    public_listener: Option<tokio::net::TcpListener>,
) -> PublicGateway {
    let observed = Arc::new(AtomicUsize::new(0));
    let counter = observed.clone();
    let flow = flow.layer(middleware::from_fn(move |request: Request, next: Next| {
        let counter = counter.clone();
        async move {
            assert_eq!(request.headers()["x-service-token"], WORKLOAD);
            for name in [
                "cookie",
                "authorization",
                "x-api-key",
                "x-user-id",
                "x-organization-id",
                "x-api-key-id",
                "x-api-key-scopes",
                "x-authenticated-user-id",
                "idempotency-key",
                "if-none-match",
            ] {
                assert!(
                    !request.headers().contains_key(name),
                    "visitor {name} reached Flow"
                );
            }
            counter.fetch_add(1, Ordering::SeqCst);
            next.run(request).await
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, flow).await.unwrap() });
    let contract = GatewayContract::load().unwrap();
    let registry =
        StaticServiceRegistry::from_urls(&BTreeMap::from([("flows".into(), url)])).unwrap();
    let upstream = ReqwestUpstream::with_client(
        1024 * 1024,
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
    )
    .unwrap();
    let proxy = GatewayProxy::new(
        contract
            .proxy_route_table_with_passport_native(false)
            .unwrap(),
        Arc::new(registry),
        Arc::new(upstream),
        ProxyConfig::default(),
    )
    .unwrap();
    let unused = Arc::new(NoVisitorAuthority);
    let state = GatewayRuntimeState::new(
        contract
            .runtime_route_table_with_passport_native(false)
            .unwrap(),
        proxy,
        unused.clone(),
        unused.clone(),
        unused.clone(),
        unused.clone(),
        unused,
        vec![],
        GatewayRateLimiter::new(Arc::new(InMemoryRateLimiter::default()), 1000).unwrap(),
        Arc::new(InMemoryIdempotencyStore::new(60000, 5000).unwrap()),
        [origin.into()],
        origin,
        origin,
        "demo.example",
        None,
        "unused-signing-key",
        "unused-issuance-key",
        ReleaseIdentity::default(),
    )
    .unwrap()
    .with_service_token(Some(WORKLOAD.into()))
    .unwrap();
    let router = gateway_router(Arc::new(state));
    let public_server = public_listener.map(|listener| {
        let app = router.clone();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() })
    });
    PublicGateway {
        router,
        observed,
        server,
        public_server,
    }
}
