//! Opt-in, disposable PostgreSQL proof of the public Gateway -> Issuance webhook handoff.

use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use chrono::Utc;
use hmac::{Hmac, Mac};
use marty_gateway::{
    authorization::{OrganizationMembership, OrganizationMembershipProvider},
    contract::GatewayContract,
    discovery::ReleaseIdentity,
    issuance_native,
    middleware::{ApiKeyIdentity, GatewayIdentityProvider, GatewayRateLimiter, SessionIdentity},
    registry::StaticServiceRegistry,
    runtime::{
        gateway_router, EventStreamProvider, EventStreamSubscription, GatewayDomainEventStream,
        GatewayRuntimeState, ReadinessProvider, ReadinessServiceStatus, ResourceOwnerContext,
        ResourceOwnerProvider,
    },
};
use marty_issuance_service::{
    migration,
    passport_bureau::BureauClient,
    passport_http::{router as passport_router, PassportHttpService},
    passport_repository::{
        PassportJobInsert, PassportJobPatch, PassportJobStatus, PostgresPassportRepository,
    },
};
use marty_passport_auth::PassportTenantKeyring;
use mmf_platform::{
    GatewayProxy, GatewayRequest, GatewayResponse, HttpMethod, InMemoryIdempotencyStore,
    PlatformError, ProxyConfig, ServiceInstance, UpstreamClient,
};
use mmf_security::{InMemoryRateLimiter, SecurityError};
use sha2::Sha256;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

const TENANT_KEYS: &str = r#"{"org-1":"native-passport-key-for-org-1-00000001","org-2":"native-passport-key-for-org-2-00000002"}"#;
const MAXIMUM_BODY_BYTES: usize = 10 * 1024 * 1024;

// This boundary does not use identities, membership, ownership, readiness or
// events. Fail loudly if the public webhook unexpectedly starts requiring one.
struct UnusedGatewayContext;

#[async_trait]
impl GatewayIdentityProvider for UnusedGatewayContext {
    async fn validate_session(&self, _: &str) -> Result<Option<SessionIdentity>, SecurityError> {
        panic!("webhook unexpectedly requested session identity")
    }
    async fn validate_api_key(&self, _: &str) -> Result<Option<ApiKeyIdentity>, SecurityError> {
        panic!("webhook unexpectedly requested API-key identity")
    }
}

#[async_trait]
impl OrganizationMembershipProvider for UnusedGatewayContext {
    async fn get_membership(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<OrganizationMembership>, SecurityError> {
        panic!("webhook unexpectedly requested membership")
    }
}

#[async_trait]
impl ResourceOwnerProvider for UnusedGatewayContext {
    async fn resolve_organization(
        &self,
        _: &str,
        _: &str,
        _: &ResourceOwnerContext,
    ) -> Result<Option<String>, SecurityError> {
        panic!("webhook unexpectedly requested resource owner")
    }
}

#[async_trait]
impl ReadinessProvider for UnusedGatewayContext {
    async fn check_services(&self, _: &[String]) -> BTreeMap<String, ReadinessServiceStatus> {
        panic!("webhook unexpectedly requested readiness")
    }
    fn all_services(&self) -> Vec<String> {
        panic!("webhook unexpectedly requested service inventory")
    }
}

#[async_trait]
impl EventStreamProvider for UnusedGatewayContext {
    async fn subscribe(
        &self,
        _: EventStreamSubscription,
    ) -> Result<GatewayDomainEventStream, SecurityError> {
        panic!("webhook unexpectedly requested event stream")
    }
}

fn passport_gateway(issuance: Router) -> Router {
    let contract = GatewayContract::load().expect("Gateway contract");
    let routes = contract
        .runtime_route_table_with_passport_native(true)
        .expect("native passport routes");
    let proxy_routes = contract
        .proxy_route_table_with_passport_native(true)
        .expect("native passport proxy routes");
    let service_urls = proxy_routes
        .routes()
        .iter()
        .map(|route| {
            (
                route.upstream_service.clone(),
                format!("http://{}:8000", route.upstream_service),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let registry = StaticServiceRegistry::from_urls(&service_urls).expect("synthetic registry");
    let proxy = GatewayProxy::new(
        proxy_routes,
        Arc::new(registry),
        Arc::new(PassportRouterUpstream(issuance)),
        ProxyConfig::default(),
    )
    .expect("Gateway proxy");
    let state = GatewayRuntimeState::new(
        routes,
        proxy,
        Arc::new(UnusedGatewayContext),
        Arc::new(UnusedGatewayContext),
        Arc::new(UnusedGatewayContext),
        Arc::new(UnusedGatewayContext),
        Arc::new(UnusedGatewayContext),
        vec!["auth".into()],
        GatewayRateLimiter::new(Arc::new(InMemoryRateLimiter::default()), 120)
            .expect("rate limiter"),
        Arc::new(InMemoryIdempotencyStore::new(60_000, 5_000).expect("idempotency")),
        ["https://beta.elevenidllc.com".into()],
        "https://issuer.example",
        "https://issuer.example",
        "issuer.example:8443",
        Some("org-root".into()),
        "internal-signing-key",
        "issuance-service-key",
        ReleaseIdentity::default(),
    )
    .expect("Gateway runtime state")
    .with_service_token(Some("s".repeat(32)))
    .expect("service token")
    .with_passport_native_gateway(
        true,
        Some(
            PassportTenantKeyring::from_json(TENANT_KEYS)
                .expect("tenant keys")
                .into(),
        ),
    )
    .expect("passport Gateway");
    gateway_router(Arc::new(state))
}

#[test]
fn gateway_fixture_keeps_native_passport_route() {
    // Runs without PostgreSQL so contract/registry drift fails on every test run.
    drop(passport_gateway(Router::new()));
}

struct PassportRouterUpstream(Router);

#[async_trait]
impl UpstreamClient for PassportRouterUpstream {
    async fn send(
        &self,
        instance: &ServiceInstance,
        request: GatewayRequest,
    ) -> Result<GatewayResponse, PlatformError> {
        assert_eq!(instance.service_name, issuance_native::NATIVE_SERVICE);
        assert_eq!(request.method, HttpMethod::Post);
        let mut builder = Request::builder().method("POST").uri(&request.path);
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let response = self
            .0
            .clone()
            .oneshot(
                builder
                    .body(Body::from(request.body.unwrap_or_default()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status_code = response.status().as_u16();
        let body = to_bytes(response.into_body(), MAXIMUM_BODY_BYTES)
            .await
            .unwrap();
        Ok(GatewayResponse {
            status_code,
            headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
            body: Some(body.to_vec()),
            response_time_ms: None,
            upstream_service: None,
        })
    }
}

fn signature(secret: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

async fn send_webhook(router: &Router, body: &[u8], signature: &str) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/passport/webhooks/personalization")
                .header("content-type", "application/json")
                .header("x-personalization-signature", signature)
                .body(Body::from(body.to_vec()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn native_passport_gateway_signed_webhook_updates_durable_tenant_job() {
    let Ok(database_url) = std::env::var("MARTY_PASSPORT_GATEWAY_TEST_URL") else {
        return;
    };
    let database = url::Url::parse(&database_url).expect("gateway passport test URL must parse");
    assert!(
        matches!(database.host_str(), Some("127.0.0.1" | "localhost")),
        "gateway passport contract requires a loopback PostgreSQL host"
    );
    let database_name = database.path().trim_start_matches('/');
    assert_eq!(
        database_name, "marty_passport_gateway_test",
        "gateway passport contract requires its dedicated disposable database"
    );
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("gateway passport test database must connect");
    sqlx::query("DROP SCHEMA IF EXISTS issuance_service CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    migration::migrate_passport(&pool).await.unwrap();

    let keyring = PassportTenantKeyring::from_json(TENANT_KEYS).unwrap();
    let repository = PostgresPassportRepository::new(pool.clone());
    for organization_id in ["org-1", "org-2"] {
        let principal = keyring
            .authenticate(
                Some(organization_id),
                Some(if organization_id == "org-1" {
                    "native-passport-key-for-org-1-00000001"
                } else {
                    "native-passport-key-for-org-2-00000002"
                }),
            )
            .unwrap();
        let job = PassportJobInsert {
            id: format!("job-{organization_id}"),
            application_id: format!("application-{organization_id}"),
            flow_execution_id: format!("flow-{organization_id}"),
            application_template_id: "template-test".into(),
            credential_template_id: "credential-test".into(),
            revocation_profile_id: None,
            delivery_destination_profile_id: "destination-test".into(),
            document_type: "TD3".into(),
            country_code: "USA".into(),
            issuer_did: None,
            secure_artifact_ciphertext: "synthetic-encrypted-artifact".into(),
            secure_artifact_reference: format!("physical-artifact://job-{organization_id}"),
        };
        repository
            .insert(&principal, &job, Utc::now())
            .await
            .unwrap();
        let mut submitted = PassportJobPatch::new(PassportJobStatus::Submitted);
        submitted.bureau_job_id = Some(Some("bureau-shared".into()));
        repository
            .update(
                &principal,
                &job.application_id,
                "DRAFT",
                &submitted,
                Utc::now(),
            )
            .await
            .unwrap()
            .unwrap();
    }

    let secret = "synthetic-personalization-webhook-secret";
    let bureau = BureauClient::new("http://127.0.0.1:1", "unused", Some(secret)).unwrap();
    let issuance = passport_router(PassportHttpService::new(
        keyring.clone(),
        repository.clone(),
        None,
        None,
        Some(bureau),
    ));
    let gateway = passport_gateway(issuance);

    let raw = br#"{ "organization_id" : "org-1", "bureau_job_id":"bureau-shared", "status":"PRINTING", "tracking_number":"tracking-org-1" }"#;
    let signed = signature(secret, raw);
    assert_eq!(send_webhook(&gateway, raw, &signed).await, StatusCode::OK);
    let org_1 = keyring
        .authenticate(
            Some("org-1"),
            Some("native-passport-key-for-org-1-00000001"),
        )
        .unwrap();
    let org_2 = keyring
        .authenticate(
            Some("org-2"),
            Some("native-passport-key-for-org-2-00000002"),
        )
        .unwrap();
    let first = repository
        .get(&org_1, "application-org-1")
        .await
        .unwrap()
        .unwrap();
    let other = repository
        .get(&org_2, "application-org-2")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.status, "IN_PRODUCTION");
    assert_eq!(first.tracking_number.as_deref(), Some("tracking-org-1"));
    assert_eq!(other.status, "SUBMITTED");
    assert_eq!(other.tracking_number, None);

    let altered = br#"{ "organization_id" : "org-2", "bureau_job_id":"bureau-shared", "status":"PRINTING", "tracking_number":"tracking-org-1" }"#;
    assert_eq!(
        send_webhook(&gateway, altered, &signed).await,
        StatusCode::UNAUTHORIZED
    );
    let rejected_owner = repository
        .get(&org_1, "application-org-1")
        .await
        .unwrap()
        .unwrap();
    let rejected_other = repository
        .get(&org_2, "application-org-2")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rejected_owner.status, "IN_PRODUCTION");
    assert_eq!(
        rejected_owner.tracking_number.as_deref(),
        Some("tracking-org-1")
    );
    assert_eq!(rejected_other.status, "SUBMITTED");
    assert_eq!(rejected_other.tracking_number, None);
    let shipped =
        br#"{"organization_id":"org-1","bureau_job_id":"bureau-shared","status":"SHIPPED"}"#;
    assert_eq!(
        send_webhook(&gateway, shipped, &signature(secret, shipped)).await,
        StatusCode::OK
    );
    let completed = repository
        .get(&org_1, "application-org-1")
        .await
        .unwrap()
        .unwrap();
    let untouched = repository
        .get(&org_2, "application-org-2")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(completed.status, "READY_FOR_ACTIVATION");
    assert_eq!(completed.tracking_number.as_deref(), Some("tracking-org-1"));
    assert_eq!(untouched.status, "SUBMITTED");
}
