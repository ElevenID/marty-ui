//! Live provider adapters for the Rust gateway.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use mmf_platform::{
    IdempotencyStore, InMemoryIdempotencyStore, PlatformError, RedisIdempotencyStore,
};
use mmf_security::{DistributedRateLimiter, InMemoryRateLimiter, RedisRateLimiter, SecurityError};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use tonic::{metadata::AsciiMetadataValue, transport::Channel, Code, Request};

use crate::{
    auth_proto::{auth_service_client::AuthServiceClient, ValidateSessionRequest},
    authorization::{OrganizationMembership, OrganizationMembershipProvider},
    event_stream_proto::{
        event_stream_service_client::EventStreamServiceClient,
        EventSubscription as ProtoEventSubscription,
    },
    middleware::{ApiKeyIdentity, GatewayIdentityProvider, SessionIdentity},
    organization_proto::{
        organization_service_client::OrganizationServiceClient, GetMemberRequest,
        ValidateApiKeyRequest,
    },
    runtime::{
        EventStreamProvider, EventStreamSubscription, GatewayDomainEvent, GatewayDomainEventStream,
        ReadinessProvider, ReadinessServiceStatus, ResourceOwnerContext, ResourceOwnerProvider,
    },
};

const SERVICE_TOKEN_HEADER: &str = "x-service-token";
const DEFAULT_IDEMPOTENCY_TTL_MS: u64 = 86_400_000;
const DEFAULT_IDEMPOTENCY_LOCK_TTL_MS: u64 = 300_000;
const DEFAULT_PROVIDER_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct HttpGatewayProvider {
    client: reqwest::Client,
    service_urls: BTreeMap<String, String>,
    internal_api_key: String,
    issuance_api_key: Option<String>,
    maximum_response_bytes: usize,
}

impl HttpGatewayProvider {
    pub fn new(
        service_urls: BTreeMap<String, String>,
        internal_api_key: impl Into<String>,
        issuance_api_key: Option<String>,
        maximum_response_bytes: Option<usize>,
    ) -> Result<Self, ProviderCompositionError> {
        let maximum_response_bytes =
            maximum_response_bytes.unwrap_or(DEFAULT_PROVIDER_RESPONSE_BYTES);
        let internal_api_key = internal_api_key.into();
        if service_urls.is_empty()
            || maximum_response_bytes == 0
            || internal_api_key.trim().is_empty()
        {
            return Err(ProviderCompositionError::InvalidConfiguration(
                "HTTP gateway provider requires service URLs, an internal API key, and a response limit"
                    .into(),
            ));
        }
        for raw_url in service_urls.values() {
            let url = url::Url::parse(raw_url).map_err(|_| {
                ProviderCompositionError::InvalidConfiguration(
                    "gateway provider service URL is invalid".into(),
                )
            })?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(ProviderCompositionError::InvalidConfiguration(
                    "gateway provider service URLs must be credential-free HTTP(S) URLs".into(),
                ));
            }
        }
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| {
                ProviderCompositionError::Unavailable(
                    "HTTP gateway provider could not be initialized".into(),
                )
            })?;
        Ok(Self {
            client,
            service_urls,
            internal_api_key,
            issuance_api_key: issuance_api_key.filter(|value| !value.trim().is_empty()),
            maximum_response_bytes,
        })
    }

    fn service_url(&self, service: &str, path: &str) -> Result<String, SecurityError> {
        let base = self
            .service_urls
            .get(service)
            .ok_or_else(|| SecurityError::ProviderUnavailable("service URL unavailable".into()))?;
        Ok(format!(
            "{}{}",
            base.trim_end_matches('/'),
            if path.starts_with('/') {
                path.to_owned()
            } else {
                format!("/{path}")
            }
        ))
    }

    async fn bounded_body(
        &self,
        mut response: reqwest::Response,
    ) -> Result<Vec<u8>, SecurityError> {
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| {
            SecurityError::ProviderUnavailable("resource-owner response failed".into())
        })? {
            if body.len().saturating_add(chunk.len()) > self.maximum_response_bytes {
                return Err(SecurityError::ProviderUnavailable(
                    "resource-owner response exceeded its limit".into(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

#[async_trait]
impl ResourceOwnerProvider for HttpGatewayProvider {
    async fn resolve_organization(
        &self,
        service: &str,
        path: &str,
        context: &ResourceOwnerContext,
    ) -> Result<Option<String>, SecurityError> {
        let mut request = self.client.get(self.service_url(service, path)?);
        for (name, value) in &context.headers {
            request = request.header(name, value);
        }
        if service == "issuance" {
            if let Some(value) = &self.issuance_api_key {
                request = request.header("x-api-key", value);
            }
        } else if path.starts_with("/internal/v1/resource-owners/") {
            request = request.header("x-api-key", &self.internal_api_key);
        }
        let response = request.send().await.map_err(|_| {
            SecurityError::ProviderUnavailable("resource-owner service unavailable".into())
        })?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(SecurityError::ProviderUnavailable(
                "resource-owner lookup failed".into(),
            ));
        }
        let body = self.bounded_body(response).await?;
        let value: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|_| SecurityError::InvalidAuthenticationResult)?;
        let organization_id = value
            .get("organization_id")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(SecurityError::InvalidAuthenticationResult)?;
        Ok(Some(organization_id.to_owned()))
    }
}

#[async_trait]
impl ReadinessProvider for HttpGatewayProvider {
    async fn check_services(
        &self,
        services: &[String],
    ) -> BTreeMap<String, ReadinessServiceStatus> {
        let mut results = BTreeMap::new();
        for service in services {
            let Some(base) = self.service_urls.get(service) else {
                results.insert(
                    service.clone(),
                    ReadinessServiceStatus {
                        status: "missing".into(),
                        url: None,
                        status_code: None,
                        error: None,
                    },
                );
                continue;
            };
            let base = base.trim_end_matches('/').to_owned();
            let status = match self.client.get(format!("{base}/health")).send().await {
                Ok(response) => ReadinessServiceStatus {
                    status: if response.status() == reqwest::StatusCode::OK {
                        "healthy".into()
                    } else {
                        "unhealthy".into()
                    },
                    url: Some(base),
                    status_code: Some(response.status().as_u16()),
                    error: None,
                },
                Err(_) => ReadinessServiceStatus {
                    status: "unreachable".into(),
                    url: Some(base),
                    status_code: None,
                    error: Some("health request failed".into()),
                },
            };
            results.insert(service.clone(), status);
        }
        results
    }

    fn all_services(&self) -> Vec<String> {
        self.service_urls.keys().cloned().collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributedProviderConfig {
    pub production: bool,
    pub redis_url: Option<String>,
    pub rate_limit_prefix: String,
    pub idempotency_prefix: String,
    pub idempotency_ttl_ms: u64,
    pub idempotency_lock_ttl_ms: u64,
}

impl Default for DistributedProviderConfig {
    fn default() -> Self {
        Self {
            production: false,
            redis_url: None,
            rate_limit_prefix: "mip:rl".into(),
            idempotency_prefix: "idempotency".into(),
            idempotency_ttl_ms: DEFAULT_IDEMPOTENCY_TTL_MS,
            idempotency_lock_ttl_ms: DEFAULT_IDEMPOTENCY_LOCK_TTL_MS,
        }
    }
}

#[derive(Debug, Error)]
pub enum ProviderCompositionError {
    #[error("invalid gateway provider configuration: {0}")]
    InvalidConfiguration(String),
    #[error("required gateway provider is unavailable: {0}")]
    Unavailable(String),
}

pub struct GatewayDistributedProviders {
    pub rate_limiter: Arc<dyn DistributedRateLimiter>,
    pub idempotency: Arc<dyn IdempotencyStore>,
    pub redis_backed: bool,
}

impl GatewayDistributedProviders {
    pub async fn compose(
        config: &DistributedProviderConfig,
    ) -> Result<Self, ProviderCompositionError> {
        validate_distributed_config(config)?;
        let Some(redis_url) = config.redis_url.as_deref() else {
            if config.production {
                return Err(ProviderCompositionError::Unavailable(
                    "production requires Redis-backed rate limiting and idempotency".into(),
                ));
            }
            let idempotency = InMemoryIdempotencyStore::new(
                config.idempotency_ttl_ms,
                config.idempotency_lock_ttl_ms,
            )
            .map_err(platform_composition_error)?;
            return Ok(Self {
                rate_limiter: Arc::new(InMemoryRateLimiter::default()),
                idempotency: Arc::new(idempotency),
                redis_backed: false,
            });
        };

        let rate_limiter = RedisRateLimiter::connect(redis_url, &config.rate_limit_prefix)
            .await
            .map_err(security_composition_error)?;
        rate_limiter
            .health_check()
            .await
            .map_err(security_composition_error)?;
        let idempotency = RedisIdempotencyStore::connect(
            redis_url,
            &config.idempotency_prefix,
            config.idempotency_ttl_ms,
            config.idempotency_lock_ttl_ms,
        )
        .await
        .map_err(platform_composition_error)?;
        idempotency
            .health_check()
            .await
            .map_err(platform_composition_error)?;
        Ok(Self {
            rate_limiter: Arc::new(rate_limiter),
            idempotency: Arc::new(idempotency),
            redis_backed: true,
        })
    }
}

fn validate_distributed_config(
    config: &DistributedProviderConfig,
) -> Result<(), ProviderCompositionError> {
    if config.rate_limit_prefix.trim().is_empty()
        || config.idempotency_prefix.trim().is_empty()
        || config.idempotency_ttl_ms == 0
        || config.idempotency_lock_ttl_ms == 0
    {
        return Err(ProviderCompositionError::InvalidConfiguration(
            "provider prefixes and idempotency TTLs must be nonempty".into(),
        ));
    }
    Ok(())
}

fn security_composition_error(_: SecurityError) -> ProviderCompositionError {
    ProviderCompositionError::Unavailable("Redis security provider failed".into())
}

fn platform_composition_error(_: PlatformError) -> ProviderCompositionError {
    ProviderCompositionError::Unavailable("Redis platform provider failed".into())
}

pub struct GrpcIdentityProvider {
    auth: Mutex<AuthServiceClient<Channel>>,
    organizations: Mutex<OrganizationServiceClient<Channel>>,
    timeout: Duration,
    service_token: Option<String>,
}

impl GrpcIdentityProvider {
    #[must_use]
    pub fn new(
        auth: Channel,
        organizations: Channel,
        timeout: Duration,
        service_token: Option<String>,
    ) -> Self {
        Self {
            auth: Mutex::new(AuthServiceClient::new(auth)),
            organizations: Mutex::new(OrganizationServiceClient::new(organizations)),
            timeout,
            service_token,
        }
    }

    fn request<T>(&self, body: T) -> Result<Request<T>, SecurityError> {
        let mut request = Request::new(body);
        request.set_timeout(self.timeout);
        if let Some(token) = &self.service_token {
            let token = AsciiMetadataValue::try_from(token.as_str()).map_err(|_| {
                SecurityError::InvalidConfiguration(
                    "service token is not valid gRPC metadata".into(),
                )
            })?;
            request.metadata_mut().insert(SERVICE_TOKEN_HEADER, token);
        }
        Ok(request)
    }
}

#[async_trait]
impl GatewayIdentityProvider for GrpcIdentityProvider {
    async fn validate_session(
        &self,
        session_id: &str,
    ) -> Result<Option<SessionIdentity>, SecurityError> {
        if session_id.trim().is_empty() {
            return Ok(None);
        }
        let request = self.request(ValidateSessionRequest {
            session_id: session_id.to_owned(),
        })?;
        let response = self
            .auth
            .lock()
            .await
            .validate_session(request)
            .await
            .map_err(|error| provider_error("auth session validation", error))?
            .into_inner();
        if !response.valid {
            return Ok(None);
        }
        let user = response
            .user
            .ok_or(SecurityError::InvalidAuthenticationResult)?;
        if user.user_id.trim().is_empty() {
            return Err(SecurityError::InvalidAuthenticationResult);
        }
        Ok(Some(SessionIdentity {
            user_id: user.user_id,
            email: optional_string(user.email),
            username: optional_string(user.username),
            given_name: optional_string(user.given_name),
            family_name: optional_string(user.family_name),
            user_type: optional_string(user.user_type),
            applicant_id: optional_string(user.applicant_id),
            roles: user.roles,
            organization_id: optional_string(user.organization_id),
            organization_name: optional_string(user.organization_name),
        }))
    }

    async fn validate_api_key(
        &self,
        api_key: &str,
    ) -> Result<Option<ApiKeyIdentity>, SecurityError> {
        if api_key.trim().is_empty() {
            return Ok(None);
        }
        let request = self.request(ValidateApiKeyRequest {
            api_key: api_key.to_owned(),
        })?;
        let response = self
            .organizations
            .lock()
            .await
            .validate_api_key(request)
            .await
            .map_err(|error| provider_error("organization API-key validation", error))?
            .into_inner();
        if !response.valid {
            return Ok(None);
        }
        if response.api_key_id.trim().is_empty() || response.organization_id.trim().is_empty() {
            return Err(SecurityError::InvalidAuthenticationResult);
        }
        Ok(Some(ApiKeyIdentity {
            api_key_id: response.api_key_id,
            organization_id: Some(response.organization_id),
            key_prefix: optional_string(response.key_prefix),
            scopes: response.scopes,
        }))
    }
}

pub struct GrpcEventStreamProvider {
    client: Mutex<EventStreamServiceClient<Channel>>,
    service_token: Option<String>,
}

impl GrpcEventStreamProvider {
    #[must_use]
    pub fn new(channel: Channel, service_token: Option<String>) -> Self {
        Self {
            client: Mutex::new(EventStreamServiceClient::new(channel)),
            service_token,
        }
    }
}

#[async_trait]
impl EventStreamProvider for GrpcEventStreamProvider {
    async fn subscribe(
        &self,
        subscription: EventStreamSubscription,
    ) -> Result<GatewayDomainEventStream, SecurityError> {
        let mut request = Request::new(ProtoEventSubscription {
            event_types: subscription.event_types,
            organization_id: subscription.organization_id,
            aggregate_type: String::new(),
            subscriber_id: String::new(),
        });
        if let Some(token) = &self.service_token {
            let token = AsciiMetadataValue::try_from(token.as_str()).map_err(|_| {
                SecurityError::InvalidConfiguration(
                    "event-stream service token is not valid gRPC metadata".into(),
                )
            })?;
            request.metadata_mut().insert(SERVICE_TOKEN_HEADER, token);
        }
        let stream = self
            .client
            .lock()
            .await
            .subscribe(request)
            .await
            .map_err(|error| provider_error("event subscription", error))?
            .into_inner()
            .map(|event| {
                event
                    .map(|event| GatewayDomainEvent {
                        event_id: event.event_id,
                        event_type: event.event_type,
                        aggregate_id: event.aggregate_id,
                        aggregate_type: event.aggregate_type,
                        organization_id: event.organization_id,
                        data: event.data.into_iter().collect(),
                        timestamp: event.timestamp,
                    })
                    .map_err(|error| provider_error("event stream", error))
            });
        Ok(Box::pin(stream))
    }
}

#[async_trait]
impl OrganizationMembershipProvider for GrpcIdentityProvider {
    async fn get_membership(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<Option<OrganizationMembership>, SecurityError> {
        if user_id.trim().is_empty() || organization_id.trim().is_empty() {
            return Ok(None);
        }
        let request = self.request(GetMemberRequest {
            organization_id: organization_id.to_owned(),
            user_id: user_id.to_owned(),
        })?;
        let response = match self.organizations.lock().await.get_member(request).await {
            Ok(response) => response.into_inner(),
            Err(error)
                if matches!(
                    error.code(),
                    Code::NotFound | Code::Unknown | Code::InvalidArgument
                ) =>
            {
                return Ok(None)
            }
            Err(error) => return Err(provider_error("organization membership lookup", error)),
        };
        if response.user_id != user_id || response.organization_id != organization_id {
            return Err(SecurityError::InvalidAuthenticationResult);
        }
        Ok(Some(OrganizationMembership {
            user_id: response.user_id,
            organization_id: response.organization_id,
            status: response.status,
            role_names: response.roles.into_iter().map(|role| role.name).collect(),
            permissions: response.permissions.into_iter().collect(),
            is_owner: response.is_owner,
        }))
    }
}

fn optional_string(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn provider_error(operation: &str, error: tonic::Status) -> SecurityError {
    SecurityError::ProviderUnavailable(format!(
        "{operation} failed with gRPC status {}",
        error.code()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::Request as AxumRequest, http::StatusCode, response::IntoResponse, routing::any,
        Json, Router,
    };
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Deserialize)]
    struct Contract {
        schema_version: u32,
        distributed_providers: Vec<DistributedProviderCase>,
    }

    #[derive(Deserialize)]
    struct DistributedProviderCase {
        name: String,
        production: bool,
        redis_url: Option<String>,
        expected: String,
    }

    fn contract() -> Contract {
        serde_json::from_str(include_str!(
            "../../../../contracts/gateway-middleware-behavior.json"
        ))
        .expect("valid gateway middleware contract")
    }

    #[test]
    fn empty_proto_strings_normalize_to_absent() {
        assert_eq!(optional_string(String::new()), None);
        assert_eq!(optional_string("value".into()), Some("value".into()));
    }

    #[test]
    fn provider_errors_do_not_expose_grpc_details() {
        let error = provider_error(
            "session validation",
            tonic::Status::unavailable("credential-bearing internal detail"),
        );
        let message = error.to_string();
        assert!(message.to_ascii_lowercase().contains("unavailable"));
        assert!(!message.contains("credential-bearing"));
    }

    #[tokio::test]
    async fn production_never_falls_back_to_process_local_distributed_state() {
        let error = GatewayDistributedProviders::compose(&DistributedProviderConfig {
            production: true,
            ..DistributedProviderConfig::default()
        })
        .await
        .err()
        .expect("production must reject missing Redis");
        assert!(error.to_string().contains("production requires Redis"));
    }

    #[tokio::test]
    async fn development_can_explicitly_use_canonical_memory_providers() {
        let providers = GatewayDistributedProviders::compose(&DistributedProviderConfig::default())
            .await
            .expect("development providers");
        assert!(!providers.redis_backed);
    }

    #[tokio::test]
    async fn configured_redis_failure_does_not_fall_back() {
        let error = GatewayDistributedProviders::compose(&DistributedProviderConfig {
            redis_url: Some("not a URL".into()),
            ..DistributedProviderConfig::default()
        })
        .await
        .err()
        .expect("bad Redis must fail");
        assert!(matches!(error, ProviderCompositionError::Unavailable(_)));
    }

    #[tokio::test]
    async fn language_neutral_distributed_provider_contract() {
        let contract = contract();
        assert_eq!(contract.schema_version, 1);
        for case in contract.distributed_providers {
            let outcome = GatewayDistributedProviders::compose(&DistributedProviderConfig {
                production: case.production,
                redis_url: case.redis_url,
                ..DistributedProviderConfig::default()
            })
            .await;
            match case.expected.as_str() {
                "memory" => assert!(!outcome.expect(&case.name).redis_backed, "{}", case.name),
                "error" => assert!(outcome.is_err(), "{}", case.name),
                expected => panic!("unknown provider outcome {expected}"),
            }
        }
    }

    async fn provider_fixture(request: AxumRequest) -> impl IntoResponse {
        match request.uri().path() {
            "/health" => (StatusCode::OK, Json(json!({"status": "healthy"}))),
            "/internal/v1/resource-owners/trust-profiles/profile-1"
                if request
                    .headers()
                    .get("x-api-key")
                    .is_some_and(|value| value == "internal-secret") =>
            {
                (StatusCode::OK, Json(json!({"organization_id": "org-1"})))
            }
            "/v1/credential-templates/template-1"
                if request
                    .headers()
                    .get("authorization")
                    .is_some_and(|value| value == "Bearer session")
                    && request
                        .headers()
                        .get("x-user-id")
                        .is_some_and(|value| value == "user-1") =>
            {
                (StatusCode::OK, Json(json!({"organization_id": "org-2"})))
            }
            "/malformed" => (StatusCode::OK, Json(json!({"unexpected": true}))),
            _ => (StatusCode::NOT_FOUND, Json(json!({"detail": "not found"}))),
        }
    }

    async fn fixture_url() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move {
            axum::serve(listener, Router::new().fallback(any(provider_fixture)))
                .await
                .expect("fixture server");
        });
        format!("http://{address}")
    }

    #[tokio::test]
    async fn http_provider_preserves_owner_auth_and_readiness_behavior() {
        let url = fixture_url().await;
        let provider = HttpGatewayProvider::new(
            BTreeMap::from([
                ("trust-profiles".into(), url.clone()),
                ("credential-templates".into(), url.clone()),
            ]),
            "internal-secret",
            Some("issuance-secret".into()),
            Some(4_096),
        )
        .expect("provider");
        let context = ResourceOwnerContext {
            headers: BTreeMap::from([
                ("authorization".into(), "Bearer session".into()),
                ("x-user-id".into(), "user-1".into()),
            ]),
        };

        assert_eq!(
            provider
                .resolve_organization(
                    "trust-profiles",
                    "/internal/v1/resource-owners/trust-profiles/profile-1",
                    &context,
                )
                .await
                .expect("internal owner")
                .as_deref(),
            Some("org-1")
        );
        assert_eq!(
            provider
                .resolve_organization(
                    "credential-templates",
                    "/v1/credential-templates/template-1",
                    &context,
                )
                .await
                .expect("forwarded owner")
                .as_deref(),
            Some("org-2")
        );
        assert!(provider
            .resolve_organization("trust-profiles", "/missing", &context)
            .await
            .expect("hidden missing")
            .is_none());
        assert!(provider
            .resolve_organization("trust-profiles", "/malformed", &context)
            .await
            .is_err());

        let health = provider
            .check_services(&["trust-profiles".into(), "absent".into()])
            .await;
        assert_eq!(health["trust-profiles"].status, "healthy");
        assert_eq!(health["absent"].status, "missing");
    }
}
