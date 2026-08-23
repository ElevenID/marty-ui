//! Marty policy values and provider adapters for canonical MMF HTTP kernels.

use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use mmf_platform::{
    ContentTypePolicy, PlatformError, ProtocolVersionDecision, ProtocolVersionPolicy,
};
use mmf_security::{
    DistributedRateLimiter, RateLimitQuota, RateLimitResult, RateLimitRule, RateLimitScope,
    RateLimitStrategy, SecurityError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const MIP_VERSION: &str = "0.5.0";
pub const RATE_LIMIT_WINDOW_MS: u64 = 60_000;

#[derive(Clone, Debug)]
pub struct GatewayHttpPolicies {
    pub versions: ProtocolVersionPolicy,
    pub content_types: ContentTypePolicy,
}

impl GatewayHttpPolicies {
    pub fn new() -> Result<Self, PlatformError> {
        let versions = ProtocolVersionPolicy::new(MIP_VERSION, [MIP_VERSION])?;
        let content_types = ContentTypePolicy {
            body_methods: ["POST", "PUT", "PATCH"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            allowed_media_types: [
                "application/json",
                "application/scim+json",
                "application/x-www-form-urlencoded",
                "multipart/form-data",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            exempt_path_prefixes: [
                "/v1/issuance/token",
                "/v1/issuance/par",
                "/v1/issuance/nonce",
                "/v1/flows/instances/",
                "/v1/flows/siop/submit",
                "/v1/auth/",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        };
        content_types.validate()?;
        Ok(Self {
            versions,
            content_types,
        })
    }

    #[must_use]
    pub fn negotiate_version(&self, advertised: Option<&str>) -> ProtocolVersionDecision {
        self.versions.negotiate(advertised)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MipError {
    pub error: String,
    pub error_description: String,
    pub message_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl MipError {
    #[must_use]
    pub fn new(error: impl Into<String>, description: impl Into<String>) -> Self {
        Self::with_message_id(error, description, Uuid::new_v4().to_string())
    }

    #[must_use]
    pub fn with_message_id(
        error: impl Into<String>,
        description: impl Into<String>,
        message_id: impl Into<String>,
    ) -> Self {
        Self {
            error: error.into(),
            error_description: description.into(),
            message_id: message_id.into(),
            field: None,
            details: Vec::new(),
            extra: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionIdentity {
    pub user_id: String,
    pub email: Option<String>,
    pub username: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub user_type: Option<String>,
    pub applicant_id: Option<String>,
    pub roles: Vec<String>,
    pub organization_id: Option<String>,
    pub organization_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApiKeyIdentity {
    pub api_key_id: String,
    pub organization_id: Option<String>,
    pub key_prefix: Option<String>,
    pub scopes: Vec<String>,
}

#[async_trait]
pub trait GatewayIdentityProvider: Send + Sync {
    async fn validate_session(
        &self,
        session_id: &str,
    ) -> Result<Option<SessionIdentity>, SecurityError>;

    async fn validate_api_key(
        &self,
        api_key: &str,
    ) -> Result<Option<ApiKeyIdentity>, SecurityError>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuthenticationInput {
    pub required: bool,
    pub headers: BTreeMap<String, String>,
    pub cookies: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationSource {
    Session,
    ApiKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayIdentity {
    pub source: AuthenticationSource,
    pub user_id: String,
    pub user_email: Option<String>,
    pub user_domain: Option<String>,
    pub session_organization_id: Option<String>,
    pub api_key_id: Option<String>,
    pub api_key_prefix: Option<String>,
    pub api_key_scopes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationOutcome {
    Bypass,
    Authenticated(GatewayIdentity),
    Failed(AuthenticationFailure),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationFailure {
    pub status: u16,
    pub error: &'static str,
    pub description: &'static str,
}

pub async fn authenticate(
    input: &AuthenticationInput,
    provider: &dyn GatewayIdentityProvider,
) -> AuthenticationOutcome {
    if !input.required {
        return AuthenticationOutcome::Bypass;
    }

    if let Some(api_key) = extract_api_key(&input.headers) {
        return match provider.validate_api_key(api_key).await {
            Ok(Some(identity)) => AuthenticationOutcome::Authenticated(api_key_context(identity)),
            Ok(None) => AuthenticationOutcome::Failed(AuthenticationFailure {
                status: 401,
                error: "unauthorized",
                description: "Invalid or expired API key",
            }),
            Err(_) => AuthenticationOutcome::Failed(AuthenticationFailure {
                status: 503,
                error: "service_unavailable",
                description: "Organization service unavailable",
            }),
        };
    }

    let Some(session_id) = input.cookies.get("sessionId") else {
        return AuthenticationOutcome::Failed(AuthenticationFailure {
            status: 401,
            error: "unauthorized",
            description: "Authentication required",
        });
    };
    match provider.validate_session(session_id).await {
        Ok(Some(identity)) if identity.user_id.trim().is_empty() => {
            AuthenticationOutcome::Failed(AuthenticationFailure {
                status: 401,
                error: "unauthorized",
                description: "Invalid session data",
            })
        }
        Ok(Some(identity)) => AuthenticationOutcome::Authenticated(session_context(identity)),
        Ok(None) => AuthenticationOutcome::Failed(AuthenticationFailure {
            status: 401,
            error: "unauthorized",
            description: "Invalid session",
        }),
        Err(_) => AuthenticationOutcome::Failed(AuthenticationFailure {
            status: 502,
            error: "auth_service_error",
            description: "Auth service unavailable",
        }),
    }
}

#[must_use]
pub fn extract_api_key(headers: &BTreeMap<String, String>) -> Option<&str> {
    if let Some(value) = header(headers, "x-api-key").map(str::trim) {
        if !value.is_empty() {
            return Some(value);
        }
    }
    let authorization = header(headers, "authorization")?;
    if authorization.len() < 7 || !authorization[..7].eq_ignore_ascii_case("bearer ") {
        return None;
    }
    let token = authorization[7..].trim();
    ["mk_live_", "mk_test_", "pk_live_", "pk_test_"]
        .iter()
        .any(|prefix| token.starts_with(prefix))
        .then_some(token)
}

fn header<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn session_context(identity: SessionIdentity) -> GatewayIdentity {
    let user_domain = identity
        .email
        .as_deref()
        .and_then(|email| email.split_once('@').map(|(_, domain)| domain.to_owned()));
    GatewayIdentity {
        source: AuthenticationSource::Session,
        user_id: identity.user_id,
        user_email: identity.email,
        user_domain,
        session_organization_id: identity.organization_id,
        api_key_id: None,
        api_key_prefix: None,
        api_key_scopes: Vec::new(),
    }
}

fn api_key_context(identity: ApiKeyIdentity) -> GatewayIdentity {
    let api_key_id = if identity.api_key_id.is_empty() {
        "unknown".to_owned()
    } else {
        identity.api_key_id
    };
    GatewayIdentity {
        source: AuthenticationSource::ApiKey,
        user_id: format!("api_key:{api_key_id}"),
        user_email: None,
        user_domain: None,
        session_organization_id: identity.organization_id,
        api_key_id: Some(api_key_id),
        api_key_prefix: identity.key_prefix,
        api_key_scopes: identity.scopes,
    }
}

pub struct GatewayRateLimiter {
    provider: Arc<dyn DistributedRateLimiter>,
    rule: RateLimitRule,
}

impl GatewayRateLimiter {
    pub fn new(
        provider: Arc<dyn DistributedRateLimiter>,
        requests_per_minute: u64,
    ) -> Result<Self, SecurityError> {
        let rule = RateLimitRule {
            name: "marty_gateway".into(),
            scope: RateLimitScope::PerUser,
            strategy: RateLimitStrategy::SlidingWindow,
            limit: requests_per_minute.max(1),
            window_ms: RATE_LIMIT_WINDOW_MS,
            burst_size: 0,
            enabled: requests_per_minute > 0,
        };
        rule.validate()?;
        Ok(Self { provider, rule })
    }

    pub async fn check(
        &self,
        session_id: Option<&str>,
        forwarded_for: Option<&str>,
        peer_ip: Option<&str>,
        path: &str,
        now_ms: u64,
    ) -> Result<Option<RateLimitResult>, SecurityError> {
        if matches!(
            path,
            "/health" | "/ready" | "/health/ready" | "/health/services"
        ) || !self.rule.enabled
        {
            return Ok(None);
        }
        let client = rate_limit_client_key(session_id, forwarded_for, peer_ip);
        let bucket = rate_limit_bucket(path);
        let quota = RateLimitQuota {
            user_id: Some(format!("{client}:{bucket}")),
            ..RateLimitQuota::default()
        };
        self.provider
            .check(&self.rule, &quota, now_ms)
            .await
            .map(Some)
    }
}

#[must_use]
pub fn rate_limit_client_key(
    session_id: Option<&str>,
    forwarded_for: Option<&str>,
    peer_ip: Option<&str>,
) -> String {
    if let Some(session_id) = session_id {
        let digest = Sha256::digest(session_id.as_bytes());
        let mut encoded = String::with_capacity(16);
        use std::fmt::Write;
        for byte in digest.iter().take(8) {
            write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
        }
        return format!("sid:{encoded}");
    }
    let ip = forwarded_for
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or(peer_ip)
        .unwrap_or("unknown");
    format!("ip:{ip}")
}

#[must_use]
pub fn rate_limit_bucket(path: &str) -> String {
    let parts = path
        .trim_matches('/')
        .split('/')
        .filter(|part| !part.is_empty())
        .take(2)
        .collect::<Vec<_>>();
    if parts.is_empty() {
        "root".into()
    } else {
        parts.join("/")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mmf_platform::ContentTypeDecision;
    use mmf_security::InMemoryRateLimiter;
    use serde::Deserialize;

    struct RejectingProvider;

    #[async_trait]
    impl GatewayIdentityProvider for RejectingProvider {
        async fn validate_session(
            &self,
            _: &str,
        ) -> Result<Option<SessionIdentity>, SecurityError> {
            Ok(None)
        }

        async fn validate_api_key(&self, _: &str) -> Result<Option<ApiKeyIdentity>, SecurityError> {
            Ok(None)
        }
    }

    struct ScriptedProvider<'a> {
        behavior: &'a str,
    }

    #[async_trait]
    impl GatewayIdentityProvider for ScriptedProvider<'_> {
        async fn validate_session(
            &self,
            _: &str,
        ) -> Result<Option<SessionIdentity>, SecurityError> {
            match self.behavior {
                "session_valid" => Ok(Some(SessionIdentity {
                    user_id: "user-1".into(),
                    email: Some("user@example.com".into()),
                    organization_id: Some("org-1".into()),
                    ..SessionIdentity::default()
                })),
                "backend_error" => Err(SecurityError::ProviderUnavailable("fixture".into())),
                _ => Ok(None),
            }
        }

        async fn validate_api_key(&self, _: &str) -> Result<Option<ApiKeyIdentity>, SecurityError> {
            match self.behavior {
                "api_key_valid" => Ok(Some(ApiKeyIdentity {
                    api_key_id: "key-1".into(),
                    organization_id: Some("org-1".into()),
                    key_prefix: Some("mk_live".into()),
                    scopes: vec!["credentials:read".into()],
                })),
                "backend_error" => Err(SecurityError::ProviderUnavailable("fixture".into())),
                _ => Ok(None),
            }
        }
    }

    #[derive(Deserialize)]
    struct Contract {
        schema_version: u32,
        api_key_extraction: Vec<ApiKeyExtractionCase>,
        rate_keys: Vec<RateKeyCase>,
        rate_buckets: Vec<RateBucketCase>,
        authentication: Vec<AuthenticationCase>,
        mip_error: MipErrorCase,
    }

    #[derive(Deserialize)]
    struct ApiKeyExtractionCase {
        headers: BTreeMap<String, String>,
        expected: Option<String>,
    }

    #[derive(Deserialize)]
    struct RateKeyCase {
        session_id: Option<String>,
        forwarded_for: Option<String>,
        peer_ip: Option<String>,
        expected: String,
    }

    #[derive(Deserialize)]
    struct RateBucketCase {
        path: String,
        expected: String,
    }

    #[derive(Deserialize)]
    struct AuthenticationCase {
        required: bool,
        headers: BTreeMap<String, String>,
        cookies: BTreeMap<String, String>,
        provider: String,
        outcome: String,
        status: Option<u16>,
        user_id: Option<String>,
    }

    #[derive(Deserialize)]
    struct MipErrorCase {
        error: String,
        description: String,
        message_id: String,
        expected: Value,
    }

    fn contract() -> Contract {
        serde_json::from_str(include_str!(
            "../../../../contracts/gateway-middleware-behavior.json"
        ))
        .expect("valid gateway middleware contract")
    }

    #[tokio::test]
    async fn language_neutral_gateway_middleware_contract() {
        let contract = contract();
        assert_eq!(contract.schema_version, 1);
        for case in contract.api_key_extraction {
            assert_eq!(extract_api_key(&case.headers), case.expected.as_deref());
        }
        for case in contract.rate_keys {
            assert_eq!(
                rate_limit_client_key(
                    case.session_id.as_deref(),
                    case.forwarded_for.as_deref(),
                    case.peer_ip.as_deref(),
                ),
                case.expected
            );
        }
        for case in contract.rate_buckets {
            assert_eq!(rate_limit_bucket(&case.path), case.expected);
        }
        for case in contract.authentication {
            let outcome = authenticate(
                &AuthenticationInput {
                    required: case.required,
                    headers: case.headers,
                    cookies: case.cookies,
                },
                &ScriptedProvider {
                    behavior: &case.provider,
                },
            )
            .await;
            let (name, status, user_id) = match outcome {
                AuthenticationOutcome::Bypass => ("bypass", None, None),
                AuthenticationOutcome::Authenticated(identity) => {
                    ("authenticated", None, Some(identity.user_id))
                }
                AuthenticationOutcome::Failed(failure) => ("failed", Some(failure.status), None),
            };
            assert_eq!(name, case.outcome);
            assert_eq!(status, case.status);
            assert_eq!(user_id.as_deref(), case.user_id.as_deref());
        }
        let error = MipError::with_message_id(
            &contract.mip_error.error,
            &contract.mip_error.description,
            &contract.mip_error.message_id,
        );
        assert_eq!(
            serde_json::to_value(error).expect("error JSON"),
            contract.mip_error.expected
        );
    }

    #[test]
    fn exact_gateway_http_policy_values_are_preserved() {
        let policies = GatewayHttpPolicies::new().expect("policies");
        assert_eq!(
            policies.negotiate_version(Some("0.5.0")),
            ProtocolVersionDecision::Accepted
        );
        assert!(matches!(
            policies.negotiate_version(Some("0.4.0")),
            ProtocolVersionDecision::Unsupported { .. }
        ));
        assert_eq!(
            policies.content_types.evaluate(
                "POST",
                "/v1/issuance/nonce",
                Some("application/octet-stream")
            ),
            ContentTypeDecision::Accepted
        );
        assert!(matches!(
            policies.content_types.evaluate(
                "POST",
                "/v1/issuance/didcomm/deliver",
                Some("application/didcomm-plain+json")
            ),
            ContentTypeDecision::Unsupported { .. }
        ));
    }

    #[tokio::test]
    async fn authentication_fails_closed_without_credentials() {
        let outcome = authenticate(
            &AuthenticationInput {
                required: true,
                ..AuthenticationInput::default()
            },
            &RejectingProvider,
        )
        .await;
        assert!(matches!(
            outcome,
            AuthenticationOutcome::Failed(AuthenticationFailure {
                status: 401,
                description: "Authentication required",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn gateway_rate_limit_reuses_mmf_sliding_window() {
        let limiter =
            GatewayRateLimiter::new(Arc::new(InMemoryRateLimiter::default()), 2).expect("limiter");
        assert!(
            limiter
                .check(None, Some("192.0.2.1"), None, "/v1/test", 1)
                .await
                .expect("first")
                .expect("limited route")
                .allowed
        );
        assert!(
            limiter
                .check(None, Some("192.0.2.1"), None, "/v1/test", 2)
                .await
                .expect("second")
                .expect("limited route")
                .allowed
        );
        assert!(
            !limiter
                .check(None, Some("192.0.2.1"), None, "/v1/test", 3)
                .await
                .expect("third")
                .expect("limited route")
                .allowed
        );
        assert!(limiter
            .check(None, None, None, "/health", 4)
            .await
            .expect("health")
            .is_none());
    }

    #[test]
    fn rate_keys_preserve_session_ip_and_bucket_contract() {
        assert_eq!(
            rate_limit_client_key(Some("session-1"), Some("192.0.2.1"), None),
            "sid:84097828fc31a8c8"
        );
        assert_eq!(
            rate_limit_client_key(None, Some("192.0.2.1, 198.51.100.1"), None),
            "ip:192.0.2.1"
        );
        assert_eq!(
            rate_limit_bucket("/v1/organizations/org-1"),
            "v1/organizations"
        );
        assert_eq!(rate_limit_bucket("/health"), "health");
        assert_eq!(rate_limit_bucket("/"), "root");
    }
}
