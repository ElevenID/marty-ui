use std::{collections::BTreeSet, fmt, sync::Arc};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use marty_oid4vci::lti::normalize_canvas_base_url;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::{
    canvas_lti_experience::portable_canvas_pilot_enabled,
    integration_secret::{
        integration_secret_id_from_ref, IntegrationSecretError, IntegrationSecretMetadata,
        NewIntegrationSecret,
    },
    management_security::ManagementSecurity,
    transaction_reads::TransactionReadError,
};

const AUTHORIZATION_TTL_SECONDS: i64 = 600;
const REVOCATION_LEASE_SECONDS: i64 = 60;

const CAPABILITY_SCOPES: &[(&str, &[&str])] = &[
    (
        "catalog",
        &[
            "url:GET|/api/v1/courses",
            "url:GET|/api/v1/courses/:course_id/assignments",
            "url:GET|/api/v1/courses/:course_id/modules",
        ],
    ),
    (
        "native_activity_scores",
        &["url:GET|/api/v1/courses/:course_id/assignments/:assignment_id/submissions/:user_id"],
    ),
    (
        "course_completion",
        &["url:GET|/api/v1/courses/:course_id/users/:user_id/progress"],
    ),
    (
        "module_completion",
        &["url:GET|/api/v1/courses/:course_id/modules/:id"],
    ),
    (
        "background_roster",
        &[
            "url:GET|/api/v1/courses/:course_id/users",
            "url:GET|/api/v1/courses/:course_id/enrollments",
            "url:GET|/api/v1/courses/:course_id/bulk_user_progress",
        ],
    ),
];

const CAPABILITY_ALIASES: &[(&str, &str)] = &[
    ("scope_catalog.read", "catalog"),
    ("assignment_submission.read", "native_activity_scores"),
    ("quiz_submission.read", "native_activity_scores"),
    ("course_progress.read", "course_completion"),
    ("module_progress.read", "module_completion"),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanvasOAuthPlatform {
    pub id: String,
    pub organization_id: String,
    pub canvas_base_url: Option<String>,
    pub config_version: i64,
    pub archived: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CanvasOAuthAuthorization {
    pub id: String,
    pub organization_id: String,
    pub platform_id: String,
    pub canvas_base_url: String,
    pub platform_config_version: i64,
    pub client_id: String,
    pub client_secret_ref: String,
    pub state_hash: String,
    pub capabilities: Vec<String>,
    pub scopes: Vec<String>,
    pub redirect_uri: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl fmt::Debug for CanvasOAuthAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasOAuthAuthorization")
            .field("id", &self.id)
            .field("organization_id", &self.organization_id)
            .field("platform_id", &self.platform_id)
            .field("canvas_base_url", &self.canvas_base_url)
            .field("platform_config_version", &self.platform_config_version)
            .field("client_id", &self.client_id)
            .field("client_secret_ref", &"[REDACTED]")
            .field("state_hash", &"[REDACTED]")
            .field("capability_count", &self.capabilities.len())
            .field("scope_count", &self.scopes.len())
            .field("redirect_uri", &self.redirect_uri)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CanvasOAuthConnection {
    pub id: String,
    pub organization_id: String,
    pub platform_id: String,
    pub canvas_base_url: String,
    pub platform_config_version: i64,
    pub client_id: String,
    pub client_secret_ref: String,
    pub capabilities: Vec<String>,
    pub scopes: Vec<String>,
    pub access_token_secret_ref: Option<String>,
    pub refresh_token_secret_ref: Option<String>,
    pub token_expires_at: Option<DateTime<Utc>>,
    pub status: String,
    pub revoke_retry_count: i32,
    pub updated_at: DateTime<Utc>,
}

impl fmt::Debug for CanvasOAuthConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasOAuthConnection")
            .field("id", &self.id)
            .field("organization_id", &self.organization_id)
            .field("platform_id", &self.platform_id)
            .field("canvas_base_url", &self.canvas_base_url)
            .field("platform_config_version", &self.platform_config_version)
            .field("client_id", &self.client_id)
            .field("client_secret_ref", &"[REDACTED]")
            .field("capability_count", &self.capabilities.len())
            .field("scope_count", &self.scopes.len())
            .field("access_token_secret_ref", &"[REDACTED]")
            .field("refresh_token_secret_ref", &"[REDACTED]")
            .field("token_expires_at", &self.token_expires_at)
            .field("status", &self.status)
            .field("revoke_retry_count", &self.revoke_retry_count)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanvasOAuthStartRequest {
    pub client_id: String,
    pub client_secret_secret_id: String,
    pub capabilities: Vec<String>,
}

impl fmt::Debug for CanvasOAuthStartRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasOAuthStartRequest")
            .field("client_id", &self.client_id)
            .field("client_secret_secret_id", &"[REDACTED]")
            .field("capabilities", &self.capabilities)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct CanvasOAuthStartResponse {
    pub authorization_url: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

impl fmt::Debug for CanvasOAuthStartResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasOAuthStartResponse")
            .field("authorization_url", &"[REDACTED]")
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CanvasOAuthConnectionResponse {
    pub platform_id: String,
    pub status: String,
    pub scopes: Vec<String>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CanvasOAuthCallbackRequest {
    pub code: Option<String>,
    pub state: String,
    pub error: Option<String>,
}

impl fmt::Debug for CanvasOAuthCallbackRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasOAuthCallbackRequest")
            .field("code", &self.code.as_ref().map(|_| "[REDACTED]"))
            .field("state", &"[REDACTED]")
            .field("error", &self.error.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CanvasOAuthCallbackResponse {
    pub location: String,
}

impl fmt::Debug for CanvasOAuthCallbackResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasOAuthCallbackResponse")
            .field("location", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CanvasOAuthTokenBundle {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in_seconds: Option<i64>,
}

impl fmt::Debug for CanvasOAuthTokenBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasOAuthTokenBundle")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_in_seconds", &self.expires_in_seconds)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanvasOAuthPlatformPatch {
    AuthorizationPending {
        client_id: String,
        authorization_id: String,
    },
    AuthorizationCompleting {
        client_id: String,
    },
    Connected {
        client_id: String,
        capabilities: Vec<String>,
        scopes: Vec<String>,
    },
    AuthorizationConflict,
    RevocationPending,
    Disconnected,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CanvasOAuthProviderError {
    #[error("Canvas OAuth provider request failed")]
    Failed { retry_after_seconds: Option<u64> },
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CanvasOAuthError {
    #[error(transparent)]
    Security(#[from] TransactionReadError),
    #[error("Canvas platform not found")]
    PlatformNotFound,
    #[error("Portable Canvas integration is not enabled for this organization")]
    PilotDisabled,
    #[error("Canvas OAuth requires a registered HTTPS Canvas base URL")]
    BaseUrlRequired,
    #[error("Canvas OAuth platform origin is not trusted")]
    OriginUntrusted,
    #[error("Disconnect the existing Canvas OAuth connection before authorizing again")]
    ConnectionExists,
    #[error("Canvas OAuth client secret reference was not found")]
    SecretNotFound,
    #[error("Canvas OAuth client ID is required")]
    ClientIdRequired,
    #[error("At least one Canvas OAuth capability is required")]
    CapabilitiesRequired,
    #[error("Unsupported Canvas OAuth capabilities: {0}")]
    UnsupportedCapabilities(String),
    #[error("Canvas platform configuration changed")]
    ConfigurationChanged,
    #[error("Canvas OAuth connection changed; retry disconnect")]
    ConnectionChanged,
    #[error("Canvas OAuth persistence is temporarily unavailable")]
    RepositoryUnavailable,
    #[error("Canvas OAuth secret storage is temporarily unavailable")]
    SecretUnavailable,
    #[error("Canvas OAuth configuration is invalid")]
    InvalidConfiguration,
}

impl From<IntegrationSecretError> for CanvasOAuthError {
    fn from(_: IntegrationSecretError) -> Self {
        Self::SecretUnavailable
    }
}

#[async_trait]
pub trait CanvasOAuthRepository: Send + Sync {
    async fn management_platform(
        &self,
        organization_id: &str,
        platform_id: &str,
    ) -> Result<Option<CanvasOAuthPlatform>, CanvasOAuthError>;
    async fn callback_platform(
        &self,
        platform_id: &str,
    ) -> Result<Option<CanvasOAuthPlatform>, CanvasOAuthError>;
    async fn connection(
        &self,
        organization_id: &str,
        platform_id: &str,
    ) -> Result<Option<CanvasOAuthConnection>, CanvasOAuthError>;
    async fn save_authorization(
        &self,
        authorization: &CanvasOAuthAuthorization,
    ) -> Result<(), CanvasOAuthError>;
    async fn consume_authorization(
        &self,
        state_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<CanvasOAuthAuthorization>, CanvasOAuthError>;
    async fn patch_platform(
        &self,
        organization_id: &str,
        platform_id: &str,
        expected_config_version: i64,
        patch: CanvasOAuthPlatformPatch,
    ) -> Result<bool, CanvasOAuthError>;
    async fn patch_validation(
        &self,
        organization_id: &str,
        platform_id: &str,
        expected_config_version: i64,
        validated_at: Option<DateTime<Utc>>,
        error_code: Option<&str>,
    ) -> Result<bool, CanvasOAuthError>;
    async fn publish_connection(
        &self,
        connection: &CanvasOAuthConnection,
    ) -> Result<Option<DateTime<Utc>>, CanvasOAuthError>;
    async fn mark_reauthorization_required(
        &self,
        organization_id: &str,
        platform_id: &str,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<bool, CanvasOAuthError>;
    async fn begin_revocation(
        &self,
        organization_id: &str,
        platform_id: &str,
        expected_updated_at: DateTime<Utc>,
        lease_owner: &str,
        lease_seconds: i64,
    ) -> Result<Option<CanvasOAuthConnection>, CanvasOAuthError>;
    async fn reschedule_revocation(
        &self,
        organization_id: &str,
        platform_id: &str,
        lease_owner: &str,
        retry_at: DateTime<Utc>,
        error_code: &str,
    ) -> Result<bool, CanvasOAuthError>;
    async fn complete_revocation(
        &self,
        organization_id: &str,
        platform_id: &str,
        lease_owner: &str,
        secret_ids: &[String],
    ) -> Result<bool, CanvasOAuthError>;
}

#[async_trait]
pub trait CanvasOAuthSecretVault: Send + Sync {
    async fn metadata(
        &self,
        organization_id: &str,
        secret_id: &str,
    ) -> Result<Option<IntegrationSecretMetadata>, CanvasOAuthError>;
    async fn value(
        &self,
        organization_id: &str,
        secret_id: &str,
    ) -> Result<Option<String>, CanvasOAuthError>;
    async fn save(&self, secret: NewIntegrationSecret) -> Result<(), CanvasOAuthError>;
    async fn delete(&self, organization_id: &str, secret_id: &str) -> Result<(), CanvasOAuthError>;
}

#[async_trait]
pub trait CanvasOAuthProvider: Send + Sync {
    async fn exchange(
        &self,
        canvas_base_url: &str,
        client_id: &str,
        client_secret: &str,
        code: &str,
        redirect_uri: &str,
    ) -> Result<CanvasOAuthTokenBundle, CanvasOAuthProviderError>;
    async fn revoke(
        &self,
        canvas_base_url: &str,
        access_token: &str,
    ) -> Result<(), CanvasOAuthProviderError>;
}

#[derive(Clone, Debug)]
pub struct CanvasOAuthServiceConfig {
    pub issuer_base_url: String,
    pub completion_base_url: String,
    pub portable_enabled: bool,
    pub pilot_organizations: BTreeSet<String>,
    pub allow_private_networks: bool,
    pub allow_http_localhost: bool,
}

#[derive(Clone)]
pub struct CanvasOAuthService {
    repository: Arc<dyn CanvasOAuthRepository>,
    vault: Arc<dyn CanvasOAuthSecretVault>,
    provider: Arc<dyn CanvasOAuthProvider>,
    security: ManagementSecurity,
    config: CanvasOAuthServiceConfig,
    redirect_uri: String,
    completion_base_url: Url,
}

impl std::fmt::Debug for CanvasOAuthService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasOAuthService")
            .field("config", &self.config)
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}

impl CanvasOAuthService {
    pub fn new(
        repository: Arc<dyn CanvasOAuthRepository>,
        vault: Arc<dyn CanvasOAuthSecretVault>,
        provider: Arc<dyn CanvasOAuthProvider>,
        management_api_key: Option<&str>,
        config: CanvasOAuthServiceConfig,
    ) -> Result<Self, CanvasOAuthError> {
        let issuer = Url::parse(&config.issuer_base_url)
            .map_err(|_| CanvasOAuthError::InvalidConfiguration)?;
        if !matches!(issuer.scheme(), "http" | "https") || issuer.host_str().is_none() {
            return Err(CanvasOAuthError::InvalidConfiguration);
        }
        let redirect_uri = Url::parse(&format!(
            "{}/v1/integrations/canvas/oauth/callback",
            config.issuer_base_url.trim_end_matches('/')
        ))
        .map_err(|_| CanvasOAuthError::InvalidConfiguration)?
        .to_string();
        let completion_base_url = trusted_completion_url(&config.completion_base_url)?;
        Ok(Self {
            repository,
            vault,
            provider,
            security: ManagementSecurity::new(management_api_key),
            config,
            redirect_uri,
            completion_base_url,
        })
    }

    pub async fn start(
        &self,
        platform_id: &str,
        request: CanvasOAuthStartRequest,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<CanvasOAuthStartResponse, CanvasOAuthError> {
        let organization_id = self.authorize_management(api_key, trusted_organization_id)?;
        self.start_authorized(platform_id, request, organization_id)
            .await
    }

    pub(crate) fn authorize_management<'organization>(
        &self,
        api_key: Option<&str>,
        trusted_organization_id: Option<&'organization str>,
    ) -> Result<&'organization str, CanvasOAuthError> {
        self.security.authorize(api_key)?;
        trusted_organization(trusted_organization_id)
    }

    pub(crate) async fn start_authorized(
        &self,
        platform_id: &str,
        request: CanvasOAuthStartRequest,
        organization_id: &str,
    ) -> Result<CanvasOAuthStartResponse, CanvasOAuthError> {
        let platform = self
            .repository
            .management_platform(organization_id, platform_id)
            .await?
            .filter(|platform| !platform.archived)
            .ok_or(CanvasOAuthError::PlatformNotFound)?;
        self.require_pilot(&platform.organization_id)?;
        let raw_origin = platform
            .canvas_base_url
            .as_deref()
            .filter(|value| value.starts_with("https://"))
            .ok_or(CanvasOAuthError::BaseUrlRequired)?;
        let canvas_base_url = normalize_canvas_base_url(
            raw_origin,
            self.config.allow_private_networks,
            self.config.allow_http_localhost,
        )
        .map_err(|_| CanvasOAuthError::OriginUntrusted)?;
        if self
            .repository
            .connection(&platform.organization_id, &platform.id)
            .await?
            .is_some()
        {
            return Err(CanvasOAuthError::ConnectionExists);
        }
        let secret = self
            .vault
            .metadata(&platform.organization_id, &request.client_secret_secret_id)
            .await?
            .filter(|secret| {
                secret.organization_id == platform.organization_id
                    && secret.enabled
                    && secret.provider == "canvas"
                    && secret.purpose == "oauth_client_secret"
            })
            .ok_or(CanvasOAuthError::SecretNotFound)?;
        let client_id = request.client_id.trim().to_owned();
        if client_id.is_empty() {
            return Err(CanvasOAuthError::ClientIdRequired);
        }
        let capabilities = normalize_capabilities(&request.capabilities)?;
        let scopes = scopes_for_capabilities(&capabilities);
        let state = secure_token(32);
        let now = Utc::now();
        let authorization = CanvasOAuthAuthorization {
            id: Uuid::new_v4().to_string(),
            organization_id: platform.organization_id.clone(),
            platform_id: platform.id.clone(),
            canvas_base_url: canvas_base_url.clone(),
            platform_config_version: platform.config_version,
            client_id: client_id.clone(),
            client_secret_ref: format!("org_secret://{}/{}", platform.organization_id, secret.id),
            state_hash: hash_state(&state),
            capabilities,
            scopes: scopes.clone(),
            redirect_uri: self.redirect_uri.clone(),
            expires_at: now + Duration::seconds(AUTHORIZATION_TTL_SECONDS),
            created_at: now,
        };
        let authorization_url = authorization_url(&authorization, &state)?;
        self.repository.save_authorization(&authorization).await?;
        let patched = self
            .repository
            .patch_platform(
                &platform.organization_id,
                &platform.id,
                platform.config_version,
                CanvasOAuthPlatformPatch::AuthorizationPending {
                    client_id,
                    authorization_id: authorization.id,
                },
            )
            .await?;
        if !patched {
            return Err(CanvasOAuthError::ConfigurationChanged);
        }
        Ok(CanvasOAuthStartResponse {
            authorization_url,
            redirect_uri: self.redirect_uri.clone(),
            scopes,
        })
    }

    pub async fn callback(
        &self,
        request: CanvasOAuthCallbackRequest,
    ) -> Result<CanvasOAuthCallbackResponse, CanvasOAuthError> {
        let now = Utc::now();
        let authorization = self
            .repository
            .consume_authorization(&hash_state(&request.state), now)
            .await?;
        let Some(authorization) = authorization else {
            return self.callback_response(None, "error", Some("oauth_state_invalid"));
        };
        let platform = self
            .repository
            .callback_platform(&authorization.platform_id)
            .await?;
        let Some(platform) = platform.filter(|platform| {
            platform.organization_id == authorization.organization_id && !platform.archived
        }) else {
            return self.callback_response(
                Some(&authorization.platform_id),
                "error",
                Some("oauth_platform_invalid"),
            );
        };
        if self.require_pilot(&platform.organization_id).is_err() {
            return self.callback_response(
                Some(&platform.id),
                "error",
                Some("oauth_rollout_disabled"),
            );
        }
        let code = request.code.as_deref().map(str::trim).unwrap_or_default();
        if request
            .error
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            || code.is_empty()
        {
            return self.callback_response(
                Some(&platform.id),
                "error",
                Some("oauth_authorization_denied"),
            );
        }
        let secret_id = integration_secret_id_from_ref(
            &platform.organization_id,
            &authorization.client_secret_ref,
        );
        let client_secret = if let Some(secret_id) = secret_id {
            self.vault
                .value(&platform.organization_id, secret_id)
                .await?
                .filter(|value| !value.is_empty())
        } else {
            None
        };
        if client_secret.is_none()
            || platform.canvas_base_url.as_deref() != Some(&authorization.canvas_base_url)
            || platform.config_version != authorization.platform_config_version
            || authorization.redirect_uri != self.redirect_uri
        {
            return self.callback_response(
                Some(&platform.id),
                "error",
                Some("oauth_configuration_changed"),
            );
        }
        if self
            .repository
            .connection(&platform.organization_id, &platform.id)
            .await?
            .is_some()
        {
            return self.callback_response(
                Some(&platform.id),
                "error",
                Some("oauth_authorization_conflict"),
            );
        }
        let token_bundle = match self
            .provider
            .exchange(
                &authorization.canvas_base_url,
                &authorization.client_id,
                client_secret.as_deref().expect("checked above"),
                code,
                &authorization.redirect_uri,
            )
            .await
        {
            Ok(bundle) => bundle,
            Err(_) => {
                self.repository
                    .patch_validation(
                        &platform.organization_id,
                        &platform.id,
                        authorization.platform_config_version,
                        None,
                        Some("oauth_token_exchange_failed"),
                    )
                    .await?;
                return self.callback_response(
                    Some(&platform.id),
                    "error",
                    Some("oauth_token_exchange_failed"),
                );
            }
        };
        let token_expires_at = match checked_token_expiration(now, token_bundle.expires_in_seconds)
        {
            Ok(value) => value,
            Err(()) => {
                self.repository
                    .patch_validation(
                        &platform.organization_id,
                        &platform.id,
                        authorization.platform_config_version,
                        None,
                        Some("oauth_token_exchange_failed"),
                    )
                    .await?;
                return self.callback_response(
                    Some(&platform.id),
                    "error",
                    Some("oauth_token_exchange_failed"),
                );
            }
        };
        if !self
            .repository
            .patch_platform(
                &platform.organization_id,
                &platform.id,
                authorization.platform_config_version,
                CanvasOAuthPlatformPatch::AuthorizationCompleting {
                    client_id: authorization.client_id.clone(),
                },
            )
            .await?
        {
            self.best_effort_revoke(&authorization.canvas_base_url, &token_bundle.access_token)
                .await;
            return self.callback_response(
                Some(&platform.id),
                "error",
                Some("oauth_configuration_changed"),
            );
        }
        self.publish_token_bundle(
            &platform,
            authorization,
            token_bundle,
            token_expires_at,
            now,
        )
        .await
    }

    async fn publish_token_bundle(
        &self,
        platform: &CanvasOAuthPlatform,
        authorization: CanvasOAuthAuthorization,
        token_bundle: CanvasOAuthTokenBundle,
        token_expires_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<CanvasOAuthCallbackResponse, CanvasOAuthError> {
        let access = NewIntegrationSecret {
            id: Uuid::new_v4().to_string(),
            organization_id: platform.organization_id.clone(),
            name: format!("Canvas OAuth access token - {}", platform.id),
            provider: "canvas".to_owned(),
            purpose: "oauth_access_token".to_owned(),
            value: token_bundle.access_token.clone(),
            metadata: json!({
                "platform_id": platform.id,
                "capabilities": authorization.capabilities,
                "scopes": authorization.scopes,
            }),
        };
        self.vault.save(access.clone()).await?;
        let refresh = token_bundle
            .refresh_token
            .as_ref()
            .map(|value| NewIntegrationSecret {
                id: Uuid::new_v4().to_string(),
                organization_id: platform.organization_id.clone(),
                name: format!("Canvas OAuth refresh token - {}", platform.id),
                provider: "canvas".to_owned(),
                purpose: "oauth_refresh_token".to_owned(),
                value: value.clone(),
                metadata: json!({"platform_id": platform.id}),
            });
        if let Some(refresh) = refresh.as_ref() {
            if let Err(error) = self.vault.save(refresh.clone()).await {
                let _ = self.vault.delete(&access.organization_id, &access.id).await;
                return Err(error);
            }
        }
        let connection = CanvasOAuthConnection {
            id: Uuid::new_v4().to_string(),
            organization_id: platform.organization_id.clone(),
            platform_id: platform.id.clone(),
            canvas_base_url: authorization.canvas_base_url.clone(),
            platform_config_version: authorization.platform_config_version,
            client_id: authorization.client_id.clone(),
            client_secret_ref: authorization.client_secret_ref,
            capabilities: authorization.capabilities.clone(),
            scopes: authorization.scopes.clone(),
            access_token_secret_ref: Some(access.secret_ref()),
            refresh_token_secret_ref: refresh.as_ref().map(NewIntegrationSecret::secret_ref),
            token_expires_at,
            status: "connected".to_owned(),
            revoke_retry_count: 0,
            updated_at: now,
        };
        let published_at = match self.repository.publish_connection(&connection).await {
            Ok(value) => value,
            Err(error) => {
                self.cleanup_unpublished_tokens(
                    &access,
                    refresh.as_ref(),
                    &connection.canvas_base_url,
                    &token_bundle.access_token,
                )
                .await;
                return Err(error);
            }
        };
        let Some(published_at) = published_at else {
            self.cleanup_unpublished_tokens(
                &access,
                refresh.as_ref(),
                &connection.canvas_base_url,
                &token_bundle.access_token,
            )
            .await;
            let current = self
                .repository
                .connection(&platform.organization_id, &platform.id)
                .await?;
            let patch = current.filter(|value| value.status == "connected").map_or(
                CanvasOAuthPlatformPatch::AuthorizationConflict,
                |value| CanvasOAuthPlatformPatch::Connected {
                    client_id: value.client_id,
                    capabilities: value.capabilities,
                    scopes: value.scopes,
                },
            );
            self.repository
                .patch_platform(
                    &platform.organization_id,
                    &platform.id,
                    authorization.platform_config_version,
                    patch,
                )
                .await?;
            return self.callback_response(
                Some(&platform.id),
                "error",
                Some("oauth_authorization_conflict"),
            );
        };
        let connected = self
            .repository
            .patch_platform(
                &platform.organization_id,
                &platform.id,
                authorization.platform_config_version,
                CanvasOAuthPlatformPatch::Connected {
                    client_id: authorization.client_id,
                    capabilities: authorization.capabilities,
                    scopes: authorization.scopes,
                },
            )
            .await?;
        if !connected {
            self.repository
                .mark_reauthorization_required(
                    &platform.organization_id,
                    &platform.id,
                    published_at,
                )
                .await?;
            return self.callback_response(
                Some(&platform.id),
                "error",
                Some("oauth_configuration_changed"),
            );
        }
        self.repository
            .patch_validation(
                &platform.organization_id,
                &platform.id,
                authorization.platform_config_version,
                Some(Utc::now()),
                None,
            )
            .await?;
        self.callback_response(Some(&platform.id), "connected", None)
    }

    async fn cleanup_unpublished_tokens(
        &self,
        access: &NewIntegrationSecret,
        refresh: Option<&NewIntegrationSecret>,
        canvas_base_url: &str,
        access_token: &str,
    ) {
        let _ = self.vault.delete(&access.organization_id, &access.id).await;
        if let Some(refresh) = refresh {
            let _ = self
                .vault
                .delete(&refresh.organization_id, &refresh.id)
                .await;
        }
        self.best_effort_revoke(canvas_base_url, access_token).await;
    }

    pub async fn disconnect(
        &self,
        platform_id: &str,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<CanvasOAuthConnectionResponse, CanvasOAuthError> {
        self.security.authorize(api_key)?;
        let organization_id = trusted_organization(trusted_organization_id)?;
        let platform = self
            .repository
            .management_platform(organization_id, platform_id)
            .await?
            .filter(|platform| !platform.archived)
            .ok_or(CanvasOAuthError::PlatformNotFound)?;
        let Some(connection) = self
            .repository
            .connection(&platform.organization_id, &platform.id)
            .await?
        else {
            self.repository
                .patch_platform(
                    &platform.organization_id,
                    &platform.id,
                    platform.config_version,
                    CanvasOAuthPlatformPatch::Disconnected,
                )
                .await?;
            return Ok(disconnected_response(&platform.id));
        };
        let lease_owner = format!("oauth-revoke:{}", Uuid::new_v4());
        let leased = self
            .repository
            .begin_revocation(
                &platform.organization_id,
                &platform.id,
                connection.updated_at,
                &lease_owner,
                REVOCATION_LEASE_SECONDS,
            )
            .await?
            .ok_or(CanvasOAuthError::ConnectionChanged)?;
        let access_token = if let Some(secret_ref) = leased.access_token_secret_ref.as_deref() {
            if let Some(secret_id) =
                integration_secret_id_from_ref(&platform.organization_id, secret_ref)
            {
                self.vault
                    .value(&platform.organization_id, secret_id)
                    .await?
            } else {
                None
            }
        } else {
            None
        };
        let revoked = if let Some(access_token) = access_token.as_deref() {
            self.provider
                .revoke(&leased.canvas_base_url, access_token)
                .await
        } else {
            Err(CanvasOAuthProviderError::Failed {
                retry_after_seconds: None,
            })
        };
        if let Err(CanvasOAuthProviderError::Failed {
            retry_after_seconds,
        }) = revoked
        {
            let exponent = u32::try_from(leased.revoke_retry_count.clamp(0, 7)).unwrap_or(0);
            let delay = 30_u64
                .saturating_mul(2_u64.pow(exponent))
                .min(3_600)
                .max(retry_after_seconds.unwrap_or(0));
            self.repository
                .reschedule_revocation(
                    &platform.organization_id,
                    &platform.id,
                    &lease_owner,
                    Utc::now() + Duration::seconds(i64::try_from(delay).unwrap_or(3_600)),
                    "canvas_oauth_revoke_failed",
                )
                .await?;
            self.repository
                .patch_platform(
                    &platform.organization_id,
                    &platform.id,
                    platform.config_version,
                    CanvasOAuthPlatformPatch::RevocationPending,
                )
                .await?;
            return Ok(CanvasOAuthConnectionResponse {
                platform_id: platform.id,
                status: "revocation_pending".to_owned(),
                scopes: leased.scopes,
            });
        }
        let secret_ids = [
            leased.access_token_secret_ref.as_deref(),
            leased.refresh_token_secret_ref.as_deref(),
        ]
        .into_iter()
        .flatten()
        .filter_map(|secret_ref| {
            integration_secret_id_from_ref(&platform.organization_id, secret_ref).map(str::to_owned)
        })
        .collect::<Vec<_>>();
        if !self
            .repository
            .complete_revocation(
                &platform.organization_id,
                &platform.id,
                &lease_owner,
                &secret_ids,
            )
            .await?
        {
            return Err(CanvasOAuthError::ConnectionChanged);
        }
        self.repository
            .patch_platform(
                &platform.organization_id,
                &platform.id,
                platform.config_version,
                CanvasOAuthPlatformPatch::Disconnected,
            )
            .await?;
        Ok(disconnected_response(&platform.id))
    }

    fn require_pilot(&self, organization_id: &str) -> Result<(), CanvasOAuthError> {
        if portable_canvas_pilot_enabled(
            self.config.portable_enabled,
            &self.config.pilot_organizations,
            organization_id,
        ) {
            Ok(())
        } else {
            Err(CanvasOAuthError::PilotDisabled)
        }
    }

    fn callback_response(
        &self,
        platform_id: Option<&str>,
        outcome: &str,
        error_code: Option<&str>,
    ) -> Result<CanvasOAuthCallbackResponse, CanvasOAuthError> {
        let mut location = self.completion_base_url.clone();
        {
            let mut query = location.query_pairs_mut();
            query.append_pair("outcome", outcome);
            if let Some(platform_id) = platform_id {
                query.append_pair("platform_id", platform_id);
            }
            if let Some(error_code) = error_code {
                query.append_pair("error_code", error_code);
            }
        }
        Ok(CanvasOAuthCallbackResponse {
            location: location.into(),
        })
    }

    async fn best_effort_revoke(&self, canvas_base_url: &str, access_token: &str) {
        let _ = self.provider.revoke(canvas_base_url, access_token).await;
    }
}

fn checked_token_expiration(
    now: DateTime<Utc>,
    expires_in_seconds: Option<i64>,
) -> Result<Option<DateTime<Utc>>, ()> {
    expires_in_seconds.map_or(Ok(None), |seconds| {
        Duration::try_seconds(seconds.max(0))
            .and_then(|duration| now.checked_add_signed(duration))
            .map(Some)
            .ok_or(())
    })
}

fn trusted_organization(value: Option<&str>) -> Result<&str, CanvasOAuthError> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(CanvasOAuthError::Security(
            TransactionReadError::TrustedOrganizationRequired,
        ))
}

fn trusted_completion_url(value: &str) -> Result<Url, CanvasOAuthError> {
    let parsed = Url::parse(value).map_err(|_| CanvasOAuthError::InvalidConfiguration)?;
    let local_http = crate::config::is_loopback_http_url(&parsed);
    if (parsed.scheme() != "https" && !local_http)
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(CanvasOAuthError::InvalidConfiguration);
    }
    Ok(parsed)
}

fn normalize_capabilities(values: &[String]) -> Result<Vec<String>, CanvasOAuthError> {
    let mut normalized = Vec::new();
    for raw in values {
        let candidate = raw.trim();
        let candidate = CAPABILITY_ALIASES
            .iter()
            .find_map(|(alias, canonical)| (*alias == candidate).then_some(*canonical))
            .unwrap_or(candidate);
        if !candidate.is_empty() && !normalized.iter().any(|value| value == candidate) {
            normalized.push(candidate.to_owned());
        }
    }
    if normalized.is_empty() {
        return Err(CanvasOAuthError::CapabilitiesRequired);
    }
    let mut unknown = normalized
        .iter()
        .filter(|value| !CAPABILITY_SCOPES.iter().any(|(known, _)| known == value))
        .cloned()
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        unknown.sort();
        unknown.dedup();
        return Err(CanvasOAuthError::UnsupportedCapabilities(
            unknown.join(", "),
        ));
    }
    Ok(normalized)
}

fn scopes_for_capabilities(capabilities: &[String]) -> Vec<String> {
    let mut scopes = Vec::new();
    for capability in capabilities {
        if let Some((_, capability_scopes)) = CAPABILITY_SCOPES
            .iter()
            .find(|(known, _)| known == capability)
        {
            for scope in *capability_scopes {
                if !scopes.iter().any(|value| value == scope) {
                    scopes.push((*scope).to_owned());
                }
            }
        }
    }
    scopes
}

fn authorization_url(
    authorization: &CanvasOAuthAuthorization,
    state: &str,
) -> Result<String, CanvasOAuthError> {
    let mut endpoint = Url::parse(&authorization.canvas_base_url)
        .and_then(|base| base.join("/login/oauth2/auth"))
        .map_err(|_| CanvasOAuthError::OriginUntrusted)?;
    endpoint
        .query_pairs_mut()
        .append_pair("client_id", &authorization.client_id)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", &authorization.redirect_uri)
        .append_pair("state", state)
        .append_pair("scope", &authorization.scopes.join(" "));
    Ok(endpoint.into())
}

fn secure_token(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn hash_state(state: &str) -> String {
    hex::encode(Sha256::digest(state.as_bytes()))
}

fn disconnected_response(platform_id: &str) -> CanvasOAuthConnectionResponse {
    CanvasOAuthConnectionResponse {
        platform_id: platform_id.to_owned(),
        status: "disconnected".to_owned(),
        scopes: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::{normalize_capabilities, scopes_for_capabilities, CanvasOAuthError};

    #[test]
    fn capability_aliases_deduplicate_and_derive_the_frozen_scope_order() {
        let capabilities = normalize_capabilities(&[
            "scope_catalog.read".to_owned(),
            "catalog".to_owned(),
            "course_progress.read".to_owned(),
        ])
        .expect("capabilities");
        assert_eq!(capabilities, ["catalog", "course_completion"]);
        assert_eq!(
            scopes_for_capabilities(&capabilities),
            [
                "url:GET|/api/v1/courses",
                "url:GET|/api/v1/courses/:course_id/assignments",
                "url:GET|/api/v1/courses/:course_id/modules",
                "url:GET|/api/v1/courses/:course_id/users/:user_id/progress",
            ]
        );
        assert_eq!(
            normalize_capabilities(&["unknown".to_owned()]),
            Err(CanvasOAuthError::UnsupportedCapabilities(
                "unknown".to_owned()
            ))
        );
    }
}
