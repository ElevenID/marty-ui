//! Application service for the Canvas platform-management lifecycle.

use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use mmf_security::constant_time_secret_eq;
use rand::RngCore;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    canvas_lti_probe::{
        probe_canvas_lti_metadata, CanvasLtiJwksRefreshConfig, CanvasLtiMetadataProbeError,
        CanvasLtiProbeClient, CanvasLtiProbeResponse, MartyCanvasLtiProbeClient,
    },
    canvas_management::{
        CanvasLtiInstallationRequest, CanvasPlatformRequest, CanvasRequestValidationError,
    },
    canvas_management_domain::{
        CanvasManagementDomainError, CanvasOriginPolicy, CanvasPlatformRecord,
    },
    management_security::ManagementSecurity,
    transaction_reads::TransactionReadError,
};

#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum CanvasManagementRepositoryError {
    #[error("Canvas management repository is unavailable")]
    Unavailable,
    #[error("Canvas platform already exists")]
    Duplicate,
    #[error("Canvas platform configuration changed")]
    ConfigurationChanged,
    #[error("Canvas OAuth connection changed")]
    OAuthConnectionChanged,
    #[error("Canvas platform configuration version is exhausted")]
    VersionExhausted,
}

#[derive(Debug, Error, PartialEq)]
pub enum CanvasPlatformManagementError {
    #[error(transparent)]
    Security(#[from] TransactionReadError),
    #[error(transparent)]
    Domain(#[from] CanvasManagementDomainError),
    #[error("Canvas platform not found")]
    PlatformNotFound,
    #[error("Canvas LTI configuration not found")]
    LtiConfigurationNotFound,
    #[error("Rotate and revoke are mutually exclusive")]
    ConflictingTokenMutation,
    #[error("Canvas LTI metadata probe failed: {0}")]
    LtiMetadataProbeFailed(String),
    #[error("Canvas metadata probe returned endpoints outside the persisted trust profile")]
    LtiMetadataEndpointMismatch,
    #[error("Canvas platform requires canvas_base_url before probing")]
    SandboxProbeBaseUrlRequired,
    #[error("Canvas sandbox probe failed: {0}")]
    SandboxProbeFailed(String),
    #[error("Canvas platform requires canvas_base_url before refreshing JWKS")]
    JwksRefreshBaseUrlRequired,
    #[error("Canvas JWKS refresh failed: {0}")]
    JwksRefreshFailed(String),
    #[error("Canvas platform configuration changed; retry the request")]
    ConfigurationChanged,
    #[error("Canvas platform configuration changed; retry platform archival")]
    ArchivalConfigurationChanged,
    #[error("Canvas OAuth connection changed; retry platform archival")]
    OAuthConnectionChanged,
    #[error("Canvas platform conflicts with an existing resource")]
    Conflict,
    #[error("Canvas platform repository is unavailable")]
    RepositoryUnavailable,
}

#[async_trait]
pub trait CanvasPlatformManagementRepository: Send + Sync {
    async fn create_platform(
        &self,
        platform: &CanvasPlatformRecord,
    ) -> Result<(), CanvasManagementRepositoryError>;

    async fn active_platform(
        &self,
        organization_id: &str,
        platform_id: &str,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError>;

    async fn list_active_platforms(
        &self,
        organization_id: &str,
    ) -> Result<Vec<CanvasPlatformRecord>, CanvasManagementRepositoryError>;

    async fn public_platform(
        &self,
        platform_id: &str,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError>;

    async fn platform_for_archival(
        &self,
        organization_id: &str,
        platform_id: &str,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError>;

    async fn save_platform_configuration(
        &self,
        platform: &CanvasPlatformRecord,
        expected_config_version: i64,
        configuration_changed: bool,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError>;

    async fn archive_platform(
        &self,
        organization_id: &str,
        platform_id: &str,
        expected_config_version: i64,
        now: DateTime<Utc>,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError>;

    async fn save_registration_state(
        &self,
        platform: &CanvasPlatformRecord,
        expected_config_version: i64,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError>;

    async fn save_lti_installation(
        &self,
        platform: &CanvasPlatformRecord,
        expected_config_version: i64,
        expected_updated_at: DateTime<Utc>,
        invalidate_bindings: bool,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError>;

    async fn save_lti_probe_metadata(
        &self,
        platform: &CanvasPlatformRecord,
        expected_config_version: i64,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError>;
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CanvasLtiRegistrationResponse {
    pub platform_id: String,
    pub developer_key_configuration: Value,
    pub installation: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasPlatformProbeResult {
    pub platform: CanvasPlatformRecord,
    pub probe: CanvasLtiProbeResponse,
}

#[derive(Clone)]
pub struct CanvasPlatformManagementService {
    repository: Arc<dyn CanvasPlatformManagementRepository>,
    security: ManagementSecurity,
    origin_policy: CanvasOriginPolicy,
    issuer_base_url: String,
    lti_probe_config: CanvasLtiJwksRefreshConfig,
    lti_probe_client: Arc<dyn CanvasLtiProbeClient>,
}

impl std::fmt::Debug for CanvasPlatformManagementService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasPlatformManagementService")
            .field("security", &self.security)
            .field("origin_policy", &self.origin_policy)
            .field("issuer_base_url", &self.issuer_base_url)
            .field("lti_probe_config", &self.lti_probe_config)
            .finish_non_exhaustive()
    }
}

impl CanvasPlatformManagementService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn CanvasPlatformManagementRepository>,
        management_api_key: Option<&str>,
        origin_policy: CanvasOriginPolicy,
        issuer_base_url: &str,
        lti_probe_config: CanvasLtiJwksRefreshConfig,
    ) -> Self {
        Self {
            repository,
            security: ManagementSecurity::new(management_api_key),
            origin_policy,
            issuer_base_url: issuer_base_url.trim_end_matches('/').to_owned(),
            lti_probe_config,
            lti_probe_client: Arc::new(MartyCanvasLtiProbeClient),
        }
    }

    #[must_use]
    pub fn with_probe_client(
        repository: Arc<dyn CanvasPlatformManagementRepository>,
        management_api_key: Option<&str>,
        origin_policy: CanvasOriginPolicy,
        issuer_base_url: &str,
        lti_probe_config: CanvasLtiJwksRefreshConfig,
        lti_probe_client: Arc<dyn CanvasLtiProbeClient>,
    ) -> Self {
        Self {
            repository,
            security: ManagementSecurity::new(management_api_key),
            origin_policy,
            issuer_base_url: issuer_base_url.trim_end_matches('/').to_owned(),
            lti_probe_config,
            lti_probe_client,
        }
    }

    pub fn authorize_request<'organization>(
        &self,
        api_key: Option<&str>,
        trusted_organization_id: Option<&'organization str>,
    ) -> Result<&'organization str, CanvasPlatformManagementError> {
        self.authorize(api_key, trusted_organization_id)
    }

    pub async fn create(
        &self,
        request: CanvasPlatformRequest,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<CanvasPlatformRecord, CanvasPlatformManagementError> {
        let organization_id = self.authorize(api_key, trusted_organization_id)?;
        let origin = self.origin_policy.resolve(&request.canvas_base_url)?;
        let platform = CanvasPlatformRecord::new_draft(
            organization_id.to_owned(),
            request,
            origin,
            Utc::now(),
        )?;
        self.repository
            .create_platform(&platform)
            .await
            .map_err(map_repository_error)?;
        Ok(platform)
    }

    pub async fn list(
        &self,
        claimed_organization_id: Option<&str>,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<Vec<CanvasPlatformRecord>, CanvasPlatformManagementError> {
        let organization_id =
            self.authorize_claimed(api_key, trusted_organization_id, claimed_organization_id)?;
        self.repository
            .list_active_platforms(organization_id)
            .await
            .map_err(map_repository_error)
    }

    pub async fn get(
        &self,
        platform_id: &str,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<CanvasPlatformRecord, CanvasPlatformManagementError> {
        let organization_id = self.authorize(api_key, trusted_organization_id)?;
        self.repository
            .active_platform(organization_id, platform_id)
            .await
            .map_err(map_repository_error)?
            .ok_or(CanvasPlatformManagementError::PlatformNotFound)
    }

    pub async fn update(
        &self,
        platform_id: &str,
        request: CanvasPlatformRequest,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<CanvasPlatformRecord, CanvasPlatformManagementError> {
        let organization_id = self.authorize(api_key, trusted_organization_id)?;
        let mut platform = self
            .repository
            .active_platform(organization_id, platform_id)
            .await
            .map_err(map_repository_error)?
            .ok_or(CanvasPlatformManagementError::PlatformNotFound)?;
        let expected_config_version = platform.config_version;
        let origin = self.origin_policy.resolve(&request.canvas_base_url)?;
        let configuration_changed = platform.reconfigure(request, origin, Utc::now())?;
        self.repository
            .save_platform_configuration(&platform, expected_config_version, configuration_changed)
            .await
            .map_err(map_repository_error)?
            .ok_or(CanvasPlatformManagementError::ConfigurationChanged)
    }

    pub async fn delete(
        &self,
        platform_id: &str,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<(), CanvasPlatformManagementError> {
        let organization_id = self.authorize(api_key, trusted_organization_id)?;
        let platform = self
            .repository
            .platform_for_archival(organization_id, platform_id)
            .await
            .map_err(map_repository_error)?
            .ok_or(CanvasPlatformManagementError::PlatformNotFound)?;
        self.repository
            .archive_platform(
                organization_id,
                platform_id,
                platform.config_version,
                Utc::now(),
            )
            .await
            .map_err(map_archive_repository_error)?
            .ok_or(CanvasPlatformManagementError::PlatformNotFound)?;
        Ok(())
    }

    pub async fn registration_config(
        &self,
        platform_id: &str,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<CanvasLtiRegistrationResponse, CanvasPlatformManagementError> {
        let organization_id = self.authorize(api_key, trusted_organization_id)?;
        let mut platform = self
            .repository
            .active_platform(organization_id, platform_id)
            .await
            .map_err(map_repository_error)?
            .ok_or(CanvasPlatformManagementError::PlatformNotFound)?;
        let expected_config_version = platform.config_version;
        let expected_updated_at = platform.updated_at;
        let token = issue_config_token(&platform.id);
        platform.issue_lti_config_token(token_hash(&token), Utc::now());
        let platform = self
            .repository
            .save_registration_state(&platform, expected_config_version, expected_updated_at)
            .await
            .map_err(map_repository_error)?
            .ok_or(CanvasPlatformManagementError::ConfigurationChanged)?;
        Ok(self.registration_response(&platform, Some(&token)))
    }

    pub async fn public_registration_config(
        &self,
        token: &str,
    ) -> Result<Value, CanvasPlatformManagementError> {
        let platform_id = platform_id_from_config_token(token)
            .ok_or(CanvasPlatformManagementError::LtiConfigurationNotFound)?;
        let platform = self
            .repository
            .public_platform(&platform_id)
            .await
            .map_err(map_repository_error)?
            .filter(|platform| platform.archived_at.is_none())
            .ok_or(CanvasPlatformManagementError::LtiConfigurationNotFound)?;
        let expected = platform
            .active_lti_config_token_hash()
            .ok_or(CanvasPlatformManagementError::LtiConfigurationNotFound)?;
        let actual = token_hash(token);
        if !constant_time_secret_eq(expected.as_bytes(), actual.as_bytes()) {
            return Err(CanvasPlatformManagementError::LtiConfigurationNotFound);
        }
        Ok(self
            .registration_response(&platform, None)
            .developer_key_configuration)
    }

    pub async fn update_lti_installation(
        &self,
        platform_id: &str,
        request: CanvasLtiInstallationRequest,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<CanvasLtiRegistrationResponse, CanvasPlatformManagementError> {
        let organization_id = self.authorize(api_key, trusted_organization_id)?;
        let mut platform = self
            .repository
            .active_platform(organization_id, platform_id)
            .await
            .map_err(map_repository_error)?
            .ok_or(CanvasPlatformManagementError::PlatformNotFound)?;
        let expected_config_version = platform.config_version;
        let expected_updated_at = platform.updated_at;
        let changed = platform
            .prepare_lti_installation(&request, Utc::now())
            .map_err(|error| match error {
                CanvasManagementDomainError::InvalidRequest(
                    CanvasRequestValidationError::ConflictingTokenMutation,
                ) => CanvasPlatformManagementError::ConflictingTokenMutation,
                error => CanvasPlatformManagementError::Domain(error),
            })?;

        if let Some(canvas_base_url) = platform.canvas_base_url.clone() {
            match probe_canvas_lti_metadata(
                &canvas_base_url,
                &platform.lti_trust_profile,
                &self.lti_probe_config,
                self.lti_probe_client.as_ref(),
            )
            .await
            {
                Ok(probe) => platform.apply_lti_metadata_probe(
                    probe,
                    self.lti_probe_config.ttl,
                    Utc::now(),
                )?,
                Err(CanvasLtiMetadataProbeError::Provider(error)) => {
                    platform.record_lti_probe_failure(error.clone(), Utc::now());
                    self.repository
                        .save_lti_installation(
                            &platform,
                            expected_config_version,
                            expected_updated_at,
                            changed,
                        )
                        .await
                        .map_err(map_repository_error)?
                        .ok_or(CanvasPlatformManagementError::ConfigurationChanged)?;
                    return Err(CanvasPlatformManagementError::LtiMetadataProbeFailed(error));
                }
                Err(CanvasLtiMetadataProbeError::EndpointMismatch) => {
                    return Err(CanvasPlatformManagementError::LtiMetadataEndpointMismatch);
                }
            }
        }
        platform.complete_lti_installation_after_probe();

        let mut token = None;
        if request.revoke_config_token {
            platform.revoke_lti_config_token(Utc::now());
        } else if changed
            || request.rotate_config_token
            || platform.active_lti_config_token_hash().is_none()
        {
            let issued = issue_config_token(&platform.id);
            platform.issue_lti_config_token(token_hash(&issued), Utc::now());
            token = Some(issued);
        }
        let platform = self
            .repository
            .save_lti_installation(
                &platform,
                expected_config_version,
                expected_updated_at,
                changed,
            )
            .await
            .map_err(map_repository_error)?
            .ok_or(CanvasPlatformManagementError::ConfigurationChanged)?;
        Ok(self.registration_response(&platform, token.as_deref()))
    }

    pub async fn sandbox_probe(
        &self,
        platform_id: &str,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<CanvasPlatformProbeResult, CanvasPlatformManagementError> {
        self.probe_and_persist(
            platform_id,
            api_key,
            trusted_organization_id,
            CanvasProbeOperation::Sandbox,
        )
        .await
    }

    pub async fn refresh_jwks(
        &self,
        platform_id: &str,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<CanvasPlatformProbeResult, CanvasPlatformManagementError> {
        self.probe_and_persist(
            platform_id,
            api_key,
            trusted_organization_id,
            CanvasProbeOperation::JwksRefresh,
        )
        .await
    }

    async fn probe_and_persist(
        &self,
        platform_id: &str,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
        operation: CanvasProbeOperation,
    ) -> Result<CanvasPlatformProbeResult, CanvasPlatformManagementError> {
        let organization_id = self.authorize(api_key, trusted_organization_id)?;
        let mut platform = self
            .repository
            .active_platform(organization_id, platform_id)
            .await
            .map_err(map_repository_error)?
            .ok_or(CanvasPlatformManagementError::PlatformNotFound)?;
        let expected_config_version = platform.config_version;
        let expected_updated_at = platform.updated_at;
        let canvas_base_url = platform
            .canvas_base_url
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| operation.base_url_error())?;
        let probe = probe_canvas_lti_metadata(
            &canvas_base_url,
            &platform.lti_trust_profile,
            &self.lti_probe_config,
            self.lti_probe_client.as_ref(),
        )
        .await
        .map_err(|error| match error {
            CanvasLtiMetadataProbeError::Provider(error) => operation.probe_error(error),
            CanvasLtiMetadataProbeError::EndpointMismatch => {
                CanvasPlatformManagementError::LtiMetadataEndpointMismatch
            }
        })?;
        let response = CanvasLtiProbeResponse::from_probe(&probe, &platform.lti_trust_profile);
        platform.apply_lti_metadata_probe(probe, self.lti_probe_config.ttl, Utc::now())?;
        let platform = self
            .repository
            .save_lti_probe_metadata(&platform, expected_config_version, expected_updated_at)
            .await
            .map_err(map_repository_error)?
            .ok_or(CanvasPlatformManagementError::ConfigurationChanged)?;
        Ok(CanvasPlatformProbeResult {
            platform,
            probe: response,
        })
    }

    fn registration_response(
        &self,
        platform: &CanvasPlatformRecord,
        config_token: Option<&str>,
    ) -> CanvasLtiRegistrationResponse {
        let launch_url = format!(
            "{}/v1/integrations/canvas/lti/platforms/{}/experience",
            self.issuer_base_url, platform.id
        );
        let login_url = format!(
            "{}/v1/integrations/canvas/lti/platforms/{}/experience-login",
            self.issuer_base_url, platform.id
        );
        let jwks_url = format!("{}/v1/integrations/canvas/lti/jwks", self.issuer_base_url);
        let capability_intent = platform
            .connection_config
            .get("lti_capability_intent")
            .and_then(Value::as_array);
        let has_capability = |expected: &str| {
            capability_intent
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(expected)))
        };
        let mut scopes = Vec::new();
        if has_capability("ags") {
            scopes.push(json!(
                "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly"
            ));
            scopes.push(json!(
                "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly"
            ));
        }
        if has_capability("nrps") {
            scopes.push(json!(
                "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly"
            ));
        }
        let developer_key_configuration = json!({
            "tool_id": "marty-portable-canvas-v1",
            "title": "Marty Portable Credentials",
            "description": "Issue externally signed Open Badges from authorized Canvas learning evidence.",
            "target_link_uri": launch_url,
            "oidc_initiation_url": login_url,
            "public_jwk_url": jwks_url,
            "custom_fields": {
                "canvas_user_id": "$Canvas.user.id",
                "canvas_course_id": "$Canvas.course.id",
                "canvas_account_id": "$Canvas.account.id",
                "canvas_assignment_id": "$Canvas.assignment.id",
            },
            "scopes": scopes,
            "extensions": [{
                "platform": "canvas.instructure.com",
                "privacy_level": "public",
                "settings": {"placements": [
                    {"placement": "course_navigation", "message_type": "LtiResourceLinkRequest", "target_link_uri": launch_url},
                    {"placement": "assignment_selection", "message_type": "LtiDeepLinkingRequest", "target_link_uri": launch_url},
                ]},
            }],
        });
        let mut installation = serde_json::Map::from_iter([
            ("method".to_owned(), json!("institution_admin_lti_1_3")),
            ("login_url".to_owned(), json!(login_url)),
            ("launch_url".to_owned(), json!(launch_url)),
            ("jwks_url".to_owned(), json!(jwks_url)),
        ]);
        if let Some(config_token) = config_token {
            installation.insert(
                "config_url".to_owned(),
                json!(format!(
                    "{}/v1/integrations/canvas/lti/config/{config_token}",
                    self.issuer_base_url
                )),
            );
        }
        CanvasLtiRegistrationResponse {
            platform_id: platform.id.clone(),
            developer_key_configuration,
            installation: Value::Object(installation),
        }
    }

    fn authorize<'organization>(
        &self,
        api_key: Option<&str>,
        trusted_organization_id: Option<&'organization str>,
    ) -> Result<&'organization str, CanvasPlatformManagementError> {
        self.security.authorize(api_key)?;
        trusted_organization_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or({
                CanvasPlatformManagementError::Security(
                    TransactionReadError::TrustedOrganizationRequired,
                )
            })
    }

    fn authorize_claimed<'organization>(
        &self,
        api_key: Option<&str>,
        trusted_organization_id: Option<&'organization str>,
        claimed_organization_id: Option<&str>,
    ) -> Result<&'organization str, CanvasPlatformManagementError> {
        let trusted = self.authorize(api_key, trusted_organization_id)?;
        let claimed = claimed_organization_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or({
                CanvasPlatformManagementError::Security(
                    TransactionReadError::OrganizationIdRequired,
                )
            })?;
        self.security
            .require_organization(Some(trusted), claimed, true)?;
        Ok(trusted)
    }
}

#[derive(Clone, Copy)]
enum CanvasProbeOperation {
    Sandbox,
    JwksRefresh,
}

impl CanvasProbeOperation {
    const fn base_url_error(self) -> CanvasPlatformManagementError {
        match self {
            Self::Sandbox => CanvasPlatformManagementError::SandboxProbeBaseUrlRequired,
            Self::JwksRefresh => CanvasPlatformManagementError::JwksRefreshBaseUrlRequired,
        }
    }

    fn probe_error(self, error: String) -> CanvasPlatformManagementError {
        match self {
            Self::Sandbox => CanvasPlatformManagementError::SandboxProbeFailed(error),
            Self::JwksRefresh => CanvasPlatformManagementError::JwksRefreshFailed(error),
        }
    }
}

fn issue_config_token(platform_id: &str) -> String {
    let mut secret = [0_u8; 32];
    rand::rng().fill_bytes(&mut secret);
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(platform_id.as_bytes()),
        URL_SAFE_NO_PAD.encode(secret)
    )
}

fn platform_id_from_config_token(token: &str) -> Option<String> {
    let (prefix, secret) = token.split_once('.')?;
    if prefix.is_empty() || secret.is_empty() {
        return None;
    }
    String::from_utf8(URL_SAFE_NO_PAD.decode(prefix).ok()?)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn map_repository_error(error: CanvasManagementRepositoryError) -> CanvasPlatformManagementError {
    match error {
        CanvasManagementRepositoryError::Duplicate => CanvasPlatformManagementError::Conflict,
        CanvasManagementRepositoryError::ConfigurationChanged => {
            CanvasPlatformManagementError::ConfigurationChanged
        }
        CanvasManagementRepositoryError::OAuthConnectionChanged => {
            CanvasPlatformManagementError::OAuthConnectionChanged
        }
        CanvasManagementRepositoryError::VersionExhausted => {
            CanvasPlatformManagementError::Domain(CanvasManagementDomainError::VersionExhausted)
        }
        CanvasManagementRepositoryError::Unavailable => {
            CanvasPlatformManagementError::RepositoryUnavailable
        }
    }
}

fn map_archive_repository_error(
    error: CanvasManagementRepositoryError,
) -> CanvasPlatformManagementError {
    match error {
        CanvasManagementRepositoryError::ConfigurationChanged => {
            CanvasPlatformManagementError::ArchivalConfigurationChanged
        }
        other => map_repository_error(other),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct MemoryRepository {
        platforms: Mutex<Vec<CanvasPlatformRecord>>,
        force_conflict: Mutex<bool>,
        force_oauth_conflict: Mutex<bool>,
    }

    #[async_trait]
    impl CanvasPlatformManagementRepository for MemoryRepository {
        async fn create_platform(
            &self,
            platform: &CanvasPlatformRecord,
        ) -> Result<(), CanvasManagementRepositoryError> {
            let mut platforms = self.platforms.lock().await;
            if platforms
                .iter()
                .any(|candidate| candidate.id == platform.id)
            {
                return Err(CanvasManagementRepositoryError::Duplicate);
            }
            platforms.push(platform.clone());
            Ok(())
        }

        async fn active_platform(
            &self,
            organization_id: &str,
            platform_id: &str,
        ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
            Ok(self
                .platforms
                .lock()
                .await
                .iter()
                .find(|platform| {
                    platform.organization_id == organization_id
                        && platform.id == platform_id
                        && platform.archived_at.is_none()
                })
                .cloned())
        }

        async fn list_active_platforms(
            &self,
            organization_id: &str,
        ) -> Result<Vec<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
            Ok(self
                .platforms
                .lock()
                .await
                .iter()
                .filter(|platform| {
                    platform.organization_id == organization_id && platform.archived_at.is_none()
                })
                .cloned()
                .collect())
        }

        async fn public_platform(
            &self,
            platform_id: &str,
        ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
            Ok(self
                .platforms
                .lock()
                .await
                .iter()
                .find(|platform| platform.id == platform_id)
                .cloned())
        }

        async fn platform_for_archival(
            &self,
            organization_id: &str,
            platform_id: &str,
        ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
            Ok(self
                .platforms
                .lock()
                .await
                .iter()
                .find(|platform| {
                    platform.organization_id == organization_id && platform.id == platform_id
                })
                .cloned())
        }

        async fn save_platform_configuration(
            &self,
            platform: &CanvasPlatformRecord,
            expected_config_version: i64,
            _configuration_changed: bool,
        ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
            if *self.force_conflict.lock().await {
                return Ok(None);
            }
            let mut platforms = self.platforms.lock().await;
            let Some(existing) = platforms.iter_mut().find(|candidate| {
                candidate.organization_id == platform.organization_id
                    && candidate.id == platform.id
                    && candidate.archived_at.is_none()
                    && candidate.config_version == expected_config_version
            }) else {
                return Ok(None);
            };
            *existing = platform.clone();
            Ok(Some(existing.clone()))
        }

        async fn archive_platform(
            &self,
            organization_id: &str,
            platform_id: &str,
            expected_config_version: i64,
            now: DateTime<Utc>,
        ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
            if *self.force_oauth_conflict.lock().await {
                return Err(CanvasManagementRepositoryError::OAuthConnectionChanged);
            }
            let mut platforms = self.platforms.lock().await;
            let Some(platform) = platforms.iter_mut().find(|platform| {
                platform.organization_id == organization_id && platform.id == platform_id
            }) else {
                return Ok(None);
            };
            if platform.archived_at.is_none()
                && (*self.force_conflict.lock().await
                    || platform.config_version != expected_config_version)
            {
                return Err(CanvasManagementRepositoryError::ConfigurationChanged);
            }
            platform
                .archive(false, now)
                .map_err(|_| CanvasManagementRepositoryError::VersionExhausted)?;
            platform.synchronize_archived_oauth_state(false, now);
            Ok(Some(platform.clone()))
        }

        async fn save_registration_state(
            &self,
            platform: &CanvasPlatformRecord,
            expected_config_version: i64,
            expected_updated_at: DateTime<Utc>,
        ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
            let mut platforms = self.platforms.lock().await;
            let Some(existing) = platforms.iter_mut().find(|candidate| {
                candidate.organization_id == platform.organization_id
                    && candidate.id == platform.id
                    && candidate.archived_at.is_none()
                    && candidate.config_version == expected_config_version
                    && candidate.updated_at == expected_updated_at
            }) else {
                return Ok(None);
            };
            existing.connection_config = platform.connection_config.clone();
            existing.updated_at = platform.updated_at;
            Ok(Some(existing.clone()))
        }

        async fn save_lti_installation(
            &self,
            platform: &CanvasPlatformRecord,
            expected_config_version: i64,
            expected_updated_at: DateTime<Utc>,
            _invalidate_bindings: bool,
        ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
            let mut platforms = self.platforms.lock().await;
            let Some(existing) = platforms.iter_mut().find(|candidate| {
                candidate.organization_id == platform.organization_id
                    && candidate.id == platform.id
                    && candidate.archived_at.is_none()
                    && candidate.config_version == expected_config_version
                    && candidate.updated_at == expected_updated_at
            }) else {
                return Ok(None);
            };
            *existing = platform.clone();
            Ok(Some(existing.clone()))
        }

        async fn save_lti_probe_metadata(
            &self,
            platform: &CanvasPlatformRecord,
            expected_config_version: i64,
            expected_updated_at: DateTime<Utc>,
        ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
            let mut platforms = self.platforms.lock().await;
            let Some(existing) = platforms.iter_mut().find(|candidate| {
                candidate.organization_id == platform.organization_id
                    && candidate.id == platform.id
                    && candidate.archived_at.is_none()
                    && candidate.config_version == expected_config_version
                    && candidate.updated_at == expected_updated_at
            }) else {
                return Ok(None);
            };
            existing.canvas_base_url = platform.canvas_base_url.clone();
            existing.lti_issuer = platform.lti_issuer.clone();
            existing.lti_jwks_url = platform.lti_jwks_url.clone();
            existing.lti_jwks_json = platform.lti_jwks_json.clone();
            existing.lti_jwks_fetched_at = platform.lti_jwks_fetched_at;
            existing.lti_jwks_expires_at = platform.lti_jwks_expires_at;
            existing.lti_openid_configuration = platform.lti_openid_configuration.clone();
            existing.last_connection_error = platform.last_connection_error.clone();
            existing.updated_at = platform.updated_at;
            Ok(Some(existing.clone()))
        }
    }

    fn request(name: &str, enabled: bool) -> CanvasPlatformRequest {
        CanvasPlatformRequest {
            display_name: Some(name.to_owned()),
            canvas_base_url: "https://canvas.example.edu".to_owned(),
            lti_client_id: Some("client".to_owned()),
            lti_deployment_id: Some("deployment".to_owned()),
            enabled,
        }
    }

    fn service(repository: Arc<MemoryRepository>) -> CanvasPlatformManagementService {
        CanvasPlatformManagementService::new(
            repository,
            Some("management-secret"),
            CanvasOriginPolicy::default(),
            "https://issuer.example.edu",
            CanvasLtiJwksRefreshConfig {
                timeout: std::time::Duration::from_secs(10),
                ttl: std::time::Duration::from_secs(3_600),
                self_managed_origins: Vec::new(),
                allow_private_networks: false,
                allow_http_localhost: false,
            },
        )
    }

    #[tokio::test]
    async fn create_list_get_and_update_share_one_security_boundary() {
        let repository = Arc::new(MemoryRepository::default());
        let service = service(repository);
        let created = service
            .create(
                request("Original", true),
                Some("management-secret"),
                Some("org-1"),
            )
            .await
            .unwrap();
        assert_eq!(created.organization_id, "org-1");
        assert!(!created.enabled);
        assert_eq!(created.connection_config["enabled_intent"], true);

        assert_eq!(
            service
                .list(Some("org-1"), Some("management-secret"), Some("org-1"))
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            service
                .get(&created.id, Some("management-secret"), Some("org-1"))
                .await
                .unwrap()
                .id,
            created.id
        );
        let updated = service
            .update(
                &created.id,
                request("Updated", true),
                Some("management-secret"),
                Some("org-1"),
            )
            .await
            .unwrap();
        assert_eq!(updated.display_name.as_deref(), Some("Updated"));
        assert_eq!(updated.config_version, 2);
    }

    #[tokio::test]
    async fn tenant_mismatch_and_archived_or_foreign_resources_are_hidden() {
        let repository = Arc::new(MemoryRepository::default());
        let service = service(repository);
        let created = service
            .create(
                request("Original", false),
                Some("management-secret"),
                Some("org-1"),
            )
            .await
            .unwrap();
        assert_eq!(
            service
                .list(Some("org-2"), Some("management-secret"), Some("org-1"))
                .await,
            Err(CanvasPlatformManagementError::Security(
                TransactionReadError::ResourceNotFound
            ))
        );
        assert_eq!(
            service
                .get(&created.id, Some("management-secret"), Some("org-2"))
                .await,
            Err(CanvasPlatformManagementError::PlatformNotFound)
        );
    }

    #[tokio::test]
    async fn missing_credentials_and_stale_writes_fail_closed() {
        let repository = Arc::new(MemoryRepository::default());
        let service = service(repository.clone());
        assert_eq!(
            service
                .create(request("Original", false), None, Some("org-1"))
                .await,
            Err(CanvasPlatformManagementError::Security(
                TransactionReadError::ApiKeyMissing
            ))
        );
        let created = service
            .create(
                request("Original", false),
                Some("management-secret"),
                Some("org-1"),
            )
            .await
            .unwrap();
        *repository.force_conflict.lock().await = true;
        assert_eq!(
            service
                .update(
                    &created.id,
                    request("Changed", false),
                    Some("management-secret"),
                    Some("org-1"),
                )
                .await,
            Err(CanvasPlatformManagementError::ConfigurationChanged)
        );
    }

    #[tokio::test]
    async fn deletion_is_tenant_hidden_idempotent_and_surfaces_queue_conflicts() {
        let repository = Arc::new(MemoryRepository::default());
        let service = service(repository.clone());
        let created = service
            .create(
                request("Original", true),
                Some("management-secret"),
                Some("org-1"),
            )
            .await
            .unwrap();
        assert_eq!(
            service
                .delete(&created.id, Some("management-secret"), Some("org-2"))
                .await,
            Err(CanvasPlatformManagementError::PlatformNotFound)
        );
        service
            .delete(&created.id, Some("management-secret"), Some("org-1"))
            .await
            .unwrap();
        service
            .delete(&created.id, Some("management-secret"), Some("org-1"))
            .await
            .unwrap();
        let archived = repository.platforms.lock().await[0].clone();
        assert!(archived.archived_at.is_some());
        assert_eq!(archived.config_version, 2);
        assert_eq!(archived.connection_config["oauth_status"], "disconnected");

        let second = service
            .create(
                request("Second", false),
                Some("management-secret"),
                Some("org-1"),
            )
            .await
            .unwrap();
        *repository.force_oauth_conflict.lock().await = true;
        assert_eq!(
            service
                .delete(&second.id, Some("management-secret"), Some("org-1"))
                .await,
            Err(CanvasPlatformManagementError::OAuthConnectionChanged)
        );
    }

    #[tokio::test]
    async fn invalid_origins_are_rejected_before_repository_access() {
        let repository = Arc::new(MemoryRepository::default());
        let service = service(repository.clone());
        let mut invalid = request("Invalid", false);
        invalid.canvas_base_url = "https://user:secret@canvas.example.edu".to_owned();
        assert!(matches!(
            service
                .create(invalid, Some("management-secret"), Some("org-1"))
                .await,
            Err(CanvasPlatformManagementError::Domain(
                CanvasManagementDomainError::OriginUntrusted
            ))
        ));
        assert!(repository.platforms.lock().await.is_empty());
    }
}
