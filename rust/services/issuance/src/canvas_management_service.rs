//! Application service for the Canvas platform-management lifecycle.

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use mmf_security::constant_time_secret_eq;
use rand::RngCore;
use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    canvas_binding_domain::{
        CanvasApplicationTemplateProjection, CanvasBindingDomainError, CanvasProgramBindingRecord,
    },
    canvas_lti_experience::portable_canvas_pilot_enabled,
    canvas_lti_probe::{
        probe_canvas_lti_metadata, CanvasLtiJwksRefreshConfig, CanvasLtiMetadataProbeError,
        CanvasLtiProbeClient, CanvasLtiProbeResponse, MartyCanvasLtiProbeClient,
    },
    canvas_management::{
        CanvasIntegrationSecretCreate, CanvasIntegrationSecretUpdate, CanvasLtiInstallationRequest,
        CanvasPlatformRequest, CanvasProgramBindingRequest, CanvasRequestValidationError,
        ValidateCanvasRequest,
    },
    canvas_management_domain::{
        CanvasManagementDomainError, CanvasOriginPolicy, CanvasPlatformRecord,
    },
    canvas_readiness::{
        apply_canvas_readiness_result, canvas_binding_is_ready_for_activation,
        evaluate_canvas_binding_readiness, readiness_timestamp,
        verified_canvas_binding_capabilities, CanvasBindingReadiness, CanvasReadinessCheck,
        CanvasReadinessInputs,
    },
    integration_secret::{integration_secret_hint, ManagedIntegrationSecret},
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
    #[error("Canvas program binding already exists")]
    DuplicateBinding,
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
    #[error("Canvas program binding not found")]
    BindingNotFound,
    #[error("Canvas readiness dependencies are not configured")]
    ReadinessUnavailable,
    #[error("Application template not found")]
    ApplicationTemplateNotFound,
    #[error("Canvas Credentials configuration requires an organization-owned API token secret")]
    CanvasCredentialsSecretRequired,
    #[error("Canvas Credentials API token secret was not found")]
    CanvasCredentialsSecretNotFound,
    #[error("Canvas Credentials API base URL must be a trusted HTTPS URL")]
    CanvasCredentialsUrlUntrusted,
    #[error("Canvas Credentials API origin is not operator allowlisted")]
    CanvasCredentialsOriginNotAllowed,
    #[error("A Canvas program binding already exists for this template and scope")]
    BindingConflict,
    #[error("Portable Canvas integration is not enabled for this organization")]
    PilotDisabled,
    #[error("Canvas program binding has blocking readiness checks")]
    ActivationBlocked(Vec<CanvasReadinessCheck>),
    #[error("Integration secret not found")]
    IntegrationSecretNotFound,
    #[error(transparent)]
    BindingDomain(#[from] CanvasBindingDomainError),
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

    async fn application_template(
        &self,
        template_id: &str,
    ) -> Result<Option<CanvasApplicationTemplateProjection>, CanvasManagementRepositoryError>;

    async fn valid_canvas_credentials_secret(
        &self,
        organization_id: &str,
        secret_id: &str,
    ) -> Result<bool, CanvasManagementRepositoryError>;

    async fn active_binding(
        &self,
        organization_id: &str,
        binding_id: &str,
    ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError>;

    async fn list_active_bindings(
        &self,
        organization_id: &str,
        platform_id: Option<&str>,
        application_template_id: Option<&str>,
    ) -> Result<Vec<CanvasProgramBindingRecord>, CanvasManagementRepositoryError>;

    async fn create_binding(
        &self,
        binding: &CanvasProgramBindingRecord,
    ) -> Result<(), CanvasManagementRepositoryError>;

    async fn save_binding_configuration(
        &self,
        binding: &CanvasProgramBindingRecord,
        expected_config_version: i64,
    ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError>;

    async fn save_binding_readiness(
        &self,
        binding: &CanvasProgramBindingRecord,
        expected_config_version: i64,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError>;

    async fn activate_binding(
        &self,
        activation: &CanvasBindingActivation,
    ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError>;

    async fn deactivate_binding(
        &self,
        binding: &CanvasProgramBindingRecord,
        deactivated_at: DateTime<Utc>,
    ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError>;

    async fn archive_binding(
        &self,
        organization_id: &str,
        binding_id: &str,
        expected_config_version: i64,
        now: DateTime<Utc>,
    ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError>;
}

#[async_trait]
pub trait CanvasReadinessInputProvider: Send + Sync {
    async fn inputs(
        &self,
        platform: &CanvasPlatformRecord,
        binding: &CanvasProgramBindingRecord,
        evaluated_at: DateTime<Utc>,
    ) -> CanvasReadinessInputs;
}

#[async_trait]
pub trait CanvasIntegrationSecretRepository: Send + Sync {
    async fn create_secret(
        &self,
        secret: &ManagedIntegrationSecret,
        plaintext: &str,
    ) -> Result<ManagedIntegrationSecret, CanvasManagementRepositoryError>;

    async fn secret(
        &self,
        organization_id: &str,
        secret_id: &str,
    ) -> Result<Option<ManagedIntegrationSecret>, CanvasManagementRepositoryError>;

    async fn list_secrets(
        &self,
        organization_id: &str,
        provider: Option<&str>,
    ) -> Result<Vec<ManagedIntegrationSecret>, CanvasManagementRepositoryError>;

    async fn update_secret(
        &self,
        secret: &ManagedIntegrationSecret,
        plaintext: Option<&str>,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<Option<ManagedIntegrationSecret>, CanvasManagementRepositoryError>;

    async fn delete_secret(
        &self,
        organization_id: &str,
        secret_id: &str,
    ) -> Result<bool, CanvasManagementRepositoryError>;
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

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasBindingValidationResult {
    pub binding: CanvasProgramBindingRecord,
    pub readiness: CanvasBindingReadiness,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasBindingActivation {
    pub binding: CanvasProgramBindingRecord,
    pub platform: CanvasPlatformRecord,
    pub activated_at: DateTime<Utc>,
    pub background_roster_metadata: Option<Map<String, Value>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasPlatformReadinessResult {
    pub platform_id: String,
    pub checks: Vec<CanvasReadinessCheck>,
}

impl CanvasPlatformReadinessResult {
    #[must_use]
    pub fn ready(&self) -> bool {
        self.checks
            .iter()
            .all(|check| !check.blocking || check.passed())
    }
}

#[derive(Clone)]
pub struct CanvasPlatformManagementService {
    repository: Arc<dyn CanvasPlatformManagementRepository>,
    security: ManagementSecurity,
    origin_policy: CanvasOriginPolicy,
    issuer_base_url: String,
    lti_probe_config: CanvasLtiJwksRefreshConfig,
    lti_probe_client: Arc<dyn CanvasLtiProbeClient>,
    canvas_credentials_origins: Arc<BTreeSet<String>>,
    readiness_input_provider: Option<Arc<dyn CanvasReadinessInputProvider>>,
    integration_secrets: Option<Arc<dyn CanvasIntegrationSecretRepository>>,
    portable_enabled: bool,
    pilot_organizations: Arc<BTreeSet<String>>,
    readiness_max_age: Duration,
}

impl std::fmt::Debug for CanvasPlatformManagementService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasPlatformManagementService")
            .field("security", &self.security)
            .field("origin_policy", &self.origin_policy)
            .field("issuer_base_url", &self.issuer_base_url)
            .field("lti_probe_config", &self.lti_probe_config)
            .field(
                "readiness_input_provider_configured",
                &self.readiness_input_provider.is_some(),
            )
            .field(
                "integration_secret_management_configured",
                &self.integration_secrets.is_some(),
            )
            .field("portable_enabled", &self.portable_enabled)
            .field("pilot_organization_count", &self.pilot_organizations.len())
            .field("readiness_max_age", &self.readiness_max_age)
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
            canvas_credentials_origins: Arc::new(BTreeSet::from([
                "https://api.badgr.io".to_owned()
            ])),
            readiness_input_provider: None,
            integration_secrets: None,
            portable_enabled: false,
            pilot_organizations: Arc::new(BTreeSet::new()),
            readiness_max_age: Duration::from_secs(900),
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
            canvas_credentials_origins: Arc::new(BTreeSet::from([
                "https://api.badgr.io".to_owned()
            ])),
            readiness_input_provider: None,
            integration_secrets: None,
            portable_enabled: false,
            pilot_organizations: Arc::new(BTreeSet::new()),
            readiness_max_age: Duration::from_secs(900),
        }
    }

    #[must_use]
    pub fn with_canvas_credentials_origins(
        mut self,
        origins: impl IntoIterator<Item = String>,
    ) -> Self {
        let mut trusted = BTreeSet::from(["https://api.badgr.io".to_owned()]);
        trusted.extend(
            origins
                .into_iter()
                .filter_map(|value| trusted_https_origin(&value)),
        );
        self.canvas_credentials_origins = Arc::new(trusted);
        self
    }

    #[must_use]
    pub fn with_readiness_input_provider(
        mut self,
        provider: Arc<dyn CanvasReadinessInputProvider>,
    ) -> Self {
        self.readiness_input_provider = Some(provider);
        self
    }

    #[must_use]
    pub fn with_activation_policy(
        mut self,
        portable_enabled: bool,
        pilot_organizations: BTreeSet<String>,
        readiness_max_age: Duration,
    ) -> Self {
        self.portable_enabled = portable_enabled;
        self.pilot_organizations = Arc::new(pilot_organizations);
        self.readiness_max_age = readiness_max_age;
        self
    }

    #[must_use]
    pub fn with_integration_secret_repository(
        mut self,
        repository: Arc<dyn CanvasIntegrationSecretRepository>,
    ) -> Self {
        self.integration_secrets = Some(repository);
        self
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

    async fn active_platform(
        &self,
        organization_id: &str,
        platform_id: &str,
    ) -> Result<CanvasPlatformRecord, CanvasPlatformManagementError> {
        self.repository
            .active_platform(organization_id, platform_id)
            .await
            .map_err(map_binding_repository_error)?
            .ok_or(CanvasPlatformManagementError::PlatformNotFound)
    }

    async fn active_binding(
        &self,
        organization_id: &str,
        binding_id: &str,
    ) -> Result<CanvasProgramBindingRecord, CanvasPlatformManagementError> {
        self.repository
            .active_binding(organization_id, binding_id)
            .await
            .map_err(map_binding_repository_error)?
            .ok_or(CanvasPlatformManagementError::BindingNotFound)
    }

    async fn application_template(
        &self,
        template_id: &str,
    ) -> Result<CanvasApplicationTemplateProjection, CanvasPlatformManagementError> {
        self.repository
            .application_template(template_id)
            .await
            .map_err(map_binding_repository_error)?
            .ok_or(CanvasPlatformManagementError::ApplicationTemplateNotFound)
    }

    async fn validated_canvas_credentials(
        &self,
        organization_id: &str,
        input: Option<&crate::canvas_management::CanvasCredentialsConfigInput>,
    ) -> Result<Map<String, Value>, CanvasPlatformManagementError> {
        let Some(input) = input else {
            return Ok(Map::new());
        };
        let secret_id = input
            .api_token_secret_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(CanvasPlatformManagementError::CanvasCredentialsSecretRequired)?;
        if !self
            .repository
            .valid_canvas_credentials_secret(organization_id, secret_id)
            .await
            .map_err(map_binding_repository_error)?
        {
            return Err(CanvasPlatformManagementError::CanvasCredentialsSecretNotFound);
        }
        if let Some(api_base_url) = input
            .api_base_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let parsed = url::Url::parse(api_base_url)
                .ok()
                .filter(|url| url.query().is_none() && url.fragment().is_none())
                .ok_or(CanvasPlatformManagementError::CanvasCredentialsUrlUntrusted)?;
            let origin = trusted_https_origin(parsed.as_str())
                .ok_or(CanvasPlatformManagementError::CanvasCredentialsUrlUntrusted)?;
            if !self.canvas_credentials_origins.contains(&origin) {
                return Err(CanvasPlatformManagementError::CanvasCredentialsOriginNotAllowed);
            }
        }
        let mut value = serde_json::to_value(input)
            .ok()
            .and_then(|value| value.as_object().cloned())
            .ok_or(CanvasPlatformManagementError::RepositoryUnavailable)?;
        value.retain(|_, value| !value.is_null());
        value.insert(
            "api_token_secret_id".to_owned(),
            Value::String(secret_id.to_owned()),
        );
        if let Some(Value::String(base_url)) = value.get_mut("api_base_url") {
            *base_url = base_url.trim().trim_end_matches('/').to_owned();
        }
        Ok(value)
    }

    pub async fn create_binding(
        &self,
        platform_id: &str,
        request: CanvasProgramBindingRequest,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<CanvasProgramBindingRecord, CanvasPlatformManagementError> {
        let organization_id = self.authorize(api_key, trusted_organization_id)?;
        let platform = self.active_platform(organization_id, platform_id).await?;
        let template = self
            .application_template(&request.application_template_id)
            .await?;
        let credentials = self
            .validated_canvas_credentials(organization_id, request.canvas_credentials.as_ref())
            .await?;
        let binding = CanvasProgramBindingRecord::configure(
            &platform,
            request,
            &template,
            credentials,
            None,
            Utc::now(),
        )?;
        self.repository
            .create_binding(&binding)
            .await
            .map_err(map_binding_repository_error)?;
        Ok(binding)
    }

    pub async fn list_bindings(
        &self,
        claimed_organization_id: Option<&str>,
        platform_id: Option<&str>,
        application_template_id: Option<&str>,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<Vec<CanvasProgramBindingRecord>, CanvasPlatformManagementError> {
        let organization_id =
            self.authorize_claimed(api_key, trusted_organization_id, claimed_organization_id)?;
        self.repository
            .list_active_bindings(organization_id, platform_id, application_template_id)
            .await
            .map_err(map_binding_repository_error)
    }

    pub async fn get_binding(
        &self,
        binding_id: &str,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<CanvasProgramBindingRecord, CanvasPlatformManagementError> {
        let organization_id = self.authorize(api_key, trusted_organization_id)?;
        self.active_binding(organization_id, binding_id).await
    }

    pub async fn update_binding(
        &self,
        binding_id: &str,
        request: CanvasProgramBindingRequest,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<CanvasProgramBindingRecord, CanvasPlatformManagementError> {
        let organization_id = self.authorize(api_key, trusted_organization_id)?;
        let existing = self.active_binding(organization_id, binding_id).await?;
        let platform = self
            .active_platform(organization_id, &existing.platform_id)
            .await?;
        let template = self
            .application_template(&request.application_template_id)
            .await?;
        let credentials = self
            .validated_canvas_credentials(organization_id, request.canvas_credentials.as_ref())
            .await?;
        let binding = CanvasProgramBindingRecord::configure(
            &platform,
            request,
            &template,
            credentials,
            Some(&existing),
            Utc::now(),
        )?;
        self.repository
            .save_binding_configuration(&binding, existing.config_version)
            .await
            .map_err(map_binding_repository_error)?
            .ok_or(CanvasPlatformManagementError::ConfigurationChanged)
    }

    pub async fn delete_binding(
        &self,
        binding_id: &str,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<(), CanvasPlatformManagementError> {
        let organization_id = self.authorize(api_key, trusted_organization_id)?;
        let existing = self.active_binding(organization_id, binding_id).await?;
        self.repository
            .archive_binding(
                organization_id,
                binding_id,
                existing.config_version,
                Utc::now(),
            )
            .await
            .map_err(map_binding_repository_error)?
            .ok_or(CanvasPlatformManagementError::ConfigurationChanged)?;
        Ok(())
    }

    pub async fn create_integration_secret(
        &self,
        request: CanvasIntegrationSecretCreate,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<ManagedIntegrationSecret, CanvasPlatformManagementError> {
        request
            .validate()
            .map_err(CanvasManagementDomainError::InvalidRequest)?;
        let organization_id = self.authorize_claimed(
            api_key,
            trusted_organization_id,
            Some(&request.organization_id),
        )?;
        let now = Utc::now();
        let secret = ManagedIntegrationSecret {
            id: uuid::Uuid::new_v4().to_string(),
            organization_id: organization_id.to_owned(),
            name: request.name.trim().to_owned(),
            provider: request.provider.as_str().to_owned(),
            purpose: request.purpose.as_str().to_owned(),
            secret_hint: integration_secret_hint(request.secret_value.expose()),
            metadata: request.metadata,
            enabled: request.enabled,
            created_at: now,
            updated_at: now,
            last_used_at: None,
        };
        self.integration_secret_repository()?
            .create_secret(&secret, request.secret_value.expose())
            .await
            .map_err(map_repository_error)
    }

    pub async fn list_integration_secrets(
        &self,
        claimed_organization_id: Option<&str>,
        provider: Option<&str>,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<Vec<ManagedIntegrationSecret>, CanvasPlatformManagementError> {
        let organization_id =
            self.authorize_claimed(api_key, trusted_organization_id, claimed_organization_id)?;
        self.integration_secret_repository()?
            .list_secrets(organization_id, provider)
            .await
            .map_err(map_repository_error)
    }

    pub async fn update_integration_secret(
        &self,
        secret_id: &str,
        request: CanvasIntegrationSecretUpdate,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<ManagedIntegrationSecret, CanvasPlatformManagementError> {
        let organization_id = self.authorize(api_key, trusted_organization_id)?;
        let repository = self.integration_secret_repository()?;
        let mut secret = repository
            .secret(organization_id, secret_id)
            .await
            .map_err(map_repository_error)?
            .ok_or(CanvasPlatformManagementError::IntegrationSecretNotFound)?;
        let expected_updated_at = secret.updated_at;
        if let Some(name) = request.name {
            secret.name = name.trim().to_owned();
        }
        if let Some(metadata) = request.metadata {
            secret.metadata = metadata;
        }
        if let Some(enabled) = request.enabled {
            secret.enabled = enabled;
        }
        // The Python repository treated an empty update value as "keep the
        // existing ciphertext". Preserve that observable behavior while a
        // non-empty value remains an explicit rotation.
        let plaintext = request
            .secret_value
            .as_ref()
            .map(|value| value.expose())
            .filter(|value| !value.is_empty());
        if let Some(hint) = plaintext.and_then(integration_secret_hint) {
            secret.secret_hint = Some(hint);
        }
        secret.updated_at = Utc::now();
        repository
            .update_secret(&secret, plaintext, expected_updated_at)
            .await
            .map_err(map_repository_error)?
            .ok_or(CanvasPlatformManagementError::ConfigurationChanged)
    }

    pub async fn delete_integration_secret(
        &self,
        secret_id: &str,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<(), CanvasPlatformManagementError> {
        let organization_id = self.authorize(api_key, trusted_organization_id)?;
        let deleted = self
            .integration_secret_repository()?
            .delete_secret(organization_id, secret_id)
            .await
            .map_err(map_repository_error)?;
        if !deleted {
            return Err(CanvasPlatformManagementError::IntegrationSecretNotFound);
        }
        Ok(())
    }

    pub async fn validate_binding(
        &self,
        binding_id: &str,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<CanvasBindingValidationResult, CanvasPlatformManagementError> {
        let organization_id = self.authorize(api_key, trusted_organization_id)?;
        let binding = self.active_binding(organization_id, binding_id).await?;
        let platform = self
            .active_platform(organization_id, &binding.platform_id)
            .await?;
        self.validate_loaded_binding(&platform, binding, Utc::now())
            .await
    }

    pub async fn activate_binding(
        &self,
        binding_id: &str,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<CanvasBindingValidationResult, CanvasPlatformManagementError> {
        let organization_id = self.authorize(api_key, trusted_organization_id)?;
        let binding = self.active_binding(organization_id, binding_id).await?;
        if !portable_canvas_pilot_enabled(
            self.portable_enabled,
            &self.pilot_organizations,
            organization_id,
        ) {
            return Err(CanvasPlatformManagementError::PilotDisabled);
        }
        let platform = self
            .active_platform(organization_id, &binding.platform_id)
            .await?;
        let evaluated_at = Utc::now();
        let mut validation = self
            .validate_loaded_binding(&platform, binding, evaluated_at)
            .await?;
        if !validation.readiness.ready
            || !canvas_binding_is_ready_for_activation(
                &validation.binding,
                evaluated_at,
                self.readiness_max_age,
            )
        {
            return Err(CanvasPlatformManagementError::ActivationBlocked(
                validation
                    .readiness
                    .checks
                    .iter()
                    .filter(|check| check.blocking && !check.passed())
                    .cloned()
                    .collect(),
            ));
        }
        let background_roster_metadata = if validation
            .binding
            .feature_flags
            .get("enable_background_awards")
            .copied()
            .unwrap_or(false)
        {
            let capabilities = verified_canvas_binding_capabilities(&platform, &validation.binding)
                .ok_or_else(|| {
                    CanvasPlatformManagementError::ActivationBlocked(
                        validation
                            .readiness
                            .checks
                            .iter()
                            .filter(|check| check.blocking && !check.passed())
                            .cloned()
                            .collect(),
                    )
                })?;
            let mut metadata = Map::from_iter([
                (
                    "created_from".to_owned(),
                    Value::String("binding_activation".to_owned()),
                ),
                (
                    "verified_binding_id".to_owned(),
                    Value::String(validation.binding.id.clone()),
                ),
                (
                    "verified_binding_config_version".to_owned(),
                    Value::from(validation.binding.config_version),
                ),
                (
                    "verified_course_id".to_owned(),
                    capabilities
                        .get("verified_course_id")
                        .cloned()
                        .unwrap_or(Value::Null),
                ),
            ]);
            if let Some(memberships_url) = capabilities
                .get("nrps_context_memberships_url")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                metadata.insert(
                    "nrps_context_memberships_url".to_owned(),
                    Value::String(memberships_url.to_owned()),
                );
            }
            Some(metadata)
        } else {
            None
        };
        let activation = CanvasBindingActivation {
            binding: validation.binding,
            platform,
            activated_at: Utc::now(),
            background_roster_metadata,
        };
        validation.binding = self
            .repository
            .activate_binding(&activation)
            .await
            .map_err(map_binding_repository_error)?
            .ok_or(CanvasPlatformManagementError::ConfigurationChanged)?;
        Ok(validation)
    }

    pub async fn deactivate_binding(
        &self,
        binding_id: &str,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<CanvasBindingValidationResult, CanvasPlatformManagementError> {
        let organization_id = self.authorize(api_key, trusted_organization_id)?;
        let binding = self.active_binding(organization_id, binding_id).await?;
        let platform = self
            .active_platform(organization_id, &binding.platform_id)
            .await?;
        let mut validation = self
            .validate_loaded_binding(&platform, binding, Utc::now())
            .await?;
        validation.binding = self
            .repository
            .deactivate_binding(&validation.binding, Utc::now())
            .await
            .map_err(map_binding_repository_error)?
            .ok_or(CanvasPlatformManagementError::ConfigurationChanged)?;
        Ok(validation)
    }

    pub async fn platform_readiness(
        &self,
        platform_id: &str,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<CanvasPlatformReadinessResult, CanvasPlatformManagementError> {
        let organization_id = self.authorize(api_key, trusted_organization_id)?;
        let platform = self.active_platform(organization_id, platform_id).await?;
        let bindings = self
            .repository
            .list_active_bindings(organization_id, Some(platform_id), None)
            .await
            .map_err(map_binding_repository_error)?;
        let mut checks = Vec::new();
        if bindings.is_empty() {
            checks.push(CanvasReadinessCheck {
                code: "program_binding".to_owned(),
                component: "bindings".to_owned(),
                status: "failed".to_owned(),
                blocking: true,
                remediation: "Create and validate at least one portable Canvas program binding."
                    .to_owned(),
                timestamp: readiness_timestamp(Utc::now()),
            });
        } else {
            for binding in bindings {
                checks.extend(
                    self.validate_loaded_binding(&platform, binding, Utc::now())
                        .await?
                        .readiness
                        .checks,
                );
            }
        }
        Ok(CanvasPlatformReadinessResult {
            platform_id: platform.id,
            checks,
        })
    }

    async fn validate_loaded_binding(
        &self,
        platform: &CanvasPlatformRecord,
        mut binding: CanvasProgramBindingRecord,
        evaluated_at: DateTime<Utc>,
    ) -> Result<CanvasBindingValidationResult, CanvasPlatformManagementError> {
        let application_template = self
            .repository
            .application_template(&binding.application_template_id)
            .await
            .map_err(map_binding_repository_error)?;
        let readiness_input_provider = self
            .readiness_input_provider
            .as_ref()
            .ok_or(CanvasPlatformManagementError::ReadinessUnavailable)?;
        let mut inputs = readiness_input_provider
            .inputs(platform, &binding, evaluated_at)
            .await;
        inputs.application_template = application_template;
        let readiness =
            evaluate_canvas_binding_readiness(platform, &binding, &inputs, evaluated_at);
        let expected_config_version = binding.config_version;
        let expected_updated_at = binding.updated_at;
        apply_canvas_readiness_result(&mut binding, &readiness)
            .map_err(|_| CanvasPlatformManagementError::ConfigurationChanged)?;
        let binding = self
            .repository
            .save_binding_readiness(&binding, expected_config_version, expected_updated_at)
            .await
            .map_err(map_binding_repository_error)?
            .ok_or(CanvasPlatformManagementError::ConfigurationChanged)?;
        Ok(CanvasBindingValidationResult { binding, readiness })
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

    fn integration_secret_repository(
        &self,
    ) -> Result<&Arc<dyn CanvasIntegrationSecretRepository>, CanvasPlatformManagementError> {
        self.integration_secrets
            .as_ref()
            .ok_or(CanvasPlatformManagementError::RepositoryUnavailable)
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

fn trusted_https_origin(value: &str) -> Option<String> {
    let url = url::Url::parse(value.trim()).ok()?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    let host = url.host_str()?.to_ascii_lowercase();
    Some(match url.port() {
        Some(port) => format!("https://{host}:{port}"),
        None => format!("https://{host}"),
    })
}

fn map_binding_repository_error(
    error: CanvasManagementRepositoryError,
) -> CanvasPlatformManagementError {
    match error {
        CanvasManagementRepositoryError::DuplicateBinding => {
            CanvasPlatformManagementError::BindingConflict
        }
        other => map_repository_error(other),
    }
}

fn map_repository_error(error: CanvasManagementRepositoryError) -> CanvasPlatformManagementError {
    match error {
        CanvasManagementRepositoryError::Duplicate => CanvasPlatformManagementError::Conflict,
        CanvasManagementRepositoryError::DuplicateBinding => {
            CanvasPlatformManagementError::BindingConflict
        }
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
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::Arc,
        time::Duration,
    };

    use tokio::sync::Mutex;

    use super::*;
    use crate::canvas_management::{
        CanvasDeliveryMode, CanvasEvidenceFactType, CanvasEvidencePassRuleInput,
        CanvasEvidenceRequirementInput, CanvasEvidenceScopeInput, CanvasEvidenceSource,
    };
    use crate::canvas_readiness::{CanvasOAuthReadinessConnection, CanvasSyncReadiness};

    #[derive(Clone, Debug)]
    struct ReadyInputProvider;

    #[async_trait]
    impl CanvasReadinessInputProvider for ReadyInputProvider {
        async fn inputs(
            &self,
            _platform: &CanvasPlatformRecord,
            _binding: &CanvasProgramBindingRecord,
            _evaluated_at: DateTime<Utc>,
        ) -> CanvasReadinessInputs {
            CanvasReadinessInputs {
                rollout_allowed: true,
                lti_metadata_ready: true,
                lti_tool_signing_ready: true,
                oauth_lookup_succeeded: true,
                oauth_connection: Some(CanvasOAuthReadinessConnection {
                    connected: true,
                    reauthorization_required: false,
                    access_token_secret_configured: true,
                    capabilities: BTreeSet::from(["course_completion".to_owned()]),
                    scopes: crate::canvas_oauth::scopes_for_capabilities(&[
                        "course_completion".to_owned()
                    ])
                    .into_iter()
                    .collect(),
                }),
                worker_heartbeat_configured: true,
                sync_state: Some(CanvasSyncReadiness {
                    dead_lettered: false,
                    stale_backlog: false,
                }),
                application_template: None,
                credential_template: json!({
                    "id": "credential-template-1",
                    "organization_id": "org-1",
                    "status": "active",
                    "credential_type": "OpenBadgeCredential",
                    "credential_payload_format": "dc+sd-jwt",
                    "revocation_profile_id": "status-profile-1",
                    "issuer_did": "did:web:issuer.example.edu:orgs:org-1",
                    "issuer_algorithm": "ES256"
                })
                .as_object()
                .expect("credential template object")
                .clone(),
                credential_status_profile: json!({
                    "id": "status-profile-1",
                    "organization_id": "org-1",
                    "status": "active"
                })
                .as_object()
                .expect("status profile object")
                .clone(),
                kms_did_signing_ready: true,
                learner_identity_status: None,
                evidence_observed_at: None,
                evidence_max_age: Duration::from_secs(900),
            }
        }
    }

    #[derive(Default)]
    struct MemoryRepository {
        platforms: Mutex<Vec<CanvasPlatformRecord>>,
        bindings: Mutex<Vec<CanvasProgramBindingRecord>>,
        templates: Mutex<Vec<CanvasApplicationTemplateProjection>>,
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

        async fn application_template(
            &self,
            template_id: &str,
        ) -> Result<Option<CanvasApplicationTemplateProjection>, CanvasManagementRepositoryError>
        {
            Ok(self
                .templates
                .lock()
                .await
                .iter()
                .find(|template| template.id == template_id)
                .cloned())
        }

        async fn valid_canvas_credentials_secret(
            &self,
            organization_id: &str,
            secret_id: &str,
        ) -> Result<bool, CanvasManagementRepositoryError> {
            Ok(organization_id == "org-1" && secret_id == "secret-1")
        }

        async fn active_binding(
            &self,
            organization_id: &str,
            binding_id: &str,
        ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
            Ok(self
                .bindings
                .lock()
                .await
                .iter()
                .find(|binding| {
                    binding.organization_id == organization_id
                        && binding.id == binding_id
                        && binding.archived_at.is_none()
                })
                .cloned())
        }

        async fn list_active_bindings(
            &self,
            organization_id: &str,
            platform_id: Option<&str>,
            application_template_id: Option<&str>,
        ) -> Result<Vec<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
            Ok(self
                .bindings
                .lock()
                .await
                .iter()
                .filter(|binding| {
                    binding.organization_id == organization_id
                        && binding.archived_at.is_none()
                        && platform_id.is_none_or(|value| binding.platform_id == value)
                        && application_template_id
                            .is_none_or(|value| binding.application_template_id == value)
                })
                .cloned()
                .collect())
        }

        async fn create_binding(
            &self,
            binding: &CanvasProgramBindingRecord,
        ) -> Result<(), CanvasManagementRepositoryError> {
            let mut bindings = self.bindings.lock().await;
            if bindings.iter().any(|candidate| {
                candidate.archived_at.is_none()
                    && candidate.organization_id == binding.organization_id
                    && candidate.platform_id == binding.platform_id
                    && candidate.application_template_id == binding.application_template_id
                    && candidate.canvas_scope == binding.canvas_scope
            }) {
                return Err(CanvasManagementRepositoryError::DuplicateBinding);
            }
            bindings.push(binding.clone());
            Ok(())
        }

        async fn save_binding_configuration(
            &self,
            binding: &CanvasProgramBindingRecord,
            expected_config_version: i64,
        ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
            let mut bindings = self.bindings.lock().await;
            if bindings.iter().any(|candidate| {
                candidate.id != binding.id
                    && candidate.archived_at.is_none()
                    && candidate.organization_id == binding.organization_id
                    && candidate.platform_id == binding.platform_id
                    && candidate.application_template_id == binding.application_template_id
                    && candidate.canvas_scope == binding.canvas_scope
            }) {
                return Err(CanvasManagementRepositoryError::DuplicateBinding);
            }
            let Some(existing) = bindings.iter_mut().find(|candidate| {
                candidate.organization_id == binding.organization_id
                    && candidate.id == binding.id
                    && candidate.archived_at.is_none()
                    && candidate.config_version == expected_config_version
            }) else {
                return Ok(None);
            };
            *existing = binding.clone();
            Ok(Some(existing.clone()))
        }

        async fn save_binding_readiness(
            &self,
            binding: &CanvasProgramBindingRecord,
            expected_config_version: i64,
            expected_updated_at: DateTime<Utc>,
        ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
            let mut bindings = self.bindings.lock().await;
            let Some(existing) = bindings.iter_mut().find(|candidate| {
                candidate.organization_id == binding.organization_id
                    && candidate.id == binding.id
                    && candidate.archived_at.is_none()
                    && candidate.config_version == expected_config_version
                    && candidate.updated_at == expected_updated_at
            }) else {
                return Ok(None);
            };
            *existing = binding.clone();
            Ok(Some(existing.clone()))
        }

        async fn activate_binding(
            &self,
            activation: &CanvasBindingActivation,
        ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
            let mut platforms = self.platforms.lock().await;
            let Some(platform) = platforms.iter_mut().find(|candidate| {
                candidate.organization_id == activation.platform.organization_id
                    && candidate.id == activation.platform.id
                    && candidate.archived_at.is_none()
                    && candidate.config_version == activation.platform.config_version
                    && candidate.updated_at == activation.platform.updated_at
            }) else {
                return Ok(None);
            };
            let mut bindings = self.bindings.lock().await;
            let Some(binding) = bindings.iter_mut().find(|candidate| {
                candidate.organization_id == activation.binding.organization_id
                    && candidate.id == activation.binding.id
                    && candidate.archived_at.is_none()
                    && candidate.config_version == activation.binding.config_version
                    && candidate.updated_at == activation.binding.updated_at
            }) else {
                return Ok(None);
            };
            platform.enabled = true;
            platform.updated_at = activation.activated_at;
            binding.enabled = true;
            binding.activated_at = Some(activation.activated_at);
            binding.updated_at = activation.activated_at;
            Ok(Some(binding.clone()))
        }

        async fn deactivate_binding(
            &self,
            binding: &CanvasProgramBindingRecord,
            deactivated_at: DateTime<Utc>,
        ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
            let mut bindings = self.bindings.lock().await;
            let Some(existing) = bindings.iter_mut().find(|candidate| {
                candidate.organization_id == binding.organization_id
                    && candidate.id == binding.id
                    && candidate.archived_at.is_none()
                    && candidate.config_version == binding.config_version
                    && candidate.updated_at == binding.updated_at
            }) else {
                return Ok(None);
            };
            existing.enabled = false;
            existing.activated_at = None;
            existing.updated_at = deactivated_at;
            Ok(Some(existing.clone()))
        }

        async fn archive_binding(
            &self,
            organization_id: &str,
            binding_id: &str,
            expected_config_version: i64,
            now: DateTime<Utc>,
        ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
            let mut bindings = self.bindings.lock().await;
            let Some(binding) = bindings.iter_mut().find(|binding| {
                binding.organization_id == organization_id
                    && binding.id == binding_id
                    && binding.archived_at.is_none()
                    && binding.config_version == expected_config_version
            }) else {
                return Ok(None);
            };
            binding.archive(now);
            Ok(Some(binding.clone()))
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

    fn binding_request(name: &str, course_id: &str) -> CanvasProgramBindingRequest {
        CanvasProgramBindingRequest {
            application_template_id: "application-template-1".to_owned(),
            credential_template_id: None,
            display_name: Some(name.to_owned()),
            auto_approve_on_evidence: true,
            evidence_requirements: vec![CanvasEvidenceRequirementInput {
                requirement_id: None,
                source: CanvasEvidenceSource::CanvasRest,
                fact_type: CanvasEvidenceFactType::CourseCompletion,
                scope: CanvasEvidenceScopeInput {
                    course_id: course_id.to_owned(),
                    activity_id: None,
                    module_id: None,
                    line_item_url: None,
                    resource_id: None,
                },
                pass_rule: CanvasEvidencePassRuleInput {
                    min_score_percent: None,
                    completed: Some(true),
                },
                required: true,
            }],
            canvas_scope: BTreeMap::from([("course_id".to_owned(), course_id.to_owned())]),
            delivery_mode: CanvasDeliveryMode::WalletOnly,
            approval_policy_set_id: None,
            deployment_profile_id: None,
            feature_flags: BTreeMap::new(),
            canvas_credentials: None,
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

    #[tokio::test]
    async fn binding_crud_preserves_server_owned_fields_and_tenant_boundary() {
        let repository = Arc::new(MemoryRepository::default());
        repository
            .templates
            .lock()
            .await
            .push(CanvasApplicationTemplateProjection {
                id: "application-template-1".to_owned(),
                organization_id: "org-1".to_owned(),
                credential_template_id: Some("credential-template-1".to_owned()),
                approval_policy_set_id: Some("policy-1".to_owned()),
                active: true,
            });
        let service = service(repository.clone());
        let platform = service
            .create(
                request("Canvas", false),
                Some("management-secret"),
                Some("org-1"),
            )
            .await
            .unwrap();
        let created = service
            .create_binding(
                &platform.id,
                binding_request("Course 101", "course-101"),
                Some("management-secret"),
                Some("org-1"),
            )
            .await
            .unwrap();
        assert_eq!(created.credential_template_id, "credential-template-1");
        assert_eq!(created.flow_mode, "elevenid_orchestrated_canvas_evidence");
        assert_eq!(created.issuer_mode, "org_managed");
        assert!(!created.direct_issue_enabled);
        assert!(!created.enabled);
        assert_eq!(created.config_version, 1);
        assert!(created.evidence_requirements[0]["requirement_id"]
            .as_str()
            .unwrap()
            .starts_with("canvas_req_"));
        assert_eq!(
            service
                .get_binding(&created.id, Some("management-secret"), Some("org-2"))
                .await,
            Err(CanvasPlatformManagementError::BindingNotFound)
        );
        assert_eq!(
            service
                .list_bindings(
                    Some("org-1"),
                    Some(&platform.id),
                    Some("application-template-1"),
                    Some("management-secret"),
                    Some("org-1"),
                )
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            service
                .create_binding(
                    &platform.id,
                    binding_request("Duplicate", "course-101"),
                    Some("management-secret"),
                    Some("org-1"),
                )
                .await,
            Err(CanvasPlatformManagementError::BindingConflict)
        );

        let updated = service
            .update_binding(
                &created.id,
                binding_request("Course 202", "course-202"),
                Some("management-secret"),
                Some("org-1"),
            )
            .await
            .unwrap();
        assert_eq!(updated.id, created.id);
        assert_eq!(updated.created_at, created.created_at);
        assert_eq!(updated.config_version, 2);
        assert!(updated.readiness_checks.is_empty());
        assert!(updated.readiness_validated_at.is_none());

        service
            .delete_binding(&created.id, Some("management-secret"), Some("org-1"))
            .await
            .unwrap();
        assert_eq!(
            service
                .get_binding(&created.id, Some("management-secret"), Some("org-1"))
                .await,
            Err(CanvasPlatformManagementError::BindingNotFound)
        );
        let archived = &repository.bindings.lock().await[0];
        assert!(archived.archived_at.is_some());
        assert!(!archived.enabled);
    }

    #[tokio::test]
    async fn readiness_validation_persists_only_the_exact_evaluated_binding_revision() {
        let repository = Arc::new(MemoryRepository::default());
        repository
            .templates
            .lock()
            .await
            .push(CanvasApplicationTemplateProjection {
                id: "application-template-1".to_owned(),
                organization_id: "org-1".to_owned(),
                credential_template_id: Some("credential-template-1".to_owned()),
                approval_policy_set_id: Some("policy-1".to_owned()),
                active: true,
            });
        let unconfigured_service = service(repository.clone());
        let service = unconfigured_service
            .clone()
            .with_readiness_input_provider(Arc::new(ReadyInputProvider));
        let platform = service
            .create(
                request("Canvas", true),
                Some("management-secret"),
                Some("org-1"),
            )
            .await
            .unwrap();
        {
            let mut platforms = repository.platforms.lock().await;
            let platform = platforms.first_mut().expect("platform");
            platform.enabled = true;
            platform.registration_status = "installed".to_owned();
        }
        let binding = service
            .create_binding(
                &platform.id,
                binding_request("Course 101", "course-101"),
                Some("management-secret"),
                Some("org-1"),
            )
            .await
            .unwrap();
        assert_eq!(
            unconfigured_service
                .validate_binding(&binding.id, Some("management-secret"), Some("org-1"))
                .await,
            Err(CanvasPlatformManagementError::ReadinessUnavailable)
        );
        let validation = service
            .validate_binding(&binding.id, Some("management-secret"), Some("org-1"))
            .await
            .unwrap();
        assert!(validation.readiness.ready);
        assert_eq!(validation.readiness.checks.len(), 23);
        assert_eq!(
            validation.binding.validated_config_version,
            Some(binding.config_version)
        );
        assert_eq!(validation.binding.updated_at, binding.updated_at);
        assert_eq!(repository.bindings.lock().await[0], validation.binding);
        let platform_readiness = service
            .platform_readiness(&platform.id, Some("management-secret"), Some("org-1"))
            .await
            .unwrap();
        assert_eq!(platform_readiness.platform_id, platform.id);
        assert!(platform_readiness.ready());
        assert_eq!(platform_readiness.checks.len(), 23);
        assert_eq!(
            service
                .platform_readiness(&platform.id, Some("management-secret"), Some("org-2"))
                .await,
            Err(CanvasPlatformManagementError::PlatformNotFound)
        );
        assert_eq!(
            service
                .validate_binding(&binding.id, Some("management-secret"), Some("org-2"))
                .await,
            Err(CanvasPlatformManagementError::BindingNotFound)
        );

        let stale = validation.binding.clone();
        repository.bindings.lock().await[0].updated_at = Utc::now();
        assert!(repository
            .save_binding_readiness(&stale, stale.config_version, stale.updated_at)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn binding_rejects_foreign_inactive_templates_and_bad_secret_references() {
        for (organization_id, active, expected) in [
            (
                "org-2",
                true,
                CanvasPlatformManagementError::BindingDomain(
                    CanvasBindingDomainError::ForeignApplicationTemplate,
                ),
            ),
            (
                "org-1",
                false,
                CanvasPlatformManagementError::BindingDomain(
                    CanvasBindingDomainError::ApplicationTemplateInactive,
                ),
            ),
        ] {
            let repository = Arc::new(MemoryRepository::default());
            repository
                .templates
                .lock()
                .await
                .push(CanvasApplicationTemplateProjection {
                    id: "application-template-1".to_owned(),
                    organization_id: organization_id.to_owned(),
                    credential_template_id: Some("credential-template-1".to_owned()),
                    approval_policy_set_id: None,
                    active,
                });
            let service = service(repository);
            let platform = service
                .create(
                    request("Canvas", false),
                    Some("management-secret"),
                    Some("org-1"),
                )
                .await
                .unwrap();
            assert_eq!(
                service
                    .create_binding(
                        &platform.id,
                        binding_request("Course", "course-101"),
                        Some("management-secret"),
                        Some("org-1"),
                    )
                    .await,
                Err(expected)
            );
        }

        let repository = Arc::new(MemoryRepository::default());
        repository
            .templates
            .lock()
            .await
            .push(CanvasApplicationTemplateProjection {
                id: "application-template-1".to_owned(),
                organization_id: "org-1".to_owned(),
                credential_template_id: Some("credential-template-1".to_owned()),
                approval_policy_set_id: None,
                active: true,
            });
        let service = service(repository);
        let platform = service
            .create(
                request("Canvas", false),
                Some("management-secret"),
                Some("org-1"),
            )
            .await
            .unwrap();
        let mut request = binding_request("Course", "course-101");
        request.canvas_credentials = Some(crate::canvas_management::CanvasCredentialsConfigInput {
            provider: None,
            api_base_url: Some("https://api.badgr.io/v2".to_owned()),
            issuer_id: None,
            badgeclass_id: None,
            assertion_scope: None,
            api_token_secret_id: Some("missing".to_owned()),
            credential_template_id: None,
        });
        assert_eq!(
            service
                .create_binding(
                    &platform.id,
                    request,
                    Some("management-secret"),
                    Some("org-1"),
                )
                .await,
            Err(CanvasPlatformManagementError::CanvasCredentialsSecretNotFound)
        );
    }
}
