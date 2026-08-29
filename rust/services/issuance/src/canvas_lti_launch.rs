use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use marty_oid4vci::{
    lti::{verify_lti_launch_jwt, VerifiedLtiLaunch},
    Oid4vciError,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::canvas_lti_login::{
    random_token, CanvasLtiLoginError, CanvasLtiLoginService, CanvasLtiPlatform,
};

const CUSTOM_CLAIM: &str = "https://purl.imsglobal.org/spec/lti/claim/custom";
const RESOURCE_LINK_CLAIM: &str = "https://purl.imsglobal.org/spec/lti/claim/resource_link";
const MESSAGE_TYPE_CLAIM: &str = "https://purl.imsglobal.org/spec/lti/claim/message_type";
const DEEP_LINKING_CLAIM: &str =
    "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings";
const AGS_ENDPOINT_CLAIM: &str = "https://purl.imsglobal.org/spec/lti-ags/claim/endpoint";
const NRPS_CLAIM: &str = "https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice";
const UNKNOWN_LTI_KID_MARKER: &str = "No JWKS entry found for LTI kid";

const FEATURE_FLAGS: [&str; 8] = [
    "enable_background_awards",
    "enable_canvas_ags",
    "enable_canvas_deep_linking",
    "enable_canvas_evidence",
    "enable_canvas_lti",
    "enable_canvas_mirror_ops",
    "enable_canvas_mirror_publish",
    "enable_canvas_nrps",
];

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasLtiProgramBinding {
    pub id: String,
    pub organization_id: String,
    pub platform_id: String,
    pub application_template_id: String,
    pub credential_template_id: String,
    pub delivery_mode: String,
    pub deployment_profile_id: Option<String>,
    pub feature_flags: Value,
    pub evidence_requirements: Vec<Value>,
    pub canvas_scope: Value,
    pub enabled: bool,
    pub archived: bool,
    pub config_version: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CanvasLtiVerifiedLaunchResponse {
    pub organization_id: String,
    pub canvas_account_id: String,
    pub canvas_platform_id: String,
    pub canvas_program_binding_id: String,
    pub application_template_id: String,
    pub credential_template_id: String,
    pub delivery_mode: String,
    pub deployment_profile_id: Option<String>,
    pub feature_flags: BTreeMap<String, bool>,
    pub evidence_requirements: Vec<Value>,
    pub state: String,
    pub verified: bool,
    pub issuer: String,
    pub subject: String,
    pub audience: Vec<String>,
    pub deployment_id: String,
    pub nonce: Option<String>,
    pub issued_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub message_type: Option<String>,
    pub lti_version: Option<String>,
    pub target_link_uri: Option<String>,
    pub context: Option<Value>,
    pub roles: Vec<String>,
    pub learner_identity: Value,
    pub raw_claims: Value,
    pub lti_capabilities: Value,
    pub identity_mapping_status: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CanvasLtiPublicLaunchResponse {
    pub verified: bool,
    pub organization_id: String,
    pub canvas_account_id: String,
    pub canvas_platform_id: String,
    pub canvas_program_binding_id: String,
    pub application_template_id: Option<String>,
    pub credential_template_id: Option<String>,
    pub message_type: Option<String>,
    pub context: BTreeMap<String, Value>,
    pub roles: Vec<String>,
    pub identity_mapping_status: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CanvasLtiLaunchSubmission {
    pub id_token: Option<String>,
    pub state: Option<String>,
}

impl CanvasLtiLaunchSubmission {
    #[must_use]
    pub fn from_json_object(object: &Map<String, Value>) -> Self {
        Self {
            id_token: object
                .get("id_token")
                .and_then(Value::as_str)
                .map(str::to_owned),
            state: object
                .get("state")
                .and_then(Value::as_str)
                .map(str::to_owned),
        }
    }

    pub fn required(self) -> Result<(String, String), CanvasLtiLaunchPlanError> {
        let id_token = non_empty(self.id_token).ok_or(CanvasLtiLaunchPlanError::Invalid(
            "Canvas LTI launch requires id_token",
        ))?;
        let state = non_empty(self.state).ok_or(CanvasLtiLaunchPlanError::Invalid(
            "Canvas LTI launch requires server-generated state",
        ))?;
        Ok((id_token, state))
    }
}

#[derive(Debug, Error)]
pub enum CanvasLtiLaunchPlanError {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("Canvas LTI launch verification failed: {0}")]
    Verification(String),
    #[error("Canvas LTI launch verification failed after JWKS refresh: {0}")]
    VerificationAfterJwksRefresh(String),
    #[error("{0}")]
    JwksRefresh(String),
    #[error("Canvas LTI launch did not match an enabled Canvas program binding")]
    BindingNotFound,
    #[error("Canvas LTI is disabled for this deployment profile")]
    FeatureDisabled,
    #[error("Canvas LTI state is unknown for this platform")]
    StateUnknown,
    #[error("Canvas LTI state has expired or already been used")]
    StateExpired,
    #[error("Canvas LTI launch repository is unavailable")]
    RepositoryUnavailable,
    #[error("Canvas launch resource does not match the selected binding")]
    AgsBindingMismatch,
    #[error("Canvas launch resource does not match an AGS requirement")]
    AgsRequirementMismatch,
    #[error("Canvas AGS line item could not be pinned: {0}")]
    AgsLineItem(String),
    #[error("Canvas capability snapshot does not match the selected platform and binding")]
    CapabilityScopeMismatch,
    #[error("Canvas platform or program binding changed before capability snapshot persistence")]
    CapabilityConfigurationDrift,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanvasLtiStoredLaunchState {
    pub id: String,
    pub platform_id: String,
    pub organization_id: String,
    pub canvas_account_id: String,
    pub state: String,
    pub nonce: String,
    pub redirect_uri: String,
    pub status: String,
    pub metadata: Value,
    pub expired: bool,
}

#[async_trait]
pub trait CanvasLtiLaunchStateRepository: Send + Sync {
    async fn get_launch_state(
        &self,
        state: &str,
    ) -> Result<Option<CanvasLtiStoredLaunchState>, CanvasLtiLaunchPlanError>;

    async fn consume_launch_state(
        &self,
        state: &str,
    ) -> Result<Option<CanvasLtiStoredLaunchState>, CanvasLtiLaunchPlanError>;
}

#[async_trait]
pub trait CanvasLtiLaunchContextRepository: Send + Sync {
    async fn list_program_bindings(
        &self,
        organization_id: &str,
        platform_id: &str,
    ) -> Result<Vec<CanvasLtiProgramBinding>, CanvasLtiLaunchPlanError>;
}

#[async_trait]
pub trait CanvasLtiJwksRefresher: Send + Sync {
    /// Refresh, validate, and persist the platform metadata before returning it.
    async fn refresh_platform_jwks(
        &self,
        platform: &CanvasLtiPlatform,
    ) -> Result<CanvasLtiPlatform, CanvasLtiLaunchPlanError>;
}

#[derive(Clone)]
pub struct CanvasLtiJwksRefreshService {
    refresher: Arc<dyn CanvasLtiJwksRefresher>,
}

impl std::fmt::Debug for CanvasLtiJwksRefreshService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasLtiJwksRefreshService")
            .finish_non_exhaustive()
    }
}

impl CanvasLtiJwksRefreshService {
    #[must_use]
    pub fn new(refresher: Arc<dyn CanvasLtiJwksRefresher>) -> Self {
        Self { refresher }
    }

    pub async fn verify_with_refresh(
        &self,
        platform: &CanvasLtiPlatform,
        id_token: &str,
        expected_nonce: &str,
    ) -> Result<(CanvasLtiPlatform, VerifiedLtiLaunch), CanvasLtiLaunchPlanError> {
        match verify_launch_classified(platform, id_token, expected_nonce) {
            Ok(verified) => Ok((platform.clone(), verified)),
            Err(LaunchVerificationFailure::Rejected(message)) => {
                Err(CanvasLtiLaunchPlanError::Verification(message))
            }
            Err(LaunchVerificationFailure::UnknownKid(message)) if !has_canvas_origin(platform) => {
                Err(CanvasLtiLaunchPlanError::Verification(message))
            }
            Err(LaunchVerificationFailure::UnknownKid(_)) => {
                let refreshed = self
                    .refresher
                    .refresh_platform_jwks(platform)
                    .await
                    .map_err(|error| {
                        CanvasLtiLaunchPlanError::VerificationAfterJwksRefresh(error.to_string())
                    })?;
                verify_launch_classified(&refreshed, id_token, expected_nonce)
                    .map(|verified| (refreshed, verified))
                    .map_err(|error| {
                        CanvasLtiLaunchPlanError::VerificationAfterJwksRefresh(error.into_message())
                    })
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanvasLtiAgsPinRequest {
    pub binding_id: String,
    pub requirement_id: String,
    pub resource_id: String,
    pub line_item_url: String,
}

#[async_trait]
pub trait CanvasLtiAgsServiceUrlValidator: Send + Sync {
    async fn validate(&self, service_url: &str) -> Result<String, String>;
}

#[async_trait]
pub trait CanvasLtiAgsPinRepository: Send + Sync {
    /// Persist the pin and invalidate every readiness artifact atomically.
    async fn pin_verified_line_item(
        &self,
        binding: &CanvasLtiProgramBinding,
        request: &CanvasLtiAgsPinRequest,
    ) -> Result<bool, CanvasLtiLaunchPlanError>;
}

#[derive(Clone)]
pub struct CanvasLtiAgsPinService {
    repository: Arc<dyn CanvasLtiAgsPinRepository>,
    url_validator: Arc<dyn CanvasLtiAgsServiceUrlValidator>,
}

impl std::fmt::Debug for CanvasLtiAgsPinService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasLtiAgsPinService")
            .finish_non_exhaustive()
    }
}

impl CanvasLtiAgsPinService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn CanvasLtiAgsPinRepository>,
        url_validator: Arc<dyn CanvasLtiAgsServiceUrlValidator>,
    ) -> Self {
        Self {
            repository,
            url_validator,
        }
    }

    pub async fn persist_verified_line_item(
        &self,
        binding: &CanvasLtiProgramBinding,
        verified: &VerifiedLtiLaunch,
    ) -> Result<bool, CanvasLtiLaunchPlanError> {
        let Some(mut request) = verified_ags_pin_request(binding, verified)? else {
            return Ok(false);
        };
        request.line_item_url = self
            .url_validator
            .validate(&request.line_item_url)
            .await
            .map_err(CanvasLtiLaunchPlanError::AgsLineItem)?;
        self.repository
            .pin_verified_line_item(binding, &request)
            .await
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasLtiCapabilitySnapshotRequest {
    pub organization_id: String,
    pub platform_id: String,
    pub selected_platform_config_version: i64,
    pub binding_id: String,
    pub selected_binding_config_version: i64,
    pub signed_course_id: String,
    pub launch_capabilities: Value,
    pub line_item_configuration_changed: bool,
    pub verified_at: DateTime<Utc>,
}

#[async_trait]
pub trait CanvasLtiCapabilitySnapshotRepository: Send + Sync {
    /// Lock the selected trust scope, reject configuration drift, and persist
    /// one binding-indexed snapshot atomically.
    async fn persist_verified_capabilities(
        &self,
        request: &CanvasLtiCapabilitySnapshotRequest,
    ) -> Result<Value, CanvasLtiLaunchPlanError>;
}

#[derive(Clone)]
pub struct CanvasLtiCapabilitySnapshotService {
    repository: Arc<dyn CanvasLtiCapabilitySnapshotRepository>,
}

impl std::fmt::Debug for CanvasLtiCapabilitySnapshotService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasLtiCapabilitySnapshotService")
            .finish_non_exhaustive()
    }
}

impl CanvasLtiCapabilitySnapshotService {
    #[must_use]
    pub fn new(repository: Arc<dyn CanvasLtiCapabilitySnapshotRepository>) -> Self {
        Self { repository }
    }

    pub async fn persist_verified_capabilities(
        &self,
        request: &CanvasLtiCapabilitySnapshotRequest,
    ) -> Result<Value, CanvasLtiLaunchPlanError> {
        if request.organization_id.trim().is_empty()
            || request.platform_id.trim().is_empty()
            || request.binding_id.trim().is_empty()
            || request.selected_platform_config_version < 1
            || request.selected_binding_config_version < 1
            || !request.launch_capabilities.is_object()
        {
            return Err(CanvasLtiLaunchPlanError::Invalid(
                "Canvas LTI capability snapshot is incomplete",
            ));
        }
        self.repository.persist_verified_capabilities(request).await
    }
}

pub trait CanvasLtiClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCanvasLtiClock;

impl CanvasLtiClock for SystemCanvasLtiClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

pub struct CanvasLtiLaunchPorts {
    pub state_repository: Arc<dyn CanvasLtiLaunchStateRepository>,
    pub context_repository: Arc<dyn CanvasLtiLaunchContextRepository>,
    pub jwks_refresher: Arc<dyn CanvasLtiJwksRefresher>,
    pub identity_repository: Arc<dyn CanvasLtiIdentityRepository>,
    pub ags_repository: Arc<dyn CanvasLtiAgsPinRepository>,
    pub ags_url_validator: Arc<dyn CanvasLtiAgsServiceUrlValidator>,
    pub capability_repository: Arc<dyn CanvasLtiCapabilitySnapshotRepository>,
    pub clock: Arc<dyn CanvasLtiClock>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasLtiLaunchResult {
    pub platform: CanvasLtiPlatform,
    pub consumed_state: CanvasLtiStoredLaunchState,
    pub response: CanvasLtiVerifiedLaunchResponse,
}

#[derive(Debug, Error)]
pub enum CanvasLtiLaunchServiceError {
    #[error(transparent)]
    Platform(#[from] CanvasLtiLoginError),
    #[error(transparent)]
    Launch(#[from] CanvasLtiLaunchPlanError),
}

#[derive(Clone)]
pub struct CanvasLtiLaunchService {
    platform_service: CanvasLtiLoginService,
    state_service: CanvasLtiLaunchStateService,
    context_repository: Arc<dyn CanvasLtiLaunchContextRepository>,
    jwks_service: CanvasLtiJwksRefreshService,
    identity_service: CanvasLtiIdentityService,
    ags_service: CanvasLtiAgsPinService,
    capability_service: CanvasLtiCapabilitySnapshotService,
    clock: Arc<dyn CanvasLtiClock>,
}

impl std::fmt::Debug for CanvasLtiLaunchService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasLtiLaunchService")
            .finish_non_exhaustive()
    }
}

impl CanvasLtiLaunchService {
    #[must_use]
    pub fn new(platform_service: CanvasLtiLoginService, ports: CanvasLtiLaunchPorts) -> Self {
        Self {
            platform_service,
            state_service: CanvasLtiLaunchStateService::new(ports.state_repository),
            context_repository: ports.context_repository,
            jwks_service: CanvasLtiJwksRefreshService::new(ports.jwks_refresher),
            identity_service: CanvasLtiIdentityService::new(ports.identity_repository),
            ags_service: CanvasLtiAgsPinService::new(ports.ags_repository, ports.ags_url_validator),
            capability_service: CanvasLtiCapabilitySnapshotService::new(
                ports.capability_repository,
            ),
            clock: ports.clock,
        }
    }

    pub(crate) async fn prepare_platform(
        &self,
        platform_id: &str,
    ) -> Result<CanvasLtiPlatform, CanvasLtiLaunchServiceError> {
        self.platform_service
            .ready_platform(platform_id)
            .await
            .map_err(Into::into)
    }

    pub async fn launch(
        &self,
        platform_id: &str,
        submission: CanvasLtiLaunchSubmission,
    ) -> Result<CanvasLtiLaunchResult, CanvasLtiLaunchServiceError> {
        let platform = self.prepare_platform(platform_id).await?;
        self.launch_prepared(platform, submission).await
    }

    pub(crate) async fn launch_prepared(
        &self,
        platform: CanvasLtiPlatform,
        submission: CanvasLtiLaunchSubmission,
    ) -> Result<CanvasLtiLaunchResult, CanvasLtiLaunchServiceError> {
        let (id_token, state) = submission.required()?;
        let consumed_state = self.state_service.claim(&platform.id, &state).await?;
        let (platform, verified) = self
            .jwks_service
            .verify_with_refresh(&platform, &id_token, &consumed_state.nonce)
            .await?;
        let identity_mapping_status = self
            .identity_service
            .record_verified_launch(&platform, &verified)
            .await?;
        let bindings = self
            .context_repository
            .list_program_bindings(&platform.organization_id, &platform.id)
            .await?;
        let selected_binding =
            select_binding_with_staff_fallback(&platform, &verified, &bindings)?.clone();
        let selected_binding_config_version = selected_binding.config_version;
        let line_item_configuration_changed = self
            .ags_service
            .persist_verified_line_item(&selected_binding, &verified)
            .await?;
        let response_binding = if line_item_configuration_changed {
            self.reload_binding(&selected_binding).await?
        } else {
            selected_binding.clone()
        };
        let signed_course_id =
            signed_custom_identifier(&verified, "canvas_course_id").unwrap_or_default();
        let response = private_launch_response(
            &platform,
            &response_binding,
            &state,
            verified,
            Some(identity_mapping_status),
        );
        self.capability_service
            .persist_verified_capabilities(&CanvasLtiCapabilitySnapshotRequest {
                organization_id: platform.organization_id.clone(),
                platform_id: platform.id.clone(),
                selected_platform_config_version: platform.config_version,
                binding_id: response_binding.id.clone(),
                selected_binding_config_version,
                signed_course_id,
                launch_capabilities: response.lti_capabilities.clone(),
                line_item_configuration_changed,
                verified_at: self.clock.now(),
            })
            .await?;
        Ok(CanvasLtiLaunchResult {
            platform,
            consumed_state,
            response,
        })
    }

    async fn reload_binding(
        &self,
        selected: &CanvasLtiProgramBinding,
    ) -> Result<CanvasLtiProgramBinding, CanvasLtiLaunchPlanError> {
        self.context_repository
            .list_program_bindings(&selected.organization_id, &selected.platform_id)
            .await?
            .into_iter()
            .find(|binding| {
                binding.id == selected.id
                    && binding.organization_id == selected.organization_id
                    && binding.platform_id == selected.platform_id
                    && !binding.archived
            })
            .ok_or(CanvasLtiLaunchPlanError::RepositoryUnavailable)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanvasLtiExperienceCodeSeed {
    pub id: String,
    pub state: String,
    pub nonce: String,
}

pub trait CanvasLtiExperienceCodeGenerator: Send + Sync {
    fn generate(&self) -> CanvasLtiExperienceCodeSeed;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SecureCanvasLtiExperienceCodeGenerator;

impl CanvasLtiExperienceCodeGenerator for SecureCanvasLtiExperienceCodeGenerator {
    fn generate(&self) -> CanvasLtiExperienceCodeSeed {
        CanvasLtiExperienceCodeSeed {
            id: uuid::Uuid::new_v4().to_string(),
            state: random_token(),
            nonce: random_token(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasLtiExperienceHandoff {
    pub mip_primitives: Value,
    pub code_metadata: Value,
    pub consumed_state_metadata: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasLtiExperienceHandoffRequest {
    pub organization_id: String,
    pub platform_id: String,
    pub canvas_account_id: String,
    pub code: CanvasLtiExperienceCodeSeed,
    pub redirect_uri: String,
    pub expires_at: DateTime<Utc>,
    pub code_metadata: Value,
    pub consumed_state: CanvasLtiStoredLaunchState,
    pub consumed_state_metadata: Value,
}

#[async_trait]
pub trait CanvasLtiExperienceHandoffRepository: Send + Sync {
    /// Persist the one-time code and attach its pointer to the consumed launch
    /// state in one transaction before any redirect is returned.
    async fn persist_experience_handoff(
        &self,
        request: &CanvasLtiExperienceHandoffRequest,
    ) -> Result<(), CanvasLtiLaunchPlanError>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasLtiExperienceResult {
    pub location: String,
    pub launch: CanvasLtiLaunchResult,
    pub code_id: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct CanvasLtiExperienceService {
    launch_service: CanvasLtiLaunchService,
    repository: Arc<dyn CanvasLtiExperienceHandoffRepository>,
    generator: Arc<dyn CanvasLtiExperienceCodeGenerator>,
    clock: Arc<dyn CanvasLtiClock>,
    code_ttl: chrono::Duration,
    experience_base_url: String,
}

impl std::fmt::Debug for CanvasLtiExperienceService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasLtiExperienceService")
            .field("code_ttl", &self.code_ttl)
            .field("experience_base_url", &self.experience_base_url)
            .finish_non_exhaustive()
    }
}

impl CanvasLtiExperienceService {
    pub fn new(
        launch_service: CanvasLtiLaunchService,
        repository: Arc<dyn CanvasLtiExperienceHandoffRepository>,
        generator: Arc<dyn CanvasLtiExperienceCodeGenerator>,
        clock: Arc<dyn CanvasLtiClock>,
        code_ttl: Duration,
        experience_base_url: &str,
    ) -> Result<Self, CanvasLtiLaunchPlanError> {
        let experience_base_url = experience_base_url.trim_end_matches('/').to_owned();
        let parsed = url::Url::parse(&experience_base_url).map_err(|_| {
            CanvasLtiLaunchPlanError::Invalid("Canvas LTI experience base URL is invalid")
        })?;
        if code_ttl.is_zero()
            || !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(CanvasLtiLaunchPlanError::Invalid(
                "Canvas LTI experience configuration is invalid",
            ));
        }
        let code_ttl = chrono::Duration::from_std(code_ttl).map_err(|_| {
            CanvasLtiLaunchPlanError::Invalid("Canvas LTI experience code TTL is invalid")
        })?;
        Ok(Self {
            launch_service,
            repository,
            generator,
            clock,
            code_ttl,
            experience_base_url,
        })
    }

    pub async fn launch(
        &self,
        platform_id: &str,
        submission: CanvasLtiLaunchSubmission,
    ) -> Result<CanvasLtiExperienceResult, CanvasLtiLaunchServiceError> {
        let platform = self.launch_service.prepare_platform(platform_id).await?;
        self.launch_prepared(platform, submission).await
    }

    pub(crate) async fn launch_prepared(
        &self,
        platform: CanvasLtiPlatform,
        submission: CanvasLtiLaunchSubmission,
    ) -> Result<CanvasLtiExperienceResult, CanvasLtiLaunchServiceError> {
        let launch = self
            .launch_service
            .launch_prepared(platform, submission)
            .await?;
        let code = self.generator.generate();
        let now = self.clock.now();
        let expires_at =
            now.checked_add_signed(self.code_ttl)
                .ok_or(CanvasLtiLaunchPlanError::Invalid(
                    "Canvas LTI experience code TTL is invalid",
                ))?;
        let encoded_code: String =
            url::form_urlencoded::byte_serialize(code.state.as_bytes()).collect();
        let location = format!(
            "{}/canvas/lti/experience?code={encoded_code}",
            self.experience_base_url
        );
        let handoff = canvas_lti_experience_handoff(
            &launch.platform,
            &launch.consumed_state,
            &launch.response,
            &location,
            &code.id,
            expires_at,
        );
        self.repository
            .persist_experience_handoff(&CanvasLtiExperienceHandoffRequest {
                organization_id: launch.platform.organization_id.clone(),
                platform_id: launch.platform.id.clone(),
                canvas_account_id: launch.platform.canvas_account_id.clone(),
                code: code.clone(),
                redirect_uri: launch.consumed_state.redirect_uri.clone(),
                expires_at,
                code_metadata: handoff.code_metadata,
                consumed_state: launch.consumed_state.clone(),
                consumed_state_metadata: handoff.consumed_state_metadata,
            })
            .await?;
        Ok(CanvasLtiExperienceResult {
            location,
            launch,
            code_id: code.id,
            expires_at,
        })
    }
}

#[must_use]
pub fn canvas_lti_experience_handoff(
    platform: &CanvasLtiPlatform,
    consumed_state: &CanvasLtiStoredLaunchState,
    verified_launch: &CanvasLtiVerifiedLaunchResponse,
    launch_url: &str,
    experience_code_id: &str,
    experience_code_expires_at: DateTime<Utc>,
) -> CanvasLtiExperienceHandoff {
    let canvas_context = verified_launch
        .context
        .as_ref()
        .filter(|value| value.is_object())
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let attributes = serde_json::json!({
        "issuer": verified_launch.issuer,
        "deployment_id": verified_launch.deployment_id,
        "canvas_context_id": canvas_context.get("id"),
        "roles": verified_launch.roles,
        "lti_capabilities": verified_launch.lti_capabilities,
    });
    let mip_primitives = serde_json::json!({
        "organization_id": platform.organization_id,
        "platform_id": platform.id,
        "provider_account_id": platform.canvas_account_id,
        "state": consumed_state.state,
        "subject_id": verified_launch.subject,
        "launch_url": launch_url,
        "source": {
            "provider": "canvas",
            "provider_account_id": platform.canvas_account_id,
            "provider_event_id": consumed_state.state,
            "event_type": "canvas.lti_launch",
            "subject_id": verified_launch.subject,
            "signature_scheme": "OIDC_ID_TOKEN",
            "payload_hash": Value::Null,
            "attributes": attributes,
        },
        "context": {
            "canvas_platform_id": verified_launch.canvas_platform_id,
            "canvas_account_id": platform.canvas_account_id,
            "canvas_context": canvas_context,
            "learner_identity": verified_launch.learner_identity,
            "roles": verified_launch.roles,
            "lti_capabilities": verified_launch.lti_capabilities,
            "canvas_program_binding_id": verified_launch.canvas_program_binding_id,
            "application_template_id": verified_launch.application_template_id,
            "credential_template_id": verified_launch.credential_template_id,
            "delivery_mode": verified_launch.delivery_mode,
            "deployment_profile_id": verified_launch.deployment_profile_id,
            "feature_flags": verified_launch.feature_flags,
            "evidence_requirements": verified_launch.evidence_requirements,
        },
        "action": "applications:read",
        "resource_type": "Application",
        "protocol": "ELEVENID_EXPERIENCE",
    });
    let code_metadata = serde_json::json!({
        "kind": "canvas_lti_experience_code",
        "launch_state": consumed_state.state,
        "verified_launch": verified_launch,
        "mip_primitives": mip_primitives,
        "launch_url": launch_url,
    });
    let mut consumed_state_metadata = consumed_state
        .metadata
        .as_object()
        .cloned()
        .unwrap_or_default();
    consumed_state_metadata.insert(
        "experience_code_id".to_owned(),
        Value::String(experience_code_id.to_owned()),
    );
    consumed_state_metadata.insert(
        "experience_code_expires_at".to_owned(),
        Value::String(experience_code_expires_at.to_rfc3339()),
    );
    CanvasLtiExperienceHandoff {
        mip_primitives,
        code_metadata,
        consumed_state_metadata: Value::Object(consumed_state_metadata),
    }
}

/// Merge capabilities from one verified launch into the binding-indexed
/// authorization snapshot without allowing launch order or configuration drift
/// to erase or carry capabilities across trust scopes.
#[must_use]
pub fn merge_verified_lti_binding_capabilities(
    capability_snapshot: &Value,
    launch_capabilities: &Value,
    binding_id: &str,
    binding_config_version: i64,
    signed_course_id: &str,
    line_item_configuration_changed: bool,
    verified_at: &str,
) -> Value {
    let mut launches = capability_snapshot
        .get("verified_binding_launches")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let prior = launches
        .get(binding_id)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let prior_version = prior
        .get("verified_binding_config_version")
        .and_then(python_int)
        .unwrap_or(-1);
    let prior_course_id = prior
        .get("verified_course_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    let can_carry_prior = prior.get("verified_binding_id").and_then(Value::as_str)
        == Some(binding_id)
        && prior_course_id == signed_course_id
        && (prior_version == binding_config_version
            || (line_item_configuration_changed && prior_version == binding_config_version - 1));
    let mut binding_capabilities = if can_carry_prior { prior } else { Map::new() };
    let current = launch_capabilities.as_object().cloned().unwrap_or_default();
    // Navigation launches can omit AGS while resource launches can omit NRPS.
    // Preserve verified positive claims for the same binding/course/config.
    for (key, value) in &current {
        if positive_capability(value) || !binding_capabilities.contains_key(key) {
            binding_capabilities.insert(key.clone(), value.clone());
        }
    }
    let mut verified_line_items = binding_capabilities
        .get("verified_ags_line_items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if let Some(current_line_item) = current
        .get("ags_lineitem_url")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        verified_line_items.insert(current_line_item.to_owned());
    }
    binding_capabilities.insert(
        "verified_binding_id".to_owned(),
        Value::String(binding_id.to_owned()),
    );
    binding_capabilities.insert(
        "verified_binding_config_version".to_owned(),
        Value::Number(binding_config_version.into()),
    );
    binding_capabilities.insert(
        "verified_course_id".to_owned(),
        Value::String(signed_course_id.to_owned()),
    );
    binding_capabilities.insert(
        "verified_at".to_owned(),
        Value::String(verified_at.to_owned()),
    );
    binding_capabilities.insert(
        "verified_ags_line_items".to_owned(),
        Value::Array(verified_line_items.into_iter().map(Value::String).collect()),
    );
    launches.insert(binding_id.to_owned(), Value::Object(binding_capabilities));

    // Keep last-launch fields for diagnostics and backward-compatible display;
    // authorization decisions consume the binding-indexed snapshot.
    let mut snapshot = current;
    snapshot.insert(
        "verified_binding_id".to_owned(),
        Value::String(binding_id.to_owned()),
    );
    snapshot.insert(
        "verified_binding_config_version".to_owned(),
        Value::Number(binding_config_version.into()),
    );
    snapshot.insert(
        "verified_course_id".to_owned(),
        Value::String(signed_course_id.to_owned()),
    );
    snapshot.insert(
        "verified_at".to_owned(),
        Value::String(verified_at.to_owned()),
    );
    snapshot.insert(
        "verified_binding_launches".to_owned(),
        Value::Object(launches),
    );
    Value::Object(snapshot)
}

fn positive_capability(value: &Value) -> bool {
    !matches!(value, Value::Null | Value::Bool(false))
        && !matches!(value, Value::String(value) if value.is_empty())
        && !matches!(value, Value::Array(value) if value.is_empty())
}

fn python_int(value: &Value) -> Option<i64> {
    match value {
        Value::Bool(value) => Some(i64::from(*value)),
        Value::Number(value) => value
            .as_i64()
            .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
            .or_else(|| value.as_f64().map(|value| value.trunc() as i64)),
        Value::String(value) => value.trim().parse().ok(),
        _ => None,
    }
}

pub fn verified_ags_pin_request(
    binding: &CanvasLtiProgramBinding,
    verified: &VerifiedLtiLaunch,
) -> Result<Option<CanvasLtiAgsPinRequest>, CanvasLtiLaunchPlanError> {
    let custom = claim_object(&verified.raw_claims, CUSTOM_CLAIM, "custom");
    let ags = claim_object(&verified.raw_claims, AGS_ENDPOINT_CLAIM, "ags_endpoint");
    let values = [
        object_non_empty_string(custom, "canvas_program_binding_id"),
        object_non_empty_string(custom, "canvas_requirement_id"),
        object_non_empty_string(custom, "canvas_resource_id"),
        object_non_empty_string(ags, "lineitem"),
    ];
    let [Some(binding_id), Some(requirement_id), Some(resource_id), Some(line_item_url)] = values
    else {
        return Ok(None);
    };
    if binding_id != binding.id {
        return Err(CanvasLtiLaunchPlanError::AgsBindingMismatch);
    }
    Ok(Some(CanvasLtiAgsPinRequest {
        binding_id,
        requirement_id,
        resource_id,
        line_item_url,
    }))
}

pub fn plan_ags_line_item_pin(
    evidence_requirements: &[Value],
    request: &CanvasLtiAgsPinRequest,
) -> Result<Option<Vec<Value>>, CanvasLtiLaunchPlanError> {
    let mut matched = false;
    let mut updated = evidence_requirements.to_vec();
    for requirement in &mut updated {
        let Some(requirement_object) = requirement.as_object_mut() else {
            continue;
        };
        let scope_matches = requirement_object
            .get("scope")
            .and_then(Value::as_object)
            .and_then(|scope| scope.get("resource_id"))
            .is_some_and(|value| scalar_string(value) == request.resource_id);
        if object_non_empty_string(Some(requirement_object), "requirement_id").as_deref()
            == Some(request.requirement_id.as_str())
            && object_non_empty_string(Some(requirement_object), "source").as_deref()
                == Some("ags_result")
            && scope_matches
        {
            let scope = requirement_object
                .get_mut("scope")
                .and_then(Value::as_object_mut)
                .expect("matching requirement has an object scope");
            scope.insert(
                "line_item_url".to_owned(),
                Value::String(request.line_item_url.clone()),
            );
            matched = true;
        }
    }
    if !matched {
        return Err(CanvasLtiLaunchPlanError::AgsRequirementMismatch);
    }
    Ok((updated != evidence_requirements).then_some(updated))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanvasLtiIdentityStatus {
    SubjectVerified,
    Linked,
    Quarantined,
}

impl CanvasLtiIdentityStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SubjectVerified => "subject_verified",
            Self::Linked => "linked",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanvasLtiIdentityRecord {
    pub id: String,
    pub organization_id: String,
    pub platform_id: String,
    pub deployment_id: String,
    pub lti_subject: String,
    pub canvas_user_id: Option<String>,
    pub status: CanvasLtiIdentityStatus,
    pub conflict_reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanvasLtiIdentityRequest {
    pub organization_id: String,
    pub platform_id: String,
    pub deployment_id: String,
    pub lti_subject: String,
    pub canvas_user_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanvasLtiIdentityPlan {
    pub identity: CanvasLtiIdentityRecord,
    pub quarantine_existing: Option<CanvasLtiIdentityRecord>,
}

#[async_trait]
pub trait CanvasLtiIdentityRepository: Send + Sync {
    async fn reconcile_verified_identity(
        &self,
        request: &CanvasLtiIdentityRequest,
    ) -> Result<CanvasLtiIdentityRecord, CanvasLtiLaunchPlanError>;
}

#[derive(Clone)]
pub struct CanvasLtiIdentityService {
    repository: Arc<dyn CanvasLtiIdentityRepository>,
}

impl std::fmt::Debug for CanvasLtiIdentityService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasLtiIdentityService")
            .finish_non_exhaustive()
    }
}

impl CanvasLtiIdentityService {
    #[must_use]
    pub fn new(repository: Arc<dyn CanvasLtiIdentityRepository>) -> Self {
        Self { repository }
    }

    pub async fn record_verified_launch(
        &self,
        platform: &CanvasLtiPlatform,
        verified: &VerifiedLtiLaunch,
    ) -> Result<String, CanvasLtiLaunchPlanError> {
        let request = identity_request(platform, verified)?;
        let has_numeric_id = request.canvas_user_id.is_some();
        let identity = self
            .repository
            .reconcile_verified_identity(&request)
            .await?;
        Ok(if has_numeric_id {
            identity.status.as_str().to_owned()
        } else {
            "numeric_id_unavailable".to_owned()
        })
    }
}

pub fn identity_request(
    platform: &CanvasLtiPlatform,
    verified: &VerifiedLtiLaunch,
) -> Result<CanvasLtiIdentityRequest, CanvasLtiLaunchPlanError> {
    let organization_id = platform.organization_id.trim();
    let platform_id = platform.id.trim();
    let deployment_id = verified.deployment_id.trim();
    let lti_subject = verified.subject.trim();
    if organization_id.is_empty()
        || platform_id.is_empty()
        || deployment_id.is_empty()
        || lti_subject.is_empty()
    {
        return Err(CanvasLtiLaunchPlanError::Invalid(
            "Canvas LTI verified identity is incomplete",
        ));
    }
    let canvas_user_id = claim_object(&verified.raw_claims, CUSTOM_CLAIM, "custom")
        .and_then(|custom| custom.get("canvas_user_id"))
        .map(scalar_string)
        .and_then(|value| non_empty(Some(value)));
    Ok(CanvasLtiIdentityRequest {
        organization_id: organization_id.to_owned(),
        platform_id: platform_id.to_owned(),
        deployment_id: deployment_id.to_owned(),
        lti_subject: lti_subject.to_owned(),
        canvas_user_id,
    })
}

#[must_use]
pub fn plan_verified_identity(
    request: &CanvasLtiIdentityRequest,
    existing_subject: Option<&CanvasLtiIdentityRecord>,
    existing_numeric: Option<&CanvasLtiIdentityRecord>,
    new_id: &str,
) -> CanvasLtiIdentityPlan {
    let mut identity = existing_subject
        .cloned()
        .unwrap_or_else(|| CanvasLtiIdentityRecord {
            id: new_id.to_owned(),
            organization_id: request.organization_id.clone(),
            platform_id: request.platform_id.clone(),
            deployment_id: request.deployment_id.clone(),
            lti_subject: request.lti_subject.clone(),
            canvas_user_id: None,
            status: CanvasLtiIdentityStatus::SubjectVerified,
            conflict_reason: None,
        });
    let Some(canvas_user_id) = request.canvas_user_id.as_ref() else {
        return CanvasLtiIdentityPlan {
            identity,
            quarantine_existing: None,
        };
    };

    let mut reasons = Vec::new();
    if existing_subject.is_some_and(|record| record.status == CanvasLtiIdentityStatus::Quarantined)
    {
        if let Some(reason) = existing_subject.and_then(|record| record.conflict_reason.as_deref())
        {
            for reason in reason
                .split(';')
                .map(str::trim)
                .filter(|reason| !reason.is_empty())
            {
                if !reasons.contains(&reason) {
                    reasons.push(reason);
                }
            }
        }
    }
    if existing_subject
        .and_then(|record| record.canvas_user_id.as_deref())
        .is_some_and(|existing| existing != canvas_user_id)
    {
        let reason = "LTI subject was previously linked to another Canvas user";
        if !reasons.contains(&reason) {
            reasons.push(reason);
        }
    }
    if existing_numeric.is_some_and(|record| record.lti_subject != request.lti_subject) {
        let reason = "Canvas user was previously linked to another LTI subject";
        if !reasons.contains(&reason) {
            reasons.push(reason);
        }
    }
    identity.canvas_user_id = Some(canvas_user_id.clone());
    if reasons.is_empty() {
        identity.status = CanvasLtiIdentityStatus::Linked;
        identity.conflict_reason = None;
        return CanvasLtiIdentityPlan {
            identity,
            quarantine_existing: None,
        };
    }

    let reason = reasons.join("; ");
    identity.status = CanvasLtiIdentityStatus::Quarantined;
    identity.conflict_reason = Some(reason.clone());
    let quarantine_existing = existing_numeric
        .filter(|record| record.id != identity.id)
        .cloned()
        .map(|mut record| {
            record.status = CanvasLtiIdentityStatus::Quarantined;
            record.conflict_reason = Some(reason);
            record
        });
    CanvasLtiIdentityPlan {
        identity,
        quarantine_existing,
    }
}

#[derive(Clone)]
pub struct CanvasLtiLaunchStateService {
    repository: Arc<dyn CanvasLtiLaunchStateRepository>,
}

impl std::fmt::Debug for CanvasLtiLaunchStateService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasLtiLaunchStateService")
            .finish_non_exhaustive()
    }
}

impl CanvasLtiLaunchStateService {
    #[must_use]
    pub fn new(repository: Arc<dyn CanvasLtiLaunchStateRepository>) -> Self {
        Self { repository }
    }

    pub async fn claim(
        &self,
        platform_id: &str,
        state: &str,
    ) -> Result<CanvasLtiStoredLaunchState, CanvasLtiLaunchPlanError> {
        let launch_state = self
            .repository
            .get_launch_state(state)
            .await?
            .filter(|launch_state| launch_state.platform_id == platform_id)
            .ok_or(CanvasLtiLaunchPlanError::StateUnknown)?;
        if launch_state.status != "pending" || launch_state.expired {
            return Err(CanvasLtiLaunchPlanError::StateExpired);
        }
        self.repository
            .consume_launch_state(state)
            .await?
            .filter(|launch_state| launch_state.platform_id == platform_id)
            .ok_or(CanvasLtiLaunchPlanError::StateExpired)
    }
}

pub fn verify_launch(
    platform: &CanvasLtiPlatform,
    id_token: &str,
    expected_nonce: &str,
) -> Result<VerifiedLtiLaunch, CanvasLtiLaunchPlanError> {
    verify_launch_classified(platform, id_token, expected_nonce)
        .map_err(|error| CanvasLtiLaunchPlanError::Verification(error.into_message()))
}

#[derive(Debug)]
enum LaunchVerificationFailure {
    UnknownKid(String),
    Rejected(String),
}

impl LaunchVerificationFailure {
    fn into_message(self) -> String {
        match self {
            Self::UnknownKid(message) | Self::Rejected(message) => message,
        }
    }
}

fn verify_launch_classified(
    platform: &CanvasLtiPlatform,
    id_token: &str,
    expected_nonce: &str,
) -> Result<VerifiedLtiLaunch, LaunchVerificationFailure> {
    let issuer = platform.lti_issuer.as_deref().unwrap_or_default();
    let client_id = platform.lti_client_id.as_deref().unwrap_or_default();
    let deployment_id = platform.lti_deployment_id.as_deref().unwrap_or_default();
    let jwks = serde_json::to_string(platform.lti_jwks_json.as_ref().unwrap_or(&Value::Null))
        .map_err(|error| LaunchVerificationFailure::Rejected(error.to_string()))?;
    verify_lti_launch_jwt(
        id_token,
        issuer,
        client_id,
        deployment_id,
        &jwks,
        Some(expected_nonce),
        120,
    )
    .map_err(|error| match error {
        Oid4vciError::InvalidRequest(message) if message.starts_with(UNKNOWN_LTI_KID_MARKER) => {
            LaunchVerificationFailure::UnknownKid(Oid4vciError::InvalidRequest(message).to_string())
        }
        other => LaunchVerificationFailure::Rejected(other.to_string()),
    })
}

fn has_canvas_origin(platform: &CanvasLtiPlatform) -> bool {
    platform
        .canvas_base_url
        .as_deref()
        .is_some_and(|origin| !origin.trim().is_empty())
}

pub fn select_binding<'a>(
    platform: &CanvasLtiPlatform,
    verified: &VerifiedLtiLaunch,
    bindings: &'a [CanvasLtiProgramBinding],
) -> Result<&'a CanvasLtiProgramBinding, CanvasLtiLaunchPlanError> {
    let actual_scope = launch_scope(verified, &platform.canvas_account_id);
    let binding = bindings
        .iter()
        .find(|binding| {
            !binding.archived
                && binding.enabled
                && binding.organization_id == platform.organization_id
                && binding.platform_id == platform.id
                && scope_matches(&binding.canvas_scope, &actual_scope)
        })
        .ok_or(CanvasLtiLaunchPlanError::BindingNotFound)?;
    if !feature_enabled(&binding.feature_flags, "enable_canvas_lti") {
        return Err(CanvasLtiLaunchPlanError::FeatureDisabled);
    }
    Ok(binding)
}

pub fn select_binding_with_staff_fallback<'a>(
    platform: &CanvasLtiPlatform,
    verified: &VerifiedLtiLaunch,
    bindings: &'a [CanvasLtiProgramBinding],
) -> Result<&'a CanvasLtiProgramBinding, CanvasLtiLaunchPlanError> {
    match select_binding(platform, verified, bindings) {
        Ok(binding) => return Ok(binding),
        Err(CanvasLtiLaunchPlanError::BindingNotFound) => {}
        Err(error) => return Err(error),
    }
    if !matches!(
        verified.message_type.as_deref(),
        Some("LtiDeepLinkingRequest" | "LtiResourceLinkRequest")
    ) || !has_staff_role(&verified.roles)
    {
        return Err(CanvasLtiLaunchPlanError::BindingNotFound);
    }
    let requested_binding_id = claim_object(&verified.raw_claims, CUSTOM_CLAIM, "custom")
        .and_then(|custom| custom.get("canvas_program_binding_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let actual_scope = launch_scope(verified, &platform.canvas_account_id);
    let mut candidates = bindings.iter().filter(|binding| {
        !binding.archived
            && binding.organization_id == platform.organization_id
            && binding.platform_id == platform.id
            && requested_binding_id.is_none_or(|id| binding.id == id)
            && scope_matches(&binding.canvas_scope, &actual_scope)
    });
    let binding = candidates
        .next()
        .filter(|_| candidates.next().is_none())
        .ok_or(CanvasLtiLaunchPlanError::BindingNotFound)?;
    if !feature_enabled(&binding.feature_flags, "enable_canvas_lti") {
        return Err(CanvasLtiLaunchPlanError::FeatureDisabled);
    }
    Ok(binding)
}

fn has_staff_role(roles: &[String]) -> bool {
    roles.iter().any(|role| {
        matches!(
            role.trim()
                .to_ascii_lowercase()
                .replace('#', "/")
                .trim_end_matches('/')
                .rsplit('/')
                .next(),
            Some("instructor" | "administrator")
        )
    })
}

#[must_use]
pub fn private_launch_response(
    platform: &CanvasLtiPlatform,
    binding: &CanvasLtiProgramBinding,
    state: &str,
    verified: VerifiedLtiLaunch,
    identity_mapping_status: Option<String>,
) -> CanvasLtiVerifiedLaunchResponse {
    let lti_capabilities = lti_capabilities(platform, binding, &verified);
    CanvasLtiVerifiedLaunchResponse {
        organization_id: platform.organization_id.clone(),
        canvas_account_id: platform.canvas_account_id.clone(),
        canvas_platform_id: platform.id.clone(),
        canvas_program_binding_id: binding.id.clone(),
        application_template_id: binding.application_template_id.clone(),
        credential_template_id: binding.credential_template_id.clone(),
        delivery_mode: if binding.delivery_mode.is_empty() {
            "wallet_only".to_owned()
        } else {
            binding.delivery_mode.clone()
        },
        deployment_profile_id: binding.deployment_profile_id.clone(),
        feature_flags: normalized_feature_flags(&binding.feature_flags),
        evidence_requirements: binding.evidence_requirements.clone(),
        state: state.to_owned(),
        verified: true,
        issuer: verified.issuer,
        subject: verified.subject,
        audience: verified.audience,
        deployment_id: verified.deployment_id,
        nonce: verified.nonce,
        issued_at: verified.issued_at,
        expires_at: verified.expires_at,
        message_type: verified.message_type,
        lti_version: verified.lti_version,
        target_link_uri: verified.target_link_uri,
        context: verified.context,
        roles: verified.roles,
        learner_identity: verified.learner_identity,
        raw_claims: verified.raw_claims,
        lti_capabilities,
        identity_mapping_status,
    }
}

#[must_use]
pub fn public_launch_response(
    response: &CanvasLtiVerifiedLaunchResponse,
) -> CanvasLtiPublicLaunchResponse {
    CanvasLtiPublicLaunchResponse {
        verified: response.verified,
        organization_id: response.organization_id.clone(),
        canvas_account_id: response.canvas_account_id.clone(),
        canvas_platform_id: response.canvas_platform_id.clone(),
        canvas_program_binding_id: response.canvas_program_binding_id.clone(),
        application_template_id: Some(response.application_template_id.clone()),
        credential_template_id: Some(response.credential_template_id.clone()),
        message_type: response.message_type.clone(),
        context: browser_safe_context(response),
        roles: response
            .roles
            .iter()
            .map(|role| role.rsplit('/').next().unwrap_or(role).to_owned())
            .collect(),
        identity_mapping_status: response.identity_mapping_status.clone(),
    }
}

#[must_use]
pub fn launch_scope(verified: &VerifiedLtiLaunch, canvas_account_id: &str) -> Map<String, Value> {
    let custom = claim_object(&verified.raw_claims, CUSTOM_CLAIM, "custom");
    let resource_link = claim_object(&verified.raw_claims, RESOURCE_LINK_CLAIM, "resource_link");
    let context = verified.context.as_ref().and_then(Value::as_object);
    let course_id = custom
        .and_then(|values| values.get("canvas_course_id"))
        .or_else(|| context.and_then(|values| values.get("id")))
        .or_else(|| context.and_then(|values| values.get("context_id")))
        .or_else(|| verified.raw_claims.get("context_id"));
    let mut scope = Map::new();
    insert_value(
        &mut scope,
        "canvas_account_id",
        custom
            .and_then(|values| values.get("canvas_account_id"))
            .cloned()
            .unwrap_or_else(|| Value::String(canvas_account_id.to_owned())),
    );
    for key in [
        "course_id",
        "canvas_course_id",
        "canvas_context_id",
        "context_id",
    ] {
        if let Some(value) = course_id.cloned() {
            insert_value(&mut scope, key, value);
        }
    }
    if let Some(value) = resource_link.and_then(|values| values.get("id")).cloned() {
        insert_value(&mut scope, "resource_link_id", value);
    }
    for key in ["subject_id", "lti_subject"] {
        insert_value(&mut scope, key, Value::String(verified.subject.clone()));
    }
    if let Some(value) = custom
        .and_then(|values| values.get("canvas_user_id"))
        .cloned()
    {
        insert_value(&mut scope, "user_id", value.clone());
        insert_value(&mut scope, "canvas_user_id", value);
    }
    scope
}

#[must_use]
pub fn scope_matches(expected: &Value, actual: &Map<String, Value>) -> bool {
    if expected.is_null() {
        return true;
    }
    let Some(expected) = expected.as_object() else {
        return false;
    };
    expected.iter().all(|(key, expected_value)| {
        if is_empty(expected_value) {
            return true;
        }
        std::iter::once(key.as_str())
            .chain(aliases(key).iter().copied())
            .find_map(|alias| actual.get(alias).filter(|value| !is_empty(value)))
            .is_some_and(|actual_value| {
                scalar_string(actual_value) == scalar_string(expected_value)
            })
    })
}

#[must_use]
pub fn feature_enabled(flags: &Value, flag: &str) -> bool {
    let normalized = normalized_feature_flags(flags);
    normalized.is_empty() || normalized.get(flag).copied().unwrap_or(false)
}

fn normalized_feature_flags(flags: &Value) -> BTreeMap<String, bool> {
    let Some(flags) = flags.as_object() else {
        return BTreeMap::new();
    };
    FEATURE_FLAGS
        .iter()
        .filter_map(|key| {
            flags
                .get(*key)
                .map(|value| ((*key).to_owned(), truthy(value)))
        })
        .collect()
}

fn lti_capabilities(
    platform: &CanvasLtiPlatform,
    binding: &CanvasLtiProgramBinding,
    verified: &VerifiedLtiLaunch,
) -> Value {
    let message_type = verified
        .message_type
        .as_deref()
        .or_else(|| {
            verified
                .raw_claims
                .get(MESSAGE_TYPE_CLAIM)
                .and_then(Value::as_str)
        })
        .or_else(|| {
            verified
                .raw_claims
                .get("message_type")
                .and_then(Value::as_str)
        })
        .unwrap_or_default();
    let deep_linking = claim_object(
        &verified.raw_claims,
        DEEP_LINKING_CLAIM,
        "deep_linking_settings",
    );
    let ags = claim_object(&verified.raw_claims, AGS_ENDPOINT_CLAIM, "ags_endpoint");
    let nrps = claim_object(&verified.raw_claims, NRPS_CLAIM, "names_roles_service");
    let requirements = if binding.evidence_requirements.is_empty() {
        vec![Value::String("canvas.course_completion".to_owned())]
    } else {
        binding.evidence_requirements.clone()
    };
    serde_json::json!({
        "message_type": (!message_type.is_empty()).then_some(message_type),
        "resource_link": message_type == "LtiResourceLinkRequest",
        "deep_linking": deep_linking.is_some_and(|claim| !claim.is_empty()) || message_type == "LtiDeepLinkingRequest",
        "assignment_grade_services": ags.is_some_and(|claim| !claim.is_empty()),
        "names_roles": nrps.is_some_and(|claim| !claim.is_empty()),
        "deep_link_return_url": object_value(deep_linking, "deep_link_return_url"),
        "deep_link_accept_types": string_list(object_value(deep_linking, "accept_types")),
        "deep_link_accept_presentation_document_targets": string_list(object_value(deep_linking, "accept_presentation_document_targets")),
        "ags_lineitems_url": object_value(ags, "lineitems"),
        "ags_lineitem_url": object_value(ags, "lineitem"),
        "ags_scopes": string_list(object_value(ags, "scope")),
        "nrps_context_memberships_url": object_value(nrps, "context_memberships_url"),
        "supported_scopes": openid_string_list(platform, "scopes_supported"),
        "supported_claims": openid_string_list(platform, "claims_supported"),
        "binding_evidence_fact_types": evidence_fact_types(&requirements),
    })
}

fn object_value<'a>(object: Option<&'a Map<String, Value>>, key: &str) -> Option<&'a Value> {
    object.and_then(|object| object.get(key))
}

fn object_non_empty_string(object: Option<&Map<String, Value>>, key: &str) -> Option<String> {
    object
        .and_then(|object| object.get(key))
        .map(scalar_string)
        .and_then(|value| non_empty(Some(value)))
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    match value {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(value)) => (!value.is_empty())
            .then(|| value.clone())
            .into_iter()
            .collect(),
        Some(Value::Array(values)) => values
            .iter()
            .filter(|value| !value.is_null())
            .map(scalar_string)
            .filter(|value| !value.is_empty())
            .collect(),
        Some(value) => {
            let value = scalar_string(value);
            (!value.is_empty()).then_some(value).into_iter().collect()
        }
    }
}

fn openid_string_list(platform: &CanvasLtiPlatform, key: &str) -> Vec<String> {
    unique_strings(string_list(
        platform
            .lti_openid_configuration
            .as_ref()
            .and_then(|configuration| configuration.get(key)),
    ))
}

fn evidence_fact_types(requirements: &[Value]) -> Vec<String> {
    unique_strings(
        requirements
            .iter()
            .filter_map(|requirement| match requirement {
                Value::String(value) => Some(value.clone()),
                Value::Object(value) => ["fact_type", "evidence_type", "type"]
                    .iter()
                    .find_map(|key| value.get(*key).filter(|value| !is_empty(value)))
                    .map(scalar_string),
                _ => None,
            })
            .collect(),
    )
}

fn unique_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    values
        .into_iter()
        .filter(|value| !value.is_empty() && seen.insert(value.clone()))
        .collect()
}

fn browser_safe_context(response: &CanvasLtiVerifiedLaunchResponse) -> BTreeMap<String, Value> {
    let context = response.context.as_ref().and_then(Value::as_object);
    let custom = claim_object(&response.raw_claims, CUSTOM_CLAIM, "custom");
    let mut result = BTreeMap::new();
    let course_id = custom
        .and_then(|values| values.get("canvas_course_id"))
        .or_else(|| context.and_then(|values| values.get("id")))
        .or_else(|| context.and_then(|values| values.get("context_id")));
    for (name, value) in [
        ("course_id", course_id),
        ("title", context.and_then(|values| values.get("title"))),
        ("label", context.and_then(|values| values.get("label"))),
    ] {
        if let Some(value) = value.filter(|value| !is_empty(value)) {
            result.insert(name.to_owned(), value.clone());
        }
    }
    result
}

fn claim_object<'a>(
    raw: &'a Value,
    canonical: &str,
    legacy: &str,
) -> Option<&'a Map<String, Value>> {
    raw.get(canonical)
        .and_then(Value::as_object)
        .or_else(|| raw.get(legacy).and_then(Value::as_object))
}

fn signed_custom_identifier(verified: &VerifiedLtiLaunch, name: &str) -> Option<String> {
    claim_object(&verified.raw_claims, CUSTOM_CLAIM, "custom")
        .and_then(|custom| custom.get(name))
        .map(scalar_string)
        .and_then(|value| non_empty(Some(value)))
}

fn aliases(key: &str) -> &'static [&'static str] {
    match key {
        "canvas_account_id" | "account_id" => &["canvas_account_id", "account_id"],
        "course_id" | "canvas_course_id" | "canvas_context_id" | "context_id" => &[
            "course_id",
            "canvas_course_id",
            "canvas_context_id",
            "context_id",
        ],
        "assignment_id" | "canvas_assignment_id" => {
            &["assignment_id", "canvas_assignment_id", "resource_link_id"]
        }
        "module_id" | "canvas_module_id" => &["module_id", "canvas_module_id"],
        "quiz_id" | "canvas_quiz_id" => &["quiz_id", "canvas_quiz_id"],
        "user_id" | "canvas_user_id" => &["user_id", "canvas_user_id"],
        "subject_id" | "lti_subject" => &["subject_id", "lti_subject"],
        "enrollment_id" | "canvas_enrollment_id" => &["enrollment_id", "canvas_enrollment_id"],
        _ => &[],
    }
}

fn insert_value(target: &mut Map<String, Value>, key: &str, value: Value) {
    if !is_empty(&value) {
        target.insert(key.to_owned(), value);
    }
}

fn is_empty(value: &Value) -> bool {
    value.is_null() || value.as_str().is_some_and(str::is_empty)
}

fn scalar_string(value: &Value) -> String {
    match value {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_owned())
    })
}
