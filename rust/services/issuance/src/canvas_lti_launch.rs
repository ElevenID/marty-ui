use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use marty_oid4vci::{
    lti::{verify_lti_launch_jwt, VerifiedLtiLaunch},
    Oid4vciError,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::canvas_lti_login::CanvasLtiPlatform;

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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanvasLtiStoredLaunchState {
    pub platform_id: String,
    pub state: String,
    pub nonce: String,
    pub status: String,
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

pub trait CanvasLtiAgsServiceUrlValidator: Send + Sync {
    fn validate(&self, service_url: &str) -> Result<String, String>;
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
            .map_err(CanvasLtiLaunchPlanError::AgsLineItem)?;
        self.repository
            .pin_verified_line_item(binding, &request)
            .await
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
