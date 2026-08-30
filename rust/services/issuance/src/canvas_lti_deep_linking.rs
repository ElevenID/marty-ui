use std::{collections::BTreeSet, fmt, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::{json, Map, Value};
use thiserror::Error;

use crate::{
    canvas_issuance_guard::validated_requirements,
    canvas_lti_experience::{
        python_string, python_truthy, CanvasLtiExperienceSessionContext,
        CanvasLtiExperienceSessionError, CanvasLtiExperienceSessionService,
    },
    canvas_lti_launch::{CanvasLtiAgsServiceUrlValidator, CanvasLtiClock},
    canvas_lti_tool_signing::{CanvasLtiToolJwtSigner, CanvasLtiToolSigningError},
};

const DEEP_LINKING_SETTINGS_CLAIM: &str =
    "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings";
const DEPLOYMENT_ID_CLAIM: &str = "https://purl.imsglobal.org/spec/lti/claim/deployment_id";
const MESSAGE_TYPE_CLAIM: &str = "https://purl.imsglobal.org/spec/lti/claim/message_type";
const VERSION_CLAIM: &str = "https://purl.imsglobal.org/spec/lti/claim/version";
const CONTENT_ITEMS_CLAIM: &str = "https://purl.imsglobal.org/spec/lti-dl/claim/content_items";
const DATA_CLAIM: &str = "https://purl.imsglobal.org/spec/lti-dl/claim/data";
const REDACTED: &str = "[REDACTED]";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanvasLtiDeepLinkingPlatform {
    pub id: String,
    pub organization_id: String,
    pub canvas_account_id: String,
    pub lti_client_id: Option<String>,
    pub lti_deployment_id: Option<String>,
    pub lti_issuer: Option<String>,
    pub config_version: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasLtiDeepLinkingBinding {
    pub id: String,
    pub organization_id: String,
    pub platform_id: String,
    pub display_name: Option<String>,
    pub application_template_id: String,
    pub credential_template_id: String,
    pub feature_flags: Value,
    pub evidence_requirements: Vec<Value>,
    pub config_version: i64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct CanvasLtiDeepLinkingPersistenceScope {
    pub session_id: String,
    pub session_state: String,
    pub platform_id: String,
    pub platform_config_version: i64,
    pub binding_id: String,
    pub binding_config_version: i64,
    pub organization_id: String,
    pub canvas_account_id: String,
}

impl fmt::Debug for CanvasLtiDeepLinkingPersistenceScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasLtiDeepLinkingPersistenceScope")
            .field("session_id", &REDACTED)
            .field("session_state", &REDACTED)
            .field("platform_id", &self.platform_id)
            .field("platform_config_version", &self.platform_config_version)
            .field("binding_id", &self.binding_id)
            .field("binding_config_version", &self.binding_config_version)
            .field("organization_id", &self.organization_id)
            .field("canvas_account_id", &self.canvas_account_id)
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct CanvasLtiDeepLinkingPlan {
    pub persistence_scope: CanvasLtiDeepLinkingPersistenceScope,
    pub jwt_payload: Value,
    pub response: CanvasLtiDeepLinkingResponse,
}

impl fmt::Debug for CanvasLtiDeepLinkingPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasLtiDeepLinkingPlan")
            .field("persistence_scope", &self.persistence_scope)
            .field("jwt_payload", &REDACTED)
            .field("response", &REDACTED)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct CanvasLtiDeepLinkingResponse {
    pub canvas_platform_id: String,
    pub organization_id: String,
    pub canvas_account_id: String,
    pub deep_link_return_url: String,
    pub content_items: Vec<Value>,
    pub jwt: String,
    pub form_post: Value,
}

impl fmt::Debug for CanvasLtiDeepLinkingResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasLtiDeepLinkingResponse")
            .field("canvas_platform_id", &self.canvas_platform_id)
            .field("organization_id", &self.organization_id)
            .field("canvas_account_id", &self.canvas_account_id)
            .field("deep_link_return_url", &REDACTED)
            .field("content_items", &REDACTED)
            .field("jwt", &REDACTED)
            .field("form_post", &REDACTED)
            .finish()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CanvasLtiDeepLinkingError {
    #[error("Canvas LTI experience session not found")]
    SessionNotFound,
    #[error("Portable Canvas integration is not enabled for this organization")]
    PilotDisabled,
    #[error("Canvas Deep Linking is disabled for this deployment profile")]
    FeatureDisabled,
    #[error("Canvas Deep Linking requires an authenticated Instructor or Administrator role")]
    StaffRoleRequired,
    #[error("Canvas platform not found")]
    PlatformNotFound,
    #[error("Canvas Deep Linking session is not bound to this platform")]
    BindingMismatch,
    #[error("Canvas LTI session was not launched with Deep Linking")]
    CapabilityMissing,
    #[error("Canvas Deep Linking launch does not accept LTI resource links")]
    ResourceLinksNotAccepted,
    #[error("Canvas Deep Linking return URL is missing")]
    ReturnUrlMissing,
    #[error("Canvas Deep Linking return URL is not trusted")]
    ReturnUrlUntrusted,
    #[error("Canvas binding evidence requirements are invalid: {0}")]
    InvalidEvidenceRequirements(String),
    #[error("Canvas LTI tool signing is unavailable: {0}")]
    SigningUnavailable(String),
    #[error("Canvas Deep Linking is temporarily unavailable")]
    RepositoryUnavailable,
    #[error("Canvas platform or program binding changed before Deep Linking response persistence")]
    ConfigurationDrift,
}

#[async_trait]
pub trait CanvasLtiDeepLinkingRepository: Send + Sync {
    async fn bound_feature_enabled(
        &self,
        organization_id: &str,
        binding_id: &str,
    ) -> Result<Option<bool>, CanvasLtiDeepLinkingError>;

    async fn get_platform(
        &self,
        context: &CanvasLtiExperienceSessionContext,
    ) -> Result<Option<CanvasLtiDeepLinkingPlatform>, CanvasLtiDeepLinkingError>;

    async fn get_binding(
        &self,
        context: &CanvasLtiExperienceSessionContext,
        platform: &CanvasLtiDeepLinkingPlatform,
    ) -> Result<Option<CanvasLtiDeepLinkingBinding>, CanvasLtiDeepLinkingError>;

    async fn persist_response(
        &self,
        scope: &CanvasLtiDeepLinkingPersistenceScope,
        response_metadata: &Value,
    ) -> Result<(), CanvasLtiDeepLinkingError>;
}

pub trait CanvasLtiDeepLinkingNonceGenerator: Send + Sync {
    fn generate(&self) -> String;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SecureCanvasLtiDeepLinkingNonceGenerator;

impl CanvasLtiDeepLinkingNonceGenerator for SecureCanvasLtiDeepLinkingNonceGenerator {
    fn generate(&self) -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }
}

#[derive(Clone)]
pub struct CanvasLtiDeepLinkingService {
    sessions: CanvasLtiExperienceSessionService,
    repository: Arc<dyn CanvasLtiDeepLinkingRepository>,
    return_url_validator: Arc<dyn CanvasLtiAgsServiceUrlValidator>,
    signer: Arc<dyn CanvasLtiToolJwtSigner>,
    clock: Arc<dyn CanvasLtiClock>,
    nonce_generator: Arc<dyn CanvasLtiDeepLinkingNonceGenerator>,
    portable_enabled: bool,
    pilot_organizations: BTreeSet<String>,
    issuer_override: Option<String>,
    tool_base_url: String,
}

impl std::fmt::Debug for CanvasLtiDeepLinkingService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasLtiDeepLinkingService")
            .field("portable_enabled", &self.portable_enabled)
            .field("pilot_organizations", &self.pilot_organizations)
            .field("issuer_override", &self.issuer_override)
            .field("tool_base_url", &self.tool_base_url)
            .finish_non_exhaustive()
    }
}

impl CanvasLtiDeepLinkingService {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        sessions: CanvasLtiExperienceSessionService,
        repository: Arc<dyn CanvasLtiDeepLinkingRepository>,
        return_url_validator: Arc<dyn CanvasLtiAgsServiceUrlValidator>,
        signer: Arc<dyn CanvasLtiToolJwtSigner>,
        clock: Arc<dyn CanvasLtiClock>,
        nonce_generator: Arc<dyn CanvasLtiDeepLinkingNonceGenerator>,
        portable_enabled: bool,
        pilot_organizations: BTreeSet<String>,
        issuer_override: Option<String>,
        tool_base_url: impl Into<String>,
    ) -> Self {
        Self {
            sessions,
            repository,
            return_url_validator,
            signer,
            clock,
            nonce_generator,
            portable_enabled,
            pilot_organizations,
            issuer_override: issuer_override.filter(|value| !value.trim().is_empty()),
            tool_base_url: tool_base_url.into().trim_end_matches('/').to_owned(),
        }
    }

    pub async fn create_response(
        &self,
        session_token: &str,
    ) -> Result<CanvasLtiDeepLinkingResponse, CanvasLtiDeepLinkingError> {
        let context = self
            .sessions
            .load(session_token)
            .await
            .map_err(session_error)?;
        let organization_id = context.launch_state.organization_id.trim();
        if !self.portable_enabled
            || organization_id.is_empty()
            || !self.pilot_organizations.contains(organization_id)
        {
            return Err(CanvasLtiDeepLinkingError::PilotDisabled);
        }
        let binding_id = context
            .canvas_program_binding_id
            .as_deref()
            .filter(|value| !value.trim().is_empty());
        if let Some(binding_id) = binding_id {
            if self
                .repository
                .bound_feature_enabled(organization_id, binding_id)
                .await?
                == Some(false)
            {
                return Err(CanvasLtiDeepLinkingError::FeatureDisabled);
            }
        }
        require_staff_role(&context.verified_launch)?;
        let platform = self
            .repository
            .get_platform(&context)
            .await?
            .ok_or(CanvasLtiDeepLinkingError::PlatformNotFound)?;
        let binding = self
            .repository
            .get_binding(&context, &platform)
            .await?
            .ok_or(CanvasLtiDeepLinkingError::BindingMismatch)?;
        if !scope_matches(&context, &platform, &binding) {
            return Err(CanvasLtiDeepLinkingError::BindingMismatch);
        }
        let now = self.clock.now();
        let mut plan = plan_deep_linking_response(
            &context,
            &platform,
            &binding,
            self.issuer_override.as_deref(),
            &self.tool_base_url,
            &self.nonce_generator.generate(),
            now,
        )?;
        let return_url = plan.response.deep_link_return_url.clone();
        let trusted_return_url = self
            .return_url_validator
            .validate(&return_url)
            .await
            .map_err(|_| CanvasLtiDeepLinkingError::ReturnUrlUntrusted)?;
        plan.response
            .deep_link_return_url
            .clone_from(&trusted_return_url);
        plan.response.form_post = form_post(&trusted_return_url, "");
        let jwt = self
            .signer
            .sign_jwt(&plan.jwt_payload)
            .await
            .map_err(signing_error)?;
        plan.response.jwt.clone_from(&jwt);
        plan.response.form_post = form_post(&trusted_return_url, &jwt);
        let response_metadata = json!({
            "created_at": now.to_rfc3339_opts(SecondsFormat::Micros, false),
            "deep_link_return_url": trusted_return_url,
            "content_items": plan.response.content_items.clone(),
        });
        self.repository
            .persist_response(&plan.persistence_scope, &response_metadata)
            .await?;
        Ok(plan.response)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn plan_deep_linking_response(
    context: &CanvasLtiExperienceSessionContext,
    platform: &CanvasLtiDeepLinkingPlatform,
    binding: &CanvasLtiDeepLinkingBinding,
    issuer_override: Option<&str>,
    tool_base_url: &str,
    nonce: &str,
    now: DateTime<Utc>,
) -> Result<CanvasLtiDeepLinkingPlan, CanvasLtiDeepLinkingError> {
    if !scope_matches(context, platform, binding) {
        return Err(CanvasLtiDeepLinkingError::BindingMismatch);
    }
    let settings = deep_linking_settings(&context.verified_launch);
    let capabilities = context.lti_capabilities.as_object();
    if !capabilities
        .and_then(|values| values.get("deep_linking"))
        .is_some_and(python_truthy)
        && settings.is_empty()
    {
        return Err(CanvasLtiDeepLinkingError::CapabilityMissing);
    }
    let accept_types = first_truthy_value(
        capabilities.and_then(|values| values.get("deep_link_accept_types")),
        settings.get("accept_types"),
    );
    let accept_types = python_string_list(accept_types);
    if !accept_types.is_empty() && !accept_types.iter().any(|value| value == "ltiResourceLink") {
        return Err(CanvasLtiDeepLinkingError::ResourceLinksNotAccepted);
    }
    let return_url = first_truthy_value(
        capabilities.and_then(|values| values.get("deep_link_return_url")),
        settings.get("deep_link_return_url"),
    )
    .and_then(Value::as_str)
    .map(str::trim)
    .filter(|value| !value.is_empty())
    .ok_or(CanvasLtiDeepLinkingError::ReturnUrlMissing)?
    .to_owned();
    let binding_json = json!({"evidence_requirements": binding.evidence_requirements.clone()});
    let requirements = validated_requirements(
        binding_json
            .as_object()
            .ok_or(CanvasLtiDeepLinkingError::RepositoryUnavailable)?,
    )
    .map_err(|cause| CanvasLtiDeepLinkingError::InvalidEvidenceRequirements(cause.to_owned()))?;
    let ags_requirements = requirements
        .iter()
        .filter(|requirement| {
            requirement.get("source").and_then(Value::as_str) == Some("ags_result")
        })
        .collect::<Vec<_>>();
    let content_items = if ags_requirements.is_empty() {
        vec![deep_linking_content_item(
            context,
            platform,
            binding,
            None,
            settings,
            tool_base_url,
        )]
    } else {
        ags_requirements
            .into_iter()
            .map(|requirement| {
                deep_linking_content_item(
                    context,
                    platform,
                    binding,
                    Some(requirement),
                    settings,
                    tool_base_url,
                )
            })
            .collect()
    };
    let raw_issuer = context
        .verified_launch
        .get("issuer")
        .filter(|value| python_truthy(value));
    let issuer = issuer_override
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| Value::String(value.to_owned()))
        .or_else(|| platform.lti_client_id.clone().map(Value::String))
        .unwrap_or(Value::Null);
    let audience = raw_issuer
        .cloned()
        .or_else(|| platform.lti_issuer.clone().map(Value::String))
        .unwrap_or(Value::Null);
    let deployment_id = context
        .verified_launch
        .get("deployment_id")
        .filter(|value| python_truthy(value))
        .cloned()
        .or_else(|| platform.lti_deployment_id.clone().map(Value::String))
        .unwrap_or(Value::Null);
    let mut payload = Map::from_iter([
        ("iss".to_owned(), issuer),
        ("aud".to_owned(), audience),
        ("iat".to_owned(), json!(now.timestamp())),
        ("exp".to_owned(), json!(now.timestamp() + 300)),
        ("nonce".to_owned(), Value::String(nonce.to_owned())),
        (DEPLOYMENT_ID_CLAIM.to_owned(), deployment_id),
        (
            MESSAGE_TYPE_CLAIM.to_owned(),
            Value::String("LtiDeepLinkingResponse".to_owned()),
        ),
        (VERSION_CLAIM.to_owned(), Value::String("1.3.0".to_owned())),
        (
            CONTENT_ITEMS_CLAIM.to_owned(),
            Value::Array(content_items.clone()),
        ),
    ]);
    if let Some(data) = settings.get("data").filter(|value| !value.is_null()) {
        payload.insert(DATA_CLAIM.to_owned(), data.clone());
    }
    let persistence_scope = CanvasLtiDeepLinkingPersistenceScope {
        session_id: context.launch_state.id.clone(),
        session_state: context.launch_state.state.clone(),
        platform_id: platform.id.clone(),
        platform_config_version: platform.config_version,
        binding_id: binding.id.clone(),
        binding_config_version: binding.config_version,
        organization_id: platform.organization_id.clone(),
        canvas_account_id: platform.canvas_account_id.clone(),
    };
    Ok(CanvasLtiDeepLinkingPlan {
        persistence_scope,
        jwt_payload: Value::Object(payload),
        response: CanvasLtiDeepLinkingResponse {
            canvas_platform_id: platform.id.clone(),
            organization_id: platform.organization_id.clone(),
            canvas_account_id: platform.canvas_account_id.clone(),
            deep_link_return_url: return_url.clone(),
            content_items,
            jwt: String::new(),
            form_post: form_post(&return_url, ""),
        },
    })
}

fn scope_matches(
    context: &CanvasLtiExperienceSessionContext,
    platform: &CanvasLtiDeepLinkingPlatform,
    binding: &CanvasLtiDeepLinkingBinding,
) -> bool {
    context.canvas_platform_id == platform.id
        && context.launch_state.platform_id == platform.id
        && context.launch_state.organization_id == platform.organization_id
        && context.launch_state.canvas_account_id == platform.canvas_account_id
        && context.canvas_program_binding_id.as_deref() == Some(binding.id.as_str())
        && binding.organization_id == platform.organization_id
        && binding.platform_id == platform.id
}

fn require_staff_role(verified: &Map<String, Value>) -> Result<(), CanvasLtiDeepLinkingError> {
    let roles = python_string_list(verified.get("roles"));
    if roles.into_iter().any(|role| {
        let normalized = role
            .trim()
            .to_ascii_lowercase()
            .replace('#', "/")
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_owned();
        matches!(normalized.as_str(), "instructor" | "administrator")
    }) {
        Ok(())
    } else {
        Err(CanvasLtiDeepLinkingError::StaffRoleRequired)
    }
}

fn deep_linking_settings(verified: &Map<String, Value>) -> &Map<String, Value> {
    static EMPTY: std::sync::OnceLock<Map<String, Value>> = std::sync::OnceLock::new();
    let raw = verified.get("raw_claims").and_then(Value::as_object);
    raw.and_then(|claims| claims.get(DEEP_LINKING_SETTINGS_CLAIM))
        .and_then(Value::as_object)
        .or_else(|| {
            raw.and_then(|claims| claims.get("deep_linking_settings"))
                .and_then(Value::as_object)
        })
        .unwrap_or_else(|| EMPTY.get_or_init(Map::new))
}

fn deep_linking_content_item(
    context: &CanvasLtiExperienceSessionContext,
    platform: &CanvasLtiDeepLinkingPlatform,
    binding: &CanvasLtiDeepLinkingBinding,
    requirement: Option<&Value>,
    settings: &Map<String, Value>,
    tool_base_url: &str,
) -> Value {
    let title = deep_linking_title(context, binding);
    let mut item = Map::from_iter([
        (
            "type".to_owned(),
            Value::String("ltiResourceLink".to_owned()),
        ),
        ("title".to_owned(), Value::String(title.clone())),
        (
            "text".to_owned(),
            Value::String("Open the Marty credential application for this course.".to_owned()),
        ),
        (
            "url".to_owned(),
            Value::String(format!(
                "{}/v1/integrations/canvas/lti/platforms/{}/experience",
                tool_base_url.trim_end_matches('/'),
                platform.id
            )),
        ),
        (
            "custom".to_owned(),
            Value::Object(deep_linking_custom_values(context, requirement)),
        ),
    ]);
    let accepted_targets = python_string_list(settings.get("accept_presentation_document_targets"))
        .into_iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    if accepted_targets.contains("window") {
        item.insert(
            "presentation".to_owned(),
            json!({"documentTarget": "window", "windowTarget": "_blank"}),
        );
    }
    if let Some(requirement) = requirement {
        let requirement_id = requirement
            .get("requirement_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let resource_id = requirement
            .get("scope")
            .and_then(Value::as_object)
            .and_then(|scope| scope.get("resource_id"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        item.insert(
            "lineItem".to_owned(),
            json!({
                "scoreMaximum": 100,
                "label": title,
                "resourceId": resource_id,
                "tag": format!("marty:{requirement_id}"),
            }),
        );
    }
    Value::Object(item)
}

fn deep_linking_title(
    context: &CanvasLtiExperienceSessionContext,
    binding: &CanvasLtiDeepLinkingBinding,
) -> String {
    let canvas = context
        .verified_launch
        .get("context")
        .and_then(Value::as_object);
    [
        binding.display_name.clone(),
        canvas
            .and_then(|value| value.get("title"))
            .and_then(python_string),
        canvas
            .and_then(|value| value.get("label"))
            .and_then(python_string),
        context.credential_template_id.clone(),
        context.application_template_id.clone(),
    ]
    .into_iter()
    .flatten()
    .map(|value| value.trim().to_owned())
    .find(|value| !value.is_empty())
    .filter(|value| !value.is_empty())
    .unwrap_or_else(|| "ElevenID Credential Application".to_owned())
}

fn deep_linking_custom_values(
    context: &CanvasLtiExperienceSessionContext,
    requirement: Option<&Value>,
) -> Map<String, Value> {
    let canvas = context
        .verified_launch
        .get("context")
        .and_then(Value::as_object);
    let mut raw = vec![
        (
            "canvas_account_id",
            Some(context.launch_state.canvas_account_id.clone()),
        ),
        (
            "canvas_platform_id",
            Some(context.canvas_platform_id.clone()),
        ),
        (
            "canvas_program_binding_id",
            context.canvas_program_binding_id.clone(),
        ),
        (
            "application_template_id",
            context.application_template_id.clone(),
        ),
        (
            "credential_template_id",
            context.credential_template_id.clone(),
        ),
        (
            "canvas_course_id",
            canvas
                .and_then(|value| value.get("id").or_else(|| value.get("context_id")))
                .and_then(python_string),
        ),
    ];
    if let Some(requirement) = requirement {
        raw.extend([
            (
                "canvas_requirement_id",
                requirement.get("requirement_id").and_then(python_string),
            ),
            (
                "canvas_resource_id",
                requirement
                    .get("scope")
                    .and_then(Value::as_object)
                    .and_then(|scope| scope.get("resource_id"))
                    .and_then(python_string),
            ),
        ]);
    }
    Map::from_iter(raw.into_iter().filter_map(|(name, value)| {
        value
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .map(|value| (name.to_owned(), Value::String(value)))
    }))
}

fn first_truthy_value<'a>(
    first: Option<&'a Value>,
    second: Option<&'a Value>,
) -> Option<&'a Value> {
    first
        .filter(|value| python_truthy(value))
        .or_else(|| second.filter(|value| python_truthy(value)))
}

fn python_string_list(value: Option<&Value>) -> Vec<String> {
    match value {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(value)) => (!value.is_empty())
            .then(|| value.clone())
            .into_iter()
            .collect(),
        Some(Value::Array(values)) => values
            .iter()
            .filter(|value| !value.is_null())
            .filter_map(python_string)
            .filter(|value| !value.is_empty())
            .collect(),
        Some(value) => python_string(value)
            .filter(|value| !value.is_empty())
            .into_iter()
            .collect(),
    }
}

fn form_post(action: &str, jwt: &str) -> Value {
    json!({
        "method": "POST",
        "action": action,
        "fields": {"JWT": jwt},
    })
}

fn session_error(error: CanvasLtiExperienceSessionError) -> CanvasLtiDeepLinkingError {
    match error {
        CanvasLtiExperienceSessionError::NotFound => CanvasLtiDeepLinkingError::SessionNotFound,
        CanvasLtiExperienceSessionError::RepositoryUnavailable => {
            CanvasLtiDeepLinkingError::RepositoryUnavailable
        }
    }
}

fn signing_error(error: CanvasLtiToolSigningError) -> CanvasLtiDeepLinkingError {
    CanvasLtiDeepLinkingError::SigningUnavailable(error.to_string())
}
