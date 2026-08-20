use std::collections::BTreeMap;

use marty_verification::flow::{
    validate_graph, FlowGraphRequest, FlowGraphStep, FlowGraphTransition, TransitionOutcome,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use thiserror::Error;
use url::{Host, Url};

use crate::{reject_private_context, FlowType};

#[derive(Clone, Debug, Eq, Error, PartialEq, Serialize)]
#[error("{code}: {field}: {message}")]
pub struct FlowApiError {
    pub code: &'static str,
    pub field: String,
    pub message: String,
}

pub trait ValidateRequest {
    fn validate(&self) -> Result<(), FlowApiError>;
}

pub fn parse_request<T>(payload: Value) -> Result<T, FlowApiError>
where
    T: for<'de> Deserialize<'de> + ValidateRequest,
{
    let request = serde_json::from_value::<T>(payload)
        .map_err(|error| api_error("FLOW.INVALID_REQUEST", "body", error.to_string()))?;
    request.validate()?;
    Ok(request)
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalStrategy {
    #[default]
    Auto,
    Manual,
    RulesBased,
    External,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HookType {
    Webhook,
    ExternalApi,
    Script,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TriggerType {
    ApiCall,
    Webhook,
    Schedule,
    ApplicationSubmitted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExtensionOutcome {
    Success,
    Failure,
    Approved,
    Rejected,
    Timeout,
    Custom,
}

impl From<ExtensionOutcome> for TransitionOutcome {
    fn from(value: ExtensionOutcome) -> Self {
        match value {
            ExtensionOutcome::Success => Self::Success,
            ExtensionOutcome::Failure => Self::Failure,
            ExtensionOutcome::Approved => Self::ApprovalGranted,
            ExtensionOutcome::Rejected => Self::ApprovalDenied,
            ExtensionOutcome::Timeout => Self::Timeout,
            ExtensionOutcome::Custom => Self::ConditionMet,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowExtensionStepRequest {
    pub step_id: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub config: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowExtensionTransitionRequest {
    pub from_step_id: String,
    pub to_step_id: String,
    pub outcome: ExtensionOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<BTreeMap<String, Value>>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowExtensionRequest {
    pub extension_uri: String,
    pub extension_version: String,
    pub extends_flow_type: FlowType,
    pub entry_step_id: String,
    pub steps: Vec<FlowExtensionStepRequest>,
    #[serde(default)]
    pub transitions: Vec<FlowExtensionTransitionRequest>,
    #[serde(default)]
    pub config: BTreeMap<String, Value>,
}

impl FlowExtensionRequest {
    pub fn validate(&self) -> Result<(), FlowApiError> {
        if self.extends_flow_type == FlowType::Custom {
            return Err(invalid(
                "extension.extends_flow_type",
                "must be a standard flow type",
            ));
        }
        absolute_uri(&self.extension_uri, "extension.extension_uri")?;
        bounded_required(&self.extension_version, 64, "extension.extension_version")?;
        for (index, step) in self.steps.iter().enumerate() {
            step_id(&step.step_id, &format!("extension.steps[{index}].step_id"))?;
            action(&step.action, &format!("extension.steps[{index}].action"))?;
            optional_max(
                &step.description,
                512,
                &format!("extension.steps[{index}].description"),
            )?;
            if step
                .timeout_seconds
                .is_some_and(|value| !(1..=86_400).contains(&value))
            {
                return Err(invalid(
                    format!("extension.steps[{index}].timeout_seconds"),
                    "must be between 1 and 86400",
                ));
            }
        }
        let graph = FlowGraphRequest {
            entry_step_id: self.entry_step_id.clone(),
            steps: self
                .steps
                .iter()
                .map(|step| FlowGraphStep {
                    step_id: step.step_id.clone(),
                })
                .collect(),
            transitions: self
                .transitions
                .iter()
                .map(|transition| FlowGraphTransition {
                    from_step_id: transition.from_step_id.clone(),
                    to_step_id: transition.to_step_id.clone(),
                    outcome: transition.outcome.into(),
                })
                .collect(),
        };
        validate_graph(&graph)
            .map_err(|error| api_error("FLOW.INVALID_GRAPH", "extension", error.to_string()))?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowHookRequest {
    pub hook_type: HookType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default)]
    pub config: BTreeMap<String, Value>,
}

impl FlowHookRequest {
    fn validate(&self, field: &str) -> Result<(), FlowApiError> {
        optional_max(&self.url, 2_048, &format!("{field}.url"))?;
        if matches!(self.hook_type, HookType::Webhook | HookType::ExternalApi) && self.url.is_none()
        {
            return Err(invalid(
                format!("{field}.url"),
                "is required for remote hooks",
            ));
        }
        if let Some(url) = &self.url {
            absolute_uri(url, &format!("{field}.url"))?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowTriggerRequest {
    pub trigger_type: TriggerType,
    #[serde(default)]
    pub config: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateFlowDefinitionRequest {
    pub organization_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub flow_type: FlowType,
    #[serde(default)]
    pub approval_strategy: ApprovalStrategy,
    #[serde(default)]
    pub hooks: BTreeMap<String, Vec<FlowHookRequest>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<FlowTriggerRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<FlowExtensionRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_template_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_template_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presentation_policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_destination_profile_id: Option<String>,
    #[serde(default)]
    pub deployment_profile_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_profile_id: Option<String>,
}

impl ValidateRequest for CreateFlowDefinitionRequest {
    fn validate(&self) -> Result<(), FlowApiError> {
        bounded_required(&self.organization_id, 255, "organization_id")?;
        bounded_required(&self.name, 255, "name")?;
        optional_max(&self.description, 2_000, "description")?;
        optional_max(&self.credential_template_id, 255, "credential_template_id")?;
        optional_max(
            &self.application_template_id,
            255,
            "application_template_id",
        )?;
        optional_max(&self.presentation_policy_id, 255, "presentation_policy_id")?;
        optional_max(
            &self.delivery_destination_profile_id,
            128,
            "delivery_destination_profile_id",
        )?;
        optional_max(&self.trust_profile_id, 255, "trust_profile_id")?;
        for (index, profile) in self.deployment_profile_ids.iter().enumerate() {
            bounded_required(profile, 255, &format!("deployment_profile_ids[{index}]"))?;
        }
        validate_hooks(&self.hooks, self.flow_type)?;
        validate_flow_references(self)?;
        match (self.flow_type, &self.extension) {
            (FlowType::Custom, Some(extension)) => extension.validate()?,
            (FlowType::Custom, None) => {
                return Err(invalid("extension", "is required for custom flow_type"))
            }
            (_, Some(_)) => {
                return Err(invalid(
                    "extension",
                    "is only permitted for custom flow_type",
                ))
            }
            (_, None) => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Patch<T> {
    #[default]
    Unset,
    Null,
    Value(T),
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Patch<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(|value| value.map_or(Self::Null, Self::Value))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateFlowDefinitionRequest {
    pub organization_id: String,
    #[serde(default, skip_serializing_if = "Patch::is_unset")]
    pub name: Patch<String>,
    #[serde(default, skip_serializing_if = "Patch::is_unset")]
    pub description: Patch<String>,
    #[serde(default, skip_serializing_if = "Patch::is_unset")]
    pub flow_type: Patch<FlowType>,
    #[serde(default, skip_serializing_if = "Patch::is_unset")]
    pub approval_strategy: Patch<ApprovalStrategy>,
    #[serde(default, skip_serializing_if = "Patch::is_unset")]
    pub hooks: Patch<BTreeMap<String, Vec<FlowHookRequest>>>,
    #[serde(default, skip_serializing_if = "Patch::is_unset")]
    pub trigger: Patch<FlowTriggerRequest>,
    #[serde(default, skip_serializing_if = "Patch::is_unset")]
    pub extension: Patch<FlowExtensionRequest>,
    #[serde(default, skip_serializing_if = "Patch::is_unset")]
    pub credential_template_id: Patch<String>,
    #[serde(default, skip_serializing_if = "Patch::is_unset")]
    pub application_template_id: Patch<String>,
    #[serde(default, skip_serializing_if = "Patch::is_unset")]
    pub presentation_policy_id: Patch<String>,
    #[serde(default, skip_serializing_if = "Patch::is_unset")]
    pub delivery_destination_profile_id: Patch<String>,
    #[serde(default, skip_serializing_if = "Patch::is_unset")]
    pub deployment_profile_ids: Patch<Vec<String>>,
    #[serde(default, skip_serializing_if = "Patch::is_unset")]
    pub trust_profile_id: Patch<String>,
}

impl<T> Patch<T> {
    #[must_use]
    pub const fn is_unset(&self) -> bool {
        matches!(self, Self::Unset)
    }

    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

impl ValidateRequest for UpdateFlowDefinitionRequest {
    fn validate(&self) -> Result<(), FlowApiError> {
        bounded_required(&self.organization_id, 255, "organization_id")?;
        if [
            self.name.is_unset(),
            self.description.is_unset(),
            self.flow_type.is_unset(),
            self.approval_strategy.is_unset(),
            self.hooks.is_unset(),
            self.trigger.is_unset(),
            self.extension.is_unset(),
            self.credential_template_id.is_unset(),
            self.application_template_id.is_unset(),
            self.presentation_policy_id.is_unset(),
            self.delivery_destination_profile_id.is_unset(),
            self.deployment_profile_ids.is_unset(),
            self.trust_profile_id.is_unset(),
        ]
        .into_iter()
        .all(|unset| unset)
        {
            return Err(invalid(
                "body",
                "at least one mutable Flow field is required",
            ));
        }
        if let Patch::Value(name) = &self.name {
            bounded_required(name, 255, "name")?;
        }
        if matches!(self.name, Patch::Null) {
            return Err(invalid("name", "cannot be null"));
        }
        if let Patch::Value(description) = &self.description {
            max_length(description, 2_000, "description")?;
        }
        for (field, null) in [
            ("flow_type", self.flow_type.is_null()),
            ("approval_strategy", self.approval_strategy.is_null()),
            ("hooks", self.hooks.is_null()),
            (
                "deployment_profile_ids",
                self.deployment_profile_ids.is_null(),
            ),
        ] {
            if null {
                return Err(invalid(field, "cannot be null"));
            }
        }
        if let Patch::Value(hooks) = &self.hooks {
            let flow_type = match &self.flow_type {
                Patch::Value(flow_type) => *flow_type,
                _ => FlowType::Custom,
            };
            validate_hooks(hooks, flow_type)?;
        }
        if let Patch::Value(extension) = &self.extension {
            extension.validate()?;
        }
        for (field, value, maximum) in [
            ("credential_template_id", &self.credential_template_id, 255),
            (
                "application_template_id",
                &self.application_template_id,
                255,
            ),
            ("presentation_policy_id", &self.presentation_policy_id, 255),
            (
                "delivery_destination_profile_id",
                &self.delivery_destination_profile_id,
                128,
            ),
            ("trust_profile_id", &self.trust_profile_id, 255),
        ] {
            if let Patch::Value(value) = value {
                max_length(value, maximum, field)?;
            }
        }
        if let Patch::Value(profiles) = &self.deployment_profile_ids {
            for (index, profile) in profiles.iter().enumerate() {
                bounded_required(profile, 255, &format!("deployment_profile_ids[{index}]"))?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartFlowRequest {
    pub organization_id: String,
    pub flow_definition_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    #[serde(default = "default_subject_type")]
    pub subject_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_reference: Option<String>,
    #[serde(default = "default_json_object")]
    pub initial_context: Value,
}

impl ValidateRequest for StartFlowRequest {
    fn validate(&self) -> Result<(), FlowApiError> {
        bounded_required(&self.organization_id, 255, "organization_id")?;
        bounded_required(&self.flow_definition_id, 255, "flow_definition_id")?;
        optional_max(&self.subject_id, 255, "subject_id")?;
        max_length(&self.subject_type, 50, "subject_type")?;
        optional_max(&self.external_reference, 500, "external_reference")?;
        require_object(&self.initial_context, "initial_context")?;
        reject_private_context(&self.initial_context).map_err(|error| {
            api_error("FLOW.PRIVATE_CONTEXT", "initial_context", error.to_string())
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdvanceFlowRequest {
    #[serde(default = "default_success")]
    pub step_result: String,
    #[serde(default = "default_json_object")]
    pub data: Value,
}

impl ValidateRequest for AdvanceFlowRequest {
    fn validate(&self) -> Result<(), FlowApiError> {
        max_length(&self.step_result, 50, "step_result")?;
        require_object(&self.data, "data")?;
        reject_private_context(&self.data)
            .map_err(|error| api_error("FLOW.PRIVATE_CONTEXT", "data", error.to_string()))
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationResponseType {
    #[default]
    VpToken,
    IdToken,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Oid4vpProfile {
    #[default]
    Standard,
    Haip,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestTransport {
    #[default]
    RequestUri,
    RequestObject,
    UrlQuery,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestUriMethod {
    #[default]
    Get,
    Post,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartVerificationFlowRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presentation_policy_id: Option<String>,
    pub organization_id: String,
    pub issuer_did: String,
    #[serde(default)]
    pub response_type: VerificationResponseType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
    #[serde(default)]
    pub oid4vp_profile: Oid4vpProfile,
    #[serde(default)]
    pub request_transport: RequestTransport,
    #[serde(default)]
    pub request_uri_method: RequestUriMethod,
    #[serde(default = "default_expiry_minutes")]
    pub expiry_minutes: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerificationRequestResponse {
    pub instance_id: String,
    pub flow_definition_id: String,
    pub request_uri: String,
    pub qr_code_data: String,
    pub presentation_policy_id: String,
    pub nonce: String,
    pub expires_at: String,
    pub status: String,
}

impl StartVerificationFlowRequest {
    pub fn validate_for_environment(&self, allow_http_loopback: bool) -> Result<(), FlowApiError> {
        bounded_required(&self.organization_id, 255, "organization_id")?;
        if !self.issuer_did.starts_with("did:") || self.issuer_did.chars().count() > 2_048 {
            return Err(invalid(
                "issuer_did",
                "must be a DID no longer than 2048 characters",
            ));
        }
        if !(1..=1_440).contains(&self.expiry_minutes) {
            return Err(invalid("expiry_minutes", "must be between 1 and 1440"));
        }
        if self.response_type == VerificationResponseType::VpToken
            && self
                .presentation_policy_id
                .as_deref()
                .is_none_or(str::is_empty)
        {
            return Err(invalid(
                "presentation_policy_id",
                "is required for vp_token flows",
            ));
        }
        if self.request_transport != RequestTransport::RequestUri
            && self.request_uri_method != RequestUriMethod::Get
        {
            return Err(invalid(
                "request_uri_method",
                "is only supported by request_uri transport",
            ));
        }
        if self.request_transport == RequestTransport::UrlQuery
            && self.response_type == VerificationResponseType::IdToken
        {
            return Err(invalid(
                "request_transport",
                "url_query does not support id_token",
            ));
        }
        if self.request_transport == RequestTransport::UrlQuery
            && self.oid4vp_profile == Oid4vpProfile::Haip
        {
            return Err(invalid(
                "request_transport",
                "unsigned url_query cannot be used for HAIP",
            ));
        }
        if let Some(callback) = &self.callback_url {
            validate_callback_url(callback, allow_http_loopback)?;
        }
        Ok(())
    }
}

impl ValidateRequest for StartVerificationFlowRequest {
    fn validate(&self) -> Result<(), FlowApiError> {
        self.validate_for_environment(false)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartSiopFlowRequest {
    pub organization_id: String,
    #[serde(default = "default_expiry_minutes")]
    pub expiry_minutes: u16,
}

impl ValidateRequest for StartSiopFlowRequest {
    fn validate(&self) -> Result<(), FlowApiError> {
        bounded_required(&self.organization_id, 255, "organization_id")?;
        if !(1..=1_440).contains(&self.expiry_minutes) {
            return Err(invalid("expiry_minutes", "must be between 1 and 1440"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiopSubmitRequest {
    pub id_token: String,
    pub instance_id: String,
}

impl ValidateRequest for SiopSubmitRequest {
    fn validate(&self) -> Result<(), FlowApiError> {
        bounded_required(&self.id_token, 16_384, "id_token")?;
        bounded_required(&self.instance_id, 255, "instance_id")
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitVerificationRequest {
    pub vp_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presentation_submission: Option<BTreeMap<String, Value>>,
}

impl ValidateRequest for SubmitVerificationRequest {
    fn validate(&self) -> Result<(), FlowApiError> {
        bounded_required(&self.vp_token, 1_048_576, "vp_token")
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DigitalCredentialSubmissionRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(default)]
    pub data: BTreeMap<String, Value>,
}

impl ValidateRequest for DigitalCredentialSubmissionRequest {
    fn validate(&self) -> Result<(), FlowApiError> {
        optional_max(&self.protocol, 128, "protocol")?;
        optional_max(&self.origin, 512, "origin")
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationApprovedWebhook {
    pub event_type: String,
    pub aggregate_id: String,
    pub aggregate_type: String,
    pub organization_id: String,
    pub data: BTreeMap<String, Value>,
    pub timestamp: String,
}

impl ValidateRequest for ApplicationApprovedWebhook {
    fn validate(&self) -> Result<(), FlowApiError> {
        if self.event_type != "application.approved" {
            return Err(invalid("event_type", "must equal application.approved"));
        }
        if self.aggregate_type != "application" {
            return Err(invalid("aggregate_type", "must equal application"));
        }
        bounded_required(&self.aggregate_id, 255, "aggregate_id")?;
        bounded_required(&self.organization_id, 255, "organization_id")?;
        bounded_required(&self.timestamp, 64, "timestamp")
    }
}

fn validate_flow_references(request: &CreateFlowDefinitionRequest) -> Result<(), FlowApiError> {
    if request.credential_template_id.is_some()
        && request.application_template_id.is_some()
        && request.flow_type != FlowType::PhysicalDocumentIssuance
    {
        return Err(invalid(
            "body",
            "credential_template_id and application_template_id are mutually exclusive",
        ));
    }
    for required in request.flow_type.required_references() {
        let present = match *required {
            "credential_template_id" => request.credential_template_id.as_deref(),
            "application_template_id" => request.application_template_id.as_deref(),
            "presentation_policy_id" => request.presentation_policy_id.as_deref(),
            "delivery_destination_profile_id" => request.delivery_destination_profile_id.as_deref(),
            "extension" => request.extension.as_ref().map(|_| "extension"),
            _ => None,
        };
        if present.is_none_or(str::is_empty) {
            return Err(invalid(
                *required,
                format!(
                    "is required for {}",
                    serde_json::to_value(request.flow_type)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_owned))
                        .unwrap_or_default()
                ),
            ));
        }
    }
    if request.flow_type == FlowType::ApplicationApprovalIssuance
        && request.credential_template_id.is_some()
    {
        return Err(invalid(
            "credential_template_id",
            "must not be set for application_approval_issuance",
        ));
    }
    Ok(())
}

fn validate_hooks(
    hooks: &BTreeMap<String, Vec<FlowHookRequest>>,
    flow_type: FlowType,
) -> Result<(), FlowApiError> {
    for (name, values) in hooks {
        let Some(step) = name
            .strip_prefix("pre_")
            .or_else(|| name.strip_prefix("post_"))
        else {
            return Err(invalid(
                format!("hooks.{name}"),
                "must use pre_{step_name} or post_{step_name}",
            ));
        };
        if step.is_empty()
            || !step.as_bytes()[0].is_ascii_alphabetic()
            || !step
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(invalid(format!("hooks.{name}"), "has an invalid step name"));
        }
        let extensible = match flow_type {
            FlowType::MdlIssuance | FlowType::ApplicationApprovalIssuance => {
                &["approval_decision", "deliver_credential"][..]
            }
            FlowType::PhysicalDocumentIssuance => &[
                "approval_decision",
                "submit_to_personalization",
                "quality_verify",
            ][..],
            FlowType::Custom => &[][..],
            _ => &[][..],
        };
        if flow_type != FlowType::Custom && !extensible.contains(&step) {
            return Err(invalid(
                format!("hooks.{name}"),
                "does not target an extensible step",
            ));
        }
        for (index, hook) in values.iter().enumerate() {
            hook.validate(&format!("hooks.{name}[{index}]"))?;
        }
    }
    Ok(())
}

fn validate_callback_url(value: &str, allow_http_loopback: bool) -> Result<(), FlowApiError> {
    max_length(value, 2_048, "callback_url")?;
    let url = Url::parse(value).map_err(|_| unsafe_callback("must be an absolute URL"))?;
    let valid_scheme = url.scheme() == "https" || (allow_http_loopback && url.scheme() == "http");
    if !valid_scheme
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(unsafe_callback(
            "must use an allowed scheme and host without userinfo",
        ));
    }
    let blocked = match url.host() {
        Some(Host::Ipv4(address)) => {
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_unspecified()
        }
        Some(Host::Ipv6(address)) => {
            address.is_loopback() || address.is_unspecified() || is_private_ipv6(address)
        }
        Some(Host::Domain(host)) => match host.to_ascii_lowercase().as_str() {
            "localhost" => !allow_http_loopback,
            "metadata.internal" => true,
            _ => false,
        },
        None => true,
    };
    if blocked {
        return Err(unsafe_callback(
            "must not target private or internal networks",
        ));
    }
    Ok(())
}

fn is_private_ipv6(address: std::net::Ipv6Addr) -> bool {
    address.segments()[0] & 0xfe00 == 0xfc00 || address.is_unicast_link_local()
}

fn absolute_uri(value: &str, field: &str) -> Result<(), FlowApiError> {
    let url = Url::parse(value).map_err(|_| invalid(field, "must be an absolute URI"))?;
    if url.scheme().is_empty() {
        return Err(invalid(field, "must be an absolute URI"));
    }
    Ok(())
}

fn step_id(value: &str, field: &str) -> Result<(), FlowApiError> {
    if value.is_empty() || value.len() > 128 || !value.is_ascii() {
        return Err(invalid(
            field,
            "must be a 1-128 character ASCII step identifier",
        ));
    }
    let mut bytes = value.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !bytes
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
    {
        return Err(invalid(field, "must match ^[a-z][a-z0-9_-]*$"));
    }
    Ok(())
}

fn action(value: &str, field: &str) -> Result<(), FlowApiError> {
    if value.is_empty() || value.len() > 160 || !value.is_ascii() {
        return Err(invalid(field, "must be a 1-160 character ASCII action"));
    }
    let mut bytes = value.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.:-".contains(&byte)
        })
    {
        return Err(invalid(field, "must match ^[a-z][a-z0-9_.:-]*$"));
    }
    Ok(())
}

fn bounded_required(value: &str, maximum: usize, field: &str) -> Result<(), FlowApiError> {
    if value.is_empty() {
        return Err(invalid(field, "is required"));
    }
    max_length(value, maximum, field)
}

fn optional_max(value: &Option<String>, maximum: usize, field: &str) -> Result<(), FlowApiError> {
    value
        .as_deref()
        .map_or(Ok(()), |value| max_length(value, maximum, field))
}

fn max_length(value: &str, maximum: usize, field: &str) -> Result<(), FlowApiError> {
    if value.chars().count() > maximum {
        Err(invalid(
            field,
            format!("must be at most {maximum} characters"),
        ))
    } else {
        Ok(())
    }
}

fn require_object(value: &Value, field: &str) -> Result<(), FlowApiError> {
    if value.is_object() {
        Ok(())
    } else {
        Err(invalid(field, "must be a JSON object"))
    }
}

fn invalid(field: impl Into<String>, message: impl Into<String>) -> FlowApiError {
    api_error("FLOW.INVALID_REQUEST", field, message)
}

fn unsafe_callback(message: impl Into<String>) -> FlowApiError {
    api_error("FLOW.UNSAFE_CALLBACK", "callback_url", message)
}

fn api_error(
    code: &'static str,
    field: impl Into<String>,
    message: impl Into<String>,
) -> FlowApiError {
    FlowApiError {
        code,
        field: field.into(),
        message: message.into(),
    }
}

fn default_subject_type() -> String {
    "applicant".into()
}

fn default_success() -> String {
    "success".into()
}

fn default_json_object() -> Value {
    Value::Object(serde_json::Map::new())
}

const fn default_expiry_minutes() -> u16 {
    15
}
