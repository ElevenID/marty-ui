//! Typed request boundary for Canvas integration management.
//!
//! These types deliberately contain only caller-owned fields. Trust metadata,
//! tenant identity, provider destinations, capability snapshots and readiness
//! state remain server-owned. HTTP adapters deserialize with unknown-field
//! rejection and call [`ValidateCanvasRequest`] before invoking a use case.

use std::{collections::BTreeMap, fmt};

use serde::Deserialize;
use serde_json::{Map, Value};
use thiserror::Error;

const PLATFORM_DISPLAY_NAME_MAX: usize = 200;
const PLATFORM_BASE_URL_MAX: usize = 2_048;
const IDENTIFIER_MAX: usize = 512;
const RESOURCE_ID_MAX: usize = 1_024;
const SECRET_NAME_MAX: usize = 200;
const SECRET_VALUE_MAX: usize = 16_384;
const REVIEW_NOTES_MAX: usize = 4_000;

#[derive(Debug, Error, PartialEq)]
pub enum CanvasRequestValidationError {
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    #[error("{field} must contain at most {max} characters")]
    TooLong { field: &'static str, max: usize },
    #[error("min_score_percent must be between 0 and 100")]
    InvalidScore,
    #[error("evidence_requirements must contain at least one item")]
    MissingEvidenceRequirement,
    #[error("unsupported Canvas binding scope fields: {fields}")]
    UnsupportedScope { fields: String },
    #[error("Canvas integration secret provider {provider} requires purpose {expected}")]
    ProviderPurpose {
        provider: &'static str,
        expected: &'static str,
    },
    #[error("rotate_config_token and revoke_config_token are mutually exclusive")]
    ConflictingTokenMutation,
    #[error("limit must be between 1 and 100")]
    InvalidDiscoveryLimit,
}

pub trait ValidateCanvasRequest {
    fn validate(&self) -> Result<(), CanvasRequestValidationError>;
}

fn validate_required(
    field: &'static str,
    value: &str,
    max: Option<usize>,
) -> Result<(), CanvasRequestValidationError> {
    if value.is_empty() {
        return Err(CanvasRequestValidationError::Empty { field });
    }
    validate_optional(field, Some(value), max)
}

fn validate_optional(
    field: &'static str,
    value: Option<&str>,
    max: Option<usize>,
) -> Result<(), CanvasRequestValidationError> {
    if let (Some(value), Some(max)) = (value, max) {
        if value.chars().count() > max {
            return Err(CanvasRequestValidationError::TooLong { field, max });
        }
    }
    Ok(())
}

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct SecretValue(String);

impl SecretValue {
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CanvasPlatformRequest {
    pub display_name: Option<String>,
    pub canvas_base_url: String,
    pub lti_client_id: Option<String>,
    pub lti_deployment_id: Option<String>,
    #[serde(default)]
    pub enabled: bool,
}

impl ValidateCanvasRequest for CanvasPlatformRequest {
    fn validate(&self) -> Result<(), CanvasRequestValidationError> {
        validate_optional(
            "display_name",
            self.display_name.as_deref(),
            Some(PLATFORM_DISPLAY_NAME_MAX),
        )?;
        validate_required(
            "canvas_base_url",
            &self.canvas_base_url,
            Some(PLATFORM_BASE_URL_MAX),
        )?;
        validate_optional(
            "lti_client_id",
            self.lti_client_id.as_deref(),
            Some(IDENTIFIER_MAX),
        )?;
        validate_optional(
            "lti_deployment_id",
            self.lti_deployment_id.as_deref(),
            Some(IDENTIFIER_MAX),
        )
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CanvasEvidenceScopeInput {
    pub course_id: String,
    pub activity_id: Option<String>,
    pub module_id: Option<String>,
    pub line_item_url: Option<String>,
    pub resource_id: Option<String>,
}

impl ValidateCanvasRequest for CanvasEvidenceScopeInput {
    fn validate(&self) -> Result<(), CanvasRequestValidationError> {
        validate_required("course_id", &self.course_id, Some(IDENTIFIER_MAX))?;
        validate_optional(
            "activity_id",
            self.activity_id.as_deref(),
            Some(IDENTIFIER_MAX),
        )?;
        validate_optional("module_id", self.module_id.as_deref(), Some(IDENTIFIER_MAX))?;
        validate_optional(
            "line_item_url",
            self.line_item_url.as_deref(),
            Some(PLATFORM_BASE_URL_MAX),
        )?;
        validate_optional(
            "resource_id",
            self.resource_id.as_deref(),
            Some(RESOURCE_ID_MAX),
        )
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CanvasEvidencePassRuleInput {
    pub min_score_percent: Option<f64>,
    pub completed: Option<bool>,
}

impl ValidateCanvasRequest for CanvasEvidencePassRuleInput {
    fn validate(&self) -> Result<(), CanvasRequestValidationError> {
        if self
            .min_score_percent
            .is_some_and(|score| !score.is_finite() || !(0.0..=100.0).contains(&score))
        {
            return Err(CanvasRequestValidationError::InvalidScore);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CanvasEvidenceSource {
    AgsResult,
    CanvasRest,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub enum CanvasEvidenceFactType {
    #[serde(rename = "canvas.assignment_score")]
    AssignmentScore,
    #[serde(rename = "canvas.quiz_score")]
    QuizScore,
    #[serde(rename = "canvas.course_completion")]
    CourseCompletion,
    #[serde(rename = "canvas.module_completion")]
    ModuleCompletion,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CanvasEvidenceRequirementInput {
    pub requirement_id: Option<String>,
    pub source: CanvasEvidenceSource,
    pub fact_type: CanvasEvidenceFactType,
    pub scope: CanvasEvidenceScopeInput,
    pub pass_rule: CanvasEvidencePassRuleInput,
    #[serde(default = "default_true")]
    pub required: bool,
}

impl ValidateCanvasRequest for CanvasEvidenceRequirementInput {
    fn validate(&self) -> Result<(), CanvasRequestValidationError> {
        validate_optional(
            "requirement_id",
            self.requirement_id.as_deref(),
            Some(IDENTIFIER_MAX),
        )?;
        self.scope.validate()?;
        self.pass_rule.validate()
    }
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CanvasCredentialProvider {
    BadgrApi,
    CanvasCredentialsApi,
    Bridge,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CanvasAssertionScope {
    Badgeclasses,
    Issuers,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CanvasCredentialsConfigInput {
    pub provider: Option<CanvasCredentialProvider>,
    pub api_base_url: Option<String>,
    pub issuer_id: Option<String>,
    pub badgeclass_id: Option<String>,
    pub assertion_scope: Option<CanvasAssertionScope>,
    pub api_token_secret_id: Option<String>,
    pub credential_template_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CanvasDeliveryMode {
    #[default]
    WalletOnly,
    WalletPlusCanvasMirror,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CanvasProgramBindingRequest {
    pub application_template_id: String,
    pub credential_template_id: Option<String>,
    pub display_name: Option<String>,
    #[serde(default)]
    pub auto_approve_on_evidence: bool,
    pub evidence_requirements: Vec<CanvasEvidenceRequirementInput>,
    #[serde(default)]
    pub canvas_scope: BTreeMap<String, String>,
    #[serde(default)]
    pub delivery_mode: CanvasDeliveryMode,
    pub approval_policy_set_id: Option<String>,
    pub deployment_profile_id: Option<String>,
    #[serde(default)]
    pub feature_flags: BTreeMap<String, bool>,
    pub canvas_credentials: Option<CanvasCredentialsConfigInput>,
}

impl CanvasProgramBindingRequest {
    /// Match the legacy contract: trim scope values and drop blank entries.
    pub fn normalize(mut self) -> Result<Self, CanvasRequestValidationError> {
        self.validate()?;
        self.canvas_scope = self
            .canvas_scope
            .into_iter()
            .filter_map(|(key, value)| {
                let value = value.trim().to_owned();
                (!value.is_empty()).then_some((key, value))
            })
            .collect();
        Ok(self)
    }
}

impl ValidateCanvasRequest for CanvasProgramBindingRequest {
    fn validate(&self) -> Result<(), CanvasRequestValidationError> {
        validate_required(
            "application_template_id",
            &self.application_template_id,
            Some(IDENTIFIER_MAX),
        )?;
        validate_optional(
            "credential_template_id",
            self.credential_template_id.as_deref(),
            Some(IDENTIFIER_MAX),
        )?;
        validate_optional(
            "display_name",
            self.display_name.as_deref(),
            Some(PLATFORM_DISPLAY_NAME_MAX),
        )?;
        if self.evidence_requirements.is_empty() {
            return Err(CanvasRequestValidationError::MissingEvidenceRequirement);
        }
        for requirement in &self.evidence_requirements {
            requirement.validate()?;
        }

        let unsupported = self
            .canvas_scope
            .keys()
            .filter(|key| {
                !matches!(
                    key.as_str(),
                    "course_id" | "assignment_id" | "module_id" | "quiz_id" | "resource_link_id"
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        if !unsupported.is_empty() {
            return Err(CanvasRequestValidationError::UnsupportedScope {
                fields: unsupported.join(", "),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CanvasCredentialsValidationRequest {
    pub organization_id: Option<String>,
    pub canvas_credentials: CanvasCredentialsConfigInput,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CanvasLtiInstallationRequest {
    pub lti_client_id: String,
    pub lti_deployment_id: String,
    #[serde(default)]
    pub rotate_config_token: bool,
    #[serde(default)]
    pub revoke_config_token: bool,
}

impl ValidateCanvasRequest for CanvasLtiInstallationRequest {
    fn validate(&self) -> Result<(), CanvasRequestValidationError> {
        validate_required("lti_client_id", &self.lti_client_id, None)?;
        validate_required("lti_deployment_id", &self.lti_deployment_id, None)?;
        if self.rotate_config_token && self.revoke_config_token {
            return Err(CanvasRequestValidationError::ConflictingTokenMutation);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CanvasSecretProvider {
    Canvas,
    #[default]
    CanvasCredentials,
}

impl CanvasSecretProvider {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Canvas => "canvas",
            Self::CanvasCredentials => "canvas_credentials",
        }
    }

    const fn required_purpose(self) -> CanvasSecretPurpose {
        match self {
            Self::Canvas => CanvasSecretPurpose::OauthClientSecret,
            Self::CanvasCredentials => CanvasSecretPurpose::ApiToken,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CanvasSecretPurpose {
    OauthClientSecret,
    #[default]
    ApiToken,
}

impl CanvasSecretPurpose {
    const fn as_str(self) -> &'static str {
        match self {
            Self::OauthClientSecret => "oauth_client_secret",
            Self::ApiToken => "api_token",
        }
    }
}

#[derive(Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CanvasIntegrationSecretCreate {
    pub organization_id: String,
    pub name: String,
    #[serde(default)]
    pub provider: CanvasSecretProvider,
    #[serde(default)]
    pub purpose: CanvasSecretPurpose,
    pub secret_value: SecretValue,
    #[serde(default)]
    pub metadata: Map<String, Value>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl fmt::Debug for CanvasIntegrationSecretCreate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasIntegrationSecretCreate")
            .field("organization_id", &self.organization_id)
            .field("name", &self.name)
            .field("provider", &self.provider)
            .field("purpose", &self.purpose)
            .field("secret_value", &self.secret_value)
            .field("metadata", &self.metadata)
            .field("enabled", &self.enabled)
            .finish()
    }
}

impl ValidateCanvasRequest for CanvasIntegrationSecretCreate {
    fn validate(&self) -> Result<(), CanvasRequestValidationError> {
        validate_required(
            "organization_id",
            &self.organization_id,
            Some(IDENTIFIER_MAX),
        )?;
        validate_required("name", &self.name, Some(SECRET_NAME_MAX))?;
        validate_required(
            "secret_value",
            self.secret_value.expose(),
            Some(SECRET_VALUE_MAX),
        )?;
        let expected = self.provider.required_purpose();
        if self.purpose != expected {
            return Err(CanvasRequestValidationError::ProviderPurpose {
                provider: self.provider.as_str(),
                expected: expected.as_str(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CanvasIntegrationSecretUpdate {
    pub name: Option<String>,
    pub secret_value: Option<SecretValue>,
    pub metadata: Option<Map<String, Value>>,
    pub enabled: Option<bool>,
}

impl fmt::Debug for CanvasIntegrationSecretUpdate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasIntegrationSecretUpdate")
            .field("name", &self.name)
            .field("secret_value", &self.secret_value)
            .field("metadata", &self.metadata)
            .field("enabled", &self.enabled)
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CanvasScopeDiscoveryRequest {
    pub course_id: Option<String>,
    #[serde(default = "default_true")]
    pub include_courses: bool,
    #[serde(default = "default_true")]
    pub include_assignments: bool,
    #[serde(default = "default_true")]
    pub include_quizzes: bool,
    #[serde(default = "default_true")]
    pub include_modules: bool,
    #[serde(default = "default_discovery_limit")]
    pub limit: u16,
}

const fn default_discovery_limit() -> u16 {
    50
}

impl ValidateCanvasRequest for CanvasScopeDiscoveryRequest {
    fn validate(&self) -> Result<(), CanvasRequestValidationError> {
        if !(1..=100).contains(&self.limit) {
            return Err(CanvasRequestValidationError::InvalidDiscoveryLimit);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CanvasApplicationApprovalRequest {
    pub review_notes: Option<String>,
}

impl ValidateCanvasRequest for CanvasApplicationApprovalRequest {
    fn validate(&self) -> Result<(), CanvasRequestValidationError> {
        validate_optional(
            "review_notes",
            self.review_notes.as_deref(),
            Some(REVIEW_NOTES_MAX),
        )
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn evidence_requirement() -> Value {
        json!({
            "source": "ags_result",
            "fact_type": "canvas.assignment_score",
            "scope": {"course_id": "course-1"},
            "pass_rule": {"min_score_percent": 80.0}
        })
    }

    #[test]
    fn rejects_unknown_and_server_owned_platform_fields() {
        for field in ["organization_id", "lti_issuer", "connection_config"] {
            let mut value = json!({"canvas_base_url": "https://canvas.example"});
            value[field] = json!("caller-selected");
            assert!(serde_json::from_value::<CanvasPlatformRequest>(value).is_err());
        }
    }

    #[test]
    fn platform_enforces_required_and_bounded_fields() {
        let request: CanvasPlatformRequest = serde_json::from_value(json!({
            "canvas_base_url": "",
            "display_name": "x".repeat(201)
        }))
        .unwrap();
        assert_eq!(
            request.validate(),
            Err(CanvasRequestValidationError::TooLong {
                field: "display_name",
                max: 200
            })
        );
    }

    #[test]
    fn binding_rejects_unknown_scope_and_normalizes_allowed_values() {
        let mut value = json!({
            "application_template_id": "application-template",
            "evidence_requirements": [evidence_requirement()],
            "canvas_scope": {"course_id": " course-1 ", "module_id": "  "}
        });
        let request = serde_json::from_value::<CanvasProgramBindingRequest>(value.clone())
            .unwrap()
            .normalize()
            .unwrap();
        assert_eq!(request.canvas_scope.get("course_id").unwrap(), "course-1");
        assert!(!request.canvas_scope.contains_key("module_id"));

        value["canvas_scope"] = json!({"private_service_url": "https://internal"});
        let error = serde_json::from_value::<CanvasProgramBindingRequest>(value)
            .unwrap()
            .validate()
            .unwrap_err();
        assert_eq!(
            error,
            CanvasRequestValidationError::UnsupportedScope {
                fields: "private_service_url".to_owned()
            }
        );
    }

    #[test]
    fn evidence_enforces_closed_enums_lengths_and_score_range() {
        let invalid_enum = json!({
            "source": "caller_plugin",
            "fact_type": "canvas.assignment_score",
            "scope": {"course_id": "course-1"},
            "pass_rule": {}
        });
        assert!(serde_json::from_value::<CanvasEvidenceRequirementInput>(invalid_enum).is_err());

        let invalid_score: CanvasEvidenceRequirementInput = serde_json::from_value(json!({
            "source": "canvas_rest",
            "fact_type": "canvas.quiz_score",
            "scope": {"course_id": "course-1"},
            "pass_rule": {"min_score_percent": 100.01}
        }))
        .unwrap();
        assert_eq!(
            invalid_score.validate(),
            Err(CanvasRequestValidationError::InvalidScore)
        );
    }

    #[test]
    fn secret_provider_purpose_is_closed_and_debug_is_redacted() {
        let request: CanvasIntegrationSecretCreate = serde_json::from_value(json!({
            "organization_id": "org-1",
            "name": "Canvas client",
            "provider": "canvas",
            "purpose": "api_token",
            "secret_value": "do-not-log-me"
        }))
        .unwrap();
        assert_eq!(
            request.validate(),
            Err(CanvasRequestValidationError::ProviderPurpose {
                provider: "canvas",
                expected: "oauth_client_secret"
            })
        );
        let debug = format!("{request:?}");
        assert!(!debug.contains("do-not-log-me"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn installation_and_discovery_enforce_cross_field_and_range_rules() {
        let installation: CanvasLtiInstallationRequest = serde_json::from_value(json!({
            "lti_client_id": "client",
            "lti_deployment_id": "deployment",
            "rotate_config_token": true,
            "revoke_config_token": true
        }))
        .unwrap();
        assert_eq!(
            installation.validate(),
            Err(CanvasRequestValidationError::ConflictingTokenMutation)
        );

        let discovery: CanvasScopeDiscoveryRequest =
            serde_json::from_value(json!({"limit": 101})).unwrap();
        assert_eq!(
            discovery.validate(),
            Err(CanvasRequestValidationError::InvalidDiscoveryLimit)
        );
    }

    #[test]
    fn approval_notes_are_bounded_and_unknown_fields_fail_closed() {
        let request: CanvasApplicationApprovalRequest = serde_json::from_value(json!({
            "review_notes": "x".repeat(4001)
        }))
        .unwrap();
        assert_eq!(
            request.validate(),
            Err(CanvasRequestValidationError::TooLong {
                field: "review_notes",
                max: 4000
            })
        );
        assert!(
            serde_json::from_value::<CanvasApplicationApprovalRequest>(json!({
                "review_notes": null,
                "signing_key_id": "caller-selected"
            }))
            .is_err()
        );
    }
}
