//! Application Template request, lifecycle and validation policy.
//!
//! The HTTP and PostgreSQL adapters intentionally do not reproduce these
//! decisions. Both call this module so validation order and lifecycle behavior
//! stay identical across transports and future workers.

use std::collections::{BTreeSet, HashSet};

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;
use uuid::Uuid;

const FIELD_ID_PATTERN: &str = r"^[a-z][a-z0-9_]*$";
const FIELD_TYPES: &[&str] = &[
    "TEXT",
    "DATE",
    "DATETIME",
    "SELECT",
    "FILE_UPLOAD",
    "INTEGER",
    "NUMBER",
    "BOOLEAN",
    "EMAIL",
    "URL",
];
const EVIDENCE_TYPES: &[&str] = &[
    "DOCUMENT_SCAN",
    "BIOMETRIC",
    "SELFIE",
    "THIRD_PARTY_VERIFICATION",
    "EXTERNAL_FACT",
    "EXTERNAL_API",
];
const CLAIM_SOURCES: &[&str] = &[
    "FORM_FIELD",
    "EVIDENCE_EXTRACTION",
    "EXTERNAL_API",
    "SYSTEM",
];
const SYSTEM_FIELDS: &[&str] = &[
    "applicant.user_id",
    "applicant.email",
    "applicant.given_name",
    "applicant.family_name",
    "application.id",
    "application.reference_number",
    "application.organization_id",
    "current.date",
    "current.datetime",
    "validity.expiry_date",
    "template.name",
    "template.description",
    "constant",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationFieldOption {
    pub label: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum SelectOption {
    Legacy(String),
    Structured(ApplicationFieldOption),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationFormField {
    pub field_id: String,
    pub label: String,
    pub field_type: String,
    pub required: bool,
    #[serde(default)]
    pub claim_mapping: Option<String>,
    #[serde(default)]
    pub validation_pattern: Option<String>,
    #[serde(default)]
    pub options: Option<Vec<SelectOption>>,
    #[serde(default)]
    pub minimum: Option<f64>,
    #[serde(default)]
    pub maximum: Option<f64>,
    #[serde(default)]
    pub placeholder: Option<String>,
    #[serde(default)]
    pub hint: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationEvidenceRequirement {
    pub evidence_id: String,
    pub evidence_type: String,
    pub description: String,
    pub required: bool,
    #[serde(default)]
    pub accepted_formats: Option<Vec<String>>,
    #[serde(default)]
    pub max_file_size_bytes: Option<u64>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub fact_type: Option<String>,
    #[serde(default)]
    pub scope: Option<Map<String, Value>>,
    #[serde(default)]
    pub pass_rule: Option<Map<String, Value>>,
    #[serde(default)]
    pub verification_method: Option<String>,
    #[serde(default)]
    pub freshness: Option<Map<String, Value>>,
    #[serde(default)]
    pub manual_fallback: Option<bool>,
    #[serde(default)]
    pub api: Option<Map<String, Value>>,
    #[serde(default)]
    pub expected_response: Option<Map<String, Value>>,
    #[serde(default)]
    pub response_mapping: Option<Map<String, Value>>,
    #[serde(default)]
    pub auto_issue_on_permit: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimCollectionRule {
    pub claim_name: String,
    pub source: String,
    #[serde(default)]
    pub source_config: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredApplicationCheck {
    pub check_type: String,
    #[serde(default = "default_true")]
    pub is_required: bool,
    pub order: i64,
    #[serde(default)]
    pub config: Map<String, Value>,
    #[serde(default)]
    pub external_provider: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationTemplateCreate {
    pub organization_id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub credential_template_id: Option<String>,
    #[serde(default)]
    pub form_fields: Vec<ApplicationFormField>,
    #[serde(default)]
    pub evidence_requirements: Vec<ApplicationEvidenceRequirement>,
    #[serde(default)]
    pub claim_collection_rules: Vec<ClaimCollectionRule>,
    #[serde(default)]
    pub required_checks: Vec<RequiredApplicationCheck>,
    #[serde(default = "default_approval_strategy")]
    pub approval_strategy: String,
    #[serde(default)]
    pub approval_policy_set_id: Option<String>,
    #[serde(default = "default_validity_days")]
    pub application_validity_days: i64,
    #[serde(default)]
    pub ui_config: Map<String, Value>,
    #[serde(default)]
    pub notification_config: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(transparent)]
pub struct ApplicationTemplatePatch {
    changes: Map<String, Value>,
}

impl ApplicationTemplatePatch {
    pub fn apply(
        self,
        template: &mut ApplicationTemplateRecord,
        now: DateTime<Utc>,
    ) -> Result<(), ApplicationTemplateRequestError> {
        template
            .require_draft_patch()
            .map_err(|_| ApplicationTemplateRequestError::NotDraft)?;
        for (name, value) in self.changes {
            match name.as_str() {
                "name" => {
                    let value = required_string("name", value)?;
                    require_length("name", &value, 1, 128)?;
                    template.name = value;
                }
                "description" => template.description = nullable_string("description", value)?,
                "credential_template_id" => {
                    template.credential_template_id =
                        nullable_string("credential_template_id", value)?
                }
                "form_fields" => {
                    let fields = typed_array::<ApplicationFormField>("form_fields", value)?;
                    validate_changed_arrays(Some(&fields), None, None, None)?;
                    template.form_fields = values(fields)?;
                }
                "evidence_requirements" => {
                    let evidence = typed_array::<ApplicationEvidenceRequirement>(
                        "evidence_requirements",
                        value,
                    )?;
                    validate_changed_arrays(None, Some(&evidence), None, None)?;
                    template.evidence_requirements = values(evidence)?;
                }
                "claim_collection_rules" => {
                    let rules =
                        typed_array::<ClaimCollectionRule>("claim_collection_rules", value)?;
                    validate_changed_arrays(None, None, Some(&rules), None)?;
                    template.claim_collection_rules = values(rules)?;
                }
                "required_checks" => {
                    let checks = typed_array::<RequiredApplicationCheck>("required_checks", value)?;
                    validate_changed_arrays(None, None, None, Some(&checks))?;
                    template.required_checks = values(checks)?;
                }
                "approval_strategy" => {
                    let value = required_string("approval_strategy", value)?;
                    if !matches!(
                        value.as_str(),
                        "AUTO" | "MANUAL" | "RULES_BASED" | "EXTERNAL"
                    ) {
                        return Err(ApplicationTemplateRequestError::InvalidField(name));
                    }
                    template.approval_strategy = value;
                }
                "approval_policy_set_id" => {
                    template.approval_policy_set_id =
                        nullable_string("approval_policy_set_id", value)?
                }
                "application_validity_days" => {
                    let value = value.as_i64().ok_or_else(|| {
                        ApplicationTemplateRequestError::InvalidField(name.clone())
                    })?;
                    if !(1..=3650).contains(&value) {
                        return Err(ApplicationTemplateRequestError::InvalidField(name));
                    }
                    template.application_validity_days = value;
                }
                "ui_config" => {
                    template.ui_config = required_object("ui_config", value)?;
                }
                "notification_config" => {
                    template.notification_config = required_object("notification_config", value)?;
                }
                _ => return Err(ApplicationTemplateRequestError::UnknownField(name)),
            }
        }
        template
            .bump(template.status, now)
            .map_err(|_| ApplicationTemplateRequestError::VersionExhausted)
    }
}

impl ApplicationTemplateCreate {
    pub fn validate_transport(&self) -> Result<(), ApplicationTemplateRequestError> {
        require_length("name", &self.name, 1, 128)?;
        if !matches!(
            self.approval_strategy.as_str(),
            "AUTO" | "MANUAL" | "RULES_BASED" | "EXTERNAL"
        ) {
            return Err(ApplicationTemplateRequestError::InvalidField(
                "approval_strategy".to_owned(),
            ));
        }
        if !(1..=3650).contains(&self.application_validity_days) {
            return Err(ApplicationTemplateRequestError::InvalidField(
                "application_validity_days".to_owned(),
            ));
        }
        let field_id = Regex::new(FIELD_ID_PATTERN).expect("static field ID expression");
        for (index, field) in self.form_fields.iter().enumerate() {
            if !field_id.is_match(&field.field_id) {
                return Err(ApplicationTemplateRequestError::InvalidField(format!(
                    "form_fields.{index}.field_id"
                )));
            }
            require_length(&format!("form_fields.{index}.label"), &field.label, 1, 256)?;
            if !FIELD_TYPES.contains(&field.field_type.as_str()) {
                return Err(ApplicationTemplateRequestError::InvalidField(format!(
                    "form_fields.{index}.field_type"
                )));
            }
            if let Some(options) = &field.options {
                for (option_index, option) in options.iter().enumerate() {
                    match option {
                        SelectOption::Legacy(value) => require_length(
                            &format!("form_fields.{index}.options.{option_index}"),
                            value,
                            1,
                            256,
                        )?,
                        SelectOption::Structured(value) => {
                            require_length(
                                &format!("form_fields.{index}.options.{option_index}.label"),
                                &value.label,
                                1,
                                256,
                            )?;
                            require_length(
                                &format!("form_fields.{index}.options.{option_index}.value"),
                                &value.value,
                                1,
                                256,
                            )?;
                        }
                    }
                }
            }
        }
        for (index, evidence) in self.evidence_requirements.iter().enumerate() {
            require_length(
                &format!("evidence_requirements.{index}.evidence_id"),
                &evidence.evidence_id,
                1,
                usize::MAX,
            )?;
            if !EVIDENCE_TYPES.contains(&evidence.evidence_type.as_str()) {
                return Err(ApplicationTemplateRequestError::InvalidField(format!(
                    "evidence_requirements.{index}.evidence_type"
                )));
            }
            if evidence.max_file_size_bytes == Some(0) {
                return Err(ApplicationTemplateRequestError::InvalidField(format!(
                    "evidence_requirements.{index}.max_file_size_bytes"
                )));
            }
        }
        for (index, rule) in self.claim_collection_rules.iter().enumerate() {
            require_length(
                &format!("claim_collection_rules.{index}.claim_name"),
                &rule.claim_name,
                1,
                usize::MAX,
            )?;
            if !CLAIM_SOURCES.contains(&rule.source.as_str()) {
                return Err(ApplicationTemplateRequestError::InvalidField(format!(
                    "claim_collection_rules.{index}.source"
                )));
            }
        }
        for (index, check) in self.required_checks.iter().enumerate() {
            require_length(
                &format!("required_checks.{index}.check_type"),
                &check.check_type,
                1,
                usize::MAX,
            )?;
            if check.order < 1 {
                return Err(ApplicationTemplateRequestError::InvalidField(format!(
                    "required_checks.{index}.order"
                )));
            }
        }
        Ok(())
    }

    pub fn into_record(
        self,
        id: String,
        now: DateTime<Utc>,
    ) -> Result<ApplicationTemplateRecord, ApplicationTemplateRequestError> {
        self.validate_transport()?;
        Ok(ApplicationTemplateRecord {
            id,
            organization_id: self.organization_id,
            name: self.name,
            description: self.description,
            credential_template_id: self.credential_template_id,
            form_fields: values(self.form_fields)?,
            evidence_requirements: values(self.evidence_requirements)?,
            claim_collection_rules: values(self.claim_collection_rules)?,
            required_checks: values(self.required_checks)?,
            approval_strategy: self.approval_strategy,
            approval_policy_set_id: self.approval_policy_set_id,
            application_validity_days: self.application_validity_days,
            ui_config: self.ui_config,
            notification_config: self.notification_config,
            status: ApplicationTemplateStatus::Draft,
            version: 1,
            created_at: now,
            updated_at: now,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApplicationTemplateStatus {
    Draft,
    Active,
    Deprecated,
}

impl ApplicationTemplateStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "DRAFT",
            Self::Active => "ACTIVE",
            Self::Deprecated => "DEPRECATED",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ApplicationTemplateRecord {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub description: Option<String>,
    pub credential_template_id: Option<String>,
    pub form_fields: Vec<Value>,
    pub evidence_requirements: Vec<Value>,
    pub claim_collection_rules: Vec<Value>,
    pub required_checks: Vec<Value>,
    pub approval_strategy: String,
    pub approval_policy_set_id: Option<String>,
    pub application_validity_days: i64,
    pub ui_config: Map<String, Value>,
    pub notification_config: Map<String, Value>,
    pub status: ApplicationTemplateStatus,
    #[serde(skip)]
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ApplicationTemplateRecord {
    pub fn new(
        request: ApplicationTemplateCreate,
        now: DateTime<Utc>,
    ) -> Result<Self, ApplicationTemplateRequestError> {
        request.into_record(Uuid::new_v4().to_string(), now)
    }

    pub fn activate(
        &mut self,
        validation_errors: &[ApplicationTemplateValidationError],
        now: DateTime<Utc>,
    ) -> Result<(), ApplicationTemplateLifecycleError> {
        self.require_draft_activation()?;
        if !validation_errors.is_empty() {
            return Err(ApplicationTemplateLifecycleError::ValidationFailed);
        }
        self.bump(ApplicationTemplateStatus::Active, now)
    }

    pub fn require_draft_activation(&self) -> Result<(), ApplicationTemplateLifecycleError> {
        if self.status == ApplicationTemplateStatus::Draft {
            Ok(())
        } else {
            Err(ApplicationTemplateLifecycleError::ActivateRequiresDraft)
        }
    }

    pub fn deprecate(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<(), ApplicationTemplateLifecycleError> {
        if self.status != ApplicationTemplateStatus::Active {
            return Err(ApplicationTemplateLifecycleError::DeprecateRequiresActive);
        }
        self.bump(ApplicationTemplateStatus::Deprecated, now)
    }

    pub fn require_draft_patch(&self) -> Result<(), ApplicationTemplateLifecycleError> {
        if self.status == ApplicationTemplateStatus::Draft {
            Ok(())
        } else {
            Err(ApplicationTemplateLifecycleError::PatchRequiresDraft)
        }
    }

    pub fn require_draft_delete(&self) -> Result<(), ApplicationTemplateLifecycleError> {
        if self.status == ApplicationTemplateStatus::Draft {
            Ok(())
        } else {
            Err(ApplicationTemplateLifecycleError::DeleteRequiresDraft)
        }
    }

    fn bump(
        &mut self,
        status: ApplicationTemplateStatus,
        now: DateTime<Utc>,
    ) -> Result<(), ApplicationTemplateLifecycleError> {
        self.version = self
            .version
            .checked_add(1)
            .ok_or(ApplicationTemplateLifecycleError::VersionExhausted)?;
        self.status = status;
        self.updated_at = now;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialTemplateValidationView {
    pub organization_id: String,
    pub status: String,
    pub revocation_profile_id: Option<String>,
    pub claims: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialTemplateValidationState {
    MissingReference,
    NotFound,
    Unavailable,
    Found(CredentialTemplateValidationView),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalPolicyValidationView {
    pub policy_type: String,
    pub status: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalPolicyValidationState {
    NotRequested,
    NotFound,
    Found(ApprovalPolicyValidationView),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApplicationTemplateValidationError {
    pub section: String,
    pub field: String,
    pub code: String,
    pub message: String,
}

pub fn validate_application_template(
    template: &ApplicationTemplateRecord,
    credential_template: &CredentialTemplateValidationState,
    approval_policy: &ApprovalPolicyValidationState,
) -> Vec<ApplicationTemplateValidationError> {
    let mut errors = Vec::new();
    let mut add = |section: &str, field: String, code: &str, message: &str| {
        errors.push(ApplicationTemplateValidationError {
            section: section.to_owned(),
            field,
            code: code.to_owned(),
            message: message.to_owned(),
        });
    };

    let claims = match credential_template {
        CredentialTemplateValidationState::MissingReference => {
            add(
                "credential_template",
                "credential_template_id".to_owned(),
                "REQUIRED",
                "Select a Credential Template.",
            );
            BTreeSet::new()
        }
        CredentialTemplateValidationState::NotFound => {
            add(
                "credential_template",
                "credential_template_id".to_owned(),
                "NOT_FOUND",
                "Credential Template was not found.",
            );
            BTreeSet::new()
        }
        CredentialTemplateValidationState::Unavailable => {
            add(
                "credential_template",
                "credential_template_id".to_owned(),
                "UNAVAILABLE",
                "Credential Template validation is unavailable.",
            );
            BTreeSet::new()
        }
        CredentialTemplateValidationState::Found(value) => {
            if value.organization_id != template.organization_id {
                add(
                    "credential_template",
                    "credential_template_id".to_owned(),
                    "WRONG_ORGANIZATION",
                    "Credential Template belongs to another organization.",
                );
            }
            if !value.status.eq_ignore_ascii_case("ACTIVE") {
                add(
                    "credential_template",
                    "credential_template_id".to_owned(),
                    "NOT_ACTIVE",
                    "Credential Template must be active.",
                );
            }
            if value
                .revocation_profile_id
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
            {
                add(
                    "credential_template",
                    "credential_template_id".to_owned(),
                    "REVOCATION_PROFILE_REQUIRED",
                    "Credential Template must reference an active Revocation Profile.",
                );
            }
            value.claims.clone()
        }
    };

    if template.form_fields.is_empty() {
        add(
            "form_fields",
            "form_fields".to_owned(),
            "REQUIRED",
            "Add at least one form field.",
        );
    }
    let mut seen_fields = HashSet::new();
    for (index, field) in template.form_fields.iter().enumerate() {
        let Some(field) = field.as_object() else {
            add(
                "form_fields",
                format!("form_fields.{index}"),
                "INVALID",
                "Form fields must use the canonical object shape.",
            );
            continue;
        };
        let field_id = text(field.get("field_id"));
        if field_id.is_empty() {
            add(
                "form_fields",
                format!("form_fields.{index}.field_id"),
                "REQUIRED",
                "Field ID is required.",
            );
        }
        if text(field.get("label")).trim().is_empty() {
            add(
                "form_fields",
                format!("form_fields.{index}.label"),
                "REQUIRED",
                "Field label is required.",
            );
        }
        let field_type = text(field.get("field_type"));
        if !FIELD_TYPES.contains(&field_type.as_str()) {
            add(
                "form_fields",
                format!("form_fields.{index}.field_type"),
                "INVALID",
                "Select a canonical field type.",
            );
        }
        if !seen_fields.insert(field_id.clone()) {
            add(
                "form_fields",
                format!("form_fields.{index}.field_id"),
                "DUPLICATE",
                "Field IDs must be unique.",
            );
        }
        if field_type == "SELECT"
            && field
                .get("options")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
        {
            add(
                "form_fields",
                format!("form_fields.{index}.options"),
                "REQUIRED",
                "Select fields require options.",
            );
        }
        if numeric(field.get("minimum"))
            .zip(numeric(field.get("maximum")))
            .is_some_and(|(minimum, maximum)| minimum > maximum)
        {
            add(
                "form_fields",
                format!("form_fields.{index}.minimum"),
                "INVALID_RANGE",
                "Minimum cannot exceed maximum.",
            );
        }
        let pattern = text(field.get("validation_pattern"));
        if !pattern.is_empty() && Regex::new(&pattern).is_err() {
            add(
                "form_fields",
                format!("form_fields.{index}.validation_pattern"),
                "INVALID_PATTERN",
                "Validation pattern is not a valid regular expression.",
            );
        }
        let claim_mapping = text(field.get("claim_mapping"));
        if !claim_mapping.is_empty() && !claims.is_empty() && !claims.contains(&claim_mapping) {
            add(
                "claim_mappings",
                format!("form_fields.{index}.claim_mapping"),
                "UNKNOWN_CLAIM",
                "Claim mapping is not defined by the Credential Template.",
            );
        }
    }

    let mut seen_evidence = HashSet::new();
    for (index, requirement) in template.evidence_requirements.iter().enumerate() {
        let Some(requirement) = requirement.as_object() else {
            add(
                "evidence",
                format!("evidence_requirements.{index}"),
                "INVALID",
                "Evidence must use the canonical object shape.",
            );
            continue;
        };
        let evidence_id = text(requirement.get("evidence_id")).trim().to_owned();
        let evidence_type = text(requirement.get("evidence_type"));
        if evidence_id.is_empty() {
            add(
                "evidence",
                format!("evidence_requirements.{index}.evidence_id"),
                "REQUIRED",
                "Evidence ID is required.",
            );
        } else if !seen_evidence.insert(evidence_id) {
            add(
                "evidence",
                format!("evidence_requirements.{index}.evidence_id"),
                "DUPLICATE",
                "Evidence IDs must be unique.",
            );
        }
        if !EVIDENCE_TYPES.contains(&evidence_type.as_str()) {
            add(
                "evidence",
                format!("evidence_requirements.{index}.evidence_type"),
                "INVALID",
                "Select a canonical evidence type.",
            );
        }
        if text(requirement.get("description")).trim().is_empty() {
            add(
                "evidence",
                format!("evidence_requirements.{index}.description"),
                "REQUIRED",
                "Evidence description is required.",
            );
        }
        if !requirement.get("required").is_some_and(Value::is_boolean) {
            add(
                "evidence",
                format!("evidence_requirements.{index}.required"),
                "REQUIRED",
                "Evidence required state must be explicit.",
            );
        }
        if matches!(evidence_type.as_str(), "EXTERNAL_FACT" | "EXTERNAL_API") {
            if text(requirement.get("provider")).trim().is_empty() {
                add(
                    "evidence",
                    format!("evidence_requirements.{index}.provider"),
                    "REQUIRED",
                    "External evidence provider is required.",
                );
            }
            if text(requirement.get("fact_type")).trim().is_empty() {
                add(
                    "evidence",
                    format!("evidence_requirements.{index}.fact_type"),
                    "REQUIRED",
                    "External evidence fact type is required.",
                );
            }
        }
        if evidence_type == "EXTERNAL_API"
            && requirement
                .get("api")
                .and_then(Value::as_object)
                .map(|api| text(api.get("url")))
                .is_none_or(|url| url.trim().is_empty())
        {
            add(
                "evidence",
                format!("evidence_requirements.{index}.api.url"),
                "REQUIRED",
                "External API URL is required.",
            );
        }
    }

    for (index, rule) in template.claim_collection_rules.iter().enumerate() {
        let Some(rule) = rule.as_object() else {
            add(
                "claim_mappings",
                format!("claim_collection_rules.{index}"),
                "INVALID",
                "Claim rules must use the canonical object shape.",
            );
            continue;
        };
        if text(rule.get("claim_name")).trim().is_empty() {
            add(
                "claim_mappings",
                format!("claim_collection_rules.{index}.claim_name"),
                "REQUIRED",
                "Claim name is required.",
            );
        }
        let source = text(rule.get("source"));
        if !CLAIM_SOURCES.contains(&source.as_str()) {
            add(
                "claim_mappings",
                format!("claim_collection_rules.{index}.source"),
                "INVALID",
                "Select a canonical claim source.",
            );
        }
        let Some(source_config) = rule.get("source_config").and_then(Value::as_object) else {
            add(
                "claim_mappings",
                format!("claim_collection_rules.{index}.source_config"),
                "INVALID",
                "Claim source configuration must be an object.",
            );
            continue;
        };
        if source == "FORM_FIELD" && !seen_fields.contains(&text(source_config.get("field_id"))) {
            add(
                "claim_mappings",
                format!("claim_collection_rules.{index}.source_config.field_id"),
                "UNKNOWN_FIELD",
                "Claim source must reference a configured form field.",
            );
        } else if source == "SYSTEM" {
            let system_field = text(source_config.get("system_field"));
            if !SYSTEM_FIELDS.contains(&system_field.as_str()) {
                add(
                    "claim_mappings",
                    format!("claim_collection_rules.{index}.source_config.system_field"),
                    "INVALID",
                    "Select a supported system claim source.",
                );
            } else if system_field == "constant" && !source_config.contains_key("value") {
                add(
                    "claim_mappings",
                    format!("claim_collection_rules.{index}.source_config.value"),
                    "REQUIRED",
                    "Constant system claims require a value.",
                );
            }
        }
    }

    let mut seen_orders = HashSet::new();
    for (index, check) in template.required_checks.iter().enumerate() {
        let Some(check) = check.as_object() else {
            add(
                "required_checks",
                format!("required_checks.{index}.check_type"),
                "REQUIRED",
                "Check type is required.",
            );
            continue;
        };
        if text(check.get("check_type")).trim().is_empty() {
            add(
                "required_checks",
                format!("required_checks.{index}.check_type"),
                "REQUIRED",
                "Check type is required.",
            );
            continue;
        }
        let order = check.get("order").and_then(Value::as_i64);
        if order.is_none_or(|value| value < 1) {
            add(
                "required_checks",
                format!("required_checks.{index}.order"),
                "INVALID",
                "Check order must be a positive integer.",
            );
        } else if !seen_orders.insert(order.expect("positive order")) {
            add(
                "required_checks",
                format!("required_checks.{index}.order"),
                "DUPLICATE",
                "Check order values must be unique.",
            );
        }
    }

    if template.approval_strategy == "RULES_BASED" {
        if template.approval_policy_set_id.is_none() {
            add(
                "approval",
                "approval_policy_set_id".to_owned(),
                "REQUIRED",
                "Rules-based approval requires an approval Policy Set.",
            );
        } else {
            match approval_policy {
                ApprovalPolicyValidationState::NotRequested
                | ApprovalPolicyValidationState::NotFound => add(
                    "approval",
                    "approval_policy_set_id".to_owned(),
                    "NOT_FOUND",
                    "Approval Policy Set was not found.",
                ),
                ApprovalPolicyValidationState::Found(policy) => {
                    if !policy.policy_type.eq_ignore_ascii_case("APPROVAL_RULES") {
                        add(
                            "approval",
                            "approval_policy_set_id".to_owned(),
                            "WRONG_TYPE",
                            "Policy Set must have type APPROVAL_RULES.",
                        );
                    } else if !policy.status.eq_ignore_ascii_case("ACTIVE") {
                        add(
                            "approval",
                            "approval_policy_set_id".to_owned(),
                            "NOT_ACTIVE",
                            "Approval Policy Set must be active.",
                        );
                    }
                }
            }
        }
    }
    if !(1..=3650).contains(&template.application_validity_days) {
        add(
            "validity",
            "application_validity_days".to_owned(),
            "OUT_OF_RANGE",
            "Validity must be between 1 and 3650 days.",
        );
    }
    errors
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ApplicationTemplateRequestError {
    #[error("invalid Application Template field: {0}")]
    InvalidField(String),
    #[error("unknown Application Template field: {0}")]
    UnknownField(String),
    #[error("Only draft Application Templates can be edited")]
    NotDraft,
    #[error("Application Template version is exhausted")]
    VersionExhausted,
    #[error("Application Template could not be projected")]
    Projection,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ApplicationTemplateLifecycleError {
    #[error("Only draft Application Templates can be edited")]
    PatchRequiresDraft,
    #[error("Only draft Application Templates can be activated")]
    ActivateRequiresDraft,
    #[error("Application Template validation failed")]
    ValidationFailed,
    #[error("Only active Application Templates can be deprecated")]
    DeprecateRequiresActive,
    #[error("Only draft Application Templates can be deleted")]
    DeleteRequiresDraft,
    #[error("Application Template version is exhausted")]
    VersionExhausted,
}

fn default_true() -> bool {
    true
}

fn default_approval_strategy() -> String {
    "MANUAL".to_owned()
}

fn default_validity_days() -> i64 {
    30
}

fn require_length(
    field: &str,
    value: &str,
    minimum: usize,
    maximum: usize,
) -> Result<(), ApplicationTemplateRequestError> {
    let length = value.chars().count();
    if !(minimum..=maximum).contains(&length) {
        return Err(ApplicationTemplateRequestError::InvalidField(
            field.to_owned(),
        ));
    }
    Ok(())
}

fn values<T: Serialize>(values: Vec<T>) -> Result<Vec<Value>, ApplicationTemplateRequestError> {
    values
        .into_iter()
        .map(|value| {
            serde_json::to_value(value).map_err(|_| ApplicationTemplateRequestError::Projection)
        })
        .collect()
}

fn required_string(field: &str, value: Value) -> Result<String, ApplicationTemplateRequestError> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| ApplicationTemplateRequestError::InvalidField(field.to_owned()))
}

fn nullable_string(
    field: &str,
    value: Value,
) -> Result<Option<String>, ApplicationTemplateRequestError> {
    if value.is_null() {
        Ok(None)
    } else {
        required_string(field, value).map(Some)
    }
}

fn required_object(
    field: &str,
    value: Value,
) -> Result<Map<String, Value>, ApplicationTemplateRequestError> {
    value
        .as_object()
        .cloned()
        .ok_or_else(|| ApplicationTemplateRequestError::InvalidField(field.to_owned()))
}

fn typed_array<T>(field: &str, value: Value) -> Result<Vec<T>, ApplicationTemplateRequestError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(value)
        .map_err(|_| ApplicationTemplateRequestError::InvalidField(field.to_owned()))
}

fn validate_changed_arrays(
    form_fields: Option<&Vec<ApplicationFormField>>,
    evidence_requirements: Option<&Vec<ApplicationEvidenceRequirement>>,
    claim_collection_rules: Option<&Vec<ClaimCollectionRule>>,
    required_checks: Option<&Vec<RequiredApplicationCheck>>,
) -> Result<(), ApplicationTemplateRequestError> {
    ApplicationTemplateCreate {
        organization_id: "validation-probe".to_owned(),
        name: "validation probe".to_owned(),
        description: None,
        credential_template_id: None,
        form_fields: form_fields.cloned().unwrap_or_default(),
        evidence_requirements: evidence_requirements.cloned().unwrap_or_default(),
        claim_collection_rules: claim_collection_rules.cloned().unwrap_or_default(),
        required_checks: required_checks.cloned().unwrap_or_default(),
        approval_strategy: default_approval_strategy(),
        approval_policy_set_id: None,
        application_validity_days: default_validity_days(),
        ui_config: Map::new(),
        notification_config: Map::new(),
    }
    .validate_transport()
}

fn text(value: Option<&Value>) -> String {
    value.and_then(Value::as_str).unwrap_or_default().to_owned()
}

fn numeric(value: Option<&Value>) -> Option<f64> {
    value.and_then(Value::as_f64)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 19, 12, 0, 0)
            .single()
            .expect("fixed timestamp")
    }

    fn canonical_request() -> ApplicationTemplateCreate {
        serde_json::from_value(json!({
            "organization_id": "org-123",
            "name": "Membership application",
            "credential_template_id": "credential-template-1",
            "form_fields": [{
                "field_id": "clearance_status",
                "label": "Clearance status",
                "field_type": "SELECT",
                "required": true,
                "claim_mapping": "clearance_status",
                "options": ["PENDING", {"label": "Cleared", "value": "CLEARED"}]
            }],
            "required_checks": [{
                "check_type": "EMAIL_VERIFICATION",
                "is_required": true,
                "order": 1
            }]
        }))
        .expect("canonical request")
    }

    #[test]
    fn create_defaults_and_projection_match_the_frozen_contract() {
        let request = canonical_request();
        request.validate_transport().expect("valid request");
        let record = request
            .into_record("template-1".to_owned(), now())
            .expect("record");
        assert_eq!(record.status, ApplicationTemplateStatus::Draft);
        assert_eq!(record.approval_strategy, "MANUAL");
        assert_eq!(record.application_validity_days, 30);
        assert_eq!(record.version, 1);
        assert_eq!(
            record.form_fields[0]["options"],
            json!(["PENDING", {"label": "Cleared", "value": "CLEARED"}])
        );
    }

    #[test]
    fn transport_rejects_removed_aliases_and_invalid_public_shapes() {
        let mut value = serde_json::to_value(canonical_request()).expect("request JSON");
        value["status"] = json!("ACTIVE");
        assert!(serde_json::from_value::<ApplicationTemplateCreate>(value).is_err());

        let mut value = serde_json::to_value(canonical_request()).expect("request JSON");
        value["form_fields"][0]["options"] =
            json!([{"label": "Cleared", "value": "CLEARED", "secret": "no"}]);
        assert!(serde_json::from_value::<ApplicationTemplateCreate>(value).is_err());

        let mut value = serde_json::to_value(canonical_request()).expect("request JSON");
        value["evidence_requirements"] = json!([{
            "evidence_id": "membership",
            "evidence_type": "EXTERNAL_FACT",
            "description": "Membership",
            "required": true,
            "auto_approve_on_evidence": true
        }]);
        assert!(serde_json::from_value::<ApplicationTemplateCreate>(value).is_err());
    }

    #[test]
    fn validation_errors_match_frozen_order_and_taxonomy() {
        let mut request = canonical_request();
        request.credential_template_id = None;
        request.form_fields.clear();
        request.approval_strategy = "RULES_BASED".to_owned();
        request.approval_policy_set_id = None;
        let record = request
            .into_record("template-1".to_owned(), now())
            .expect("record");
        assert_eq!(
            validate_application_template(
                &record,
                &CredentialTemplateValidationState::MissingReference,
                &ApprovalPolicyValidationState::NotRequested,
            ),
            vec![
                ApplicationTemplateValidationError {
                    section: "credential_template".to_owned(),
                    field: "credential_template_id".to_owned(),
                    code: "REQUIRED".to_owned(),
                    message: "Select a Credential Template.".to_owned(),
                },
                ApplicationTemplateValidationError {
                    section: "form_fields".to_owned(),
                    field: "form_fields".to_owned(),
                    code: "REQUIRED".to_owned(),
                    message: "Add at least one form field.".to_owned(),
                },
                ApplicationTemplateValidationError {
                    section: "approval".to_owned(),
                    field: "approval_policy_set_id".to_owned(),
                    code: "REQUIRED".to_owned(),
                    message: "Rules-based approval requires an approval Policy Set.".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn lifecycle_is_explicit_and_versioned() {
        let mut record = canonical_request()
            .into_record("template-1".to_owned(), now())
            .expect("record");
        let later = now() + chrono::Duration::seconds(1);
        record.activate(&[], later).expect("activate");
        assert_eq!(record.status, ApplicationTemplateStatus::Active);
        assert_eq!(record.version, 2);
        assert_eq!(
            record.require_draft_patch(),
            Err(ApplicationTemplateLifecycleError::PatchRequiresDraft)
        );
        record
            .deprecate(later + chrono::Duration::seconds(1))
            .expect("deprecate");
        assert_eq!(record.status, ApplicationTemplateStatus::Deprecated);
        assert_eq!(record.version, 3);
    }
}
