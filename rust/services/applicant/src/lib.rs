use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, NaiveDate, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use uuid::Uuid;

pub mod http;
pub mod issuance;
pub mod migration;
pub mod providers;
pub mod service;
pub mod store;

pub const MAX_EVIDENCE_BYTES: usize = 10 * 1024 * 1024;
pub const LOCK_TTL_SECONDS: i64 = 300;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecycleStatus {
    #[default]
    Draft,
    Submitted,
    UnderReview,
    PendingInformation,
    Approved,
    Offered,
    Rejected,
    Withdrawn,
    Credentialed,
    Suspended,
}

impl LifecycleStatus {
    pub fn from_released(value: &str) -> Result<Self, ApplicantError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "draft" => Ok(Self::Draft),
            "pending" | "submitted" => Ok(Self::Submitted),
            "in_review" | "under_review" => Ok(Self::UnderReview),
            "needs_info" | "pending_information" => Ok(Self::PendingInformation),
            "approved" => Ok(Self::Approved),
            "offered" => Ok(Self::Offered),
            "rejected" => Ok(Self::Rejected),
            "withdrawn" => Ok(Self::Withdrawn),
            "issued" | "credentialed" => Ok(Self::Credentialed),
            "revoked" | "suspended" => Ok(Self::Suspended),
            _ => Err(ApplicantError::InvalidStatus(value.to_owned())),
        }
    }

    pub fn transition(self, target: Self) -> Result<Self, ApplicantError> {
        if self == target {
            return Ok(target);
        }
        let allowed = match self {
            Self::Draft => matches!(target, Self::Submitted | Self::Withdrawn),
            Self::Submitted => matches!(
                target,
                Self::UnderReview
                    | Self::Approved
                    | Self::Rejected
                    | Self::PendingInformation
                    | Self::Withdrawn
                    | Self::Suspended
            ),
            Self::UnderReview => matches!(
                target,
                Self::Approved | Self::Rejected | Self::PendingInformation | Self::Suspended
            ),
            Self::PendingInformation => matches!(
                target,
                Self::Submitted
                    | Self::UnderReview
                    | Self::Approved
                    | Self::Rejected
                    | Self::Withdrawn
                    | Self::Suspended
            ),
            Self::Approved => {
                matches!(target, Self::Offered | Self::Credentialed | Self::Suspended)
            }
            Self::Offered => matches!(target, Self::Credentialed | Self::Suspended),
            Self::Rejected | Self::Withdrawn | Self::Credentialed | Self::Suspended => false,
        };
        allowed
            .then_some(target)
            .ok_or(ApplicantError::InvalidTransition {
                current: self,
                target,
            })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimState {
    #[default]
    NotReady,
    Blocked,
    OfferReady,
    Claimed,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceStatus {
    Active,
    Revoked,
    Expired,
    Deleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    NotStarted,
    Pending,
    InProgress,
    Passed,
    Failed,
    RequiresManualReview,
    CompletedPassed,
    CompletedFailed,
    CompletedConditional,
    Expired,
    Waived,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckType {
    CriminalHistory,
    EmploymentVerification,
    IdentityVerification,
    SecurityClearance,
    AviationExperience,
    SanctionsScreening,
    WatchlistCheck,
    ReferenceCheck,
    EducationVerification,
    AddressVerification,
    BiometricEnrollment,
    DocumentVerification,
    FinancialCheck,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Applicant {
    pub id: String,
    pub organization_id: String,
    #[serde(default)]
    pub flow_id: String,
    pub email: String,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub family_name: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub oidc_subject: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub external_id: Option<String>,
    #[serde(default)]
    pub credential_template_id: Option<String>,
    #[serde(default)]
    pub status: LifecycleStatus,
    #[serde(default)]
    pub vetting_data: Value,
    #[serde(default)]
    pub verification_results: Vec<Value>,
    #[serde(default)]
    pub reviewer_notes: Option<String>,
    #[serde(default)]
    pub rejection_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Applicant {
    pub fn new(organization_id: String, email: String, now: DateTime<Utc>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            organization_id,
            flow_id: String::new(),
            email,
            given_name: None,
            family_name: None,
            phone: None,
            oidc_subject: None,
            user_id: None,
            external_id: None,
            credential_template_id: None,
            status: LifecycleStatus::Draft,
            vetting_data: Value::Object(Map::new()),
            verification_results: Vec::new(),
            reviewer_notes: None,
            rejection_reason: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn set_status(
        &mut self,
        target: LifecycleStatus,
        now: DateTime<Utc>,
    ) -> Result<(), ApplicantError> {
        self.status = self.status.transition(target)?;
        self.updated_at = now;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Application {
    pub id: String,
    pub applicant_id: String,
    pub organization_id: String,
    #[serde(default)]
    pub reference_number: Option<String>,
    pub application_template_id: String,
    pub credential_template_id: String,
    #[serde(default)]
    pub status: LifecycleStatus,
    #[serde(default)]
    pub form_data: Map<String, Value>,
    #[serde(default)]
    pub integration_context: Map<String, Value>,
    #[serde(default)]
    pub system_data: Map<String, Value>,
    #[serde(default)]
    pub required_checks: Vec<Value>,
    #[serde(default)]
    pub evidence_requirements: Vec<Value>,
    #[serde(default)]
    pub claim_state: ClaimState,
    #[serde(default)]
    pub claim_blocker: Option<Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub submitted_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub reviewed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub issued_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Biometric {
    pub id: String,
    pub applicant_id: String,
    pub biometric_type: String,
    pub template_data_base64: String,
    #[serde(default)]
    pub image_data_base64: Option<String>,
    pub is_live_capture: bool,
    #[serde(default)]
    pub capture_device_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VettingCheck {
    pub id: String,
    pub application_id: String,
    pub check_type: CheckType,
    #[serde(default)]
    pub custom_name: Option<String>,
    pub is_required: bool,
    pub order: i32,
    pub status: CheckStatus,
    #[serde(default)]
    pub config: Map<String, Value>,
    #[serde(default)]
    pub result: Map<String, Value>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub performed_by: Option<String>,
    #[serde(default)]
    pub external_provider: Option<String>,
    #[serde(default)]
    pub webhook_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub completed_at: Option<DateTime<Utc>>,
}

impl VettingCheck {
    pub fn start(&mut self, now: DateTime<Utc>) {
        self.status = CheckStatus::InProgress;
        self.started_at = Some(now);
        self.updated_at = now;
    }

    pub fn complete(
        &mut self,
        passed: bool,
        notes: Option<String>,
        performed_by: Option<String>,
        mut result: Map<String, Value>,
        evidence_submission_ids: Vec<String>,
        now: DateTime<Utc>,
    ) {
        let unique: BTreeSet<_> = evidence_submission_ids.into_iter().collect();
        result.insert(
            "evidence_submission_ids".into(),
            Value::Array(unique.into_iter().map(Value::String).collect()),
        );
        self.status = if passed {
            CheckStatus::CompletedPassed
        } else {
            CheckStatus::CompletedFailed
        };
        self.notes = notes;
        self.performed_by = performed_by;
        self.result = result;
        self.completed_at = Some(now);
        self.updated_at = now;
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub application_id: String,
    pub applicant_id: String,
    pub organization_id: String,
    pub evidence_requirement_id: String,
    pub evidence_type: String,
    pub source: String,
    pub media_type: String,
    pub filename: String,
    #[serde(rename = "content_base64", with = "base64_bytes")]
    pub content: Vec<u8>,
    pub size_bytes: usize,
    pub sha256: String,
    pub status: EvidenceStatus,
    pub submitted_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub captured_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub revocation_reason: Option<String>,
}

impl Evidence {
    pub fn from_upload(
        input: EvidenceUpload,
        maximum: usize,
        now: DateTime<Utc>,
    ) -> Result<Self, ApplicantError> {
        let maximum = maximum.min(MAX_EVIDENCE_BYTES);
        let content = STANDARD
            .decode(input.content_base64.as_bytes())
            .map_err(|_| ApplicantError::MalformedEvidence)?;
        if content.is_empty() || content.len() > maximum {
            return Err(ApplicantError::EvidenceSize { maximum });
        }
        let filename = safe_filename(&input.filename)?;
        let sha256 = hex_digest(&content);
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            application_id: input.application_id,
            applicant_id: input.applicant_id,
            organization_id: input.organization_id,
            evidence_requirement_id: input.evidence_requirement_id,
            evidence_type: input.evidence_type,
            source: "APPLICANT_UPLOAD".into(),
            media_type: input.media_type,
            filename,
            size_bytes: content.len(),
            content,
            sha256,
            status: EvidenceStatus::Active,
            submitted_by: input.submitted_by,
            created_at: now,
            updated_at: now,
            captured_at: input.captured_at,
            expires_at: input.expires_at,
            revoked_at: None,
            revocation_reason: None,
        })
    }

    pub fn refresh_expiry(&mut self, now: DateTime<Utc>) {
        if self.status == EvidenceStatus::Active
            && self.expires_at.is_some_and(|expiry| expiry <= now)
        {
            self.status = EvidenceStatus::Expired;
            self.updated_at = now;
        }
    }
}

#[derive(Debug, Clone)]
pub struct EvidenceUpload {
    pub application_id: String,
    pub applicant_id: String,
    pub organization_id: String,
    pub evidence_requirement_id: String,
    pub evidence_type: String,
    pub media_type: String,
    pub filename: String,
    pub content_base64: String,
    pub submitted_by: String,
    pub captured_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewerLock {
    pub id: String,
    pub application_id: String,
    pub reviewer_id: String,
    pub reviewer_name: String,
    pub acquired_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Default)]
pub struct ReviewerLocks(BTreeMap<String, ReviewerLock>);

impl ReviewerLocks {
    pub fn acquire(
        &mut self,
        application_id: &str,
        reviewer_id: &str,
        reviewer_name: &str,
        now: DateTime<Utc>,
    ) -> Result<&ReviewerLock, ApplicantError> {
        if let Some(current) = self.0.get(application_id) {
            if current.expires_at > now && current.reviewer_id != reviewer_id {
                return Err(ApplicantError::Locked(current.clone()));
            }
        }
        let lock = ReviewerLock {
            id: Uuid::new_v4().to_string(),
            application_id: application_id.to_owned(),
            reviewer_id: reviewer_id.to_owned(),
            reviewer_name: reviewer_name.to_owned(),
            acquired_at: now,
            expires_at: now + chrono::Duration::seconds(LOCK_TTL_SECONDS),
        };
        self.0.insert(application_id.to_owned(), lock);
        Ok(self.0.get(application_id).expect("inserted reviewer lock"))
    }

    pub fn release(&mut self, application_id: &str, reviewer_id: &str, now: DateTime<Utc>) -> bool {
        let removable = self
            .0
            .get(application_id)
            .is_some_and(|lock| lock.reviewer_id == reviewer_id || lock.expires_at <= now);
        if removable {
            self.0.remove(application_id);
        }
        removable
    }

    pub fn held_by(&self, application_id: &str, reviewer_id: &str, now: DateTime<Utc>) -> bool {
        self.0
            .get(application_id)
            .is_some_and(|lock| lock.expires_at > now && lock.reviewer_id == reviewer_id)
    }

    pub fn active(&self, application_id: &str, now: DateTime<Utc>) -> Option<&ReviewerLock> {
        self.0
            .get(application_id)
            .filter(|lock| lock.expires_at > now)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct FieldDefinition {
    pub field_id: String,
    #[serde(default)]
    pub field_type: Option<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub options: Vec<Value>,
    #[serde(default)]
    pub validation_pattern: Option<String>,
    #[serde(default)]
    pub minimum: Option<f64>,
    #[serde(default)]
    pub maximum: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldError {
    pub field: String,
    pub code: &'static str,
    pub message: String,
}

pub fn validate_form_data(
    form: &Map<String, Value>,
    fields: &[FieldDefinition],
) -> Result<(), ApplicantError> {
    let mut errors = Vec::new();
    let allowed: BTreeSet<_> = fields.iter().map(|field| field.field_id.as_str()).collect();
    for field in fields {
        let value = form.get(&field.field_id);
        if field.required && value.is_none_or(empty_value) {
            errors.push(field_error(
                &field.field_id,
                "REQUIRED",
                "This field is required.",
            ));
            continue;
        }
        let Some(value) = value.filter(|value| !empty_value(value)) else {
            continue;
        };
        let kind = field
            .field_type
            .as_deref()
            .unwrap_or("text")
            .to_ascii_lowercase();
        match kind.as_str() {
            "date"
                if value
                    .as_str()
                    .and_then(|v| NaiveDate::parse_from_str(v, "%Y-%m-%d").ok())
                    .is_none() =>
            {
                errors.push(field_error(
                    &field.field_id,
                    "INVALID_DATE",
                    "Use an ISO date in YYYY-MM-DD format.",
                ))
            }
            "datetime" | "datetime-local"
                if value
                    .as_str()
                    .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
                    .is_none() =>
            {
                errors.push(field_error(
                    &field.field_id,
                    "INVALID_DATETIME",
                    "Use a valid ISO 8601 date-time.",
                ))
            }
            "integer" | "int" if value.as_i64().is_none() && value.as_u64().is_none() => errors
                .push(field_error(
                    &field.field_id,
                    "INVALID_INTEGER",
                    "Enter a whole number.",
                )),
            "number" | "float" | "decimal" if !value.is_number() => errors.push(field_error(
                &field.field_id,
                "INVALID_NUMBER",
                "Enter a number.",
            )),
            "boolean" | "bool" if !value.is_boolean() => errors.push(field_error(
                &field.field_id,
                "INVALID_BOOLEAN",
                "Choose true or false.",
            )),
            _ => {}
        }
        if !field.options.is_empty()
            && !field
                .options
                .iter()
                .any(|option| option.get("value").unwrap_or(option) == value)
        {
            errors.push(field_error(
                &field.field_id,
                "INVALID_CHOICE",
                "Choose one of the allowed values.",
            ));
        }
        if let (Some(pattern), Some(value)) = (&field.validation_pattern, value.as_str()) {
            match Regex::new(pattern) {
                Ok(regex) if !regex.is_match(value) => errors.push(field_error(
                    &field.field_id,
                    "PATTERN_MISMATCH",
                    "Value does not match the required format.",
                )),
                Err(_) => errors.push(field_error(
                    &field.field_id,
                    "INVALID_FIELD_CONFIGURATION",
                    "Field validation pattern is invalid.",
                )),
                _ => {}
            }
        }
        if let Some(number) = value.as_f64() {
            if field.minimum.is_some_and(|minimum| number < minimum) {
                errors.push(field_error(
                    &field.field_id,
                    "BELOW_MINIMUM",
                    "Value is below the configured minimum.",
                ));
            }
            if field.maximum.is_some_and(|maximum| number > maximum) {
                errors.push(field_error(
                    &field.field_id,
                    "ABOVE_MAXIMUM",
                    "Value is above the configured maximum.",
                ));
            }
        }
    }
    for name in form.keys().filter(|name| !allowed.contains(name.as_str())) {
        errors.push(field_error(
            name,
            "UNKNOWN_FIELD",
            "This field is not defined by the Application Template.",
        ));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(ApplicantError::FieldValidation(errors))
    }
}

fn empty_value(value: &Value) -> bool {
    value.is_null() || value.as_str() == Some("") || value.as_array().is_some_and(Vec::is_empty)
}
fn field_error(field: &str, code: &'static str, message: &str) -> FieldError {
    FieldError {
        field: field.to_owned(),
        code,
        message: message.to_owned(),
    }
}
fn safe_filename(value: &str) -> Result<String, ApplicantError> {
    let name = value.rsplit(['/', '\\']).next().unwrap_or_default().trim();
    if name.is_empty() || name == "." || name == ".." || name.chars().any(char::is_control) {
        return Err(ApplicantError::UnsafeFilename);
    }
    Ok(name.to_owned())
}
fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

mod base64_bytes {
    use super::*;
    pub fn serialize<S: serde::Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(value))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let value = String::deserialize(deserializer)?;
        STANDARD.decode(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Error)]
pub enum ApplicantError {
    #[error("invalid applicant status: {0}")]
    InvalidStatus(String),
    #[error("invalid lifecycle transition: {current:?} -> {target:?}")]
    InvalidTransition {
        current: LifecycleStatus,
        target: LifecycleStatus,
    },
    #[error("application data failed validation")]
    FieldValidation(Vec<FieldError>),
    #[error("evidence content is malformed")]
    MalformedEvidence,
    #[error("evidence exceeds the {maximum}-byte limit")]
    EvidenceSize { maximum: usize },
    #[error("evidence filename is unsafe")]
    UnsafeFilename,
    #[error("application is locked by another reviewer")]
    Locked(ReviewerLock),
}
