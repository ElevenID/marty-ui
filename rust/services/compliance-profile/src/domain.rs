use chrono::{DateTime, Utc};
use marty_credential_template::CredentialFormat;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComplianceStatus {
    #[default]
    Draft,
    Active,
    Suspended,
    Deprecated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IssuanceProtocol {
    Oid4vciPreAuth,
    Oid4vciAuthCode,
    Direct,
    CredentialManager,
    AppleWallet,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum RetentionPeriod {
    #[serde(rename = "none")]
    None,
    #[default]
    #[serde(rename = "session")]
    Session,
    #[serde(rename = "1_day")]
    Day,
    #[serde(rename = "1_week")]
    Week,
    #[serde(rename = "1_month")]
    Month,
    #[serde(rename = "1_year")]
    Year,
    #[serde(rename = "3_years")]
    Years3,
    #[serde(rename = "7_years")]
    Years7,
    #[serde(rename = "indefinite")]
    Indefinite,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentType {
    #[default]
    Explicit,
    Implicit,
    OptOut,
    None,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditLevel {
    None,
    Minimal,
    #[default]
    Standard,
    Detailed,
    Forensic,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DataRetentionPolicy {
    pub retention_period: RetentionPeriod,
    pub retain_metadata_only: bool,
    pub anonymize_after_days: Option<i32>,
    pub deletion_confirmation_required: bool,
    pub backup_retention_days: Option<i32>,
}
impl Default for DataRetentionPolicy {
    fn default() -> Self {
        Self {
            retention_period: RetentionPeriod::Session,
            retain_metadata_only: false,
            anonymize_after_days: None,
            deletion_confirmation_required: false,
            backup_retention_days: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConsentRequirement {
    pub consent_type: ConsentType,
    pub consent_text: String,
    pub consent_version: String,
    pub require_re_consent_days: Option<i32>,
    pub allow_partial_consent: bool,
    pub track_consent_history: bool,
}
impl Default for ConsentRequirement {
    fn default() -> Self {
        Self {
            consent_type: ConsentType::Explicit,
            consent_text: String::new(),
            consent_version: "1.0".into(),
            require_re_consent_days: None,
            allow_partial_consent: false,
            track_consent_history: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfiguration {
    pub audit_level: AuditLevel,
    pub log_credential_access: bool,
    pub log_verification_results: bool,
    pub log_consent_changes: bool,
    pub log_data_exports: bool,
    pub tamper_evident: bool,
    pub retention_days: i32,
}
impl Default for AuditConfiguration {
    fn default() -> Self {
        Self {
            audit_level: AuditLevel::Standard,
            log_credential_access: true,
            log_verification_results: true,
            log_consent_changes: true,
            log_data_exports: true,
            tamper_evident: true,
            retention_days: 365,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DataMinimizationRule {
    #[serde(default = "new_id")]
    pub id: String,
    pub description: String,
    #[serde(default)]
    pub applies_to_claims: Vec<String>,
    #[serde(default = "redact")]
    pub action: String,
    #[serde(default)]
    pub parameters: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JurisdictionalConstraint {
    #[serde(default = "new_id")]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub allowed_countries: Vec<String>,
    #[serde(default)]
    pub blocked_countries: Vec<String>,
    #[serde(default)]
    pub data_residency_required: bool,
    #[serde(default)]
    pub allowed_data_regions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgeVerificationRule {
    pub enabled: bool,
    pub minimum_age: i32,
    pub verification_method: String,
    pub allow_credential_expiry_check: bool,
}
impl Default for AgeVerificationRule {
    fn default() -> Self {
        Self {
            enabled: false,
            minimum_age: 18,
            verification_method: "derived".into(),
            allow_credential_expiry_check: true,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct IssuerArtifactRequirements {
    pub requires_x509_cert: bool,
    pub requires_did: bool,
    pub requires_jwk: bool,
    pub cert_key_usage: Vec<String>,
    pub recommended_algorithms: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrustProfileConstraints {
    pub compatible_profile_types: Vec<String>,
    pub required_source_types: Vec<String>,
    pub required_formats: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiSurfaceEndpoint {
    pub rel: String,
    pub path_template: String,
    #[serde(default = "get_method")]
    pub method: String,
    #[serde(default = "yes")]
    pub auth_required: bool,
    #[serde(default)]
    pub org_scoped_path: Option<String>,
    #[serde(default)]
    pub response_schema_ref: Option<String>,
    #[serde(default)]
    pub standard_ref: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ComplianceProfile {
    pub id: String,
    pub organization_id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub status: ComplianceStatus,
    pub compliance_code: Option<String>,
    pub credential_format: CredentialFormat,
    pub issuance_protocol: Option<IssuanceProtocol>,
    pub issuer_artifact_requirements: Option<IssuerArtifactRequirements>,
    pub verification_policy_set_id: Option<String>,
    pub trust_profile_constraints: TrustProfileConstraints,
    pub api_surface: Vec<ApiSurfaceEndpoint>,
    pub discoverable: bool,
    pub is_system: bool,
    pub frameworks: Vec<String>,
    pub data_retention: DataRetentionPolicy,
    pub consent_requirement: ConsentRequirement,
    pub audit_configuration: AuditConfiguration,
    pub data_minimization_rules: Vec<DataMinimizationRule>,
    pub jurisdictional_constraints: Vec<JurisdictionalConstraint>,
    pub age_verification: AgeVerificationRule,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateComplianceProfileRequest {
    #[serde(default)]
    pub organization_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub compliance_code: Option<String>,
    #[serde(default = "default_format")]
    pub credential_format: String,
    #[serde(default)]
    pub issuance_protocol: Option<IssuanceProtocol>,
    #[serde(default)]
    pub issuer_artifact_requirements: Option<IssuerArtifactRequirements>,
    #[serde(default)]
    pub verification_policy_set_id: Option<String>,
    #[serde(default)]
    pub trust_profile_constraints: Option<TrustProfileConstraints>,
    #[serde(default)]
    pub api_surface: Vec<ApiSurfaceEndpoint>,
    #[serde(default = "yes")]
    pub discoverable: bool,
    #[serde(default)]
    pub is_system: bool,
    #[serde(default)]
    pub system_profile: Option<bool>,
    #[serde(default)]
    pub frameworks: Vec<String>,
    #[serde(default)]
    pub data_retention: Option<DataRetentionPolicy>,
    #[serde(default)]
    pub consent_requirement: Option<ConsentRequirement>,
    #[serde(default)]
    pub audit_configuration: Option<AuditConfiguration>,
    #[serde(default)]
    pub data_minimization_rules: Vec<DataMinimizationRule>,
    #[serde(default)]
    pub jurisdictional_constraints: Vec<JurisdictionalConstraint>,
    #[serde(default)]
    pub age_verification: Option<AgeVerificationRule>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateComplianceProfileRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub compliance_code: Option<String>,
    pub credential_format: Option<String>,
    pub issuance_protocol: Option<IssuanceProtocol>,
    pub issuer_artifact_requirements: Option<IssuerArtifactRequirements>,
    pub verification_policy_set_id: Option<String>,
    pub trust_profile_constraints: Option<TrustProfileConstraints>,
    pub api_surface: Option<Vec<ApiSurfaceEndpoint>>,
    pub discoverable: Option<bool>,
    pub is_system: Option<bool>,
    pub frameworks: Option<Vec<String>>,
    pub data_retention: Option<DataRetentionPolicy>,
    pub consent_requirement: Option<ConsentRequirement>,
    pub audit_configuration: Option<AuditConfiguration>,
    pub data_minimization_rules: Option<Vec<DataMinimizationRule>>,
    pub jurisdictional_constraints: Option<Vec<JurisdictionalConstraint>>,
    pub age_verification: Option<AgeVerificationRule>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ComplianceProfileResponse {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance_code: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub credential_format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuance_protocol: Option<IssuanceProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_artifact_requirements: Option<IssuerArtifactRequirements>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_policy_set_id: Option<String>,
    pub trust_profile_constraints: TrustProfileConstraints,
    pub api_surface: Vec<ApiSurfaceEndpoint>,
    pub discoverable: bool,
    pub status: ComplianceStatus,
    pub is_system: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ComplianceError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Dependency(String),
    #[error("{0}")]
    Persistence(String),
}

impl ComplianceProfile {
    pub fn new(
        request: CreateComplianceProfileRequest,
        now: DateTime<Utc>,
    ) -> Result<Self, ComplianceError> {
        validate_name(&request.name)?;
        let system = request.system_profile.unwrap_or(request.is_system);
        if system {
            return Err(ComplianceError::Forbidden(
                "System compliance profiles are migration-owned".into(),
            ));
        }
        let organization_id = request
            .organization_id
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| {
                ComplianceError::BadRequest(
                    "organization_id is required for non-system compliance profiles".into(),
                )
            })?;
        let credential_format = CredentialFormat::parse(&request.credential_format)
            .map_err(|_| ComplianceError::BadRequest("credential_format is invalid".into()))?;
        let profile = Self {
            id: new_id(),
            organization_id: Some(organization_id),
            name: request.name,
            description: request.description,
            status: ComplianceStatus::Draft,
            compliance_code: request.compliance_code,
            credential_format,
            issuance_protocol: request.issuance_protocol,
            issuer_artifact_requirements: request.issuer_artifact_requirements,
            verification_policy_set_id: request.verification_policy_set_id,
            trust_profile_constraints: request.trust_profile_constraints.unwrap_or_default(),
            api_surface: request.api_surface,
            discoverable: request.discoverable,
            is_system: false,
            frameworks: request.frameworks,
            data_retention: request.data_retention.unwrap_or_default(),
            consent_requirement: request.consent_requirement.unwrap_or_default(),
            audit_configuration: request.audit_configuration.unwrap_or_default(),
            data_minimization_rules: request.data_minimization_rules,
            jurisdictional_constraints: request.jurisdictional_constraints,
            age_verification: request.age_verification.unwrap_or_default(),
            created_at: now,
            updated_at: now,
        };
        profile.validate()?;
        Ok(profile)
    }
    pub fn apply(
        &mut self,
        r: UpdateComplianceProfileRequest,
        now: DateTime<Utc>,
    ) -> Result<(), ComplianceError> {
        if self.is_system {
            return Err(ComplianceError::Forbidden(
                "System compliance profiles are immutable".into(),
            ));
        }
        if r.is_system == Some(true) {
            return Err(ComplianceError::Forbidden(
                "System compliance profiles are migration-owned".into(),
            ));
        }
        if let Some(v) = r.name {
            validate_name(&v)?;
            self.name = v;
        }
        if let Some(v) = r.description {
            self.description = Some(v);
        }
        if let Some(v) = r.compliance_code {
            self.compliance_code = Some(v);
        }
        if let Some(v) = r.credential_format {
            self.credential_format = CredentialFormat::parse(&v)
                .map_err(|_| ComplianceError::BadRequest("credential_format is invalid".into()))?;
        }
        if let Some(v) = r.issuance_protocol {
            self.issuance_protocol = Some(v);
        }
        if let Some(v) = r.issuer_artifact_requirements {
            self.issuer_artifact_requirements = Some(v);
        }
        if let Some(v) = r.verification_policy_set_id {
            self.verification_policy_set_id = Some(v);
        }
        if let Some(v) = r.trust_profile_constraints {
            self.trust_profile_constraints = v;
        }
        if let Some(v) = r.api_surface {
            self.api_surface = v;
        }
        if let Some(v) = r.discoverable {
            self.discoverable = v;
        }
        if let Some(v) = r.frameworks {
            self.frameworks = v;
        }
        if let Some(v) = r.data_retention {
            self.data_retention = v;
        }
        if let Some(v) = r.consent_requirement {
            self.consent_requirement = v;
        }
        if let Some(v) = r.audit_configuration {
            self.audit_configuration = v;
        }
        if let Some(v) = r.data_minimization_rules {
            self.data_minimization_rules = v;
        }
        if let Some(v) = r.jurisdictional_constraints {
            self.jurisdictional_constraints = v;
        }
        if let Some(v) = r.age_verification {
            self.age_verification = v;
        }
        self.updated_at = now;
        self.validate()
    }
    pub fn response(&self) -> ComplianceProfileResponse {
        ComplianceProfileResponse {
            id: self.id.clone(),
            organization_id: self.organization_id.clone(),
            compliance_code: self.compliance_code.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
            credential_format: self.credential_format.canonical().into(),
            issuance_protocol: self.issuance_protocol,
            issuer_artifact_requirements: self.issuer_artifact_requirements.clone(),
            verification_policy_set_id: self.verification_policy_set_id.clone(),
            trust_profile_constraints: self.trust_profile_constraints.clone(),
            api_surface: self.api_surface.clone(),
            discoverable: self.discoverable,
            status: self.status,
            is_system: self.is_system,
            created_at: self.created_at.to_rfc3339(),
            updated_at: self.updated_at.to_rfc3339(),
        }
    }
    fn validate(&self) -> Result<(), ComplianceError> {
        if self.description.as_ref().is_some_and(|v| v.len() > 2000) {
            return Err(ComplianceError::BadRequest("description is invalid".into()));
        }
        if self
            .data_retention
            .anonymize_after_days
            .is_some_and(|v| v < 0)
            || self
                .data_retention
                .backup_retention_days
                .is_some_and(|v| v < 0)
            || self
                .consent_requirement
                .require_re_consent_days
                .is_some_and(|v| v < 0)
            || self.audit_configuration.retention_days < 0
            || !(0..=150).contains(&self.age_verification.minimum_age)
        {
            return Err(ComplianceError::BadRequest(
                "policy duration is invalid".into(),
            ));
        }
        for rule in &self.data_minimization_rules {
            if rule.description.trim().is_empty()
                || !matches!(
                    rule.action.as_str(),
                    "redact" | "hash" | "truncate" | "generalize"
                )
            {
                return Err(ComplianceError::BadRequest(
                    "data minimization rule is invalid".into(),
                ));
            }
        }
        for c in &self.jurisdictional_constraints {
            if c.name.trim().is_empty()
                || c.allowed_countries
                    .iter()
                    .chain(&c.blocked_countries)
                    .any(|v| v.len() != 2 || !v.chars().all(|c| c.is_ascii_alphabetic()))
            {
                return Err(ComplianceError::BadRequest(
                    "jurisdictional constraint is invalid".into(),
                ));
            }
        }
        for e in &self.api_surface {
            if e.rel.trim().is_empty()
                || !e.path_template.starts_with('/')
                || !matches!(
                    e.method.as_str(),
                    "GET" | "POST" | "PUT" | "PATCH" | "DELETE"
                )
            {
                return Err(ComplianceError::BadRequest(
                    "API surface endpoint is invalid".into(),
                ));
            }
        }
        Ok(())
    }
}
fn validate_name(v: &str) -> Result<(), ComplianceError> {
    if v.trim().is_empty() || v.len() > 255 {
        Err(ComplianceError::BadRequest("name is invalid".into()))
    } else {
        Ok(())
    }
}
fn new_id() -> String {
    Uuid::new_v4().to_string()
}
fn redact() -> String {
    "redact".into()
}
fn get_method() -> String {
    "GET".into()
}
const fn yes() -> bool {
    true
}
fn default_format() -> String {
    "SD_JWT_VC".into()
}
