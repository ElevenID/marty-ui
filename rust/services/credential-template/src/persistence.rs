use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{CredentialFormat, CredentialTemplateError};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateStatus {
    Draft,
    Active,
    Deprecated,
    Archived,
}

impl TemplateStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Deprecated => "deprecated",
            Self::Archived => "archived",
        }
    }

    pub fn parse(value: &str) -> Result<Self, CredentialTemplateError> {
        match value {
            "draft" => Ok(Self::Draft),
            "active" => Ok(Self::Active),
            "deprecated" => Ok(Self::Deprecated),
            "archived" => Ok(Self::Archived),
            _ => Err(invalid("template status", value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyPosture {
    Standard,
    SelectiveDisclosure,
    ZeroKnowledge,
    Minimal,
}

impl PrivacyPosture {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::SelectiveDisclosure => "selective_disclosure",
            Self::ZeroKnowledge => "zero_knowledge",
            Self::Minimal => "minimal",
        }
    }

    pub fn parse(value: &str) -> Result<Self, CredentialTemplateError> {
        match value {
            "standard" => Ok(Self::Standard),
            "selective_disclosure" => Ok(Self::SelectiveDisclosure),
            "zero_knowledge" => Ok(Self::ZeroKnowledge),
            "minimal" => Ok(Self::Minimal),
            _ => Err(invalid("privacy posture", value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimType {
    String,
    Integer,
    Boolean,
    Date,
    Datetime,
    Object,
    Array,
    Image,
    Binary,
}

impl ClaimType {
    pub fn parse(value: &str) -> Result<Self, CredentialTemplateError> {
        match normalize_legacy_claim_type(value).as_str() {
            "string" => Ok(Self::String),
            "integer" => Ok(Self::Integer),
            "boolean" => Ok(Self::Boolean),
            "date" => Ok(Self::Date),
            "datetime" => Ok(Self::Datetime),
            "object" => Ok(Self::Object),
            "array" => Ok(Self::Array),
            "image" => Ok(Self::Image),
            "binary" => Ok(Self::Binary),
            value => Err(invalid("claim type", value)),
        }
    }
}

#[must_use]
pub fn normalize_legacy_claim_type(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "number" | "float" | "decimal" => "integer".to_owned(),
        "text" | "str" => "string".to_owned(),
        "bool" => "boolean".to_owned(),
        value => value.to_owned(),
    }
}

#[must_use]
pub fn stable_legacy_claim_id(template_id: &str, index: usize, name: &str) -> String {
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("credential-template:{template_id}:claim:{name}:{index}").as_bytes(),
    )
    .to_string()
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ClaimDefinition {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub claim_type: ClaimType,
    pub required: bool,
    pub selectively_disclosable: bool,
    pub derivable: bool,
    pub derived_from: Option<String>,
    pub pattern: Option<String>,
    pub enum_values: Option<Vec<String>>,
    pub min_value: Option<f64>,
    pub max_value: Option<f64>,
    pub mdoc_namespace: Option<String>,
    pub mdoc_element_identifier: Option<String>,
    pub display_icon: Option<String>,
}

impl ClaimDefinition {
    pub fn from_legacy_value(
        template_id: &str,
        index: usize,
        value: &Value,
    ) -> Result<Self, CredentialTemplateError> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid("claim", &format!("index {index} is not an object")))?;
        let name = optional_string(object.get("name"))
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| format!("claim_{}", index + 1));
        let raw_type = optional_string(object.get("claim_type").or_else(|| object.get("type")))
            .unwrap_or_else(|| "string".to_owned());
        Ok(Self {
            id: optional_string(object.get("id"))
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| stable_legacy_claim_id(template_id, index, &name)),
            display_name: optional_string(object.get("display_name"))
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| title_case(&name)),
            description: optional_string(object.get("description")),
            claim_type: ClaimType::parse(&raw_type)?,
            required: optional_bool(object.get("required")).unwrap_or(true),
            selectively_disclosable: optional_bool(object.get("selectively_disclosable"))
                .unwrap_or(true),
            derivable: optional_bool(object.get("derivable")).unwrap_or(false)
                || optional_string(object.get("derived_from")).is_some(),
            derived_from: optional_string(object.get("derived_from")),
            pattern: optional_string(object.get("pattern")),
            enum_values: optional_string_list(object.get("enum_values"))?,
            min_value: optional_number(object.get("min_value"))?,
            max_value: optional_number(object.get("max_value"))?,
            mdoc_namespace: optional_string(object.get("mdoc_namespace")),
            mdoc_element_identifier: optional_string(object.get("mdoc_element_identifier")),
            display_icon: optional_string(object.get("display_icon")),
            name,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default)]
pub struct DisplayStyle {
    pub background_color: String,
    pub text_color: String,
    pub logo_url: Option<String>,
    pub background_image_url: Option<String>,
    pub icon: Option<String>,
}

impl Default for DisplayStyle {
    fn default() -> Self {
        Self {
            background_color: "#1a1a2e".to_owned(),
            text_color: "#ffffff".to_owned(),
            logo_url: None,
            background_image_url: None,
            icon: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct ValidityRules {
    pub default_validity_days: i32,
    pub max_validity_days: i32,
    pub renewable: bool,
    pub renewal_window_days: i32,
    pub not_before_offset_seconds: i32,
    pub require_revalidation: bool,
    pub revalidation_interval_days: Option<i32>,
}

impl Default for ValidityRules {
    fn default() -> Self {
        Self {
            default_validity_days: 365,
            max_validity_days: 1_095,
            renewable: true,
            renewal_window_days: 30,
            not_before_offset_seconds: 0,
            require_revalidation: false,
            revalidation_interval_days: None,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct IssuerRequirements {
    pub allowed_issuer_dids: Vec<String>,
    pub trust_tier_required: Option<String>,
    pub audit_level_required: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DerivedAttribute {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub source_claim: String,
    pub derivation_type: String,
    #[serde(default = "empty_json_object")]
    pub parameters: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct WalletConfig {
    pub wallet_id: String,
    pub deep_link_scheme: String,
    pub format_variant: Option<String>,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            wallet_id: String::new(),
            deep_link_scheme: "openid-credential-offer://".to_owned(),
            format_variant: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CredentialTemplate {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub description: Option<String>,
    pub status: TemplateStatus,
    pub credential_type: String,
    pub vct: String,
    pub doctype: Option<String>,
    pub claims: Vec<ClaimDefinition>,
    pub privacy_posture: PrivacyPosture,
    pub selective_disclosure_fields: Vec<String>,
    pub zk_predicate_claims: Vec<String>,
    pub derived_attributes: Vec<DerivedAttribute>,
    pub display_style: DisplayStyle,
    pub validity_rules: ValidityRules,
    pub issuer_requirements: IssuerRequirements,
    pub supported_formats: Vec<CredentialFormat>,
    pub credential_payload_format: String,
    pub wallet_configs: Vec<WalletConfig>,
    pub compliance_profile: Option<Value>,
    pub compliance_profile_id: Option<String>,
    pub application_template_id: Option<String>,
    pub trust_profile_id: Option<String>,
    pub revocation_profile_id: Option<String>,
    pub issuer_algorithm: Option<String>,
    pub issuer_did: Option<String>,
    pub issuance_protocol: String,
    pub version: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl CredentialTemplate {
    pub fn validate_definition(&self) -> Result<(), CredentialTemplateError> {
        validate_credential_type(&self.credential_type)?;
        if self.claims.is_empty() {
            return Err(CredentialTemplateError::MissingClaims);
        }
        validate_claim_definitions(&self.claims)
    }

    pub fn activate(&mut self, now: DateTime<Utc>) -> Result<(), CredentialTemplateError> {
        if self.claims.is_empty() {
            return Err(CredentialTemplateError::MissingClaims);
        }
        self.status = TemplateStatus::Active;
        self.updated_at = now;
        Ok(())
    }

    pub fn deprecate(&mut self, now: DateTime<Utc>) {
        self.status = TemplateStatus::Deprecated;
        self.updated_at = now;
    }

    pub fn ensure_draft_mutation(&self) -> Result<(), CredentialTemplateError> {
        if self.status == TemplateStatus::Draft {
            Ok(())
        } else {
            Err(CredentialTemplateError::TemplateNotDraft)
        }
    }

    pub fn ensure_deletable(&self) -> Result<(), CredentialTemplateError> {
        if self.status == TemplateStatus::Draft {
            Ok(())
        } else {
            Err(CredentialTemplateError::TemplateNotDeletable)
        }
    }

    pub fn add_claim(
        &mut self,
        claim: ClaimDefinition,
        now: DateTime<Utc>,
    ) -> Result<(), CredentialTemplateError> {
        self.ensure_draft_mutation()?;
        let mut claims = self.claims.clone();
        claims.push(claim);
        validate_claim_definitions(&claims)?;
        self.claims = claims;
        self.updated_at = now;
        Ok(())
    }

    #[must_use]
    pub fn new_version(&self, id: String, now: DateTime<Utc>) -> Self {
        let mut version = self.clone();
        version.id = id;
        version.status = TemplateStatus::Draft;
        version.version += 1;
        version.created_at = now;
        version.updated_at = now;
        version
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ValidityRulesInput {
    pub default_validity_days: Option<i32>,
    pub max_validity_days: Option<i32>,
    pub renewable: Option<bool>,
    pub renewal_window_days: Option<i32>,
    pub ttl_seconds: Option<i64>,
    pub reissue_within_seconds: Option<i64>,
    pub not_before_offset_seconds: Option<i32>,
    pub not_before_offset: Option<i32>,
    pub max_validity_seconds: Option<i64>,
    pub require_revalidation: Option<bool>,
    pub revalidation_interval_days: Option<i32>,
}

pub fn resolve_validity_rules(
    input: &ValidityRulesInput,
    existing: Option<&ValidityRules>,
) -> Result<ValidityRules, CredentialTemplateError> {
    let base = existing.cloned().unwrap_or_default();
    if input.ttl_seconds.is_some_and(|seconds| seconds <= 0) {
        return Err(CredentialTemplateError::InvalidValidityRules(
            "ttl_seconds must be > 0".to_owned(),
        ));
    }
    let default_validity_days = input.ttl_seconds.map_or_else(
        || {
            input
                .default_validity_days
                .unwrap_or(base.default_validity_days)
        },
        days_from_seconds,
    );
    let max_validity_days = input.max_validity_seconds.map_or_else(
        || input.max_validity_days.unwrap_or(base.max_validity_days),
        days_from_seconds,
    );
    let renewal_window_days = input.reissue_within_seconds.map_or_else(
        || {
            input
                .renewal_window_days
                .unwrap_or(base.renewal_window_days)
        },
        days_from_seconds,
    );
    Ok(ValidityRules {
        default_validity_days,
        max_validity_days,
        renewable: input.renewable.unwrap_or(base.renewable),
        renewal_window_days,
        not_before_offset_seconds: input
            .not_before_offset_seconds
            .or(input.not_before_offset)
            .unwrap_or(base.not_before_offset_seconds),
        require_revalidation: input
            .require_revalidation
            .unwrap_or(base.require_revalidation),
        revalidation_interval_days: input
            .revalidation_interval_days
            .or(base.revalidation_interval_days),
    })
}

pub fn validate_credential_type(value: &str) -> Result<(), CredentialTemplateError> {
    let expression = Regex::new(r"^(?:[A-Z][a-zA-Z0-9]+|[a-z][a-zA-Z0-9]*(?:\.[a-zA-Z0-9]+)+)$")
        .map_err(|_| {
            CredentialTemplateError::InvalidConfiguration("credential type expression".to_owned())
        })?;
    if expression.is_match(value) {
        Ok(())
    } else {
        Err(CredentialTemplateError::InvalidCredentialType(
            value.to_owned(),
        ))
    }
}

pub fn validate_claim_definitions(
    claims: &[ClaimDefinition],
) -> Result<(), CredentialTemplateError> {
    let names = claims
        .iter()
        .map(|claim| claim.name.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if names.len() != claims.len() {
        return Err(CredentialTemplateError::DuplicateClaimNames);
    }
    for claim in claims {
        if claim.derived_from.as_deref() == Some(claim.name.as_str()) {
            return Err(CredentialTemplateError::SelfDerivedClaim(
                claim.name.clone(),
            ));
        }
        if let Some(source) = claim
            .derived_from
            .as_deref()
            .filter(|source| !names.contains(source))
        {
            return Err(CredentialTemplateError::UnknownDerivedClaim {
                claim: claim.name.clone(),
                source_claim: source.to_owned(),
            });
        }
    }
    Ok(())
}

fn days_from_seconds(seconds: i64) -> i32 {
    let days = seconds.saturating_add(86_399) / 86_400;
    i32::try_from(days.max(1)).unwrap_or(i32::MAX)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MergeStrategy {
    #[serde(rename = "APPEND")]
    Append,
    #[serde(rename = "REPLACE")]
    Replace,
}

impl MergeStrategy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Append => "APPEND",
            Self::Replace => "REPLACE",
        }
    }

    pub fn parse(value: &str) -> Result<Self, CredentialTemplateError> {
        match value {
            "APPEND" => Ok(Self::Append),
            "REPLACE" => Ok(Self::Replace),
            _ => Err(invalid("wallet merge strategy", value)),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct WalletRegistryEntry {
    pub id: String,
    pub organization_id: Option<String>,
    pub is_override: bool,
    pub override_precedence: i32,
    pub merge_strategy: MergeStrategy,
    pub credential_format: Option<String>,
    pub issuance_protocol: Option<String>,
    pub compliance_profile_code: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub wallet_apps: Vec<String>,
    pub specifications: Vec<String>,
    pub logo_url: Option<String>,
    pub deep_link_template: String,
    pub routing_templates: BTreeMap<String, String>,
    pub install_urls: BTreeMap<String, String>,
    pub ios_scheme: Option<String>,
    pub universal_link_template: Option<String>,
    pub android_package: Option<String>,
    pub supported_formats: Vec<String>,
    pub supported_protocols: Vec<String>,
    pub platforms: Vec<String>,
    pub supports_qr: bool,
    pub supports_deeplink: bool,
    pub supports_digital_credentials: bool,
    pub supports_haip: bool,
    pub docs_url: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeliveryDestinationEntry {
    pub id: String,
    pub organization_id: Option<String>,
    pub is_system: bool,
    pub name: String,
    pub description: Option<String>,
    pub provider: String,
    pub mode: String,
    pub setup_actor: String,
    pub delivery_target: String,
    pub wallet_profile_id: Option<String>,
    pub credential_format: Option<String>,
    pub issuance_protocol: Option<String>,
    pub compliance_profile_code: Option<String>,
    pub connector_type: Option<String>,
    pub connector_id: Option<String>,
    pub requires_consent: bool,
    pub claim_projection_policy: Value,
    pub setup_requirements: Vec<String>,
    pub capabilities: BTreeMap<String, bool>,
    pub docs_url: Option<String>,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn optional_string(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_owned)
}

fn optional_bool(value: Option<&Value>) -> Option<bool> {
    value.and_then(Value::as_bool)
}

fn optional_string_list(
    value: Option<&Value>,
) -> Result<Option<Vec<String>>, CredentialTemplateError> {
    value
        .map(|value| {
            serde_json::from_value(value.clone())
                .map_err(|_| invalid("claim enum_values", &value.to_string()))
        })
        .transpose()
}

fn optional_number(value: Option<&Value>) -> Result<Option<f64>, CredentialTemplateError> {
    value
        .map(|value| {
            value
                .as_f64()
                .ok_or_else(|| invalid("claim numeric bound", &value.to_string()))
        })
        .transpose()
}

fn title_case(value: &str) -> String {
    value
        .split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            chars
                .next()
                .map(|first| first.to_uppercase().chain(chars).collect())
                .unwrap_or_default()
        })
        .collect::<Vec<String>>()
        .join(" ")
}

fn empty_json_object() -> Value {
    Value::Object(serde_json::Map::new())
}

fn invalid(field: &str, value: &str) -> CredentialTemplateError {
    CredentialTemplateError::InvalidConfiguration(format!("invalid {field}: {value}"))
}
