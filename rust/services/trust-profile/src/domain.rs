use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustProfileStatus {
    Draft,
    Active,
    Suspended,
    Archived,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustProfileType {
    Icao,
    Aamva,
    Eudi,
    Custom,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComplianceStatus {
    Compliant,
    NeedsAttention,
    SetupRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustSourceType {
    TrustList,
    PinnedIssuer,
    RootCa,
    PkdUrl,
    #[serde(rename = "REGISTRY")]
    LegacyRegistry,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RevocationCheckMode {
    HardFail,
    SoftFail,
    Skip,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IssuerEntityType {
    Organization,
    Government,
    Device,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IssuerEntityComplianceStatus {
    Accredited,
    Compliant,
    Suspended,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustRelationshipStatus {
    Trusted,
    Denied,
    UnderReview,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CascadeRevocationPolicy {
    AutoCascade,
    Manual,
    NotifyOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustAnchorType {
    Csca,
    Dsc,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegistryOperation {
    Add,
    Remove,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegistrySource {
    IcaoPkd,
    Aamva,
    EudiLotl,
    Manual,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegistryImportType {
    IcaoPkd,
    EuTrustList,
    Aamva,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustSource {
    pub id: Uuid,
    pub name: String,
    pub source_type: TrustSourceType,
    pub url: Option<String>,
    pub certificate_pem: Option<String>,
    pub issuer_did: Option<String>,
    pub description: Option<String>,
    pub pinned_certificates: Vec<String>,
    pub refresh_interval_hours: u16,
    pub enabled: bool,
    pub registry_sync: Option<Value>,
    pub registry_sync_token: Option<String>,
    pub registry_sequence: u64,
    pub registry_entries: Map<String, Value>,
    pub registry_last_synced_at: Option<DateTime<Utc>>,
    #[serde(flatten)]
    pub extensions: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ValidationRules {
    pub allowed_algorithms: Vec<String>,
    pub min_key_size_rsa: u16,
    pub min_key_size_ec: u16,
    pub require_key_usage: bool,
    pub max_chain_depth: u8,
    pub allow_self_signed: bool,
    #[serde(flatten)]
    pub extensions: Map<String, Value>,
}

impl Default for ValidationRules {
    fn default() -> Self {
        Self {
            allowed_algorithms: vec!["ES256".into(), "ES384".into(), "EdDSA".into()],
            min_key_size_rsa: 2_048,
            min_key_size_ec: 256,
            require_key_usage: true,
            max_chain_depth: 5,
            allow_self_signed: false,
            extensions: Map::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevocationPolicy {
    pub check_mode: RevocationCheckMode,
    pub check_ocsp: bool,
    pub check_crl: bool,
    pub check_status_list: bool,
    pub offline_grace_period_hours: u16,
    pub cache_duration_hours: u16,
}

impl Default for RevocationPolicy {
    fn default() -> Self {
        Self {
            check_mode: RevocationCheckMode::HardFail,
            check_ocsp: true,
            check_crl: true,
            check_status_list: true,
            offline_grace_period_hours: 24,
            cache_duration_hours: 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TimePolicy {
    pub max_clock_skew_seconds: u32,
    pub credential_freshness_hours: Option<u32>,
    pub require_not_before: bool,
    pub require_expiration: bool,
}

impl Default for TimePolicy {
    fn default() -> Self {
        Self {
            max_clock_skew_seconds: 300,
            credential_freshness_hours: None,
            require_not_before: true,
            require_expiration: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustProfile {
    pub id: Uuid,
    pub organization_id: String,
    pub name: String,
    pub description: Option<String>,
    pub status: TrustProfileStatus,
    pub profile_type: TrustProfileType,
    pub compliance_status: ComplianceStatus,
    pub trust_sources: Vec<TrustSource>,
    pub validation_rules: ValidationRules,
    pub allowed_issuers: Option<Vec<String>>,
    pub denied_issuers: Option<Vec<String>>,
    pub system_issuer_overrides: Map<String, Value>,
    pub compatible_compliance_codes: Vec<String>,
    pub verification_policy_set_id: Option<String>,
    pub auto_generated: bool,
    pub revocation_policy: RevocationPolicy,
    pub revocation_profile_id: Option<String>,
    pub time_policy: TimePolicy,
    pub supported_formats: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TrustProfile {
    pub fn activate(&mut self, now: DateTime<Utc>) {
        self.status = TrustProfileStatus::Active;
        self.updated_at = now;
    }

    pub fn suspend(&mut self, now: DateTime<Utc>) {
        self.status = TrustProfileStatus::Suspended;
        self.updated_at = now;
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustFramework {
    pub id: Uuid,
    pub code: String,
    pub display_name: String,
    pub description: Option<String>,
    pub pkd_endpoints: Vec<String>,
    pub default_algorithms: Vec<String>,
    pub default_formats: Vec<String>,
    pub validation_ruleset: Value,
    pub sync_config: Value,
    pub is_system: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OrganizationTrustProfile {
    pub id: Uuid,
    pub organization_id: String,
    pub framework_id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub enabled: bool,
    pub use_case_tags: Vec<String>,
    pub compliance_status: ComplianceStatus,
    pub auto_generated: bool,
    pub revocation_policy: Option<Value>,
    pub time_policy: Option<Value>,
    pub allowed_algorithms: Option<Vec<String>>,
    pub allowed_formats: Option<Vec<String>>,
    pub allowed_issuers: Option<Vec<String>>,
    pub denied_issuers: Option<Vec<String>>,
    pub jurisdiction_filter: Option<Vec<String>>,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustRegistryEntry {
    pub id: Uuid,
    pub anchor_type: TrustAnchorType,
    pub operation: RegistryOperation,
    pub country_code: String,
    pub certificate_pem: Option<String>,
    pub subject_key_id: Option<String>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub source: RegistrySource,
    pub framework_code: Option<String>,
    pub sequence: u64,
    pub is_current: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssuerEntity {
    pub id: Uuid,
    pub organization_id: Option<String>,
    pub issuer_id: String,
    pub issuer_type: IssuerEntityType,
    pub display_name: String,
    pub description: Option<String>,
    pub is_system_issuer: bool,
    pub compliance_status: IssuerEntityComplianceStatus,
    pub accreditation_body: Option<String>,
    pub accreditations: Vec<String>,
    pub accreditation_date: Option<DateTime<Utc>>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub trust_anchor_id: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
    pub revoked_by: Option<String>,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustProfileIssuer {
    pub id: Uuid,
    pub trust_profile_id: Uuid,
    pub issuer_id: Uuid,
    pub trust_level: u8,
    pub relationship_status: TrustRelationshipStatus,
    pub cascade_revocation_policy: CascadeRevocationPolicy,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistryImportSource {
    pub id: Uuid,
    pub trust_profile_id: Uuid,
    pub registry_type: RegistryImportType,
    pub registry_name: String,
    pub registry_url: Option<String>,
    pub enabled: bool,
    pub sync_enabled: bool,
    pub last_synced_at: Option<DateTime<Utc>>,
    pub next_sync_at: Option<DateTime<Utc>>,
    pub sync_interval_hours: u16,
    pub credential_format_filter: Vec<String>,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistryImportedIssuer {
    pub id: Uuid,
    pub registry_source_id: Uuid,
    pub trust_profile_id: Uuid,
    pub issuer_did: String,
    pub issuer_name: Option<String>,
    pub country_code: Option<String>,
    pub issuer_type: Option<String>,
    pub verification_keys: Vec<Value>,
    pub credential_templates: Vec<Value>,
    pub status: String,
    pub imported_at: DateTime<Utc>,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
