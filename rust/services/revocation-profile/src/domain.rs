use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RevocationProfileStatus {
    Draft,
    Active,
    Suspended,
}

impl RevocationProfileStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationCheckMode {
    #[serde(rename = "HARD_FAIL")]
    HardFail,
    #[serde(rename = "SOFT_FAIL")]
    SoftFail,
    #[serde(rename = "SKIP")]
    Skip,
}

impl RevocationCheckMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HardFail => "HARD_FAIL",
            Self::SoftFail => "SOFT_FAIL",
            Self::Skip => "SKIP",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationTimingMode {
    #[serde(rename = "ALWAYS")]
    Always,
    #[serde(rename = "CACHED")]
    Cached,
    #[serde(rename = "OFFLINE_GRACE")]
    OfflineGrace,
    #[serde(rename = "DISABLED")]
    Disabled,
}

impl RevocationTimingMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Always => "ALWAYS",
            Self::Cached => "CACHED",
            Self::OfflineGrace => "OFFLINE_GRACE",
            Self::Disabled => "DISABLED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RevocationMechanism {
    Ocsp,
    Crl,
    BitstringStatusList,
    TokenStatusList,
    LegacyRevocationList,
}

impl RevocationMechanism {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ocsp => "OCSP",
            Self::Crl => "CRL",
            Self::BitstringStatusList => "BITSTRING_STATUS_LIST",
            Self::TokenStatusList => "TOKEN_STATUS_LIST",
            Self::LegacyRevocationList => "LEGACY_REVOCATION_LIST",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StatusListStrategy {
    Auto,
    Manual,
    Registry,
}

impl StatusListStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Manual => "manual",
            Self::Registry => "registry",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateMode {
    Sync,
    Async,
    Batch,
}

impl UpdateMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sync => "sync",
            Self::Async => "async",
            Self::Batch => "batch",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CredentialFormat {
    SdJwtVc,
    Mdoc,
    VcJwt,
}

impl CredentialFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SdJwtVc => "SD_JWT_VC",
            Self::Mdoc => "MDOC",
            Self::VcJwt => "VC_JWT",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IssuerRevocationConfig {
    pub status_list_strategy: StatusListStrategy,
    pub status_list_base_url: Option<String>,
    pub status_list_size: usize,
    pub update_mode: UpdateMode,
    pub batch_interval_seconds: u32,
    pub enable_rotation: bool,
    pub rotation_threshold_percent: u8,
    pub enable_bitstring_status_list: bool,
    pub enable_token_status_list: bool,
    pub enable_legacy_revocation_list: bool,
}

impl Default for IssuerRevocationConfig {
    fn default() -> Self {
        Self {
            status_list_strategy: StatusListStrategy::Auto,
            status_list_base_url: None,
            status_list_size: 131_072,
            update_mode: UpdateMode::Sync,
            batch_interval_seconds: 300,
            enable_rotation: true,
            rotation_threshold_percent: 80,
            enable_bitstring_status_list: true,
            enable_token_status_list: true,
            enable_legacy_revocation_list: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VerifierRevocationConfig {
    pub check_mode: RevocationCheckMode,
    pub timing_mode: RevocationTimingMode,
    pub mechanism_priority: Vec<RevocationMechanism>,
    pub cache_status_lists: bool,
    pub cache_ttl_seconds: u32,
    pub offline_grace_seconds: u32,
    pub check_timeout_seconds: u32,
    pub max_retries: u32,
    pub require_issuer_signature_on_status_list: bool,
    pub allow_third_party_registries: bool,
}

impl Default for VerifierRevocationConfig {
    fn default() -> Self {
        Self {
            check_mode: RevocationCheckMode::HardFail,
            timing_mode: RevocationTimingMode::Always,
            mechanism_priority: vec![RevocationMechanism::BitstringStatusList],
            cache_status_lists: true,
            cache_ttl_seconds: 3_600,
            offline_grace_seconds: 86_400,
            check_timeout_seconds: 5,
            max_retries: 2,
            require_issuer_signature_on_status_list: true,
            allow_third_party_registries: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RevocationAutomationConfig {
    pub auto_allocate_indices: bool,
    pub auto_publish: bool,
    pub auto_generate_status_list_credentials: bool,
    pub auto_discover_endpoints: bool,
    pub use_format_defaults: bool,
}

impl Default for RevocationAutomationConfig {
    fn default() -> Self {
        Self {
            auto_allocate_indices: true,
            auto_publish: true,
            auto_generate_status_list_credentials: true,
            auto_discover_endpoints: true,
            use_format_defaults: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationProfile {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub description: Option<String>,
    pub status: RevocationProfileStatus,
    pub issuer_config: IssuerRevocationConfig,
    pub verifier_config: VerifierRevocationConfig,
    pub automation_config: RevocationAutomationConfig,
    pub supported_formats: Vec<CredentialFormat>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl RevocationProfile {
    pub fn new(organization_id: String, name: String, description: Option<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            organization_id,
            name,
            description,
            status: RevocationProfileStatus::Draft,
            issuer_config: IssuerRevocationConfig::default(),
            verifier_config: VerifierRevocationConfig::default(),
            automation_config: RevocationAutomationConfig::default(),
            supported_formats: vec![
                CredentialFormat::SdJwtVc,
                CredentialFormat::Mdoc,
                CredentialFormat::VcJwt,
            ],
            created_at: now,
            updated_at: now,
        }
    }

    pub fn activate(&mut self) {
        self.status = RevocationProfileStatus::Active;
        self.updated_at = Utc::now();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewProfile {
    pub organization_id: String,
    pub name: String,
    pub description: Option<String>,
    pub issuer_config: Option<IssuerRevocationConfig>,
    pub verifier_config: Option<VerifierRevocationConfig>,
    pub automation_config: Option<RevocationAutomationConfig>,
    pub supported_formats: Option<Vec<CredentialFormat>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRevocation {
    pub profile_id: String,
    pub organization_id: String,
    pub credential_id: String,
    pub index: usize,
    pub status: CredentialStatus,
    pub credential_format: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialStatus {
    Revoked,
    Suspended,
    Reinstated,
}
