use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{CredentialTemplate, MergeStrategy, WalletConfig, WalletRegistryEntry};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedWalletProfile {
    pub credential_format: String,
    pub issuance_protocol: String,
    pub compliance_profile_code: Option<String>,
    pub name: String,
    pub description: String,
    pub wallet_apps: Vec<String>,
    pub specifications: Vec<String>,
    pub supported_platforms: Vec<String>,
    pub deep_link_pattern: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletCompatibility {
    pub id: Option<String>,
    pub organization_id: Option<String>,
    pub derived_from: DerivedFrom,
    pub is_override: bool,
    pub override_precedence: i32,
    pub merge_strategy: String,
    pub name: String,
    pub description: String,
    pub credential_format: String,
    pub issuance_protocol: String,
    pub compliance_profile_code: Option<String>,
    pub wallet_apps: Vec<String>,
    pub specifications: Vec<String>,
    pub supported_platforms: Vec<String>,
    pub deep_link_pattern: String,
    pub applied_override_ids: Vec<String>,
    pub template_wallet_configs: Vec<WalletConfig>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DerivedFrom {
    pub credential_format: String,
    pub issuance_protocol: String,
    pub compliance_profile_code: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IosSameDeviceMode {
    DigitalCredentials,
    UniversalLink,
    NestedLink,
    ProtocolOnly,
    Unsupported,
}

impl IosSameDeviceMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DigitalCredentials => "digital_credentials",
            Self::UniversalLink => "universal_link",
            Self::NestedLink => "nested_link",
            Self::ProtocolOnly => "protocol_only",
            Self::Unsupported => "unsupported",
        }
    }
}

#[must_use]
pub fn normalize_issuance_protocol(value: Option<&str>) -> String {
    let normalized = value
        .unwrap_or("OID4VCI_PRE_AUTH")
        .trim()
        .to_ascii_uppercase();
    match normalized.as_str() {
        "OID4VCI"
        | "OID4VCI_PRE_AUTH"
        | "OID4VCI_PRE_AUTHORIZED"
        | "OID4VCI_PREAUTHORIZED"
        | "OID4VCI_PRE_AUTH_CODE" => "OID4VCI_PRE_AUTH".to_owned(),
        "OID4VCI_AUTHORIZATION_CODE" => "OID4VCI_AUTH_CODE".to_owned(),
        _ => normalized,
    }
}

#[must_use]
pub fn derive_wallet_profile(
    credential_format: &str,
    issuance_protocol: &str,
    compliance_profile_code: Option<&str>,
) -> DerivedWalletProfile {
    let format = credential_format.trim().to_ascii_uppercase();
    let protocol = normalize_issuance_protocol(Some(issuance_protocol));
    let compliance = compliance_profile_code
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_uppercase);
    let exact = profile(&format, &protocol, compliance.as_deref());
    exact
        .or_else(|| profile(&format, &protocol, None))
        .unwrap_or_else(|| DerivedWalletProfile {
            credential_format: format.clone(),
            issuance_protocol: protocol.clone(),
            compliance_profile_code: compliance,
            name: format!("{format} Wallet Compatibility"),
            description: "Derived fallback compatibility profile for this credential format and issuance protocol.".to_owned(),
            wallet_apps: strings(&["OID4VCI-compatible wallets"]),
            specifications: vec![format, protocol],
            supported_platforms: strings(&["ios", "android", "web"]),
            deep_link_pattern:
                "openid-credential-offer://?credential_offer_uri={offer_uri}".to_owned(),
        })
}

#[must_use]
pub fn matching_wallet_overrides(
    entries: &[WalletRegistryEntry],
    organization_id: &str,
    credential_format: &str,
    issuance_protocol: &str,
    compliance_profile_code: Option<&str>,
) -> Vec<WalletRegistryEntry> {
    let mut matches = entries
        .iter()
        .filter(|entry| {
            entry.is_active
                && entry.is_override
                && entry.organization_id.as_deref() == Some(organization_id)
                && entry_matches(
                    entry,
                    credential_format,
                    issuance_protocol,
                    compliance_profile_code,
                )
        })
        .cloned()
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| {
        right
            .override_precedence
            .cmp(&left.override_precedence)
            .then_with(|| left.id.cmp(&right.id))
    });
    matches
}

#[must_use]
pub fn merge_wallet_profile(
    derived: DerivedWalletProfile,
    overrides: &[WalletRegistryEntry],
    template: &CredentialTemplate,
) -> WalletCompatibility {
    merge_wallet_profile_parts(
        derived,
        overrides,
        template.wallet_configs.clone(),
        template.created_at,
        template.updated_at,
    )
}

#[must_use]
pub fn merge_wallet_profile_parts(
    derived: DerivedWalletProfile,
    overrides: &[WalletRegistryEntry],
    template_wallet_configs: Vec<WalletConfig>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
) -> WalletCompatibility {
    let mut name = derived.name.clone();
    let mut description = derived.description.clone();
    let mut wallet_apps = derived.wallet_apps.clone();
    let mut specifications = derived.specifications.clone();
    let mut platforms = derived.supported_platforms.clone();
    let mut deep_link_pattern = derived.deep_link_pattern.clone();
    let mut applied_override_ids = Vec::new();
    for item in overrides {
        applied_override_ids.push(item.id.clone());
        let apps = if item.wallet_apps.is_empty() {
            vec![item.name.clone()]
        } else {
            item.wallet_apps.clone()
        };
        if item.merge_strategy == MergeStrategy::Replace {
            if !apps.is_empty() {
                wallet_apps = apps;
            }
            if !item.specifications.is_empty() {
                specifications = item.specifications.clone();
            }
            if !item.platforms.is_empty() {
                platforms = item.platforms.clone();
            }
        } else {
            merge_unique(&mut wallet_apps, &apps);
            merge_unique(&mut specifications, &item.specifications);
            merge_unique(&mut platforms, &item.platforms);
        }
        if !item.name.is_empty() {
            name.clone_from(&item.name);
        }
        if let Some(value) = item.description.as_ref().filter(|value| !value.is_empty()) {
            description.clone_from(value);
        }
        if !item.deep_link_template.is_empty() {
            deep_link_pattern.clone_from(&item.deep_link_template);
        }
    }
    let primary = overrides.first();
    WalletCompatibility {
        id: primary.map(|item| item.id.clone()),
        organization_id: primary.and_then(|item| item.organization_id.clone()),
        derived_from: DerivedFrom {
            credential_format: derived.credential_format.clone(),
            issuance_protocol: derived.issuance_protocol.clone(),
            compliance_profile_code: derived.compliance_profile_code.clone(),
        },
        is_override: !applied_override_ids.is_empty(),
        override_precedence: primary.map_or(0, |item| item.override_precedence),
        merge_strategy: primary
            .map_or("APPEND", |item| item.merge_strategy.as_str())
            .to_owned(),
        name,
        description,
        credential_format: derived.credential_format,
        issuance_protocol: derived.issuance_protocol,
        compliance_profile_code: derived.compliance_profile_code,
        wallet_apps,
        specifications,
        supported_platforms: platforms,
        deep_link_pattern,
        applied_override_ids,
        template_wallet_configs,
        created_at: primary.map_or(created_at, |item| item.created_at),
        updated_at: primary.map_or(updated_at, |item| item.updated_at),
    }
}

#[must_use]
pub fn wallet_routing_templates(entry: &WalletRegistryEntry) -> BTreeMap<String, String> {
    if !entry.supports_deeplink {
        return BTreeMap::new();
    }
    let mut templates = entry.routing_templates.clone();
    if !entry.deep_link_template.is_empty() {
        templates
            .entry("generic".to_owned())
            .or_insert_with(|| entry.deep_link_template.clone());
    }
    if let Some(template) = entry.universal_link_template.as_ref() {
        templates
            .entry("web".to_owned())
            .or_insert_with(|| template.clone());
        templates
            .entry("ios".to_owned())
            .or_insert_with(|| template.clone());
    }
    if let Some(scheme) = entry.ios_scheme.as_ref() {
        templates
            .entry("ios".to_owned())
            .or_insert_with(|| format!("{scheme}://open?inner={{inner_uri_encoded}}"));
    }
    for platform in &entry.platforms {
        if matches!(platform.as_str(), "ios" | "android" | "web" | "desktop")
            && !entry.deep_link_template.is_empty()
        {
            templates
                .entry(platform.clone())
                .or_insert_with(|| entry.deep_link_template.clone());
        }
    }
    templates
}

#[must_use]
pub fn wallet_route_template(entry: &WalletRegistryEntry, platform: Option<&str>) -> String {
    let templates = wallet_routing_templates(entry);
    let normalized = match platform
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "desktop" => "web".to_owned(),
        value => value.to_owned(),
    };
    if let Some(exact) = templates.get(&normalized).filter(|value| !value.is_empty()) {
        return exact.clone();
    }
    if let Some(generic) = templates
        .get("generic")
        .or_else(|| templates.get("default"))
        .filter(|value| !value.is_empty())
    {
        return generic.clone();
    }
    if !entry.deep_link_template.is_empty() {
        return entry.deep_link_template.clone();
    }
    if !normalized.is_empty() {
        return String::new();
    }
    ["ios", "android", "web", "desktop"]
        .iter()
        .filter_map(|key| templates.get(*key))
        .chain(templates.values())
        .find(|value| is_wallet_routing_template(value))
        .cloned()
        .unwrap_or_default()
}

#[must_use]
pub fn wallet_capabilities(entry: &WalletRegistryEntry) -> BTreeMap<String, bool> {
    let tokens = entry
        .specifications
        .iter()
        .chain(&entry.supported_protocols)
        .cloned()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    let oid4vci = tokens.contains("oid4vci") || tokens.contains("oid4vci_pre_auth");
    let oid4vp = tokens.contains("oid4vp");
    let digital_credentials = entry.supports_digital_credentials
        || ["credentialmanager", "digital_credentials", "dc_api"]
            .iter()
            .any(|marker| tokens.contains(marker));
    let haip = entry.supports_haip || tokens.contains("haip");
    BTreeMap::from([
        ("digital_credentials".to_owned(), digital_credentials),
        ("haip".to_owned(), haip),
        ("oid4vci".to_owned(), oid4vci),
        ("oid4vp".to_owned(), oid4vp),
        (
            "same_device".to_owned(),
            entry.supports_deeplink || digital_credentials,
        ),
        ("qr".to_owned(), entry.supports_qr),
    ])
}

#[must_use]
pub fn derive_ios_same_device_mode(entry: &WalletRegistryEntry) -> IosSameDeviceMode {
    if !targets_ios_same_device(entry) {
        return IosSameDeviceMode::Unsupported;
    }
    if entry.supports_digital_credentials {
        return IosSameDeviceMode::DigitalCredentials;
    }
    let template = wallet_route_template(entry, Some("ios"));
    let scheme = template
        .split_once(':')
        .map(|(scheme, _)| scheme.to_ascii_lowercase());
    if scheme
        .as_deref()
        .is_some_and(|value| matches!(value, "https" | "http"))
    {
        IosSameDeviceMode::UniversalLink
    } else if is_wallet_routing_template(&template) {
        IosSameDeviceMode::NestedLink
    } else if scheme.as_deref().is_some_and(|value| {
        matches!(
            value,
            "openid-credential-offer" | "openid4vp" | "haip-vci" | "haip-vp"
        )
    }) {
        IosSameDeviceMode::ProtocolOnly
    } else {
        IosSameDeviceMode::Unsupported
    }
}

fn targets_ios_same_device(entry: &WalletRegistryEntry) -> bool {
    let platforms = entry
        .platforms
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if platforms
        .iter()
        .any(|value| matches!(value.as_str(), "ios" | "any"))
    {
        return true;
    }
    let explicit = entry.universal_link_template.is_some()
        || entry.ios_scheme.is_some()
        || entry.routing_templates.contains_key("ios");
    if !platforms.is_empty() {
        return explicit;
    }
    entry.supports_digital_credentials || explicit || !entry.deep_link_template.is_empty()
}

fn is_wallet_routing_template(template: &str) -> bool {
    let scheme = template
        .split_once(':')
        .map_or("", |(scheme, _)| scheme)
        .to_ascii_lowercase();
    if matches!(
        scheme.as_str(),
        "openid-credential-offer" | "openid4vp" | "haip-vci" | "haip-vp"
    ) {
        return false;
    }
    [
        "{inner_uri}",
        "{inner_uri_encoded}",
        "{uri}",
        "{uri_encoded}",
        "{offer_uri}",
        "{offer_uri_encoded}",
        "{offer}",
        "{offer_encoded}",
        "{credential_offer_uri}",
        "{credential_offer_uri_encoded}",
        "{request_uri}",
        "{request_uri_encoded}",
    ]
    .iter()
    .any(|placeholder| template.contains(placeholder))
}

fn entry_matches(
    entry: &WalletRegistryEntry,
    credential_format: &str,
    issuance_protocol: &str,
    compliance_profile_code: Option<&str>,
) -> bool {
    if entry
        .credential_format
        .as_deref()
        .is_some_and(|value| !value.eq_ignore_ascii_case(credential_format))
    {
        return false;
    }
    if entry.issuance_protocol.as_deref().is_some_and(|value| {
        normalize_issuance_protocol(Some(value))
            != normalize_issuance_protocol(Some(issuance_protocol))
    }) {
        return false;
    }
    if entry
        .compliance_profile_code
        .as_deref()
        .is_some_and(|value| {
            compliance_profile_code.is_none_or(|expected| !value.eq_ignore_ascii_case(expected))
        })
    {
        return false;
    }
    true
}

fn profile(format: &str, protocol: &str, compliance: Option<&str>) -> Option<DerivedWalletProfile> {
    let values: (&str, &str, &[&str], &[&str], &[&str]) = match (format, protocol, compliance) {
        ("MDOC", "OID4VCI_PRE_AUTH", Some("AAMVA_MDL")) => (
            "AAMVA mDL Wallet",
            "Derived compatibility profile for AAMVA mobile driver licenses.",
            &[
                "Apple Wallet (mDL)",
                "Google Wallet (mDL)",
                "ISO mDL wallets",
            ] as &[_],
            &["ISO 18013-5", "ISO 23220-3", "OID4VCI"] as &[_],
            &["ios", "android"] as &[_],
        ),
        ("MDOC", "OID4VCI_PRE_AUTH", Some("ICAO_DTC")) => (
            "ICAO DTC Wallet",
            "Derived compatibility profile for ICAO DTC wallets.",
            &["ICAO DTC-compliant wallets"],
            &["ICAO DTC", "OID4VCI"],
            &["ios", "android"],
        ),
        ("MDOC", "OID4VCI_PRE_AUTH", Some("EUDI_MDL")) => (
            "EUDI mDL Wallet",
            "Derived compatibility profile for EUDI mobile driving licences.",
            &["EUDI Wallet", "eIDAS wallets"],
            &["eIDAS", "OID4VCI", "ISO 18013-5"],
            &["ios", "android", "web"],
        ),
        ("SD_JWT_VC", "OID4VCI_PRE_AUTH", Some("EUDI_PID")) => (
            "EUDI PID Wallet",
            "Derived compatibility profile for EUDI PID credentials.",
            &["EUDI Wallet", "eIDAS wallets"],
            &["SD-JWT VC", "OID4VCI", "eIDAS"],
            &["ios", "android", "web"],
        ),
        ("SD_JWT_VC", "OID4VCI_PRE_AUTH", None) => (
            "Generic SD-JWT VC Wallet",
            "Derived compatibility profile for generic SD-JWT VC issuance.",
            &["EUDI Wallet", "OID4VCI-compatible wallets"],
            &["SD-JWT VC", "OID4VCI"],
            &["ios", "android", "web"],
        ),
        ("VC_JWT", "OID4VCI_PRE_AUTH", Some("OB3_JWT")) => (
            "Open Badges JWT Wallet",
            "Derived compatibility profile for Open Badges JWT credentials.",
            &["1EdTech Open Badge Passport", "Learning Credential Wallet"],
            &["Open Badges 3.0", "OID4VCI"],
            &["ios", "android", "web"],
        ),
        ("JSON_LD", "OID4VCI_PRE_AUTH", Some("OB3_JSONLD")) => (
            "Open Badges JSON-LD Wallet",
            "Derived compatibility profile for Open Badges JSON-LD credentials.",
            &["1EdTech Open Badge Passport", "DIF Universal Wallet"],
            &["Open Badges 3.0", "VC Data Model", "OID4VCI"],
            &["ios", "android", "web"],
        ),
        ("VC_JWT", "OID4VCI_PRE_AUTH", Some("ENTERPRISE_VC")) => (
            "Enterprise VC Wallet",
            "Derived compatibility profile for enterprise-managed VC JWT credentials.",
            &["Organization-managed wallets"],
            &["VC JWT", "OID4VCI"],
            &["ios", "android", "web"],
        ),
        _ => return None,
    };
    Some(DerivedWalletProfile {
        credential_format: format.to_owned(),
        issuance_protocol: protocol.to_owned(),
        compliance_profile_code: compliance.map(str::to_owned),
        name: values.0.to_owned(),
        description: values.1.to_owned(),
        wallet_apps: strings(values.2),
        specifications: strings(values.3),
        supported_platforms: strings(values.4),
        deep_link_pattern: "openid-credential-offer://?credential_offer_uri={offer_uri}".to_owned(),
    })
}

fn merge_unique(target: &mut Vec<String>, extra: &[String]) {
    for value in extra {
        if !target.contains(value) {
            target.push(value.clone());
        }
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}
