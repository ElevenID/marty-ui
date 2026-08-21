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
        template_wallet_configs: template.wallet_configs.clone(),
        created_at: primary.map_or(template.created_at, |item| item.created_at),
        updated_at: primary.map_or(template.updated_at, |item| item.updated_at),
    }
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
