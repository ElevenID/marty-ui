use std::collections::BTreeSet;

use serde_json::{Map, Value};
use thiserror::Error;

use crate::IssuerEntityComplianceStatus;

const PRIVATE_CUSTODY_FIELDS: &[&str] = &[
    "issuer_algorithm",
    "issuer_key_id",
    "issuer_profile_id",
    "key_access_mode",
    "key_binding",
    "key_management",
    "key_reference",
    "key_name",
    "key_version",
    "kms_arn",
    "kms_provider",
    "kms_region",
    "managed_key_id",
    "provider",
    "service_id",
    "signing_agent_auth",
    "signing_agent_url",
    "signing_key_reference",
    "signing_service_id",
    "transit_mount",
    "verification_method_id",
];
const PRIVATE_JWK_PARAMETERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TrustDomainError {
    #[error("TRUST_PROFILE.INVALID_ACCREDITATION: {0}")]
    InvalidAccreditation(String),
    #[error("TRUST_PROFILE.INVALID_JURISDICTION: {0}")]
    InvalidJurisdiction(String),
    #[error("TRUST_PROFILE.PRIVATE_CUSTODY_METADATA: {0}")]
    PrivateCustodyMetadata(String),
    #[error("TRUST_PROFILE.REVOKED_ISSUER_TERMINAL: revoked issuer cannot be reinstated")]
    RevokedIssuerTerminal,
}

pub fn normalize_accreditations(
    values: impl IntoIterator<Item = String>,
) -> Result<Vec<String>, TrustDomainError> {
    let mut normalized = Vec::new();
    let mut seen = BTreeSet::new();
    for value in values {
        let cleaned = value.trim();
        if cleaned.is_empty() {
            return Err(TrustDomainError::InvalidAccreditation(
                "accreditation identifiers cannot be blank".into(),
            ));
        }
        if cleaned.chars().count() > 128 {
            return Err(TrustDomainError::InvalidAccreditation(
                "accreditation identifiers cannot exceed 128 characters".into(),
            ));
        }
        if !seen.insert(cleaned.to_lowercase()) {
            return Err(TrustDomainError::InvalidAccreditation(
                "accreditation identifiers must be unique case-insensitively".into(),
            ));
        }
        normalized.push(cleaned.to_owned());
    }
    Ok(normalized)
}

pub fn normalize_jurisdictions(
    values: impl IntoIterator<Item = String>,
) -> Result<Vec<String>, TrustDomainError> {
    values
        .into_iter()
        .map(|value| {
            let normalized = value.to_uppercase();
            let mut parts = normalized.split('-');
            let country = parts.next().unwrap_or_default();
            let subdivision = parts.next();
            if parts.next().is_some()
                || country.len() != 2
                || !country
                    .chars()
                    .all(|character| character.is_ascii_alphabetic())
                || subdivision.is_some_and(|part| {
                    !(1..=3).contains(&part.len())
                        || !part
                            .chars()
                            .all(|character| character.is_ascii_alphanumeric())
                })
            {
                return Err(TrustDomainError::InvalidJurisdiction(value));
            }
            Ok(normalized)
        })
        .collect()
}

#[must_use]
pub fn allowed_issuers_after_request(
    current: Option<Vec<String>>,
    trust_source_count: usize,
    allowed_was_provided: bool,
    requested: Option<Vec<String>>,
    is_update: bool,
) -> Option<Vec<String>> {
    if allowed_was_provided {
        return requested;
    }
    if is_update {
        if trust_source_count == 0 && current.is_none() {
            return Some(Vec::new());
        }
        return current;
    }
    if trust_source_count == 0 {
        Some(Vec::new())
    } else {
        None
    }
}

pub fn reject_private_custody_metadata(value: &Value) -> Result<(), TrustDomainError> {
    find_private_custody_metadata(value).map_or(Ok(()), |field| {
        Err(TrustDomainError::PrivateCustodyMetadata(field))
    })
}

#[must_use]
pub fn sanitize_private_custody_metadata(value: &Value) -> Value {
    match value {
        Value::Object(values) => {
            let is_jwk = values.keys().any(|name| name.eq_ignore_ascii_case("kty"));
            Value::Object(
                values
                    .iter()
                    .filter(|(name, _)| {
                        !(contains_case_insensitive(PRIVATE_CUSTODY_FIELDS, name)
                            || is_jwk && contains_case_insensitive(PRIVATE_JWK_PARAMETERS, name))
                    })
                    .map(|(name, value)| (name.clone(), sanitize_private_custody_metadata(value)))
                    .collect::<Map<_, _>>(),
            )
        }
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(sanitize_private_custody_metadata)
                .collect(),
        ),
        _ => value.clone(),
    }
}

pub fn require_issuer_status_transition(
    current: IssuerEntityComplianceStatus,
    requested: IssuerEntityComplianceStatus,
) -> Result<(), TrustDomainError> {
    if current == IssuerEntityComplianceStatus::Revoked
        && requested != IssuerEntityComplianceStatus::Revoked
    {
        return Err(TrustDomainError::RevokedIssuerTerminal);
    }
    Ok(())
}

fn find_private_custody_metadata(value: &Value) -> Option<String> {
    match value {
        Value::Object(values) => {
            let is_jwk = values.keys().any(|name| name.eq_ignore_ascii_case("kty"));
            if is_jwk {
                if let Some(name) = values
                    .keys()
                    .find(|name| contains_case_insensitive(PRIVATE_JWK_PARAMETERS, name))
                {
                    return Some(format!("private JWK parameter '{name}'"));
                }
            }
            for (name, nested) in values {
                if contains_case_insensitive(PRIVATE_CUSTODY_FIELDS, name) {
                    return Some(name.clone());
                }
                if let Some(found) = find_private_custody_metadata(nested) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(values) => values.iter().find_map(find_private_custody_metadata),
        _ => None,
    }
}

fn contains_case_insensitive(values: &[&str], candidate: &str) -> bool {
    values
        .iter()
        .any(|value| value.eq_ignore_ascii_case(candidate))
}
