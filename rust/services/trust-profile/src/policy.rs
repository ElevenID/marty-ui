use std::collections::BTreeSet;

use serde_json::{Map, Value};
use thiserror::Error;

use crate::IssuerEntityComplianceStatus;

use marty_issuer_key_resolution::custody::{
    contains_case_insensitive, find_private_custody_metadata, PRIVATE_CUSTODY_FIELDS,
    PRIVATE_JWK_PARAMETERS,
};

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
