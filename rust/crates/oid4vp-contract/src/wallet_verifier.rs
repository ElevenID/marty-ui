//! Public wire registrations used by the gateway and the verifier trust owner.
use crate::Oid4vpContractError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredVerifier {
    pub client_id: String,
    pub request_key_id: String,
    pub public_jwk: Value,
    pub response_uris: Vec<String>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedFlowVerifier {
    /// Selects an operator-configured fixed owner transport; never an URL.
    pub producer_id: String,
    pub public_base_url: String,
    pub verifier_did: String,
    pub request_key_id: String,
    pub public_jwk: Value,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

fn invalid() -> Oid4vpContractError {
    Oid4vpContractError::InvalidField("wallet.verifier_registration")
}

fn text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn canonical_base(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    text(value)
        && !value.contains('*')
        && url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && !value.ends_with('/')
        && url.as_str().trim_end_matches('/') == value
}

fn validate_public_request_key(
    public_jwk: &Value,
    request_key_id: &str,
) -> Result<(), Oid4vpContractError> {
    if serde_json::to_vec(public_jwk).map_err(|_| invalid())?.len() > 2048 {
        return Err(invalid());
    }
    let jwk = public_jwk.as_object().ok_or_else(invalid)?;
    if jwk.keys().any(|key| {
        !["kty", "crv", "x", "y", "kid", "alg", "use", "key_ops"].contains(&key.as_str())
    }) || jwk
        .get("kid")
        .is_some_and(|kid| kid.as_str() != Some(request_key_id))
        || crate::trust_authority::issuer_public_key_algorithm(public_jwk).map_err(|_| invalid())?
            != "ES256"
    {
        return Err(invalid());
    }
    Ok(())
}

impl RegisteredVerifier {
    pub fn validate(&self) -> Result<(), Oid4vpContractError> {
        if !text(&self.client_id)
            || self.client_id.contains(':')
            || !text(&self.request_key_id)
            || self.valid_until <= self.valid_from
            || self.valid_from.timestamp_subsec_nanos() != 0
            || self.valid_until.timestamp_subsec_nanos() != 0
            || self.response_uris.is_empty()
            || self.response_uris.len() > 8
            || serde_json::to_vec(&self.public_jwk)
                .map_err(|_| invalid())?
                .len()
                > 2048
        {
            return Err(invalid());
        }
        validate_public_request_key(&self.public_jwk, &self.request_key_id)?;
        let mut recipients = BTreeSet::new();
        for uri in &self.response_uris {
            let url = url::Url::parse(uri).map_err(|_| invalid())?;
            if !text(uri)
                || url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
                || !recipients.insert(uri)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
impl ManagedFlowVerifier {
    pub fn validate(&self) -> Result<(), Oid4vpContractError> {
        if !text(&self.producer_id)
            || self.producer_id.len() > 128
            || !self
                .producer_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || !canonical_base(&self.public_base_url)
            || !text(&self.verifier_did)
            || !["did:web:", "did:jwk:", "did:key:"].iter().any(|prefix| {
                self.verifier_did
                    .strip_prefix(prefix)
                    .is_some_and(|value| !value.is_empty())
            })
            || self
                .verifier_did
                .chars()
                .any(|c| c.is_whitespace() || matches!(c, '?' | '#' | '/'))
            || !text(&self.request_key_id)
            || self
                .request_key_id
                .strip_prefix(&format!("{}#", self.verifier_did))
                .is_none_or(str::is_empty)
            || self.valid_until <= self.valid_from
            || self.valid_from.timestamp_subsec_nanos() != 0
            || self.valid_until.timestamp_subsec_nanos() != 0
        {
            return Err(invalid());
        }
        validate_public_request_key(&self.public_jwk, &self.request_key_id)?;
        Ok(())
    }
}
