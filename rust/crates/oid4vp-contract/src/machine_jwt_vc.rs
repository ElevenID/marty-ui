//! Internal owner contracts for the explicitly selected nested machine JWT VC.
//!
//! These records describe owner observations, not credential authentication or
//! bearer authority. Only the configured Trust Profile and Issuance owners may
//! supply them. The machine verifier still authenticates the original token.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub const MACHINE_NESTED_JWT_PROFILE: &str = "marty_nested_vc2_jwt_v1";
pub const MACHINE_NESTED_JWT_AUTHORIZATIONS: &str = "marty_nested_vc2_jwt_v1_authorizations";
pub const MACHINE_JWT_SOURCE_MAX_AGE_SECONDS: i64 = 30;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MachineJwtVcOwnerError {
    #[error("MACHINE_JWT_VC.INVALID_REQUEST")]
    InvalidRequest,
    #[error("MACHINE_JWT_VC.OWNER_RECORD_NOT_FOUND")]
    NotFound,
    #[error("MACHINE_JWT_VC.UNSUPPORTED_OWNER_RECORD")]
    Unsupported,
    #[error("MACHINE_JWT_VC.OWNER_UNAVAILABLE")]
    Unavailable,
}

/// The digest binds the complete machine/grant/nonce/operation scope. All other
/// members select independently persisted owner records; none is a fetch URL.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineJwtVcOwnerSelection {
    pub organization_id: Uuid,
    pub trust_profile_id: Uuid,
    pub credential_id: Uuid,
    pub credential_digest: String,
    pub issuer: String,
    pub subject: String,
    pub verification_method_id: String,
    pub algorithm: String,
    pub scope_digest: String,
}

impl MachineJwtVcOwnerSelection {
    pub fn validate(&self) -> Result<(), MachineJwtVcOwnerError> {
        if self.organization_id.is_nil()
            || self.trust_profile_id.is_nil()
            || self.credential_id.is_nil()
            || !valid_digest(&self.credential_digest)
            || !valid_digest(&self.scope_digest)
            || !bounded_text(&self.issuer, 2_048)
            || !bounded_text(&self.subject, 2_048)
            || !bounded_text(&self.verification_method_id, 2_048)
            || !matches!(self.algorithm.as_str(), "ES256" | "EdDSA")
        {
            return Err(MachineJwtVcOwnerError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MachineJwtVcLifecycleState {
    Active,
    Suspended,
    Revoked,
}

/// Exact Issuance-owned artifact and transaction correspondence. Raw credential
/// bytes remain at Issuance. Negative lifecycle observations are retained as
/// negative facts and can never be converted into a positive machine proof.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineJwtVcStatusObservation {
    pub selection: MachineJwtVcOwnerSelection,
    pub securing_profile: String,
    pub transaction_id: String,
    pub credential_template_id: String,
    pub credential_types: Vec<String>,
    pub state: MachineJwtVcLifecycleState,
    pub status_updated_at: DateTime<Utc>,
    pub issued_at: DateTime<Utc>,
    pub credential_expires_at: DateTime<Utc>,
    pub signature_expires_at: DateTime<Utc>,
    pub signature_not_before: Option<DateTime<Utc>>,
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

impl MachineJwtVcStatusObservation {
    pub fn validate_for(
        &self,
        selection: &MachineJwtVcOwnerSelection,
        now: DateTime<Utc>,
    ) -> Result<(), MachineJwtVcOwnerError> {
        selection.validate()?;
        validate_types(&self.credential_types)?;
        validate_window(self.observed_at, self.valid_until, now)?;
        if self.selection != *selection
            || self.securing_profile != MACHINE_NESTED_JWT_PROFILE
            || !bounded_text(&self.transaction_id, 255)
            || !bounded_text(&self.credential_template_id, 255)
            || !self
                .credential_types
                .iter()
                .any(|kind| kind == "VerifiableCredential")
            || self.credential_types.len() < 2
            || self.status_updated_at > self.observed_at
            || self.issued_at > self.status_updated_at
            || self.valid_until > self.credential_expires_at
            || self.valid_until > self.signature_expires_at
            || self
                .signature_not_before
                .is_some_and(|time| time > self.observed_at)
        {
            return Err(MachineJwtVcOwnerError::Unsupported);
        }
        Ok(())
    }
}

/// The exact owner decision graph is retained with the aggregate observation.
/// It contains public keys and administrative configuration, never a credential
/// or bearer presentation. The source audit is private, independently protected.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineJwtVcTrustObservation {
    pub selection: MachineJwtVcOwnerSelection,
    pub securing_profile: String,
    pub credential_types: Vec<String>,
    pub profile_revision: u64,
    pub profile_digest: String,
    pub authority_basis: Value,
    pub issuer_public_jwk: Value,
    pub authorized_credential_types: Vec<String>,
    pub require_not_before: bool,
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

impl MachineJwtVcTrustObservation {
    pub fn validate_for(
        &self,
        selection: &MachineJwtVcOwnerSelection,
        credential_types: &[String],
        now: DateTime<Utc>,
    ) -> Result<(), MachineJwtVcOwnerError> {
        selection.validate()?;
        validate_types(credential_types)?;
        validate_types(&self.authorized_credential_types)?;
        validate_window(self.observed_at, self.valid_until, now)?;
        if self.selection != *selection
            || self.securing_profile != MACHINE_NESTED_JWT_PROFILE
            || self.credential_types != credential_types
            || !(1..=9_007_199_254_740_991).contains(&self.profile_revision)
            || !valid_digest(&self.profile_digest)
            || !self.authority_basis.is_object()
            || serde_json::to_vec(&self.authority_basis)
                .map_err(|_| MachineJwtVcOwnerError::Unsupported)?
                .len()
                > 2_097_152
            || !self.issuer_public_jwk.is_object()
            || self.issuer_public_jwk.get("kid").and_then(Value::as_str)
                != Some(selection.verification_method_id.as_str())
            || credential_types
                .iter()
                .filter(|kind| kind.as_str() != "VerifiableCredential")
                .any(|kind| !self.authorized_credential_types.contains(kind))
        {
            return Err(MachineJwtVcOwnerError::Unsupported);
        }
        Ok(())
    }
}

/// This namespace is independent from SD-JWT VCT and wallet-issuance grants.
/// Existing trusted-issuer create/edit permissions own this metadata. Missing
/// metadata is an empty grant list; broad issuer trust supplies no implicit type.
pub fn nested_machine_credential_authorizations(
    metadata: &Value,
) -> Result<Vec<String>, MachineJwtVcOwnerError> {
    let Some(value) = metadata
        .as_object()
        .and_then(|m| m.get(MACHINE_NESTED_JWT_AUTHORIZATIONS))
    else {
        return Ok(Vec::new());
    };
    let types: Vec<String> =
        serde_json::from_value(value.clone()).map_err(|_| MachineJwtVcOwnerError::Unsupported)?;
    if types.is_empty() {
        return Ok(types);
    }
    validate_types(&types)?;
    if types.iter().any(|kind| kind == "VerifiableCredential") {
        return Err(MachineJwtVcOwnerError::Unsupported);
    }
    let mut types = types;
    types.sort();
    Ok(types)
}

pub fn validate_types(types: &[String]) -> Result<(), MachineJwtVcOwnerError> {
    if types.is_empty()
        || types.len() > 32
        || types.iter().any(|kind| !bounded_text(kind, 256))
        || types.iter().collect::<BTreeSet<_>>().len() != types.len()
    {
        return Err(MachineJwtVcOwnerError::Unsupported);
    }
    Ok(())
}

pub fn validate_window(
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), MachineJwtVcOwnerError> {
    if observed_at > now
        || valid_until <= now
        || valid_until <= observed_at
        || valid_until
            > observed_at
                .checked_add_signed(Duration::seconds(MACHINE_JWT_SOURCE_MAX_AGE_SECONDS))
                .ok_or(MachineJwtVcOwnerError::Unavailable)?
    {
        return Err(MachineJwtVcOwnerError::Unavailable);
    }
    Ok(())
}

pub fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

pub fn bounded_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn selected_profile_grants_are_separate_strict_and_never_implicit() {
        assert!(nested_machine_credential_authorizations(&json!({
            "marty_credential_authorizations_v1":[{"format":"SD_JWT_VC","vct":"https://example.test/type"}]
        })).unwrap().is_empty());
        assert_eq!(
            nested_machine_credential_authorizations(&json!({
                MACHINE_NESTED_JWT_AUTHORIZATIONS:["MachineCredential", "EmployeeCredential"]
            }))
            .unwrap(),
            ["EmployeeCredential", "MachineCredential"]
        );
        for bad in [
            json!(null),
            json!({"allow":true}),
            json!(["Same", "Same"]),
            json!(["VerifiableCredential"]),
            json!(["bad\nvalue"]),
            json!(["x".repeat(257)]),
            json!((0..33).map(|i| format!("Type{i}")).collect::<Vec<_>>()),
        ] {
            assert!(nested_machine_credential_authorizations(
                &json!({MACHINE_NESTED_JWT_AUTHORIZATIONS:bad})
            )
            .is_err());
        }
    }
}
