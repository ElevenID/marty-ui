//! Privacy-minimized server-owned diagnostics for a rejected presentation attempt.
//! These values never authorize a credential, issuer, claim, or session.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Oid4vpContractError;

pub const AUTHENTICATION_DIAGNOSTIC: &str = "authentication_diagnostic";
pub const LAST_PRESENTATION_ATTEMPT: &str = "last_presentation_attempt";

pub fn authentication_binding_sha256(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificateTrustFailure {
    MissingTrustAnchors,
    InvalidTrustConfiguration,
    CertificateChainRejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MdocDiagnosticFormat {
    #[serde(rename = "mso_mdoc")]
    MsoMdoc,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MdocAuthenticationDiagnosticV1 {
    pub format: MdocDiagnosticFormat,
    pub document_count: u32,
    pub document_type: String,
    pub issuer_signature_valid: bool,
    pub certificate_trust_passed: bool,
    pub device_authentication_valid: bool,
    pub certificate_trust_failures: Vec<CertificateTrustFailure>,
    /// Fingerprint of a signature-verified certificate, NOT an accepted issuer.
    pub issuer_certificate_sha256: String,
}

impl MdocAuthenticationDiagnosticV1 {
    pub fn validate(&self) -> Result<(), Oid4vpContractError> {
        let failures = self
            .certificate_trust_failures
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        if self.document_count != 1
            || !self.issuer_signature_valid
            || self.document_type.is_empty()
            || self.document_type.len() > 256
            || self.document_type.chars().any(char::is_control)
            || !valid_digest(&self.issuer_certificate_sha256)
            || failures.len() != self.certificate_trust_failures.len()
            || self.certificate_trust_passed != self.certificate_trust_failures.is_empty()
        {
            return Err(Oid4vpContractError::InvalidField(
                "mdoc_authentication_diagnostic",
            ));
        }
        Ok(())
    }
}

/// Produced by policy evaluation; tied to the exact request, never a credential row.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundAuthenticationDiagnosticV1 {
    pub policy_id: String,
    pub nonce_sha256: String,
    pub vp_token_sha256: String,
    pub native_credential_count: u32,
    pub authentication: MdocAuthenticationDiagnosticV1,
}

impl BoundAuthenticationDiagnosticV1 {
    pub fn bind(
        policy_id: &str,
        nonce: &str,
        vp_token: &str,
        native_credential_count: u32,
        authentication: MdocAuthenticationDiagnosticV1,
    ) -> Result<Self, Oid4vpContractError> {
        let value = Self {
            policy_id: policy_id.into(),
            nonce_sha256: authentication_binding_sha256(nonce),
            vp_token_sha256: authentication_binding_sha256(vp_token),
            native_credential_count,
            authentication,
        };
        value.validate_request(policy_id, nonce, vp_token)?;
        Ok(value)
    }

    pub fn from_optional_json(
        input: &str,
        policy_id: &str,
        nonce: &str,
        vp_token: &str,
    ) -> Result<Option<Self>, Oid4vpContractError> {
        if input.trim().is_empty() || input.trim() == "null" {
            return Ok(None);
        }
        if input.len() > 4096 {
            return Err(Oid4vpContractError::InvalidField(AUTHENTICATION_DIAGNOSTIC));
        }
        let value: Self = serde_json::from_str(input)
            .map_err(|_| Oid4vpContractError::InvalidField(AUTHENTICATION_DIAGNOSTIC))?;
        value.validate_request(policy_id, nonce, vp_token)?;
        Ok(Some(value))
    }

    pub fn validate_request(
        &self,
        policy_id: &str,
        nonce: &str,
        vp_token: &str,
    ) -> Result<(), Oid4vpContractError> {
        self.authentication.validate()?;
        if self.native_credential_count != 1
            || policy_id.is_empty()
            || nonce.is_empty()
            || vp_token.is_empty()
            || self.policy_id != policy_id
            || self.nonce_sha256 != authentication_binding_sha256(nonce)
            || self.vp_token_sha256 != authentication_binding_sha256(vp_token)
        {
            return Err(Oid4vpContractError::BindingMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationAttemptOutcome {
    Rejected,
}

/// A retryable current-attempt result. It is not the session's terminal result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RejectedPresentationAttemptV1 {
    pub schema_version: u32,
    pub instance_id: String,
    pub policy_id: String,
    pub nonce_sha256: String,
    pub submission_digest: String,
    pub vp_token_sha256: String,
    pub native_credential_count: u32,
    pub outcome: PresentationAttemptOutcome,
    pub retryable: bool,
    pub observed_at: String,
    pub authentication: MdocAuthenticationDiagnosticV1,
}

impl RejectedPresentationAttemptV1 {
    pub fn new(
        instance_id: &str,
        submission_digest: &str,
        observed_at: &str,
        diagnostic: BoundAuthenticationDiagnosticV1,
    ) -> Result<Self, Oid4vpContractError> {
        let value = Self {
            schema_version: 1,
            instance_id: instance_id.into(),
            policy_id: diagnostic.policy_id,
            nonce_sha256: diagnostic.nonce_sha256,
            submission_digest: submission_digest.into(),
            vp_token_sha256: diagnostic.vp_token_sha256,
            native_credential_count: diagnostic.native_credential_count,
            outcome: PresentationAttemptOutcome::Rejected,
            retryable: true,
            observed_at: observed_at.into(),
            authentication: diagnostic.authentication,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), Oid4vpContractError> {
        self.authentication.validate()?;
        if self.schema_version != 1
            || !self.retryable
            || self.native_credential_count != 1
            || self.instance_id.is_empty()
            || self.policy_id.is_empty()
            || self.instance_id.len() > 256
            || self.policy_id.len() > 256
            || self.observed_at.is_empty()
            || self.observed_at.len() > 64
            || self.observed_at.chars().any(char::is_control)
            || !valid_digest(&self.nonce_sha256)
            || !valid_digest(&self.submission_digest)
            || !valid_digest(&self.vp_token_sha256)
        {
            return Err(Oid4vpContractError::InvalidField(
                "last_presentation_attempt",
            ));
        }
        Ok(())
    }

    pub fn matches_session(&self, instance_id: &str, policy_id: &str, nonce: &str) -> bool {
        self.validate().is_ok()
            && self.instance_id == instance_id
            && self.policy_id == policy_id
            && !nonce.is_empty()
            && self.nonce_sha256 == authentication_binding_sha256(nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn authentication() -> MdocAuthenticationDiagnosticV1 {
        MdocAuthenticationDiagnosticV1 {
            format: MdocDiagnosticFormat::MsoMdoc,
            document_count: 1,
            document_type: "org.iso.18013.5.1.mDL".into(),
            issuer_signature_valid: true,
            certificate_trust_passed: false,
            device_authentication_valid: true,
            certificate_trust_failures: vec![CertificateTrustFailure::CertificateChainRejected],
            issuer_certificate_sha256: "1".repeat(64),
        }
    }

    #[test]
    fn rejection_transport_refuses_nonce_policy_token_and_document_swaps() {
        let bound = BoundAuthenticationDiagnosticV1::bind(
            "policy-1",
            "nonce-1",
            "token-1",
            1,
            authentication(),
        )
        .unwrap();
        let json = serde_json::to_string(&bound).unwrap();
        assert_eq!(
            BoundAuthenticationDiagnosticV1::from_optional_json(
                &json, "policy-1", "nonce-1", "token-1"
            )
            .unwrap(),
            Some(bound.clone())
        );
        for (policy, nonce, token) in [
            ("policy-2", "nonce-1", "token-1"),
            ("policy-1", "nonce-2", "token-1"),
            ("policy-1", "nonce-1", "token-2"),
        ] {
            assert!(BoundAuthenticationDiagnosticV1::from_optional_json(
                &json, policy, nonce, token
            )
            .is_err());
        }
        for value in ["", "null"] {
            assert_eq!(
                BoundAuthenticationDiagnosticV1::from_optional_json(
                    value, "policy-1", "nonce-1", "token-1"
                )
                .unwrap(),
                None
            );
        }
        let mut changed = bound.clone();
        changed.native_credential_count = 2;
        assert!(changed
            .validate_request("policy-1", "nonce-1", "token-1")
            .is_err());
        let mut changed = bound;
        changed.authentication.document_count = 2;
        assert!(changed
            .validate_request("policy-1", "nonce-1", "token-1")
            .is_err());
    }

    #[test]
    fn rejection_diagnostic_never_promotes_bad_signatures_or_raw_claims() {
        let mut value = authentication();
        value.issuer_signature_valid = false;
        assert!(value.validate().is_err());
        let mut value = authentication();
        value.certificate_trust_passed = true;
        assert!(value.validate().is_err());
        let mut value = authentication();
        value.device_authentication_valid = false;
        assert!(value.validate().is_ok());
        let mut json = serde_json::to_value(authentication()).unwrap();
        json["claims"] = serde_json::json!({"secret":"value"});
        assert!(serde_json::from_value::<MdocAuthenticationDiagnosticV1>(json).is_err());
        let bound = BoundAuthenticationDiagnosticV1::bind(
            "policy-1",
            "nonce-1",
            "token-1",
            1,
            authentication(),
        )
        .unwrap();
        let attempt = RejectedPresentationAttemptV1::new(
            "instance-1",
            &"2".repeat(64),
            "2026-10-26T00:00:00Z",
            bound,
        )
        .unwrap();
        assert!(attempt.matches_session("instance-1", "policy-1", "nonce-1"));
        assert!(!attempt.matches_session("instance-2", "policy-1", "nonce-1"));
        assert!(!attempt.matches_session("instance-1", "policy-2", "nonce-1"));
        assert!(!attempt.matches_session("instance-1", "policy-1", "nonce-2"));
        let encoded = serde_json::to_string(&attempt).unwrap();
        assert!(!encoded.contains("token-1"));
        assert!(!encoded.contains("nonce-1"));
    }
}
