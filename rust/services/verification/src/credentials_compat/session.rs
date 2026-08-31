use std::{fmt, time::Duration};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::NaiveDateTime;
use rand::RngCore;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{PersistedEvidence, PersistedEvidenceError};

const SECRET_BYTES: usize = 32;
const ENCODED_NONCE_LENGTH: usize = 43;
const MIN_PROCESSING_LEASE_SECONDS: u64 = 5;
const MAX_PROCESSING_LEASE_SECONDS: u64 = 300;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SessionInvariantError {
    #[error("SHA-256 digest must contain exactly 64 lowercase hexadecimal characters")]
    Digest,
    #[error("verifier nonce must contain exactly 43 ASCII characters")]
    Nonce,
    #[error("processing token must be a non-empty ASCII secret")]
    ProcessingToken,
    #[error("processing lease must be between 5 and 300 seconds")]
    ProcessingLease,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    #[must_use]
    pub fn calculate(input: impl AsRef<[u8]>) -> Self {
        Self(format!("{:x}", Sha256::digest(input.as_ref())))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, SessionInvariantError> {
        let value = value.into();
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(SessionInvariantError::Digest)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifierNonce(String);

impl VerifierNonce {
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0_u8; SECRET_BYTES];
        rand::rng().fill_bytes(&mut bytes);
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, SessionInvariantError> {
        let value = value.into();
        let decoded = URL_SAFE_NO_PAD
            .decode(&value)
            .map_err(|_| SessionInvariantError::Nonce)?;
        if value.len() != ENCODED_NONCE_LENGTH
            || decoded.len() != SECRET_BYTES
            || URL_SAFE_NO_PAD.encode(decoded) != value
        {
            return Err(SessionInvariantError::Nonce);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for VerifierNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifierNonce([REDACTED])")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProcessingToken(String);

impl ProcessingToken {
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0_u8; SECRET_BYTES];
        rand::rng().fill_bytes(&mut bytes);
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, SessionInvariantError> {
        let value = value.into();
        if !value.is_empty() && value.is_ascii() {
            Ok(Self(value))
        } else {
            Err(SessionInvariantError::ProcessingToken)
        }
    }

    #[must_use]
    pub(crate) fn digest(&self) -> Sha256Digest {
        Sha256Digest::calculate(self.0.as_bytes())
    }
}

impl fmt::Debug for ProcessingToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProcessingToken([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessingLease(Duration);

impl ProcessingLease {
    pub fn from_seconds(seconds: u64) -> Result<Self, SessionInvariantError> {
        if (MIN_PROCESSING_LEASE_SECONDS..=MAX_PROCESSING_LEASE_SECONDS).contains(&seconds) {
            Ok(Self(Duration::from_secs(seconds)))
        } else {
            Err(SessionInvariantError::ProcessingLease)
        }
    }

    #[must_use]
    pub const fn seconds(self) -> u64 {
        self.0.as_secs()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionStatus {
    Pending,
    InProgress,
    Verified,
    Failed,
    Expired,
}

impl SessionStatus {
    #[must_use]
    pub const fn as_database_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::InProgress => "IN_PROGRESS",
            Self::Verified => "VERIFIED",
            Self::Failed => "FAILED",
            Self::Expired => "EXPIRED",
        }
    }

    pub(crate) fn parse_database(value: &str) -> Option<Self> {
        match value.to_ascii_uppercase().as_str() {
            "PENDING" => Some(Self::Pending),
            "IN_PROGRESS" => Some(Self::InProgress),
            "VERIFIED" => Some(Self::Verified),
            "FAILED" => Some(Self::Failed),
            "EXPIRED" => Some(Self::Expired),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationMethod {
    W3cVc,
    SdJwt,
    Mdoc,
    ZkProof,
    JwtVp,
}

impl VerificationMethod {
    #[must_use]
    pub const fn as_database_str(self) -> &'static str {
        match self {
            Self::W3cVc => "W3C_VC",
            Self::SdJwt => "SD_JWT",
            Self::Mdoc => "MDOC",
            Self::ZkProof => "ZK_PROOF",
            Self::JwtVp => "JWT_VP",
        }
    }

    pub(crate) fn parse_database(value: &str) -> Option<Self> {
        match value.to_ascii_uppercase().as_str() {
            "W3C_VC" => Some(Self::W3cVc),
            "SD_JWT" => Some(Self::SdJwt),
            "MDOC" => Some(Self::Mdoc),
            "ZK_PROOF" => Some(Self::ZkProof),
            "JWT_VP" => Some(Self::JwtVp),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SessionDraft {
    pub id: String,
    pub organization_id: String,
    pub verifier_did: String,
    pub presentation_definition: Value,
    pub required_credential_types: Vec<String>,
    pub trusted_issuers: Vec<String>,
    pub required_claims: Vec<String>,
    pub verification_evidence: PersistedEvidence,
    pub request_uri: String,
    pub nonce: VerifierNonce,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SessionRecord {
    pub id: String,
    pub organization_id: String,
    pub verifier_did: String,
    pub presentation_definition: Value,
    pub status: SessionStatus,
    pub required_credential_types: Vec<String>,
    pub trusted_issuers: Vec<String>,
    pub required_claims: Vec<String>,
    pub verification_evidence: PersistedEvidence,
    pub verification_method: Option<VerificationMethod>,
    pub verified_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub expires_at: Option<NaiveDateTime>,
    pub error_message: Option<String>,
    pub request_uri: Option<String>,
    pub nonce: Option<VerifierNonce>,
    pub submission_sha256: Option<Sha256Digest>,
    pub processing_started_at: Option<NaiveDateTime>,
    pub processing_expires_at: Option<NaiveDateTime>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TerminalDecision(TerminalDecisionKind);

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum TerminalDecisionKind {
    Verified {
        verification_evidence: PersistedEvidence,
        method: VerificationMethod,
    },
    Failed {
        verification_evidence: PersistedEvidence,
        method: Option<VerificationMethod>,
        error_message: String,
    },
}

impl TerminalDecision {
    pub fn verified(
        verification_evidence: PersistedEvidence,
        method: VerificationMethod,
    ) -> Result<Self, PersistedEvidenceError> {
        verification_evidence.require_verified()?;
        Ok(Self(TerminalDecisionKind::Verified {
            verification_evidence,
            method,
        }))
    }

    pub fn failed(
        verification_evidence: PersistedEvidence,
        method: Option<VerificationMethod>,
        error_message: String,
    ) -> Result<Self, PersistedEvidenceError> {
        verification_evidence.require_failed()?;
        Ok(Self(TerminalDecisionKind::Failed {
            verification_evidence,
            method,
            error_message,
        }))
    }

    #[must_use]
    pub const fn status(&self) -> SessionStatus {
        match self.0 {
            TerminalDecisionKind::Verified { .. } => SessionStatus::Verified,
            TerminalDecisionKind::Failed { .. } => SessionStatus::Failed,
        }
    }

    pub(crate) fn into_kind(self) -> TerminalDecisionKind {
        self.0
    }

    pub(crate) fn validate_session(
        &self,
        current: &SessionRecord,
        presentation_digest: &Sha256Digest,
    ) -> Result<(), PersistedEvidenceError> {
        let evidence = match &self.0 {
            TerminalDecisionKind::Verified {
                verification_evidence,
                ..
            }
            | TerminalDecisionKind::Failed {
                verification_evidence,
                ..
            } => verification_evidence,
        };
        evidence.validate_terminal_binding(&current.id, presentation_digest)?;
        evidence.validate_session_authority(
            &current.verification_evidence,
            &current.organization_id,
            &current.verifier_did,
            &current.presentation_definition,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimState {
    Claimed,
    Finalized,
    Terminal,
    Busy,
    Conflict,
    Stale,
    Expired,
    NotFound,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SubmissionClaim {
    pub state: ClaimState,
    pub session: Option<SessionRecord>,
    pub verifier_nonce: Option<VerifierNonce>,
}

impl SubmissionClaim {
    #[must_use]
    pub const fn state(state: ClaimState) -> Self {
        Self {
            state,
            session: None,
            verifier_nonce: None,
        }
    }

    #[must_use]
    pub const fn session(state: ClaimState, session: SessionRecord) -> Self {
        Self {
            state,
            session: Some(session),
            verifier_nonce: None,
        }
    }

    #[must_use]
    pub const fn claimed(session: SessionRecord, verifier_nonce: VerifierNonce) -> Self {
        Self {
            state: ClaimState::Claimed,
            session: Some(session),
            verifier_nonce: Some(verifier_nonce),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Map;

    use super::*;

    #[test]
    fn secrets_are_validated_generated_and_redacted() {
        let nonce = VerifierNonce::generate();
        let token = ProcessingToken::generate();
        assert_eq!(nonce.as_str().len(), 43);
        assert_eq!(format!("{nonce:?}"), "VerifierNonce([REDACTED])");
        assert_eq!(format!("{token:?}"), "ProcessingToken([REDACTED])");
        assert_eq!(token.digest().as_str().len(), 64);
        assert!(VerifierNonce::parse("short").is_err());
        assert!(ProcessingToken::parse("").is_err());
        assert!(ProcessingToken::parse("not-ascii-é").is_err());
    }

    #[test]
    fn digests_and_leases_fail_closed_at_construction() {
        assert!(Sha256Digest::parse("a".repeat(64)).is_ok());
        assert!(Sha256Digest::parse("A".repeat(64)).is_err());
        assert!(Sha256Digest::parse("a".repeat(63)).is_err());
        assert!(ProcessingLease::from_seconds(5).is_ok());
        assert!(ProcessingLease::from_seconds(300).is_ok());
        assert!(ProcessingLease::from_seconds(4).is_err());
        assert!(ProcessingLease::from_seconds(301).is_err());
    }

    #[test]
    fn terminal_decisions_cannot_represent_nonterminal_states_or_raw_presentations() {
        let evidence = PersistedEvidence::from_database(Value::Object(Map::new()));
        assert_eq!(
            TerminalDecision::verified(evidence.clone(), VerificationMethod::JwtVp),
            Err(PersistedEvidenceError::CanonicalPassRequired)
        );
        assert_eq!(
            TerminalDecision::failed(evidence, Some(VerificationMethod::JwtVp), "failed".into()),
            Err(PersistedEvidenceError::InvalidTerminalEvidence)
        );
        assert_eq!(
            SessionStatus::parse_database("verified"),
            Some(SessionStatus::Verified)
        );
        assert_eq!(
            VerificationMethod::parse_database("jwt_vp"),
            Some(VerificationMethod::JwtVp)
        );
    }

    #[test]
    fn nonce_requires_canonical_base64url_encoding_of_exactly_32_bytes() {
        for invalid in [
            " ".repeat(43),
            "!".repeat(43),
            URL_SAFE_NO_PAD.encode([0_u8; 31]),
            URL_SAFE_NO_PAD.encode([0_u8; 33]),
            format!("{}=", URL_SAFE_NO_PAD.encode([0_u8; 32])),
        ] {
            assert!(VerifierNonce::parse(invalid).is_err());
        }
        let canonical = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        assert_eq!(
            VerifierNonce::parse(&canonical).unwrap().as_str(),
            canonical
        );
    }
}
