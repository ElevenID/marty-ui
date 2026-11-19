//! OID4VP-backed delegated proof verification.
//!
//! Reuses Marty Core's OID4VP JWT VP proof verifier and Marty Verification's
//! RFC 7638 JWK thumbprint implementation. Challenge issuance/storage is
//! supplied by the existing Flow/session owner; this module never invents
//! request URLs, nonce persistence, signing keys or protocol paths.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use marty_oid4vci::verifier::VerificationEngine;
use marty_verification::jwk::Jwk;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    BindingMethod, DelegateProofError, DelegateProofVerifier, DelegationGrant,
    DelegationUseRequest, MAX_DELEGATE_PROOF_BYTES,
};

const MAX_CHALLENGE_BYTES: usize = 256;
const MIN_NONCE_CHARS: usize = 22;
const MAX_CLOCK_SKEW_SECONDS: i64 = 30;

/// Authoritative OID4VP challenge state resolved by its opaque ID. Implementations
/// must scope reads to the authenticated organization and grant, and only return
/// challenges created from the active Flow's configured verifier authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DelegationOid4vpChallenge {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub grant_id: Uuid,
    pub grant_revision: u64,
    /// OID4VP nonce from the signed authorization request.
    pub nonce: String,
    /// OID4VP verifier client identifier / expected VP audience.
    pub audience: String,
    pub expires_at: DateTime<Utc>,
    /// Required for SESSION grants and matched to the grant's exact binding.
    pub session_ref: Option<String>,
    pub establishment_evidence_ref: Option<String>,
    /// Thumbprint of the key established by the session evidence.
    pub session_key_thumbprint: Option<String>,
}

/// Challenge lookup port backed by Flow's authoritative OID4VP session state.
/// The final-use transaction, not this read-only verifier, must atomically
/// consume the challenge together with the current grant revision and replay
/// reservation. This prevents evaluation from consuming a challenge before the
/// external domain operation is ready to commit.
#[async_trait]
pub trait DelegationOid4vpChallengeStore: Send + Sync {
    async fn load_active(
        &self,
        organization_id: Uuid,
        grant_id: Uuid,
        challenge_id: Uuid,
    ) -> Result<DelegationOid4vpChallenge, DelegationOid4vpChallengeStoreError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("OID4VP challenge is unavailable or already consumed")]
pub struct DelegationOid4vpChallengeStoreError;

/// Production adapter over the pinned Marty Core OID4VP verifier. The challenge
/// store is deliberately injected: Flow remains the owner of protocol session,
/// nonce lifecycle, signed request construction and endpoint configuration.
#[derive(Clone)]
pub struct MartyOid4vpDelegateProofVerifier {
    challenges: Arc<dyn DelegationOid4vpChallengeStore>,
    max_proof_age: Duration,
}

impl MartyOid4vpDelegateProofVerifier {
    pub fn new(
        challenges: Arc<dyn DelegationOid4vpChallengeStore>,
        max_proof_age_seconds: i64,
    ) -> Result<Self, DelegateProofError> {
        if !(30..=600).contains(&max_proof_age_seconds) {
            return Err(DelegateProofError);
        }
        Ok(Self {
            challenges,
            max_proof_age: Duration::seconds(max_proof_age_seconds),
        })
    }
}

#[async_trait]
impl DelegateProofVerifier for MartyOid4vpDelegateProofVerifier {
    async fn verify(
        &self,
        grant: &DelegationGrant,
        request: &DelegationUseRequest,
        now: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, DelegateProofError> {
        if request.proof.len() > MAX_DELEGATE_PROOF_BYTES {
            return Err(DelegateProofError);
        }
        let compact_vp = std::str::from_utf8(&request.proof).map_err(|_| DelegateProofError)?;
        if compact_vp.trim() != compact_vp || compact_vp.is_empty() {
            return Err(DelegateProofError);
        }

        let challenge = self
            .challenges
            .load_active(
                request.organization_id,
                request.grant_id,
                request.challenge_id,
            )
            .await
            .map_err(|_| DelegateProofError)?;
        validate_challenge(grant, request, &challenge, now)?;

        let evaluated_at = now.timestamp();
        let verified = VerificationEngine::new(request.audience.clone(), "")
            .verify_authenticated_vp_proof_at(compact_vp, &challenge.nonce, evaluated_at)
            .map_err(|_| DelegateProofError)?;

        let claims = verified.claims();
        let presentation = claims
            .get("vp")
            .and_then(serde_json::Value::as_object)
            .ok_or(DelegateProofError)?;
        let presentation_types = presentation
            .get("type")
            .and_then(serde_json::Value::as_array)
            .ok_or(DelegateProofError)?;
        if !presentation_types
            .iter()
            .any(|value| value.as_str() == Some("VerifiablePresentation"))
            || presentation
                .get("holder")
                .and_then(serde_json::Value::as_str)
                != Some(request.actor.id.as_str())
            || claims.get("iss").and_then(serde_json::Value::as_str)
                != Some(request.actor.id.as_str())
            || claims
                .get("sub")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|subject| subject != request.actor.id)
        {
            return Err(DelegateProofError);
        }
        let issued_at = claims
            .get("iat")
            .and_then(serde_json::Value::as_i64)
            .filter(|iat| *iat > 0 && *iat <= evaluated_at.saturating_add(MAX_CLOCK_SKEW_SECONDS))
            .ok_or(DelegateProofError)?;
        let expires_at = claims
            .get("exp")
            .and_then(serde_json::Value::as_i64)
            .filter(|exp| *exp > evaluated_at && *exp > issued_at)
            .ok_or(DelegateProofError)?;
        if evaluated_at.saturating_sub(issued_at) > self.max_proof_age.num_seconds()
            || expires_at.saturating_sub(issued_at) > self.max_proof_age.num_seconds()
        {
            return Err(DelegateProofError);
        }

        // Marty Core's RFC 7638 implementation calculates the canonical JWK
        // thumbprint; no parallel JOSE/JWK implementation is maintained here.
        let jwk_json =
            serde_json::to_string(verified.signer_public_jwk()).map_err(|_| DelegateProofError)?;
        let signer = Jwk::from_json(&jwk_json).map_err(|_| DelegateProofError)?;
        let signer_thumbprint = format!(
            "sha256:{}",
            signer.thumbprint().map_err(|_| DelegateProofError)?
        );
        validate_signer_binding(grant, &challenge, &signer_thumbprint)?;

        let proof_deadline = DateTime::from_timestamp(expires_at, 0).ok_or(DelegateProofError)?;
        Ok(proof_deadline.min(challenge.expires_at))
    }
}

fn validate_challenge(
    grant: &DelegationGrant,
    request: &DelegationUseRequest,
    challenge: &DelegationOid4vpChallenge,
    now: DateTime<Utc>,
) -> Result<(), DelegateProofError> {
    if challenge.id != request.challenge_id
        || challenge.organization_id != request.organization_id
        || challenge.grant_id != request.grant_id
        || challenge.grant_revision != request.expected_revision
        || challenge.grant_revision != grant.revision
        || challenge.audience != request.audience
        || challenge.expires_at <= now
        || challenge.nonce.len() > MAX_CHALLENGE_BYTES
        || challenge.nonce.chars().count() < MIN_NONCE_CHARS
        || !challenge.nonce.is_ascii()
        || !challenge
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(DelegateProofError);
    }
    match grant.terms.binding.method {
        BindingMethod::Key => {
            if challenge.session_ref.is_some()
                || challenge.establishment_evidence_ref.is_some()
                || challenge.session_key_thumbprint.is_some()
            {
                return Err(DelegateProofError);
            }
        }
        BindingMethod::Session => {
            if challenge.session_ref.as_deref() != grant.terms.binding.session_ref.as_deref()
                || challenge.establishment_evidence_ref.as_deref()
                    != grant.terms.binding.establishment_evidence_ref.as_deref()
                || challenge.session_key_thumbprint.is_none()
            {
                return Err(DelegateProofError);
            }
        }
    }
    Ok(())
}

fn validate_signer_binding(
    grant: &DelegationGrant,
    challenge: &DelegationOid4vpChallenge,
    signer_thumbprint: &str,
) -> Result<(), DelegateProofError> {
    match grant.terms.binding.method {
        BindingMethod::Key => {
            if grant.terms.binding.key_thumbprint.as_deref() != Some(signer_thumbprint) {
                return Err(DelegateProofError);
            }
        }
        BindingMethod::Session => {
            if challenge.session_key_thumbprint.as_deref() != Some(signer_thumbprint) {
                return Err(DelegateProofError);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_support::pending_grant, Binding};

    #[test]
    fn challenge_requires_exact_grant_revision_audience_and_session_evidence() {
        let grant = pending_grant();
        let request = DelegationUseRequest {
            organization_id: grant.organization_id,
            grant_id: grant.id,
            expected_revision: grant.revision,
            challenge_id: Uuid::new_v4(),
            actor: grant.terms.delegate.clone(),
            action: grant.terms.actions[0].clone(),
            audience: grant.terms.audiences[0].clone(),
            resource: grant.terms.resources[0].clone(),
            operation_profile: "https://commerce.example/profiles/desk-lamp-purchase/v1".into(),
            operation_digest: format!("sha256:{}", "c".repeat(64)),
            proof: b"not-a-real-vp".to_vec(),
        };
        let now = grant.created_at + Duration::seconds(1);
        let challenge = DelegationOid4vpChallenge {
            id: request.challenge_id,
            organization_id: grant.organization_id,
            grant_id: grant.id,
            grant_revision: grant.revision,
            nonce: "A-single-use-OID4VP-nonce-123456".into(),
            audience: request.audience.clone(),
            expires_at: now + Duration::minutes(2),
            session_ref: grant.terms.binding.session_ref.clone(),
            establishment_evidence_ref: grant.terms.binding.establishment_evidence_ref.clone(),
            session_key_thumbprint: Some(format!("sha256:{}", "a".repeat(43))),
        };
        assert!(validate_challenge(&grant, &request, &challenge, now).is_ok());

        let mut wrong_revision = challenge.clone();
        wrong_revision.grant_revision += 1;
        assert!(validate_challenge(&grant, &request, &wrong_revision, now).is_err());

        let mut wrong_audience = challenge.clone();
        wrong_audience.audience = "https://attacker.example".into();
        assert!(validate_challenge(&grant, &request, &wrong_audience, now).is_err());

        let mut wrong_session = challenge;
        wrong_session.establishment_evidence_ref =
            Some("https://identity.example/evidence/other".into());
        assert!(validate_challenge(&grant, &request, &wrong_session, now).is_err());
    }

    #[test]
    fn signer_binding_uses_rfc7638_thumbprint_and_exact_session_key() {
        let mut grant = pending_grant();
        let challenge = DelegationOid4vpChallenge {
            id: Uuid::new_v4(),
            organization_id: grant.organization_id,
            grant_id: grant.id,
            grant_revision: grant.revision,
            nonce: "A-single-use-OID4VP-nonce-123456".into(),
            audience: grant.terms.audiences[0].clone(),
            expires_at: grant.terms.valid_until,
            session_ref: grant.terms.binding.session_ref.clone(),
            establishment_evidence_ref: grant.terms.binding.establishment_evidence_ref.clone(),
            session_key_thumbprint: Some(format!("sha256:{}", "a".repeat(43))),
        };
        let thumbprint = challenge.session_key_thumbprint.clone().unwrap();
        assert!(validate_signer_binding(&grant, &challenge, &thumbprint).is_ok());
        assert!(validate_signer_binding(&grant, &challenge, "sha256:wrong").is_err());

        grant.terms.binding = Binding {
            method: BindingMethod::Key,
            key_thumbprint: Some(thumbprint.clone()),
            session_ref: None,
            establishment_evidence_ref: None,
        };
        assert!(validate_signer_binding(&grant, &challenge, &thumbprint).is_ok());
    }
}
