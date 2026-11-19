//! OID4VP-backed delegated proof verification.
//!
//! Reuses Marty Core's OID4VP JWT VP proof verifier and Marty Verification's
//! RFC 7638 JWK thumbprint implementation. Challenge issuance/storage is
//! supplied by the existing Flow/session owner; this module never invents
//! request URLs, nonce persistence, signing keys or protocol paths.

use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use marty_oid4vci::verifier::VerificationEngine;
use marty_verification::jwk::Jwk;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use uuid::Uuid;

use crate::{
    domain::{valid_digest, valid_uri},
    BindingMethod, DelegateProofError, DelegateProofVerifier, DelegationGrant,
    DelegationUseRequest, Principal, MAX_DELEGATE_PROOF_BYTES, MAX_GRANT_REVISION,
};

const MAX_CHALLENGE_BYTES: usize = 256;
const MIN_NONCE_CHARS: usize = 22;
const MAX_CLOCK_SKEW_SECONDS: i64 = 30;
const MAX_VERIFIER_CLIENT_ID_BYTES: usize = 2_048;

/// Reserved Flow context key. Public Flow start/update inputs reject the
/// `_marty_` prefix, and public projections remove it recursively.
pub const DELEGATION_FLOW_CONTEXT_KEY: &str = "_marty_delegation_oid4vp_v1";

/// Immutable, Flow-owned binding between one OID4VP nonce and one delegated
/// operation. The authenticated Flow producer must populate this snapshot from
/// the resolved grant, exact operation and independently established session;
/// deserialization alone does not establish its authority. It must never be
/// copied from caller-supplied initial context or proof claims.
///
/// The snapshot is deliberately scoped to one Flow instance as well as its
/// tenant, grant revision and entire operation tuple. A broad grant cannot make
/// a proof for one operation usable for another in-scope operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationFlowContextV1 {
    pub challenge_id: Uuid,
    pub organization_id: Uuid,
    pub grant_id: Uuid,
    pub grant_revision: u64,
    pub actor: Principal,
    pub action: String,
    pub audience: String,
    pub resource: String,
    pub operation_profile: String,
    pub operation_digest: String,
    /// Required for SESSION grants and matched to the grant's exact binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub establishment_evidence_ref: Option<String>,
    /// Thumbprint of the key established by the session evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_key_thumbprint: Option<String>,
}

impl DelegationFlowContextV1 {
    pub fn validate(&self) -> Result<(), DelegationOid4vpChallengeStoreError> {
        if self.challenge_id.is_nil()
            || self.organization_id.is_nil()
            || self.grant_id.is_nil()
            || !(1..=MAX_GRANT_REVISION).contains(&self.grant_revision)
            || [
                &self.actor.id,
                &self.action,
                &self.audience,
                &self.resource,
                &self.operation_profile,
            ]
            .into_iter()
            .any(|value| !valid_uri(Some(value)))
            || !valid_digest(Some(&self.operation_digest))
        {
            return Err(DelegationOid4vpChallengeStoreError);
        }
        match (
            self.session_ref.as_deref(),
            self.establishment_evidence_ref.as_deref(),
            self.session_key_thumbprint.as_deref(),
        ) {
            (None, None, None) => Ok(()),
            (Some(session), Some(evidence), Some(thumbprint))
                if valid_uri(Some(session))
                    && valid_uri(Some(evidence))
                    && valid_digest(Some(thumbprint)) =>
            {
                Ok(())
            }
            _ => Err(DelegationOid4vpChallengeStoreError),
        }
    }
}

/// Authoritative OID4VP challenge state resolved by its opaque ID. Implementations
/// must scope reads to the authenticated organization and grant, and only return
/// challenges created from the active Flow's configured verifier authority.
/// This in-process result is not a caller-deserializable authorization object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationOid4vpChallenge {
    pub binding: DelegationFlowContextV1,
    /// Flow's configured OID4VP verifier, separate from the operation audience.
    pub verifier_client_id: String,
    /// OID4VP nonce from the signed authorization request.
    pub nonce: String,
    pub expires_at: DateTime<Utc>,
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
    ) -> Result<crate::VerifiedDelegateProof, DelegateProofError> {
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
        let verified = VerificationEngine::new(challenge.verifier_client_id.clone(), "")
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
            || presentation_types.iter().any(|value| !value.is_string())
            || claims
                .get("sub")
                .is_some_and(|subject| subject.as_str() != Some(request.actor.id.as_str()))
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
            || claims.get("nbf").is_some_and(|not_before| {
                not_before
                    .as_i64()
                    .is_none_or(|not_before| not_before > evaluated_at || not_before >= expires_at)
            })
        {
            return Err(DelegateProofError);
        }

        // Marty Core's RFC 7638 implementation calculates the canonical JWK
        // thumbprint; no parallel JOSE/JWK implementation is maintained here.
        let jwk_json =
            serde_json::to_string(verified.signer_public_jwk()).map_err(|_| DelegateProofError)?;
        let signer = Jwk::from_json(&jwk_json).map_err(|_| DelegateProofError)?;
        // RFC 7638 returns the SHA-256 thumbprint as base64url. The MIP
        // DelegationGrant digest vocabulary serializes that same 32-byte value
        // as lowercase hexadecimal after the sha256: prefix.
        let thumbprint = signer.thumbprint().map_err(|_| DelegateProofError)?;
        let thumbprint_bytes = URL_SAFE_NO_PAD
            .decode(thumbprint)
            .map_err(|_| DelegateProofError)?;
        if thumbprint_bytes.len() != 32 {
            return Err(DelegateProofError);
        }
        let signer_thumbprint = format!("sha256:{}", hex::encode(thumbprint_bytes));
        validate_signer_binding(grant, &challenge, &signer_thumbprint)?;

        let proof_deadline = DateTime::from_timestamp(expires_at, 0).ok_or(DelegateProofError)?;
        let digest = hex::encode(sha2::Sha256::digest(&request.proof));
        Ok(crate::VerifiedDelegateProof {
            evidence_ref: format!("urn:marty:oid4vp-proof:{digest}"),
            challenge: challenge.nonce,
            verified_at: now,
            valid_until: proof_deadline.min(challenge.expires_at),
        })
    }
}

fn validate_challenge(
    grant: &DelegationGrant,
    request: &DelegationUseRequest,
    challenge: &DelegationOid4vpChallenge,
    now: DateTime<Utc>,
) -> Result<(), DelegateProofError> {
    let binding = &challenge.binding;
    binding.validate().map_err(|_| DelegateProofError)?;
    if binding.challenge_id != request.challenge_id
        || binding.organization_id != request.organization_id
        || binding.organization_id != grant.organization_id
        || binding.grant_id != request.grant_id
        || binding.grant_id != grant.id
        || binding.grant_revision != request.expected_revision
        || binding.grant_revision != grant.revision
        || binding.actor != request.actor
        || binding.actor != grant.terms.delegate
        || binding.action != request.action
        || binding.audience != request.audience
        || binding.resource != request.resource
        || binding.operation_profile != request.operation_profile
        || binding.operation_digest != request.operation_digest
        // OID4VP identifiers such as decentralized_identifier:did:... are not
        // RFC 3986 URI schemes. Flow's canonical identity constructor owns
        // their format and authority. This trusted value remains opaque here;
        // Core compares it exactly to the authenticated JWT audience.
        || challenge.verifier_client_id.is_empty()
        || challenge.verifier_client_id.len() > MAX_VERIFIER_CLIENT_ID_BYTES
        || !challenge.verifier_client_id.bytes().all(|byte| byte.is_ascii_graphic())
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
            if binding.session_ref.is_some()
                || binding.establishment_evidence_ref.is_some()
                || binding.session_key_thumbprint.is_some()
            {
                return Err(DelegateProofError);
            }
        }
        BindingMethod::Session => {
            if binding.session_ref.as_deref() != grant.terms.binding.session_ref.as_deref()
                || binding.establishment_evidence_ref.as_deref()
                    != grant.terms.binding.establishment_evidence_ref.as_deref()
                || binding.session_key_thumbprint.is_none()
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
            if challenge.binding.session_key_thumbprint.as_deref() != Some(signer_thumbprint) {
                return Err(DelegateProofError);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_support::pending_grant, Binding, PrincipalType};
    use serde_json::{json, Value};

    fn vectors() -> Value {
        serde_json::from_str(include_str!(
            "../tests/fixtures/oid4vp-delegate-proofs.json"
        ))
        .unwrap()
    }

    fn fixture() -> (
        DelegationGrant,
        DelegationUseRequest,
        DelegationOid4vpChallenge,
        DateTime<Utc>,
    ) {
        let vectors = vectors();
        let grant = pending_grant();
        let now = DateTime::from_timestamp(vectors["evaluated_at"].as_i64().unwrap(), 0).unwrap();
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
            proof: vectors["vectors"]["valid"]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec(),
        };
        let challenge = DelegationOid4vpChallenge {
            binding: DelegationFlowContextV1 {
                challenge_id: request.challenge_id,
                organization_id: grant.organization_id,
                grant_id: grant.id,
                grant_revision: grant.revision,
                actor: request.actor.clone(),
                action: request.action.clone(),
                audience: request.audience.clone(),
                resource: request.resource.clone(),
                operation_profile: request.operation_profile.clone(),
                operation_digest: request.operation_digest.clone(),
                session_ref: grant.terms.binding.session_ref.clone(),
                establishment_evidence_ref: grant.terms.binding.establishment_evidence_ref.clone(),
                session_key_thumbprint: Some(vectors["signer_thumbprint"].as_str().unwrap().into()),
            },
            verifier_client_id: request.audience.clone(),
            nonce: vectors["nonce"].as_str().unwrap().into(),
            expires_at: now + Duration::minutes(2),
        };
        (grant, request, challenge, now)
    }

    struct FixedChallenge(DelegationOid4vpChallenge);

    #[async_trait]
    impl DelegationOid4vpChallengeStore for FixedChallenge {
        async fn load_active(
            &self,
            _organization_id: Uuid,
            _grant_id: Uuid,
            _challenge_id: Uuid,
        ) -> Result<DelegationOid4vpChallenge, DelegationOid4vpChallengeStoreError> {
            // Deliberately do not filter here: the adapter itself must reject a
            // foreign or mismatched snapshot, even from a faulty provider.
            Ok(self.0.clone())
        }
    }

    fn verifier(challenge: DelegationOid4vpChallenge) -> MartyOid4vpDelegateProofVerifier {
        MartyOid4vpDelegateProofVerifier::new(Arc::new(FixedChallenge(challenge)), 120).unwrap()
    }

    #[test]
    fn flow_context_rejects_incomplete_session_bindings_and_unknown_fields() {
        let (_, _, challenge, _) = fixture();
        let binding = challenge.binding;
        binding.validate().unwrap();
        for mask in 0..8 {
            let mut changed = binding.clone();
            if mask & 1 == 0 {
                changed.session_ref = None;
            }
            if mask & 2 == 0 {
                changed.establishment_evidence_ref = None;
            }
            if mask & 4 == 0 {
                changed.session_key_thumbprint = None;
            }
            assert_eq!(
                changed.validate().is_ok(),
                mask == 0 || mask == 7,
                "mask {mask}"
            );
        }
        let mut encoded = serde_json::to_value(&binding).unwrap();
        encoded["unchecked_authority"] = json!(true);
        assert!(serde_json::from_value::<DelegationFlowContextV1>(encoded).is_err());
        let mut encoded = serde_json::to_value(&binding).unwrap();
        encoded.as_object_mut().unwrap().remove("operation_digest");
        assert!(serde_json::from_value::<DelegationFlowContextV1>(encoded).is_err());
    }

    #[test]
    fn flow_context_rejects_nil_ids_invalid_revisions_uris_and_thumbprints() {
        let (_, _, challenge, _) = fixture();
        let mutations: &[fn(&mut DelegationFlowContextV1)] = &[
            |binding| binding.challenge_id = Uuid::nil(),
            |binding| binding.organization_id = Uuid::nil(),
            |binding| binding.grant_id = Uuid::nil(),
            |binding| binding.grant_revision = 0,
            |binding| binding.grant_revision = MAX_GRANT_REVISION + 1,
            |binding| binding.actor.id = "not-an-absolute-uri".into(),
            |binding| binding.action = "urn:action:*".into(),
            |binding| binding.audience = "https:// bad.example".into(),
            |binding| binding.resource = "relative/resource".into(),
            |binding| binding.operation_profile = "".into(),
            |binding| binding.operation_digest = format!("sha256:{}", "A".repeat(64)),
            |binding| binding.session_ref = Some("relative/session".into()),
            |binding| binding.establishment_evidence_ref = Some("relative/evidence".into()),
            |binding| binding.session_key_thumbprint = Some("sha256:wrong".into()),
        ];
        for mutate in mutations {
            let mut changed = challenge.binding.clone();
            mutate(&mut changed);
            assert!(changed.validate().is_err(), "invalid binding: {changed:?}");
        }
    }

    #[tokio::test]
    async fn signed_vp_verifies_exact_session_key_and_caps_deadline() {
        let (grant, request, mut challenge, now) = fixture();
        assert_eq!(
            verifier(challenge.clone())
                .verify(&grant, &request, now)
                .await
                .unwrap(),
            now + Duration::seconds(90),
        );
        challenge.expires_at = now + Duration::seconds(20);
        assert_eq!(
            verifier(challenge.clone())
                .verify(&grant, &request, now)
                .await
                .unwrap(),
            challenge.expires_at,
        );
        challenge.binding.session_key_thumbprint = Some(format!("sha256:{}", "b".repeat(64)));
        assert!(verifier(challenge)
            .verify(&grant, &request, now)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn signed_vp_verifies_key_binding_and_optional_subject() {
        let (mut grant, mut request, mut challenge, now) = fixture();
        grant.terms.binding = Binding {
            method: BindingMethod::Key,
            key_thumbprint: challenge.binding.session_key_thumbprint.take(),
            session_ref: None,
            establishment_evidence_ref: None,
        };
        grant.terms_digest = grant.calculate_terms_digest().unwrap();
        challenge.binding.session_ref = None;
        challenge.binding.establishment_evidence_ref = None;
        request.proof = vectors()["vectors"]["valid_without_subject"]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec();
        assert!(verifier(challenge.clone())
            .verify(&grant, &request, now)
            .await
            .is_ok());
        grant.terms.binding.key_thumbprint = Some(format!("sha256:{}", "b".repeat(64)));
        assert!(verifier(challenge)
            .verify(&grant, &request, now)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn real_verifier_rejects_signed_bad_claims_wrong_key_and_altered_signature() {
        let (grant, mut request, challenge, now) = fixture();
        let verifier = verifier(challenge);
        let vectors = vectors();
        for (name, token) in vectors["vectors"].as_object().unwrap() {
            if name.starts_with("valid") {
                continue;
            }
            request.proof = token.as_str().unwrap().as_bytes().to_vec();
            assert!(
                verifier.verify(&grant, &request, now).await.is_err(),
                "accepted {name}"
            );
        }
        let valid = vectors["vectors"]["valid"].as_str().unwrap();
        let (prefix, signature) = valid.rsplit_once('.').unwrap();
        let changed = if signature.starts_with('A') { 'B' } else { 'A' };
        request.proof = format!("{prefix}.{changed}{}", &signature[1..]).into_bytes();
        assert!(verifier.verify(&grant, &request, now).await.is_err());
        for malformed in [
            vec![0xff],
            b" a.b.c".to_vec(),
            vec![b'a'; MAX_DELEGATE_PROOF_BYTES + 1],
        ] {
            request.proof = malformed;
            assert!(verifier.verify(&grant, &request, now).await.is_err());
        }
    }

    #[tokio::test]
    async fn signed_proof_cannot_be_reused_for_another_operation_or_typed_actor() {
        let (grant, request, challenge, now) = fixture();
        let verifier = verifier(challenge);
        let mutations: &[fn(&mut DelegationUseRequest)] = &[
            |request| request.organization_id = Uuid::new_v4(),
            |request| request.grant_id = Uuid::new_v4(),
            |request| request.expected_revision += 1,
            |request| request.challenge_id = Uuid::new_v4(),
            |request| request.actor.id = "https://agents.example/agents/other".into(),
            |request| request.actor.principal_type = PrincipalType::User,
            |request| request.action = "urn:commerce:action:purchase.prepare".into(),
            |request| request.audience = "https://other.example".into(),
            |request| request.resource = "urn:commerce:product:other".into(),
            |request| request.operation_profile = "https://commerce.example/profiles/other".into(),
            |request| request.operation_digest = format!("sha256:{}", "d".repeat(64)),
        ];
        for mutate in mutations {
            let mut changed = request.clone();
            mutate(&mut changed);
            assert!(
                verifier.verify(&grant, &changed, now).await.is_err(),
                "accepted {changed:?}"
            );
        }
    }

    #[tokio::test]
    async fn protocol_verifier_audience_is_independent_from_the_operation_domain() {
        let (mut grant, mut request, mut challenge, now) = fixture();
        let operation_audience = "https://consuming-domain.example";
        grant.terms.audiences = vec![operation_audience.into()];
        grant.terms_digest = grant.calculate_terms_digest().unwrap();
        request.audience = operation_audience.into();
        challenge.binding.audience = operation_audience.into();
        assert_ne!(challenge.binding.audience, challenge.verifier_client_id);
        assert!(verifier(challenge.clone())
            .verify(&grant, &request, now)
            .await
            .is_ok());
        challenge.verifier_client_id = "https://another-verifier.example".into();
        assert!(verifier(challenge)
            .verify(&grant, &request, now)
            .await
            .is_err());
    }

    #[test]
    fn challenge_requires_live_nonce_and_exact_session_evidence() {
        let (grant, request, challenge, now) = fixture();
        assert!(validate_challenge(&grant, &request, &challenge, now).is_ok());
        let mutations: &[fn(&mut DelegationOid4vpChallenge)] = &[
            |challenge| challenge.verifier_client_id = String::new(),
            |challenge| challenge.verifier_client_id = "verifier with whitespace".into(),
            |challenge| challenge.verifier_client_id = "x".repeat(MAX_VERIFIER_CLIENT_ID_BYTES + 1),
            |challenge| challenge.nonce = "too-short".into(),
            |challenge| challenge.nonce = "x".repeat(MAX_CHALLENGE_BYTES + 1),
            |challenge| challenge.nonce = "non-ascii-nonce-établissement".into(),
            |challenge| challenge.nonce = "nonce-with-invalid-characters-!".into(),
            |challenge| challenge.binding.session_ref = Some("urn:session:other".into()),
            |challenge| {
                challenge.binding.establishment_evidence_ref = Some("urn:evidence:other".into())
            },
            |challenge| challenge.binding.session_key_thumbprint = None,
        ];
        for mutate in mutations {
            let mut changed = challenge.clone();
            mutate(&mut changed);
            assert!(validate_challenge(&grant, &request, &changed, now).is_err());
        }
        assert!(validate_challenge(&grant, &request, &challenge, challenge.expires_at).is_err());
        let mut wrong_grant = grant.clone();
        wrong_grant.organization_id = Uuid::new_v4();
        assert!(validate_challenge(&wrong_grant, &request, &challenge, now).is_err());
        wrong_grant = grant;
        wrong_grant.terms.delegate.principal_type = PrincipalType::User;
        assert!(validate_challenge(&wrong_grant, &request, &challenge, now).is_err());
    }
}
