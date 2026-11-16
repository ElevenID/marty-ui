//! Server-owned profile selection and native proof retention. Neither type has
//! a deserializer or a constructor accepting caller-provided verification facts.

use marty_oid4vci::{types::SigningAlgorithm, ResolvedSdJwtIssuerKey, TrustedSdJwtIssuerKeys};
use marty_oid4vp_contract::jwt_vc_profile::{profiled_jwt_vc_query, ProfiledJwtVcQuery};
use marty_oid4vp_contract::QueryKind;
use serde_json::Value;

use crate::{
    CredentialVerificationEvidence, EvaluatePresentationRequest, PresentationPolicy,
    PresentationVerificationError, ResolvedIssuerKey,
};

fn invalid() -> PresentationVerificationError {
    PresentationVerificationError::Failed(
        "PRESENTATION_POLICY.EXPLICIT_JWT_VC_BINDING_INVALID".into(),
    )
}

#[derive(Clone, PartialEq)]
pub struct ProfiledJwtVcRequest {
    query: ProfiledJwtVcQuery,
    query_digest: String,
    nonce: String,
    audience: String,
    evaluated_at: i64,
}

impl std::fmt::Debug for ProfiledJwtVcRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProfiledJwtVcRequest")
            .field("binding", &self.query.binding)
            .finish_non_exhaustive()
    }
}

impl ProfiledJwtVcRequest {
    pub(crate) fn prepare(
        policy: &PresentationPolicy,
        request: &EvaluatePresentationRequest,
        clock: impl FnOnce() -> u64,
    ) -> Result<Option<Self>, PresentationVerificationError> {
        let expected = policy
            .credential_requirements
            .iter()
            .chain(
                policy
                    .alternative_requirements
                    .iter()
                    .flat_map(|alternative| &alternative.credential_requirements),
            )
            .find_map(|requirement| requirement.expected_securing_profile);
        let query = request
            .oid4vp_transport
            .as_ref()
            .map(|transport| {
                profiled_jwt_vc_query(&transport.query_document).map_err(|_| invalid())
            })
            .transpose()?
            .flatten();
        if expected.is_none() && query.is_none() {
            if policy
                .credential_requirements
                .iter()
                .any(|requirement| requirement.credential_payload_format == "VC_JWT_DIRECT_V1")
            {
                return Err(invalid());
            }
            return Ok(None);
        }
        policy.validate().map_err(|_| invalid())?;
        let expected = expected.ok_or_else(invalid)?;
        let query = query.ok_or_else(invalid)?;
        let transport = request.oid4vp_transport.as_ref().ok_or_else(invalid)?;
        let requirement = policy.credential_requirements.first().ok_or_else(invalid)?;
        if !request.trusted_internal_context
            || transport.query_kind != QueryKind::Dcql
            || transport.presentation_submission.is_some()
            || query.binding.securing_profile() != expected
            || query.id != requirement.id.to_string()
            || transport.request_nonce.is_empty()
            || transport.verifier_client_id.is_empty()
            || request.nonce.as_deref() != Some(transport.request_nonce.as_str())
            || request.audience.as_deref() != Some(transport.verifier_client_id.as_str())
            || transport
                .associate_response()
                .map_err(|_| invalid())?
                .tokens
                .len()
                != 1
        {
            return Err(invalid());
        }
        let evaluated_at = i64::try_from(clock())
            .ok()
            .filter(|now| *now > 0)
            .ok_or_else(invalid)?;
        Ok(Some(Self {
            query,
            query_digest: transport.query_digest.clone(),
            nonce: transport.request_nonce.clone(),
            audience: transport.verifier_client_id.clone(),
            evaluated_at,
        }))
    }

    pub(crate) fn query(&self) -> &ProfiledJwtVcQuery {
        &self.query
    }
    pub(crate) fn nonce(&self) -> &str {
        &self.nonce
    }
    pub(crate) fn audience(&self) -> &str {
        &self.audience
    }
    pub(crate) fn evaluated_at(&self) -> i64 {
        self.evaluated_at
    }
}

pub(crate) fn pinned_keys(
    key: &ResolvedIssuerKey,
    kid: Option<String>,
    algorithm: SigningAlgorithm,
) -> Result<TrustedSdJwtIssuerKeys, PresentationVerificationError> {
    TrustedSdJwtIssuerKeys::new(vec![ResolvedSdJwtIssuerKey::new(
        key.issuer_id.clone(),
        kid,
        algorithm,
        serde_json::to_string(&key.public_jwk).map_err(|_| invalid())?,
    )])
    .map_err(|_| invalid())
}

#[derive(Clone, PartialEq)]
pub struct AuthenticatedProfiledJwtVcEvidence {
    request: ProfiledJwtVcRequest,
    raw_presentation: String,
    issuer_key: ResolvedIssuerKey,
    key_id: Option<String>,
    algorithm: SigningAlgorithm,
    credential_sha256: String,
    proof_issued_at: i64,
    authenticated_facts: Value,
}

impl std::fmt::Debug for AuthenticatedProfiledJwtVcEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedProfiledJwtVcEvidence")
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

impl AuthenticatedProfiledJwtVcEvidence {
    pub(crate) fn from_authenticated(
        request: ProfiledJwtVcRequest,
        raw_presentation: &str,
        issuer_key: ResolvedIssuerKey,
        proof: &marty_oid4vci::VerifiedProfiledJwtVcPresentation,
        evidence: &CredentialVerificationEvidence,
    ) -> Result<Self, PresentationVerificationError> {
        let credential = proof.credential();
        let algorithm = match credential.algorithm() {
            "ES256" => SigningAlgorithm::ES256,
            "ES384" => SigningAlgorithm::ES384,
            "EdDSA" => SigningAlgorithm::EdDSA,
            "RS256" => SigningAlgorithm::RS256,
            _ => return Err(invalid()),
        };
        Ok(Self {
            request,
            raw_presentation: raw_presentation.into(),
            issuer_key,
            key_id: credential.verification_method_id().map(str::to_owned),
            algorithm,
            credential_sha256: credential.credential_sha256().into(),
            proof_issued_at: proof.proof_issued_at(),
            authenticated_facts: serde_json::to_value(evidence).map_err(|_| invalid())?,
        })
    }

    pub(crate) fn matches(
        &self,
        request: &ProfiledJwtVcRequest,
        raw_presentation: &str,
        evidence: &CredentialVerificationEvidence,
    ) -> bool {
        &self.request == request
            && self.raw_presentation == raw_presentation
            && serde_json::to_value(evidence).ok().as_ref() == Some(&self.authenticated_facts)
    }

    pub(crate) fn binding(&self) -> marty_oid4vci::JwtVcProfileBinding {
        self.request.query.binding
    }

    pub(crate) fn revalidate_at(&self, now: u64) -> Result<(), PresentationVerificationError> {
        let now = i64::try_from(now).map_err(|_| invalid())?;
        let keys = pinned_keys(&self.issuer_key, self.key_id.clone(), self.algorithm)?;
        let proof = marty_oid4vci::verify_jwt_vc_presentation_with_profile(
            &self.raw_presentation,
            &keys,
            &self.request.nonce,
            &self.request.audience,
            now,
            self.binding().securing_profile(),
        )
        .map_err(|_| invalid())?;
        if proof.binding() != self.binding()
            || proof.credential().credential_sha256() != self.credential_sha256
            || proof.proof_issued_at() != self.proof_issued_at
        {
            return Err(invalid());
        }
        Ok(())
    }
}
