use std::sync::Arc;

use super::{
    build_canonical_decision, ClaimState, CompatibilityError, CompatibilityUseCases,
    CreateSessionRequest, CredentialVerificationKernel, EvidenceFailureReason, GovernanceEngine,
    GovernancePurpose, GovernanceSnapshot, IssuerKeyRequest, IssuerKeyResolver,
    IssuerResolutionError, PersistedEvidence, PresentationPayload, Presented, ProcessingLease,
    ProcessingToken, SessionDraft, SessionRecord, SessionRepository, SessionResponse,
    SubmitPresentationRequest, TerminalDecision, VerificationMethod, VerificationResult,
    VerifierNonce, VerifyDirectRequest, VerifyVdsNcRequest,
};
use async_trait::async_trait;

pub struct CredentialsCompatibilityService {
    repository: Arc<dyn SessionRepository>,
    kernel: Arc<dyn CredentialVerificationKernel>,
    issuer_resolver: Arc<dyn IssuerKeyResolver>,
    governance: GovernanceEngine,
    processing_lease: ProcessingLease,
}

impl std::fmt::Debug for CredentialsCompatibilityService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialsCompatibilityService")
            .field("repository", &"[CONFIGURED]")
            .field("kernel", &"[CONFIGURED]")
            .field("issuer_resolver", &"[CONFIGURED]")
            .field("governance", &"[VALIDATED AND REDACTED]")
            .field("processing_lease", &self.processing_lease)
            .finish()
    }
}

impl CredentialsCompatibilityService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn SessionRepository>,
        kernel: Arc<dyn CredentialVerificationKernel>,
        issuer_resolver: Arc<dyn IssuerKeyResolver>,
        governance: GovernanceEngine,
        processing_lease: ProcessingLease,
    ) -> Self {
        Self {
            repository,
            kernel,
            issuer_resolver,
            governance,
            processing_lease,
        }
    }

    async fn submit(
        &self,
        session_id: &str,
        presentation: &str,
    ) -> Result<SessionRecord, CompatibilityError> {
        let presentation_digest = Presented::String(presentation).digest();
        let processing_token = ProcessingToken::generate();
        let claim = self
            .repository
            .claim(
                session_id,
                &presentation_digest,
                &processing_token,
                self.processing_lease,
            )
            .await
            .map_err(|_| CompatibilityError::Internal)?;
        let session = match claim.state {
            ClaimState::Claimed => claim.session.ok_or(CompatibilityError::Internal)?,
            ClaimState::Terminal => return claim.session.ok_or(CompatibilityError::Internal),
            ClaimState::NotFound => return Err(CompatibilityError::NotFound),
            ClaimState::Expired => return Err(CompatibilityError::Expired),
            ClaimState::Busy => return Err(CompatibilityError::Busy),
            ClaimState::Conflict | ClaimState::Stale | ClaimState::Finalized => {
                return Err(CompatibilityError::Conflict);
            }
        };
        let nonce = claim
            .verifier_nonce
            .as_ref()
            .ok_or(CompatibilityError::Internal)?;
        let decision = self
            .session_decision(&session, presentation, &presentation_digest, nonce)
            .await;
        let finalized = self
            .repository
            .finalize(
                session_id,
                &presentation_digest,
                &processing_token,
                decision,
            )
            .await
            .map_err(|_| CompatibilityError::Internal)?;
        match finalized.state {
            ClaimState::Finalized | ClaimState::Terminal => {
                finalized.session.ok_or(CompatibilityError::Internal)
            }
            ClaimState::NotFound => Err(CompatibilityError::NotFound),
            ClaimState::Expired => Err(CompatibilityError::Expired),
            ClaimState::Claimed | ClaimState::Busy | ClaimState::Conflict | ClaimState::Stale => {
                Err(CompatibilityError::Conflict)
            }
        }
    }

    async fn session_decision(
        &self,
        session: &SessionRecord,
        presentation: &str,
        presentation_digest: &super::Sha256Digest,
        nonce: &VerifierNonce,
    ) -> TerminalDecision {
        let Some(frozen) = session.verification_evidence.pending_governance() else {
            return fail_closed(
                presentation_digest,
                EvidenceFailureReason::MissingGovernanceProvenance,
                "Verification provenance unavailable",
            );
        };
        let governance = self.governance.resume(frozen).and_then(|governance| {
            governance.require_purpose(GovernancePurpose::SessionCreate)?;
            if governance.organization_id() != session.organization_id {
                return Err(super::GovernanceError::PolicyMismatch);
            }
            governance.validate_request(&session.verifier_did, &session.presentation_definition)?;
            Ok(governance)
        });
        let Ok(governance) = governance else {
            return fail_closed(
                presentation_digest,
                EvidenceFailureReason::MissingGovernanceProvenance,
                "Verification provenance unavailable",
            );
        };
        let facts = self
            .kernel
            .verify_jwt_vp(presentation, &session.verifier_did, Some(nonce.as_str()))
            .await;
        let result = build_canonical_decision(
            &governance,
            &format!("verification:{}", session.id),
            &session.id,
            Presented::String(presentation),
            &facts,
        );
        let evidence = result.and_then(|result| {
            PersistedEvidence::canonical(&governance, &session.id, presentation_digest, &result)
                .map(|evidence| (result, evidence))
                .map_err(|_| super::DecisionBuildError::Core)
        });
        match evidence {
            Ok((result, evidence)) if result.is_valid() => {
                TerminalDecision::verified(evidence, VerificationMethod::JwtVp)
                    .expect("canonical Core PASS constructs verified terminal evidence")
            }
            Ok((_, evidence)) => TerminalDecision::failed(
                evidence,
                Some(VerificationMethod::JwtVp),
                "Verification did not produce a passing canonical decision".into(),
            )
            .expect("canonical Core non-PASS constructs failed terminal evidence"),
            Err(_) => fail_closed(
                presentation_digest,
                EvidenceFailureReason::CanonicalResultBuildFailed,
                "Canonical verification result unavailable",
            ),
        }
    }
}

#[async_trait]
impl CompatibilityUseCases for CredentialsCompatibilityService {
    async fn create_session(
        &self,
        request: CreateSessionRequest,
        governance: GovernanceSnapshot,
    ) -> Result<SessionResponse, CompatibilityError> {
        governance
            .require_purpose(GovernancePurpose::SessionCreate)
            .and_then(|()| {
                governance.validate_request(
                    &request.verifier_did,
                    &serde_json::to_value(&request.presentation_definition)
                        .map_err(|_| super::GovernanceError::PolicyMismatch)?,
                )
            })
            .map_err(|_| CompatibilityError::PolicyMismatch)?;
        let id = VerifierNonce::generate().as_str().to_owned();
        let nonce = VerifierNonce::generate();
        let presentation_definition = serde_json::to_value(&request.presentation_definition)
            .map_err(|_| CompatibilityError::Internal)?;
        let session = self
            .repository
            .create(
                SessionDraft {
                    id: id.clone(),
                    organization_id: governance.organization_id().into(),
                    verifier_did: request.verifier_did,
                    presentation_definition,
                    required_credential_types: Vec::new(),
                    trusted_issuers: governance.trust_profile().trusted_issuers().to_vec(),
                    required_claims: Vec::new(),
                    verification_evidence: PersistedEvidence::pending(&governance),
                    request_uri: format!("oid4vp://request?session_id={id}"),
                    nonce,
                },
                request.session_duration_seconds,
            )
            .await
            .map_err(|_| CompatibilityError::Internal)?;
        Ok(session_response(&session))
    }

    async fn submit_presentation(
        &self,
        session_id: &str,
        request: SubmitPresentationRequest,
    ) -> Result<VerificationResult, CompatibilityError> {
        let session = self.submit(session_id, &request.presentation).await?;
        Ok(verification_result(&session))
    }

    async fn get_session(&self, session_id: &str) -> Result<SessionResponse, CompatibilityError> {
        self.repository
            .get(session_id)
            .await
            .map_err(|_| CompatibilityError::Internal)?
            .as_ref()
            .map(session_response)
            .ok_or(CompatibilityError::NotFound)
    }

    async fn verify_direct(
        &self,
        request: VerifyDirectRequest,
        governance: GovernanceSnapshot,
    ) -> Result<VerificationResult, CompatibilityError> {
        governance
            .require_purpose(GovernancePurpose::Direct)
            .and_then(|()| {
                governance.validate_request(
                    &request.verifier_did,
                    &serde_json::to_value(&request.presentation_definition)
                        .map_err(|_| super::GovernanceError::PolicyMismatch)?,
                )
            })
            .map_err(|_| CompatibilityError::PolicyMismatch)?;
        let (facts, presented, method) = match &request.presentation {
            PresentationPayload::String(value) => (
                self.kernel
                    .verify_jwt_vp(value, &request.verifier_did, None)
                    .await,
                Presented::String(value),
                "jwt_vp",
            ),
            PresentationPayload::Object(value) => (
                self.kernel
                    .verify_structured_presentation(
                        value,
                        &request.presentation_definition,
                        &request.verifier_did,
                        &governance,
                        self.issuer_resolver.as_ref(),
                    )
                    .await,
                Presented::Object(value),
                "w3c_vc",
            ),
        };
        let transaction = format!("transaction:{}", VerifierNonce::generate().as_str());
        let verification = format!("verification:{}", VerifierNonce::generate().as_str());
        let canonical =
            build_canonical_decision(&governance, &verification, &transaction, presented, &facts)
                .map_err(|_| CompatibilityError::Internal)?;
        Ok(VerificationResult::from_canonical(
            Some(&canonical),
            Some(method.into()),
            None,
        ))
    }

    async fn verify_vds_nc(
        &self,
        request: VerifyVdsNcRequest,
        governance: GovernanceSnapshot,
    ) -> Result<VerificationResult, CompatibilityError> {
        governance
            .require_purpose(GovernancePurpose::VdsNc)
            .map_err(|_| CompatibilityError::PolicyMismatch)?;
        let issuer = self
            .issuer_resolver
            .resolve(
                &governance,
                IssuerKeyRequest {
                    issuer_did: &request.issuer_did,
                    verification_method_id: request.verification_method_id.as_deref(),
                    credential_format: "vds_nc",
                    key_purpose: "vdsnc_signing",
                    algorithm: request.algorithm.as_deref(),
                },
            )
            .await
            .map_err(|error| match error {
                IssuerResolutionError::UnusablePublicKey => CompatibilityError::UnusableIssuerDid,
                IssuerResolutionError::Untrusted
                | IssuerResolutionError::Unavailable
                | IssuerResolutionError::Invalid => CompatibilityError::Internal,
            })?;
        let facts = self
            .kernel
            .verify_vds_nc(&request.barcode, issuer.public_jwk())
            .await;
        let transaction = format!("transaction:{}", VerifierNonce::generate().as_str());
        let verification = format!("verification:{}", VerifierNonce::generate().as_str());
        let canonical = build_canonical_decision(
            &governance,
            &verification,
            &transaction,
            Presented::String(&request.barcode),
            &facts,
        )
        .map_err(|_| CompatibilityError::Internal)?;
        Ok(VerificationResult::from_canonical(
            Some(&canonical),
            Some("vds_nc".into()),
            (!canonical.is_valid()).then(|| "VDS-NC credential proof did not verify".into()),
        ))
    }
}

fn fail_closed(
    digest: &super::Sha256Digest,
    reason: EvidenceFailureReason,
    message: &str,
) -> TerminalDecision {
    TerminalDecision::failed(
        PersistedEvidence::fail_closed(digest, reason),
        Some(VerificationMethod::JwtVp),
        message.into(),
    )
    .expect("fail-closed evidence constructs only a failed terminal decision")
}

fn session_response(session: &SessionRecord) -> SessionResponse {
    SessionResponse {
        id: session.id.clone(),
        organization_id: session.organization_id.clone(),
        verifier_did: session.verifier_did.clone(),
        status: session.status.as_public_str().into(),
        request_uri: session.request_uri.clone().unwrap_or_default(),
        nonce: session
            .nonce
            .as_ref()
            .map_or_else(String::new, |nonce| nonce.as_str().into()),
        expires_at: session.expires_at.map_or_else(String::new, timestamp),
        created_at: timestamp(session.created_at),
    }
}

fn verification_result(session: &SessionRecord) -> VerificationResult {
    VerificationResult::from_canonical(
        session.verification_evidence.canonical_result(),
        session
            .verification_method
            .map(|method| method.as_public_str().into()),
        session.error_message.clone(),
    )
}

fn timestamp(value: chrono::NaiveDateTime) -> String {
    value.format("%Y-%m-%dT%H:%M:%S%.f").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_debug_is_secret_free() {
        assert_eq!(
            format!("{:?}", Presented::String("header.secret.signature")),
            "Presented([REDACTED])"
        );
    }

    #[test]
    fn terminal_projection_never_recovers_verified_claims_from_storage() {
        let unavailable = VerificationResult::from_canonical(None, Some("jwt_vp".into()), None);
        assert!(!unavailable.is_valid());
        assert!(unavailable.error().is_some());
    }
}
