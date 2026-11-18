//! Fail-closed delegated operation evaluation.
//!
//! This layer deliberately does not implement a second Cedar engine or accept
//! caller-supplied policy results. Production composition must provide:
//! (1) a cryptographic delegate-proof verifier for the exact key/session binding,
//! (2) an authenticated external-constraint evidence verifier when selected, and
//! (3) a Cedar evaluator backed by the organization's active, versioned policy.
//! There is no allow-all implementation. All provider errors are sanitized.
//!
//! A successful evaluation is an ephemeral decision input, NOT a bearer permit
//! and NOT permission to execute an operation. The consuming operation must
//! still perform an atomic final-use revision/replay reservation at its own
//! commit boundary. Commerce execution remains outside this crate.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::{
    domain::valid_uri, DelegationAuthorityService, DelegationClock, DelegationGrant, GrantStatus,
    Principal, ResolvedDelegationGrant, SystemDelegationClock,
};

const MAX_PROOF_BYTES: usize = 16_384;
const MAX_POLICY_OBSERVATION_AGE_SECONDS: i64 = 30;

#[derive(Clone)]
pub struct DelegationUseRequest {
    pub organization_id: Uuid,
    pub grant_id: Uuid,
    pub expected_revision: u64,
    pub actor: Principal,
    pub action: String,
    pub audience: String,
    pub resource: String,
    pub operation_profile: String,
    pub operation_digest: String,
    /// Original signed proof bytes. Debug output is intentionally unavailable.
    pub proof: Vec<u8>,
}

impl std::fmt::Debug for DelegationUseRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelegationUseRequest")
            .field("organization_id", &self.organization_id)
            .field("grant_id", &self.grant_id)
            .field("expected_revision", &self.expected_revision)
            .field("actor", &self.actor)
            .field("action", &self.action)
            .field("audience", &self.audience)
            .field("resource", &self.resource)
            .field("operation_profile", &self.operation_profile)
            .field("operation_digest", &self.operation_digest)
            .field("proof_bytes", &self.proof.len())
            .finish()
    }
}

/// The proof adapter verifies the actual cryptographic proof and binding:
/// key-based grants require the configured key thumbprint; session-based grants
/// require the exact established session and establishment evidence. It must
/// verify actor identity, grant ID, organization, challenge/nonce, audience,
/// operation digest, signature, proof freshness and replay status. Returning
/// success means those checks passed; a login or a caller boolean is insufficient.
#[async_trait]
pub trait DelegateProofVerifier: Send + Sync {
    async fn verify(
        &self,
        grant: &DelegationGrant,
        request: &DelegationUseRequest,
        now: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, DelegateProofError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("delegate proof verification failed")]
pub struct DelegateProofError;

/// Authenticated evidence for an external-profile constraint. The provider must
/// bind the exact grant, operation, profile, document digest and configured
/// evaluator identity. It must not fetch a caller-selected document URI.
#[async_trait]
pub trait ExternalConstraintVerifier: Send + Sync {
    async fn verify(
        &self,
        grant: &DelegationGrant,
        request: &DelegationUseRequest,
        now: DateTime<Utc>,
    ) -> Result<VerifiedConstraintEvidence, ConstraintVerificationError>;
}

#[derive(Clone, Debug)]
pub struct VerifiedConstraintEvidence {
    pub valid_until: DateTime<Utc>,
    /// Sanitized, authenticated context produced by the constraint adapter.
    /// It must contain no bearer credentials or raw private source documents.
    pub context: serde_json::Value,
    pub evidence_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("external constraint evidence verification failed")]
pub struct ConstraintVerificationError;

/// The Cedar adapter must load an active organization-owned policy set and
/// evaluate this exact principal/action/resource/context. Policy identity,
/// revision and digest are returned as authenticated adapter metadata.
#[derive(Clone, Debug)]
pub struct CedarEvaluationRequest {
    pub organization_id: Uuid,
    pub grant_id: Uuid,
    pub grant_revision: u64,
    pub actor: Principal,
    pub grantor: Principal,
    pub subject: Principal,
    pub delegate: Principal,
    pub action: String,
    pub audience: String,
    pub resource: String,
    pub operation_profile: String,
    pub operation_digest: String,
    /// Exact-operation constraints are represented by a service-built context;
    /// external-profile context is returned only by the trusted verifier port.
    pub constraint_context: serde_json::Value,
    pub constraint_evidence_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CedarDecision {
    Permit,
    Forbid,
    Abstain,
}

#[derive(Clone, Debug)]
pub struct CedarEvaluation {
    pub decision: CedarDecision,
    pub policy_id: String,
    pub policy_revision: u64,
    pub policy_digest: String,
    pub evaluated_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

#[async_trait]
pub trait DelegationCedarEvaluator: Send + Sync {
    async fn evaluate(
        &self,
        request: CedarEvaluationRequest,
        now: DateTime<Utc>,
    ) -> Result<CedarEvaluation, CedarEvaluationError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("delegation policy evaluation failed")]
pub struct CedarEvaluationError;

/// An evaluation result, not a capability token. The fields are private so a
/// caller cannot construct one from an unverified grant or policy response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationUseEvaluation {
    organization_id: Uuid,
    grant_id: Uuid,
    grant_revision: u64,
    terms_digest: String,
    policy_id: String,
    policy_revision: u64,
    policy_digest: String,
    evaluated_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
}

impl DelegationUseEvaluation {
    pub fn organization_id(&self) -> Uuid { self.organization_id }
    pub fn grant_id(&self) -> Uuid { self.grant_id }
    pub fn grant_revision(&self) -> u64 { self.grant_revision }
    pub fn terms_digest(&self) -> &str { &self.terms_digest }
    pub fn policy_id(&self) -> &str { &self.policy_id }
    pub fn policy_revision(&self) -> u64 { self.policy_revision }
    pub fn policy_digest(&self) -> &str { &self.policy_digest }
    pub fn evaluated_at(&self) -> DateTime<Utc> { self.evaluated_at }
    pub fn valid_until(&self) -> DateTime<Utc> { self.valid_until }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DelegationUseError {
    #[error("delegation use request is invalid")]
    InvalidRequest,
    #[error("delegation grant revision changed")]
    RevisionConflict,
    #[error("delegate does not match the grant")]
    WrongDelegate,
    #[error("delegation scope does not authorize this operation")]
    ScopeDenied,
    #[error("delegate proof was not verified")]
    ProofNotVerified,
    #[error("operation constraint was not verified")]
    ConstraintNotVerified,
    #[error("delegation policy did not permit this operation")]
    PolicyDenied,
    #[error("delegation evidence expired during evaluation")]
    EvidenceExpired,
    #[error("delegation state changed during evaluation")]
    StateChanged,
    #[error("delegation service is unavailable")]
    Unavailable,
}

#[derive(Clone)]
pub struct DelegationUseAuthorizer {
    lifecycle: Arc<DelegationAuthorityService>,
    proof: Arc<dyn DelegateProofVerifier>,
    constraints: Arc<dyn ExternalConstraintVerifier>,
    cedar: Arc<dyn DelegationCedarEvaluator>,
    clock: Arc<dyn DelegationClock>,
}

impl DelegationUseAuthorizer {
    pub fn new(
        lifecycle: Arc<DelegationAuthorityService>,
        proof: Arc<dyn DelegateProofVerifier>,
        constraints: Arc<dyn ExternalConstraintVerifier>,
        cedar: Arc<dyn DelegationCedarEvaluator>,
    ) -> Self {
        Self::with_clock(
            lifecycle, proof, constraints, cedar, Arc::new(SystemDelegationClock),
        )
    }

    pub fn with_clock(
        lifecycle: Arc<DelegationAuthorityService>,
        proof: Arc<dyn DelegateProofVerifier>,
        constraints: Arc<dyn ExternalConstraintVerifier>,
        cedar: Arc<dyn DelegationCedarEvaluator>,
        clock: Arc<dyn DelegationClock>,
    ) -> Self {
        Self { lifecycle, proof, constraints, cedar, clock }
    }

    /// Evaluate one exact operation. Any unknown, stale, mismatched or
    /// unavailable dependency fails closed. The grant is re-resolved after all
    /// asynchronous checks to detect revocation/revision changes during policy
    /// evaluation.
    pub async fn evaluate(
        &self,
        request: &DelegationUseRequest,
    ) -> Result<DelegationUseEvaluation, DelegationUseError> {
        validate_request(request)?;
        let started_at = self.clock.now();
        let resolved = self.resolve(request).await?;
        let grant = &resolved.grant;
        if grant.revision != request.expected_revision {
            return Err(DelegationUseError::RevisionConflict);
        }
        validate_exact_scope(grant, request)?;
        let proof_deadline = self.proof.verify(grant, request, started_at)
            .await.map_err(|_| DelegationUseError::ProofNotVerified)?;
        let after_proof = self.now_after(started_at)?;
        if proof_deadline <= after_proof {
            return Err(DelegationUseError::EvidenceExpired);
        }

        let (constraint_deadline, constraint_context, constraint_evidence_digest) = match grant.terms.constraints.mode {
            crate::ConstraintMode::ExactOperation => {
                if grant.terms.constraints.request_profile.as_deref()
                    != Some(request.operation_profile.as_str())
                    || grant.terms.constraints.request_digest.as_deref()
                    != Some(request.operation_digest.as_str())
                {
                    return Err(DelegationUseError::ConstraintNotVerified);
                }
                (
                    grant.terms.valid_until,
                    serde_json::json!({
                        "mode": "EXACT_OPERATION",
                        "request_profile": request.operation_profile,
                        "request_digest": request.operation_digest,
                    }),
                    request.operation_digest.clone(),
                )
            }
            crate::ConstraintMode::ExternalProfile => {
                let verified = self.constraints.verify(grant, request, after_proof)
                    .await.map_err(|_| DelegationUseError::ConstraintNotVerified)?;
                if !valid_digest(&verified.evidence_digest) || !verified.context.is_object() {
                    return Err(DelegationUseError::ConstraintNotVerified);
                }
                (verified.valid_until, verified.context, verified.evidence_digest)
            }
        };
        let after_constraints = self.now_after(started_at)?;
        if constraint_deadline <= after_constraints {
            return Err(DelegationUseError::EvidenceExpired);
        }

        let cedar_result = self.cedar.evaluate(CedarEvaluationRequest {
            organization_id: grant.organization_id,
            grant_id: grant.id,
            grant_revision: grant.revision,
            actor: request.actor.clone(),
            grantor: grant.terms.grantor.clone(),
            subject: grant.terms.subject.clone(),
            delegate: grant.terms.delegate.clone(),
            action: request.action.clone(),
            audience: request.audience.clone(),
            resource: request.resource.clone(),
            operation_profile: request.operation_profile.clone(),
            operation_digest: request.operation_digest.clone(),
            constraint_context,
            constraint_evidence_digest,
        }, after_constraints).await.map_err(|_| DelegationUseError::Unavailable)?;
        let after_policy = self.now_after(started_at)?;
        validate_cedar_result(&cedar_result, after_policy)?;
        if cedar_result.decision != CedarDecision::Permit {
            return Err(DelegationUseError::PolicyDenied);
        }

        // The second trusted resolution also refreshes consent/authority status.
        // Do not return an evaluation against a stale revision or expired proof.
        let latest = self.resolve(request).await?;
        let final_now = self.now_after(started_at)?;
        if latest.grant != *grant || latest.grant.revision != request.expected_revision {
            return Err(DelegationUseError::StateChanged);
        }
        let valid_until = [
            grant.terms.valid_until,
            resolved.consent_valid_until,
            latest.consent_valid_until,
            proof_deadline,
            constraint_deadline,
            cedar_result.valid_until,
        ].into_iter().min().ok_or(DelegationUseError::EvidenceExpired)?;
        if valid_until <= final_now {
            return Err(DelegationUseError::EvidenceExpired);
        }

        Ok(DelegationUseEvaluation {
            organization_id: grant.organization_id,
            grant_id: grant.id,
            grant_revision: grant.revision,
            terms_digest: grant.terms_digest.clone(),
            policy_id: cedar_result.policy_id,
            policy_revision: cedar_result.policy_revision,
            policy_digest: cedar_result.policy_digest,
            evaluated_at: cedar_result.evaluated_at,
            valid_until,
        })
    }

    async fn resolve(
        &self,
        request: &DelegationUseRequest,
    ) -> Result<ResolvedDelegationGrant, DelegationUseError> {
        self.lifecycle.resolve_verified(request.organization_id, request.grant_id)
            .await.map_err(|_| DelegationUseError::Unavailable)
    }

    fn now_after(&self, started_at: DateTime<Utc>) -> Result<DateTime<Utc>, DelegationUseError> {
        let now = self.clock.now();
        if now < started_at {
            return Err(DelegationUseError::EvidenceExpired);
        }
        Ok(now)
    }
}

fn validate_request(request: &DelegationUseRequest) -> Result<(), DelegationUseError> {
    if request.expected_revision == 0
        || !valid_uri(Some(&request.actor.id))
        || !valid_uri(Some(&request.action))
        || !valid_uri(Some(&request.audience))
        || !valid_uri(Some(&request.resource))
        || !valid_uri(Some(&request.operation_profile))
        || !valid_digest(&request.operation_digest)
        || request.proof.is_empty()
        || request.proof.len() > MAX_PROOF_BYTES
    {
        return Err(DelegationUseError::InvalidRequest);
    }
    Ok(())
}

fn validate_exact_scope(
    grant: &DelegationGrant,
    request: &DelegationUseRequest,
) -> Result<(), DelegationUseError> {
    if request.actor != grant.terms.delegate {
        return Err(DelegationUseError::WrongDelegate);
    }
    if grant.status != GrantStatus::Active
        || !grant.terms.actions.iter().any(|value| value == &request.action)
        || !grant.terms.audiences.iter().any(|value| value == &request.audience)
        || !grant.terms.resources.iter().any(|value| value == &request.resource)
    {
        return Err(DelegationUseError::ScopeDenied);
    }
    Ok(())
}

fn validate_cedar_result(
    result: &CedarEvaluation,
    now: DateTime<Utc>,
) -> Result<(), DelegationUseError> {
    if !valid_uri(Some(&result.policy_id))
        || result.policy_revision == 0
        || !valid_digest(&result.policy_digest)
        || result.evaluated_at > now
        || result.valid_until <= now
        || result.valid_until <= result.evaluated_at
        || result.valid_until > result.evaluated_at + Duration::seconds(MAX_POLICY_OBSERVATION_AGE_SECONDS)
        || now.signed_duration_since(result.evaluated_at)
            > Duration::seconds(MAX_POLICY_OBSERVATION_AGE_SECONDS)
    {
        return Err(DelegationUseError::PolicyDenied);
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_support::pending_grant, ApprovalEvidence, ConsentEvidenceVerifier,
        ConsentVerificationRequest, InMemoryDelegationGrantRepository, ServiceError,
    };
    use std::sync::Mutex;

    struct FixedClock(Mutex<DateTime<Utc>>);
    impl FixedClock {
        fn set(&self, now: DateTime<Utc>) { *self.0.lock().unwrap() = now; }
    }
    impl DelegationClock for FixedClock {
        fn now(&self) -> DateTime<Utc> { *self.0.lock().unwrap() }
    }
    struct Consent;
    #[async_trait]
    impl ConsentEvidenceVerifier for Consent {
        async fn verify_approval(&self, request: ConsentVerificationRequest<'_>)
            -> Result<VerifiedConsent, crate::ConsentVerificationError> {
            Ok(VerifiedConsent { valid_until: request.grant.terms.valid_until })
        }
    }
    struct Proof { reject: bool, calls: Mutex<usize> }
    #[async_trait]
    impl DelegateProofVerifier for Proof {
        async fn verify(&self, grant: &DelegationGrant, request: &DelegationUseRequest,
            _now: DateTime<Utc>) -> Result<DateTime<Utc>, DelegateProofError> {
            *self.calls.lock().unwrap() += 1;
            if self.reject || request.actor != grant.terms.delegate || request.proof != [7,8,9] {
                return Err(DelegateProofError);
            }
            Ok(grant.terms.valid_until)
        }
    }
    struct Constraint { reject: bool }
    #[async_trait]
    impl ExternalConstraintVerifier for Constraint {
        async fn verify(&self, grant: &DelegationGrant, _request: &DelegationUseRequest,
            _now: DateTime<Utc>) -> Result<VerifiedConstraintEvidence, ConstraintVerificationError> {
            if self.reject { return Err(ConstraintVerificationError); }
            Ok(VerifiedConstraintEvidence {
                valid_until: grant.terms.valid_until,
                context: serde_json::json!({"authorized": true, "source": "test-only"}),
                evidence_digest: format!("sha256:{}", "d".repeat(64)),
            })
        }
    }
    struct Cedar { decision: CedarDecision, mutate: bool, lifecycle: Option<Arc<DelegationAuthorityService>>, clock: Option<Arc<FixedClock>> }
    #[async_trait]
    impl DelegationCedarEvaluator for Cedar {
        async fn evaluate(&self, request: CedarEvaluationRequest, now: DateTime<Utc>)
            -> Result<CedarEvaluation, CedarEvaluationError> {
            if self.mutate {
                let clock = self.clock.as_ref().unwrap();
                clock.set(clock.now() + Duration::seconds(1));
                self.lifecycle.as_ref().unwrap()
                    .suspend(request.organization_id, request.grant_id, request.grant_revision)
                    .await.map_err(|_| CedarEvaluationError)?;
            }
            Ok(CedarEvaluation {
                decision: self.decision,
                policy_id: "urn:example:commerce:policy:checkout".into(),
                policy_revision: 4,
                policy_digest: format!("sha256:{}", "b".repeat(64)),
                evaluated_at: now,
                valid_until: now + Duration::minutes(1),
            })
        }
    }
    struct Harness {
        lifecycle: Arc<DelegationAuthorityService>,
        authorizer: DelegationUseAuthorizer,
        request: DelegationUseRequest,
        proof: Arc<Proof>,
        clock: Arc<FixedClock>,
    }
    impl Harness {
        async fn new(decision: CedarDecision) -> Self {
            let template = pending_grant();
            let now = template.created_at;
            let clock = Arc::new(FixedClock(Mutex::new(now)));
            let repository = Arc::new(InMemoryDelegationGrantRepository::default());
            let lifecycle = Arc::new(DelegationAuthorityService::with_clock(
                repository, Arc::new(Consent), template.authority.clone(), clock.clone()
            ).unwrap());
            let pending = lifecycle.propose(template.organization_id, template.terms.clone()).await.unwrap();
            clock.set(template.created_at + Duration::seconds(1));
            lifecycle.approve(pending.organization_id, pending.id, 1, &pending.terms.grantor,
                ApprovalEvidence {
                    profile: "urn:example:consent:v1".into(),
                    evidence_ref: "urn:example:consent:1".into(),
                    authority_evidence_ref: "urn:example:authority:1".into(),
                }).await.unwrap();
            let proof = Arc::new(Proof { reject: false, calls: Mutex::new(0) });
            let authorizer = DelegationUseAuthorizer::with_clock(
                lifecycle.clone(), proof.clone(), Arc::new(Constraint { reject: false }),
                Arc::new(Cedar { decision, mutate: false, lifecycle: None, clock: None }), clock.clone()
            );
            let request = DelegationUseRequest {
                organization_id: pending.organization_id, grant_id: pending.id, expected_revision: 2,
                actor: pending.terms.delegate.clone(), action: pending.terms.actions[0].clone(),
                audience: pending.terms.audiences[0].clone(), resource: pending.terms.resources[0].clone(),
                operation_profile: "https://commerce.example/profiles/desk-lamp-purchase/v1".into(),
                operation_digest: format!("sha256:{}", "c".repeat(64)), proof: vec![7,8,9],
            };
            Self { lifecycle, authorizer, request, proof, clock }
        }
    }

    #[tokio::test]
    async fn exact_delegate_scope_proof_constraint_and_cedar_permit_are_required() {
        let h = Harness::new(CedarDecision::Permit).await;
        let decision = h.authorizer.evaluate(&h.request).await.unwrap();
        assert_eq!(decision.organization_id(), h.request.organization_id);
        assert_eq!(decision.grant_id(), h.request.grant_id);
        assert_eq!(decision.grant_revision(), 2);
        assert_eq!(decision.policy_revision(), 4);
        assert_eq!(decision.policy_digest(), format!("sha256:{}", "b".repeat(64)));
        assert!(decision.valid_until() > h.clock.now());
        assert_eq!(*h.proof.calls.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn wrong_delegate_and_out_of_scope_request_fail_before_proof() {
        let h = Harness::new(CedarDecision::Permit).await;
        let mut wrong = h.request.clone();
        wrong.actor.id = "https://agents.example/agents/attacker".into();
        assert_eq!(h.authorizer.evaluate(&wrong).await, Err(DelegationUseError::WrongDelegate));
        let mut wrong_scope = h.request.clone();
        wrong_scope.resource = "urn:commerce:product:other".into();
        assert_eq!(h.authorizer.evaluate(&wrong_scope).await, Err(DelegationUseError::ScopeDenied));
        assert_eq!(*h.proof.calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn failed_proof_and_non_permit_cedar_decisions_fail_closed() {
        let h = Harness::new(CedarDecision::Permit).await;
        h.proof.reject = true;
        assert_eq!(h.authorizer.evaluate(&h.request).await, Err(DelegationUseError::ProofNotVerified));
        let h = Harness::new(CedarDecision::Forbid).await;
        assert_eq!(h.authorizer.evaluate(&h.request).await, Err(DelegationUseError::PolicyDenied));
        let h = Harness::new(CedarDecision::Abstain).await;
        assert_eq!(h.authorizer.evaluate(&h.request).await, Err(DelegationUseError::PolicyDenied));
    }

    #[tokio::test]
    async fn concurrent_suspension_during_cedar_evaluation_is_not_authorized() {
        let h = Harness::new(CedarDecision::Permit).await;
        let authorizer = DelegationUseAuthorizer::with_clock(
            h.lifecycle.clone(), h.proof.clone(), Arc::new(Constraint { reject: false }),
            Arc::new(Cedar { decision: CedarDecision::Permit, mutate: true, lifecycle: Some(h.lifecycle.clone()), clock: Some(h.clock.clone()) }),
            h.clock.clone()
        );
        assert_eq!(authorizer.evaluate(&h.request).await, Err(DelegationUseError::Unavailable));
        assert!(matches!(h.lifecycle.resolve(h.request.organization_id, h.request.grant_id).await,
            Err(ServiceError::Inactive)));
    }

    #[tokio::test]
    async fn malformed_request_and_external_constraint_failure_are_rejected() {
        let h = Harness::new(CedarDecision::Permit).await;
        let mut malformed = h.request.clone();
        malformed.operation_digest = "sha256:NOT-A-DIGEST".into();
        assert_eq!(h.authorizer.evaluate(&malformed).await, Err(DelegationUseError::InvalidRequest));
        let authorizer = DelegationUseAuthorizer::with_clock(
            h.lifecycle.clone(), h.proof.clone(), Arc::new(Constraint { reject: true }),
            Arc::new(Cedar { decision: CedarDecision::Permit, mutate: false, lifecycle: None, clock: None }),
            h.clock.clone()
        );
        assert_eq!(authorizer.evaluate(&h.request).await, Err(DelegationUseError::ConstraintNotVerified));
    }
}
