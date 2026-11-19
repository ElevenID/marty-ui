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
use mmf_security::cedar::{CedarAuthorizationRequest, CedarEntityTypes, CedarPolicyEngine};
use uuid::Uuid;

use crate::{
    domain::valid_uri, DelegationAuthorityService, DelegationClock, DelegationGrant, GrantStatus,
    Principal, ResolvedDelegationGrant, SystemDelegationClock,
};

pub const MAX_DELEGATE_PROOF_BYTES: usize = 256 * 1024;
const MAX_CONSTRAINT_CONTEXT_BYTES: usize = 16_384;
const MAX_POLICY_OBSERVATION_AGE_SECONDS: i64 = 30;
const EVALUATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Clone)]
pub struct DelegationUseRequest {
    pub organization_id: Uuid,
    pub grant_id: Uuid,
    pub expected_revision: u64,
    /// Server-issued OID4VP transaction challenge identifier. The nonce itself
    /// is resolved from the authoritative challenge store, never from input.
    pub challenge_id: Uuid,
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
            .field("challenge_id", &self.challenge_id)
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
/// operation digest, signature, proof freshness and the observed live challenge
/// binding. Returning success means those checks passed; a login or a caller
/// boolean is insufficient. Atomic challenge consumption and replay enforcement
/// still belong to the consuming final-use transaction.
#[async_trait]
pub trait DelegateProofVerifier: Send + Sync {
    async fn verify(
        &self,
        grant: &DelegationGrant,
        request: &DelegationUseRequest,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegateProof, DelegateProofError>;
}

/// Authenticated proof facts retained for the protocol receipt. The challenge
/// and evidence reference are derived from the authoritative Flow state and
/// original proof bytes, never caller-provided metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDelegateProof {
    pub evidence_ref: String,
    pub challenge: String,
    pub verified_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
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
    /// When the configured evaluator authenticated this exact grant/operation.
    pub checked_at: DateTime<Utc>,
    /// Authenticated evidence identifier from the configured evaluator.
    pub evidence_ref: String,
    /// Sanitized, authenticated context produced by the constraint adapter.
    /// It must contain no bearer credentials or raw private source documents.
    pub context: serde_json::Value,
    pub evidence_digest: String,
}

/// Minimal external-profile evidence retained for the signed protocol receipt.
/// Profile, document digest and evaluator are copied from immutable grant terms;
/// only the evidence reference and observation are returned by the verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDomainConstraintReceipt {
    pub evaluator: Principal,
    pub profile: String,
    pub document_digest: String,
    pub checked_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub evidence_ref: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("external constraint evidence verification failed")]
pub struct ConstraintVerificationError;

/// A validated organization-owned active policy snapshot returned by the
/// consuming domain's policy provider. The provider must load the active policy and
/// schema together and bind `policy_digest` to both immutable documents.
#[derive(Clone)]
pub struct ResolvedCedarPolicy {
    pub organization_id: Uuid,
    pub policy_id: String,
    pub revision: u64,
    pub policy_digest: String,
    pub valid_until: DateTime<Utc>,
    pub entity_types: CedarEntityTypes,
    /// Trusted, organization-scoped entity graph: membership/roles, actor
    /// attributes and resource ownership. The provider must bind it to the
    /// request actor, organization and resource; the engine validates it against
    /// the active Cedar schema before evaluation.
    pub entities: serde_json::Value,
    pub engine: Arc<CedarPolicyEngine>,
}

/// Trusted source of the current active Cedar policy, owned by the consuming
/// domain or its organization policy provider. A draft, archived, foreign-tenant,
/// stale or missing policy must return an error.
#[async_trait]
pub trait CedarPolicySource: Send + Sync {
    async fn resolve_active(
        &self,
        request: &CedarEvaluationRequest,
        now: DateTime<Utc>,
    ) -> Result<ResolvedCedarPolicy, CedarPolicySourceError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("active Cedar policy could not be resolved")]
pub struct CedarPolicySourceError;

/// Concrete adapter to MMF's canonical Cedar parser, schema validator and
/// fail-closed authorizer. Policy selection, storage and domain entity ownership
/// remain with the consuming domain or its organization policy provider; this
/// adapter never accepts policy source from an operation request.
#[derive(Clone)]
pub struct MmfCedarEvaluator {
    source: Arc<dyn CedarPolicySource>,
}

impl MmfCedarEvaluator {
    pub fn new(source: Arc<dyn CedarPolicySource>) -> Self {
        Self { source }
    }
}

#[async_trait]
impl DelegationCedarEvaluator for MmfCedarEvaluator {
    async fn evaluate(
        &self,
        request: CedarEvaluationRequest,
        now: DateTime<Utc>,
    ) -> Result<CedarEvaluation, CedarEvaluationError> {
        let maximum_deadline = now
            .checked_add_signed(Duration::seconds(MAX_POLICY_OBSERVATION_AGE_SECONDS))
            .ok_or(CedarEvaluationError)?;
        if request.actor != request.delegate {
            return Err(CedarEvaluationError);
        }
        let policy = self
            .source
            .resolve_active(&request, now)
            .await
            .map_err(|_| CedarEvaluationError)?;
        if policy.organization_id != request.organization_id
            || !valid_uri(Some(&policy.policy_id))
            || policy.revision == 0
            || !valid_digest(&policy.policy_digest)
            || policy.valid_until <= now
            || policy.valid_until > maximum_deadline
        {
            return Err(CedarEvaluationError);
        }

        let context = serde_json::json!({
            "organization_id": request.organization_id.to_string(),
            "grant_id": request.grant_id.to_string(),
            "grant_revision": request.grant_revision,
            "actor_type": request.actor.principal_type,
            "grantor": request.grantor.id,
            "grantor_type": request.grantor.principal_type,
            "subject": request.subject.id,
            "subject_type": request.subject.principal_type,
            "delegate": request.delegate.id,
            "delegate_type": request.delegate.principal_type,
            "audience": request.audience,
            "operation_profile": request.operation_profile,
            "operation_digest": request.operation_digest,
            "constraint_context": request.constraint_context,
            "constraint_evidence_digest": request.constraint_evidence_digest,
            "delegate_proof_verified": true,
            "consent_and_authority_verified": true,
        });
        let decision = policy
            .engine
            .authorize_request(CedarAuthorizationRequest {
                principal_type: policy.entity_types.principal.clone(),
                principal_id: request.actor.id,
                action_type: policy.entity_types.action.clone(),
                action_id: request.action,
                resource_type: policy.entity_types.resource.clone(),
                resource_id: request.resource,
                context,
                entities: policy.entities,
            })
            .map_err(|_| CedarEvaluationError)?;
        if !decision.errors.is_empty() {
            return Err(CedarEvaluationError);
        }
        Ok(CedarEvaluation {
            decision: if decision.allowed {
                CedarDecision::Permit
            } else {
                CedarDecision::Forbid
            },
            policy_id: policy.policy_id,
            policy_revision: policy.revision,
            policy_digest: policy.policy_digest,
            evaluated_at: now,
            valid_until: policy.valid_until,
        })
    }
}

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
/// The exact typed actor and operation are retained for the consuming final-use
/// transaction; a grant/challenge pair alone must not authorize substitution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationUseEvaluation {
    organization_id: Uuid,
    grant_id: Uuid,
    challenge_id: Uuid,
    grant_revision: u64,
    terms_digest: String,
    actor: Principal,
    action: String,
    audience: String,
    resource: String,
    operation_profile: String,
    operation_digest: String,
    constraint_evidence_digest: String,
    policy_id: String,
    policy_revision: u64,
    policy_digest: String,
    evaluated_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    subject: Principal,
    binding: crate::Binding,
    approval_evidence_ref: String,
    authority_evidence_ref: String,
    authority_issuer: Principal,
    status_evidence_ref: String,
    status_checked_at: DateTime<Utc>,
    status_valid_until: DateTime<Utc>,
    proof_evidence_ref: String,
    proof_challenge: String,
    proof_verified_at: DateTime<Utc>,
    proof_valid_until: DateTime<Utc>,
    domain_evidence: Option<VerifiedDomainConstraintReceipt>,
}

impl DelegationUseEvaluation {
    pub fn organization_id(&self) -> Uuid {
        self.organization_id
    }
    pub fn grant_id(&self) -> Uuid {
        self.grant_id
    }
    pub fn challenge_id(&self) -> Uuid {
        self.challenge_id
    }
    pub fn grant_revision(&self) -> u64 {
        self.grant_revision
    }
    pub fn terms_digest(&self) -> &str {
        &self.terms_digest
    }
    pub fn actor(&self) -> &Principal {
        &self.actor
    }
    pub fn action(&self) -> &str {
        &self.action
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }
    pub fn resource(&self) -> &str {
        &self.resource
    }
    pub fn operation_profile(&self) -> &str {
        &self.operation_profile
    }
    pub fn operation_digest(&self) -> &str {
        &self.operation_digest
    }
    pub fn constraint_evidence_digest(&self) -> &str {
        &self.constraint_evidence_digest
    }
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }
    pub fn policy_revision(&self) -> u64 {
        self.policy_revision
    }
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }
    pub fn evaluated_at(&self) -> DateTime<Utc> {
        self.evaluated_at
    }
    pub fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }
    pub(crate) fn receipt_subject(&self) -> &Principal {
        &self.subject
    }
    pub(crate) fn receipt_binding(&self) -> &crate::Binding {
        &self.binding
    }
    pub(crate) fn receipt_approval_evidence_ref(&self) -> &str {
        &self.approval_evidence_ref
    }
    pub(crate) fn receipt_authority_evidence_ref(&self) -> &str {
        &self.authority_evidence_ref
    }
    pub(crate) fn receipt_authority_issuer(&self) -> &Principal {
        &self.authority_issuer
    }
    pub(crate) fn receipt_status_evidence_ref(&self) -> &str {
        &self.status_evidence_ref
    }
    pub(crate) fn receipt_status_checked_at(&self) -> DateTime<Utc> {
        self.status_checked_at
    }
    pub(crate) fn receipt_status_valid_until(&self) -> DateTime<Utc> {
        self.status_valid_until
    }
    pub(crate) fn receipt_proof_evidence_ref(&self) -> &str {
        &self.proof_evidence_ref
    }
    pub(crate) fn receipt_proof_challenge(&self) -> &str {
        &self.proof_challenge
    }
    pub(crate) fn receipt_proof_verified_at(&self) -> DateTime<Utc> {
        self.proof_verified_at
    }
    pub(crate) fn receipt_proof_valid_until(&self) -> DateTime<Utc> {
        self.proof_valid_until
    }
    pub(crate) fn receipt_domain_evidence(&self) -> Option<&VerifiedDomainConstraintReceipt> {
        self.domain_evidence.as_ref()
    }
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
    evaluation_timeout: std::time::Duration,
}

impl DelegationUseAuthorizer {
    pub fn new(
        lifecycle: Arc<DelegationAuthorityService>,
        proof: Arc<dyn DelegateProofVerifier>,
        constraints: Arc<dyn ExternalConstraintVerifier>,
        cedar: Arc<dyn DelegationCedarEvaluator>,
    ) -> Self {
        Self::with_clock(
            lifecycle,
            proof,
            constraints,
            cedar,
            Arc::new(SystemDelegationClock),
        )
    }

    pub fn with_clock(
        lifecycle: Arc<DelegationAuthorityService>,
        proof: Arc<dyn DelegateProofVerifier>,
        constraints: Arc<dyn ExternalConstraintVerifier>,
        cedar: Arc<dyn DelegationCedarEvaluator>,
        clock: Arc<dyn DelegationClock>,
    ) -> Self {
        Self {
            lifecycle,
            proof,
            constraints,
            cedar,
            clock,
            evaluation_timeout: EVALUATION_TIMEOUT,
        }
    }

    /// Evaluate one exact operation. Any unknown, stale, mismatched or
    /// unavailable dependency fails closed. The grant is re-resolved after all
    /// asynchronous checks to detect revocation/revision changes during policy
    /// evaluation. The complete asynchronous evaluation, including both trusted
    /// lifecycle resolutions, has a five-second timeout; a pending provider
    /// cannot leave the operation waiting indefinitely.
    pub async fn evaluate(
        &self,
        request: &DelegationUseRequest,
    ) -> Result<DelegationUseEvaluation, DelegationUseError> {
        validate_request(request)?;
        let deadline = tokio::time::Instant::now() + self.evaluation_timeout;
        let result = tokio::time::timeout_at(deadline, self.evaluate_inner(request))
            .await
            .map_err(|_| DelegationUseError::Unavailable)?;
        // A synchronous engine/provider may finish without yielding to the
        // timeout timer. It still cannot return a late successful evaluation.
        if tokio::time::Instant::now() >= deadline {
            return Err(DelegationUseError::Unavailable);
        }
        result
    }

    async fn evaluate_inner(
        &self,
        request: &DelegationUseRequest,
    ) -> Result<DelegationUseEvaluation, DelegationUseError> {
        let started_at = self.clock.now();
        let resolved = self.resolve(request).await?;
        let after_resolution = self.now_after(started_at)?;
        let grant = &resolved.grant;
        if grant.revision != request.expected_revision {
            return Err(DelegationUseError::RevisionConflict);
        }
        validate_exact_scope(grant, request)?;
        let mut valid_until = grant.terms.valid_until.min(resolved.consent_valid_until);
        if valid_until <= after_resolution {
            return Err(DelegationUseError::EvidenceExpired);
        }
        let verified_proof = self
            .proof
            .verify(grant, request, after_resolution)
            .await
            .map_err(|_| DelegationUseError::ProofNotVerified)?;
        let after_proof = self.now_after(after_resolution)?;
        if !valid_uri(Some(&verified_proof.evidence_ref))
            || verified_proof.challenge.len() < 22
            || verified_proof.challenge.len() > 128
            || !verified_proof
                .challenge
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || verified_proof.verified_at < after_resolution
            || verified_proof.verified_at > after_proof
            || verified_proof.valid_until <= after_proof
        {
            return Err(DelegationUseError::ProofNotVerified);
        }
        valid_until = valid_until.min(verified_proof.valid_until);
        if valid_until <= after_proof {
            return Err(DelegationUseError::EvidenceExpired);
        }

        let mut domain_evidence = None;
        let (constraint_deadline, constraint_context, constraint_evidence_digest) =
            match grant.terms.constraints.mode {
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
                    let verified = self
                        .constraints
                        .verify(grant, request, after_proof)
                        .await
                        .map_err(|_| DelegationUseError::ConstraintNotVerified)?;
                    // Observe the trusted clock before classifying provider evidence.
                    // Otherwise a regressed clock can be misreported as malformed
                    // constraint evidence because the timestamp comparison short-circuits.
                    let after_constraint_provider = self.now_after(after_proof)?;
                    if !valid_digest(&verified.evidence_digest)
                        || !valid_uri(Some(&verified.evidence_ref))
                        || !verified.context.is_object()
                        || verified.checked_at < after_proof
                        || verified.checked_at > after_constraint_provider
                        || verified.valid_until <= verified.checked_at
                        || verified.valid_until > grant.terms.valid_until
                    {
                        return Err(DelegationUseError::ConstraintNotVerified);
                    }
                    domain_evidence = Some(VerifiedDomainConstraintReceipt {
                        evaluator: grant
                            .terms
                            .constraints
                            .evaluator
                            .clone()
                            .ok_or(DelegationUseError::ConstraintNotVerified)?,
                        profile: grant
                            .terms
                            .constraints
                            .profile
                            .clone()
                            .ok_or(DelegationUseError::ConstraintNotVerified)?,
                        document_digest: grant
                            .terms
                            .constraints
                            .document_digest
                            .clone()
                            .ok_or(DelegationUseError::ConstraintNotVerified)?,
                        checked_at: verified.checked_at,
                        valid_until: verified.valid_until,
                        evidence_ref: verified.evidence_ref,
                    });
                    (
                        verified.valid_until,
                        verified.context,
                        verified.evidence_digest,
                    )
                }
            };
        let after_constraints = self.now_after(after_proof)?;
        valid_until = valid_until.min(constraint_deadline);
        if valid_until <= after_constraints {
            return Err(DelegationUseError::EvidenceExpired);
        }
        if serde_json::to_vec(&constraint_context)
            .map_or(true, |bytes| bytes.len() > MAX_CONSTRAINT_CONTEXT_BYTES)
        {
            return Err(DelegationUseError::ConstraintNotVerified);
        }

        let cedar_result = self
            .cedar
            .evaluate(
                CedarEvaluationRequest {
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
                    constraint_evidence_digest: constraint_evidence_digest.clone(),
                },
                after_constraints,
            )
            .await
            .map_err(|_| DelegationUseError::Unavailable)?;
        let after_policy = self.now_after(after_constraints)?;
        validate_cedar_result(&cedar_result, after_constraints, after_policy)?;
        if cedar_result.decision != CedarDecision::Permit {
            return Err(DelegationUseError::PolicyDenied);
        }
        valid_until = valid_until.min(cedar_result.valid_until);
        if valid_until <= after_policy {
            return Err(DelegationUseError::EvidenceExpired);
        }

        // The second trusted resolution also refreshes consent/authority status.
        // Do not return an evaluation against a stale revision or expired proof.
        let latest = self.resolve(request).await?;
        let final_now = self.now_after(after_policy)?;
        if latest.grant != *grant || latest.grant.revision != request.expected_revision {
            return Err(DelegationUseError::StateChanged);
        }
        valid_until = valid_until.min(latest.consent_valid_until);
        if valid_until <= final_now {
            return Err(DelegationUseError::EvidenceExpired);
        }

        let approval = grant
            .approval
            .as_ref()
            .ok_or(DelegationUseError::Unavailable)?;
        if approval.grant_id != grant.id || approval.terms_digest != grant.terms_digest {
            return Err(DelegationUseError::Unavailable);
        }
        Ok(DelegationUseEvaluation {
            organization_id: grant.organization_id,
            grant_id: grant.id,
            challenge_id: request.challenge_id,
            grant_revision: grant.revision,
            terms_digest: grant.terms_digest.clone(),
            actor: request.actor.clone(),
            action: request.action.clone(),
            audience: request.audience.clone(),
            resource: request.resource.clone(),
            operation_profile: request.operation_profile.clone(),
            operation_digest: request.operation_digest.clone(),
            constraint_evidence_digest,
            policy_id: cedar_result.policy_id,
            policy_revision: cedar_result.policy_revision,
            policy_digest: cedar_result.policy_digest,
            // Receipt evaluation time is the final post-policy grant/consent
            // observation. Cedar's policy snapshot was validated immediately before it.
            evaluated_at: final_now,
            valid_until,
            subject: grant.terms.subject.clone(),
            binding: grant.terms.binding.clone(),
            approval_evidence_ref: approval.evidence_ref.clone(),
            authority_evidence_ref: approval.authority_evidence_ref.clone(),
            authority_issuer: grant.authority.issuer.clone(),
            status_evidence_ref: grant.authority.status_ref.clone(),
            status_checked_at: final_now,
            status_valid_until: latest.consent_valid_until,
            proof_evidence_ref: verified_proof.evidence_ref,
            proof_challenge: verified_proof.challenge,
            proof_verified_at: verified_proof.verified_at,
            proof_valid_until: verified_proof.valid_until,
            domain_evidence,
        })
    }

    async fn resolve(
        &self,
        request: &DelegationUseRequest,
    ) -> Result<ResolvedDelegationGrant, DelegationUseError> {
        self.lifecycle
            .resolve_verified(request.organization_id, request.grant_id)
            .await
            .map_err(|_| DelegationUseError::Unavailable)
    }

    fn now_after(&self, previous: DateTime<Utc>) -> Result<DateTime<Utc>, DelegationUseError> {
        let now = self.clock.now();
        if now < previous {
            return Err(DelegationUseError::EvidenceExpired);
        }
        Ok(now)
    }
}

fn validate_request(request: &DelegationUseRequest) -> Result<(), DelegationUseError> {
    if request.organization_id.is_nil()
        || request.grant_id.is_nil()
        || request.challenge_id.is_nil()
        || request.expected_revision == 0
        || request.expected_revision > crate::MAX_GRANT_REVISION
        || !valid_uri(Some(&request.actor.id))
        || !valid_uri(Some(&request.action))
        || !valid_uri(Some(&request.audience))
        || !valid_uri(Some(&request.resource))
        || !valid_uri(Some(&request.operation_profile))
        || !valid_digest(&request.operation_digest)
        || request.proof.is_empty()
        || request.proof.len() > MAX_DELEGATE_PROOF_BYTES
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
        || !grant
            .terms
            .actions
            .iter()
            .any(|value| value == &request.action)
        || !grant
            .terms
            .audiences
            .iter()
            .any(|value| value == &request.audience)
        || !grant
            .terms
            .resources
            .iter()
            .any(|value| value == &request.resource)
    {
        return Err(DelegationUseError::ScopeDenied);
    }
    Ok(())
}

fn validate_cedar_result(
    result: &CedarEvaluation,
    requested_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), DelegationUseError> {
    let maximum_deadline = result
        .evaluated_at
        .checked_add_signed(Duration::seconds(MAX_POLICY_OBSERVATION_AGE_SECONDS))
        .ok_or(DelegationUseError::PolicyDenied)?;
    if !valid_uri(Some(&result.policy_id))
        || result.policy_revision == 0
        || !valid_digest(&result.policy_digest)
        || result.evaluated_at < requested_at
        || result.evaluated_at > now
        || result.valid_until <= now
        || result.valid_until <= result.evaluated_at
        || result.valid_until > maximum_deadline
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
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_support::pending_grant, ApprovalEvidence, ConsentEvidenceVerifier,
        ConsentVerificationRequest, InMemoryDelegationGrantRepository, ServiceError,
        VerifiedConsent,
    };
    use std::sync::Mutex;

    struct FixedClock(Mutex<DateTime<Utc>>);
    impl FixedClock {
        fn set(&self, now: DateTime<Utc>) {
            *self.0.lock().unwrap() = now;
        }
    }
    impl DelegationClock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            *self.0.lock().unwrap()
        }
    }
    struct Consent;
    #[async_trait]
    impl ConsentEvidenceVerifier for Consent {
        async fn verify_approval(
            &self,
            request: ConsentVerificationRequest<'_>,
        ) -> Result<VerifiedConsent, crate::ConsentVerificationError> {
            Ok(VerifiedConsent {
                valid_until: request.grant.terms.valid_until,
            })
        }
    }
    struct Proof {
        reject: Mutex<bool>,
        calls: Mutex<usize>,
    }
    #[async_trait]
    impl DelegateProofVerifier for Proof {
        async fn verify(
            &self,
            grant: &DelegationGrant,
            request: &DelegationUseRequest,
            _now: DateTime<Utc>,
        ) -> Result<VerifiedDelegateProof, DelegateProofError> {
            *self.calls.lock().unwrap() += 1;
            if *self.reject.lock().unwrap()
                || request.actor != grant.terms.delegate
                || request.proof.as_slice() != [7, 8, 9]
            {
                return Err(DelegateProofError);
            }
            Ok(VerifiedDelegateProof {
                evidence_ref: format!("urn:marty:oid4vp-proof:{}", request.challenge_id),
                challenge: request.challenge_id.simple().to_string(),
                verified_at: _now,
                valid_until: grant.terms.valid_until,
            })
        }
    }
    struct Constraint {
        reject: bool,
    }
    #[async_trait]
    impl ExternalConstraintVerifier for Constraint {
        async fn verify(
            &self,
            grant: &DelegationGrant,
            _request: &DelegationUseRequest,
            _now: DateTime<Utc>,
        ) -> Result<VerifiedConstraintEvidence, ConstraintVerificationError> {
            if self.reject {
                return Err(ConstraintVerificationError);
            }
            Ok(VerifiedConstraintEvidence {
                valid_until: grant.terms.valid_until,
                checked_at: _now,
                evidence_ref: "urn:example:constraint-evidence:test".into(),
                context: serde_json::json!({"authorized": true, "source": "test-only"}),
                evidence_digest: format!("sha256:{}", "d".repeat(64)),
            })
        }
    }
    struct Cedar {
        decision: CedarDecision,
        mutate: bool,
        lifecycle: Option<Arc<DelegationAuthorityService>>,
        clock: Option<Arc<FixedClock>>,
    }
    #[async_trait]
    impl DelegationCedarEvaluator for Cedar {
        async fn evaluate(
            &self,
            request: CedarEvaluationRequest,
            now: DateTime<Utc>,
        ) -> Result<CedarEvaluation, CedarEvaluationError> {
            if self.mutate {
                let clock = self.clock.as_ref().unwrap();
                clock.set(clock.now() + Duration::seconds(1));
                self.lifecycle
                    .as_ref()
                    .unwrap()
                    .suspend(
                        request.organization_id,
                        request.grant_id,
                        request.grant_revision,
                    )
                    .await
                    .map_err(|_| CedarEvaluationError)?;
            }
            Ok(CedarEvaluation {
                decision: self.decision,
                policy_id: "urn:example:commerce:policy:checkout".into(),
                policy_revision: 4,
                policy_digest: format!("sha256:{}", "b".repeat(64)),
                evaluated_at: now,
                valid_until: now + Duration::seconds(20),
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
            Self::with_template(decision, pending_grant()).await
        }

        async fn with_template(decision: CedarDecision, template: DelegationGrant) -> Self {
            let now = template.created_at;
            let clock = Arc::new(FixedClock(Mutex::new(now)));
            let repository = Arc::new(InMemoryDelegationGrantRepository::default());
            let lifecycle = Arc::new(
                DelegationAuthorityService::with_clock(
                    repository,
                    Arc::new(Consent),
                    template.authority.clone(),
                    clock.clone(),
                )
                .unwrap(),
            );
            let pending = lifecycle
                .propose(template.organization_id, template.terms.clone())
                .await
                .unwrap();
            clock.set(template.created_at + Duration::seconds(1));
            lifecycle
                .approve(
                    pending.organization_id,
                    pending.id,
                    1,
                    &pending.terms.grantor,
                    ApprovalEvidence {
                        profile: "urn:example:consent:v1".into(),
                        evidence_ref: "urn:example:consent:1".into(),
                        authority_evidence_ref: "urn:example:authority:1".into(),
                    },
                )
                .await
                .unwrap();
            let proof = Arc::new(Proof {
                reject: Mutex::new(false),
                calls: Mutex::new(0),
            });
            let authorizer = DelegationUseAuthorizer::with_clock(
                lifecycle.clone(),
                proof.clone(),
                Arc::new(Constraint { reject: false }),
                Arc::new(Cedar {
                    decision,
                    mutate: false,
                    lifecycle: None,
                    clock: None,
                }),
                clock.clone(),
            );
            let request = DelegationUseRequest {
                organization_id: pending.organization_id,
                grant_id: pending.id,
                expected_revision: 2,
                challenge_id: Uuid::new_v4(),
                actor: pending.terms.delegate.clone(),
                action: pending.terms.actions[0].clone(),
                audience: pending.terms.audiences[0].clone(),
                resource: pending.terms.resources[0].clone(),
                operation_profile: "https://commerce.example/profiles/desk-lamp-purchase/v1".into(),
                operation_digest: format!("sha256:{}", "c".repeat(64)),
                proof: vec![7, 8, 9],
            };
            Self {
                lifecycle,
                authorizer,
                request,
                proof,
                clock,
            }
        }
    }

    #[tokio::test]
    async fn exact_delegate_scope_proof_constraint_and_cedar_permit_are_required() {
        let h = Harness::new(CedarDecision::Permit).await;
        let decision = h.authorizer.evaluate(&h.request).await.unwrap();
        assert_eq!(decision.organization_id(), h.request.organization_id);
        assert_eq!(decision.grant_id(), h.request.grant_id);
        assert_eq!(decision.challenge_id(), h.request.challenge_id);
        assert_eq!(decision.grant_revision(), 2);
        assert_eq!(decision.actor(), &h.request.actor);
        assert_eq!(decision.action(), h.request.action);
        assert_eq!(decision.audience(), h.request.audience);
        assert_eq!(decision.resource(), h.request.resource);
        assert_eq!(decision.operation_profile(), h.request.operation_profile);
        assert_eq!(decision.operation_digest(), h.request.operation_digest);
        assert_eq!(
            decision.constraint_evidence_digest(),
            format!("sha256:{}", "d".repeat(64))
        );
        assert_eq!(decision.policy_revision(), 4);
        assert_eq!(
            decision.policy_digest(),
            format!("sha256:{}", "b".repeat(64))
        );
        assert!(decision.valid_until() > h.clock.now());
        assert_eq!(*h.proof.calls.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn wrong_delegate_and_out_of_scope_request_fail_before_proof() {
        let h = Harness::new(CedarDecision::Permit).await;
        let mut wrong = h.request.clone();
        wrong.actor.id = "https://agents.example/agents/attacker".into();
        assert_eq!(
            h.authorizer.evaluate(&wrong).await,
            Err(DelegationUseError::WrongDelegate)
        );
        let mut wrong_type = h.request.clone();
        wrong_type.actor.principal_type = crate::PrincipalType::User;
        assert_eq!(
            h.authorizer.evaluate(&wrong_type).await,
            Err(DelegationUseError::WrongDelegate)
        );
        let mut wrong_scope = h.request.clone();
        wrong_scope.resource = "urn:commerce:product:other".into();
        assert_eq!(
            h.authorizer.evaluate(&wrong_scope).await,
            Err(DelegationUseError::ScopeDenied)
        );
        assert_eq!(*h.proof.calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn failed_proof_and_non_permit_cedar_decisions_fail_closed() {
        let h = Harness::new(CedarDecision::Permit).await;
        *h.proof.reject.lock().unwrap() = true;
        assert_eq!(
            h.authorizer.evaluate(&h.request).await,
            Err(DelegationUseError::ProofNotVerified)
        );
        let h = Harness::new(CedarDecision::Forbid).await;
        assert_eq!(
            h.authorizer.evaluate(&h.request).await,
            Err(DelegationUseError::PolicyDenied)
        );
        let h = Harness::new(CedarDecision::Abstain).await;
        assert_eq!(
            h.authorizer.evaluate(&h.request).await,
            Err(DelegationUseError::PolicyDenied)
        );
    }

    #[tokio::test]
    async fn concurrent_suspension_during_cedar_evaluation_is_not_authorized() {
        let h = Harness::new(CedarDecision::Permit).await;
        let authorizer = DelegationUseAuthorizer::with_clock(
            h.lifecycle.clone(),
            h.proof.clone(),
            Arc::new(Constraint { reject: false }),
            Arc::new(Cedar {
                decision: CedarDecision::Permit,
                mutate: true,
                lifecycle: Some(h.lifecycle.clone()),
                clock: Some(h.clock.clone()),
            }),
            h.clock.clone(),
        );
        assert_eq!(
            authorizer.evaluate(&h.request).await,
            Err(DelegationUseError::Unavailable)
        );
        assert!(matches!(
            h.lifecycle
                .resolve(h.request.organization_id, h.request.grant_id)
                .await,
            Err(ServiceError::Inactive)
        ));
    }

    #[tokio::test]
    async fn malformed_request_and_external_constraint_failure_are_rejected() {
        let h = Harness::new(CedarDecision::Permit).await;
        let mut malformed = h.request.clone();
        malformed.operation_digest = "sha256:NOT-A-DIGEST".into();
        assert_eq!(
            h.authorizer.evaluate(&malformed).await,
            Err(DelegationUseError::InvalidRequest)
        );
        let authorizer = DelegationUseAuthorizer::with_clock(
            h.lifecycle.clone(),
            h.proof.clone(),
            Arc::new(Constraint { reject: true }),
            Arc::new(Cedar {
                decision: CedarDecision::Permit,
                mutate: false,
                lifecycle: None,
                clock: None,
            }),
            h.clock.clone(),
        );
        assert_eq!(
            authorizer.evaluate(&h.request).await,
            Err(DelegationUseError::ConstraintNotVerified)
        );
    }

    #[tokio::test]
    async fn nil_identifiers_and_non_protocol_revisions_fail_before_providers() {
        let h = Harness::new(CedarDecision::Permit).await;
        let mut missing_organization = h.request.clone();
        missing_organization.organization_id = Uuid::nil();
        let mut missing_grant = h.request.clone();
        missing_grant.grant_id = Uuid::nil();
        let mut missing_challenge = h.request.clone();
        missing_challenge.challenge_id = Uuid::nil();
        let mut zero_revision = h.request.clone();
        zero_revision.expected_revision = 0;
        let mut oversized_revision = h.request.clone();
        oversized_revision.expected_revision = crate::MAX_GRANT_REVISION + 1;
        for request in [
            missing_organization,
            missing_grant,
            missing_challenge,
            zero_revision,
            oversized_revision,
        ] {
            assert_eq!(
                h.authorizer.evaluate(&request).await,
                Err(DelegationUseError::InvalidRequest)
            );
        }
        assert_eq!(*h.proof.calls.lock().unwrap(), 0);
    }

    struct PendingProvider;

    #[async_trait]
    impl DelegateProofVerifier for PendingProvider {
        async fn verify(
            &self,
            _grant: &DelegationGrant,
            _request: &DelegationUseRequest,
            _now: DateTime<Utc>,
        ) -> Result<VerifiedDelegateProof, DelegateProofError> {
            std::future::pending().await
        }
    }

    #[async_trait]
    impl ExternalConstraintVerifier for PendingProvider {
        async fn verify(
            &self,
            _grant: &DelegationGrant,
            _request: &DelegationUseRequest,
            _now: DateTime<Utc>,
        ) -> Result<VerifiedConstraintEvidence, ConstraintVerificationError> {
            std::future::pending().await
        }
    }

    #[async_trait]
    impl DelegationCedarEvaluator for PendingProvider {
        async fn evaluate(
            &self,
            _request: CedarEvaluationRequest,
            _now: DateTime<Utc>,
        ) -> Result<CedarEvaluation, CedarEvaluationError> {
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn pending_proof_constraint_or_policy_provider_times_out_without_evaluation() {
        let h = Harness::new(CedarDecision::Permit).await;
        assert_eq!(h.authorizer.evaluation_timeout, EVALUATION_TIMEOUT);
        for stage in ["proof", "constraint", "policy"] {
            let mut authorizer = h.authorizer.clone();
            authorizer.evaluation_timeout = std::time::Duration::from_millis(1);
            match stage {
                "proof" => authorizer.proof = Arc::new(PendingProvider),
                "constraint" => authorizer.constraints = Arc::new(PendingProvider),
                "policy" => authorizer.cedar = Arc::new(PendingProvider),
                _ => unreachable!(),
            }
            assert_eq!(
                authorizer.evaluate(&h.request).await,
                Err(DelegationUseError::Unavailable),
                "{stage}"
            );
        }
    }

    #[tokio::test]
    async fn exact_operation_constraints_bind_both_profile_and_digest() {
        let mut template = pending_grant();
        template.terms.constraints = crate::Constraints {
            mode: crate::ConstraintMode::ExactOperation,
            request_profile: Some("https://commerce.example/profiles/desk-lamp-purchase/v1".into()),
            request_digest: Some(format!("sha256:{}", "c".repeat(64))),
            profile: None,
            document_ref: None,
            document_digest: None,
            evaluator: None,
        };
        let h = Harness::with_template(CedarDecision::Permit, template).await;
        let authorizer = DelegationUseAuthorizer::with_clock(
            h.lifecycle.clone(),
            h.proof.clone(),
            // Exact-operation evaluation must never call this external source.
            Arc::new(Constraint { reject: true }),
            h.authorizer.cedar.clone(),
            h.clock.clone(),
        );
        let evaluated = authorizer.evaluate(&h.request).await.unwrap();
        assert_eq!(
            evaluated.constraint_evidence_digest(),
            h.request.operation_digest
        );
        let mut wrong_profile = h.request.clone();
        wrong_profile.operation_profile = "urn:example:operation:other".into();
        let mut wrong_digest = h.request.clone();
        wrong_digest.operation_digest = format!("sha256:{}", "f".repeat(64));
        for request in [wrong_profile, wrong_digest] {
            assert_eq!(
                authorizer.evaluate(&request).await,
                Err(DelegationUseError::ConstraintNotVerified)
            );
        }
    }

    struct TimedProof {
        clock: Arc<FixedClock>,
        after: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    }

    #[async_trait]
    impl DelegateProofVerifier for TimedProof {
        async fn verify(
            &self,
            _grant: &DelegationGrant,
            _request: &DelegationUseRequest,
            _now: DateTime<Utc>,
        ) -> Result<VerifiedDelegateProof, DelegateProofError> {
            self.clock.set(self.after);
            Ok(VerifiedDelegateProof {
                evidence_ref: format!("urn:marty:oid4vp-proof:{}", _request.challenge_id),
                challenge: _request.challenge_id.simple().to_string(),
                verified_at: self.after,
                valid_until: self.valid_until,
            })
        }
    }

    struct TimedConstraint {
        clock: Arc<FixedClock>,
        after: DateTime<Utc>,
        context: serde_json::Value,
    }

    #[async_trait]
    impl ExternalConstraintVerifier for TimedConstraint {
        async fn verify(
            &self,
            grant: &DelegationGrant,
            _request: &DelegationUseRequest,
            _now: DateTime<Utc>,
        ) -> Result<VerifiedConstraintEvidence, ConstraintVerificationError> {
            self.clock.set(self.after);
            Ok(VerifiedConstraintEvidence {
                valid_until: grant.terms.valid_until,
                checked_at: self.after,
                evidence_ref: "urn:example:constraint-evidence:timed".into(),
                context: self.context.clone(),
                evidence_digest: format!("sha256:{}", "d".repeat(64)),
            })
        }
    }

    struct UnexpectedCedar;

    #[async_trait]
    impl DelegationCedarEvaluator for UnexpectedCedar {
        async fn evaluate(
            &self,
            _request: CedarEvaluationRequest,
            _now: DateTime<Utc>,
        ) -> Result<CedarEvaluation, CedarEvaluationError> {
            panic!("invalid or expired evidence must not reach Cedar")
        }
    }

    #[tokio::test]
    async fn clock_regression_between_proof_and_constraint_fails_before_cedar() {
        let h = Harness::new(CedarDecision::Permit).await;
        let now = h.clock.now();
        let authorizer = DelegationUseAuthorizer::with_clock(
            h.lifecycle.clone(),
            Arc::new(TimedProof {
                clock: h.clock.clone(),
                after: now + Duration::seconds(2),
                valid_until: now + Duration::minutes(1),
            }),
            Arc::new(TimedConstraint {
                clock: h.clock.clone(),
                // Still later than the initial clock, but earlier than the
                // previous trusted observation. Comparing only start misses it.
                after: now + Duration::seconds(1),
                context: serde_json::json!({"authorized": true}),
            }),
            Arc::new(UnexpectedCedar),
            h.clock.clone(),
        );
        assert_eq!(
            authorizer.evaluate(&h.request).await,
            Err(DelegationUseError::EvidenceExpired)
        );
    }

    #[tokio::test]
    async fn proof_expiry_during_constraint_resolution_fails_before_cedar() {
        let h = Harness::new(CedarDecision::Permit).await;
        let now = h.clock.now();
        let authorizer = DelegationUseAuthorizer::with_clock(
            h.lifecycle.clone(),
            Arc::new(TimedProof {
                clock: h.clock.clone(),
                after: now,
                valid_until: now + Duration::seconds(1),
            }),
            Arc::new(TimedConstraint {
                clock: h.clock.clone(),
                after: now + Duration::seconds(1),
                context: serde_json::json!({"authorized": true}),
            }),
            Arc::new(UnexpectedCedar),
            h.clock.clone(),
        );
        assert_eq!(
            authorizer.evaluate(&h.request).await,
            Err(DelegationUseError::EvidenceExpired)
        );
    }

    #[tokio::test]
    async fn oversized_constraint_context_fails_before_cedar() {
        let h = Harness::new(CedarDecision::Permit).await;
        let authorizer = DelegationUseAuthorizer::with_clock(
            h.lifecycle.clone(),
            h.proof.clone(),
            Arc::new(TimedConstraint {
                clock: h.clock.clone(),
                after: h.clock.now(),
                context: serde_json::json!({"data": "x".repeat(MAX_CONSTRAINT_CONTEXT_BYTES)}),
            }),
            Arc::new(UnexpectedCedar),
            h.clock.clone(),
        );
        assert_eq!(
            authorizer.evaluate(&h.request).await,
            Err(DelegationUseError::ConstraintNotVerified)
        );
    }

    #[test]
    fn cached_future_expired_or_overlong_cedar_observations_are_rejected() {
        let now = pending_grant().created_at;
        let valid = CedarEvaluation {
            decision: CedarDecision::Permit,
            policy_id: "urn:example:policy:1".into(),
            policy_revision: 1,
            policy_digest: format!("sha256:{}", "a".repeat(64)),
            evaluated_at: now,
            valid_until: now + Duration::seconds(MAX_POLICY_OBSERVATION_AGE_SECONDS),
        };
        assert!(validate_cedar_result(&valid, now, now).is_ok());
        let mut cached = valid.clone();
        cached.evaluated_at = now - Duration::seconds(1);
        cached.valid_until = now + Duration::seconds(20);
        let mut future = valid.clone();
        future.evaluated_at = now + Duration::seconds(1);
        let mut expired = valid.clone();
        expired.valid_until = now;
        let mut overlong = valid.clone();
        overlong.valid_until += Duration::nanoseconds(1);
        for result in [cached, future, expired, overlong] {
            assert_eq!(
                validate_cedar_result(&result, now, now),
                Err(DelegationUseError::PolicyDenied)
            );
        }
        let mut overflowing = valid;
        overflowing.evaluated_at = DateTime::<Utc>::MAX_UTC;
        overflowing.valid_until = DateTime::<Utc>::MAX_UTC;
        assert_eq!(
            validate_cedar_result(&overflowing, now, DateTime::<Utc>::MAX_UTC),
            Err(DelegationUseError::PolicyDenied)
        );
    }
}

#[cfg(test)]
mod mmf_cedar_tests {
    use super::*;
    use mmf_security::cedar::CedarConfig;

    const SCHEMA: &str = r#"
namespace Delegation {
  entity Organization {};
  entity Role in [Organization] {};
  entity User in [Organization, Role] { status: String };
  entity Resource in [Organization] {};
  action "urn:commerce:action:purchase.complete" appliesTo {
    principal: [User],
    resource: [Resource],
    context: {
      organization_id: String,
      grant_id: String,
      grant_revision: Long,
      actor_type: String,
      grantor: String,
      grantor_type: String,
      subject: String,
      subject_type: String,
      delegate: String,
      delegate_type: String,
      audience: String,
      operation_profile: String,
      operation_digest: String,
      constraint_context: { authorized: Bool },
      constraint_evidence_digest: String,
      delegate_proof_verified: Bool,
      consent_and_authority_verified: Bool,
    }
  };
}
"#;

    struct Source(ResolvedCedarPolicy);
    #[async_trait]
    impl CedarPolicySource for Source {
        async fn resolve_active(
            &self,
            request: &CedarEvaluationRequest,
            _now: DateTime<Utc>,
        ) -> Result<ResolvedCedarPolicy, CedarPolicySourceError> {
            if request.organization_id != self.0.organization_id
                || request.actor != request.delegate
            {
                return Err(CedarPolicySourceError);
            }
            Ok(self.0.clone())
        }
    }

    fn policy(organization_id: Uuid, now: DateTime<Utc>) -> ResolvedCedarPolicy {
        let config = CedarConfig {
            entity_types: CedarEntityTypes {
                principal: "Delegation::User".into(),
                action: "Delegation::Action".into(),
                resource: "Delegation::Resource".into(),
            },
            ..CedarConfig::default()
        };
        let organization = organization_id.to_string();
        let policy_source = format!(
            r#"
@id("delegated-commerce-member-permit")
permit (
  principal is Delegation::User,
  action == Delegation::Action::"urn:commerce:action:purchase.complete",
  resource is Delegation::Resource
)
when {{
  principal in Delegation::Role::"delegate"
  && principal.status == "ACTIVE"
  && resource in Delegation::Organization::"{organization}"
  && context.organization_id == "{organization}"
  && context.actor_type == "EXTERNAL"
  && context.delegate_type == "EXTERNAL"
  && context.grantor_type == "USER"
  && context.subject_type == "USER"
  && context.constraint_context.authorized
  && context.delegate_proof_verified
  && context.consent_and_authority_verified
}};
"#
        );
        let engine = CedarPolicyEngine::from_human_schema(&policy_source, SCHEMA, config).unwrap();
        ResolvedCedarPolicy {
            organization_id,
            policy_id: "urn:example:policies:delegated-commerce".into(),
            revision: 7,
            policy_digest: format!("sha256:{}", "e".repeat(64)),
            valid_until: now + Duration::seconds(20),
            entity_types: CedarEntityTypes {
                principal: "Delegation::User".into(),
                action: "Delegation::Action".into(),
                resource: "Delegation::Resource".into(),
            },
            entities: serde_json::json!([
                {"uid":{"type":"Delegation::Organization","id":organization},"attrs":{},"parents":[]},
                {"uid":{"type":"Delegation::Role","id":"delegate"},"attrs":{},"parents":[{"type":"Delegation::Organization","id":organization}]},
                {"uid":{"type":"Delegation::User","id":"https://agents.example/agents/shopper-1"},"attrs":{"status":"ACTIVE"},"parents":[
                    {"type":"Delegation::Organization","id":organization},
                    {"type":"Delegation::Role","id":"delegate"}
                ]},
                {"uid":{"type":"Delegation::Resource","id":"urn:commerce:product:lamp-001"},"attrs":{},"parents":[{"type":"Delegation::Organization","id":organization}]}
            ]),
            engine: Arc::new(engine),
        }
    }

    fn request(organization_id: Uuid) -> CedarEvaluationRequest {
        let delegate = Principal {
            principal_type: crate::PrincipalType::External,
            id: "https://agents.example/agents/shopper-1".into(),
        };
        CedarEvaluationRequest {
            organization_id,
            grant_id: Uuid::new_v4(),
            grant_revision: 3,
            actor: delegate.clone(),
            grantor: Principal {
                principal_type: crate::PrincipalType::User,
                id: "https://identity.example/users/customer-1".into(),
            },
            subject: Principal {
                principal_type: crate::PrincipalType::User,
                id: "https://identity.example/users/customer-1".into(),
            },
            delegate,
            action: "urn:commerce:action:purchase.complete".into(),
            audience: "https://merchant.example".into(),
            resource: "urn:commerce:product:lamp-001".into(),
            operation_profile: "https://commerce.example/profiles/desk-lamp-purchase/v1".into(),
            operation_digest: format!("sha256:{}", "c".repeat(64)),
            constraint_context: serde_json::json!({"authorized":true}),
            constraint_evidence_digest: format!("sha256:{}", "d".repeat(64)),
        }
    }

    #[tokio::test]
    async fn canonical_mmf_cedar_engine_enforces_membership_and_verified_context() {
        let organization_id = Uuid::new_v4();
        let now = Utc::now();
        let evaluator = MmfCedarEvaluator::new(Arc::new(Source(policy(organization_id, now))));
        let allowed = evaluator
            .evaluate(request(organization_id), now)
            .await
            .unwrap();
        assert_eq!(allowed.decision, CedarDecision::Permit);
        assert_eq!(allowed.policy_id, "urn:example:policies:delegated-commerce");
        assert_eq!(allowed.policy_revision, 7);

        let mut denied_request = request(organization_id);
        denied_request.constraint_context = serde_json::json!({"authorized":false});
        let denied = evaluator.evaluate(denied_request, now).await.unwrap();
        assert_eq!(denied.decision, CedarDecision::Forbid);
    }

    #[tokio::test]
    async fn cedar_policy_source_is_organization_scoped() {
        let configured_organization = Uuid::new_v4();
        let other_organization = Uuid::new_v4();
        let now = Utc::now();
        let evaluator =
            MmfCedarEvaluator::new(Arc::new(Source(policy(configured_organization, now))));
        assert!(evaluator
            .evaluate(request(other_organization), now)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn canonical_cedar_requires_role_resource_ownership_and_typed_context() {
        let organization_id = Uuid::new_v4();
        let now = Utc::now();
        let mut without_role = policy(organization_id, now);
        without_role.entities[2]["parents"] = serde_json::json!([
            {"type":"Delegation::Organization","id":organization_id.to_string()}
        ]);
        let mut without_owner = policy(organization_id, now);
        without_owner.entities[3]["parents"] = serde_json::json!([]);
        for snapshot in [without_role, without_owner] {
            let evaluator = MmfCedarEvaluator::new(Arc::new(Source(snapshot)));
            assert_eq!(
                evaluator
                    .evaluate(request(organization_id), now)
                    .await
                    .unwrap()
                    .decision,
                CedarDecision::Forbid
            );
        }
        let evaluator = MmfCedarEvaluator::new(Arc::new(Source(policy(organization_id, now))));
        let mut malformed = request(organization_id);
        malformed.constraint_context = serde_json::json!({"authorized": "true"});
        assert!(evaluator.evaluate(malformed, now).await.is_err());
    }

    #[tokio::test]
    async fn canonical_cedar_context_preserves_each_principal_type() {
        let organization_id = Uuid::new_v4();
        let now = Utc::now();
        let evaluator = MmfCedarEvaluator::new(Arc::new(Source(policy(organization_id, now))));
        let original = request(organization_id);
        let mut changed_actor = original.clone();
        changed_actor.actor.principal_type = crate::PrincipalType::User;
        changed_actor.delegate.principal_type = crate::PrincipalType::User;
        let mut changed_grantor = original.clone();
        changed_grantor.grantor.principal_type = crate::PrincipalType::Organization;
        let mut changed_subject = original.clone();
        changed_subject.subject.principal_type = crate::PrincipalType::Organization;
        for changed in [changed_actor, changed_grantor, changed_subject] {
            // IDs and the trusted entity graph are identical. The active
            // policy must still be able to distinguish the principal types.
            assert_eq!(
                evaluator.evaluate(changed, now).await.unwrap().decision,
                CedarDecision::Forbid
            );
        }
        assert_eq!(
            evaluator.evaluate(original, now).await.unwrap().decision,
            CedarDecision::Permit
        );
    }

    #[tokio::test]
    async fn cedar_adapter_rejects_typed_delegate_mismatch_and_clock_overflow() {
        let organization_id = Uuid::new_v4();
        let now = Utc::now();
        let evaluator = MmfCedarEvaluator::new(Arc::new(Source(policy(organization_id, now))));
        let mut mismatched = request(organization_id);
        mismatched.actor.principal_type = crate::PrincipalType::User;
        assert!(evaluator.evaluate(mismatched, now).await.is_err());
        assert!(evaluator
            .evaluate(request(organization_id), DateTime::<Utc>::MAX_UTC)
            .await
            .is_err());
    }
}
