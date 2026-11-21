//! Concrete MMF Cedar adapter for the MAP's separately selected machine policy.
//! This local action mapping authenticates a managed machine; it does not run the
//! relying domain's requested business action or replace delegated authorization.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use mmf_security::cedar::{CedarAuthorizationRequest, CedarEntityTypes, CedarPolicyEngine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    domain::valid_digest,
    machine_auth::{
        MachineAuthenticationScope, MachineAuthorizationVerifier, MachineEvidenceError,
        MachineEvidenceRequest, VerifiedMachineAuthorization,
    },
    DelegationClock, SystemDelegationClock,
};
use marty_principal_runtime_binding::machine_policy::valid_policy_revision;

pub const MACHINE_AUTHENTICATION_ACTION: &str = "urn:marty:machine:authenticate";

/// Independently loaded policy and schema compiled by the canonical MMF engine,
/// with the exact current tenant/runtime entity graph. The source must bind its
/// digest to both policy and schema and authenticate the selected policy record.
#[derive(Clone)]
pub struct ResolvedMachineCedarPolicy {
    pub scope: MachineAuthenticationScope,
    pub policy_set_id: Uuid,
    pub policy_type: String,
    pub status: String,
    pub revision: u64,
    pub policy_digest: String,
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub entity_types: CedarEntityTypes,
    pub entities: Value,
    pub engine: Arc<CedarPolicyEngine>,
}

#[async_trait]
pub trait MachineCedarPolicySource: Send + Sync {
    async fn resolve_current(
        &self,
        scope: &MachineAuthenticationScope,
        policy_set_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<ResolvedMachineCedarPolicy, MachineEvidenceError>;
}

#[derive(Clone)]
pub struct MmfMachineAuthorizationVerifier {
    source: Arc<dyn MachineCedarPolicySource>,
    clock: Arc<dyn DelegationClock>,
}

impl MmfMachineAuthorizationVerifier {
    pub fn new(source: Arc<dyn MachineCedarPolicySource>) -> Self {
        Self::with_clock(source, Arc::new(SystemDelegationClock))
    }
    pub fn with_clock(
        source: Arc<dyn MachineCedarPolicySource>,
        clock: Arc<dyn DelegationClock>,
    ) -> Self {
        Self { source, clock }
    }
}

#[async_trait]
impl MachineAuthorizationVerifier for MmfMachineAuthorizationVerifier {
    async fn verify_permitted(
        &self,
        request: MachineEvidenceRequest<'_>,
    ) -> Result<VerifiedMachineAuthorization, MachineEvidenceError> {
        let policy_set_id = request
            .policy
            .authorization_policy_set_id()
            .ok_or(MachineEvidenceError)?;
        let policy = self
            .source
            .resolve_current(request.scope, policy_set_id, request.now)
            .await?;
        let now = self.clock.now();
        let original_deadline = request
            .now
            .checked_add_signed(Duration::seconds(30))
            .ok_or(MachineEvidenceError)?;
        let source_deadline = policy
            .observed_at
            .checked_add_signed(Duration::seconds(30))
            .ok_or(MachineEvidenceError)?;
        if now < request.now
            || now >= original_deadline
            || policy.scope != *request.scope
            || policy.policy_set_id != policy_set_id
            || policy.policy_type != "MACHINE_AUTHORIZATION"
            || policy.status != "ACTIVE"
            || !valid_policy_revision(policy.revision)
            || !valid_digest(Some(&policy.policy_digest))
            || policy.observed_at > now
            || policy.valid_until <= now
            || policy.valid_until <= policy.observed_at
            || policy.valid_until > source_deadline
        {
            return Err(MachineEvidenceError);
        }
        let scope = request.scope;
        let context = json!({
            "organization_id": scope.organization_id.to_string(),
            "machine_identity_id": scope.machine_identity_id.to_string(),
            "deployment_profile_id": scope.deployment_profile_id.to_string(),
            "runtime_instance_ref": scope.runtime_instance_ref,
            "key_id": scope.key_id,
            "key_thumbprint": scope.key_thumbprint,
            "machine_authentication_policy_id": scope.policy_id.to_string(),
            "machine_authentication_policy_digest": scope.policy_digest,
            "grant_id": scope.grant_id.to_string(),
            "grant_revision": scope.grant_revision,
            "challenge_id": scope.challenge_id.to_string(),
            "challenge_digest": scope.challenge_digest,
            "proof_evidence_ref": scope.proof_evidence_ref,
            "requested_action": scope.action,
            "requested_audience": scope.audience,
            "requested_resource": scope.resource,
            "operation_profile": scope.operation_profile,
            "operation_digest": scope.operation_digest,
        });
        let decision = policy
            .engine
            .authorize_request(CedarAuthorizationRequest {
                principal_type: policy.entity_types.principal.clone(),
                principal_id: scope.principal.id.clone(),
                action_type: policy.entity_types.action.clone(),
                action_id: MACHINE_AUTHENTICATION_ACTION.into(),
                resource_type: policy.entity_types.resource.clone(),
                resource_id: scope.machine_identity_id.to_string(),
                context: context.clone(),
                entities: policy.entities,
            })
            .map_err(|_| MachineEvidenceError)?;
        if !decision.allowed || !decision.errors.is_empty() {
            return Err(MachineEvidenceError);
        }
        let completed_at = self.clock.now();
        let valid_until = policy.valid_until.min(original_deadline);
        if completed_at < now || completed_at >= valid_until {
            return Err(MachineEvidenceError);
        }
        let evidence = json!({
            "context": context,
            "policy_set_id": policy_set_id.to_string(),
            "policy_revision": policy.revision,
            "policy_digest": policy.policy_digest,
            "evaluated_at": completed_at.to_rfc3339(),
            "valid_until": valid_until.to_rfc3339(),
            "decision": "PERMIT",
        });
        let evidence_ref = format!(
            "urn:marty:machine-authorization:sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&evidence).map_err(|_| MachineEvidenceError)?)
        );
        Ok(VerifiedMachineAuthorization {
            scope: scope.clone(),
            policy_set_id,
            policy_type: policy.policy_type,
            revision: policy.revision,
            policy_digest: policy.policy_digest,
            evidence_ref,
            observed_at: policy.observed_at,
            valid_until,
        })
    }
}
