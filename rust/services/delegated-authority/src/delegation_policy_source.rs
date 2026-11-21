//! Concrete current Organization delegated-use Cedar policy source.
//!
//! This selection supports the service-built EXACT_OPERATION constraint only.
//! Consumer-owned external-profile/domain policy remains a separate adapter.
//! Policy selection is fixed by deployment construction, never command input.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use marty_organization::delegation_use_policy::{
    compile_delegation_use_policy, delegation_use_entity_types, DelegationPolicyPrincipal,
    DelegationUsePolicyScope, PgDelegationUsePolicySource,
};
use uuid::Uuid;

use crate::{
    CedarEvaluationRequest, CedarPolicySource, CedarPolicySourceError, DelegationClock, Principal,
    ResolvedCedarPolicy, SystemDelegationClock,
};

#[derive(Clone)]
pub struct OrganizationDelegationCedarPolicySource {
    owner: PgDelegationUsePolicySource,
    organization_id: Uuid,
    policy_id: Uuid,
    clock: Arc<dyn DelegationClock>,
}
impl OrganizationDelegationCedarPolicySource {
    pub fn new(
        owner: PgDelegationUsePolicySource,
        organization_id: Uuid,
        policy_id: Uuid,
    ) -> Result<Self, CedarPolicySourceError> {
        Self::with_clock(
            owner,
            organization_id,
            policy_id,
            Arc::new(SystemDelegationClock),
        )
    }
    pub fn with_clock(
        owner: PgDelegationUsePolicySource,
        organization_id: Uuid,
        policy_id: Uuid,
        clock: Arc<dyn DelegationClock>,
    ) -> Result<Self, CedarPolicySourceError> {
        if organization_id.is_nil() || policy_id.is_nil() {
            return Err(CedarPolicySourceError);
        }
        Ok(Self {
            owner,
            organization_id,
            policy_id,
            clock,
        })
    }
    pub async fn readiness(&self) -> Result<(), CedarPolicySourceError> {
        self.owner
            .readiness()
            .await
            .map_err(|_| CedarPolicySourceError)
    }
}
#[async_trait]
impl CedarPolicySource for OrganizationDelegationCedarPolicySource {
    async fn resolve_active(
        &self,
        request: &CedarEvaluationRequest,
        now: DateTime<Utc>,
    ) -> Result<ResolvedCedarPolicy, CedarPolicySourceError> {
        if request.organization_id != self.organization_id {
            return Err(CedarPolicySourceError);
        }
        let scope = DelegationUsePolicyScope {
            organization_id: request.organization_id,
            grant_id: request.grant_id,
            grant_revision: request.grant_revision,
            actor: principal(&request.actor)?,
            grantor: principal(&request.grantor)?,
            subject: principal(&request.subject)?,
            delegate: principal(&request.delegate)?,
            action: request.action.clone(),
            audience: request.audience.clone(),
            resource: request.resource.clone(),
            operation_profile: request.operation_profile.clone(),
            operation_digest: request.operation_digest.clone(),
            constraint_context: request.constraint_context.clone(),
            constraint_evidence_digest: request.constraint_evidence_digest.clone(),
        };
        let observation = self
            .owner
            .observe_current(self.policy_id, &scope, now)
            .await
            .map_err(|_| CedarPolicySourceError)?;
        let snapshot = observation.snapshot();
        let engine = compile_delegation_use_policy(&snapshot.policy_source, &snapshot.actions)
            .map_err(|_| CedarPolicySourceError)?;
        let completed = self.clock.now();
        if observation.scope() != &scope
            || snapshot.organization_id != self.organization_id
            || snapshot.policy_id != self.policy_id
            || observation.observed_at() < now
            || completed < observation.observed_at()
            || completed >= observation.valid_until()
            || observation.valid_until()
                > now
                    .checked_add_signed(Duration::seconds(30))
                    .ok_or(CedarPolicySourceError)?
        {
            return Err(CedarPolicySourceError);
        }
        Ok(ResolvedCedarPolicy {
            organization_id: self.organization_id,
            policy_id: format!(
                "urn:marty:delegation-use-policy:{}:{}",
                self.organization_id, self.policy_id
            ),
            revision: snapshot.revision,
            policy_digest: snapshot.policy_digest.clone(),
            valid_until: observation.valid_until(),
            entity_types: delegation_use_entity_types(),
            entities: scope.entities(),
            engine: Arc::new(engine),
        })
    }
}
fn principal(p: &Principal) -> Result<DelegationPolicyPrincipal, CedarPolicySourceError> {
    serde_json::from_value(serde_json::to_value(p).map_err(|_| CedarPolicySourceError)?)
        .map_err(|_| CedarPolicySourceError)
}

#[cfg(test)]
#[path = "delegation_policy_source_tests.rs"]
mod tests;
