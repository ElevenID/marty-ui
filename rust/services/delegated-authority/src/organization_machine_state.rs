//! Concrete full-machine source adapter over Organization's distinct registry.
//! The configured tenant/deployment chooses the registered MAP. Use payloads
//! cannot supply replacement source documents or promote agent enrollment.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use marty_organization::machine_registry::{MachineRegistryUseScope, PgMachineRegistrySource};

use crate::{
    machine_auth::{
        MachineAuthenticationStateSource, MachineEvidenceError, ResolvedMachineAuthenticationState,
    },
    BindingMethod, DelegationGrant, DelegationUseRequest, PrincipalType,
};

#[derive(Clone, Debug)]
pub struct OrganizationMachineAuthenticationStateSource {
    source: PgMachineRegistrySource,
}

impl OrganizationMachineAuthenticationStateSource {
    pub fn new(source: PgMachineRegistrySource) -> Self {
        Self { source }
    }
    pub async fn readiness(&self) -> Result<(), MachineEvidenceError> {
        self.source
            .readiness()
            .await
            .map_err(|_| MachineEvidenceError)
    }
}

#[async_trait]
impl MachineAuthenticationStateSource for OrganizationMachineAuthenticationStateSource {
    async fn resolve_current(
        &self,
        grant: &DelegationGrant,
        request: &DelegationUseRequest,
        now: DateTime<Utc>,
    ) -> Result<ResolvedMachineAuthenticationState, MachineEvidenceError> {
        if request.actor.principal_type != PrincipalType::MachineIdentity
            || grant.terms.delegate != request.actor
            || grant.organization_id != request.organization_id
            || request.organization_id != self.source.selection().organization_id()
            || grant.id != request.grant_id
            || grant.revision != request.expected_revision
            || grant.terms.binding.method != BindingMethod::Key
        {
            return Err(MachineEvidenceError);
        }
        let observation = self
            .source
            .observe(
                MachineRegistryUseScope {
                    organization_id: request.organization_id,
                    principal_id: request.actor.id.clone(),
                    key_thumbprint: grant
                        .terms
                        .binding
                        .key_thumbprint
                        .clone()
                        .ok_or(MachineEvidenceError)?,
                    grant_id: grant.id,
                    grant_revision: grant.revision,
                    challenge_id: request.challenge_id,
                    action: request.action.clone(),
                    audience: request.audience.clone(),
                    resource: request.resource.clone(),
                    operation_profile: request.operation_profile.clone(),
                    operation_digest: request.operation_digest.clone(),
                },
                now,
            )
            .await
            .map_err(|_| MachineEvidenceError)?;
        let documents = observation.documents();
        Ok(ResolvedMachineAuthenticationState {
            binding_record: documents.binding_record.clone(),
            binding_configuration: documents.binding_configuration.clone(),
            machine_identity: documents.machine_identity.clone(),
            machine_authentication_policy: documents.machine_authentication_policy.clone(),
            evidence_ref: observation.evidence_ref().into(),
            observed_at: observation.observed_at(),
            valid_until: observation.valid_until(),
        })
    }
}
