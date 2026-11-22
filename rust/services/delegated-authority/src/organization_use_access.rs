//! Current full-machine component access from the Organization owner. Workload
//! authentication is established separately; grants/consent/domain policy still
//! run through their existing owners. No public route is installed here.
use crate::{
    BindingMethod, DelegationCommandCaller, DelegationGrant, DelegationUseCommandAuthorizer,
    DelegationUseCommandError as Error, DelegationUseIngressAuthorizer,
    DelegationUseIngressOperation, DelegationUseIntent, GrantStatus, PrincipalType,
    VerifiedDelegationCommandAccess,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use marty_organization::machine_use_access::{
    MachineUseAccessRequest, MachineUseAccessScope, PgMachineUseAccessSource,
};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct OrganizationDelegationUseCommandAuthorizer {
    source: PgMachineUseAccessSource,
}
impl OrganizationDelegationUseCommandAuthorizer {
    pub fn new(source: PgMachineUseAccessSource) -> Self {
        Self { source }
    }
    pub async fn readiness(&self) -> Result<(), Error> {
        self.source
            .readiness()
            .await
            .map_err(|_| Error::Unavailable)
    }
    fn context(&self, caller: &DelegationCommandCaller) -> Result<(), Error> {
        if caller.organization_id() != self.source.selection().organization_id()
            || caller.actor().principal_type != PrincipalType::MachineIdentity
            || caller.authentication_session_ref().is_some()
        {
            return Err(Error::AccessDenied);
        }
        Ok(())
    }
    fn grant_context(
        &self,
        caller: &DelegationCommandCaller,
        grant: &DelegationGrant,
    ) -> Result<(), Error> {
        self.context(caller)?;
        grant.validate().map_err(|_| Error::AccessDenied)?;
        if grant.id.is_nil()
            || grant.organization_id != caller.organization_id()
            || grant.terms.delegate != *caller.actor()
            || grant.terms.binding.method != BindingMethod::Key
        {
            return Err(Error::AccessDenied);
        }
        Ok(())
    }
    async fn observe(
        &self,
        caller: &DelegationCommandCaller,
        request: MachineUseAccessRequest,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, Error> {
        self.context(caller)?;
        let scope = MachineUseAccessScope {
            organization_id: caller.organization_id(),
            principal_id: caller.actor().id.clone(),
            request,
        };
        let observation = self
            .source
            .observe(scope.clone(), now)
            .await
            .map_err(|_| Error::AccessDenied)?;
        if observation.scope() != &scope {
            return Err(Error::AccessDenied);
        }
        Ok(VerifiedDelegationCommandAccess {
            observed_at: observation.observed_at(),
            valid_until: observation.valid_until(),
        })
    }
}
#[async_trait]
impl DelegationUseCommandAuthorizer for OrganizationDelegationUseCommandAuthorizer {
    async fn authorize(
        &self,
        caller: &DelegationCommandCaller,
        intent: &DelegationUseIntent,
        grant: &DelegationGrant,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, Error> {
        self.grant_context(caller, grant)?;
        if grant.current_status(now) != GrantStatus::Active || grant.terms.valid_from > now {
            return Err(Error::AccessDenied);
        }
        let key = grant
            .terms
            .binding
            .key_thumbprint
            .clone()
            .ok_or(Error::AccessDenied)?;
        let request = match intent {
            DelegationUseIntent::Start {
                grant: reference, ..
            } => {
                if reference.id != grant.id
                    || reference.revision != grant.revision
                    || reference.terms_digest != grant.terms_digest
                {
                    return Err(Error::AccessDenied);
                }
                MachineUseAccessRequest::Start {
                    grant_id: grant.id,
                    grant_revision: grant.revision,
                    terms_digest: grant.terms_digest.clone(),
                    key_thumbprint: key,
                }
            }
            DelegationUseIntent::Finalize {
                challenge_id,
                proof_submission_id,
            } => {
                if proof_submission_id.is_nil() {
                    return Err(Error::AccessDenied);
                }
                MachineUseAccessRequest::Finalize {
                    grant_id: grant.id,
                    grant_revision: grant.revision,
                    terms_digest: grant.terms_digest.clone(),
                    key_thumbprint: key,
                    challenge_id: *challenge_id,
                }
            }
        };
        self.observe(caller, request, now).await
    }
    async fn authorize_recovery(
        &self,
        caller: &DelegationCommandCaller,
        original_grant: &DelegationGrant,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, Error> {
        self.grant_context(caller, original_grant)?;
        // Current read rights remain mandatory; old grant/key expiry, revocation
        // or proof consumption must not prevent authorized historical recovery.
        self.observe(
            caller,
            MachineUseAccessRequest::Recover {
                grant_id: original_grant.id,
                grant_revision: original_grant.revision,
                terms_digest: original_grant.terms_digest.clone(),
            },
            now,
        )
        .await
    }
}
#[async_trait]
impl DelegationUseIngressAuthorizer for OrganizationDelegationUseCommandAuthorizer {
    async fn authorize_ingress(
        &self,
        caller: &DelegationCommandCaller,
        challenge_id: Uuid,
        operation: DelegationUseIngressOperation,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, Error> {
        let request = match operation {
            DelegationUseIngressOperation::RequestRead => {
                MachineUseAccessRequest::RequestRead { challenge_id }
            }
            DelegationUseIngressOperation::ProofSubmit => {
                MachineUseAccessRequest::ProofSubmit { challenge_id }
            }
        };
        self.observe(caller, request, now).await
    }
}

#[cfg(test)]
#[path = "organization_use_access_tests.rs"]
mod tests;
