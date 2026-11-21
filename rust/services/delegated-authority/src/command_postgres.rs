//! Production source composition for human-administered lifecycle commands.
//! No consent or representation-authority producer credential is held here.
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use marty_organization::postgres::PostgresOrganizationStore;
use sqlx::PgPool;

use crate::{
    approval::{canonical_user_id, organization_principal},
    organization_authority::CurrentOrganizationAuthority,
    AuthenticatedApprovalSession, Authority, AuthorityMode, BindingMethod,
    ConfiguredConsentEvidenceVerifier, DelegationAuthorityService, DelegationClock,
    DelegationCommandAccessError, DelegationCommandAuthorizer, DelegationCommandCaller,
    DelegationCommandError, DelegationCommandResponse, DelegationCommandService, DelegationGrant,
    DelegationMutation, OrganizationApprovalConfiguration,
    OrganizationRepresentationAuthorityProvider, PgApprovalConfirmationSource,
    PgConsentEvidenceProvider, PgDelegationGrantRepository, VerifiedDelegationCommandAccess,
};

pub fn mutation_permission(intent: &DelegationMutation) -> &'static str {
    match intent {
        DelegationMutation::Create { .. } => "delegation-grant:create",
        DelegationMutation::Approve { .. } => "delegation-grant:approve",
        DelegationMutation::Suspend { .. } => "delegation-grant:suspend",
        DelegationMutation::Reinstate { .. } => "delegation-grant:reinstate",
        DelegationMutation::Revoke { .. } => "delegation-grant:revoke",
    }
}

#[derive(Clone)]
pub struct PgOrganizationCommandService {
    lifecycle: Arc<DelegationAuthorityService>,
    confirmations: Arc<PgApprovalConfirmationSource>,
    current: CurrentOrganizationAuthority,
    writer_pool: PgPool,
    read_pool: PgPool,
}

impl PgOrganizationCommandService {
    pub fn new(
        writer_pool: PgPool,
        evidence_read_pool: PgPool,
        organization_store: PostgresOrganizationStore,
        configuration: OrganizationApprovalConfiguration,
        authority: Authority,
        clock: Arc<dyn DelegationClock>,
    ) -> Result<Self, DelegationCommandError> {
        if authority.mode != AuthorityMode::Managed
            || authority.issuer != configuration.issuer
            || configuration.issuer != organization_principal(configuration.organization_id)
        {
            return Err(DelegationCommandError::InvalidCommand);
        }
        let verifier = ConfiguredConsentEvidenceVerifier::with_clock(
            [configuration.consent_profile()],
            Arc::new(PgConsentEvidenceProvider::new(evidence_read_pool.clone())),
            Arc::new(
                OrganizationRepresentationAuthorityProvider::from_read_sources(
                    organization_store.clone(),
                    evidence_read_pool.clone(),
                    configuration.clone(),
                    clock.clone(),
                ),
            ),
            clock.clone(),
        )
        .map_err(|_| DelegationCommandError::Unavailable)?;
        let lifecycle = Arc::new(
            DelegationAuthorityService::with_clock(
                Arc::new(PgDelegationGrantRepository::new(writer_pool.clone())),
                Arc::new(verifier),
                authority,
                clock.clone(),
            )
            .map_err(|_| DelegationCommandError::InvalidCommand)?,
        );
        Ok(Self {
            lifecycle,
            confirmations: Arc::new(PgApprovalConfirmationSource::new(
                evidence_read_pool.clone(),
                configuration.clone(),
                clock.clone(),
            )),
            current: CurrentOrganizationAuthority {
                store: organization_store,
                configuration,
                clock,
            },
            writer_pool,
            read_pool: evidence_read_pool,
        })
    }

    pub async fn readiness(&self) -> Result<(), DelegationCommandError> {
        PgDelegationGrantRepository::new(self.read_pool.clone())
            .readiness()
            .await
            .map_err(|_| DelegationCommandError::Unavailable)?;
        super::command_role_boundary::check_command_roles(
            &self.writer_pool,
            &self.read_pool,
            self.current.store.pool(),
        )
        .await
        .map_err(|_| DelegationCommandError::Unavailable)
    }

    pub async fn execute(
        &self,
        session: &AuthenticatedApprovalSession,
        raw: &[u8],
    ) -> Result<DelegationCommandResponse, DelegationCommandError> {
        session
            .check(
                self.current.configuration.organization_id,
                self.current.clock.now(),
            )
            .map_err(|_| DelegationCommandError::AccessDenied)?;
        let caller = session
            .command_caller()
            .map_err(|_| DelegationCommandError::AccessDenied)?;
        // A distinct immutable authorizer holds this exact authenticated session.
        // Its bounded observation follows the command into the locked write path.
        let authorizer = Arc::new(OrganizationCommandAuthorizer {
            current: self.current.clone(),
            session: session.clone(),
        });
        DelegationCommandService::new(
            self.lifecycle.clone(),
            authorizer,
            Some(self.confirmations.clone()),
        )
        .execute(&caller, raw)
        .await
    }
}

#[derive(Clone)]
struct OrganizationCommandAuthorizer {
    current: CurrentOrganizationAuthority,
    session: AuthenticatedApprovalSession,
}
impl OrganizationCommandAuthorizer {
    fn check_context(
        &self,
        caller: &DelegationCommandCaller,
        now: DateTime<Utc>,
    ) -> Result<(), DelegationCommandAccessError> {
        self.session
            .check(self.current.configuration.organization_id, now)
            .map_err(|_| DelegationCommandAccessError)?;
        if caller.organization_id() != self.session.organization_id()
            || canonical_user_id(caller.actor()) != Some(self.session.user_id())
            || caller.authentication_session_ref() != Some(self.session.session_ref())
        {
            return Err(DelegationCommandAccessError);
        }
        Ok(())
    }
    async fn observe(
        &self,
        caller: &DelegationCommandCaller,
        permission: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, DelegationCommandAccessError> {
        self.check_context(caller, now)?;
        let action = self
            .current
            .check_actor(self.session.user_id(), permission)
            .await
            .map_err(|_| DelegationCommandAccessError)?;
        let read = if permission == "delegation-grant:view" {
            None
        } else {
            Some(
                self.current
                    .check_actor(self.session.user_id(), "delegation-grant:view")
                    .await
                    .map_err(|_| DelegationCommandAccessError)?,
            )
        };
        let observed_at = read.as_ref().map_or(action.observed_at, |read| {
            read.observed_at.max(action.observed_at)
        });
        let valid_until = read
            .as_ref()
            .map_or(action.valid_until, |read| {
                read.valid_until.min(action.valid_until)
            })
            .min(self.session.access_valid_until);
        let current = self.current.clock.now();
        self.check_context(caller, current)?;
        if observed_at < now || observed_at > current || valid_until <= current {
            return Err(DelegationCommandAccessError);
        }
        Ok(VerifiedDelegationCommandAccess {
            observed_at,
            valid_until,
        })
    }
}

#[async_trait]
impl DelegationCommandAuthorizer for OrganizationCommandAuthorizer {
    async fn authorize_mutation(
        &self,
        caller: &DelegationCommandCaller,
        intent: &DelegationMutation,
        current: Option<&DelegationGrant>,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, DelegationCommandAccessError> {
        self.check_context(caller, now)?;
        match intent {
            DelegationMutation::Create { terms } => {
                if current.is_some()
                    || terms.grantor != self.session.actor()
                    || terms.subject != organization_principal(self.session.organization_id())
                    || terms.binding.method != BindingMethod::Key
                {
                    return Err(DelegationCommandAccessError);
                }
                terms.validate().map_err(|_| DelegationCommandAccessError)?;
            }
            _ => {
                let grant = current.ok_or(DelegationCommandAccessError)?;
                self.current
                    .configuration
                    .check_grant(grant)
                    .map_err(|_| DelegationCommandAccessError)?;
                if matches!(intent, DelegationMutation::Approve { .. })
                    && grant.terms.grantor != self.session.actor()
                {
                    return Err(DelegationCommandAccessError);
                }
            }
        }
        let mut access = self
            .observe(caller, mutation_permission(intent), now)
            .await?;
        if matches!(intent, DelegationMutation::Reinstate { .. }) {
            // A different administrator may reinstate the grant. Their mutation
            // permission cannot substitute for the original grantor's current
            // representation authority, including after a grant-row lock wait.
            let grantor =
                canonical_user_id(&current.ok_or(DelegationCommandAccessError)?.terms.grantor)
                    .ok_or(DelegationCommandAccessError)?;
            let authority = self
                .current
                .check_actor(grantor, crate::ORGANIZATION_DELEGATION_APPROVE_PERMISSION)
                .await
                .map_err(|_| DelegationCommandAccessError)?;
            access.observed_at = access.observed_at.max(authority.observed_at);
            access.valid_until = access.valid_until.min(authority.valid_until);
            self.check_context(caller, self.current.clock.now())?;
        }
        Ok(access)
    }

    async fn authorize_result_read(
        &self,
        caller: &DelegationCommandCaller,
        original: &DelegationGrant,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, DelegationCommandAccessError> {
        self.current
            .configuration
            .check_grant(original)
            .map_err(|_| DelegationCommandAccessError)?;
        // A historical result never needs the old mutation permission or ACTIVE
        // grant status. Current source read access and original actor still do.
        self.observe(caller, "delegation-grant:view", now).await
    }
}
