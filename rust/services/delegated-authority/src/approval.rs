//! Trusted human approval of an immutable, organization-representing KEY grant.
//!
//! Public request DTOs carry intent only. `AuthenticatedApprovalSession` is
//! supplied separately by the authenticated Gateway hop; its constructor checks
//! shape/freshness, not authentication. A login never creates consent. The
//! durable producer requires a server-issued review and an explicit CONFIRM.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    consent::{valid_digest, valid_time, valid_version},
    domain::valid_uri,
    ApprovalAdapterPin, AuthorityMode, BindingMethod, CommandGrantReference,
    ConsentProfileConfiguration, DelegationCommandCaller, DelegationGrant, GrantStatus, GrantTerms,
    Principal, PrincipalType,
};

pub const ORGANIZATION_DELEGATION_APPROVE_PERMISSION: &str = "delegation-grant:approve";
pub const ORGANIZATION_DELEGATION_VIEW_PERMISSION: &str = "delegation-grant:view";
pub const APPROVAL_SESSION_PREFIX: &str = "urn:marty:session:sha256:";

#[derive(Clone, Debug)]
pub struct OrganizationApprovalConfiguration {
    pub(crate) organization_id: Uuid,
    pub(crate) issuer: Principal,
    pub(crate) pin: ApprovalAdapterPin,
    pub(crate) review_ttl_seconds: u32,
    pub(crate) confirmation_max_age_seconds: u32,
    pub(crate) authority_validity_seconds: u32,
}

impl OrganizationApprovalConfiguration {
    pub fn new(
        organization_id: Uuid,
        issuer: Principal,
        pin: ApprovalAdapterPin,
        review_ttl_seconds: u32,
        confirmation_max_age_seconds: u32,
        authority_validity_seconds: u32,
    ) -> Result<Self, ApprovalProducerError> {
        if organization_id.is_nil()
            || issuer.principal_type != PrincipalType::Organization
            || !valid_uri(Some(&issuer.id))
            || !valid_uri(Some(&pin.profile))
            || pin.profile.len() > 512
            || !valid_version(&pin.version)
            || !valid_digest(&pin.artifact_digest)
            || !(1..=300).contains(&review_ttl_seconds)
            || !(1..=300).contains(&confirmation_max_age_seconds)
            || !(1..=15).contains(&authority_validity_seconds)
        {
            return Err(ApprovalProducerError::InvalidInput);
        }
        Ok(Self {
            organization_id,
            issuer,
            pin,
            review_ttl_seconds,
            confirmation_max_age_seconds,
            authority_validity_seconds,
        })
    }

    pub fn organization_id(&self) -> Uuid {
        self.organization_id
    }
    pub fn consent_profile(&self) -> ConsentProfileConfiguration {
        ConsentProfileConfiguration {
            pin: self.pin.clone(),
            max_observation_age_seconds: self.authority_validity_seconds,
            max_confirmation_age_seconds: self.confirmation_max_age_seconds,
            max_authority_age_seconds: self.authority_validity_seconds,
        }
    }

    pub(crate) fn check_grant(&self, grant: &DelegationGrant) -> Result<(), ApprovalProducerError> {
        grant
            .validate()
            .map_err(|_| ApprovalProducerError::InvalidInput)?;
        if grant.organization_id != self.organization_id
            || grant.authority.mode != AuthorityMode::Managed
            || grant.authority.issuer != self.issuer
            || grant.terms.subject != organization_principal(self.organization_id)
            || canonical_user_id(&grant.terms.grantor).is_none()
            || grant.terms.binding.method != BindingMethod::Key
        {
            return Err(ApprovalProducerError::AccessDenied);
        }
        Ok(())
    }

    pub(crate) fn check_pending(
        &self,
        grant: &DelegationGrant,
        now: DateTime<Utc>,
    ) -> Result<(), ApprovalProducerError> {
        self.check_grant(grant)?;
        if grant.status != GrantStatus::Pending
            || now < grant.created_at
            || now >= grant.terms.valid_until
        {
            return Err(ApprovalProducerError::Conflict);
        }
        Ok(())
    }
}

/// Independently authenticated, non-impersonated, live human session. The
/// Gateway must validate the exact cookie through Auth, require its actual
/// expiry, cap `access_valid_until` by that expiry and 30 seconds, and validate
/// the configured Origin before constructing this value. Never deserialize it
/// from an approval body or populate it from caller-controlled actor headers.
#[derive(Clone, Debug)]
pub struct AuthenticatedApprovalSession {
    pub(crate) organization_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) session_ref: String,
    pub(crate) observed_at: DateTime<Utc>,
    pub(crate) access_valid_until: DateTime<Utc>,
}

impl AuthenticatedApprovalSession {
    pub fn from_authenticated_gateway_context(
        organization_id: Uuid,
        user_id: Uuid,
        session_ref: String,
        observed_at: DateTime<Utc>,
        access_valid_until: DateTime<Utc>,
    ) -> Result<Self, ApprovalProducerError> {
        if organization_id.is_nil()
            || user_id.is_nil()
            || !valid_session_ref(&session_ref)
            || !valid_time(observed_at)
            || !valid_time(access_valid_until)
            || access_valid_until <= observed_at
            || access_valid_until > observed_at + Duration::seconds(30)
        {
            return Err(ApprovalProducerError::InvalidInput);
        }
        Ok(Self {
            organization_id,
            user_id,
            session_ref,
            observed_at,
            access_valid_until,
        })
    }
    pub fn organization_id(&self) -> Uuid {
        self.organization_id
    }
    pub fn user_id(&self) -> Uuid {
        self.user_id
    }
    pub fn actor(&self) -> Principal {
        user_principal(self.user_id)
    }
    pub fn session_ref(&self) -> &str {
        &self.session_ref
    }
    pub fn command_caller(&self) -> Result<DelegationCommandCaller, ApprovalProducerError> {
        DelegationCommandCaller::from_authenticated_context(self.organization_id, self.actor())
            .and_then(|caller| caller.with_authenticated_session_ref(self.session_ref.clone()))
            .map_err(|_| ApprovalProducerError::InvalidInput)
    }
    pub(crate) fn check(
        &self,
        organization_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(), ApprovalProducerError> {
        if self.organization_id != organization_id
            || now < self.observed_at
            || now >= self.access_valid_until
        {
            return Err(ApprovalProducerError::AccessDenied);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalReviewRequest {
    pub grant: CommandGrantReference,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExplicitApprovalConfirmation {
    pub confirmation_id: Uuid,
    pub terms_digest: String,
    pub decision: ApprovalDecision,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum ApprovalDecision {
    #[serde(rename = "CONFIRM")]
    Confirm,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApprovalReview {
    pub review_id: Uuid,
    pub grant: CommandGrantReference,
    pub terms: GrantTerms,
    pub issuer: Principal,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub confirmation_max_age_seconds: u32,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ApprovalConfirmation {
    pub confirmation_id: Uuid,
    pub review_id: Uuid,
    pub grant_id: Uuid,
    pub terms_digest: String,
    pub confirmed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    /// Historical retrieval of the same confirmation does not renew consent.
    pub recovered: bool,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ApprovalWithdrawal {
    pub confirmation_id: Uuid,
    pub grant_id: Uuid,
    pub withdrawn_at: DateTime<Utc>,
    pub recovered: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ApprovalProducerError {
    #[error("approval request or configuration is invalid")]
    InvalidInput,
    #[error("approval access was denied or expired")]
    AccessDenied,
    #[error("approval review or confirmation conflicts with its original binding")]
    Conflict,
    #[error("approval review or confirmation was not found")]
    NotFound,
    #[error("approval review or trusted authority observation has expired")]
    Stale,
    #[error("trusted approval source is unavailable")]
    Unavailable,
    #[error("approval producer credential separation or schema is not ready")]
    NotReady,
}

pub(crate) fn valid_session_ref(value: &str) -> bool {
    value
        .strip_prefix(APPROVAL_SESSION_PREFIX)
        .is_some_and(|suffix| {
            suffix.len() == 64
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}
pub fn user_principal(user_id: Uuid) -> Principal {
    Principal {
        principal_type: PrincipalType::User,
        id: format!("urn:marty:user:{user_id}"),
    }
}
pub fn organization_principal(organization_id: Uuid) -> Principal {
    Principal {
        principal_type: PrincipalType::Organization,
        id: format!("urn:marty:organization:{organization_id}"),
    }
}
pub(crate) fn canonical_user_id(principal: &Principal) -> Option<Uuid> {
    if principal.principal_type != PrincipalType::User {
        return None;
    }
    let raw = principal.id.strip_prefix("urn:marty:user:")?;
    let id = Uuid::parse_str(raw).ok()?;
    (!id.is_nil() && id.to_string() == raw).then_some(id)
}
