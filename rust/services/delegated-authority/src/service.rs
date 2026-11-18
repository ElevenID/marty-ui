use std::sync::Arc;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use crate::{DelegationGrant, DelegationGrantRepository, GrantApproval, GrantStatus, GrantValidationError, RepositoryError};

#[async_trait]
pub trait ConsentEvidenceVerifier: Send + Sync {
    /// Verify the authenticated approver, their authority to grant, the trusted
    /// approval evidence, and that the displayed terms digest is the approved one.
    async fn verify_approval(&self, organization_id: Uuid, grant_id: Uuid, authenticated_approver: &str,
        evidence_ref: &str, authority_evidence_ref: &str, terms_digest: &str)
        -> Result<(), ConsentVerificationError>;
}
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("consent evidence verification failed")]
pub struct ConsentVerificationError;

#[derive(Clone)]
pub struct DelegationAuthorityService {
    repository: Arc<dyn DelegationGrantRepository>,
    consent_verifier: Arc<dyn ConsentEvidenceVerifier>,
}
impl DelegationAuthorityService {
    pub fn new(repository: Arc<dyn DelegationGrantRepository>, consent_verifier: Arc<dyn ConsentEvidenceVerifier>) -> Self {
        Self { repository, consent_verifier }
    }
    pub async fn propose(&self, grant: DelegationGrant, now: DateTime<Utc>) -> Result<DelegationGrant, ServiceError> {
        grant.validate(now)?;
        if grant.status != GrantStatus::Pending || grant.approval.is_some() || grant.revision != 1 {
            return Err(ServiceError::InvalidTransition);
        }
        self.repository.insert(grant.clone()).await?; Ok(grant)
    }
    pub async fn approve(&self, organization_id: Uuid, grant_id: Uuid, expected_revision: u64,
        authenticated_approver: &crate::Principal, evidence_ref: &str, authority_evidence_ref: &str,
        now: DateTime<Utc>) -> Result<DelegationGrant, ServiceError> {
        let mut grant = self.load_current(organization_id, grant_id, expected_revision, now).await?;
        if grant.status != GrantStatus::Pending { return Err(ServiceError::InvalidTransition); }
        self.consent_verifier.verify_approval(organization_id, grant_id, &authenticated_approver.id,
            evidence_ref, authority_evidence_ref, &grant.terms_digest).await
            .map_err(|_| ServiceError::ConsentNotVerified)?;
        grant.approval = Some(GrantApproval { profile: "urn:marty:delegation-approval:v1".into(),
            grant_id, approver: authenticated_approver.clone(), evidence_ref: evidence_ref.into(),
            authority_evidence_ref: authority_evidence_ref.into(), terms_digest: grant.terms_digest.clone(),
            approved_at: now });
        grant.status = GrantStatus::Active;
        self.save_next(grant, expected_revision, now).await
    }
    pub async fn suspend(&self, organization_id: Uuid, grant_id: Uuid, expected_revision: u64,
        now: DateTime<Utc>) -> Result<DelegationGrant, ServiceError> {
        let mut grant = self.load_current(organization_id, grant_id, expected_revision, now).await?;
        if grant.status != GrantStatus::Active { return Err(ServiceError::InvalidTransition); }
        grant.status = GrantStatus::Suspended; self.save_next(grant, expected_revision, now).await
    }
    pub async fn reinstate(&self, organization_id: Uuid, grant_id: Uuid, expected_revision: u64,
        now: DateTime<Utc>) -> Result<DelegationGrant, ServiceError> {
        let mut grant = self.load_current(organization_id, grant_id, expected_revision, now).await?;
        if grant.status != GrantStatus::Suspended { return Err(ServiceError::InvalidTransition); }
        if grant.terms.valid_until <= now { return Err(ServiceError::Expired); }
        grant.status = GrantStatus::Active; self.save_next(grant, expected_revision, now).await
    }
    pub async fn revoke(&self, organization_id: Uuid, grant_id: Uuid, expected_revision: u64,
        now: DateTime<Utc>) -> Result<DelegationGrant, ServiceError> {
        let mut grant = self.load_current(organization_id, grant_id, expected_revision, now).await?;
        if !matches!(grant.status, GrantStatus::Pending | GrantStatus::Active | GrantStatus::Suspended) {
            return Err(ServiceError::InvalidTransition);
        }
        grant.status = GrantStatus::Revoked; self.save_next(grant, expected_revision, now).await
    }
    pub async fn resolve(&self, organization_id: Uuid, grant_id: Uuid, now: DateTime<Utc>)
        -> Result<DelegationGrant, ServiceError> {
        let grant = self.repository.get(organization_id, grant_id).await?.ok_or(ServiceError::NotFound)?;
        if grant.current_status(now) != grant.status {
            return Err(ServiceError::Expired);
        }
        Ok(grant)
    }
    async fn load_current(&self, organization_id: Uuid, grant_id: Uuid, expected_revision: u64,
        now: DateTime<Utc>) -> Result<DelegationGrant, ServiceError> {
        let grant = self.repository.get(organization_id, grant_id).await?.ok_or(ServiceError::NotFound)?;
        if grant.revision != expected_revision { return Err(ServiceError::Repository(RepositoryError::RevisionConflict)); }
        if grant.current_status(now) == GrantStatus::Expired { return Err(ServiceError::Expired); }
        Ok(grant)
    }
    async fn save_next(&self, mut grant: DelegationGrant, expected_revision: u64, now: DateTime<Utc>)
        -> Result<DelegationGrant, ServiceError> {
        grant.revision = expected_revision.checked_add(1).ok_or(ServiceError::RevisionOverflow)?;
        grant.updated_at = now;
        grant.validate(now)?;
        Ok(self.repository.compare_and_swap(grant.organization_id, grant.id, expected_revision, grant).await?)
    }
}
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("delegation grant not found")] NotFound,
    #[error("delegation grant transition is not allowed")] InvalidTransition,
    #[error("consent evidence was not verified")] ConsentNotVerified,
    #[error("delegation grant has expired")] Expired,
    #[error("delegation revision overflow")] RevisionOverflow,
    #[error(transparent)] Validation(#[from] GrantValidationError),
    #[error(transparent)] Repository(#[from] RepositoryError),
}
