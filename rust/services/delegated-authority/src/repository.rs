use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    validate_transition, AuthorityMode, DelegationClock, DelegationGrant, GrantStatus,
    GrantValidationError, VerifiedConsent,
};

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RepositoryError {
    #[error("delegation grant not found")]
    NotFound,
    #[error("delegation grant already exists")]
    AlreadyExists,
    #[error("delegation grant revision conflict")]
    RevisionConflict,
    #[error("repository insertion requires a new managed pending grant")]
    InvalidInitialState,
    #[error(transparent)]
    InvalidGrant(#[from] GrantValidationError),
    #[error("stored delegation data failed integrity validation")]
    CorruptData,
    #[error("delegation database operation failed")]
    DatabaseFailure,
    #[error("delegation schema migration checksum mismatch")]
    MigrationMismatch,
    #[error("delegation schema is not ready")]
    SchemaNotReady,
    #[error("activation requires grant-bound verified consent")]
    ActivationGuardRequired,
    #[error("activation evidence expired or clock changed before commit")]
    ActivationEvidenceExpired,
}

/// A minimal lifecycle journal entry, committed atomically with its grant revision.
///
/// This journal deliberately excludes principal identifiers, evidence references,
/// and grant documents. Authenticated operator attribution and external audit
/// delivery belong to the runtime integration; this is not an authorization log.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantAuditEvent {
    pub organization_id: Uuid,
    pub grant_id: Uuid,
    pub revision: u64,
    pub previous_status: Option<GrantStatus>,
    pub status: GrantStatus,
    pub terms_digest: String,
    pub occurred_at: DateTime<Utc>,
}

impl GrantAuditEvent {
    fn from_grant(grant: &DelegationGrant, previous_status: Option<GrantStatus>) -> Self {
        Self {
            organization_id: grant.organization_id,
            grant_id: grant.id,
            revision: grant.revision,
            previous_status,
            status: grant.status,
            terms_digest: grant.terms_digest.clone(),
            occurred_at: grant.updated_at,
        }
    }
}

/// A service-created freshness bound for one exact activation revision.
/// This is an internal persistence capability, not a serialized authorization
/// token. It cannot replace actor proof, scope checks or final-use evaluation.
#[derive(Clone)]
pub struct ActivationCommitGuard {
    organization_id: Uuid,
    grant_id: Uuid,
    revision: u64,
    terms_digest: String,
    approval: Option<crate::GrantApproval>,
    verified_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    clock: Arc<dyn DelegationClock>,
}

impl ActivationCommitGuard {
    pub(crate) fn for_verified(
        grant: &DelegationGrant,
        consent: VerifiedConsent,
        clock: Arc<dyn DelegationClock>,
    ) -> Self {
        Self {
            organization_id: grant.organization_id,
            grant_id: grant.id,
            revision: grant.revision,
            terms_digest: grant.terms_digest.clone(),
            approval: grant.approval.clone(),
            verified_at: grant.updated_at,
            valid_until: consent.valid_until.min(grant.terms.valid_until),
            clock,
        }
    }

    /// Recheck under the repository's atomic write boundary. Database adapters
    /// supply a freshly sampled database clock after their awaited writes.
    pub fn check(
        &self,
        grant: &DelegationGrant,
        database_now: Option<DateTime<Utc>>,
    ) -> Result<(), RepositoryError> {
        if grant.status != GrantStatus::Active
            || grant.organization_id != self.organization_id
            || grant.id != self.grant_id
            || grant.revision != self.revision
            || grant.terms_digest != self.terms_digest
            || grant.approval.is_none()
            || grant.approval != self.approval
            || grant.updated_at != self.verified_at
        {
            return Err(RepositoryError::ActivationGuardRequired);
        }
        for now in std::iter::once(self.clock.now()).chain(database_now) {
            if now < self.verified_at || now < grant.terms.valid_from || now >= self.valid_until {
                return Err(RepositoryError::ActivationEvidenceExpired);
            }
        }
        Ok(())
    }
}

pub(crate) fn check_activation_guard(
    grant: &DelegationGrant,
    guard: Option<&ActivationCommitGuard>,
    database_now: Option<DateTime<Utc>>,
) -> Result<(), RepositoryError> {
    if grant.status == GrantStatus::Active {
        guard
            .ok_or(RepositoryError::ActivationGuardRequired)?
            .check(grant, database_now)?;
    } else if guard.is_some() {
        return Err(RepositoryError::ActivationGuardRequired);
    }
    Ok(())
}

/// Trusted persistence port. This does not authenticate or authorize callers.
/// Implementations must validate snapshots/transitions and commit the lifecycle
/// journal atomically. Importing arbitrary active or external snapshots is not a
/// supported way to create authoritative managed grants.
#[async_trait]
pub trait DelegationGrantRepository: Send + Sync {
    async fn insert(&self, grant: DelegationGrant) -> Result<(), RepositoryError>;
    async fn get(
        &self,
        organization_id: Uuid,
        grant_id: Uuid,
    ) -> Result<Option<DelegationGrant>, RepositoryError>;
    async fn compare_and_swap(
        &self,
        organization_id: Uuid,
        grant_id: Uuid,
        expected_revision: u64,
        replacement: DelegationGrant,
    ) -> Result<DelegationGrant, RepositoryError> {
        self.compare_and_swap_guarded(
            organization_id,
            grant_id,
            expected_revision,
            replacement,
            None,
        )
        .await
    }
    /// Activation must carry the service's exact grant-bound freshness deadline.
    /// Implementations check it under their lock and after awaited database writes.
    async fn compare_and_swap_guarded(
        &self,
        organization_id: Uuid,
        grant_id: Uuid,
        expected_revision: u64,
        replacement: DelegationGrant,
        activation: Option<ActivationCommitGuard>,
    ) -> Result<DelegationGrant, RepositoryError>;
    /// Lists stored lifecycle states. Expiry must still be evaluated at use time.
    async fn list(
        &self,
        organization_id: Uuid,
        status: Option<GrantStatus>,
    ) -> Result<Vec<DelegationGrant>, RepositoryError>;
    /// Unknown grants and grants outside the organization return an empty journal.
    async fn audit(
        &self,
        organization_id: Uuid,
        grant_id: Uuid,
    ) -> Result<Vec<GrantAuditEvent>, RepositoryError>;
}

pub(crate) fn validate_initial(grant: &DelegationGrant) -> Result<(), RepositoryError> {
    grant.validate()?;
    if grant.authority.mode != AuthorityMode::Managed
        || grant.status != GrantStatus::Pending
        || grant.revision != 1
        || grant.approval.is_some()
        || grant.created_at != grant.updated_at
        || grant.created_at >= grant.terms.valid_until
    {
        return Err(RepositoryError::InvalidInitialState);
    }
    Ok(())
}

#[derive(Default)]
struct MemoryState {
    grants: HashMap<Uuid, DelegationGrant>,
    audit: HashMap<Uuid, Vec<GrantAuditEvent>>,
}

#[derive(Clone, Default)]
pub struct InMemoryDelegationGrantRepository {
    state: Arc<RwLock<MemoryState>>,
}

#[async_trait]
impl DelegationGrantRepository for InMemoryDelegationGrantRepository {
    async fn insert(&self, grant: DelegationGrant) -> Result<(), RepositoryError> {
        validate_initial(&grant)?;
        let mut state = self.state.write().await;
        if state.grants.contains_key(&grant.id) {
            return Err(RepositoryError::AlreadyExists);
        }
        state
            .audit
            .insert(grant.id, vec![GrantAuditEvent::from_grant(&grant, None)]);
        state.grants.insert(grant.id, grant);
        Ok(())
    }

    async fn get(
        &self,
        organization_id: Uuid,
        grant_id: Uuid,
    ) -> Result<Option<DelegationGrant>, RepositoryError> {
        let state = self.state.read().await;
        let grant = state
            .grants
            .get(&grant_id)
            .filter(|grant| grant.organization_id == organization_id);
        if let Some(grant) = grant {
            grant.validate().map_err(|_| RepositoryError::CorruptData)?;
        }
        Ok(grant.cloned())
    }

    async fn compare_and_swap_guarded(
        &self,
        organization_id: Uuid,
        grant_id: Uuid,
        expected_revision: u64,
        replacement: DelegationGrant,
        activation: Option<ActivationCommitGuard>,
    ) -> Result<DelegationGrant, RepositoryError> {
        let mut state = self.state.write().await;
        let current = state
            .grants
            .get(&grant_id)
            .ok_or(RepositoryError::NotFound)?;
        if current.organization_id != organization_id {
            return Err(RepositoryError::NotFound);
        }
        current
            .validate()
            .map_err(|_| RepositoryError::CorruptData)?;
        if current.revision != expected_revision {
            return Err(RepositoryError::RevisionConflict);
        }
        validate_transition(current, &replacement)?;
        check_activation_guard(&replacement, activation.as_ref(), None)?;
        let event = GrantAuditEvent::from_grant(&replacement, Some(current.status));
        state.audit.entry(grant_id).or_default().push(event);
        state.grants.insert(grant_id, replacement.clone());
        Ok(replacement)
    }

    async fn list(
        &self,
        organization_id: Uuid,
        status: Option<GrantStatus>,
    ) -> Result<Vec<DelegationGrant>, RepositoryError> {
        let state = self.state.read().await;
        let mut values = Vec::new();
        for grant in state
            .grants
            .values()
            .filter(|grant| grant.organization_id == organization_id)
        {
            grant.validate().map_err(|_| RepositoryError::CorruptData)?;
            if status.is_none_or(|wanted| grant.status == wanted) {
                values.push(grant.clone());
            }
        }
        values.sort_by_key(|grant| (grant.created_at, grant.id));
        Ok(values)
    }

    async fn audit(
        &self,
        organization_id: Uuid,
        grant_id: Uuid,
    ) -> Result<Vec<GrantAuditEvent>, RepositoryError> {
        let state = self.state.read().await;
        if state
            .grants
            .get(&grant_id)
            .is_none_or(|grant| grant.organization_id != organization_id)
        {
            return Ok(Vec::new());
        }
        Ok(state.audit.get(&grant_id).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;
    use crate::test_support::pending_grant;

    fn revoked(grant: &DelegationGrant) -> DelegationGrant {
        let mut next = grant.clone();
        next.status = GrantStatus::Revoked;
        next.revision += 1;
        next.updated_at += Duration::seconds(1);
        next
    }

    #[tokio::test]
    async fn organization_scope_hides_grants_and_journal() {
        let repository = InMemoryDelegationGrantRepository::default();
        let grant = pending_grant();
        repository.insert(grant.clone()).await.unwrap();
        let outsider = Uuid::new_v4();
        assert!(repository.get(outsider, grant.id).await.unwrap().is_none());
        assert!(repository.list(outsider, None).await.unwrap().is_empty());
        assert!(repository
            .audit(outsider, grant.id)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            repository
                .compare_and_swap(outsider, grant.id, 1, revoked(&grant))
                .await,
            Err(RepositoryError::NotFound)
        );
        assert_eq!(
            repository
                .get(grant.organization_id, grant.id)
                .await
                .unwrap(),
            Some(grant)
        );
    }

    #[tokio::test]
    async fn invalid_insert_never_creates_a_grant_or_journal() {
        let repository = InMemoryDelegationGrantRepository::default();
        let mut grant = pending_grant();
        grant.status = GrantStatus::Revoked;
        assert_eq!(
            repository.insert(grant.clone()).await,
            Err(RepositoryError::InvalidInitialState)
        );
        assert!(repository
            .get(grant.organization_id, grant.id)
            .await
            .unwrap()
            .is_none());
        assert!(repository
            .audit(grant.organization_id, grant.id)
            .await
            .unwrap()
            .is_empty());
        grant.status = GrantStatus::Pending;
        grant.terms_digest = format!("sha256:{}", "0".repeat(64));
        assert!(matches!(
            repository.insert(grant).await,
            Err(RepositoryError::InvalidGrant(
                GrantValidationError::TermsDigestMismatch
            ))
        ));
    }

    #[tokio::test]
    async fn recomputed_digest_cannot_replace_immutable_terms() {
        let repository = InMemoryDelegationGrantRepository::default();
        let grant = pending_grant();
        repository.insert(grant.clone()).await.unwrap();
        let mut next = revoked(&grant);
        next.terms.resources = vec!["urn:example:substituted".into()];
        next.terms_digest = next.calculate_terms_digest().unwrap();
        assert_eq!(
            repository
                .compare_and_swap(grant.organization_id, grant.id, 1, next)
                .await,
            Err(RepositoryError::InvalidGrant(
                GrantValidationError::ImmutableGrantDataChanged
            ))
        );
        assert_eq!(
            repository
                .get(grant.organization_id, grant.id)
                .await
                .unwrap(),
            Some(grant.clone())
        );
        assert_eq!(
            repository
                .audit(grant.organization_id, grant.id)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn concurrent_writers_commit_one_revision_and_one_event() {
        let repository = InMemoryDelegationGrantRepository::default();
        let grant = pending_grant();
        repository.insert(grant.clone()).await.unwrap();
        let (left, right) = tokio::join!(
            repository.compare_and_swap(grant.organization_id, grant.id, 1, revoked(&grant)),
            repository.compare_and_swap(grant.organization_id, grant.id, 1, revoked(&grant)),
        );
        assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
        let loser = if left.is_err() { left } else { right };
        assert_eq!(loser, Err(RepositoryError::RevisionConflict));
        let journal = repository
            .audit(grant.organization_id, grant.id)
            .await
            .unwrap();
        assert_eq!(journal.len(), 2);
        assert_eq!(journal[0].revision, 1);
        assert_eq!(journal[0].previous_status, None);
        assert_eq!(journal[1].revision, 2);
        assert_eq!(journal[1].previous_status, Some(GrantStatus::Pending));
        assert_eq!(journal[1].status, GrantStatus::Revoked);
    }

    #[tokio::test]
    async fn terminal_grants_cannot_be_resurrected_or_rewritten() {
        let repository = InMemoryDelegationGrantRepository::default();
        let grant = pending_grant();
        repository.insert(grant.clone()).await.unwrap();
        let terminal = repository
            .compare_and_swap(grant.organization_id, grant.id, 1, revoked(&grant))
            .await
            .unwrap();
        let mut next = terminal.clone();
        next.revision += 1;
        next.updated_at += Duration::seconds(1);
        assert_eq!(
            repository
                .compare_and_swap(grant.organization_id, grant.id, 2, next)
                .await,
            Err(RepositoryError::InvalidGrant(
                GrantValidationError::InvalidStatusTransition
            ))
        );
        assert_eq!(
            repository
                .audit(grant.organization_id, grant.id)
                .await
                .unwrap()
                .len(),
            2
        );
    }

    fn active(grant: &DelegationGrant, at: DateTime<Utc>) -> DelegationGrant {
        let mut next = grant.clone();
        next.status = GrantStatus::Active;
        next.revision += 1;
        next.updated_at = at;
        next.approval = Some(crate::GrantApproval {
            profile: "urn:example:consent:v1".into(),
            grant_id: grant.id,
            approver: grant.terms.grantor.clone(),
            evidence_ref: "urn:example:consent:1".into(),
            authority_evidence_ref: "urn:example:authority:1".into(),
            terms_digest: grant.terms_digest.clone(),
            approved_at: at,
        });
        next
    }

    struct MutableClock(std::sync::Mutex<DateTime<Utc>>);
    impl DelegationClock for MutableClock {
        fn now(&self) -> DateTime<Utc> {
            *self.0.lock().unwrap()
        }
    }

    #[tokio::test]
    async fn active_writes_require_exact_verified_revision_guard() {
        let repository = InMemoryDelegationGrantRepository::default();
        let grant = pending_grant();
        repository.insert(grant.clone()).await.unwrap();
        let next = active(&grant, grant.created_at + Duration::seconds(1));
        assert_eq!(
            repository
                .compare_and_swap(grant.organization_id, grant.id, 1, next.clone())
                .await,
            Err(RepositoryError::ActivationGuardRequired)
        );
        let clock = Arc::new(MutableClock(std::sync::Mutex::new(next.updated_at)));
        let mut wrong = next.clone();
        wrong.id = Uuid::new_v4();
        let guard = ActivationCommitGuard::for_verified(
            &wrong,
            VerifiedConsent {
                valid_until: grant.terms.valid_until,
            },
            clock.clone(),
        );
        assert_eq!(
            repository
                .compare_and_swap_guarded(
                    grant.organization_id,
                    grant.id,
                    1,
                    next.clone(),
                    Some(guard)
                )
                .await,
            Err(RepositoryError::ActivationGuardRequired)
        );
        let guard = ActivationCommitGuard::for_verified(
            &next,
            VerifiedConsent {
                valid_until: grant.terms.valid_until,
            },
            clock,
        );
        let mut substituted = next.clone();
        substituted.approval.as_mut().unwrap().evidence_ref =
            "urn:example:substituted-consent".into();
        assert_eq!(
            repository
                .compare_and_swap_guarded(
                    grant.organization_id,
                    grant.id,
                    1,
                    substituted,
                    Some(guard.clone())
                )
                .await,
            Err(RepositoryError::ActivationGuardRequired)
        );
        assert_eq!(
            repository
                .compare_and_swap_guarded(
                    grant.organization_id,
                    grant.id,
                    1,
                    next.clone(),
                    Some(guard)
                )
                .await
                .unwrap(),
            next
        );
        assert_eq!(
            repository
                .audit(grant.organization_id, grant.id)
                .await
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn expiry_during_memory_lock_wait_commits_neither_grant_nor_journal() {
        let repository = InMemoryDelegationGrantRepository::default();
        let grant = pending_grant();
        repository.insert(grant.clone()).await.unwrap();
        let next = active(&grant, grant.created_at + Duration::seconds(1));
        let clock = Arc::new(MutableClock(std::sync::Mutex::new(next.updated_at)));
        let deadline = next.updated_at + Duration::seconds(1);
        let guard = ActivationCommitGuard::for_verified(
            &next,
            VerifiedConsent {
                valid_until: deadline,
            },
            clock.clone(),
        );
        let held_lock = repository.state.write().await;
        let cloned = repository.clone();
        let organization_id = grant.organization_id;
        let grant_id = grant.id;
        let write = tokio::spawn(async move {
            cloned
                .compare_and_swap_guarded(organization_id, grant_id, 1, next, Some(guard))
                .await
        });
        tokio::task::yield_now().await;
        *clock.0.lock().unwrap() = deadline;
        drop(held_lock);
        assert_eq!(
            write.await.unwrap(),
            Err(RepositoryError::ActivationEvidenceExpired)
        );
        assert_eq!(
            repository.get(organization_id, grant_id).await.unwrap(),
            Some(grant)
        );
        assert_eq!(
            repository
                .audit(organization_id, grant_id)
                .await
                .unwrap()
                .len(),
            1
        );
    }
}
