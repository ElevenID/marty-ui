use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    domain::validate_authority, validate_transition, Authority, AuthorityMode, DelegationGrant,
    DelegationGrantRepository, GrantApproval, GrantStatus, GrantTerms, GrantValidationError,
    Principal, RepositoryError, MAX_GRANT_REVISION,
};

/// Identifiers of evidence from a configured, trusted approval surface. These
/// references must never be treated as caller-authorized network locations.
#[derive(Clone, Debug)]
pub struct ApprovalEvidence {
    pub profile: String,
    pub evidence_ref: String,
    pub authority_evidence_ref: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsentVerificationPurpose {
    Activation,
    Reinstatement,
    Resolution,
}

/// The full immutable grant and approval binding must be checked by the trusted
/// verifier, including the grantor's current authority over the subject. `now`
/// is read from the service clock, never from a request body.
pub struct ConsentVerificationRequest<'a> {
    pub grant: &'a DelegationGrant,
    pub approval: &'a GrantApproval,
    pub purpose: ConsentVerificationPurpose,
    pub now: DateTime<Utc>,
}

/// A deadline authenticated by the evidence verifier. It must be bounded by
/// the freshness of both consent evidence and the grantor's authority.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedConsent {
    pub valid_until: DateTime<Utc>,
}

/// The runtime clock is injected for deterministic boundary/race testing.
pub trait DelegationClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

pub struct SystemDelegationClock;
impl DelegationClock for SystemDelegationClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[async_trait]
pub trait ConsentEvidenceVerifier: Send + Sync {
    /// Authenticate a configured approval profile, evidence provenance, explicit
    /// consent to this exact grant/digest, and current grantor authority. Unknown
    /// profiles, unavailable evidence and stale/revoked authority must fail
    /// closed. A login, a URI's shape or a caller boolean is never consent.
    ///
    /// Called again on reinstatement and active resolution. Verification must
    /// be read-only: a failed/concurrent CAS must not consume an approval or
    /// otherwise commit a separate side effect.
    async fn verify_approval(
        &self,
        request: ConsentVerificationRequest<'_>,
    ) -> Result<VerifiedConsent, ConsentVerificationError>;
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("consent evidence verification failed")]
pub struct ConsentVerificationError;

/// Managed lifecycle application service. Callers must authenticate the tenant,
/// authorize the requested lifecycle action before invoking this port. It does not itself expose an HTTP authorization boundary.
#[derive(Clone)]
pub struct DelegationAuthorityService {
    repository: Arc<dyn DelegationGrantRepository>,
    consent_verifier: Arc<dyn ConsentEvidenceVerifier>,
    authority: Authority,
    clock: Arc<dyn DelegationClock>,
}

impl DelegationAuthorityService {
    /// `authority` comes from trusted issuer configuration for this service's
    /// tenant context, not from the agent's proposal. External grants require a
    /// separate qualified source resolver and cannot use this managed owner.
    pub fn new(
        repository: Arc<dyn DelegationGrantRepository>,
        consent_verifier: Arc<dyn ConsentEvidenceVerifier>,
        authority: Authority,
    ) -> Result<Self, ServiceError> {
        Self::with_clock(
            repository,
            consent_verifier,
            authority,
            Arc::new(SystemDelegationClock),
        )
    }

    pub fn with_clock(
        repository: Arc<dyn DelegationGrantRepository>,
        consent_verifier: Arc<dyn ConsentEvidenceVerifier>,
        authority: Authority,
        clock: Arc<dyn DelegationClock>,
    ) -> Result<Self, ServiceError> {
        validate_authority(&authority)?;
        if authority.mode != AuthorityMode::Managed {
            return Err(ServiceError::UnsupportedAuthority);
        }
        Ok(Self {
            repository,
            consent_verifier,
            authority,
            clock,
        })
    }

    /// The organization is taken from authenticated caller context. The service
    /// owns the grant ID, issuer, creation time, status, revision and digest.
    pub async fn propose(
        &self,
        organization_id: Uuid,
        terms: GrantTerms,
    ) -> Result<DelegationGrant, ServiceError> {
        let now = self.clock.now();
        let grant = DelegationGrant::pending(organization_id, self.authority.clone(), terms, now)?;
        grant.validate()?;
        self.repository.insert(grant.clone()).await?;
        Ok(grant)
    }

    pub async fn approve(
        &self,
        organization_id: Uuid,
        grant_id: Uuid,
        expected_revision: u64,
        authenticated_approver: &Principal,
        evidence: ApprovalEvidence,
    ) -> Result<DelegationGrant, ServiceError> {
        let now = self.clock.now();
        let previous = self
            .load_current(organization_id, grant_id, expected_revision, now)
            .await?;
        if previous.status != GrantStatus::Pending {
            return Err(ServiceError::InvalidTransition);
        }
        if authenticated_approver != &previous.terms.grantor {
            return Err(ServiceError::ApproverNotGrantor);
        }
        ensure_current_validity(&previous, now)?;
        let mut grant = next_snapshot(&previous, GrantStatus::Active, now)?;
        grant.approval = Some(GrantApproval {
            profile: evidence.profile,
            grant_id,
            approver: authenticated_approver.clone(),
            evidence_ref: evidence.evidence_ref,
            authority_evidence_ref: evidence.authority_evidence_ref,
            terms_digest: grant.terms_digest.clone(),
            approved_at: now,
        });
        validate_transition(&previous, &grant)?;
        let verified = self
            .verify_consent(&grant, ConsentVerificationPurpose::Activation, now)
            .await?;
        grant.updated_at = self.check_freshness(&grant, verified, now)?;
        self.persist(&previous, grant).await
    }

    pub async fn suspend(
        &self,
        organization_id: Uuid,
        grant_id: Uuid,
        expected_revision: u64,
    ) -> Result<DelegationGrant, ServiceError> {
        let now = self.clock.now();
        let previous = self
            .load_current(organization_id, grant_id, expected_revision, now)
            .await?;
        if previous.status != GrantStatus::Active {
            return Err(ServiceError::InvalidTransition);
        }
        let grant = next_snapshot(&previous, GrantStatus::Suspended, now)?;
        self.persist(&previous, grant).await
    }

    pub async fn reinstate(
        &self,
        organization_id: Uuid,
        grant_id: Uuid,
        expected_revision: u64,
    ) -> Result<DelegationGrant, ServiceError> {
        let now = self.clock.now();
        let previous = self
            .load_current(organization_id, grant_id, expected_revision, now)
            .await?;
        if previous.status != GrantStatus::Suspended {
            return Err(ServiceError::InvalidTransition);
        }
        ensure_current_validity(&previous, now)?;
        let mut grant = next_snapshot(&previous, GrantStatus::Active, now)?;
        validate_transition(&previous, &grant)?;
        let verified = self
            .verify_consent(&grant, ConsentVerificationPurpose::Reinstatement, now)
            .await?;
        grant.updated_at = self.check_freshness(&grant, verified, now)?;
        self.persist(&previous, grant).await
    }

    pub async fn revoke(
        &self,
        organization_id: Uuid,
        grant_id: Uuid,
        expected_revision: u64,
    ) -> Result<DelegationGrant, ServiceError> {
        let now = self.clock.now();
        let previous = self
            .load_current(organization_id, grant_id, expected_revision, now)
            .await?;
        let grant = next_snapshot(&previous, GrantStatus::Revoked, now)?;
        self.persist(&previous, grant).await
    }

    pub async fn expire(
        &self,
        organization_id: Uuid,
        grant_id: Uuid,
        expected_revision: u64,
    ) -> Result<DelegationGrant, ServiceError> {
        let now = self.clock.now();
        let previous = self
            .load_current(organization_id, grant_id, expected_revision, now)
            .await?;
        let grant = next_snapshot(&previous, GrantStatus::Expired, now)?;
        self.persist(&previous, grant).await
    }

    /// Resolve a currently active managed candidate and revalidate consent and
    /// grantor authority. This is NOT an operation authorization decision: the
    /// caller still needs actor proof/binding, exact scope, constraints, policy
    /// and final-use revision/replay enforcement. No stale snapshot fallback.
    pub async fn resolve(
        &self,
        organization_id: Uuid,
        grant_id: Uuid,
    ) -> Result<DelegationGrant, ServiceError> {
        let now = self.clock.now();
        let grant = self.load_scoped(organization_id, grant_id, now).await?;
        ensure_current_validity(&grant, now)?;
        if grant.status != GrantStatus::Active {
            return Err(ServiceError::Inactive);
        }
        let verified = self
            .verify_consent(&grant, ConsentVerificationPurpose::Resolution, now)
            .await?;
        let checked_at = self.check_freshness(&grant, verified, now)?;
        // Evidence resolution can involve an asynchronous trusted provider. Do
        // not return the old grant if a concurrent revoke/update won meantime.
        let latest = self
            .load_scoped(organization_id, grant_id, checked_at)
            .await?;
        self.check_freshness(&latest, verified, checked_at)?;
        if latest != grant {
            return Err(RepositoryError::RevisionConflict.into());
        }
        Ok(latest)
    }

    async fn load_scoped(
        &self,
        organization_id: Uuid,
        grant_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<DelegationGrant, ServiceError> {
        let grant = self
            .repository
            .get(organization_id, grant_id)
            .await?
            .ok_or(ServiceError::NotFound)?;
        if grant.id != grant_id || grant.organization_id != organization_id {
            return Err(ServiceError::NotFound);
        }
        grant.validate()?;
        if grant.authority.mode != AuthorityMode::Managed || grant.authority != self.authority {
            return Err(ServiceError::UnsupportedAuthority);
        }
        if grant.updated_at > now {
            return Err(ServiceError::FutureSnapshot);
        }
        Ok(grant)
    }

    async fn load_current(
        &self,
        organization_id: Uuid,
        grant_id: Uuid,
        expected_revision: u64,
        now: DateTime<Utc>,
    ) -> Result<DelegationGrant, ServiceError> {
        let grant = self.load_scoped(organization_id, grant_id, now).await?;
        if grant.revision != expected_revision {
            return Err(RepositoryError::RevisionConflict.into());
        }
        Ok(grant)
    }

    async fn verify_consent(
        &self,
        grant: &DelegationGrant,
        purpose: ConsentVerificationPurpose,
        now: DateTime<Utc>,
    ) -> Result<VerifiedConsent, ServiceError> {
        let approval = grant
            .approval
            .as_ref()
            .ok_or(ServiceError::ConsentNotVerified)?;
        self.consent_verifier
            .verify_approval(ConsentVerificationRequest {
                grant,
                approval,
                purpose,
                now,
            })
            .await
            .map_err(|_| ServiceError::ConsentNotVerified)
    }

    fn check_freshness(
        &self,
        grant: &DelegationGrant,
        verified: VerifiedConsent,
        started_at: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, ServiceError> {
        let now = self.clock.now();
        if now < started_at {
            return Err(ServiceError::ClockRegressed);
        }
        ensure_current_validity(grant, now)?;
        if verified.valid_until <= now {
            return Err(ServiceError::ConsentNotVerified);
        }
        Ok(now)
    }

    async fn persist(
        &self,
        previous: &DelegationGrant,
        grant: DelegationGrant,
    ) -> Result<DelegationGrant, ServiceError> {
        // Also checked by both repositories under the atomic write boundary.
        validate_transition(previous, &grant)?;
        Ok(self
            .repository
            .compare_and_swap(
                previous.organization_id,
                previous.id,
                previous.revision,
                grant,
            )
            .await?)
    }
}

fn next_snapshot(
    previous: &DelegationGrant,
    status: GrantStatus,
    now: DateTime<Utc>,
) -> Result<DelegationGrant, ServiceError> {
    if now <= previous.updated_at {
        return Err(ServiceError::TransitionTimeMustAdvance);
    }
    let revision = previous
        .revision
        .checked_add(1)
        .filter(|revision| *revision <= MAX_GRANT_REVISION)
        .ok_or(ServiceError::RevisionOverflow)?;
    let mut grant = previous.clone();
    grant.status = status;
    grant.revision = revision;
    grant.updated_at = now;
    Ok(grant)
}

fn ensure_current_validity(
    grant: &DelegationGrant,
    now: DateTime<Utc>,
) -> Result<(), ServiceError> {
    if grant.current_status(now) == GrantStatus::Expired {
        return Err(ServiceError::Expired);
    }
    if grant.terms.valid_from > now {
        return Err(ServiceError::NotYetValid);
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("delegation grant not found")]
    NotFound,
    #[error("delegation grant transition is not allowed")]
    InvalidTransition,
    #[error("consent evidence was not verified")]
    ConsentNotVerified,
    #[error("delegation grant has expired")]
    Expired,
    #[error("delegation grant is not yet valid")]
    NotYetValid,
    #[error("delegation grant is not active")]
    Inactive,
    #[error("grant does not belong to the configured managed authority")]
    UnsupportedAuthority,
    #[error("stored grant update is in the future")]
    FutureSnapshot,
    #[error("service clock moved backwards during verification")]
    ClockRegressed,
    #[error("lifecycle transition timestamp must advance")]
    TransitionTimeMustAdvance,
    #[error("only the grantor may approve this proposal")]
    ApproverNotGrantor,
    #[error("delegation revision overflow")]
    RevisionOverflow,
    #[error(transparent)]
    Validation(#[from] GrantValidationError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_support::pending_grant, InMemoryDelegationGrantRepository, PrincipalType};
    use chrono::Duration;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    };

    const TEST_PROFILE: &str = "urn:example:trusted-approval:v1";

    struct TestClock(Mutex<DateTime<Utc>>);
    impl TestClock {
        fn set(&self, time: DateTime<Utc>) {
            *self.0.lock().unwrap() = time;
        }
    }
    impl DelegationClock for TestClock {
        fn now(&self) -> DateTime<Utc> {
            *self.0.lock().unwrap()
        }
    }

    struct TestEvidence {
        reject: AtomicBool,
        checks: AtomicUsize,
        clock: Arc<TestClock>,
        advance_during_verification: Mutex<Duration>,
        freshness: Mutex<Option<DateTime<Utc>>>,
        revoke_during_resolution: AtomicBool,
        repository: Arc<InMemoryDelegationGrantRepository>,
    }
    #[async_trait]
    impl ConsentEvidenceVerifier for TestEvidence {
        async fn verify_approval(
            &self,
            request: ConsentVerificationRequest<'_>,
        ) -> Result<VerifiedConsent, ConsentVerificationError> {
            self.checks.fetch_add(1, Ordering::SeqCst);
            if self.reject.load(Ordering::SeqCst)
                || request.approval.profile != TEST_PROFILE
                || request.approval.evidence_ref != "urn:example:consent:1"
                || request.approval.authority_evidence_ref != "urn:example:authority:1"
                || request.approval.approver != request.grant.terms.grantor
                || request.approval.terms_digest != request.grant.terms_digest
                || request.approval.grant_id != request.grant.id
                || request.now < request.approval.approved_at
            {
                return Err(ConsentVerificationError);
            }
            let elapsed = *self.advance_during_verification.lock().unwrap();
            self.clock.set(self.clock.now() + elapsed);
            if request.purpose == ConsentVerificationPurpose::Resolution
                && self.revoke_during_resolution.load(Ordering::SeqCst)
            {
                let revoked =
                    next_snapshot(request.grant, GrantStatus::Revoked, self.clock.now()).unwrap();
                self.repository
                    .compare_and_swap(
                        request.grant.organization_id,
                        request.grant.id,
                        request.grant.revision,
                        revoked,
                    )
                    .await
                    .unwrap();
            }
            Ok(VerifiedConsent {
                valid_until: self
                    .freshness
                    .lock()
                    .unwrap()
                    .unwrap_or(request.grant.terms.valid_until),
            })
        }
    }

    fn evidence() -> ApprovalEvidence {
        ApprovalEvidence {
            profile: TEST_PROFILE.into(),
            evidence_ref: "urn:example:consent:1".into(),
            authority_evidence_ref: "urn:example:authority:1".into(),
        }
    }

    struct Harness {
        service: DelegationAuthorityService,
        repository: Arc<InMemoryDelegationGrantRepository>,
        verifier: Arc<TestEvidence>,
        clock: Arc<TestClock>,
        grant: DelegationGrant,
    }
    impl Harness {
        async fn new() -> Self {
            let repository = Arc::new(InMemoryDelegationGrantRepository::default());
            let template = pending_grant();
            let clock = Arc::new(TestClock(Mutex::new(template.created_at)));
            let verifier = Arc::new(TestEvidence {
                reject: AtomicBool::new(false),
                checks: AtomicUsize::new(0),
                clock: clock.clone(),
                advance_during_verification: Mutex::new(Duration::zero()),
                freshness: Mutex::new(None),
                revoke_during_resolution: AtomicBool::new(false),
                repository: repository.clone(),
            });
            let service = DelegationAuthorityService::with_clock(
                repository.clone(),
                verifier.clone(),
                template.authority.clone(),
                clock.clone(),
            )
            .unwrap();
            let grant = service
                .propose(template.organization_id, template.terms.clone())
                .await
                .unwrap();
            assert_ne!(grant.id, template.id);
            Self {
                service,
                repository,
                verifier,
                clock,
                grant,
            }
        }
        fn at(&self, seconds: i64) {
            self.clock
                .set(self.grant.created_at + Duration::seconds(seconds));
        }
        async fn approve(
            &self,
            approver: &Principal,
            evidence: ApprovalEvidence,
        ) -> Result<DelegationGrant, ServiceError> {
            self.service
                .approve(
                    self.grant.organization_id,
                    self.grant.id,
                    1,
                    approver,
                    evidence,
                )
                .await
        }
        async fn activate(&self) -> DelegationGrant {
            self.at(1);
            self.approve(&self.grant.terms.grantor, evidence())
                .await
                .unwrap()
        }
        async fn stored(&self) -> DelegationGrant {
            self.repository
                .get(self.grant.organization_id, self.grant.id)
                .await
                .unwrap()
                .unwrap()
        }
        async fn journal_len(&self) -> usize {
            self.repository
                .audit(self.grant.organization_id, self.grant.id)
                .await
                .unwrap()
                .len()
        }
        async fn resolve(&self) -> Result<DelegationGrant, ServiceError> {
            self.service
                .resolve(self.grant.organization_id, self.grant.id)
                .await
        }
    }

    #[tokio::test]
    async fn lifecycle_approves_suspends_reinstates_and_revokes_with_revisions() {
        let h = Harness::new().await;
        let org = h.grant.organization_id;
        let id = h.grant.id;
        let active = h.activate().await;
        assert_eq!(active.status, GrantStatus::Active);
        assert_eq!(active.revision, 2);
        assert_eq!(
            active.approval.as_ref().unwrap().approver,
            h.grant.terms.grantor
        );
        h.at(2);
        let suspended = h.service.suspend(org, id, 2).await.unwrap();
        assert_eq!(suspended.status, GrantStatus::Suspended);
        h.at(3);
        let active = h.service.reinstate(org, id, 3).await.unwrap();
        assert_eq!(active.status, GrantStatus::Active);
        assert_eq!(active.approval, suspended.approval);
        assert_eq!(h.resolve().await.unwrap(), active);
        h.at(4);
        let revoked = h.service.revoke(org, id, 4).await.unwrap();
        assert_eq!(revoked.status, GrantStatus::Revoked);
        assert_eq!(revoked.revision, 5);
        assert_eq!(h.verifier.checks.load(Ordering::SeqCst), 3);
        assert_eq!(h.journal_len().await, 5);
    }

    #[tokio::test]
    async fn approval_requires_current_verified_consent_and_known_profile() {
        let h = Harness::new().await;
        h.at(1);
        let mut unknown = evidence();
        unknown.profile = "urn:example:unknown:v1".into();
        assert!(matches!(
            h.approve(&h.grant.terms.grantor, unknown).await,
            Err(ServiceError::ConsentNotVerified)
        ));
        h.verifier.reject.store(true, Ordering::SeqCst);
        assert!(matches!(
            h.approve(&h.grant.terms.grantor, evidence()).await,
            Err(ServiceError::ConsentNotVerified)
        ));
        assert_eq!(h.stored().await, h.grant);
        assert_eq!(h.journal_len().await, 1);
    }

    #[tokio::test]
    async fn same_id_with_wrong_principal_type_cannot_approve() {
        let h = Harness::new().await;
        h.at(1);
        let mut impostor = h.grant.terms.grantor.clone();
        impostor.principal_type = PrincipalType::External;
        assert!(matches!(
            h.approve(&impostor, evidence()).await,
            Err(ServiceError::ApproverNotGrantor)
        ));
        assert_eq!(h.verifier.checks.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn stale_revision_cannot_overwrite_newer_lifecycle_state() {
        let h = Harness::new().await;
        h.activate().await;
        h.at(2);
        assert!(matches!(
            h.service
                .suspend(h.grant.organization_id, h.grant.id, 1)
                .await,
            Err(ServiceError::Repository(RepositoryError::RevisionConflict))
        ));
    }

    #[tokio::test]
    async fn reinstatement_and_resolution_fail_closed_after_authority_is_withdrawn() {
        let h = Harness::new().await;
        h.activate().await;
        h.at(2);
        h.verifier.reject.store(true, Ordering::SeqCst);
        assert!(matches!(
            h.resolve().await,
            Err(ServiceError::ConsentNotVerified)
        ));
        let suspended = h
            .service
            .suspend(h.grant.organization_id, h.grant.id, 2)
            .await
            .unwrap();
        h.at(3);
        assert!(matches!(
            h.service
                .reinstate(h.grant.organization_id, h.grant.id, 3)
                .await,
            Err(ServiceError::ConsentNotVerified)
        ));
        assert_eq!(h.stored().await, suspended);
    }

    #[tokio::test]
    async fn inactive_states_and_other_tenants_do_not_resolve() {
        let h = Harness::new().await;
        assert!(matches!(h.resolve().await, Err(ServiceError::Inactive)));
        assert!(matches!(
            h.service.resolve(Uuid::new_v4(), h.grant.id).await,
            Err(ServiceError::NotFound)
        ));
        h.activate().await;
        h.at(2);
        h.service
            .suspend(h.grant.organization_id, h.grant.id, 2)
            .await
            .unwrap();
        assert!(matches!(h.resolve().await, Err(ServiceError::Inactive)));
        h.at(3);
        h.service
            .revoke(h.grant.organization_id, h.grant.id, 3)
            .await
            .unwrap();
        assert!(matches!(h.resolve().await, Err(ServiceError::Inactive)));
    }

    #[tokio::test]
    async fn expiry_is_terminal_and_cannot_be_applied_early() {
        let h = Harness::new().await;
        h.at(1);
        assert!(matches!(
            h.service
                .expire(h.grant.organization_id, h.grant.id, 1)
                .await,
            Err(ServiceError::Validation(
                GrantValidationError::PrematureExpiration
            ))
        ));
        h.clock.set(h.grant.terms.valid_until);
        assert!(matches!(
            h.approve(&h.grant.terms.grantor, evidence()).await,
            Err(ServiceError::Expired)
        ));
        let expired = h
            .service
            .expire(h.grant.organization_id, h.grant.id, 1)
            .await
            .unwrap();
        assert_eq!(expired.status, GrantStatus::Expired);
        h.clock.set(h.clock.now() + Duration::seconds(1));
        assert!(matches!(
            h.service
                .revoke(h.grant.organization_id, h.grant.id, 2)
                .await,
            Err(ServiceError::Validation(
                GrantValidationError::InvalidStatusTransition
            ))
        ));
        assert_eq!(h.journal_len().await, 2);
    }

    #[tokio::test]
    async fn proposals_are_server_owned_and_expired_terms_are_rejected() {
        let h = Harness::new().await;
        assert_eq!(h.grant.status, GrantStatus::Pending);
        assert_eq!(h.grant.revision, 1);
        assert_eq!(h.grant.created_at, h.grant.updated_at);
        assert!(h.grant.approval.is_none());
        h.clock.set(h.grant.terms.valid_until);
        assert!(matches!(
            h.service
                .propose(h.grant.organization_id, h.grant.terms.clone())
                .await,
            Err(ServiceError::Validation(
                GrantValidationError::AlreadyExpired
            ))
        ));
    }

    #[tokio::test]
    async fn approval_before_valid_from_and_nonadvancing_time_are_rejected() {
        let h = Harness::new().await;
        assert!(matches!(
            h.approve(&h.grant.terms.grantor, evidence()).await,
            Err(ServiceError::TransitionTimeMustAdvance)
        ));
        let mut terms = h.grant.terms.clone();
        terms.valid_from = h.grant.created_at + Duration::minutes(1);
        let future = h
            .service
            .propose(h.grant.organization_id, terms)
            .await
            .unwrap();
        h.at(1);
        assert!(matches!(
            h.service
                .approve(
                    future.organization_id,
                    future.id,
                    1,
                    &future.terms.grantor,
                    evidence()
                )
                .await,
            Err(ServiceError::NotYetValid)
        ));
    }

    #[tokio::test]
    async fn external_authority_cannot_construct_managed_service() {
        let h = Harness::new().await;
        let mut authority = h.grant.authority;
        authority.mode = AuthorityMode::External;
        authority.source_profile = Some("urn:example:external:v1".into());
        authority.source_evidence_ref = Some("urn:example:external:1".into());
        authority.source_evidence_digest = Some(format!("sha256:{}", "a".repeat(64)));
        authority.source_expires_at = Some(h.grant.terms.valid_until);
        assert!(matches!(
            DelegationAuthorityService::new(h.repository, h.verifier, authority),
            Err(ServiceError::UnsupportedAuthority)
        ));
    }

    #[tokio::test]
    async fn approval_does_not_commit_if_grant_expires_during_verification() {
        let h = Harness::new().await;
        h.at(1);
        *h.verifier.advance_during_verification.lock().unwrap() = Duration::hours(2);
        assert!(matches!(
            h.approve(&h.grant.terms.grantor, evidence()).await,
            Err(ServiceError::Expired)
        ));
        assert_eq!(h.stored().await, h.grant);
        assert_eq!(h.journal_len().await, 1);
    }

    #[tokio::test]
    async fn resolution_checks_elapsed_time_and_evidence_deadline() {
        let h = Harness::new().await;
        h.activate().await;
        h.at(2);
        *h.verifier.freshness.lock().unwrap() = Some(h.clock.now() + Duration::seconds(1));
        *h.verifier.advance_during_verification.lock().unwrap() = Duration::seconds(2);
        assert!(matches!(
            h.resolve().await,
            Err(ServiceError::ConsentNotVerified)
        ));
        *h.verifier.freshness.lock().unwrap() = None;
        *h.verifier.advance_during_verification.lock().unwrap() = Duration::hours(2);
        assert!(matches!(h.resolve().await, Err(ServiceError::Expired)));
    }

    #[tokio::test]
    async fn resolution_detects_revoke_during_evidence_lookup() {
        let h = Harness::new().await;
        h.activate().await;
        h.at(2);
        h.verifier
            .revoke_during_resolution
            .store(true, Ordering::SeqCst);
        assert!(matches!(
            h.resolve().await,
            Err(ServiceError::Repository(RepositoryError::RevisionConflict))
        ));
        assert_eq!(h.stored().await.status, GrantStatus::Revoked);
    }

    #[tokio::test]
    async fn clock_regression_during_verification_fails_closed() {
        let h = Harness::new().await;
        h.at(2);
        *h.verifier.advance_during_verification.lock().unwrap() = Duration::seconds(-1);
        assert!(matches!(
            h.approve(&h.grant.terms.grantor, evidence()).await,
            Err(ServiceError::ClockRegressed)
        ));
        assert_eq!(h.stored().await, h.grant);
    }
}
