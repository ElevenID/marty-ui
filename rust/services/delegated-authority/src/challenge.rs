//! Trusted admission of one delegated operation into the existing Flow owner.
//!
//! Admission creates an identity challenge, not an operation authorization. It
//! verifies current grant/consent and, for SESSION grants, independently sourced
//! session establishment. Flow owns nonce generation, request signing and durable
//! storage. Proof, constraints, Cedar and final-use replay checks still follow.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::{
    domain::valid_digest, BindingMethod, DelegationAuthorityService, DelegationClock,
    DelegationFlowContextV1, DelegationGrant, GrantStatus, Principal, SystemDelegationClock,
};

const ADMISSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// An operation requested by an already authenticated delegate. Tenant and
/// typed caller identity are separate trusted arguments to `admit`; no proof,
/// session establishment, challenge ID or verifier identity is supplied here.
#[derive(Clone)]
pub struct DelegationChallengeRequest {
    pub grant_id: Uuid,
    pub expected_revision: u64,
    pub action: String,
    /// Relying-domain audience, independent of Flow's OID4VP verifier client ID.
    pub audience: String,
    pub resource: String,
    pub operation_profile: String,
    pub operation_digest: String,
}

/// Current authenticated session-establishment evidence from a configured
/// provider. The provider must resolve the grant's exact references through its
/// own trusted source, verify establishment and current status, and return a
/// fresh observation. It must not fetch an arbitrary caller-selected URI.
/// An establishment evidence reference must remain bound to its established key;
/// the source must not retarget old evidence to a rotated or replacement key.
/// A bound-key change requires a new grant identifier and fresh approval in v1.
///
/// These are internal provider results, not deserializable network DTOs. A
/// session name or a JWK supplied by the delegate is not establishment evidence.
#[derive(Clone)]
pub struct VerifiedDelegationSessionBinding {
    pub organization_id: Uuid,
    pub grant_id: Uuid,
    pub terms_digest: String,
    pub delegate: Principal,
    pub session_ref: String,
    pub establishment_evidence_ref: String,
    pub key_thumbprint: String,
    pub observed_at: DateTime<Utc>,
    /// Bounds both the freshness of the authenticated status observation and
    /// the session/key lifetime. A nominal session expiry alone is insufficient;
    /// later rotation or revocation still requires revalidation at final use.
    pub valid_until: DateTime<Utc>,
}

#[async_trait]
pub trait DelegationSessionBindingSource: Send + Sync {
    /// Read-only verification; failure/cancellation must not consume or create
    /// session evidence. Production composition must independently authenticate
    /// this source and its relationship to the grant's establishment profile.
    async fn resolve_current(
        &self,
        grant: &DelegationGrant,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationSessionBinding, DelegationSessionBindingError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("delegation session binding is unavailable")]
pub struct DelegationSessionBindingError;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DelegationChallengeError {
    #[error("invalid delegation challenge configuration")]
    InvalidConfiguration,
    #[error("invalid delegation challenge request")]
    InvalidRequest,
    #[error("delegation grant is unavailable")]
    GrantUnavailable,
    #[error("delegation grant revision does not match")]
    RevisionConflict,
    #[error("authenticated delegate does not match the grant")]
    WrongDelegate,
    #[error("delegation scope does not admit this operation")]
    ScopeDenied,
    #[error("delegation session binding was not verified")]
    SessionNotVerified,
    #[error("delegation state changed during challenge admission")]
    StateChanged,
    #[error("delegation challenge admission is no longer live")]
    Expired,
    #[error("delegation challenge admission is unavailable")]
    Unavailable,
}

/// Configured application boundary. Its caller must authenticate the tenant and
/// complete typed actor and authorize challenge creation before invoking it.
/// This type does not authenticate a network request or expose a public route.
#[derive(Clone)]
pub struct DelegationChallengeIssuer {
    lifecycle: Arc<DelegationAuthorityService>,
    sessions: Option<Arc<dyn DelegationSessionBindingSource>>,
    clock: Arc<dyn DelegationClock>,
    maximum_lifetime: Duration,
    timeout: std::time::Duration,
}

impl DelegationChallengeIssuer {
    pub fn new(
        lifecycle: Arc<DelegationAuthorityService>,
        sessions: Option<Arc<dyn DelegationSessionBindingSource>>,
        maximum_lifetime_seconds: i64,
    ) -> Result<Self, DelegationChallengeError> {
        Self::with_clock(
            lifecycle,
            sessions,
            maximum_lifetime_seconds,
            Arc::new(SystemDelegationClock),
        )
    }

    pub fn with_clock(
        lifecycle: Arc<DelegationAuthorityService>,
        sessions: Option<Arc<dyn DelegationSessionBindingSource>>,
        maximum_lifetime_seconds: i64,
        clock: Arc<dyn DelegationClock>,
    ) -> Result<Self, DelegationChallengeError> {
        if !(30..=600).contains(&maximum_lifetime_seconds) {
            return Err(DelegationChallengeError::InvalidConfiguration);
        }
        Ok(Self {
            lifecycle,
            sessions,
            clock,
            maximum_lifetime: Duration::seconds(maximum_lifetime_seconds),
            timeout: ADMISSION_TIMEOUT,
        })
    }

    pub async fn admit(
        &self,
        organization_id: Uuid,
        authenticated_actor: &Principal,
        request: DelegationChallengeRequest,
    ) -> Result<DelegationChallengeAdmission, DelegationChallengeError> {
        let deadline = tokio::time::Instant::now() + self.timeout;
        let admission = tokio::time::timeout_at(
            deadline,
            self.admit_inner(organization_id, authenticated_actor, request),
        )
        .await
        .map_err(|_| DelegationChallengeError::Unavailable)??;
        if tokio::time::Instant::now() >= deadline {
            return Err(DelegationChallengeError::Unavailable);
        }
        Ok(admission)
    }

    async fn admit_inner(
        &self,
        organization_id: Uuid,
        authenticated_actor: &Principal,
        request: DelegationChallengeRequest,
    ) -> Result<DelegationChallengeAdmission, DelegationChallengeError> {
        let mut binding = DelegationFlowContextV1 {
            challenge_id: Uuid::new_v4(),
            organization_id,
            grant_id: request.grant_id,
            grant_revision: request.expected_revision,
            actor: authenticated_actor.clone(),
            action: request.action,
            audience: request.audience,
            resource: request.resource,
            operation_profile: request.operation_profile,
            operation_digest: request.operation_digest,
            session_ref: None,
            establishment_evidence_ref: None,
            session_key_thumbprint: None,
        };
        binding
            .validate()
            .map_err(|_| DelegationChallengeError::InvalidRequest)?;
        let admitted_at = self.clock.now();
        let maximum_deadline = admitted_at
            .checked_add_signed(self.maximum_lifetime)
            .ok_or(DelegationChallengeError::Expired)?;
        let resolved = self
            .lifecycle
            .resolve_verified(organization_id, binding.grant_id)
            .await
            .map_err(|_| DelegationChallengeError::GrantUnavailable)?;
        let after_grant = self.now_after(admitted_at)?;
        let grant = resolved.grant;
        validate_operation(&grant, &binding)?;
        if grant.updated_at > after_grant || grant.terms.valid_from > after_grant {
            return Err(DelegationChallengeError::Expired);
        }
        let mut valid_until = maximum_deadline
            .min(grant.terms.valid_until)
            .min(resolved.consent_valid_until);
        require_live(after_grant, valid_until)?;

        let (session, after_session) = self.resolve_session(&grant, after_grant).await?;
        if let Some(session) = session {
            valid_until = valid_until.min(session.valid_until);
            binding.session_ref = Some(session.session_ref);
            binding.establishment_evidence_ref = Some(session.establishment_evidence_ref);
            binding.session_key_thumbprint = Some(session.key_thumbprint);
        }
        require_live(after_session, valid_until)?;
        binding
            .validate()
            .map_err(|_| DelegationChallengeError::SessionNotVerified)?;

        // Session establishment may have awaited another owner. Observe current
        // grant/consent again before handing an admission to Flow.
        let latest = self
            .lifecycle
            .resolve_verified(organization_id, grant.id)
            .await
            .map_err(|_| DelegationChallengeError::GrantUnavailable)?;
        let checked_at = self.now_after(after_session)?;
        if latest.grant != grant {
            return Err(DelegationChallengeError::StateChanged);
        }
        valid_until = valid_until.min(latest.consent_valid_until);
        require_live(checked_at, valid_until)?;
        Ok(DelegationChallengeAdmission {
            binding,
            grant,
            admitted_at,
            checked_at,
            valid_until,
            issuer: self.clone(),
        })
    }

    async fn resolve_session(
        &self,
        grant: &DelegationGrant,
        requested_at: DateTime<Utc>,
    ) -> Result<(Option<VerifiedDelegationSessionBinding>, DateTime<Utc>), DelegationChallengeError>
    {
        if grant.terms.binding.method == BindingMethod::Key {
            return Ok((None, self.now_after(requested_at)?));
        }
        let session = self
            .sessions
            .as_ref()
            .ok_or(DelegationChallengeError::SessionNotVerified)?
            .resolve_current(grant, requested_at)
            .await
            .map_err(|_| DelegationChallengeError::SessionNotVerified)?;
        let checked_at = self.now_after(requested_at)?;
        if session.organization_id != grant.organization_id
            || session.grant_id != grant.id
            || session.terms_digest != grant.terms_digest
            || session.delegate != grant.terms.delegate
            || Some(session.session_ref.as_str()) != grant.terms.binding.session_ref.as_deref()
            || Some(session.establishment_evidence_ref.as_str())
                != grant.terms.binding.establishment_evidence_ref.as_deref()
            || !valid_digest(Some(&session.key_thumbprint))
            || session.observed_at < requested_at
            || session.observed_at > checked_at
            || session.valid_until <= checked_at
        {
            return Err(DelegationChallengeError::SessionNotVerified);
        }
        Ok((Some(session), checked_at))
    }

    fn now_after(
        &self,
        previous: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, DelegationChallengeError> {
        let now = self.clock.now();
        if now < previous {
            return Err(DelegationChallengeError::Expired);
        }
        Ok(now)
    }
}

/// Move-only, nonserializable preparation input for the trusted Flow starter.
/// There is no public constructor and no mutable access to its exact operation.
/// It cannot authorize an operation or replace final-use replay enforcement.
pub struct DelegationChallengeAdmission {
    binding: DelegationFlowContextV1,
    grant: DelegationGrant,
    admitted_at: DateTime<Utc>,
    checked_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    issuer: DelegationChallengeIssuer,
}

impl std::fmt::Debug for DelegationChallengeAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelegationChallengeAdmission")
            .field("challenge_id", &self.binding.challenge_id)
            .field("admitted_at", &self.admitted_at)
            .field("valid_until", &self.valid_until)
            .finish_non_exhaustive()
    }
}

impl DelegationChallengeAdmission {
    pub fn binding(&self) -> &DelegationFlowContextV1 {
        &self.binding
    }

    pub fn admitted_at(&self) -> DateTime<Utc> {
        self.admitted_at
    }

    pub fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }

    /// Observe the issuer's trusted clock, not a caller-selected timestamp.
    pub fn check_live(&self) -> Result<DateTime<Utc>, DelegationChallengeError> {
        let now = self.issuer.clock.now();
        self.check_live_at(now)?;
        Ok(now)
    }

    /// Used with a fresh database clock under Flow's write transaction. The
    /// database clock must not precede the last authenticated observation.
    pub fn check_live_at(&self, now: DateTime<Utc>) -> Result<(), DelegationChallengeError> {
        if now < self.checked_at {
            return Err(DelegationChallengeError::Expired);
        }
        require_live(now, self.valid_until)
    }

    /// Recheck current grant/consent and session establishment after Flow's
    /// asynchronous provider work and before opening its write transaction.
    /// Neither this read-only refresh nor its timeout can consume a nonce.
    /// The original binding and deadline can never be replaced or extended.
    pub async fn revalidate(&mut self) -> Result<(), DelegationChallengeError> {
        let deadline = tokio::time::Instant::now() + self.issuer.timeout;
        let (checked_at, valid_until) = tokio::time::timeout_at(deadline, self.revalidate_inner())
            .await
            .map_err(|_| DelegationChallengeError::Unavailable)??;
        if tokio::time::Instant::now() >= deadline {
            return Err(DelegationChallengeError::Unavailable);
        }
        self.checked_at = checked_at;
        self.valid_until = self.valid_until.min(valid_until);
        self.check_live()?;
        Ok(())
    }

    async fn revalidate_inner(
        &self,
    ) -> Result<(DateTime<Utc>, DateTime<Utc>), DelegationChallengeError> {
        let started_at = self.check_live()?;
        let resolved = self
            .issuer
            .lifecycle
            .resolve_verified(self.binding.organization_id, self.binding.grant_id)
            .await
            .map_err(|_| DelegationChallengeError::GrantUnavailable)?;
        let after_grant = self.issuer.now_after(started_at)?;
        if resolved.grant != self.grant {
            return Err(DelegationChallengeError::StateChanged);
        }
        let mut valid_until = self.valid_until.min(resolved.consent_valid_until);
        require_live(after_grant, valid_until)?;
        let (session, after_session) = self
            .issuer
            .resolve_session(&self.grant, after_grant)
            .await?;
        if let Some(session) = session {
            if Some(session.key_thumbprint.as_str())
                != self.binding.session_key_thumbprint.as_deref()
            {
                return Err(DelegationChallengeError::StateChanged);
            }
            valid_until = valid_until.min(session.valid_until);
        }
        require_live(after_session, valid_until)?;
        let latest = self
            .issuer
            .lifecycle
            .resolve_verified(self.binding.organization_id, self.binding.grant_id)
            .await
            .map_err(|_| DelegationChallengeError::GrantUnavailable)?;
        let checked_at = self.issuer.now_after(after_session)?;
        if latest.grant != self.grant {
            return Err(DelegationChallengeError::StateChanged);
        }
        valid_until = valid_until.min(latest.consent_valid_until);
        require_live(checked_at, valid_until)?;
        Ok((checked_at, valid_until))
    }
}

fn require_live(
    now: DateTime<Utc>,
    valid_until: DateTime<Utc>,
) -> Result<(), DelegationChallengeError> {
    if now >= valid_until {
        return Err(DelegationChallengeError::Expired);
    }
    Ok(())
}

fn validate_operation(
    grant: &DelegationGrant,
    binding: &DelegationFlowContextV1,
) -> Result<(), DelegationChallengeError> {
    if grant.id != binding.grant_id || grant.organization_id != binding.organization_id {
        return Err(DelegationChallengeError::GrantUnavailable);
    }
    if grant.revision != binding.grant_revision {
        return Err(DelegationChallengeError::RevisionConflict);
    }
    if grant.terms.delegate != binding.actor {
        return Err(DelegationChallengeError::WrongDelegate);
    }
    if grant.status != GrantStatus::Active
        || !grant.terms.actions.contains(&binding.action)
        || !grant.terms.audiences.contains(&binding.audience)
        || !grant.terms.resources.contains(&binding.resource)
        || (grant.terms.constraints.mode == crate::ConstraintMode::ExactOperation
            && (grant.terms.constraints.request_profile.as_deref()
                != Some(binding.operation_profile.as_str())
                || grant.terms.constraints.request_digest.as_deref()
                    != Some(binding.operation_digest.as_str())))
    {
        return Err(DelegationChallengeError::ScopeDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_support::pending_grant, ApprovalEvidence, Binding, ConsentEvidenceVerifier,
        ConsentVerificationError, ConsentVerificationRequest, ConstraintMode, Constraints,
        InMemoryDelegationGrantRepository, PrincipalType, VerifiedConsent,
    };
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    };

    struct Clock(Mutex<DateTime<Utc>>);
    impl Clock {
        fn set(&self, now: DateTime<Utc>) {
            *self.0.lock().unwrap() = now;
        }
    }
    impl DelegationClock for Clock {
        fn now(&self) -> DateTime<Utc> {
            *self.0.lock().unwrap()
        }
    }

    #[derive(Default)]
    struct Consent {
        withdrawn: AtomicBool,
        calls: AtomicUsize,
        valid_until: Mutex<Option<DateTime<Utc>>>,
    }
    #[async_trait]
    impl ConsentEvidenceVerifier for Consent {
        async fn verify_approval(
            &self,
            request: ConsentVerificationRequest<'_>,
        ) -> Result<VerifiedConsent, ConsentVerificationError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.withdrawn.load(Ordering::SeqCst) {
                return Err(ConsentVerificationError);
            }
            Ok(VerifiedConsent {
                valid_until: self
                    .valid_until
                    .lock()
                    .unwrap()
                    .unwrap_or(request.grant.terms.valid_until),
            })
        }
    }

    #[derive(Clone, Copy, Default)]
    enum SessionEffect {
        #[default]
        None,
        Pending,
        RegressClock,
        Expire,
        Suspend,
        Reinstate,
        Withdraw,
    }

    type SessionMutation = fn(&mut VerifiedDelegationSessionBinding);
    struct Sessions {
        calls: AtomicUsize,
        reject: AtomicBool,
        key: Mutex<String>,
        valid_until: Mutex<Option<DateTime<Utc>>>,
        mutate: Mutex<Option<SessionMutation>>,
        effect: Mutex<SessionEffect>,
        lifecycle: Arc<DelegationAuthorityService>,
        consent: Arc<Consent>,
        clock: Arc<Clock>,
    }
    #[async_trait]
    impl DelegationSessionBindingSource for Sessions {
        async fn resolve_current(
            &self,
            grant: &DelegationGrant,
            now: DateTime<Utc>,
        ) -> Result<VerifiedDelegationSessionBinding, DelegationSessionBindingError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.reject.load(Ordering::SeqCst) {
                return Err(DelegationSessionBindingError);
            }
            let effect = *self.effect.lock().unwrap();
            match effect {
                SessionEffect::None => {}
                SessionEffect::Pending => return std::future::pending().await,
                SessionEffect::RegressClock => self.clock.set(now - Duration::seconds(1)),
                SessionEffect::Expire => self.clock.set(grant.terms.valid_until),
                SessionEffect::Suspend => {
                    self.clock.set(now + Duration::seconds(1));
                    self.lifecycle
                        .suspend(grant.organization_id, grant.id, grant.revision)
                        .await
                        .unwrap();
                }
                SessionEffect::Reinstate => {
                    self.clock.set(now + Duration::seconds(1));
                    let suspended = self
                        .lifecycle
                        .suspend(grant.organization_id, grant.id, grant.revision)
                        .await
                        .unwrap();
                    self.clock.set(now + Duration::seconds(2));
                    self.lifecycle
                        .reinstate(grant.organization_id, grant.id, suspended.revision)
                        .await
                        .unwrap();
                }
                SessionEffect::Withdraw => self.consent.withdrawn.store(true, Ordering::SeqCst),
            }
            let mut evidence = VerifiedDelegationSessionBinding {
                organization_id: grant.organization_id,
                grant_id: grant.id,
                terms_digest: grant.terms_digest.clone(),
                delegate: grant.terms.delegate.clone(),
                session_ref: grant.terms.binding.session_ref.clone().unwrap(),
                establishment_evidence_ref: grant
                    .terms
                    .binding
                    .establishment_evidence_ref
                    .clone()
                    .unwrap(),
                key_thumbprint: self.key.lock().unwrap().clone(),
                observed_at: now,
                valid_until: self
                    .valid_until
                    .lock()
                    .unwrap()
                    .unwrap_or(grant.terms.valid_until),
            };
            if let Some(mutate) = *self.mutate.lock().unwrap() {
                mutate(&mut evidence);
            }
            Ok(evidence)
        }
    }

    struct Harness {
        issuer: DelegationChallengeIssuer,
        lifecycle: Arc<DelegationAuthorityService>,
        grant: DelegationGrant,
        consent: Arc<Consent>,
        sessions: Arc<Sessions>,
        clock: Arc<Clock>,
    }
    impl Harness {
        async fn new(method: BindingMethod) -> Self {
            let mut template = pending_grant();
            if method == BindingMethod::Key {
                template.terms.binding = Binding {
                    method,
                    key_thumbprint: Some(format!("sha256:{}", "a".repeat(64))),
                    session_ref: None,
                    establishment_evidence_ref: None,
                };
            }
            Self::with_template(template).await
        }

        async fn with_template(template: DelegationGrant) -> Self {
            let clock = Arc::new(Clock(Mutex::new(template.created_at)));
            let consent = Arc::new(Consent::default());
            let lifecycle = Arc::new(
                DelegationAuthorityService::with_clock(
                    Arc::new(InMemoryDelegationGrantRepository::default()),
                    consent.clone(),
                    template.authority,
                    clock.clone(),
                )
                .unwrap(),
            );
            let pending = lifecycle
                .propose(template.organization_id, template.terms)
                .await
                .unwrap();
            clock.set(template.created_at + Duration::seconds(1));
            let grant = lifecycle
                .approve(
                    pending.organization_id,
                    pending.id,
                    pending.revision,
                    &pending.terms.grantor,
                    ApprovalEvidence {
                        profile: "urn:example:consent:v1".into(),
                        evidence_ref: "urn:example:consent:1".into(),
                        authority_evidence_ref: "urn:example:authority:1".into(),
                    },
                )
                .await
                .unwrap();
            let sessions = Arc::new(Sessions {
                calls: AtomicUsize::new(0),
                reject: AtomicBool::new(false),
                key: Mutex::new(format!("sha256:{}", "b".repeat(64))),
                valid_until: Mutex::new(None),
                mutate: Mutex::new(None),
                effect: Mutex::new(SessionEffect::None),
                lifecycle: lifecycle.clone(),
                consent: consent.clone(),
                clock: clock.clone(),
            });
            let issuer = DelegationChallengeIssuer::with_clock(
                lifecycle.clone(),
                Some(sessions.clone()),
                120,
                clock.clone(),
            )
            .unwrap();
            Self {
                issuer,
                lifecycle,
                grant,
                consent,
                sessions,
                clock,
            }
        }

        fn request(&self) -> DelegationChallengeRequest {
            DelegationChallengeRequest {
                grant_id: self.grant.id,
                expected_revision: self.grant.revision,
                action: self.grant.terms.actions[0].clone(),
                audience: self.grant.terms.audiences[0].clone(),
                resource: self.grant.terms.resources[0].clone(),
                operation_profile: "urn:example:operation:v1".into(),
                operation_digest: format!("sha256:{}", "c".repeat(64)),
            }
        }

        async fn admit(&self) -> Result<DelegationChallengeAdmission, DelegationChallengeError> {
            self.issuer
                .admit(
                    self.grant.organization_id,
                    &self.grant.terms.delegate,
                    self.request(),
                )
                .await
        }
    }

    #[tokio::test]
    async fn key_admission_uses_service_ids_exact_operation_and_no_session_provider() {
        let mut h = Harness::new(BindingMethod::Key).await;
        h.issuer.sessions = None;
        let first = h.admit().await.unwrap();
        let second = h.admit().await.unwrap();
        assert_ne!(first.binding().challenge_id, second.binding().challenge_id);
        assert_eq!(first.binding().grant_id, h.grant.id);
        assert_eq!(first.binding().organization_id, h.grant.organization_id);
        assert_eq!(first.binding().actor, h.grant.terms.delegate);
        assert_eq!(first.binding().grant_revision, h.grant.revision);
        assert_eq!(first.binding().action, h.request().action);
        assert_eq!(first.binding().audience, h.request().audience);
        assert_eq!(first.binding().resource, h.request().resource);
        assert_eq!(
            first.binding().operation_profile,
            h.request().operation_profile
        );
        assert_eq!(
            first.binding().operation_digest,
            h.request().operation_digest
        );
        assert!(first.binding().session_ref.is_none());
        assert_eq!(first.valid_until(), h.clock.now() + Duration::seconds(120));
        assert_eq!(h.sessions.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn session_admission_requires_an_independently_verified_current_binding() {
        let mut h = Harness::new(BindingMethod::Session).await;
        h.issuer.sessions = None;
        assert_eq!(
            h.admit().await.unwrap_err(),
            DelegationChallengeError::SessionNotVerified
        );
        h.issuer.sessions = Some(h.sessions.clone());
        h.sessions.reject.store(true, Ordering::SeqCst);
        assert_eq!(
            h.admit().await.unwrap_err(),
            DelegationChallengeError::SessionNotVerified
        );
        h.sessions.reject.store(false, Ordering::SeqCst);
        let admission = h.admit().await.unwrap();
        assert_eq!(
            admission.binding().session_ref,
            h.grant.terms.binding.session_ref
        );
        assert_eq!(
            admission.binding().establishment_evidence_ref,
            h.grant.terms.binding.establishment_evidence_ref
        );
        assert_eq!(
            admission.binding().session_key_thumbprint.as_deref(),
            Some(h.sessions.key.lock().unwrap().as_str())
        );
    }

    #[tokio::test]
    async fn session_evidence_rejects_cross_binding_stale_future_and_expired_results() {
        let mutations: &[(&str, SessionMutation)] = &[
            ("tenant", |s| s.organization_id = Uuid::new_v4()),
            ("grant", |s| s.grant_id = Uuid::new_v4()),
            ("terms", |s| {
                s.terms_digest = format!("sha256:{}", "d".repeat(64))
            }),
            ("actor type", |s| {
                s.delegate.principal_type = PrincipalType::User
            }),
            ("actor id", |s| {
                s.delegate.id = "urn:example:other-actor".into()
            }),
            ("session", |s| {
                s.session_ref = "urn:example:other-session".into()
            }),
            ("establishment", |s| {
                s.establishment_evidence_ref = "urn:example:other-evidence".into()
            }),
            ("key", |s| s.key_thumbprint = "unverified-key".into()),
            ("stale", |s| s.observed_at -= Duration::seconds(1)),
            ("future", |s| s.observed_at += Duration::seconds(1)),
            ("expired", |s| s.valid_until = s.observed_at),
        ];
        let h = Harness::new(BindingMethod::Session).await;
        for (label, mutate) in mutations {
            *h.sessions.mutate.lock().unwrap() = Some(*mutate);
            assert_eq!(
                h.admit().await.unwrap_err(),
                DelegationChallengeError::SessionNotVerified,
                "{label}"
            );
        }
    }

    #[tokio::test]
    async fn request_identity_revision_and_scope_fail_before_session_resolution() {
        let h = Harness::new(BindingMethod::Session).await;
        let mut wrong_actor = h.grant.terms.delegate.clone();
        wrong_actor.principal_type = PrincipalType::User;
        assert_eq!(
            h.issuer
                .admit(h.grant.organization_id, &wrong_actor, h.request())
                .await
                .unwrap_err(),
            DelegationChallengeError::WrongDelegate
        );
        assert_eq!(
            h.issuer
                .admit(Uuid::new_v4(), &h.grant.terms.delegate, h.request())
                .await
                .unwrap_err(),
            DelegationChallengeError::GrantUnavailable
        );
        let mut request = h.request();
        request.expected_revision += 1;
        assert_eq!(
            h.issuer
                .admit(h.grant.organization_id, &h.grant.terms.delegate, request)
                .await
                .unwrap_err(),
            DelegationChallengeError::RevisionConflict
        );
        for field in 0..3 {
            let mut request = h.request();
            match field {
                0 => request.action = "urn:example:other-action".into(),
                1 => request.audience = "https://other.example".into(),
                _ => request.resource = "urn:example:other-resource".into(),
            }
            assert_eq!(
                h.issuer
                    .admit(h.grant.organization_id, &h.grant.terms.delegate, request)
                    .await
                    .unwrap_err(),
                DelegationChallengeError::ScopeDenied
            );
        }
        let before = h.consent.calls.load(Ordering::SeqCst);
        let mut request = h.request();
        request.operation_digest = "bad-digest".into();
        assert_eq!(
            h.issuer
                .admit(h.grant.organization_id, &h.grant.terms.delegate, request)
                .await
                .unwrap_err(),
            DelegationChallengeError::InvalidRequest
        );
        assert_eq!(h.consent.calls.load(Ordering::SeqCst), before);
        assert_eq!(h.sessions.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn exact_operation_grants_require_both_profile_and_digest() {
        let mut template = pending_grant();
        template.terms.constraints = Constraints {
            mode: ConstraintMode::ExactOperation,
            request_profile: Some("urn:example:operation:v1".into()),
            request_digest: Some(format!("sha256:{}", "c".repeat(64))),
            profile: None,
            document_ref: None,
            document_digest: None,
            evaluator: None,
        };
        let h = Harness::with_template(template).await;
        h.admit().await.unwrap();
        for change_profile in [true, false] {
            let mut request = h.request();
            if change_profile {
                request.operation_profile = "urn:example:other-operation:v1".into();
            } else {
                request.operation_digest = format!("sha256:{}", "d".repeat(64));
            }
            assert_eq!(
                h.issuer
                    .admit(h.grant.organization_id, &h.grant.terms.delegate, request)
                    .await
                    .unwrap_err(),
                DelegationChallengeError::ScopeDenied
            );
        }
        assert_eq!(h.sessions.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn admission_deadline_is_capped_by_grant_consent_and_session_freshness() {
        let mut template = pending_grant();
        template.terms.valid_until = template.created_at + Duration::seconds(90);
        let h = Harness::with_template(template).await;
        assert_eq!(
            h.admit().await.unwrap().valid_until(),
            h.grant.terms.valid_until
        );
        let consent_deadline = h.clock.now() + Duration::seconds(50);
        *h.consent.valid_until.lock().unwrap() = Some(consent_deadline);
        assert_eq!(h.admit().await.unwrap().valid_until(), consent_deadline);
        let session_deadline = h.clock.now() + Duration::seconds(20);
        *h.sessions.valid_until.lock().unwrap() = Some(session_deadline);
        assert_eq!(h.admit().await.unwrap().valid_until(), session_deadline);
    }

    #[tokio::test]
    async fn state_changes_during_session_resolution_prevent_admission() {
        for effect in [SessionEffect::Suspend, SessionEffect::Withdraw] {
            let h = Harness::new(BindingMethod::Session).await;
            *h.sessions.effect.lock().unwrap() = effect;
            assert_eq!(
                h.admit().await.unwrap_err(),
                DelegationChallengeError::GrantUnavailable
            );
        }
    }

    #[tokio::test]
    async fn reactivated_grant_is_not_the_same_active_revision() {
        let h = Harness::new(BindingMethod::Session).await;
        *h.sessions.effect.lock().unwrap() = SessionEffect::Reinstate;
        assert_eq!(
            h.admit().await.unwrap_err(),
            DelegationChallengeError::StateChanged
        );

        let h = Harness::new(BindingMethod::Session).await;
        let mut admission = h.admit().await.unwrap();
        *h.sessions.effect.lock().unwrap() = SessionEffect::Reinstate;
        assert_eq!(
            admission.revalidate().await,
            Err(DelegationChallengeError::StateChanged)
        );
        // The same old admission also fails before any session provider call
        // when the newer ACTIVE revision already exists at refresh entry.
        let before = h.sessions.calls.load(Ordering::SeqCst);
        *h.sessions.effect.lock().unwrap() = SessionEffect::None;
        assert_eq!(
            admission.revalidate().await,
            Err(DelegationChallengeError::StateChanged)
        );
        assert_eq!(h.sessions.calls.load(Ordering::SeqCst), before);
    }

    #[tokio::test]
    async fn clock_regression_and_expiry_during_provider_work_fail_closed() {
        let h = Harness::new(BindingMethod::Session).await;
        *h.sessions.effect.lock().unwrap() = SessionEffect::RegressClock;
        assert_eq!(
            h.admit().await.unwrap_err(),
            DelegationChallengeError::Expired
        );
        let h = Harness::new(BindingMethod::Session).await;
        *h.sessions.effect.lock().unwrap() = SessionEffect::Expire;
        assert_eq!(
            h.admit().await.unwrap_err(),
            DelegationChallengeError::SessionNotVerified
        );
    }

    #[tokio::test]
    async fn issuer_clock_cannot_admit_a_grant_updated_in_its_future() {
        let mut h = Harness::new(BindingMethod::Key).await;
        h.issuer.clock = Arc::new(Clock(Mutex::new(h.grant.created_at)));
        assert_eq!(
            h.admit().await.unwrap_err(),
            DelegationChallengeError::Expired
        );
    }

    #[tokio::test]
    async fn revalidation_rejects_revocation_consent_withdrawal_and_key_rotation() {
        for scenario in 0..3 {
            let h = Harness::new(BindingMethod::Session).await;
            let mut admission = h.admit().await.unwrap();
            h.clock.set(h.clock.now() + Duration::seconds(1));
            let expected = match scenario {
                0 => {
                    h.lifecycle
                        .revoke(h.grant.organization_id, h.grant.id, h.grant.revision)
                        .await
                        .unwrap();
                    DelegationChallengeError::GrantUnavailable
                }
                1 => {
                    h.consent.withdrawn.store(true, Ordering::SeqCst);
                    DelegationChallengeError::GrantUnavailable
                }
                _ => {
                    *h.sessions.key.lock().unwrap() = format!("sha256:{}", "d".repeat(64));
                    DelegationChallengeError::StateChanged
                }
            };
            assert_eq!(admission.revalidate().await, Err(expected));
        }
    }

    #[tokio::test]
    async fn revalidation_shortens_deadlines_without_replacing_or_extending_the_binding() {
        let h = Harness::new(BindingMethod::Session).await;
        let mut admission = h.admit().await.unwrap();
        let original_binding = admission.binding().clone();
        let original_deadline = admission.valid_until();
        h.clock.set(h.clock.now() + Duration::seconds(1));
        admission.revalidate().await.unwrap();
        assert_eq!(admission.valid_until(), original_deadline);
        let shorter = h.clock.now() + Duration::seconds(30);
        *h.sessions.valid_until.lock().unwrap() = Some(shorter);
        admission.revalidate().await.unwrap();
        assert_eq!(admission.valid_until(), shorter);
        *h.sessions.valid_until.lock().unwrap() = None;
        admission.revalidate().await.unwrap();
        assert_eq!(admission.valid_until(), shorter);
        let consent_deadline = h.clock.now() + Duration::seconds(10);
        *h.consent.valid_until.lock().unwrap() = Some(consent_deadline);
        admission.revalidate().await.unwrap();
        assert_eq!(admission.valid_until(), consent_deadline);
        *h.consent.valid_until.lock().unwrap() = None;
        admission.revalidate().await.unwrap();
        assert_eq!(admission.valid_until(), consent_deadline);
        assert_eq!(admission.binding(), &original_binding);
    }

    #[tokio::test]
    async fn independent_database_time_expiry_and_regression_are_rejected() {
        let h = Harness::new(BindingMethod::Key).await;
        let mut admission = h.admit().await.unwrap();
        assert_eq!(
            admission.check_live_at(admission.valid_until()),
            Err(DelegationChallengeError::Expired)
        );
        assert_eq!(
            admission.check_live_at(admission.admitted_at() - Duration::seconds(1)),
            Err(DelegationChallengeError::Expired)
        );
        assert!(admission.check_live().is_ok());
        h.clock.set(h.clock.now() + Duration::seconds(1));
        admission.revalidate().await.unwrap();
        assert_eq!(
            admission.check_live_at(admission.admitted_at()),
            Err(DelegationChallengeError::Expired)
        );
        h.clock.set(admission.valid_until());
        assert_eq!(
            admission.revalidate().await,
            Err(DelegationChallengeError::Expired)
        );
    }

    #[tokio::test]
    async fn pending_session_source_is_bounded_during_admission_and_revalidation() {
        let mut h = Harness::new(BindingMethod::Session).await;
        let mut admission = h.admit().await.unwrap();
        h.issuer.timeout = std::time::Duration::from_millis(100);
        admission.issuer.timeout = h.issuer.timeout;
        *h.sessions.effect.lock().unwrap() = SessionEffect::Pending;
        let before = h.sessions.calls.load(Ordering::SeqCst);
        assert_eq!(
            h.admit().await.unwrap_err(),
            DelegationChallengeError::Unavailable
        );
        assert_eq!(h.sessions.calls.load(Ordering::SeqCst), before + 1);
        assert_eq!(
            admission.revalidate().await,
            Err(DelegationChallengeError::Unavailable)
        );
        assert_eq!(h.sessions.calls.load(Ordering::SeqCst), before + 2);
    }

    #[tokio::test]
    async fn configuration_bounds_and_debug_redaction_preserve_internal_boundary() {
        let h = Harness::new(BindingMethod::Session).await;
        for seconds in [0, 29, 601, i64::MAX] {
            assert!(matches!(
                DelegationChallengeIssuer::with_clock(
                    h.lifecycle.clone(),
                    None,
                    seconds,
                    h.clock.clone()
                ),
                Err(DelegationChallengeError::InvalidConfiguration)
            ));
        }
        let admission = h.admit().await.unwrap();
        let debug = format!("{admission:?}");
        assert!(debug.contains(&admission.binding().challenge_id.to_string()));
        for private in [
            h.grant.terms.delegate.id.as_str(),
            h.request().operation_digest.as_str(),
            h.grant.terms.binding.session_ref.as_deref().unwrap(),
            h.grant
                .terms
                .binding
                .establishment_evidence_ref
                .as_deref()
                .unwrap(),
        ] {
            assert!(!debug.contains(private));
        }
    }
}
