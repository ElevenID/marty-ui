//! Configured consent and representation-authority admission.
//!
//! This module checks the bindings and freshness of records returned by trusted
//! adapter implementations. It does not define an approval token/JWS profile,
//! fetch evidence references, authenticate arbitrary JSON, or turn a login into
//! consent. Runtime composition must install authenticated provider adapters and
//! reviewed profile/artifact pins. These pins are deployment metadata checked
//! for exact equality; this module does not measure an executing artifact's
//! digest or establish that an adapter implements its claimed profile. The
//! record types intentionally do not support `Deserialize`: request bodies
//! cannot be used as trusted observations. Provider calls share a five-second
//! deadline and any timeout or provider error fails verification.

use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Datelike, Duration, Utc};
use uuid::Uuid;

use crate::{
    domain::valid_uri, AuthorityMode, ConsentEvidenceVerifier, ConsentVerificationError,
    ConsentVerificationPurpose, ConsentVerificationRequest, DelegationClock, DelegationGrant,
    GrantApproval, GrantStatus, Principal, SystemDelegationClock, VerifiedConsent,
};

const MAX_CONFIGURED_PROFILES: usize = 64;
const MAX_FRESHNESS_SECONDS: u32 = 3600;
const PROVIDER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Exact identity of the installed approval adapter whose contract includes
/// consent provenance and representation-authority verification. The pin comes
/// from reviewed organization deployment configuration, not returned evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalAdapterPin {
    pub profile: String,
    pub version: String,
    pub artifact_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentProfileConfiguration {
    pub pin: ApprovalAdapterPin,
    pub max_observation_age_seconds: u32,
    pub max_confirmation_age_seconds: u32,
    pub max_authority_age_seconds: u32,
}

/// Exact relationship being approved. The terms digest also binds the delegate,
/// key/session binding, scopes, validity and constraints in the immutable grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentEvidenceBinding {
    pub organization_id: Uuid,
    pub grant_id: Uuid,
    pub terms_digest: String,
    pub grantor: Principal,
    pub subject: Principal,
    pub issuer: Principal,
    pub evidence_ref: String,
    pub authority_evidence_ref: String,
}

impl ConsentEvidenceBinding {
    /// Projects identifiers only; constructing this value proves no authority.
    pub fn from_grant(grant: &DelegationGrant, approval: &GrantApproval) -> Self {
        Self {
            organization_id: grant.organization_id,
            grant_id: grant.id,
            terms_digest: grant.terms_digest.clone(),
            grantor: grant.terms.grantor.clone(),
            subject: grant.terms.subject.clone(),
            issuer: grant.authority.issuer.clone(),
            evidence_ref: approval.evidence_ref.clone(),
            authority_evidence_ref: approval.authority_evidence_ref.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsentRecordState {
    Confirmed,
    Withdrawn,
}

/// A current observation of an original trusted, explicit confirmation. The
/// provider must check current withdrawal state; reading a historical receipt
/// alone is insufficient. `confirmed_at` is immutable confirmation time, while
/// `observed_at` is the time the provider checked its current state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentRecord {
    pub pin: ApprovalAdapterPin,
    pub binding: ConsentEvidenceBinding,
    pub state: ConsentRecordState,
    pub confirmed_at: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepresentationAuthorityState {
    Authorized,
    Revoked,
}

/// `asserted_at` records when representation authority was independently
/// established. A fresh database read only updates `observed_at`; it must never
/// silently renew an old authority assertion. Providers may record new trusted
/// assertions under an unchanged evidence reference while retaining history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepresentationAuthorityRecord {
    pub pin: ApprovalAdapterPin,
    pub binding: ConsentEvidenceBinding,
    pub state: RepresentationAuthorityState,
    pub asserted_at: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

#[derive(Clone, Copy)]
pub struct ConsentEvidenceLookup<'a> {
    pub pin: &'a ApprovalAdapterPin,
    pub binding: &'a ConsentEvidenceBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConsentProviderError {
    #[error("trusted consent evidence was not found")]
    NotFound,
    #[error("trusted consent evidence provider is unavailable")]
    Unavailable,
    #[error("trusted consent evidence is invalid")]
    Invalid,
}

/// A trusted, authenticated producer port. The caller supplies an exact
/// configured lookup, never an authorization to fetch a caller-selected URL.
/// Implementations must be read-only because concurrent lifecycle CAS can fail.
#[async_trait]
pub trait ConsentRecordProvider: Send + Sync {
    async fn resolve_consent(
        &self,
        lookup: ConsentEvidenceLookup<'_>,
    ) -> Result<ConsentRecord, ConsentProviderError>;
}

/// Independently establishes the grantor's current representation authority.
/// Matching grantor/subject identifiers do not bypass this port. A raw caller
/// assertion, self-reported role or successful login is not sufficient evidence.
#[async_trait]
pub trait RepresentationAuthorityProvider: Send + Sync {
    async fn resolve_authority(
        &self,
        lookup: ConsentEvidenceLookup<'_>,
    ) -> Result<RepresentationAuthorityRecord, ConsentProviderError>;
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConsentConfigurationError {
    #[error("consent profile configuration is invalid")]
    InvalidConfiguration,
    #[error("consent approval profile is configured more than once")]
    DuplicateProfile,
}

#[derive(Clone)]
pub struct ConfiguredConsentEvidenceVerifier {
    profiles: BTreeMap<String, ConsentProfileConfiguration>,
    consent: Arc<dyn ConsentRecordProvider>,
    authority: Arc<dyn RepresentationAuthorityProvider>,
    clock: Arc<dyn DelegationClock>,
    provider_timeout: std::time::Duration,
}

impl ConfiguredConsentEvidenceVerifier {
    pub fn new(
        profiles: impl IntoIterator<Item = ConsentProfileConfiguration>,
        consent: Arc<dyn ConsentRecordProvider>,
        authority: Arc<dyn RepresentationAuthorityProvider>,
    ) -> Result<Self, ConsentConfigurationError> {
        Self::with_clock(
            profiles,
            consent,
            authority,
            Arc::new(SystemDelegationClock),
        )
    }

    pub fn with_clock(
        profiles: impl IntoIterator<Item = ConsentProfileConfiguration>,
        consent: Arc<dyn ConsentRecordProvider>,
        authority: Arc<dyn RepresentationAuthorityProvider>,
        clock: Arc<dyn DelegationClock>,
    ) -> Result<Self, ConsentConfigurationError> {
        let mut configured = BTreeMap::new();
        for profile in profiles {
            if !valid_uri(Some(&profile.pin.profile))
                || profile.pin.profile.len() > 512
                || !valid_version(&profile.pin.version)
                || !valid_digest(&profile.pin.artifact_digest)
                || [
                    profile.max_observation_age_seconds,
                    profile.max_confirmation_age_seconds,
                    profile.max_authority_age_seconds,
                ]
                .iter()
                .any(|seconds| !(1..=MAX_FRESHNESS_SECONDS).contains(seconds))
                || configured.len() >= MAX_CONFIGURED_PROFILES
            {
                return Err(ConsentConfigurationError::InvalidConfiguration);
            }
            if configured
                .insert(profile.pin.profile.clone(), profile)
                .is_some()
            {
                return Err(ConsentConfigurationError::DuplicateProfile);
            }
        }
        if configured.is_empty() {
            return Err(ConsentConfigurationError::InvalidConfiguration);
        }
        Ok(Self {
            profiles: configured,
            consent,
            authority,
            clock,
            provider_timeout: PROVIDER_TIMEOUT,
        })
    }
}

#[async_trait]
impl ConsentEvidenceVerifier for ConfiguredConsentEvidenceVerifier {
    async fn verify_approval(
        &self,
        request: ConsentVerificationRequest<'_>,
    ) -> Result<VerifiedConsent, ConsentVerificationError> {
        let grant = request.grant;
        grant.validate().map_err(|_| ConsentVerificationError)?;
        if grant.authority.mode != AuthorityMode::Managed
            || grant.status != GrantStatus::Active
            || grant.approval.as_ref() != Some(request.approval)
            || grant.updated_at > request.now
            || !(grant.terms.valid_from <= request.now && request.now < grant.terms.valid_until)
        {
            return Err(ConsentVerificationError);
        }
        let configuration = self
            .profiles
            .get(&request.approval.profile)
            .ok_or(ConsentVerificationError)?;
        let started_at = self.clock.now();
        if started_at < request.now || !valid_time(started_at) {
            return Err(ConsentVerificationError);
        }
        let binding = ConsentEvidenceBinding::from_grant(grant, request.approval);
        let lookup = ConsentEvidenceLookup {
            pin: &configuration.pin,
            binding: &binding,
        };
        // These independent authenticated lookups are read-only. Both must
        // succeed; neither provider's result supplies trust for the other.
        let (consent, authority) = tokio::time::timeout(self.provider_timeout, async {
            tokio::try_join!(
                self.consent.resolve_consent(lookup),
                self.authority.resolve_authority(lookup),
            )
        })
        .await
        .map_err(|_| ConsentVerificationError)?
        .map_err(|_| ConsentVerificationError)?;
        let now = self.clock.now();
        if now < started_at
            || !valid_time(now)
            || consent.pin != configuration.pin
            || authority.pin != configuration.pin
            || consent.binding != binding
            || authority.binding != binding
            || consent.state != ConsentRecordState::Confirmed
            || authority.state != RepresentationAuthorityState::Authorized
            || ![
                consent.confirmed_at,
                consent.observed_at,
                consent.valid_until,
                authority.asserted_at,
                authority.observed_at,
                authority.valid_until,
            ]
            .into_iter()
            .all(valid_time)
            || consent.confirmed_at < grant.created_at
            || consent.confirmed_at > request.approval.approved_at
            || consent.confirmed_at > consent.observed_at
            || authority.asserted_at < grant.created_at
            || authority.asserted_at > authority.observed_at
            || consent.observed_at > now
            || authority.observed_at > now
        {
            return Err(ConsentVerificationError);
        }
        let mut deadline = grant
            .terms
            .valid_until
            .min(consent.valid_until)
            .min(authority.valid_until)
            .min(after(
                consent.observed_at,
                configuration.max_observation_age_seconds,
            )?)
            .min(after(
                authority.observed_at,
                configuration.max_observation_age_seconds,
            )?)
            .min(after(
                authority.asserted_at,
                configuration.max_authority_age_seconds,
            )?);
        // Original consent can survive reinstatement. Fresh authority and
        // withdrawal observations are always mandatory, but a reinstatement
        // must not rewrite the original confirmation/admission timestamp.
        if request.purpose == ConsentVerificationPurpose::Activation {
            deadline = deadline.min(after(
                consent.confirmed_at,
                configuration.max_confirmation_age_seconds,
            )?);
        }
        if now >= deadline {
            return Err(ConsentVerificationError);
        }
        Ok(VerifiedConsent {
            valid_until: deadline,
        })
    }
}

fn after(time: DateTime<Utc>, seconds: u32) -> Result<DateTime<Utc>, ConsentVerificationError> {
    time.checked_add_signed(Duration::seconds(i64::from(seconds)))
        .ok_or(ConsentVerificationError)
}

pub(crate) fn valid_time(time: DateTime<Utc>) -> bool {
    (1..=9999).contains(&time.year()) && time.timestamp_subsec_nanos() < 1_000_000_000
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn valid_version(value: &str) -> bool {
    if value.len() > 64 {
        return false;
    }
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && (part.len() == 1 || !part.starts_with('0'))
                && part.bytes().all(|b| b.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    };

    use crate::{
        test_support::pending_grant, ApprovalEvidence, DelegationAuthorityService,
        DelegationGrantRepository, InMemoryDelegationGrantRepository, PrincipalType, ServiceError,
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

    struct Sources {
        consent: Mutex<Result<ConsentRecord, ConsentProviderError>>,
        authority: Mutex<Result<RepresentationAuthorityRecord, ConsentProviderError>>,
        clock: Arc<Clock>,
        advance_on_consent: Mutex<Duration>,
        consent_calls: AtomicUsize,
        authority_calls: AtomicUsize,
        stall: AtomicBool,
    }
    #[async_trait]
    impl ConsentRecordProvider for Sources {
        async fn resolve_consent(
            &self,
            _: ConsentEvidenceLookup<'_>,
        ) -> Result<ConsentRecord, ConsentProviderError> {
            self.consent_calls.fetch_add(1, Ordering::SeqCst);
            if self.stall.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            let advance = *self.advance_on_consent.lock().unwrap();
            self.clock.set(self.clock.now() + advance);
            self.consent.lock().unwrap().clone()
        }
    }
    #[async_trait]
    impl RepresentationAuthorityProvider for Sources {
        async fn resolve_authority(
            &self,
            _: ConsentEvidenceLookup<'_>,
        ) -> Result<RepresentationAuthorityRecord, ConsentProviderError> {
            self.authority_calls.fetch_add(1, Ordering::SeqCst);
            self.authority.lock().unwrap().clone()
        }
    }

    struct Fixture {
        pending: DelegationGrant,
        active: DelegationGrant,
        clock: Arc<Clock>,
        sources: Arc<Sources>,
        configuration: ConsentProfileConfiguration,
        verifier: ConfiguredConsentEvidenceVerifier,
    }
    impl Fixture {
        fn new() -> Self {
            let pending = pending_grant();
            let now = pending.created_at + Duration::seconds(1);
            let pin = ApprovalAdapterPin {
                profile: "urn:example:trusted-approval:v1".into(),
                version: "1.0.0".into(),
                artifact_digest: format!("sha256:{}", "a".repeat(64)),
            };
            let approval = GrantApproval {
                profile: pin.profile.clone(),
                grant_id: pending.id,
                approver: pending.terms.grantor.clone(),
                evidence_ref: "urn:example:consent:1".into(),
                authority_evidence_ref: "urn:example:representation:1".into(),
                terms_digest: pending.terms_digest.clone(),
                approved_at: now,
            };
            let mut active = pending.clone();
            active.status = GrantStatus::Active;
            active.revision = 2;
            active.updated_at = now;
            active.approval = Some(approval.clone());
            let binding = ConsentEvidenceBinding::from_grant(&active, &approval);
            let clock = Arc::new(Clock(Mutex::new(now)));
            let sources = Arc::new(Sources {
                consent: Mutex::new(Ok(ConsentRecord {
                    pin: pin.clone(),
                    binding: binding.clone(),
                    state: ConsentRecordState::Confirmed,
                    confirmed_at: pending.created_at + Duration::milliseconds(500),
                    observed_at: now,
                    valid_until: pending.terms.valid_until,
                })),
                authority: Mutex::new(Ok(RepresentationAuthorityRecord {
                    pin: pin.clone(),
                    binding,
                    state: RepresentationAuthorityState::Authorized,
                    asserted_at: now,
                    observed_at: now,
                    valid_until: pending.terms.valid_until,
                })),
                clock: clock.clone(),
                advance_on_consent: Mutex::new(Duration::zero()),
                consent_calls: AtomicUsize::new(0),
                authority_calls: AtomicUsize::new(0),
                stall: AtomicBool::new(false),
            });
            let configuration = ConsentProfileConfiguration {
                pin,
                max_observation_age_seconds: 30,
                max_confirmation_age_seconds: 300,
                max_authority_age_seconds: 60,
            };
            let verifier = ConfiguredConsentEvidenceVerifier::with_clock(
                [configuration.clone()],
                sources.clone(),
                sources.clone(),
                clock.clone(),
            )
            .unwrap();
            Self {
                pending,
                active,
                clock,
                sources,
                configuration,
                verifier,
            }
        }
        async fn verify(
            &self,
            purpose: ConsentVerificationPurpose,
        ) -> Result<VerifiedConsent, ConsentVerificationError> {
            self.verifier
                .verify_approval(ConsentVerificationRequest {
                    grant: &self.active,
                    approval: self.active.approval.as_ref().unwrap(),
                    purpose,
                    now: self.clock.now(),
                })
                .await
        }
        fn consent(&self, edit: impl FnOnce(&mut ConsentRecord)) {
            edit(self.sources.consent.lock().unwrap().as_mut().unwrap());
        }
        fn authority(&self, edit: impl FnOnce(&mut RepresentationAuthorityRecord)) {
            edit(self.sources.authority.lock().unwrap().as_mut().unwrap());
        }
        fn fresh_at(&self, seconds_after_creation: i64) {
            let now = self.pending.created_at + Duration::seconds(seconds_after_creation);
            self.clock.set(now);
            self.consent(|record| record.observed_at = now);
            self.authority(|record| {
                record.observed_at = now;
                record.asserted_at = now;
            });
        }
    }

    #[tokio::test]
    async fn accepts_exact_trusted_bindings_and_clamps_to_every_deadline() {
        for deadline_source in 0..6 {
            let f = Fixture::new();
            let expected = f.clock.now() + Duration::seconds(5);
            match deadline_source {
                0 => f.consent(|r| r.valid_until = expected),
                1 => f.authority(|r| r.valid_until = expected),
                2 => {
                    f.fresh_at(100);
                    let observed = f.clock.now() - Duration::seconds(25);
                    f.consent(|r| r.observed_at = observed);
                }
                3 => {
                    f.fresh_at(100);
                    let observed = f.clock.now() - Duration::seconds(25);
                    f.authority(|r| {
                        r.observed_at = observed;
                        r.asserted_at = observed;
                    });
                }
                4 => {
                    f.fresh_at(100);
                    f.authority(|r| r.asserted_at = f.clock.now() - Duration::seconds(55));
                }
                5 => {
                    f.fresh_at(295);
                    // Confirmation was at creation+0.5s; its age bound expires
                    // before the otherwise-fresh status/authority observations.
                }
                _ => unreachable!(),
            }
            let verified = f
                .verify(ConsentVerificationPurpose::Activation)
                .await
                .unwrap();
            let expected = match deadline_source {
                0 | 1 => expected,
                2..=4 => f.clock.now() + Duration::seconds(5),
                5 => f.pending.created_at + Duration::milliseconds(300_500),
                _ => unreachable!(),
            };
            assert_eq!(verified.valid_until, expected);
        }
        let mut f = Fixture::new();
        f.active.terms.valid_until = f.clock.now() + Duration::seconds(3);
        f.active.terms_digest = f.active.calculate_terms_digest().unwrap();
        f.active.approval.as_mut().unwrap().terms_digest = f.active.terms_digest.clone();
        let binding =
            ConsentEvidenceBinding::from_grant(&f.active, f.active.approval.as_ref().unwrap());
        f.consent(|r| r.binding = binding.clone());
        f.authority(|r| r.binding = binding);
        assert_eq!(
            f.verify(ConsentVerificationPurpose::Activation)
                .await
                .unwrap()
                .valid_until,
            f.active.terms.valid_until
        );
    }

    #[tokio::test]
    async fn both_sources_must_match_every_principal_grant_tenant_and_reference() {
        let substitutions: &[fn(&mut ConsentEvidenceBinding)] = &[
            |b| b.organization_id = Uuid::new_v4(),
            |b| b.grant_id = Uuid::new_v4(),
            |b| b.terms_digest = format!("sha256:{}", "b".repeat(64)),
            |b| b.grantor.principal_type = PrincipalType::External,
            |b| b.grantor.id = "urn:example:other-grantor".into(),
            |b| b.subject.principal_type = PrincipalType::Organization,
            |b| b.subject.id = "urn:example:other-subject".into(),
            |b| b.issuer.principal_type = PrincipalType::ServiceAccount,
            |b| b.issuer.id = "urn:example:other-issuer".into(),
            |b| b.evidence_ref = "urn:example:other-consent".into(),
            |b| b.authority_evidence_ref = "urn:example:other-authority".into(),
        ];
        for change in substitutions {
            for source in 0..2 {
                let f = Fixture::new();
                if source == 0 {
                    f.consent(|r| change(&mut r.binding));
                } else {
                    f.authority(|r| change(&mut r.binding));
                }
                assert!(f
                    .verify(ConsentVerificationPurpose::Activation)
                    .await
                    .is_err());
            }
        }
    }

    #[tokio::test]
    async fn profile_version_and_artifact_must_match_for_both_sources() {
        let substitutions: &[fn(&mut ApprovalAdapterPin)] = &[
            |p| p.profile = "urn:example:unreviewed:v1".into(),
            |p| p.version = "1.0.1".into(),
            |p| p.artifact_digest = format!("sha256:{}", "b".repeat(64)),
        ];
        for change in substitutions {
            for source in 0..2 {
                let f = Fixture::new();
                if source == 0 {
                    f.consent(|r| change(&mut r.pin));
                } else {
                    f.authority(|r| change(&mut r.pin));
                }
                assert!(f
                    .verify(ConsentVerificationPurpose::Activation)
                    .await
                    .is_err());
            }
        }
        let mut f = Fixture::new();
        f.active.approval.as_mut().unwrap().profile = "urn:example:unknown:v1".into();
        assert!(f
            .verify(ConsentVerificationPurpose::Activation)
            .await
            .is_err());
        assert_eq!(f.sources.consent_calls.load(Ordering::SeqCst), 0);
        assert_eq!(f.sources.authority_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn withdrawal_and_representation_revocation_fail_even_for_self_grants() {
        for source in 0..2 {
            let f = Fixture::new();
            assert_eq!(f.active.terms.grantor, f.active.terms.subject);
            if source == 0 {
                f.consent(|r| r.state = ConsentRecordState::Withdrawn);
            } else {
                f.authority(|r| r.state = RepresentationAuthorityState::Revoked);
            }
            assert!(f
                .verify(ConsentVerificationPurpose::Resolution)
                .await
                .is_err());
        }
    }

    #[tokio::test]
    async fn old_authority_assertion_is_not_renewed_by_fresh_database_observation() {
        let f = Fixture::new();
        f.fresh_at(100);
        f.authority(|r| r.asserted_at = f.clock.now() - Duration::seconds(60));
        assert!(f
            .verify(ConsentVerificationPurpose::Resolution)
            .await
            .is_err());
        f.authority(|r| r.asserted_at = f.clock.now() - Duration::seconds(59));
        assert_eq!(
            f.verify(ConsentVerificationPurpose::Resolution)
                .await
                .unwrap()
                .valid_until,
            f.clock.now() + Duration::seconds(1)
        );
    }

    #[tokio::test]
    async fn stale_observations_and_expired_records_are_rejected_at_exclusive_deadlines() {
        for source in 0..4 {
            let f = Fixture::new();
            f.fresh_at(100);
            let now = f.clock.now();
            match source {
                0 => f.consent(|r| r.observed_at = now - Duration::seconds(30)),
                1 => f.authority(|r| {
                    r.observed_at = now - Duration::seconds(30);
                    r.asserted_at = r.observed_at;
                }),
                2 => f.consent(|r| r.valid_until = now),
                3 => f.authority(|r| r.valid_until = now),
                _ => unreachable!(),
            }
            assert!(f
                .verify(ConsentVerificationPurpose::Resolution)
                .await
                .is_err());
        }
    }

    #[tokio::test]
    async fn confirmation_must_follow_creation_and_precede_admission_and_observation() {
        for variant in 0..3 {
            let f = Fixture::new();
            f.fresh_at(10);
            let confirmed = match variant {
                0 => f.pending.created_at - Duration::nanoseconds(1),
                1 => f.active.approval.as_ref().unwrap().approved_at + Duration::nanoseconds(1),
                2 => f.pending.created_at + Duration::milliseconds(500),
                _ => unreachable!(),
            };
            f.consent(|r| {
                r.confirmed_at = confirmed;
                if variant == 2 {
                    r.observed_at = confirmed - Duration::nanoseconds(1);
                }
            });
            assert!(f
                .verify(ConsentVerificationPurpose::Activation)
                .await
                .is_err());
        }
    }

    #[tokio::test]
    async fn future_observations_fail_but_provider_latency_is_measured_after_awaits() {
        for source in 0..2 {
            let f = Fixture::new();
            let future = f.clock.now() + Duration::seconds(1);
            if source == 0 {
                f.consent(|r| r.observed_at = future);
            } else {
                f.authority(|r| r.observed_at = future);
            }
            assert!(f
                .verify(ConsentVerificationPurpose::Resolution)
                .await
                .is_err());
            *f.sources.advance_on_consent.lock().unwrap() = Duration::seconds(1);
            assert!(f
                .verify(ConsentVerificationPurpose::Resolution)
                .await
                .is_ok());
        }
        let f = Fixture::new();
        *f.sources.advance_on_consent.lock().unwrap() = Duration::seconds(31);
        assert!(f
            .verify(ConsentVerificationPurpose::Resolution)
            .await
            .is_err());
        let f = Fixture::new();
        *f.sources.advance_on_consent.lock().unwrap() = Duration::seconds(-1);
        assert!(f
            .verify(ConsentVerificationPurpose::Resolution)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn confirmation_age_applies_only_to_initial_activation() {
        let f = Fixture::new();
        f.fresh_at(1000);
        assert!(f
            .verify(ConsentVerificationPurpose::Activation)
            .await
            .is_err());
        assert!(f
            .verify(ConsentVerificationPurpose::Reinstatement)
            .await
            .is_ok());
        assert!(f
            .verify(ConsentVerificationPurpose::Resolution)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn missing_invalid_unavailable_or_stalled_providers_fail_closed() {
        for failure in [
            ConsentProviderError::NotFound,
            ConsentProviderError::Unavailable,
            ConsentProviderError::Invalid,
        ] {
            for source in 0..2 {
                let f = Fixture::new();
                if source == 0 {
                    *f.sources.consent.lock().unwrap() = Err(failure);
                } else {
                    *f.sources.authority.lock().unwrap() = Err(failure);
                }
                let error = f
                    .verify(ConsentVerificationPurpose::Activation)
                    .await
                    .unwrap_err();
                assert_eq!(error.to_string(), "consent evidence verification failed");
            }
        }
        let mut f = Fixture::new();
        assert_eq!(
            f.verifier.provider_timeout,
            std::time::Duration::from_secs(5)
        );
        f.verifier.provider_timeout = std::time::Duration::from_millis(1);
        f.sources.stall.store(true, Ordering::SeqCst);
        assert!(f
            .verify(ConsentVerificationPurpose::Activation)
            .await
            .is_err());
    }

    #[test]
    fn empty_duplicate_malformed_or_unbounded_configuration_is_rejected() {
        let f = Fixture::new();
        let build = |profiles: Vec<ConsentProfileConfiguration>| {
            ConfiguredConsentEvidenceVerifier::with_clock(
                profiles,
                f.sources.clone(),
                f.sources.clone(),
                f.clock.clone(),
            )
        };
        assert!(matches!(
            build(vec![]),
            Err(ConsentConfigurationError::InvalidConfiguration)
        ));
        assert!(matches!(
            build(vec![f.configuration.clone(); 2]),
            Err(ConsentConfigurationError::DuplicateProfile)
        ));
        let mutations: &[fn(&mut ConsentProfileConfiguration)] = &[
            |c| c.pin.profile = "not a URI".into(),
            |c| c.pin.version = "1.0".into(),
            |c| c.pin.version = "01.0.0".into(),
            |c| c.pin.version = "1.0.0-dev".into(),
            |c| c.pin.artifact_digest = format!("sha256:{}", "A".repeat(64)),
            |c| c.max_observation_age_seconds = 0,
            |c| c.max_authority_age_seconds = 3601,
            |c| c.max_confirmation_age_seconds = 0,
        ];
        for change in mutations {
            let mut config = f.configuration.clone();
            change(&mut config);
            assert!(matches!(
                build(vec![config]),
                Err(ConsentConfigurationError::InvalidConfiguration)
            ));
        }
    }

    #[tokio::test]
    async fn lifecycle_uses_configured_sources_and_withdrawn_authority_prevents_reinstatement() {
        let f = Fixture::new();
        let repository = Arc::new(InMemoryDelegationGrantRepository::default());
        repository.insert(f.pending.clone()).await.unwrap();
        let service = DelegationAuthorityService::with_clock(
            repository.clone(),
            Arc::new(f.verifier.clone()),
            f.pending.authority.clone(),
            f.clock.clone(),
        )
        .unwrap();
        let approval = f.active.approval.as_ref().unwrap();
        let active = service
            .approve(
                f.pending.organization_id,
                f.pending.id,
                1,
                &f.pending.terms.grantor,
                ApprovalEvidence {
                    profile: approval.profile.clone(),
                    evidence_ref: approval.evidence_ref.clone(),
                    authority_evidence_ref: approval.authority_evidence_ref.clone(),
                },
            )
            .await
            .unwrap();
        assert_eq!(active.status, GrantStatus::Active);
        f.clock.set(f.clock.now() + Duration::seconds(1));
        assert!(service
            .resolve(f.pending.organization_id, f.pending.id)
            .await
            .is_ok());
        let suspended = service
            .suspend(f.pending.organization_id, f.pending.id, 2)
            .await
            .unwrap();
        f.clock.set(f.clock.now() + Duration::seconds(1));
        f.authority(|r| r.state = RepresentationAuthorityState::Revoked);
        assert!(matches!(
            service
                .reinstate(f.pending.organization_id, f.pending.id, 3)
                .await,
            Err(ServiceError::ConsentNotVerified)
        ));
        assert_eq!(
            repository
                .get(f.pending.organization_id, f.pending.id)
                .await
                .unwrap(),
            Some(suspended)
        );
        assert_eq!(
            repository
                .audit(f.pending.organization_id, f.pending.id)
                .await
                .unwrap()
                .len(),
            3
        );
    }
}
