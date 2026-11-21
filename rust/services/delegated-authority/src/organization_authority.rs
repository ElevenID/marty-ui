//! Concrete current representation authority from the Organization owner.
//!
//! Uses the authoritative Organization PostgreSQL store, active organization and
//! membership, and the exact dedicated permission. Role names, owner flags,
//! login success and self-representation are never authority substitutes.
//! Producers append bounded source observations with separate credentials.
//! Runtime verification is read-only: it rechecks Organization and reads the
//! existing assertion; it cannot renew an assertion or consent timestamp.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use marty_organization::{
    authorization::{authorize_forwarded_principal, ForwardedPrincipal},
    domain::{MemberStatus, OrganizationStatus},
    postgres::PostgresOrganizationStore,
};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{
    approval::{canonical_user_id, organization_principal},
    approval_postgres::{database_now, load_grant, lock_reference, timestamp},
    ApprovalProducerError, ConsentEvidenceBinding, ConsentEvidenceLookup, ConsentProviderError,
    DelegationClock, OrganizationApprovalConfiguration, PgConsentEvidenceProvider,
    RepresentationAuthorityProvider, RepresentationAuthorityRecord, RepresentationAuthorityState,
    MAX_GRANT_REVISION, ORGANIZATION_DELEGATION_APPROVE_PERMISSION,
};

const SOURCE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Clone)]
pub(crate) struct CurrentOrganizationAuthority {
    pub(crate) store: PostgresOrganizationStore,
    pub(crate) configuration: OrganizationApprovalConfiguration,
    pub(crate) clock: Arc<dyn DelegationClock>,
}

pub(crate) struct CurrentOrganizationObservation {
    pub(crate) member_id: Uuid,
    pub(crate) observed_at: DateTime<Utc>,
    pub(crate) valid_until: DateTime<Utc>,
}
impl CurrentOrganizationObservation {
    pub(crate) fn check(&self, now: DateTime<Utc>) -> Result<(), ApprovalProducerError> {
        if now < self.observed_at || now >= self.valid_until {
            return Err(ApprovalProducerError::Stale);
        }
        Ok(())
    }
}

impl CurrentOrganizationAuthority {
    pub(crate) async fn check_actor(
        &self,
        user_id: Uuid,
        permission: &str,
    ) -> Result<CurrentOrganizationObservation, ApprovalProducerError> {
        if user_id.is_nil() {
            return Err(ApprovalProducerError::AccessDenied);
        }
        let started_at = self.clock.now();
        let organization_id = self.configuration.organization_id;
        let observation = tokio::time::timeout(SOURCE_TIMEOUT, async {
            let organization = self
                .store
                .organization_by_id(organization_id)
                .await
                .map_err(|_| ApprovalProducerError::Unavailable)?
                .ok_or(ApprovalProducerError::AccessDenied)?;
            let member = self
                .store
                .member_by_user_and_organization(&user_id.to_string(), organization_id)
                .await
                .map_err(|_| ApprovalProducerError::Unavailable)?
                .ok_or(ApprovalProducerError::AccessDenied)?;
            if organization.status != OrganizationStatus::Active
                || member.status != MemberStatus::Active
                || member.organization_id != organization_id
                || member.user_id != user_id.to_string()
                || member
                    .roles
                    .iter()
                    .any(|role| role.organization_id != organization_id)
                || !member.effective_permissions().contains(permission)
            {
                return Err(ApprovalProducerError::AccessDenied);
            }
            authorize_forwarded_principal(
                organization_id,
                &ForwardedPrincipal::User {
                    user_id: user_id.to_string(),
                },
                permission,
                false,
                Some(&member),
            )
            .map_err(|_| ApprovalProducerError::AccessDenied)?;
            let observed_at = self.clock.now();
            // The deadline starts BEFORE the source reads. Slow reads do not
            // create a fresh full lifetime by merely returning later.
            let valid_until = started_at
                + Duration::seconds(i64::from(self.configuration.authority_validity_seconds));
            if observed_at < started_at || observed_at >= valid_until {
                return Err(ApprovalProducerError::Stale);
            }
            Ok(CurrentOrganizationObservation {
                member_id: member.id,
                observed_at,
                valid_until,
            })
        })
        .await
        .map_err(|_| ApprovalProducerError::Unavailable)??;
        observation.check(self.clock.now())?;
        Ok(observation)
    }

    pub(crate) fn check_binding(
        &self,
        binding: &ConsentEvidenceBinding,
    ) -> Result<Uuid, ApprovalProducerError> {
        if binding.organization_id != self.configuration.organization_id
            || binding.subject != organization_principal(binding.organization_id)
            || binding.issuer != self.configuration.issuer
        {
            return Err(ApprovalProducerError::AccessDenied);
        }
        canonical_user_id(&binding.grantor).ok_or(ApprovalProducerError::AccessDenied)
    }
}

#[derive(Clone)]
pub struct PgOrganizationAuthorityProducer {
    pub(crate) current: CurrentOrganizationAuthority,
    pub(crate) pool: PgPool,
}
impl PgOrganizationAuthorityProducer {
    pub fn new(
        store: PostgresOrganizationStore,
        authority_writer_pool: PgPool,
        configuration: OrganizationApprovalConfiguration,
        clock: Arc<dyn DelegationClock>,
    ) -> Self {
        Self {
            current: CurrentOrganizationAuthority {
                store,
                configuration,
                clock,
            },
            pool: authority_writer_pool,
        }
    }

    /// The resulting provider owns no producer credential and cannot refresh
    /// authority as a side effect of a grant resolution or failed lifecycle CAS.
    pub fn read_provider(
        &self,
        runtime_read_pool: PgPool,
    ) -> OrganizationRepresentationAuthorityProvider {
        OrganizationRepresentationAuthorityProvider {
            current: self.current.clone(),
            pool: runtime_read_pool,
        }
    }

    pub async fn readiness(&self) -> Result<(), ApprovalProducerError> {
        crate::approval_postgres::check_authority_roles(&self.pool, self.current.store.pool()).await
    }

    pub(crate) async fn establish(
        &self,
        binding: &ConsentEvidenceBinding,
    ) -> Result<RepresentationAuthorityRecord, ApprovalProducerError> {
        self.write_observation(binding, true).await
    }

    /// A separately scheduled trusted producer operation, never a consent
    /// renewal or a public assertion endpoint. Revocation of a source is terminal.
    pub async fn refresh_authority(
        &self,
        organization_id: Uuid,
        authority_evidence_ref: &str,
    ) -> Result<(), ApprovalProducerError> {
        if organization_id != self.current.configuration.organization_id {
            return Err(ApprovalProducerError::AccessDenied);
        }
        let binding = self.load_binding(authority_evidence_ref).await?;
        self.write_observation(&binding, false).await.map(|_| ())
    }

    /// Refreshes a bounded oldest-due batch. The host runs this at an interval
    /// shorter than the configured assertion horizon. Failed sources remain
    /// unavailable to read verification even before their old assertion expires.
    pub async fn refresh_due_authorities(&self, limit: u32) -> Result<u32, ApprovalProducerError> {
        if !(1..=128).contains(&limit) {
            return Err(ApprovalProducerError::InvalidInput);
        }
        let refs: Vec<String> = sqlx::query_scalar(
            "SELECT s.authority_evidence_ref
             FROM delegated_authority_service.representation_authority_sources s
             JOIN LATERAL (SELECT state,valid_until FROM delegated_authority_service.representation_authority_assertions
               WHERE organization_id=s.organization_id AND authority_evidence_ref=s.authority_evidence_ref ORDER BY revision DESC LIMIT 1) a ON true
             JOIN delegated_authority_service.delegation_grants g ON g.organization_id=s.organization_id AND g.id=s.grant_id
             WHERE s.organization_id=$1 AND s.profile=$2 AND s.adapter_version=$3 AND s.artifact_digest=$4
               AND a.state='AUTHORIZED' AND g.status IN ('PENDING','ACTIVE','SUSPENDED')
               AND delegated_authority_service.grant_instant(g.grant_document #>> '{terms,valid_until}') > extract(epoch FROM clock_timestamp())
               AND delegated_authority_service.grant_instant(a.valid_until) <= extract(epoch FROM clock_timestamp()) + $5
             ORDER BY delegated_authority_service.grant_instant(a.valid_until),s.authority_evidence_ref LIMIT $6"
        ).bind(self.current.configuration.organization_id).bind(&self.current.configuration.pin.profile)
            .bind(&self.current.configuration.pin.version).bind(&self.current.configuration.pin.artifact_digest)
            .bind(f64::from(self.current.configuration.authority_validity_seconds) / 2.0).bind(i64::from(limit))
            .fetch_all(&self.pool).await.map_err(unavailable)?;
        let mut count = 0;
        for reference in refs {
            match self
                .refresh_authority(self.current.configuration.organization_id, &reference)
                .await
            {
                Ok(()) | Err(ApprovalProducerError::AccessDenied) => count += 1,
                Err(error) => return Err(error),
            }
        }
        Ok(count)
    }

    async fn load_binding(
        &self,
        reference: &str,
    ) -> Result<ConsentEvidenceBinding, ApprovalProducerError> {
        let row = sqlx::query("SELECT grant_id,terms_digest,grantor,subject,issuer,evidence_ref,authority_evidence_ref,profile,adapter_version,artifact_digest
            FROM delegated_authority_service.representation_authority_sources WHERE organization_id=$1 AND authority_evidence_ref=$2")
            .bind(self.current.configuration.organization_id).bind(reference).fetch_optional(&self.pool).await.map_err(unavailable)?
            .ok_or(ApprovalProducerError::NotFound)?;
        let configuration = &self.current.configuration;
        if row.try_get::<String, _>("profile").map_err(unavailable)? != configuration.pin.profile
            || row
                .try_get::<String, _>("adapter_version")
                .map_err(unavailable)?
                != configuration.pin.version
            || row
                .try_get::<String, _>("artifact_digest")
                .map_err(unavailable)?
                != configuration.pin.artifact_digest
        {
            return Err(ApprovalProducerError::AccessDenied);
        }
        let principal = |column| {
            serde_json::from_value(
                row.try_get::<serde_json::Value, _>(column)
                    .map_err(unavailable)?,
            )
            .map_err(|_| ApprovalProducerError::Unavailable)
        };
        Ok(ConsentEvidenceBinding {
            organization_id: configuration.organization_id,
            grant_id: row.try_get("grant_id").map_err(unavailable)?,
            terms_digest: row.try_get("terms_digest").map_err(unavailable)?,
            grantor: principal("grantor")?,
            subject: principal("subject")?,
            issuer: principal("issuer")?,
            evidence_ref: row.try_get("evidence_ref").map_err(unavailable)?,
            authority_evidence_ref: row.try_get("authority_evidence_ref").map_err(unavailable)?,
        })
    }

    async fn write_observation(
        &self,
        binding: &ConsentEvidenceBinding,
        allow_create: bool,
    ) -> Result<RepresentationAuthorityRecord, ApprovalProducerError> {
        let user_id = self.current.check_binding(binding)?;
        let grant = load_grant(&self.pool, binding.organization_id, binding.grant_id).await?;
        self.current.configuration.check_grant(&grant)?;
        if binding.terms_digest != grant.terms_digest || binding.grantor != grant.terms.grantor {
            return Err(ApprovalProducerError::Conflict);
        }
        let mut transaction = self.pool.begin().await.map_err(unavailable)?;
        lock_reference(
            &mut transaction,
            "organization-authority",
            binding.organization_id,
            &binding.authority_evidence_ref,
        )
        .await?;
        let existing = sqlx::query("SELECT revision,state,asserted_at FROM delegated_authority_service.representation_authority_assertions
            WHERE organization_id=$1 AND authority_evidence_ref=$2 ORDER BY revision DESC LIMIT 1")
            .bind(binding.organization_id).bind(&binding.authority_evidence_ref).fetch_optional(&mut *transaction).await.map_err(unavailable)?;
        let revision = if let Some(row) = &existing {
            if self.load_binding(&binding.authority_evidence_ref).await? != *binding {
                return Err(ApprovalProducerError::Conflict);
            }
            let revision: i64 = row.try_get("revision").map_err(unavailable)?;
            if row.try_get::<String, _>("state").map_err(unavailable)? != "AUTHORIZED"
                || revision >= MAX_GRANT_REVISION as i64
            {
                return Err(ApprovalProducerError::AccessDenied);
            }
            revision + 1
        } else if allow_create {
            1
        } else {
            return Err(ApprovalProducerError::NotFound);
        };
        // Query AFTER the advisory wait, so queueing cannot age an observation
        // before it even reaches the source owner.
        let observation = self
            .current
            .check_actor(user_id, ORGANIZATION_DELEGATION_APPROVE_PERMISSION)
            .await;
        let (authorized, member_id, observed_at, valid_until) = match observation {
            Ok(observation) => (
                true,
                Some(observation.member_id),
                observation.observed_at,
                observation.valid_until.min(grant.terms.valid_until),
            ),
            Err(ApprovalProducerError::AccessDenied) if existing.is_some() => {
                let now = self.current.clock.now();
                (false, None, now, now.min(grant.terms.valid_until))
            }
            Err(error) => return Err(error),
        };
        if let Some(row) = &existing {
            let old = parse_time(
                row.try_get::<String, _>("asserted_at")
                    .map_err(unavailable)?,
            )?;
            if observed_at <= old {
                return Err(ApprovalProducerError::Stale);
            }
        }
        let database_time = database_now(&mut transaction).await?;
        let prepared_at = self.current.clock.now();
        if observed_at > database_time
            || prepared_at < observed_at
            || (authorized && (prepared_at >= valid_until || database_time >= valid_until))
        {
            return Err(ApprovalProducerError::Stale);
        }
        if existing.is_none() {
            let pin = &self.current.configuration.pin;
            sqlx::query("INSERT INTO delegated_authority_service.representation_authority_sources
                (organization_id,authority_evidence_ref,evidence_ref,grant_id,terms_digest,grantor,subject,issuer,profile,adapter_version,artifact_digest)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
                .bind(binding.organization_id).bind(&binding.authority_evidence_ref).bind(&binding.evidence_ref)
                .bind(binding.grant_id).bind(&binding.terms_digest).bind(serde_json::to_value(&binding.grantor).map_err(unavailable)?)
                .bind(serde_json::to_value(&binding.subject).map_err(unavailable)?).bind(serde_json::to_value(&binding.issuer).map_err(unavailable)?)
                .bind(&pin.profile).bind(&pin.version).bind(&pin.artifact_digest).execute(&mut *transaction).await.map_err(unavailable)?;
        }
        sqlx::query("INSERT INTO delegated_authority_service.representation_authority_assertions
            (organization_id,authority_evidence_ref,revision,state,asserted_at,valid_until) VALUES ($1,$2,$3,$4,$5,$6)")
            .bind(binding.organization_id).bind(&binding.authority_evidence_ref).bind(revision)
            .bind(if authorized {"AUTHORIZED"} else {"REVOKED"}).bind(timestamp(observed_at)).bind(timestamp(valid_until))
            .execute(&mut *transaction).await.map_err(unavailable)?;
        sqlx::query("INSERT INTO delegated_authority_service.organization_authority_observations
            (organization_id,authority_evidence_ref,revision,user_id,member_id,source,permission,authorized,observed_at,valid_until)
            VALUES ($1,$2,$3,$4,$5,'urn:marty:organization-store:v1','delegation-grant:approve',$6,$7,$8)")
            .bind(binding.organization_id).bind(&binding.authority_evidence_ref).bind(revision).bind(user_id).bind(member_id)
            .bind(authorized).bind(timestamp(observed_at)).bind(timestamp(valid_until)).execute(&mut *transaction).await.map_err(unavailable)?;
        let final_database_time = database_now(&mut transaction).await?;
        let final_time = self.current.clock.now();
        if final_time < prepared_at
            || final_database_time < database_time
            || (authorized && (final_time >= valid_until || final_database_time >= valid_until))
        {
            return Err(ApprovalProducerError::Stale);
        }
        transaction.commit().await.map_err(unavailable)?;
        if !authorized {
            return Err(ApprovalProducerError::AccessDenied);
        }
        Ok(RepresentationAuthorityRecord {
            pin: self.current.configuration.pin.clone(),
            binding: binding.clone(),
            state: RepresentationAuthorityState::Authorized,
            asserted_at: observed_at,
            observed_at: final_database_time,
            valid_until,
        })
    }
}

#[derive(Clone)]
pub struct OrganizationRepresentationAuthorityProvider {
    current: CurrentOrganizationAuthority,
    pool: PgPool,
}
#[async_trait]
impl RepresentationAuthorityProvider for OrganizationRepresentationAuthorityProvider {
    async fn resolve_authority(
        &self,
        lookup: ConsentEvidenceLookup<'_>,
    ) -> Result<RepresentationAuthorityRecord, ConsentProviderError> {
        if lookup.pin != &self.current.configuration.pin {
            return Err(ConsentProviderError::Invalid);
        }
        let user_id = self
            .current
            .check_binding(lookup.binding)
            .map_err(provider_error)?;
        let grant = load_grant(
            &self.pool,
            lookup.binding.organization_id,
            lookup.binding.grant_id,
        )
        .await
        .map_err(provider_error)?;
        self.current
            .configuration
            .check_grant(&grant)
            .map_err(provider_error)?;
        if grant.terms_digest != lookup.binding.terms_digest
            || grant.terms.grantor != lookup.binding.grantor
        {
            return Err(ConsentProviderError::Invalid);
        }
        let observation = self
            .current
            .check_actor(user_id, ORGANIZATION_DELEGATION_APPROVE_PERMISSION)
            .await
            .map_err(provider_error)?;
        let mut record = PgConsentEvidenceProvider::new(self.pool.clone())
            .resolve_authority(lookup)
            .await?;
        let provenance: bool = sqlx::query_scalar("SELECT EXISTS (
            SELECT 1 FROM delegated_authority_service.organization_authority_observations o
            JOIN delegated_authority_service.representation_authority_assertions a
              ON a.organization_id=o.organization_id AND a.authority_evidence_ref=o.authority_evidence_ref AND a.revision=o.revision
            WHERE o.organization_id=$1 AND o.authority_evidence_ref=$2 AND o.user_id=$3
              AND o.authorized=true AND o.member_id=$4 AND o.observed_at=$5 AND o.valid_until=$6
              AND o.revision=(SELECT max(revision) FROM delegated_authority_service.representation_authority_assertions
                WHERE organization_id=$1 AND authority_evidence_ref=$2))")
            .bind(lookup.binding.organization_id).bind(&lookup.binding.authority_evidence_ref).bind(user_id).bind(observation.member_id)
            .bind(timestamp(record.asserted_at)).bind(timestamp(record.valid_until)).fetch_one(&self.pool).await.map_err(|_| ConsentProviderError::Unavailable)?;
        observation
            .check(self.current.clock.now())
            .map_err(provider_error)?;
        if !provenance || record.state != RepresentationAuthorityState::Authorized {
            return Err(ConsentProviderError::Invalid);
        }
        // Existing durable assertion time remains unchanged. The additional
        // live Organization observation can only shorten its authority horizon.
        record.valid_until = record.valid_until.min(observation.valid_until);
        if record.valid_until <= self.current.clock.now() {
            return Err(ConsentProviderError::Invalid);
        }
        Ok(record)
    }
}

fn parse_time(text: String) -> Result<DateTime<Utc>, ApprovalProducerError> {
    DateTime::parse_from_rfc3339(&text)
        .map(|v| v.with_timezone(&Utc))
        .map_err(unavailable)
}
fn unavailable(_: impl std::fmt::Debug) -> ApprovalProducerError {
    ApprovalProducerError::Unavailable
}
fn provider_error(error: ApprovalProducerError) -> ConsentProviderError {
    match error {
        ApprovalProducerError::Unavailable | ApprovalProducerError::NotReady => {
            ConsentProviderError::Unavailable
        }
        _ => ConsentProviderError::Invalid,
    }
}
