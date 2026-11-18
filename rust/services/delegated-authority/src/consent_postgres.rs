//! Durable providers for a configured trusted consent/authority producer.
//!
//! Separate writer credentials from the lifecycle runtime's SELECT-only pool.
//! Writing a record is a trusted producer operation after explicit authenticated
//! confirmation or an independent authority check; it is not a request-body
//! admission API. No type in this module deserializes public evidence JSON.
//! Read from the authoritative database, not an asynchronously replicated cache.

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;
use sqlx::{postgres::PgRow, PgPool, Row};
use uuid::Uuid;

use crate::{
    consent::{valid_digest, valid_time, valid_version},
    domain::valid_uri,
    ApprovalAdapterPin, ConsentEvidenceBinding, ConsentEvidenceLookup, ConsentProviderError,
    ConsentRecord, ConsentRecordProvider, ConsentRecordState, RepresentationAuthorityProvider,
    RepresentationAuthorityRecord, RepresentationAuthorityState, MAX_GRANT_REVISION,
};

#[derive(Clone)]
pub struct PgConsentEvidenceProvider {
    pool: PgPool,
}

impl PgConsentEvidenceProvider {
    /// The runtime role only needs SELECT on the four evidence tables. Every
    /// observation reads current withdrawal/revocation state from the primary.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ConsentRecordProvider for PgConsentEvidenceProvider {
    async fn resolve_consent(
        &self,
        lookup: ConsentEvidenceLookup<'_>,
    ) -> Result<ConsentRecord, ConsentProviderError> {
        let row = sqlx::query(
            "SELECT c.organization_id,c.grant_id,c.terms_digest,c.grantor,c.subject,c.issuer,
                    c.evidence_ref,c.authority_evidence_ref,c.profile,c.adapter_version,c.artifact_digest,
                    c.confirmed_at,c.valid_until,(w.evidence_ref IS NOT NULL) AS withdrawn,
                    statement_timestamp() AS observed_at
             FROM delegated_authority_service.consent_confirmations c
             LEFT JOIN delegated_authority_service.consent_withdrawals w
               ON w.organization_id=c.organization_id AND w.evidence_ref=c.evidence_ref
             WHERE c.organization_id=$1 AND c.evidence_ref=$2",
        )
        .bind(lookup.binding.organization_id)
        .bind(&lookup.binding.evidence_ref)
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?
        .ok_or(ConsentProviderError::NotFound)?;
        let (pin, binding) = decode_source(&row)?;
        if &pin != lookup.pin || &binding != lookup.binding {
            return Err(ConsentProviderError::Invalid);
        }
        Ok(ConsentRecord {
            pin,
            binding,
            state: if row.try_get::<bool, _>("withdrawn").map_err(invalid)? {
                ConsentRecordState::Withdrawn
            } else {
                ConsentRecordState::Confirmed
            },
            confirmed_at: decode_time(&row, "confirmed_at")?,
            observed_at: row.try_get("observed_at").map_err(invalid)?,
            valid_until: decode_time(&row, "valid_until")?,
        })
    }
}

#[async_trait]
impl RepresentationAuthorityProvider for PgConsentEvidenceProvider {
    async fn resolve_authority(
        &self,
        lookup: ConsentEvidenceLookup<'_>,
    ) -> Result<RepresentationAuthorityRecord, ConsentProviderError> {
        let row = sqlx::query(
            "SELECT s.organization_id,s.grant_id,s.terms_digest,s.grantor,s.subject,s.issuer,
                    s.evidence_ref,s.authority_evidence_ref,s.profile,s.adapter_version,s.artifact_digest,
                    a.state,a.asserted_at,a.valid_until,statement_timestamp() AS observed_at
             FROM delegated_authority_service.representation_authority_sources s
             JOIN LATERAL (
                 SELECT state,asserted_at,valid_until
                 FROM delegated_authority_service.representation_authority_assertions
                 WHERE organization_id=s.organization_id AND authority_evidence_ref=s.authority_evidence_ref
                 ORDER BY revision DESC LIMIT 1
             ) a ON true
             WHERE s.organization_id=$1 AND s.authority_evidence_ref=$2",
        )
        .bind(lookup.binding.organization_id)
        .bind(&lookup.binding.authority_evidence_ref)
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?
        .ok_or(ConsentProviderError::NotFound)?;
        let (pin, binding) = decode_source(&row)?;
        if &pin != lookup.pin || &binding != lookup.binding {
            return Err(ConsentProviderError::Invalid);
        }
        Ok(RepresentationAuthorityRecord {
            pin,
            binding,
            state: match row.try_get::<String, _>("state").map_err(invalid)?.as_str() {
                "AUTHORIZED" => RepresentationAuthorityState::Authorized,
                "REVOKED" => RepresentationAuthorityState::Revoked,
                _ => return Err(ConsentProviderError::Invalid),
            },
            asserted_at: decode_time(&row, "asserted_at")?,
            observed_at: row.try_get("observed_at").map_err(invalid)?,
            valid_until: decode_time(&row, "valid_until")?,
        })
    }
}

/// Constructed only by a configured trusted approval-surface adapter after an
/// explicit authenticated confirmation. Identifiers/digests alone prove nothing.
#[derive(Clone, Debug)]
pub struct ConfirmedConsentInput {
    pub pin: ApprovalAdapterPin,
    pub binding: ConsentEvidenceBinding,
    pub confirmed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

/// Constructed by an independent trusted authority adapter after checking the
/// grantor's current authority over the subject and exact bound grant terms.
#[derive(Clone, Debug)]
pub struct RepresentationAuthorityInput {
    pub pin: ApprovalAdapterPin,
    pub binding: ConsentEvidenceBinding,
    pub asserted_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConsentStoreError {
    #[error("trusted evidence producer input is invalid")]
    InvalidInput,
    #[error("trusted evidence source was not found")]
    NotFound,
    #[error("trusted evidence source already exists")]
    AlreadyExists,
    #[error("trusted evidence revision or state conflict")]
    RevisionConflict,
    #[error("trusted evidence database is unavailable")]
    Unavailable,
}

#[derive(Clone)]
pub struct PgTrustedConsentWriter {
    pool: PgPool,
}

impl PgTrustedConsentWriter {
    /// Use a separately authorized trusted producer pool. Never give this pool
    /// or its INSERT privileges to the managed lifecycle request handler.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn record_consent(
        &self,
        input: ConfirmedConsentInput,
    ) -> Result<(), ConsentStoreError> {
        validate_input(
            &input.pin,
            &input.binding,
            input.confirmed_at,
            input.valid_until,
        )?;
        sqlx::query(
            "INSERT INTO delegated_authority_service.consent_confirmations
             (organization_id,evidence_ref,authority_evidence_ref,grant_id,terms_digest,
              grantor,subject,issuer,profile,adapter_version,artifact_digest,confirmed_at,valid_until)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
        )
        .bind(input.binding.organization_id)
        .bind(&input.binding.evidence_ref)
        .bind(&input.binding.authority_evidence_ref)
        .bind(input.binding.grant_id)
        .bind(&input.binding.terms_digest)
        .bind(principal_value(&input.binding.grantor)?)
        .bind(principal_value(&input.binding.subject)?)
        .bind(principal_value(&input.binding.issuer)?)
        .bind(input.pin.profile)
        .bind(input.pin.version)
        .bind(input.pin.artifact_digest)
        .bind(timestamp(input.confirmed_at))
        .bind(timestamp(input.valid_until))
        .execute(&self.pool)
        .await
        .map_err(store_error)?;
        Ok(())
    }

    /// Records a terminal withdrawal once. A duplicate does not rewrite the
    /// original event or restore the confirmation; it returns AlreadyExists.
    pub async fn withdraw_consent(
        &self,
        organization_id: Uuid,
        evidence_ref: &str,
    ) -> Result<(), ConsentStoreError> {
        if !valid_uri(Some(evidence_ref)) {
            return Err(ConsentStoreError::InvalidInput);
        }
        sqlx::query(
            "INSERT INTO delegated_authority_service.consent_withdrawals (organization_id,evidence_ref)
             VALUES ($1,$2)",
        )
        .bind(organization_id)
        .bind(evidence_ref)
        .execute(&self.pool)
        .await
        .map_err(store_error)?;
        Ok(())
    }

    pub async fn record_authority(
        &self,
        input: RepresentationAuthorityInput,
    ) -> Result<(), ConsentStoreError> {
        validate_input(
            &input.pin,
            &input.binding,
            input.asserted_at,
            input.valid_until,
        )?;
        let mut transaction = self.pool.begin().await.map_err(store_error)?;
        sqlx::query(
            "INSERT INTO delegated_authority_service.representation_authority_sources
             (organization_id,authority_evidence_ref,evidence_ref,grant_id,terms_digest,
              grantor,subject,issuer,profile,adapter_version,artifact_digest)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(input.binding.organization_id)
        .bind(&input.binding.authority_evidence_ref)
        .bind(&input.binding.evidence_ref)
        .bind(input.binding.grant_id)
        .bind(&input.binding.terms_digest)
        .bind(principal_value(&input.binding.grantor)?)
        .bind(principal_value(&input.binding.subject)?)
        .bind(principal_value(&input.binding.issuer)?)
        .bind(input.pin.profile)
        .bind(input.pin.version)
        .bind(input.pin.artifact_digest)
        .execute(&mut *transaction)
        .await
        .map_err(store_error)?;
        sqlx::query(
            "INSERT INTO delegated_authority_service.representation_authority_assertions
             (organization_id,authority_evidence_ref,revision,state,asserted_at,valid_until)
             VALUES ($1,$2,1,'AUTHORIZED',$3,$4)",
        )
        .bind(input.binding.organization_id)
        .bind(input.binding.authority_evidence_ref)
        .bind(timestamp(input.asserted_at))
        .bind(timestamp(input.valid_until))
        .execute(&mut *transaction)
        .await
        .map_err(store_error)?;
        transaction.commit().await.map_err(store_error)
    }

    /// Appends a new independent authority check under the same immutable
    /// reference/binding. Reading the source never performs this renewal.
    pub async fn refresh_authority(
        &self,
        organization_id: Uuid,
        authority_evidence_ref: &str,
        expected_revision: u64,
        asserted_at: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<(), ConsentStoreError> {
        validate_revision_and_time(
            authority_evidence_ref,
            expected_revision,
            asserted_at,
            valid_until,
        )?;
        sqlx::query(
            "INSERT INTO delegated_authority_service.representation_authority_assertions
             (organization_id,authority_evidence_ref,revision,state,asserted_at,valid_until)
             VALUES ($1,$2,$3,'AUTHORIZED',$4,$5)",
        )
        .bind(organization_id)
        .bind(authority_evidence_ref)
        .bind((expected_revision + 1) as i64)
        .bind(timestamp(asserted_at))
        .bind(timestamp(valid_until))
        .execute(&self.pool)
        .await
        .map_err(assertion_error)?;
        Ok(())
    }

    /// Revocation is terminal and uses database time. No source body supplies
    /// the withdrawal timestamp or revives an older authorized revision.
    pub async fn revoke_authority(
        &self,
        organization_id: Uuid,
        authority_evidence_ref: &str,
        expected_revision: u64,
    ) -> Result<(), ConsentStoreError> {
        if !valid_uri(Some(authority_evidence_ref))
            || !(1..MAX_GRANT_REVISION).contains(&expected_revision)
        {
            return Err(ConsentStoreError::InvalidInput);
        }
        let result = sqlx::query(
            "INSERT INTO delegated_authority_service.representation_authority_assertions
             (organization_id,authority_evidence_ref,revision,state,asserted_at,valid_until)
             SELECT organization_id,authority_evidence_ref,$3,'REVOKED',
                    to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),valid_until
             FROM delegated_authority_service.representation_authority_assertions
             WHERE organization_id=$1 AND authority_evidence_ref=$2 AND revision=$4",
        )
        .bind(organization_id)
        .bind(authority_evidence_ref)
        .bind((expected_revision + 1) as i64)
        .bind(expected_revision as i64)
        .execute(&self.pool)
        .await
        .map_err(assertion_error)?;
        if result.rows_affected() != 1 {
            return Err(ConsentStoreError::NotFound);
        }
        Ok(())
    }
}

fn validate_input(
    pin: &ApprovalAdapterPin,
    binding: &ConsentEvidenceBinding,
    issued: DateTime<Utc>,
    deadline: DateTime<Utc>,
) -> Result<(), ConsentStoreError> {
    if !valid_uri(Some(&pin.profile))
        || pin.profile.len() > 512
        || !valid_version(&pin.version)
        || !valid_digest(&pin.artifact_digest)
        || !valid_digest(&binding.terms_digest)
        || [
            &binding.grantor.id,
            &binding.subject.id,
            &binding.issuer.id,
            &binding.evidence_ref,
            &binding.authority_evidence_ref,
        ]
        .into_iter()
        .any(|uri| !valid_uri(Some(uri)))
        || !valid_time(issued)
        || !valid_time(deadline)
        || issued >= deadline
    {
        return Err(ConsentStoreError::InvalidInput);
    }
    Ok(())
}

fn validate_revision_and_time(
    reference: &str,
    revision: u64,
    issued: DateTime<Utc>,
    deadline: DateTime<Utc>,
) -> Result<(), ConsentStoreError> {
    if !valid_uri(Some(reference))
        || !(1..MAX_GRANT_REVISION).contains(&revision)
        || !valid_time(issued)
        || !valid_time(deadline)
        || issued >= deadline
    {
        return Err(ConsentStoreError::InvalidInput);
    }
    Ok(())
}

fn timestamp(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

fn principal_value(principal: &crate::Principal) -> Result<Value, ConsentStoreError> {
    serde_json::to_value(principal).map_err(|_| ConsentStoreError::InvalidInput)
}

fn decode_source(
    row: &PgRow,
) -> Result<(ApprovalAdapterPin, ConsentEvidenceBinding), ConsentProviderError> {
    let principal = |column: &str| -> Result<crate::Principal, ConsentProviderError> {
        serde_json::from_value(row.try_get::<Value, _>(column).map_err(invalid)?)
            .map_err(|_| ConsentProviderError::Invalid)
    };
    let pin = ApprovalAdapterPin {
        profile: row.try_get("profile").map_err(invalid)?,
        version: row.try_get("adapter_version").map_err(invalid)?,
        artifact_digest: row.try_get("artifact_digest").map_err(invalid)?,
    };
    let binding = ConsentEvidenceBinding {
        organization_id: row.try_get("organization_id").map_err(invalid)?,
        grant_id: row.try_get("grant_id").map_err(invalid)?,
        terms_digest: row.try_get("terms_digest").map_err(invalid)?,
        grantor: principal("grantor")?,
        subject: principal("subject")?,
        issuer: principal("issuer")?,
        evidence_ref: row.try_get("evidence_ref").map_err(invalid)?,
        authority_evidence_ref: row.try_get("authority_evidence_ref").map_err(invalid)?,
    };
    if !valid_uri(Some(&pin.profile))
        || pin.profile.len() > 512
        || !valid_version(&pin.version)
        || !valid_digest(&pin.artifact_digest)
        || !valid_digest(&binding.terms_digest)
        || [
            &binding.grantor.id,
            &binding.subject.id,
            &binding.issuer.id,
            &binding.evidence_ref,
            &binding.authority_evidence_ref,
        ]
        .into_iter()
        .any(|uri| !valid_uri(Some(uri)))
    {
        return Err(ConsentProviderError::Invalid);
    }
    Ok((pin, binding))
}

fn decode_time(row: &PgRow, column: &str) -> Result<DateTime<Utc>, ConsentProviderError> {
    let text: String = row.try_get(column).map_err(invalid)?;
    let time = DateTime::parse_from_rfc3339(&text)
        .map_err(|_| ConsentProviderError::Invalid)?
        .with_timezone(&Utc);
    if !valid_time(time) {
        return Err(ConsentProviderError::Invalid);
    }
    Ok(time)
}
fn invalid(_: sqlx::Error) -> ConsentProviderError {
    ConsentProviderError::Invalid
}
fn unavailable(_: sqlx::Error) -> ConsentProviderError {
    ConsentProviderError::Unavailable
}
fn store_error(error: sqlx::Error) -> ConsentStoreError {
    if let sqlx::Error::Database(database) = &error {
        return match database.code().as_deref() {
            Some("23505") => ConsentStoreError::AlreadyExists,
            Some("23503" | "P0002") => ConsentStoreError::NotFound,
            Some("23514" | "22007" | "22008") => ConsentStoreError::InvalidInput,
            Some("40001") => ConsentStoreError::RevisionConflict,
            _ => ConsentStoreError::Unavailable,
        };
    }
    ConsentStoreError::Unavailable
}

fn assertion_error(error: sqlx::Error) -> ConsentStoreError {
    match store_error(error) {
        ConsentStoreError::AlreadyExists => ConsentStoreError::RevisionConflict,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_support::pending_grant, ApprovalEvidence, ConfiguredConsentEvidenceVerifier,
        ConsentProfileConfiguration, DelegationAuthorityService, DelegationGrant,
        DelegationGrantRepository, GrantStatus, PgDelegationGrantRepository, PrincipalType,
        ServiceError,
    };
    use chrono::Duration;
    use std::sync::Arc;

    fn pin() -> ApprovalAdapterPin {
        ApprovalAdapterPin {
            profile: "urn:example:trusted-delegation-approval:v1".into(),
            version: "1.0.0".into(),
            artifact_digest: format!("sha256:{}", "a".repeat(64)),
        }
    }

    fn bindings(grant: &DelegationGrant) -> ConsentEvidenceBinding {
        ConsentEvidenceBinding {
            organization_id: grant.organization_id,
            grant_id: grant.id,
            terms_digest: grant.terms_digest.clone(),
            grantor: grant.terms.grantor.clone(),
            subject: grant.terms.subject.clone(),
            issuer: grant.authority.issuer.clone(),
            evidence_ref: format!("urn:example:consent:{}", Uuid::new_v4()),
            authority_evidence_ref: format!("urn:example:authority:{}", Uuid::new_v4()),
        }
    }

    fn evidence(binding: &ConsentEvidenceBinding) -> ApprovalEvidence {
        ApprovalEvidence {
            profile: pin().profile,
            evidence_ref: binding.evidence_ref.clone(),
            authority_evidence_ref: binding.authority_evidence_ref.clone(),
        }
    }

    fn lookup<'a>(
        pin: &'a ApprovalAdapterPin,
        binding: &'a ConsentEvidenceBinding,
    ) -> ConsentEvidenceLookup<'a> {
        ConsentEvidenceLookup { pin, binding }
    }

    fn consent_input(
        grant: &DelegationGrant,
        binding: &ConsentEvidenceBinding,
    ) -> ConfirmedConsentInput {
        ConfirmedConsentInput {
            pin: pin(),
            binding: binding.clone(),
            confirmed_at: Utc::now(),
            valid_until: grant.terms.valid_until,
        }
    }

    fn authority_input(
        grant: &DelegationGrant,
        binding: &ConsentEvidenceBinding,
    ) -> RepresentationAuthorityInput {
        RepresentationAuthorityInput {
            pin: pin(),
            binding: binding.clone(),
            asserted_at: Utc::now(),
            valid_until: grant.terms.valid_until,
        }
    }

    #[tokio::test]
    async fn postgres_trusted_consent_activates_and_revocation_is_terminal() {
        let Ok(url) = std::env::var("DELEGATED_AUTHORITY_TEST_DATABASE_URL") else {
            return;
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        let repository = Arc::new(PgDelegationGrantRepository::new(pool.clone()));
        repository.migrate().await.unwrap();
        repository.readiness().await.unwrap();
        let provider = Arc::new(PgConsentEvidenceProvider::new(pool.clone()));
        let writer = PgTrustedConsentWriter::new(pool.clone());
        let verifier = Arc::new(
            ConfiguredConsentEvidenceVerifier::new(
                [ConsentProfileConfiguration {
                    pin: pin(),
                    max_observation_age_seconds: 60,
                    max_confirmation_age_seconds: 120,
                    max_authority_age_seconds: 60,
                }],
                provider.clone(),
                provider.clone(),
            )
            .unwrap(),
        );
        let template = pending_grant();
        let service = DelegationAuthorityService::new(
            repository.clone(),
            verifier,
            template.authority.clone(),
        )
        .unwrap();
        let mut terms = template.terms.clone();
        terms.valid_from = Utc::now() - Duration::minutes(1);
        terms.valid_until = Utc::now() + Duration::hours(2);
        let grant = service
            .propose(Uuid::new_v4(), terms.clone())
            .await
            .unwrap();
        let binding = bindings(&grant);
        let installed = pin();
        let confirmation = consent_input(&grant, &binding);
        writer.record_consent(confirmation.clone()).await.unwrap();
        assert_eq!(
            writer.record_consent(confirmation.clone()).await,
            Err(ConsentStoreError::AlreadyExists)
        );
        assert!(matches!(
            service
                .approve(
                    grant.organization_id,
                    grant.id,
                    1,
                    &grant.terms.grantor,
                    evidence(&binding)
                )
                .await,
            Err(ServiceError::ConsentNotVerified)
        ));
        assert_eq!(
            repository
                .audit(grant.organization_id, grant.id)
                .await
                .unwrap()
                .len(),
            1
        );

        // The authority source is independent even for self-delegation.
        let original_authority = authority_input(&grant, &binding);
        writer
            .record_authority(original_authority.clone())
            .await
            .unwrap();
        let active = service
            .approve(
                grant.organization_id,
                grant.id,
                1,
                &grant.terms.grantor,
                evidence(&binding),
            )
            .await
            .unwrap();
        assert_eq!(active.status, GrantStatus::Active);
        assert_eq!(
            service
                .resolve(grant.organization_id, grant.id)
                .await
                .unwrap(),
            active
        );
        let journal = repository
            .audit(grant.organization_id, grant.id)
            .await
            .unwrap();
        assert_eq!(journal.len(), 2);
        let consent = provider
            .resolve_consent(lookup(&installed, &binding))
            .await
            .unwrap();
        assert_eq!(consent.confirmed_at, confirmation.confirmed_at);
        assert!(consent.observed_at >= consent.confirmed_at);
        let first = provider
            .resolve_authority(lookup(&installed, &binding))
            .await
            .unwrap();
        let second = provider
            .resolve_authority(lookup(&installed, &binding))
            .await
            .unwrap();
        assert_eq!(first.asserted_at, original_authority.asserted_at);
        assert_eq!(second.asserted_at, first.asserted_at);
        assert!(second.observed_at >= first.observed_at);

        let mut outsider = binding.clone();
        outsider.organization_id = Uuid::new_v4();
        assert_eq!(
            provider
                .resolve_consent(lookup(&installed, &outsider))
                .await,
            Err(ConsentProviderError::NotFound)
        );
        assert_eq!(
            provider
                .resolve_authority(lookup(&installed, &outsider))
                .await,
            Err(ConsentProviderError::NotFound)
        );
        let mut substituted_pin = installed.clone();
        substituted_pin.artifact_digest = format!("sha256:{}", "b".repeat(64));
        assert_eq!(
            provider
                .resolve_consent(lookup(&substituted_pin, &binding))
                .await,
            Err(ConsentProviderError::Invalid)
        );
        let mut substituted = confirmation.clone();
        substituted.binding.grantor.principal_type = PrincipalType::External;
        substituted.binding.evidence_ref = format!("urn:example:consent:{}", Uuid::new_v4());
        assert_eq!(
            writer.record_consent(substituted).await,
            Err(ConsentStoreError::InvalidInput)
        );

        // Confirmation withdrawal changes current evidence, not grant history.
        writer
            .withdraw_consent(grant.organization_id, &binding.evidence_ref)
            .await
            .unwrap();
        assert_eq!(
            writer
                .withdraw_consent(grant.organization_id, &binding.evidence_ref)
                .await,
            Err(ConsentStoreError::AlreadyExists)
        );
        assert_eq!(
            provider
                .resolve_consent(lookup(&installed, &binding))
                .await
                .unwrap()
                .state,
            ConsentRecordState::Withdrawn
        );
        assert!(matches!(
            service.resolve(grant.organization_id, grant.id).await,
            Err(ServiceError::ConsentNotVerified)
        ));
        assert_eq!(
            repository
                .get(grant.organization_id, grant.id)
                .await
                .unwrap(),
            Some(active)
        );
        assert_eq!(
            repository
                .audit(grant.organization_id, grant.id)
                .await
                .unwrap(),
            journal
        );

        // Renewal is a new explicit trusted authority assertion. It cannot
        // modify the source binding, reuse a stale revision or erase history.
        let refreshed_at = Utc::now();
        writer
            .refresh_authority(
                grant.organization_id,
                &binding.authority_evidence_ref,
                1,
                refreshed_at,
                grant.terms.valid_until,
            )
            .await
            .unwrap();
        assert_eq!(
            provider
                .resolve_authority(lookup(&installed, &binding))
                .await
                .unwrap()
                .asserted_at,
            refreshed_at
        );
        let next_time = Utc::now();
        let (left, right) = tokio::join!(
            writer.refresh_authority(
                grant.organization_id,
                &binding.authority_evidence_ref,
                2,
                next_time,
                grant.terms.valid_until
            ),
            writer.refresh_authority(
                grant.organization_id,
                &binding.authority_evidence_ref,
                2,
                next_time,
                grant.terms.valid_until
            ),
        );
        assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
        let loser = if left.is_err() { left } else { right };
        assert_eq!(loser, Err(ConsentStoreError::RevisionConflict));
        writer
            .revoke_authority(grant.organization_id, &binding.authority_evidence_ref, 3)
            .await
            .unwrap();
        assert_eq!(
            provider
                .resolve_authority(lookup(&installed, &binding))
                .await
                .unwrap()
                .state,
            RepresentationAuthorityState::Revoked
        );
        assert_eq!(
            writer
                .refresh_authority(
                    grant.organization_id,
                    &binding.authority_evidence_ref,
                    4,
                    Utc::now(),
                    grant.terms.valid_until
                )
                .await,
            Err(ConsentStoreError::RevisionConflict)
        );
        let assertions: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM delegated_authority_service.representation_authority_assertions WHERE organization_id=$1 AND authority_evidence_ref=$2",
        ).bind(grant.organization_id).bind(&binding.authority_evidence_ref).fetch_one(&pool).await.unwrap();
        assert_eq!(assertions, 4);

        // A different represented subject also requires its own current proof;
        // confirmed consent alone never grants that representation authority.
        terms.subject.id = "urn:example:represented:other".into();
        let represented = service.propose(Uuid::new_v4(), terms).await.unwrap();
        let represented_binding = bindings(&represented);
        writer
            .record_consent(consent_input(&represented, &represented_binding))
            .await
            .unwrap();
        assert!(matches!(
            service
                .approve(
                    represented.organization_id,
                    represented.id,
                    1,
                    &represented.terms.grantor,
                    evidence(&represented_binding)
                )
                .await,
            Err(ServiceError::ConsentNotVerified)
        ));
        assert_eq!(
            repository
                .get(represented.organization_id, represented.id)
                .await
                .unwrap(),
            Some(represented)
        );

        restricted_roles_cannot_fabricate_authority(&pool, &binding).await;
        for sql in [
            "UPDATE delegated_authority_service.consent_confirmations SET confirmed_at=confirmed_at",
            "DELETE FROM delegated_authority_service.consent_withdrawals",
            "TRUNCATE delegated_authority_service.representation_authority_sources CASCADE",
        ] {
            let mut tx = pool.begin().await.unwrap();
            let result = sqlx::query(sql).execute(&mut *tx).await;
            tx.rollback().await.unwrap();
            assert!(matches!(result, Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("P0001")));
        }
        pool.close().await;
    }

    async fn restricted_roles_cannot_fabricate_authority(
        pool: &PgPool,
        binding: &ConsentEvidenceBinding,
    ) {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SELECT set_config('marty.consent_reader_test',$1,true),set_config('marty.consent_writer_test',$2,true)")
            .bind(format!("consent_reader_{}", Uuid::new_v4().simple()))
            .bind(format!("consent_writer_{}", Uuid::new_v4().simple()))
            .execute(&mut *tx).await.unwrap();
        sqlx::raw_sql(
            "DO $roles$
             DECLARE reader TEXT:=current_setting('marty.consent_reader_test'); producer TEXT:=current_setting('marty.consent_writer_test');
             BEGIN
                 EXECUTE format('CREATE ROLE %I NOLOGIN',reader);
                 EXECUTE format('CREATE ROLE %I NOLOGIN',producer);
                 EXECUTE format('GRANT USAGE ON SCHEMA delegated_authority_service TO %I,%I',reader,producer);
                 EXECUTE format('GRANT SELECT ON delegated_authority_service.consent_confirmations,delegated_authority_service.consent_withdrawals,delegated_authority_service.representation_authority_sources,delegated_authority_service.representation_authority_assertions TO %I',reader);
                 EXECUTE format('GRANT SELECT,INSERT ON delegated_authority_service.consent_confirmations,delegated_authority_service.consent_withdrawals TO %I',producer);
                 EXECUTE format('GRANT EXECUTE ON FUNCTION delegated_authority_service.grant_instant(TEXT) TO %I',producer);
                 EXECUTE format('SET LOCAL ROLE %I',reader);
             END $roles$;",
        ).execute(&mut *tx).await.unwrap();
        let readable: i64 = sqlx::query_scalar("SELECT count(*) FROM delegated_authority_service.consent_confirmations WHERE organization_id=$1 AND evidence_ref=$2")
            .bind(binding.organization_id).bind(&binding.evidence_ref).fetch_one(&mut *tx).await.unwrap();
        assert_eq!(readable, 1);
        for sql in [
            "INSERT INTO delegated_authority_service.consent_withdrawals (organization_id,evidence_ref) VALUES ($1,$2)",
            "INSERT INTO delegated_authority_service.representation_authority_assertions (organization_id,authority_evidence_ref,revision,state,asserted_at,valid_until) VALUES ($1,$2,5,'AUTHORIZED','2026-01-01T00:00:00Z','2027-01-01T00:00:00Z')",
        ] {
            sqlx::query("SAVEPOINT denied_source_write").execute(&mut *tx).await.unwrap();
            let result = sqlx::query(sql).bind(binding.organization_id).bind(&binding.evidence_ref).execute(&mut *tx).await;
            sqlx::query("ROLLBACK TO SAVEPOINT denied_source_write").execute(&mut *tx).await.unwrap();
            assert!(matches!(result, Err(sqlx::Error::Database(error)) if error.code().as_deref()==Some("42501")));
        }
        sqlx::raw_sql("RESET ROLE; DO $role$ BEGIN EXECUTE format('SET LOCAL ROLE %I',current_setting('marty.consent_writer_test')); END $role$;")
            .execute(&mut *tx).await.unwrap();
        sqlx::query(
            "INSERT INTO delegated_authority_service.consent_confirmations
             (organization_id,evidence_ref,authority_evidence_ref,grant_id,terms_digest,grantor,subject,issuer,profile,adapter_version,artifact_digest,confirmed_at,valid_until)
             SELECT organization_id,$3,authority_evidence_ref,grant_id,terms_digest,grantor,subject,issuer,profile,adapter_version,artifact_digest,confirmed_at,valid_until
             FROM delegated_authority_service.consent_confirmations WHERE organization_id=$1 AND evidence_ref=$2",
        ).bind(binding.organization_id).bind(&binding.evidence_ref)
            .bind(format!("urn:example:permission-test:{}",Uuid::new_v4())).execute(&mut *tx).await.unwrap();
        sqlx::query("SAVEPOINT denied_authority_write")
            .execute(&mut *tx)
            .await
            .unwrap();
        let result = sqlx::query("INSERT INTO delegated_authority_service.representation_authority_assertions (organization_id,authority_evidence_ref,revision,state,asserted_at,valid_until) VALUES ($1,$2,5,'AUTHORIZED','2026-01-01T00:00:00Z','2027-01-01T00:00:00Z')")
            .bind(binding.organization_id).bind(&binding.authority_evidence_ref).execute(&mut *tx).await;
        sqlx::query("ROLLBACK TO SAVEPOINT denied_authority_write")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        assert!(
            matches!(result, Err(sqlx::Error::Database(error)) if error.code().as_deref()==Some("42501"))
        );
    }
}
