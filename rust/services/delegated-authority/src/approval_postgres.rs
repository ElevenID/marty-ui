//! Durable review/confirmation producer and read-only P03 confirmation lookup.
//! No mutation here activates a grant. Consent and its exact review/session
//! index commit together. Authority is independently produced using another
//! credential; an orphan authority observation confers no consent or activation.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgRow, PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{
    consent::valid_digest, decode_grant_snapshot, ApprovalConfirmation, ApprovalEvidence,
    ApprovalProducerError, ApprovalReview, ApprovalWithdrawal, AuthenticatedApprovalSession,
    CommandGrantReference, ConsentEvidenceBinding, DelegationClock, DelegationCommandCaller,
    DelegationConfirmationError, DelegationConfirmationSource, DelegationGrant,
    ExplicitApprovalConfirmation, OrganizationApprovalConfiguration, PgDelegationGrantRepository,
    PgOrganizationAuthorityProducer, MAX_GRANT_REVISION,
    ORGANIZATION_DELEGATION_APPROVE_PERMISSION, ORGANIZATION_DELEGATION_VIEW_PERMISSION,
};

#[derive(Clone)]
pub struct PgOrganizationApprovalService {
    read_pool: PgPool,
    consent_pool: PgPool,
    authority: Arc<PgOrganizationAuthorityProducer>,
    configuration: OrganizationApprovalConfiguration,
    clock: Arc<dyn DelegationClock>,
}

impl PgOrganizationApprovalService {
    pub fn new(
        runtime_read_pool: PgPool,
        consent_writer_pool: PgPool,
        authority: Arc<PgOrganizationAuthorityProducer>,
        configuration: OrganizationApprovalConfiguration,
        clock: Arc<dyn DelegationClock>,
    ) -> Result<Self, ApprovalProducerError> {
        if authority.current.configuration.organization_id != configuration.organization_id
            || authority.current.configuration.pin != configuration.pin
            || authority.current.configuration.issuer != configuration.issuer
            || authority.current.configuration.authority_validity_seconds
                != configuration.authority_validity_seconds
        {
            return Err(ApprovalProducerError::InvalidInput);
        }
        Ok(Self {
            read_pool: runtime_read_pool,
            consent_pool: consent_writer_pool,
            authority,
            configuration,
            clock,
        })
    }

    pub async fn readiness(&self) -> Result<(), ApprovalProducerError> {
        PgDelegationGrantRepository::new(self.read_pool.clone())
            .readiness()
            .await
            .map_err(|_| ApprovalProducerError::NotReady)?;
        self.authority.readiness().await?;
        let reader = check_role(
            &self.read_pool,
            "delegated_authority_service",
            &[],
            &EVIDENCE_READ_TABLES,
        )
        .await?;
        let consent = check_role(
            &self.consent_pool,
            "delegated_authority_service",
            &CONSENT_WRITE_TABLES,
            &CONSENT_READ_TABLES,
        )
        .await?;
        let authority = role_identity(&self.authority.pool).await?;
        let organization = role_identity(self.authority.current.store.pool()).await?;
        let names = [&reader, &consent, &authority, &organization];
        for (i, name) in names.iter().enumerate() {
            if names.iter().skip(i + 1).any(|other| name == other) {
                return Err(ApprovalProducerError::NotReady);
            }
        }
        // PostgreSQL roles are cluster-wide. Inspect the Organization database
        // for every evidence role that exists there, including grants in a
        // separate database on the same cluster. A separate URL is not a trust
        // boundary if its producer can modify the authoritative source.
        for name in [&reader, &consent, &authority] {
            check_role_boundary(
                self.authority.current.store.pool(),
                "organization_service",
                name,
                &[],
            )
            .await?;
        }
        check_role_boundary(
            &self.read_pool,
            "delegated_authority_service",
            &organization,
            &[],
        )
        .await?;
        let storage_id = storage_identity(&self.read_pool).await?;
        if storage_identity(&self.consent_pool).await? != storage_id
            || storage_identity(&self.authority.pool).await? != storage_id
        {
            return Err(ApprovalProducerError::NotReady);
        }
        let guards: i64 = sqlx::query_scalar("SELECT count(*) FROM (VALUES
            ('approval_reviews','approval_reviews_binding','guard_approval_review',7,true),
            ('approval_reviews','approval_reviews_immutable','reject_lifecycle_event_mutation',27,false),
            ('approval_reviews','approval_reviews_no_truncate','reject_lifecycle_event_mutation',34,false),
            ('approval_confirmation_bindings','approval_confirmation_bindings_guard','guard_approval_confirmation_binding',7,true),
            ('approval_confirmation_bindings','approval_confirmation_bindings_immutable','reject_lifecycle_event_mutation',27,false),
            ('approval_confirmation_bindings','approval_confirmation_bindings_no_truncate','reject_lifecycle_event_mutation',34,false),
            ('organization_authority_observations','organization_authority_observations_guard','guard_organization_authority_observation',7,true),
            ('organization_authority_observations','organization_authority_observations_immutable','reject_lifecycle_event_mutation',27,false),
            ('organization_authority_observations','organization_authority_observations_no_truncate','reject_lifecycle_event_mutation',34,false),
            ('approval_storage_identity','approval_storage_identity_immutable','reject_lifecycle_event_mutation',27,false),
            ('approval_storage_identity','approval_storage_identity_no_truncate','reject_lifecycle_event_mutation',34,false)
          ) expected(table_name,trigger_name,function_name,event_bits,is_definer)
          JOIN pg_namespace n ON n.nspname='delegated_authority_service'
          JOIN pg_class c ON c.relnamespace=n.oid AND c.relname=expected.table_name
          JOIN pg_trigger t ON t.tgrelid=c.oid AND t.tgname=expected.trigger_name
          JOIN pg_proc p ON p.oid=t.tgfoid AND p.pronamespace=n.oid AND p.proname=expected.function_name
          WHERE NOT t.tgisinternal AND t.tgenabled='O' AND t.tgtype=expected.event_bits
            AND t.tgnargs=0 AND t.tgqual IS NULL AND NOT t.tgdeferrable AND NOT t.tginitdeferred
            AND p.prosecdef=expected.is_definer AND p.proconfig=ARRAY['search_path=pg_catalog']::TEXT[]
            AND p.proowner=c.relowner AND c.relowner=n.nspowner")
            .fetch_one(&self.read_pool).await.map_err(not_ready)?;
        if guards != 11 {
            return Err(ApprovalProducerError::NotReady);
        }
        Ok(())
    }

    pub async fn review(
        &self,
        session: &AuthenticatedApprovalSession,
        expected: &CommandGrantReference,
    ) -> Result<ApprovalReview, ApprovalProducerError> {
        let started_at = self.clock.now();
        session.check(self.configuration.organization_id, started_at)?;
        validate_reference(expected)?;
        let access = self
            .authority
            .current
            .check_actor(session.user_id, ORGANIZATION_DELEGATION_APPROVE_PERMISSION)
            .await?;
        let grant = load_grant(&self.read_pool, session.organization_id, expected.id).await?;
        if grant.terms.grantor != session.actor() {
            return Err(ApprovalProducerError::AccessDenied);
        }
        // Authorization precedes expected-revision disclosure.
        self.configuration.check_pending(&grant, self.clock.now())?;
        if grant.revision != expected.revision || grant.terms_digest != expected.terms_digest {
            return Err(ApprovalProducerError::Conflict);
        }
        let created_at = self.clock.now();
        if created_at < started_at || created_at < access.observed_at {
            return Err(ApprovalProducerError::Stale);
        }
        let expires_at = (created_at
            + Duration::seconds(i64::from(self.configuration.review_ttl_seconds)))
        .min(grant.terms.valid_until);
        let review_id = Uuid::new_v4();
        let mut transaction = self.consent_pool.begin().await.map_err(unavailable)?;
        sqlx::query("INSERT INTO delegated_authority_service.approval_reviews
            (organization_id,review_id,grant_id,grant_revision,terms_digest,grant_document,actor_id,session_ref,
             profile,adapter_version,artifact_digest,created_at,expires_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
            .bind(session.organization_id).bind(review_id).bind(grant.id).bind(grant.revision as i64).bind(&grant.terms_digest)
            .bind(serde_json::to_value(&grant).map_err(unavailable)?).bind(session.user_id).bind(&session.session_ref)
            .bind(&self.configuration.pin.profile).bind(&self.configuration.pin.version).bind(&self.configuration.pin.artifact_digest)
            .bind(timestamp(created_at)).bind(timestamp(expires_at)).execute(&mut *transaction).await.map_err(database_error)?;
        let now = self.clock.now();
        let database_time = database_now(&mut transaction).await?;
        if now < created_at || database_time < created_at {
            return Err(ApprovalProducerError::Stale);
        }
        session.check(self.configuration.organization_id, now)?;
        session.check(self.configuration.organization_id, database_time)?;
        access.check(now)?;
        access.check(database_time)?;
        transaction.commit().await.map_err(unavailable)?;
        Ok(ApprovalReview {
            review_id,
            grant: expected.clone(),
            terms: grant.terms,
            issuer: grant.authority.issuer,
            created_at,
            expires_at,
            confirmation_max_age_seconds: self.configuration.confirmation_max_age_seconds,
        })
    }

    pub async fn confirm(
        &self,
        session: &AuthenticatedApprovalSession,
        expected_grant_id: Uuid,
        review_id: Uuid,
        request: &ExplicitApprovalConfirmation,
    ) -> Result<ApprovalConfirmation, ApprovalProducerError> {
        let started_at = self.clock.now();
        session.check(self.configuration.organization_id, started_at)?;
        if expected_grant_id.is_nil()
            || review_id.is_nil()
            || request.confirmation_id.is_nil()
            || !valid_digest(&request.terms_digest)
        {
            return Err(ApprovalProducerError::InvalidInput);
        }
        let mut transaction = self.consent_pool.begin().await.map_err(unavailable)?;
        // Serialize one review and one typed human retry identity. Locks do not
        // consume a review; its unique immutable binding does, at commit only.
        lock_reference(
            &mut transaction,
            "approval-review",
            session.organization_id,
            &review_id.to_string(),
        )
        .await?;
        lock_reference(
            &mut transaction,
            "approval-confirmation",
            session.organization_id,
            &format!("{}:{}", session.user_id, request.confirmation_id),
        )
        .await?;
        let read_access = self
            .authority
            .current
            .check_actor(session.user_id, ORGANIZATION_DELEGATION_VIEW_PERMISSION)
            .await?;
        if let Some(row) = confirmation_row(
            &mut transaction,
            session.organization_id,
            session.user_id,
            request.confirmation_id,
        )
        .await?
        {
            let original = decode_confirmation(&row, true)?;
            if original.review_id != review_id
                || original.grant_id != expected_grant_id
                || original.terms_digest != request.terms_digest
                || row
                    .try_get::<String, _>("session_ref")
                    .map_err(unavailable)?
                    != session.session_ref
            {
                return Err(ApprovalProducerError::Conflict);
            }
            // Historical recovery does not recheck old approval authority or
            // revive expired/withdrawn consent. Current read access still applies.
            let now = self.clock.now();
            session.check(self.configuration.organization_id, now)?;
            read_access.check(now)?;
            transaction.commit().await.map_err(unavailable)?;
            session.check(self.configuration.organization_id, self.clock.now())?;
            read_access.check(self.clock.now())?;
            return Ok(original);
        }
        let review = sqlx::query("SELECT * FROM delegated_authority_service.approval_reviews WHERE organization_id=$1 AND review_id=$2")
            .bind(session.organization_id).bind(review_id).fetch_optional(&mut *transaction).await.map_err(unavailable)?
            .ok_or(ApprovalProducerError::NotFound)?;
        if review.try_get::<Uuid, _>("actor_id").map_err(unavailable)? != session.user_id
            || review
                .try_get::<String, _>("session_ref")
                .map_err(unavailable)?
                != session.session_ref
        {
            return Err(ApprovalProducerError::AccessDenied);
        }
        let already_confirmed: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM delegated_authority_service.approval_confirmation_bindings WHERE organization_id=$1 AND review_id=$2)")
            .bind(session.organization_id).bind(review_id).fetch_one(&mut *transaction).await.map_err(unavailable)?;
        if already_confirmed {
            return Err(ApprovalProducerError::Conflict);
        }
        check_review_profile(&review, &self.configuration)?;
        if review.try_get::<Uuid, _>("grant_id").map_err(unavailable)? != expected_grant_id
            || review
                .try_get::<String, _>("terms_digest")
                .map_err(unavailable)?
                != request.terms_digest
        {
            return Err(ApprovalProducerError::Conflict);
        }
        let original_grant =
            grant_document(review.try_get("grant_document").map_err(unavailable)?)?;
        let grant = load_grant(&self.read_pool, session.organization_id, expected_grant_id).await?;
        self.configuration.check_pending(&grant, self.clock.now())?;
        if grant != original_grant || grant.terms.grantor != session.actor() {
            return Err(ApprovalProducerError::Conflict);
        }
        let created_at = read_time(&review, "created_at")?;
        let expires_at = read_time(&review, "expires_at")?;
        let before_authority = self.clock.now();
        if before_authority < started_at
            || before_authority < created_at
            || before_authority >= expires_at
        {
            return Err(ApprovalProducerError::Stale);
        }
        let binding = ConsentEvidenceBinding {
            organization_id: session.organization_id,
            grant_id: grant.id,
            terms_digest: grant.terms_digest.clone(),
            grantor: grant.terms.grantor.clone(),
            subject: grant.terms.subject.clone(),
            issuer: grant.authority.issuer.clone(),
            evidence_ref: format!(
                "urn:marty:consent:{}:{}:{}",
                session.organization_id, session.user_id, request.confirmation_id
            ),
            authority_evidence_ref: format!(
                "urn:marty:organization-authority:{}:{}:{}",
                session.organization_id, session.user_id, request.confirmation_id
            ),
        };
        // Separate producer credential, separate independently verified source.
        // An orphan assertion after a failed consent transaction cannot activate.
        let authority = self.authority.establish(&binding).await?;
        let confirmed_at = self.clock.now();
        if confirmed_at < before_authority
            || confirmed_at < authority.asserted_at
            || confirmed_at < authority.observed_at
            || confirmed_at >= expires_at
            || confirmed_at >= authority.valid_until
        {
            return Err(ApprovalProducerError::Stale);
        }
        let valid_until = (confirmed_at
            + Duration::seconds(i64::from(self.configuration.confirmation_max_age_seconds)))
        .min(grant.terms.valid_until);
        let pin = &self.configuration.pin;
        sqlx::query("INSERT INTO delegated_authority_service.consent_confirmations
            (organization_id,evidence_ref,authority_evidence_ref,grant_id,terms_digest,grantor,subject,issuer,profile,adapter_version,artifact_digest,confirmed_at,valid_until)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
            .bind(binding.organization_id).bind(&binding.evidence_ref).bind(&binding.authority_evidence_ref).bind(grant.id).bind(&grant.terms_digest)
            .bind(serde_json::to_value(&binding.grantor).map_err(unavailable)?).bind(serde_json::to_value(&binding.subject).map_err(unavailable)?)
            .bind(serde_json::to_value(&binding.issuer).map_err(unavailable)?).bind(&pin.profile).bind(&pin.version).bind(&pin.artifact_digest)
            .bind(timestamp(confirmed_at)).bind(timestamp(valid_until)).execute(&mut *transaction).await.map_err(database_error)?;
        sqlx::query("INSERT INTO delegated_authority_service.approval_confirmation_bindings
            (organization_id,actor_id,confirmation_id,review_id,grant_id,terms_digest,session_ref,evidence_ref,authority_evidence_ref,confirmed_at,valid_until)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
            .bind(session.organization_id).bind(session.user_id).bind(request.confirmation_id).bind(review_id).bind(grant.id).bind(&grant.terms_digest)
            .bind(&session.session_ref).bind(&binding.evidence_ref).bind(&binding.authority_evidence_ref).bind(timestamp(confirmed_at)).bind(timestamp(valid_until))
            .execute(&mut *transaction).await.map_err(database_error)?;
        let database_time = database_now(&mut transaction).await?;
        for now in [self.clock.now(), database_time] {
            session.check(self.configuration.organization_id, now)?;
            if now < confirmed_at
                || now >= authority.valid_until
                || now >= expires_at
                || now >= valid_until
            {
                return Err(ApprovalProducerError::Stale);
            }
        }
        transaction.commit().await.map_err(unavailable)?;
        Ok(ApprovalConfirmation {
            confirmation_id: request.confirmation_id,
            review_id,
            grant_id: grant.id,
            terms_digest: grant.terms_digest,
            confirmed_at,
            valid_until,
            recovered: false,
        })
    }

    /// Withdrawal does not require present representation authority or the old
    /// session. The same authenticated human must still have current tenant read
    /// access. A duplicate returns the first withdrawal time without rewriting it.
    pub async fn withdraw(
        &self,
        session: &AuthenticatedApprovalSession,
        expected_grant_id: Uuid,
        confirmation_id: Uuid,
    ) -> Result<ApprovalWithdrawal, ApprovalProducerError> {
        session.check(self.configuration.organization_id, self.clock.now())?;
        if expected_grant_id.is_nil() || confirmation_id.is_nil() {
            return Err(ApprovalProducerError::InvalidInput);
        }
        let mut transaction = self.consent_pool.begin().await.map_err(unavailable)?;
        lock_reference(
            &mut transaction,
            "approval-confirmation",
            session.organization_id,
            &format!("{}:{confirmation_id}", session.user_id),
        )
        .await?;
        let access = self
            .authority
            .current
            .check_actor(session.user_id, ORGANIZATION_DELEGATION_VIEW_PERMISSION)
            .await?;
        let row = confirmation_row(
            &mut transaction,
            session.organization_id,
            session.user_id,
            confirmation_id,
        )
        .await?
        .ok_or(ApprovalProducerError::NotFound)?;
        if row.try_get::<Uuid, _>("grant_id").map_err(unavailable)? != expected_grant_id {
            return Err(ApprovalProducerError::Conflict);
        }
        let evidence_ref: String = row.try_get("evidence_ref").map_err(unavailable)?;
        let original: Option<DateTime<Utc>> = sqlx::query_scalar("SELECT withdrawn_at FROM delegated_authority_service.consent_withdrawals WHERE organization_id=$1 AND evidence_ref=$2")
            .bind(session.organization_id).bind(&evidence_ref).fetch_optional(&mut *transaction).await.map_err(unavailable)?;
        let (withdrawn_at, recovered) = if let Some(original) = original {
            (original, true)
        } else {
            let inserted = sqlx::query_scalar("INSERT INTO delegated_authority_service.consent_withdrawals (organization_id,evidence_ref) VALUES ($1,$2) RETURNING withdrawn_at")
                .bind(session.organization_id).bind(&evidence_ref).fetch_one(&mut *transaction).await.map_err(database_error)?;
            (inserted, false)
        };
        for now in [self.clock.now(), database_now(&mut transaction).await?] {
            session.check(self.configuration.organization_id, now)?;
            access.check(now)?;
        }
        transaction.commit().await.map_err(unavailable)?;
        Ok(ApprovalWithdrawal {
            confirmation_id,
            grant_id: expected_grant_id,
            withdrawn_at,
            recovered,
        })
    }
}

#[derive(Clone)]
pub struct PgApprovalConfirmationSource {
    pool: PgPool,
    configuration: OrganizationApprovalConfiguration,
    clock: Arc<dyn DelegationClock>,
}
impl PgApprovalConfirmationSource {
    pub fn new(
        pool: PgPool,
        configuration: OrganizationApprovalConfiguration,
        clock: Arc<dyn DelegationClock>,
    ) -> Self {
        Self {
            pool,
            configuration,
            clock,
        }
    }
}
#[async_trait]
impl DelegationConfirmationSource for PgApprovalConfirmationSource {
    async fn resolve_confirmation(
        &self,
        caller: &DelegationCommandCaller,
        grant: &DelegationGrant,
        confirmation_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<ApprovalEvidence, DelegationConfirmationError> {
        self.configuration
            .check_grant(grant)
            .map_err(|_| DelegationConfirmationError)?;
        let user_id = crate::approval::canonical_user_id(caller.actor())
            .ok_or(DelegationConfirmationError)?;
        if caller.organization_id() != self.configuration.organization_id
            || caller.actor() != &grant.terms.grantor
            || self.clock.now() < now
        {
            return Err(DelegationConfirmationError);
        }
        let session_ref = caller
            .authentication_session_ref()
            .ok_or(DelegationConfirmationError)?;
        let row = sqlx::query("SELECT b.*,c.profile,c.adapter_version,c.artifact_digest,c.grantor,c.subject,c.issuer,
            (w.evidence_ref IS NOT NULL) AS withdrawn,statement_timestamp() AS observed_at
            FROM delegated_authority_service.approval_confirmation_bindings b
            JOIN delegated_authority_service.consent_confirmations c ON c.organization_id=b.organization_id AND c.evidence_ref=b.evidence_ref
            LEFT JOIN delegated_authority_service.consent_withdrawals w ON w.organization_id=b.organization_id AND w.evidence_ref=b.evidence_ref
            WHERE b.organization_id=$1 AND b.actor_id=$2 AND b.confirmation_id=$3")
            .bind(caller.organization_id()).bind(user_id).bind(confirmation_id).fetch_optional(&self.pool).await.map_err(|_| DelegationConfirmationError)?
            .ok_or(DelegationConfirmationError)?;
        let original = decode_confirmation(&row, true).map_err(|_| DelegationConfirmationError)?;
        check_review_profile(&row, &self.configuration).map_err(|_| DelegationConfirmationError)?;
        let current = self.clock.now();
        let database_time: DateTime<Utc> = row
            .try_get("observed_at")
            .map_err(|_| DelegationConfirmationError)?;
        if original.grant_id != grant.id
            || original.terms_digest != grant.terms_digest
            || row
                .try_get::<String, _>("session_ref")
                .map_err(|_| DelegationConfirmationError)?
                != session_ref
            || row
                .try_get::<bool, _>("withdrawn")
                .map_err(|_| DelegationConfirmationError)?
            || original.confirmed_at < grant.created_at
            || original.confirmed_at > now
            || current < now
            || current >= original.valid_until
            || database_time >= original.valid_until
            || database_time < original.confirmed_at
            || current
                >= original.confirmed_at
                    + Duration::seconds(i64::from(self.configuration.confirmation_max_age_seconds))
        {
            return Err(DelegationConfirmationError);
        }
        for (column, principal) in [
            ("grantor", &grant.terms.grantor),
            ("subject", &grant.terms.subject),
            ("issuer", &grant.authority.issuer),
        ] {
            if row
                .try_get::<Value, _>(column)
                .map_err(|_| DelegationConfirmationError)?
                != serde_json::to_value(principal).map_err(|_| DelegationConfirmationError)?
            {
                return Err(DelegationConfirmationError);
            }
        }
        Ok(ApprovalEvidence {
            profile: self.configuration.pin.profile.clone(),
            evidence_ref: row
                .try_get("evidence_ref")
                .map_err(|_| DelegationConfirmationError)?,
            authority_evidence_ref: row
                .try_get("authority_evidence_ref")
                .map_err(|_| DelegationConfirmationError)?,
        })
    }
}

pub(crate) async fn load_grant(
    pool: &PgPool,
    org: Uuid,
    id: Uuid,
) -> Result<DelegationGrant, ApprovalProducerError> {
    let value: Value = sqlx::query_scalar("SELECT grant_document FROM delegated_authority_service.delegation_grants WHERE organization_id=$1 AND id=$2")
        .bind(org).bind(id).fetch_optional(pool).await.map_err(unavailable)?.ok_or(ApprovalProducerError::NotFound)?;
    let grant = grant_document(value)?;
    if grant.organization_id != org || grant.id != id {
        return Err(ApprovalProducerError::Unavailable);
    }
    Ok(grant)
}
fn grant_document(value: Value) -> Result<DelegationGrant, ApprovalProducerError> {
    decode_grant_snapshot(&serde_json::to_vec(&value).map_err(unavailable)?).map_err(unavailable)
}
pub(crate) async fn database_now(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<DateTime<Utc>, ApprovalProducerError> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **transaction)
        .await
        .map_err(unavailable)
}
pub(crate) async fn lock_reference(
    transaction: &mut Transaction<'_, Postgres>,
    namespace: &str,
    org: Uuid,
    reference: &str,
) -> Result<(), ApprovalProducerError> {
    let bytes = serde_json::to_vec(&(namespace, org, reference)).map_err(unavailable)?;
    let hash = Sha256::digest(bytes);
    let lock = i64::from_be_bytes(hash[..8].try_into().map_err(unavailable)?);
    sqlx::query("SET LOCAL lock_timeout='3s'")
        .execute(&mut **transaction)
        .await
        .map_err(unavailable)?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock)
        .execute(&mut **transaction)
        .await
        .map_err(unavailable)?;
    Ok(())
}
pub(crate) fn timestamp(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}
fn read_time(row: &PgRow, name: &str) -> Result<DateTime<Utc>, ApprovalProducerError> {
    DateTime::parse_from_rfc3339(&row.try_get::<String, _>(name).map_err(unavailable)?)
        .map(|value| value.with_timezone(&Utc))
        .map_err(unavailable)
}
async fn confirmation_row(
    transaction: &mut Transaction<'_, Postgres>,
    org: Uuid,
    actor: Uuid,
    id: Uuid,
) -> Result<Option<PgRow>, ApprovalProducerError> {
    sqlx::query("SELECT * FROM delegated_authority_service.approval_confirmation_bindings WHERE organization_id=$1 AND actor_id=$2 AND confirmation_id=$3")
        .bind(org).bind(actor).bind(id).fetch_optional(&mut **transaction).await.map_err(unavailable)
}
fn decode_confirmation(
    row: &PgRow,
    recovered: bool,
) -> Result<ApprovalConfirmation, ApprovalProducerError> {
    Ok(ApprovalConfirmation {
        confirmation_id: row.try_get("confirmation_id").map_err(unavailable)?,
        review_id: row.try_get("review_id").map_err(unavailable)?,
        grant_id: row.try_get("grant_id").map_err(unavailable)?,
        terms_digest: row.try_get("terms_digest").map_err(unavailable)?,
        confirmed_at: read_time(row, "confirmed_at")?,
        valid_until: read_time(row, "valid_until")?,
        recovered,
    })
}
fn check_review_profile(
    row: &PgRow,
    config: &OrganizationApprovalConfiguration,
) -> Result<(), ApprovalProducerError> {
    if row.try_get::<String, _>("profile").map_err(unavailable)? != config.pin.profile
        || row
            .try_get::<String, _>("adapter_version")
            .map_err(unavailable)?
            != config.pin.version
        || row
            .try_get::<String, _>("artifact_digest")
            .map_err(unavailable)?
            != config.pin.artifact_digest
    {
        return Err(ApprovalProducerError::AccessDenied);
    }
    Ok(())
}
fn validate_reference(reference: &CommandGrantReference) -> Result<(), ApprovalProducerError> {
    if reference.id.is_nil()
        || !(1..=MAX_GRANT_REVISION).contains(&reference.revision)
        || !valid_digest(&reference.terms_digest)
    {
        return Err(ApprovalProducerError::InvalidInput);
    }
    Ok(())
}
fn database_error(error: sqlx::Error) -> ApprovalProducerError {
    match error.as_database_error().and_then(|e| e.code()).as_deref() {
        Some("23505" | "23514" | "23503" | "40001") => ApprovalProducerError::Conflict,
        _ => ApprovalProducerError::Unavailable,
    }
}
fn unavailable(_: impl std::fmt::Debug) -> ApprovalProducerError {
    ApprovalProducerError::Unavailable
}
fn not_ready(_: impl std::fmt::Debug) -> ApprovalProducerError {
    ApprovalProducerError::NotReady
}

const CONSENT_WRITE_TABLES: [&str; 4] = [
    "approval_reviews",
    "approval_confirmation_bindings",
    "consent_confirmations",
    "consent_withdrawals",
];
const AUTHORITY_WRITE_TABLES: [&str; 3] = [
    "representation_authority_sources",
    "representation_authority_assertions",
    "organization_authority_observations",
];
const CONSENT_READ_TABLES: [&str; 5] = [
    "consent_confirmations",
    "consent_withdrawals",
    "approval_reviews",
    "approval_confirmation_bindings",
    "approval_storage_identity",
];
pub(crate) const EVIDENCE_READ_TABLES: [&str; 12] = [
    "schema_migrations",
    "delegation_grants",
    "grant_lifecycle_events",
    "consent_confirmations",
    "consent_withdrawals",
    "representation_authority_sources",
    "representation_authority_assertions",
    "command_results",
    "approval_reviews",
    "approval_confirmation_bindings",
    "organization_authority_observations",
    "approval_storage_identity",
];

pub(crate) async fn check_authority_roles(
    authority_pool: &PgPool,
    organization_pool: &PgPool,
) -> Result<(), ApprovalProducerError> {
    check_role(
        authority_pool,
        "delegated_authority_service",
        &AUTHORITY_WRITE_TABLES,
        &[
            "delegation_grants",
            "representation_authority_sources",
            "representation_authority_assertions",
            "organization_authority_observations",
            "approval_storage_identity",
        ],
    )
    .await?;
    check_role(
        organization_pool,
        "organization_service",
        &[],
        &[
            "organizations",
            "members",
            "roles",
            "permissions",
            "member_roles",
            "role_permissions",
        ],
    )
    .await?;
    if role_identity(authority_pool).await? == role_identity(organization_pool).await? {
        return Err(ApprovalProducerError::NotReady);
    }
    Ok(())
}
pub(crate) async fn storage_identity(pool: &PgPool) -> Result<Uuid, ApprovalProducerError> {
    sqlx::query_scalar("SELECT instance_id FROM delegated_authority_service.approval_storage_identity WHERE singleton=true").fetch_one(pool).await.map_err(not_ready)
}
pub(crate) async fn role_identity(pool: &PgPool) -> Result<String, ApprovalProducerError> {
    sqlx::query_scalar("SELECT current_user::TEXT")
        .fetch_one(pool)
        .await
        .map_err(not_ready)
}
pub(crate) async fn check_role(
    pool: &PgPool,
    schema: &str,
    insert_tables: &[&str],
    select_tables: &[&str],
) -> Result<String, ApprovalProducerError> {
    let role = role_identity(pool).await?;
    check_role_boundary(pool, schema, &role, insert_tables).await?;
    for table in select_tables {
        let okay: bool = sqlx::query_scalar(
            "SELECT has_table_privilege(current_user,format('%I.%I',$1::TEXT,$2::TEXT),'SELECT')",
        )
        .bind(schema)
        .bind(table)
        .fetch_one(pool)
        .await
        .map_err(not_ready)?;
        if !okay {
            return Err(ApprovalProducerError::NotReady);
        }
    }
    for table in insert_tables {
        let okay: bool = sqlx::query_scalar(
            "SELECT has_table_privilege(current_user,format('%I.%I',$1::TEXT,$2::TEXT),'INSERT')",
        )
        .bind(schema)
        .bind(table)
        .fetch_one(pool)
        .await
        .map_err(not_ready)?;
        if !okay {
            return Err(ApprovalProducerError::NotReady);
        }
    }
    Ok(role)
}

pub(crate) async fn check_role_boundary(
    pool: &PgPool,
    schema: &str,
    role: &str,
    insert_tables: &[&str],
) -> Result<(), ApprovalProducerError> {
    check_role_boundary_mutations(pool, schema, role, insert_tables, &[]).await
}

/// An explicitly bounded request writer may update its grant table; evidence
/// readers/producers keep the stricter no-update wrapper above.
pub(crate) async fn check_role_boundary_mutations(
    pool: &PgPool,
    schema: &str,
    role: &str,
    insert_tables: &[&str],
    update_tables: &[&str],
) -> Result<(), ApprovalProducerError> {
    // Inspect every reachable role, including roles available via SET ROLE even
    // when automatic inheritance is disabled. A role name alone is no isolation.
    // If the role does not exist on a separately hosted source cluster, it has
    // no PostgreSQL role path there. Deployment/network identity remains an
    // operator qualification, not something these catalog checks attest.
    let unsafe_role: bool = sqlx::query_scalar("SELECT pg_is_in_recovery() OR EXISTS (
        SELECT 1 FROM pg_roles subject JOIN pg_roles r ON (r.oid=subject.oid OR pg_has_role(subject.oid,r.oid,'MEMBER'))
        WHERE subject.rolname=$3 AND (
          r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls
          OR EXISTS (SELECT 1 FROM pg_database d WHERE d.datname=current_database() AND d.datdba=r.oid)
          OR has_database_privilege(r.oid,current_database(),'CREATE,CREATE WITH GRANT OPTION,CONNECT WITH GRANT OPTION,TEMPORARY WITH GRANT OPTION')
          OR EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspname=$1 AND
                (n.nspowner=r.oid OR has_schema_privilege(r.oid,n.oid,'CREATE,CREATE WITH GRANT OPTION,USAGE WITH GRANT OPTION')))
          OR EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
              WHERE n.nspname=$1 AND c.relkind IN ('r','p','v','m','f') AND (
                c.relowner=r.oid OR has_table_privilege(r.oid,c.oid,'DELETE,TRUNCATE,TRIGGER,REFERENCES')
                OR has_any_column_privilege(r.oid,c.oid,'REFERENCES')
                OR ((has_table_privilege(r.oid,c.oid,'UPDATE') OR has_any_column_privilege(r.oid,c.oid,'UPDATE')) AND NOT (c.relname=ANY($4::TEXT[])))
                OR has_table_privilege(r.oid,c.oid,'SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION,DELETE WITH GRANT OPTION,TRUNCATE WITH GRANT OPTION,REFERENCES WITH GRANT OPTION,TRIGGER WITH GRANT OPTION')
                OR has_any_column_privilege(r.oid,c.oid,'SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION,REFERENCES WITH GRANT OPTION')
                OR ((has_table_privilege(r.oid,c.oid,'INSERT') OR has_any_column_privilege(r.oid,c.oid,'INSERT')) AND NOT (c.relname=ANY($2::TEXT[])))))
          OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
              WHERE n.nspname=$1 AND (p.proowner=r.oid OR has_function_privilege(r.oid,p.oid,'EXECUTE WITH GRANT OPTION')
                OR (p.prosecdef AND has_function_privilege(r.oid,p.oid,'EXECUTE'))))))")
        .bind(schema).bind(insert_tables).bind(role).bind(update_tables).fetch_one(pool).await.map_err(not_ready)?;
    if unsafe_role {
        return Err(ApprovalProducerError::NotReady);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
