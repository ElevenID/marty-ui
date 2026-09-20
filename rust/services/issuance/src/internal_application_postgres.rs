//! PostgreSQL persistence for internal Application management.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use sqlx::{postgres::PgRow, Executor, PgPool, Postgres, Row};
use tracing::error;

use crate::{
    application_template_domain::ApplicationTemplateRecord,
    application_template_postgres::PostgresApplicationTemplateRepository,
    canvas_award_candidate_approval::CanvasApplicationApprovalError,
    canvas_award_candidate_approval_postgres::reserve_management_canvas_issuance_in_transaction,
    canvas_event_status::CanvasEventReceipt,
    credential::{CredentialTransaction, CredentialTransactionStatus},
    credential_postgres::{
        insert_issuance_transaction, issuance_transaction_by_id, lock_issuance_transaction_by_id,
        lock_issuance_transaction_by_idempotency, refresh_pending_application_offer,
    },
    internal_application_approval::{
        canvas_bound_application, InternalApplicationApprovalReader,
        InternalApplicationApprovalRepository,
    },
    internal_application_domain::{
        ApplicationRecord, ApplicationStatus, EvidenceFactRecord, IssuanceEventRecord,
    },
    internal_application_evidence::{
        EvidenceCommitOutcome, EvidenceTransitionWrite, InternalApplicationEvidenceRepository,
        InternalApplicationEvidenceRepositoryError,
    },
    internal_application_offer::{
        InternalApplicationOfferError, InternalApplicationOfferRepository,
    },
    internal_application_reconciliation::{
        canvas_scope_matches, EvidenceReconciliationCommitOutcome,
        EvidenceReconciliationReceiptSnapshot, EvidenceReconciliationRepositoryError,
        EvidenceReconciliationSnapshot, EvidenceReconciliationWrite,
        InternalApplicationReconciliationRepository,
    },
    internal_application_service::{
        InternalApplicationApprovalError, InternalApplicationRepository,
        InternalApplicationRepositoryError,
    },
};

macro_rules! application_columns {
    () => {
        "id, organization_id, application_template_id, applicant_identifier,
         form_data, submitted_evidence, integration_context, status,
         review_notes, reviewer_id, rejection_reason, derived_claims,
         issuance_transaction_id, credential_id, created_at, updated_at,
         submitted_at, reviewed_at, expires_at"
    };
}

const INSERT: &str = "INSERT INTO issuance_service.applications (
        id, organization_id, application_template_id, applicant_identifier,
        form_data, submitted_evidence, integration_context, status,
        review_notes, reviewer_id, rejection_reason, derived_claims,
        issuance_transaction_id, credential_id, created_at, updated_at,
        submitted_at, reviewed_at, expires_at
    ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
        $11, $12, $13, $14, $15, $16, $17, $18, $19
    )";

const LIST: &str = concat!(
    "SELECT ",
    application_columns!(),
    " FROM issuance_service.applications
      WHERE organization_id = $1
        AND ($2::text IS NULL OR status = $2)
        AND ($3::text IS NULL OR application_template_id = $3)"
);

const GET: &str = concat!(
    "SELECT ",
    application_columns!(),
    " FROM issuance_service.applications WHERE id = $1"
);

const GET_FOR_UPDATE: &str = concat!(
    "SELECT ",
    application_columns!(),
    " FROM issuance_service.applications WHERE id = $1 FOR UPDATE"
);

const LIST_EVIDENCE_FACTS: &str = "SELECT
        id, organization_id, application_id, subject_id, provider, fact_type,
        scope, assertion, verification, source, requirement_id, logical_key,
        source_revision, payload_hash, observed_at, effective_at,
        superseded_fact_id, created_at
    FROM issuance_service.evidence_facts
    WHERE application_id = $1
    ORDER BY created_at";

const LIST_ISSUANCE_EVENTS: &str = "SELECT
        id, transaction_id, application_id, event_type, metadata, created_at
    FROM issuance_service.issuance_events
    WHERE application_id = $1
    ORDER BY created_at";

const REPLACE_IF_REVISION: &str = "UPDATE issuance_service.applications
    SET application_template_id = $1,
        applicant_identifier = $2,
        form_data = $3,
        submitted_evidence = $4,
        integration_context = $5,
        status = $6,
        review_notes = $7,
        reviewer_id = $8,
        rejection_reason = $9,
        derived_claims = $10,
        issuance_transaction_id = $11,
        credential_id = $12,
        updated_at = $13,
        submitted_at = $14,
        reviewed_at = $15,
        expires_at = $16
    WHERE id = $17
      AND organization_id = $18
      AND status = $19
      AND updated_at = $20";

const BIND_OFFER_TRANSACTION: &str = "UPDATE issuance_service.applications
    SET issuance_transaction_id = $3
    WHERE id = $1 AND organization_id = $2 AND status = 'approved'
      AND issuance_transaction_id IS NOT DISTINCT FROM $4";

const INSERT_ISSUANCE_EVENT: &str = "INSERT INTO issuance_service.issuance_events
    (id, transaction_id, application_id, event_type, metadata, created_at)
    VALUES ($1, $2, $3, $4, $5, $6)";

const INSERT_EVIDENCE_FACT: &str = "INSERT INTO issuance_service.evidence_facts (
        id, organization_id, application_id, subject_id, provider, fact_type,
        scope, assertion, verification, source, requirement_id, logical_key,
        source_revision, payload_hash, observed_at, effective_at,
        superseded_fact_id, created_at
    ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
        $13, $14, $15, $16, $17, $18
    )";

const UPSERT_EVIDENCE_FACT_HEAD: &str = "INSERT INTO issuance_service.evidence_fact_heads (
        organization_id, application_id, logical_key, fact_id, updated_at
    ) VALUES ($1, $2, $3, $4, $5)
    ON CONFLICT (application_id, logical_key) DO UPDATE SET
        organization_id = EXCLUDED.organization_id,
        fact_id = EXCLUDED.fact_id,
        updated_at = EXCLUDED.updated_at";

const GET_APPROVAL_POLICY_SET: &str = "SELECT
        id::text AS id, status, policy_type, cedar_policies
    FROM organization_service.policy_sets
    WHERE organization_id::text = $1 AND id::text = $2";

const GET_RECONCILIATION_PLATFORM_BY_ID: &str = "SELECT jsonb_build_object(
        'id', id, 'organization_id', organization_id,
        'canvas_account_id', canvas_account_id,
        'registration_status', registration_status,
        'enabled', enabled, 'archived_at', archived_at
    ) FROM issuance_service.canvas_platforms
    WHERE id = $1 AND organization_id = $2";

const GET_RECONCILIATION_PLATFORM_BY_ACCOUNT: &str = "SELECT jsonb_build_object(
        'id', id, 'organization_id', organization_id,
        'canvas_account_id', canvas_account_id,
        'registration_status', registration_status,
        'enabled', enabled, 'archived_at', archived_at
    ) FROM issuance_service.canvas_platforms
    WHERE organization_id = $1 AND canvas_account_id = $2";

const GET_RECONCILIATION_BINDING: &str = "SELECT jsonb_build_object(
        'id', id, 'organization_id', organization_id, 'platform_id', platform_id,
        'application_template_id', application_template_id,
        'credential_template_id', credential_template_id,
        'approval_policy_set_id', approval_policy_set_id,
        'auto_approve_on_evidence', auto_approve_on_evidence,
        'evidence_requirements', evidence_requirements,
        'canvas_scope', canvas_scope, 'delivery_mode', delivery_mode,
        'deployment_profile_id', deployment_profile_id,
        'feature_flags', feature_flags, 'enabled', enabled,
        'config_version', config_version,
        'validated_config_version', validated_config_version,
        'readiness_checks', readiness_checks,
        'readiness_validated_at', readiness_validated_at,
        'credential_template_snapshot', credential_template_snapshot,
        'activated_at', activated_at, 'archived_at', archived_at
    ) FROM issuance_service.canvas_program_bindings
    WHERE id = $1 AND organization_id = $2
      AND application_template_id = $3";

const LIST_RECONCILIATION_BINDINGS: &str = "SELECT jsonb_build_object(
        'id', id, 'organization_id', organization_id, 'platform_id', platform_id,
        'application_template_id', application_template_id,
        'credential_template_id', credential_template_id,
        'approval_policy_set_id', approval_policy_set_id,
        'auto_approve_on_evidence', auto_approve_on_evidence,
        'evidence_requirements', evidence_requirements,
        'canvas_scope', canvas_scope, 'delivery_mode', delivery_mode,
        'deployment_profile_id', deployment_profile_id,
        'feature_flags', feature_flags, 'enabled', enabled,
        'config_version', config_version,
        'validated_config_version', validated_config_version,
        'readiness_checks', readiness_checks,
        'readiness_validated_at', readiness_validated_at,
        'credential_template_snapshot', credential_template_snapshot,
        'activated_at', activated_at, 'archived_at', archived_at
    ) FROM issuance_service.canvas_program_bindings
    WHERE organization_id = $1 AND platform_id = $2
      AND application_template_id = $3
    ORDER BY created_at";

const LIST_RECONCILIATION_RECEIPTS: &str = "SELECT
        id, provider_event_id, canvas_account_id, organization_id,
        credential_template_id, payload_hash, issuance_transaction_id,
        issuance_response, status, error_summary, first_seen_at, last_seen_at
    FROM issuance_service.canvas_event_receipts
    WHERE organization_id = $1 AND status = 'evidence_received'
    ORDER BY last_seen_at DESC
    LIMIT $2";

const UPDATE_RECONCILIATION_CONTEXT_AFTER_RESERVATION: &str = "UPDATE issuance_service.applications
     SET integration_context = $3
     WHERE id = $1 AND organization_id = $2
       AND status = 'approved' AND issuance_transaction_id = $4
       AND updated_at = $5";

#[derive(Clone)]
pub struct PostgresInternalApplicationRepository {
    pool: PgPool,
    templates: PostgresApplicationTemplateRepository,
}

impl std::fmt::Debug for PostgresInternalApplicationRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresInternalApplicationRepository")
            .finish_non_exhaustive()
    }
}

impl PostgresInternalApplicationRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            templates: PostgresApplicationTemplateRepository::new(pool.clone()),
            pool,
        }
    }
}

async fn replace_application_if_revision_on<'executor, E>(
    executor: E,
    application: &ApplicationRecord,
    expected_status: ApplicationStatus,
    expected_updated_at: DateTime<Utc>,
) -> Result<bool, InternalApplicationRepositoryError>
where
    E: Executor<'executor, Database = Postgres>,
{
    let affected = sqlx::query(REPLACE_IF_REVISION)
        .bind(&application.application_template_id)
        .bind(&application.applicant_identifier)
        .bind(Value::Object(application.form_data.clone()))
        .bind(Value::Array(
            application
                .evidence_submissions
                .iter()
                .cloned()
                .map(Value::Object)
                .collect(),
        ))
        .bind(Value::Object(application.integration_context.clone()))
        .bind(application.status.as_str())
        .bind(&application.review_notes)
        .bind(&application.reviewer_id)
        .bind(&application.rejection_reason)
        .bind(Value::Object(application.derived_claims.clone()))
        .bind(&application.issuance_transaction_id)
        .bind(&application.credential_id)
        .bind(application.updated_at)
        .bind(application.submitted_at)
        .bind(application.reviewed_at)
        .bind(application.expires_at)
        .bind(&application.id)
        .bind(&application.organization_id)
        .bind(expected_status.as_str())
        .bind(expected_updated_at)
        .execute(executor)
        .await
        .map_err(repository_error)?
        .rows_affected();
    Ok(affected == 1)
}

async fn insert_evidence_fact_on<'executor, E>(
    executor: E,
    fact: &EvidenceFactRecord,
) -> Result<(), InternalApplicationEvidenceRepositoryError>
where
    E: Executor<'executor, Database = Postgres>,
{
    sqlx::query(INSERT_EVIDENCE_FACT)
        .bind(&fact.id)
        .bind(&fact.organization_id)
        .bind(&fact.application_id)
        .bind(&fact.subject_id)
        .bind(&fact.provider)
        .bind(&fact.fact_type)
        .bind(Value::Object(fact.scope.clone()))
        .bind(Value::Object(fact.assertion.clone()))
        .bind(Value::Object(fact.verification.clone()))
        .bind(Value::Object(fact.source.clone()))
        .bind(&fact.requirement_id)
        .bind(&fact.logical_key)
        .bind(&fact.source_revision)
        .bind(&fact.payload_hash)
        .bind(fact.observed_at)
        .bind(fact.effective_at)
        .bind(&fact.superseded_fact_id)
        .bind(fact.created_at)
        .execute(executor)
        .await
        .map_err(evidence_repository_error)?;
    Ok(())
}

async fn upsert_evidence_fact_head_on<'executor, E>(
    executor: E,
    fact: &EvidenceFactRecord,
) -> Result<(), InternalApplicationEvidenceRepositoryError>
where
    E: Executor<'executor, Database = Postgres>,
{
    sqlx::query(UPSERT_EVIDENCE_FACT_HEAD)
        .bind(&fact.organization_id)
        .bind(&fact.application_id)
        .bind(&fact.logical_key)
        .bind(&fact.id)
        .bind(fact.created_at)
        .execute(executor)
        .await
        .map_err(evidence_repository_error)?;
    Ok(())
}

async fn insert_issuance_event_on<'executor, E>(
    executor: E,
    event: &IssuanceEventRecord,
) -> Result<(), InternalApplicationEvidenceRepositoryError>
where
    E: Executor<'executor, Database = Postgres>,
{
    sqlx::query(INSERT_ISSUANCE_EVENT)
        .bind(&event.id)
        .bind(&event.transaction_id)
        .bind(&event.application_id)
        .bind(&event.event_type)
        .bind(Value::Object(event.metadata.clone()))
        .bind(event.created_at)
        .execute(executor)
        .await
        .map_err(evidence_repository_error)?;
    Ok(())
}

#[async_trait]
impl InternalApplicationRepository for PostgresInternalApplicationRepository {
    async fn get_application_template(
        &self,
        template_id: &str,
    ) -> Result<Option<ApplicationTemplateRecord>, InternalApplicationRepositoryError> {
        self.templates
            .get_unscoped(template_id)
            .await
            .map_err(|cause| {
                error!(%cause, "internal Application template lookup failed");
                InternalApplicationRepositoryError::Unavailable
            })
    }

    async fn insert_application(
        &self,
        application: &ApplicationRecord,
    ) -> Result<(), InternalApplicationRepositoryError> {
        sqlx::query(INSERT)
            .bind(&application.id)
            .bind(&application.organization_id)
            .bind(&application.application_template_id)
            .bind(&application.applicant_identifier)
            .bind(Value::Object(application.form_data.clone()))
            .bind(Value::Array(
                application
                    .evidence_submissions
                    .iter()
                    .cloned()
                    .map(Value::Object)
                    .collect(),
            ))
            .bind(Value::Object(application.integration_context.clone()))
            .bind(application.status.as_str())
            .bind(&application.review_notes)
            .bind(&application.reviewer_id)
            .bind(&application.rejection_reason)
            .bind(Value::Object(application.derived_claims.clone()))
            .bind(&application.issuance_transaction_id)
            .bind(&application.credential_id)
            .bind(application.created_at)
            .bind(application.updated_at)
            .bind(application.submitted_at)
            .bind(application.reviewed_at)
            .bind(application.expires_at)
            .execute(&self.pool)
            .await
            .map_err(repository_error)?;
        Ok(())
    }

    async fn list_applications(
        &self,
        organization_id: &str,
        status: Option<ApplicationStatus>,
        template_id: Option<&str>,
    ) -> Result<Vec<ApplicationRecord>, InternalApplicationRepositoryError> {
        let status = status.map(ApplicationStatus::as_str);
        sqlx::query(LIST)
            .bind(organization_id)
            .bind(status)
            .bind(template_id)
            .fetch_all(&self.pool)
            .await
            .map_err(repository_error)?
            .into_iter()
            .map(application_row)
            .collect()
    }

    async fn get_application(
        &self,
        application_id: &str,
    ) -> Result<Option<ApplicationRecord>, InternalApplicationRepositoryError> {
        sqlx::query(GET)
            .bind(application_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(application_row)
            .transpose()
    }

    async fn list_evidence_facts_for_application(
        &self,
        application_id: &str,
    ) -> Result<Vec<EvidenceFactRecord>, InternalApplicationRepositoryError> {
        sqlx::query(LIST_EVIDENCE_FACTS)
            .bind(application_id)
            .fetch_all(&self.pool)
            .await
            .map_err(repository_error)?
            .into_iter()
            .map(evidence_fact_row)
            .collect()
    }

    async fn list_events_for_application(
        &self,
        application_id: &str,
    ) -> Result<Vec<IssuanceEventRecord>, InternalApplicationRepositoryError> {
        sqlx::query(LIST_ISSUANCE_EVENTS)
            .bind(application_id)
            .fetch_all(&self.pool)
            .await
            .map_err(repository_error)?
            .into_iter()
            .map(issuance_event_row)
            .collect()
    }

    async fn replace_application_if_revision(
        &self,
        application: &ApplicationRecord,
        expected_status: ApplicationStatus,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<bool, InternalApplicationRepositoryError> {
        replace_application_if_revision_on(
            &self.pool,
            application,
            expected_status,
            expected_updated_at,
        )
        .await
    }
}

#[async_trait]
impl InternalApplicationEvidenceRepository for PostgresInternalApplicationRepository {
    async fn list_facts(
        &self,
        application_id: &str,
    ) -> Result<Vec<EvidenceFactRecord>, InternalApplicationEvidenceRepositoryError> {
        InternalApplicationRepository::list_evidence_facts_for_application(self, application_id)
            .await
            .map_err(|_| InternalApplicationEvidenceRepositoryError::Unavailable)
    }

    async fn approval_policy_set(
        &self,
        organization_id: &str,
        policy_set_id: &str,
    ) -> Result<Option<Map<String, Value>>, InternalApplicationEvidenceRepositoryError> {
        let row = match sqlx::query(GET_APPROVAL_POLICY_SET)
            .bind(organization_id)
            .bind(policy_set_id)
            .fetch_optional(&self.pool)
            .await
        {
            Ok(row) => row,
            Err(_) => {
                error!("approval PolicySet lookup failed during evidence evaluation");
                return Ok(None);
            }
        };
        row.map(|row| {
            Ok(Map::from_iter([
                (
                    "id".to_owned(),
                    Value::String(row.try_get("id").map_err(evidence_repository_error)?),
                ),
                (
                    "status".to_owned(),
                    Value::String(row.try_get("status").map_err(evidence_repository_error)?),
                ),
                (
                    "policy_type".to_owned(),
                    Value::String(
                        row.try_get("policy_type")
                            .map_err(evidence_repository_error)?,
                    ),
                ),
                (
                    "cedar_policies".to_owned(),
                    Value::String(
                        row.try_get("cedar_policies")
                            .map_err(evidence_repository_error)?,
                    ),
                ),
            ]))
        })
        .transpose()
    }

    async fn commit_transition(
        &self,
        write: &EvidenceTransitionWrite,
    ) -> Result<EvidenceCommitOutcome, InternalApplicationEvidenceRepositoryError> {
        if write.evidence_fact.application_id != write.application.id
            || write.evidence_fact.organization_id != write.application.organization_id
            || write.events.iter().any(|event| {
                event.application_id.as_deref() != Some(write.application.id.as_str())
                    || event
                        .metadata
                        .get("organization_id")
                        .and_then(Value::as_str)
                        != Some(write.application.organization_id.as_str())
            })
            || write.transaction.as_ref().is_some_and(|transaction| {
                transaction.application_id.as_deref() != Some(write.application.id.as_str())
                    || transaction.organization_id != write.application.organization_id
            })
        {
            return Err(InternalApplicationEvidenceRepositoryError::Unavailable);
        }

        let mut database = self.pool.begin().await.map_err(evidence_repository_error)?;
        let current = sqlx::query(GET_FOR_UPDATE)
            .bind(&write.application.id)
            .fetch_optional(&mut *database)
            .await
            .map_err(evidence_repository_error)?
            .map(application_row)
            .transpose()
            .map_err(|_| InternalApplicationEvidenceRepositoryError::Unavailable)?;
        let Some(current) = current else {
            return Ok(EvidenceCommitOutcome::ConcurrentChange);
        };
        if current.organization_id != write.application.organization_id
            || current.status != write.expected_status
            || current.updated_at != write.expected_updated_at
        {
            return Ok(EvidenceCommitOutcome::ConcurrentChange);
        }

        if let Some(transaction) = &write.transaction {
            let inserted = insert_issuance_transaction(&mut *database, transaction)
                .await
                .map_err(|_| InternalApplicationEvidenceRepositoryError::Unavailable)?;
            if inserted.as_ref().map(|value| value.id.as_str()) != Some(transaction.id.as_str()) {
                return Err(InternalApplicationEvidenceRepositoryError::Unavailable);
            }
        }
        insert_evidence_fact_on(&mut *database, &write.evidence_fact).await?;
        upsert_evidence_fact_head_on(&mut *database, &write.evidence_fact).await?;
        if !replace_application_if_revision_on(
            &mut *database,
            &write.application,
            write.expected_status,
            write.expected_updated_at,
        )
        .await
        .map_err(|_| InternalApplicationEvidenceRepositoryError::Unavailable)?
        {
            return Ok(EvidenceCommitOutcome::ConcurrentChange);
        }
        for event in &write.events {
            insert_issuance_event_on(&mut *database, event).await?;
        }
        database.commit().await.map_err(evidence_repository_error)?;
        Ok(EvidenceCommitOutcome::Committed)
    }

    async fn commit_conflict_evidence(
        &self,
        application_id: &str,
        organization_id: &str,
        fact: &EvidenceFactRecord,
        events: &[IssuanceEventRecord],
    ) -> Result<(), InternalApplicationEvidenceRepositoryError> {
        if fact.application_id != application_id
            || fact.organization_id != organization_id
            || events.iter().any(|event| {
                event.application_id.as_deref() != Some(application_id)
                    || event
                        .metadata
                        .get("organization_id")
                        .and_then(Value::as_str)
                        != Some(organization_id)
            })
        {
            return Err(InternalApplicationEvidenceRepositoryError::Unavailable);
        }
        let mut database = self.pool.begin().await.map_err(evidence_repository_error)?;
        let current_organization = sqlx::query_scalar::<_, String>(
            "SELECT organization_id FROM issuance_service.applications WHERE id = $1 FOR UPDATE",
        )
        .bind(application_id)
        .fetch_optional(&mut *database)
        .await
        .map_err(evidence_repository_error)?;
        if current_organization.as_deref() != Some(organization_id) {
            return Err(InternalApplicationEvidenceRepositoryError::Unavailable);
        }
        insert_evidence_fact_on(&mut *database, fact).await?;
        upsert_evidence_fact_head_on(&mut *database, fact).await?;
        for event in events {
            insert_issuance_event_on(&mut *database, event).await?;
        }
        database.commit().await.map_err(evidence_repository_error)?;
        Ok(())
    }
}

#[async_trait]
impl InternalApplicationReconciliationRepository for PostgresInternalApplicationRepository {
    async fn applications(
        &self,
        organization_id: &str,
        application_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ApplicationRecord>, EvidenceReconciliationRepositoryError> {
        let mut applications = if let Some(application_id) = application_id {
            InternalApplicationRepository::get_application(self, application_id)
                .await
                .map_err(|_| EvidenceReconciliationRepositoryError::Unavailable)?
                .filter(|application| application.organization_id == organization_id)
                .into_iter()
                .collect()
        } else {
            InternalApplicationRepository::list_applications(self, organization_id, None, None)
                .await
                .map_err(|_| EvidenceReconciliationRepositoryError::Unavailable)?
        };
        applications.truncate(limit);
        Ok(applications)
    }

    async fn snapshot(
        &self,
        application: &ApplicationRecord,
    ) -> Result<EvidenceReconciliationSnapshot, EvidenceReconciliationRepositoryError> {
        let template = InternalApplicationRepository::get_application_template(
            self,
            &application.application_template_id,
        )
        .await
        .map_err(|_| EvidenceReconciliationRepositoryError::Unavailable)?
        .filter(|template| template.organization_id == application.organization_id);
        let facts = InternalApplicationRepository::list_evidence_facts_for_application(
            self,
            &application.id,
        )
        .await
        .map_err(|_| EvidenceReconciliationRepositoryError::Unavailable)?;
        let canvas_facts = facts
            .iter()
            .filter(|fact| fact.provider == "canvas")
            .collect::<Vec<_>>();
        let canvas = application
            .integration_context
            .get("canvas")
            .and_then(Value::as_object);
        let binding_id = canvas
            .and_then(|canvas| canvas.get("canvas_program_binding_id"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty());
        let expected_platform_id = canvas
            .and_then(|canvas| canvas.get("canvas_platform_id"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty());

        let (platform, binding) = if let Some(binding_id) = binding_id {
            let binding = sqlx::query_scalar::<_, Value>(GET_RECONCILIATION_BINDING)
                .bind(binding_id)
                .bind(&application.organization_id)
                .bind(&application.application_template_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(reconciliation_repository_error)?
                .and_then(|value| value.as_object().cloned())
                .filter(active_binding);
            let platform = if let Some(binding) = binding.as_ref() {
                let platform_id = binding
                    .get("platform_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if expected_platform_id.is_some_and(|expected| expected != platform_id) {
                    None
                } else {
                    sqlx::query_scalar::<_, Value>(GET_RECONCILIATION_PLATFORM_BY_ID)
                        .bind(platform_id)
                        .bind(&application.organization_id)
                        .fetch_optional(&self.pool)
                        .await
                        .map_err(reconciliation_repository_error)?
                        .and_then(|value| value.as_object().cloned())
                        .filter(active_platform)
                }
            } else {
                None
            };
            if platform.is_none() {
                (None, None)
            } else {
                (platform, binding)
            }
        } else {
            let canvas_account_id = canvas
                .and_then(|canvas| canvas.get("canvas_account_id"))
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .or_else(|| canvas_facts.last().and_then(|fact| canvas_account_id(fact)));
            let platform = match canvas_account_id.as_deref() {
                Some(canvas_account_id) => {
                    sqlx::query_scalar::<_, Value>(GET_RECONCILIATION_PLATFORM_BY_ACCOUNT)
                        .bind(&application.organization_id)
                        .bind(canvas_account_id)
                        .fetch_optional(&self.pool)
                        .await
                        .map_err(reconciliation_repository_error)?
                        .and_then(|value| value.as_object().cloned())
                        .filter(active_platform)
                }
                None => None,
            };
            let binding = if let Some(platform) = platform.as_ref() {
                let platform_id = platform
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let actual_scope = canvas_facts
                    .last()
                    .map(|fact| fact.scope.clone())
                    .unwrap_or_default();
                sqlx::query_scalar::<_, Value>(LIST_RECONCILIATION_BINDINGS)
                    .bind(&application.organization_id)
                    .bind(platform_id)
                    .bind(&application.application_template_id)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(reconciliation_repository_error)?
                    .into_iter()
                    .filter_map(|value| value.as_object().cloned())
                    .find(|binding| {
                        active_binding(binding)
                            && canvas_scope_matches(binding.get("canvas_scope"), &actual_scope)
                    })
            } else {
                None
            };
            if binding.is_none() {
                (None, None)
            } else {
                (platform, binding)
            }
        };

        let policy_set_id = binding
            .as_ref()
            .and_then(|binding| binding.get("approval_policy_set_id"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .or_else(|| {
                template
                    .as_ref()
                    .and_then(|template| template.approval_policy_set_id.as_deref())
                    .filter(|value| !value.is_empty())
            });
        let policy_set = if let Some(policy_set_id) = policy_set_id {
            InternalApplicationEvidenceRepository::approval_policy_set(
                self,
                &application.organization_id,
                policy_set_id,
            )
            .await
            .map_err(|_| EvidenceReconciliationRepositoryError::Unavailable)?
        } else {
            None
        };
        let existing_transaction =
            if let Some(transaction_id) = application.issuance_transaction_id.as_deref() {
                issuance_transaction_by_id(&self.pool, transaction_id, &application.organization_id)
                    .await
                    .map_err(|_| EvidenceReconciliationRepositoryError::Unavailable)?
                    .filter(|transaction| {
                        transaction.application_id.as_deref() == Some(&application.id)
                    })
            } else {
                None
            };
        Ok(EvidenceReconciliationSnapshot {
            application: application.clone(),
            template,
            platform,
            binding,
            facts,
            policy_set,
            existing_transaction,
        })
    }

    async fn receipts(
        &self,
        organization_id: &str,
        limit: usize,
    ) -> Result<Vec<EvidenceReconciliationReceiptSnapshot>, EvidenceReconciliationRepositoryError>
    {
        let limit =
            i64::try_from(limit).map_err(|_| EvidenceReconciliationRepositoryError::Unavailable)?;
        let rows = sqlx::query(LIST_RECONCILIATION_RECEIPTS)
            .bind(organization_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(reconciliation_repository_error)?;
        let mut receipts = Vec::with_capacity(rows.len());
        for row in rows {
            let receipt = reconciliation_receipt_row(&row)?;
            let application_id = receipt
                .issuance_response
                .as_object()
                .and_then(|response| response.get("application_id"))
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty());
            let application = if let Some(application_id) = application_id {
                InternalApplicationRepository::get_application(self, application_id)
                    .await
                    .map_err(|_| EvidenceReconciliationRepositoryError::Unavailable)?
                    .filter(|application| application.organization_id == organization_id)
            } else {
                None
            };
            receipts.push(EvidenceReconciliationReceiptSnapshot {
                receipt,
                application,
            });
        }
        Ok(receipts)
    }

    async fn commit(
        &self,
        write: &EvidenceReconciliationWrite,
    ) -> Result<EvidenceReconciliationCommitOutcome, EvidenceReconciliationRepositoryError> {
        validate_reconciliation_write(write)?;
        let mut database = self
            .pool
            .begin()
            .await
            .map_err(reconciliation_repository_error)?;
        let current = sqlx::query(GET_FOR_UPDATE)
            .bind(&write.application.id)
            .fetch_optional(&mut *database)
            .await
            .map_err(reconciliation_repository_error)?
            .map(application_row)
            .transpose()
            .map_err(|_| EvidenceReconciliationRepositoryError::Unavailable)?;
        let Some(current) = current else {
            return Ok(EvidenceReconciliationCommitOutcome::ConcurrentChange { current: None });
        };
        if current.organization_id != write.application.organization_id
            || current.status != write.expected_status
            || current.updated_at != write.expected_updated_at
        {
            return Ok(EvidenceReconciliationCommitOutcome::ConcurrentChange {
                current: Some(Box::new(current)),
            });
        }

        if let Some(transaction) = write.transaction.as_ref() {
            let snapshot = write
                .approval_snapshot
                .as_ref()
                .ok_or(EvidenceReconciliationRepositoryError::Unavailable)?;
            let reserved_id = match reserve_management_canvas_issuance_in_transaction(
                &mut database,
                transaction,
                snapshot,
                write
                    .application
                    .reviewer_id
                    .as_deref()
                    .ok_or(EvidenceReconciliationRepositoryError::Unavailable)?,
                write.application.review_notes.as_deref(),
                write.reconciled_at,
            )
            .await
            {
                Ok(reserved_id) => reserved_id,
                Err(CanvasApplicationApprovalError::Unavailable) => {
                    return Err(EvidenceReconciliationRepositoryError::Unavailable)
                }
                Err(_) => {
                    return Ok(EvidenceReconciliationCommitOutcome::ConcurrentChange {
                        current: Some(Box::new(current)),
                    })
                }
            };
            if write.application.issuance_transaction_id.as_deref() != Some(reserved_id.as_str()) {
                return Err(EvidenceReconciliationRepositoryError::Unavailable);
            }
            let updated = sqlx::query(UPDATE_RECONCILIATION_CONTEXT_AFTER_RESERVATION)
                .bind(&write.application.id)
                .bind(&write.application.organization_id)
                .bind(Value::Object(write.application.integration_context.clone()))
                .bind(&reserved_id)
                .bind(write.reconciled_at)
                .execute(&mut *database)
                .await
                .map_err(reconciliation_repository_error)?;
            if updated.rows_affected() != 1 {
                return Ok(EvidenceReconciliationCommitOutcome::ConcurrentChange {
                    current: Some(Box::new(current)),
                });
            }
        } else if !replace_application_if_revision_on(
            &mut *database,
            &write.application,
            write.expected_status,
            write.expected_updated_at,
        )
        .await
        .map_err(|_| EvidenceReconciliationRepositoryError::Unavailable)?
        {
            return Ok(EvidenceReconciliationCommitOutcome::ConcurrentChange {
                current: Some(Box::new(current)),
            });
        }
        for event in &write.events {
            insert_reconciliation_event(&mut database, event).await?;
        }
        database
            .commit()
            .await
            .map_err(reconciliation_repository_error)?;
        Ok(EvidenceReconciliationCommitOutcome::Committed)
    }

    async fn commit_conflict_events(
        &self,
        application_id: &str,
        organization_id: &str,
        events: &[IssuanceEventRecord],
    ) -> Result<(), EvidenceReconciliationRepositoryError> {
        if events.iter().any(|event| {
            event.application_id.as_deref() != Some(application_id)
                || event
                    .metadata
                    .get("organization_id")
                    .and_then(Value::as_str)
                    != Some(organization_id)
        }) {
            return Err(EvidenceReconciliationRepositoryError::Unavailable);
        }
        let mut database = self
            .pool
            .begin()
            .await
            .map_err(reconciliation_repository_error)?;
        let current_organization = sqlx::query_scalar::<_, String>(
            "SELECT organization_id FROM issuance_service.applications
             WHERE id = $1 FOR UPDATE",
        )
        .bind(application_id)
        .fetch_optional(&mut *database)
        .await
        .map_err(reconciliation_repository_error)?;
        if current_organization.as_deref() != Some(organization_id) {
            return Err(EvidenceReconciliationRepositoryError::Unavailable);
        }
        for event in events {
            insert_reconciliation_event(&mut database, event).await?;
        }
        database
            .commit()
            .await
            .map_err(reconciliation_repository_error)?;
        Ok(())
    }
}

#[async_trait]
impl InternalApplicationApprovalRepository for PostgresInternalApplicationRepository {
    async fn reserve_ordinary_approval(
        &self,
        application: &ApplicationRecord,
        transaction: &CredentialTransaction,
        reviewer_id: &str,
        review_notes: Option<&str>,
        reviewed_at: DateTime<Utc>,
    ) -> Result<Option<ApplicationRecord>, InternalApplicationApprovalError> {
        if transaction.application_id.as_deref() != Some(application.id.as_str())
            || transaction.organization_id != application.organization_id
            || transaction.idempotency_key_hash.is_some()
            || transaction.idempotency_request_hash.is_some()
        {
            return Err(InternalApplicationApprovalError::Unavailable);
        }

        let mut database = self
            .pool
            .begin()
            .await
            .map_err(|_| InternalApplicationApprovalError::Unavailable)?;
        let current = sqlx::query(GET_FOR_UPDATE)
            .bind(&application.id)
            .fetch_optional(&mut *database)
            .await
            .map_err(|cause| {
                error!(%cause, "ordinary application approval lock failed");
                InternalApplicationApprovalError::Unavailable
            })?
            .map(application_row)
            .transpose()
            .map_err(|_| InternalApplicationApprovalError::Unavailable)?;
        let Some(mut current) = current else {
            return Ok(None);
        };
        if current.organization_id != application.organization_id
            || current.status != ApplicationStatus::Pending
            || current.updated_at != application.updated_at
            || canvas_bound_application(&current)
        {
            return Ok(None);
        }

        let inserted = insert_issuance_transaction(&mut *database, transaction)
            .await
            .map_err(|cause| {
                error!(%cause, "ordinary application transaction reservation failed");
                InternalApplicationApprovalError::Unavailable
            })?;
        if inserted.as_ref().map(|value| value.id.as_str()) != Some(transaction.id.as_str()) {
            return Err(InternalApplicationApprovalError::Unavailable);
        }

        current
            .approve_reserved(
                transaction.id.clone(),
                review_notes.map(str::to_owned),
                reviewer_id,
                reviewed_at,
            )
            .map_err(|_| InternalApplicationApprovalError::ConcurrentChange)?;
        if !replace_application_if_revision_on(
            &mut *database,
            &current,
            ApplicationStatus::Pending,
            application.updated_at,
        )
        .await
        .map_err(|_| InternalApplicationApprovalError::Unavailable)?
        {
            return Ok(None);
        }
        database
            .commit()
            .await
            .map_err(|_| InternalApplicationApprovalError::Unavailable)?;
        Ok(Some(current))
    }
}

#[async_trait]
impl InternalApplicationApprovalReader for PostgresInternalApplicationRepository {
    async fn reload_approved_application(
        &self,
        application_id: &str,
    ) -> Result<Option<ApplicationRecord>, InternalApplicationApprovalError> {
        InternalApplicationRepository::get_application(self, application_id)
            .await
            .map_err(|_| InternalApplicationApprovalError::Unavailable)
    }
}

#[async_trait]
impl InternalApplicationOfferRepository for PostgresInternalApplicationRepository {
    async fn reserve_or_refresh_offer(
        &self,
        application: &ApplicationRecord,
        prepared: &CredentialTransaction,
        now: DateTime<Utc>,
    ) -> Result<Option<CredentialTransaction>, InternalApplicationOfferError> {
        if prepared.organization_id != application.organization_id
            || prepared.application_id.as_deref() != Some(application.id.as_str())
            || prepared.status != CredentialTransactionStatus::Pending
            || prepared
                .idempotency_key_hash
                .as_deref()
                .is_none_or(|value| value.len() != 64)
            || prepared
                .idempotency_request_hash
                .as_deref()
                .is_none_or(|value| value.len() != 64)
        {
            return Err(InternalApplicationOfferError::Unavailable);
        }
        let key_hash = prepared
            .idempotency_key_hash
            .as_deref()
            .ok_or(InternalApplicationOfferError::Unavailable)?;
        let mut expected_binding = application.issuance_transaction_id.clone();
        for _ in 0..3 {
            let mut database = self
                .pool
                .begin()
                .await
                .map_err(|_| InternalApplicationOfferError::Unavailable)?;

            // Credential finalization locks transaction then application. Keep
            // the same order for existing offers to avoid a cross-flow
            // deadlock. An unbound generation may have an idempotent
            // reservation left by an older implementation, so lock that first.
            let prelocked = match expected_binding.as_deref() {
                Some(transaction_id) => {
                    lock_issuance_transaction_by_id(
                        &mut *database,
                        transaction_id,
                        &application.organization_id,
                    )
                    .await
                }
                None => {
                    lock_issuance_transaction_by_idempotency(
                        &mut *database,
                        &application.organization_id,
                        key_hash,
                    )
                    .await
                }
            }
            .map_err(|_| InternalApplicationOfferError::Unavailable)?;
            let current = sqlx::query(GET_FOR_UPDATE)
                .bind(&application.id)
                .fetch_optional(&mut *database)
                .await
                .map_err(offer_repository_error)?
                .map(application_row)
                .transpose()
                .map_err(|_| InternalApplicationOfferError::Unavailable)?;
            let Some(current) = current else {
                return Ok(None);
            };
            if current.organization_id != application.organization_id
                || current.status != ApplicationStatus::Approved
                || current.updated_at != application.updated_at
            {
                return Ok(None);
            }
            if current.issuance_transaction_id != expected_binding {
                expected_binding = current.issuance_transaction_id;
                database
                    .rollback()
                    .await
                    .map_err(|_| InternalApplicationOfferError::Unavailable)?;
                continue;
            }

            if let Some(existing) = prelocked.as_ref() {
                if existing.application_id.as_deref() != Some(current.id.as_str())
                    || existing.organization_id != current.organization_id
                {
                    return Err(InternalApplicationOfferError::Unavailable);
                }
                if expected_binding.is_some()
                    && existing.status == CredentialTransactionStatus::Pending
                    && now <= existing.expires_at
                {
                    let refresh_canvas_context = canvas_bound_application(&current);
                    let mut refreshed_context = prepared.clone();
                    if refresh_canvas_context {
                        refreshed_context.claims = existing.claims.clone();
                        if let Some(vct) = prepared.claims.get("_vct") {
                            refreshed_context
                                .claims
                                .insert("_vct".to_owned(), vct.clone());
                        }
                    }
                    let refreshed = refresh_pending_application_offer(
                        &mut *database,
                        existing,
                        &refreshed_context,
                        refresh_canvas_context,
                    )
                    .await
                    .map_err(|_| InternalApplicationOfferError::Unavailable)?
                    .ok_or(InternalApplicationOfferError::ConcurrentChange)?;
                    database
                        .commit()
                        .await
                        .map_err(|_| InternalApplicationOfferError::Unavailable)?;
                    return Ok(Some(refreshed));
                }
            }

            // A changed terminal generation needs new hashes derived from its
            // new anchor; do not silently reserve with stale request semantics.
            if expected_binding != application.issuance_transaction_id {
                return Err(InternalApplicationOfferError::ConcurrentChange);
            }
            let transaction = match insert_issuance_transaction(&mut *database, prepared)
                .await
                .map_err(|_| InternalApplicationOfferError::Unavailable)?
            {
                Some(transaction) => transaction,
                None => prelocked
                    .filter(|transaction| {
                        transaction.idempotency_request_hash == prepared.idempotency_request_hash
                            && transaction.application_id == prepared.application_id
                    })
                    .ok_or(InternalApplicationOfferError::Unavailable)?,
            };
            let bound = sqlx::query(BIND_OFFER_TRANSACTION)
                .bind(&current.id)
                .bind(&current.organization_id)
                .bind(&transaction.id)
                .bind(&current.issuance_transaction_id)
                .execute(&mut *database)
                .await
                .map_err(offer_repository_error)?;
            if bound.rows_affected() != 1 {
                return Ok(None);
            }
            database
                .commit()
                .await
                .map_err(|_| InternalApplicationOfferError::Unavailable)?;
            return Ok(Some(transaction));
        }
        Err(InternalApplicationOfferError::ConcurrentChange)
    }

    async fn get_offer_transaction(
        &self,
        transaction_id: &str,
        organization_id: &str,
    ) -> Result<Option<CredentialTransaction>, InternalApplicationOfferError> {
        issuance_transaction_by_id(&self.pool, transaction_id, organization_id)
            .await
            .map_err(|_| InternalApplicationOfferError::Unavailable)
    }

    async fn append_offer_event(
        &self,
        event: &IssuanceEventRecord,
    ) -> Result<(), InternalApplicationOfferError> {
        sqlx::query(INSERT_ISSUANCE_EVENT)
            .bind(&event.id)
            .bind(&event.transaction_id)
            .bind(&event.application_id)
            .bind(&event.event_type)
            .bind(Value::Object(event.metadata.clone()))
            .bind(event.created_at)
            .execute(&self.pool)
            .await
            .map_err(offer_repository_error)?;
        Ok(())
    }
}

fn offer_repository_error(cause: sqlx::Error) -> InternalApplicationOfferError {
    error!(%cause, "internal Application offer persistence failed");
    InternalApplicationOfferError::Unavailable
}

fn active_platform(platform: &Map<String, Value>) -> bool {
    platform.get("enabled").and_then(Value::as_bool) == Some(true)
        && platform.get("archived_at").is_none_or(Value::is_null)
}

fn active_binding(binding: &Map<String, Value>) -> bool {
    binding.get("enabled").and_then(Value::as_bool) == Some(true)
        && binding.get("archived_at").is_none_or(Value::is_null)
}

fn canvas_account_id(fact: &EvidenceFactRecord) -> Option<String> {
    fact.scope
        .get("canvas_account_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            fact.source
                .get("mip_receipt")
                .and_then(Value::as_object)
                .and_then(|receipt| receipt.get("source"))
                .and_then(Value::as_object)
                .and_then(|source| source.get("provider_account_id"))
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        })
}

fn validate_reconciliation_write(
    write: &EvidenceReconciliationWrite,
) -> Result<(), EvidenceReconciliationRepositoryError> {
    if write.events.iter().any(|event| {
        event.application_id.as_deref() != Some(write.application.id.as_str())
            || event
                .metadata
                .get("organization_id")
                .and_then(Value::as_str)
                != Some(write.application.organization_id.as_str())
    }) || write.transaction.as_ref().is_some_and(|transaction| {
        transaction.application_id.as_deref() != Some(write.application.id.as_str())
            || transaction.organization_id != write.application.organization_id
            || transaction.status != CredentialTransactionStatus::Pending
    }) || write.transaction.is_some() != write.approval_snapshot.is_some()
    {
        return Err(EvidenceReconciliationRepositoryError::Unavailable);
    }
    Ok(())
}

async fn insert_reconciliation_event(
    database: &mut sqlx::Transaction<'_, Postgres>,
    event: &IssuanceEventRecord,
) -> Result<(), EvidenceReconciliationRepositoryError> {
    sqlx::query(INSERT_ISSUANCE_EVENT)
        .bind(&event.id)
        .bind(&event.transaction_id)
        .bind(&event.application_id)
        .bind(&event.event_type)
        .bind(Value::Object(event.metadata.clone()))
        .bind(event.created_at)
        .execute(&mut **database)
        .await
        .map_err(reconciliation_repository_error)?;
    Ok(())
}

fn reconciliation_receipt_row(
    row: &PgRow,
) -> Result<CanvasEventReceipt, EvidenceReconciliationRepositoryError> {
    Ok(CanvasEventReceipt {
        id: row.try_get("id").map_err(reconciliation_repository_error)?,
        provider_event_id: row
            .try_get("provider_event_id")
            .map_err(reconciliation_repository_error)?,
        canvas_account_id: row
            .try_get("canvas_account_id")
            .map_err(reconciliation_repository_error)?,
        organization_id: row
            .try_get("organization_id")
            .map_err(reconciliation_repository_error)?,
        credential_template_id: row
            .try_get("credential_template_id")
            .map_err(reconciliation_repository_error)?,
        payload_hash: row
            .try_get("payload_hash")
            .map_err(reconciliation_repository_error)?,
        issuance_transaction_id: row
            .try_get("issuance_transaction_id")
            .map_err(reconciliation_repository_error)?,
        issuance_response: row
            .try_get("issuance_response")
            .map_err(reconciliation_repository_error)?,
        status: row
            .try_get("status")
            .map_err(reconciliation_repository_error)?,
        error_summary: row
            .try_get("error_summary")
            .map_err(reconciliation_repository_error)?,
        first_seen_at: row
            .try_get("first_seen_at")
            .map_err(reconciliation_repository_error)?,
        last_seen_at: row
            .try_get("last_seen_at")
            .map_err(reconciliation_repository_error)?,
    })
}

fn reconciliation_repository_error(_cause: sqlx::Error) -> EvidenceReconciliationRepositoryError {
    error!("internal Application evidence reconciliation persistence failed");
    EvidenceReconciliationRepositoryError::Unavailable
}

fn application_row(row: PgRow) -> Result<ApplicationRecord, InternalApplicationRepositoryError> {
    Ok(ApplicationRecord {
        id: get(&row, "id")?,
        organization_id: get(&row, "organization_id")?,
        application_template_id: get(&row, "application_template_id")?,
        applicant_identifier: get(&row, "applicant_identifier")?,
        form_data: json_object(&row, "form_data")?,
        evidence_submissions: json_object_array(&row, "submitted_evidence")?,
        integration_context: json_object(&row, "integration_context")?,
        status: status(&get::<String>(&row, "status")?)?,
        review_notes: get(&row, "review_notes")?,
        reviewer_id: get(&row, "reviewer_id")?,
        rejection_reason: get(&row, "rejection_reason")?,
        derived_claims: json_object(&row, "derived_claims")?,
        issuance_transaction_id: get(&row, "issuance_transaction_id")?,
        credential_id: get(&row, "credential_id")?,
        created_at: get(&row, "created_at")?,
        updated_at: get(&row, "updated_at")?,
        submitted_at: get(&row, "submitted_at")?,
        reviewed_at: get(&row, "reviewed_at")?,
        expires_at: get(&row, "expires_at")?,
    })
}

fn evidence_fact_row(row: PgRow) -> Result<EvidenceFactRecord, InternalApplicationRepositoryError> {
    Ok(EvidenceFactRecord {
        id: get(&row, "id")?,
        organization_id: get(&row, "organization_id")?,
        application_id: get(&row, "application_id")?,
        subject_id: get(&row, "subject_id")?,
        provider: get(&row, "provider")?,
        fact_type: get(&row, "fact_type")?,
        scope: json_object(&row, "scope")?,
        assertion: json_object(&row, "assertion")?,
        verification: json_object(&row, "verification")?,
        source: json_object(&row, "source")?,
        requirement_id: get(&row, "requirement_id")?,
        logical_key: get(&row, "logical_key")?,
        source_revision: get(&row, "source_revision")?,
        payload_hash: get(&row, "payload_hash")?,
        observed_at: get(&row, "observed_at")?,
        effective_at: get(&row, "effective_at")?,
        superseded_fact_id: get(&row, "superseded_fact_id")?,
        created_at: get(&row, "created_at")?,
    })
}

fn issuance_event_row(
    row: PgRow,
) -> Result<IssuanceEventRecord, InternalApplicationRepositoryError> {
    Ok(IssuanceEventRecord {
        id: get(&row, "id")?,
        transaction_id: get(&row, "transaction_id")?,
        application_id: get(&row, "application_id")?,
        event_type: get(&row, "event_type")?,
        metadata: json_object(&row, "metadata")?,
        created_at: get(&row, "created_at")?,
    })
}

fn status(value: &str) -> Result<ApplicationStatus, InternalApplicationRepositoryError> {
    value.parse().map_err(|cause| {
        error!(%cause, status = value, "Application row has an invalid status");
        InternalApplicationRepositoryError::Unavailable
    })
}

fn json_object(
    row: &PgRow,
    name: &str,
) -> Result<Map<String, Value>, InternalApplicationRepositoryError> {
    let value = get::<Value>(row, name)?;
    value.as_object().cloned().ok_or_else(|| {
        error!(column = name, "Application JSON column is not an object");
        InternalApplicationRepositoryError::Unavailable
    })
}

fn json_object_array(
    row: &PgRow,
    name: &str,
) -> Result<Vec<Map<String, Value>>, InternalApplicationRepositoryError> {
    let value = get::<Value>(row, name)?;
    value
        .as_array()
        .ok_or_else(|| {
            error!(column = name, "Application JSON column is not an array");
            InternalApplicationRepositoryError::Unavailable
        })?
        .iter()
        .map(|item| {
            item.as_object().cloned().ok_or_else(|| {
                error!(
                    column = name,
                    "Application JSON array contains a non-object"
                );
                InternalApplicationRepositoryError::Unavailable
            })
        })
        .collect()
}

fn get<'row, T>(row: &'row PgRow, name: &str) -> Result<T, InternalApplicationRepositoryError>
where
    T: sqlx::Decode<'row, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(name).map_err(row_error)
}

fn repository_error(cause: sqlx::Error) -> InternalApplicationRepositoryError {
    error!(%cause, "internal Application repository query failed");
    InternalApplicationRepositoryError::Unavailable
}

fn evidence_repository_error(_cause: sqlx::Error) -> InternalApplicationEvidenceRepositoryError {
    // SQL details may contain provider-derived values. Keep the public error
    // stable and redact the database cause at this boundary.
    error!("internal Application evidence persistence failed");
    InternalApplicationEvidenceRepositoryError::Unavailable
}

fn row_error(cause: sqlx::Error) -> InternalApplicationRepositoryError {
    error!(%cause, "internal Application repository row is invalid");
    InternalApplicationRepositoryError::Unavailable
}
