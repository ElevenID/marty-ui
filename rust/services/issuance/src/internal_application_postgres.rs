//! PostgreSQL persistence for internal Application management.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use sqlx::{postgres::PgRow, Executor, PgPool, Postgres, Row};
use tracing::error;

use crate::{
    application_template_domain::ApplicationTemplateRecord,
    application_template_postgres::PostgresApplicationTemplateRepository,
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
    internal_application_offer::{
        InternalApplicationOfferError, InternalApplicationOfferRepository,
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

fn row_error(cause: sqlx::Error) -> InternalApplicationRepositoryError {
    error!(%cause, "internal Application repository row is invalid");
    InternalApplicationRepositoryError::Unavailable
}
