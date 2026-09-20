//! PostgreSQL persistence for internal Application management.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use sqlx::{postgres::PgRow, PgPool, Row};
use tracing::error;

use crate::{
    application_template_domain::ApplicationTemplateRecord,
    application_template_postgres::PostgresApplicationTemplateRepository,
    internal_application_domain::{
        ApplicationRecord, ApplicationStatus, EvidenceFactRecord, IssuanceEventRecord,
    },
    internal_application_service::{
        InternalApplicationRepository, InternalApplicationRepositoryError,
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
            .execute(&self.pool)
            .await
            .map_err(repository_error)?
            .rows_affected();
        Ok(affected == 1)
    }
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
