//! Durable physical-document jobs, scoped by an authenticated passport tenant.

use chrono::{DateTime, Utc};
use marty_passport_auth::PassportTenantPrincipal;
use serde_json::Value;
use sqlx::{postgres::PgRow, PgPool, Row};

pub struct PassportJobInsert {
    pub id: String,
    pub application_id: String,
    pub flow_execution_id: String,
    pub application_template_id: String,
    pub credential_template_id: String,
    pub revocation_profile_id: Option<String>,
    pub delivery_destination_profile_id: String,
    pub document_type: String,
    pub country_code: String,
    pub secure_artifact_ciphertext: String,
    pub secure_artifact_reference: String,
}

/// The ciphertext is intentionally kept out of Debug and HTTP projections.
pub struct PassportJob {
    pub id: String,
    pub organization_id: String,
    pub flow_execution_id: String,
    pub application_id: String,
    pub application_template_id: String,
    pub credential_template_id: String,
    pub revocation_profile_id: Option<String>,
    pub delivery_destination_profile_id: String,
    pub document_type: String,
    pub country_code: String,
    pub secure_artifact_ciphertext: String,
    pub secure_artifact_reference: String,
    pub sod_sha256: Option<String>,
    pub bureau_job_id: Option<String>,
    pub tracking_number: Option<String>,
    pub status: String,
    pub quality_result: Option<Value>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub submitted_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct PostgresPassportRepository {
    pool: PgPool,
}

impl PostgresPassportRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn insert(
        &self,
        principal: &PassportTenantPrincipal,
        job: &PassportJobInsert,
        now: DateTime<Utc>,
    ) -> Result<PassportJob, sqlx::Error> {
        let row = sqlx::query(
            "INSERT INTO issuance_service.physical_document_jobs (
                id, organization_id, flow_execution_id, application_id,
                application_template_id, credential_template_id, revocation_profile_id,
                delivery_destination_profile_id, document_type, country_code,
                secure_artifact_ciphertext, secure_artifact_reference, status,
                created_at, updated_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'DRAFT',$13,$13)
            RETURNING *",
        )
        .bind(&job.id)
        .bind(principal.organization_id())
        .bind(&job.flow_execution_id)
        .bind(&job.application_id)
        .bind(&job.application_template_id)
        .bind(&job.credential_template_id)
        .bind(&job.revocation_profile_id)
        .bind(&job.delivery_destination_profile_id)
        .bind(&job.document_type)
        .bind(&job.country_code)
        .bind(&job.secure_artifact_ciphertext)
        .bind(&job.secure_artifact_reference)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        row_to_job(&row)
    }

    pub async fn get(
        &self,
        principal: &PassportTenantPrincipal,
        application_id: &str,
    ) -> Result<Option<PassportJob>, sqlx::Error> {
        sqlx::query(
            "SELECT * FROM issuance_service.physical_document_jobs
             WHERE organization_id = $1 AND application_id = $2",
        )
        .bind(principal.organization_id())
        .bind(application_id)
        .fetch_optional(&self.pool)
        .await?
        .as_ref()
        .map(row_to_job)
        .transpose()
    }
}

fn row_to_job(row: &PgRow) -> Result<PassportJob, sqlx::Error> {
    Ok(PassportJob {
        id: row.try_get("id")?,
        organization_id: row.try_get("organization_id")?,
        flow_execution_id: row.try_get("flow_execution_id")?,
        application_id: row.try_get("application_id")?,
        application_template_id: row.try_get("application_template_id")?,
        credential_template_id: row.try_get("credential_template_id")?,
        revocation_profile_id: row.try_get("revocation_profile_id")?,
        delivery_destination_profile_id: row.try_get("delivery_destination_profile_id")?,
        document_type: row.try_get("document_type")?,
        country_code: row.try_get("country_code")?,
        secure_artifact_ciphertext: row.try_get("secure_artifact_ciphertext")?,
        secure_artifact_reference: row.try_get("secure_artifact_reference")?,
        sod_sha256: row.try_get("sod_sha256")?,
        bureau_job_id: row.try_get("bureau_job_id")?,
        tracking_number: row.try_get("tracking_number")?,
        status: row.try_get("status")?,
        quality_result: row.try_get("quality_result")?,
        error_code: row.try_get("error_code")?,
        error_message: row.try_get("error_message")?,
        submitted_at: row.try_get("submitted_at")?,
        completed_at: row.try_get("completed_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}
