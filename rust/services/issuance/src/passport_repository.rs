//! Durable physical-document jobs, scoped by an authenticated passport tenant.

use chrono::{DateTime, Utc};
use marty_passport_auth::PassportTenantPrincipal;
use serde_json::Value;
use sqlx::{postgres::PgRow, PgPool, Postgres, QueryBuilder, Row};

use crate::passport_bureau::VerifiedWebhookEvent;

#[derive(Debug, thiserror::Error)]
pub enum PassportWebhookRepositoryError {
    #[error("physical document repository failed")]
    Storage(#[from] sqlx::Error),
    #[error("bureau job ID identifies multiple physical documents")]
    AmbiguousBureauJob,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PassportJobStatus {
    Draft,
    DataGenerated,
    SodSigned,
    Submitted,
    InProduction,
    QualityCheck,
    ReadyForActivation,
    Failed,
    Cancelled,
    Active,
}

impl PassportJobStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "DRAFT",
            Self::DataGenerated => "DATA_GENERATED",
            Self::SodSigned => "SOD_SIGNED",
            Self::Submitted => "SUBMITTED",
            Self::InProduction => "IN_PRODUCTION",
            Self::QualityCheck => "QUALITY_CHECK",
            Self::ReadyForActivation => "READY_FOR_ACTIVATION",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
            Self::Active => "ACTIVE",
        }
    }
}

pub struct PassportJobPatch {
    pub status: PassportJobStatus,
    pub sod_sha256: Option<Option<String>>,
    pub bureau_job_id: Option<Option<String>>,
    pub tracking_number: Option<Option<String>>,
    pub quality_result: Option<Option<Value>>,
    pub error_code: Option<Option<String>>,
    pub error_message: Option<Option<String>>,
    pub submitted_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub secure_artifact_ciphertext: Option<String>,
}

impl PassportJobPatch {
    #[must_use]
    pub fn new(status: PassportJobStatus) -> Self {
        Self {
            status,
            sod_sha256: None,
            bureau_job_id: None,
            tracking_number: None,
            quality_result: None,
            error_code: None,
            error_message: None,
            submitted_at: None,
            completed_at: None,
            secure_artifact_ciphertext: None,
        }
    }
}

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
    pub issuer_did: Option<String>,
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
    pub issuer_did: Option<String>,
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
                delivery_destination_profile_id, document_type, country_code, issuer_did,
                secure_artifact_ciphertext, secure_artifact_reference, status,
                created_at, updated_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'DRAFT',$14,$14)
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
        .bind(&job.issuer_did)
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

    pub async fn update(
        &self,
        principal: &PassportTenantPrincipal,
        application_id: &str,
        expected_status: &str,
        patch: &PassportJobPatch,
        now: DateTime<Utc>,
    ) -> Result<Option<PassportJob>, sqlx::Error> {
        let mut query = QueryBuilder::<Postgres>::new(
            "UPDATE issuance_service.physical_document_jobs SET status = ",
        );
        query.push_bind(patch.status.as_str());
        query.push(", updated_at = ").push_bind(now);
        macro_rules! nullable_change {
            ($field:ident) => {
                if let Some(value) = &patch.$field {
                    query
                        .push(concat!(", ", stringify!($field), " = "))
                        .push_bind(value);
                }
            };
        }
        nullable_change!(sod_sha256);
        nullable_change!(bureau_job_id);
        nullable_change!(tracking_number);
        nullable_change!(quality_result);
        nullable_change!(error_code);
        nullable_change!(error_message);
        if let Some(value) = patch.submitted_at {
            query.push(", submitted_at = ").push_bind(value);
        }
        if let Some(value) = patch.completed_at {
            query.push(", completed_at = ").push_bind(value);
        }
        if let Some(value) = &patch.secure_artifact_ciphertext {
            query
                .push(", secure_artifact_ciphertext = ")
                .push_bind(value);
        }
        query
            .push(" WHERE organization_id = ")
            .push_bind(principal.organization_id())
            .push(" AND application_id = ")
            .push_bind(application_id)
            .push(" AND status = ")
            .push_bind(expected_status)
            .push(" RETURNING *");
        query
            .build()
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(row_to_job)
            .transpose()
    }

    pub async fn apply_verified_webhook(
        &self,
        event: &VerifiedWebhookEvent,
        now: DateTime<Utc>,
    ) -> Result<Option<PassportJob>, PassportWebhookRepositoryError> {
        let mut transaction = self.pool.begin().await?;
        let matches = sqlx::query(
            "SELECT * FROM issuance_service.physical_document_jobs
             WHERE bureau_job_id = $1 AND organization_id = $2 LIMIT 2 FOR UPDATE",
        )
        .bind(event.bureau_job_id())
        .bind(event.organization_id())
        .fetch_all(&mut *transaction)
        .await?;
        if matches.len() > 1 {
            return Err(PassportWebhookRepositoryError::AmbiguousBureauJob);
        }
        let Some(matched) = matches.first() else {
            return Ok(None);
        };
        let current_status: &str = matched.try_get("status")?;
        if !should_apply_webhook_status(current_status, event.status().issuance_status()) {
            let unchanged = row_to_job(matched)?;
            transaction.commit().await?;
            return Ok(Some(unchanged));
        }
        let id: &str = matched.try_get("id")?;
        let organization_id: &str = matched.try_get("organization_id")?;
        let updated = sqlx::query(
            "UPDATE issuance_service.physical_document_jobs
             SET status = $1, tracking_number = $2, error_message = $3, updated_at = $4
             WHERE id = $5 AND organization_id = $6 AND bureau_job_id = $7
             RETURNING *",
        )
        .bind(event.status().issuance_status())
        .bind(event.tracking_number())
        .bind(event.error_message())
        .bind(now)
        .bind(id)
        .bind(organization_id)
        .bind(event.bureau_job_id())
        .fetch_optional(&mut *transaction)
        .await?;
        transaction.commit().await?;
        updated
            .as_ref()
            .map(row_to_job)
            .transpose()
            .map_err(Into::into)
    }
}

fn should_apply_webhook_status(current: &str, incoming: &str) -> bool {
    if matches!(current, "ACTIVE" | "FAILED" | "CANCELLED") {
        return false;
    }
    if matches!(incoming, "FAILED" | "CANCELLED") {
        return true;
    }
    let rank = |status| match status {
        "SUBMITTED" => Some(1),
        "IN_PRODUCTION" => Some(2),
        "QUALITY_CHECK" => Some(3),
        "READY_FOR_ACTIVATION" => Some(4),
        _ => None,
    };
    match (rank(current), rank(incoming)) {
        (Some(current), Some(incoming)) => incoming >= current,
        _ => true,
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
        issuer_did: row.try_get("issuer_did")?,
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

#[cfg(test)]
mod webhook_state_tests {
    use super::should_apply_webhook_status;
    use serde_json::Value;

    #[test]
    fn stale_or_terminal_callback_never_rewinds_a_document() {
        let contract: Value = serde_json::from_str(include_str!(
            "../../../../contracts/passport-webhook-progress-behavior.json"
        ))
        .unwrap();
        assert_eq!(contract["schema_version"], 1);
        for (field, expected) in [
            ("accepted_transitions", true),
            ("ignored_transitions", false),
        ] {
            for pair in contract[field].as_array().unwrap() {
                assert_eq!(
                    should_apply_webhook_status(
                        pair[0].as_str().unwrap(),
                        pair[1].as_str().unwrap()
                    ),
                    expected,
                    "transition: {pair}"
                );
            }
        }
    }
}
