//! Tenant-qualified PostgreSQL persistence for Application Template management.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use sqlx::{postgres::PgRow, PgPool, Row};
use tracing::error;

use crate::{
    application_template_domain::{ApplicationTemplateRecord, ApplicationTemplateStatus},
    application_template_service::{
        ApplicationTemplateIdempotencyBinding, ApplicationTemplateRepository,
        ApplicationTemplateRepositoryError, ApplicationTemplateReservation, ApprovalPolicyRecord,
    },
};

macro_rules! template_columns {
    () => {
        "id, organization_id, name, description, credential_template_id,
         form_fields, evidence_requirements, claim_collection_rules, required_checks,
         approval_strategy, approval_policy_set_id, application_validity_days,
         ui_config, notification_config, status, management_version,
         created_at, updated_at"
    };
}

const INSERT_IDEMPOTENT: &str = concat!(
    "INSERT INTO issuance_service.application_templates (
        id, organization_id, name, description, credential_template_id,
        form_fields, evidence_requirements, claim_collection_rules, required_checks,
        approval_strategy, approval_policy_set_id, application_validity_days,
        ui_config, notification_config, status, management_version,
        created_at, updated_at, idempotency_key_hash, idempotency_request_hash
     ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
        $11, $12, $13, $14, $15, $16, $17, $18, $19, $20
     )
     ON CONFLICT (organization_id, idempotency_key_hash)
       WHERE idempotency_key_hash IS NOT NULL
     DO NOTHING
     RETURNING ",
    template_columns!()
);

const GET_BY_IDEMPOTENCY_KEY: &str = concat!(
    "SELECT ",
    template_columns!(),
    ", idempotency_request_hash
     FROM issuance_service.application_templates
     WHERE organization_id = $1 AND idempotency_key_hash = $2"
);

const LIST: &str = concat!(
    "SELECT ",
    template_columns!(),
    " FROM issuance_service.application_templates
      WHERE organization_id = $1
      ORDER BY created_at ASC, id ASC"
);

const GET: &str = concat!(
    "SELECT ",
    template_columns!(),
    " FROM issuance_service.application_templates
      WHERE organization_id = $1 AND id = $2"
);

const GET_UNSCOPED: &str = concat!(
    "SELECT ",
    template_columns!(),
    " FROM issuance_service.application_templates
      WHERE id = $1"
);

const REPLACE_IF_VERSION: &str = "UPDATE issuance_service.application_templates
    SET name = $1,
        description = $2,
        credential_template_id = $3,
        form_fields = $4,
        evidence_requirements = $5,
        claim_collection_rules = $6,
        required_checks = $7,
        approval_strategy = $8,
        approval_policy_set_id = $9,
        application_validity_days = $10,
        ui_config = $11,
        notification_config = $12,
        status = $13,
        management_version = $14,
        updated_at = $15
    WHERE organization_id = $16 AND id = $17 AND management_version = $18
    RETURNING management_version";

const DELETE_IF_VERSION: &str = "DELETE FROM issuance_service.application_templates
    WHERE organization_id = $1 AND id = $2 AND management_version = $3";

const GET_APPROVAL_POLICY: &str = "SELECT policy_type, status
    FROM organization_service.policy_sets
    WHERE organization_id = $1 AND id = $2";

#[derive(Clone)]
pub struct PostgresApplicationTemplateRepository {
    pool: PgPool,
}

impl std::fmt::Debug for PostgresApplicationTemplateRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresApplicationTemplateRepository")
            .finish_non_exhaustive()
    }
}

impl PostgresApplicationTemplateRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Internal Application creation must distinguish a missing template from
    /// a foreign-tenant template before applying tenant hiding. Keep that
    /// exceptional lookup crate-private and reuse the canonical row decoder.
    pub(crate) async fn get_unscoped(
        &self,
        template_id: &str,
    ) -> Result<Option<ApplicationTemplateRecord>, ApplicationTemplateRepositoryError> {
        sqlx::query(GET_UNSCOPED)
            .bind(template_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(template_row)
            .transpose()
    }
}

#[async_trait]
impl ApplicationTemplateRepository for PostgresApplicationTemplateRepository {
    async fn reserve_idempotently(
        &self,
        template: &ApplicationTemplateRecord,
        binding: &ApplicationTemplateIdempotencyBinding,
    ) -> Result<ApplicationTemplateReservation, ApplicationTemplateRepositoryError> {
        let validity_days = database_validity_days(template.application_validity_days)?;
        let inserted = sqlx::query(INSERT_IDEMPOTENT)
            .bind(&template.id)
            .bind(&template.organization_id)
            .bind(&template.name)
            .bind(&template.description)
            .bind(&template.credential_template_id)
            .bind(Value::Array(template.form_fields.clone()))
            .bind(Value::Array(template.evidence_requirements.clone()))
            .bind(Value::Array(template.claim_collection_rules.clone()))
            .bind(Value::Array(template.required_checks.clone()))
            .bind(&template.approval_strategy)
            .bind(&template.approval_policy_set_id)
            .bind(validity_days)
            .bind(Value::Object(template.ui_config.clone()))
            .bind(Value::Object(template.notification_config.clone()))
            .bind(template.status.as_str())
            .bind(template.version)
            .bind(template.created_at)
            .bind(template.updated_at)
            .bind(&binding.key_hash)
            .bind(&binding.request_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?;
        if let Some(row) = inserted {
            return Ok(ApplicationTemplateReservation {
                template: template_row(row)?,
                created: true,
            });
        }

        let row = sqlx::query(GET_BY_IDEMPOTENCY_KEY)
            .bind(&template.organization_id)
            .bind(&binding.key_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .ok_or(ApplicationTemplateRepositoryError::Unavailable)?;
        let stored_request_hash: Option<String> =
            row.try_get("idempotency_request_hash").map_err(row_error)?;
        if stored_request_hash.as_deref() != Some(binding.request_hash.as_str()) {
            return Err(ApplicationTemplateRepositoryError::IdempotencyConflict);
        }
        Ok(ApplicationTemplateReservation {
            template: template_row(row)?,
            created: false,
        })
    }

    async fn list(
        &self,
        organization_id: &str,
    ) -> Result<Vec<ApplicationTemplateRecord>, ApplicationTemplateRepositoryError> {
        sqlx::query(LIST)
            .bind(organization_id)
            .fetch_all(&self.pool)
            .await
            .map_err(repository_error)?
            .into_iter()
            .map(template_row)
            .collect()
    }

    async fn get(
        &self,
        organization_id: &str,
        template_id: &str,
    ) -> Result<Option<ApplicationTemplateRecord>, ApplicationTemplateRepositoryError> {
        sqlx::query(GET)
            .bind(organization_id)
            .bind(template_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(template_row)
            .transpose()
    }

    async fn replace_if_version(
        &self,
        template: &ApplicationTemplateRecord,
        expected_version: i64,
    ) -> Result<(), ApplicationTemplateRepositoryError> {
        let validity_days = database_validity_days(template.application_validity_days)?;
        let version = sqlx::query_scalar::<_, i64>(REPLACE_IF_VERSION)
            .bind(&template.name)
            .bind(&template.description)
            .bind(&template.credential_template_id)
            .bind(Value::Array(template.form_fields.clone()))
            .bind(Value::Array(template.evidence_requirements.clone()))
            .bind(Value::Array(template.claim_collection_rules.clone()))
            .bind(Value::Array(template.required_checks.clone()))
            .bind(&template.approval_strategy)
            .bind(&template.approval_policy_set_id)
            .bind(validity_days)
            .bind(Value::Object(template.ui_config.clone()))
            .bind(Value::Object(template.notification_config.clone()))
            .bind(template.status.as_str())
            .bind(template.version)
            .bind(template.updated_at)
            .bind(&template.organization_id)
            .bind(&template.id)
            .bind(expected_version)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?;
        if version != Some(template.version) {
            return Err(ApplicationTemplateRepositoryError::ConcurrentModification);
        }
        Ok(())
    }

    async fn delete_if_version(
        &self,
        organization_id: &str,
        template_id: &str,
        expected_version: i64,
    ) -> Result<(), ApplicationTemplateRepositoryError> {
        let affected = sqlx::query(DELETE_IF_VERSION)
            .bind(organization_id)
            .bind(template_id)
            .bind(expected_version)
            .execute(&self.pool)
            .await
            .map_err(repository_error)?
            .rows_affected();
        if affected != 1 {
            return Err(ApplicationTemplateRepositoryError::ConcurrentModification);
        }
        Ok(())
    }

    async fn approval_policy(
        &self,
        organization_id: &str,
        policy_set_id: &str,
    ) -> Result<Option<ApprovalPolicyRecord>, ApplicationTemplateRepositoryError> {
        sqlx::query_as::<_, (String, String)>(GET_APPROVAL_POLICY)
            .bind(organization_id)
            .bind(policy_set_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)
            .map(|value| {
                value.map(|(policy_type, status)| ApprovalPolicyRecord {
                    policy_type,
                    status,
                })
            })
    }
}

fn template_row(
    row: PgRow,
) -> Result<ApplicationTemplateRecord, ApplicationTemplateRepositoryError> {
    Ok(ApplicationTemplateRecord {
        id: get(&row, "id")?,
        organization_id: get(&row, "organization_id")?,
        name: get(&row, "name")?,
        description: get(&row, "description")?,
        credential_template_id: get(&row, "credential_template_id")?,
        form_fields: json_array(&row, "form_fields")?,
        evidence_requirements: json_array(&row, "evidence_requirements")?,
        claim_collection_rules: json_array(&row, "claim_collection_rules")?,
        required_checks: json_array(&row, "required_checks")?,
        approval_strategy: get(&row, "approval_strategy")?,
        approval_policy_set_id: get(&row, "approval_policy_set_id")?,
        application_validity_days: i64::from(get::<i32>(&row, "application_validity_days")?),
        ui_config: json_object(&row, "ui_config")?,
        notification_config: json_object(&row, "notification_config")?,
        status: status(&get::<String>(&row, "status")?)?,
        version: get(&row, "management_version")?,
        created_at: get::<DateTime<Utc>>(&row, "created_at")?,
        updated_at: get::<DateTime<Utc>>(&row, "updated_at")?,
    })
}

fn status(value: &str) -> Result<ApplicationTemplateStatus, ApplicationTemplateRepositoryError> {
    match value.trim().to_ascii_uppercase().as_str() {
        "DRAFT" => Ok(ApplicationTemplateStatus::Draft),
        "ACTIVE" => Ok(ApplicationTemplateStatus::Active),
        "DEPRECATED" => Ok(ApplicationTemplateStatus::Deprecated),
        _ => {
            error!(
                status = value,
                "application template row has an invalid status"
            );
            Err(ApplicationTemplateRepositoryError::Unavailable)
        }
    }
}

fn database_validity_days(value: i64) -> Result<i32, ApplicationTemplateRepositoryError> {
    i32::try_from(value).map_err(|cause| {
        error!(%cause, value, "application template validity does not fit PostgreSQL INTEGER");
        ApplicationTemplateRepositoryError::Unavailable
    })
}

fn json_array(row: &PgRow, name: &str) -> Result<Vec<Value>, ApplicationTemplateRepositoryError> {
    let value = get::<Value>(row, name)?;
    value.as_array().cloned().ok_or_else(|| {
        error!(
            column = name,
            "application template JSON column is not an array"
        );
        ApplicationTemplateRepositoryError::Unavailable
    })
}

fn json_object(
    row: &PgRow,
    name: &str,
) -> Result<Map<String, Value>, ApplicationTemplateRepositoryError> {
    let value = get::<Value>(row, name)?;
    value.as_object().cloned().ok_or_else(|| {
        error!(
            column = name,
            "application template JSON column is not an object"
        );
        ApplicationTemplateRepositoryError::Unavailable
    })
}

fn get<'row, T>(row: &'row PgRow, name: &str) -> Result<T, ApplicationTemplateRepositoryError>
where
    T: sqlx::Decode<'row, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(name).map_err(row_error)
}

fn repository_error(cause: sqlx::Error) -> ApplicationTemplateRepositoryError {
    error!(%cause, "application template repository query failed");
    ApplicationTemplateRepositoryError::Unavailable
}

fn row_error(cause: sqlx::Error) -> ApplicationTemplateRepositoryError {
    error!(%cause, "application template repository row is invalid");
    ApplicationTemplateRepositoryError::Unavailable
}
