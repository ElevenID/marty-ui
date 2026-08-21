use async_trait::async_trait;
use sqlx::{postgres::PgRow, PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    PolicyRecord, PolicyRecordError, PolicyRepository, PresentationPolicy,
    PRESENTATION_POLICY_MIGRATION,
};

const ADVISORY_LOCK_ID: i64 = 718_431_219;
const REQUIRED_COLUMNS: [&str; 13] = [
    "id",
    "organization_id",
    "name",
    "description",
    "status",
    "display_metadata",
    "credential_requirements",
    "alternative_requirements",
    "compliance_profile_id",
    "version",
    "created_at",
    "updated_at",
    "policy_document",
];

#[derive(Debug, Error)]
pub enum PostgresPolicyStoreError {
    #[error("PRESENTATION_POLICY.DATABASE: {0}")]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Record(#[from] PolicyRecordError),
    #[error("PRESENTATION_POLICY.SCHEMA: {0}")]
    Schema(String),
}

#[derive(Clone, Debug)]
pub struct PostgresPolicyStore {
    pool: PgPool,
}

impl PostgresPolicyStore {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn save_policy(
        &self,
        policy: &PresentationPolicy,
    ) -> Result<(), PostgresPolicyStoreError> {
        let record = PolicyRecord::from_policy(policy)?;
        sqlx::query(
            "INSERT INTO presentation_policy_service.presentation_policies (
                id, organization_id, name, description, status, display_metadata,
                credential_requirements, alternative_requirements, compliance_profile_id,
                version, created_at, updated_at, policy_document
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
             ON CONFLICT (id) DO UPDATE SET
                organization_id=EXCLUDED.organization_id,
                name=EXCLUDED.name,
                description=EXCLUDED.description,
                status=EXCLUDED.status,
                display_metadata=EXCLUDED.display_metadata,
                credential_requirements=EXCLUDED.credential_requirements,
                alternative_requirements=EXCLUDED.alternative_requirements,
                compliance_profile_id=EXCLUDED.compliance_profile_id,
                version=EXCLUDED.version,
                updated_at=EXCLUDED.updated_at,
                policy_document=EXCLUDED.policy_document",
        )
        .bind(record.id)
        .bind(record.organization_id)
        .bind(record.name)
        .bind(record.description)
        .bind(record.status)
        .bind(record.display_metadata)
        .bind(record.credential_requirements)
        .bind(record.alternative_requirements)
        .bind(record.compliance_profile_id)
        .bind(record.version)
        .bind(record.created_at)
        .bind(record.updated_at)
        .bind(record.policy_document)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn policy_by_id(
        &self,
        policy_id: Uuid,
    ) -> Result<Option<PresentationPolicy>, PostgresPolicyStoreError> {
        sqlx::query("SELECT * FROM presentation_policy_service.presentation_policies WHERE id=$1")
            .bind(policy_id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(policy_from_row)
            .transpose()
    }

    pub async fn policies_by_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<PresentationPolicy>, PostgresPolicyStoreError> {
        sqlx::query(
            "SELECT * FROM presentation_policy_service.presentation_policies
             WHERE organization_id=$1 ORDER BY created_at DESC, id",
        )
        .bind(organization_id.to_string())
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(policy_from_row)
        .collect()
    }

    pub async fn delete_policy(&self, policy_id: Uuid) -> Result<(), PostgresPolicyStoreError> {
        sqlx::query("DELETE FROM presentation_policy_service.presentation_policies WHERE id=$1")
            .bind(policy_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl PolicyRepository for PostgresPolicyStore {
    async fn save(&self, policy: &PresentationPolicy) -> Result<(), String> {
        self.save_policy(policy)
            .await
            .map_err(|error| error.to_string())
    }

    async fn get(&self, policy_id: Uuid) -> Result<Option<PresentationPolicy>, String> {
        self.policy_by_id(policy_id)
            .await
            .map_err(|error| error.to_string())
    }

    async fn list(&self, organization_id: Uuid) -> Result<Vec<PresentationPolicy>, String> {
        self.policies_by_organization(organization_id)
            .await
            .map_err(|error| error.to_string())
    }

    async fn delete(&self, policy_id: Uuid) -> Result<(), String> {
        self.delete_policy(policy_id)
            .await
            .map_err(|error| error.to_string())
    }
}

pub async fn migrate_presentation_policy_schema(
    pool: &PgPool,
) -> Result<(), PostgresPolicyStoreError> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(ADVISORY_LOCK_ID)
        .execute(&mut *transaction)
        .await?;
    sqlx::raw_sql(PRESENTATION_POLICY_MIGRATION)
        .execute(&mut *transaction)
        .await?;
    validate(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn validate_presentation_policy_schema(
    pool: &PgPool,
) -> Result<(), PostgresPolicyStoreError> {
    let mut connection = pool.acquire().await?;
    validate(&mut connection).await
}

async fn validate(connection: &mut sqlx::PgConnection) -> Result<(), PostgresPolicyStoreError> {
    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns
         WHERE table_schema='presentation_policy_service'
           AND table_name='presentation_policies'",
    )
    .fetch_all(&mut *connection)
    .await?;
    for required in REQUIRED_COLUMNS {
        if !columns.iter().any(|column| column == required) {
            return Err(PostgresPolicyStoreError::Schema(format!(
                "missing presentation_policies.{required}"
            )));
        }
    }
    Ok(())
}

fn policy_from_row(row: &PgRow) -> Result<PresentationPolicy, PostgresPolicyStoreError> {
    PolicyRecord {
        id: row.try_get("id")?,
        organization_id: row.try_get("organization_id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        status: row.try_get("status")?,
        display_metadata: row.try_get("display_metadata")?,
        credential_requirements: row.try_get("credential_requirements")?,
        alternative_requirements: row.try_get("alternative_requirements")?,
        compliance_profile_id: row.try_get("compliance_profile_id")?,
        version: row.try_get("version")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        policy_document: row.try_get("policy_document")?,
    }
    .into_policy()
    .map_err(Into::into)
}
