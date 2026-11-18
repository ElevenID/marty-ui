use async_trait::async_trait;
use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{validate_transition, DelegationGrant, DelegationGrantRepository, GrantStatus, RepositoryError};

#[derive(Clone)]
pub struct PgDelegationGrantRepository {
    pool: PgPool,
}
impl PgDelegationGrantRepository {
    pub fn new(pool: PgPool) -> Self { Self { pool } }
    pub fn pool(&self) -> &PgPool { &self.pool }
}
#[async_trait]
impl DelegationGrantRepository for PgDelegationGrantRepository {
    async fn insert(&self, grant: DelegationGrant) -> Result<(), RepositoryError> {
        let document = serde_json::to_value(&grant)
            .map_err(|error| RepositoryError::Failure(error.to_string()))?;
        sqlx::query(
            "INSERT INTO delegated_authority_service.delegation_grants
             (id, organization_id, status, revision, terms_digest, grant_document, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)"
        )
        .bind(grant.id)
        .bind(grant.organization_id)
        .bind(grant.status.as_str())
        .bind(i64::try_from(grant.revision).map_err(|_| RepositoryError::Failure("revision exceeds PostgreSQL BIGINT".into()))?)
        .bind(&grant.terms_digest)
        .bind(document)
        .bind(grant.created_at)
        .bind(grant.updated_at)
        .execute(&self.pool).await.map_err(map_database)?;
        Ok(())
    }

    async fn get(&self, organization_id: Uuid, grant_id: Uuid)
        -> Result<Option<DelegationGrant>, RepositoryError> {
        let row = sqlx::query(
            "SELECT grant_document FROM delegated_authority_service.delegation_grants
             WHERE organization_id=$1 AND id=$2"
        ).bind(organization_id).bind(grant_id).fetch_optional(&self.pool).await.map_err(map_database)?;
        row.map(|row| decode(row.try_get("grant_document").map_err(map_database)?)).transpose()
    }

    async fn compare_and_swap(&self, organization_id: Uuid, grant_id: Uuid, expected_revision: u64,
        replacement: DelegationGrant) -> Result<DelegationGrant, RepositoryError> {
        let current = self.get(organization_id, grant_id).await?.ok_or(RepositoryError::NotFound)?;
        if current.revision != expected_revision { return Err(RepositoryError::RevisionConflict); }
        validate_transition(&current, &replacement)
            .map_err(|error| RepositoryError::Failure(error.to_string()))?;
        let document = serde_json::to_value(&replacement)
            .map_err(|error| RepositoryError::Failure(error.to_string()))?;
        let old_terms = serde_json::to_value(&current.terms)
            .map_err(|error| RepositoryError::Failure(error.to_string()))?;
        let old_authority = serde_json::to_value(&current.authority)
            .map_err(|error| RepositoryError::Failure(error.to_string()))?;
        let row = sqlx::query(
            "UPDATE delegated_authority_service.delegation_grants
             SET status=$1, revision=$2, grant_document=$3, updated_at=$4
             WHERE organization_id=$5 AND id=$6 AND revision=$7 AND terms_digest=$8
               AND grant_document->'terms'=$9 AND grant_document->'authority'=$10
             RETURNING grant_document"
        )
        .bind(replacement.status.as_str())
        .bind(i64::try_from(replacement.revision).map_err(|_| RepositoryError::Failure("revision exceeds PostgreSQL BIGINT".into()))?)
        .bind(document)
        .bind(replacement.updated_at)
        .bind(organization_id)
        .bind(grant_id)
        .bind(i64::try_from(expected_revision).map_err(|_| RepositoryError::Failure("revision exceeds PostgreSQL BIGINT".into()))?)
        .bind(&current.terms_digest)
        .bind(old_terms)
        .bind(old_authority)
        .fetch_optional(&self.pool).await.map_err(map_database)?;
        match row {
            Some(row) => decode(row.try_get("grant_document").map_err(map_database)?).map_err(Into::into),
            None => {
                if self.get(organization_id, grant_id).await?.is_some() {
                    Err(RepositoryError::RevisionConflict)
                } else { Err(RepositoryError::NotFound) }
            }
        }
    }

    async fn list(&self, organization_id: Uuid, status: Option<GrantStatus>)
        -> Result<Vec<DelegationGrant>, RepositoryError> {
        let rows = if let Some(status) = status {
            sqlx::query("SELECT grant_document FROM delegated_authority_service.delegation_grants
                WHERE organization_id=$1 AND status=$2 ORDER BY created_at,id")
                .bind(organization_id).bind(status.as_str()).fetch_all(&self.pool).await.map_err(map_database)?
        } else {
            sqlx::query("SELECT grant_document FROM delegated_authority_service.delegation_grants
                WHERE organization_id=$1 ORDER BY created_at,id")
                .bind(organization_id).fetch_all(&self.pool).await.map_err(map_database)?
        };
        rows.into_iter().map(|row| decode(row.try_get("grant_document").map_err(map_database)?))
            .collect()
    }
}
fn decode(value: Value) -> Result<DelegationGrant, RepositoryError> {
    serde_json::from_value(value).map_err(|error| RepositoryError::Failure(format!("stored grant document is invalid: {error}")))
}
fn map_database(error: sqlx::Error) -> RepositoryError {
    if let sqlx::Error::Database(database) = &error {
        if database.code().as_deref() == Some("23505") { return RepositoryError::AlreadyExists; }
    }
    RepositoryError::Failure(error.to_string())
}
