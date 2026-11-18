use crate::operations::{
    CascadeOperationType, CascadeRevocationOperation, CascadeStatus, OperationError,
    RevocationBatch, RevocationBatchStatus, RevocationOperationRepository, TriggerEntityType,
};
use async_trait::async_trait;
use serde_json::Value;
use sqlx::{postgres::PgRow, PgPool, Row};

#[derive(Debug, Clone)]
pub struct PgRevocationOperationRepository {
    pool: PgPool,
}

impl PgRevocationOperationRepository {
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn connect(database_url: &str) -> Result<Self, OperationError> {
        let pool = PgPool::connect(database_url).await.map_err(storage_error)?;
        Ok(Self::from_pool(pool))
    }
}

#[async_trait]
impl RevocationOperationRepository for PgRevocationOperationRepository {
    async fn save_cascade(
        &self,
        operation: CascadeRevocationOperation,
    ) -> Result<(), OperationError> {
        sqlx::query(
            r#"
            INSERT INTO revocation_profile_service.cascade_revocation_operations (
                id, organization_id, operation_type, trigger_entity_type,
                trigger_entity_id, status, affected_credential_count,
                affected_credential_ids, requires_confirmation, confirmed_at,
                confirmed_by, max_cascade_depth, current_depth,
                circuit_breaker_threshold, circuit_breaker_triggered,
                can_rollback, rollback_snapshot, rolled_back_at, rolled_back_by,
                error_message, metadata, created_at, updated_at, completed_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24
            )
            ON CONFLICT (id) DO UPDATE SET
                organization_id = EXCLUDED.organization_id,
                operation_type = EXCLUDED.operation_type,
                trigger_entity_type = EXCLUDED.trigger_entity_type,
                trigger_entity_id = EXCLUDED.trigger_entity_id,
                status = EXCLUDED.status,
                affected_credential_count = EXCLUDED.affected_credential_count,
                affected_credential_ids = EXCLUDED.affected_credential_ids,
                requires_confirmation = EXCLUDED.requires_confirmation,
                confirmed_at = EXCLUDED.confirmed_at,
                confirmed_by = EXCLUDED.confirmed_by,
                max_cascade_depth = EXCLUDED.max_cascade_depth,
                current_depth = EXCLUDED.current_depth,
                circuit_breaker_threshold = EXCLUDED.circuit_breaker_threshold,
                circuit_breaker_triggered = EXCLUDED.circuit_breaker_triggered,
                can_rollback = EXCLUDED.can_rollback,
                rollback_snapshot = EXCLUDED.rollback_snapshot,
                rolled_back_at = EXCLUDED.rolled_back_at,
                rolled_back_by = EXCLUDED.rolled_back_by,
                error_message = EXCLUDED.error_message,
                metadata = EXCLUDED.metadata,
                updated_at = EXCLUDED.updated_at,
                completed_at = EXCLUDED.completed_at
            "#,
        )
        .bind(&operation.id)
        .bind(&operation.organization_id)
        .bind(cascade_operation_type_name(operation.operation_type))
        .bind(trigger_entity_type_name(operation.trigger_entity_type))
        .bind(&operation.trigger_entity_id)
        .bind(cascade_status_name(operation.status))
        .bind(to_i64(operation.affected_credential_count)?)
        .bind(serde_json::to_value(&operation.affected_credential_ids).map_err(storage_error)?)
        .bind(operation.requires_confirmation)
        .bind(operation.confirmed_at)
        .bind(&operation.confirmed_by)
        .bind(i16::from(operation.max_cascade_depth))
        .bind(i16::from(operation.current_depth))
        .bind(to_i64(operation.circuit_breaker_threshold)?)
        .bind(operation.circuit_breaker_triggered)
        .bind(operation.can_rollback)
        .bind(operation.rollback_snapshot)
        .bind(operation.rolled_back_at)
        .bind(&operation.rolled_back_by)
        .bind(&operation.error_message)
        .bind(operation.metadata)
        .bind(operation.created_at)
        .bind(operation.updated_at)
        .bind(operation.completed_at)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(())
    }

    async fn get_cascade(
        &self,
        operation_id: &str,
    ) -> Result<Option<CascadeRevocationOperation>, OperationError> {
        sqlx::query(
            "SELECT * FROM revocation_profile_service.cascade_revocation_operations WHERE id = $1",
        )
        .bind(operation_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?
        .map(row_to_cascade)
        .transpose()
    }

    async fn list_cascades(
        &self,
        organization_id: &str,
        status: Option<CascadeStatus>,
    ) -> Result<Vec<CascadeRevocationOperation>, OperationError> {
        let rows = sqlx::query(
            r#"
            SELECT * FROM revocation_profile_service.cascade_revocation_operations
            WHERE organization_id = $1 AND ($2::text IS NULL OR status = $2)
            ORDER BY created_at DESC
            "#,
        )
        .bind(organization_id)
        .bind(status.map(cascade_status_name))
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        rows.into_iter().map(row_to_cascade).collect()
    }

    async fn delete_cascade(&self, operation_id: &str) -> Result<bool, OperationError> {
        let result = sqlx::query(
            "DELETE FROM revocation_profile_service.cascade_revocation_operations WHERE id = $1",
        )
        .bind(operation_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn save_batch(&self, batch: RevocationBatch) -> Result<(), OperationError> {
        sqlx::query(
            r#"
            INSERT INTO revocation_profile_service.revocation_batches (
                id, organization_id, revocation_profile_id, batch_interval,
                credential_format, credential_ids, status, created_at, published_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (id) DO UPDATE SET
                organization_id = EXCLUDED.organization_id,
                revocation_profile_id = EXCLUDED.revocation_profile_id,
                batch_interval = EXCLUDED.batch_interval,
                credential_format = EXCLUDED.credential_format,
                credential_ids = EXCLUDED.credential_ids,
                status = EXCLUDED.status,
                published_at = EXCLUDED.published_at
            "#,
        )
        .bind(&batch.id)
        .bind(&batch.organization_id)
        .bind(&batch.revocation_profile_id)
        .bind(&batch.batch_interval)
        .bind(&batch.credential_format)
        .bind(serde_json::to_value(&batch.credential_ids).map_err(storage_error)?)
        .bind(batch_status_name(batch.status))
        .bind(batch.created_at)
        .bind(batch.published_at)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(())
    }

    async fn get_batch(&self, batch_id: &str) -> Result<Option<RevocationBatch>, OperationError> {
        sqlx::query("SELECT * FROM revocation_profile_service.revocation_batches WHERE id = $1")
            .bind(batch_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
            .map(row_to_batch)
            .transpose()
    }

    async fn list_batches(
        &self,
        organization_id: Option<&str>,
        status: Option<RevocationBatchStatus>,
    ) -> Result<Vec<RevocationBatch>, OperationError> {
        let rows = sqlx::query(
            r#"
            SELECT * FROM revocation_profile_service.revocation_batches
            WHERE ($1::text IS NULL OR organization_id = $1)
              AND ($2::text IS NULL OR status = $2)
            ORDER BY created_at DESC
            "#,
        )
        .bind(organization_id)
        .bind(status.map(batch_status_name))
        .fetch_all(&self.pool)
        .await
        .map_err(storage_error)?;
        rows.into_iter().map(row_to_batch).collect()
    }

    async fn delete_batch(&self, batch_id: &str) -> Result<bool, OperationError> {
        let result =
            sqlx::query("DELETE FROM revocation_profile_service.revocation_batches WHERE id = $1")
                .bind(batch_id)
                .execute(&self.pool)
                .await
                .map_err(storage_error)?;
        Ok(result.rows_affected() == 1)
    }
}

fn row_to_cascade(row: PgRow) -> Result<CascadeRevocationOperation, OperationError> {
    Ok(CascadeRevocationOperation {
        id: get(&row, "id")?,
        organization_id: get(&row, "organization_id")?,
        operation_type: parse_cascade_operation_type(&get::<String>(&row, "operation_type")?)?,
        trigger_entity_type: parse_trigger_entity_type(&get::<String>(
            &row,
            "trigger_entity_type",
        )?)?,
        trigger_entity_id: get(&row, "trigger_entity_id")?,
        status: parse_cascade_status(&get::<String>(&row, "status")?)?,
        affected_credential_count: to_usize(get::<i64>(&row, "affected_credential_count")?)?,
        affected_credential_ids: serde_json::from_value(get::<Value>(
            &row,
            "affected_credential_ids",
        )?)
        .map_err(storage_error)?,
        requires_confirmation: get(&row, "requires_confirmation")?,
        confirmed_at: get(&row, "confirmed_at")?,
        confirmed_by: get(&row, "confirmed_by")?,
        max_cascade_depth: to_u8(get::<i16>(&row, "max_cascade_depth")?)?,
        current_depth: to_u8(get::<i16>(&row, "current_depth")?)?,
        circuit_breaker_threshold: to_usize(get::<i64>(&row, "circuit_breaker_threshold")?)?,
        circuit_breaker_triggered: get(&row, "circuit_breaker_triggered")?,
        can_rollback: get(&row, "can_rollback")?,
        rollback_snapshot: get(&row, "rollback_snapshot")?,
        rolled_back_at: get(&row, "rolled_back_at")?,
        rolled_back_by: get(&row, "rolled_back_by")?,
        error_message: get(&row, "error_message")?,
        metadata: get(&row, "metadata")?,
        created_at: get(&row, "created_at")?,
        updated_at: get(&row, "updated_at")?,
        completed_at: get(&row, "completed_at")?,
    })
}

fn row_to_batch(row: PgRow) -> Result<RevocationBatch, OperationError> {
    Ok(RevocationBatch {
        id: get(&row, "id")?,
        organization_id: get(&row, "organization_id")?,
        revocation_profile_id: get(&row, "revocation_profile_id")?,
        batch_interval: get(&row, "batch_interval")?,
        credential_format: get(&row, "credential_format")?,
        credential_ids: serde_json::from_value(get::<Value>(&row, "credential_ids")?)
            .map_err(storage_error)?,
        status: parse_batch_status(&get::<String>(&row, "status")?)?,
        created_at: get(&row, "created_at")?,
        published_at: get(&row, "published_at")?,
    })
}

fn get<T>(row: &PgRow, column: &str) -> Result<T, OperationError>
where
    for<'r> T: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(column).map_err(storage_error)
}

fn cascade_operation_type_name(value: CascadeOperationType) -> &'static str {
    match value {
        CascadeOperationType::IssuerRevocation => "ISSUER_REVOCATION",
        CascadeOperationType::AnchorRevocation => "ANCHOR_REVOCATION",
    }
}

fn trigger_entity_type_name(value: TriggerEntityType) -> &'static str {
    match value {
        TriggerEntityType::Issuer => "ISSUER",
        TriggerEntityType::TrustAnchor => "TRUST_ANCHOR",
    }
}

fn cascade_status_name(value: CascadeStatus) -> &'static str {
    match value {
        CascadeStatus::PendingConfirmation => "PENDING_CONFIRMATION",
        CascadeStatus::InProgress => "IN_PROGRESS",
        CascadeStatus::Completed => "COMPLETED",
        CascadeStatus::RolledBack => "ROLLED_BACK",
        CascadeStatus::Failed => "FAILED",
    }
}

fn batch_status_name(value: RevocationBatchStatus) -> &'static str {
    crate::operations::batch_status_name(value)
}

fn parse_cascade_operation_type(value: &str) -> Result<CascadeOperationType, OperationError> {
    match value {
        "ISSUER_REVOCATION" => Ok(CascadeOperationType::IssuerRevocation),
        "ANCHOR_REVOCATION" => Ok(CascadeOperationType::AnchorRevocation),
        _ => Err(storage_error(format!(
            "unknown cascade operation type: {value}"
        ))),
    }
}

fn parse_trigger_entity_type(value: &str) -> Result<TriggerEntityType, OperationError> {
    match value {
        "ISSUER" => Ok(TriggerEntityType::Issuer),
        "TRUST_ANCHOR" => Ok(TriggerEntityType::TrustAnchor),
        _ => Err(storage_error(format!(
            "unknown trigger entity type: {value}"
        ))),
    }
}

fn parse_cascade_status(value: &str) -> Result<CascadeStatus, OperationError> {
    match value {
        "PENDING_CONFIRMATION" => Ok(CascadeStatus::PendingConfirmation),
        "IN_PROGRESS" => Ok(CascadeStatus::InProgress),
        "COMPLETED" => Ok(CascadeStatus::Completed),
        "ROLLED_BACK" => Ok(CascadeStatus::RolledBack),
        "FAILED" => Ok(CascadeStatus::Failed),
        _ => Err(storage_error(format!("unknown cascade status: {value}"))),
    }
}

fn parse_batch_status(value: &str) -> Result<RevocationBatchStatus, OperationError> {
    match value {
        "PENDING" => Ok(RevocationBatchStatus::Pending),
        "PUBLISHING" => Ok(RevocationBatchStatus::Publishing),
        "PUBLISHED" => Ok(RevocationBatchStatus::Published),
        "FAILED" => Ok(RevocationBatchStatus::Failed),
        _ => Err(storage_error(format!("unknown batch status: {value}"))),
    }
}

fn to_i64(value: usize) -> Result<i64, OperationError> {
    i64::try_from(value).map_err(storage_error)
}

fn to_usize(value: i64) -> Result<usize, OperationError> {
    usize::try_from(value).map_err(storage_error)
}

fn to_u8(value: i16) -> Result<u8, OperationError> {
    u8::try_from(value).map_err(storage_error)
}

fn storage_error(error: impl std::fmt::Display) -> OperationError {
    OperationError::Storage(error.to_string())
}
