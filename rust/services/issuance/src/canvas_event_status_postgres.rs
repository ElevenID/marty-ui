use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{postgres::PgRow, PgPool, Row};
use tracing::error;

use crate::canvas_event_status::{
    CanvasEventReceipt, CanvasEventStatusRepository, CanvasEventStatusRepositoryError,
};

const LOAD_RECEIPT: &str = "SELECT id, provider_event_id, canvas_account_id,
        organization_id, credential_template_id, payload_hash,
        issuance_transaction_id, issuance_response, status, error_summary,
        first_seen_at, last_seen_at
    FROM issuance_service.canvas_event_receipts
    WHERE canvas_account_id = $1 AND provider_event_id = $2";

#[derive(Clone, Debug)]
pub struct PostgresCanvasEventStatusRepository {
    pool: PgPool,
}

impl PostgresCanvasEventStatusRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CanvasEventStatusRepository for PostgresCanvasEventStatusRepository {
    async fn receipt(
        &self,
        canvas_account_id: &str,
        provider_event_id: &str,
    ) -> Result<Option<CanvasEventReceipt>, CanvasEventStatusRepositoryError> {
        sqlx::query(LOAD_RECEIPT)
            .bind(canvas_account_id)
            .bind(provider_event_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(receipt_from_row)
            .transpose()
            .map_err(repository_error)
    }
}

fn receipt_from_row(row: PgRow) -> Result<CanvasEventReceipt, sqlx::Error> {
    Ok(CanvasEventReceipt {
        id: row.try_get("id")?,
        provider_event_id: row.try_get("provider_event_id")?,
        canvas_account_id: row.try_get("canvas_account_id")?,
        organization_id: row.try_get("organization_id")?,
        credential_template_id: row.try_get("credential_template_id")?,
        payload_hash: row.try_get("payload_hash")?,
        issuance_transaction_id: row.try_get("issuance_transaction_id")?,
        issuance_response: row.try_get::<Value, _>("issuance_response")?,
        status: row.try_get("status")?,
        error_summary: row.try_get("error_summary")?,
        first_seen_at: row.try_get::<DateTime<Utc>, _>("first_seen_at")?,
        last_seen_at: row.try_get::<DateTime<Utc>, _>("last_seen_at")?,
    })
}

fn repository_error(error: sqlx::Error) -> CanvasEventStatusRepositoryError {
    error!(error = %error, "Canvas event status repository operation failed");
    CanvasEventStatusRepositoryError::Unavailable
}

#[cfg(test)]
mod tests {
    use super::LOAD_RECEIPT;

    #[test]
    fn lookup_is_schema_qualified_and_uses_the_exact_composite_key() {
        assert!(LOAD_RECEIPT.contains("issuance_service.canvas_event_receipts"));
        assert!(LOAD_RECEIPT.contains("canvas_account_id = $1"));
        assert!(LOAD_RECEIPT.contains("provider_event_id = $2"));
        assert!(!LOAD_RECEIPT.to_ascii_lowercase().contains(" order by "));
        assert!(!LOAD_RECEIPT.to_ascii_lowercase().contains(" limit "));
    }
}
