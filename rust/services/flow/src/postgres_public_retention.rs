use super::{record, storage, PostgresFlowRepository};
use crate::{PublicVerificationRetentionSweep, RepositoryError};

impl PostgresFlowRepository {
    /// A payload may have been deleted while its minimal receipt is still live.
    pub async fn public_verification_receipt_exists(
        &self,
        id: &str,
    ) -> Result<bool, RepositoryError> {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM flow_service.public_verification_receipts WHERE instance_id=$1)")
            .bind(id).fetch_one(&self.pool).await.map_err(storage)
    }

    /// Uses the DB clock and transactionally bounded batches. Ownership comes
    /// from receipts created by public insertion, never caller-supplied context.
    pub async fn sweep_public_verification_retention(
        &self,
        limit: u32,
    ) -> Result<PublicVerificationRetentionSweep, RepositoryError> {
        if !(1..=1000).contains(&limit) {
            return Err(record("public_retention_batch_limit"));
        }
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        sqlx::query("SET LOCAL statement_timeout='5s'")
            .execute(&mut *transaction)
            .await
            .map_err(storage)?;
        let nonces = sqlx::query("DELETE FROM flow_service.flow_nonce_consumptions WHERE nonce_digest IN ( \
            SELECT nonce.nonce_digest FROM flow_service.flow_nonce_consumptions AS nonce \
            JOIN flow_service.public_verification_receipts AS receipt ON receipt.instance_id=nonce.flow_instance_id \
            WHERE receipt.payload_delete_after <= clock_timestamp() AND nonce.expires_at <= clock_timestamp() \
            ORDER BY nonce.expires_at,nonce.nonce_digest LIMIT $1)")
            .bind(i64::from(limit)).execute(&mut *transaction).await.map_err(storage)?.rows_affected();
        let sessions = sqlx::query("DELETE FROM flow_service.flow_instances WHERE id IN ( \
            SELECT instance.id FROM flow_service.flow_instances AS instance \
            JOIN flow_service.public_verification_receipts AS receipt ON receipt.instance_id=instance.id \
            AND receipt.organization_id=instance.organization_id \
            WHERE receipt.payload_delete_after <= clock_timestamp() \
            ORDER BY receipt.payload_delete_after,instance.id LIMIT $1 FOR UPDATE OF instance SKIP LOCKED)")
            .bind(i64::from(limit)).execute(&mut *transaction).await.map_err(storage)?.rows_affected();
        // Do not orphan an undeleted payload if another replica currently holds
        // its row lock. Another sweep will retry before removing the receipt.
        let receipts = sqlx::query("DELETE FROM flow_service.public_verification_receipts WHERE instance_id IN ( \
            SELECT receipt.instance_id FROM flow_service.public_verification_receipts AS receipt \
            WHERE receipt.receipt_delete_after <= clock_timestamp() \
            AND NOT EXISTS(SELECT 1 FROM flow_service.flow_instances AS instance \
                WHERE instance.id=receipt.instance_id AND instance.organization_id=receipt.organization_id) \
            AND NOT EXISTS(SELECT 1 FROM flow_service.flow_nonce_consumptions AS nonce \
                WHERE nonce.flow_instance_id=receipt.instance_id) \
            ORDER BY receipt.receipt_delete_after,receipt.instance_id LIMIT $1)")
            .bind(i64::from(limit)).execute(&mut *transaction).await.map_err(storage)?.rows_affected();
        transaction.commit().await.map_err(storage)?;
        Ok(PublicVerificationRetentionSweep {
            sessions,
            nonces,
            receipts,
        })
    }
}
