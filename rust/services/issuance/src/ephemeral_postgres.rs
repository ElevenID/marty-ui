use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::error;

use crate::proof_nonce::{ProofNonceError, ProofNonceRepository};

const MAX_TTL_SECONDS: u64 = 3_600;
const CLEANUP_LIMIT: i64 = 1_000;

const CLEANUP_EXPIRED: &str = "WITH expired AS (
         SELECT purpose, key_digest
         FROM issuance_service.oid4vci_ephemeral_capabilities
         WHERE expires_at <= clock_timestamp()
         ORDER BY expires_at
         LIMIT $1
         FOR UPDATE SKIP LOCKED
     )
     DELETE FROM issuance_service.oid4vci_ephemeral_capabilities AS capabilities
     USING expired
     WHERE capabilities.purpose = expired.purpose
       AND capabilities.key_digest = expired.key_digest";

const SAVE_PROOF_NONCE: &str = "
     INSERT INTO issuance_service.oid4vci_ephemeral_capabilities
         (purpose, key_digest, payload, created_at, expires_at)
     VALUES (
         'proof_nonce', $1, NULL, clock_timestamp(),
         clock_timestamp() + ($2::double precision * interval '1 second')
     )
     ON CONFLICT (purpose, key_digest) DO NOTHING
     RETURNING key_digest";

const CONSUME_PROOF_NONCE: &str = "DELETE FROM issuance_service.oid4vci_ephemeral_capabilities
     WHERE purpose = 'proof_nonce' AND key_digest = $1
     RETURNING expires_at > clock_timestamp() AS is_live";

#[derive(Clone)]
pub struct PostgresProofNonceRepository {
    pool: PgPool,
}

impl std::fmt::Debug for PostgresProofNonceRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresProofNonceRepository")
            .finish_non_exhaustive()
    }
}

impl PostgresProofNonceRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ProofNonceRepository for PostgresProofNonceRepository {
    async fn save_proof_nonce(
        &self,
        nonce: &str,
        ttl_seconds: u64,
    ) -> Result<bool, ProofNonceError> {
        if nonce.is_empty() || !(1..=MAX_TTL_SECONDS).contains(&ttl_seconds) {
            return Err(ProofNonceError::RepositoryUnavailable);
        }
        let ttl_seconds =
            i64::try_from(ttl_seconds).map_err(|_| ProofNonceError::RepositoryUnavailable)?;
        let mut transaction = self.pool.begin().await.map_err(repository_error)?;
        sqlx::query(CLEANUP_EXPIRED)
            .bind(CLEANUP_LIMIT)
            .execute(&mut *transaction)
            .await
            .map_err(repository_error)?;
        let inserted = sqlx::query(SAVE_PROOF_NONCE)
            .bind(capability_digest(nonce))
            .bind(ttl_seconds)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(repository_error)?
            .is_some();
        transaction.commit().await.map_err(repository_error)?;
        Ok(inserted)
    }

    async fn consume_proof_nonce(&self, nonce: &str) -> Result<bool, ProofNonceError> {
        if nonce.is_empty() {
            return Ok(false);
        }
        Ok(sqlx::query_scalar::<_, bool>(CONSUME_PROOF_NONCE)
            .bind(capability_digest(nonce))
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .unwrap_or(false))
    }
}

fn capability_digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn repository_error(cause: sqlx::Error) -> ProofNonceError {
    error!(%cause, "proof nonce repository query failed");
    ProofNonceError::RepositoryUnavailable
}

#[cfg(test)]
mod tests {
    use super::capability_digest;

    #[test]
    fn capability_keys_are_sha_256_digests() {
        assert_eq!(
            capability_digest("contract-proof-nonce"),
            "80badd89d90de3c28b55a1a3ac09fdfd4015f89f909434ea40118b66f039821f"
        );
    }
}
