//! Read-only PostgreSQL projection for gateway resource-owner authorization.

use async_trait::async_trait;
use sqlx::{PgPool, Row};
use tracing::error;

use crate::{
    resource_owner::{ResourceOwnerKind, ResourceOwnerRepository},
    transaction_reads::TransactionReadError,
};

const APPLICATION_TEMPLATE_OWNER: &str =
    "SELECT organization_id FROM issuance_service.application_templates WHERE id = $1";
const ISSUED_CREDENTIAL_OWNER: &str =
    "SELECT organization_id FROM issuance_service.issued_credentials WHERE id = $1";
const ISSUANCE_TRANSACTION_OWNER: &str =
    "SELECT organization_id FROM issuance_service.issuance_transactions WHERE id = $1";

#[derive(Clone)]
pub struct PostgresResourceOwnerRepository {
    pool: PgPool,
}

impl std::fmt::Debug for PostgresResourceOwnerRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresResourceOwnerRepository")
            .finish_non_exhaustive()
    }
}

impl PostgresResourceOwnerRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ResourceOwnerRepository for PostgresResourceOwnerRepository {
    async fn find_owner(
        &self,
        kind: ResourceOwnerKind,
        resource_id: &str,
    ) -> Result<Option<String>, TransactionReadError> {
        let query = match kind {
            ResourceOwnerKind::ApplicationTemplate => APPLICATION_TEMPLATE_OWNER,
            ResourceOwnerKind::IssuedCredential => ISSUED_CREDENTIAL_OWNER,
            ResourceOwnerKind::IssuanceTransaction => ISSUANCE_TRANSACTION_OWNER,
        };
        sqlx::query(query)
            .bind(resource_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(|row| row.try_get("organization_id").map_err(repository_error))
            .transpose()
    }
}

fn repository_error(cause: sqlx::Error) -> TransactionReadError {
    error!(%cause, "resource-owner repository query failed");
    TransactionReadError::RepositoryUnavailable
}

#[cfg(test)]
mod tests {
    use super::{APPLICATION_TEMPLATE_OWNER, ISSUANCE_TRANSACTION_OWNER, ISSUED_CREDENTIAL_OWNER};

    #[test]
    fn every_owner_query_is_a_single_column_read_from_the_exact_owned_table() {
        assert_eq!(
            APPLICATION_TEMPLATE_OWNER,
            "SELECT organization_id FROM issuance_service.application_templates WHERE id = $1"
        );
        assert_eq!(
            ISSUED_CREDENTIAL_OWNER,
            "SELECT organization_id FROM issuance_service.issued_credentials WHERE id = $1"
        );
        assert_eq!(
            ISSUANCE_TRANSACTION_OWNER,
            "SELECT organization_id FROM issuance_service.issuance_transactions WHERE id = $1"
        );
        for query in [
            APPLICATION_TEMPLATE_OWNER,
            ISSUED_CREDENTIAL_OWNER,
            ISSUANCE_TRANSACTION_OWNER,
        ] {
            assert!(query.starts_with("SELECT organization_id FROM issuance_service."));
            assert!(!query.contains(','));
            assert!(!query.contains("INSERT "));
            assert!(!query.contains("UPDATE "));
            assert!(!query.contains("DELETE "));
        }
    }
}
