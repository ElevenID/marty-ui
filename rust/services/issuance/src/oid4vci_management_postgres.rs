use async_trait::async_trait;
use serde_json::Value;
use sqlx::{postgres::PgRow, PgPool, Row};

use crate::oid4vci_management::{
    ManagementTransaction, Oid4vciManagementRepository, Oid4vciManagementRepositoryError,
    RegisteredClientRecord, RegisteredClientWrite, TransactionCredentialBinding,
};

const UPSERT_REGISTERED_CLIENT: &str = "INSERT INTO issuance_service.oid4vci_registered_clients
         (organization_id, client_id, jwks, redirect_uris,
          token_endpoint_auth_method, active, created_at, updated_at)
     VALUES ($1, $2, $3, $4, 'private_key_jwt', $5,
             clock_timestamp(), clock_timestamp())
     ON CONFLICT (organization_id, client_id) DO UPDATE
     SET jwks = EXCLUDED.jwks,
         redirect_uris = EXCLUDED.redirect_uris,
         token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method,
         active = EXCLUDED.active,
         updated_at = clock_timestamp()";

const GET_REGISTERED_CLIENT: &str = "SELECT organization_id, client_id, jwks, redirect_uris,
            token_endpoint_auth_method, active, created_at, updated_at
     FROM issuance_service.oid4vci_registered_clients
     WHERE organization_id = $1 AND client_id = $2";

const GET_TRANSACTION: &str = "SELECT id, organization_id, status, revoked_at, revocation_reason
     FROM issuance_service.issuance_transactions WHERE id = $1";

const GET_TRANSACTION_CREDENTIAL: &str = "SELECT id, transaction_id, organization_id
     FROM issuance_service.issued_credentials WHERE transaction_id = $1";

const REVOKE_TRANSACTION: &str = "UPDATE issuance_service.issuance_transactions
     SET status = 'revoked',
         revoked_at = CASE
             WHEN status = 'revoked' THEN revoked_at
             ELSE clock_timestamp()
         END,
         revocation_reason = CASE
             WHEN status = 'revoked' THEN revocation_reason
             ELSE $2
         END
     WHERE id = $1
     RETURNING id, organization_id, status, revoked_at, revocation_reason";

#[derive(Clone, Debug)]
pub struct PostgresOid4vciManagementRepository {
    pool: PgPool,
}

impl PostgresOid4vciManagementRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl Oid4vciManagementRepository for PostgresOid4vciManagementRepository {
    async fn save_registered_client(
        &self,
        client: &RegisteredClientWrite,
    ) -> Result<(), Oid4vciManagementRepositoryError> {
        sqlx::query(UPSERT_REGISTERED_CLIENT)
            .bind(&client.organization_id)
            .bind(&client.client_id)
            .bind(&client.jwks)
            .bind(serde_json::to_value(&client.redirect_uris).map_err(repository_error)?)
            .bind(client.active)
            .execute(&self.pool)
            .await
            .map_err(repository_error)?;
        Ok(())
    }

    async fn registered_client(
        &self,
        organization_id: &str,
        client_id: &str,
    ) -> Result<Option<RegisteredClientRecord>, Oid4vciManagementRepositoryError> {
        sqlx::query(GET_REGISTERED_CLIENT)
            .bind(organization_id)
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(|row| registered_client(&row))
            .transpose()
    }

    async fn transaction(
        &self,
        transaction_id: &str,
    ) -> Result<Option<ManagementTransaction>, Oid4vciManagementRepositoryError> {
        sqlx::query(GET_TRANSACTION)
            .bind(transaction_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(|row| transaction(&row))
            .transpose()
    }

    async fn credential_for_transaction(
        &self,
        transaction_id: &str,
    ) -> Result<Option<TransactionCredentialBinding>, Oid4vciManagementRepositoryError> {
        sqlx::query(GET_TRANSACTION_CREDENTIAL)
            .bind(transaction_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(|row| {
                Ok(TransactionCredentialBinding {
                    id: get(&row, "id")?,
                    transaction_id: get(&row, "transaction_id")?,
                    organization_id: get(&row, "organization_id")?,
                })
            })
            .transpose()
    }

    async fn revoke_transaction(
        &self,
        transaction_id: &str,
        reason: Option<&str>,
    ) -> Result<ManagementTransaction, Oid4vciManagementRepositoryError> {
        let row = sqlx::query(REVOKE_TRANSACTION)
            .bind(transaction_id)
            .bind(reason)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .ok_or(Oid4vciManagementRepositoryError)?;
        transaction(&row)
    }
}

fn registered_client(
    row: &PgRow,
) -> Result<RegisteredClientRecord, Oid4vciManagementRepositoryError> {
    let redirect_uris = serde_json::from_value::<Vec<String>>(get::<Value>(row, "redirect_uris")?)
        .map_err(repository_error)?;
    Ok(RegisteredClientRecord {
        organization_id: get(row, "organization_id")?,
        client_id: get(row, "client_id")?,
        jwks: get(row, "jwks")?,
        redirect_uris,
        token_endpoint_auth_method: get(row, "token_endpoint_auth_method")?,
        active: get(row, "active")?,
        created_at: get(row, "created_at")?,
        updated_at: get(row, "updated_at")?,
    })
}

fn transaction(row: &PgRow) -> Result<ManagementTransaction, Oid4vciManagementRepositoryError> {
    Ok(ManagementTransaction {
        id: get(row, "id")?,
        organization_id: get(row, "organization_id")?,
        status: get(row, "status")?,
        revoked_at: get(row, "revoked_at")?,
        revocation_reason: get(row, "revocation_reason")?,
    })
}

fn get<'row, T>(row: &'row PgRow, name: &str) -> Result<T, Oid4vciManagementRepositoryError>
where
    T: sqlx::Decode<'row, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(name).map_err(repository_error)
}

fn repository_error(error: impl std::fmt::Display) -> Oid4vciManagementRepositoryError {
    tracing::error!(%error, "OID4VCI management repository operation failed");
    Oid4vciManagementRepositoryError
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_preserve_created_at_and_revocation_is_ordered_after_credential_work() {
        assert!(UPSERT_REGISTERED_CLIENT.contains("ON CONFLICT"));
        assert!(!UPSERT_REGISTERED_CLIENT.contains("created_at ="));
        assert!(UPSERT_REGISTERED_CLIENT.contains("updated_at = clock_timestamp()"));
        assert_eq!(
            REVOKE_TRANSACTION
                .matches("WHEN status = 'revoked'")
                .count(),
            2
        );
        assert!(REVOKE_TRANSACTION.contains("RETURNING id"));
    }
}
