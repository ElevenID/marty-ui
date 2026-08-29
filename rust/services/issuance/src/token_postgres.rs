use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use marty_oid4vci::CodeChallengeMethod;
use sha2::Sha256;
use sqlx::{postgres::PgRow, PgPool, Row};
use tracing::error;

use crate::client_auth::{RegisteredClientRepository, RegisteredOid4vciClient};
use crate::token_exchange::{
    TokenAuthorizationSession, TokenExchangeError, TokenExchangeRepository, TokenTransaction,
    TokenTransactionStatus,
};

const GET_TRANSACTION: &str =
    "SELECT id, organization_id, pre_auth_code, status, expires_at, oid4vci_client_id, claims
     FROM issuance_service.issuance_transactions
     WHERE pre_auth_code = $1";

const CLAIM_TRANSACTION: &str = "UPDATE issuance_service.issuance_transactions
     SET access_token = $3,
         c_nonce = NULL,
         claims = CASE
             WHEN $4::text IS NULL THEN claims
             ELSE jsonb_set(COALESCE(claims, '{}'::jsonb), '{_dpop_jkt}', to_jsonb($4::text), true)
         END,
         status = 'authorized'
     WHERE id = $1 AND pre_auth_code = $2 AND status = 'pending'
     RETURNING id";

const GET_AUTHORIZATION: &str =
    "SELECT id, code, client_id, organization_id, redirect_uri, issuer_state,
            credential_configuration_ids, code_challenge, code_challenge_method, status,
            created_at, expires_at
     FROM issuance_service.authorization_sessions
     WHERE code = $1";

const CLAIM_AUTHORIZATION: &str = "UPDATE issuance_service.authorization_sessions
     SET access_token = $3, c_nonce = NULL, dpop_jkt = $4, status = 'exchanged'
     WHERE id = $1 AND code = $2 AND status = 'pending' AND expires_at > clock_timestamp()
     RETURNING id";

const GET_REGISTERED_CLIENT: &str =
    "SELECT organization_id, client_id, jwks, token_endpoint_auth_method, active
     FROM issuance_service.oid4vci_registered_clients
     WHERE organization_id = $1 AND client_id = $2";

const CLAIM_CLIENT_ASSERTION: &str = "WITH cleanup AS (
         DELETE FROM issuance_service.oid4vci_client_assertions
         WHERE expires_at <= clock_timestamp()
     )
     INSERT INTO issuance_service.oid4vci_client_assertions
         (organization_id, client_id, jti, expires_at, created_at)
     VALUES ($1, $2, $3, $4, clock_timestamp())
     ON CONFLICT (organization_id, client_id, jti) DO NOTHING
     RETURNING jti";

#[derive(Clone)]
pub struct PostgresTokenExchangeRepository {
    pool: PgPool,
    token_hmac_key: std::sync::Arc<[u8]>,
}

impl std::fmt::Debug for PostgresTokenExchangeRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresTokenExchangeRepository")
            .finish_non_exhaustive()
    }
}

impl PostgresTokenExchangeRepository {
    #[must_use]
    pub fn new(pool: PgPool, token_hmac_key: impl AsRef<[u8]>) -> Self {
        Self {
            pool,
            token_hmac_key: std::sync::Arc::from(token_hmac_key.as_ref()),
        }
    }
}

#[async_trait]
impl TokenExchangeRepository for PostgresTokenExchangeRepository {
    async fn transaction_by_pre_authorized_code(
        &self,
        code: &str,
    ) -> Result<Option<TokenTransaction>, TokenExchangeError> {
        sqlx::query(GET_TRANSACTION)
            .bind(code)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(transaction_row)
            .transpose()
    }

    async fn claim_transaction(
        &self,
        transaction: &TokenTransaction,
        access_token: &str,
        dpop_jkt: Option<&str>,
    ) -> Result<bool, TokenExchangeError> {
        Ok(sqlx::query(CLAIM_TRANSACTION)
            .bind(&transaction.id)
            .bind(&transaction.pre_authorized_code)
            .bind(hash_access_token(&self.token_hmac_key, access_token))
            .bind(dpop_jkt)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .is_some())
    }

    async fn authorization_by_code(
        &self,
        code: &str,
    ) -> Result<Option<TokenAuthorizationSession>, TokenExchangeError> {
        sqlx::query(GET_AUTHORIZATION)
            .bind(code)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(authorization_row)
            .transpose()
    }

    async fn claim_authorization(
        &self,
        session: &TokenAuthorizationSession,
        access_token: &str,
        dpop_jkt: Option<&str>,
    ) -> Result<bool, TokenExchangeError> {
        Ok(sqlx::query(CLAIM_AUTHORIZATION)
            .bind(&session.id)
            .bind(&session.code)
            .bind(hash_access_token(&self.token_hmac_key, access_token))
            .bind(dpop_jkt)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .is_some())
    }
}

#[async_trait]
impl RegisteredClientRepository for PostgresTokenExchangeRepository {
    async fn client(
        &self,
        organization_id: &str,
        client_id: &str,
    ) -> Result<Option<RegisteredOid4vciClient>, TokenExchangeError> {
        sqlx::query(GET_REGISTERED_CLIENT)
            .bind(organization_id)
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(|row| {
                Ok(RegisteredOid4vciClient {
                    organization_id: get(&row, "organization_id")?,
                    client_id: get(&row, "client_id")?,
                    jwks: get(&row, "jwks")?,
                    token_endpoint_auth_method: get(&row, "token_endpoint_auth_method")?,
                    active: get(&row, "active")?,
                })
            })
            .transpose()
    }

    async fn claim_assertion(
        &self,
        organization_id: &str,
        client_id: &str,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, TokenExchangeError> {
        Ok(sqlx::query(CLAIM_CLIENT_ASSERTION)
            .bind(organization_id)
            .bind(client_id)
            .bind(jti)
            .bind(expires_at)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .is_some())
    }
}

fn transaction_row(row: PgRow) -> Result<TokenTransaction, TokenExchangeError> {
    let status: String = get(&row, "status")?;
    Ok(TokenTransaction {
        id: get(&row, "id")?,
        organization_id: get(&row, "organization_id")?,
        pre_authorized_code: get(&row, "pre_auth_code")?,
        status: TokenTransactionStatus::try_from(status.as_str())?,
        expires_at: get::<DateTime<Utc>>(&row, "expires_at")?,
        oid4vci_client_id: get(&row, "oid4vci_client_id")?,
        claims: get(&row, "claims")?,
    })
}

fn authorization_row(row: PgRow) -> Result<TokenAuthorizationSession, TokenExchangeError> {
    let code_challenge_method = get::<Option<String>>(&row, "code_challenge_method")?
        .map(|value| match value.as_str() {
            "S256" => Ok(CodeChallengeMethod::S256),
            "plain" => Ok(CodeChallengeMethod::Plain),
            _ => Err(TokenExchangeError::RepositoryUnavailable),
        })
        .transpose()?;
    let credential_configuration_ids = serde_json::from_value(get::<serde_json::Value>(
        &row,
        "credential_configuration_ids",
    )?)
    .map_err(|error| {
        error!(%error, "authorization credential configuration ids are invalid");
        TokenExchangeError::RepositoryUnavailable
    })?;
    Ok(TokenAuthorizationSession {
        id: get(&row, "id")?,
        code: get(&row, "code")?,
        client_id: get(&row, "client_id")?,
        organization_id: get(&row, "organization_id")?,
        redirect_uri: get(&row, "redirect_uri")?,
        issuer_state: get(&row, "issuer_state")?,
        credential_configuration_ids,
        code_challenge: get(&row, "code_challenge")?,
        code_challenge_method,
        status: get(&row, "status")?,
        created_at: get::<DateTime<Utc>>(&row, "created_at")?,
        expires_at: get::<DateTime<Utc>>(&row, "expires_at")?,
    })
}

pub(crate) fn hash_access_token(key: &[u8], token: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any size");
    mac.update(token.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn get<'row, T>(row: &'row PgRow, name: &str) -> Result<T, TokenExchangeError>
where
    T: sqlx::Decode<'row, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(name).map_err(row_error)
}

fn repository_error(cause: sqlx::Error) -> TokenExchangeError {
    error!(%cause, "token exchange repository query failed");
    TokenExchangeError::RepositoryUnavailable
}

fn row_error(cause: sqlx::Error) -> TokenExchangeError {
    error!(%cause, "token exchange repository row is invalid");
    TokenExchangeError::RepositoryUnavailable
}

#[cfg(test)]
mod tests {
    use super::hash_access_token;

    #[test]
    fn access_tokens_are_one_way_hashed_before_persistence() {
        assert_eq!(
            hash_access_token(b"test-only-not-a-secret", "clear-access-token"),
            "c8bbab78c3100a251baa92d44fe608aeec993e5dce470b5d61e75db549528ca2"
        );
    }
}
