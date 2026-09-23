use async_trait::async_trait;
use chrono::{DateTime, Duration};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgRow, PgPool, Row};
use tracing::error;
use uuid::Uuid;

use crate::{
    oid4vci_authorization::{
        AccessTokenGrant, AuthorizationParameters, AuthorizationSessionWrite,
        DeferredCredentialLookup, DeferredCredentialRecord, DeferredStatus, NotificationLookup,
        NotificationRequest, Oid4vciAuthorizationRepository, Oid4vciAuthorizationRepositoryError,
        RegisteredAuthorizationClient,
    },
    token_postgres::hash_access_token,
};

#[derive(Clone)]
pub struct PostgresOid4vciAuthorizationRepository {
    pool: PgPool,
    token_hmac_key: std::sync::Arc<[u8]>,
}

const TOKEN_BOUND_TO_TRANSACTION_SQL: &str = "((transaction.access_token = $2
        AND transaction.access_token_expires_at > clock_timestamp())
      OR EXISTS (
          SELECT 1
          FROM issuance_service.authorization_sessions AS session
          WHERE session.access_token = $2
            AND session.access_token_expires_at > clock_timestamp()
            AND session.issuer_state = transaction.pre_auth_code
            AND session.organization_id = transaction.organization_id
            AND ((transaction.access_token IS NULL
                  AND transaction.access_token_expires_at IS NULL)
                 OR (transaction.access_token = session.access_token
                     AND transaction.access_token_expires_at = session.access_token_expires_at))
            AND (transaction.oid4vci_client_id IS NULL
                 OR transaction.oid4vci_client_id = session.client_id)
            AND ((transaction.claims::jsonb ->> '_dpop_jkt') IS NULL
                 OR (transaction.claims::jsonb ->> '_dpop_jkt') = session.dpop_jkt)
      )) IS TRUE";

impl std::fmt::Debug for PostgresOid4vciAuthorizationRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresOid4vciAuthorizationRepository")
            .finish_non_exhaustive()
    }
}

impl PostgresOid4vciAuthorizationRepository {
    #[must_use]
    pub fn new(pool: PgPool, token_hmac_key: impl AsRef<[u8]>) -> Self {
        Self {
            pool,
            token_hmac_key: std::sync::Arc::from(token_hmac_key.as_ref()),
        }
    }

    fn token_digest(&self, access_token: &str) -> String {
        hash_access_token(&self.token_hmac_key, access_token)
    }
}

#[async_trait]
impl Oid4vciAuthorizationRepository for PostgresOid4vciAuthorizationRepository {
    async fn store_par(
        &self,
        request_uri: &str,
        parameters: &AuthorizationParameters,
        ttl_seconds: u64,
    ) -> Result<bool, Oid4vciAuthorizationRepositoryError> {
        let ttl = i32::try_from(ttl_seconds).map_err(|_| repository_error("PAR TTL overflow"))?;
        Ok(sqlx::query(
            "WITH expired AS (
                 SELECT purpose, key_digest
                 FROM issuance_service.oid4vci_ephemeral_capabilities
                 WHERE expires_at <= clock_timestamp()
                 ORDER BY expires_at LIMIT 128 FOR UPDATE SKIP LOCKED
             ), cleanup AS (
                 DELETE FROM issuance_service.oid4vci_ephemeral_capabilities AS capabilities
                 USING expired
                 WHERE capabilities.purpose = expired.purpose
                   AND capabilities.key_digest = expired.key_digest
             )
             INSERT INTO issuance_service.oid4vci_ephemeral_capabilities
                 (purpose, key_digest, payload, created_at, expires_at)
             VALUES ('par', $1, $2, clock_timestamp(),
                     clock_timestamp() + $3::integer * INTERVAL '1 second')
             ON CONFLICT (purpose, key_digest) DO NOTHING
             RETURNING key_digest",
        )
        .bind(capability_digest(request_uri))
        .bind(json!(parameters))
        .bind(ttl)
        .fetch_optional(&self.pool)
        .await
        .map_err(sql_error)?
        .is_some())
    }

    async fn consume_par(
        &self,
        request_uri: &str,
    ) -> Result<Option<AuthorizationParameters>, Oid4vciAuthorizationRepositoryError> {
        let row = sqlx::query(
            "DELETE FROM issuance_service.oid4vci_ephemeral_capabilities
             WHERE purpose = 'par' AND key_digest = $1
             RETURNING payload, expires_at > clock_timestamp() AS is_live",
        )
        .bind(capability_digest(request_uri))
        .fetch_optional(&self.pool)
        .await
        .map_err(sql_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        if !row.try_get::<bool, _>("is_live").map_err(row_error)? {
            return Ok(None);
        }
        serde_json::from_value(row.try_get::<Value, _>("payload").map_err(row_error)?)
            .map(Some)
            .map_err(|cause| {
                error!(%cause, "stored PAR payload is invalid");
                Oid4vciAuthorizationRepositoryError
            })
    }

    async fn registered_client(
        &self,
        organization_id: &str,
        client_id: &str,
    ) -> Result<Option<RegisteredAuthorizationClient>, Oid4vciAuthorizationRepositoryError> {
        sqlx::query(
            "SELECT active, redirect_uris
             FROM issuance_service.oid4vci_registered_clients
             WHERE organization_id = $1 AND client_id = $2",
        )
        .bind(organization_id)
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(sql_error)?
        .map(|row| {
            let redirects = row
                .try_get::<Value, _>("redirect_uris")
                .map_err(row_error)?;
            Ok(RegisteredAuthorizationClient {
                active: row.try_get("active").map_err(row_error)?,
                redirect_uris: serde_json::from_value(redirects).map_err(|cause| {
                    error!(%cause, "registered client redirects are invalid");
                    Oid4vciAuthorizationRepositoryError
                })?,
            })
        })
        .transpose()
    }

    async fn save_authorization_session(
        &self,
        write: &AuthorizationSessionWrite,
    ) -> Result<(), Oid4vciAuthorizationRepositoryError> {
        let created_at = DateTime::from_timestamp(
            i64::try_from(write.session.created_at)
                .map_err(|_| repository_error("authorization timestamp overflow"))?,
            0,
        )
        .ok_or_else(|| repository_error("authorization timestamp is invalid"))?;
        let expires_at = created_at
            .checked_add_signed(Duration::seconds(write.persisted_lifetime_seconds))
            .ok_or_else(|| repository_error("authorization expiry overflow"))?;
        sqlx::query(
            "INSERT INTO issuance_service.authorization_sessions
                 (id, code, client_id, redirect_uri, scope, state, issuer_state,
                  credential_configuration_ids, organization_id, code_challenge,
                  code_challenge_method, status, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                     'pending', $12, $13)",
        )
        .bind(&write.id)
        .bind(&write.session.code)
        .bind(&write.session.client_id)
        .bind(&write.session.redirect_uri)
        .bind(&write.scope)
        .bind(&write.state)
        .bind(&write.session.issuer_state)
        .bind(json!(write.session.credential_configuration_ids))
        .bind(&write.organization_id)
        .bind(&write.session.code_challenge)
        .bind(
            write
                .session
                .code_challenge_method
                .as_ref()
                .map(ToString::to_string),
        )
        .bind(created_at)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        Ok(())
    }

    async fn access_token_grant(
        &self,
        access_token: &str,
    ) -> Result<Option<AccessTokenGrant>, Oid4vciAuthorizationRepositoryError> {
        let digest = self.token_digest(access_token);
        let rows = sqlx::query(
            "SELECT 'transaction'::text AS source, id, organization_id,
                    oid4vci_client_id AS client_id,
                    pre_auth_code AS issuer_link,
                    claims::jsonb ->> '_dpop_jkt' AS dpop_jkt,
                    access_token_expires_at
             FROM issuance_service.issuance_transactions
             WHERE access_token = $1
               AND access_token_expires_at > clock_timestamp()
             UNION ALL
             SELECT 'session'::text AS source, id, organization_id, client_id,
                    issuer_state AS issuer_link, dpop_jkt, access_token_expires_at
             FROM issuance_service.authorization_sessions
             WHERE access_token = $1
               AND access_token_expires_at > clock_timestamp()",
        )
        .bind(digest)
        .fetch_all(&self.pool)
        .await
        .map_err(sql_error)?;
        match rows.as_slice() {
            [] => Ok(None),
            [row] => Ok(Some(AccessTokenGrant {
                dpop_jkt: row.try_get("dpop_jkt").map_err(row_error)?,
            })),
            [first, second] if linked_grants(first, second)? => Ok(Some(AccessTokenGrant {
                dpop_jkt: first.try_get("dpop_jkt").map_err(row_error)?,
            })),
            _ => Err(repository_error(
                "access token digest is bound to multiple grants",
            )),
        }
    }

    async fn deferred_credential(
        &self,
        access_token: &str,
        transaction_id: &str,
    ) -> Result<DeferredCredentialLookup, Oid4vciAuthorizationRepositoryError> {
        let query = sqlx::AssertSqlSafe(format!(
            "SELECT transaction.status, credential.credential_jwt,
                    {TOKEN_BOUND_TO_TRANSACTION_SQL} AS token_bound,
                    (credential.id IS NULL
                     OR credential.organization_id = transaction.organization_id) IS TRUE
                        AS credential_bound
             FROM issuance_service.issuance_transactions AS transaction
             LEFT JOIN issuance_service.issued_credentials AS credential
               ON credential.transaction_id = transaction.id
             WHERE transaction.id = $1"
        ));
        let row = sqlx::query(query)
            .bind(transaction_id)
            .bind(self.token_digest(access_token))
            .fetch_optional(&self.pool)
            .await
            .map_err(sql_error)?;
        let Some(row) = row else {
            return Ok(DeferredCredentialLookup::Missing);
        };
        if !row.try_get::<bool, _>("token_bound").map_err(row_error)? {
            return Ok(DeferredCredentialLookup::Unbound);
        }
        if !row
            .try_get::<bool, _>("credential_bound")
            .map_err(row_error)?
        {
            return Err(repository_error(
                "deferred credential organization binding is inconsistent",
            ));
        }
        deferred_row(row).map(DeferredCredentialLookup::Bound)
    }

    async fn notification_transaction(
        &self,
        access_token: &str,
        notification_id: &str,
    ) -> Result<NotificationLookup, Oid4vciAuthorizationRepositoryError> {
        let query = sqlx::AssertSqlSafe(format!(
            "SELECT event.transaction_id,
                    {TOKEN_BOUND_TO_TRANSACTION_SQL} AS token_bound,
                    (event.application_id IS NOT DISTINCT FROM transaction.application_id
                     AND event.metadata ->> 'organization_id' = transaction.organization_id
                     AND event.metadata ->> 'credential_id' = credential.id
                     AND credential.organization_id = transaction.organization_id) IS TRUE
                        AS binding_bound
             FROM issuance_service.issuance_events AS event
             JOIN issuance_service.issuance_transactions AS transaction
               ON transaction.id = event.transaction_id
             LEFT JOIN issuance_service.issued_credentials AS credential
               ON credential.transaction_id = transaction.id
             WHERE event.event_type = 'oid4vci_notification_binding'
               AND event.metadata ->> 'notification_id' = $1"
        ));
        let row = sqlx::query(query)
            .bind(notification_id)
            .bind(self.token_digest(access_token))
            .fetch_optional(&self.pool)
            .await
            .map_err(sql_error)?;
        let Some(row) = row else {
            return Ok(NotificationLookup::Missing);
        };
        if !row.try_get::<bool, _>("token_bound").map_err(row_error)? {
            return Ok(NotificationLookup::Unbound);
        }
        if !row.try_get::<bool, _>("binding_bound").map_err(row_error)? {
            return Err(repository_error(
                "notification binding identity is inconsistent",
            ));
        }
        row.try_get("transaction_id")
            .map(NotificationLookup::Bound)
            .map_err(row_error)
    }

    async fn record_notification(
        &self,
        transaction_id: &str,
        request: &NotificationRequest,
    ) -> Result<(), Oid4vciAuthorizationRepositoryError> {
        let id = notification_event_id(transaction_id, request);
        let metadata = json!({
            "notification_id": request.notification_id,
            "event": request.event.as_str(),
            "event_description": request.event_description,
        });
        sqlx::query(
            "INSERT INTO issuance_service.issuance_events
                 (id, transaction_id, application_id, event_type, metadata, created_at)
             SELECT $1, transaction.id, transaction.application_id,
                    'oid4vci_wallet_notification', $3, clock_timestamp()
             FROM issuance_service.issuance_transactions AS transaction
             WHERE transaction.id = $2
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&id)
        .bind(transaction_id)
        .bind(&metadata)
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        let persisted = sqlx::query(
            "SELECT event.transaction_id, event.event_type, event.metadata,
                    (event.application_id IS NOT DISTINCT FROM transaction.application_id)
                        AS application_bound
             FROM issuance_service.issuance_events AS event
             JOIN issuance_service.issuance_transactions AS transaction
               ON transaction.id = event.transaction_id
             WHERE event.id = $1",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(sql_error)?;
        if persisted
            .try_get::<Option<String>, _>("transaction_id")
            .map_err(row_error)?
            .as_deref()
            != Some(transaction_id)
            || persisted
                .try_get::<String, _>("event_type")
                .map_err(row_error)?
                != "oid4vci_wallet_notification"
            || persisted
                .try_get::<Value, _>("metadata")
                .map_err(row_error)?
                != metadata
            || !persisted
                .try_get::<bool, _>("application_bound")
                .map_err(row_error)?
        {
            return Err(repository_error(
                "wallet notification event identity is already occupied",
            ));
        }
        Ok(())
    }
}

fn linked_grants(
    first: &PgRow,
    second: &PgRow,
) -> Result<bool, Oid4vciAuthorizationRepositoryError> {
    let first_source = first.try_get::<String, _>("source").map_err(row_error)?;
    let second_source = second.try_get::<String, _>("source").map_err(row_error)?;
    let (transaction, session) = match (first_source.as_str(), second_source.as_str()) {
        ("transaction", "session") => (first, second),
        ("session", "transaction") => (second, first),
        _ => return Ok(false),
    };
    let transaction_id = transaction.try_get::<String, _>("id").map_err(row_error)?;
    let transaction_link = transaction
        .try_get::<String, _>("issuer_link")
        .map_err(row_error)?;
    let session_id = session.try_get::<String, _>("id").map_err(row_error)?;
    let session_link = session
        .try_get::<Option<String>, _>("issuer_link")
        .map_err(row_error)?;
    let deterministic_link = transaction_id == authorization_transaction_id(&session_id);
    let same_logical_grant =
        session_link.as_deref() == Some(transaction_link.as_str()) || deterministic_link;
    let transaction_client = transaction
        .try_get::<Option<String>, _>("client_id")
        .map_err(row_error)?;
    let session_client = session
        .try_get::<String, _>("client_id")
        .map_err(row_error)?;
    Ok(same_logical_grant
        && transaction
            .try_get::<String, _>("organization_id")
            .map_err(row_error)?
            == session
                .try_get::<String, _>("organization_id")
                .map_err(row_error)?
        && (transaction_client.as_deref() == Some(session_client.as_str())
            || (deterministic_link && transaction_client.is_none()))
        && transaction
            .try_get::<Option<String>, _>("dpop_jkt")
            .map_err(row_error)?
            == session
                .try_get::<Option<String>, _>("dpop_jkt")
                .map_err(row_error)?
        && transaction
            .try_get::<DateTime<chrono::Utc>, _>("access_token_expires_at")
            .map_err(row_error)?
            == session
                .try_get::<DateTime<chrono::Utc>, _>("access_token_expires_at")
                .map_err(row_error)?)
}

fn authorization_transaction_id(session_id: &str) -> String {
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("marty:oid4vci:authorization-session:{session_id}").as_bytes(),
    )
    .to_string()
}

fn notification_event_id(transaction_id: &str, request: &NotificationRequest) -> String {
    let identity = json!({
        "transaction_id": transaction_id,
        "notification_id": request.notification_id,
        "event": request.event.as_str(),
        "event_description": request.event_description,
    });
    Uuid::new_v5(&Uuid::NAMESPACE_URL, identity.to_string().as_bytes()).to_string()
}

fn deferred_row(
    row: PgRow,
) -> Result<DeferredCredentialRecord, Oid4vciAuthorizationRepositoryError> {
    let status = match row
        .try_get::<String, _>("status")
        .map_err(row_error)?
        .as_str()
    {
        "pending" => DeferredStatus::Pending,
        "authorized" => DeferredStatus::Authorized,
        "issued" => DeferredStatus::Issued,
        "signing" => DeferredStatus::Signing,
        "failed" => DeferredStatus::Failed,
        "expired" => DeferredStatus::Expired,
        "revoked" => DeferredStatus::Revoked,
        _ => return Err(repository_error("deferred transaction status is invalid")),
    };
    Ok(DeferredCredentialRecord {
        status,
        credential: row.try_get("credential_jwt").map_err(row_error)?,
    })
}

fn capability_digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn sql_error(cause: sqlx::Error) -> Oid4vciAuthorizationRepositoryError {
    error!(%cause, "OID4VCI authorization repository query failed");
    Oid4vciAuthorizationRepositoryError
}

fn row_error(cause: sqlx::Error) -> Oid4vciAuthorizationRepositoryError {
    error!(%cause, "OID4VCI authorization repository row is invalid");
    Oid4vciAuthorizationRepositoryError
}

fn repository_error(message: &str) -> Oid4vciAuthorizationRepositoryError {
    error!(message, "OID4VCI authorization repository invariant failed");
    Oid4vciAuthorizationRepositoryError
}

#[cfg(test)]
mod tests {
    use super::capability_digest;

    #[test]
    fn par_capabilities_use_the_python_compatible_sha256_digest() {
        assert_eq!(
            capability_digest("urn:ietf:params:oauth:request_uri:secret"),
            "29c010dec7108b429017214410e93ed9f43a2ba94cf161fddbf2129ebad9d2b5"
        );
    }
}
