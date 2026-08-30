use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use sqlx::{PgPool, Postgres, Row, Transaction};
use tracing::error;

use crate::{
    canvas_oauth::{
        CanvasOAuthAuthorization, CanvasOAuthConnection, CanvasOAuthError, CanvasOAuthPlatform,
        CanvasOAuthPlatformPatch, CanvasOAuthRepository, CanvasOAuthSecretVault,
    },
    integration_secret::{
        IntegrationSecretCipher, IntegrationSecretMetadata, NewIntegrationSecret,
    },
};

#[derive(Clone)]
pub struct PostgresCanvasOAuthRepository {
    pool: PgPool,
}

impl std::fmt::Debug for PostgresCanvasOAuthRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresCanvasOAuthRepository")
            .finish_non_exhaustive()
    }
}

impl PostgresCanvasOAuthRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanvasOAuthRevocationQueueOutcome {
    Absent,
    AlreadyPending,
    Queued,
    Disconnected,
}

/// Move a Canvas OAuth grant into the worker-owned durable revocation queue
/// inside the caller's transaction. Platform archival and any future atomic
/// lifecycle transition share this one persistence implementation.
pub(crate) async fn queue_canvas_oauth_revocation_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    platform_id: &str,
    retry_at: DateTime<Utc>,
    reason_code: &str,
) -> Result<CanvasOAuthRevocationQueueOutcome, CanvasOAuthError> {
    let status = sqlx::query_scalar::<_, String>(
        "SELECT status FROM issuance_service.canvas_oauth_connections
         WHERE organization_id = $1 AND platform_id = $2 FOR UPDATE",
    )
    .bind(organization_id)
    .bind(platform_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(repository_error)?;
    match status.as_deref() {
        None => Ok(CanvasOAuthRevocationQueueOutcome::Absent),
        Some("revocation_pending") => Ok(CanvasOAuthRevocationQueueOutcome::AlreadyPending),
        Some("disconnected") => Ok(CanvasOAuthRevocationQueueOutcome::Disconnected),
        Some(_) => {
            let result = sqlx::query(
                "UPDATE issuance_service.canvas_oauth_connections
                 SET status = 'revocation_pending', reauthorization_required = false,
                     revoke_retry_count = revoke_retry_count + 1, revoke_retry_at = $3,
                     revoke_last_error_code = left($4, 120),
                     refresh_lease_owner = NULL, refresh_lease_expires_at = NULL,
                     updated_at = clock_timestamp()
                 WHERE organization_id = $1 AND platform_id = $2
                   AND status <> 'disconnected'",
            )
            .bind(organization_id)
            .bind(platform_id)
            .bind(retry_at)
            .bind(reason_code)
            .execute(&mut **transaction)
            .await
            .map_err(repository_error)?;
            if result.rows_affected() == 1 {
                Ok(CanvasOAuthRevocationQueueOutcome::Queued)
            } else {
                Ok(CanvasOAuthRevocationQueueOutcome::Disconnected)
            }
        }
    }
}

#[derive(Clone)]
pub struct PostgresIntegrationSecretVault {
    pool: PgPool,
    cipher: IntegrationSecretCipher,
}

impl std::fmt::Debug for PostgresIntegrationSecretVault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresIntegrationSecretVault")
            .field("cipher", &self.cipher)
            .finish_non_exhaustive()
    }
}

impl PostgresIntegrationSecretVault {
    #[must_use]
    pub fn new(pool: PgPool, cipher: IntegrationSecretCipher) -> Self {
        Self { pool, cipher }
    }
}

#[async_trait]
impl CanvasOAuthRepository for PostgresCanvasOAuthRepository {
    async fn management_platform(
        &self,
        organization_id: &str,
        platform_id: &str,
    ) -> Result<Option<CanvasOAuthPlatform>, CanvasOAuthError> {
        sqlx::query(
            "SELECT id, organization_id, canvas_base_url, config_version, archived_at
             FROM issuance_service.canvas_platforms
             WHERE id = $1 AND organization_id = $2",
        )
        .bind(platform_id)
        .bind(organization_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(repository_error)?
        .map(platform_from_row)
        .transpose()
    }

    async fn callback_platform(
        &self,
        platform_id: &str,
    ) -> Result<Option<CanvasOAuthPlatform>, CanvasOAuthError> {
        sqlx::query(
            "SELECT id, organization_id, canvas_base_url, config_version, archived_at
             FROM issuance_service.canvas_platforms WHERE id = $1",
        )
        .bind(platform_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(repository_error)?
        .map(platform_from_row)
        .transpose()
    }

    async fn connection(
        &self,
        organization_id: &str,
        platform_id: &str,
    ) -> Result<Option<CanvasOAuthConnection>, CanvasOAuthError> {
        sqlx::query(
            "SELECT id, organization_id, platform_id, canvas_base_url,
                    platform_config_version, client_id, client_secret_ref,
                    capabilities, scopes, access_token_secret_ref,
                    refresh_token_secret_ref, token_expires_at, status,
                    revoke_retry_count, updated_at
             FROM issuance_service.canvas_oauth_connections
             WHERE organization_id = $1 AND platform_id = $2",
        )
        .bind(organization_id)
        .bind(platform_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(repository_error)?
        .map(connection_from_row)
        .transpose()
    }

    async fn save_authorization(
        &self,
        authorization: &CanvasOAuthAuthorization,
    ) -> Result<(), CanvasOAuthError> {
        sqlx::query(
            "INSERT INTO issuance_service.canvas_oauth_authorizations
                (id, organization_id, platform_id, canvas_base_url,
                 platform_config_version, client_id, client_secret_ref,
                 state_hash, capabilities, scopes, redirect_uri, expires_at,
                 consumed_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NULL, $13)
             ON CONFLICT (state_hash) DO NOTHING",
        )
        .bind(&authorization.id)
        .bind(&authorization.organization_id)
        .bind(&authorization.platform_id)
        .bind(&authorization.canvas_base_url)
        .bind(
            i32::try_from(authorization.platform_config_version)
                .map_err(|_| repository_failure())?,
        )
        .bind(&authorization.client_id)
        .bind(&authorization.client_secret_ref)
        .bind(&authorization.state_hash)
        .bind(serde_json::to_value(&authorization.capabilities).map_err(|_| repository_failure())?)
        .bind(serde_json::to_value(&authorization.scopes).map_err(|_| repository_failure())?)
        .bind(&authorization.redirect_uri)
        .bind(authorization.expires_at)
        .bind(authorization.created_at)
        .execute(&self.pool)
        .await
        .map_err(repository_error)?;
        Ok(())
    }

    async fn consume_authorization(
        &self,
        state_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<CanvasOAuthAuthorization>, CanvasOAuthError> {
        sqlx::query(
            "UPDATE issuance_service.canvas_oauth_authorizations
             SET consumed_at = $2
             WHERE state_hash = $1 AND consumed_at IS NULL AND expires_at > $2
             RETURNING id, organization_id, platform_id, canvas_base_url,
                       platform_config_version, client_id, client_secret_ref,
                       state_hash, capabilities, scopes, redirect_uri, expires_at, created_at",
        )
        .bind(state_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(repository_error)?
        .map(authorization_from_row)
        .transpose()
    }

    async fn patch_platform(
        &self,
        organization_id: &str,
        platform_id: &str,
        expected_config_version: i64,
        patch: CanvasOAuthPlatformPatch,
    ) -> Result<bool, CanvasOAuthError> {
        let mut transaction = self.pool.begin().await.map_err(repository_error)?;
        let selected = sqlx::query(
            "SELECT connection_config
             FROM issuance_service.canvas_platforms
             WHERE id = $1 AND organization_id = $2 AND config_version = $3
             FOR UPDATE",
        )
        .bind(platform_id)
        .bind(organization_id)
        .bind(i32::try_from(expected_config_version).map_err(|_| repository_failure())?)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(repository_error)?;
        let Some(selected) = selected else {
            transaction.rollback().await.map_err(repository_error)?;
            return Ok(false);
        };
        let mut config = selected
            .try_get::<Value, _>("connection_config")
            .map_err(repository_error)?
            .as_object()
            .cloned()
            .unwrap_or_default();
        apply_platform_patch(&mut config, patch);
        let result = sqlx::query(
            "UPDATE issuance_service.canvas_platforms
             SET connection_config = $4, updated_at = clock_timestamp()
             WHERE id = $1 AND organization_id = $2 AND config_version = $3",
        )
        .bind(platform_id)
        .bind(organization_id)
        .bind(i32::try_from(expected_config_version).map_err(|_| repository_failure())?)
        .bind(Value::Object(config))
        .execute(&mut *transaction)
        .await
        .map_err(repository_error)?;
        transaction.commit().await.map_err(repository_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn patch_validation(
        &self,
        organization_id: &str,
        platform_id: &str,
        expected_config_version: i64,
        validated_at: Option<DateTime<Utc>>,
        error_code: Option<&str>,
    ) -> Result<bool, CanvasOAuthError> {
        let result = sqlx::query(
            "UPDATE issuance_service.canvas_platforms
             SET last_validated_at = $4, last_connection_error = $5,
                 updated_at = clock_timestamp()
             WHERE id = $1 AND organization_id = $2 AND config_version = $3",
        )
        .bind(platform_id)
        .bind(organization_id)
        .bind(i32::try_from(expected_config_version).map_err(|_| repository_failure())?)
        .bind(validated_at)
        .bind(error_code)
        .execute(&self.pool)
        .await
        .map_err(repository_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn publish_connection(
        &self,
        connection: &CanvasOAuthConnection,
    ) -> Result<Option<DateTime<Utc>>, CanvasOAuthError> {
        let mut transaction = self.pool.begin().await.map_err(repository_error)?;
        let platform = sqlx::query(
            "SELECT id FROM issuance_service.canvas_platforms
             WHERE id = $1 AND organization_id = $2 AND config_version = $3
               AND archived_at IS NULL
             FOR UPDATE",
        )
        .bind(&connection.platform_id)
        .bind(&connection.organization_id)
        .bind(i32::try_from(connection.platform_config_version).map_err(|_| repository_failure())?)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(repository_error)?;
        if platform.is_none() {
            transaction.rollback().await.map_err(repository_error)?;
            return Ok(None);
        }
        let row = sqlx::query(
            "INSERT INTO issuance_service.canvas_oauth_connections
                (id, organization_id, platform_id, canvas_base_url,
                 platform_config_version, client_id, client_secret_ref,
                 capabilities, scopes, access_token_secret_ref,
                 refresh_token_secret_ref, token_expires_at, status,
                 reauthorization_required, refresh_lease_owner,
                 refresh_lease_expires_at, revoke_retry_count, revoke_retry_at,
                 revoke_last_error_code, connected_at, last_refreshed_at,
                 created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                     'connected', false, NULL, NULL, 0, NULL, NULL,
                     clock_timestamp(), NULL, clock_timestamp(), clock_timestamp())
             ON CONFLICT (organization_id, platform_id) DO NOTHING
             RETURNING updated_at",
        )
        .bind(&connection.id)
        .bind(&connection.organization_id)
        .bind(&connection.platform_id)
        .bind(&connection.canvas_base_url)
        .bind(i32::try_from(connection.platform_config_version).map_err(|_| repository_failure())?)
        .bind(&connection.client_id)
        .bind(&connection.client_secret_ref)
        .bind(serde_json::to_value(&connection.capabilities).map_err(|_| repository_failure())?)
        .bind(serde_json::to_value(&connection.scopes).map_err(|_| repository_failure())?)
        .bind(&connection.access_token_secret_ref)
        .bind(&connection.refresh_token_secret_ref)
        .bind(connection.token_expires_at)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(repository_error)?;
        transaction.commit().await.map_err(repository_error)?;
        row.map(|row| row.try_get("updated_at").map_err(repository_error))
            .transpose()
    }

    async fn mark_reauthorization_required(
        &self,
        organization_id: &str,
        platform_id: &str,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<bool, CanvasOAuthError> {
        let result = sqlx::query(
            "UPDATE issuance_service.canvas_oauth_connections
             SET status = 'reauthorization_required', reauthorization_required = true,
                 refresh_lease_owner = NULL, refresh_lease_expires_at = NULL,
                 updated_at = clock_timestamp()
             WHERE organization_id = $1 AND platform_id = $2 AND updated_at = $3
               AND status <> 'disconnected'
               AND (refresh_lease_owner IS NULL OR refresh_lease_expires_at IS NULL
                    OR refresh_lease_expires_at <= clock_timestamp())",
        )
        .bind(organization_id)
        .bind(platform_id)
        .bind(expected_updated_at)
        .execute(&self.pool)
        .await
        .map_err(repository_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn begin_revocation(
        &self,
        organization_id: &str,
        platform_id: &str,
        expected_updated_at: DateTime<Utc>,
        lease_owner: &str,
        lease_seconds: i64,
    ) -> Result<Option<CanvasOAuthConnection>, CanvasOAuthError> {
        sqlx::query(
            "UPDATE issuance_service.canvas_oauth_connections
             SET status = 'revocation_pending', reauthorization_required = false,
                 revoke_retry_at = NULL, revoke_last_error_code = NULL,
                 refresh_lease_owner = $4,
                 refresh_lease_expires_at = clock_timestamp() + make_interval(secs => $5),
                 updated_at = clock_timestamp()
             WHERE organization_id = $1 AND platform_id = $2 AND updated_at = $3
               AND status <> 'disconnected'
             RETURNING id, organization_id, platform_id, canvas_base_url,
                       platform_config_version, client_id, client_secret_ref,
                       capabilities, scopes, access_token_secret_ref,
                       refresh_token_secret_ref, token_expires_at, status,
                       revoke_retry_count, updated_at",
        )
        .bind(organization_id)
        .bind(platform_id)
        .bind(expected_updated_at)
        .bind(lease_owner)
        .bind(lease_seconds.max(30))
        .fetch_optional(&self.pool)
        .await
        .map_err(repository_error)?
        .map(connection_from_row)
        .transpose()
    }

    async fn reschedule_revocation(
        &self,
        organization_id: &str,
        platform_id: &str,
        lease_owner: &str,
        retry_at: DateTime<Utc>,
        error_code: &str,
    ) -> Result<bool, CanvasOAuthError> {
        let result = sqlx::query(
            "UPDATE issuance_service.canvas_oauth_connections
             SET revoke_retry_count = revoke_retry_count + 1,
                 revoke_retry_at = $4, revoke_last_error_code = left($5, 120),
                 refresh_lease_owner = NULL, refresh_lease_expires_at = NULL,
                 updated_at = clock_timestamp()
             WHERE organization_id = $1 AND platform_id = $2
               AND status = 'revocation_pending' AND refresh_lease_owner = $3",
        )
        .bind(organization_id)
        .bind(platform_id)
        .bind(lease_owner)
        .bind(retry_at)
        .bind(error_code)
        .execute(&self.pool)
        .await
        .map_err(repository_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn complete_revocation(
        &self,
        organization_id: &str,
        platform_id: &str,
        lease_owner: &str,
        secret_ids: &[String],
    ) -> Result<bool, CanvasOAuthError> {
        let mut transaction = self.pool.begin().await.map_err(repository_error)?;
        let leased: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM issuance_service.canvas_oauth_connections
             WHERE organization_id = $1 AND platform_id = $2
               AND status = 'revocation_pending' AND refresh_lease_owner = $3
             FOR UPDATE",
        )
        .bind(organization_id)
        .bind(platform_id)
        .bind(lease_owner)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(repository_error)?;
        if leased.is_none() {
            transaction.rollback().await.map_err(repository_error)?;
            return Ok(false);
        }
        for secret_id in secret_ids {
            sqlx::query(
                "DELETE FROM issuance_service.organization_integration_secrets
                 WHERE id = $1 AND organization_id = $2",
            )
            .bind(secret_id)
            .bind(organization_id)
            .execute(&mut *transaction)
            .await
            .map_err(repository_error)?;
        }
        let result = sqlx::query(
            "DELETE FROM issuance_service.canvas_oauth_connections
             WHERE organization_id = $1 AND platform_id = $2
               AND status = 'revocation_pending' AND refresh_lease_owner = $3",
        )
        .bind(organization_id)
        .bind(platform_id)
        .bind(lease_owner)
        .execute(&mut *transaction)
        .await
        .map_err(repository_error)?;
        transaction.commit().await.map_err(repository_error)?;
        Ok(result.rows_affected() == 1)
    }
}

#[async_trait]
impl CanvasOAuthSecretVault for PostgresIntegrationSecretVault {
    async fn metadata(
        &self,
        organization_id: &str,
        secret_id: &str,
    ) -> Result<Option<IntegrationSecretMetadata>, CanvasOAuthError> {
        sqlx::query(
            "SELECT id, organization_id, provider, purpose, enabled
             FROM issuance_service.organization_integration_secrets
             WHERE id = $1 AND organization_id = $2",
        )
        .bind(secret_id)
        .bind(organization_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(repository_error)?
        .map(|row| {
            Ok(IntegrationSecretMetadata {
                id: row.try_get("id").map_err(repository_error)?,
                organization_id: row.try_get("organization_id").map_err(repository_error)?,
                provider: row.try_get("provider").map_err(repository_error)?,
                purpose: row.try_get("purpose").map_err(repository_error)?,
                enabled: row.try_get("enabled").map_err(repository_error)?,
            })
        })
        .transpose()
    }

    async fn value(
        &self,
        organization_id: &str,
        secret_id: &str,
    ) -> Result<Option<String>, CanvasOAuthError> {
        let mut transaction = self.pool.begin().await.map_err(repository_error)?;
        let row = sqlx::query(
            "SELECT encrypted_secret_value
             FROM issuance_service.organization_integration_secrets
             WHERE id = $1 AND organization_id = $2 AND enabled = true",
        )
        .bind(secret_id)
        .bind(organization_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(repository_error)?;
        let Some(row) = row else {
            transaction.rollback().await.map_err(repository_error)?;
            return Ok(None);
        };
        sqlx::query(
            "UPDATE issuance_service.organization_integration_secrets
             SET last_used_at = clock_timestamp() WHERE id = $1",
        )
        .bind(secret_id)
        .execute(&mut *transaction)
        .await
        .map_err(repository_error)?;
        transaction.commit().await.map_err(repository_error)?;
        let encrypted: String = row
            .try_get("encrypted_secret_value")
            .map_err(repository_error)?;
        self.cipher
            .decrypt(&encrypted)
            .map(Some)
            .map_err(Into::into)
    }

    async fn save(&self, secret: NewIntegrationSecret) -> Result<(), CanvasOAuthError> {
        let encrypted = self.cipher.encrypt(&secret.value)?;
        let hint = format!(
            "...{}",
            secret
                .value
                .chars()
                .rev()
                .take(4)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<String>()
        );
        sqlx::query(
            "INSERT INTO issuance_service.organization_integration_secrets
                (id, organization_id, name, provider, purpose,
                 encrypted_secret_value, secret_hint, metadata, enabled,
                 created_at, updated_at, last_used_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true,
                     clock_timestamp(), clock_timestamp(), NULL)",
        )
        .bind(&secret.id)
        .bind(&secret.organization_id)
        .bind(&secret.name)
        .bind(&secret.provider)
        .bind(&secret.purpose)
        .bind(encrypted)
        .bind(hint)
        .bind(secret.metadata)
        .execute(&self.pool)
        .await
        .map_err(repository_error)?;
        Ok(())
    }

    async fn delete(&self, organization_id: &str, secret_id: &str) -> Result<(), CanvasOAuthError> {
        sqlx::query(
            "DELETE FROM issuance_service.organization_integration_secrets
             WHERE id = $1 AND organization_id = $2",
        )
        .bind(secret_id)
        .bind(organization_id)
        .execute(&self.pool)
        .await
        .map_err(repository_error)?;
        Ok(())
    }
}

fn platform_from_row(row: sqlx::postgres::PgRow) -> Result<CanvasOAuthPlatform, CanvasOAuthError> {
    Ok(CanvasOAuthPlatform {
        id: row.try_get("id").map_err(repository_error)?,
        organization_id: row.try_get("organization_id").map_err(repository_error)?,
        canvas_base_url: row.try_get("canvas_base_url").map_err(repository_error)?,
        config_version: row
            .try_get::<i32, _>("config_version")
            .map(i64::from)
            .map_err(repository_error)?,
        archived: row
            .try_get::<Option<DateTime<Utc>>, _>("archived_at")
            .map_err(repository_error)?
            .is_some(),
    })
}

fn authorization_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<CanvasOAuthAuthorization, CanvasOAuthError> {
    Ok(CanvasOAuthAuthorization {
        id: row.try_get("id").map_err(repository_error)?,
        organization_id: row.try_get("organization_id").map_err(repository_error)?,
        platform_id: row.try_get("platform_id").map_err(repository_error)?,
        canvas_base_url: row.try_get("canvas_base_url").map_err(repository_error)?,
        platform_config_version: row
            .try_get::<i32, _>("platform_config_version")
            .map(i64::from)
            .map_err(repository_error)?,
        client_id: row.try_get("client_id").map_err(repository_error)?,
        client_secret_ref: row.try_get("client_secret_ref").map_err(repository_error)?,
        state_hash: row.try_get("state_hash").map_err(repository_error)?,
        capabilities: string_vec(row.try_get("capabilities").map_err(repository_error)?)?,
        scopes: string_vec(row.try_get("scopes").map_err(repository_error)?)?,
        redirect_uri: row.try_get("redirect_uri").map_err(repository_error)?,
        expires_at: row.try_get("expires_at").map_err(repository_error)?,
        created_at: row.try_get("created_at").map_err(repository_error)?,
    })
}

fn connection_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<CanvasOAuthConnection, CanvasOAuthError> {
    Ok(CanvasOAuthConnection {
        id: row.try_get("id").map_err(repository_error)?,
        organization_id: row.try_get("organization_id").map_err(repository_error)?,
        platform_id: row.try_get("platform_id").map_err(repository_error)?,
        canvas_base_url: row.try_get("canvas_base_url").map_err(repository_error)?,
        platform_config_version: row
            .try_get::<i32, _>("platform_config_version")
            .map(i64::from)
            .map_err(repository_error)?,
        client_id: row.try_get("client_id").map_err(repository_error)?,
        client_secret_ref: row.try_get("client_secret_ref").map_err(repository_error)?,
        capabilities: string_vec(row.try_get("capabilities").map_err(repository_error)?)?,
        scopes: string_vec(row.try_get("scopes").map_err(repository_error)?)?,
        access_token_secret_ref: row
            .try_get("access_token_secret_ref")
            .map_err(repository_error)?,
        refresh_token_secret_ref: row
            .try_get("refresh_token_secret_ref")
            .map_err(repository_error)?,
        token_expires_at: row.try_get("token_expires_at").map_err(repository_error)?,
        status: row.try_get("status").map_err(repository_error)?,
        revoke_retry_count: row
            .try_get("revoke_retry_count")
            .map_err(repository_error)?,
        updated_at: row.try_get("updated_at").map_err(repository_error)?,
    })
}

fn string_vec(value: Value) -> Result<Vec<String>, CanvasOAuthError> {
    serde_json::from_value(value).map_err(|_| repository_failure())
}

fn apply_platform_patch(config: &mut Map<String, Value>, patch: CanvasOAuthPlatformPatch) {
    match patch {
        CanvasOAuthPlatformPatch::AuthorizationPending {
            client_id,
            authorization_id,
        } => {
            config.insert("oauth_client_id".to_owned(), Value::String(client_id));
            config.insert(
                "oauth_status".to_owned(),
                Value::String("authorization_pending".to_owned()),
            );
            config.insert(
                "oauth_pending_authorization_id".to_owned(),
                Value::String(authorization_id),
            );
        }
        CanvasOAuthPlatformPatch::AuthorizationCompleting { client_id } => {
            config.insert("oauth_client_id".to_owned(), Value::String(client_id));
            config.insert(
                "oauth_status".to_owned(),
                Value::String("authorization_completing".to_owned()),
            );
        }
        CanvasOAuthPlatformPatch::Connected {
            client_id,
            capabilities,
            scopes,
        } => {
            config.remove("oauth_pending_authorization_id");
            config.insert("oauth_client_id".to_owned(), Value::String(client_id));
            config.insert(
                "oauth_status".to_owned(),
                Value::String("connected".to_owned()),
            );
            config.insert(
                "oauth_capabilities".to_owned(),
                serde_json::to_value(capabilities).unwrap_or_else(|_| Value::Array(Vec::new())),
            );
            config.insert(
                "granted_scopes".to_owned(),
                serde_json::to_value(scopes).unwrap_or_else(|_| Value::Array(Vec::new())),
            );
        }
        CanvasOAuthPlatformPatch::AuthorizationConflict => {
            config.remove("oauth_pending_authorization_id");
            config.insert(
                "oauth_status".to_owned(),
                Value::String("authorization_conflict".to_owned()),
            );
        }
        CanvasOAuthPlatformPatch::RevocationPending => {
            config.remove("oauth_pending_authorization_id");
            config.insert(
                "oauth_status".to_owned(),
                Value::String("revocation_pending".to_owned()),
            );
        }
        CanvasOAuthPlatformPatch::Disconnected => {
            config.remove("oauth_pending_authorization_id");
            config.insert(
                "oauth_status".to_owned(),
                Value::String("disconnected".to_owned()),
            );
            config.insert("granted_scopes".to_owned(), Value::Array(Vec::new()));
            config.insert("oauth_capabilities".to_owned(), Value::Array(Vec::new()));
        }
    }
}

fn repository_error(error: sqlx::Error) -> CanvasOAuthError {
    error!(error = %error, "Canvas OAuth PostgreSQL operation failed");
    repository_failure()
}

fn repository_failure() -> CanvasOAuthError {
    CanvasOAuthError::RepositoryUnavailable
}
