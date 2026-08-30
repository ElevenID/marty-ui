//! PostgreSQL persistence for the Canvas management aggregate.

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use sqlx::{postgres::PgRow, PgPool, Row};
use tracing::error;

use crate::{
    canvas_management_domain::CanvasPlatformRecord,
    canvas_management_service::{
        CanvasManagementRepositoryError, CanvasPlatformManagementRepository,
    },
    canvas_oauth_postgres::{
        queue_canvas_oauth_revocation_in_transaction, CanvasOAuthRevocationQueueOutcome,
    },
};

#[cfg(test)]
const PLATFORM_COLUMNS: &str = "id, organization_id, canvas_account_id,
    display_name, canvas_base_url, lti_client_id, lti_deployment_id,
    lti_trust_profile, lti_issuer, lti_jwks_url, lti_jwks_json,
    lti_jwks_fetched_at, lti_jwks_expires_at, lti_openid_configuration,
    registration_status, connection_config, capability_snapshot,
    last_validated_at, last_connection_error, config_version, archived_at,
    enabled, created_at, updated_at";

const INSERT_PLATFORM: &str = "INSERT INTO issuance_service.canvas_platforms (
    id, organization_id, canvas_account_id, display_name, canvas_base_url,
    lti_client_id, lti_deployment_id, lti_trust_profile, lti_issuer,
    lti_jwks_url, lti_jwks_json, lti_jwks_fetched_at, lti_jwks_expires_at,
    lti_openid_configuration, registration_status, connection_config,
    capability_snapshot, last_validated_at, last_connection_error,
    config_version, archived_at, enabled, created_at, updated_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
    $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24
)";

const GET_ACTIVE_PLATFORM: &str = "SELECT id, organization_id, canvas_account_id,
    display_name, canvas_base_url, lti_client_id, lti_deployment_id,
    lti_trust_profile, lti_issuer, lti_jwks_url, lti_jwks_json,
    lti_jwks_fetched_at, lti_jwks_expires_at, lti_openid_configuration,
    registration_status, connection_config, capability_snapshot,
    last_validated_at, last_connection_error, config_version, archived_at,
    enabled, created_at, updated_at
 FROM issuance_service.canvas_platforms
 WHERE organization_id = $1 AND id = $2 AND archived_at IS NULL";

const GET_PLATFORM_FOR_ARCHIVAL: &str = "SELECT id, organization_id, canvas_account_id,
    display_name, canvas_base_url, lti_client_id, lti_deployment_id,
    lti_trust_profile, lti_issuer, lti_jwks_url, lti_jwks_json,
    lti_jwks_fetched_at, lti_jwks_expires_at, lti_openid_configuration,
    registration_status, connection_config, capability_snapshot,
    last_validated_at, last_connection_error, config_version, archived_at,
    enabled, created_at, updated_at
 FROM issuance_service.canvas_platforms
 WHERE organization_id = $1 AND id = $2";

const GET_PUBLIC_PLATFORM: &str = "SELECT id, organization_id, canvas_account_id,
    display_name, canvas_base_url, lti_client_id, lti_deployment_id,
    lti_trust_profile, lti_issuer, lti_jwks_url, lti_jwks_json,
    lti_jwks_fetched_at, lti_jwks_expires_at, lti_openid_configuration,
    registration_status, connection_config, capability_snapshot,
    last_validated_at, last_connection_error, config_version, archived_at,
    enabled, created_at, updated_at
 FROM issuance_service.canvas_platforms
 WHERE id = $1";

const LOCK_PLATFORM_FOR_ARCHIVAL: &str = "SELECT id, organization_id, canvas_account_id,
    display_name, canvas_base_url, lti_client_id, lti_deployment_id,
    lti_trust_profile, lti_issuer, lti_jwks_url, lti_jwks_json,
    lti_jwks_fetched_at, lti_jwks_expires_at, lti_openid_configuration,
    registration_status, connection_config, capability_snapshot,
    last_validated_at, last_connection_error, config_version, archived_at,
    enabled, created_at, updated_at
 FROM issuance_service.canvas_platforms
 WHERE organization_id = $1 AND id = $2
 FOR UPDATE";

const LIST_ACTIVE_PLATFORMS: &str = "SELECT id, organization_id, canvas_account_id,
    display_name, canvas_base_url, lti_client_id, lti_deployment_id,
    lti_trust_profile, lti_issuer, lti_jwks_url, lti_jwks_json,
    lti_jwks_fetched_at, lti_jwks_expires_at, lti_openid_configuration,
    registration_status, connection_config, capability_snapshot,
    last_validated_at, last_connection_error, config_version, archived_at,
    enabled, created_at, updated_at
 FROM issuance_service.canvas_platforms
 WHERE organization_id = $1 AND archived_at IS NULL
 ORDER BY created_at";

const UPDATE_PLATFORM_CONFIGURATION: &str = "UPDATE issuance_service.canvas_platforms
 SET display_name = $4,
     canvas_base_url = $5,
     lti_client_id = $6,
     lti_deployment_id = $7,
     lti_trust_profile = $8,
     lti_issuer = $9,
     lti_jwks_url = $10,
     lti_jwks_json = $11,
     lti_jwks_fetched_at = $12,
     lti_jwks_expires_at = $13,
     lti_openid_configuration = $14,
     registration_status = $15,
     connection_config = jsonb_set(
         CASE
             WHEN COALESCE(connection_config, '{}'::jsonb) ? 'lti_capability_intent'
                 THEN COALESCE(connection_config, '{}'::jsonb)
             ELSE COALESCE(connection_config, '{}'::jsonb)
                  || jsonb_build_object('lti_capability_intent', '[\"ags\",\"nrps\"]'::jsonb)
         END,
         '{enabled_intent}', to_jsonb($16::boolean), true
     ),
     capability_snapshot = $17,
     last_validated_at = $18,
     last_connection_error = $19,
     config_version = $20,
     enabled = $21,
     updated_at = $22
 WHERE organization_id = $1 AND id = $2 AND config_version = $3
   AND archived_at IS NULL
 RETURNING id, organization_id, canvas_account_id, display_name, canvas_base_url,
     lti_client_id, lti_deployment_id, lti_trust_profile, lti_issuer,
     lti_jwks_url, lti_jwks_json, lti_jwks_fetched_at, lti_jwks_expires_at,
     lti_openid_configuration, registration_status, connection_config,
     capability_snapshot, last_validated_at, last_connection_error,
     config_version, archived_at, enabled, created_at, updated_at";

const TOUCH_PLATFORM_CONFIGURATION: &str = "UPDATE issuance_service.canvas_platforms
 SET display_name = $4,
     canvas_base_url = $5,
     lti_client_id = $6,
     lti_deployment_id = $7,
     lti_trust_profile = $8,
     connection_config = jsonb_set(
         CASE
             WHEN COALESCE(connection_config, '{}'::jsonb) ? 'lti_capability_intent'
                 THEN COALESCE(connection_config, '{}'::jsonb)
             ELSE COALESCE(connection_config, '{}'::jsonb)
                  || jsonb_build_object('lti_capability_intent', '[\"ags\",\"nrps\"]'::jsonb)
         END,
         '{enabled_intent}', to_jsonb($9::boolean), true
     ),
     updated_at = $10
 WHERE organization_id = $1 AND id = $2 AND config_version = $3
   AND archived_at IS NULL
 RETURNING id, organization_id, canvas_account_id, display_name, canvas_base_url,
     lti_client_id, lti_deployment_id, lti_trust_profile, lti_issuer,
     lti_jwks_url, lti_jwks_json, lti_jwks_fetched_at, lti_jwks_expires_at,
     lti_openid_configuration, registration_status, connection_config,
     capability_snapshot, last_validated_at, last_connection_error,
     config_version, archived_at, enabled, created_at, updated_at";

const INVALIDATE_PLATFORM_BINDINGS: &str = "UPDATE issuance_service.canvas_program_bindings
 SET enabled = false,
     validated_config_version = NULL,
     readiness_checks = '[]'::jsonb,
     readiness_validated_at = NULL,
     activated_at = NULL,
     updated_at = $3
 WHERE organization_id = $1 AND platform_id = $2 AND archived_at IS NULL";

const PERSIST_PLATFORM_ARCHIVE: &str = "UPDATE issuance_service.canvas_platforms
 SET registration_status = $4,
     connection_config = $5,
     config_version = $6,
     archived_at = $7,
     enabled = $8,
     updated_at = $9
 WHERE organization_id = $1 AND id = $2 AND config_version = $3
 RETURNING id, organization_id, canvas_account_id, display_name,
     canvas_base_url, lti_client_id, lti_deployment_id, lti_trust_profile,
     lti_issuer, lti_jwks_url, lti_jwks_json, lti_jwks_fetched_at,
     lti_jwks_expires_at, lti_openid_configuration, registration_status,
     connection_config, capability_snapshot, last_validated_at,
     last_connection_error, config_version, archived_at, enabled, created_at,
     updated_at";

const PERSIST_REGISTRATION_STATE: &str = "UPDATE issuance_service.canvas_platforms
 SET connection_config = $5, updated_at = $6
 WHERE organization_id = $1 AND id = $2 AND config_version = $3
   AND updated_at = $4 AND archived_at IS NULL
 RETURNING id, organization_id, canvas_account_id, display_name,
     canvas_base_url, lti_client_id, lti_deployment_id, lti_trust_profile,
     lti_issuer, lti_jwks_url, lti_jwks_json, lti_jwks_fetched_at,
     lti_jwks_expires_at, lti_openid_configuration, registration_status,
     connection_config, capability_snapshot, last_validated_at,
     last_connection_error, config_version, archived_at, enabled, created_at,
     updated_at";

const PERSIST_LTI_INSTALLATION: &str = "UPDATE issuance_service.canvas_platforms
 SET canvas_base_url = $5,
     lti_client_id = $6,
     lti_deployment_id = $7,
     lti_trust_profile = $8,
     lti_issuer = $9,
     lti_jwks_url = $10,
     lti_jwks_json = $11,
     lti_jwks_fetched_at = $12,
     lti_jwks_expires_at = $13,
     lti_openid_configuration = $14,
     registration_status = $15,
     connection_config = $16,
     capability_snapshot = $17,
     last_validated_at = $18,
     last_connection_error = $19,
     config_version = $20,
     enabled = $21,
     updated_at = $22
 WHERE organization_id = $1 AND id = $2 AND config_version = $3
   AND updated_at = $4 AND archived_at IS NULL
 RETURNING id, organization_id, canvas_account_id, display_name,
     canvas_base_url, lti_client_id, lti_deployment_id, lti_trust_profile,
     lti_issuer, lti_jwks_url, lti_jwks_json, lti_jwks_fetched_at,
     lti_jwks_expires_at, lti_openid_configuration, registration_status,
     connection_config, capability_snapshot, last_validated_at,
     last_connection_error, config_version, archived_at, enabled, created_at,
     updated_at";

const ARCHIVE_PLATFORM_BINDINGS: &str = "UPDATE issuance_service.canvas_program_bindings
 SET enabled = false, archived_at = $3, updated_at = $3
 WHERE organization_id = $1 AND platform_id = $2 AND archived_at IS NULL";

#[derive(Clone)]
pub struct PostgresCanvasManagementRepository {
    pool: PgPool,
}

impl std::fmt::Debug for PostgresCanvasManagementRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresCanvasManagementRepository")
            .finish_non_exhaustive()
    }
}

impl PostgresCanvasManagementRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_platform(
        &self,
        platform: &CanvasPlatformRecord,
    ) -> Result<(), CanvasManagementRepositoryError> {
        let config_version = version_i32(platform.config_version)?;
        let result = bind_platform_insert(sqlx::query(INSERT_PLATFORM), platform, config_version)
            .execute(&self.pool)
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(error) if is_unique_violation(&error) => {
                Err(CanvasManagementRepositoryError::Duplicate)
            }
            Err(error) => Err(repository_error(error)),
        }
    }

    pub async fn active_platform(
        &self,
        organization_id: &str,
        platform_id: &str,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        sqlx::query(GET_ACTIVE_PLATFORM)
            .bind(organization_id)
            .bind(platform_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(platform_from_row)
            .transpose()
    }

    pub async fn list_active_platforms(
        &self,
        organization_id: &str,
    ) -> Result<Vec<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        sqlx::query(LIST_ACTIVE_PLATFORMS)
            .bind(organization_id)
            .fetch_all(&self.pool)
            .await
            .map_err(repository_error)?
            .into_iter()
            .map(platform_from_row)
            .collect()
    }

    pub async fn platform_for_archival(
        &self,
        organization_id: &str,
        platform_id: &str,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        sqlx::query(GET_PLATFORM_FOR_ARCHIVAL)
            .bind(organization_id)
            .bind(platform_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(platform_from_row)
            .transpose()
    }

    pub async fn public_platform(
        &self,
        platform_id: &str,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        sqlx::query(GET_PUBLIC_PLATFORM)
            .bind(platform_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(platform_from_row)
            .transpose()
    }

    /// Persist a pure domain reconfiguration under CAS. When configuration
    /// changed, all live bindings are invalidated in the same transaction.
    pub async fn save_platform_configuration(
        &self,
        platform: &CanvasPlatformRecord,
        expected_config_version: i64,
        configuration_changed: bool,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        let expected_version = version_i32(expected_config_version)?;
        let next_version = expected_config_version
            .checked_add(1)
            .ok_or(CanvasManagementRepositoryError::Unavailable)?;
        let persisted_version = version_i32(platform.config_version)?;
        if (configuration_changed && platform.config_version != next_version)
            || (!configuration_changed && platform.config_version != expected_config_version)
        {
            return Err(CanvasManagementRepositoryError::Unavailable);
        }
        let mut transaction = self.pool.begin().await.map_err(repository_error)?;
        let row = if configuration_changed {
            bind_platform_update(
                sqlx::query(UPDATE_PLATFORM_CONFIGURATION),
                platform,
                expected_version,
                persisted_version,
            )
            .fetch_optional(&mut *transaction)
            .await
            .map_err(repository_error)?
        } else {
            let enabled_intent = platform
                .connection_config
                .get("enabled_intent")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            sqlx::query(TOUCH_PLATFORM_CONFIGURATION)
                .bind(&platform.organization_id)
                .bind(&platform.id)
                .bind(expected_version)
                .bind(&platform.display_name)
                .bind(&platform.canvas_base_url)
                .bind(&platform.lti_client_id)
                .bind(&platform.lti_deployment_id)
                .bind(&platform.lti_trust_profile)
                .bind(enabled_intent)
                .bind(platform.updated_at)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(repository_error)?
        };

        let Some(row) = row else {
            transaction.rollback().await.map_err(repository_error)?;
            return Ok(None);
        };
        if configuration_changed {
            sqlx::query(INVALIDATE_PLATFORM_BINDINGS)
                .bind(&platform.organization_id)
                .bind(&platform.id)
                .bind(platform.updated_at)
                .execute(&mut *transaction)
                .await
                .map_err(repository_error)?;
        }
        transaction.commit().await.map_err(repository_error)?;
        platform_from_row(row).map(Some)
    }

    /// Atomically queue durable OAuth revocation, archive the tenant platform,
    /// and disable/archive every live binding. The platform row lock is the
    /// same serialization boundary used by OAuth callback publication.
    pub async fn archive_platform(
        &self,
        organization_id: &str,
        platform_id: &str,
        expected_config_version: i64,
        now: DateTime<Utc>,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(repository_error)?;
        let row = sqlx::query(LOCK_PLATFORM_FOR_ARCHIVAL)
            .bind(organization_id)
            .bind(platform_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(repository_error)?;
        let Some(row) = row else {
            transaction.rollback().await.map_err(repository_error)?;
            return Ok(None);
        };
        let mut platform = platform_from_row(row)?;
        if platform.archived_at.is_none() && platform.config_version != expected_config_version {
            transaction.rollback().await.map_err(repository_error)?;
            return Err(CanvasManagementRepositoryError::ConfigurationChanged);
        }

        let queue_outcome = queue_canvas_oauth_revocation_in_transaction(
            &mut transaction,
            organization_id,
            platform_id,
            now,
            "canvas_platform_archived",
        )
        .await
        .map_err(|_| CanvasManagementRepositoryError::Unavailable)?;
        let connection_exists = !matches!(queue_outcome, CanvasOAuthRevocationQueueOutcome::Absent);
        if queue_outcome == CanvasOAuthRevocationQueueOutcome::Disconnected {
            transaction.rollback().await.map_err(repository_error)?;
            return Err(CanvasManagementRepositoryError::OAuthConnectionChanged);
        }

        let locked_version = platform.config_version;
        let archived_now = platform
            .archive(connection_exists, now)
            .map_err(|_| CanvasManagementRepositoryError::VersionExhausted)?;
        if !archived_now {
            platform.synchronize_archived_oauth_state(connection_exists, now);
        }
        let persisted_version = version_i32(platform.config_version)?;
        let row = sqlx::query(PERSIST_PLATFORM_ARCHIVE)
            .bind(organization_id)
            .bind(platform_id)
            .bind(version_i32(locked_version)?)
            .bind(&platform.registration_status)
            .bind(Value::Object(platform.connection_config.clone()))
            .bind(persisted_version)
            .bind(platform.archived_at)
            .bind(platform.enabled)
            .bind(platform.updated_at)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(repository_error)?;
        let Some(row) = row else {
            transaction.rollback().await.map_err(repository_error)?;
            return Err(CanvasManagementRepositoryError::ConfigurationChanged);
        };
        sqlx::query(ARCHIVE_PLATFORM_BINDINGS)
            .bind(organization_id)
            .bind(platform_id)
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(repository_error)?;
        transaction.commit().await.map_err(repository_error)?;
        platform_from_row(row).map(Some)
    }

    pub async fn save_registration_state(
        &self,
        platform: &CanvasPlatformRecord,
        expected_config_version: i64,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        sqlx::query(PERSIST_REGISTRATION_STATE)
            .bind(&platform.organization_id)
            .bind(&platform.id)
            .bind(version_i32(expected_config_version)?)
            .bind(expected_updated_at)
            .bind(Value::Object(platform.connection_config.clone()))
            .bind(platform.updated_at)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(platform_from_row)
            .transpose()
    }

    pub async fn save_lti_installation(
        &self,
        platform: &CanvasPlatformRecord,
        expected_config_version: i64,
        expected_updated_at: DateTime<Utc>,
        invalidate_bindings: bool,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        let expected_version = version_i32(expected_config_version)?;
        let persisted_version = version_i32(platform.config_version)?;
        let mut transaction = self.pool.begin().await.map_err(repository_error)?;
        let row = bind_lti_installation(
            sqlx::query(PERSIST_LTI_INSTALLATION),
            platform,
            expected_version,
            expected_updated_at,
            persisted_version,
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(repository_error)?;
        let Some(row) = row else {
            transaction.rollback().await.map_err(repository_error)?;
            return Ok(None);
        };
        if invalidate_bindings {
            sqlx::query(INVALIDATE_PLATFORM_BINDINGS)
                .bind(&platform.organization_id)
                .bind(&platform.id)
                .bind(platform.updated_at)
                .execute(&mut *transaction)
                .await
                .map_err(repository_error)?;
        }
        transaction.commit().await.map_err(repository_error)?;
        platform_from_row(row).map(Some)
    }
}

#[async_trait::async_trait]
impl CanvasPlatformManagementRepository for PostgresCanvasManagementRepository {
    async fn create_platform(
        &self,
        platform: &CanvasPlatformRecord,
    ) -> Result<(), CanvasManagementRepositoryError> {
        PostgresCanvasManagementRepository::create_platform(self, platform).await
    }

    async fn active_platform(
        &self,
        organization_id: &str,
        platform_id: &str,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        PostgresCanvasManagementRepository::active_platform(self, organization_id, platform_id)
            .await
    }

    async fn list_active_platforms(
        &self,
        organization_id: &str,
    ) -> Result<Vec<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        PostgresCanvasManagementRepository::list_active_platforms(self, organization_id).await
    }

    async fn public_platform(
        &self,
        platform_id: &str,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        PostgresCanvasManagementRepository::public_platform(self, platform_id).await
    }

    async fn platform_for_archival(
        &self,
        organization_id: &str,
        platform_id: &str,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        PostgresCanvasManagementRepository::platform_for_archival(
            self,
            organization_id,
            platform_id,
        )
        .await
    }

    async fn save_platform_configuration(
        &self,
        platform: &CanvasPlatformRecord,
        expected_config_version: i64,
        configuration_changed: bool,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        PostgresCanvasManagementRepository::save_platform_configuration(
            self,
            platform,
            expected_config_version,
            configuration_changed,
        )
        .await
    }

    async fn archive_platform(
        &self,
        organization_id: &str,
        platform_id: &str,
        expected_config_version: i64,
        now: DateTime<Utc>,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        PostgresCanvasManagementRepository::archive_platform(
            self,
            organization_id,
            platform_id,
            expected_config_version,
            now,
        )
        .await
    }

    async fn save_registration_state(
        &self,
        platform: &CanvasPlatformRecord,
        expected_config_version: i64,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        PostgresCanvasManagementRepository::save_registration_state(
            self,
            platform,
            expected_config_version,
            expected_updated_at,
        )
        .await
    }

    async fn save_lti_installation(
        &self,
        platform: &CanvasPlatformRecord,
        expected_config_version: i64,
        expected_updated_at: DateTime<Utc>,
        invalidate_bindings: bool,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        PostgresCanvasManagementRepository::save_lti_installation(
            self,
            platform,
            expected_config_version,
            expected_updated_at,
            invalidate_bindings,
        )
        .await
    }
}

fn bind_lti_installation<'query>(
    query: sqlx::query::Query<'query, sqlx::Postgres, sqlx::postgres::PgArguments>,
    platform: &'query CanvasPlatformRecord,
    expected_config_version: i32,
    expected_updated_at: DateTime<Utc>,
    persisted_config_version: i32,
) -> sqlx::query::Query<'query, sqlx::Postgres, sqlx::postgres::PgArguments> {
    query
        .bind(&platform.organization_id)
        .bind(&platform.id)
        .bind(expected_config_version)
        .bind(expected_updated_at)
        .bind(&platform.canvas_base_url)
        .bind(&platform.lti_client_id)
        .bind(&platform.lti_deployment_id)
        .bind(&platform.lti_trust_profile)
        .bind(&platform.lti_issuer)
        .bind(&platform.lti_jwks_url)
        .bind(&platform.lti_jwks_json)
        .bind(platform.lti_jwks_fetched_at)
        .bind(platform.lti_jwks_expires_at)
        .bind(&platform.lti_openid_configuration)
        .bind(&platform.registration_status)
        .bind(Value::Object(platform.connection_config.clone()))
        .bind(Value::Object(platform.capability_snapshot.clone()))
        .bind(platform.last_validated_at)
        .bind(&platform.last_connection_error)
        .bind(persisted_config_version)
        .bind(platform.enabled)
        .bind(platform.updated_at)
}

fn bind_platform_insert<'query>(
    query: sqlx::query::Query<'query, sqlx::Postgres, sqlx::postgres::PgArguments>,
    platform: &'query CanvasPlatformRecord,
    config_version: i32,
) -> sqlx::query::Query<'query, sqlx::Postgres, sqlx::postgres::PgArguments> {
    query
        .bind(&platform.id)
        .bind(&platform.organization_id)
        .bind(&platform.canvas_account_id)
        .bind(&platform.display_name)
        .bind(&platform.canvas_base_url)
        .bind(&platform.lti_client_id)
        .bind(&platform.lti_deployment_id)
        .bind(&platform.lti_trust_profile)
        .bind(&platform.lti_issuer)
        .bind(&platform.lti_jwks_url)
        .bind(&platform.lti_jwks_json)
        .bind(platform.lti_jwks_fetched_at)
        .bind(platform.lti_jwks_expires_at)
        .bind(&platform.lti_openid_configuration)
        .bind(&platform.registration_status)
        .bind(Value::Object(platform.connection_config.clone()))
        .bind(Value::Object(platform.capability_snapshot.clone()))
        .bind(platform.last_validated_at)
        .bind(&platform.last_connection_error)
        .bind(config_version)
        .bind(platform.archived_at)
        .bind(platform.enabled)
        .bind(platform.created_at)
        .bind(platform.updated_at)
}

fn bind_platform_update<'query>(
    query: sqlx::query::Query<'query, sqlx::Postgres, sqlx::postgres::PgArguments>,
    platform: &'query CanvasPlatformRecord,
    expected_config_version: i32,
    persisted_config_version: i32,
) -> sqlx::query::Query<'query, sqlx::Postgres, sqlx::postgres::PgArguments> {
    let enabled_intent = platform
        .connection_config
        .get("enabled_intent")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    query
        .bind(&platform.organization_id)
        .bind(&platform.id)
        .bind(expected_config_version)
        .bind(&platform.display_name)
        .bind(&platform.canvas_base_url)
        .bind(&platform.lti_client_id)
        .bind(&platform.lti_deployment_id)
        .bind(&platform.lti_trust_profile)
        .bind(&platform.lti_issuer)
        .bind(&platform.lti_jwks_url)
        .bind(&platform.lti_jwks_json)
        .bind(platform.lti_jwks_fetched_at)
        .bind(platform.lti_jwks_expires_at)
        .bind(&platform.lti_openid_configuration)
        .bind(&platform.registration_status)
        .bind(enabled_intent)
        .bind(Value::Object(platform.capability_snapshot.clone()))
        .bind(platform.last_validated_at)
        .bind(&platform.last_connection_error)
        .bind(persisted_config_version)
        .bind(platform.enabled)
        .bind(platform.updated_at)
}

fn platform_from_row(row: PgRow) -> Result<CanvasPlatformRecord, CanvasManagementRepositoryError> {
    Ok(CanvasPlatformRecord {
        id: row_value(&row, "id")?,
        organization_id: row_value(&row, "organization_id")?,
        canvas_account_id: row_value(&row, "canvas_account_id")?,
        display_name: row_value(&row, "display_name")?,
        canvas_base_url: row_value(&row, "canvas_base_url")?,
        lti_client_id: row_value(&row, "lti_client_id")?,
        lti_deployment_id: row_value(&row, "lti_deployment_id")?,
        lti_trust_profile: row_value(&row, "lti_trust_profile")?,
        lti_issuer: row_value(&row, "lti_issuer")?,
        lti_jwks_url: row_value(&row, "lti_jwks_url")?,
        lti_jwks_json: row_value(&row, "lti_jwks_json")?,
        lti_jwks_fetched_at: row_value(&row, "lti_jwks_fetched_at")?,
        lti_jwks_expires_at: row_value(&row, "lti_jwks_expires_at")?,
        lti_openid_configuration: row_value(&row, "lti_openid_configuration")?,
        registration_status: row_value(&row, "registration_status")?,
        connection_config: json_object(row_value(&row, "connection_config")?)?,
        capability_snapshot: json_object(row_value(&row, "capability_snapshot")?)?,
        last_validated_at: row_value(&row, "last_validated_at")?,
        last_connection_error: row_value(&row, "last_connection_error")?,
        config_version: i64::from(row_value::<i32>(&row, "config_version")?),
        archived_at: row_value(&row, "archived_at")?,
        enabled: row_value(&row, "enabled")?,
        created_at: row_value(&row, "created_at")?,
        updated_at: row_value(&row, "updated_at")?,
    })
}

fn row_value<T>(row: &PgRow, column: &str) -> Result<T, CanvasManagementRepositoryError>
where
    for<'decode> T: sqlx::Decode<'decode, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(column).map_err(repository_error)
}

fn json_object(value: Value) -> Result<Map<String, Value>, CanvasManagementRepositoryError> {
    value
        .as_object()
        .cloned()
        .ok_or(CanvasManagementRepositoryError::Unavailable)
}

fn version_i32(value: i64) -> Result<i32, CanvasManagementRepositoryError> {
    if value < 1 {
        return Err(CanvasManagementRepositoryError::Unavailable);
    }
    i32::try_from(value).map_err(|_| CanvasManagementRepositoryError::Unavailable)
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|error| error.code())
        .is_some_and(|code| code == "23505")
}

fn repository_error(cause: sqlx::Error) -> CanvasManagementRepositoryError {
    error!(%cause, "Canvas management repository query failed");
    CanvasManagementRepositoryError::Unavailable
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;

    #[test]
    fn management_queries_are_tenant_and_archive_scoped() {
        for query in [GET_ACTIVE_PLATFORM, LIST_ACTIVE_PLATFORMS] {
            assert!(query.contains("organization_id = $1"));
            assert!(query.contains("archived_at IS NULL"));
        }
    }

    #[test]
    fn configuration_cas_and_readiness_invalidation_are_explicit() {
        assert!(UPDATE_PLATFORM_CONFIGURATION.contains("config_version = $3"));
        assert!(UPDATE_PLATFORM_CONFIGURATION.contains("archived_at IS NULL"));
        assert!(INVALIDATE_PLATFORM_BINDINGS.contains("validated_config_version = NULL"));
        assert!(INVALIDATE_PLATFORM_BINDINGS.contains("readiness_checks = '[]'::jsonb"));
        assert!(INVALIDATE_PLATFORM_BINDINGS.contains("activated_at = NULL"));
    }

    #[test]
    fn archival_queries_preserve_tenant_cas_locking_and_atomic_binding_cleanup() {
        assert!(GET_PLATFORM_FOR_ARCHIVAL.contains("organization_id = $1 AND id = $2"));
        assert!(!GET_PLATFORM_FOR_ARCHIVAL.contains("archived_at IS NULL"));
        assert!(LOCK_PLATFORM_FOR_ARCHIVAL.contains("organization_id = $1 AND id = $2"));
        assert!(LOCK_PLATFORM_FOR_ARCHIVAL.contains("FOR UPDATE"));
        assert!(PERSIST_PLATFORM_ARCHIVE.contains("config_version = $3"));
        assert!(PERSIST_PLATFORM_ARCHIVE.contains("connection_config = $5"));
        assert!(ARCHIVE_PLATFORM_BINDINGS.contains("organization_id = $1"));
        assert!(ARCHIVE_PLATFORM_BINDINGS.contains("platform_id = $2"));
        assert!(ARCHIVE_PLATFORM_BINDINGS.contains("archived_at IS NULL"));
        assert!(GET_PUBLIC_PLATFORM.contains("WHERE id = $1"));
        assert!(PERSIST_REGISTRATION_STATE.contains("config_version = $3"));
        assert!(PERSIST_REGISTRATION_STATE.contains("updated_at = $4"));
        assert!(PERSIST_REGISTRATION_STATE.contains("archived_at IS NULL"));
    }

    #[test]
    fn platform_projection_covers_the_complete_persisted_record() {
        for column in [
            "lti_jwks_json",
            "lti_jwks_fetched_at",
            "lti_jwks_expires_at",
            "lti_openid_configuration",
            "connection_config",
            "capability_snapshot",
            "config_version",
            "archived_at",
        ] {
            assert!(PLATFORM_COLUMNS.contains(column), "missing {column}");
            assert!(GET_ACTIVE_PLATFORM.contains(column), "missing {column}");
        }
    }

    #[test]
    fn feature_intent_patch_preserves_operational_connection_keys() {
        for query in [UPDATE_PLATFORM_CONFIGURATION, TOUCH_PLATFORM_CONFIGURATION] {
            assert!(query.contains("COALESCE(connection_config"));
            assert!(query.contains("jsonb_set"));
            assert!(query.contains("enabled_intent"));
            assert!(query.contains("lti_capability_intent"));
        }
    }

    #[test]
    fn feature_flag_map_shape_is_btree_compatible() {
        let value = Value::Object(
            BTreeMap::from([("enabled".to_owned(), json!(true))])
                .into_iter()
                .collect(),
        );
        assert_eq!(json_object(value).unwrap()["enabled"], json!(true));
    }

    #[test]
    fn persisted_configuration_versions_are_positive_i32_values() {
        assert_eq!(version_i32(1).unwrap(), 1);
        assert_eq!(
            version_i32(0),
            Err(CanvasManagementRepositoryError::Unavailable)
        );
        assert_eq!(
            version_i32(i64::from(i32::MAX) + 1),
            Err(CanvasManagementRepositoryError::Unavailable)
        );
    }
}
