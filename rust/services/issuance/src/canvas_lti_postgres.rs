use async_trait::async_trait;
use serde_json::Value;
use sqlx::{PgPool, Row};
use tracing::error;

use crate::canvas_lti_login::{
    CanvasLtiLaunchState, CanvasLtiLoginError, CanvasLtiLoginRepository, CanvasLtiPlatform,
};

const GET_PLATFORM: &str = "SELECT id, organization_id, canvas_account_id, canvas_base_url,
        lti_client_id, lti_deployment_id, lti_trust_profile, lti_issuer, lti_jwks_url,
        lti_jwks_json, lti_openid_configuration, enabled
     FROM issuance_service.canvas_platforms
     WHERE id = $1";

const SAVE_LAUNCH_STATE: &str = "WITH database_clock AS (
        SELECT clock_timestamp() AS now
    )
    INSERT INTO issuance_service.canvas_lti_launch_states (
        id, platform_id, organization_id, canvas_account_id, state, nonce, login_hint,
        target_link_uri, lti_message_hint, redirect_uri, status, metadata,
        created_at, expires_at, consumed_at
    ) SELECT
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'pending', $11,
        database_clock.now,
        database_clock.now + ($12::double precision * interval '1 second'),
        NULL
    FROM database_clock";

#[derive(Clone)]
pub struct PostgresCanvasLtiLoginRepository {
    pool: PgPool,
}

impl std::fmt::Debug for PostgresCanvasLtiLoginRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresCanvasLtiLoginRepository")
            .finish_non_exhaustive()
    }
}

impl PostgresCanvasLtiLoginRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CanvasLtiLoginRepository for PostgresCanvasLtiLoginRepository {
    async fn get_platform(
        &self,
        platform_id: &str,
    ) -> Result<Option<CanvasLtiPlatform>, CanvasLtiLoginError> {
        let row = sqlx::query(GET_PLATFORM)
            .bind(platform_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?;
        row.map(|row| {
            Ok(CanvasLtiPlatform {
                id: row.try_get("id").map_err(repository_error)?,
                organization_id: row.try_get("organization_id").map_err(repository_error)?,
                canvas_account_id: row.try_get("canvas_account_id").map_err(repository_error)?,
                canvas_base_url: row.try_get("canvas_base_url").map_err(repository_error)?,
                lti_client_id: row.try_get("lti_client_id").map_err(repository_error)?,
                lti_deployment_id: row.try_get("lti_deployment_id").map_err(repository_error)?,
                lti_trust_profile: row
                    .try_get::<Option<String>, _>("lti_trust_profile")
                    .map_err(repository_error)?
                    .unwrap_or_else(|| "hosted_global".to_owned()),
                lti_issuer: row.try_get("lti_issuer").map_err(repository_error)?,
                lti_jwks_url: row.try_get("lti_jwks_url").map_err(repository_error)?,
                lti_jwks_json: row
                    .try_get::<Option<Value>, _>("lti_jwks_json")
                    .map_err(repository_error)?,
                lti_openid_configuration: row
                    .try_get::<Option<Value>, _>("lti_openid_configuration")
                    .map_err(repository_error)?,
                enabled: row.try_get("enabled").map_err(repository_error)?,
            })
        })
        .transpose()
    }

    async fn save_launch_state(
        &self,
        launch_state: &CanvasLtiLaunchState,
    ) -> Result<(), CanvasLtiLoginError> {
        let ttl_seconds = launch_state.ttl.as_secs();
        if ttl_seconds == 0 || ttl_seconds > i64::MAX as u64 {
            return Err(CanvasLtiLoginError::RepositoryUnavailable);
        }
        sqlx::query(SAVE_LAUNCH_STATE)
            .bind(&launch_state.id)
            .bind(&launch_state.platform_id)
            .bind(&launch_state.organization_id)
            .bind(&launch_state.canvas_account_id)
            .bind(&launch_state.state)
            .bind(&launch_state.nonce)
            .bind(&launch_state.login_hint)
            .bind(&launch_state.target_link_uri)
            .bind(&launch_state.lti_message_hint)
            .bind(&launch_state.redirect_uri)
            .bind(&launch_state.metadata)
            .bind(ttl_seconds as i64)
            .execute(&self.pool)
            .await
            .map_err(repository_error)?;
        Ok(())
    }
}

fn repository_error(cause: sqlx::Error) -> CanvasLtiLoginError {
    error!(%cause, "Canvas LTI login repository query failed");
    CanvasLtiLoginError::RepositoryUnavailable
}
