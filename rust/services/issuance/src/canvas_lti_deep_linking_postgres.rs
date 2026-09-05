use async_trait::async_trait;
use serde_json::Value;
use sqlx::{PgPool, Row};

use crate::{
    canvas_lti_deep_linking::{
        CanvasLtiDeepLinkingBinding, CanvasLtiDeepLinkingError,
        CanvasLtiDeepLinkingPersistenceScope, CanvasLtiDeepLinkingPlatform,
        CanvasLtiDeepLinkingRepository,
    },
    canvas_lti_experience::CanvasLtiExperienceSessionContext,
    canvas_lti_launch::feature_enabled,
};

const GET_BOUND_FEATURE_FLAGS: &str = "SELECT feature_flags
    FROM issuance_service.canvas_program_bindings
    WHERE id = $1 AND organization_id = $2";

const GET_SESSION_PLATFORM: &str = "SELECT id, organization_id, canvas_account_id,
        lti_client_id, lti_deployment_id, lti_issuer, config_version
    FROM issuance_service.canvas_platforms
    WHERE id = $1 AND organization_id = $2 AND canvas_account_id = $3";

const GET_SESSION_BINDING: &str = "SELECT id, organization_id, platform_id, display_name,
        application_template_id, credential_template_id, feature_flags,
        evidence_requirements, config_version
    FROM issuance_service.canvas_program_bindings
    WHERE id = $1 AND organization_id = $2 AND platform_id = $3";

const PERSIST_DEEP_LINKING_RESPONSE: &str = "WITH valid_scope AS (
        SELECT 1
        FROM issuance_service.canvas_platforms AS platform
        JOIN issuance_service.canvas_program_bindings AS binding
          ON binding.platform_id = platform.id
         AND binding.organization_id = platform.organization_id
        WHERE platform.id = $3
          AND platform.organization_id = $7
          AND platform.canvas_account_id = $8
          AND platform.config_version = $4
          AND binding.id = $5
          AND binding.config_version = $6
    )
    UPDATE issuance_service.canvas_lti_launch_states AS session
    SET metadata = jsonb_set(
        session.metadata::jsonb,
        '{deep_linking_response}',
        $9::jsonb,
        true
    )
    FROM valid_scope
    WHERE session.id = $1
      AND session.state = $2
      AND session.platform_id = $3
      AND session.organization_id = $7
      AND session.canvas_account_id = $8
      AND session.status = 'session'
      AND session.expires_at > clock_timestamp()
      AND session.metadata->>'kind' = 'canvas_lti_experience_session'";

#[derive(Clone, Debug)]
pub struct PostgresCanvasLtiDeepLinkingRepository {
    pool: PgPool,
}

impl PostgresCanvasLtiDeepLinkingRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CanvasLtiDeepLinkingRepository for PostgresCanvasLtiDeepLinkingRepository {
    async fn bound_feature_enabled(
        &self,
        organization_id: &str,
        binding_id: &str,
    ) -> Result<Option<bool>, CanvasLtiDeepLinkingError> {
        let row = sqlx::query(GET_BOUND_FEATURE_FLAGS)
            .bind(binding_id)
            .bind(organization_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?;
        let Some(row) = row else { return Ok(None) };
        let flags: Value = row.try_get("feature_flags").map_err(repository_error)?;
        Ok(Some(feature_enabled(&flags, "enable_canvas_deep_linking")))
    }

    async fn get_platform(
        &self,
        context: &CanvasLtiExperienceSessionContext,
    ) -> Result<Option<CanvasLtiDeepLinkingPlatform>, CanvasLtiDeepLinkingError> {
        sqlx::query(GET_SESSION_PLATFORM)
            .bind(&context.canvas_platform_id)
            .bind(&context.launch_state.organization_id)
            .bind(&context.launch_state.canvas_account_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(platform_from_row)
            .transpose()
    }

    async fn get_binding(
        &self,
        context: &CanvasLtiExperienceSessionContext,
        platform: &CanvasLtiDeepLinkingPlatform,
    ) -> Result<Option<CanvasLtiDeepLinkingBinding>, CanvasLtiDeepLinkingError> {
        let Some(binding_id) = context.canvas_program_binding_id.as_deref() else {
            return Ok(None);
        };
        sqlx::query(GET_SESSION_BINDING)
            .bind(binding_id)
            .bind(&platform.organization_id)
            .bind(&platform.id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(binding_from_row)
            .transpose()
    }

    async fn persist_response(
        &self,
        scope: &CanvasLtiDeepLinkingPersistenceScope,
        response_metadata: &Value,
    ) -> Result<(), CanvasLtiDeepLinkingError> {
        let result = sqlx::query(PERSIST_DEEP_LINKING_RESPONSE)
            .bind(&scope.session_id)
            .bind(&scope.session_state)
            .bind(&scope.platform_id)
            .bind(scope.platform_config_version)
            .bind(&scope.binding_id)
            .bind(scope.binding_config_version)
            .bind(&scope.organization_id)
            .bind(&scope.canvas_account_id)
            .bind(response_metadata)
            .execute(&self.pool)
            .await
            .map_err(repository_error)?;
        if result.rows_affected() != 1 {
            return Err(CanvasLtiDeepLinkingError::ConfigurationDrift);
        }
        Ok(())
    }
}

fn platform_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<CanvasLtiDeepLinkingPlatform, CanvasLtiDeepLinkingError> {
    Ok(CanvasLtiDeepLinkingPlatform {
        id: row.try_get("id").map_err(repository_error)?,
        organization_id: row.try_get("organization_id").map_err(repository_error)?,
        canvas_account_id: row.try_get("canvas_account_id").map_err(repository_error)?,
        lti_client_id: row.try_get("lti_client_id").map_err(repository_error)?,
        lti_deployment_id: row.try_get("lti_deployment_id").map_err(repository_error)?,
        lti_issuer: row.try_get("lti_issuer").map_err(repository_error)?,
        config_version: row
            .try_get::<i32, _>("config_version")
            .map(i64::from)
            .map_err(repository_error)?,
    })
}

fn binding_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<CanvasLtiDeepLinkingBinding, CanvasLtiDeepLinkingError> {
    let evidence_requirements: Value = row
        .try_get("evidence_requirements")
        .map_err(repository_error)?;
    Ok(CanvasLtiDeepLinkingBinding {
        id: row.try_get("id").map_err(repository_error)?,
        organization_id: row.try_get("organization_id").map_err(repository_error)?,
        platform_id: row.try_get("platform_id").map_err(repository_error)?,
        display_name: row.try_get("display_name").map_err(repository_error)?,
        application_template_id: row
            .try_get("application_template_id")
            .map_err(repository_error)?,
        credential_template_id: row
            .try_get("credential_template_id")
            .map_err(repository_error)?,
        feature_flags: row.try_get("feature_flags").map_err(repository_error)?,
        evidence_requirements: evidence_requirements
            .as_array()
            .cloned()
            .ok_or(CanvasLtiDeepLinkingError::RepositoryUnavailable)?,
        config_version: row
            .try_get::<i32, _>("config_version")
            .map(i64::from)
            .map_err(repository_error)?,
    })
}

fn repository_error(_cause: sqlx::Error) -> CanvasLtiDeepLinkingError {
    CanvasLtiDeepLinkingError::RepositoryUnavailable
}
