use async_trait::async_trait;
use serde_json::Value;
use sqlx::{PgPool, Row};
use tracing::error;

use crate::canvas_lti_launch::{
    plan_verified_identity, CanvasLtiIdentityRecord, CanvasLtiIdentityRepository,
    CanvasLtiIdentityRequest, CanvasLtiIdentityStatus, CanvasLtiLaunchContextRepository,
    CanvasLtiLaunchPlanError, CanvasLtiLaunchStateRepository, CanvasLtiProgramBinding,
    CanvasLtiStoredLaunchState,
};
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

const GET_LAUNCH_STATE: &str = "SELECT platform_id, state, nonce, status,
        expires_at <= clock_timestamp() AS expired
    FROM issuance_service.canvas_lti_launch_states
    WHERE state = $1";

const CONSUME_LAUNCH_STATE: &str = "UPDATE issuance_service.canvas_lti_launch_states
    SET status = 'consumed', consumed_at = clock_timestamp()
    WHERE state = $1
      AND status = 'pending'
      AND expires_at > clock_timestamp()
    RETURNING platform_id, state, nonce, status, false AS expired";

const LIST_PROGRAM_BINDINGS: &str = "SELECT id, organization_id, platform_id,
        application_template_id, credential_template_id, delivery_mode,
        deployment_profile_id, feature_flags, evidence_requirements, canvas_scope, enabled
    FROM issuance_service.canvas_program_bindings
    WHERE organization_id = $1 AND platform_id = $2
    ORDER BY created_at";

const LOCK_IDENTITY_SCOPE: &str = "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))";

const GET_IDENTITY_BY_SUBJECT: &str = "SELECT id, organization_id, platform_id,
        deployment_id, lti_subject, canvas_user_id, status, conflict_reason
    FROM issuance_service.canvas_learner_identities
    WHERE organization_id = $1 AND platform_id = $2 AND deployment_id = $3
      AND lti_subject = $4
    FOR UPDATE";

const GET_IDENTITY_BY_CANVAS_USER: &str = "SELECT id, organization_id, platform_id,
        deployment_id, lti_subject, canvas_user_id, status, conflict_reason
    FROM issuance_service.canvas_learner_identities
    WHERE organization_id = $1 AND platform_id = $2 AND deployment_id = $3
      AND canvas_user_id = $4
    FOR UPDATE";

const SAVE_IDENTITY: &str = "INSERT INTO issuance_service.canvas_learner_identities (
        id, organization_id, platform_id, deployment_id, lti_subject, canvas_user_id,
        sis_user_id, status, conflict_reason, verified_at, created_at, updated_at
    ) VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, $8,
        clock_timestamp(), clock_timestamp(), clock_timestamp())
    ON CONFLICT (platform_id, deployment_id, lti_subject) DO UPDATE SET
        canvas_user_id = EXCLUDED.canvas_user_id,
        status = EXCLUDED.status,
        conflict_reason = EXCLUDED.conflict_reason,
        verified_at = clock_timestamp(),
        updated_at = clock_timestamp()
    RETURNING id, organization_id, platform_id, deployment_id, lti_subject,
        canvas_user_id, status, conflict_reason";

const QUARANTINE_IDENTITY: &str = "UPDATE issuance_service.canvas_learner_identities
    SET status = 'quarantined', conflict_reason = $3, updated_at = clock_timestamp()
    WHERE id = $1 AND organization_id = $2";

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

#[async_trait]
impl CanvasLtiLaunchStateRepository for PostgresCanvasLtiLoginRepository {
    async fn get_launch_state(
        &self,
        state: &str,
    ) -> Result<Option<CanvasLtiStoredLaunchState>, CanvasLtiLaunchPlanError> {
        let row = sqlx::query(GET_LAUNCH_STATE)
            .bind(state)
            .fetch_optional(&self.pool)
            .await
            .map_err(launch_repository_error)?;
        row.map(stored_launch_state).transpose()
    }

    async fn consume_launch_state(
        &self,
        state: &str,
    ) -> Result<Option<CanvasLtiStoredLaunchState>, CanvasLtiLaunchPlanError> {
        let row = sqlx::query(CONSUME_LAUNCH_STATE)
            .bind(state)
            .fetch_optional(&self.pool)
            .await
            .map_err(launch_repository_error)?;
        row.map(stored_launch_state).transpose()
    }
}

#[async_trait]
impl CanvasLtiLaunchContextRepository for PostgresCanvasLtiLoginRepository {
    async fn list_program_bindings(
        &self,
        organization_id: &str,
        platform_id: &str,
    ) -> Result<Vec<CanvasLtiProgramBinding>, CanvasLtiLaunchPlanError> {
        sqlx::query(LIST_PROGRAM_BINDINGS)
            .bind(organization_id)
            .bind(platform_id)
            .fetch_all(&self.pool)
            .await
            .map_err(launch_repository_error)?
            .into_iter()
            .map(program_binding)
            .collect()
    }
}

#[async_trait]
impl CanvasLtiIdentityRepository for PostgresCanvasLtiLoginRepository {
    async fn reconcile_verified_identity(
        &self,
        request: &CanvasLtiIdentityRequest,
    ) -> Result<CanvasLtiIdentityRecord, CanvasLtiLaunchPlanError> {
        if request.organization_id.is_empty()
            || request.platform_id.is_empty()
            || request.deployment_id.is_empty()
            || request.lti_subject.is_empty()
        {
            return Err(CanvasLtiLaunchPlanError::Invalid(
                "Canvas LTI verified identity is incomplete",
            ));
        }
        let mut transaction = self.pool.begin().await.map_err(launch_repository_error)?;
        let lock_key = format!(
            "{}\u{1f}{}\u{1f}{}",
            request.organization_id, request.platform_id, request.deployment_id
        );
        sqlx::query(LOCK_IDENTITY_SCOPE)
            .bind(lock_key)
            .execute(&mut *transaction)
            .await
            .map_err(launch_repository_error)?;
        let existing_subject = sqlx::query(GET_IDENTITY_BY_SUBJECT)
            .bind(&request.organization_id)
            .bind(&request.platform_id)
            .bind(&request.deployment_id)
            .bind(&request.lti_subject)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(launch_repository_error)?
            .map(identity_record)
            .transpose()?;
        let existing_numeric = if let Some(canvas_user_id) = request.canvas_user_id.as_ref() {
            sqlx::query(GET_IDENTITY_BY_CANVAS_USER)
                .bind(&request.organization_id)
                .bind(&request.platform_id)
                .bind(&request.deployment_id)
                .bind(canvas_user_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(launch_repository_error)?
                .map(identity_record)
                .transpose()?
        } else {
            None
        };
        let plan = plan_verified_identity(
            request,
            existing_subject.as_ref(),
            existing_numeric.as_ref(),
            &uuid::Uuid::new_v4().to_string(),
        );
        if let Some(existing) = plan.quarantine_existing.as_ref() {
            sqlx::query(QUARANTINE_IDENTITY)
                .bind(&existing.id)
                .bind(&existing.organization_id)
                .bind(&existing.conflict_reason)
                .execute(&mut *transaction)
                .await
                .map_err(launch_repository_error)?;
        }
        let stored = sqlx::query(SAVE_IDENTITY)
            .bind(&plan.identity.id)
            .bind(&plan.identity.organization_id)
            .bind(&plan.identity.platform_id)
            .bind(&plan.identity.deployment_id)
            .bind(&plan.identity.lti_subject)
            .bind(&plan.identity.canvas_user_id)
            .bind(plan.identity.status.as_str())
            .bind(&plan.identity.conflict_reason)
            .fetch_one(&mut *transaction)
            .await
            .map_err(launch_repository_error)
            .and_then(identity_record)?;
        transaction
            .commit()
            .await
            .map_err(launch_repository_error)?;
        Ok(stored)
    }
}

fn program_binding(
    row: sqlx::postgres::PgRow,
) -> Result<CanvasLtiProgramBinding, CanvasLtiLaunchPlanError> {
    let evidence_requirements: Value = row
        .try_get("evidence_requirements")
        .map_err(launch_repository_error)?;
    let evidence_requirements = evidence_requirements
        .as_array()
        .cloned()
        .ok_or(CanvasLtiLaunchPlanError::RepositoryUnavailable)?;
    Ok(CanvasLtiProgramBinding {
        id: row.try_get("id").map_err(launch_repository_error)?,
        organization_id: row
            .try_get("organization_id")
            .map_err(launch_repository_error)?,
        platform_id: row
            .try_get("platform_id")
            .map_err(launch_repository_error)?,
        application_template_id: row
            .try_get("application_template_id")
            .map_err(launch_repository_error)?,
        credential_template_id: row
            .try_get("credential_template_id")
            .map_err(launch_repository_error)?,
        delivery_mode: row
            .try_get::<Option<String>, _>("delivery_mode")
            .map_err(launch_repository_error)?
            .unwrap_or_else(|| "wallet_only".to_owned()),
        deployment_profile_id: row
            .try_get("deployment_profile_id")
            .map_err(launch_repository_error)?,
        feature_flags: row
            .try_get("feature_flags")
            .map_err(launch_repository_error)?,
        evidence_requirements,
        canvas_scope: row
            .try_get("canvas_scope")
            .map_err(launch_repository_error)?,
        enabled: row.try_get("enabled").map_err(launch_repository_error)?,
    })
}

fn stored_launch_state(
    row: sqlx::postgres::PgRow,
) -> Result<CanvasLtiStoredLaunchState, CanvasLtiLaunchPlanError> {
    Ok(CanvasLtiStoredLaunchState {
        platform_id: row
            .try_get("platform_id")
            .map_err(launch_repository_error)?,
        state: row.try_get("state").map_err(launch_repository_error)?,
        nonce: row.try_get("nonce").map_err(launch_repository_error)?,
        status: row.try_get("status").map_err(launch_repository_error)?,
        expired: row.try_get("expired").map_err(launch_repository_error)?,
    })
}

fn identity_record(
    row: sqlx::postgres::PgRow,
) -> Result<CanvasLtiIdentityRecord, CanvasLtiLaunchPlanError> {
    let status: String = row.try_get("status").map_err(launch_repository_error)?;
    let status = match status.as_str() {
        "subject_verified" => CanvasLtiIdentityStatus::SubjectVerified,
        "linked" => CanvasLtiIdentityStatus::Linked,
        "quarantined" => CanvasLtiIdentityStatus::Quarantined,
        _ => return Err(CanvasLtiLaunchPlanError::RepositoryUnavailable),
    };
    Ok(CanvasLtiIdentityRecord {
        id: row.try_get("id").map_err(launch_repository_error)?,
        organization_id: row
            .try_get("organization_id")
            .map_err(launch_repository_error)?,
        platform_id: row
            .try_get("platform_id")
            .map_err(launch_repository_error)?,
        deployment_id: row
            .try_get("deployment_id")
            .map_err(launch_repository_error)?,
        lti_subject: row
            .try_get("lti_subject")
            .map_err(launch_repository_error)?,
        canvas_user_id: row
            .try_get("canvas_user_id")
            .map_err(launch_repository_error)?,
        status,
        conflict_reason: row
            .try_get("conflict_reason")
            .map_err(launch_repository_error)?,
    })
}

fn repository_error(cause: sqlx::Error) -> CanvasLtiLoginError {
    error!(%cause, "Canvas LTI login repository query failed");
    CanvasLtiLoginError::RepositoryUnavailable
}

fn launch_repository_error(cause: sqlx::Error) -> CanvasLtiLaunchPlanError {
    error!(%cause, "Canvas LTI launch-state repository query failed");
    CanvasLtiLaunchPlanError::RepositoryUnavailable
}
