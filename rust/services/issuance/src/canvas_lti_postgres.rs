use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use chrono::Duration as ChronoDuration;
use marty_oid4vci::lti::{
    canvas_lti_trust_profile, normalize_canvas_base_url, probe_canvas_lti_platform,
    validate_canvas_lti_service_url, CanvasLtiPlatformProbe,
};
use serde_json::Value;
use sqlx::{PgPool, Row};
use tracing::error;

use crate::canvas_lti_bootstrap::{
    plan_canvas_lti_experience_bootstrap, CanvasLtiBootstrapApplication,
    CanvasLtiBootstrapApplicationAction, CanvasLtiBootstrapApplicationSeed,
    CanvasLtiBootstrapPersistence, CanvasLtiBootstrapPlan, CanvasLtiBootstrapRepository,
    CanvasLtiBootstrapRepositoryError, CanvasLtiBootstrapRequest, CanvasLtiBootstrapTemplate,
};
use crate::canvas_lti_experience::{
    canvas_lti_experience_exchange_metadata, generate_valid_session, lti_subject,
    CanvasLtiExperienceExchangeError, CanvasLtiExperienceExchangePersistence,
    CanvasLtiExperienceExchangeRecord, CanvasLtiExperienceExchangeRepository,
    CanvasLtiExperienceSessionGenerator,
};
use crate::canvas_lti_launch::{
    feature_enabled, merge_verified_lti_binding_capabilities, plan_ags_line_item_pin,
    plan_verified_identity, CanvasLtiAgsPinRepository, CanvasLtiAgsPinRequest,
    CanvasLtiAgsServiceUrlValidator, CanvasLtiCapabilitySnapshotRepository,
    CanvasLtiCapabilitySnapshotRequest, CanvasLtiClock, CanvasLtiExperienceHandoffRepository,
    CanvasLtiExperienceHandoffRequest, CanvasLtiIdentityRecord, CanvasLtiIdentityRepository,
    CanvasLtiIdentityRequest, CanvasLtiIdentityStatus, CanvasLtiJwksRefresher,
    CanvasLtiLaunchContextRepository, CanvasLtiLaunchPlanError, CanvasLtiLaunchStateRepository,
    CanvasLtiProgramBinding, CanvasLtiStoredLaunchState,
};
use crate::canvas_lti_login::{
    CanvasLtiLaunchState, CanvasLtiLoginError, CanvasLtiLoginRepository, CanvasLtiPlatform,
};

const GET_PLATFORM: &str = "SELECT id, organization_id, canvas_account_id, canvas_base_url,
        lti_client_id, lti_deployment_id, lti_trust_profile, lti_issuer, lti_jwks_url,
        lti_jwks_json, lti_openid_configuration, config_version, enabled
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

const GET_LAUNCH_STATE: &str = "SELECT id, platform_id, organization_id, canvas_account_id,
        state, nonce, redirect_uri, status, metadata,
        expires_at <= clock_timestamp() AS expired
    FROM issuance_service.canvas_lti_launch_states
    WHERE state = $1";

const CONSUME_LAUNCH_STATE: &str = "UPDATE issuance_service.canvas_lti_launch_states
    SET status = 'consumed', consumed_at = clock_timestamp()
    WHERE state = $1
      AND status = 'pending'
      AND expires_at > clock_timestamp()
    RETURNING id, platform_id, organization_id, canvas_account_id, state, nonce,
        redirect_uri, status, metadata, false AS expired";

const INSERT_EXPERIENCE_CODE: &str = "INSERT INTO issuance_service.canvas_lti_launch_states (
        id, platform_id, organization_id, canvas_account_id, state, nonce, login_hint,
        target_link_uri, lti_message_hint, redirect_uri, status, metadata,
        created_at, expires_at, consumed_at
    ) VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL, NULL, $7, 'pending', $8,
        clock_timestamp(), $9, NULL)";

const ATTACH_EXPERIENCE_CODE: &str = "UPDATE issuance_service.canvas_lti_launch_states
    SET metadata = $6
    WHERE id = $1 AND state = $2 AND platform_id = $3 AND organization_id = $4
      AND canvas_account_id = $5 AND status = 'consumed'";

const INSERT_EXPERIENCE_SESSION: &str = "INSERT INTO issuance_service.canvas_lti_launch_states (
        id, platform_id, organization_id, canvas_account_id, state, nonce, login_hint,
        target_link_uri, lti_message_hint, redirect_uri, status, metadata,
        created_at, expires_at, consumed_at
    ) VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL, NULL, $7, 'session', $8,
        $9, $10, $9)";

const REDACT_SPENT_EXPERIENCE_CODE: &str = "UPDATE issuance_service.canvas_lti_launch_states
    SET metadata = $3
    WHERE id = $1 AND state = $2 AND status = 'consumed'";

const LIST_PROGRAM_BINDINGS: &str = "SELECT id, organization_id, platform_id,
        application_template_id, credential_template_id, delivery_mode,
        deployment_profile_id, feature_flags, evidence_requirements, canvas_scope, enabled,
        archived_at IS NOT NULL AS archived, config_version
    FROM issuance_service.canvas_program_bindings
    WHERE organization_id = $1 AND platform_id = $2
    ORDER BY created_at";

const GET_BOOTSTRAP_FEATURE_FLAGS: &str = "SELECT feature_flags
    FROM issuance_service.canvas_program_bindings
    WHERE id = $1 AND organization_id = $2";

const GET_BOOTSTRAP_TEMPLATE: &str = "SELECT id, organization_id
    FROM issuance_service.application_templates
    WHERE id = $1";

const LIST_BOOTSTRAP_APPLICATIONS: &str = "SELECT id, organization_id,
        application_template_id, applicant_identifier, form_data, integration_context,
        status, created_at, updated_at
    FROM issuance_service.applications
    WHERE organization_id = $1 AND application_template_id = $2
    ORDER BY created_at DESC";

const GET_BOOTSTRAP_APPLICATION: &str = "SELECT id, organization_id,
        application_template_id, applicant_identifier, form_data, integration_context,
        status, created_at, updated_at
    FROM issuance_service.applications
    WHERE id = $1";

const LOCK_BOOTSTRAP_SCOPE: &str = "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))";

const LIST_LOCKED_BOOTSTRAP_APPLICATIONS: &str = "SELECT id, organization_id,
        application_template_id, applicant_identifier, form_data, integration_context,
        status, created_at, updated_at
    FROM issuance_service.applications
    WHERE organization_id = $1 AND application_template_id = $2
    ORDER BY created_at DESC
    FOR UPDATE";

const INSERT_BOOTSTRAP_APPLICATION: &str = "INSERT INTO issuance_service.applications (
        id, organization_id, application_template_id, applicant_identifier, form_data,
        submitted_evidence, integration_context, status, review_notes, reviewer_id,
        rejection_reason, derived_claims, issuance_transaction_id, credential_id,
        created_at, updated_at, submitted_at, reviewed_at, expires_at
    ) VALUES ($1, $2, $3, $4, $5, '[]'::json, $6, $7, NULL, NULL, NULL,
        '{}'::json, NULL, NULL, $8, $8, $8, NULL, $9)";

const UPDATE_BOOTSTRAP_APPLICATION: &str = "UPDATE issuance_service.applications
    SET integration_context = $3, updated_at = $4
    WHERE id = $1 AND organization_id = $2";

const INSERT_BOOTSTRAP_EVENT: &str = "INSERT INTO issuance_service.issuance_events (
        id, transaction_id, application_id, event_type, metadata, created_at
    ) VALUES ($1, NULL, $2, 'canvas_lti_application_bootstrapped', $3, $4)";

const ATTACH_BOOTSTRAP_SESSION: &str = "UPDATE issuance_service.canvas_lti_launch_states
    SET metadata = $4
    WHERE id = $1 AND state = $2 AND organization_id = $3
      AND status = 'session' AND expires_at > clock_timestamp()";

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

const SAVE_REFRESHED_JWKS: &str = "UPDATE issuance_service.canvas_platforms
    SET canvas_base_url = $4,
        lti_issuer = $5,
        lti_jwks_url = $6,
        lti_jwks_json = $7,
        lti_jwks_fetched_at = clock_timestamp(),
        lti_jwks_expires_at = clock_timestamp() + ($8::double precision * interval '1 second'),
        lti_openid_configuration = $9,
        updated_at = clock_timestamp()
    WHERE id = $1
      AND organization_id = $2
      AND lti_trust_profile = $3
      AND canvas_base_url = $10";

const LOCK_AGS_BINDING: &str = "SELECT evidence_requirements
    FROM issuance_service.canvas_program_bindings
    WHERE id = $1 AND organization_id = $2 AND platform_id = $3 AND archived_at IS NULL
    FOR UPDATE";

const SAVE_AGS_LINE_ITEM: &str = "UPDATE issuance_service.canvas_program_bindings
    SET evidence_requirements = $4,
        config_version = config_version + 1,
        enabled = false,
        validated_config_version = NULL,
        readiness_checks = '[]'::json,
        readiness_validated_at = NULL,
        activated_at = NULL,
        credential_template_snapshot = '{}'::json,
        updated_at = clock_timestamp()
    WHERE id = $1 AND organization_id = $2 AND platform_id = $3 AND archived_at IS NULL";

const LOCK_CAPABILITY_BINDING: &str = "SELECT config_version
    FROM issuance_service.canvas_program_bindings
    WHERE id = $1 AND organization_id = $2 AND platform_id = $3 AND archived_at IS NULL
    FOR UPDATE";

const LOCK_CAPABILITY_PLATFORM: &str = "SELECT capability_snapshot, config_version
    FROM issuance_service.canvas_platforms
    WHERE id = $1 AND organization_id = $2 AND archived_at IS NULL
    FOR UPDATE";

const SAVE_CAPABILITY_SNAPSHOT: &str = "UPDATE issuance_service.canvas_platforms
    SET capability_snapshot = $3,
        registration_status = 'verified',
        last_validated_at = $4,
        last_connection_error = NULL,
        updated_at = clock_timestamp()
    WHERE id = $1 AND organization_id = $2 AND archived_at IS NULL";

#[derive(Clone, Debug)]
pub struct MartyCanvasLtiAgsServiceUrlValidator {
    private_origin_allowlist: Vec<String>,
}

impl MartyCanvasLtiAgsServiceUrlValidator {
    #[must_use]
    pub fn new(private_origin_allowlist: Vec<String>) -> Self {
        Self {
            private_origin_allowlist,
        }
    }
}

#[async_trait]
impl CanvasLtiAgsServiceUrlValidator for MartyCanvasLtiAgsServiceUrlValidator {
    async fn validate(&self, service_url: &str) -> Result<String, String> {
        validate_canvas_lti_service_url(service_url, &self.private_origin_allowlist)
            .await
            .map_err(|error| error.to_string())
    }
}

#[derive(Clone, Debug)]
pub struct CanvasLtiJwksRefreshConfig {
    pub timeout: Duration,
    pub ttl: Duration,
    pub self_managed_origins: Vec<String>,
    pub allow_private_networks: bool,
    pub allow_http_localhost: bool,
}

#[async_trait]
pub trait CanvasLtiProbeClient: Send + Sync {
    async fn probe(
        &self,
        canvas_base_url: &str,
        config: &CanvasLtiJwksRefreshConfig,
    ) -> Result<CanvasLtiPlatformProbe, String>;
}

#[derive(Debug)]
struct MartyCanvasLtiProbeClient;

#[async_trait]
impl CanvasLtiProbeClient for MartyCanvasLtiProbeClient {
    async fn probe(
        &self,
        canvas_base_url: &str,
        config: &CanvasLtiJwksRefreshConfig,
    ) -> Result<CanvasLtiPlatformProbe, String> {
        probe_canvas_lti_platform(
            canvas_base_url,
            config.timeout.as_secs().max(1),
            config.allow_private_networks,
            config.allow_http_localhost,
        )
        .await
        .map_err(|error| error.to_string())
    }
}

#[derive(Clone)]
pub struct PostgresCanvasLtiJwksRefresher {
    pool: PgPool,
    config: CanvasLtiJwksRefreshConfig,
    probe_client: Arc<dyn CanvasLtiProbeClient>,
}

impl std::fmt::Debug for PostgresCanvasLtiJwksRefresher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresCanvasLtiJwksRefresher")
            .field("timeout", &self.config.timeout)
            .field("ttl", &self.config.ttl)
            .field(
                "self_managed_origin_count",
                &self.config.self_managed_origins.len(),
            )
            .finish_non_exhaustive()
    }
}

impl PostgresCanvasLtiJwksRefresher {
    #[must_use]
    pub fn new(pool: PgPool, config: CanvasLtiJwksRefreshConfig) -> Self {
        Self {
            pool,
            config,
            probe_client: Arc::new(MartyCanvasLtiProbeClient),
        }
    }

    #[must_use]
    pub fn with_probe_client(
        pool: PgPool,
        config: CanvasLtiJwksRefreshConfig,
        probe_client: Arc<dyn CanvasLtiProbeClient>,
    ) -> Self {
        Self {
            pool,
            config,
            probe_client,
        }
    }
}

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
                config_version: row
                    .try_get::<i32, _>("config_version")
                    .map(i64::from)
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
impl CanvasLtiExperienceHandoffRepository for PostgresCanvasLtiLoginRepository {
    async fn persist_experience_handoff(
        &self,
        request: &CanvasLtiExperienceHandoffRequest,
    ) -> Result<(), CanvasLtiLaunchPlanError> {
        if request.organization_id.trim().is_empty()
            || request.platform_id.trim().is_empty()
            || request.canvas_account_id.trim().is_empty()
            || request.code.id.trim().is_empty()
            || request.code.state.trim().is_empty()
            || request.code.nonce.trim().is_empty()
            || request.redirect_uri.trim().is_empty()
            || request.consumed_state.id.trim().is_empty()
            || request.consumed_state.status != "consumed"
            || request.consumed_state.platform_id != request.platform_id
            || request.consumed_state.organization_id != request.organization_id
            || request.consumed_state.canvas_account_id != request.canvas_account_id
            || request.consumed_state.redirect_uri != request.redirect_uri
            || request.code_metadata.get("kind").and_then(Value::as_str)
                != Some("canvas_lti_experience_code")
            || request
                .code_metadata
                .get("launch_state")
                .and_then(Value::as_str)
                != Some(request.consumed_state.state.as_str())
            || !request.consumed_state_metadata.is_object()
        {
            return Err(CanvasLtiLaunchPlanError::RepositoryUnavailable);
        }
        let mut transaction = self.pool.begin().await.map_err(launch_repository_error)?;
        sqlx::query(INSERT_EXPERIENCE_CODE)
            .bind(&request.code.id)
            .bind(&request.platform_id)
            .bind(&request.organization_id)
            .bind(&request.canvas_account_id)
            .bind(&request.code.state)
            .bind(&request.code.nonce)
            .bind(&request.redirect_uri)
            .bind(&request.code_metadata)
            .bind(request.expires_at)
            .execute(&mut *transaction)
            .await
            .map_err(launch_repository_error)?;
        let updated = sqlx::query(ATTACH_EXPERIENCE_CODE)
            .bind(&request.consumed_state.id)
            .bind(&request.consumed_state.state)
            .bind(&request.platform_id)
            .bind(&request.organization_id)
            .bind(&request.canvas_account_id)
            .bind(&request.consumed_state_metadata)
            .execute(&mut *transaction)
            .await
            .map_err(launch_repository_error)?;
        if updated.rows_affected() != 1 {
            return Err(CanvasLtiLaunchPlanError::RepositoryUnavailable);
        }
        transaction.commit().await.map_err(launch_repository_error)
    }
}

#[async_trait]
impl CanvasLtiExperienceExchangeRepository for PostgresCanvasLtiLoginRepository {
    async fn exchange_experience_code(
        &self,
        request: &CanvasLtiExperienceExchangePersistence,
        generator: &dyn CanvasLtiExperienceSessionGenerator,
        clock: &dyn CanvasLtiClock,
    ) -> Result<CanvasLtiExperienceExchangeRecord, CanvasLtiExperienceExchangeError> {
        let ttl = chrono::Duration::from_std(request.session_ttl)
            .map_err(|_| CanvasLtiExperienceExchangeError::InvalidConfiguration)?;
        if request.code.trim().is_empty() || request.session_ttl.is_zero() {
            return Err(CanvasLtiExperienceExchangeError::InvalidConfiguration);
        }
        let mut transaction = self.pool.begin().await.map_err(exchange_repository_error)?;
        let consumed = sqlx::query(CONSUME_LAUNCH_STATE)
            .bind(&request.code)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(exchange_repository_error)?;
        let Some(consumed) = consumed else {
            return Err(CanvasLtiExperienceExchangeError::InvalidCode);
        };
        let consumed = stored_launch_state(consumed).map_err(exchange_plan_error)?;
        if consumed.metadata.get("kind").and_then(Value::as_str)
            != Some("canvas_lti_experience_code")
        {
            // Preserve the frozen Python boundary: an unrecognized pending
            // state is consumed before its experience-code kind fails.
            transaction
                .commit()
                .await
                .map_err(exchange_repository_error)?;
            return Err(CanvasLtiExperienceExchangeError::InvalidCode);
        }
        let session = generate_valid_session(generator)?;
        let created_at = clock.now();
        let expires_at = created_at
            .checked_add_signed(ttl)
            .ok_or(CanvasLtiExperienceExchangeError::InvalidConfiguration)?;
        let (session_metadata, spent_code_metadata) = canvas_lti_experience_exchange_metadata(
            &consumed.metadata,
            &consumed.id,
            &session.id,
            created_at,
        );
        sqlx::query(INSERT_EXPERIENCE_SESSION)
            .bind(&session.id)
            .bind(&consumed.platform_id)
            .bind(&consumed.organization_id)
            .bind(&consumed.canvas_account_id)
            .bind(&session.state_digest)
            .bind(&session.nonce)
            .bind(&consumed.redirect_uri)
            .bind(&session_metadata)
            .bind(created_at)
            .bind(expires_at)
            .execute(&mut *transaction)
            .await
            .map_err(exchange_repository_error)?;
        let redacted = sqlx::query(REDACT_SPENT_EXPERIENCE_CODE)
            .bind(&consumed.id)
            .bind(&consumed.state)
            .bind(&spent_code_metadata)
            .execute(&mut *transaction)
            .await
            .map_err(exchange_repository_error)?;
        if redacted.rows_affected() != 1 {
            return Err(CanvasLtiExperienceExchangeError::RepositoryUnavailable);
        }
        transaction
            .commit()
            .await
            .map_err(exchange_repository_error)?;
        Ok(CanvasLtiExperienceExchangeRecord {
            experience_code_id: consumed.id,
            session,
            created_at,
            expires_at,
            session_metadata,
            spent_code_metadata,
        })
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
impl CanvasLtiAgsPinRepository for PostgresCanvasLtiLoginRepository {
    async fn pin_verified_line_item(
        &self,
        binding: &CanvasLtiProgramBinding,
        request: &CanvasLtiAgsPinRequest,
    ) -> Result<bool, CanvasLtiLaunchPlanError> {
        if request.binding_id != binding.id {
            return Err(CanvasLtiLaunchPlanError::AgsBindingMismatch);
        }
        let mut transaction = self.pool.begin().await.map_err(launch_repository_error)?;
        let row = sqlx::query(LOCK_AGS_BINDING)
            .bind(&binding.id)
            .bind(&binding.organization_id)
            .bind(&binding.platform_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(launch_repository_error)?
            .ok_or(CanvasLtiLaunchPlanError::AgsBindingMismatch)?;
        let evidence_requirements = row
            .try_get::<Value, _>("evidence_requirements")
            .map_err(launch_repository_error)?
            .as_array()
            .cloned()
            .ok_or(CanvasLtiLaunchPlanError::RepositoryUnavailable)?;
        let Some(updated) = plan_ags_line_item_pin(&evidence_requirements, request)? else {
            transaction
                .commit()
                .await
                .map_err(launch_repository_error)?;
            return Ok(false);
        };
        let result = sqlx::query(SAVE_AGS_LINE_ITEM)
            .bind(&binding.id)
            .bind(&binding.organization_id)
            .bind(&binding.platform_id)
            .bind(Value::Array(updated))
            .execute(&mut *transaction)
            .await
            .map_err(launch_repository_error)?;
        if result.rows_affected() != 1 {
            return Err(CanvasLtiLaunchPlanError::AgsBindingMismatch);
        }
        transaction
            .commit()
            .await
            .map_err(launch_repository_error)?;
        Ok(true)
    }
}

#[async_trait]
impl CanvasLtiCapabilitySnapshotRepository for PostgresCanvasLtiLoginRepository {
    async fn persist_verified_capabilities(
        &self,
        request: &CanvasLtiCapabilitySnapshotRequest,
    ) -> Result<Value, CanvasLtiLaunchPlanError> {
        let mut transaction = self.pool.begin().await.map_err(launch_repository_error)?;
        let binding = sqlx::query(LOCK_CAPABILITY_BINDING)
            .bind(&request.binding_id)
            .bind(&request.organization_id)
            .bind(&request.platform_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(launch_repository_error)?
            .ok_or(CanvasLtiLaunchPlanError::CapabilityScopeMismatch)?;
        let current_config_version = binding
            .try_get::<i32, _>("config_version")
            .map(i64::from)
            .map_err(launch_repository_error)?;
        let expected_config_version = request
            .selected_binding_config_version
            .checked_add(i64::from(request.line_item_configuration_changed))
            .ok_or(CanvasLtiLaunchPlanError::CapabilityConfigurationDrift)?;
        if current_config_version != expected_config_version {
            return Err(CanvasLtiLaunchPlanError::CapabilityConfigurationDrift);
        }
        let platform = sqlx::query(LOCK_CAPABILITY_PLATFORM)
            .bind(&request.platform_id)
            .bind(&request.organization_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(launch_repository_error)?
            .ok_or(CanvasLtiLaunchPlanError::CapabilityScopeMismatch)?;
        let capability_snapshot = platform
            .try_get::<Value, _>("capability_snapshot")
            .map_err(launch_repository_error)?;
        let current_platform_config_version = platform
            .try_get::<i32, _>("config_version")
            .map(i64::from)
            .map_err(launch_repository_error)?;
        if current_platform_config_version != request.selected_platform_config_version {
            return Err(CanvasLtiLaunchPlanError::CapabilityConfigurationDrift);
        }
        let updated = merge_verified_lti_binding_capabilities(
            &capability_snapshot,
            &request.launch_capabilities,
            &request.binding_id,
            current_config_version,
            &request.signed_course_id,
            request.line_item_configuration_changed,
            &request.verified_at.to_rfc3339(),
        );
        let result = sqlx::query(SAVE_CAPABILITY_SNAPSHOT)
            .bind(&request.platform_id)
            .bind(&request.organization_id)
            .bind(&updated)
            .bind(request.verified_at)
            .execute(&mut *transaction)
            .await
            .map_err(launch_repository_error)?;
        if result.rows_affected() != 1 {
            return Err(CanvasLtiLaunchPlanError::CapabilityScopeMismatch);
        }
        transaction
            .commit()
            .await
            .map_err(launch_repository_error)?;
        Ok(updated)
    }
}

#[async_trait]
impl CanvasLtiBootstrapRepository for PostgresCanvasLtiLoginRepository {
    async fn bound_feature_enabled(
        &self,
        organization_id: &str,
        binding_id: &str,
        flag: &str,
    ) -> Result<Option<bool>, CanvasLtiBootstrapRepositoryError> {
        let row = sqlx::query(GET_BOOTSTRAP_FEATURE_FLAGS)
            .bind(binding_id)
            .bind(organization_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(bootstrap_repository_error)?;
        let Some(row) = row else { return Ok(None) };
        let flags: Value = row
            .try_get("feature_flags")
            .map_err(bootstrap_repository_error)?;
        Ok(Some(feature_enabled(&flags, flag)))
    }

    async fn get_template(
        &self,
        template_id: &str,
    ) -> Result<Option<CanvasLtiBootstrapTemplate>, CanvasLtiBootstrapRepositoryError> {
        sqlx::query(GET_BOOTSTRAP_TEMPLATE)
            .bind(template_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(bootstrap_repository_error)?
            .map(bootstrap_template)
            .transpose()
    }

    async fn list_applications(
        &self,
        organization_id: &str,
        template_id: &str,
    ) -> Result<Vec<CanvasLtiBootstrapApplication>, CanvasLtiBootstrapRepositoryError> {
        sqlx::query(LIST_BOOTSTRAP_APPLICATIONS)
            .bind(organization_id)
            .bind(template_id)
            .fetch_all(&self.pool)
            .await
            .map_err(bootstrap_repository_error)?
            .into_iter()
            .map(bootstrap_application)
            .collect()
    }

    async fn persist_plan(
        &self,
        context: &crate::canvas_lti_experience::CanvasLtiExperienceSessionContext,
        plan: &CanvasLtiBootstrapPlan,
    ) -> Result<CanvasLtiBootstrapPersistence, CanvasLtiBootstrapRepositoryError> {
        let template_id = context
            .application_template_id
            .as_deref()
            .ok_or(CanvasLtiBootstrapRepositoryError::Unavailable)?;
        let join_identity = lti_subject(&context.verified_launch).map_or_else(
            || format!("state:{}", context.state),
            |subject| {
                format!(
                    "subject:{}:{subject}",
                    context
                        .canvas_program_binding_id
                        .as_deref()
                        .unwrap_or_default()
                )
            },
        );
        let lock_scope = format!(
            "canvas-bootstrap:{}:{template_id}:{join_identity}",
            context.launch_state.organization_id
        );
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(bootstrap_repository_error)?;
        sqlx::query(LOCK_BOOTSTRAP_SCOPE)
            .bind(lock_scope)
            .execute(&mut *transaction)
            .await
            .map_err(bootstrap_repository_error)?;
        let locked_applications = sqlx::query(LIST_LOCKED_BOOTSTRAP_APPLICATIONS)
            .bind(&context.launch_state.organization_id)
            .bind(template_id)
            .fetch_all(&mut *transaction)
            .await
            .map_err(bootstrap_repository_error)?
            .into_iter()
            .map(bootstrap_application)
            .collect::<Result<Vec<_>, _>>()?;
        let template = CanvasLtiBootstrapTemplate {
            id: template_id.to_owned(),
            organization_id: context.launch_state.organization_id.clone(),
        };
        let replay = plan_canvas_lti_experience_bootstrap(
            context,
            &CanvasLtiBootstrapRequest::default(),
            true,
            Some(true),
            Some(&template),
            &locked_applications,
            |_| CanvasLtiBootstrapApplicationSeed {
                id: plan.application.id.clone(),
                anonymous_identifier_suffix: String::new(),
            },
            plan.planned_at,
        )
        .map_err(|_| CanvasLtiBootstrapRepositoryError::Unavailable)?;
        let actual = if replay.created {
            if !plan.created {
                return Err(CanvasLtiBootstrapRepositoryError::Unavailable);
            }
            plan.clone()
        } else {
            replay
        };

        match (actual.application_action, actual.created) {
            (CanvasLtiBootstrapApplicationAction::Create, true) => {
                let expires_at = actual.planned_at + ChronoDuration::days(30);
                sqlx::query(INSERT_BOOTSTRAP_APPLICATION)
                    .bind(&actual.application.id)
                    .bind(&actual.application.organization_id)
                    .bind(&actual.application.application_template_id)
                    .bind(&actual.application.applicant_identifier)
                    .bind(&actual.application.form_data)
                    .bind(&actual.application.integration_context)
                    .bind(&actual.application.status)
                    .bind(actual.planned_at)
                    .bind(expires_at)
                    .execute(&mut *transaction)
                    .await
                    .map_err(bootstrap_repository_error)?;
                let event_metadata = actual
                    .bootstrap_event_metadata
                    .as_ref()
                    .ok_or(CanvasLtiBootstrapRepositoryError::Unavailable)?;
                sqlx::query(INSERT_BOOTSTRAP_EVENT)
                    .bind(uuid::Uuid::new_v4().to_string())
                    .bind(&actual.application.id)
                    .bind(event_metadata)
                    .bind(actual.planned_at)
                    .execute(&mut *transaction)
                    .await
                    .map_err(bootstrap_repository_error)?;
            }
            (CanvasLtiBootstrapApplicationAction::Resume, false) => {
                let updated = sqlx::query(UPDATE_BOOTSTRAP_APPLICATION)
                    .bind(&actual.application.id)
                    .bind(&actual.application.organization_id)
                    .bind(&actual.application.integration_context)
                    .bind(actual.application.updated_at)
                    .execute(&mut *transaction)
                    .await
                    .map_err(bootstrap_repository_error)?;
                if updated.rows_affected() != 1 {
                    return Err(CanvasLtiBootstrapRepositoryError::Unavailable);
                }
            }
            (CanvasLtiBootstrapApplicationAction::Replay, false) => {}
            _ => return Err(CanvasLtiBootstrapRepositoryError::Unavailable),
        }
        let attached = sqlx::query(ATTACH_BOOTSTRAP_SESSION)
            .bind(&context.launch_state.id)
            .bind(&context.launch_state.state)
            .bind(&context.launch_state.organization_id)
            .bind(&actual.session_metadata)
            .execute(&mut *transaction)
            .await
            .map_err(bootstrap_repository_error)?;
        if attached.rows_affected() != 1 {
            return Err(CanvasLtiBootstrapRepositoryError::Unavailable);
        }
        transaction
            .commit()
            .await
            .map_err(bootstrap_repository_error)?;
        Ok(CanvasLtiBootstrapPersistence {
            application: actual.application,
            created: actual.created,
        })
    }

    async fn get_application(
        &self,
        application_id: &str,
    ) -> Result<Option<CanvasLtiBootstrapApplication>, CanvasLtiBootstrapRepositoryError> {
        sqlx::query(GET_BOOTSTRAP_APPLICATION)
            .bind(application_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(bootstrap_repository_error)?
            .map(bootstrap_application)
            .transpose()
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

#[async_trait]
impl CanvasLtiJwksRefresher for PostgresCanvasLtiJwksRefresher {
    async fn refresh_platform_jwks(
        &self,
        platform: &CanvasLtiPlatform,
    ) -> Result<CanvasLtiPlatform, CanvasLtiLaunchPlanError> {
        let canvas_base_url = platform
            .canvas_base_url
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or(CanvasLtiLaunchPlanError::Invalid(
                "Canvas platform requires canvas_base_url before refreshing JWKS",
            ))?;
        let normalized_origin = normalize_canvas_base_url(
            canvas_base_url,
            self.config.allow_private_networks,
            self.config.allow_http_localhost,
        )
        .map_err(|error| CanvasLtiLaunchPlanError::JwksRefresh(error.to_string()))?;
        let expected = canvas_lti_trust_profile(
            &normalized_origin,
            &platform.lti_trust_profile,
            &self.config.self_managed_origins,
        )
        .map_err(|error| CanvasLtiLaunchPlanError::JwksRefresh(error.to_string()))?;
        let probe = self
            .probe_client
            .probe(&normalized_origin, &self.config)
            .await
            .map_err(CanvasLtiLaunchPlanError::JwksRefresh)?;
        if probe.canvas_base_url != normalized_origin
            || probe.issuer != expected.issuer
            || probe.authorization_endpoint.as_deref()
                != Some(expected.authorization_endpoint.as_str())
            || probe.token_endpoint.as_deref() != Some(expected.token_endpoint.as_str())
            || probe.jwks_uri != expected.jwks_uri
        {
            return Err(CanvasLtiLaunchPlanError::JwksRefresh(
                "Canvas metadata probe returned endpoints outside the persisted trust profile"
                    .to_owned(),
            ));
        }
        let ttl_seconds = self.config.ttl.as_secs();
        if ttl_seconds == 0 || ttl_seconds > i64::MAX as u64 {
            return Err(CanvasLtiLaunchPlanError::JwksRefresh(
                "Canvas JWKS cache TTL is invalid".to_owned(),
            ));
        }
        let result = sqlx::query(SAVE_REFRESHED_JWKS)
            .bind(&platform.id)
            .bind(&platform.organization_id)
            .bind(&platform.lti_trust_profile)
            .bind(&normalized_origin)
            .bind(&probe.issuer)
            .bind(&probe.jwks_uri)
            .bind(&probe.jwks_json)
            .bind(ttl_seconds as i64)
            .bind(&probe.raw_openid_configuration)
            .bind(canvas_base_url)
            .execute(&self.pool)
            .await
            .map_err(launch_repository_error)?;
        if result.rows_affected() != 1 {
            return Err(CanvasLtiLaunchPlanError::JwksRefresh(
                "Canvas platform trust configuration changed during JWKS refresh".to_owned(),
            ));
        }

        let mut refreshed = platform.clone();
        refreshed.canvas_base_url = Some(normalized_origin);
        refreshed.lti_issuer = Some(probe.issuer);
        refreshed.lti_jwks_url = Some(probe.jwks_uri);
        refreshed.lti_jwks_json = Some(probe.jwks_json);
        refreshed.lti_openid_configuration = Some(probe.raw_openid_configuration);
        Ok(refreshed)
    }
}

fn bootstrap_template(
    row: sqlx::postgres::PgRow,
) -> Result<CanvasLtiBootstrapTemplate, CanvasLtiBootstrapRepositoryError> {
    Ok(CanvasLtiBootstrapTemplate {
        id: row.try_get("id").map_err(bootstrap_repository_error)?,
        organization_id: row
            .try_get("organization_id")
            .map_err(bootstrap_repository_error)?,
    })
}

fn bootstrap_application(
    row: sqlx::postgres::PgRow,
) -> Result<CanvasLtiBootstrapApplication, CanvasLtiBootstrapRepositoryError> {
    Ok(CanvasLtiBootstrapApplication {
        id: row.try_get("id").map_err(bootstrap_repository_error)?,
        organization_id: row
            .try_get("organization_id")
            .map_err(bootstrap_repository_error)?,
        application_template_id: row
            .try_get("application_template_id")
            .map_err(bootstrap_repository_error)?,
        applicant_identifier: row
            .try_get("applicant_identifier")
            .map_err(bootstrap_repository_error)?,
        form_data: row
            .try_get("form_data")
            .map_err(bootstrap_repository_error)?,
        integration_context: row
            .try_get("integration_context")
            .map_err(bootstrap_repository_error)?,
        status: row.try_get("status").map_err(bootstrap_repository_error)?,
        created_at: row
            .try_get("created_at")
            .map_err(bootstrap_repository_error)?,
        updated_at: row
            .try_get("updated_at")
            .map_err(bootstrap_repository_error)?,
    })
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
        archived: row.try_get("archived").map_err(launch_repository_error)?,
        config_version: row
            .try_get::<i32, _>("config_version")
            .map(i64::from)
            .map_err(launch_repository_error)?,
    })
}

fn stored_launch_state(
    row: sqlx::postgres::PgRow,
) -> Result<CanvasLtiStoredLaunchState, CanvasLtiLaunchPlanError> {
    Ok(CanvasLtiStoredLaunchState {
        id: row.try_get("id").map_err(launch_repository_error)?,
        platform_id: row
            .try_get("platform_id")
            .map_err(launch_repository_error)?,
        organization_id: row
            .try_get("organization_id")
            .map_err(launch_repository_error)?,
        canvas_account_id: row
            .try_get("canvas_account_id")
            .map_err(launch_repository_error)?,
        state: row.try_get("state").map_err(launch_repository_error)?,
        nonce: row.try_get("nonce").map_err(launch_repository_error)?,
        redirect_uri: row
            .try_get("redirect_uri")
            .map_err(launch_repository_error)?,
        status: row.try_get("status").map_err(launch_repository_error)?,
        metadata: row.try_get("metadata").map_err(launch_repository_error)?,
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

fn exchange_repository_error(cause: sqlx::Error) -> CanvasLtiExperienceExchangeError {
    error!(%cause, "Canvas LTI experience exchange repository query failed");
    CanvasLtiExperienceExchangeError::RepositoryUnavailable
}

fn exchange_plan_error(cause: CanvasLtiLaunchPlanError) -> CanvasLtiExperienceExchangeError {
    error!(%cause, "Canvas LTI experience exchange record was invalid");
    CanvasLtiExperienceExchangeError::RepositoryUnavailable
}

fn bootstrap_repository_error(cause: sqlx::Error) -> CanvasLtiBootstrapRepositoryError {
    error!(%cause, "Canvas LTI bootstrap repository query failed");
    CanvasLtiBootstrapRepositoryError::Unavailable
}
