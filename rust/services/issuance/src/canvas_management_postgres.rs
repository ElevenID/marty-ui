//! PostgreSQL persistence for the Canvas management aggregate.

use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use sqlx::{postgres::PgRow, PgPool, Postgres, Row, Transaction};
use tracing::error;

use crate::{
    canvas_binding_domain::{CanvasApplicationTemplateProjection, CanvasProgramBindingRecord},
    canvas_management_domain::CanvasPlatformRecord,
    canvas_management_service::{
        CanvasBindingActivation, CanvasManagementRepositoryError,
        CanvasPlatformManagementRepository,
    },
    canvas_oauth_postgres::{
        queue_canvas_oauth_revocation_in_transaction, CanvasOAuthRevocationQueueOutcome,
    },
};

#[cfg(test)]
const BINDING_COLUMNS: &str = "id, organization_id, platform_id,
    application_template_id, credential_template_id, display_name, flow_mode,
    direct_issue_enabled, auto_approve_on_evidence, evidence_requirements,
    canvas_scope, delivery_mode, issuer_mode, approval_policy_set_id,
    deployment_profile_id, feature_flags, canvas_credentials, config_version,
    validated_config_version, readiness_checks, readiness_validated_at,
    activated_at, archived_at, credential_template_snapshot, enabled,
    created_at, updated_at";

const GET_APPLICATION_TEMPLATE: &str = "SELECT id, organization_id,
    credential_template_id, approval_policy_set_id, status
 FROM issuance_service.application_templates
 WHERE id = $1";

const VALID_CANVAS_CREDENTIALS_SECRET: &str = "SELECT EXISTS (
    SELECT 1 FROM issuance_service.organization_integration_secrets
     WHERE organization_id = $1 AND id = $2 AND enabled = true
       AND provider = 'canvas_credentials' AND purpose = 'api_token'
)";

const GET_ACTIVE_BINDING: &str = "SELECT id, organization_id, platform_id,
    application_template_id, credential_template_id, display_name, flow_mode,
    direct_issue_enabled, auto_approve_on_evidence, evidence_requirements,
    canvas_scope, delivery_mode, issuer_mode, approval_policy_set_id,
    deployment_profile_id, feature_flags, canvas_credentials, config_version,
    validated_config_version, readiness_checks, readiness_validated_at,
    activated_at, archived_at, credential_template_snapshot, enabled,
    created_at, updated_at
 FROM issuance_service.canvas_program_bindings
 WHERE organization_id = $1 AND id = $2 AND archived_at IS NULL";

const LIST_ACTIVE_BINDINGS: &str = "SELECT id, organization_id, platform_id,
    application_template_id, credential_template_id, display_name, flow_mode,
    direct_issue_enabled, auto_approve_on_evidence, evidence_requirements,
    canvas_scope, delivery_mode, issuer_mode, approval_policy_set_id,
    deployment_profile_id, feature_flags, canvas_credentials, config_version,
    validated_config_version, readiness_checks, readiness_validated_at,
    activated_at, archived_at, credential_template_snapshot, enabled,
    created_at, updated_at
 FROM issuance_service.canvas_program_bindings
 WHERE organization_id = $1 AND archived_at IS NULL
   AND ($2::text IS NULL OR platform_id = $2)
   AND ($3::text IS NULL OR application_template_id = $3)
 ORDER BY created_at";

const LOCK_ACTIVE_BINDING_PLATFORM: &str = "SELECT 1
 FROM issuance_service.canvas_platforms
 WHERE organization_id = $1 AND id = $2 AND archived_at IS NULL
 FOR UPDATE";

const FIND_DUPLICATE_BINDING: &str = "SELECT id
 FROM issuance_service.canvas_program_bindings
 WHERE organization_id = $1 AND platform_id = $2
   AND application_template_id = $3
   AND canvas_scope::jsonb = $4::jsonb AND archived_at IS NULL
   AND ($5::text IS NULL OR id <> $5)
 LIMIT 1";

const INSERT_BINDING: &str = "INSERT INTO issuance_service.canvas_program_bindings (
    id, organization_id, platform_id, application_template_id,
    credential_template_id, display_name, flow_mode, direct_issue_enabled,
    auto_approve_on_evidence, evidence_requirements, canvas_scope,
    delivery_mode, issuer_mode, approval_policy_set_id, deployment_profile_id,
    feature_flags, canvas_credentials, config_version, validated_config_version,
    readiness_checks, readiness_validated_at, activated_at, archived_at,
    credential_template_snapshot, enabled, created_at, updated_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
    $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27
)";

const UPDATE_BINDING_CONFIGURATION: &str = "UPDATE issuance_service.canvas_program_bindings
 SET application_template_id = $4, credential_template_id = $5,
     display_name = $6, flow_mode = $7, direct_issue_enabled = $8,
     auto_approve_on_evidence = $9, evidence_requirements = $10,
     canvas_scope = $11, delivery_mode = $12, issuer_mode = $13,
     approval_policy_set_id = $14, deployment_profile_id = $15,
     feature_flags = $16, canvas_credentials = $17, config_version = $18,
     validated_config_version = $19, readiness_checks = $20,
     readiness_validated_at = $21, activated_at = $22, archived_at = $23,
     credential_template_snapshot = $24, enabled = $25, updated_at = $26
 WHERE organization_id = $1 AND id = $2 AND config_version = $3
   AND archived_at IS NULL
 RETURNING id, organization_id, platform_id, application_template_id,
     credential_template_id, display_name, flow_mode, direct_issue_enabled,
     auto_approve_on_evidence, evidence_requirements, canvas_scope,
     delivery_mode, issuer_mode, approval_policy_set_id, deployment_profile_id,
     feature_flags, canvas_credentials, config_version, validated_config_version,
     readiness_checks, readiness_validated_at, activated_at, archived_at,
     credential_template_snapshot, enabled, created_at, updated_at";

const UPDATE_BINDING_READINESS: &str = "UPDATE issuance_service.canvas_program_bindings
 SET validated_config_version = $5, readiness_checks = $6,
     readiness_validated_at = $7, credential_template_snapshot = $8
 WHERE organization_id = $1 AND id = $2 AND config_version = $3
   AND updated_at = $4 AND archived_at IS NULL
 RETURNING id, organization_id, platform_id, application_template_id,
     credential_template_id, display_name, flow_mode, direct_issue_enabled,
     auto_approve_on_evidence, evidence_requirements, canvas_scope,
     delivery_mode, issuer_mode, approval_policy_set_id, deployment_profile_id,
     feature_flags, canvas_credentials, config_version, validated_config_version,
     readiness_checks, readiness_validated_at, activated_at, archived_at,
     credential_template_snapshot, enabled, created_at, updated_at";

const ARCHIVE_BINDING: &str = "UPDATE issuance_service.canvas_program_bindings
 SET enabled = false, archived_at = $4, updated_at = $4
 WHERE organization_id = $1 AND id = $2 AND config_version = $3
   AND archived_at IS NULL
 RETURNING id, organization_id, platform_id, application_template_id,
     credential_template_id, display_name, flow_mode, direct_issue_enabled,
     auto_approve_on_evidence, evidence_requirements, canvas_scope,
     delivery_mode, issuer_mode, approval_policy_set_id, deployment_profile_id,
     feature_flags, canvas_credentials, config_version, validated_config_version,
     readiness_checks, readiness_validated_at, activated_at, archived_at,
     credential_template_snapshot, enabled, created_at, updated_at";

const ENABLE_PLATFORM_FOR_BINDING: &str = "UPDATE issuance_service.canvas_platforms
 SET enabled = true, updated_at = $5
 WHERE organization_id = $1 AND id = $2 AND config_version = $3
   AND updated_at = $4 AND archived_at IS NULL
 RETURNING id";

const ACTIVATE_BINDING: &str = "UPDATE issuance_service.canvas_program_bindings
 SET enabled = true, activated_at = $5, updated_at = $5
 WHERE organization_id = $1 AND id = $2 AND config_version = $3
   AND updated_at = $4 AND validated_config_version = $3
   AND readiness_validated_at IS NOT NULL AND archived_at IS NULL
 RETURNING id, organization_id, platform_id, application_template_id,
     credential_template_id, display_name, flow_mode, direct_issue_enabled,
     auto_approve_on_evidence, evidence_requirements, canvas_scope,
     delivery_mode, issuer_mode, approval_policy_set_id, deployment_profile_id,
     feature_flags, canvas_credentials, config_version, validated_config_version,
     readiness_checks, readiness_validated_at, activated_at, archived_at,
     credential_template_snapshot, enabled, created_at, updated_at";

const DEACTIVATE_BINDING: &str = "UPDATE issuance_service.canvas_program_bindings
 SET enabled = false, activated_at = NULL, updated_at = $5
 WHERE organization_id = $1 AND id = $2 AND config_version = $3
   AND updated_at = $4 AND archived_at IS NULL
 RETURNING id, organization_id, platform_id, application_template_id,
     credential_template_id, display_name, flow_mode, direct_issue_enabled,
     auto_approve_on_evidence, evidence_requirements, canvas_scope,
     delivery_mode, issuer_mode, approval_policy_set_id, deployment_profile_id,
     feature_flags, canvas_credentials, config_version, validated_config_version,
     readiness_checks, readiness_validated_at, activated_at, archived_at,
     credential_template_snapshot, enabled, created_at, updated_at";

const UPSERT_SYNC_TARGET: &str = "INSERT INTO issuance_service.canvas_evidence_sync_targets (
    id, organization_id, platform_id, binding_id, target_type, logical_key,
    application_id, candidate_id, enabled, schedule_seconds, next_run_at,
    last_enqueued_at, last_succeeded_at, config_version, metadata,
    created_at, updated_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, NULL, true, $8, $9,
    NULL, NULL, $10, $11, $9, $9
)
ON CONFLICT (organization_id, logical_key) DO UPDATE SET
    platform_id = EXCLUDED.platform_id,
    binding_id = EXCLUDED.binding_id,
    target_type = EXCLUDED.target_type,
    application_id = EXCLUDED.application_id,
    enabled = true,
    schedule_seconds = EXCLUDED.schedule_seconds,
    config_version = EXCLUDED.config_version,
    metadata = COALESCE(issuance_service.canvas_evidence_sync_targets.metadata::jsonb, '{}'::jsonb)
        || $12::jsonb,
    updated_at = EXCLUDED.updated_at
RETURNING id";

const ENQUEUE_SYNC_JOB: &str = "INSERT INTO issuance_service.canvas_evidence_sync_jobs (
    id, organization_id, target_id, status, attempt_count, max_attempts,
    available_at, result, created_at, updated_at
) VALUES ($1, $2, $3, 'queued', 0, 8, $4, '{}'::jsonb, $4, $4)
ON CONFLICT DO NOTHING";

const MARK_TARGET_ENQUEUED: &str = "UPDATE issuance_service.canvas_evidence_sync_targets
 SET last_enqueued_at = $3, updated_at = $3
 WHERE organization_id = $1 AND id = $2";

const ACTIVATION_APPLICATIONS: &str = "SELECT id, credential_id
 FROM issuance_service.applications
 WHERE organization_id = $1 AND application_template_id = $2
   AND status NOT IN ('rejected', 'withdrawn')
   AND integration_context->'canvas'->>'canvas_program_binding_id' = $3";

const DISABLE_ROSTER_TARGET: &str = "UPDATE issuance_service.canvas_evidence_sync_targets
 SET enabled = false, updated_at = $3
 WHERE organization_id = $1 AND logical_key = $2";

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
             WHEN COALESCE(connection_config::jsonb, '{}'::jsonb) ? 'lti_capability_intent'
                 THEN COALESCE(connection_config::jsonb, '{}'::jsonb)
             ELSE COALESCE(connection_config::jsonb, '{}'::jsonb)
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
             WHEN COALESCE(connection_config::jsonb, '{}'::jsonb) ? 'lti_capability_intent'
                 THEN COALESCE(connection_config::jsonb, '{}'::jsonb)
             ELSE COALESCE(connection_config::jsonb, '{}'::jsonb)
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

const PERSIST_LTI_PROBE_METADATA: &str = "UPDATE issuance_service.canvas_platforms
 SET canvas_base_url = $5,
     lti_issuer = $6,
     lti_jwks_url = $7,
     lti_jwks_json = $8,
     lti_jwks_fetched_at = $9,
     lti_jwks_expires_at = $10,
     lti_openid_configuration = $11,
     last_connection_error = $12,
     updated_at = $13
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

    pub async fn save_lti_probe_metadata(
        &self,
        platform: &CanvasPlatformRecord,
        expected_config_version: i64,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        sqlx::query(PERSIST_LTI_PROBE_METADATA)
            .bind(&platform.organization_id)
            .bind(&platform.id)
            .bind(version_i32(expected_config_version)?)
            .bind(expected_updated_at)
            .bind(&platform.canvas_base_url)
            .bind(&platform.lti_issuer)
            .bind(&platform.lti_jwks_url)
            .bind(&platform.lti_jwks_json)
            .bind(platform.lti_jwks_fetched_at)
            .bind(platform.lti_jwks_expires_at)
            .bind(&platform.lti_openid_configuration)
            .bind(&platform.last_connection_error)
            .bind(platform.updated_at)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(platform_from_row)
            .transpose()
    }

    pub async fn application_template(
        &self,
        template_id: &str,
    ) -> Result<Option<CanvasApplicationTemplateProjection>, CanvasManagementRepositoryError> {
        sqlx::query(GET_APPLICATION_TEMPLATE)
            .bind(template_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(|row| {
                Ok(CanvasApplicationTemplateProjection {
                    id: row_value(&row, "id")?,
                    organization_id: row_value(&row, "organization_id")?,
                    credential_template_id: row_value(&row, "credential_template_id")?,
                    approval_policy_set_id: row_value(&row, "approval_policy_set_id")?,
                    active: row_value::<String>(&row, "status")?.eq_ignore_ascii_case("active"),
                })
            })
            .transpose()
    }

    pub async fn valid_canvas_credentials_secret(
        &self,
        organization_id: &str,
        secret_id: &str,
    ) -> Result<bool, CanvasManagementRepositoryError> {
        sqlx::query_scalar::<_, bool>(VALID_CANVAS_CREDENTIALS_SECRET)
            .bind(organization_id)
            .bind(secret_id)
            .fetch_one(&self.pool)
            .await
            .map_err(repository_error)
    }

    pub async fn active_binding(
        &self,
        organization_id: &str,
        binding_id: &str,
    ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
        sqlx::query(GET_ACTIVE_BINDING)
            .bind(organization_id)
            .bind(binding_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(binding_from_row)
            .transpose()
    }

    pub async fn list_active_bindings(
        &self,
        organization_id: &str,
        platform_id: Option<&str>,
        application_template_id: Option<&str>,
    ) -> Result<Vec<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
        sqlx::query(LIST_ACTIVE_BINDINGS)
            .bind(organization_id)
            .bind(platform_id)
            .bind(application_template_id)
            .fetch_all(&self.pool)
            .await
            .map_err(repository_error)?
            .into_iter()
            .map(binding_from_row)
            .collect()
    }

    pub async fn create_binding(
        &self,
        binding: &CanvasProgramBindingRecord,
    ) -> Result<(), CanvasManagementRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(repository_error)?;
        let locked = sqlx::query(LOCK_ACTIVE_BINDING_PLATFORM)
            .bind(&binding.organization_id)
            .bind(&binding.platform_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(repository_error)?;
        if locked.is_none() {
            transaction.rollback().await.map_err(repository_error)?;
            return Err(CanvasManagementRepositoryError::ConfigurationChanged);
        }
        if duplicate_binding_id(&mut transaction, binding, None)
            .await?
            .is_some()
        {
            transaction.rollback().await.map_err(repository_error)?;
            return Err(CanvasManagementRepositoryError::DuplicateBinding);
        }
        bind_binding_insert(sqlx::query(INSERT_BINDING), binding)?
            .execute(&mut *transaction)
            .await
            .map_err(repository_error)?;
        transaction.commit().await.map_err(repository_error)
    }

    pub async fn save_binding_configuration(
        &self,
        binding: &CanvasProgramBindingRecord,
        expected_config_version: i64,
    ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
        let expected_version = version_i32(expected_config_version)?;
        if binding.config_version
            != expected_config_version
                .checked_add(1)
                .ok_or(CanvasManagementRepositoryError::VersionExhausted)?
        {
            return Err(CanvasManagementRepositoryError::ConfigurationChanged);
        }
        let mut transaction = self.pool.begin().await.map_err(repository_error)?;
        let locked = sqlx::query(LOCK_ACTIVE_BINDING_PLATFORM)
            .bind(&binding.organization_id)
            .bind(&binding.platform_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(repository_error)?;
        if locked.is_none() {
            transaction.rollback().await.map_err(repository_error)?;
            return Ok(None);
        }
        if duplicate_binding_id(&mut transaction, binding, Some(&binding.id))
            .await?
            .is_some()
        {
            transaction.rollback().await.map_err(repository_error)?;
            return Err(CanvasManagementRepositoryError::DuplicateBinding);
        }
        let row = bind_binding_update(
            sqlx::query(UPDATE_BINDING_CONFIGURATION),
            binding,
            expected_version,
        )?
        .fetch_optional(&mut *transaction)
        .await
        .map_err(repository_error)?;
        let Some(row) = row else {
            transaction.rollback().await.map_err(repository_error)?;
            return Ok(None);
        };
        transaction.commit().await.map_err(repository_error)?;
        binding_from_row(row).map(Some)
    }

    pub async fn save_binding_readiness(
        &self,
        binding: &CanvasProgramBindingRecord,
        expected_config_version: i64,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
        if binding.config_version != expected_config_version
            || binding.updated_at != expected_updated_at
            || binding.validated_config_version != Some(expected_config_version)
            || binding.readiness_validated_at.is_none()
            || binding.readiness_checks.is_empty()
        {
            return Err(CanvasManagementRepositoryError::ConfigurationChanged);
        }
        sqlx::query(UPDATE_BINDING_READINESS)
            .bind(&binding.organization_id)
            .bind(&binding.id)
            .bind(version_i32(expected_config_version)?)
            .bind(expected_updated_at)
            .bind(version_i32(binding.validated_config_version.ok_or(
                CanvasManagementRepositoryError::ConfigurationChanged,
            )?)?)
            .bind(Value::Array(binding.readiness_checks.clone()))
            .bind(binding.readiness_validated_at)
            .bind(Value::Object(binding.credential_template_snapshot.clone()))
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(binding_from_row)
            .transpose()
    }

    pub async fn activate_binding(
        &self,
        activation: &CanvasBindingActivation,
    ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
        let binding = &activation.binding;
        let platform = &activation.platform;
        let binding_version = version_i32(binding.config_version)?;
        let platform_version = version_i32(platform.config_version)?;
        let mut transaction = self.pool.begin().await.map_err(repository_error)?;

        let platform_enabled = sqlx::query(ENABLE_PLATFORM_FOR_BINDING)
            .bind(&platform.organization_id)
            .bind(&platform.id)
            .bind(platform_version)
            .bind(platform.updated_at)
            .bind(activation.activated_at)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(repository_error)?;
        if platform_enabled.is_none() {
            transaction.rollback().await.map_err(repository_error)?;
            return Ok(None);
        }

        let row = sqlx::query(ACTIVATE_BINDING)
            .bind(&binding.organization_id)
            .bind(&binding.id)
            .bind(binding_version)
            .bind(binding.updated_at)
            .bind(activation.activated_at)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(repository_error)?;
        let Some(row) = row else {
            transaction.rollback().await.map_err(repository_error)?;
            return Ok(None);
        };

        if let Some(metadata) = &activation.background_roster_metadata {
            upsert_and_enqueue_target(
                &mut transaction,
                &binding.organization_id,
                &platform.id,
                &binding.id,
                "background_roster",
                &format!("roster:{}", binding.id),
                None,
                15 * 60,
                binding_version,
                Value::Object(metadata.clone()),
                Value::Object(metadata.clone()),
                activation.activated_at,
            )
            .await?;
        }

        let applications = sqlx::query(ACTIVATION_APPLICATIONS)
            .bind(&binding.organization_id)
            .bind(&binding.application_template_id)
            .bind(&binding.id)
            .fetch_all(&mut *transaction)
            .await
            .map_err(repository_error)?;
        for application in applications {
            let application_id = application
                .try_get::<String, _>("id")
                .map_err(|_| CanvasManagementRepositoryError::Unavailable)?;
            let issued = application
                .try_get::<Option<String>, _>("credential_id")
                .map_err(|_| CanvasManagementRepositoryError::Unavailable)?
                .is_some();
            upsert_and_enqueue_target(
                &mut transaction,
                &binding.organization_id,
                &platform.id,
                &binding.id,
                if issued {
                    "issued_drift"
                } else {
                    "learner_application"
                },
                &format!("application:{application_id}"),
                Some(&application_id),
                if issued { 6 * 60 * 60 } else { 15 * 60 },
                binding_version,
                json!({"created_from": "application_sync_api"}),
                json!({"last_requested_from": "application_sync_api"}),
                activation.activated_at,
            )
            .await?;
        }

        transaction.commit().await.map_err(repository_error)?;
        binding_from_row(row).map(Some)
    }

    pub async fn deactivate_binding(
        &self,
        binding: &CanvasProgramBindingRecord,
        deactivated_at: DateTime<Utc>,
    ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(repository_error)?;
        let row = sqlx::query(DEACTIVATE_BINDING)
            .bind(&binding.organization_id)
            .bind(&binding.id)
            .bind(version_i32(binding.config_version)?)
            .bind(binding.updated_at)
            .bind(deactivated_at)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(repository_error)?;
        let Some(row) = row else {
            transaction.rollback().await.map_err(repository_error)?;
            return Ok(None);
        };
        sqlx::query(DISABLE_ROSTER_TARGET)
            .bind(&binding.organization_id)
            .bind(format!("roster:{}", binding.id))
            .bind(deactivated_at)
            .execute(&mut *transaction)
            .await
            .map_err(repository_error)?;
        transaction.commit().await.map_err(repository_error)?;
        binding_from_row(row).map(Some)
    }

    pub async fn archive_binding(
        &self,
        organization_id: &str,
        binding_id: &str,
        expected_config_version: i64,
        now: DateTime<Utc>,
    ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
        sqlx::query(ARCHIVE_BINDING)
            .bind(organization_id)
            .bind(binding_id)
            .bind(version_i32(expected_config_version)?)
            .bind(now)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(binding_from_row)
            .transpose()
    }
}

#[allow(clippy::too_many_arguments)]
async fn upsert_and_enqueue_target(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    platform_id: &str,
    binding_id: &str,
    target_type: &str,
    logical_key: &str,
    application_id: Option<&str>,
    schedule_seconds: i32,
    config_version: i32,
    create_metadata: Value,
    update_metadata: Value,
    now: DateTime<Utc>,
) -> Result<(), CanvasManagementRepositoryError> {
    let target_id = uuid::Uuid::new_v4().to_string();
    let row = sqlx::query(UPSERT_SYNC_TARGET)
        .bind(&target_id)
        .bind(organization_id)
        .bind(platform_id)
        .bind(binding_id)
        .bind(target_type)
        .bind(logical_key)
        .bind(application_id)
        .bind(schedule_seconds)
        .bind(now)
        .bind(config_version)
        .bind(create_metadata)
        .bind(update_metadata)
        .fetch_one(&mut **transaction)
        .await
        .map_err(repository_error)?;
    let canonical_target_id = row
        .try_get::<String, _>("id")
        .map_err(|_| CanvasManagementRepositoryError::Unavailable)?;
    sqlx::query(ENQUEUE_SYNC_JOB)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(organization_id)
        .bind(&canonical_target_id)
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(repository_error)?;
    sqlx::query(MARK_TARGET_ENQUEUED)
        .bind(organization_id)
        .bind(canonical_target_id)
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(repository_error)?;
    Ok(())
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

    async fn save_lti_probe_metadata(
        &self,
        platform: &CanvasPlatformRecord,
        expected_config_version: i64,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        PostgresCanvasManagementRepository::save_lti_probe_metadata(
            self,
            platform,
            expected_config_version,
            expected_updated_at,
        )
        .await
    }

    async fn application_template(
        &self,
        template_id: &str,
    ) -> Result<Option<CanvasApplicationTemplateProjection>, CanvasManagementRepositoryError> {
        PostgresCanvasManagementRepository::application_template(self, template_id).await
    }

    async fn valid_canvas_credentials_secret(
        &self,
        organization_id: &str,
        secret_id: &str,
    ) -> Result<bool, CanvasManagementRepositoryError> {
        PostgresCanvasManagementRepository::valid_canvas_credentials_secret(
            self,
            organization_id,
            secret_id,
        )
        .await
    }

    async fn active_binding(
        &self,
        organization_id: &str,
        binding_id: &str,
    ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
        PostgresCanvasManagementRepository::active_binding(self, organization_id, binding_id).await
    }

    async fn list_active_bindings(
        &self,
        organization_id: &str,
        platform_id: Option<&str>,
        application_template_id: Option<&str>,
    ) -> Result<Vec<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
        PostgresCanvasManagementRepository::list_active_bindings(
            self,
            organization_id,
            platform_id,
            application_template_id,
        )
        .await
    }

    async fn create_binding(
        &self,
        binding: &CanvasProgramBindingRecord,
    ) -> Result<(), CanvasManagementRepositoryError> {
        PostgresCanvasManagementRepository::create_binding(self, binding).await
    }

    async fn save_binding_configuration(
        &self,
        binding: &CanvasProgramBindingRecord,
        expected_config_version: i64,
    ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
        PostgresCanvasManagementRepository::save_binding_configuration(
            self,
            binding,
            expected_config_version,
        )
        .await
    }

    async fn save_binding_readiness(
        &self,
        binding: &CanvasProgramBindingRecord,
        expected_config_version: i64,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
        PostgresCanvasManagementRepository::save_binding_readiness(
            self,
            binding,
            expected_config_version,
            expected_updated_at,
        )
        .await
    }

    async fn activate_binding(
        &self,
        activation: &CanvasBindingActivation,
    ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
        PostgresCanvasManagementRepository::activate_binding(self, activation).await
    }

    async fn deactivate_binding(
        &self,
        binding: &CanvasProgramBindingRecord,
        deactivated_at: DateTime<Utc>,
    ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
        PostgresCanvasManagementRepository::deactivate_binding(self, binding, deactivated_at).await
    }

    async fn archive_binding(
        &self,
        organization_id: &str,
        binding_id: &str,
        expected_config_version: i64,
        now: DateTime<Utc>,
    ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
        PostgresCanvasManagementRepository::archive_binding(
            self,
            organization_id,
            binding_id,
            expected_config_version,
            now,
        )
        .await
    }
}

async fn duplicate_binding_id(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    binding: &CanvasProgramBindingRecord,
    excluded_id: Option<&str>,
) -> Result<Option<String>, CanvasManagementRepositoryError> {
    let scope = serde_json::to_value(&binding.canvas_scope)
        .map_err(|_| CanvasManagementRepositoryError::Unavailable)?;
    sqlx::query_scalar::<_, String>(FIND_DUPLICATE_BINDING)
        .bind(&binding.organization_id)
        .bind(&binding.platform_id)
        .bind(&binding.application_template_id)
        .bind(scope)
        .bind(excluded_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(repository_error)
}

fn bind_binding_insert<'query>(
    query: sqlx::query::Query<'query, sqlx::Postgres, sqlx::postgres::PgArguments>,
    binding: &'query CanvasProgramBindingRecord,
) -> Result<
    sqlx::query::Query<'query, sqlx::Postgres, sqlx::postgres::PgArguments>,
    CanvasManagementRepositoryError,
> {
    let scope = serde_json::to_value(&binding.canvas_scope)
        .map_err(|_| CanvasManagementRepositoryError::Unavailable)?;
    let feature_flags = serde_json::to_value(&binding.feature_flags)
        .map_err(|_| CanvasManagementRepositoryError::Unavailable)?;
    Ok(query
        .bind(&binding.id)
        .bind(&binding.organization_id)
        .bind(&binding.platform_id)
        .bind(&binding.application_template_id)
        .bind(&binding.credential_template_id)
        .bind(&binding.display_name)
        .bind(&binding.flow_mode)
        .bind(binding.direct_issue_enabled)
        .bind(binding.auto_approve_on_evidence)
        .bind(Value::Array(binding.evidence_requirements.clone()))
        .bind(scope)
        .bind(&binding.delivery_mode)
        .bind(&binding.issuer_mode)
        .bind(&binding.approval_policy_set_id)
        .bind(&binding.deployment_profile_id)
        .bind(feature_flags)
        .bind(Value::Object(binding.canvas_credentials.clone()))
        .bind(version_i32(binding.config_version)?)
        .bind(
            binding
                .validated_config_version
                .map(version_i32)
                .transpose()?,
        )
        .bind(Value::Array(binding.readiness_checks.clone()))
        .bind(binding.readiness_validated_at)
        .bind(binding.activated_at)
        .bind(binding.archived_at)
        .bind(Value::Object(binding.credential_template_snapshot.clone()))
        .bind(binding.enabled)
        .bind(binding.created_at)
        .bind(binding.updated_at))
}

fn bind_binding_update<'query>(
    query: sqlx::query::Query<'query, sqlx::Postgres, sqlx::postgres::PgArguments>,
    binding: &'query CanvasProgramBindingRecord,
    expected_config_version: i32,
) -> Result<
    sqlx::query::Query<'query, sqlx::Postgres, sqlx::postgres::PgArguments>,
    CanvasManagementRepositoryError,
> {
    let scope = serde_json::to_value(&binding.canvas_scope)
        .map_err(|_| CanvasManagementRepositoryError::Unavailable)?;
    let feature_flags = serde_json::to_value(&binding.feature_flags)
        .map_err(|_| CanvasManagementRepositoryError::Unavailable)?;
    Ok(query
        .bind(&binding.organization_id)
        .bind(&binding.id)
        .bind(expected_config_version)
        .bind(&binding.application_template_id)
        .bind(&binding.credential_template_id)
        .bind(&binding.display_name)
        .bind(&binding.flow_mode)
        .bind(binding.direct_issue_enabled)
        .bind(binding.auto_approve_on_evidence)
        .bind(Value::Array(binding.evidence_requirements.clone()))
        .bind(scope)
        .bind(&binding.delivery_mode)
        .bind(&binding.issuer_mode)
        .bind(&binding.approval_policy_set_id)
        .bind(&binding.deployment_profile_id)
        .bind(feature_flags)
        .bind(Value::Object(binding.canvas_credentials.clone()))
        .bind(version_i32(binding.config_version)?)
        .bind(
            binding
                .validated_config_version
                .map(version_i32)
                .transpose()?,
        )
        .bind(Value::Array(binding.readiness_checks.clone()))
        .bind(binding.readiness_validated_at)
        .bind(binding.activated_at)
        .bind(binding.archived_at)
        .bind(Value::Object(binding.credential_template_snapshot.clone()))
        .bind(binding.enabled)
        .bind(binding.updated_at))
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

fn binding_from_row(
    row: PgRow,
) -> Result<CanvasProgramBindingRecord, CanvasManagementRepositoryError> {
    let evidence_requirements = row_value::<Value>(&row, "evidence_requirements")?
        .as_array()
        .cloned()
        .ok_or(CanvasManagementRepositoryError::Unavailable)?;
    let readiness_checks = row_value::<Value>(&row, "readiness_checks")?
        .as_array()
        .cloned()
        .ok_or(CanvasManagementRepositoryError::Unavailable)?;
    let canvas_scope = serde_json::from_value(row_value(&row, "canvas_scope")?)
        .map_err(|_| CanvasManagementRepositoryError::Unavailable)?;
    let feature_flags = serde_json::from_value(row_value(&row, "feature_flags")?)
        .map_err(|_| CanvasManagementRepositoryError::Unavailable)?;
    Ok(CanvasProgramBindingRecord {
        id: row_value(&row, "id")?,
        organization_id: row_value(&row, "organization_id")?,
        platform_id: row_value(&row, "platform_id")?,
        application_template_id: row_value(&row, "application_template_id")?,
        credential_template_id: row_value(&row, "credential_template_id")?,
        display_name: row_value(&row, "display_name")?,
        flow_mode: row_value(&row, "flow_mode")?,
        direct_issue_enabled: row_value(&row, "direct_issue_enabled")?,
        auto_approve_on_evidence: row_value(&row, "auto_approve_on_evidence")?,
        evidence_requirements,
        canvas_scope,
        delivery_mode: row_value(&row, "delivery_mode")?,
        issuer_mode: row_value(&row, "issuer_mode")?,
        approval_policy_set_id: row_value(&row, "approval_policy_set_id")?,
        deployment_profile_id: row_value(&row, "deployment_profile_id")?,
        feature_flags,
        canvas_credentials: json_object(row_value(&row, "canvas_credentials")?)?,
        config_version: i64::from(row_value::<i32>(&row, "config_version")?),
        validated_config_version: row_value::<Option<i32>>(&row, "validated_config_version")?
            .map(i64::from),
        readiness_checks,
        readiness_validated_at: row_value(&row, "readiness_validated_at")?,
        activated_at: row_value(&row, "activated_at")?,
        archived_at: row_value(&row, "archived_at")?,
        credential_template_snapshot: json_object(row_value(
            &row,
            "credential_template_snapshot",
        )?)?,
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
        assert!(UPDATE_BINDING_READINESS.contains("organization_id = $1"));
        assert!(UPDATE_BINDING_READINESS.contains("config_version = $3"));
        assert!(UPDATE_BINDING_READINESS.contains("updated_at = $4"));
        assert!(UPDATE_BINDING_READINESS.contains("archived_at IS NULL"));
        assert!(UPDATE_BINDING_READINESS.contains("validated_config_version = $5"));
        assert!(UPDATE_BINDING_READINESS.contains("credential_template_snapshot = $8"));
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
    fn binding_projection_and_mutations_cover_the_complete_persisted_record() {
        for column in [
            "application_template_id",
            "credential_template_id",
            "evidence_requirements",
            "canvas_scope",
            "canvas_credentials",
            "config_version",
            "credential_template_snapshot",
            "created_at",
        ] {
            assert!(BINDING_COLUMNS.contains(column), "missing {column}");
            assert!(GET_ACTIVE_BINDING.contains(column), "missing {column}");
            assert!(LIST_ACTIVE_BINDINGS.contains(column), "missing {column}");
        }
        assert!(GET_ACTIVE_BINDING.contains("organization_id = $1"));
        assert!(GET_ACTIVE_BINDING.contains("archived_at IS NULL"));
        assert!(FIND_DUPLICATE_BINDING.contains("canvas_scope::jsonb = $4::jsonb"));
        assert!(UPDATE_BINDING_CONFIGURATION.contains("config_version = $3"));
        assert!(UPDATE_BINDING_CONFIGURATION.contains("archived_at IS NULL"));
        assert!(ARCHIVE_BINDING.contains("organization_id = $1"));
        assert!(ARCHIVE_BINDING.contains("config_version = $3"));
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
