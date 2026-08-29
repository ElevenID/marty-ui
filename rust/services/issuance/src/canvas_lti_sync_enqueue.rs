use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use serde_json::{Map, Value};
use sqlx::{PgPool, Row};
use tracing::error;

use crate::canvas_lti_bootstrap::{CanvasLtiBootstrapSyncEnqueuer, CanvasLtiBootstrapSyncError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanvasSyncEnqueueIds {
    pub target_id: String,
    pub job_id: String,
}

pub trait CanvasSyncEnqueueIdGenerator: Send + Sync {
    fn generate(&self) -> CanvasSyncEnqueueIds;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UuidCanvasSyncEnqueueIdGenerator;

impl CanvasSyncEnqueueIdGenerator for UuidCanvasSyncEnqueueIdGenerator {
    fn generate(&self) -> CanvasSyncEnqueueIds {
        CanvasSyncEnqueueIds {
            target_id: uuid::Uuid::new_v4().to_string(),
            job_id: uuid::Uuid::new_v4().to_string(),
        }
    }
}

#[derive(Clone)]
pub struct PostgresCanvasLtiBootstrapSyncEnqueuer {
    pool: PgPool,
    enabled: bool,
    pilot_organizations: BTreeSet<String>,
    ids: Arc<dyn CanvasSyncEnqueueIdGenerator>,
}

impl std::fmt::Debug for PostgresCanvasLtiBootstrapSyncEnqueuer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresCanvasLtiBootstrapSyncEnqueuer")
            .field("enabled", &self.enabled)
            .field("pilot_organizations", &self.pilot_organizations)
            .finish_non_exhaustive()
    }
}

impl PostgresCanvasLtiBootstrapSyncEnqueuer {
    #[must_use]
    pub fn new(
        pool: PgPool,
        enabled: bool,
        pilot_organizations: BTreeSet<String>,
        ids: Arc<dyn CanvasSyncEnqueueIdGenerator>,
    ) -> Self {
        Self {
            pool,
            enabled,
            pilot_organizations,
            ids,
        }
    }
}

#[async_trait]
impl CanvasLtiBootstrapSyncEnqueuer for PostgresCanvasLtiBootstrapSyncEnqueuer {
    async fn enqueue(
        &self,
        organization_id: &str,
        application_id: &str,
    ) -> Result<(), CanvasLtiBootstrapSyncError> {
        if !self.enabled || !self.pilot_organizations.contains(organization_id) {
            return Err(CanvasLtiBootstrapSyncError);
        }
        enqueue_application_sync(
            &self.pool,
            organization_id,
            application_id,
            &self.ids.generate(),
        )
        .await
    }
}

async fn enqueue_application_sync(
    pool: &PgPool,
    organization_id: &str,
    application_id: &str,
    ids: &CanvasSyncEnqueueIds,
) -> Result<(), CanvasLtiBootstrapSyncError> {
    let mut database = pool.begin().await.map_err(sync_error)?;
    let application = sqlx::query(
        "SELECT integration_context, credential_id
         FROM issuance_service.applications
         WHERE id = $1 AND organization_id = $2 FOR SHARE",
    )
    .bind(application_id)
    .bind(organization_id)
    .fetch_optional(&mut *database)
    .await
    .map_err(sync_error)?
    .ok_or(CanvasLtiBootstrapSyncError)?;
    let integration: Value = application
        .try_get("integration_context")
        .map_err(sync_error)?;
    let canvas = integration
        .get("canvas")
        .and_then(Value::as_object)
        .ok_or(CanvasLtiBootstrapSyncError)?;
    let platform_id = required_text(canvas, "canvas_platform_id")?;
    let binding_id = required_text(canvas, "canvas_program_binding_id")?;
    let credential_id: Option<String> = application.try_get("credential_id").map_err(sync_error)?;
    let platform_active: Option<String> = sqlx::query_scalar(
        "SELECT id FROM issuance_service.canvas_platforms
         WHERE id = $1 AND organization_id = $2 AND enabled = true
         FOR SHARE",
    )
    .bind(&platform_id)
    .bind(organization_id)
    .fetch_optional(&mut *database)
    .await
    .map_err(sync_error)?;
    let binding = sqlx::query(
        "SELECT config_version FROM issuance_service.canvas_program_bindings
         WHERE id = $1 AND organization_id = $2 AND platform_id = $3 AND enabled = true
         FOR SHARE",
    )
    .bind(&binding_id)
    .bind(organization_id)
    .bind(&platform_id)
    .fetch_optional(&mut *database)
    .await
    .map_err(sync_error)?;
    let Some(binding) = binding else {
        return Err(CanvasLtiBootstrapSyncError);
    };
    if platform_active.is_none() {
        return Err(CanvasLtiBootstrapSyncError);
    }
    let config_version: i32 = binding.try_get("config_version").map_err(sync_error)?;
    let issued = credential_id.is_some();
    let target_type = if issued {
        "issued_drift"
    } else {
        "learner_application"
    };
    let schedule_seconds = if issued { 21_600_i32 } else { 900_i32 };
    let logical_key = format!("application:{application_id}");
    let target_id: String = sqlx::query_scalar(
        "INSERT INTO issuance_service.canvas_evidence_sync_targets (
            id, organization_id, platform_id, binding_id, target_type, logical_key,
            application_id, candidate_id, enabled, schedule_seconds, next_run_at,
            last_enqueued_at, last_succeeded_at, config_version, metadata,
            created_at, updated_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, true, $8,
                   clock_timestamp(), NULL, NULL, $9,
                   '{\"created_from\":\"application_sync_api\"}'::json,
                   clock_timestamp(), clock_timestamp())
         ON CONFLICT (organization_id, logical_key) DO UPDATE SET
            platform_id = EXCLUDED.platform_id,
            binding_id = EXCLUDED.binding_id,
            target_type = EXCLUDED.target_type,
            application_id = EXCLUDED.application_id,
            enabled = true,
            schedule_seconds = EXCLUDED.schedule_seconds,
            config_version = EXCLUDED.config_version,
            metadata = COALESCE(
                           to_jsonb(issuance_service.canvas_evidence_sync_targets.metadata),
                           '{}'::jsonb)
                       || '{\"last_requested_from\":\"application_sync_api\"}'::jsonb,
            updated_at = clock_timestamp()
         RETURNING id",
    )
    .bind(&ids.target_id)
    .bind(organization_id)
    .bind(&platform_id)
    .bind(&binding_id)
    .bind(target_type)
    .bind(&logical_key)
    .bind(application_id)
    .bind(schedule_seconds)
    .bind(config_version)
    .fetch_one(&mut *database)
    .await
    .map_err(sync_error)?;
    let inserted_job: Option<String> = sqlx::query_scalar(
        "INSERT INTO issuance_service.canvas_evidence_sync_jobs (
            id, organization_id, target_id, status, attempt_count, max_attempts,
            available_at, lease_owner, lease_expires_at, last_error_code,
            last_error_summary, result, created_at, updated_at, started_at, completed_at
         ) VALUES ($1, $2, $3, 'queued', 0, 8, clock_timestamp(), NULL, NULL,
                   NULL, NULL, '{}'::json, clock_timestamp(), clock_timestamp(), NULL, NULL)
         ON CONFLICT DO NOTHING RETURNING id",
    )
    .bind(&ids.job_id)
    .bind(organization_id)
    .bind(&target_id)
    .fetch_optional(&mut *database)
    .await
    .map_err(sync_error)?;
    if inserted_job.is_none() {
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT id FROM issuance_service.canvas_evidence_sync_jobs
             WHERE target_id = $1 AND status IN ('queued', 'leased', 'retry')
             ORDER BY created_at LIMIT 1 FOR SHARE",
        )
        .bind(&target_id)
        .fetch_optional(&mut *database)
        .await
        .map_err(sync_error)?;
        if existing.is_none() {
            return Err(CanvasLtiBootstrapSyncError);
        }
    }
    let touched = sqlx::query(
        "UPDATE issuance_service.canvas_evidence_sync_targets
         SET last_enqueued_at = clock_timestamp(), updated_at = clock_timestamp()
         WHERE id = $1 AND organization_id = $2",
    )
    .bind(&target_id)
    .bind(organization_id)
    .execute(&mut *database)
    .await
    .map_err(sync_error)?;
    if touched.rows_affected() != 1 {
        return Err(CanvasLtiBootstrapSyncError);
    }
    database.commit().await.map_err(sync_error)
}

fn required_text(
    value: &Map<String, Value>,
    name: &str,
) -> Result<String, CanvasLtiBootstrapSyncError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(CanvasLtiBootstrapSyncError)
}

fn sync_error(cause: sqlx::Error) -> CanvasLtiBootstrapSyncError {
    error!(%cause, "Canvas bootstrap sync enqueue query failed");
    CanvasLtiBootstrapSyncError
}
