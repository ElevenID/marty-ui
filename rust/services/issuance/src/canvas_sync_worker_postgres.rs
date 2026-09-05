//! PostgreSQL persistence for the standalone Canvas synchronization worker.

use async_trait::async_trait;
use serde_json::Value;
use sqlx::{PgPool, Postgres, Row, Transaction};
use tracing::error;

use crate::canvas_sync_worker::{
    maximum_attempts, random_job_retry_delay_seconds, CanvasSyncJob, CanvasSyncJobStatus,
    CanvasSyncRepositoryError, CanvasSyncResult, CanvasSyncTarget, CanvasSyncTargetType,
    CanvasSyncWorkerRepository, JobFailure, WorkerHeartbeat,
};

#[derive(Clone)]
pub struct PostgresCanvasSyncWorkerRepository {
    pool: PgPool,
}

impl std::fmt::Debug for PostgresCanvasSyncWorkerRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresCanvasSyncWorkerRepository")
            .finish_non_exhaustive()
    }
}

impl PostgresCanvasSyncWorkerRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CanvasSyncWorkerRepository for PostgresCanvasSyncWorkerRepository {
    async fn upsert_heartbeat(
        &self,
        heartbeat: &WorkerHeartbeat,
    ) -> Result<(), CanvasSyncRepositoryError> {
        sqlx::query(
            "INSERT INTO issuance_service.canvas_worker_heartbeats
                (worker_id, role, started_at, last_heartbeat_at, metadata)
             VALUES ($1, 'canvas_sync', $2, clock_timestamp(), $3)
             ON CONFLICT (worker_id) DO UPDATE SET
                role = 'canvas_sync', last_heartbeat_at = clock_timestamp(),
                metadata = EXCLUDED.metadata",
        )
        .bind(&heartbeat.worker_id)
        .bind(heartbeat.started_at)
        .bind(serde_json::json!({
            "phase": heartbeat.phase,
            "leased_jobs": heartbeat.leased_jobs,
            "process": "standalone",
            "processor_configured": heartbeat.processor_configured,
        }))
        .execute(&self.pool)
        .await
        .map_err(repository_error)?;
        Ok(())
    }

    async fn enqueue_due(&self, limit: usize) -> Result<usize, CanvasSyncRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(repository_error)?;
        let due = sqlx::query(
            "SELECT id, organization_id, schedule_seconds
             FROM issuance_service.canvas_evidence_sync_targets
             WHERE enabled = true AND next_run_at <= clock_timestamp()
             ORDER BY next_run_at ASC
             LIMIT $1 FOR UPDATE SKIP LOCKED",
        )
        .bind(limit_as_i64(limit)?)
        .fetch_all(&mut *transaction)
        .await
        .map_err(repository_error)?;
        let mut scheduled = 0;
        for target in due {
            let target_id: String = target.try_get("id").map_err(repository_error)?;
            let organization_id: String = target
                .try_get("organization_id")
                .map_err(repository_error)?;
            let schedule_seconds: i32 = target
                .try_get("schedule_seconds")
                .map_err(repository_error)?;
            let inserted: Option<String> = sqlx::query_scalar(
                "INSERT INTO issuance_service.canvas_evidence_sync_jobs
                    (id, organization_id, target_id, status, attempt_count, max_attempts,
                     available_at, result, created_at, updated_at)
                 VALUES ($1, $2, $3, 'queued', 0, $4,
                         clock_timestamp(), '{}'::json, clock_timestamp(), clock_timestamp())
                 ON CONFLICT DO NOTHING RETURNING id",
            )
            .bind(UuidString::generate())
            .bind(&organization_id)
            .bind(&target_id)
            .bind(maximum_attempts())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(repository_error)?;
            scheduled += usize::from(inserted.is_some());
            sqlx::query(
                "UPDATE issuance_service.canvas_evidence_sync_targets
                 SET last_enqueued_at = clock_timestamp(),
                     next_run_at = clock_timestamp() + make_interval(secs => $2),
                     updated_at = clock_timestamp()
                 WHERE id = $1",
            )
            .bind(&target_id)
            .bind(schedule_seconds.max(60))
            .execute(&mut *transaction)
            .await
            .map_err(repository_error)?;
        }
        transaction.commit().await.map_err(repository_error)?;
        Ok(scheduled)
    }

    async fn lease_ready(
        &self,
        worker_id: &str,
        limit: usize,
        lease_seconds: i64,
    ) -> Result<Vec<CanvasSyncJob>, CanvasSyncRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(repository_error)?;
        recover_expired_final(&mut transaction).await?;
        recover_expired_retry(&mut transaction).await?;
        let ready = sqlx::query(
            "SELECT id FROM issuance_service.canvas_evidence_sync_jobs
             WHERE status IN ('queued', 'retry')
               AND available_at <= clock_timestamp()
               AND attempt_count < max_attempts
             ORDER BY available_at ASC, created_at ASC
             LIMIT $1 FOR UPDATE SKIP LOCKED",
        )
        .bind(limit_as_i64(limit)?)
        .fetch_all(&mut *transaction)
        .await
        .map_err(repository_error)?;
        let mut leased = Vec::with_capacity(ready.len());
        for row in ready {
            let id: String = row.try_get("id").map_err(repository_error)?;
            let leased_row = sqlx::query(
                "UPDATE issuance_service.canvas_evidence_sync_jobs
                 SET status = 'leased', attempt_count = attempt_count + 1,
                     lease_owner = $2,
                     lease_expires_at = clock_timestamp() + make_interval(secs => $3),
                     started_at = COALESCE(started_at, clock_timestamp()),
                     result = jsonb_set(COALESCE(result::jsonb, '{}'::jsonb),
                         '{target_config_version}',
                         COALESCE(to_jsonb((SELECT config_version
                                   FROM issuance_service.canvas_evidence_sync_targets
                                   WHERE id = target_id AND organization_id = canvas_evidence_sync_jobs.organization_id)),
                                  '0'::jsonb),
                         true),
                     updated_at = clock_timestamp()
                 WHERE id = $1
                 RETURNING id, organization_id, target_id, status, attempt_count,
                           max_attempts, available_at, lease_owner, lease_expires_at,
                           created_at, started_at,
                           (result->>'target_config_version')::integer AS target_config_version",
            )
            .bind(id)
            .bind(worker_id)
            .bind(lease_seconds.max(30))
            .fetch_one(&mut *transaction)
            .await
            .map_err(repository_error)?;
            leased.push(job_from_row(&leased_row)?);
        }
        transaction.commit().await.map_err(repository_error)?;
        Ok(leased)
    }

    async fn target(
        &self,
        organization_id: &str,
        target_id: &str,
    ) -> Result<Option<CanvasSyncTarget>, CanvasSyncRepositoryError> {
        sqlx::query(
            "SELECT id, organization_id, platform_id, binding_id, target_type,
                    logical_key, application_id, candidate_id, enabled,
                    schedule_seconds, config_version, metadata, created_at
             FROM issuance_service.canvas_evidence_sync_targets
             WHERE id = $1 AND organization_id = $2",
        )
        .bind(target_id)
        .bind(organization_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(repository_error)?
        .map(|row| target_from_row(&row))
        .transpose()
    }

    async fn touch_target_heartbeat(
        &self,
        target: &CanvasSyncTarget,
        worker_id: &str,
    ) -> Result<bool, CanvasSyncRepositoryError> {
        let result = sqlx::query(
            "UPDATE issuance_service.canvas_evidence_sync_targets
             SET metadata = COALESCE(metadata::jsonb, '{}'::jsonb)
                            || jsonb_build_object(
                                 'worker_id', $5::text,
                                 'worker_heartbeat_at', clock_timestamp()::text
                               ),
                 updated_at = clock_timestamp()
             WHERE id = $1 AND organization_id = $2 AND config_version = $3
               AND enabled = $4",
        )
        .bind(&target.id)
        .bind(&target.organization_id)
        .bind(target.config_version)
        .bind(true)
        .bind(worker_id)
        .execute(&self.pool)
        .await
        .map_err(repository_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn validate_target(
        &self,
        target: &CanvasSyncTarget,
    ) -> Result<(), crate::canvas_sync_worker::CanvasSyncProcessingError> {
        use crate::canvas_sync_worker::CanvasSyncProcessingError;

        if [
            target.organization_id.as_str(),
            target.platform_id.as_str(),
            target.binding_id.as_str(),
            target.logical_key.as_str(),
        ]
        .iter()
        .any(|value| value.trim().is_empty())
        {
            return Err(CanvasSyncProcessingError::terminal(
                "canvas_sync_target_incomplete",
                "Canvas synchronization target is incomplete",
            ));
        }
        if metadata_contains_secret(&Value::Object(target.metadata.clone())) {
            return Err(CanvasSyncProcessingError::terminal(
                "canvas_sync_target_contains_secret",
                "Canvas synchronization target contains authentication material",
            ));
        }
        let scope = sqlx::query(
            "SELECT p.enabled AS platform_enabled, p.archived_at AS platform_archived_at,
                    b.enabled AS binding_enabled, b.archived_at AS binding_archived_at,
                    b.config_version AS binding_config_version
             FROM issuance_service.canvas_platforms p
             JOIN issuance_service.canvas_program_bindings b
               ON b.organization_id = p.organization_id AND b.platform_id = p.id
             WHERE p.organization_id = $1 AND p.id = $2 AND b.id = $3",
        )
        .bind(&target.organization_id)
        .bind(&target.platform_id)
        .bind(&target.binding_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| {
            CanvasSyncProcessingError::retryable(
                "canvas_sync_resources_unavailable",
                "Canvas synchronization resources are unavailable",
            )
        })?;
        let Some(scope) = scope else {
            return Err(CanvasSyncProcessingError::terminal(
                "canvas_sync_target_scope_invalid",
                "Canvas synchronization target scope is invalid",
            ));
        };
        let platform_enabled: bool = scope.try_get("platform_enabled").map_err(|_| {
            CanvasSyncProcessingError::retryable(
                "canvas_sync_resources_unavailable",
                "Canvas synchronization resources are unavailable",
            )
        })?;
        let binding_enabled: bool = scope.try_get("binding_enabled").map_err(|_| {
            CanvasSyncProcessingError::retryable(
                "canvas_sync_resources_unavailable",
                "Canvas synchronization resources are unavailable",
            )
        })?;
        let platform_archived_at: Option<chrono::DateTime<chrono::Utc>> =
            scope.try_get("platform_archived_at").map_err(|_| {
                CanvasSyncProcessingError::retryable(
                    "canvas_sync_resources_unavailable",
                    "Canvas synchronization resources are unavailable",
                )
            })?;
        let binding_archived_at: Option<chrono::DateTime<chrono::Utc>> =
            scope.try_get("binding_archived_at").map_err(|_| {
                CanvasSyncProcessingError::retryable(
                    "canvas_sync_resources_unavailable",
                    "Canvas synchronization resources are unavailable",
                )
            })?;
        let binding_config_version: i32 =
            scope.try_get("binding_config_version").map_err(|_| {
                CanvasSyncProcessingError::retryable(
                    "canvas_sync_resources_unavailable",
                    "Canvas synchronization resources are unavailable",
                )
            })?;
        if !target.enabled
            || !platform_enabled
            || !binding_enabled
            || platform_archived_at.is_some()
            || binding_archived_at.is_some()
        {
            disable_target(&self.pool, target).await;
            return Err(CanvasSyncProcessingError::terminal(
                "canvas_sync_target_inactive",
                "Canvas synchronization target is inactive",
            ));
        }
        if target.config_version != binding_config_version {
            disable_target(&self.pool, target).await;
            return Err(CanvasSyncProcessingError::terminal(
                "canvas_sync_target_config_stale",
                "Canvas synchronization target configuration is stale",
            ));
        }
        match target.target_type {
            CanvasSyncTargetType::LearnerApplication | CanvasSyncTargetType::IssuedDrift => {
                let Some(application_id) = target.application_id.as_deref() else {
                    return Err(CanvasSyncProcessingError::terminal(
                        "canvas_sync_target_application_missing",
                        "Canvas synchronization application is missing",
                    ));
                };
                let exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS(
                         SELECT 1 FROM issuance_service.applications
                         WHERE id = $1 AND organization_id = $2
                     )",
                )
                .bind(application_id)
                .bind(&target.organization_id)
                .fetch_one(&self.pool)
                .await
                .map_err(|_| {
                    CanvasSyncProcessingError::retryable(
                        "canvas_sync_resources_unavailable",
                        "Canvas synchronization resources are unavailable",
                    )
                })?;
                if !exists {
                    return Err(CanvasSyncProcessingError::terminal(
                        "canvas_sync_target_application_invalid",
                        "Canvas synchronization application is invalid",
                    ));
                }
            }
            CanvasSyncTargetType::AwardCandidate => {
                let Some(candidate_id) = target.candidate_id.as_deref() else {
                    return Err(CanvasSyncProcessingError::terminal(
                        "canvas_sync_target_candidate_missing",
                        "Canvas synchronization candidate is missing",
                    ));
                };
                let exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS(
                         SELECT 1 FROM issuance_service.canvas_award_candidates
                         WHERE id = $1 AND organization_id = $2
                     )",
                )
                .bind(candidate_id)
                .bind(&target.organization_id)
                .fetch_one(&self.pool)
                .await
                .map_err(|_| {
                    CanvasSyncProcessingError::retryable(
                        "canvas_sync_resources_unavailable",
                        "Canvas synchronization resources are unavailable",
                    )
                })?;
                if !exists {
                    return Err(CanvasSyncProcessingError::terminal(
                        "canvas_sync_target_candidate_invalid",
                        "Canvas synchronization candidate is invalid",
                    ));
                }
            }
            CanvasSyncTargetType::BackgroundRoster => {}
        }
        Ok(())
    }

    async fn renew_lease(
        &self,
        job: &CanvasSyncJob,
        worker_id: &str,
        lease_seconds: i64,
    ) -> Result<bool, CanvasSyncRepositoryError> {
        let result = sqlx::query(
            "UPDATE issuance_service.canvas_evidence_sync_jobs
             SET lease_expires_at = clock_timestamp() + make_interval(secs => $5),
                 updated_at = clock_timestamp()
             WHERE id = $1 AND organization_id = $2 AND status = 'leased'
               AND lease_owner = $3 AND lease_expires_at > clock_timestamp()
               AND attempt_count = $4",
        )
        .bind(&job.id)
        .bind(&job.organization_id)
        .bind(worker_id)
        .bind(job.attempt_count)
        .bind(lease_seconds.max(30))
        .execute(&self.pool)
        .await
        .map_err(repository_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn complete_job(
        &self,
        job: &CanvasSyncJob,
        worker_id: &str,
        target_config_version: i32,
        result: &CanvasSyncResult,
    ) -> Result<bool, CanvasSyncRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(repository_error)?;
        // Lock and finalize the lease-owned job first. Expiry recovery uses the
        // same job-before-target order, avoiding a target/job lock inversion.
        // A concurrently reconfigured target must not undo a valid job outcome.
        let updated: Option<String> = sqlx::query_scalar(
            "UPDATE issuance_service.canvas_evidence_sync_jobs
             SET status = 'succeeded', result = $5, last_error_code = NULL,
                 last_error_summary = NULL, lease_owner = NULL,
                 lease_expires_at = NULL, completed_at = clock_timestamp(),
                 updated_at = clock_timestamp()
             WHERE id = $1 AND organization_id = $2 AND status = 'leased'
               AND lease_owner = $3 AND lease_expires_at > clock_timestamp()
               AND attempt_count = $4
             RETURNING id",
        )
        .bind(&job.id)
        .bind(&job.organization_id)
        .bind(worker_id)
        .bind(job.attempt_count)
        .bind(sqlx::types::Json(result))
        .fetch_optional(&mut *transaction)
        .await
        .map_err(repository_error)?;
        if updated.is_none() {
            transaction.rollback().await.map_err(repository_error)?;
            return Ok(false);
        }
        // Target success is an independent generation CAS. Its loss leaves the
        // lease-fenced job succeeded and never overwrites the newer target.
        sqlx::query(
            "UPDATE issuance_service.canvas_evidence_sync_targets
             SET last_succeeded_at = clock_timestamp(), updated_at = clock_timestamp()
             WHERE id = $1 AND organization_id = $2 AND config_version = $3
               AND enabled = true",
        )
        .bind(&job.target_id)
        .bind(&job.organization_id)
        .bind(target_config_version)
        .execute(&mut *transaction)
        .await
        .map_err(repository_error)?;
        transaction.commit().await.map_err(repository_error)?;
        Ok(true)
    }

    async fn fail_job(
        &self,
        job: &CanvasSyncJob,
        worker_id: &str,
        failure: &JobFailure<'_>,
        target_config_version: i32,
    ) -> Result<Option<CanvasSyncJobStatus>, CanvasSyncRepositoryError> {
        let dead_letter = failure.force_dead_letter || job.attempt_count >= job.max_attempts;
        let status = if dead_letter {
            CanvasSyncJobStatus::DeadLetter
        } else {
            CanvasSyncJobStatus::Retry
        };
        let delay = random_job_retry_delay_seconds(job.attempt_count, failure.retry_after_seconds);
        let mut transaction = self.pool.begin().await.map_err(repository_error)?;
        let updated: Option<String> = sqlx::query_scalar(
            "UPDATE issuance_service.canvas_evidence_sync_jobs
             SET status = $5,
                 max_attempts = CASE WHEN $6 THEN GREATEST(1, attempt_count)
                                     ELSE max_attempts END,
                 available_at = CASE WHEN $6 THEN available_at
                                     ELSE clock_timestamp() + make_interval(secs => $7) END,
                 lease_owner = NULL, lease_expires_at = NULL,
                 last_error_code = left($8, 120), last_error_summary = $9,
                 result = '{}'::json,
                 completed_at = CASE WHEN $6 THEN clock_timestamp() ELSE NULL END,
                 updated_at = clock_timestamp()
             WHERE id = $1 AND organization_id = $2 AND status = 'leased'
               AND lease_owner = $3 AND lease_expires_at > clock_timestamp()
               AND attempt_count = $4
             RETURNING id",
        )
        .bind(&job.id)
        .bind(&job.organization_id)
        .bind(worker_id)
        .bind(job.attempt_count)
        .bind(status.as_database())
        .bind(dead_letter)
        .bind(i64::try_from(delay).unwrap_or(86_400))
        .bind(failure.error_code)
        .bind(failure.error_summary)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(repository_error)?;
        if updated.is_none() {
            transaction.rollback().await.map_err(repository_error)?;
            return Ok(None);
        }
        if dead_letter {
            sqlx::query(
                "UPDATE issuance_service.canvas_evidence_sync_targets
                 SET enabled = false, updated_at = clock_timestamp()
                 WHERE id = $1 AND organization_id = $2 AND config_version = $3",
            )
            .bind(&job.target_id)
            .bind(&job.organization_id)
            .bind(target_config_version)
            .execute(&mut *transaction)
            .await
            .map_err(repository_error)?;
        }
        transaction.commit().await.map_err(repository_error)?;
        Ok(Some(status))
    }
}

async fn recover_expired_final(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), CanvasSyncRepositoryError> {
    let expired = sqlx::query(
        "SELECT id, organization_id, target_id,
                (result->>'target_config_version')::integer AS target_config_version
         FROM issuance_service.canvas_evidence_sync_jobs
         WHERE status = 'leased' AND lease_expires_at <= clock_timestamp()
           AND attempt_count >= max_attempts
         FOR UPDATE SKIP LOCKED",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(repository_error)?;
    for row in expired {
        let id: String = row.try_get("id").map_err(repository_error)?;
        let organization_id: String = row.try_get("organization_id").map_err(repository_error)?;
        let target_id: String = row.try_get("target_id").map_err(repository_error)?;
        let target_config_version: Option<i32> = row
            .try_get("target_config_version")
            .map_err(repository_error)?;
        sqlx::query(
            "UPDATE issuance_service.canvas_evidence_sync_jobs
             SET status = 'dead_letter', lease_owner = NULL, lease_expires_at = NULL,
                 last_error_code = 'canvas_worker_lease_expired',
                 last_error_summary = 'Canvas worker lease expired on final attempt',
                 completed_at = clock_timestamp(), updated_at = clock_timestamp()
             WHERE id = $1 AND status = 'leased' AND lease_expires_at <= clock_timestamp()",
        )
        .bind(id)
        .execute(&mut **transaction)
        .await
        .map_err(repository_error)?;
        sqlx::query(
            "UPDATE issuance_service.canvas_evidence_sync_targets
             SET enabled = false, updated_at = clock_timestamp()
             WHERE id = $1 AND organization_id = $2 AND config_version = $3",
        )
        .bind(target_id)
        .bind(organization_id)
        .bind(target_config_version.unwrap_or(i32::MIN))
        .execute(&mut **transaction)
        .await
        .map_err(repository_error)?;
    }
    Ok(())
}

async fn recover_expired_retry(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), CanvasSyncRepositoryError> {
    let expired = sqlx::query(
        "SELECT id, attempt_count
         FROM issuance_service.canvas_evidence_sync_jobs
         WHERE status = 'leased' AND lease_expires_at <= clock_timestamp()
           AND attempt_count < max_attempts
         FOR UPDATE SKIP LOCKED",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(repository_error)?;
    for row in expired {
        let id: String = row.try_get("id").map_err(repository_error)?;
        let attempt_count: i32 = row.try_get("attempt_count").map_err(repository_error)?;
        let delay = random_job_retry_delay_seconds(attempt_count, None);
        sqlx::query(
            "UPDATE issuance_service.canvas_evidence_sync_jobs
             SET status = 'retry',
                 available_at = clock_timestamp() + make_interval(secs => $2),
                 lease_owner = NULL, lease_expires_at = NULL,
                 last_error_code = 'canvas_worker_lease_expired',
                 last_error_summary = 'Canvas worker lease expired before completion',
                 updated_at = clock_timestamp()
             WHERE id = $1 AND status = 'leased' AND lease_expires_at <= clock_timestamp()",
        )
        .bind(id)
        .bind(i64::try_from(delay).unwrap_or(3_600))
        .execute(&mut **transaction)
        .await
        .map_err(repository_error)?;
    }
    Ok(())
}

fn job_from_row(row: &sqlx::postgres::PgRow) -> Result<CanvasSyncJob, CanvasSyncRepositoryError> {
    let status: String = row.try_get("status").map_err(repository_error)?;
    Ok(CanvasSyncJob {
        id: row.try_get("id").map_err(repository_error)?,
        organization_id: row.try_get("organization_id").map_err(repository_error)?,
        target_id: row.try_get("target_id").map_err(repository_error)?,
        target_config_version: row
            .try_get("target_config_version")
            .map_err(repository_error)?,
        status: CanvasSyncJobStatus::from_database(&status)
            .ok_or(CanvasSyncRepositoryError::InvalidState)?,
        attempt_count: row.try_get("attempt_count").map_err(repository_error)?,
        max_attempts: row.try_get("max_attempts").map_err(repository_error)?,
        available_at: row.try_get("available_at").map_err(repository_error)?,
        lease_owner: row.try_get("lease_owner").map_err(repository_error)?,
        lease_expires_at: row.try_get("lease_expires_at").map_err(repository_error)?,
        created_at: row.try_get("created_at").map_err(repository_error)?,
        started_at: row.try_get("started_at").map_err(repository_error)?,
    })
}

fn target_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<CanvasSyncTarget, CanvasSyncRepositoryError> {
    let target_type: String = row.try_get("target_type").map_err(repository_error)?;
    let metadata: Value = row.try_get("metadata").map_err(repository_error)?;
    Ok(CanvasSyncTarget {
        id: row.try_get("id").map_err(repository_error)?,
        organization_id: row.try_get("organization_id").map_err(repository_error)?,
        platform_id: row.try_get("platform_id").map_err(repository_error)?,
        binding_id: row.try_get("binding_id").map_err(repository_error)?,
        target_type: CanvasSyncTargetType::from_database(&target_type)
            .ok_or(CanvasSyncRepositoryError::InvalidState)?,
        logical_key: row.try_get("logical_key").map_err(repository_error)?,
        application_id: row.try_get("application_id").map_err(repository_error)?,
        candidate_id: row.try_get("candidate_id").map_err(repository_error)?,
        enabled: row.try_get("enabled").map_err(repository_error)?,
        schedule_seconds: row.try_get("schedule_seconds").map_err(repository_error)?,
        config_version: row.try_get("config_version").map_err(repository_error)?,
        metadata: metadata.as_object().cloned().unwrap_or_default(),
        created_at: row.try_get("created_at").map_err(repository_error)?,
    })
}

fn metadata_contains_secret(value: &Value) -> bool {
    const FORBIDDEN: &[&str] = &[
        "access_token",
        "refresh_token",
        "bearer",
        "authorization",
        "cookie",
        "api_key",
        "client_secret",
    ];
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    let normalized = key.trim().to_ascii_lowercase();
                    if FORBIDDEN
                        .iter()
                        .any(|fragment| normalized.contains(fragment))
                    {
                        return true;
                    }
                    pending.push(value);
                }
            }
            Value::Array(array) => pending.extend(array),
            Value::String(value)
                if value
                    .trim_start()
                    .get(..7)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("bearer ")) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

async fn disable_target(pool: &PgPool, target: &CanvasSyncTarget) {
    if let Err(error) = sqlx::query(
        "UPDATE issuance_service.canvas_evidence_sync_targets
         SET enabled = false, updated_at = clock_timestamp()
         WHERE id = $1 AND organization_id = $2 AND config_version = $3",
    )
    .bind(&target.id)
    .bind(&target.organization_id)
    .bind(target.config_version)
    .execute(pool)
    .await
    {
        tracing::warn!(
            exception_class = "SqlxError",
            "Canvas sync target disable failed"
        );
        let _ = error;
    }
}

fn limit_as_i64(limit: usize) -> Result<i64, CanvasSyncRepositoryError> {
    i64::try_from(limit.max(1)).map_err(|_| CanvasSyncRepositoryError::InvalidState)
}

fn repository_error(error: sqlx::Error) -> CanvasSyncRepositoryError {
    error!(
        exception_class = "SqlxError",
        "Canvas sync persistence operation failed"
    );
    let _ = error;
    CanvasSyncRepositoryError::Unavailable
}

struct UuidString;

impl UuidString {
    fn generate() -> String {
        uuid::Uuid::new_v4().to_string()
    }
}
