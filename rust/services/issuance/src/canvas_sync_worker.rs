//! Headless, durable Canvas synchronization worker kernel.
//!
//! This module owns scheduling, leases, retries, privacy projections,
//! heartbeats, revocation polling, bounded concurrency, and shutdown. Provider
//! reconciliation remains behind [`CanvasSyncProcessor`] so the worker can
//! reuse the canonical Canvas/evidence implementations rather than duplicate
//! their kernels.

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;
use tokio::{sync::watch, task::JoinSet};
use tracing::{error, warn};
use uuid::Uuid;

use crate::{
    canvas_oauth::{
        CanvasOAuthConnection, CanvasOAuthError, CanvasOAuthPlatformPatch, CanvasOAuthProvider,
        CanvasOAuthProviderError, CanvasOAuthRepository, CanvasOAuthSecretVault,
    },
    integration_secret::integration_secret_id_from_ref,
};

pub const CANVAS_SYNC_ROLE: &str = "canvas_sync";
const MAX_RETRY_AFTER_SECONDS: u64 = 86_400;
const MAX_RESULT_STRING_CHARS: usize = 200;
const MAX_ERROR_CODE_CHARS: usize = 120;
const MAX_ERROR_SUMMARY_CHARS: usize = 500;
const MAX_ATTEMPTS: i32 = 8;

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasSyncWorkerConfig {
    pub worker_id: String,
    pub batch_size: usize,
    pub lease_seconds: i64,
    pub job_timeout: Duration,
    pub schedule_limit: usize,
    pub oauth_revocation_limit: usize,
    pub poll_interval: Duration,
    pub portable_enabled: bool,
    pub pilot_organizations: BTreeSet<String>,
}

impl CanvasSyncWorkerConfig {
    pub fn from_env() -> Result<Self, CanvasSyncWorkerConfigError> {
        Self::from_values(&env::vars().collect())
    }

    pub fn from_values(
        values: &BTreeMap<String, String>,
    ) -> Result<Self, CanvasSyncWorkerConfigError> {
        let configured_id = values
            .get("CANVAS_SYNC_WORKER_ID")
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let host = values
            .get("HOSTNAME")
            .or_else(|| values.get("COMPUTERNAME"))
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("canvas-worker");
        let worker_id = configured_id.map(str::to_owned).unwrap_or_else(|| {
            let random = Uuid::new_v4().simple().to_string();
            format!("{host}-{}-{}", std::process::id(), &random[..8])
        });
        Ok(Self {
            worker_id,
            batch_size: parse_usize_floor(values, "CANVAS_SYNC_WORKER_BATCH_SIZE", 10, 1)?,
            lease_seconds: parse_integer(values, "CANVAS_SYNC_WORKER_LEASE_SECONDS", 120)?.max(30),
            job_timeout: Duration::from_secs_f64(
                parse_float(values, "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS", 600.0)?
                    .clamp(30.0, 3_600.0),
            ),
            schedule_limit: parse_usize_floor(values, "CANVAS_SYNC_SCHEDULE_LIMIT", 100, 1)?,
            oauth_revocation_limit: parse_usize_floor(
                values,
                "CANVAS_OAUTH_REVOCATION_BATCH_SIZE",
                25,
                1,
            )?,
            poll_interval: Duration::from_secs_f64(
                parse_float(values, "CANVAS_SYNC_WORKER_POLL_SECONDS", 5.0)?.clamp(0.1, 60.0),
            ),
            portable_enabled: parse_python_bool(
                values.get("CANVAS_PORTABLE_INTEGRATION_ENABLED"),
                false,
            ),
            pilot_organizations: comma_set(values.get("CANVAS_PILOT_ORGANIZATION_IDS")),
        })
    }

    #[must_use]
    pub fn lease_renewal_interval(&self) -> Duration {
        Duration::from_secs_f64((self.lease_seconds as f64 / 3.0).clamp(10.0, 30.0))
    }

    #[must_use]
    pub fn enabled_for(&self, organization_id: &str) -> bool {
        self.portable_enabled && self.pilot_organizations.contains(organization_id)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CanvasSyncWorkerConfigError {
    #[error("invalid numeric Canvas worker configuration: {name}")]
    InvalidNumber { name: &'static str },
}

fn parse_integer(
    values: &BTreeMap<String, String>,
    name: &'static str,
    default: i64,
) -> Result<i64, CanvasSyncWorkerConfigError> {
    values.get(name).map_or(Ok(default), |value| {
        value
            .trim()
            .parse::<i64>()
            .map_err(|_| CanvasSyncWorkerConfigError::InvalidNumber { name })
    })
}

fn parse_usize_floor(
    values: &BTreeMap<String, String>,
    name: &'static str,
    default: i64,
    minimum: i64,
) -> Result<usize, CanvasSyncWorkerConfigError> {
    usize::try_from(parse_integer(values, name, default)?.max(minimum))
        .map_err(|_| CanvasSyncWorkerConfigError::InvalidNumber { name })
}

fn parse_float(
    values: &BTreeMap<String, String>,
    name: &'static str,
    default: f64,
) -> Result<f64, CanvasSyncWorkerConfigError> {
    values.get(name).map_or(Ok(default), |value| {
        let parsed = value
            .trim()
            .parse::<f64>()
            .map_err(|_| CanvasSyncWorkerConfigError::InvalidNumber { name })?;
        if parsed.is_finite() {
            Ok(parsed)
        } else {
            Err(CanvasSyncWorkerConfigError::InvalidNumber { name })
        }
    })
}

fn parse_python_bool(value: Option<&String>, default: bool) -> bool {
    value.map_or(default, |value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes"
        )
    })
}

fn comma_set(value: Option<&String>) -> BTreeSet<String> {
    value
        .map(String::as_str)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanvasSyncTargetType {
    LearnerApplication,
    BackgroundRoster,
    AwardCandidate,
    IssuedDrift,
}

impl CanvasSyncTargetType {
    pub fn from_database(value: &str) -> Option<Self> {
        match value {
            "learner_application" => Some(Self::LearnerApplication),
            "background_roster" => Some(Self::BackgroundRoster),
            "award_candidate" => Some(Self::AwardCandidate),
            "issued_drift" => Some(Self::IssuedDrift),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasSyncTarget {
    pub id: String,
    pub organization_id: String,
    pub platform_id: String,
    pub binding_id: String,
    pub target_type: CanvasSyncTargetType,
    pub logical_key: String,
    pub application_id: Option<String>,
    pub candidate_id: Option<String>,
    pub enabled: bool,
    pub schedule_seconds: i32,
    pub config_version: i32,
    pub metadata: Map<String, Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanvasSyncJobStatus {
    Queued,
    Leased,
    Retry,
    Succeeded,
    DeadLetter,
    Cancelled,
}

impl CanvasSyncJobStatus {
    #[must_use]
    pub const fn as_database(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Leased => "leased",
            Self::Retry => "retry",
            Self::Succeeded => "succeeded",
            Self::DeadLetter => "dead_letter",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn from_database(value: &str) -> Option<Self> {
        match value {
            "queued" => Some(Self::Queued),
            "leased" => Some(Self::Leased),
            "retry" => Some(Self::Retry),
            "succeeded" => Some(Self::Succeeded),
            "dead_letter" => Some(Self::DeadLetter),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasSyncJob {
    pub id: String,
    pub organization_id: String,
    pub target_id: String,
    pub status: CanvasSyncJobStatus,
    pub attempt_count: i32,
    pub max_attempts: i32,
    pub available_at: DateTime<Utc>,
    pub lease_owner: Option<String>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerHeartbeat {
    pub worker_id: String,
    pub started_at: DateTime<Utc>,
    pub phase: &'static str,
    pub leased_jobs: usize,
    pub processor_configured: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CanvasSyncWorkerCycleResult {
    pub scheduled: usize,
    pub leased: usize,
    pub succeeded: usize,
    pub retried: usize,
    pub dead_lettered: usize,
    pub oauth_revocations_succeeded: usize,
    pub oauth_revocations_retried: usize,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CanvasSyncRepositoryError {
    #[error("Canvas synchronization persistence is unavailable")]
    Unavailable,
    #[error("Canvas synchronization persistence returned invalid state")]
    InvalidState,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{summary}")]
pub struct CanvasSyncProcessingError {
    pub code: &'static str,
    pub summary: &'static str,
    pub retryable: bool,
    pub retry_after_seconds: Option<u64>,
}

impl CanvasSyncProcessingError {
    #[must_use]
    pub const fn retryable(code: &'static str, summary: &'static str) -> Self {
        Self {
            code,
            summary,
            retryable: true,
            retry_after_seconds: None,
        }
    }

    #[must_use]
    pub const fn terminal(code: &'static str, summary: &'static str) -> Self {
        Self {
            code,
            summary,
            retryable: false,
            retry_after_seconds: None,
        }
    }
}

#[async_trait]
pub trait CanvasSyncProcessor: Send + Sync {
    fn configured(&self) -> bool;
    async fn process(
        &self,
        target: &CanvasSyncTarget,
    ) -> Result<Map<String, Value>, CanvasSyncProcessingError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobFailure<'a> {
    pub error_code: &'a str,
    pub error_summary: Option<&'a str>,
    pub retry_after_seconds: Option<u64>,
    pub force_dead_letter: bool,
}

#[async_trait]
pub trait CanvasSyncWorkerRepository: Send + Sync {
    async fn upsert_heartbeat(
        &self,
        heartbeat: &WorkerHeartbeat,
    ) -> Result<(), CanvasSyncRepositoryError>;
    async fn enqueue_due(&self, limit: usize) -> Result<usize, CanvasSyncRepositoryError>;
    async fn lease_ready(
        &self,
        worker_id: &str,
        limit: usize,
        lease_seconds: i64,
    ) -> Result<Vec<CanvasSyncJob>, CanvasSyncRepositoryError>;
    async fn target(
        &self,
        organization_id: &str,
        target_id: &str,
    ) -> Result<Option<CanvasSyncTarget>, CanvasSyncRepositoryError>;
    async fn touch_target_heartbeat(
        &self,
        target: &CanvasSyncTarget,
        worker_id: &str,
    ) -> Result<bool, CanvasSyncRepositoryError>;
    async fn validate_target(
        &self,
        target: &CanvasSyncTarget,
    ) -> Result<(), CanvasSyncProcessingError>;
    async fn renew_lease(
        &self,
        job: &CanvasSyncJob,
        worker_id: &str,
        lease_seconds: i64,
    ) -> Result<bool, CanvasSyncRepositoryError>;
    async fn complete_job(
        &self,
        job: &CanvasSyncJob,
        worker_id: &str,
        target_config_version: i32,
        result: &Map<String, Value>,
    ) -> Result<bool, CanvasSyncRepositoryError>;
    async fn fail_job(
        &self,
        job: &CanvasSyncJob,
        worker_id: &str,
        failure: &JobFailure<'_>,
    ) -> Result<Option<CanvasSyncJobStatus>, CanvasSyncRepositoryError>;
}

#[derive(Clone)]
pub struct CanvasSyncWorker {
    repository: Arc<dyn CanvasSyncWorkerRepository>,
    oauth_repository: Arc<dyn CanvasOAuthRepository>,
    oauth_vault: Arc<dyn CanvasOAuthSecretVault>,
    oauth_provider: Arc<dyn CanvasOAuthProvider>,
    processor: Arc<dyn CanvasSyncProcessor>,
    config: CanvasSyncWorkerConfig,
    started_at: DateTime<Utc>,
}

impl fmt::Debug for CanvasSyncWorker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasSyncWorker")
            .field("worker_id", &self.config.worker_id)
            .field("batch_size", &self.config.batch_size)
            .field("processor_configured", &self.processor.configured())
            .finish_non_exhaustive()
    }
}

impl CanvasSyncWorker {
    #[must_use]
    pub fn new(
        repository: Arc<dyn CanvasSyncWorkerRepository>,
        oauth_repository: Arc<dyn CanvasOAuthRepository>,
        oauth_vault: Arc<dyn CanvasOAuthSecretVault>,
        oauth_provider: Arc<dyn CanvasOAuthProvider>,
        processor: Arc<dyn CanvasSyncProcessor>,
        config: CanvasSyncWorkerConfig,
    ) -> Self {
        Self {
            repository,
            oauth_repository,
            oauth_vault,
            oauth_provider,
            processor,
            config,
            started_at: Utc::now(),
        }
    }

    pub async fn run_cycle(
        &self,
    ) -> Result<CanvasSyncWorkerCycleResult, CanvasSyncRepositoryError> {
        self.heartbeat("scheduling", 0).await?;
        let (oauth_revocations_succeeded, oauth_revocations_retried) =
            self.process_oauth_revocations().await;
        let scheduled = self
            .repository
            .enqueue_due(self.config.schedule_limit)
            .await?;
        let leased = self
            .repository
            .lease_ready(
                &self.config.worker_id,
                self.config.batch_size,
                self.config.lease_seconds,
            )
            .await?;
        self.heartbeat(
            if leased.is_empty() {
                "idle"
            } else {
                "processing"
            },
            leased.len(),
        )
        .await?;

        let mut tasks = JoinSet::new();
        for job in leased.iter().cloned() {
            let worker = self.clone();
            tasks.spawn(async move {
                let job_id = job.id.clone();
                (job_id, worker.process_job(job).await)
            });
        }
        let mut result = CanvasSyncWorkerCycleResult {
            scheduled,
            leased: leased.len(),
            oauth_revocations_succeeded,
            oauth_revocations_retried,
            ..CanvasSyncWorkerCycleResult::default()
        };
        while let Some(outcome) = tasks.join_next().await {
            match outcome {
                Ok((_, Ok(CanvasSyncJobStatus::Succeeded))) => result.succeeded += 1,
                Ok((_, Ok(CanvasSyncJobStatus::Retry))) => result.retried += 1,
                Ok((_, Ok(CanvasSyncJobStatus::DeadLetter))) => result.dead_lettered += 1,
                Ok((_, Ok(_))) => {}
                Ok((job_id, Err(error))) => {
                    error!(
                        job_id,
                        exception_class = error.class(),
                        "Canvas sync job escaped outcome handling"
                    );
                }
                Err(error) => {
                    error!(
                        task_cancelled = error.is_cancelled(),
                        task_panicked = error.is_panic(),
                        "Canvas sync job task failed"
                    );
                }
            }
        }
        self.heartbeat("idle", 0).await?;
        Ok(result)
    }

    pub async fn run_loop(
        &self,
        mut stop: watch::Receiver<bool>,
    ) -> Result<(), CanvasSyncRepositoryError> {
        loop {
            if *stop.borrow() {
                return Ok(());
            }
            if let Err(error) = self.run_cycle().await {
                error!(
                    exception_class = error.class(),
                    "Canvas sync worker cycle failed"
                );
            }
            tokio::select! {
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        return Ok(());
                    }
                }
                () = tokio::time::sleep(self.config.poll_interval) => {}
            }
        }
    }

    async fn heartbeat(
        &self,
        phase: &'static str,
        leased_jobs: usize,
    ) -> Result<(), CanvasSyncRepositoryError> {
        self.repository
            .upsert_heartbeat(&WorkerHeartbeat {
                worker_id: self.config.worker_id.clone(),
                started_at: self.started_at,
                phase,
                leased_jobs,
                processor_configured: self.processor.configured(),
            })
            .await
    }

    async fn process_job(
        &self,
        job: CanvasSyncJob,
    ) -> Result<CanvasSyncJobStatus, EscapedJobError> {
        let Some(mut target) = self
            .repository
            .target(&job.organization_id, &job.target_id)
            .await?
        else {
            return self
                .persist_failure(
                    &job,
                    JobFailure {
                        error_code: "canvas_sync_target_not_found",
                        error_summary: Some("Canvas synchronization target is unavailable"),
                        retry_after_seconds: None,
                        force_dead_letter: true,
                    },
                )
                .await;
        };
        if !self
            .repository
            .touch_target_heartbeat(&target, &self.config.worker_id)
            .await?
        {
            if let Some(current) = self
                .repository
                .target(&job.organization_id, &job.target_id)
                .await?
            {
                target = current;
            }
        }

        let evaluation = async {
            if self.config.enabled_for(&target.organization_id) {
                self.repository.validate_target(&target).await?;
            } else {
                // Closed rollout is intentionally evaluated by the processor
                // before any target/provider validation reads.
            }
            self.processor.process(&target).await
        };
        let processing = tokio::time::timeout(self.config.job_timeout, evaluation);
        tokio::pin!(processing);
        let mut lease_maintenance_active = true;
        let outcome = loop {
            tokio::select! {
                outcome = &mut processing => break outcome,
                () = tokio::time::sleep(self.config.lease_renewal_interval()), if lease_maintenance_active => {
                    lease_maintenance_active = self.repository.renew_lease(
                        &job,
                        &self.config.worker_id,
                        self.config.lease_seconds,
                    ).await?;
                    if lease_maintenance_active {
                        let _ = self.repository.touch_target_heartbeat(
                            &target,
                            &self.config.worker_id,
                        ).await?;
                        self.heartbeat("processing", 1).await?;
                    }
                }
            }
        };
        let status = match outcome {
            Err(_) => {
                self.persist_failure(
                    &job,
                    JobFailure {
                        error_code: "canvas_sync_deadline_exceeded",
                        error_summary: Some(
                            "Canvas synchronization exceeded its wall-clock deadline",
                        ),
                        retry_after_seconds: None,
                        force_dead_letter: false,
                    },
                )
                .await
            }
            Ok(Err(processing)) => {
                self.persist_failure(
                    &job,
                    JobFailure {
                        error_code: processing.code,
                        error_summary: Some(processing.summary),
                        retry_after_seconds: processing.retry_after_seconds,
                        force_dead_letter: !processing.retryable,
                    },
                )
                .await
            }
            Ok(Ok(result)) => {
                if [
                    "credential_id",
                    "issued_credential_id",
                    "signed_credential",
                    "credential_jwt",
                ]
                .iter()
                .any(|key| result.contains_key(*key))
                {
                    self.persist_failure(
                        &job,
                        JobFailure {
                            error_code: "canvas_background_signing_forbidden",
                            error_summary: Some(
                                "Canvas synchronization attempted to return a signed credential",
                            ),
                            retry_after_seconds: None,
                            force_dead_letter: true,
                        },
                    )
                    .await
                } else {
                    let safe = safe_result(&result);
                    self.repository
                        .complete_job(&job, &self.config.worker_id, target.config_version, &safe)
                        .await?
                        .then_some(CanvasSyncJobStatus::Succeeded)
                        .ok_or(EscapedJobError::StaleLease)
                }
            }
        };
        status
    }

    async fn persist_failure(
        &self,
        job: &CanvasSyncJob,
        mut failure: JobFailure<'_>,
    ) -> Result<CanvasSyncJobStatus, EscapedJobError> {
        let code = bounded_chars(failure.error_code, MAX_ERROR_CODE_CHARS);
        let summary = failure
            .error_summary
            .map(collapse_whitespace)
            .map(|value| bounded_chars(&value, MAX_ERROR_SUMMARY_CHARS));
        failure.error_code = &code;
        failure.error_summary = summary.as_deref();
        self.repository
            .fail_job(job, &self.config.worker_id, &failure)
            .await?
            .ok_or(EscapedJobError::StaleLease)
    }

    async fn process_oauth_revocations(&self) -> (usize, usize) {
        let due = match self
            .oauth_repository
            .due_revocations(self.config.oauth_revocation_limit)
            .await
        {
            Ok(due) => due,
            Err(error) => {
                warn!(
                    exception_class = oauth_error_class(&error),
                    "Canvas OAuth revocation queue read failed"
                );
                return (0, 0);
            }
        };
        let mut succeeded = 0;
        let mut retried = 0;
        for pending in due {
            if let Err(error) = self.heartbeat("oauth_revocation", 0).await {
                warn!(
                    exception_class = error.class(),
                    "Canvas OAuth revocation heartbeat failed"
                );
            }
            let lease_seconds = self.config.lease_seconds.clamp(30, 300);
            let connection = match self
                .oauth_repository
                .acquire_due_revocation(
                    &pending.organization_id,
                    &pending.platform_id,
                    &self.config.worker_id,
                    lease_seconds,
                )
                .await
            {
                Ok(Some(connection)) => connection,
                Ok(None) => continue,
                Err(error) => {
                    warn!(
                        exception_class = oauth_error_class(&error),
                        "Canvas OAuth revocation lease failed"
                    );
                    continue;
                }
            };
            match self.revoke_connection(&connection).await {
                Ok(()) => succeeded += 1,
                Err(()) => retried += 1,
            }
        }
        (succeeded, retried)
    }

    async fn revoke_connection(&self, connection: &CanvasOAuthConnection) -> Result<(), ()> {
        let access_id = connection
            .access_token_secret_ref
            .as_deref()
            .and_then(|value| integration_secret_id_from_ref(&connection.organization_id, value));
        let refresh_id = connection
            .refresh_token_secret_ref
            .as_deref()
            .and_then(|value| integration_secret_id_from_ref(&connection.organization_id, value));
        let access_token = match access_id {
            Some(id) => {
                self.oauth_vault
                    .value(&connection.organization_id, id)
                    .await
            }
            None => Ok(None),
        };
        let revoke_result = match access_token {
            Ok(Some(token)) if !connection.canvas_base_url.trim().is_empty() => {
                self.oauth_provider
                    .revoke(&connection.canvas_base_url, &token)
                    .await
            }
            Ok(_) | Err(_) => Err(CanvasOAuthProviderError::RevocationRejected),
        };
        if let Err(error) = revoke_result {
            let code = oauth_revocation_error_code(&error);
            let delay = oauth_revocation_delay_seconds(
                connection.revoke_retry_count,
                provider_retry_after(&error),
            );
            let retry_at = Utc::now() + TimeDelta::seconds(i64::try_from(delay).unwrap_or(86_400));
            let rescheduled = self
                .oauth_repository
                .reschedule_revocation(
                    &connection.organization_id,
                    &connection.platform_id,
                    &self.config.worker_id,
                    retry_at,
                    code,
                )
                .await
                .unwrap_or(false);
            if rescheduled {
                warn!(
                    organization_id = %connection.organization_id,
                    platform_id = %connection.platform_id,
                    stable_error_code = code,
                    "Canvas OAuth revocation retry scheduled"
                );
            }
            return Err(());
        }
        let secret_ids = [access_id, refresh_id]
            .into_iter()
            .flatten()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let deleted = self
            .oauth_repository
            .complete_revocation(
                &connection.organization_id,
                &connection.platform_id,
                &self.config.worker_id,
                &secret_ids,
            )
            .await
            .unwrap_or(false);
        if !deleted {
            return Err(());
        }
        if let Err(error) = self
            .oauth_repository
            .patch_platform(
                &connection.organization_id,
                &connection.platform_id,
                connection.platform_config_version,
                CanvasOAuthPlatformPatch::Disconnected,
            )
            .await
        {
            warn!(
                organization_id = %connection.organization_id,
                platform_id = %connection.platform_id,
                exception_class = oauth_error_class(&error),
                "Canvas OAuth disconnected projection failed"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum EscapedJobError {
    #[error(transparent)]
    Repository(#[from] CanvasSyncRepositoryError),
    #[error("Canvas sync lease was no longer current")]
    StaleLease,
}

impl CanvasSyncRepositoryError {
    const fn class(&self) -> &'static str {
        match self {
            Self::Unavailable => "CanvasSyncRepositoryUnavailable",
            Self::InvalidState => "CanvasSyncRepositoryInvalidState",
        }
    }
}

impl EscapedJobError {
    const fn class(&self) -> &'static str {
        match self {
            Self::Repository(error) => error.class(),
            Self::StaleLease => "CanvasSyncStaleLease",
        }
    }
}

fn oauth_error_class(error: &CanvasOAuthError) -> &'static str {
    match error {
        CanvasOAuthError::RepositoryUnavailable => "CanvasOAuthRepositoryUnavailable",
        CanvasOAuthError::SecretUnavailable => "CanvasOAuthSecretUnavailable",
        _ => "CanvasOAuthError",
    }
}

#[must_use]
pub fn safe_result(input: &Map<String, Value>) -> Map<String, Value> {
    const ALLOWED: &[&str] = &[
        "application_id",
        "candidate_id",
        "candidate_state",
        "config_version",
        "requirements_checked",
        "facts_observed",
        "facts_changed",
        "negative_observations",
        "review_created",
        "identity_link_required",
        "candidates_seen",
        "pending_claim",
        "observations_written",
        "facts_created",
        "facts_reused",
        "policy_allowed",
        "no_change",
    ];
    input
        .iter()
        .filter(|(key, _)| ALLOWED.contains(&key.as_str()))
        .filter_map(|(key, value)| {
            let value = match value {
                Value::Bool(value) => Value::Bool(*value),
                Value::Null => Value::Null,
                Value::Number(value) if value.is_i64() => {
                    Value::from(value.as_i64().unwrap_or_default().max(0))
                }
                Value::Number(value) if value.is_u64() => Value::from(value.as_u64()),
                Value::String(value) => {
                    Value::String(bounded_chars(value, MAX_RESULT_STRING_CHARS))
                }
                _ => return None,
            };
            Some((key.clone(), value))
        })
        .collect()
}

#[must_use]
pub fn retry_after_seconds(value: &str, now: DateTime<Utc>) -> Option<u64> {
    let normalized = value.trim();
    if let Ok(seconds) = normalized.parse::<i64>() {
        return Some(seconds.max(0).cast_unsigned().min(MAX_RETRY_AFTER_SECONDS));
    }
    let retry_at = httpdate::parse_http_date(normalized).ok()?;
    let retry_at: DateTime<Utc> = retry_at.into();
    Some(
        (retry_at - now)
            .num_seconds()
            .max(0)
            .cast_unsigned()
            .min(MAX_RETRY_AFTER_SECONDS),
    )
}

#[must_use]
pub fn job_retry_delay_seconds(attempt_count: i32, retry_after: Option<u64>, jitter: u64) -> u64 {
    let exponent = attempt_count.saturating_sub(1).clamp(0, 10) as u32;
    let base = (15_u64.saturating_mul(2_u64.saturating_pow(exponent))).min(3_600);
    let bounded_jitter = jitter.min(base / 3);
    (base + bounded_jitter).max(retry_after.unwrap_or_default().min(MAX_RETRY_AFTER_SECONDS))
}

/// Normalize the durable background-roster cursor and calculate its next
/// stable window without retaining any roster PII.
#[must_use]
pub fn roster_cursor_window(cursor: i64, size: usize, batch_size: usize) -> (usize, usize) {
    if size == 0 {
        return (0, 0);
    }
    let normalized = usize::try_from(cursor)
        .ok()
        .filter(|cursor| *cursor < size)
        .unwrap_or(0);
    let processed = batch_size.max(1).min(size.saturating_sub(normalized));
    let advanced = normalized.saturating_add(processed);
    let next = if advanced >= size { 0 } else { advanced };
    (normalized, next)
}

#[must_use]
pub fn oauth_revocation_delay_seconds(retry_count: i32, retry_after: Option<u64>) -> u64 {
    let exponent = retry_count.clamp(0, 11) as u32;
    let base = (30_u64.saturating_mul(2_u64.saturating_pow(exponent))).min(21_600);
    let jitter = rand::rng().random_range(0..=(base / 4));
    (base + jitter)
        .max(retry_after.unwrap_or_default().min(MAX_RETRY_AFTER_SECONDS))
        .min(MAX_RETRY_AFTER_SECONDS)
}

fn provider_retry_after(error: &CanvasOAuthProviderError) -> Option<u64> {
    match error {
        CanvasOAuthProviderError::Failed {
            retry_after_seconds,
        } => *retry_after_seconds,
        CanvasOAuthProviderError::RefreshRejected => None,
        CanvasOAuthProviderError::Timeout => None,
        CanvasOAuthProviderError::RevocationRejected => None,
    }
}

fn oauth_revocation_error_code(error: &CanvasOAuthProviderError) -> &'static str {
    match error {
        CanvasOAuthProviderError::Failed {
            retry_after_seconds: Some(_),
        } => "canvas_oauth_revoke_rate_limited",
        CanvasOAuthProviderError::RefreshRejected => "canvas_oauth_revoke_rejected",
        CanvasOAuthProviderError::RevocationRejected => "canvas_oauth_revoke_rejected",
        CanvasOAuthProviderError::Timeout => "canvas_oauth_revoke_timeout",
        CanvasOAuthProviderError::Failed { .. } => "canvas_oauth_revoke_unavailable",
    }
}

fn bounded_chars(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}

fn collapse_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(crate) fn random_job_retry_delay_seconds(attempt_count: i32, retry_after: Option<u64>) -> u64 {
    let exponent = attempt_count.saturating_sub(1).clamp(0, 10) as u32;
    let base = (15_u64.saturating_mul(2_u64.saturating_pow(exponent))).min(3_600);
    let jitter = rand::rng().random_range(0..=(base / 3));
    job_retry_delay_seconds(attempt_count, retry_after, jitter)
}

pub(crate) const fn maximum_attempts() -> i32 {
    MAX_ATTEMPTS
}
