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
    future::Future,
    panic::AssertUnwindSafe,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use futures_util::{stream::FuturesUnordered, FutureExt, StreamExt};
use mmf_config::numeric_config::{parse_bounded_python_config_float, PythonConfigInteger};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{value::RawValue, Map, Value};
use thiserror::Error;
use tokio::sync::watch;
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
    pub batch_size: PythonConfigInteger,
    pub lease_seconds: PythonConfigInteger,
    pub job_timeout: Duration,
    pub schedule_limit: PythonConfigInteger,
    pub oauth_revocation_limit: PythonConfigInteger,
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
            .filter(|value| !value.is_empty());
        let worker_id = if let Some(identity) = configured_id {
            identity.to_owned()
        } else {
            // Match socket.gethostname(), not a mutable HOSTNAME override.
            let host =
                hostname::get().map_err(|_| CanvasSyncWorkerConfigError::HostNameUnavailable)?;
            let random = Uuid::new_v4().simple().to_string();
            format!(
                "{}-{}-{}",
                host.to_string_lossy(),
                std::process::id(),
                &random[..8]
            )
        };
        Ok(Self {
            worker_id,
            batch_size: parse_integer_floor(values, "CANVAS_SYNC_WORKER_BATCH_SIZE", "10", 1)?,
            lease_seconds: parse_integer_floor(
                values,
                "CANVAS_SYNC_WORKER_LEASE_SECONDS",
                "120",
                30,
            )?,
            job_timeout: parse_duration(
                values,
                "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS",
                "600",
                30.0,
                3_600.0,
            )?,
            schedule_limit: parse_integer_floor(values, "CANVAS_SYNC_SCHEDULE_LIMIT", "100", 1)?,
            oauth_revocation_limit: parse_integer_floor(
                values,
                "CANVAS_OAUTH_REVOCATION_BATCH_SIZE",
                "25",
                1,
            )?,
            poll_interval: parse_duration(
                values,
                "CANVAS_SYNC_WORKER_POLL_SECONDS",
                "5",
                0.1,
                60.0,
            )?,
            portable_enabled: parse_python_bool(
                values.get("CANVAS_PORTABLE_INTEGRATION_ENABLED"),
                false,
            ),
            pilot_organizations: comma_set(values.get("CANVAS_PILOT_ORGANIZATION_IDS")),
        })
    }

    #[must_use]
    pub fn lease_renewal_interval(&self) -> Duration {
        // Apply this derived interval's bounds before machine conversion.
        // Invalid lease timestamps fail at leasing, before job renewal starts.
        let seconds = self
            .lease_seconds
            .clone()
            .max(30_u64.into())
            .min(90_u64.into())
            .to_u64()
            .expect("bounded lease renewal interval");
        Duration::from_secs_f64(seconds as f64 / 3.0)
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
    #[error("Canvas worker host identity is unavailable")]
    HostNameUnavailable,
}

fn parse_integer_floor(
    values: &BTreeMap<String, String>,
    name: &'static str,
    default: &str,
    minimum: u64,
) -> Result<PythonConfigInteger, CanvasSyncWorkerConfigError> {
    values
        .get(name)
        .map(String::as_str)
        .unwrap_or(default)
        .parse::<PythonConfigInteger>()
        .map(|value| value.max(minimum.into()))
        .map_err(|_| CanvasSyncWorkerConfigError::InvalidNumber { name })
}

fn parse_duration(
    values: &BTreeMap<String, String>,
    name: &'static str,
    default: &str,
    minimum: f64,
    maximum: f64,
) -> Result<Duration, CanvasSyncWorkerConfigError> {
    parse_bounded_python_config_float(
        values.get(name).map(String::as_str).unwrap_or(default),
        minimum,
        maximum,
    )
    .map(Duration::from_secs_f64)
    .map_err(|_| CanvasSyncWorkerConfigError::InvalidNumber { name })
}

fn parse_python_bool(value: Option<&String>, default: bool) -> bool {
    value.map_or(default, |value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
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
    pub target_config_version: i32,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OAuthRevocationOutcome {
    Succeeded,
    Retried,
    OwnerFenceLost,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CanvasSyncRepositoryError {
    #[error("Canvas synchronization persistence is unavailable")]
    Unavailable,
    #[error("Canvas synchronization persistence returned invalid state")]
    InvalidState,
    #[error("Canvas synchronization integer exceeds the SQL consumer range")]
    IntegerSqlRange,
    #[error("Canvas synchronization lease exceeds the time consumer range")]
    DurationRange,
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
        lease: &crate::canvas_sync_lease::CanvasSyncLease,
    ) -> Result<CanvasSyncResult, CanvasSyncProcessingError>;
}

/// Lossless JSON at the processor-to-durable-result boundary. Unlike `Value`,
/// this retains integer lexemes outside i64/u64 without enabling arbitrary
/// precision (and changing serialization) for the shared crypto dependency tree.
pub type CanvasSyncResult = BTreeMap<String, Box<RawValue>>;

/// Convert native, already-typed processor fields without changing their JSON
/// types. JSON-facing processors should deserialize `CanvasSyncResult` directly
/// from the original bytes so large integers never pass through `Value`.
pub fn canvas_sync_result(
    fields: Map<String, Value>,
) -> Result<CanvasSyncResult, CanvasSyncProcessingError> {
    fields
        .into_iter()
        .map(|(key, value)| serde_json::value::to_raw_value(&value).map(|raw| (key, raw)))
        .collect::<Result<_, _>>()
        .map_err(|_| {
            CanvasSyncProcessingError::terminal(
                "canvas_sync_result_invalid",
                "Canvas processor result could not be serialized",
            )
        })
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
    async fn enqueue_due(
        &self,
        limit: &PythonConfigInteger,
    ) -> Result<usize, CanvasSyncRepositoryError>;
    async fn lease_ready(
        &self,
        worker_id: &str,
        limit: &PythonConfigInteger,
        lease_seconds: &PythonConfigInteger,
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
        lease_seconds: &PythonConfigInteger,
    ) -> Result<bool, CanvasSyncRepositoryError>;
    async fn complete_job(
        &self,
        job: &CanvasSyncJob,
        worker_id: &str,
        target_config_version: i32,
        result: &CanvasSyncResult,
    ) -> Result<bool, CanvasSyncRepositoryError>;
    async fn fail_job(
        &self,
        job: &CanvasSyncJob,
        worker_id: &str,
        failure: &JobFailure<'_>,
        target_config_version: i32,
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
            .enqueue_due(&self.config.schedule_limit)
            .await?;
        let leased = self
            .repository
            .lease_ready(
                &self.config.worker_id,
                &self.config.batch_size,
                &self.config.lease_seconds,
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

        // Own concurrent job futures in this cycle, rather than spawning
        // children whose cancellation can outlive the parent. Dropping the
        // cycle synchronously drops processor and renewal futures together.
        // Keep per-job panic isolation: one failed job must not cancel siblings.
        let mut tasks = FuturesUnordered::new();
        for job in leased.iter().cloned() {
            let worker = self.clone();
            tasks.push(
                AssertUnwindSafe(async move {
                    let job_id = job.id.clone();
                    (job_id, worker.process_job(job).await)
                })
                .catch_unwind(),
            );
        }
        let mut result = CanvasSyncWorkerCycleResult {
            scheduled,
            leased: leased.len(),
            oauth_revocations_succeeded,
            oauth_revocations_retried,
            ..CanvasSyncWorkerCycleResult::default()
        };
        while let Some(outcome) = tasks.next().await {
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
                Err(_) => {
                    error!(
                        task_cancelled = false,
                        task_panicked = true,
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
            let Some(current_target) = self
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
            // Reconcile against the canonical target. The leased job's
            // generation remains the outcome fence, but validation must see a
            // newly disabled or reconfigured target instead of abandoning the
            // lease without a durable terminal outcome.
            target = current_target;
        }

        let lease =
            crate::canvas_sync_lease::CanvasSyncLease::from_job(&job, &self.config.worker_id)?;
        let evaluation = async {
            if self.config.enabled_for(&target.organization_id) {
                self.repository.validate_target(&target).await?;
            } else {
                // Closed rollout is intentionally evaluated by the processor
                // before any target/provider validation reads.
            }
            self.processor.process(&target, &lease).await
        };
        let (outcome, renewal_error) = await_with_lease_renewal(
            tokio::time::timeout(self.config.job_timeout, evaluation),
            self.config.lease_renewal_interval(),
            || async {
                let renewed = self
                    .repository
                    .renew_lease(&job, &self.config.worker_id, &self.config.lease_seconds)
                    .await?;
                if !renewed {
                    return Ok(false);
                }
                let target_is_current = self
                    .repository
                    .touch_target_heartbeat(&target, &self.config.worker_id)
                    .await?;
                if !target_is_current {
                    // Mirror the frozen worker's reload-on-target-CAS-loss
                    // behavior. Side-effect repositories independently fence
                    // the captured generation, so a live canonical target may
                    // be reconciled without dropping the durable job lease.
                    let target_exists = self
                        .repository
                        .target(&job.organization_id, &job.target_id)
                        .await?
                        .is_some();
                    if !target_exists {
                        return Ok(false);
                    }
                    // A rejected old-generation target heartbeat must not
                    // suppress liveness for the still-owned, renewed job.
                    // Never write that heartbeat into the newer target.
                }
                self.heartbeat("processing", 1).await?;
                Ok(true)
            },
        )
        .await?;
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
                        .complete_job(
                            &job,
                            &self.config.worker_id,
                            job.target_config_version,
                            &safe,
                        )
                        .await
                        .map_err(EscapedJobError::from)
                        .and_then(|completed| {
                            completed
                                .then_some(CanvasSyncJobStatus::Succeeded)
                                .ok_or(EscapedJobError::StaleLease)
                        })
                }
            }
        };
        if let Some(error) = renewal_error {
            // Match the frozen handler's error observation AFTER its fenced
            // durable outcome. A repository error is not proof of lease loss.
            // Keep any secondary persistence failure observable without hiding
            // the original renewal failure or changing cycle accounting.
            if let Err(persistence_error) = &status {
                warn!(
                    job_id = %job.id,
                    exception_class = persistence_error.class(),
                    "Canvas outcome persistence failed after renewal error"
                );
            }
            Err(error.into())
        } else {
            status
        }
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
            .fail_job(
                job,
                &self.config.worker_id,
                &failure,
                job.target_config_version,
            )
            .await?
            .ok_or(EscapedJobError::StaleLease)
    }

    async fn process_oauth_revocations(&self) -> (usize, usize) {
        let due = match self
            .oauth_repository
            .due_revocations(
                self.config
                    .oauth_revocation_limit
                    .clone()
                    .max(1_u64.into())
                    .min(500_u64.into())
                    .to_usize()
                    .expect("bounded OAuth revocation limit"),
            )
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
            let lease_seconds = self
                .config
                .lease_seconds
                .clone()
                .max(30_u64.into())
                .min(300_u64.into())
                .to_i64()
                .expect("bounded OAuth lease duration");
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
                OAuthRevocationOutcome::Succeeded => succeeded += 1,
                OAuthRevocationOutcome::Retried => retried += 1,
                OAuthRevocationOutcome::OwnerFenceLost => {}
            }
        }
        (succeeded, retried)
    }

    async fn revoke_connection(
        &self,
        connection: &CanvasOAuthConnection,
    ) -> OAuthRevocationOutcome {
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
                .await;
            if matches!(rescheduled, Ok(true)) {
                warn!(
                    organization_id = %connection.organization_id,
                    platform_id = %connection.platform_id,
                    stable_error_code = code,
                    "Canvas OAuth revocation retry scheduled"
                );
            }
            return if matches!(rescheduled, Ok(true)) {
                OAuthRevocationOutcome::Retried
            } else {
                OAuthRevocationOutcome::OwnerFenceLost
            };
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
            .await;
        if !matches!(deleted, Ok(true)) {
            return OAuthRevocationOutcome::OwnerFenceLost;
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
        OAuthRevocationOutcome::Succeeded
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
            Self::IntegerSqlRange => "CanvasSyncIntegerSqlRange",
            Self::DurationRange => "CanvasSyncDurationRange",
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
pub fn safe_result(input: &CanvasSyncResult) -> CanvasSyncResult {
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
            let raw = value.get().trim();
            let value = if matches!(raw, "true" | "false" | "null") {
                value.clone()
            } else if raw.starts_with('"') {
                let text: String = serde_json::from_str(raw).ok()?;
                serde_json::value::to_raw_value(&bounded_chars(&text, MAX_RESULT_STRING_CHARS))
                    .ok()?
            } else if !raw.is_empty()
                && raw
                    .strip_prefix('-')
                    .unwrap_or(raw)
                    .bytes()
                    .all(|byte| byte.is_ascii_digit())
            {
                if raw.starts_with('-') {
                    RawValue::from_string("0".to_owned()).expect("zero is valid JSON")
                } else {
                    value.clone()
                }
            } else {
                // Floats (including integral/exponent forms), arrays and
                // objects are omitted, not coerced to counters or text.
                return None;
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
        }
        | CanvasOAuthProviderError::RateLimited {
            retry_after_seconds,
        } => *retry_after_seconds,
        CanvasOAuthProviderError::RefreshRejected => None,
        CanvasOAuthProviderError::Timeout => None,
        CanvasOAuthProviderError::RevocationRejected => None,
    }
}

fn oauth_revocation_error_code(error: &CanvasOAuthProviderError) -> &'static str {
    match error {
        CanvasOAuthProviderError::RateLimited { .. } => "canvas_oauth_revoke_rate_limited",
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

async fn await_with_lease_renewal<F, R, RF>(
    processing: F,
    interval: Duration,
    mut renew: R,
) -> Result<(F::Output, Option<CanvasSyncRepositoryError>), EscapedJobError>
where
    F: Future,
    R: FnMut() -> RF,
    RF: Future<Output = Result<bool, CanvasSyncRepositoryError>>,
{
    tokio::pin!(processing);
    let renewal = async {
        loop {
            tokio::time::sleep(interval).await;
            match renew().await {
                Ok(true) => {}
                Ok(false) => return EscapedJobError::StaleLease,
                Err(error) => return error.into(),
            }
        }
    };
    // Poll both owned futures throughout renewal I/O. Awaiting renewal inside
    // a select branch would suspend processing and its wall-clock deadline.
    // Definite lease loss cancels processing. Operational renewal failure stops
    // only renewal: let the already-bounded processor finish, then surface the
    // failure after its durable, independently lease-fenced outcome. Both futures
    // remain parent-owned, so external cancellation never becomes a renewal error.
    tokio::select! {
        // If both branches are ready, observe an already-failed maintainer
        // before accepting the result; do not randomly lose its error.
        biased;
        error = renewal => match error {
            EscapedJobError::StaleLease => Err(EscapedJobError::StaleLease),
            EscapedJobError::Repository(error) => Ok((processing.await, Some(error))),
        },
        outcome = &mut processing => Ok((outcome, None)),
    }
}

#[cfg(test)]
mod lease_tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    use super::*;

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    async fn assert_progress_during_blocked_renewal(deadline: bool, ready_renewal_error: bool) {
        let processing_dropped = Arc::new(AtomicBool::new(false));
        let renewal_dropped = Arc::new(AtomicBool::new(false));
        let processing_guard = DropSignal(processing_dropped.clone());
        let release = Arc::new(tokio::sync::Notify::new());
        let processing_release = release.clone();
        let renewal_entered = tokio::sync::Notify::new();
        let renewal_release = tokio::sync::Notify::new();
        let processing = async move {
            let _guard = processing_guard;
            processing_release.notified().await;
            if deadline {
                tokio::time::timeout(Duration::from_millis(1), std::future::pending::<u8>()).await
            } else {
                Ok(42)
            }
        };
        let mut owned = Box::pin(await_with_lease_renewal(
            processing,
            Duration::from_millis(1),
            || {
                let guard = DropSignal(renewal_dropped.clone());
                let entered = &renewal_entered;
                let released = &renewal_release;
                async move {
                    let _guard = guard;
                    entered.notify_one();
                    released.notified().await;
                    Err(CanvasSyncRepositoryError::Unavailable)
                }
            },
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::select! {
                _ = &mut owned => panic!("work finished before the renewal was blocked"),
                () = renewal_entered.notified() => {}
            }
        })
        .await
        .expect("renewal must reach the controlled pending operation");
        release.notify_one();
        if ready_renewal_error {
            renewal_release.notify_one();
        }
        let (result, renewal_error) = tokio::time::timeout(Duration::from_millis(100), &mut owned)
            .await
            .expect("blocked renewal stalled processor completion or deadline")
            .unwrap();
        assert_eq!(
            renewal_error,
            ready_renewal_error.then_some(CanvasSyncRepositoryError::Unavailable)
        );
        if deadline {
            assert!(result.is_err(), "processing deadline must still expire");
        } else {
            assert_eq!(result.unwrap(), 42);
        }
        assert!(processing_dropped.load(Ordering::SeqCst));
        assert!(
            renewal_dropped.load(Ordering::SeqCst),
            "no pending renewal may escape"
        );
    }

    #[tokio::test]
    async fn completed_processing_is_not_stalled_by_pending_renewal() {
        assert_progress_during_blocked_renewal(false, false).await;
    }

    #[tokio::test]
    async fn processing_deadline_is_not_stalled_by_pending_renewal() {
        assert_progress_during_blocked_renewal(true, false).await;
    }

    #[tokio::test]
    async fn already_ready_renewal_error_is_not_lost_to_ready_processing() {
        assert_progress_during_blocked_renewal(false, true).await;
    }

    async fn assert_processing_after_renewal_error(deadline: bool, cancel: bool) {
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropSignal(dropped.clone());
        let release = tokio::sync::Notify::new();
        let failed = tokio::sync::Notify::new();
        let processing = async {
            let _guard = guard;
            release.notified().await;
            if deadline {
                tokio::time::timeout(Duration::from_millis(1), std::future::pending::<u8>()).await
            } else {
                Ok(42)
            }
        };
        let mut owned = Box::pin(await_with_lease_renewal(
            processing,
            Duration::from_millis(1),
            || async {
                failed.notify_one();
                Err(CanvasSyncRepositoryError::Unavailable)
            },
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::select! {
                _ = &mut owned => panic!("renewal failure discarded processing"),
                () = failed.notified() => {}
            }
        })
        .await
        .unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(20), &mut owned)
            .await
            .is_err());
        assert!(!dropped.load(Ordering::SeqCst));
        if cancel {
            drop(owned);
            assert!(
                dropped.load(Ordering::SeqCst),
                "cancellation must synchronously clean processing"
            );
            return;
        }
        release.notify_one();
        let (result, renewal_error) = tokio::time::timeout(Duration::from_secs(1), owned)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            renewal_error,
            Some(CanvasSyncRepositoryError::Unavailable)
        ));
        if deadline {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), 42);
        }
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn renewal_error_preserves_later_processing_and_error_class() {
        assert_processing_after_renewal_error(false, false).await;
    }

    #[tokio::test]
    async fn renewal_error_preserves_processing_deadline() {
        assert_processing_after_renewal_error(true, false).await;
    }

    #[tokio::test]
    async fn cancellation_after_renewal_error_cleans_processing_immediately() {
        assert_processing_after_renewal_error(false, true).await;
    }

    #[tokio::test]
    async fn lease_loss_immediately_drops_processing_future() {
        let dropped = Arc::new(AtomicBool::new(false));
        let signal = DropSignal(dropped.clone());
        let processing = async move {
            let _signal = signal;
            std::future::pending::<()>().await;
        };
        let result =
            await_with_lease_renewal(processing, Duration::from_millis(1), || async { Ok(false) })
                .await;
        assert!(matches!(result, Err(EscapedJobError::StaleLease)));
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn target_generation_loss_after_job_renewal_drops_processing_future() {
        let dropped = Arc::new(AtomicBool::new(false));
        let renewal_succeeded = Arc::new(AtomicBool::new(false));
        let signal = DropSignal(dropped.clone());
        let processing = async move {
            let _signal = signal;
            std::future::pending::<()>().await;
        };
        let result = await_with_lease_renewal(processing, Duration::from_millis(1), || {
            let renewal_succeeded = renewal_succeeded.clone();
            async move {
                // The durable job lease renewed, but the target generation
                // heartbeat CAS reported that this target is no longer current.
                renewal_succeeded.store(true, Ordering::SeqCst);
                Ok(false)
            }
        })
        .await;
        assert!(renewal_succeeded.load(Ordering::SeqCst));
        assert!(matches!(result, Err(EscapedJobError::StaleLease)));
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn canonical_target_snapshot_can_be_newer_or_disabled_than_the_lease_snapshot() {
        let now = Utc::now();
        let job = CanvasSyncJob {
            id: "job".into(),
            organization_id: "org".into(),
            target_id: "target".into(),
            target_config_version: 3,
            status: CanvasSyncJobStatus::Leased,
            attempt_count: 1,
            max_attempts: 8,
            available_at: now,
            lease_owner: Some("worker".into()),
            lease_expires_at: Some(now + TimeDelta::minutes(1)),
            created_at: now,
            started_at: Some(now),
        };
        let target = CanvasSyncTarget {
            id: "target".into(),
            organization_id: "org".into(),
            platform_id: "platform".into(),
            binding_id: "binding".into(),
            target_type: CanvasSyncTargetType::LearnerApplication,
            logical_key: "logical".into(),
            application_id: Some("application".into()),
            candidate_id: None,
            enabled: true,
            schedule_seconds: 60,
            config_version: 4,
            metadata: Map::new(),
            created_at: now,
        };
        assert_ne!(target.config_version, job.target_config_version);
        assert!(target.enabled);
        let mut disabled = target;
        disabled.enabled = false;
        assert!(!disabled.enabled);
    }
}
