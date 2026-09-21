//! Shared completion-relative Canvas mirror scheduler.

use async_trait::async_trait;
use mmf_config::numeric_config::PythonConfigInteger;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tracing::warn;

use crate::canvas_mirror_service::CanvasMirrorService;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanvasMirrorAutomationConfig {
    pub enabled: bool,
    pub organization_id: Option<String>,
    pub publish_interval_seconds: u64,
    pub status_sync_interval_seconds: u64,
    pub batch_limit: u32,
    pub retry_failed_publish: bool,
    pub run_on_startup: bool,
}

impl Default for CanvasMirrorAutomationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            organization_id: None,
            publish_interval_seconds: 300,
            status_sync_interval_seconds: 900,
            batch_limit: 25,
            retry_failed_publish: true,
            run_on_startup: true,
        }
    }
}

impl CanvasMirrorAutomationConfig {
    #[must_use]
    pub fn from_values(values: &BTreeMap<String, String>) -> Self {
        let defaults = Self::default();
        Self {
            enabled: flag(values, "CANVAS_MIRROR_WORKER_ENABLED", defaults.enabled),
            organization_id: values
                .get("CANVAS_MIRROR_WORKER_ORGANIZATION_ID")
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
            publish_interval_seconds: positive(
                values,
                "CANVAS_MIRROR_PUBLISH_INTERVAL_SECONDS",
                defaults.publish_interval_seconds,
            )
            .to_u64()
            .unwrap_or_else(|| {
                warn!(
                    "Clamping CANVAS_MIRROR_PUBLISH_INTERVAL_SECONDS to native maximum {}",
                    u64::MAX
                );
                u64::MAX
            }),
            status_sync_interval_seconds: positive(
                values,
                "CANVAS_MIRROR_STATUS_SYNC_INTERVAL_SECONDS",
                defaults.status_sync_interval_seconds,
            )
            .to_u64()
            .unwrap_or_else(|| {
                warn!(
                    "Clamping CANVAS_MIRROR_STATUS_SYNC_INTERVAL_SECONDS to native maximum {}",
                    u64::MAX
                );
                u64::MAX
            }),
            batch_limit: positive(
                values,
                "CANVAS_MIRROR_WORKER_BATCH_LIMIT",
                u64::from(defaults.batch_limit),
            )
            .to_u64()
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or_else(clamped_batch_limit),
            retry_failed_publish: flag(
                values,
                "CANVAS_MIRROR_WORKER_RETRY_FAILED",
                defaults.retry_failed_publish,
            ),
            run_on_startup: flag(
                values,
                "CANVAS_MIRROR_WORKER_RUN_ON_STARTUP",
                defaults.run_on_startup,
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanvasMirrorAutomationError;

#[async_trait]
pub trait CanvasMirrorAutomationPort: Send + Sync {
    async fn publish(
        &self,
        organization_id: Option<&str>,
        limit: u32,
        retry_failed: bool,
    ) -> Result<(), CanvasMirrorAutomationError>;

    async fn status_sync(
        &self,
        organization_id: Option<&str>,
        limit: u32,
    ) -> Result<(), CanvasMirrorAutomationError>;
}

#[async_trait]
impl CanvasMirrorAutomationPort for CanvasMirrorService {
    async fn publish(
        &self,
        organization_id: Option<&str>,
        limit: u32,
        retry_failed: bool,
    ) -> Result<(), CanvasMirrorAutomationError> {
        self.process_pending(organization_id, limit, retry_failed, chrono::Utc::now())
            .await
            .map(|_| ())
            .map_err(|_| CanvasMirrorAutomationError)
    }

    async fn status_sync(
        &self,
        organization_id: Option<&str>,
        limit: u32,
    ) -> Result<(), CanvasMirrorAutomationError> {
        self.process_status_sync_failures(organization_id, limit, chrono::Utc::now())
            .await
            .map(|_| ())
            .map_err(|_| CanvasMirrorAutomationError)
    }
}

#[async_trait]
pub trait CanvasMirrorAutomationRuntime: Send + Sync {
    fn monotonic_seconds(&self) -> f64;
    async fn sleep(&self, duration: Duration);
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TokioCanvasMirrorAutomationRuntime;

#[async_trait]
impl CanvasMirrorAutomationRuntime for TokioCanvasMirrorAutomationRuntime {
    fn monotonic_seconds(&self) -> f64 {
        static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        START
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_secs_f64()
    }

    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

/// Owns the optional in-process worker so shutdown cannot leave a detached
/// publisher running after the HTTP/gRPC listeners have begun draining.
pub struct CanvasMirrorAutomationHandle {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for CanvasMirrorAutomationHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl CanvasMirrorAutomationHandle {
    pub async fn shutdown(mut self) {
        self.task.abort();
        match (&mut self.task).await {
            Ok(()) => {}
            Err(error) if error.is_cancelled() => {}
            Err(error) => tracing::error!(%error, "Canvas mirror automation worker join failed"),
        }
    }
}

#[must_use]
pub fn spawn_canvas_mirror_automation(
    port: Arc<dyn CanvasMirrorAutomationPort>,
    config: CanvasMirrorAutomationConfig,
) -> Option<CanvasMirrorAutomationHandle> {
    if !config.enabled {
        return None;
    }
    let task = tokio::spawn(run_canvas_mirror_automation_loop(
        port,
        Arc::new(TokioCanvasMirrorAutomationRuntime),
        config,
    ));
    Some(CanvasMirrorAutomationHandle { task })
}

pub async fn run_canvas_mirror_automation_loop(
    port: Arc<dyn CanvasMirrorAutomationPort>,
    runtime: Arc<dyn CanvasMirrorAutomationRuntime>,
    config: CanvasMirrorAutomationConfig,
) {
    if !config.enabled {
        return;
    }
    tracing::info!(
        organization_id = config.organization_id.as_deref(),
        batch_limit = config.batch_limit,
        retry_failed = config.retry_failed_publish,
        "Canvas mirror automation worker enabled"
    );
    let now = runtime.monotonic_seconds();
    let mut next_publish = if config.run_on_startup {
        now
    } else {
        now + config.publish_interval_seconds as f64
    };
    let mut next_status = if config.run_on_startup {
        now
    } else {
        now + config.status_sync_interval_seconds as f64
    };
    loop {
        let current = runtime.monotonic_seconds();
        if current >= next_publish {
            if port
                .publish(
                    config.organization_id.as_deref(),
                    config.batch_limit,
                    config.retry_failed_publish,
                )
                .await
                .is_err()
            {
                tracing::error!("Canvas mirror publish worker cycle failed");
            }
            next_publish = runtime.monotonic_seconds() + config.publish_interval_seconds as f64;
        }
        let current = runtime.monotonic_seconds();
        if current >= next_status {
            if port
                .status_sync(config.organization_id.as_deref(), config.batch_limit)
                .await
                .is_err()
            {
                tracing::error!("Canvas mirror status-sync worker cycle failed");
            }
            next_status = runtime.monotonic_seconds() + config.status_sync_interval_seconds as f64;
        }
        let sleep = (next_publish.min(next_status) - runtime.monotonic_seconds()).max(1.0);
        runtime.sleep(Duration::from_secs_f64(sleep)).await;
    }
}

fn flag(values: &BTreeMap<String, String>, key: &str, default: bool) -> bool {
    values
        .get(key)
        .map(|value| match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => {
                warn!(
                    "Ignoring invalid boolean {key}='{value}'; using {}",
                    if default { "True" } else { "False" }
                );
                default
            }
        })
        .unwrap_or(default)
}

fn positive(values: &BTreeMap<String, String>, key: &str, default: u64) -> PythonConfigInteger {
    let Some(raw) = values.get(key) else {
        return default.into();
    };
    let Ok(value) = raw.parse::<PythonConfigInteger>() else {
        warn!("Ignoring invalid integer {key}='{raw}'; using {default}");
        return default.into();
    };
    if value < PythonConfigInteger::from(1_u64) {
        warn!("Ignoring {key}='{raw}' below minimum 1; using {default}");
        return default.into();
    }
    value
}

fn clamped_batch_limit() -> u32 {
    warn!(
        "Clamping CANVAS_MIRROR_WORKER_BATCH_LIMIT to native maximum {}",
        u32::MAX
    );
    u32::MAX
}
