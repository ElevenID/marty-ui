use std::{env, error::Error, fs, process::ExitCode, sync::Arc, time::Duration};

use marty_issuance_service::{
    canvas_lti_tool_signing::{
        HttpCanvasLtiToolIdentityResolver, HttpCanvasLtiToolSignatureProvider,
        IssuerDidCanvasLtiToolJwtSigner,
    },
    canvas_oauth::{CanvasOAuthService, CanvasOAuthServiceConfig},
    canvas_oauth_http::HttpCanvasOAuthProvider,
    canvas_oauth_postgres::{PostgresCanvasOAuthRepository, PostgresIntegrationSecretVault},
    canvas_provider_http::CanvasHttpClientPolicy,
    canvas_sync_processor::NativeCanvasSyncProcessor,
    canvas_sync_processor_postgres::PostgresCanvasSyncProcessorRepository,
    canvas_sync_provider_http::HttpCanvasAuthoritativeProvider,
    canvas_sync_worker::{CanvasSyncWorker, CanvasSyncWorkerConfig},
    canvas_sync_worker_lifecycle::{
        finish_on_shutdown, spawn_with_postgres_cleanup, WorkerShutdown,
    },
    canvas_sync_worker_postgres::PostgresCanvasSyncWorkerRepository,
    integration_secret::IntegrationSecretCipher,
};
use mmf_runtime::managed_task::{CleanupOutcome, TaskCompletion, TaskOutcome};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::sync::watch;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<ExitCode, Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let config = CanvasSyncWorkerConfig::from_env().inspect_err(|_error| {
        error!(
            exception_class = "CanvasSyncWorkerConfigError",
            "invalid Canvas worker configuration"
        );
    })?;
    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgresql://marty:marty_dev@postgres:5432/marty_credentials".to_owned()
    });
    let master_key = integration_master_key()?;
    let cipher = IntegrationSecretCipher::from_base64(&master_key)?;
    let pool = PgPoolOptions::new()
        .min_connections(1)
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(10))
        .connect_lazy(&database_url)?;
    let (stop, receiver) = watch::channel(false);
    // Register Unix handlers before worker tasks can report database readiness.
    let shutdown = shutdown_signal();
    let owner = spawn_with_postgres_cleanup(pool, move |pool| {
        run_initialized_worker(pool, config, cipher, receiver)
    });
    let completion = finish_on_shutdown(owner, stop, shutdown).await?;
    completion_result(completion)
}

fn completion_result(
    completion: TaskCompletion<(), Box<dyn Error + Send + Sync>>,
) -> Result<ExitCode, Box<dyn Error + Send + Sync>> {
    match (completion.outcome, completion.cleanup) {
        (TaskOutcome::Completed(()), CleanupOutcome::Completed) => Ok(ExitCode::SUCCESS),
        // Preserve the published asyncio.run SIGINT exit status, but only
        // after cleanup is acknowledged. This is a non-success process exit.
        (TaskOutcome::Cancelled, CleanupOutcome::Completed) => Ok(ExitCode::from(130)),
        (TaskOutcome::Failed(error), CleanupOutcome::Completed) => Err(error),
        (outcome, cleanup) => {
            // Inspect both outcomes without logging configuration, SQL or panic
            // payloads. Cancellation is not a successful graceful shutdown.
            error!(
                operation_outcome = match outcome {
                    TaskOutcome::Completed(()) => "completed",
                    TaskOutcome::Failed(_) => "failed",
                    TaskOutcome::Cancelled => "cancelled",
                    TaskOutcome::Panicked => "panicked",
                },
                cleanup_outcome = match cleanup {
                    CleanupOutcome::Completed => "completed",
                    CleanupOutcome::Failed(never) => match never {},
                    CleanupOutcome::Cancelled => "cancelled",
                    CleanupOutcome::Panicked => "panicked",
                },
                "Canvas worker did not complete cleanly"
            );
            Err("Canvas worker did not complete cleanly".into())
        }
    }
}

async fn run_initialized_worker(
    pool: PgPool,
    config: CanvasSyncWorkerConfig,
    cipher: IntegrationSecretCipher,
    stop: watch::Receiver<bool>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let oauth_repository = Arc::new(PostgresCanvasOAuthRepository::new(pool.clone()));
    let worker_repository = Arc::new(PostgresCanvasSyncWorkerRepository::new(pool.clone()));
    let vault = Arc::new(PostgresIntegrationSecretVault::new(pool.clone(), cipher));
    let private_origins = comma_values("CANVAS_PRIVATE_ORIGIN_ALLOWLIST");
    let self_managed_origins = comma_values("CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST");
    let allow_private = env_bool("CANVAS_ALLOW_PRIVATE_BASE_URLS");
    let allow_localhost = env_bool("CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS");
    let provider = Arc::new(HttpCanvasOAuthProvider::new_with_policy(
        Duration::from_secs(10),
        private_origins.clone(),
        allow_private,
        allow_localhost,
    ));
    let issuance_api_key =
        required_secret_with_fallback("ISSUANCE_API_KEY", "SIGNING_KEYS_INTERNAL_API_KEY")?;
    let oauth = Arc::new(CanvasOAuthService::new(
        oauth_repository.clone(),
        vault.clone(),
        provider.clone(),
        Some(&issuance_api_key),
        CanvasOAuthServiceConfig {
            issuer_base_url: env::var("ISSUER_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:8000".to_owned()),
            completion_base_url: env::var("CANVAS_OAUTH_COMPLETION_REDIRECT_URL")
                .or_else(|_| env::var("UI_BASE_URL"))
                .unwrap_or_else(|_| "http://localhost:3000".to_owned()),
            portable_enabled: config.portable_enabled,
            pilot_organizations: config.pilot_organizations.clone(),
            allow_private_networks: allow_private,
            allow_http_localhost: allow_localhost,
        },
    )?);
    let signing_url = url::Url::parse(
        &env::var("SIGNING_KEYS_INTERNAL_URL")
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "http://gateway:8000/internal/signing-keys".to_owned()),
    )?;
    let signing_key =
        required_secret_with_fallback("SIGNING_KEYS_INTERNAL_API_KEY", "ISSUANCE_API_KEY")?;
    let signer = Arc::new(IssuerDidCanvasLtiToolJwtSigner::new(
        required_env("CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID")?,
        required_env("CANVAS_LTI_TOOL_ISSUER_DID")?,
        true,
        Arc::new(HttpCanvasLtiToolIdentityResolver::new(
            signing_url.clone(),
            Some(&signing_key),
            Duration::from_secs(10),
        )?),
        Arc::new(HttpCanvasLtiToolSignatureProvider::new(
            signing_url,
            Some(&signing_key),
            Duration::from_secs(15),
        )?),
    ));
    let authoritative_provider = Arc::new(HttpCanvasAuthoritativeProvider::new(
        oauth,
        issuance_api_key,
        signer,
        CanvasHttpClientPolicy {
            timeout: Duration::from_secs(20),
            private_origin_allowlist: private_origins,
            allow_private_networks: allow_private,
            allow_http_localhost: allow_localhost,
        },
        self_managed_origins,
    ));
    let processor = Arc::new(NativeCanvasSyncProcessor::new(
        Arc::new(PostgresCanvasSyncProcessorRepository::new(pool.clone())),
        authoritative_provider,
        config.clone(),
        bounded_usize("CANVAS_BACKGROUND_ROSTER_BATCH_SIZE", 500, 1, 2_000)?,
        bounded_usize("CANVAS_BACKGROUND_ROSTER_MAX_SIZE", 5_000, 1, 10_000)?,
    ));
    let worker = CanvasSyncWorker::new(
        worker_repository,
        oauth_repository,
        vault,
        provider,
        processor,
        config,
    );
    info!(worker = ?worker, "starting standalone Rust Canvas sync worker candidate");
    worker.run_loop(stop).await?;
    Ok(())
}

fn required_env(name: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} is required").into())
}

fn optional_secret(name: &str) -> Result<Option<String>, Box<dyn Error + Send + Sync>> {
    if let Ok(value) = env::var(name) {
        let value = value.trim().to_owned();
        if !value.is_empty() {
            return Ok(Some(value));
        }
    }
    let file_name = format!("{name}_FILE");
    if let Ok(path) = env::var(&file_name) {
        let path = path.trim();
        if !path.is_empty() {
            let value = fs::read_to_string(path)?.trim().to_owned();
            if !value.is_empty() {
                return Ok(Some(value));
            }
            return Err(format!("{file_name} contains an empty secret").into());
        }
    }
    Ok(None)
}

fn required_secret_with_fallback(
    preferred: &str,
    fallback: &str,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    first_present_or_else(optional_secret(preferred)?, || optional_secret(fallback))?
        .ok_or_else(|| format!("{preferred} or {fallback} is required").into())
}

fn first_present_or_else<T, E>(
    preferred: Option<T>,
    fallback: impl FnOnce() -> Result<Option<T>, E>,
) -> Result<Option<T>, E> {
    match preferred {
        Some(value) => Ok(Some(value)),
        None => fallback(),
    }
}

fn bounded_usize(
    name: &str,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, Box<dyn Error + Send + Sync>> {
    let value = env::var(name)
        .ok()
        .map(|value| value.trim().parse::<i64>())
        .transpose()?
        .unwrap_or(i64::try_from(default)?);
    Ok(usize::try_from(
        value.clamp(i64::try_from(minimum)?, i64::try_from(maximum)?),
    )?)
}

fn env_bool(name: &str) -> bool {
    env::var(name).is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

#[cfg(unix)]
fn shutdown_signal() -> impl std::future::Future<Output = WorkerShutdown> {
    use tokio::signal::unix::{signal, SignalKind};
    // These calls register synchronously, not on a later future poll.
    let interrupt = signal(SignalKind::interrupt());
    let terminate = signal(SignalKind::terminate());
    async move {
        let (Ok(mut interrupt), Ok(mut terminate)) = (interrupt, terminate) else {
            error!(
                exception_class = "SignalRegistrationError",
                "Canvas signal handler failed"
            );
            return WorkerShutdown::Cancel;
        };
        tokio::select! {
            _ = interrupt.recv() => WorkerShutdown::Cancel,
            event = terminate.recv() => {
                if event.is_some() { WorkerShutdown::Drain } else { WorkerShutdown::Cancel }
            },
        }
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> WorkerShutdown {
    if tokio::signal::ctrl_c().await.is_err() {
        error!(
            exception_class = "SignalRegistrationError",
            "Canvas interrupt handler failed"
        );
    }
    WorkerShutdown::Cancel
}

fn integration_master_key() -> Result<String, Box<dyn Error + Send + Sync>> {
    if let Ok(value) = env::var("INTEGRATION_SECRET_MASTER_KEY") {
        if !value.trim().is_empty() {
            return Ok(value.trim().to_owned());
        }
    }
    if let Ok(path) = env::var("INTEGRATION_SECRET_MASTER_KEY_FILE") {
        if !path.trim().is_empty() {
            return Ok(fs::read_to_string(path.trim())?.trim().to_owned());
        }
    }
    if let Ok(name) = env::var("INTEGRATION_SECRET_MASTER_KEY_ENV") {
        if !name.trim().is_empty() {
            return Ok(env::var(name.trim())?.trim().to_owned());
        }
    }
    Err("INTEGRATION_SECRET_MASTER_KEY source is required".into())
}

fn comma_values(name: &str) -> Vec<String> {
    env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{completion_result, first_present_or_else, ExitCode};
    use mmf_runtime::managed_task::{CleanupOutcome, TaskCompletion, TaskOutcome};

    #[test]
    fn cancelled_process_matches_published_python_sigint_exit_code() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../contracts/issuance-canvas-worker-process-signals.json"
        ))
        .unwrap();
        assert_eq!(fixture["legacy_observation"]["exit_code"], 130);
        let result = completion_result(TaskCompletion {
            outcome: TaskOutcome::Cancelled,
            cleanup: CleanupOutcome::Completed,
        });
        assert!(
            result.is_ok(),
            "cancellation needs a distinct process exit status"
        );
        assert_eq!(
            result.unwrap(),
            ExitCode::from(fixture["legacy_observation"]["exit_code"].as_u64().unwrap() as u8)
        );
    }

    #[test]
    fn process_success_requires_both_operation_and_cleanup_success() {
        for outcome in [
            TaskOutcome::Completed(()),
            TaskOutcome::Failed("synthetic operation failure".into()),
            TaskOutcome::Cancelled,
            TaskOutcome::Panicked,
        ] {
            let succeeds = matches!(outcome, TaskOutcome::Completed(()));
            assert_eq!(
                completion_result(TaskCompletion {
                    outcome,
                    cleanup: CleanupOutcome::Completed,
                })
                .is_ok_and(|exit| exit == ExitCode::SUCCESS),
                succeeds
            );
        }
        for cleanup in [CleanupOutcome::Cancelled, CleanupOutcome::Panicked] {
            assert!(completion_result(TaskCompletion {
                outcome: TaskOutcome::Completed(()),
                cleanup,
            })
            .is_err());
        }
    }

    #[test]
    fn successful_disposal_preserves_original_operation_failure() {
        let failure = completion_result(TaskCompletion {
            outcome: TaskOutcome::Failed("synthetic operation failure".into()),
            cleanup: CleanupOutcome::Completed,
        })
        .unwrap_err();
        assert_eq!(failure.to_string(), "synthetic operation failure");
    }

    #[test]
    fn preferred_secret_does_not_read_an_invalid_unused_fallback() {
        let resolved = first_present_or_else(Some("preferred".to_owned()), || {
            Err::<Option<String>, _>("unused fallback must not be read")
        })
        .expect("preferred secret short-circuits fallback");

        assert_eq!(resolved.as_deref(), Some("preferred"));
    }

    #[test]
    fn missing_preferred_secret_reads_the_fallback() {
        let resolved = first_present_or_else(None, || Ok::<_, &'static str>(Some("fallback")))
            .expect("fallback secret");

        assert_eq!(resolved, Some("fallback"));
    }
}
