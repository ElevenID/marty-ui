use std::{env, error::Error, fs, sync::Arc, time::Duration};

use marty_issuance_service::{
    canvas_lti_tool_signing::{
        HttpCanvasLtiToolIdentityResolver, HttpCanvasLtiToolSignatureProvider,
        IssuerDidCanvasLtiToolJwtSigner,
    },
    canvas_oauth::{CanvasOAuthService, CanvasOAuthServiceConfig},
    canvas_oauth_http::HttpCanvasOAuthProvider,
    canvas_oauth_postgres::{PostgresCanvasOAuthRepository, PostgresIntegrationSecretVault},
    canvas_sync_processor::NativeCanvasSyncProcessor,
    canvas_sync_processor_postgres::PostgresCanvasSyncProcessorRepository,
    canvas_sync_provider_http::HttpCanvasAuthoritativeProvider,
    canvas_sync_worker::{CanvasSyncWorker, CanvasSyncWorkerConfig},
    canvas_sync_worker_postgres::PostgresCanvasSyncWorkerRepository,
    integration_secret::IntegrationSecretCipher,
};
use sqlx::postgres::PgPoolOptions;
use tokio::sync::watch;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
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
    let oauth_repository = Arc::new(PostgresCanvasOAuthRepository::new(pool.clone()));
    let worker_repository = Arc::new(PostgresCanvasSyncWorkerRepository::new(pool.clone()));
    let vault = Arc::new(PostgresIntegrationSecretVault::new(pool.clone(), cipher));
    let private_origins = comma_values("CANVAS_PRIVATE_ORIGIN_ALLOWLIST");
    let allow_private = env_bool("CANVAS_ALLOW_PRIVATE_BASE_URLS");
    let allow_localhost = env_bool("CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS");
    let provider = Arc::new(HttpCanvasOAuthProvider::new_with_policy(
        Duration::from_secs(10),
        private_origins.clone(),
        allow_private,
        allow_localhost,
    ));
    let issuance_api_key = required_env("ISSUANCE_API_KEY")?;
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
    let signing_url = url::Url::parse(&required_env("SIGNING_KEYS_INTERNAL_URL")?)?;
    let signing_key = required_env("SIGNING_KEYS_INTERNAL_API_KEY")?;
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
            Duration::from_secs(10),
        )?),
    ));
    let authoritative_provider = Arc::new(HttpCanvasAuthoritativeProvider::new(
        oauth,
        issuance_api_key,
        signer,
        Duration::from_secs(20),
        private_origins,
        allow_private,
        allow_localhost,
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
    let (stop_tx, stop_rx) = watch::channel(false);
    let shutdown = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = stop_tx.send(true);
        }
    });
    info!(worker = ?worker, "starting standalone Rust Canvas sync worker candidate");
    let outcome = worker.run_loop(stop_rx).await;
    shutdown.abort();
    pool.close().await;
    outcome?;
    Ok(())
}

fn required_env(name: &str) -> Result<String, Box<dyn Error>> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} is required").into())
}

fn bounded_usize(
    name: &str,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, Box<dyn Error>> {
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
            "1" | "true" | "yes"
        )
    })
}

fn integration_master_key() -> Result<String, Box<dyn Error>> {
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
