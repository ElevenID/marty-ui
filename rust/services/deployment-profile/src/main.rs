use marty_service_runtime::shutdown_signal_best_effort as shutdown_signal;
use std::{error::Error, sync::Arc, time::Duration};

use marty_deployment_profile::{
    deployment_authority_router, deployment_router, run_migrations, tenant_membership_provider,
    DeploymentDependency, DeploymentHttpState, DeploymentRepository, DeploymentRuntime,
    DeploymentService, DeploymentServiceConfig, PostgresDeploymentRepository,
};
use sqlx::postgres::PgPoolOptions;
use tokio::{net::TcpListener, sync::watch};
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    marty_service_runtime::install_tls_crypto_provider();
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let config = DeploymentServiceConfig::from_env().map_err(|error| {
        error!(%error, "invalid Deployment Profile configuration");
        error
    })?;
    let runtime = DeploymentRuntime::new(&config)?;
    let pool = PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&config.database_url)
        .await?;
    runtime.mark_healthy(DeploymentDependency::Database)?;
    run_migrations(&pool, config.marty_organization_id).await?;
    runtime.mark_healthy(DeploymentDependency::Schema)?;
    let memberships = tenant_membership_provider(&config).await?;
    runtime.mark_healthy(DeploymentDependency::Organization)?;
    let repository: Arc<dyn DeploymentRepository> =
        Arc::new(PostgresDeploymentRepository::new(pool));
    let service = Arc::new(DeploymentService::new(repository, memberships));
    runtime.mark_healthy(DeploymentDependency::NativeKernel)?;
    let state =
        DeploymentHttpState::new(service).with_service_token(config.service_token.clone())?;
    let authority_server = match &config.managed_authority_https {
        Some(https) => Some(
            marty_service_runtime::https::BoundKeylessHttpsServer::bind(
                https,
                deployment_authority_router(state.clone()),
            )
            .await?,
        ),
        None => None,
    };
    let listener = TcpListener::bind(config.http_addr).await?;
    runtime.mark_healthy(DeploymentDependency::HttpListener)?;
    let app = runtime
        .operational_router()
        .merge(deployment_router(state))
        .layer(TraceLayer::new_for_http());
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let authority =
        marty_service_runtime::https::serve_optional(authority_server, shutdown_rx.clone());
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        while !*shutdown_rx.borrow() && shutdown_rx.changed().await.is_ok() {}
    });
    runtime.activate()?;
    info!(http_address=%config.http_addr, release_version=%config.release_version,
        build_revision=%config.build_revision, "native Rust Deployment Profile service active");
    let servers = async { tokio::try_join!(server, authority).map(|_| ()) };
    tokio::pin!(servers);
    let result = tokio::select! {
        result = &mut servers => result,
        () = shutdown_signal() => {
            runtime.drain()?;
            let _ = shutdown_tx.send(true);
            servers.await
        }
    };
    let _ = shutdown_tx.send(true);
    runtime.stop()?;
    result?;
    Ok(())
}
