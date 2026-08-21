use std::{error::Error, sync::Arc, time::Duration};

use marty_deployment_profile::{
    deployment_router, run_migrations, tenant_membership_provider, DeploymentDependency,
    DeploymentHttpState, DeploymentRepository, DeploymentRuntime, DeploymentService,
    DeploymentServiceConfig, PostgresDeploymentRepository,
};
use sqlx::postgres::PgPoolOptions;
use tokio::{net::TcpListener, sync::watch};
use tower_http::trace::TraceLayer;
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
    run_migrations(&pool).await?;
    runtime.mark_healthy(DeploymentDependency::Schema)?;
    let memberships = tenant_membership_provider(&config)?;
    runtime.mark_healthy(DeploymentDependency::Organization)?;
    let repository: Arc<dyn DeploymentRepository> =
        Arc::new(PostgresDeploymentRepository::new(pool));
    let service = Arc::new(DeploymentService::new(repository, memberships));
    runtime.mark_healthy(DeploymentDependency::NativeKernel)?;
    let listener = TcpListener::bind(config.http_addr).await?;
    runtime.mark_healthy(DeploymentDependency::HttpListener)?;
    let app = runtime
        .operational_router()
        .merge(deployment_router(DeploymentHttpState { service }))
        .layer(TraceLayer::new_for_http());
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        while !*shutdown_rx.borrow() && shutdown_rx.changed().await.is_ok() {}
    });
    runtime.activate()?;
    info!(http_address=%config.http_addr, release_version=%config.release_version,
        build_revision=%config.build_revision, "native Rust Deployment Profile service active");
    tokio::select! {
        result = server => result?,
        () = shutdown_signal() => { runtime.drain()?; let _ = shutdown_tx.send(true); }
    }
    let _ = shutdown_tx.send(true);
    runtime.stop()?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { () = ctrl_c => {}, () = terminate => {} }
}
