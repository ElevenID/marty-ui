use std::{error::Error, sync::Arc, time::Duration};

use marty_trust_profile::{
    bootstrap_system_catalog, run_migrations, trust_profile_router, MartyBootstrapConfig,
    NativeTrustProfileControlPlane, NativeTrustRegistrySynchronizer,
    PostgresTrustProfileRepository, TrustProfileApplication, TrustProfileDependency,
    TrustProfileHttpState, TrustProfileRepository, TrustProfileRuntime, TrustProfileServiceConfig,
    TrustRegistryScheduler,
};
use mmf_security::ServiceTokenAuthenticator;
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
    let config = TrustProfileServiceConfig::from_env().map_err(|error| {
        error!(%error, "invalid Trust Profile configuration");
        error
    })?;
    let runtime = TrustProfileRuntime::new(&config)?;
    let pool = PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&config.database_url)
        .await?;
    runtime.mark_healthy(TrustProfileDependency::Database)?;
    run_migrations(&pool).await?;
    runtime.mark_healthy(TrustProfileDependency::Schema)?;

    let store = Arc::new(PostgresTrustProfileRepository::new(pool));
    bootstrap_system_catalog(
        store.as_ref(),
        &MartyBootstrapConfig {
            organization_id: config.marty_organization_id.to_string(),
            issuer_did: config.marty_issuer_did.clone(),
            issuer_url: config.marty_issuer_url.clone(),
        },
        chrono::Utc::now(),
    )
    .await?;
    runtime.mark_healthy(TrustProfileDependency::SystemCatalog)?;

    let control = Arc::new(NativeTrustProfileControlPlane::connect_lazy(
        &config.organization_grpc_target,
        config.service_token.as_deref(),
        config.dependency_timeout,
    )?);
    runtime.mark_healthy(TrustProfileDependency::ControlPlane)?;
    let repository: Arc<dyn TrustProfileRepository> = store;
    let application = Arc::new(TrustProfileApplication::new(
        Arc::clone(&repository),
        control,
    ));
    let registry_synchronizer = Arc::new(NativeTrustRegistrySynchronizer::new(
        Arc::clone(&repository),
        config.dependency_timeout,
        config.registry_private_hosts.clone(),
        config.registry_ca_bundle.as_deref(),
    )?);
    runtime.mark_healthy(TrustProfileDependency::NativeRegistryKernel)?;
    let service_authenticator = Arc::new(ServiceTokenAuthenticator::new(
        config.service_token.clone(),
        config.service_authentication_required(),
    )?);
    let scheduler_repository = Arc::clone(&repository);
    let state = TrustProfileHttpState {
        application,
        repository,
        service_authenticator,
        internal_api_key: config.internal_api_key.clone().map(Arc::from),
        registry_synchronizer: registry_synchronizer.clone(),
    };

    let listener = TcpListener::bind(config.http_addr).await?;
    runtime.mark_healthy(TrustProfileDependency::HttpListener)?;
    let app = runtime
        .operational_router()
        .merge(trust_profile_router(state))
        .layer(TraceLayer::new_for_http());
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let scheduler = TrustRegistryScheduler::new(
        scheduler_repository,
        registry_synchronizer,
        config.registry_sync_poll_interval,
    );
    let scheduler_task = tokio::spawn(scheduler.run(shutdown_rx.clone()));
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        while !*shutdown_rx.borrow() && shutdown_rx.changed().await.is_ok() {}
    });
    runtime.activate()?;
    info!(
        http_address = %config.http_addr,
        release_version = %config.release_version,
        build_revision = %config.build_revision,
        "native Rust Trust Profile service active"
    );
    tokio::select! {
        result = server => result?,
        () = shutdown_signal() => {
            runtime.drain()?;
            let _ = shutdown_tx.send(true);
        }
    }
    let _ = shutdown_tx.send(true);
    let _ = scheduler_task.await;
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
