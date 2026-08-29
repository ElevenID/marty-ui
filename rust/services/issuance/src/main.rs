use std::error::Error;

use marty_issuance_service::{
    http::router, transport::TransportPolicy, validate_embedded_contract, IssuanceRuntime,
    IssuanceServiceConfig,
};
use marty_oid4vci::discovery::StaticDiscoveryDocuments;
use tokio::net::TcpListener;
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
    validate_embedded_contract().map_err(|error| {
        error!(%error, "invalid embedded issuance migration contract");
        error
    })?;
    let config = IssuanceServiceConfig::from_env().map_err(|error| {
        error!(%error, "invalid issuance configuration");
        error
    })?;
    let runtime = IssuanceRuntime::new(&config)?;
    let discovery =
        StaticDiscoveryDocuments::new(&config.issuer_base_url, &config.issuer_display_name);
    let listener = TcpListener::bind(config.http_addr).await?;
    runtime.mark_listener_healthy()?;
    let transport = TransportPolicy::new(config.cors_allowed_origins.clone());
    let app = router(runtime.state(), discovery, transport);
    runtime.activate()?;
    info!(
        address = %config.http_addr,
        release_version = %config.release_version,
        build_revision = %config.build_revision,
        "native Rust issuance candidate active"
    );

    let result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await;
    runtime.drain()?;
    runtime.stop()?;
    result.map_err(Into::into)
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
