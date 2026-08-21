use marty_signing_keys::{
    config::Config, documents::DocumentStore, flow_envelope::OpenBaoEnvelopeProvider, http,
    profiles::ProfileStore, registry::RegistryStore,
};
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env().map_err(|error| {
        error!(%error, "invalid signing-keys configuration");
        error
    })?;
    let registry_store = RegistryStore::connect(&config.registry_redis_url).await?;
    let document_store = DocumentStore::from_connection(registry_store.connection());
    let profile_store = ProfileStore::from_connection(registry_store.connection());
    let flow_envelopes = match (config.bao_addr, config.bao_token) {
        (Some(address), Some(token)) => Some(OpenBaoEnvelopeProvider::new(address, token)?),
        (None, None) => None,
        _ => unreachable!("configuration validates paired OpenBao values"),
    };
    let listener = TcpListener::bind(config.http_addr).await?;
    info!(
        address = %config.http_addr,
        release_version = %config.release_version,
        build_revision = %config.build_revision,
        "starting Rust signing-keys service"
    );
    axum::serve(
        listener,
        http::router_with_dependencies(
            config.internal_api_key,
            Some(registry_store),
            Some(document_store),
            Some(profile_store),
            flow_envelopes,
            config.public_domain,
        ),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    info!("shutdown requested");
}
