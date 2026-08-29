use std::{error::Error, sync::Arc};

use marty_issuance_service::{
    http::router_with_services, signing_policy::HttpProofPolicyResolver,
    tenant_discovery::TenantDiscoveryService, tenant_postgres::PostgresTenantDiscoveryRepository,
    transaction_postgres::PostgresTransactionReadRepository,
    transaction_reads::TransactionReadService, transport::TransportPolicy,
    validate_embedded_contract, IssuanceRuntime, IssuanceServiceConfig,
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
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect_lazy(&config.database_url)?;
    let tenant_discovery = TenantDiscoveryService::new(
        discovery.clone(),
        Arc::new(PostgresTenantDiscoveryRepository::new(pool.clone())),
        Arc::new(HttpProofPolicyResolver::new(
            config.signing_keys_internal_url.clone(),
            config.signing_keys_internal_api_key.as_deref(),
            config.dependency_timeout,
        )?),
    );
    let transaction_reads = TransactionReadService::new(
        Arc::new(PostgresTransactionReadRepository::new(pool)),
        config.issuance_api_key.as_deref(),
        &config.issuer_base_url,
    );
    let listener = TcpListener::bind(config.http_addr).await?;
    runtime.mark_listener_healthy()?;
    let transport = TransportPolicy::new(config.cors_allowed_origins.clone());
    let app = router_with_services(
        runtime.state(),
        discovery,
        transport,
        tenant_discovery,
        transaction_reads,
    );
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
