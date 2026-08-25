use std::{error::Error, fs, sync::Arc, time::Duration};

use marty_gateway::{
    authorization::OrganizationMembershipProvider,
    config::GatewayConfig,
    contract::GatewayContract,
    middleware::{GatewayIdentityProvider, GatewayRateLimiter},
    providers::{
        DistributedProviderConfig, GatewayDistributedProviders, GrpcEventStreamProvider,
        GrpcIdentityProvider, HttpGatewayProvider,
    },
    registry::StaticServiceRegistry,
    runtime::{
        gateway_router, run_hosted_pilot_auto_purge_sweep, GatewayRuntimeState, ReadinessProvider,
        ResourceOwnerProvider,
    },
    transport::ReqwestUpstream,
};
use mmf_platform::{GatewayProxy, ProxyConfig};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .json()
        .init();

    let config = GatewayConfig::from_env()?;
    let contract = GatewayContract::load()?;
    let routes = contract.runtime_route_table()?;
    let proxy_routes = contract.proxy_route_table()?;
    let registry = StaticServiceRegistry::from_urls(&config.service_urls)?;
    let upstream = ReqwestUpstream::new(config.maximum_response_bytes)?;
    let proxy_config = ProxyConfig {
        maximum_response_bytes: config.maximum_response_bytes,
        ..ProxyConfig::default()
    };
    let proxy = GatewayProxy::new(
        proxy_routes,
        Arc::new(registry),
        Arc::new(upstream),
        proxy_config,
    )?;

    let distributed = GatewayDistributedProviders::compose(&DistributedProviderConfig {
        production: config.production,
        redis_url: config.redis_url.clone(),
        ..DistributedProviderConfig::default()
    })
    .await?;
    let identity_provider = Arc::new(GrpcIdentityProvider::new(
        grpc_channel(&config, &config.auth_grpc_target)?,
        grpc_channel(&config, &config.organization_grpc_target)?,
        Duration::from_secs(5),
        config.grpc_service_token.clone(),
    ));
    let identities: Arc<dyn GatewayIdentityProvider> = identity_provider.clone();
    let memberships: Arc<dyn OrganizationMembershipProvider> = identity_provider;

    let http_provider = Arc::new(HttpGatewayProvider::new(
        config.service_urls.clone(),
        config.signing_internal_api_key.clone(),
        Some(config.issuance_api_key.clone()),
        config.grpc_service_token.clone(),
        None,
    )?);
    let owners: Arc<dyn ResourceOwnerProvider> = http_provider.clone();
    let readiness: Arc<dyn ReadinessProvider> = http_provider;
    let event_streams = Arc::new(GrpcEventStreamProvider::new(
        grpc_channel(&config, &config.event_stream_grpc_target)?,
        config.grpc_service_token.clone(),
    ));
    let state = Arc::new(
        GatewayRuntimeState::new(
            routes,
            proxy,
            identities,
            memberships,
            owners,
            readiness,
            event_streams,
            config.required_ready_services.clone(),
            GatewayRateLimiter::new(distributed.rate_limiter, config.rate_limit_rpm)?,
            distributed.idempotency,
            config.cors_origins.clone(),
            config.issuer_base_url.clone(),
            config.public_api_url.clone(),
            config.public_domain.clone(),
            config.default_organization_id.clone(),
            config.signing_internal_api_key.clone(),
            config.issuance_api_key.clone(),
            config.release_identity.clone(),
        )?
        .with_service_token(config.grpc_service_token.clone())?,
    );

    let purge_task = if config.hosted_pilot_auto_purge_enabled {
        let state = Arc::clone(&state);
        let interval = Duration::from_secs(config.hosted_pilot_auto_purge_interval_seconds);
        let batch_size = config.hosted_pilot_auto_purge_batch_size;
        Some(tokio::spawn(async move {
            loop {
                let stats = run_hosted_pilot_auto_purge_sweep(&state, batch_size).await;
                info!(
                    organizations_scanned = stats.organizations_scanned,
                    hosted_pilot_orgs = stats.hosted_pilot_orgs,
                    purge_requests = stats.purge_requests,
                    purged_records = stats.purged_records,
                    "Hosted Pilot auto-purge sweep complete"
                );
                tokio::time::sleep(interval).await;
            }
        }))
    } else {
        None
    };

    let listener = tokio::net::TcpListener::bind(config.address).await?;
    info!(address = %config.address, redis_backed = distributed.redis_backed, "Rust gateway listening");
    let server_result = axum::serve(
        listener,
        gateway_router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await;
    if let Some(task) = purge_task {
        task.abort();
        let _ = task.await;
    }
    server_result?;
    Ok(())
}

fn grpc_channel(config: &GatewayConfig, target: &str) -> Result<Channel, Box<dyn Error>> {
    let mut endpoint_target = target.to_owned();
    let mut endpoint = if let Some(ca_path) = &config.grpc_ca_certificate {
        if endpoint_target.starts_with("http://") {
            endpoint_target = endpoint_target.replacen("http://", "https://", 1);
        }
        let parsed = url::Url::parse(&endpoint_target)?;
        let host = parsed.host_str().ok_or("gRPC endpoint requires a host")?;
        Endpoint::from_shared(endpoint_target.clone())?.tls_config(
            ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(fs::read(ca_path)?))
                .domain_name(host),
        )?
    } else {
        Endpoint::from_shared(endpoint_target)?
    };
    endpoint = endpoint
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(5));
    Ok(endpoint.connect_lazy())
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
            .expect("failed to install termination handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
