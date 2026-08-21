use std::{error::Error, sync::Arc};

use marty_verification_service::{
    http::{router, HttpState},
    verification_proto::verification_service_server::VerificationServiceServer,
    Environment, MemorySessionStore, RedisSessionStore, SessionStore, VerificationDependency,
    VerificationGrpcService, VerificationProviders, VerificationRuntime, VerificationService,
    VerificationServiceConfig,
};
use tokio::{net::TcpListener, sync::watch};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
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
    let config = VerificationServiceConfig::from_env().map_err(|error| {
        error!(%error, "invalid Verification configuration");
        error
    })?;
    let runtime = VerificationRuntime::new(&config)?;
    let store: Arc<dyn SessionStore> = match config.redis_url.as_deref() {
        Some(url) => Arc::new(RedisSessionStore::connect(url).await?),
        None if matches!(
            config.environment,
            Environment::Development | Environment::Test
        ) =>
        {
            Arc::new(MemorySessionStore::new())
        }
        None => return Err("deployed Verification requires Redis".into()),
    };
    runtime.mark_healthy(VerificationDependency::SessionStore)?;
    let providers = VerificationProviders::connect_lazy(&config.providers)?;
    runtime.mark_healthy(VerificationDependency::Organization)?;
    runtime.mark_healthy(VerificationDependency::CredentialTemplate)?;
    runtime.mark_healthy(VerificationDependency::PresentationPolicy)?;
    runtime.mark_healthy(VerificationDependency::NativeVerification)?;

    let http_service = Arc::new(VerificationService::new(
        store.clone(),
        providers.clone(),
        config.public_base_url.clone(),
        true,
    ));
    let grpc_service = Arc::new(VerificationService::new(
        store,
        providers,
        config.public_base_url.clone(),
        false,
    ));
    let http_listener = TcpListener::bind(config.http_addr).await?;
    runtime.mark_healthy(VerificationDependency::HttpListener)?;
    let grpc_listener = if config.grpc_enabled {
        let listener = TcpListener::bind(config.grpc_addr).await?;
        runtime.mark_healthy(VerificationDependency::GrpcListener)?;
        Some(listener)
    } else {
        None
    };
    let http_app = router(HttpState {
        service: http_service,
        runtime: runtime.state(),
        release_version: config.release_version.clone(),
        build_revision: config.build_revision.clone(),
    })
    .layer(TraceLayer::new_for_http());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut http_shutdown = shutdown_rx.clone();
    let http = axum::serve(http_listener, http_app).with_graceful_shutdown(async move {
        wait_for_shutdown(&mut http_shutdown).await;
    });
    let mut grpc_shutdown = shutdown_rx;
    let grpc = grpc_listener.map(|listener| async move {
        let (health_reporter, health_service) = tonic_health::server::health_reporter();
        let server = VerificationServiceServer::new(VerificationGrpcService::new(grpc_service));
        health_reporter
            .set_serving::<VerificationServiceServer<VerificationGrpcService>>()
            .await;
        Server::builder()
            .add_service(health_service)
            .add_service(server)
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async move {
                wait_for_shutdown(&mut grpc_shutdown).await;
            })
            .await
    });
    runtime.activate()?;
    info!(
        http_address = %config.http_addr,
        grpc_address = config.grpc_enabled.then(|| config.grpc_addr.to_string()),
        release_version = %config.release_version,
        build_revision = %config.build_revision,
        "native Rust Verification service active"
    );

    let result: Result<(), Box<dyn Error>> = if let Some(grpc) = grpc {
        tokio::select! {
            result = http => result.map_err(|error| Box::new(error) as Box<dyn Error>),
            result = grpc => result.map_err(|error| Box::new(error) as Box<dyn Error>),
            () = shutdown_signal() => Ok(()),
        }
    } else {
        tokio::select! {
            result = http => result.map_err(|error| Box::new(error) as Box<dyn Error>),
            () = shutdown_signal() => Ok(()),
        }
    };
    runtime.drain()?;
    let _ = shutdown_tx.send(true);
    runtime.stop()?;
    result
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    while !*shutdown.borrow() && shutdown.changed().await.is_ok() {}
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
