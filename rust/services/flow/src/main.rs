use std::{error::Error, sync::Arc};

use marty_flow::{
    flow_proto::flow_service_server::FlowServiceServer, flow_read_router, run_callback_dispatcher,
    CallbackDeliveryConfig, FlowBackendConnections, FlowDependency,
    FlowGrpcApplicationApprovalOptions, FlowGrpcSecurity, FlowGrpcService,
    FlowHttpApplicationApprovalOptions, FlowHttpState, FlowHttpVerificationOptions, FlowRuntime,
    FlowServiceConfig,
};
use tokio::{net::TcpListener, sync::watch};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
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

    let config = FlowServiceConfig::from_env().map_err(|error| {
        error!(%error, "invalid Flow configuration");
        error
    })?;
    let runtime = FlowRuntime::new(&config)?;
    let connections = FlowBackendConnections::connect(&config, &runtime).await?;
    let grpc_security = Arc::new(FlowGrpcSecurity::from_config(&config)?);
    let callback_config = CallbackDeliveryConfig::from_env()?;
    let http_application =
        FlowHttpApplicationApprovalOptions::from_config(&config, connections.nonce_store.clone())?;
    let grpc_application =
        FlowGrpcApplicationApprovalOptions::from_config(&config, connections.nonce_store.clone())?;
    let mut verification = FlowHttpVerificationOptions::from_config(&config);
    verification.callback_retention_seconds = callback_config.retention_seconds;
    verification.callback_max_attempts = callback_config.max_attempts;

    let http_state = FlowHttpState {
        repository: connections.repository.clone(),
        providers: Arc::clone(&connections.providers),
        public_base_url: config.public_base_url.clone(),
        verification,
        application_approval: http_application,
    };
    let grpc_service = FlowGrpcService::new(
        connections.repository.clone(),
        Arc::clone(&connections.providers),
        Arc::clone(&grpc_security),
        config.public_base_url.clone(),
        config.callback_destinations.clone(),
        config.verification_start_options(),
        grpc_application,
    );

    let http_listener = TcpListener::bind(config.http_addr).await?;
    runtime.mark_healthy(FlowDependency::HttpListener)?;
    let grpc_listener = TcpListener::bind(config.grpc_addr).await?;
    runtime.mark_healthy(FlowDependency::GrpcListener)?;

    let callback_secret = config.webhook_secret.clone();
    let (worker_shutdown_tx, worker_shutdown_rx) = watch::channel(false);
    let callback_worker = callback_secret.map(|secret| {
        tokio::spawn(run_callback_dispatcher(
            connections.repository.clone(),
            config.callback_destinations.clone(),
            secret,
            callback_config,
            worker_shutdown_rx,
        ))
    });
    runtime.mark_healthy(FlowDependency::CallbackDelivery)?;

    let http = axum::serve(
        http_listener,
        runtime
            .operational_router()
            .merge(flow_read_router(http_state)),
    );
    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    let flow_server = FlowServiceServer::new(grpc_service);
    let mut grpc_builder = Server::builder();
    if let Some(tls) = grpc_security.server_tls_config() {
        grpc_builder = grpc_builder.tls_config(tls)?;
    }
    let (listener_shutdown_tx, listener_shutdown_rx) = watch::channel(false);
    let mut http_shutdown = listener_shutdown_rx.clone();
    let mut grpc_shutdown = listener_shutdown_rx;
    let http = http.with_graceful_shutdown(async move {
        wait_for_shutdown(&mut http_shutdown).await;
    });
    let grpc = grpc_builder
        .add_service(health_service)
        .add_service(flow_server)
        .serve_with_incoming_shutdown(TcpListenerStream::new(grpc_listener), async move {
            wait_for_shutdown(&mut grpc_shutdown).await;
        });

    runtime.activate()?;
    health_reporter
        .set_serving::<FlowServiceServer<FlowGrpcService>>()
        .await;
    info!(
        http_address = %config.http_addr,
        grpc_address = %config.grpc_addr,
        release_version = %config.release_version,
        build_revision = %config.build_revision,
        "native Rust Flow service active"
    );

    let servers = async {
        tokio::try_join!(
            async {
                http.await
                    .map_err(|error| Box::new(error) as Box<dyn Error>)
            },
            async {
                grpc.await
                    .map_err(|error| Box::new(error) as Box<dyn Error>)
            },
        )
        .map(|_| ())
    };
    tokio::pin!(servers);
    let (result, already_draining) = tokio::select! {
        result = &mut servers => (result, false),
        () = shutdown_signal() => {
            info!("Flow shutdown requested");
            runtime.drain()?;
            health_reporter
                .set_not_serving::<FlowServiceServer<FlowGrpcService>>()
                .await;
            let _ = listener_shutdown_tx.send(true);
            (servers.await, true)
        }
    };

    if !already_draining {
        runtime.drain()?;
    }
    health_reporter
        .set_not_serving::<FlowServiceServer<FlowGrpcService>>()
        .await;
    let _ = listener_shutdown_tx.send(true);
    let _ = worker_shutdown_tx.send(true);
    if let Some(worker) = callback_worker {
        match worker.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => error!(%error, "Flow callback dispatcher stopped with an error"),
            Err(error) => error!(%error, "Flow callback dispatcher task failed"),
        }
    }
    runtime.stop()?;
    result?;
    Ok(())
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    while !*shutdown.borrow() && shutdown.changed().await.is_ok() {}
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
        () = ctrl_c => {}
        () = terminate => {}
    }
}
