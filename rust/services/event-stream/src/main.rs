use marty_event_stream::{
    bus::EventBus, config::Config, grpc::EventStreamGrpc, http,
    proto::event_stream_service_server::EventStreamServiceServer,
};
use std::{future::Future, pin::Pin, time::Duration};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_stream::{wrappers::TcpListenerStream, StreamExt};
use tonic::transport::Server;
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
        error!(%error, "invalid event-stream configuration");
        error
    })?;
    let bus = EventBus::default();
    let http_listener = TcpListener::bind(config.http_addr).await?;
    let http_app = http::router(bus.clone());
    let grpc_service = EventStreamGrpc::new(
        bus,
        config.service_token.clone(),
        config.service_authentication_required,
    )?;
    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<EventStreamServiceServer<EventStreamGrpc>>()
        .await;

    info!(http_address = %config.http_addr, grpc_address = %config.grpc_addr, "starting Rust event-stream service");

    let (shutdown_sender, _) = broadcast::channel::<()>(1);
    let shutdown_trigger = shutdown_sender.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_trigger.send(());
    });

    let mut http_shutdown = shutdown_sender.subscribe();
    let http_server = axum::serve(http_listener, http_app).with_graceful_shutdown(async move {
        let _ = http_shutdown.recv().await;
    });

    if config.grpc_enabled {
        let grpc_listener = TcpListener::bind(config.grpc_addr).await?;
        let tls_acceptor = if let Some(files) = &config.grpc_server_tls {
            Some(
                files
                    .grpc_acceptor_without_client_auth(64, Duration::from_secs(15))
                    .await?,
            )
        } else {
            None
        };
        let mut grpc_shutdown = shutdown_sender.subscribe();
        let grpc_router = Server::builder()
            .add_service(health_service)
            .add_service(EventStreamServiceServer::new(grpc_service));
        let grpc_server: Pin<Box<dyn Future<Output = Result<(), tonic::transport::Error>> + Send>> =
            if let Some(acceptor) = tls_acceptor {
                let incoming = TcpListenerStream::new(grpc_listener).then(move |connection| {
                    let acceptor = acceptor.clone();
                    async move {
                        match connection {
                            Ok(stream) => acceptor.accept(stream).await,
                            Err(error) => Err(error),
                        }
                    }
                });
                Box::pin(
                    grpc_router.serve_with_incoming_shutdown(incoming, async move {
                        let _ = grpc_shutdown.recv().await;
                    }),
                )
            } else {
                Box::pin(grpc_router.serve_with_incoming_shutdown(
                    TcpListenerStream::new(grpc_listener),
                    async move {
                        let _ = grpc_shutdown.recv().await;
                    },
                ))
            };
        tokio::try_join!(
            async {
                http_server
                    .await
                    .map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
            },
            async {
                grpc_server
                    .await
                    .map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
            }
        )?;
    } else {
        info!("gRPC listener disabled by EVENT_STREAM_GRPC_ENABLED=false");
        http_server.await?;
    }
    Ok(())
}

async fn shutdown_signal() {
    mmf_runtime::shutdown_signal().await;
    info!("shutdown requested");
}
