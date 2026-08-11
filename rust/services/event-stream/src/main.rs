use marty_event_stream::{
    bus::EventBus, config::Config, grpc::EventStreamGrpc, http,
    proto::event_stream_service_server::EventStreamServiceServer,
};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
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
    let grpc_service = EventStreamGrpc::new(bus);
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
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
        let mut grpc_shutdown = shutdown_sender.subscribe();
        let grpc_server = Server::builder()
            .add_service(health_service)
            .add_service(EventStreamServiceServer::new(grpc_service))
            .serve_with_shutdown(config.grpc_addr, async move {
                let _ = grpc_shutdown.recv().await;
            });
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
