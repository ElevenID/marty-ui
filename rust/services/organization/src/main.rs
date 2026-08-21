use std::{error::Error, sync::Arc, time::Duration};

use marty_organization::{
    organization_core_router,
    organization_proto::organization_service_server::OrganizationServiceServer,
    postgres::PostgresOrganizationStore, reconcile_organization_startup, EventStreamTransport,
    MembershipPolicy, OrganizationApplication, OrganizationCache, OrganizationDependency,
    OrganizationGrpcService, OrganizationHttpState, OrganizationRuntime, OrganizationServiceConfig,
    ORGANIZATION_CEDAR_SCHEMA,
};
use mmf_data::{CacheBackend, CacheConfig, RedisCache};
use mmf_messaging::{run_outbox_dispatcher, MessageTransport};
use mmf_security::{CedarConfig, CedarPolicyValidator, ServiceTokenAuthenticator};
use sqlx::postgres::PgPoolOptions;
use tokio::{net::TcpListener, sync::watch};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = OrganizationServiceConfig::from_env().map_err(|error| {
        error!(%error, "invalid Organization configuration");
        error
    })?;
    let runtime = OrganizationRuntime::new(&config)?;
    let pool = PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .connect(&config.database_url)
        .await?;
    runtime.mark_healthy(OrganizationDependency::Database)?;

    let redis = RedisCache::connect(
        CacheConfig {
            backend: CacheBackend::Redis,
            url: Some(config.redis_url.clone()),
            database: config.redis_database,
            namespace: "organization".into(),
            ..CacheConfig::default()
        },
        config.environment == marty_organization::OrganizationEnvironment::Production,
    )
    .await?;
    let cache = OrganizationCache::from_redis(&redis)?;
    runtime.mark_healthy(OrganizationDependency::Redis)?;

    let validator = Arc::new(CedarPolicyValidator::from_human_schema(
        ORGANIZATION_CEDAR_SCHEMA,
        CedarConfig::default(),
    )?);
    runtime.mark_healthy(OrganizationDependency::PolicyValidation)?;
    let membership_policy = MembershipPolicy::new(
        Some(config.marty_organization_id),
        config.marty_admin_email.clone(),
    );
    let application = Arc::new(
        OrganizationApplication::new(PostgresOrganizationStore::new(pool), cache)?
            .with_membership_policy(membership_policy)
            .with_policy_validator(validator),
    );
    application.initialize().await?;
    application.outbox().health().await?;
    runtime.mark_healthy(OrganizationDependency::TransactionalOutbox)?;

    let startup = reconcile_organization_startup(
        application.store(),
        config.marty_organization_id,
        config.marty_admin_email.as_deref(),
        config.marty_reviewer_email.as_deref(),
        chrono::Utc::now(),
    )
    .await?;
    info!(
        organizations = startup.organizations_reconciled,
        bootstrap_memberships = startup.bootstrap_memberships_reconciled,
        "Organization startup state reconciled"
    );

    let event_transport = Arc::new(EventStreamTransport::new(
        &config.event_stream_target,
        Duration::from_secs(config.event_stream_timeout_seconds),
    ));
    match event_transport.connect().await {
        Ok(()) => runtime.mark_healthy(OrganizationDependency::EventStream)?,
        Err(error) => {
            warn!(%error, "event stream unavailable; durable outbox will retry");
            runtime.mark_degraded(OrganizationDependency::EventStream, error.to_string())?;
        }
    }

    let service_authenticator = Arc::new(ServiceTokenAuthenticator::new(
        config.service_token.clone(),
        config.environment.is_deployed(),
    )?);
    let http_state = OrganizationHttpState {
        application: Arc::clone(&application),
        service_authenticator,
        organization_creation_enabled: config.organization_creation_enabled,
        marty_organization_id: Some(config.marty_organization_id),
    };
    let grpc_service = OrganizationGrpcService::new(
        Arc::clone(&application),
        config.service_token.clone(),
        config.environment.is_deployed(),
    )?;

    let http_listener = TcpListener::bind(config.http_addr).await?;
    runtime.mark_healthy(OrganizationDependency::HttpListener)?;
    let grpc_listener = TcpListener::bind(config.grpc_addr).await?;
    runtime.mark_healthy(OrganizationDependency::GrpcListener)?;

    let (worker_shutdown_tx, worker_shutdown_rx) = watch::channel(false);
    let outbox_worker = tokio::spawn(run_outbox_dispatcher(
        Arc::new(application.outbox().clone()),
        event_transport as Arc<dyn MessageTransport>,
        config.outbox.clone(),
        worker_shutdown_rx,
    ));
    let http = axum::serve(
        http_listener,
        runtime
            .operational_router()
            .merge(organization_core_router(http_state)),
    );
    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    let organization_server = OrganizationServiceServer::new(grpc_service);
    let (listener_shutdown_tx, listener_shutdown_rx) = watch::channel(false);
    let mut http_shutdown = listener_shutdown_rx.clone();
    let mut grpc_shutdown = listener_shutdown_rx;
    let http = http.with_graceful_shutdown(async move {
        wait_for_shutdown(&mut http_shutdown).await;
    });
    let grpc = Server::builder()
        .add_service(health_service)
        .add_service(organization_server)
        .serve_with_incoming_shutdown(TcpListenerStream::new(grpc_listener), async move {
            wait_for_shutdown(&mut grpc_shutdown).await;
        });

    runtime.activate()?;
    health_reporter
        .set_serving::<OrganizationServiceServer<OrganizationGrpcService>>()
        .await;
    info!(
        http_address = %config.http_addr,
        grpc_address = %config.grpc_addr,
        release_version = %config.release_version,
        build_revision = %config.build_revision,
        "native Rust Organization service active"
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
    let result = tokio::select! {
        result = &mut servers => result,
        () = shutdown_signal() => {
            info!("Organization shutdown requested");
            runtime.drain()?;
            health_reporter
                .set_not_serving::<OrganizationServiceServer<OrganizationGrpcService>>()
                .await;
            let _ = listener_shutdown_tx.send(true);
            servers.await
        }
    };

    let _ = listener_shutdown_tx.send(true);
    let _ = worker_shutdown_tx.send(true);
    health_reporter
        .set_not_serving::<OrganizationServiceServer<OrganizationGrpcService>>()
        .await;
    match outbox_worker.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => error!(%error, "Organization outbox dispatcher stopped with an error"),
        Err(error) => error!(%error, "Organization outbox dispatcher task failed"),
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
