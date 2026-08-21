use std::{error::Error, sync::Arc, time::Duration};

use marty_credential_template::{
    application::{
        CredentialTemplateApplication, CredentialTemplateControlPlane, CredentialTemplateRepository,
    },
    catalog::seed_system_catalog,
    config::CredentialTemplateServiceConfig,
    control_plane::NativeCredentialTemplateControlPlane,
    credential_template_proto::credential_template_service_server::CredentialTemplateServiceServer,
    grpc_service::CredentialTemplateGrpcService,
    http_service::{credential_template_router, CredentialTemplateHttpState},
    migration::{
        migrate_credential_template_schema, reconcile_credential_template_data,
        CredentialTemplateDataReconciliationConfig,
    },
    registry_application::{
        CredentialTemplateRegistryApplication, CredentialTemplateRegistryRepository,
    },
    runtime::{CredentialTemplateDependency, CredentialTemplateRuntime},
    PostgresCredentialTemplateStore,
};
use mmf_security::ServiceTokenAuthenticator;
use sqlx::postgres::PgPoolOptions;
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

    let config = CredentialTemplateServiceConfig::from_env().map_err(|error| {
        error!(%error, "invalid Credential Template configuration");
        error
    })?;
    let runtime = CredentialTemplateRuntime::new(&config)?;
    let pool = PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&config.database_url)
        .await?;
    runtime.mark_healthy(CredentialTemplateDependency::Database)?;

    migrate_credential_template_schema(&pool).await?;
    let public_hostname = config
        .public_api_origin
        .host_str()
        .ok_or("PUBLIC_API_URL must include a hostname")?
        .to_owned();
    let reconciliation = reconcile_credential_template_data(
        &pool,
        &CredentialTemplateDataReconciliationConfig {
            marty_organization_id: config.marty_organization_id.to_string(),
            public_api_origin: config.public_api_origin.to_string(),
            public_hostname,
            selfhost_production: config.migration_profile == "selfhost-production",
        },
    )
    .await?;
    info!(
        public_vcts_repaired = reconciliation.public_vcts_repaired,
        issuer_dids_repaired = reconciliation.issuer_dids_repaired,
        revocation_profiles_repaired = reconciliation.revocation_profiles_repaired,
        templates_deprecated = reconciliation.templates_deprecated,
        selfhost_templates_archived = reconciliation.selfhost_templates_archived,
        "Credential Template legacy data reconciled"
    );
    runtime.mark_healthy(CredentialTemplateDependency::Schema)?;
    let store = Arc::new(PostgresCredentialTemplateStore::new(pool));
    let seeded = seed_system_catalog(&store, chrono::Utc::now()).await?;
    info!(
        wallets_inserted = seeded.wallets_inserted,
        wallets_reconciled = seeded.wallets_reconciled,
        destinations_inserted = seeded.destinations_inserted,
        destinations_reconciled = seeded.destinations_reconciled,
        "Credential Template system catalog reconciled"
    );
    runtime.mark_healthy(CredentialTemplateDependency::SystemCatalog)?;

    let control_plane: Arc<dyn CredentialTemplateControlPlane> =
        Arc::new(NativeCredentialTemplateControlPlane::connect_lazy(
            &config.organization_grpc_target,
            &config.revocation_grpc_target,
            config.service_token.as_deref(),
            config.signing_keys_internal_url.clone(),
            config.signing_keys_internal_api_key.as_deref(),
            config.trust_profile_service_url.clone(),
            config.dependency_timeout,
        )?);
    runtime.mark_healthy(CredentialTemplateDependency::ControlPlane)?;
    let template_repository: Arc<dyn CredentialTemplateRepository> = store.clone();
    let registry_repository: Arc<dyn CredentialTemplateRegistryRepository> = store;
    let application = Arc::new(CredentialTemplateApplication::new(
        Arc::clone(&template_repository),
        Arc::clone(&control_plane),
    ));
    let registry_application = Arc::new(CredentialTemplateRegistryApplication::new(
        template_repository,
        registry_repository,
        control_plane,
    ));

    let service_authenticator = Arc::new(ServiceTokenAuthenticator::new(
        config.service_token.clone(),
        config.service_authentication_required(),
    )?);
    let http_state = CredentialTemplateHttpState {
        application: Arc::clone(&application),
        registry_application: Arc::clone(&registry_application),
        service_authenticator,
        environment: config.environment,
    };
    let grpc_service = CredentialTemplateGrpcService::new(
        application,
        registry_application,
        config.service_token.clone(),
        config.service_authentication_required(),
    )?;

    let http_listener = TcpListener::bind(config.http_addr).await?;
    runtime.mark_healthy(CredentialTemplateDependency::HttpListener)?;
    let grpc_listener = TcpListener::bind(config.grpc_addr).await?;
    runtime.mark_healthy(CredentialTemplateDependency::GrpcListener)?;

    let http_app = runtime
        .operational_router()
        .merge(credential_template_router(http_state))
        .layer(TraceLayer::new_for_http());
    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    let grpc_server = CredentialTemplateServiceServer::new(grpc_service);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut http_shutdown = shutdown_rx.clone();
    let mut grpc_shutdown = shutdown_rx;
    let http = axum::serve(http_listener, http_app).with_graceful_shutdown(async move {
        wait_for_shutdown(&mut http_shutdown).await;
    });
    let grpc = Server::builder()
        .add_service(health_service)
        .add_service(grpc_server)
        .serve_with_incoming_shutdown(TcpListenerStream::new(grpc_listener), async move {
            wait_for_shutdown(&mut grpc_shutdown).await;
        });

    runtime.activate()?;
    health_reporter
        .set_serving::<CredentialTemplateServiceServer<CredentialTemplateGrpcService>>()
        .await;
    info!(
        http_address = %config.http_addr,
        grpc_address = %config.grpc_addr,
        release_version = %config.release_version,
        build_revision = %config.build_revision,
        "native Rust Credential Template service active"
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
            info!("Credential Template shutdown requested");
            runtime.drain()?;
            health_reporter
                .set_not_serving::<CredentialTemplateServiceServer<CredentialTemplateGrpcService>>()
                .await;
            let _ = shutdown_tx.send(true);
            servers.await
        }
    };
    let _ = shutdown_tx.send(true);
    health_reporter
        .set_not_serving::<CredentialTemplateServiceServer<CredentialTemplateGrpcService>>()
        .await;
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
