use std::{error::Error, sync::Arc, time::Duration};

use marty_presentation_policy::{
    migrate_presentation_policy_schema,
    presentation_policy_proto::presentation_policy_service_server::PresentationPolicyServiceServer,
    presentation_policy_router, reconcile_builtin_policies, validate_presentation_policy_schema,
    CredentialStatusResolver, CredentialVerificationKernel, NativePresentationControlPlane,
    PolicyApplication, PolicyAuthorization, PolicyRepository, PostgresPolicyStore,
    PresentationGrpcSecurity, PresentationPolicyDependency, PresentationPolicyGrpcService,
    PresentationPolicyHttpState, PresentationPolicyRuntime, PresentationPolicyServiceConfig,
    PresentationTrustResolver, RustCredentialKernel, VerifiedFactsOrchestrator,
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
    let config = PresentationPolicyServiceConfig::from_env().map_err(|error| {
        error!(%error, "invalid Presentation Policy configuration");
        error
    })?;
    let runtime = PresentationPolicyRuntime::new(&config)?;
    let pool = PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&config.database_url)
        .await?;
    runtime.mark_healthy(PresentationPolicyDependency::Database)?;
    migrate_presentation_policy_schema(&pool).await?;
    validate_presentation_policy_schema(&pool).await?;
    runtime.mark_healthy(PresentationPolicyDependency::Schema)?;

    let control = Arc::new(NativePresentationControlPlane::connect_lazy(
        &config.organization_grpc_target,
        &config.trust_profile_url,
        &config.credential_status_url_template,
        config.service_token.as_deref(),
        config.issuance_api_key.as_deref(),
        config.managed_issuers.clone(),
        config.dependency_timeout,
    )?);
    runtime.mark_healthy(PresentationPolicyDependency::ControlPlane)?;

    let store = Arc::new(PostgresPolicyStore::new(pool));
    reconcile_builtin_policies(store.as_ref()).await?;
    let repository: Arc<dyn PolicyRepository> = store;
    let authorization: Arc<dyn PolicyAuthorization> = control.clone();
    let application = Arc::new(PolicyApplication::new(repository, authorization));
    let kernel: Arc<dyn CredentialVerificationKernel> = Arc::new(RustCredentialKernel);
    let trust: Arc<dyn PresentationTrustResolver> = control.clone();
    let status: Arc<dyn CredentialStatusResolver> = control;
    let verification = Arc::new(VerifiedFactsOrchestrator::new(kernel, trust, status));
    runtime.mark_healthy(PresentationPolicyDependency::NativeVerification)?;

    let service_authenticator = Arc::new(ServiceTokenAuthenticator::new(
        config.service_token.clone(),
        config.service_authentication_required(),
    )?);
    let http_state = PresentationPolicyHttpState {
        application: Arc::clone(&application),
        verification: verification.clone(),
        service_authenticator,
    };
    let grpc_security = Arc::new(PresentationGrpcSecurity::from_config(&config)?);
    let grpc_service = PresentationPolicyGrpcService::new(
        application,
        verification,
        config.service_token.clone(),
        config.service_authentication_required(),
    )?
    .with_workload_security(Arc::clone(&grpc_security));

    let http_listener = TcpListener::bind(config.http_addr).await?;
    runtime.mark_healthy(PresentationPolicyDependency::HttpListener)?;
    let grpc_listener = TcpListener::bind(config.grpc_addr).await?;
    runtime.mark_healthy(PresentationPolicyDependency::GrpcListener)?;
    let http_app = runtime
        .operational_router()
        .merge(presentation_policy_router(http_state))
        .layer(TraceLayer::new_for_http());
    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    let grpc_server = PresentationPolicyServiceServer::new(grpc_service);
    let mut grpc_builder = Server::builder();
    if let Some(tls) = grpc_security.server_tls_config() {
        grpc_builder = grpc_builder.tls_config(tls)?;
    }
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut http_shutdown = shutdown_rx.clone();
    let mut grpc_shutdown = shutdown_rx;
    let http = axum::serve(http_listener, http_app).with_graceful_shutdown(async move {
        wait_for_shutdown(&mut http_shutdown).await;
    });
    let grpc = grpc_builder
        .add_service(health_service)
        .add_service(grpc_server)
        .serve_with_incoming_shutdown(TcpListenerStream::new(grpc_listener), async move {
            wait_for_shutdown(&mut grpc_shutdown).await;
        });
    runtime.activate()?;
    health_reporter
        .set_serving::<PresentationPolicyServiceServer<PresentationPolicyGrpcService>>()
        .await;
    info!(http_address=%config.http_addr, grpc_address=%config.grpc_addr, "native Rust Presentation Policy service active");

    tokio::select! {
        result = http => result?,
        result = grpc => result?,
        () = shutdown_signal() => {
            runtime.drain()?;
            let _ = shutdown_tx.send(true);
        }
    }
    let _ = shutdown_tx.send(true);
    runtime.stop()?;
    Ok(())
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
