use std::{error::Error, sync::Arc};

use axum::middleware;
use marty_auth::{
    auth_core_router, auth_proto::auth_service_server::AuthServiceServer,
    auth_rate_limit_middleware, workload_server_tls, AuthApplication, AuthApplicationConfig,
    AuthApplicationPorts, AuthCacheKeySpace, AuthCacheRepository, AuthConnections, AuthDependency,
    AuthGrpcService, AuthHttpState, AuthRateLimiter, AuthRuntime, AuthServiceConfig,
    CanvasLtiApplication, CredentialAccountResolver, CredentialCallbackApplication,
    CredentialCallbackConfig, CredentialCallbackPolicy, CredentialIdentityProvisioner,
    CredentialLoginHttpApplication, CredentialLoginStartConfig, CredentialLoginStateStore,
    ExchangedTokenValidator, HttpCanvasExperienceSessionProvider, JitProvisioningConfig,
    JitUserProvisioner, KeycloakAdminAdapter, MmfApplicantProfileProvisioner,
    MmfAuthOutboxPublisher, PkceStateRepository, PostgresAuthRepository,
    RustCredentialLoginPageRenderer, SessionRepository, UserProvisioner,
};
use mmf_messaging::{run_outbox_dispatcher, MessageTransport};
use tokio::{net::TcpListener, sync::watch};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = AuthServiceConfig::from_env().map_err(|error| {
        error!(%error, "invalid Auth configuration");
        error
    })?;
    let runtime = AuthRuntime::new(&config)?;
    let connections = AuthConnections::connect(&config, &runtime).await?;
    let components = assemble_applications(&config, &connections)?;

    let http_listener = TcpListener::bind(config.http_addr).await?;
    runtime.mark_healthy(AuthDependency::HttpListener)?;
    let grpc_listener = TcpListener::bind(config.grpc_addr).await?;
    runtime.mark_healthy(AuthDependency::GrpcListener)?;

    let limiter = Arc::new(AuthRateLimiter::new(
        connections.rate_limiter.clone(),
        config.auth_rate_limit_rpm,
    )?);
    let http_router = runtime
        .operational_router()
        .merge(auth_core_router(components.http_state)?)
        .layer(middleware::from_fn_with_state(
            limiter,
            auth_rate_limit_middleware,
        ));
    let http = axum::serve(
        http_listener,
        http_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    );

    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    let auth_server = AuthServiceServer::new(AuthGrpcService::new(components.application));
    let mut grpc_builder = Server::builder();
    if let Some(tls) = workload_server_tls(&config)? {
        grpc_builder = grpc_builder.tls_config(tls.server_tls_config())?;
    }

    let (listener_shutdown_tx, listener_shutdown_rx) = watch::channel(false);
    let mut http_shutdown = listener_shutdown_rx.clone();
    let mut grpc_shutdown = listener_shutdown_rx;
    let http = http.with_graceful_shutdown(async move {
        wait_for_shutdown(&mut http_shutdown).await;
    });
    let grpc = grpc_builder
        .add_service(health_service)
        .add_service(auth_server)
        .serve_with_incoming_shutdown(TcpListenerStream::new(grpc_listener), async move {
            wait_for_shutdown(&mut grpc_shutdown).await;
        });

    let (worker_shutdown_tx, worker_shutdown_rx) = watch::channel(false);
    let outbox_worker = tokio::spawn(run_outbox_dispatcher(
        connections.outbox.clone(),
        connections.event_transport.clone() as Arc<dyn MessageTransport>,
        config.outbox.clone(),
        worker_shutdown_rx,
    ));

    runtime.activate()?;
    health_reporter
        .set_serving::<AuthServiceServer<AuthGrpcService>>()
        .await;
    info!(
        http_address = %config.http_addr,
        grpc_address = %config.grpc_addr,
        release_version = %config.release_version,
        build_revision = %config.build_revision,
        "native Rust Auth service active"
    );

    let servers = async {
        tokio::try_join!(
            async {
                http.await
                    .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync>)
            },
            async {
                grpc.await
                    .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync>)
            },
        )
        .map(|_| ())
    };
    tokio::pin!(servers);
    let result = tokio::select! {
        result = &mut servers => result,
        () = shutdown_signal() => {
            info!("Auth shutdown requested");
            runtime.drain()?;
            health_reporter
                .set_not_serving::<AuthServiceServer<AuthGrpcService>>()
                .await;
            let _ = listener_shutdown_tx.send(true);
            servers.await
        }
    };

    let _ = listener_shutdown_tx.send(true);
    let _ = worker_shutdown_tx.send(true);
    health_reporter
        .set_not_serving::<AuthServiceServer<AuthGrpcService>>()
        .await;
    match outbox_worker.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => error!(%error, "Auth outbox dispatcher stopped with an error"),
        Err(error) => error!(%error, "Auth outbox dispatcher task failed"),
    }
    runtime.stop()?;
    result?;
    Ok(())
}

struct AuthComponents {
    application: Arc<AuthApplication>,
    http_state: AuthHttpState,
}

fn assemble_applications(
    config: &AuthServiceConfig,
    connections: &AuthConnections,
) -> Result<AuthComponents, Box<dyn Error + Send + Sync>> {
    let cache_repository = Arc::new(AuthCacheRepository::new(
        connections.cache.clone(),
        AuthCacheKeySpace::default(),
    ));
    let sessions: Arc<dyn SessionRepository> = cache_repository.clone();
    let pkce_states: Arc<dyn PkceStateRepository> = cache_repository;
    let postgres = Arc::new(PostgresAuthRepository::new(connections.pool.clone()));
    let organizations = Arc::new(
        connections
            .grpc_clients
            .organization_provisioning(config.default_organization_id.clone()),
    );
    let provisioner = Arc::new(JitUserProvisioner::new(
        postgres.clone(),
        organizations,
        JitProvisioningConfig {
            default_organization_id: config.default_organization_id.clone(),
            default_organization_slug: config.default_organization_slug.clone(),
            default_organization_name: config.default_organization_name.clone(),
        },
    ));
    let user_provisioner: Arc<dyn UserProvisioner> = provisioner.clone();
    let credential_provisioner: Arc<dyn CredentialIdentityProvisioner> = provisioner;
    let event_publisher = Arc::new(MmfAuthOutboxPublisher::new(connections.outbox.clone()));
    let application = Arc::new(AuthApplication::new(
        AuthApplicationPorts {
            sessions: sessions.clone(),
            pkce_states,
            oidc: connections.oidc.clone(),
            provisioner: user_provisioner,
            events: event_publisher,
            audit: Some(postgres.clone()),
        },
        AuthApplicationConfig {
            session_ttl_seconds: config.session_ttl_seconds,
            post_logout_redirect_uri: config.post_logout_redirect_uri.clone(),
        },
    ));

    let canvas_provider = Arc::new(HttpCanvasExperienceSessionProvider::new(
        connections.outbound_http.clone(),
        &config.issuance_service_url,
    )?);
    let applicant_profile = Arc::new(MmfApplicantProfileProvisioner::new(
        connections.outbound_http.clone(),
        config.applicant_service_url.clone(),
    )?);
    let canvas = Arc::new(CanvasLtiApplication::new(
        canvas_provider,
        sessions.clone(),
        Some(applicant_profile),
        config.session_ttl_seconds,
    )?);

    let credential_state = Arc::new(CredentialLoginStateStore::new(
        connections.cache.clone(),
        CredentialCallbackPolicy {
            secret: config.credential_login_webhook_secret.clone(),
            expected_policy_id: config.credential_login_policy_id.clone(),
            expected_organization_id: config.credential_login_organization_id.clone(),
            maximum_timestamp_skew_seconds: config.credential_callback_timestamp_skew_seconds,
            pending_ttl_seconds: config.credential_login_pending_ttl_seconds,
            completion_ttl_seconds: config.credential_login_completion_ttl_seconds,
            claim_lease_seconds: config.credential_login_claim_lease_seconds,
        },
    )?);
    let accounts = keycloak_accounts(config, connections)?;
    let credential_callback = Arc::new(CredentialCallbackApplication::new(
        credential_state.clone(),
        sessions.clone(),
        accounts,
        Some(credential_provisioner),
        CredentialCallbackConfig {
            default_organization_id: config.default_organization_id.clone(),
            session_ttl_seconds: config.session_ttl_seconds,
            require_existing_keycloak_user: config.credential_login_require_existing_keycloak_user,
            create_keycloak_users: config.credential_login_create_users,
        },
    ));
    let credential_login = Arc::new(CredentialLoginHttpApplication::new(
        credential_state,
        credential_callback,
        Arc::new(connections.grpc_clients.credential_verification()),
        Arc::new(RustCredentialLoginPageRenderer::from_environment()),
        CredentialLoginStartConfig {
            presentation_policy_id: config.credential_login_policy_id.clone(),
            organization_id: config.credential_login_organization_id.clone(),
            issuer_did: config.credential_login_issuer_did.clone(),
            auth_service_internal_url: config.auth_service_internal_url.clone(),
        },
    )?);

    let http_state = AuthHttpState {
        application: application.clone(),
        canvas,
        credential_login,
        sessions,
        origins: config.ui_origins.clone(),
        cookie: config.cookie.clone(),
        canvas_session_ttl_seconds: config.canvas_lti_session_ttl_seconds,
        impersonation_handoff_cookie_name: config.impersonation_handoff_cookie_name.clone(),
    };
    Ok(AuthComponents {
        application,
        http_state,
    })
}

fn keycloak_accounts(
    config: &AuthServiceConfig,
    connections: &AuthConnections,
) -> Result<Option<Arc<dyn CredentialAccountResolver>>, Box<dyn Error + Send + Sync>> {
    let Some(admin_config) = config.keycloak_admin.clone() else {
        return Ok(None);
    };
    let token_validator: Arc<dyn ExchangedTokenValidator> = connections.oidc.clone();
    let adapter = KeycloakAdminAdapter::with_reqwest(admin_config, token_validator)?;
    Ok(Some(Arc::new(adapter)))
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
