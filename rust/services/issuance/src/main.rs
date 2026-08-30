use std::{error::Error, sync::Arc};

use marty_issuance_service::issuance_proto::issuance_service_server::IssuanceServiceServer;
use marty_issuance_service::{
    canvas_award_candidate_approval::{
        CanvasAwardCandidateApprovalService, SecureCanvasAwardApprovalSeedGenerator,
    },
    canvas_award_candidate_approval_postgres::PostgresCanvasAwardApprovalRepository,
    canvas_award_candidate_postgres::PostgresCanvasAwardCandidateRepository,
    canvas_award_candidate_service::{
        CanvasAwardCandidateMaterializerConfig, CanvasAwardCandidateMaterializerService,
        UuidCanvasEvidenceFactIdGenerator,
    },
    canvas_issuance_guard::CanvasGuardConfig,
    canvas_lti_bootstrap::{
        CanvasLtiBootstrapService, SecureCanvasLtiBootstrapApplicationGenerator,
    },
    canvas_lti_deep_linking::{
        CanvasLtiDeepLinkingService, SecureCanvasLtiDeepLinkingNonceGenerator,
    },
    canvas_lti_deep_linking_postgres::PostgresCanvasLtiDeepLinkingRepository,
    canvas_lti_evidence::{CanvasLtiEvidenceService, CanvasLtiEvidenceSyncService},
    canvas_lti_evidence_postgres::PostgresCanvasLtiEvidenceRepository,
    canvas_lti_experience::{
        CanvasLtiExperienceExchangeService, CanvasLtiExperienceSessionService,
        SecureCanvasLtiExperienceSessionGenerator,
    },
    canvas_lti_launch::{
        CanvasLtiExperienceService, CanvasLtiLaunchPorts, CanvasLtiLaunchService,
        SecureCanvasLtiExperienceCodeGenerator, SystemCanvasLtiClock,
    },
    canvas_lti_login::CanvasLtiLoginService,
    canvas_lti_postgres::{
        CanvasLtiJwksRefreshConfig, MartyCanvasLtiAgsServiceUrlValidator,
        PostgresCanvasLtiJwksRefresher, PostgresCanvasLtiLoginRepository,
    },
    canvas_lti_sync_enqueue::{
        PostgresCanvasLtiBootstrapSyncEnqueuer, UuidCanvasSyncEnqueueIdGenerator,
    },
    canvas_lti_tool_signing::{
        HttpCanvasLtiToolIdentityResolver, HttpCanvasLtiToolSignatureProvider,
        IssuerDidCanvasLtiToolJwtSigner,
    },
    canvas_management_domain::CanvasOriginPolicy,
    canvas_management_http::CanvasPlatformManagementHttpService,
    canvas_management_postgres::PostgresCanvasManagementRepository,
    canvas_management_service::CanvasPlatformManagementService,
    canvas_oauth::{CanvasOAuthService, CanvasOAuthServiceConfig},
    canvas_oauth_http::HttpCanvasOAuthProvider,
    canvas_oauth_postgres::{PostgresCanvasOAuthRepository, PostgresIntegrationSecretVault},
    client_auth::RegisteredClientAuthenticator,
    credential::{CredentialIssuanceService, CredentialPorts, UuidNotificationIdGenerator},
    credential_builder::HttpCredentialBuilder,
    credential_issuer::{HttpIssuerContextResolver, NativeCredentialProofVerifier},
    credential_lifecycle::PostgresCredentialLifecycle,
    credential_management::CredentialManagementService,
    credential_management_events::CredentialLifecycleEventBus,
    credential_management_grpc::{CredentialManagementGrpcService, IssuanceGrpcPlatform},
    credential_management_http::CredentialManagementHttpService,
    credential_management_postgres::PostgresCredentialManagementRepository,
    credential_postgres::PostgresCredentialRepository,
    dpop::MartyDpopProofVerifier,
    ephemeral_postgres::PostgresProofNonceRepository,
    http::{
        router_with_all_services, CanvasLtiExperienceSessionServices, CanvasLtiServices,
        CanvasServices, IssuanceCoreServices, IssuanceServices,
    },
    initiation::{
        InitiationPorts, InitiationService, SecureInitiationSeedGenerator, SystemInitiationClock,
    },
    initiation_dependencies::{
        HttpInitiationRelatedResourceValidator, NativeInitiationControlPlane,
        PostgresInitiationApplicationClaimsResolver,
    },
    initiation_didcomm::{
        DidcommEndpointValidator, DidcommTransport, NativeDidcommEnvelope,
        NativeInitiationDidcommDelivery, NativeInitiationDidcommPorts,
    },
    initiation_didcomm_http::InitiationDidcommHttpService,
    initiation_http::InitiationHttpService,
    initiation_response::InitiationOfferProjector,
    integration_secret::IntegrationSecretCipher,
    proof_nonce::{ProofNonceService, SecureProofNonceGenerator},
    signing_policy::HttpProofPolicyResolver,
    tenant_discovery::TenantDiscoveryService,
    tenant_postgres::PostgresTenantDiscoveryRepository,
    token_exchange::{MartyTokenGenerator, TokenExchangeService},
    token_postgres::PostgresTokenExchangeRepository,
    token_rate_limit::TokenRateLimiter,
    transaction_postgres::PostgresTransactionReadRepository,
    transaction_reads::TransactionReadService,
    transport::TransportPolicy,
    validate_embedded_contract, IssuanceRuntime, IssuanceServiceConfig,
};
use marty_oid4vci::discovery::StaticDiscoveryDocuments;
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
        Arc::new(PostgresTransactionReadRepository::new(pool.clone())),
        config.issuance_api_key.as_deref(),
        &config.issuer_base_url,
    );
    let token_hmac_key = config
        .token_hmac_key
        .as_deref()
        .expect("from_env requires TOKEN_HMAC_KEY");
    let token_repository = Arc::new(PostgresTokenExchangeRepository::new(
        pool.clone(),
        token_hmac_key,
    ));
    let token_exchange = TokenExchangeService::new(
        token_repository.clone(),
        Arc::new(RegisteredClientAuthenticator::new(token_repository.clone())),
        Arc::new(MartyDpopProofVerifier),
        Arc::new(MartyTokenGenerator),
        &config.issuer_base_url,
    );
    let nonce_repository = Arc::new(PostgresProofNonceRepository::new(pool.clone()));
    let proof_nonce = ProofNonceService::new(
        nonce_repository.clone(),
        Arc::new(SecureProofNonceGenerator),
    );
    let canvas_lti_repository = Arc::new(PostgresCanvasLtiLoginRepository::new(pool.clone()));
    let integration_secret_cipher = IntegrationSecretCipher::from_base64(
        config
            .integration_secret_master_key
            .as_deref()
            .expect("from_env requires INTEGRATION_SECRET_MASTER_KEY"),
    )?;
    let canvas_oauth = CanvasOAuthService::new(
        Arc::new(PostgresCanvasOAuthRepository::new(pool.clone())),
        Arc::new(PostgresIntegrationSecretVault::new(
            pool.clone(),
            integration_secret_cipher,
        )),
        Arc::new(HttpCanvasOAuthProvider::new(
            std::time::Duration::from_secs(15),
            config.canvas_private_origin_allowlist.clone(),
            config.canvas_allow_private_base_urls,
        )),
        config.issuance_api_key.as_deref(),
        CanvasOAuthServiceConfig {
            issuer_base_url: config.issuer_base_url.clone(),
            completion_base_url: config.canvas_oauth_completion_redirect_url.clone(),
            portable_enabled: config.canvas_portable_enabled,
            pilot_organizations: config.canvas_pilot_organizations.clone(),
            allow_private_networks: config.canvas_allow_private_base_urls,
            allow_http_localhost: config.canvas_allow_http_localhost_base_urls,
        },
    )?;
    let canvas_lti_jwks_refresh_config = CanvasLtiJwksRefreshConfig {
        timeout: config.dependency_timeout,
        ttl: config.canvas_lti_jwks_ttl,
        self_managed_origins: config.canvas_self_managed_origins.clone(),
        allow_private_networks: config.canvas_allow_private_base_urls,
        allow_http_localhost: config.canvas_allow_http_localhost_base_urls,
    };
    let canvas_management =
        CanvasPlatformManagementHttpService::new(CanvasPlatformManagementService::new(
            Arc::new(PostgresCanvasManagementRepository::new(pool.clone())),
            config.issuance_api_key.as_deref(),
            CanvasOriginPolicy {
                allow_http_localhost: config.canvas_allow_http_localhost_base_urls,
                private_origin_allowlist: config.canvas_private_origin_allowlist.clone(),
                self_managed_origin_allowlist: config.canvas_self_managed_origins.clone(),
            },
            &config.issuer_base_url,
            canvas_lti_jwks_refresh_config.clone(),
        ));
    let canvas_lti_login = CanvasLtiLoginService::new(
        canvas_lti_repository.clone(),
        &config.issuer_base_url,
        config.canvas_portable_enabled,
        config.canvas_pilot_organizations.clone(),
        config.canvas_lti_state_ttl,
        config.canvas_self_managed_origins.clone(),
    )?;
    let canvas_lti_clock = Arc::new(SystemCanvasLtiClock);
    let canvas_lti_service_url_validator = Arc::new(MartyCanvasLtiAgsServiceUrlValidator::new(
        config.canvas_private_origin_allowlist.clone(),
    ));
    let canvas_lti_launch = CanvasLtiLaunchService::new(
        canvas_lti_login.clone(),
        CanvasLtiLaunchPorts {
            state_repository: canvas_lti_repository.clone(),
            context_repository: canvas_lti_repository.clone(),
            jwks_refresher: Arc::new(PostgresCanvasLtiJwksRefresher::new(
                pool.clone(),
                canvas_lti_jwks_refresh_config,
            )),
            identity_repository: canvas_lti_repository.clone(),
            ags_repository: canvas_lti_repository.clone(),
            ags_url_validator: canvas_lti_service_url_validator.clone(),
            capability_repository: canvas_lti_repository.clone(),
            clock: canvas_lti_clock.clone(),
        },
    );
    let canvas_lti_experience = CanvasLtiExperienceService::new(
        canvas_lti_launch.clone(),
        canvas_lti_repository.clone(),
        Arc::new(SecureCanvasLtiExperienceCodeGenerator),
        canvas_lti_clock.clone(),
        config.canvas_lti_experience_code_ttl,
        &config.canvas_lti_experience_base_url,
    )?;
    let canvas_lti_experience_exchange = CanvasLtiExperienceExchangeService::new(
        canvas_lti_repository.clone(),
        Arc::new(SecureCanvasLtiExperienceSessionGenerator),
        canvas_lti_clock.clone(),
        config.canvas_lti_experience_session_ttl,
    )?;
    let canvas_lti_experience_session =
        CanvasLtiExperienceSessionService::new(canvas_lti_repository.clone());
    let issuer_resolver = Arc::new(HttpIssuerContextResolver::new(
        config.signing_keys_internal_url.clone(),
        config.signing_keys_internal_api_key.as_deref(),
        config.dependency_timeout,
    )?);
    let canvas_award_approver = Arc::new(CanvasAwardCandidateApprovalService::new(
        Arc::new(PostgresCanvasAwardApprovalRepository::new(pool.clone())),
        issuer_resolver.clone(),
        Arc::new(SecureCanvasAwardApprovalSeedGenerator),
        canvas_lti_clock.clone(),
        config.canvas_readiness_max_age,
    ));
    let canvas_award_materializer = Arc::new(CanvasAwardCandidateMaterializerService::new(
        Arc::new(PostgresCanvasAwardCandidateRepository::new(pool.clone())),
        canvas_award_approver,
        Arc::new(UuidCanvasEvidenceFactIdGenerator),
        canvas_lti_clock.clone(),
        CanvasAwardCandidateMaterializerConfig {
            enabled: config.canvas_portable_enabled,
            pilot_organizations: config.canvas_pilot_organizations.clone(),
            evidence_max_age: config.canvas_evidence_max_age,
        },
    ));
    let canvas_lti_sync_enqueuer = Arc::new(PostgresCanvasLtiBootstrapSyncEnqueuer::new(
        pool.clone(),
        config.canvas_portable_enabled,
        config.canvas_pilot_organizations.clone(),
        Arc::new(UuidCanvasSyncEnqueueIdGenerator),
    ));
    let canvas_lti_bootstrap = CanvasLtiBootstrapService::new(
        canvas_lti_experience_session.clone(),
        canvas_lti_repository.clone(),
        canvas_award_materializer,
        canvas_lti_sync_enqueuer.clone(),
        Arc::new(SecureCanvasLtiBootstrapApplicationGenerator),
        canvas_lti_clock.clone(),
        config.canvas_portable_enabled,
        config.canvas_pilot_organizations.clone(),
    );
    let canvas_lti_tool_signer = Arc::new(IssuerDidCanvasLtiToolJwtSigner::new(
        config.canvas_lti_tool_signing_organization_id.clone(),
        config.canvas_lti_tool_issuer_did.clone(),
        config.signing_keys_internal_api_key.is_some(),
        Arc::new(HttpCanvasLtiToolIdentityResolver::new(
            config.signing_keys_internal_url.clone(),
            config.signing_keys_internal_api_key.as_deref(),
            config.dependency_timeout,
        )?),
        Arc::new(HttpCanvasLtiToolSignatureProvider::new(
            config.signing_keys_internal_url.clone(),
            config.signing_keys_internal_api_key.as_deref(),
            config.dependency_timeout,
        )?),
    ));
    let canvas_lti_deep_linking = CanvasLtiDeepLinkingService::new(
        canvas_lti_experience_session.clone(),
        Arc::new(PostgresCanvasLtiDeepLinkingRepository::new(pool.clone())),
        canvas_lti_service_url_validator,
        canvas_lti_tool_signer.clone(),
        canvas_lti_clock.clone(),
        Arc::new(SecureCanvasLtiDeepLinkingNonceGenerator),
        config.canvas_portable_enabled,
        config.canvas_pilot_organizations.clone(),
        config.canvas_lti_deep_linking_issuer.clone(),
        &config.issuer_base_url,
    );
    let canvas_lti_evidence = CanvasLtiEvidenceService::new(
        canvas_lti_experience_session.clone(),
        Arc::new(PostgresCanvasLtiEvidenceRepository::new(pool.clone())),
        config.canvas_portable_enabled,
        config.canvas_pilot_organizations.clone(),
    );
    let canvas_lti_evidence_sync =
        CanvasLtiEvidenceSyncService::new(canvas_lti_evidence.clone(), canvas_lti_sync_enqueuer);
    let credential_repository = Arc::new(PostgresCredentialRepository::new(
        pool.clone(),
        token_hmac_key,
    ));
    let credential_builder = Arc::new(HttpCredentialBuilder::new(
        config.signing_keys_internal_url.clone(),
        config.signing_keys_internal_api_key.as_deref(),
        config.dependency_timeout,
    )?);
    let credential_lifecycle = Arc::new(PostgresCredentialLifecycle::new(
        pool.clone(),
        config.revocation_profile_service_url.clone(),
        config.internal_service_token.as_deref(),
        config.dependency_timeout,
        CanvasGuardConfig {
            enabled: config.canvas_portable_enabled,
            pilot_organizations: config.canvas_pilot_organizations.clone(),
            evidence_max_age: config.canvas_evidence_max_age,
            readiness_max_age: config.canvas_readiness_max_age,
        },
    )?);
    let didcomm_delivery = Arc::new(NativeInitiationDidcommDelivery::new(
        NativeInitiationDidcommPorts {
            repository: credential_repository.clone(),
            issuer_resolver: issuer_resolver.clone(),
            builder: credential_builder.clone(),
            lifecycle: credential_lifecycle.clone(),
            envelope: Arc::new(NativeDidcommEnvelope::new(
                config.didcomm_universal_resolver_url.as_deref(),
                config.didcomm_did_web_internal_base_url.as_deref(),
                config.didcomm_encryption_policy_file.as_deref(),
            )),
            endpoints: Arc::new(DidcommEndpointValidator::new(
                config.didcomm_allow_private_ips,
            )),
            transport: Arc::new(DidcommTransport::new(
                config.didcomm_tls_ca_file.as_deref(),
            )?),
        },
        &config.issuer_base_url,
    )?);
    let didcomm_http = InitiationDidcommHttpService::new(
        didcomm_delivery.clone(),
        config.issuance_api_key.as_deref(),
    );
    let initiation_control_plane = Arc::new(NativeInitiationControlPlane::connect_lazy(
        &config.organization_grpc_target,
        &config.credential_template_grpc_target,
        &config.revocation_profile_grpc_target,
        config.credential_template_service_url.clone(),
        config.internal_service_token.as_deref(),
        config.dependency_timeout,
    )?);
    let initiation = InitiationService::new(
        InitiationPorts {
            repository: credential_repository.clone(),
            organizations: initiation_control_plane.clone(),
            clients: token_repository,
            templates: initiation_control_plane.clone(),
            revocation_profiles: initiation_control_plane,
            applications: Arc::new(PostgresInitiationApplicationClaimsResolver::new(
                pool.clone(),
            )),
            related_resources: Arc::new(HttpInitiationRelatedResourceValidator::new(
                config.vcdm_related_resource_urls.clone(),
                config.vcdm_related_resource_max_bytes,
                config.vcdm_related_resource_timeout,
            )?),
            issuer_resolver: issuer_resolver.clone(),
            seeds: Arc::new(SecureInitiationSeedGenerator),
            clock: Arc::new(SystemInitiationClock),
        },
        config.issuer_base_url.clone(),
    )?;
    let initiation_projector =
        InitiationOfferProjector::new(config.issuer_base_url.clone(), didcomm_delivery)?;
    let initiation_http = InitiationHttpService::new(
        initiation.clone(),
        initiation_projector.clone(),
        config.issuance_api_key.as_deref(),
    );
    let credential = CredentialIssuanceService::new(
        CredentialPorts {
            repository: credential_repository.clone(),
            nonce_repository,
            dpop_verifier: Arc::new(MartyDpopProofVerifier),
            proof_verifier: Arc::new(NativeCredentialProofVerifier),
            issuer_resolver: issuer_resolver.clone(),
            builder: credential_builder.clone(),
            lifecycle: credential_lifecycle.clone(),
            notification_ids: Arc::new(UuidNotificationIdGenerator),
        },
        &config.issuer_base_url,
    );
    let lifecycle_events = CredentialLifecycleEventBus::default();
    let credential_management = CredentialManagementService::new(
        Arc::new(PostgresCredentialManagementRepository::new(pool.clone())),
        Arc::new(credential_lifecycle.status_publisher()),
        Arc::new(lifecycle_events.clone()),
    );
    let credential_management_http = CredentialManagementHttpService::new(
        credential_management.clone(),
        config.issuance_api_key.as_deref(),
    );
    let grpc_platform = IssuanceGrpcPlatform::new(
        initiation,
        initiation_projector,
        token_exchange.clone(),
        credential.clone(),
        transaction_reads.clone(),
        &config.issuer_base_url,
    );
    let grpc_service = CredentialManagementGrpcService::new(
        credential_management,
        lifecycle_events,
        grpc_platform,
        config.internal_service_token.as_deref(),
    );
    let http_listener = TcpListener::bind(config.http_addr).await?;
    runtime.mark_http_listener_healthy()?;
    let grpc_enabled = config.grpc_enabled;
    let grpc_listener = if grpc_enabled {
        let listener = TcpListener::bind(config.grpc_addr).await?;
        runtime.mark_grpc_listener_healthy()?;
        Some(listener)
    } else {
        None
    };
    let transport = TransportPolicy::new(config.cors_allowed_origins.clone());
    let app = router_with_all_services(
        runtime.state(),
        discovery,
        transport,
        IssuanceServices::new(
            IssuanceCoreServices::new(
                tenant_discovery,
                transaction_reads,
                token_exchange,
                proof_nonce,
                credential,
                initiation_http,
                didcomm_http,
            ),
            credential_management_http,
            CanvasServices::new(
                canvas_oauth,
                canvas_management,
                CanvasLtiServices::new(
                    canvas_lti_login,
                    canvas_lti_launch,
                    canvas_lti_experience,
                    canvas_lti_experience_exchange,
                    CanvasLtiExperienceSessionServices::new(
                        canvas_lti_experience_session,
                        canvas_lti_bootstrap,
                        canvas_lti_deep_linking,
                        canvas_lti_evidence,
                        canvas_lti_evidence_sync,
                    ),
                    canvas_lti_tool_signer,
                ),
            ),
            TokenRateLimiter::new(config.token_rate_limit, config.token_rate_window),
        ),
    );
    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    let grpc_server = IssuanceServiceServer::new(grpc_service);
    let (listener_shutdown_tx, listener_shutdown_rx) = watch::channel(false);
    let mut http_shutdown = listener_shutdown_rx.clone();
    let mut grpc_shutdown = listener_shutdown_rx;
    let http = axum::serve(
        http_listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        wait_for_shutdown(&mut http_shutdown).await;
    });
    let grpc = async move {
        let Some(grpc_listener) = grpc_listener else {
            wait_for_shutdown(&mut grpc_shutdown).await;
            return Ok(());
        };
        Server::builder()
            .add_service(health_service)
            .add_service(grpc_server)
            .serve_with_incoming_shutdown(TcpListenerStream::new(grpc_listener), async move {
                wait_for_shutdown(&mut grpc_shutdown).await;
            })
            .await
    };
    runtime.activate()?;
    if grpc_enabled {
        health_reporter
            .set_serving::<IssuanceServiceServer<CredentialManagementGrpcService>>()
            .await;
    }
    info!(
        http_address = %config.http_addr,
        grpc_address = %config.grpc_addr,
        grpc_enabled,
        release_version = %config.release_version,
        build_revision = %config.build_revision,
        "native Rust issuance service active"
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
            info!("Issuance shutdown requested");
            runtime.drain()?;
            if grpc_enabled {
                health_reporter
                    .set_not_serving::<IssuanceServiceServer<CredentialManagementGrpcService>>()
                    .await;
            }
            let _ = listener_shutdown_tx.send(true);
            (servers.await, true)
        }
    };
    let _ = listener_shutdown_tx.send(true);
    if grpc_enabled {
        health_reporter
            .set_not_serving::<IssuanceServiceServer<CredentialManagementGrpcService>>()
            .await;
    }
    if !already_draining {
        runtime.drain()?;
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
