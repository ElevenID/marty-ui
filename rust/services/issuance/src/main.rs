use marty_service_runtime::{shutdown_signal_best_effort as shutdown_signal, wait_for_shutdown};
use marty_signing_grant::SigningOrigin;
use std::{error::Error, future::Future, pin::Pin, sync::Arc, time::Duration};

use marty_issuance_service::issuance_proto::issuance_service_server::IssuanceServiceServer;
use marty_issuance_service::{
    application_issuance::{SecureApprovalSeedGenerator, SystemApplicationClock},
    application_template_catalog::runtime_catalog,
    application_template_postgres::PostgresApplicationTemplateRepository,
    application_template_service::{ApplicationTemplateService, SystemApplicationTemplateClock},
    canvas_award_candidate_approval::CanvasApplicationApprovalService,
    canvas_award_candidate_approval_postgres::PostgresCanvasAwardApprovalRepository,
    canvas_issuance_guard::CanvasGuardConfig,
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
    credential_renewal::CredentialRenewalService,
    dependency_probe,
    didcomm_kms::RegisteredDidcommKms,
    dpop::MartyDpopProofVerifier,
    ephemeral_postgres::PostgresProofNonceRepository,
    http::{
        router_with_all_services, IssuanceCoreServices, IssuanceReadServices, IssuanceServices,
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
    internal_application_approval::{
        CompositeInternalApplicationApprover, CompositeInternalApplicationTransactionPreparer,
        OrdinaryInternalApplicationApprover,
    },
    internal_application_evidence::DefaultInternalApplicationEvidenceCoordinator,
    internal_application_offer::{
        InternalApplicationOfferProjector, NativeInternalApplicationOfferCoordinator,
    },
    internal_application_postgres::PostgresInternalApplicationRepository,
    internal_application_reconciliation::{
        CanvasEvidenceReconciliationPreparer, DefaultInternalApplicationReconciler,
    },
    internal_application_service::{
        InternalApplicationService, SystemInternalApplicationClock,
        UuidInternalApplicationIdGenerator,
    },
    issued_credential_postgres::PostgresIssuedCredentialRecordRepository,
    issued_credential_records::{IssuedCredentialAdapterService, SystemIssuedCredentialClock},
    migration,
    oid4vci_authorization::Oid4vciAuthorizationService,
    oid4vci_authorization_postgres::PostgresOid4vciAuthorizationRepository,
    oid4vci_management::Oid4vciManagementService,
    oid4vci_management_postgres::PostgresOid4vciManagementRepository,
    passport_http::PassportHttpService,
    proof_nonce::{ProofNonceService, SecureProofNonceGenerator},
    resource_owner::ResourceOwnerService,
    resource_owner_postgres::PostgresResourceOwnerRepository,
    retention::{PostgresRetentionRepository, RetentionService},
    signing_grant_config::managed_grant_minter,
    signing_policy::HttpProofPolicyResolver,
    tenant_discovery::TenantDiscoveryService,
    tenant_postgres::PostgresTenantDiscoveryRepository,
    token_exchange::{protocol_engine, MartyTokenGenerator, TokenExchangeService},
    token_postgres::PostgresTokenExchangeRepository,
    token_rate_limit::TokenRateLimiter,
    transaction_postgres::PostgresTransactionReadRepository,
    transaction_reads::TransactionReadService,
    transport::TransportPolicy,
    IssuanceRuntime, IssuanceServiceConfig,
};
use marty_oid4vci::discovery::StaticDiscoveryDocuments;
use marty_schema_startup::SchemaStartupMode;
use sqlx::ConnectOptions;
use tokio::{net::TcpListener, sync::watch};
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::StreamExt;
use tonic::transport::Server;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    marty_service_runtime::install_tls_crypto_provider();
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let mut arguments = std::env::args().skip(1);
    match (arguments.next().as_deref(), arguments.next()) {
        (Some("migrate"), None) => {
            let organization_id =
                migration::seed_organization_id(std::env::var("MARTY_ORG_ID").ok().as_deref())?;
            let database_url = std::env::var("DATABASE_URL")?;
            let options = database_url
                .parse::<sqlx::postgres::PgConnectOptions>()?
                .disable_statement_logging();
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect_with(options)
                .await?;
            migration::migrate_owned_schema(&pool, organization_id).await?;
            pool.close().await;
            return Ok(());
        }
        (Some("verify-owned-schema"), None) => {
            let database_url = std::env::var("DATABASE_URL")?;
            let options = database_url
                .parse::<sqlx::postgres::PgConnectOptions>()?
                .disable_statement_logging();
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect_with(options)
                .await?;
            migration::verify_owned_schema(&pool).await?;
            pool.close().await;
            return Ok(());
        }
        (Some("probe-dependencies"), None) => {
            let config = IssuanceServiceConfig::from_env()?;
            dependency_probe::probe(&config)
                .await
                .map_err(std::io::Error::other)?;
            println!("{{\"schema\":\"marty.issuance-dependency-probe/v1\",\"verified\":true}}");
            return Ok(());
        }
        (None, None) => {}
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "issuance service accepts only migrate, verify-owned-schema or probe-dependencies subcommands",
            )
            .into());
        }
    }
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
    let passport_http = PassportHttpService::from_config(&config, pool.clone())?;
    let schema_mode = SchemaStartupMode::from_env()?;
    let schema_result = match schema_mode {
        SchemaStartupMode::Migrate => {
            async {
                migration::migrate(&pool).await?;
                migration::migrate_jwt_vc_profile(&pool).await
            }
            .await
        }
        SchemaStartupMode::Validate => {
            async {
                migration::validate(&pool).await?;
                migration::validate_jwt_vc_profile(&pool).await
            }
            .await
        }
    };
    schema_result.map_err(|error| {
        if error
            .as_database_error()
            .and_then(|database| database.code())
            .is_some_and(|code| code == "28P01")
        {
            // Stable, secret-free evidence for operators and the packaged
            // self-host gate. PostgreSQL 28P01 is invalid_password.
            error!(
                database_sqlstate = "28P01",
                "issuance startup database authentication failed"
            );
        } else {
            error!(%error, "issuance startup database migration failed");
        }
        error
    })?;
    if config.passport_native.enabled {
        let passport_schema_result = match schema_mode {
            SchemaStartupMode::Migrate => migration::migrate_passport(&pool).await,
            SchemaStartupMode::Validate => migration::validate_passport(&pool).await,
        };
        passport_schema_result.map_err(|error| {
            error!(%error, "passport native schema migration failed");
            error
        })?;
    }
    let observations =
        marty_issuance_service::external_observation_startup::prepare_isolated_observation_router(
            &pool,
            config.external_observation_database_url.as_deref(),
            config.external_observations_enabled,
            config.issuance_api_key.as_deref(),
        )
        .await
        .map_err(std::io::Error::other)?;
    let ownership = marty_issuance_service::application_ownership_startup::prepare_router(
        &pool,
        config.application_ownership_enabled,
        config.issuance_api_key.as_deref(),
    )
    .await
    .map_err(std::io::Error::other)?;
    let associations =
        marty_issuance_service::external_association_startup::prepare_isolated_router(
            &pool,
            config.external_association_database_url.as_deref(),
            config.external_associations_enabled,
            config.issuance_api_key.as_deref(),
        )
        .await
        .map_err(std::io::Error::other)?;
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
    let resource_owners = ResourceOwnerService::new(
        Arc::new(PostgresResourceOwnerRepository::new(pool.clone())),
        config.issuance_api_key.as_deref(),
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
    let oid4vci_authorization = Oid4vciAuthorizationService::new(
        Arc::new(PostgresOid4vciAuthorizationRepository::new(
            pool.clone(),
            token_hmac_key,
        )),
        Arc::new(MartyDpopProofVerifier),
        protocol_engine(),
        &config.issuer_base_url,
        config.allowed_redirect_uris.clone(),
        config.authorization_session_ttl_minutes.clone(),
    );
    let nonce_repository = Arc::new(PostgresProofNonceRepository::new(pool.clone()));
    let proof_nonce = ProofNonceService::new(
        nonce_repository.clone(),
        Arc::new(SecureProofNonceGenerator),
    );
    let application_clock = Arc::new(SystemApplicationClock);
    let issuer_resolver = Arc::new(HttpIssuerContextResolver::new(
        config.signing_keys_internal_url.clone(),
        config.signing_keys_internal_api_key.as_deref(),
        config.dependency_timeout,
    )?);
    let canvas_guard_config = CanvasGuardConfig {
        enabled: config.canvas_portable_enabled,
        pilot_organizations: config.canvas_pilot_organizations.clone(),
        evidence_max_age: config.canvas_evidence_max_age,
        readiness_max_age: config.canvas_readiness_max_age,
    };
    let canvas_approval_repository =
        Arc::new(PostgresCanvasAwardApprovalRepository::new(pool.clone()));
    let canvas_application_approval = CanvasApplicationApprovalService::new(
        canvas_approval_repository,
        issuer_resolver.clone(),
        Arc::new(SecureApprovalSeedGenerator),
        application_clock.clone(),
        canvas_guard_config.clone(),
    );
    let credential_repository = Arc::new(PostgresCredentialRepository::new(
        pool.clone(),
        token_hmac_key,
    ));
    let credential_grants = managed_grant_minter(SigningOrigin::IssuanceCredential)?;
    let credential_builder = Arc::new(HttpCredentialBuilder::new_with_grant(
        config.signing_keys_internal_url.clone(),
        config.issuer_sign_key.as_deref(),
        config.dependency_timeout,
        credential_grants.clone(),
    )?);
    let credential_lifecycle = Arc::new(PostgresCredentialLifecycle::new(
        pool.clone(),
        config.revocation_profile_service_url.clone(),
        config.internal_service_token.as_deref(),
        config.dependency_timeout,
        canvas_guard_config.clone(),
    )?);
    let mut didcomm_envelope = NativeDidcommEnvelope::new(
        config.didcomm_universal_resolver_url.as_deref(),
        config.didcomm_did_web_internal_base_url.as_deref(),
        config.didcomm_encryption_policy_file.as_deref(),
    );
    if [
        "DIDCOMM_KMS_ADDR",
        "DIDCOMM_KMS_TOKEN_FILE",
        "DIDCOMM_KMS_CA_CERT_FILE",
    ]
    .iter()
    .any(|name| std::env::var_os(name).is_some())
    {
        return Err(
            "DIDComm extension credentials belong to the registered Signing Keys service".into(),
        );
    }
    if std::env::var_os("INTEGRATION_SECRET_KMS_URL").is_some() {
        didcomm_envelope =
            didcomm_envelope.with_registered_kms(RegisteredDidcommKms::from_environment(
                config.issuer_sign_key.as_deref().unwrap_or_default(),
                Arc::new(credential_grants),
            )?);
    }
    let didcomm_delivery = Arc::new(NativeInitiationDidcommDelivery::new(
        NativeInitiationDidcommPorts {
            repository: credential_repository.clone(),
            issuer_resolver: issuer_resolver.clone(),
            builder: credential_builder.clone(),
            lifecycle: credential_lifecycle.clone(),
            envelope: Arc::new(didcomm_envelope),
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
    let initiation_control_plane = Arc::new(
        NativeInitiationControlPlane::connect_lazy(
            &config.organization_grpc_target,
            &config.credential_template_grpc_target,
            &config.revocation_profile_grpc_target,
            config.internal_service_token.as_deref(),
            config.dependency_timeout,
        )
        .await?,
    );
    let application_templates = ApplicationTemplateService::new(
        Arc::new(PostgresApplicationTemplateRepository::new(pool.clone())),
        runtime_catalog(
            &config.credential_template_grpc_target,
            config.internal_service_token.as_deref(),
            config.dependency_timeout,
        )
        .await?,
        Arc::new(SystemApplicationTemplateClock),
        config.issuance_api_key.as_deref(),
    );
    let internal_application_repository =
        Arc::new(PostgresInternalApplicationRepository::new(pool.clone()));
    let ordinary_internal_application_approver =
        Arc::new(OrdinaryInternalApplicationApprover::new(
            internal_application_repository.clone(),
            initiation_control_plane.clone(),
            issuer_resolver.clone(),
            Arc::new(SecureApprovalSeedGenerator),
            application_clock.clone(),
            config.issuer_base_url.clone(),
            // Python accepts arbitrary-width integer settings and reports an
            // unusable expiry at request time. Preserve deferred failure for
            // values outside Rust's i64 range instead of rejecting startup.
            config
                .issuance_offer_ttl_minutes
                .to_i64()
                .unwrap_or(i64::MAX),
        ));
    let internal_application_preparer =
        Arc::new(CompositeInternalApplicationTransactionPreparer::new(
            ordinary_internal_application_approver.clone(),
            Arc::new(canvas_application_approval.clone()),
        ));
    let internal_application_approver = Arc::new(CompositeInternalApplicationApprover::new(
        ordinary_internal_application_approver,
        Arc::new(canvas_application_approval),
        internal_application_repository.clone(),
    ));
    let internal_application_offers = Arc::new(NativeInternalApplicationOfferCoordinator::new(
        internal_application_repository.clone(),
        internal_application_preparer.clone(),
        InternalApplicationOfferProjector::new(
            config.issuer_base_url.clone(),
            initiation_control_plane.clone(),
            application_clock.clone(),
        )?,
        application_clock.clone(),
    ));
    let internal_application_evidence =
        Arc::new(DefaultInternalApplicationEvidenceCoordinator::new(
            internal_application_repository.clone(),
            internal_application_preparer,
        ));
    let internal_application_reconciler = Arc::new(DefaultInternalApplicationReconciler::new(
        internal_application_repository.clone(),
        Arc::new(CanvasEvidenceReconciliationPreparer::new(
            issuer_resolver.clone(),
            Arc::new(SecureApprovalSeedGenerator),
            canvas_guard_config,
        )),
    ));
    let internal_applications = InternalApplicationService::new(
        internal_application_repository,
        Arc::new(SystemInternalApplicationClock),
        Arc::new(UuidInternalApplicationIdGenerator),
        config.issuance_api_key.as_deref(),
    )
    .with_approver(internal_application_approver)
    .with_offers(internal_application_offers)
    .with_evidence(internal_application_evidence)
    .with_reconciler(internal_application_reconciler);
    let initiation_clock = Arc::new(SystemInitiationClock);
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
            clock: initiation_clock.clone(),
        },
        config.issuer_base_url.clone(),
    )?
    .with_offer_ttl_minutes(config.issuance_offer_ttl_minutes.clone());
    let initiation_projector =
        InitiationOfferProjector::new(config.issuer_base_url.clone(), didcomm_delivery)?;
    let initiation_http = InitiationHttpService::new(
        initiation.clone(),
        initiation_projector.clone(),
        config.issuance_api_key.as_deref(),
    );
    let renewal = CredentialRenewalService::new(
        credential_repository.clone(),
        initiation_http.clone(),
        config.issuance_api_key.as_deref(),
        initiation_clock,
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
    // All three consumers share the same lifecycle policy, repository, status
    // publisher and event bus. Gateway adoption of operations remains separate.
    let credential_management_http = CredentialManagementHttpService::new(
        credential_management.clone(),
        config.issuance_api_key.as_deref(),
    );
    let issued_credential_repository =
        Arc::new(PostgresIssuedCredentialRecordRepository::new(pool.clone()));
    let issued_credentials = IssuedCredentialAdapterService::new(
        issued_credential_repository.clone(),
        credential_management.clone(),
        config.issuance_api_key.as_deref(),
        Arc::new(SystemIssuedCredentialClock),
    );
    let oid4vci_management = Oid4vciManagementService::new(
        Arc::new(PostgresOid4vciManagementRepository::new(pool.clone())),
        issued_credential_repository,
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
    let authority_server = match &config.managed_authority_https {
        Some(https) => Some(
            marty_service_runtime::https::BoundKeylessHttpsServer::bind(
                https,
                marty_issuance_service::http::managed_status_owner_router(
                    credential_management_http.clone(),
                ),
            )
            .await?,
        ),
        None => None,
    };
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
    let tls_acceptor = if let Some(tls) = &config.workload_server_tls {
        Some(
            tls.identity
                .grpc_acceptor(&tls.ca_certificate, 64, Duration::from_secs(15))
                .await?,
        )
    } else {
        None
    };
    let transport = TransportPolicy::new(config.cors_allowed_origins.clone());
    let app = router_with_all_services(runtime.state(), discovery, transport, {
        let services = IssuanceServices::new(
            IssuanceCoreServices::new(
                tenant_discovery,
                IssuanceReadServices::new(transaction_reads, resource_owners),
                token_exchange,
                proof_nonce,
                credential,
                initiation_http,
                didcomm_http,
            )
            .with_renewal(renewal),
            credential_management_http,
            application_templates,
            TokenRateLimiter::from_python_config(config.token_rate_limit, config.token_rate_window),
            oid4vci_authorization,
        )
        .with_internal_applications(internal_applications)
        .with_issued_credentials(issued_credentials)
        .with_oid4vci_management(oid4vci_management)
        .with_retention(RetentionService::new(
            Arc::new(PostgresRetentionRepository::new(pool.clone())),
            config.issuance_api_key.as_deref(),
        ));
        if let Some(passport_http) = passport_http {
            services.with_passport(passport_http)
        } else {
            services
        }
    });
    let app = if let Some(observations) = observations {
        app.merge(observations)
    } else {
        app
    };
    let app = if let Some(ownership) = ownership {
        app.merge(ownership)
    } else {
        app
    };
    let app = if let Some(associations) = associations {
        app.merge(associations)
    } else {
        app
    };
    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    let grpc_server = IssuanceServiceServer::new(grpc_service);
    let (listener_shutdown_tx, listener_shutdown_rx) = watch::channel(false);
    let mut http_shutdown = listener_shutdown_rx.clone();
    let authority = marty_service_runtime::https::serve_optional(
        authority_server,
        listener_shutdown_rx.clone(),
    );
    let mut grpc_shutdown = listener_shutdown_rx;
    let http = axum::serve(
        http_listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        wait_for_shutdown(&mut http_shutdown).await;
    });
    // Poll the TLS-enabled server behind a heap boundary: the combined HTTP
    // and gRPC future otherwise overflows the Windows executable main stack.
    let grpc: Pin<Box<dyn Future<Output = Result<(), tonic::transport::Error>> + Send>> =
        Box::pin(async move {
            let Some(grpc_listener) = grpc_listener else {
                wait_for_shutdown(&mut grpc_shutdown).await;
                return Ok(());
            };
            let router = Server::builder()
                .add_service(health_service)
                .add_service(grpc_server);
            if let Some(acceptor) = tls_acceptor {
                let incoming = TcpListenerStream::new(grpc_listener).then(move |connection| {
                    let acceptor = acceptor.clone();
                    async move {
                        match connection {
                            Ok(stream) => match acceptor.accept(stream).await {
                                Ok(encrypted) => Ok(encrypted),
                                Err(error) => {
                                    debug!(%error, "Issuance workload TLS handshake rejected");
                                    Err(error)
                                }
                            },
                            Err(error) => Err(error),
                        }
                    }
                });
                router
                    .serve_with_incoming_shutdown(incoming, async move {
                        wait_for_shutdown(&mut grpc_shutdown).await;
                    })
                    .await
            } else {
                router
                    .serve_with_incoming_shutdown(
                        TcpListenerStream::new(grpc_listener),
                        async move {
                            wait_for_shutdown(&mut grpc_shutdown).await;
                        },
                    )
                    .await
            }
        });
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
                authority
                    .await
                    .map_err(|error| Box::new(error) as Box<dyn Error>)
            },
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
