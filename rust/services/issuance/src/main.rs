use std::{error::Error, sync::Arc};

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
    canvas_oauth::{CanvasOAuthService, CanvasOAuthServiceConfig},
    canvas_oauth_http::HttpCanvasOAuthProvider,
    canvas_oauth_postgres::{PostgresCanvasOAuthRepository, PostgresIntegrationSecretVault},
    client_auth::RegisteredClientAuthenticator,
    credential::{CredentialIssuanceService, CredentialPorts, UuidNotificationIdGenerator},
    credential_builder::HttpCredentialBuilder,
    credential_issuer::{HttpIssuerContextResolver, NativeCredentialProofVerifier},
    credential_lifecycle::PostgresCredentialLifecycle,
    credential_postgres::PostgresCredentialRepository,
    dpop::MartyDpopProofVerifier,
    ephemeral_postgres::PostgresProofNonceRepository,
    http::{
        router_with_all_services, CanvasLtiExperienceSessionServices, CanvasLtiServices,
        CanvasServices, IssuanceCoreServices, IssuanceServices,
    },
    initiation_didcomm::{
        DidcommEndpointValidator, DidcommTransport, NativeDidcommEnvelope,
        NativeInitiationDidcommDelivery, NativeInitiationDidcommPorts,
    },
    initiation_didcomm_http::InitiationDidcommHttpService,
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
use tokio::net::TcpListener;
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
        Arc::new(RegisteredClientAuthenticator::new(token_repository)),
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
                CanvasLtiJwksRefreshConfig {
                    timeout: config.dependency_timeout,
                    ttl: config.canvas_lti_jwks_ttl,
                    self_managed_origins: config.canvas_self_managed_origins.clone(),
                    allow_private_networks: config.canvas_allow_private_base_urls,
                    allow_http_localhost: config.canvas_allow_http_localhost_base_urls,
                },
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
    let didcomm_http =
        InitiationDidcommHttpService::new(didcomm_delivery, config.issuance_api_key.as_deref());
    let credential = CredentialIssuanceService::new(
        CredentialPorts {
            repository: credential_repository,
            nonce_repository,
            dpop_verifier: Arc::new(MartyDpopProofVerifier),
            proof_verifier: Arc::new(NativeCredentialProofVerifier),
            issuer_resolver,
            builder: credential_builder,
            lifecycle: credential_lifecycle,
            notification_ids: Arc::new(UuidNotificationIdGenerator),
        },
        &config.issuer_base_url,
    );
    let listener = TcpListener::bind(config.http_addr).await?;
    runtime.mark_listener_healthy()?;
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
                didcomm_http,
            ),
            CanvasServices::new(
                canvas_oauth,
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
    runtime.activate()?;
    info!(
        address = %config.http_addr,
        release_version = %config.release_version,
        build_revision = %config.build_revision,
        "native Rust issuance candidate active"
    );

    let result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await;
    runtime.drain()?;
    runtime.stop()?;
    result.map_err(Into::into)
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
