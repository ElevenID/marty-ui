use std::{net::SocketAddr, sync::Arc};

use axum::{
    body::to_bytes,
    extract::{ConnectInfo, FromRequest, Path, RawForm, RawQuery, Request, State},
    http::{header as http_header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use marty_oid4vci::discovery::{
    AuthorizationServerMetadata, CredentialIssuerMetadata, CredentialTypeMetadata, IssuerVariant,
    StaticDiscoveryDocuments,
};
use mmf_core::HealthReport;
use mmf_runtime::{system_router_with_options, RuntimeState, SystemRouteOptions};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::{
    canvas_lti_bootstrap::{
        CanvasLtiBootstrapPlanError, CanvasLtiBootstrapRequest, CanvasLtiBootstrapService,
        CanvasLtiBootstrapServiceError,
    },
    canvas_lti_deep_linking::{CanvasLtiDeepLinkingError, CanvasLtiDeepLinkingService},
    canvas_lti_evidence::{
        CanvasLtiEvidenceError, CanvasLtiEvidenceService, CanvasLtiEvidenceSyncEnqueueError,
        CanvasLtiEvidenceSyncError, CanvasLtiEvidenceSyncService,
    },
    canvas_lti_experience::{
        CanvasLtiExperienceExchangeError, CanvasLtiExperienceExchangeService,
        CanvasLtiExperienceSessionError, CanvasLtiExperienceSessionService,
    },
    canvas_lti_launch::{
        public_launch_response, CanvasLtiExperienceService, CanvasLtiLaunchPlanError,
        CanvasLtiLaunchService, CanvasLtiLaunchServiceError, CanvasLtiLaunchSubmission,
    },
    canvas_lti_login::{
        CanvasLtiLoginError, CanvasLtiLoginMode, CanvasLtiLoginService, CanvasLtiLoginSubmission,
    },
    canvas_lti_tool_signing::{CanvasLtiToolJwtSigner, CanvasLtiToolSigningError},
    canvas_management::CanvasPlatformRequest,
    canvas_management_http::{
        organization_id_from_query, parse_lti_installation_request, parse_platform_request,
        CanvasManagementHttpError, CanvasPlatformManagementHttpService, CanvasPlatformResponse,
    },
    canvas_oauth::{
        CanvasOAuthCallbackRequest, CanvasOAuthError, CanvasOAuthService, CanvasOAuthStartRequest,
    },
    credential::{CredentialIssuanceError, CredentialIssuanceService, CredentialRequest},
    credential_management::{
        CredentialLifecycleAction, CredentialManagementError, CredentialStatusView,
    },
    credential_management_http::{CredentialManagementHttpError, CredentialManagementHttpService},
    initiation::InitiationRequest,
    initiation_didcomm_http::{
        DidcommDeliverRequest, InitiationDidcommHttpError, InitiationDidcommHttpService,
    },
    initiation_http::{InitiationHttpError, InitiationHttpService},
    proof_nonce::{ProofNonceError, ProofNonceService},
    tenant_discovery::{TenantDiscoveryError, TenantDiscoveryService},
    token_exchange::{TokenExchangeError, TokenExchangeRequest, TokenExchangeService},
    token_rate_limit::TokenRateLimiter,
    transaction_reads::{
        IssuanceTransactionResponse, ResourceOwner, TransactionReadError, TransactionReadService,
        TransactionRevocationStatus,
    },
    transport::{legacy_transport, TransportPolicy},
};

#[derive(Clone)]
struct IssuanceState {
    documents: StaticDiscoveryDocuments,
    tenant: Option<TenantDiscoveryService>,
    transactions: Option<TransactionReadService>,
    token_exchange: Option<TokenExchangeService>,
    proof_nonce: Option<ProofNonceService>,
    credential: Option<CredentialIssuanceService>,
    initiation: Option<InitiationHttpService>,
    didcomm_delivery: Option<InitiationDidcommHttpService>,
    credential_management: Option<CredentialManagementHttpService>,
    canvas_lti_login: Option<CanvasLtiLoginService>,
    canvas_lti_launch: Option<CanvasLtiLaunchService>,
    canvas_lti_experience: Option<CanvasLtiExperienceService>,
    canvas_lti_experience_exchange: Option<CanvasLtiExperienceExchangeService>,
    canvas_lti_experience_session: Option<CanvasLtiExperienceSessionService>,
    canvas_lti_bootstrap: Option<CanvasLtiBootstrapService>,
    canvas_lti_deep_linking: Option<CanvasLtiDeepLinkingService>,
    canvas_lti_evidence: Option<CanvasLtiEvidenceService>,
    canvas_lti_evidence_sync: Option<CanvasLtiEvidenceSyncService>,
    canvas_lti_tool_signer: Option<Arc<dyn CanvasLtiToolJwtSigner>>,
    canvas_oauth: Option<CanvasOAuthService>,
    canvas_management: Option<CanvasPlatformManagementHttpService>,
}

pub struct IssuanceServices {
    tenant: TenantDiscoveryService,
    transactions: TransactionReadService,
    token_exchange: TokenExchangeService,
    proof_nonce: ProofNonceService,
    credential: CredentialIssuanceService,
    initiation: InitiationHttpService,
    didcomm_delivery: InitiationDidcommHttpService,
    credential_management: CredentialManagementHttpService,
    canvas: CanvasServices,
    token_rate_limiter: TokenRateLimiter,
}

pub struct IssuanceCoreServices {
    tenant: TenantDiscoveryService,
    transactions: TransactionReadService,
    token_exchange: TokenExchangeService,
    proof_nonce: ProofNonceService,
    credential: CredentialIssuanceService,
    initiation: InitiationHttpService,
    didcomm_delivery: InitiationDidcommHttpService,
}

impl IssuanceCoreServices {
    #[must_use]
    pub fn new(
        tenant: TenantDiscoveryService,
        transactions: TransactionReadService,
        token_exchange: TokenExchangeService,
        proof_nonce: ProofNonceService,
        credential: CredentialIssuanceService,
        initiation: InitiationHttpService,
        didcomm_delivery: InitiationDidcommHttpService,
    ) -> Self {
        Self {
            tenant,
            transactions,
            token_exchange,
            proof_nonce,
            credential,
            initiation,
            didcomm_delivery,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CanvasServices {
    oauth: CanvasOAuthService,
    management: CanvasPlatformManagementHttpService,
    lti: CanvasLtiServices,
}

impl CanvasServices {
    #[must_use]
    pub fn new(
        oauth: CanvasOAuthService,
        management: CanvasPlatformManagementHttpService,
        lti: CanvasLtiServices,
    ) -> Self {
        Self {
            oauth,
            management,
            lti,
        }
    }
}

#[derive(Clone)]
pub struct CanvasLtiServices {
    login: CanvasLtiLoginService,
    launch: CanvasLtiLaunchService,
    experience: CanvasLtiExperienceService,
    experience_exchange: CanvasLtiExperienceExchangeService,
    session: CanvasLtiExperienceSessionServices,
    tool_signer: Arc<dyn CanvasLtiToolJwtSigner>,
}

#[derive(Clone, Debug)]
pub struct CanvasLtiExperienceSessionServices {
    current: CanvasLtiExperienceSessionService,
    bootstrap: CanvasLtiBootstrapService,
    deep_linking: CanvasLtiDeepLinkingService,
    evidence: CanvasLtiEvidenceService,
    evidence_sync: CanvasLtiEvidenceSyncService,
}

impl CanvasLtiExperienceSessionServices {
    #[must_use]
    pub fn new(
        current: CanvasLtiExperienceSessionService,
        bootstrap: CanvasLtiBootstrapService,
        deep_linking: CanvasLtiDeepLinkingService,
        evidence: CanvasLtiEvidenceService,
        evidence_sync: CanvasLtiEvidenceSyncService,
    ) -> Self {
        Self {
            current,
            bootstrap,
            deep_linking,
            evidence,
            evidence_sync,
        }
    }
}

impl CanvasLtiServices {
    #[must_use]
    pub fn new(
        login: CanvasLtiLoginService,
        launch: CanvasLtiLaunchService,
        experience: CanvasLtiExperienceService,
        experience_exchange: CanvasLtiExperienceExchangeService,
        session: CanvasLtiExperienceSessionServices,
        tool_signer: Arc<dyn CanvasLtiToolJwtSigner>,
    ) -> Self {
        Self {
            login,
            launch,
            experience,
            experience_exchange,
            session,
            tool_signer,
        }
    }
}

impl std::fmt::Debug for CanvasLtiServices {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasLtiServices")
            .finish_non_exhaustive()
    }
}

impl IssuanceServices {
    #[must_use]
    pub fn new(
        core: IssuanceCoreServices,
        credential_management: CredentialManagementHttpService,
        canvas: CanvasServices,
        token_rate_limiter: TokenRateLimiter,
    ) -> Self {
        Self {
            tenant: core.tenant,
            transactions: core.transactions,
            token_exchange: core.token_exchange,
            proof_nonce: core.proof_nonce,
            credential: core.credential,
            initiation: core.initiation,
            didcomm_delivery: core.didcomm_delivery,
            credential_management,
            canvas,
            token_rate_limiter,
        }
    }
}

#[derive(Default)]
struct OptionalServices {
    tenant: Option<TenantDiscoveryService>,
    transactions: Option<TransactionReadService>,
    token_exchange: Option<TokenExchangeService>,
    proof_nonce: Option<ProofNonceService>,
    credential: Option<CredentialIssuanceService>,
    initiation: Option<InitiationHttpService>,
    didcomm_delivery: Option<InitiationDidcommHttpService>,
    credential_management: Option<CredentialManagementHttpService>,
    canvas_lti_login: Option<CanvasLtiLoginService>,
    canvas_lti_launch: Option<CanvasLtiLaunchService>,
    canvas_lti_experience: Option<CanvasLtiExperienceService>,
    canvas_lti_experience_exchange: Option<CanvasLtiExperienceExchangeService>,
    canvas_lti_experience_session: Option<CanvasLtiExperienceSessionService>,
    canvas_lti_bootstrap: Option<CanvasLtiBootstrapService>,
    canvas_lti_deep_linking: Option<CanvasLtiDeepLinkingService>,
    canvas_lti_evidence: Option<CanvasLtiEvidenceService>,
    canvas_lti_evidence_sync: Option<CanvasLtiEvidenceSyncService>,
    canvas_lti_tool_signer: Option<Arc<dyn CanvasLtiToolJwtSigner>>,
    canvas_oauth: Option<CanvasOAuthService>,
    canvas_management: Option<CanvasPlatformManagementHttpService>,
    token_rate_limiter: Option<TokenRateLimiter>,
}

fn legacy_health(_report: &HealthReport) -> Value {
    json!({"status": "healthy", "service": "issuance-service"})
}

pub fn router(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
) -> Router {
    router_with_optional_services(runtime, discovery, transport, OptionalServices::default())
}

pub fn router_with_tenant_discovery(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    tenant: TenantDiscoveryService,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            tenant: Some(tenant),
            ..OptionalServices::default()
        },
    )
}

pub fn router_with_services(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    tenant: TenantDiscoveryService,
    transactions: TransactionReadService,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            tenant: Some(tenant),
            transactions: Some(transactions),
            ..OptionalServices::default()
        },
    )
}

pub fn router_with_all_services(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    services: IssuanceServices,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            tenant: Some(services.tenant),
            transactions: Some(services.transactions),
            token_exchange: Some(services.token_exchange),
            proof_nonce: Some(services.proof_nonce),
            credential: Some(services.credential),
            initiation: Some(services.initiation),
            didcomm_delivery: Some(services.didcomm_delivery),
            credential_management: Some(services.credential_management),
            canvas_oauth: Some(services.canvas.oauth),
            canvas_management: Some(services.canvas.management),
            canvas_lti_login: Some(services.canvas.lti.login),
            canvas_lti_launch: Some(services.canvas.lti.launch),
            canvas_lti_experience: Some(services.canvas.lti.experience),
            canvas_lti_experience_exchange: Some(services.canvas.lti.experience_exchange),
            canvas_lti_experience_session: Some(services.canvas.lti.session.current),
            canvas_lti_bootstrap: Some(services.canvas.lti.session.bootstrap),
            canvas_lti_deep_linking: Some(services.canvas.lti.session.deep_linking),
            canvas_lti_evidence: Some(services.canvas.lti.session.evidence),
            canvas_lti_evidence_sync: Some(services.canvas.lti.session.evidence_sync),
            canvas_lti_tool_signer: Some(services.canvas.lti.tool_signer),
            token_rate_limiter: Some(services.token_rate_limiter),
        },
    )
}

pub fn router_with_token_exchange(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    token_exchange: TokenExchangeService,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            token_exchange: Some(token_exchange),
            token_rate_limiter: Some(TokenRateLimiter::legacy_defaults()),
            ..OptionalServices::default()
        },
    )
}

pub fn router_with_token_exchange_and_rate_limit(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    token_exchange: TokenExchangeService,
    token_rate_limiter: TokenRateLimiter,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            token_exchange: Some(token_exchange),
            token_rate_limiter: Some(token_rate_limiter),
            ..OptionalServices::default()
        },
    )
}

pub fn router_with_proof_nonce_and_rate_limit(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    proof_nonce: ProofNonceService,
    token_rate_limiter: TokenRateLimiter,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            proof_nonce: Some(proof_nonce),
            token_rate_limiter: Some(token_rate_limiter),
            ..OptionalServices::default()
        },
    )
}

pub fn router_with_credential_issuance(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    credential: CredentialIssuanceService,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            credential: Some(credential),
            ..OptionalServices::default()
        },
    )
}

pub fn router_with_didcomm_delivery(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    didcomm_delivery: InitiationDidcommHttpService,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            didcomm_delivery: Some(didcomm_delivery),
            ..OptionalServices::default()
        },
    )
}

pub fn router_with_initiation(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    initiation: InitiationHttpService,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            initiation: Some(initiation),
            ..OptionalServices::default()
        },
    )
}

pub fn router_with_credential_management(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    credential_management: CredentialManagementHttpService,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            credential_management: Some(credential_management),
            ..OptionalServices::default()
        },
    )
}

pub fn router_with_canvas_lti_login(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    canvas_lti_login: CanvasLtiLoginService,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            canvas_lti_login: Some(canvas_lti_login),
            ..OptionalServices::default()
        },
    )
}

pub fn router_with_canvas_oauth(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    canvas_oauth: CanvasOAuthService,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            canvas_oauth: Some(canvas_oauth),
            ..OptionalServices::default()
        },
    )
}

pub fn router_with_canvas_management(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    canvas_management: CanvasPlatformManagementHttpService,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            canvas_management: Some(canvas_management),
            ..OptionalServices::default()
        },
    )
}

pub fn router_with_canvas_lti_launch(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    canvas_lti_launch: CanvasLtiLaunchService,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            canvas_lti_launch: Some(canvas_lti_launch),
            ..OptionalServices::default()
        },
    )
}

pub fn router_with_canvas_lti_experience(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    canvas_lti_experience: CanvasLtiExperienceService,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            canvas_lti_experience: Some(canvas_lti_experience),
            ..OptionalServices::default()
        },
    )
}

pub fn router_with_canvas_lti_experience_exchange(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    canvas_lti_experience_exchange: CanvasLtiExperienceExchangeService,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            canvas_lti_experience_exchange: Some(canvas_lti_experience_exchange),
            ..OptionalServices::default()
        },
    )
}

pub fn router_with_canvas_lti_experience_session(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    canvas_lti_experience_session: CanvasLtiExperienceSessionService,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            canvas_lti_experience_session: Some(canvas_lti_experience_session),
            ..OptionalServices::default()
        },
    )
}

pub fn router_with_canvas_lti_bootstrap(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    canvas_lti_bootstrap: CanvasLtiBootstrapService,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            canvas_lti_bootstrap: Some(canvas_lti_bootstrap),
            ..OptionalServices::default()
        },
    )
}

pub fn router_with_canvas_lti_deep_linking(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    canvas_lti_deep_linking: CanvasLtiDeepLinkingService,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            canvas_lti_deep_linking: Some(canvas_lti_deep_linking),
            ..OptionalServices::default()
        },
    )
}

pub fn router_with_canvas_lti_evidence(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    canvas_lti_evidence: CanvasLtiEvidenceService,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            canvas_lti_evidence: Some(canvas_lti_evidence),
            ..OptionalServices::default()
        },
    )
}

pub fn router_with_canvas_lti_evidence_sync(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    canvas_lti_evidence_sync: CanvasLtiEvidenceSyncService,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            canvas_lti_evidence_sync: Some(canvas_lti_evidence_sync),
            ..OptionalServices::default()
        },
    )
}

pub fn router_with_canvas_lti_tool_signer(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    canvas_lti_tool_signer: Arc<dyn CanvasLtiToolJwtSigner>,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            canvas_lti_tool_signer: Some(canvas_lti_tool_signer),
            ..OptionalServices::default()
        },
    )
}

fn router_with_optional_services(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    services: OptionalServices,
) -> Router {
    let system = system_router_with_options(
        runtime,
        SystemRouteOptions::default().with_health_projector(legacy_health),
    );
    let oauth = Router::new()
        .route("/v1/issuance/token", post(exchange_token))
        .route("/v1/issuance/nonce", post(issue_proof_nonce))
        .route_layer(middleware::from_fn_with_state(
            services.token_rate_limiter.clone(),
            token_rate_limit_middleware,
        ));
    let mut api = Router::new()
        .route(
            "/.well-known/openid-credential-issuer",
            get(root_issuer_metadata),
        )
        .route(
            "/credentials/{*credential_type}",
            get(credential_type_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(root_authorization_server_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server/org/{organization_id}",
            get(organization_authorization_server_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server/org/{organization_id}/credential-manager",
            get(credential_manager_authorization_server_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server/org/{organization_id}/apple-wallet",
            get(apple_wallet_authorization_server_metadata),
        )
        .route(
            "/.well-known/openid-credential-issuer/org/{organization_id}",
            get(organization_issuer_metadata),
        )
        .route(
            "/.well-known/openid-credential-issuer/org/{organization_id}/credential-manager",
            get(credential_manager_issuer_metadata),
        )
        .route(
            "/.well-known/openid-credential-issuer/org/{organization_id}/apple-wallet",
            get(apple_wallet_issuer_metadata),
        )
        .route(
            "/v1/issuance/offers/{transaction_id}",
            get(credential_offer),
        )
        .route("/v1/issuance/transactions", get(list_transactions))
        .route(
            "/v1/issuance/transactions/{transaction_id}",
            get(get_transaction),
        )
        .route(
            "/v1/issuance/transactions/{transaction_id}/revocation-status",
            get(transaction_revocation_status),
        )
        .route(
            "/internal/v1/resource-owners/issuance-transactions/{transaction_id}",
            get(transaction_owner),
        );
    if services.credential.is_some() {
        api = api.route("/v1/issuance/credential", post(issue_credential));
    }
    if services.initiation.is_some() {
        api = api.route("/v1/issuance/initiate", post(initiate_issuance));
    }
    if services.didcomm_delivery.is_some() {
        api = api.route(
            "/v1/issuance/didcomm/deliver",
            post(deliver_didcomm_credential),
        );
    }
    if services.credential_management.is_some() {
        api = api
            .route(
                "/v1/issuance/credentials/{credential_id}/revoke",
                post(revoke_credential),
            )
            .route(
                "/v1/issuance/credentials/{credential_id}/suspend",
                post(suspend_credential),
            )
            .route(
                "/v1/issuance/credentials/{credential_id}/reinstate",
                post(reinstate_credential),
            )
            .route(
                "/v1/issuance/credentials/{credential_id}/status",
                get(get_credential_status),
            );
    }
    if services.canvas_oauth.is_some() {
        api = api
            .route(
                "/v1/integrations/canvas/platforms/{platform_id}/oauth/authorizations",
                post(start_canvas_oauth_connection),
            )
            .route(
                "/v1/integrations/canvas/oauth/callback",
                get(complete_canvas_oauth_connection),
            )
            .route(
                "/v1/integrations/canvas/platforms/{platform_id}/oauth",
                delete(disconnect_canvas_oauth_connection),
            );
    }
    if services.canvas_management.is_some() {
        api = api
            .route(
                "/v1/integrations/canvas/lti/config/{token}",
                get(get_public_canvas_lti_config),
            )
            .route(
                "/v1/integrations/canvas/platforms",
                get(list_canvas_platforms).post(create_canvas_platform),
            )
            .route(
                "/v1/integrations/canvas/platforms/{platform_id}/registration-config",
                get(get_canvas_lti_registration_config),
            )
            .route(
                "/v1/integrations/canvas/platforms/{platform_id}/lti-installation",
                put(update_canvas_lti_installation),
            )
            .route(
                "/v1/integrations/canvas/platforms/{platform_id}/sandbox-probe",
                post(probe_canvas_platform_sandbox),
            )
            .route(
                "/v1/integrations/canvas/platforms/{platform_id}/jwks-refresh",
                post(refresh_canvas_platform_jwks),
            )
            .route(
                "/v1/integrations/canvas/platforms/{platform_id}",
                get(get_canvas_platform)
                    .put(update_canvas_platform)
                    .delete(delete_canvas_platform),
            );
    }
    if services.canvas_lti_login.is_some() {
        api = api
            .route(
                "/v1/integrations/canvas/lti/platforms/{platform_id}/login",
                post(initiate_canvas_lti_login),
            )
            .route(
                "/v1/integrations/canvas/lti/platforms/{platform_id}/experience-login",
                post(initiate_canvas_lti_experience_login),
            );
    }
    if services.canvas_lti_launch.is_some() {
        api = api.route(
            "/v1/integrations/canvas/lti/platforms/{platform_id}/launch",
            post(verify_canvas_lti_launch),
        );
    }
    if services.canvas_lti_experience.is_some() {
        api = api.route(
            "/v1/integrations/canvas/lti/platforms/{platform_id}/experience",
            post(launch_canvas_lti_experience),
        );
    }
    if services.canvas_lti_experience_exchange.is_some() {
        api = api.route(
            "/v1/integrations/canvas/lti/experience-sessions/exchange",
            post(exchange_canvas_lti_experience_code),
        );
    }
    if services.canvas_lti_tool_signer.is_some() {
        api = api.route(
            "/v1/integrations/canvas/lti/jwks",
            get(get_canvas_lti_tool_jwks),
        );
    }
    if services.canvas_lti_experience_session.is_some() {
        api = api.route(
            "/v1/integrations/canvas/lti/experience-sessions/current",
            get(get_canvas_lti_experience_session),
        );
    }
    if services.canvas_lti_bootstrap.is_some() {
        api = api.route(
            "/v1/integrations/canvas/lti/experience-sessions/current/bootstrap",
            post(bootstrap_canvas_lti_experience_application),
        );
    }
    if services.canvas_lti_deep_linking.is_some() {
        api = api.route(
            "/v1/integrations/canvas/lti/experience-sessions/current/deep-linking-response",
            post(create_canvas_lti_deep_linking_response),
        );
    }
    if services.canvas_lti_evidence.is_some() {
        api = api.route(
            "/v1/integrations/canvas/lti/experience-sessions/current/evidence-status",
            get(get_canvas_lti_evidence_status),
        );
    }
    if services.canvas_lti_evidence_sync.is_some() {
        api = api.route(
            "/v1/integrations/canvas/lti/experience-sessions/current/evidence-sync",
            post(sync_canvas_lti_evidence),
        );
    }
    let api = api.merge(oauth).with_state(IssuanceState {
        documents: discovery,
        tenant: services.tenant,
        transactions: services.transactions,
        token_exchange: services.token_exchange,
        proof_nonce: services.proof_nonce,
        credential: services.credential,
        initiation: services.initiation,
        didcomm_delivery: services.didcomm_delivery,
        credential_management: services.credential_management,
        canvas_oauth: services.canvas_oauth,
        canvas_management: services.canvas_management,
        canvas_lti_login: services.canvas_lti_login,
        canvas_lti_launch: services.canvas_lti_launch,
        canvas_lti_experience: services.canvas_lti_experience,
        canvas_lti_experience_exchange: services.canvas_lti_experience_exchange,
        canvas_lti_experience_session: services.canvas_lti_experience_session,
        canvas_lti_bootstrap: services.canvas_lti_bootstrap,
        canvas_lti_deep_linking: services.canvas_lti_deep_linking,
        canvas_lti_evidence: services.canvas_lti_evidence,
        canvas_lti_evidence_sync: services.canvas_lti_evidence_sync,
        canvas_lti_tool_signer: services.canvas_lti_tool_signer,
    });
    system
        .merge(api)
        .layer(middleware::from_fn_with_state(transport, legacy_transport))
}

async fn create_canvas_platform(
    State(state): State<IssuanceState>,
    request: Request,
) -> Result<Json<CanvasPlatformResponse>, CanvasManagementHttpError> {
    let service = canvas_management(&state)?;
    service.authorize(request.headers())?;
    let headers = request.headers().clone();
    let request = parse_platform_request(request).await?;
    service.create(&headers, request).await.map(Json)
}

async fn list_canvas_platforms(
    State(state): State<IssuanceState>,
    request: Request,
) -> Result<Json<Vec<CanvasPlatformResponse>>, CanvasManagementHttpError> {
    let service = canvas_management(&state)?;
    service.authorize(request.headers())?;
    let organization_id = organization_id_from_query(request.uri().query());
    service
        .list(request.headers(), organization_id.as_deref())
        .await
        .map(Json)
}

async fn get_canvas_platform(
    State(state): State<IssuanceState>,
    Path(platform_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<CanvasPlatformResponse>, CanvasManagementHttpError> {
    canvas_management(&state)?
        .get(&headers, &platform_id)
        .await
        .map(Json)
}

async fn update_canvas_platform(
    State(state): State<IssuanceState>,
    Path(platform_id): Path<String>,
    request: Request,
) -> Result<Json<CanvasPlatformResponse>, CanvasManagementHttpError> {
    let service = canvas_management(&state)?;
    service.authorize(request.headers())?;
    let headers = request.headers().clone();
    let request: CanvasPlatformRequest = parse_platform_request(request).await?;
    service
        .update(&headers, &platform_id, request)
        .await
        .map(Json)
}

async fn delete_canvas_platform(
    State(state): State<IssuanceState>,
    Path(platform_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, CanvasManagementHttpError> {
    canvas_management(&state)?
        .delete(&headers, &platform_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_canvas_lti_registration_config(
    State(state): State<IssuanceState>,
    Path(platform_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, CanvasManagementHttpError> {
    canvas_management(&state)?
        .registration_config(&headers, &platform_id)
        .await
        .map(|response| Json(response).into_response())
}

async fn get_public_canvas_lti_config(
    State(state): State<IssuanceState>,
    Path(token): Path<String>,
) -> Result<Response, CanvasManagementHttpError> {
    let configuration = canvas_management(&state)?
        .public_registration_config(&token)
        .await?;
    let mut response = Json(configuration).into_response();
    response.headers_mut().insert(
        http_header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

async fn update_canvas_lti_installation(
    State(state): State<IssuanceState>,
    Path(platform_id): Path<String>,
    request: Request,
) -> Result<Response, CanvasManagementHttpError> {
    let service = canvas_management(&state)?;
    service.authorize(request.headers())?;
    let headers = request.headers().clone();
    let installation = parse_lti_installation_request(request).await?;
    service
        .update_lti_installation(&headers, &platform_id, installation)
        .await
        .map(|response| Json(response).into_response())
}

async fn probe_canvas_platform_sandbox(
    State(state): State<IssuanceState>,
    Path(platform_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, CanvasManagementHttpError> {
    canvas_management(&state)?
        .sandbox_probe(&headers, &platform_id)
        .await
        .map(|response| Json(response).into_response())
}

async fn refresh_canvas_platform_jwks(
    State(state): State<IssuanceState>,
    Path(platform_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, CanvasManagementHttpError> {
    canvas_management(&state)?
        .refresh_jwks(&headers, &platform_id)
        .await
        .map(|response| Json(response).into_response())
}

fn canvas_management(
    state: &IssuanceState,
) -> Result<&CanvasPlatformManagementHttpService, CanvasManagementHttpError> {
    state.canvas_management.as_ref().ok_or_else(|| {
        CanvasManagementHttpError::Service(
            crate::canvas_management_service::CanvasPlatformManagementError::RepositoryUnavailable,
        )
    })
}

async fn start_canvas_oauth_connection(
    State(state): State<IssuanceState>,
    Path(platform_id): Path<String>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, CanvasOAuthHttpError> {
    let service = canvas_oauth(&state)?;
    let organization_id = service.authorize_management(
        header(&headers, "X-API-Key"),
        header(&headers, "X-Organization-ID"),
    )?;
    let input = parse_canvas_oauth_start(request).await?;
    let result = service
        .start_authorized(&platform_id, input, organization_id)
        .await?;
    Ok(canvas_oauth_no_store(Json(result).into_response()))
}

async fn complete_canvas_oauth_connection(
    State(state): State<IssuanceState>,
    RawQuery(raw_query): RawQuery,
) -> Result<Response, CanvasOAuthHttpError> {
    let input = parse_canvas_oauth_callback(raw_query.as_deref())?;
    let result = canvas_oauth(&state)?.callback(input).await?;
    let location = HeaderValue::from_str(&result.location)
        .map_err(|_| CanvasOAuthHttpError::Service(CanvasOAuthError::InvalidConfiguration))?;
    Ok(canvas_oauth_no_store(
        (StatusCode::SEE_OTHER, [(http_header::LOCATION, location)]).into_response(),
    ))
}

fn canvas_oauth_no_store(mut response: Response) -> Response {
    response = private_no_store(response);
    response.headers_mut().insert(
        http_header::HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    response
}

async fn disconnect_canvas_oauth_connection(
    State(state): State<IssuanceState>,
    Path(platform_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, CanvasOAuthHttpError> {
    let result = canvas_oauth(&state)?
        .disconnect(
            &platform_id,
            header(&headers, "X-API-Key"),
            header(&headers, "X-Organization-ID"),
        )
        .await?;
    Ok(canvas_oauth_no_store(Json(result).into_response()))
}

fn canvas_oauth(state: &IssuanceState) -> Result<&CanvasOAuthService, CanvasOAuthHttpError> {
    state
        .canvas_oauth
        .as_ref()
        .ok_or_else(|| CanvasOAuthHttpError::Service(CanvasOAuthError::RepositoryUnavailable))
}

async fn parse_canvas_oauth_start(
    request: Request,
) -> Result<CanvasOAuthStartRequest, CanvasOAuthHttpError> {
    const MAX_BODY_BYTES: usize = 64 * 1024;
    let json_content_type = request
        .headers()
        .get(http_header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .is_some_and(|value| {
            value.eq_ignore_ascii_case("application/json")
                || value.to_ascii_lowercase().ends_with("+json")
        });
    let bytes = to_bytes(request.into_body(), MAX_BODY_BYTES)
        .await
        .map_err(|_| CanvasOAuthHttpError::BodyTooLarge)?;
    if !bytes.is_empty() && !json_content_type {
        return Err(CanvasOAuthHttpError::Validation(vec![json!({
            "type": "model_attributes_type",
            "loc": ["body"],
            "msg": "Input should be a valid dictionary or object to extract fields from",
            "input": String::from_utf8_lossy(&bytes),
        })]));
    }
    let input: Value = serde_json::from_slice(&bytes).map_err(|error| {
        CanvasOAuthHttpError::Validation(vec![json!({
            "type": "json_invalid",
            "loc": ["body", error.line(), error.column()],
            "msg": "JSON decode error",
            "input": {},
            "ctx": {"error": error.to_string()},
        })])
    })?;
    let Some(object) = input.as_object() else {
        return Err(CanvasOAuthHttpError::Validation(vec![json!({
            "type": "model_attributes_type",
            "loc": ["body"],
            "msg": "Input should be a valid dictionary or object to extract fields from",
            "input": input,
        })]));
    };
    let mut errors = Vec::new();
    let client_id = oauth_string_field(object, "client_id", 1, 512, &mut errors);
    let client_secret_secret_id =
        oauth_string_field(object, "client_secret_secret_id", 1, 512, &mut errors);
    let capabilities = match object.get("capabilities") {
        None => {
            errors.push(json!({
                "type": "missing", "loc": ["body", "capabilities"],
                "msg": "Field required", "input": object,
            }));
            None
        }
        Some(Value::Array(values)) => {
            if values.is_empty() {
                errors.push(json!({
                    "type": "too_short", "loc": ["body", "capabilities"],
                    "msg": "List should have at least 1 item after validation, not 0",
                    "input": values, "ctx": {"field_type": "List", "min_length": 1, "actual_length": 0},
                }));
            } else if values.len() > 5 {
                errors.push(json!({
                    "type": "too_long", "loc": ["body", "capabilities"],
                    "msg": format!("List should have at most 5 items after validation, not {}", values.len()),
                    "input": values, "ctx": {"field_type": "List", "max_length": 5, "actual_length": values.len()},
                }));
            }
            let mut capabilities = Vec::new();
            for (index, value) in values.iter().enumerate() {
                if let Some(value) = value.as_str() {
                    capabilities.push(value.to_owned());
                } else {
                    errors.push(json!({
                        "type": "string_type", "loc": ["body", "capabilities", index],
                        "msg": "Input should be a valid string", "input": value,
                    }));
                }
            }
            Some(capabilities)
        }
        Some(value) => {
            errors.push(json!({
                "type": "list_type", "loc": ["body", "capabilities"],
                "msg": "Input should be a valid list", "input": value,
            }));
            None
        }
    };
    for (name, value) in object {
        if !matches!(
            name.as_str(),
            "client_id" | "client_secret_secret_id" | "capabilities"
        ) {
            errors.push(json!({
                "type": "extra_forbidden", "loc": ["body", name],
                "msg": "Extra inputs are not permitted", "input": value,
            }));
        }
    }
    if !errors.is_empty() {
        return Err(CanvasOAuthHttpError::Validation(errors));
    }
    Ok(CanvasOAuthStartRequest {
        client_id: client_id.expect("validated"),
        client_secret_secret_id: client_secret_secret_id.expect("validated"),
        capabilities: capabilities.expect("validated"),
    })
}

fn oauth_string_field(
    object: &Map<String, Value>,
    name: &str,
    minimum: usize,
    maximum: usize,
    errors: &mut Vec<Value>,
) -> Option<String> {
    match object.get(name) {
        None => {
            errors.push(json!({
                "type": "missing", "loc": ["body", name],
                "msg": "Field required", "input": object,
            }));
            None
        }
        Some(Value::String(value)) => {
            let length = value.chars().count();
            if length < minimum {
                errors.push(json!({
                    "type": "string_too_short", "loc": ["body", name],
                    "msg": format!("String should have at least {minimum} character"),
                    "input": value, "ctx": {"min_length": minimum},
                }));
            } else if length > maximum {
                errors.push(json!({
                    "type": "string_too_long", "loc": ["body", name],
                    "msg": format!("String should have at most {maximum} characters"),
                    "input": value, "ctx": {"max_length": maximum},
                }));
            }
            Some(value.clone())
        }
        Some(value) => {
            errors.push(json!({
                "type": "string_type", "loc": ["body", name],
                "msg": "Input should be a valid string", "input": value,
            }));
            None
        }
    }
}

fn parse_canvas_oauth_callback(
    raw_query: Option<&str>,
) -> Result<CanvasOAuthCallbackRequest, CanvasOAuthHttpError> {
    let values = raw_query
        .into_iter()
        .flat_map(|query| url::form_urlencoded::parse(query.as_bytes()))
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut errors = Vec::new();
    let state = query_string(&values, "state", true, 32, 512, &mut errors);
    let code = query_string(&values, "code", false, 1, 4096, &mut errors);
    let error = query_string(&values, "error", false, 1, 256, &mut errors);
    if !errors.is_empty() {
        return Err(CanvasOAuthHttpError::Validation(errors));
    }
    Ok(CanvasOAuthCallbackRequest {
        code,
        state: state.expect("required and validated"),
        error,
    })
}

fn query_string(
    values: &std::collections::BTreeMap<String, String>,
    name: &str,
    required: bool,
    minimum: usize,
    maximum: usize,
    errors: &mut Vec<Value>,
) -> Option<String> {
    let Some(value) = values.get(name) else {
        if required {
            errors.push(json!({
                "type": "missing", "loc": ["query", name],
                "msg": "Field required", "input": null,
            }));
        }
        return None;
    };
    let length = value.chars().count();
    if length < minimum {
        errors.push(json!({
            "type": "string_too_short", "loc": ["query", name],
            "msg": format!("String should have at least {minimum} characters"),
            "input": "[REDACTED]", "ctx": {"min_length": minimum},
        }));
    } else if length > maximum {
        errors.push(json!({
            "type": "string_too_long", "loc": ["query", name],
            "msg": format!("String should have at most {maximum} characters"),
            "input": "[REDACTED]", "ctx": {"max_length": maximum},
        }));
    }
    Some(value.clone())
}

async fn initiate_canvas_lti_login(
    State(state): State<IssuanceState>,
    Path(platform_id): Path<String>,
    request: Request,
) -> Result<Response, CanvasLtiLoginHttpError> {
    initiate_canvas_lti_login_mode(state, platform_id, request, CanvasLtiLoginMode::Launch).await
}

async fn verify_canvas_lti_launch(
    State(state): State<IssuanceState>,
    Path(platform_id): Path<String>,
    request: Request,
) -> Result<Response, CanvasLtiLaunchHttpError> {
    let service = state
        .canvas_lti_launch
        .as_ref()
        .ok_or(CanvasLtiLaunchPlanError::RepositoryUnavailable)?;
    // Preserve the Python boundary: platform lookup, pilot authorization, and
    // trust validation occur before request-body parsing.
    let platform = service.prepare_platform(&platform_id).await?;
    let submission = parse_canvas_lti_launch_submission(request).await?;
    let result = service.launch_prepared(platform, submission).await?;
    Ok(Json(public_launch_response(&result.response)).into_response())
}

async fn launch_canvas_lti_experience(
    State(state): State<IssuanceState>,
    Path(platform_id): Path<String>,
    request: Request,
) -> Result<Response, CanvasLtiLaunchHttpError> {
    let service = state
        .canvas_lti_experience
        .as_ref()
        .ok_or(CanvasLtiLaunchPlanError::RepositoryUnavailable)?;
    // Preserve the shared Python boundary: platform authorization and trust
    // validation happen before request-body parsing for both callback routes.
    let platform = service.prepare_platform(&platform_id).await?;
    let submission = parse_canvas_lti_launch_submission(request).await?;
    let result = service.launch_prepared(platform, submission).await?;
    let location = HeaderValue::from_str(&result.location)
        .map_err(|_| CanvasLtiLaunchPlanError::RepositoryUnavailable)?;
    Ok((StatusCode::SEE_OTHER, [(http_header::LOCATION, location)]).into_response())
}

async fn exchange_canvas_lti_experience_code(
    State(state): State<IssuanceState>,
    request: Request,
) -> Result<Response, CanvasLtiExperienceExchangeHttpError> {
    let code = parse_canvas_lti_experience_exchange(request).await?;
    let result = state
        .canvas_lti_experience_exchange
        .as_ref()
        .ok_or(CanvasLtiExperienceExchangeError::RepositoryUnavailable)?
        .exchange(&code)
        .await?;
    let response = Json(json!({
        "session_token": result.session_token,
        "expires_at": result.expires_at.to_rfc3339(),
    }))
    .into_response();
    Ok(private_no_store(response))
}

fn private_no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        http_header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response
        .headers_mut()
        .insert(http_header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

async fn get_canvas_lti_tool_jwks(
    State(state): State<IssuanceState>,
) -> Result<Json<Value>, CanvasLtiToolSigningHttpError> {
    let signer = state
        .canvas_lti_tool_signer
        .as_ref()
        .ok_or(CanvasLtiToolSigningError::ConfigurationIncomplete)?;
    Ok(Json(signer.public_jwks().await?))
}

async fn get_canvas_lti_experience_session(
    State(state): State<IssuanceState>,
    request: Request,
) -> Result<Response, CanvasLtiExperienceSessionHttpError> {
    let token = canvas_lti_experience_bearer_token(request.headers())?;
    let session = state
        .canvas_lti_experience_session
        .as_ref()
        .ok_or(CanvasLtiExperienceSessionError::RepositoryUnavailable)?
        .current(token)
        .await?;
    Ok(private_no_store(Json(session).into_response()))
}

async fn bootstrap_canvas_lti_experience_application(
    State(state): State<IssuanceState>,
    request: Request,
) -> Result<Response, CanvasLtiBootstrapHttpError> {
    // Match the Python dependency order: reject an invalid bearer before
    // parsing a caller-controlled body.
    let token = canvas_lti_experience_bearer_token(request.headers())
        .map_err(|_| CanvasLtiBootstrapHttpError::Unauthorized)?
        .to_owned();
    let request = parse_canvas_lti_bootstrap_request(request).await?;
    let response = state
        .canvas_lti_bootstrap
        .as_ref()
        .ok_or(CanvasLtiBootstrapServiceError::RepositoryUnavailable)?
        .bootstrap(&token, &request)
        .await?;
    Ok(private_no_store(Json(response).into_response()))
}

async fn create_canvas_lti_deep_linking_response(
    State(state): State<IssuanceState>,
    request: Request,
) -> Result<Response, CanvasLtiDeepLinkingHttpError> {
    // Match the session-bound Python boundary: authenticate before validating
    // even the confirmation-only request body.
    let token = canvas_lti_experience_bearer_token(request.headers())
        .map_err(|_| CanvasLtiDeepLinkingHttpError::Unauthorized)?
        .to_owned();
    parse_canvas_lti_deep_linking_request(request).await?;
    let response = state
        .canvas_lti_deep_linking
        .as_ref()
        .ok_or(CanvasLtiDeepLinkingError::RepositoryUnavailable)?
        .create_response(&token)
        .await?;
    Ok(private_no_store(Json(response).into_response()))
}

async fn get_canvas_lti_evidence_status(
    State(state): State<IssuanceState>,
    request: Request,
) -> Result<Response, CanvasLtiEvidenceHttpError> {
    let token = canvas_lti_experience_bearer_token(request.headers())
        .map_err(|_| CanvasLtiEvidenceHttpError::Unauthorized)?;
    let status = state
        .canvas_lti_evidence
        .as_ref()
        .ok_or(CanvasLtiEvidenceError::RepositoryUnavailable)?
        .status(token)
        .await?;
    Ok(private_no_store(Json(status).into_response()))
}

async fn sync_canvas_lti_evidence(
    State(state): State<IssuanceState>,
    request: Request,
) -> Result<Response, CanvasLtiEvidenceSyncHttpError> {
    let token = canvas_lti_experience_bearer_token(request.headers())
        .map_err(|_| CanvasLtiEvidenceSyncHttpError::Unauthorized)?;
    let status = state
        .canvas_lti_evidence_sync
        .as_ref()
        .ok_or(CanvasLtiEvidenceSyncEnqueueError::RepositoryUnavailable)?
        .sync(token)
        .await?;
    Ok(private_no_store(
        (StatusCode::ACCEPTED, Json(status)).into_response(),
    ))
}

fn canvas_lti_experience_bearer_token(
    headers: &HeaderMap,
) -> Result<&str, CanvasLtiExperienceSessionHttpError> {
    let authorization = headers
        .get(http_header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .trim();
    let Some((scheme, token)) = authorization.split_once(' ') else {
        return Err(CanvasLtiExperienceSessionHttpError::Unauthorized);
    };
    let token = token.trim();
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
        return Err(CanvasLtiExperienceSessionHttpError::Unauthorized);
    }
    Ok(token)
}

async fn initiate_canvas_lti_experience_login(
    State(state): State<IssuanceState>,
    Path(platform_id): Path<String>,
    request: Request,
) -> Result<Response, CanvasLtiLoginHttpError> {
    initiate_canvas_lti_login_mode(state, platform_id, request, CanvasLtiLoginMode::Experience)
        .await
}

async fn initiate_canvas_lti_login_mode(
    state: IssuanceState,
    platform_id: String,
    request: Request,
    mode: CanvasLtiLoginMode,
) -> Result<Response, CanvasLtiLoginHttpError> {
    let service = state
        .canvas_lti_login
        .as_ref()
        .ok_or(CanvasLtiLoginError::RepositoryUnavailable)?;
    let prepared = service.prepare(&platform_id, mode).await?;
    let submission = parse_canvas_lti_login_submission(request).await?;
    let location = service.initiate_prepared(prepared, submission).await?;
    let location =
        HeaderValue::from_str(&location).map_err(|_| CanvasLtiLoginError::RepositoryUnavailable)?;
    Ok((StatusCode::SEE_OTHER, [(http_header::LOCATION, location)]).into_response())
}

async fn parse_canvas_lti_login_submission(
    request: Request,
) -> Result<CanvasLtiLoginSubmission, CanvasLtiLoginHttpError> {
    let object = parse_canvas_lti_payload(request)
        .await
        .map_err(CanvasLtiLoginError::Invalid)?;
    Ok(CanvasLtiLoginSubmission::from_json_object(&object))
}

async fn parse_canvas_lti_launch_submission(
    request: Request,
) -> Result<CanvasLtiLaunchSubmission, CanvasLtiLaunchHttpError> {
    let object = parse_canvas_lti_payload(request)
        .await
        .map_err(CanvasLtiLaunchPlanError::Invalid)?;
    Ok(CanvasLtiLaunchSubmission::from_json_object(&object))
}

async fn parse_canvas_lti_experience_exchange(
    request: Request,
) -> Result<String, CanvasLtiExperienceExchangeHttpError> {
    const MAX_EXCHANGE_BODY_BYTES: usize = 64 * 1024;
    let is_json = request
        .headers()
        .get(http_header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| {
            let media_type = value.trim().to_ascii_lowercase();
            media_type == "application/json"
                || (media_type.starts_with("application/") && media_type.ends_with("+json"))
        });
    let bytes = to_bytes(request.into_body(), MAX_EXCHANGE_BODY_BYTES)
        .await
        .map_err(|_| CanvasLtiExperienceExchangeHttpError::BodyTooLarge)?;
    if !is_json {
        return Err(CanvasLtiExperienceExchangeHttpError::Validation(vec![
            json!({
                "type": "model_attributes_type",
                "loc": ["body"],
                "msg": "Input should be a valid dictionary or object to extract fields from",
                "input": String::from_utf8_lossy(&bytes),
            }),
        ]));
    }
    let input: Value = serde_json::from_slice(&bytes)
        .map_err(|_| CanvasLtiExperienceExchangeHttpError::InvalidJson)?;
    let Some(object) = input.as_object() else {
        return Err(CanvasLtiExperienceExchangeHttpError::Validation(vec![
            json!({
                "type": "model_attributes_type",
                "loc": ["body"],
                "msg": "Input should be a valid dictionary or object to extract fields from",
                "input": input,
            }),
        ]));
    };
    let mut errors = Vec::new();
    let code = match object.get("code") {
        None => {
            errors.push(json!({
                "type": "missing",
                "loc": ["body", "code"],
                "msg": "Field required",
                "input": object,
            }));
            None
        }
        Some(Value::String(code)) => {
            let length = code.chars().count();
            if length < 32 {
                errors.push(json!({
                    "type": "string_too_short",
                    "loc": ["body", "code"],
                    "msg": "String should have at least 32 characters",
                    "input": code,
                    "ctx": {"min_length": 32},
                }));
            } else if length > 256 {
                errors.push(json!({
                    "type": "string_too_long",
                    "loc": ["body", "code"],
                    "msg": "String should have at most 256 characters",
                    "input": code,
                    "ctx": {"max_length": 256},
                }));
            }
            Some(code.clone())
        }
        Some(value) => {
            errors.push(json!({
                "type": "string_type",
                "loc": ["body", "code"],
                "msg": "Input should be a valid string",
                "input": value,
            }));
            None
        }
    };
    for (name, value) in object.iter().filter(|(name, _)| name.as_str() != "code") {
        errors.push(json!({
            "type": "extra_forbidden",
            "loc": ["body", name],
            "msg": "Extra inputs are not permitted",
            "input": value,
        }));
    }
    if !errors.is_empty() {
        return Err(CanvasLtiExperienceExchangeHttpError::Validation(errors));
    }
    code.ok_or(CanvasLtiExperienceExchangeHttpError::Service(
        CanvasLtiExperienceExchangeError::InvalidConfiguration,
    ))
}

async fn parse_canvas_lti_payload(request: Request) -> Result<Map<String, Value>, &'static str> {
    const MAX_CANVAS_LTI_BODY_BYTES: usize = 64 * 1024;
    let content_type = request
        .headers()
        .get(http_header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .map(str::to_ascii_lowercase);
    let Some(content_type) = content_type else {
        return Ok(Map::new());
    };
    if content_type != "application/json" && content_type != "application/x-www-form-urlencoded" {
        // Match Starlette's request.form() boundary: unsupported media types
        // produce an empty form rather than interpreting arbitrary text as an
        // LTI submission.
        return Ok(Map::new());
    }
    let bytes = to_bytes(request.into_body(), MAX_CANVAS_LTI_BODY_BYTES)
        .await
        .map_err(|_| "Canvas LTI request body exceeds the size limit")?;
    if content_type == "application/json" {
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| "Invalid JSON body")?;
        return value
            .as_object()
            .cloned()
            .ok_or("Canvas LTI JSON body must be an object");
    }
    let mut object = Map::new();
    for (name, value) in url::form_urlencoded::parse(&bytes) {
        object.insert(name.into_owned(), Value::String(value.into_owned()));
    }
    Ok(object)
}

async fn root_issuer_metadata(
    State(state): State<IssuanceState>,
) -> Json<CredentialIssuerMetadata> {
    Json(state.documents.root_issuer_metadata())
}

async fn credential_type_metadata(
    State(state): State<IssuanceState>,
    Path(credential_type): Path<String>,
) -> Json<CredentialTypeMetadata> {
    Json(state.documents.credential_type_metadata(&credential_type))
}

async fn root_authorization_server_metadata(
    State(state): State<IssuanceState>,
) -> Json<AuthorizationServerMetadata> {
    Json(state.documents.root_authorization_server_metadata())
}

async fn organization_authorization_server_metadata(
    State(state): State<IssuanceState>,
    Path(organization_id): Path<String>,
) -> Json<AuthorizationServerMetadata> {
    Json(
        state
            .documents
            .organization_authorization_server_metadata(&organization_id, IssuerVariant::Default),
    )
}

async fn credential_manager_authorization_server_metadata(
    State(state): State<IssuanceState>,
    Path(organization_id): Path<String>,
) -> Json<AuthorizationServerMetadata> {
    Json(state.documents.organization_authorization_server_metadata(
        &organization_id,
        IssuerVariant::CredentialManager,
    ))
}

async fn apple_wallet_authorization_server_metadata(
    State(state): State<IssuanceState>,
    Path(organization_id): Path<String>,
) -> Json<AuthorizationServerMetadata> {
    Json(
        state.documents.organization_authorization_server_metadata(
            &organization_id,
            IssuerVariant::AppleWallet,
        ),
    )
}

async fn organization_issuer_metadata(
    State(state): State<IssuanceState>,
    Path(organization_id): Path<String>,
) -> Result<Json<CredentialIssuerMetadata>, TenantDiscoveryHttpError> {
    tenant_issuer_metadata(state, organization_id, IssuerVariant::Default).await
}

async fn credential_manager_issuer_metadata(
    State(state): State<IssuanceState>,
    Path(organization_id): Path<String>,
) -> Result<Json<CredentialIssuerMetadata>, TenantDiscoveryHttpError> {
    tenant_issuer_metadata(state, organization_id, IssuerVariant::CredentialManager).await
}

async fn apple_wallet_issuer_metadata(
    State(state): State<IssuanceState>,
    Path(organization_id): Path<String>,
) -> Result<Json<CredentialIssuerMetadata>, TenantDiscoveryHttpError> {
    tenant_issuer_metadata(state, organization_id, IssuerVariant::AppleWallet).await
}

async fn tenant_issuer_metadata(
    state: IssuanceState,
    organization_id: String,
    variant: IssuerVariant,
) -> Result<Json<CredentialIssuerMetadata>, TenantDiscoveryHttpError> {
    let tenant = state
        .tenant
        .ok_or(TenantDiscoveryError::RepositoryUnavailable)?;
    tenant
        .metadata(&organization_id, variant)
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn credential_offer(
    State(state): State<IssuanceState>,
    Path(transaction_id): Path<String>,
) -> Result<Json<Value>, TransactionReadHttpError> {
    transactions(&state)?
        .offer(&transaction_id)
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn exchange_token(
    State(state): State<IssuanceState>,
    headers: HeaderMap,
    RawForm(raw_form): RawForm,
) -> Result<Json<marty_oid4vci::types::TokenResponse>, TokenExchangeHttpError> {
    let request = token_request(&raw_form)?;
    let endpoint_url = external_endpoint_url(&headers, "/v1/issuance/token");
    state
        .token_exchange
        .as_ref()
        .ok_or(TokenExchangeError::RepositoryUnavailable)?
        .exchange(&request, header(&headers, "DPoP"), &endpoint_url)
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn issue_proof_nonce(
    State(state): State<IssuanceState>,
) -> Result<Response, ProofNonceHttpError> {
    let response = state
        .proof_nonce
        .as_ref()
        .ok_or(ProofNonceError::RepositoryUnavailable)?
        .issue()
        .await?;
    let mut response = Json(response).into_response();
    response.headers_mut().insert(
        http_header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

async fn issue_credential(
    State(state): State<IssuanceState>,
    headers: HeaderMap,
    Json(request): Json<CredentialRequest>,
) -> Result<Json<crate::credential::CredentialResponse>, CredentialIssuanceHttpError> {
    let endpoint_url = external_endpoint_url(&headers, "/v1/issuance/credential");
    state
        .credential
        .as_ref()
        .ok_or(CredentialIssuanceError::RepositoryUnavailable)?
        .issue(
            &request,
            header(&headers, "Authorization"),
            header(&headers, "DPoP"),
            &endpoint_url,
        )
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn initiate_issuance(State(state): State<IssuanceState>, request: Request) -> Response {
    let Some(service) = state.initiation.as_ref() else {
        return InitiationHttpError::Unavailable.into_response();
    };
    if let Err(error) = service.authorize(request.headers()) {
        return error.into_response();
    }
    let headers = request.headers().clone();
    let Json(input) = match Json::<InitiationRequest>::from_request(request, &state).await {
        Ok(input) => input,
        Err(rejection) => return rejection.into_response(),
    };
    match service.initiate_authorized(&headers, &input).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn deliver_didcomm_credential(
    State(state): State<IssuanceState>,
    request: Request,
) -> Response {
    let Some(service) = state.didcomm_delivery.as_ref() else {
        return InitiationDidcommHttpError::Delivery(
            crate::initiation_didcomm::NativeInitiationDidcommDeliveryError::InvalidConfiguration,
        )
        .into_response();
    };
    if let Err(error) = service.authorize(request.headers()) {
        return error.into_response();
    }
    let Json(input) = match Json::<DidcommDeliverRequest>::from_request(request, &state).await {
        Ok(input) => input,
        Err(rejection) => return rejection.into_response(),
    };
    match service.deliver_authorized(&input).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn token_rate_limit_middleware(
    State(limiter): State<Option<TokenRateLimiter>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(limiter) = limiter else {
        return next.run(request).await;
    };
    let client = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or("unknown".to_owned(), |ConnectInfo(address)| {
            address.ip().to_string()
        });
    if limiter.check(&client) {
        return next.run(request).await;
    }
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({"detail": "Rate limit exceeded"})),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&limiter.retry_after_seconds().to_string()) {
        response
            .headers_mut()
            .insert(http_header::RETRY_AFTER, value);
    }
    response
}

fn token_request(raw_form: &[u8]) -> Result<TokenExchangeRequest, TokenExchangeError> {
    let values = url::form_urlencoded::parse(raw_form)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let grant_type = values
        .get("grant_type")
        .cloned()
        .ok_or(TokenExchangeError::GrantTypeRequired)?;
    Ok(TokenExchangeRequest {
        grant_type,
        pre_authorized_code: values.get("pre-authorized_code").cloned(),
        code: values.get("code").cloned(),
        redirect_uri: values.get("redirect_uri").cloned(),
        client_id: values.get("client_id").cloned(),
        code_verifier: values.get("code_verifier").cloned(),
        client_assertion_type: values.get("client_assertion_type").cloned(),
        client_assertion: values.get("client_assertion").cloned(),
    })
}

fn external_endpoint_url(headers: &HeaderMap, path: &str) -> String {
    let protocol = header(headers, "x-forwarded-proto")
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("http");
    let host = header(headers, "x-forwarded-host")
        .or_else(|| header(headers, "host"))
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("localhost");
    format!("{protocol}://{host}{path}")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialStatusRequest {
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct CredentialStatusHttpResponse {
    id: String,
    issuer_did: Option<String>,
    status: String,
    status_updated_at: String,
    reason: Option<String>,
}

impl From<CredentialStatusView> for CredentialStatusHttpResponse {
    fn from(value: CredentialStatusView) -> Self {
        Self {
            id: value.id,
            issuer_did: value.issuer_did,
            status: value.status,
            status_updated_at: value
                .status_updated_at
                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, false),
            reason: value.reason,
        }
    }
}

async fn revoke_credential(
    State(state): State<IssuanceState>,
    Path(credential_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CredentialStatusRequest>,
) -> Result<Json<CredentialStatusHttpResponse>, CredentialManagementHttpError> {
    transition_credential(
        &state,
        &credential_id,
        &headers,
        CredentialLifecycleAction::Revoke,
        request.reason.as_deref(),
    )
    .await
}

async fn suspend_credential(
    State(state): State<IssuanceState>,
    Path(credential_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CredentialStatusRequest>,
) -> Result<Json<CredentialStatusHttpResponse>, CredentialManagementHttpError> {
    transition_credential(
        &state,
        &credential_id,
        &headers,
        CredentialLifecycleAction::Suspend,
        request.reason.as_deref(),
    )
    .await
}

async fn reinstate_credential(
    State(state): State<IssuanceState>,
    Path(credential_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CredentialStatusRequest>,
) -> Result<Json<CredentialStatusHttpResponse>, CredentialManagementHttpError> {
    transition_credential(
        &state,
        &credential_id,
        &headers,
        CredentialLifecycleAction::Reinstate,
        request.reason.as_deref(),
    )
    .await
}

async fn transition_credential(
    state: &IssuanceState,
    credential_id: &str,
    headers: &HeaderMap,
    action: CredentialLifecycleAction,
    reason: Option<&str>,
) -> Result<Json<CredentialStatusHttpResponse>, CredentialManagementHttpError> {
    credential_management(state)?
        .transition(
            credential_id,
            header(headers, "X-API-Key"),
            header(headers, "X-Organization-ID"),
            action,
            reason,
        )
        .await
        .map(CredentialStatusHttpResponse::from)
        .map(Json)
}

async fn get_credential_status(
    State(state): State<IssuanceState>,
    Path(credential_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<CredentialStatusHttpResponse>, CredentialManagementHttpError> {
    credential_management(&state)?
        .get_status(
            &credential_id,
            header(&headers, "X-API-Key"),
            header(&headers, "X-Organization-ID"),
        )
        .await
        .map(CredentialStatusHttpResponse::from)
        .map(Json)
}

fn credential_management(
    state: &IssuanceState,
) -> Result<&CredentialManagementHttpService, CredentialManagementHttpError> {
    state.credential_management.as_ref().ok_or_else(|| {
        CredentialManagementHttpError::Lifecycle(CredentialManagementError::RepositoryUnavailable(
            "service unavailable".to_owned(),
        ))
    })
}

async fn list_transactions(
    State(state): State<IssuanceState>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Result<Json<Vec<IssuanceTransactionResponse>>, TransactionReadHttpError> {
    let organization_id = organization_id(raw_query.as_deref());
    transactions(&state)?
        .list(
            organization_id.as_deref(),
            header(&headers, "X-API-Key"),
            header(&headers, "X-Organization-ID"),
        )
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn get_transaction(
    State(state): State<IssuanceState>,
    Path(transaction_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<IssuanceTransactionResponse>, TransactionReadHttpError> {
    transactions(&state)?
        .get(
            &transaction_id,
            header(&headers, "X-API-Key"),
            header(&headers, "X-Organization-ID"),
        )
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn transaction_revocation_status(
    State(state): State<IssuanceState>,
    Path(transaction_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<TransactionRevocationStatus>, TransactionReadHttpError> {
    transactions(&state)?
        .revocation_status(
            &transaction_id,
            header(&headers, "X-API-Key"),
            header(&headers, "X-Organization-ID"),
        )
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn transaction_owner(
    State(state): State<IssuanceState>,
    Path(transaction_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ResourceOwner>, TransactionReadHttpError> {
    transactions(&state)?
        .owner(&transaction_id, header(&headers, "X-API-Key"))
        .await
        .map(Json)
        .map_err(Into::into)
}

fn transactions(state: &IssuanceState) -> Result<&TransactionReadService, TransactionReadError> {
    state
        .transactions
        .as_ref()
        .ok_or(TransactionReadError::RepositoryUnavailable)
}

fn header<'headers>(headers: &'headers HeaderMap, name: &str) -> Option<&'headers str> {
    headers
        .get(name)
        .map(|value| value.to_str().unwrap_or("\0"))
}

fn organization_id(raw_query: Option<&str>) -> Option<String> {
    raw_query
        .into_iter()
        .flat_map(|query| url::form_urlencoded::parse(query.as_bytes()))
        .filter(|(name, _)| name == "organization_id")
        .map(|(_, value)| value.into_owned())
        .last()
}

struct TenantDiscoveryHttpError(TenantDiscoveryError);

impl From<TenantDiscoveryError> for TenantDiscoveryHttpError {
    fn from(value: TenantDiscoveryError) -> Self {
        Self(value)
    }
}

struct TokenExchangeHttpError(TokenExchangeError);

struct ProofNonceHttpError(ProofNonceError);

struct CredentialIssuanceHttpError(CredentialIssuanceError);

struct CanvasLtiLoginHttpError(CanvasLtiLoginError);

struct CanvasLtiLaunchHttpError(CanvasLtiLaunchServiceError);

struct CanvasLtiToolSigningHttpError(CanvasLtiToolSigningError);

impl From<CanvasLtiToolSigningError> for CanvasLtiToolSigningHttpError {
    fn from(value: CanvasLtiToolSigningError) -> Self {
        Self(value)
    }
}

impl IntoResponse for CanvasLtiToolSigningHttpError {
    fn into_response(self) -> Response {
        let _cause = self.0;
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"detail": "Canvas LTI tool signing is temporarily unavailable"})),
        )
            .into_response()
    }
}

enum CanvasLtiExperienceExchangeHttpError {
    Service(CanvasLtiExperienceExchangeError),
    Validation(Vec<Value>),
    InvalidJson,
    BodyTooLarge,
}

async fn parse_canvas_lti_bootstrap_request(
    request: Request,
) -> Result<CanvasLtiBootstrapRequest, CanvasLtiBootstrapHttpError> {
    const MAX_BOOTSTRAP_BODY_BYTES: usize = 64 * 1024;
    let is_json = request
        .headers()
        .get(http_header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| {
            let media_type = value.trim().to_ascii_lowercase();
            media_type == "application/json"
                || (media_type.starts_with("application/") && media_type.ends_with("+json"))
        });
    let bytes = to_bytes(request.into_body(), MAX_BOOTSTRAP_BODY_BYTES)
        .await
        .map_err(|_| CanvasLtiBootstrapHttpError::BodyTooLarge)?;
    if !is_json {
        return Err(CanvasLtiBootstrapHttpError::Validation(vec![json!({
            "type": "model_attributes_type",
            "loc": ["body"],
            "msg": "Input should be a valid dictionary or object to extract fields from",
            "input": String::from_utf8_lossy(&bytes),
        })]));
    }
    let input: Value = serde_json::from_slice(&bytes).map_err(|error| {
        CanvasLtiBootstrapHttpError::Validation(vec![json!({
            "type": "json_invalid",
            "loc": ["body", error.line(), error.column()],
            "msg": "JSON decode error",
            "input": {},
            "ctx": {"error": error.to_string()},
        })])
    })?;
    let Some(object) = input.as_object() else {
        return Err(CanvasLtiBootstrapHttpError::Validation(vec![json!({
            "type": "model_attributes_type",
            "loc": ["body"],
            "msg": "Input should be a valid dictionary or object to extract fields from",
            "input": input,
        })]));
    };
    let mut errors = Vec::new();
    let applicant_identifier = match object.get("applicant_identifier") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.clone()),
        Some(value) => {
            errors.push(json!({
                "type": "string_type",
                "loc": ["body", "applicant_identifier"],
                "msg": "Input should be a valid string",
                "input": value,
            }));
            None
        }
    };
    let applicant_data = match object.get("applicant_data") {
        None => Map::new(),
        Some(Value::Object(value)) => value.clone(),
        Some(value) => {
            errors.push(json!({
                "type": "dict_type",
                "loc": ["body", "applicant_data"],
                "msg": "Input should be a valid dictionary",
                "input": value,
            }));
            Map::new()
        }
    };
    if !errors.is_empty() {
        return Err(CanvasLtiBootstrapHttpError::Validation(errors));
    }
    Ok(CanvasLtiBootstrapRequest {
        applicant_identifier,
        applicant_data,
    })
}

async fn parse_canvas_lti_deep_linking_request(
    request: Request,
) -> Result<(), CanvasLtiDeepLinkingHttpError> {
    const MAX_DEEP_LINKING_BODY_BYTES: usize = 64 * 1024;
    let is_json = request
        .headers()
        .get(http_header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| {
            let media_type = value.trim().to_ascii_lowercase();
            media_type == "application/json"
                || (media_type.starts_with("application/") && media_type.ends_with("+json"))
        });
    let bytes = to_bytes(request.into_body(), MAX_DEEP_LINKING_BODY_BYTES)
        .await
        .map_err(|_| CanvasLtiDeepLinkingHttpError::BodyTooLarge)?;
    if bytes.is_empty() {
        return Err(CanvasLtiDeepLinkingHttpError::Validation(vec![json!({
            "type": "missing",
            "loc": ["body"],
            "msg": "Field required",
            "input": null,
        })]));
    }
    if !is_json {
        return Err(CanvasLtiDeepLinkingHttpError::Validation(vec![json!({
            "type": "model_attributes_type",
            "loc": ["body"],
            "msg": "Input should be a valid dictionary or object to extract fields from",
            "input": String::from_utf8_lossy(&bytes),
        })]));
    }
    let input: Value = serde_json::from_slice(&bytes).map_err(|error| {
        CanvasLtiDeepLinkingHttpError::Validation(vec![json!({
            "type": "json_invalid",
            "loc": ["body", error.line(), error.column()],
            "msg": "JSON decode error",
            "input": {},
            "ctx": {"error": error.to_string()},
        })])
    })?;
    let Some(object) = input.as_object() else {
        return Err(CanvasLtiDeepLinkingHttpError::Validation(vec![json!({
            "type": "model_attributes_type",
            "loc": ["body"],
            "msg": "Input should be a valid dictionary or object to extract fields from",
            "input": input,
        })]));
    };
    if object.is_empty() {
        return Ok(());
    }
    Err(CanvasLtiDeepLinkingHttpError::Validation(
        object
            .iter()
            .map(|(name, value)| {
                json!({
                    "type": "extra_forbidden",
                    "loc": ["body", name],
                    "msg": "Extra inputs are not permitted",
                    "input": value,
                })
            })
            .collect(),
    ))
}

enum CanvasOAuthHttpError {
    Service(CanvasOAuthError),
    Validation(Vec<Value>),
    BodyTooLarge,
}

impl From<CanvasOAuthError> for CanvasOAuthHttpError {
    fn from(value: CanvasOAuthError) -> Self {
        Self::Service(value)
    }
}

impl IntoResponse for CanvasOAuthHttpError {
    fn into_response(self) -> Response {
        use CanvasOAuthError as Error;

        let response = match self {
            Self::Validation(errors) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail": errors})),
            )
                .into_response(),
            Self::BodyTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({"detail": "Canvas OAuth request body exceeds the size limit"})),
            )
                .into_response(),
            Self::Service(Error::Security(error)) => {
                TransactionReadHttpError(error).into_response()
            }
            Self::Service(
                Error::RepositoryUnavailable
                | Error::SecretUnavailable
                | Error::InvalidConfiguration,
            ) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response(),
            Self::Service(error) => {
                let (status, detail) = match error {
                    Error::PlatformNotFound => (StatusCode::NOT_FOUND, error.to_string()),
                    Error::PilotDisabled => (StatusCode::NOT_FOUND, error.to_string()),
                    Error::SecretNotFound => (StatusCode::NOT_FOUND, error.to_string()),
                    Error::BaseUrlRequired
                    | Error::OriginUntrusted
                    | Error::ConnectionExists
                    | Error::ConfigurationChanged
                    | Error::ConnectionChanged => (StatusCode::CONFLICT, error.to_string()),
                    Error::ClientIdRequired
                    | Error::CapabilitiesRequired
                    | Error::UnsupportedCapabilities(_) => {
                        (StatusCode::BAD_REQUEST, error.to_string())
                    }
                    Error::RepositoryUnavailable
                    | Error::SecretUnavailable
                    | Error::InvalidConfiguration => unreachable!("handled above"),
                    Error::Security(_) => unreachable!("handled above"),
                };
                (status, Json(json!({"detail": detail}))).into_response()
            }
        };
        canvas_oauth_no_store(response)
    }
}

enum CanvasLtiExperienceSessionHttpError {
    Unauthorized,
    Service(CanvasLtiExperienceSessionError),
}

enum CanvasLtiBootstrapHttpError {
    Unauthorized,
    Service(CanvasLtiBootstrapServiceError),
    Validation(Vec<Value>),
    BodyTooLarge,
}

enum CanvasLtiDeepLinkingHttpError {
    Unauthorized,
    Service(CanvasLtiDeepLinkingError),
    Validation(Vec<Value>),
    BodyTooLarge,
}

enum CanvasLtiEvidenceHttpError {
    Unauthorized,
    Service(CanvasLtiEvidenceError),
}

enum CanvasLtiEvidenceSyncHttpError {
    Unauthorized,
    Service(CanvasLtiEvidenceSyncError),
}

impl From<CanvasLtiEvidenceSyncError> for CanvasLtiEvidenceSyncHttpError {
    fn from(value: CanvasLtiEvidenceSyncError) -> Self {
        Self::Service(value)
    }
}

impl From<CanvasLtiEvidenceSyncEnqueueError> for CanvasLtiEvidenceSyncHttpError {
    fn from(value: CanvasLtiEvidenceSyncEnqueueError) -> Self {
        Self::Service(CanvasLtiEvidenceSyncError::Enqueue(value))
    }
}

impl IntoResponse for CanvasLtiEvidenceSyncHttpError {
    fn into_response(self) -> Response {
        let response = match self {
            Self::Unauthorized => CanvasLtiExperienceSessionHttpError::Unauthorized.into_response(),
            Self::Service(CanvasLtiEvidenceSyncError::Evidence(error)) => {
                CanvasLtiEvidenceHttpError::Service(error).into_response()
            }
            Self::Service(CanvasLtiEvidenceSyncError::Enqueue(
                CanvasLtiEvidenceSyncEnqueueError::NotFound,
            )) => (
                StatusCode::NOT_FOUND,
                Json(json!({"detail": "Canvas application context was not found"})),
            )
                .into_response(),
            Self::Service(CanvasLtiEvidenceSyncError::Enqueue(
                CanvasLtiEvidenceSyncEnqueueError::Conflict { code },
            )) => (
                StatusCode::CONFLICT,
                Json(json!({
                    "detail": {
                        "code": code,
                        "message": "Canvas synchronization is unavailable"
                    }
                })),
            )
                .into_response(),
            Self::Service(CanvasLtiEvidenceSyncError::Enqueue(
                CanvasLtiEvidenceSyncEnqueueError::RepositoryUnavailable,
            )) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response(),
        };
        private_no_store(response)
    }
}

impl From<CanvasLtiEvidenceError> for CanvasLtiEvidenceHttpError {
    fn from(value: CanvasLtiEvidenceError) -> Self {
        Self::Service(value)
    }
}

impl IntoResponse for CanvasLtiEvidenceHttpError {
    fn into_response(self) -> Response {
        use CanvasLtiEvidenceError as Error;
        let response = match self {
            Self::Unauthorized => CanvasLtiExperienceSessionHttpError::Unauthorized.into_response(),
            Self::Service(Error::SessionNotFound) => (
                StatusCode::NOT_FOUND,
                Json(json!({"detail": "Canvas LTI experience session not found"})),
            )
                .into_response(),
            Self::Service(error @ (Error::ContextNotFound | Error::PilotDisabled)) => (
                StatusCode::NOT_FOUND,
                Json(json!({"detail": error.to_string()})),
            )
                .into_response(),
            Self::Service(
                error @ (Error::BootstrapRequired | Error::EvidenceConfigurationUnavailable),
            ) => (
                StatusCode::CONFLICT,
                Json(json!({"detail": error.to_string()})),
            )
                .into_response(),
            Self::Service(Error::RepositoryUnavailable) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
            }
        };
        private_no_store(response)
    }
}

impl From<CanvasLtiDeepLinkingError> for CanvasLtiDeepLinkingHttpError {
    fn from(value: CanvasLtiDeepLinkingError) -> Self {
        Self::Service(value)
    }
}

impl IntoResponse for CanvasLtiDeepLinkingHttpError {
    fn into_response(self) -> Response {
        use CanvasLtiDeepLinkingError as Error;
        let response = match self {
            Self::Unauthorized => CanvasLtiExperienceSessionHttpError::Unauthorized.into_response(),
            Self::Service(Error::SessionNotFound) => (
                StatusCode::NOT_FOUND,
                Json(json!({"detail": "Canvas LTI experience session not found"})),
            )
                .into_response(),
            Self::Service(error @ (Error::PilotDisabled | Error::PlatformNotFound)) => {
                (StatusCode::NOT_FOUND, Json(json!({"detail": error.to_string()}))).into_response()
            }
            Self::Service(Error::StaffRoleRequired) => (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "detail": "Canvas Deep Linking requires an authenticated Instructor or Administrator role"
                })),
            )
                .into_response(),
            Self::Service(
                error @ (Error::FeatureDisabled
                | Error::BindingMismatch
                | Error::CapabilityMissing
                | Error::ResourceLinksNotAccepted
                | Error::ReturnUrlMissing
                | Error::ReturnUrlUntrusted
                | Error::InvalidEvidenceRequirements(_)
                | Error::SigningClaimsInvalid
                | Error::ConfigurationDrift),
            ) => (StatusCode::CONFLICT, Json(json!({"detail": error.to_string()}))).into_response(),
            Self::Service(Error::NonceGenerationFailed | Error::SigningUnavailable(_)) => {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"detail": "Canvas LTI tool signing is temporarily unavailable"})),
                )
                    .into_response()
            }
            Self::Service(Error::RepositoryUnavailable) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
            }
            Self::Validation(errors) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail": errors})),
            )
                .into_response(),
            Self::BodyTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({"detail": "Canvas LTI Deep Linking body exceeds the size limit"})),
            )
                .into_response(),
        };
        private_no_store(response)
    }
}

impl From<CanvasLtiBootstrapServiceError> for CanvasLtiBootstrapHttpError {
    fn from(value: CanvasLtiBootstrapServiceError) -> Self {
        Self::Service(value)
    }
}

impl IntoResponse for CanvasLtiBootstrapHttpError {
    fn into_response(self) -> Response {
        let response = match self {
            Self::Unauthorized => CanvasLtiExperienceSessionHttpError::Unauthorized.into_response(),
            Self::Service(CanvasLtiBootstrapServiceError::SessionNotFound)
            | Self::Service(CanvasLtiBootstrapServiceError::Plan(
                CanvasLtiBootstrapPlanError::InvalidSession,
            )) => (
                StatusCode::NOT_FOUND,
                Json(json!({"detail": "Canvas LTI experience session not found"})),
            )
                .into_response(),
            Self::Service(CanvasLtiBootstrapServiceError::Plan(cause)) => {
                let status = match cause {
                    CanvasLtiBootstrapPlanError::PilotDisabled
                    | CanvasLtiBootstrapPlanError::ApplicationTemplateNotFound => {
                        StatusCode::NOT_FOUND
                    }
                    CanvasLtiBootstrapPlanError::FeatureDisabled
                    | CanvasLtiBootstrapPlanError::MissingApplicationTemplate
                    | CanvasLtiBootstrapPlanError::CrossOrganizationTemplate => {
                        StatusCode::CONFLICT
                    }
                    CanvasLtiBootstrapPlanError::InvalidSession => unreachable!(),
                };
                (status, Json(json!({"detail": cause.to_string()}))).into_response()
            }
            Self::Service(CanvasLtiBootstrapServiceError::RepositoryUnavailable) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
            }
            Self::Validation(errors) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail": errors})),
            )
                .into_response(),
            Self::BodyTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({"detail": "Canvas LTI bootstrap body exceeds the size limit"})),
            )
                .into_response(),
        };
        private_no_store(response)
    }
}

impl From<CanvasLtiExperienceSessionError> for CanvasLtiExperienceSessionHttpError {
    fn from(value: CanvasLtiExperienceSessionError) -> Self {
        Self::Service(value)
    }
}

impl IntoResponse for CanvasLtiExperienceSessionHttpError {
    fn into_response(self) -> Response {
        let response = match self {
            Self::Unauthorized => {
                let mut response = (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "detail": "Canvas LTI experience session bearer token is required"
                    })),
                )
                    .into_response();
                response.headers_mut().insert(
                    http_header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Bearer"),
                );
                response
            }
            Self::Service(CanvasLtiExperienceSessionError::NotFound) => (
                StatusCode::NOT_FOUND,
                Json(json!({"detail": "Canvas LTI experience session not found"})),
            )
                .into_response(),
            Self::Service(CanvasLtiExperienceSessionError::RepositoryUnavailable) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
            }
        };
        private_no_store(response)
    }
}

impl From<CanvasLtiExperienceExchangeError> for CanvasLtiExperienceExchangeHttpError {
    fn from(value: CanvasLtiExperienceExchangeError) -> Self {
        Self::Service(value)
    }
}

impl IntoResponse for CanvasLtiExperienceExchangeHttpError {
    fn into_response(self) -> Response {
        match self {
            Self::Service(CanvasLtiExperienceExchangeError::InvalidCode) => (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "detail": "Canvas LTI experience code has expired, is invalid, or was already used"
                })),
            )
                .into_response(),
            Self::Service(
                CanvasLtiExperienceExchangeError::RepositoryUnavailable
                | CanvasLtiExperienceExchangeError::InvalidConfiguration,
            ) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response(),
            Self::Validation(errors) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail": errors})),
            )
                .into_response(),
            Self::InvalidJson => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "detail": [{
                        "type": "json_invalid",
                        "loc": ["body", 0],
                        "msg": "JSON decode error",
                        "input": {},
                        "ctx": {"error": "Invalid JSON"},
                    }]
                })),
            )
                .into_response(),
            Self::BodyTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({"detail": "Canvas LTI exchange body exceeds the size limit"})),
            )
                .into_response(),
        }
    }
}

impl From<CanvasLtiLoginError> for CanvasLtiLoginHttpError {
    fn from(value: CanvasLtiLoginError) -> Self {
        Self(value)
    }
}

impl IntoResponse for CanvasLtiLoginHttpError {
    fn into_response(self) -> Response {
        let (status, detail) = canvas_lti_login_status_detail(self.0);
        (status, Json(json!({"detail": detail}))).into_response()
    }
}

impl From<CanvasLtiLaunchServiceError> for CanvasLtiLaunchHttpError {
    fn from(value: CanvasLtiLaunchServiceError) -> Self {
        Self(value)
    }
}

impl From<CanvasLtiLaunchPlanError> for CanvasLtiLaunchHttpError {
    fn from(value: CanvasLtiLaunchPlanError) -> Self {
        Self(CanvasLtiLaunchServiceError::Launch(value))
    }
}

impl IntoResponse for CanvasLtiLaunchHttpError {
    fn into_response(self) -> Response {
        let (status, detail) = match self.0 {
            CanvasLtiLaunchServiceError::Platform(CanvasLtiLoginError::RepositoryUnavailable) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Canvas LTI launch is temporarily unavailable".to_owned(),
            ),
            CanvasLtiLaunchServiceError::Platform(error) => canvas_lti_login_status_detail(error),
            CanvasLtiLaunchServiceError::Launch(error) => {
                use CanvasLtiLaunchPlanError as Error;
                match error {
                    error @ (Error::Invalid(_)
                    | Error::Verification(_)
                    | Error::VerificationAfterJwksRefresh(_)
                    | Error::JwksRefresh(_)
                    | Error::StateUnknown
                    | Error::StateExpired) => (StatusCode::BAD_REQUEST, error.to_string()),
                    error @ (Error::BindingNotFound
                    | Error::FeatureDisabled
                    | Error::AgsBindingMismatch
                    | Error::AgsRequirementMismatch
                    | Error::AgsLineItem(_)
                    | Error::CapabilityScopeMismatch
                    | Error::CapabilityConfigurationDrift) => {
                        (StatusCode::CONFLICT, error.to_string())
                    }
                    Error::RepositoryUnavailable => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Canvas LTI launch is temporarily unavailable".to_owned(),
                    ),
                }
            }
        };
        (status, Json(json!({"detail": detail}))).into_response()
    }
}

fn canvas_lti_login_status_detail(error: CanvasLtiLoginError) -> (StatusCode, String) {
    match error {
        error @ (CanvasLtiLoginError::PlatformNotFound | CanvasLtiLoginError::PilotDisabled) => {
            (StatusCode::NOT_FOUND, error.to_string())
        }
        CanvasLtiLoginError::Invalid(detail) => (StatusCode::BAD_REQUEST, detail.to_owned()),
        CanvasLtiLoginError::Conflict(detail) => (StatusCode::CONFLICT, detail.to_owned()),
        CanvasLtiLoginError::TrustConflict(detail) => (StatusCode::CONFLICT, detail),
        CanvasLtiLoginError::RepositoryUnavailable => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Canvas LTI login is temporarily unavailable".to_owned(),
        ),
    }
}

impl From<CredentialIssuanceError> for CredentialIssuanceHttpError {
    fn from(value: CredentialIssuanceError) -> Self {
        Self(value)
    }
}

impl IntoResponse for CredentialIssuanceHttpError {
    fn into_response(self) -> Response {
        use CredentialIssuanceError as Error;

        let (status, body) = match self.0 {
            Error::MissingAuthorization => (
                StatusCode::UNAUTHORIZED,
                json!({"detail": "Missing or invalid authorization"}),
            ),
            Error::InvalidAccessToken => (
                StatusCode::UNAUTHORIZED,
                json!({"detail": "Invalid access token"}),
            ),
            Error::DpopRequired => (
                StatusCode::UNAUTHORIZED,
                json!({"detail": "DPoP proof is required for this access token"}),
            ),
            Error::InvalidDpopProof => (
                StatusCode::UNAUTHORIZED,
                json!({"detail": "Invalid DPoP proof"}),
            ),
            Error::DpopMismatch => (
                StatusCode::UNAUTHORIZED,
                json!({"detail": "DPoP proof does not match access token"}),
            ),
            Error::SelectorRequired => (
                StatusCode::BAD_REQUEST,
                json!({
                    "error": "invalid_credential_request",
                    "error_description": "Provide exactly one of credential_configuration_id or credential_identifier"
                }),
            ),
            Error::CredentialAlreadyIssued => (
                StatusCode::BAD_REQUEST,
                json!({
                    "error": "invalid_credential_request",
                    "error_description": "Credential already issued — access token is single-use"
                }),
            ),
            Error::InvalidTransactionState => (
                StatusCode::BAD_REQUEST,
                json!({
                    "error": "invalid_credential_request",
                    "error_description": "Invalid transaction state"
                }),
            ),
            Error::UnknownConfiguration(value) => (
                StatusCode::BAD_REQUEST,
                json!({
                    "error": "unknown_credential_configuration",
                    "error_description": format!("Unknown credential_configuration_id: '{value}'")
                }),
            ),
            Error::UnknownIdentifier(value) => (
                StatusCode::BAD_REQUEST,
                json!({
                    "error": "unknown_credential_identifier",
                    "error_description": format!("Unknown credential_identifier: '{value}'")
                }),
            ),
            Error::ProofRequired => (
                StatusCode::BAD_REQUEST,
                json!({
                    "error": "invalid_proof",
                    "error_description": "Proof of possession is required per OID4VCI §7.2"
                }),
            ),
            Error::MalformedProof => (
                StatusCode::BAD_REQUEST,
                json!({
                    "error": "invalid_proof",
                    "error_description": "Could not decode proof JWT audience"
                }),
            ),
            Error::AudienceMismatch { allowed, actual } => (
                StatusCode::BAD_REQUEST,
                json!({
                    "error": "invalid_proof",
                    "error_description": format!(
                        "OID4VCI §8.2: proof JWT aud MUST be the credential_issuer URL (path in ('{}', '{}', '{}', '{}')), got '{}'",
                        allowed[0], allowed[1], allowed[2], allowed[3], actual
                    )
                }),
            ),
            Error::InvalidNonce => (
                StatusCode::BAD_REQUEST,
                json!({
                    "error": "invalid_nonce",
                    "error_description": "Proof nonce is missing, expired, or already used"
                }),
            ),
            Error::InvalidProof(description) => (
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid_proof", "error_description": description}),
            ),
            Error::NonceRepositoryUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                json!({
                    "error": "temporarily_unavailable",
                    "error_description": "Proof nonce storage is unavailable"
                }),
            ),
            Error::MdocHolderKeyRequired => (
                StatusCode::BAD_REQUEST,
                json!({
                    "error": "invalid_proof",
                    "error_description": "mso_mdoc issuance requires a cryptographically verified holder public JWK for device-key binding"
                }),
            ),
            Error::IssuanceInProgress => (
                StatusCode::CONFLICT,
                json!({
                    "error": "issuance_in_progress",
                    "error_description": "Credential signing is already in progress for this transaction"
                }),
            ),
            Error::UnsupportedFormat(value) => (
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"detail": format!("Unsupported credential signing format: {value}")}),
            ),
            Error::IssuerUnavailable(detail)
            | Error::SigningUnavailable(detail)
            | Error::LifecycleUnavailable(detail) => {
                (StatusCode::SERVICE_UNAVAILABLE, json!({"detail": detail}))
            }
            Error::RevocationProfileRequired => (
                StatusCode::UNPROCESSABLE_ENTITY,
                json!({"detail": "The Credential Template has no Revocation Profile."}),
            ),
            Error::CanvasEligibilityDenied => (
                StatusCode::BAD_REQUEST,
                json!({
                    "error": "invalid_credential_request",
                    "error_description": "Credential eligibility requirements are not satisfied"
                }),
            ),
            Error::BuilderChangedCredentialId
            | Error::InvalidStoredDataIntegrityCredential
            | Error::RepositoryUnavailable => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"detail": "Credential issuance is temporarily unavailable"}),
            ),
        };
        (status, Json(body)).into_response()
    }
}

impl IntoResponse for CredentialManagementHttpError {
    fn into_response(self) -> Response {
        let (status, detail) = match self {
            Self::Security(error) => match error {
                TransactionReadError::ApiKeyNotConfigured => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "ISSUANCE_API_KEY not configured on server",
                ),
                TransactionReadError::ApiKeyMissing => {
                    (StatusCode::UNAUTHORIZED, "X-API-Key header is missing")
                }
                TransactionReadError::InvalidApiKey => {
                    (StatusCode::UNAUTHORIZED, "Invalid API Key")
                }
                TransactionReadError::TrustedOrganizationRequired => (
                    StatusCode::FORBIDDEN,
                    "Trusted organization context is required",
                ),
                TransactionReadError::ResourceNotFound => {
                    (StatusCode::NOT_FOUND, "Resource not found")
                }
                TransactionReadError::OrganizationMismatch => (
                    StatusCode::FORBIDDEN,
                    "Organization context does not match requested organization",
                ),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Credential lifecycle service is temporarily unavailable",
                ),
            },
            Self::Lifecycle(error) => match error {
                CredentialManagementError::NotFound => {
                    (StatusCode::NOT_FOUND, "Credential not found")
                }
                CredentialManagementError::ResourceNotFound => {
                    (StatusCode::NOT_FOUND, "Resource not found")
                }
                CredentialManagementError::AlreadyRevoked => {
                    (StatusCode::BAD_REQUEST, "Credential already revoked")
                }
                CredentialManagementError::CannotSuspendRevoked => {
                    (StatusCode::BAD_REQUEST, "Cannot suspend revoked credential")
                }
                CredentialManagementError::CannotReinstateRevoked => (
                    StatusCode::BAD_REQUEST,
                    "Cannot reinstate revoked credential",
                ),
                CredentialManagementError::NotSuspended => (
                    StatusCode::BAD_REQUEST,
                    "Only suspended credentials can be reinstated",
                ),
                CredentialManagementError::ReasonTooLong => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Credential lifecycle reason exceeds 2000 characters",
                ),
                CredentialManagementError::RepositoryUnavailable(_) => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Credential repository is temporarily unavailable",
                ),
                CredentialManagementError::PublicationUnavailable(_) => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Revocation service unavailable",
                ),
                CredentialManagementError::CanvasRetryUnavailable(_) => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Canvas lifecycle retry could not be recorded",
                ),
            },
        };
        (status, Json(json!({"detail": detail}))).into_response()
    }
}

impl From<ProofNonceError> for ProofNonceHttpError {
    fn from(value: ProofNonceError) -> Self {
        Self(value)
    }
}

impl IntoResponse for ProofNonceHttpError {
    fn into_response(self) -> Response {
        match self.0 {
            ProofNonceError::RepositoryUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"detail": "Proof nonce storage is unavailable"})),
            )
                .into_response(),
        }
    }
}

impl From<TokenExchangeError> for TokenExchangeHttpError {
    fn from(value: TokenExchangeError) -> Self {
        Self(value)
    }
}

impl IntoResponse for TokenExchangeHttpError {
    fn into_response(self) -> Response {
        if self.0 == TokenExchangeError::RepositoryUnavailable {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response();
        }
        let (status, body) = match self.0 {
            TokenExchangeError::GrantTypeRequired => (
                StatusCode::UNPROCESSABLE_ENTITY,
                json!({
                    "detail": [{
                        "type": "missing",
                        "loc": ["body", "grant_type"],
                        "msg": "Field required",
                        "input": null
                    }]
                }),
            ),
            TokenExchangeError::InvalidDpopProof => (
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid_dpop_proof"}),
            ),
            TokenExchangeError::AuthorizationCodeRequired => (
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid_request", "error_description": "code is required"}),
            ),
            TokenExchangeError::InvalidAuthorizationCode => (
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid_grant", "error_description": "Invalid authorization code"}),
            ),
            TokenExchangeError::AuthorizationCodeExpired => (
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid_grant", "error_description": "Authorization code expired"}),
            ),
            TokenExchangeError::AuthorizationCodeUsed => (
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid_grant", "error_description": "Authorization code already used"}),
            ),
            TokenExchangeError::PreAuthorizedCodeRequired => (
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid_request", "error_description": "pre-authorized_code is required"}),
            ),
            TokenExchangeError::UnsupportedGrantType => (
                StatusCode::BAD_REQUEST,
                json!({"error": "unsupported_grant_type", "error_description": "Unsupported grant type"}),
            ),
            TokenExchangeError::InvalidPreAuthorizedCode => (
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid_grant", "error_description": "Invalid pre-authorized code"}),
            ),
            TokenExchangeError::TransactionExpired => (
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid_grant", "error_description": "Transaction expired"}),
            ),
            TokenExchangeError::PreAuthorizedCodeUsed => (
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid_grant", "error_description": "Pre-authorized code has already been used and is single-use only"}),
            ),
            TokenExchangeError::InvalidTransactionState => (
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid_grant", "error_description": "Invalid transaction state"}),
            ),
            TokenExchangeError::InvalidClient => (
                StatusCode::UNAUTHORIZED,
                json!({"error": "invalid_client", "error_description": "Client authentication failed"}),
            ),
            TokenExchangeError::Protocol(description) => (
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid_grant", "error_description": description}),
            ),
            TokenExchangeError::RepositoryUnavailable => unreachable!("handled above"),
        };
        (status, Json(body)).into_response()
    }
}

impl IntoResponse for TenantDiscoveryHttpError {
    fn into_response(self) -> Response {
        let (status, detail) = match self.0 {
            TenantDiscoveryError::ProofPolicyUnavailable | TenantDiscoveryError::IncompletePlan => {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Issuer proof policy is temporarily unavailable",
                )
            }
            TenantDiscoveryError::RepositoryUnavailable => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Tenant credential metadata is temporarily unavailable",
            ),
        };
        (status, Json(json!({"detail": detail}))).into_response()
    }
}

struct TransactionReadHttpError(TransactionReadError);

impl From<TransactionReadError> for TransactionReadHttpError {
    fn from(value: TransactionReadError) -> Self {
        Self(value)
    }
}

impl IntoResponse for TransactionReadHttpError {
    fn into_response(self) -> Response {
        if self.0 == TransactionReadError::OrganizationIdRequired {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "detail": [{
                        "type": "missing",
                        "loc": ["query", "organization_id"],
                        "msg": "Field required",
                        "input": null
                    }]
                })),
            )
                .into_response();
        }
        let (status, detail) = match self.0 {
            TransactionReadError::OfferNotFound => (StatusCode::NOT_FOUND, "Offer not found"),
            TransactionReadError::OfferExpired => (StatusCode::GONE, "Offer expired"),
            TransactionReadError::TransactionNotFound => {
                (StatusCode::NOT_FOUND, "Transaction not found")
            }
            TransactionReadError::ResourceNotFound => (StatusCode::NOT_FOUND, "Resource not found"),
            TransactionReadError::ApiKeyNotConfigured => (
                StatusCode::SERVICE_UNAVAILABLE,
                "ISSUANCE_API_KEY not configured on server",
            ),
            TransactionReadError::ApiKeyMissing => {
                (StatusCode::UNAUTHORIZED, "X-API-Key header is missing")
            }
            TransactionReadError::InvalidApiKey => (StatusCode::UNAUTHORIZED, "Invalid API Key"),
            TransactionReadError::TrustedOrganizationRequired => (
                StatusCode::FORBIDDEN,
                "Trusted organization context is required",
            ),
            TransactionReadError::OrganizationMismatch => (
                StatusCode::FORBIDDEN,
                "Organization context does not match requested organization",
            ),
            TransactionReadError::OrganizationIdRequired => unreachable!("handled above"),
            TransactionReadError::RepositoryUnavailable
            | TransactionReadError::OfferUnavailable => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Issuance transaction data is temporarily unavailable",
            ),
        };
        (status, Json(json!({"detail": detail}))).into_response()
    }
}
