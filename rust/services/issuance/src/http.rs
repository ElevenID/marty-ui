#[cfg(test)]
#[path = "token_rate_limit_http_tests.rs"]
mod token_rate_limit_http_tests;

use axum::{
    extract::{FromRequest, Path, RawForm, RawQuery, Request, State},
    http::{header as http_header, HeaderMap, HeaderValue, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use marty_oid4vci::discovery::{
    AuthorizationServerMetadata, CredentialIssuerMetadata, CredentialTypeMetadata, IssuerVariant,
    StaticDiscoveryDocuments,
};
use mmf_core::HealthReport;
use mmf_runtime::{system_router_with_options, RuntimeState, SystemRouteOptions};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    application_template_service::ApplicationTemplateService,
    credential::{CredentialIssuanceError, CredentialIssuanceService, CredentialRequest},
    credential_management::{
        CredentialLifecycleAction, CredentialManagementError, CredentialStatusView,
    },
    credential_management_http::{CredentialManagementHttpError, CredentialManagementHttpService},
    credential_renewal::CredentialRenewalService,
    initiation::InitiationRequest,
    initiation_didcomm_http::{
        DidcommDeliverRequest, InitiationDidcommHttpError, InitiationDidcommHttpService,
    },
    initiation_http::{InitiationHttpError, InitiationHttpService},
    internal_application_service::InternalApplicationService,
    issued_credential_records::IssuedCredentialAdapterService,
    oid4vci_authorization::Oid4vciAuthorizationService,
    oid4vci_management::Oid4vciManagementService,
    passport_http::PassportHttpService,
    proof_nonce::{ProofNonceError, ProofNonceService},
    resource_owner::{ResourceOwner, ResourceOwnerKind, ResourceOwnerService},
    retention::RetentionService,
    tenant_discovery::{TenantDiscoveryError, TenantDiscoveryService},
    token_exchange::{TokenExchangeError, TokenExchangeRequest, TokenExchangeService},
    token_rate_limit::{token_rate_limit_middleware, TokenRateLimiter},
    transaction_reads::{
        IssuanceTransactionResponse, TransactionReadError, TransactionReadService,
        TransactionRevocationStatus,
    },
    transport::{legacy_transport, TransportPolicy},
};

#[derive(Clone)]
struct IssuanceState {
    documents: StaticDiscoveryDocuments,
    tenant: Option<TenantDiscoveryService>,
    transactions: Option<TransactionReadService>,
    resource_owners: Option<ResourceOwnerService>,
    token_exchange: Option<TokenExchangeService>,
    proof_nonce: Option<ProofNonceService>,
    credential: Option<CredentialIssuanceService>,
    initiation: Option<InitiationHttpService>,
    didcomm_delivery: Option<InitiationDidcommHttpService>,
    credential_management: Option<CredentialManagementHttpService>,
}

pub struct IssuanceServices {
    tenant: TenantDiscoveryService,
    transactions: TransactionReadService,
    resource_owners: ResourceOwnerService,
    token_exchange: TokenExchangeService,
    proof_nonce: ProofNonceService,
    credential: CredentialIssuanceService,
    initiation: InitiationHttpService,
    didcomm_delivery: InitiationDidcommHttpService,
    renewal: Option<CredentialRenewalService>,
    credential_management: CredentialManagementHttpService,
    issued_credentials: Option<IssuedCredentialAdapterService>,
    oid4vci_management: Option<Oid4vciManagementService>,
    application_templates: ApplicationTemplateService,
    internal_applications: Option<InternalApplicationService>,
    retention: Option<RetentionService>,
    passport: Option<PassportHttpService>,
    token_rate_limiter: TokenRateLimiter,
    oid4vci_authorization: Oid4vciAuthorizationService,
}

pub struct IssuanceCoreServices {
    tenant: TenantDiscoveryService,
    transactions: TransactionReadService,
    resource_owners: ResourceOwnerService,
    token_exchange: TokenExchangeService,
    proof_nonce: ProofNonceService,
    credential: CredentialIssuanceService,
    initiation: InitiationHttpService,
    didcomm_delivery: InitiationDidcommHttpService,
    renewal: Option<CredentialRenewalService>,
}

pub struct IssuanceReadServices {
    transactions: TransactionReadService,
    resource_owners: ResourceOwnerService,
}

impl IssuanceReadServices {
    #[must_use]
    pub fn new(
        transactions: TransactionReadService,
        resource_owners: ResourceOwnerService,
    ) -> Self {
        Self {
            transactions,
            resource_owners,
        }
    }
}

impl IssuanceCoreServices {
    #[must_use]
    pub fn new(
        tenant: TenantDiscoveryService,
        reads: IssuanceReadServices,
        token_exchange: TokenExchangeService,
        proof_nonce: ProofNonceService,
        credential: CredentialIssuanceService,
        initiation: InitiationHttpService,
        didcomm_delivery: InitiationDidcommHttpService,
    ) -> Self {
        Self {
            tenant,
            transactions: reads.transactions,
            resource_owners: reads.resource_owners,
            token_exchange,
            proof_nonce,
            credential,
            initiation,
            didcomm_delivery,
            renewal: None,
        }
    }

    /// Compose the shared renewal owner without changing other service routes.
    #[must_use]
    pub fn with_renewal(mut self, renewal: CredentialRenewalService) -> Self {
        self.renewal = Some(renewal);
        self
    }
}

impl IssuanceServices {
    #[must_use]
    pub fn new(
        core: IssuanceCoreServices,
        credential_management: CredentialManagementHttpService,
        application_templates: ApplicationTemplateService,
        token_rate_limiter: TokenRateLimiter,
        oid4vci_authorization: Oid4vciAuthorizationService,
    ) -> Self {
        Self {
            tenant: core.tenant,
            transactions: core.transactions,
            resource_owners: core.resource_owners,
            token_exchange: core.token_exchange,
            proof_nonce: core.proof_nonce,
            credential: core.credential,
            initiation: core.initiation,
            didcomm_delivery: core.didcomm_delivery,
            renewal: core.renewal,
            credential_management,
            issued_credentials: None,
            oid4vci_management: None,
            application_templates,
            internal_applications: None,
            retention: None,
            passport: None,
            token_rate_limiter,
            oid4vci_authorization,
        }
    }

    /// Opt in to the complete native internal-Application surface.
    #[must_use]
    pub fn with_internal_applications(
        mut self,
        internal_applications: InternalApplicationService,
    ) -> Self {
        self.internal_applications = Some(internal_applications);
        self
    }

    /// Opt in to the public issued-credential read and lifecycle adapters.
    #[must_use]
    pub fn with_issued_credentials(
        mut self,
        issued_credentials: IssuedCredentialAdapterService,
    ) -> Self {
        self.issued_credentials = Some(issued_credentials);
        self
    }

    /// Opt in to the tenant-owned OID4VCI management component.
    #[must_use]
    pub fn with_oid4vci_management(mut self, oid4vci_management: Oid4vciManagementService) -> Self {
        self.oid4vci_management = Some(oid4vci_management);
        self
    }

    /// Opt in only after the frozen retention and PostgreSQL parity gates pass.
    #[must_use]
    pub fn with_retention(mut self, retention: RetentionService) -> Self {
        self.retention = Some(retention);
        self
    }

    /// Opt in only after the frozen nine-route passport and provider gates pass.
    #[must_use]
    pub fn with_passport(mut self, passport: PassportHttpService) -> Self {
        self.passport = Some(passport);
        self
    }
}

#[derive(Default)]
struct OptionalServices {
    tenant: Option<TenantDiscoveryService>,
    transactions: Option<TransactionReadService>,
    resource_owners: Option<ResourceOwnerService>,
    token_exchange: Option<TokenExchangeService>,
    proof_nonce: Option<ProofNonceService>,
    credential: Option<CredentialIssuanceService>,
    initiation: Option<InitiationHttpService>,
    didcomm_delivery: Option<InitiationDidcommHttpService>,
    renewal: Option<CredentialRenewalService>,
    credential_management: Option<CredentialManagementHttpService>,
    issued_credentials: Option<IssuedCredentialAdapterService>,
    oid4vci_management: Option<Oid4vciManagementService>,
    application_templates: Option<ApplicationTemplateService>,
    internal_applications: Option<InternalApplicationService>,
    retention: Option<RetentionService>,
    passport: Option<PassportHttpService>,
    token_rate_limiter: Option<TokenRateLimiter>,
    oid4vci_authorization: Option<Oid4vciAuthorizationService>,
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
    resource_owners: ResourceOwnerService,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            tenant: Some(tenant),
            transactions: Some(transactions),
            resource_owners: Some(resource_owners),
            ..OptionalServices::default()
        },
    )
}

/// Exercise the production resource-owner transport without unrelated services.
pub fn router_with_resource_owners(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    resource_owners: ResourceOwnerService,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            resource_owners: Some(resource_owners),
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
            resource_owners: Some(services.resource_owners),
            token_exchange: Some(services.token_exchange),
            proof_nonce: Some(services.proof_nonce),
            credential: Some(services.credential),
            initiation: Some(services.initiation),
            didcomm_delivery: Some(services.didcomm_delivery),
            renewal: services.renewal,
            credential_management: Some(services.credential_management),
            issued_credentials: services.issued_credentials,
            oid4vci_management: services.oid4vci_management,
            application_templates: Some(services.application_templates),
            internal_applications: services.internal_applications,
            retention: services.retention,
            passport: services.passport,
            token_rate_limiter: Some(services.token_rate_limiter),
            oid4vci_authorization: Some(services.oid4vci_authorization),
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

/// Exercise the production OID4VCI public-protocol composition and transport.
pub fn router_with_oid4vci_authorization(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    service: Oid4vciAuthorizationService,
    token_rate_limiter: TokenRateLimiter,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            oid4vci_authorization: Some(service),
            token_rate_limiter: Some(token_rate_limiter),
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

/// Exercise the same internal-Application composition and transport layer as
/// the full service without requiring unrelated issuance dependencies.
pub fn router_with_internal_applications(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    internal_applications: InternalApplicationService,
) -> Router {
    router_with_optional_services(
        runtime,
        discovery,
        transport,
        OptionalServices {
            internal_applications: Some(internal_applications),
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
    let oid4vci_authorization = services.oid4vci_authorization.clone();
    let oid4vci_management = services.oid4vci_management.clone();
    let oid4vci_rate_limiter = services.token_rate_limiter.clone();
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
    if services.resource_owners.is_some() {
        api = api
            .route(
                "/internal/v1/resource-owners/application-templates/{template_id}",
                get(application_template_owner),
            )
            .route(
                "/internal/v1/resource-owners/issued-credentials/{credential_id}",
                get(issued_credential_owner),
            );
    }
    if services.credential.is_some() {
        api = api.route("/v1/issuance/credential", post(issue_credential));
    }
    if services.initiation.is_some() {
        api = api
            .route("/v1/issuance/initiate", post(initiate_issuance))
            .route(
                "/internal/compat/issuance/offer-lifetime/validate",
                post(validate_offer_lifetime),
            );
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
            )
            .route(
                marty_oid4vp_contract::managed_status::MANAGED_STATUS_OBSERVATION_PATH,
                post(observe_sd_jwt_status),
            );
    }
    let api = api.merge(oauth).with_state(IssuanceState {
        documents: discovery,
        tenant: services.tenant,
        transactions: services.transactions,
        resource_owners: services.resource_owners,
        token_exchange: services.token_exchange,
        proof_nonce: services.proof_nonce,
        credential: services.credential,
        initiation: services.initiation,
        didcomm_delivery: services.didcomm_delivery,
        credential_management: services.credential_management,
    });
    let api = if let Some(issued_credentials) = services.issued_credentials {
        api.merge(crate::issued_credential_http::router(issued_credentials))
    } else {
        api
    };
    let api = if let Some(management) = oid4vci_management {
        api.merge(crate::oid4vci_management_http::router(management))
    } else {
        api
    };
    let api = if let Some(retention) = services.retention {
        api.merge(crate::retention_http::router(retention))
    } else {
        api
    };
    let api = if let Some(passport) = services.passport {
        api.merge(crate::passport_http::router(passport))
    } else {
        api.merge(crate::passport_http::disabled_router())
    };
    let api = if let Some(application_templates) = services.application_templates {
        api.merge(crate::application_template_http::router(
            application_templates,
        ))
    } else {
        api
    };
    let api = if let Some(internal_applications) = services.internal_applications {
        api.merge(crate::internal_application_http::router(
            internal_applications,
        ))
    } else {
        api
    };
    let api = if let Some(renewal) = services.renewal {
        api.merge(crate::credential_renewal::router(renewal))
    } else {
        api
    };
    let api = if let Some(authorization) = oid4vci_authorization {
        api.merge(
            crate::oid4vci_authorization::router_with_optional_rate_limit(
                authorization,
                oid4vci_rate_limiter,
            ),
        )
    } else {
        api
    };
    system
        .merge(api)
        .layer(middleware::from_fn_with_state(transport, legacy_transport))
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
) -> Result<Json<Value>, TenantDiscoveryHttpError> {
    tenant_issuer_metadata(state, organization_id, IssuerVariant::Default).await
}

async fn credential_manager_issuer_metadata(
    State(state): State<IssuanceState>,
    Path(organization_id): Path<String>,
) -> Result<Json<Value>, TenantDiscoveryHttpError> {
    tenant_issuer_metadata(state, organization_id, IssuerVariant::CredentialManager).await
}

async fn apple_wallet_issuer_metadata(
    State(state): State<IssuanceState>,
    Path(organization_id): Path<String>,
) -> Result<Json<Value>, TenantDiscoveryHttpError> {
    tenant_issuer_metadata(state, organization_id, IssuerVariant::AppleWallet).await
}

async fn tenant_issuer_metadata(
    state: IssuanceState,
    organization_id: String,
    variant: IssuerVariant,
) -> Result<Json<Value>, TenantDiscoveryHttpError> {
    let tenant = state
        .tenant
        .ok_or(TenantDiscoveryError::RepositoryUnavailable)?;
    tenant
        .metadata_with_profiles(&organization_id, variant)
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

async fn validate_offer_lifetime(State(state): State<IssuanceState>, request: Request) -> Response {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        offer_ttl_seconds: u64,
    }
    let Some(service) = state.initiation.as_ref() else {
        return InitiationHttpError::Unavailable.into_response();
    };
    if let Err(error) = service.authorize(request.headers()) {
        return error.into_response();
    }
    let headers = request.headers().clone();
    let Json(input) = match Json::<Input>::from_request(request, &state).await {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    match service.validate_offer_lifetime(&headers, input.offer_ttl_seconds) {
        Ok(organization) => Json(
            json!({"organization_id":organization,"offer_ttl_seconds":input.offer_ttl_seconds}),
        )
        .into_response(),
        Err(error) => error.into_response(),
    }
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
    let headers = request.headers().clone();
    let Json(input) = match Json::<DidcommDeliverRequest>::from_request(request, &state).await {
        Ok(input) => input,
        Err(rejection) => return rejection.into_response(),
    };
    match service.deliver_authorized(&headers, &input).await {
        Ok(response) => Json(response).into_response(),
        Err(error) => error.into_response(),
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    mdoc_status_reference: Option<String>,
    id: String,
    issuer_did: Option<String>,
    status: String,
    status_updated_at: String,
    reason: Option<String>,
}

impl From<CredentialStatusView> for CredentialStatusHttpResponse {
    fn from(value: CredentialStatusView) -> Self {
        Self {
            mdoc_status_reference: value.mdoc_status_reference,
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

/// Direct HTTPS owner surface; ordinary issuance and management routes are absent.
pub fn managed_status_owner_router(service: CredentialManagementHttpService) -> Router {
    Router::new()
        .route(
            "/internal/issuance/sd-jwt-status/observe",
            post(
                |State(service): State<CredentialManagementHttpService>,
                 headers: HeaderMap,
                 Json(request): Json<
                    marty_oid4vp_contract::managed_status::ManagedCredentialStatusRequestV1,
                >| async move {
                    observe_sd_jwt_status_with_service(&service, &headers, &request).await
                },
            ),
        )
        .layer(axum::extract::DefaultBodyLimit::max(
            marty_oid4vp_contract::MAX_FROZEN_REQUEST_BYTES,
        ))
        .with_state(service)
}

async fn observe_sd_jwt_status(
    State(state): State<IssuanceState>,
    headers: HeaderMap,
    Json(request): Json<marty_oid4vp_contract::managed_status::ManagedCredentialStatusRequestV1>,
) -> Result<Response, CredentialManagementHttpError> {
    observe_sd_jwt_status_with_service(credential_management(&state)?, &headers, &request).await
}

async fn observe_sd_jwt_status_with_service(
    service: &CredentialManagementHttpService,
    headers: &HeaderMap,
    request: &marty_oid4vp_contract::managed_status::ManagedCredentialStatusRequestV1,
) -> Result<Response, CredentialManagementHttpError> {
    let observation = service
        .observe_sd_jwt_status(
            request,
            header(headers, "X-API-Key"),
            header(headers, "X-Organization-ID"),
        )
        .await?;
    Ok(([("Cache-Control", "no-store")], Json(observation)).into_response())
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
    resource_owners(&state)?
        .owner(
            ResourceOwnerKind::IssuanceTransaction,
            &transaction_id,
            header(&headers, "X-API-Key"),
        )
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn application_template_owner(
    State(state): State<IssuanceState>,
    Path(template_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ResourceOwner>, TransactionReadHttpError> {
    owner_response(
        &state,
        ResourceOwnerKind::ApplicationTemplate,
        &template_id,
        &headers,
    )
    .await
}

async fn issued_credential_owner(
    State(state): State<IssuanceState>,
    Path(credential_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ResourceOwner>, TransactionReadHttpError> {
    owner_response(
        &state,
        ResourceOwnerKind::IssuedCredential,
        &credential_id,
        &headers,
    )
    .await
}

async fn owner_response(
    state: &IssuanceState,
    kind: ResourceOwnerKind,
    resource_id: &str,
    headers: &HeaderMap,
) -> Result<Json<ResourceOwner>, TransactionReadHttpError> {
    resource_owners(state)?
        .owner(kind, resource_id, header(headers, "X-API-Key"))
        .await
        .map(Json)
        .map_err(Into::into)
}

fn resource_owners(state: &IssuanceState) -> Result<&ResourceOwnerService, TransactionReadError> {
    state
        .resource_owners
        .as_ref()
        .ok_or(TransactionReadError::RepositoryUnavailable)
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
            Error::InvalidCredentialRequest(description) => (
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid_credential_request", "error_description": description}),
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
            Error::RetiredOpenBadge => (
                StatusCode::BAD_REQUEST,
                json!({"detail": Error::RetiredOpenBadge.to_string()}),
            ),
            Error::IssuerUnavailable(detail)
            | Error::SigningUnavailable(detail)
            | Error::LifecycleUnavailable(detail) => {
                (StatusCode::SERVICE_UNAVAILABLE, json!({"detail": detail}))
            }
            Error::SigningResponse(cause) => {
                let Some(detail) = cause.scalar_detail() else {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
                        .into_response();
                };
                (StatusCode::SERVICE_UNAVAILABLE, json!({"detail": detail}))
            }
            Error::RevocationProfileRequired => (
                StatusCode::UNPROCESSABLE_ENTITY,
                json!({"detail": "The Credential Template has no Revocation Profile."}),
            ),
            Error::ApplicationEligibilityDenied => (
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
        if let Self::Security(error) = &self {
            if let Some((status, detail)) = crate::management_http::authentication_error(error) {
                return (status, Json(json!({"detail": detail}))).into_response();
            }
        }
        let (status, detail) = match self {
            Self::Observation(error) => match error {
                crate::managed_status::ManagedStatusError::InvalidRequest => (
                    StatusCode::BAD_REQUEST,
                    "Invalid managed credential status request",
                ),
                crate::managed_status::ManagedStatusError::NotFound => {
                    (StatusCode::NOT_FOUND, "Managed credential was not found")
                }
                crate::managed_status::ManagedStatusError::UnsupportedRecord => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Stored credential does not support this status observation",
                ),
                crate::managed_status::ManagedStatusError::Unavailable => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Managed credential status is temporarily unavailable",
                ),
            },
            Self::Security(error) => match error {
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
            Self::Lifecycle(error) => {
                return crate::management_http::lifecycle_error(
                    error,
                    crate::management_http::LifecycleSurface::Transaction,
                )
            }
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
            TenantDiscoveryError::ProofPolicyResponseInvalid => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
                    .into_response();
            }
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

pub(crate) struct TransactionReadHttpError(TransactionReadError);

impl From<TransactionReadError> for TransactionReadHttpError {
    fn from(value: TransactionReadError) -> Self {
        Self(value)
    }
}

impl IntoResponse for TransactionReadHttpError {
    fn into_response(self) -> Response {
        if let Some((status, detail)) = crate::management_http::authentication_error(&self.0) {
            return (status, Json(json!({"detail": detail}))).into_response();
        }
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
            TransactionReadError::ApiKeyNotConfigured
            | TransactionReadError::ApiKeyMissing
            | TransactionReadError::InvalidApiKey => unreachable!("authentication handled above"),
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

#[cfg(test)]
mod authentication_projection_tests {
    use super::*;

    #[tokio::test]
    async fn lifecycle_and_transaction_reads_keep_auth_and_tenant_denial_contracts() {
        for (error, status, detail) in [
            (
                TransactionReadError::ApiKeyNotConfigured,
                StatusCode::SERVICE_UNAVAILABLE,
                "ISSUANCE_API_KEY not configured on server",
            ),
            (
                TransactionReadError::ApiKeyMissing,
                StatusCode::UNAUTHORIZED,
                "X-API-Key header is missing",
            ),
            (
                TransactionReadError::InvalidApiKey,
                StatusCode::UNAUTHORIZED,
                "Invalid API Key",
            ),
            (
                TransactionReadError::OrganizationMismatch,
                StatusCode::FORBIDDEN,
                "Organization context does not match requested organization",
            ),
            (
                TransactionReadError::TrustedOrganizationRequired,
                StatusCode::FORBIDDEN,
                "Trusted organization context is required",
            ),
        ] {
            for response in [
                CredentialManagementHttpError::Security(error.clone()).into_response(),
                TransactionReadHttpError(error).into_response(),
            ] {
                assert_eq!(response.status(), status);
                let body = axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap();
                let actual: Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(actual, json!({"detail": detail}));
            }
        }
        let response =
            TransactionReadHttpError(TransactionReadError::OrganizationIdRequired).into_response();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let actual: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            actual["detail"][0]["loc"],
            json!(["query", "organization_id"])
        );
    }
}
