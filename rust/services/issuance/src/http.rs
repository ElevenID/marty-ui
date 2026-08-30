use std::net::SocketAddr;

use axum::{
    body::to_bytes,
    extract::{ConnectInfo, Path, RawForm, RawQuery, Request, State},
    http::{header as http_header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
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
use serde_json::{json, Map, Value};

use crate::{
    canvas_lti_experience::{CanvasLtiExperienceExchangeError, CanvasLtiExperienceExchangeService},
    canvas_lti_launch::{
        public_launch_response, CanvasLtiExperienceService, CanvasLtiLaunchPlanError,
        CanvasLtiLaunchService, CanvasLtiLaunchServiceError, CanvasLtiLaunchSubmission,
    },
    canvas_lti_login::{
        CanvasLtiLoginError, CanvasLtiLoginMode, CanvasLtiLoginService, CanvasLtiLoginSubmission,
    },
    credential::{CredentialIssuanceError, CredentialIssuanceService, CredentialRequest},
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
    canvas_lti_login: Option<CanvasLtiLoginService>,
    canvas_lti_launch: Option<CanvasLtiLaunchService>,
    canvas_lti_experience: Option<CanvasLtiExperienceService>,
    canvas_lti_experience_exchange: Option<CanvasLtiExperienceExchangeService>,
}

pub struct IssuanceServices {
    tenant: TenantDiscoveryService,
    transactions: TransactionReadService,
    token_exchange: TokenExchangeService,
    proof_nonce: ProofNonceService,
    credential: CredentialIssuanceService,
    canvas_lti: CanvasLtiServices,
    token_rate_limiter: TokenRateLimiter,
}

#[derive(Clone, Debug)]
pub struct CanvasLtiServices {
    login: CanvasLtiLoginService,
    launch: CanvasLtiLaunchService,
    experience: CanvasLtiExperienceService,
    experience_exchange: CanvasLtiExperienceExchangeService,
}

impl CanvasLtiServices {
    #[must_use]
    pub fn new(
        login: CanvasLtiLoginService,
        launch: CanvasLtiLaunchService,
        experience: CanvasLtiExperienceService,
        experience_exchange: CanvasLtiExperienceExchangeService,
    ) -> Self {
        Self {
            login,
            launch,
            experience,
            experience_exchange,
        }
    }
}

impl IssuanceServices {
    #[must_use]
    pub fn new(
        tenant: TenantDiscoveryService,
        transactions: TransactionReadService,
        token_exchange: TokenExchangeService,
        proof_nonce: ProofNonceService,
        credential: CredentialIssuanceService,
        canvas_lti: CanvasLtiServices,
        token_rate_limiter: TokenRateLimiter,
    ) -> Self {
        Self {
            tenant,
            transactions,
            token_exchange,
            proof_nonce,
            credential,
            canvas_lti,
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
    canvas_lti_login: Option<CanvasLtiLoginService>,
    canvas_lti_launch: Option<CanvasLtiLaunchService>,
    canvas_lti_experience: Option<CanvasLtiExperienceService>,
    canvas_lti_experience_exchange: Option<CanvasLtiExperienceExchangeService>,
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
            canvas_lti_login: Some(services.canvas_lti.login),
            canvas_lti_launch: Some(services.canvas_lti.launch),
            canvas_lti_experience: Some(services.canvas_lti.experience),
            canvas_lti_experience_exchange: Some(services.canvas_lti.experience_exchange),
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
    let api = api.merge(oauth).with_state(IssuanceState {
        documents: discovery,
        tenant: services.tenant,
        transactions: services.transactions,
        token_exchange: services.token_exchange,
        proof_nonce: services.proof_nonce,
        credential: services.credential,
        canvas_lti_login: services.canvas_lti_login,
        canvas_lti_launch: services.canvas_lti_launch,
        canvas_lti_experience: services.canvas_lti_experience,
        canvas_lti_experience_exchange: services.canvas_lti_experience_exchange,
    });
    system
        .merge(api)
        .layer(middleware::from_fn_with_state(transport, legacy_transport))
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
    let mut response = Json(json!({
        "session_token": result.session_token,
        "expires_at": result.expires_at.to_rfc3339(),
    }))
    .into_response();
    response.headers_mut().insert(
        http_header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response
        .headers_mut()
        .insert(http_header::PRAGMA, HeaderValue::from_static("no-cache"));
    Ok(response)
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

enum CanvasLtiExperienceExchangeHttpError {
    Service(CanvasLtiExperienceExchangeError),
    Validation(Vec<Value>),
    InvalidJson,
    BodyTooLarge,
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
