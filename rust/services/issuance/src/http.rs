use std::net::SocketAddr;

use axum::{
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
use serde_json::{json, Value};

use crate::{
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
}

pub struct IssuanceServices {
    tenant: TenantDiscoveryService,
    transactions: TransactionReadService,
    token_exchange: TokenExchangeService,
    proof_nonce: ProofNonceService,
    token_rate_limiter: TokenRateLimiter,
}

impl IssuanceServices {
    #[must_use]
    pub fn new(
        tenant: TenantDiscoveryService,
        transactions: TransactionReadService,
        token_exchange: TokenExchangeService,
        proof_nonce: ProofNonceService,
        token_rate_limiter: TokenRateLimiter,
    ) -> Self {
        Self {
            tenant,
            transactions,
            token_exchange,
            proof_nonce,
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
    let discovery = Router::new()
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
        )
        .merge(oauth)
        .with_state(IssuanceState {
            documents: discovery,
            tenant: services.tenant,
            transactions: services.transactions,
            token_exchange: services.token_exchange,
            proof_nonce: services.proof_nonce,
        });
    system
        .merge(discovery)
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
