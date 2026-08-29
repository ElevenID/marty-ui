use axum::{
    extract::{Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
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
    tenant_discovery::{TenantDiscoveryError, TenantDiscoveryService},
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
}

fn legacy_health(_report: &HealthReport) -> Value {
    json!({"status": "healthy", "service": "issuance-service"})
}

pub fn router(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
) -> Router {
    router_with_optional_services(runtime, discovery, transport, None, None)
}

pub fn router_with_tenant_discovery(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    tenant: TenantDiscoveryService,
) -> Router {
    router_with_optional_services(runtime, discovery, transport, Some(tenant), None)
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
        Some(tenant),
        Some(transactions),
    )
}

fn router_with_optional_services(
    runtime: RuntimeState,
    discovery: StaticDiscoveryDocuments,
    transport: TransportPolicy,
    tenant: Option<TenantDiscoveryService>,
    transactions: Option<TransactionReadService>,
) -> Router {
    let system = system_router_with_options(
        runtime,
        SystemRouteOptions::default().with_health_projector(legacy_health),
    );
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
        .with_state(IssuanceState {
            documents: discovery,
            tenant,
            transactions,
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
