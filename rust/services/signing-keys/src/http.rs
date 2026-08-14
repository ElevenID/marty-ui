use crate::domain::{key_purposes, service_capabilities};
use crate::kms::{self, ProviderRequest, SignRequest};
use crate::registry::{
    self, NormalizeRegistryRequest, NormalizeRegistryResponse, NormalizeServiceRequest,
    NormalizeServiceResponse, RegistryStore, ResolveRequest, ResolveResponse, SaveRegistryRequest,
};
use crate::validation::{self, ValidationRequest};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Html,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tower_http::trace::TraceLayer;

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

#[derive(Debug, Serialize)]
struct ServiceStatus {
    service_name: &'static str,
    phase: &'static str,
    migrated_capabilities: [&'static str; 8],
    pending_capabilities: [&'static str; 3],
}

#[derive(Clone)]
struct AppState {
    internal_api_key: Arc<str>,
    registry_store: Option<RegistryStore>,
}

pub fn router() -> Router {
    router_with_internal_api_key("dev-signing-keys-internal-api-key".to_string())
}

pub fn router_with_internal_api_key(internal_api_key: String) -> Router {
    router_with_dependencies(internal_api_key, None)
}

pub fn router_with_dependencies(
    internal_api_key: String,
    registry_store: Option<RegistryStore>,
) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/startup", get(startup))
        .route("/openapi.json", get(openapi))
        .route("/docs", get(docs))
        .route("/redoc", get(redoc))
        .route("/v1/signing-keys/service-status", get(service_status))
        .route("/v1/signing-keys/config/purposes", get(purposes))
        .route(
            "/v1/signing-keys/config/service-capabilities",
            get(capabilities),
        )
        .route("/internal/kms/sign", post(kms_sign))
        .route("/internal/kms/public-key", post(kms_public_key))
        .route("/internal/kms/verify", post(kms_verify))
        .route("/internal/config/validate", post(validate_service))
        .route("/internal/registry/catalog", get(registry_catalog))
        .route(
            "/internal/registry/normalize-service",
            post(normalize_registry_service),
        )
        .route("/internal/registry/normalize", post(normalize_registry))
        .route("/internal/registry/resolve", post(resolve_registry))
        .route(
            "/internal/registry/{organization_id}",
            get(load_registry).put(save_registry),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(AppState {
            internal_api_key: Arc::from(internal_api_key),
            registry_store,
        })
}

async fn kms_sign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SignRequest>,
) -> Result<Json<kms::SignResponse>, kms::KmsError> {
    authorize_internal(&state, &headers)?;
    Ok(Json(kms::sign(request).await?))
}

async fn kms_public_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ProviderRequest>,
) -> Result<Json<serde_json::Value>, kms::KmsError> {
    authorize_internal(&state, &headers)?;
    Ok(Json(kms::public_key(request).await?))
}

async fn kms_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ProviderRequest>,
) -> Result<Json<kms::CapabilityResult>, kms::KmsError> {
    authorize_internal(&state, &headers)?;
    Ok(Json(kms::verify(request).await?))
}

async fn validate_service(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ValidationRequest>,
) -> Result<Json<validation::ValidationResult>, kms::KmsError> {
    authorize_internal(&state, &headers)?;
    Ok(Json(validation::validate(request).await))
}

type RegistryHttpError = (StatusCode, Json<serde_json::Value>);

async fn registry_catalog(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, RegistryHttpError> {
    authorize_registry(&state, &headers)?;
    Ok(Json(
        serde_json::json!({"service_types": registry::service_catalog()}),
    ))
}

async fn normalize_registry_service(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<NormalizeServiceRequest>,
) -> Result<Json<NormalizeServiceResponse>, RegistryHttpError> {
    authorize_registry(&state, &headers)?;
    registry::normalize_service(request)
        .map(Json)
        .map_err(registry_error)
}

async fn normalize_registry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<NormalizeRegistryRequest>,
) -> Result<Json<NormalizeRegistryResponse>, RegistryHttpError> {
    authorize_registry(&state, &headers)?;
    registry::normalize_registry(request)
        .map(Json)
        .map_err(registry_error)
}

async fn resolve_registry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ResolveRequest>,
) -> Result<Json<ResolveResponse>, RegistryHttpError> {
    authorize_registry(&state, &headers)?;
    registry::resolve(request).map(Json).map_err(registry_error)
}

async fn load_registry(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, RegistryHttpError> {
    authorize_registry(&state, &headers)?;
    let store = state
        .registry_store
        .as_ref()
        .ok_or_else(registry_unavailable)?;
    store
        .load(&organization_id)
        .await
        .map(Json)
        .map_err(registry_error)
}

async fn save_registry(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<SaveRegistryRequest>,
) -> Result<Json<serde_json::Value>, RegistryHttpError> {
    authorize_registry(&state, &headers)?;
    let store = state
        .registry_store
        .as_ref()
        .ok_or_else(registry_unavailable)?;
    store
        .save(&organization_id, &request.registry)
        .await
        .map(Json)
        .map_err(registry_error)
}

fn authorize_registry(state: &AppState, headers: &HeaderMap) -> Result<(), RegistryHttpError> {
    authorize_internal(state, headers).map_err(|error| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"detail": error.to_string()})),
        )
    })
}

fn registry_error(error: registry::RegistryError) -> RegistryHttpError {
    let status = match error {
        registry::RegistryError::Invalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
        registry::RegistryError::Storage(_) => StatusCode::SERVICE_UNAVAILABLE,
        registry::RegistryError::Corrupt(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(serde_json::json!({"detail": error.to_string()})),
    )
}

fn registry_unavailable() -> RegistryHttpError {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({"detail": "signing registry storage is unavailable"})),
    )
}

fn authorize_internal(state: &AppState, headers: &HeaderMap) -> Result<(), kms::KmsError> {
    let candidate = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let expected = state.internal_api_key.as_bytes();
    let supplied = candidate.as_bytes();
    if expected.len() != supplied.len() || expected.ct_eq(supplied).unwrap_u8() != 1 {
        return Err(kms::KmsError::Unauthorized);
    }
    Ok(())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy",
        service: "signing-keys-service",
    })
}

async fn ready() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ready",
        service: "signing-keys-service",
    })
}

async fn startup() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "started",
        service: "signing-keys-service",
    })
}

async fn service_status() -> Json<ServiceStatus> {
    Json(ServiceStatus {
        service_name: "signing-keys-service",
        phase: "provider-validation",
        migrated_capabilities: [
            "service-bootstrap",
            "health-surface",
            "integration-test-target",
            "kms-adapter-integration",
            "provider-key-normalization",
            "service-registration-validation",
            "registry-normalization-resolution",
            "registry-persistence",
        ],
        pending_capabilities: [
            "jwks-did-publication-persistence",
            "audit-event-storage",
            "compliance-summary-computation",
        ],
    })
}

async fn purposes() -> Json<serde_json::Value> {
    Json(serde_json::json!({"purposes": key_purposes()}))
}

async fn capabilities() -> Json<serde_json::Value> {
    Json(serde_json::json!({"service_capabilities": service_capabilities()}))
}

async fn openapi() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "openapi": "3.1.0",
        "info": {"title": "Signing Keys Service", "version": "1.0.0"},
        "paths": {
            "/health": {"get": {"summary": "Health Check", "responses": {"200": {"description": "Successful Response"}}}},
            "/v1/signing-keys/service-status": {"get": {"summary": "Signing Keys Service Extraction Status", "responses": {"200": {"description": "Successful Response"}}}},
            "/v1/signing-keys/config/purposes": {"get": {"summary": "List Available Key Purposes", "responses": {"200": {"description": "Successful Response"}}}},
            "/v1/signing-keys/config/service-capabilities": {"get": {"summary": "List Provider Capability Metadata", "responses": {"200": {"description": "Successful Response"}}}}
        }
    }))
}

async fn docs() -> Html<&'static str> {
    Html(
        r#"<!doctype html><html><head><title>Signing Keys Service - Swagger UI</title></head><body><div id="swagger-ui"></div><script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script><script>SwaggerUIBundle({url:'/openapi.json',dom_id:'#swagger-ui'})</script></body></html>"#,
    )
}

async fn redoc() -> Html<&'static str> {
    Html(
        r#"<!doctype html><html><head><title>Signing Keys Service - ReDoc</title></head><body><redoc spec-url="/openapi.json"></redoc><script src="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js"></script></body></html>"#,
    )
}
