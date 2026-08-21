use crate::compat::{
    CompatibilityError, IssuerContextRequest, IssuerDidSignRequest, ProfileIdentityRequest,
    ProfileWriteRequest, ResolveIssuerDidRequest, ServiceSignRequest, SigningCompatibilityService,
};
use crate::documents::{
    self, CertificateAlertsRequest, CertificateAlertsResponse, DeleteJwkResponse, DocumentStore,
    InspectCertificateRequest, InspectCertificateResponse, LoadDidRequest, LoadDidResponse,
    PublishDidRequest, PublishDidResponse, PublishJwkRequest, PublishJwkResponse,
    StoredCertificate, UpdateJwkRequest, UpdateJwkResponse,
};
use crate::domain::{key_purposes, service_capabilities};
use crate::flow_envelope::{
    FlowEnvelopeError, OpenBaoEnvelopeProvider, UnwrapRequest, WrapRequest,
};
use crate::kms::{self, ProviderRequest, SignRequest};
use crate::profiles::{
    self, CustodyFormatRequest, CustodyFormatResponse, DuplicateProfileRequest,
    DuplicateProfileResponse, FindProfilesRequest, NormalizeProfileRequest, ProfileStore,
    ValidateBindingRequest,
};
use crate::registry::{
    self, BindProfileRequest, NormalizeRegistryRequest, NormalizeRegistryResponse,
    NormalizeServiceRequest, NormalizeServiceResponse, RegistryStore, ResolveRequest,
    ResolveResponse, SaveRegistryRequest,
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
    migrated_capabilities: [&'static str; 11],
    pending_capabilities: [&'static str; 2],
}

#[derive(Clone)]
struct AppState {
    internal_api_key: Arc<str>,
    registry_store: Option<RegistryStore>,
    document_store: Option<DocumentStore>,
    profile_store: Option<ProfileStore>,
    flow_envelopes: Option<OpenBaoEnvelopeProvider>,
    compatibility: Option<SigningCompatibilityService>,
}

pub fn router() -> Router {
    router_with_internal_api_key("dev-signing-keys-internal-api-key".to_string())
}

pub fn router_with_internal_api_key(internal_api_key: String) -> Router {
    router_with_dependencies(internal_api_key, None, None, None, None, None)
}

pub fn router_with_dependencies(
    internal_api_key: String,
    registry_store: Option<RegistryStore>,
    document_store: Option<DocumentStore>,
    profile_store: Option<ProfileStore>,
    flow_envelopes: Option<OpenBaoEnvelopeProvider>,
    public_domain: Option<String>,
) -> Router {
    let compatibility = match (&registry_store, &document_store, &profile_store) {
        (Some(registry), Some(documents), Some(profiles)) => {
            Some(SigningCompatibilityService::new(
                registry.clone(),
                documents.clone(),
                profiles.clone(),
                public_domain.clone(),
            ))
        }
        _ => None,
    };
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
        .route("/internal/flow-key-envelopes/wrap", post(wrap_flow_key))
        .route("/internal/flow-key-envelopes/unwrap", post(unwrap_flow_key))
        .route("/internal/compat/issuer-context", post(issuer_context))
        .route(
            "/internal/compat/resolve-issuer-did",
            post(resolve_issuer_did),
        )
        .route(
            "/internal/compat/issuer-profiles/{profile_id}/identity",
            post(profile_identity),
        )
        .route(
            "/internal/compat/issuer-profiles/{profile_id}/public-identity",
            post(profile_public_identity),
        )
        .route(
            "/internal/compat/services/{service_id}/sign",
            post(service_sign),
        )
        .route("/internal/compat/issuer-dids/sign", post(issuer_did_sign))
        .route(
            "/internal/compat/issuer-profiles",
            post(create_compatibility_profile),
        )
        .route(
            "/internal/compat/issuer-profiles/{profile_id}",
            axum::routing::patch(update_compatibility_profile),
        )
        .route(
            "/internal/compat/issuer-profiles/{profile_id}/certificate",
            axum::routing::put(attach_compatibility_certificate),
        )
        .route("/internal/config/validate", post(validate_service))
        .route("/internal/registry/catalog", get(registry_catalog))
        .route(
            "/internal/registry/normalize-service",
            post(normalize_registry_service),
        )
        .route("/internal/registry/normalize", post(normalize_registry))
        .route("/internal/registry/resolve", post(resolve_registry))
        .route(
            "/internal/registry/{organization_id}/bind-profile",
            post(bind_registry_profile),
        )
        .route(
            "/internal/registry/{organization_id}",
            get(load_registry).put(save_registry),
        )
        .route(
            "/internal/documents/certificate/inspect",
            post(inspect_certificate),
        )
        .route(
            "/internal/documents/certificate-alerts",
            post(certificate_alerts),
        )
        .route(
            "/internal/documents/{organization_id}/certificates",
            get(certificate_overrides),
        )
        .route(
            "/internal/documents/{organization_id}/certificates/{service_id}",
            axum::routing::put(store_certificate),
        )
        .route("/internal/documents/{organization_id}/jwks", get(load_jwks))
        .route(
            "/internal/documents/{organization_id}/jwks/{service_id}",
            axum::routing::put(publish_jwk)
                .patch(update_jwk)
                .delete(delete_jwk),
        )
        .route(
            "/internal/documents/{organization_id}/did/load",
            post(load_did),
        )
        .route(
            "/internal/documents/{organization_id}/did/{service_id}",
            axum::routing::put(publish_did),
        )
        .route("/internal/documents/did-web/{slug}", get(resolve_did_slug))
        .route(
            "/internal/profiles/{organization_id}/normalize",
            post(normalize_profile),
        )
        .route(
            "/internal/profiles/{organization_id}/validate-binding",
            post(validate_profile_binding),
        )
        .route(
            "/internal/profiles/{organization_id}/custody-format",
            post(resolve_profile_custody_format),
        )
        .route(
            "/internal/profiles/{organization_id}/find",
            post(find_profiles),
        )
        .route(
            "/internal/profiles/{organization_id}/find-duplicate",
            post(find_duplicate_profile),
        )
        .route("/internal/profiles/{organization_id}", get(list_profiles))
        .route(
            "/internal/profiles/{organization_id}/{profile_id}",
            get(get_profile).put(put_profile).delete(delete_profile),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(AppState {
            internal_api_key: Arc::from(internal_api_key),
            registry_store,
            document_store,
            profile_store,
            flow_envelopes,
            compatibility,
        })
}

async fn issuer_context(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<IssuerContextRequest>,
) -> Result<Json<serde_json::Value>, CompatibilityError> {
    authorize_internal(&state, &headers).map_err(|_| CompatibilityError::Unauthorized)?;
    let service = state
        .compatibility
        .as_ref()
        .ok_or(CompatibilityError::Unavailable)?;
    service.issuer_context(&request).await.map(Json)
}

async fn resolve_issuer_did(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ResolveIssuerDidRequest>,
) -> Result<Json<serde_json::Value>, CompatibilityError> {
    authorize_internal(&state, &headers).map_err(|_| CompatibilityError::Unauthorized)?;
    let service = state
        .compatibility
        .as_ref()
        .ok_or(CompatibilityError::Unavailable)?;
    service.resolve_issuer_did(&request).await.map(Json)
}

async fn profile_identity(
    State(state): State<AppState>,
    Path(profile_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ProfileIdentityRequest>,
) -> Result<Json<serde_json::Value>, CompatibilityError> {
    profile_identity_response(&state, &headers, &request, &profile_id, false).await
}

async fn profile_public_identity(
    State(state): State<AppState>,
    Path(profile_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ProfileIdentityRequest>,
) -> Result<Json<serde_json::Value>, CompatibilityError> {
    profile_identity_response(&state, &headers, &request, &profile_id, true).await
}

async fn profile_identity_response(
    state: &AppState,
    headers: &HeaderMap,
    request: &ProfileIdentityRequest,
    profile_id: &str,
    public_projection: bool,
) -> Result<Json<serde_json::Value>, CompatibilityError> {
    authorize_internal(state, headers).map_err(|_| CompatibilityError::Unauthorized)?;
    let service = state
        .compatibility
        .as_ref()
        .ok_or(CompatibilityError::Unavailable)?;
    service
        .profile_identity(&request.organization_id, profile_id, public_projection)
        .await
        .map(Json)
}

async fn service_sign(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ServiceSignRequest>,
) -> Result<Json<serde_json::Value>, CompatibilityError> {
    authorize_internal(&state, &headers).map_err(|_| CompatibilityError::Unauthorized)?;
    let service = state
        .compatibility
        .as_ref()
        .ok_or(CompatibilityError::Unavailable)?;
    service
        .sign_with_service(&service_id, &request)
        .await
        .map(Json)
}

async fn issuer_did_sign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<IssuerDidSignRequest>,
) -> Result<Json<serde_json::Value>, CompatibilityError> {
    authorize_internal(&state, &headers).map_err(|_| CompatibilityError::Unauthorized)?;
    let service = state
        .compatibility
        .as_ref()
        .ok_or(CompatibilityError::Unavailable)?;
    service.sign_with_issuer_did(&request).await.map(Json)
}

async fn create_compatibility_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ProfileWriteRequest>,
) -> Result<Json<serde_json::Value>, CompatibilityError> {
    authorize_internal(&state, &headers).map_err(|_| CompatibilityError::Unauthorized)?;
    let service = state
        .compatibility
        .as_ref()
        .ok_or(CompatibilityError::Unavailable)?;
    service.create_profile(&request).await.map(Json)
}

async fn update_compatibility_profile(
    State(state): State<AppState>,
    Path(profile_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ProfileWriteRequest>,
) -> Result<Json<serde_json::Value>, CompatibilityError> {
    authorize_internal(&state, &headers).map_err(|_| CompatibilityError::Unauthorized)?;
    let service = state
        .compatibility
        .as_ref()
        .ok_or(CompatibilityError::Unavailable)?;
    service
        .update_profile(&profile_id, &request)
        .await
        .map(Json)
}

async fn attach_compatibility_certificate(
    State(state): State<AppState>,
    Path(profile_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ProfileWriteRequest>,
) -> Result<Json<serde_json::Value>, CompatibilityError> {
    authorize_internal(&state, &headers).map_err(|_| CompatibilityError::Unauthorized)?;
    let service = state
        .compatibility
        .as_ref()
        .ok_or(CompatibilityError::Unavailable)?;
    service
        .attach_profile_certificate(&profile_id, &request)
        .await
        .map(Json)
}

async fn wrap_flow_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<WrapRequest>,
) -> Result<Json<serde_json::Value>, FlowEnvelopeError> {
    authorize_internal(&state, &headers).map_err(|_| FlowEnvelopeError::Unauthorized)?;
    let provider = state
        .flow_envelopes
        .as_ref()
        .ok_or(FlowEnvelopeError::Unavailable)?;
    provider.wrap(request).await.map(Json)
}

async fn unwrap_flow_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UnwrapRequest>,
) -> Result<Json<serde_json::Value>, FlowEnvelopeError> {
    authorize_internal(&state, &headers).map_err(|_| FlowEnvelopeError::Unauthorized)?;
    let provider = state
        .flow_envelopes
        .as_ref()
        .ok_or(FlowEnvelopeError::Unavailable)?;
    provider.unwrap(request).await.map(Json)
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

async fn bind_registry_profile(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<BindProfileRequest>,
) -> Result<Json<serde_json::Value>, RegistryHttpError> {
    authorize_registry(&state, &headers)?;
    let store = state
        .registry_store
        .as_ref()
        .ok_or_else(registry_unavailable)?;
    store
        .bind_profile(&organization_id, &request.profile)
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

type DocumentHttpError = (StatusCode, Json<serde_json::Value>);

async fn inspect_certificate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<InspectCertificateRequest>,
) -> Result<Json<InspectCertificateResponse>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    documents::inspect_certificate(&request)
        .map(Json)
        .map_err(document_error)
}

async fn certificate_alerts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CertificateAlertsRequest>,
) -> Result<Json<CertificateAlertsResponse>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    documents::certificate_alerts(request)
        .map(Json)
        .map_err(document_error)
}

async fn certificate_overrides(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    document_store(&state)?
        .certificate_overrides(&organization_id)
        .await
        .map(Json)
        .map_err(document_error)
}

async fn store_certificate(
    State(state): State<AppState>,
    Path((organization_id, service_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<InspectCertificateRequest>,
) -> Result<Json<StoredCertificate>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    document_store(&state)?
        .store_certificate(&organization_id, &service_id, request)
        .await
        .map(Json)
        .map_err(document_error)
}

async fn load_jwks(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    document_store(&state)?
        .jwks(&organization_id)
        .await
        .map(Json)
        .map_err(document_error)
}

async fn publish_jwk(
    State(state): State<AppState>,
    Path((organization_id, service_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<PublishJwkRequest>,
) -> Result<Json<PublishJwkResponse>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    document_store(&state)?
        .publish_jwk(&organization_id, &service_id, request)
        .await
        .map(Json)
        .map_err(document_error)
}

async fn update_jwk(
    State(state): State<AppState>,
    Path((organization_id, key_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<UpdateJwkRequest>,
) -> Result<Json<UpdateJwkResponse>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    document_store(&state)?
        .update_jwk(&organization_id, &key_id, request)
        .await
        .map(Json)
        .map_err(document_error)
}

async fn delete_jwk(
    State(state): State<AppState>,
    Path((organization_id, key_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<DeleteJwkResponse>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    document_store(&state)?
        .delete_jwk(&organization_id, &key_id)
        .await
        .map(Json)
        .map_err(document_error)
}

async fn load_did(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<LoadDidRequest>,
) -> Result<Json<LoadDidResponse>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    document_store(&state)?
        .load_did(&organization_id, request)
        .await
        .map(Json)
        .map_err(document_error)
}

async fn publish_did(
    State(state): State<AppState>,
    Path((organization_id, service_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<PublishDidRequest>,
) -> Result<Json<PublishDidResponse>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    document_store(&state)?
        .publish_did(&organization_id, &service_id, request)
        .await
        .map(Json)
        .map_err(document_error)
}

async fn resolve_did_slug(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    let organization_id = document_store(&state)?
        .resolve_slug(&slug)
        .await
        .map_err(document_error)?;
    Ok(Json(
        serde_json::json!({"organization_id": organization_id}),
    ))
}

fn document_store(state: &AppState) -> Result<&DocumentStore, DocumentHttpError> {
    state.document_store.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"detail": "signing document storage is unavailable"})),
        )
    })
}

fn authorize_documents(state: &AppState, headers: &HeaderMap) -> Result<(), DocumentHttpError> {
    authorize_internal(state, headers).map_err(|error| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"detail": error.to_string()})),
        )
    })
}

fn document_error(error: documents::DocumentError) -> DocumentHttpError {
    let status = match &error {
        documents::DocumentError::Invalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
        documents::DocumentError::Conflict(_) => StatusCode::CONFLICT,
        documents::DocumentError::NotFound(_) => StatusCode::NOT_FOUND,
        documents::DocumentError::Storage(_) => StatusCode::SERVICE_UNAVAILABLE,
        documents::DocumentError::Corrupt(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(serde_json::json!({"detail": error.to_string()})),
    )
}

type ProfileHttpError = (StatusCode, Json<serde_json::Value>);

async fn normalize_profile(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<NormalizeProfileRequest>,
) -> Result<Json<serde_json::Value>, ProfileHttpError> {
    authorize_profiles(&state, &headers)?;
    profiles::normalize_profile(&organization_id, request)
        .map(|profile| Json(serde_json::json!({"profile": profile})))
        .map_err(profile_error)
}

async fn validate_profile_binding(
    State(state): State<AppState>,
    Path(_organization_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ValidateBindingRequest>,
) -> Result<Json<serde_json::Value>, ProfileHttpError> {
    authorize_profiles(&state, &headers)?;
    profiles::validate_binding(&request).map_err(profile_error)?;
    Ok(Json(serde_json::json!({"ok": true})))
}

async fn resolve_profile_custody_format(
    State(state): State<AppState>,
    Path(_organization_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CustodyFormatRequest>,
) -> Result<Json<CustodyFormatResponse>, ProfileHttpError> {
    authorize_profiles(&state, &headers)?;
    profiles::custody_format(&request)
        .map(Json)
        .map_err(profile_error)
}

async fn list_profiles(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ProfileHttpError> {
    authorize_profiles(&state, &headers)?;
    profile_store(&state)?
        .list(&organization_id)
        .await
        .map(Json)
        .map_err(profile_error)
}

async fn get_profile(
    State(state): State<AppState>,
    Path((organization_id, profile_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ProfileHttpError> {
    authorize_profiles(&state, &headers)?;
    profile_store(&state)?
        .get(&organization_id, &profile_id)
        .await
        .map(|profile| Json(serde_json::json!({"profile": profile})))
        .map_err(profile_error)
}

async fn put_profile(
    State(state): State<AppState>,
    Path((organization_id, profile_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(profile): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ProfileHttpError> {
    authorize_profiles(&state, &headers)?;
    profile_store(&state)?
        .put(&organization_id, &profile_id, profile)
        .await
        .map(|profile| Json(serde_json::json!({"profile": profile})))
        .map_err(profile_error)
}

async fn delete_profile(
    State(state): State<AppState>,
    Path((organization_id, profile_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ProfileHttpError> {
    authorize_profiles(&state, &headers)?;
    profile_store(&state)?
        .delete(&organization_id, &profile_id)
        .await
        .map_err(profile_error)?;
    Ok(Json(serde_json::json!({"deleted": profile_id})))
}

async fn find_profiles(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<FindProfilesRequest>,
) -> Result<Json<serde_json::Value>, ProfileHttpError> {
    authorize_profiles(&state, &headers)?;
    profile_store(&state)?
        .find(&organization_id, request)
        .await
        .map(|profiles| Json(serde_json::json!({"profiles": profiles})))
        .map_err(profile_error)
}

async fn find_duplicate_profile(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<DuplicateProfileRequest>,
) -> Result<Json<DuplicateProfileResponse>, ProfileHttpError> {
    authorize_profiles(&state, &headers)?;
    profile_store(&state)?
        .find_duplicate(&organization_id, request)
        .await
        .map(Json)
        .map_err(profile_error)
}

fn profile_store(state: &AppState) -> Result<&ProfileStore, ProfileHttpError> {
    state.profile_store.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"detail": "issuer profile storage is unavailable"})),
        )
    })
}

fn authorize_profiles(state: &AppState, headers: &HeaderMap) -> Result<(), ProfileHttpError> {
    authorize_internal(state, headers).map_err(|error| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"detail": error.to_string()})),
        )
    })
}

fn profile_error(error: profiles::ProfileError) -> ProfileHttpError {
    let status = match &error {
        profiles::ProfileError::Invalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
        profiles::ProfileError::Conflict(_) => StatusCode::CONFLICT,
        profiles::ProfileError::NotFound(_) => StatusCode::NOT_FOUND,
        profiles::ProfileError::Storage(_) => StatusCode::SERVICE_UNAVAILABLE,
        profiles::ProfileError::Corrupt(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(serde_json::json!({"detail": error.to_string()})),
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
            "certificate-document-persistence",
            "jwks-did-publication-persistence",
            "issuer-profile-policy-selection-persistence",
        ],
        pending_capabilities: ["audit-event-storage", "compliance-summary-computation"],
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
