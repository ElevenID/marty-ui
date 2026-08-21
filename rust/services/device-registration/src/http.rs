use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

use crate::{
    control_plane::MembershipAuthorizer, ChallengeRequest, CreateRegistration, DeviceError,
    DeviceRegistration, DeviceService, ProofHeaders, UpdateRegistration,
};

#[derive(Clone)]
pub struct HttpState {
    pub service: Arc<DeviceService>,
    pub memberships: Arc<dyn MembershipAuthorizer>,
    pub release_version: String,
    pub build_revision: String,
}

pub fn router(state: HttpState) -> Router {
    Router::new()
        .route("/v1/devices", get(list_devices).post(register_device))
        .route("/v1/devices/challenge", post(request_challenge))
        .route(
            "/v1/devices/{registration_id}",
            get(get_device).patch(update_device).delete(delete_device),
        )
        .route("/health", get(health))
        .route("/ready", get(health))
        .route("/startup", get(health))
        .route("/health/native-backend", get(native_health))
        .route("/metrics", get(metrics))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[derive(Debug)]
pub struct ApiError(DeviceError);

impl From<DeviceError> for ApiError {
    fn from(value: DeviceError) -> Self {
        Self(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            DeviceError::BadRequest(_) | DeviceError::Native(_) => StatusCode::BAD_REQUEST,
            DeviceError::Forbidden(_) => StatusCode::FORBIDDEN,
            DeviceError::NotFound(_) => StatusCode::NOT_FOUND,
            DeviceError::Conflict(_) => StatusCode::CONFLICT,
            DeviceError::Persistence(_)
            | DeviceError::ChallengeStore(_)
            | DeviceError::AuthorizationUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        };
        (status, Json(json!({"detail": self.0.to_string()}))).into_response()
    }
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    organization_id: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

const fn default_limit() -> usize {
    100
}

fn identity(headers: &HeaderMap) -> Result<String, ApiError> {
    headers
        .get("x-user-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| DeviceError::BadRequest("X-User-Id header is required".into()).into())
}

fn proof(headers: &HeaderMap) -> ProofHeaders {
    ProofHeaders {
        challenge_id: header(headers, "x-device-challenge-id"),
        signature: header(headers, "x-device-challenge-signature"),
    }
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

async fn authorize(
    state: &HttpState,
    user_id: &str,
    organization_id: Option<&str>,
) -> Result<(), ApiError> {
    if let Some(organization_id) = organization_id {
        state
            .memberships
            .require_active(user_id, organization_id)
            .await?
    }
    Ok(())
}

async fn request_challenge(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<ChallengeRequest>,
) -> Result<Json<crate::ChallengeResponse>, ApiError> {
    let user_id = identity(&headers)?;
    Ok(Json(state.service.request_challenge(&user_id, body).await?))
}

async fn register_device(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<CreateRegistration>,
) -> Result<Json<DeviceRegistration>, ApiError> {
    let user_id = identity(&headers)?;
    authorize(&state, &user_id, body.organization_id.as_deref()).await?;
    Ok(Json(
        state
            .service
            .register(&user_id, body, proof(&headers))
            .await?,
    ))
}

async fn list_devices(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<DeviceRegistration>>, ApiError> {
    let user_id = identity(&headers)?;
    authorize(&state, &user_id, query.organization_id.as_deref()).await?;
    Ok(Json(
        state
            .service
            .list(
                &user_id,
                query.organization_id.as_deref(),
                query.limit,
                query.offset,
            )
            .await?,
    ))
}

async fn get_device(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<DeviceRegistration>, ApiError> {
    let user_id = identity(&headers)?;
    let value = state.service.get(&user_id, &id).await?;
    authorize(&state, &user_id, value.organization_id.as_deref()).await?;
    Ok(Json(value))
}

async fn update_device(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateRegistration>,
) -> Result<Json<DeviceRegistration>, ApiError> {
    let user_id = identity(&headers)?;
    let current = state.service.get(&user_id, &id).await?;
    authorize(&state, &user_id, current.organization_id.as_deref()).await?;
    Ok(Json(
        state
            .service
            .update(&user_id, &id, body, proof(&headers))
            .await?,
    ))
}

async fn delete_device(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let user_id = identity(&headers)?;
    let current = state.service.get(&user_id, &id).await?;
    authorize(&state, &user_id, current.organization_id.as_deref()).await?;
    state.service.delete(&user_id, &id).await?;
    Ok(Json(json!({"success": true})))
}

async fn health(State(state): State<HttpState>) -> Json<Value> {
    Json(
        json!({"status":"healthy","service":"device-registration-service","backend":"rust","version":state.release_version,"build_revision":state.build_revision}),
    )
}

async fn native_health(State(state): State<HttpState>) -> Json<Value> {
    Json(
        json!({"status":"ready","available":true,"backend":"marty-verification","version":env!("CARGO_PKG_VERSION"),"build_revision":state.build_revision,"required_capability":"device_authentication","capabilities":["device_authentication"]}),
    )
}

async fn metrics() -> &'static str {
    "# HELP marty_device_registration_backend_info Native backend information\n# TYPE marty_device_registration_backend_info gauge\nmarty_device_registration_backend_info{backend=\"rust\"} 1\n"
}
