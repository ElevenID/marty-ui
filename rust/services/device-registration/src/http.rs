use axum::{
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tower_http::trace::TraceLayer;

use crate::{
    control_plane::MembershipAuthorizer,
    holder_signer::HolderSigner,
    pairing_confirmation::PostgresPairingConfirmations,
    pairing_enrollment::{PairingEnrollment, PairingRedeemRequest},
    pairing_ticket::PairingTicketRepository,
    CreateRegistration, DeviceError, DeviceRegistration, DeviceService, UpdateRegistration,
};

#[derive(Clone)]
pub struct HttpState {
    pub service: Arc<DeviceService>,
    pub memberships: Arc<dyn MembershipAuthorizer>,
    pub pairing_tickets: Arc<dyn PairingTicketRepository>,
    pub pairing_confirmations: Option<Arc<PostgresPairingConfirmations>>,
    pub pairing_enrollment: Option<Arc<PairingEnrollment>>,
    pub holder_signer: Option<Arc<HolderSigner>>,
    pub release_version: String,
    pub build_revision: String,
    pub gateway_key: String,
}

pub fn router(state: HttpState) -> Router {
    Router::new()
        .route("/v1/devices", get(list_devices).post(register_device))
        .route(
            "/v1/devices/pairing-tickets",
            axum::routing::post(issue_pairing_ticket),
        )
        .route(
            "/v1/devices/pair",
            axum::routing::post(redeem_pairing_ticket),
        )
        .route(
            "/v1/devices/pairing-confirmations/{pairing_id}",
            get(pairing_status),
        )
        .route(
            "/v1/devices/pairing-ack",
            axum::routing::post(confirm_pairing),
        )
        .route(
            "/v1/devices/holder-signatures",
            axum::routing::post(sign_holder_payload),
        )
        .route(
            "/v1/devices/{registration_id}",
            get(get_device).patch(update_device).delete(delete_device),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), gateway_auth))
        .route("/health", get(health))
        .route("/ready", get(health))
        .route("/startup", get(health))
        .route("/health/native-backend", get(native_health))
        .route("/metrics", get(metrics))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn gateway_auth(State(state): State<HttpState>, request: Request, next: Next) -> Response {
    let supplied = request
        .headers()
        .get("x-service-token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if state.gateway_key.len() < 32
        || supplied
            .as_bytes()
            .ct_eq(state.gateway_key.as_bytes())
            .unwrap_u8()
            != 1
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"detail":"Gateway authentication is required"})),
        )
            .into_response();
    }
    next.run(request).await
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
            DeviceError::BadRequest(_) => StatusCode::BAD_REQUEST,
            DeviceError::Forbidden(_) => StatusCode::FORBIDDEN,
            DeviceError::NotFound(_) => StatusCode::NOT_FOUND,
            DeviceError::Conflict(_) => StatusCode::CONFLICT,
            DeviceError::Persistence(_)
            | DeviceError::PairingStore(_)
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairingTicketRequest {
    organization_id: String,
}

async fn issue_pairing_ticket(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<PairingTicketRequest>,
) -> Result<Response, ApiError> {
    let user_id = identity(&headers)?;
    let organization_id = body.organization_id.trim();
    if organization_id.is_empty() {
        return Err(DeviceError::BadRequest("organization_id is required".into()).into());
    }
    state
        .memberships
        .require_active(&user_id, organization_id)
        .await?;
    let confirmations = state.pairing_confirmations.as_ref().ok_or_else(|| {
        DeviceError::PairingStore("wallet pairing confirmation is unavailable".into())
    })?;
    let ticket = state
        .pairing_tickets
        .issue(&user_id, organization_id)
        .await?;
    confirmations.record_issued(&ticket.scope).await?;
    let mut response = Json(json!({
        "pairing_code": ticket.token,
        "pairing_id": ticket.scope.pairing_id,
        "expires_at": ticket.scope.expires_at,
    }))
    .into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

async fn pairing_status(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(pairing_id): Path<String>,
) -> Result<Response, ApiError> {
    let user_id = identity(&headers)?;
    let confirmations = state.pairing_confirmations.as_ref().ok_or_else(|| {
        DeviceError::PairingStore("wallet pairing confirmation is unavailable".into())
    })?;
    let status = confirmations.status(&pairing_id, &user_id).await?;
    state
        .memberships
        .require_active(&user_id, &status.organization_id)
        .await?;
    let mut response = Json(json!({
        "state": status.state,
        "registration_id": status.registration_id,
    }))
    .into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

async fn confirm_pairing(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<PairingAckRequest>,
) -> Result<Response, ApiError> {
    let confirmations = state.pairing_confirmations.as_ref().ok_or_else(|| {
        DeviceError::PairingStore("wallet pairing confirmation is unavailable".into())
    })?;
    let signer = state
        .holder_signer
        .as_ref()
        .ok_or_else(|| DeviceError::PairingStore("remote holder signing is unavailable".into()))?;
    let bearer = bearer(&headers)?;
    signer
        .sign_pairing_confirmation(bearer, &body.pairing_id)
        .await?;
    confirmations.confirm(&body.pairing_id, bearer).await?;
    let mut response = Json(json!({"confirmed": true})).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairingAckRequest {
    pairing_id: String,
}

async fn redeem_pairing_ticket(
    State(state): State<HttpState>,
    Json(body): Json<PairingRedeemRequest>,
) -> Result<Response, ApiError> {
    let enrollment = state.pairing_enrollment.as_ref().ok_or_else(|| {
        DeviceError::PairingStore("remote holder enrollment is unavailable".into())
    })?;
    let enrolled = enrollment.redeem(body).await?;
    let mut response = Json(enrolled).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HolderSignRequest {
    purpose: String,
    payload_b64: String,
}

async fn sign_holder_payload(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<HolderSignRequest>,
) -> Result<Response, ApiError> {
    let signer = state
        .holder_signer
        .as_ref()
        .ok_or_else(|| DeviceError::Persistence("remote holder signing is unavailable".into()))?;
    let bearer = bearer(&headers)?;
    if body.payload_b64.len() > 87_384 {
        return Err(DeviceError::BadRequest("holder signing input is invalid".into()).into());
    }
    let payload = URL_SAFE_NO_PAD
        .decode(&body.payload_b64)
        .map_err(|_| DeviceError::BadRequest("holder signing input is invalid".into()))?;
    let signature = signer
        .sign_from_bearer(bearer, &body.purpose, &payload)
        .await?;
    let mut response = Json(signature).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

fn bearer(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty() && !value.contains(' '))
        .ok_or_else(|| {
            DeviceError::Forbidden("holder signing authorization is invalid".into()).into()
        })
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

async fn register_device(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<CreateRegistration>,
) -> Result<Json<DeviceRegistration>, ApiError> {
    let user_id = identity(&headers)?;
    authorize(&state, &user_id, body.organization_id.as_deref()).await?;
    Ok(Json(state.service.register(&user_id, body).await?))
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
    Ok(Json(state.service.update(&user_id, &id, body).await?))
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
        json!({"status":"ready","available":true,"backend":"marty-device-registration","version":env!("CARGO_PKG_VERSION"),"build_revision":state.build_revision,"required_capability":"keyless_registration","capabilities":["keyless_registration"]}),
    )
}

async fn metrics() -> &'static str {
    "# HELP marty_device_registration_backend_info Native backend information\n# TYPE marty_device_registration_backend_info gauge\nmarty_device_registration_backend_info{backend=\"rust\"} 1\n"
}
