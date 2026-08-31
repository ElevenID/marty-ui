use std::sync::Arc;

use axum::{
    extract::{rejection::JsonRejection, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use mmf_core::HealthReport;
use mmf_runtime::{system_router_with_options, RuntimeState, SystemRouteOptions};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    EvaluateRequest, ManagementPrincipal, StartVerificationRequest, SubmitVerificationRequest,
    VerificationError, VerificationService, ZkpSubmitRequest,
};

#[derive(Clone)]
pub struct HttpState {
    pub service: Arc<VerificationService>,
    pub runtime: RuntimeState,
    pub release_version: String,
    pub build_revision: String,
}

#[derive(Debug)]
enum ApiError {
    Domain(VerificationError),
    Validation,
}

impl From<VerificationError> for ApiError {
    fn from(error: VerificationError) -> Self {
        Self::Domain(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::Validation => (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_request",
                    "error_description": "Request validation failed"
                })),
            )
                .into_response(),
            Self::Domain(error) => {
                let status = match error {
                    VerificationError::BadRequest(_) => StatusCode::BAD_REQUEST,
                    VerificationError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
                    VerificationError::Forbidden(_) => StatusCode::FORBIDDEN,
                    VerificationError::NotFound(_) => StatusCode::NOT_FOUND,
                    VerificationError::Conflict(_) => StatusCode::CONFLICT,
                    VerificationError::Gone(_) => StatusCode::GONE,
                    VerificationError::Dependency(_) => StatusCode::BAD_GATEWAY,
                    VerificationError::Coordination(_) => StatusCode::SERVICE_UNAVAILABLE,
                    VerificationError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
                };
                (status, Json(json!({"detail": error.to_string()}))).into_response()
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    organization_id: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

const fn default_limit() -> usize {
    50
}

pub fn router(state: HttpState) -> Router {
    Router::new()
        .route("/v1/verify", post(start))
        .route("/v1/verify/sessions", get(list))
        .route("/v1/verify/evaluate", post(evaluate))
        .route("/v1/verify/zkp", post(evaluate_zkp))
        .route("/v1/verify/health", get(service_health))
        .route("/v1/verify/{session_id}/request", get(request_object))
        .route("/v1/verify/{session_id}/inspection", get(inspection))
        .route("/v1/verify/{session_id}/submit", post(submit_presentation))
        .route("/v1/verify/{session_id}", get(get_session))
        .route("/startup", get(startup))
        .route("/health/native-backend", get(native_health))
        .route("/metrics", get(metrics))
        .with_state(state.clone())
        .merge(system_router_with_options(
            state.runtime,
            SystemRouteOptions::default().with_health_projector(compatibility_health),
        ))
}

fn compatibility_health(_: &HealthReport) -> Value {
    compatibility_health_body()
}

fn compatibility_health_body() -> Value {
    json!({
        "status": "healthy",
        "service": "verification",
        "native_backend": {
            "available": true,
            "module": "_marty_rs",
            "version": env!("CARGO_PKG_VERSION"),
            "missing_capabilities": [],
            "error": null,
        },
    })
}

async fn start(
    State(state): State<HttpState>,
    headers: HeaderMap,
    body: Result<Json<StartVerificationRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(body) = body.map_err(|_| ApiError::Validation)?;
    Ok(Json(state.service.start(body, &principal(&headers)).await?))
}

async fn list(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        state
            .service
            .list(
                &query.organization_id,
                query.status.as_deref(),
                query.limit,
                query.offset,
                &principal(&headers),
            )
            .await?,
    ))
}

async fn request_object(
    State(state): State<HttpState>,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(state.service.request_object(&session_id).await?))
}

async fn get_session(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        state.service.get(&session_id, &principal(&headers)).await?,
    ))
}

async fn submit_presentation(
    State(state): State<HttpState>,
    Path(session_id): Path<String>,
    body: Result<Json<SubmitVerificationRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(body) = body.map_err(|_| ApiError::Validation)?;
    Ok(Json(
        state
            .service
            .submit(&session_id, &body.vp_token, true)
            .await?,
    ))
}

async fn evaluate(
    State(state): State<HttpState>,
    headers: HeaderMap,
    body: Result<Json<EvaluateRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(body) = body.map_err(|_| ApiError::Validation)?;
    Ok(Json(
        state.service.evaluate(body, &principal(&headers)).await?,
    ))
}

async fn evaluate_zkp(
    State(state): State<HttpState>,
    headers: HeaderMap,
    body: Result<Json<ZkpSubmitRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(body) = body.map_err(|_| ApiError::Validation)?;
    Ok(Json(
        state
            .service
            .evaluate_zkp(body, &principal(&headers))
            .await?,
    ))
}

async fn inspection(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        state
            .service
            .inspection(&session_id, &principal(&headers))
            .await?,
    ))
}

async fn service_health(State(state): State<HttpState>) -> Json<Value> {
    Json(
        json!({"status":"healthy","service":"verification","backend":"rust","version":state.release_version,"build_revision":state.build_revision}),
    )
}

async fn startup(State(state): State<HttpState>) -> Json<Value> {
    Json(
        json!({"status":"started","service":"verification","backend":"rust","version":state.release_version,"build_revision":state.build_revision}),
    )
}

async fn native_health(State(state): State<HttpState>) -> Json<Value> {
    Json(json!({
        "status":"ready",
        "available":true,
        "backend":"marty-flow+marty-core",
        "version":env!("CARGO_PKG_VERSION"),
        "build_revision":state.build_revision,
        "required_capability":"oid4vp_verification",
        "capabilities":["oid4vp_request","dcql","presentation_evaluation","session_coordination"]
    }))
}

async fn metrics() -> &'static str {
    "# TYPE marty_verification_native_backend gauge\nmarty_verification_native_backend 1\n"
}

fn principal(headers: &HeaderMap) -> ManagementPrincipal {
    ManagementPrincipal {
        user_id: header(headers, "x-user-id"),
        organization_id: header(headers, "x-organization-id"),
        api_key_id: header(headers, "x-api-key-id"),
        api_key_scopes: header(headers, "x-api-key-scopes"),
        required_permission: header(headers, "x-required-permission"),
    }
}

fn header(headers: &HeaderMap, name: &'static str) -> String {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .unwrap_or_default()
        .into()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::compatibility_health_body;

    #[test]
    fn root_health_uses_the_released_compatibility_projection() {
        assert_eq!(
            compatibility_health_body(),
            json!({
                "status": "healthy",
                "service": "verification",
                "native_backend": {
                    "available": true,
                    "module": "_marty_rs",
                    "version": env!("CARGO_PKG_VERSION"),
                    "missing_capabilities": [],
                    "error": null,
                },
            })
        );
    }
}
