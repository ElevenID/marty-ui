use std::sync::Arc;

use axum::{
    extract::{rejection::JsonRejection, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    AssignDeviceRequest, CreateDeploymentProfileRequest, CreateLaneRequest, DeploymentError,
    DeploymentService, UpdateDeploymentProfileRequest, UpdateLaneRequest,
};

#[derive(Clone)]
pub struct DeploymentHttpState {
    pub service: Arc<DeploymentService>,
}

#[derive(Debug)]
enum ApiError {
    Domain(DeploymentError),
    Validation,
}
impl From<DeploymentError> for ApiError {
    fn from(value: DeploymentError) -> Self {
        Self::Domain(value)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::Validation => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail":"Request validation failed"})),
            )
                .into_response(),
            Self::Domain(error) => {
                let status = match error {
                    DeploymentError::BadRequest(_) => StatusCode::UNPROCESSABLE_ENTITY,
                    DeploymentError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
                    DeploymentError::Forbidden(_) => StatusCode::FORBIDDEN,
                    DeploymentError::NotFound(_) => StatusCode::NOT_FOUND,
                    DeploymentError::Conflict(_) => StatusCode::CONFLICT,
                    DeploymentError::Dependency(_) => StatusCode::BAD_GATEWAY,
                    DeploymentError::Persistence(_) => StatusCode::INTERNAL_SERVER_ERROR,
                };
                (status, Json(json!({"detail":error.to_string()}))).into_response()
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    organization_id: String,
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}
#[derive(Debug, Deserialize)]
struct PageQuery {
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}
const fn default_limit() -> usize {
    100
}

#[derive(Debug, Serialize)]
struct DeleteResponse {
    deleted: bool,
}

pub fn deployment_router(state: DeploymentHttpState) -> Router {
    Router::new()
        .route("/v1/deployment-profiles", post(create).get(list))
        .route(
            "/v1/deployment-profiles/{profile_id}",
            get(get_profile).patch(update).delete(delete_profile),
        )
        .route(
            "/v1/deployment-profiles/{profile_id}/activate",
            post(activate),
        )
        .route(
            "/v1/deployment-profiles/{profile_id}/suspend",
            post(suspend),
        )
        .route(
            "/v1/deployment-profiles/{profile_id}/generate-api-key",
            post(generate_api_key),
        )
        .route(
            "/v1/deployment-profiles/{profile_id}/lanes",
            post(create_lane).get(list_lanes),
        )
        .route(
            "/v1/deployment-profiles/{profile_id}/lanes/{lane_id}",
            get(get_lane).put(update_lane).delete(delete_lane),
        )
        .route(
            "/v1/deployment-profiles/{profile_id}/lanes/{lane_id}/devices",
            post(assign_device),
        )
        .with_state(state)
}

async fn create(
    State(s): State<DeploymentHttpState>,
    h: HeaderMap,
    body: Result<Json<CreateDeploymentProfileRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(body) = body.map_err(|_| ApiError::Validation)?;
    Ok(Json(
        serde_json::to_value(s.service.create(body, &user(&h)).await?)
            .map_err(|_| ApiError::Validation)?,
    ))
}
async fn list(
    State(s): State<DeploymentHttpState>,
    h: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    validate_page(q.limit, q.offset)?;
    Ok(Json(
        serde_json::to_value(
            s.service
                .list(&q.organization_id, q.limit, q.offset, &user(&h))
                .await?,
        )
        .map_err(|_| ApiError::Validation)?,
    ))
}
async fn get_profile(
    State(s): State<DeploymentHttpState>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        serde_json::to_value(s.service.get(&id, &user(&h)).await?)
            .map_err(|_| ApiError::Validation)?,
    ))
}
async fn update(
    State(s): State<DeploymentHttpState>,
    h: HeaderMap,
    Path(id): Path<String>,
    body: Result<Json<UpdateDeploymentProfileRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(body) = body.map_err(|_| ApiError::Validation)?;
    Ok(Json(
        serde_json::to_value(s.service.update(&id, body, &user(&h)).await?)
            .map_err(|_| ApiError::Validation)?,
    ))
}
async fn activate(
    State(s): State<DeploymentHttpState>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        serde_json::to_value(s.service.activate(&id, &user(&h)).await?)
            .map_err(|_| ApiError::Validation)?,
    ))
}
async fn suspend(
    State(s): State<DeploymentHttpState>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        serde_json::to_value(s.service.suspend(&id, &user(&h)).await?)
            .map_err(|_| ApiError::Validation)?,
    ))
}
async fn generate_api_key(
    State(s): State<DeploymentHttpState>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        serde_json::to_value(s.service.generate_api_key(&id, &user(&h)).await?)
            .map_err(|_| ApiError::Validation)?,
    ))
}
async fn delete_profile(
    State(s): State<DeploymentHttpState>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<DeleteResponse>, ApiError> {
    s.service.delete(&id, &user(&h)).await?;
    Ok(Json(DeleteResponse { deleted: true }))
}
async fn create_lane(
    State(s): State<DeploymentHttpState>,
    h: HeaderMap,
    Path(profile): Path<String>,
    body: Result<Json<CreateLaneRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(body) = body.map_err(|_| ApiError::Validation)?;
    Ok(Json(
        serde_json::to_value(s.service.create_lane(&profile, body, &user(&h)).await?)
            .map_err(|_| ApiError::Validation)?,
    ))
}
async fn list_lanes(
    State(s): State<DeploymentHttpState>,
    h: HeaderMap,
    Path(profile): Path<String>,
    Query(q): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    validate_page(q.limit, q.offset)?;
    Ok(Json(
        serde_json::to_value(
            s.service
                .list_lanes(&profile, q.limit, q.offset, &user(&h))
                .await?,
        )
        .map_err(|_| ApiError::Validation)?,
    ))
}
async fn get_lane(
    State(s): State<DeploymentHttpState>,
    h: HeaderMap,
    Path((profile, lane)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        serde_json::to_value(s.service.get_lane(&profile, &lane, &user(&h)).await?)
            .map_err(|_| ApiError::Validation)?,
    ))
}
async fn update_lane(
    State(s): State<DeploymentHttpState>,
    h: HeaderMap,
    Path((profile, lane)): Path<(String, String)>,
    body: Result<Json<UpdateLaneRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(body) = body.map_err(|_| ApiError::Validation)?;
    Ok(Json(
        serde_json::to_value(
            s.service
                .update_lane(&profile, &lane, body, &user(&h))
                .await?,
        )
        .map_err(|_| ApiError::Validation)?,
    ))
}
async fn delete_lane(
    State(s): State<DeploymentHttpState>,
    h: HeaderMap,
    Path((profile, lane)): Path<(String, String)>,
) -> Result<Json<DeleteResponse>, ApiError> {
    s.service.delete_lane(&profile, &lane, &user(&h)).await?;
    Ok(Json(DeleteResponse { deleted: true }))
}
async fn assign_device(
    State(s): State<DeploymentHttpState>,
    h: HeaderMap,
    Path((profile, lane)): Path<(String, String)>,
    body: Result<Json<AssignDeviceRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(body) = body.map_err(|_| ApiError::Validation)?;
    Ok(Json(
        serde_json::to_value(
            s.service
                .assign_device(&profile, &lane, body, &user(&h))
                .await?,
        )
        .map_err(|_| ApiError::Validation)?,
    ))
}

fn validate_page(limit: usize, offset: usize) -> Result<(), ApiError> {
    if limit == 0 || limit > 500 || offset > 10_000_000 {
        Err(ApiError::Validation)
    } else {
        Ok(())
    }
}
fn user(headers: &HeaderMap) -> String {
    headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or_default()
        .into()
}
