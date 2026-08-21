use crate::{
    ComplianceError, ComplianceService, CreateComplianceProfileRequest,
    UpdateComplianceProfileRequest,
};
use axum::{
    extract::{rejection::JsonRejection, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
#[derive(Clone)]
pub struct ComplianceHttpState {
    pub service: Arc<ComplianceService>,
}
enum ApiError {
    Domain(ComplianceError),
    Validation,
}
impl From<ComplianceError> for ApiError {
    fn from(v: ComplianceError) -> Self {
        Self::Domain(v)
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
            Self::Domain(e) => {
                let s = match &e {
                    ComplianceError::BadRequest(_) => StatusCode::BAD_REQUEST,
                    ComplianceError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
                    ComplianceError::Forbidden(_) => StatusCode::FORBIDDEN,
                    ComplianceError::NotFound(_) => StatusCode::NOT_FOUND,
                    ComplianceError::Conflict(_) => StatusCode::CONFLICT,
                    ComplianceError::Dependency(_) => StatusCode::BAD_GATEWAY,
                    ComplianceError::Persistence(_) => StatusCode::INTERNAL_SERVER_ERROR,
                };
                let detail = match e {
                    ComplianceError::Persistence(_) => {
                        "Compliance Profile storage unavailable".to_owned()
                    }
                    other => other.to_string(),
                };
                (s, Json(json!({"detail":detail}))).into_response()
            }
        }
    }
}
#[derive(Deserialize)]
struct ListQuery {
    organization_id: String,
    #[serde(default = "limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}
const fn limit() -> usize {
    100
}
pub fn compliance_router(s: ComplianceHttpState) -> Router {
    Router::new()
        .route("/v1/compliance-profiles", post(create).get(list))
        .route(
            "/v1/compliance-profiles/system/discoverable",
            get(discoverable),
        )
        .route(
            "/v1/compliance-profiles/{profile_id}",
            get(get_one).patch(update).delete(delete_one),
        )
        .route(
            "/v1/compliance-profiles/{profile_id}/activate",
            post(activate),
        )
        .route(
            "/v1/compliance-profiles/{profile_id}/suspend",
            post(suspend),
        )
        .with_state(s)
}
async fn create(
    State(s): State<ComplianceHttpState>,
    h: HeaderMap,
    b: Result<Json<CreateComplianceProfileRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(b) = b.map_err(|_| ApiError::Validation)?;
    value(s.service.create(b, &user(&h)).await?)
}
async fn list(
    State(s): State<ComplianceHttpState>,
    h: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    if q.limit == 0 || q.limit > 500 {
        return Err(ApiError::Validation);
    }
    value(
        s.service
            .list(&q.organization_id, q.limit, q.offset, &user(&h))
            .await?,
    )
}
async fn discoverable(State(s): State<ComplianceHttpState>) -> Result<Json<Value>, ApiError> {
    value(s.service.discoverable().await?)
}
async fn get_one(
    State(s): State<ComplianceHttpState>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    value(s.service.get(&id, &user(&h)).await?)
}
async fn update(
    State(s): State<ComplianceHttpState>,
    h: HeaderMap,
    Path(id): Path<String>,
    b: Result<Json<UpdateComplianceProfileRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(b) = b.map_err(|_| ApiError::Validation)?;
    value(s.service.update(&id, b, &user(&h)).await?)
}
async fn activate(
    State(s): State<ComplianceHttpState>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    value(s.service.activate(&id, &user(&h)).await?)
}
async fn suspend(
    State(s): State<ComplianceHttpState>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    value(s.service.suspend(&id, &user(&h)).await?)
}
async fn delete_one(
    State(s): State<ComplianceHttpState>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    s.service.delete(&id, &user(&h)).await?;
    Ok(Json(json!({"success":true})))
}
fn user(h: &HeaderMap) -> String {
    h.get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or_default()
        .into()
}
fn value(v: impl serde::Serialize) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        serde_json::to_value(v).map_err(|_| ApiError::Validation)?,
    ))
}
