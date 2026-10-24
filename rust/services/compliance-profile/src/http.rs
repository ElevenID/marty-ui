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
    service_authenticator: Option<Arc<mmf_security::ServiceTokenAuthenticator>>,
}

impl ComplianceHttpState {
    pub fn new(service: Arc<ComplianceService>) -> Self {
        Self {
            service,
            service_authenticator: None,
        }
    }

    pub fn with_service_token(
        mut self,
        token: Option<String>,
    ) -> Result<Self, mmf_security::SecurityError> {
        self.service_authenticator = token
            .map(|token| {
                mmf_security::ServiceTokenAuthenticator::new(Some(token), true).map(Arc::new)
            })
            .transpose()?;
        Ok(self)
    }

    fn authenticate_service(&self, headers: &HeaderMap) -> Result<(), ApiError> {
        match &self.service_authenticator {
            Some(authenticator) => authenticator
                .authenticate(header(headers, "x-service-token"))
                .map_err(|_| {
                    ComplianceError::Unauthorized("Service authentication required".into()).into()
                }),
            None => {
                Err(ComplianceError::Unauthorized("Service authentication required".into()).into())
            }
        }
    }

    fn for_request(&self, headers: &HeaderMap) -> Result<ComplianceService, ApiError> {
        let is_key =
            headers.contains_key("x-api-key-id") || headers.contains_key("x-api-key-scopes");
        if !is_key {
            return Ok(self.service.as_ref().clone());
        }
        self.authenticate_service(headers)?;
        let actor = marty_api_key_policy::GatewayApiKeyActor::parse(
            header(headers, "x-api-key-id").unwrap_or_default(),
            header(headers, "x-organization-id").unwrap_or_default(),
            header(headers, "x-api-key-scopes").unwrap_or_default(),
        )
        .map_err(|_| ComplianceError::Unauthorized("Invalid gateway principal".into()))?;
        Ok(self.service.for_gateway_api_key(actor))
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
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
        .route(
            "/internal/v1/resource-owners/compliance-profiles/{profile_id}",
            get(resource_owner),
        )
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

async fn resource_owner(
    State(state): State<ComplianceHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    state.authenticate_service(&headers)?;
    let (id, organization_id, is_system) = state.service.internal_owner(&id).await?;
    Ok(Json(
        json!({"id": id, "organization_id": organization_id, "is_system": is_system}),
    ))
}
async fn create(
    State(s): State<ComplianceHttpState>,
    h: HeaderMap,
    b: Result<Json<CreateComplianceProfileRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(b) = b.map_err(|_| ApiError::Validation)?;
    value(s.for_request(&h)?.create(b, &user(&h)).await?)
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
        s.for_request(&h)?
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
    value(s.for_request(&h)?.get(&id, &user(&h)).await?)
}
async fn update(
    State(s): State<ComplianceHttpState>,
    h: HeaderMap,
    Path(id): Path<String>,
    b: Result<Json<UpdateComplianceProfileRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(b) = b.map_err(|_| ApiError::Validation)?;
    value(s.for_request(&h)?.update(&id, b, &user(&h)).await?)
}
async fn activate(
    State(s): State<ComplianceHttpState>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    value(s.for_request(&h)?.activate(&id, &user(&h)).await?)
}
async fn suspend(
    State(s): State<ComplianceHttpState>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    value(s.for_request(&h)?.suspend(&id, &user(&h)).await?)
}
async fn delete_one(
    State(s): State<ComplianceHttpState>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    s.for_request(&h)?.delete(&id, &user(&h)).await?;
    Ok(Json(json!({"success":true})))
}
fn user(h: &HeaderMap) -> String {
    h.get("x-api-key-id")
        .or_else(|| h.get("x-user-id"))
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
