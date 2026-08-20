use std::{collections::BTreeMap, sync::Arc};

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use marty_verification::flow::FlowInstanceStatus;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    FlowProviderError, FlowProviderRegistry, FlowRecordError, FlowType, PostgresFlowRepository,
    RepositoryError,
};

const MIP_VERSION: &str = "0.4.1";
const DEFAULT_PAGE_SIZE: usize = 100;
const MAXIMUM_PAGE_SIZE: usize = 500;

#[derive(Clone)]
pub struct FlowHttpState {
    pub repository: PostgresFlowRepository,
    pub providers: Arc<FlowProviderRegistry>,
}

pub fn flow_read_router(state: FlowHttpState) -> Router {
    Router::new()
        .route("/v1/flows/capabilities", get(capabilities))
        .route("/v1/flows/definitions", get(list_definitions))
        .route(
            "/v1/flows/definitions/{flow_id}",
            get(get_definition).delete(delete_definition),
        )
        .route("/v1/flows/instances", get(list_instances))
        .route("/v1/flows/instances/{instance_id}", get(get_instance))
        .route(
            "/v1/flows/instances/{instance_id}/cancel",
            post(cancel_instance),
        )
        .route("/v1/flows/instances/{instance_id}/result", get(get_result))
        .route(
            "/v1/flows/instances/{instance_id}/artifacts",
            get(list_artifacts),
        )
        .route(
            "/v1/flows/instances/{instance_id}/artifacts/{artifact_id}",
            get(get_artifact),
        )
        .with_state(state)
}

#[derive(Debug, Serialize)]
struct FlowHttpErrorBody {
    error: &'static str,
    detail: String,
}

#[derive(Debug)]
struct FlowHttpError {
    status: StatusCode,
    code: &'static str,
    detail: String,
}

impl FlowHttpError {
    fn new(status: StatusCode, code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status,
            code,
            detail: detail.into(),
        }
    }
}

impl IntoResponse for FlowHttpError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(FlowHttpErrorBody {
                error: self.code,
                detail: self.detail,
            }),
        )
            .into_response()
    }
}

#[derive(Serialize)]
struct FlowCapabilities {
    protocol_version: &'static str,
    flow_types: Vec<FlowType>,
    standard_flow_types: Vec<FlowType>,
    sequences: BTreeMap<FlowType, &'static [&'static str]>,
    required_references: BTreeMap<FlowType, &'static [&'static str]>,
    extensible_steps: BTreeMap<FlowType, &'static [&'static str]>,
    triggers: [&'static str; 4],
    physical_document_issuance: Value,
}

async fn capabilities() -> Json<FlowCapabilities> {
    let flow_types = FlowType::all().collect::<Vec<_>>();
    let standard_flow_types = flow_types
        .iter()
        .copied()
        .filter(|flow_type| *flow_type != FlowType::Custom)
        .collect::<Vec<_>>();
    Json(FlowCapabilities {
        protocol_version: MIP_VERSION,
        sequences: FlowType::all()
            .filter(|flow_type| *flow_type != FlowType::Custom)
            .map(|flow_type| (flow_type, flow_type.sequence()))
            .collect(),
        required_references: FlowType::all()
            .map(|flow_type| (flow_type, flow_type.required_references()))
            .collect(),
        extensible_steps: FlowType::all()
            .filter_map(|flow_type| {
                let steps = extensible_steps(flow_type);
                (!steps.is_empty()).then_some((flow_type, steps))
            })
            .collect(),
        flow_types,
        standard_flow_types,
        triggers: ["API_CALL", "WEBHOOK", "SCHEDULE", "APPLICATION_SUBMITTED"],
        physical_document_issuance: json!({"supported": true, "blockers": []}),
    })
}

#[derive(Deserialize)]
struct DefinitionListQuery {
    organization_id: String,
    #[serde(default = "default_page_size")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

async fn list_definitions(
    State(state): State<FlowHttpState>,
    headers: HeaderMap,
    Query(query): Query<DefinitionListQuery>,
) -> Result<Json<Value>, FlowHttpError> {
    validate_page(query.limit)?;
    authorize(
        &state,
        &headers,
        &query.organization_id,
        "flow-definition:view",
    )
    .await?;
    let definitions = state
        .repository
        .definitions_for_tenant(&query.organization_id)
        .await?
        .into_iter()
        .skip(query.offset)
        .take(query.limit)
        .map(|record| record.projection())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(json!(definitions)))
}

async fn get_definition(
    State(state): State<FlowHttpState>,
    headers: HeaderMap,
    Path(flow_id): Path<String>,
) -> Result<Json<Value>, FlowHttpError> {
    let definition = state
        .repository
        .definition(&flow_id)
        .await?
        .ok_or_else(|| not_found("Flow Definition not found"))?;
    authorize(
        &state,
        &headers,
        &definition.organization_id,
        "flow-definition:view",
    )
    .await?;
    Ok(Json(json!(definition.projection()?)))
}

async fn delete_definition(
    State(state): State<FlowHttpState>,
    headers: HeaderMap,
    Path(flow_id): Path<String>,
) -> Result<Json<Value>, FlowHttpError> {
    let definition = state
        .repository
        .definition(&flow_id)
        .await?
        .ok_or_else(|| not_found("Flow Definition not found"))?;
    authorize(
        &state,
        &headers,
        &definition.organization_id,
        "flow-definition:delete",
    )
    .await?;
    if definition.status != crate::DefinitionStatus::Draft {
        return Err(FlowHttpError::new(
            StatusCode::BAD_REQUEST,
            "flow_definition_not_draft",
            "Only draft flows can be deleted",
        ));
    }
    if !state.repository.delete_definition(&flow_id).await? {
        return Err(not_found("Flow Definition not found"));
    }
    Ok(Json(json!({"success": true})))
}

#[derive(Deserialize)]
struct InstanceListQuery {
    organization_id: String,
    #[serde(default)]
    flow_definition_id: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default = "default_page_size")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

async fn list_instances(
    State(state): State<FlowHttpState>,
    headers: HeaderMap,
    Query(query): Query<InstanceListQuery>,
) -> Result<Json<Value>, FlowHttpError> {
    validate_page(query.limit)?;
    authorize(
        &state,
        &headers,
        &query.organization_id,
        "flow-instance:view",
    )
    .await?;
    let status = query.status.as_deref().map(parse_status).transpose()?;
    let instances = state
        .repository
        .instances_for_tenant(
            &query.organization_id,
            query.flow_definition_id.as_deref(),
            status,
        )
        .await?
        .into_iter()
        .skip(query.offset)
        .take(query.limit)
        .map(|record| record.projection())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(json!(instances)))
}

async fn get_instance(
    State(state): State<FlowHttpState>,
    headers: HeaderMap,
    Path(instance_id): Path<String>,
) -> Result<Json<Value>, FlowHttpError> {
    let instance = required_instance(&state, &instance_id).await?;
    authorize(
        &state,
        &headers,
        &instance.organization_id,
        "flow-instance:view",
    )
    .await?;
    Ok(Json(json!(instance.projection()?)))
}

async fn cancel_instance(
    State(state): State<FlowHttpState>,
    headers: HeaderMap,
    Path(instance_id): Path<String>,
) -> Result<Json<Value>, FlowHttpError> {
    let instance = required_instance(&state, &instance_id).await?;
    let principal = authorize(
        &state,
        &headers,
        &instance.organization_id,
        "flow-instance:cancel",
    )
    .await?;
    let mut kernel = instance.kernel()?;
    let now = chrono::Utc::now();
    kernel
        .transition_to(
            FlowInstanceStatus::Cancelled,
            Some(principal.clone()),
            Some("flow_cancelled".into()),
            u64::try_from(now.timestamp_millis()).map_err(|_| {
                FlowHttpError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "invalid_system_clock",
                    "System clock is invalid",
                )
            })?,
        )
        .map_err(|_| {
            FlowHttpError::new(
                StatusCode::BAD_REQUEST,
                "flow_already_ended",
                "Flow already ended",
            )
        })?;
    let cancelled = state
        .repository
        .cancel_instance(&instance_id, &principal, now)
        .await?
        .ok_or_else(|| {
            FlowHttpError::new(
                StatusCode::CONFLICT,
                "flow_already_ended",
                "Flow already ended",
            )
        })?;
    Ok(Json(json!(cancelled.projection()?)))
}

async fn get_result(
    State(state): State<FlowHttpState>,
    headers: HeaderMap,
    Path(instance_id): Path<String>,
) -> Result<Json<Value>, FlowHttpError> {
    let instance = required_instance(&state, &instance_id).await?;
    authorize(
        &state,
        &headers,
        &instance.organization_id,
        "flow-instance:view",
    )
    .await?;
    if !matches!(
        instance.status,
        FlowInstanceStatus::Completed | FlowInstanceStatus::Failed
    ) {
        return Err(FlowHttpError::new(
            StatusCode::CONFLICT,
            "verification_result_pending",
            "The verification transaction has no terminal result",
        ));
    }
    Ok(Json(json!(instance.verification_projection()?)))
}

#[derive(Deserialize)]
struct ArtifactListQuery {
    #[serde(default = "default_page_size")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

async fn list_artifacts(
    State(state): State<FlowHttpState>,
    headers: HeaderMap,
    Path(instance_id): Path<String>,
    Query(query): Query<ArtifactListQuery>,
) -> Result<Json<Value>, FlowHttpError> {
    validate_page(query.limit)?;
    let instance = required_instance(&state, &instance_id).await?;
    authorize(
        &state,
        &headers,
        &instance.organization_id,
        "flow-instance:view",
    )
    .await?;
    let artifacts = state
        .repository
        .artifacts_for_instance(&instance_id)
        .await?
        .into_iter()
        .skip(query.offset)
        .take(query.limit)
        .map(|record| record.projection())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(json!(artifacts)))
}

async fn get_artifact(
    State(state): State<FlowHttpState>,
    headers: HeaderMap,
    Path((instance_id, artifact_id)): Path<(String, String)>,
) -> Result<Json<Value>, FlowHttpError> {
    let artifact = state
        .repository
        .artifact_record(&artifact_id)
        .await?
        .filter(|artifact| artifact.flow_instance_id == instance_id)
        .ok_or_else(|| not_found("Artifact not found"))?;
    let instance = required_instance(&state, &instance_id).await?;
    authorize(
        &state,
        &headers,
        &instance.organization_id,
        "flow-instance:view",
    )
    .await?;
    Ok(Json(json!(artifact.projection()?)))
}

async fn required_instance(
    state: &FlowHttpState,
    instance_id: &str,
) -> Result<crate::FlowInstanceRecord, FlowHttpError> {
    state
        .repository
        .instance(instance_id)
        .await?
        .ok_or_else(|| not_found("Flow Instance not found"))
}

async fn authorize(
    state: &FlowHttpState,
    headers: &HeaderMap,
    organization_id: &str,
    permission: &str,
) -> Result<String, FlowHttpError> {
    let principal = headers
        .get("x-user-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            FlowHttpError::new(
                StatusCode::UNAUTHORIZED,
                "authentication_required",
                "X-User-ID header required",
            )
        })?;
    state
        .providers
        .authorize(principal, organization_id, permission, false)
        .await?;
    Ok(principal.to_owned())
}

fn validate_page(limit: usize) -> Result<(), FlowHttpError> {
    if (1..=MAXIMUM_PAGE_SIZE).contains(&limit) {
        Ok(())
    } else {
        Err(FlowHttpError::new(
            StatusCode::BAD_REQUEST,
            "invalid_pagination",
            "limit must be between 1 and 500",
        ))
    }
}

fn parse_status(value: &str) -> Result<FlowInstanceStatus, FlowHttpError> {
    serde_json::from_value(Value::String(value.trim().to_ascii_lowercase())).map_err(|_| {
        FlowHttpError::new(
            StatusCode::BAD_REQUEST,
            "invalid_status",
            "status is not a canonical Flow instance status",
        )
    })
}

const fn extensible_steps(flow_type: FlowType) -> &'static [&'static str] {
    match flow_type {
        FlowType::MdlIssuance | FlowType::ApplicationApprovalIssuance => {
            &["approval_decision", "deliver_credential"]
        }
        FlowType::PhysicalDocumentIssuance => &[
            "approval_decision",
            "submit_to_personalization",
            "quality_verify",
        ],
        _ => &[],
    }
}

const fn default_page_size() -> usize {
    DEFAULT_PAGE_SIZE
}

fn not_found(detail: &str) -> FlowHttpError {
    FlowHttpError::new(StatusCode::NOT_FOUND, "not_found", detail)
}

impl From<RepositoryError> for FlowHttpError {
    fn from(_error: RepositoryError) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "flow_repository_unavailable",
            "Flow persistence is unavailable",
        )
    }
}

impl From<FlowRecordError> for FlowHttpError {
    fn from(_error: FlowRecordError) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_stored_flow_state",
            "Stored Flow state is invalid",
        )
    }
}

impl From<FlowProviderError> for FlowHttpError {
    fn from(error: FlowProviderError) -> Self {
        let status = match error {
            FlowProviderError::Rejected { .. } => StatusCode::FORBIDDEN,
            FlowProviderError::NotFound { .. } => StatusCode::NOT_FOUND,
            FlowProviderError::Conflict { .. } => StatusCode::CONFLICT,
            FlowProviderError::InvalidResponse { .. }
            | FlowProviderError::Unavailable { .. }
            | FlowProviderError::Missing(_) => StatusCode::SERVICE_UNAVAILABLE,
        };
        Self::new(status, "flow_authorization_failed", error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    use super::*;

    fn router() -> Router {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://localhost/flow")
            .unwrap();
        flow_read_router(FlowHttpState {
            repository: PostgresFlowRepository::new(pool),
            providers: Arc::new(FlowProviderRegistry::default()),
        })
    }

    #[tokio::test]
    async fn capabilities_preserve_the_complete_mip_surface() {
        let response = router()
            .oneshot(
                Request::get("/v1/flows/capabilities")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["protocol_version"], MIP_VERSION);
        assert_eq!(value["flow_types"].as_array().unwrap().len(), 12);
        assert_eq!(value["standard_flow_types"].as_array().unwrap().len(), 11);
        assert_eq!(value["triggers"].as_array().unwrap().len(), 4);
        assert_eq!(value["physical_document_issuance"]["supported"], true);
        assert_eq!(value["extensible_steps"].as_object().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn protected_reads_reject_missing_identity_before_storage() {
        let response = router()
            .oneshot(
                Request::get("/v1/flows/definitions?organization_id=org-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn pagination_and_status_filters_are_bounded_and_canonical() {
        assert!(validate_page(1).is_ok());
        assert!(validate_page(500).is_ok());
        assert!(validate_page(0).is_err());
        assert!(validate_page(501).is_err());
        assert_eq!(
            parse_status("COMPLETED").unwrap(),
            FlowInstanceStatus::Completed
        );
        assert!(parse_status("waiting").is_err());
    }
}
