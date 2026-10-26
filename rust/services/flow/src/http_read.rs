use std::{collections::BTreeMap, sync::Arc};

use axum::{
    extract::{FromRequestParts, Path, Query},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use marty_verification::flow::{FlowInstanceStatus, TransitionOutcome};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    advance_instance_record, apply_physical_advance_side_effect, create_definition_record,
    definition_references, effective_flow_type, flow_application_routes, flow_verification_routes,
    parse_request, prepare_instance_start, prepare_oid4vci_retry, start_instance_record,
    start_physical_instance, update_definition_record, validate_definition_record,
    validated_client_key, AdvanceFlowRequest, CreateFlowDefinitionRequest, DefinitionStatus,
    FlowDefinitionMutationError, FlowInstanceExecutionError, FlowInstanceSideEffectError,
    FlowProviderError, FlowProviderRegistry, FlowRecordError, FlowType, PhysicalStartError,
    PostgresFlowRepository, RepositoryError, StartFlowRequest, UpdateFlowDefinitionRequest,
};

const MIP_VERSION: &str = "0.5.0";
const DEFAULT_PAGE_SIZE: usize = 100;
const MAXIMUM_PAGE_SIZE: usize = 500;

#[derive(Clone)]
pub struct FlowHttpState {
    pub service_authenticator: Option<Arc<mmf_security::ServiceTokenAuthenticator>>,
    pub repository: PostgresFlowRepository,
    pub providers: Arc<FlowProviderRegistry>,
    pub public_base_url: String,
    pub verification: crate::FlowHttpVerificationOptions,
    pub application_approval: crate::FlowHttpApplicationApprovalOptions,
}

pub(crate) struct FlowRequestState(pub FlowHttpState);

impl FromRequestParts<FlowHttpState> for FlowRequestState {
    type Rejection = FlowHttpError;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &FlowHttpState,
    ) -> Result<Self, Self::Rejection> {
        let mut scoped = state.clone();
        if parts.headers.contains_key("x-api-key-id")
            || parts.headers.contains_key("x-api-key-scopes")
        {
            authenticate_gateway_service(state, &parts.headers)?;
            let header = |name: &str| {
                parts
                    .headers
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .map(str::trim)
                    .unwrap_or_default()
            };
            let actor = marty_api_key_policy::GatewayApiKeyActor::parse(
                header("x-api-key-id"),
                header("x-organization-id"),
                header("x-api-key-scopes"),
            )
            .map_err(|_| {
                FlowHttpError::new(
                    StatusCode::UNAUTHORIZED,
                    "authentication_required",
                    "Invalid gateway principal",
                )
            })?;
            let mut providers = state.providers.as_ref().clone();
            providers.gateway_api_key_actor = Some(actor);
            scoped.providers = Arc::new(providers);
        }
        Ok(Self(scoped))
    }
}

fn authenticate_gateway_service(
    state: &FlowHttpState,
    headers: &HeaderMap,
) -> Result<(), FlowHttpError> {
    let authenticator = state.service_authenticator.as_ref().ok_or_else(|| {
        FlowHttpError::new(
            StatusCode::UNAUTHORIZED,
            "service_authentication_required",
            "Gateway service authentication required",
        )
    })?;
    authenticator
        .authenticate(
            headers
                .get("x-service-token")
                .and_then(|value| value.to_str().ok()),
        )
        .map_err(|_| {
            FlowHttpError::new(
                StatusCode::UNAUTHORIZED,
                "service_authentication_required",
                "Gateway service authentication required",
            )
        })
}

pub fn flow_read_router(state: FlowHttpState) -> Router {
    Router::new()
        .route(
            "/internal/v1/resource-owners/flows/definitions/{flow_id}",
            get(definition_owner),
        )
        .route(
            "/internal/v1/resource-owners/flows/instances/{instance_id}",
            get(instance_owner),
        )
        .route("/v1/flows/capabilities", get(capabilities))
        .route(
            "/v1/flows/definitions",
            get(list_definitions).post(create_definition),
        )
        .route(
            "/v1/flows/definitions/{flow_id}",
            get(get_definition)
                .patch(update_definition)
                .delete(delete_definition),
        )
        .route(
            "/v1/flows/definitions/{flow_id}/validate",
            post(validate_definition),
        )
        .route(
            "/v1/flows/definitions/{flow_id}/test",
            post(test_definition),
        )
        .route(
            "/v1/flows/definitions/{flow_id}/activate",
            post(activate_definition),
        )
        .route(
            "/v1/flows/instances",
            get(list_instances).post(start_instance),
        )
        .route(
            "/v1/flows/physical-start-intents",
            get(list_pending_physical_starts),
        )
        .route("/v1/flows/instances/{instance_id}", get(get_instance))
        .route(
            "/v1/flows/instances/{instance_id}/advance",
            post(advance_instance),
        )
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
        .route(
            "/v1/flows/instances/{instance_id}/generate-qr",
            post(generate_qr),
        )
        .merge(flow_application_routes())
        .merge(flow_verification_routes())
        .with_state(state)
}

async fn definition_owner(
    FlowRequestState(state): FlowRequestState,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, FlowHttpError> {
    authenticate_gateway_service(&state, &headers)?;
    let definition = state
        .repository
        .definition(&id)
        .await?
        .ok_or_else(|| not_found("Flow Definition not found"))?;
    Ok(Json(
        json!({"id": definition.id, "organization_id": definition.organization_id}),
    ))
}

async fn instance_owner(
    FlowRequestState(state): FlowRequestState,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, FlowHttpError> {
    authenticate_gateway_service(&state, &headers)?;
    let instance = required_instance(&state, &id).await?;
    Ok(Json(
        json!({"id": instance.id, "organization_id": instance.organization_id}),
    ))
}

#[derive(Debug, Serialize)]
struct FlowHttpErrorBody {
    error: &'static str,
    detail: Value,
}

#[derive(Debug)]
pub(crate) struct FlowHttpError {
    status: StatusCode,
    code: &'static str,
    detail: Value,
}

impl FlowHttpError {
    pub(crate) fn new(status: StatusCode, code: &'static str, detail: impl Into<Value>) -> Self {
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
    FlowRequestState(state): FlowRequestState,
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

async fn create_definition(
    FlowRequestState(state): FlowRequestState,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, FlowHttpError> {
    let request: CreateFlowDefinitionRequest = parse_request(payload)?;
    let principal = authorize(
        &state,
        &headers,
        &request.organization_id,
        "flow-definition:create",
    )
    .await?;
    let record = create_definition_record(request, chrono::Utc::now())?;
    crate::validate_definition_references(
        &state.providers,
        &principal,
        &record.organization_id,
        &definition_references(&record),
        false,
    )
    .await?;
    state.repository.save_definition(&record).await?;
    Ok(Json(json!(record.projection()?)))
}

async fn get_definition(
    FlowRequestState(state): FlowRequestState,
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

async fn update_definition(
    FlowRequestState(state): FlowRequestState,
    headers: HeaderMap,
    Path(flow_id): Path<String>,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, FlowHttpError> {
    let existing = state
        .repository
        .definition(&flow_id)
        .await?
        .ok_or_else(|| not_found("Flow Definition not found"))?;
    if existing.status == DefinitionStatus::Archived {
        return Err(FlowHttpError::new(
            StatusCode::BAD_REQUEST,
            "flow_definition_archived",
            "Archived flow definitions cannot be updated",
        ));
    }
    let principal = authorize(
        &state,
        &headers,
        &existing.organization_id,
        "flow-definition:edit",
    )
    .await?;
    let request: UpdateFlowDefinitionRequest = parse_request(payload)?;
    let record = update_definition_record(&existing, request, chrono::Utc::now())?;
    crate::validate_definition_references(
        &state.providers,
        &principal,
        &record.organization_id,
        &definition_references(&record),
        false,
    )
    .await?;
    state.repository.save_definition(&record).await?;
    Ok(Json(json!(record.projection()?)))
}

async fn validate_definition(
    FlowRequestState(state): FlowRequestState,
    headers: HeaderMap,
    Path(flow_id): Path<String>,
) -> Result<Json<Value>, FlowHttpError> {
    let definition = state
        .repository
        .definition(&flow_id)
        .await?
        .ok_or_else(|| not_found("Flow Definition not found"))?;
    let principal = authorize(
        &state,
        &headers,
        &definition.organization_id,
        "flow-definition:view",
    )
    .await?;
    Ok(Json(json!(
        validate_definition_record(&state.providers, &principal, &definition).await
    )))
}

async fn test_definition(
    FlowRequestState(state): FlowRequestState,
    headers: HeaderMap,
    Path(flow_id): Path<String>,
) -> Result<Json<Value>, FlowHttpError> {
    let definition = state
        .repository
        .definition(&flow_id)
        .await?
        .ok_or_else(|| not_found("Flow Definition not found"))?;
    let principal = authorize(
        &state,
        &headers,
        &definition.organization_id,
        "flow-definition:view",
    )
    .await?;
    let validation = validate_definition_record(&state.providers, &principal, &definition).await;
    let would_execute = if validation.valid {
        validation.resolved_steps.clone()
    } else {
        Vec::new()
    };
    let mut response = serde_json::to_value(validation).map_err(|_| {
        FlowHttpError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "flow_serialization_failed",
            "Flow validation could not be serialized",
        )
    })?;
    let object = response.as_object_mut().ok_or_else(|| {
        FlowHttpError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "flow_serialization_failed",
            "Flow validation could not be serialized",
        )
    })?;
    object.insert("mode".into(), json!("DRY_RUN"));
    object.insert("would_execute".into(), json!(would_execute));
    object.insert("side_effects_executed".into(), json!(false));
    Ok(Json(response))
}

async fn activate_definition(
    FlowRequestState(state): FlowRequestState,
    headers: HeaderMap,
    Path(flow_id): Path<String>,
) -> Result<Json<Value>, FlowHttpError> {
    let mut definition = state
        .repository
        .definition(&flow_id)
        .await?
        .ok_or_else(|| not_found("Flow Definition not found"))?;
    let principal = authorize(
        &state,
        &headers,
        &definition.organization_id,
        "flow-definition:activate",
    )
    .await?;
    let validation = validate_definition_record(&state.providers, &principal, &definition).await;
    if !validation.valid {
        return Err(FlowHttpError::new(
            StatusCode::BAD_REQUEST,
            "flow_validation_failed",
            json!({
                "message": "Flow validation failed; resolve all blockers before activation.",
                "valid": validation.valid,
                "errors": validation.errors,
                "warnings": validation.warnings,
                "resolved_dependencies": validation.resolved_dependencies,
                "resolved_steps": validation.resolved_steps
            }),
        ));
    }
    definition.status = DefinitionStatus::Active;
    definition.updated_at = chrono::Utc::now();
    state.repository.save_definition(&definition).await?;
    Ok(Json(json!(definition.projection()?)))
}

async fn delete_definition(
    FlowRequestState(state): FlowRequestState,
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
    FlowRequestState(state): FlowRequestState,
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

#[derive(Deserialize)]
struct PendingPhysicalStartsQuery {
    organization_id: String,
    #[serde(default = "default_page_size")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

async fn list_pending_physical_starts(
    FlowRequestState(state): FlowRequestState,
    headers: HeaderMap,
    Query(query): Query<PendingPhysicalStartsQuery>,
) -> Result<Json<Value>, FlowHttpError> {
    validate_page(query.limit)?;
    authorize(
        &state,
        &headers,
        &query.organization_id,
        "flow-instance:view",
    )
    .await?;
    let pending = state
        .repository
        .pending_physical_starts(
            &query.organization_id,
            i64::try_from(query.limit).map_err(|_| {
                FlowHttpError::new(
                    StatusCode::BAD_REQUEST,
                    "page_invalid",
                    "Page size is invalid",
                )
            })?,
            i64::try_from(query.offset).map_err(|_| {
                FlowHttpError::new(StatusCode::BAD_REQUEST, "page_invalid", "Offset is invalid")
            })?,
        )
        .await?;
    Ok(Json(json!(pending
        .into_iter()
        .map(|item| json!({
            "flow_instance_id": item.instance_id,
            "flow_definition_id": item.flow_definition_id,
            "created_at": item.created_at,
            "recovery": if item.key_source == "generated" {
                "original_input_and_flow_instance_id_as_idempotency_key_required"
            } else {
                "original_input_and_original_idempotency_key_required"
            },
        }))
        .collect::<Vec<_>>())))
}

fn physical_start_header_key(headers: &HeaderMap) -> Result<Option<&str>, FlowHttpError> {
    let mut values = headers.get_all("idempotency-key").iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(PhysicalStartError::InvalidKey.into());
    }
    let raw = first
        .map(|value| value.to_str().map_err(|_| PhysicalStartError::InvalidKey))
        .transpose()?;
    validated_client_key(raw).map_err(Into::into)
}

#[cfg(test)]
mod physical_start_header_tests {
    use super::*;

    #[test]
    fn physical_http_start_rejects_duplicate_or_ambiguous_keys() {
        let mut headers = HeaderMap::new();
        assert_eq!(physical_start_header_key(&headers).unwrap(), None);
        headers.append("idempotency-key", "owned-1".parse().unwrap());
        assert_eq!(
            physical_start_header_key(&headers).unwrap(),
            Some("owned-1")
        );
        headers.append("idempotency-key", "owned-2".parse().unwrap());
        assert!(physical_start_header_key(&headers).is_err());
        headers.remove("idempotency-key");
        headers.append("idempotency-key", "owned-1,owned-2".parse().unwrap());
        assert!(physical_start_header_key(&headers).is_err());
    }
}

async fn start_instance(
    FlowRequestState(state): FlowRequestState,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, FlowHttpError> {
    let request: StartFlowRequest = parse_request(payload)?;
    let definition = state
        .repository
        .definition(&request.flow_definition_id)
        .await?
        .filter(|definition| definition.organization_id == request.organization_id)
        .ok_or_else(|| not_found("Flow Definition not found"))?;
    let principal = authorize(
        &state,
        &headers,
        &definition.organization_id,
        "flow-instance:start",
    )
    .await?;
    let now = chrono::Utc::now();
    if effective_flow_type(&definition) == FlowType::PhysicalDocumentIssuance {
        let key = physical_start_header_key(&headers)?;
        let result = start_physical_instance(
            &state.repository,
            &state.providers,
            &definition,
            request,
            &principal,
            &state.public_base_url,
            now,
            key,
        )
        .await?;
        return Ok(Json(json!(result.instance.projection()?)));
    }
    let instance = start_instance_record(&definition, request, &principal, now)?;
    let prepared = prepare_instance_start(
        &state.providers,
        &definition,
        instance,
        &state.public_base_url,
        now,
    )
    .await?;
    if !state
        .repository
        .save_started_instance(&prepared.instance, prepared.artifact.as_ref())
        .await?
    {
        return Err(FlowHttpError::new(
            StatusCode::CONFLICT,
            "flow_instance_start_conflict",
            "Flow instance or protocol artifact already exists",
        ));
    }
    Ok(Json(json!(prepared.instance.projection()?)))
}

async fn get_instance(
    FlowRequestState(state): FlowRequestState,
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

async fn advance_instance(
    FlowRequestState(state): FlowRequestState,
    headers: HeaderMap,
    Path(instance_id): Path<String>,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, FlowHttpError> {
    let current = required_instance(&state, &instance_id).await?;
    let principal = authorize(
        &state,
        &headers,
        &current.organization_id,
        "flow-instance:advance",
    )
    .await?;
    let definition = state
        .repository
        .definition(&current.flow_definition_id)
        .await?
        .ok_or_else(|| not_found("Flow Definition not found"))?;
    let request: AdvanceFlowRequest = parse_request(payload)?;
    let outcome: TransitionOutcome = serde_json::from_value(Value::String(
        request.step_result.trim().to_ascii_lowercase(),
    ))
    .map_err(|_| {
        FlowHttpError::new(
            StatusCode::BAD_REQUEST,
            "flow_invalid_step_result",
            "step_result is not a supported transition outcome",
        )
    })?;
    let expected_status = current.status;
    let expected_updated_at = current.updated_at;
    let side_effected = apply_physical_advance_side_effect(
        &state.providers,
        &definition,
        current,
        outcome,
        &request.data,
    )
    .await?;
    let now = chrono::Utc::now();
    let advanced = advance_instance_record(&definition, &side_effected, request, &principal, now)?;
    if !state
        .repository
        .compare_and_swap_instance(&advanced, expected_status, expected_updated_at)
        .await?
    {
        return Err(FlowHttpError::new(
            StatusCode::CONFLICT,
            "flow_instance_advance_conflict",
            "Flow instance changed before this advancement could be committed",
        ));
    }
    Ok(Json(json!(advanced.projection()?)))
}

async fn cancel_instance(
    FlowRequestState(state): FlowRequestState,
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
    FlowRequestState(state): FlowRequestState,
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
    FlowRequestState(state): FlowRequestState,
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
    FlowRequestState(state): FlowRequestState,
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

async fn generate_qr(
    FlowRequestState(state): FlowRequestState,
    headers: HeaderMap,
    Path(instance_id): Path<String>,
) -> Result<Json<Value>, FlowHttpError> {
    let current = required_instance(&state, &instance_id).await?;
    authorize(
        &state,
        &headers,
        &current.organization_id,
        "flow-instance:advance",
    )
    .await?;
    let definition = state
        .repository
        .definition(&current.flow_definition_id)
        .await?
        .ok_or_else(|| not_found("Flow Definition not found"))?;
    let existing = state
        .repository
        .artifacts_for_instance(&instance_id)
        .await?;
    let attempt_number = existing
        .iter()
        .map(|artifact| artifact.attempt_number)
        .max()
        .unwrap_or(1)
        .checked_add(1)
        .ok_or_else(|| {
            FlowHttpError::new(
                StatusCode::CONFLICT,
                "flow_artifact_attempt_limit",
                "Flow artifact attempt counter is exhausted",
            )
        })?;
    let expected_updated_at = current.updated_at;
    let now = chrono::Utc::now().max(expected_updated_at + chrono::Duration::microseconds(1));
    let prepared = prepare_oid4vci_retry(
        &state.providers,
        &definition,
        current,
        &state.public_base_url,
        now,
        attempt_number,
    )
    .await?;
    let artifact = prepared.artifact.ok_or_else(|| {
        FlowHttpError::new(
            StatusCode::BAD_GATEWAY,
            "flow_artifact_generation_failed",
            "OID4VCI artifact was not generated",
        )
    })?;
    if !state
        .repository
        .replace_active_artifacts(&prepared.instance, &artifact, expected_updated_at, now)
        .await?
    {
        return Err(FlowHttpError::new(
            StatusCode::CONFLICT,
            "flow_artifact_generation_conflict",
            "Flow instance changed before the replacement artifact could be committed",
        ));
    }
    Ok(Json(json!(artifact.projection()?)))
}

pub(crate) async fn required_instance(
    state: &FlowHttpState,
    instance_id: &str,
) -> Result<crate::FlowInstanceRecord, FlowHttpError> {
    state
        .repository
        .instance(instance_id)
        .await?
        .ok_or_else(|| not_found("Flow Instance not found"))
}

pub(crate) async fn authorize(
    state: &FlowHttpState,
    headers: &HeaderMap,
    organization_id: &str,
    permission: &str,
) -> Result<String, FlowHttpError> {
    if let Some(actor) = &state.providers.gateway_api_key_actor {
        let principal = actor.principal_id();
        state
            .providers
            .authorize(&principal, organization_id, permission, false)
            .await?;
        return Ok(principal);
    }
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
    fn from(error: RepositoryError) -> Self {
        if matches!(error, RepositoryError::PhysicalStartKeyConflict) {
            return Self::new(
                StatusCode::CONFLICT,
                "physical_start_key_conflict",
                "Idempotency-Key is bound to another physical Flow request",
            );
        }
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "flow_repository_unavailable",
            "Flow persistence is unavailable",
        )
    }
}

impl From<PhysicalStartError> for FlowHttpError {
    fn from(error: PhysicalStartError) -> Self {
        match error {
            PhysicalStartError::InvalidKey => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "physical_start_key_invalid",
                "Idempotency-Key is invalid",
            ),
            PhysicalStartError::InProgress => Self::new(
                StatusCode::CONFLICT,
                "physical_start_in_progress",
                "Physical Flow start is in progress",
            ),
            PhysicalStartError::Conflict => Self::new(
                StatusCode::CONFLICT,
                "physical_start_conflict",
                "Physical Flow start identity changed",
            ),
            PhysicalStartError::StoredIncomplete => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "physical_start_incomplete",
                "Stored physical Flow start is incomplete",
            ),
            PhysicalStartError::Execution(error) => error.into(),
            PhysicalStartError::SideEffect(error) => error.into(),
            PhysicalStartError::Repository(error) => error.into(),
        }
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
        let reference_validation = matches!(
            &error,
            FlowProviderError::Rejected {
                provider: "reference_validation",
                ..
            }
        );
        let status = match error {
            FlowProviderError::Rejected { .. } if reference_validation => StatusCode::BAD_REQUEST,
            FlowProviderError::Rejected { .. } => StatusCode::FORBIDDEN,
            FlowProviderError::NotFound { .. } => StatusCode::NOT_FOUND,
            FlowProviderError::Conflict { .. } => StatusCode::CONFLICT,
            FlowProviderError::InvalidResponse { .. }
            | FlowProviderError::Unavailable { .. }
            | FlowProviderError::Missing(_) => StatusCode::SERVICE_UNAVAILABLE,
        };
        let code = if reference_validation {
            "flow_reference_invalid"
        } else {
            "flow_authorization_failed"
        };
        Self::new(status, code, error.to_string())
    }
}

impl From<crate::FlowApiError> for FlowHttpError {
    fn from(error: crate::FlowApiError) -> Self {
        Self::new(StatusCode::BAD_REQUEST, error.code, error.to_string())
    }
}

impl From<FlowDefinitionMutationError> for FlowHttpError {
    fn from(error: FlowDefinitionMutationError) -> Self {
        match error {
            FlowDefinitionMutationError::Api(error) => error.into(),
            FlowDefinitionMutationError::Domain(error) => Self::new(
                StatusCode::BAD_REQUEST,
                "flow_definition_invalid",
                error.to_string(),
            ),
            FlowDefinitionMutationError::Stored(_) => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid_stored_flow_state",
                "Stored Flow state is invalid",
            ),
            FlowDefinitionMutationError::Serialization(_) => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "flow_serialization_failed",
                "Flow state could not be serialized",
            ),
        }
    }
}

impl From<FlowInstanceExecutionError> for FlowHttpError {
    fn from(error: FlowInstanceExecutionError) -> Self {
        match error {
            FlowInstanceExecutionError::Api(error) => error.into(),
            FlowInstanceExecutionError::Record(_) => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid_stored_flow_state",
                "Stored Flow state is invalid",
            ),
            FlowInstanceExecutionError::DefinitionTenantMismatch => {
                not_found("Flow Definition not found")
            }
            FlowInstanceExecutionError::NotAdvanceable(_) => Self::new(
                StatusCode::CONFLICT,
                "flow_instance_not_advanceable",
                error.to_string(),
            ),
            _ => Self::new(
                StatusCode::BAD_REQUEST,
                "flow_instance_operation_invalid",
                error.to_string(),
            ),
        }
    }
}

impl From<FlowInstanceSideEffectError> for FlowHttpError {
    fn from(error: FlowInstanceSideEffectError) -> Self {
        match error {
            FlowInstanceSideEffectError::Provider(error) => error.into(),
            FlowInstanceSideEffectError::InvalidContext(_) => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "flow_instance_context_invalid",
                error.to_string(),
            ),
            FlowInstanceSideEffectError::InvalidResponse(_)
            | FlowInstanceSideEffectError::Protocol(_)
            | FlowInstanceSideEffectError::InvalidClock => Self::new(
                StatusCode::BAD_GATEWAY,
                "flow_instance_side_effect_failed",
                error.to_string(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    use super::*;

    fn state() -> FlowHttpState {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://localhost/flow")
            .unwrap();
        FlowHttpState {
            service_authenticator: None,
            repository: PostgresFlowRepository::new(pool),
            providers: Arc::new(FlowProviderRegistry::default()),
            public_base_url: "http://localhost:8000".into(),
            verification: crate::FlowHttpVerificationOptions::default(),
            application_approval: crate::FlowHttpApplicationApprovalOptions::default(),
        }
    }

    fn router() -> Router {
        flow_read_router(state())
    }

    #[tokio::test]
    async fn owner_projections_require_service_identity_before_storage_access() {
        let mut configured = state();
        configured.service_authenticator = Some(Arc::new(
            mmf_security::ServiceTokenAuthenticator::new(Some("s".repeat(32)), true).unwrap(),
        ));
        let app = flow_read_router(configured);
        for kind in ["definitions", "instances"] {
            for token in ["", "wrong"] {
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .uri(format!(
                                "/internal/v1/resource-owners/flows/{kind}/never-query-storage"
                            ))
                            .header("x-service-token", token)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            }
        }
    }

    #[tokio::test]
    async fn gateway_key_context_is_service_authenticated_request_local_and_scope_bound() {
        const KEY: &str = "10000000-0000-4000-8000-000000000001";
        const ORG: &str = "20000000-0000-4000-8000-000000000001";
        let mut original = state();
        let token = "s".repeat(32);
        original.service_authenticator = Some(Arc::new(
            mmf_security::ServiceTokenAuthenticator::new(Some(token.clone()), true).unwrap(),
        ));
        for (supplied, key, expected) in [
            ("", KEY, false),
            ("wrong", KEY, false),
            (token.as_str(), "malformed", false),
            (token.as_str(), KEY, true),
        ] {
            let (mut parts, _) = Request::builder()
                .header("x-service-token", supplied)
                .header("x-api-key-id", key)
                .header("x-api-key-scopes", "flows:read")
                .header("x-organization-id", ORG)
                .body(Body::empty())
                .unwrap()
                .into_parts();
            let scoped = FlowRequestState::from_request_parts(&mut parts, &original).await;
            if !expected {
                assert_eq!(scoped.err().unwrap().status, StatusCode::UNAUTHORIZED);
                continue;
            }
            let FlowRequestState(scoped) = scoped.unwrap();
            assert!(original.providers.gateway_api_key_actor.is_none());
            assert!(!Arc::ptr_eq(&scoped.providers, &original.providers));
            assert_eq!(
                authorize(&scoped, &parts.headers, ORG, "flow-definition:view")
                    .await
                    .unwrap(),
                KEY
            );
            assert_eq!(
                authorize(&scoped, &parts.headers, ORG, "flow-definition:create")
                    .await
                    .unwrap_err()
                    .status,
                StatusCode::FORBIDDEN
            );
            assert_eq!(
                authorize(
                    &scoped,
                    &parts.headers,
                    "20000000-0000-4000-8000-000000000002",
                    "flow-definition:view"
                )
                .await
                .unwrap_err()
                .status,
                StatusCode::FORBIDDEN
            );
            assert!(scoped
                .providers
                .authorize(KEY, ORG, "flow-definition:view", true)
                .await
                .is_err());
        }
        // No configured service credential means no key-actor assertions are accepted.
        original.service_authenticator = None;
        let (mut parts, _) = Request::builder()
            .header("x-api-key-id", KEY)
            .header("x-api-key-scopes", "admin:full")
            .header("x-organization-id", ORG)
            .body(Body::empty())
            .unwrap()
            .into_parts();
        assert_eq!(
            FlowRequestState::from_request_parts(&mut parts, &original)
                .await
                .err()
                .unwrap()
                .status,
            StatusCode::UNAUTHORIZED
        );
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
