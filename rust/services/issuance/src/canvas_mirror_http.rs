//! Native HTTP owner for the frozen Canvas mirror management surface.

use axum::{
    extract::{Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use mmf_config::numeric_config::PythonConfigInteger;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::{
    canvas_mirror_service::{
        CanvasMirrorProvenanceSelector, CanvasMirrorService, CanvasMirrorServiceError,
    },
    management_http::header,
    management_security::ManagementSecurity,
    transaction_reads::TransactionReadError,
};

const API_KEY_HEADER: &str = "x-api-key";
const ORGANIZATION_HEADER: &str = "x-organization-id";

pub trait CanvasMirrorHttpClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCanvasMirrorHttpClock;

impl CanvasMirrorHttpClock for SystemCanvasMirrorHttpClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Clone)]
struct CanvasMirrorHttpState {
    service: CanvasMirrorService,
    security: ManagementSecurity,
    clock: Arc<dyn CanvasMirrorHttpClock>,
}

#[derive(Clone)]
pub struct CanvasMirrorHttpService {
    service: CanvasMirrorService,
    api_key: Option<String>,
}

impl CanvasMirrorHttpService {
    #[must_use]
    pub fn new(service: CanvasMirrorService, api_key: Option<&str>) -> Self {
        Self {
            service,
            api_key: api_key.map(str::to_owned),
        }
    }

    pub fn into_router(self) -> Router {
        router(self.service, self.api_key.as_deref())
    }
}

impl std::fmt::Debug for CanvasMirrorHttpService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasMirrorHttpService")
            .field("api_key_configured", &self.api_key.is_some())
            .finish_non_exhaustive()
    }
}

pub fn router(service: CanvasMirrorService, api_key: Option<&str>) -> Router {
    router_with_clock(service, api_key, Arc::new(SystemCanvasMirrorHttpClock))
}

pub fn router_with_clock(
    service: CanvasMirrorService,
    api_key: Option<&str>,
    clock: Arc<dyn CanvasMirrorHttpClock>,
) -> Router {
    let state = CanvasMirrorHttpState {
        service,
        security: ManagementSecurity::new(api_key),
        clock,
    };
    Router::new()
        .route(
            "/v1/issued-credentials/{credential_id}/deliveries/canvas-credentials/publish",
            post(publish),
        )
        .route(
            "/v1/issuance/delivery-records/canvas-credentials/process-pending",
            post(process_pending),
        )
        .route(
            "/v1/issuance/delivery-records/canvas-credentials/process-status-sync-failures",
            post(process_status_sync_failures),
        )
        .route(
            "/v1/issuance/delivery-records/canvas-credentials/run-automation-cycle",
            post(run_automation_cycle),
        )
        .route(
            "/v1/issuance/organizations/{organization_id}/canvas-mirror-health",
            get(health),
        )
        .route(
            "/v1/issuance/delivery-records/canvas-credentials/provenance",
            get(provenance),
        )
        .with_state(state)
}

async fn publish(
    State(state): State<CanvasMirrorHttpState>,
    Path(credential_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = authorize(&state, &headers) {
        return authentication_error(error);
    }
    match state
        .service
        .publish_admitted(
            &credential_id,
            header(&headers, ORGANIZATION_HEADER),
            state.clock.now(),
        )
        .await
    {
        Ok(record) if record.status == "delivered" => {
            (StatusCode::OK, Json(record.public_projection())).into_response()
        }
        Ok(record) => {
            let detail = record
                .last_error
                .as_deref()
                .unwrap_or("Canvas Credentials publish failed");
            let normalized = detail.to_ascii_lowercase();
            let status = if ["missing", "not found", "disabled", "no canvas mirror"]
                .iter()
                .any(|token| normalized.contains(token))
            {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_GATEWAY
            };
            detail_response(status, detail)
        }
        Err(error) => publish_error(error),
    }
}

async fn process_pending(
    State(state): State<CanvasMirrorHttpState>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = authorize(&state, &headers) {
        return authentication_error(error);
    }
    let query = match BatchQuery::parse(raw_query.as_deref(), false) {
        Ok(query) => query,
        Err(error) => return error.into_response(),
    };
    result_json(
        state
            .service
            .process_pending(
                query.organization_id.as_deref(),
                query.limit,
                query.retry_failed,
                state.clock.now(),
            )
            .await,
    )
}

async fn process_status_sync_failures(
    State(state): State<CanvasMirrorHttpState>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = authorize(&state, &headers) {
        return authentication_error(error);
    }
    let query = match BatchQuery::parse(raw_query.as_deref(), false) {
        Ok(query) => query,
        Err(error) => return error.into_response(),
    };
    result_json(
        state
            .service
            .process_status_sync_failures(
                query.organization_id.as_deref(),
                query.limit,
                state.clock.now(),
            )
            .await,
    )
}

async fn run_automation_cycle(
    State(state): State<CanvasMirrorHttpState>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = authorize(&state, &headers) {
        return authentication_error(error);
    }
    let query = match BatchQuery::parse(raw_query.as_deref(), true) {
        Ok(query) => query,
        Err(error) => return error.into_response(),
    };
    let started_at = state.clock.now();
    result_json(
        state
            .service
            .run_automation_cycle(
                query.organization_id.as_deref(),
                query.limit,
                query.retry_failed,
                started_at,
                state.clock.now(),
            )
            .await,
    )
}

async fn health(
    State(state): State<CanvasMirrorHttpState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = authorize(&state, &headers) {
        return authentication_error(error);
    }
    result_json(state.service.health(&organization_id).await)
}

async fn provenance(
    State(state): State<CanvasMirrorHttpState>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = authorize(&state, &headers) {
        return authentication_error(error);
    }
    let query = match ProvenanceQuery::parse(raw_query.as_deref()) {
        Ok(query) => query,
        Err(error) => return error.into_response(),
    };
    let trusted = header(&headers, ORGANIZATION_HEADER)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(trusted) = trusted else {
        return detail_response(
            StatusCode::FORBIDDEN,
            "Trusted organization context is required",
        );
    };
    if !mmf_security::constant_time_secret_eq(trusted.as_bytes(), query.organization_id.as_bytes())
    {
        return detail_response(
            StatusCode::FORBIDDEN,
            "Organization context does not match requested organization",
        );
    }
    result_json(
        state
            .service
            .provenance(
                &query.organization_id,
                CanvasMirrorProvenanceSelector {
                    delivery_record_id: query.delivery_record_id,
                    external_credential_id: query.external_credential_id,
                    credential_id: query.credential_id,
                    canvas_account_id: query.canvas_account_id,
                },
                state.clock.now(),
            )
            .await,
    )
}

fn authorize(
    state: &CanvasMirrorHttpState,
    headers: &HeaderMap,
) -> Result<(), TransactionReadError> {
    state.security.authorize(header(headers, API_KEY_HEADER))
}

fn authentication_error(error: TransactionReadError) -> Response {
    match error {
        TransactionReadError::ApiKeyNotConfigured => detail_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "ISSUANCE_API_KEY not configured on server",
        ),
        TransactionReadError::ApiKeyMissing => {
            detail_response(StatusCode::UNAUTHORIZED, "X-API-Key header is missing")
        }
        TransactionReadError::InvalidApiKey => {
            detail_response(StatusCode::UNAUTHORIZED, "Invalid API Key")
        }
        _ => internal_error(),
    }
}

fn result_json(result: Result<Value, CanvasMirrorServiceError>) -> Response {
    match result {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(error) => service_error(error),
    }
}

fn publish_error(error: CanvasMirrorServiceError) -> Response {
    match error {
        CanvasMirrorServiceError::NotFound => {
            detail_response(StatusCode::NOT_FOUND, "Issued credential not found")
        }
        CanvasMirrorServiceError::TrustedOrganizationRequired => detail_response(
            StatusCode::FORBIDDEN,
            "Trusted organization context is required",
        ),
        CanvasMirrorServiceError::TransactionNotFound => detail_response(
            StatusCode::NOT_FOUND,
            "Issuance transaction not found for credential",
        ),
        CanvasMirrorServiceError::DeliveryNotFound => detail_response(
            StatusCode::CONFLICT,
            "No Canvas mirror delivery record exists for this credential",
        ),
        CanvasMirrorServiceError::DeliveryInProgress => detail_response(
            StatusCode::CONFLICT,
            "Canvas mirror delivery is already being processed",
        ),
        _ => internal_error(),
    }
}

fn service_error(error: CanvasMirrorServiceError) -> Response {
    match error {
        CanvasMirrorServiceError::SelectorRequired => detail_response(
            StatusCode::BAD_REQUEST,
            "Provide delivery_record_id, external_credential_id, or credential_id",
        ),
        CanvasMirrorServiceError::NotFound => detail_response(
            StatusCode::NOT_FOUND,
            "Canvas mirror delivery record not found",
        ),
        CanvasMirrorServiceError::CanonicalCredentialMissing => detail_response(
            StatusCode::CONFLICT,
            "Canonical issued credential not found for Canvas mirror record",
        ),
        _ => internal_error(),
    }
}

fn detail_response(status: StatusCode, detail: &str) -> Response {
    (status, Json(json!({"detail": detail}))).into_response()
}

fn internal_error() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
}

#[derive(Debug)]
struct BatchQuery {
    organization_id: Option<String>,
    limit: u32,
    retry_failed: bool,
}

impl BatchQuery {
    fn parse(raw_query: Option<&str>, retry_default: bool) -> Result<Self, QueryValidationError> {
        Ok(Self {
            organization_id: query_value(raw_query, "organization_id"),
            limit: parse_limit(query_value(raw_query, "limit"))?,
            retry_failed: parse_bool(
                "retry_failed",
                query_value(raw_query, "retry_failed"),
                retry_default,
            )?,
        })
    }
}

struct ProvenanceQuery {
    organization_id: String,
    delivery_record_id: Option<String>,
    external_credential_id: Option<String>,
    credential_id: Option<String>,
    canvas_account_id: Option<String>,
}

impl ProvenanceQuery {
    fn parse(raw_query: Option<&str>) -> Result<Self, QueryValidationError> {
        let Some(organization_id) = query_value(raw_query, "organization_id") else {
            return Err(query_validation(
                "missing",
                "organization_id",
                "Field required",
                Value::Null,
            ));
        };
        if organization_id.is_empty() {
            return Err(query_validation(
                "string_too_short",
                "organization_id",
                "String should have at least 1 character",
                json!(organization_id),
            ));
        }
        Ok(Self {
            organization_id,
            delivery_record_id: query_value(raw_query, "delivery_record_id"),
            external_credential_id: query_value(raw_query, "external_credential_id"),
            credential_id: query_value(raw_query, "credential_id"),
            canvas_account_id: query_value(raw_query, "canvas_account_id"),
        })
    }
}

fn parse_limit(raw: Option<String>) -> Result<u32, QueryValidationError> {
    let Some(raw) = raw else {
        return Ok(25);
    };
    let Ok(value) = raw.parse::<PythonConfigInteger>() else {
        return Err(query_validation(
            "int_parsing",
            "limit",
            "Input should be a valid integer, unable to parse string as an integer",
            json!(raw),
        ));
    };
    let Some(value) = value.to_u64() else {
        return Err(query_validation(
            "less_than_equal",
            "limit",
            "Input should be less than or equal to 200",
            json!(raw),
        ));
    };
    if value < 1 {
        return Err(query_validation(
            "greater_than_equal",
            "limit",
            "Input should be greater than or equal to 1",
            json!(raw),
        ));
    }
    if value > 200 {
        return Err(query_validation(
            "less_than_equal",
            "limit",
            "Input should be less than or equal to 200",
            json!(raw),
        ));
    }
    Ok(value as u32)
}

fn parse_bool(
    name: &'static str,
    raw: Option<String>,
    default: bool,
) -> Result<bool, QueryValidationError> {
    let Some(raw) = raw else {
        return Ok(default);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(query_validation(
            "bool_parsing",
            name,
            "Input should be a valid boolean, unable to interpret input",
            json!(raw),
        )),
    }
}

#[derive(Debug)]
struct QueryValidationError {
    kind: &'static str,
    name: &'static str,
    message: &'static str,
    input: Value,
}

impl IntoResponse for QueryValidationError {
    fn into_response(self) -> Response {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "detail": [{
                    "type": self.kind,
                    "loc": ["query", self.name],
                    "msg": self.message,
                    "input": self.input,
                }]
            })),
        )
            .into_response()
    }
}

fn query_validation(
    kind: &'static str,
    name: &'static str,
    message: &'static str,
    input: Value,
) -> QueryValidationError {
    QueryValidationError {
        kind,
        name,
        message,
        input,
    }
}

fn query_value(raw_query: Option<&str>, expected: &str) -> Option<String> {
    url::form_urlencoded::parse(raw_query?.as_bytes())
        .filter(|(name, _)| name == expected)
        .map(|(_, value)| value.into_owned())
        .last()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_parsing_uses_python_integer_boolean_and_last_value_rules() {
        let query = BatchQuery::parse(
            Some("limit=1&limit=+%D9%A3_%D9%A0&retry_failed=YeS&organization_id=org-1"),
            false,
        )
        .unwrap();
        assert_eq!(query.limit, 30);
        assert!(query.retry_failed);
        assert_eq!(query.organization_id.as_deref(), Some("org-1"));
    }
}
