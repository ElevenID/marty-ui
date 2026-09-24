//! Management-authenticated HTTP adapter for tenant-owned retention.

use axum::{
    extract::{Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use tracing::error;

use crate::{
    management_http::header, retention::RetentionService, transaction_reads::TransactionReadError,
};

const API_KEY_HEADER: &str = "x-api-key";
const ORGANIZATION_HEADER: &str = "x-organization-id";

pub fn router(service: RetentionService) -> Router {
    Router::new()
        .route(
            "/v1/issuance/organizations/{organization_id}/retention",
            get(summary),
        )
        .route(
            "/v1/issuance/organizations/{organization_id}/retention/purge",
            post(purge),
        )
        .with_state(service)
}

fn retention_days(query: Option<&str>) -> Result<u16, Box<Response>> {
    let value = url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .filter(|(key, _)| key == "retention_days")
        .map(|(_, value)| value.into_owned())
        .last();
    let Some(value) = value else {
        return Ok(30);
    };
    match value.parse::<u16>() {
        Ok(days @ 1..=3650) => Ok(days),
        _ => Err(Box::new(
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail": "retention_days must be between 1 and 3650"})),
            )
                .into_response(),
        )),
    }
}

fn authorize(
    service: &RetentionService,
    headers: &HeaderMap,
    organization_id: &str,
) -> Result<(), Box<Response>> {
    service
        .authorize(
            header(headers, API_KEY_HEADER),
            header(headers, ORGANIZATION_HEADER),
            organization_id,
        )
        .map_err(|error| Box::new(security_error(error)))
}

fn security_error(error: TransactionReadError) -> Response {
    let (status, detail) = match error {
        TransactionReadError::ApiKeyMissing => {
            (StatusCode::UNAUTHORIZED, "X-API-Key header is missing")
        }
        TransactionReadError::InvalidApiKey => (StatusCode::UNAUTHORIZED, "Invalid API Key"),
        TransactionReadError::TrustedOrganizationRequired => (
            StatusCode::FORBIDDEN,
            "X-Organization-ID header is required",
        ),
        TransactionReadError::OrganizationMismatch => {
            (StatusCode::FORBIDDEN, "Organization does not match")
        }
        TransactionReadError::ApiKeyNotConfigured => (
            StatusCode::SERVICE_UNAVAILABLE,
            "ISSUANCE_API_KEY not configured on server",
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Retention authorization failed",
        ),
    };
    (status, Json(json!({"detail": detail}))).into_response()
}

fn repository_error(error: sqlx::Error) -> Response {
    error!(%error, "issuance retention repository operation failed");
    (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
}

async fn summary(
    State(service): State<RetentionService>,
    Path(organization_id): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorize(&service, &headers, &organization_id) {
        return *response;
    }
    let days = match retention_days(query.as_deref()) {
        Ok(days) => days,
        Err(response) => return *response,
    };
    match service.summary(&organization_id, days).await {
        Ok(summary) => (StatusCode::OK, Json(summary)).into_response(),
        Err(error) => repository_error(error),
    }
}

async fn purge(
    State(service): State<RetentionService>,
    Path(organization_id): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorize(&service, &headers, &organization_id) {
        return *response;
    }
    let days = match retention_days(query.as_deref()) {
        Ok(days) => days,
        Err(response) => return *response,
    };
    match service.purge(&organization_id, days).await {
        Ok(purged) => (StatusCode::OK, Json(purged)).into_response(),
        Err(error) => repository_error(error),
    }
}
