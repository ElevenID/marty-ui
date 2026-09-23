//! Shared HTTP boundary helpers for management surfaces.

use axum::{
    extract::rejection::JsonRejection,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::transaction_reads::TransactionReadError;

pub(crate) fn security_error(
    error: TransactionReadError,
    unavailable_detail: &'static str,
) -> (StatusCode, &'static str) {
    match error {
        TransactionReadError::ApiKeyNotConfigured => (
            StatusCode::SERVICE_UNAVAILABLE,
            "ISSUANCE_API_KEY not configured on server",
        ),
        TransactionReadError::ApiKeyMissing => {
            (StatusCode::UNAUTHORIZED, "X-API-Key header is missing")
        }
        TransactionReadError::InvalidApiKey => (StatusCode::UNAUTHORIZED, "Invalid API Key"),
        TransactionReadError::TrustedOrganizationRequired => (
            StatusCode::BAD_REQUEST,
            "X-Organization-ID is required for application management",
        ),
        TransactionReadError::OrganizationMismatch | TransactionReadError::ResourceNotFound => {
            (StatusCode::NOT_FOUND, "Application resource not found")
        }
        TransactionReadError::OrganizationIdRequired => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "organization_id query parameter is required",
        ),
        _ => (StatusCode::SERVICE_UNAVAILABLE, unavailable_detail),
    }
}

pub(crate) fn malformed_json(error: JsonRejection) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({"detail": error.body_text()})),
    )
        .into_response()
}

pub(crate) fn malformed_query() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"detail": "Query parameters are invalid"})),
    )
        .into_response()
}

pub(crate) fn missing_organization_query() -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "detail": [{
                "type": "missing",
                "loc": ["query", "organization_id"],
                "msg": "Field required",
                "input": null,
            }]
        })),
    )
        .into_response()
}

pub(crate) fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}
