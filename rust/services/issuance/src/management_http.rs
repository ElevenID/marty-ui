//! Shared HTTP boundary helpers for management surfaces.

use axum::{
    extract::rejection::JsonRejection,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::transaction_reads::TransactionReadError;

pub(crate) fn authentication_error(
    error: &TransactionReadError,
) -> Option<(StatusCode, &'static str)> {
    Some(match error {
        TransactionReadError::ApiKeyNotConfigured => (
            StatusCode::SERVICE_UNAVAILABLE,
            "ISSUANCE_API_KEY not configured on server",
        ),
        TransactionReadError::ApiKeyMissing => {
            (StatusCode::UNAUTHORIZED, "X-API-Key header is missing")
        }
        TransactionReadError::InvalidApiKey => (StatusCode::UNAUTHORIZED, "Invalid API Key"),
        _ => return None,
    })
}

pub(crate) fn security_error(
    error: TransactionReadError,
    unavailable_detail: &'static str,
) -> (StatusCode, &'static str) {
    if let Some(response) = authentication_error(&error) {
        return response;
    }
    match error {
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

pub(crate) fn missing_header(name: &'static str) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "detail": [{
                "type": "missing",
                "loc": ["header", name],
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_authentication_does_not_choose_tenant_or_resource_policy() {
        for (error, status, detail) in [
            (
                TransactionReadError::ApiKeyMissing,
                StatusCode::UNAUTHORIZED,
                "X-API-Key header is missing",
            ),
            (
                TransactionReadError::InvalidApiKey,
                StatusCode::UNAUTHORIZED,
                "Invalid API Key",
            ),
            (
                TransactionReadError::ApiKeyNotConfigured,
                StatusCode::SERVICE_UNAVAILABLE,
                "ISSUANCE_API_KEY not configured on server",
            ),
        ] {
            assert_eq!(authentication_error(&error), Some((status, detail)));
            assert_eq!(security_error(error, "unavailable"), (status, detail));
        }
        for error in [
            TransactionReadError::TrustedOrganizationRequired,
            TransactionReadError::OrganizationMismatch,
            TransactionReadError::ResourceNotFound,
        ] {
            assert_eq!(authentication_error(&error), None);
        }
        assert_eq!(
            security_error(
                TransactionReadError::TrustedOrganizationRequired,
                "unavailable"
            )
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            security_error(TransactionReadError::OrganizationMismatch, "unavailable").0,
            StatusCode::NOT_FOUND
        );
    }
}
