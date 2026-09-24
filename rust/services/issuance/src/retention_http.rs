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

#[derive(Clone, Copy)]
enum RetentionDaysError {
    Parse,
    BelowMinimum,
    AboveMaximum,
}

// Match the released Python query boundary, including its string-to-integer coercions.
// Saturating at 3651 preserves range classification for arbitrarily long integers.
fn parse_retention_integer(value: &str) -> Option<i32> {
    let trimmed = value.trim();
    let (negative, unsigned) = match trimmed.as_bytes().first() {
        Some(b'-') => (true, &trimmed[1..]),
        Some(b'+') => (false, &trimmed[1..]),
        _ => (false, trimmed),
    };
    let unsigned = unsigned
        .rsplit_once('.')
        .and_then(|(whole, fraction)| {
            (!fraction.is_empty() && fraction.bytes().all(|byte| byte == b'0')).then_some(whole)
        })
        .unwrap_or(unsigned);
    let mut digits = unsigned.bytes().peekable();
    let mut number: i32 = 0;
    let mut saw_digit = false;
    while let Some(byte) = digits.next() {
        match byte {
            b'0'..=b'9' => {
                saw_digit = true;
                number = number
                    .saturating_mul(10)
                    .saturating_add(i32::from(byte - b'0'));
            }
            b'_' if saw_digit && matches!(digits.peek(), Some(b'0'..=b'9')) => {}
            _ => return None,
        }
    }
    saw_digit.then_some(if negative { -number } else { number })
}

fn retention_validation_error(value: &str, error: RetentionDaysError) -> Response {
    let (kind, message, context) = match error {
        RetentionDaysError::Parse => (
            "int_parsing",
            "Input should be a valid integer, unable to parse string as an integer",
            None,
        ),
        RetentionDaysError::BelowMinimum => (
            "greater_than_equal",
            "Input should be greater than or equal to 1",
            Some(json!({"ge": 1})),
        ),
        RetentionDaysError::AboveMaximum => (
            "less_than_equal",
            "Input should be less than or equal to 3650",
            Some(json!({"le": 3650})),
        ),
    };
    let mut detail = json!({
        "type": kind,
        "loc": ["query", "retention_days"],
        "msg": message,
        "input": value,
        "url": format!("https://errors.pydantic.dev/2.11/v/{kind}"),
    });
    if let Some(context) = context {
        detail["ctx"] = context;
    }
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({"detail": [detail]})),
    )
        .into_response()
}

fn retention_days(query: Option<&str>) -> Result<u16, Box<Response>> {
    let value = url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .filter(|(key, _)| key == "retention_days")
        .map(|(_, value)| value.into_owned())
        .last();
    let Some(value) = value else {
        return Ok(30);
    };
    match parse_retention_integer(&value) {
        Some(days @ 1..=3650) => Ok(days as u16),
        other => {
            let error = match other {
                None => RetentionDaysError::Parse,
                Some(days) if days < 1 => RetentionDaysError::BelowMinimum,
                Some(_) => RetentionDaysError::AboveMaximum,
            };
            Err(Box::new(retention_validation_error(&value, error)))
        }
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
