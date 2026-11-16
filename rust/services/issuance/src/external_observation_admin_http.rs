// SPDX-License-Identifier: AGPL-3.0-only
use crate::{
    external_observation_admin::{revoke_grant, AdminError},
    external_observation_http::{gateway_service_authenticated, one_header},
};
use axum::{
    body::to_bytes,
    extract::{Path, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

pub const REVOKE_PATH: &str =
    "/v1/organizations/{organization_id}/external-observation-producers/{grant_id}/revoke";
struct AdminState {
    pool: PgPool,
    gateway_service_key: Vec<u8>,
}
pub fn admin_router(pool: PgPool, gateway_service_key: &[u8]) -> Result<Router, &'static str> {
    if !(32..=512).contains(&gateway_service_key.len())
        || !gateway_service_key.iter().all(u8::is_ascii_graphic)
    {
        return Err("Invalid observation Gateway service credential");
    }
    Ok(Router::new()
        .route(REVOKE_PATH, post(revoke))
        .with_state(Arc::new(AdminState {
            pool,
            gateway_service_key: gateway_service_key.to_vec(),
        })))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeRequest {
    expected_revision: i64,
}
fn failure(status: StatusCode, code: &'static str) -> Response {
    (
        status,
        [("cache-control", "no-store")],
        Json(json!({"error":code})),
    )
        .into_response()
}
async fn revoke(
    State(state): State<Arc<AdminState>>,
    Path((org, grant)): Path<(Uuid, Uuid)>,
    request: Request,
) -> Response {
    let headers = request.headers();
    // The proxy strips caller headers before inserting trusted user context.
    // API-key identities may submit observations but cannot administer grants.
    if !gateway_service_authenticated(headers, &state.gateway_service_key)
        || headers.contains_key("x-api-key-id")
        || one_header(headers, "x-organization-id") != Some(org.to_string().as_str())
    {
        return failure(
            StatusCode::UNAUTHORIZED,
            "administrator_authentication_required",
        );
    }
    let Some(actor) = one_header(headers, "x-user-id")
        .filter(|value| {
            !value.is_empty() && value.len() <= 255 && !value.chars().any(char::is_control)
        })
        .map(str::to_owned)
    else {
        return failure(
            StatusCode::UNAUTHORIZED,
            "administrator_authentication_required",
        );
    };
    if request.uri().query().is_some() {
        return failure(StatusCode::BAD_REQUEST, "invalid_admin_request");
    }
    if !one_header(headers, "content-type")
        .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
        || one_header(headers, "content-encoding")
            .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
    {
        return failure(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_admin_format",
        );
    }
    // Preserve strict framing before original-byte JSON decoding.
    for name in ["content-length", "transfer-encoding", "content-encoding"] {
        if headers.get_all(name).iter().count() > 1 {
            return failure(StatusCode::BAD_REQUEST, "invalid_admin_request");
        }
    }
    if headers.contains_key("trailer")
        || (headers.contains_key("content-length") && headers.contains_key("transfer-encoding"))
    {
        return failure(StatusCode::BAD_REQUEST, "invalid_admin_request");
    }
    if one_header(headers, "transfer-encoding")
        .is_some_and(|value| !value.eq_ignore_ascii_case("chunked"))
    {
        return failure(StatusCode::BAD_REQUEST, "invalid_admin_request");
    }
    let expected_length = if let Some(value) = one_header(headers, "content-length") {
        match value.parse::<usize>() {
            Ok(length)
                if !value.is_empty()
                    && value.bytes().all(|byte| byte.is_ascii_digit())
                    && length <= 4096 =>
            {
                Some(length)
            }
            _ => return failure(StatusCode::BAD_REQUEST, "invalid_admin_request"),
        }
    } else {
        None
    };
    let bytes =
        match tokio::time::timeout(Duration::from_secs(10), to_bytes(request.into_body(), 4096))
            .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(_)) => return failure(StatusCode::PAYLOAD_TOO_LARGE, "admin_request_too_large"),
            Err(_) => return failure(StatusCode::REQUEST_TIMEOUT, "admin_body_timeout"),
        };
    if expected_length.is_some_and(|length| length != bytes.len()) {
        return failure(StatusCode::BAD_REQUEST, "invalid_admin_request");
    }
    let input: RevokeRequest = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return failure(StatusCode::BAD_REQUEST, "invalid_admin_request"),
    };
    if !(1..=9007199254740991).contains(&input.expected_revision) {
        return failure(StatusCode::BAD_REQUEST, "invalid_admin_request");
    }
    match revoke_grant(&state.pool, org, &actor, grant, input.expected_revision).await {
        Ok(result) => (
            StatusCode::OK,
            [("cache-control", "no-store")],
            Json(json!({"revision":result.revision,"audit_id":result.audit_id.to_string()})),
        )
            .into_response(),
        Err(error) => {
            let (status, code) = match error {
                AdminError::NotAuthorized => {
                    (StatusCode::FORBIDDEN, "administrator_not_authorized")
                }
                AdminError::Conflict => (StatusCode::CONFLICT, "admin_revision_conflict"),
                AdminError::Unavailable => {
                    (StatusCode::SERVICE_UNAVAILABLE, "admin_service_unavailable")
                }
                AdminError::CommitUnknown => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "admin_reconciliation_required",
                ),
            };
            failure(status, code)
        }
    }
}
