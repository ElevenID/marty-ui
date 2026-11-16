// SPDX-License-Identifier: AGPL-3.0-only
use crate::{
    external_observation_admin::{revoke_grant, AdminError},
    external_observation_admin_read::{inspect, AdminRead, AuditCursor, GrantPage, ResourceKind},
    external_observation_binding_admin::{
        create_binding, replace_binding_definition, set_binding_active, valid_definition,
        valid_replacement, BindingDefinition, BindingReplacement,
    },
    external_observation_grant_edit::{change_grant_expiry, create_grant},
    external_observation_grant_lifecycle::{approve_grant, rotate_grant_api_key},
    external_observation_http::{gateway_service_authenticated, one_header},
    external_observation_membership_admin::{
        replace_grant_bindings, valid_selection, BindingSelection,
    },
};
use axum::{
    body::{to_bytes, Bytes},
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
pub const APPROVE_PATH: &str =
    "/v1/organizations/{organization_id}/external-observation-producers/{grant_id}/approve";
pub const ROTATE_PATH: &str =
    "/v1/organizations/{organization_id}/external-observation-producers/{grant_id}/rotate-api-key";
pub const CREATE_PATH: &str =
    "/v1/organizations/{organization_id}/external-observation-producers/{grant_id}/create";
pub const EXPIRY_PATH: &str =
    "/v1/organizations/{organization_id}/external-observation-producers/{grant_id}/change-expiry";
pub const BINDINGS_PATH: &str = "/v1/organizations/{organization_id}/external-observation-producers/{grant_id}/replace-bindings";
pub const BINDING_CREATE_PATH: &str =
    "/v1/organizations/{organization_id}/external-observation-bindings/{binding_id}/create";
pub const BINDING_ACTIVATE_PATH: &str =
    "/v1/organizations/{organization_id}/external-observation-bindings/{binding_id}/activate";
pub const BINDING_DEACTIVATE_PATH: &str =
    "/v1/organizations/{organization_id}/external-observation-bindings/{binding_id}/deactivate";
pub const BINDING_REPLACE_PATH:&str="/v1/organizations/{organization_id}/external-observation-bindings/{binding_id}/replace-definition";
pub const GRANT_READ_PATH: &str =
    "/v1/organizations/{organization_id}/external-observation-producers/{grant_id}/inspect";
pub const GRANT_AUDIT_PATH: &str =
    "/v1/organizations/{organization_id}/external-observation-producers/{grant_id}/audit";
pub const BINDING_READ_PATH: &str =
    "/v1/organizations/{organization_id}/external-observation-bindings/{binding_id}/inspect";
pub const BINDING_AUDIT_PATH: &str =
    "/v1/organizations/{organization_id}/external-observation-bindings/{binding_id}/audit";
pub const RECEIPT_READ_PATH: &str =
    "/v1/organizations/{organization_id}/external-observation-receipts/{observation_id}/inspect";
#[derive(Clone, Copy)]
enum Action {
    Bindings,
    Create,
    Expiry,
    Revoke,
    Approve,
    Rotate,
}
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
        .route(REVOKE_PATH, post(mutate))
        .route(APPROVE_PATH, post(mutate))
        .route(ROTATE_PATH, post(mutate))
        .route(CREATE_PATH, post(mutate))
        .route(EXPIRY_PATH, post(mutate))
        .route(BINDINGS_PATH, post(mutate))
        .route(BINDING_CREATE_PATH, post(mutate_binding))
        .route(BINDING_ACTIVATE_PATH, post(mutate_binding))
        .route(BINDING_DEACTIVATE_PATH, post(mutate_binding))
        .route(BINDING_REPLACE_PATH, post(mutate_binding))
        .route(GRANT_READ_PATH, post(read_admin))
        .route(GRANT_AUDIT_PATH, post(read_admin))
        .route(BINDING_READ_PATH, post(read_admin))
        .route(BINDING_AUDIT_PATH, post(read_admin))
        .route(RECEIPT_READ_PATH, post(read_admin))
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotateRequest {
    expected_revision: i64,
    new_api_key_id: Uuid,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    api_key_id: Uuid,
    source_id: String,
    expires_at_ms: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpiryRequest {
    expected_revision: i64,
    expires_at_ms: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingsRequest {
    expected_revision: i64,
    bindings: Vec<BindingSelection>,
}
fn failure(status: StatusCode, code: &'static str) -> Response {
    (
        status,
        [("cache-control", "no-store")],
        Json(json!({"error":code})),
    )
        .into_response()
}
async fn mutate(
    State(state): State<Arc<AdminState>>,
    Path((org, grant)): Path<(Uuid, Uuid)>,
    request: Request,
) -> Response {
    let action = match request.uri().path().rsplit('/').next() {
        Some("replace-bindings") => Action::Bindings,
        Some("create") => Action::Create,
        Some("change-expiry") => Action::Expiry,
        Some("approve") => Action::Approve,
        Some("rotate-api-key") => Action::Rotate,
        _ => Action::Revoke,
    };
    let (actor, bytes) = match admin_body(&state, org, request).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if matches!(action, Action::Bindings) {
        let value = match serde_json::from_slice::<BindingsRequest>(&bytes) {
            Ok(value)
                if !grant.is_nil()
                    && (1..=9007199254740991).contains(&value.expected_revision)
                    && valid_selection(&value.bindings) =>
            {
                value
            }
            _ => return failure(StatusCode::BAD_REQUEST, "invalid_admin_request"),
        };
        return mutation_response(
            replace_grant_bindings(
                &state.pool,
                org,
                &actor,
                grant,
                value.expected_revision,
                &value.bindings,
            )
            .await
            .map(|r| (r.revision, r.audit_id)),
        );
    }
    if matches!(action, Action::Create | Action::Expiry) {
        let result = if matches!(action, Action::Create) {
            let value = match serde_json::from_slice::<CreateRequest>(&bytes) {
                Ok(value)
                    if !value.api_key_id.is_nil()
                        && !grant.is_nil()
                        && !value.source_id.is_empty()
                        && value.source_id.len() <= 128
                        && value
                            .source_id
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                        && (1..=9007199254740991).contains(&value.expires_at_ms) =>
                {
                    value
                }
                _ => return failure(StatusCode::BAD_REQUEST, "invalid_admin_request"),
            };
            create_grant(
                &state.pool,
                org,
                &actor,
                grant,
                value.api_key_id,
                &value.source_id,
                value.expires_at_ms,
            )
            .await
        } else {
            let value = match serde_json::from_slice::<ExpiryRequest>(&bytes) {
                Ok(value)
                    if !grant.is_nil()
                        && (1..=9007199254740991).contains(&value.expected_revision)
                        && (1..=9007199254740991).contains(&value.expires_at_ms) =>
                {
                    value
                }
                _ => return failure(StatusCode::BAD_REQUEST, "invalid_admin_request"),
            };
            change_grant_expiry(
                &state.pool,
                org,
                &actor,
                grant,
                value.expected_revision,
                value.expires_at_ms,
            )
            .await
        };
        return mutation_response(result.map(|r| (r.revision, r.audit_id)));
    }
    let (expected_revision, new_key) = if matches!(action, Action::Rotate) {
        match serde_json::from_slice::<RotateRequest>(&bytes) {
            Ok(value) => (value.expected_revision, Some(value.new_api_key_id)),
            Err(_) => return failure(StatusCode::BAD_REQUEST, "invalid_admin_request"),
        }
    } else {
        match serde_json::from_slice::<RevokeRequest>(&bytes) {
            Ok(value) => (value.expected_revision, None),
            Err(_) => return failure(StatusCode::BAD_REQUEST, "invalid_admin_request"),
        }
    };
    if !(1..=9007199254740991).contains(&expected_revision) || new_key.is_some_and(|id| id.is_nil())
    {
        return failure(StatusCode::BAD_REQUEST, "invalid_admin_request");
    }
    let result = match action {
        Action::Create | Action::Expiry | Action::Bindings => unreachable!("handled above"),
        Action::Revoke => revoke_grant(&state.pool, org, &actor, grant, expected_revision)
            .await
            .map(|r| (r.revision, r.audit_id)),
        Action::Approve => approve_grant(&state.pool, org, &actor, grant, expected_revision)
            .await
            .map(|r| (r.revision, r.audit_id)),
        Action::Rotate => rotate_grant_api_key(
            &state.pool,
            org,
            &actor,
            grant,
            expected_revision,
            new_key.expect("rotation input decoded above"),
        )
        .await
        .map(|r| (r.revision, r.audit_id)),
    };
    mutation_response(result)
}
fn mutation_response(result: Result<(i64, Uuid), AdminError>) -> Response {
    match result {
        Ok((revision, audit_id)) => (
            StatusCode::OK,
            [("cache-control", "no-store")],
            Json(json!({"revision":revision,"audit_id":audit_id.to_string()})),
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivateBindingRequest {
    expected_revision: i64,
    expected_application_revision: i64,
}
async fn mutate_binding(
    State(state): State<Arc<AdminState>>,
    Path((org, binding)): Path<(Uuid, String)>,
    request: Request,
) -> Response {
    let action = request
        .uri()
        .path()
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_owned();
    let (actor, bytes) = match admin_body(&state, org, request).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !crate::external_observation_admission::id(&binding) {
        return failure(StatusCode::BAD_REQUEST, "invalid_admin_request");
    }
    let result = match action.as_str() {
        "create" => {
            let value = match serde_json::from_slice::<BindingDefinition>(&bytes) {
                Ok(v) if valid_definition(&v) => v,
                _ => return failure(StatusCode::BAD_REQUEST, "invalid_admin_request"),
            };
            create_binding(&state.pool, org, &actor, &binding, &value).await
        }
        "replace-definition" => {
            let value = match serde_json::from_slice::<BindingReplacement>(&bytes) {
                Ok(v) if valid_replacement(&v) => v,
                _ => return failure(StatusCode::BAD_REQUEST, "invalid_admin_request"),
            };
            replace_binding_definition(&state.pool, org, &actor, &binding, &value).await
        }
        "activate" => {
            let value = match serde_json::from_slice::<ActivateBindingRequest>(&bytes) {
                Ok(v)
                    if (1..=9007199254740991).contains(&v.expected_revision)
                        && (1..=9007199254740991).contains(&v.expected_application_revision) =>
                {
                    v
                }
                _ => return failure(StatusCode::BAD_REQUEST, "invalid_admin_request"),
            };
            set_binding_active(
                &state.pool,
                org,
                &actor,
                &binding,
                value.expected_revision,
                Some(value.expected_application_revision),
            )
            .await
        }
        "deactivate" => {
            let value = match serde_json::from_slice::<RevokeRequest>(&bytes) {
                Ok(v) if (1..=9007199254740991).contains(&v.expected_revision) => v,
                _ => return failure(StatusCode::BAD_REQUEST, "invalid_admin_request"),
            };
            set_binding_active(
                &state.pool,
                org,
                &actor,
                &binding,
                value.expected_revision,
                None,
            )
            .await
        }
        _ => return failure(StatusCode::BAD_REQUEST, "invalid_admin_request"),
    };
    mutation_response(result.map(|r| (r.revision, r.audit_id)))
}

async fn admin_body(
    state: &AdminState,
    org: Uuid,
    request: Request,
) -> Result<(String, Bytes), Response> {
    let headers = request.headers();
    // The proxy strips caller headers before inserting trusted user context.
    // API-key identities may submit observations but cannot administer grants.
    if !gateway_service_authenticated(headers, &state.gateway_service_key)
        || headers.contains_key("x-api-key-id")
        || one_header(headers, "x-organization-id") != Some(org.to_string().as_str())
    {
        return Err(failure(
            StatusCode::UNAUTHORIZED,
            "administrator_authentication_required",
        ));
    }
    let Some(actor) = one_header(headers, "x-user-id")
        .filter(|value| {
            !value.is_empty() && value.len() <= 255 && !value.chars().any(char::is_control)
        })
        .map(str::to_owned)
    else {
        return Err(failure(
            StatusCode::UNAUTHORIZED,
            "administrator_authentication_required",
        ));
    };
    if request.uri().query().is_some() {
        return Err(failure(StatusCode::BAD_REQUEST, "invalid_admin_request"));
    }
    if !one_header(headers, "content-type")
        .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
        || one_header(headers, "content-encoding")
            .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
    {
        return Err(failure(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_admin_format",
        ));
    }
    // Preserve strict framing before original-byte JSON decoding.
    for name in ["content-length", "transfer-encoding", "content-encoding"] {
        if headers.get_all(name).iter().count() > 1 {
            return Err(failure(StatusCode::BAD_REQUEST, "invalid_admin_request"));
        }
    }
    if headers.contains_key("trailer")
        || (headers.contains_key("content-length") && headers.contains_key("transfer-encoding"))
    {
        return Err(failure(StatusCode::BAD_REQUEST, "invalid_admin_request"));
    }
    if one_header(headers, "transfer-encoding")
        .is_some_and(|value| !value.eq_ignore_ascii_case("chunked"))
    {
        return Err(failure(StatusCode::BAD_REQUEST, "invalid_admin_request"));
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
            _ => return Err(failure(StatusCode::BAD_REQUEST, "invalid_admin_request")),
        }
    } else {
        None
    };
    let bytes =
        match tokio::time::timeout(Duration::from_secs(10), to_bytes(request.into_body(), 4096))
            .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(_)) => {
                return Err(failure(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "admin_request_too_large",
                ))
            }
            Err(_) => return Err(failure(StatusCode::REQUEST_TIMEOUT, "admin_body_timeout")),
        };
    if expected_length.is_some_and(|length| length != bytes.len()) {
        return Err(failure(StatusCode::BAD_REQUEST, "invalid_admin_request"));
    }
    Ok((actor, bytes))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyRead {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptRead {
    source_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditRead {
    cursor: Option<AuditCursor>,
}
async fn read_admin(
    State(state): State<Arc<AdminState>>,
    Path((org, resource)): Path<(Uuid, String)>,
    request: Request,
) -> Response {
    let path = request.uri().path().to_owned();
    let parts: Vec<_> = path.split('/').collect();
    let (actor, bytes) = match admin_body(&state, org, request).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let query = match (parts.get(4).copied(), parts.last().copied()) {
        (Some("external-observation-producers"), Some("inspect")) => {
            let grant = match Uuid::parse_str(&resource) {
                Ok(v) if !v.is_nil() && v.to_string() == resource => v,
                _ => return failure(StatusCode::BAD_REQUEST, "invalid_admin_request"),
            };
            let page = match serde_json::from_slice::<GrantPage>(&bytes) {
                Ok(v) => v,
                _ => return failure(StatusCode::BAD_REQUEST, "invalid_admin_request"),
            };
            AdminRead::Grant { grant, page }
        }
        (Some("external-observation-bindings"), Some("inspect")) => {
            if serde_json::from_slice::<EmptyRead>(&bytes).is_err() {
                return failure(StatusCode::BAD_REQUEST, "invalid_admin_request");
            }
            AdminRead::Binding { binding: resource }
        }
        (Some("external-observation-receipts"), Some("inspect")) => {
            let input = match serde_json::from_slice::<ReceiptRead>(&bytes) {
                Ok(v) => v,
                _ => return failure(StatusCode::BAD_REQUEST, "invalid_admin_request"),
            };
            AdminRead::Receipt {
                source: input.source_id,
                observation: resource,
            }
        }
        (
            Some(group @ ("external-observation-producers" | "external-observation-bindings")),
            Some("audit"),
        ) => {
            let input = match serde_json::from_slice::<AuditRead>(&bytes) {
                Ok(v) => v,
                _ => return failure(StatusCode::BAD_REQUEST, "invalid_admin_request"),
            };
            AdminRead::Audit {
                kind: if group == "external-observation-producers" {
                    ResourceKind::Producer
                } else {
                    ResourceKind::Binding
                },
                resource,
                cursor: input.cursor,
            }
        }
        _ => return failure(StatusCode::BAD_REQUEST, "invalid_admin_request"),
    };
    if !query.valid() {
        return failure(StatusCode::BAD_REQUEST, "invalid_admin_request");
    }
    match inspect(&state.pool, org, &actor, query).await {
        Ok(value) => (StatusCode::OK, [("cache-control", "no-store")], Json(value)).into_response(),
        Err(error) => mutation_response(Err(error)),
    }
}
