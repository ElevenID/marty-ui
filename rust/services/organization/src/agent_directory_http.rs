//! Explicit opt-in, service-authenticated HTTP administration for agent inventory.
use std::sync::Arc;

use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Json, Router,
};
use mmf_security::{SecurityError, ServiceTokenAuthenticator};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    agent_directory::{
        decode_agent_request, AgentDirectoryError, AgentDirectoryService, AgentEnrollmentSession,
        AgentLifecycleAction, AgentLifecycleRequest, CompleteAgentEnrollment,
        CreateAgentEnrollmentChallenge, RegisterAgentRequest, RotateAgentKeyRequest,
        UpdateAgentMetadataRequest,
    },
    authenticate_forwarded_http_request, ForwardedPrincipal,
};

#[derive(Clone)]
pub struct AgentDirectoryHttpState {
    directory: AgentDirectoryService,
    authenticator: Arc<ServiceTokenAuthenticator>,
}

impl AgentDirectoryHttpState {
    /// Unlike the legacy development transport, this candidate has no unauthenticated mode.
    pub fn new(
        directory: AgentDirectoryService,
        service_token: String,
    ) -> Result<Self, SecurityError> {
        if service_token.len() < 32 {
            return Err(SecurityError::InvalidAuthenticationResult);
        }
        Ok(Self {
            directory,
            authenticator: Arc::new(ServiceTokenAuthenticator::new(Some(service_token), true)?),
        })
    }
}

pub fn organization_agent_admin_router(state: AgentDirectoryHttpState) -> Router {
    Router::new()
        .route("/v1/organizations/{organization_id}/agents", any(handle))
        .route(
            "/v1/organizations/{organization_id}/agents/{agent_id}",
            any(handle),
        )
        .route(
            "/v1/organizations/{organization_id}/agents/{agent_id}/{action}",
            any(handle),
        )
        .route(
            "/v1/organizations/{organization_id}/agents/{agent_id}/enrollment-challenges/{challenge_id}",
            any(handle),
        )
        .route(
            "/v1/organizations/{organization_id}/agents/{agent_id}/enrollment-challenges/{challenge_id}/complete",
            any(handle),
        )
        .with_state(state)
}

fn canonical(value: &str) -> Option<Uuid> {
    Uuid::parse_str(value)
        .ok()
        .filter(|id| !id.is_nil() && id.to_string() == value)
}
fn single<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(first)
}
fn reply(status: StatusCode, value: Value, request_id: Uuid) -> Response {
    let mut response = (status, Json(value)).into_response();
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&request_id.to_string()).expect("UUID"),
    );
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response
}
fn error(status: StatusCode, code: &'static str, request_id: Uuid) -> Response {
    reply(
        status,
        json!({"error":code,"message_id":request_id}),
        request_id,
    )
}

#[derive(Clone, Copy)]
enum Operation {
    List,
    Register,
    Inspect,
    History,
    Update,
    Rotate,
    Transition(AgentLifecycleAction),
    EnrollmentCreate,
    EnrollmentInspect(Uuid),
    EnrollmentComplete(Uuid),
}
impl Operation {
    fn permission(self) -> &'static str {
        match self {
            Self::List | Self::Inspect | Self::History | Self::EnrollmentInspect(_) => {
                "agent-identity:view"
            }
            Self::EnrollmentCreate | Self::EnrollmentComplete(_) => "agent-identity:enroll",
            Self::Register => "agent-identity:create",
            Self::Update => "agent-identity:update",
            Self::Rotate => "agent-identity:rotate-key",
            Self::Transition(AgentLifecycleAction::Suspend) => "agent-identity:suspend",
            Self::Transition(AgentLifecycleAction::Revoke) => "agent-identity:revoke",
            Self::Transition(AgentLifecycleAction::Retire) => "agent-identity:retire",
        }
    }
    fn read(self) -> bool {
        matches!(
            self,
            Self::List | Self::Inspect | Self::History | Self::EnrollmentInspect(_)
        )
    }
    fn enrollment(self) -> bool {
        matches!(
            self,
            Self::EnrollmentCreate | Self::EnrollmentInspect(_) | Self::EnrollmentComplete(_)
        )
    }
}

fn route(method: &str, path: &str) -> Option<(Uuid, Option<Uuid>, Operation)> {
    let parts: Vec<_> = path.split('/').collect();
    if parts.len() < 5 || parts[..3] != ["", "v1", "organizations"] || parts[4] != "agents" {
        return None;
    }
    let org = canonical(parts[3])?;
    let id = if parts.len() > 5 {
        Some(canonical(parts[5])?)
    } else {
        None
    };
    let operation = match (method, parts.len(), parts.get(6).copied()) {
        ("GET", 5, _) => Operation::List,
        ("POST", 5, _) => Operation::Register,
        ("GET", 6, _) => Operation::Inspect,
        ("PATCH", 6, _) => Operation::Update,
        ("GET", 7, Some("history")) => Operation::History,
        ("POST", 7, Some("rotate-key")) => Operation::Rotate,
        ("POST", 7, Some("suspend")) => Operation::Transition(AgentLifecycleAction::Suspend),
        ("POST", 7, Some("revoke")) => Operation::Transition(AgentLifecycleAction::Revoke),
        ("POST", 7, Some("retire")) => Operation::Transition(AgentLifecycleAction::Retire),
        ("POST", 7, Some("enrollment-challenges")) => Operation::EnrollmentCreate,
        ("GET", 8, Some("enrollment-challenges")) => {
            Operation::EnrollmentInspect(canonical(parts[7])?)
        }
        ("POST", 9, Some("enrollment-challenges")) if parts[8] == "complete" => {
            Operation::EnrollmentComplete(canonical(parts[7])?)
        }
        _ => return None,
    };
    Some((org, id, operation))
}

fn enrollment_session(
    headers: &HeaderMap,
    organization: Uuid,
    principal: &ForwardedPrincipal,
) -> Option<AgentEnrollmentSession> {
    let organization_id = canonical(single(headers, "x-marty-enrollment-organization-id")?)?;
    let user_id = canonical(single(headers, "x-marty-enrollment-user-id")?)?;
    if organization_id != organization
        || !matches!(principal, ForwardedPrincipal::User {user_id: forwarded} if forwarded==&user_id.to_string())
    {
        return None;
    }
    let timestamp = |name| {
        chrono::DateTime::parse_from_rfc3339(single(headers, name)?)
            .ok()
            .map(|value| value.with_timezone(&chrono::Utc))
    };
    AgentEnrollmentSession::new(
        organization_id,
        user_id,
        single(headers, "x-marty-enrollment-session-ref")?.into(),
        timestamp("x-marty-enrollment-observed-at")?,
        timestamp("x-marty-enrollment-valid-until")?,
    )
    .ok()
}

fn pagination(operation: Operation, raw: Option<&str>) -> Result<(u32, u32), AgentDirectoryError> {
    let mut limit = None;
    let mut offset = None;
    for (key, value) in url::form_urlencoded::parse(raw.unwrap_or("").as_bytes()) {
        if !matches!(operation, Operation::List | Operation::History) {
            return Err(AgentDirectoryError::InvalidRequest);
        }
        let parsed: u32 = value
            .parse()
            .map_err(|_| AgentDirectoryError::InvalidRequest)?;
        if parsed.to_string() != value {
            return Err(AgentDirectoryError::InvalidRequest);
        }
        match key.as_ref() {
            "limit" if limit.is_none() && (1..=100).contains(&parsed) => limit = Some(parsed),
            "offset" if offset.is_none() && parsed <= 10_000 => offset = Some(parsed),
            _ => return Err(AgentDirectoryError::InvalidRequest),
        }
    }
    Ok((limit.unwrap_or(50), offset.unwrap_or(0)))
}

async fn handle(State(state): State<AgentDirectoryHttpState>, request: Request) -> Response {
    let mut request_id = Uuid::new_v4();
    // Do not trust correlation, principal or tenant headers until this service
    // hop is authenticated. Duplicate security headers are never collapsed.
    if single(request.headers(), "x-service-token").is_none()
        || state
            .authenticator
            .authenticate(single(request.headers(), "x-service-token"))
            .is_err()
    {
        return error(
            StatusCode::UNAUTHORIZED,
            "service_authentication_required",
            request_id,
        );
    }
    if request.headers().contains_key("x-request-id") {
        let Some(id) = single(request.headers(), "x-request-id").and_then(canonical) else {
            return error(StatusCode::BAD_REQUEST, "invalid_correlation", request_id);
        };
        request_id = id;
    }
    let Some((org, id, operation)) = route(request.method().as_str(), request.uri().path()) else {
        return error(StatusCode::NOT_FOUND, "not_found", request_id);
    };
    if operation.enrollment() && !state.directory.enrollment_enabled() {
        return error(StatusCode::NOT_FOUND, "not_found", request_id);
    }
    if request.headers().contains_key("x-api-key-id")
        || single(request.headers(), "x-user-id")
            .and_then(canonical)
            .is_none()
        || single(request.headers(), "x-organization-id").and_then(canonical) != Some(org)
        || single(request.headers(), "x-required-permission") != Some(operation.permission())
    {
        return error(
            StatusCode::FORBIDDEN,
            "human_tenant_context_required",
            request_id,
        );
    }
    let principal =
        match authenticate_forwarded_http_request(request.headers(), &state.authenticator) {
            Ok(principal @ ForwardedPrincipal::User { .. }) => principal,
            _ => {
                return error(
                    StatusCode::FORBIDDEN,
                    "human_tenant_context_required",
                    request_id,
                )
            }
        };
    let enrollment = if operation.enrollment() {
        match enrollment_session(request.headers(), org, &principal) {
            Some(session) => Some(session),
            None => {
                return error(
                    StatusCode::FORBIDDEN,
                    "human_session_context_required",
                    request_id,
                )
            }
        }
    } else {
        None
    };
    if !operation.read()
        && single(request.headers(), "content-type")
            .is_none_or(|value| value.split(';').next().map(str::trim) != Some("application/json"))
    {
        return error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "application_json_required",
            request_id,
        );
    }
    let (limit, offset) = match pagination(operation, request.uri().query()) {
        Ok(paging) => paging,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_request", request_id),
    };
    let body = match to_bytes(request.into_body(), 16_384).await {
        Ok(body) => body,
        Err(_) => {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                request_id,
            )
        }
    };
    if operation.read() && !body.is_empty() {
        return error(StatusCode::BAD_REQUEST, "invalid_request", request_id);
    }
    let service = state.directory.with_request_id(request_id);
    let result: Result<Value, AgentDirectoryError> = async {
        let value = match operation {
            Operation::List => {
                serde_json::to_value(service.list(org, &principal, limit, offset).await?)
            }
            Operation::Inspect => serde_json::to_value(
                service
                    .inspect(org, &principal, id.expect("item route"))
                    .await?,
            ),
            Operation::History => serde_json::to_value(
                service
                    .history(org, &principal, id.expect("item route"), limit, offset)
                    .await?,
            ),
            Operation::Register => serde_json::to_value(
                service
                    .register(
                        org,
                        &principal,
                        decode_agent_request::<RegisterAgentRequest>(&body)?,
                    )
                    .await?,
            ),
            Operation::Update => serde_json::to_value(
                service
                    .update_metadata(
                        org,
                        &principal,
                        id.expect("item route"),
                        decode_agent_request::<UpdateAgentMetadataRequest>(&body)?,
                    )
                    .await?,
            ),
            Operation::Rotate => serde_json::to_value(
                service
                    .rotate_key(
                        org,
                        &principal,
                        id.expect("item route"),
                        decode_agent_request::<RotateAgentKeyRequest>(&body)?,
                    )
                    .await?,
            ),
            Operation::Transition(action) => serde_json::to_value(
                service
                    .transition(
                        org,
                        &principal,
                        id.expect("item route"),
                        action,
                        decode_agent_request::<AgentLifecycleRequest>(&body)?,
                    )
                    .await?,
            ),
            Operation::EnrollmentCreate => serde_json::to_value(
                service
                    .create_enrollment_challenge(
                        org,
                        &principal,
                        enrollment.as_ref().expect("enrollment route"),
                        id.expect("item route"),
                        decode_agent_request::<CreateAgentEnrollmentChallenge>(&body)?,
                    )
                    .await?,
            ),
            Operation::EnrollmentInspect(challenge) => serde_json::to_value(
                service
                    .inspect_enrollment_challenge(
                        org,
                        &principal,
                        enrollment.as_ref().expect("enrollment route"),
                        id.expect("item route"),
                        challenge,
                    )
                    .await?,
            ),
            Operation::EnrollmentComplete(challenge) => serde_json::to_value(
                service
                    .complete_enrollment(
                        org,
                        &principal,
                        enrollment.as_ref().expect("enrollment route"),
                        id.expect("item route"),
                        challenge,
                        decode_agent_request::<CompleteAgentEnrollment>(&body)?,
                    )
                    .await?,
            ),
        };
        value.map_err(|_| AgentDirectoryError::CorruptData)
    }
    .await;
    match result {
        Ok(value) => reply(
            if matches!(operation, Operation::Register)
                || matches!(operation, Operation::EnrollmentCreate)
                    && value.get("recovered") == Some(&json!(false))
            {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            value,
            request_id,
        ),
        Err(failure) => error(
            match failure {
                AgentDirectoryError::InvalidRequest => StatusCode::BAD_REQUEST,
                AgentDirectoryError::AccessDenied => StatusCode::FORBIDDEN,
                AgentDirectoryError::NotFound => StatusCode::NOT_FOUND,
                AgentDirectoryError::Conflict | AgentDirectoryError::InvalidTransition => {
                    StatusCode::CONFLICT
                }
                AgentDirectoryError::Unavailable | AgentDirectoryError::CorruptData => {
                    StatusCode::SERVICE_UNAVAILABLE
                }
            },
            match failure {
                AgentDirectoryError::InvalidRequest => "invalid_request",
                AgentDirectoryError::AccessDenied => "action_not_authorized",
                AgentDirectoryError::NotFound => "not_found",
                AgentDirectoryError::Conflict | AgentDirectoryError::InvalidTransition => {
                    "agent_state_conflict"
                }
                _ => "agent_directory_unavailable",
            },
            request_id,
        ),
    }
}
