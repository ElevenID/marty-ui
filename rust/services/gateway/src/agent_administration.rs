//! Opt-in human agent-directory administration and explicit delegation approval.
//! This transport never enrolls a trusted runtime or enables delegated use.
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
};

use axum::{
    body::{to_bytes, Body},
    extract::Request,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, SecondsFormat, Utc};
use mmf_platform::{
    AuthenticationType, GatewayRequest, HttpMethod, PlatformError, ProxyOverrides, RouteConfig,
    RouteMatchType, RouteTable, TrustedIdentityContext,
};
use serde::{
    de::{MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    authorization::authorize_membership,
    middleware::{AuthenticationSource, GatewayIdentity, MipError},
    runtime::GatewayRuntimeState,
};

#[path = "agent_enrollment_response.rs"]
mod enrollment_response;
#[path = "agent_administration_response.rs"]
pub(crate) mod response_contract;

pub const MAXIMUM_BODY_BYTES: usize = 16_384;
const MAX_REVISION: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    List,
    Register,
    Inspect,
    History,
    Update,
    Suspend,
    Revoke,
    Retire,
    RotateKey,
    CreateEnrollmentChallenge,
    InspectEnrollmentChallenge,
    CompleteEnrollment,
    ReviewApproval,
    ConfirmApproval,
    WithdrawApproval,
}

impl Operation {
    pub fn permission(self) -> &'static str {
        match self {
            Self::List | Self::Inspect | Self::History | Self::InspectEnrollmentChallenge => {
                "agent-identity:view"
            }
            Self::CreateEnrollmentChallenge | Self::CompleteEnrollment => "agent-identity:enroll",
            Self::Register => "agent-identity:create",
            Self::Update => "agent-identity:update",
            Self::Suspend => "agent-identity:suspend",
            Self::Revoke => "agent-identity:revoke",
            Self::Retire => "agent-identity:retire",
            Self::RotateKey => "agent-identity:rotate-key",
            Self::ReviewApproval => "delegation-grant:approve",
            Self::ConfirmApproval | Self::WithdrawApproval => "delegation-grant:view",
        }
    }
    fn is_approval(self) -> bool {
        matches!(
            self,
            Self::ReviewApproval | Self::ConfirmApproval | Self::WithdrawApproval
        )
    }
    fn is_enrollment(self) -> bool {
        matches!(
            self,
            Self::CreateEnrollmentChallenge
                | Self::InspectEnrollmentChallenge
                | Self::CompleteEnrollment
        )
    }
    fn read(self) -> bool {
        matches!(
            self,
            Self::List | Self::Inspect | Self::History | Self::InspectEnrollmentChallenge
        )
    }
    fn enabled(self, state: &GatewayRuntimeState) -> bool {
        if self.is_enrollment() {
            state.agent_enrollment_enabled
        } else if self.is_approval() {
            state.delegation_approval_enabled
        } else {
            state.agent_admin_enabled
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminRoute {
    pub organization_id: Uuid,
    pub resource_id: Option<Uuid>,
    pub linked_id: Option<Uuid>,
    pub operation: Operation,
}

pub(crate) fn canonical_uuid(value: &str) -> Option<Uuid> {
    Uuid::parse_str(value)
        .ok()
        .filter(|id| !id.is_nil() && id.to_string() == value)
}

pub fn is_namespace(path: &str) -> bool {
    let parts: Vec<_> = path.split('/').collect();
    parts.len() >= 5
        && parts[..3] == ["", "v1", "organizations"]
        && matches!(parts[4], "agents" | "delegation-grants")
}

pub fn route(method: &str, path: &str) -> Option<AdminRoute> {
    let p: Vec<_> = path.split('/').collect();
    if p.len() < 5 || p[..3] != ["", "v1", "organizations"] {
        return None;
    }
    let organization_id = canonical_uuid(p[3])?;
    let resource_id = if p.len() > 5 {
        Some(canonical_uuid(p[5])?)
    } else {
        None
    };
    let operation = match (method, p[4], p.len(), p.get(6).copied()) {
        ("GET", "agents", 5, _) => Operation::List,
        ("POST", "agents", 5, _) => Operation::Register,
        ("GET", "agents", 6, _) => Operation::Inspect,
        ("PATCH", "agents", 6, _) => Operation::Update,
        ("GET", "agents", 7, Some("history")) => Operation::History,
        ("POST", "agents", 7, Some("suspend")) => Operation::Suspend,
        ("POST", "agents", 7, Some("revoke")) => Operation::Revoke,
        ("POST", "agents", 7, Some("retire")) => Operation::Retire,
        ("POST", "agents", 7, Some("rotate-key")) => Operation::RotateKey,
        ("POST", "agents", 7, Some("enrollment-challenges")) => {
            Operation::CreateEnrollmentChallenge
        }
        ("GET", "agents", 8, Some("enrollment-challenges")) if canonical_uuid(p[7]).is_some() => {
            Operation::InspectEnrollmentChallenge
        }
        ("POST", "agents", 9, Some("enrollment-challenges"))
            if canonical_uuid(p[7]).is_some() && p[8] == "complete" =>
        {
            Operation::CompleteEnrollment
        }
        ("POST", "delegation-grants", 7, Some("approval-reviews")) => Operation::ReviewApproval,
        ("POST", "delegation-grants", 9, Some("approval-reviews"))
            if canonical_uuid(p[7]).is_some() && p[8] == "confirm" =>
        {
            Operation::ConfirmApproval
        }
        ("POST", "delegation-grants", 9, Some("approval-confirmations"))
            if canonical_uuid(p[7]).is_some() && p[8] == "withdraw" =>
        {
            Operation::WithdrawApproval
        }
        _ => return None,
    };
    Some(AdminRoute {
        organization_id,
        resource_id,
        linked_id: if p.len() >= 8 {
            canonical_uuid(p[7])
        } else {
            None
        },
        operation,
    })
}

pub fn paths(directory: bool, approval: bool) -> Vec<(HttpMethod, String, &'static str)> {
    let base = "/v1/organizations/{organization_id}/agents";
    let mut routes = Vec::new();
    if directory {
        routes.extend([
            (HttpMethod::Get, base.to_owned(), "organizations"),
            (HttpMethod::Post, base.to_owned(), "organizations"),
            (
                HttpMethod::Get,
                format!("{base}/{{agent_id}}"),
                "organizations",
            ),
            (
                HttpMethod::Patch,
                format!("{base}/{{agent_id}}"),
                "organizations",
            ),
            (
                HttpMethod::Get,
                format!("{base}/{{agent_id}}/history"),
                "organizations",
            ),
        ]);
        for action in ["suspend", "revoke", "retire", "rotate-key"] {
            routes.push((
                HttpMethod::Post,
                format!("{base}/{{agent_id}}/{action}"),
                "organizations",
            ));
        }
    }
    if approval {
        let base = "/v1/organizations/{organization_id}/delegation-grants/{grant_id}";
        for suffix in [
            "approval-reviews",
            "approval-reviews/{review_id}/confirm",
            "approval-confirmations/{confirmation_id}/withdraw",
        ] {
            routes.push((
                HttpMethod::Post,
                format!("{base}/{suffix}"),
                "delegated-authority",
            ));
        }
    }
    routes
}

pub fn add_routes(
    table: &mut RouteTable,
    directory: bool,
    approval: bool,
) -> Result<(), PlatformError> {
    install_routes(table, paths(directory, approval))
}

pub fn add_enrollment_routes(table: &mut RouteTable, enabled: bool) -> Result<(), PlatformError> {
    install_routes(table, enrollment_paths(enabled))
}

fn enrollment_paths(enabled: bool) -> Vec<(HttpMethod, String, &'static str)> {
    if !enabled {
        return Vec::new();
    }
    let base = "/v1/organizations/{organization_id}/agents/{agent_id}/enrollment-challenges";
    vec![
        (HttpMethod::Post, base.into(), "organizations"),
        (
            HttpMethod::Get,
            format!("{base}/{{challenge_id}}"),
            "organizations",
        ),
        (
            HttpMethod::Post,
            format!("{base}/{{challenge_id}}/complete"),
            "organizations",
        ),
    ]
}

fn install_routes(
    table: &mut RouteTable,
    routes: Vec<(HttpMethod, String, &'static str)>,
) -> Result<(), PlatformError> {
    for (method, path, service) in routes {
        table.add(RouteConfig {
            name: format!("agent-administration:{method:?}:{path}"),
            pattern: path,
            match_type: RouteMatchType::Template,
            upstream_service: service.into(),
            methods: BTreeSet::from([method]),
            host: None,
            required_headers: BTreeMap::new(),
            rewrite_path: None,
            timeout_ms: 10_000,
            retries: 0,
            auth_required: true,
            authentication_type: AuthenticationType::Jwt,
            priority: 200,
            tags: BTreeSet::from(["candidate-human-administration".into()]),
        })?;
    }
    Ok(())
}

#[derive(Clone)]
struct AuthorizedAdmin {
    request: GatewayRequest,
    identity: TrustedIdentityContext,
    request_id: String,
    route: AdminRoute,
    submitted: Option<Value>,
    session_ref: String,
    valid_until: i64,
}

pub(crate) fn rejection(status: u16, code: &'static str, request_id: &str) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = (
        status,
        Json(MipError::with_message_id(code, code, request_id)),
    )
        .into_response();
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    if let Ok(value) = HeaderValue::from_str(request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

pub(crate) fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    (values.next().is_none()).then_some(first)
}

pub fn preflight(state: &GatewayRuntimeState, path: &str, headers: &HeaderMap) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let Some(method) = single_header(headers, "access-control-request-method") else {
        return rejection(404, "not_found", &request_id);
    };
    let Some(selected) = route(method, path) else {
        return rejection(404, "not_found", &request_id);
    };
    if !selected.operation.enabled(state) {
        return rejection(404, "not_found", &request_id);
    }
    let Some(origin) =
        single_header(headers, "origin").filter(|origin| state.cors_origins.contains(*origin))
    else {
        return rejection(403, "origin_required", &request_id);
    };
    if headers
        .get_all("access-control-request-headers")
        .iter()
        .count()
        > 1
        || single_header(headers, "access-control-request-headers").is_some_and(|names| {
            names.split(',').any(|name| {
                !matches!(
                    name.trim().to_ascii_lowercase().as_str(),
                    "content-type" | "x-mip-version" | "x-request-id"
                )
            })
        })
    {
        return rejection(403, "headers_not_allowed", &request_id);
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    for (name, value) in [
        ("access-control-allow-origin", origin),
        ("access-control-allow-methods", method),
        (
            "access-control-allow-headers",
            "content-type,x-mip-version,x-request-id",
        ),
        ("access-control-allow-credentials", "true"),
        ("cache-control", "no-store"),
        ("vary", "Origin"),
        ("x-request-id", request_id.as_str()),
    ] {
        response.headers_mut().insert(
            axum::http::HeaderName::from_static(name),
            HeaderValue::from_str(value).expect("validated header"),
        );
    }
    response
}

pub(crate) fn session_cookie(headers: &HeaderMap) -> Option<String> {
    let mut result = None;
    for header in headers.get_all("cookie") {
        for pair in header.to_str().ok()?.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if name == "sessionId" {
                if result.is_some() || canonical_uuid(value).is_none() {
                    return None;
                }
                result = Some(value.to_owned());
            }
        }
    }
    result
}

fn query(operation: Operation, raw: Option<&str>) -> Option<BTreeMap<String, Vec<String>>> {
    let mut query = BTreeMap::new();
    for (name, value) in url::form_urlencoded::parse(raw.unwrap_or("").as_bytes()) {
        if !matches!(operation, Operation::List | Operation::History)
            || !matches!(name.as_ref(), "limit" | "offset")
            || query.contains_key(name.as_ref())
        {
            return None;
        }
        let value_number: u32 = value.parse().ok()?;
        if value_number.to_string() != value
            || (name == "limit" && !(1..=100).contains(&value_number))
            || (name == "offset" && value_number > 10_000)
        {
            return None;
        }
        query.insert(name.into_owned(), vec![value.into_owned()]);
    }
    Some(query)
}

/// Called before generic idempotency. Every request needs a fresh session and
/// current membership; responses from this candidate bypass generic replay.
pub async fn admit(state: &GatewayRuntimeState, request: Request) -> Result<Request, Response> {
    let request_id = Uuid::new_v4().to_string();
    let fail = |status, code| rejection(status, code, &request_id);
    let selected = route(request.method().as_str(), request.uri().path())
        .ok_or_else(|| fail(404, "not_found"))?;
    if !selected.operation.enabled(state) {
        return Err(fail(404, "not_found"));
    }
    if state
        .service_token
        .as_ref()
        .is_none_or(|token| token.len() < 32)
    {
        return Err(fail(503, "administration_unavailable"));
    }
    let identity = request
        .extensions()
        .get::<GatewayIdentity>()
        .ok_or_else(|| fail(401, "authentication_required"))?
        .clone();
    let now = Utc::now().timestamp();
    let observed = identity
        .session_observed_at_unix
        .ok_or_else(|| fail(403, "own_session_required"))?;
    let expires = identity
        .expires_at_unix
        .ok_or_else(|| fail(403, "own_session_required"))?;
    let organization = selected.organization_id.to_string();
    if identity.source != AuthenticationSource::Session
        || identity.api_key_id.is_some()
        || identity.non_impersonated_session != Some(true)
        || canonical_uuid(&identity.user_id).is_none()
        || observed > now
        || now >= observed.saturating_add(30)
        || expires <= now
    {
        return Err(fail(403, "own_session_required"));
    }
    let cookie =
        session_cookie(request.headers()).ok_or_else(|| fail(403, "own_session_required"))?;
    if !selected.operation.read() {
        let origin = single_header(request.headers(), "origin")
            .filter(|origin| state.cors_origins.contains(*origin))
            .ok_or_else(|| fail(403, "origin_required"))?;
        if origin == "null" {
            return Err(fail(403, "origin_required"));
        }
        if single_header(request.headers(), "content-type")
            .is_none_or(|value| value.split(';').next().map(str::trim) != Some("application/json"))
        {
            return Err(fail(415, "application_json_required"));
        }
    }
    let query = query(selected.operation, request.uri().query())
        .ok_or_else(|| fail(400, "invalid_administration_request"))?;
    // Auth's session organization is the login/default organization. A human
    // can administer another organization only through its current membership
    // and exact action permission; the URL selects that authorization scope.
    let membership = state
        .memberships
        .get_membership(&identity.user_id, &organization)
        .await
        .map_err(|_| fail(503, "authorization_unavailable"))?;
    authorize_membership(
        selected.operation.permission(),
        &identity.user_id,
        &organization,
        membership.as_ref(),
    )
    .map_err(|_| fail(403, "action_not_authorized"))?;
    let (parts, body) = request.into_parts();
    let body = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        to_bytes(body, MAXIMUM_BODY_BYTES.min(state.maximum_body_bytes)),
    )
    .await
    .map_err(|_| fail(408, "request_timeout"))?
    .map_err(|_| fail(413, "payload_too_large"))?;
    validate_body(&selected, &body).map_err(|_| fail(400, "invalid_administration_request"))?;
    let valid_until = expires.min(observed.saturating_add(30));
    if Utc::now().timestamp() >= valid_until {
        return Err(fail(403, "session_observation_expired"));
    }
    let mut upstream = GatewayRequest::new(
        match parts.method.as_str() {
            "GET" => HttpMethod::Get,
            "PATCH" => HttpMethod::Patch,
            _ => HttpMethod::Post,
        },
        parts.uri.path(),
        Utc::now().timestamp_millis().try_into().unwrap_or_default(),
    );
    upstream.request_id = request_id.clone();
    upstream.query = query;
    upstream.body = (!body.is_empty()).then(|| body.to_vec());
    // Start from an empty header map. Client assertions, keys, cookies,
    // correlation IDs and producer-proof headers never cross this boundary.
    upstream
        .headers
        .insert("x-request-id".into(), request_id.clone());
    if !body.is_empty() {
        upstream
            .headers
            .insert("content-type".into(), "application/json".into());
    }
    let session_ref = format!(
        "urn:marty:session:sha256:{:x}",
        Sha256::digest(cookie.as_bytes())
    );
    if selected.operation.is_enrollment() {
        for (name, value) in [
            ("x-marty-enrollment-organization-id", organization.clone()),
            ("x-marty-enrollment-user-id", identity.user_id.clone()),
            ("x-marty-enrollment-session-ref", session_ref.clone()),
            ("x-marty-enrollment-observed-at", instant(observed)),
            ("x-marty-enrollment-valid-until", instant(valid_until)),
        ] {
            upstream.headers.insert(name.into(), value);
        }
    }
    if selected.operation.is_approval() {
        for (name, value) in [
            ("x-marty-approval-organization-id", organization.clone()),
            ("x-marty-approval-user-id", identity.user_id.clone()),
            (
                "x-marty-approval-session-ref",
                format!(
                    "urn:marty:session:sha256:{:x}",
                    Sha256::digest(cookie.as_bytes())
                ),
            ),
            ("x-marty-approval-observed-at", instant(observed)),
            ("x-marty-approval-valid-until", instant(valid_until)),
        ] {
            upstream.headers.insert(name.into(), value);
        }
    }
    let membership = membership.expect("authorized membership");
    let trusted = TrustedIdentityContext {
        user_id: Some(identity.user_id),
        organization_id: Some(organization),
        organization_permissions: membership.permissions.into_iter().collect(),
        organization_roles: membership.role_names.into_iter().collect(),
        required_permission: Some(selected.operation.permission().into()),
        ..Default::default()
    };
    let mut request = Request::from_parts(parts, Body::empty());
    let submitted =
        (!body.is_empty()).then(|| serde_json::from_slice(&body).expect("validated request"));
    request.extensions_mut().insert(AuthorizedAdmin {
        request: upstream,
        identity: trusted,
        request_id,
        route: selected,
        submitted,
        session_ref,
        valid_until,
    });
    Ok(request)
}

pub(crate) fn instant(unix: i64) -> String {
    DateTime::<Utc>::from_timestamp(unix, 0)
        .expect("validated session instant")
        .to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub async fn dispatch(state: Arc<GatewayRuntimeState>, request: Request) -> Response {
    let Some(authorized) = request.extensions().get::<AuthorizedAdmin>().cloned() else {
        return rejection(
            403,
            "administration_authorization_required",
            &Uuid::new_v4().to_string(),
        );
    };
    if Utc::now().timestamp() >= authorized.valid_until {
        return rejection(403, "session_observation_expired", &authorized.request_id);
    }
    let Some(token) = state.service_token.as_ref() else {
        return rejection(503, "administration_unavailable", &authorized.request_id);
    };
    let mut overrides = ProxyOverrides::default();
    overrides
        .headers
        .insert("x-service-token".into(), token.clone());
    let response = match state
        .proxy
        .execute(authorized.request, &authorized.identity, &overrides)
        .await
    {
        Ok(response) => response,
        Err(_) => {
            return rejection(
                502,
                "administration_dependency_unavailable",
                &authorized.request_id,
            )
        }
    };
    if !(200..300).contains(&response.status_code) {
        let status = match response.status_code {
            400 | 401 | 403 | 404 | 409 | 413 | 422 => response.status_code,
            _ => 502,
        };
        return rejection(
            status,
            "administration_request_rejected",
            &authorized.request_id,
        );
    }
    let Some(body) = response.body else {
        return rejection(
            502,
            "invalid_administration_response",
            &authorized.request_id,
        );
    };
    let value = match serde_json::from_slice::<UniqueValue>(&body) {
        Ok(value)
            if valid_response(
                &authorized.route,
                &authorized.identity,
                authorized.submitted.as_ref(),
                &authorized.session_ref,
                &value.0,
            ) =>
        {
            value.0
        }
        _ => {
            return rejection(
                502,
                "invalid_administration_response",
                &authorized.request_id,
            )
        }
    };
    let mut result = (
        StatusCode::from_u16(response.status_code).unwrap_or(StatusCode::OK),
        Json(value),
    )
        .into_response();
    result
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    result
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    result.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&authorized.request_id).expect("UUID header"),
    );
    result
}

pub(crate) fn fields(value: &Map<String, Value>, required: &[&str], optional: &[&str]) -> bool {
    required.iter().all(|name| value.contains_key(*name))
        && value
            .keys()
            .all(|name| required.contains(&name.as_str()) || optional.contains(&name.as_str()))
}
fn text_field(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        !text.trim().is_empty() && text.len() <= 2_048 && !text.chars().any(char::is_control)
    })
}
pub(crate) fn revision(value: &Value) -> bool {
    value
        .as_u64()
        .is_some_and(|number| (1..=MAX_REVISION).contains(&number))
}
pub(crate) fn digest(value: &Value) -> bool {
    value
        .as_str()
        .and_then(|v| v.strip_prefix("sha256:"))
        .is_some_and(|v| {
            v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}
fn public_key(value: &Value) -> bool {
    value.as_object().is_some_and(|key| {
        let required: &[&str] = match (
            key.get("kty").and_then(Value::as_str),
            key.get("crv").and_then(Value::as_str),
        ) {
            (Some("EC"), Some("P-256")) => &["kty", "crv", "x", "y"],
            (Some("OKP"), Some("Ed25519")) => &["kty", "crv", "x"],
            _ => return false,
        };
        fields(key, required, &["kid", "alg", "use", "key_ops"])
            && required.iter().all(|name| key[*name].as_str().is_some())
            && key.get("kid").is_none_or(|v| {
                v.as_str()
                    .is_some_and(|text| !text.is_empty() && text.chars().count() <= 512)
            })
            && key.get("alg").is_none_or(|v| {
                v.as_str().is_some_and(|algorithm| {
                    if key["crv"] == "P-256" {
                        algorithm == "ES256"
                    } else {
                        matches!(algorithm, "EdDSA" | "Ed25519")
                    }
                })
            })
            && key.get("use").is_none_or(|v| v == "sig")
            && key.get("key_ops").is_none_or(|v| v == &json!(["verify"]))
    })
}

pub fn validate_body(route: &AdminRoute, raw: &[u8]) -> Result<(), &'static str> {
    if route.operation.read() {
        return if raw.is_empty() {
            Ok(())
        } else {
            Err("body_not_allowed")
        };
    }
    if raw.len() > MAXIMUM_BODY_BYTES {
        return Err("oversize");
    }
    let value: UniqueValue = serde_json::from_slice(raw).map_err(|_| "invalid_json")?;
    let value = value.0.as_object().ok_or("object_required")?;
    let valid = match route.operation {
        Operation::Register => {
            fields(
                value,
                &[
                    "kind",
                    "display_name",
                    "logical_application_ref",
                    "issuer",
                    "subject",
                    "runtime_instance_ref",
                    "public_key_jwk",
                ],
                &["description"],
            ) && matches!(value["kind"].as_str(), Some("EXTERNAL" | "MANAGED"))
                && [
                    "display_name",
                    "logical_application_ref",
                    "issuer",
                    "subject",
                    "runtime_instance_ref",
                ]
                .into_iter()
                .all(|name| text_field(&value[name]))
                && public_key(&value["public_key_jwk"])
        }
        Operation::Update => {
            fields(
                value,
                &[
                    "expected_revision",
                    "display_name",
                    "logical_application_ref",
                ],
                &["description"],
            ) && revision(&value["expected_revision"])
                && text_field(&value["display_name"])
                && text_field(&value["logical_application_ref"])
        }
        Operation::RotateKey => {
            fields(value, &["expected_revision", "public_key_jwk"], &[])
                && revision(&value["expected_revision"])
                && public_key(&value["public_key_jwk"])
        }
        Operation::Suspend
        | Operation::Revoke
        | Operation::Retire
        | Operation::CreateEnrollmentChallenge => {
            fields(value, &["expected_revision"], &[]) && revision(&value["expected_revision"])
        }
        Operation::CompleteEnrollment => {
            fields(value, &["proof"], &[])
                && value["proof"]
                    .as_str()
                    .is_some_and(enrollment_response::compact_proof)
        }
        Operation::ReviewApproval => {
            fields(value, &["grant"], &[])
                && value["grant"].as_object().is_some_and(|grant| {
                    fields(grant, &["id", "revision", "terms_digest"], &[])
                        && grant["id"].as_str().and_then(canonical_uuid) == route.resource_id
                        && revision(&grant["revision"])
                        && digest(&grant["terms_digest"])
                })
        }
        Operation::ConfirmApproval => {
            fields(value, &["confirmation_id", "terms_digest", "decision"], &[])
                && value["confirmation_id"]
                    .as_str()
                    .and_then(canonical_uuid)
                    .is_some()
                && digest(&value["terms_digest"])
                && value["decision"].as_str() == Some("CONFIRM")
        }
        Operation::WithdrawApproval => value.is_empty(),
        _ => false,
    };
    if !valid
        || value.get("description").is_some_and(|v| {
            !v.is_null()
                && v.as_str()
                    .is_none_or(|text| text.len() > 2048 || text.contains('\0'))
        })
    {
        return Err("invalid_contract");
    }
    Ok(())
}

fn valid_agent(value: &Value, organization: Uuid, expected_id: Option<Uuid>) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let id = value["id"].as_str().and_then(canonical_uuid);
    fields(
        object,
        &[
            "id",
            "organization_id",
            "owner_user_id",
            "created_by",
            "kind",
            "status",
            "revision",
            "metadata",
            "principal",
            "issuer",
            "subject",
            "runtime_instance_ref",
            "keys",
            "provenance",
            "authority_status",
            "created_at",
            "updated_at",
        ],
        &[],
    ) && id.is_some()
        && expected_id.is_none_or(|expected| id == Some(expected))
        && value["organization_id"].as_str().and_then(canonical_uuid) == Some(organization)
        && value["authority_status"] == "NOT_ASSESSED"
        && revision(&value["revision"])
        && matches!(value["kind"].as_str(), Some("EXTERNAL" | "MANAGED"))
        && matches!(
            value["status"].as_str(),
            Some("PROVISIONED" | "ACTIVE" | "SUSPENDED" | "REVOKED" | "RETIRED")
        )
        && !(value["kind"] == "MANAGED"
            && value["status"] == "ACTIVE"
            && value["provenance"]["managed_enrollment"] != "KEY_CONTROL_VERIFIED")
        && value["provenance"].as_object().is_some_and(|provenance| {
            fields(
                provenance,
                &[
                    "kind",
                    "registered_by",
                    "registration_ref",
                    "managed_enrollment",
                    "external_authentication",
                ],
                &[],
            ) && provenance["kind"] == "OPERATOR_DECLARATION"
                && (provenance["managed_enrollment"] == "NOT_ASSESSED"
                    || (value["kind"] == "MANAGED"
                        && provenance["managed_enrollment"] == "KEY_CONTROL_VERIFIED"))
                && provenance["external_authentication"] == "NOT_ASSESSED"
        })
        && value["keys"].as_array().is_some_and(|keys| {
            keys.len() <= 1
                && keys.iter().all(|key| {
                    key.as_object().is_some_and(|key| {
                        fields(
                            key,
                            &[
                                "key_id",
                                "algorithm",
                                "status",
                                "fingerprint",
                                "public_key_jwk",
                                "created_at",
                            ],
                            &[],
                        )
                    }) && public_key(&key["public_key_jwk"])
                })
        })
}

fn valid_response(
    route: &AdminRoute,
    identity: &TrustedIdentityContext,
    submitted: Option<&Value>,
    session_ref: &str,
    value: &Value,
) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    match route.operation {
        Operation::CreateEnrollmentChallenge
        | Operation::InspectEnrollmentChallenge
        | Operation::CompleteEnrollment => {
            enrollment_response::valid_response(route, identity, submitted, session_ref, value)
        }
        Operation::List | Operation::History => {
            fields(object, &["items", "total", "limit", "offset"], &[])
                && value["total"].as_u64().is_some()
                && value["offset"].as_u64().is_some()
                && value["limit"]
                    .as_u64()
                    .is_some_and(|limit| (1..=100).contains(&limit))
                && value["items"].as_array().is_some_and(|items| {
                    items.len() <= 100
                        && items.iter().all(|item| {
                            if route.operation == Operation::History {
                                item.as_object().is_some_and(|event| {
                                    fields(
                                        event,
                                        &[
                                            "revision",
                                            "action",
                                            "actor_user_id",
                                            "request_id",
                                            "occurred_at",
                                            "snapshot",
                                        ],
                                        &[],
                                    )
                                }) && valid_agent(
                                    &item["snapshot"],
                                    route.organization_id,
                                    route.resource_id,
                                ) && item["revision"] == item["snapshot"]["revision"]
                            } else {
                                valid_agent(item, route.organization_id, None)
                            }
                        })
                })
        }
        Operation::ReviewApproval => {
            fields(
                object,
                &[
                    "review_id",
                    "grant",
                    "terms",
                    "issuer",
                    "created_at",
                    "expires_at",
                    "confirmation_max_age_seconds",
                ],
                &[],
            ) && value["review_id"]
                .as_str()
                .and_then(canonical_uuid)
                .is_some()
                && submitted.is_some_and(|input| value["grant"] == input["grant"])
                && response_contract::valid_review(route, identity.user_id.as_deref(), value)
        }
        Operation::ConfirmApproval => {
            fields(
                object,
                &[
                    "confirmation_id",
                    "review_id",
                    "grant_id",
                    "terms_digest",
                    "confirmed_at",
                    "valid_until",
                    "recovered",
                ],
                &[],
            ) && value["grant_id"].as_str().and_then(canonical_uuid) == route.resource_id
                && value["review_id"].as_str().and_then(canonical_uuid) == route.linked_id
                && submitted.is_some_and(|input| {
                    value["confirmation_id"] == input["confirmation_id"]
                        && value["terms_digest"] == input["terms_digest"]
                })
                && value["recovered"].is_boolean()
                && response_contract::ordered_instants(
                    &value["confirmed_at"],
                    &value["valid_until"],
                    300,
                )
        }
        Operation::WithdrawApproval => {
            fields(
                object,
                &["confirmation_id", "grant_id", "withdrawn_at", "recovered"],
                &[],
            ) && value["grant_id"].as_str().and_then(canonical_uuid) == route.resource_id
                && value["confirmation_id"].as_str().and_then(canonical_uuid) == route.linked_id
                && value["recovered"].is_boolean()
                && response_contract::timestamp(&value["withdrawn_at"]).is_some()
        }
        _ => valid_agent(value, route.organization_id, route.resource_id),
    }
}

/// Value projection which rejects duplicate names at every depth, including JWKs.
pub(crate) struct UniqueValue(pub(crate) Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Strict;
        impl<'de> Visitor<'de> for Strict {
            type Value = Value;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("unambiguous JSON")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Value, E> {
                Ok(Value::Bool(v))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Value, E> {
                Ok(v.into())
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Value, E> {
                Ok(v.into())
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Value, E> {
                Ok(v.into())
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Value, E> {
                Ok(v.into())
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<UniqueValue>()? {
                    values.push(value.0);
                }
                Ok(Value::Array(values))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
                let mut values = Map::new();
                while let Some(name) = map.next_key::<String>()? {
                    if values.contains_key(&name) {
                        return Err(serde::de::Error::custom("duplicate field"));
                    }
                    values.insert(name, map.next_value::<UniqueValue>()?.0);
                }
                Ok(Value::Object(values))
            }
        }
        deserializer.deserialize_any(Strict).map(Self)
    }
}

/// Candidate documentation is attached only when the matching opt-in is enabled.
pub fn extend_openapi(document: &mut Value, directory: bool, approval: bool) {
    document_routes(document, paths(directory, approval));
}

pub fn extend_enrollment_openapi(document: &mut Value, enabled: bool) {
    document_routes(document, enrollment_paths(enabled));
}

fn document_routes(document: &mut Value, routes: Vec<(HttpMethod, String, &'static str)>) {
    for (method, path, service) in routes {
        let method = match method {
            HttpMethod::Get => "get",
            HttpMethod::Patch => "patch",
            _ => "post",
        };
        let concrete = path
            .split('/')
            .map(|part| {
                if part.starts_with('{') {
                    "11111111-1111-4111-8111-111111111111"
                } else {
                    part
                }
            })
            .collect::<Vec<_>>()
            .join("/");
        let selected =
            route(&method.to_ascii_uppercase(), &concrete).expect("declared candidate route");
        let mut operation = json!({
            "tags":["Candidate agent administration"], "security":[{"sessionCookie":[]}],
            "description":"Opt-in human administration. Requires a current own non-impersonated session and exact tenant/action membership. Mutations require an allowed Origin. API keys cannot administer agents or supply approval. Directory metadata is an operator declaration. Explicit enrollment verifies registered key control only; external issuer/host trust, operational machine policy and delegated authority remain separate. Historical enrollment results do not authorize current use.",
            "x-marty-upstream-service":service, "x-marty-runtime-qualification":"NOT_ASSESSED",
            "responses":{"200":{"description":"Authorized administration result"},"400":{"description":"Invalid strict request"},"403":{"description":"Session, tenant, action or Origin denied"},"409":{"description":"Revision or confirmation conflict"},"503":{"description":"Dependency unavailable"}}
        });
        let mut parameters=path.split('/').filter_map(|part|part.strip_prefix('{').and_then(|part|part.strip_suffix('}')))
            .map(|name|json!({"name":name,"in":"path","required":true,"schema":{"type":"string","format":"uuid"}})).collect::<Vec<_>>();
        if matches!(selected.operation, Operation::List | Operation::History) {
            parameters.extend([json!({"name":"limit","in":"query","schema":{"type":"integer","minimum":1,"maximum":100,"default":50}}),
                json!({"name":"offset","in":"query","schema":{"type":"integer","minimum":0,"maximum":10000,"default":0}})]);
        }
        if !selected.operation.read() {
            parameters.push(json!({"name":"Origin","in":"header","required":true,"schema":{"type":"string","format":"uri"},"description":"Exactly one configured browser origin."}));
            operation["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":request_schema(selected.operation)}}});
        }
        operation["parameters"] = Value::Array(parameters);
        operation["x-marty-required-permission"] = json!(selected.operation.permission());
        document["paths"][&path][method] = operation;
    }
}

fn request_schema(operation: Operation) -> Value {
    let uuid = json!({"type":"string","format":"uuid"});
    let revision = json!({"type":"integer","minimum":1,"maximum":MAX_REVISION});
    let digest = json!({"type":"string","pattern":"^sha256:[0-9a-f]{64}$"});
    let text = json!({"type":"string","minLength":1,"maxLength":1024});
    let description = json!({"type":["string","null"],"maxLength":2048});
    let key = json!({"type":"object","description":"Public RFC 7517 JWK, P-256/ES256 or Ed25519/EdDSA. Private/symmetric members and unknown fields are rejected. Organization validates the public point and canonical encoding; submission is an operator declaration, not proof of possession.",
        "properties":{"kty":{"enum":["EC","OKP"]},"crv":{"enum":["P-256","Ed25519"]},"x":{"type":"string"},"y":{"type":"string"},
            "kid":{"type":"string","minLength":1,"maxLength":512},"alg":{"enum":["ES256","EdDSA","Ed25519"]},"use":{"const":"sig"},"key_ops":{"const":["verify"]}},
        "required":["kty","crv","x"],"additionalProperties":false});
    let (required, properties) = match operation {
        Operation::Register => (
            vec![
                "kind",
                "display_name",
                "logical_application_ref",
                "issuer",
                "subject",
                "runtime_instance_ref",
                "public_key_jwk",
            ],
            json!({"kind":{"enum":["EXTERNAL","MANAGED"]},"display_name":{"type":"string","minLength":1,"maxLength":200},"description":description,
                "logical_application_ref":text,"issuer":text,"subject":{"type":"string","minLength":1,"maxLength":512},"runtime_instance_ref":text,"public_key_jwk":key}),
        ),
        Operation::Update => (
            vec![
                "expected_revision",
                "display_name",
                "logical_application_ref",
            ],
            json!({"expected_revision":revision,"display_name":{"type":"string","minLength":1,"maxLength":200},"description":description,"logical_application_ref":text}),
        ),
        Operation::RotateKey => (
            vec!["expected_revision", "public_key_jwk"],
            json!({"expected_revision":revision,"public_key_jwk":key}),
        ),
        Operation::ReviewApproval => (
            vec!["grant"],
            json!({"grant":{"type":"object","additionalProperties":false,"required":["id","revision","terms_digest"],"properties":{"id":uuid,"revision":revision,"terms_digest":digest}}}),
        ),
        Operation::ConfirmApproval => (
            vec!["confirmation_id", "terms_digest", "decision"],
            json!({"confirmation_id":uuid,"terms_digest":digest,"decision":{"const":"CONFIRM"}}),
        ),
        Operation::WithdrawApproval => (vec![], json!({})),
        Operation::CompleteEnrollment => (
            vec!["proof"],
            json!({"proof":{"type":"string","description":"Compact JWS over the exact server-retained enrollment payload. Signed only by the registered runtime key; never send a private key.","maxLength":16000}}),
        ),
        _ => (
            vec!["expected_revision"],
            json!({"expected_revision":revision}),
        ),
    };
    json!({"type":"object","required":required,"properties":properties,"additionalProperties":false})
}

#[cfg(test)]
mod tests {
    use super::*;
    const ORG: &str = "11111111-1111-4111-8111-111111111111";
    #[test]
    fn directory_registration_rejects_claimed_authority_private_keys_and_nested_ambiguity() {
        let selected = route("POST", &format!("/v1/organizations/{ORG}/agents")).unwrap();
        let body = json!({"kind":"EXTERNAL","display_name":"Synthetic worker","description":"multiline\noperator note",
            "logical_application_ref":"urn:test:application","issuer":"https://issuer.example.invalid","subject":"worker",
            "runtime_instance_ref":"urn:test:runtime","public_key_jwk":{"kty":"OKP","crv":"Ed25519","x":"public-shape-checked-again-by-organization"}});
        assert!(validate_body(&selected, &serde_json::to_vec(&body).unwrap()).is_ok());
        for field in [
            "organization_id",
            "owner_user_id",
            "actor_id",
            "status",
            "authority_status",
            "managed_enrollment",
            "transaction_data",
        ] {
            let mut changed = body.clone();
            changed[field] = json!("caller-claim");
            assert!(
                validate_body(&selected, &serde_json::to_vec(&changed).unwrap()).is_err(),
                "{field}"
            );
        }
        for field in ["d", "p", "q", "k", "credential", "trusted"] {
            let mut changed = body.clone();
            changed["public_key_jwk"][field] = json!("must-not-forward");
            assert!(
                validate_body(&selected, &serde_json::to_vec(&changed).unwrap()).is_err(),
                "{field}"
            );
        }
        let raw = serde_json::to_string(&body)
            .unwrap()
            .replace("\"kty\":\"OKP\"", "\"kty\":\"OKP\",\"kty\":\"EC\"");
        assert!(validate_body(&selected, raw.as_bytes()).is_err());
    }
    #[test]
    fn candidate_routes_do_not_admit_runtime_enrollment_activation_or_delegated_use() {
        for path in [
            format!("/v1/organizations/{ORG}/agents/{ORG}/activate"),
            format!("/v1/organizations/{ORG}/agents/{ORG}/enroll"),
            format!("/v1/organizations/{ORG}/delegation-grants/{ORG}/start-use"),
            format!("/v1/organizations/{ORG}/delegation-grants/{ORG}/finalize-use"),
        ] {
            assert!(is_namespace(&path));
            assert!(route("POST", &path).is_none());
        }
        assert!(route(
            "POST",
            "/v1/organizations/00000000-0000-0000-0000-000000000000/agents"
        )
        .is_none());
        let mut document = json!({"paths":{}});
        extend_openapi(&mut document, true, true);
        assert_eq!(paths(true, true).len(), 12);
        for (method, path, _) in paths(true, true) {
            let method = match method {
                HttpMethod::Get => "get",
                HttpMethod::Patch => "patch",
                _ => "post",
            };
            assert_eq!(
                document["paths"][&path][method]["security"],
                json!([{"sessionCookie":[]}])
            );
            if method != "get" {
                assert_eq!(
                    document["paths"][&path][method]["requestBody"]["content"]["application/json"]
                        ["schema"]["additionalProperties"],
                    false
                );
            }
        }
    }
}
