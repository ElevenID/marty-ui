//! Opt-in human organization grant lifecycle transport. Original command bytes
//! and results belong to the authoritative service, never generic HTTP replay.
//! This route cannot authenticate a machine or start/finalize delegated use.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use axum::{
    body::{to_bytes, Body},
    extract::Request,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use mmf_platform::{
    AuthenticationType, GatewayRequest, HttpMethod, PlatformError, ProxyOverrides, RouteConfig,
    RouteMatchType, RouteTable, TrustedIdentityContext,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    agent_administration::{
        canonical_uuid, digest, fields, instant, rejection,
        response_contract::{timestamp, uri, valid_terms},
        revision, session_cookie, single_header, UniqueValue,
    },
    authorization::authorize_membership,
    middleware::{AuthenticationSource, GatewayIdentity},
    runtime::GatewayRuntimeState,
};

pub const PATH: &str = "/v1/organizations/{organization_id}/delegation-commands";
pub const MAXIMUM_BODY_BYTES: usize = 65_536;
const REQUEST_PROFILE: &str = "urn:marty:delegation-command:v1";
const RESPONSE_PROFILE: &str = "urn:marty:delegation-command-response:v1";

pub fn is_namespace(path: &str) -> bool {
    let parts = path.split('/').collect::<Vec<_>>();
    parts.len() >= 5
        && parts[..3] == ["", "v1", "organizations"]
        && parts[4] == "delegation-commands"
}

fn organization(method: &str, path: &str) -> Option<Uuid> {
    let parts = path.split('/').collect::<Vec<_>>();
    (method == "POST" && parts.len() == 5 && is_namespace(path))
        .then(|| canonical_uuid(parts[3]))
        .flatten()
}

pub fn add_routes(table: &mut RouteTable, enabled: bool) -> Result<(), PlatformError> {
    if enabled {
        table.add(RouteConfig {
            name: "candidate-delegation-commands".into(),
            pattern: PATH.into(),
            match_type: RouteMatchType::Template,
            upstream_service: "delegated-commands".into(),
            methods: BTreeSet::from([HttpMethod::Post]),
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

pub fn preflight(state: &GatewayRuntimeState, path: &str, headers: &HeaderMap) -> Response {
    let request_id = Uuid::new_v4().to_string();
    if !state.delegation_commands_enabled
        || single_header(headers, "access-control-request-method") != Some("POST")
        || organization("POST", path).is_none()
    {
        return rejection(404, "not_found", &request_id);
    }
    let Some(origin) = single_header(headers, "origin")
        .filter(|origin| *origin != "null" && state.cors_origins.contains(*origin))
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
        ("access-control-allow-methods", "POST"),
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

#[derive(Clone)]
struct Command {
    document: Value,
    permission: &'static str,
    original_id: Uuid,
    expected_digest: String,
}

// RFC 8785 subset of the closed P03 command and number-free grant terms. The
// service independently applies the authoritative decoder and digest contract.
fn canonical(value: &Value, depth: usize) -> Option<Vec<u8>> {
    if depth > 32 {
        return None;
    }
    match value {
        Value::Null => None,
        Value::Number(number) => number
            .as_u64()
            .filter(|n| *n <= 9_007_199_254_740_991)
            .map(|n| n.to_string().into_bytes()),
        Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            let mut bytes = vec![b'{'];
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    bytes.push(b',');
                }
                bytes.extend(serde_json::to_vec(key).ok()?);
                bytes.push(b':');
                bytes.extend(canonical(&map[key], depth + 1)?);
            }
            bytes.push(b'}');
            Some(bytes)
        }
        Value::Array(values) => {
            let mut bytes = vec![b'['];
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    bytes.push(b',');
                }
                bytes.extend(canonical(value, depth + 1)?);
            }
            bytes.push(b']');
            Some(bytes)
        }
        _ => serde_json::to_vec(value).ok(),
    }
}

fn content_digest(value: &Value) -> Option<String> {
    Some(format!("sha256:{:x}", Sha256::digest(canonical(value, 0)?)))
}

fn decode(raw: &[u8], org: Uuid, user: &str) -> Option<Command> {
    if raw.len() > MAXIMUM_BODY_BYTES {
        return None;
    }
    let document = serde_json::from_slice::<UniqueValue>(raw).ok()?.0;
    let object = document.as_object()?;
    if document["profile"] != REQUEST_PROFILE {
        return None;
    }
    let (required, permission): (&[&str], _) = match document["command"].as_str()? {
        "CREATE_GRANT" => (
            &["profile", "command", "command_id", "terms"],
            "delegation-grant:create",
        ),
        "APPROVE_GRANT" => (
            &[
                "profile",
                "command",
                "command_id",
                "grant",
                "confirmation_id",
            ],
            "delegation-grant:approve",
        ),
        "SUSPEND_GRANT" => (
            &["profile", "command", "command_id", "grant"],
            "delegation-grant:suspend",
        ),
        "REINSTATE_GRANT" => (
            &["profile", "command", "command_id", "grant"],
            "delegation-grant:reinstate",
        ),
        "REVOKE_GRANT" => (
            &["profile", "command", "command_id", "grant"],
            "delegation-grant:revoke",
        ),
        "RECOVER_RESULT" => (
            &[
                "profile",
                "command",
                "original_command_id",
                "expected_command_digest",
            ],
            "delegation-grant:view",
        ),
        _ => return None,
    };
    if !fields(object, required, &[]) {
        return None;
    }
    let recover = document["command"] == "RECOVER_RESULT";
    let original_id = canonical_uuid(
        document[if recover {
            "original_command_id"
        } else {
            "command_id"
        }]
        .as_str()?,
    )?;
    if let Some(grant) = object.get("grant") {
        if !fields(grant.as_object()?, &["id", "revision", "terms_digest"], &[])
            || canonical_uuid(grant["id"].as_str()?).is_none()
            || !revision(&grant["revision"])
            || !digest(&grant["terms_digest"])
        {
            return None;
        }
    }
    if document["command"] == "CREATE_GRANT"
        && (!valid_terms(org, &document["terms"])
            || document["terms"]["grantor"]
                != json!({"type":"USER", "id":format!("urn:marty:user:{user}")}))
    {
        return None;
    }
    if document["command"] == "APPROVE_GRANT"
        && canonical_uuid(document["confirmation_id"].as_str()?).is_none()
    {
        return None;
    }
    let calculated = content_digest(&document)?;
    let expected_digest = if recover {
        if !digest(&document["expected_command_digest"]) {
            return None;
        }
        document["expected_command_digest"].as_str()?.to_owned()
    } else {
        calculated
    };
    Some(Command {
        document,
        permission,
        original_id,
        expected_digest,
    })
}

#[derive(Clone)]
struct AuthorizedCommand {
    request: GatewayRequest,
    identity: TrustedIdentityContext,
    request_id: String,
    organization: Uuid,
    command: Command,
    valid_until: i64,
}

pub async fn admit(state: &GatewayRuntimeState, request: Request) -> Result<Request, Response> {
    let request_id = Uuid::new_v4().to_string();
    let fail = |status, code| rejection(status, code, &request_id);
    let org = organization(request.method().as_str(), request.uri().path())
        .filter(|_| state.delegation_commands_enabled)
        .ok_or_else(|| fail(404, "not_found"))?;
    if state
        .service_token
        .as_ref()
        .is_none_or(|token| token.len() < 32)
    {
        return Err(fail(503, "delegation_commands_unavailable"));
    }
    if request.uri().query().is_some() {
        return Err(fail(400, "invalid_delegation_command"));
    }
    let identity = request
        .extensions()
        .get::<GatewayIdentity>()
        .cloned()
        .ok_or_else(|| fail(401, "authentication_required"))?;
    let now = Utc::now().timestamp();
    let observed = identity
        .session_observed_at_unix
        .ok_or_else(|| fail(403, "own_session_required"))?;
    let expires = identity
        .expires_at_unix
        .ok_or_else(|| fail(403, "own_session_required"))?;
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
    single_header(request.headers(), "origin")
        .filter(|origin| *origin != "null" && state.cors_origins.contains(*origin))
        .ok_or_else(|| fail(403, "origin_required"))?;
    if single_header(request.headers(), "content-type")
        .is_none_or(|v| v.split(';').next().map(str::trim) != Some("application/json"))
    {
        return Err(fail(415, "application_json_required"));
    }
    let (parts, body) = request.into_parts();
    let body = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        to_bytes(body, MAXIMUM_BODY_BYTES.min(state.maximum_body_bytes)),
    )
    .await
    .map_err(|_| fail(408, "request_timeout"))?
    .map_err(|_| fail(413, "payload_too_large"))?;
    let command = decode(&body, org, &identity.user_id)
        .ok_or_else(|| fail(400, "invalid_delegation_command"))?;
    let organization_id = org.to_string();
    let membership = state
        .memberships
        .get_membership(&identity.user_id, &organization_id)
        .await
        .map_err(|_| fail(503, "authorization_unavailable"))?;
    authorize_membership(
        command.permission,
        &identity.user_id,
        &organization_id,
        membership.as_ref(),
    )
    .map_err(|_| fail(403, "action_not_authorized"))?;
    let valid_until = expires.min(observed.saturating_add(30));
    if Utc::now().timestamp() >= valid_until {
        return Err(fail(403, "session_observation_expired"));
    }
    let mut upstream = GatewayRequest::new(
        HttpMethod::Post,
        parts.uri.path(),
        Utc::now().timestamp_millis().try_into().unwrap_or_default(),
    );
    upstream.request_id = request_id.clone();
    upstream.body = Some(body.to_vec());
    // Rebuild from authenticated state. Never forward cookies, caller identity,
    // proof assertions, alternate authorization, or generic idempotency headers.
    for (name, value) in [
        ("content-type", "application/json".to_owned()),
        ("x-request-id", request_id.clone()),
        ("x-marty-command-organization-id", organization_id.clone()),
        ("x-marty-command-user-id", identity.user_id.clone()),
        (
            "x-marty-command-session-ref",
            format!(
                "urn:marty:session:sha256:{:x}",
                Sha256::digest(cookie.as_bytes())
            ),
        ),
        ("x-marty-command-observed-at", instant(observed)),
        ("x-marty-command-valid-until", instant(valid_until)),
    ] {
        upstream.headers.insert(name.into(), value);
    }
    let membership = membership.expect("authorized membership");
    let trusted = TrustedIdentityContext {
        user_id: Some(identity.user_id),
        organization_id: Some(organization_id),
        organization_permissions: membership.permissions.into_iter().collect(),
        organization_roles: membership.role_names.into_iter().collect(),
        required_permission: Some(command.permission.into()),
        ..Default::default()
    };
    let mut request = Request::from_parts(parts, Body::empty());
    request.extensions_mut().insert(AuthorizedCommand {
        request: upstream,
        identity: trusted,
        request_id,
        organization: org,
        command,
        valid_until,
    });
    Ok(request)
}

fn valid_snapshot(org: Uuid, grant: &Value) -> bool {
    let Some(object) = grant.as_object() else {
        return false;
    };
    if !fields(
        object,
        &[
            "profile",
            "id",
            "organization_id",
            "authority",
            "terms",
            "terms_digest",
            "status",
            "revision",
            "created_at",
            "updated_at",
        ],
        &["approval"],
    ) || grant["profile"] != "urn:marty:delegation-grant:v1"
        || grant["id"].as_str().and_then(canonical_uuid).is_none()
        || grant["organization_id"] != org.to_string()
        || !revision(&grant["revision"])
        || !valid_terms(org, &grant["terms"])
        || !digest(&grant["terms_digest"])
        || !matches!(
            grant["status"].as_str(),
            Some("PENDING" | "ACTIVE" | "SUSPENDED" | "REVOKED" | "EXPIRED")
        )
    {
        return false;
    }
    let authority = &grant["authority"];
    if !authority
        .as_object()
        .is_some_and(|v| fields(v, &["mode", "issuer", "status_ref"], &[]))
        || authority["mode"] != "MANAGED"
        || authority["issuer"]
            != json!({"type":"ORGANIZATION","id":format!("urn:marty:organization:{org}")})
        || !uri(&authority["status_ref"])
        || !authority["status_ref"]
            .as_str()
            .is_some_and(|value| value.starts_with("https://"))
    {
        return false;
    }
    let Some(created) = timestamp(&grant["created_at"]) else {
        return false;
    };
    let Some(updated) = timestamp(&grant["updated_at"]) else {
        return false;
    };
    if created > updated {
        return false;
    }
    let committed_terms = json!({"profile":grant["profile"],"id":grant["id"],"organization_id":grant["organization_id"],"authority":authority,"terms":grant["terms"]});
    if content_digest(&committed_terms).as_deref() != grant["terms_digest"].as_str() {
        return false;
    }
    if matches!(grant["status"].as_str(), Some("ACTIVE" | "SUSPENDED"))
        && object.get("approval").is_none()
    {
        return false;
    }
    if grant["status"] == "PENDING" && object.contains_key("approval") {
        return false;
    }
    if let Some(approval) = object.get("approval") {
        if !approval.as_object().is_some_and(|v| {
            fields(
                v,
                &[
                    "profile",
                    "grant_id",
                    "approver",
                    "evidence_ref",
                    "authority_evidence_ref",
                    "terms_digest",
                    "approved_at",
                ],
                &[],
            )
        }) || approval["grant_id"] != grant["id"]
            || approval["terms_digest"] != grant["terms_digest"]
            || approval["approver"] != grant["terms"]["grantor"]
            || !uri(&approval["profile"])
            || !uri(&approval["evidence_ref"])
            || !uri(&approval["authority_evidence_ref"])
            || timestamp(&approval["approved_at"])
                .is_none_or(|approved| approved < created || approved > updated)
        {
            return false;
        }
    }
    true
}

fn valid_response(org: Uuid, command: &Command, value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if !fields(
        object,
        &[
            "profile",
            "original_command_id",
            "command_digest",
            "recovered",
            "result",
        ],
        &[],
    ) || value["profile"] != RESPONSE_PROFILE
        || value["original_command_id"] != command.original_id.to_string()
        || value["command_digest"] != command.expected_digest
        || !value["recovered"].is_boolean()
        || !value["result"]
            .as_object()
            .is_some_and(|v| fields(v, &["kind", "grant"], &[]))
        || value["result"]["kind"] != "GRANT_SNAPSHOT"
        || !valid_snapshot(org, &value["result"]["grant"])
    {
        return false;
    }
    let grant = &value["result"]["grant"];
    match command.document["command"].as_str() {
        Some("RECOVER_RESULT") => value["recovered"] == true,
        Some("CREATE_GRANT") => {
            grant["status"] == "PENDING"
                && grant["revision"] == 1
                && grant["terms"] == command.document["terms"]
        }
        Some(name) => {
            let expected = &command.document["grant"];
            let status = match name {
                "APPROVE_GRANT" | "REINSTATE_GRANT" => "ACTIVE",
                "SUSPEND_GRANT" => "SUSPENDED",
                "REVOKE_GRANT" => "REVOKED",
                _ => return false,
            };
            grant["id"] == expected["id"]
                && grant["terms_digest"] == expected["terms_digest"]
                && grant["status"] == status
                && grant["revision"].as_u64()
                    == expected["revision"].as_u64().and_then(|v| v.checked_add(1))
        }
        _ => false,
    }
}

pub async fn dispatch(state: Arc<GatewayRuntimeState>, request: Request) -> Response {
    let Some(authorized) = request.extensions().get::<AuthorizedCommand>().cloned() else {
        return rejection(
            403,
            "delegation_authorization_required",
            &Uuid::new_v4().to_string(),
        );
    };
    let fail = |status, code| rejection(status, code, &authorized.request_id);
    if Utc::now().timestamp() >= authorized.valid_until {
        return fail(403, "session_observation_expired");
    }
    let Some(token) = state.service_token.as_ref() else {
        return fail(503, "delegation_commands_unavailable");
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
        Err(_) => return fail(502, "delegation_dependency_unavailable"),
    };
    if response.status_code != 200 {
        let status = match response.status_code {
            400 | 401 | 403 | 404 | 409 | 413 | 422 => response.status_code,
            _ => 502,
        };
        return fail(status, "delegation_command_rejected");
    }
    let Some(body) = response
        .body
        .filter(|body| body.len() <= MAXIMUM_BODY_BYTES * 2)
    else {
        return fail(502, "invalid_delegation_response");
    };
    let value = match serde_json::from_slice::<UniqueValue>(&body) {
        Ok(value) if valid_response(authorized.organization, &authorized.command, &value.0) => {
            value.0
        }
        _ => return fail(502, "invalid_delegation_response"),
    };
    let mut response = (StatusCode::OK, Json(value)).into_response();
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&authorized.request_id).expect("UUID header"),
    );
    response
}

pub fn extend_openapi(document: &mut Value, enabled: bool) {
    if !enabled {
        return;
    }
    document["paths"][PATH] = json!({"post":{
        "operationId":"submitDelegationLifecycleCommand", "tags":["Candidate delegation administration"],
        "summary":"Submit or recover a human organization grant lifecycle command",
        "description":"Explicit opt-in. Current own human session, Origin and per-command organization permission are required. Retain original command ID, exact intent and digest for recovery. Historical snapshots do not authorize use. START_USE and FINALIZE_USE are unsupported. No automatic retries or generic Idempotency-Key cache.",
        "security":[{"sessionCookie":[]}], "parameters":[{"name":"organization_id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}],
        "requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","description":"Strict urn:marty:delegation-command:v1 lifecycle command; closed, command-specific fields."}}}},
        "responses":{"200":{"description":"Original immutable command result; recovered indicates historical recovery."},"400":{"description":"Invalid or unsupported command"},"403":{"description":"Current human/session/permission requirements failed"},"404":{"description":"No result found; this does not prove that work is not in progress"},"409":{"description":"Command identity or grant revision conflicts"},"502":{"description":"Dependency or response validation failed; reconcile original command identity"}}
    }});
}
