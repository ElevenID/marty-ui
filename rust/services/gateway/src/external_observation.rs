// SPDX-License-Identifier: AGPL-3.0-only
use axum::{
    body::{to_bytes, Body},
    extract::Request,
    http::{HeaderMap, StatusCode},
};
use std::time::Duration;
use uuid::Uuid;

pub const PATH: &str = "/v1/evidence/observations";
pub const OWNERSHIP_PATHS: [&str; 5] = [
    "/v1/organizations/{organization_id}/application-ownerships/{application_id}/propose",
    "/v1/organizations/{organization_id}/application-ownerships/{application_id}/confirm",
    "/v1/organizations/{organization_id}/application-ownerships/{application_id}/revoke",
    "/v1/organizations/{organization_id}/application-ownerships/{application_id}/inspect",
    "/v1/organizations/{organization_id}/application-ownerships/{application_id}/receipt",
];
pub const MAX_BODY_BYTES: usize = 65_536;
pub type Rejection = (StatusCode, &'static str);
pub fn ownership_operation(action: &str) -> serde_json::Value {
    use serde_json::json;
    let mut properties = json!({});
    let mut required = Vec::new();
    if action != "inspect" {
        properties["operation_id"] = json!({"type":"string","format":"uuid"});
        required.push("operation_id");
    }
    if matches!(action, "propose" | "confirm" | "revoke") {
        properties["expected_revision"] = json!({"type":"integer","minimum":if action=="propose" {0} else {1},"maximum":9007199254740990_u64});
        properties["expected_application_revision"] =
            json!({"type":"integer","minimum":1,"maximum":9007199254740991_u64});
        required.extend(["expected_revision", "expected_application_revision"]);
    }
    if action == "propose" {
        properties["user_id"] = json!({"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9][A-Za-z0-9_-]*$"});
        required.push("user_id");
    }
    json!({"operationId":format!("{action}_application_ownership"),"tags":["applications"],
      "summary":format!("{action} canonical application ownership"),
      "description":"Session-only with exact active tenant and allowed Origin. Producer API keys are rejected. Propose/revoke require current canonical application:manage-ownership; confirmation is restricted to the proposed authenticated user. Original JSON is bounded to4096bytes and rejects duplicate/unknown fields. Core derives subject from the current issuance application. Reconcile unknown outcomes using the original operation; no automatic retries. Receipt results are historical and confer no current ownership; inspect returns separately revalidated current state. This grants no evidence scope, verification, approval, signing, issuance or provider association.",
      "security":[{"sessionCookie":[]}],
      "parameters":[{"name":"organization_id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}},
        {"name":"application_id","in":"path","required":true,"schema":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"}},
        {"name":"Origin","in":"header","required":true,"schema":{"type":"string","format":"uri"}}],
      "requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","additionalProperties":false,"properties":properties,"required":required}}}},
      "responses":{"200":{"description":"No-store original operation receipt or current ownership result"},"400":{"description":"Invalid original request"},
        "401":{"description":"Session required"},"403":{"description":"Current tenant, permission or intended learner denied"},
        "409":{"description":"Revision conflict"},"503":{"description":"Unavailable or uncertain commit; reconcile original operation"}}})
}
const INVALID: Rejection = (StatusCode::BAD_REQUEST, "invalid_observation_request");

pub fn openapi_operation() -> serde_json::Value {
    use serde_json::json;
    let identifier =
        json!({"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"});
    let positive = json!({"type":"integer","minimum":1,"maximum":9007199254740991_u64});
    json!({
        "operationId":"submit_external_observation", "tags":["evidence"],
        "summary":"Submit an unsigned producer observation",
        "description":"Requires exact evidence:submit scope on a canonical organization API key plus an administrator-approved producer grant and current binding. Tenant, subject, source and application authority come from core. A receipt never verifies evidence or authorizes issuance. Retry uncertain outcomes using the same observation ID and original content.",
        "security":[{"apiKeyAuth":[]},{"bearerAuth":[]}],
        "parameters":[{"name":"Idempotency-Key","in":"header","required":true,"schema":identifier,
          "description":"Must equal observation_id. Exact retries reauthorize and return the original receipt."}],
        "requestBody":{"required":true,"content":{"application/json":{"schema":{
          "type":"object","additionalProperties":false,
          "required":["binding_id","binding_revision","observation_id","sequence","observed_at_ms","effective_at_ms","claims"],
          "properties":{"binding_id":identifier,"observation_id":identifier,"binding_revision":positive,
            "sequence":positive,"observed_at_ms":positive,"effective_at_ms":positive,
            "claims":{"type":"object","maxProperties":32,"additionalProperties":{"oneOf":[
              {"type":"boolean"},{"type":"null"},{"type":"number"},
              {"type":"string","maxLength":512,"description":"Additionally bounded to 512 UTF-8 bytes."}]}}},
          "description":"Original JSON bytes limited to 65536 bytes. Duplicate fields, nested claims, unknown fields and ambiguous framing are rejected. Claim names/types/ranges must match the current binding."
        }}}},
        "responses":{
          "200":{"description":"Durable unsigned receipt; exact retries have replayed=true.","content":{"application/json":{"schema":{
            "type":"object","additionalProperties":false,"required":["receipt_id","replayed"],
            "properties":{"receipt_id":{"type":"string","format":"uuid"},"replayed":{"type":"boolean"}}}}}},
          "400":{"description":"Invalid observation request"},"401":{"description":"Actual organization API-key authentication required"},
          "403":{"description":"Exact scope or canonical delegation missing"},"409":{"description":"Authority/replay/sequence conflict"},
          "413":{"description":"Observation exceeds 65536 bytes"},"415":{"description":"Unsupported representation"},
          "503":{"description":"Unavailable or uncertain commit; reconcile using the same observation ID"}
        }
    })
}

fn one<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, Rejection> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(INVALID);
    }
    first
        .map(|value| value.to_str().map_err(|_| INVALID))
        .transpose()
}
fn canonical_id(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
    })
}

/// Identity parameters must come solely from successful Gateway authentication.
/// This guard reads bounded original bytes before shared tenant/body middleware.
pub async fn admit(
    request: Request,
    api_key_identity: bool,
    key_id: Option<&str>,
    organization_id: Option<&str>,
    scopes: &[String],
) -> Result<Request, Rejection> {
    if !api_key_identity || !canonical_id(key_id) || !canonical_id(organization_id) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "observation_authentication_required",
        ));
    }
    if !scopes.iter().any(|scope| scope == "evidence:submit") {
        return Err((StatusCode::FORBIDDEN, "observation_not_authorized"));
    }
    if request.method() != "POST" || request.uri().query().is_some() {
        return Err(INVALID);
    }
    let headers = request.headers();
    let key = one(headers, "x-api-key")?;
    let bearer = one(headers, "authorization")?;
    if key.is_some() == bearer.is_some() {
        return Err(INVALID);
    }
    let content = one(headers, "content-type")?.ok_or(INVALID)?;
    let mut parts = content.split(';').map(str::trim);
    if !parts
        .next()
        .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
    {
        return Err(INVALID);
    }
    if let Some(parameter) = parts.next() {
        let (name, value) = parameter.split_once('=').ok_or(INVALID)?;
        if !name.trim().eq_ignore_ascii_case("charset")
            || !matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "utf-8" | "\"utf-8\""
            )
            || parts.next().is_some()
        {
            return Err(INVALID);
        }
    }
    if content.len() > 128
        || one(headers, "content-encoding")?
            .is_some_and(|value| !value.trim().eq_ignore_ascii_case("identity"))
    {
        return Err(INVALID);
    }
    let length = one(headers, "content-length")?;
    let transfer = one(headers, "transfer-encoding")?;
    if headers.contains_key("trailer")
        || (length.is_some() && transfer.is_some())
        || transfer.is_some_and(|value| !value.trim().eq_ignore_ascii_case("chunked"))
    {
        return Err(INVALID);
    }
    let expected = length
        .map(|value| {
            if value.is_empty()
                || value.len() > 20
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(INVALID);
            }
            value.parse::<usize>().map_err(|_| INVALID)
        })
        .transpose()?;
    if expected.is_some_and(|value| value > MAX_BODY_BYTES) {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "observation_too_large"));
    }
    let idempotency = one(headers, "idempotency-key")?.ok_or(INVALID)?;
    if idempotency.is_empty()
        || idempotency.len() > 128
        || !idempotency
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
    {
        return Err(INVALID);
    }
    let (parts, body) = request.into_parts();
    let bytes =
        match tokio::time::timeout(Duration::from_secs(10), to_bytes(body, MAX_BODY_BYTES)).await {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(_)) => return Err((StatusCode::PAYLOAD_TOO_LARGE, "observation_too_large")),
            Err(_) => return Err((StatusCode::REQUEST_TIMEOUT, "observation_body_timeout")),
        };
    if expected.is_some_and(|length| length != bytes.len()) {
        return Err(INVALID);
    }
    Ok(Request::from_parts(parts, Body::from(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: &str = "10000000-0000-4000-8000-000000000001";
    const ORG: &str = "20000000-0000-4000-8000-000000000001";
    fn request(bytes: Vec<u8>) -> Request {
        Request::builder()
            .method("POST")
            .uri(PATH)
            .header("x-api-key", "synthetic-key")
            .header("content-type", "application/json")
            .header("idempotency-key", "observation-one")
            .body(Body::from(bytes))
            .unwrap()
    }
    #[tokio::test]
    async fn original_bytes_survive_without_json_reencoding() {
        let bytes = br#"{ "claim": false, "claim": true }"#.to_vec();
        let result = admit(
            request(bytes.clone()),
            true,
            Some(KEY),
            Some(ORG),
            &["evidence:submit".into()],
        )
        .await
        .unwrap();
        assert_eq!(
            to_bytes(result.into_body(), MAX_BODY_BYTES)
                .await
                .unwrap()
                .as_ref(),
            bytes
        );
    }
    #[tokio::test]
    async fn only_actual_key_identity_and_exact_scope_are_admitted() {
        for scope in ["admin:full", "evidence:*", "*", "integrations:write"] {
            assert_eq!(
                admit(request(vec![]), true, Some(KEY), Some(ORG), &[scope.into()])
                    .await
                    .unwrap_err()
                    .0,
                StatusCode::FORBIDDEN
            );
        }
        assert_eq!(
            admit(
                request(vec![]),
                false,
                Some(KEY),
                Some(ORG),
                &["evidence:submit".into()]
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::UNAUTHORIZED
        );
    }
    #[tokio::test]
    async fn duplicate_headers_and_oversized_or_misframed_bodies_fail() {
        let scopes = ["evidence:submit".into()];
        for name in ["content-type", "idempotency-key", "x-api-key"] {
            let mut duplicate = request(vec![]);
            duplicate
                .headers_mut()
                .append(name, "duplicate".parse().unwrap());
            assert_eq!(
                admit(duplicate, true, Some(KEY), Some(ORG), &scopes)
                    .await
                    .unwrap_err()
                    .0,
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            admit(request(vec![0; 65537]), true, Some(KEY), Some(ORG), &scopes)
                .await
                .unwrap_err()
                .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let mut mismatch = request(vec![0; 10]);
        mismatch
            .headers_mut()
            .insert("content-length", "9".parse().unwrap());
        assert_eq!(
            admit(mismatch, true, Some(KEY), Some(ORG), &scopes)
                .await
                .unwrap_err()
                .0,
            StatusCode::BAD_REQUEST
        );
    }
}

/// Canonical namespaces eligible for session-only Core administration/consent.
pub const ADMIN_PATH: &str =
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
pub const BINDING_REPLACE_PATH: &str = "/v1/organizations/{organization_id}/external-observation-bindings/{binding_id}/replace-definition";
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
pub const MATERIALIZE_PATH: &str = "/v1/organizations/{organization_id}/external-observation-receipts/{observation_id}/materialize";
pub const MATERIALIZATION_READ_PATH: &str = "/v1/organizations/{organization_id}/external-observation-receipts/{observation_id}/materialization";
/// Reserved administrator namespaces must enter the guard even when a path
/// identifier is malformed. Canonical parsing is authorization, not routing.
pub fn is_admin_namespace(path: &str) -> bool {
    let mut parts = path.split('/');
    if parts.next() != Some("")
        || parts.next() != Some("v1")
        || parts.next() != Some("organizations")
        || parts.next().is_none()
    {
        return false;
    }
    matches!(
        parts.next(),
        Some(
            "external-observation-producers"
                | "external-observation-bindings"
                | "external-observation-receipts"
                | "application-ownerships"
        )
    )
}
pub fn admin_organization(path: &str) -> Option<&str> {
    let parts: Vec<_> = path.split('/').collect();
    if parts.len() != 7
        || !parts[0].is_empty()
        || parts[1] != "v1"
        || parts[2] != "organizations"
        || !canonical_id(Some(parts[3]))
    {
        return None;
    }
    let valid = match parts[4] {
        "external-observation-producers" => {
            canonical_id(Some(parts[5]))
                && matches!(
                    parts[6],
                    "revoke"
                        | "approve"
                        | "rotate-api-key"
                        | "create"
                        | "change-expiry"
                        | "replace-bindings"
                        | "inspect"
                        | "audit"
                )
        }
        "external-observation-bindings" => {
            !parts[5].is_empty()
                && parts[5].len() <= 128
                && parts[5]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                && matches!(
                    parts[6],
                    "create"
                        | "activate"
                        | "deactivate"
                        | "replace-definition"
                        | "inspect"
                        | "audit"
                )
        }
        "application-ownerships" => {
            !parts[5].is_empty()
                && parts[5].len() <= 128
                && parts[5]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                && matches!(
                    parts[6],
                    "propose" | "confirm" | "revoke" | "inspect" | "receipt"
                )
        }
        "external-observation-receipts" => {
            !parts[5].is_empty()
                && parts[5].len() <= 128
                && parts[5]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                && matches!(parts[6], "inspect" | "materialize" | "materialization")
        }
        _ => false,
    };
    valid.then_some(parts[3])
}
/// Permissions or intended-learner ownership are reloaded and locked by Core.
/// This guard requires a session, canonical active tenant and allowed Origin.
pub async fn admit_admin(
    request: Request,
    session_identity: bool,
    organization_id: Option<&str>,
    user_id: &str,
    allowed_origin: bool,
) -> Result<Request, Rejection> {
    if !session_identity
        || !canonical_id(organization_id)
        || user_id.is_empty()
        || user_id.len() > 255
        || user_id.chars().any(char::is_control)
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            "administrator_authentication_required",
        ));
    }
    if !allowed_origin || admin_organization(request.uri().path()) != organization_id {
        return Err((StatusCode::FORBIDDEN, "administrator_not_authorized"));
    }
    if request.method() != "POST" || request.uri().query().is_some() {
        return Err(INVALID);
    }
    let headers = request.headers();
    if !one(headers, "content-type")?.is_some_and(|v| v.eq_ignore_ascii_case("application/json")) {
        return Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_admin_format",
        ));
    }
    if one(headers, "content-encoding")?.is_some_and(|v| !v.eq_ignore_ascii_case("identity"))
        || one(headers, "transfer-encoding")?.is_some_and(|v| !v.eq_ignore_ascii_case("chunked"))
        || headers.contains_key("trailer")
    {
        return Err(INVALID);
    }
    let length = one(headers, "content-length")?;
    if length.is_some() && headers.contains_key("transfer-encoding") {
        return Err(INVALID);
    }
    let expected = match length {
        Some(v) if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) => {
            Some(v.parse::<usize>().map_err(|_| INVALID)?)
        }
        Some(_) => return Err(INVALID),
        None => None,
    };
    if expected.is_some_and(|n| n > 4096) {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "admin_request_too_large"));
    }
    let (parts, body) = request.into_parts();
    let bytes = match tokio::time::timeout(Duration::from_secs(10), to_bytes(body, 4096)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => return Err((StatusCode::PAYLOAD_TOO_LARGE, "admin_request_too_large")),
        Err(_) => return Err((StatusCode::REQUEST_TIMEOUT, "admin_body_timeout")),
    };
    if expected.is_some_and(|n| n != bytes.len()) {
        return Err(INVALID);
    }
    Ok(Request::from_parts(parts, Body::from(bytes)))
}

#[cfg(test)]
mod admin_guard_tests {
    use super::*;
    const ORG: &str = "20000000-0000-4000-8000-000000000001";
    const ROUTE: &str="/v1/organizations/20000000-0000-4000-8000-000000000001/external-observation-producers/30000000-0000-4000-8000-000000000001/revoke";
    fn request() -> Request {
        Request::builder()
            .method("POST")
            .uri(ROUTE)
            .header("content-type", "application/json")
            .body(Body::from("{ \"expected_revision\":2 }".replace("\\", "")))
            .unwrap()
    }
    #[tokio::test]
    async fn administrator_guard_is_session_tenant_origin_and_framing_bound() {
        assert_eq!(
            admit_admin(request(), false, Some(ORG), "admin-one", true)
                .await
                .unwrap_err()
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            admit_admin(request(), true, Some(ORG), "admin-one", false)
                .await
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            admit_admin(
                request(),
                true,
                Some("20000000-0000-4000-8000-000000000002"),
                "admin-one",
                true
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::FORBIDDEN
        );
        let mut ambiguous = request();
        ambiguous
            .headers_mut()
            .append("content-type", "application/json".parse().unwrap());
        assert_eq!(
            admit_admin(ambiguous, true, Some(ORG), "admin-one", true)
                .await
                .unwrap_err()
                .0,
            StatusCode::BAD_REQUEST
        );
        let mut oversized = request();
        *oversized.body_mut() = Body::from(vec![b' '; 4097]);
        assert_eq!(
            admit_admin(oversized, true, Some(ORG), "admin-one", true)
                .await
                .unwrap_err()
                .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let accepted = admit_admin(request(), true, Some(ORG), "admin-one", true)
            .await
            .unwrap();
        let bytes = to_bytes(accepted.into_body(), 4096).await.unwrap();
        assert_eq!(bytes.as_ref(), br#"{ "expected_revision":2 }"#);
    }
    #[test]
    fn administrator_route_requires_exact_canonical_identifiers() {
        assert_eq!(admin_organization(ROUTE), Some(ORG));
        for path in [
            format!("{ROUTE}/"),
            ROUTE.replace(ORG, "org-1"),
            ROUTE.replace("/revoke", "/delete"),
            ROUTE.replace("/external-observation-producers/", "/api-keys/"),
        ] {
            assert_eq!(admin_organization(&path), None);
        }
    }
}

#[cfg(test)]
mod grant_edit_guard_tests {
    use super::*;
    #[tokio::test]
    async fn creation_and_expiry_paths_use_the_session_tenant_and_origin_guard() {
        let org = "20000000-0000-4000-8000-000000000001";
        for action in ["create", "change-expiry", "replace-bindings"] {
            let path=format!("/v1/organizations/{org}/external-observation-producers/30000000-0000-4000-8000-000000000001/{action}");
            assert_eq!(admin_organization(&path), Some(org));
            let request = || {
                Request::builder()
                    .method("POST")
                    .uri(&path)
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap()
            };
            assert!(admit_admin(request(), true, Some(org), "admin-one", true)
                .await
                .is_ok());
            assert_eq!(
                admit_admin(request(), false, Some(org), "admin-one", true)
                    .await
                    .unwrap_err()
                    .0,
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                admit_admin(request(), true, Some(org), "admin-one", false)
                    .await
                    .unwrap_err()
                    .0,
                StatusCode::FORBIDDEN
            );
            assert_eq!(
                admit_admin(
                    request(),
                    true,
                    Some("20000000-0000-4000-8000-000000000002"),
                    "admin-one",
                    true
                )
                .await
                .unwrap_err()
                .0,
                StatusCode::FORBIDDEN
            );
        }
    }
}

pub fn binding_admin_operation(action: &str) -> serde_json::Value {
    use serde_json::json;
    let identifier =
        json!({"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"});
    let label =
        json!({"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_.:-]+$"});
    let revision = json!({"type":"integer","minimum":1,"maximum":9007199254740991_u64});
    let (operation, summary) = match action {
        "create" => (
            "create_external_observation_binding",
            "Create an inactive canonical external observation binding",
        ),
        "replace-definition" => (
            "replace_external_observation_binding_definition",
            "Replace binding constraints and invalidate linked producer approvals",
        ),
        "activate" => (
            "activate_external_observation_binding",
            "Activate a canonical binding and invalidate linked grant approvals",
        ),
        _ => (
            "deactivate_external_observation_binding",
            "Deactivate a canonical binding and invalidate linked grant approvals",
        ),
    };
    let mut properties = json!({"expected_revision":revision});
    let mut required = vec!["expected_revision"];
    if matches!(action, "create" | "replace-definition") {
        let common = json!({"required":{"type":"boolean"},"nullable":{"type":"boolean"}});
        let rule = |kind: &str, extras: serde_json::Value, names: Vec<&str>| {
            let mut props = common.clone();
            props
                .as_object_mut()
                .expect("static object")
                .insert("kind".into(), json!({"const":kind}));
            props
                .as_object_mut()
                .expect("static object")
                .extend(extras.as_object().expect("static object").clone());
            let mut required = vec!["kind", "required", "nullable"];
            required.extend(names);
            json!({"type":"object","additionalProperties":false,"properties":props,"required":required})
        };
        properties = json!({"source_id":identifier,"application_id":identifier,"expected_application_revision":revision,
          "provider":label,"fact_type":label,
          "resource_scope":{"type":"object","minProperties":1,"maxProperties":16,"propertyNames":label,"additionalProperties":{"type":"string","minLength":1,"maxLength":512,"description":"Also bounded to512 UTF8 bytes; controls rejected"}},
          "claim_rules":{"type":"object","minProperties":1,"maxProperties":32,"propertyNames":label,"additionalProperties":{"oneOf":[
             rule("boolean",json!({}),vec![]),rule("number",json!({"minimum":{"type":"number"},"maximum":{"type":"number"}}),vec!["minimum","maximum"]),
             rule("text",json!({"max_bytes":{"type":"integer","minimum":1,"maximum":512}}),vec!["max_bytes"]) ]}},
          "max_age_ms":{"type":"integer","minimum":1,"maximum":900000},"max_clock_skew_ms":{"type":"integer","minimum":0,"maximum":30000}});
        required = vec![
            "source_id",
            "application_id",
            "expected_application_revision",
            "provider",
            "fact_type",
            "resource_scope",
            "claim_rules",
            "max_age_ms",
            "max_clock_skew_ms",
        ];
        if action == "replace-definition" {
            let props = properties.as_object_mut().expect("static object");
            for name in ["source_id", "application_id", "provider", "fact_type"] {
                props.remove(name);
            }
            props.insert("expected_revision".into(), revision.clone());
            required = vec![
                "expected_revision",
                "expected_application_revision",
                "resource_scope",
                "claim_rules",
                "max_age_ms",
                "max_clock_skew_ms",
            ];
        }
    } else if action == "activate" {
        properties
            .as_object_mut()
            .expect("static object")
            .insert("expected_application_revision".into(), revision);
        required.push("expected_application_revision");
    }
    json!({"operationId":operation,"tags":["evidence"],"summary":summary,
      "description":"Session-only current canonical administrator, exact active tenant and allowed Origin required. No connector API-key administration. Create derives subject from locked current eligible application at expected_application_revision and starts inactive. Activation revalidates definition, application revision, subject, lifecycle and expiry. Definition replacement changes only resource/claim/freshness constraints and leaves the binding inactive; identity and provenance are immutable through this route. Replacement/activation/deactivation invalidate every linked producer grant approval and deactivate those grants. Deactivation remains available for closed/expired applications. Original JSON is limited to4096bytes; duplicate fields at every map level, unknown fields and reserved authority/secret claim names are rejected. Mutation and audit commit atomically with revision fences; no automatic uncertain-commit retries. No verification, application approval, signing or issuance.",
      "security":[{"sessionCookie":[]}],
      "parameters":[{"name":"organization_id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}},
        {"name":"binding_id","in":"path","required":true,"schema":identifier},{"name":"Origin","in":"header","required":true,"schema":{"type":"string"}}],
      "requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","additionalProperties":false,"properties":properties,"required":required}}}},
      "responses":{"200":{"description":"Committed revision and audit_id; no-store"},"400":{"description":"Invalid or ambiguous request"},"401":{"description":"Session required"},"403":{"description":"Current canonical authority denied"},"409":{"description":"Revision/state/transaction conflict"},"413":{"description":"Body too large"},"503":{"description":"Unavailable or uncertain commit; reconcile before retry"}}})
}
#[cfg(test)]
mod binding_admin_guard_tests {
    use super::*;
    #[tokio::test]
    async fn binding_paths_require_session_tenant_origin_and_canonical_identifiers() {
        let org = "20000000-0000-4000-8000-000000000001";
        for action in ["create", "activate", "deactivate", "replace-definition"] {
            let path = format!(
                "/v1/organizations/{org}/external-observation-bindings/binding-one/{action}"
            );
            assert_eq!(admin_organization(&path), Some(org));
            let request = || {
                Request::builder()
                    .method("POST")
                    .uri(&path)
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap()
            };
            assert!(admit_admin(request(), true, Some(org), "admin-one", true)
                .await
                .is_ok());
            assert_eq!(
                admit_admin(request(), false, Some(org), "admin-one", true)
                    .await
                    .unwrap_err()
                    .0,
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                admit_admin(request(), true, Some(org), "admin-one", false)
                    .await
                    .unwrap_err()
                    .0,
                StatusCode::FORBIDDEN
            );
            assert_eq!(
                admit_admin(
                    request(),
                    true,
                    Some("20000000-0000-4000-8000-000000000002"),
                    "admin-one",
                    true
                )
                .await
                .unwrap_err()
                .0,
                StatusCode::FORBIDDEN
            );
        }
        assert_eq!(
            admin_organization(&format!(
                "/v1/organizations/{org}/external-observation-bindings/bad.name/activate"
            )),
            None
        );
        assert_eq!(
            admin_organization(&format!(
                "/v1/organizations/{org}/external-observation-bindings/binding-one/delete"
            )),
            None
        );
    }
}

#[cfg(test)]
mod reserved_admin_namespace_tests {
    use super::*;
    #[tokio::test]
    async fn malformed_admin_identifiers_remain_guarded_and_cannot_become_aliases() {
        let org = "20000000-0000-4000-8000-000000000001";
        for path in [
            "/v1/organizations/%32%30%30%30%30%30%30%30-0000-4000-8000-000000000001/external-observation-producers/30000000-0000-4000-8000-000000000001/revoke",
            "/v1/organizations/20000000-0000-4000-8000-000000000001/external-observation-producers/00000000-0000-0000-0000-000000000000/revoke",
            "/v1/organizations/20000000-0000-4000-8000-000000000001/external-observation-bindings/bad.name/activate",
        ] {
            assert!(is_admin_namespace(path));assert_eq!(admin_organization(path),None);
            let request=Request::builder().method("POST").uri(path).header("content-type","application/json").body(Body::from("{}")).unwrap();
            assert_eq!(admit_admin(request,true,Some(org),"admin-one",true).await.unwrap_err().0,StatusCode::FORBIDDEN);
        }
        assert!(!is_admin_namespace("/v1/organizations/one/api-keys"));
    }
}

pub fn admin_read_operation(kind: &str) -> serde_json::Value {
    use serde_json::json;
    let identifier =
        json!({"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"});
    let revision = json!({"type":"integer","minimum":1,"maximum":9007199254740991_u64});
    let audit = matches!(kind, "grant_audit" | "binding_audit");
    let (operation, resource) = match kind {
        "grant" => ("inspect_external_observation_producer", "grant_id"),
        "binding" => ("inspect_external_observation_binding", "binding_id"),
        "grant_audit" => ("read_external_observation_producer_audit", "grant_id"),
        "binding_audit" => ("read_external_observation_binding_audit", "binding_id"),
        _ => ("inspect_external_observation_receipt", "observation_id"),
    };
    let (properties, required) = if audit {
        (
            json!({"cursor":{"type":"object","additionalProperties":false,"required":["created_at","id"],"properties":{"created_at":{"type":"string","format":"date-time","description":"Use the exact returned PostgreSQL microsecond cursor"},"id":{"type":"string","format":"uuid"}}}}),
            vec![],
        )
    } else if kind == "grant" {
        (
            json!({"after_binding_id":identifier,"expected_revision":revision}),
            vec![],
        )
    } else if kind == "receipt" {
        (json!({"source_id":identifier}), vec!["source_id"])
    } else {
        (json!({}), vec![])
    };
    json!({"operationId":operation,"tags":["evidence"],"summary":"Read a canonical authorized observation authority or reconciliation snapshot",
      "description":"POST query with no authority writes. Requires current canonical external-observation:manage, authenticated session tenant and allowed Origin. API keys cannot inspect. Response is no-store and bounded to131072bytes. Grant membership pages contain at most32 IDs; after_binding_id requires expected_revision and stale revisions conflict. Audit pages contain at most8 events and a stable timestamp/UUID cursor, exposing only structured allowed change fields without metadata/secrets. Receipt inspection requires exact tenant/source/observation ID and returns the original unsigned envelope/key reference plus admission-audit/head consistency. Revoked producer keys do not prevent an authorized administrator inspecting historical receipts. No receipt means absent at this snapshot, not proof an in-flight commit cannot occur or permission to regenerate IDs/times/sequences. Reads do not reapprove, verify, issue or retry anything. These snapshots must not be cached as authority; every submission/mutation reauthorizes current records.",
      "security":[{"sessionCookie":[]}],"parameters":[{"name":"organization_id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}},
        {"name":resource,"in":"path","required":true,"schema":if resource=="grant_id"{json!({"type":"string","format":"uuid"})}else{identifier}},
        {"name":"Origin","in":"header","required":true,"schema":{"type":"string"}}],
      "requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","additionalProperties":false,"properties":properties,"required":required}}}},
      "responses":{"200":{"description":"Consistent authorized snapshot_at_ms and found/record or events/next_cursor; no-store"},"400":{"description":"Invalid or ambiguous query"},"401":{"description":"Session required"},"403":{"description":"Current canonical administrator authority denied"},"409":{"description":"Stale revision/snapshot conflict; inspect again, no blind write retry"},"413":{"description":"Request exceeds4096bytes"},"503":{"description":"Unavailable or inconsistent stored record; never report absence"}}})
}
#[cfg(test)]
mod admin_read_guard_tests {
    use super::*;
    #[tokio::test]
    async fn reads_use_session_tenant_origin_and_reserved_namespace_guards() {
        let org = "20000000-0000-4000-8000-000000000001";
        for tail in [
            "external-observation-producers/30000000-0000-4000-8000-000000000001/inspect",
            "external-observation-producers/30000000-0000-4000-8000-000000000001/audit",
            "external-observation-bindings/binding-one/inspect",
            "external-observation-bindings/binding-one/audit",
            "external-observation-receipts/observation-one/inspect",
            "external-observation-receipts/observation-one/materialize",
            "external-observation-receipts/observation-one/materialization",
        ] {
            let path = format!("/v1/organizations/{org}/{tail}");
            assert!(is_admin_namespace(&path));
            assert_eq!(admin_organization(&path), Some(org));
            let request = || {
                Request::builder()
                    .method("POST")
                    .uri(&path)
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap()
            };
            assert!(admit_admin(request(), true, Some(org), "admin-one", true)
                .await
                .is_ok());
            assert_eq!(
                admit_admin(request(), false, Some(org), "admin-one", true)
                    .await
                    .unwrap_err()
                    .0,
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                admit_admin(request(), true, Some(org), "admin-one", false)
                    .await
                    .unwrap_err()
                    .0,
                StatusCode::FORBIDDEN
            );
            assert_eq!(
                admit_admin(
                    request(),
                    true,
                    Some("20000000-0000-4000-8000-000000000002"),
                    "admin-one",
                    true
                )
                .await
                .unwrap_err()
                .0,
                StatusCode::FORBIDDEN
            );
        }
        let alias =
            format!("/v1/organizations/{org}/external-observation-receipts/bad.name/inspect");
        assert!(is_admin_namespace(&alias));
        assert_eq!(admin_organization(&alias), None);
    }
}

pub fn materialization_operation(read: bool) -> serde_json::Value {
    let mut properties = serde_json::json!({"source_id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"}});
    let mut required = vec!["source_id"];
    if !read {
        properties["expected_application_revision"] =
            serde_json::json!({"type":"integer","minimum":1,"maximum":9007199254740991u64});
        required.push("expected_application_revision");
    }
    serde_json::json!({"operationId":if read {"inspect_external_observation_materialization"} else {"materialize_external_observation_receipt"},
      "summary":if read {"Inspect original receipt materialization"} else {"Attach an admitted unsigned observation to application evidence"},
      "description":"Session, allowed Origin, exact active tenant and current canonical external-observation:manage required. Connector API keys cannot materialize. Core derives every evidence identity from the immutable receipt. First attachment requires current active binding, latest observation head, matching eligible subject/application and expected application revision. The fact is always UNVERIFIED with UNSIGNED_PRODUCER_ATTESTATION; no requirement is satisfied by verification, and no approval, issuance transaction or signing occurs. Fact, head, application revision and actor event commit atomically. Matching retries return the original result without moving old heads. Original expected_application_revision is required on retries. After uncertain COMMIT, inspect the same source/observation; absence is a snapshot, not permission to regenerate identity or blindly retry. Existing attachment remains inspectable after source revocation or application closure. Responses are no-store. Request original JSON is limited to4096bytes.",
      "security":[{"sessionCookie":[]}],"parameters":[{"name":"organization_id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}},{"name":"observation_id","in":"path","required":true,"schema":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"}},{"name":"Origin","in":"header","required":true,"schema":{"type":"string"}}],
      "requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","additionalProperties":false,"required":required,"properties":properties}}}},
      "responses":{"200":{"description":"Original materialization or authorized snapshot; no-store"},"400":{"description":"Invalid original request"},"401":{"description":"Session required"},"403":{"description":"Canonical administrator or application authority denied"},"409":{"description":"Current revision/head conflict; inspect before manual reconciliation"},"413":{"description":"Request exceeds4096bytes"},"503":{"description":"Unavailable or uncertain COMMIT; inspect same identity"}}})
}

#[cfg(test)]
mod materialization_openapi_tests {
    use super::*;
    #[test]
    fn administrator_operations_declare_session_cookie_and_required_origin() {
        for operation in [
            materialization_operation(false),
            materialization_operation(true),
            binding_admin_operation("create"),
            admin_read_operation("receipt"),
        ] {
            assert_eq!(
                operation["security"],
                serde_json::json!([{"sessionCookie":[]}])
            );
            assert!(operation["parameters"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["name"] == "Origin" && p["in"] == "header" && p["required"] == true));
        }
    }
}
#[cfg(test)]
mod ownership_guard_tests {
    use super::*;
    const ORG: &str = "20000000-0000-4000-8000-000000000001";
    #[tokio::test]
    async fn ownership_operations_require_session_origin_and_exact_tenant() {
        for action in ["propose", "confirm", "revoke", "inspect", "receipt"] {
            let path = format!("/v1/organizations/{ORG}/application-ownerships/app-one/{action}");
            let request = || {
                Request::builder()
                    .method("POST")
                    .uri(&path)
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap()
            };
            assert!(is_admin_namespace(&path));
            assert_eq!(admin_organization(&path), Some(ORG));
            assert!(admit_admin(request(), true, Some(ORG), "learner-one", true)
                .await
                .is_ok());
            assert_eq!(
                admit_admin(request(), false, Some(ORG), "learner-one", true)
                    .await
                    .unwrap_err()
                    .0,
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                admit_admin(request(), true, Some(ORG), "learner-one", false)
                    .await
                    .unwrap_err()
                    .0,
                StatusCode::FORBIDDEN
            );
            assert_eq!(
                admit_admin(
                    request(),
                    true,
                    Some("20000000-0000-4000-8000-000000000002"),
                    "learner-one",
                    true
                )
                .await
                .unwrap_err()
                .0,
                StatusCode::FORBIDDEN
            );
        }
    }
    #[test]
    fn malformed_ownership_aliases_still_enter_the_guard() {
        for path in [
            format!("/v1/organizations/{ORG}/application-ownerships/app-one/delete"),
            format!("/v1/organizations/{ORG}/application-ownerships/app-one/confirm/"),
            format!("/v1/organizations/{ORG}/application-ownerships/%2e%2e/confirm"),
            "/v1/organizations/wrong/application-ownerships/app-one/confirm".into(),
        ] {
            assert!(is_admin_namespace(&path));
            assert_eq!(admin_organization(&path), None);
        }
    }
}
