// SPDX-License-Identifier: AGPL-3.0-only
use axum::{
    body::{to_bytes, Body},
    extract::Request,
    http::{HeaderMap, StatusCode},
};
use std::time::Duration;
use uuid::Uuid;

pub const PATH: &str = "/v1/evidence/observations";
pub const MAX_BODY_BYTES: usize = 65_536;
pub type Rejection = (StatusCode, &'static str);
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
