// SPDX-License-Identifier: AGPL-3.0-only
//! Public Common Gateway transport policy for generic learner associations.
use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, StatusCode},
};
use http_body_util::BodyExt;
use std::time::Duration;
use uuid::Uuid;
pub type Rejection = (StatusCode, &'static str);
const INVALID: Rejection = (StatusCode::BAD_REQUEST, "invalid_association_request");
#[derive(Clone, Copy, PartialEq)]
pub enum Access {
    Producer,
    Administrator,
    Learner,
}
pub fn paths() -> Vec<(String, Access)> {
    let mut result = Vec::new();
    for (base, access, actions) in [
        (
            "/v1/organizations/{organization_id}/external-association-sources/{resource_id}",
            Access::Administrator,
            &[
                "create",
                "approve",
                "revoke",
                "replace-key",
                "change-expiry",
                "inspect",
                "receipt",
            ][..],
        ),
        (
            "/v1/identity/association-challenges/{resource_id}",
            Access::Producer,
            &["create", "inspect", "receipt", "abandon", "expire"][..],
        ),
        (
            "/v1/organizations/{organization_id}/external-association-challenges/{resource_id}",
            Access::Learner,
            &["confirm", "deny", "relink", "inspect", "receipt"][..],
        ),
        (
            "/v1/organizations/{organization_id}/external-associations/{resource_id}",
            Access::Learner,
            &["unlink", "receipt"][..],
        ),
    ] {
        for action in actions {
            result.push((format!("{base}/{action}"), access));
        }
    }
    result
}
pub fn is_producer_namespace(path: &str) -> bool {
    path.strip_prefix("/v1/identity/association-challenges")
        .is_some_and(|tail| tail.is_empty() || tail.starts_with('/'))
}
pub fn is_namespace(path: &str) -> bool {
    is_producer_namespace(path) || {
        let p: Vec<_> = path.split('/').collect();
        p.len() >= 5
            && p[0].is_empty()
            && p[1] == "v1"
            && p[2] == "organizations"
            && matches!(
                p[4],
                "external-association-sources"
                    | "external-association-challenges"
                    | "external-associations"
            )
    }
}
fn canonical(value: Option<&str>) -> bool {
    value.is_some_and(|v| Uuid::parse_str(v).is_ok_and(|id| !id.is_nil() && id.to_string() == v))
}
fn route(path: &str) -> Option<(Access, Option<&str>)> {
    let p: Vec<_> = path.split('/').collect();
    if p.len() == 6
        && p[..4] == ["", "v1", "identity", "association-challenges"]
        && canonical(Some(p[4]))
        && matches!(
            p[5],
            "create" | "inspect" | "receipt" | "abandon" | "expire"
        )
    {
        return Some((Access::Producer, None));
    }
    if p.len() != 7
        || p[..3] != ["", "v1", "organizations"]
        || !canonical(Some(p[3]))
        || !canonical(Some(p[5]))
    {
        return None;
    }
    match (p[4], p[6]) {
        (
            "external-association-sources",
            "create" | "approve" | "revoke" | "replace-key" | "change-expiry" | "inspect"
            | "receipt",
        ) => Some((Access::Administrator, Some(p[3]))),
        (
            "external-association-challenges",
            "confirm" | "deny" | "relink" | "inspect" | "receipt",
        )
        | ("external-associations", "unlink" | "receipt") => Some((Access::Learner, Some(p[3]))),
        _ => None,
    }
}
pub fn required_permission(path: &str) -> Option<&'static str> {
    match route(path)?.0 {
        Access::Producer => Some("identity:attest"),
        Access::Administrator => Some("external-association:manage"),
        Access::Learner => None,
    }
}
pub fn requires_own_session(path: &str) -> bool {
    route(path).is_some_and(|(access, _)| access == Access::Learner)
}
pub fn operation(path: &str, access: Access) -> serde_json::Value {
    use serde_json::json;
    let action = path.rsplit('/').next().expect("static association route");
    let uuid = json!({"type":"string","format":"uuid"});
    let positive = json!({"type":"integer","minimum":1,"maximum":9007199254740991_u64});
    let revision = json!({"type":"integer","minimum":1,"maximum":9007199254740990_u64});
    let identifier =
        json!({"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"});
    let hash = json!({"type":"string","pattern":"^[a-f0-9]{64}$","minLength":64,"maxLength":64});
    let mut properties = serde_json::Map::new();
    if action != "inspect" {
        properties.insert("operation_id".into(), uuid.clone());
    }
    if access == Access::Administrator {
        if matches!(
            action,
            "create" | "approve" | "revoke" | "replace-key" | "change-expiry"
        ) {
            properties.insert(
                "expected_revision".into(),
                if action == "create" {
                    json!({"type":"integer","minimum":0,"maximum":0})
                } else {
                    revision.clone()
                },
            );
        }
        if matches!(action, "create" | "replace-key") {
            properties.insert("api_key_id".into(), uuid.clone());
            properties.insert("key_revision".into(), positive.clone());
        }
        if matches!(action, "create" | "change-expiry") {
            properties.insert("expires_at_ms".into(), positive.clone());
        }
        if action == "create" {
            properties.insert("source_id".into(), identifier.clone());
        }
    } else if access == Access::Producer && action == "create" {
        for (name, value) in [
            ("challenge_id", uuid.clone()),
            ("source_grant_id", uuid.clone()),
            ("expected_source_revision", positive.clone()),
            ("binding_id", identifier),
            ("expected_binding_revision", positive.clone()),
            ("provider_reference", hash.clone()),
            ("provider_revision", positive.clone()),
            ("code_hash", hash),
            ("expires_at_ms", positive.clone()),
        ] {
            properties.insert(name.into(), value);
        }
    } else if !matches!(action, "inspect" | "receipt") {
        properties.insert("expected_revision".into(), revision.clone());
    }
    if matches!(action, "confirm" | "deny" | "relink") {
        properties.insert("code".into(),json!({"type":"string","minLength":43,"maxLength":43,"pattern":"^[A-Za-z0-9_-]{43}$","writeOnly":true,"description":"Original canonical unpadded base64url32-byte code; Core hashes decoded bytes before SQL. Never log or retain in server URLs."}));
    }
    if action == "relink" {
        properties.insert("expected_identity_revision".into(), revision);
    }
    let required: Vec<_> = properties.keys().cloned().collect();
    let mut parameters =
        vec![json!({"name":"resource_id","in":"path","required":true,"schema":uuid})];
    if access != Access::Producer {
        parameters.push(json!({"name":"organization_id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}));
        parameters.push(json!({"name":"Origin","in":"header","required":true,"schema":{"type":"string","format":"uri"}}));
    }
    json!({"operationId":format!("association_{}_{}",if access==Access::Producer {"producer"} else if access==Access::Administrator {"source"} else if path.contains("/external-associations/") {"identity"} else {"learner"},action),
        "tags":["identity"],"summary":format!("{action} external learner association"),
        "description":"Public Common Gateway only. Producer calls require canonical organization API-key authentication and exact identity:attest scope; evidence:submit and wildcards do not suffice. Source administration requires session tenant, allowed Origin and current external-association:manage. Learner operations require the captured authenticated user, with no administrator substitute. Core derives subject/application/ownership, revalidates source/key/binding revisions and durable unlink generation, and requires explicit fresh-code consent. Requests preserve original bytes bounded to4096 and reject duplicate/unknown fields and trailers. Mutation receipts are historical; inspect separately revalidates current authority and producer reads omit Core subject/application/identity. Reconcile uncertain writes using the original operation; never generate a replacement or automatically retry. No evidence verification, approval or issuance is granted.",
        "security":if access==Access::Producer {json!([{"apiKeyAuth":[]},{"bearerAuth":[]}])} else {json!([{"sessionCookie":[]}])},
        "parameters":parameters,"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","additionalProperties":false,"properties":properties,"required":required}}}},
        "responses":{"200":{"description":"No-store original mutation receipt, actor-scoped historical receipt envelope, or separately qualified current envelope"},
            "400":{"description":"Invalid original request"},"401":{"description":"Required producer/session authentication missing"},"403":{"description":"Current canonical authority or original actor denied"},
            "409":{"description":"Revision or original intent conflict"},"413":{"description":"Original body exceeds4096bytes"},"415":{"description":"Unsupported representation"},"503":{"description":"Unavailable or uncertain write; recover original receipt"}}})
}
pub enum Identity<'a> {
    Producer {
        key_id: Option<&'a str>,
        organization_id: Option<&'a str>,
        scopes: &'a [String],
    },
    Session {
        organization_id: Option<&'a str>,
        user_id: &'a str,
        allowed_origin: bool,
    },
}
fn one<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, Rejection> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(INVALID);
    }
    first.map(|v| v.to_str().map_err(|_| INVALID)).transpose()
}
pub async fn admit(request: Request, identity: Identity<'_>) -> Result<Request, Rejection> {
    let (access, tenant) = route(request.uri().path()).ok_or(INVALID)?;
    match identity {
        Identity::Producer {
            key_id,
            organization_id,
            scopes,
        } => {
            if access != Access::Producer || !canonical(key_id) || !canonical(organization_id) {
                return Err((StatusCode::UNAUTHORIZED, "association_producer_required"));
            }
            if !scopes.iter().any(|v| v == "identity:attest") {
                return Err((StatusCode::FORBIDDEN, "association_not_authorized"));
            }
        }
        Identity::Session {
            organization_id,
            user_id,
            allowed_origin,
        } => {
            if access == Access::Producer
                || !canonical(organization_id)
                || user_id.is_empty()
                || user_id.len() > 128
                || !user_id.as_bytes()[0].is_ascii_alphanumeric()
                || !user_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                return Err((StatusCode::UNAUTHORIZED, "association_session_required"));
            }
            if !allowed_origin || tenant != organization_id {
                return Err((StatusCode::FORBIDDEN, "association_not_authorized"));
            }
        }
    }
    if request.method() != "POST" || request.uri().query().is_some() {
        return Err(INVALID);
    }
    let headers = request.headers();
    if access == Access::Producer
        && one(headers, "x-api-key")?.is_some() == one(headers, "authorization")?.is_some()
    {
        return Err(INVALID);
    }
    if !one(headers, "content-type")?.is_some_and(|v| v.eq_ignore_ascii_case("application/json"))
        || one(headers, "content-encoding")?.is_some_and(|v| !v.eq_ignore_ascii_case("identity"))
    {
        return Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_association_format",
        ));
    }
    let length = one(headers, "content-length")?;
    let transfer = one(headers, "transfer-encoding")?;
    if headers.contains_key("trailer")
        || (length.is_some() && transfer.is_some())
        || transfer.is_some_and(|v| !v.eq_ignore_ascii_case("chunked"))
    {
        return Err(INVALID);
    }
    let expected = length
        .map(|v| {
            if v.is_empty() || v.len() > 20 || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(INVALID);
            }
            v.parse::<usize>().map_err(|_| INVALID)
        })
        .transpose()?;
    if expected.is_some_and(|n| n > 4096) {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "association_request_too_large",
        ));
    }
    let (parts, mut body) = request.into_parts();
    let collect = async {
        let mut bytes = Vec::new();
        let mut frames = 0;
        while let Some(frame) = body.frame().await {
            frames += 1;
            if frames > 8192 {
                return Err(INVALID);
            }
            let data = frame
                .map_err(|_| INVALID)?
                .into_data()
                .map_err(|_| INVALID)?;
            if bytes.len().saturating_add(data.len()) > 4096 {
                return Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "association_request_too_large",
                ));
            }
            bytes.extend_from_slice(&data);
        }
        Ok(bytes)
    };
    let bytes = tokio::time::timeout(Duration::from_secs(10), collect)
        .await
        .map_err(|_| (StatusCode::REQUEST_TIMEOUT, "association_body_timeout"))??;
    if expected.is_some_and(|n| n != bytes.len()) {
        return Err(INVALID);
    }
    Ok(Request::from_parts(parts, Body::from(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    const ORG: &str = "10000000-0000-4000-8000-000000000001";
    const KEY: &str = "20000000-0000-4000-8000-000000000001";
    fn request(path: &str, body: Body) -> Request {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("x-api-key", "synthetic-public-key")
            .body(body)
            .unwrap()
    }
    #[tokio::test]
    async fn producer_requires_actual_key_context_and_exact_independent_scope() {
        let path = format!("/v1/identity/association-challenges/{KEY}/create");
        for scopes in [
            vec![],
            vec!["evidence:submit".into()],
            vec!["identity:*".into(), "*".into()],
        ] {
            assert!(admit(
                request(&path, Body::from("{}")),
                Identity::Producer {
                    key_id: Some(KEY),
                    organization_id: Some(ORG),
                    scopes: &scopes
                }
            )
            .await
            .is_err());
        }
        let raw = b"{\"operation_id\":\"original\",\"code_hash\":\"original-bytes\"}\n";
        let scopes = vec!["identity:attest".into()];
        let accepted = admit(
            request(&path, Body::from(raw.as_slice())),
            Identity::Producer {
                key_id: Some(KEY),
                organization_id: Some(ORG),
                scopes: &scopes,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            &axum::body::to_bytes(accepted.into_body(), 4096)
                .await
                .unwrap()[..],
            raw
        );
        assert!(admit(
            request(&path, Body::from("{}")),
            Identity::Session {
                organization_id: Some(ORG),
                user_id: "learner-one",
                allowed_origin: true
            }
        )
        .await
        .is_err());
        let mut ambiguous = request(&path, Body::from("{}"));
        ambiguous
            .headers_mut()
            .insert("authorization", "Bearer synthetic-other".parse().unwrap());
        assert!(admit(
            ambiguous,
            Identity::Producer {
                key_id: Some(KEY),
                organization_id: Some(ORG),
                scopes: &scopes
            }
        )
        .await
        .is_err());
    }
    #[tokio::test]
    async fn source_and_learner_paths_require_current_session_tenant_origin_and_original_framing() {
        let source = format!("/v1/organizations/{ORG}/external-association-sources/{KEY}/approve");
        let learner =
            format!("/v1/organizations/{ORG}/external-association-challenges/{KEY}/confirm");
        assert_eq!(
            required_permission(&source),
            Some("external-association:manage")
        );
        assert_eq!(required_permission(&learner), None);
        for allowed_origin in [false, true] {
            let result = admit(
                request(&learner, Body::from("{}")),
                Identity::Session {
                    organization_id: Some(ORG),
                    user_id: "learner-one",
                    allowed_origin,
                },
            )
            .await;
            assert_eq!(result.is_ok(), allowed_origin);
        }
        assert!(admit(
            request(&source, Body::from("{}")),
            Identity::Producer {
                key_id: Some(KEY),
                organization_id: Some(ORG),
                scopes: &["identity:attest".into()]
            }
        )
        .await
        .is_err());
        assert!(admit(
            request(&source, Body::from("{}")),
            Identity::Session {
                organization_id: Some(KEY),
                user_id: "admin-one",
                allowed_origin: true
            }
        )
        .await
        .is_err());
        for path in [
            source.replace(KEY, "invalid"),
            format!("{source}/"),
            format!("{source}?x=y"),
            source.replace("approve", "unknown"),
        ] {
            assert!(is_namespace(path.split('?').next().unwrap()));
            assert!(admit(
                request(&path, Body::from("{}")),
                Identity::Session {
                    organization_id: Some(ORG),
                    user_id: "admin-one",
                    allowed_origin: true
                }
            )
            .await
            .is_err());
        }
        let body = Body::new(
            http_body_util::Full::new(axum::body::Bytes::from_static(b"{}"))
                .with_trailers(async { Some(Ok(HeaderMap::new())) }),
        );
        assert!(admit(
            request(&source, body),
            Identity::Session {
                organization_id: Some(ORG),
                user_id: "admin-one",
                allowed_origin: true
            }
        )
        .await
        .is_err());
        assert!(admit(
            request(&source, Body::from(" ".repeat(4097))),
            Identity::Session {
                organization_id: Some(ORG),
                user_id: "admin-one",
                allowed_origin: true
            }
        )
        .await
        .is_err());
    }
}
