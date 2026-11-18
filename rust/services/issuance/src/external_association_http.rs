// SPDX-License-Identifier: AGPL-3.0-only
//! Core boundary behind the authenticated public Common Gateway. No public
//! connector obtains this service credential or a private service endpoint.
use crate::external_association::{self as domain, AssociationError};
use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use http_body_util::BodyExt;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use uuid::Uuid;

pub const SOURCE_BASE: &str =
    "/v1/organizations/{organization_id}/external-association-sources/{resource_id}";
pub const PRODUCER_BASE: &str = "/v1/identity/association-challenges/{resource_id}";
pub const LEARNER_BASE: &str =
    "/v1/organizations/{organization_id}/external-association-challenges/{resource_id}";
pub const IDENTITY_BASE: &str =
    "/v1/organizations/{organization_id}/external-associations/{resource_id}";
#[derive(Clone, Copy, PartialEq)]
enum Class {
    Source,
    Producer,
    Learner,
    Identity,
}
struct Boundary {
    pool: PgPool,
    service_key: Vec<u8>,
}
struct Authenticated<'a> {
    class: Class,
    org: Uuid,
    actor: &'a str,
    key: Option<Uuid>,
    resource: Uuid,
}

pub fn association_router(pool: PgPool, service_key: &[u8]) -> Result<Router, &'static str> {
    if !(32..=512).contains(&service_key.len()) || !service_key.iter().all(u8::is_ascii_graphic) {
        return Err("Invalid association Gateway service credential");
    }
    let mut router = Router::new();
    for (class, base, actions) in [
        (
            Class::Source,
            SOURCE_BASE,
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
            Class::Producer,
            PRODUCER_BASE,
            &["create", "inspect", "receipt", "abandon", "expire"][..],
        ),
        (
            Class::Learner,
            LEARNER_BASE,
            &["confirm", "deny", "relink", "inspect", "receipt"][..],
        ),
        (Class::Identity, IDENTITY_BASE, &["unlink", "receipt"][..]),
    ] {
        for action in actions {
            router = router.route(
                &format!("{base}/{action}"),
                post(
                    move |State(state): State<Arc<Boundary>>,
                          Path(params): Path<BTreeMap<String, String>>,
                          request: Request| {
                        handle(class, state, params, request)
                    },
                ),
            );
        }
    }
    Ok(router.with_state(Arc::new(Boundary {
        pool,
        service_key: service_key.to_vec(),
    })))
}
fn one<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}
fn uuid(value: &str) -> Option<Uuid> {
    Uuid::parse_str(value)
        .ok()
        .filter(|id| !id.is_nil() && id.to_string() == value)
}
fn user(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn failure(status: StatusCode, code: &'static str) -> Response {
    (
        status,
        [("cache-control", "no-store")],
        Json(json!({"error":code})),
    )
        .into_response()
}
fn error(error: AssociationError) -> Response {
    let (status, code) = match error {
        AssociationError::InvalidRequest => {
            (StatusCode::BAD_REQUEST, "invalid_association_request")
        }
        AssociationError::NotAuthorized => (StatusCode::FORBIDDEN, "association_not_authorized"),
        AssociationError::Conflict => (StatusCode::CONFLICT, "association_conflict"),
        AssociationError::Unavailable => {
            (StatusCode::SERVICE_UNAVAILABLE, "association_unavailable")
        }
        AssociationError::CommitUnknown => (
            StatusCode::SERVICE_UNAVAILABLE,
            "association_commit_unknown",
        ),
    };
    failure(status, code)
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, AssociationError> {
    serde_json::from_slice(bytes).map_err(|_| AssociationError::InvalidRequest)
}
fn output<T: Serialize>(
    result: Result<T, AssociationError>,
    mutation: bool,
) -> Result<Value, AssociationError> {
    serde_json::to_value(result?).map_err(|_| {
        if mutation {
            AssociationError::CommitUnknown
        } else {
            AssociationError::Unavailable
        }
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    operation_id: Uuid,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Relink {
    operation_id: Uuid,
    expected_revision: i64,
    expected_identity_revision: i64,
    code: String,
}
enum BodyFailure {
    Invalid,
    TooLarge,
}
async fn original_bytes(mut body: Body) -> Result<Vec<u8>, BodyFailure> {
    let mut bytes = Vec::new();
    let mut frames = 0;
    while let Some(frame) = body.frame().await {
        frames += 1;
        if frames > 8192 {
            return Err(BodyFailure::Invalid);
        }
        let data = frame
            .map_err(|_| BodyFailure::Invalid)?
            .into_data()
            .map_err(|_| BodyFailure::Invalid)?;
        if bytes.len().saturating_add(data.len()) > 4096 {
            return Err(BodyFailure::TooLarge);
        }
        bytes.extend_from_slice(&data);
    }
    Ok(bytes)
}

async fn handle(
    class: Class,
    state: Arc<Boundary>,
    params: BTreeMap<String, String>,
    request: Request,
) -> Response {
    let headers = request.headers();
    if one(headers, "x-api-key")
        .is_none_or(|key| key.as_bytes().ct_eq(&state.service_key).unwrap_u8() != 1)
    {
        return failure(StatusCode::UNAUTHORIZED, "association_gateway_required");
    }
    let Some(org) = one(headers, "x-organization-id").and_then(uuid) else {
        return failure(StatusCode::UNAUTHORIZED, "association_identity_required");
    };
    let (actor, producer) = if class == Class::Producer {
        if headers.contains_key("x-user-id") {
            return failure(StatusCode::UNAUTHORIZED, "association_producer_required");
        }
        let Some(key) = one(headers, "x-api-key-id").and_then(uuid) else {
            return failure(StatusCode::UNAUTHORIZED, "association_producer_required");
        };
        (String::new(), Some(key))
    } else {
        if headers.contains_key("x-api-key-id") {
            return failure(StatusCode::UNAUTHORIZED, "association_session_required");
        }
        let Some(actor) = one(headers, "x-user-id").filter(|v| user(v)) else {
            return failure(StatusCode::UNAUTHORIZED, "association_session_required");
        };
        if params.get("organization_id").and_then(|v| uuid(v)) != Some(org) {
            return failure(StatusCode::FORBIDDEN, "association_tenant_denied");
        }
        (actor.to_owned(), None)
    };
    let Some(resource) = params.get("resource_id").and_then(|v| uuid(v)) else {
        return error(AssociationError::InvalidRequest);
    };
    let action = request
        .uri()
        .path()
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_owned();
    let base = match class {
        Class::Source => format!("/v1/organizations/{org}/external-association-sources/{resource}"),
        Class::Producer => format!("/v1/identity/association-challenges/{resource}"),
        Class::Learner => {
            format!("/v1/organizations/{org}/external-association-challenges/{resource}")
        }
        Class::Identity => format!("/v1/organizations/{org}/external-associations/{resource}"),
    };
    if request.uri().query().is_some() || request.uri().path() != format!("{base}/{action}") {
        return error(AssociationError::InvalidRequest);
    }
    if !one(headers, "content-type").is_some_and(|v| v.eq_ignore_ascii_case("application/json"))
        || one(headers, "content-encoding").is_some_and(|v| !v.eq_ignore_ascii_case("identity"))
    {
        return failure(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_association_format",
        );
    }
    if [
        "content-type",
        "content-encoding",
        "content-length",
        "transfer-encoding",
    ]
    .iter()
    .any(|name| headers.get_all(*name).iter().count() > 1)
        || headers.contains_key("trailer")
        || (headers.contains_key("content-length") && headers.contains_key("transfer-encoding"))
        || one(headers, "transfer-encoding").is_some_and(|v| !v.eq_ignore_ascii_case("chunked"))
    {
        return error(AssociationError::InvalidRequest);
    }
    let expected = match one(headers, "content-length") {
        Some(v) if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) => {
            match v.parse::<usize>() {
                Ok(n) if n <= 4096 => Some(n),
                _ => {
                    return failure(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "association_request_too_large",
                    )
                }
            }
        }
        Some(_) => return error(AssociationError::InvalidRequest),
        None => None,
    };
    let bytes =
        match tokio::time::timeout(Duration::from_secs(10), original_bytes(request.into_body()))
            .await
        {
            Ok(Ok(v)) => v,
            Ok(Err(BodyFailure::TooLarge)) => {
                return failure(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "association_request_too_large",
                )
            }
            Ok(Err(BodyFailure::Invalid)) => return error(AssociationError::InvalidRequest),
            Err(_) => return failure(StatusCode::REQUEST_TIMEOUT, "association_body_timeout"),
        };
    if expected.is_some_and(|n| n != bytes.len()) {
        return error(AssociationError::InvalidRequest);
    }
    let mutation = !matches!(action.as_str(), "inspect" | "receipt");
    let identity = Authenticated {
        class,
        org,
        actor: &actor,
        key: producer,
        resource,
    };
    let result = tokio::time::timeout(
        Duration::from_secs(15),
        dispatch(&state.pool, identity, &action, &bytes),
    )
    .await;
    match result {
        Ok(Ok(value)) => ([("cache-control", "no-store")], Json(value)).into_response(),
        Ok(Err(e)) => error(e),
        Err(_) => error(if mutation {
            AssociationError::CommitUnknown
        } else {
            AssociationError::Unavailable
        }),
    }
}

async fn dispatch(
    pool: &PgPool,
    identity: Authenticated<'_>,
    action: &str,
    bytes: &[u8],
) -> Result<Value, AssociationError> {
    let Authenticated {
        class,
        org,
        actor,
        key,
        resource,
    } = identity;
    if class == Class::Source {
        let scope = domain::SourceScope {
            organization: org,
            actor,
            grant: resource,
        };
        if action == "inspect" || action == "receipt" {
            let op = if action == "receipt" {
                Some(decode::<Receipt>(bytes)?.operation_id)
            } else {
                decode::<Empty>(bytes)?;
                None
            };
            return output(domain::inspect_source(pool, scope, op).await, false);
        }
        let request = match action {
            "create" => domain::SourceRequest::Create(decode(bytes)?),
            "approve" => domain::SourceRequest::Approve(decode(bytes)?),
            "revoke" => domain::SourceRequest::Revoke(decode(bytes)?),
            "replace-key" => domain::SourceRequest::ReplaceKey(decode(bytes)?),
            "change-expiry" => domain::SourceRequest::ChangeExpiry(decode(bytes)?),
            _ => return Err(AssociationError::InvalidRequest),
        };
        return output(domain::mutate_source(pool, scope, &request).await, true);
    }
    if class == Class::Identity {
        let scope = domain::IdentityScope {
            organization: org,
            user_id: actor,
            identity_id: resource,
        };
        return match action {
            "unlink" => output(domain::unlink(pool, scope, &decode(bytes)?).await, true),
            "receipt" => output(
                domain::recover_unlink(pool, scope, decode::<Receipt>(bytes)?.operation_id).await,
                false,
            ),
            _ => Err(AssociationError::InvalidRequest),
        };
    }
    let learner = domain::LearnerScope {
        organization: org,
        user_id: actor,
        challenge_id: resource,
    };
    if action == "inspect" || action == "receipt" {
        let op = if action == "receipt" {
            Some(decode::<Receipt>(bytes)?.operation_id)
        } else {
            decode::<Empty>(bytes)?;
            None
        };
        let reader = if let Some(api_key_id) = key {
            domain::ChallengeReader::Producer {
                scope: domain::ProducerScope {
                    organization: org,
                    api_key_id,
                },
                challenge_id: resource,
            }
        } else {
            domain::ChallengeReader::Learner(learner)
        };
        return output(domain::inspect_challenge(pool, reader, op).await, false);
    }
    if class == Class::Producer {
        let scope = domain::ProducerScope {
            organization: org,
            api_key_id: key.ok_or(AssociationError::InvalidRequest)?,
        };
        if action == "create" {
            let request: domain::CreateChallenge = decode(bytes)?;
            if request.challenge_id != resource {
                return Err(AssociationError::InvalidRequest);
            }
            return output(domain::create_challenge(pool, scope, &request).await, true);
        }
        let request = decode(bytes)?;
        let action = match action {
            "abandon" => domain::CloseAction::Abandon,
            "expire" => domain::CloseAction::Expire,
            _ => return Err(AssociationError::InvalidRequest),
        };
        return output(
            domain::close_challenge(pool, scope, resource, action, &request).await,
            true,
        );
    }
    let (request, action) = match action {
        "confirm" => (decode(bytes)?, domain::ConsentAction::Confirm),
        "deny" => (decode(bytes)?, domain::ConsentAction::Deny),
        "relink" => {
            let v: Relink = decode(bytes)?;
            (
                domain::ChallengeConsent {
                    operation_id: v.operation_id,
                    expected_revision: v.expected_revision,
                    code: v.code,
                },
                domain::ConsentAction::Relink {
                    expected_identity_revision: v.expected_identity_revision,
                },
            )
        }
        _ => return Err(AssociationError::InvalidRequest),
    };
    output(domain::consent(pool, learner, action, &request).await, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;
    const SERVICE: &str = "synthetic-gateway-service-key-000000000001";
    const ORG: &str = "10000000-0000-4000-8000-000000000001";
    const RESOURCE: &str = "20000000-0000-4000-8000-00000000000a";
    fn router() -> Router {
        association_router(
            sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
                .unwrap(),
            SERVICE.as_bytes(),
        )
        .unwrap()
    }
    fn request(path: &str, body: Body) -> HttpRequest<Body> {
        HttpRequest::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("x-api-key", SERVICE)
            .header("x-organization-id", ORG)
            .header("x-user-id", "learner-one")
            .body(body)
            .unwrap()
    }
    async fn rejected(request: HttpRequest<Body>, status: StatusCode) {
        let response = router().oneshot(request).await.unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    }
    #[tokio::test]
    async fn identity_confusion_and_original_body_failures_never_reach_storage() {
        let source =
            format!("/v1/organizations/{ORG}/external-association-sources/{RESOURCE}/approve");
        let producer = format!("/v1/identity/association-challenges/{RESOURCE}/create");
        let learner =
            format!("/v1/organizations/{ORG}/external-association-challenges/{RESOURCE}/confirm");
        let duplicate = r#"{"operation_id":"30000000-0000-4000-8000-000000000001","expected_revision":1,"expected_revision":2}"#;
        rejected(
            request(&source, Body::from(duplicate)),
            StatusCode::BAD_REQUEST,
        )
        .await;
        rejected(request(&learner,Body::from(r#"{"operation_id":"30000000-0000-4000-8000-000000000001","expected_revision":1,"code":"x","user_id":"forged"}"#)),StatusCode::BAD_REQUEST).await;
        rejected(
            request(&producer, Body::from("{}")),
            StatusCode::UNAUTHORIZED,
        )
        .await;
        let mut confused = request(&source, Body::from("{}"));
        confused
            .headers_mut()
            .insert("x-api-key-id", RESOURCE.parse().unwrap());
        rejected(confused, StatusCode::UNAUTHORIZED).await;
        let mut confused = request(&producer, Body::from("{}"));
        confused
            .headers_mut()
            .insert("x-api-key-id", RESOURCE.parse().unwrap());
        rejected(confused, StatusCode::UNAUTHORIZED).await;
        let mut producer_unknown = request(&producer, Body::from(r#"{"user_id":"forged"}"#));
        producer_unknown.headers_mut().remove("x-user-id");
        producer_unknown
            .headers_mut()
            .insert("x-api-key-id", RESOURCE.parse().unwrap());
        rejected(producer_unknown, StatusCode::BAD_REQUEST).await;
        for name in ["x-api-key", "x-organization-id", "x-user-id"] {
            let mut missing = request(&source, Body::from("{}"));
            missing.headers_mut().remove(name);
            rejected(missing, StatusCode::UNAUTHORIZED).await;
        }
        let mut tenant = request(&source, Body::from("{}"));
        tenant.headers_mut().insert(
            "x-organization-id",
            "10000000-0000-4000-8000-000000000002".parse().unwrap(),
        );
        rejected(tenant, StatusCode::FORBIDDEN).await;
        let mut duplicate_org = request(&source, Body::from("{}"));
        duplicate_org
            .headers_mut()
            .append("x-organization-id", ORG.parse().unwrap());
        rejected(duplicate_org, StatusCode::UNAUTHORIZED).await;
        rejected(
            request(&format!("{source}?user_id=forged"), Body::from("{}")),
            StatusCode::BAD_REQUEST,
        )
        .await;
        rejected(
            request(
                &source.replace(RESOURCE, &RESOURCE.to_uppercase()),
                Body::from("{}"),
            ),
            StatusCode::BAD_REQUEST,
        )
        .await;
        rejected(
            request(&source, Body::from(" ".repeat(4097))),
            StatusCode::PAYLOAD_TOO_LARGE,
        )
        .await;
        let mut mismatch = request(&source, Body::from("{} "));
        mismatch
            .headers_mut()
            .insert("content-length", "2".parse().unwrap());
        rejected(mismatch, StatusCode::BAD_REQUEST).await;
        let mut ambiguous = request(&source, Body::from("{}"));
        ambiguous
            .headers_mut()
            .insert("content-length", "2".parse().unwrap());
        ambiguous
            .headers_mut()
            .insert("transfer-encoding", "chunked".parse().unwrap());
        rejected(ambiguous, StatusCode::BAD_REQUEST).await;
        let mut trailer = request(&source, Body::from("{}"));
        trailer
            .headers_mut()
            .insert("trailer", "x-user-id".parse().unwrap());
        rejected(trailer, StatusCode::BAD_REQUEST).await;
        let body = Body::new(
            http_body_util::Full::new(axum::body::Bytes::from_static(b"{}"))
                .with_trailers(async { Some(Ok(HeaderMap::new())) }),
        );
        rejected(request(&source, body), StatusCode::BAD_REQUEST).await;
    }
}
