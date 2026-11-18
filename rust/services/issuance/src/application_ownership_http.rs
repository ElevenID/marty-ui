// SPDX-License-Identifier: AGPL-3.0-only
//! Session-only Core boundary behind the authenticated public Common Gateway.
use crate::application_ownership::{
    self, OwnershipAction, OwnershipChange, OwnershipError, OwnershipMutation, OwnershipProposal,
};
use axum::{
    body::to_bytes,
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use uuid::Uuid;

pub const BASE: &str =
    "/v1/organizations/{organization_id}/application-ownerships/{application_id}";
struct OwnershipState {
    pool: PgPool,
    service_key: Vec<u8>,
}
pub fn ownership_router(pool: PgPool, service_key: &[u8]) -> Result<Router, &'static str> {
    if !(32..=512).contains(&service_key.len()) || !service_key.iter().all(u8::is_ascii_graphic) {
        return Err("Invalid ownership Gateway service credential");
    }
    let mut router = Router::new();
    for action in ["propose", "confirm", "revoke", "inspect", "receipt"] {
        router = router.route(&format!("{BASE}/{action}"), post(handle));
    }
    Ok(router.with_state(Arc::new(OwnershipState {
        pool,
        service_key: service_key.to_vec(),
    })))
}
fn one<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(first)
}
fn failure(status: StatusCode, code: &'static str) -> Response {
    (
        status,
        [("cache-control", "no-store")],
        Json(json!({"error":code})),
    )
        .into_response()
}
fn error(error: OwnershipError) -> Response {
    let (status, code) = match error {
        OwnershipError::InvalidRequest => (StatusCode::BAD_REQUEST, "invalid_ownership_request"),
        OwnershipError::NotAuthorized => (StatusCode::FORBIDDEN, "ownership_not_authorized"),
        OwnershipError::Conflict => (StatusCode::CONFLICT, "ownership_conflict"),
        OwnershipError::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "ownership_unavailable"),
        OwnershipError::CommitUnknown => {
            (StatusCode::SERVICE_UNAVAILABLE, "ownership_commit_unknown")
        }
    };
    failure(status, code)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptRequest {
    operation_id: Uuid,
}

async fn handle(
    State(state): State<Arc<OwnershipState>>,
    Path((org, app)): Path<(Uuid, String)>,
    request: Request,
) -> Response {
    let headers = request.headers();
    if one(headers, "x-api-key")
        .is_none_or(|key| key.as_bytes().ct_eq(&state.service_key).unwrap_u8() != 1)
        || headers.contains_key("x-api-key-id")
        || one(headers, "x-organization-id") != Some(org.to_string().as_str())
    {
        return failure(StatusCode::UNAUTHORIZED, "ownership_session_required");
    }
    let Some(actor) = one(headers, "x-user-id")
        .filter(|id| {
            !id.is_empty()
                && id.len() <= 128
                && id.as_bytes()[0].is_ascii_alphanumeric()
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
        .map(str::to_owned)
    else {
        return failure(StatusCode::UNAUTHORIZED, "ownership_session_required");
    };
    let action = request
        .uri()
        .path()
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_owned();
    if org.is_nil()
        || app.is_empty()
        || app.len() > 128
        || !app
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        || request.uri().query().is_some()
        || request.uri().path()
            != format!("/v1/organizations/{org}/application-ownerships/{app}/{action}")
    {
        return error(OwnershipError::InvalidRequest);
    }
    if !one(headers, "content-type").is_some_and(|v| v.eq_ignore_ascii_case("application/json"))
        || one(headers, "content-encoding").is_some_and(|v| !v.eq_ignore_ascii_case("identity"))
    {
        return failure(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_ownership_format",
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
        return error(OwnershipError::InvalidRequest);
    }
    let length = match one(headers, "content-length") {
        Some(v) if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) => {
            match v.parse::<usize>() {
                Ok(value) if value <= 4096 => Some(value),
                _ => return error(OwnershipError::InvalidRequest),
            }
        }
        Some(_) => return error(OwnershipError::InvalidRequest),
        None => None,
    };
    let bytes =
        match tokio::time::timeout(Duration::from_secs(10), to_bytes(request.into_body(), 4096))
            .await
        {
            Ok(Ok(value)) => value,
            Ok(Err(_)) => {
                return failure(StatusCode::PAYLOAD_TOO_LARGE, "ownership_request_too_large")
            }
            Err(_) => return failure(StatusCode::REQUEST_TIMEOUT, "ownership_body_timeout"),
        };
    if length.is_some_and(|length| length != bytes.len()) {
        return error(OwnershipError::InvalidRequest);
    }
    if action == "inspect" || action == "receipt" {
        let operation = if action == "receipt" {
            match serde_json::from_slice::<ReceiptRequest>(&bytes) {
                Ok(value) => Some(value.operation_id),
                Err(_) => return error(OwnershipError::InvalidRequest),
            }
        } else {
            if serde_json::from_slice::<Empty>(&bytes).is_err() {
                return error(OwnershipError::InvalidRequest);
            }
            None
        };
        return match tokio::time::timeout(
            Duration::from_secs(15),
            application_ownership::read(&state.pool, org, &app, &actor, operation),
        )
        .await
        {
            Ok(Ok(value)) => ([("cache-control", "no-store")], Json(value)).into_response(),
            Ok(Err(value)) => error(value),
            Err(_) => error(OwnershipError::Unavailable),
        };
    }
    let (operation, expected, application_revision, recipient, kind) = if action == "propose" {
        match serde_json::from_slice::<OwnershipProposal>(&bytes) {
            Ok(v) => (
                v.operation_id,
                v.expected_revision,
                v.expected_application_revision,
                Some(v.user_id),
                OwnershipAction::Propose,
            ),
            Err(_) => return error(OwnershipError::InvalidRequest),
        }
    } else {
        let kind = match action.as_str() {
            "confirm" => OwnershipAction::Confirm,
            "revoke" => OwnershipAction::Revoke,
            _ => return error(OwnershipError::InvalidRequest),
        };
        match serde_json::from_slice::<OwnershipChange>(&bytes) {
            Ok(v) => (
                v.operation_id,
                v.expected_revision,
                v.expected_application_revision,
                None,
                kind,
            ),
            Err(_) => return error(OwnershipError::InvalidRequest),
        }
    };
    let command = OwnershipMutation {
        org,
        app: &app,
        actor: &actor,
        operation,
        action: kind,
        expected,
        application_revision,
        recipient: recipient.as_deref(),
    };
    match tokio::time::timeout(
        Duration::from_secs(15),
        application_ownership::mutate(&state.pool, &command),
    )
    .await
    {
        Ok(Ok(value)) => ([("cache-control", "no-store")], Json(value)).into_response(),
        Ok(Err(value)) => error(value),
        Err(_) => error(OwnershipError::CommitUnknown),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;
    const ORG: &str = "20000000-0000-4000-8000-000000000001";
    const KEY: &str = "synthetic-gateway-service-key-000000000001";
    fn request(action: &str, body: &str) -> Request {
        Request::builder()
            .method("POST")
            .uri(format!(
                "/v1/organizations/{ORG}/application-ownerships/app-one/{action}"
            ))
            .header("x-api-key", KEY)
            .header("x-organization-id", ORG)
            .header("x-user-id", "learner-one")
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap()
    }
    #[tokio::test]
    async fn identity_spoofs_and_original_byte_body_failures_never_reach_database() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://synthetic:synthetic@127.0.0.1:1/unused")
            .unwrap();
        let router = ownership_router(pool.clone(), KEY.as_bytes()).unwrap();
        for mutation in [
            "producer",
            "bad-service",
            "wrong-org",
            "duplicate-user",
            "unknown-field",
            "duplicate-field",
            "oversize",
            "bad-length",
            "ambiguous-frame",
        ] {
            let mut req = request(
                "confirm",
                r#"{"operation_id":"30000000-0000-4000-8000-000000000001","expected_revision":1,"expected_application_revision":1}"#,
            );
            let expected = match mutation {
                "producer" => {
                    req.headers_mut().insert(
                        "x-api-key-id",
                        "30000000-0000-4000-8000-000000000002".parse().unwrap(),
                    );
                    StatusCode::UNAUTHORIZED
                }
                "bad-service" => {
                    req.headers_mut()
                        .insert("x-api-key", "forged".parse().unwrap());
                    StatusCode::UNAUTHORIZED
                }
                "wrong-org" => {
                    req.headers_mut().insert(
                        "x-organization-id",
                        "20000000-0000-4000-8000-000000000002".parse().unwrap(),
                    );
                    StatusCode::UNAUTHORIZED
                }
                "duplicate-user" => {
                    req.headers_mut()
                        .append("x-user-id", "other-user".parse().unwrap());
                    StatusCode::UNAUTHORIZED
                }
                "unknown-field" => {
                    *req.body_mut() = Body::from(
                        r#"{"operation_id":"30000000-0000-4000-8000-000000000001","expected_revision":1,"expected_application_revision":1,"user_id":"other-user"}"#,
                    );
                    StatusCode::BAD_REQUEST
                }
                "duplicate-field" => {
                    *req.body_mut() = Body::from(
                        r#"{"operation_id":"30000000-0000-4000-8000-000000000001","expected_revision":1,"expected_revision":2,"expected_application_revision":1}"#,
                    );
                    StatusCode::BAD_REQUEST
                }
                "oversize" => {
                    *req.body_mut() = Body::from(vec![b' '; 4097]);
                    StatusCode::PAYLOAD_TOO_LARGE
                }
                "bad-length" => {
                    req.headers_mut()
                        .insert("content-length", "1".parse().unwrap());
                    StatusCode::BAD_REQUEST
                }
                _ => {
                    req.headers_mut()
                        .insert("content-length", "1".parse().unwrap());
                    req.headers_mut()
                        .insert("transfer-encoding", "chunked".parse().unwrap());
                    StatusCode::BAD_REQUEST
                }
            };
            let response = router.clone().oneshot(req).await.unwrap();
            assert_eq!(response.status(), expected, "{mutation}");
            assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        }
        assert_eq!(pool.size(), 0);
        pool.close().await;
    }
}
