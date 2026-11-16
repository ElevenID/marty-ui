// SPDX-License-Identifier: AGPL-3.0-only
//! Issuance HTTP boundary. Mount only behind the authenticated Common Gateway;
//! the connector never receives the service credential or a private endpoint.
use std::{sync::Arc, time::Duration};

use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde_json::json;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{
    external_observation_admission::Denial,
    external_observation_ingress::{submit_observation, IngressError},
    external_observation_postgres::{JournalError, PostgresObservationJournal, ProducerIdentity},
    external_observation_wire::{WireError, MAX_BODY_BYTES},
};

pub const OBSERVATION_PATH: &str = "/v1/evidence/observations";

struct HttpState {
    journal: Arc<PostgresObservationJournal>,
    gateway_service_key: Vec<u8>,
}

/// Explicit service credential is mandatory; there is no environment/default
/// identity. This router alone does not authenticate public organization keys.
pub fn observation_router(
    journal: Arc<PostgresObservationJournal>,
    gateway_service_key: &[u8],
) -> Result<Router, &'static str> {
    if !(32..=512).contains(&gateway_service_key.len())
        || !gateway_service_key.iter().all(u8::is_ascii_graphic)
    {
        return Err("Invalid observation Gateway service credential");
    }
    Ok(Router::new()
        .route(OBSERVATION_PATH, post(submit))
        .with_state(Arc::new(HttpState {
            journal,
            gateway_service_key: gateway_service_key.to_vec(),
        })))
}

pub(crate) fn one_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(first)
}

fn canonical_uuid(value: &str) -> Option<String> {
    let parsed = Uuid::parse_str(value).ok()?;
    if parsed.is_nil() || parsed.to_string() != value {
        return None;
    }
    Some(parsed.to_string())
}

pub(crate) fn gateway_service_authenticated(headers: &HeaderMap, expected: &[u8]) -> bool {
    one_header(headers, "x-api-key")
        .is_some_and(|supplied| supplied.as_bytes().ct_eq(expected).unwrap_u8() == 1)
}

fn identity(headers: &HeaderMap, state: &HttpState) -> Option<ProducerIdentity> {
    if !gateway_service_authenticated(headers, &state.gateway_service_key) {
        return None;
    }
    Some(ProducerIdentity {
        api_key_id: canonical_uuid(one_header(headers, "x-api-key-id")?)?,
        organization_id: canonical_uuid(one_header(headers, "x-organization-id")?)?,
    })
}

fn failure(status: StatusCode, code: &'static str) -> Response {
    (
        status,
        [("cache-control", "no-store")],
        Json(json!({"error":code})),
    )
        .into_response()
}

fn ingress_failure(error: IngressError) -> Response {
    let (status, code) = match error {
        IngressError::Request(WireError::BodyTooLarge) => {
            (StatusCode::PAYLOAD_TOO_LARGE, "observation_too_large")
        }
        IngressError::Request(WireError::UnsupportedMediaType | WireError::UnsupportedEncoding) => {
            (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_observation_format",
            )
        }
        IngressError::Request(_) => (StatusCode::BAD_REQUEST, "invalid_observation_request"),
        IngressError::Journal(JournalError::Denied(Denial::AuthenticationRequired)) => (
            StatusCode::UNAUTHORIZED,
            "observation_authentication_required",
        ),
        IngressError::Journal(JournalError::Denied(
            Denial::ScopeMissing | Denial::NotAuthorized,
        )) => (StatusCode::FORBIDDEN, "observation_not_authorized"),
        IngressError::Journal(JournalError::Denied(
            Denial::InvalidRequest
            | Denial::InvalidClaims
            | Denial::StaleObservation
            | Denial::FutureObservation,
        )) => (StatusCode::BAD_REQUEST, "invalid_observation_request"),
        IngressError::Journal(
            JournalError::Denied(
                Denial::BindingChanged
                | Denial::ApplicationClosed
                | Denial::ReplayConflict
                | Denial::OutOfOrder,
            )
            | JournalError::Conflict,
        ) => (StatusCode::CONFLICT, "observation_conflict"),
        IngressError::Journal(JournalError::CommitUnknown) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "observation_reconciliation_required",
        ),
        IngressError::Journal(_) => (StatusCode::SERVICE_UNAVAILABLE, "observation_unavailable"),
    };
    failure(status, code)
}

async fn submit(State(state): State<Arc<HttpState>>, request: Request) -> Response {
    let Some(identity) = identity(request.headers(), &state) else {
        return failure(
            StatusCode::UNAUTHORIZED,
            "observation_authentication_required",
        );
    };
    if request.uri().query().is_some() {
        return failure(StatusCode::BAD_REQUEST, "invalid_observation_request");
    }
    let (parts, body) = request.into_parts();
    let bytes =
        match tokio::time::timeout(Duration::from_secs(10), to_bytes(body, MAX_BODY_BYTES)).await {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(_)) => return failure(StatusCode::PAYLOAD_TOO_LARGE, "observation_too_large"),
            Err(_) => return failure(StatusCode::REQUEST_TIMEOUT, "observation_body_timeout"),
        };
    match submit_observation(&state.journal, &identity, &parts.headers, &bytes).await {
        Ok(ack) => (
            StatusCode::OK,
            [("cache-control", "no-store")],
            Json(json!({"receipt_id":ack.receipt_id,"replayed":ack.replayed})),
        )
            .into_response(),
        Err(error) => ingress_failure(error),
    }
}
