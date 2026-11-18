//! Trusted, explicitly selected physical-bureau callback ingress.

use std::collections::BTreeMap;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use reqwest::{Client, Url};
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::{
    passport_bureau::ProductionStatus,
    passport_callback_handoff::{sign_and_deliver, verify_provider_callback},
    passport_repository::{PassportWebhookRepositoryError, PostgresPassportRepository},
};

const MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct ProviderIngressState {
    pub provider_profile_id: String,
    pub provider_hmac_key_version: u32,
    pub repository: PostgresPassportRepository,
    pub signing_base_url: Url,
    pub signing_api_key: String,
    pub native_callback_url: Url,
    pub http: Client,
}

#[derive(Debug)]
enum IngressError {
    InvalidSignature,
    InvalidEvent,
    Unresolved,
    Unavailable,
}

impl IntoResponse for IngressError {
    fn into_response(self) -> Response {
        let (status, detail) = match self {
            Self::InvalidSignature => (
                StatusCode::UNAUTHORIZED,
                "Invalid personalization webhook signature",
            ),
            Self::InvalidEvent => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid personalization webhook event",
            ),
            Self::Unresolved => (StatusCode::NOT_FOUND, "Physical document job not found"),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Passport callback unavailable",
            ),
        };
        (status, Json(json!({"detail": detail}))).into_response()
    }
}

#[derive(Serialize)]
struct InternalCallback<'a> {
    organization_id: &'a str,
    provider_profile_id: &'a str,
    bureau_job_id: &'a str,
    status: ProductionStatus,
    #[serde(flatten)]
    metadata: BTreeMap<String, Value>,
}

pub fn router(state: ProviderIngressState) -> Router {
    Router::new()
        .route("/health", get(|| async { Json(json!({"status": "ok"})) }))
        .route(
            "/v1/passport/webhooks/personalization",
            post(provider_webhook),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

async fn provider_webhook(
    State(state): State<ProviderIngressState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, IngressError> {
    let signature = headers
        .get("x-personalization-signature")
        .and_then(|value| value.to_str().ok())
        .ok_or(IngressError::InvalidSignature)?;
    if body.is_empty()
        || body.len() > MAX_BODY_BYTES
        || signature.len() != 64
        || !signature
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(IngressError::InvalidSignature);
    }
    let valid = verify_provider_callback(
        &state.http,
        &state.signing_base_url,
        &state.signing_api_key,
        &state.provider_profile_id,
        state.provider_hmac_key_version,
        &body,
        signature,
    )
    .await
    .map_err(|_| IngressError::Unavailable)?;
    if !valid {
        return Err(IngressError::InvalidSignature);
    }
    let mut event: Map<String, Value> =
        serde_json::from_slice(&body).map_err(|_| IngressError::InvalidEvent)?;
    let bureau_job_id = event
        .remove("bureau_job_id")
        .and_then(|value| value.as_str().map(str::to_owned))
        .filter(|value| !value.is_empty() && value.len() <= 255)
        .ok_or(IngressError::InvalidEvent)?;
    let status: ProductionStatus =
        serde_json::from_value(event.remove("status").ok_or(IngressError::InvalidEvent)?)
            .map_err(|_| IngressError::InvalidEvent)?;
    let provider_claim = event.remove("provider_profile_id");
    if provider_claim.is_some() {
        return Err(IngressError::InvalidEvent);
    }
    let untrusted_org = event.remove("organization_id");
    let organization_id = state
        .repository
        .resolve_provider_callback_tenant(&state.provider_profile_id, &bureau_job_id)
        .await
        .map_err(|error| match error {
            PassportWebhookRepositoryError::Storage(_) => IngressError::Unavailable,
            PassportWebhookRepositoryError::AmbiguousBureauJob
            | PassportWebhookRepositoryError::InvalidProviderBinding => IngressError::Unresolved,
        })?
        .ok_or(IngressError::Unresolved)?;
    if untrusted_org
        .as_ref()
        .is_some_and(|value| value.as_str() != Some(&organization_id))
    {
        return Err(IngressError::Unresolved);
    }
    let callback = InternalCallback {
        organization_id: &organization_id,
        provider_profile_id: &state.provider_profile_id,
        bureau_job_id: &bureau_job_id,
        status,
        metadata: event.into_iter().collect(),
    };
    let internal_body = serde_json::to_vec(&callback).map_err(|_| IngressError::InvalidEvent)?;
    if internal_body.len() > MAX_BODY_BYTES {
        return Err(IngressError::InvalidEvent);
    }
    sign_and_deliver(
        &state.http,
        &state.signing_base_url,
        &state.signing_api_key,
        &state.native_callback_url,
        &organization_id,
        &internal_body,
    )
    .await
    .map_err(|_| IngressError::Unavailable)?;
    Ok(Json(json!({"accepted": true})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_internal_callback_body_order_and_metadata_are_preserved() {
        let mut metadata = BTreeMap::new();
        metadata.insert("tracking_number".to_owned(), json!("TRACK-42"));
        let body = serde_json::to_string(&InternalCallback {
            organization_id: "org-reference",
            provider_profile_id: "provider-reference",
            bureau_job_id: "bureau-reference",
            status: ProductionStatus::Shipped,
            metadata,
        })
        .unwrap();
        assert_eq!(body, "{\"organization_id\":\"org-reference\",\"provider_profile_id\":\"provider-reference\",\"bureau_job_id\":\"bureau-reference\",\"status\":\"SHIPPED\",\"tracking_number\":\"TRACK-42\"}");
    }
}
