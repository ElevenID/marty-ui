use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::{
    authenticate_forwarded_http_request,
    offline_audit::{OfflineAuditBatch, OfflineAuditError, CONTRACT, MAX_BATCH, MAX_BODY_BYTES},
    offline_audit_store::OfflineAuditAuthority,
    OrganizationHttpState,
};

pub(crate) fn organization_offline_audit_router() -> Router<OrganizationHttpState> {
    Router::new()
        .route(
            "/v1/organizations/{organization_id}/offline-verification-events",
            get(capabilities).post(ingest),
        )
        .route(
            "/v1/organizations/{organization_id}/offline-verification-events/{verification_id}",
            get(receipt),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

impl IntoResponse for OfflineAuditError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::InvalidEvent => StatusCode::BAD_REQUEST,
            Self::Conflict => StatusCode::CONFLICT,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Persistence => StatusCode::SERVICE_UNAVAILABLE,
        };
        no_store((status, Json(json!({"detail":self.to_string()}))).into_response())
    }
}

fn authority(
    state: &OrganizationHttpState,
    headers: &HeaderMap,
    organization_id: Uuid,
) -> Result<OfflineAuditAuthority, OfflineAuditError> {
    let principal = authenticate_forwarded_http_request(headers, &state.service_authenticator)
        .map_err(|_| OfflineAuditError::Unauthorized)?;
    OfflineAuditAuthority::from_principal(organization_id, &principal)
}

async fn capabilities(
    State(state): State<OrganizationHttpState>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
) -> Result<Response, OfflineAuditError> {
    let authority = authority(&state, &headers, organization_id)?;
    let transaction = state
        .application
        .offline_audit_transaction(authority)
        .await?;
    transaction
        .commit()
        .await
        .map_err(|_| OfflineAuditError::Persistence)?;
    Ok(no_store(
        Json(json!({
            "kind":CONTRACT,
            "organization_id":authority.organization_id,
            "producer_id":authority.producer_id,
            "max_batch":MAX_BATCH,
            "receipt_storage":"organization_service.audit_events",
            "scope":"authenticated_api_key",
            "evidence":"client_reported_offline_verification"
        }))
        .into_response(),
    ))
}

async fn ingest(
    State(state): State<OrganizationHttpState>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
    body: Result<Json<OfflineAuditBatch>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, OfflineAuditError> {
    let authority = authority(&state, &headers, organization_id)?;
    let events = body
        .map_err(|_| OfflineAuditError::InvalidEvent)?
        .0
        .validate(Utc::now())?;
    let acknowledgement = state
        .application
        .ingest_offline_audit(authority, events)
        .await?;
    Ok(no_store(Json(acknowledgement).into_response()))
}

async fn receipt(
    State(state): State<OrganizationHttpState>,
    headers: HeaderMap,
    Path((organization_id, verification_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, OfflineAuditError> {
    let authority = authority(&state, &headers, organization_id)?;
    let receipt = state
        .application
        .offline_audit_receipt(authority, verification_id)
        .await?;
    Ok(no_store(Json(receipt).into_response()))
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
