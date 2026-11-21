//! Explicit internal original-receipt retrieval. Public command/discovery and
//! human administration routes remain separate from this protected artifact.
use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{
    body::to_bytes,
    extract::{Path, Request, State},
    http::StatusCode,
    middleware,
    routing::post,
    Json, Router,
};
use chrono::Utc;

use crate::{
    decode_delegation_use_command,
    use_http::{
        no_store, single_header, AuthenticatedDelegationUseContext, DelegationUseHttpAuthenticator,
        UseHttpError,
    },
    DecodedDelegationUseCommand, DelegationUseCommandError, DelegationUseCommandService,
    RecoveredDelegatedUseReceipt,
};

#[async_trait]
pub trait DelegationUseReceiptHttpApplication: Send + Sync {
    async fn recover_receipt(
        &self,
        context: &AuthenticatedDelegationUseContext,
        raw: &[u8],
    ) -> Result<RecoveredDelegatedUseReceipt, DelegationUseCommandError>;
}
#[async_trait]
impl DelegationUseReceiptHttpApplication for DelegationUseCommandService {
    async fn recover_receipt(
        &self,
        context: &AuthenticatedDelegationUseContext,
        raw: &[u8],
    ) -> Result<RecoveredDelegatedUseReceipt, DelegationUseCommandError> {
        self.recover_receipt_before(
            context.caller(),
            raw,
            context.observed_at(),
            context.valid_until(),
        )
        .await
    }
}

#[derive(Clone)]
pub struct DelegationUseReceiptHttpState {
    application: Arc<dyn DelegationUseReceiptHttpApplication>,
    authenticator: Arc<DelegationUseHttpAuthenticator>,
}
impl DelegationUseReceiptHttpState {
    pub fn with_authenticator(
        application: Arc<dyn DelegationUseReceiptHttpApplication>,
        authenticator: Arc<DelegationUseHttpAuthenticator>,
    ) -> Self {
        Self {
            application,
            authenticator,
        }
    }
}

pub fn delegated_use_receipt_router(state: DelegationUseReceiptHttpState) -> Router {
    Router::new()
        .route(
            "/internal/v1/organizations/{organization_id}/delegated-use/receipts/recover",
            post(recover),
        )
        .with_state(state)
        .layer(middleware::from_fn(no_store))
}

async fn recover(
    State(state): State<DelegationUseReceiptHttpState>,
    Path(organization): Path<String>,
    request: Request,
) -> Result<Json<RecoveredDelegatedUseReceipt>, UseHttpError> {
    let context = state.authenticator.authenticate(&organization, &request)?;
    if request.uri().query().is_some() {
        return Err(DelegationUseCommandError::InvalidCommand.into());
    }
    let content_type = single_header(request.headers(), "content-type")?;
    if !content_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err(UseHttpError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "delegation_use_json_required",
        ));
    }
    let raw = tokio::time::timeout(
        Duration::from_secs(5),
        to_bytes(request.into_body(), crate::wire::MAX_GRANT_WIRE_BYTES),
    )
    .await
    .map_err(|_| UseHttpError::new(StatusCode::REQUEST_TIMEOUT, "delegation_use_body_timeout"))?
    .map_err(|_| {
        UseHttpError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "delegation_use_body_too_large",
        )
    })?;
    if !matches!(
        decode_delegation_use_command(&raw)?,
        DecodedDelegationUseCommand::Recover { .. }
    ) {
        return Err(DelegationUseCommandError::Unsupported.into());
    }
    context.check(Utc::now())?;
    let recovered = state.application.recover_receipt(&context, &raw).await?;
    context.check(Utc::now())?;
    Ok(Json(recovered))
}

#[cfg(test)]
#[path = "use_receipt_http_tests.rs"]
mod tests;
