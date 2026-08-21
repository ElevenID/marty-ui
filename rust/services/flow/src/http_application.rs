use std::{collections::BTreeMap, sync::Arc};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use chrono::Utc;
use mmf_security::{
    ApplicationEventAuthError, ApplicationEventAuthenticator, ApplicationEventReplayStore,
};
use serde_json::Value;

use crate::{
    execute_application_event_plan, parse_request, ApplicationApprovalError,
    ApplicationApprovedWebhook, FlowHttpError, FlowHttpState, FlowServiceConfig,
    RedisApplicationEventReplayStore,
};

#[derive(Clone, Default)]
pub struct FlowHttpApplicationApprovalOptions {
    authenticator: Option<ApplicationEventAuthenticator>,
    replay_store: Option<Arc<dyn ApplicationEventReplayStore>>,
}

impl FlowHttpApplicationApprovalOptions {
    pub fn from_config(
        config: &FlowServiceConfig,
        nonce_store: redis::aio::ConnectionManager,
    ) -> Result<Self, ApplicationEventAuthError> {
        let secret = config
            .application_event_hmac_key
            .as_deref()
            .ok_or(ApplicationEventAuthError::Configuration)?;
        let authenticator = ApplicationEventAuthenticator::new(
            secret,
            i64::from(config.application_event_max_age_seconds),
            u64::from(config.application_event_replay_ttl_seconds),
        )?;
        Ok(Self {
            authenticator: Some(authenticator),
            replay_store: Some(Arc::new(RedisApplicationEventReplayStore::new(nonce_store))),
        })
    }
}

pub fn flow_application_routes() -> Router<FlowHttpState> {
    Router::new().route(
        "/v1/flows/webhooks/application-approved",
        post(receive_application_approved),
    )
}

async fn receive_application_approved(
    State(state): State<FlowHttpState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<crate::ApplicationApprovalResponse>, FlowHttpError> {
    let event: ApplicationApprovedWebhook = parse_request(payload.clone()).map_err(|error| {
        FlowHttpError::new(
            StatusCode::BAD_REQUEST,
            "FLOW.INVALID_REQUEST",
            error.to_string(),
        )
    })?;
    let authenticator = state
        .application_approval
        .authenticator
        .as_ref()
        .ok_or_else(native_unavailable)?;
    let replay_store = state
        .application_approval
        .replay_store
        .as_deref()
        .ok_or_else(native_unavailable)?;
    let metadata = event_metadata(&headers);
    let now = Utc::now();
    let evidence = authenticator
        .authenticate(&payload, &metadata, now.timestamp())
        .map_err(application_auth_error)?;
    let response = execute_application_event_plan(
        &event,
        &evidence,
        crate::ApplicationEventExecutionContext {
            authenticator,
            replay_store,
            repository: &state.repository,
            providers: &state.providers,
            public_base_url: &state.public_base_url,
        },
        now,
    )
    .await
    .map_err(application_error)?;
    Ok(Json(response))
}

fn event_metadata(headers: &HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().into(), value.into()))
        })
        .collect()
}

fn application_error(error: ApplicationApprovalError) -> FlowHttpError {
    match error {
        ApplicationApprovalError::Authentication(error) => application_auth_error(error),
        ApplicationApprovalError::Api(error) => FlowHttpError::new(
            StatusCode::BAD_REQUEST,
            "FLOW.INVALID_REQUEST",
            error.to_string(),
        ),
        ApplicationApprovalError::Conflict(_) => FlowHttpError::new(
            StatusCode::CONFLICT,
            "APPLICATION_OFFER_CONFLICT",
            error.to_string(),
        ),
        ApplicationApprovalError::Repository(_)
        | ApplicationApprovalError::Execution(_)
        | ApplicationApprovalError::Record(_)
        | ApplicationApprovalError::InvalidClock
        | ApplicationApprovalError::Canonicalization => FlowHttpError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "FLOW.APPLICATION_EVENT_UNAVAILABLE",
            "application event could not be processed",
        ),
    }
}

fn application_auth_error(error: ApplicationEventAuthError) -> FlowHttpError {
    let status = match error {
        ApplicationEventAuthError::ReplayedEvent => StatusCode::CONFLICT,
        ApplicationEventAuthError::Configuration
        | ApplicationEventAuthError::ReplayStoreUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::UNAUTHORIZED,
    };
    FlowHttpError::new(
        status,
        error.code(),
        "application event authentication failed",
    )
}

fn native_unavailable() -> FlowHttpError {
    FlowHttpError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "FLOW.NATIVE_BACKEND_UNAVAILABLE",
        "application event native backend is unavailable",
    )
}
