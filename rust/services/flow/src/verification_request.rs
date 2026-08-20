use chrono::{DateTime, Utc};
use marty_verification::flow::FlowInstanceStatus;
use serde_json::{json, Value};
use thiserror::Error;

use crate::{
    build_flow_presentation_request, build_profiled_request_object, FlowInstanceRecord,
    FlowPresentationRequestError, FlowProviderError, FlowProviderRegistry, FlowRecordError,
    FlowRequestObjectError, RequestObjectCompatibility, RequestObjectOptions,
    RequestObjectTransport, SignedRequestObject,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum VerificationRequestMethod {
    #[default]
    Get,
    Post,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum VerificationRequestTransport {
    #[default]
    RequestUri,
    DigitalCredentialsApi,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationRequestRetrievalOptions {
    pub request_object: RequestObjectOptions,
    pub method: VerificationRequestMethod,
    pub transport: VerificationRequestTransport,
    pub compatibility: RequestObjectCompatibility,
    pub wallet_nonce: Option<String>,
}

impl Default for VerificationRequestRetrievalOptions {
    fn default() -> Self {
        Self {
            request_object: RequestObjectOptions::default(),
            method: VerificationRequestMethod::Get,
            transport: VerificationRequestTransport::RequestUri,
            compatibility: RequestObjectCompatibility::Standard,
            wallet_nonce: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum PreparedVerificationRequest {
    Ready(SignedRequestObject),
    Expired(FlowInstanceRecord),
}

#[derive(Debug, Error)]
pub enum FlowVerificationRequestError {
    #[error(transparent)]
    Provider(#[from] FlowProviderError),
    #[error(transparent)]
    Presentation(#[from] FlowPresentationRequestError),
    #[error(transparent)]
    RequestObject(#[from] FlowRequestObjectError),
    #[error(transparent)]
    Record(#[from] FlowRecordError),
    #[error("FLOW.VERIFICATION_REQUEST_INVALID_STATE")]
    InvalidState,
    #[error("FLOW.VERIFICATION_REQUEST_UNSIGNED_TRANSPORT")]
    UnsignedTransport,
    #[error("FLOW.VERIFICATION_REQUEST_METHOD_NOT_ALLOWED")]
    MethodNotAllowed,
    #[error("FLOW.VERIFICATION_REQUEST_WALLET_NONCE_REQUIRED")]
    WalletNonceRequired,
    #[error("FLOW.VERIFICATION_REQUEST_INVALID_CONTEXT")]
    InvalidContext,
}

pub async fn prepare_verification_request(
    providers: &FlowProviderRegistry,
    mut instance: FlowInstanceRecord,
    public_base_url: &str,
    options: &VerificationRequestRetrievalOptions,
    now: DateTime<Utc>,
) -> Result<PreparedVerificationRequest, FlowVerificationRequestError> {
    if !matches!(
        instance.status,
        FlowInstanceStatus::AwaitingWallet | FlowInstanceStatus::InProgress
    ) {
        return Err(FlowVerificationRequestError::InvalidState);
    }
    if instance
        .expires_at
        .is_some_and(|expires_at| now >= expires_at)
    {
        expire_request(&mut instance, now)?;
        return Ok(PreparedVerificationRequest::Expired(instance));
    }
    let context = instance
        .context
        .as_object()
        .ok_or(FlowVerificationRequestError::InvalidContext)?;
    if context.get("request_transport").and_then(Value::as_str) == Some("url_query") {
        return Err(FlowVerificationRequestError::UnsignedTransport);
    }
    let requires_post = context.get("request_uri_method").and_then(Value::as_str) == Some("post");
    if requires_post && options.method != VerificationRequestMethod::Post {
        return Err(FlowVerificationRequestError::MethodNotAllowed);
    }
    if requires_post
        && options
            .wallet_nonce
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
    {
        return Err(FlowVerificationRequestError::WalletNonceRequired);
    }
    let is_siop = context.get("flow_type").and_then(Value::as_str) == Some("siop_v2");
    let artifacts = if is_siop {
        None
    } else {
        let policy_id = context
            .get("presentation_policy_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or(FlowVerificationRequestError::InvalidContext)?;
        Some(
            build_flow_presentation_request(providers, policy_id, &instance.organization_id)
                .await?,
        )
    };
    let mut request_options = options.request_object.clone();
    request_options.wallet_nonce = options.wallet_nonce.clone();
    request_options.compatibility = options.compatibility;
    request_options.transport = match options.transport {
        VerificationRequestTransport::RequestUri => RequestObjectTransport::RequestUri,
        VerificationRequestTransport::DigitalCredentialsApi => {
            RequestObjectTransport::DigitalCredentialsApi
        }
    };
    let built = build_profiled_request_object(
        providers,
        instance,
        artifacts.as_ref(),
        public_base_url,
        &request_options,
        now,
    )
    .await?;
    Ok(PreparedVerificationRequest::Ready(built))
}

fn expire_request(
    instance: &mut FlowInstanceRecord,
    now: DateTime<Utc>,
) -> Result<(), FlowVerificationRequestError> {
    let prior = serde_json::to_value(instance.status)
        .map_err(|_| FlowVerificationRequestError::InvalidContext)?;
    instance.status = FlowInstanceStatus::Expired;
    instance.completed_at = Some(now);
    instance.error = Some("request_expired".into());
    instance.updated_at = now;
    instance.state_history.push(json!({
        "prior_state": prior,
        "new_state": "expired",
        "timestamp": now.to_rfc3339(),
        "actor": "wallet_request",
        "event": "request_expired"
    }));
    instance.kernel()?;
    Ok(())
}
