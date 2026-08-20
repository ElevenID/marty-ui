use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use marty_verification::flow::FlowInstanceStatus;
use mmf_push::WebhookDestinationRegistry;
use rand::random;
use serde_json::{json, Map, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    build_flow_presentation_request, build_standard_request_object, build_unsigned_url_query,
    FlowApiError, FlowInstanceRecord, FlowPresentationRequestError, FlowProviderError,
    FlowProviderRegistry, FlowRequestObjectError, RequestTransport, RequestUriMethod,
    StartVerificationFlowRequest, VerificationRequestResponse, VerificationResponseType,
    REQUEST_ALGORITHM, REQUEST_FORMAT, REQUEST_PURPOSE,
};

#[derive(Clone, Debug, PartialEq)]
pub struct PreparedVerificationStart {
    pub instance: FlowInstanceRecord,
    pub response: VerificationRequestResponse,
}

#[derive(Debug, Error)]
pub enum FlowVerificationStartError {
    #[error(transparent)]
    Api(#[from] FlowApiError),
    #[error(transparent)]
    Provider(#[from] FlowProviderError),
    #[error(transparent)]
    Presentation(#[from] FlowPresentationRequestError),
    #[error(transparent)]
    RequestObject(#[from] FlowRequestObjectError),
    #[error("FLOW.VERIFICATION_CALLBACK_REJECTED")]
    CallbackRejected,
    #[error("FLOW.VERIFICATION_INVALID_POLICY")]
    InvalidPolicy,
    #[error("FLOW.VERIFICATION_INVALID_CLOCK")]
    InvalidClock,
    #[error("FLOW.VERIFICATION_SERIALIZATION")]
    Serialization,
}

#[allow(clippy::too_many_arguments)]
pub async fn prepare_verification_start(
    providers: &FlowProviderRegistry,
    callback_destinations: &WebhookDestinationRegistry,
    request: StartVerificationFlowRequest,
    public_base_url: &str,
    allow_http_loopback: bool,
    request_object_maximum_length: usize,
    url_query_maximum_length: usize,
    verifier_client_id: Option<&str>,
    now: DateTime<Utc>,
) -> Result<PreparedVerificationStart, FlowVerificationStartError> {
    request.validate_for_environment(allow_http_loopback)?;
    if let Some(callback_url) = request.callback_url.as_deref() {
        callback_destinations
            .require(&request.organization_id, callback_url)
            .map_err(|_| FlowVerificationStartError::CallbackRejected)?;
    }
    let identity_provider =
        providers
            .signing_identity
            .as_ref()
            .ok_or(FlowProviderError::Unavailable {
                provider: "signing_identity",
            })?;
    let identity = identity_provider
        .resolve(
            &request.organization_id,
            &request.issuer_did,
            REQUEST_PURPOSE,
            REQUEST_FORMAT,
            Some(REQUEST_ALGORITHM),
        )
        .await?;
    identity.validate_binding(
        &request.organization_id,
        &request.issuer_did,
        REQUEST_PURPOSE,
        REQUEST_FORMAT,
        Some(REQUEST_ALGORITHM),
    )?;

    let is_siop = request.response_type == VerificationResponseType::IdToken;
    if !is_siop {
        let policy_id = request
            .presentation_policy_id
            .as_deref()
            .ok_or(FlowVerificationStartError::InvalidPolicy)?;
        let provider =
            providers
                .presentation_policy
                .as_ref()
                .ok_or(FlowProviderError::Unavailable {
                    provider: "presentation_policy",
                })?;
        let policy = provider.get_policy(policy_id).await?;
        if policy.id != policy_id
            || policy.organization_id != request.organization_id
            || !policy.status.eq_ignore_ascii_case("active")
            || policy.credential_requirements.is_empty()
        {
            return Err(FlowVerificationStartError::InvalidPolicy);
        }
    }

    let nonce = URL_SAFE_NO_PAD.encode(random::<[u8; 32]>());
    let instance_id = Uuid::new_v4().to_string();
    let flow_definition_id = Uuid::new_v4().to_string();
    let expires_at = now
        .checked_add_signed(Duration::minutes(i64::from(request.expiry_minutes)))
        .ok_or(FlowVerificationStartError::InvalidClock)?;
    let base = public_base_url.trim_end_matches('/');
    let request_uri = format!("{base}/v1/flows/instances/{instance_id}/request");
    let mut context = Map::new();
    context.insert(
        "flow_definition_reference".into(),
        json!(if is_siop {
            "__siop_v2__"
        } else {
            "__verification__"
        }),
    );
    context.insert("nonce".into(), json!(nonce));
    context.insert(
        "flow_type".into(),
        json!(if is_siop { "siop_v2" } else { "verification" }),
    );
    context.insert(
        "protocol_flow_type".into(),
        json!(if is_siop {
            "siopv2"
        } else {
            "oid4vp_presentation"
        }),
    );
    context.insert("current_step_name".into(), json!("create_request"));
    context.insert("current_step_index".into(), json!(0));
    context.insert("step_results".into(), json!({}));
    context.insert("callback_url".into(), json!(request.callback_url));
    context.insert("oid4vp_issuer_did".into(), json!(identity.issuer_did));
    context.insert(
        "oid4vp_signing_identity".into(),
        serde_json::to_value(&identity).map_err(|_| FlowVerificationStartError::Serialization)?,
    );
    context.insert("request_uri".into(), json!(request_uri));
    if is_siop {
        context.insert("response_type".into(), json!("id_token"));
    } else {
        context.insert(
            "presentation_policy_id".into(),
            json!(request.presentation_policy_id),
        );
        context.insert("trust_profile_id".into(), json!(request.trust_profile_id));
        context.insert(
            "deployment_profile_id".into(),
            json!(request.deployment_profile_id),
        );
        context.insert(
            "oid4vp_profile".into(),
            serde_json::to_value(request.oid4vp_profile)
                .map_err(|_| FlowVerificationStartError::Serialization)?,
        );
        context.insert(
            "request_transport".into(),
            serde_json::to_value(request.request_transport)
                .map_err(|_| FlowVerificationStartError::Serialization)?,
        );
        context.insert(
            "request_uri_method".into(),
            serde_json::to_value(request.request_uri_method)
                .map_err(|_| FlowVerificationStartError::Serialization)?,
        );
    }
    let mut instance = FlowInstanceRecord {
        id: instance_id.clone(),
        flow_definition_id: flow_definition_id.clone(),
        organization_id: request.organization_id.clone(),
        status: FlowInstanceStatus::AwaitingWallet,
        current_step_id: None,
        context: Value::Object(context),
        step_history: Vec::new(),
        state_history: vec![json!({
            "prior_state": null,
            "new_state": "awaiting_wallet",
            "timestamp": now.to_rfc3339(),
            "actor": "verification_api",
            "event": "verification_started"
        })],
        subject_id: None,
        subject_type: "holder".into(),
        external_reference: request.external_reference,
        application_flow_key_hash: None,
        started_at: Some(now),
        completed_at: None,
        expires_at: Some(expires_at),
        result: None,
        error: None,
        created_at: now,
        updated_at: now,
    };

    let auth_request = if is_siop {
        let client_id = verifier_client_id
            .filter(|value| !value.trim().is_empty())
            .map_or_else(|| format!("{base}/verifier"), str::to_owned);
        instance.context["siop_client_id"] = json!(client_id);
        authorization_uri(
            "openid://authorize",
            &[("request_uri", request_uri.as_str())],
        )
    } else {
        let policy_id = request
            .presentation_policy_id
            .as_deref()
            .ok_or(FlowVerificationStartError::InvalidPolicy)?;
        match request.request_transport {
            RequestTransport::RequestUri => {
                let client_id = format!("decentralized_identifier:{}", identity.issuer_did);
                instance.context["oid4vp_client_id"] = json!(client_id);
                let mut parameters = vec![
                    ("client_id", client_id.as_str()),
                    ("request_uri", request_uri.as_str()),
                ];
                if request.request_uri_method == RequestUriMethod::Post {
                    parameters.push(("request_uri_method", "post"));
                }
                authorization_uri("openid4vp://authorize", &parameters)
            }
            RequestTransport::RequestObject => {
                let artifacts =
                    build_flow_presentation_request(providers, policy_id, &request.organization_id)
                        .await?;
                let built = build_standard_request_object(
                    providers,
                    instance,
                    Some(&artifacts),
                    base,
                    None,
                    None,
                    now,
                )
                .await?;
                let uri = authorization_uri(
                    "openid4vp://authorize",
                    &[
                        ("client_id", built.client_id.as_str()),
                        ("request", built.compact_jwt.as_str()),
                    ],
                );
                if request_object_maximum_length < 1_024
                    || uri.len() > request_object_maximum_length
                {
                    return Err(FlowRequestObjectError::TooLarge.into());
                }
                instance = built.instance;
                uri
            }
            RequestTransport::UrlQuery => {
                let artifacts =
                    build_flow_presentation_request(providers, policy_id, &request.organization_id)
                        .await?;
                let built = build_unsigned_url_query(
                    instance,
                    &artifacts,
                    base,
                    url_query_maximum_length,
                    now,
                )?;
                instance = built.instance;
                built.authorization_request
            }
        }
    };
    instance.context["auth_request"] = json!(auth_request);
    instance.context["qr_code_data"] = json!(auth_request);
    instance.updated_at = now;
    instance
        .kernel()
        .map_err(|_| FlowVerificationStartError::Serialization)?;

    let presentation_policy_id = request.presentation_policy_id.unwrap_or_default();
    let response = VerificationRequestResponse {
        instance_id,
        flow_definition_id,
        request_uri: auth_request.clone(),
        qr_code_data: auth_request,
        presentation_policy_id,
        nonce,
        expires_at: expires_at.to_rfc3339_opts(SecondsFormat::AutoSi, true),
        status: FlowInstanceStatus::AwaitingWallet.to_string(),
    };
    Ok(PreparedVerificationStart { instance, response })
}

fn authorization_uri(scheme: &str, parameters: &[(&str, &str)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in parameters {
        serializer.append_pair(name, value);
    }
    format!("{scheme}?{}", serializer.finish())
}
