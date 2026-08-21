use axum::{
    extract::{Form, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use mmf_push::WebhookDestinationRegistry;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    authorize, constant_time_equal, decrypt_verification_response, parse_request,
    prepare_profiled_verification_start, prepare_siop_submission, prepare_verification_request,
    prepare_verification_submission, required_instance, DigitalCredentialSubmissionRequest,
    FlowHttpError, FlowHttpState, FlowSiopSubmissionError, FlowVerificationRequestError,
    FlowVerificationStartError, FlowVerificationSubmissionError, Oid4vpProfile,
    PreparedSiopSubmission, PreparedVerificationFinalization, PreparedVerificationRequest,
    PreparedVerificationSubmission, RequestObjectCompatibility, RequestObjectOptions,
    RequestTransport, RequestUriMethod, SiopSubmissionOptions, SiopSubmitRequest,
    StartSiopFlowRequest, StartVerificationFlowRequest, VerificationRequestMethod,
    VerificationRequestRetrievalOptions, VerificationRequestTransport, VerificationResponseType,
    VerificationStartOptions, VerificationSubmissionInput, VerificationSubmissionOptions,
};

const DC_API_PROTOCOL: &str = "openid4vp-v1-signed";
const DC_API_RESPONSE_MODE: &str = "dc_api.jwt";
const NONCE_TTL_SECONDS: u64 = 900;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowHttpVerificationOptions {
    pub callback_destinations: WebhookDestinationRegistry,
    pub callback_secret: Option<String>,
    pub request_object: RequestObjectOptions,
    pub verification_start: VerificationStartOptions,
    pub default_issuer_did: String,
    pub default_organization_id: String,
    pub allow_http_loopback: bool,
    pub nonce_ttl_seconds: u64,
    pub callback_retention_seconds: u64,
    pub callback_max_attempts: u32,
}

impl Default for FlowHttpVerificationOptions {
    fn default() -> Self {
        Self {
            callback_destinations: WebhookDestinationRegistry::default(),
            callback_secret: None,
            request_object: RequestObjectOptions::default(),
            verification_start: VerificationStartOptions::default(),
            default_issuer_did: "did:web:localhost:orgs:marty".into(),
            default_organization_id: "00000000-0000-0000-0000-000000000001".into(),
            allow_http_loopback: true,
            nonce_ttl_seconds: NONCE_TTL_SECONDS,
            callback_retention_seconds: crate::CALLBACK_RETENTION_SECONDS,
            callback_max_attempts: crate::CALLBACK_MAX_ATTEMPTS,
        }
    }
}

impl FlowHttpVerificationOptions {
    #[must_use]
    pub fn from_config(config: &crate::FlowServiceConfig) -> Self {
        Self {
            callback_destinations: config.callback_destinations.clone(),
            callback_secret: config.webhook_secret.clone(),
            request_object: config.request_object_options(),
            verification_start: config.verification_start_options(),
            default_issuer_did: config.oid4vp_issuer_did.clone(),
            default_organization_id: config.marty_organization_id.clone(),
            allow_http_loopback: !config.environment.is_deployed(),
            nonce_ttl_seconds: NONCE_TTL_SECONDS,
            callback_retention_seconds: crate::CALLBACK_RETENTION_SECONDS,
            callback_max_attempts: crate::CALLBACK_MAX_ATTEMPTS,
        }
    }
}

pub(crate) fn flow_verification_routes() -> Router<FlowHttpState> {
    Router::new()
        .route("/v1/flows/verify", post(start_verification))
        .route("/v1/flows/siop", post(start_siop))
        .route("/v1/flows/siop/submit", post(submit_siop))
        .route("/oid4vp/did.json", get(oid4vp_did_document))
        .route(
            "/v1/flows/instances/{instance_id}/request",
            get(get_request_object).post(post_request_object),
        )
        .route(
            "/v1/flows/instances/{instance_id}/submit",
            post(submit_direct_post),
        )
        .route(
            "/v1/flows/instances/{instance_id}/submit/dc-api",
            post(submit_dc_api),
        )
}

async fn oid4vp_did_document(
    State(state): State<FlowHttpState>,
) -> Result<Response, FlowHttpError> {
    let options = &state.verification;
    let signing =
        state
            .providers
            .signing_identity
            .as_ref()
            .ok_or(crate::FlowProviderError::Unavailable {
                provider: "signing_identity",
            })?;
    let identity = signing
        .resolve(
            &options.default_organization_id,
            &options.default_issuer_did,
            "oid4vp_request_signing",
            "oauth-authz-req+jwt",
            Some("ES256"),
        )
        .await?;
    let document = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": identity.issuer_did,
        "verificationMethod": [{
            "id": identity.verification_method_id,
            "type": "JsonWebKey2020",
            "controller": identity.issuer_did,
            "publicKeyJwk": identity.public_jwk
        }],
        "authentication": [identity.verification_method_id],
        "assertionMethod": [identity.verification_method_id]
    });
    Ok((
        [
            (header::CONTENT_TYPE, "application/did+json"),
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
        ],
        Json(document),
    )
        .into_response())
}

async fn start_verification(
    State(state): State<FlowHttpState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, FlowHttpError> {
    let request: StartVerificationFlowRequest = serde_json::from_value(payload).map_err(|_| {
        FlowHttpError::new(
            StatusCode::BAD_REQUEST,
            "flow_invalid_request",
            "Verification start request is malformed",
        )
    })?;
    authorize(
        &state,
        &headers,
        &request.organization_id,
        "verification:execute",
    )
    .await?;
    Ok(Json(json!(
        persist_verification_start(&state, request).await?
    )))
}

async fn start_siop(
    State(state): State<FlowHttpState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, FlowHttpError> {
    let request: StartSiopFlowRequest = parse_request(payload)?;
    authorize(
        &state,
        &headers,
        &request.organization_id,
        "verification:execute",
    )
    .await?;
    let response = persist_verification_start(
        &state,
        StartVerificationFlowRequest {
            presentation_policy_id: None,
            organization_id: request.organization_id,
            issuer_did: state.verification.default_issuer_did.clone(),
            response_type: VerificationResponseType::IdToken,
            trust_profile_id: None,
            deployment_profile_id: None,
            external_reference: None,
            callback_url: None,
            oid4vp_profile: Oid4vpProfile::Standard,
            request_transport: RequestTransport::RequestUri,
            request_uri_method: RequestUriMethod::Get,
            expiry_minutes: request.expiry_minutes,
        },
    )
    .await?;
    Ok(Json(siop_start_response(response)))
}

async fn persist_verification_start(
    state: &FlowHttpState,
    request: StartVerificationFlowRequest,
) -> Result<crate::VerificationRequestResponse, FlowHttpError> {
    let prepared = prepare_profiled_verification_start(
        &state.providers,
        &state.verification.callback_destinations,
        request,
        &state.public_base_url,
        state.verification.allow_http_loopback,
        &state.verification.verification_start,
        Utc::now(),
    )
    .await?;
    if !state
        .repository
        .save_started_instance(&prepared.instance, None)
        .await?
    {
        return Err(FlowHttpError::new(
            StatusCode::CONFLICT,
            "verification_start_conflict",
            "Verification transaction already exists",
        ));
    }
    Ok(prepared.response)
}

#[derive(Default, Deserialize)]
struct RequestObjectQuery {
    #[serde(default)]
    transport: Option<String>,
    #[serde(default)]
    compat: Option<String>,
}

#[derive(Default, Deserialize)]
struct RequestObjectForm {
    #[serde(default)]
    wallet_nonce: Option<String>,
}

async fn get_request_object(
    State(state): State<FlowHttpState>,
    Path(instance_id): Path<String>,
    Query(query): Query<RequestObjectQuery>,
) -> Result<Response, FlowHttpError> {
    retrieve_request_object(
        &state,
        &instance_id,
        query,
        VerificationRequestMethod::Get,
        None,
    )
    .await
}

async fn post_request_object(
    State(state): State<FlowHttpState>,
    Path(instance_id): Path<String>,
    Query(query): Query<RequestObjectQuery>,
    Form(form): Form<RequestObjectForm>,
) -> Result<Response, FlowHttpError> {
    retrieve_request_object(
        &state,
        &instance_id,
        query,
        VerificationRequestMethod::Post,
        form.wallet_nonce,
    )
    .await
}

async fn retrieve_request_object(
    state: &FlowHttpState,
    instance_id: &str,
    query: RequestObjectQuery,
    method: VerificationRequestMethod,
    wallet_nonce: Option<String>,
) -> Result<Response, FlowHttpError> {
    let current = required_instance(state, instance_id).await?;
    let expected_status = current.status;
    let expected_updated_at = current.updated_at;
    let now = Utc::now().max(expected_updated_at + Duration::microseconds(1));
    let options = VerificationRequestRetrievalOptions {
        request_object: state.verification.request_object.clone(),
        method,
        transport: parse_request_transport(query.transport.as_deref())?,
        compatibility: parse_compatibility(query.compat.as_deref())?,
        wallet_nonce,
    };
    match prepare_verification_request(
        &state.providers,
        current,
        &state.public_base_url,
        &options,
        now,
    )
    .await?
    {
        PreparedVerificationRequest::Ready(ready) => {
            commit_request_snapshot(state, &ready.instance, expected_status, expected_updated_at)
                .await?;
            request_object_response(ready.compact_jwt)
        }
        PreparedVerificationRequest::Expired(expired) => {
            commit_request_snapshot(state, &expired, expected_status, expected_updated_at).await?;
            Err(FlowHttpError::new(
                StatusCode::GONE,
                "verification_request_expired",
                "Verification request has expired",
            ))
        }
    }
}

async fn commit_request_snapshot(
    state: &FlowHttpState,
    instance: &crate::FlowInstanceRecord,
    expected_status: marty_verification::flow::FlowInstanceStatus,
    expected_updated_at: chrono::DateTime<Utc>,
) -> Result<(), FlowHttpError> {
    if state
        .repository
        .compare_and_swap_instance(instance, expected_status, expected_updated_at)
        .await?
    {
        Ok(())
    } else {
        Err(FlowHttpError::new(
            StatusCode::CONFLICT,
            "verification_request_conflict",
            "Verification transaction changed during request retrieval",
        ))
    }
}

fn request_object_response(compact_jwt: String) -> Result<Response, FlowHttpError> {
    let mut response = compact_jwt.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/oauth-authz-req+jwt"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    Ok(response)
}

#[derive(Default, Deserialize)]
struct DirectPostForm {
    #[serde(default)]
    vp_token: Option<String>,
    #[serde(default)]
    presentation_submission: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    response: Option<String>,
}

async fn submit_direct_post(
    State(state): State<FlowHttpState>,
    Path(instance_id): Path<String>,
    Form(form): Form<DirectPostForm>,
) -> Result<Json<Value>, FlowHttpError> {
    let instance = required_instance(&state, &instance_id).await?;
    let (input, instance) = direct_post_input(&state, instance, form).await?;
    let result = evaluate_submission(&state, instance, input, false).await?;
    if result.decision.as_deref() != Some("allow") || result.result.as_deref() != Some("passed") {
        return Err(FlowHttpError::new(
            StatusCode::BAD_REQUEST,
            "invalid_presentation",
            json!({"error": "invalid_presentation", "error_description": "presentation verification failed"}),
        ));
    }
    let stored = required_instance(&state, &instance_id).await?;
    if stored.context.get("oid4vp_profile").and_then(Value::as_str) == Some("haip") {
        if !state.public_base_url.starts_with("https://") {
            return Err(FlowHttpError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "haip_redirect_unavailable",
                "HAIP redirect URI requires a public HTTPS origin",
            ));
        }
        return Ok(Json(json!({
            "redirect_uri": format!("{}/v1/flows/instances/{instance_id}", state.public_base_url.trim_end_matches('/'))
        })));
    }
    Ok(Json(json!({})))
}

async fn direct_post_input(
    state: &FlowHttpState,
    instance: crate::FlowInstanceRecord,
    form: DirectPostForm,
) -> Result<(VerificationSubmissionInput, crate::FlowInstanceRecord), FlowHttpError> {
    let vp_token = form.vp_token.filter(|value| !value.is_empty());
    let response = form.response.filter(|value| !value.is_empty());
    if vp_token.is_some() == response.is_some() {
        return Err(FlowHttpError::new(
            StatusCode::BAD_REQUEST,
            "verification_submission_shape",
            "Exactly one of vp_token or response is required",
        ));
    }
    if let Some(response) = response {
        let decrypted =
            decrypt_verification_response(&state.providers, &instance, &response).await?;
        let vp_token = decrypted.get("vp_token").cloned().ok_or_else(|| {
            FlowHttpError::new(
                StatusCode::BAD_REQUEST,
                "invalid_encrypted_response",
                "Encrypted response has no vp_token",
            )
        })?;
        return Ok((
            VerificationSubmissionInput {
                vp_token: token_string(vp_token)?,
                presentation_submission: decrypted
                    .get("presentation_submission")
                    .cloned()
                    .or_else(|| form.presentation_submission.map(Value::String)),
                state: decrypted
                    .get("state")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .or(form.state),
                audience_override: None,
            },
            instance,
        ));
    }
    Ok((
        VerificationSubmissionInput {
            vp_token: vp_token.unwrap_or_default(),
            presentation_submission: form.presentation_submission.map(Value::String),
            state: form.state,
            audience_override: None,
        },
        instance,
    ))
}

async fn submit_dc_api(
    State(state): State<FlowHttpState>,
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, FlowHttpError> {
    let request: DigitalCredentialSubmissionRequest = parse_request(payload)?;
    if request.protocol.as_deref().unwrap_or(DC_API_PROTOCOL) != DC_API_PROTOCOL {
        return Err(FlowHttpError::new(
            StatusCode::BAD_REQUEST,
            "unsupported_dc_api_protocol",
            "Unsupported Digital Credentials protocol",
        ));
    }
    let mut instance = required_instance(&state, &instance_id).await?;
    let mut data = Value::Object(request.data.into_iter().collect());
    let mut response_mode = None;
    if let Some(response) = data
        .get("response")
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        data = decrypt_verification_response(&state.providers, &instance, &response).await?;
        response_mode = Some(DC_API_RESPONSE_MODE);
    }
    if let Some(error) = data.get("error") {
        return Err(FlowHttpError::new(
            StatusCode::BAD_REQUEST,
            "wallet_verification_error",
            json!({"error": error, "error_description": "Wallet returned an OpenID4VP error"}),
        ));
    }
    let vp_token = data.get("vp_token").cloned().ok_or_else(|| {
        FlowHttpError::new(
            StatusCode::BAD_REQUEST,
            "dc_api_vp_token_required",
            "DigitalCredential.data.vp_token is required",
        )
    })?;
    let expected_origins = instance
        .context
        .get("dc_api_expected_origins")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(|value| value.trim_end_matches('/').to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let origin = request
        .origin
        .or_else(|| {
            headers
                .get(header::ORIGIN)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        })
        .map(|value| value.trim_end_matches('/').to_owned())
        .or_else(|| (expected_origins.len() == 1).then(|| expected_origins[0].clone()))
        .ok_or_else(|| {
            FlowHttpError::new(
                StatusCode::BAD_REQUEST,
                "dc_api_origin_required",
                "Verifier origin is required for dc_api submissions",
            )
        })?;
    if !expected_origins.iter().any(|expected| expected == &origin) {
        return Err(FlowHttpError::new(
            StatusCode::BAD_REQUEST,
            "dc_api_origin_mismatch",
            json!({"error": "invalid_request", "error_description": "Origin does not match expected_origins"}),
        ));
    }
    instance.context["dc_api_last_origin"] = json!(origin);
    if let Some(response_mode) = response_mode {
        instance.context["dc_api_last_response_mode"] = json!(response_mode);
    }
    let input = VerificationSubmissionInput {
        vp_token: token_string(vp_token)?,
        presentation_submission: data.get("presentation_submission").cloned(),
        state: None,
        audience_override: Some(format!("origin:{origin}")),
    };
    Ok(Json(json!(
        evaluate_submission(&state, instance, input, true).await?
    )))
}

async fn evaluate_submission(
    state: &FlowHttpState,
    instance: crate::FlowInstanceRecord,
    input: VerificationSubmissionInput,
    permit_terminal_replay: bool,
) -> Result<crate::VerificationResultResponse, FlowHttpError> {
    let expected_status = instance.status;
    let expected_updated_at = instance.updated_at;
    let verifier_sender_id = instance
        .context
        .get("oid4vp_client_id")
        .and_then(Value::as_str)
        .unwrap_or(&state.verification.default_issuer_did)
        .to_owned();
    let now = Utc::now().max(instance.updated_at + Duration::microseconds(1));
    let prepared = prepare_verification_submission(
        &state.providers,
        instance,
        input,
        &VerificationSubmissionOptions {
            callback_destinations: state.verification.callback_destinations.clone(),
            callback_secret: state.verification.callback_secret.clone(),
            verifier_sender_id,
            nonce_ttl_seconds: state.verification.nonce_ttl_seconds,
            callback_retention_seconds: state.verification.callback_retention_seconds,
            callback_max_attempts: state.verification.callback_max_attempts,
        },
        now,
    )
    .await?;
    match prepared {
        PreparedVerificationSubmission::Final(finalization) => {
            commit_verification(state, &finalization, permit_terminal_replay).await
        }
        PreparedVerificationSubmission::Retryable(response) => Ok(response),
        PreparedVerificationSubmission::Expired(expired) => {
            persist_expired(state, &expired, expected_status, expected_updated_at).await?;
            Err(FlowHttpError::new(
                StatusCode::GONE,
                "verification_submission_expired",
                "Verification transaction has expired",
            ))
        }
        PreparedVerificationSubmission::SameTerminal(response) if permit_terminal_replay => {
            Ok(response)
        }
        PreparedVerificationSubmission::SameTerminal(_) => Err(already_processed()),
        PreparedVerificationSubmission::ReplayConflict => Err(replay_conflict()),
    }
}

async fn commit_verification(
    state: &FlowHttpState,
    finalization: &PreparedVerificationFinalization,
    permit_terminal_replay: bool,
) -> Result<crate::VerificationResultResponse, FlowHttpError> {
    let response = finalization.instance.verification_projection()?;
    if !state
        .repository
        .finalize_verification(
            &finalization.instance,
            &finalization.nonce_digest,
            finalization.replay_expires_at_ms,
            finalization.expected_status,
            finalization.callback.as_ref(),
        )
        .await?
    {
        let current = required_instance(state, &finalization.instance.id).await?;
        let same_digest = current
            .result
            .as_ref()
            .and_then(|result| result.get("submission_digest"))
            .and_then(Value::as_str)
            .is_some_and(|digest| constant_time_equal(digest, &finalization.submission_digest));
        if same_digest && permit_terminal_replay {
            return Ok(current.verification_projection()?);
        }
        if same_digest {
            return Err(already_processed());
        }
        return Err(replay_conflict());
    }
    Ok(response)
}

async fn submit_siop(
    State(state): State<FlowHttpState>,
    Json(payload): Json<Value>,
) -> Result<Json<Value>, FlowHttpError> {
    let request: SiopSubmitRequest = parse_request(payload)?;
    let instance = required_instance(&state, &request.instance_id).await?;
    let expected_status = instance.status;
    let expected_updated_at = instance.updated_at;
    let now = Utc::now().max(expected_updated_at + Duration::microseconds(1));
    match prepare_siop_submission(
        instance,
        &request.id_token,
        &SiopSubmissionOptions {
            nonce_ttl_seconds: state.verification.nonce_ttl_seconds,
            ..SiopSubmissionOptions::default()
        },
        now,
    )? {
        PreparedSiopSubmission::Final(prepared) => {
            if !state
                .repository
                .finalize_verification(
                    &prepared.finalization.instance,
                    &prepared.finalization.nonce_digest,
                    prepared.finalization.replay_expires_at_ms,
                    prepared.finalization.expected_status,
                    None,
                )
                .await?
            {
                let current = required_instance(&state, &request.instance_id).await?;
                if let PreparedSiopSubmission::SameTerminal(response) = prepare_siop_submission(
                    current,
                    &request.id_token,
                    &SiopSubmissionOptions {
                        nonce_ttl_seconds: state.verification.nonce_ttl_seconds,
                        ..SiopSubmissionOptions::default()
                    },
                    Utc::now(),
                )? {
                    return Ok(Json(json!(response)));
                }
                return Err(replay_conflict());
            }
            Ok(Json(json!(prepared.response)))
        }
        PreparedSiopSubmission::Expired(expired) => {
            persist_expired(&state, &expired, expected_status, expected_updated_at).await?;
            Err(FlowHttpError::new(
                StatusCode::GONE,
                "siop_submission_expired",
                "SIOPv2 transaction has expired",
            ))
        }
        PreparedSiopSubmission::SameTerminal(response) => Ok(Json(json!(response))),
        PreparedSiopSubmission::ReplayConflict => Err(replay_conflict()),
    }
}

async fn persist_expired(
    state: &FlowHttpState,
    expired: &crate::FlowInstanceRecord,
    expected_status: marty_verification::flow::FlowInstanceStatus,
    expected_updated_at: chrono::DateTime<Utc>,
) -> Result<(), FlowHttpError> {
    if state
        .repository
        .compare_and_swap_instance(expired, expected_status, expected_updated_at)
        .await?
    {
        Ok(())
    } else {
        Err(replay_conflict())
    }
}

fn token_string(value: Value) -> Result<String, FlowHttpError> {
    match value {
        Value::String(value) => Ok(value),
        value => serde_json::to_string(&value).map_err(|_| {
            FlowHttpError::new(
                StatusCode::BAD_REQUEST,
                "invalid_vp_token",
                "vp_token could not be serialized",
            )
        }),
    }
}

fn siop_start_response(response: crate::VerificationRequestResponse) -> Value {
    json!({
        "instance_id": response.instance_id,
        "request_uri": response.request_uri,
        "siop_uri": response.qr_code_data,
        "nonce": response.nonce,
        "expires_at": response.expires_at
    })
}

fn parse_request_transport(
    value: Option<&str>,
) -> Result<VerificationRequestTransport, FlowHttpError> {
    match value.unwrap_or("request_uri") {
        "request_uri" => Ok(VerificationRequestTransport::RequestUri),
        "dc_api" => Ok(VerificationRequestTransport::DigitalCredentialsApi),
        _ => Err(FlowHttpError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request_transport",
            "transport must be request_uri or dc_api",
        )),
    }
}

fn parse_compatibility(value: Option<&str>) -> Result<RequestObjectCompatibility, FlowHttpError> {
    match value.unwrap_or("standard") {
        "standard" | "" => Ok(RequestObjectCompatibility::Standard),
        "lissi" => Ok(RequestObjectCompatibility::Lissi),
        _ => Err(FlowHttpError::new(
            StatusCode::BAD_REQUEST,
            "invalid_compatibility_profile",
            "compat must be standard or lissi",
        )),
    }
}

fn already_processed() -> FlowHttpError {
    FlowHttpError::new(
        StatusCode::BAD_REQUEST,
        "verification_already_processed",
        "Verification response has already been processed",
    )
}

fn replay_conflict() -> FlowHttpError {
    FlowHttpError::new(
        StatusCode::CONFLICT,
        "verification_replay_conflict",
        "Verification response conflicts with the terminal transaction",
    )
}

impl From<FlowVerificationStartError> for FlowHttpError {
    fn from(error: FlowVerificationStartError) -> Self {
        match error {
            FlowVerificationStartError::Api(error) => error.into(),
            FlowVerificationStartError::Provider(error) => error.into(),
            FlowVerificationStartError::CallbackRejected => Self::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "verification_callback_rejected",
                error.to_string(),
            ),
            FlowVerificationStartError::InvalidPolicy => Self::new(
                StatusCode::NOT_FOUND,
                "verification_policy_invalid",
                error.to_string(),
            ),
            FlowVerificationStartError::HaipDisabled => Self::new(
                StatusCode::CONFLICT,
                "verification_haip_disabled",
                error.to_string(),
            ),
            _ => Self::new(
                StatusCode::BAD_GATEWAY,
                "verification_start_failed",
                error.to_string(),
            ),
        }
    }
}

impl From<FlowVerificationRequestError> for FlowHttpError {
    fn from(error: FlowVerificationRequestError) -> Self {
        match error {
            FlowVerificationRequestError::Provider(error) => error.into(),
            FlowVerificationRequestError::MethodNotAllowed => Self::new(
                StatusCode::METHOD_NOT_ALLOWED,
                "verification_request_method_not_allowed",
                error.to_string(),
            ),
            FlowVerificationRequestError::Record(_)
            | FlowVerificationRequestError::InvalidContext => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid_stored_flow_state",
                "Stored verification transaction is invalid",
            ),
            _ => Self::new(
                StatusCode::BAD_REQUEST,
                "verification_request_invalid",
                error.to_string(),
            ),
        }
    }
}

impl From<FlowVerificationSubmissionError> for FlowHttpError {
    fn from(error: FlowVerificationSubmissionError) -> Self {
        match error {
            FlowVerificationSubmissionError::Provider(error) => error.into(),
            FlowVerificationSubmissionError::Record(_)
            | FlowVerificationSubmissionError::InvalidContext(_) => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid_stored_flow_state",
                "Stored verification transaction is invalid",
            ),
            FlowVerificationSubmissionError::CallbackUnavailable => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "verification_callback_unavailable",
                error.to_string(),
            ),
            _ => Self::new(
                StatusCode::BAD_REQUEST,
                "verification_submission_invalid",
                error.to_string(),
            ),
        }
    }
}

impl From<FlowSiopSubmissionError> for FlowHttpError {
    fn from(error: FlowSiopSubmissionError) -> Self {
        match error {
            FlowSiopSubmissionError::Record(_) | FlowSiopSubmissionError::InvalidContext(_) => {
                Self::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "invalid_stored_flow_state",
                    "Stored SIOPv2 transaction is invalid",
                )
            }
            FlowSiopSubmissionError::InvalidClock | FlowSiopSubmissionError::Serialization => {
                Self::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "siop_verification_failed",
                    error.to_string(),
                )
            }
            _ => Self::new(
                StatusCode::BAD_REQUEST,
                "invalid_id_token",
                error.to_string(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_object_response_and_transport_profiles_are_exact() {
        let response = request_object_response("header.claims.signature".into()).unwrap();
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/oauth-authz-req+jwt"
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
        assert_eq!(
            parse_request_transport(None).unwrap(),
            VerificationRequestTransport::RequestUri
        );
        assert_eq!(
            parse_request_transport(Some("dc_api")).unwrap(),
            VerificationRequestTransport::DigitalCredentialsApi
        );
        assert!(parse_request_transport(Some("unsigned")).is_err());
        assert_eq!(
            parse_compatibility(Some("lissi")).unwrap(),
            RequestObjectCompatibility::Lissi
        );
        assert!(parse_compatibility(Some("unknown")).is_err());
    }

    #[test]
    fn vp_token_transport_preserves_strings_and_canonicalizes_objects() {
        assert_eq!(token_string(json!("token")).unwrap(), "token");
        assert_eq!(
            token_string(json!({"query": ["token"]})).unwrap(),
            r#"{"query":["token"]}"#
        );
    }

    #[test]
    fn standalone_siop_start_retains_its_released_response_shape() {
        let response = siop_start_response(crate::VerificationRequestResponse {
            instance_id: "instance-1".into(),
            flow_definition_id: "definition-1".into(),
            request_uri: "openid://authorize?request_uri=request".into(),
            qr_code_data: "openid://authorize?request_uri=request".into(),
            presentation_policy_id: String::new(),
            nonce: "nonce".into(),
            expires_at: "2026-08-20T12:15:00Z".into(),
            status: "awaiting_wallet".into(),
        });
        assert_eq!(response.as_object().unwrap().len(), 5);
        assert_eq!(response["request_uri"], response["siop_uri"]);
        assert!(response.get("flow_definition_id").is_none());
        assert!(response.get("status").is_none());
    }
}
