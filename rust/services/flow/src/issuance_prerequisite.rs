//! Issuance's authenticated prerequisite owner boundary.
//!
//! The issuance selection is admitted before the wallet request is published.
//! Its private context is part of the existing V2 full-request digest; no V2
//! digest or historical receipt is reinterpreted as a new issuance authority.

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use chrono::{DateTime, Utc};
use marty_oid4vp_contract::issuance_prerequisite::{
    IssuanceIntentBindingV1, IssuancePrerequisiteEvidenceRequestV1,
    IssuancePrerequisiteStartRequestV1, IssuancePrerequisiteStartResponseV1,
    ISSUANCE_PREREQUISITE_CONTEXT_V1, ISSUANCE_PREREQUISITE_START_RESPONSE_V1,
    MAX_ISSUANCE_INTENT_BYTES,
};
use marty_verification::flow::FlowInstanceStatus;
use serde_json::Value;

use crate::{
    defined_verification::prepare_admitted_defined_verification_start,
    presentation_request::load_frozen_flow_presentation_request, FlowHttpError, FlowHttpState,
    FlowInstanceRecord, RepositoryError, VerificationDefinitionBinding, VerificationStartContext,
};

pub(crate) fn issuance_prerequisite_owner_routes() -> Router<FlowHttpState> {
    Router::new()
        .route(
            "/internal/v1/issuance-prerequisites/{transaction_id}/start",
            post(start),
        )
        .route(
            "/internal/v1/issuance-prerequisites/{transaction_id}/evidence",
            post(evidence),
        )
        .layer(DefaultBodyLimit::max(MAX_ISSUANCE_INTENT_BYTES + 1_024))
}

fn authenticate(state: &FlowHttpState, headers: &HeaderMap) -> Result<(), FlowHttpError> {
    let rejected = || {
        FlowHttpError::new(
            StatusCode::UNAUTHORIZED,
            "issuance_service_authentication_required",
            "Issuance service authentication required",
        )
    };
    if headers.get_all("x-service-token").iter().count() != 1 {
        return Err(rejected());
    }
    state
        .issuance_prerequisite_authenticator
        .as_ref()
        .filter(|authenticator| authenticator.is_configured())
        .ok_or_else(rejected)?
        .authenticate(
            headers
                .get("x-service-token")
                .and_then(|value| value.to_str().ok()),
        )
        .map_err(|_| rejected())
}

async fn start(
    State(state): State<FlowHttpState>,
    headers: HeaderMap,
    Path(transaction_id): Path<String>,
    body: Bytes,
) -> Result<Response, FlowHttpError> {
    authenticate(&state, &headers)?;
    let request = IssuancePrerequisiteStartRequestV1::from_json(
        std::str::from_utf8(&body).map_err(|_| invalid_request())?,
    )
    .map_err(|_| invalid_request())?;
    let intent = request.intent;
    if intent.transaction_id != transaction_id {
        return Err(invalid_request());
    }
    let instance_id =
        uuid::Uuid::parse_str(&intent.flow_instance_id).map_err(|_| invalid_request())?;
    let now = state.repository.issuance_prerequisite_clock().await?;
    intent
        .validate_at(now.timestamp_micros())
        .map_err(|_| expired())?;
    // The authenticated Issuance caller supplies the same principal whose
    // normal Flow/PDP start and referenced resources must still be admitted.
    state
        .providers
        .authorize(
            &intent.initiating_principal_id,
            &intent.organization_id,
            "flow-instance:start",
            false,
        )
        .await?;
    if let Some(existing) = state
        .repository
        .issuance_prerequisite_instance(&intent)
        .await?
    {
        // Authorization and repository reads can wait beyond the original
        // deadline. Idempotent retries need the same fresh-clock guarantee.
        let now = state.repository.issuance_prerequisite_clock().await?;
        return no_store(start_response(&existing, &intent, now)?);
    }
    let definition = state
        .repository
        .definition(&intent.prerequisite.flow_definition_id)
        .await?
        .ok_or_else(unavailable)?;
    let binding = VerificationDefinitionBinding {
        organization_id: intent.organization_id.clone(),
        definition_id: intent.prerequisite.flow_definition_id.clone(),
        version: intent.prerequisite.flow_definition_version,
    };
    binding.validate(&definition).map_err(|_| unavailable())?;
    if definition.presentation_policy_id.as_deref() != Some(intent.prerequisite.policy.id.as_str())
    {
        return Err(unavailable());
    }
    crate::validate_definition_references(
        &state.providers,
        &intent.initiating_principal_id,
        &intent.organization_id,
        &crate::definition_references(&definition),
        true,
    )
    .await?;
    let mut prepared = prepare_admitted_defined_verification_start(
        &state.providers,
        &state.verification.callback_destinations,
        &definition,
        &binding,
        &intent.prerequisite.verifier_issuer_did,
        &state.verification.verification_start,
        VerificationStartContext {
            public_base_url: &state.public_base_url,
            allow_http_loopback: false,
            principal_id: &intent.initiating_principal_id,
            now,
        },
        instance_id,
        Some(&intent.prerequisite.policy.content_digest),
    )
    .await
    .map_err(|_| unavailable())?;
    let frozen =
        load_frozen_flow_presentation_request(&prepared.instance).map_err(|_| unavailable())?;
    if frozen.policy_revision != intent.prerequisite.policy
        || frozen.credential_authority.is_none()
        || !managed_single_credential_query(&frozen.dcql_query)
    {
        return Err(unavailable());
    }
    // Request-URI preparation has not signed or published a request yet. The
    // admitted immutable intent and the shorter deadline are present before
    // either signing, wallet retrieval, or Policy evaluation can happen.
    let deadline = DateTime::from_timestamp_micros(intent.expires_at_epoch_micros)
        .ok_or_else(invalid_request)?;
    prepared.instance.expires_at = Some(
        prepared
            .instance
            .expires_at
            .ok_or_else(unavailable)?
            .min(deadline),
    );
    prepared.instance.context[ISSUANCE_PREREQUISITE_CONTEXT_V1] =
        serde_json::to_value(&intent).map_err(|_| invalid_request())?;
    validate_bound_instance(&prepared.instance, &intent)?;
    state
        .repository
        .save_issuance_prerequisite_start(&prepared.instance, &intent)
        .await?;
    // A racing identical start returns the original nonce and URI. The owner
    // persistence path rejects every different intent for this transaction.
    let stored = state
        .repository
        .issuance_prerequisite_instance(&intent)
        .await?
        .ok_or_else(unavailable)?;
    let now = state.repository.issuance_prerequisite_clock().await?;
    no_store(start_response(&stored, &intent, now)?)
}

async fn evidence(
    State(state): State<FlowHttpState>,
    headers: HeaderMap,
    Path(transaction_id): Path<String>,
    body: Bytes,
) -> Result<Response, FlowHttpError> {
    authenticate(&state, &headers)?;
    let request = IssuancePrerequisiteEvidenceRequestV1::from_json(
        std::str::from_utf8(&body).map_err(|_| invalid_request())?,
    )
    .map_err(|_| invalid_request())?;
    if request.intent.transaction_id != transaction_id {
        return Err(invalid_request());
    }
    let result = state
        .repository
        .issuance_prerequisite_evidence(&request.intent)
        .await?
        .ok_or_else(|| {
            FlowHttpError::new(
                StatusCode::CONFLICT,
                "issuance_prerequisite_not_completed",
                "The configured verification prerequisite has not completed",
            )
        })?;
    no_store(result)
}

fn no_store(value: impl serde::Serialize) -> Result<Response, FlowHttpError> {
    let mut response = Json(value).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    Ok(response)
}

pub(crate) fn start_response(
    instance: &FlowInstanceRecord,
    intent: &IssuanceIntentBindingV1,
    now: DateTime<Utc>,
) -> Result<IssuancePrerequisiteStartResponseV1, FlowHttpError> {
    validate_bound_instance(instance, intent)?;
    if !matches!(
        instance.status,
        FlowInstanceStatus::AwaitingWallet
            | FlowInstanceStatus::InProgress
            | FlowInstanceStatus::Completed
    ) {
        return Err(unavailable());
    }
    let response = IssuancePrerequisiteStartResponseV1 {
        contract: ISSUANCE_PREREQUISITE_START_RESPONSE_V1.into(),
        intent_digest: intent.intent_digest.clone(),
        flow_instance_id: instance.id.clone(),
        request_uri: context_text(instance, "request_uri")?.into(),
        qr_data: context_text(instance, "qr_code_data")?.into(),
        expires_at_epoch_micros: instance
            .expires_at
            .ok_or_else(unavailable)?
            .timestamp_micros(),
    };
    response
        .validate_for_intent(intent, now.timestamp_micros())
        .map_err(|_| expired())?;
    Ok(response)
}

pub(crate) fn bound_intent(
    instance: &FlowInstanceRecord,
) -> Result<Option<IssuanceIntentBindingV1>, RepositoryError> {
    instance
        .context
        .get(ISSUANCE_PREREQUISITE_CONTEXT_V1)
        .map(|value| {
            let intent: IssuanceIntentBindingV1 =
                serde_json::from_value(value.clone()).map_err(|_| conflict())?;
            validate_bound_instance(instance, &intent)?;
            Ok(intent)
        })
        .transpose()
}

pub(crate) fn validate_bound_instance(
    instance: &FlowInstanceRecord,
    intent: &IssuanceIntentBindingV1,
) -> Result<(), RepositoryError> {
    intent.validate().map_err(|_| conflict())?;
    let frozen = load_frozen_flow_presentation_request(instance).map_err(|_| conflict())?;
    let binding = &instance.context["_marty_verification_definition"]["binding"];
    if instance.id != intent.flow_instance_id
        || instance.organization_id != intent.organization_id
        || instance.flow_definition_id != intent.prerequisite.flow_definition_id
        || instance.context.get(ISSUANCE_PREREQUISITE_CONTEXT_V1)
            != Some(&serde_json::to_value(intent).map_err(|_| conflict())?)
        || instance.context["_marty_verification_principal_id"] != intent.initiating_principal_id
        || instance.context["oid4vp_issuer_did"] != intent.prerequisite.verifier_issuer_did
        || binding["organization_id"] != intent.organization_id
        || binding["definition_id"] != intent.prerequisite.flow_definition_id
        || binding["version"] != intent.prerequisite.flow_definition_version
        || frozen.policy_revision != intent.prerequisite.policy
        || frozen.credential_authority.is_none()
        || !managed_single_credential_query(&frozen.dcql_query)
        || frozen
            .credential_authority
            .as_ref()
            .is_some_and(|authority| {
                instance.context["trust_profile_id"].as_str() != Some(authority.profile.id.as_str())
            })
        || instance.created_at.timestamp_micros() < intent.created_at_epoch_micros
        || instance.expires_at.is_none_or(|expiry| {
            expiry.timestamp_micros() > intent.expires_at_epoch_micros
                || expiry <= instance.created_at
        })
    {
        return Err(conflict());
    }
    Ok(())
}

pub(crate) fn reject_supplied_intent(context: &Value) -> Result<(), RepositoryError> {
    if context.get(ISSUANCE_PREREQUISITE_CONTEXT_V1).is_some() {
        return Err(conflict());
    }
    Ok(())
}

pub(crate) fn validate_preserved_intent(
    before: &FlowInstanceRecord,
    after: &FlowInstanceRecord,
) -> Result<(), RepositoryError> {
    if before.context.get(ISSUANCE_PREREQUISITE_CONTEXT_V1)
        != after.context.get(ISSUANCE_PREREQUISITE_CONTEXT_V1)
    {
        return Err(conflict());
    }
    if let Some(intent) = bound_intent(before)? {
        validate_bound_instance(after, &intent)?;
        if before.created_at != after.created_at || before.expires_at != after.expires_at {
            return Err(conflict());
        }
    }
    Ok(())
}

fn managed_single_credential_query(query: &Value) -> bool {
    query
        .get("credentials")
        .and_then(Value::as_array)
        .is_some_and(|credentials| {
            credentials.len() == 1
                && credentials[0]["format"] == "dc+sd-jwt"
                && credentials[0]
                    .get("require_cryptographic_holder_binding")
                    .is_none_or(|value| value.as_bool() == Some(true))
        })
}

fn context_text<'a>(instance: &'a FlowInstanceRecord, key: &str) -> Result<&'a str, FlowHttpError> {
    instance
        .context
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(unavailable)
}

pub(crate) fn conflict() -> RepositoryError {
    RepositoryError::IssuancePrerequisiteConflict
}

fn invalid_request() -> FlowHttpError {
    FlowHttpError::new(
        StatusCode::BAD_REQUEST,
        "issuance_prerequisite_invalid",
        "Invalid issuance prerequisite request",
    )
}

fn unavailable() -> FlowHttpError {
    FlowHttpError::new(
        StatusCode::CONFLICT,
        "issuance_prerequisite_unavailable",
        "The configured issuance prerequisite is unavailable",
    )
}

fn expired() -> FlowHttpError {
    FlowHttpError::new(
        StatusCode::GONE,
        "issuance_prerequisite_expired",
        "The issuance prerequisite has expired",
    )
}
