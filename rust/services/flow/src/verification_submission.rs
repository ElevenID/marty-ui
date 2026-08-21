use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use marty_verification::flow::FlowInstanceStatus;
use mmf_messaging::Message;
use mmf_push::{payload_digest, WebhookDestinationRegistry, MINIMUM_EVENT_SECRET_BYTES};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::{
    public_context, public_status, CallbackEvent, FlowInstanceRecord, FlowKeyEnvelope,
    FlowProviderError, FlowProviderRegistry, FlowRecordError, PresentationEvaluationRequest,
    VerificationResultResponse,
};

#[derive(Clone, Debug, PartialEq)]
pub struct VerificationSubmissionInput {
    pub vp_token: String,
    pub presentation_submission: Option<Value>,
    pub state: Option<String>,
    pub audience_override: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationSubmissionOptions {
    pub callback_destinations: WebhookDestinationRegistry,
    pub callback_secret: Option<String>,
    pub verifier_sender_id: String,
    pub nonce_ttl_seconds: u64,
    pub callback_retention_seconds: u64,
    pub callback_max_attempts: u32,
}

#[derive(Clone, Debug)]
pub struct PreparedVerificationFinalization {
    pub instance: FlowInstanceRecord,
    pub expected_status: FlowInstanceStatus,
    pub nonce_digest: String,
    pub replay_expires_at_ms: u64,
    pub callback: Option<Message>,
    pub submission_digest: String,
}

#[derive(Clone, Debug)]
pub enum PreparedVerificationSubmission {
    Final(Box<PreparedVerificationFinalization>),
    Retryable(VerificationResultResponse),
    Expired(FlowInstanceRecord),
    SameTerminal(VerificationResultResponse),
    ReplayConflict,
}

#[derive(Debug, Error)]
pub enum FlowVerificationSubmissionError {
    #[error(transparent)]
    Provider(#[from] FlowProviderError),
    #[error(transparent)]
    Record(#[from] FlowRecordError),
    #[error("FLOW.VERIFICATION_SUBMISSION_INVALID_STATE")]
    InvalidState,
    #[error("FLOW.VERIFICATION_SUBMISSION_INVALID_CONTEXT: {0}")]
    InvalidContext(&'static str),
    #[error("FLOW.VERIFICATION_SUBMISSION_STATE_MISMATCH")]
    StateMismatch,
    #[error("FLOW.VERIFICATION_SUBMISSION_INVALID_PRESENTATION_SUBMISSION")]
    InvalidPresentationSubmission,
    #[error("FLOW.VERIFICATION_SUBMISSION_CALLBACK_UNAVAILABLE")]
    CallbackUnavailable,
    #[error("FLOW.VERIFICATION_SUBMISSION_INVALID_ENCRYPTED_RESPONSE")]
    InvalidEncryptedResponse,
    #[error("FLOW.VERIFICATION_SUBMISSION_SERIALIZATION")]
    Serialization,
    #[error("FLOW.VERIFICATION_SUBMISSION_INVALID_CLOCK")]
    InvalidClock,
}

pub async fn decrypt_verification_response(
    providers: &FlowProviderRegistry,
    instance: &FlowInstanceRecord,
    compact_jwe: &str,
) -> Result<Value, FlowVerificationSubmissionError> {
    marty_verification::jwk::validate_haip_response_header(compact_jwe)
        .map_err(|_| FlowVerificationSubmissionError::InvalidEncryptedResponse)?;
    let envelope = instance
        .context
        .get("haip_response_encryption_key_envelope")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("vault:"))
        .ok_or(FlowVerificationSubmissionError::InvalidEncryptedResponse)?;
    let provider = providers
        .flow_key_envelope
        .as_ref()
        .ok_or(FlowProviderError::Unavailable {
            provider: "flow_key_envelope",
        })?;
    let private_jwk = provider
        .unwrap(&FlowKeyEnvelope {
            organization_id: instance.organization_id.clone(),
            flow_instance_id: instance.id.clone(),
            purpose: "oid4vp_response_decryption".into(),
            envelope: envelope.into(),
        })
        .await?;
    let plaintext = marty_verification::jwk::decrypt_haip_response(compact_jwe, &private_jwk)
        .map_err(|_| FlowVerificationSubmissionError::InvalidEncryptedResponse)?;
    let value: Value = serde_json::from_slice(&plaintext)
        .map_err(|_| FlowVerificationSubmissionError::InvalidEncryptedResponse)?;
    if !value.is_object() {
        return Err(FlowVerificationSubmissionError::InvalidEncryptedResponse);
    }
    Ok(value)
}

pub async fn prepare_verification_submission(
    providers: &FlowProviderRegistry,
    mut instance: FlowInstanceRecord,
    input: VerificationSubmissionInput,
    options: &VerificationSubmissionOptions,
    now: DateTime<Utc>,
) -> Result<PreparedVerificationSubmission, FlowVerificationSubmissionError> {
    let submission_digest = payload_digest(&json!({
        "vp_token": input.vp_token,
        "presentation_submission": input.presentation_submission,
        "state": input.state
    }))
    .map_err(|_| FlowVerificationSubmissionError::Serialization)?;
    if matches!(
        instance.status,
        FlowInstanceStatus::Completed | FlowInstanceStatus::Failed
    ) {
        let prior = instance
            .result
            .as_ref()
            .and_then(|value| value.get("submission_digest"))
            .and_then(Value::as_str);
        return if prior.is_some_and(|prior| constant_time_equal(prior, &submission_digest)) {
            Ok(PreparedVerificationSubmission::SameTerminal(
                instance.verification_projection()?,
            ))
        } else {
            Ok(PreparedVerificationSubmission::ReplayConflict)
        };
    }
    if instance
        .expires_at
        .is_some_and(|expires_at| now >= expires_at)
    {
        expire_submission(&mut instance, now, "submission_expired")?;
        return Ok(PreparedVerificationSubmission::Expired(instance));
    }
    if !matches!(
        instance.status,
        FlowInstanceStatus::AwaitingWallet | FlowInstanceStatus::InProgress
    ) {
        return Err(FlowVerificationSubmissionError::InvalidState);
    }
    let expected_status = instance.status;
    let context = instance
        .context
        .as_object()
        .ok_or(FlowVerificationSubmissionError::InvalidContext("context"))?;
    if let Some(expected_state) = context.get("oid4vp_expected_state").and_then(Value::as_str) {
        if input
            .state
            .as_deref()
            .is_none_or(|state| !constant_time_equal(state, expected_state))
        {
            return Err(FlowVerificationSubmissionError::StateMismatch);
        }
    }
    let nonce = required_context_string(context, "nonce")?.to_owned();
    let policy_id = required_context_string(context, "presentation_policy_id")?.to_owned();
    let audience = input
        .audience_override
        .as_deref()
        .or_else(|| context.get("verification_audience").and_then(Value::as_str))
        .unwrap_or_default()
        .to_owned();
    let presentation_submission = parse_presentation_submission(input.presentation_submission)?;
    let raw_vp_token = input.vp_token;
    let vp_token = select_vp_token(&raw_vp_token);
    let mut evaluation_context = BTreeMap::new();
    if context
        .get("oid4vp_verifier_context")
        .and_then(Value::as_bool)
        == Some(true)
    {
        evaluation_context.insert("oid4vp_verifier_context".into(), json!(true));
        evaluation_context.insert("replay_check_verified".into(), json!(true));
    }
    if let (Some(client_id), Some(response_uri)) = (
        context.get("oid4vp_client_id").and_then(Value::as_str),
        context.get("oid4vp_response_uri").and_then(Value::as_str),
    ) {
        let response_jwk = context
            .get("oid4vp_response_encryption_jwk")
            .filter(|value| value.is_object())
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| FlowVerificationSubmissionError::Serialization)?;
        let transcript = marty_iso18013::openid4vp::build_mdoc_session_transcript(
            client_id,
            &nonce,
            response_uri,
            response_jwk.as_deref(),
        )
        .map_err(|_| FlowVerificationSubmissionError::InvalidContext("mdoc_handover"))?;
        marty_iso18013::openid4vp::mdoc_binding_digests(
            &transcript,
            client_id,
            &nonce,
            response_uri,
            response_jwk.as_deref(),
            &vp_token,
        )
        .map_err(|_| FlowVerificationSubmissionError::InvalidContext("mdoc_handover"))?;
        evaluation_context.insert(
            "mdoc_session_transcript_b64url".into(),
            json!(URL_SAFE_NO_PAD.encode(transcript)),
        );
        evaluation_context.insert("oid4vp_client_id".into(), json!(client_id));
        evaluation_context.insert("oid4vp_response_uri".into(), json!(response_uri));
    }
    if let Some(trust_profile_id) = context.get("trust_profile_id").cloned() {
        evaluation_context.insert("trust_profile_id".into(), trust_profile_id);
    }
    let policy = providers
        .presentation_policy
        .as_ref()
        .ok_or(FlowProviderError::Unavailable {
            provider: "presentation_policy",
        });
    let evaluation = match policy {
        Ok(provider) => {
            provider
                .evaluate(&PresentationEvaluationRequest {
                    policy_id: policy_id.clone(),
                    organization_id: instance.organization_id.clone(),
                    presentation: vp_token.clone(),
                    nonce: nonce.clone(),
                    audience: audience.clone(),
                    context: evaluation_context,
                })
                .await
        }
        Err(error) => Err(error),
    };
    let evaluation = match evaluation {
        Ok(evaluation) if !evaluation.result.trim().is_empty() => evaluation,
        Ok(_) => {
            return Ok(retryable_result(
                &instance,
                "Policy service returned no verification decision",
                now,
            ))
        }
        Err(error) => {
            return Ok(retryable_result(
                &instance,
                &format!("Policy service unavailable: {error}"),
                now,
            ))
        }
    };
    let authenticated = !evaluation.credential_results.is_empty()
        && evaluation
            .credential_results
            .iter()
            .all(|result| result.get("signature_valid").and_then(Value::as_bool) == Some(true));
    if !authenticated {
        return Ok(retryable_result(
            &instance,
            evaluation
                .decision_reason
                .as_deref()
                .unwrap_or("Presentation authentication failed"),
            now,
        ));
    }
    let final_allowed = evaluation.result == "passed" && evaluation.decision == "allow";
    let verified_claims = if final_allowed {
        public_context(&json!(evaluation.verified_claims))
    } else {
        json!({})
    };
    let credential_results = public_context(&json!(evaluation.credential_results))
        .as_array()
        .cloned()
        .ok_or(FlowVerificationSubmissionError::Serialization)?;
    let error_codes = merged_error_codes(&evaluation.error_codes, &credential_results);
    let warnings = merged_warnings(&evaluation.warnings, &credential_results);
    let context = instance
        .context
        .as_object_mut()
        .ok_or(FlowVerificationSubmissionError::InvalidContext("context"))?;
    for key in ["vp_token", "vp_token_raw", "presentation_submission"] {
        context.remove(key);
    }
    context.insert(
        "vp_token_sha256".into(),
        json!(sha256_hex(vp_token.as_bytes())),
    );
    if raw_vp_token != vp_token {
        context.insert(
            "vp_transport_sha256".into(),
            json!(sha256_hex(raw_vp_token.as_bytes())),
        );
    }
    if let Some(submission) = &presentation_submission {
        context.insert(
            "presentation_submission_sha256".into(),
            json!(payload_digest(submission)
                .map_err(|_| FlowVerificationSubmissionError::Serialization)?),
        );
    }
    if let Some(state) = &input.state {
        context.insert("state".into(), json!(state));
    }
    if !audience.is_empty() {
        context.insert("verification_audience".into(), json!(audience));
    }
    if instance.status == FlowInstanceStatus::AwaitingWallet {
        transition(
            &mut instance,
            FlowInstanceStatus::InProgress,
            "wallet_submission_received",
            now,
        );
    }
    transition(
        &mut instance,
        if final_allowed {
            FlowInstanceStatus::Completed
        } else {
            FlowInstanceStatus::Failed
        },
        if final_allowed {
            "verification_completed"
        } else {
            "verification_failed"
        },
        now,
    );
    instance.result = Some(json!({
        "evaluation_result": evaluation.result,
        "decision": evaluation.decision,
        "decision_reason": evaluation.decision_reason,
        "verified_claims": verified_claims,
        "credential_results": credential_results,
        "error_codes": error_codes,
        "warnings": warnings,
        "submission_digest": submission_digest
    }));
    record_verification_result_message(&mut instance, &policy_id, options, now)?;
    instance.kernel()?;
    let callback = build_callback(&instance, &policy_id, options, now)?;
    let replay_expires_at = instance
        .expires_at
        .filter(|expires_at| *expires_at > now)
        .unwrap_or(
            now.checked_add_signed(Duration::seconds(
                i64::try_from(options.nonce_ttl_seconds)
                    .map_err(|_| FlowVerificationSubmissionError::InvalidClock)?,
            ))
            .ok_or(FlowVerificationSubmissionError::InvalidClock)?,
        );
    let replay_expires_at_ms = u64::try_from(replay_expires_at.timestamp_millis())
        .map_err(|_| FlowVerificationSubmissionError::InvalidClock)?;
    Ok(PreparedVerificationSubmission::Final(Box::new(
        PreparedVerificationFinalization {
            instance,
            expected_status,
            nonce_digest: sha256_hex(nonce.as_bytes()),
            replay_expires_at_ms,
            callback,
            submission_digest,
        },
    )))
}

fn parse_presentation_submission(
    value: Option<Value>,
) -> Result<Option<Value>, FlowVerificationSubmissionError> {
    let Some(value) = value else { return Ok(None) };
    let parsed = match value {
        Value::String(raw) => serde_json::from_str(&raw)
            .map_err(|_| FlowVerificationSubmissionError::InvalidPresentationSubmission)?,
        value => value,
    };
    let object = parsed
        .as_object()
        .ok_or(FlowVerificationSubmissionError::InvalidPresentationSubmission)?;
    if ["id", "definition_id"].iter().any(|field| {
        object
            .get(*field)
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
    }) || object
        .get("descriptor_map")
        .and_then(Value::as_array)
        .is_none()
    {
        return Err(FlowVerificationSubmissionError::InvalidPresentationSubmission);
    }
    Ok(Some(parsed))
}

fn select_vp_token(raw: &str) -> String {
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return raw.into();
    };
    if let Some(object) = value.as_object() {
        if object.len() == 1 {
            if let Some(values) = object.values().next().and_then(Value::as_array) {
                if values.len() == 1 {
                    if let Some(token) = values[0].as_str().filter(|value| !value.trim().is_empty())
                    {
                        return token.into();
                    }
                }
            }
        }
    }
    find_token(&value).unwrap_or(raw).into()
}

fn find_token(value: &Value) -> Option<&str> {
    match value {
        Value::String(value)
            if value.contains('~')
                || value.matches('.').count() >= 2
                || value.starts_with("mso_mdoc:")
                || value.starts_with("mdoc:")
                || value.starts_with("oob:") =>
        {
            Some(value)
        }
        Value::Array(values) => values.iter().find_map(find_token),
        Value::Object(values) => values.values().find_map(find_token),
        _ => None,
    }
}

fn retryable_result(
    instance: &FlowInstanceRecord,
    reason: &str,
    now: DateTime<Utc>,
) -> PreparedVerificationSubmission {
    PreparedVerificationSubmission::Retryable(VerificationResultResponse {
        instance_id: instance.id.clone(),
        status: public_status(instance.status).into(),
        result: Some("failed".into()),
        decision: Some("deny".into()),
        decision_reason: Some(reason.into()),
        verified_claims: json!({}),
        credential_results: Vec::new(),
        error_codes: Vec::new(),
        warnings: Vec::new(),
        evaluation_timestamp: Some(now.to_rfc3339()),
    })
}

pub(crate) fn transition(
    instance: &mut FlowInstanceRecord,
    status: FlowInstanceStatus,
    event: &str,
    now: DateTime<Utc>,
) {
    let prior = instance.status;
    instance.status = status;
    instance.updated_at = now;
    if status.is_terminal() {
        instance.completed_at = Some(now);
    }
    instance.state_history.push(json!({
        "prior_state": prior,
        "new_state": status,
        "timestamp": now.to_rfc3339(),
        "actor": "wallet_submission",
        "event": event
    }));
}

fn expire_submission(
    instance: &mut FlowInstanceRecord,
    now: DateTime<Utc>,
    event: &str,
) -> Result<(), FlowVerificationSubmissionError> {
    transition(instance, FlowInstanceStatus::Expired, event, now);
    instance.error = Some(event.into());
    instance.kernel()?;
    Ok(())
}

fn record_verification_result_message(
    instance: &mut FlowInstanceRecord,
    policy_id: &str,
    options: &VerificationSubmissionOptions,
    now: DateTime<Utc>,
) -> Result<(), FlowVerificationSubmissionError> {
    let result = instance
        .result
        .as_ref()
        .and_then(Value::as_object)
        .ok_or(FlowVerificationSubmissionError::Serialization)?;
    let claims = result
        .get("verified_claims")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let credentials = result
        .get("credential_results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let revocation_checked = !credentials.is_empty()
        && credentials
            .iter()
            .all(|item| item.get("revocation_checked").and_then(Value::as_bool) == Some(true));
    let not_revoked = revocation_checked.then(|| {
        credentials
            .iter()
            .all(|item| item.get("not_revoked").and_then(Value::as_bool) == Some(true))
    });
    let trust_valid = !credentials.is_empty()
        && credentials
            .iter()
            .all(|item| item.get("trust_check_passed").and_then(Value::as_bool) == Some(true));
    let nonce = instance
        .context
        .get("nonce")
        .cloned()
        .unwrap_or(Value::Null);
    let message = json!({
        "mip_version": "0.3.1",
        "message_type": "VerificationResult",
        "message_id": uuid::Uuid::new_v4().to_string(),
        "correlation_id": instance.id,
        "timestamp": now.to_rfc3339(),
        "sender_id": options.verifier_sender_id,
        "nonce": nonce,
        "payload": {
            "flow_instance_id": instance.id,
            "policy_id": policy_id,
            "overall_result": result.get("evaluation_result").and_then(Value::as_str).unwrap_or("failed").to_ascii_uppercase(),
            "claim_results": claims.into_iter().map(|(name, value)| json!({
                "claim_name": name,
                "required": false,
                "present": !value.is_null(),
                "satisfies_predicate": !value.is_null(),
                "result": if value.is_null() { "SKIPPED" } else { "PASS" }
            })).collect::<Vec<_>>(),
            "trust_chain_valid": trust_valid,
            "revocation_checked": revocation_checked,
            "revocation_status": match not_revoked { Some(true) => "VALID", Some(false) => "REVOKED", None => "UNKNOWN" },
            "evaluated_at": now.to_rfc3339(),
            "verifier_nonce": instance.context.get("nonce").and_then(Value::as_str).unwrap_or_default()
        },
        "signature": null
    });
    instance
        .context
        .as_object_mut()
        .ok_or(FlowVerificationSubmissionError::InvalidContext("context"))?
        .entry("mip_messages")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or(FlowVerificationSubmissionError::InvalidContext(
            "mip_messages",
        ))?
        .insert("verification_result".into(), message);
    Ok(())
}

fn build_callback(
    instance: &FlowInstanceRecord,
    policy_id: &str,
    options: &VerificationSubmissionOptions,
    now: DateTime<Utc>,
) -> Result<Option<Message>, FlowVerificationSubmissionError> {
    let Some(destination) = instance
        .context
        .get("callback_url")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    if options
        .callback_secret
        .as_deref()
        .is_none_or(|secret| secret.len() < MINIMUM_EVENT_SECRET_BYTES)
    {
        return Err(FlowVerificationSubmissionError::CallbackUnavailable);
    }
    let result = instance
        .result
        .as_ref()
        .and_then(Value::as_object)
        .ok_or(FlowVerificationSubmissionError::Serialization)?;
    let credential_results = result
        .get("credential_results")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let mut payload = json!({
        "flow_instance_id": instance.id,
        "result": result.get("evaluation_result"),
        "decision": result.get("decision"),
        "decision_reason": result.get("decision_reason"),
        "verified_claims": result.get("verified_claims"),
        "presentation_policy_id": policy_id,
        "completed_at": instance.completed_at.map(|value| value.to_rfc3339()),
        "evidence_digest": payload_digest(&json!({"credential_results": credential_results}))
            .map_err(|_| FlowVerificationSubmissionError::Serialization)?
    });
    let decision_digest =
        payload_digest(&payload).map_err(|_| FlowVerificationSubmissionError::Serialization)?;
    payload["decision_digest"] = json!(decision_digest);
    let created_at_ms = u64::try_from(now.timestamp_millis())
        .map_err(|_| FlowVerificationSubmissionError::InvalidClock)?;
    CallbackEvent::new_with_retention(
        instance.id.clone(),
        instance.organization_id.clone(),
        destination,
        payload,
        created_at_ms,
        &options.callback_destinations,
        options.callback_retention_seconds,
    )
    .map(|event| event.into_outbox_message_with_max_attempts(options.callback_max_attempts))
    .map(Some)
    .map_err(|_| FlowVerificationSubmissionError::CallbackUnavailable)
}

fn required_context_string<'a>(
    context: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, FlowVerificationSubmissionError> {
    context
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(FlowVerificationSubmissionError::InvalidContext(field))
}

fn merged_error_codes(top_level: &[String], credentials: &[Value]) -> Vec<String> {
    top_level
        .iter()
        .map(String::as_str)
        .chain(credentials.iter().flat_map(|credential| {
            credential
                .get("error_codes")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
        }))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn merged_warnings(top_level: &[String], credentials: &[Value]) -> Vec<String> {
    top_level
        .iter()
        .map(String::as_str)
        .chain(credentials.iter().flat_map(|credential| {
            credential
                .get("warnings")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
        }))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(crate) fn sha256_hex(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn constant_time_equal(left: &str, right: &str) -> bool {
    left.len() == right.len() && bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}
