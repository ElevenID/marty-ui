use chrono::{DateTime, Duration, Utc};
use marty_oid4vci::siop::{verify_jwk_thumbprint_id_token, JWK_THUMBPRINT_SUBJECT_PREFIX};
use marty_verification::flow::FlowInstanceStatus;
use mmf_push::payload_digest;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use thiserror::Error;

use crate::{
    constant_time_equal, sha256_hex, transition, FlowInstanceRecord, FlowRecordError,
    PreparedVerificationFinalization,
};

pub const SIOP_CLOCK_SKEW_SECONDS: i64 = 60;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiopSubmissionOptions {
    pub nonce_ttl_seconds: u64,
    pub clock_skew_seconds: i64,
}

impl Default for SiopSubmissionOptions {
    fn default() -> Self {
        Self {
            nonce_ttl_seconds: 900,
            clock_skew_seconds: SIOP_CLOCK_SKEW_SECONDS,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SiopVerificationResponse {
    pub status: String,
    pub sub: String,
    pub nonce: String,
    pub subject_syntax_type: String,
}

#[derive(Clone, Debug)]
pub struct PreparedSiopFinalization {
    pub finalization: PreparedVerificationFinalization,
    pub response: SiopVerificationResponse,
}

#[derive(Clone, Debug)]
pub enum PreparedSiopSubmission {
    Final(Box<PreparedSiopFinalization>),
    Expired(Box<FlowInstanceRecord>),
    SameTerminal(SiopVerificationResponse),
    ReplayConflict,
}

#[derive(Debug, Error)]
pub enum FlowSiopSubmissionError {
    #[error(transparent)]
    Record(#[from] FlowRecordError),
    #[error("FLOW.SIOP_INVALID_STATE")]
    InvalidState,
    #[error("FLOW.SIOP_INVALID_TRANSACTION")]
    InvalidTransaction,
    #[error("FLOW.SIOP_INVALID_CONTEXT: {0}")]
    InvalidContext(&'static str),
    #[error("FLOW.SIOP_INVALID_ID_TOKEN: {0}")]
    InvalidIdToken(String),
    #[error("FLOW.SIOP_ISSUER_SUBJECT_MISMATCH")]
    IssuerSubjectMismatch,
    #[error("FLOW.SIOP_AUDIENCE_MISMATCH")]
    AudienceMismatch,
    #[error("FLOW.SIOP_NONCE_MISMATCH")]
    NonceMismatch,
    #[error("FLOW.SIOP_INVALID_TIME_CLAIMS")]
    InvalidTimeClaims,
    #[error("FLOW.SIOP_IAT_IN_FUTURE")]
    IssuedAtInFuture,
    #[error("FLOW.SIOP_TOKEN_EXPIRED")]
    TokenExpired,
    #[error("FLOW.SIOP_INVALID_VALIDITY_WINDOW")]
    InvalidValidityWindow,
    #[error("FLOW.SIOP_TOKEN_PREDATES_TRANSACTION")]
    TokenPredatesTransaction,
    #[error("FLOW.SIOP_SERIALIZATION")]
    Serialization,
    #[error("FLOW.SIOP_INVALID_CLOCK")]
    InvalidClock,
}

pub fn prepare_siop_submission(
    mut instance: FlowInstanceRecord,
    id_token: &str,
    options: &SiopSubmissionOptions,
    now: DateTime<Utc>,
) -> Result<PreparedSiopSubmission, FlowSiopSubmissionError> {
    validate_options(options)?;
    let context = instance_context(&instance)?;
    if context.get("flow_type").and_then(Value::as_str) != Some("siop_v2") {
        return Err(FlowSiopSubmissionError::InvalidTransaction);
    }
    let submission_digest = payload_digest(&json!({"id_token": id_token}))
        .map_err(|_| FlowSiopSubmissionError::Serialization)?;
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
            Ok(PreparedSiopSubmission::SameTerminal(terminal_response(
                &instance,
            )?))
        } else {
            Ok(PreparedSiopSubmission::ReplayConflict)
        };
    }
    if instance
        .expires_at
        .is_some_and(|expires_at| now >= expires_at)
    {
        transition(
            &mut instance,
            FlowInstanceStatus::Expired,
            "siop_submission_expired",
            now,
        );
        instance.error = Some("siop_submission_expired".into());
        instance.kernel()?;
        return Ok(PreparedSiopSubmission::Expired(Box::new(instance)));
    }
    if !matches!(
        instance.status,
        FlowInstanceStatus::AwaitingWallet | FlowInstanceStatus::InProgress
    ) {
        return Err(FlowSiopSubmissionError::InvalidState);
    }
    let expected_status = instance.status;
    let context = instance_context(&instance)?;
    let expected_nonce = required_string(context, "nonce")?.to_owned();
    let expected_audience = required_string(context, "siop_client_id")?.to_owned();
    let verified = verify_jwk_thumbprint_id_token(id_token)
        .map_err(|error| FlowSiopSubmissionError::InvalidIdToken(error.to_string()))?;
    let claims = verified.claims.as_object().ok_or_else(|| {
        FlowSiopSubmissionError::InvalidIdToken("claims are not an object".into())
    })?;
    let subject = required_claim_string(claims, "sub")?;
    let issuer = required_claim_string(claims, "iss")?;
    if !constant_time_equal(issuer, subject) {
        return Err(FlowSiopSubmissionError::IssuerSubjectMismatch);
    }
    if !audience_matches(claims.get("aud"), &expected_audience) {
        return Err(FlowSiopSubmissionError::AudienceMismatch);
    }
    let nonce = required_claim_string(claims, "nonce")?;
    if !constant_time_equal(nonce, &expected_nonce) {
        return Err(FlowSiopSubmissionError::NonceMismatch);
    }
    validate_time_claims(&instance, claims, options.clock_skew_seconds, now)?;

    if instance.status == FlowInstanceStatus::AwaitingWallet {
        transition(
            &mut instance,
            FlowInstanceStatus::InProgress,
            "siop_submission_received",
            now,
        );
    }
    transition(
        &mut instance,
        FlowInstanceStatus::Completed,
        "siop_verification_completed",
        now,
    );
    instance.subject_id = Some(subject.to_owned());
    instance.result = Some(json!({
        "evaluation_result": "passed",
        "decision": "allow",
        "subject": subject,
        "subject_syntax_type": JWK_THUMBPRINT_SUBJECT_PREFIX,
        "signing_algorithm": verified.signing_algorithm,
        "claims_trust": "self_attested",
        "submission_digest": submission_digest
    }));
    instance.kernel()?;
    let response = terminal_response(&instance)?;
    let replay_expires_at = instance
        .expires_at
        .filter(|expires_at| *expires_at > now)
        .unwrap_or(
            now.checked_add_signed(Duration::seconds(
                i64::try_from(options.nonce_ttl_seconds)
                    .map_err(|_| FlowSiopSubmissionError::InvalidClock)?,
            ))
            .ok_or(FlowSiopSubmissionError::InvalidClock)?,
        );
    let replay_expires_at_ms = u64::try_from(replay_expires_at.timestamp_millis())
        .map_err(|_| FlowSiopSubmissionError::InvalidClock)?;
    Ok(PreparedSiopSubmission::Final(Box::new(
        PreparedSiopFinalization {
            finalization: PreparedVerificationFinalization {
                instance,
                expected_status,
                nonce_digest: sha256_hex(expected_nonce.as_bytes()),
                replay_expires_at_ms,
                callback: None,
                submission_digest,
            },
            response,
        },
    )))
}

fn validate_options(options: &SiopSubmissionOptions) -> Result<(), FlowSiopSubmissionError> {
    if options.nonce_ttl_seconds == 0 || !(0..=300).contains(&options.clock_skew_seconds) {
        return Err(FlowSiopSubmissionError::InvalidClock);
    }
    Ok(())
}

fn validate_time_claims(
    instance: &FlowInstanceRecord,
    claims: &Map<String, Value>,
    clock_skew_seconds: i64,
    now: DateTime<Utc>,
) -> Result<(), FlowSiopSubmissionError> {
    let issued_at = numeric_date(claims.get("iat"))?;
    let expires_at = numeric_date(claims.get("exp"))?;
    let now = now.timestamp() as f64;
    let skew = clock_skew_seconds as f64;
    if issued_at > now + skew {
        return Err(FlowSiopSubmissionError::IssuedAtInFuture);
    }
    if expires_at <= now - skew {
        return Err(FlowSiopSubmissionError::TokenExpired);
    }
    if issued_at >= expires_at {
        return Err(FlowSiopSubmissionError::InvalidValidityWindow);
    }
    if instance
        .started_at
        .is_some_and(|started_at| issued_at < (started_at.timestamp() - clock_skew_seconds) as f64)
    {
        return Err(FlowSiopSubmissionError::TokenPredatesTransaction);
    }
    Ok(())
}

fn numeric_date(value: Option<&Value>) -> Result<f64, FlowSiopSubmissionError> {
    value
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
        .ok_or(FlowSiopSubmissionError::InvalidTimeClaims)
}

fn audience_matches(value: Option<&Value>, expected: &str) -> bool {
    match value {
        Some(Value::String(value)) => constant_time_equal(value, expected),
        Some(Value::Array(values)) => values.iter().any(|value| {
            value
                .as_str()
                .is_some_and(|value| constant_time_equal(value, expected))
        }),
        _ => false,
    }
}

fn terminal_response(
    instance: &FlowInstanceRecord,
) -> Result<SiopVerificationResponse, FlowSiopSubmissionError> {
    let result = instance
        .result
        .as_ref()
        .and_then(Value::as_object)
        .ok_or(FlowSiopSubmissionError::InvalidContext("result"))?;
    Ok(SiopVerificationResponse {
        status: "verified".into(),
        sub: required_string(result, "subject")?.to_owned(),
        nonce: required_string(instance_context(instance)?, "nonce")?.to_owned(),
        subject_syntax_type: result
            .get("subject_syntax_type")
            .and_then(Value::as_str)
            .unwrap_or(JWK_THUMBPRINT_SUBJECT_PREFIX)
            .to_owned(),
    })
}

fn instance_context(
    instance: &FlowInstanceRecord,
) -> Result<&Map<String, Value>, FlowSiopSubmissionError> {
    instance
        .context
        .as_object()
        .ok_or(FlowSiopSubmissionError::InvalidContext("context"))
}

fn required_claim_string<'a>(
    claims: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, FlowSiopSubmissionError> {
    claims
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| FlowSiopSubmissionError::InvalidIdToken(format!("missing {field}")))
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, FlowSiopSubmissionError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(FlowSiopSubmissionError::InvalidContext(field))
}
