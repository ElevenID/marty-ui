//! Isolated signing-response diagnostic compatibility, not production adoption.
//!
//! Mirrors the pinned Python signing helper's selection and evaluation order.
//! Callers own HTTP, JSON parsing and response-text decoding. The bound covers
//! selected diagnostic characters, not response allocation, operation prefixes
//! or secret redaction. This module does not log or contact a signing service.

use std::borrow::Cow;

use serde_json::Value;

use crate::python_value::{python_string, python_truthy, strip};

const MAX_DETAIL_CHARACTERS: usize = 500;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SigningOperation {
    Context,
    Resolve,
    Sign,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum SigningResponseAction {
    /// Continue to the existing operation-specific successful-response parser.
    Continue,
    /// Context and DID resolution retain their existing optional-result branch.
    NotFound,
    Error(String),
}

/// Evaluate response text even when a parsed JSON detail will replace it.
/// Parsing has already been attempted by the caller; text failures propagate.
pub(crate) fn error_detail<E>(
    payload: Option<&Value>,
    response_text: impl FnOnce() -> Result<String, E>,
    reason_phrase: &str,
) -> Result<String, E> {
    let text = response_text()?;
    let stripped = strip(&text);
    let fallback = if stripped.is_empty() {
        reason_phrase
    } else {
        stripped
    };
    let selected = payload.and_then(Value::as_object).and_then(|payload| {
        payload
            .get("detail")
            .filter(|value| python_truthy(value))
            .or_else(|| {
                payload
                    .get("error_description")
                    .filter(|value| python_truthy(value))
            })
            // Python's final `or` operand is returned even when falsey. An
            // empty dictionary here is therefore rendered as "{}", not lost.
            .or_else(|| payload.get("error"))
    });
    let detail = match selected {
        Some(Value::String(value)) if !strip(value).is_empty() => Cow::Borrowed(strip(value)),
        Some(value @ Value::Object(_)) => Cow::Owned(
            python_string(value).expect("JSON objects have a Python string representation"),
        ),
        _ => Cow::Borrowed(fallback),
    };
    Ok(detail.chars().take(MAX_DETAIL_CHARACTERS).collect())
}

/// Classify only the remote status/diagnostic boundary. Neither supplier runs
/// for successful-response continuation, resolver absence or API-key rejection.
pub(crate) fn operation_response<E>(
    operation: SigningOperation,
    status: u16,
    json_payload: impl FnOnce() -> Option<Value>,
    response_text: impl FnOnce() -> Result<String, E>,
    reason_phrase: &str,
) -> Result<SigningResponseAction, E> {
    if status == 404 && operation != SigningOperation::Sign {
        return Ok(SigningResponseAction::NotFound);
    }
    if status == 401 {
        return Ok(SigningResponseAction::Error(
            "Internal signing API rejected the service API key".into(),
        ));
    }
    if status < 400 {
        return Ok(SigningResponseAction::Continue);
    }
    let payload = json_payload();
    let detail = error_detail(payload.as_ref(), response_text, reason_phrase)?;
    let prefix = match operation {
        SigningOperation::Context => "DID issuer context resolution failed",
        SigningOperation::Resolve => "Issuer DID resolution failed",
        SigningOperation::Sign => "DID-mediated signing failed",
    };
    Ok(SigningResponseAction::Error(format!(
        "{prefix} (HTTP {status}): {detail}"
    )))
}
