//! Shared lossless signing-response diagnostic compatibility.
//!
//! Mirrors the pinned Python signing helper's selection and evaluation order.
//! Callers own HTTP, JSON parsing and response-text decoding. The bound covers
//! selected diagnostic characters, not response allocation, operation prefixes
//! or secret redaction. This module does not log or contact a signing service.

#[cfg(test)]
use serde_json::Value;

use crate::python_value::{
    representation_points, strip_points, value_truthy, PythonValueNode, PythonValueView,
};

const MAX_DETAIL_CHARACTERS: usize = 500;

#[cfg(test)]
#[test]
fn scalar_api_remains_a_projection_of_the_shared_owner() {
    let payload = serde_json::json!({"detail": {"ok": false}});
    assert_eq!(
        error_detail(Some(&payload), || Ok::<_, ()>("fallback".into()), "reason").unwrap(),
        "{'ok': False}"
    );
    assert_eq!(
        operation_response(
            SigningOperation::Context,
            503,
            || Some(payload),
            || Ok::<_, ()>("fallback".into()),
            "reason"
        )
        .unwrap(),
        SigningResponseAction::Error(
            "DID issuer context resolution failed (HTTP 503): {'ok': False}".into()
        )
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SigningOperation {
    Context,
    Resolve,
    Sign,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum SigningResponseAction<T = String> {
    /// Continue to the existing operation-specific successful-response parser.
    Continue,
    /// Context and DID resolution retain their existing optional-result branch.
    NotFound,
    Error(T),
}

/// Evaluate response text even when a parsed JSON detail will replace it.
/// Parsing has already been attempted by the caller; text failures propagate.
#[cfg(test)]
pub(crate) fn error_detail<E>(
    payload: Option<&Value>,
    response_text: impl FnOnce() -> Result<String, E>,
    reason_phrase: &str,
) -> Result<String, E> {
    error_detail_points(
        payload,
        || response_text().map(|text| text.chars().map(u32::from).collect()),
        reason_phrase,
    )
    .map(scalar_points)
}

pub(crate) fn error_detail_points<V: PythonValueView, E>(
    payload: Option<V>,
    response_text: impl FnOnce() -> Result<Vec<u32>, E>,
    reason_phrase: &str,
) -> Result<Vec<u32>, E> {
    let text = response_text()?;
    let stripped = strip_points(&text);
    let reason: Vec<_> = reason_phrase.chars().map(u32::from).collect();
    let fallback = if stripped.is_empty() {
        &reason
    } else {
        stripped
    };
    let selected = payload.and_then(|payload| {
        let PythonValueNode::Object(fields) = payload.view() else {
            return None;
        };
        let field = |name: &str| {
            fields
                .iter()
                .find(|(key, _)| key.iter().copied().eq(name.bytes().map(u32::from)))
                .map(|(_, value)| *value)
        };
        field("detail")
            .filter(|value| value_truthy(*value))
            .or_else(|| field("error_description").filter(|value| value_truthy(*value)))
            // The final `or` operand is retained even when falsey.
            .or_else(|| field("error"))
    });
    let detail = match selected.map(|value| (value, value.view())) {
        Some((_, PythonValueNode::Text(value))) if !strip_points(&value).is_empty() => {
            strip_points(&value).to_vec()
        }
        Some((value, PythonValueNode::Object(_))) => representation_points(value),
        _ => fallback.to_vec(),
    };
    Ok(detail.into_iter().take(MAX_DETAIL_CHARACTERS).collect())
}

/// Classify only the remote status/diagnostic boundary. Neither supplier runs
/// for successful-response continuation, resolver absence or API-key rejection.
#[cfg(test)]
pub(crate) fn operation_response<E>(
    operation: SigningOperation,
    status: u16,
    json_payload: impl FnOnce() -> Option<Value>,
    response_text: impl FnOnce() -> Result<String, E>,
    reason_phrase: &str,
) -> Result<SigningResponseAction, E> {
    if let Some(action) = response_without_body(operation, status) {
        return Ok(match action {
            SigningResponseAction::Continue => SigningResponseAction::Continue,
            SigningResponseAction::NotFound => SigningResponseAction::NotFound,
            SigningResponseAction::Error(points) => {
                SigningResponseAction::Error(scalar_points(points))
            }
        });
    }
    let payload = json_payload();
    operation_error_points(
        operation,
        status,
        payload.as_ref(),
        || response_text().map(|text| text.chars().map(u32::from).collect()),
        reason_phrase,
    )
    .map(|points| SigningResponseAction::Error(scalar_points(points)))
}

#[cfg(test)]
fn scalar_points(points: Vec<u32>) -> String {
    points
        .into_iter()
        .map(|point| char::from_u32(point).expect("scalar diagnostic compatibility input"))
        .collect()
}

pub(crate) fn response_without_body(
    operation: SigningOperation,
    status: u16,
) -> Option<SigningResponseAction<Vec<u32>>> {
    if status == 404 && operation != SigningOperation::Sign {
        return Some(SigningResponseAction::NotFound);
    }
    if status == 401 {
        return Some(SigningResponseAction::Error(
            "Internal signing API rejected the service API key"
                .chars()
                .map(u32::from)
                .collect(),
        ));
    }
    if status < 400 {
        return Some(SigningResponseAction::Continue);
    }
    None
}

pub(crate) fn operation_error_points<V: PythonValueView, E>(
    operation: SigningOperation,
    status: u16,
    payload: Option<V>,
    response_text: impl FnOnce() -> Result<Vec<u32>, E>,
    reason_phrase: &str,
) -> Result<Vec<u32>, E> {
    let detail = error_detail_points(payload, response_text, reason_phrase)?;
    let prefix = match operation {
        SigningOperation::Context => "DID issuer context resolution failed",
        SigningOperation::Resolve => "Issuer DID resolution failed",
        SigningOperation::Sign => "DID-mediated signing failed",
    };
    Ok(format!("{prefix} (HTTP {status}): ")
        .chars()
        .map(u32::from)
        .chain(detail)
        .collect())
}
