//! Shared protocol primitives, without conflating validation and delivery policy.
use crate::http_response_text::{response_text, HttpResponseTextError};
use crate::lossless_json::{LosslessJson, LosslessObject};
pub(crate) use marty_response_compat::canvas_response_json as response_json;

pub(crate) const MAX_EXCERPT_CHARS: usize = 1_000;

/// Preserve the published ordered assignments without imposing a transport
/// range. Runtime Duration adoption remains a separate consumer constraint.
/// Projection follows complete body consumption. Only text excerpts are bounded;
/// valid JSON objects/scalars must not silently lose fields at an I/O buffer size.
pub(crate) fn response_excerpt(
    bytes: &[u8],
    content_type: Option<&str>,
) -> Result<LosslessJson, HttpResponseTextError> {
    if let Some(payload) = response_json::parse(bytes) {
        return Ok(match payload {
            LosslessJson::Parsed(ref tree) if tree.is_object() => payload,
            LosslessJson::PythonObject(_) => payload,
            payload => {
                LosslessJson::Object(LosslessObject::from_iter([("payload".into(), payload)]))
            }
        });
    }
    let text = response_text(bytes, content_type)?;
    Ok(LosslessJson::Object(LosslessObject::from_iter([(
        "body_excerpt".into(),
        LosslessJson::Text(truncate_text(&text)),
    )])))
}

pub(crate) fn truncate_text(
    text: &crate::python_text::PythonText,
) -> crate::python_text::PythonText {
    crate::python_text::PythonText::excerpt(text.codepoints(), MAX_EXCERPT_CHARS)
        .expect("decoded codepoints are valid")
}
