//! Single owner for the three Canvas Credentials URL helpers inherited from
//! the Python service. Formatting, eager quoting, defaults and diagnostics are
//! replayed from the frozen language-neutral contract.

use crate::{
    python_format::{format_named, PythonFormatError, PythonFormatErrorKind},
    python_text::PythonText,
    python_value::strip_points,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanvasUrlErrorKind {
    KeyError,
    IndexError,
    ValueError,
    TypeError,
    AttributeError,
    UnicodeEncodeError,
    RuntimeError,
    UnmodeledCapability,
    ResourceFailure,
}

impl CanvasUrlErrorKind {
    #[cfg(test)]
    pub(crate) fn class_name(self) -> &'static str {
        match self {
            Self::KeyError => "KeyError",
            Self::IndexError => "IndexError",
            Self::ValueError => "ValueError",
            Self::TypeError => "TypeError",
            Self::AttributeError => "AttributeError",
            Self::UnicodeEncodeError => "UnicodeEncodeError",
            Self::RuntimeError => "RuntimeError",
            Self::UnmodeledCapability => "UnmodeledCapability",
            Self::ResourceFailure => "ResourceFailure",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanvasUrlError {
    kind: CanvasUrlErrorKind,
    message: PythonText,
}

impl CanvasUrlError {
    #[cfg(test)]
    pub(crate) fn kind(&self) -> CanvasUrlErrorKind {
        self.kind
    }

    #[cfg(test)]
    pub(crate) fn message(&self) -> &PythonText {
        &self.message
    }

    pub(crate) fn scalar_message(&self) -> &str {
        self.message
            .as_scalar()
            .unwrap_or("Canvas URL error contains non-scalar text")
    }

    pub(crate) fn into_scalar_message(self) -> Result<String, PythonText> {
        self.message.into_scalar()
    }
}

impl From<PythonFormatError> for CanvasUrlError {
    fn from(error: PythonFormatError) -> Self {
        let kind = match error.kind() {
            PythonFormatErrorKind::KeyError => CanvasUrlErrorKind::KeyError,
            PythonFormatErrorKind::IndexError => CanvasUrlErrorKind::IndexError,
            PythonFormatErrorKind::ValueError => CanvasUrlErrorKind::ValueError,
            PythonFormatErrorKind::TypeError => CanvasUrlErrorKind::TypeError,
            PythonFormatErrorKind::AttributeError => CanvasUrlErrorKind::AttributeError,
            PythonFormatErrorKind::UnmodeledCapability => CanvasUrlErrorKind::UnmodeledCapability,
            PythonFormatErrorKind::ResourceFailure => CanvasUrlErrorKind::ResourceFailure,
        };
        Self {
            kind,
            message: error.message().clone(),
        }
    }
}

fn error(kind: CanvasUrlErrorKind, message: impl Into<String>) -> CanvasUrlError {
    CanvasUrlError {
        kind,
        message: message.into().into(),
    }
}

fn text(points: impl IntoIterator<Item = u32>) -> PythonText {
    PythonText::from_codepoints(points).expect("existing Python codepoints")
}

fn stripped(template: Option<&PythonText>) -> Option<PythonText> {
    let points: Vec<_> = template?.codepoints().collect();
    let points = strip_points(&points);
    (!points.is_empty()).then(|| text(points.iter().copied()))
}

fn quote(value: Option<&PythonText>) -> Result<PythonText, CanvasUrlError> {
    let Some(value) = value else {
        return Err(error(
            CanvasUrlErrorKind::TypeError,
            "quote_from_bytes() expected bytes",
        ));
    };
    let points: Vec<_> = value.codepoints().collect();
    if let Some(start) = points
        .iter()
        .position(|point| (0xd800..=0xdfff).contains(point))
    {
        let end = points[start..]
            .iter()
            .position(|point| !(0xd800..=0xdfff).contains(point))
            .map_or(points.len(), |offset| start + offset);
        let message = if end == start + 1 {
            format!(
                "'utf-8' codec can't encode character '\\u{:04x}' in position {start}: surrogates not allowed",
                points[start]
            )
        } else {
            format!(
                "'utf-8' codec can't encode characters in position {start}-{}: surrogates not allowed",
                end - 1
            )
        };
        return Err(error(CanvasUrlErrorKind::UnicodeEncodeError, message));
    }
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::new();
    for point in points {
        let character = char::from_u32(point).expect("surrogates rejected above");
        if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '~') {
            output.push(character);
            continue;
        }
        let mut encoded = [0; 4];
        for byte in character.encode_utf8(&mut encoded).bytes() {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    Ok(output.into())
}

fn concatenate(parts: &[&PythonText], literals: &[&str]) -> PythonText {
    debug_assert!(parts.len() == literals.len() || parts.len() == literals.len() + 1);
    let mut points = Vec::new();
    for (index, part) in parts.iter().enumerate() {
        points.extend(part.codepoints());
        if let Some(literal) = literals.get(index) {
            points.extend(literal.chars().map(u32::from));
        }
    }
    text(points)
}

fn empty_when_false(value: Option<&PythonText>) -> PythonText {
    value
        .filter(|value| value.codepoints().next().is_some())
        .cloned()
        .unwrap_or_default()
}

pub(crate) fn assertion_url(
    template: Option<&PythonText>,
    api_base_url: &PythonText,
    scope: &PythonText,
    badgeclass_id: Option<&PythonText>,
    issuer_id: Option<&PythonText>,
) -> Result<PythonText, CanvasUrlError> {
    if let Some(template) = stripped(template) {
        // Python evaluates all keyword arguments before str.format, including
        // fields the selected template never references.
        let quoted_scope = quote(Some(scope))?;
        let quoted_badge = quote(badgeclass_id)?;
        let quoted_issuer = quote(Some(&empty_when_false(issuer_id)))?;
        return format_named(
            &template,
            &[
                ("api_base_url", api_base_url.clone()),
                ("scope", quoted_scope),
                ("badgeclass_id", quoted_badge),
                ("issuer_id", quoted_issuer),
            ],
        )
        .map_err(Into::into);
    }
    let selected = if scope.as_scalar() == Some("issuers") {
        issuer_id
    } else {
        badgeclass_id
    }
    .filter(|value| value.codepoints().next().is_some())
    .ok_or_else(|| {
        error(
            CanvasUrlErrorKind::RuntimeError,
            "CANVAS_CREDENTIALS_ISSUER_ID is required when assertion scope is 'issuers'",
        )
    })?;
    let quoted_scope = quote(Some(scope))?;
    let quoted_selected = quote(Some(selected))?;
    Ok(concatenate(
        &[api_base_url, &quoted_scope, &quoted_selected],
        &["/v2/", "/", "/assertions"],
    ))
}

pub(crate) fn validation_url(
    template: Option<&PythonText>,
    api_base_url: &PythonText,
    scope: &PythonText,
    badgeclass_id: Option<&PythonText>,
    issuer_id: Option<&PythonText>,
) -> Result<PythonText, CanvasUrlError> {
    if let Some(template) = stripped(template) {
        let quoted_scope = quote(Some(scope))?;
        let quoted_badge = quote(Some(&empty_when_false(badgeclass_id)))?;
        let quoted_issuer = quote(Some(&empty_when_false(issuer_id)))?;
        return format_named(
            &template,
            &[
                ("api_base_url", api_base_url.clone()),
                ("scope", quoted_scope),
                ("badgeclass_id", quoted_badge),
                ("issuer_id", quoted_issuer),
            ],
        )
        .map_err(Into::into);
    }
    let (selected, message) = if scope.as_scalar() == Some("issuers") {
        (
            issuer_id,
            "CANVAS_CREDENTIALS_ISSUER_ID is required when assertion scope is 'issuers'",
        )
    } else {
        (
            badgeclass_id,
            "CANVAS_CREDENTIALS_BADGECLASS_ID is required for Canvas Credentials validation",
        )
    };
    let selected = selected
        .filter(|value| value.codepoints().next().is_some())
        .ok_or_else(|| error(CanvasUrlErrorKind::RuntimeError, message))?;
    let quoted_scope = quote(Some(scope))?;
    let quoted_selected = quote(Some(selected))?;
    Ok(concatenate(
        &[api_base_url, &quoted_scope, &quoted_selected],
        &["/v2/", "/"],
    ))
}

pub(crate) fn revoke_url(
    template: Option<&PythonText>,
    api_base_url: &PythonText,
    external_credential_id: Option<&PythonText>,
) -> Result<PythonText, CanvasUrlError> {
    let quoted_identifier = quote(external_credential_id)?;
    if let Some(template) = stripped(template) {
        return format_named(
            &template,
            &[
                ("api_base_url", api_base_url.clone()),
                ("external_credential_id", quoted_identifier),
            ],
        )
        .map_err(Into::into);
    }
    Ok(concatenate(
        &[api_base_url, &quoted_identifier],
        &["/v2/assertions/"],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lossless_json_tree::{JsonNode, JsonTree};
    use serde_json::Value;

    fn member(tree: &JsonTree, id: usize, key: &str) -> usize {
        let JsonNode::Object(fields) = tree.node(id) else {
            panic!("object required")
        };
        fields
            .iter()
            .find(|(name, _)| name.as_scalar() == Some(key))
            .unwrap()
            .1
    }
    fn maybe_member(tree: &JsonTree, id: usize, key: &str) -> Option<usize> {
        let JsonNode::Object(fields) = tree.node(id) else {
            panic!("object required")
        };
        fields
            .iter()
            .find(|(name, _)| name.as_scalar() == Some(key))
            .map(|(_, id)| *id)
    }
    fn value_text(tree: &JsonTree, id: usize) -> Option<PythonText> {
        match tree.node(id) {
            JsonNode::Scalar(Value::Null) => None,
            JsonNode::Scalar(Value::String(value)) => Some(value.clone().into()),
            JsonNode::Text(value) => Some(value.clone()),
            _ => panic!("text or null required"),
        }
    }
    fn scalar(tree: &JsonTree, id: usize) -> String {
        value_text(tree, id).unwrap().into_scalar().unwrap()
    }
    fn array(tree: &JsonTree, id: usize) -> &[usize] {
        let JsonNode::Array(values) = tree.node(id) else {
            panic!("array required")
        };
        values
    }

    #[test]
    fn every_frozen_canvas_url_helper_case_matches_without_exclusions() {
        let cases = JsonTree::from_json_bytes(include_bytes!(
            "../../../../contracts/canvas-url-template-scenarios.json"
        ))
        .unwrap();
        let reference = JsonTree::from_json_bytes(include_bytes!(
            "../../../../contracts/canvas-url-template-python-reference.json"
        ))
        .unwrap();
        let inputs = array(&cases, member(&cases, cases.root(), "cases"));
        let observations = array(
            &reference,
            member(&reference, reference.root(), "observations"),
        );
        assert_eq!(inputs.len(), 123);
        assert_eq!(observations.len(), inputs.len());
        for (&input, &observation) in inputs.iter().zip(observations) {
            let id = scalar(&cases, member(&cases, input, "id"));
            assert_eq!(
                id,
                scalar(&reference, member(&reference, observation, "id"))
            );
            let operation = scalar(&cases, member(&cases, input, "operation"));
            let template = value_text(&cases, member(&cases, input, "template"));
            let args = member(&cases, input, "arguments");
            let argument =
                |name| maybe_member(&cases, args, name).and_then(|id| value_text(&cases, id));
            let base = argument("api_base_url").unwrap();
            let actual = match operation.as_str() {
                "assertion" => assertion_url(
                    template.as_ref(),
                    &base,
                    &argument("scope").unwrap(),
                    argument("badgeclass_id").as_ref(),
                    argument("issuer_id").as_ref(),
                ),
                "validation" => validation_url(
                    template.as_ref(),
                    &base,
                    &argument("scope").unwrap(),
                    argument("badgeclass_id").as_ref(),
                    argument("issuer_id").as_ref(),
                ),
                "revoke" => revoke_url(
                    template.as_ref(),
                    &base,
                    argument("external_credential_id").as_ref(),
                ),
                _ => panic!("unknown operation {operation}"),
            };
            if let Some(url) = maybe_member(&reference, observation, "url") {
                assert_eq!(actual, Ok(value_text(&reference, url).unwrap()), "{id}");
            } else {
                let expected = member(&reference, observation, "error");
                let actual = actual.expect_err(&id);
                assert_eq!(
                    actual.kind().class_name(),
                    scalar(&reference, member(&reference, expected, "type")),
                    "{id}"
                );
                assert_eq!(
                    actual.message(),
                    &value_text(&reference, member(&reference, expected, "message")).unwrap(),
                    "{id}"
                );
            }
        }
    }
}
