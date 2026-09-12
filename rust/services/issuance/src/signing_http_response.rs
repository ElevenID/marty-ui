//! One HTTP error-response owner for signing, issuer context and proof policy.
//! Diagnostics remain lossless until an explicitly unmasked scalar renderer.
//! Debug/Display never expose remote diagnostic material. This module does not
//! choose public privacy policy, routes, cryptography or success validation.

use reqwest::Response;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{
    canvas_content_decoder::CanvasContentDecoder,
    canvas_response_text::{response_text, CanvasResponseTextError},
    lossless_json_tree::{JsonNode, JsonTree},
    python_text::PythonText,
    python_value::{float, PythonValueNode, PythonValueView},
    signing_error_detail::{
        operation_error_points, response_without_body, SigningOperation, SigningResponseAction,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SigningExceptionClass {
    Runtime,
    Unicode,
    Value,
    Type,
    Json,
    ResponseRead,
}

/// Public only because public credential errors carry this typed cause. Access
/// to the actual diagnostic remains crate-private and opt-in, never Display.
#[derive(Clone, PartialEq, Eq)]
pub struct SigningResponseFailure {
    operation: SigningOperation,
    class: SigningExceptionClass,
    diagnostic: PythonText,
}

impl std::fmt::Debug for SigningResponseFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SigningResponseFailure")
            .field("operation", &self.operation)
            .field("class", &self.class)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for SigningResponseFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Remote signing response unavailable")
    }
}
impl std::error::Error for SigningResponseFailure {}

impl SigningResponseFailure {
    fn new(
        operation: SigningOperation,
        class: SigningExceptionClass,
        diagnostic: Vec<u32>,
    ) -> Self {
        Self {
            operation,
            class,
            diagnostic: PythonText::from_codepoints(diagnostic).expect("decoded Python codepoints"),
        }
    }
    pub(crate) fn is_runtime(&self) -> bool {
        self.class == SigningExceptionClass::Runtime
    }
    pub(crate) fn is_signing(&self) -> bool {
        self.operation == SigningOperation::Sign
    }
    pub(crate) fn scalar_detail(&self) -> Option<&str> {
        self.diagnostic.as_scalar()
    }
    /// Explicit existing credential/gRPC text projection, never implicit logging.
    pub(crate) fn credential_detail(&self) -> Option<String> {
        self.scalar_detail().map(|detail| {
            format!(
                "{}: {detail}",
                if self.is_signing() {
                    "credential signing is unavailable"
                } else {
                    "issuer identity is unavailable"
                }
            )
        })
    }

    fn text(operation: SigningOperation, error: CanvasResponseTextError) -> Self {
        let class = match error {
            CanvasResponseTextError::InternalCodec => SigningExceptionClass::Runtime,
            CanvasResponseTextError::Utf16MissingBom
            | CanvasResponseTextError::Utf32MissingBom
            | CanvasResponseTextError::PendingBufferOverflow => SigningExceptionClass::Unicode,
            CanvasResponseTextError::ContinuationOrdinalLimit { .. }
            | CanvasResponseTextError::EmbeddedNullEncoding => SigningExceptionClass::Value,
            CanvasResponseTextError::NumberedAfterBareContinuation
            | CanvasResponseTextError::BareAfterNumberedContinuation => SigningExceptionClass::Type,
        };
        Self::new(
            operation,
            class,
            error.to_string().chars().map(u32::from).collect(),
        )
    }

    fn response_read(operation: SigningOperation) -> Self {
        Self::new(
            operation,
            SigningExceptionClass::ResponseRead,
            "Signing response could not be read"
                .chars()
                .map(u32::from)
                .collect(),
        )
    }
}

#[derive(Clone, Copy)]
enum DiagnosticValue<'a> {
    Scalar(&'a Value),
    Tree(&'a JsonTree, usize),
}

impl PythonValueView for DiagnosticValue<'_> {
    fn truthy(self) -> bool {
        match self {
            Self::Scalar(value) => value.truthy(),
            Self::Tree(tree, id) => match tree.node(id) {
                JsonNode::Scalar(value) => value.truthy(),
                JsonNode::Text(value) => value.codepoints().next().is_some(),
                JsonNode::Float(value) => *value != 0.0,
                JsonNode::Array(values) => !values.is_empty(),
                JsonNode::Object(values) => !values.is_empty(),
            },
        }
    }
    fn view(self) -> PythonValueNode<Self> {
        let Self::Tree(tree, id) = self else {
            let Self::Scalar(value) = self else {
                unreachable!()
            };
            return value.view().map(Self::Scalar);
        };
        match tree.node(id) {
            JsonNode::Scalar(value) => Self::Scalar(value).view(),
            JsonNode::Text(text) => PythonValueNode::Text(text.codepoints().collect()),
            JsonNode::Float(value) => PythonValueNode::Number {
                representation: float(*value),
                zero: *value == 0.0,
            },
            JsonNode::Array(values) => {
                PythonValueNode::Array(values.iter().map(|id| Self::Tree(tree, *id)).collect())
            }
            JsonNode::Object(values) => PythonValueNode::Object(
                values
                    .iter()
                    .map(|(key, id)| (key.codepoints().collect(), Self::Tree(tree, *id)))
                    .collect(),
            ),
        }
    }
}

pub(crate) enum SigningHttpResponse {
    Continue(Response),
    NotFound,
}

pub(crate) async fn classify(
    mut response: Response,
    operation: SigningOperation,
) -> Result<SigningHttpResponse, SigningResponseFailure> {
    let status = response.status();
    if let Some(action) = response_without_body(operation, status.as_u16()) {
        return match action {
            SigningResponseAction::Continue => Ok(SigningHttpResponse::Continue(response)),
            SigningResponseAction::NotFound => Ok(SigningHttpResponse::NotFound),
            SigningResponseAction::Error(diagnostic) => Err(SigningResponseFailure::new(
                operation,
                SigningExceptionClass::Runtime,
                diagnostic,
            )),
        };
    }
    let content_types: Vec<String> = response
        .headers()
        .get_all(http::header::CONTENT_TYPE)
        .iter()
        .map(|value| {
            value
                .as_bytes()
                .iter()
                .map(|byte| char::from(*byte))
                .collect()
        })
        .collect();
    let content_type = (!content_types.is_empty()).then(|| content_types.join(", "));
    let mut decoders = CanvasContentDecoder::from_headers(response.headers());
    let mut body = Vec::new();
    loop {
        let chunk = response
            .chunk()
            .await
            .map_err(|_| SigningResponseFailure::response_read(operation))?;
        let finished = chunk.is_none();
        let mut decoded = chunk.unwrap_or_default().to_vec();
        for decoder in &mut decoders {
            decoded = decoder
                .decode(&decoded)
                .map_err(|_| SigningResponseFailure::response_read(operation))?;
        }
        body.extend(decoded);
        if finished {
            break;
        }
    }
    // JSON byte detection/parsing is independent of charset text decoding. A
    // rejected JSON payload follows Python's ValueError fallback, not a lossy
    // conversion of successfully parsed non-scalar values.
    let payload = JsonTree::from_response_bytes(&body);
    let detail = operation_error_points(
        operation,
        status.as_u16(),
        payload
            .as_ref()
            .map(|tree| DiagnosticValue::Tree(tree, tree.root())),
        || {
            response_text(&body, content_type.as_deref())
                .map(|text| text.codepoints().collect())
                .map_err(|error| SigningResponseFailure::text(operation, error))
        },
        status.canonical_reason().unwrap_or(""),
    )?;
    Err(SigningResponseFailure::new(
        operation,
        SigningExceptionClass::Runtime,
        detail,
    ))
}

/// Preserve each caller's existing scalar success DTO/parser. Only the error
/// classification is shared; no validation, identity or private-selector checks
/// are performed or bypassed by this response adapter.
pub(crate) async fn success_json<T: DeserializeOwned>(
    response: Response,
    operation: SigningOperation,
) -> Result<T, SigningResponseFailure> {
    response.json().await.map_err(|error| {
        let prefix = match operation {
            SigningOperation::Sign => "DID-mediated signer returned invalid JSON",
            SigningOperation::Context | SigningOperation::Resolve => {
                "DID issuer context returned invalid JSON"
            }
        };
        SigningResponseFailure::new(
            operation,
            SigningExceptionClass::Json,
            format!("{prefix}: {}", error.without_url())
                .chars()
                .map(u32::from)
                .collect(),
        )
    })
}

#[cfg(test)]
#[path = "signing_http_response_tests.rs"]
pub(crate) mod tests;
