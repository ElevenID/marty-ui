//! Organization- and flow-bound private-key envelopes backed by OpenBao Transit.

use std::time::Duration;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use thiserror::Error;

const SCHEMA: &str = "marty.flow-key-envelope/v1";
const PURPOSE: &str = "oid4vp_response_decryption";
const KEY_ID: &str = "flow-response-envelope-marty-aes256";
const MAX_PLAINTEXT_BYTES: usize = 16_384;
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct OpenBaoEnvelopeProvider {
    endpoint: String,
    token: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
pub struct WrapRequest {
    pub organization_id: String,
    pub flow_instance_id: String,
    pub plaintext_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct UnwrapRequest {
    pub organization_id: String,
    pub flow_instance_id: String,
    pub ciphertext: String,
}

#[derive(Debug, Error)]
pub enum FlowEnvelopeError {
    #[error("Invalid internal signing API key.")]
    Unauthorized,
    #[error("flow_instance_id and plaintext_b64 are required.")]
    MissingWrapInput,
    #[error("plaintext_b64 is invalid.")]
    InvalidPlaintext,
    #[error("Flow key material has an invalid size.")]
    InvalidPlaintextSize,
    #[error("flow_instance_id and KMS ciphertext are required.")]
    MissingUnwrapInput,
    #[error("KMS flow-key wrapping failed.")]
    WrapFailed,
    #[error("KMS returned an invalid flow-key envelope.")]
    InvalidCiphertextResponse,
    #[error("KMS flow-key envelope could not be decrypted.")]
    DecryptFailed,
    #[error("KMS flow-key envelope binding does not match this flow.")]
    BindingMismatch,
    #[error("KMS flow-key provider is unavailable.")]
    Unavailable,
}

impl IntoResponse for FlowEnvelopeError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::MissingWrapInput
            | Self::InvalidPlaintext
            | Self::InvalidPlaintextSize
            | Self::MissingUnwrapInput => StatusCode::UNPROCESSABLE_ENTITY,
            Self::DecryptFailed => StatusCode::BAD_REQUEST,
            Self::BindingMismatch => StatusCode::CONFLICT,
            Self::WrapFailed | Self::InvalidCiphertextResponse | Self::Unavailable => {
                StatusCode::SERVICE_UNAVAILABLE
            }
        };
        (status, Json(json!({"detail": self.to_string()}))).into_response()
    }
}

impl OpenBaoEnvelopeProvider {
    pub fn new(endpoint: impl Into<String>, token: impl Into<String>) -> Result<Self, String> {
        let endpoint = endpoint.into().trim_end_matches('/').to_owned();
        let token = token.into();
        let url = reqwest::Url::parse(&endpoint)
            .map_err(|error| format!("BAO_ADDR is invalid: {error}"))?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || token.trim().is_empty()
        {
            return Err("OpenBao envelope provider configuration is invalid".into());
        }
        Ok(Self {
            endpoint,
            token,
            client: Client::new(),
        })
    }

    pub async fn wrap(&self, request: WrapRequest) -> Result<Value, FlowEnvelopeError> {
        let envelope = prepare_envelope(&request)?;
        let response = self
            .post(
                &format!("/v1/transit/encrypt/{KEY_ID}"),
                json!({"plaintext": STANDARD.encode(envelope)}),
            )
            .await
            .map_err(|_| FlowEnvelopeError::WrapFailed)?;
        let ciphertext = response
            .pointer("/data/ciphertext")
            .and_then(Value::as_str)
            .filter(|value| value.starts_with("vault:"))
            .ok_or(FlowEnvelopeError::InvalidCiphertextResponse)?;
        Ok(json!({
            "schema": SCHEMA,
            "flow_instance_id": request.flow_instance_id.trim(),
            "ciphertext": ciphertext
        }))
    }

    pub async fn unwrap(&self, request: UnwrapRequest) -> Result<Value, FlowEnvelopeError> {
        validate_unwrap_request(&request)?;
        let response = self
            .post(
                &format!("/v1/transit/decrypt/{KEY_ID}"),
                json!({"ciphertext": request.ciphertext.trim()}),
            )
            .await
            .map_err(|_| FlowEnvelopeError::DecryptFailed)?;
        let plaintext = response
            .pointer("/data/plaintext")
            .and_then(Value::as_str)
            .ok_or(FlowEnvelopeError::DecryptFailed)
            .and_then(|value| {
                STANDARD
                    .decode(value)
                    .map_err(|_| FlowEnvelopeError::DecryptFailed)
            })?;
        validate_envelope(&request, &plaintext)
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value, reqwest::Error> {
        self.client
            .post(format!("{}{path}", self.endpoint))
            .timeout(TIMEOUT)
            .header("X-Vault-Token", &self.token)
            .header("accept", "application/json")
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
    }
}

pub fn prepare_envelope(request: &WrapRequest) -> Result<Vec<u8>, FlowEnvelopeError> {
    let flow_instance_id = request.flow_instance_id.trim();
    let plaintext_b64 = request.plaintext_b64.trim();
    if request.organization_id.trim().is_empty()
        || flow_instance_id.is_empty()
        || plaintext_b64.is_empty()
    {
        return Err(FlowEnvelopeError::MissingWrapInput);
    }
    let plaintext = decode_urlsafe(plaintext_b64)?;
    if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(FlowEnvelopeError::InvalidPlaintextSize);
    }
    serde_json::to_vec(&json!({
        "schema": SCHEMA,
        "organization_id": request.organization_id,
        "flow_instance_id": flow_instance_id,
        "purpose": PURPOSE,
        "plaintext_b64": plaintext_b64
    }))
    .map_err(|_| FlowEnvelopeError::InvalidPlaintext)
}

pub fn validate_envelope(
    request: &UnwrapRequest,
    plaintext: &[u8],
) -> Result<Value, FlowEnvelopeError> {
    let envelope: Value =
        serde_json::from_slice(plaintext).map_err(|_| FlowEnvelopeError::DecryptFailed)?;
    if envelope.get("schema").and_then(Value::as_str) != Some(SCHEMA)
        || envelope.get("organization_id").and_then(Value::as_str)
            != Some(request.organization_id.as_str())
        || envelope.get("flow_instance_id").and_then(Value::as_str)
            != Some(request.flow_instance_id.trim())
        || envelope.get("purpose").and_then(Value::as_str) != Some(PURPOSE)
        || envelope
            .get("plaintext_b64")
            .and_then(Value::as_str)
            .is_none()
    {
        return Err(FlowEnvelopeError::BindingMismatch);
    }
    Ok(json!({
        "schema": SCHEMA,
        "flow_instance_id": request.flow_instance_id.trim(),
        "plaintext_b64": envelope["plaintext_b64"]
    }))
}

fn validate_unwrap_request(request: &UnwrapRequest) -> Result<(), FlowEnvelopeError> {
    if request.organization_id.trim().is_empty()
        || request.flow_instance_id.trim().is_empty()
        || !request.ciphertext.trim().starts_with("vault:")
    {
        return Err(FlowEnvelopeError::MissingUnwrapInput);
    }
    Ok(())
}

fn decode_urlsafe(value: &str) -> Result<Vec<u8>, FlowEnvelopeError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .map_err(|_| FlowEnvelopeError::InvalidPlaintext)
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct Contract {
        schema_version: u8,
        organization_id: String,
        flow_instance_id: String,
        plaintext_b64: String,
        ciphertext: String,
        unwrap_response: Value,
        binding_mismatch_status: u16,
        maximum_plaintext_bytes: usize,
        invalid_plaintext_status: u16,
    }

    fn contract() -> Contract {
        serde_json::from_str(include_str!(
            "../../../../contracts/gateway-flow-key-envelope-behavior.json"
        ))
        .expect("flow envelope contract")
    }

    #[test]
    fn envelope_round_trip_preserves_exact_binding_and_payload() {
        let contract = contract();
        assert_eq!(contract.schema_version, 1);
        assert_eq!(contract.binding_mismatch_status, 409);
        assert_eq!(contract.invalid_plaintext_status, 422);
        assert_eq!(contract.maximum_plaintext_bytes, MAX_PLAINTEXT_BYTES);
        let wrap = WrapRequest {
            organization_id: contract.organization_id.clone(),
            flow_instance_id: contract.flow_instance_id.clone(),
            plaintext_b64: contract.plaintext_b64.clone(),
        };
        let envelope = prepare_envelope(&wrap).expect("envelope");
        let request = UnwrapRequest {
            organization_id: contract.organization_id.clone(),
            flow_instance_id: contract.flow_instance_id.clone(),
            ciphertext: contract.ciphertext,
        };
        assert_eq!(
            validate_envelope(&request, &envelope).expect("valid binding"),
            contract.unwrap_response
        );
        let wrong_tenant = UnwrapRequest {
            organization_id: "org-2".into(),
            ..request
        };
        assert!(matches!(
            validate_envelope(&wrong_tenant, &envelope),
            Err(FlowEnvelopeError::BindingMismatch)
        ));
    }

    #[test]
    fn malformed_and_oversized_plaintext_fail_closed() {
        for plaintext_b64 in ["%%%".into(), URL_SAFE_NO_PAD.encode([])] {
            assert!(prepare_envelope(&WrapRequest {
                organization_id: "org-1".into(),
                flow_instance_id: "flow-1".into(),
                plaintext_b64,
            })
            .is_err());
        }
        assert!(matches!(
            prepare_envelope(&WrapRequest {
                organization_id: "org-1".into(),
                flow_instance_id: "flow-1".into(),
                plaintext_b64: URL_SAFE_NO_PAD.encode(vec![0; MAX_PLAINTEXT_BYTES + 1]),
            }),
            Err(FlowEnvelopeError::InvalidPlaintextSize)
        ));
    }
}
