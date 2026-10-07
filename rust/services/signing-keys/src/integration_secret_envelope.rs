//! Purpose-bound integration-secret storage using a dedicated Transit key.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

use crate::flow_envelope::OpenBaoEnvelopeProvider;

const SCHEMA: &str = "marty.integration-secret-envelope/v1";
const KEY_ID: &str = "integration-secret-envelope-marty-aes256";
const MAX_SECRET_BYTES: usize = 64 * 1024;
const MAX_ENVELOPE_BYTES: usize = 96 * 1024;
const MAX_CIPHERTEXT_BYTES: usize = 200 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptRequest {
    pub organization_id: String,
    pub secret_id: String,
    pub provider: String,
    pub purpose: String,
    pub plaintext_b64: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecryptRequest {
    pub organization_id: String,
    pub secret_id: String,
    pub provider: String,
    pub purpose: String,
    pub envelope: Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredEnvelope {
    schema: String,
    ciphertext: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BoundSecret {
    schema: String,
    organization_id: String,
    secret_id: String,
    provider: String,
    purpose: String,
    plaintext_b64: String,
}

#[derive(Debug, Error)]
pub enum IntegrationSecretEnvelopeError {
    #[error("Invalid internal signing API key.")]
    Unauthorized,
    #[error("Integration-secret identity or value is invalid.")]
    InvalidSecret,
    #[error("Integration-secret envelope is invalid.")]
    InvalidEnvelope,
    #[error("Integration-secret envelope binding does not match this secret.")]
    BindingMismatch,
    #[error("KMS integration-secret encryption failed.")]
    EncryptFailed,
    #[error("KMS integration-secret decryption failed.")]
    DecryptFailed,
    #[error("KMS integration-secret provider is unavailable.")]
    Unavailable,
}

impl IntoResponse for IntegrationSecretEnvelopeError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::InvalidSecret | Self::InvalidEnvelope => StatusCode::UNPROCESSABLE_ENTITY,
            Self::BindingMismatch => StatusCode::CONFLICT,
            Self::EncryptFailed | Self::DecryptFailed | Self::Unavailable => {
                StatusCode::SERVICE_UNAVAILABLE
            }
        };
        (status, Json(json!({"detail": self.to_string()}))).into_response()
    }
}

fn valid_identity(organization_id: &str, secret_id: &str, provider: &str, purpose: &str) -> bool {
    [organization_id, secret_id, provider, purpose]
        .iter()
        .all(|part| !part.trim().is_empty())
        && organization_id.len() <= 256
        && secret_id.len() <= 256
        && provider.len() <= 80
        && purpose.len() <= 80
}

fn prepare(request: &EncryptRequest) -> Result<Vec<u8>, IntegrationSecretEnvelopeError> {
    if !valid_identity(
        &request.organization_id,
        &request.secret_id,
        &request.provider,
        &request.purpose,
    ) || request.plaintext_b64.len() > MAX_SECRET_BYTES.div_ceil(3) * 4
    {
        return Err(IntegrationSecretEnvelopeError::InvalidSecret);
    }
    let plaintext = STANDARD
        .decode(&request.plaintext_b64)
        .map_err(|_| IntegrationSecretEnvelopeError::InvalidSecret)?;
    if plaintext.len() > MAX_SECRET_BYTES {
        return Err(IntegrationSecretEnvelopeError::InvalidSecret);
    }
    serde_json::to_vec(&BoundSecret {
        schema: SCHEMA.into(),
        organization_id: request.organization_id.clone(),
        secret_id: request.secret_id.clone(),
        provider: request.provider.clone(),
        purpose: request.purpose.clone(),
        plaintext_b64: STANDARD.encode(plaintext),
    })
    .map_err(|_| IntegrationSecretEnvelopeError::InvalidSecret)
}

fn validate(
    request: &DecryptRequest,
    plaintext: &[u8],
) -> Result<Value, IntegrationSecretEnvelopeError> {
    if plaintext.len() > MAX_ENVELOPE_BYTES {
        return Err(IntegrationSecretEnvelopeError::DecryptFailed);
    }
    let bound: BoundSecret = serde_json::from_slice(plaintext)
        .map_err(|_| IntegrationSecretEnvelopeError::DecryptFailed)?;
    if bound.schema != SCHEMA
        || bound.organization_id != request.organization_id
        || bound.secret_id != request.secret_id
        || bound.provider != request.provider
        || bound.purpose != request.purpose
    {
        return Err(IntegrationSecretEnvelopeError::BindingMismatch);
    }
    let secret = STANDARD
        .decode(bound.plaintext_b64)
        .map_err(|_| IntegrationSecretEnvelopeError::DecryptFailed)?;
    if secret.len() > MAX_SECRET_BYTES {
        return Err(IntegrationSecretEnvelopeError::DecryptFailed);
    }
    Ok(json!({"plaintext_b64": STANDARD.encode(secret)}))
}

fn ciphertext(request: &DecryptRequest) -> Result<String, IntegrationSecretEnvelopeError> {
    if !valid_identity(
        &request.organization_id,
        &request.secret_id,
        &request.provider,
        &request.purpose,
    ) {
        return Err(IntegrationSecretEnvelopeError::InvalidSecret);
    }
    let envelope: StoredEnvelope = serde_json::from_value(request.envelope.clone())
        .map_err(|_| IntegrationSecretEnvelopeError::InvalidEnvelope)?;
    if envelope.schema != SCHEMA
        || !envelope.ciphertext.starts_with("vault:v")
        || envelope.ciphertext.len() > MAX_CIPHERTEXT_BYTES
    {
        return Err(IntegrationSecretEnvelopeError::InvalidEnvelope);
    }
    Ok(envelope.ciphertext)
}

pub async fn encrypt(
    provider: &OpenBaoEnvelopeProvider,
    request: EncryptRequest,
) -> Result<Value, IntegrationSecretEnvelopeError> {
    let plaintext = prepare(&request)?;
    require_non_exportable_key(provider).await?;
    let response = provider
        .post(
            &format!("/v1/transit/encrypt/{KEY_ID}"),
            json!({"plaintext": STANDARD.encode(plaintext)}),
        )
        .await
        .map_err(|_| IntegrationSecretEnvelopeError::EncryptFailed)?;
    let ciphertext = response
        .pointer("/data/ciphertext")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("vault:v") && value.len() <= MAX_CIPHERTEXT_BYTES)
        .ok_or(IntegrationSecretEnvelopeError::EncryptFailed)?;
    Ok(json!(StoredEnvelope {
        schema: SCHEMA.into(),
        ciphertext: ciphertext.into(),
    }))
}

pub async fn decrypt(
    provider: &OpenBaoEnvelopeProvider,
    request: DecryptRequest,
) -> Result<Value, IntegrationSecretEnvelopeError> {
    let ciphertext = ciphertext(&request)?;
    require_non_exportable_key(provider).await?;
    let response = provider
        .post(
            &format!("/v1/transit/decrypt/{KEY_ID}"),
            json!({"ciphertext": ciphertext}),
        )
        .await
        .map_err(|_| IntegrationSecretEnvelopeError::DecryptFailed)?;
    let plaintext = response
        .pointer("/data/plaintext")
        .and_then(Value::as_str)
        .ok_or(IntegrationSecretEnvelopeError::DecryptFailed)
        .and_then(|value| {
            STANDARD
                .decode(value)
                .map_err(|_| IntegrationSecretEnvelopeError::DecryptFailed)
        })?;
    validate(&request, &plaintext)
}

async fn require_non_exportable_key(
    provider: &OpenBaoEnvelopeProvider,
) -> Result<(), IntegrationSecretEnvelopeError> {
    let metadata = provider
        .get(&format!("/v1/transit/keys/{KEY_ID}"))
        .await
        .map_err(|_| IntegrationSecretEnvelopeError::Unavailable)?;
    if !non_exportable_aes256_key(&metadata) {
        return Err(IntegrationSecretEnvelopeError::Unavailable);
    }
    Ok(())
}

fn non_exportable_aes256_key(metadata: &Value) -> bool {
    metadata.pointer("/data/type").and_then(Value::as_str) == Some("aes256-gcm96")
        && metadata
            .pointer("/data/exportable")
            .and_then(Value::as_bool)
            == Some(false)
        && metadata
            .pointer("/data/allow_plaintext_backup")
            .and_then(Value::as_bool)
            == Some(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> EncryptRequest {
        EncryptRequest {
            organization_id: "org-1".into(),
            secret_id: "secret-1".into(),
            provider: "canvas".into(),
            purpose: "oauth_client_secret".into(),
            plaintext_b64: STANDARD.encode("test-secret"),
        }
    }

    #[test]
    fn decrypted_value_is_bound_to_all_four_identity_fields() {
        let input = request();
        let bound = prepare(&input).unwrap();
        let mut decrypt = DecryptRequest {
            organization_id: input.organization_id,
            secret_id: input.secret_id,
            provider: input.provider,
            purpose: input.purpose,
            envelope: json!({"schema": SCHEMA, "ciphertext": "vault:v1:synthetic"}),
        };
        assert_eq!(
            validate(&decrypt, &bound).unwrap(),
            json!({"plaintext_b64": STANDARD.encode("test-secret")})
        );
        for changed in ["organization", "id", "provider", "purpose"] {
            match changed {
                "organization" => decrypt.organization_id = "org-2".into(),
                "id" => decrypt.secret_id = "secret-2".into(),
                "provider" => decrypt.provider = "other".into(),
                _ => decrypt.purpose = "other".into(),
            }
            assert!(matches!(
                validate(&decrypt, &bound),
                Err(IntegrationSecretEnvelopeError::BindingMismatch)
            ));
            decrypt.organization_id = "org-1".into();
            decrypt.secret_id = "secret-1".into();
            decrypt.provider = "canvas".into();
            decrypt.purpose = "oauth_client_secret".into();
        }
    }

    #[test]
    fn invalid_value_and_envelope_are_rejected() {
        let mut input = request();
        input.plaintext_b64 = "%%%".into();
        assert!(prepare(&input).is_err());
        input.plaintext_b64 = STANDARD.encode(vec![0; MAX_SECRET_BYTES + 1]);
        assert!(prepare(&input).is_err());
        let mut decrypt = DecryptRequest {
            organization_id: "org-1".into(),
            secret_id: "secret-1".into(),
            provider: "canvas".into(),
            purpose: "oauth_client_secret".into(),
            envelope: json!({"schema": SCHEMA, "ciphertext": "vault:v1:synthetic"}),
        };
        assert_eq!(ciphertext(&decrypt).unwrap(), "vault:v1:synthetic");
        for invalid in [
            json!({"schema": "unknown", "ciphertext": "vault:v1:synthetic"}),
            json!({"schema": SCHEMA, "ciphertext": "raw-key"}),
            json!({"schema": SCHEMA, "ciphertext": "vault:v1:synthetic", "key": "private"}),
        ] {
            decrypt.envelope = invalid;
            assert!(matches!(
                ciphertext(&decrypt),
                Err(IntegrationSecretEnvelopeError::InvalidEnvelope)
            ));
        }
    }

    #[test]
    fn key_metadata_must_prove_non_exportable_aes() {
        let valid = json!({"data": {
            "type": "aes256-gcm96", "exportable": false,
            "allow_plaintext_backup": false
        }});
        assert!(non_exportable_aes256_key(&valid));
        for changed in [
            json!({"data": {"type": "aes256-gcm96", "exportable": true, "allow_plaintext_backup": false}}),
            json!({"data": {"type": "aes256-gcm96", "exportable": false, "allow_plaintext_backup": true}}),
            json!({"data": {"type": "ecdsa-p256", "exportable": false, "allow_plaintext_backup": false}}),
            json!({"data": {"type": "aes256-gcm96", "exportable": false}}),
        ] {
            assert!(!non_exportable_aes256_key(&changed));
        }
    }
}
