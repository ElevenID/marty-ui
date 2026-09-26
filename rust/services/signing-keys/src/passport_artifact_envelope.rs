//! KMS-held, tenant- and artifact-bound encryption of passport artifact chunks.
//! The issuance service never receives or stores a Transit key or data key.

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

const SCHEMA: &str = "marty.passport-artifact-chunk/v1";
const KEY_ID: &str = "passport-artifact-marty-aes256";
pub const MAX_CHUNK_BYTES: usize = 512 * 1024;
pub const MAX_CHUNKS: u32 = 4096;
const MAX_ENCODED_CHUNK_BYTES: usize = MAX_CHUNK_BYTES.div_ceil(3) * 4;
const MAX_ENVELOPE_BYTES: usize = MAX_ENCODED_CHUNK_BYTES + 1024;
const MAX_CIPHERTEXT_BYTES: usize = 2_000_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptChunkRequest {
    pub artifact_id: String,
    pub chunk_index: u32,
    pub chunk_count: u32,
    pub plaintext_b64: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecryptChunkRequest {
    pub artifact_id: String,
    pub chunk_index: u32,
    pub chunk_count: u32,
    pub ciphertext: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BoundChunk {
    schema: String,
    organization_id: String,
    artifact_id: String,
    chunk_index: u32,
    chunk_count: u32,
    plaintext_b64: String,
}

#[derive(Debug, Error)]
pub enum ArtifactEnvelopeError {
    #[error("Invalid internal signing API key.")]
    Unauthorized,
    #[error("Passport artifact chunk identity or size is invalid.")]
    InvalidChunk,
    #[error("Passport artifact ciphertext is invalid.")]
    InvalidCiphertext,
    #[error("Passport artifact envelope binding does not match this organization and artifact.")]
    BindingMismatch,
    #[error("KMS passport artifact encryption failed.")]
    EncryptFailed,
    #[error("KMS passport artifact decryption failed.")]
    DecryptFailed,
    #[error("KMS passport artifact provider is unavailable.")]
    Unavailable,
}

impl IntoResponse for ArtifactEnvelopeError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::InvalidChunk | Self::InvalidCiphertext => StatusCode::UNPROCESSABLE_ENTITY,
            Self::BindingMismatch => StatusCode::CONFLICT,
            Self::EncryptFailed | Self::DecryptFailed | Self::Unavailable => {
                StatusCode::SERVICE_UNAVAILABLE
            }
        };
        (status, Json(json!({"detail": self.to_string()}))).into_response()
    }
}

fn valid_identity(organization_id: &str, artifact_id: &str, index: u32, count: u32) -> bool {
    !organization_id.trim().is_empty()
        && !artifact_id.trim().is_empty()
        && organization_id.len() <= 256
        && artifact_id.len() <= 256
        && count > 0
        && count <= MAX_CHUNKS
        && index < count
}

fn prepare_chunk(
    organization_id: &str,
    request: &EncryptChunkRequest,
) -> Result<Vec<u8>, ArtifactEnvelopeError> {
    if !valid_identity(
        organization_id,
        &request.artifact_id,
        request.chunk_index,
        request.chunk_count,
    ) || request.plaintext_b64.len() > MAX_ENCODED_CHUNK_BYTES
    {
        return Err(ArtifactEnvelopeError::InvalidChunk);
    }
    let plaintext = STANDARD
        .decode(&request.plaintext_b64)
        .map_err(|_| ArtifactEnvelopeError::InvalidChunk)?;
    if plaintext.is_empty() || plaintext.len() > MAX_CHUNK_BYTES {
        return Err(ArtifactEnvelopeError::InvalidChunk);
    }
    serde_json::to_vec(&BoundChunk {
        schema: SCHEMA.into(),
        organization_id: organization_id.into(),
        artifact_id: request.artifact_id.clone(),
        chunk_index: request.chunk_index,
        chunk_count: request.chunk_count,
        plaintext_b64: STANDARD.encode(plaintext),
    })
    .map_err(|_| ArtifactEnvelopeError::InvalidChunk)
}

fn validate_chunk(
    organization_id: &str,
    request: &DecryptChunkRequest,
    plaintext: &[u8],
) -> Result<Value, ArtifactEnvelopeError> {
    if !valid_identity(
        organization_id,
        &request.artifact_id,
        request.chunk_index,
        request.chunk_count,
    ) {
        return Err(ArtifactEnvelopeError::InvalidChunk);
    }
    if plaintext.len() > MAX_ENVELOPE_BYTES {
        return Err(ArtifactEnvelopeError::DecryptFailed);
    }
    let chunk: BoundChunk =
        serde_json::from_slice(plaintext).map_err(|_| ArtifactEnvelopeError::DecryptFailed)?;
    if chunk.schema != SCHEMA
        || chunk.organization_id != organization_id
        || chunk.artifact_id != request.artifact_id
        || chunk.chunk_index != request.chunk_index
        || chunk.chunk_count != request.chunk_count
    {
        return Err(ArtifactEnvelopeError::BindingMismatch);
    }
    if chunk.plaintext_b64.len() > MAX_ENCODED_CHUNK_BYTES {
        return Err(ArtifactEnvelopeError::DecryptFailed);
    }
    let decoded = STANDARD
        .decode(&chunk.plaintext_b64)
        .map_err(|_| ArtifactEnvelopeError::DecryptFailed)?;
    if decoded.is_empty() || decoded.len() > MAX_CHUNK_BYTES {
        return Err(ArtifactEnvelopeError::DecryptFailed);
    }
    Ok(json!({"plaintext_b64": STANDARD.encode(decoded)}))
}

pub async fn encrypt_chunk(
    provider: &OpenBaoEnvelopeProvider,
    organization_id: &str,
    request: EncryptChunkRequest,
) -> Result<Value, ArtifactEnvelopeError> {
    let plaintext = prepare_chunk(organization_id, &request)?;
    let response = provider
        .post(
            &format!("/v1/transit/encrypt/{KEY_ID}"),
            json!({"plaintext": STANDARD.encode(plaintext)}),
        )
        .await
        .map_err(|_| ArtifactEnvelopeError::EncryptFailed)?;
    let ciphertext = response
        .pointer("/data/ciphertext")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("vault:v") && value.len() <= MAX_CIPHERTEXT_BYTES)
        .ok_or(ArtifactEnvelopeError::EncryptFailed)?;
    Ok(json!({"ciphertext": ciphertext}))
}

pub async fn decrypt_chunk(
    provider: &OpenBaoEnvelopeProvider,
    organization_id: &str,
    request: DecryptChunkRequest,
) -> Result<Value, ArtifactEnvelopeError> {
    if !valid_identity(
        organization_id,
        &request.artifact_id,
        request.chunk_index,
        request.chunk_count,
    ) || !request.ciphertext.starts_with("vault:v")
        || request.ciphertext.len() > MAX_CIPHERTEXT_BYTES
    {
        return Err(ArtifactEnvelopeError::InvalidCiphertext);
    }
    let response = provider
        .post(
            &format!("/v1/transit/decrypt/{KEY_ID}"),
            json!({"ciphertext": request.ciphertext}),
        )
        .await
        .map_err(|_| ArtifactEnvelopeError::DecryptFailed)?;
    let plaintext = response
        .pointer("/data/plaintext")
        .and_then(Value::as_str)
        .ok_or(ArtifactEnvelopeError::DecryptFailed)
        .and_then(|value| {
            STANDARD
                .decode(value)
                .map_err(|_| ArtifactEnvelopeError::DecryptFailed)
        })?;
    validate_chunk(organization_id, &request, &plaintext)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{extract::State, routing::post, Router};

    use super::*;

    #[test]
    fn language_neutral_contract_fixes_key_custody_limits_and_error_taxonomy() {
        let contract: Value = serde_json::from_str(include_str!(
            "../../../../contracts/passport-artifact-transit-behavior.json"
        ))
        .unwrap();
        assert_eq!(contract["schema_version"], 1);
        assert_eq!(contract["chunk_schema"], SCHEMA);
        assert_eq!(contract["transit_key_id"], KEY_ID);
        assert_eq!(contract["maximum_chunk_bytes"], MAX_CHUNK_BYTES);
        assert_eq!(contract["maximum_chunks"], MAX_CHUNKS);
        assert_eq!(contract["status"]["unauthorized"], 401);
        assert_eq!(contract["status"]["invalid_chunk"], 422);
        assert_eq!(contract["status"]["binding_mismatch"], 409);
        assert_eq!(contract["status"]["provider_unavailable"], 503);
    }

    #[test]
    fn chunk_round_trip_is_bound_to_tenant_artifact_position_and_count() {
        let request = EncryptChunkRequest {
            artifact_id: "artifact-1".into(),
            chunk_index: 1,
            chunk_count: 3,
            plaintext_b64: STANDARD.encode(b"synthetic passport bytes"),
        };
        let encoded = prepare_chunk("org-a", &request).unwrap();
        let decrypt = DecryptChunkRequest {
            artifact_id: request.artifact_id.clone(),
            chunk_index: request.chunk_index,
            chunk_count: request.chunk_count,
            ciphertext: "vault:v1:synthetic".into(),
        };
        assert_eq!(
            validate_chunk("org-a", &decrypt, &encoded).unwrap()["plaintext_b64"],
            request.plaintext_b64
        );
        assert!(matches!(
            validate_chunk("org-b", &decrypt, &encoded),
            Err(ArtifactEnvelopeError::BindingMismatch)
        ));
        assert!(matches!(
            validate_chunk(
                "org-a",
                &DecryptChunkRequest {
                    chunk_index: 0,
                    ..decrypt
                },
                &encoded
            ),
            Err(ArtifactEnvelopeError::BindingMismatch)
        ));
    }

    #[test]
    fn oversized_empty_and_unbounded_chunk_metadata_fail_before_kms() {
        let request = EncryptChunkRequest {
            artifact_id: "artifact-1".into(),
            chunk_index: 0,
            chunk_count: 1,
            plaintext_b64: STANDARD.encode([0_u8; MAX_CHUNK_BYTES + 1]),
        };
        assert!(matches!(
            prepare_chunk("org-a", &request),
            Err(ArtifactEnvelopeError::InvalidChunk)
        ));
        let request = EncryptChunkRequest {
            plaintext_b64: STANDARD.encode([1_u8]),
            chunk_count: MAX_CHUNKS + 1,
            ..request
        };
        assert!(matches!(
            prepare_chunk("org-a", &request),
            Err(ArtifactEnvelopeError::InvalidChunk)
        ));
    }

    #[tokio::test]
    async fn transit_adapter_uses_the_passport_key_and_checks_binding_after_decrypt() {
        #[derive(Clone, Default)]
        struct Mock(Arc<Mutex<Vec<u8>>>);

        async fn encrypt(State(mock): State<Mock>, Json(body): Json<Value>) -> Json<Value> {
            *mock.0.lock().unwrap() = STANDARD
                .decode(body["plaintext"].as_str().unwrap())
                .unwrap();
            Json(json!({"data": {"ciphertext": "vault:v1:synthetic"}}))
        }

        async fn decrypt(State(mock): State<Mock>, Json(body): Json<Value>) -> Json<Value> {
            assert_eq!(body["ciphertext"], "vault:v1:synthetic");
            Json(json!({
                "data": {"plaintext": STANDARD.encode(mock.0.lock().unwrap().as_slice())}
            }))
        }

        let app = Router::new()
            .route(
                "/v1/transit/encrypt/passport-artifact-marty-aes256",
                post(encrypt),
            )
            .route(
                "/v1/transit/decrypt/passport-artifact-marty-aes256",
                post(decrypt),
            )
            .with_state(Mock::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let provider =
            OpenBaoEnvelopeProvider::new(format!("http://{address}"), "synthetic-token").unwrap();
        let encrypted = encrypt_chunk(
            &provider,
            "org-a",
            EncryptChunkRequest {
                artifact_id: "artifact-1".into(),
                chunk_index: 0,
                chunk_count: 1,
                plaintext_b64: STANDARD.encode(b"synthetic applicant"),
            },
        )
        .await
        .unwrap();
        let request = DecryptChunkRequest {
            artifact_id: "artifact-1".into(),
            chunk_index: 0,
            chunk_count: 1,
            ciphertext: encrypted["ciphertext"].as_str().unwrap().into(),
        };
        assert_eq!(
            decrypt_chunk(&provider, "org-a", request).await.unwrap()["plaintext_b64"],
            STANDARD.encode(b"synthetic applicant")
        );
        assert!(matches!(
            decrypt_chunk(
                &provider,
                "org-b",
                DecryptChunkRequest {
                    artifact_id: "artifact-1".into(),
                    chunk_index: 0,
                    chunk_count: 1,
                    ciphertext: "vault:v1:synthetic".into(),
                }
            )
            .await,
            Err(ArtifactEnvelopeError::BindingMismatch)
        ));
        server.abort();
    }
}
