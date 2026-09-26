//! KMS-only passport artifact storage client. OpenBao keys never enter issuance.

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::passport_artifact::PassportSensitiveArtifact;

const MANIFEST_SCHEMA: &str = "marty.passport-artifact-manifest/v1";
const MAX_CHUNK_BYTES: usize = 512 * 1024;
const MAX_CHUNKS: usize = 4096;
const MAX_CIPHERTEXT_BYTES: usize = 2_000_000;

#[derive(Clone)]
pub struct KmsPassportArtifactCipher {
    client: Client,
    base_url: Url,
    api_key: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactManifest {
    schema: String,
    chunks: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum KmsArtifactError {
    #[error("KMS passport artifact configuration is invalid")]
    InvalidConfig,
    #[error("KMS passport artifact provider is unavailable")]
    Unavailable,
    #[error("Secure physical document artifact cannot be decrypted")]
    InvalidArtifact,
}

impl KmsPassportArtifactCipher {
    pub fn new(mut base_url: Url, api_key: &str) -> Result<Self, KmsArtifactError> {
        if api_key.trim().is_empty()
            || !matches!(base_url.scheme(), "http" | "https")
            || base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
        {
            return Err(KmsArtifactError::InvalidConfig);
        }
        base_url.set_query(None);
        base_url.set_fragment(None);
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| KmsArtifactError::InvalidConfig)?;
        Ok(Self {
            client,
            base_url,
            api_key: api_key.to_owned(),
        })
    }

    pub async fn encrypt(
        &self,
        organization_id: &str,
        artifact_id: &str,
        artifact: &PassportSensitiveArtifact,
    ) -> Result<String, KmsArtifactError> {
        let plaintext = Zeroizing::new(
            serde_json::to_vec(artifact).map_err(|_| KmsArtifactError::InvalidArtifact)?,
        );
        self.encrypt_bytes(organization_id, artifact_id, &plaintext)
            .await
    }

    pub async fn decrypt(
        &self,
        organization_id: &str,
        artifact_id: &str,
        ciphertext: &str,
    ) -> Result<PassportSensitiveArtifact, KmsArtifactError> {
        let manifest: ArtifactManifest =
            serde_json::from_str(ciphertext).map_err(|_| KmsArtifactError::InvalidArtifact)?;
        if manifest.schema != MANIFEST_SCHEMA
            || manifest.chunks.is_empty()
            || manifest.chunks.len() > MAX_CHUNKS
            || manifest
                .chunks
                .iter()
                .any(|chunk| !chunk.starts_with("vault:v") || chunk.len() > MAX_CIPHERTEXT_BYTES)
        {
            return Err(KmsArtifactError::InvalidArtifact);
        }
        let mut plaintext = Zeroizing::new(Vec::new());
        for (index, ciphertext) in manifest.chunks.iter().enumerate() {
            let response = self
                .post(
                    organization_id,
                    "decrypt",
                    json!({
                        "artifact_id": artifact_id,
                        "chunk_index": index,
                        "chunk_count": manifest.chunks.len(),
                        "ciphertext": ciphertext,
                    }),
                )
                .await?;
            let encoded = response
                .get("plaintext_b64")
                .and_then(Value::as_str)
                .filter(|value| value.len() <= MAX_CHUNK_BYTES.div_ceil(3) * 4)
                .ok_or(KmsArtifactError::InvalidArtifact)?;
            let chunk = Zeroizing::new(
                STANDARD
                    .decode(encoded)
                    .map_err(|_| KmsArtifactError::InvalidArtifact)?,
            );
            if chunk.is_empty() || chunk.len() > MAX_CHUNK_BYTES {
                return Err(KmsArtifactError::InvalidArtifact);
            }
            plaintext.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&plaintext).map_err(|_| KmsArtifactError::InvalidArtifact)
    }

    pub async fn encrypted_scrubbed_artifact(
        &self,
        organization_id: &str,
        artifact_id: &str,
    ) -> Result<String, KmsArtifactError> {
        self.encrypt_bytes(organization_id, artifact_id, b"{}")
            .await
    }

    async fn encrypt_bytes(
        &self,
        organization_id: &str,
        artifact_id: &str,
        plaintext: &[u8],
    ) -> Result<String, KmsArtifactError> {
        if organization_id.trim().is_empty()
            || artifact_id.trim().is_empty()
            || plaintext.is_empty()
            || plaintext.len().div_ceil(MAX_CHUNK_BYTES) > MAX_CHUNKS
        {
            return Err(KmsArtifactError::InvalidArtifact);
        }
        let chunk_count = plaintext.len().div_ceil(MAX_CHUNK_BYTES);
        let mut chunks = Vec::with_capacity(chunk_count);
        for (index, chunk) in plaintext.chunks(MAX_CHUNK_BYTES).enumerate() {
            let response = self
                .post(
                    organization_id,
                    "encrypt",
                    json!({
                        "artifact_id": artifact_id,
                        "chunk_index": index,
                        "chunk_count": chunk_count,
                        "plaintext_b64": STANDARD.encode(chunk),
                    }),
                )
                .await?;
            let ciphertext = response
                .get("ciphertext")
                .and_then(Value::as_str)
                .filter(|value| value.starts_with("vault:v") && value.len() <= MAX_CIPHERTEXT_BYTES)
                .ok_or(KmsArtifactError::Unavailable)?;
            chunks.push(ciphertext.to_owned());
        }
        serde_json::to_string(&ArtifactManifest {
            schema: MANIFEST_SCHEMA.into(),
            chunks,
        })
        .map_err(|_| KmsArtifactError::Unavailable)
    }

    async fn post(
        &self,
        organization_id: &str,
        operation: &str,
        body: Value,
    ) -> Result<Value, KmsArtifactError> {
        let mut endpoint = self.base_url.clone();
        endpoint.set_path(&format!(
            "{}/passport-artifacts/{operation}",
            self.base_url.path().trim_end_matches('/')
        ));
        endpoint
            .query_pairs_mut()
            .append_pair("organization_id", organization_id);
        let response = self
            .client
            .post(endpoint)
            .header("X-API-Key", &self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|_| KmsArtifactError::Unavailable)?;
        if matches!(
            response.status(),
            StatusCode::CONFLICT | StatusCode::UNPROCESSABLE_ENTITY
        ) {
            return Err(KmsArtifactError::InvalidArtifact);
        }
        response
            .error_for_status()
            .map_err(|_| KmsArtifactError::Unavailable)?
            .json()
            .await
            .map_err(|_| KmsArtifactError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc, Mutex,
        },
    };

    use axum::{
        extract::{Query, State},
        http::{HeaderMap, StatusCode},
        routing::post,
        Json, Router,
    };

    use super::*;

    #[test]
    fn language_neutral_manifest_contract_matches_the_client() {
        let contract: Value = serde_json::from_str(include_str!(
            "../../../../contracts/passport-artifact-manifest-behavior.json"
        ))
        .unwrap();
        assert_eq!(contract["schema"], MANIFEST_SCHEMA);
        assert_eq!(contract["maximum_chunk_bytes"], MAX_CHUNK_BYTES);
        assert_eq!(contract["maximum_chunks"], MAX_CHUNKS);
        assert_eq!(
            contract["maximum_ciphertext_bytes_per_chunk"],
            MAX_CIPHERTEXT_BYTES
        );
        assert_eq!(
            contract["encrypted_artifact_shape"]["schema"],
            MANIFEST_SCHEMA
        );
    }

    #[derive(Clone, Default)]
    struct Mock {
        chunks: Arc<Mutex<BTreeMap<String, MockBoundChunk>>>,
        sequence: Arc<AtomicU64>,
    }

    #[derive(Clone)]
    struct MockBoundChunk {
        organization_id: String,
        artifact_id: String,
        chunk_index: u64,
        chunk_count: u64,
        plaintext_b64: String,
    }

    async fn encrypt_chunk(
        State(mock): State<Mock>,
        Query(query): Query<BTreeMap<String, String>>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        assert_eq!(headers["x-api-key"], "synthetic-internal-key");
        assert_eq!(query["organization_id"], "org-a");
        assert_eq!(body["artifact_id"], "artifact-1");
        let ciphertext = format!("vault:v1:{}", mock.sequence.fetch_add(1, Ordering::Relaxed));
        mock.chunks.lock().unwrap().insert(
            ciphertext.clone(),
            MockBoundChunk {
                organization_id: query["organization_id"].clone(),
                artifact_id: body["artifact_id"].as_str().unwrap().into(),
                chunk_index: body["chunk_index"].as_u64().unwrap(),
                chunk_count: body["chunk_count"].as_u64().unwrap(),
                plaintext_b64: body["plaintext_b64"].as_str().unwrap().into(),
            },
        );
        Json(json!({"ciphertext": ciphertext}))
    }

    async fn decrypt_chunk(
        State(mock): State<Mock>,
        Query(query): Query<BTreeMap<String, String>>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        assert_eq!(headers["x-api-key"], "synthetic-internal-key");
        let ciphertext = body["ciphertext"].as_str().unwrap();
        let stored = mock
            .chunks
            .lock()
            .unwrap()
            .get(ciphertext)
            .cloned()
            .unwrap();
        if stored.organization_id != query["organization_id"]
            || stored.artifact_id != body["artifact_id"]
            || stored.chunk_index != body["chunk_index"]
            || stored.chunk_count != body["chunk_count"]
        {
            return (
                StatusCode::CONFLICT,
                Json(json!({"detail": "binding mismatch"})),
            );
        }
        (
            StatusCode::OK,
            Json(json!({"plaintext_b64": stored.plaintext_b64})),
        )
    }

    #[tokio::test]
    async fn kms_chunk_manifest_round_trips_and_rejects_tenant_or_artifact_corruption() {
        let mock = Mock::default();
        let app = Router::new()
            .route(
                "/internal/signing-keys/passport-artifacts/encrypt",
                post(encrypt_chunk),
            )
            .route(
                "/internal/signing-keys/passport-artifacts/decrypt",
                post(decrypt_chunk),
            )
            .with_state(mock.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let cipher = KmsPassportArtifactCipher::new(
            Url::parse(&format!("http://{address}/internal/signing-keys/")).unwrap(),
            "synthetic-internal-key",
        )
        .unwrap();
        let artifact = PassportSensitiveArtifact {
            applicant: json!({"synthetic": "test-person"}),
            mrz: BTreeMap::from([("line_1".into(), "P<TEST".into())]),
            data_groups: BTreeMap::from([("DG2".into(), "A".repeat(MAX_CHUNK_BYTES))]),
        };
        let encrypted = cipher
            .encrypt("org-a", "artifact-1", &artifact)
            .await
            .unwrap();
        let manifest: Value = serde_json::from_str(&encrypted).unwrap();
        assert_eq!(manifest["schema"], MANIFEST_SCHEMA);
        assert_eq!(manifest["chunks"].as_array().unwrap().len(), 2);
        assert!(!encrypted.contains("test-person"));
        assert!(
            cipher
                .decrypt("org-a", "artifact-1", &encrypted)
                .await
                .unwrap()
                == artifact
        );
        assert!(matches!(
            cipher.decrypt("org-b", "artifact-1", &encrypted).await,
            Err(KmsArtifactError::InvalidArtifact)
        ));
        assert!(matches!(
            cipher.decrypt("org-a", "artifact-2", &encrypted).await,
            Err(KmsArtifactError::InvalidArtifact)
        ));
        assert!(matches!(
            cipher.decrypt("org-a", "artifact-1", "{}").await,
            Err(KmsArtifactError::InvalidArtifact)
        ));
        let scrubbed = cipher
            .encrypted_scrubbed_artifact("org-a", "artifact-1")
            .await
            .unwrap();
        assert!(matches!(
            cipher.decrypt("org-a", "artifact-1", &scrubbed).await,
            Err(KmsArtifactError::InvalidArtifact)
        ));
        server.abort();
    }

    #[tokio::test]
    async fn provider_failure_or_redirect_never_produces_an_artifact() {
        for status in [StatusCode::SERVICE_UNAVAILABLE, StatusCode::FOUND] {
            let app = Router::new().route(
                "/internal/signing-keys/passport-artifacts/encrypt",
                post(move || async move {
                    (
                        status,
                        [(axum::http::header::LOCATION, "http://127.0.0.1:1/")],
                    )
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let cipher = KmsPassportArtifactCipher::new(
                Url::parse(&format!("http://{address}/internal/signing-keys")).unwrap(),
                "synthetic-internal-key",
            )
            .unwrap();
            assert!(matches!(
                cipher.encrypt_bytes("org-a", "artifact-1", b"{}").await,
                Err(KmsArtifactError::Unavailable)
            ));
            server.abort();
        }
    }

    #[test]
    fn client_requires_an_internal_key_without_exposing_it_in_errors() {
        assert!(matches!(
            KmsPassportArtifactCipher::new(
                Url::parse("http://gateway/internal/signing-keys").unwrap(),
                ""
            ),
            Err(KmsArtifactError::InvalidConfig)
        ));
    }
}
