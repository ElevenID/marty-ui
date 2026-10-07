//! Typed client for the remote integration-secret envelope.
//!
//! The signing-keys service owns the Transit key. Issuance stores only the
//! returned versioned envelope and supplies database-bound identity on reads.

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const SCHEMA: &str = "marty.integration-secret-envelope/v1";
const MAX_SECRET_BYTES: usize = 64 * 1024;
const MAX_CIPHERTEXT_BYTES: usize = 200 * 1024;
const MAX_STORED_BYTES: usize = MAX_CIPHERTEXT_BYTES + 1024;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub struct KmsIntegrationSecretCipher {
    client: Client,
    base_url: Url,
    api_key: String,
}

#[derive(Debug, thiserror::Error)]
pub enum KmsIntegrationSecretError {
    #[error("KMS integration-secret configuration is invalid")]
    InvalidConfig,
    #[error("KMS integration-secret provider is unavailable")]
    Unavailable,
    #[error("KMS integration-secret envelope is invalid")]
    InvalidEnvelope,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    ciphertext: String,
}

#[derive(Serialize)]
struct EncryptRequest<'a> {
    organization_id: &'a str,
    secret_id: &'a str,
    provider: &'a str,
    purpose: &'a str,
    plaintext_b64: String,
}

#[derive(Serialize)]
struct DecryptRequest<'a> {
    organization_id: &'a str,
    secret_id: &'a str,
    provider: &'a str,
    purpose: &'a str,
    envelope: Envelope,
}

impl KmsIntegrationSecretCipher {
    pub fn new(base_url: Url, api_key: &str) -> Result<Self, KmsIntegrationSecretError> {
        if api_key.trim().is_empty()
            || !matches!(base_url.scheme(), "http" | "https")
            || base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(KmsIntegrationSecretError::InvalidConfig);
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| KmsIntegrationSecretError::InvalidConfig)?;
        Ok(Self {
            client,
            base_url,
            api_key: api_key.to_owned(),
        })
    }

    pub async fn encrypt(
        &self,
        organization_id: &str,
        secret_id: &str,
        provider: &str,
        purpose: &str,
        plaintext: &str,
    ) -> Result<String, KmsIntegrationSecretError> {
        if !valid_identity(organization_id, secret_id, provider, purpose)
            || plaintext.len() > MAX_SECRET_BYTES
        {
            return Err(KmsIntegrationSecretError::InvalidEnvelope);
        }
        let response = self
            .post(
                organization_id,
                "encrypt",
                &EncryptRequest {
                    organization_id,
                    secret_id,
                    provider,
                    purpose,
                    plaintext_b64: STANDARD.encode(plaintext),
                },
            )
            .await?;
        let envelope = parse_envelope(response)?;
        serde_json::to_string(&envelope).map_err(|_| KmsIntegrationSecretError::InvalidEnvelope)
    }

    pub async fn decrypt(
        &self,
        organization_id: &str,
        secret_id: &str,
        provider: &str,
        purpose: &str,
        stored: &str,
    ) -> Result<String, KmsIntegrationSecretError> {
        if !valid_identity(organization_id, secret_id, provider, purpose)
            || stored.len() > MAX_STORED_BYTES
        {
            return Err(KmsIntegrationSecretError::InvalidEnvelope);
        }
        let envelope = parse_envelope(
            serde_json::from_str(stored).map_err(|_| KmsIntegrationSecretError::InvalidEnvelope)?,
        )?;
        let response = self
            .post(
                organization_id,
                "decrypt",
                &DecryptRequest {
                    organization_id,
                    secret_id,
                    provider,
                    purpose,
                    envelope,
                },
            )
            .await?;
        let encoded = response
            .get("plaintext_b64")
            .and_then(Value::as_str)
            .filter(|value| value.len() <= MAX_SECRET_BYTES.div_ceil(3) * 4)
            .ok_or(KmsIntegrationSecretError::InvalidEnvelope)?;
        let plaintext = STANDARD
            .decode(encoded)
            .map_err(|_| KmsIntegrationSecretError::InvalidEnvelope)?;
        if plaintext.len() > MAX_SECRET_BYTES {
            return Err(KmsIntegrationSecretError::InvalidEnvelope);
        }
        String::from_utf8(plaintext).map_err(|_| KmsIntegrationSecretError::InvalidEnvelope)
    }

    async fn post<T: Serialize>(
        &self,
        organization_id: &str,
        operation: &str,
        request: &T,
    ) -> Result<Value, KmsIntegrationSecretError> {
        let mut endpoint = self.base_url.clone();
        endpoint.set_path(&format!(
            "{}/integration-secrets/{operation}",
            self.base_url.path().trim_end_matches('/')
        ));
        endpoint
            .query_pairs_mut()
            .append_pair("organization_id", organization_id);
        let response = self
            .client
            .post(endpoint)
            .header("X-API-Key", &self.api_key)
            .json(request)
            .send()
            .await
            .map_err(|_| KmsIntegrationSecretError::Unavailable)?;
        if matches!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY | StatusCode::CONFLICT
        ) {
            return Err(KmsIntegrationSecretError::InvalidEnvelope);
        }
        let mut response = response
            .error_for_status()
            .map_err(|_| KmsIntegrationSecretError::Unavailable)?;
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| KmsIntegrationSecretError::Unavailable)?
        {
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(KmsIntegrationSecretError::InvalidEnvelope);
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| KmsIntegrationSecretError::InvalidEnvelope)
    }
}

fn parse_envelope(value: Value) -> Result<Envelope, KmsIntegrationSecretError> {
    let envelope: Envelope =
        serde_json::from_value(value).map_err(|_| KmsIntegrationSecretError::InvalidEnvelope)?;
    if envelope.schema != SCHEMA
        || !envelope.ciphertext.starts_with("vault:v")
        || envelope.ciphertext.len() > MAX_CIPHERTEXT_BYTES
    {
        return Err(KmsIntegrationSecretError::InvalidEnvelope);
    }
    Ok(envelope)
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::{Query, Request},
        http::StatusCode as AxumStatusCode,
        routing::post,
        Json, Router,
    };
    use serde_json::json;

    #[test]
    fn envelope_parser_rejects_legacy_and_unexpected_fields() {
        assert!(parse_envelope(json!({"schema": SCHEMA, "ciphertext": "vault:v1:test"})).is_ok());
        for invalid in [
            json!({"schema": "legacy", "ciphertext": "vault:v1:test"}),
            json!({"schema": SCHEMA, "ciphertext": "local-key"}),
            json!({"schema": SCHEMA, "ciphertext": "vault:v1:test", "private_key": "bad"}),
        ] {
            assert!(parse_envelope(invalid).is_err());
        }
    }

    #[tokio::test]
    async fn client_sends_bound_identity_and_rejects_legacy_reads() {
        async fn encrypt(
            Query(query): Query<std::collections::HashMap<String, String>>,
            request: Request,
        ) -> (AxumStatusCode, Json<Value>) {
            assert_eq!(
                query.get("organization_id").map(String::as_str),
                Some("org-1")
            );
            assert_eq!(request.headers()["x-api-key"], "test-key");
            let body = axum::body::to_bytes(request.into_body(), 200_000)
                .await
                .unwrap();
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["organization_id"], "org-1");
            assert_eq!(body["secret_id"], "secret-1");
            assert_eq!(body["provider"], "canvas");
            assert_eq!(body["purpose"], "oauth_client_secret");
            assert_eq!(
                STANDARD
                    .decode(body["plaintext_b64"].as_str().unwrap())
                    .unwrap(),
                b"synthetic"
            );
            (
                AxumStatusCode::OK,
                Json(json!({"schema": SCHEMA, "ciphertext": "vault:v1:synthetic"})),
            )
        }
        async fn decrypt(
            Query(query): Query<std::collections::HashMap<String, String>>,
            request: Request,
        ) -> Json<Value> {
            assert_eq!(
                query.get("organization_id").map(String::as_str),
                Some("org-1")
            );
            assert_eq!(request.headers()["x-api-key"], "test-key");
            let body = axum::body::to_bytes(request.into_body(), 200_000)
                .await
                .unwrap();
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["organization_id"], "org-1");
            assert_eq!(body["secret_id"], "secret-1");
            assert_eq!(body["provider"], "canvas");
            assert_eq!(body["purpose"], "oauth_client_secret");
            assert_eq!(body["envelope"]["schema"], SCHEMA);
            Json(json!({"plaintext_b64": STANDARD.encode("synthetic")}))
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route(
                        "/internal/signing-keys/integration-secrets/encrypt",
                        post(encrypt),
                    )
                    .route(
                        "/internal/signing-keys/integration-secrets/decrypt",
                        post(decrypt),
                    ),
            )
            .await
            .unwrap();
        });
        let client = KmsIntegrationSecretCipher::new(
            Url::parse(&format!("http://{address}/internal/signing-keys")).unwrap(),
            "test-key",
        )
        .unwrap();
        let stored = client
            .encrypt(
                "org-1",
                "secret-1",
                "canvas",
                "oauth_client_secret",
                "synthetic",
            )
            .await
            .unwrap();
        assert_eq!(
            client
                .decrypt(
                    "org-1",
                    "secret-1",
                    "canvas",
                    "oauth_client_secret",
                    &stored
                )
                .await
                .unwrap(),
            "synthetic"
        );
        assert!(client
            .decrypt(
                "org-1",
                "secret-1",
                "canvas",
                "oauth_client_secret",
                "legacy-base64"
            )
            .await
            .is_err());
        server.abort();
    }
}
