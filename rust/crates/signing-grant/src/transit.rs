//! Versioned signing-grant HMAC operations in OpenBao Transit.
//!
//! The caller supplies a mounted, operation-scoped token for each call. No
//! local HMAC or private-key implementation exists in this client.

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::{redirect::Policy, Client, Url};
use serde_json::{json, Value};
use thiserror::Error;

const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: usize = 8192;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum TransitGrantError {
    #[error("signing grant Transit configuration is invalid")]
    InvalidConfig,
    #[error("signing grant Transit request failed")]
    Unavailable,
    #[error("signing grant Transit response is invalid")]
    InvalidResponse,
}

#[derive(Clone)]
pub struct TransitGrantClient {
    endpoint: Url,
    key_name: String,
    http: Client,
}

impl TransitGrantClient {
    /// `endpoint` must be the exact mounted `BAO_ADDR` root origin. Internal
    /// deployments may use their operator-configured HTTP service endpoint;
    /// external Transit callers must use a separate HTTPS-only adapter.
    pub fn for_managed_openbao(endpoint: &str, key_name: &str) -> Result<Self, TransitGrantError> {
        let mounted = std::env::var("BAO_ADDR").map_err(|_| TransitGrantError::InvalidConfig)?;
        if mounted.trim_end_matches('/') != endpoint.trim_end_matches('/') {
            return Err(TransitGrantError::InvalidConfig);
        }
        let url = Url::parse(endpoint).map_err(|_| TransitGrantError::InvalidConfig)?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || key_name.is_empty()
            || key_name.len() > 128
            || !key_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(TransitGrantError::InvalidConfig);
        }
        let http = Client::builder()
            .redirect(Policy::none())
            .timeout(TIMEOUT)
            .build()
            .map_err(|_| TransitGrantError::Unavailable)?;
        Ok(Self {
            endpoint: url,
            key_name: key_name.to_owned(),
            http,
        })
    }

    pub async fn mint(&self, token: &str, input: &[u8]) -> Result<String, TransitGrantError> {
        let response = self
            .post(token, "hmac", json!({"input": STANDARD.encode(input)}))
            .await?;
        let hmac = response
            .pointer("/data/hmac")
            .and_then(Value::as_str)
            .ok_or(TransitGrantError::InvalidResponse)?;
        validate_hmac(hmac)?;
        Ok(hmac.to_owned())
    }

    pub async fn verify(
        &self,
        token: &str,
        input: &[u8],
        hmac: &str,
    ) -> Result<bool, TransitGrantError> {
        validate_hmac(hmac)?;
        let response = self
            .post(
                token,
                "verify",
                json!({"input": STANDARD.encode(input), "hmac": hmac}),
            )
            .await?;
        response
            .pointer("/data/valid")
            .and_then(Value::as_bool)
            .ok_or(TransitGrantError::InvalidResponse)
    }

    async fn post(
        &self,
        token: &str,
        operation: &str,
        body: Value,
    ) -> Result<Value, TransitGrantError> {
        if token.is_empty()
            || token.len() > 4096
            || !token.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(TransitGrantError::InvalidConfig);
        }
        let url = self
            .endpoint
            .join(&format!(
                "/v1/transit/{operation}/{}/sha2-256",
                self.key_name
            ))
            .map_err(|_| TransitGrantError::InvalidConfig)?;
        let mut response = self
            .http
            .post(url)
            .header("X-Vault-Token", token)
            .json(&body)
            .send()
            .await
            .map_err(|_| TransitGrantError::Unavailable)?;
        if !response.status().is_success() {
            return Err(TransitGrantError::Unavailable);
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(TransitGrantError::InvalidResponse);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| TransitGrantError::Unavailable)?
        {
            if chunk.len() > MAX_RESPONSE_BYTES.saturating_sub(bytes.len()) {
                return Err(TransitGrantError::InvalidResponse);
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| TransitGrantError::InvalidResponse)
    }
}

fn validate_hmac(hmac: &str) -> Result<(), TransitGrantError> {
    let mut parts = hmac.split(':');
    let (Some("vault"), Some(version), Some(encoded), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(TransitGrantError::InvalidResponse);
    };
    if version
        .strip_prefix('v')
        .and_then(|value| value.parse::<u32>().ok())
        .is_none_or(|value| value == 0)
        || !STANDARD
            .decode(encoded)
            .is_ok_and(|decoded| decoded.len() == 32)
    {
        return Err(TransitGrantError::InvalidResponse);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::Json,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::post,
        Router,
    };

    #[test]
    fn hmac_must_be_versioned_sha256() {
        let valid = format!("vault:v3:{}", STANDARD.encode([7_u8; 32]));
        assert!(validate_hmac(&valid).is_ok());
        for hmac in ["vault:v0:AAAA", "vault:v1:AQ==", "AQ==", "vault:v1:!!"] {
            assert_eq!(validate_hmac(hmac), Err(TransitGrantError::InvalidResponse));
        }
    }

    #[tokio::test]
    async fn mounted_origin_uses_transit_hmac_and_verify_without_local_key() {
        let hmac = format!("vault:v1:{}", STANDARD.encode([7_u8; 32]));
        let expected = hmac.clone();
        let app = Router::new()
            .route(
                "/v1/transit/hmac/grant-gateway/sha2-256",
                post(move |headers: HeaderMap, Json(body): Json<Value>| {
                    let hmac = hmac.clone();
                    async move {
                        if headers.get("X-Vault-Token").and_then(|v| v.to_str().ok())
                            != Some("test-mint-token")
                            || body["input"] != STANDARD.encode(b"bound.claim")
                        {
                            return (StatusCode::FORBIDDEN, Json(json!({}))).into_response();
                        }
                        (StatusCode::OK, Json(json!({"data": {"hmac": hmac}}))).into_response()
                    }
                }),
            )
            .route(
                "/v1/transit/verify/grant-gateway/sha2-256",
                post(move |headers: HeaderMap, Json(body): Json<Value>| async move {
                    if headers.get("X-Vault-Token").and_then(|v| v.to_str().ok())
                        != Some("test-verify-token")
                    {
                        return (StatusCode::FORBIDDEN, Json(json!({}))).into_response();
                    }
                    (
                        StatusCode::OK,
                        Json(json!({"data": {"valid": body["input"] == STANDARD.encode(b"bound.claim")}})),
                    )
                        .into_response()
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let previous = std::env::var_os("BAO_ADDR");
        std::env::set_var("BAO_ADDR", &endpoint);
        let client = TransitGrantClient::for_managed_openbao(&endpoint, "grant-gateway").unwrap();
        assert!(
            TransitGrantClient::for_managed_openbao("https://other.example", "grant-gateway")
                .is_err()
        );
        assert!(TransitGrantClient::for_managed_openbao(&endpoint, "../escape").is_err());
        let minted = client
            .mint("test-mint-token", b"bound.claim")
            .await
            .unwrap();
        assert_eq!(minted, expected);
        assert!(client
            .verify("test-verify-token", b"bound.claim", &minted)
            .await
            .unwrap());
        assert!(!client
            .verify("test-verify-token", b"altered.claim", &minted)
            .await
            .unwrap());
        assert_eq!(
            client.mint("wrong-token", b"bound.claim").await,
            Err(TransitGrantError::Unavailable)
        );
        server.abort();
        if let Some(previous) = previous {
            std::env::set_var("BAO_ADDR", previous);
        } else {
            std::env::remove_var("BAO_ADDR");
        }
    }

    #[tokio::test]
    #[ignore = "requires marked disposable loopback OpenBao and disjoint HMAC/verify tokens"]
    async fn live_openbao_grant_key_enforces_mint_verify_separation() {
        let endpoint = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
        let url = Url::parse(&endpoint).expect("OpenBao URL");
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(
            std::env::var("BAO_ADDR").ok().as_deref(),
            Some(endpoint.as_str())
        );
        let root = std::env::var("MARTY_TEST_OPENBAO_ROOT_TOKEN").expect("root guard token");
        let nonce = std::env::var("MARTY_TEST_OPENBAO_DISPOSABLE_NONCE").expect("guard nonce");
        assert!(nonce.len() >= 16);
        let marker: Value = Client::new()
            .get(format!(
                "{endpoint}/v1/secret/data/marty-test-disposable-guard"
            ))
            .header("X-Vault-Token", &root)
            .send()
            .await
            .expect("marker request")
            .error_for_status()
            .expect("disposable marker")
            .json()
            .await
            .expect("marker JSON");
        assert_eq!(marker["data"]["data"]["nonce"], nonce);
        let mint = std::env::var("MARTY_TEST_GRANT_MINT_TOKEN").expect("scoped mint token");
        let verify = std::env::var("MARTY_TEST_GRANT_VERIFY_TOKEN").expect("scoped verify token");
        assert_ne!(mint, verify);
        assert_ne!(mint, root);
        assert_ne!(verify, root);
        let client = TransitGrantClient::for_managed_openbao(&endpoint, "marty-grant-test")
            .expect("mounted OpenBao client");
        let input = format!("marty-grant-live:{nonce}");
        let hmac = client
            .mint(&mint, input.as_bytes())
            .await
            .expect("KMS HMAC");
        assert!(client
            .verify(&verify, input.as_bytes(), &hmac)
            .await
            .expect("KMS verify"));
        assert!(!client
            .verify(&verify, b"altered-grant", &hmac)
            .await
            .expect("KMS denies altered input"));
        assert_eq!(
            client.mint(&verify, input.as_bytes()).await,
            Err(TransitGrantError::Unavailable)
        );
        assert_eq!(
            client.verify(&mint, input.as_bytes(), &hmac).await,
            Err(TransitGrantError::Unavailable)
        );
    }
}
