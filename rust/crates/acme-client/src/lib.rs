//! Bounded ACME transports using a nonexportable OpenBao account signing key.
//! The installation owner must verify the Transit key's nonexportable configuration,
//! bind the exact public key/version to durable account state, and supply fresh
//! workload credentials. This module neither provisions nor exports any private key.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use async_trait::async_trait;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use bytes::Bytes;
use http::{Method, Request, Response};
use http_body_util::BodyExt;
/// The pinned maintained ACME protocol implementation with an external signer boundary.
pub use instant_acme as protocol;
use instant_acme::{BodyWrapper, BytesResponse, Error, ExternalAccountSigner, HttpClient};

use marty_openbao_http::OpenBaoHttp;
use reqwest::header::HeaderValue;
use serde_json::{json, Value};

const INPUT_LIMIT: usize = 64 * 1024;
const RESPONSE_LIMIT: usize = 64 * 1024;
const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
const UNAVAILABLE: &str = "OpenBao ACME account signing unavailable";

/// Credentials are requested anew on each signing operation. The owner handles
/// renewal/re-authentication and supplies only the narrow account-sign policy.
#[async_trait]
pub trait WorkloadCredentials: Send + Sync {
    async fn token(&self) -> Result<HeaderValue, Error>;
}

#[async_trait]
trait Transit: Send + Sync {
    async fn sign(&self, key_name: &str, payload: &Value) -> Result<Vec<u8>, Error>;
}

struct HttpsTransit {
    http: OpenBaoHttp,
    credentials: Arc<dyn WorkloadCredentials>,
}

#[async_trait]
impl Transit for HttpsTransit {
    async fn sign(&self, key_name: &str, payload: &Value) -> Result<Vec<u8>, Error> {
        let mut token = self
            .credentials
            .token()
            .await
            .map_err(|_| Error::Str(UNAVAILABLE))?;
        if token.as_bytes().is_empty() || token.as_bytes().len() > 16 * 1024 {
            return Err(Error::Str(UNAVAILABLE));
        }
        token.set_sensitive(true);
        let response = self
            .http
            .client()
            .post(format!("{}/v1/transit/sign/{key_name}", self.http.origin()))
            .header("X-Vault-Token", token)
            .json(payload)
            .send()
            .await
            .map_err(|_| Error::Str(UNAVAILABLE))?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(Error::Str(UNAVAILABLE));
        }
        bounded_body(response, RESPONSE_LIMIT).await
    }
}

/// One fixed Transit key version and public identity for ACME account requests.
/// Debug/serialization are intentionally absent so credentials cannot be exported.
pub struct OpenBaoAccountSigner {
    transit: Arc<dyn Transit>,
    key_name: String,
    key_version: u32,
    public_key: [u8; 65],
}

impl OpenBaoAccountSigner {
    pub fn new(
        http: OpenBaoHttp,
        credentials: Arc<dyn WorkloadCredentials>,
        key_name: String,
        key_version: u32,
        public_key: [u8; 65],
    ) -> Result<Self, Error> {
        if key_name.is_empty()
            || key_name.len() > 128
            || !key_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || key_version == 0
            || public_key[0] != 4
        {
            return Err(Error::Str("invalid pinned ACME account key"));
        }
        Ok(Self {
            transit: Arc::new(HttpsTransit { http, credentials }),
            key_name,
            key_version,
            public_key,
        })
    }
}

#[async_trait]
impl ExternalAccountSigner for OpenBaoAccountSigner {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    async fn sign(&self, signing_input: &[u8]) -> Result<[u8; 64], Error> {
        let payload = sign_payload(signing_input, self.key_version)?;
        let body = tokio::time::timeout(
            REQUEST_DEADLINE,
            self.transit.sign(&self.key_name, &payload),
        )
        .await
        .map_err(|_| Error::Str(UNAVAILABLE))??;
        decode_signature(&body, self.key_version)
    }
}

fn sign_payload(input: &[u8], key_version: u32) -> Result<Value, Error> {
    if input.is_empty()
        || input.len() > INPUT_LIMIT
        || key_version == 0
        || input[0] == b'.'
        || input.iter().filter(|b| **b == b'.').count() != 1
        || !input
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'_' | b'-' | b'.'))
    {
        return Err(Error::Str("invalid ACME JWS signing input"));
    }
    Ok(json!({
        "input": STANDARD.encode(input),
        // OpenBao 2.5 ACL parameter matching preserves JSON/HCL number types.
        // A decimal string matches the exact reviewed ["1"] policy constraint.
        "key_version": key_version.to_string(),
        "prehashed": false,
        "hash_algorithm": "sha2-256",
        "marshaling_algorithm": "jws",
    }))
}

fn decode_signature(raw: &[u8], key_version: u32) -> Result<[u8; 64], Error> {
    if raw.is_empty() || raw.len() > RESPONSE_LIMIT || key_version == 0 {
        return Err(Error::Str(UNAVAILABLE));
    }
    let value: Value = serde_json::from_slice(raw).map_err(|_| Error::Str(UNAVAILABLE))?;
    let encoded = value
        .pointer("/data/signature")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix(&format!("vault:v{key_version}:")))
        .filter(|value| value.len() == 86)
        .ok_or(Error::Str(UNAVAILABLE))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::Str(UNAVAILABLE))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return Err(Error::Str(UNAVAILABLE));
    }
    bytes.try_into().map_err(|_| Error::Str(UNAVAILABLE))
}

async fn bounded_body(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>, Error> {
    if response
        .content_length()
        .is_some_and(|len| len > limit as u64)
    {
        return Err(Error::Str("ACME transport response exceeded bound"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| Error::Str("ACME transport failed"))?
    {
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(Error::Str("ACME transport response exceeded bound"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Bounded HTTPS transport for the existing client's public ACME requests.
/// Production and staging instances have separate origin-bound clients.
pub struct AcmeHttps {
    client: reqwest::Client,
    origin: String,
}

impl AcmeHttps {
    pub fn new(directory_url: &str) -> Result<Self, Error> {
        let url =
            reqwest::Url::parse(directory_url).map_err(|_| Error::Str("invalid ACME directory"))?;
        if !matches!(
            directory_url,
            "https://acme-staging-v02.api.letsencrypt.org/directory"
                | "https://acme-v02.api.letsencrypt.org/directory"
        ) {
            return Err(Error::Str("unsupported ACME directory"));
        }
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_DEADLINE)
            .build()
            .map_err(|_| Error::Str("ACME HTTPS client unavailable"))?;
        Ok(Self {
            client,
            origin: url.origin().ascii_serialization(),
        })
    }
}

impl HttpClient for AcmeHttps {
    fn request(
        &self,
        req: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>> {
        let client = self.client.clone();
        let origin = self.origin.clone();
        Box::pin(async move {
            tokio::time::timeout(REQUEST_DEADLINE, async move {
                let (parts, body) = req.into_parts();
                let url = reqwest::Url::parse(&parts.uri.to_string())
                    .map_err(|_| Error::Str("invalid ACME request URL"))?;
                if url.origin().ascii_serialization() != origin
                    || url.scheme() != "https"
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.fragment().is_some()
                    || !matches!(parts.method, Method::GET | Method::HEAD | Method::POST)
                {
                    return Err(Error::Str("ACME request escaped configured origin"));
                }
                let body = body
                    .collect()
                    .await
                    .map_err(|never| -> Error { match never {} })?
                    .to_bytes();
                if body.len() > INPUT_LIMIT {
                    return Err(Error::Str("ACME request exceeded bound"));
                }
                let response = client
                    .request(parts.method, url)
                    .headers(parts.headers)
                    .body(body)
                    .send()
                    .await
                    .map_err(|_| Error::Str("ACME HTTPS request failed"))?;
                let status = response.status();
                if status.is_redirection() {
                    return Err(Error::Str("ACME redirect refused"));
                }
                let mut result = Response::builder().status(status);
                *result
                    .headers_mut()
                    .ok_or(Error::Str("ACME response unavailable"))? = response.headers().clone();
                let body = bounded_body(response, RESPONSE_LIMIT).await?;
                Ok(BytesResponse::from(result.body(BodyWrapper::from(body))?))
            })
            .await
            .map_err(|_| Error::Str("ACME request timed out"))?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeTransit {
        calls: AtomicUsize,
        reply: Vec<u8>,
        hang: bool,
    }

    #[async_trait]
    impl Transit for FakeTransit {
        async fn sign(&self, key_name: &str, payload: &Value) -> Result<Vec<u8>, Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(key_name, "marty-acme-account-test");
            assert_eq!(
                payload,
                &json!({
                    "input": STANDARD.encode(b"protected.payload"), "key_version": "3",
                    "prehashed": false, "hash_algorithm": "sha2-256", "marshaling_algorithm": "jws"
                })
            );
            if self.hang {
                std::future::pending::<()>().await;
            }
            Ok(self.reply.clone())
        }
    }

    fn signer(transit: Arc<FakeTransit>) -> OpenBaoAccountSigner {
        let mut public_key = [0; 65];
        public_key[0] = 4;
        OpenBaoAccountSigner {
            transit,
            key_name: "marty-acme-account-test".into(),
            key_version: 3,
            public_key,
        }
    }

    #[tokio::test]
    async fn openbao_adapter_pins_version_and_preserves_exact_jws_input() {
        let signature = [0xfbu8; 64];
        let transit = Arc::new(FakeTransit { calls: AtomicUsize::new(0), hang: false,
            reply: serde_json::to_vec(&json!({"data":{"signature":format!("vault:v3:{}", URL_SAFE_NO_PAD.encode(signature))}})).unwrap() });
        assert_eq!(
            signer(transit.clone())
                .sign(b"protected.payload")
                .await
                .unwrap(),
            signature
        );
        assert_eq!(transit.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn remote_sign_deadline_cancels_pending_transit_request() {
        let transit = Arc::new(FakeTransit {
            calls: AtomicUsize::new(0),
            hang: true,
            reply: vec![],
        });
        assert!(signer(transit).sign(b"protected.payload").await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn remote_sign_deadline_includes_workload_credential_obtainment() {
        struct PendingCredentials(AtomicUsize);
        #[async_trait]
        impl WorkloadCredentials for PendingCredentials {
            async fn token(&self) -> Result<HeaderValue, Error> {
                self.0.fetch_add(1, Ordering::SeqCst);
                std::future::pending().await
            }
        }
        let credentials = Arc::new(PendingCredentials(AtomicUsize::new(0)));
        let http =
            OpenBaoHttp::connect("https://127.0.0.1:18443", None, Duration::from_secs(5)).unwrap();
        let mut key = [0; 65];
        key[0] = 4;
        let signer =
            OpenBaoAccountSigner::new(http, credentials.clone(), "account-test".into(), 1, key)
                .unwrap();
        assert!(signer.sign(b"protected.payload").await.is_err());
        assert_eq!(credentials.0.load(Ordering::SeqCst), 1);
        // The credential future never returns, so no HTTP send is reachable.
    }

    #[tokio::test]
    async fn credential_provider_errors_are_redacted_before_leaving_signer() {
        struct FailedCredentials;
        #[async_trait]
        impl WorkloadCredentials for FailedCredentials {
            async fn token(&self) -> Result<HeaderValue, Error> {
                Err(Error::Str("sensitive fixture credential error"))
            }
        }
        let http =
            OpenBaoHttp::connect("https://127.0.0.1:18443", None, Duration::from_secs(5)).unwrap();
        let mut key = [0; 65];
        key[0] = 4;
        let signer = OpenBaoAccountSigner::new(
            http,
            Arc::new(FailedCredentials),
            "account-test".into(),
            1,
            key,
        )
        .unwrap();
        assert!(matches!(
            signer.sign(b"protected.payload").await,
            Err(Error::Str(UNAVAILABLE))
        ));
    }

    #[tokio::test]
    async fn acme_transport_refuses_origin_escape_and_oversized_inputs_before_network() {
        let staging =
            AcmeHttps::new("https://acme-staging-v02.api.letsencrypt.org/directory").unwrap();
        for (method, url) in [
            (
                Method::GET,
                "https://acme-v02.api.letsencrypt.org/directory",
            ),
            (Method::GET, "https://different.example/directory"),
            (
                Method::GET,
                "http://acme-staging-v02.api.letsencrypt.org/directory",
            ),
            (
                Method::GET,
                "https://user@acme-staging-v02.api.letsencrypt.org/directory",
            ),
            (
                Method::PUT,
                "https://acme-staging-v02.api.letsencrypt.org/directory",
            ),
        ] {
            let request = Request::builder()
                .method(method)
                .uri(url)
                .body(BodyWrapper::default())
                .unwrap();
            assert!(matches!(
                staging.request(request).await,
                Err(Error::Str("ACME request escaped configured origin"))
            ));
        }
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://acme-staging-v02.api.letsencrypt.org/order")
            .body(BodyWrapper::from(vec![b'0'; INPUT_LIMIT + 1]))
            .unwrap();
        assert!(matches!(
            staging.request(request).await,
            Err(Error::Str("ACME request exceeded bound"))
        ));
        let production = AcmeHttps::new("https://acme-v02.api.letsencrypt.org/directory").unwrap();
        let request = Request::builder()
            .uri("https://acme-staging-v02.api.letsencrypt.org/directory")
            .body(BodyWrapper::default())
            .unwrap();
        assert!(matches!(
            production.request(request).await,
            Err(Error::Str("ACME request escaped configured origin"))
        ));
    }

    #[test]
    fn acme_transport_requires_an_exact_supported_directory() {
        for url in [
            "http://acme-v02.api.letsencrypt.org/directory",
            "https://user@acme-v02.api.letsencrypt.org/directory",
            "https://acme-v02.api.letsencrypt.org/directory?alternate=1",
            "https://different.example/directory",
        ] {
            assert!(AcmeHttps::new(url).is_err());
        }
    }

    #[test]
    fn refuses_bad_version_encoding_or_oversized_openbao_reply() {
        let good = URL_SAFE_NO_PAD.encode([0xfbu8; 64]);
        for text in [
            format!("vault:v4:{good}"),
            format!("vault:v0:{good}"),
            format!("vault:v3:{good}=="),
            format!("vault:v03:{good}"),
            format!("vault:v3:{}", STANDARD.encode([0xfbu8; 64])),
            "vault:v3:AA".to_owned(),
        ] {
            assert!(decode_signature(
                &serde_json::to_vec(&json!({"data":{"signature":text}})).unwrap(),
                3
            )
            .is_err());
        }
        assert!(decode_signature(&vec![b' '; RESPONSE_LIMIT + 1], 3).is_err());
        assert!(decode_signature(br#"{"data":{}}"#, 3).is_err());
    }

    #[test]
    fn refuses_ambiguous_signing_inputs_and_bounds_post_as_get() {
        for bad in [
            b"".as_slice(),
            b".payload",
            b"a.b.c",
            b"a.\nb",
            b"a.b=",
            b"a. b",
        ] {
            assert!(sign_payload(bad, 3).is_err());
        }
        assert!(sign_payload(&vec![b'a'; INPUT_LIMIT + 1], 3).is_err());
        assert!(sign_payload(b"protected.", 3).is_ok());
    }
}
