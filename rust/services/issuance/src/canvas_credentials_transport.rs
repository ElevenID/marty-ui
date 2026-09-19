//! Shared Canvas delivery HTTP owner; no logging of credentials or payloads.
use crate::{
    canvas_network_timeout::CanvasNetworkTimeout,
    canvas_operation_http::{CanvasOperationHttpClient, CanvasOperationHttpError},
    canvas_provider_http::{CanvasHttpClientPolicy, CanvasOriginPolicy},
};
use async_trait::async_trait;
use serde_json::Value;
use url::Url;
/// Deliberately not Debug: the token and credential payload are confidential.
pub struct CanvasCredentialsRequest {
    pub method: reqwest::Method,
    pub url: String,
    pub token: Option<String>,
    pub body: Value,
}

pub struct CanvasCredentialsResponse {
    pub status: u16,
    pub request_id: Option<String>,
    /// Original response bytes: JSON encoding detection must precede text loss.
    pub body: Vec<u8>,
    pub content_type: Option<String>,
}

#[async_trait]
pub trait CanvasCredentialsTransport: Send + Sync {
    /// Errors must be safe for durable public diagnostics, without raw client
    /// errors (which can contain URLs, credentials, or internal network details).
    async fn send(
        &self,
        request: CanvasCredentialsRequest,
    ) -> Result<CanvasCredentialsResponse, String>;
}

#[derive(Clone, Debug)]
pub struct HttpCanvasCredentialsTransport {
    client: CanvasOperationHttpClient,
}

impl HttpCanvasCredentialsTransport {
    pub fn new(policy: CanvasHttpClientPolicy) -> Self {
        let timeout = CanvasNetworkTimeout::from_seconds(policy.timeout.as_secs_f64());
        Self::with_operation_timeout(CanvasOriginPolicy::from(&policy), timeout)
    }

    pub fn with_operation_timeout(
        policy: CanvasOriginPolicy,
        timeout: CanvasNetworkTimeout,
    ) -> Self {
        Self {
            client: CanvasOperationHttpClient::new(policy, timeout),
        }
    }
}

#[async_trait]
impl CanvasCredentialsTransport for HttpCanvasCredentialsTransport {
    async fn send(
        &self,
        request: CanvasCredentialsRequest,
    ) -> Result<CanvasCredentialsResponse, String> {
        let parsed = Url::parse(&request.url).map_err(|_| "Provider URL is invalid")?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err("Provider URL must not contain credentials".into());
        }
        // Pin the actual request destination, including operator URL templates;
        // never construct a client for one origin then send a token to another.
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            http::HeaderValue::from_static("application/json"),
        );
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        if let Some(token) = request.token {
            headers.insert(
                http::header::AUTHORIZATION,
                http::HeaderValue::from_str(&format!("Bearer {token}"))
                    .map_err(|_| "Provider request unavailable")?,
            );
        }
        let body = serde_json::to_vec(&request.body).map_err(|_| "Provider request unavailable")?;
        let response = self
            .client
            .send(request.method, parsed, headers, body)
            .await
            .map_err(|error| match error {
                CanvasOperationHttpError::Origin => "Provider origin is unavailable or disallowed",
                CanvasOperationHttpError::Timeout(_) => "Provider request timed out",
                _ => "Provider request unavailable",
            })?;
        let status = response.response.status().as_u16();
        let request_id = response
            .response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let content_type = response.content_type();
        let body = response
            .bytes()
            .await
            .map_err(|_| "Provider response unavailable")?;
        Ok(CanvasCredentialsResponse {
            status,
            request_id,
            body: body.to_vec(),
            content_type,
        })
    }
}
