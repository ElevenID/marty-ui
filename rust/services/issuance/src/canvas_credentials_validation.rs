//! Safe, reusable Canvas Credentials provider configuration validation.
//!
//! The management route and the eventual native delivery worker share these
//! provider, URL, secret-resolution, and response-projection rules. Validation
//! is read-only: it may perform a bounded provider GET, but never publishes or
//! mutates a credential.

use std::{collections::BTreeSet, sync::Arc};

use crate::lossless_json::LosslessJson;
use async_trait::async_trait;
use chrono::Utc;
use reqwest::header::{ACCEPT, AUTHORIZATION};
use serde::Serialize;
use serde_json::{Map, Value};
use url::Url;

use crate::canvas_network_timeout::CanvasNetworkTimeout;
use crate::canvas_operation_http::CanvasOperationHttpClient;
use crate::canvas_operator_secret::{
    resolve_canvas_operator_token, CanvasOperatorSecretError, CanvasOperatorSecretReader,
    FileCanvasOperatorSecretReader,
};
use crate::canvas_provider_http::{CanvasHttpClientPolicy, CanvasOriginPolicy};

#[cfg(test)]
use crate::canvas_credentials_protocol::MAX_EXCERPT_CHARS;
use crate::canvas_credentials_protocol::{
    https_origin, provider_alias, response_excerpt as failure_excerpt, DEFAULT_API_BASE_URL,
};

#[derive(Clone, Default, Eq, PartialEq)]
pub struct CanvasCredentialsValidationConfig {
    pub operator_api_token: Option<String>,
    pub operator_api_token_file: Option<String>,
    pub provider: Option<String>,
    pub publish_url: Option<String>,
    pub api_base_url: Option<String>,
    pub assertion_scope: Option<String>,
    pub issuer_id: Option<String>,
    pub badgeclass_id: Option<String>,
    pub validation_url_template: Option<String>,
    pub allowed_api_origins: Vec<String>,
}

impl std::fmt::Debug for CanvasCredentialsValidationConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasCredentialsValidationConfig")
            .field(
                "operator_api_token_configured",
                &self.operator_api_token.is_some(),
            )
            .field(
                "operator_api_token_file_configured",
                &self.operator_api_token_file.is_some(),
            )
            .field("provider_configured", &self.provider.is_some())
            .field("publish_url_configured", &self.publish_url.is_some())
            .field("api_base_url_configured", &self.api_base_url.is_some())
            .field(
                "assertion_scope_configured",
                &self.assertion_scope.is_some(),
            )
            .field("issuer_id_configured", &self.issuer_id.is_some())
            .field("badgeclass_id_configured", &self.badgeclass_id.is_some())
            .field(
                "validation_url_template_configured",
                &self.validation_url_template.is_some(),
            )
            .field("allowed_api_origin_count", &self.allowed_api_origins.len())
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CanvasCredentialsValidationResult {
    pub ok: bool,
    pub provider: String,
    pub api_base_url: Option<String>,
    pub assertion_scope: Option<String>,
    pub issuer_id: Option<String>,
    pub badgeclass_id: Option<String>,
    pub token_configured: bool,
    pub validation_url: Option<String>,
    pub status_code: Option<u16>,
    pub request_id: Option<String>,
    pub error: Option<String>,
    #[serde(serialize_with = "crate::lossless_json::serialize_validation_excerpt")]
    pub response_excerpt: Option<LosslessJson>,
    pub validated_at: String,
}

impl CanvasCredentialsValidationResult {
    fn empty(provider: impl Into<String>) -> Self {
        Self {
            ok: false,
            provider: provider.into(),
            api_base_url: None,
            assertion_scope: None,
            issuer_id: None,
            badgeclass_id: None,
            token_configured: false,
            validation_url: None,
            status_code: None,
            request_id: None,
            error: None,
            response_excerpt: None,
            validated_at: Utc::now().to_rfc3339(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasCredentialsProviderResponse {
    pub status_code: u16,
    pub request_id: Option<String>,
    pub response_excerpt: Option<LosslessJson>,
}

pub use crate::canvas_response_text::CanvasResponseTextError;

impl CanvasCredentialsProviderResponse {
    /// Project an already-complete response. Successful bodies are not decoded.
    pub fn from_body(
        status_code: u16,
        request_id: Option<String>,
        body: &[u8],
        content_type: Option<&str>,
    ) -> Result<Self, CanvasResponseTextError> {
        Ok(Self {
            status_code,
            request_id,
            response_excerpt: if (200..300).contains(&status_code) {
                None
            } else {
                Some(failure_excerpt(body, content_type)?)
            },
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CanvasCredentialsTransportError {
    #[error("Canvas Credentials validation request failed")]
    Request,
    #[error(transparent)]
    ResponseText(#[from] CanvasResponseTextError),
}

#[async_trait]
pub trait CanvasCredentialsSecretResolver: Send + Sync {
    async fn secret_value(
        &self,
        organization_id: &str,
        secret_id: &str,
    ) -> Result<Option<String>, ()>;
}

#[async_trait]
pub trait CanvasCredentialsValidationTransport: Send + Sync {
    async fn get(
        &self,
        api_origin: &str,
        validation_url: &str,
        token: &str,
    ) -> Result<CanvasCredentialsProviderResponse, CanvasCredentialsTransportError>;
}

#[async_trait]
pub trait CanvasCredentialsValidator: Send + Sync {
    async fn validate(
        &self,
        organization_id: &str,
        canvas_credentials: &Map<String, Value>,
    ) -> Result<CanvasCredentialsValidationResult, CanvasCredentialsValidationError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CanvasCredentialsValidationError {
    #[error(transparent)]
    OperatorSecret(#[from] CanvasOperatorSecretError),
    #[error(transparent)]
    ResponseText(#[from] CanvasResponseTextError),
}

#[derive(Debug, thiserror::Error)]
enum ValidationPreparationError {
    #[error("{0}")]
    Configuration(String),
    #[error(transparent)]
    OperatorSecret(#[from] CanvasOperatorSecretError),
}

impl From<String> for ValidationPreparationError {
    fn from(error: String) -> Self {
        Self::Configuration(error)
    }
}

#[derive(Clone)]
pub struct CanvasCredentialsValidationService {
    config: CanvasCredentialsValidationConfig,
    allowed_origins: Arc<BTreeSet<String>>,
    secrets: Arc<dyn CanvasCredentialsSecretResolver>,
    operator_secrets: Arc<dyn CanvasOperatorSecretReader>,
    transport: Arc<dyn CanvasCredentialsValidationTransport>,
}

impl std::fmt::Debug for CanvasCredentialsValidationService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasCredentialsValidationService")
            .field("config", &self.config)
            .field("allowed_origin_count", &self.allowed_origins.len())
            .finish_non_exhaustive()
    }
}

impl CanvasCredentialsValidationService {
    /// Override the trusted operator file reader without allowing tenant paths.
    pub fn with_operator_secret_reader(
        mut self,
        reader: Arc<dyn CanvasOperatorSecretReader>,
    ) -> Self {
        self.operator_secrets = reader;
        self
    }
    #[must_use]
    pub fn new(
        config: CanvasCredentialsValidationConfig,
        secrets: Arc<dyn CanvasCredentialsSecretResolver>,
        transport: Arc<dyn CanvasCredentialsValidationTransport>,
    ) -> Self {
        let allowed_origins = std::iter::once(DEFAULT_API_BASE_URL)
            .chain(config.allowed_api_origins.iter().map(String::as_str))
            .filter_map(https_origin)
            .collect();
        Self {
            config,
            allowed_origins: Arc::new(allowed_origins),
            secrets,
            operator_secrets: Arc::new(FileCanvasOperatorSecretReader),
            transport,
        }
    }

    async fn token(
        &self,
        organization_id: &str,
        canvas_credentials: &Map<String, Value>,
    ) -> Result<Option<String>, CanvasOperatorSecretError> {
        if canvas_credentials.is_empty() {
            return resolve_canvas_operator_token(
                self.config.operator_api_token.as_deref(),
                self.config.operator_api_token_file.as_deref(),
                self.operator_secrets.as_ref(),
            )
            .await;
        }
        let Some(secret_id) = map_text(canvas_credentials, "api_token_secret_id") else {
            return Ok(None);
        };
        Ok(self
            .secrets
            .secret_value(organization_id, secret_id)
            .await
            .ok()
            .flatten()
            .filter(|value| !value.is_empty()))
    }

    fn provider(&self, canvas_credentials: &Map<String, Value>) -> String {
        let configured = map_text(canvas_credentials, "provider")
            .map(str::to_owned)
            .or_else(|| self.config.provider.clone())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if configured.is_empty() {
            if self.config.publish_url.is_some() {
                return "bridge".to_owned();
            }
            if map_text(canvas_credentials, "badgeclass_id").is_some()
                || self.config.badgeclass_id.is_some()
            {
                return "badgr_api".to_owned();
            }
            return "bridge".to_owned();
        }
        provider_alias(configured)
    }

    fn base_url(
        &self,
        canvas_credentials: &Map<String, Value>,
    ) -> Result<(String, String), String> {
        let value = map_text(canvas_credentials, "api_base_url")
            .map(str::to_owned)
            .or_else(|| self.config.api_base_url.clone())
            .unwrap_or_else(|| DEFAULT_API_BASE_URL.to_owned());
        let value = value.trim().trim_end_matches('/').to_owned();
        let parsed = Url::parse(&value)
            .map_err(|_| "Canvas Credentials API base URL must be a trusted HTTPS URL")?;
        let origin = https_origin(&value).ok_or_else(|| {
            "Canvas Credentials API base URL must be a trusted HTTPS URL".to_owned()
        })?;
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err("Canvas Credentials API base URL must be a trusted HTTPS URL".to_owned());
        }
        if !self.allowed_origins.contains(&origin) {
            return Err(
                "Canvas Credentials API origin is not in CANVAS_CREDENTIALS_API_ORIGIN_ALLOWLIST"
                    .to_owned(),
            );
        }
        Ok((value, origin))
    }

    fn assertion_scope(&self, canvas_credentials: &Map<String, Value>) -> Result<String, String> {
        let scope = map_text(canvas_credentials, "assertion_scope")
            .map(str::to_owned)
            .or_else(|| self.config.assertion_scope.clone())
            .unwrap_or_else(|| "badgeclasses".to_owned())
            .to_ascii_lowercase();
        matches!(scope.as_str(), "badgeclasses" | "issuers")
            .then_some(scope)
            .ok_or_else(|| {
                "CANVAS_CREDENTIALS_ASSERTION_SCOPE must be 'badgeclasses' or 'issuers'".to_owned()
            })
    }

    fn validation_url(
        &self,
        base_url: &str,
        scope: &str,
        issuer_id: Option<&str>,
        badgeclass_id: Option<&str>,
    ) -> Result<String, String> {
        if let Some(template) = self.config.validation_url_template.as_deref() {
            let url = template
                .replace("{api_base_url}", base_url)
                .replace("{scope}", &encoded_path_segment(scope))
                .replace(
                    "{badgeclass_id}",
                    &encoded_path_segment(badgeclass_id.unwrap_or_default()),
                )
                .replace(
                    "{issuer_id}",
                    &encoded_path_segment(issuer_id.unwrap_or_default()),
                );
            let origin = https_origin(&url).ok_or_else(|| {
                "Canvas Credentials validation URL must be a trusted HTTPS URL".to_owned()
            })?;
            if !self.allowed_origins.contains(&origin) {
                return Err(
                    "Canvas Credentials validation URL origin is not operator allowlisted"
                        .to_owned(),
                );
            }
            return Ok(url);
        }
        let identifier = if scope == "issuers" {
            issuer_id.ok_or_else(|| {
                "CANVAS_CREDENTIALS_ISSUER_ID is required when assertion scope is 'issuers'"
                    .to_owned()
            })?
        } else {
            badgeclass_id.ok_or_else(|| {
                "CANVAS_CREDENTIALS_BADGECLASS_ID is required for Canvas Credentials validation"
                    .to_owned()
            })?
        };
        let mut url =
            Url::parse(&format!("{}/", base_url.trim_end_matches('/'))).map_err(|_| {
                "Canvas Credentials API base URL must be a trusted HTTPS URL".to_owned()
            })?;
        url.path_segments_mut()
            .map_err(|_| "Canvas Credentials API base URL must be a trusted HTTPS URL".to_owned())?
            .pop_if_empty()
            .extend(["v2", scope, identifier]);
        Ok(url.to_string().trim_end_matches('/').to_owned())
    }
}

#[async_trait]
impl CanvasCredentialsValidator for CanvasCredentialsValidationService {
    async fn validate(
        &self,
        organization_id: &str,
        canvas_credentials: &Map<String, Value>,
    ) -> Result<CanvasCredentialsValidationResult, CanvasCredentialsValidationError> {
        let provider = self.provider(canvas_credentials);
        if provider == "bridge" {
            let token = self.token(organization_id, canvas_credentials).await?;
            let mut result = CanvasCredentialsValidationResult::empty(provider);
            result.token_configured = token.is_some();
            let Some(publish_url) = self.config.publish_url.clone() else {
                result.error = Some("CANVAS_CREDENTIALS_PUBLISH_URL is not configured".to_owned());
                return Ok(result);
            };
            result.ok = true;
            result.validation_url = Some(publish_url);
            return Ok(result);
        }
        if !matches!(provider.as_str(), "badgr_api" | "canvas_credentials_api") {
            let mut result = CanvasCredentialsValidationResult::empty(&provider);
            result.error = Some(format!(
                "Unsupported Canvas Credentials provider: {provider}"
            ));
            return Ok(result);
        }

        // Preserve the published try/catch boundary, including the second lazy
        // token lookup after URL construction fails. File rotation is observable.
        let prepared: Result<_, ValidationPreparationError> = async {
            let (api_base_url, api_origin) = self.base_url(canvas_credentials)?;
            let scope = self.assertion_scope(canvas_credentials)?;
            let issuer_id = map_text(canvas_credentials, "issuer_id")
                .map(str::to_owned).or_else(|| self.config.issuer_id.clone());
            let badgeclass_id = map_text(canvas_credentials, "badgeclass_id")
                .map(str::to_owned).or_else(|| self.config.badgeclass_id.clone());
            if badgeclass_id.is_none() {
                return Err(ValidationPreparationError::Configuration(
                    "CANVAS_CREDENTIALS_BADGECLASS_ID is required for real Canvas Credentials publish".into()));
            }
            let token = self.token(organization_id, canvas_credentials).await?;
            let validation_url = self.validation_url(&api_base_url, &scope, issuer_id.as_deref(), badgeclass_id.as_deref())?;
            let mut result = CanvasCredentialsValidationResult::empty(&provider);
            result.api_base_url = Some(api_base_url);
            result.assertion_scope = Some(scope);
            result.issuer_id = issuer_id;
            result.badgeclass_id = badgeclass_id;
            result.validation_url = Some(validation_url);
            Ok((result, api_origin, token))
        }.await;
        let (mut result, api_origin, token) = match prepared {
            Ok(value) => value,
            Err(ValidationPreparationError::OperatorSecret(error)) => return Err(error.into()),
            Err(ValidationPreparationError::Configuration(error)) => {
                let mut result = CanvasCredentialsValidationResult::empty(&provider);
                result.api_base_url = map_text(canvas_credentials, "api_base_url")
                    .map(str::to_owned)
                    .or_else(|| self.config.api_base_url.clone())
                    .or_else(|| Some(DEFAULT_API_BASE_URL.to_owned()));
                result.token_configured = self
                    .token(organization_id, canvas_credentials)
                    .await?
                    .is_some();
                result.error = Some(error);
                return Ok(result);
            }
        };
        let Some(token) = token else {
            result.error = Some(
                "CANVAS_CREDENTIALS_API_TOKEN is required for Canvas Credentials validation"
                    .to_owned(),
            );
            return Ok(result);
        };
        result.token_configured = true;
        let response = match self
            .transport
            .get(
                &api_origin,
                result.validation_url.as_deref().expect("prepared URL"),
                &token,
            )
            .await
        {
            Ok(response) => response,
            Err(CanvasCredentialsTransportError::ResponseText(error)) => return Err(error.into()),
            Err(CanvasCredentialsTransportError::Request) => {
                result.error = Some("Canvas Credentials validation request failed".to_owned());
                return Ok(result);
            }
        };
        result.status_code = Some(response.status_code);
        result.request_id = response.request_id;
        result.ok = (200..300).contains(&response.status_code);
        if !result.ok {
            result.error = Some(format!(
                "Canvas Credentials validation failed with HTTP {}",
                response.status_code
            ));
            result.response_excerpt = response.response_excerpt;
        }
        Ok(result)
    }
}

#[derive(Clone)]
pub struct HttpCanvasCredentialsValidationTransport {
    client: CanvasOperationHttpClient,
}

impl std::fmt::Debug for HttpCanvasCredentialsValidationTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpCanvasCredentialsValidationTransport")
            .field("client", &self.client)
            .finish()
    }
}

impl HttpCanvasCredentialsValidationTransport {
    #[must_use]
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
impl CanvasCredentialsValidationTransport for HttpCanvasCredentialsValidationTransport {
    async fn get(
        &self,
        api_origin: &str,
        validation_url: &str,
        token: &str,
    ) -> Result<CanvasCredentialsProviderResponse, CanvasCredentialsTransportError> {
        use CanvasCredentialsTransportError::Request;
        let target = Url::parse(validation_url).map_err(|_| Request)?;
        if target.origin() != Url::parse(api_origin).map_err(|_| Request)?.origin() {
            return Err(Request);
        }
        let mut headers = http::HeaderMap::new();
        headers.insert(ACCEPT, http::HeaderValue::from_static("application/json"));
        headers.insert(
            AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| Request)?,
        );
        let mut response = self
            .client
            .send(http::Method::GET, target, headers, Vec::new())
            .await
            .map_err(|_| Request)?;
        let status_code = response.response.status().as_u16();
        let request_id = response
            .response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let content_type = response.content_type();
        let body = if (200..300).contains(&status_code) {
            // Published HTTPX get() consumes the body before returning. Drain
            // without retaining it: headers alone cannot attest success when a
            // later read stalls or the peer truncates the response.
            while response.chunk().await.map_err(|_| Request)?.is_some() {}
            bytes::Bytes::new()
        } else {
            // HTTPX consumes the entire response before JSON/excerpt projection.
            // The excerpt limit is not a response-read cutoff or a JSON limit.
            response.bytes().await.map_err(|_| Request)?
        };
        CanvasCredentialsProviderResponse::from_body(
            status_code,
            request_id,
            &body,
            content_type.as_deref(),
        )
        .map_err(Into::into)
    }
}

fn map_text<'value>(value: &'value Map<String, Value>, key: &str) -> Option<&'value str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn encoded_path_segment(value: &str) -> String {
    let mut url = Url::parse("https://encoding.invalid/").expect("static URL");
    url.path_segments_mut()
        .expect("hierarchical URL")
        .push(value);
    url.path().trim_start_matches('/').to_owned()
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use serde_json::json;

    use super::*;

    fn failure_excerpt(
        bytes: &[u8],
        content_type: Option<&str>,
    ) -> Result<Map<String, Value>, CanvasResponseTextError> {
        super::failure_excerpt(bytes, content_type).map(|value| {
            value
                .to_scalar()
                .expect("existing excerpt fixtures are scalar")
                .as_object()
                .unwrap()
                .clone()
        })
    }

    #[tokio::test]
    async fn response_decoder_errors_and_success_bypass_use_actual_http_transport() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let scenarios: Value = serde_json::from_str(include_str!(
            "../../../../contracts/canvas-validation-boundary-scenarios.json"
        ))
        .unwrap();
        let oracle: Value = serde_json::from_str(include_str!(
            "../../../../contracts/canvas-validation-boundary-oracle.json"
        ))
        .unwrap();
        let mut count = 0;
        for (case, expected) in scenarios["cases"]
            .as_array()
            .unwrap()
            .iter()
            .zip(oracle["observations"].as_array().unwrap())
        {
            let Some(encoded) = case["response_hex"].as_str() else {
                continue;
            };
            count += 1;
            assert_eq!(case["name"], expected["name"]);
            let body = hex::decode(encoded).unwrap();
            let status = case["response_status"].as_u64().unwrap();
            let content_type = case["response_content_type"].as_str().unwrap().to_owned();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") {
                    socket.read_exact(&mut byte).await.unwrap();
                    request.push(byte[0]);
                    assert!(request.len() < 8192);
                }
                socket.write_all(format!("HTTP/1.1 {status} Synthetic\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nx-request-id: synthetic-provider\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
                socket.write_all(&body).await.unwrap();
            });
            let transport = HttpCanvasCredentialsValidationTransport::with_operation_timeout(
                CanvasOriginPolicy {
                    allow_http_localhost: true,
                    ..Default::default()
                },
                CanvasNetworkTimeout::from_seconds(2.0),
            );
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                transport.get(&origin, &origin, "synthetic-token"),
            )
            .await
            .unwrap();
            if expected["status"] == 500 {
                assert!(
                    matches!(
                        result,
                        Err(CanvasCredentialsTransportError::ResponseText(_))
                    ),
                    "decoder failure must remain distinct from a network failure: {}",
                    case["name"]
                );
            } else {
                let response = result.unwrap();
                assert_eq!(u64::from(response.status_code), status);
                assert_eq!(response.request_id.as_deref(), Some("synthetic-provider"));
                assert_eq!(
                    serde_json::to_value(response.response_excerpt).unwrap(),
                    expected["body"]["response_excerpt"],
                    "{}",
                    case["name"]
                );
            }
            tokio::time::timeout(std::time::Duration::from_secs(5), server)
                .await
                .unwrap()
                .unwrap();
        }
        assert_eq!(count, 27);
    }

    #[tokio::test]
    async fn failure_body_completion_and_json_are_not_limited_by_excerpt_buffer() {
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for mode in [
            "json_exact",
            "json_large",
            "text_large",
            "latin1",
            "stalled",
            "truncated",
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") {
                    socket.read_exact(&mut byte).await.unwrap();
                    request.push(byte[0]);
                    assert!(request.len() < 8192);
                }
                let payload = br#"{"late":true}"#;
                let body = if mode == "latin1" {
                    vec![0xe9; 1001]
                } else if mode == "text_large" {
                    vec![b'x'; 65537]
                } else {
                    let count = if mode == "json_exact" {
                        65536 - payload.len()
                    } else {
                        65537
                    };
                    let mut body = vec![b' '; count];
                    body.extend_from_slice(payload);
                    body
                };
                let content_type = if mode == "latin1" {
                    "text/plain; charset=latin1"
                } else {
                    "application/json"
                };
                socket.write_all(format!("HTTP/1.1 403 Forbidden\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
                if matches!(mode, "stalled" | "truncated") {
                    socket.write_all(&body[..65537]).await.unwrap();
                    if mode == "stalled" {
                        assert_eq!(socket.read(&mut byte).await.unwrap(), 0);
                    }
                } else {
                    socket.write_all(&body).await.unwrap();
                }
            });
            let transport = HttpCanvasCredentialsValidationTransport::with_operation_timeout(
                CanvasOriginPolicy {
                    allow_http_localhost: true,
                    ..Default::default()
                },
                CanvasNetworkTimeout::from_seconds(0.2),
            );
            let result = tokio::time::timeout(
                Duration::from_secs(3),
                transport.get(&origin, &origin, "synthetic-token"),
            )
            .await
            .unwrap();
            if matches!(mode, "stalled" | "truncated") {
                assert!(
                    result.is_err(),
                    "{mode} body must fail even after the old excerpt limit"
                );
            } else {
                let response = result.unwrap();
                assert_eq!(response.status_code, 403);
                let expected = if mode == "text_large" {
                    json!({"body_excerpt":format!("{}…", "x".repeat(1000))})
                } else if mode == "latin1" {
                    json!({"body_excerpt":format!("{}…", "é".repeat(1000))})
                } else {
                    json!({"late":true})
                };
                assert_eq!(
                    serde_json::to_value(&response.response_excerpt).unwrap(),
                    expected,
                    "{mode}"
                );
            }
            tokio::time::timeout(Duration::from_secs(3), server)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn successful_status_requires_complete_body_with_progress_deadlines() {
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        for mode in ["progress", "truncated", "stalled", "compressed_invalid"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") {
                    socket.read_exact(&mut byte).await.unwrap();
                    request.push(byte[0]);
                    assert!(request.len() < 8192);
                }
                if mode == "compressed_invalid" {
                    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 6\r\n\r\nresult").await.unwrap();
                    return;
                }
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nx-request-id: synthetic-body\r\n\r\nr").await.unwrap();
                if mode == "progress" {
                    for byte in b"esult" {
                        tokio::time::sleep(Duration::from_millis(75)).await;
                        socket.write_all(&[*byte]).await.unwrap();
                    }
                } else if mode == "stalled" {
                    // Only the owned client can close this incomplete response.
                    assert_eq!(socket.read(&mut byte).await.unwrap(), 0);
                }
            });
            let transport = HttpCanvasCredentialsValidationTransport::with_operation_timeout(
                CanvasOriginPolicy {
                    allow_http_localhost: true,
                    ..Default::default()
                },
                CanvasNetworkTimeout::from_seconds(0.2),
            );
            let result = tokio::time::timeout(
                Duration::from_secs(3),
                transport.get(&origin, &origin, "synthetic-token"),
            )
            .await
            .unwrap();
            if mode == "progress" {
                let response = result.unwrap();
                assert_eq!(response.status_code, 200);
                assert_eq!(response.request_id.as_deref(), Some("synthetic-body"));
                assert!(response.response_excerpt.is_none());
            } else {
                assert!(
                    result.is_err(),
                    "{mode} response must not report validation success"
                );
            }
            tokio::time::timeout(Duration::from_secs(3), server)
                .await
                .unwrap()
                .unwrap();
        }
    }

    struct CountingOperatorFile(std::sync::atomic::AtomicUsize);
    #[async_trait]
    impl CanvasOperatorSecretReader for CountingOperatorFile {
        async fn read(&self, path: &str) -> Result<Vec<u8>, std::io::Error> {
            assert_eq!(path, "/synthetic/operator-token");
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(b"synthetic-file-token\n".to_vec())
        }
    }

    #[tokio::test]
    async fn lazy_operator_file_does_not_weaken_canonical_tenant_validation_policy() {
        let reader = Arc::new(CountingOperatorFile(std::sync::atomic::AtomicUsize::new(0)));
        let mut service = CanvasCredentialsValidationService::new(
            CanvasCredentialsValidationConfig {
                operator_api_token_file: Some("/synthetic/operator-token".into()),
                publish_url: Some("https://bridge.example/publish".into()),
                ..Default::default()
            },
            Arc::new(Secret(None)),
            Arc::new(Transport::default()),
        );
        service.operator_secrets = reader.clone();
        assert_eq!(reader.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        let empty = service.validate("org-review", &Map::new()).await.unwrap();
        assert!(empty.ok && empty.token_configured);
        assert_eq!(reader.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        let canonical = json!({"provider":"bridge","api_token_secret_id":"missing"});
        let nonempty = service
            .validate("org-review", canonical.as_object().unwrap())
            .await
            .unwrap();
        assert!(nonempty.ok && !nonempty.token_configured);
        assert_eq!(
            reader.0.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "nonempty tenant configuration must not fall back to operator file"
        );
    }

    #[derive(Debug)]
    struct Secret(Option<String>);

    struct InvalidOperatorFile;

    #[async_trait]
    impl CanvasOperatorSecretReader for InvalidOperatorFile {
        async fn read(&self, _: &str) -> Result<Vec<u8>, std::io::Error> {
            Ok(vec![0xff])
        }
    }

    #[tokio::test]
    async fn invalid_operator_utf8_returns_typed_error_without_provider_http() {
        let transport = Arc::new(Transport::default());
        let config = CanvasCredentialsValidationConfig {
            operator_api_token_file: Some("/synthetic/private-token-path".into()),
            ..Default::default()
        };
        assert!(!format!("{config:?}").contains("private-token-path"));
        let mut service = CanvasCredentialsValidationService::new(
            config,
            Arc::new(Secret(None)),
            transport.clone(),
        );
        service.operator_secrets = Arc::new(InvalidOperatorFile);
        let result = service.validate("org-review", &Map::new()).await;
        assert_eq!(
            result,
            Err(CanvasCredentialsValidationError::OperatorSecret(
                CanvasOperatorSecretError::InvalidUtf8
            ))
        );
        assert!(transport.calls.lock().unwrap().is_empty());
    }

    #[async_trait]
    impl CanvasCredentialsSecretResolver for Secret {
        async fn secret_value(
            &self,
            _organization_id: &str,
            _secret_id: &str,
        ) -> Result<Option<String>, ()> {
            Ok(self.0.clone())
        }
    }

    #[derive(Debug, Default)]
    struct Transport {
        calls: Mutex<Vec<(String, String, String)>>,
        status: u16,
    }

    #[async_trait]
    impl CanvasCredentialsValidationTransport for Transport {
        async fn get(
            &self,
            origin: &str,
            url: &str,
            token: &str,
        ) -> Result<CanvasCredentialsProviderResponse, CanvasCredentialsTransportError> {
            self.calls
                .lock()
                .unwrap()
                .push((origin.to_owned(), url.to_owned(), token.to_owned()));
            Ok(CanvasCredentialsProviderResponse {
                status_code: self.status,
                request_id: Some("request-1".to_owned()),
                response_excerpt: Some(LosslessJson::Object(crate::lossless_json::object(
                    json!({"error": "denied"})
                        .as_object()
                        .expect("object")
                        .clone(),
                ))),
            })
        }
    }

    fn credentials(provider: &str) -> Map<String, Value> {
        json!({
            "provider": provider,
            "api_base_url": "https://badgr.example/api",
            "badgeclass_id": "badge/class 1",
            "api_token_secret_id": "secret-1"
        })
        .as_object()
        .unwrap()
        .clone()
    }

    #[tokio::test]
    async fn real_provider_is_allowlisted_encoded_bounded_and_safe() {
        let transport = Arc::new(Transport {
            status: 403,
            ..Transport::default()
        });
        let service = CanvasCredentialsValidationService::new(
            CanvasCredentialsValidationConfig {
                allowed_api_origins: vec!["https://badgr.example".to_owned()],
                ..CanvasCredentialsValidationConfig::default()
            },
            Arc::new(Secret(Some("sensitive-token".to_owned()))),
            transport.clone(),
        );
        let result = service
            .validate("org-1", &credentials("badgr_api"))
            .await
            .unwrap();
        assert!(!result.ok);
        assert_eq!(result.status_code, Some(403));
        assert_eq!(result.request_id.as_deref(), Some("request-1"));
        assert_eq!(
            serde_json::to_value(&result.response_excerpt).unwrap(),
            json!({"error": "denied"})
        );
        let calls = transport.calls.lock().unwrap();
        assert_eq!(calls[0].0, "https://badgr.example");
        assert_eq!(
            calls[0].1,
            "https://badgr.example/api/v2/badgeclasses/badge%2Fclass%201"
        );
        assert_eq!(calls[0].2, "sensitive-token");
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains("sensitive-token"));
        assert!(!serialized.contains("secret-1"));
    }

    #[tokio::test]
    async fn real_provider_accepts_a_successful_bounded_probe() {
        let transport = Arc::new(Transport {
            status: 204,
            ..Transport::default()
        });
        let service = CanvasCredentialsValidationService::new(
            CanvasCredentialsValidationConfig {
                allowed_api_origins: vec!["https://badgr.example".to_owned()],
                ..CanvasCredentialsValidationConfig::default()
            },
            Arc::new(Secret(Some("sensitive-token".to_owned()))),
            transport.clone(),
        );

        let result = service
            .validate("org-1", &credentials("badgr_api"))
            .await
            .unwrap();

        assert!(result.ok);
        assert_eq!(result.status_code, Some(204));
        assert_eq!(result.request_id.as_deref(), Some("request-1"));
        assert!(result.error.is_none());
        assert!(result.response_excerpt.is_none());
        assert_eq!(transport.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn bridge_and_invalid_real_configuration_return_safe_results_without_transport() {
        let transport = Arc::new(Transport::default());
        let bridge = CanvasCredentialsValidationService::new(
            CanvasCredentialsValidationConfig::default(),
            Arc::new(Secret(Some("token".to_owned()))),
            transport.clone(),
        )
        .validate("org-1", &credentials("bridge"))
        .await
        .unwrap();
        assert!(!bridge.ok);
        assert_eq!(
            bridge.error.as_deref(),
            Some("CANVAS_CREDENTIALS_PUBLISH_URL is not configured")
        );

        let foreign_origin = CanvasCredentialsValidationService::new(
            CanvasCredentialsValidationConfig::default(),
            Arc::new(Secret(Some("token".to_owned()))),
            transport.clone(),
        )
        .validate("org-1", &credentials("badgr_api"))
        .await
        .unwrap();
        assert!(!foreign_origin.ok);
        assert!(foreign_origin.error.unwrap().contains("ALLOWLIST"));
        assert!(transport.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn empty_tenant_configuration_uses_only_the_fixed_operator_secret() {
        let transport = Arc::new(Transport::default());
        let result = CanvasCredentialsValidationService::new(
            CanvasCredentialsValidationConfig {
                operator_api_token: Some("operator-token".to_owned()),
                publish_url: Some("https://bridge.example/publish".to_owned()),
                ..CanvasCredentialsValidationConfig::default()
            },
            Arc::new(Secret(None)),
            transport.clone(),
        )
        .validate("org-1", &Map::new())
        .await
        .unwrap();
        assert!(result.ok);
        assert_eq!(result.provider, "bridge");
        assert!(result.token_configured);
        assert_eq!(
            result.validation_url.as_deref(),
            Some("https://bridge.example/publish")
        );
        assert!(transport.calls.lock().unwrap().is_empty());
        assert!(!serde_json::to_string(&result)
            .unwrap()
            .contains("operator-token"));
    }

    #[test]
    fn failure_excerpts_preserve_objects_wrap_arrays_and_bound_text() {
        assert_eq!(
            failure_excerpt(br#"{"error":"denied"}"#, None).unwrap(),
            json!({"error": "denied"}).as_object().unwrap().clone()
        );
        assert_eq!(
            failure_excerpt(br#"["one","two"]"#, None).unwrap(),
            json!({"payload": ["one", "two"]})
                .as_object()
                .unwrap()
                .clone()
        );
        let excerpt = failure_excerpt(&vec![b'x'; MAX_EXCERPT_CHARS + 50], None).unwrap();
        let body = excerpt["body_excerpt"].as_str().unwrap();
        assert_eq!(body.chars().count(), MAX_EXCERPT_CHARS + 1);
        assert!(body.ends_with('…'));
    }
}
