//! Safe, reusable Canvas Credentials provider configuration validation.
//!
//! The management route and the eventual native delivery worker share these
//! provider, URL, secret-resolution, and response-projection rules. Validation
//! is read-only: it may perform a bounded provider GET, but never publishes or
//! mutates a credential.

use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use chrono::Utc;
use reqwest::header::{ACCEPT, AUTHORIZATION};
use serde::Serialize;
use serde_json::{Map, Value};
use url::Url;

use crate::canvas_provider_http::{client_for_canvas_origin, CanvasHttpClientPolicy};

const DEFAULT_API_BASE_URL: &str = "https://api.badgr.io";
const MAX_FAILURE_BODY_BYTES: usize = 64 * 1024;
const MAX_EXCERPT_CHARS: usize = 1_000;

#[derive(Clone, Default, Eq, PartialEq)]
pub struct CanvasCredentialsValidationConfig {
    pub operator_api_token: Option<String>,
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
    pub response_excerpt: Option<Map<String, Value>>,
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
    pub response_excerpt: Option<Map<String, Value>>,
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
    ) -> Result<CanvasCredentialsProviderResponse, ()>;
}

#[async_trait]
pub trait CanvasCredentialsValidator: Send + Sync {
    async fn validate(
        &self,
        organization_id: &str,
        canvas_credentials: &Map<String, Value>,
    ) -> CanvasCredentialsValidationResult;
}

#[derive(Clone)]
pub struct CanvasCredentialsValidationService {
    config: CanvasCredentialsValidationConfig,
    allowed_origins: Arc<BTreeSet<String>>,
    secrets: Arc<dyn CanvasCredentialsSecretResolver>,
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
            transport,
        }
    }

    async fn token(
        &self,
        organization_id: &str,
        canvas_credentials: &Map<String, Value>,
    ) -> Option<String> {
        if canvas_credentials.is_empty() {
            return self
                .config
                .operator_api_token
                .clone()
                .filter(|value| !value.is_empty());
        }
        let secret_id = map_text(canvas_credentials, "api_token_secret_id")?;
        self.secrets
            .secret_value(organization_id, secret_id)
            .await
            .ok()
            .flatten()
            .filter(|value| !value.is_empty())
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
        match configured.as_str() {
            "badgr" | "canvas_credentials" | "credentials_api" | "canvas" => "badgr_api".to_owned(),
            "sandbox" | "proxy" | "bridge_api" => "bridge".to_owned(),
            _ => configured,
        }
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
    ) -> CanvasCredentialsValidationResult {
        let provider = self.provider(canvas_credentials);
        let token = self.token(organization_id, canvas_credentials).await;
        if provider == "bridge" {
            let mut result = CanvasCredentialsValidationResult::empty(provider);
            result.token_configured = token.is_some();
            let Some(publish_url) = self.config.publish_url.clone() else {
                result.error = Some("CANVAS_CREDENTIALS_PUBLISH_URL is not configured".to_owned());
                return result;
            };
            result.ok = true;
            result.validation_url = Some(publish_url);
            return result;
        }
        if !matches!(provider.as_str(), "badgr_api" | "canvas_credentials_api") {
            let mut result = CanvasCredentialsValidationResult::empty(&provider);
            result.error = Some(format!(
                "Unsupported Canvas Credentials provider: {provider}"
            ));
            return result;
        }

        let mut result = CanvasCredentialsValidationResult::empty(&provider);
        let (api_base_url, api_origin) = match self.base_url(canvas_credentials) {
            Ok(value) => value,
            Err(error) => {
                result.api_base_url = map_text(canvas_credentials, "api_base_url")
                    .map(str::to_owned)
                    .or_else(|| self.config.api_base_url.clone())
                    .or_else(|| Some(DEFAULT_API_BASE_URL.to_owned()));
                result.token_configured = token.is_some();
                result.error = Some(error);
                return result;
            }
        };
        result.api_base_url = Some(api_base_url.clone());
        let scope = match self.assertion_scope(canvas_credentials) {
            Ok(scope) => scope,
            Err(error) => {
                result.token_configured = token.is_some();
                result.error = Some(error);
                return result;
            }
        };
        result.assertion_scope = Some(scope.clone());
        result.issuer_id = map_text(canvas_credentials, "issuer_id")
            .map(str::to_owned)
            .or_else(|| self.config.issuer_id.clone());
        result.badgeclass_id = map_text(canvas_credentials, "badgeclass_id")
            .map(str::to_owned)
            .or_else(|| self.config.badgeclass_id.clone());
        if result.badgeclass_id.is_none() {
            result.token_configured = token.is_some();
            result.error = Some(
                "CANVAS_CREDENTIALS_BADGECLASS_ID is required for real Canvas Credentials publish"
                    .to_owned(),
            );
            return result;
        }
        let validation_url = match self.validation_url(
            &api_base_url,
            &scope,
            result.issuer_id.as_deref(),
            result.badgeclass_id.as_deref(),
        ) {
            Ok(url) => url,
            Err(error) => {
                result.token_configured = token.is_some();
                result.error = Some(error);
                return result;
            }
        };
        result.validation_url = Some(validation_url.clone());
        let Some(token) = token else {
            result.error = Some(
                "CANVAS_CREDENTIALS_API_TOKEN is required for Canvas Credentials validation"
                    .to_owned(),
            );
            return result;
        };
        result.token_configured = true;
        let response = match self
            .transport
            .get(&api_origin, &validation_url, &token)
            .await
        {
            Ok(response) => response,
            Err(()) => {
                result.error = Some("Canvas Credentials validation request failed".to_owned());
                return result;
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
        result
    }
}

#[derive(Clone)]
pub struct HttpCanvasCredentialsValidationTransport {
    policy: CanvasHttpClientPolicy,
}

impl std::fmt::Debug for HttpCanvasCredentialsValidationTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpCanvasCredentialsValidationTransport")
            .field("policy", &self.policy)
            .finish()
    }
}

impl HttpCanvasCredentialsValidationTransport {
    #[must_use]
    pub fn new(policy: CanvasHttpClientPolicy) -> Self {
        Self { policy }
    }
}

#[async_trait]
impl CanvasCredentialsValidationTransport for HttpCanvasCredentialsValidationTransport {
    async fn get(
        &self,
        api_origin: &str,
        validation_url: &str,
        token: &str,
    ) -> Result<CanvasCredentialsProviderResponse, ()> {
        let (client, _) = client_for_canvas_origin(api_origin, &self.policy).await?;
        let mut response = client
            .get(validation_url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .send()
            .await
            .map_err(|_| ())?;
        let status_code = response.status().as_u16();
        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let response_excerpt = if (200..300).contains(&status_code) {
            None
        } else {
            Some(read_failure_excerpt(&mut response).await?)
        };
        Ok(CanvasCredentialsProviderResponse {
            status_code,
            request_id,
            response_excerpt,
        })
    }
}

async fn read_failure_excerpt(response: &mut reqwest::Response) -> Result<Map<String, Value>, ()> {
    let mut bytes = Vec::new();
    let mut truncated = response
        .content_length()
        .is_some_and(|length| length > MAX_FAILURE_BODY_BYTES as u64);
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        let remaining = MAX_FAILURE_BODY_BYTES.saturating_sub(bytes.len());
        if chunk.len() > remaining {
            bytes.extend_from_slice(&chunk[..remaining]);
            truncated = true;
            break;
        }
        bytes.extend_from_slice(&chunk);
        if bytes.len() == MAX_FAILURE_BODY_BYTES {
            truncated = true;
            break;
        }
    }
    Ok(failure_excerpt(&bytes, truncated))
}

fn failure_excerpt(bytes: &[u8], truncated: bool) -> Map<String, Value> {
    if !truncated {
        if let Ok(Value::Object(object)) = serde_json::from_slice::<Value>(bytes) {
            return object;
        }
        if let Ok(payload) = serde_json::from_slice::<Value>(bytes) {
            return Map::from_iter([("payload".to_owned(), payload)]);
        }
    }
    let mut body = String::from_utf8_lossy(bytes)
        .chars()
        .take(MAX_EXCERPT_CHARS)
        .collect::<String>();
    if truncated || String::from_utf8_lossy(bytes).chars().count() > MAX_EXCERPT_CHARS {
        body.push('…');
    }
    Map::from_iter([("body_excerpt".to_owned(), Value::String(body))])
}

fn map_text<'value>(value: &'value Map<String, Value>, key: &str) -> Option<&'value str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn https_origin(value: &str) -> Option<String> {
    let parsed = Url::parse(value.trim()).ok()?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return None;
    }
    let host = parsed.host_str()?.to_ascii_lowercase();
    Some(match parsed.port() {
        Some(port) => format!("https://{host}:{port}"),
        None => format!("https://{host}"),
    })
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

    #[derive(Debug)]
    struct Secret(Option<String>);

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
        ) -> Result<CanvasCredentialsProviderResponse, ()> {
            self.calls
                .lock()
                .unwrap()
                .push((origin.to_owned(), url.to_owned(), token.to_owned()));
            Ok(CanvasCredentialsProviderResponse {
                status_code: self.status,
                request_id: Some("request-1".to_owned()),
                response_excerpt: Some(
                    json!({"error": "denied"})
                        .as_object()
                        .expect("object")
                        .clone(),
                ),
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
        let result = service.validate("org-1", &credentials("badgr_api")).await;
        assert!(!result.ok);
        assert_eq!(result.status_code, Some(403));
        assert_eq!(result.request_id.as_deref(), Some("request-1"));
        assert_eq!(
            result.response_excerpt,
            json!({"error": "denied"}).as_object().cloned()
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

        let result = service.validate("org-1", &credentials("badgr_api")).await;

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
        .await;
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
        .await;
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
        .await;
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
            failure_excerpt(br#"{"error":"denied"}"#, false),
            json!({"error": "denied"}).as_object().unwrap().clone()
        );
        assert_eq!(
            failure_excerpt(br#"["one","two"]"#, false),
            json!({"payload": ["one", "two"]})
                .as_object()
                .unwrap()
                .clone()
        );
        let excerpt = failure_excerpt(&vec![b'x'; MAX_EXCERPT_CHARS + 50], true);
        let body = excerpt["body_excerpt"].as_str().unwrap();
        assert_eq!(body.chars().count(), MAX_EXCERPT_CHARS + 1);
        assert!(body.ends_with('…'));
    }
}
