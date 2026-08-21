use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use marty_oid4vci::oidc::{validate_id_token, OidcIdTokenPolicy, OidcValidationError};
use serde_json::Value;
use tokio::sync::Mutex;
use url::Url;

use crate::{
    OidcAuthorizationRequest, OidcCodeExchange, OidcLogoutRequest, OidcProvider, OidcTokenSet,
    OidcUserInfo, OidcValidatedIdentity, PortError,
};

pub const OIDC_DISCOVERY_MAX_BYTES: usize = 256 * 1024;
pub const OIDC_JWKS_MAX_BYTES: usize = 1024 * 1024;
pub const OIDC_TOKEN_RESPONSE_MAX_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub external_issuer_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub allowed_algorithms: Vec<String>,
    pub leeway_seconds: u64,
    pub jwks_cache_seconds: u64,
}

impl OidcConfig {
    pub fn validate(mut self) -> Result<Self, PortError> {
        self.issuer_url = normalize_issuer(&self.issuer_url, "internal issuer")?;
        self.external_issuer_url = normalize_issuer(&self.external_issuer_url, "external issuer")?;
        if self.client_id.trim().is_empty() {
            return Err(config_error("OIDC client ID is required"));
        }
        if self.redirect_uri.trim().is_empty() {
            return Err(config_error("OIDC redirect URI is required"));
        }
        Url::parse(&self.redirect_uri)
            .map_err(|error| config_error(format!("OIDC redirect URI is invalid: {error}")))?;
        if self.scopes.is_empty() || self.scopes.iter().any(|scope| scope.trim().is_empty()) {
            return Err(config_error("OIDC scopes must contain non-empty values"));
        }
        if self.allowed_algorithms.is_empty() {
            return Err(config_error(
                "OIDC allowed algorithm list must not be empty",
            ));
        }
        let unique = self
            .allowed_algorithms
            .iter()
            .collect::<std::collections::HashSet<_>>();
        if unique.len() != self.allowed_algorithms.len() {
            return Err(config_error("OIDC allowed algorithms must be unique"));
        }
        if self.leeway_seconds > 300 {
            return Err(config_error(
                "OIDC clock leeway must be between 0 and 300 seconds",
            ));
        }
        if !(1..=3_600).contains(&self.jwks_cache_seconds) {
            return Err(config_error(
                "OIDC JWKS cache duration must be between 1 and 3600 seconds",
            ));
        }
        Ok(self)
    }

    #[must_use]
    pub fn authorization_endpoint(&self) -> String {
        format!("{}/protocol/openid-connect/auth", self.external_issuer_url)
    }

    #[must_use]
    pub fn registration_endpoint(&self) -> String {
        format!(
            "{}/protocol/openid-connect/registrations",
            self.external_issuer_url
        )
    }

    #[must_use]
    pub fn token_endpoint(&self) -> String {
        format!("{}/protocol/openid-connect/token", self.issuer_url)
    }

    #[must_use]
    pub fn logout_endpoint(&self) -> String {
        format!(
            "{}/protocol/openid-connect/logout",
            self.external_issuer_url
        )
    }

    #[must_use]
    pub fn discovery_endpoint(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.issuer_url)
    }
}

fn normalize_issuer(value: &str, name: &str) -> Result<String, PortError> {
    let normalized = value.trim_end_matches('/');
    let parsed = Url::parse(normalized)
        .map_err(|error| config_error(format!("OIDC {name} URL is invalid: {error}")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(config_error(format!(
            "OIDC {name} must be an absolute HTTP(S) URL"
        )));
    }
    Ok(normalized.to_owned())
}

fn config_error(message: impl Into<String>) -> PortError {
    PortError::new("invalid_oidc_configuration", message)
}

#[async_trait]
pub trait OidcHttpClient: Send + Sync {
    async fn get_json_object(
        &self,
        url: &str,
        max_bytes: usize,
        document_name: &str,
    ) -> Result<Value, PortError>;

    async fn post_form_json_object(
        &self,
        url: &str,
        form: &[(String, String)],
        max_bytes: usize,
        document_name: &str,
    ) -> Result<Value, PortError>;
}

#[async_trait]
pub trait ExchangedTokenValidator: Send + Sync {
    async fn validate_exchanged_identity(
        &self,
        tokens: &Value,
        expected_audience: &str,
    ) -> Result<Option<OidcValidatedIdentity>, PortError>;
}

#[derive(Clone)]
pub struct ReqwestOidcHttpClient {
    client: reqwest::Client,
}

impl ReqwestOidcHttpClient {
    pub fn new() -> Result<Self, PortError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| PortError::new("oidc_http_configuration_failed", error.to_string()))?;
        Ok(Self { client })
    }

    async fn bounded_json(
        mut response: reqwest::Response,
        max_bytes: usize,
        document_name: &str,
    ) -> Result<Value, PortError> {
        if !response.status().is_success() {
            return Err(PortError::new(
                "oidc_http_request_failed",
                format!("OIDC {document_name} returned HTTP {}", response.status()),
            ));
        }
        if response
            .content_length()
            .is_some_and(|length| length > max_bytes as u64)
        {
            return Err(PortError::new(
                "oidc_resource_limit",
                format!("OIDC {document_name} exceeds the size limit"),
            ));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|error| {
            PortError::new(
                "oidc_http_request_failed",
                format!("OIDC {document_name} read failed: {error}"),
            )
        })? {
            if body.len().saturating_add(chunk.len()) > max_bytes {
                return Err(PortError::new(
                    "oidc_resource_limit",
                    format!("OIDC {document_name} exceeds the size limit"),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&body).map_err(|error| {
            PortError::new(
                "invalid_oidc_json",
                format!("OIDC {document_name} is not valid JSON: {error}"),
            )
        })?;
        if !value.is_object() {
            return Err(PortError::new(
                "invalid_oidc_json",
                format!("OIDC {document_name} must be an object"),
            ));
        }
        Ok(value)
    }
}

#[async_trait]
impl OidcHttpClient for ReqwestOidcHttpClient {
    async fn get_json_object(
        &self,
        url: &str,
        max_bytes: usize,
        document_name: &str,
    ) -> Result<Value, PortError> {
        let response = self.client.get(url).send().await.map_err(|error| {
            PortError::new(
                "oidc_http_request_failed",
                format!("OIDC {document_name} request failed: {error}"),
            )
        })?;
        Self::bounded_json(response, max_bytes, document_name).await
    }

    async fn post_form_json_object(
        &self,
        url: &str,
        form: &[(String, String)],
        max_bytes: usize,
        document_name: &str,
    ) -> Result<Value, PortError> {
        let body = {
            let mut encoded = url::form_urlencoded::Serializer::new(String::new());
            for (name, value) in form {
                encoded.append_pair(name, value);
            }
            encoded.finish()
        };
        let response = self
            .client
            .post(url)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .map_err(|error| {
                PortError::new(
                    "oidc_http_request_failed",
                    format!("OIDC {document_name} request failed: {error}"),
                )
            })?;
        Self::bounded_json(response, max_bytes, document_name).await
    }
}

struct JwksCache {
    document: Option<Value>,
    expires_at: Instant,
}

pub struct KeycloakOidcProvider {
    config: OidcConfig,
    http: Arc<dyn OidcHttpClient>,
    jwks: Mutex<JwksCache>,
}

impl KeycloakOidcProvider {
    pub fn new(config: OidcConfig, http: Arc<dyn OidcHttpClient>) -> Result<Self, PortError> {
        Ok(Self {
            config: config.validate()?,
            http,
            jwks: Mutex::new(JwksCache {
                document: None,
                expires_at: Instant::now(),
            }),
        })
    }

    pub fn with_reqwest(config: OidcConfig) -> Result<Self, PortError> {
        Self::new(config, Arc::new(ReqwestOidcHttpClient::new()?))
    }

    async fn provider_jwks(&self, force_refresh: bool) -> Result<Value, PortError> {
        let mut cache = self.jwks.lock().await;
        if !force_refresh && cache.document.is_some() && Instant::now() < cache.expires_at {
            return Ok(cache.document.clone().expect("document checked as present"));
        }
        let jwks = self.fetch_provider_jwks().await?;
        cache.document = Some(jwks.clone());
        cache.expires_at = Instant::now() + Duration::from_secs(self.config.jwks_cache_seconds);
        Ok(jwks)
    }

    async fn fetch_provider_jwks(&self) -> Result<Value, PortError> {
        let discovery = self
            .http
            .get_json_object(
                &self.config.discovery_endpoint(),
                OIDC_DISCOVERY_MAX_BYTES,
                "discovery document",
            )
            .await?;
        let discovered_issuer = discovery
            .get("issuer")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim_end_matches('/');
        if discovered_issuer != self.config.external_issuer_url {
            return Err(PortError::new(
                "oidc_discovery_issuer_mismatch",
                "OIDC discovery issuer does not match configured issuer",
            ));
        }
        let jwks_uri = discovery
            .get("jwks_uri")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let internal_jwks_uri = self.trusted_internal_jwks_uri(jwks_uri)?;
        let jwks = self
            .http
            .get_json_object(
                internal_jwks_uri.as_str(),
                OIDC_JWKS_MAX_BYTES,
                "JWKS document",
            )
            .await?;
        if !jwks.get("keys").is_some_and(Value::is_array) {
            return Err(PortError::new(
                "invalid_oidc_jwks",
                "OIDC JWKS response is malformed",
            ));
        }
        Ok(jwks)
    }

    fn trusted_internal_jwks_uri(&self, jwks_uri: &str) -> Result<Url, PortError> {
        let expected = Url::parse(&self.config.external_issuer_url)
            .map_err(|error| config_error(error.to_string()))?;
        let discovered = Url::parse(jwks_uri).map_err(|_| {
            PortError::new(
                "invalid_oidc_jwks_uri",
                "OIDC jwks_uri must be an absolute HTTP(S) URL",
            )
        })?;
        if !matches!(discovered.scheme(), "http" | "https") {
            return Err(PortError::new(
                "invalid_oidc_jwks_uri",
                "OIDC jwks_uri must be an absolute HTTP(S) URL",
            ));
        }
        if discovered.origin() != expected.origin() {
            return Err(PortError::new(
                "untrusted_oidc_jwks_uri",
                "OIDC jwks_uri origin does not match configured issuer",
            ));
        }
        let issuer_path = expected.path().trim_end_matches('/');
        if !issuer_path.is_empty() && !discovered.path().starts_with(&format!("{issuer_path}/")) {
            return Err(PortError::new(
                "untrusted_oidc_jwks_uri",
                "OIDC jwks_uri is outside the configured issuer path",
            ));
        }
        let mut internal =
            Url::parse(&self.config.issuer_url).map_err(|error| config_error(error.to_string()))?;
        internal.set_path(discovered.path());
        internal.set_query(discovered.query());
        internal.set_fragment(None);
        Ok(internal)
    }

    async fn validate(
        &self,
        id_token: &str,
        expected_audience: &str,
        expected_nonce: Option<&str>,
        access_token: Option<&str>,
    ) -> Result<Value, PortError> {
        if expected_nonce.is_some_and(str::is_empty) {
            return Err(PortError::new(
                "oidc_nonce_required",
                "OIDC nonce is required",
            ));
        }
        let allowed = self
            .config
            .allowed_algorithms
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        for refreshed in [false, true] {
            let jwks = self.provider_jwks(refreshed).await?;
            let jwks_json = serde_json::to_string(&jwks).map_err(|error| {
                PortError::new(
                    "invalid_oidc_jwks",
                    format!("JWKS serialization failed: {error}"),
                )
            })?;
            let policy = OidcIdTokenPolicy {
                expected_issuer: &self.config.external_issuer_url,
                expected_audience,
                expected_nonce,
                access_token,
                allowed_algorithms: &allowed,
                leeway_seconds: self.config.leeway_seconds,
            };
            match validate_id_token(id_token, &jwks_json, &policy) {
                Ok(claims) => return Ok(claims),
                Err(OidcValidationError::KeyNotFound(_)) if !refreshed => {}
                Err(error) => {
                    return Err(PortError::new(
                        "oidc_token_validation_failed",
                        error.to_string(),
                    ));
                }
            }
        }
        Err(PortError::new(
            "oidc_token_validation_failed",
            "OIDC.KEY_NOT_FOUND: provider key was not found after refresh",
        ))
    }

    pub async fn validate_exchanged_tokens(
        &self,
        tokens: &Value,
        expected_audience: &str,
    ) -> Result<Option<OidcValidatedIdentity>, PortError> {
        let id_token = tokens
            .get("id_token")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let access_token = tokens
            .get("access_token")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if id_token.is_empty() && access_token.is_empty() {
            return Ok(None);
        }
        if id_token.is_empty() {
            return Err(PortError::new(
                "oidc_id_token_required",
                "OIDC token exchange requires a verifiable ID token",
            ));
        }
        let claims = self
            .validate(
                id_token,
                expected_audience,
                None,
                (!access_token.is_empty()).then_some(access_token),
            )
            .await?;
        let access_claims = Value::Object(serde_json::Map::new());
        Ok(Some(OidcValidatedIdentity {
            user_info: OidcUserInfo::from_claims(&claims, Some(&access_claims)),
            id_token_claims: claims,
            access_token_claims: access_claims,
        }))
    }
}

#[async_trait]
impl OidcProvider for KeycloakOidcProvider {
    fn authorization_url(&self, request: &OidcAuthorizationRequest) -> Result<String, PortError> {
        let endpoint = if request.registration {
            self.config.registration_endpoint()
        } else {
            self.config.authorization_endpoint()
        };
        let mut url = Url::parse(&endpoint).map_err(|error| config_error(error.to_string()))?;
        let redirect_uri = request
            .redirect_uri
            .as_deref()
            .unwrap_or(&self.config.redirect_uri);
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("response_type", "code")
                .append_pair("client_id", &self.config.client_id)
                .append_pair("redirect_uri", redirect_uri)
                .append_pair("scope", &self.config.scopes.join(" "))
                .append_pair("state", &request.state)
                .append_pair("nonce", &request.nonce)
                .append_pair("code_challenge", &request.code_challenge)
                .append_pair("code_challenge_method", "S256");
            if !request.registration {
                query.append_pair("prompt", "consent login");
            }
        }
        Ok(url.into())
    }

    async fn exchange_code(&self, request: &OidcCodeExchange) -> Result<OidcTokenSet, PortError> {
        let mut form = vec![
            ("grant_type".to_owned(), "authorization_code".to_owned()),
            ("code".to_owned(), request.code.clone()),
            (
                "redirect_uri".to_owned(),
                request
                    .redirect_uri
                    .clone()
                    .unwrap_or_else(|| self.config.redirect_uri.clone()),
            ),
            ("client_id".to_owned(), self.config.client_id.clone()),
            ("code_verifier".to_owned(), request.code_verifier.clone()),
        ];
        if let Some(secret) = &self.config.client_secret {
            form.push(("client_secret".to_owned(), secret.clone()));
        }
        let tokens = self
            .http
            .post_form_json_object(
                &self.config.token_endpoint(),
                &form,
                OIDC_TOKEN_RESPONSE_MAX_BYTES,
                "token response",
            )
            .await?;
        Ok(OidcTokenSet {
            access_token: tokens
                .get("access_token")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            id_token: tokens
                .get("id_token")
                .and_then(Value::as_str)
                .map(str::to_owned),
            refresh_token: tokens
                .get("refresh_token")
                .and_then(Value::as_str)
                .map(str::to_owned),
        })
    }

    async fn validate_tokens(
        &self,
        id_token: &str,
        access_token: &str,
        expected_nonce: &str,
    ) -> Result<OidcValidatedIdentity, PortError> {
        let claims = self
            .validate(
                id_token,
                &self.config.client_id,
                Some(expected_nonce),
                Some(access_token),
            )
            .await?;
        let access_claims = Value::Object(serde_json::Map::new());
        Ok(OidcValidatedIdentity {
            user_info: OidcUserInfo::from_claims(&claims, Some(&access_claims)),
            id_token_claims: claims,
            access_token_claims: access_claims,
        })
    }

    fn logout_url(&self, request: &OidcLogoutRequest) -> Result<Option<String>, PortError> {
        let mut url = Url::parse(&self.config.logout_endpoint())
            .map_err(|error| config_error(error.to_string()))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("client_id", &self.config.client_id);
            if let Some(id_token) = &request.id_token {
                query.append_pair("id_token_hint", id_token);
            }
            query.append_pair(
                "post_logout_redirect_uri",
                &request.post_logout_redirect_uri,
            );
        }
        Ok(Some(url.into()))
    }
}

#[async_trait]
impl ExchangedTokenValidator for KeycloakOidcProvider {
    async fn validate_exchanged_identity(
        &self,
        tokens: &Value,
        expected_audience: &str,
    ) -> Result<Option<OidcValidatedIdentity>, PortError> {
        self.validate_exchanged_tokens(tokens, expected_audience)
            .await
    }
}
