//! Canvas lifecycle provider candidate. Consumer cutover is separately gated.
//! Uses the published delivery configuration precedence; management validation
//! deliberately retains its stricter, canonical-tenant secret fallback policy.
use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use serde_json::{json, Map, Value};
use url::Url;

use crate::{
    canvas_credentials_protocol::{
        https_origin, provider_alias, quote_identifier, response_excerpt, truncate_text,
        DEFAULT_API_BASE_URL,
    },
    canvas_credentials_validation::{
        CanvasCredentialsSecretResolver, CanvasCredentialsValidationConfig,
    },
    canvas_lifecycle_delivery::{CanvasLifecycleCredential, CanvasLifecycleStatusProvider},
    canvas_provider_http::{client_for_canvas_origin, CanvasHttpClientPolicy},
    credential_management::{CredentialLifecycleAction, CredentialManagementPortError},
    python_value::{python_string, python_truthy, strip},
};

#[derive(Clone, Default, Eq, PartialEq)]
pub struct CanvasCredentialsStatusConfig {
    /// Already resolved by the operator configuration/secret owner. No tenant
    /// metadata can select an environment variable or a filesystem path.
    pub provider: CanvasCredentialsValidationConfig,
    /// Legacy operator fallback selects a URL but does not grant origin trust.
    pub legacy_api_base_url: Option<String>,
    pub status_sync_url: Option<String>,
    pub revoke_url_template: Option<String>,
    pub portable_enabled: bool,
    pub pilot_organizations: BTreeSet<String>,
}

impl std::fmt::Debug for CanvasCredentialsStatusConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CanvasCredentialsStatusConfig")
            .field("provider", &self.provider)
            .field(
                "legacy_api_base_url_configured",
                &self.legacy_api_base_url.is_some(),
            )
            .field(
                "status_sync_url_configured",
                &self.status_sync_url.is_some(),
            )
            .field(
                "revoke_url_template_configured",
                &self.revoke_url_template.is_some(),
            )
            .field("portable_enabled", &self.portable_enabled)
            .field("pilot_organization_count", &self.pilot_organizations.len())
            .finish()
    }
}

/// Deliberately not Debug: the token and credential payload are confidential.
pub struct CanvasStatusRequest {
    pub method: reqwest::Method,
    pub url: String,
    pub token: Option<String>,
    pub body: Value,
}

pub struct CanvasStatusResponse {
    pub status: u16,
    pub request_id: Option<String>,
    pub body: String,
}

#[async_trait]
pub trait CanvasStatusTransport: Send + Sync {
    /// Errors must be safe for durable public diagnostics, without raw client
    /// errors (which can contain URLs, credentials, or internal network details).
    async fn send(&self, request: CanvasStatusRequest) -> Result<CanvasStatusResponse, String>;
}

#[derive(Clone)]
pub struct CanvasCredentialsStatusService {
    config: CanvasCredentialsStatusConfig,
    secrets: Arc<dyn CanvasCredentialsSecretResolver>,
    transport: Arc<dyn CanvasStatusTransport>,
}

impl CanvasCredentialsStatusService {
    /// Shared runtime assembly, also exercised by the database + HTTP contract.
    /// Live consumer adoption remains a separate cutover gate.
    pub fn from_runtime(
        config: &crate::config::IssuanceServiceConfig,
        secrets: Arc<dyn CanvasCredentialsSecretResolver>,
    ) -> Self {
        Self::new(
            config.canvas_credentials_status.clone(),
            secrets,
            Arc::new(HttpCanvasStatusTransport::new(CanvasHttpClientPolicy {
                timeout: config.canvas_credentials_validation_timeout,
                private_origin_allowlist: config.canvas_private_origin_allowlist.clone(),
                allow_private_networks: config.canvas_allow_private_base_urls,
                allow_http_localhost: config.canvas_allow_http_localhost_base_urls,
            })),
        )
    }

    pub fn new(
        config: CanvasCredentialsStatusConfig,
        secrets: Arc<dyn CanvasCredentialsSecretResolver>,
        transport: Arc<dyn CanvasStatusTransport>,
    ) -> Self {
        Self {
            config,
            secrets,
            transport,
        }
    }

    async fn token(
        &self,
        organization: &str,
        sources: &[&Map<String, Value>],
    ) -> Result<Option<String>, CredentialManagementPortError> {
        for source in sources {
            let reference = [
                "api_token_secret_id",
                "api_token_secret_ref",
                "api_token_ref",
                "canvas_credentials_api_token_secret_id",
                "canvas_credentials_api_token_secret_ref",
            ]
            .iter()
            .filter_map(|key| source.get(*key))
            .find(|value| python_truthy(value))
            .and_then(python_string)
            .unwrap_or_default();
            let reference = strip(&reference);
            if reference.is_empty() {
                continue;
            }
            let identifier = if reference.starts_with("org_secret://") {
                reference
                    .trim_end_matches('/')
                    .rsplit('/')
                    .next()
                    .unwrap_or_default()
            } else {
                reference
            };
            // Lookup is always scoped by the verified delivery organization,
            // never by an organization component embedded in the reference.
            let token = self
                .secrets
                .secret_value(organization, identifier)
                .await
                .map_err(|()| error("Canvas Credentials secret lookup failed"))?;
            if let Some(token) = token.filter(|value| !value.is_empty()) {
                return Ok(Some(token));
            }
        }
        Ok(self
            .config
            .provider
            .operator_api_token
            .clone()
            .filter(|value| !value.is_empty()))
    }

    fn provider(&self, sources: &[&Map<String, Value>]) -> String {
        let raw = config_value(
            sources,
            &["provider", "canvas_credentials_provider"],
            self.config.provider.provider.as_deref(),
        )
        .to_lowercase();
        if raw.is_empty() {
            if self
                .config
                .provider
                .publish_url
                .as_deref()
                .is_some_and(|value| !strip(value).is_empty())
            {
                return "bridge".into();
            }
            if !config_value(
                sources,
                &["badgeclass_id", "canvas_credentials_badgeclass_id"],
                self.config.provider.badgeclass_id.as_deref(),
            )
            .is_empty()
            {
                return "badgr_api".into();
            }
            return "bridge".into();
        }
        provider_alias(raw)
    }

    fn base_url(
        &self,
        sources: &[&Map<String, Value>],
    ) -> Result<String, CredentialManagementPortError> {
        let configured = config_value(
            sources,
            &[
                "api_base_url",
                "base_url",
                "canvas_credentials_api_base_url",
                "canvas_credentials_base_url",
            ],
            self.config
                .provider
                .api_base_url
                .as_deref()
                .filter(|value| !strip(value).is_empty())
                .or(self.config.legacy_api_base_url.as_deref()),
        );
        let value = if configured.is_empty() {
            DEFAULT_API_BASE_URL
        } else {
            &configured
        }
        .trim_end_matches('/');
        let invalid = || error("Canvas Credentials API base URL must be a trusted HTTPS URL");
        let parsed = Url::parse(value).map_err(|_| invalid())?;
        let origin = https_origin(value).ok_or_else(invalid)?;
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(invalid());
        }
        let allowed = std::iter::once(DEFAULT_API_BASE_URL)
            .chain(self.config.provider.api_base_url.as_deref())
            .chain(
                self.config
                    .provider
                    .allowed_api_origins
                    .iter()
                    .map(String::as_str),
            )
            .filter_map(https_origin)
            .any(|candidate| candidate == origin);
        if !allowed {
            return Err(error(
                "Canvas Credentials API origin is not in CANVAS_CREDENTIALS_API_ORIGIN_ALLOWLIST",
            ));
        }
        Ok(value.into())
    }
}

#[async_trait]
impl CanvasLifecycleStatusProvider for CanvasCredentialsStatusService {
    async fn synchronize(
        &self,
        context: CanvasLifecycleCredential<'_>,
        platform: &Value,
        delivery: &Value,
        action: CredentialLifecycleAction,
        reason: Option<&str>,
    ) -> Result<Map<String, Value>, CredentialManagementPortError> {
        let credential = context.credential;
        let organization = delivery["organization_id"].as_str().unwrap_or_default();
        if !self.config.portable_enabled
            || strip(organization).is_empty()
            || !self
                .config
                .pilot_organizations
                .contains(strip(organization))
        {
            return Err(error(
                "Portable Canvas delivery is not enabled for this organization",
            ));
        }
        if strip(organization).is_empty()
            || strip(organization) != strip(&credential.organization_id)
            || strip(organization)
                != strip(platform["organization_id"].as_str().unwrap_or_default())
            || delivery["credential_id"].as_str() != Some(credential.id.as_str())
            || delivery["transaction_id"].as_str() != Some(context.transaction_id)
        {
            return Err(error("Canvas delivery resources are unavailable"));
        }
        let sources = metadata_sources(&delivery["metadata"]);
        let real_provider = matches!(
            self.provider(&sources).as_str(),
            "badgr_api" | "canvas_credentials_api"
        );
        if real_provider && action != CredentialLifecycleAction::Revoke {
            return Ok(object(
                json!({"provider":"badgr_api", "status_sync_mode":"canonical_provenance_only",
                "status_sync_skipped":true, "status_sync_reason":"Canvas Credentials API does not expose suspend/reinstate operations; canonical ElevenID status and provenance remain authoritative.",
                "status_synced_at":chrono::Utc::now().to_rfc3339(),
                "canvas_credentials_lifecycle_mapping":{"requested_action":action.as_str(),"external_action":null,"canonical_status":credential.status.as_str()}}),
            ));
        }
        let (method, url, token, payload, operation) = if real_provider {
            let external_id = delivery["external_credential_id"]
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    error("Canvas Credentials revoke requires external_credential_id")
                })?;
            let token = self.token(organization, &sources).await?.ok_or_else(|| error("CANVAS_CREDENTIALS_API_TOKEN is required for real Canvas Credentials status sync"))?;
            let base = self.base_url(&sources)?;
            let identifier = quote_identifier(external_id);
            let url = match self
                .config
                .revoke_url_template
                .as_deref()
                .map(strip)
                .filter(|value| !value.is_empty())
            {
                Some(template) => template
                    .replace("{api_base_url}", &base)
                    .replace("{external_credential_id}", &identifier),
                None => format!("{base}/v2/assertions/{identifier}"),
            };
            let reason = reason
                .filter(|value| !value.is_empty())
                .or(credential
                    .revocation_reason
                    .as_deref()
                    .filter(|value| !value.is_empty()))
                .unwrap_or("Canonical ElevenID credential was revoked.");
            (
                reqwest::Method::DELETE,
                url,
                Some(token),
                json!({"revocation_reason":reason}),
                "assertion revoke",
            )
        } else {
            let url = self
                .config
                .status_sync_url
                .as_deref()
                .map(strip)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| error("CANVAS_CREDENTIALS_STATUS_SYNC_URL is not configured"))?
                .to_owned();
            let token = self.token(organization, &sources).await?;
            let issuer = delivery
                .get("external_issuer_id")
                .filter(|value| python_truthy(value))
                .cloned()
                .unwrap_or_else(|| {
                    let issuer = config_value(
                        &sources,
                        &[
                            "canvas_credentials_issuer_id",
                            "issuer_id",
                            "external_issuer_id",
                        ],
                        self.config.provider.issuer_id.as_deref(),
                    );
                    if issuer.is_empty() {
                        Value::Null
                    } else {
                        json!(issuer)
                    }
                });
            let payload = json!({"issuer_id":issuer, "canvas_platform_id":platform["id"],
                "canvas_program_binding_id":delivery["metadata"]["canvas_program_binding_id"],
                "canvas_account_id":platform["canvas_account_id"], "lifecycle_action":action.as_str(),
                "credential":{"id":credential.id,"external_credential_id":delivery["external_credential_id"],
                    "external_issuer_id":delivery["external_issuer_id"], "issuer_did":credential.issuer_did,
                    "status":credential.status.as_str(),"status_updated_at":credential.status_updated_at.to_rfc3339(),
                    "revoked_at":credential.revoked_at.map(|value| value.to_rfc3339()),"reason":reason},
                "metadata":{"delivery_record_id":delivery["id"],"organization_id":credential.organization_id,
                    "credential_template_id":credential.credential_template_id}});
            (reqwest::Method::POST, url, token, payload, "status sync")
        };
        let response = self
            .transport
            .send(CanvasStatusRequest {
                method,
                url: url.clone(),
                token,
                body: payload,
            })
            .await
            .map_err(|detail| {
                error(format!(
                    "Canvas Credentials {operation} request failed: {detail}"
                ))
            })?;
        if !(200..300).contains(&response.status) {
            return Err(error(format!(
                "Canvas Credentials {operation} failed (HTTP {}): {}",
                response.status,
                truncate_text(&response.body)
            )));
        }
        let mut metadata = object(
            json!({"status_sync_url":url,"status_sync_http_status":response.status,
            "status_sync_response":response_excerpt(response.body.as_bytes(), false),
            "status_sync_request_id":response.request_id,"status_synced_at":chrono::Utc::now().to_rfc3339()}),
        );
        if real_provider {
            metadata.insert("provider".into(), json!("badgr_api"));
        }
        Ok(metadata)
    }
}

fn metadata_sources(metadata: &Value) -> Vec<&Map<String, Value>> {
    let Some(metadata) = metadata.as_object() else {
        return Vec::new();
    };
    [
        "canvas_credentials",
        "canvas_credentials_config",
        "provider_config",
    ]
    .iter()
    .filter_map(|key| metadata.get(*key).and_then(Value::as_object))
    .chain(std::iter::once(metadata))
    .collect()
}

fn config_value(sources: &[&Map<String, Value>], keys: &[&str], operator: Option<&str>) -> String {
    sources
        .iter()
        .flat_map(|source| keys.iter().filter_map(|key| source.get(*key)))
        .filter(|value| !value.is_null())
        .filter_map(python_string)
        .map(|value| strip(&value).to_owned())
        .find(|value| !value.is_empty())
        .or_else(|| {
            operator
                .map(strip)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

fn object(value: Value) -> Map<String, Value> {
    value.as_object().expect("static object projection").clone()
}

fn error(detail: impl Into<String>) -> CredentialManagementPortError {
    CredentialManagementPortError(detail.into())
}

#[derive(Clone, Debug)]
pub struct HttpCanvasStatusTransport {
    policy: CanvasHttpClientPolicy,
}

impl HttpCanvasStatusTransport {
    pub fn new(policy: CanvasHttpClientPolicy) -> Self {
        Self { policy }
    }
}

#[async_trait]
impl CanvasStatusTransport for HttpCanvasStatusTransport {
    async fn send(&self, request: CanvasStatusRequest) -> Result<CanvasStatusResponse, String> {
        let parsed = Url::parse(&request.url).map_err(|_| "Provider URL is invalid")?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err("Provider URL must not contain credentials".into());
        }
        // Pin the actual request destination, including operator URL templates;
        // never construct a client for one origin then send a token to another.
        let (client, _) =
            client_for_canvas_origin(&parsed.origin().ascii_serialization(), &self.policy)
                .await
                .map_err(|()| "Provider origin is unavailable or disallowed")?;
        let mut builder = client
            .request(request.method, parsed)
            .header(reqwest::header::ACCEPT, "application/json")
            .json(&request.body);
        if let Some(token) = request.token {
            builder = builder.bearer_auth(token);
        }
        let response = builder.send().await.map_err(|error| {
            if error.is_timeout() {
                "Provider request timed out"
            } else {
                "Provider request unavailable"
            }
        })?;
        let status = response.status().as_u16();
        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = response
            .text()
            .await
            .map_err(|_| "Provider response unavailable")?;
        Ok(CanvasStatusResponse {
            status,
            request_id,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Mutex, time::Duration};

    #[tokio::test]
    async fn http_transport_preserves_wire_protocol_and_does_not_follow_redirects() {
        use axum::{
            body::to_bytes, extract::Request, http::StatusCode, response::IntoResponse,
            routing::any, Json, Router,
        };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let observed = calls.clone();
        let application = Router::new().fallback(any(move |request: Request| {
            let calls = observed.clone();
            async move {
                let method = request.method().to_string();
                let path = request.uri().path().to_owned();
                let headers = request.headers().clone();
                let body = to_bytes(request.into_body(), 8192).await.unwrap();
                calls
                    .lock()
                    .unwrap()
                    .push(json!({"method":method, "path":path,
                    "accept":headers.get("accept").and_then(|v| v.to_str().ok()),
                    "content_type":headers.get("content-type").and_then(|v| v.to_str().ok()),
                    "authorization":headers.get("authorization").and_then(|v| v.to_str().ok()),
                    "body":serde_json::from_slice::<Value>(&body).unwrap()}));
                let mut response = if path == "/redirect" {
                    (StatusCode::FOUND, "Synthetic redirect").into_response()
                } else {
                    Json(json!({"accepted":true})).into_response()
                };
                response
                    .headers_mut()
                    .insert("x-request-id", "synthetic-wire-request".parse().unwrap());
                if path == "/redirect" {
                    response
                        .headers_mut()
                        .insert("location", "/must-not-follow".parse().unwrap());
                }
                response
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, application)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
        });
        let policy = CanvasHttpClientPolicy {
            timeout: Duration::from_secs(2),
            private_origin_allowlist: Vec::new(),
            allow_private_networks: false,
            allow_http_localhost: true,
        };
        let transport = HttpCanvasStatusTransport::new(policy.clone());
        let mut results = Vec::new();
        for (method, path, token) in [
            (
                reqwest::Method::POST,
                "/status",
                Some("synthetic-wire-token"),
            ),
            (
                reqwest::Method::DELETE,
                "/status",
                Some("synthetic-wire-token"),
            ),
            (reqwest::Method::POST, "/status", None),
            (
                reqwest::Method::POST,
                "/redirect",
                Some("synthetic-wire-token"),
            ),
        ] {
            results.push(
                transport
                    .send(CanvasStatusRequest {
                        method,
                        url: format!("{origin}{path}"),
                        token: token.map(str::to_owned),
                        body: json!({"reason":"synthetic café"}),
                    })
                    .await,
            );
        }
        let denied = HttpCanvasStatusTransport::new(CanvasHttpClientPolicy {
            allow_http_localhost: false,
            ..policy
        })
        .send(CanvasStatusRequest {
            method: reqwest::Method::POST,
            url: format!("{origin}/must-not-call"),
            token: Some("synthetic-wire-token".into()),
            body: json!({}),
        })
        .await;
        let _ = stop.send(());
        server.await.unwrap().unwrap();
        // Always stop the owned server before making result assertions.
        let results = results.into_iter().collect::<Result<Vec<_>, _>>().unwrap();
        assert!(denied.is_err());
        assert_eq!(
            results.iter().map(|r| r.status).collect::<Vec<_>>(),
            [200, 200, 200, 302]
        );
        for response in &results {
            assert_eq!(
                response.request_id.as_deref(),
                Some("synthetic-wire-request")
            );
        }
        assert_eq!(results[0].body, "{\"accepted\":true}");
        assert_eq!(results[3].body, "Synthetic redirect");
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 4);
        for (index, call) in calls.iter().enumerate() {
            assert_eq!(call["method"], if index == 1 { "DELETE" } else { "POST" });
            assert_eq!(
                call["path"],
                if index == 3 { "/redirect" } else { "/status" }
            );
            assert_eq!(call["accept"], "application/json");
            assert_eq!(call["content_type"], "application/json");
            assert_eq!(
                call["authorization"],
                if index == 2 {
                    Value::Null
                } else {
                    json!("Bearer synthetic-wire-token")
                }
            );
            assert_eq!(call["body"], json!({"reason":"synthetic café"}));
        }
    }

    #[test]
    fn configuration_debug_never_discloses_secrets_or_operator_urls() {
        let config = CanvasCredentialsStatusConfig {
            provider: CanvasCredentialsValidationConfig {
                operator_api_token: Some("synthetic-secret-value".into()),
                ..Default::default()
            },
            status_sync_url: Some("https://operator.example.invalid/synthetic-private-path".into()),
            revoke_url_template: Some(
                "https://operator.example.invalid/synthetic-private-path/{external_credential_id}"
                    .into(),
            ),
            ..Default::default()
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("synthetic-secret-value"));
        assert!(!rendered.contains("synthetic-private-path"));
        assert!(rendered.contains("status_sync_url_configured: true"));
    }
}
