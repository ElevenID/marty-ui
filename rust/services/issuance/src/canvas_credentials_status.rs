//! Canvas lifecycle provider candidate. Consumer cutover is separately gated.
//! Uses the published delivery configuration precedence; management validation
//! deliberately retains its stricter, canonical-tenant secret fallback policy.
pub use crate::canvas_credentials_delivery_config::{
    CanvasCredentialsDeliveryConfig as CanvasCredentialsStatusConfig,
    CanvasCredentialsProviderError as CanvasCredentialsStatusError,
};
pub use crate::canvas_credentials_transport::{
    CanvasCredentialsRequest as CanvasStatusRequest,
    CanvasCredentialsResponse as CanvasStatusResponse,
    CanvasCredentialsTransport as CanvasStatusTransport,
    HttpCanvasCredentialsTransport as HttpCanvasStatusTransport,
};
use crate::{
    canvas_credentials_delivery_config::{config_value, metadata_sources, DeliveryConfiguration},
    canvas_credentials_protocol::{quote_identifier, response_excerpt, truncate_text},
    canvas_credentials_validation::CanvasCredentialsSecretResolver,
    canvas_lifecycle_delivery::{
        CanvasLifecycleCredential, CanvasLifecycleProviderError, CanvasLifecycleStatusProvider,
    },
    canvas_operator_secret::{CanvasOperatorSecretReader, FileCanvasOperatorSecretReader},
    canvas_provider_http::CanvasOriginPolicy,
    canvas_response_text::response_text,
    credential_management::CredentialLifecycleAction,
    lossless_json::LosslessObject,
    python_text::PythonText,
    python_value::{python_truthy, strip},
};
#[cfg(test)]
use crate::{
    canvas_credentials_validation::CanvasCredentialsValidationConfig,
    canvas_provider_http::CanvasHttpClientPolicy,
};
use async_trait::async_trait;
use serde_json::{json, Map, Value};
use std::sync::Arc;

#[derive(Clone)]
pub struct CanvasCredentialsStatusService {
    config: CanvasCredentialsStatusConfig,
    secrets: Arc<dyn CanvasCredentialsSecretResolver>,
    operator_secrets: Arc<dyn CanvasOperatorSecretReader>,
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
            Arc::new(HttpCanvasStatusTransport::with_operation_timeout(
                CanvasOriginPolicy {
                    private_origin_allowlist: config.canvas_private_origin_allowlist.clone(),
                    allow_private_networks: config.canvas_allow_private_base_urls,
                    allow_http_localhost: config.canvas_allow_http_localhost_base_urls,
                },
                config.canvas_credentials_validation_timeout,
            )),
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
            operator_secrets: Arc::new(FileCanvasOperatorSecretReader),
            transport,
        }
    }

    fn delivery_configuration(&self) -> DeliveryConfiguration<'_> {
        DeliveryConfiguration {
            config: &self.config,
            secrets: &self.secrets,
            operator_secrets: &self.operator_secrets,
        }
    }
    async fn token(
        &self,
        organization: &str,
        sources: &[&Map<String, Value>],
    ) -> Result<Option<String>, CanvasCredentialsStatusError> {
        self.delivery_configuration()
            .token(organization, sources)
            .await
    }
    fn provider(&self, sources: &[&Map<String, Value>]) -> String {
        self.delivery_configuration().provider(sources)
    }
    fn base_url(
        &self,
        sources: &[&Map<String, Value>],
    ) -> Result<String, CanvasCredentialsStatusError> {
        self.delivery_configuration().base_url(sources)
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
    ) -> Result<LosslessObject, CanvasLifecycleProviderError> {
        // Published lifecycle persistence records str(failure), not its class.
        // Retain the typed provider outcome until that deliberate port boundary.
        self.synchronize_provider(context, platform, delivery, action, reason)
            .await
            .map_err(|failure| CanvasLifecycleProviderError(failure.message()))
    }
}

impl CanvasCredentialsStatusService {
    /// The one provider implementation; lifecycle callers delegate here and
    /// project safe diagnostic text only at their persistence boundary.
    pub async fn synchronize_provider(
        &self,
        context: CanvasLifecycleCredential<'_>,
        platform: &Value,
        delivery: &Value,
        action: CredentialLifecycleAction,
        reason: Option<&str>,
    ) -> Result<LosslessObject, CanvasCredentialsStatusError> {
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
            return Ok(crate::lossless_json::object(object(
                json!({"provider":"badgr_api", "status_sync_mode":"canonical_provenance_only",
                "status_sync_skipped":true, "status_sync_reason":"Canvas Credentials API does not expose suspend/reinstate operations; canonical ElevenID status and provenance remain authoritative.",
                "status_synced_at":chrono::Utc::now().to_rfc3339(),
                "canvas_credentials_lifecycle_mapping":{"requested_action":action.as_str(),"external_action":null,"canonical_status":credential.status.as_str()}}),
            )));
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
            let text = response_text(&response.body, response.content_type.as_deref())?;
            let excerpt = truncate_text(&text);
            let prefix = format!(
                "Canvas Credentials {operation} failed (HTTP {}): ",
                response.status
            );
            let message = PythonText::from_codepoints(
                prefix.chars().map(u32::from).chain(excerpt.codepoints()),
            )
            .expect("prefix and decoded text contain valid codepoints");
            return Err(match message.into_scalar() {
                Ok(message) => error(message),
                Err(message) => CanvasCredentialsStatusError::NonScalarRuntime(message),
            });
        }
        let mut metadata = crate::lossless_json::object(object(
            json!({"status_sync_url":url,"status_sync_http_status":response.status,
            "status_sync_request_id":response.request_id,"status_synced_at":chrono::Utc::now().to_rfc3339()}),
        ));
        metadata.insert(
            "status_sync_response".into(),
            response_excerpt(&response.body, response.content_type.as_deref())?,
        );
        if real_provider {
            metadata.insert("provider".into(), json!("badgr_api").into());
        }
        Ok(metadata)
    }
}

fn object(value: Value) -> Map<String, Value> {
    value.as_object().expect("static object projection").clone()
}

fn error(detail: impl Into<String>) -> CanvasCredentialsStatusError {
    CanvasCredentialsStatusError::Runtime(detail.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Mutex, time::Duration};

    struct SecretPorts {
        case: Value,
        files: Mutex<Vec<String>>,
        lookups: Mutex<Vec<Value>>,
    }

    #[async_trait]
    impl CanvasCredentialsSecretResolver for SecretPorts {
        async fn secret_value(
            &self,
            organization: &str,
            identifier: &str,
        ) -> Result<Option<String>, ()> {
            self.lookups
                .lock()
                .unwrap()
                .push(json!({"organization_id":organization,"secret_id":identifier}));
            Ok(self.case["tenant_value"].as_str().map(str::to_owned))
        }
    }

    #[async_trait]
    impl CanvasOperatorSecretReader for SecretPorts {
        async fn read(&self, path: &str) -> Result<Vec<u8>, std::io::Error> {
            assert_eq!(path, "/synthetic/operator-token");
            self.files.lock().unwrap().push("operator-token".into());
            let text = match self.case["file"].as_str().unwrap() {
                "missing" => return Err(std::io::ErrorKind::NotFound.into()),
                "permission" => return Err(std::io::ErrorKind::PermissionDenied.into()),
                "directory" => return Err(std::io::ErrorKind::IsADirectory.into()),
                "invalid_utf8" => return Ok(vec![0xff]),
                "value" => "synthetic-file\n",
                "mixed_newlines" => " synthetic-first\r\nsecond\rthird\n ",
                "empty" => "",
                "whitespace" => "\u{1c}\u{2003}\n",
                "unicode_value" => "\u{1c}\u{2003}synthetic-file\u{2003}\u{1c}",
                _ => panic!("unknown synthetic file kind"),
            };
            Ok(text.as_bytes().to_vec())
        }
    }

    #[async_trait]
    impl CanvasStatusTransport for SecretPorts {
        async fn send(&self, _: CanvasStatusRequest) -> Result<CanvasStatusResponse, String> {
            panic!("secret helper replay must not perform HTTP")
        }
    }

    #[tokio::test]
    async fn lazy_operator_secret_matches_exact_published_helper_cases() {
        let cases: Value = serde_json::from_str(include_str!(
            "../../../../contracts/canvas-provider-configuration-scenarios.json"
        ))
        .unwrap();
        let expected: Value = serde_json::from_str(include_str!(
            "../../../../contracts/canvas-provider-configuration-oracle.json"
        ))
        .unwrap();
        assert_eq!(
            cases["secrets"].as_array().unwrap().len(),
            expected["secrets"].as_array().unwrap().len()
        );
        for (case, expected) in cases["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .zip(expected["secrets"].as_array().unwrap())
        {
            assert_eq!(case["name"], expected["name"]);
            let ports = Arc::new(SecretPorts {
                case: case.clone(),
                files: Mutex::new(Vec::new()),
                lookups: Mutex::new(Vec::new()),
            });
            let mut service = CanvasCredentialsStatusService::new(
                CanvasCredentialsStatusConfig {
                    provider: CanvasCredentialsValidationConfig {
                        operator_api_token: case["direct"].as_str().map(str::to_owned),
                        operator_api_token_file: case
                            .get("file")
                            .map(|_| "/synthetic/operator-token".into()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ports.clone(),
                ports.clone(),
            );
            service.operator_secrets = ports.clone();
            let result = service
                .token("org-review", &metadata_sources(&case["metadata"]))
                .await;
            let mut actual = match result {
                Ok(value) => json!({"value":value.unwrap_or_default()}),
                Err(failure) => {
                    assert_eq!(
                        failure.to_string(),
                        "Canvas Credentials operator token file is not valid UTF-8"
                    );
                    json!({"error_class":"UnicodeDecodeError"})
                }
            };
            actual["name"] = case["name"].clone();
            actual["files"] = json!(*ports.files.lock().unwrap());
            actual["secrets"] = json!(*ports.lookups.lock().unwrap());
            assert_eq!(&actual, expected, "{}", case["name"]);
        }
    }

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
                    let mut response =
                        (StatusCode::FOUND, b"Synthetic redirect caf\xe9".to_vec()).into_response();
                    response.headers_mut().insert(
                        "content-type",
                        "text/plain; charset=latin1".parse().unwrap(),
                    );
                    response
                } else if method == "DELETE" {
                    let bytes = "{\"accepted\":true}"
                        .encode_utf16()
                        .flat_map(u16::to_le_bytes)
                        .collect::<Vec<_>>();
                    let mut encoder =
                        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                    std::io::Write::write_all(&mut encoder, &bytes).unwrap();
                    let mut response = encoder.finish().unwrap().into_response();
                    response
                        .headers_mut()
                        .insert("content-encoding", "gzip".parse().unwrap());
                    response.headers_mut().insert(
                        "content-type",
                        "application/json; charset=ascii".parse().unwrap(),
                    );
                    response
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
        assert_eq!(results[0].body, b"{\"accepted\":true}");
        assert_eq!(results[3].body, b"Synthetic redirect caf\xe9");
        assert_eq!(
            response_text(&results[3].body, results[3].content_type.as_deref())
                .unwrap()
                .into_scalar()
                .unwrap(),
            "Synthetic redirect café"
        );
        assert_eq!(
            results[1].body,
            "{\"accepted\":true}"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            response_excerpt(&results[1].body, results[1].content_type.as_deref())
                .unwrap()
                .to_scalar()
                .unwrap(),
            json!({"accepted":true})
        );
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
