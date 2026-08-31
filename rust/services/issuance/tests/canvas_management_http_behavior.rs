use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chrono::{DateTime, Utc};
use marty_issuance_service::{
    canvas_binding_domain::{CanvasApplicationTemplateProjection, CanvasProgramBindingRecord},
    canvas_catalog::{CanvasCatalogOAuth, CanvasCatalogProvider, CanvasCatalogProviderError},
    canvas_lti_probe::{CanvasLtiJwksRefreshConfig, CanvasLtiProbeClient},
    canvas_management_domain::{CanvasOriginPolicy, CanvasPlatformRecord},
    canvas_management_http::CanvasPlatformManagementHttpService,
    canvas_management_service::{
        CanvasManagementRepositoryError, CanvasPlatformManagementRepository,
        CanvasPlatformManagementService, CanvasReadinessInputProvider,
    },
    canvas_oauth::CanvasOAuthError,
    canvas_readiness::{
        CanvasOAuthReadinessConnection, CanvasReadinessInputs, CanvasSyncReadiness,
    },
    http::router_with_canvas_management,
    transport::TransportPolicy,
    IssuanceRuntime, IssuanceServiceConfig,
};
use marty_oid4vci::{discovery::StaticDiscoveryDocuments, lti::CanvasLtiPlatformProbe};
use serde_json::{json, Value};
use tower::ServiceExt;

#[derive(Default)]
struct MemoryRepository {
    platforms: Mutex<Vec<CanvasPlatformRecord>>,
    bindings: Mutex<Vec<CanvasProgramBindingRecord>>,
    templates: Mutex<Vec<CanvasApplicationTemplateProjection>>,
    force_conflict: Mutex<bool>,
    force_oauth_conflict: Mutex<bool>,
    create_calls: Mutex<usize>,
    installation_invalidations: Mutex<Vec<bool>>,
}

struct SuccessfulProbe;

struct ReadyReadinessInputProvider;

#[async_trait]
impl CanvasReadinessInputProvider for ReadyReadinessInputProvider {
    async fn inputs(
        &self,
        _platform: &CanvasPlatformRecord,
        _binding: &CanvasProgramBindingRecord,
        _evaluated_at: DateTime<Utc>,
    ) -> CanvasReadinessInputs {
        CanvasReadinessInputs {
            rollout_allowed: true,
            lti_metadata_ready: true,
            lti_tool_signing_ready: true,
            oauth_lookup_succeeded: true,
            oauth_connection: Some(CanvasOAuthReadinessConnection {
                connected: true,
                reauthorization_required: false,
                access_token_secret_configured: true,
                capabilities: BTreeSet::from(["course_completion".to_owned()]),
                scopes: BTreeSet::from([
                    "url:GET|/api/v1/courses/:course_id/users/:user_id/progress".to_owned(),
                ]),
            }),
            worker_heartbeat_configured: true,
            sync_state: Some(CanvasSyncReadiness::default()),
            application_template: None,
            credential_template: json!({
                "id": "credential-template-1",
                "organization_id": "org-1",
                "status": "active",
                "credential_type": "OpenBadgeCredential",
                "credential_payload_format": "dc+sd-jwt",
                "revocation_profile_id": "status-profile-1",
                "issuer_did": "did:web:issuer.example.edu:orgs:org-1",
                "issuer_algorithm": "ES256"
            })
            .as_object()
            .expect("credential template")
            .clone(),
            credential_status_profile: json!({
                "id": "status-profile-1",
                "organization_id": "org-1",
                "status": "active"
            })
            .as_object()
            .expect("status profile")
            .clone(),
            kms_did_signing_ready: true,
            learner_identity_status: None,
            evidence_observed_at: None,
            evidence_max_age: Duration::from_secs(900),
        }
    }
}

fn successful_probe(canvas_base_url: &str, kid: &str) -> CanvasLtiPlatformProbe {
    CanvasLtiPlatformProbe {
        canvas_base_url: canvas_base_url.to_owned(),
        issuer: "https://canvas.instructure.com".to_owned(),
        authorization_endpoint: Some(
            "https://sso.canvaslms.com/api/lti/authorize_redirect".to_owned(),
        ),
        token_endpoint: Some(format!("{canvas_base_url}/login/oauth2/token")),
        jwks_uri: "https://sso.canvaslms.com/api/lti/security/jwks".to_owned(),
        registration_endpoint: None,
        raw_openid_configuration: json!({"issuer": "https://canvas.instructure.com"}),
        jwks_json: json!({"keys": [{"kid": kid}]}),
    }
}

#[async_trait]
impl CanvasLtiProbeClient for SuccessfulProbe {
    async fn probe(
        &self,
        canvas_base_url: &str,
        _config: &CanvasLtiJwksRefreshConfig,
    ) -> Result<CanvasLtiPlatformProbe, String> {
        Ok(successful_probe(canvas_base_url, "canvas-key"))
    }
}

struct CountingProbe(Arc<AtomicUsize>);

#[async_trait]
impl CanvasLtiProbeClient for CountingProbe {
    async fn probe(
        &self,
        canvas_base_url: &str,
        _config: &CanvasLtiJwksRefreshConfig,
    ) -> Result<CanvasLtiPlatformProbe, String> {
        let count = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(successful_probe(
            canvas_base_url,
            &format!("canvas-key-{count}"),
        ))
    }
}

struct FailedProbe;

#[async_trait]
impl CanvasLtiProbeClient for FailedProbe {
    async fn probe(
        &self,
        _canvas_base_url: &str,
        _config: &CanvasLtiJwksRefreshConfig,
    ) -> Result<CanvasLtiPlatformProbe, String> {
        Err("provider metadata unavailable".to_owned())
    }
}

struct DriftProbe;

#[derive(Default)]
struct FixedCatalogOAuth {
    token: Mutex<Option<String>>,
    calls: Mutex<Vec<OAuthCall>>,
    rejected_tokens: Mutex<Vec<String>>,
}

type OAuthCall = (String, Option<String>, Option<String>);

#[async_trait]
impl CanvasCatalogOAuth for FixedCatalogOAuth {
    async fn access_token(
        &self,
        platform_id: &str,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<Option<String>, CanvasOAuthError> {
        self.calls.lock().expect("OAuth calls").push((
            platform_id.to_owned(),
            api_key.map(str::to_owned),
            trusted_organization_id.map(str::to_owned),
        ));
        Ok(self.token.lock().expect("OAuth token").clone())
    }

    async fn mark_rejected_access_token(
        &self,
        _platform_id: &str,
        rejected_access_token: &str,
        _api_key: Option<&str>,
        _trusted_organization_id: Option<&str>,
    ) -> Result<bool, CanvasOAuthError> {
        self.rejected_tokens
            .lock()
            .expect("rejected tokens")
            .push(rejected_access_token.to_owned());
        Ok(true)
    }
}

#[derive(Default)]
struct FixedCatalogProvider {
    calls: Mutex<Vec<(String, String, u16)>>,
    error: Mutex<Option<CanvasCatalogProviderError>>,
}

#[async_trait]
impl CanvasCatalogProvider for FixedCatalogProvider {
    async fn collection(
        &self,
        _canvas_base_url: &str,
        access_token: &str,
        path: &str,
        limit: u16,
    ) -> Result<Vec<serde_json::Map<String, Value>>, CanvasCatalogProviderError> {
        self.calls.lock().expect("catalog calls").push((
            access_token.to_owned(),
            path.to_owned(),
            limit,
        ));
        if let Some(error) = self.error.lock().expect("catalog error").clone() {
            return Err(error);
        }
        let items = if path == "courses" {
            vec![json!({"id": "course-1", "name": "Biology", "workflow_state": "available"})]
        } else if path.ends_with("/assignments") {
            vec![
                json!({"id": "assignment-1", "name": "Essay", "points_possible": 20}),
                json!({"id": "assignment-2", "name": "Quiz", "quiz_id": "quiz-1"}),
            ]
        } else {
            vec![json!({"id": "module-1", "name": "Module One"})]
        };
        Ok(items
            .into_iter()
            .map(|item| item.as_object().cloned().expect("catalog object"))
            .collect())
    }
}

#[async_trait]
impl CanvasLtiProbeClient for DriftProbe {
    async fn probe(
        &self,
        canvas_base_url: &str,
        _config: &CanvasLtiJwksRefreshConfig,
    ) -> Result<CanvasLtiPlatformProbe, String> {
        let mut probe = successful_probe(canvas_base_url, "drift-key");
        probe.jwks_uri = "https://attacker.example/jwks".to_owned();
        Ok(probe)
    }
}

#[async_trait]
impl CanvasPlatformManagementRepository for MemoryRepository {
    async fn create_platform(
        &self,
        platform: &CanvasPlatformRecord,
    ) -> Result<(), CanvasManagementRepositoryError> {
        *self.create_calls.lock().expect("create calls") += 1;
        let mut platforms = self.platforms.lock().expect("platforms");
        if platforms
            .iter()
            .any(|candidate| candidate.id == platform.id)
        {
            return Err(CanvasManagementRepositoryError::Duplicate);
        }
        platforms.push(platform.clone());
        Ok(())
    }

    async fn active_platform(
        &self,
        organization_id: &str,
        platform_id: &str,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        Ok(self
            .platforms
            .lock()
            .expect("platforms")
            .iter()
            .find(|platform| {
                platform.organization_id == organization_id
                    && platform.id == platform_id
                    && platform.archived_at.is_none()
            })
            .cloned())
    }

    async fn list_active_platforms(
        &self,
        organization_id: &str,
    ) -> Result<Vec<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        Ok(self
            .platforms
            .lock()
            .expect("platforms")
            .iter()
            .filter(|platform| {
                platform.organization_id == organization_id && platform.archived_at.is_none()
            })
            .cloned()
            .collect())
    }

    async fn public_platform(
        &self,
        platform_id: &str,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        Ok(self
            .platforms
            .lock()
            .expect("platforms")
            .iter()
            .find(|platform| platform.id == platform_id)
            .cloned())
    }

    async fn platform_for_archival(
        &self,
        organization_id: &str,
        platform_id: &str,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        Ok(self
            .platforms
            .lock()
            .expect("platforms")
            .iter()
            .find(|platform| {
                platform.organization_id == organization_id && platform.id == platform_id
            })
            .cloned())
    }

    async fn save_platform_configuration(
        &self,
        platform: &CanvasPlatformRecord,
        expected_config_version: i64,
        _configuration_changed: bool,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        if *self.force_conflict.lock().expect("force conflict") {
            return Ok(None);
        }
        let mut platforms = self.platforms.lock().expect("platforms");
        let Some(existing) = platforms.iter_mut().find(|candidate| {
            candidate.organization_id == platform.organization_id
                && candidate.id == platform.id
                && candidate.archived_at.is_none()
                && candidate.config_version == expected_config_version
        }) else {
            return Ok(None);
        };
        *existing = platform.clone();
        Ok(Some(existing.clone()))
    }

    async fn archive_platform(
        &self,
        organization_id: &str,
        platform_id: &str,
        expected_config_version: i64,
        now: DateTime<Utc>,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        if *self.force_oauth_conflict.lock().expect("OAuth conflict") {
            return Err(CanvasManagementRepositoryError::OAuthConnectionChanged);
        }
        let mut platforms = self.platforms.lock().expect("platforms");
        let Some(platform) = platforms.iter_mut().find(|platform| {
            platform.organization_id == organization_id && platform.id == platform_id
        }) else {
            return Ok(None);
        };
        if platform.archived_at.is_none() && platform.config_version != expected_config_version {
            return Err(CanvasManagementRepositoryError::ConfigurationChanged);
        }
        platform
            .archive(false, now)
            .map_err(|_| CanvasManagementRepositoryError::VersionExhausted)?;
        platform.synchronize_archived_oauth_state(false, now);
        Ok(Some(platform.clone()))
    }

    async fn save_registration_state(
        &self,
        platform: &CanvasPlatformRecord,
        expected_config_version: i64,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        let mut platforms = self.platforms.lock().expect("platforms");
        let Some(existing) = platforms.iter_mut().find(|candidate| {
            candidate.organization_id == platform.organization_id
                && candidate.id == platform.id
                && candidate.archived_at.is_none()
                && candidate.config_version == expected_config_version
                && candidate.updated_at == expected_updated_at
        }) else {
            return Ok(None);
        };
        existing.connection_config = platform.connection_config.clone();
        existing.updated_at = platform.updated_at;
        Ok(Some(existing.clone()))
    }

    async fn save_lti_installation(
        &self,
        platform: &CanvasPlatformRecord,
        expected_config_version: i64,
        expected_updated_at: DateTime<Utc>,
        invalidate_bindings: bool,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        if *self.force_conflict.lock().expect("conflict") {
            return Ok(None);
        }
        self.installation_invalidations
            .lock()
            .expect("installation invalidations")
            .push(invalidate_bindings);
        let mut platforms = self.platforms.lock().expect("platforms");
        let Some(existing) = platforms.iter_mut().find(|candidate| {
            candidate.organization_id == platform.organization_id
                && candidate.id == platform.id
                && candidate.archived_at.is_none()
                && candidate.config_version == expected_config_version
                && candidate.updated_at == expected_updated_at
        }) else {
            return Ok(None);
        };
        *existing = platform.clone();
        Ok(Some(existing.clone()))
    }

    async fn save_lti_probe_metadata(
        &self,
        platform: &CanvasPlatformRecord,
        expected_config_version: i64,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
        if *self.force_conflict.lock().expect("conflict") {
            return Ok(None);
        }
        let mut platforms = self.platforms.lock().expect("platforms");
        let Some(existing) = platforms.iter_mut().find(|candidate| {
            candidate.organization_id == platform.organization_id
                && candidate.id == platform.id
                && candidate.archived_at.is_none()
                && candidate.config_version == expected_config_version
                && candidate.updated_at == expected_updated_at
        }) else {
            return Ok(None);
        };
        existing.canvas_base_url = platform.canvas_base_url.clone();
        existing.lti_issuer = platform.lti_issuer.clone();
        existing.lti_jwks_url = platform.lti_jwks_url.clone();
        existing.lti_jwks_json = platform.lti_jwks_json.clone();
        existing.lti_jwks_fetched_at = platform.lti_jwks_fetched_at;
        existing.lti_jwks_expires_at = platform.lti_jwks_expires_at;
        existing.lti_openid_configuration = platform.lti_openid_configuration.clone();
        existing.last_connection_error = platform.last_connection_error.clone();
        existing.updated_at = platform.updated_at;
        Ok(Some(existing.clone()))
    }

    async fn application_template(
        &self,
        template_id: &str,
    ) -> Result<Option<CanvasApplicationTemplateProjection>, CanvasManagementRepositoryError> {
        Ok(self
            .templates
            .lock()
            .expect("templates")
            .iter()
            .find(|template| template.id == template_id)
            .cloned())
    }

    async fn valid_canvas_credentials_secret(
        &self,
        organization_id: &str,
        secret_id: &str,
    ) -> Result<bool, CanvasManagementRepositoryError> {
        Ok(organization_id == "org-1" && secret_id == "secret-1")
    }

    async fn active_binding(
        &self,
        organization_id: &str,
        binding_id: &str,
    ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
        Ok(self
            .bindings
            .lock()
            .expect("bindings")
            .iter()
            .find(|binding| {
                binding.organization_id == organization_id
                    && binding.id == binding_id
                    && binding.archived_at.is_none()
            })
            .cloned())
    }

    async fn list_active_bindings(
        &self,
        organization_id: &str,
        platform_id: Option<&str>,
        application_template_id: Option<&str>,
    ) -> Result<Vec<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
        Ok(self
            .bindings
            .lock()
            .expect("bindings")
            .iter()
            .filter(|binding| {
                binding.organization_id == organization_id
                    && binding.archived_at.is_none()
                    && platform_id.is_none_or(|value| binding.platform_id == value)
                    && application_template_id
                        .is_none_or(|value| binding.application_template_id == value)
            })
            .cloned()
            .collect())
    }

    async fn create_binding(
        &self,
        binding: &CanvasProgramBindingRecord,
    ) -> Result<(), CanvasManagementRepositoryError> {
        let mut bindings = self.bindings.lock().expect("bindings");
        if bindings.iter().any(|candidate| {
            candidate.archived_at.is_none()
                && candidate.organization_id == binding.organization_id
                && candidate.platform_id == binding.platform_id
                && candidate.application_template_id == binding.application_template_id
                && candidate.canvas_scope == binding.canvas_scope
        }) {
            return Err(CanvasManagementRepositoryError::DuplicateBinding);
        }
        bindings.push(binding.clone());
        Ok(())
    }

    async fn save_binding_configuration(
        &self,
        binding: &CanvasProgramBindingRecord,
        expected_config_version: i64,
    ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
        let mut bindings = self.bindings.lock().expect("bindings");
        if bindings.iter().any(|candidate| {
            candidate.id != binding.id
                && candidate.archived_at.is_none()
                && candidate.organization_id == binding.organization_id
                && candidate.platform_id == binding.platform_id
                && candidate.application_template_id == binding.application_template_id
                && candidate.canvas_scope == binding.canvas_scope
        }) {
            return Err(CanvasManagementRepositoryError::DuplicateBinding);
        }
        let Some(existing) = bindings.iter_mut().find(|candidate| {
            candidate.organization_id == binding.organization_id
                && candidate.id == binding.id
                && candidate.archived_at.is_none()
                && candidate.config_version == expected_config_version
        }) else {
            return Ok(None);
        };
        *existing = binding.clone();
        Ok(Some(existing.clone()))
    }

    async fn save_binding_readiness(
        &self,
        binding: &CanvasProgramBindingRecord,
        expected_config_version: i64,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
        let mut bindings = self.bindings.lock().expect("bindings");
        let Some(existing) = bindings.iter_mut().find(|candidate| {
            candidate.organization_id == binding.organization_id
                && candidate.id == binding.id
                && candidate.archived_at.is_none()
                && candidate.config_version == expected_config_version
                && candidate.updated_at == expected_updated_at
        }) else {
            return Ok(None);
        };
        *existing = binding.clone();
        Ok(Some(existing.clone()))
    }

    async fn archive_binding(
        &self,
        organization_id: &str,
        binding_id: &str,
        expected_config_version: i64,
        now: DateTime<Utc>,
    ) -> Result<Option<CanvasProgramBindingRecord>, CanvasManagementRepositoryError> {
        let mut bindings = self.bindings.lock().expect("bindings");
        let Some(binding) = bindings.iter_mut().find(|binding| {
            binding.organization_id == organization_id
                && binding.id == binding_id
                && binding.archived_at.is_none()
                && binding.config_version == expected_config_version
        }) else {
            return Ok(None);
        };
        binding.archive(now);
        Ok(Some(binding.clone()))
    }
}

fn app(repository: Arc<MemoryRepository>) -> axum::Router {
    app_with_probe(repository, Arc::new(SuccessfulProbe))
}

fn app_with_probe(
    repository: Arc<MemoryRepository>,
    probe_client: Arc<dyn CanvasLtiProbeClient>,
) -> axum::Router {
    let config = IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>())
        .expect("configuration");
    let runtime = IssuanceRuntime::new(&config).expect("runtime");
    let service = CanvasPlatformManagementHttpService::new(
        CanvasPlatformManagementService::with_probe_client(
            repository,
            Some("management-key"),
            CanvasOriginPolicy::default(),
            "https://issuer.example.edu",
            CanvasLtiJwksRefreshConfig {
                timeout: Duration::from_secs(10),
                ttl: Duration::from_secs(3_600),
                self_managed_origins: Vec::new(),
                allow_private_networks: false,
                allow_http_localhost: false,
            },
            probe_client,
        ),
    );
    router_with_canvas_management(
        runtime.state(),
        StaticDiscoveryDocuments::new("https://issuer.example.edu", "Issuer"),
        TransportPolicy::new(Vec::new()),
        service,
    )
}

fn app_with_readiness(repository: Arc<MemoryRepository>) -> axum::Router {
    let config = IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>())
        .expect("configuration");
    let runtime = IssuanceRuntime::new(&config).expect("runtime");
    let management = CanvasPlatformManagementService::with_probe_client(
        repository,
        Some("management-key"),
        CanvasOriginPolicy::default(),
        "https://issuer.example.edu",
        CanvasLtiJwksRefreshConfig {
            timeout: Duration::from_secs(10),
            ttl: Duration::from_secs(3_600),
            self_managed_origins: Vec::new(),
            allow_private_networks: false,
            allow_http_localhost: false,
        },
        Arc::new(SuccessfulProbe),
    )
    .with_readiness_input_provider(Arc::new(ReadyReadinessInputProvider));
    router_with_canvas_management(
        runtime.state(),
        StaticDiscoveryDocuments::new("https://issuer.example.edu", "Issuer"),
        TransportPolicy::new(Vec::new()),
        CanvasPlatformManagementHttpService::new(management),
    )
}

fn app_with_catalog(
    repository: Arc<MemoryRepository>,
    oauth: Arc<dyn CanvasCatalogOAuth>,
    provider: Arc<dyn CanvasCatalogProvider>,
) -> axum::Router {
    app_with_catalog_options(repository, oauth, provider, None)
}

fn app_with_catalog_options(
    repository: Arc<MemoryRepository>,
    oauth: Arc<dyn CanvasCatalogOAuth>,
    provider: Arc<dyn CanvasCatalogProvider>,
    local_admin_token: Option<String>,
) -> axum::Router {
    let config = IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>())
        .expect("configuration");
    let runtime = IssuanceRuntime::new(&config).expect("runtime");
    let management = CanvasPlatformManagementService::with_probe_client(
        repository,
        Some("management-key"),
        CanvasOriginPolicy::default(),
        "https://issuer.example.edu",
        CanvasLtiJwksRefreshConfig {
            timeout: Duration::from_secs(10),
            ttl: Duration::from_secs(3_600),
            self_managed_origins: Vec::new(),
            allow_private_networks: false,
            allow_http_localhost: false,
        },
        Arc::new(SuccessfulProbe),
    );
    router_with_canvas_management(
        runtime.state(),
        StaticDiscoveryDocuments::new("https://issuer.example.edu", "Issuer"),
        TransportPolicy::new(Vec::new()),
        CanvasPlatformManagementHttpService::with_catalog_options(
            management,
            oauth,
            provider,
            local_admin_token,
        ),
    )
}

async fn seed_platform(app: &axum::Router, repository: &MemoryRepository) -> String {
    let response = app
        .clone()
        .oneshot(management_request(
            Request::post("/v1/integrations/canvas/platforms"),
            platform_request("Catalog Canvas", "client-1"),
        ))
        .await
        .expect("create platform");
    assert_eq!(response.status(), StatusCode::OK);
    repository.platforms.lock().expect("platforms")[0]
        .id
        .clone()
}

fn management_request(builder: axum::http::request::Builder, body: Value) -> Request<Body> {
    builder
        .header("content-type", "application/json")
        .header("x-api-key", "management-key")
        .header("x-organization-id", "org-1")
        .body(Body::from(serde_json::to_vec(&body).expect("request JSON")))
        .expect("request")
}

async fn response_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("response JSON")
}

fn platform_request(display_name: &str, client_id: &str) -> Value {
    json!({
        "display_name": display_name,
        "canvas_base_url": "https://canvas.example.edu",
        "lti_client_id": client_id,
        "lti_deployment_id": "deployment-1",
        "enabled": true
    })
}

fn binding_request(course_id: &str) -> Value {
    json!({
        "application_template_id": "application-template-1",
        "display_name": format!("Course {course_id}"),
        "auto_approve_on_evidence": true,
        "evidence_requirements": [{
            "source": "canvas_rest",
            "fact_type": "canvas.course_completion",
            "scope": {"course_id": course_id},
            "pass_rule": {"completed": true},
            "required": true
        }],
        "canvas_scope": {"course_id": course_id},
        "delivery_mode": "wallet_only",
        "feature_flags": {}
    })
}

#[tokio::test]
async fn platform_readiness_requires_a_binding_and_preserves_tenant_hiding() {
    let repository = Arc::new(MemoryRepository::default());
    let app = app(repository.clone());
    let platform_id = seed_platform(&app, &repository).await;

    let response = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/v1/integrations/canvas/platforms/{platform_id}/readiness"
            ))
            .header("x-api-key", "management-key")
            .header("x-organization-id", "org-1")
            .body(Body::empty())
            .expect("request"),
        )
        .await
        .expect("readiness response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["platform_id"], platform_id);
    assert_eq!(body["ready"], false);
    assert_eq!(body["checks"].as_array().expect("checks").len(), 1);
    assert_eq!(body["checks"][0]["code"], "program_binding");
    assert_eq!(body["checks"][0]["blocking"], true);

    let hidden = app
        .oneshot(
            Request::get(format!(
                "/v1/integrations/canvas/platforms/{platform_id}/readiness"
            ))
            .header("x-api-key", "management-key")
            .header("x-organization-id", "org-2")
            .body(Body::empty())
            .expect("request"),
        )
        .await
        .expect("hidden response");
    assert_eq!(hidden.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn binding_validation_returns_and_persists_the_frozen_readiness_projection() {
    let repository = Arc::new(MemoryRepository::default());
    repository
        .templates
        .lock()
        .expect("templates")
        .push(CanvasApplicationTemplateProjection {
            id: "application-template-1".to_owned(),
            organization_id: "org-1".to_owned(),
            credential_template_id: Some("credential-template-1".to_owned()),
            approval_policy_set_id: None,
            active: true,
        });
    let app = app_with_readiness(repository.clone());
    let platform_id = seed_platform(&app, &repository).await;
    {
        let mut platforms = repository.platforms.lock().expect("platforms");
        platforms[0].enabled = true;
        platforms[0].registration_status = "installed".to_owned();
    }
    let created = app
        .clone()
        .oneshot(management_request(
            Request::post(format!(
                "/v1/integrations/canvas/platforms/{platform_id}/program-bindings"
            )),
            binding_request("course-101"),
        ))
        .await
        .expect("binding response");
    assert_eq!(created.status(), StatusCode::OK);
    let binding_id = response_json(created).await["id"]
        .as_str()
        .expect("binding ID")
        .to_owned();

    let validated = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/v1/integrations/canvas/program-bindings/{binding_id}/validate"
            ))
            .header("x-api-key", "management-key")
            .header("x-organization-id", "org-1")
            .body(Body::empty())
            .expect("request"),
        )
        .await
        .expect("validation response");
    assert_eq!(validated.status(), StatusCode::OK);
    let body = response_json(validated).await;
    assert_eq!(
        body.as_object()
            .expect("response object")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "active",
            "binding_id",
            "checks",
            "config_version",
            "evaluated_at",
            "ready",
            "valid",
        ])
    );
    assert_eq!(body["binding_id"], binding_id);
    assert_eq!(body["ready"], true);
    assert_eq!(body["valid"], true);
    assert_eq!(body["active"], false);
    assert_eq!(body["config_version"], 1);
    assert_eq!(body["checks"].as_array().expect("checks").len(), 23);
    assert!(body["evaluated_at"].as_str().is_some());
    {
        let bindings = repository.bindings.lock().expect("bindings");
        let persisted = &bindings[0];
        assert_eq!(persisted.validated_config_version, Some(1));
        assert_eq!(persisted.readiness_checks.len(), 23);
    }

    let hidden = app
        .oneshot(
            Request::post(format!(
                "/v1/integrations/canvas/program-bindings/{binding_id}/validate"
            ))
            .header("x-api-key", "management-key")
            .header("x-organization-id", "org-2")
            .body(Body::empty())
            .expect("request"),
        )
        .await
        .expect("hidden response");
    assert_eq!(hidden.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn platform_routes_authenticate_before_parsing_and_hide_tenant_mismatches() {
    let repository = Arc::new(MemoryRepository::default());
    let app = app(repository.clone());
    let unauthorized = app
        .clone()
        .oneshot(
            Request::post("/v1/integrations/canvas/platforms")
                .header("content-type", "application/json")
                .header("x-organization-id", "org-1")
                .body(Body::from("not-json"))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(unauthorized).await,
        json!({"detail": "X-API-Key header is missing"})
    );
    assert_eq!(*repository.create_calls.lock().expect("create calls"), 0);

    let missing_organization = app
        .clone()
        .oneshot(
            Request::post("/v1/integrations/canvas/platforms")
                .header("content-type", "application/json")
                .header("x-api-key", "management-key")
                .body(Body::from("not-json"))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(missing_organization.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(missing_organization).await,
        json!({"detail": "X-Organization-ID is required for Canvas management"})
    );

    let created = app
        .clone()
        .oneshot(management_request(
            Request::post("/v1/integrations/canvas/platforms"),
            platform_request("Canvas Production", "client-1"),
        ))
        .await
        .expect("response");
    assert_eq!(created.status(), StatusCode::OK);
    let created = response_json(created).await;
    let platform_id = created["id"].as_str().expect("platform ID").to_owned();
    assert_eq!(created["organization_id"], "org-1");
    assert_eq!(created["enabled"], false);
    assert_eq!(created["connection_config"]["enabled_intent"], true);

    let missing_query = app
        .clone()
        .oneshot(
            Request::get("/v1/integrations/canvas/platforms")
                .header("x-api-key", "management-key")
                .header("x-organization-id", "org-1")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(missing_query.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        response_json(missing_query).await["detail"][0]["loc"],
        json!(["query", "organization_id"])
    );

    let forged_query = app
        .clone()
        .oneshot(
            Request::get("/v1/integrations/canvas/platforms?organization_id=org-2")
                .header("x-api-key", "management-key")
                .header("x-organization-id", "org-1")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(forged_query.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(forged_query).await,
        json!({"detail": "Canvas resource not found"})
    );

    let foreign_get = app
        .oneshot(
            Request::get(format!("/v1/integrations/canvas/platforms/{platform_id}"))
                .header("x-api-key", "management-key")
                .header("x-organization-id", "org-2")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(foreign_get.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(foreign_get).await,
        json!({"detail": "Canvas platform not found"})
    );
}

#[tokio::test]
async fn platform_routes_reject_private_fields_and_preserve_safe_update_projection() {
    let repository = Arc::new(MemoryRepository::default());
    let app = app(repository.clone());
    let rejected = app
        .clone()
        .oneshot(management_request(
            Request::post("/v1/integrations/canvas/platforms"),
            json!({
                "canvas_base_url": "https://canvas.example.edu",
                "organization_id": "attacker"
            }),
        ))
        .await
        .expect("response");
    assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        response_json(rejected).await["detail"][0]["type"],
        "extra_forbidden"
    );
    assert_eq!(*repository.create_calls.lock().expect("create calls"), 0);

    let created = app
        .clone()
        .oneshot(management_request(
            Request::post("/v1/integrations/canvas/platforms"),
            platform_request("Original", "client-1"),
        ))
        .await
        .expect("response");
    let created = response_json(created).await;
    let platform_id = created["id"].as_str().expect("platform ID").to_owned();
    repository.platforms.lock().expect("platforms")[0]
        .connection_config
        .insert(
            "access_token_secret_ref".to_owned(),
            json!("org_secret://org-1/private"),
        );

    let updated = app
        .clone()
        .oneshot(management_request(
            Request::put(format!("/v1/integrations/canvas/platforms/{platform_id}")),
            platform_request("Updated", "client-2"),
        ))
        .await
        .expect("response");
    assert_eq!(updated.status(), StatusCode::OK);
    let updated = response_json(updated).await;
    assert_eq!(updated["display_name"], "Updated");
    assert_eq!(updated["config_version"], 2);
    assert_eq!(updated["enabled"], false);
    assert!(updated["connection_config"]
        .get("access_token_secret_ref")
        .is_none());

    *repository.force_conflict.lock().expect("force conflict") = true;
    let stale = app
        .oneshot(management_request(
            Request::put(format!("/v1/integrations/canvas/platforms/{platform_id}")),
            platform_request("Stale", "client-3"),
        ))
        .await
        .expect("response");
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    assert_eq!(
        response_json(stale).await,
        json!({"detail": "Canvas platform configuration changed; retry the request"})
    );
}

#[tokio::test]
async fn platform_delete_is_tenant_hidden_idempotent_and_returns_an_empty_204() {
    let repository = Arc::new(MemoryRepository::default());
    let app = app(repository.clone());
    let created = app
        .clone()
        .oneshot(management_request(
            Request::post("/v1/integrations/canvas/platforms"),
            platform_request("Archive me", "client-1"),
        ))
        .await
        .expect("response");
    let platform_id = response_json(created).await["id"]
        .as_str()
        .expect("platform ID")
        .to_owned();
    {
        let mut platforms = repository.platforms.lock().expect("platforms");
        platforms[0]
            .connection_config
            .insert("lti_config_token_hash".to_owned(), json!("digest"));
        platforms[0].connection_config.insert(
            "oauth_pending_authorization_id".to_owned(),
            json!("authorization-1"),
        );
    }

    let foreign = app
        .clone()
        .oneshot(
            Request::delete(format!("/v1/integrations/canvas/platforms/{platform_id}"))
                .header("x-api-key", "management-key")
                .header("x-organization-id", "org-2")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(foreign).await,
        json!({"detail": "Canvas platform not found"})
    );

    for _ in 0..2 {
        let deleted = app
            .clone()
            .oneshot(
                Request::delete(format!("/v1/integrations/canvas/platforms/{platform_id}"))
                    .header("x-api-key", "management-key")
                    .header("x-organization-id", "org-1")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
        let body = axum::body::to_bytes(deleted.into_body(), 1024)
            .await
            .expect("response body");
        assert!(body.is_empty());
    }

    let archived = repository.platforms.lock().expect("platforms")[0].clone();
    assert_eq!(archived.config_version, 2);
    assert_eq!(archived.registration_status, "archived");
    assert_eq!(archived.connection_config["oauth_status"], "disconnected");
    assert_eq!(
        archived.connection_config["lti_config_token_status"],
        "revoked"
    );
    assert!(!archived
        .connection_config
        .contains_key("lti_config_token_hash"));
    assert!(!archived
        .connection_config
        .contains_key("oauth_pending_authorization_id"));

    let hidden = app
        .oneshot(
            Request::get(format!("/v1/integrations/canvas/platforms/{platform_id}"))
                .header("x-api-key", "management-key")
                .header("x-organization-id", "org-1")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(hidden.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn platform_delete_reports_the_frozen_oauth_queue_conflict() {
    let repository = Arc::new(MemoryRepository::default());
    let app = app(repository.clone());
    let created = app
        .clone()
        .oneshot(management_request(
            Request::post("/v1/integrations/canvas/platforms"),
            platform_request("Queue conflict", "client-1"),
        ))
        .await
        .expect("response");
    let platform_id = response_json(created).await["id"]
        .as_str()
        .expect("platform ID")
        .to_owned();
    *repository
        .force_oauth_conflict
        .lock()
        .expect("OAuth conflict") = true;
    let conflict = app
        .oneshot(
            Request::delete(format!("/v1/integrations/canvas/platforms/{platform_id}"))
                .header("x-api-key", "management-key")
                .header("x-organization-id", "org-1")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(
        response_json(conflict).await,
        json!({"detail": "Canvas OAuth connection changed; retry platform archival"})
    );
    assert!(repository.platforms.lock().expect("platforms")[0]
        .archived_at
        .is_none());
}

#[tokio::test]
async fn registration_config_rotates_digest_only_tokens_and_public_lookup_is_no_store() {
    let repository = Arc::new(MemoryRepository::default());
    let app = app(repository.clone());
    let created = app
        .clone()
        .oneshot(management_request(
            Request::post("/v1/integrations/canvas/platforms"),
            platform_request("Portable registration", "client-1"),
        ))
        .await
        .expect("response");
    let platform_id = response_json(created).await["id"]
        .as_str()
        .expect("platform ID")
        .to_owned();

    let mut issued_tokens = Vec::new();
    for _ in 0..2 {
        let registration = app
            .clone()
            .oneshot(
                Request::get(format!(
                    "/v1/integrations/canvas/platforms/{platform_id}/registration-config"
                ))
                .header("x-api-key", "management-key")
                .header("x-organization-id", "org-1")
                .body(Body::empty())
                .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(registration.status(), StatusCode::OK);
        let registration = response_json(registration).await;
        assert_eq!(registration["platform_id"], platform_id);
        assert_eq!(
            registration["developer_key_configuration"]["target_link_uri"],
            format!(
                "https://issuer.example.edu/v1/integrations/canvas/lti/platforms/{platform_id}/experience"
            )
        );
        assert_eq!(
            registration["developer_key_configuration"]["scopes"],
            json!([
                "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly",
                "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly",
                "https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly"
            ])
        );
        let config_url = registration["installation"]["config_url"]
            .as_str()
            .expect("config URL");
        issued_tokens.push(
            config_url
                .rsplit('/')
                .next()
                .expect("config token")
                .to_owned(),
        );
    }
    assert_ne!(issued_tokens[0], issued_tokens[1]);
    let persisted = repository.platforms.lock().expect("platforms")[0].clone();
    let digest = persisted.connection_config["lti_config_token_hash"]
        .as_str()
        .expect("token digest");
    assert_eq!(digest.len(), 64);
    assert!(!serde_json::to_string(&persisted.connection_config)
        .expect("connection config JSON")
        .contains(&issued_tokens[1]));
    assert_eq!(
        persisted.connection_config["lti_config_token_status"],
        "active"
    );

    let retired = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/v1/integrations/canvas/lti/config/{}",
                issued_tokens[0]
            ))
            .body(Body::empty())
            .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(retired.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(retired).await,
        json!({"detail": "Canvas LTI configuration not found"})
    );

    let public = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/v1/integrations/canvas/lti/config/{}",
                issued_tokens[1]
            ))
            .body(Body::empty())
            .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(public.status(), StatusCode::OK);
    assert_eq!(public.headers()["cache-control"], "no-store");
    let public = response_json(public).await;
    assert_eq!(public["tool_id"], "marty-portable-canvas-v1");
    assert!(public.get("installation").is_none());

    let deleted = app
        .clone()
        .oneshot(
            Request::delete(format!("/v1/integrations/canvas/platforms/{platform_id}"))
                .header("x-api-key", "management-key")
                .header("x-organization-id", "org-1")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    let revoked = app
        .oneshot(
            Request::get(format!(
                "/v1/integrations/canvas/lti/config/{}",
                issued_tokens[1]
            ))
            .body(Body::empty())
            .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(revoked.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn lti_installation_probes_trust_rotates_token_and_invalidates_changed_bindings() {
    let repository = Arc::new(MemoryRepository::default());
    let app = app(repository.clone());
    let created = app
        .clone()
        .oneshot(management_request(
            Request::post("/v1/integrations/canvas/platforms"),
            platform_request("Install", "old-client"),
        ))
        .await
        .expect("response");
    let platform_id = response_json(created).await["id"]
        .as_str()
        .expect("platform ID")
        .to_owned();

    let installed = app
        .clone()
        .oneshot(management_request(
            Request::put(format!(
                "/v1/integrations/canvas/platforms/{platform_id}/lti-installation"
            )),
            json!({
                "lti_client_id": " installed-client ",
                "lti_deployment_id": " installed-deployment "
            }),
        ))
        .await
        .expect("response");
    assert_eq!(installed.status(), StatusCode::OK);
    let installed_response = response_json(installed).await;
    assert!(installed_response["installation"]["config_url"]
        .as_str()
        .is_some());

    let persisted = repository.platforms.lock().expect("platforms")[0].clone();
    assert_eq!(persisted.lti_client_id.as_deref(), Some("installed-client"));
    assert_eq!(
        persisted.lti_deployment_id.as_deref(),
        Some("installed-deployment")
    );
    assert_eq!(persisted.registration_status, "installed");
    assert!(persisted.enabled);
    assert_eq!(persisted.config_version, 2);
    assert_eq!(
        persisted.lti_issuer.as_deref(),
        Some("https://canvas.instructure.com")
    );
    assert_eq!(
        persisted.lti_jwks_url.as_deref(),
        Some("https://sso.canvaslms.com/api/lti/security/jwks")
    );
    assert!(persisted.lti_jwks_fetched_at.is_some());
    assert!(persisted.lti_jwks_expires_at > persisted.lti_jwks_fetched_at);
    assert_eq!(
        repository
            .installation_invalidations
            .lock()
            .expect("installation invalidations")
            .as_slice(),
        &[true]
    );

    let revoked = app
        .oneshot(management_request(
            Request::put(format!(
                "/v1/integrations/canvas/platforms/{platform_id}/lti-installation"
            )),
            json!({
                "lti_client_id": "installed-client",
                "lti_deployment_id": "installed-deployment",
                "revoke_config_token": "yes"
            }),
        ))
        .await
        .expect("response");
    assert_eq!(revoked.status(), StatusCode::OK);
    let revoked = response_json(revoked).await;
    assert!(revoked["installation"].get("config_url").is_none());
    let persisted = repository.platforms.lock().expect("platforms")[0].clone();
    assert_eq!(persisted.config_version, 2);
    assert_eq!(
        persisted.connection_config["lti_config_token_status"],
        "revoked"
    );
    assert_eq!(
        repository
            .installation_invalidations
            .lock()
            .expect("installation invalidations")
            .as_slice(),
        &[true, false]
    );
}

#[tokio::test]
async fn lti_installation_persists_probe_failure_and_rejects_conflicting_token_actions() {
    let repository = Arc::new(MemoryRepository::default());
    let healthy_app = app(repository.clone());
    let created = healthy_app
        .clone()
        .oneshot(management_request(
            Request::post("/v1/integrations/canvas/platforms"),
            platform_request("Failure", "old-client"),
        ))
        .await
        .expect("response");
    let platform_id = response_json(created).await["id"]
        .as_str()
        .expect("platform ID")
        .to_owned();
    let registration = healthy_app
        .oneshot(
            Request::get(format!(
                "/v1/integrations/canvas/platforms/{platform_id}/registration-config"
            ))
            .header("x-api-key", "management-key")
            .header("x-organization-id", "org-1")
            .body(Body::empty())
            .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(registration.status(), StatusCode::OK);

    let failed_app = app_with_probe(repository.clone(), Arc::new(FailedProbe));
    let failed = failed_app
        .clone()
        .oneshot(management_request(
            Request::put(format!(
                "/v1/integrations/canvas/platforms/{platform_id}/lti-installation"
            )),
            json!({
                "lti_client_id": "new-client",
                "lti_deployment_id": "new-deployment"
            }),
        ))
        .await
        .expect("response");
    assert_eq!(failed.status(), StatusCode::CONFLICT);
    assert_eq!(
        response_json(failed).await,
        json!({"detail": "Canvas LTI metadata probe failed: provider metadata unavailable"})
    );
    let persisted = repository.platforms.lock().expect("platforms")[0].clone();
    assert_eq!(persisted.config_version, 2);
    assert!(!persisted.enabled);
    assert_eq!(persisted.registration_status, "draft");
    assert_eq!(
        persisted.last_connection_error.as_deref(),
        Some("provider metadata unavailable")
    );
    assert_eq!(
        persisted.connection_config["lti_config_token_status"],
        "revoked"
    );
    assert!(!persisted
        .connection_config
        .contains_key("lti_config_token_hash"));

    let conflicting = failed_app
        .oneshot(management_request(
            Request::put(format!(
                "/v1/integrations/canvas/platforms/{platform_id}/lti-installation"
            )),
            json!({
                "lti_client_id": "new-client",
                "lti_deployment_id": "new-deployment",
                "rotate_config_token": true,
                "revoke_config_token": true
            }),
        ))
        .await
        .expect("response");
    assert_eq!(conflicting.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(conflicting).await,
        json!({"detail": "Rotate and revoke are mutually exclusive"})
    );
}

#[tokio::test]
async fn sandbox_probe_and_jwks_refresh_share_trust_without_enabling_the_platform() {
    let repository = Arc::new(MemoryRepository::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let app = app_with_probe(repository.clone(), Arc::new(CountingProbe(calls.clone())));
    let created = app
        .clone()
        .oneshot(management_request(
            Request::post("/v1/integrations/canvas/platforms"),
            platform_request("Probe", "client-1"),
        ))
        .await
        .expect("response");
    let platform_id = response_json(created).await["id"]
        .as_str()
        .expect("platform ID")
        .to_owned();

    let sandbox = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/v1/integrations/canvas/platforms/{platform_id}/sandbox-probe"
            ))
            .header("x-api-key", "management-key")
            .header("x-organization-id", "org-1")
            .body(Body::empty())
            .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(sandbox.status(), StatusCode::OK);
    let sandbox = response_json(sandbox).await;
    assert_eq!(sandbox["probe"]["lti_trust_profile"], "hosted_global");
    assert_eq!(
        sandbox["probe"]["jwks_json"]["keys"][0]["kid"],
        "canvas-key-1"
    );
    assert_eq!(sandbox["platform"]["registration_status"], "draft");
    assert_eq!(sandbox["platform"]["enabled"], false);

    let refreshed = app
        .oneshot(
            Request::post(format!(
                "/v1/integrations/canvas/platforms/{platform_id}/jwks-refresh"
            ))
            .header("x-api-key", "management-key")
            .header("x-organization-id", "org-1")
            .body(Body::empty())
            .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(refreshed.status(), StatusCode::OK);
    let refreshed = response_json(refreshed).await;
    assert_eq!(refreshed["refreshed"], true);
    assert_eq!(
        refreshed["probe"]["jwks_json"]["keys"][0]["kid"],
        "canvas-key-2"
    );
    assert_eq!(refreshed["platform"]["registration_status"], "draft");
    assert_eq!(refreshed["platform"]["enabled"], false);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let persisted = repository.platforms.lock().expect("platforms")[0].clone();
    assert_eq!(
        persisted.lti_jwks_json,
        Some(json!({"keys": [{"kid": "canvas-key-2"}]}))
    );
    assert!(!persisted.enabled);
}

#[tokio::test]
async fn management_probe_failures_preserve_route_specific_errors() {
    let repository = Arc::new(MemoryRepository::default());
    let healthy = app(repository.clone());
    let created = healthy
        .oneshot(management_request(
            Request::post("/v1/integrations/canvas/platforms"),
            platform_request("Probe errors", "client-1"),
        ))
        .await
        .expect("response");
    let platform_id = response_json(created).await["id"]
        .as_str()
        .expect("platform ID")
        .to_owned();
    let failed = app_with_probe(repository, Arc::new(FailedProbe));

    for (suffix, detail) in [
        (
            "sandbox-probe",
            "Canvas sandbox probe failed: provider metadata unavailable",
        ),
        (
            "jwks-refresh",
            "Canvas JWKS refresh failed: provider metadata unavailable",
        ),
    ] {
        let response = failed
            .clone()
            .oneshot(
                Request::post(format!(
                    "/v1/integrations/canvas/platforms/{platform_id}/{suffix}"
                ))
                .header("x-api-key", "management-key")
                .header("x-organization-id", "org-1")
                .body(Body::empty())
                .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_json(response).await, json!({"detail": detail}));
    }
}

#[tokio::test]
async fn scope_discovery_and_catalog_share_one_authenticated_mapping_kernel() {
    let repository = Arc::new(MemoryRepository::default());
    let oauth = Arc::new(FixedCatalogOAuth::default());
    *oauth.token.lock().expect("OAuth token") = Some("organization-token".to_owned());
    let provider = Arc::new(FixedCatalogProvider::default());
    let app = app_with_catalog(repository.clone(), oauth.clone(), provider.clone());
    let platform_id = seed_platform(&app, &repository).await;

    let post = app
        .clone()
        .oneshot(management_request(
            Request::post(format!(
                "/v1/integrations/canvas/platforms/{platform_id}/scope-discovery"
            )),
            json!({
                "course_id": " course/1 ",
                "include_courses": "yes",
                "include_assignments": true,
                "include_quizzes": 1,
                "include_modules": "on",
                "limit": "12"
            }),
        ))
        .await
        .expect("scope discovery");
    assert_eq!(post.status(), StatusCode::OK);
    let post_body = response_json(post).await;
    assert_eq!(post_body["platform_id"], platform_id);
    assert_eq!(post_body["organization_id"], "org-1");
    assert_eq!(post_body["course_id"], "course/1");
    assert_eq!(post_body["courses"][0]["published"], true);
    assert_eq!(post_body["assignments"][0]["id"], "assignment-1");
    assert_eq!(post_body["quizzes"][0]["id"], "assignment-2");
    assert_eq!(post_body["modules"][0]["id"], "module-1");
    assert!(post_body["fetched_at"].as_str().is_some());

    let get = app
        .oneshot(
            Request::get(format!(
                "/v1/integrations/canvas/platforms/{platform_id}/catalog?course_id=course%2F1&include_courses=false&include_assignments=yes&include_quizzes=0&include_modules=off&limit=7"
            ))
            .header("x-api-key", "management-key")
            .header("x-organization-id", "org-1")
            .body(Body::empty())
            .expect("request"),
        )
        .await
        .expect("catalog");
    assert_eq!(get.status(), StatusCode::OK);
    let get_body = response_json(get).await;
    assert!(get_body["courses"].as_array().expect("courses").is_empty());
    assert_eq!(get_body["assignments"][0]["id"], "assignment-1");
    assert!(get_body["quizzes"].as_array().expect("quizzes").is_empty());
    assert!(get_body["modules"].as_array().expect("modules").is_empty());
    assert_eq!(oauth.calls.lock().expect("OAuth calls").len(), 2);
    assert!(provider
        .calls
        .lock()
        .expect("catalog calls")
        .iter()
        .all(|(token, _, _)| token == "organization-token"));
}

#[tokio::test]
async fn discovery_authenticates_before_body_and_preserves_validation_and_oauth_errors() {
    let repository = Arc::new(MemoryRepository::default());
    let oauth = Arc::new(FixedCatalogOAuth::default());
    let provider = Arc::new(FixedCatalogProvider::default());
    let app = app_with_catalog(repository.clone(), oauth.clone(), provider);
    let platform_id = seed_platform(&app, &repository).await;

    let unauthorized = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/v1/integrations/canvas/platforms/{platform_id}/scope-discovery"
            ))
            .header("content-type", "application/json")
            .header("x-organization-id", "org-1")
            .body(Body::from("{"))
            .expect("request"),
        )
        .await
        .expect("unauthorized response");
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let invalid = app
        .clone()
        .oneshot(management_request(
            Request::post(format!(
                "/v1/integrations/canvas/platforms/{platform_id}/scope-discovery"
            )),
            json!({"limit": 101, "provider_url": "https://attacker.example"}),
        ))
        .await
        .expect("validation response");
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let validation = response_json(invalid).await;
    assert_eq!(validation["detail"][0]["type"], "less_than_equal");
    assert_eq!(validation["detail"][1]["type"], "extra_forbidden");

    let missing_oauth = app
        .oneshot(management_request(
            Request::post(format!(
                "/v1/integrations/canvas/platforms/{platform_id}/scope-discovery"
            )),
            json!({}),
        ))
        .await
        .expect("missing OAuth response");
    assert_eq!(missing_oauth.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(missing_oauth).await,
        json!({"detail": "Canvas scope discovery requires an organization OAuth connection; environment tokens are local compatibility fallbacks"})
    );
}

#[tokio::test]
async fn discovery_preserves_the_explicit_local_admin_token_compatibility_path() {
    let repository = Arc::new(MemoryRepository::default());
    let oauth = Arc::new(FixedCatalogOAuth::default());
    let provider = Arc::new(FixedCatalogProvider::default());
    let app = app_with_catalog_options(
        repository.clone(),
        oauth,
        provider.clone(),
        Some("local-simulator-token".to_owned()),
    );
    let platform_id = seed_platform(&app, &repository).await;

    let response = app
        .oneshot(management_request(
            Request::post(format!(
                "/v1/integrations/canvas/platforms/{platform_id}/scope-discovery"
            )),
            json!({"include_assignments": false, "include_quizzes": false, "include_modules": false}),
        ))
        .await
        .expect("local fallback response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        provider.calls.lock().expect("catalog calls")[0].0,
        "local-simulator-token"
    );
}

#[tokio::test]
async fn discovery_marks_rejected_tokens_and_propagates_bounded_retry_after() {
    let repository = Arc::new(MemoryRepository::default());
    let oauth = Arc::new(FixedCatalogOAuth::default());
    *oauth.token.lock().expect("OAuth token") = Some("rejected-token".to_owned());
    let provider = Arc::new(FixedCatalogProvider::default());
    *provider.error.lock().expect("catalog error") =
        Some(CanvasCatalogProviderError::ReauthorizationRequired);
    let app = app_with_catalog(repository.clone(), oauth.clone(), provider.clone());
    let platform_id = seed_platform(&app, &repository).await;

    let rejected = app
        .clone()
        .oneshot(management_request(
            Request::post(format!(
                "/v1/integrations/canvas/platforms/{platform_id}/scope-discovery"
            )),
            json!({}),
        ))
        .await
        .expect("rejected response");
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(rejected).await,
        json!({"detail": "Canvas OAuth connection requires reauthorization"})
    );
    assert_eq!(
        oauth
            .rejected_tokens
            .lock()
            .expect("rejected tokens")
            .as_slice(),
        ["rejected-token"]
    );

    *provider.error.lock().expect("catalog error") =
        Some(CanvasCatalogProviderError::TemporarilyUnavailable {
            retry_after_seconds: Some(23),
        });
    let unavailable = app
        .oneshot(
            Request::get(format!(
                "/v1/integrations/canvas/platforms/{platform_id}/catalog"
            ))
            .header("x-api-key", "management-key")
            .header("x-organization-id", "org-1")
            .body(Body::empty())
            .expect("request"),
        )
        .await
        .expect("unavailable response");
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(unavailable.headers()["retry-after"], "23");
    assert_eq!(
        response_json(unavailable).await,
        json!({"detail": "Canvas discovery is temporarily unavailable"})
    );
}

#[tokio::test]
async fn endpoint_drift_is_an_exact_conflict_and_never_persists_installation_changes() {
    let repository = Arc::new(MemoryRepository::default());
    let healthy = app(repository.clone());
    let created = healthy
        .clone()
        .oneshot(management_request(
            Request::post("/v1/integrations/canvas/platforms"),
            platform_request("Endpoint drift", "old-client"),
        ))
        .await
        .expect("response");
    let platform_id = response_json(created).await["id"]
        .as_str()
        .expect("platform ID")
        .to_owned();
    let registration = healthy
        .oneshot(
            Request::get(format!(
                "/v1/integrations/canvas/platforms/{platform_id}/registration-config"
            ))
            .header("x-api-key", "management-key")
            .header("x-organization-id", "org-1")
            .body(Body::empty())
            .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(registration.status(), StatusCode::OK);
    let before = repository.platforms.lock().expect("platforms")[0].clone();

    let drift = app_with_probe(repository.clone(), Arc::new(DriftProbe));
    let installation = drift
        .clone()
        .oneshot(management_request(
            Request::put(format!(
                "/v1/integrations/canvas/platforms/{platform_id}/lti-installation"
            )),
            json!({
                "lti_client_id": "new-client",
                "lti_deployment_id": "new-deployment"
            }),
        ))
        .await
        .expect("response");
    assert_eq!(installation.status(), StatusCode::CONFLICT);
    assert_eq!(
        response_json(installation).await,
        json!({"detail": "Canvas metadata probe returned endpoints outside the persisted trust profile"})
    );
    let after = repository.platforms.lock().expect("platforms")[0].clone();
    assert_eq!(after.lti_client_id, before.lti_client_id);
    assert_eq!(after.lti_deployment_id, before.lti_deployment_id);
    assert_eq!(after.config_version, before.config_version);
    assert_eq!(
        after.active_lti_config_token_hash(),
        before.active_lti_config_token_hash()
    );
    assert!(repository
        .installation_invalidations
        .lock()
        .expect("installation invalidations")
        .is_empty());

    let sandbox = drift
        .oneshot(
            Request::post(format!(
                "/v1/integrations/canvas/platforms/{platform_id}/sandbox-probe"
            ))
            .header("x-api-key", "management-key")
            .header("x-organization-id", "org-1")
            .body(Body::empty())
            .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(sandbox.status(), StatusCode::CONFLICT);
    assert_eq!(
        response_json(sandbox).await,
        json!({"detail": "Canvas metadata probe returned endpoints outside the persisted trust profile"})
    );
}

#[tokio::test]
async fn program_binding_routes_preserve_auth_server_ownership_and_soft_delete() {
    let repository = Arc::new(MemoryRepository::default());
    repository
        .templates
        .lock()
        .expect("templates")
        .push(CanvasApplicationTemplateProjection {
            id: "application-template-1".to_owned(),
            organization_id: "org-1".to_owned(),
            credential_template_id: Some("credential-template-1".to_owned()),
            approval_policy_set_id: Some("policy-1".to_owned()),
            active: true,
        });
    let app = app(repository.clone());
    let platform_id = seed_platform(&app, &repository).await;
    let create_path = format!("/v1/integrations/canvas/platforms/{platform_id}/program-bindings");

    let unauthorized = app
        .clone()
        .oneshot(
            Request::post(&create_path)
                .header("content-type", "application/json")
                .header("x-organization-id", "org-1")
                .body(Body::from("not-json"))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let mut caller_owned = binding_request("course-101");
    caller_owned["enabled"] = json!(true);
    let rejected = app
        .clone()
        .oneshot(management_request(
            Request::post(&create_path),
            caller_owned,
        ))
        .await
        .expect("response");
    assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(repository.bindings.lock().expect("bindings").is_empty());

    let created = app
        .clone()
        .oneshot(management_request(
            Request::post(&create_path),
            binding_request("course-101"),
        ))
        .await
        .expect("response");
    assert_eq!(created.status(), StatusCode::OK);
    let created = response_json(created).await;
    let binding_id = created["id"].as_str().expect("binding id").to_owned();
    assert_eq!(
        created["canvas_account_id"],
        format!("unverified:{platform_id}")
    );
    assert_eq!(created["credential_template_id"], "credential-template-1");
    assert_eq!(
        created["flow_mode"],
        "elevenid_orchestrated_canvas_evidence"
    );
    assert_eq!(created["issuer_mode"], "org_managed");
    assert_eq!(created["direct_issue_enabled"], false);
    assert_eq!(created["enabled"], false);
    assert_eq!(created["config_version"], 1);

    let duplicate = app
        .clone()
        .oneshot(management_request(
            Request::post(&create_path),
            binding_request("course-101"),
        ))
        .await
        .expect("response");
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);

    let missing_query = app
        .clone()
        .oneshot(
            Request::get("/v1/integrations/canvas/program-bindings")
                .header("x-api-key", "management-key")
                .header("x-organization-id", "org-1")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(missing_query.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let listed = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/v1/integrations/canvas/program-bindings?organization_id=forged&organization_id=org-1&platform_id={platform_id}"
            ))
            .header("x-api-key", "management-key")
            .header("x-organization-id", "org-1")
            .body(Body::empty())
            .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(listed.status(), StatusCode::OK);
    assert_eq!(response_json(listed).await.as_array().unwrap().len(), 1);

    let foreign = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/v1/integrations/canvas/program-bindings/{binding_id}"
            ))
            .header("x-api-key", "management-key")
            .header("x-organization-id", "org-2")
            .body(Body::empty())
            .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);

    let updated = app
        .clone()
        .oneshot(management_request(
            Request::put(format!(
                "/v1/integrations/canvas/program-bindings/{binding_id}"
            )),
            binding_request("course-202"),
        ))
        .await
        .expect("response");
    assert_eq!(updated.status(), StatusCode::OK);
    let updated = response_json(updated).await;
    assert_eq!(updated["id"], binding_id);
    assert_eq!(updated["config_version"], 2);
    assert_eq!(updated["readiness_checks"], json!([]));
    assert_eq!(updated["readiness_validated_at"], Value::Null);

    let deleted = app
        .clone()
        .oneshot(
            Request::delete(format!(
                "/v1/integrations/canvas/program-bindings/{binding_id}"
            ))
            .header("x-api-key", "management-key")
            .header("x-organization-id", "org-1")
            .body(Body::empty())
            .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    let hidden = app
        .oneshot(
            Request::get(format!(
                "/v1/integrations/canvas/program-bindings/{binding_id}"
            ))
            .header("x-api-key", "management-key")
            .header("x-organization-id", "org-1")
            .body(Body::empty())
            .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(hidden.status(), StatusCode::NOT_FOUND);
    let archived = &repository.bindings.lock().expect("bindings")[0];
    assert!(archived.archived_at.is_some());
    assert!(!archived.enabled);
}
