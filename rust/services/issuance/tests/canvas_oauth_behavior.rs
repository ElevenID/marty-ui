use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use chrono::{DateTime, Utc};
use marty_issuance_service::{
    canvas_oauth::{
        CanvasOAuthAuthorization, CanvasOAuthCallbackRequest, CanvasOAuthConnection,
        CanvasOAuthError, CanvasOAuthPlatform, CanvasOAuthPlatformPatch, CanvasOAuthProvider,
        CanvasOAuthProviderError, CanvasOAuthRepository, CanvasOAuthSecretVault,
        CanvasOAuthService, CanvasOAuthServiceConfig, CanvasOAuthStartRequest,
        CanvasOAuthTokenBundle,
    },
    http::router_with_canvas_oauth,
    integration_secret::{IntegrationSecretMetadata, NewIntegrationSecret},
    transaction_reads::TransactionReadError,
    transport::TransportPolicy,
    IssuanceRuntime, IssuanceServiceConfig,
};
use marty_oid4vci::discovery::StaticDiscoveryDocuments;
use serde_json::Value;
use tower::ServiceExt;
use url::Url;

#[derive(Clone, Default)]
struct MemoryRepository {
    state: Arc<Mutex<RepositoryState>>,
}

#[derive(Default)]
struct RepositoryState {
    platforms: HashMap<String, CanvasOAuthPlatform>,
    authorizations: HashMap<String, CanvasOAuthAuthorization>,
    connections: HashMap<(String, String), CanvasOAuthConnection>,
    patches: Vec<CanvasOAuthPlatformPatch>,
    management_reads: usize,
    publish_allowed: bool,
    retry_at: Option<DateTime<Utc>>,
}

#[async_trait]
impl CanvasOAuthRepository for MemoryRepository {
    async fn management_platform(
        &self,
        organization_id: &str,
        platform_id: &str,
    ) -> Result<Option<CanvasOAuthPlatform>, CanvasOAuthError> {
        let mut state = self.state.lock().expect("repository state");
        state.management_reads += 1;
        Ok(state
            .platforms
            .get(platform_id)
            .filter(|platform| platform.organization_id == organization_id)
            .cloned())
    }

    async fn callback_platform(
        &self,
        platform_id: &str,
    ) -> Result<Option<CanvasOAuthPlatform>, CanvasOAuthError> {
        Ok(self
            .state
            .lock()
            .expect("repository state")
            .platforms
            .get(platform_id)
            .cloned())
    }

    async fn connection(
        &self,
        organization_id: &str,
        platform_id: &str,
    ) -> Result<Option<CanvasOAuthConnection>, CanvasOAuthError> {
        Ok(self
            .state
            .lock()
            .expect("repository state")
            .connections
            .get(&(organization_id.to_owned(), platform_id.to_owned()))
            .cloned())
    }

    async fn save_authorization(
        &self,
        authorization: &CanvasOAuthAuthorization,
    ) -> Result<(), CanvasOAuthError> {
        self.state
            .lock()
            .expect("repository state")
            .authorizations
            .insert(authorization.state_hash.clone(), authorization.clone());
        Ok(())
    }

    async fn consume_authorization(
        &self,
        state_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<CanvasOAuthAuthorization>, CanvasOAuthError> {
        Ok(self
            .state
            .lock()
            .expect("repository state")
            .authorizations
            .remove(state_hash)
            .filter(|authorization| authorization.expires_at > now))
    }

    async fn patch_platform(
        &self,
        organization_id: &str,
        platform_id: &str,
        expected_config_version: i64,
        patch: CanvasOAuthPlatformPatch,
    ) -> Result<bool, CanvasOAuthError> {
        let mut state = self.state.lock().expect("repository state");
        let matches = state.platforms.get(platform_id).is_some_and(|platform| {
            platform.organization_id == organization_id
                && platform.config_version == expected_config_version
        });
        if matches {
            state.patches.push(patch);
        }
        Ok(matches)
    }

    async fn patch_validation(
        &self,
        _organization_id: &str,
        _platform_id: &str,
        _expected_config_version: i64,
        _validated_at: Option<DateTime<Utc>>,
        _error_code: Option<&str>,
    ) -> Result<bool, CanvasOAuthError> {
        Ok(true)
    }

    async fn publish_connection(
        &self,
        connection: &CanvasOAuthConnection,
    ) -> Result<Option<DateTime<Utc>>, CanvasOAuthError> {
        let mut state = self.state.lock().expect("repository state");
        let key = (
            connection.organization_id.clone(),
            connection.platform_id.clone(),
        );
        if !state.publish_allowed || state.connections.contains_key(&key) {
            return Ok(None);
        }
        let now = Utc::now();
        let mut stored = connection.clone();
        stored.updated_at = now;
        state.connections.insert(key, stored);
        Ok(Some(now))
    }

    async fn mark_reauthorization_required(
        &self,
        _organization_id: &str,
        _platform_id: &str,
        _expected_updated_at: DateTime<Utc>,
    ) -> Result<bool, CanvasOAuthError> {
        Ok(true)
    }

    async fn begin_revocation(
        &self,
        organization_id: &str,
        platform_id: &str,
        expected_updated_at: DateTime<Utc>,
        _lease_owner: &str,
        _lease_seconds: i64,
    ) -> Result<Option<CanvasOAuthConnection>, CanvasOAuthError> {
        let mut state = self.state.lock().expect("repository state");
        let key = (organization_id.to_owned(), platform_id.to_owned());
        let Some(connection) = state.connections.get_mut(&key) else {
            return Ok(None);
        };
        if connection.updated_at != expected_updated_at {
            return Ok(None);
        }
        connection.status = "revocation_pending".to_owned();
        connection.updated_at = Utc::now();
        Ok(Some(connection.clone()))
    }

    async fn reschedule_revocation(
        &self,
        _organization_id: &str,
        _platform_id: &str,
        _lease_owner: &str,
        retry_at: DateTime<Utc>,
        _error_code: &str,
    ) -> Result<bool, CanvasOAuthError> {
        self.state.lock().expect("repository state").retry_at = Some(retry_at);
        Ok(true)
    }

    async fn complete_revocation(
        &self,
        organization_id: &str,
        platform_id: &str,
        _lease_owner: &str,
    ) -> Result<bool, CanvasOAuthError> {
        Ok(self
            .state
            .lock()
            .expect("repository state")
            .connections
            .remove(&(organization_id.to_owned(), platform_id.to_owned()))
            .is_some())
    }
}

#[derive(Clone, Default)]
struct MemoryVault {
    state: Arc<Mutex<VaultState>>,
}

#[derive(Default)]
struct VaultState {
    metadata: HashMap<String, IntegrationSecretMetadata>,
    values: HashMap<(String, String), String>,
    saved: Vec<NewIntegrationSecret>,
    deleted: Vec<String>,
}

#[async_trait]
impl CanvasOAuthSecretVault for MemoryVault {
    async fn metadata(
        &self,
        secret_id: &str,
    ) -> Result<Option<IntegrationSecretMetadata>, CanvasOAuthError> {
        Ok(self
            .state
            .lock()
            .expect("vault state")
            .metadata
            .get(secret_id)
            .cloned())
    }

    async fn value(
        &self,
        organization_id: &str,
        secret_id: &str,
    ) -> Result<Option<String>, CanvasOAuthError> {
        Ok(self
            .state
            .lock()
            .expect("vault state")
            .values
            .get(&(organization_id.to_owned(), secret_id.to_owned()))
            .cloned())
    }

    async fn save(&self, secret: NewIntegrationSecret) -> Result<(), CanvasOAuthError> {
        let mut state = self.state.lock().expect("vault state");
        state.values.insert(
            (secret.organization_id.clone(), secret.id.clone()),
            secret.value.clone(),
        );
        state.metadata.insert(
            secret.id.clone(),
            IntegrationSecretMetadata {
                id: secret.id.clone(),
                organization_id: secret.organization_id.clone(),
                provider: secret.provider.clone(),
                purpose: secret.purpose.clone(),
                enabled: true,
            },
        );
        state.saved.push(secret);
        Ok(())
    }

    async fn delete(&self, secret_id: &str) -> Result<(), CanvasOAuthError> {
        let mut state = self.state.lock().expect("vault state");
        state.metadata.remove(secret_id);
        state.values.retain(|(_, id), _| id != secret_id);
        state.deleted.push(secret_id.to_owned());
        Ok(())
    }
}

#[derive(Clone, Default)]
struct MemoryProvider {
    state: Arc<Mutex<ProviderState>>,
}

#[derive(Default)]
struct ProviderState {
    exchanges: Vec<(String, String, String)>,
    revocations: Vec<(String, String)>,
    fail_revoke_with_retry_after: Option<u64>,
}

#[async_trait]
impl CanvasOAuthProvider for MemoryProvider {
    async fn exchange(
        &self,
        canvas_base_url: &str,
        _client_id: &str,
        client_secret: &str,
        code: &str,
        _redirect_uri: &str,
    ) -> Result<CanvasOAuthTokenBundle, CanvasOAuthProviderError> {
        self.state.lock().expect("provider state").exchanges.push((
            canvas_base_url.to_owned(),
            client_secret.to_owned(),
            code.to_owned(),
        ));
        Ok(CanvasOAuthTokenBundle {
            access_token: "access-token-value".to_owned(),
            refresh_token: Some("refresh-token-value".to_owned()),
            expires_in_seconds: Some(3_600),
        })
    }

    async fn revoke(
        &self,
        canvas_base_url: &str,
        access_token: &str,
    ) -> Result<(), CanvasOAuthProviderError> {
        let mut state = self.state.lock().expect("provider state");
        state
            .revocations
            .push((canvas_base_url.to_owned(), access_token.to_owned()));
        if let Some(retry_after_seconds) = state.fail_revoke_with_retry_after {
            Err(CanvasOAuthProviderError::Failed {
                retry_after_seconds: Some(retry_after_seconds),
            })
        } else {
            Ok(())
        }
    }
}

fn fixture() -> (
    CanvasOAuthService,
    MemoryRepository,
    MemoryVault,
    MemoryProvider,
) {
    fixture_with_issuer("https://issuer.example.edu")
}

fn fixture_with_issuer(
    issuer_base_url: &str,
) -> (
    CanvasOAuthService,
    MemoryRepository,
    MemoryVault,
    MemoryProvider,
) {
    let repository = MemoryRepository::default();
    {
        let mut state = repository.state.lock().expect("repository state");
        state.publish_allowed = true;
        state.platforms.insert(
            "platform-1".to_owned(),
            CanvasOAuthPlatform {
                id: "platform-1".to_owned(),
                organization_id: "org-1".to_owned(),
                canvas_base_url: Some("https://canvas.example.edu".to_owned()),
                config_version: 1,
                archived: false,
            },
        );
    }
    let vault = MemoryVault::default();
    {
        let mut state = vault.state.lock().expect("vault state");
        state.metadata.insert(
            "client-secret-1".to_owned(),
            IntegrationSecretMetadata {
                id: "client-secret-1".to_owned(),
                organization_id: "org-1".to_owned(),
                provider: "canvas".to_owned(),
                purpose: "oauth_client_secret".to_owned(),
                enabled: true,
            },
        );
        state.values.insert(
            ("org-1".to_owned(), "client-secret-1".to_owned()),
            "client-secret-value".to_owned(),
        );
    }
    let provider = MemoryProvider::default();
    let service = CanvasOAuthService::new(
        Arc::new(repository.clone()),
        Arc::new(vault.clone()),
        Arc::new(provider.clone()),
        Some("management-key"),
        CanvasOAuthServiceConfig {
            issuer_base_url: issuer_base_url.to_owned(),
            completion_base_url: "https://app.example.edu/integrations/canvas".to_owned(),
            portable_enabled: true,
            pilot_organizations: BTreeSet::from(["org-1".to_owned()]),
            allow_private_networks: false,
            allow_http_localhost: false,
        },
    )
    .expect("service");
    (service, repository, vault, provider)
}

fn start_request() -> CanvasOAuthStartRequest {
    CanvasOAuthStartRequest {
        client_id: "canvas-client".to_owned(),
        client_secret_secret_id: "client-secret-1".to_owned(),
        capabilities: vec![
            "scope_catalog.read".to_owned(),
            "course_progress.read".to_owned(),
        ],
    }
}

fn state_from_authorization_url(value: &str) -> String {
    Url::parse(value)
        .expect("authorization URL")
        .query_pairs()
        .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
        .expect("state")
}

fn service_app(service: CanvasOAuthService) -> axum::Router {
    let config = IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>())
        .expect("configuration");
    let runtime = IssuanceRuntime::new(&config).expect("runtime");
    router_with_canvas_oauth(
        runtime.state(),
        StaticDiscoveryDocuments::new("https://issuer.example.edu", "Issuer"),
        TransportPolicy::new(Vec::new()),
        service,
    )
}

async fn response_json(response: axum::response::Response) -> Value {
    let body = axum::body::to_bytes(response.into_body(), 128 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&body).expect("JSON response")
}

#[tokio::test]
async fn start_authorizes_before_storage_and_persists_only_hashed_server_owned_scope() {
    let (service, repository, _vault, _provider) = fixture();
    assert_eq!(
        service
            .start("platform-1", start_request(), Some("wrong"), Some("org-1"))
            .await,
        Err(CanvasOAuthError::Security(
            TransactionReadError::InvalidApiKey
        ))
    );
    assert_eq!(
        repository
            .state
            .lock()
            .expect("repository state")
            .management_reads,
        0
    );
    let response = service
        .start(
            "platform-1",
            start_request(),
            Some("management-key"),
            Some("org-1"),
        )
        .await
        .expect("start");
    let state = state_from_authorization_url(&response.authorization_url);
    assert!(state.len() >= 32);
    assert_eq!(
        response.scopes,
        [
            "url:GET|/api/v1/courses",
            "url:GET|/api/v1/courses/:course_id/assignments",
            "url:GET|/api/v1/courses/:course_id/modules",
            "url:GET|/api/v1/courses/:course_id/users/:user_id/progress",
        ]
    );
    {
        let stored = repository.state.lock().expect("repository state");
        let authorization = stored
            .authorizations
            .values()
            .next()
            .expect("authorization");
        assert_ne!(authorization.state_hash, state);
        assert_eq!(authorization.state_hash.len(), 64);
        assert!((authorization.expires_at - authorization.created_at).num_seconds() == 600);
        assert!(matches!(
            stored.patches.last(),
            Some(CanvasOAuthPlatformPatch::AuthorizationPending { .. })
        ));
    }

    let (subpath_service, _, _, _) = fixture_with_issuer("https://issuer.example.edu/tenant");
    let subpath = subpath_service
        .start(
            "platform-1",
            start_request(),
            Some("management-key"),
            Some("org-1"),
        )
        .await
        .expect("subpath issuer start");
    assert_eq!(
        subpath.redirect_uri,
        "https://issuer.example.edu/tenant/v1/integrations/canvas/oauth/callback"
    );
}

#[tokio::test]
async fn callback_is_single_use_never_reflects_provider_error_and_publishes_encrypted_refs() {
    let (service, repository, vault, provider) = fixture();
    let started = service
        .start(
            "platform-1",
            start_request(),
            Some("management-key"),
            Some("org-1"),
        )
        .await
        .expect("start");
    let state = state_from_authorization_url(&started.authorization_url);
    let denied = service
        .callback(CanvasOAuthCallbackRequest {
            code: None,
            state: state.clone(),
            error: Some("access_denied_with_secret_text".to_owned()),
        })
        .await
        .expect("denial redirect");
    assert!(denied
        .location
        .contains("error_code=oauth_authorization_denied"));
    assert!(!denied.location.contains("access_denied_with_secret_text"));
    assert!(provider
        .state
        .lock()
        .expect("provider state")
        .exchanges
        .is_empty());
    let replay = service
        .callback(CanvasOAuthCallbackRequest {
            code: Some("replay".to_owned()),
            state,
            error: None,
        })
        .await
        .expect("replay redirect");
    assert!(replay.location.contains("error_code=oauth_state_invalid"));

    let started = service
        .start(
            "platform-1",
            start_request(),
            Some("management-key"),
            Some("org-1"),
        )
        .await
        .expect("second start");
    let connected = service
        .callback(CanvasOAuthCallbackRequest {
            code: Some("authorization-code".to_owned()),
            state: state_from_authorization_url(&started.authorization_url),
            error: None,
        })
        .await
        .expect("callback");
    assert!(connected.location.contains("outcome=connected"));
    assert!(!connected.location.contains("access-token-value"));
    let secrets = vault.state.lock().expect("vault state");
    assert_eq!(secrets.saved.len(), 2);
    assert!(secrets
        .saved
        .iter()
        .all(|secret| secret.purpose == "oauth_access_token"
            || secret.purpose == "oauth_refresh_token"));
    drop(secrets);
    let stored = repository.state.lock().expect("repository state");
    let connection = stored
        .connections
        .get(&("org-1".to_owned(), "platform-1".to_owned()))
        .expect("connection");
    assert!(connection
        .access_token_secret_ref
        .as_deref()
        .is_some_and(|value| value.starts_with("org_secret://org-1/")));
    assert!(matches!(
        stored.patches.last(),
        Some(CanvasOAuthPlatformPatch::Connected { .. })
    ));
}

#[tokio::test]
async fn publication_conflict_deletes_local_secrets_and_revokes_remote_token() {
    let (service, repository, vault, provider) = fixture();
    repository
        .state
        .lock()
        .expect("repository state")
        .publish_allowed = false;
    let started = service
        .start(
            "platform-1",
            start_request(),
            Some("management-key"),
            Some("org-1"),
        )
        .await
        .expect("start");
    let response = service
        .callback(CanvasOAuthCallbackRequest {
            code: Some("authorization-code".to_owned()),
            state: state_from_authorization_url(&started.authorization_url),
            error: None,
        })
        .await
        .expect("conflict redirect");
    assert!(response
        .location
        .contains("error_code=oauth_authorization_conflict"));
    assert_eq!(vault.state.lock().expect("vault state").deleted.len(), 2);
    assert_eq!(
        provider.state.lock().expect("provider state").revocations,
        [(
            "https://canvas.example.edu".to_owned(),
            "access-token-value".to_owned()
        )]
    );
}

#[tokio::test]
async fn callback_treats_an_empty_client_secret_as_configuration_drift() {
    let (service, _repository, vault, provider) = fixture();
    let started = service
        .start(
            "platform-1",
            start_request(),
            Some("management-key"),
            Some("org-1"),
        )
        .await
        .expect("start");
    vault.state.lock().expect("vault state").values.insert(
        ("org-1".to_owned(), "client-secret-1".to_owned()),
        String::new(),
    );
    let response = service
        .callback(CanvasOAuthCallbackRequest {
            code: Some("authorization-code".to_owned()),
            state: state_from_authorization_url(&started.authorization_url),
            error: None,
        })
        .await
        .expect("configuration drift redirect");
    assert!(response
        .location
        .contains("error_code=oauth_configuration_changed"));
    assert!(provider
        .state
        .lock()
        .expect("provider state")
        .exchanges
        .is_empty());
}

#[tokio::test]
async fn disconnect_revokes_against_pinned_connection_origin_and_durably_reschedules_failure() {
    let (service, repository, vault, provider) = fixture();
    let updated_at = Utc::now();
    repository
        .state
        .lock()
        .expect("repository state")
        .connections
        .insert(
            ("org-1".to_owned(), "platform-1".to_owned()),
            CanvasOAuthConnection {
                id: "connection-1".to_owned(),
                organization_id: "org-1".to_owned(),
                platform_id: "platform-1".to_owned(),
                canvas_base_url: "https://authorized-canvas.example.edu".to_owned(),
                platform_config_version: 1,
                client_id: "canvas-client".to_owned(),
                client_secret_ref: "org_secret://org-1/client-secret-1".to_owned(),
                capabilities: vec!["catalog".to_owned()],
                scopes: vec!["url:GET|/api/v1/courses".to_owned()],
                access_token_secret_ref: Some("org_secret://org-1/access-1".to_owned()),
                refresh_token_secret_ref: None,
                token_expires_at: None,
                status: "connected".to_owned(),
                revoke_retry_count: 2,
                updated_at,
            },
        );
    vault.state.lock().expect("vault state").values.insert(
        ("org-1".to_owned(), "access-1".to_owned()),
        "access-token".to_owned(),
    );
    provider
        .state
        .lock()
        .expect("provider state")
        .fail_revoke_with_retry_after = Some(500);
    let before = Utc::now();
    let response = service
        .disconnect("platform-1", Some("management-key"), Some("org-1"))
        .await
        .expect("disconnect");
    assert_eq!(response.status, "revocation_pending");
    assert_eq!(response.scopes, ["url:GET|/api/v1/courses"]);
    assert_eq!(
        provider.state.lock().expect("provider state").revocations,
        [(
            "https://authorized-canvas.example.edu".to_owned(),
            "access-token".to_owned()
        )]
    );
    let retry_at = repository
        .state
        .lock()
        .expect("repository state")
        .retry_at
        .expect("retry");
    assert!(retry_at >= before + chrono::Duration::seconds(500));
}

#[tokio::test]
async fn management_http_preserves_auth_validation_and_tenant_hiding() {
    let path = "/v1/integrations/canvas/platforms/platform-1/oauth/authorizations";
    let valid_body = serde_json::json!({
        "client_id": "canvas-client",
        "client_secret_secret_id": "client-secret-1",
        "capabilities": ["catalog"]
    });
    let (service, repository, _vault, _provider) = fixture();
    let unauthorized = service_app(service.clone())
        .oneshot(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-Organization-ID", "org-1")
                .body(Body::from(valid_body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(unauthorized).await,
        serde_json::json!({"detail": "X-API-Key header is missing"})
    );
    assert_eq!(
        repository
            .state
            .lock()
            .expect("repository state")
            .management_reads,
        0
    );

    let wrong_content_type = service_app(service.clone())
        .oneshot(
            Request::post(path)
                .header(header::CONTENT_TYPE, "text/plain")
                .header("X-API-Key", "management-key")
                .header("X-Organization-ID", "org-1")
                .body(Body::from(valid_body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        wrong_content_type.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let invalid = service_app(service.clone())
        .oneshot(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-API-Key", "management-key")
                .header("X-Organization-ID", "org-1")
                .body(Body::from(
                    serde_json::json!({
                        "client_id": "canvas-client",
                        "client_secret_secret_id": "client-secret-1",
                        "capabilities": ["catalog"],
                        "raw_scope": "url:DELETE|/api/v1/accounts/:id"
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(response_json(invalid).await["detail"]
        .as_array()
        .is_some_and(|errors| errors
            .iter()
            .any(|error| error["type"] == "extra_forbidden")));

    let foreign = service_app(service.clone())
        .oneshot(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-API-Key", "management-key")
                .header("X-Organization-ID", "org-2")
                .body(Body::from(valid_body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(foreign).await,
        serde_json::json!({"detail": "Canvas platform not found"})
    );

    let success = service_app(service)
        .oneshot(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-API-Key", "management-key")
                .header("X-Organization-ID", "org-1")
                .body(Body::from(valid_body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(success.status(), StatusCode::OK);
    let body = response_json(success).await;
    assert_eq!(
        body["redirect_uri"],
        "https://issuer.example.edu/v1/integrations/canvas/oauth/callback"
    );
    assert!(body["authorization_url"]
        .as_str()
        .is_some_and(|value| value.starts_with("https://canvas.example.edu/login/oauth2/auth?")));
}

#[tokio::test]
async fn callback_http_is_public_but_state_bound_and_never_browser_cacheable() {
    let (service, _repository, _vault, provider) = fixture();
    let invalid = service_app(service.clone())
        .oneshot(
            Request::get("/v1/integrations/canvas/oauth/callback?state=short")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(provider
        .state
        .lock()
        .expect("provider state")
        .exchanges
        .is_empty());
    let started = service
        .start(
            "platform-1",
            start_request(),
            Some("management-key"),
            Some("org-1"),
        )
        .await
        .expect("start");
    let state = state_from_authorization_url(&started.authorization_url);
    let response = service_app(service)
        .oneshot(
            Request::get(format!(
                "/v1/integrations/canvas/oauth/callback?state={state}&error=access_denied"
            ))
            .body(Body::empty())
            .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    let location = response.headers()[header::LOCATION]
        .to_str()
        .expect("location");
    assert!(location.contains("error_code=oauth_authorization_denied"));
    assert!(!location.contains("access_denied"));
}
