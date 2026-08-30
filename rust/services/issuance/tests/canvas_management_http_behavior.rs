use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chrono::{DateTime, Utc};
use marty_issuance_service::{
    canvas_management_domain::{CanvasOriginPolicy, CanvasPlatformRecord},
    canvas_management_http::CanvasPlatformManagementHttpService,
    canvas_management_service::{
        CanvasManagementRepositoryError, CanvasPlatformManagementRepository,
        CanvasPlatformManagementService,
    },
    http::router_with_canvas_management,
    transport::TransportPolicy,
    IssuanceRuntime, IssuanceServiceConfig,
};
use marty_oid4vci::discovery::StaticDiscoveryDocuments;
use serde_json::{json, Value};
use tower::ServiceExt;

#[derive(Default)]
struct MemoryRepository {
    platforms: Mutex<Vec<CanvasPlatformRecord>>,
    force_conflict: Mutex<bool>,
    force_oauth_conflict: Mutex<bool>,
    create_calls: Mutex<usize>,
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
}

fn app(repository: Arc<MemoryRepository>) -> axum::Router {
    let config = IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>())
        .expect("configuration");
    let runtime = IssuanceRuntime::new(&config).expect("runtime");
    let service = CanvasPlatformManagementHttpService::new(CanvasPlatformManagementService::new(
        repository,
        Some("management-key"),
        CanvasOriginPolicy::default(),
        "https://issuer.example.edu",
    ));
    router_with_canvas_management(
        runtime.state(),
        StaticDiscoveryDocuments::new("https://issuer.example.edu", "Issuer"),
        TransportPolicy::new(Vec::new()),
        service,
    )
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
