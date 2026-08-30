use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
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
}

fn app(repository: Arc<MemoryRepository>) -> axum::Router {
    let config = IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>())
        .expect("configuration");
    let runtime = IssuanceRuntime::new(&config).expect("runtime");
    let service = CanvasPlatformManagementHttpService::new(CanvasPlatformManagementService::new(
        repository,
        Some("management-key"),
        CanvasOriginPolicy::default(),
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
