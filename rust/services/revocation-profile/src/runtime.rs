use crate::OrganizationAuthorization;
use async_trait::async_trait;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use redis::aio::ConnectionManager;
use serde::Serialize;
use serde_json::json;
use sqlx::PgPool;
use std::{collections::BTreeMap, sync::Arc};

const SERVICE_NAME: &str = "revocation-profile-service";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NativeDiagnostics {
    pub available: bool,
    pub backend: &'static str,
    pub version: &'static str,
    pub release_version: String,
    pub build_revision: String,
    pub capabilities: Vec<&'static str>,
}

impl NativeDiagnostics {
    pub fn new(release_version: String, build_revision: String) -> Self {
        Self {
            available: true,
            backend: "marty-status-rust",
            version: env!("CARGO_PKG_VERSION"),
            release_version,
            build_revision,
            capabilities: vec![
                "profile-lifecycle",
                "status-allocation",
                "status-mutation",
                "status-document",
                "cascade-revocation",
                "revocation-batch",
                "schema-migration",
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReadinessReport {
    pub components: BTreeMap<&'static str, bool>,
}

impl ReadinessReport {
    pub fn is_ready(&self) -> bool {
        self.components.values().all(|ready| *ready)
    }
}

#[async_trait]
pub trait Readiness: Send + Sync {
    async fn check(&self) -> ReadinessReport;
}

#[derive(Clone)]
pub struct BackendReadiness {
    pool: PgPool,
    redis: ConnectionManager,
    organization: OrganizationAuthorization,
}

impl std::fmt::Debug for BackendReadiness {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BackendReadiness")
            .finish_non_exhaustive()
    }
}

impl BackendReadiness {
    pub fn new(
        pool: PgPool,
        redis: ConnectionManager,
        organization: OrganizationAuthorization,
    ) -> Self {
        Self {
            pool,
            redis,
            organization,
        }
    }
}

#[async_trait]
impl Readiness for BackendReadiness {
    async fn check(&self) -> ReadinessReport {
        let mut connection = self.redis.clone();
        let postgres_check = async {
            sqlx::query_scalar::<_, i32>("SELECT 1")
                .fetch_one(&self.pool)
                .await
                .is_ok()
        };
        let redis_check = async {
            redis::cmd("PING")
                .query_async::<String>(&mut connection)
                .await
                .is_ok()
        };
        let organization_check = async { self.organization.check_health().await.is_ok() };
        let (postgres, redis, organization) =
            tokio::join!(postgres_check, redis_check, organization_check);
        ReadinessReport {
            components: BTreeMap::from([
                ("organization", organization),
                ("postgres", postgres),
                ("redis", redis),
            ]),
        }
    }
}

#[derive(Clone)]
pub struct OperationalState {
    readiness: Arc<dyn Readiness>,
    diagnostics: NativeDiagnostics,
}

impl OperationalState {
    pub fn new(readiness: Arc<dyn Readiness>, diagnostics: NativeDiagnostics) -> Self {
        Self {
            readiness,
            diagnostics,
        }
    }
}

pub fn operational_router(state: OperationalState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/startup", get(startup))
        .route("/health/native-backend", get(native_backend))
        .route("/metrics", get(metrics))
        .route("/openapi.json", get(openapi))
        .route("/docs", get(docs))
        .route("/docs/oauth2-redirect", get(oauth_redirect))
        .route("/redoc", get(redoc))
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({"status": "healthy", "service": SERVICE_NAME}))
}

async fn startup() -> Json<serde_json::Value> {
    Json(json!({"status": "started", "service": SERVICE_NAME}))
}

async fn ready(State(state): State<OperationalState>) -> Response {
    let report = state.readiness.check().await;
    let status = if report.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "status": if report.is_ready() { "ready" } else { "unavailable" },
            "service": SERVICE_NAME,
            "components": report.components,
        })),
    )
        .into_response()
}

async fn native_backend(State(state): State<OperationalState>) -> Json<serde_json::Value> {
    Json(json!({
        "status": "ready",
        "service": SERVICE_NAME,
        "available": state.diagnostics.available,
        "backend": state.diagnostics.backend,
        "version": state.diagnostics.version,
        "release_version": state.diagnostics.release_version,
        "build_revision": state.diagnostics.build_revision,
        "capabilities": state.diagnostics.capabilities,
    }))
}

async fn metrics(State(state): State<OperationalState>) -> Response {
    let report = state.readiness.check().await;
    let mut body = String::from(
        "# HELP marty_revocation_profile_backend_ready Whether a required backend is ready.\n\
         # TYPE marty_revocation_profile_backend_ready gauge\n",
    );
    for (component, ready) in report.components {
        body.push_str(&format!(
            "marty_revocation_profile_backend_ready{{backend=\"{component}\"}} {}\n",
            u8::from(ready)
        ));
    }
    body.push_str(
        "# HELP marty_revocation_profile_native_backend_ready Whether the canonical Rust backend is loaded.\n\
         # TYPE marty_revocation_profile_native_backend_ready gauge\n\
         marty_revocation_profile_native_backend_ready 1\n",
    );
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

async fn openapi() -> Json<serde_json::Value> {
    Json(json!({
        "openapi": "3.1.0",
        "info": {
            "title": "RevocationProfile Service",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Format-agnostic revocation configuration and automation"
        },
        "paths": {
            "/health": {"get": {"summary": "Health Check", "responses": {"200": {"description": "Healthy"}}}},
            "/ready": {"get": {"summary": "Readiness Check", "responses": {"200": {"description": "Ready"}, "503": {"description": "Required backend unavailable"}}}},
            "/startup": {"get": {"summary": "Startup Check", "responses": {"200": {"description": "Started"}}}},
            "/health/native-backend": {"get": {"summary": "Native Backend Diagnostics", "responses": {"200": {"description": "Canonical Rust backend ready"}}}}
        }
    }))
}

async fn docs() -> Html<&'static str> {
    Html(
        r#"<!doctype html><html><head><title>RevocationProfile Service - Swagger UI</title><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css"></head><body><div id="swagger-ui"></div><script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script><script>SwaggerUIBundle({url:'/openapi.json',dom_id:'#swagger-ui',deepLinking:true})</script></body></html>"#,
    )
}

async fn oauth_redirect() -> Html<&'static str> {
    Html("<!doctype html><html><body>OAuth redirect complete.</body></html>")
}

async fn redoc() -> Html<&'static str> {
    Html(
        r#"<!doctype html><html><head><title>RevocationProfile Service - ReDoc</title></head><body><redoc spec-url="/openapi.json"></redoc><script src="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js"></script></body></html>"#,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::Request;
    use tower::ServiceExt;

    #[derive(Debug)]
    struct FixedReadiness(bool);

    #[async_trait]
    impl Readiness for FixedReadiness {
        async fn check(&self) -> ReadinessReport {
            ReadinessReport {
                components: BTreeMap::from([
                    ("organization", self.0),
                    ("postgres", self.0),
                    ("redis", self.0),
                ]),
            }
        }
    }

    fn router(ready: bool) -> Router {
        operational_router(OperationalState::new(
            Arc::new(FixedReadiness(ready)),
            NativeDiagnostics::new("test".into(), "revision".into()),
        ))
    }

    #[tokio::test]
    async fn exposes_operational_and_documentation_contracts() {
        for path in [
            "/health",
            "/ready",
            "/startup",
            "/health/native-backend",
            "/metrics",
            "/openapi.json",
            "/docs",
            "/docs/oauth2-redirect",
            "/redoc",
        ] {
            let response = router(true)
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
        }
    }

    #[tokio::test]
    async fn readiness_fails_closed_when_a_required_backend_is_unavailable() {
        let response = router(false)
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
