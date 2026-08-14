use crate::domain::{key_purposes, service_capabilities};
use axum::{response::Html, routing::get, Json, Router};
use serde::Serialize;
use tower_http::trace::TraceLayer;

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

#[derive(Debug, Serialize)]
struct ServiceStatus {
    service_name: &'static str,
    phase: &'static str,
    migrated_capabilities: [&'static str; 3],
    pending_capabilities: [&'static str; 5],
}

pub fn router() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/startup", get(startup))
        .route("/openapi.json", get(openapi))
        .route("/docs", get(docs))
        .route("/redoc", get(redoc))
        .route("/v1/signing-keys/service-status", get(service_status))
        .route("/v1/signing-keys/config/purposes", get(purposes))
        .route(
            "/v1/signing-keys/config/service-capabilities",
            get(capabilities),
        )
        .layer(TraceLayer::new_for_http())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy",
        service: "signing-keys-service",
    })
}

async fn ready() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ready",
        service: "signing-keys-service",
    })
}

async fn startup() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "started",
        service: "signing-keys-service",
    })
}

async fn service_status() -> Json<ServiceStatus> {
    Json(ServiceStatus {
        service_name: "signing-keys-service",
        phase: "bootstrap",
        migrated_capabilities: [
            "service-bootstrap",
            "health-surface",
            "integration-test-target",
        ],
        pending_capabilities: [
            "registry-persistence",
            "kms-adapter-integration",
            "jwks-did-publication-persistence",
            "audit-event-storage",
            "compliance-summary-computation",
        ],
    })
}

async fn purposes() -> Json<serde_json::Value> {
    Json(serde_json::json!({"purposes": key_purposes()}))
}

async fn capabilities() -> Json<serde_json::Value> {
    Json(serde_json::json!({"service_capabilities": service_capabilities()}))
}

async fn openapi() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "openapi": "3.1.0",
        "info": {"title": "Signing Keys Service", "version": "1.0.0"},
        "paths": {
            "/health": {"get": {"summary": "Health Check", "responses": {"200": {"description": "Successful Response"}}}},
            "/v1/signing-keys/service-status": {"get": {"summary": "Signing Keys Service Extraction Status", "responses": {"200": {"description": "Successful Response"}}}},
            "/v1/signing-keys/config/purposes": {"get": {"summary": "List Available Key Purposes", "responses": {"200": {"description": "Successful Response"}}}},
            "/v1/signing-keys/config/service-capabilities": {"get": {"summary": "List Provider Capability Metadata", "responses": {"200": {"description": "Successful Response"}}}}
        }
    }))
}

async fn docs() -> Html<&'static str> {
    Html(
        r#"<!doctype html><html><head><title>Signing Keys Service - Swagger UI</title></head><body><div id="swagger-ui"></div><script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script><script>SwaggerUIBundle({url:'/openapi.json',dom_id:'#swagger-ui'})</script></body></html>"#,
    )
}

async fn redoc() -> Html<&'static str> {
    Html(
        r#"<!doctype html><html><head><title>Signing Keys Service - ReDoc</title></head><body><redoc spec-url="/openapi.json"></redoc><script src="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js"></script></body></html>"#,
    )
}
