use crate::bus::EventBus;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

pub fn router(bus: EventBus) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/startup", get(startup))
        .route("/metrics", get(metrics))
        .route("/openapi.json", get(openapi))
        .route("/docs", get(docs))
        .route("/docs/oauth2-redirect", get(oauth_redirect))
        .route("/redoc", get(redoc))
        .with_state(bus)
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy",
        service: "event-stream",
    })
}

async fn ready() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ready",
        service: "event-stream",
    })
}

async fn startup() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "started",
        service: "event-stream",
    })
}

async fn openapi() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "openapi": "3.1.0",
        "info": {"title": "Marty Event Stream Service", "version": "1.0.0"},
        "paths": {
            "/health": {"get": health_operation("Health Check", "health_check_health_get", None, "Response Health Check Health Get")},
            "/ready": {"get": health_operation(
                "Readiness Check",
                "readiness_check_ready_get",
                Some("Readiness probe — returns 200 once the service can accept traffic.\n\nBecause all routers are registered synchronously before the app\nstarts serving, reaching this handler already implies the\nFastAPI app is fully wired.  Services that need deeper checks\n(e.g. DB connectivity) can override via a custom router."),
                "Response Readiness Check Ready Get"
            )},
            "/startup": {"get": health_operation(
                "Startup Check",
                "startup_check_startup_get",
                Some("Startup probe — returns 200 once initial boot is complete."),
                "Response Startup Check Startup Get"
            )}
        }
    }))
}

fn health_operation(
    summary: &str,
    operation_id: &str,
    description: Option<&str>,
    schema_title: &str,
) -> serde_json::Value {
    let mut operation = serde_json::json!({
        "summary": summary,
        "operationId": operation_id,
        "responses": {
            "200": {
                "description": "Successful Response",
                "content": {"application/json": {"schema": {
                    "additionalProperties": true,
                    "title": schema_title,
                    "type": "object"
                }}}
            }
        }
    });
    if let Some(description) = description {
        operation["description"] = serde_json::Value::String(description.to_string());
    }
    operation
}

async fn docs() -> Html<&'static str> {
    Html(
        r#"<!doctype html><html><head><title>Marty Event Stream Service - Swagger UI</title><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css"></head><body><div id="swagger-ui"></div><script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script><script>SwaggerUIBundle({url:'/openapi.json',dom_id:'#swagger-ui',deepLinking:true,displayOperationId:false})</script></body></html>"#,
    )
}

async fn oauth_redirect() -> Html<&'static str> {
    Html("<!doctype html><html><body>OAuth redirect complete.</body></html>")
}

async fn redoc() -> Html<&'static str> {
    Html(
        r#"<!doctype html><html><head><title>Marty Event Stream Service - ReDoc</title></head><body><redoc spec-url="/openapi.json"></redoc><script src="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js"></script></body></html>"#,
    )
}

async fn metrics(State(bus): State<EventBus>) -> Response {
    let snapshot = bus.metrics().await;
    let body = format!(
        "# TYPE marty_event_stream_subscribers gauge\n\
         marty_event_stream_subscribers {}\n\
         # TYPE marty_event_stream_published_total counter\n\
         marty_event_stream_published_total {}\n\
         # TYPE marty_event_stream_delivered_total counter\n\
         marty_event_stream_delivered_total {}\n\
         # TYPE marty_event_stream_dropped_total counter\n\
         marty_event_stream_dropped_total {}\n",
        snapshot.subscribers, snapshot.published, snapshot.delivered, snapshot.dropped
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn exposes_health_and_metrics_contracts() {
        let app = router(EventBus::default());
        for path in [
            "/health",
            "/ready",
            "/startup",
            "/metrics",
            "/openapi.json",
            "/docs",
            "/docs/oauth2-redirect",
            "/redoc",
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
        }
    }
}
