use axum::Router;
use mmf_core::HealthReport;
use mmf_runtime::{system_router_with_options, RuntimeState, SystemRouteOptions};
use serde_json::{json, Value};

fn legacy_health(_report: &HealthReport) -> Value {
    json!({"status": "healthy", "service": "issuance-service"})
}

pub fn router(runtime: RuntimeState) -> Router {
    system_router_with_options(
        runtime,
        SystemRouteOptions::default().with_health_projector(legacy_health),
    )
}
