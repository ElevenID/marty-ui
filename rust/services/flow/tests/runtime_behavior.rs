use axum::{body::Body, http::Request};
use marty_flow::{FlowDependency, FlowRuntime, FlowServiceConfig};
use serde::Deserialize;
use serde_json::Value;
use tower::ServiceExt;

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    required_components: Vec<String>,
    native_backend: String,
    native_capabilities: Vec<String>,
    ready_before_all_healthy: bool,
    ready_after_all_healthy: bool,
    ready_after_required_failure: bool,
}

fn config() -> FlowServiceConfig {
    FlowServiceConfig::from_values([
        ("ENVIRONMENT".into(), "development".into()),
        ("DATABASE_URL".into(), "postgresql://db/flow".into()),
        ("REDIS_URL".into(), "redis://redis".into()),
    ])
    .expect("configuration")
}

#[tokio::test]
async fn flow_runtime_uses_the_shared_required_readiness_gate() {
    let contract: Contract = serde_json::from_str(include_str!(
        "../../../../contracts/flow-runtime-behavior.json"
    ))
    .expect("contract");
    assert_eq!(contract.schema_version, 1);
    assert!(!contract.ready_before_all_healthy);
    assert!(contract.ready_after_all_healthy);
    assert!(!contract.ready_after_required_failure);
    assert_eq!(
        FlowDependency::all()
            .map(|dependency| dependency.name().to_owned())
            .collect::<Vec<_>>(),
        contract.required_components
    );

    let runtime = FlowRuntime::new(&config()).expect("runtime");
    assert!(!runtime.state().readiness().expect("readiness").ready);
    assert!(runtime.activate().is_err());
    for dependency in FlowDependency::all() {
        runtime.mark_healthy(dependency).expect("healthy");
    }
    runtime.activate().expect("active");
    assert!(runtime.state().readiness().expect("readiness").ready);
    runtime
        .mark_unhealthy(FlowDependency::NonceStore, "connection lost")
        .expect("unhealthy");
    assert!(!runtime.state().readiness().expect("readiness").ready);
}

#[tokio::test]
async fn operational_routes_report_native_and_dependency_state() {
    let contract: Contract = serde_json::from_str(include_str!(
        "../../../../contracts/flow-runtime-behavior.json"
    ))
    .expect("contract");
    let runtime = FlowRuntime::new(&config()).expect("runtime");
    let router = runtime.operational_router();
    let not_ready = router
        .clone()
        .oneshot(Request::get("/ready").body(Body::empty()).expect("request"))
        .await
        .expect("response");
    assert_eq!(not_ready.status(), 503);

    let native = router
        .oneshot(
            Request::get("/health/native-backend")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(native.status(), 200);
    let bytes = axum::body::to_bytes(native.into_body(), 64 * 1024)
        .await
        .expect("body");
    let body: Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(body["backend"], contract.native_backend);
    assert_eq!(
        body["capabilities"],
        serde_json::json!(contract.native_capabilities)
    );
}
