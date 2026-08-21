use axum::{routing::get, Json, Router};
use mmf_core::{BuildInfo, ComponentHealth, HealthStatus, LifecycleState, MmfError};
use mmf_runtime::{system_router, RuntimeState};
use serde_json::{json, Value};

use crate::DeploymentServiceConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeploymentDependency {
    Database,
    Schema,
    Organization,
    NativeKernel,
    HttpListener,
}

impl DeploymentDependency {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::Schema => "deployment_profile_schema",
            Self::Organization => "organization_grpc",
            Self::NativeKernel => "native_deployment_profile_kernel",
            Self::HttpListener => "http_listener",
        }
    }
    fn all() -> impl Iterator<Item = Self> {
        [
            Self::Database,
            Self::Schema,
            Self::Organization,
            Self::NativeKernel,
            Self::HttpListener,
        ]
        .into_iter()
    }
}

#[derive(Clone)]
pub struct DeploymentRuntime {
    state: RuntimeState,
}

impl DeploymentRuntime {
    pub fn new(config: &DeploymentServiceConfig) -> Result<Self, MmfError> {
        let state = RuntimeState::new(BuildInfo {
            service: "deployment-profile".into(),
            version: config.release_version.clone(),
            build_revision: config.build_revision.clone(),
            enabled_features: vec![
                "http".into(),
                "postgres_migrations".into(),
                "tenant_authorization".into(),
                "atomic_lane_assignment".into(),
                "native_deployment_profiles".into(),
            ],
        });
        for dependency in DeploymentDependency::all() {
            state.register_required_component(dependency.name())?;
        }
        state.transition(LifecycleState::Initialized)?;
        state.transition(LifecycleState::Starting)?;
        Ok(Self { state })
    }
    pub fn state(&self) -> RuntimeState {
        self.state.clone()
    }
    pub fn mark_healthy(&self, dependency: DeploymentDependency) -> Result<(), MmfError> {
        self.state.set_component_health(
            dependency.name(),
            ComponentHealth {
                status: HealthStatus::Healthy,
                message: None,
            },
        )
    }
    pub fn activate(&self) -> Result<(), MmfError> {
        self.state.transition(LifecycleState::Active)
    }
    pub fn drain(&self) -> Result<(), MmfError> {
        self.state.transition(LifecycleState::Draining)
    }
    pub fn stop(&self) -> Result<(), MmfError> {
        self.state.transition(LifecycleState::Stopped)
    }
    pub fn operational_router(&self) -> Router {
        system_router(self.state()).merge(native_backend_router())
    }
}

fn native_backend_router() -> Router {
    Router::new().route("/health/native-backend", get(native_health))
}
async fn native_health() -> Json<Value> {
    Json(json!({
        "status":"ready", "available":true, "backend":"marty-deployment-profile-rust",
        "version":env!("CARGO_PKG_VERSION"), "authoritative":true, "python_fallback":false,
        "capabilities":["profile_lifecycle","runtime_configuration","api_key_generation","lane_management","atomic_device_assignment","postgres_migrations"]
    }))
}
