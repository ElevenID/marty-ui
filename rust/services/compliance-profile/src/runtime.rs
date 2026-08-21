use crate::ComplianceServiceConfig;
use axum::{routing::get, Json, Router};
use mmf_core::{BuildInfo, ComponentHealth, HealthStatus, LifecycleState, MmfError};
use mmf_runtime::{system_router, RuntimeState};
use serde_json::{json, Value};
#[derive(Clone, Copy)]
pub enum ComplianceDependency {
    Database,
    Schema,
    SystemCatalog,
    Organization,
    NativeKernel,
    HttpListener,
}
impl ComplianceDependency {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::Schema => "compliance_profile_schema",
            Self::SystemCatalog => "system_catalog",
            Self::Organization => "organization_grpc",
            Self::NativeKernel => "native_compliance_profile_kernel",
            Self::HttpListener => "http_listener",
        }
    }
    fn all() -> impl Iterator<Item = Self> {
        [
            Self::Database,
            Self::Schema,
            Self::SystemCatalog,
            Self::Organization,
            Self::NativeKernel,
            Self::HttpListener,
        ]
        .into_iter()
    }
}
#[derive(Clone)]
pub struct ComplianceRuntime {
    state: RuntimeState,
}
impl ComplianceRuntime {
    pub fn new(c: &ComplianceServiceConfig) -> Result<Self, MmfError> {
        let state = RuntimeState::new(BuildInfo {
            service: "compliance-profile".into(),
            version: c.release_version.clone(),
            build_revision: c.build_revision.clone(),
            enabled_features: vec![
                "http".into(),
                "postgres_migrations".into(),
                "system_catalog".into(),
                "tenant_authorization".into(),
                "native_compliance_profiles".into(),
            ],
        });
        for d in ComplianceDependency::all() {
            state.register_required_component(d.name())?;
        }
        state.transition(LifecycleState::Initialized)?;
        state.transition(LifecycleState::Starting)?;
        Ok(Self { state })
    }
    pub fn mark_healthy(&self, d: ComplianceDependency) -> Result<(), MmfError> {
        self.state.set_component_health(
            d.name(),
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
    pub fn router(&self) -> Router {
        system_router(self.state.clone()).route("/health/native-backend", get(native))
    }
}
async fn native() -> Json<Value> {
    Json(
        json!({"status":"ready","available":true,"backend":"marty-compliance-profile-rust","version":env!("CARGO_PKG_VERSION"),"authoritative":true,"python_fallback":false,"capabilities":["profile_lifecycle","policy_storage","system_catalog","tenant_authorization","postgres_migrations"]}),
    )
}
