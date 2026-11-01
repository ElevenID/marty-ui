use crate::ComplianceServiceConfig;
use axum::{routing::get, Json, Router};
use mmf_core::{BuildInfo, LifecycleState, MmfError};
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
        let state = RuntimeState::starting(
            BuildInfo {
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
            },
            ComplianceDependency::all().map(|d| d.name()),
        )?;
        Ok(Self { state })
    }
    pub fn mark_healthy(&self, d: ComplianceDependency) -> Result<(), MmfError> {
        self.state.mark_component_healthy(d.name())
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    async fn readiness(runtime: &ComplianceRuntime) -> StatusCode {
        runtime
            .router()
            .oneshot(Request::get("/ready").body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn required_listener_health_and_drain_control_operational_readiness() {
        let config = ComplianceServiceConfig::from_values([
            ("ENVIRONMENT".into(), "development".into()),
            ("DATABASE_URL".into(), "postgresql://db/compliance".into()),
        ])
        .unwrap();
        let runtime = ComplianceRuntime::new(&config).unwrap();
        assert_eq!(readiness(&runtime).await, StatusCode::SERVICE_UNAVAILABLE);
        assert!(runtime.activate().is_err());
        for dependency in ComplianceDependency::all().filter(|d| d.name() != "http_listener") {
            runtime.mark_healthy(dependency).unwrap();
        }
        assert!(runtime.activate().is_err());
        assert_eq!(readiness(&runtime).await, StatusCode::SERVICE_UNAVAILABLE);
        runtime
            .mark_healthy(ComplianceDependency::HttpListener)
            .unwrap();
        runtime.activate().unwrap();
        assert_eq!(readiness(&runtime).await, StatusCode::OK);
        runtime.drain().unwrap();
        assert_eq!(readiness(&runtime).await, StatusCode::SERVICE_UNAVAILABLE);
        runtime.stop().unwrap();
        assert_eq!(readiness(&runtime).await, StatusCode::SERVICE_UNAVAILABLE);
    }
}
