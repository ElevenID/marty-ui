use axum::{routing::get, Json, Router};
use mmf_core::{BuildInfo, ComponentHealth, HealthStatus, LifecycleState, MmfError};
use mmf_runtime::{system_router, RuntimeState};
use serde::Serialize;

use crate::OrganizationServiceConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrganizationDependency {
    Database,
    Redis,
    PolicyValidation,
    TransactionalOutbox,
    EventStream,
    HttpListener,
    GrpcListener,
}

impl OrganizationDependency {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::Redis => "redis",
            Self::PolicyValidation => "cedar_policy_validation",
            Self::TransactionalOutbox => "transactional_outbox",
            Self::EventStream => "event_stream_grpc",
            Self::HttpListener => "http_listener",
            Self::GrpcListener => "grpc_listener",
        }
    }

    fn required() -> impl Iterator<Item = Self> {
        [
            Self::Database,
            Self::Redis,
            Self::PolicyValidation,
            Self::TransactionalOutbox,
            Self::HttpListener,
            Self::GrpcListener,
        ]
        .into_iter()
    }
}

#[derive(Clone)]
pub struct OrganizationRuntime {
    state: RuntimeState,
}

impl OrganizationRuntime {
    pub fn new(config: &OrganizationServiceConfig) -> Result<Self, MmfError> {
        let state = RuntimeState::new(BuildInfo {
            service: "organization".into(),
            version: config.release_version.clone(),
            build_revision: config.build_revision.clone(),
            enabled_features: vec![
                "native_organization".into(),
                "http".into(),
                "grpc".into(),
                "postgres".into(),
                "redis".into(),
                "cedar".into(),
                "transactional_outbox".into(),
                "scim".into(),
            ],
        });
        for dependency in OrganizationDependency::required() {
            state.register_required_component(dependency.name())?;
        }
        state.register_optional_component(OrganizationDependency::EventStream.name())?;
        state.transition(LifecycleState::Initialized)?;
        state.transition(LifecycleState::Starting)?;
        Ok(Self { state })
    }

    pub fn mark_healthy(&self, dependency: OrganizationDependency) -> Result<(), MmfError> {
        self.set_health(dependency, HealthStatus::Healthy, None)
    }

    pub fn mark_degraded(
        &self,
        dependency: OrganizationDependency,
        message: impl Into<String>,
    ) -> Result<(), MmfError> {
        self.set_health(dependency, HealthStatus::Degraded, Some(message.into()))
    }

    fn set_health(
        &self,
        dependency: OrganizationDependency,
        status: HealthStatus,
        message: Option<String>,
    ) -> Result<(), MmfError> {
        self.state
            .set_component_health(dependency.name(), ComponentHealth { status, message })
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
        system_router(self.state.clone()).merge(native_backend_router())
    }
}

#[derive(Debug, Serialize)]
struct NativeBackendDiagnostics {
    backend: &'static str,
    version: &'static str,
    capabilities: &'static [&'static str],
}

fn native_backend_router() -> Router {
    Router::new().route("/health/native-backend", get(native_backend_health))
}

async fn native_backend_health() -> Json<NativeBackendDiagnostics> {
    Json(NativeBackendDiagnostics {
        backend: "marty-organization-rust",
        version: env!("CARGO_PKG_VERSION"),
        capabilities: &[
            "organization_lifecycle",
            "membership",
            "join_workflows",
            "api_keys",
            "rbac",
            "scim",
            "policy_sets",
            "audit",
            "http_service",
            "grpc_service",
            "transactional_outbox",
        ],
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn config() -> OrganizationServiceConfig {
        OrganizationServiceConfig::from_values(BTreeMap::from([(
            "DATABASE_URL".into(),
            "postgresql://marty:secret@localhost/marty".into(),
        )]))
        .unwrap()
    }

    #[test]
    fn readiness_cannot_activate_before_required_dependencies_are_healthy() {
        let runtime = OrganizationRuntime::new(&config()).unwrap();
        assert!(runtime.activate().is_err());
        for dependency in OrganizationDependency::required() {
            runtime.mark_healthy(dependency).unwrap();
        }
        runtime
            .mark_degraded(OrganizationDependency::EventStream, "retrying")
            .unwrap();
        runtime.activate().unwrap();
    }
}
