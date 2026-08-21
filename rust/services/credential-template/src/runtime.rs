use axum::{routing::get, Json, Router};
use mmf_core::{BuildInfo, ComponentHealth, HealthStatus, LifecycleState, MmfError};
use mmf_runtime::{system_router, RuntimeState};
use serde::Serialize;

use crate::config::CredentialTemplateServiceConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialTemplateDependency {
    Database,
    Schema,
    SystemCatalog,
    ControlPlane,
    HttpListener,
    GrpcListener,
}

impl CredentialTemplateDependency {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::Schema => "credential_template_schema",
            Self::SystemCatalog => "system_catalog",
            Self::ControlPlane => "control_plane_clients",
            Self::HttpListener => "http_listener",
            Self::GrpcListener => "grpc_listener",
        }
    }

    fn required() -> impl Iterator<Item = Self> {
        [
            Self::Database,
            Self::Schema,
            Self::SystemCatalog,
            Self::ControlPlane,
            Self::HttpListener,
            Self::GrpcListener,
        ]
        .into_iter()
    }
}

#[derive(Clone)]
pub struct CredentialTemplateRuntime {
    state: RuntimeState,
}

impl CredentialTemplateRuntime {
    pub fn new(config: &CredentialTemplateServiceConfig) -> Result<Self, MmfError> {
        let state = RuntimeState::new(BuildInfo {
            service: "credential-template".into(),
            version: config.release_version.clone(),
            build_revision: config.build_revision.clone(),
            enabled_features: vec![
                "native_credential_templates".into(),
                "wallet_registry".into(),
                "delivery_destinations".into(),
                "http".into(),
                "grpc".into(),
                "postgres".into(),
                "fail_closed_control_plane".into(),
            ],
        });
        for dependency in CredentialTemplateDependency::required() {
            state.register_required_component(dependency.name())?;
        }
        state.transition(LifecycleState::Initialized)?;
        state.transition(LifecycleState::Starting)?;
        Ok(Self { state })
    }

    pub fn mark_healthy(&self, dependency: CredentialTemplateDependency) -> Result<(), MmfError> {
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
        backend: "marty-credential-template-rust",
        version: env!("CARGO_PKG_VERSION"),
        capabilities: &[
            "credential_template_lifecycle",
            "credential_configuration_projection",
            "wallet_registry",
            "delivery_destinations",
            "http_service",
            "grpc_service",
            "postgres_migrations",
            "system_catalog_reconciliation",
        ],
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn readiness_requires_every_native_runtime_dependency() {
        let config = CredentialTemplateServiceConfig::from_values(BTreeMap::from([(
            "DATABASE_URL".into(),
            "postgresql://marty:secret@localhost/marty".into(),
        )]))
        .unwrap();
        let runtime = CredentialTemplateRuntime::new(&config).unwrap();
        assert!(runtime.activate().is_err());
        for dependency in CredentialTemplateDependency::required() {
            runtime.mark_healthy(dependency).unwrap();
        }
        runtime.activate().unwrap();
    }
}
