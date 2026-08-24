use axum::{routing::get, Json, Router};
use mmf_core::{BuildInfo, ComponentHealth, HealthStatus, LifecycleState, MmfError};
use mmf_runtime::{system_router, RuntimeState};
use serde::Serialize;

use crate::TrustProfileServiceConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustProfileDependency {
    Database,
    Schema,
    SystemCatalog,
    ControlPlane,
    NativeRegistryKernel,
    NativeDidResolver,
    HttpListener,
}

impl TrustProfileDependency {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::Schema => "trust_profile_schema",
            Self::SystemCatalog => "system_catalog",
            Self::ControlPlane => "organization_control_plane",
            Self::NativeRegistryKernel => "native_registry_kernel",
            Self::NativeDidResolver => "native_did_resolver",
            Self::HttpListener => "http_listener",
        }
    }

    fn required() -> impl Iterator<Item = Self> {
        [
            Self::Database,
            Self::Schema,
            Self::SystemCatalog,
            Self::ControlPlane,
            Self::NativeRegistryKernel,
            Self::NativeDidResolver,
            Self::HttpListener,
        ]
        .into_iter()
    }
}

#[derive(Clone)]
pub struct TrustProfileRuntime {
    state: RuntimeState,
}

impl TrustProfileRuntime {
    pub fn new(config: &TrustProfileServiceConfig) -> Result<Self, MmfError> {
        let state = RuntimeState::new(BuildInfo {
            service: "trust-profile".into(),
            version: config.release_version.clone(),
            build_revision: config.build_revision.clone(),
            enabled_features: vec![
                "native_trust_profiles".into(),
                "native_issuer_registry".into(),
                "native_registry_sync_validation".into(),
                "native_did_assertion_key_resolution".into(),
                "organization_overlays".into(),
                "postgres_migrations".into(),
                "system_catalog_reconciliation".into(),
                "fail_closed_control_plane".into(),
                "http".into(),
            ],
        });
        for dependency in TrustProfileDependency::required() {
            state.register_required_component(dependency.name())?;
        }
        state.transition(LifecycleState::Initialized)?;
        state.transition(LifecycleState::Starting)?;
        Ok(Self { state })
    }

    pub fn mark_healthy(&self, dependency: TrustProfileDependency) -> Result<(), MmfError> {
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
    authoritative: bool,
    python_fallback: bool,
    capabilities: &'static [&'static str],
}

fn native_backend_router() -> Router {
    Router::new().route("/health/native-backend", get(native_backend_health))
}

async fn native_backend_health() -> Json<NativeBackendDiagnostics> {
    Json(NativeBackendDiagnostics {
        backend: "marty-trust-profile-rust",
        version: env!("CARGO_PKG_VERSION"),
        authoritative: true,
        python_fallback: false,
        capabilities: &[
            "trust_profile_lifecycle",
            "organization_trust_profiles",
            "issuer_entities",
            "trust_relationships",
            "registry_import_storage",
            "registry_sync_validation",
            "did_assertion_key_resolution",
            "trust_framework_catalog",
            "postgres_migrations",
        ],
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn readiness_requires_every_native_dependency() {
        let config = TrustProfileServiceConfig::from_values(BTreeMap::from([
            (
                "DATABASE_URL".into(),
                "postgresql://marty:secret@localhost/marty".into(),
            ),
            ("MARTY_ISSUER_DID".into(), "did:web:issuer.example".into()),
            (
                "MARTY_ISSUER_BASE_URL".into(),
                "https://issuer.example".into(),
            ),
        ]))
        .unwrap();
        let runtime = TrustProfileRuntime::new(&config).unwrap();
        assert!(runtime.activate().is_err());
        for dependency in TrustProfileDependency::required() {
            runtime.mark_healthy(dependency).unwrap();
        }
        runtime.activate().unwrap();
    }
}
