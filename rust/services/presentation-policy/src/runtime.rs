use axum::Router;
use mmf_core::{BuildInfo, ComponentHealth, HealthStatus, LifecycleState, MmfError};
use mmf_runtime::{system_router, NativeBackendDiagnostics, RuntimeState};

use crate::PresentationPolicyServiceConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresentationPolicyDependency {
    Database,
    Schema,
    ControlPlane,
    NativeVerification,
    HttpListener,
    GrpcListener,
}

impl PresentationPolicyDependency {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::Schema => "presentation_policy_schema",
            Self::ControlPlane => "control_plane_clients",
            Self::NativeVerification => "native_verification",
            Self::HttpListener => "http_listener",
            Self::GrpcListener => "grpc_listener",
        }
    }

    fn required() -> impl Iterator<Item = Self> {
        [
            Self::Database,
            Self::Schema,
            Self::ControlPlane,
            Self::NativeVerification,
            Self::HttpListener,
            Self::GrpcListener,
        ]
        .into_iter()
    }
}

#[derive(Clone)]
pub struct PresentationPolicyRuntime {
    state: RuntimeState,
}

impl PresentationPolicyRuntime {
    pub fn new(config: &PresentationPolicyServiceConfig) -> Result<Self, MmfError> {
        let state = RuntimeState::new(BuildInfo {
            service: "presentation-policy".into(),
            version: config.release_version.clone(),
            build_revision: config.build_revision.clone(),
            enabled_features: vec![
                "native_policy_lifecycle".into(),
                "native_credential_verification".into(),
                "live_trust_and_status".into(),
                "http".into(),
                "grpc".into(),
                "postgres".into(),
                "workload_mtls".into(),
            ],
        });
        for dependency in PresentationPolicyDependency::required() {
            state.register_required_component(dependency.name())?;
        }
        state.transition(LifecycleState::Initialized)?;
        state.transition(LifecycleState::Starting)?;
        Ok(Self { state })
    }

    pub fn mark_healthy(&self, dependency: PresentationPolicyDependency) -> Result<(), MmfError> {
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

fn native_backend_router() -> Router {
    mmf_runtime::native_backend_router(NativeBackendDiagnostics {
        backend: "marty-presentation-policy-rust",
        version: env!("CARGO_PKG_VERSION"),
        capabilities: &[
            "policy_lifecycle",
            "verified_fact_evaluation",
            "vc_jwt",
            "data_integrity",
            "sd_jwt",
            "open_badges_v2",
            "open_badges_v3",
            "live_trust",
            "credential_status",
        ],
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn shared_diagnostics_preserve_the_existing_wire_contract() {
        let response = native_backend_router()
            .oneshot(
                Request::builder()
                    .uri("/health/native-backend")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let actual: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            actual,
            serde_json::json!({
                "backend": "marty-presentation-policy-rust",
                "version": env!("CARGO_PKG_VERSION"),
                "capabilities": ["policy_lifecycle", "verified_fact_evaluation", "vc_jwt", "data_integrity", "sd_jwt", "open_badges_v2", "open_badges_v3", "live_trust", "credential_status"]
            })
        );
    }
}
