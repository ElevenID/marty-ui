use mmf_core::{BuildInfo, ComponentHealth, HealthStatus, LifecycleState, MmfError};
use mmf_runtime::RuntimeState;

use crate::VerificationServiceConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationDependency {
    SessionStore,
    Organization,
    CredentialTemplate,
    PresentationPolicy,
    NativeVerification,
    HttpListener,
    GrpcListener,
}

impl VerificationDependency {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SessionStore => "session_store",
            Self::Organization => "organization_grpc",
            Self::CredentialTemplate => "credential_template_grpc",
            Self::PresentationPolicy => "presentation_policy_grpc",
            Self::NativeVerification => "native_verification",
            Self::HttpListener => "http_listener",
            Self::GrpcListener => "grpc_listener",
        }
    }
}

#[derive(Clone)]
pub struct VerificationRuntime {
    state: RuntimeState,
}

impl VerificationRuntime {
    pub fn new(config: &VerificationServiceConfig) -> Result<Self, MmfError> {
        let state = RuntimeState::new(BuildInfo {
            service: "verification".into(),
            version: config.release_version.clone(),
            build_revision: config.build_revision.clone(),
            enabled_features: vec![
                "http".into(),
                "redis_session_coordination".into(),
                "native_oid4vp".into(),
                "native_siopv2".into(),
                "terminal_data_minimization".into(),
            ],
        });
        for dependency in [
            VerificationDependency::SessionStore,
            VerificationDependency::Organization,
            VerificationDependency::CredentialTemplate,
            VerificationDependency::PresentationPolicy,
            VerificationDependency::NativeVerification,
            VerificationDependency::HttpListener,
        ] {
            state.register_required_component(dependency.name())?;
        }
        if config.grpc_enabled {
            state.register_required_component(VerificationDependency::GrpcListener.name())?;
        }
        state.transition(LifecycleState::Initialized)?;
        state.transition(LifecycleState::Starting)?;
        Ok(Self { state })
    }

    #[must_use]
    pub fn state(&self) -> RuntimeState {
        self.state.clone()
    }

    pub fn mark_healthy(&self, dependency: VerificationDependency) -> Result<(), MmfError> {
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
}
