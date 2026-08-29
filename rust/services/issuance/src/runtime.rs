use mmf_core::{BuildInfo, ComponentHealth, HealthStatus, LifecycleState, MmfError};
use mmf_runtime::RuntimeState;

use crate::IssuanceServiceConfig;

const HTTP_LISTENER: &str = "http_listener";

#[derive(Clone)]
pub struct IssuanceRuntime {
    state: RuntimeState,
}

impl IssuanceRuntime {
    pub fn new(config: &IssuanceServiceConfig) -> Result<Self, MmfError> {
        let state = RuntimeState::new(BuildInfo {
            service: "issuance-service".to_owned(),
            version: config.release_version.clone(),
            build_revision: config.build_revision.clone(),
            enabled_features: vec![
                "http_candidate".to_owned(),
                "contract_guard".to_owned(),
                "static_discovery".to_owned(),
            ],
        });
        state.register_required_component(HTTP_LISTENER)?;
        state.transition(LifecycleState::Initialized)?;
        state.transition(LifecycleState::Starting)?;
        Ok(Self { state })
    }

    #[must_use]
    pub fn state(&self) -> RuntimeState {
        self.state.clone()
    }

    pub fn mark_listener_healthy(&self) -> Result<(), MmfError> {
        self.state.set_component_health(
            HTTP_LISTENER,
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
