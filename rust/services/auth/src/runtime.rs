use axum::{routing::get, Json, Router};
use mmf_core::{BuildInfo, ComponentHealth, HealthStatus, LifecycleState, MmfError};
use mmf_runtime::{system_router, RuntimeState};
use serde::Serialize;

use crate::AuthServiceConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthDependency {
    Database,
    SessionCache,
    Oidc,
    Flow,
    Organization,
    Applicant,
    EventOutbox,
    EventStream,
    HttpListener,
    GrpcListener,
}

impl AuthDependency {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::SessionCache => "session_cache",
            Self::Oidc => "oidc",
            Self::Flow => "flow_grpc",
            Self::Organization => "organization_grpc",
            Self::Applicant => "applicant_http",
            Self::EventOutbox => "event_outbox",
            Self::EventStream => "event_stream_grpc",
            Self::HttpListener => "http_listener",
            Self::GrpcListener => "grpc_listener",
        }
    }

    pub fn all() -> impl Iterator<Item = Self> {
        [
            Self::Database,
            Self::SessionCache,
            Self::Oidc,
            Self::Flow,
            Self::Organization,
            Self::Applicant,
            Self::EventOutbox,
            Self::EventStream,
            Self::HttpListener,
            Self::GrpcListener,
        ]
        .into_iter()
    }
}

#[derive(Clone)]
pub struct AuthRuntime {
    state: RuntimeState,
}

impl AuthRuntime {
    pub fn new(config: &AuthServiceConfig) -> Result<Self, MmfError> {
        let state = RuntimeState::new(BuildInfo {
            service: "auth".into(),
            version: config.release_version.clone(),
            build_revision: config.build_revision.clone(),
            enabled_features: vec![
                "http".into(),
                "grpc".into(),
                "postgres".into(),
                "redis".into(),
                "oidc".into(),
                "credential_login".into(),
                "durable_outbox".into(),
                "native_auth".into(),
            ],
        });
        for dependency in AuthDependency::all() {
            state.register_required_component(dependency.name())?;
        }
        state.transition(LifecycleState::Initialized)?;
        state.transition(LifecycleState::Starting)?;
        Ok(Self { state })
    }

    #[must_use]
    pub const fn state(&self) -> &RuntimeState {
        &self.state
    }

    pub fn mark_healthy(&self, dependency: AuthDependency) -> Result<(), MmfError> {
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
    available: bool,
    backend: &'static str,
    version: &'static str,
    capabilities: &'static [&'static str],
}

fn native_backend_router() -> Router {
    Router::new().route("/health/native-backend", get(native_backend_health))
}

async fn native_backend_health() -> Json<NativeBackendDiagnostics> {
    Json(NativeBackendDiagnostics {
        available: true,
        backend: "marty-auth-rust",
        version: env!("CARGO_PKG_VERSION"),
        capabilities: &[
            "oidc",
            "sessions",
            "pkce",
            "credential_login",
            "canvas_lti",
            "http_service",
            "grpc_service",
            "mmf_transports",
        ],
    })
}
