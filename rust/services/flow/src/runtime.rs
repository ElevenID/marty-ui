use axum::{routing::get, Json, Router};
use mmf_core::{BuildInfo, ComponentHealth, HealthStatus, LifecycleState, MmfError};
use mmf_runtime::{system_router, RuntimeState};
use serde::Serialize;

use crate::FlowServiceConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowDependency {
    Database,
    NonceStore,
    Organization,
    CredentialTemplate,
    PresentationPolicy,
    IssuanceGrpc,
    SigningKeys,
    PhysicalIssuance,
    ReferenceCatalog,
    CallbackDelivery,
    HttpListener,
    GrpcListener,
}

impl FlowDependency {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::NonceStore => "nonce_store",
            Self::Organization => "organization_grpc",
            Self::CredentialTemplate => "credential_template_grpc",
            Self::PresentationPolicy => "presentation_policy_grpc",
            Self::IssuanceGrpc => "issuance_grpc",
            Self::SigningKeys => "signing_keys_http",
            Self::PhysicalIssuance => "physical_issuance_http",
            Self::ReferenceCatalog => "reference_catalog_http",
            Self::CallbackDelivery => "callback_delivery",
            Self::HttpListener => "http_listener",
            Self::GrpcListener => "grpc_listener",
        }
    }

    pub fn all() -> impl Iterator<Item = Self> {
        [
            Self::Database,
            Self::NonceStore,
            Self::Organization,
            Self::CredentialTemplate,
            Self::PresentationPolicy,
            Self::IssuanceGrpc,
            Self::SigningKeys,
            Self::PhysicalIssuance,
            Self::ReferenceCatalog,
            Self::CallbackDelivery,
            Self::HttpListener,
            Self::GrpcListener,
        ]
        .into_iter()
    }

    /// Dependencies that must be connected and probed before listener and
    /// callback-worker startup can begin.
    pub fn connection_probes() -> impl Iterator<Item = Self> {
        [
            Self::Database,
            Self::NonceStore,
            Self::Organization,
            Self::CredentialTemplate,
            Self::PresentationPolicy,
            Self::IssuanceGrpc,
            Self::SigningKeys,
            Self::PhysicalIssuance,
            Self::ReferenceCatalog,
        ]
        .into_iter()
    }
}

#[derive(Clone)]
pub struct FlowRuntime {
    state: RuntimeState,
}

impl FlowRuntime {
    pub fn new(config: &FlowServiceConfig) -> Result<Self, MmfError> {
        let state = RuntimeState::new(BuildInfo {
            service: "flow".into(),
            version: config.release_version.clone(),
            build_revision: config.build_revision.clone(),
            enabled_features: vec![
                "http".into(),
                "grpc".into(),
                "postgres".into(),
                "redis_nonce_store".into(),
                "native_flow".into(),
                "native_oid4vp".into(),
            ],
        });
        for dependency in FlowDependency::all() {
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

    pub fn mark_healthy(&self, dependency: FlowDependency) -> Result<(), MmfError> {
        self.state.set_component_health(
            dependency.name(),
            ComponentHealth {
                status: HealthStatus::Healthy,
                message: None,
            },
        )
    }

    pub fn mark_unhealthy(
        &self,
        dependency: FlowDependency,
        message: impl Into<String>,
    ) -> Result<(), MmfError> {
        self.state.set_component_health(
            dependency.name(),
            ComponentHealth {
                status: HealthStatus::Unhealthy,
                message: Some(message.into()),
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
        backend: "marty-flow-rust",
        version: env!("CARGO_PKG_VERSION"),
        capabilities: &[
            "flow_graph",
            "flow_transition",
            "oid4vp_request",
            "oid4vp_evaluation",
            "mdoc_handover",
            "haip_jwe",
            "siopv2_verification",
            "http_service",
            "grpc_service",
            "callback_delivery",
        ],
    })
}
