use mmf_core::{BuildInfo, ComponentHealth, HealthStatus, LifecycleState, MmfError};
use mmf_runtime::RuntimeState;
use sqlx::PgPool;
use tokio::{sync::watch, time::MissedTickBehavior};

use crate::VerificationServiceConfig;

const COMPATIBILITY_DATABASE_UNAVAILABLE: &str =
    "compatibility PostgreSQL session store unavailable";
const COMPATIBILITY_DATABASE_CHECK_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationDependency {
    SessionStore,
    Organization,
    CredentialTemplate,
    PresentationPolicy,
    NativeVerification,
    CompatibilityDatabase,
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
            Self::CompatibilityDatabase => "compatibility_database",
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
        if config.credentials_compat_enabled {
            state.register_required_component(
                VerificationDependency::CompatibilityDatabase.name(),
            )?;
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

    pub fn mark_degraded(
        &self,
        dependency: VerificationDependency,
        message: &'static str,
    ) -> Result<(), MmfError> {
        self.state.set_component_health(
            dependency.name(),
            ComponentHealth {
                status: HealthStatus::Degraded,
                message: Some(message.into()),
            },
        )
    }

    /// Continuously owns compatibility-database readiness until shutdown.
    ///
    /// A degraded required component keeps liveness available for diagnostics,
    /// while MMF removes the service from readiness until the database recovers.
    pub async fn monitor_compatibility_database(
        &self,
        pool: PgPool,
        shutdown: watch::Receiver<bool>,
    ) -> Result<(), MmfError> {
        self.monitor_compatibility_database_with_interval(
            &pool,
            shutdown,
            COMPATIBILITY_DATABASE_CHECK_INTERVAL,
        )
        .await
    }

    async fn monitor_compatibility_database_with_interval(
        &self,
        pool: &PgPool,
        mut shutdown: watch::Receiver<bool>,
        interval: std::time::Duration,
    ) -> Result<(), MmfError> {
        let mut checks = tokio::time::interval(interval);
        checks.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = checks.tick() => self.refresh_compatibility_database_health(pool).await?,
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
            }
        }
    }

    async fn refresh_compatibility_database_health(&self, pool: &PgPool) -> Result<(), MmfError> {
        if sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(pool)
            .await
            .is_ok()
        {
            self.mark_healthy(VerificationDependency::CompatibilityDatabase)
        } else {
            self.mark_degraded(
                VerificationDependency::CompatibilityDatabase,
                COMPATIBILITY_DATABASE_UNAVAILABLE,
            )
        }
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::{body::Body, http::Request};
    use mmf_core::HealthStatus;
    use mmf_runtime::system_router;
    use sqlx::postgres::PgPoolOptions;
    use tokio::sync::watch;
    use tower::ServiceExt;

    use super::*;

    fn config(credentials_compat_enabled: bool) -> VerificationServiceConfig {
        let fixture: serde_json::Value =
            serde_json::from_str(marty_verification::governance::behavior_fixture_json()).unwrap();
        let mut values = vec![("ENVIRONMENT".into(), "test".into())];
        if credentials_compat_enabled {
            values.extend([
                (
                    "VERIFICATION_CREDENTIALS_COMPAT_ENABLED".into(),
                    "true".into(),
                ),
                (
                    "VERIFICATION_GOVERNANCE_JSON".into(),
                    fixture["governance"].to_string(),
                ),
                (
                    "DATABASE_URL".into(),
                    "postgres://verification:secret@postgres/verification".into(),
                ),
                (
                    "SIGNING_KEYS_INTERNAL_API_KEY".into(),
                    "resolver-secret".into(),
                ),
            ]);
        }
        VerificationServiceConfig::from_values(values).unwrap()
    }

    fn mark_static_dependencies_healthy(runtime: &VerificationRuntime) {
        for dependency in [
            VerificationDependency::SessionStore,
            VerificationDependency::Organization,
            VerificationDependency::CredentialTemplate,
            VerificationDependency::PresentationPolicy,
            VerificationDependency::NativeVerification,
            VerificationDependency::HttpListener,
        ] {
            runtime.mark_healthy(dependency).unwrap();
        }
    }

    #[test]
    fn compatibility_database_is_required_only_when_the_adapter_is_enabled() {
        let native = VerificationRuntime::new(&config(false)).unwrap();
        mark_static_dependencies_healthy(&native);
        native.activate().unwrap();
        assert!(native.state().readiness().unwrap().ready);

        let compatibility = VerificationRuntime::new(&config(true)).unwrap();
        mark_static_dependencies_healthy(&compatibility);
        let error = compatibility.activate().unwrap_err();
        assert!(error
            .details
            .get("components")
            .is_some_and(|components| components == "compatibility_database"));
        compatibility
            .mark_healthy(VerificationDependency::CompatibilityDatabase)
            .unwrap();
        compatibility.activate().unwrap();
        assert!(compatibility.state().readiness().unwrap().ready);
    }

    #[tokio::test]
    async fn database_monitor_removes_readiness_without_failing_liveness_and_stops_cleanly() {
        let runtime = VerificationRuntime::new(&config(true)).unwrap();
        mark_static_dependencies_healthy(&runtime);
        runtime
            .mark_healthy(VerificationDependency::CompatibilityDatabase)
            .unwrap();
        runtime.activate().unwrap();

        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://verification:secret@127.0.0.1/verification")
            .unwrap();
        pool.close().await;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let monitor_runtime = runtime.clone();
        let monitor_pool = pool.clone();
        let monitor = tokio::spawn(async move {
            monitor_runtime
                .monitor_compatibility_database_with_interval(
                    &monitor_pool,
                    shutdown_rx,
                    Duration::from_millis(1),
                )
                .await
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if !runtime.state().readiness().unwrap().ready {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let readiness = runtime.state().readiness().unwrap();
        assert!(!readiness.ready);
        assert_eq!(readiness.health, HealthStatus::Degraded);
        let health = runtime.state().health().unwrap();
        assert_eq!(health.status, HealthStatus::Degraded);
        assert_eq!(
            health.components[VerificationDependency::CompatibilityDatabase.name()]
                .message
                .as_deref(),
            Some(COMPATIBILITY_DATABASE_UNAVAILABLE)
        );
        assert!(!format!("{health:?}").contains("secret"));
        let diagnostics = system_router(runtime.state());
        let liveness = diagnostics
            .clone()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(liveness.status(), 200);
        let readiness = diagnostics
            .oneshot(Request::get("/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(readiness.status(), 503);

        shutdown_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), monitor)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
