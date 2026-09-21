//! Secret-safe structured diagnostics for internal Application operations.
//!
//! Callers can report only an enumerated stage/category plus identifiers that
//! are immediately reduced to bounded, domain-separated correlation hashes.
//! The API intentionally accepts no free-form error, URL, header, body, token,
//! or applicant data, so dependency failures remain useful to operators
//! without becoming a second secret-disclosure surface.

use sha2::{Digest, Sha256};

const DIAGNOSTIC_EVENT: &str = "internal_application_failure";
const DIAGNOSTIC_TARGET: &str = "marty.internal_application.diagnostics";
const CORRELATION_DOMAIN: &[u8] = b"marty:internal-application-diagnostic:v1:";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InternalApplicationDiagnosticStage {
    ExternalEvidenceTransport,
    CanvasApprovalReadiness,
    CanvasApprovalIssuerContext,
    CanvasOfferReadiness,
    CanvasOfferIssuerContext,
    OrdinaryIssuerContext,
    WalletCatalogTemplate,
    WalletCatalogConfiguration,
    WalletCatalogList,
    WalletCatalogGet,
}

impl InternalApplicationDiagnosticStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ExternalEvidenceTransport => "external_evidence_transport",
            Self::CanvasApprovalReadiness => "canvas_approval_readiness",
            Self::CanvasApprovalIssuerContext => "canvas_approval_issuer_context",
            Self::CanvasOfferReadiness => "canvas_offer_readiness",
            Self::CanvasOfferIssuerContext => "canvas_offer_issuer_context",
            Self::OrdinaryIssuerContext => "ordinary_issuer_context",
            Self::WalletCatalogTemplate => "wallet_catalog_template",
            Self::WalletCatalogConfiguration => "wallet_catalog_configuration",
            Self::WalletCatalogList => "wallet_catalog_list",
            Self::WalletCatalogGet => "wallet_catalog_get",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InternalApplicationDiagnosticCategory {
    DependencyUnavailable,
    InvalidResponse,
    InvalidConfiguration,
    NotFound,
    RolloutDisabled,
    InvalidStatus,
    NotReady,
    TransactionPlanUnavailable,
    IssuerContextInvalid,
}

impl InternalApplicationDiagnosticCategory {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DependencyUnavailable => "dependency_unavailable",
            Self::InvalidResponse => "invalid_response",
            Self::InvalidConfiguration => "invalid_configuration",
            Self::NotFound => "not_found",
            Self::RolloutDisabled => "rollout_disabled",
            Self::InvalidStatus => "invalid_status",
            Self::NotReady => "not_ready",
            Self::TransactionPlanUnavailable => "transaction_plan_unavailable",
            Self::IssuerContextInvalid => "issuer_context_invalid",
        }
    }
}

/// Immutable, secret-safe projection shared by structured logging and
/// governed behavior observation. Identifier inputs are retained only as
/// bounded domain-separated hashes.
#[derive(Clone, Debug, Eq, PartialEq)]
struct InternalApplicationDiagnosticProjection {
    stage: InternalApplicationDiagnosticStage,
    category: InternalApplicationDiagnosticCategory,
    application_correlation_sha256: Option<String>,
    check_correlation_sha256: Option<String>,
    resource_correlation_sha256: Option<String>,
}

#[cfg(any(test, feature = "feature-regression-observer"))]
tokio::task_local! {
    /// The observer is scoped to exactly one async request task. It is absent
    /// from regular production builds and never changes tracing emission.
    static FEATURE_REGRESSION_OBSERVATIONS: std::cell::RefCell<Vec<String>>;
}

impl InternalApplicationDiagnosticProjection {
    /// Stable one-line diagnostic containing only enumerated values and hashes.
    #[cfg(any(test, feature = "feature-regression-observer"))]
    #[must_use]
    fn safe_server_diagnostic(&self) -> String {
        format!(
            "event={DIAGNOSTIC_EVENT};stage={};category={};application_correlation_sha256={};check_correlation_sha256={};resource_correlation_sha256={}",
            self.stage.as_str(),
            self.category.as_str(),
            self.application_correlation_sha256.as_deref().unwrap_or(""),
            self.check_correlation_sha256.as_deref().unwrap_or(""),
            self.resource_correlation_sha256.as_deref().unwrap_or("")
        )
    }

    fn emit(self) {
        #[cfg(any(test, feature = "feature-regression-observer"))]
        let _ = FEATURE_REGRESSION_OBSERVATIONS.try_with(|observations| {
            observations
                .borrow_mut()
                .push(self.safe_server_diagnostic());
        });
        tracing::warn!(
            target: DIAGNOSTIC_TARGET,
            event = DIAGNOSTIC_EVENT,
            stage = self.stage.as_str(),
            category = self.category.as_str(),
            application_correlation_sha256 =
                self.application_correlation_sha256.as_deref().unwrap_or(""),
            check_correlation_sha256 = self.check_correlation_sha256.as_deref().unwrap_or(""),
            resource_correlation_sha256 = self.resource_correlation_sha256.as_deref().unwrap_or(""),
            "internal Application operation failed"
        );
    }
}

fn correlation_sha256(kind: &str, value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(CORRELATION_DOMAIN);
    digest.update(kind.as_bytes());
    digest.update(b":");
    digest.update(value.as_bytes());
    hex::encode(digest.finalize())
}

pub(crate) fn warn_application_failure(
    stage: InternalApplicationDiagnosticStage,
    category: InternalApplicationDiagnosticCategory,
    application_id: &str,
) {
    application_failure_diagnostic(stage, category, application_id).emit();
}

#[cfg(any(test, feature = "feature-regression-observer"))]
async fn capture_internal_application_diagnostics<F>(
    run: F,
) -> (F::Output, Vec<String>)
where
    F: std::future::Future,
{
    assert!(
        FEATURE_REGRESSION_OBSERVATIONS.try_with(|_| ()).is_err(),
        "internal Application diagnostic observer scopes cannot be nested"
    );
    FEATURE_REGRESSION_OBSERVATIONS
        .scope(std::cell::RefCell::new(Vec::new()), async move {
            let output = run.await;
            let observations = FEATURE_REGRESSION_OBSERVATIONS
                .with(|values| std::mem::take(&mut *values.borrow_mut()));
            (output, observations)
        })
        .await
}

/// Observe the secret-safe diagnostics emitted by exactly one governed async
/// behavior invocation. This bootstrap-only API is compiled out unless the
/// dedicated feature-regression probe opts in.
#[cfg(feature = "feature-regression-observer")]
pub async fn observe_internal_application_diagnostics<F>(
    run: F,
) -> (F::Output, Vec<String>)
where
    F: std::future::Future,
{
    capture_internal_application_diagnostics(run).await
}

#[cfg(test)]
pub(crate) async fn capture_test_internal_application_diagnostics<F>(
    run: F,
) -> (F::Output, Vec<String>)
where
    F: std::future::Future,
{
    capture_internal_application_diagnostics(run).await
}

fn application_failure_diagnostic(
    stage: InternalApplicationDiagnosticStage,
    category: InternalApplicationDiagnosticCategory,
    application_id: &str,
) -> InternalApplicationDiagnosticProjection {
    InternalApplicationDiagnosticProjection {
        stage,
        category,
        application_correlation_sha256: Some(correlation_sha256("application", application_id)),
        check_correlation_sha256: None,
        resource_correlation_sha256: None,
    }
}

pub(crate) fn warn_external_evidence_failure(application_id: &str, check_id: &str) {
    InternalApplicationDiagnosticProjection {
        stage: InternalApplicationDiagnosticStage::ExternalEvidenceTransport,
        category: InternalApplicationDiagnosticCategory::DependencyUnavailable,
        application_correlation_sha256: Some(correlation_sha256("application", application_id)),
        check_correlation_sha256: Some(correlation_sha256("check", check_id)),
        resource_correlation_sha256: None,
    }
    .emit();
}

pub(crate) fn warn_wallet_catalog_failure(
    stage: InternalApplicationDiagnosticStage,
    category: InternalApplicationDiagnosticCategory,
    resource_id: &str,
) {
    InternalApplicationDiagnosticProjection {
        stage,
        category,
        application_correlation_sha256: None,
        check_correlation_sha256: None,
        resource_correlation_sha256: Some(correlation_sha256("resource", resource_id)),
    }
    .emit();
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        fmt,
        process::Command,
        sync::{Arc, Mutex},
    };

    #[cfg(feature = "feature-regression-observer")]
    use futures_util::FutureExt;
    #[cfg(feature = "feature-regression-observer")]
    use std::panic::AssertUnwindSafe;
    use serde_json::Value;
    use tracing::{field::Visit, subscriber::Interest, Event, Metadata, Subscriber};
    use tracing_subscriber::{layer::Context, prelude::*, Layer};

    use super::*;

    #[test]
    fn application_projection_is_stable_and_retains_only_a_correlation_hash() {
        let raw = "application-private-id\nBearer private-token https://provider.example alice@example.test";
        let projection = application_failure_diagnostic(
            InternalApplicationDiagnosticStage::OrdinaryIssuerContext,
            InternalApplicationDiagnosticCategory::DependencyUnavailable,
            raw,
        );
        let safe = projection.safe_server_diagnostic();
        assert_eq!(
            safe,
            format!(
                "event=internal_application_failure;stage=ordinary_issuer_context;category=dependency_unavailable;application_correlation_sha256={};check_correlation_sha256=;resource_correlation_sha256=",
                correlation_sha256("application", raw)
            )
        );
        for forbidden in [
            raw,
            "application-private-id",
            "private-token",
            "https://provider.example",
            "alice@example.test",
        ] {
            assert!(!safe.contains(forbidden), "leaked {forbidden:?}");
        }
    }

    #[cfg(feature = "feature-regression-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn feature_observer_is_task_scoped_non_nested_and_cleans_up() {
        let application = "scoped-application";
        let ((), captured) = observe_internal_application_diagnostics(async {
            warn_application_failure(
                InternalApplicationDiagnosticStage::OrdinaryIssuerContext,
                InternalApplicationDiagnosticCategory::DependencyUnavailable,
                application,
            );
        })
        .await;
        assert_eq!(captured.len(), 1);

        let nested = AssertUnwindSafe(observe_internal_application_diagnostics(async {
            let _ = observe_internal_application_diagnostics(async {}).await;
        }))
        .catch_unwind()
        .await;
        assert!(nested.is_err(), "observer scopes must reject nesting");

        warn_application_failure(
            InternalApplicationDiagnosticStage::OrdinaryIssuerContext,
            InternalApplicationDiagnosticCategory::DependencyUnavailable,
            "outside-scope",
        );
        let ((), after_cleanup) = observe_internal_application_diagnostics(async {}).await;
        assert!(after_cleanup.is_empty(), "observer state leaked across scopes");
    }

    #[derive(Clone, Default)]
    struct CaptureLayer(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

    #[derive(Default)]
    struct EventVisitor(BTreeMap<String, String>);

    impl Visit for EventVisitor {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.insert(field.name().to_owned(), value.to_owned());
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
            self.0.insert(
                field.name().to_owned(),
                format!("{value:?}").trim_matches('"').to_owned(),
            );
        }
    }

    impl<S: Subscriber> Layer<S> for CaptureLayer {
        fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
            if metadata.target() == DIAGNOSTIC_TARGET {
                Interest::always()
            } else {
                Interest::never()
            }
        }

        fn enabled(&self, metadata: &Metadata<'_>, _context: Context<'_, S>) -> bool {
            metadata.target() == DIAGNOSTIC_TARGET
        }

        fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
            if event.metadata().target() != DIAGNOSTIC_TARGET {
                return;
            }
            let mut visitor = EventVisitor::default();
            event.record(&mut visitor);
            visitor
                .0
                .insert("level".to_owned(), event.metadata().level().to_string());
            self.0.lock().expect("captured diagnostics").push(visitor.0);
        }
    }

    #[test]
    fn actual_tracing_event_fields_are_stable_in_isolated_process() {
        let output = Command::new(std::env::current_exe().expect("current unit-test executable"))
            .args([
                "--exact",
                "internal_application_diagnostics::tests::actual_tracing_event_child",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .expect("run isolated tracing assertion");
        assert!(
            output.status.success(),
            "isolated tracing assertion failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "run by actual_tracing_event_fields_are_stable_in_isolated_process"]
    fn actual_tracing_event_child() {
        let application = "child-application\nBearer private-child-token";
        let check = "child-check https://provider.example/?token=private child@example.test";
        let capture = CaptureLayer::default();
        let events = capture.0.clone();
        let subscriber = tracing_subscriber::registry().with(capture);

        tracing::subscriber::with_default(subscriber, || {
            warn_external_evidence_failure(application, check);
        });

        let events = events.lock().expect("captured diagnostic event");
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event["event"], DIAGNOSTIC_EVENT);
        assert_eq!(event["level"], "WARN");
        assert_eq!(event["stage"], "external_evidence_transport");
        assert_eq!(event["category"], "dependency_unavailable");
        assert_eq!(
            event["application_correlation_sha256"],
            correlation_sha256("application", application)
        );
        assert_eq!(
            event["check_correlation_sha256"],
            correlation_sha256("check", check)
        );
        assert_eq!(event["resource_correlation_sha256"], "");
        let serialized = format!("{event:?}");
        for forbidden in [
            application,
            check,
            "private-child-token",
            "https://provider.example",
            "child@example.test",
        ] {
            assert!(!serialized.contains(forbidden), "leaked {forbidden:?}");
        }
    }

    fn diagnostic_field<'a>(diagnostic: &'a str, name: &str) -> &'a str {
        diagnostic
            .split(';')
            .filter_map(|field| field.split_once('='))
            .find_map(|(key, value)| (key == name).then_some(value))
            .expect("diagnostic field")
    }

    #[tokio::test(flavor = "current_thread")]
    async fn all_diagnostic_stages_emit_only_hashed_correlations() {
        let application = "application\nBearer secret-token https://provider.example/path?token=x alice@example.test";
        let check = "check\nsecret-token https://check.example/?key=x bob@example.test";
        let resource = "resource\nsecret-token https://wallet.example/?key=x eve@example.test";
        let ((), events) = capture_test_internal_application_diagnostics(async {
                warn_external_evidence_failure(application, check);
                for (stage, category) in [
                    (
                        InternalApplicationDiagnosticStage::CanvasApprovalReadiness,
                        InternalApplicationDiagnosticCategory::RolloutDisabled,
                    ),
                    (
                        InternalApplicationDiagnosticStage::CanvasApprovalIssuerContext,
                        InternalApplicationDiagnosticCategory::DependencyUnavailable,
                    ),
                    (
                        InternalApplicationDiagnosticStage::CanvasOfferReadiness,
                        InternalApplicationDiagnosticCategory::InvalidStatus,
                    ),
                    (
                        InternalApplicationDiagnosticStage::CanvasOfferIssuerContext,
                        InternalApplicationDiagnosticCategory::IssuerContextInvalid,
                    ),
                    (
                        InternalApplicationDiagnosticStage::OrdinaryIssuerContext,
                        InternalApplicationDiagnosticCategory::NotReady,
                    ),
                ] {
                    warn_application_failure(stage, category, application);
                }
                for (stage, category) in [
                    (
                        InternalApplicationDiagnosticStage::WalletCatalogTemplate,
                        InternalApplicationDiagnosticCategory::NotFound,
                    ),
                    (
                        InternalApplicationDiagnosticStage::WalletCatalogConfiguration,
                        InternalApplicationDiagnosticCategory::InvalidConfiguration,
                    ),
                    (
                        InternalApplicationDiagnosticStage::WalletCatalogList,
                        InternalApplicationDiagnosticCategory::InvalidResponse,
                    ),
                    (
                        InternalApplicationDiagnosticStage::WalletCatalogGet,
                        InternalApplicationDiagnosticCategory::TransactionPlanUnavailable,
                    ),
                ] {
                    warn_wallet_catalog_failure(stage, category, resource);
                }
            })
            .await;

        assert_eq!(events.len(), 10);
        let contract: Value = serde_json::from_str(include_str!(
            "../../../../contracts/issuance-internal-applications.json"
        ))
        .expect("internal Application contract");
        let diagnostics = &contract["operational_diagnostics"];
        let expected_stages = diagnostics["stages"]
            .as_array()
            .expect("diagnostic stages")
            .iter()
            .map(|stage| stage.as_str().expect("stage").to_owned())
            .collect::<Vec<_>>();
        let actual_stages = events
            .iter()
            .map(|diagnostic| diagnostic_field(diagnostic, "stage").to_owned())
            .collect::<Vec<_>>();
        assert_eq!(actual_stages, expected_stages);
        assert_eq!(
            events
                .iter()
                .map(|diagnostic| diagnostic_field(diagnostic, "category"))
                .collect::<BTreeSet<_>>(),
            diagnostics["categories"]
                .as_array()
                .expect("diagnostic categories")
                .iter()
                .map(|category| category.as_str().expect("category"))
                .collect::<BTreeSet<_>>()
        );

        let serialized = format!("{events:?}");
        for forbidden in [
            application,
            check,
            resource,
            "secret-token",
            "https://provider.example",
            "https://check.example",
            "https://wallet.example",
            "alice@example.test",
            "bob@example.test",
            "eve@example.test",
        ] {
            assert!(!serialized.contains(forbidden), "leaked {forbidden:?}");
        }

        assert_eq!(DIAGNOSTIC_EVENT, diagnostics["event"]);
        assert_eq!(DIAGNOSTIC_TARGET, "marty.internal_application.diagnostics");
        for diagnostic in events.iter() {
            for field in [
                "application_correlation_sha256",
                "check_correlation_sha256",
                "resource_correlation_sha256",
            ] {
                let value = diagnostic_field(diagnostic, field);
                assert!(
                    value.is_empty()
                        || (value.len() == 64
                            && value.chars().all(|character| {
                                character.is_ascii_hexdigit() && !character.is_ascii_uppercase()
                            })),
                    "invalid correlation hash in {field}: {value:?}"
                );
            }
        }
        assert_eq!(
            diagnostic_field(&events[0], "application_correlation_sha256"),
            correlation_sha256("application", application)
        );
        assert_eq!(
            diagnostic_field(&events[0], "check_correlation_sha256"),
            correlation_sha256("check", check)
        );
        assert_eq!(
            diagnostic_field(&events[6], "resource_correlation_sha256"),
            correlation_sha256("resource", resource)
        );
        assert_eq!(
            diagnostics["fields"],
            serde_json::json!([
                "event",
                "stage",
                "category",
                "application_correlation_sha256",
                "check_correlation_sha256",
                "resource_correlation_sha256"
            ])
        );
    }
}
