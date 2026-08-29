use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use marty_issuance_service::{
    canvas_lti_bootstrap::{
        plan_canvas_lti_experience_bootstrap, CanvasLtiAwardCandidateMaterializer,
        CanvasLtiBootstrapApplication, CanvasLtiBootstrapApplicationAction,
        CanvasLtiBootstrapApplicationGenerator, CanvasLtiBootstrapApplicationSeed,
        CanvasLtiBootstrapPlan, CanvasLtiBootstrapPlanError, CanvasLtiBootstrapRepository,
        CanvasLtiBootstrapRepositoryError, CanvasLtiBootstrapRequest, CanvasLtiBootstrapService,
        CanvasLtiBootstrapSyncEnqueuer, CanvasLtiBootstrapSyncError, CanvasLtiBootstrapTemplate,
    },
    canvas_lti_experience::{
        canvas_lti_experience_session_context, CanvasLtiExperienceSessionService,
    },
    canvas_lti_launch::{
        CanvasLtiClock, CanvasLtiLaunchPlanError, CanvasLtiLaunchStateRepository,
        CanvasLtiStoredLaunchState,
    },
};
use serde_json::{json, Map, Value};

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/issuance-canvas-lti-foundation.json"
    ))
    .expect("valid Canvas LTI contract")
}

fn bootstrap_context(
) -> marty_issuance_service::canvas_lti_experience::CanvasLtiExperienceSessionContext {
    let vector = &contract()["experience"]["bootstrap"]["vector"];
    let values = &vector["session_values"];
    let mip_context = values
        .as_object()
        .unwrap()
        .iter()
        .filter(|(name, _)| !matches!(name.as_str(), "state" | "canvas_account_id" | "launch_url"))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<Map<_, _>>();
    canvas_lti_experience_session_context(CanvasLtiStoredLaunchState {
        id: "bootstrap-session-id-1".to_owned(),
        platform_id: values["canvas_platform_id"].as_str().unwrap().to_owned(),
        organization_id: "org-1".to_owned(),
        canvas_account_id: values["canvas_account_id"].as_str().unwrap().to_owned(),
        state: "private-session-digest".to_owned(),
        nonce: "private-session-nonce".to_owned(),
        redirect_uri: "https://ui.example.test/canvas/lti/experience".to_owned(),
        status: "session".to_owned(),
        metadata: json!({
            "kind": "canvas_lti_experience_session",
            "launch_state": values["state"],
            "launch_url": values["launch_url"],
            "verified_launch": vector["verified_launch"],
            "mip_primitives": {"context": mip_context},
        }),
        expired: false,
    })
    .unwrap()
}

fn request() -> CanvasLtiBootstrapRequest {
    let request = &contract()["experience"]["bootstrap"]["vector"]["request"];
    CanvasLtiBootstrapRequest {
        applicant_identifier: request["applicant_identifier"].as_str().map(str::to_owned),
        applicant_data: request["applicant_data"].as_object().unwrap().clone(),
    }
}

fn template() -> CanvasLtiBootstrapTemplate {
    CanvasLtiBootstrapTemplate {
        id: "application-template-1".to_owned(),
        organization_id: "org-1".to_owned(),
    }
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 29, 16, 0, 0).unwrap()
}

fn seed(id: &str) -> impl FnOnce(bool) -> CanvasLtiBootstrapApplicationSeed + '_ {
    move |_| CanvasLtiBootstrapApplicationSeed {
        id: id.to_owned(),
        anonymous_identifier_suffix: "deadbeef".to_owned(),
    }
}

#[derive(Default)]
struct SessionRepository {
    record: Mutex<Option<CanvasLtiStoredLaunchState>>,
}

#[async_trait]
impl CanvasLtiLaunchStateRepository for SessionRepository {
    async fn get_launch_state(
        &self,
        _state: &str,
    ) -> Result<Option<CanvasLtiStoredLaunchState>, CanvasLtiLaunchPlanError> {
        Ok(self.record.lock().unwrap().clone())
    }

    async fn consume_launch_state(
        &self,
        _state: &str,
    ) -> Result<Option<CanvasLtiStoredLaunchState>, CanvasLtiLaunchPlanError> {
        unreachable!("bootstrap never consumes its session")
    }
}

#[derive(Default)]
struct BootstrapRepository {
    feature_enabled: Mutex<Option<bool>>,
    application: Mutex<Option<CanvasLtiBootstrapApplication>>,
    persisted_created: Mutex<Vec<bool>>,
}

#[async_trait]
impl CanvasLtiBootstrapRepository for BootstrapRepository {
    async fn bound_feature_enabled(
        &self,
        _organization_id: &str,
        _binding_id: &str,
        _flag: &str,
    ) -> Result<Option<bool>, CanvasLtiBootstrapRepositoryError> {
        Ok(*self.feature_enabled.lock().unwrap())
    }

    async fn get_template(
        &self,
        template_id: &str,
    ) -> Result<Option<CanvasLtiBootstrapTemplate>, CanvasLtiBootstrapRepositoryError> {
        Ok(Some(CanvasLtiBootstrapTemplate {
            id: template_id.to_owned(),
            organization_id: "org-1".to_owned(),
        }))
    }

    async fn list_applications(
        &self,
        _organization_id: &str,
        _template_id: &str,
    ) -> Result<Vec<CanvasLtiBootstrapApplication>, CanvasLtiBootstrapRepositoryError> {
        Ok(self
            .application
            .lock()
            .unwrap()
            .clone()
            .into_iter()
            .collect())
    }

    async fn persist_plan(
        &self,
        _context: &marty_issuance_service::canvas_lti_experience::CanvasLtiExperienceSessionContext,
        plan: &CanvasLtiBootstrapPlan,
    ) -> Result<(), CanvasLtiBootstrapRepositoryError> {
        self.persisted_created.lock().unwrap().push(plan.created);
        *self.application.lock().unwrap() = Some(plan.application.clone());
        Ok(())
    }

    async fn get_application(
        &self,
        _application_id: &str,
    ) -> Result<Option<CanvasLtiBootstrapApplication>, CanvasLtiBootstrapRepositoryError> {
        Ok(self.application.lock().unwrap().clone())
    }
}

struct Materializer {
    repository: Arc<BootstrapRepository>,
    calls: AtomicUsize,
}

#[async_trait]
impl CanvasLtiAwardCandidateMaterializer for Materializer {
    async fn materialize(
        &self,
        _context: &marty_issuance_service::canvas_lti_experience::CanvasLtiExperienceSessionContext,
        _application: &CanvasLtiBootstrapApplication,
    ) -> Result<(), CanvasLtiBootstrapRepositoryError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(application) = self.repository.application.lock().unwrap().as_mut() {
            application.status = "approved".to_owned();
        }
        Ok(())
    }
}

struct FailingSync(AtomicUsize);

#[async_trait]
impl CanvasLtiBootstrapSyncEnqueuer for FailingSync {
    async fn enqueue(
        &self,
        _organization_id: &str,
        _application_id: &str,
    ) -> Result<(), CanvasLtiBootstrapSyncError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(CanvasLtiBootstrapSyncError)
    }
}

struct CountingGenerator(AtomicUsize);

impl CanvasLtiBootstrapApplicationGenerator for CountingGenerator {
    fn generate(&self, anonymous_identifier_required: bool) -> CanvasLtiBootstrapApplicationSeed {
        assert!(!anonymous_identifier_required);
        self.0.fetch_add(1, Ordering::SeqCst);
        seed("application-1")(false)
    }
}

struct FixedClock;

impl CanvasLtiClock for FixedClock {
    fn now(&self) -> chrono::DateTime<Utc> {
        now()
    }
}

#[test]
fn bootstrap_create_replays_identity_context_attachment_and_public_response() {
    let policy = &contract()["experience"]["bootstrap"];
    let vector = &policy["vector"];
    let plan = plan_canvas_lti_experience_bootstrap(
        &bootstrap_context(),
        &request(),
        true,
        Some(true),
        Some(&template()),
        &[],
        seed("application-1"),
        now(),
    )
    .unwrap();

    assert!(plan.created);
    assert_eq!(
        plan.application_action,
        CanvasLtiBootstrapApplicationAction::Create
    );
    assert_eq!(
        plan.application.applicant_identifier,
        vector["expected_applicant_identifier"]
    );
    assert_eq!(plan.application.form_data, vector["expected_form_data"]);
    assert_eq!(
        plan.application.integration_context["canvas"],
        vector["expected_canvas_context"]
    );
    assert_eq!(
        plan.application.integration_context["delivery_mode"],
        vector["session_values"]["delivery_mode"]
    );
    assert_eq!(
        plan.response.canvas_context,
        vector["expected_public_canvas_context"]
    );
    assert_eq!(plan.response.application_id, "application-1");
    assert_eq!(plan.response.application_status, "pending");
    assert!(plan.response.created);
    assert!(plan.materialize_award_candidate);
    assert!(plan.enqueue_canvas_sync);
    assert!(plan.bootstrap_event_metadata.is_some());
    assert_eq!(
        plan.session_metadata["verified_launch"]["application_id"],
        "application-1"
    );
    assert_eq!(
        plan.session_metadata["mip_primitives"]["context"]["application_id"],
        "application-1"
    );
    assert_eq!(
        plan.session_metadata["application_bootstrap"]["created"],
        true
    );
    let response = serde_json::to_value(plan.response).unwrap();
    for field in policy["response"]["private_fields_forbidden"]
        .as_array()
        .unwrap()
    {
        assert!(response.get(field.as_str().unwrap()).is_none());
    }
}

#[test]
fn bootstrap_resume_preserves_original_join_and_bounds_launch_history() {
    let first = plan_canvas_lti_experience_bootstrap(
        &bootstrap_context(),
        &request(),
        true,
        Some(true),
        Some(&template()),
        &[],
        seed("application-1"),
        now(),
    )
    .unwrap();
    let mut application = first.application;
    application.integration_context["canvas"]["lti_states"] = Value::Array(
        (0..10)
            .map(|index| Value::String(format!("prior-state-{index}")))
            .collect(),
    );
    let mut context = bootstrap_context();
    context.state = "launch-state-2".to_owned();
    let resumed = plan_canvas_lti_experience_bootstrap(
        &context,
        &request(),
        true,
        Some(true),
        Some(&template()),
        &[application],
        seed("must-not-be-used"),
        now() + chrono::Duration::minutes(1),
    )
    .unwrap();

    assert!(!resumed.created);
    assert_eq!(
        resumed.application_action,
        CanvasLtiBootstrapApplicationAction::Resume
    );
    assert_eq!(resumed.application.id, "application-1");
    assert_eq!(
        resumed.application.integration_context["canvas"]["lti_state"],
        "launch-state-1"
    );
    assert_eq!(
        resumed.application.integration_context["canvas"]["last_lti_state"],
        "launch-state-2"
    );
    let states = resumed.application.integration_context["canvas"]["lti_states"]
        .as_array()
        .unwrap();
    assert_eq!(states.len(), 10);
    assert_eq!(states.last().unwrap(), "launch-state-2");
    assert!(resumed.bootstrap_event_metadata.is_none());

    let mut terminal = resumed.application;
    terminal.status = "rejected".to_owned();
    let mut exact_context = bootstrap_context();
    exact_context.state = "launch-state-1".to_owned();
    let exact = plan_canvas_lti_experience_bootstrap(
        &exact_context,
        &request(),
        true,
        Some(true),
        Some(&template()),
        &[terminal],
        seed("must-not-be-used"),
        now(),
    )
    .unwrap();
    assert!(!exact.created);
    assert_eq!(
        exact.application_action,
        CanvasLtiBootstrapApplicationAction::Replay
    );
    assert_eq!(exact.application.status, "rejected");
}

#[test]
fn bootstrap_terminal_applications_on_other_launches_are_not_resumed() {
    let original = plan_canvas_lti_experience_bootstrap(
        &bootstrap_context(),
        &request(),
        true,
        Some(true),
        Some(&template()),
        &[],
        "application-1",
        "deadbeef",
        now(),
    )
    .unwrap()
    .application;
    let mut next_context = bootstrap_context();
    next_context.state = "different-launch-state".to_owned();

    for terminal_status in ["rejected", "withdrawn"] {
        let mut terminal = original.clone();
        terminal.status = terminal_status.to_owned();
        let plan = plan_canvas_lti_experience_bootstrap(
            &next_context,
            &request(),
            true,
            Some(true),
            Some(&template()),
            &[terminal],
            "application-2",
            "feedface",
            now() + chrono::Duration::minutes(1),
        )
        .unwrap();

        assert!(plan.created, "{terminal_status} application was resumed");
        assert_eq!(
            plan.application_action,
            CanvasLtiBootstrapApplicationAction::Create
        );
        assert_eq!(plan.application.id, "application-2");
        assert!(plan.bootstrap_event_metadata.is_some());
    }
}

#[test]
fn bootstrap_subject_resume_requires_the_same_program_binding() {
    let original = plan_canvas_lti_experience_bootstrap(
        &bootstrap_context(),
        &request(),
        true,
        Some(true),
        Some(&template()),
        &[],
        "application-1",
        "deadbeef",
        now(),
    )
    .unwrap()
    .application;
    let mut different_binding = bootstrap_context();
    different_binding.state = "different-launch-state".to_owned();
    different_binding.canvas_program_binding_id = Some("different-binding".to_owned());

    let plan = plan_canvas_lti_experience_bootstrap(
        &different_binding,
        &request(),
        true,
        Some(true),
        Some(&template()),
        &[original],
        "application-2",
        "feedface",
        now() + chrono::Duration::minutes(1),
    )
    .unwrap();

    assert!(plan.created);
    assert_eq!(
        plan.application_action,
        CanvasLtiBootstrapApplicationAction::Create
    );
    assert_eq!(plan.application.id, "application-2");
}

#[test]
fn bootstrap_debug_output_redacts_private_applicant_and_session_data() {
    let request_secret = "request-secret@example.test";
    let identifier_secret = "private-applicant-identifier";
    let session_secret = "private-session-secret";
    let mut private_request = request();
    private_request.applicant_identifier = Some(identifier_secret.to_owned());
    private_request
        .applicant_data
        .insert("email".to_owned(), json!(request_secret));
    let request_debug = format!("{private_request:?}");
    assert!(request_debug.contains("[REDACTED]"));
    assert!(!request_debug.contains(request_secret));
    assert!(!request_debug.contains(identifier_secret));

    let mut context = bootstrap_context();
    context.launch_state.metadata["private_debug_sentinel"] = json!(session_secret);
    let plan = plan_canvas_lti_experience_bootstrap(
        &context,
        &private_request,
        true,
        Some(true),
        Some(&template()),
        &[],
        "application-safe-id",
        "deadbeef",
        now(),
    )
    .unwrap();
    let application_debug = format!("{:?}", plan.application);
    assert!(application_debug.contains("application-safe-id"));
    assert!(application_debug.contains("[REDACTED]"));
    assert!(!application_debug.contains(request_secret));
    assert!(!application_debug.contains(identifier_secret));

    let plan_debug = format!("{plan:?}");
    assert!(plan_debug.contains("application-safe-id"));
    assert!(plan_debug.contains("[REDACTED]"));
    assert!(!plan_debug.contains(request_secret));
    assert!(!plan_debug.contains(identifier_secret));
    assert!(!plan_debug.contains(session_secret));
}

#[test]
fn bootstrap_gates_and_template_failures_preserve_order_and_exact_errors() {
    let context = bootstrap_context();
    let cases = [
        (
            false,
            Some(false),
            Some(template()),
            CanvasLtiBootstrapPlanError::FeatureDisabled,
        ),
        (
            false,
            Some(true),
            Some(template()),
            CanvasLtiBootstrapPlanError::PilotDisabled,
        ),
        (
            true,
            Some(true),
            None,
            CanvasLtiBootstrapPlanError::ApplicationTemplateNotFound,
        ),
        (
            true,
            Some(true),
            Some(CanvasLtiBootstrapTemplate {
                id: "different-application-template".to_owned(),
                organization_id: "org-1".to_owned(),
            }),
            CanvasLtiBootstrapPlanError::ApplicationTemplateNotFound,
        ),
        (
            true,
            Some(true),
            Some(CanvasLtiBootstrapTemplate {
                id: "application-template-1".to_owned(),
                organization_id: "org-2".to_owned(),
            }),
            CanvasLtiBootstrapPlanError::CrossOrganizationTemplate,
        ),
    ];
    for (pilot, feature, template, expected) in cases {
        assert_eq!(
            plan_canvas_lti_experience_bootstrap(
                &context,
                &request(),
                pilot,
                feature,
                template.as_ref(),
                &[],
                seed("application-1"),
                now(),
            )
            .unwrap_err(),
            expected
        );
    }

    let mut missing = bootstrap_context();
    missing.application_template_id = None;
    assert_eq!(
        plan_canvas_lti_experience_bootstrap(
            &missing,
            &request(),
            true,
            Some(true),
            None,
            &[],
            seed("application-1"),
            now(),
        )
        .unwrap_err(),
        CanvasLtiBootstrapPlanError::MissingApplicationTemplate
    );

    let mut unbound = context;
    unbound.canvas_program_binding_id = None;
    let plan = plan_canvas_lti_experience_bootstrap(
        &unbound,
        &request(),
        true,
        Some(false),
        Some(&template()),
        &[],
        "application-1",
        "deadbeef",
        now(),
    )
    .unwrap();
    assert!(plan.created);
}

#[tokio::test]
async fn bootstrap_service_reloads_materialized_status_and_ignores_sync_outage() {
    let session_repository = Arc::new(SessionRepository {
        record: Mutex::new(Some(bootstrap_context().launch_state)),
    });
    let repository = Arc::new(BootstrapRepository {
        feature_enabled: Mutex::new(Some(true)),
        ..BootstrapRepository::default()
    });
    let materializer = Arc::new(Materializer {
        repository: repository.clone(),
        calls: AtomicUsize::new(0),
    });
    let sync = Arc::new(FailingSync(AtomicUsize::new(0)));
    let generator = Arc::new(CountingGenerator(AtomicUsize::new(0)));
    let service = CanvasLtiBootstrapService::new(
        CanvasLtiExperienceSessionService::new(session_repository),
        repository.clone(),
        materializer.clone(),
        sync.clone(),
        generator.clone(),
        Arc::new(FixedClock),
        true,
        BTreeSet::from(["org-1".to_owned()]),
    );

    let first = service
        .bootstrap("bootstrap-session-token", &request())
        .await
        .unwrap();
    let second = service
        .bootstrap("bootstrap-session-token", &request())
        .await
        .unwrap();

    assert!(first.created);
    assert!(!second.created);
    assert_eq!(first.application_id, second.application_id);
    assert_eq!(first.application_status, "approved");
    assert_eq!(second.application_status, "approved");
    assert_eq!(generator.0.load(Ordering::SeqCst), 1);
    assert_eq!(materializer.calls.load(Ordering::SeqCst), 2);
    assert_eq!(sync.0.load(Ordering::SeqCst), 2);
    assert_eq!(
        repository.persisted_created.lock().unwrap().as_slice(),
        [true, false]
    );
}
