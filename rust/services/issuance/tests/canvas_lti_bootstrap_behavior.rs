use chrono::{TimeZone, Utc};
use marty_issuance_service::{
    canvas_lti_bootstrap::{
        plan_canvas_lti_experience_bootstrap, CanvasLtiBootstrapPlanError,
        CanvasLtiBootstrapRequest, CanvasLtiBootstrapTemplate,
    },
    canvas_lti_experience::canvas_lti_experience_session_context,
    canvas_lti_launch::CanvasLtiStoredLaunchState,
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
        "application-1",
        "deadbeef",
        now(),
    )
    .unwrap();

    assert!(plan.created);
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
        "application-1",
        "deadbeef",
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
        "must-not-be-used",
        "must-not-be-used",
        now() + chrono::Duration::minutes(1),
    )
    .unwrap();

    assert!(!resumed.created);
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
        "must-not-be-used",
        "must-not-be-used",
        now(),
    )
    .unwrap();
    assert!(!exact.created);
    assert_eq!(exact.application.status, "rejected");
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
                "application-1",
                "deadbeef",
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
            "application-1",
            "deadbeef",
            now(),
        )
        .unwrap_err(),
        CanvasLtiBootstrapPlanError::MissingApplicationTemplate
    );
}
