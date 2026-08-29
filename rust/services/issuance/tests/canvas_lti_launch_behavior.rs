use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use marty_issuance_service::{
    canvas_lti_launch::{
        feature_enabled, launch_scope, private_launch_response, public_launch_response,
        scope_matches, select_binding, CanvasLtiLaunchPlanError, CanvasLtiLaunchStateRepository,
        CanvasLtiLaunchStateService, CanvasLtiLaunchSubmission, CanvasLtiProgramBinding,
        CanvasLtiStoredLaunchState,
    },
    canvas_lti_login::CanvasLtiPlatform,
};
use marty_oid4vci::lti::VerifiedLtiLaunch;
use serde_json::{json, Value};

#[derive(Default)]
struct StateRepository {
    states: Mutex<HashMap<String, CanvasLtiStoredLaunchState>>,
}

impl StateRepository {
    fn insert(&self, state: CanvasLtiStoredLaunchState) {
        self.states
            .lock()
            .unwrap()
            .insert(state.state.clone(), state);
    }
}

#[async_trait]
impl CanvasLtiLaunchStateRepository for StateRepository {
    async fn get_launch_state(
        &self,
        state: &str,
    ) -> Result<Option<CanvasLtiStoredLaunchState>, CanvasLtiLaunchPlanError> {
        Ok(self.states.lock().unwrap().get(state).cloned())
    }

    async fn consume_launch_state(
        &self,
        state: &str,
    ) -> Result<Option<CanvasLtiStoredLaunchState>, CanvasLtiLaunchPlanError> {
        let mut states = self.states.lock().unwrap();
        let Some(stored) = states.get_mut(state) else {
            return Ok(None);
        };
        if stored.status != "pending" || stored.expired {
            return Ok(None);
        }
        stored.status = "consumed".to_owned();
        Ok(Some(stored.clone()))
    }
}

fn pending_state(platform_id: &str, state: &str) -> CanvasLtiStoredLaunchState {
    CanvasLtiStoredLaunchState {
        platform_id: platform_id.to_owned(),
        state: state.to_owned(),
        nonce: "nonce-1".to_owned(),
        status: "pending".to_owned(),
        expired: false,
    }
}

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/issuance-canvas-lti-foundation.json"
    ))
    .expect("valid Canvas LTI contract")
}

fn platform_from(value: &Value) -> CanvasLtiPlatform {
    CanvasLtiPlatform {
        id: value["id"].as_str().unwrap().to_owned(),
        organization_id: value["organization_id"].as_str().unwrap().to_owned(),
        canvas_account_id: value["canvas_account_id"].as_str().unwrap().to_owned(),
        canvas_base_url: Some("https://school.canvas.example".to_owned()),
        lti_client_id: Some("client-1".to_owned()),
        lti_deployment_id: Some("deployment-1".to_owned()),
        lti_trust_profile: "hosted_global".to_owned(),
        lti_issuer: Some("https://canvas.instructure.com".to_owned()),
        lti_jwks_url: Some("https://sso.canvaslms.com/api/lti/security/jwks".to_owned()),
        lti_jwks_json: Some(json!({"keys": []})),
        lti_openid_configuration: None,
        enabled: true,
    }
}

fn binding_from(value: &Value, platform: &CanvasLtiPlatform) -> CanvasLtiProgramBinding {
    CanvasLtiProgramBinding {
        id: value["id"].as_str().unwrap().to_owned(),
        organization_id: platform.organization_id.clone(),
        platform_id: platform.id.clone(),
        application_template_id: value["application_template_id"]
            .as_str()
            .unwrap()
            .to_owned(),
        credential_template_id: value["credential_template_id"].as_str().unwrap().to_owned(),
        delivery_mode: "wallet_only".to_owned(),
        deployment_profile_id: None,
        feature_flags: json!({}),
        evidence_requirements: Vec::new(),
        canvas_scope: json!({}),
        enabled: true,
    }
}

#[test]
fn public_projection_replays_the_python_oracle_contract() {
    let contract = contract();
    let vector = &contract["launch"]["public_response_vector"];
    let platform = platform_from(&vector["platform"]);
    let binding = binding_from(&vector["binding"], &platform);
    let verified: VerifiedLtiLaunch =
        serde_json::from_value(vector["verified"].clone()).expect("valid verified launch vector");
    let identity_status = vector["verified"]["identity_mapping_status"]
        .as_str()
        .map(str::to_owned);
    let private = private_launch_response(
        &platform,
        &binding,
        "private-state",
        verified,
        identity_status,
    );
    assert_eq!(private.lti_capabilities["resource_link"], true);
    assert_eq!(
        private.lti_capabilities["binding_evidence_fact_types"],
        json!(["canvas.course_completion"])
    );
    let public = serde_json::to_value(public_launch_response(&private)).unwrap();

    assert_eq!(public, vector["expected"]);
    for private_field in contract["launch"]["private_response_fields"]
        .as_array()
        .unwrap()
    {
        assert!(public.get(private_field.as_str().unwrap()).is_none());
    }
}

#[test]
fn launch_submission_replays_required_and_non_string_json_semantics() {
    let contract = contract();
    let failures = contract["launch"]["submission"]["failures"]
        .as_array()
        .unwrap();
    let failure = |name: &str| {
        failures
            .iter()
            .find(|failure| failure["name"] == name)
            .unwrap()["detail"]
            .as_str()
            .unwrap()
    };
    let cases = [
        (json!({"state": "state-1"}), "id_token_missing"),
        (
            json!({"id_token": "header.payload.signature"}),
            "state_missing",
        ),
        (
            json!({"id_token": 7, "state": "state-1"}),
            "id_token_missing",
        ),
        (
            json!({"id_token": "header.payload.signature", "state": false}),
            "state_missing",
        ),
    ];
    for (value, expected_failure) in cases {
        let submission = CanvasLtiLaunchSubmission::from_json_object(value.as_object().unwrap());
        assert_eq!(
            submission.required().unwrap_err().to_string(),
            failure(expected_failure)
        );
    }
    assert_eq!(
        CanvasLtiLaunchSubmission {
            id_token: Some(" token ".to_owned()),
            state: Some(" state-1 ".to_owned()),
        }
        .required()
        .unwrap(),
        ("token".to_owned(), "state-1".to_owned())
    );
}

#[test]
fn scope_matching_preserves_canvas_identity_namespaces_and_aliases() {
    let verified = VerifiedLtiLaunch {
        issuer: "https://canvas.instructure.com".to_owned(),
        subject: "opaque-lti-subject".to_owned(),
        audience: vec!["client-1".to_owned()],
        deployment_id: "deployment-1".to_owned(),
        nonce: Some("nonce-1".to_owned()),
        issued_at: None,
        expires_at: None,
        message_type: Some("LtiResourceLinkRequest".to_owned()),
        lti_version: Some("1.3.0".to_owned()),
        target_link_uri: None,
        context: Some(json!({"id": "course-101"})),
        roles: vec!["Learner".to_owned()],
        learner_identity: json!({}),
        raw_claims: json!({
            "https://purl.imsglobal.org/spec/lti/claim/custom": {
                "canvas_user_id": "42"
            },
            "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
                "id": "resource-7"
            }
        }),
    };
    let actual = launch_scope(&verified, "account-1");

    assert!(scope_matches(
        &json!({"canvas_course_id": "course-101", "assignment_id": "resource-7"}),
        &actual
    ));
    assert!(scope_matches(
        &json!({"resource_link_id": "resource-7"}),
        &actual
    ));
    assert!(scope_matches(&json!({"canvas_user_id": 42}), &actual));
    assert!(scope_matches(
        &json!({"lti_subject": "opaque-lti-subject"}),
        &actual
    ));
    assert!(!scope_matches(
        &json!({"canvas_user_id": "opaque-lti-subject"}),
        &actual
    ));
    assert!(!scope_matches(&json!({"lti_subject": "42"}), &actual));
    assert!(!scope_matches(&json!(["course-101"]), &actual));
}

#[test]
fn binding_selection_is_tenant_bound_ordered_and_fail_closed_on_flags() {
    let platform = platform_from(&json!({
        "id": "platform-1",
        "organization_id": "org-1",
        "canvas_account_id": "account-1"
    }));
    let verified = VerifiedLtiLaunch {
        issuer: "https://canvas.instructure.com".to_owned(),
        subject: "student-1".to_owned(),
        audience: vec!["client-1".to_owned()],
        deployment_id: "deployment-1".to_owned(),
        nonce: Some("nonce-1".to_owned()),
        issued_at: None,
        expires_at: None,
        message_type: None,
        lti_version: None,
        target_link_uri: None,
        context: Some(json!({"id": "course-101"})),
        roles: vec![],
        learner_identity: json!({}),
        raw_claims: json!({}),
    };
    let base = binding_from(
        &json!({
            "id": "binding-1",
            "application_template_id": "app-1",
            "credential_template_id": "credential-1"
        }),
        &platform,
    );
    let mut wrong_tenant = base.clone();
    wrong_tenant.id = "wrong-tenant".to_owned();
    wrong_tenant.organization_id = "org-2".to_owned();
    let mut disabled = base.clone();
    disabled.id = "disabled".to_owned();
    disabled.enabled = false;
    let mut selected = base.clone();
    selected.canvas_scope = json!({"course_id": "course-101"});

    assert_eq!(
        select_binding(
            &platform,
            &verified,
            &[wrong_tenant, disabled, selected.clone()]
        )
        .unwrap()
        .id,
        selected.id
    );

    selected.feature_flags = json!({"enable_canvas_evidence": true});
    assert!(matches!(
        select_binding(&platform, &verified, &[selected]),
        Err(CanvasLtiLaunchPlanError::FeatureDisabled)
    ));
    assert!(feature_enabled(&json!({}), "enable_canvas_lti"));
    assert!(!feature_enabled(
        &json!({"enable_canvas_evidence": true}),
        "enable_canvas_lti"
    ));
}

#[tokio::test]
async fn launch_state_is_platform_bound_and_consumed_before_verification() {
    let repository = Arc::new(StateRepository::default());
    repository.insert(pending_state("platform-1", "state-1"));
    let service = CanvasLtiLaunchStateService::new(repository);

    assert!(matches!(
        service.claim("platform-2", "state-1").await,
        Err(CanvasLtiLaunchPlanError::StateUnknown)
    ));
    assert_eq!(
        service.claim("platform-1", "state-1").await.unwrap().status,
        "consumed"
    );
    assert!(matches!(
        service.claim("platform-1", "state-1").await,
        Err(CanvasLtiLaunchPlanError::StateExpired)
    ));
}

#[tokio::test]
async fn launch_state_claim_is_atomic_under_race() {
    let repository = Arc::new(StateRepository::default());
    repository.insert(pending_state("platform-1", "state-1"));
    let service = CanvasLtiLaunchStateService::new(repository);
    let first = service.clone();
    let second = service;
    let (first, second) = tokio::join!(
        first.claim("platform-1", "state-1"),
        second.claim("platform-1", "state-1")
    );

    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let loser = if first.is_err() { first } else { second };
    assert!(matches!(loser, Err(CanvasLtiLaunchPlanError::StateExpired)));
}

#[tokio::test]
async fn expired_state_never_reaches_atomic_consume() {
    let repository = Arc::new(StateRepository::default());
    let mut expired = pending_state("platform-1", "state-1");
    expired.expired = true;
    repository.insert(expired);
    let service = CanvasLtiLaunchStateService::new(repository);

    assert!(matches!(
        service.claim("platform-1", "state-1").await,
        Err(CanvasLtiLaunchPlanError::StateExpired)
    ));
}
