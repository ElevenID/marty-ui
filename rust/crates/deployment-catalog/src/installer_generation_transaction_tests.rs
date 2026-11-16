//! Crash-boundary tests use the production native observer with a synthetic
//! Docker CLI. They neither execute Docker nor qualify an installed deployment.
use super::*;
use std::os::unix::fs::PermissionsExt;

fn evidence(root: &Path) {
    std::fs::create_dir(root.join("evidence")).unwrap();
    std::fs::set_permissions(
        root.join("evidence"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
}
fn write_intent(root: &Path, phase: &str, ordinal: u64, value: &Value) -> (String, String) {
    let operation = format!("g{:020}-{phase}-{ordinal:06}", 1);
    let bytes = serde_json::to_vec(value).unwrap();
    let path = root
        .join("evidence")
        .join(format!("generation-compose-{operation}-intent.json"));
    std::fs::write(&path, &bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    (operation, hash(&bytes))
}
fn create(session: &ComposeSession, prior: &ProjectResources, selected: &[&str]) -> Value {
    json!({"schema":"elevenid.installer-compose-intent/v1","project":session.model()["name"],
        "engine_id":session.runtime_binding().engine_id,"configuration_sha256":session.configuration_sha256(),
        "input_files":session.input_files(),"command":["up","--no-build","--pull","never","--no-deps","--no-start","--force-recreate","--timeout","60"],
        "prior_resources":prior,"selected_services":selected,"automatic_retry":false,"installation_ready":false})
}

#[test]
fn a_same_model_new_helper_without_a_bound_create_intent_is_not_adopted() {
    let mut fixture = ComposeSession::generation_test_fixture(GenerationOperation::Candidate);
    evidence(fixture.root());
    let prior = fixture.session().observe_resources().unwrap();
    fixture.replacement("installer-generation", 'a', "created");
    fixture.flush();
    let observed = fixture
        .session()
        .observe_generation_transition(GenerationOperation::Candidate)
        .unwrap();
    let roles = BTreeSet::from(["installer-generation".into()]);
    let creates = authorized_creates(
        fixture.root(),
        Attempt::new(1, 0),
        "create",
        fixture.session(),
        &prior,
        &roles,
    )
    .unwrap();
    assert!(creates.is_empty());
    assert!(
        require_replacements_authorized(fixture.root(), &creates, &prior, &observed, &roles)
            .is_err()
    );
}

#[test]
fn a_lost_create_response_reconciles_only_the_exact_prior_config_inputs_and_selected_role() {
    let mut fixture = ComposeSession::generation_test_fixture(GenerationOperation::Candidate);
    evidence(fixture.root());
    let prior = fixture.session().observe_resources().unwrap();
    let intent = create(fixture.session(), &prior, &["installer-generation"]);
    let (op, digest) = write_intent(fixture.root(), "create", 0, &intent);
    fixture.replacement("installer-generation", 'a', "created");
    fixture.flush();
    let observed = fixture
        .session()
        .observe_generation_transition(GenerationOperation::Candidate)
        .unwrap();
    let roles = BTreeSet::from(["installer-generation".into()]);
    let creates = authorized_creates(
        fixture.root(),
        Attempt::new(1, 0),
        "create",
        fixture.session(),
        &prior,
        &roles,
    )
    .unwrap();
    assert_eq!(creates, BTreeMap::from([(op, digest)]));
    require_replacements_authorized(fixture.root(), &creates, &prior, &observed, &roles).unwrap();
    for field in [
        "configuration_sha256",
        "input_files",
        "command",
        "selected_services",
        "engine_id",
        "project",
        "automatic_retry",
    ] {
        let mut changed = intent.clone();
        changed[field] = match field {
            "input_files" => json!({"/foreign":"a".repeat(64)}),
            "command" => json!(["up", "--force-recreate"]),
            "selected_services" => json!(["bootstrap"]),
            "automatic_retry" => json!(true),
            _ => json!("changed"),
        };
        write_intent(fixture.root(), "create", 0, &changed);
        assert!(
            authorized_creates(
                fixture.root(),
                Attempt::new(1, 0),
                "create",
                fixture.session(),
                &prior,
                &roles
            )
            .is_err(),
            "{field}"
        );
    }
}

#[test]
fn partial_activation_requires_each_changed_or_missing_role_to_have_a_prior_create_intent() {
    let mut fixture = ComposeSession::generation_test_fixture(GenerationOperation::Activate);
    evidence(fixture.root());
    let prior = fixture.session().observe_resources().unwrap();
    write_intent(
        fixture.root(),
        "activate-create",
        0,
        &create(fixture.session(), &prior, &["api"]),
    );
    fixture.replacement("api", 'a', "created");
    fixture.replacement("edge", 'b', "created");
    fixture.flush();
    let observed = fixture
        .session()
        .observe_generation_transition(GenerationOperation::Activate)
        .unwrap();
    let roles = BTreeSet::from(["api".into(), "edge".into()]);
    let creates = authorized_creates(
        fixture.root(),
        Attempt::new(1, 0),
        "activate-create",
        fixture.session(),
        &prior,
        &roles,
    )
    .unwrap();
    assert!(
        require_replacements_authorized(fixture.root(), &creates, &prior, &observed, &roles)
            .is_err()
    );
    write_intent(
        fixture.root(),
        "activate-create",
        1,
        &create(fixture.session(), &prior, &["edge"]),
    );
    let creates = authorized_creates(
        fixture.root(),
        Attempt::new(1, 0),
        "activate-create",
        fixture.session(),
        &prior,
        &roles,
    )
    .unwrap();
    require_replacements_authorized(fixture.root(), &creates, &prior, &observed, &roles).unwrap();
    fixture.remove_role("edge");
    fixture.flush();
    let missing = fixture
        .session()
        .observe_generation_transition(GenerationOperation::Activate)
        .unwrap();
    require_replacements_authorized(fixture.root(), &creates, &prior, &missing, &roles).unwrap();
    let only_api = creates
        .into_iter()
        .filter(|(operation, _)| operation.ends_with("000000"))
        .collect();
    assert!(
        require_replacements_authorized(fixture.root(), &only_api, &prior, &missing, &roles)
            .is_err()
    );
}

#[test]
fn lost_start_response_with_created_state_holds_and_running_or_exited_only_wait() {
    assert_eq!(
        candidate_execution("created", false).unwrap(),
        CandidateExecution::StartOnce
    );
    assert!(candidate_execution("created", true).is_err());
    for state in ["running", "exited"] {
        assert_eq!(
            candidate_execution(state, true).unwrap(),
            CandidateExecution::Wait
        );
        assert!(candidate_execution(state, false).is_err());
    }
    for state in ["dead", "removing", "restarting", "paused", ""] {
        assert!(candidate_execution(state, true).is_err());
        assert!(candidate_execution(state, false).is_err());
    }
}
