//! Additional interruption invariants over the same immutable fixture.
use super::*;

#[test]
fn retained_baseline_allows_infrastructure_reboot_without_restarting_consumers() {
    let fixture = Fixture::new(true);
    fixture.require().unwrap();
    let observed = native(fixture.root.path(), &fixture.baseline.observation).unwrap();
    let resources = observed.resources.as_ref().unwrap();
    let mut rows = observed.status;
    for role in ["openbao", "openbao-unseal", "installer-acme-http01"] {
        rows.iter_mut().find(|row| row["Service"] == role).unwrap()["State"] = json!("exited");
    }
    require_baseline_status(resources, &rows, &fixture.baseline.stopped_services).unwrap();
    for role in ["openbao", "openbao-unseal", "installer-acme-http01"] {
        rows.iter_mut().find(|row| row["Service"] == role).unwrap()["State"] = json!("running");
    }
    require_baseline_status(resources, &rows, &fixture.baseline.stopped_services).unwrap();
    let original = rows.clone();
    rows.iter_mut().find(|row| row["Service"] == "api").unwrap()["State"] = json!("running");
    assert!(require_baseline_status(resources, &rows, &fixture.baseline.stopped_services).is_err());
    let mut rows = original;
    rows.iter_mut()
        .find(|row| row["Service"] == "openbao")
        .unwrap()["ID"] = json!("e".repeat(64));
    assert!(require_baseline_status(resources, &rows, &fixture.baseline.stopped_services).is_err());
}

#[test]
fn a_second_no_start_create_intent_is_bound_to_the_same_completed_attempt_and_native_model() {
    let mut fixture = Fixture::new(true);
    fixture.require().unwrap();
    let activation =
        load_activation_intent(fixture.root.path(), &fixture.old, &fixture.previous).unwrap();
    let helper = completed_helper(fixture.root.path(), &fixture.old).unwrap();
    let operation = fixture
        .supersession
        .scope()
        .operation("supersede-create", 0);
    let dummy = receipt(
        &operation,
        &activation.configuration_sha256,
        &activation.inputs,
        helper.resources.as_ref().unwrap().clone(),
        false,
    );
    let mut intent = command(
        &dummy,
        &fixture.supersession.before_resources,
        &["api"],
        true,
    );
    let digest = write(
        fixture.root.path(),
        &format!("generation-compose-{operation}-intent.json"),
        &intent,
    );
    fixture
        .baseline
        .create_intents
        .insert(operation.clone(), digest);
    fixture.require().unwrap();
    for field in [
        "configuration_sha256",
        "input_files",
        "selected_services",
        "command",
        "engine_id",
    ] {
        let saved = intent.clone();
        intent[field] = match field {
            "input_files" => json!({}),
            "selected_services" => json!(["openbao"]),
            "command" => json!(["up", "--force-recreate"]),
            _ => json!("changed"),
        };
        write(
            fixture.root.path(),
            &format!("generation-compose-{operation}-intent.json"),
            &intent,
        );
        assert!(fixture.require().is_err(), "{field}");
        intent = saved;
        write(
            fixture.root.path(),
            &format!("generation-compose-{operation}-intent.json"),
            &intent,
        );
    }
    fixture.require().unwrap();
}

#[test]
fn stale_activation_cannot_be_relabelled_as_successful_selection_or_a_different_baseline() {
    let fixture = Fixture::new(true);
    fixture.require().unwrap();
    for field in [
        "activation_performed",
        "installation_ready",
        "attempt",
        "supersession_sha256",
        "configuration_sha256",
    ] {
        let mut value = serde_json::to_value(&fixture.baseline).unwrap();
        value[field] = match field {
            "activation_performed" | "installation_ready" => json!(true),
            "attempt" => json!(2),
            _ => json!("a".repeat(64)),
        };
        let changed: Baseline = serde_json::from_value(value).unwrap();
        assert!(
            require_baseline(
                fixture.root.path(),
                &fixture.supersession,
                &fixture.old,
                &fixture.previous,
                &fixture.parent,
                &changed
            )
            .is_err(),
            "{field}"
        );
    }
    assert!(!fixture.root.path().join("evidence").join(SELECTOR).exists());
    assert!(!fixture
        .root
        .path()
        .join("evidence")
        .join(fixture.supersession.scope().record("intent"))
        .exists());
}

#[test]
fn exact_attempt_producer_journal_cannot_borrow_another_attempts_success() {
    let fixture = Fixture::new(false);
    completed_helper(fixture.root.path(), &fixture.old).unwrap();
    let mut changed = fixture.old.clone();
    changed.attempt = 1;
    let scope = changed.scope();
    for kind in ["helper", "producer"] {
        let original: Value =
            decode(&read(fixture.root.path(), &fixture.old.scope().record(kind)).unwrap()).unwrap();
        write(fixture.root.path(), &scope.record(kind), &original);
    }
    assert!(completed_helper(fixture.root.path(), &changed).is_err());
    assert!(require_producer_journal_at(
        fixture.root.path(),
        scope,
        &"7".repeat(64),
        &fixture.old.scope().operation("wait", 0)
    )
    .is_err());
}
