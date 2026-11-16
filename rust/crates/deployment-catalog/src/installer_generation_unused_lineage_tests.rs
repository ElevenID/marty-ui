//! A completed producer followed by unused preparations remains one forward
//! attempt lineage. Native execution is represented by synthetic receipts.
use super::*;

fn completed_then_unused() -> (Fixture, GenerationRecoveryBaseline) {
    let (root, previous, abandoned) = super::super::super::completed_test_fixture();
    let scope = abandoned.attempt_id();
    let parent = generation::load_attempt(root.path(), 0, 0).unwrap();
    let old: Intent = decode(&read(root.path(), &previous.record_name("intent")).unwrap()).unwrap();
    put(
        root.path(),
        installer_doctor::SESSION_RECORD,
        &old.parent_session,
    );
    // Reuse the real complete predecessor proof, but model the later attempt
    // as a crash after plan storage and before any helper authorization.
    for name in fs::file_names(&directory(&root.path().join("evidence")).unwrap(), REFUSED).unwrap()
    {
        let keep = [
            scope.record("supersession-intent"),
            scope.record("supersession-baseline"),
            scope.record("public-ingress-plan"),
        ];
        if own_evidence(&name, scope) && !keep.contains(&name)
            || native_suffix(&name, scope).is_some_and(|v| !v.starts_with("supersede-baseline-"))
        {
            std::fs::remove_file(root.path().join("evidence").join(name)).unwrap();
        }
    }
    std::fs::remove_dir_all(scope.work(root.path())).unwrap();
    private(&scope.work(root.path()));
    private(&scope.work(root.path()).join("transfer"));
    let baseline = generation::load_preparation_baseline(root.path(), scope, 0).unwrap();
    let native = baseline.receipt().unwrap();
    put(
        root.path(),
        &format!("generation-compose-{}-intent.json", native.operation),
        &json!({
        "schema":"elevenid.installer-compose-intent/v1","project":native.project,"engine_id":native.engine_id,
        "configuration_sha256":native.configuration_sha256,"input_files":native.input_files,
        "command":["ps","--all","--no-trunc","--format","json"],"prior_resources":native.resources,
        "selected_services":[],"automatic_retry":false,"installation_ready":false}),
    );
    let fixture = Fixture {
        root,
        parent,
        saved: old.parent_session,
    };
    (fixture, baseline)
}

#[test]
fn completed_and_unused_attempts_share_one_linear_walk_and_the_actual_last_helper() {
    let (fixture, first) = completed_then_unused();
    let second = fixture.record(Attempt::new(1, 1), Some(&first));
    fixture.plan(Attempt::new(1, 2));
    let third = fixture.record(Attempt::new(1, 2), Some(&second));
    let (result, visits) = generation::test_lineage_visits(|| {
        generation::load_preparation_baseline(fixture.root.path(), Attempt::new(1, 3), 0)
    });
    let result = result.unwrap();
    assert_eq!(result.sha256(), third.sha256());
    assert_eq!(
        visits,
        [0, 1],
        "only the selected parent and real completed producer are admitted"
    );
    assert_eq!(result.last_helper().unwrap(), Some(Attempt::new(1, 0)));
    assert_eq!(
        result.previous_work(fixture.root.path()).unwrap(),
        Some(Attempt::new(1, 0).work(fixture.root.path()))
    );
    assert_ne!(
        result.previous_work(fixture.root.path()).unwrap(),
        Some(Attempt::new(1, 2).work(fixture.root.path()))
    );
    let original = generation::load_attempt(fixture.root.path(), 1, 0).unwrap();
    assert_eq!(original.attempt(), 0);
    assert!(generation::load_attempt(fixture.root.path(), 1, 1).is_err());
    assert!(generation::load_attempt(fixture.root.path(), 1, 2).is_err());
}

#[test]
fn unused_descendant_cannot_rebind_or_skip_a_completed_recovery_source() {
    let (fixture, first) = completed_then_unused();
    let second = fixture.record(Attempt::new(1, 1), Some(&first));
    let name = second.scope().record("unused-preparation");
    let original = read(fixture.root.path(), &name).unwrap();
    for field in ["source", "previous_attempt", "last_helper"] {
        let mut value: Value = decode(&original).unwrap();
        value[field] = match field {
            "source" => json!({"kind":"recovery","attempt":1,"baseline_sha256":"f".repeat(64)}),
            "previous_attempt" => json!(0),
            "last_helper" => json!({"sequence":1,"number":1}),
            _ => unreachable!(),
        };
        put(fixture.root.path(), &name, &value);
        assert!(
            generation::load_preparation_baseline(fixture.root.path(), second.scope(), 0).is_err(),
            "{field}"
        );
        bytes(
            &fixture.root.path().join("evidence").join(&name),
            &original,
            0o600,
        );
    }
    let earlier = first.scope().record("supersession-baseline");
    std::fs::remove_file(fixture.root.path().join("evidence").join(earlier)).unwrap();
    assert!(generation::load_preparation_baseline(fixture.root.path(), second.scope(), 0).is_err());
}
