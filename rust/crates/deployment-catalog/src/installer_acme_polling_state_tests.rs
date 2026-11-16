//! Recovery of timing is deliberately separate from phase authority.
use super::*;

fn path(fixture: &Fixture) -> std::path::PathBuf {
    fixture
        .installation
        .join("evidence/acme-poll-staging-00000000000000000000.json")
}
fn read(fixture: &Fixture) -> Value {
    serde_json::from_slice(&std::fs::read(path(fixture)).unwrap()).unwrap()
}
fn write(path: &Path, value: &Value) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
fn saved(fixture: &Fixture) -> Ledger {
    let view = LockedInspection::open(&fixture.installation).unwrap();
    Ledger::load(&view, AcmeEnvironment::Staging)
        .unwrap()
        .unwrap()
}

#[test]
fn prepared_and_displaced_checkpoints_keep_the_later_deadline_before_another_request() {
    for after_exchange in [false, true] {
        let fixture = Fixture::new();
        fixture.run().unwrap();
        let original = read(&fixture);
        let mut later = original.clone();
        let deadline = now().unwrap() + 900;
        later["timing"]["next_poll_at"] = json!(deadline);
        let pending =
            path(&fixture).with_file_name("acme-poll-staging-00000000000000000000.json.next");
        if after_exchange {
            write(&path(&fixture), &later);
            write(&pending, &original);
        } else {
            write(&pending, &later);
        }
        assert_eq!(saved(&fixture).next_poll_at(), Some(deadline));
        let requests = fixture.ca.state.lock().unwrap().requests.len();
        assert_eq!(fixture.run().unwrap().report["next_poll_at"], deadline);
        assert_eq!(fixture.ca.state.lock().unwrap().requests.len(), requests);
        // Reconciliation may remove the fixed staging file only after its
        // applicable longer timing has reached the next complete checkpoint.
        {
            let mut state = LockedMaintenance::open(&fixture.installation).unwrap();
            let mut ledger = Ledger::load(state.inspection(), AcmeEnvironment::Staging)
                .unwrap()
                .unwrap();
            polling::record(
                &mut state,
                &mut ledger,
                None,
                Some(now().unwrap() + 5),
                now().unwrap(),
            )
            .unwrap();
        }
        assert!(!pending.exists());
        assert_eq!(saved(&fixture).next_poll_at(), Some(deadline));
        fixture.advance(899);
        fixture.run().unwrap();
        assert_eq!(fixture.ca.state.lock().unwrap().requests.len(), requests);
    }
}

#[test]
fn invented_checkpoint_anchors_fail_before_network_and_unknown_order_remains_held() {
    for change in ["sequence", "digest", "binding", "clock", "authority"] {
        let fixture = Fixture::new();
        fixture.run().unwrap();
        let mut value = read(&fixture);
        match change {
            "sequence" => {
                value["anchor_sequence"] = json!(value["anchor_sequence"].as_u64().unwrap() + 1)
            }
            "digest" => value["anchor_sha256"] = json!("a".repeat(64)),
            "binding" => value["binding_sha256"] = json!("b".repeat(64)),
            "clock" => value["timing"]["observed_at"] = json!(1),
            "authority" => value["order_url"] = json!(format!("{CA}/order/invented")),
            _ => unreachable!(),
        }
        write(&path(&fixture), &value);
        let requests = fixture.ca.state.lock().unwrap().requests.len();
        assert!(fixture.run().is_err(), "{change}");
        assert_eq!(fixture.ca.state.lock().unwrap().requests.len(), requests);
    }
    let fixture = Fixture::new();
    fixture.ca.state.lock().unwrap().lose_order = true;
    assert_eq!(fixture.run().unwrap().report["stage"], "order_pending");
    let requests = fixture.ca.state.lock().unwrap().requests.len();
    {
        let mut state = LockedMaintenance::open(&fixture.installation).unwrap();
        let mut ledger = Ledger::load(state.inspection(), AcmeEnvironment::Staging)
            .unwrap()
            .unwrap();
        assert!(polling::record(
            &mut state,
            &mut ledger,
            None,
            Some(now().unwrap() + 5),
            now().unwrap()
        )
        .is_err());
    }
    fixture.advance(100_000);
    assert_eq!(fixture.run().unwrap().report["stage"], "order_pending");
    assert_eq!(fixture.ca.state.lock().unwrap().requests.len(), requests);
}

#[test]
fn same_phase_duplicates_keep_checkpoint_timing_and_only_real_transition_obsoletes_it() {
    let fixture = Fixture::new();
    fixture.run().unwrap();
    let deadline = now().unwrap() + 900;
    {
        let mut state = LockedMaintenance::open(&fixture.installation).unwrap();
        let mut ledger = Ledger::load(state.inspection(), AcmeEnvironment::Staging)
            .unwrap()
            .unwrap();
        polling::record(
            &mut state,
            &mut ledger,
            None,
            Some(deadline),
            now().unwrap(),
        )
        .unwrap();
        let duplicate = ledger.state.clone();
        ledger
            .append(&mut state, duplicate, now().unwrap())
            .unwrap();
    }
    assert_eq!(saved(&fixture).next_poll_at(), Some(deadline));
    let mut old = read(&fixture);
    {
        let mut state = LockedMaintenance::open(&fixture.installation).unwrap();
        let mut ledger = Ledger::load(state.inspection(), AcmeEnvironment::Staging)
            .unwrap()
            .unwrap();
        let mut next = ledger.state.clone();
        next.stage = Stage::ChallengeReadyPending;
        next.pending_challenge = Some(next.authorizations[1].url.clone());
        ledger.append(&mut state, next, now().unwrap()).unwrap();
    }
    assert!(saved(&fixture).next_poll_at().is_none());
    // Old authority with a newly claimed observation is corruption, not a
    // stale predecessor which the reader may quietly ignore.
    old["timing"]["observed_at"] = json!(now().unwrap() + 500);
    old["timing"]["next_poll_at"] = json!(now().unwrap() + 1000);
    write(&path(&fixture), &old);
    assert!(fixture.run().is_err());
}

#[test]
fn legacy_same_phase_lower_bound_survives_without_an_applicable_checkpoint() {
    let fixture = Fixture::new();
    fixture.run().unwrap();
    std::fs::remove_file(path(&fixture)).unwrap();
    // Model an actual legacy stream, predating the checkpoint-required marker.
    std::fs::remove_file(
        fixture
            .installation
            .join("evidence/acme-poll-required-staging-00000000000000000000.json"),
    )
    .unwrap();
    let deadline = now().unwrap() + 900;
    {
        let mut state = LockedMaintenance::open(&fixture.installation).unwrap();
        let mut ledger = Ledger::load(state.inspection(), AcmeEnvironment::Staging)
            .unwrap()
            .unwrap();
        let mut earlier = ledger.state.clone();
        earlier.next_poll_at = Some(deadline);
        ledger.append(&mut state, earlier, now().unwrap()).unwrap();
        let mut later = ledger.state.clone();
        later.next_poll_at = Some(now().unwrap() + 5);
        ledger.append(&mut state, later, now().unwrap()).unwrap();
    }
    assert_eq!(saved(&fixture).next_poll_at(), Some(deadline));
    let requests = fixture.ca.state.lock().unwrap().requests.len();
    fixture.run().unwrap();
    assert_eq!(fixture.ca.state.lock().unwrap().requests.len(), requests);
}

#[test]
fn checkpoint_publication_refuses_a_same_phase_clock_regression() {
    let fixture = Fixture::new();
    fixture.run().unwrap();
    let original = std::fs::read(path(&fixture)).unwrap();
    let mut state = LockedMaintenance::open(&fixture.installation).unwrap();
    let mut ledger = Ledger::load(state.inspection(), AcmeEnvironment::Staging)
        .unwrap()
        .unwrap();
    let at = ledger.timing_observed_at();
    assert!(polling::record(&mut state, &mut ledger, None, Some(at + 5), at - 1).is_err());
    assert_eq!(std::fs::read(path(&fixture)).unwrap(), original);
}

#[test]
fn terminal_status_cannot_change_the_identifier_of_a_retained_authorization_url() {
    let fixture = Fixture::new();
    fixture.run().unwrap();
    let original = saved(&fixture);
    fixture.ca.state.lock().unwrap().target_change = Some(TargetChange::TerminalOtherIdentifier);
    fixture.advance(5);
    assert!(fixture.run().is_err());
    let after = saved(&fixture);
    assert_eq!(after.state.stage, original.state.stage);
    assert_eq!(after.state.authorizations, original.state.authorizations);
    assert!(after.state.terminal_retry.is_none());
    assert_eq!(fixture.ca.state.lock().unwrap().new_orders, 1);
}

#[test]
fn required_checkpoint_disappearance_holds_and_interrupted_marker_completion_recovers() {
    let fixture = Fixture::new();
    fixture.run().unwrap();
    let marker = fixture
        .installation
        .join("evidence/acme-poll-required-staging-00000000000000000000.json");
    std::fs::remove_file(&marker).unwrap();
    fixture.advance(5);
    fixture.run().unwrap();
    assert!(marker.is_file());
    write(
        &path(&fixture).with_file_name("acme-poll-staging-00000000000000000000.json.next"),
        &read(&fixture),
    );
    std::fs::remove_file(path(&fixture)).unwrap();
    let requests = fixture.ca.state.lock().unwrap().requests.len();
    assert!(fixture.run().is_err());
    assert_eq!(fixture.ca.state.lock().unwrap().requests.len(), requests);
}

fn reserve(fixture: &Fixture) -> Ledger {
    let mut state = LockedMaintenance::open(&fixture.installation).unwrap();
    let mut ledger = Ledger::load(state.inspection(), AcmeEnvironment::Staging)
        .unwrap()
        .unwrap();
    while ledger.ordinary_phase_available() {
        let duplicate = ledger.state.clone();
        ledger
            .append(&mut state, duplicate, now().unwrap())
            .unwrap();
    }
    assert!(ledger.sequence < 448);
    ledger
}

#[test]
fn reserved_capacity_still_observes_terminal_order_and_withdraws() {
    let fixture = Fixture::with_certificate_lifetime(72);
    fixture.ca.state.lock().unwrap().hold_pending = true;
    fixture.run().unwrap();
    fixture.advance(5);
    let baseline = reserve(&fixture);
    let result = fixture.run().unwrap();
    assert_eq!(
        result.report["blocking_dependency"],
        "acme_phase_budget_waiting_for_order_expiry"
    );
    assert_eq!(saved(&fixture).sequence, baseline.sequence);
    let expiry = baseline.state.order.as_ref().unwrap().expires_at;
    assert!(saved(&fixture).next_poll_at().unwrap() >= expiry);
    fixture.ca.state.lock().unwrap().order_invalid = true;
    fixture.advance(expiry - now().unwrap());
    let result = fixture.run().unwrap();
    assert_eq!(result.report["stage"], "terminal");
    assert_eq!(result.report["failure"], "order_invalid");
    let completed = saved(&fixture);
    assert!(completed.sequence <= baseline.sequence + 3);
    let snapshot: Snapshot =
        serde_json::from_slice(&std::fs::read(&fixture.ca.projection).unwrap()).unwrap();
    assert!(snapshot.challenges.is_empty());
    assert_eq!(fixture.ca.state.lock().unwrap().new_orders, 1);
}

#[test]
fn reserved_capacity_keeps_known_processing_order_resumable_until_completion() {
    let fixture = Fixture::new();
    fixture.ca.state.lock().unwrap().hold_processing = true;
    for _ in 0..3 {
        fixture.run().unwrap();
        fixture.advance(5);
    }
    assert_eq!(saved(&fixture).state.stage, Stage::CertificatePending);
    let baseline = reserve(&fixture);
    for _ in 0..3 {
        assert_eq!(
            fixture.run().unwrap().report["stage"],
            "certificate_pending"
        );
        assert_eq!(saved(&fixture).sequence, baseline.sequence);
        fixture.advance(5);
    }
    fixture.ca.state.lock().unwrap().hold_processing = false;
    assert!(fixture.run().unwrap().candidate.is_some());
    assert!(saved(&fixture).sequence <= baseline.sequence + 3);
    assert_eq!(fixture.ca.state.lock().unwrap().new_orders, 1);
    assert_eq!(fixture.ca.state.lock().unwrap().finalizations, 1);
}
