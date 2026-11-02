use super::*;
use crate::installer_state::{Identity, InstallerState, RuntimeBinding, RuntimeProfile};
use std::{os::unix::fs::symlink, path::PathBuf};

fn fixture() -> (tempfile::TempDir, PathBuf, LockedMaintenance, Checkpoint) {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("installation");
    let mut original = InstallerState::create_with_runtime(
        &path,
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        },
        RuntimeBinding {
            docker_host: "unix:///var/run/docker.sock".into(),
            engine_id: "fixture-engine".into(),
            openbao_port: 18443,
            profile: RuntimeProfile::Rootful,
        },
    )
    .unwrap();
    original.create_private_directory("evidence").unwrap();
    drop(original);
    let mut state = LockedMaintenance::open(&path).unwrap();
    let (mut checkpoint, bytes) = load(&mut state).unwrap();
    assert!(bytes.is_none());
    checkpoint.observed_at = 10000;
    checkpoint.roles.insert(
        "gateway".into(),
        Role {
            container_id: "c".repeat(64),
            unhealthy_since: Some(10000),
            attempts: vec![],
        },
    );
    (parent, path, state, checkpoint)
}

#[test]
fn sustained_unhealthy_policy_backs_off_and_respects_upstream_outage() {
    let mut role = Role {
        container_id: "a".repeat(64),
        unhealthy_since: Some(1000),
        attempts: vec![],
    };
    assert_eq!(
        eligibility(&role, 1599, &[]),
        "unhealthy_observation_window"
    );
    assert_eq!(
        eligibility(&role, 1600, &["postgres".into()]),
        "dependency_unavailable"
    );
    assert_eq!(eligibility(&role, 1600, &[]), "eligible");
    role.attempts.push(Attempt {
        operation: format!("repair-{}", uuid::Uuid::new_v4()),
        started_at: 1600,
        outcome: Outcome::IntentRecorded,
    });
    assert_eq!(eligibility(&role, 3399, &[]), "repair_cooldown");
    assert_eq!(eligibility(&role, 3400, &[]), "eligible");
    role.attempts.push(Attempt {
        operation: format!("repair-{}", uuid::Uuid::new_v4()),
        started_at: 3400,
        outcome: Outcome::FailedOrUnconfirmed,
    });
    assert_eq!(eligibility(&role, 9000, &[]), "daily_repair_limit");
    // A lost client response consumes the same limit as an observed restart.
    role.attempts[0].outcome = Outcome::HealthyObserved;
    assert_eq!(eligibility(&role, 9000, &[]), "daily_repair_limit");
}

#[test]
fn native_dependency_conditions_do_not_restart_downstream_services() {
    let model = json!({"services":{"gateway":{"depends_on":{
        "postgres":{"condition":"service_healthy"},"migration":{"condition":"service_completed_successfully"},
        "proxy":{"condition":"service_started"}}}}});
    let postgres = json!({"State":"running","Health":"unhealthy"});
    let migration = json!({"State":"exited","ExitCode":0});
    let proxy = json!({"State":"running"});
    let rows = BTreeMap::from([
        ("postgres".into(), &postgres),
        ("migration".into(), &migration),
        ("proxy".into(), &proxy),
    ]);
    assert_eq!(
        blocked_dependencies(&model, "gateway", &rows).unwrap(),
        vec!["postgres"]
    );
    assert!(blocked_dependencies(&model, "unknown", &rows)
        .unwrap()
        .is_empty());
    let unknown =
        json!({"services":{"gateway":{"depends_on":{"postgres":{"condition":"future_policy"}}}}});
    assert_eq!(
        blocked_dependencies(&unknown, "gateway", &rows).unwrap(),
        vec!["postgres"]
    );
}

#[test]
fn native_state_comparison_ignores_elapsed_text_but_detects_runtime_changes() {
    let original = json!({"ID":"a".repeat(64),"State":"running","Health":"unhealthy",
        "ExitCode":0,"RunningFor":"59 seconds ago","Status":"Up 59 seconds (unhealthy)"});
    let mut current = original.clone();
    current["RunningFor"] = json!("About a minute ago");
    current["Status"] = json!("Up About a minute (unhealthy)");
    let before = BTreeMap::from([("gateway".into(), &original)]);
    assert!(same_runtime_states(
        &before,
        &BTreeMap::from([("gateway".into(), &current)])
    ));
    for (field, value) in [
        ("ID", json!("b".repeat(64))),
        ("State", json!("restarting")),
        ("Health", json!("healthy")),
        ("ExitCode", json!(1)),
    ] {
        let mut changed = current.clone();
        changed[field] = value;
        assert!(!same_runtime_states(
            &before,
            &BTreeMap::from([("gateway".into(), &changed)])
        ));
    }
    assert!(!same_runtime_states(&before, &BTreeMap::new()));
}

#[test]
fn thousands_of_observations_use_a_bounded_durable_checkpoint() {
    let (_parent, path, mut state, mut checkpoint) = fixture();
    let mut prior = None;
    for offset in 0..2100 {
        checkpoint.observed_at = 10000 + offset;
        save(&mut state, &mut checkpoint, &mut prior).unwrap();
    }
    let retained = std::fs::read_dir(path.join("evidence"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(retained.len(), 2);
    assert!(
        std::fs::metadata(path.join("evidence").join(CHECKPOINT))
            .unwrap()
            .len()
            < 4096
    );
    drop(state);
    let mut state = LockedMaintenance::open(&path).unwrap();
    let (loaded, bytes) = load(&mut state).unwrap();
    assert_eq!(loaded, checkpoint);
    assert_eq!(bytes, prior);
    // Removing the selected checkpoint cannot silently reset repair limits.
    std::fs::remove_file(path.join("evidence").join(CHECKPOINT)).unwrap();
    assert!(load(&mut state).is_err());
}

#[test]
fn pending_checkpoint_reconciles_exact_predecessor_after_process_loss() {
    let (_parent, path, mut state, mut checkpoint) = fixture();
    checkpoint.sequence = 1;
    let first = encode(&checkpoint).unwrap();
    state.write_evidence_exclusive(PENDING, &first).unwrap();
    // Crash before the initialization marker and rename is recoverable.
    drop(state);
    let mut state = LockedMaintenance::open(&path).unwrap();
    let (loaded, bytes) = load(&mut state).unwrap();
    assert_eq!(loaded, checkpoint);
    assert_eq!(bytes.as_deref(), Some(first.as_slice()));
    assert!(state.read_evidence(PENDING).unwrap().is_none());
    checkpoint.sequence = 2;
    checkpoint.previous_sha256 = Some(installer_release::sha256(&first));
    checkpoint.observed_at += 1;
    let next = encode(&checkpoint).unwrap();
    state.write_evidence_exclusive(PENDING, &next).unwrap();
    drop(state);
    let mut state = LockedMaintenance::open(&path).unwrap();
    assert_eq!(load(&mut state).unwrap().0, checkpoint);
}

#[test]
fn changed_pending_checkpoint_or_symlink_never_replaces_current() {
    for corruption in [
        "predecessor",
        "sequence",
        "clock",
        "foreign",
        "unknown",
        "symlink",
    ] {
        let (_parent, path, mut state, mut checkpoint) = fixture();
        let mut prior = None;
        save(&mut state, &mut checkpoint, &mut prior).unwrap();
        let before = prior.unwrap();
        checkpoint.sequence += 1;
        checkpoint.previous_sha256 = Some(installer_release::sha256(&before));
        let mut next = serde_json::to_value(&checkpoint).unwrap();
        match corruption {
            "predecessor" => next["previous_sha256"] = json!("f".repeat(64)),
            "sequence" => next["sequence"] = json!(99),
            "clock" => next["observed_at"] = json!(0),
            "foreign" => next["installation_id"] = json!(uuid::Uuid::new_v4()),
            "unknown" => next["unreviewed"] = json!(true),
            "symlink" => {}
            _ => unreachable!(),
        }
        if corruption == "symlink" {
            symlink(CHECKPOINT, path.join("evidence").join(PENDING)).unwrap();
        } else {
            state
                .write_evidence_exclusive(PENDING, &encode(&next).unwrap())
                .unwrap();
        }
        assert!(load(&mut state).is_err(), "{corruption}");
        assert_eq!(
            std::fs::read(path.join("evidence").join(CHECKPOINT)).unwrap(),
            before
        );
    }
}
