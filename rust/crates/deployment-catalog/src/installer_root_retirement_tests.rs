use super::*;
use crate::installer_state::{InstallerState, RuntimeBinding, RuntimeProfile};
use std::{os::unix::fs::PermissionsExt, path::PathBuf};

const CLUSTER: &str = "33333333-3333-4333-8333-333333333333";
const ISSUER: &str = "44444444-4444-4444-8444-444444444444";
const AT: u64 = 10_000;

fn fixture() -> (
    tempfile::TempDir,
    PathBuf,
    LockedMaintenance,
    QualificationContext,
) {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let installation = directory.path().join("installation");
    let release = Identity {
        source_sha: "a".repeat(40),
        release_tag: "v1.2.3".into(),
        inventory_sha256: format!("sha256:{}", "b".repeat(64)),
    };
    let mut writer = InstallerState::create_with_runtime(
        &installation,
        release.clone(),
        RuntimeBinding {
            docker_host: "unix:///var/run/docker.sock".into(),
            engine_id: "test-engine".into(),
            openbao_port: 18200,
            profile: RuntimeProfile::Rootful,
        },
    )
    .unwrap();
    writer.create_private_directory("evidence").unwrap();
    let id = writer.journal().installation_id().to_string();
    let selection = RetirementSelection {
        installation_id: id.clone(),
        engine_id: "test-engine".into(),
        current_generation_sha256: "1".repeat(64),
        rollback_generation_sha256: "2".repeat(64),
        current_helper_receipt_sha256: "3".repeat(64),
        rollback_helper_receipt_sha256: "4".repeat(64),
        selected_session_sha256: "5".repeat(64),
        configuration_sha256: "6".repeat(64),
        activation_receipt_sha256: "7".repeat(64),
        selection_receipt_sha256: "8".repeat(64),
        public_renewal_enrollment_sha256: "9".repeat(64),
        public_identity_sha256: BTreeMap::from([("renewal-role-id".into(), "a".repeat(64))]),
    };
    let control = LocalControlBinding {
        installation_id: id,
        engine_id: "test-engine".into(),
        project: writer.journal().compose_project(),
        container_id: "a".repeat(64),
        image: format!("sha256:{}", "b".repeat(64)),
        config_hash: "c".repeat(64),
        resources_sha256: "d".repeat(64),
        control_observation_sha256: "e".repeat(64),
        cluster_id: CLUSTER.into(),
        issuer_id: ISSUER.into(),
        ca_sha256: "f".repeat(64),
        spki_sha256: "0".repeat(64),
    };
    drop(writer);
    let state = LockedMaintenance::open(&installation).unwrap();
    (
        directory,
        installation,
        state,
        QualificationContext {
            release,
            selection,
            local_control: control,
        },
    )
}

fn proof(context: &QualificationContext, kind: ProofKind) -> InstalledProof {
    InstalledProof {
        schema: "elevenid.installed-root-retirement-proof/v1".into(),
        proof_id: uuid::Uuid::new_v4().to_string(),
        kind,
        subject: "installed_deployment".into(),
        context: context.clone(),
        started_at: AT - 60,
        completed_at: AT - 10,
        checks: kind
            .checks()
            .iter()
            .map(|key| ((*key).into(), true))
            .collect(),
        initial_root_used: false,
        initialization_replayed: false,
        installation_ready: false,
    }
}
fn reference(proof: &InstalledProof, bytes: &[u8]) -> ArtifactRef {
    ArtifactRef {
        name: format!(
            "openbao-root-retirement-{}-{}.json",
            proof.kind.label(),
            proof.proof_id
        ),
        sha256: sha256(bytes),
    }
}
fn persist_proofs(
    state: &mut LockedMaintenance,
    context: &QualificationContext,
) -> RetirementEvidence {
    let mut values = Vec::new();
    for kind in [
        ProofKind::Application,
        ProofKind::ScopedAuthorities,
        ProofKind::Restart,
        ProofKind::Restore,
    ] {
        let value = proof(context, kind);
        let bytes = encode(&value).unwrap();
        let reference = reference(&value, &bytes);
        state
            .write_evidence_exclusive(&reference.name, &bytes)
            .unwrap();
        values.push(reference);
    }
    RetirementEvidence {
        application: Some(values[0].clone()),
        scoped_authorities: Some(values[1].clone()),
        restart: Some(values[2].clone()),
        restore: Some(values[3].clone()),
    }
}
fn receipt(intent: &Intent, digest: &str) -> HelperReceipt {
    HelperReceipt {
        schema: "elevenid.openbao-initial-root-retirement-result/v1".into(),
        installation_id: intent.installation_id.clone(),
        attempt_id: intent.attempt_id.clone(),
        intent_sha256: digest.into(),
        cluster_id: CLUSTER.into(),
        root_rejection_observed: true,
        root_token_removed: true,
        recovery_key_preserved: true,
        original_authority_verified: true,
        authority_record_preserved: true,
        initialization_replayed: false,
        installation_ready: false,
    }
}

#[test]
fn missing_or_component_only_evidence_never_persists_retirement_intent() {
    let (_directory, installation, mut state, context) = fixture();
    context.selection.validate(state.inspection()).unwrap();
    let empty = RetirementEvidence::default();
    let assessment = assess(state.inspection(), &context, &empty, AT).unwrap();
    assert_eq!(assessment.len(), 4);
    assert!(assessment
        .iter()
        .all(|v| !v.satisfied && v.reason == "installed_evidence_missing"));
    assert!(authorize(&mut state, &context, &empty, AT).is_err());
    assert!(state.read_evidence(INTENT).unwrap().is_none());

    let id = uuid::Uuid::new_v4().to_string();
    let name = format!("openbao-root-retirement-restore-{id}.json");
    let component = encode(&serde_json::json!({"schema":"elevenid.openbao-static-restore-proof/v1",
        "source_cluster_restored":true,"actual_root_retirement_core":true,"customer_restore_qualified":false})).unwrap();
    state.write_evidence_exclusive(&name, &component).unwrap();
    let evidence = RetirementEvidence {
        restore: Some(ArtifactRef {
            name,
            sha256: sha256(&component),
        }),
        ..Default::default()
    };
    let assessment = assess(state.inspection(), &context, &evidence, AT).unwrap();
    assert_eq!(assessment[3].reason, "installed_proof_schema_required");
    assert!(authorize(&mut state, &context, &evidence, AT).is_err());
    assert!(!installation.join("evidence").join(INTENT).exists());
    assert!(!installation.join("evidence").join(COMPLETION).exists());
}

#[test]
fn installed_proof_requires_fresh_exact_selection_and_each_scoped_check() {
    let (_directory, _, _state, context) = fixture();
    for kind in [
        ProofKind::Application,
        ProofKind::ScopedAuthorities,
        ProofKind::Restart,
        ProofKind::Restore,
    ] {
        let original = proof(&context, kind);
        let bytes = encode(&original).unwrap();
        assert_eq!(
            proof_reason(&bytes, &reference(&original, &bytes), kind, &context, AT),
            None
        );
        for failure in [
            "current",
            "rollback",
            "session",
            "native-helper",
            "renewal",
            "cluster",
            "container",
            "release",
            "stale",
            "future",
            "check",
            "missing-check",
            "extra-check",
            "root-used",
            "init-replayed",
            "ready",
            "detached",
            "scope",
        ] {
            let mut changed = original.clone();
            match failure {
                "current" => changed.context.selection.current_generation_sha256 = "a".repeat(64),
                "rollback" => changed.context.selection.rollback_generation_sha256 = "a".repeat(64),
                "session" => changed.context.selection.selected_session_sha256 = "a".repeat(64),
                "native-helper" => {
                    changed.context.selection.rollback_helper_receipt_sha256 = "a".repeat(64)
                }
                "renewal" => changed.context.selection.public_identity_sha256.clear(),
                "cluster" => changed.context.local_control.cluster_id = ISSUER.into(),
                "container" => changed.context.local_control.container_id = "c".repeat(64),
                "release" => changed.context.release.source_sha = "c".repeat(40),
                "stale" => {
                    changed.completed_at = AT - FRESHNESS - 1;
                    changed.started_at = changed.completed_at - 1;
                }
                "future" => changed.completed_at = AT + 1,
                "check" => *changed.checks.values_mut().next().unwrap() = false,
                "missing-check" => {
                    changed.checks.pop_first();
                }
                "extra-check" => {
                    changed.checks.insert("component_test_passed".into(), true);
                }
                "root-used" => changed.initial_root_used = true,
                "init-replayed" => changed.initialization_replayed = true,
                "ready" => changed.installation_ready = true,
                "detached" => changed.subject = "official_binary_fixture".into(),
                "scope" => {
                    changed.kind = if kind == ProofKind::Application {
                        ProofKind::Restart
                    } else {
                        ProofKind::Application
                    }
                }
                _ => unreachable!(),
            }
            let changed_bytes = encode(&changed).unwrap();
            assert!(
                proof_reason(
                    &changed_bytes,
                    &reference(&changed, &changed_bytes),
                    kind,
                    &context,
                    AT
                )
                .is_some(),
                "accepted {failure} for {kind:?}"
            );
        }
        for field in [
            "initial_root_used",
            "initialization_replayed",
            "installation_ready",
            "context",
        ] {
            let mut omitted = serde_json::to_value(&original).unwrap();
            omitted.as_object_mut().unwrap().remove(field);
            assert!(decode::<InstalledProof>(&encode(&omitted).unwrap()).is_err());
        }
        let text = String::from_utf8(bytes.clone()).unwrap();
        for invalid in [
            text.replacen('{', "{\"schema\":\"duplicate\",", 1),
            text.replacen('{', "{\"token\":\"forbidden\",", 1),
            format!("{text} {{}}"),
        ] {
            assert!(decode::<InstalledProof>(invalid.as_bytes()).is_err());
        }
        let mut wrong_hash = reference(&original, &bytes);
        wrong_hash.sha256 = "0".repeat(64);
        assert_eq!(
            proof_reason(&bytes, &wrong_hash, kind, &context, AT),
            Some("artifact_digest_differs")
        );
    }
}

#[test]
fn authorized_attempt_survives_reopen_and_aged_proof_without_creating_a_second_attempt() {
    let (_directory, installation, mut state, context) = fixture();
    let evidence = persist_proofs(&mut state, &context);
    let (first, first_bytes, complete) = authorize(&mut state, &context, &evidence, AT).unwrap();
    assert!(!complete);
    drop(state);
    let mut state = LockedMaintenance::open(&installation).unwrap();
    // Fresh authorization would fail at this time, but the original authorized
    // operation is resumable even when the Docker client result was lost.
    let later = AT + 2 * 24 * 60 * 60;
    assert!(assess(state.inspection(), &context, &evidence, later)
        .unwrap()
        .iter()
        .all(|v| !v.satisfied));
    let (resumed, resumed_bytes, complete) =
        authorize(&mut state, &context, &RetirementEvidence::default(), later).unwrap();
    assert_eq!(resumed.attempt_id, first.attempt_id);
    assert_eq!(resumed_bytes, first_bytes);
    assert!(!complete);
    let names: BTreeSet<_> = std::fs::read_dir(installation.join("evidence"))
        .unwrap()
        .map(|v| v.unwrap().file_name())
        .collect();
    assert_eq!(names.len(), 5);
    let mut other_selection = context.clone();
    other_selection.selection.current_generation_sha256 = "a".repeat(64);
    assert!(authorize(&mut state, &other_selection, &evidence, later).is_err());
    assert_eq!(state.read_evidence(INTENT).unwrap().unwrap(), first_bytes);
}

#[test]
fn completion_binds_exact_helper_proof_and_survives_later_validated_generations() {
    let (_directory, installation, mut state, context) = fixture();
    let evidence = persist_proofs(&mut state, &context);
    let (intent, bytes, _) = authorize(&mut state, &context, &evidence, AT).unwrap();
    let digest = sha256(&bytes);
    let valid = receipt(&intent, &digest);
    valid.validate(&intent, &digest).unwrap();
    for field in [
        "schema",
        "installation_id",
        "attempt_id",
        "intent_sha256",
        "cluster_id",
        "root_rejection_observed",
        "root_token_removed",
        "recovery_key_preserved",
        "original_authority_verified",
        "authority_record_preserved",
        "initialization_replayed",
        "installation_ready",
    ] {
        let mut changed = serde_json::to_value(&valid).unwrap();
        if changed[field].is_boolean() {
            changed[field] = serde_json::json!(!changed[field].as_bool().unwrap());
        } else {
            changed[field] = serde_json::json!("different");
        }
        assert!(
            decode::<HelperReceipt>(&encode(&changed).unwrap())
                .unwrap()
                .validate(&intent, &digest)
                .is_err(),
            "accepted {field}"
        );
        let mut omitted = serde_json::to_value(&valid).unwrap();
        omitted.as_object_mut().unwrap().remove(field);
        assert!(decode::<HelperReceipt>(&encode(&omitted).unwrap()).is_err());
    }
    let completed = Completion {
        schema: "elevenid.installer-openbao-root-retirement-complete/v1".into(),
        installation_id: intent.installation_id.clone(),
        attempt_id: intent.attempt_id.clone(),
        intent_sha256: digest,
        completed_at: AT + 1,
        helper_receipt: valid,
        root_retired: true,
        installation_ready: false,
    };
    state
        .write_evidence_exclusive(COMPLETION, &encode(&completed).unwrap())
        .unwrap();
    require_no_pending_for_generation(state.inspection()).unwrap();
    drop(state);
    let mut state = LockedMaintenance::open(&installation).unwrap();
    let mut successor = context.clone();
    successor.selection.current_generation_sha256 = "b".repeat(64);
    successor.selection.rollback_generation_sha256 =
        context.selection.current_generation_sha256.clone();
    successor.selection.selected_session_sha256 = "c".repeat(64);
    successor.local_control.resources_sha256 = "a".repeat(64);
    let (retained, _, completed) = authorize(
        &mut state,
        &successor,
        &RetirementEvidence::default(),
        AT + 100_000,
    )
    .unwrap();
    assert!(completed);
    assert_eq!(retained.attempt_id, intent.attempt_id);
    let mut wrong_cluster = successor;
    wrong_cluster.local_control.cluster_id = ISSUER.into();
    assert!(history(&state, &wrong_cluster, AT + 100_000).is_err());
}

#[test]
fn changed_installed_proof_cannot_resume_a_previously_authorized_root_operation() {
    let (_directory, installation, mut state, context) = fixture();
    let evidence = persist_proofs(&mut state, &context);
    let (_, bytes, _) = authorize(&mut state, &context, &evidence, AT).unwrap();
    let original = evidence.restart.as_ref().unwrap();
    let path = installation.join("evidence").join(&original.name);
    let mut changed: InstalledProof = decode(&std::fs::read(&path).unwrap()).unwrap();
    changed
        .checks
        .insert("initial_root_unavailable_during_restart".into(), false);
    std::fs::write(&path, encode(&changed).unwrap()).unwrap();
    assert!(authorize(&mut state, &context, &evidence, AT + 1).is_err());
    assert_eq!(state.read_evidence(INTENT).unwrap().unwrap(), bytes);
    assert!(state.read_evidence(COMPLETION).unwrap().is_none());
}

#[test]
fn generation_exclusion_and_resume_never_authorize_a_replacement_retirement() {
    let (_directory, installation, mut state, context) = fixture();
    require_no_pending_for_generation(state.inspection()).unwrap();
    assert!(existing_authorization(&state, &context, b"missing", AT).is_err());
    assert!(state.read_evidence(INTENT).unwrap().is_none());
    let evidence = persist_proofs(&mut state, &context);
    let (intent, bytes, _) = authorize(&mut state, &context, &evidence, AT).unwrap();
    assert!(require_no_pending_for_generation(state.inspection()).is_err());
    let (resumed, _, complete) =
        existing_authorization(&state, &context, &bytes, AT + 100_000).unwrap();
    assert_eq!(resumed.attempt_id, intent.attempt_id);
    assert!(!complete);
    let mut different = intent.clone();
    different.attempt_id = uuid::Uuid::new_v4().to_string();
    assert!(
        existing_authorization(&state, &context, &encode(&different).unwrap(), AT + 1).is_err()
    );
    std::fs::remove_file(installation.join("evidence").join(INTENT)).unwrap();
    assert!(existing_authorization(&state, &context, &bytes, AT + 1).is_err());
    assert!(state.read_evidence(INTENT).unwrap().is_none());
}

#[test]
fn cli_accepts_only_two_fixed_actions_and_protected_evidence_references() {
    let args = |values: &[&str]| values.iter().map(|v| (*v).to_owned()).collect::<Vec<_>>();
    let parsed = arguments(&args(&["status", "--install-dir", "/opt/marty"])).unwrap();
    assert_eq!(parsed.action, Action::Status);
    assert_eq!(parsed.docker, Path::new("/usr/bin/docker"));
    assert!(parsed.evidence.is_none());
    let parsed = arguments(&args(&[
        "retire",
        "--install-dir",
        "/opt/marty",
        "--docker-bin",
        "/usr/local/bin/docker",
        "--evidence",
        "/opt/private/refs.json",
    ]))
    .unwrap();
    assert_eq!(parsed.action, Action::Retire);
    for invalid in [
        vec![],
        vec!["force"],
        vec!["retire"],
        vec!["retire", "--install-dir", "/opt/marty", "--force", "true"],
        vec![
            "status",
            "--install-dir",
            "/opt/marty",
            "--install-dir",
            "/opt/other",
        ],
        vec!["status", "--install-dir", "relative"],
        vec!["status", "--install-dir", "/opt/../marty"],
        vec!["status", "--install-dir", "/opt//marty"],
        vec![
            "status",
            "--install-dir",
            "/opt/marty",
            "--evidence",
            "/opt/private/refs.json\n",
        ],
        vec![
            "retire",
            "--install-dir",
            "/opt/marty",
            "--intent-sha256",
            "arbitrary",
        ],
    ] {
        assert!(arguments(&args(&invalid)).is_err(), "accepted {invalid:?}");
    }
    assert_eq!(
        read_evidence_input(None).unwrap(),
        RetirementEvidence::default()
    );
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let input = directory.path().join("refs.json");
    std::fs::write(&input, b"{}").unwrap();
    std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        read_evidence_input(Some(&input)).unwrap(),
        RetirementEvidence::default()
    );
    std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o400)).unwrap();
    assert_eq!(
        read_evidence_input(Some(&input)).unwrap(),
        RetirementEvidence::default()
    );
    std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o600)).unwrap();
    for forbidden in [
        b"{\"root_retired\":true}".as_slice(),
        b"{\"application\":null,\"application\":null}".as_slice(),
        b"{\"application\":{\"name\":\"a\",\"sha256\":\"b\",\"passed\":true}}".as_slice(),
    ] {
        std::fs::write(&input, forbidden).unwrap();
        assert!(read_evidence_input(Some(&input)).is_err());
    }
    std::fs::write(&input, b"{}").unwrap();
    std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_evidence_input(Some(&input)).is_err());
    std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o600)).unwrap();
    let linked = directory.path().join("hardlink.json");
    std::fs::hard_link(&input, &linked).unwrap();
    assert!(read_evidence_input(Some(&input)).is_err());
    std::fs::remove_file(&linked).unwrap();
    std::os::unix::fs::symlink(&input, &linked).unwrap();
    assert!(read_evidence_input(Some(&linked)).is_err());
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(read_evidence_input(Some(&input)).is_err());
}
