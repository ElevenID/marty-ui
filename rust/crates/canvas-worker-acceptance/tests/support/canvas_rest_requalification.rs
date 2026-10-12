//! Fresh native REST replay evidence, never provenance of the original capture.

use super::canvas_startup_attestation as attestation;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};

const ARTIFACT: &str = "canvas-rest-fresh-run.json";
const INPUTS: [&str; 10] = [
    "contracts/canvas-issued-review-scenarios.json",
    "contracts/canvas-worker-rest-oracle.json",
    "contracts/canvas-worker-rest-scenarios.json",
    "contracts/fixtures/canvas_worker_test_trust.py",
    "rust/services/issuance/tests/support/canvas_worker_rest_replay.rs",
    "rust/services/issuance/tests/support/remote_integration_secret.rs",
    "scripts/canvas_worker_https_fixture.py",
    "scripts/prepare_canvas_published_schema.py",
    "scripts/test_canvas_lti_https.py",
    "scripts/test_canvas_worker_rest_https.py",
];

fn source_inputs(root: &Path, sidecar: &Value) -> BTreeMap<String, String> {
    assert_eq!(
        sidecar["schema"],
        "marty.canvas-worker-rest-current-inputs/v2"
    );
    assert!(sidecar["purpose"]
        .as_str()
        .is_some_and(|purpose| purpose.contains("native REST replay")));
    assert_eq!(
        sidecar["normalization"],
        "UTF-8 text with CRLF and CR converted to LF before SHA-256"
    );
    let pins = sidecar["sha256"]
        .as_object()
        .expect("REST input pins missing");
    assert_eq!(pins.len(), INPUTS.len(), "Unreviewed REST input pin set");
    INPUTS
        .iter()
        .map(|name| {
            let pin = pins[*name].as_str().expect("REST input pin missing");
            assert!(
                attestation::valid_sha(pin, 64),
                "Invalid REST input pin: {name}"
            );
            let actual = attestation::normalized_sha(&root.join(name));
            assert_eq!(actual, pin, "REST capture input drift: {name}");
            ((*name).to_owned(), actual)
        })
        .collect()
}

fn rest_evidence(root: &Path, run: Value, executable: &Path, worker_binary_sha: &str) -> Value {
    let sidecar: Value = serde_json::from_slice(
        &fs::read(root.join("contracts/canvas-worker-rest-current-inputs.json"))
            .expect("REST current-input inventory missing"),
    )
    .expect("REST current-input inventory invalid");
    let inputs = source_inputs(root, &sidecar);
    let fixture: Value = serde_json::from_slice(
        &fs::read(root.join("contracts/canvas-worker-consumer-range-oracle.json"))
            .expect("Pinned Canvas image fixture missing"),
    )
    .expect("Pinned Canvas image fixture invalid");
    let issuance = attestation::image_digest(&fixture["observed_image"]);
    let postgres = attestation::image_digest(&fixture["observed_postgres_image"]);
    let revisions = &fixture["migration_revisions"];
    assert!(revisions
        .as_array()
        .is_some_and(|items| items.len() == 1 && items[0] == "merge_issuance_heads"));
    let corpus = fs::read(root.join("contracts/canvas-worker-rest-oracle.json"))
        .expect("Frozen REST corpus missing");
    let expected: Value = serde_json::from_slice(&corpus).expect("Frozen REST corpus invalid");
    assert_eq!(expected["schema"], "marty.canvas-worker-rest-oracle/v1");
    let observations = expected["observations"]
        .as_array()
        .expect("Frozen REST observations missing");
    assert_eq!(observations.len(), 4, "REST observation count changed");
    let scenarios: Value = serde_json::from_slice(
        &fs::read(root.join("contracts/canvas-worker-rest-scenarios.json"))
            .expect("REST scenarios missing"),
    )
    .expect("REST scenarios invalid");
    let stages = scenarios["stages"].as_array().expect("REST stages missing");
    assert_eq!(stages.len(), 4, "REST stage count changed");
    let stage_names: Vec<&str> = stages
        .iter()
        .map(|stage| stage["name"].as_str().expect("REST stage name missing"))
        .collect();
    assert_eq!(
        stage_names
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        stage_names.len(),
        "Duplicate REST stage name"
    );
    assert_eq!(
        stage_names,
        observations
            .iter()
            .map(|observation| observation["name"]
                .as_str()
                .expect("REST observation name missing"))
            .collect::<Vec<_>>(),
        "Frozen REST observations no longer cover all stages"
    );
    assert!(attestation::valid_sha(worker_binary_sha, 64));
    json!({
        "schema": "marty.canvas-worker-rest-fresh-run/v2",
        "scope": "fresh full-main native REST worker replay against four frozen observations on published-schema databases; no legacy Python worker oracle",
        "workflow_result_required": "success for this run and attempt before external use",
        "run": run,
        "test": "worker_rest_matches_frozen_published_process",
        "source_inputs_sha256": inputs,
        "input_inventory_sha256": attestation::normalized_sha(&root.join("contracts/canvas-worker-rest-current-inputs.json")),
        "image_fixture_sha256": attestation::normalized_sha(&root.join("contracts/canvas-worker-consumer-range-oracle.json")),
        "corpus_sha256": format!("{:x}", Sha256::digest(&corpus)),
        "stage_names": stage_names,
        "issuance_image": issuance,
        "postgres_image": postgres,
        "verified_migration_revisions": revisions,
        "test_executable_sha256": attestation::file_sha(executable),
        "worker_binary_sha256": worker_binary_sha,
        "native_replay": "passed",
        "owned_cleanup": "passed",
    })
}

pub(super) fn emit_after_rest_pass(root: &Path, worker_binary: &Path, worker_binary_before: &str) {
    let resolved = super::canvas_worker_process_signals::worker_executable();
    let worker_binary_after =
        attestation::verified_worker_binary_sha(worker_binary, worker_binary_before, &resolved);
    let Some(run) = attestation::main_run_from(|name| std::env::var(name).ok()) else {
        return;
    };
    let runner_temp = std::env::var("RUNNER_TEMP").expect("REST evidence output directory missing");
    let output = Path::new(&runner_temp).join(ARTIFACT);
    attestation::persist_verified_evidence(root, &output, &run, || {
        let executable = std::env::current_exe().expect("REST test executable path missing");
        rest_evidence(root, run.clone(), &executable, &worker_binary_after)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rest_input_mutation_fails_before_evidence() {
        let root = tempfile::tempdir().unwrap();
        let source = super::super::canvas_published_database::repository_root();
        let sidecar: Value = serde_json::from_slice(
            &fs::read(source.join("contracts/canvas-worker-rest-current-inputs.json")).unwrap(),
        )
        .unwrap();
        for name in INPUTS {
            let path = root.path().join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::copy(source.join(name), path).unwrap();
        }
        assert_eq!(source_inputs(root.path(), &sidecar).len(), INPUTS.len());
        for name in [
            "scripts/test_canvas_lti_https.py",
            "scripts/prepare_canvas_published_schema.py",
            "contracts/fixtures/canvas_worker_test_trust.py",
            "rust/services/issuance/tests/support/canvas_worker_rest_replay.rs",
        ] {
            let path = root.path().join(name);
            fs::write(
                &path,
                [fs::read(&path).unwrap(), b"\n# drift\n".to_vec()].concat(),
            )
            .unwrap();
            assert!(std::panic::catch_unwind(|| source_inputs(root.path(), &sidecar)).is_err());
            fs::copy(source.join(name), path).unwrap();
        }
    }

    #[test]
    fn missing_or_extra_rest_pin_is_rejected() {
        let root = super::super::canvas_published_database::repository_root();
        let mut sidecar: Value = serde_json::from_slice(
            &fs::read(root.join("contracts/canvas-worker-rest-current-inputs.json")).unwrap(),
        )
        .unwrap();
        sidecar["sha256"].as_object_mut().unwrap().remove(INPUTS[0]);
        assert!(std::panic::catch_unwind(|| source_inputs(&root, &sidecar)).is_err());
        sidecar["sha256"][INPUTS[0]] = json!("a".repeat(64));
        sidecar["sha256"]["scripts/unreviewed.py"] = json!("b".repeat(64));
        assert!(std::panic::catch_unwind(|| source_inputs(&root, &sidecar)).is_err());
    }

    #[test]
    fn rest_evidence_binds_native_inputs_and_rejects_changed_corpus() {
        let source = super::super::canvas_published_database::repository_root();
        let root = tempfile::tempdir().unwrap();
        for name in INPUTS.into_iter().chain([
            "contracts/canvas-worker-rest-current-inputs.json",
            "contracts/canvas-worker-consumer-range-oracle.json",
        ]) {
            let target = root.path().join(name);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::copy(source.join(name), target).unwrap();
        }
        let executable = root.path().join("test-executable");
        let worker = root.path().join("worker-binary");
        fs::write(&executable, b"test executable bytes").unwrap();
        fs::write(&worker, b"different worker bytes").unwrap();
        let worker_sha = attestation::file_sha(&worker);
        let evidence = rest_evidence(root.path(), json!({"sha":"test"}), &executable, &worker_sha);
        assert_eq!(evidence["schema"], "marty.canvas-worker-rest-fresh-run/v2");
        assert_eq!(
            evidence["source_inputs_sha256"].as_object().unwrap().len(),
            INPUTS.len()
        );
        assert_eq!(evidence["native_replay"], "passed");
        assert_eq!(evidence["stage_names"].as_array().unwrap().len(), 4);
        assert_eq!(evidence["worker_binary_sha256"], worker_sha);
        assert_ne!(
            evidence["worker_binary_sha256"],
            evidence["test_executable_sha256"]
        );
        assert!(evidence["scope"]
            .as_str()
            .unwrap()
            .contains("no legacy Python worker oracle"));
        let corpus_path = root.path().join("contracts/canvas-worker-rest-oracle.json");
        let mut changed: Value = serde_json::from_slice(&fs::read(&corpus_path).unwrap()).unwrap();
        changed["observations"][0]["status"] = json!("changed");
        fs::write(corpus_path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(std::panic::catch_unwind(|| {
            rest_evidence(root.path(), json!({"sha":"test"}), &executable, &worker_sha)
        })
        .is_err());
    }
}
