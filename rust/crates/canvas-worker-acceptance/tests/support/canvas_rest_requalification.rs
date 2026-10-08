//! Fresh REST reproducibility evidence, never provenance of the original capture.

use super::canvas_startup_attestation as attestation;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};

const ARTIFACT: &str = "canvas-rest-fresh-run.json";
const INPUTS: [&str; 10] = [
    "contracts/canvas-issued-review-scenarios.json",
    "contracts/canvas-worker-rest-scenarios.json",
    "contracts/canvas-worker-startup-scenarios.json",
    "contracts/fixtures/canvas_worker_test_trust.py",
    "scripts/canvas_worker_https_fixture.py",
    "scripts/prepare_canvas_published_schema.py",
    "scripts/run_canvas_worker_rest_oracle.py",
    "scripts/run_canvas_worker_single_cycle.py",
    "scripts/run_canvas_worker_startup_oracle.py",
    "scripts/test_canvas_lti_https.py",
];

fn source_inputs(root: &Path, sidecar: &Value) -> BTreeMap<String, String> {
    assert_eq!(
        sidecar["schema"],
        "marty.canvas-worker-rest-current-inputs/v1"
    );
    assert!(sidecar["purpose"].as_str().is_some_and(
        |purpose| purpose.contains("do not attest historical REST or downstream corpora")
    ));
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

fn rest_evidence(root: &Path, observed: &Value, run: Value, executable: &Path) -> Value {
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
    assert!(
        observed == &expected,
        "REST live comparison must pass first"
    );
    assert_eq!(observed["schema"], "marty.canvas-worker-rest-oracle/v1");
    assert_eq!(observed["observations"].as_array().map(Vec::len), Some(4));
    assert!(observed["source_sha256"]
        .as_object()
        .is_some_and(|sources| sources.len() == 2
            && sources.values().all(|digest| digest
                .as_str()
                .is_some_and(|value| attestation::valid_sha(value, 64)))));
    json!({
        "schema": "marty.canvas-worker-rest-fresh-run/v1",
        "scope": "fresh full-main REST reproducibility, not original historical capture provenance or qualification reuse",
        "workflow_result_required": "success for this run and attempt before external use",
        "run": run,
        "test": "worker_rest_reference_matches_published_process",
        "source_inputs_sha256": inputs,
        "input_inventory_sha256": attestation::normalized_sha(&root.join("contracts/canvas-worker-rest-current-inputs.json")),
        "script_graph_sha256": attestation::normalized_sha(&root.join("contracts/canvas-worker-oracle-script-imports.json")),
        "image_fixture_sha256": attestation::normalized_sha(&root.join("contracts/canvas-worker-consumer-range-oracle.json")),
        "corpus_sha256": format!("{:x}", Sha256::digest(&corpus)),
        "observed_source_sha256": observed["source_sha256"],
        "issuance_image": issuance,
        "postgres_image": postgres,
        "verified_migration_revisions": revisions,
        "test_executable_sha256": attestation::file_sha(executable),
        "published_comparison": "passed",
        "owned_cleanup": "passed",
    })
}

pub(super) fn emit_after_rest_pass(root: &Path, observed: &Value) {
    let Some(run) = attestation::main_run_from(|name| std::env::var(name).ok()) else {
        return;
    };
    let runner_temp = std::env::var("RUNNER_TEMP").expect("REST evidence output directory missing");
    let output = Path::new(&runner_temp).join(ARTIFACT);
    attestation::persist_verified_evidence(root, &output, &run, || {
        let executable = std::env::current_exe().expect("REST test executable path missing");
        rest_evidence(root, observed, run.clone(), &executable)
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
    fn rest_evidence_rejects_changed_corpus() {
        let root = super::super::canvas_published_database::repository_root();
        let corpus: Value = serde_json::from_slice(
            &fs::read(root.join("contracts/canvas-worker-rest-oracle.json")).unwrap(),
        )
        .unwrap();
        let executable = std::env::current_exe().unwrap();
        let evidence = rest_evidence(&root, &corpus, json!({"sha":"test"}), &executable);
        assert_eq!(
            evidence["source_inputs_sha256"].as_object().unwrap().len(),
            INPUTS.len()
        );
        assert_eq!(evidence["published_comparison"], "passed");
        assert!(evidence["scope"]
            .as_str()
            .unwrap()
            .contains("not original historical capture provenance"));
        let mut changed = corpus;
        changed["observations"][0]["status"] = json!("changed");
        assert!(std::panic::catch_unwind(|| rest_evidence(
            &root,
            &changed,
            json!({"sha":"test"}),
            &executable
        ))
        .is_err());
    }
}
