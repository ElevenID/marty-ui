//! Fresh-run evidence only; never a retrofit of the original frozen capture.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

const ARTIFACT: &str = "canvas-startup-fresh-run.json";
const INPUTS: [&str; 3] = [
    "contracts/canvas-worker-startup-scenarios.json",
    "scripts/run_canvas_worker_single_cycle.py",
    "scripts/run_canvas_worker_startup_oracle.py",
];

fn valid_sha(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn main_run_from(env: impl Fn(&str) -> Option<String>) -> Option<Value> {
    if env("GITHUB_ACTIONS").as_deref() != Some("true")
        || env("MARTY_CANVAS_FULL_QUALIFICATION").as_deref() != Some("1")
        || env("GITHUB_REF").as_deref() != Some("refs/heads/main")
    {
        return None;
    }
    let required = |name| {
        env(name).unwrap_or_else(|| panic!("Missing startup attestation run identity: {name}"))
    };
    let event = required("GITHUB_EVENT_NAME");
    assert!(matches!(event.as_str(), "schedule" | "workflow_dispatch"));
    let repository = required("GITHUB_REPOSITORY");
    assert_eq!(repository, "ElevenID/marty-ui");
    let sha = required("GITHUB_SHA");
    assert!(valid_sha(&sha, 40), "Invalid startup attestation main SHA");
    let run_id = required("GITHUB_RUN_ID");
    let attempt = required("GITHUB_RUN_ATTEMPT");
    assert!(run_id.parse::<u64>().is_ok_and(|number| number > 0));
    assert!(attempt.parse::<u64>().is_ok_and(|number| number > 0));
    let job = required("GITHUB_JOB");
    assert_eq!(job, "test-rust-services");
    Some(json!({
        "repository": repository,
        "ref": "refs/heads/main",
        "sha": sha,
        "event": event,
        "run_id": run_id,
        "run_attempt": attempt,
        "job": job,
        "lane": "canvas",
    }))
}

fn normalized_sha(path: &Path) -> String {
    let source = fs::read_to_string(path).expect("Startup capture input is missing or not UTF-8");
    format!(
        "{:x}",
        Sha256::digest(source.replace("\r\n", "\n").replace('\r', "\n").as_bytes())
    )
}

pub(super) fn file_sha(path: &Path) -> String {
    let mut source = File::open(path).expect("Startup attestation executable is unavailable");
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = source
            .read(&mut buffer)
            .expect("Startup attestation executable read failed");
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    format!("{:x}", digest.finalize())
}

fn verified_worker_binary_sha(path: &Path, before: &str, resolved: &Path) -> String {
    assert!(
        path == resolved,
        "Startup replay worker binary identity changed"
    );
    assert!(
        valid_sha(before, 64),
        "Invalid startup worker binary digest"
    );
    let after = file_sha(path);
    assert!(
        after == before,
        "Startup replay worker binary bytes changed"
    );
    after
}

fn source_inputs(root: &Path, sidecar: &Value) -> BTreeMap<String, String> {
    assert_eq!(
        sidecar["schema"],
        "marty.canvas-worker-startup-current-inputs/v1"
    );
    assert!(sidecar["purpose"]
        .as_str()
        .is_some_and(|purpose| purpose.contains("do not attest the historical startup corpus")));
    let pins = sidecar["sha256"].as_object().expect("Input pins missing");
    assert_eq!(pins.len(), INPUTS.len(), "Unreviewed startup input pins");
    INPUTS
        .iter()
        .map(|name| {
            let pinned = pins[*name].as_str().expect("Startup input pin missing");
            assert!(valid_sha(pinned, 64), "Invalid startup input pin: {name}");
            let actual = normalized_sha(&root.join(name));
            assert_eq!(actual, pinned, "Startup capture input drift: {name}");
            ((*name).to_owned(), actual)
        })
        .collect()
}

fn image_digest(reference: &Value) -> &str {
    let image = reference.as_str().expect("Pinned image reference missing");
    let (_, digest) = image.split_once("@sha256:").expect("Unpinned image");
    assert!(valid_sha(digest, 64), "Invalid image digest");
    image
}

fn startup_evidence(
    root: &Path,
    observed: &Value,
    run: Value,
    executable: &Path,
    worker_binary_sha: &str,
) -> Value {
    let sidecar: Value = serde_json::from_slice(
        &fs::read(root.join("contracts/canvas-worker-startup-current-inputs.json"))
            .expect("Startup input sidecar missing"),
    )
    .expect("Startup input sidecar invalid");
    let inputs = source_inputs(root, &sidecar);
    let fixture: Value = serde_json::from_slice(
        &fs::read(root.join("contracts/canvas-worker-consumer-range-oracle.json"))
            .expect("Pinned Canvas image fixture missing"),
    )
    .expect("Pinned Canvas image fixture invalid");
    let issuance = image_digest(&fixture["observed_image"]);
    let postgres = image_digest(&fixture["observed_postgres_image"]);
    let revisions = &fixture["migration_revisions"];
    assert!(revisions
        .as_array()
        .is_some_and(|items| items.len() == 1 && items[0] == "merge_issuance_heads"));
    let corpus = fs::read(root.join("contracts/canvas-worker-startup-oracle.json"))
        .expect("Frozen startup corpus missing");
    let expected: Value = serde_json::from_slice(&corpus).expect("Frozen startup corpus invalid");
    assert_eq!(
        observed, &expected,
        "Startup evidence must match the live comparison"
    );
    assert_eq!(observed["schema"], "marty.canvas-worker-startup-oracle/v1");
    assert!(observed["python"]
        .as_str()
        .is_some_and(|version| !version.is_empty()));
    assert!(observed["source_sha256"]
        .as_object()
        .is_some_and(|sources| !sources.is_empty()
            && sources
                .values()
                .all(|digest| digest.as_str().is_some_and(|value| valid_sha(value, 64)))));
    let corpus_sha = format!("{:x}", Sha256::digest(&corpus));
    let scenarios: Value = serde_json::from_slice(
        &fs::read(root.join("contracts/canvas-worker-startup-scenarios.json"))
            .expect("Startup scenarios missing"),
    )
    .expect("Startup scenarios invalid");
    let conditional_child = scenarios["cases"]
        .as_array()
        .expect("Startup cases missing")
        .iter()
        .any(|case| case["observe_cycle_result"] == true);
    let executable = file_sha(executable);
    assert!(valid_sha(worker_binary_sha, 64));
    json!({
        "schema": "marty.canvas-worker-startup-fresh-run/v1",
        "scope": "fresh live full-main startup comparison and native replay, not original-capture attestation or qualification reuse",
        "workflow_result_required": "success for this run and attempt before external use",
        "run": run,
        "test": "worker_startup_matches_published_process_and_idle_heartbeat",
        "source_inputs_sha256": inputs,
        "input_inventory_sha256": normalized_sha(&root.join("contracts/canvas-worker-startup-current-inputs.json")),
        "script_graph_sha256": normalized_sha(&root.join("contracts/canvas-worker-oracle-script-imports.json")),
        "image_fixture_sha256": normalized_sha(&root.join("contracts/canvas-worker-consumer-range-oracle.json")),
        "conditional_child_requested": conditional_child,
        "corpus_sha256": corpus_sha,
        "observed_python": observed["python"],
        "observed_source_sha256": observed["source_sha256"],
        "issuance_image": issuance,
        "postgres_image": postgres,
        "verified_migration_revisions": revisions,
        "test_executable_sha256": executable,
        "worker_binary_sha256": worker_binary_sha,
        "published_comparison": "passed",
        "native_replay": "passed",
        "owned_cleanup": "passed",
    })
}

pub(super) fn emit_after_startup_pass(
    root: &Path,
    observed: &Value,
    worker_binary: &Path,
    worker_binary_before: &str,
) {
    let resolved = super::canvas_worker_process_signals::worker_executable();
    let worker_binary_after =
        verified_worker_binary_sha(worker_binary, worker_binary_before, &resolved);
    let Some(run) = main_run_from(|name| std::env::var(name).ok()) else {
        return;
    };
    let executable = std::env::current_exe().expect("Test executable path missing");
    let evidence = startup_evidence(root, observed, run, &executable, &worker_binary_after);
    let runner_temp =
        std::env::var("RUNNER_TEMP").expect("Startup attestation output directory missing");
    let output = Path::new(&runner_temp).join(ARTIFACT);
    persist_evidence(&output, &evidence);
}

fn persist_evidence(output: &Path, evidence: &Value) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .expect("Refusing to overwrite startup attestation");
    serde_json::to_writer_pretty(&mut file, evidence).expect("Startup attestation write failed");
    file.write_all(b"\n")
        .expect("Startup attestation write failed");
    file.sync_all().expect("Startup attestation sync failed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_write_rejects_existing_record_without_overwriting_it() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(ARTIFACT);
        let first = json!({"run_id": "12"});
        persist_evidence(&path, &first);
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&path).unwrap()).unwrap(),
            first
        );
        let second = json!({"run_id": "13"});
        assert!(std::panic::catch_unwind(|| persist_evidence(&path, &second)).is_err());
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&path).unwrap()).unwrap(),
            first
        );
    }

    #[test]
    fn startup_input_mutation_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        for name in INPUTS {
            let target = root.path().join(name);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(&target, "original\n").unwrap();
        }
        let pins: serde_json::Map<String, Value> = INPUTS
            .iter()
            .map(|name| {
                (
                    (*name).to_owned(),
                    json!(normalized_sha(&root.path().join(name))),
                )
            })
            .collect();
        let sidecar = json!({
            "schema": "marty.canvas-worker-startup-current-inputs/v1",
            "purpose": "These hashes do not attest the historical startup corpus",
            "sha256": pins,
        });
        assert_eq!(source_inputs(root.path(), &sidecar).len(), INPUTS.len());
        for name in INPUTS {
            let path = root.path().join(name);
            fs::write(&path, "changed\n").unwrap();
            assert!(std::panic::catch_unwind(|| source_inputs(root.path(), &sidecar)).is_err());
            fs::write(path, "original\n").unwrap();
        }
        let mut extra = sidecar;
        extra["sha256"]["scripts/unreviewed.py"] = json!("0".repeat(64));
        assert!(std::panic::catch_unwind(|| source_inputs(root.path(), &extra)).is_err());
    }

    #[test]
    fn attestation_rejects_mutable_image_references() {
        assert!(std::panic::catch_unwind(|| {
            image_digest(&json!("image:latest"));
        })
        .is_err());
    }

    #[test]
    fn evidence_binds_observed_corpus_inputs_images_and_executable() {
        let root = tempfile::tempdir().unwrap();
        for name in INPUTS {
            let target = root.path().join(name);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(
                &target,
                if name.ends_with(".json") {
                    "{\"cases\":[{}]}\n"
                } else {
                    "# input\n"
                },
            )
            .unwrap();
        }
        let pins: serde_json::Map<String, Value> = INPUTS
            .iter()
            .map(|name| {
                (
                    (*name).to_owned(),
                    json!(normalized_sha(&root.path().join(name))),
                )
            })
            .collect();
        let sidecar = json!({"schema":"marty.canvas-worker-startup-current-inputs/v1", "purpose":"These hashes do not attest the historical startup corpus", "sha256":pins});
        fs::write(
            root.path()
                .join("contracts/canvas-worker-startup-current-inputs.json"),
            serde_json::to_vec(&sidecar).unwrap(),
        )
        .unwrap();
        fs::write(
            root.path()
                .join("contracts/canvas-worker-oracle-script-imports.json"),
            b"{}",
        )
        .unwrap();
        let image = format!("issuance@sha256:{}", "a".repeat(64));
        let fixture = json!({"observed_image":image, "observed_postgres_image":format!("postgres@sha256:{}", "b".repeat(64)), "migration_revisions":["merge_issuance_heads"]});
        fs::write(
            root.path()
                .join("contracts/canvas-worker-consumer-range-oracle.json"),
            serde_json::to_vec(&fixture).unwrap(),
        )
        .unwrap();
        let observed = json!({"schema":"marty.canvas-worker-startup-oracle/v1", "python":"3.12.13", "source_sha256":{"worker":"c".repeat(64)}, "cases":[]});
        let corpus = serde_json::to_vec(&observed).unwrap();
        fs::write(
            root.path()
                .join("contracts/canvas-worker-startup-oracle.json"),
            &corpus,
        )
        .unwrap();
        let executable = root.path().join("executable");
        fs::write(&executable, b"abc").unwrap();
        let worker_binary = root.path().join("worker-binary");
        fs::write(&worker_binary, b"independent worker bytes").unwrap();
        let worker_sha = file_sha(&worker_binary);
        let run = json!({"sha":"d".repeat(40), "run_id":"12"});
        let evidence = startup_evidence(
            root.path(),
            &observed,
            run.clone(),
            &executable,
            &worker_sha,
        );
        assert_eq!(
            evidence["schema"],
            "marty.canvas-worker-startup-fresh-run/v1"
        );
        assert_eq!(evidence["run"], run);
        assert_eq!(
            evidence["corpus_sha256"],
            format!("{:x}", Sha256::digest(&corpus))
        );
        assert_eq!(evidence["source_inputs_sha256"], sidecar["sha256"]);
        assert_eq!(evidence["issuance_image"], image);
        assert_eq!(evidence["observed_python"], "3.12.13");
        assert_eq!(evidence["test_executable_sha256"], file_sha(&executable));
        assert_eq!(evidence["worker_binary_sha256"], worker_sha);
        assert_ne!(
            evidence["worker_binary_sha256"],
            evidence["test_executable_sha256"]
        );
        assert_eq!(evidence["conditional_child_requested"], false);
        let mut different = observed.clone();
        different["python"] = json!("different");
        assert!(std::panic::catch_unwind(|| startup_evidence(
            root.path(),
            &different,
            run.clone(),
            &executable,
            &worker_sha
        ))
        .is_err());
        let mut unpinned = fixture;
        unpinned["observed_image"] = json!("image:latest");
        fs::write(
            root.path()
                .join("contracts/canvas-worker-consumer-range-oracle.json"),
            serde_json::to_vec(&unpinned).unwrap(),
        )
        .unwrap();
        assert!(std::panic::catch_unwind(|| startup_evidence(
            root.path(),
            &observed,
            run.clone(),
            &executable,
            &worker_sha
        ))
        .is_err());
    }

    #[test]
    fn executable_digest_hashes_file_contents() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("executable");
        fs::write(&path, b"abc").unwrap();
        assert_eq!(
            file_sha(&path),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn worker_binary_identity_and_bytes_are_stable_across_replay() {
        let root = tempfile::tempdir().unwrap();
        let worker = root.path().join("worker");
        let other = root.path().join("other");
        fs::write(&worker, b"worker before replay").unwrap();
        fs::write(&other, b"different worker").unwrap();
        let before = file_sha(&worker);
        assert_eq!(
            verified_worker_binary_sha(&worker, &before, &worker),
            before
        );
        assert!(std::panic::catch_unwind(|| {
            verified_worker_binary_sha(&other, &before, &worker)
        })
        .is_err());
        fs::write(&worker, b"worker changed during replay").unwrap();
        assert!(std::panic::catch_unwind(|| {
            verified_worker_binary_sha(&worker, &before, &worker)
        })
        .is_err());
    }

    #[test]
    fn startup_evidence_requires_full_main_run_identity() {
        let mut env = BTreeMap::from([
            ("GITHUB_ACTIONS", "true".to_owned()),
            ("MARTY_CANVAS_FULL_QUALIFICATION", "1".to_owned()),
            ("GITHUB_REF", "refs/heads/main".to_owned()),
            ("GITHUB_EVENT_NAME", "schedule".to_owned()),
            ("GITHUB_REPOSITORY", "ElevenID/marty-ui".to_owned()),
            ("GITHUB_SHA", "a".repeat(40)),
            ("GITHUB_RUN_ID", "12".to_owned()),
            ("GITHUB_RUN_ATTEMPT", "1".to_owned()),
            ("GITHUB_JOB", "test-rust-services".to_owned()),
        ]);
        assert_eq!(
            main_run_from(|name| env.get(name).cloned()).unwrap()["run_id"],
            "12"
        );
        for (name, value) in [
            ("GITHUB_ACTIONS", "false"),
            ("MARTY_CANVAS_FULL_QUALIFICATION", "0"),
            ("GITHUB_REF", "refs/pull/1/merge"),
        ] {
            let mut inactive = env.clone();
            inactive.insert(name, value.to_owned());
            assert_eq!(main_run_from(|key| inactive.get(key).cloned()), None);
        }
        for (name, value) in [
            ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_SHA", "invalid"),
            ("GITHUB_RUN_ID", "0"),
            ("GITHUB_RUN_ATTEMPT", "0"),
            ("GITHUB_JOB", "other"),
        ] {
            let mut invalid = env.clone();
            invalid.insert(name, value.to_owned());
            assert!(
                std::panic::catch_unwind(|| main_run_from(|key| invalid.get(key).cloned()))
                    .is_err()
            );
        }
        env.remove("GITHUB_RUN_ID");
        assert!(std::panic::catch_unwind(|| main_run_from(|key| env.get(key).cloned())).is_err());
    }
}
