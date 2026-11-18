//! Exercise retired production dispatch without network or credentials.
#![cfg(target_os = "linux")]

use marty_deployment_catalog::kubernetes_legacy_recovery as recovery;
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

const OPERATIONS: &[&str] = &[
    "kubernetes-legacy-recovery-targets",
    "kubernetes-legacy-recovery-predecessors",
    "kubernetes-legacy-recovery-stage",
    "kubernetes-legacy-recovery-qualify",
    "kubernetes-legacy-recovery-target",
    "kubernetes-legacy-recovery-inspect",
];

fn command(directory: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_marty-deploy"));
    command
        .args(args)
        .current_dir(directory)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn invoke(directory: &Path, args: &[&str], input: &[u8]) -> Output {
    let mut child = command(directory, args).spawn().unwrap();
    // Retirement can close stdin before an oversized caller finishes writing.
    let _ = child.stdin.take().unwrap().write_all(input);
    child.wait_with_output().unwrap()
}

fn refused(result: Output) {
    assert_eq!(result.status.code(), Some(3));
    assert!(result.stdout.is_empty());
    assert_eq!(
        result.stderr,
        format!("{}\n", recovery::RECOVERY).as_bytes()
    );
}

#[test]
fn production_contract_is_explicitly_unavailable_without_reading_private_inputs() {
    let directory = tempfile::tempdir().unwrap();
    for contract in [
        "kubernetes-legacy-recovery-contract",
        "kubernetes-legacy-recovery-stage-contract",
    ] {
        let result = invoke(directory.path(), &["operator", contract], b"");
        assert!(result.status.success());
        assert!(result.stderr.is_empty());
        let value: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(value["legacyRuntimeSourceSha"], recovery::LEGACY_RUNTIME);
        assert_eq!(
            value["historicalInitializerSha256"],
            "57adbf26ef7b6f22a47c1ec85b9de75b807e394a2d7de48f6550b374cc8ebe1f"
        );
        for field in [
            "available",
            "mutationAvailable",
            "credentialAccess",
            "networkAccess",
            "historicalStateReinterpreted",
        ] {
            assert_eq!(value[field], false, "{field}");
        }
    }
    assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
}

#[test]
fn production_targets_do_not_reinterpret_legacy_context_or_read_authority() {
    let directory = tempfile::tempdir().unwrap();
    let request = serde_json::to_vec(&json!({"schema":recovery::SCHEMA,
        "bootstrap":{"runtimeSourceSha":recovery::LEGACY_RUNTIME},
        "current":directory.path().join("absent-current"),
        "rootTokenFile":directory.path().join("absent-root-private-sentinel")}))
    .unwrap();
    refused(invoke(
        directory.path(),
        &["operator", "kubernetes-legacy-recovery-targets"],
        &request,
    ));
    assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
}

#[test]
fn production_operations_refuse_bad_or_oversized_context_without_echo_or_side_effects() {
    let directory = tempfile::tempdir().unwrap();
    let requests = [
        Vec::new(),
        b"{}".to_vec(),
        b"not-json-private-sentinel".to_vec(),
        br#"{"schema":"private-sentinel","context":{"namespace":"a","namespace":"b"}}"#.to_vec(),
        vec![b' '; 512 * 1024 + 1],
    ];
    for operation in OPERATIONS {
        for request in &requests {
            refused(invoke(
                directory.path(),
                &["operator", operation, "private-sentinel"],
                request,
            ));
        }
    }
    assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
}

#[test]
fn production_metadata_rejects_extra_arguments_and_operations_remain_unavailable() {
    let directory = tempfile::tempdir().unwrap();
    for contract in [
        "kubernetes-legacy-recovery-contract",
        "kubernetes-legacy-recovery-stage-contract",
    ] {
        let result = invoke(
            directory.path(),
            &["operator", contract, "private-sentinel"],
            b"",
        );
        assert_eq!(result.status.code(), Some(1));
        assert!(result.stdout.is_empty());
        assert_eq!(
            result.stderr,
            format!("{}\n", marty_deployment_catalog::operator::REFUSAL).as_bytes()
        );
    }
    for operation in OPERATIONS {
        refused(invoke(
            directory.path(),
            &["operator", operation, "private-sentinel", "extra"],
            b"",
        ));
    }
    assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
}

#[test]
fn production_operations_refuse_while_stdin_is_still_open() {
    let directory = tempfile::tempdir().unwrap();
    for operation in OPERATIONS {
        let mut child = command(directory.path(), &["operator", operation])
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("retired operation waited for stdin: {operation}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        refused(child.wait_with_output().unwrap());
    }
    assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
}
