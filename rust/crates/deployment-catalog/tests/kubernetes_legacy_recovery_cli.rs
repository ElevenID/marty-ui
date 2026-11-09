//! Exercise the actual production command dispatch without network or credentials.
#![cfg(target_os = "linux")]

use marty_deployment_catalog::{application_tokens, kubernetes_legacy_recovery as recovery};
use marty_selfhost_identity::SELFHOST_ROLES;
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};

fn invoke(directory: &Path, args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_marty-deploy"))
        .args(args)
        .current_dir(directory)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Refusal may close stdin before an oversized caller finishes writing.
    let _ = child.stdin.take().unwrap().write_all(input);
    child.wait_with_output().unwrap()
}

fn context(directory: &Path) -> Value {
    let namespace = "marty-cli-local-test";
    let bootstrap = "00000000-0000-4000-8000-000000000001";
    let namespace_uid = "00000000-0000-4000-8000-000000000002";
    let cluster = "00000000-0000-4000-8000-000000000003";
    let nonce = "012345abcdef";
    let project = format!("marty-selfhost-disposable-k8s-{nonce}");
    let ordinary: Vec<_> = application_tokens::specifications()
        .iter()
        .map(|spec| {
            json!({
                "input":spec.input,"requestedPolicies":spec.policies,
                "requestedTtl":if spec.input == "OPENBAO_BOOTSTRAP_TOKEN" {"2h"} else {"8h"},
                "requestedRenewable":false,"requestedOrphan":true,"requestedNoDefaultPolicy":true,
            })
        })
        .collect();
    let roles: Vec<_> = SELFHOST_ROLES
        .iter()
        .map(|role| {
            json!({
                "role":role.name,"key_name":role.key_name,"version":1,
            })
        })
        .collect();
    json!({"schema":recovery::SCHEMA,
        "bootstrap":{"bootstrapId":bootstrap,"namespace":namespace,"openbaoClusterId":cluster,
            "status":"openbao-and-application-credentials-ready","runtimeSourceSha":recovery::LEGACY_RUNTIME,
            "chartSourceSha":"a".repeat(40),"credentialLifetimeHours":8,"migrationBootstrapLifetimeHours":2,
            "credentialLifecycle":{"schema":"marty.kubernetes-credential-lifecycle/v1","namespaceUid":namespace_uid,
                "producerNonce":nonce,"workloadProject":project,"ordinaryTokens":ordinary}},
        "initializeRequest":{"bootstrapId":bootstrap,"namespace":namespace,"namespaceUid":namespace_uid,
            "producerNonce":nonce,"workloadProject":project,"operation":"bao operator init",
            "recoveryShares":1,"recoveryThreshold":1},
        "tlsKeyMetadata":{"schema":"marty.selfhost-disposable-tls-keys/v1","roles":roles},
        "namespaceObservation":{"name":namespace,"uid":namespace_uid},
        "current":directory.join("absent-current"),"rootTokenFile":directory.join("absent-root"),
        "retainedRootSha256":"b".repeat(64)})
}

#[test]
fn production_contract_is_explicit_closed_and_does_not_read_private_inputs() {
    let directory = tempfile::tempdir().unwrap();
    let result = invoke(
        directory.path(),
        &["operator", "kubernetes-legacy-recovery-stage-contract"],
        b"",
    );
    assert!(result.status.success());
    assert!(result.stderr.is_empty());
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(
        value,
        json!({"schema":"marty.kubernetes-legacy-recovery-stage/v1",
        "legacyRuntimeSourceSha":recovery::LEGACY_RUNTIME,"certificateReplacements":18,"tokenReplacements":33,
        "replacementFiles":51,"existingSecretTargets":34,"maximumReplacementTtlSeconds":28800,
        "migrationTokenReplacement":false,"scopeMutation":false,"activationPerformed":false,
        "qualificationSchema":"marty.kubernetes-legacy-recovery-qualified-plan/v1","planLifetimeSeconds":300})
    );
    assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
}

#[test]
fn production_targets_validate_retained_binding_without_reading_authority() {
    let directory = tempfile::tempdir().unwrap();
    let request = serde_json::to_vec(&context(directory.path())).unwrap();
    let result = invoke(
        directory.path(),
        &["operator", "kubernetes-legacy-recovery-targets"],
        &request,
    );
    assert!(result.status.success());
    assert!(result.stderr.is_empty());
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(
        value["schema"],
        "marty.kubernetes-legacy-recovery-targets/v1"
    );
    assert_eq!(value["namespace"], "marty-cli-local-test");
    assert_eq!(value["replacementCount"], 51);
    let names = value["names"].as_array().unwrap();
    assert_eq!(names.len(), 34);
    assert!(names.contains(&json!("notification-tls-kms")));
    assert!(names.contains(&json!("notification-workload-tls")));
    assert!(names
        .windows(2)
        .all(|pair| pair[0].as_str().unwrap() < pair[1].as_str().unwrap()));
    assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
}

#[test]
fn production_private_commands_refuse_bad_or_oversized_context_without_echo_or_side_effects() {
    let directory = tempfile::tempdir().unwrap();
    let requests = [
        Vec::new(), b"{}".to_vec(), b"not-json-private-sentinel".to_vec(),
        br#"{"schema":"private-sentinel","context":{"bootstrap":{"namespace":"a","namespace":"b"}}}"#.to_vec(),
        vec![b' '; 512 * 1024 + 1],
    ];
    for command in [
        "kubernetes-legacy-recovery-targets",
        "kubernetes-legacy-recovery-stage",
        "kubernetes-legacy-recovery-qualify",
    ] {
        for request in &requests {
            let result = invoke(directory.path(), &["operator", command], request);
            assert_eq!(result.status.code(), Some(1), "{command}");
            assert!(result.stdout.is_empty());
            assert_eq!(
                result.stderr,
                format!("{}\n", marty_deployment_catalog::operator::REFUSAL).as_bytes()
            );
        }
    }
    assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
}

#[test]
fn production_recovery_commands_accept_no_extra_or_credential_arguments() {
    let directory = tempfile::tempdir().unwrap();
    for command in [
        "kubernetes-legacy-recovery-stage-contract",
        "kubernetes-legacy-recovery-targets",
        "kubernetes-legacy-recovery-stage",
        "kubernetes-legacy-recovery-qualify",
    ] {
        let result = invoke(
            directory.path(),
            &["operator", command, "private-sentinel"],
            b"",
        );
        assert_eq!(result.status.code(), Some(1), "{command}");
        assert!(result.stdout.is_empty());
        assert_eq!(
            result.stderr,
            format!("{}\n", marty_deployment_catalog::operator::REFUSAL).as_bytes()
        );
    }
    assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
}
