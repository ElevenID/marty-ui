#![cfg(target_os = "linux")]

use marty_deployment_catalog::installer_state::{Identity, InstallerState, Phase, RuntimeBinding};
use serde_json::Value;
#[test]
fn internal_generation_refuses_unowned_invocation_without_output_or_argument_echo() {
    let secret = "never-echo-generation-input";
    for args in [
        vec!["installer-generation-provision"],
        vec!["installer-generation-provision-transfer"],
        vec![
            "installer-generation-provision-transfer",
            "--installation-id",
            secret,
        ],
        vec![
            "installer-generation-provision",
            "--installation-id",
            secret,
        ],
        vec![
            "installer-generation-provision",
            "--installation-id",
            "00000000-0000-0000-0000-000000000000",
        ],
        vec!["installer-generation-provision", "--root-token", secret],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_marty-deploy"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
    }
}
#[test]
fn uninstall_cli_refuses_unbound_or_destructive_options_without_output() {
    for args in [
        vec!["uninstall"],
        vec!["uninstall", "--install-dir", "/missing", "--purge", "true"],
        vec!["uninstall", "--install-dir", "/missing", "--force", "true"],
        vec!["uninstall", "--install-dir", "relative"],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_marty-deploy"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}
#[test]
fn log_cli_refuses_unbounded_or_unbound_requests_without_output() {
    for args in [
        vec!["logs"],
        vec![
            "logs",
            "--install-dir",
            "/missing",
            "--service",
            "gateway",
            "--tail",
            "1001",
        ],
        vec![
            "logs",
            "--install-dir",
            "/missing",
            "--service",
            "keycloak-configurator",
        ],
        vec![
            "logs",
            "--install-dir",
            "/missing",
            "--service",
            "gateway",
            "--follow",
            "true",
        ],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_marty-deploy"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}
#[test]
fn internal_ingress_provisioner_refuses_invalid_invocation_without_output() {
    for args in [
        vec!["installer-ingress-provision"],
        vec![
            "installer-ingress-provision",
            "--installation-id",
            "invalid",
        ],
        vec![
            "installer-ingress-provision",
            "--installation-id",
            "00000000-0000-0000-0000-000000000000",
        ],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_marty-deploy"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}
#[test]
fn internal_renewal_bootstrap_refuses_unowned_invocation_without_output() {
    for args in [
        vec!["installer-renewal-bootstrap"],
        vec!["installer-renewal-bootstrap-transfer"],
        vec![
            "installer-renewal-bootstrap-transfer",
            "--installation-id",
            "invalid",
        ],
        vec![
            "installer-renewal-bootstrap-transfer",
            "--owner",
            "secret-sentinel",
        ],
        vec![
            "installer-renewal-bootstrap",
            "--installation-id",
            "invalid",
        ],
        vec![
            "installer-renewal-bootstrap",
            "--installation-id",
            "00000000-0000-0000-0000-000000000000",
        ],
        vec![
            "installer-renewal-bootstrap",
            "--root-token",
            "secret-sentinel",
        ],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_marty-deploy"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-sentinel"));
    }
}
use std::process::Command;

#[test]
fn internal_keycloak_bridge_refuses_invalid_nonce_without_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_marty-deploy"))
        .args(["installer-keycloak-bridge", "--nonce", "invalid"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Keycloak bridge input refused"));
}

#[test]
fn persisted_operator_runs_after_bootstrap_storage_is_removed() {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let stage = root.path().join("bootstrap");
    std::fs::create_dir(&stage).unwrap();
    std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o700)).unwrap();
    let source = stage.join("operator");
    std::fs::copy(env!("CARGO_BIN_EXE_marty-deploy"), &source).unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700)).unwrap();
    let digest = format!("{:x}", Sha256::digest(std::fs::read(&source).unwrap()));
    let path = root.path().join("installation");
    let mut state = InstallerState::create(
        &path,
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        },
    )
    .unwrap();
    state.persist_operator(&source, &digest).unwrap();
    drop(state);
    std::fs::remove_file(source).unwrap();
    std::fs::remove_dir(stage).unwrap();
    let output = Command::new(path.join("marty-deploy"))
        .current_dir(root.path())
        .args(["status", "--install-dir"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["runtime_observed"], false);
    assert_eq!(report["cleanup"]["state"], "not_started");
}

#[test]
fn doctor_observes_bound_engine_without_source_or_inherited_context() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("installation");
    let state = InstallerState::create_with_runtime(
        &path,
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        },
        RuntimeBinding {
            docker_host: "unix:///var/run/docker.sock".into(),
            engine_id: "test-engine".into(),
            openbao_port: 18200,
        },
    )
    .unwrap();
    let binary = path.join("docker-stub");
    let script = r#"#!/bin/sh
[ "$DOCKER_HOST" = 'unix:///var/run/docker.sock' ] || exit 4
[ -z "${DOCKER_CONTEXT:-}" ] || exit 5
case "$1" in
info) printf '%s\n' '{"id":"test-engine","os":"linux","architecture":"x86_64","server_version":"28.0.0","security_options":["name=seccomp,profile=builtin"]}' ;;
compose) printf '2.39.0\n' ;;
*) exit 9 ;;
esac
"#;
    std::fs::write(&binary, script).unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    let invoke = || {
        Command::new(env!("CARGO_BIN_EXE_marty-deploy"))
            .current_dir(root.path())
            .args(["doctor", "--install-dir"])
            .arg(&path)
            .arg("--docker-bin")
            .arg(&binary)
            .env("DOCKER_CONTEXT", "unrelated")
            .env("DOCKER_HOST", "tcp://unrelated:2375")
            .output()
            .unwrap()
    };
    let output = invoke();
    assert!(
        !output.status.success(),
        "doctor must refuse an active lifecycle writer"
    );
    assert!(output.stdout.is_empty());
    let project = state.journal().compose_project();
    drop(state);
    let output = invoke();
    assert!(output.status.success(), "{:?}", output.stderr);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["docker"]["engine_id"], "test-engine");
    assert_eq!(report["compose_project"], project);
    assert_eq!(report["services_observed"], false);
    assert_eq!(report["installation_ready"], false);
    assert_eq!(report["cleanup"]["state"], "not_started");
    std::fs::write(&binary, script.replace("test-engine", "replacement-engine")).unwrap();
    let output = invoke();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!std::fs::read_dir(&path).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".installer-command-")));
}

#[test]
fn status_reports_uncertain_journal_without_checkout_or_secret_values() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("installation");
    let mut state = InstallerState::create(
        &path,
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        },
    )
    .unwrap();
    state.advance(Phase::Verified).unwrap();
    state.advance(Phase::Provisioning).unwrap();
    std::fs::write(path.join("operator-password"), "secret-sentinel").unwrap();
    let active = Command::new(env!("CARGO_BIN_EXE_marty-deploy"))
        .args(["status", "--install-dir"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        !active.status.success(),
        "status must not mix active cleanup and journal state"
    );
    assert!(active.stdout.is_empty());
    drop(state);
    let output = Command::new(env!("CARGO_BIN_EXE_marty-deploy"))
        .current_dir(root.path())
        .arg("status")
        .arg("--install-dir")
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["scope"], "installation-journal");
    assert_eq!(report["runtime_observed"], false);
    assert_eq!(report["journal"]["phase"], "provisioning");
    assert!(!String::from_utf8(output.stdout)
        .unwrap()
        .contains("secret-sentinel"));
    assert!(output.stderr.is_empty());

    // A legacy/preparation-only journal must not adopt the caller's daemon.
    let doctor = Command::new(env!("CARGO_BIN_EXE_marty-deploy"))
        .current_dir(root.path())
        .args(["doctor", "--install-dir"])
        .arg(&path)
        .env("DOCKER_HOST", "tcp://unrelated-host:2375")
        .output()
        .unwrap();
    assert!(!doctor.status.success());
    assert!(doctor.stdout.is_empty());
    assert!(String::from_utf8(doctor.stderr)
        .unwrap()
        .contains("no recorded Docker binding"));
}
