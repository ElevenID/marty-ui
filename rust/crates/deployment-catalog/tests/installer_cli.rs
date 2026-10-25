#![cfg(target_os = "linux")]

use marty_deployment_catalog::installer_state::{Identity, InstallerState, Phase};
use serde_json::Value;
use std::process::Command;

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
}
