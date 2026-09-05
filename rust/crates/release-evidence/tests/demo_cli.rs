use std::process::{Command, Output};

fn arguments() -> Vec<String> {
    vec![
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/synthetic-demo-run.json"
        )
        .into(),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/synthetic-demo-report.json"
        )
        .into(),
        "123".into(),
        "3".repeat(40),
        "1.1.217".into(),
        "2".repeat(40),
        "1".repeat(40),
        "a".repeat(64),
        "b".repeat(64),
    ]
}

fn execute(args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_validate-demo-qualification"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn workflow_invocation_publishes_only_verified_allowlisted_context() {
    let output = execute(&arguments());
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["recorderRunId"], 123);
    assert_eq!(report["recorderRevision"], "3".repeat(40));
    assert_eq!(report["martyUiRevision"], "2".repeat(40));
    assert_eq!(report["sourceId"], "1".repeat(40));
    assert_eq!(report["deploymentManifestSha256"], "a".repeat(64));
    assert_eq!(report["officialStackManifestSha256"], "b".repeat(64));
    assert_eq!(report["freshRecordingRequired"], true);
    assert!(!report.to_string().contains("private-value"));
    assert!(report.get("testFixtureOnly").is_none());
}

#[test]
fn failed_cli_inputs_never_publish_partial_context_or_private_values() {
    let mut cases = vec![vec![], arguments()[..8].to_vec()];
    for index in 0..9 {
        let mut args = arguments();
        args[index] = "private-value".into();
        cases.push(args);
    }
    for (index, replacement) in [
        (0, env!("CARGO_MANIFEST_DIR")),
        (1, concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")),
        (2, "124"),
        (4, "1.1.216"),
    ] {
        let mut args = arguments();
        args[index] = replacement.into();
        cases.push(args);
    }
    for args in cases {
        let output = execute(&args);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8(output.stderr)
            .unwrap()
            .contains("private-value"));
    }
}
