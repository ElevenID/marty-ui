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
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/synthetic-review-comment.json"
        )
        .into(),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/synthetic-review-permission.json"
        )
        .into(),
        "123".into(),
        "3".repeat(40),
        "101".into(),
        "1.1.217".into(),
        "https://beta.elevenidllc.com".into(),
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
    assert_eq!(report["lifecycleQualified"], true);
    assert_eq!(report["qualificationMode"], "official-private");
    assert_eq!(report["betaOrigin"], "https://beta.elevenidllc.com");
    assert_eq!(report["maintainerReviewRecordId"], 101);
    assert_eq!(
        report["maintainerReviewRecordSha256"],
        "f2331a44ac0cebd7fe7e62e1dd4855d9f81e55afa1072fef3b2d3e8d630a02f8"
    );
    assert_eq!(
        report["maintainerReviewBodySha256"],
        "330f2bc3ba3ecd785b7c7a23fa4193041564bfd24c327685d6ab583d0d459748"
    );
    assert_eq!(
        report["maintainerReviewRepository"],
        "ElevenID/marty-demo-recorder"
    );
    assert_eq!(report["maintainerReviewPullRequest"], 42);
    assert_eq!(report["maintainerReviewPullRequestHeadSha"], "4".repeat(40));
    assert_eq!(report["maintainerReviewRecorderHeadSha"], "3".repeat(40));
    assert_eq!(report["maintainerReviewRecorderTreeSha"], "5".repeat(40));
    assert_eq!(report["maintainerReviewAuthor"], "BurdettAdam");
    assert_eq!(report["maintainerReviewAuthorAssociation"], "OWNER");
    assert_eq!(report["maintainerReviewPermission"], "admin");
    assert_eq!(report["maintainerReviewCreatedAt"], "2026-09-22T12:34:56Z");
    assert_eq!(report["maintainerReviewUpdatedAt"], "2026-09-22T12:34:56Z");
    assert!(!report.to_string().contains("private-value"));
    assert!(report.get("testFixtureOnly").is_none());
}

#[test]
fn failed_cli_inputs_never_publish_partial_context_or_private_values() {
    let mut cases = vec![vec![], arguments()[..12].to_vec()];
    for index in 0..13 {
        let mut args = arguments();
        args[index] = "private-value".into();
        cases.push(args);
    }
    for (index, replacement) in [
        (0, env!("CARGO_MANIFEST_DIR")),
        (1, concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")),
        (2, concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")),
        (3, concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")),
        (4, "124"),
        (6, "102"),
        (7, "1.1.216"),
        (8, "https://beta.elevenidllc.com/"),
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
