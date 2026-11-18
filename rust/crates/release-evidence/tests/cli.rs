use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

const SOURCE: &str = "1866528ab859ea7007ca34671ad80a62131fd79d";
const FIXTURE: &[u8] = include_bytes!("fixtures/published-1.1.215.json");

fn execute(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_validate-stack-release-run"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if !input.is_empty() {
        child.stdin.take().unwrap().write_all(input).unwrap();
    }
    child.wait_with_output().unwrap()
}

#[test]
fn both_workflow_invocations_emit_only_the_validated_sha() {
    for args in [
        vec!["33937499784", "1.1.215"],
        vec!["33937499784", "1.1.215", SOURCE],
    ] {
        let output = execute(&args, FIXTURE);
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("{SOURCE}\n")
        );
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn invalid_invocations_and_payloads_emit_no_source_or_private_values() {
    for args in [
        vec![],
        vec!["not-a-run-id", "1.1.215"],
        vec!["33937499784", "1.1.215", "invalid-source"],
    ] {
        let output = execute(&args, b"");
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
    for input in [b"private-value-not-json".as_slice(), b"[]".as_slice()] {
        let output = execute(&["33937499784", "1.1.215"], input);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8(output.stderr)
            .unwrap()
            .contains("private-value"));
    }
}
