use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn matches_frozen_python_cli_cases() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap();
    let source = root.join("contracts/deployment-catalog-cli-behavior.json");
    let corpus: Value = serde_json::from_slice(&std::fs::read(source).unwrap()).unwrap();
    let root_display = root.to_string_lossy();
    let root_display = root_display.strip_prefix(r"\\?\").unwrap_or(&root_display);
    for case in corpus["cases"].as_array().unwrap() {
        let args = case["args"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect::<Vec<_>>();
        let output = Command::new(env!("CARGO_BIN_EXE_marty-deploy"))
            .args(["--repo-root", root_display]).args(&args).output().unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap().replace(root_display, "$REPO_ROOT");
        let stderr = String::from_utf8(output.stderr).unwrap().replace(root_display, "$REPO_ROOT");
        assert_eq!(output.status.code().unwrap(), case["exit_code"].as_i64().unwrap() as i32, "args: {args:?}");
        assert_eq!(stdout, case["stdout"].as_str().unwrap(), "args: {args:?}");
        assert_eq!(stderr, case["stderr"].as_str().unwrap(), "args: {args:?}");
    }
}
