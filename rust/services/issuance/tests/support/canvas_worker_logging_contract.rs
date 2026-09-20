//! Invalid deployed logging settings fail before any secret/database setup.
use std::{
    io::Read,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn invalid_log_level_process_failure_does_not_echo_operator_value() {
    let reference: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-logging-oracle.json"
    ))
    .unwrap();
    for case in reference["cases"].as_array().unwrap() {
        if case["observed"]["error_class"] != "ValueError" {
            continue;
        }
        let mut command = Command::new(env!("CARGO_BIN_EXE_marty-canvas-sync-worker"));
        command
            .env_clear()
            .env("LOG_LEVEL", case["input"].as_str().unwrap())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        if let Some(system_root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", system_root);
        }
        let mut child = super::ChildGuard(command.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if child.0.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                panic!("invalid logging must fail before connection setup");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(child.0.wait().unwrap().code(), Some(1));
        let mut stdout = String::new();
        let mut stderr = String::new();
        child
            .0
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut stdout)
            .unwrap();
        child
            .0
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert!(stdout.is_empty());
        assert_eq!(
            stderr.replace("\r\n", "\n"),
            "Error: \"invalid Canvas worker LOG_LEVEL\"\n"
        );
    }
}
