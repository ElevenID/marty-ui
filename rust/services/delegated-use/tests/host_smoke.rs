//! Real executable failures must happen before opening a listener or contacting
//! dependencies. These tests intentionally supply no production credential.
use std::{
    net::TcpListener,
    process::{Command, Output},
    time::{Duration, Instant},
};

fn run(arguments: &[&str], env: &[(&str, &str)]) -> Output {
    let started = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_marty-delegated-use"))
        .args(arguments)
        .env_clear()
        .envs(env.iter().copied())
        .output()
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("never-log"));
    output
}

#[test]
fn executable_is_disabled_before_file_network_and_listener_work() {
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = occupied.local_addr().unwrap().to_string();
    let output = run(
        &[],
        &[
            ("DELEGATED_USE_LISTEN_ADDR", &address),
            ("DELEGATED_USE_HEALTH_ADDR", &address),
            (
                "DELEGATED_USE_USE_WRITER_DATABASE_URL_FILE",
                "/never-log-unreadable-secret",
            ),
            (
                "DELEGATED_USE_CLIENT_CA_FILES_FILE",
                "/never-log-unreadable-ca",
            ),
            (
                "DELEGATED_USE_REQUEST_SIGN_CREDENTIAL",
                "never-log-credential",
            ),
        ],
    );
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("requires explicit MARTY_DELEGATED_USE_ENABLED=true"));
    #[cfg(unix)]
    {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};
        let output = Command::new(env!("CARGO_BIN_EXE_marty-delegated-use"))
            .env_clear()
            .env("MARTY_DELEGATED_USE_ENABLED", "false")
            .env(
                "DELEGATED_USE_SERVICE_TOKEN",
                OsString::from_vec(vec![0xff]),
            )
            .output()
            .unwrap();
        assert!(!output.status.success());
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(message.contains("requires explicit MARTY_DELEGATED_USE_ENABLED=true"));
        assert!(!message.contains("panicked"));
    }
}

#[test]
fn executable_rejects_migration_and_other_arguments_without_echoing_them() {
    for arguments in [
        vec!["migrate"],
        vec!["verify-owned-schema"],
        vec!["--service-token=never-log-secret"],
    ] {
        let output = run(&arguments, &[("MARTY_DELEGATED_USE_ENABLED", "true")]);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("accepts no command-line arguments")
        );
    }
}

#[test]
fn migration_tool_requires_one_scope_and_its_own_file_inputs() {
    let invoke = |arguments: &[&str], variables: &[(&str, &str)]| {
        let output = Command::new(env!("CARGO_BIN_EXE_marty-delegated-use-migrate"))
            .args(arguments)
            .env_clear()
            .envs(variables.iter().copied())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let message = String::from_utf8(output.stderr).unwrap();
        assert!(!message.contains("never-log"));
        message
    };
    assert!(invoke(&["never-log"], &[]).contains("select delegated-authority"));
    for schema in ["delegated-authority", "machine-credential-source"] {
        assert!(invoke(
            &[schema],
            &[("DELEGATED_USE_MIGRATION_DATABASE_URL", "never-log")]
        )
        .contains("DELEGATED_USE_MIGRATION_DATABASE_URL_FILE is required"));
        assert!(invoke(
            &[schema],
            &[("DELEGATED_USE_MIGRATION_DATABASE_URL_FILE", "never-log")],
        )
        .contains("DELEGATED_USE_MIGRATION_DATABASE_CA_FILE is required"));
    }
}

#[test]
fn executable_rejects_unknown_options_and_sanitizes_secret_file_errors() {
    let output = run(
        &[],
        &[
            ("MARTY_DELEGATED_USE_ENABLED", "true"),
            ("DELEGATED_USE_ALLOW_PLAINTEXT", "true"),
            (
                "DELEGATED_USE_USE_WRITER_DATABASE_URL_FILE",
                "/never-log-secret",
            ),
        ],
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown or duplicate field"));
    let output = run(
        &[],
        &[
            ("MARTY_DELEGATED_USE_ENABLED", "true"),
            (
                "DELEGATED_USE_USE_WRITER_DATABASE_URL_FILE",
                "/never-log-secret",
            ),
        ],
    );
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("DELEGATED_USE_USE_WRITER_DATABASE_URL"));
    assert!(message.contains("file is unavailable"));
}
