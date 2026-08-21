use std::process::{Command, Output};

fn run_service(environment: &str, values: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_marty-presentation-policy"));
    command.env_clear().env("ENVIRONMENT", environment);
    for (name, value) in values {
        command.env(name, value);
    }
    command.output().expect("service executable must start")
}

fn diagnostics(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn executable_fails_before_binding_without_database_configuration() {
    let output = run_service("development", &[]);
    assert!(!output.status.success());
    assert!(diagnostics(&output).contains("DATABASE_URL is required"));
}

#[test]
fn deployed_executable_fails_before_database_io_without_service_identity() {
    let output = run_service(
        "beta",
        &[(
            "DATABASE_URL",
            "postgresql://marty:secret@127.0.0.1:1/unreachable",
        )],
    );
    assert!(!output.status.success());
    assert!(diagnostics(&output).contains("GRPC_SERVICE_TOKEN is required"));

    let output = run_service(
        "beta",
        &[
            (
                "DATABASE_URL",
                "postgresql://marty:secret@127.0.0.1:1/unreachable",
            ),
            (
                "GRPC_SERVICE_TOKEN",
                "test-only-service-token-with-at-least-32-bytes",
            ),
            (
                "ISSUANCE_API_KEY",
                "test-only-issuance-key-with-at-least-32-bytes",
            ),
            ("MIP_MANAGED_ISSUER_IDENTIFIERS", "did:example:issuer"),
        ],
    );
    assert!(!output.status.success());
    assert!(diagnostics(&output).contains("GRPC_WORKLOAD_TLS_SERVER_CERT is required"));
}
