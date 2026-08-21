use std::process::{Command, Output};

fn run_with(configure: impl FnOnce(&mut Command)) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_marty-credential-template"));
    command
        .env("RUST_LOG", "error")
        .env_remove("DATABASE_URL")
        .env_remove("ENVIRONMENT")
        .env_remove("GRPC_SERVICE_TOKEN")
        .env_remove("GRPC_SERVICE_TOKEN_FILE")
        .env_remove("SIGNING_KEYS_INTERNAL_API_KEY")
        .env_remove("SIGNING_KEYS_INTERNAL_API_KEY_FILE")
        .env_remove("PUBLIC_API_URL");
    configure(&mut command);
    command
        .output()
        .expect("Credential Template executable must run")
}

fn output_text(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn executable_fails_closed_without_database_configuration() {
    let output = run_with(|_| {});

    assert!(!output.status.success());
    assert!(output_text(&output).contains("DATABASE_URL is required"));
}

#[test]
fn deployed_executable_validates_native_secrets_before_connecting() {
    let output = run_with(|command| {
        command
            .env("ENVIRONMENT", "production")
            .env(
                "DATABASE_URL",
                "postgresql://marty:secret@127.0.0.1:1/unreachable",
            )
            .env("PUBLIC_API_URL", "https://issuer.example");
    });

    assert!(!output.status.success());
    let text = output_text(&output);
    assert!(text.contains("GRPC_SERVICE_TOKEN is required"));
    assert!(!text.contains("connection refused"));
}
