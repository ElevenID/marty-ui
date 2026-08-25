use std::process::Stdio;

#[test]
fn executable_fails_closed_before_startup_when_required_configuration_is_missing() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_marty-auth"))
        .env("ENVIRONMENT", "beta")
        .env_remove("KEYCLOAK_REALM")
        .env_remove("DATABASE_URL")
        .env_remove("REDIS_URL")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("run Auth executable");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("KEYCLOAK_REALM is required"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn container_entrypoint_dispatches_auth_only_to_the_native_binary() {
    let entrypoint = include_str!("../../../../services/entrypoint.sh");
    let dispatch = r#"if [ "$MODULE_NAME" = "auth" ]; then"#;
    let start = entrypoint.find(dispatch).expect("Auth dispatch exists");
    let block = &entrypoint[start..];
    let end = block.find("\nfi").expect("Auth dispatch terminates");
    let block = &block[..end];
    assert!(block.contains("exec /usr/local/bin/marty-auth"));
    assert!(!block.contains("python"));
}

#[test]
fn service_image_builds_and_installs_the_native_auth_executable() {
    let dockerfile = include_str!("../../../../services/Dockerfile");
    assert!(dockerfile.contains("-p marty-auth --bin marty-auth"));
    assert!(dockerfile.contains(
        "COPY --from=rust-service-builder /build/rust/target/release/marty-auth /usr/local/bin/marty-auth"
    ));
}
