use std::io::Write;
use std::{net::TcpListener, process::Stdio, time::Duration};

fn scoped_grant_token() -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("temporary grant token file");
    file.write_all(b"synthetic-gateway-grant-mint-token")
        .expect("write synthetic grant token");
    file
}

fn production_command() -> (std::process::Command, tempfile::NamedTempFile) {
    let token = scoped_grant_token();
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_marty-gateway"));
    command
        .env("ENVIRONMENT", "production")
        .env("BAO_ADDR", "http://127.0.0.1:8200")
        .env("GATEWAY_SIGN_GRANT_MINT_TOKEN_FILE", token.path())
        .env(
            "GRPC_SERVICE_TOKEN",
            "production-grpc-token-at-least-32-characters",
        )
        .env(
            "DEVICE_REGISTRATION_GATEWAY_KEY",
            "production-device-gateway-key-at-least-32-characters",
        )
        .env(
            "SIGNING_KEYS_INTERNAL_API_KEY",
            "production-signing-key-at-least-32-characters",
        )
        .env(
            "SIGNING_KEYS_SERVICE_SIGN_GATEWAY_KEY",
            "production-service-sign-gateway-key-at-least-32-characters",
        )
        .env(
            "SIGNING_KEYS_ISSUER_SIGN_KEY",
            "production-issuer-sign-key-at-least-32-characters",
        )
        .env("ISSUANCE_API_KEY", "production-issuance-key")
        .env("GRPC_INSECURE_ALLOWED", "true")
        .env_remove("REDIS_URL")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    (command, token)
}

#[tokio::test]
async fn executable_starts_and_serves_gateway_health() {
    let reservation = TcpListener::bind("127.0.0.1:0").expect("reserve port");
    let port = reservation.local_addr().expect("reserved address").port();
    drop(reservation);

    let token = scoped_grant_token();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_marty-gateway"))
        .env("ENVIRONMENT", "test")
        .env("BAO_ADDR", "http://127.0.0.1:8200")
        .env("GATEWAY_SIGN_GRANT_MINT_TOKEN_FILE", token.path())
        .env("GATEWAY_PORT", port.to_string())
        .env("RATE_LIMIT_RPM", "0")
        .env_remove("REDIS_URL")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start gateway executable");

    let client = reqwest::Client::new();
    let health_url = format!("http://127.0.0.1:{port}/health");
    let mut payload = None;
    for _ in 0..50 {
        if let Ok(response) = client.get(&health_url).send().await {
            if response.status().is_success() {
                payload = response.json::<serde_json::Value>().await.ok();
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    child.kill().expect("stop gateway executable");
    child.wait().expect("reap gateway executable");
    assert_eq!(
        payload.expect("gateway health endpoint became available"),
        serde_json::json!({"status": "healthy", "service": "api-gateway"})
    );
}

#[test]
fn executable_refuses_production_without_redis() {
    let (mut command, _token) = production_command();
    let output = command.output().expect("run gateway executable");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("production requires Redis-backed rate limiting and idempotency"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn executable_never_falls_back_when_configured_redis_is_unavailable() {
    let (mut command, _token) = production_command();
    let output = command
        .env("REDIS_URL", "redis://127.0.0.1:1/15")
        .output()
        .expect("run gateway executable");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Redis security provider failed"),
        "unexpected stderr: {stderr}"
    );
}
