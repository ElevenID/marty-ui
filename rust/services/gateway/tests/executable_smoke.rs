use std::io::Write;
use std::{net::TcpListener, process::Stdio, time::Duration};

fn scoped_grant_token() -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("temporary grant token file");
    file.write_all(b"synthetic-gateway-grant-mint-token")
        .expect("write synthetic grant token");
    file
}

fn production_command() -> (std::process::Command, Vec<tempfile::NamedTempFile>) {
    let token = scoped_grant_token();
    let issuer_token = scoped_grant_token();
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_marty-gateway"));
    command
        .env("ENVIRONMENT", "production")
        .env("BAO_ADDR", "https://127.0.0.1:8200")
        .env("GATEWAY_SIGN_GRANT_MINT_TOKEN_FILE", token.path())
        .env(
            "GATEWAY_ISSUER_CSR_GRANT_MINT_TOKEN_FILE",
            issuer_token.path(),
        )
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
        .env("GRPC_INSECURE_ALLOWED", "false")
        // The process must reject Redis before opening this unused CA path.
        .env("GRPC_TLS_CA_CERT", "unused-after-redis-failure.pem")
        .env("ORG_GRPC_CA_CERT", "unused-after-redis-failure.pem")
        .env("ES_GRPC_CA_CERT", "unused-after-redis-failure.pem")
        .env(
            "GRPC_WORKLOAD_TLS_CLIENT_CERT",
            "unused-after-redis-failure.pem",
        )
        .env(
            "GRPC_WORKLOAD_TLS_CA_CERT",
            "unused-after-redis-failure.pem",
        )
        .env(
            "GRPC_WORKLOAD_TLS_CLIENT_KMS_ADDR",
            "https://127.0.0.1:8200",
        )
        .env(
            "GRPC_WORKLOAD_TLS_CLIENT_KMS_CA_CERT",
            "unused-after-redis-failure.pem",
        )
        .env("GRPC_WORKLOAD_TLS_CLIENT_KMS_TOKEN_FILE", token.path())
        .env("GRPC_WORKLOAD_TLS_CLIENT_KMS_KEY_NAME", "gateway-test-tls")
        .env("GRPC_WORKLOAD_TLS_CLIENT_KMS_KEY_VERSION", "1")
        .env("AUTH_GRPC_TARGET", "https://localhost:9001")
        .env("ORG_GRPC_TARGET", "https://localhost:9002")
        .env("ES_GRPC_TARGET", "https://localhost:9015")
        .env_remove("REDIS_URL")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    (command, vec![token, issuer_token])
}

#[tokio::test]
async fn executable_starts_and_serves_gateway_health() {
    let reservation = TcpListener::bind("127.0.0.1:0").expect("reserve port");
    let port = reservation.local_addr().expect("reserved address").port();
    drop(reservation);

    let token = scoped_grant_token();
    let issuer_token = scoped_grant_token();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_marty-gateway"))
        .env("ENVIRONMENT", "test")
        .env("BAO_ADDR", "https://127.0.0.1:8200")
        .env("GATEWAY_SIGN_GRANT_MINT_TOKEN_FILE", token.path())
        .env(
            "GATEWAY_ISSUER_CSR_GRANT_MINT_TOKEN_FILE",
            issuer_token.path(),
        )
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

struct RunningGateway(std::process::Child);
impl Drop for RunningGateway {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Exercises the real executable's feature wiring and authentication admission.
/// No Auth/Organization/command deployment is started or impersonated: these
/// unauthenticated requests must stop before any owner/proxy invocation.
#[tokio::test]
async fn executable_installs_selected_enrollment_and_command_routes_before_authentication() {
    let reservation = TcpListener::bind("127.0.0.1:0").expect("reserve port");
    let port = reservation.local_addr().expect("reserved address").port();
    drop(reservation);
    let token = scoped_grant_token();
    let issuer_token = scoped_grant_token();
    let mut child = RunningGateway(
        std::process::Command::new(env!("CARGO_BIN_EXE_marty-gateway"))
            .env("ENVIRONMENT", "test")
            .env("BAO_ADDR", "https://127.0.0.1:8200")
            .env("GATEWAY_SIGN_GRANT_MINT_TOKEN_FILE", token.path())
            .env(
                "GATEWAY_ISSUER_CSR_GRANT_MINT_TOKEN_FILE",
                issuer_token.path(),
            )
            .env("GATEWAY_PORT", port.to_string())
            .env("RATE_LIMIT_RPM", "0")
            .env(
                "GRPC_SERVICE_TOKEN",
                "synthetic-command-enrollment-service-token",
            )
            .env("MARTY_AGENT_ADMIN_ENABLED", "true")
            .env("MARTY_AGENT_ENROLLMENT_ENABLED", "true")
            .env("MARTY_DELEGATION_COMMANDS_ENABLED", "true")
            .env("MARTY_DELEGATION_APPROVAL_ENABLED", "false")
            .env("DELEGATED_COMMAND_SERVICE_URL", "http://127.0.0.1:1")
            .env_remove("GRPC_SERVICE_TOKEN_FILE")
            .env_remove("DELEGATED_AUTHORITY_SERVICE_URL")
            .env_remove("REDIS_URL")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start selected-feature gateway executable"),
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    let base = format!("http://127.0.0.1:{port}");
    let mut ready = false;
    for _ in 0..50 {
        if let Ok(response) = client.get(format!("{base}/health")).send().await {
            if response.status().is_success() {
                ready = true;
                break;
            }
        }
        assert!(
            child
                .0
                .try_wait()
                .expect("observe gateway process")
                .is_none(),
            "gateway exited before health became available"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "selected-feature gateway health became available");
    let schema = client
        .get(format!("{base}/openapi.json"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    let directory = "/v1/organizations/{organization_id}/agents";
    let enrollment = format!("{directory}/{{agent_id}}/enrollment-challenges");
    for (path, method) in [
        (directory.to_owned(), "post"),
        (enrollment.clone(), "post"),
        (format!("{enrollment}/{{challenge_id}}"), "get"),
        (format!("{enrollment}/{{challenge_id}}/complete"), "post"),
        (
            "/v1/organizations/{organization_id}/delegation-commands".to_owned(),
            "post",
        ),
    ] {
        assert!(
            schema["paths"][&path][method].is_object(),
            "selected operation absent from live OpenAPI: {method} {path}"
        );
    }
    assert!(
        schema["paths"]
            ["/v1/organizations/{organization_id}/delegation-grants/{grant_id}/approval-reviews"]
            .is_null(),
        "enrollment/commands must not select approval routing"
    );
    let organization = "11111111-1111-4111-8111-111111111111";
    let agent = "22222222-2222-4222-8222-222222222222";
    let challenge = "33333333-3333-4333-8333-333333333333";
    let enrollment =
        format!("/v1/organizations/{organization}/agents/{agent}/enrollment-challenges");
    for (path, method) in [
        (enrollment.clone(), reqwest::Method::POST),
        (format!("{enrollment}/{challenge}"), reqwest::Method::GET),
        (
            format!("{enrollment}/{challenge}/complete"),
            reqwest::Method::POST,
        ),
        (
            format!("/v1/organizations/{organization}/delegation-commands"),
            reqwest::Method::POST,
        ),
    ] {
        let response = client
            .request(method.clone(), format!("{base}{path}"))
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED,
            "selected route must reach authentication, not a missing-route fallback: {method} {path}");
    }
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
