//! Actual packaged issuance process primitives, not a second service graph.
//! Callers own any database and provider fixtures, and supply their explicit
//! synthetic configuration to the isolated command before spawning it.
use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};

use serde_json::Value;

#[path = "remote_integration_secret.rs"]
pub(super) mod remote_integration_secret;

pub(super) struct ChildGuard(pub(super) Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub(super) fn reserve_port() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve port");
    let port = listener.local_addr().expect("reserved address").port();
    (listener, port)
}

/// Read a fixed-size snapshot without moving the child writer's shared file
/// offset. This is also safe while an unhealthy child remains alive.
pub(super) fn bounded_startup_diagnostic(stderr: &std::fs::File) -> std::io::Result<String> {
    let length = stderr.metadata()?.len();
    let start = length.saturating_sub(16 * 1024);
    let mut bytes = vec![0; (length - start) as usize];
    let mut filled = 0;
    while filled < bytes.len() {
        #[cfg(unix)]
        let count = {
            use std::os::unix::fs::FileExt;
            stderr.read_at(&mut bytes[filled..], start + filled as u64)?
        };
        #[cfg(windows)]
        let count = {
            use std::os::windows::fs::FileExt;
            stderr.seek_read(&mut bytes[filled..], start + filled as u64)?
        };
        if count == 0 {
            break;
        }
        filled += count;
    }
    bytes.truncate(filled);
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub(super) fn retryable_listener_bind_failure(terminal_failure: bool, diagnostic: &str) -> bool {
    terminal_failure && diagnostic.contains("kind: AddrInUse")
}

/// Cargo only exposes a package's binary path to that package's integration
/// tests. Cross-service acceptance receives the exact built artifact from CI.
pub(super) fn issuance_binary() -> PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_marty-issuance-service") {
        return PathBuf::from(path);
    }
    let path = PathBuf::from(
        std::env::var_os("MARTY_ISSUANCE_TEST_BINARY")
            .expect("set MARTY_ISSUANCE_TEST_BINARY to the built issuance binary"),
    );
    assert!(
        path.is_absolute() && path.is_file(),
        "issuance binary must be an absolute built artifact"
    );
    path
}

/// Retain the existing health/gRPC smoke tests' ambient-environment behavior.
pub(super) fn smoke_command(http_port: u16, grpc_port: u16) -> Command {
    let mut command = Command::new(issuance_binary());
    // These process-smoke probes do not authorize signing. Give startup a
    // syntactically valid grant configuration whose token file cannot exist;
    // an unexpected signing attempt must still fail closed.
    let absent_grant_file = std::env::temp_dir().join(format!(
        "marty-issuance-smoke-no-grant-{}/token",
        uuid::Uuid::new_v4()
    ));
    for (name, _) in std::env::vars().filter(|(name, _)| {
        name.starts_with("MARTY_ISSUANCE__")
            || matches!(
                name.as_str(),
                "ISSUANCE_SERVICE_PORT"
                    | "ISSUANCE_GRPC_PORT"
                    | "ISSUANCE_GRPC_ENABLED"
                    | "GRPC_SERVICE_TOKEN"
                    | "GRPC_SERVICE_TOKEN_FILE"
                    | "INTEGRATION_SECRET_MASTER_KEY"
                    | "INTEGRATION_SECRET_MASTER_KEY_ENV"
                    | "INTEGRATION_SECRET_MASTER_KEY_FILE"
                    | "SIGNING_KEYS_INTERNAL_URL"
                    | "SIGNING_KEYS_INTERNAL_API_KEY"
                    | "SIGNING_KEYS_ISSUER_SIGN_KEY"
                    | "SIGNING_KEYS_INTEGRATION_SECRET_KEY"
                    | "MARTY_RELEASE_VERSION"
                    | "MARTY_UI_SHA"
                    | "ISSUER_BASE_URL"
                    | "ISSUER_DISPLAY_NAME"
                    | "CORS_ALLOWED_ORIGINS"
            )
    }) {
        command.env_remove(name);
    }
    command
        .env("ENVIRONMENT", "development")
        .env("MARTY_ISSUANCE__SERVER__HOST", "127.0.0.1")
        .env("MARTY_ISSUANCE__SERVER__PORT", http_port.to_string())
        .env("MARTY_ISSUANCE__SERVER__GRPC_PORT", grpc_port.to_string())
        .env(
            "TOKEN_HMAC_KEY",
            format!("executable-smoke-{}", uuid::Uuid::new_v4()),
        )
        .env(
            "SIGNING_KEYS_INTERNAL_URL",
            remote_integration_secret::base_url().as_str(),
        )
        .env(
            "INTEGRATION_SECRET_KMS_URL",
            remote_integration_secret::base_url().as_str(),
        )
        .env(
            "INTEGRATION_SECRET_KMS_CA_FILE",
            remote_integration_secret::ca_file(),
        )
        .env(
            "SIGNING_KEYS_INTERNAL_API_KEY",
            remote_integration_secret::API_KEY,
        )
        .env(
            "SIGNING_KEYS_ISSUER_SIGN_KEY",
            "synthetic-issuance-issuer-sign-key-32-chars",
        )
        .env(
            "SIGNING_KEYS_INTEGRATION_SECRET_KEY",
            remote_integration_secret::INTEGRATION_SECRET_KEY,
        )
        .env("BAO_ADDR", "https://127.0.0.1:1")
        .env(
            "ISSUANCE_CREDENTIAL_SIGN_GRANT_MINT_TOKEN_FILE",
            &absent_grant_file,
        )
        .env(
            "ISSUANCE_CANVAS_SIGN_GRANT_MINT_TOKEN_FILE",
            &absent_grant_file,
        )
        .env(
            "ISSUANCE_READINESS_SIGN_GRANT_MINT_TOKEN_FILE",
            &absent_grant_file,
        )
        .env(
            "ISSUANCE_PASSPORT_SIGN_GRANT_MINT_TOKEN_FILE",
            &absent_grant_file,
        )
        .env("MARTY_RELEASE_VERSION", "9.8.7")
        .env("MARTY_UI_SHA", "smoke-revision")
        .env("ISSUER_BASE_URL", "https://issuer.example")
        .env("ISSUER_DISPLAY_NAME", "Example Issuer")
        .env("CORS_ALLOWED_ORIGINS", "https://wallet.example");
    command
}

/// Inherit no application secrets, configuration, proxies, or deployment URLs.
/// Database/key/provider overrides must be explicitly supplied by the fixture.
pub(super) fn isolated_smoke_command(http_port: u16, grpc_port: u16) -> Command {
    let mut command = smoke_command(http_port, grpc_port);
    let explicit: Vec<_> = command
        .get_envs()
        .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.to_owned())))
        .collect();
    command
        .env_clear()
        .envs(explicit)
        .env("ISSUANCE_GRPC_ENABLED", "false")
        .env("RUST_LOG", "error")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", system_root);
    }
    command
}

pub(super) fn bounded_http_client(timeout: Duration) -> reqwest::Client {
    assert!(
        !timeout.is_zero(),
        "owned HTTP request timeout must be positive"
    );
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .build()
        .expect("configure owned process HTTP client")
}

/// Callers also bound the whole readiness wait; each request uses their client.
pub(super) async fn wait_for_health_with_client(
    port: u16,
    client: &reqwest::Client,
) -> Option<Value> {
    for _ in 0..50 {
        if let Ok(response) = client
            .get(format!("http://127.0.0.1:{port}/health"))
            .send()
            .await
        {
            if response.status().is_success() {
                return response.json::<Value>().await.ok();
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

#[cfg(test)]
mod listener_bind_collision_tests {
    use super::{bounded_startup_diagnostic, retryable_listener_bind_failure};
    use std::io::Write;

    #[test]
    fn retries_only_terminal_addr_in_use() {
        let bind = "Error: Os { code: 98, kind: AddrInUse, message: \"Address already in use\" }";
        assert!(retryable_listener_bind_failure(true, bind));
        assert!(!retryable_listener_bind_failure(false, bind));
        assert!(!retryable_listener_bind_failure(
            true,
            "Error: database migration failed"
        ));
        assert!(!retryable_listener_bind_failure(
            true,
            "timed out waiting for readiness"
        ));
    }

    #[test]
    fn retains_bounded_tail_for_non_bind_failure() {
        let path = std::env::temp_dir().join(format!(
            "marty-issuance-stderr-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let mut child_writer = file.try_clone().unwrap();
        child_writer.write_all(&vec![b'x'; 17 * 1024]).unwrap();
        child_writer
            .write_all(b"Error: database migration failed")
            .unwrap();
        let diagnostic = bounded_startup_diagnostic(&file).unwrap();
        assert!(diagnostic.len() <= 16 * 1024);
        assert!(diagnostic.ends_with("Error: database migration failed"));
        assert!(!retryable_listener_bind_failure(true, &diagnostic));
        child_writer.write_all(b"; writer remains at end").unwrap();
        let later = bounded_startup_diagnostic(&file).unwrap();
        assert!(later.ends_with("Error: database migration failed; writer remains at end"));
        drop(child_writer);
        drop(file);
        std::fs::remove_file(path).unwrap();
    }
}
