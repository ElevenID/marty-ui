//! Actual packaged issuance process primitives, not a second service graph.
//! Callers own any database and provider fixtures, and supply their explicit
//! synthetic configuration to the isolated command before spawning it.
use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
    time::Duration,
};

use serde_json::Value;

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

/// Retain the existing health/gRPC smoke tests' ambient-environment behavior.
pub(super) fn smoke_command(http_port: u16, grpc_port: u16) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_marty-issuance-service"));
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
            "INTEGRATION_SECRET_MASTER_KEY",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
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
