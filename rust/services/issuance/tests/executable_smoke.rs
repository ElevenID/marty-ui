use std::{
    net::TcpListener,
    process::{Child, Command},
    time::Duration,
};

use serde_json::{json, Value};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn executable_serves_health_readiness_and_version() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve port");
    let port = listener.local_addr().expect("address").port();
    drop(listener);
    let mut command = Command::new(env!("CARGO_BIN_EXE_marty-issuance-service"));
    for (name, _) in std::env::vars().filter(|(name, _)| {
        name.starts_with("MARTY_ISSUANCE__")
            || matches!(
                name.as_str(),
                "ISSUANCE_SERVICE_PORT"
                    | "MARTY_RELEASE_VERSION"
                    | "MARTY_UI_SHA"
                    | "ISSUER_BASE_URL"
                    | "ISSUER_DISPLAY_NAME"
                    | "CORS_ALLOWED_ORIGINS"
            )
    }) {
        command.env_remove(name);
    }
    let _child = ChildGuard(
        command
            .env("MARTY_ISSUANCE__SERVER__HOST", "127.0.0.1")
            .env("MARTY_ISSUANCE__SERVER__PORT", port.to_string())
            .env("MARTY_RELEASE_VERSION", "9.8.7")
            .env("MARTY_UI_SHA", "smoke-revision")
            .env("ISSUER_BASE_URL", "https://issuer.example")
            .env("ISSUER_DISPLAY_NAME", "Example Issuer")
            .env("CORS_ALLOWED_ORIGINS", "https://wallet.example")
            .spawn()
            .expect("start issuance candidate"),
    );
    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{port}");
    let health = async {
        for _ in 0..50 {
            if let Ok(response) = client.get(format!("{base}/health")).send().await {
                if response.status().is_success() {
                    return response.json::<Value>().await.ok();
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        None
    }
    .await;
    let ready = client
        .get(format!("{base}/ready"))
        .send()
        .await
        .expect("readiness");
    let version = client
        .get(format!("{base}/version"))
        .send()
        .await
        .expect("version")
        .json::<Value>()
        .await
        .expect("version json");
    let issuer_metadata = client
        .get(format!("{base}/.well-known/openid-credential-issuer"))
        .send()
        .await
        .expect("issuer metadata")
        .json::<Value>()
        .await
        .expect("issuer metadata json");
    assert_eq!(
        health,
        Some(json!({"status":"healthy", "service":"issuance-service"}))
    );
    assert_eq!(ready.status(), 200);
    assert_eq!(version["service"], "issuance-service");
    assert_eq!(version["version"], "9.8.7");
    assert_eq!(version["build_revision"], "smoke-revision");
    assert_eq!(
        issuer_metadata["credential_issuer"],
        "https://issuer.example"
    );
    assert_eq!(issuer_metadata["display"][0]["name"], "Example Issuer");
}
