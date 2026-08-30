use std::{
    net::TcpListener,
    process::{Child, Command},
    time::Duration,
};

use serde_json::{json, Value};

use marty_issuance_service::issuance_proto::{
    issuance_service_client::IssuanceServiceClient, CredentialLifecycleRequest,
    ExchangeTokenRequest, GetCredentialStatusRequest, GetOfferRequest, GetTransactionRequest,
    HealthCheckRequest, InitiateIssuanceRequest, IssueCredentialRequest, ListTransactionsRequest,
    StreamCredentialEventsRequest,
};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn reserve_port() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve port");
    let port = listener.local_addr().expect("reserved address").port();
    (listener, port)
}

fn smoke_command(http_port: u16, grpc_port: u16) -> Command {
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

async fn wait_for_health(port: u16) -> Option<Value> {
    let client = reqwest::Client::new();
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

#[tokio::test]
async fn executable_serves_health_readiness_and_version() {
    let (listener, port) = reserve_port();
    drop(listener);
    let (grpc_listener, grpc_port) = reserve_port();
    drop(grpc_listener);
    let mut command = smoke_command(port, grpc_port);
    let _child = ChildGuard(
        command
            .env(
                "GRPC_SERVICE_TOKEN",
                "executable-smoke-service-token-at-least-32-bytes",
            )
            .spawn()
            .expect("start issuance candidate"),
    );
    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{port}");
    let health = wait_for_health(port).await;
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
    let grpc_uri = format!("http://127.0.0.1:{grpc_port}");
    let grpc_status = async {
        for _ in 0..50 {
            if let Ok(channel) = tonic::transport::Endpoint::from_shared(grpc_uri.clone())
                .expect("gRPC endpoint")
                .connect()
                .await
            {
                let mut health = tonic_health::pb::health_client::HealthClient::new(channel);
                if let Ok(response) = health
                    .check(tonic_health::pb::HealthCheckRequest {
                        service: "marty.ui.issuance.v1.IssuanceService".to_owned(),
                    })
                    .await
                {
                    return Some(response.into_inner().status);
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        None
    }
    .await;
    let channel = tonic::transport::Endpoint::from_shared(grpc_uri)
        .expect("issuance gRPC endpoint")
        .connect()
        .await
        .expect("issuance gRPC channel");
    let mut issuance = IssuanceServiceClient::new(channel);
    let mut authenticated_health = tonic::Request::new(HealthCheckRequest {});
    authenticated_health.metadata_mut().insert(
        "x-service-token",
        "executable-smoke-service-token-at-least-32-bytes"
            .parse()
            .expect("service token metadata"),
    );
    assert_eq!(
        issuance
            .health_check(authenticated_health)
            .await
            .expect("authenticated issuance health")
            .into_inner()
            .status,
        "serving"
    );
    macro_rules! assert_unauthenticated {
        ($rpc:expr) => {
            assert_eq!(
                $rpc.await.expect_err("service token required").code(),
                tonic::Code::Unauthenticated
            );
        };
    }
    assert_unauthenticated!(issuance.initiate_issuance(InitiateIssuanceRequest::default()));
    assert_unauthenticated!(issuance.exchange_token(ExchangeTokenRequest::default()));
    assert_unauthenticated!(issuance.issue_credential(IssueCredentialRequest::default()));
    assert_unauthenticated!(issuance.get_offer(GetOfferRequest::default()));
    assert_unauthenticated!(issuance.list_transactions(ListTransactionsRequest::default()));
    assert_unauthenticated!(issuance.get_transaction(GetTransactionRequest::default()));
    assert_unauthenticated!(issuance.revoke_credential(CredentialLifecycleRequest::default()));
    assert_unauthenticated!(issuance.suspend_credential(CredentialLifecycleRequest::default()));
    assert_unauthenticated!(issuance.reinstate_credential(CredentialLifecycleRequest::default()));
    assert_unauthenticated!(issuance.get_credential_status(GetCredentialStatusRequest::default()));
    assert_unauthenticated!(
        issuance.stream_credential_events(StreamCredentialEventsRequest::default())
    );
    assert_unauthenticated!(issuance.health_check(HealthCheckRequest {}));
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
    assert_eq!(
        grpc_status,
        Some(tonic_health::pb::health_check_response::ServingStatus::Serving as i32)
    );
    assert_eq!(version["service"], "issuance-service");
    assert_eq!(version["version"], "9.8.7");
    assert_eq!(version["build_revision"], "smoke-revision");
    assert_eq!(
        issuer_metadata["credential_issuer"],
        "https://issuer.example"
    );
    assert_eq!(issuer_metadata["display"][0]["name"], "Example Issuer");
}

#[tokio::test]
async fn executable_does_not_bind_an_explicitly_disabled_grpc_listener() {
    let (http_listener, http_port) = reserve_port();
    drop(http_listener);
    let (grpc_reservation, grpc_port) = reserve_port();
    let mut command = smoke_command(http_port, grpc_port);
    let _child = ChildGuard(
        command
            .env("ISSUANCE_GRPC_ENABLED", "false")
            .spawn()
            .expect("start HTTP-only issuance candidate"),
    );

    assert_eq!(
        wait_for_health(http_port).await,
        Some(json!({"status":"healthy", "service":"issuance-service"}))
    );
    drop(grpc_reservation);
}
