use std::time::Duration;

use serde_json::{json, Value};

use marty_issuance_service::issuance_proto::{
    issuance_service_client::IssuanceServiceClient, CredentialLifecycleRequest,
    ExchangeTokenRequest, GetCredentialStatusRequest, GetOfferRequest, GetTransactionRequest,
    HealthCheckRequest, InitiateIssuanceRequest, IssueCredentialRequest, ListTransactionsRequest,
    StreamCredentialEventsRequest,
};

#[path = "support/issuance_process.rs"]
mod issuance_process;

use issuance_process::{
    bounded_http_client, isolated_smoke_command, reserve_port, smoke_command,
    wait_for_health_with_client, ChildGuard,
};

#[path = "support/canvas_worker_logging_contract.rs"]
mod canvas_worker_logging_contract;

async fn wait_for_health(port: u16) -> Option<Value> {
    let client = reqwest::Client::new();
    wait_for_health_with_client(port, &client).await
}

#[tokio::test]
async fn executable_serves_unrelated_health_with_missing_or_malformed_didcomm_ca() {
    use std::io::Write;
    struct OwnedFile(std::path::PathBuf);
    impl Drop for OwnedFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let path = std::env::temp_dir().join(format!(
        "marty-didcomm-ca-smoke-{}.pem",
        uuid::Uuid::new_v4()
    ));
    assert!(!path.exists());
    let mut file_guard = None;
    for malformed in [false, true] {
        if malformed {
            let mut file = std::fs::File::create_new(&path).unwrap();
            file_guard = Some(OwnedFile(path.clone()));
            file.write_all(b"synthetic-invalid-ca").unwrap();
        }
        let (http_reservation, port) = reserve_port();
        let (_grpc_reservation, grpc_port) = reserve_port();
        let (database_denied, database_port) = reserve_port();
        database_denied.set_nonblocking(true).unwrap();
        let mut command = isolated_smoke_command(port, grpc_port);
        command.env("DIDCOMM_TLS_CA_FILE", &path).env(
            "DATABASE_URL",
            format!("postgres://synthetic@127.0.0.1:{database_port}/didcomm_ca_smoke"),
        );
        drop(http_reservation);
        let child = ChildGuard(
            command
                .spawn()
                .expect("start isolated issuance with deferred CA"),
        );
        let client = bounded_http_client(Duration::from_secs(2));
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(10),
                wait_for_health_with_client(port, &client)
            )
            .await
            .expect("bounded unrelated health readiness"),
            Some(json!({"status":"healthy", "service":"issuance-service"})),
        );
        drop(child);
        assert_eq!(
            database_denied.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    drop(file_guard);
    assert!(!path.exists(), "owned malformed CA cleanup");
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

/// Exercise main -> CanvasServices.with_operations -> router_with_all_services.
/// Authentication must finish before database access; this does not qualify the
/// authenticated lifecycle, provider effects, or gateway cutover.
#[tokio::test]
async fn executable_canvas_operations_preserve_auth_and_common_transport() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-canvas-operations.json"
    ))
    .unwrap();
    let routes = contract["routes"].as_array().unwrap();
    assert_eq!(routes.len(), 8);
    let (http_reservation, port) = reserve_port();
    let (_grpc_reservation, grpc_port) = reserve_port();
    // No PostgreSQL instance is needed or contacted. This owned listener never
    // accepts connections, and its empty accept queue is asserted after exit.
    let (database_denied, database_port) = reserve_port();
    database_denied.set_nonblocking(true).unwrap();
    let mut command = isolated_smoke_command(port, grpc_port);
    command
        .env("ISSUANCE_API_KEY", "synthetic-process-operations-key")
        .env(
            "DATABASE_URL",
            format!("postgres://synthetic@127.0.0.1:{database_port}/operations_auth_test"),
        );
    drop(http_reservation);
    let child = ChildGuard(command.spawn().expect("start actual issuance process"));
    let client = bounded_http_client(Duration::from_secs(2));
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(10),
            wait_for_health_with_client(port, &client)
        )
        .await
        .expect("bounded native process readiness"),
        Some(json!({"status":"healthy", "service":"issuance-service"}))
    );
    let base = format!("http://127.0.0.1:{port}");
    let mut covered = std::collections::BTreeSet::new();
    for (index, route) in routes.iter().enumerate() {
        let method = route["method"].as_str().unwrap();
        let path = route["path"]
            .as_str()
            .unwrap()
            .replace("{application_id}", "synthetic-application")
            .replace("{job_id}", "synthetic-job")
            .replace("{review_id}", "synthetic-review");
        assert!(!path.contains(['{', '}']));
        assert!(covered.insert((method.to_owned(), path.clone())));
        for wrong_key in [false, true] {
            let request_id = format!("operations-auth-{index}-{wrong_key}");
            let mut request = client
                .request(
                    method.parse().unwrap(),
                    format!("{base}{}{path}", contract["route_prefix"].as_str().unwrap()),
                )
                .header("origin", "https://wallet.example")
                .header("x-request-id", &request_id)
                .header("x-organization-id", "synthetic-organization");
            if method == "POST" {
                // Valid JSON avoids exercising the separate pre-auth syntax
                // error path on review resolution.
                request = request.json(&json!({"action":"dismiss"}));
            }
            if wrong_key {
                request = request.header("x-api-key", "synthetic-wrong-key");
            }
            let response = request.send().await.expect("owned process auth response");
            assert_eq!(response.status(), 401, "route {index}");
            assert_eq!(response.headers()["x-request-id"], request_id.as_str());
            assert_eq!(
                response.headers()["access-control-allow-origin"],
                "https://wallet.example"
            );
            assert_eq!(
                response.headers()["access-control-allow-credentials"],
                "true"
            );
            assert_eq!(response.headers()["vary"], "Origin");
            assert_eq!(
                response.json::<Value>().await.unwrap(),
                json!({"detail": if wrong_key { "Invalid API Key" } else { "X-API-Key header is missing" }})
            );
        }
    }
    assert_eq!(covered.len(), 8);
    let missing = client
        .get(format!(
            "{base}/v1/integrations/canvas/synthetic-unregistered-route"
        ))
        .header("x-api-key", "synthetic-process-operations-key")
        .header("origin", "https://wallet.example")
        .header("x-request-id", "operations-negative-route")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
    assert_eq!(
        missing.headers()["x-request-id"],
        "operations-negative-route"
    );
    assert_eq!(
        missing.headers()["access-control-allow-origin"],
        "https://wallet.example"
    );
    drop(child);
    assert_eq!(
        database_denied.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "auth-only process must not contact PostgreSQL"
    );
}
