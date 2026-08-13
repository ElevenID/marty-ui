mod support;

use marty_revocation_profile::proto::{
    revocation_profile_service_client::RevocationProfileServiceClient, HealthCheckRequest,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{
    net::TcpListener as StdTcpListener,
    process::{Child, Command, Stdio},
    time::Duration,
};
use support::{start_organization_server, TOKEN};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::sleep,
};
use tonic::{metadata::MetadataValue, Request};
use uuid::Uuid;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct HttpResponse {
    status: u16,
    body: Value,
}

#[tokio::test]
#[ignore = "requires MARTY_TEST_POSTGRES_URL and MARTY_TEST_REDIS_URL"]
async fn executable_serves_http_grpc_and_operational_contracts() {
    let database_url = std::env::var("MARTY_TEST_POSTGRES_URL").expect("test PostgreSQL URL");
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("test Redis URL");
    let pool = PgPool::connect(&database_url).await.unwrap();
    install_schema(&pool).await;

    let permissions = ["create", "view", "activate", "delete"]
        .into_iter()
        .map(|action| format!("revocation-profile:{action}"))
        .collect();
    let (organization_target, organization_shutdown) =
        start_organization_server(true, permissions).await;
    let http_port = available_port();
    let grpc_port = available_port();
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_marty-revocation-profile"))
            .env("ENVIRONMENT", "beta")
            .env("DATABASE_URL", &database_url)
            .env("REDIS_URL", &redis_url)
            .env("ORG_GRPC_TARGET", &organization_target)
            .env("GRPC_SERVICE_TOKEN", TOKEN)
            .env_remove("GRPC_SERVICE_TOKEN_FILE")
            .env("REVOCATION_PROFILE_SERVICE_PORT", http_port.to_string())
            .env("RP_GRPC_PORT", grpc_port.to_string())
            .env("RP_GRPC_ENABLED", "true")
            .env("STATUS_LIST_BASE_URL", "https://status.contract.test")
            .env("MARTY_RELEASE_VERSION", "runtime-contract")
            .env("MARTY_UI_SHA", "runtime-contract-sha")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start revocation-profile executable"),
    );

    wait_for_http(http_port, &mut child.0).await;

    let health = http_request(http_port, "GET", "/health", &[], None).await;
    assert_eq!(health.status, 200);
    assert_eq!(health.body["status"], "healthy");

    let ready = http_request(http_port, "GET", "/ready", &[], None).await;
    assert_eq!(ready.status, 200, "{}", ready.body);
    assert_eq!(ready.body["components"]["postgres"], true);
    assert_eq!(ready.body["components"]["redis"], true);
    assert_eq!(ready.body["components"]["organization"], true);

    let diagnostics = http_request(http_port, "GET", "/health/native-backend", &[], None).await;
    assert_eq!(diagnostics.status, 200);
    assert_eq!(diagnostics.body["backend"], "marty-status-rust");
    assert_eq!(diagnostics.body["release_version"], "runtime-contract");
    assert_eq!(diagnostics.body["build_revision"], "runtime-contract-sha");

    let organization_id = format!("org-runtime-{}", Uuid::new_v4());
    let create_body = json!({
        "organization_id": organization_id,
        "name": "runtime contract",
        "revocation_mechanism": ["BITSTRING_STATUS_LIST"]
    });
    let missing_identity = http_request(
        http_port,
        "POST",
        "/v1/revocation-profiles",
        &[],
        Some(&create_body),
    )
    .await;
    assert_eq!(missing_identity.status, 401);

    let created = http_request(
        http_port,
        "POST",
        "/v1/revocation-profiles",
        &[("x-user-id", "user-runtime")],
        Some(&create_body),
    )
    .await;
    assert_eq!(created.status, 200, "{}", created.body);
    assert_eq!(created.body["organization_id"], organization_id);
    let profile_id = created.body["id"].as_str().unwrap().to_string();

    let listed = http_request(
        http_port,
        "GET",
        &format!("/v1/revocation-profiles?organization_id={organization_id}"),
        &[("x-user-id", "user-runtime")],
        None,
    )
    .await;
    assert_eq!(listed.status, 200, "{}", listed.body);
    assert_eq!(listed.body.as_array().unwrap().len(), 1);
    assert_eq!(listed.body[0]["id"], profile_id);

    let endpoint = format!("http://127.0.0.1:{grpc_port}");
    let mut grpc = connect_grpc(&endpoint).await;
    let error = grpc
        .health_check(Request::new(HealthCheckRequest {}))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unauthenticated);

    let mut request = Request::new(HealthCheckRequest {});
    request
        .metadata_mut()
        .insert("x-service-token", MetadataValue::try_from(TOKEN).unwrap());
    let response = grpc.health_check(request).await.unwrap().into_inner();
    assert_eq!(response.status, "serving");

    sqlx::query(
        "DELETE FROM revocation_profile_service.revocation_profiles WHERE organization_id = $1",
    )
    .bind(&organization_id)
    .execute(&pool)
    .await
    .unwrap();
    drop(child);
    let _ = organization_shutdown.send(());
}

fn available_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_for_http(port: u16, child: &mut Child) {
    for _ in 0..100 {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("revocation-profile exited before becoming healthy: {status}");
        }
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("revocation-profile did not become healthy");
}

async fn connect_grpc(target: &str) -> RevocationProfileServiceClient<tonic::transport::Channel> {
    for _ in 0..50 {
        if let Ok(client) = RevocationProfileServiceClient::connect(target.to_string()).await {
            return client;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("revocation-profile gRPC listener did not become available");
}

async fn http_request(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&Value>,
) -> HttpResponse {
    let body = body.map(Value::to_string).unwrap_or_default();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if !body.is_empty() {
        request.push_str("Content-Type: application/json\r\n");
    }
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(&body);

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    let status = head
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    HttpResponse {
        status,
        body: serde_json::from_str(body).unwrap(),
    }
}

async fn install_schema(pool: &PgPool) {
    let mut transaction = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('revocation_profile_service')::bigint)")
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query("CREATE SCHEMA IF NOT EXISTS revocation_profile_service")
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS revocation_profile_service.revocation_profiles (
            id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft',
            issuer_config JSONB NOT NULL DEFAULT '{}'::jsonb,
            verifier_config JSONB NOT NULL DEFAULT '{}'::jsonb,
            automation_config JSONB NOT NULL DEFAULT '{}'::jsonb,
            supported_formats JSONB NOT NULL DEFAULT '[]'::jsonb,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
    )
    .execute(&mut *transaction)
    .await
    .unwrap();
    transaction.commit().await.unwrap();
}
