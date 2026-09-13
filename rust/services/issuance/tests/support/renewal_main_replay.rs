//! Packaged main wiring and historical ordinary reservation recovery, not fresh
//! delivery proof. The organization peer deliberately returns 503, preserving
//! the existing best-effort admission rule; every other dependency is forbidden.
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use marty_issuance_service::{
    credential::CredentialTransactionStatus, credential_postgres::PostgresCredentialRepository,
    initiation::InitiationRepository,
};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool};

use super::renewal_reference_fixture as reference;
use super::{
    didcomm_gateway_replay::OwnedHttp,
    issuance_process::{
        bounded_http_client, isolated_smoke_command, reserve_port, wait_for_health_with_client,
        ChildGuard,
    },
};

const ORGANIZATION: &str = "synthetic-org";
const SOURCE: &str = "synthetic-source-credential";
const API_KEY: &str = "synthetic-renewal-main-management";
const TOKEN: &str = "synthetic-renewal-main-service-token-32";
const KEY: &str = "synthetic-renewal-key";

async fn snapshot(pool: &PgPool) -> Value {
    sqlx::query_scalar("SELECT jsonb_build_object(
      'transactions',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id),'[]') FROM issuance_service.issuance_transactions t WHERE organization_id=$1),
      'credentials',(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY id),'[]') FROM issuance_service.issued_credentials c WHERE organization_id=$1),
      'deliveries',(SELECT COALESCE(jsonb_agg(to_jsonb(d) ORDER BY id),'[]') FROM issuance_service.credential_delivery_records d WHERE organization_id=$1),
      'events',(SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY id),'[]') FROM issuance_service.issuance_events e WHERE transaction_id IN (SELECT id FROM issuance_service.issuance_transactions WHERE organization_id=$1)))")
      .bind(ORGANIZATION).fetch_one(pool).await.unwrap()
}

pub(super) async fn run(database_url: &str) {
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(database_url)
        .await
        .unwrap();
    let repository =
        PostgresCredentialRepository::new(pool.clone(), b"synthetic-renewal-main-hmac");
    let corpus = reference::corpus();
    let case = reference::case(&corpus, "ordinary-keyed-retry");
    let frozen = reference::snapshot(&corpus, case, "after_first");
    for row in frozen["transactions"].as_array().unwrap() {
        let mut transaction = reference::transaction(row);
        if transaction.id == "synthetic-source-transaction" {
            transaction.status = CredentialTransactionStatus::Issued;
        }
        let reserved = repository.reserve_idempotently(&transaction).await.unwrap();
        assert!(reserved.created);
        assert_eq!(reserved.transaction, transaction);
    }
    let source = reference::source(frozen).unwrap();
    sqlx::query("INSERT INTO issuance_service.issued_credentials
      (id,transaction_id,organization_id,credential_template_id,applicant_id,subject_did,issuer_did,
       credential_jwt,credential_hash,status,status_updated_at,revoked,issued_at,expires_at)
      VALUES($1,$2,$3,$4,$5,$6,'did:example:renewal-issuer','synthetic-historical-source','synthetic-source-hash','active','2023-11-01T00:00:00Z',false,'2023-11-01T00:00:00Z',$7)")
      .bind(SOURCE).bind(&source.transaction_id).bind(ORGANIZATION).bind(&source.credential_template_id)
      .bind(&source.applicant_id).bind(&source.subject_did).bind(source.expires_at).execute(&pool).await.unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let observed = calls.clone();
    let peer = OwnedHttp::start(Router::new().fallback(move |request: Request<Body>| {
        let observed = observed.clone();
        async move {
            observed
                .lock()
                .unwrap()
                .push(request.uri().path().to_owned());
            assert_eq!(request.method(), "POST");
            assert_eq!(
                request.uri().path(),
                "/marty.ui.organization.v1.OrganizationService/GetOrganization"
            );
            assert_eq!(request.headers()["x-service-token"], TOKEN);
            let bytes = to_bytes(request.into_body(), 4096).await.unwrap();
            assert!(!bytes.is_empty());
            StatusCode::SERVICE_UNAVAILABLE
        }
    }))
    .await;
    let origin = format!("http://127.0.0.1:{}", peer.port);
    let (http_listener, http_port) = reserve_port();
    let (grpc_listener, grpc_port) = reserve_port();
    let mut command = isolated_smoke_command(http_port, grpc_port);
    command
        .env("DATABASE_URL", database_url)
        .env("ISSUANCE_API_KEY", API_KEY)
        .env("GRPC_SERVICE_TOKEN", TOKEN)
        .env("TOKEN_HMAC_KEY", "synthetic-renewal-main-hmac")
        .env("ORG_GRPC_TARGET", &origin)
        .env("CT_GRPC_TARGET", &origin)
        .env("RP_GRPC_TARGET", &origin)
        .env("CREDENTIAL_TEMPLATE_SERVICE_URL", &origin)
        .env("REVOCATION_PROFILE_SERVICE_URL", &origin)
        .env("SIGNING_KEYS_INTERNAL_URL", &origin)
        .env(
            "ISSUANCE_OFFER_TTL_MINUTES",
            "999999999999999999999999999999",
        );
    drop((http_listener, grpc_listener));
    let mut child = ChildGuard(command.spawn().unwrap());
    let client = bounded_http_client(Duration::from_secs(10));
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(10),
            wait_for_health_with_client(http_port, &client)
        )
        .await
        .unwrap(),
        Some(json!({"status":"healthy","service":"issuance-service"}))
    );
    let url = format!("http://127.0.0.1:{http_port}/v1/issued-credentials/{SOURCE}/renew");
    let initial = snapshot(&pool).await;
    for (key, tenant, status, detail) in [
        (None, Some(ORGANIZATION), 401, "X-API-Key header is missing"),
        (Some("wrong"), Some(ORGANIZATION), 401, "Invalid API Key"),
        (
            Some(API_KEY),
            None,
            403,
            "Trusted organization context is required",
        ),
        (
            Some(API_KEY),
            Some("foreign-org"),
            404,
            "Resource not found",
        ),
    ] {
        let mut request = client.post(&url);
        if let Some(key) = key {
            request = request.header("x-api-key", key);
        }
        if let Some(tenant) = tenant {
            request = request.header("x-organization-id", tenant);
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(
            response.json::<Value>().await.unwrap(),
            json!({"detail":detail})
        );
        assert!(calls.lock().unwrap().is_empty());
        assert_eq!(snapshot(&pool).await, initial);
    }
    for expected_count in 1..=2 {
        let response = client
            .post(&url)
            .header("x-api-key", API_KEY)
            .header("x-organization-id", ORGANIZATION)
            .header("idempotency-key", KEY)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.json::<Value>().await.unwrap(),
            case["responses"][0]["body"]
        );
        assert_eq!(calls.lock().unwrap().len(), expected_count);
        assert_eq!(
            snapshot(&pool).await,
            initial,
            "recovery keeps complete stored identity/expiry and has no delivery effects"
        );
    }
    sqlx::query("UPDATE issuance_service.issuance_transactions SET claims = (claims::jsonb || '{\"changed\":true}'::jsonb)::json WHERE id='synthetic-source-transaction' AND organization_id=$1")
      .bind(ORGANIZATION).execute(&pool).await.unwrap();
    let before_conflict = snapshot(&pool).await;
    let response = client
        .post(&url)
        .header("x-api-key", API_KEY)
        .header("x-organization-id", ORGANIZATION)
        .header("idempotency-key", KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        response.json::<Value>().await.unwrap(),
        reference::case(&corpus, "ordinary-keyed-conflict")["responses"][1]["body"]
    );
    assert_eq!(calls.lock().unwrap().len(), 3);
    assert_eq!(snapshot(&pool).await, before_conflict);
    assert!(child.0.try_wait().unwrap().is_none());
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    peer.close().await;
    pool.close().await;
}
