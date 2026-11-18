//! Real PostgreSQL regressions. Explicitly ignored, never a successful no-op
//! when a database is absent. Use an owned loopback database named
//! `marty_offline_audit_test...` and OFFLINE_AUDIT_POSTGRES_TEST_URL.
use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use chrono::{Duration, Utc};
use marty_organization::{
    migration::{migrate_organization_schema, validate_organization_schema},
    organization_core_router,
    postgres::PostgresOrganizationStore,
    ApiKey, ApiKeySpec, OrganizationApplication, OrganizationCache, OrganizationHttpState,
};
use mmf_data::MemoryCache;
use mmf_security::ServiceTokenAuthenticator;
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tower::ServiceExt;
use uuid::Uuid;

const TOKEN: &str = "offline-audit-postgres-service-token-0001";

fn database_url() -> String {
    let raw = std::env::var("OFFLINE_AUDIT_POSTGRES_TEST_URL")
        .expect("explicit isolated PostgreSQL URL is required");
    let url = url::Url::parse(&raw).expect("PostgreSQL URL");
    assert!(matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]")
    ));
    assert!(
        url.path().starts_with("/marty_offline_audit_test"),
        "refusing an unowned test database name"
    );
    raw
}

fn router(pool: PgPool) -> axum::Router {
    let cache = OrganizationCache::new(
        Arc::new(MemoryCache::default()),
        Arc::new(MemoryCache::default()),
        Arc::new(MemoryCache::default()),
    );
    let application =
        OrganizationApplication::new(PostgresOrganizationStore::new(pool), cache).unwrap();
    organization_core_router(OrganizationHttpState {
        application: Arc::new(application),
        service_authenticator: Arc::new(
            ServiceTokenAuthenticator::new(Some(TOKEN.into()), true).unwrap(),
        ),
        organization_creation_enabled: false,
        marty_organization_id: None,
    })
}

async fn fixture() -> (PgPool, Uuid, ApiKey) {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url())
        .await
        .unwrap();
    migrate_organization_schema(&pool).await.unwrap();
    migrate_organization_schema(&pool).await.unwrap();
    validate_organization_schema(&pool).await.unwrap();
    let org = Uuid::new_v4();
    sqlx::query("INSERT INTO organization_service.organizations(id,name,status,created_at,updated_at) VALUES($1,$2,'active',now(),now())")
        .bind(org).bind(format!("offline-audit-test-{org}")).execute(&pool).await.unwrap();
    let key = create_key(&pool, org, vec!["audit:write".into()]).await;
    (pool, org, key)
}

async fn create_key(pool: &PgPool, org: Uuid, scopes: Vec<String>) -> ApiKey {
    let (key, _) = ApiKey::create(
        ApiKeySpec {
            organization_id: org,
            name: "offline-audit-test".into(),
            created_by: "isolated-test".into(),
            scopes: Some(scopes),
            description: None,
            expires_at: Some(Utc::now() + Duration::hours(1)),
            now: Utc::now(),
        },
        true,
    );
    PostgresOrganizationStore::new(pool.clone())
        .save_api_key(&key)
        .await
        .unwrap();
    key
}

fn event() -> Value {
    let mut value = serde_json::from_str::<Value>(include_str!(
        "../../../../contracts/offline-verification-ingest.json"
    ))
    .unwrap()["native_request"]["events"][0]
        .clone();
    value["event_id"] = json!(Uuid::new_v4());
    value["payload"]["verification_id"] = json!(Uuid::new_v4());
    value["timestamp"] = json!(Utc::now());
    value
}

fn base(org: Uuid) -> String {
    format!("/v1/organizations/{org}/offline-verification-events")
}

async fn request(
    app: axum::Router,
    method: &str,
    path: &str,
    key: &ApiKey,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("x-service-token", TOKEN)
        .header("x-user-id", format!("api_key:{}", key.id))
        .header("x-api-key-id", key.id.to_string())
        .header("x-organization-id", key.organization_id.to_string())
        .header("x-required-permission", "audit:ingest")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let body =
        serde_json::from_slice(&to_bytes(response.into_body(), 131072).await.unwrap()).unwrap();
    (status, body)
}

async fn retire(pool: &PgPool, org: Uuid) {
    sqlx::query("DELETE FROM organization_service.organizations WHERE id=$1")
        .bind(org)
        .execute(pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL"]
async fn offline_audit_commits_receipts_survives_reconnect_and_deduplicates_concurrent_replay() {
    let (pool, org, key) = fixture().await;
    let app = router(pool.clone());
    let value = event();
    let path = base(org);
    let receipt_path = format!(
        "{path}/{}",
        value["payload"]["verification_id"].as_str().unwrap()
    );
    assert_eq!(
        request(app.clone(), "GET", &receipt_path, &key, Value::Null)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let body = json!({"events":[value]});
    let (a, b) = tokio::join!(
        request(app.clone(), "POST", &path, &key, body.clone()),
        request(app.clone(), "POST", &path, &key, body)
    );
    assert_eq!((a.0, b.0), (StatusCode::OK, StatusCode::OK));
    assert_eq!(
        a.1["accepted"].as_u64().unwrap() + b.1["accepted"].as_u64().unwrap(),
        1
    );
    assert_eq!(
        a.1["duplicates"].as_u64().unwrap() + b.1["duplicates"].as_u64().unwrap(),
        1
    );
    assert_eq!(a.1["receipts"], b.1["receipts"]);
    let receipt = a.1["receipts"][0].clone();
    let row_count:i64 = sqlx::query_scalar("SELECT count(*) FROM organization_service.audit_events WHERE organization_id=$1 AND event_type='offline_verification.reported'")
        .bind(org).fetch_one(&pool).await.unwrap();
    assert_eq!(row_count, 1);
    drop(app);
    pool.close().await;
    let reopened = PgPoolOptions::new().connect(&database_url()).await.unwrap();
    let (status, readback) = request(
        router(reopened.clone()),
        "GET",
        &receipt_path,
        &key,
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(readback, receipt);
    assert_eq!(readback["organization_id"], org.to_string());
    assert_eq!(readback["producer_id"], key.id.to_string());
    retire(&reopened, org).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL"]
async fn offline_audit_conflicting_event_or_verification_ids_roll_back_the_entire_batch() {
    let (pool, org, key) = fixture().await;
    let app = router(pool.clone());
    let original = event();
    let path = base(org);
    let (_, accepted) = request(
        app.clone(),
        "POST",
        &path,
        &key,
        json!({"events":[original.clone()]}),
    )
    .await;
    assert_eq!(accepted["accepted"], 1);
    for replacement in ["payload", "event_id", "verification_id"] {
        let mut changed = original.clone();
        match replacement {
            "payload" => changed["payload"]["result"] = json!("invalid"),
            "event_id" => changed["event_id"] = json!(Uuid::new_v4()),
            _ => changed["payload"]["verification_id"] = json!(Uuid::new_v4()),
        }
        let new = event();
        let absent = format!(
            "{path}/{}",
            new["payload"]["verification_id"].as_str().unwrap()
        );
        assert_eq!(
            request(
                app.clone(),
                "POST",
                &path,
                &key,
                json!({"events":[new,changed]})
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            request(app.clone(), "GET", &absent, &key, Value::Null)
                .await
                .0,
            StatusCode::NOT_FOUND
        );
    }
    let receipt_path = format!(
        "{path}/{}",
        original["payload"]["verification_id"].as_str().unwrap()
    );
    assert_eq!(
        request(app.clone(), "GET", &receipt_path, &key, Value::Null)
            .await
            .1,
        accepted["receipts"][0]
    );
    retire(&pool, org).await;
}

#[tokio::test]
#[ignore = "requires explicitly owned loopback PostgreSQL"]
async fn offline_audit_rechecks_key_scope_expiry_revocation_profile_and_read_ownership() {
    let (pool, org, key) = fixture().await;
    let app = router(pool.clone());
    let path = base(org);
    let original = event();
    assert_eq!(
        request(
            app.clone(),
            "POST",
            &path,
            &key,
            json!({"events":[original.clone()]})
        )
        .await
        .0,
        StatusCode::OK
    );
    let receipt_path = format!(
        "{path}/{}",
        original["payload"]["verification_id"].as_str().unwrap()
    );
    let other_key = create_key(&pool, org, vec!["audit:write".into()]).await;
    assert_eq!(
        request(app.clone(), "GET", &receipt_path, &other_key, Value::Null)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    for reuse in ["both", "event_id", "verification_id"] {
        let mut duplicate = original.clone();
        if reuse == "event_id" {
            duplicate["payload"]["verification_id"] = json!(Uuid::new_v4());
        }
        if reuse == "verification_id" {
            duplicate["event_id"] = json!(Uuid::new_v4());
        }
        assert_eq!(
            request(
                app.clone(),
                "POST",
                &path,
                &other_key,
                json!({"events":[duplicate]})
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
    }
    let concurrent = event();
    let batch = json!({"events":[concurrent]});
    let (a, b) = tokio::join!(
        request(app.clone(), "POST", &path, &key, batch.clone()),
        request(app.clone(), "POST", &path, &other_key, batch)
    );
    assert!(
        (a.0 == StatusCode::OK && b.0 == StatusCode::CONFLICT)
            || (b.0 == StatusCode::OK && a.0 == StatusCode::CONFLICT)
    );
    let count:i64 = sqlx::query_scalar("SELECT count(*) FROM organization_service.audit_events WHERE organization_id=$1 AND event_type='offline_verification.reported'")
        .bind(org).fetch_one(&pool).await.unwrap();
    assert_eq!(
        count, 2,
        "cross-producer reuse must not create another accounting event"
    );
    let read_only = create_key(&pool, org, vec!["audit:read".into()]).await;
    assert_eq!(
        request(
            app.clone(),
            "POST",
            &path,
            &read_only,
            json!({"events":[event()]})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let other_org = Uuid::new_v4();
    assert_eq!(
        request(app.clone(), "GET", &base(other_org), &key, Value::Null)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    for update in [
        "UPDATE organization_service.api_keys SET expires_at=now()-interval '1 second' WHERE id=$1",
        "UPDATE organization_service.api_keys SET enabled=false WHERE id=$1",
        "UPDATE organization_service.api_keys SET status='revoked' WHERE id=$1",
        "UPDATE organization_service.api_keys SET scope_type='DEPLOYMENT_PROFILE' WHERE id=$1",
    ] {
        let candidate = create_key(&pool, org, vec!["audit:write".into()]).await;
        sqlx::query(update)
            .bind(candidate.id)
            .execute(&pool)
            .await
            .unwrap();
        for (method, body) in [("GET", Value::Null), ("POST", json!({"events":[event()]}))] {
            assert_eq!(
                request(app.clone(), method, &path, &candidate, body)
                    .await
                    .0,
                StatusCode::FORBIDDEN,
                "{update}"
            );
        }
    }
    retire(&pool, org).await;
}
