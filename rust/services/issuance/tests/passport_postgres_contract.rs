use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, Request, StatusCode},
    routing::{get, post},
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use chrono::{TimeZone, Utc};
use marty_issuance_service::config::IssuanceServiceConfig;
use marty_issuance_service::migration;
use marty_issuance_service::passport_artifact::PassportSensitiveArtifact;
use marty_issuance_service::passport_artifact_kms::KmsPassportArtifactCipher;
use marty_issuance_service::passport_beta_material::PassportBetaMaterialDigests;
use marty_issuance_service::passport_bureau::{BetaBatchWireCommitments, BureauClient};
use marty_issuance_service::passport_http::{router as passport_router, PassportHttpService};
use marty_issuance_service::passport_provider_ingress::{
    router as provider_ingress_router, ProviderIngressState,
};
use marty_issuance_service::passport_repository::{
    PassportBatchIdentity, PassportBetaBatchBinding, PassportBetaBatchDestination,
    PassportJobInsert, PassportJobPatch, PassportJobStatus, PassportSubmissionReservation,
    PostgresPassportRepository,
};
use marty_issuance_service::passport_signer::{ManagedProfileSigner, PassportSigner};
use marty_passport_auth::PassportTenantKeyring;
use marty_signing_grant::SigningOrigin;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use tokio::sync::{oneshot, Barrier};
use tower::ServiceExt;

<<<<<<< HEAD
// Reuse the session-scoped test helper shared with the Flow schema-reset tests.
#[path = "../../flow/tests/support/flow_schema.rs"]
mod shared_schema_lock;

#[tokio::test]
async fn readonly_passport_job_get_is_tenant_scoped_and_has_no_side_effects() {
    let Ok(database_url) = std::env::var("MARTY_PASSPORT_POSTGRES_TEST_URL") else {
        eprintln!("explicit disposable PostgreSQL URL required for actual readback proof");
        return;
    };
    let parsed = url::Url::parse(&database_url).unwrap();
    assert!(matches!(parsed.host_str(), Some("127.0.0.1" | "localhost")));
    assert_eq!(parsed.path(), "/marty_passport_contract_test");
    let _schema_guard =
        shared_schema_lock::lock_shared_test_schemas(&database_url.parse().unwrap())
            .await
            .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .unwrap();
    sqlx::query("DROP SCHEMA IF EXISTS issuance_service CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    migration::migrate_passport(&pool).await.unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let mock = Router::new().fallback(move || {
        let counter = counter.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
    let ring = PassportTenantKeyring::from_json(&format!(
        "{{\"org-a\":\"{}\",\"org-b\":\"{}\"}}",
        "a".repeat(32),
        "b".repeat(32)
    ))
    .unwrap();
    let principal = ring
        .authenticate(Some("org-a"), Some(&"a".repeat(32)))
        .unwrap();
    let repository = PostgresPassportRepository::new(pool.clone());
    // A counting bureau is configured, while no KMS/decrypt/signer exists.
    // Deliberately undecryptable test custody must never be opened by this GET.
    let app = passport_router(PassportHttpService::new(
        ring,
        repository.clone(),
        None,
        None,
        Some(BureauClient::new(&base, "synthetic-bureau-key").unwrap()),
    ));
    for status in [
        "DRAFT",
        "SOD_SIGNED",
        "SUBMITTED",
        "READY_FOR_ACTIVATION",
        "ACTIVE",
        "FAILED",
        "CANCELLED",
    ] {
        let id = uuid::Uuid::new_v4().to_string();
        let application = uuid::Uuid::new_v4().to_string();
        repository
            .insert(
                &principal,
                &PassportJobInsert {
                    id: id.clone(),
                    application_id: application.clone(),
                    flow_execution_id: "owned-read-flow".into(),
                    application_template_id: "synthetic-application".into(),
                    credential_template_id: "synthetic-credential".into(),
                    revocation_profile_id: None,
                    delivery_destination_profile_id: "synthetic-destination".into(),
                    document_type: "P".into(),
                    country_code: "UTO".into(),
                    issuer_did: None,
                    secure_artifact_ciphertext: "must-not-decrypt-test-custody".into(),
                    secure_artifact_reference: "opaque-public-test-reference".into(),
                },
                Utc::now(),
            )
            .await
            .unwrap();
        sqlx::query("UPDATE issuance_service.physical_document_jobs SET status=$2,bureau_job_id=$3 WHERE id=$1")
            .bind(&id).bind(status).bind(format!("bureau-{id}")).execute(&pool).await.unwrap();
        let before: Value = sqlx::query_scalar(
            "SELECT to_jsonb(job) FROM issuance_service.physical_document_jobs job WHERE id=$1",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();
        for (organization, key, expected) in [
            (Some("org-a"), Some("a".repeat(32)), StatusCode::OK),
            (Some("org-b"), Some("b".repeat(32)), StatusCode::NOT_FOUND),
            (Some("org-a"), None, StatusCode::UNAUTHORIZED),
            (None, Some("a".repeat(32)), StatusCode::UNAUTHORIZED),
        ] {
            let mut request =
                Request::builder().uri(format!("/v1/passport/applications/{application}"));
            if let Some(org) = organization {
                request = request.header("x-organization-id", org);
            }
            if let Some(key) = key {
                request = request.header("x-api-key", key);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            if expected == StatusCode::OK {
                let value: Value =
                    serde_json::from_slice(&to_bytes(response.into_body(), 32768).await.unwrap())
                        .unwrap();
                assert_eq!(value["id"], id);
                assert_eq!(value["status"], status);
                for sensitive in [
                    "secure_artifact_ciphertext",
                    "submission_intent_id",
                    "bureau_provider_profile_id",
                    "sod_sha256",
                ] {
                    assert!(value.get(sensitive).is_none(), "{sensitive}");
                }
            }
        }
        let after: Value = sqlx::query_scalar(
            "SELECT to_jsonb(job) FROM issuance_service.physical_document_jobs job WHERE id=$1",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(before, after, "read mutated {status} job");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "read contacted bureau for {status}"
        );
    }
    server.abort();
    let _ = server.await;
    pool.close().await;
}

=======
// Share the existing dedicated session lock for every passport schema reset.
#[path = "../../flow/tests/support/flow_schema.rs"]
mod shared_schema_lock;

>>>>>>> fix/passport-administrative-cancellation
/// The companion SQL fixture provisions an isolated cluster using the actual
/// finalizer. Explicit invocation prevents an absent URL becoming pass evidence.
#[tokio::test]
#[ignore = "requires uniquely owned disposable fenced-role PostgreSQL fixture"]
async fn fenced_cancellation_role_can_append_but_not_rewrite_history() {
    let database_url =
        std::env::var("PASSPORT_FENCED_APP_TEST_URL").expect("explicit owned fixture URL");
    let parsed = url::Url::parse(&database_url).unwrap();
    assert!(matches!(parsed.host_str(), Some("127.0.0.1" | "localhost")));
    assert_eq!(parsed.path(), "/marty");
    assert_eq!(parsed.username(), "marty");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .unwrap();
    let (actor, marker): (String, Option<String>) = sqlx::query_as(
        "SELECT current_user::text,current_setting('marty.disposable_test_owner',true)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(actor, "marty");
    assert_eq!(marker.as_deref(), Some("android-wallet-d12-role-fixture"));
    migration::validate_passport(&pool).await.unwrap();
    let ready: bool = sqlx::query_scalar("SELECT issuance_service.passport_cancellation_acl_ready() AND flow_service.physical_start_acl_ready()")
        .fetch_one(&pool).await.unwrap();
    assert!(ready);
    let ring =
        PassportTenantKeyring::from_json(&format!("{{\"org-fenced\":\"{}\"}}", "f".repeat(32)))
            .unwrap();
    let principal = ring
        .authenticate(Some("org-fenced"), Some(&"f".repeat(32)))
        .unwrap();
    let repository = PostgresPassportRepository::new(pool.clone());
    let id = uuid::Uuid::new_v4().to_string();
    let application = uuid::Uuid::new_v4().to_string();
    repository
        .insert(
            &principal,
            &PassportJobInsert {
                id: id.clone(),
                application_id: application.clone(),
                flow_execution_id: "fenced-role-only".into(),
                application_template_id: "synthetic-application".into(),
                credential_template_id: "synthetic-credential".into(),
                revocation_profile_id: None,
                delivery_destination_profile_id: "synthetic-destination".into(),
                document_type: "P".into(),
                country_code: "UTO".into(),
                issuer_did: None,
                secure_artifact_ciphertext: "opaque-non-document-test-custody".into(),
                secure_artifact_reference: "synthetic-only".into(),
            },
            Utc::now(),
        )
        .await
        .unwrap();
    let app = passport_router(PassportHttpService::new(ring, repository, None, None, None));
    let request = Request::builder().method("POST")
        .uri(format!("/v1/passport/applications/{application}/cancel"))
        .header("content-type","application/json").header("x-organization-id","org-fenced")
        .header("x-api-key","f".repeat(32)).header("idempotency-key","fenced-role-cancel")
        .body(Body::from(json!({"expected_job_id":id,"reason_code":"ADMINISTRATIVE_ABANDONMENT","reason":"isolated actual-role permission test"}).to_string())).unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM issuance_service.passport_job_administrative_cancellations WHERE job_id=$1")
        .bind(&id).fetch_one(&pool).await.unwrap();
    assert_eq!(count, 1);
    // These must fail on app privileges, independently of immutable-row triggers.
    for statement in [
        "UPDATE issuance_service.passport_job_administrative_cancellations SET reason='changed'",
        "DELETE FROM issuance_service.passport_job_administrative_cancellations",
        "TRUNCATE issuance_service.passport_job_administrative_cancellations",
        "CREATE TRIGGER forbidden_history_trigger BEFORE INSERT ON issuance_service.passport_job_administrative_cancellations FOR EACH ROW EXECUTE FUNCTION issuance_service.guard_passport_cancellation_history()",
        "ALTER TABLE issuance_service.passport_job_administrative_cancellations OWNER TO marty",
        "CREATE TABLE issuance_service.forbidden_app_ddl(id integer)",
    ] {
        let error = sqlx::raw_sql(statement).execute(&pool).await.unwrap_err();
        assert_eq!(error.as_database_error().and_then(|error| error.code()).as_deref(),Some("42501"),"{statement}: {error}");
    }
    let owner: String = sqlx::query_scalar("SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='issuance_service.passport_job_administrative_cancellations'::regclass")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(owner, "marty_passport_fence_owner");
    let admin_url =
        std::env::var("PASSPORT_FENCED_FIXTURE_ADMIN_TEST_URL").expect("owned fixture admin URL");
    let admin_parsed = url::Url::parse(&admin_url).unwrap();
    assert_eq!(admin_parsed.host_str(), parsed.host_str());
    assert_eq!(
        admin_parsed.port_or_known_default(),
        parsed.port_or_known_default()
    );
    assert_eq!(admin_parsed.path(), "/marty");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .unwrap();
    let admin_marker: Option<String> =
        sqlx::query_scalar("SELECT current_setting('marty.disposable_test_owner',true)")
            .fetch_one(&admin)
            .await
            .unwrap();
    assert_eq!(
        admin_marker.as_deref(),
        Some("android-wallet-d12-role-fixture")
    );
    assert!(
        migration::validate_passport(&admin).await.is_err(),
        "fenced non-marty application startup must refuse"
    );
    for (tamper,restore) in [
        ("GRANT UPDATE ON issuance_service.passport_job_administrative_cancellations TO marty", "REVOKE UPDATE ON issuance_service.passport_job_administrative_cancellations FROM marty"),
        ("GRANT UPDATE(reason) ON issuance_service.passport_job_administrative_cancellations TO marty", "REVOKE UPDATE(reason) ON issuance_service.passport_job_administrative_cancellations FROM marty"),
        ("GRANT SELECT ON issuance_service.passport_job_administrative_cancellations TO PUBLIC", "REVOKE SELECT ON issuance_service.passport_job_administrative_cancellations FROM PUBLIC"),
        ("ALTER TABLE issuance_service.passport_job_administrative_cancellations OWNER TO marty", "ALTER TABLE issuance_service.passport_job_administrative_cancellations OWNER TO marty_passport_fence_owner; GRANT SELECT,INSERT ON issuance_service.passport_job_administrative_cancellations TO marty"),
    ] {
        sqlx::raw_sql(tamper).execute(&admin).await.unwrap();
        let ready: bool = sqlx::query_scalar("SELECT issuance_service.passport_cancellation_acl_ready()")
            .fetch_one(&pool).await.unwrap();
        let validation = migration::validate_passport(&pool).await;
        // Restore before assertions so a regression does not strand widened ACLs.
        sqlx::raw_sql(restore).execute(&admin).await.unwrap();
        assert!(!ready,"changed ACL was accepted: {tamper}");
        assert!(validation.is_err(),"app startup accepted changed ACL: {tamper}");
        migration::validate_passport(&pool).await.unwrap();
    }
    admin.close().await;
    pool.close().await;
}

#[tokio::test]
async fn administrative_cancellation_preserves_history_and_closes_terminal_races() {
    let Ok(database_url) = std::env::var("MARTY_PASSPORT_POSTGRES_TEST_URL") else {
        eprintln!(
            "MARTY_PASSPORT_POSTGRES_TEST_URL required for actual cancellation PostgreSQL evidence"
        );
        return;
    };
    let parsed = url::Url::parse(&database_url).unwrap();
    assert!(matches!(parsed.host_str(), Some("127.0.0.1" | "localhost")));
    assert_eq!(parsed.path(), "/marty_passport_contract_test");
    let _schema_guard =
        shared_schema_lock::lock_shared_test_schemas(&database_url.parse().unwrap())
            .await
            .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(6)
        .connect(&database_url)
        .await
        .unwrap();
    sqlx::query("DROP SCHEMA IF EXISTS issuance_service CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    migration::migrate_passport(&pool).await.unwrap();
    migration::validate_passport(&pool).await.unwrap();
    // Catalog formatting may use platform newlines, never different SQL semantics.
    let cancellation_sql =
        include_str!("../migrations/0011_passport_administrative_cancellation.sql");
    let history_body = cancellation_sql
        .split("$cancellation_history_guard$")
        .nth(1)
        .unwrap();
    let newline_body = history_body.replace("\r\n", "\n").replace('\n', "\r\n");
    // Audited fixture DDL: body comes only from the embedded committed migration.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE OR REPLACE FUNCTION issuance_service.guard_passport_cancellation_history() RETURNS trigger LANGUAGE plpgsql AS $body${newline_body}$body$")))
        .execute(&pool).await.unwrap();
    migration::validate_passport(&pool).await.unwrap();
    for (name, wrong_definition) in [
        (
            "ck_passport_cancel_reason_code",
            "CHECK (reason_code = 'ADMINISTRATIVE ABANDONMENT')",
        ),
        (
            "ck_passport_cancel_key_hash",
            "CHECK (idempotency_key_hash ~ '^[0-9a-f] {64}$')",
        ),
    ] {
        let original: String = sqlx::query_scalar("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='issuance_service.passport_job_administrative_cancellations'::regclass AND conname=$1")
            .bind(name).fetch_one(&pool).await.unwrap();
        // Fixed local allowlist; no request-derived identifiers or definitions.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("ALTER TABLE issuance_service.passport_job_administrative_cancellations DROP CONSTRAINT {name}, ADD CONSTRAINT {name} {wrong_definition}")))
            .execute(&pool).await.unwrap();
        assert!(
            migration::validate_passport(&pool).await.is_err(),
            "quoted SQL content must remain significant: {name}"
        );
        // Restore only the catalog definition captured in this owned empty fixture.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("ALTER TABLE issuance_service.passport_job_administrative_cancellations DROP CONSTRAINT {name}, ADD CONSTRAINT {name} {original}")))
            .execute(&pool).await.unwrap();
        migration::validate_passport(&pool).await.unwrap();
    }
    let ring = PassportTenantKeyring::from_json(&format!(
        "{{\"org-a\":\"{}\",\"org-b\":\"{}\"}}",
        "a".repeat(32),
        "b".repeat(32),
    ))
    .unwrap();
    let principal = ring
        .authenticate(Some("org-a"), Some(&"a".repeat(32)))
        .unwrap();
    let repository = PostgresPassportRepository::new(pool.clone());
    // Cancellation needs no decrypt/sign/bureau provider. Dummy encrypted test
    // custody must remain byte-identical; it is not a usable document fixture.
    let app = passport_router(PassportHttpService::new(
        ring.clone(),
        repository.clone(),
        None,
        None,
        None,
    ));

    async fn seed(
        pool: &sqlx::PgPool,
        repository: &PostgresPassportRepository,
        principal: &marty_passport_auth::PassportTenantPrincipal,
        status: &str,
    ) -> (String, String) {
        let id = uuid::Uuid::new_v4().to_string();
        let application = uuid::Uuid::new_v4().to_string();
        repository
            .insert(
                principal,
                &PassportJobInsert {
                    id: id.clone(),
                    application_id: application.clone(),
                    flow_execution_id: "owned-flow".into(),
                    application_template_id: "owned-application-template".into(),
                    credential_template_id: "owned-credential-template".into(),
                    revocation_profile_id: None,
                    delivery_destination_profile_id: "owned-destination".into(),
                    document_type: "P".into(),
                    country_code: "USA".into(),
                    issuer_did: Some("did:web:test.example:issuer".into()),
                    secure_artifact_ciphertext: "opaque-original-ciphertext".into(),
                    secure_artifact_reference: "opaque-original-reference".into(),
                },
                Utc::now(),
            )
            .await
            .unwrap();
        sqlx::query("UPDATE issuance_service.physical_document_jobs SET status=$2, sod_sha256=$3,
            quality_result=$4,tracking_number='original-tracking',error_code='original-error',error_message='original-detail' WHERE id=$1")
            .bind(&id).bind(status).bind("a".repeat(64)).bind(json!({"passed":true,"checked_by":"original"}))
            .execute(pool).await.unwrap();
        (id, application)
    }
    fn request(
        application: &str,
        id: &str,
        organization: &str,
        key: &str,
        reason: &str,
    ) -> Request<Body> {
        Request::builder().method("POST").uri(format!("/v1/passport/applications/{application}/cancel"))
            .header("content-type","application/json").header("x-organization-id",organization)
            .header("x-api-key",if organization=="org-a" {"a".repeat(32)} else {"b".repeat(32)})
            .header("idempotency-key",key).header("x-user-id","untrusted-human-claim")
            .body(Body::from(json!({"expected_job_id":id,"reason_code":"ADMINISTRATIVE_ABANDONMENT","reason":reason}).to_string())).unwrap()
    }
    async fn body(response: axum::response::Response) -> Value {
        serde_json::from_slice(&to_bytes(response.into_body(), 32768).await.unwrap()).unwrap()
    }
    async fn snapshot(pool: &sqlx::PgPool, id: &str) -> Value {
        sqlx::query_scalar("SELECT to_jsonb(job)-'status'-'updated_at' FROM issuance_service.physical_document_jobs job WHERE id=$1")
            .bind(id).fetch_one(pool).await.unwrap()
    }
    let (id, application) = seed(&pool, &repository, &principal, "READY_FOR_ACTIVATION").await;
    sqlx::query("UPDATE issuance_service.physical_document_jobs SET bureau_job_id='owned-cancelled-bureau' WHERE id=$1").bind(&id).execute(&pool).await.unwrap();
    let original = snapshot(&pool, &id).await;
    for (org, expected_id) in [
        ("org-b", id.clone()),
        ("org-a", uuid::Uuid::new_v4().to_string()),
    ] {
        let denied = app
            .clone()
            .oneshot(request(
                &application,
                &expected_id,
                org,
                "owned-cancel-1",
                "End failed attempt",
            ))
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::NOT_FOUND);
    }
    let mut duplicate = request(
        &application,
        &id,
        "org-a",
        "owned-cancel-1",
        "End failed attempt",
    );
    duplicate
        .headers_mut()
        .append("idempotency-key", "other".parse().unwrap());
    assert_eq!(
        app.clone().oneshot(duplicate).await.unwrap().status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let malformed=app.clone().oneshot(Request::builder().method("POST")
        .uri(format!("/v1/passport/applications/{application}/cancel"))
        .header("content-type","application/json").header("x-organization-id","org-a")
        .header("x-api-key","a".repeat(32)).header("idempotency-key","owned-cancel-1")
        .body(Body::from(format!(r#"{{"expected_job_id":"{id}","expected_job_id":"{id}","reason_code":"ADMINISTRATIVE_ABANDONMENT","reason":"End failed attempt"}}"#))).unwrap()).await.unwrap();
    assert_eq!(malformed.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let cancelled = app
        .clone()
        .oneshot(request(
            &application,
            &id,
            "org-a",
            "owned-cancel-1",
            "End failed attempt",
        ))
        .await
        .unwrap();
    assert_eq!(cancelled.status(), StatusCode::OK);
    let first = body(cancelled).await;
    assert_eq!(first["job"]["status"], "CANCELLED");
    assert_eq!(first["bureau_cancellation_requested"], false);
    assert_eq!(first["flow_cancellation_requested"], false);
    assert_eq!(
        first["administrative_cancellation"]["actor_kind"],
        "AUTHENTICATED_PASSPORT_TENANT"
    );
    assert_eq!(
        first["administrative_cancellation"]["actor_organization_id"],
        "org-a"
    );
    assert_eq!(snapshot(&pool, &id).await, original);
    let replay = app
        .clone()
        .oneshot(request(
            &application,
            &id,
            "org-a",
            "owned-cancel-1",
            "End failed attempt",
        ))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    let replay = body(replay).await;
    assert_eq!(first["job"], replay["job"]);
    assert_eq!(
        first["administrative_cancellation"],
        replay["administrative_cancellation"]
    );
    assert_eq!(replay["replayed"], true);
    let conflict = app
        .clone()
        .oneshot(request(
            &application,
            &id,
            "org-a",
            "owned-cancel-1",
            "Different reason",
        ))
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM issuance_service.passport_job_administrative_cancellations WHERE job_id=$1").bind(&id).fetch_one(&pool).await.unwrap();
    assert_eq!(count, 1);
    assert!(repository
        .update(
            &principal,
            &application,
            "CANCELLED",
            &PassportJobPatch::new(PassportJobStatus::SodSigned),
            Utc::now()
        )
        .await
        .unwrap()
        .is_none());
    for mutation in [
        "UPDATE issuance_service.physical_document_jobs SET status='SOD_SIGNED' WHERE id=$1",
        "UPDATE issuance_service.physical_document_jobs SET secure_artifact_ciphertext='replacement' WHERE id=$1",
        "UPDATE issuance_service.physical_document_jobs SET quality_result='{\"passed\":false}'::json WHERE id=$1",
        "DELETE FROM issuance_service.physical_document_jobs WHERE id=$1",
        "UPDATE issuance_service.passport_job_administrative_cancellations SET reason='rewritten' WHERE job_id=$1",
        "DELETE FROM issuance_service.passport_job_administrative_cancellations WHERE job_id=$1",
    ] { assert!(sqlx::query(mutation).bind(&id).execute(&pool).await.is_err(),"{mutation}"); }
    for action in [
        "generate-data-groups",
        "generate-sod",
        "activate",
        "quality-verify",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/passport/applications/{application}/{action}"))
                    .header("x-organization-id", "org-a")
                    .header("x-api-key", "a".repeat(32))
                    .header("content-type", "application/json")
                    .body(Body::from("{\"passed\":true}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT, "{action}");
    }
    assert!(
        sqlx::query("TRUNCATE issuance_service.passport_job_administrative_cancellations")
            .execute(&pool)
            .await
            .is_err()
    );
    assert_eq!(snapshot(&pool, &id).await, original);
    let poll = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/passport/applications/{application}/production-status"
                ))
                .header("x-organization-id", "org-a")
                .header("x-api-key", "a".repeat(32))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(poll.status(), StatusCode::OK); // no bureau provider is installed
    assert_eq!(body(poll).await["status"], "CANCELLED");
    let kms = passport_mock_artifact_kms::start().await;
    let callback=serde_json::to_vec(&json!({"organization_id":"org-a","bureau_job_id":"owned-cancelled-bureau","status":"SHIPPED","metadata":{"tracking_number":"late-override"}})).unwrap();
    let event = kms.verified_callback(&callback).await;
    let unchanged = repository
        .apply_verified_webhook(&event, Utc::now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.status, "CANCELLED");
    assert_eq!(snapshot(&pool, &id).await, original);
    kms.server.abort();
    let (unsubmitted, unsubmitted_app) = seed(&pool, &repository, &principal, "DRAFT").await;
    let old_status = repository
        .get(&principal, &unsubmitted_app)
        .await
        .unwrap()
        .unwrap()
        .status;
    assert_eq!(
        app.clone()
            .oneshot(request(
                &unsubmitted_app,
                &unsubmitted,
                "org-a",
                "unsubmitted-cancel",
                "End failed attempt"
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    for action in ["generate-data-groups", "generate-sod"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/v1/passport/applications/{unsubmitted_app}/{action}"
                    ))
                    .header("x-organization-id", "org-a")
                    .header("x-api-key", "a".repeat(32))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            body(response).await["detail"],
            "Physical document job is terminal"
        );
    }
    assert!(repository
        .update(
            &principal,
            &unsubmitted_app,
            &old_status,
            &PassportJobPatch::new(PassportJobStatus::SodSigned),
            Utc::now()
        )
        .await
        .unwrap()
        .is_none());
    for status in ["ACTIVE", "FAILED"] {
        let (id, application) = seed(&pool, &repository, &principal, status).await;
        let response = app
            .clone()
            .oneshot(request(
                &application,
                &id,
                "org-a",
                "terminal-cancel",
                "End failed attempt",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
    let (reserved, reserved_app) = seed(&pool, &repository, &principal, "SOD_SIGNED").await;
    sqlx::query(
        "UPDATE issuance_service.physical_document_jobs SET submission_intent_id=$2,
        submission_intent_started_at=now(),submission_intent_bureau_endpoint_sha256=$3 WHERE id=$1",
    )
    .bind(&reserved)
    .bind(uuid::Uuid::new_v4())
    .bind("b".repeat(64))
    .execute(&pool)
    .await
    .unwrap();
    let response = app
        .clone()
        .oneshot(request(
            &reserved_app,
            &reserved,
            "org-a",
            "reserved-cancel",
            "End failed attempt",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    // Deterministic real row-lock ordering in both directions. This tests the
    // persistence race, not interruption of externally started KMS/bureau work.
    async fn wait_for_lock(pool: &sqlx::PgPool, name: &str) {
        for _ in 0..200 {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock')").bind(name).fetch_one(pool).await.unwrap();
            if waiting {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        panic!("owned race actor did not reach its row lock: {name}");
    }
    let cancellation_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            database_url
                .parse::<sqlx::postgres::PgConnectOptions>()
                .unwrap()
                .application_name("passport-cancel-race"),
        )
        .await
        .unwrap();
    let activation_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            database_url
                .parse::<sqlx::postgres::PgConnectOptions>()
                .unwrap()
                .application_name("passport-activate-race"),
        )
        .await
        .unwrap();
    let race_app = passport_router(PassportHttpService::new(
        ring,
        PostgresPassportRepository::new(cancellation_pool.clone()),
        None,
        None,
        None,
    ));
    for cancel_first in [true, false] {
        let (id, application) = seed(&pool, &repository, &principal, "READY_FOR_ACTIVATION").await;
        let mut blocker = pool.begin().await.unwrap();
        sqlx::query(
            "SELECT id FROM issuance_service.physical_document_jobs WHERE id=$1 FOR UPDATE",
        )
        .bind(&id)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
        let cancel_request = request(
            &application,
            &id,
            "org-a",
            "race-cancel",
            "End failed attempt",
        );
        let router = race_app.clone();
        let activate_repo = PostgresPassportRepository::new(activation_pool.clone());
        let activate_org = principal.clone();
        let activate_app = application.clone();
        let activate = async move {
            activate_repo
                .update(
                    &activate_org,
                    &activate_app,
                    "READY_FOR_ACTIVATION",
                    &PassportJobPatch::new(PassportJobStatus::Active),
                    Utc::now(),
                )
                .await
                .unwrap()
        };
        let cancel = async move { router.oneshot(cancel_request).await.unwrap() };
        let (cancel_handle, activate_handle) = if cancel_first {
            let c = tokio::spawn(cancel);
            wait_for_lock(&pool, "passport-cancel-race").await;
            let a = tokio::spawn(activate);
            wait_for_lock(&pool, "passport-activate-race").await;
            (c, a)
        } else {
            let a = tokio::spawn(activate);
            wait_for_lock(&pool, "passport-activate-race").await;
            let c = tokio::spawn(cancel);
            wait_for_lock(&pool, "passport-cancel-race").await;
            (c, a)
        };
        blocker.commit().await.unwrap();
        let cancelled = cancel_handle.await.unwrap();
        let activated = activate_handle.await.unwrap();
        if cancel_first {
            assert_eq!(cancelled.status(), StatusCode::OK);
            assert!(activated.is_none());
        } else {
            assert_eq!(cancelled.status(), StatusCode::CONFLICT);
            assert!(activated.is_some());
        }
        let actual = repository
            .get(&principal, &application)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            actual.status,
            if cancel_first { "CANCELLED" } else { "ACTIVE" }
        );
    }
    // Validator must reject a same-name guard with a changed body.
    sqlx::raw_sql("CREATE OR REPLACE FUNCTION issuance_service.guard_administratively_cancelled_passport_job() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$").execute(&pool).await.unwrap();
    assert!(migration::validate_passport(&pool).await.is_err());
    migration::migrate_passport(&pool).await.unwrap();
    migration::validate_passport(&pool).await.unwrap();
    cancellation_pool.close().await;
    activation_pool.close().await;
    pool.close().await;
}

#[tokio::test]
async fn keyed_physical_start_creates_one_tenant_owned_job_and_preserves_legacy_calls() {
    let Ok(database_url) = std::env::var("MARTY_PASSPORT_POSTGRES_TEST_URL") else {
        eprintln!(
            "MARTY_PASSPORT_POSTGRES_TEST_URL is not configured; PostgreSQL contract skipped"
        );
        return;
    };
    let parsed = url::Url::parse(&database_url).unwrap();
    assert!(matches!(parsed.host_str(), Some("127.0.0.1" | "localhost")));
    assert_eq!(parsed.path(), "/marty_passport_contract_test");
    let _schema_guard =
        shared_schema_lock::lock_shared_test_schemas(&database_url.parse().unwrap())
            .await
            .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .unwrap();
    sqlx::query("DROP SCHEMA IF EXISTS issuance_service CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    migration::migrate_passport(&pool).await.unwrap();
    migration::validate_passport(&pool).await.unwrap();
    sqlx::query("DROP INDEX issuance_service.ux_physical_document_jobs_org_start_key")
        .execute(&pool)
        .await
        .unwrap();
    assert!(migration::validate_passport(&pool).await.is_err());
    migration::migrate_passport(&pool).await.unwrap();
    migration::validate_passport(&pool).await.unwrap();
    let ring = PassportTenantKeyring::from_json(&format!(
        "{{\"org-a\":\"{}\",\"org-b\":\"{}\"}}",
        "a".repeat(32),
        "b".repeat(32)
    ))
    .unwrap();
    let org_a = ring
        .authenticate(Some("org-a"), Some(&"a".repeat(32)))
        .unwrap();
    let org_b = ring
        .authenticate(Some("org-b"), Some(&"b".repeat(32)))
        .unwrap();
    let repository = PostgresPassportRepository::new(pool.clone());
    let now = Utc::now();
    let job = |id: &str| PassportJobInsert {
        id: id.into(),
        application_id: format!("app-{id}"),
        flow_execution_id: "90000000-0000-0000-0000-000000000041".into(),
        application_template_id: "app-template".into(),
        credential_template_id: "credential-template".into(),
        revocation_profile_id: None,
        delivery_destination_profile_id: "destination".into(),
        document_type: "TD3".into(),
        country_code: "USA".into(),
        issuer_did: None,
        secure_artifact_ciphertext: "synthetic-encrypted-fixture".into(),
        secure_artifact_reference: format!("physical-artifact://{id}"),
    };
    let key = hex::encode(Sha256::digest(
        b"marty:passport-start-key:v1:90000000-0000-0000-0000-000000000041",
    ));
    let digest = "b".repeat(64);
    let left_job = job("left");
    let right_job = job("right");
    let (left, right) = tokio::join!(
        repository.insert_idempotent(&org_a, &left_job, now, &key, &digest),
        repository.insert_idempotent(&org_a, &right_job, now, &key, &digest),
    );
    let (left, right) = (left.unwrap().unwrap(), right.unwrap().unwrap());
    assert_eq!(left.0.id, right.0.id);
    assert_ne!(left.1, right.1);
    assert!(repository
        .get_by_start_key(&org_b, &key)
        .await
        .unwrap()
        .is_none());
    let service_token = "synthetic-internal-passport-token-00000001";
    let config = IssuanceServiceConfig::from_values(vec![
        ("PASSPORT_NATIVE_HTTP_ENABLED".into(), "true".into()),
        (
            "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED".into(),
            "true".into(),
        ),
        ("GRPC_SERVICE_TOKEN".into(), service_token.into()),
        ("DATABASE_URL".into(), database_url.clone()),
    ])
    .unwrap();
    let app = passport_router(
        PassportHttpService::from_config(&config, pool.clone())
            .unwrap()
            .unwrap(),
    );
    let duplicate_flow_id = "90000000-0000-0000-0000-000000000099";
    let duplicate_body = json!({
        "organization_id":"org-a", "flow_execution_id":duplicate_flow_id,
        "application_template_id":"app-template", "credential_template_id":"credential-template",
        "delivery_destination_profile_id":"destination", "country_code":"USA",
        "applicant":{}, "mrz":{}, "data_groups":{"DG1":"YQ==", "DG2":"Yg=="}
    });
    for keys in [vec!["owned-1", "owned-2"], vec!["owned-1,owned-2"]] {
        let mut request = Request::builder()
            .method("POST")
            .uri("/v1/passport/applications")
            .header("content-type", "application/json")
            .header("x-organization-id", "org-a")
            .header("x-api-key", service_token);
        for key in keys {
            request = request.header("idempotency-key", key);
        }
        let response = app
            .clone()
            .oneshot(
                request
                    .body(Body::from(duplicate_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(
            body["detail"],
            "Physical document Idempotency-Key is invalid"
        );
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM issuance_service.physical_document_jobs WHERE flow_execution_id = $1"
        ).bind(duplicate_flow_id).fetch_one(&pool).await.unwrap();
        assert_eq!(count, 0);
    }
    let flow_path = "/internal/passport/flow-starts/90000000-0000-0000-0000-000000000041";
    for (organization, internal_token, expected) in [
        ("org-a", Some(service_token), StatusCode::OK),
        ("org-b", Some(service_token), StatusCode::NOT_FOUND),
        ("org-a", None, StatusCode::UNAUTHORIZED),
    ] {
        let mut request = Request::builder()
            .method("GET")
            .uri(flow_path)
            .header("x-organization-id", organization)
            .header("x-api-key", service_token);
        if let Some(internal_token) = internal_token {
            request = request.header("x-service-token", internal_token);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        if expected == StatusCode::OK {
            let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
            let safe: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(safe["organization_id"], "org-a");
            assert_eq!(
                safe["flow_execution_id"],
                "90000000-0000-0000-0000-000000000041"
            );
            assert!(safe.get("secure_artifact_ciphertext").is_none());
        }
    }
    assert!(repository
        .insert_idempotent(&org_a, &job("changed"), now, &key, &"c".repeat(64))
        .await
        .unwrap()
        .is_none());
    let mut changed_flow = job("changed-flow");
    changed_flow.flow_execution_id = "90000000-0000-0000-0000-000000000099".into();
    assert!(repository
        .insert_idempotent(&org_a, &changed_flow, now, &key, &digest)
        .await
        .unwrap()
        .is_none());
    let legacy = repository
        .insert(&org_a, &job("legacy"), now)
        .await
        .unwrap();
    assert_eq!(legacy.status, "DRAFT");
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM issuance_service.physical_document_jobs")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 2);
    sqlx::query("DROP SCHEMA IF EXISTS issuance_service CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[path = "support/passport_mock_artifact_kms.rs"]
mod passport_mock_artifact_kms;

#[path = "support/passport_delivery_destinations.rs"]
mod passport_delivery_destinations;

#[path = "support/contract_grant.rs"]
mod contract_grant;

#[path = "../src/passport_test_vectors.rs"]
mod passport_test_vectors;

async fn provider_ingress_request(
    app: &Router,
    body: &[u8],
    signature: &str,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/passport/webhooks/personalization")
                .header("x-personalization-signature", signature)
                .header("content-type", "application/json")
                .body(Body::from(body.to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

async fn passport_http_request(
    app: &Router,
    method: &str,
    path: &str,
    organization: Option<&str>,
    key: Option<&str>,
    body: Value,
    signature: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(organization) = organization {
        request = request.header("x-organization-id", organization);
    }
    if let Some(key) = key {
        request = request.header("x-api-key", key);
    }
    if let Some(signature) = signature {
        request = request.header("x-personalization-signature", signature);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn exercise_native_passport_http(
    pool: &sqlx::PgPool,
    repository: PostgresPassportRepository,
    keyring: PassportTenantKeyring,
    cipher: KmsPassportArtifactCipher,
    kms: &passport_mock_artifact_kms::MockPassportKms,
    key_a: &str,
    key_b: &str,
) {
    type SubmitGate = Arc<Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>>;
    type SignGate = Arc<Mutex<Option<Arc<Barrier>>>>;
    #[derive(Clone)]
    struct MockState {
        observed: Arc<Mutex<Vec<Value>>>,
        submit_gate: SubmitGate,
        reject_next_submit: Arc<AtomicBool>,
        server_error_next_submit: Arc<AtomicBool>,
        omit_next_bureau_id: Arc<AtomicBool>,
        sign_calls: Arc<AtomicUsize>,
        sign_gate: SignGate,
        vector: passport_test_vectors::PublicPassportVector,
    }
    async fn resolve(State(state): State<MockState>) -> Json<Value> {
        Json(json!({
            "ok": true,
            "organization_id": "org-a",
            "issuer_did": "did:web:issuer.example:orgs:org-a",
            "key_purpose": "x509_doc_signer",
            "algorithm": "ES256",
            "verification_method_id": "did:web:issuer.example:orgs:org-a#dsc",
            "signing_key_reference": "transit/keys/passport-dsc-a",
            "issuer_profile": {"id":"passport-profile-a", "credential_format":"ICAO_EMRTD", "signing_key_reference":"transit/keys/passport-dsc-a"},
            "issuer_x5c": [state.vector.dsc_der_b64, state.vector.csca_der_b64]
        }))
    }
    async fn trust(State(state): State<MockState>) -> Json<Value> {
        Json(json!([{
            "certificate_id":"csca-a",
            "certificate_data":passport_test_vectors::certificate_pem(&state.vector.csca_der_b64),
            "status":"VALID"
        }]))
    }
    async fn sign(
        State(state): State<MockState>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        assert_eq!(body["issuer_did"], "did:web:issuer.example:orgs:org-a");
        let grant = marty_signing_grant::GrantEnvelope::from_header_value(
            headers[marty_signing_grant::HEADER_NAME].to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(grant.claims.origin, SigningOrigin::IssuancePassport);
        assert_eq!(grant.claims.organization_id, "org-a");
        assert!(!grant.claims.operation_id.is_empty());
        assert_eq!(
            grant.claims.key_reference.as_deref(),
            Some("transit/keys/passport-dsc-a")
        );
        let signing_input = URL_SAFE_NO_PAD
            .decode(body["payload_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&signing_input)),
            state.vector.signing_input_sha256
        );
        assert_eq!(
            grant.claims.payload_sha256_b64,
            marty_signing_grant::payload_digest(&signing_input)
        );
        state.sign_calls.fetch_add(1, Ordering::SeqCst);
        let gated = { state.sign_gate.lock().unwrap().clone() };
        if let Some(barrier) = gated {
            barrier.wait().await;
        }
        let native_signature = STANDARD.decode(&state.vector.signature_der_b64).unwrap();
        Json(json!({
            "ok":true,
            "issuer_did":"did:web:issuer.example:orgs:org-a",
            "algorithm":"ES256",
            "verification_method_id":"did:web:issuer.example:orgs:org-a#dsc",
            "signature_b64":URL_SAFE_NO_PAD.encode(&native_signature),
            "signature_raw_b64":URL_SAFE_NO_PAD.encode(&native_signature)
        }))
    }
    async fn submit(
        State(state): State<MockState>,
        Json(body): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        state.observed.lock().unwrap().push(body);
        let gated = { state.submit_gate.lock().unwrap().take() };
        if let Some((entered, release)) = gated {
            entered.send(()).unwrap();
            release.await.unwrap();
        }
        if state.reject_next_submit.swap(false, Ordering::SeqCst) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"private":"bureau failure"})),
            );
        }
        if state.server_error_next_submit.swap(false, Ordering::SeqCst) {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"private":"bureau failure"})),
            );
        }
        if state.omit_next_bureau_id.swap(false, Ordering::SeqCst) {
            return (StatusCode::ACCEPTED, Json(json!({"status":"QUEUED"})));
        }
        (
            StatusCode::ACCEPTED,
            Json(json!({"bureau_job_id":"bureau-http", "status":"QUEUED"})),
        )
    }
    async fn signed_callback(
        app: &Router,
        kms: &passport_mock_artifact_kms::MockPassportKms,
        body: Value,
    ) -> (StatusCode, Value) {
        let signature = kms.callback_signature(body.to_string().as_bytes());
        passport_http_request(
            app,
            "POST",
            "/v1/passport/webhooks/personalization",
            None,
            None,
            body,
            Some(&signature),
        )
        .await
    }
    let observed = Arc::new(Mutex::new(Vec::new()));
    let sign_calls = Arc::new(AtomicUsize::new(0));
    let sign_gate: SignGate = Arc::new(Mutex::new(None));
    let submit_gate: SubmitGate = Arc::new(Mutex::new(None));
    let reject_next_submit = Arc::new(AtomicBool::new(false));
    let server_error_next_submit = Arc::new(AtomicBool::new(false));
    let omit_next_bureau_id = Arc::new(AtomicBool::new(false));
    let stale_poll = Arc::new(AtomicBool::new(false));
    let poll_state = stale_poll.clone();
    let same_rank_poll = Arc::new(AtomicBool::new(false));
    let same_rank_state = same_rank_poll.clone();
    let poll_gate = Arc::new(Mutex::new(
        None::<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
    ));
    let gate_state = poll_gate.clone();
    let vector = passport_test_vectors::public_passport_vectors()[0].clone();
    let mock = Router::new()
        .route("/internal/signing-keys/resolve-issuer-did", get(resolve))
        .route("/internal/signing-keys/csca-trust-anchors", get(trust))
        .route("/internal/signing-keys/issuer-dids/sign", post(sign))
        .route("/v1/personalization/jobs", post(submit))
        .route(
            "/v1/personalization/jobs/{job_id}",
            get(move || {
                let stale_poll = poll_state.clone();
                let same_rank_poll = same_rank_state.clone();
                let poll_gate = gate_state.clone();
                async move {
                    let gated = { poll_gate.lock().unwrap().take() };
                    if let Some((entered, release)) = gated {
                        entered.send(()).unwrap();
                        release.await.unwrap();
                    }
                    Json(if same_rank_poll.load(Ordering::SeqCst) {
                        json!({"status":"QUEUED", "tracking_number":null})
                    } else if stale_poll.load(Ordering::SeqCst) {
                        json!({"status":"PRINTING", "tracking_number":null})
                    } else {
                        json!({"status":"SHIPPED", "tracking_number":"tracking-http"})
                    })
                }
            }),
        )
        .with_state(MockState {
            observed: observed.clone(),
            submit_gate: submit_gate.clone(),
            reject_next_submit: reject_next_submit.clone(),
            server_error_next_submit: server_error_next_submit.clone(),
            omit_next_bureau_id: omit_next_bureau_id.clone(),
            sign_calls: sign_calls.clone(),
            sign_gate: sign_gate.clone(),
            vector: vector.clone(),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
    let signing_url = url::Url::parse(&format!("{base_url}/internal/signing-keys/")).unwrap();
    let app = passport_router(
        PassportHttpService::new(
            keyring.clone(),
            repository.clone(),
            Some(cipher.clone()),
            Some(PassportSigner::Managed(Box::new(
                ManagedProfileSigner::new_with_grant(
                    signing_url,
                    Some("synthetic-internal-key"),
                    Some("synthetic-issuer-sign-key"),
                    contract_grant::ContractGrantMinter(SigningOrigin::IssuancePassport),
                )
                .unwrap(),
            ))),
            Some(BureauClient::new(&base_url, "bureau-key").unwrap()),
        )
        .with_webhook_verifier(kms.webhook_verifier.clone()),
    );
    let payload = json!({
        "organization_id":"org-a", "issuer_did":"did:web:issuer.example:orgs:org-a", "flow_execution_id":"flow-http",
        "application_template_id":"template-http", "credential_template_id":"credential-http",
        "delivery_destination_profile_id":"destination-http", "document_type":"TD1",
        "country_code":"USA", "applicant":{"name":"Synthetic Sensitive"},
        "mrz":{"line_1":"P<TEST", "line_2":"SYNTHETIC"},
        "data_groups":{"DG1":"AQ==", "DG2":"Ag=="}
    });
    let (status, _) = passport_http_request(
        &app,
        "POST",
        "/v1/passport/applications",
        None,
        Some(key_a),
        payload.clone(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = passport_http_request(
        &app,
        "POST",
        "/v1/passport/applications",
        Some("org-b"),
        Some(key_b),
        payload.clone(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, created) = passport_http_request(
        &app,
        "POST",
        "/v1/passport/applications",
        Some("org-a"),
        Some(key_a),
        payload,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["status"], "DRAFT");
    assert_eq!(created["document_type"], "TD1");
    assert!(!created.to_string().contains("Synthetic Sensitive"));
    let application_id = created["application_id"].as_str().unwrap();
    let job = repository
        .get(
            &keyring.authenticate(Some("org-a"), Some(key_a)).unwrap(),
            application_id,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(!job
        .secure_artifact_ciphertext
        .contains("Synthetic Sensitive"));
    let path = format!("/v1/passport/applications/{application_id}");
    let (status, _) = passport_http_request(
        &app,
        "POST",
        &format!("{path}/generate-data-groups"),
        Some("org-b"),
        Some(key_b),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, generated) = passport_http_request(
        &app,
        "POST",
        &format!("{path}/generate-data-groups"),
        Some("org-a"),
        Some(key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(generated["status"], "DATA_GENERATED");
    let (status, signed) = passport_http_request(
        &app,
        "POST",
        &format!("{path}/generate-sod"),
        Some("org-a"),
        Some(key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(signed["status"], "SOD_SIGNED");
    assert_eq!(signed["sod_signature_verified"], true);
    let principal = keyring.authenticate(Some("org-a"), Some(key_a)).unwrap();
    let before_denial = repository
        .get(&principal, application_id)
        .await
        .unwrap()
        .unwrap();
    let prior_sign_calls = sign_calls.load(Ordering::SeqCst);
    for patch in [
        json!({"is_enabled":false}),
        json!({"organization_id":"org-b"}),
        json!({"organization_id":null}),
        json!({"organization_id":"org-b", "is_system":true}),
        json!({"provider":"oid4vci_wallet"}),
        json!({"mode":"holder_wallet"}),
        json!({"delivery_target":"wallet"}),
        json!({"credential_format":"VC_JWT"}),
        json!({"issuance_protocol":"DIRECT"}),
        json!({"connector_id":"another-bureau"}),
        json!({"id":"temporarily-missing-destination"}),
    ] {
        let mut destination = json!({
            "id":"destination-http", "organization_id":"org-a", "is_system":false,
            "is_enabled":true, "provider":"physical_document_bureau", "mode":"physical_document",
            "delivery_target":"physical_document", "credential_format":"ICAO_EMRTD",
            "issuance_protocol":"PHYSICAL_DOCUMENT", "connector_id":null
        });
        destination
            .as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        sqlx::query(
            "UPDATE credential_template_service.delivery_destinations
             SET id=$1, organization_id=$2, is_system=$3, is_enabled=$4, provider=$5,
                 mode=$6, delivery_target=$7, credential_format=$8, issuance_protocol=$9,
                 connector_id=$10 WHERE id='destination-http'",
        )
        .bind(destination["id"].as_str().unwrap())
        .bind(destination["organization_id"].as_str())
        .bind(destination["is_system"].as_bool().unwrap())
        .bind(destination["is_enabled"].as_bool().unwrap())
        .bind(destination["provider"].as_str().unwrap())
        .bind(destination["mode"].as_str().unwrap())
        .bind(destination["delivery_target"].as_str().unwrap())
        .bind(destination["credential_format"].as_str())
        .bind(destination["issuance_protocol"].as_str())
        .bind(destination["connector_id"].as_str())
        .execute(pool)
        .await
        .unwrap();
        let (status, body) = passport_http_request(
            &app,
            "POST",
            &format!("{path}/submit-personalization"),
            Some("org-a"),
            Some(key_a),
            json!({}),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "destination patch: {patch}");
        assert_eq!(
            body["detail"],
            "Physical document delivery destination is unavailable or incompatible"
        );
        assert!(observed.lock().unwrap().is_empty());
        assert_eq!(sign_calls.load(Ordering::SeqCst), prior_sign_calls);
        let denied = repository
            .get(&principal, application_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(denied.status, "SOD_SIGNED");
        assert_eq!(denied.sod_sha256, before_denial.sod_sha256);
        assert_eq!(
            denied.secure_artifact_ciphertext,
            before_denial.secure_artifact_ciphertext
        );
        assert!(denied.submission_intent_id.is_none());
        assert!(denied.bureau_job_id.is_none());
    }
    passport_delivery_destinations::seed(pool).await;
    assert_eq!(
        signed["sod_sha256"],
        hex::encode(sha2::Sha256::digest(
            STANDARD.decode(&vector.sod_der_b64).unwrap()
        ))
    );
    let (status, repeated_signed) = passport_http_request(
        &app,
        "POST",
        &format!("{path}/generate-sod"),
        Some("org-a"),
        Some(key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(repeated_signed["sod_sha256"], signed["sod_sha256"]);
    assert_eq!(sign_calls.load(Ordering::SeqCst), 1);
    let signed_job = repository
        .get(
            &keyring.authenticate(Some("org-a"), Some(key_a)).unwrap(),
            application_id,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        cipher
            .decrypt(
                &signed_job.organization_id,
                &signed_job.id,
                &signed_job.secure_artifact_ciphertext
            )
            .await
            .unwrap()
            .signed_material
            .unwrap()
            .sod_der_base64,
        vector.sod_der_b64
    );
    assert!(!signed_job
        .secure_artifact_ciphertext
        .contains(&vector.sod_der_b64));
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    *submit_gate.lock().unwrap() = Some((entered_tx, release_rx));
    let pending_app = app.clone();
    let pending_path = format!("{path}/submit-personalization");
    let pending_key = key_a.to_owned();
    let pending_submit = tokio::spawn(async move {
        passport_http_request(
            &pending_app,
            "POST",
            &pending_path,
            Some("org-a"),
            Some(&pending_key),
            json!({}),
            None,
        )
        .await
    });
    entered_rx.await.unwrap();
    let retry_app = app.clone();
    let retry_path = format!("{path}/submit-personalization");
    let retry_key = key_a.to_owned();
    let concurrent_retry = tokio::spawn(async move {
        passport_http_request(
            &retry_app,
            "POST",
            &retry_path,
            Some("org-a"),
            Some(&retry_key),
            json!({}),
            None,
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(!concurrent_retry.is_finished());
    release_tx.send(()).unwrap();
    let (status, raced_submit) = pending_submit.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(raced_submit["status"], "SUBMITTED");
    let (status, submitted) = concurrent_retry.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(submitted["bureau_job_id"], raced_submit["bureau_job_id"]);
    assert_eq!(observed.lock().unwrap().len(), 1);
    assert_eq!(observed.lock().unwrap()[0]["document_type"], "TD1");
    assert_eq!(
        observed.lock().unwrap()[0]["sod_der_base64"],
        vector.sod_der_b64
    );
    assert_eq!(raced_submit["sod_sha256"], signed["sod_sha256"]);
    assert_eq!(sign_calls.load(Ordering::SeqCst), 1);
    let (status, _) = passport_http_request(
        &app,
        "POST",
        &format!("{path}/quality-verify"),
        Some("org-a"),
        Some(key_a),
        json!({"passed":true}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, polled) = passport_http_request(
        &app,
        "GET",
        &format!("{path}/production-status"),
        Some("org-a"),
        Some(key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(polled["status"], "READY_FOR_ACTIVATION");
    for operation in ["generate-data-groups", "generate-sod"] {
        let (status, _) = passport_http_request(
            &app,
            "POST",
            &format!("{path}/{operation}"),
            Some("org-a"),
            Some(key_a),
            json!({}),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }
    let (status, repeated) = passport_http_request(
        &app,
        "POST",
        &format!("{path}/submit-personalization"),
        Some("org-a"),
        Some(key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(repeated["status"], "READY_FOR_ACTIVATION");
    assert_eq!(repeated["bureau_job_id"], "bureau-http");
    assert_eq!(repeated, polled);
    assert_eq!(observed.lock().unwrap().len(), 1);
    let webhook = json!({"organization_id":"org-a", "bureau_job_id":"bureau-http", "status":"SHIPPED", "tracking_number":"webhook-tracking"});
    let (status, _) = passport_http_request(
        &app,
        "POST",
        "/v1/passport/webhooks/personalization",
        None,
        None,
        webhook.clone(),
        Some("invalid"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let signature = kms.callback_signature(webhook.to_string().as_bytes());
    let (status, accepted) = passport_http_request(
        &app,
        "POST",
        "/v1/passport/webhooks/personalization",
        None,
        None,
        webhook,
        Some(&signature),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(accepted, json!({"accepted":true}));
    stale_poll.store(true, Ordering::SeqCst);
    let (status, after_stale_poll) = passport_http_request(
        &app,
        "GET",
        &format!("{path}/production-status"),
        Some("org-a"),
        Some(key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(after_stale_poll["status"], "READY_FOR_ACTIVATION");
    assert_eq!(after_stale_poll["tracking_number"], "tracking-http");
    let (status, quality) = passport_http_request(
        &app,
        "POST",
        &format!("{path}/quality-verify"),
        Some("org-a"),
        Some(key_a),
        json!({"passed":true,"failure_codes":[]}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(quality["status"], "READY_FOR_ACTIVATION");
    let (status, after_quality_poll) = passport_http_request(
        &app,
        "GET",
        &format!("{path}/production-status"),
        Some("org-a"),
        Some(key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(after_quality_poll["status"], "READY_FOR_ACTIVATION");
    assert_eq!(after_quality_poll["quality_result"]["passed"], true);
    let (status, active) = passport_http_request(
        &app,
        "POST",
        &format!("{path}/activate"),
        Some("org-a"),
        Some(key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(active["status"], "ACTIVE");
    let (status, repeated_active) = passport_http_request(
        &app,
        "POST",
        &format!("{path}/submit-personalization"),
        Some("org-a"),
        Some(key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(repeated_active["status"], "ACTIVE");
    assert_eq!(repeated_active, active);
    assert_eq!(observed.lock().unwrap().len(), 1);
    let job = repository
        .get(
            &keyring.authenticate(Some("org-a"), Some(key_a)).unwrap(),
            application_id,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(cipher
        .decrypt(
            &job.organization_id,
            &job.id,
            &job.secure_artifact_ciphertext
        )
        .await
        .is_err());
    let frozen: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-physical-passport-native.json"
    ))
    .unwrap();
    let wide_name = frozen["wide_data_group_number_observation"]["input_name"]
        .as_str()
        .unwrap();
    let mut wide_payload = json!({
        "organization_id":"org-a", "issuer_did":"did:web:issuer.example:orgs:org-a", "flow_execution_id":"wide-data-group-test",
        "application_template_id":"template-test", "credential_template_id":"credential-test",
        "delivery_destination_profile_id":"destination-test", "country_code":"USA",
        "applicant":{}, "mrz":{}, "data_groups":{"DG1":"AQ==", "DG2":"Ag=="}
    });
    wide_payload["data_groups"][wide_name] = json!("Yw==");
    wide_payload["data_groups"]["DG１２"] = json!("ZA==");
    wide_payload["data_groups"]["DG١٣"] = json!("ZQ==");
    let (status, wide_created) = passport_http_request(
        &app,
        "POST",
        "/v1/passport/applications",
        Some("org-a"),
        Some(key_a),
        wide_payload,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let wide_path = format!(
        "/v1/passport/applications/{}/generate-data-groups",
        wide_created["application_id"].as_str().unwrap()
    );
    let (status, wide_generated) = passport_http_request(
        &app,
        "POST",
        &wide_path,
        Some("org-a"),
        Some(key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(wide_generated["status"], "DATA_GENERATED");
    let principal = keyring.authenticate(Some("org-a"), Some(key_a)).unwrap();
    let race_job = PassportJobInsert {
        id: "job-poll-race".into(),
        application_id: "application-poll-race".into(),
        flow_execution_id: "flow-poll-race".into(),
        application_template_id: "template-poll-race".into(),
        credential_template_id: "credential-poll-race".into(),
        revocation_profile_id: None,
        delivery_destination_profile_id: "destination-poll-race".into(),
        document_type: "TD1".into(),
        country_code: "USA".into(),
        issuer_did: None,
        secure_artifact_ciphertext: cipher
            .encrypted_scrubbed_artifact("org-a", "job-poll-race")
            .await
            .unwrap(),
        secure_artifact_reference: "physical-artifact://poll-race".into(),
    };
    repository
        .insert(&principal, &race_job, Utc::now())
        .await
        .unwrap();
    let mut race_submitted = PassportJobPatch::new(PassportJobStatus::Submitted);
    race_submitted.bureau_job_id = Some(Some("bureau-poll-race".into()));
    repository
        .update(
            &principal,
            &race_job.application_id,
            "DRAFT",
            &race_submitted,
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap();
    let mut stale_no_id = PassportJobPatch::new(PassportJobStatus::Submitted);
    stale_no_id.bureau_job_id = Some(None);
    stale_no_id.error_code = Some(Some("BUREAU_SUBMISSION_FAILED".into()));
    assert!(repository
        .update(
            &principal,
            &race_job.application_id,
            "SUBMITTED",
            &stale_no_id,
            Utc::now(),
        )
        .await
        .unwrap()
        .is_none());
    let still_bound = repository
        .get(&principal, &race_job.application_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        still_bound.bureau_job_id.as_deref(),
        Some("bureau-poll-race")
    );
    assert!(still_bound.error_code.is_none());
    let race_path = format!(
        "/v1/passport/applications/{}/production-status",
        race_job.application_id
    );
    same_rank_poll.store(true, Ordering::SeqCst);
    let (entered, entered_rx) = oneshot::channel();
    let (release_tx, release) = oneshot::channel();
    *poll_gate.lock().unwrap() = Some((entered, release));
    let poll_app = app.clone();
    let poll_path = race_path.clone();
    let poll_key = key_a.to_owned();
    let in_flight = tokio::spawn(async move {
        passport_http_request(
            &poll_app,
            "GET",
            &poll_path,
            Some("org-a"),
            Some(&poll_key),
            json!({}),
            None,
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered_rx)
        .await
        .unwrap()
        .unwrap();
    let (status, _) = signed_callback(
        &app,
        kms,
        json!({"organization_id":"org-a", "bureau_job_id":"bureau-poll-race",
               "status":"SHIPPED", "tracking_number":"race-tracking"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    release_tx.send(()).unwrap();
    let (status, after_same_rank_poll) = in_flight.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(after_same_rank_poll["status"], "READY_FOR_ACTIVATION");
    assert_eq!(after_same_rank_poll["tracking_number"], "race-tracking");

    same_rank_poll.store(false, Ordering::SeqCst);
    let (entered, entered_rx) = oneshot::channel();
    let (release_tx, release) = oneshot::channel();
    *poll_gate.lock().unwrap() = Some((entered, release));
    let poll_app = app.clone();
    let poll_path = race_path;
    let poll_key = key_a.to_owned();
    let in_flight = tokio::spawn(async move {
        passport_http_request(
            &poll_app,
            "GET",
            &poll_path,
            Some("org-a"),
            Some(&poll_key),
            json!({}),
            None,
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered_rx)
        .await
        .unwrap()
        .unwrap();
    let (status, _) = signed_callback(
        &app,
        kms,
        json!({"organization_id":"org-a", "bureau_job_id":"bureau-poll-race",
               "status":"FAILED", "error_message":"production failed"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    release_tx.send(()).unwrap();
    let (status, after_stale_poll) = in_flight.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(after_stale_poll["status"], "FAILED");
    assert_eq!(after_stale_poll["tracking_number"], "race-tracking");
    assert_eq!(after_stale_poll["error_message"], "production failed");
    let (status, legacy_created) = passport_http_request(
        &app,
        "POST",
        "/v1/passport/applications",
        Some("org-a"),
        Some(key_a),
        json!({
            "organization_id":"org-a", "issuer_did":"did:web:issuer.example:orgs:org-a", "flow_execution_id":"legacy-sod",
            "application_template_id":"template-http", "credential_template_id":"credential-http",
            "delivery_destination_profile_id":"destination-http", "country_code":"USA",
            "applicant":{}, "mrz":{}, "data_groups":{"DG1":"AQ==", "DG2":"Ag=="}
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let legacy_id = legacy_created["application_id"].as_str().unwrap();
    let principal = keyring.authenticate(Some("org-a"), Some(key_a)).unwrap();
    let legacy_job = repository
        .get(&principal, legacy_id)
        .await
        .unwrap()
        .unwrap();
    let mut legacy_patch = PassportJobPatch::new(PassportJobStatus::SodSigned);
    legacy_patch.sod_sha256 = Some(Some("a".repeat(64)));
    repository
        .update(
            &principal,
            legacy_id,
            &legacy_job.status,
            &legacy_patch,
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap();
    let legacy_path = format!("/v1/passport/applications/{legacy_id}");
    let (status, _) = passport_http_request(
        &app,
        "POST",
        &format!("{legacy_path}/submit-personalization"),
        Some("org-a"),
        Some(key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(sign_calls.load(Ordering::SeqCst), 1);
    let (status, recovered) = passport_http_request(
        &app,
        "POST",
        &format!("{legacy_path}/generate-sod"),
        Some("org-a"),
        Some(key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        recovered["sod_sha256"],
        hex::encode(Sha256::digest(
            STANDARD.decode(&vector.sod_der_b64).unwrap()
        ))
    );
    let recovered_job = repository
        .get(&principal, legacy_id)
        .await
        .unwrap()
        .unwrap();
    let mut python_resigned = PassportJobPatch::new(PassportJobStatus::SodSigned);
    python_resigned.sod_sha256 = Some(Some("b".repeat(64)));
    repository
        .update(
            &principal,
            legacy_id,
            &recovered_job.status,
            &python_resigned,
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap();
    let (status, _) = passport_http_request(
        &app,
        "POST",
        &format!("{legacy_path}/submit-personalization"),
        Some("org-a"),
        Some(key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, refreshed) = passport_http_request(
        &app,
        "POST",
        &format!("{legacy_path}/generate-sod"),
        Some("org-a"),
        Some(key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        refreshed["sod_sha256"],
        hex::encode(Sha256::digest(
            STANDARD.decode(&vector.sod_der_b64).unwrap()
        ))
    );
    assert_eq!(sign_calls.load(Ordering::SeqCst), 3);
    let refreshed_job = repository
        .get(&principal, legacy_id)
        .await
        .unwrap()
        .unwrap();
    let mut stale_writer = PassportJobPatch::new(PassportJobStatus::SodSigned);
    stale_writer.sod_sha256 = Some(Some("c".repeat(64)));
    repository
        .update(
            &principal,
            legacy_id,
            &refreshed_job.status,
            &stale_writer,
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap();
    *sign_gate.lock().unwrap() = Some(Arc::new(Barrier::new(2)));
    let regenerate_path = format!("{legacy_path}/generate-sod");
    let (first, second) = tokio::join!(
        passport_http_request(
            &app,
            "POST",
            &regenerate_path,
            Some("org-a"),
            Some(key_a),
            json!({}),
            None,
        ),
        passport_http_request(
            &app,
            "POST",
            &regenerate_path,
            Some("org-a"),
            Some(key_a),
            json!({}),
            None,
        )
    );
    *sign_gate.lock().unwrap() = None;
    assert_eq!(sign_calls.load(Ordering::SeqCst), 5);
    let successes = [&first, &second]
        .into_iter()
        .filter(|(status, _)| *status == StatusCode::OK)
        .collect::<Vec<_>>();
    assert_eq!(successes.len(), 1);
    assert!([first.0, second.0].contains(&StatusCode::CONFLICT));
    let raced_job = repository
        .get(&principal, legacy_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(successes[0].1["sod_sha256"], raced_job.sod_sha256.unwrap());

    // A rejected direct submit has no bureau binding and must keep the
    // historical ability to sign again on retry.
    let (status, retry_created) = passport_http_request(
        &app,
        "POST",
        "/v1/passport/applications",
        Some("org-a"),
        Some(key_a),
        json!({"organization_id":"org-a", "issuer_did":"did:web:issuer.example:orgs:org-a", "flow_execution_id":"retry-direct",
            "application_template_id":"template-http", "credential_template_id":"credential-http",
            "delivery_destination_profile_id":"destination-http", "document_type":"TD1",
            "country_code":"USA", "applicant":{}, "mrz":{"line_1":"P<TEST","line_2":"SYNTHETIC"},
            "data_groups":{"DG1":"AQ==","DG2":"Ag=="}}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let retry_path = format!(
        "/v1/passport/applications/{}/submit-personalization",
        retry_created["application_id"].as_str().unwrap()
    );
    let retry_job = repository
        .get(
            &principal,
            retry_created["application_id"].as_str().unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    let retry_artifact = cipher
        .decrypt(
            &retry_job.organization_id,
            &retry_job.id,
            &retry_job.secure_artifact_ciphertext,
        )
        .await
        .unwrap();
    assert_eq!(
        retry_artifact.data_groups.get("DG1").map(String::as_str),
        Some("AQ==")
    );
    assert!(retry_artifact.numbered_data_groups().is_ok());
    reject_next_submit.store(true, Ordering::SeqCst);
    let (status, rejected) = passport_http_request(
        &app,
        "POST",
        &retry_path,
        Some("org-a"),
        Some(key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{rejected}");
    assert!(rejected["bureau_job_id"].is_null());
    let rejected_job = repository
        .get(
            &principal,
            retry_created["application_id"].as_str().unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(rejected_job.submission_intent_id.is_some());
    assert!(rejected_job.sod_sha256.is_some());
    assert!(cipher
        .decrypt(
            &rejected_job.organization_id,
            &rejected_job.id,
            &rejected_job.secure_artifact_ciphertext
        )
        .await
        .unwrap()
        .signed_material
        .is_some());

    let (status, server_error_created) = passport_http_request(
        &app,
        "POST",
        "/v1/passport/applications",
        Some("org-a"),
        Some(key_a),
        json!({"organization_id":"org-a", "issuer_did":"did:web:issuer.example:orgs:org-a", "flow_execution_id":"server-error-submit",
            "application_template_id":"template-http", "credential_template_id":"credential-http",
            "delivery_destination_profile_id":"destination-http", "document_type":"TD1",
            "country_code":"USA", "applicant":{}, "mrz":{"line_1":"P<TEST","line_2":"SYNTHETIC"},
            "data_groups":{"DG1":"AQ==","DG2":"Ag=="}}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let server_error_id = server_error_created["application_id"].as_str().unwrap();
    let server_error_path =
        format!("/v1/passport/applications/{server_error_id}/submit-personalization");
    server_error_next_submit.store(true, Ordering::SeqCst);
    assert_eq!(
        passport_http_request(
            &app,
            "POST",
            &server_error_path,
            Some("org-a"),
            Some(key_a),
            json!({}),
            None,
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let server_error_job = repository
        .get(&principal, server_error_id)
        .await
        .unwrap()
        .unwrap();
    assert!(server_error_job.submission_intent_id.is_some());
    assert!(server_error_job.sod_sha256.is_some());
    assert!(
        Utc::now().signed_duration_since(server_error_job.submission_intent_started_at.unwrap())
            < chrono::Duration::seconds(35),
        "intent started at {:?}, now {:?}",
        server_error_job.submission_intent_started_at,
        Utc::now()
    );
    let bureau_calls_before_retry = observed.lock().unwrap().len();
    let wait_result = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        passport_http_request(
            &app,
            "POST",
            &server_error_path,
            Some("org-a"),
            Some(key_a),
            json!({}),
            None,
        ),
    )
    .await;
    assert!(wait_result.is_err(), "{wait_result:?}");
    assert_eq!(observed.lock().unwrap().len(), bureau_calls_before_retry);

    // A success response without an identity is ambiguous: keep the claim
    // and exact material so a later private reconciliation can prove it.
    let (status, ambiguous_created) = passport_http_request(
        &app,
        "POST",
        "/v1/passport/applications",
        Some("org-a"),
        Some(key_a),
        json!({"organization_id":"org-a", "issuer_did":"did:web:issuer.example:orgs:org-a", "flow_execution_id":"ambiguous-submit",
            "application_template_id":"template-http", "credential_template_id":"credential-http",
            "delivery_destination_profile_id":"destination-http", "document_type":"TD1",
            "country_code":"USA", "applicant":{}, "mrz":{"line_1":"P<TEST","line_2":"SYNTHETIC"},
            "data_groups":{"DG1":"AQ==","DG2":"Ag=="}}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let ambiguous_id = ambiguous_created["application_id"].as_str().unwrap();
    let ambiguous_path = format!("/v1/passport/applications/{ambiguous_id}");
    omit_next_bureau_id.store(true, Ordering::SeqCst);
    assert_eq!(
        passport_http_request(
            &app,
            "POST",
            &format!("{ambiguous_path}/submit-personalization"),
            Some("org-a"),
            Some(key_a),
            json!({}),
            None,
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let ambiguous_job = repository
        .get(&principal, ambiguous_id)
        .await
        .unwrap()
        .unwrap();
    assert!(ambiguous_job.submission_intent_id.is_some());
    assert!(ambiguous_job.bureau_job_id.is_none());
    assert!(ambiguous_job.sod_sha256.is_some());
    assert!(cipher
        .decrypt(
            &ambiguous_job.organization_id,
            &ambiguous_job.id,
            &ambiguous_job.secure_artifact_ciphertext
        )
        .await
        .unwrap()
        .signed_material
        .is_some());
    for operation in ["generate-data-groups", "generate-sod"] {
        assert_eq!(
            passport_http_request(
                &app,
                "POST",
                &format!("{ambiguous_path}/{operation}"),
                Some("org-a"),
                Some(key_a),
                json!({}),
                None,
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
    }

    // A reserved submission blocks both native and older writers from
    // replacing the accepted bureau's exact signed material.
    let (status, race_created) = passport_http_request(
        &app,
        "POST",
        "/v1/passport/applications",
        Some("org-a"),
        Some(key_a),
        json!({"organization_id":"org-a", "issuer_did":"did:web:issuer.example:orgs:org-a", "flow_execution_id":"race-submit",
            "application_template_id":"template-http", "credential_template_id":"credential-http",
            "delivery_destination_profile_id":"destination-http", "document_type":"TD1",
            "country_code":"USA", "applicant":{}, "mrz":{"line_1":"P<TEST","line_2":"SYNTHETIC"},
            "data_groups":{"DG1":"AQ==","DG2":"Ag=="}}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let race_id = race_created["application_id"].as_str().unwrap();
    let race_base = format!("/v1/passport/applications/{race_id}");
    let (status, _) = passport_http_request(
        &app,
        "POST",
        &format!("{race_base}/generate-sod"),
        Some("org-a"),
        Some(key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    *submit_gate.lock().unwrap() = Some((entered_tx, release_rx));
    let pending_app = app.clone();
    let pending_key = key_a.to_owned();
    let pending_path = format!("{race_base}/submit-personalization");
    let pending = tokio::spawn(async move {
        passport_http_request(
            &pending_app,
            "POST",
            &pending_path,
            Some("org-a"),
            Some(&pending_key),
            json!({}),
            None,
        )
        .await
    });
    entered_rx.await.unwrap();
    let before = repository.get(&principal, race_id).await.unwrap().unwrap();
    assert!(before.submission_intent_id.is_some());
    let mut replacement = cipher
        .decrypt(
            &before.organization_id,
            &before.id,
            &before.secure_artifact_ciphertext,
        )
        .await
        .unwrap();
    replacement.signed_material.as_mut().unwrap().sod_der_base64 = STANDARD.encode(b"SOD-refresh");
    let new_hash = hex::encode(Sha256::digest(b"SOD-refresh"));
    let new_ciphertext = cipher
        .encrypt(&before.organization_id, &before.id, &replacement)
        .await
        .unwrap();
    let mut refresh = PassportJobPatch::new(PassportJobStatus::SodSigned);
    refresh.expected_sod_sha256 = Some(before.sod_sha256.clone());
    refresh.expected_secure_artifact_ciphertext = Some(before.secure_artifact_ciphertext.clone());
    refresh.sod_sha256 = Some(Some(new_hash.clone()));
    refresh.secure_artifact_ciphertext = Some(new_ciphertext.clone());
    assert!(repository
        .update(&principal, race_id, &before.status, &refresh, Utc::now())
        .await
        .unwrap()
        .is_none());
    let old_writer = sqlx::query(
        "UPDATE issuance_service.physical_document_jobs SET sod_sha256=$1 WHERE application_id=$2",
    )
    .bind(&new_hash)
    .bind(race_id)
    .execute(pool)
    .await;
    assert!(old_writer.is_err());
    release_tx.send(()).unwrap();
    assert_eq!(pending.await.unwrap().0, StatusCode::OK);
    let after = repository.get(&principal, race_id).await.unwrap().unwrap();
    assert_eq!(after.sod_sha256, before.sod_sha256);
    assert_eq!(
        after.secure_artifact_ciphertext,
        before.secure_artifact_ciphertext
    );
    assert_eq!(after.bureau_job_id.as_deref(), Some("bureau-http"));
    assert!(after.submission_intent_id.is_none());

    server.abort();
}

#[tokio::test]
async fn passport_jobs_survive_restart_without_cross_tenant_reads() {
    let Ok(database_url) = std::env::var("MARTY_PASSPORT_POSTGRES_TEST_URL") else {
        return;
    };
    let database_name = url::Url::parse(&database_url)
        .expect("passport contract URL must parse")
        .path()
        .trim_start_matches('/')
        .to_owned();
    assert_eq!(
        database_name, "marty_passport_contract_test",
        "passport contract requires its dedicated disposable database"
    );
    let _schema_guard =
        shared_schema_lock::lock_shared_test_schemas(&database_url.parse().unwrap())
            .await
            .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("passport contract database must connect");
    sqlx::query("DROP SCHEMA IF EXISTS issuance_service CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP SCHEMA IF EXISTS flow_service CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    migration::migrate_passport(&pool).await.unwrap();
    passport_delivery_destinations::seed(&pool).await;
    sqlx::query(
        "ALTER TABLE issuance_service.physical_document_jobs
         DROP CONSTRAINT physical_document_jobs_pkey",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(migration::validate_passport(&pool).await.is_err());
    sqlx::query("ALTER TABLE issuance_service.physical_document_jobs ADD PRIMARY KEY (id)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "ALTER TABLE issuance_service.physical_document_jobs
         DROP CONSTRAINT physical_document_jobs_application_id_key",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(migration::validate_passport(&pool).await.is_err());
    sqlx::query(
        "ALTER TABLE issuance_service.physical_document_jobs
         ADD UNIQUE (application_id)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "DROP TRIGGER trg_physical_document_submission_intent
         ON issuance_service.physical_document_jobs",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(migration::validate_passport(&pool).await.is_err());
    migration::migrate_passport(&pool).await.unwrap();
    sqlx::query(
        "ALTER TABLE issuance_service.passport_beta_batch_intents
         DROP CONSTRAINT passport_beta_batch_intents_pkey",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(migration::validate_passport(&pool).await.is_err());
    sqlx::query(
        "ALTER TABLE issuance_service.passport_beta_batch_intents
         ADD PRIMARY KEY (batch_id)",
    )
    .execute(&pool)
    .await
    .unwrap();
    migration::migrate_passport(&pool).await.unwrap(); // startup is idempotent
    let lf_intent_migration =
        include_str!("../migrations/0004_passport_submission_intent.sql").replace("\r\n", "\n");
    let crlf_intent_migration = lf_intent_migration.replace('\n', "\r\n");
    // Both strings are the checked-in migration with line endings changed only.
    sqlx::raw_sql(sqlx::AssertSqlSafe(crlf_intent_migration.as_str()))
        .execute(&pool)
        .await
        .unwrap();
    migration::validate_passport(&pool).await.unwrap();
    sqlx::raw_sql(sqlx::AssertSqlSafe(lf_intent_migration.as_str()))
        .execute(&pool)
        .await
        .unwrap();
    migration::validate_passport(&pool).await.unwrap();
    let read_only_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .unwrap();
    sqlx::query("SET default_transaction_read_only = on")
        .execute(&read_only_pool)
        .await
        .unwrap();
    migration::validate_passport(&read_only_pool).await.unwrap();
    read_only_pool.close().await;
    sqlx::raw_sql(
        "CREATE ROLE passport_batch_acl_test NOLOGIN;
         GRANT USAGE ON SCHEMA issuance_service TO passport_batch_acl_test;
         GRANT SELECT ON issuance_service.physical_document_jobs,
                         issuance_service.passport_beta_batch_intents
             TO passport_batch_acl_test;",
    )
    .execute(&pool)
    .await
    .unwrap();
    let limited_pool = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE passport_batch_acl_test")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&database_url)
        .await
        .unwrap();
    let access_error = migration::validate_passport(&limited_pool)
        .await
        .unwrap_err();
    assert!(access_error
        .to_string()
        .contains("lacks application CRUD privileges"));
    sqlx::query(
        "GRANT INSERT, UPDATE, DELETE ON issuance_service.passport_beta_batch_intents
         TO passport_batch_acl_test",
    )
    .execute(&pool)
    .await
    .unwrap();
    migration::validate_passport(&limited_pool).await.unwrap();
    limited_pool.close().await;
    sqlx::raw_sql("DROP OWNED BY passport_batch_acl_test; DROP ROLE passport_batch_acl_test;")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE issuance_service.passport_beta_batch_intents")
        .execute(&pool)
        .await
        .unwrap();
    assert!(migration::validate_passport(&pool).await.is_err());
    migration::migrate_passport(&pool).await.unwrap();
    sqlx::raw_sql(
        "ALTER TABLE issuance_service.passport_beta_batch_intents
           DROP CONSTRAINT ck_passport_beta_batch_send_attempts;
         ALTER TABLE issuance_service.passport_beta_batch_intents
           ADD CONSTRAINT ck_passport_beta_batch_send_attempts CHECK (true);",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(migration::validate_passport(&pool).await.is_err());
    sqlx::query(
        "ALTER TABLE issuance_service.passport_beta_batch_intents
         DROP CONSTRAINT ck_passport_beta_batch_send_attempts",
    )
    .execute(&pool)
    .await
    .unwrap();
    migration::migrate_passport(&pool).await.unwrap();

    let key_a = "a".repeat(32);
    let key_b = "b".repeat(32);
    let keyring = PassportTenantKeyring::from_json(&format!(
        "{{\"org-a\":\"{key_a}\",\"org-b\":\"{key_b}\"}}"
    ))
    .unwrap();
    let org_a = keyring.authenticate(Some("org-a"), Some(&key_a)).unwrap();
    let org_b = keyring.authenticate(Some("org-b"), Some(&key_b)).unwrap();
    let repository = PostgresPassportRepository::new(pool.clone());
    let now = Utc
        .with_ymd_and_hms(2026, 9, 24, 12, 0, 0)
        .single()
        .unwrap();
    let kms = passport_mock_artifact_kms::start().await;
    let cipher = kms.cipher.clone();
    let artifact: PassportSensitiveArtifact = serde_json::from_value(serde_json::json!({
        "applicant": {"synthetic": "test-person"},
        "mrz": {"line_1": "P<TEST", "line_2": "SYNTHETIC"},
        "data_groups": {"DG1": "UkR4", "DG2": "UkR5"}
    }))
    .unwrap();
    let encrypted_artifact = cipher.encrypt("org-a", "job-a", &artifact).await.unwrap();
    let job = PassportJobInsert {
        id: "job-a".into(),
        application_id: "application-a".into(),
        flow_execution_id: "flow-a".into(),
        application_template_id: "template-a".into(),
        credential_template_id: "credential-a".into(),
        revocation_profile_id: Some("revocation-a".into()),
        delivery_destination_profile_id: "destination-a".into(),
        document_type: "TD2".into(),
        country_code: "USA".into(),
        issuer_did: Some("did:web:issuer.example:orgs:org-a".into()),
        secure_artifact_ciphertext: encrypted_artifact.clone(),
        secure_artifact_reference: "physical-artifact://job-a".into(),
    };
    let inserted = repository.insert(&org_a, &job, now).await.unwrap();
    assert_eq!(inserted.organization_id, "org-a");
    assert_eq!(inserted.status, "DRAFT");
    assert_eq!(inserted.document_type, "TD2");
    assert_eq!(
        inserted.issuer_did.as_deref(),
        Some("did:web:issuer.example:orgs:org-a")
    );
    assert!(!inserted.secure_artifact_ciphertext.contains("test-person"));
    assert_eq!(
        inserted.revocation_profile_id.as_deref(),
        Some("revocation-a")
    );
    assert!(repository
        .get(&org_b, "application-a")
        .await
        .unwrap()
        .is_none());

    // The opt-in internal handoff must retain the same PostgreSQL tenant
    // boundary as the frozen per-tenant keyring, even though both trusted
    // callers now present the same workload credential.
    let internal_token = "synthetic-internal-passport-token-00000001";
    let config = IssuanceServiceConfig::from_values(vec![
        ("PASSPORT_NATIVE_HTTP_ENABLED".into(), "true".into()),
        (
            "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED".into(),
            "true".into(),
        ),
        ("GRPC_SERVICE_TOKEN".into(), internal_token.into()),
        ("DATABASE_URL".into(), database_url.clone()),
    ])
    .unwrap();
    let internal = passport_router(
        PassportHttpService::from_config(&config, pool.clone())
            .unwrap()
            .unwrap(),
    );
    let path = "/v1/passport/applications/application-a/production-status";
    let (status, body) = passport_http_request(
        &internal,
        "GET",
        path,
        Some("org-a"),
        Some(internal_token),
        json!(null),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["organization_id"], "org-a");
    let (status, _) = passport_http_request(
        &internal,
        "GET",
        path,
        Some("org-b"),
        Some(internal_token),
        json!(null),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = passport_http_request(
        &internal,
        "GET",
        path,
        Some("org-a"),
        Some("wrong-token"),
        json!(null),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    pool.close().await;
    let restarted_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .unwrap();
    let restarted = PostgresPassportRepository::new(restarted_pool.clone());
    let recovered = restarted
        .get(&org_a, "application-a")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.secure_artifact_ciphertext, encrypted_artifact);
    assert_eq!(
        cipher
            .decrypt(
                &recovered.organization_id,
                &recovered.id,
                &recovered.secure_artifact_ciphertext
            )
            .await
            .unwrap()
            .mrz,
        artifact.mrz
    );
    assert_eq!(recovered.created_at, now);
    assert!(restarted
        .get(&org_b, "application-a")
        .await
        .unwrap()
        .is_none());

    let next = now + chrono::Duration::minutes(1);
    let patch = PassportJobPatch::new(PassportJobStatus::DataGenerated);
    assert!(restarted
        .update(&org_b, "application-a", "DRAFT", &patch, next)
        .await
        .unwrap()
        .is_none());
    assert!(restarted
        .update(&org_a, "application-a", "SOD_SIGNED", &patch, next)
        .await
        .unwrap()
        .is_none());
    let generated = restarted
        .update(&org_a, "application-a", "DRAFT", &patch, next)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(generated.status, "DATA_GENERATED");
    assert_eq!(generated.updated_at, next);
    assert!(restarted
        .update(&org_a, "application-a", "DRAFT", &patch, next)
        .await
        .unwrap()
        .is_none());

    let mut signed = PassportJobPatch::new(PassportJobStatus::SodSigned);
    signed.sod_sha256 = Some(Some("a".repeat(64)));
    let updated = restarted
        .update(&org_a, "application-a", "DATA_GENERATED", &signed, next)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.sod_sha256.as_deref(), Some("a".repeat(64).as_str()));
    assert!(restarted
        .get(&org_b, "application-a")
        .await
        .unwrap()
        .is_none());

    let mut submitted = PassportJobPatch::new(PassportJobStatus::Submitted);
    submitted.bureau_job_id = Some(Some("bureau-a".into()));
    submitted.bureau_provider_profile_id = Some("provider-a".into());
    submitted.tracking_number = Some(Some("submitted-tracking".into()));
    let submitted_job = restarted
        .update(&org_a, "application-a", "SOD_SIGNED", &submitted, next)
        .await
        .unwrap()
        .unwrap();
    let rotated_provider = IssuanceServiceConfig::from_values(vec![
        ("PASSPORT_NATIVE_HTTP_ENABLED".into(), "true".into()),
        (
            "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED".into(),
            "true".into(),
        ),
        ("GRPC_SERVICE_TOKEN".into(), internal_token.into()),
        ("DATABASE_URL".into(), database_url.clone()),
        (
            "PERSONALIZATION_BUREAU_URL".into(),
            "http://127.0.0.1:1".into(),
        ),
        (
            "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID".into(),
            "provider-b".into(),
        ),
    ])
    .unwrap();
    let rotated_router = passport_router(
        PassportHttpService::from_config(&rotated_provider, restarted_pool.clone())
            .unwrap()
            .unwrap(),
    );
    let (rotation_status, rotation_body) = passport_http_request(
        &rotated_router,
        "GET",
        "/v1/passport/applications/application-a/production-status",
        Some("org-a"),
        Some(internal_token),
        json!(null),
        None,
    )
    .await;
    assert_eq!(
        rotation_status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{rotation_body}"
    );
    assert_eq!(
        rotation_body["detail"],
        "Personalization bureau provider is unavailable for this job"
    );
    assert_eq!(
        restarted
            .get(&org_a, "application-a")
            .await
            .unwrap()
            .unwrap()
            .status,
        submitted_job.status
    );
    let foreign_body = serde_json::to_vec(&serde_json::json!({
        "organization_id": "org-b",
        "bureau_job_id": "bureau-a",
        "status": "SHIPPED"
    }))
    .unwrap();
    let foreign_event = kms.verified_callback(&foreign_body).await;
    assert!(restarted
        .apply_verified_webhook(&foreign_event, next)
        .await
        .unwrap()
        .is_none());
    let queued_body = serde_json::to_vec(&serde_json::json!({
        "organization_id": "org-a", "bureau_job_id": "bureau-a", "status": "QUEUED"
    }))
    .unwrap();
    let queued_event = kms.verified_callback(&queued_body).await;
    let queued_replay = restarted
        .apply_verified_webhook(&queued_event, next + chrono::Duration::seconds(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(queued_replay.status, "SUBMITTED");
    assert_eq!(
        queued_replay.tracking_number.as_deref(),
        Some("submitted-tracking")
    );
    assert_eq!(queued_replay.updated_at, submitted_job.updated_at);
    let queued_with_error_body = serde_json::to_vec(&serde_json::json!({
        "organization_id": "org-a", "bureau_job_id": "bureau-a", "status": "QUEUED",
        "error_message": "bureau accepted the job"
    }))
    .unwrap();
    let queued_with_error = kms.verified_callback(&queued_with_error_body).await;
    let metadata_filled = restarted
        .apply_verified_webhook(&queued_with_error, next + chrono::Duration::seconds(2))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(metadata_filled.status, "SUBMITTED");
    assert_eq!(
        metadata_filled.tracking_number.as_deref(),
        Some("submitted-tracking")
    );
    assert_eq!(
        metadata_filled.error_message.as_deref(),
        Some("bureau accepted the job")
    );
    assert!(metadata_filled.updated_at > queued_replay.updated_at);
    let printing_body = serde_json::to_vec(&serde_json::json!({
        "organization_id": "org-a", "bureau_job_id": "bureau-a", "status": "PRINTING",
        "tracking_number": "   "
    }))
    .unwrap();
    let printing_event = kms.verified_callback(&printing_body).await;
    let printing = restarted
        .apply_verified_webhook(&printing_event, next + chrono::Duration::seconds(3))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(printing.status, "IN_PRODUCTION");
    assert_eq!(
        printing.tracking_number.as_deref(),
        Some("submitted-tracking")
    );
    assert_eq!(printing.error_message, None);
    let body = serde_json::to_vec(&serde_json::json!({
        "organization_id": "org-a",
        "bureau_job_id": "bureau-a",
        "status": "SHIPPED",
        "tracking_number": "tracking-a"
    }))
    .unwrap();
    let signature = kms.callback_signature(&body);
    assert!(kms.rejected_callback(&body, "invalid").await.is_err());
    assert_eq!(
        restarted
            .get(&org_a, "application-a")
            .await
            .unwrap()
            .unwrap()
            .status,
        "IN_PRODUCTION"
    );
    let event = kms
        .webhook_verifier
        .verify(&body, &signature)
        .await
        .unwrap();
    let webhook_updated = restarted
        .apply_verified_webhook(&event, next + chrono::Duration::seconds(4))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(webhook_updated.status, "READY_FOR_ACTIVATION");
    assert_eq!(
        webhook_updated.tracking_number.as_deref(),
        Some("tracking-a")
    );
    let delivered_body = serde_json::to_vec(&serde_json::json!({
        "organization_id": "org-a", "bureau_job_id": "bureau-a", "status": "DELIVERED"
    }))
    .unwrap();
    let delivered_event = kms.verified_callback(&delivered_body).await;
    let delivered_replay = restarted
        .apply_verified_webhook(&delivered_event, next + chrono::Duration::seconds(5))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delivered_replay.status, "READY_FOR_ACTIVATION");
    assert_eq!(
        delivered_replay.tracking_number.as_deref(),
        Some("tracking-a")
    );
    assert_eq!(delivered_replay.updated_at, webhook_updated.updated_at);
    let stale_body = serde_json::to_vec(&serde_json::json!({
        "organization_id": "org-a", "bureau_job_id": "bureau-a", "status": "PRINTING"
    }))
    .unwrap();
    let stale_event = kms.verified_callback(&stale_body).await;
    let unchanged = restarted
        .apply_verified_webhook(&stale_event, next)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.status, "READY_FOR_ACTIVATION");
    assert_eq!(unchanged.tracking_number.as_deref(), Some("tracking-a"));
    let mut quality = PassportJobPatch::new(PassportJobStatus::ReadyForActivation);
    quality.quality_result = Some(Some(serde_json::json!({"passed": true})));
    restarted
        .update(
            &org_a,
            "application-a",
            "READY_FOR_ACTIVATION",
            &quality,
            next,
        )
        .await
        .unwrap()
        .unwrap();
    let mut activated = PassportJobPatch::new(PassportJobStatus::Active);
    activated.completed_at = Some(next);
    activated.secure_artifact_ciphertext = Some(
        cipher
            .encrypted_scrubbed_artifact("org-a", "job-a")
            .await
            .unwrap(),
    );
    let active = restarted
        .update(
            &org_a,
            "application-a",
            "READY_FOR_ACTIVATION",
            &activated,
            next,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.status, "ACTIVE");
    assert_eq!(active.completed_at, Some(next));
    assert!(cipher
        .decrypt(
            &active.organization_id,
            &active.id,
            &active.secure_artifact_ciphertext
        )
        .await
        .is_err());
    let replayed = restarted
        .apply_verified_webhook(&event, next)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replayed.status, "ACTIVE");
    assert_eq!(replayed.completed_at, Some(next));
    assert_eq!(replayed.tracking_number.as_deref(), Some("tracking-a"));

    let second_job = PassportJobInsert {
        id: "job-b".into(),
        application_id: "application-b".into(),
        flow_execution_id: "flow-b".into(),
        application_template_id: "template-b".into(),
        credential_template_id: "credential-b".into(),
        revocation_profile_id: None,
        delivery_destination_profile_id: "destination-b".into(),
        document_type: "TD1".into(),
        country_code: "CAN".into(),
        issuer_did: None,
        secure_artifact_ciphertext: cipher.encrypt("org-b", "job-b", &artifact).await.unwrap(),
        secure_artifact_reference: "physical-artifact://job-b".into(),
    };
    restarted.insert(&org_b, &second_job, now).await.unwrap();
    let mut second_submitted = PassportJobPatch::new(PassportJobStatus::Submitted);
    second_submitted.bureau_job_id = Some(Some("bureau-a".into()));
    second_submitted.bureau_provider_profile_id = Some("provider-b".into());
    let second_submitted_job = restarted
        .update(&org_b, "application-b", "DRAFT", &second_submitted, next)
        .await
        .unwrap()
        .unwrap();
    assert!(restarted
        .fill_missing_bureau_metadata(
            &org_a,
            "application-b",
            "SUBMITTED",
            Some("tracking-b"),
            None,
            next + chrono::Duration::seconds(1),
        )
        .await
        .unwrap()
        .is_none());
    let filled = restarted
        .fill_missing_bureau_metadata(
            &org_b,
            "application-b",
            "SUBMITTED",
            Some("tracking-b"),
            None,
            next + chrono::Duration::seconds(1),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(filled.tracking_number.as_deref(), Some("tracking-b"));
    assert!(filled.updated_at > second_submitted_job.updated_at);
    assert!(restarted
        .fill_missing_bureau_metadata(
            &org_b,
            "application-b",
            "SUBMITTED",
            Some("replacement-b"),
            None,
            next + chrono::Duration::seconds(2),
        )
        .await
        .unwrap()
        .is_none());
    let preserved = restarted
        .get(&org_b, "application-b")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(preserved.tracking_number.as_deref(), Some("tracking-b"));
    assert_eq!(preserved.updated_at, filled.updated_at);
    // A provider may reuse a job ID for a different tenant; the signed
    // organization claim must select exactly that tenant's row.
    let other_body = serde_json::to_vec(&serde_json::json!({
        "organization_id": "org-b",
        "bureau_job_id": "bureau-a",
        "status": "SHIPPED"
    }))
    .unwrap();
    let other_event = kms.verified_callback(&other_body).await;
    let other_updated = restarted
        .apply_verified_webhook(&other_event, next)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(other_updated.organization_id, "org-b");
    assert_eq!(other_updated.tracking_number.as_deref(), Some("tracking-b"));
    assert_eq!(
        restarted
            .get(&org_b, "application-b")
            .await
            .unwrap()
            .unwrap()
            .status,
        "READY_FOR_ACTIVATION"
    );
    assert_eq!(
        restarted
            .get(&org_a, "application-a")
            .await
            .unwrap()
            .unwrap()
            .status,
        "ACTIVE"
    );
    assert_eq!(
        restarted
            .resolve_provider_callback_tenant("provider-a", "bureau-a")
            .await
            .unwrap()
            .as_deref(),
        Some("org-a")
    );
    assert_eq!(
        restarted
            .resolve_provider_callback_tenant("provider-b", "bureau-a")
            .await
            .unwrap()
            .as_deref(),
        Some("org-b")
    );
    assert!(restarted
        .resolve_provider_callback_tenant("provider-foreign", "bureau-a")
        .await
        .unwrap()
        .is_none());
    assert!(restarted
        .resolve_provider_callback_tenant("provider-a", "missing")
        .await
        .unwrap()
        .is_none());
    assert!(restarted
        .resolve_provider_callback_tenant("", "bureau-a")
        .await
        .is_err());
    assert!(sqlx::query(
        "UPDATE issuance_service.physical_document_jobs
         SET bureau_provider_profile_id='provider-a' WHERE id='job-b'",
    )
    .execute(&restarted_pool)
    .await
    .is_err());
    assert_eq!(
        restarted
            .resolve_provider_callback_tenant("provider-b", "bureau-a")
            .await
            .unwrap()
            .as_deref(),
        Some("org-b")
    );

    // A same-name but nonunique partial-upgrade index cannot bypass the
    // provider/job uniqueness gate on restart.
    sqlx::query("DROP INDEX issuance_service.ux_physical_document_jobs_bureau_provider_job")
        .execute(&restarted_pool)
        .await
        .unwrap();
    sqlx::query(
        "CREATE INDEX ux_physical_document_jobs_bureau_provider_job
         ON issuance_service.physical_document_jobs (bureau_provider_profile_id, bureau_job_id)
         WHERE bureau_provider_profile_id IS NOT NULL AND bureau_job_id IS NOT NULL",
    )
    .execute(&restarted_pool)
    .await
    .unwrap();
    assert!(migration::migrate_passport(&restarted_pool).await.is_err());
    sqlx::query("DROP INDEX issuance_service.ux_physical_document_jobs_bureau_provider_job")
        .execute(&restarted_pool)
        .await
        .unwrap();
    migration::migrate_passport(&restarted_pool).await.unwrap();

    // Simulate a partially upgraded database with duplicate bound provider
    // jobs. Both lookup and restart migration must fail before choosing a tenant.
    sqlx::query("DROP INDEX issuance_service.ux_physical_document_jobs_bureau_provider_job")
        .execute(&restarted_pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE issuance_service.physical_document_jobs
         SET bureau_provider_profile_id='provider-a' WHERE id='job-b'",
    )
    .execute(&restarted_pool)
    .await
    .unwrap();
    assert!(restarted
        .resolve_provider_callback_tenant("provider-a", "bureau-a")
        .await
        .is_err());
    assert!(migration::migrate_passport(&restarted_pool).await.is_err());
    sqlx::query(
        "UPDATE issuance_service.physical_document_jobs
         SET bureau_provider_profile_id='provider-b' WHERE id='job-b'",
    )
    .execute(&restarted_pool)
    .await
    .unwrap();
    migration::migrate_passport(&restarted_pool).await.unwrap();
    // The same tenant can receive the same bureau job ID from two distinct
    // providers. A signed provider claim selects only its bound row; an older
    // two-field callback remains ambiguous and cannot update either row.
    let colliding_job = PassportJobInsert {
        id: "job-provider-c".into(),
        application_id: "application-provider-c".into(),
        flow_execution_id: "flow-provider-c".into(),
        application_template_id: "template-provider-c".into(),
        credential_template_id: "credential-provider-c".into(),
        revocation_profile_id: None,
        delivery_destination_profile_id: "destination-provider-c".into(),
        document_type: "TD1".into(),
        country_code: "USA".into(),
        issuer_did: None,
        secure_artifact_ciphertext: "synthetic-encrypted-artifact".into(),
        secure_artifact_reference: "physical-artifact://provider-c".into(),
    };
    restarted.insert(&org_a, &colliding_job, now).await.unwrap();
    let mut colliding_submission = PassportJobPatch::new(PassportJobStatus::Submitted);
    colliding_submission.bureau_job_id = Some(Some("bureau-a".into()));
    colliding_submission.bureau_provider_profile_id = Some("provider-c".into());
    restarted
        .update(
            &org_a,
            "application-provider-c",
            "DRAFT",
            &colliding_submission,
            next,
        )
        .await
        .unwrap()
        .unwrap();
    let signed_event = |provider_profile_id: Option<&str>| {
        let mut body = serde_json::json!({
            "organization_id": "org-a",
            "bureau_job_id": "bureau-a",
            "status": "SHIPPED",
        });
        if let Some(provider_profile_id) = provider_profile_id {
            body["provider_profile_id"] = serde_json::json!(provider_profile_id);
        }
        serde_json::to_vec(&body).unwrap()
    };
    let unsigned_event = signed_event(None);
    let unsigned_event = kms.verified_callback(&unsigned_event).await;
    assert!(restarted
        .apply_verified_webhook(&unsigned_event, next)
        .await
        .is_err());
    let foreign_event = signed_event(Some("provider-foreign"));
    let foreign_event = kms.verified_callback(&foreign_event).await;
    assert!(restarted
        .apply_verified_webhook(&foreign_event, next)
        .await
        .unwrap()
        .is_none());
    let provider_c_event = signed_event(Some("provider-c"));
    let provider_c_event = kms.verified_callback(&provider_c_event).await;
    let provider_c_updated = restarted
        .apply_verified_webhook(&provider_c_event, next)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(provider_c_updated.application_id, "application-provider-c");
    assert_eq!(provider_c_updated.status, "READY_FOR_ACTIVATION");
    assert_eq!(
        restarted
            .get(&org_a, "application-a")
            .await
            .unwrap()
            .unwrap()
            .status,
        "ACTIVE"
    );
    type ObservedCallbacks = Arc<Mutex<Vec<Vec<u8>>>>;
    type ProviderSignatures = Arc<Mutex<BTreeMap<String, (String, Vec<u8>)>>>;
    async fn mock_callback_signer(
        State((signed, _, _)): State<(ObservedCallbacks, ObservedCallbacks, ProviderSignatures)>,
        Path(organization_id): Path<String>,
        headers: HeaderMap,
        Json(request): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        assert_eq!(organization_id, "org-a");
        if headers["x-api-key"] != "dedicated-ingress-signing-key" {
            return (StatusCode::UNAUTHORIZED, Json(json!({"detail": "denied"})));
        }
        let body = STANDARD
            .decode(request["body_b64"].as_str().unwrap())
            .unwrap();
        signed.lock().unwrap().push(body);
        (
            StatusCode::OK,
            Json(json!({"signature": format!("vault:v1:{}", STANDARD.encode([7u8; 32]))})),
        )
    }
    async fn mock_native_callback(
        State((_, delivered, _)): State<(ObservedCallbacks, ObservedCallbacks, ProviderSignatures)>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Json<Value> {
        assert_eq!(
            headers["x-personalization-signature"],
            format!("vault:v1:{}", STANDARD.encode([7u8; 32]))
        );
        delivered.lock().unwrap().push(body.to_vec());
        Json(json!({"accepted": true}))
    }
    async fn mock_provider_verifier(
        State((_, _, signatures)): State<(
            ObservedCallbacks,
            ObservedCallbacks,
            ProviderSignatures,
        )>,
        Path(profile_id): Path<String>,
        headers: HeaderMap,
        Json(request): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        if headers["x-api-key"] != "dedicated-ingress-signing-key" {
            return (StatusCode::UNAUTHORIZED, Json(json!({"detail": "denied"})));
        }
        let body = STANDARD
            .decode(request["body_b64"].as_str().unwrap())
            .unwrap();
        let valid = request["signature_hex"].as_str().is_some_and(|signature| {
            signatures.lock().unwrap().get(signature).is_some_and(
                |(expected_profile, expected_body)| {
                    expected_profile == &profile_id && expected_body == &body
                },
            )
        }) && request["key_version"] == 1;
        (StatusCode::OK, Json(json!({"valid": valid})))
    }
    let signed = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let delivered = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let signatures: ProviderSignatures = Arc::new(Mutex::new(BTreeMap::new()));
    let mock = Router::new()
        .route(
            "/internal/documents/{organization_id}/passport-callbacks/sign",
            post(mock_callback_signer),
        )
        .route(
            "/v1/passport/webhooks/personalization",
            post(mock_native_callback),
        )
        .route(
            "/internal/documents/{profile_id}/passport-provider-callbacks/verify",
            post(mock_provider_verifier),
        )
        .with_state((signed.clone(), delivered.clone(), signatures.clone()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let mock_server = tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
    let ingress_state = ProviderIngressState {
        provider_profile_id: "provider-a".into(),
        provider_hmac_key_version: 1,
        repository: PostgresPassportRepository::new(restarted_pool.clone()),
        signing_base_url: url::Url::parse(&format!("{base_url}/internal/documents")).unwrap(),
        signing_api_key: "dedicated-ingress-signing-key".into(),
        native_callback_url: url::Url::parse(&format!(
            "{base_url}/v1/passport/webhooks/personalization"
        ))
        .unwrap(),
        http: reqwest::Client::new(),
    };
    let ingress = provider_ingress_router(ingress_state.clone());
    let raw_provider_body =
        br#"{"bureau_job_id":"bureau-a","status":"SHIPPED","tracking_number":"TRACK-42"}"#;
    let provider_signature = "aa".repeat(32);
    signatures.lock().unwrap().insert(
        provider_signature.clone(),
        ("provider-a".into(), raw_provider_body.to_vec()),
    );
    let (status, _) = provider_ingress_request(&ingress, raw_provider_body, "00").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(signed.lock().unwrap().is_empty());
    let tampered =
        br#"{"bureau_job_id":"bureau-a","status":"FAILED","tracking_number":"TRACK-42"}"#;
    let (status, _) = provider_ingress_request(&ingress, tampered, &provider_signature).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(signed.lock().unwrap().is_empty());
    let forged =
        br#"{"bureau_job_id":"bureau-a","status":"SHIPPED","organization_id":"org-foreign"}"#;
    let forged_signature = "bb".repeat(32);
    signatures.lock().unwrap().insert(
        forged_signature.clone(),
        ("provider-a".into(), forged.to_vec()),
    );
    let (status, _) = provider_ingress_request(&ingress, forged, &forged_signature).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(signed.lock().unwrap().is_empty());
    let mut foreign_state = ingress_state.clone();
    foreign_state.provider_profile_id = "provider-foreign".into();
    let foreign_signature = "cc".repeat(32);
    signatures.lock().unwrap().insert(
        foreign_signature.clone(),
        ("provider-foreign".into(), raw_provider_body.to_vec()),
    );
    let (status, _) = provider_ingress_request(
        &provider_ingress_router(foreign_state),
        raw_provider_body,
        &foreign_signature,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(signed.lock().unwrap().is_empty());
    let mut unavailable_signer = ingress_state;
    unavailable_signer.signing_api_key = "wrong-credential".into();
    let (status, _) = provider_ingress_request(
        &provider_ingress_router(unavailable_signer),
        raw_provider_body,
        &provider_signature,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(signed.lock().unwrap().is_empty());
    assert!(delivered.lock().unwrap().is_empty());
    let (status, body) =
        provider_ingress_request(&ingress, raw_provider_body, &provider_signature).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"accepted": true}));
    let expected_internal = br#"{"organization_id":"org-a","provider_profile_id":"provider-a","bureau_job_id":"bureau-a","status":"SHIPPED","tracking_number":"TRACK-42"}"#;
    assert_eq!(
        signed.lock().unwrap().as_slice(),
        &[expected_internal.to_vec()]
    );
    assert_eq!(
        delivered.lock().unwrap().as_slice(),
        &[expected_internal.to_vec()]
    );
    mock_server.abort();
    exercise_native_passport_http(
        &restarted_pool,
        restarted,
        keyring,
        cipher,
        &kms,
        &key_a,
        &key_b,
    )
    .await;
    let profile_repository = PostgresPassportRepository::new(restarted_pool.clone());
    let profile_job = profile_repository
        .insert(
            &org_a,
            &PassportJobInsert {
                id: "profile-intent-job".into(),
                application_id: "profile-intent-application".into(),
                flow_execution_id: "profile-intent-flow".into(),
                application_template_id: "profile-template".into(),
                credential_template_id: "profile-credential".into(),
                revocation_profile_id: None,
                delivery_destination_profile_id: "profile-destination".into(),
                document_type: "TD1".into(),
                country_code: "USA".into(),
                issuer_did: None,
                secure_artifact_ciphertext: "encrypted-test".into(),
                secure_artifact_reference: "physical-artifact://profile-intent-job".into(),
            },
            Utc::now(),
        )
        .await
        .unwrap();
    let endpoint_sha256 = "a".repeat(64);
    let signing_provenance = serde_json::json!({
        "signing_mode": "managed-issuer-profile",
        "artifact_custody": "kms",
        "issuer_did": "did:web:issuer.example:orgs:org-a",
        "dsc_der_sha256": "dsc-digest",
        "csca_der_sha256": "csca-digest",
        "validated_at": Utc::now(),
    });
    let pinned = profile_repository
        .reserve_submission(
            &org_a,
            &profile_job,
            &PassportSubmissionReservation {
                intent_id: uuid::Uuid::new_v4(),
                sod_sha256: "b",
                signed_artifact_ciphertext: None,
                provider_profile_id: Some("passport-beta-bureau"),
                bureau_endpoint_sha256: &endpoint_sha256,
                signing_provenance: Some(&signing_provenance),
                now: Utc::now(),
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        pinned.submission_intent_provider_profile_id.as_deref(),
        Some("passport-beta-bureau")
    );
    assert_eq!(
        pinned.submission_intent_bureau_endpoint_sha256.as_deref(),
        Some(endpoint_sha256.as_str())
    );
    assert_eq!(
        pinned.submission_intent_signing_provenance,
        Some(signing_provenance)
    );
    sqlx::raw_sql(include_str!("../src/bin/passport_beta_bureau_schema.sql"))
        .execute(&restarted_pool)
        .await
        .unwrap();
    let beta_uuid = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO issuance_service.passport_beta_bureau_jobs
         (bureau_job_id, organization_id, source_job_id, request_sha256,
          content_sha256, sod_der_sha256, dsc_der_sha256, dsc_pem_wire_sha256,
          document_type, status)
         VALUES ($1,'org-a','profile-intent-job',$2,$3,$4,$5,$6,'TD1','QUEUED')",
    )
    .bind(beta_uuid)
    .bind(vec![9_u8; 32])
    .bind(vec![1_u8; 32])
    .bind(vec![2_u8; 32])
    .bind(vec![3_u8; 32])
    .bind(vec![4_u8; 32])
    .execute(&restarted_pool)
    .await
    .unwrap();
    assert!(profile_repository
        .beta_material_receipt(&org_b, "profile-intent-job")
        .await
        .unwrap()
        .is_none());
    let receipt = profile_repository
        .beta_material_receipt(&org_a, "profile-intent-job")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.bureau_job_id, beta_uuid);
    assert_eq!(receipt.sod_der_sha256, Some(vec![2_u8; 32]));
    assert!(receipt.first_accepted_at <= Utc::now() + chrono::Duration::seconds(30));
    let mut pair = Vec::new();
    for suffix in ["a", "b"] {
        pair.push(
            profile_repository
                .insert(
                    &org_a,
                    &PassportJobInsert {
                        id: format!("batch-reservation-job-{suffix}"),
                        application_id: format!("batch-reservation-application-{suffix}"),
                        flow_execution_id: format!("batch-reservation-flow-{suffix}"),
                        application_template_id: "profile-template".into(),
                        credential_template_id: "profile-credential".into(),
                        revocation_profile_id: None,
                        delivery_destination_profile_id: "profile-destination".into(),
                        document_type: "TD1".into(),
                        country_code: "USA".into(),
                        issuer_did: Some("did:web:issuer.example:orgs:org-a".into()),
                        secure_artifact_ciphertext: "encrypted-pair-test".into(),
                        secure_artifact_reference: format!(
                            "physical-artifact://batch-reservation-job-{suffix}"
                        ),
                    },
                    Utc::now(),
                )
                .await
                .unwrap(),
        );
    }
    for (index, job) in pair.iter_mut().enumerate() {
        let mut signed = PassportJobPatch::new(PassportJobStatus::SodSigned);
        signed.sod_sha256 = Some(Some(if index == 0 { "02" } else { "12" }.repeat(32)));
        *job = profile_repository
            .update(
                &org_a,
                &job.application_id,
                &job.status,
                &signed,
                Utc::now(),
            )
            .await
            .unwrap()
            .unwrap();
    }
    sqlx::raw_sql(include_str!("../../flow/migrations/0001_flow_schema.sql"))
        .execute(&restarted_pool)
        .await
        .unwrap();
    let physical_steps = [
        "accept_application",
        "validate_evidence",
        "approval_decision",
        "generate_data_groups",
        "sign_sod",
        "submit_to_personalization",
        "track_production",
        "quality_verify",
        "activate_credential",
    ];
    let flow_steps = physical_steps
        .iter()
        .map(|name| json!({"id": name, "config": {"protocol_step": name}}))
        .collect::<Vec<_>>();
    sqlx::query(
        "INSERT INTO flow_service.flow_definitions
         (id, organization_id, name, status, flow_type, steps,
          credential_template_id, application_template_id,
          delivery_destination_profile_id)
         VALUES ('batch-flow-definition','org-a','Beta batch Flow','ACTIVE',
                 'physical_document_issuance',$1,$2,$3,$4)",
    )
    .bind(json!(flow_steps))
    .bind(&pair[0].credential_template_id)
    .bind(&pair[0].application_template_id)
    .bind(&pair[0].delivery_destination_profile_id)
    .execute(&restarted_pool)
    .await
    .unwrap();
    let flow_context = json!({
        "application_id": pair[0].application_id,
        "physical_document_job": {
            "id": pair[0].id,
            "organization_id": "org-a",
            "flow_execution_id": pair[0].flow_execution_id,
            "application_id": pair[0].application_id,
            "issuer_did": pair[0].issuer_did,
            "sod_sha256": pair[0].sod_sha256,
            "sod_signature_verified": true,
            "status": "SOD_SIGNED",
        },
        "step_results": {"sign_sod": {"result": " SUCCESS ", "completed_at": Utc::now().to_rfc3339()}},
    });
    let flow_history = json!([
        {"step_id": "sign_sod", "status": "entered", "result": " Success ",
         "completed_at": Utc::now().to_rfc3339()},
        {"step_id": "submit_to_personalization", "status": "entered",
         "entered_at": Utc::now().to_rfc3339()},
    ]);
    sqlx::query(
        "INSERT INTO flow_service.flow_instances
         (id, flow_definition_id, organization_id, status, current_step_id,
          context, step_history)
         VALUES ($1,'batch-flow-definition','org-a','in_progress',
                 'submit_to_personalization',$2,$3)",
    )
    .bind(&pair[0].flow_execution_id)
    .bind(&flow_context)
    .bind(flow_history)
    .execute(&restarted_pool)
    .await
    .unwrap();
    let occupied_intent = uuid::Uuid::new_v4();
    let occupied = profile_repository
        .reserve_submission(
            &org_a,
            &pair[1],
            &PassportSubmissionReservation {
                intent_id: occupied_intent,
                sod_sha256: "occupied-sod",
                signed_artifact_ciphertext: None,
                provider_profile_id: Some("passport-beta-bureau"),
                bureau_endpoint_sha256: &endpoint_sha256,
                signing_provenance: None,
                now: Utc::now(),
            },
        )
        .await
        .unwrap()
        .unwrap();
    let first_batch_intent = uuid::Uuid::new_v4();
    let second_batch_intent = uuid::Uuid::new_v4();
    let batch_time = Utc::now();
    let batch_signing_provenance = json!({
        "signing_mode": "managed-issuer-profile",
        "artifact_custody": "kms",
        "issuer_did": "did:web:issuer.example:orgs:org-a",
        "issuer_profile_id": "synthetic-passport-issuer-profile",
    });
    let batch_reservations = [
        PassportSubmissionReservation {
            intent_id: first_batch_intent,
            sod_sha256: "0202020202020202020202020202020202020202020202020202020202020202",
            signed_artifact_ciphertext: None,
            provider_profile_id: Some("passport-beta-bureau"),
            bureau_endpoint_sha256: &endpoint_sha256,
            signing_provenance: Some(&batch_signing_provenance),
            now: batch_time,
        },
        PassportSubmissionReservation {
            intent_id: second_batch_intent,
            sod_sha256: "1212121212121212121212121212121212121212121212121212121212121212",
            signed_artifact_ciphertext: None,
            provider_profile_id: Some("passport-beta-bureau"),
            bureau_endpoint_sha256: &endpoint_sha256,
            signing_provenance: Some(&batch_signing_provenance),
            now: batch_time,
        },
    ];
    let batch_selected_flow = pair[0].flow_execution_id.clone();
    let batch_selected_id = pair[0].id.clone();
    let batch_companion_id = pair[1].id.clone();
    let batch_identity = PassportBatchIdentity {
        batch_id: uuid::Uuid::new_v4(),
        selected_flow_instance_id: &batch_selected_flow,
        selected_job_id: &batch_selected_id,
        companion_job_id: &batch_companion_id,
    };
    assert!(profile_repository
        .reserve_batch_submissions(
            &org_a,
            [&pair[0], &pair[1]],
            [&batch_reservations[0], &batch_reservations[1]],
            &batch_identity,
        )
        .await
        .unwrap()
        .is_none());
    assert!(profile_repository
        .get(&org_a, &pair[0].application_id)
        .await
        .unwrap()
        .unwrap()
        .submission_intent_id
        .is_none());
    let mut release = PassportJobPatch::new(PassportJobStatus::SodSigned);
    release.expected_submission_intent_id = Some(occupied_intent);
    release.clear_submission_intent = true;
    release.sod_sha256 = Some(Some("12".repeat(32)));
    let released = profile_repository
        .update(
            &org_a,
            &occupied.application_id,
            &occupied.status,
            &release,
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap();
    sqlx::query("UPDATE flow_service.flow_instances SET status='cancelled' WHERE id=$1")
        .bind(&pair[0].flow_execution_id)
        .execute(&restarted_pool)
        .await
        .unwrap();
    assert!(profile_repository
        .reserve_batch_submissions(
            &org_a,
            [&pair[0], &released],
            [&batch_reservations[0], &batch_reservations[1]],
            &batch_identity,
        )
        .await
        .unwrap()
        .is_none());
    let premature_batch_identity_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM issuance_service.passport_beta_batch_intents WHERE batch_id=$1",
    )
    .bind(batch_identity.batch_id)
    .fetch_one(&restarted_pool)
    .await
    .unwrap();
    assert_eq!(premature_batch_identity_count, 0);
    sqlx::query("UPDATE flow_service.flow_instances SET status='in_progress' WHERE id=$1")
        .bind(&pair[0].flow_execution_id)
        .execute(&restarted_pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE flow_service.flow_instances
         SET context=jsonb_set(context::jsonb, '{physical_document_job,sod_sha256}',
                               to_jsonb('wrong-flow-sod'::text))::json
         WHERE id=$1",
    )
    .bind(&pair[0].flow_execution_id)
    .execute(&restarted_pool)
    .await
    .unwrap();
    assert!(profile_repository
        .reserve_batch_submissions(
            &org_a,
            [&pair[0], &released],
            [&batch_reservations[0], &batch_reservations[1]],
            &batch_identity,
        )
        .await
        .unwrap()
        .is_none());
    sqlx::query("UPDATE flow_service.flow_instances SET context=$2 WHERE id=$1")
        .bind(&pair[0].flow_execution_id)
        .bind(&flow_context)
        .execute(&restarted_pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE flow_service.flow_instances
         SET context=jsonb_set(context::jsonb, '{physical_document_job,issuer_profile_id}',
                               to_jsonb('wrong-issuer-profile'::text))::json
         WHERE id=$1",
    )
    .bind(&pair[0].flow_execution_id)
    .execute(&restarted_pool)
    .await
    .unwrap();
    assert!(profile_repository
        .reserve_batch_submissions(
            &org_a,
            [&pair[0], &released],
            [&batch_reservations[0], &batch_reservations[1]],
            &batch_identity,
        )
        .await
        .unwrap()
        .is_none());
    sqlx::query("UPDATE flow_service.flow_instances SET context=$2 WHERE id=$1")
        .bind(&pair[0].flow_execution_id)
        .bind(&flow_context)
        .execute(&restarted_pool)
        .await
        .unwrap();
    let original_selected_sod = pair[0].sod_sha256.clone();
    let mut conflicting_sod = PassportJobPatch::new(PassportJobStatus::SodSigned);
    conflicting_sod.expected_sod_sha256 = Some(original_selected_sod.clone());
    conflicting_sod.sod_sha256 = Some(Some("33".repeat(32)));
    pair[0] = profile_repository
        .update(
            &org_a,
            &pair[0].application_id,
            &pair[0].status,
            &conflicting_sod,
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(profile_repository
        .reserve_batch_submissions(
            &org_a,
            [&pair[0], &released],
            [&batch_reservations[0], &batch_reservations[1]],
            &batch_identity,
        )
        .await
        .unwrap()
        .is_none());
    let mut restore_sod = PassportJobPatch::new(PassportJobStatus::SodSigned);
    restore_sod.expected_sod_sha256 = Some(pair[0].sod_sha256.clone());
    restore_sod.sod_sha256 = Some(original_selected_sod);
    pair[0] = profile_repository
        .update(
            &org_a,
            &pair[0].application_id,
            &pair[0].status,
            &restore_sod,
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap();
    let correct_source_id = pair[0].id.clone();
    pair[0].id = "stale-preflight-source-id".into();
    assert!(profile_repository
        .reserve_submission(&org_a, &pair[0], &batch_reservations[0])
        .await
        .unwrap()
        .is_none());
    assert!(profile_repository
        .reserve_batch_submissions(
            &org_a,
            [&pair[0], &released],
            [&batch_reservations[0], &batch_reservations[1]],
            &batch_identity,
        )
        .await
        .unwrap()
        .is_none());
    pair[0].id = correct_source_id;
    let reserved_pair = profile_repository
        .reserve_batch_submissions(
            &org_a,
            [&pair[0], &released],
            [&batch_reservations[0], &batch_reservations[1]],
            &batch_identity,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        reserved_pair[0].submission_intent_id,
        Some(first_batch_intent)
    );
    assert_eq!(
        reserved_pair[1].submission_intent_id,
        Some(second_batch_intent)
    );
    assert!(!profile_repository
        .claim_beta_batch_replay(&org_a, batch_identity.batch_id, Utc::now())
        .await
        .unwrap());
    sqlx::query(
        "UPDATE issuance_service.passport_beta_batch_intents
         SET last_send_started_at=$2 WHERE batch_id=$1",
    )
    .bind(batch_identity.batch_id)
    .bind(Utc::now() - chrono::Duration::seconds(131))
    .execute(&restarted_pool)
    .await
    .unwrap();
    assert!(profile_repository
        .mark_beta_batch_first_response(&org_a, &batch_identity, Utc::now())
        .await
        .unwrap());
    assert!(!profile_repository
        .claim_beta_batch_receipt_completion(&org_a, batch_identity.batch_id, Utc::now())
        .await
        .unwrap());
    assert!(!profile_repository
        .mark_beta_batch_first_response(&org_a, &batch_identity, Utc::now())
        .await
        .unwrap());
    assert!(!profile_repository
        .claim_beta_batch_replay(&org_a, batch_identity.batch_id, Utc::now())
        .await
        .unwrap());
    let wire_key_sha256 = "a".repeat(64);
    let wire_commitments = BetaBatchWireCommitments {
        request_commitment: "b".repeat(64),
        response_commitment: "c".repeat(64),
    };
    assert!(profile_repository
        .retain_beta_batch_first_wire(
            &org_a,
            &batch_identity,
            "kms-manifest-string",
            &wire_key_sha256,
            &wire_commitments,
        )
        .await
        .unwrap());
    assert!(!profile_repository
        .retain_beta_batch_first_wire(
            &org_a,
            &batch_identity,
            "replacement-kms-manifest",
            &wire_key_sha256,
            &wire_commitments,
        )
        .await
        .unwrap());
    let retained = profile_repository
        .beta_batch_first_wire_commitments(&org_a, batch_identity.batch_id, &wire_key_sha256)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        retained.request_commitment,
        wire_commitments.request_commitment
    );
    assert_eq!(
        retained.response_commitment,
        wire_commitments.response_commitment
    );
    assert!(profile_repository
        .beta_batch_first_wire_commitments(&org_a, batch_identity.batch_id, &"d".repeat(64))
        .await
        .unwrap()
        .is_none());
    assert!(profile_repository
        .beta_batch_first_wire_commitments(&org_b, batch_identity.batch_id, &wire_key_sha256)
        .await
        .unwrap()
        .is_none());
    assert!(profile_repository
        .claim_beta_batch_receipt_completion(&org_a, batch_identity.batch_id, Utc::now())
        .await
        .unwrap());
    assert!(!profile_repository
        .claim_beta_batch_receipt_completion(&org_a, batch_identity.batch_id, Utc::now())
        .await
        .unwrap());
    sqlx::query(
        "UPDATE issuance_service.passport_beta_batch_intents
         SET last_receipt_completion_started_at=$2 WHERE batch_id=$1",
    )
    .bind(batch_identity.batch_id)
    .bind(Utc::now() - chrono::Duration::seconds(66))
    .execute(&restarted_pool)
    .await
    .unwrap();
    assert!(profile_repository
        .claim_beta_batch_receipt_completion(&org_a, batch_identity.batch_id, Utc::now())
        .await
        .unwrap());
    assert!(!profile_repository
        .claim_beta_batch_receipt_completion(&org_a, batch_identity.batch_id, Utc::now())
        .await
        .unwrap());
    sqlx::query(
        "UPDATE issuance_service.passport_beta_batch_intents
         SET last_receipt_completion_started_at=$2 WHERE batch_id=$1",
    )
    .bind(batch_identity.batch_id)
    .bind(Utc::now() - chrono::Duration::seconds(66))
    .execute(&restarted_pool)
    .await
    .unwrap();
    assert!(profile_repository
        .claim_beta_batch_receipt_completion(&org_a, batch_identity.batch_id, Utc::now())
        .await
        .unwrap());
    let completion_attempts: i64 = sqlx::query_scalar(
        "SELECT receipt_completion_attempts
         FROM issuance_service.passport_beta_batch_intents WHERE batch_id=$1",
    )
    .bind(batch_identity.batch_id)
    .fetch_one(&restarted_pool)
    .await
    .unwrap();
    assert_eq!(completion_attempts, 3);
    assert!(!profile_repository
        .claim_beta_batch_replay(&org_a, batch_identity.batch_id, Utc::now())
        .await
        .unwrap());
    // Reset this disposable row to exercise the alternative one-batch replay.
    sqlx::query(
        "UPDATE issuance_service.passport_beta_batch_intents
         SET send_attempts=1, receipt_completion_attempts=0,
             last_receipt_completion_started_at=NULL, last_send_started_at=$2,
             first_dispatch_response_seen_at=NULL,
             first_dispatch_wire_ciphertext=NULL,
             first_dispatch_wire_key_sha256=NULL,
             first_dispatch_request_commitment=NULL,
             first_dispatch_response_commitment=NULL
         WHERE batch_id=$1",
    )
    .bind(batch_identity.batch_id)
    .bind(Utc::now() - chrono::Duration::seconds(131))
    .execute(&restarted_pool)
    .await
    .unwrap();
    assert!(profile_repository
        .claim_beta_batch_replay(&org_a, batch_identity.batch_id, Utc::now())
        .await
        .unwrap());
    assert!(!profile_repository
        .claim_beta_batch_replay(&org_a, batch_identity.batch_id, Utc::now())
        .await
        .unwrap());
    for job in &reserved_pair {
        assert_eq!(job.submission_batch_id, Some(batch_identity.batch_id));
        assert!(job.submission_batch_signing_provenance.is_none());
        assert!(job.submission_batch_bureau_endpoint_sha256.is_none());
        assert!(job.submission_batch_material_digests.is_none());
        assert_eq!(
            job.submission_batch_selected_flow_instance_id.as_deref(),
            Some(batch_identity.selected_flow_instance_id)
        );
        assert_eq!(
            job.submission_batch_selected_job_id.as_deref(),
            Some(batch_identity.selected_job_id)
        );
        assert_eq!(
            job.submission_batch_companion_job_id.as_deref(),
            Some(batch_identity.companion_job_id)
        );
    }
    assert!(profile_repository
        .beta_batch_jobs(&org_b, batch_identity.batch_id)
        .await
        .unwrap()
        .is_none());
    let replay_pair = profile_repository
        .beta_batch_jobs(&org_a, batch_identity.batch_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replay_pair[0].id, reserved_pair[0].id);
    assert_eq!(replay_pair[1].id, reserved_pair[1].id);
    let mut collision_pair = Vec::new();
    for suffix in ["c", "d"] {
        collision_pair.push(
            profile_repository
                .insert(
                    &org_a,
                    &PassportJobInsert {
                        id: format!("batch-reservation-job-{suffix}"),
                        application_id: format!("batch-reservation-application-{suffix}"),
                        flow_execution_id: format!("batch-reservation-flow-{suffix}"),
                        application_template_id: "profile-template".into(),
                        credential_template_id: "profile-credential".into(),
                        revocation_profile_id: None,
                        delivery_destination_profile_id: "profile-destination".into(),
                        document_type: "TD1".into(),
                        country_code: "USA".into(),
                        issuer_did: Some("did:web:issuer.example:orgs:org-a".into()),
                        secure_artifact_ciphertext: "encrypted-pair-test".into(),
                        secure_artifact_reference: format!(
                            "physical-artifact://batch-reservation-job-{suffix}"
                        ),
                    },
                    Utc::now(),
                )
                .await
                .unwrap(),
        );
    }
    for (index, job) in collision_pair.iter_mut().enumerate() {
        let mut signed = PassportJobPatch::new(PassportJobStatus::SodSigned);
        signed.sod_sha256 = Some(Some(if index == 0 { "02" } else { "12" }.repeat(32)));
        *job = profile_repository
            .update(
                &org_a,
                &job.application_id,
                &job.status,
                &signed,
                Utc::now(),
            )
            .await
            .unwrap()
            .unwrap();
    }
    let collision_identity = PassportBatchIdentity {
        batch_id: batch_identity.batch_id,
        selected_flow_instance_id: &collision_pair[0].flow_execution_id,
        selected_job_id: &collision_pair[0].id,
        companion_job_id: &collision_pair[1].id,
    };
    assert!(profile_repository
        .reserve_batch_submissions(
            &org_a,
            [&collision_pair[0], &collision_pair[1]],
            [&batch_reservations[0], &batch_reservations[1]],
            &collision_identity,
        )
        .await
        .unwrap()
        .is_none());
    for job in &collision_pair {
        assert!(profile_repository
            .get(&org_a, &job.application_id)
            .await
            .unwrap()
            .unwrap()
            .submission_intent_id
            .is_none());
    }
    let batch_guard_keyring = PassportTenantKeyring::from_json(&format!(
        "{{\"org-a\":\"{key_a}\",\"org-b\":\"{key_b}\"}}"
    ))
    .unwrap();
    let batch_guard_router = passport_router(PassportHttpService::new(
        batch_guard_keyring,
        profile_repository.clone(),
        None,
        None,
        None,
    ));
    let (blocked_batch_single_submit, _) = passport_http_request(
        &batch_guard_router,
        "POST",
        &format!(
            "/v1/passport/applications/{}/submit-personalization",
            reserved_pair[0].application_id
        ),
        Some("org-a"),
        Some(&key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(blocked_batch_single_submit, StatusCode::CONFLICT);
    assert_eq!(
        reserved_pair[0].sod_sha256.as_deref(),
        Some(batch_reservations[0].sod_sha256)
    );
    assert_eq!(
        reserved_pair[1].sod_sha256.as_deref(),
        Some(batch_reservations[1].sod_sha256)
    );
    let mut batch_bind_patches = [
        PassportJobPatch::new(PassportJobStatus::Submitted),
        PassportJobPatch::new(PassportJobStatus::Submitted),
    ];
    for (index, (patch, job)) in batch_bind_patches
        .iter_mut()
        .zip(reserved_pair.iter())
        .enumerate()
    {
        patch.expected_submission_intent_id = job.submission_intent_id;
        patch.expected_sod_sha256 = Some(job.sod_sha256.clone());
        patch.expected_secure_artifact_ciphertext = Some(job.secure_artifact_ciphertext.clone());
        patch.clear_submission_intent = true;
        patch.bureau_job_id = Some(Some(uuid::Uuid::new_v4().to_string()));
        patch.bureau_provider_profile_id = Some("passport-beta-bureau".into());
        patch.submitted_at = Some(batch_time);
        assert_eq!(job.application_id, pair[index].application_id);
    }
    let batch_digests = [
        PassportBetaMaterialDigests {
            content_sha256: vec![1; 32],
            legacy_request_sha256: vec![9; 32],
            sod_der_sha256: Some(vec![2; 32]),
            dsc_der_sha256: Some(vec![3; 32]),
            dsc_pem_wire_sha256: vec![4; 32],
        },
        PassportBetaMaterialDigests {
            content_sha256: vec![11; 32],
            legacy_request_sha256: vec![19; 32],
            sod_der_sha256: Some(vec![18; 32]),
            dsc_der_sha256: Some(vec![13; 32]),
            dsc_pem_wire_sha256: vec![14; 32],
        },
    ];
    for (patch, digests) in batch_bind_patches.iter_mut().zip(&batch_digests) {
        patch.submission_batch_material_digests = Some(serde_json::to_value(digests).unwrap());
    }
    let batch_bindings = [
        PassportBetaBatchBinding {
            bureau_job_id: uuid::Uuid::parse_str(
                batch_bind_patches[0]
                    .bureau_job_id
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .unwrap(),
            )
            .unwrap(),
            material_digests: &batch_digests[0],
        },
        PassportBetaBatchBinding {
            bureau_job_id: uuid::Uuid::parse_str(
                batch_bind_patches[1]
                    .bureau_job_id
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .unwrap(),
            )
            .unwrap(),
            material_digests: &batch_digests[1],
        },
    ];
    let batch_destination = PassportBetaBatchDestination {
        provider_profile_id: "passport-beta-bureau",
        endpoint_sha256: &endpoint_sha256,
    };
    assert!(profile_repository
        .bind_batch_submissions(
            &org_a,
            [&reserved_pair[0], &reserved_pair[1]],
            [&batch_bind_patches[0], &batch_bind_patches[1]],
            [&batch_bindings[0], &batch_bindings[1]],
            &batch_destination,
            batch_time,
        )
        .await
        .unwrap()
        .is_none());
    for (index, binding) in batch_bindings.iter().enumerate() {
        let digests = binding.material_digests;
        sqlx::query(
            "INSERT INTO issuance_service.passport_beta_bureau_jobs
             (bureau_job_id, organization_id, source_job_id, request_sha256,
              content_sha256, sod_der_sha256, dsc_der_sha256, dsc_pem_wire_sha256,
              document_type, status)
             VALUES ($1, 'org-a', $2, $3, $4, $5, $6, $7, 'TD1', 'QUEUED')",
        )
        .bind(binding.bureau_job_id)
        .bind(&reserved_pair[index].id)
        .bind(&digests.legacy_request_sha256)
        .bind(&digests.content_sha256)
        .bind(digests.sod_der_sha256.as_ref().unwrap())
        .bind(digests.dsc_der_sha256.as_ref().unwrap())
        .bind(&digests.dsc_pem_wire_sha256)
        .execute(&restarted_pool)
        .await
        .unwrap();
    }
    let wrong_digests = PassportBetaMaterialDigests {
        content_sha256: vec![99; 32],
        legacy_request_sha256: batch_digests[1].legacy_request_sha256.clone(),
        sod_der_sha256: batch_digests[1].sod_der_sha256.clone(),
        dsc_der_sha256: batch_digests[1].dsc_der_sha256.clone(),
        dsc_pem_wire_sha256: batch_digests[1].dsc_pem_wire_sha256.clone(),
    };
    let wrong_binding = PassportBetaBatchBinding {
        bureau_job_id: batch_bindings[1].bureau_job_id,
        material_digests: &wrong_digests,
    };
    assert!(profile_repository
        .bind_batch_submissions(
            &org_a,
            [&reserved_pair[0], &reserved_pair[1]],
            [&batch_bind_patches[0], &batch_bind_patches[1]],
            [&batch_bindings[0], &wrong_binding],
            &batch_destination,
            batch_time,
        )
        .await
        .unwrap()
        .is_none());
    let mut stale_second = profile_repository
        .get(&org_a, &reserved_pair[1].application_id)
        .await
        .unwrap()
        .unwrap();
    stale_second.id = "stale-batch-bind-source-id".into();
    assert!(profile_repository
        .bind_batch_submissions(
            &org_a,
            [&reserved_pair[0], &stale_second],
            [&batch_bind_patches[0], &batch_bind_patches[1]],
            [&batch_bindings[0], &batch_bindings[1]],
            &batch_destination,
            batch_time,
        )
        .await
        .unwrap()
        .is_none());
    let first_after_failed_bind = profile_repository
        .get(&org_a, &reserved_pair[0].application_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first_after_failed_bind.status, reserved_pair[0].status);
    assert_eq!(
        first_after_failed_bind.submission_intent_id,
        reserved_pair[0].submission_intent_id
    );
    assert!(first_after_failed_bind.bureau_job_id.is_none());
    let bound_pair = profile_repository
        .bind_batch_submissions(
            &org_a,
            [&reserved_pair[0], &reserved_pair[1]],
            [&batch_bind_patches[0], &batch_bind_patches[1]],
            [&batch_bindings[0], &batch_bindings[1]],
            &batch_destination,
            batch_time,
        )
        .await
        .unwrap()
        .unwrap();
    for (job, patch) in bound_pair.iter().zip(batch_bind_patches.iter()) {
        assert_eq!(job.status, "SUBMITTED");
        assert_eq!(job.submission_intent_id, None);
        assert_eq!(job.submission_batch_id, Some(batch_identity.batch_id));
        assert_eq!(
            job.submission_batch_signing_provenance.as_ref(),
            Some(&batch_signing_provenance)
        );
        assert_eq!(
            job.submission_batch_bureau_endpoint_sha256.as_deref(),
            Some(endpoint_sha256.as_str())
        );
        assert_eq!(
            job.submission_batch_material_digests.as_ref(),
            patch.submission_batch_material_digests.as_ref()
        );
        assert_eq!(job.bureau_job_id, patch.bureau_job_id.clone().flatten());
        assert_eq!(
            job.submitted_at,
            reserved_pair[0].submission_intent_started_at
        );
    }
    let bound_replay_pair = profile_repository
        .beta_batch_jobs(&org_a, batch_identity.batch_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bound_replay_pair[0].id, bound_pair[0].id);
    assert_eq!(bound_replay_pair[1].id, bound_pair[1].id);
    let (bound_batch_single_submit, bound_response) = passport_http_request(
        &batch_guard_router,
        "POST",
        &format!(
            "/v1/passport/applications/{}/submit-personalization",
            bound_pair[0].application_id
        ),
        Some("org-a"),
        Some(&key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(bound_batch_single_submit, StatusCode::OK);
    assert_eq!(
        bound_response["bureau_job_id"].as_str(),
        bound_pair[0].bureau_job_id.as_deref()
    );

    // Upgrade a populated released Python table rather than only testing a
    // fresh Rust table. The existing row and its original column type survive.
    sqlx::raw_sql(include_str!(
        "fixtures/physical_document_jobs_python_base.sql"
    ))
    .execute(&restarted_pool)
    .await
    .unwrap();
    migration::migrate_passport(&restarted_pool).await.unwrap();
    migration::migrate_passport(&restarted_pool).await.unwrap();
    let released: (String, Option<String>, String, Option<String>) = sqlx::query_as(
        "SELECT status, revocation_profile_id, document_type, issuer_did \
         FROM issuance_service.physical_document_jobs WHERE id='released-python-job'",
    )
    .fetch_one(&restarted_pool)
    .await
    .unwrap();
    assert_eq!(released, ("DRAFT".into(), None, "TD2".into(), None));
    let legacy_provider: Option<String> = sqlx::query_scalar(
        "SELECT bureau_provider_profile_id FROM issuance_service.physical_document_jobs
         WHERE id='released-python-job'",
    )
    .fetch_one(&restarted_pool)
    .await
    .unwrap();
    assert!(legacy_provider.is_none());
    let legacy_intent: (Option<uuid::Uuid>, Option<chrono::DateTime<Utc>>) = sqlx::query_as(
        "SELECT submission_intent_id, submission_intent_started_at
         FROM issuance_service.physical_document_jobs WHERE id='released-python-job'",
    )
    .fetch_one(&restarted_pool)
    .await
    .unwrap();
    assert_eq!(legacy_intent, (None, None));
    sqlx::query(
        "UPDATE issuance_service.physical_document_jobs
         SET bureau_job_id='bureau-a' WHERE id='released-python-job'",
    )
    .execute(&restarted_pool)
    .await
    .unwrap();
    // The fixture drops and recreates the table with the released varchar
    // shape, so use a new connection without the pre-upgrade prepared plan.
    let upgraded_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .unwrap();
    assert!(PostgresPassportRepository::new(upgraded_pool.clone())
        .resolve_provider_callback_tenant("provider-a", "bureau-a")
        .await
        .unwrap()
        .is_none());
    upgraded_pool.close().await;
    let id_type: String = sqlx::query_scalar(
        "SELECT data_type FROM information_schema.columns \
         WHERE table_schema='issuance_service' AND table_name='physical_document_jobs' \
           AND column_name='id'",
    )
    .fetch_one(&restarted_pool)
    .await
    .unwrap();
    assert_eq!(id_type, "character varying");
    let indexes: Vec<String> = sqlx::query_scalar(
        "SELECT indexname FROM pg_indexes \
         WHERE schemaname='issuance_service' AND tablename='physical_document_jobs'",
    )
    .fetch_all(&restarted_pool)
    .await
    .unwrap();
    for index in [
        "ix_physical_document_jobs_organization_id",
        "ix_physical_document_jobs_flow_execution_id",
        "ix_physical_document_jobs_status",
        "ix_physical_document_jobs_bureau_job_id",
        "ux_physical_document_jobs_bureau_provider_job",
    ] {
        assert!(indexes.iter().any(|existing| existing == index));
    }
    kms.server.abort();
}
