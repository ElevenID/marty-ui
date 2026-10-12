//! Local disposable Postgres gate for the Canvas badge/application template pair.

use marty_canvas_demo_seed::{seed_open_badge_templates, GatewaySeedConfig};
use serde_json::{json, Value};
use sqlx::{Connection, PgConnection};
use std::{env, process, time::SystemTime};
use url::Url;

fn config() -> GatewaySeedConfig {
    GatewaySeedConfig {
        base_url: "http://localhost:8000".into(),
        organization_id: "org-1".into(),
        canvas_account_id: "account-1".into(),
        credential_template_id: "ct-1".into(),
        application_template_id: "at-1".into(),
        display_name: "Canvas Demo".into(),
        canvas_base_url: "https://canvas.example".into(),
        lti_client_id: "client-1".into(),
        lti_deployment_id: "deployment-1".into(),
        probe_after_upsert: false,
        program_binding_display_name: "Program Demo".into(),
        program_binding_evidence_type: "canvas.quiz_score".into(),
        program_binding_delivery_mode: "wallet_plus_canvas_mirror".into(),
        program_binding_auto_approve: true,
        program_binding_direct_issue: false,
        program_binding_score_threshold: 80,
        signing_keys_internal_base_url: "http://signing-keys:8000".into(),
    }
}

async fn exec(conn: &mut PgConnection, sql: &str) {
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .execute(conn)
        .await
        .unwrap();
}

fn table_ddl(migration: &str, start: &str) -> String {
    let (_, tail) = migration.split_once(start).expect("migration table DDL");
    let (body, _) = tail.split_once("\n);").expect("migration table end");
    format!("{start}{body}\n);")
}

async fn run_case(url: &Url) {
    let mut conn = PgConnection::connect(url.as_str()).await.unwrap();
    exec(&mut conn, "CREATE SCHEMA credential_template_service").await;
    exec(&mut conn, "CREATE SCHEMA issuance_service").await;
    let credential_migration = include_str!(
        "../../../services/credential-template/migrations/0001_credential_template_schema.sql"
    );
    let issuance_migration =
        include_str!("../../../services/issuance/migrations/0000_issuance_service_baseline.sql");
    exec(
        &mut conn,
        &table_ddl(
            credential_migration,
            "CREATE TABLE IF NOT EXISTS credential_template_service.credential_templates (",
        ),
    )
    .await;
    exec(
        &mut conn,
        &table_ddl(
            issuance_migration,
            "CREATE TABLE issuance_service.application_templates (",
        ),
    )
    .await;
    exec(&mut conn, "ALTER TABLE issuance_service.application_templates ADD CONSTRAINT application_templates_pkey PRIMARY KEY (id)").await;
    drop(conn);

    let cfg = config();
    let initial_scope = json!({});
    seed_open_badge_templates(url.as_str(), &cfg, &initial_scope)
        .await
        .unwrap();
    let mut conn = PgConnection::connect(url.as_str()).await.unwrap();
    let (credential_count, application_count): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM credential_template_service.credential_templates), (SELECT count(*) FROM issuance_service.application_templates)",
    ).fetch_one(&mut conn).await.unwrap();
    assert_eq!((credential_count, application_count), (1, 1));
    drop(conn);

    let scoped = json!({"course_id": "42", "quiz_id": "9"});
    seed_open_badge_templates(url.as_str(), &cfg, &scoped)
        .await
        .unwrap();
    let mut conn = PgConnection::connect(url.as_str()).await.unwrap();
    let (credential_count, application_count): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM credential_template_service.credential_templates), (SELECT count(*) FROM issuance_service.application_templates)",
    ).fetch_one(&mut conn).await.unwrap();
    assert_eq!((credential_count, application_count), (1, 1));
    let ui: Value = sqlx::query_scalar(
        "SELECT ui_config::jsonb FROM issuance_service.application_templates WHERE id='at-1'",
    )
    .fetch_one(&mut conn)
    .await
    .unwrap();
    assert_eq!(ui["scope"], scoped);

    // Legacy schemas can still carry remote-signing and auto-approval columns.
    exec(&mut conn, "ALTER TABLE credential_template_service.credential_templates ADD COLUMN key_access_mode text, ADD COLUMN issuer_key_id text, ADD COLUMN remote_signing_config jsonb").await;
    exec(
        &mut conn,
        "ALTER TABLE issuance_service.application_templates ADD COLUMN auto_approval_rules json",
    )
    .await;
    drop(conn);
    seed_open_badge_templates(url.as_str(), &cfg, &scoped)
        .await
        .unwrap();
    let mut conn = PgConnection::connect(url.as_str()).await.unwrap();
    let remote: Value = sqlx::query_scalar("SELECT remote_signing_config FROM credential_template_service.credential_templates WHERE id='ct-1'")
        .fetch_one(&mut conn).await.unwrap();
    assert_eq!(remote["issuer_profile_id"], "ip-marty-vc-jwt-issuer");
    let auto: Value = sqlx::query_scalar("SELECT auto_approval_rules::jsonb FROM issuance_service.application_templates WHERE id='at-1'")
        .fetch_one(&mut conn).await.unwrap();
    assert_eq!(auto, json!([]));

    // A later application failure must roll back the credential update.
    exec(&mut conn, "UPDATE credential_template_service.credential_templates SET name='stale badge' WHERE id='ct-1'").await;
    exec(&mut conn, "ALTER TABLE issuance_service.application_templates ADD CONSTRAINT reject_demo_seed CHECK (false) NOT VALID").await;
    drop(conn);
    assert!(seed_open_badge_templates(url.as_str(), &cfg, &scoped)
        .await
        .is_err());
    let mut conn = PgConnection::connect(url.as_str()).await.unwrap();
    let name: String = sqlx::query_scalar(
        "SELECT name FROM credential_template_service.credential_templates WHERE id='ct-1'",
    )
    .fetch_one(&mut conn)
    .await
    .unwrap();
    assert_eq!(name, "stale badge");
}

#[tokio::test]
async fn current_and_legacy_schema_upsert_and_rollback() {
    let Ok(value) = env::var("MARTY_CANVAS_SEED_TEST_DATABASE_URL") else {
        eprintln!("set MARTY_CANVAS_SEED_TEST_DATABASE_URL for disposable Postgres coverage");
        return;
    };
    let base = Url::parse(&value).unwrap();
    assert_eq!(base.scheme(), "postgresql");
    assert!(matches!(base.host_str(), Some("localhost" | "127.0.0.1")));
    let name = format!(
        "canvas_seed_{}_{}",
        process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    let mut admin = PgConnection::connect(base.as_str()).await.unwrap();
    exec(&mut admin, &format!("CREATE DATABASE {name}")).await;
    let mut url = base.clone();
    url.set_path(&format!("/{name}"));
    let result = tokio::spawn(async move { run_case(&url).await }).await;
    exec(&mut admin, &format!("DROP DATABASE {name} WITH (FORCE)")).await;
    result.unwrap();
}
