//! Run against disposable local PostgreSQL with MARTY_DEMO_SEED_TEST_DATABASE_URL.
//! The URL must point at a local PostgreSQL instance where the user can create databases.

use marty_demo_vendor_seed::{reference, seed, ORGANIZATION_ID};
use sqlx::{Connection, PgConnection};
use std::{env, process, time::SystemTime};
use url::Url;

fn test_url() -> Option<Url> {
    let value = env::var("MARTY_DEMO_SEED_TEST_DATABASE_URL").ok()?;
    let url = Url::parse(&value).expect("test database URL must be valid");
    assert_eq!(url.scheme(), "postgresql");
    assert!(matches!(url.host_str(), Some("localhost" | "127.0.0.1")));
    Some(url)
}

async fn exec(conn: &mut PgConnection, sql: &str) {
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .execute(conn)
        .await
        .unwrap();
}

async fn count(conn: &mut PgConnection, table: &str) -> i64 {
    let query = match table {
        "organization_service.organizations" => {
            "SELECT count(*) FROM organization_service.organizations"
        }
        "credential_service.credential_types" => {
            "SELECT count(*) FROM credential_service.credential_types"
        }
        "credential_template_service.credential_templates" => {
            "SELECT count(*) FROM credential_template_service.credential_templates"
        }
        _ => panic!("unexpected test table"),
    };
    sqlx::query_scalar::<_, i64>(query)
        .fetch_one(conn)
        .await
        .unwrap()
}

async fn schema(conn: &mut PgConnection, optional_tables: bool, optional_columns: bool) {
    exec(conn, "CREATE SCHEMA organization_service").await;
    exec(conn, "CREATE TABLE organization_service.organizations (id uuid PRIMARY KEY, name text NOT NULL, display_name text NOT NULL, slug text NOT NULL, description text NOT NULL, org_type text NOT NULL, status text NOT NULL, join_mechanism text NOT NULL, requires_approval boolean NOT NULL, is_discoverable boolean NOT NULL, settings jsonb NOT NULL, created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL)").await;
    if !optional_tables {
        return;
    }
    exec(conn, "CREATE SCHEMA credential_service").await;
    exec(conn, "CREATE TABLE credential_service.credential_types (id text PRIMARY KEY, organization_id text NOT NULL, name text NOT NULL, description text NOT NULL, format text NOT NULL, status text NOT NULL, schema_definition jsonb NOT NULL, display_config jsonb NOT NULL, validity_days integer NOT NULL, revocable boolean NOT NULL, created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL)").await;
    exec(conn, "CREATE SCHEMA credential_template_service").await;
    exec(conn, "CREATE TABLE credential_template_service.credential_templates (id text PRIMARY KEY, organization_id text NOT NULL, name text NOT NULL, description text NOT NULL, status text NOT NULL, credential_type text NOT NULL, vct text, doctype text, claims jsonb NOT NULL, privacy_posture text NOT NULL, selective_disclosure_fields jsonb NOT NULL, derived_attributes jsonb NOT NULL, display_style jsonb NOT NULL, validity_rules jsonb NOT NULL, issuer_requirements jsonb NOT NULL, supported_formats jsonb NOT NULL, version bigint NOT NULL, created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL)").await;
    if optional_columns {
        exec(conn, "ALTER TABLE credential_template_service.credential_templates ADD COLUMN credential_payload_format text, ADD COLUMN wallet_configs jsonb").await;
    }
}

async fn case(
    base: &Url,
    name: &str,
    optional_tables: bool,
    optional_columns: bool,
    rollback: bool,
) {
    let mut admin = PgConnection::connect(base.as_str()).await.unwrap();
    // The generated name is ASCII alphanumeric/underscore, and never comes from external input.
    exec(&mut admin, &format!("CREATE DATABASE {name}")).await;
    let mut url = base.clone();
    url.set_path(&format!("/{name}"));
    let result = run_case(&url, optional_tables, optional_columns, rollback).await;
    exec(&mut admin, &format!("DROP DATABASE {name} WITH (FORCE)")).await;
    result.unwrap();
}

async fn run_case(
    url: &Url,
    optional_tables: bool,
    optional_columns: bool,
    rollback: bool,
) -> Result<(), String> {
    let mut conn = PgConnection::connect(url.as_str())
        .await
        .map_err(|e| e.to_string())?;
    schema(&mut conn, optional_tables, optional_columns).await;
    if rollback {
        exec(&mut conn, "ALTER TABLE credential_template_service.credential_templates ADD CONSTRAINT reject_demo_seed CHECK (false)").await;
        drop(conn);
        assert!(seed(url.as_str()).await.is_err());
        let mut conn = PgConnection::connect(url.as_str())
            .await
            .map_err(|e| e.to_string())?;
        for table in [
            "organization_service.organizations",
            "credential_service.credential_types",
            "credential_template_service.credential_templates",
        ] {
            assert_eq!(count(&mut conn, table).await, 0, "{table} must roll back");
        }
        return Ok(());
    }
    drop(conn);
    let expected = reference().map_err(|e| e.to_string())?;
    let first = seed(url.as_str()).await?;
    assert_eq!(
        first.credential_types_seeded,
        if optional_tables { 7 } else { 0 }
    );
    assert_eq!(
        first.credential_templates_seeded,
        if optional_tables { 8 } else { 0 }
    );
    assert_eq!(
        first.wallet_configs_applied,
        optional_tables && optional_columns
    );
    let mut conn = PgConnection::connect(url.as_str())
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(
        count(&mut conn, "organization_service.organizations").await,
        1
    );
    let name: String =
        sqlx::query_scalar("SELECT name FROM organization_service.organizations WHERE id=$1::uuid")
            .bind(ORGANIZATION_ID)
            .fetch_one(&mut conn)
            .await
            .map_err(|e| e.to_string())?;
    assert_eq!(name, expected["vendor_bundle"]["organization"]["name"]);
    if optional_tables {
        assert_eq!(
            count(&mut conn, "credential_service.credential_types").await,
            7
        );
        assert_eq!(
            count(
                &mut conn,
                "credential_template_service.credential_templates"
            )
            .await,
            8
        );
        if optional_columns {
            let (format, wallet): (String, serde_json::Value) = sqlx::query_as("SELECT credential_payload_format, wallet_configs FROM credential_template_service.credential_templates WHERE credential_type=$1")
                .bind(expected["vendor_bundle"]["credential_templates"][0]["credential_type"].as_str().unwrap())
                .fetch_one(&mut conn).await.map_err(|e| e.to_string())?;
            assert!(!format.is_empty());
            assert!(wallet.is_array());
        }
    }
    exec(
        &mut conn,
        "UPDATE organization_service.organizations SET name='stale organization'",
    )
    .await;
    if optional_tables {
        exec(
            &mut conn,
            "UPDATE credential_service.credential_types SET description='stale type'",
        )
        .await;
        exec(&mut conn, "UPDATE credential_template_service.credential_templates SET description='stale template'").await;
    }
    drop(conn);
    assert_eq!(
        seed(url.as_str()).await?,
        first,
        "second run must retain seed behavior"
    );
    let mut conn = PgConnection::connect(url.as_str())
        .await
        .map_err(|e| e.to_string())?;
    assert_eq!(
        count(&mut conn, "organization_service.organizations").await,
        1
    );
    let restored_name: String =
        sqlx::query_scalar("SELECT name FROM organization_service.organizations WHERE id=$1::uuid")
            .bind(ORGANIZATION_ID)
            .fetch_one(&mut conn)
            .await
            .map_err(|e| e.to_string())?;
    assert_eq!(
        restored_name,
        expected["vendor_bundle"]["organization"]["name"]
    );
    if optional_tables {
        assert_eq!(
            count(&mut conn, "credential_service.credential_types").await,
            7
        );
        assert_eq!(
            count(
                &mut conn,
                "credential_template_service.credential_templates"
            )
            .await,
            8
        );
        let stale_types: i64 = sqlx::query_scalar("SELECT count(*) FROM credential_service.credential_types WHERE description='stale type'")
            .fetch_one(&mut conn).await.map_err(|e| e.to_string())?;
        let stale_templates: i64 = sqlx::query_scalar("SELECT count(*) FROM credential_template_service.credential_templates WHERE description='stale template'")
            .fetch_one(&mut conn).await.map_err(|e| e.to_string())?;
        assert_eq!((stale_types, stale_templates), (0, 0));
    }
    Ok(())
}

#[tokio::test]
async fn postgres_first_second_optional_and_rollback() {
    let Some(base) = test_url() else {
        eprintln!("set MARTY_DEMO_SEED_TEST_DATABASE_URL to run disposable PostgreSQL coverage");
        return;
    };
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let prefix = format!("marty_demo_seed_it_{}_{}", process::id(), nanos);
    case(&base, &format!("{prefix}_full"), true, true, false).await;
    case(&base, &format!("{prefix}_bare"), true, false, false).await;
    case(&base, &format!("{prefix}_org"), false, false, false).await;
    case(&base, &format!("{prefix}_rollback"), true, true, true).await;
}
