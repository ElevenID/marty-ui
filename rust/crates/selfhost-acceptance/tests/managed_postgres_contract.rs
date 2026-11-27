//! Local source-level PostgreSQL qualification, not a Supabase account or pooler test.
#![cfg(unix)]

#[path = "support/managed_postgres.rs"]
mod managed_postgres;

#[cfg(target_os = "linux")]
#[path = "support/feature_profile_database.rs"]
mod feature_profile;
#[cfg(target_os = "linux")]
#[path = "../../deployment-catalog/src/installer_feature_database.rs"]
mod installer_feature_database;
#[cfg(target_os = "linux")]
#[path = "../../deployment-catalog/src/installer_json.rs"]
mod installer_json;

use managed_postgres::{Database, APP_PASSWORD, APP_ROLE, DATABASE};
use sqlx::{postgres::PgPoolOptions, ConnectOptions, Connection, PgConnection, PgPool};
use std::{
    collections::BTreeSet,
    process::Command,
    time::{Duration, Instant},
};

const CASE: &str = "restricted_role_migrates_without_touching_provider_schemas";
const CHILD: &str = "MARTY_MANAGED_POSTGRES_CONTRACT_CHILD";
const SCHEMAS: [&str; 13] = [
    "auth_service",
    "organization_service",
    "credential_template_service",
    "trust_profile_service",
    "issuance_service",
    "notification_service",
    "compliance_profile_service",
    "presentation_policy_service",
    "deployment_profile_service",
    "flow_service",
    "revocation_profile_service",
    "device_registration_service",
    "mmf_messaging",
];

#[tokio::test]
#[ignore = "requires local PostgreSQL initdb/postgres/pg_ctl via MARTY_TEST_POSTGRES_BIN_DIR"]
async fn restricted_role_migrates_without_touching_provider_schemas() {
    if std::env::var_os(CHILD).is_none() {
        // Notification's existing constructor reads provider configuration. Keep
        // the synthetic, never-contacted provider outside the parent environment.
        let output = managed_postgres::run(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", CASE, "--ignored", "--nocapture"])
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env(CHILD, "1")
                .env(
                    "MARTY_TEST_POSTGRES_BIN_DIR",
                    std::env::var_os("MARTY_TEST_POSTGRES_BIN_DIR")
                        .expect("local PostgreSQL executables are required"),
                )
                .env("NOTIFICATION_SECRET_KMS_PROVIDER", "aws-kms")
                .env("NOTIFICATION_SECRET_AWS_REGION", "us-east-2")
                .env(
                    "NOTIFICATION_SECRET_AWS_KEY_ARN",
                    "arn:aws:kms:us-east-2:111122223333:key/schema-only-fixture",
                )
                .env("AWS_EC2_METADATA_DISABLED", "true"),
            180,
        );
        assert!(
            output.status.success(),
            "owned migration qualification failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        print!("{}", String::from_utf8_lossy(&output.stdout));
        return;
    }
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut database = Database::start();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut admin = loop {
        database.assert_running();
        if let Ok(connection) =
            PgConnection::connect_with(&database.admin_options("postgres")).await
        {
            break connection;
        }
        assert!(
            Instant::now() < deadline,
            "owned PostgreSQL did not become ready"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    sqlx::raw_sql(
        "CREATE ROLE elevenid LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION
             CONNECTION LIMIT 30 PASSWORD 'synthetic:p@ss/?#%$&=+[]';"
    ).execute(&mut admin).await.unwrap();
    sqlx::query("CREATE DATABASE managed_service_test")
        .execute(&mut admin)
        .await
        .unwrap();
    admin.close().await.unwrap();
    let mut admin = PgConnection::connect_with(&database.admin_options(DATABASE))
        .await
        .unwrap();
    sqlx::raw_sql(
        "REVOKE ALL ON DATABASE managed_service_test FROM PUBLIC;
         GRANT CONNECT, CREATE ON DATABASE managed_service_test TO elevenid;
         REVOKE ALL ON SCHEMA public FROM PUBLIC;
         CREATE SCHEMA auth;
         CREATE SCHEMA storage;
         REVOKE ALL ON SCHEMA auth,storage FROM PUBLIC;
         CREATE TABLE auth.users(id uuid PRIMARY KEY, fixture text NOT NULL);
         CREATE TABLE storage.objects(id uuid PRIMARY KEY, fixture text NOT NULL);
         INSERT INTO auth.users VALUES ('00000000-0000-0000-0000-000000000001','protected-auth-sentinel');
         INSERT INTO storage.objects VALUES ('00000000-0000-0000-0000-000000000002','protected-storage-sentinel');"
    ).execute(&mut admin).await.unwrap();
    let before = provider_snapshot(&mut admin).await;
    let app_url = database.app_url_from_secret_loader();
    let options = app_url.parse::<sqlx::postgres::PgConnectOptions>().unwrap();
    assert_eq!(options.get_username(), APP_ROLE);
    assert_eq!(options.get_database(), Some(DATABASE));
    assert!(matches!(
        options.get_ssl_mode(),
        sqlx::postgres::PgSslMode::VerifyFull
    ));
    assert!(
        !app_url.contains(APP_PASSWORD),
        "raw punctuation must be encoded"
    );
    assert_tls_rejected(options.clone(), CertificateRejection::Untrusted).await;
    assert_tls_rejected(
        options
            .clone()
            .ssl_root_cert(database.ca())
            .host("localhost"),
        CertificateRejection::Hostname,
    )
    .await;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(
            options
                .ssl_root_cert(database.ca())
                .disable_statement_logging(),
        )
        .await
        .unwrap();
    let encrypted: bool =
        sqlx::query_scalar("SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(encrypted);
    assert_restricted_role(&pool).await;
    for provider in ["SELECT * FROM auth.users", "SELECT * FROM storage.objects"] {
        let denied = sqlx::query(sqlx::AssertSqlSafe(provider))
            .fetch_all(&pool)
            .await
            .unwrap_err();
        assert_eq!(
            denied.as_database_error().unwrap().code().as_deref(),
            Some("42501")
        );
    }
    let envelope = marty_notification::webhook::WebhookSecretEnvelope::from_environment().unwrap();
    migrate_all(&pool, &envelope).await;
    validate_all(&pool).await;
    let first = application_inventory(&pool).await;
    migrate_all(&pool, &envelope).await;
    validate_all(&pool).await;
    assert_eq!(
        application_inventory(&pool).await,
        first,
        "migration rerun changes object inventory"
    );
    assert_eq!(
        provider_snapshot(&mut admin).await,
        before,
        "provider schemas or sentinel rows changed"
    );
    let schemas: Vec<String> = sqlx::query_scalar(
        "SELECT nspname FROM pg_namespace WHERE nspowner=current_user::regrole ORDER BY nspname",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        schemas.into_iter().collect::<BTreeSet<_>>(),
        SCHEMAS.into_iter().map(str::to_owned).collect()
    );
    let extensions: Vec<String> =
        sqlx::query_scalar("SELECT extname FROM pg_extension ORDER BY extname")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        extensions,
        ["plpgsql"],
        "ordinary migrations must not require installed extensions"
    );
    let public_objects: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(public_objects, 0);
    pool.close().await;
    admin.close().await.unwrap();
    database.stop();
    println!(
        "Qualified 12 native schema owners plus MMF outbox: restricted role, pool2, TLS, protected provider schemas, rerun, validation. Local PostgreSQL only; no Supabase/Supavisor qualification."
    );
}

enum CertificateRejection {
    Untrusted,
    Hostname,
}

async fn assert_tls_rejected(
    options: sqlx::postgres::PgConnectOptions,
    expected: CertificateRejection,
) {
    let result = tokio::time::timeout(Duration::from_secs(5), PgConnection::connect_with(&options))
        .await
        .expect("negative TLS control must finish");
    match result {
        Err(error) => {
            // SQLx propagates rustls handshake errors through std::io::Error.
            // Match their typed certificate cause, not any connection failure.
            let tls = match &error {
                sqlx::Error::Io(io) => io.get_ref().and_then(|error| error.downcast_ref()),
                sqlx::Error::Tls(error) => error.downcast_ref(),
                _ => None,
            };
            let rejected = matches!(
                (&expected, tls),
                (
                    CertificateRejection::Untrusted,
                    Some(rustls::Error::InvalidCertificate(
                        rustls::CertificateError::UnknownIssuer
                    ))
                ) | (
                    CertificateRejection::Hostname,
                    Some(rustls::Error::InvalidCertificate(
                        rustls::CertificateError::NotValidForName
                            | rustls::CertificateError::NotValidForNameContext { .. }
                    ))
                )
            );
            assert!(rejected, "wrong verify-full rejection cause: {error:?}");
        }
        Ok(connection) => {
            connection.close().await.unwrap();
            panic!("verify-full accepted invalid certificate trust or hostname");
        }
    }
}

async fn assert_restricted_role(pool: &PgPool) {
    let privileges: (bool, bool, bool, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT rolsuper,rolcreatedb,rolcreaterole,rolinherit,rolbypassrls,rolreplication,
            has_database_privilege(current_user,current_database(),'CREATE'),
            has_schema_privilege(current_user,'public','CREATE'),
            (SELECT datdba=current_user::regrole FROM pg_database WHERE datname=current_database())
         FROM pg_roles WHERE rolname=current_user",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        privileges,
        (false, false, false, false, false, false, true, false, false)
    );
}

async fn migrate_all(pool: &PgPool, envelope: &marty_notification::webhook::WebhookSecretEnvelope) {
    migrate_schemas(pool, envelope, true).await;
}

async fn migrate_schemas(
    pool: &PgPool,
    envelope: &marty_notification::webhook::WebhookSecretEnvelope,
    include_flow_and_trust: bool,
) {
    let organization_id = uuid::Uuid::from_u128(1);
    marty_revocation_profile::migrate_and_seed(
        pool,
        &organization_id.to_string(),
        "https://fixture.invalid",
    )
    .await
    .unwrap();
    marty_auth::migration::migrate_auth_schema(pool)
        .await
        .unwrap();
    marty_organization::migration::migrate_organization_schema(pool)
        .await
        .unwrap();
    mmf_messaging::PostgresOutboxStore::new(pool.clone(), "organization", 1)
        .unwrap()
        .migrate()
        .await
        .unwrap();
    marty_credential_template::migration::migrate_credential_template_schema(pool)
        .await
        .unwrap();
    if include_flow_and_trust {
        marty_trust_profile::migration::run_migrations(pool)
            .await
            .unwrap();
    }
    marty_notification::migration::migrate(pool, envelope)
        .await
        .unwrap();
    marty_compliance_profile::migration::run_migrations(pool)
        .await
        .unwrap();
    marty_presentation_policy::migrate_presentation_policy_schema(pool)
        .await
        .unwrap();
    marty_deployment_profile::migration::run_migrations(pool, organization_id)
        .await
        .unwrap();
    if include_flow_and_trust {
        marty_flow::migrate_flow_schema_for_organization(pool, organization_id)
            .await
            .unwrap();
    }
    marty_device_registration::migration::migrate(pool)
        .await
        .unwrap();
    marty_issuance_service::migration::migrate_owned_schema(pool, organization_id)
        .await
        .unwrap();
}

async fn validate_all(pool: &PgPool) {
    marty_auth::migration::validate_auth_schema(pool)
        .await
        .unwrap();
    marty_organization::migration::validate_organization_schema(pool)
        .await
        .unwrap();
    marty_credential_template::migration::validate_credential_template_schema(pool)
        .await
        .unwrap();
    marty_notification::migration::validate(pool).await.unwrap();
    marty_presentation_policy::validate_presentation_policy_schema(pool)
        .await
        .unwrap();
    marty_flow::validate_flow_schema(pool).await.unwrap();
    marty_device_registration::migration::validate(pool)
        .await
        .unwrap();
    marty_issuance_service::migration::verify_owned_schema(pool)
        .await
        .unwrap();
}

async fn application_inventory(pool: &PgPool) -> Vec<(String, String, String)> {
    sqlx::query_as(
        "SELECT n.nspname,c.relname,c.relkind::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
         WHERE n.nspowner=current_user::regrole ORDER BY n.nspname,c.relname,c.relkind"
    ).fetch_all(pool).await.unwrap()
}

async fn provider_snapshot(admin: &mut PgConnection) -> serde_json::Value {
    sqlx::query_scalar(
        "SELECT jsonb_build_object(
           'schemas',(SELECT jsonb_agg(jsonb_build_array(nspname,nspowner,nspacl::text) ORDER BY nspname)
                      FROM pg_namespace WHERE nspname IN ('auth','storage')),
           'relations',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,c.relkind,c.relowner,c.relacl::text) ORDER BY n.nspname,c.relname)
                        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('auth','storage')),
           'auth',(SELECT jsonb_agg(to_jsonb(u)) FROM auth.users u),
           'storage',(SELECT jsonb_agg(to_jsonb(o)) FROM storage.objects o))"
    ).fetch_one(admin).await.unwrap()
}
