use chrono::{TimeZone, Utc};
use marty_issuance_service::{
    canvas_management::CanvasPlatformRequest,
    canvas_management_domain::{CanvasOriginPolicy, CanvasPlatformRecord},
    canvas_management_postgres::PostgresCanvasManagementRepository,
    canvas_management_service::CanvasManagementRepositoryError,
};
use serde_json::json;
use sqlx::{postgres::PgPoolOptions, Row};

fn database_url() -> Option<String> {
    std::env::var("MARTY_ISSUANCE_POSTGRES_CONTRACT_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn platform_request(display_name: &str, enabled: bool) -> CanvasPlatformRequest {
    CanvasPlatformRequest {
        display_name: Some(display_name.to_owned()),
        canvas_base_url: "https://canvas.example.edu".to_owned(),
        lti_client_id: Some("client-1".to_owned()),
        lti_deployment_id: Some("deployment-1".to_owned()),
        enabled,
    }
}

#[tokio::test]
async fn platform_configuration_is_tenant_hidden_cas_safe_and_atomically_invalidates_bindings() {
    let Some(database_url) = database_url() else {
        eprintln!("skipping Canvas management PostgreSQL contract without database URL");
        return;
    };
    let database_name = url::Url::parse(&database_url)
        .expect("Canvas management PostgreSQL contract URL must parse")
        .path()
        .trim_start_matches('/')
        .to_owned();
    assert!(
        database_name.ends_with("_test"),
        "MARTY_ISSUANCE_POSTGRES_CONTRACT_URL must name a dedicated *_test database"
    );
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("Canvas management PostgreSQL contract database must connect");
    setup_schema(&pool).await;

    let now = Utc.with_ymd_and_hms(2026, 8, 30, 22, 0, 0).unwrap();
    let origin = CanvasOriginPolicy::default()
        .resolve("https://canvas.example.edu")
        .unwrap();
    let mut platform = CanvasPlatformRecord::new_draft(
        "org-management".to_owned(),
        platform_request("Original", false),
        origin.clone(),
        now,
    )
    .unwrap();
    let repository = PostgresCanvasManagementRepository::new(pool.clone());
    repository.create_platform(&platform).await.unwrap();
    assert_eq!(
        repository.create_platform(&platform).await,
        Err(CanvasManagementRepositoryError::Duplicate)
    );
    assert!(repository
        .active_platform("org-foreign", &platform.id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        repository
            .list_active_platforms("org-management")
            .await
            .unwrap()
            .len(),
        1
    );

    sqlx::query(
        "UPDATE issuance_service.canvas_platforms
         SET connection_config = connection_config || '{\"oauth_status\":\"connected\"}'::jsonb,
             enabled = true,
             registration_status = 'active',
             capability_snapshot = '{\"ags\":true}'::jsonb,
             last_validated_at = clock_timestamp()
         WHERE id = $1",
    )
    .bind(&platform.id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.canvas_program_bindings
             (id, organization_id, platform_id, enabled, validated_config_version,
              readiness_checks, readiness_validated_at, activated_at, archived_at, updated_at)
         VALUES ('binding-management', 'org-management', $1, true, 1,
                 '[{\"status\":\"pass\"}]'::jsonb, clock_timestamp(),
                 clock_timestamp(), NULL, clock_timestamp())",
    )
    .bind(&platform.id)
    .execute(&pool)
    .await
    .unwrap();

    platform = repository
        .active_platform("org-management", &platform.id)
        .await
        .unwrap()
        .unwrap();
    let changed = platform
        .reconfigure(
            platform_request("Updated", true),
            origin,
            now + chrono::Duration::seconds(1),
        )
        .unwrap();
    assert!(changed);
    let updated = repository
        .save_platform_configuration(&platform, 1, changed)
        .await
        .unwrap()
        .expect("configuration CAS");
    assert_eq!(updated.config_version, 2);
    assert_eq!(updated.display_name.as_deref(), Some("Updated"));
    assert!(!updated.enabled);
    assert_eq!(updated.registration_status, "draft");
    assert!(updated.capability_snapshot.is_empty());
    assert!(updated.last_validated_at.is_none());
    assert_eq!(updated.connection_config["enabled_intent"], json!(true));
    assert_eq!(
        updated.connection_config["oauth_status"],
        json!("connected")
    );

    let binding = sqlx::query(
        "SELECT enabled, validated_config_version, readiness_checks,
                readiness_validated_at, activated_at
         FROM issuance_service.canvas_program_bindings
         WHERE id = 'binding-management'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!binding.try_get::<bool, _>("enabled").unwrap());
    assert!(binding
        .try_get::<Option<i32>, _>("validated_config_version")
        .unwrap()
        .is_none());
    assert_eq!(
        binding
            .try_get::<serde_json::Value, _>("readiness_checks")
            .unwrap(),
        json!([])
    );
    assert!(binding
        .try_get::<Option<chrono::DateTime<Utc>>, _>("readiness_validated_at")
        .unwrap()
        .is_none());
    assert!(binding
        .try_get::<Option<chrono::DateTime<Utc>>, _>("activated_at")
        .unwrap()
        .is_none());

    assert!(repository
        .save_platform_configuration(&platform, 1, true)
        .await
        .unwrap()
        .is_none());
    sqlx::query(
        "UPDATE issuance_service.canvas_platforms
         SET connection_config = connection_config
             || '{\"lti_config_token_hash\":\"digest\",\"oauth_pending_authorization_id\":\"authorization-1\"}'::jsonb
         WHERE id = $1",
    )
    .bind(&updated.id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.canvas_oauth_connections
             (id, organization_id, platform_id, status, reauthorization_required,
              revoke_retry_count, updated_at)
         VALUES ('oauth-management', 'org-management', $1, 'connected', false, 0,
                 clock_timestamp())",
    )
    .bind(&updated.id)
    .execute(&pool)
    .await
    .unwrap();

    let archival_snapshot = repository
        .platform_for_archival("org-management", &updated.id)
        .await
        .unwrap()
        .expect("archival snapshot");
    let archived = repository
        .archive_platform(
            "org-management",
            &updated.id,
            archival_snapshot.config_version,
            now + chrono::Duration::seconds(2),
        )
        .await
        .unwrap()
        .expect("archived platform");
    assert_eq!(archived.config_version, 3);
    assert_eq!(archived.registration_status, "archived");
    assert!(!archived.enabled);
    assert_eq!(
        archived.connection_config["oauth_status"],
        json!("revocation_pending")
    );
    assert_eq!(
        archived.connection_config["lti_config_token_status"],
        json!("revoked")
    );
    assert!(!archived
        .connection_config
        .contains_key("lti_config_token_hash"));
    assert!(!archived
        .connection_config
        .contains_key("oauth_pending_authorization_id"));

    let queued = sqlx::query(
        "SELECT status, revoke_retry_count, revoke_retry_at,
                revoke_last_error_code, refresh_lease_owner
         FROM issuance_service.canvas_oauth_connections
         WHERE id = 'oauth-management'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        queued.try_get::<String, _>("status").unwrap(),
        "revocation_pending"
    );
    assert_eq!(queued.try_get::<i32, _>("revoke_retry_count").unwrap(), 1);
    assert!(queued
        .try_get::<Option<chrono::DateTime<Utc>>, _>("revoke_retry_at")
        .unwrap()
        .is_some());
    assert_eq!(
        queued
            .try_get::<Option<String>, _>("revoke_last_error_code")
            .unwrap()
            .as_deref(),
        Some("canvas_platform_archived")
    );
    assert!(queued
        .try_get::<Option<String>, _>("refresh_lease_owner")
        .unwrap()
        .is_none());

    let binding = sqlx::query(
        "SELECT enabled, archived_at FROM issuance_service.canvas_program_bindings
         WHERE id = 'binding-management'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!binding.try_get::<bool, _>("enabled").unwrap());
    assert!(binding
        .try_get::<Option<chrono::DateTime<Utc>>, _>("archived_at")
        .unwrap()
        .is_some());

    let retry_snapshot = repository
        .platform_for_archival("org-management", &updated.id)
        .await
        .unwrap()
        .expect("archived snapshot");
    let retried = repository
        .archive_platform(
            "org-management",
            &updated.id,
            retry_snapshot.config_version,
            now + chrono::Duration::seconds(3),
        )
        .await
        .unwrap()
        .expect("idempotent archive");
    assert_eq!(retried.config_version, 3);
    assert!(repository
        .active_platform("org-management", &updated.id)
        .await
        .unwrap()
        .is_none());
    assert!(repository
        .list_active_platforms("org-management")
        .await
        .unwrap()
        .is_empty());
    assert!(repository
        .platform_for_archival("org-foreign", &updated.id)
        .await
        .unwrap()
        .is_none());

    let conflicting = CanvasPlatformRecord::new_draft(
        "org-management".to_owned(),
        platform_request("Conflict", false),
        CanvasOriginPolicy::default()
            .resolve("https://canvas.example.edu")
            .unwrap(),
        now + chrono::Duration::seconds(4),
    )
    .unwrap();
    repository.create_platform(&conflicting).await.unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.canvas_program_bindings
             (id, organization_id, platform_id, enabled, readiness_checks,
              archived_at, updated_at)
         VALUES ('binding-conflict', 'org-management', $1, true, '[]'::jsonb,
                 NULL, clock_timestamp())",
    )
    .bind(&conflicting.id)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        repository
            .archive_platform(
                "org-management",
                &conflicting.id,
                conflicting.config_version + 1,
                now + chrono::Duration::seconds(5),
            )
            .await,
        Err(CanvasManagementRepositoryError::ConfigurationChanged)
    );
    sqlx::query(
        "INSERT INTO issuance_service.canvas_oauth_connections
             (id, organization_id, platform_id, status, reauthorization_required,
              revoke_retry_count, updated_at)
         VALUES ('oauth-conflict', 'org-management', $1, 'disconnected', false, 0,
                 clock_timestamp())",
    )
    .bind(&conflicting.id)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        repository
            .archive_platform(
                "org-management",
                &conflicting.id,
                conflicting.config_version,
                now + chrono::Duration::seconds(6),
            )
            .await,
        Err(CanvasManagementRepositoryError::OAuthConnectionChanged)
    );
    let still_active = repository
        .active_platform("org-management", &conflicting.id)
        .await
        .unwrap()
        .expect("conflicted platform remains active");
    assert!(still_active.archived_at.is_none());
    assert_eq!(still_active.config_version, conflicting.config_version);
    let binding = sqlx::query(
        "SELECT enabled, archived_at FROM issuance_service.canvas_program_bindings
         WHERE id = 'binding-conflict'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(binding.try_get::<bool, _>("enabled").unwrap());
    assert!(binding
        .try_get::<Option<chrono::DateTime<Utc>>, _>("archived_at")
        .unwrap()
        .is_none());
}

async fn setup_schema(pool: &sqlx::PgPool) {
    sqlx::query("DROP SCHEMA IF EXISTS issuance_service CASCADE")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("CREATE SCHEMA issuance_service")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE issuance_service.canvas_platforms (
            id text PRIMARY KEY,
            organization_id text NOT NULL,
            canvas_account_id text NOT NULL,
            display_name text,
            canvas_base_url text,
            lti_client_id text,
            lti_deployment_id text,
            lti_trust_profile varchar(40) NOT NULL,
            lti_issuer text,
            lti_jwks_url text,
            lti_jwks_json jsonb,
            lti_jwks_fetched_at timestamptz,
            lti_jwks_expires_at timestamptz,
            lti_openid_configuration jsonb,
            registration_status varchar(40) NOT NULL,
            connection_config jsonb NOT NULL,
            capability_snapshot jsonb NOT NULL,
            last_validated_at timestamptz,
            last_connection_error text,
            config_version integer NOT NULL,
            archived_at timestamptz,
            enabled boolean NOT NULL,
            created_at timestamptz NOT NULL,
            updated_at timestamptz NOT NULL,
            UNIQUE (organization_id, canvas_account_id))",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE issuance_service.canvas_program_bindings (
            id text PRIMARY KEY,
            organization_id text NOT NULL,
            platform_id text NOT NULL REFERENCES issuance_service.canvas_platforms(id),
            enabled boolean NOT NULL,
            validated_config_version integer,
            readiness_checks jsonb NOT NULL,
            readiness_validated_at timestamptz,
            activated_at timestamptz,
            archived_at timestamptz,
            updated_at timestamptz NOT NULL)",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE issuance_service.canvas_oauth_connections (
            id text PRIMARY KEY,
            organization_id text NOT NULL,
            platform_id text NOT NULL REFERENCES issuance_service.canvas_platforms(id),
            status varchar(40) NOT NULL,
            reauthorization_required boolean NOT NULL DEFAULT false,
            refresh_lease_owner text,
            refresh_lease_expires_at timestamptz,
            revoke_retry_count integer NOT NULL DEFAULT 0,
            revoke_retry_at timestamptz,
            revoke_last_error_code varchar(120),
            updated_at timestamptz NOT NULL,
            UNIQUE (organization_id, platform_id))",
    )
    .execute(pool)
    .await
    .unwrap();
}
