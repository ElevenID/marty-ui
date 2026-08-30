use chrono::{TimeZone, Utc};
use marty_issuance_service::{
    canvas_management::CanvasPlatformRequest,
    canvas_management_domain::{CanvasOriginPolicy, CanvasPlatformRecord},
    canvas_management_postgres::{
        CanvasManagementRepositoryError, PostgresCanvasManagementRepository,
    },
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
         SET archived_at = clock_timestamp(), enabled = false,
             registration_status = 'archived'
         WHERE id = $1",
    )
    .bind(&platform.id)
    .execute(&pool)
    .await
    .unwrap();
    assert!(repository
        .active_platform("org-management", &platform.id)
        .await
        .unwrap()
        .is_none());
    assert!(repository
        .list_active_platforms("org-management")
        .await
        .unwrap()
        .is_empty());
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
}
