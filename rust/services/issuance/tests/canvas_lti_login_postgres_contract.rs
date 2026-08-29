use std::{sync::Arc, time::Duration};

use marty_issuance_service::{
    canvas_lti_launch::{
        CanvasLtiLaunchContextRepository, CanvasLtiLaunchStateRepository,
        CanvasLtiLaunchStateService,
    },
    canvas_lti_login::{CanvasLtiLaunchState, CanvasLtiLoginRepository},
    canvas_lti_postgres::PostgresCanvasLtiLoginRepository,
};
use serde_json::json;
use sqlx::{postgres::PgPoolOptions, Row};
use uuid::Uuid;

fn database_url() -> Option<String> {
    std::env::var("MARTY_ISSUANCE_POSTGRES_CONTRACT_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

#[tokio::test]
async fn canvas_lti_login_uses_the_existing_schema_and_database_clock() {
    let Some(database_url) = database_url() else {
        eprintln!("skipping Canvas LTI login PostgreSQL contract without database URL");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("issuance PostgreSQL contract database must connect");
    sqlx::query("CREATE SCHEMA IF NOT EXISTS issuance_service")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE IF EXISTS issuance_service.canvas_lti_launch_states")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE IF EXISTS issuance_service.canvas_program_bindings")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE IF EXISTS issuance_service.canvas_platforms")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE issuance_service.canvas_platforms (
            id text PRIMARY KEY,
            organization_id text NOT NULL,
            canvas_account_id text NOT NULL,
            canvas_base_url text NULL,
            lti_client_id text NULL,
            lti_deployment_id text NULL,
            lti_trust_profile varchar(40) NOT NULL DEFAULT 'hosted_global',
            lti_issuer text NULL,
            lti_jwks_url text NULL,
            lti_jwks_json jsonb NULL,
            lti_openid_configuration jsonb NULL,
            enabled boolean NOT NULL DEFAULT false
        )",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE issuance_service.canvas_program_bindings (
            id text PRIMARY KEY,
            organization_id text NOT NULL,
            platform_id text NOT NULL REFERENCES issuance_service.canvas_platforms(id) ON DELETE CASCADE,
            application_template_id text NOT NULL,
            credential_template_id text NOT NULL,
            delivery_mode text NULL,
            deployment_profile_id text NULL,
            feature_flags jsonb NOT NULL DEFAULT '{}'::jsonb,
            evidence_requirements jsonb NOT NULL DEFAULT '[]'::jsonb,
            canvas_scope jsonb NOT NULL DEFAULT '{}'::jsonb,
            enabled boolean NOT NULL DEFAULT false,
            created_at timestamptz NOT NULL DEFAULT clock_timestamp()
        )",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE issuance_service.canvas_lti_launch_states (
            id text PRIMARY KEY,
            platform_id text NOT NULL REFERENCES issuance_service.canvas_platforms(id) ON DELETE CASCADE,
            organization_id text NOT NULL,
            canvas_account_id text NOT NULL,
            state text NOT NULL UNIQUE,
            nonce text NOT NULL,
            login_hint text NULL,
            target_link_uri text NULL,
            lti_message_hint text NULL,
            redirect_uri text NULL,
            status text NOT NULL DEFAULT 'pending',
            metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            expires_at timestamptz NOT NULL,
            consumed_at timestamptz NULL
        )",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.canvas_platforms (
            id, organization_id, canvas_account_id, canvas_base_url, lti_client_id,
            lti_deployment_id, lti_trust_profile, lti_issuer, lti_jwks_url,
            lti_jwks_json, lti_openid_configuration, enabled
        ) VALUES ($1, 'org-123', 'account-123', 'https://school.canvas.example',
            'client-123', 'deployment-123', 'hosted_global',
            'https://canvas.instructure.com',
            'https://sso.canvaslms.com/api/lti/security/jwks',
            '{\"keys\":[{\"kid\":\"canvas-key\"}]}'::jsonb,
            '{\"authorization_endpoint\":\"https://sso.canvaslms.com/api/lti/authorize_redirect\"}'::jsonb,
            true)",
    )
    .bind("platform-123")
    .execute(&pool)
    .await
    .unwrap();

    let repository = PostgresCanvasLtiLoginRepository::new(pool.clone());
    let platform = repository
        .get_platform("platform-123")
        .await
        .unwrap()
        .expect("platform");
    assert_eq!(platform.organization_id, "org-123");
    assert_eq!(platform.lti_trust_profile, "hosted_global");
    assert!(platform.enabled);
    assert!(repository.get_platform("missing").await.unwrap().is_none());

    sqlx::query(
        "INSERT INTO issuance_service.canvas_program_bindings (
            id, organization_id, platform_id, application_template_id,
            credential_template_id, delivery_mode, deployment_profile_id,
            feature_flags, evidence_requirements, canvas_scope, enabled, created_at
        ) VALUES
            ('binding-first', 'org-123', 'platform-123', 'app-first', 'credential-first',
             'wallet_only', NULL, '{\"enable_canvas_lti\":true}'::jsonb,
             '[{\"fact_type\":\"canvas.course_completion\"}]'::jsonb,
             '{\"course_id\":\"course-101\"}'::jsonb, true, clock_timestamp() - interval '1 minute'),
            ('binding-second', 'org-123', 'platform-123', 'app-second', 'credential-second',
             'wallet_and_canvas', 'profile-1', '{}'::jsonb, '[]'::jsonb, '{}'::jsonb,
             false, clock_timestamp())",
    )
    .execute(&pool)
    .await
    .unwrap();
    let bindings = repository
        .list_program_bindings("org-123", "platform-123")
        .await
        .unwrap();
    assert_eq!(bindings.len(), 2);
    assert_eq!(bindings[0].id, "binding-first");
    assert_eq!(bindings[0].canvas_scope, json!({"course_id": "course-101"}));
    assert_eq!(
        bindings[0].evidence_requirements,
        vec![json!({"fact_type": "canvas.course_completion"})]
    );
    assert!(bindings[0].enabled);
    assert_eq!(
        bindings[1].deployment_profile_id.as_deref(),
        Some("profile-1")
    );
    assert!(!bindings[1].enabled);

    let state = format!("state-{}", Uuid::new_v4());
    let nonce = format!("nonce-{}", Uuid::new_v4());
    let launch_state = CanvasLtiLaunchState {
        id: Uuid::new_v4().to_string(),
        platform_id: platform.id,
        organization_id: platform.organization_id,
        canvas_account_id: platform.canvas_account_id,
        state: state.clone(),
        nonce: nonce.clone(),
        login_hint: "login-hint-123".to_owned(),
        target_link_uri: Some("https://issuer.example/launch".to_owned()),
        lti_message_hint: Some("message-hint-123".to_owned()),
        redirect_uri:
            "https://issuer.example/v1/integrations/canvas/lti/platforms/platform-123/launch"
                .to_owned(),
        metadata: json!({"experience_mode": false, "issuer": null}),
        ttl: Duration::from_secs(600),
    };
    repository.save_launch_state(&launch_state).await.unwrap();
    let row = sqlx::query(
        "SELECT *,
            extract(epoch FROM created_at - clock_timestamp())::double precision AS created_skew,
            extract(epoch FROM expires_at - created_at)::double precision AS ttl_seconds
         FROM issuance_service.canvas_lti_launch_states WHERE state = $1",
    )
    .bind(&state)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.try_get::<String, _>("status").unwrap(), "pending");
    assert_eq!(row.try_get::<String, _>("nonce").unwrap(), nonce);
    assert_eq!(
        row.try_get::<Option<String>, _>("login_hint")
            .unwrap()
            .as_deref(),
        Some("login-hint-123")
    );
    assert!(row
        .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("consumed_at")
        .unwrap()
        .is_none());
    assert!(row.try_get::<f64, _>("created_skew").unwrap().abs() < 5.0);
    assert!((599.9..=600.1).contains(&row.try_get::<f64, _>("ttl_seconds").unwrap()));
    assert_eq!(
        row.try_get::<serde_json::Value, _>("metadata").unwrap(),
        launch_state.metadata
    );

    let stored = repository
        .get_launch_state(&state)
        .await
        .unwrap()
        .expect("stored state");
    assert_eq!(stored.platform_id, "platform-123");
    assert_eq!(stored.nonce, nonce);
    assert!(!stored.expired);

    let service = CanvasLtiLaunchStateService::new(Arc::new(repository));
    let first = service.clone();
    let second = service;
    let (first, second) = tokio::join!(
        first.claim("platform-123", &state),
        second.claim("platform-123", &state)
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let consumed = sqlx::query(
        "SELECT status, consumed_at FROM issuance_service.canvas_lti_launch_states WHERE state = $1",
    )
    .bind(&state)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(consumed.try_get::<String, _>("status").unwrap(), "consumed");
    assert!(consumed
        .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("consumed_at")
        .unwrap()
        .is_some());

    sqlx::query("DROP TABLE issuance_service.canvas_lti_launch_states")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE issuance_service.canvas_program_bindings")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE issuance_service.canvas_platforms")
        .execute(&pool)
        .await
        .unwrap();
}
