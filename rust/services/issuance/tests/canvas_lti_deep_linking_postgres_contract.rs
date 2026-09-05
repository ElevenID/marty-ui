use marty_issuance_service::{
    canvas_lti_deep_linking::{
        CanvasLtiDeepLinkingError, CanvasLtiDeepLinkingPersistenceScope,
        CanvasLtiDeepLinkingRepository,
    },
    canvas_lti_deep_linking_postgres::PostgresCanvasLtiDeepLinkingRepository,
    canvas_lti_experience::canvas_lti_experience_session_context,
    canvas_lti_launch::CanvasLtiStoredLaunchState,
};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;

fn database_url() -> Option<String> {
    std::env::var("MARTY_ISSUANCE_POSTGRES_CONTRACT_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn context() -> marty_issuance_service::canvas_lti_experience::CanvasLtiExperienceSessionContext {
    canvas_lti_experience_session_context(CanvasLtiStoredLaunchState {
        id: "session-id-1".to_owned(),
        platform_id: "platform-1".to_owned(),
        organization_id: "org-1".to_owned(),
        canvas_account_id: "account-1".to_owned(),
        state: "session-digest-1".to_owned(),
        nonce: "session-nonce-1".to_owned(),
        redirect_uri: "https://ui.example.test/canvas/lti/experience".to_owned(),
        status: "session".to_owned(),
        metadata: json!({
            "kind": "canvas_lti_experience_session",
            "launch_state": "launch-state-1",
            "verified_launch": {"roles": ["Instructor"], "raw_claims": {}},
            "mip_primitives": {"context": {
                "canvas_platform_id": "platform-1",
                "canvas_program_binding_id": "binding-1",
                "application_template_id": "application-template-1",
                "credential_template_id": "credential-template-1"
            }}
        }),
        expired: false,
    })
    .unwrap()
}

#[tokio::test]
async fn deep_linking_snapshot_and_metadata_commit_are_tenant_bound_and_drift_safe() {
    for storage_type in ["json", "jsonb"] {
        deep_linking_contract(storage_type).await;
    }
}

async fn deep_linking_contract(storage_type: &str) {
    let Some(database_url) = database_url() else {
        eprintln!("skipping Canvas Deep Linking PostgreSQL contract without database URL");
        return;
    };
    assert!(
        url::Url::parse(&database_url)
            .unwrap()
            .path()
            .ends_with("_test"),
        "Canvas PostgreSQL contracts require a dedicated *_test database"
    );
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("issuance PostgreSQL contract database must connect");
    setup_schema(&pool).await;
    if storage_type == "json" {
        sqlx::query("ALTER TABLE issuance_service.canvas_lti_launch_states ALTER COLUMN metadata TYPE json USING metadata::json")
            .execute(&pool).await.unwrap();
    }
    let actual_type: String = sqlx::query_scalar(
        "SELECT data_type FROM information_schema.columns WHERE table_schema = 'issuance_service'
         AND table_name = 'canvas_lti_launch_states' AND column_name = 'metadata'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(actual_type, storage_type);
    seed_scope(&pool).await;
    let repository = PostgresCanvasLtiDeepLinkingRepository::new(pool.clone());
    let session_context = context();

    assert_eq!(
        repository
            .bound_feature_enabled("org-1", "binding-1")
            .await
            .unwrap(),
        Some(true)
    );
    assert_eq!(
        repository
            .bound_feature_enabled("org-other", "binding-1")
            .await
            .unwrap(),
        None
    );
    let platform = repository
        .get_platform(&session_context)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(platform.organization_id, "org-1");
    assert_eq!(platform.canvas_account_id, "account-1");
    assert_eq!(platform.config_version, 7);
    let binding = repository
        .get_binding(&session_context, &platform)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(binding.display_name.as_deref(), Some("Biology Credential"));
    assert_eq!(binding.config_version, 11);

    let scope = CanvasLtiDeepLinkingPersistenceScope {
        session_id: "session-id-1".to_owned(),
        session_state: "session-digest-1".to_owned(),
        platform_id: "platform-1".to_owned(),
        platform_config_version: 7,
        binding_id: "binding-1".to_owned(),
        binding_config_version: 11,
        organization_id: "org-1".to_owned(),
        canvas_account_id: "account-1".to_owned(),
    };
    let metadata = json!({
        "created_at": "2026-08-29T16:30:00.000000+00:00",
        "deep_link_return_url": "https://canvas.example.test/return",
        "content_items": [{"type": "ltiResourceLink"}]
    });
    repository
        .persist_response(&scope, &metadata)
        .await
        .unwrap();
    let stored: Value = sqlx::query_scalar(
        "SELECT metadata FROM issuance_service.canvas_lti_launch_states
         WHERE id = 'session-id-1'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored["unrelated"], "preserved");
    assert_eq!(stored["deep_linking_response"], metadata);

    // Each persisted scope dimension is independently fenced. Rejected writes
    // must leave the complete session document intact, not only the response.
    for dimension in 0..8 {
        let mut stale = scope.clone();
        match dimension {
            0 => stale.session_id = "other-session".into(),
            1 => stale.session_state = "other-state".into(),
            2 => stale.platform_id = "other-platform".into(),
            3 => stale.platform_config_version += 1,
            4 => stale.binding_id = "other-binding".into(),
            5 => stale.binding_config_version += 1,
            6 => stale.organization_id = "other-org".into(),
            _ => stale.canvas_account_id = "other-account".into(),
        }
        assert_eq!(
            repository
                .persist_response(&stale, &json!({"rejected": true}))
                .await,
            Err(CanvasLtiDeepLinkingError::ConfigurationDrift)
        );
        let unchanged: Value = sqlx::query_scalar(
            "SELECT metadata FROM issuance_service.canvas_lti_launch_states WHERE id = 'session-id-1'",
        ).fetch_one(&pool).await.unwrap();
        assert_eq!(unchanged, stored);
    }

    sqlx::query(
        "UPDATE issuance_service.canvas_program_bindings
         SET config_version = 12 WHERE id = 'binding-1'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        repository
            .persist_response(&scope, &json!({"created_at": "should-not-write"}))
            .await
            .unwrap_err(),
        CanvasLtiDeepLinkingError::ConfigurationDrift
    );
    let stored_after_drift: Value = sqlx::query_scalar(
        "SELECT metadata FROM issuance_service.canvas_lti_launch_states
         WHERE id = 'session-id-1'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored_after_drift["deep_linking_response"], metadata);

    let mut wrong_tenant = context();
    wrong_tenant.launch_state.organization_id = "org-other".to_owned();
    assert!(repository
        .get_platform(&wrong_tenant)
        .await
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
    for statement in [
        "CREATE TABLE issuance_service.canvas_platforms (
            id text PRIMARY KEY,
            organization_id text NOT NULL,
            canvas_account_id text NOT NULL,
            lti_client_id text,
            lti_deployment_id text,
            lti_issuer text,
            config_version integer NOT NULL)",
        "CREATE TABLE issuance_service.canvas_program_bindings (
            id text PRIMARY KEY,
            organization_id text NOT NULL,
            platform_id text NOT NULL REFERENCES issuance_service.canvas_platforms(id),
            display_name varchar(255),
            application_template_id text NOT NULL,
            credential_template_id text NOT NULL,
            feature_flags jsonb NOT NULL,
            evidence_requirements jsonb NOT NULL,
            config_version integer NOT NULL)",
        "CREATE TABLE issuance_service.canvas_lti_launch_states (
            id text PRIMARY KEY,
            platform_id text NOT NULL REFERENCES issuance_service.canvas_platforms(id),
            organization_id text NOT NULL,
            canvas_account_id text NOT NULL,
            state text NOT NULL UNIQUE,
            nonce text NOT NULL,
            redirect_uri text,
            status text NOT NULL,
            metadata jsonb NOT NULL,
            expires_at timestamptz NOT NULL)",
    ] {
        sqlx::query(statement).execute(pool).await.unwrap();
    }
}

async fn seed_scope(pool: &sqlx::PgPool) {
    sqlx::query(
        "INSERT INTO issuance_service.canvas_platforms
         VALUES ('platform-1', 'org-1', 'account-1', 'client-1', 'deployment-1',
                 'https://canvas.example.test', 7)",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.canvas_program_bindings
         VALUES ('binding-1', 'org-1', 'platform-1', 'Biology Credential',
                 'application-template-1', 'credential-template-1',
                 '{\"enable_canvas_deep_linking\":true}'::jsonb,
                 '[{\"requirement_id\":\"assignment-1\",\"source\":\"ags_result\",\"fact_type\":\"canvas.assignment_score\",\"scope\":{\"course_id\":\"course-42\",\"resource_id\":\"resource-1\"},\"pass_rule\":{\"min_score_percent\":80},\"required\":true}]'::jsonb,
                 11)",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.canvas_lti_launch_states
         VALUES ('session-id-1', 'platform-1', 'org-1', 'account-1',
                 'session-digest-1', 'session-nonce-1',
                 'https://ui.example.test/canvas/lti/experience', 'session',
                 '{\"kind\":\"canvas_lti_experience_session\",\"unrelated\":\"preserved\"}'::jsonb,
                 clock_timestamp() + interval '30 minutes')",
    )
    .execute(pool)
    .await
    .unwrap();
}
