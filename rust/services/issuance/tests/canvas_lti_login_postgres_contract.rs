use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use marty_issuance_service::{
    canvas_lti_launch::{
        CanvasLtiAgsPinRepository, CanvasLtiAgsPinRequest, CanvasLtiCapabilitySnapshotRequest,
        CanvasLtiCapabilitySnapshotService, CanvasLtiExperienceCodeSeed,
        CanvasLtiExperienceHandoffRepository, CanvasLtiExperienceHandoffRequest,
        CanvasLtiIdentityService, CanvasLtiJwksRefresher, CanvasLtiLaunchContextRepository,
        CanvasLtiLaunchPlanError, CanvasLtiLaunchStateRepository, CanvasLtiLaunchStateService,
    },
    canvas_lti_login::{CanvasLtiLaunchState, CanvasLtiLoginRepository},
    canvas_lti_postgres::{
        CanvasLtiJwksRefreshConfig, CanvasLtiProbeClient, PostgresCanvasLtiJwksRefresher,
        PostgresCanvasLtiLoginRepository,
    },
};
use marty_oid4vci::lti::{CanvasLtiPlatformProbe, VerifiedLtiLaunch};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, Row};
use uuid::Uuid;

struct FixedProbe(CanvasLtiPlatformProbe);

#[async_trait]
impl CanvasLtiProbeClient for FixedProbe {
    async fn probe(
        &self,
        _canvas_base_url: &str,
        _config: &CanvasLtiJwksRefreshConfig,
    ) -> Result<CanvasLtiPlatformProbe, String> {
        Ok(self.0.clone())
    }
}

fn database_url() -> Option<String> {
    std::env::var("MARTY_ISSUANCE_POSTGRES_CONTRACT_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn verified_identity(subject: &str, canvas_user_id: Option<&str>) -> VerifiedLtiLaunch {
    VerifiedLtiLaunch {
        issuer: "https://canvas.instructure.com".to_owned(),
        subject: subject.to_owned(),
        audience: vec!["client-123".to_owned()],
        deployment_id: "deployment-123".to_owned(),
        nonce: Some("nonce-123".to_owned()),
        issued_at: None,
        expires_at: None,
        message_type: None,
        lti_version: None,
        target_link_uri: None,
        context: None,
        roles: Vec::new(),
        learner_identity: json!({}),
        raw_claims: json!({
            "https://purl.imsglobal.org/spec/lti/claim/custom": canvas_user_id
                .map(|value| json!({"canvas_user_id": value}))
                .unwrap_or_else(|| json!({}))
        }),
    }
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
    sqlx::query("DROP TABLE IF EXISTS issuance_service.canvas_learner_identities")
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
            lti_jwks_fetched_at timestamptz NULL,
            lti_jwks_expires_at timestamptz NULL,
            lti_openid_configuration jsonb NULL,
            registration_status varchar(40) NOT NULL DEFAULT 'draft',
            capability_snapshot json NOT NULL DEFAULT '{}'::json,
            last_validated_at timestamptz NULL,
            last_connection_error text NULL,
            config_version integer NOT NULL DEFAULT 1,
            archived_at timestamptz NULL,
            enabled boolean NOT NULL DEFAULT false,
            updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
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
            config_version integer NOT NULL DEFAULT 1,
            validated_config_version integer NULL,
            readiness_checks json NOT NULL DEFAULT '[]'::json,
            readiness_validated_at timestamptz NULL,
            activated_at timestamptz NULL,
            credential_template_snapshot json NOT NULL DEFAULT '{}'::json,
            archived_at timestamptz NULL,
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
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
        "CREATE TABLE issuance_service.canvas_learner_identities (
            id text PRIMARY KEY,
            organization_id text NOT NULL,
            platform_id text NOT NULL REFERENCES issuance_service.canvas_platforms(id) ON DELETE CASCADE,
            deployment_id text NOT NULL,
            lti_subject text NOT NULL,
            canvas_user_id text NULL,
            sis_user_id text NULL,
            status varchar(32) NOT NULL DEFAULT 'linked',
            conflict_reason text NULL,
            verified_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            UNIQUE (platform_id, deployment_id, lti_subject)
        )",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE UNIQUE INDEX ux_canvas_learner_identity_numeric_link
         ON issuance_service.canvas_learner_identities(platform_id, deployment_id, canvas_user_id)
         WHERE status = 'linked' AND canvas_user_id IS NOT NULL",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.canvas_platforms (
            id, organization_id, canvas_account_id, canvas_base_url, lti_client_id,
            lti_deployment_id, lti_trust_profile, lti_issuer, lti_jwks_url,
            lti_jwks_json, lti_openid_configuration, enabled
        ) VALUES ($1, 'org-123', 'account-123', 'https://SCHOOL.CANVAS.EXAMPLE:443/',
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

    let probe = CanvasLtiPlatformProbe {
        canvas_base_url: "https://school.canvas.example".to_owned(),
        issuer: "https://canvas.instructure.com".to_owned(),
        authorization_endpoint: Some(
            "https://sso.canvaslms.com/api/lti/authorize_redirect".to_owned(),
        ),
        token_endpoint: Some("https://school.canvas.example/login/oauth2/token".to_owned()),
        jwks_uri: "https://sso.canvaslms.com/api/lti/security/jwks".to_owned(),
        registration_endpoint: None,
        raw_openid_configuration: json!({"issuer": "https://canvas.instructure.com"}),
        jwks_json: json!({"keys": [{"kid": "rotated-canvas-key"}]}),
    };
    let jwks_refresher = PostgresCanvasLtiJwksRefresher::with_probe_client(
        pool.clone(),
        CanvasLtiJwksRefreshConfig {
            timeout: Duration::from_secs(10),
            ttl: Duration::from_secs(1_200),
            self_managed_origins: Vec::new(),
            allow_private_networks: false,
            allow_http_localhost: false,
        },
        Arc::new(FixedProbe(probe)),
    );
    let refreshed = jwks_refresher
        .refresh_platform_jwks(&platform)
        .await
        .unwrap();
    assert_eq!(
        refreshed.lti_jwks_json,
        Some(json!({"keys": [{"kid": "rotated-canvas-key"}]}))
    );
    let persisted_refresh = sqlx::query(
        "SELECT canvas_base_url, lti_jwks_json,
                lti_jwks_fetched_at IS NOT NULL AS fetched,
                lti_jwks_expires_at > lti_jwks_fetched_at + interval '1199 seconds' AS ttl_persisted
         FROM issuance_service.canvas_platforms WHERE id = 'platform-123'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        persisted_refresh.get::<String, _>("canvas_base_url"),
        "https://school.canvas.example"
    );
    assert_eq!(
        persisted_refresh.get::<serde_json::Value, _>("lti_jwks_json"),
        json!({"keys": [{"kid": "rotated-canvas-key"}]})
    );
    assert!(persisted_refresh.get::<bool, _>("fetched"));
    assert!(persisted_refresh.get::<bool, _>("ttl_persisted"));

    let identity_service = CanvasLtiIdentityService::new(Arc::new(repository.clone()));
    assert_eq!(
        identity_service
            .record_verified_launch(&platform, &verified_identity("opaque-a", None))
            .await
            .unwrap(),
        "numeric_id_unavailable"
    );
    let subject_id: String = sqlx::query_scalar(
        "SELECT id FROM issuance_service.canvas_learner_identities
         WHERE platform_id = 'platform-123' AND lti_subject = 'opaque-a'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    for _ in 0..2 {
        assert_eq!(
            identity_service
                .record_verified_launch(&platform, &verified_identity("opaque-a", Some("99")),)
                .await
                .unwrap(),
            "linked"
        );
    }
    let enriched_id: String = sqlx::query_scalar(
        "SELECT id FROM issuance_service.canvas_learner_identities
         WHERE platform_id = 'platform-123' AND lti_subject = 'opaque-a'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(subject_id, enriched_id);
    assert_eq!(
        identity_service
            .record_verified_launch(&platform, &verified_identity("opaque-b", Some("99")),)
            .await
            .unwrap(),
        "quarantined"
    );
    let quarantined: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM issuance_service.canvas_learner_identities
         WHERE canvas_user_id = '99' AND status = 'quarantined'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(quarantined, 2);
    for subject in ["opaque-b", "opaque-c"] {
        assert_eq!(
            identity_service
                .record_verified_launch(&platform, &verified_identity(subject, Some("99")),)
                .await
                .unwrap(),
            "quarantined"
        );
    }
    let sticky_quarantined: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM issuance_service.canvas_learner_identities
         WHERE canvas_user_id = '99' AND status = 'quarantined'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(sticky_quarantined, 3);

    let first = identity_service.clone();
    let second = identity_service.clone();
    let first_platform = platform.clone();
    let second_platform = platform.clone();
    let (first_result, second_result) = tokio::join!(
        async move {
            first
                .record_verified_launch(
                    &first_platform,
                    &verified_identity("opaque-c", Some("100")),
                )
                .await
        },
        async move {
            second
                .record_verified_launch(
                    &second_platform,
                    &verified_identity("opaque-d", Some("100")),
                )
                .await
        }
    );
    assert!(first_result.is_ok());
    assert!(second_result.is_ok());
    let concurrent_quarantined: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM issuance_service.canvas_learner_identities
         WHERE canvas_user_id = '100' AND status = 'quarantined'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(concurrent_quarantined, 2);

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

    sqlx::query(
        "INSERT INTO issuance_service.canvas_program_bindings (
            id, organization_id, platform_id, application_template_id,
            credential_template_id, feature_flags, evidence_requirements, canvas_scope,
            enabled, config_version, validated_config_version, readiness_checks,
            readiness_validated_at, activated_at, credential_template_snapshot
        ) VALUES (
            'binding-ags', 'org-123', 'platform-123', 'app-ags', 'credential-ags',
            '{\"enable_canvas_lti\":true}'::jsonb,
            '[{\"requirement_id\":\"score-1\",\"source\":\"ags_result\",\"scope\":{\"resource_id\":\"resource-1\",\"line_item_url\":\"https://canvas.example.edu/old\"}}]'::jsonb,
            '{\"course_id\":\"course-101\"}'::jsonb, true, 4, 4,
            '[{\"code\":\"ready\",\"status\":\"ready\"}]'::json,
            clock_timestamp(), clock_timestamp(), '{\"id\":\"credential-ags\"}'::json
        )",
    )
    .execute(&pool)
    .await
    .unwrap();
    let binding = repository
        .list_program_bindings("org-123", "platform-123")
        .await
        .unwrap()
        .into_iter()
        .find(|binding| binding.id == "binding-ags")
        .unwrap();
    let request = CanvasLtiAgsPinRequest {
        binding_id: binding.id.clone(),
        requirement_id: "score-1".to_owned(),
        resource_id: "resource-1".to_owned(),
        line_item_url: "https://canvas.example.edu/new".to_owned(),
    };
    let first_repository = repository.clone();
    let second_repository = repository.clone();
    let (first, second) = tokio::join!(
        first_repository.pin_verified_line_item(&binding, &request),
        second_repository.pin_verified_line_item(&binding, &request)
    );
    assert_eq!(
        usize::from(first.unwrap()) + usize::from(second.unwrap()),
        1
    );
    let pinned = sqlx::query(
        "SELECT evidence_requirements, config_version, enabled,
            validated_config_version, readiness_checks, readiness_validated_at,
            activated_at, credential_template_snapshot
         FROM issuance_service.canvas_program_bindings WHERE id = 'binding-ags'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        pinned.get::<Value, _>("evidence_requirements")[0]["scope"]["line_item_url"],
        "https://canvas.example.edu/new"
    );
    assert_eq!(pinned.get::<i32, _>("config_version"), 5);
    assert!(!pinned.get::<bool, _>("enabled"));
    assert!(pinned
        .get::<Option<i32>, _>("validated_config_version")
        .is_none());
    assert_eq!(pinned.get::<Value, _>("readiness_checks"), json!([]));
    assert!(pinned
        .get::<Option<chrono::DateTime<chrono::Utc>>, _>("readiness_validated_at")
        .is_none());
    assert!(pinned
        .get::<Option<chrono::DateTime<chrono::Utc>>, _>("activated_at")
        .is_none());
    assert_eq!(
        pinned.get::<Value, _>("credential_template_snapshot"),
        json!({})
    );

    sqlx::query(
        "INSERT INTO issuance_service.canvas_program_bindings (
            id, organization_id, platform_id, application_template_id,
            credential_template_id, feature_flags, evidence_requirements, canvas_scope,
            enabled, config_version
        ) VALUES (
            'binding-capability', 'org-123', 'platform-123', 'app-capability',
            'credential-capability', '{\"enable_canvas_lti\":true}'::jsonb,
            '[]'::jsonb, '{\"course_id\":\"course-101\"}'::jsonb, true, 4
        )",
    )
    .execute(&pool)
    .await
    .unwrap();
    let verified_at = "2026-08-29T12:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let capability_service = CanvasLtiCapabilitySnapshotService::new(Arc::new(repository.clone()));
    let first_request = CanvasLtiCapabilitySnapshotRequest {
        organization_id: "org-123".to_owned(),
        platform_id: "platform-123".to_owned(),
        selected_platform_config_version: 1,
        binding_id: "binding-capability".to_owned(),
        selected_binding_config_version: 4,
        signed_course_id: "course-101".to_owned(),
        launch_capabilities: json!({
            "assignment_grade_services": false,
            "names_roles": true
        }),
        line_item_configuration_changed: false,
        verified_at,
    };
    let second_request = CanvasLtiCapabilitySnapshotRequest {
        launch_capabilities: json!({
            "assignment_grade_services": true,
            "names_roles": false
        }),
        ..first_request.clone()
    };
    let first_service = capability_service.clone();
    let second_service = capability_service.clone();
    let (first_snapshot, second_snapshot) = tokio::join!(
        first_service.persist_verified_capabilities(&first_request),
        second_service.persist_verified_capabilities(&second_request)
    );
    first_snapshot.unwrap();
    second_snapshot.unwrap();
    let persisted_capabilities = sqlx::query(
        "SELECT capability_snapshot, registration_status, last_validated_at,
            last_connection_error
         FROM issuance_service.canvas_platforms WHERE id = 'platform-123'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let capability_snapshot = persisted_capabilities.get::<Value, _>("capability_snapshot");
    let binding_snapshot = &capability_snapshot["verified_binding_launches"]["binding-capability"];
    assert_eq!(binding_snapshot["assignment_grade_services"], true);
    assert_eq!(binding_snapshot["names_roles"], true);
    assert_eq!(binding_snapshot["verified_binding_config_version"], 4);
    assert_eq!(binding_snapshot["verified_course_id"], "course-101");
    assert_eq!(
        persisted_capabilities.get::<String, _>("registration_status"),
        "verified"
    );
    assert_eq!(
        persisted_capabilities.get::<DateTime<Utc>, _>("last_validated_at"),
        verified_at
    );
    assert!(persisted_capabilities
        .get::<Option<String>, _>("last_connection_error")
        .is_none());

    let ags_transition_request = CanvasLtiCapabilitySnapshotRequest {
        binding_id: "binding-ags".to_owned(),
        selected_binding_config_version: 4,
        launch_capabilities: json!({
            "assignment_grade_services": true,
            "ags_lineitem_url": "https://canvas.example.edu/new"
        }),
        line_item_configuration_changed: true,
        ..first_request.clone()
    };
    let after_ags_transition = capability_service
        .persist_verified_capabilities(&ags_transition_request)
        .await
        .unwrap();
    assert_eq!(
        after_ags_transition["verified_binding_launches"]["binding-ags"]
            ["verified_binding_config_version"],
        5
    );
    assert!(after_ags_transition["verified_binding_launches"]["binding-capability"].is_object());

    let stale_request = CanvasLtiCapabilitySnapshotRequest {
        selected_binding_config_version: 3,
        ..first_request.clone()
    };
    assert!(matches!(
        capability_service
            .persist_verified_capabilities(&stale_request)
            .await,
        Err(CanvasLtiLaunchPlanError::CapabilityConfigurationDrift)
    ));
    let wrong_tenant_request = CanvasLtiCapabilitySnapshotRequest {
        organization_id: "org-other".to_owned(),
        ..first_request.clone()
    };
    assert!(matches!(
        capability_service
            .persist_verified_capabilities(&wrong_tenant_request)
            .await,
        Err(CanvasLtiLaunchPlanError::CapabilityScopeMismatch)
    ));
    sqlx::query(
        "UPDATE issuance_service.canvas_platforms
         SET config_version = 2 WHERE id = 'platform-123'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        capability_service
            .persist_verified_capabilities(&first_request)
            .await,
        Err(CanvasLtiLaunchPlanError::CapabilityConfigurationDrift)
    ));
    let after_rejections = sqlx::query_scalar::<_, Value>(
        "SELECT capability_snapshot
         FROM issuance_service.canvas_platforms WHERE id = 'platform-123'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after_rejections, after_ags_transition);

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

    let handoff_repository = PostgresCanvasLtiLoginRepository::new(pool.clone());
    let consumed_state = handoff_repository
        .get_launch_state(&state)
        .await
        .unwrap()
        .unwrap();
    let code_state = format!("experience-{}", Uuid::new_v4());
    let request = CanvasLtiExperienceHandoffRequest {
        organization_id: "org-123".to_owned(),
        platform_id: "platform-123".to_owned(),
        canvas_account_id: "account-123".to_owned(),
        code: CanvasLtiExperienceCodeSeed {
            id: Uuid::new_v4().to_string(),
            state: code_state.clone(),
            nonce: Uuid::new_v4().to_string(),
        },
        redirect_uri: consumed_state.redirect_uri.clone(),
        expires_at: Utc::now() + chrono::Duration::seconds(60),
        code_metadata: json!({
            "kind": "canvas_lti_experience_code",
            "launch_state": consumed_state.state
        }),
        consumed_state: consumed_state.clone(),
        consumed_state_metadata: json!({"experience_code_id": "code-1"}),
    };
    handoff_repository
        .persist_experience_handoff(&request)
        .await
        .unwrap();
    let handoff_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM issuance_service.canvas_lti_launch_states
         WHERE state = $1 AND status = 'pending'",
    )
    .bind(&code_state)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(handoff_rows, 1);
    assert_eq!(
        handoff_repository
            .get_launch_state(&state)
            .await
            .unwrap()
            .unwrap()
            .metadata,
        request.consumed_state_metadata
    );

    let mut rejected = request.clone();
    rejected.code.id = Uuid::new_v4().to_string();
    rejected.code.state = format!("rejected-{}", Uuid::new_v4());
    rejected.consumed_state.id = "wrong-consumed-id".to_owned();
    assert!(handoff_repository
        .persist_experience_handoff(&rejected)
        .await
        .is_err());
    let rolled_back: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM issuance_service.canvas_lti_launch_states WHERE state = $1",
    )
    .bind(&rejected.code.state)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rolled_back, 0);

    sqlx::query("DROP TABLE issuance_service.canvas_lti_launch_states")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP TABLE issuance_service.canvas_learner_identities")
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
