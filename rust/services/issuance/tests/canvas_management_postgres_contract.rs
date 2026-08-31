use std::collections::BTreeMap;

use chrono::{TimeZone, Utc};
use marty_issuance_service::{
    canvas_binding_domain::{CanvasApplicationTemplateProjection, CanvasProgramBindingRecord},
    canvas_management::{
        CanvasDeliveryMode, CanvasEvidenceFactType, CanvasEvidencePassRuleInput,
        CanvasEvidenceRequirementInput, CanvasEvidenceScopeInput, CanvasEvidenceSource,
        CanvasLtiInstallationRequest, CanvasPlatformRequest, CanvasProgramBindingRequest,
    },
    canvas_management_domain::{CanvasOriginPolicy, CanvasPlatformRecord},
    canvas_management_postgres::PostgresCanvasManagementRepository,
    canvas_management_service::CanvasManagementRepositoryError,
};
use marty_oid4vci::lti::CanvasLtiPlatformProbe;
use serde_json::{json, Map};
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

fn binding_request(course_id: &str) -> CanvasProgramBindingRequest {
    CanvasProgramBindingRequest {
        application_template_id: "application-template-native".to_owned(),
        credential_template_id: None,
        display_name: Some(format!("Course {course_id}")),
        auto_approve_on_evidence: false,
        evidence_requirements: vec![CanvasEvidenceRequirementInput {
            requirement_id: None,
            source: CanvasEvidenceSource::CanvasRest,
            fact_type: CanvasEvidenceFactType::CourseCompletion,
            scope: CanvasEvidenceScopeInput {
                course_id: course_id.to_owned(),
                activity_id: None,
                module_id: None,
                line_item_url: None,
                resource_id: None,
            },
            pass_rule: CanvasEvidencePassRuleInput {
                min_score_percent: None,
                completed: Some(true),
            },
            required: true,
        }],
        canvas_scope: BTreeMap::from([("course_id".to_owned(), course_id.to_owned())]),
        delivery_mode: CanvasDeliveryMode::WalletOnly,
        approval_policy_set_id: None,
        deployment_profile_id: None,
        feature_flags: BTreeMap::new(),
        canvas_credentials: None,
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
    let mut registration_platform = platform.clone();
    registration_platform
        .issue_lti_config_token("a".repeat(64), now + chrono::Duration::seconds(1));
    let registration_platform = repository
        .save_registration_state(&registration_platform, 1, platform.updated_at)
        .await
        .unwrap()
        .expect("registration state CAS");
    assert_eq!(
        registration_platform.active_lti_config_token_hash(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert_eq!(
        repository
            .public_platform(&platform.id)
            .await
            .unwrap()
            .expect("public token lookup")
            .active_lti_config_token_hash(),
        registration_platform.active_lti_config_token_hash()
    );
    assert!(repository
        .save_registration_state(&registration_platform, 1, platform.updated_at)
        .await
        .unwrap()
        .is_none());
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

    let mut installation = CanvasPlatformRecord::new_draft(
        "org-management".to_owned(),
        platform_request("Installation", true),
        CanvasOriginPolicy::default()
            .resolve("https://canvas.example.edu")
            .unwrap(),
        now + chrono::Duration::seconds(4),
    )
    .unwrap();
    repository.create_platform(&installation).await.unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.canvas_program_bindings
             (id, organization_id, platform_id, enabled, validated_config_version,
              readiness_checks, readiness_validated_at, activated_at,
              archived_at, updated_at)
         VALUES ('binding-installation', 'org-management', $1, true, 1,
                 '[{\"status\":\"ready\"}]'::jsonb, clock_timestamp(),
                 clock_timestamp(), NULL, clock_timestamp())",
    )
    .bind(&installation.id)
    .execute(&pool)
    .await
    .unwrap();
    let installation_updated_at = installation.updated_at;
    let changed = installation
        .prepare_lti_installation(
            &CanvasLtiInstallationRequest {
                lti_client_id: "installed-client".to_owned(),
                lti_deployment_id: "installed-deployment".to_owned(),
                rotate_config_token: false,
                revoke_config_token: false,
            },
            now + chrono::Duration::seconds(5),
        )
        .unwrap();
    assert!(changed);
    installation
        .apply_lti_metadata_probe(
            CanvasLtiPlatformProbe {
                canvas_base_url: "https://canvas.example.edu".to_owned(),
                issuer: "https://canvas.instructure.com".to_owned(),
                authorization_endpoint: Some(
                    "https://sso.canvaslms.com/api/lti/authorize_redirect".to_owned(),
                ),
                token_endpoint: Some("https://canvas.example.edu/login/oauth2/token".to_owned()),
                jwks_uri: "https://sso.canvaslms.com/api/lti/security/jwks".to_owned(),
                registration_endpoint: None,
                raw_openid_configuration: json!({"issuer": "https://canvas.instructure.com"}),
                jwks_json: json!({"keys": [{"kid": "installation-key"}]}),
            },
            std::time::Duration::from_secs(3_600),
            now + chrono::Duration::seconds(6),
        )
        .unwrap();
    installation.complete_lti_installation_after_probe();
    installation.issue_lti_config_token("b".repeat(64), now + chrono::Duration::seconds(7));
    let installed = repository
        .save_lti_installation(&installation, 1, installation_updated_at, changed)
        .await
        .unwrap()
        .expect("installation CAS");
    assert_eq!(installed.config_version, 2);
    assert_eq!(installed.registration_status, "installed");
    assert!(installed.enabled);
    assert_eq!(installed.lti_client_id.as_deref(), Some("installed-client"));
    assert_eq!(
        installed.lti_jwks_json,
        Some(json!({"keys": [{"kid": "installation-key"}]}))
    );
    assert_eq!(
        installed.active_lti_config_token_hash(),
        Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    );
    let binding = sqlx::query(
        "SELECT enabled, validated_config_version, readiness_checks,
                readiness_validated_at, activated_at
         FROM issuance_service.canvas_program_bindings
         WHERE id = 'binding-installation'",
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
    assert!(repository
        .save_lti_installation(&installation, 1, installation_updated_at, true)
        .await
        .unwrap()
        .is_none());

    sqlx::query(
        "UPDATE issuance_service.canvas_program_bindings
         SET enabled = true, validated_config_version = 2,
             readiness_checks = '[{\"status\":\"ready\"}]'::jsonb,
             readiness_validated_at = clock_timestamp(),
             activated_at = clock_timestamp()
         WHERE id = 'binding-installation'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let mut refreshed = installed.clone();
    refreshed
        .apply_lti_metadata_probe(
            CanvasLtiPlatformProbe {
                canvas_base_url: "https://canvas.example.edu".to_owned(),
                issuer: "https://canvas.instructure.com".to_owned(),
                authorization_endpoint: Some(
                    "https://sso.canvaslms.com/api/lti/authorize_redirect".to_owned(),
                ),
                token_endpoint: Some("https://canvas.example.edu/login/oauth2/token".to_owned()),
                jwks_uri: "https://sso.canvaslms.com/api/lti/security/jwks".to_owned(),
                registration_endpoint: None,
                raw_openid_configuration: json!({"issuer": "https://canvas.instructure.com"}),
                jwks_json: json!({"keys": [{"kid": "refreshed-key"}]}),
            },
            std::time::Duration::from_secs(7_200),
            now + chrono::Duration::seconds(8),
        )
        .unwrap();
    let refreshed = repository
        .save_lti_probe_metadata(&refreshed, installed.config_version, installed.updated_at)
        .await
        .unwrap()
        .expect("probe metadata CAS");
    assert_eq!(
        refreshed.lti_jwks_json,
        Some(json!({"keys": [{"kid": "refreshed-key"}]}))
    );
    assert!(refreshed.enabled);
    assert_eq!(refreshed.registration_status, "installed");
    assert_eq!(
        refreshed.active_lti_config_token_hash(),
        installed.active_lti_config_token_hash()
    );
    let binding = sqlx::query(
        "SELECT enabled, validated_config_version FROM issuance_service.canvas_program_bindings
         WHERE id = 'binding-installation'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(binding.try_get::<bool, _>("enabled").unwrap());
    assert_eq!(
        binding
            .try_get::<Option<i32>, _>("validated_config_version")
            .unwrap(),
        Some(2)
    );
    assert!(repository
        .save_lti_probe_metadata(&refreshed, installed.config_version, installed.updated_at)
        .await
        .unwrap()
        .is_none());

    let conflicting = CanvasPlatformRecord::new_draft(
        "org-management".to_owned(),
        platform_request("Conflict", false),
        CanvasOriginPolicy::default()
            .resolve("https://canvas.example.edu")
            .unwrap(),
        now + chrono::Duration::seconds(9),
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
                now + chrono::Duration::seconds(10),
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
                now + chrono::Duration::seconds(11),
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

    sqlx::query(
        "INSERT INTO issuance_service.application_templates
             (id, organization_id, credential_template_id, approval_policy_set_id, status)
         VALUES ('application-template-native', 'org-management',
                 'credential-template-native', 'policy-native', 'active')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.organization_integration_secrets
             (id, organization_id, provider, purpose, enabled)
         VALUES ('secret-native', 'org-management', 'canvas_credentials',
                 'api_token', true)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let template = repository
        .application_template("application-template-native")
        .await
        .unwrap()
        .expect("application template projection");
    assert_eq!(
        template,
        CanvasApplicationTemplateProjection {
            id: "application-template-native".to_owned(),
            organization_id: "org-management".to_owned(),
            credential_template_id: Some("credential-template-native".to_owned()),
            approval_policy_set_id: Some("policy-native".to_owned()),
            active: true,
        }
    );
    assert!(repository
        .valid_canvas_credentials_secret("org-management", "secret-native")
        .await
        .unwrap());
    assert!(!repository
        .valid_canvas_credentials_secret("org-foreign", "secret-native")
        .await
        .unwrap());

    let native_binding = CanvasProgramBindingRecord::configure(
        &conflicting,
        binding_request("course-101"),
        &template,
        Map::new(),
        None,
        now + chrono::Duration::seconds(12),
    )
    .unwrap();
    repository.create_binding(&native_binding).await.unwrap();
    assert_eq!(
        repository.create_binding(&native_binding).await,
        Err(CanvasManagementRepositoryError::DuplicateBinding)
    );
    assert!(repository
        .active_binding("org-foreign", &native_binding.id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        repository
            .list_active_bindings(
                "org-management",
                Some(&conflicting.id),
                Some("application-template-native"),
            )
            .await
            .unwrap(),
        vec![native_binding.clone()]
    );

    let updated_binding = CanvasProgramBindingRecord::configure(
        &conflicting,
        binding_request("course-202"),
        &template,
        Map::new(),
        Some(&native_binding),
        now + chrono::Duration::seconds(13),
    )
    .unwrap();
    let updated_binding = repository
        .save_binding_configuration(&updated_binding, native_binding.config_version)
        .await
        .unwrap()
        .expect("binding configuration CAS");
    assert_eq!(updated_binding.config_version, 2);
    assert_eq!(updated_binding.canvas_scope["course_id"], "course-202");
    assert!(repository
        .save_binding_configuration(&updated_binding, native_binding.config_version)
        .await
        .unwrap()
        .is_none());
    let mut readiness_binding = updated_binding.clone();
    readiness_binding.validated_config_version = Some(updated_binding.config_version);
    readiness_binding.readiness_checks = vec![json!({
        "code": "worker_heartbeat",
        "component": "synchronization",
        "status": "ready",
        "blocking": true,
        "remediation": "",
        "timestamp": "2026-08-30T22:00:14+00:00"
    })];
    readiness_binding.readiness_validated_at = Some(now + chrono::Duration::seconds(14));
    readiness_binding.credential_template_snapshot = json!({
        "id": "credential-template-native",
        "status": "active"
    })
    .as_object()
    .unwrap()
    .clone();
    let readiness_binding = repository
        .save_binding_readiness(
            &readiness_binding,
            updated_binding.config_version,
            updated_binding.updated_at,
        )
        .await
        .unwrap()
        .expect("binding readiness CAS");
    assert_eq!(
        readiness_binding.validated_config_version,
        Some(updated_binding.config_version)
    );
    assert_eq!(readiness_binding.readiness_checks.len(), 1);
    assert_eq!(
        readiness_binding.credential_template_snapshot["id"],
        "credential-template-native"
    );
    assert_eq!(readiness_binding.updated_at, updated_binding.updated_at);
    sqlx::query(
        "UPDATE issuance_service.canvas_program_bindings
         SET updated_at = $2 WHERE id = $1",
    )
    .bind(&readiness_binding.id)
    .bind(now + chrono::Duration::seconds(15))
    .execute(&pool)
    .await
    .unwrap();
    assert!(repository
        .save_binding_readiness(
            &readiness_binding,
            readiness_binding.config_version,
            readiness_binding.updated_at,
        )
        .await
        .unwrap()
        .is_none());
    let archived_binding = repository
        .archive_binding(
            "org-management",
            &updated_binding.id,
            updated_binding.config_version,
            now + chrono::Duration::seconds(16),
        )
        .await
        .unwrap()
        .expect("binding archive CAS");
    assert!(!archived_binding.enabled);
    assert!(archived_binding.archived_at.is_some());
    assert!(repository
        .active_binding("org-management", &updated_binding.id)
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
        "CREATE TABLE issuance_service.application_templates (
            id text PRIMARY KEY,
            organization_id text NOT NULL,
            credential_template_id text,
            approval_policy_set_id text,
            status text NOT NULL)",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE issuance_service.organization_integration_secrets (
            id text PRIMARY KEY,
            organization_id text NOT NULL,
            provider text NOT NULL,
            purpose text NOT NULL,
            enabled boolean NOT NULL)",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE issuance_service.canvas_program_bindings (
            id text PRIMARY KEY,
            organization_id text NOT NULL,
            platform_id text NOT NULL REFERENCES issuance_service.canvas_platforms(id),
            application_template_id text NOT NULL DEFAULT 'application-template-contract',
            credential_template_id text NOT NULL DEFAULT 'credential-template-contract',
            display_name text,
            flow_mode text NOT NULL DEFAULT 'elevenid_orchestrated_canvas_evidence',
            direct_issue_enabled boolean NOT NULL DEFAULT false,
            auto_approve_on_evidence boolean NOT NULL DEFAULT false,
            evidence_requirements jsonb NOT NULL DEFAULT '[]'::jsonb,
            canvas_scope jsonb NOT NULL DEFAULT '{}'::jsonb,
            delivery_mode text NOT NULL DEFAULT 'wallet_only',
            issuer_mode text NOT NULL DEFAULT 'org_managed',
            approval_policy_set_id text,
            deployment_profile_id text,
            feature_flags jsonb NOT NULL DEFAULT '{}'::jsonb,
            canvas_credentials jsonb NOT NULL DEFAULT '{}'::jsonb,
            config_version integer NOT NULL DEFAULT 1,
            enabled boolean NOT NULL,
            validated_config_version integer,
            readiness_checks jsonb NOT NULL,
            readiness_validated_at timestamptz,
            activated_at timestamptz,
            archived_at timestamptz,
            credential_template_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
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
