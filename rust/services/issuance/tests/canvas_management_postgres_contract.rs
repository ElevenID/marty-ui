use std::{collections::BTreeMap, sync::Arc, time::Duration};

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
    canvas_management_service::{CanvasBindingActivation, CanvasManagementRepositoryError},
    canvas_readiness_runtime::{
        CanvasReadinessStateProvider, PostgresCanvasReadinessStateProvider,
    },
    canvas_sync_lease::CanvasSyncLease,
    canvas_sync_processor::{
        CanvasAuthoritativeObservation, CanvasRosterCandidate, CanvasSyncProcessorRepository,
    },
    canvas_sync_processor_postgres::PostgresCanvasSyncProcessorRepository,
    canvas_sync_worker::CanvasSyncWorkerRepository,
    canvas_sync_worker_postgres::PostgresCanvasSyncWorkerRepository,
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
    for storage_type in ["json", "jsonb"] {
        management_contract(storage_type).await;
    }
}

async fn management_contract(storage_type: &str) {
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
    if storage_type == "json" {
        // These are newly created isolated tables, never a live schema rewrite.
        for statement in [
            "ALTER TABLE issuance_service.canvas_platforms ALTER COLUMN connection_config TYPE json USING connection_config::json",
            "ALTER TABLE issuance_service.canvas_evidence_sync_targets ALTER COLUMN metadata TYPE json USING metadata::json, ALTER COLUMN metadata SET DEFAULT '{}'::json",
        ] {
            sqlx::query(statement).execute(&pool).await.unwrap();
        }
    }
    for (table, column) in [
        ("canvas_platforms", "connection_config"),
        ("canvas_evidence_sync_targets", "metadata"),
    ] {
        let actual_type: String = sqlx::query_scalar(
            "SELECT data_type FROM information_schema.columns WHERE table_schema = 'issuance_service'
             AND table_name = $1 AND column_name = $2",
        ).bind(table).bind(column).fetch_one(&pool).await.unwrap();
        assert_eq!(actual_type, storage_type);
    }

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
    let mut touch_platform = CanvasPlatformRecord::new_draft(
        "org-touch".to_owned(),
        platform_request("Touch", false),
        origin.clone(),
        now,
    )
    .unwrap();
    touch_platform
        .connection_config
        .insert("lti_capability_intent".into(), json!([]));
    touch_platform
        .connection_config
        .insert("unrelated".into(), json!({"nested": [true, null, "keep"]}));
    repository.create_platform(&touch_platform).await.unwrap();
    let touched = repository
        .save_platform_configuration(&touch_platform, 1, false)
        .await
        .unwrap()
        .expect("no-change configuration touch supports stored JSON type");
    assert_eq!(touched.config_version, 1);
    assert_eq!(touched.connection_config, touch_platform.connection_config);
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
         SET connection_config = (connection_config::jsonb - 'lti_capability_intent') || '{\"oauth_status\":\"connected\",\"unrelated\":{\"nested\":[true,null,\"preserved\"]}}'::jsonb,
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
        updated.connection_config["unrelated"],
        json!({"nested": [true, null, "preserved"]})
    );
    assert_eq!(
        updated.connection_config["lti_capability_intent"],
        json!(["ags", "nrps"])
    );
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
         SET connection_config = connection_config::jsonb
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
        "INSERT INTO issuance_service.applications
             (id, organization_id, application_template_id, integration_context,
              status, credential_id)
         VALUES
             ('application-pending', 'org-management', 'application-template-native',
              jsonb_build_object('canvas', jsonb_build_object(
                  'canvas_program_binding_id', $1)), 'pending', NULL),
             ('application-issued', 'org-management', 'application-template-native',
              jsonb_build_object('canvas', jsonb_build_object(
                  'canvas_program_binding_id', $1)), 'approved', 'credential-1'),
             ('application-rejected', 'org-management', 'application-template-native',
              jsonb_build_object('canvas', jsonb_build_object(
                  'canvas_program_binding_id', $1)), 'rejected', NULL),
             ('application-other-binding', 'org-management', 'application-template-native',
              '{\"canvas\":{\"canvas_program_binding_id\":\"other\"}}'::jsonb,
              'pending', NULL)",
    )
    .bind(&readiness_binding.id)
    .execute(&pool)
    .await
    .unwrap();
    let activated_at = now + chrono::Duration::seconds(15);
    // Force the conflict-update path as well as the fresh application targets.
    // Existing unrelated roster progress must survive metadata merging.
    sqlx::query(
        "INSERT INTO issuance_service.canvas_evidence_sync_targets
         (id, organization_id, platform_id, binding_id, logical_key, enabled,
          schedule_seconds, next_run_at, metadata)
         VALUES ('existing-roster', 'org-management', $1, $2, $3, false, 60, $4,
                 '{\"unrelated\":{\"cursor\":\"keep\",\"values\":[true,null,42]},\"verified_course_id\":\"old\"}'::json)",
    ).bind(&conflicting.id).bind(&readiness_binding.id)
        .bind(format!("roster:{}", readiness_binding.id)).bind(activated_at)
        .execute(&pool).await.unwrap();
    let activated = repository
        .activate_binding(&CanvasBindingActivation {
            binding: readiness_binding.clone(),
            platform: conflicting.clone(),
            activated_at,
            background_roster_metadata: Some(
                json!({
                    "created_from": "binding_activation",
                    "verified_binding_id": readiness_binding.id,
                    "verified_binding_config_version": readiness_binding.config_version,
                    "verified_course_id": "course-202",
                    "nrps_context_memberships_url": "https://canvas.example.edu/nrps"
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        })
        .await
        .unwrap()
        .expect("atomic binding activation");
    assert!(activated.enabled);
    assert_eq!(activated.activated_at, Some(activated_at));
    assert!(
        repository
            .active_platform("org-management", &conflicting.id)
            .await
            .unwrap()
            .expect("activated platform")
            .enabled
    );
    let targets = sqlx::query(
        "SELECT logical_key, target_type, enabled, schedule_seconds, metadata
         FROM issuance_service.canvas_evidence_sync_targets
         ORDER BY logical_key",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(targets.len(), 3);
    assert_eq!(
        targets[0].try_get::<String, _>("logical_key").unwrap(),
        "application:application-issued"
    );
    assert_eq!(
        targets[0].try_get::<String, _>("target_type").unwrap(),
        "issued_drift"
    );
    assert_eq!(
        targets[0].try_get::<i32, _>("schedule_seconds").unwrap(),
        6 * 60 * 60
    );
    assert_eq!(
        targets[1].try_get::<String, _>("logical_key").unwrap(),
        "application:application-pending"
    );
    assert_eq!(
        targets[1].try_get::<String, _>("target_type").unwrap(),
        "learner_application"
    );
    assert_eq!(
        targets[2].try_get::<String, _>("logical_key").unwrap(),
        format!("roster:{}", readiness_binding.id)
    );
    assert_eq!(
        targets[2].try_get::<String, _>("target_type").unwrap(),
        "background_roster"
    );
    assert_eq!(
        targets[2]
            .try_get::<serde_json::Value, _>("metadata")
            .unwrap()["verified_course_id"],
        "course-202"
    );
    assert!(targets
        .iter()
        .all(|target| target.try_get::<bool, _>("enabled").unwrap()));
    assert_eq!(
        targets[2].get::<serde_json::Value, _>("metadata")["unrelated"],
        json!({"cursor": "keep", "values": [true, null, 42]})
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.canvas_evidence_sync_jobs
             WHERE status = 'queued'",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        3
    );
    assert!(repository
        .activate_binding(&CanvasBindingActivation {
            binding: readiness_binding.clone(),
            platform: conflicting.clone(),
            activated_at,
            background_roster_metadata: None,
        })
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.canvas_evidence_sync_targets",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        3
    );
    assert_roster_cursor_storage(&pool).await;
    let deactivated = repository
        .deactivate_binding(&activated, now + chrono::Duration::seconds(16))
        .await
        .unwrap()
        .expect("atomic binding deactivation");
    assert!(!deactivated.enabled);
    assert!(deactivated.activated_at.is_none());
    assert!(!sqlx::query_scalar::<_, bool>(
        "SELECT enabled FROM issuance_service.canvas_evidence_sync_targets
         WHERE logical_key = $1",
    )
    .bind(format!("roster:{}", readiness_binding.id))
    .fetch_one(&pool)
    .await
    .unwrap());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.canvas_evidence_sync_targets
             WHERE enabled = true",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        2
    );

    let evaluated_at = now + chrono::Duration::minutes(30);
    sqlx::query(
        "UPDATE issuance_service.canvas_oauth_connections
         SET status = 'connected', reauthorization_required = false,
             access_token_secret_ref = 'org_secret://org-management/oauth-access',
             capabilities = '[\"course_completion\"]'::jsonb,
             scopes = '[\"url:GET|/api/v1/courses/:course_id\"]'::jsonb
         WHERE id = 'oauth-conflict'",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.canvas_worker_heartbeats
             (worker_id, role, last_heartbeat_at, metadata)
         VALUES ('worker-contract', 'canvas_sync', $1,
                 '{\"processor_configured\":true}'::jsonb)",
    )
    .bind(evaluated_at - chrono::Duration::seconds(30))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.canvas_evidence_sync_targets
             (id, organization_id, platform_id, binding_id, logical_key, enabled,
              schedule_seconds, next_run_at)
         VALUES ('target-contract', 'org-management', $1, $2,
                 'contract:readiness', true, 300, $3)",
    )
    .bind(&conflicting.id)
    .bind(&readiness_binding.id)
    .bind(evaluated_at + chrono::Duration::seconds(300))
    .execute(&pool)
    .await
    .unwrap();
    let readiness_state =
        PostgresCanvasReadinessStateProvider::new(pool.clone(), Duration::from_secs(120));
    let oauth = readiness_state
        .oauth_connection("org-management", &conflicting.id)
        .await
        .unwrap()
        .expect("connected OAuth projection");
    assert!(oauth.connected);
    assert!(oauth.access_token_secret_configured);
    assert_eq!(
        oauth.capabilities,
        ["course_completion".to_owned()].into_iter().collect()
    );
    assert!(readiness_state
        .worker_heartbeat_configured(evaluated_at)
        .await
        .unwrap());
    assert_eq!(
        readiness_state
            .sync_readiness(
                "org-management",
                &conflicting.id,
                &readiness_binding.id,
                evaluated_at,
            )
            .await
            .unwrap(),
        Default::default()
    );
    sqlx::query(
        "INSERT INTO issuance_service.canvas_evidence_sync_jobs
             (id, target_id, organization_id, status, created_at)
         VALUES ('job-dead-letter', 'target-contract', 'org-management',
                 'dead_letter', $1)",
    )
    .bind(evaluated_at)
    .execute(&pool)
    .await
    .unwrap();
    let failed_sync = readiness_state
        .sync_readiness(
            "org-management",
            &conflicting.id,
            &readiness_binding.id,
            evaluated_at,
        )
        .await
        .unwrap();
    assert!(failed_sync.dead_lettered);
    assert!(!failed_sync.stale_backlog);

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

async fn assert_roster_cursor_storage(pool: &sqlx::PgPool) {
    let worker = PostgresCanvasSyncWorkerRepository::new(pool.clone());
    let unscoped = Arc::new(PostgresCanvasSyncProcessorRepository::new(pool.clone()));
    let target = worker
        .target("org-management", "existing-roster")
        .await
        .unwrap()
        .unwrap();
    let resources = unscoped.resources(&target).await.unwrap().unwrap();
    let original = roster_storage(pool).await;
    let candidate = CanvasRosterCandidate {
        id: "unauthorized-candidate".into(),
        candidate_key: "synthetic".into(),
        canvas_user_id: None,
        lti_subject: None,
        learner_identity_id: None,
        state: "pending".into(),
    };
    let observation = CanvasAuthoritativeObservation {
        assertion: Map::new(),
        source_payload: Map::new(),
        verification_method: "synthetic",
        effective_at: None,
    };
    for effect in [
        "fact",
        "application",
        "platform",
        "disable",
        "candidate",
        "observation",
        "cursor",
    ] {
        let denied = match effect {
            "fact" => unscoped
                .record_fact(&target, &resources, &json!({}))
                .await
                .map(|_| ()),
            "application" => unscoped
                .patch_application_sync(&target, &resources, &[], true)
                .await
                .map(|_| ()),
            "platform" => unscoped
                .patch_platform_validation(&target, &resources, None)
                .await
                .map(|_| ()),
            "disable" => unscoped.disable_target(&target).await,
            "candidate" => unscoped
                .save_candidate(&target, &resources, &candidate)
                .await
                .map(|_| ()),
            "observation" => unscoped
                .save_candidate_observation(
                    &target,
                    &resources,
                    &candidate.id,
                    "synthetic",
                    &observation,
                )
                .await
                .map(|_| ()),
            "cursor" => {
                unscoped
                    .update_roster_cursor(&target, &resources, 25, 40)
                    .await
            }
            _ => unreachable!(),
        }
        .unwrap_err();
        assert_eq!(denied.code, "canvas_sync_lease_lost", "{effect}");
    }
    assert_eq!(roster_storage(pool).await, original);
    // Binding activation already created the durable roster job. Lease that
    // real job instead of inventing a second active job for the same target.
    let job = worker
        .lease_ready("processor-auth-worker", &100_u64.into(), &120_u64.into())
        .await
        .unwrap()
        .into_iter()
        .find(|job| job.target_id == "existing-roster")
        .unwrap();
    let lease = CanvasSyncLease::from_job(&job, "processor-auth-worker").unwrap();
    let processor = unscoped.clone().for_lease(lease);
    processor
        .update_roster_cursor(&target, &resources, 25, 40)
        .await
        .unwrap();
    let partial = roster_storage(pool).await;
    assert_eq!(partial.0["roster_cursor"], 25);
    assert_eq!(partial.0["roster_size"], 40);
    assert_eq!(
        partial.0["roster_cycle_completed_at"],
        serde_json::Value::Null
    );
    for (key, value) in original.0.as_object().unwrap() {
        assert_eq!(&partial.0[key], value, "cursor update must preserve {key}");
    }
    // Compare timestamps from the same database statement, not wall-clock
    // time after CI scheduling/transport delays.
    let scheduled_seconds = (partial.1 - partial.2).num_seconds();
    assert!((59..=60).contains(&scheduled_seconds));
    processor
        .update_roster_cursor(&target, &resources, 0, 40)
        .await
        .unwrap();
    let completed = roster_storage(pool).await;
    assert_eq!(completed.0["roster_cursor"], 0);
    assert_eq!(completed.0["roster_size"], 40);
    assert!(completed.0["roster_cycle_completed_at"].as_str().is_some());
    assert_eq!(
        completed.1, partial.1,
        "cycle completion must not reschedule"
    );

    for dimension in 0..6 {
        let mut stale_target = target.clone();
        let mut stale_resources = resources.clone();
        match dimension {
            0 => stale_target.id = "other-target".into(),
            1 => stale_target.organization_id = "other-org".into(),
            2 => stale_target.platform_id = "other-platform".into(),
            3 => stale_target.binding_id = "other-binding".into(),
            4 => stale_target.config_version += 1,
            _ => stale_resources.platform.config_version += 1,
        }
        let failure = processor
            .update_roster_cursor(&stale_target, &stale_resources, 99, 100)
            .await
            .unwrap_err();
        assert_eq!(
            failure.code,
            if dimension < 2 {
                "canvas_sync_lease_lost"
            } else {
                "canvas_platform_reconfigured"
            }
        );
        assert!(failure.retryable);
        assert_eq!(roster_storage(pool).await, completed);
    }

    // Independent per-job handles must not change the shared repository's
    // identity or another job's authorization. Exercise the new guard only
    // after implementation, against this dedicated synthetic database.
    for dimension in ["missing", "organization", "target", "owner", "attempt"] {
        let mut different_job = job.clone();
        let mut expected_worker = "processor-auth-worker";
        match dimension {
            "missing" => different_job.id = "missing-processor-job".into(),
            "organization" => different_job.organization_id = "other-org".into(),
            "target" => different_job.target_id = "other-target".into(),
            "owner" => {
                expected_worker = "other-worker";
                different_job.lease_owner = Some(expected_worker.into());
            }
            "attempt" => different_job.attempt_count += 1,
            _ => unreachable!(),
        }
        let other = unscoped
            .clone()
            .for_lease(CanvasSyncLease::from_job(&different_job, expected_worker).unwrap());
        let denied = other
            .update_roster_cursor(&target, &resources, 99, 100)
            .await
            .unwrap_err();
        assert_eq!(denied.code, "canvas_sync_lease_lost", "{dimension}");
        assert_eq!(roster_storage(pool).await, completed, "{dimension}");
    }
    processor
        .update_roster_cursor(&target, &resources, 0, 40)
        .await
        .unwrap();
    let completed = roster_storage(pool).await;
    sqlx::query("UPDATE issuance_service.canvas_evidence_sync_jobs SET status = 'retry' WHERE target_id = 'existing-roster'")
        .execute(pool).await.unwrap();
    assert_eq!(
        processor
            .update_roster_cursor(&target, &resources, 99, 100)
            .await
            .unwrap_err()
            .code,
        "canvas_sync_lease_lost"
    );
    assert_eq!(roster_storage(pool).await, completed);
    sqlx::query("UPDATE issuance_service.canvas_evidence_sync_jobs SET status = 'leased' WHERE target_id = 'existing-roster'")
        .execute(pool).await.unwrap();

    // Expiry while an effect is in its transaction must roll the entire effect
    // back. This trigger is a test-only deterministic clock/expiry fault, not a
    // replacement for the production writer or its authorization queries.
    sqlx::raw_sql(
        "CREATE FUNCTION issuance_service.expire_processor_test_lease() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
           UPDATE issuance_service.canvas_evidence_sync_jobs
             SET lease_expires_at = clock_timestamp() - interval '1 second'
             WHERE target_id = 'existing-roster';
           RETURN NEW;
         END $$;
         CREATE TRIGGER expire_processor_test_lease AFTER UPDATE OF metadata
           ON issuance_service.canvas_evidence_sync_targets FOR EACH ROW
           EXECUTE FUNCTION issuance_service.expire_processor_test_lease();",
    ).execute(pool).await.unwrap();
    assert_eq!(
        processor
            .update_roster_cursor(&target, &resources, 99, 100)
            .await
            .unwrap_err()
            .code,
        "canvas_sync_lease_lost"
    );
    assert_eq!(roster_storage(pool).await, completed);
    let expiry: chrono::DateTime<Utc> = sqlx::query_scalar("SELECT lease_expires_at FROM issuance_service.canvas_evidence_sync_jobs WHERE target_id = 'existing-roster'")
        .fetch_one(pool).await.unwrap();
    assert_eq!(
        Some(expiry),
        job.lease_expires_at,
        "both the effect and injected expiry rolled back"
    );
    sqlx::raw_sql(
        "DROP TRIGGER expire_processor_test_lease ON issuance_service.canvas_evidence_sync_targets;
         DROP FUNCTION issuance_service.expire_processor_test_lease();",
    )
    .execute(pool)
    .await
    .unwrap();

    let mut blocked = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM issuance_service.canvas_evidence_sync_jobs WHERE target_id = 'existing-roster' FOR UPDATE")
        .fetch_one(&mut *blocked).await.unwrap();
    let mut waiting = Box::pin(processor.update_roster_cursor(&target, &resources, 99, 100));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut waiting)
            .await
            .is_err()
    );
    sqlx::query("UPDATE issuance_service.canvas_evidence_sync_jobs SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE target_id = 'existing-roster'")
        .execute(&mut *blocked).await.unwrap();
    blocked.commit().await.unwrap();
    let denied = tokio::time::timeout(Duration::from_secs(3), waiting)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(denied.code, "canvas_sync_lease_lost");
    assert_eq!(
        roster_storage(pool).await,
        completed,
        "no pre-lock timestamp grant"
    );
}

async fn roster_storage(
    pool: &sqlx::PgPool,
) -> (
    serde_json::Value,
    chrono::DateTime<Utc>,
    chrono::DateTime<Utc>,
) {
    sqlx::query_as("SELECT metadata, next_run_at, updated_at FROM issuance_service.canvas_evidence_sync_targets WHERE id = 'existing-roster'")
        .fetch_one(pool).await.unwrap()
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
            access_token_secret_ref text,
            capabilities jsonb NOT NULL DEFAULT '[]'::jsonb,
            scopes jsonb NOT NULL DEFAULT '[]'::jsonb,
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
    sqlx::query(
        "CREATE TABLE issuance_service.canvas_worker_heartbeats (
            worker_id text NOT NULL,
            role text NOT NULL,
            last_heartbeat_at timestamptz NOT NULL,
            metadata jsonb NOT NULL DEFAULT '{}'::jsonb)",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE issuance_service.applications (
            id text PRIMARY KEY,
            organization_id text NOT NULL,
            application_template_id text NOT NULL,
            integration_context jsonb NOT NULL DEFAULT '{}'::jsonb,
            status text NOT NULL,
            credential_id text)",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE issuance_service.canvas_evidence_sync_targets (
            id text PRIMARY KEY,
            organization_id text NOT NULL,
            platform_id text NOT NULL,
            binding_id text NOT NULL,
            target_type text NOT NULL DEFAULT 'learner_application',
            logical_key text NOT NULL,
            application_id text,
            candidate_id text,
            enabled boolean NOT NULL,
            schedule_seconds integer NOT NULL,
            next_run_at timestamptz NOT NULL,
            last_enqueued_at timestamptz,
            last_succeeded_at timestamptz,
            config_version integer NOT NULL DEFAULT 1,
            metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            UNIQUE (organization_id, logical_key))",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE issuance_service.canvas_evidence_sync_jobs (
            id text PRIMARY KEY,
            target_id text NOT NULL,
            organization_id text NOT NULL,
            status text NOT NULL,
            attempt_count integer NOT NULL DEFAULT 0,
            max_attempts integer NOT NULL DEFAULT 8,
            available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            lease_owner text,
            lease_expires_at timestamptz,
            last_error_code text,
            last_error_summary text,
            result jsonb NOT NULL DEFAULT '{}'::jsonb,
            created_at timestamptz NOT NULL,
            updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            started_at timestamptz,
            completed_at timestamptz)",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE UNIQUE INDEX ux_canvas_sync_jobs_one_active_target
         ON issuance_service.canvas_evidence_sync_jobs (target_id)
         WHERE status IN ('queued', 'leased', 'retry')",
    )
    .execute(pool)
    .await
    .unwrap();
}
