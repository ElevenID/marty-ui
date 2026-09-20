use chrono::{Duration, TimeZone, Utc};
use marty_issuance_service::{
    application_template_domain::{ApplicationTemplateCreate, ApplicationTemplateStatus},
    internal_application_domain::{
        ApplicationCreate, ApplicationRecord, ApplicationStatus, EvidenceFactRecord,
        EvidenceSubmission, IssuanceEventRecord,
    },
    internal_application_postgres::PostgresInternalApplicationRepository,
    internal_application_service::{
        InternalApplicationRepository, InternalApplicationRepositoryError,
    },
};
use serde_json::{json, Map};
use sqlx::postgres::PgPoolOptions;

#[tokio::test]
async fn internal_application_repository_round_trips_filters_and_compares_exact_revisions() {
    let Ok(database_url) = std::env::var("ISSUANCE_POSTGRES_TEST_URL") else {
        return;
    };
    let database_name = url::Url::parse(&database_url)
        .expect("issuance PostgreSQL contract URL must parse")
        .path()
        .trim_start_matches('/')
        .to_owned();
    assert!(
        database_name.ends_with("_test"),
        "ISSUANCE_POSTGRES_TEST_URL must name a dedicated *_test database"
    );
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("issuance PostgreSQL contract database must connect");

    for statement in [
        "CREATE SCHEMA IF NOT EXISTS issuance_service",
        "DROP TABLE IF EXISTS issuance_service.issuance_events CASCADE",
        "DROP TABLE IF EXISTS issuance_service.evidence_facts CASCADE",
        "DROP TABLE IF EXISTS issuance_service.applications CASCADE",
        "DROP TABLE IF EXISTS issuance_service.application_templates CASCADE",
        "CREATE TABLE issuance_service.application_templates (
            id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            credential_template_id TEXT,
            form_fields JSON NOT NULL DEFAULT '[]'::json,
            evidence_requirements JSON NOT NULL DEFAULT '[]'::json,
            claim_collection_rules JSON NOT NULL DEFAULT '[]'::json,
            required_checks JSON NOT NULL DEFAULT '[]'::json,
            approval_strategy TEXT NOT NULL,
            approval_policy_set_id TEXT,
            application_validity_days INTEGER NOT NULL,
            ui_config JSON NOT NULL DEFAULT '{}'::json,
            notification_config JSON NOT NULL DEFAULT '{}'::json,
            status TEXT NOT NULL,
            management_version BIGINT NOT NULL DEFAULT 1,
            idempotency_key_hash VARCHAR(64),
            idempotency_request_hash VARCHAR(64),
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL
        )",
        "CREATE TABLE issuance_service.applications (
            id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            application_template_id TEXT NOT NULL
                REFERENCES issuance_service.application_templates(id),
            applicant_identifier TEXT NOT NULL,
            form_data JSON NOT NULL DEFAULT '{}'::json,
            submitted_evidence JSON NOT NULL DEFAULT '[]'::json,
            integration_context JSON NOT NULL DEFAULT '{}'::json,
            status TEXT NOT NULL DEFAULT 'pending',
            review_notes TEXT,
            reviewer_id TEXT,
            rejection_reason TEXT,
            derived_claims JSON NOT NULL DEFAULT '{}'::json,
            issuance_transaction_id TEXT,
            credential_id TEXT,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            submitted_at TIMESTAMPTZ NOT NULL,
            reviewed_at TIMESTAMPTZ,
            expires_at TIMESTAMPTZ NOT NULL
        )",
        "CREATE TABLE issuance_service.evidence_facts (
            id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            application_id TEXT NOT NULL REFERENCES issuance_service.applications(id),
            subject_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            fact_type TEXT NOT NULL,
            scope JSON NOT NULL,
            assertion JSON NOT NULL,
            verification JSON NOT NULL,
            source JSON NOT NULL,
            requirement_id TEXT,
            logical_key TEXT NOT NULL,
            source_revision TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            observed_at TIMESTAMPTZ NOT NULL,
            effective_at TIMESTAMPTZ,
            superseded_fact_id TEXT,
            created_at TIMESTAMPTZ NOT NULL
        )",
        "CREATE TABLE issuance_service.issuance_events (
            id TEXT PRIMARY KEY,
            transaction_id TEXT,
            application_id TEXT REFERENCES issuance_service.applications(id),
            event_type TEXT NOT NULL,
            metadata JSON NOT NULL,
            created_at TIMESTAMPTZ NOT NULL
        )",
    ] {
        sqlx::query(statement)
            .execute(&pool)
            .await
            .expect("internal Application contract schema statement must succeed");
    }

    let observed_at = Utc
        .with_ymd_and_hms(2026, 9, 19, 12, 34, 56)
        .single()
        .expect("fixed timestamp");
    let template_request: ApplicationTemplateCreate = serde_json::from_value(json!({
        "organization_id": "org-123",
        "name": "Employee application"
    }))
    .expect("template request");
    let mut template = template_request
        .into_record("template-1".to_owned(), observed_at)
        .expect("template record");
    template.status = ApplicationTemplateStatus::Active;
    insert_template(&pool, &template).await;

    let repository = PostgresInternalApplicationRepository::new(pool.clone());
    assert_eq!(
        repository
            .get_application_template("template-1")
            .await
            .expect("template lookup")
            .expect("template")
            .status,
        ApplicationTemplateStatus::Active
    );

    let request = ApplicationCreate {
        application_template_id: "template-1".to_owned(),
        applicant_data: json!({"given_name": "Ada", "family_name": "Lovelace"})
            .as_object()
            .expect("applicant object")
            .clone(),
        integration_context: Map::from_iter([("source".to_owned(), json!("contract"))]),
    };
    let application = ApplicationRecord::new(
        "application-1".to_owned(),
        "org-123".to_owned(),
        request,
        "unused-fallback",
        observed_at,
    )
    .expect("application record");
    repository
        .insert_application(&application)
        .await
        .expect("insert application");
    assert_eq!(
        repository
            .get_application("application-1")
            .await
            .expect("application lookup"),
        Some(application.clone())
    );
    assert_eq!(
        repository
            .list_applications(
                "org-123",
                Some(ApplicationStatus::Pending),
                Some("template-1")
            )
            .await
            .expect("filtered list"),
        vec![application.clone()]
    );
    assert!(repository
        .list_applications("org-other", None, None)
        .await
        .expect("tenant-isolated list")
        .is_empty());
    assert!(repository
        .list_applications("org-123", Some(ApplicationStatus::Approved), None)
        .await
        .expect("status-filtered list")
        .is_empty());

    sqlx::query(
        "INSERT INTO issuance_service.evidence_facts (
            id, organization_id, application_id, subject_id, provider, fact_type,
            scope, assertion, verification, source, requirement_id, logical_key,
            source_revision, payload_hash, observed_at, effective_at,
            superseded_fact_id, created_at
        ) VALUES (
            'fact-1', 'org-123', 'application-1', 'ada@example.test',
            'contract-provider', 'identity.document', $1, $2, $3, $4,
            'requirement-1', 'logical-key-1', 'revision-1', 'payload-hash-1',
            $5, $5, NULL, $5
        )",
    )
    .bind(json!({"document_type": "passport"}))
    .bind(json!({"verified": true}))
    .bind(json!({"method": "CONTRACT", "status": "VERIFIED"}))
    .bind(json!({"event_id": "event-1"}))
    .bind(observed_at)
    .execute(&pool)
    .await
    .expect("evidence fact fixture must insert");
    let expected_fact = EvidenceFactRecord {
        id: "fact-1".to_owned(),
        organization_id: "org-123".to_owned(),
        application_id: "application-1".to_owned(),
        subject_id: "ada@example.test".to_owned(),
        provider: "contract-provider".to_owned(),
        fact_type: "identity.document".to_owned(),
        scope: Map::from_iter([("document_type".to_owned(), json!("passport"))]),
        assertion: Map::from_iter([("verified".to_owned(), json!(true))]),
        verification: json!({"method": "CONTRACT", "status": "VERIFIED"})
            .as_object()
            .unwrap()
            .clone(),
        source: Map::from_iter([("event_id".to_owned(), json!("event-1"))]),
        requirement_id: Some("requirement-1".to_owned()),
        logical_key: "logical-key-1".to_owned(),
        source_revision: "revision-1".to_owned(),
        payload_hash: "payload-hash-1".to_owned(),
        observed_at,
        effective_at: Some(observed_at),
        superseded_fact_id: None,
        created_at: observed_at,
    };
    assert_eq!(
        repository
            .list_evidence_facts_for_application("application-1")
            .await
            .expect("evidence facts"),
        vec![expected_fact]
    );
    assert!(repository
        .list_evidence_facts_for_application("missing")
        .await
        .expect("empty evidence facts")
        .is_empty());

    sqlx::query(
        "INSERT INTO issuance_service.issuance_events (
            id, transaction_id, application_id, event_type, metadata, created_at
        ) VALUES (
            'event-1', 'transaction-1', 'application-1', 'offer_viewed', $1, $2
        )",
    )
    .bind(json!({"channel": "contract"}))
    .bind(observed_at)
    .execute(&pool)
    .await
    .expect("issuance event fixture must insert");
    assert_eq!(
        repository
            .list_events_for_application("application-1")
            .await
            .expect("issuance events"),
        vec![IssuanceEventRecord {
            id: "event-1".to_owned(),
            transaction_id: Some("transaction-1".to_owned()),
            application_id: Some("application-1".to_owned()),
            event_type: "offer_viewed".to_owned(),
            metadata: Map::from_iter([("channel".to_owned(), json!("contract"))]),
            created_at: observed_at,
        }]
    );

    let mut winning = application.clone();
    winning
        .submit_evidence(
            EvidenceSubmission {
                evidence_type: "DOCUMENT_SCAN".to_owned(),
                evidence_data: Map::from_iter([("digest".to_owned(), json!("sha256:1"))]),
            },
            observed_at + Duration::minutes(1),
        )
        .expect("evidence mutation");
    let mut stale = application.clone();
    stale
        .submit_evidence(
            EvidenceSubmission {
                evidence_type: "DOCUMENT_SCAN".to_owned(),
                evidence_data: Map::new(),
            },
            observed_at + Duration::minutes(2),
        )
        .expect("stale evidence mutation");
    assert!(repository
        .replace_application_if_revision(
            &winning,
            ApplicationStatus::Pending,
            application.updated_at,
        )
        .await
        .expect("winning compare-and-swap"));
    assert!(
        !repository
            .replace_application_if_revision(
                &stale,
                ApplicationStatus::Pending,
                application.updated_at,
            )
            .await
            .expect("stale compare-and-swap")
    );
    assert_eq!(
        repository
            .get_application("application-1")
            .await
            .unwrap()
            .unwrap(),
        winning
    );

    sqlx::query(
        "UPDATE issuance_service.applications
         SET status = 'not-a-status' WHERE id = 'application-1'",
    )
    .execute(&pool)
    .await
    .expect("invalid status fixture");
    assert_eq!(
        repository.get_application("application-1").await,
        Err(InternalApplicationRepositoryError::Unavailable)
    );

    sqlx::query("DROP TABLE issuance_service.issuance_events CASCADE")
        .execute(&pool)
        .await
        .expect("issuance events contract table must clean up");
    sqlx::query("DROP TABLE issuance_service.evidence_facts CASCADE")
        .execute(&pool)
        .await
        .expect("evidence facts contract table must clean up");
    sqlx::query("DROP TABLE issuance_service.applications CASCADE")
        .execute(&pool)
        .await
        .expect("internal Application contract table must clean up");
    sqlx::query("DROP TABLE issuance_service.application_templates CASCADE")
        .execute(&pool)
        .await
        .expect("Application Template contract table must clean up");
}

async fn insert_template(
    pool: &sqlx::PgPool,
    template: &marty_issuance_service::application_template_domain::ApplicationTemplateRecord,
) {
    sqlx::query(
        "INSERT INTO issuance_service.application_templates (
            id, organization_id, name, description, credential_template_id,
            form_fields, evidence_requirements, claim_collection_rules, required_checks,
            approval_strategy, approval_policy_set_id, application_validity_days,
            ui_config, notification_config, status, management_version,
            created_at, updated_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18
        )",
    )
    .bind(&template.id)
    .bind(&template.organization_id)
    .bind(&template.name)
    .bind(&template.description)
    .bind(&template.credential_template_id)
    .bind(json!(template.form_fields))
    .bind(json!(template.evidence_requirements))
    .bind(json!(template.claim_collection_rules))
    .bind(json!(template.required_checks))
    .bind(&template.approval_strategy)
    .bind(&template.approval_policy_set_id)
    .bind(i32::try_from(template.application_validity_days).expect("validity fits integer"))
    .bind(json!(template.ui_config))
    .bind(json!(template.notification_config))
    .bind(template.status.as_str())
    .bind(template.version)
    .bind(template.created_at)
    .bind(template.updated_at)
    .execute(pool)
    .await
    .expect("template fixture must insert");
}
