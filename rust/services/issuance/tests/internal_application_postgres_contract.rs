use chrono::{Duration, TimeZone, Utc};
use marty_issuance_service::{
    application_template_domain::{ApplicationTemplateCreate, ApplicationTemplateStatus},
    credential::{CredentialTransaction, CredentialTransactionStatus},
    internal_application_approval::InternalApplicationApprovalRepository,
    internal_application_domain::{
        ApplicationCreate, ApplicationRecord, ApplicationStatus, EvidenceFactRecord,
        EvidenceSubmission, IssuanceEventRecord,
    },
    internal_application_evidence::{
        EvidenceCommitOutcome, EvidenceTransitionWrite, InternalApplicationEvidenceRepository,
    },
    internal_application_offer::InternalApplicationOfferRepository,
    internal_application_postgres::PostgresInternalApplicationRepository,
    internal_application_service::{
        InternalApplicationRepository, InternalApplicationRepositoryError,
    },
};
use serde_json::{json, Map, Value};
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
        "DROP TABLE IF EXISTS issuance_service.issuance_transactions CASCADE",
        "DROP TABLE IF EXISTS issuance_service.evidence_fact_heads CASCADE",
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
        "CREATE TABLE issuance_service.issuance_transactions (
            id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            credential_template_id TEXT NOT NULL,
            revocation_profile_id TEXT,
            renewal_of_credential_id TEXT,
            applicant_id TEXT,
            application_id TEXT,
            subject_did TEXT,
            idempotency_key_hash TEXT,
            idempotency_request_hash TEXT,
            status TEXT NOT NULL,
            pre_auth_code TEXT NOT NULL CHECK (pre_auth_code <> 'reject-me'),
            c_nonce TEXT,
            claims JSON NOT NULL,
            credential_type TEXT,
            selective_disclosure_claims JSON NOT NULL,
            zk_predicate_claims JSON NOT NULL,
            credential_payload_format TEXT NOT NULL,
            wallet_configs JSON NOT NULL,
            validity_days INTEGER NOT NULL,
            renewable BOOLEAN NOT NULL,
            renewal_window_days INTEGER NOT NULL,
            delivery_mode TEXT NOT NULL,
            issuer_profile_id TEXT,
            issuer_mode TEXT NOT NULL,
            issuer_did_override TEXT,
            issuer_algorithm TEXT,
            signing_service_id TEXT,
            reserved_credential_id TEXT,
            oid4vci_client_id TEXT,
            created_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            UNIQUE (organization_id, idempotency_key_hash)
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
        "CREATE TABLE issuance_service.evidence_fact_heads (
            organization_id TEXT NOT NULL,
            application_id TEXT NOT NULL,
            logical_key TEXT NOT NULL,
            fact_id TEXT NOT NULL UNIQUE,
            updated_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (application_id, logical_key)
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

    let approved_application = application_fixture(&application, "application-approved");
    repository
        .insert_application(&approved_application)
        .await
        .expect("approval fixture must insert");
    let approved = repository
        .reserve_ordinary_approval(
            &approved_application,
            &approval_transaction("transaction-approved", &approved_application, observed_at),
            "issuance-management-api",
            Some("Reviewed"),
            observed_at + Duration::minutes(3),
        )
        .await
        .expect("ordinary approval reservation")
        .expect("ordinary approval must win");
    assert_eq!(approved.status, ApplicationStatus::Approved);
    assert_eq!(
        approved.reviewer_id.as_deref(),
        Some("issuance-management-api")
    );
    assert_eq!(approved.review_notes.as_deref(), Some("Reviewed"));
    assert_eq!(
        approved.issuance_transaction_id.as_deref(),
        Some("transaction-approved")
    );
    assert_eq!(transaction_count(&pool, "application-approved").await, 1);

    let rejected_race = application_fixture(&application, "application-rejected-race");
    repository
        .insert_application(&rejected_race)
        .await
        .expect("approval/rejection race fixture must insert");
    let mut rejection_lock = pool.begin().await.expect("rejection race transaction");
    sqlx::query("SELECT id FROM issuance_service.applications WHERE id = $1 FOR UPDATE")
        .bind(&rejected_race.id)
        .fetch_one(&mut *rejection_lock)
        .await
        .expect("rejection race must lock application");
    let approval_repository = repository.clone();
    let approval_snapshot = rejected_race.clone();
    let rejected_race_transaction =
        approval_transaction("transaction-rejected-race", &approval_snapshot, observed_at);
    let approval_loser = tokio::spawn(async move {
        approval_repository
            .reserve_ordinary_approval(
                &approval_snapshot,
                &rejected_race_transaction,
                "issuance-management-api",
                None,
                observed_at + Duration::minutes(4),
            )
            .await
    });
    sqlx::query(
        "UPDATE issuance_service.applications
         SET status = 'rejected', reviewer_id = 'issuance-management-api',
             review_notes = 'Rejected', reviewed_at = $2, updated_at = $2
         WHERE id = $1 AND status = 'pending'",
    )
    .bind(&rejected_race.id)
    .bind(observed_at + Duration::minutes(4))
    .execute(&mut *rejection_lock)
    .await
    .expect("rejection must win while holding the row lock");
    rejection_lock
        .commit()
        .await
        .expect("rejection winner must commit");
    assert!(approval_loser
        .await
        .expect("approval race task")
        .expect("approval loser query")
        .is_none());
    assert_eq!(transaction_count(&pool, &rejected_race.id).await, 0);
    assert_eq!(
        repository
            .get_application(&rejected_race.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        ApplicationStatus::Rejected
    );

    let approval_race = application_fixture(&application, "application-approval-race");
    repository
        .insert_application(&approval_race)
        .await
        .expect("approval/approval race fixture must insert");
    let first_repository = repository.clone();
    let second_repository = repository.clone();
    let first_snapshot = approval_race.clone();
    let second_snapshot = approval_race.clone();
    let first_transaction =
        approval_transaction("transaction-race-first", &first_snapshot, observed_at);
    let second_transaction =
        approval_transaction("transaction-race-second", &second_snapshot, observed_at);
    let (first, second) = tokio::join!(
        first_repository.reserve_ordinary_approval(
            &first_snapshot,
            &first_transaction,
            "issuance-management-api",
            None,
            observed_at + Duration::minutes(5),
        ),
        second_repository.reserve_ordinary_approval(
            &second_snapshot,
            &second_transaction,
            "issuance-management-api",
            None,
            observed_at + Duration::minutes(5),
        )
    );
    let outcomes = [first.unwrap().is_some(), second.unwrap().is_some()];
    assert_eq!(outcomes.into_iter().filter(|won| *won).count(), 1);
    assert_eq!(transaction_count(&pool, &approval_race.id).await, 1);

    let rollback_application = application_fixture(&application, "application-rollback");
    repository
        .insert_application(&rollback_application)
        .await
        .expect("rollback fixture must insert");
    let mut rejected_transaction =
        approval_transaction("transaction-rollback", &rollback_application, observed_at);
    rejected_transaction.pre_authorized_code = "reject-me".to_owned();
    assert!(repository
        .reserve_ordinary_approval(
            &rollback_application,
            &rejected_transaction,
            "issuance-management-api",
            None,
            observed_at + Duration::minutes(6),
        )
        .await
        .is_err());
    assert_eq!(transaction_count(&pool, &rollback_application.id).await, 0);
    let rollback_current = repository
        .get_application(&rollback_application.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rollback_current.status, ApplicationStatus::Pending);
    assert!(rollback_current.issuance_transaction_id.is_none());

    let mut offer_application = application_fixture(&application, "application-offer-race");
    offer_application.status = ApplicationStatus::Approved;
    offer_application.reviewer_id = Some("issuance-management-api".to_owned());
    offer_application.reviewed_at = Some(observed_at);
    repository
        .insert_application(&offer_application)
        .await
        .expect("offer race fixture must insert");
    let mut first_offer =
        approval_transaction("transaction-offer-first", &offer_application, observed_at);
    first_offer.pre_authorized_code = "pre-offer-first".to_owned();
    first_offer.idempotency_key_hash = Some("a".repeat(64));
    first_offer.idempotency_request_hash = Some("b".repeat(64));
    let mut second_offer =
        approval_transaction("transaction-offer-second", &offer_application, observed_at);
    second_offer.pre_authorized_code = "pre-offer-second".to_owned();
    second_offer.idempotency_key_hash = Some("a".repeat(64));
    second_offer.idempotency_request_hash = Some("b".repeat(64));
    let first_repository = repository.clone();
    let second_repository = repository.clone();
    let first_snapshot = offer_application.clone();
    let second_snapshot = offer_application.clone();
    let (first, second) = tokio::join!(
        first_repository.reserve_or_refresh_offer(
            &first_snapshot,
            &first_offer,
            observed_at + Duration::minutes(7),
        ),
        second_repository.reserve_or_refresh_offer(
            &second_snapshot,
            &second_offer,
            observed_at + Duration::minutes(7),
        )
    );
    let first = first
        .expect("first offer reservation")
        .expect("first authoritative offer");
    let second = second
        .expect("second offer reservation")
        .expect("second authoritative offer");
    assert_eq!(first.id, second.id);
    assert_eq!(first.pre_authorized_code, second.pre_authorized_code);
    assert_eq!(transaction_count(&pool, &offer_application.id).await, 1);
    let offer_current = repository
        .get_application(&offer_application.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        offer_current.issuance_transaction_id.as_deref(),
        Some(first.id.as_str())
    );
    let mut refresh = approval_transaction("unused-refresh-id", &offer_application, observed_at);
    refresh.idempotency_key_hash = Some("c".repeat(64));
    refresh.idempotency_request_hash = Some("d".repeat(64));
    refresh.delivery_mode = "wallet_plus_email".to_owned();
    let refreshed = repository
        .reserve_or_refresh_offer(&offer_current, &refresh, observed_at + Duration::minutes(8))
        .await
        .expect("offer refresh")
        .expect("refreshed offer");
    assert_eq!(refreshed.id, first.id);
    assert_eq!(refreshed.pre_authorized_code, first.pre_authorized_code);
    assert_eq!(refreshed.delivery_mode, "wallet_plus_email");

    sqlx::query(
        "UPDATE issuance_service.issuance_transactions SET status = 'issued' WHERE id = $1",
    )
    .bind(&refreshed.id)
    .execute(&pool)
    .await
    .expect("issued offer fixture");
    let issued = repository
        .get_offer_transaction(&refreshed.id, &offer_application.organization_id)
        .await
        .expect("issued transaction lookup")
        .expect("issued transaction remains readable");
    assert_eq!(issued.status, CredentialTransactionStatus::Issued);
    repository
        .append_offer_event(&IssuanceEventRecord {
            id: "event-offer-viewed".to_owned(),
            transaction_id: Some(issued.id.clone()),
            application_id: Some(offer_application.id.clone()),
            event_type: "offer_viewed".to_owned(),
            metadata: Map::from_iter([("expired".to_owned(), json!(false))]),
            created_at: observed_at + Duration::minutes(9),
        })
        .await
        .expect("offer event append");
    assert!(repository
        .list_events_for_application(&offer_application.id)
        .await
        .expect("offer events")
        .iter()
        .any(|event| event.event_type == "offer_viewed"));

    let mut canvas_offer = application_fixture(&application, "application-canvas-offer");
    canvas_offer.status = ApplicationStatus::Approved;
    canvas_offer.integration_context = Map::from_iter([(
        "canvas".to_owned(),
        json!({"source":"Canvas LTI", "canvas_platform_id":"platform-1"}),
    )]);
    repository
        .insert_application(&canvas_offer)
        .await
        .expect("Canvas offer fixture must insert");
    let mut canvas_initial =
        approval_transaction("transaction-canvas-offer", &canvas_offer, observed_at);
    canvas_initial.claims = Map::from_iter([
        ("name".to_owned(), json!("Learner")),
        ("_vct".to_owned(), json!("https://credentials.example/old")),
    ]);
    canvas_initial.idempotency_key_hash = Some("1".repeat(64));
    canvas_initial.idempotency_request_hash = Some("2".repeat(64));
    let canvas_reserved = repository
        .reserve_or_refresh_offer(
            &canvas_offer,
            &canvas_initial,
            observed_at + Duration::minutes(9),
        )
        .await
        .expect("Canvas offer reservation")
        .expect("Canvas offer transaction");
    let canvas_current = repository
        .get_application(&canvas_offer.id)
        .await
        .unwrap()
        .unwrap();
    let mut canvas_refresh = canvas_initial.clone();
    canvas_refresh.id = "unused-canvas-refresh".to_owned();
    canvas_refresh.credential_template_id = "credential-template-canvas-new".to_owned();
    canvas_refresh.claims = Map::from_iter([
        ("name".to_owned(), json!("must-not-overwrite")),
        ("_vct".to_owned(), json!("https://credentials.example/new")),
    ]);
    canvas_refresh.credential_type = Some("CanvasCredential".to_owned());
    canvas_refresh.wallet_configs = vec![json!({"wallet_id":"wallet-canvas"})];
    canvas_refresh.selective_disclosure_claims = vec!["email".to_owned()];
    canvas_refresh.zk_predicate_claims = vec!["age".to_owned()];
    canvas_refresh.validity_days = 730;
    canvas_refresh.renewable = true;
    canvas_refresh.renewal_window_days = 60;
    canvas_refresh.issuer_did = Some("did:web:issuer.example:canvas".to_owned());
    let canvas_refreshed = repository
        .reserve_or_refresh_offer(
            &canvas_current,
            &canvas_refresh,
            observed_at + Duration::minutes(10),
        )
        .await
        .expect("Canvas offer refresh")
        .expect("refreshed Canvas transaction");
    assert_eq!(canvas_refreshed.id, canvas_reserved.id);
    assert_eq!(
        canvas_refreshed.credential_template_id,
        "credential-template-canvas-new"
    );
    assert_eq!(
        canvas_refreshed.credential_type.as_deref(),
        Some("CanvasCredential")
    );
    assert_eq!(
        canvas_refreshed.wallet_configs,
        vec![json!({"wallet_id":"wallet-canvas"})]
    );
    assert_eq!(canvas_refreshed.validity_days, 730);
    assert!(canvas_refreshed.renewable);
    assert_eq!(canvas_refreshed.claims.get("name"), Some(&json!("Learner")));
    assert_eq!(
        canvas_refreshed.claims.get("_vct"),
        Some(&json!("https://credentials.example/new"))
    );

    let mut offer_rollback = application_fixture(&application, "application-offer-rollback");
    offer_rollback.status = ApplicationStatus::Approved;
    repository
        .insert_application(&offer_rollback)
        .await
        .expect("offer rollback fixture must insert");
    let mut rejected_offer =
        approval_transaction("transaction-offer-rollback", &offer_rollback, observed_at);
    rejected_offer.pre_authorized_code = "reject-me".to_owned();
    rejected_offer.idempotency_key_hash = Some("e".repeat(64));
    rejected_offer.idempotency_request_hash = Some("f".repeat(64));
    assert!(repository
        .reserve_or_refresh_offer(
            &offer_rollback,
            &rejected_offer,
            observed_at + Duration::minutes(10),
        )
        .await
        .is_err());
    assert_eq!(transaction_count(&pool, &offer_rollback.id).await, 0);
    assert!(repository
        .get_application(&offer_rollback.id)
        .await
        .unwrap()
        .unwrap()
        .issuance_transaction_id
        .is_none());

    let evidence_application = application_fixture(&application, "application-evidence-atomic");
    repository
        .insert_application(&evidence_application)
        .await
        .expect("evidence application fixture must insert");
    let evidence_transaction = approval_transaction(
        "transaction-evidence-atomic",
        &evidence_application,
        observed_at,
    );
    let evidence_fact =
        evidence_fact_fixture("fact-evidence-atomic", &evidence_application, observed_at);
    let mut evidence_updated = evidence_application.clone();
    evidence_updated
        .approve_reserved(
            evidence_transaction.id.clone(),
            Some("Evidence permitted".to_owned()),
            "external-evidence:auto-approval",
            observed_at + Duration::minutes(11),
        )
        .expect("evidence approval transition");
    evidence_updated.evidence_submissions.push(Map::from_iter([(
        "evidence_fact_ids".to_owned(),
        json!([evidence_fact.id]),
    )]));
    evidence_updated
        .integration_context
        .insert("policy".to_owned(), json!({"allowed": true}));
    let evidence_events = [
        "evidence_fact_created",
        "evidence_policy_permitted",
        "approval_issuance_succeeded",
    ]
    .into_iter()
    .enumerate()
    .map(|(index, event_type)| {
        evidence_event_fixture(
            &format!("event-evidence-atomic-{index}"),
            &evidence_application,
            event_type,
            observed_at + Duration::minutes(11),
        )
    })
    .collect::<Vec<_>>();
    assert_eq!(
        repository
            .commit_transition(&EvidenceTransitionWrite {
                application: evidence_updated.clone(),
                expected_status: ApplicationStatus::Pending,
                expected_updated_at: evidence_application.updated_at,
                evidence_fact: evidence_fact.clone(),
                transaction: Some(evidence_transaction.clone()),
                events: evidence_events,
            })
            .await
            .expect("atomic evidence transition"),
        EvidenceCommitOutcome::Committed
    );
    let evidence_stored = repository
        .get_application(&evidence_application.id)
        .await
        .expect("evidence application lookup")
        .expect("evidence application");
    assert_eq!(evidence_stored.status, ApplicationStatus::Approved);
    assert_eq!(
        evidence_stored.issuance_transaction_id.as_deref(),
        Some("transaction-evidence-atomic")
    );
    assert_eq!(
        repository
            .list_facts(&evidence_application.id)
            .await
            .expect("evidence facts"),
        vec![evidence_fact]
    );
    assert_eq!(
        repository
            .list_events_for_application(&evidence_application.id)
            .await
            .expect("evidence events")
            .iter()
            .map(|event| event.event_type.as_str())
            .collect::<Vec<_>>(),
        [
            "evidence_fact_created",
            "evidence_policy_permitted",
            "approval_issuance_succeeded"
        ]
    );

    let failure_application = application_fixture(&application, "application-evidence-failure");
    repository
        .insert_application(&failure_application)
        .await
        .expect("failure application fixture must insert");
    let mut failure_transaction = approval_transaction(
        "transaction-evidence-failure",
        &failure_application,
        observed_at,
    );
    failure_transaction.pre_authorized_code = "reject-me".to_owned();
    let failure_fact =
        evidence_fact_fixture("fact-evidence-failure", &failure_application, observed_at);
    let mut failure_updated = failure_application.clone();
    failure_updated
        .approve_reserved(
            failure_transaction.id.clone(),
            None,
            "external-evidence:auto-approval",
            observed_at + Duration::minutes(12),
        )
        .expect("failure transition candidate");
    assert!(repository
        .commit_transition(&EvidenceTransitionWrite {
            application: failure_updated,
            expected_status: ApplicationStatus::Pending,
            expected_updated_at: failure_application.updated_at,
            evidence_fact: failure_fact,
            transaction: Some(failure_transaction),
            events: vec![evidence_event_fixture(
                "event-evidence-failure",
                &failure_application,
                "evidence_fact_created",
                observed_at + Duration::minutes(12),
            )],
        })
        .await
        .is_err());
    assert_eq!(
        repository
            .get_application(&failure_application.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        ApplicationStatus::Pending
    );
    assert!(repository
        .list_facts(&failure_application.id)
        .await
        .expect("rolled back facts")
        .is_empty());
    assert!(repository
        .list_events_for_application(&failure_application.id)
        .await
        .expect("rolled back events")
        .is_empty());
    assert_eq!(transaction_count(&pool, &failure_application.id).await, 0);

    let conflict_application = application_fixture(&application, "application-evidence-conflict");
    repository
        .insert_application(&conflict_application)
        .await
        .expect("conflict application fixture must insert");
    sqlx::query("UPDATE issuance_service.applications SET status = 'rejected' WHERE id = $1")
        .bind(&conflict_application.id)
        .execute(&pool)
        .await
        .expect("rejection wins conflict fixture");
    let conflict_fact =
        evidence_fact_fixture("fact-evidence-conflict", &conflict_application, observed_at);
    let mut stale_candidate = conflict_application.clone();
    stale_candidate.updated_at = observed_at + Duration::minutes(13);
    assert_eq!(
        repository
            .commit_transition(&EvidenceTransitionWrite {
                application: stale_candidate,
                expected_status: ApplicationStatus::Pending,
                expected_updated_at: conflict_application.updated_at,
                evidence_fact: conflict_fact.clone(),
                transaction: None,
                events: Vec::new(),
            })
            .await
            .expect("evidence lifecycle conflict"),
        EvidenceCommitOutcome::ConcurrentChange
    );
    let conflict_events = [
        "evidence_fact_created",
        "evidence_policy_permitted",
        "approval_issuance_failed",
    ]
    .into_iter()
    .enumerate()
    .map(|(index, event_type)| {
        evidence_event_fixture(
            &format!("event-evidence-conflict-{index}"),
            &conflict_application,
            event_type,
            observed_at + Duration::minutes(13),
        )
    })
    .collect::<Vec<_>>();
    repository
        .commit_conflict_evidence(
            &conflict_application.id,
            &conflict_application.organization_id,
            &conflict_fact,
            &conflict_events,
        )
        .await
        .expect("conflict fact and audit retention");
    assert_eq!(
        repository
            .get_application(&conflict_application.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        ApplicationStatus::Rejected
    );
    assert_eq!(
        repository
            .list_facts(&conflict_application.id)
            .await
            .expect("retained conflict fact")
            .len(),
        1
    );
    assert_eq!(
        repository
            .list_events_for_application(&conflict_application.id)
            .await
            .expect("retained conflict events")
            .iter()
            .map(|event| event.event_type.as_str())
            .collect::<Vec<_>>(),
        [
            "evidence_fact_created",
            "evidence_policy_permitted",
            "approval_issuance_failed"
        ]
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
    sqlx::query("DROP TABLE issuance_service.issuance_transactions CASCADE")
        .execute(&pool)
        .await
        .expect("issuance transactions contract table must clean up");
    sqlx::query("DROP TABLE issuance_service.evidence_fact_heads CASCADE")
        .execute(&pool)
        .await
        .expect("evidence fact heads contract table must clean up");
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

fn application_fixture(source: &ApplicationRecord, id: &str) -> ApplicationRecord {
    let mut application = source.clone();
    application.id = id.to_owned();
    application
}

fn evidence_fact_fixture(
    id: &str,
    application: &ApplicationRecord,
    now: chrono::DateTime<Utc>,
) -> EvidenceFactRecord {
    EvidenceFactRecord {
        id: id.to_owned(),
        organization_id: application.organization_id.clone(),
        application_id: application.id.clone(),
        subject_id: application.applicant_identifier.clone(),
        provider: "passport_verifier".to_owned(),
        fact_type: "passport.document_verified".to_owned(),
        scope: Map::from_iter([("document_type".to_owned(), json!("passport"))]),
        assertion: Map::from_iter([("verified".to_owned(), json!(true))]),
        verification: Map::from_iter([
            ("method".to_owned(), json!("EXTERNAL_API_RESPONSE")),
            ("status".to_owned(), json!("VERIFIED")),
        ]),
        source: Map::from_iter([("check_id".to_owned(), json!("passport-check"))]),
        requirement_id: None,
        logical_key: format!("logical-{id}"),
        source_revision: format!("revision-{id}"),
        payload_hash: format!("payload-{id}"),
        observed_at: now,
        effective_at: Some(now),
        superseded_fact_id: None,
        created_at: now,
    }
}

fn evidence_event_fixture(
    id: &str,
    application: &ApplicationRecord,
    event_type: &str,
    now: chrono::DateTime<Utc>,
) -> IssuanceEventRecord {
    IssuanceEventRecord {
        id: id.to_owned(),
        transaction_id: None,
        application_id: Some(application.id.clone()),
        event_type: event_type.to_owned(),
        metadata: Map::from_iter([(
            "organization_id".to_owned(),
            Value::String(application.organization_id.clone()),
        )]),
        created_at: now,
    }
}

fn approval_transaction(
    id: &str,
    application: &ApplicationRecord,
    now: chrono::DateTime<Utc>,
) -> CredentialTransaction {
    CredentialTransaction {
        id: id.to_owned(),
        organization_id: application.organization_id.clone(),
        credential_template_id: "credential-template-1".to_owned(),
        revocation_profile_id: Some("revocation-profile-1".to_owned()),
        renewal_of_credential_id: None,
        applicant_id: Some(application.applicant_identifier.clone()),
        application_id: Some(application.id.clone()),
        subject_did: None,
        idempotency_key_hash: None,
        idempotency_request_hash: None,
        status: CredentialTransactionStatus::Pending,
        pre_authorized_code: "pre-authorized-code".to_owned(),
        nonce: None,
        claims: application.form_data.clone(),
        credential_type: Some("EmployeeCredential".to_owned()),
        selective_disclosure_claims: vec!["email".to_owned()],
        zk_predicate_claims: Vec::new(),
        credential_payload_format: "w3c_vcdm_v2_sd_jwt".to_owned(),
        wallet_configs: Vec::new(),
        validity_days: 365,
        renewable: false,
        renewal_window_days: 30,
        delivery_mode: "wallet_only".to_owned(),
        issuer_profile_id: Some("issuer-profile-1".to_owned()),
        issuer_mode: "org_managed".to_owned(),
        issuer_did: Some("did:web:issuer.example:org-123".to_owned()),
        issuer_algorithm: Some("ES256".to_owned()),
        signing_service_id: Some("kms-service-1".to_owned()),
        reserved_credential_id: None,
        oid4vci_client_id: None,
        created_at: now,
        expires_at: now + Duration::days(7),
    }
}

async fn transaction_count(pool: &sqlx::PgPool, application_id: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM issuance_service.issuance_transactions WHERE application_id = $1",
    )
    .bind(application_id)
    .fetch_one(pool)
    .await
    .expect("transaction count")
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
