use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use hmac::{Hmac, Mac};
use marty_issuance_service::{
    canvas_award_candidate::{
        plan_selected_canvas_award_candidate_materialization, select_canvas_award_candidate,
        CanvasIdentityJoin,
    },
    canvas_award_candidate_approval::{
        plan_canvas_approval_transaction, plan_canvas_award_approval,
        CanvasApplicationApprovalError, CanvasApplicationApprovalRepository,
        CanvasApplicationApprovalService, CanvasAwardApprovalRepository, CanvasAwardApprovalSeed,
        CanvasAwardApprovalSeedGenerator, CanvasAwardCandidateApprovalService,
    },
    canvas_award_candidate_approval_postgres::PostgresCanvasAwardApprovalRepository,
    canvas_award_candidate_postgres::PostgresCanvasAwardCandidateRepository,
    canvas_award_candidate_service::{
        CanvasAwardCandidateApprover, CanvasAwardCandidateRepository,
        CanvasAwardCandidateRepositoryError,
    },
    canvas_issuance_guard::CanvasGuardConfig,
    canvas_legacy_ingest::{
        CanvasLegacyEventKind, CanvasLegacyIdGenerator, CanvasLegacyIngestConfig,
        CanvasLegacyIngestError, CanvasLegacyIngestService,
    },
    canvas_legacy_ingest_postgres::PostgresCanvasLegacyIngestRepository,
    canvas_lti_bootstrap::CanvasLtiBootstrapApplication,
    canvas_lti_experience::{
        canvas_lti_experience_session_context, CanvasLtiExperienceSessionContext,
    },
    canvas_lti_launch::{CanvasLtiClock, CanvasLtiStoredLaunchState},
    credential::{
        CredentialIssuanceError, CredentialTransaction, IssuerContext, IssuerContextResolver,
    },
};
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::{postgres::PgPoolOptions, Row};

fn database_url() -> Option<String> {
    std::env::var("MARTY_ISSUANCE_POSTGRES_CONTRACT_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 29, 16, 0, 0)
        .single()
        .unwrap()
}

fn context() -> CanvasLtiExperienceSessionContext {
    canvas_lti_experience_session_context(CanvasLtiStoredLaunchState {
        id: "candidate-session-id".to_owned(),
        platform_id: "platform-1".to_owned(),
        organization_id: "org-1".to_owned(),
        canvas_account_id: "account-1".to_owned(),
        state: "private-session-digest".to_owned(),
        nonce: "private-session-nonce".to_owned(),
        redirect_uri: "https://ui.example.test/canvas/lti/experience".to_owned(),
        status: "session".to_owned(),
        metadata: json!({
            "kind": "canvas_lti_experience_session",
            "launch_state": "launch-state-1",
            "verified_launch": {
                "subject": "learner-subject-1",
                "deployment_id": "deployment-123",
                "learner_identity": {},
                "raw_claims": {
                    "sub": "learner-subject-1",
                    "https://purl.imsglobal.org/spec/lti/claim/custom": {
                        "canvas_user_id": "42"
                    }
                }
            },
            "mip_primitives": {"context": {
                "canvas_platform_id": "platform-1",
                "canvas_program_binding_id": "binding-1",
                "application_template_id": "application-template-1",
                "credential_template_id": "credential-template-1",
                "feature_flags": {"enable_canvas_evidence": true}
            }}
        }),
        expired: false,
    })
    .unwrap()
}

fn application() -> CanvasLtiBootstrapApplication {
    CanvasLtiBootstrapApplication {
        id: "application-1".to_owned(),
        organization_id: "org-1".to_owned(),
        application_template_id: "application-template-1".to_owned(),
        applicant_identifier: "canvas_lti:learner-subject-1".to_owned(),
        form_data: json!({}),
        integration_context: json!({"canvas": {"source": "canvas_lti_bootstrap"}}),
        status: "pending".to_owned(),
        created_at: now(),
        updated_at: now(),
    }
}

fn revised_fact(fact: &Value, id: &str, score: i64, timestamp: &str) -> Value {
    let mut fact = fact.clone();
    fact["id"] = json!(id);
    fact["assertion"]["score_percent"] = json!(score);
    fact["payload_hash"] = json!(format!("payload-{id}"));
    fact["source_revision"] = json!(format!("revision-{id}"));
    fact["observed_at"] = json!(timestamp);
    fact["effective_at"] = json!(timestamp);
    fact["created_at"] = json!(timestamp);
    fact
}

struct ApprovalSeeds;

impl CanvasAwardApprovalSeedGenerator for ApprovalSeeds {
    fn generate(&self) -> CanvasAwardApprovalSeed {
        CanvasAwardApprovalSeed {
            transaction_id: "transaction-1".to_owned(),
            pre_authorized_code: "pre-authorized-code-1".to_owned(),
        }
    }
}

struct ManualApprovalSeeds;

impl CanvasAwardApprovalSeedGenerator for ManualApprovalSeeds {
    fn generate(&self) -> CanvasAwardApprovalSeed {
        CanvasAwardApprovalSeed {
            transaction_id: "transaction-manual-1".to_owned(),
            pre_authorized_code: "pre-authorized-code-manual-1".to_owned(),
        }
    }
}

struct ApprovalClock;

impl CanvasLtiClock for ApprovalClock {
    fn now(&self) -> DateTime<Utc> {
        now()
    }
}

struct ApprovalIssuer;

#[async_trait]
impl IssuerContextResolver for ApprovalIssuer {
    async fn resolve(
        &self,
        transaction: &CredentialTransaction,
        credential_format: &str,
        force: bool,
    ) -> Result<IssuerContext, CredentialIssuanceError> {
        assert_eq!(
            transaction.issuer_did.as_deref(),
            Some("did:web:issuer.example:orgs:org-1")
        );
        assert_eq!(credential_format, "dc+sd-jwt");
        assert!(force);
        let issuer_did = "did:web:issuer.example:orgs:org-1";
        Ok(IssuerContext {
            issuer_profile_id: "issuer-profile-1".to_owned(),
            issuer_did: issuer_did.to_owned(),
            signing_service_id: "kms-service-1".to_owned(),
            algorithm: "ES256".to_owned(),
            verification_method_id: Some(format!("{issuer_did}#badge-key-1")),
            public_jwk: Some(json!({"kty":"EC","crv":"P-256","x":"x","y":"y"})),
            certificate_chain: Vec::new(),
            raw_context: json!({
                "organization_id":"org-1",
                "issuer_did":issuer_did,
                "algorithm":"ES256",
                "issuer_profile_id":"issuer-profile-1",
                "signing_service_id":"kms-service-1",
                "signing_key_reference":"org_secret://org-1/badge-key",
                "verification_method_id":format!("{issuer_did}#badge-key-1"),
                "key_purpose":"vc_jwt_issuer",
                "public_jwk":{"kty":"EC","crv":"P-256","x":"x","y":"y"},
                "issuer_profile":{
                    "id":"issuer-profile-1","status":"active","organization_id":"org-1",
                    "issuer_did":issuer_did,
                    "verification_method_id":format!("{issuer_did}#badge-key-1"),
                    "key_purpose":"vc_jwt_issuer"
                },
                "service":{"id":"kms-service-1","algorithm":"ES256"}
            }),
        })
    }
}

#[tokio::test]
async fn candidate_materialization_matches_production_json_and_revision_contracts() {
    let Some(database_url) = database_url() else {
        eprintln!("skipping Canvas award candidate PostgreSQL contract without database URL");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("issuance PostgreSQL contract database must connect");
    setup_schema(&pool).await;
    seed_candidate(&pool).await;

    let repository = PostgresCanvasAwardCandidateRepository::new(pool.clone());
    let application = application();
    let context = context();
    let snapshot = repository
        .load_snapshot(&context, &application)
        .await
        .unwrap()
        .expect("tenant-bound candidate snapshot");
    let selection = select_canvas_award_candidate(
        &context,
        &application,
        &snapshot.candidates,
        CanvasIdentityJoin {
            by_subject: snapshot.identity_by_subject.as_ref(),
            by_canvas_user: snapshot.identity_by_canvas_user.as_ref(),
        },
    )
    .expect("exact linked candidate");
    let observations = repository
        .current_observations("org-1", "candidate-1")
        .await
        .unwrap();
    let plan = plan_selected_canvas_award_candidate_materialization(
        &context,
        &application,
        &snapshot.binding,
        &selection,
        &observations,
        now(),
        Duration::from_secs(900),
        || "fact-1".to_owned(),
    )
    .expect("fresh verified candidate plan");
    assert!(repository
        .record_fact_and_evaluate_policy(
            &application,
            &snapshot.binding,
            &snapshot.application_template,
            &plan.facts[0],
        )
        .await
        .unwrap());
    repository
        .link_candidate(&application, &plan)
        .await
        .unwrap();

    let counts = sqlx::query(
        "SELECT
            (SELECT count(*) FROM issuance_service.evidence_facts) AS facts,
            (SELECT count(*) FROM issuance_service.evidence_fact_heads) AS heads,
            (SELECT count(*) FROM issuance_service.issuance_events) AS events",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(counts.get::<i64, _>("facts"), 1);
    assert_eq!(counts.get::<i64, _>("heads"), 1);
    assert_eq!(counts.get::<i64, _>("events"), 1);
    let linked = sqlx::query(
        "SELECT candidate.application_id, candidate.learner_identity_id,
                application.integration_context
         FROM issuance_service.canvas_award_candidates AS candidate
         JOIN issuance_service.applications AS application
           ON application.id = candidate.application_id
         WHERE candidate.id = 'candidate-1'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(linked.get::<String, _>("application_id"), "application-1");
    assert_eq!(
        linked
            .get::<Option<String>, _>("learner_identity_id")
            .as_deref(),
        Some("identity-1")
    );
    let integration: Value = linked.get("integration_context");
    assert_eq!(integration["canvas"]["source"], "canvas_lti_bootstrap");
    assert_eq!(
        integration["canvas"]["canvas_award_candidate_id"],
        "candidate-1"
    );

    let approval = CanvasAwardCandidateApprovalService::new(
        Arc::new(PostgresCanvasAwardApprovalRepository::new(pool.clone())),
        Arc::new(ApprovalIssuer),
        Arc::new(ApprovalSeeds),
        Arc::new(ApprovalClock),
        Duration::from_secs(900),
    );
    approval
        .approve_if_ready(&context, &application, &plan, true)
        .await
        .unwrap();
    let approved = sqlx::query(
        "SELECT status, reviewer_id, review_notes, issuance_transaction_id
         FROM issuance_service.applications WHERE id = 'application-1'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(approved.get::<String, _>("status"), "approved");
    assert_eq!(
        approved.get::<Option<String>, _>("reviewer_id").as_deref(),
        Some("canvas-pending-award-claim")
    );
    assert_eq!(
        approved.get::<Option<String>, _>("review_notes").as_deref(),
        Some("Learner claimed an eligible Canvas pending award")
    );
    assert_eq!(
        approved
            .get::<Option<String>, _>("issuance_transaction_id")
            .as_deref(),
        Some("transaction-1")
    );
    let transaction = sqlx::query(
        "SELECT status, credential_template_id, credential_type,
                credential_payload_format, revocation_profile_id, issuer_profile_id,
                issuer_did_override, issuer_algorithm, signing_service_id,
                pre_auth_code, expires_at > created_at AS future_expiry
         FROM issuance_service.issuance_transactions WHERE id = 'transaction-1'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(transaction.get::<String, _>("status"), "pending");
    assert_eq!(
        transaction.get::<String, _>("credential_template_id"),
        "credential-template-1"
    );
    assert_eq!(
        transaction
            .get::<Option<String>, _>("credential_type")
            .as_deref(),
        Some("OpenBadgeCredential")
    );
    assert_eq!(
        transaction
            .get::<Option<String>, _>("revocation_profile_id")
            .as_deref(),
        Some("revocation-profile-1")
    );
    assert_eq!(
        transaction
            .get::<Option<String>, _>("issuer_profile_id")
            .as_deref(),
        Some("issuer-profile-1")
    );
    assert_eq!(
        transaction
            .get::<Option<String>, _>("signing_service_id")
            .as_deref(),
        Some("kms-service-1")
    );
    assert_eq!(
        transaction.get::<String, _>("pre_auth_code"),
        "pre-authorized-code-1"
    );
    assert!(transaction.get::<bool, _>("future_expiry"));

    // Management approval shares the exact repository, KMS context and
    // transaction planner while preserving the route's distinct reviewer.
    sqlx::query(
        "INSERT INTO issuance_service.applications
         (id, organization_id, application_template_id, applicant_identifier,
          form_data, integration_context, status, updated_at)
         VALUES ('application-manual-1', 'org-1', 'application-template-1',
                 'canvas_lti:manual-subject',
                 '{\"achievement\":\"Manual Canvas\"}'::json,
                 '{\"delivery_mode\":\"wallet_only\",\"canvas\":{
                    \"source\":\"canvas_lti_bootstrap\",
                    \"canvas_platform_id\":\"platform-1\",
                    \"canvas_program_binding_id\":\"binding-1\",
                    \"canvas_account_id\":\"account-1\",
                    \"application_template_id\":\"application-template-1\",
                    \"credential_template_id\":\"credential-template-1\",
                    \"lti_subject\":\"manual-subject\"}}'::json,
                 'pending', clock_timestamp())",
    )
    .execute(&pool)
    .await
    .unwrap();
    let management_repository = Arc::new(PostgresCanvasAwardApprovalRepository::new(pool.clone()));
    let manual_approval = CanvasApplicationApprovalService::new(
        management_repository.clone(),
        Arc::new(ApprovalIssuer),
        Arc::new(ManualApprovalSeeds),
        Arc::new(ApprovalClock),
        CanvasGuardConfig {
            enabled: true,
            pilot_organizations: BTreeSet::from(["org-1".to_owned()]),
            evidence_max_age: Duration::from_secs(900),
            readiness_max_age: Duration::from_secs(900),
        },
    );
    let manual_result = manual_approval
        .approve("org-1", "application-manual-1", Some(""))
        .await
        .unwrap();
    assert_eq!(
        manual_result.issuance_transaction_id,
        "transaction-manual-1"
    );
    let manual_application = sqlx::query(
        "SELECT status, reviewer_id, review_notes, issuance_transaction_id
         FROM issuance_service.applications WHERE id = 'application-manual-1'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(manual_application.get::<String, _>("status"), "approved");
    assert_eq!(
        manual_application
            .get::<Option<String>, _>("reviewer_id")
            .as_deref(),
        Some("canvas-integration-management-api")
    );
    assert_eq!(
        manual_application
            .get::<Option<String>, _>("review_notes")
            .as_deref(),
        Some("Approved through Canvas integration operations")
    );
    assert_eq!(
        manual_application
            .get::<Option<String>, _>("issuance_transaction_id")
            .as_deref(),
        Some("transaction-manual-1")
    );

    // An already linked unexpired pending transaction is the exact object
    // refreshed and resolved. Capability material and lifecycle timestamps
    // remain unchanged while mutable credential/delivery/KMS context advances.
    sqlx::query(
        "INSERT INTO issuance_service.applications
         (id, organization_id, application_template_id, applicant_identifier,
          form_data, integration_context, status, issuance_transaction_id, updated_at)
         SELECT 'application-manual-existing', organization_id,
                application_template_id, applicant_identifier, form_data,
                jsonb_set(integration_context::jsonb, '{delivery_mode}',
                          '\"wallet_plus_canvas_mirror\"'::jsonb)::json,
                'pending', 'transaction-manual-existing', clock_timestamp()
         FROM issuance_service.applications WHERE id = 'application-manual-1'",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.issuance_transactions (
            id, organization_id, credential_template_id, revocation_profile_id,
            renewal_of_credential_id, applicant_id, application_id, subject_did,
            idempotency_key_hash, idempotency_request_hash, status, pre_auth_code,
            c_nonce, claims, credential_type, selective_disclosure_claims,
            zk_predicate_claims, credential_payload_format, wallet_configs,
            validity_days, renewable, renewal_window_days, delivery_mode,
            issuer_profile_id, issuer_mode, issuer_did_override, issuer_algorithm,
            signing_service_id, reserved_credential_id, oid4vci_client_id,
            created_at, expires_at)
         SELECT 'transaction-manual-existing', organization_id,
                credential_template_id, revocation_profile_id,
                renewal_of_credential_id, applicant_id,
                'application-manual-existing', subject_did, NULL, NULL, 'pending',
                'existing-pre-authorized-code', 'existing-nonce',
                (claims::jsonb || '{\"preserved_claim\":\"keep-me\"}'::jsonb)::json,
                'stale-type', selective_disclosure_claims,
                zk_predicate_claims, 'stale-format', wallet_configs,
                validity_days, renewable, renewal_window_days, 'wallet_only',
                'stale-profile', issuer_mode, 'did:web:stale.example', 'ES384',
                'stale-service', 'reserved-capability', 'oid4vci-client-1',
                created_at, expires_at
         FROM issuance_service.issuance_transactions
         WHERE id = 'transaction-manual-1'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let before_refresh = sqlx::query(
        "SELECT pre_auth_code, c_nonce, claims, reserved_credential_id,
                oid4vci_client_id, created_at, expires_at
         FROM issuance_service.issuance_transactions
         WHERE id = 'transaction-manual-existing'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let existing_result = manual_approval
        .approve("org-1", "application-manual-existing", Some("existing"))
        .await
        .unwrap();
    assert_eq!(
        existing_result.issuance_transaction_id,
        "transaction-manual-existing"
    );
    let after_refresh = sqlx::query(
        "SELECT pre_auth_code, c_nonce, claims, reserved_credential_id,
                oid4vci_client_id, created_at, expires_at, status,
                delivery_mode, credential_type, credential_payload_format,
                issuer_profile_id, issuer_did_override, issuer_algorithm,
                signing_service_id
         FROM issuance_service.issuance_transactions
         WHERE id = 'transaction-manual-existing'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    for field in [
        "pre_auth_code",
        "c_nonce",
        "reserved_credential_id",
        "oid4vci_client_id",
    ] {
        assert_eq!(
            before_refresh.get::<Option<String>, _>(field),
            after_refresh.get::<Option<String>, _>(field),
            "{field}"
        );
    }
    assert_eq!(
        before_refresh.get::<Value, _>("claims"),
        after_refresh.get::<Value, _>("claims")
    );
    assert_eq!(
        after_refresh.get::<Value, _>("claims")["preserved_claim"],
        "keep-me"
    );
    assert_eq!(
        before_refresh.get::<DateTime<Utc>, _>("created_at"),
        after_refresh.get::<DateTime<Utc>, _>("created_at")
    );
    assert_eq!(
        before_refresh.get::<DateTime<Utc>, _>("expires_at"),
        after_refresh.get::<DateTime<Utc>, _>("expires_at")
    );
    assert_eq!(after_refresh.get::<String, _>("status"), "pending");
    assert_eq!(
        after_refresh.get::<String, _>("delivery_mode"),
        "wallet_plus_canvas_mirror"
    );
    assert_eq!(
        after_refresh
            .get::<Option<String>, _>("credential_type")
            .as_deref(),
        Some("OpenBadgeCredential")
    );
    assert_eq!(
        after_refresh.get::<String, _>("credential_payload_format"),
        "w3c_vcdm_v2_sd_jwt"
    );
    assert_eq!(
        after_refresh
            .get::<Option<String>, _>("issuer_profile_id")
            .as_deref(),
        Some("issuer-profile-1")
    );
    assert_eq!(
        after_refresh
            .get::<Option<String>, _>("signing_service_id")
            .as_deref(),
        Some("kms-service-1")
    );

    // Two approvers that both observed pending state serialize on the
    // application row and converge on one active transaction.
    sqlx::query(
        "INSERT INTO issuance_service.applications
         (id, organization_id, application_template_id, applicant_identifier,
          form_data, integration_context, status, updated_at)
         SELECT 'application-manual-race', organization_id,
                application_template_id, applicant_identifier, form_data,
                jsonb_set(integration_context::jsonb,
                          '{canvas,lti_subject}', '\"manual-race\"'::jsonb)::json,
                'pending', clock_timestamp()
         FROM issuance_service.applications WHERE id = 'application-manual-1'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let race_snapshot = management_repository
        .load_application_approval_snapshot("org-1", "application-manual-race")
        .await
        .unwrap()
        .unwrap();
    let mut race_a = plan_canvas_approval_transaction(
        &race_snapshot.application,
        &race_snapshot.binding,
        &CanvasAwardApprovalSeed {
            transaction_id: "transaction-manual-race-a".to_owned(),
            pre_authorized_code: "pre-authorized-code-manual-race-a".to_owned(),
        },
        now(),
    )
    .unwrap();
    let mut race_b = plan_canvas_approval_transaction(
        &race_snapshot.application,
        &race_snapshot.binding,
        &CanvasAwardApprovalSeed {
            transaction_id: "transaction-manual-race-b".to_owned(),
            pre_authorized_code: "pre-authorized-code-manual-race-b".to_owned(),
        },
        now(),
    )
    .unwrap();
    for transaction in [&mut race_a, &mut race_b] {
        transaction.issuer_profile_id = Some("issuer-profile-1".to_owned());
        transaction.signing_service_id = Some("kms-service-1".to_owned());
    }
    let (reserved_a, reserved_b) = tokio::join!(
        management_repository.reserve_application_issuance(
            &race_a,
            &race_snapshot,
            "canvas-integration-management-api",
            "review-a",
            now(),
        ),
        management_repository.reserve_application_issuance(
            &race_b,
            &race_snapshot,
            "canvas-integration-management-api",
            "review-b",
            now(),
        ),
    );
    let reserved_a = reserved_a.unwrap();
    let reserved_b = reserved_b.unwrap();
    assert_eq!(reserved_a, reserved_b);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.issuance_transactions
             WHERE application_id = 'application-manual-race'",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT issuance_transaction_id FROM issuance_service.applications
             WHERE id = 'application-manual-race'",
        )
        .fetch_one(&pool)
        .await
        .unwrap()
        .as_deref(),
        Some(reserved_a.as_str())
    );

    // Dependency drift after snapshot load rolls back both transaction insert
    // and application approval.
    sqlx::query(
        "INSERT INTO issuance_service.applications
         (id, organization_id, application_template_id, applicant_identifier,
          form_data, integration_context, status, updated_at)
         SELECT 'application-manual-drift', organization_id,
                application_template_id, applicant_identifier, form_data,
                jsonb_set(integration_context::jsonb,
                          '{canvas,lti_subject}', '\"manual-drift\"'::jsonb)::json,
                'pending', clock_timestamp()
         FROM issuance_service.applications WHERE id = 'application-manual-1'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let drift_snapshot = management_repository
        .load_application_approval_snapshot("org-1", "application-manual-drift")
        .await
        .unwrap()
        .unwrap();
    let mut drift_transaction = plan_canvas_approval_transaction(
        &drift_snapshot.application,
        &drift_snapshot.binding,
        &CanvasAwardApprovalSeed {
            transaction_id: "transaction-manual-drift".to_owned(),
            pre_authorized_code: "pre-authorized-code-manual-drift".to_owned(),
        },
        now(),
    )
    .unwrap();
    drift_transaction.issuer_profile_id = Some("issuer-profile-1".to_owned());
    drift_transaction.signing_service_id = Some("kms-service-1".to_owned());
    sqlx::query(
        "UPDATE issuance_service.canvas_program_bindings
         SET config_version = config_version + 1 WHERE id = 'binding-1'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        management_repository
            .reserve_application_issuance(
                &drift_transaction,
                &drift_snapshot,
                "canvas-integration-management-api",
                "must-not-commit",
                now(),
            )
            .await,
        Err(CanvasApplicationApprovalError::NotReady)
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM issuance_service.applications
             WHERE id = 'application-manual-drift'",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        "pending"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.issuance_transactions
             WHERE id = 'transaction-manual-drift'",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );
    sqlx::query(
        "UPDATE issuance_service.canvas_program_bindings SET config_version = 3
         WHERE id = 'binding-1'",
    )
    .execute(&pool)
    .await
    .unwrap();

    // Same payload and same identifier are both replay-safe no-ops.
    assert!(repository
        .record_fact_and_evaluate_policy(
            &application,
            &snapshot.binding,
            &snapshot.application_template,
            &plan.facts[0],
        )
        .await
        .unwrap());
    let id_collision = revised_fact(&plan.facts[0], "fact-1", 70, "2026-08-29T16:01:00Z");
    assert!(repository
        .record_fact_and_evaluate_policy(
            &application,
            &snapshot.binding,
            &snapshot.application_template,
            &id_collision,
        )
        .await
        .unwrap());
    assert_eq!(table_count(&pool, "evidence_facts").await, 1);
    assert_eq!(table_count(&pool, "issuance_events").await, 1);

    // Immutable out-of-order history is retained without rolling back its head.
    let stale = revised_fact(&plan.facts[0], "fact-stale", 70, "2026-08-29T15:58:00Z");
    assert!(repository
        .record_fact_and_evaluate_policy(
            &application,
            &snapshot.binding,
            &snapshot.application_template,
            &stale,
        )
        .await
        .unwrap());
    assert_eq!(table_count(&pool, "evidence_facts").await, 2);
    assert_eq!(table_count(&pool, "issuance_events").await, 2);
    assert_eq!(head_id(&pool).await, "fact-1");

    // A current permit-to-deny revision after issuance creates one correction review.
    sqlx::query(
        "UPDATE issuance_service.applications SET credential_id = 'credential-1'
         WHERE id = 'application-1'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let denied = revised_fact(&plan.facts[0], "fact-denied", 70, "2026-08-29T16:01:00Z");
    assert!(!repository
        .record_fact_and_evaluate_policy(
            &application,
            &snapshot.binding,
            &snapshot.application_template,
            &denied,
        )
        .await
        .unwrap());
    assert_eq!(head_id(&pool).await, "fact-denied");
    let review = sqlx::query(
        "SELECT status, triggering_fact_id, prior_decision, current_decision
         FROM issuance_service.evidence_policy_reviews",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(review.get::<String, _>("status"), "open");
    assert_eq!(review.get::<String, _>("triggering_fact_id"), "fact-denied");
    assert_eq!(review.get::<Value, _>("prior_decision")["allowed"], true);
    assert_eq!(review.get::<Value, _>("current_decision")["allowed"], false);

    let recovered = revised_fact(&plan.facts[0], "fact-recovered", 95, "2026-08-29T16:02:00Z");
    assert!(repository
        .record_fact_and_evaluate_policy(
            &application,
            &snapshot.binding,
            &snapshot.application_template,
            &recovered,
        )
        .await
        .unwrap());
    let review = sqlx::query(
        "SELECT status, resolution_action FROM issuance_service.evidence_policy_reviews",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(review.get::<String, _>("status"), "resolved");
    assert_eq!(
        review
            .get::<Option<String>, _>("resolution_action")
            .as_deref(),
        Some("evidence_recovered")
    );

    // A lifecycle handler that already claimed an open review retains ownership.
    sqlx::query(
        "UPDATE issuance_service.evidence_policy_reviews
         SET status = 'open', resolution_action = NULL, resolution_notes = NULL,
             resolved_by = NULL, resolved_at = NULL,
             resolution_claim_token = 'claim-token-1', resolution_claim_action = 'dismiss',
             resolution_claimed_at = clock_timestamp(), resolution_recovery_pending = false",
    )
    .execute(&pool)
    .await
    .unwrap();
    let claimed_recovery = revised_fact(
        &plan.facts[0],
        "fact-claimed-recovery",
        95,
        "2026-08-29T16:03:00Z",
    );
    assert!(repository
        .record_fact_and_evaluate_policy(
            &application,
            &snapshot.binding,
            &snapshot.application_template,
            &claimed_recovery,
        )
        .await
        .unwrap());
    let claimed = sqlx::query(
        "SELECT status, resolution_claim_token, resolution_recovery_pending
         FROM issuance_service.evidence_policy_reviews",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(claimed.get::<String, _>("status"), "open");
    assert_eq!(
        claimed
            .get::<Option<String>, _>("resolution_claim_token")
            .as_deref(),
        Some("claim-token-1")
    );
    assert!(claimed.get::<bool, _>("resolution_recovery_pending"));

    // Approval locks and rechecks the exact identity; drift after planning cannot reserve.
    sqlx::query(
        "INSERT INTO issuance_service.applications
         VALUES ('application-approval-race', 'org-1', 'application-template-1',
                 'canvas_lti:learner-subject-1',
                 '{\"achievement\":\"Portable Canvas\"}'::json,
                 '{\"canvas\":{\"source\":\"canvas_lti_bootstrap\"}}'::json,
                 'pending', NULL, NULL, NULL, NULL, NULL, clock_timestamp())",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.canvas_award_candidates
         (id, organization_id, platform_id, binding_id, learner_identity_id,
          candidate_key, canvas_user_id, lti_subject, state, application_id,
          observed_at, created_at, updated_at)
         VALUES ('candidate-approval-race', 'org-1', 'platform-1', 'binding-1',
                 'identity-1', 'approval-race', '42', 'learner-subject-1', 'eligible',
                 'application-approval-race', clock_timestamp(), clock_timestamp(),
                 clock_timestamp())",
    )
    .execute(&pool)
    .await
    .unwrap();
    let mut race_application = application.clone();
    race_application.id = "application-approval-race".to_owned();
    let mut approval_race_plan = plan.clone();
    approval_race_plan.candidate_id = "candidate-approval-race".to_owned();
    let approval_repository = PostgresCanvasAwardApprovalRepository::new(pool.clone());
    let approval_snapshot = approval_repository
        .load_approval_snapshot(&context, &race_application, &approval_race_plan)
        .await
        .unwrap()
        .unwrap();
    let mut approval_transaction = plan_canvas_award_approval(
        &context,
        &race_application,
        &approval_race_plan,
        &approval_snapshot,
        &CanvasAwardApprovalSeed {
            transaction_id: "transaction-approval-race".to_owned(),
            pre_authorized_code: "pre-authorized-code-race".to_owned(),
        },
        now(),
        Duration::from_secs(900),
    )
    .unwrap();
    approval_transaction.issuer_profile_id = Some("issuer-profile-1".to_owned());
    approval_transaction.signing_service_id = Some("kms-service-1".to_owned());
    sqlx::query(
        "UPDATE issuance_service.canvas_learner_identities SET status = 'quarantined'
         WHERE id = 'identity-1'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        approval_repository
            .reserve_issuance(
                &approval_transaction,
                &context,
                &approval_race_plan,
                &approval_snapshot,
            )
            .await,
        Err(marty_issuance_service::canvas_award_candidate_service::CanvasAwardCandidateApprovalError::ReadinessDrift)
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM issuance_service.applications
             WHERE id = 'application-approval-race'",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        "pending"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.issuance_transactions
             WHERE id = 'transaction-approval-race'",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );

    // A concurrent state change makes linking fail atomically and leaves the app untouched.
    sqlx::query(
        "INSERT INTO issuance_service.canvas_award_candidates
         (id, organization_id, platform_id, binding_id, candidate_key, lti_subject, state,
          observed_at, created_at, updated_at)
         VALUES ('candidate-race', 'org-1', 'platform-1', 'binding-1', 'race',
                 'learner-subject-1', 'dismissed', clock_timestamp(), clock_timestamp(),
                 clock_timestamp())",
    )
    .execute(&pool)
    .await
    .unwrap();
    let mut raced_plan = plan.clone();
    raced_plan.candidate_id = "candidate-race".to_owned();
    raced_plan.application_canvas_patch = json!({"must_not_commit": true})
        .as_object()
        .unwrap()
        .clone();
    assert_eq!(
        repository.link_candidate(&application, &raced_plan).await,
        Err(CanvasAwardCandidateRepositoryError::Unavailable)
    );
    let integration: Value = sqlx::query_scalar(
        "SELECT integration_context FROM issuance_service.applications
         WHERE id = 'application-1'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(integration["canvas"].get("must_not_commit").is_none());

    exercise_legacy_ingest_postgres_contract(&pool).await;
}

struct LegacyIds(AtomicUsize);

impl CanvasLegacyIdGenerator for LegacyIds {
    fn receipt_id(&self) -> String {
        format!(
            "legacy-receipt-{}",
            self.0.fetch_add(1, Ordering::SeqCst) + 1
        )
    }

    fn fact_id(&self) -> String {
        format!("legacy-fact-{}", self.0.fetch_add(1, Ordering::SeqCst) + 1)
    }
}

struct LegacySeeds;

impl CanvasAwardApprovalSeedGenerator for LegacySeeds {
    fn generate(&self) -> CanvasAwardApprovalSeed {
        CanvasAwardApprovalSeed {
            transaction_id: "transaction-legacy-auto".to_owned(),
            pre_authorized_code: "legacy-auto-private-code".to_owned(),
        }
    }
}

fn signed_legacy_payload(
    application_id: &str,
    event_id: &str,
    course_id: &str,
) -> (Vec<u8>, BTreeMap<String, String>) {
    signed_legacy_payload_with_achievement(application_id, event_id, course_id, "Completed")
}

fn signed_legacy_payload_with_achievement(
    application_id: &str,
    event_id: &str,
    course_id: &str,
    achievement_name: &str,
) -> (Vec<u8>, BTreeMap<String, String>) {
    let body = serde_json::to_vec(&json!({
        "canvas_event_id":event_id,"application_id":application_id,
        "canvas_account_id":"account-1","canvas_course_id":course_id,
        "canvas_course_name":"Portable Canvas","canvas_enrollment_id":"enrollment-1",
        "canvas_user_id":"42","learner_email":"learner@example.test",
        "achievement_name":achievement_name,"completion_at":"2026-08-29T16:00:00Z",
        "evidence_type":"canvas.course_completion"
    }))
    .unwrap();
    let timestamp = now().timestamp().to_string();
    let mut mac = Hmac::<Sha256>::new_from_slice(b"legacy-pg-secret").unwrap();
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(&body);
    (
        body,
        BTreeMap::from([
            ("x-canvas-timestamp".to_owned(), timestamp),
            (
                "x-canvas-signature-256".to_owned(),
                hex::encode(mac.finalize().into_bytes()),
            ),
        ]),
    )
}

async fn insert_legacy_application(
    pool: &sqlx::PgPool,
    application_id: &str,
    transaction_id: Option<&str>,
) {
    sqlx::query(
        "INSERT INTO issuance_service.applications (
            id, organization_id, application_template_id, applicant_identifier,
            form_data, submitted_evidence, integration_context, status,
            issuance_transaction_id, credential_id, created_at, updated_at)
         VALUES ($1, 'org-1', 'application-template-1', 'learner@example.test',
                 '{\"achievement\":\"Portable Canvas\"}'::json, '[]'::json,
                 '{\"canvas\":{\"source\":\"canvas_lti_bootstrap\",
                    \"canvas_platform_id\":\"platform-1\",
                    \"canvas_program_binding_id\":\"binding-legacy\",
                    \"canvas_account_id\":\"account-1\",
                    \"application_template_id\":\"application-template-1\",
                    \"credential_template_id\":\"credential-template-1\",
                    \"lti_subject\":\"verified-legacy-subject\",
                    \"verified_launch\":{\"nonce\":\"preserve-me\"}}}'::json,
                 'pending', $2, NULL, '2026-08-29T15:00:00Z',
                 '2026-08-29T15:00:00Z')",
    )
    .bind(application_id)
    .bind(transaction_id)
    .execute(pool)
    .await
    .unwrap();
}

async fn exercise_legacy_ingest_postgres_contract(pool: &sqlx::PgPool) {
    for statement in [
        "ALTER TABLE issuance_service.applications
             ADD COLUMN submitted_evidence json NOT NULL DEFAULT '[]'::json,
             ADD COLUMN created_at timestamptz NOT NULL DEFAULT clock_timestamp()",
        "ALTER TABLE issuance_service.application_templates
             ADD COLUMN evidence_requirements json",
        "ALTER TABLE issuance_service.canvas_program_bindings
             ADD COLUMN canvas_scope json,
             ADD COLUMN delivery_mode text NOT NULL DEFAULT 'wallet_only',
             ADD COLUMN deployment_profile_id text,
             ADD COLUMN created_at timestamptz NOT NULL DEFAULT clock_timestamp()",
        "CREATE TABLE issuance_service.canvas_event_receipts (
             id text PRIMARY KEY, provider_event_id text NOT NULL,
             organization_id text NOT NULL, credential_template_id text NOT NULL,
             canvas_account_id text NOT NULL, payload_hash text NOT NULL,
             issuance_transaction_id text, issuance_response json NOT NULL,
             status text NOT NULL, error_summary text,
             first_seen_at timestamptz NOT NULL, last_seen_at timestamptz NOT NULL,
             UNIQUE (canvas_account_id, provider_event_id))",
        "CREATE TABLE issuance_service.issued_credentials (
             id text PRIMARY KEY, transaction_id text NOT NULL UNIQUE)",
        "INSERT INTO issuance_service.canvas_program_bindings (
             id, organization_id, platform_id, application_template_id,
             credential_template_id, approval_policy_set_id, auto_approve_on_evidence,
             evidence_requirements, canvas_scope, delivery_mode, deployment_profile_id,
             feature_flags, enabled, config_version, validated_config_version,
             readiness_checks, readiness_validated_at, credential_template_snapshot,
             activated_at, archived_at, created_at)
         VALUES ('binding-legacy', 'org-1', 'platform-1', 'application-template-1',
             'credential-template-1', NULL, false,
             '[{\"requirement_id\":\"legacy-completion\",\"provider\":\"canvas\",
                \"fact_type\":\"canvas.course_completion\",\"scope\":{},
                \"pass_rule\":{\"completed\":true},\"required\":true}]'::json,
             NULL, 'wallet_plus_canvas_mirror', NULL,
             '{\"enable_canvas_evidence\":true}'::json, true, 3, 3,
             '[{\"code\":\"kms\",\"status\":\"ready\",\"blocking\":true}]'::json,
             '2026-08-29T15:59:00Z',
             '{\"id\":\"credential-template-1\",\"organization_id\":\"org-1\",
               \"status\":\"active\",\"credential_type\":\"OpenBadgeCredential\",
               \"credential_payload_format\":\"w3c_vcdm_v2_sd_jwt\",
               \"revocation_profile_id\":\"revocation-profile-1\",
               \"issuer_did\":\"did:web:issuer.example:orgs:org-1\",
               \"issuer_algorithm\":\"ES256\",\"wallet_configs\":[],
               \"selective_disclosure_fields\":[],\"zk_predicate_claims\":[],
               \"validity_rules\":{\"default_validity_days\":365,
                 \"renewable\":false,\"renewal_window_days\":30}}'::json,
             '2026-08-29T15:00:00Z', NULL, '2026-08-29T15:00:00Z')",
    ] {
        sqlx::query(statement).execute(pool).await.unwrap();
    }
    insert_legacy_application(pool, "application-legacy", None).await;

    let service = CanvasLegacyIngestService::new(
        Arc::new(PostgresCanvasLegacyIngestRepository::new(pool.clone())),
        Arc::new(ApprovalIssuer),
        Arc::new(LegacySeeds),
        Arc::new(LegacyIds(AtomicUsize::new(0))),
        Arc::new(ApprovalClock),
        CanvasLegacyIngestConfig {
            enabled: true,
            shared_secret: Some("legacy-pg-secret".to_owned()),
            shared_secret_file: None,
            signature_tolerance_seconds: 300,
        },
    );

    let (body, headers) = signed_legacy_payload("application-legacy", "legacy-event-1", "course-1");
    let first = service
        .process(CanvasLegacyEventKind::Evidence, &body, &headers)
        .await
        .unwrap();
    assert_eq!(first.application_status.as_deref(), Some("pending"));
    let persisted = sqlx::query(
        "SELECT id, requirement_id, logical_key, source
         FROM issuance_service.evidence_facts
         WHERE application_id = 'application-legacy'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(persisted.get::<String, _>("id"), "legacy-fact-1");
    assert!(persisted
        .get::<Option<String>, _>("requirement_id")
        .is_none());
    assert!(!persisted.get::<String, _>("logical_key").is_empty());
    let source: Value = persisted.get("source");
    assert!(source.get("source").is_none());
    let application = sqlx::query(
        "SELECT submitted_evidence, integration_context
         FROM issuance_service.applications WHERE id = 'application-legacy'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        application
            .get::<Value, _>("submitted_evidence")
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        application.get::<Value, _>("integration_context")["canvas"]["lti_subject"],
        "verified-legacy-subject"
    );
    assert_eq!(
        application.get::<Value, _>("integration_context")["canvas"]["verified_launch"]["nonce"],
        "preserve-me"
    );

    let replay = service
        .process(CanvasLegacyEventKind::Evidence, &body, &headers)
        .await
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.evidence_facts
             WHERE application_id = 'application-legacy'",
        )
        .fetch_one(pool)
        .await
        .unwrap(),
        1
    );

    let (body, headers) = signed_legacy_payload_with_achievement(
        "application-legacy",
        "legacy-event-2",
        "course-1",
        "Completed Again",
    );
    service
        .process(CanvasLegacyEventKind::Evidence, &body, &headers)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT fact_id FROM issuance_service.evidence_fact_heads
             WHERE application_id = 'application-legacy'",
        )
        .fetch_one(pool)
        .await
        .unwrap(),
        "legacy-fact-3"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.evidence_facts
             WHERE application_id = 'application-legacy'",
        )
        .fetch_one(pool)
        .await
        .unwrap(),
        2
    );

    sqlx::query(
        "UPDATE issuance_service.canvas_program_bindings
         SET auto_approve_on_evidence = true WHERE id = 'binding-legacy'",
    )
    .execute(pool)
    .await
    .unwrap();
    let (body, headers) =
        signed_legacy_payload("application-legacy", "legacy-event-auto", "course-2");
    let approved = service
        .process(CanvasLegacyEventKind::Evidence, &body, &headers)
        .await
        .unwrap();
    assert_eq!(approved.application_status.as_deref(), Some("approved"));
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT reviewer_id FROM issuance_service.applications
             WHERE id = 'application-legacy'",
        )
        .fetch_one(pool)
        .await
        .unwrap()
        .as_deref(),
        Some("canvas:auto-approval")
    );
    let policy_metadata: Value = sqlx::query_scalar(
        "SELECT metadata FROM issuance_service.issuance_events
         WHERE application_id = 'application-legacy'
           AND event_type = 'evidence_policy_permitted'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        policy_metadata["evidence_fact_ids"],
        json!(["legacy-fact-3", "legacy-fact-5"])
    );
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT issuance_transaction_id FROM issuance_service.canvas_event_receipts
             WHERE provider_event_id = 'legacy-event-auto'",
        )
        .fetch_one(pool)
        .await
        .unwrap()
        .as_deref(),
        Some("transaction-legacy-auto")
    );

    insert_legacy_application(pool, "application-legacy-reuse", Some("legacy-reuse")).await;
    sqlx::query(
        "INSERT INTO issuance_service.issuance_transactions
         SELECT 'legacy-reuse', organization_id, credential_template_id,
                revocation_profile_id, renewal_of_credential_id, applicant_id,
                'application-legacy-reuse', subject_did, NULL, NULL,
                'pending', 'legacy-reuse-private-code', 'legacy-reuse-nonce',
                (claims::jsonb || '{\"preserved_claim\":\"keep-me\"}'::jsonb)::json,
                'stale-type', selective_disclosure_claims, zk_predicate_claims,
                'stale-format', wallet_configs, validity_days, renewable,
                renewal_window_days, 'wallet_only', 'stale-profile', issuer_mode,
                'did:web:stale.example', 'ES384', 'stale-service', NULL, NULL,
                created_at, expires_at
         FROM issuance_service.issuance_transactions
         WHERE id = 'transaction-legacy-auto'",
    )
    .execute(pool)
    .await
    .unwrap();
    let reuse_before = sqlx::query(
        "SELECT pre_auth_code, c_nonce, claims, created_at, expires_at
         FROM issuance_service.issuance_transactions WHERE id = 'legacy-reuse'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    let (body, headers) =
        signed_legacy_payload("application-legacy-reuse", "legacy-event-reuse", "course-1");
    let reuse = service
        .process(CanvasLegacyEventKind::Evidence, &body, &headers)
        .await
        .unwrap();
    assert_eq!(reuse.application_status.as_deref(), Some("approved"));
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT issuance_transaction_id FROM issuance_service.canvas_event_receipts
             WHERE provider_event_id = 'legacy-event-reuse'",
        )
        .fetch_one(pool)
        .await
        .unwrap()
        .as_deref(),
        Some("legacy-reuse")
    );
    let reuse_after = sqlx::query(
        "SELECT pre_auth_code, c_nonce, claims, created_at, expires_at,
                delivery_mode, credential_type, credential_payload_format,
                issuer_profile_id, issuer_did_override, issuer_algorithm,
                signing_service_id
         FROM issuance_service.issuance_transactions WHERE id = 'legacy-reuse'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        reuse_before.get::<String, _>("pre_auth_code"),
        reuse_after.get::<String, _>("pre_auth_code")
    );
    assert_eq!(
        reuse_before.get::<Option<String>, _>("c_nonce"),
        reuse_after.get::<Option<String>, _>("c_nonce")
    );
    assert_eq!(
        reuse_before.get::<Value, _>("claims"),
        reuse_after.get::<Value, _>("claims")
    );
    assert_eq!(
        reuse_before.get::<DateTime<Utc>, _>("created_at"),
        reuse_after.get::<DateTime<Utc>, _>("created_at")
    );
    assert_eq!(
        reuse_before.get::<DateTime<Utc>, _>("expires_at"),
        reuse_after.get::<DateTime<Utc>, _>("expires_at")
    );
    assert_eq!(
        reuse_after.get::<String, _>("delivery_mode"),
        "wallet_plus_canvas_mirror"
    );
    assert_eq!(
        reuse_after
            .get::<Option<String>, _>("credential_type")
            .as_deref(),
        Some("OpenBadgeCredential")
    );
    assert_eq!(
        reuse_after
            .get::<Option<String>, _>("issuer_profile_id")
            .as_deref(),
        Some("issuer-profile-1")
    );
    assert_eq!(
        reuse_after
            .get::<Option<String>, _>("signing_service_id")
            .as_deref(),
        Some("kms-service-1")
    );

    insert_legacy_application(
        pool,
        "application-legacy-authorized",
        Some("legacy-authorized"),
    )
    .await;
    sqlx::query(
        "INSERT INTO issuance_service.issuance_transactions
         SELECT 'legacy-authorized', organization_id, credential_template_id,
                revocation_profile_id, renewal_of_credential_id, applicant_id,
                'application-legacy-authorized', subject_did, NULL, NULL,
                'authorized', 'legacy-authorized-code', c_nonce, claims,
                credential_type, selective_disclosure_claims, zk_predicate_claims,
                credential_payload_format, wallet_configs, validity_days, renewable,
                renewal_window_days, delivery_mode, issuer_profile_id, issuer_mode,
                issuer_did_override, issuer_algorithm, signing_service_id, NULL, NULL,
                created_at, expires_at
         FROM issuance_service.issuance_transactions
         WHERE id = 'transaction-legacy-auto'",
    )
    .execute(pool)
    .await
    .unwrap();
    let (body, headers) = signed_legacy_payload(
        "application-legacy-authorized",
        "legacy-event-authorized",
        "course-1",
    );
    let authorized = service
        .process(CanvasLegacyEventKind::Evidence, &body, &headers)
        .await
        .unwrap();
    assert_eq!(authorized.application_status.as_deref(), Some("approved"));
    assert_eq!(
        authorized.policy_decision.as_ref().unwrap()["errors"],
        json!(["Canvas credential claim is already in progress"])
    );
    let authorized_row = sqlx::query(
        "SELECT status, reviewer_id FROM issuance_service.applications
         WHERE id = 'application-legacy-authorized'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(authorized_row.get::<String, _>("status"), "approved");
    assert_eq!(
        authorized_row
            .get::<Option<String>, _>("reviewer_id")
            .as_deref(),
        Some("canvas:auto-approval")
    );
    assert!(sqlx::query_scalar::<_, Option<String>>(
        "SELECT issuance_transaction_id FROM issuance_service.canvas_event_receipts
         WHERE provider_event_id = 'legacy-event-authorized'",
    )
    .fetch_one(pool)
    .await
    .unwrap()
    .is_none());

    insert_legacy_application(pool, "application-legacy-issued", Some("legacy-issued")).await;
    sqlx::query(
        "INSERT INTO issuance_service.issuance_transactions
         SELECT 'legacy-issued', organization_id, credential_template_id,
                revocation_profile_id, renewal_of_credential_id, applicant_id,
                'application-legacy-issued', subject_did, NULL, NULL,
                'issued', 'legacy-issued-code', c_nonce, claims,
                credential_type, selective_disclosure_claims, zk_predicate_claims,
                credential_payload_format, wallet_configs, validity_days, renewable,
                renewal_window_days, delivery_mode, issuer_profile_id, issuer_mode,
                issuer_did_override, issuer_algorithm, signing_service_id, NULL, NULL,
                created_at, expires_at
         FROM issuance_service.issuance_transactions
         WHERE id = 'transaction-legacy-auto'",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.issued_credentials
         VALUES ('credential-legacy-issued', 'legacy-issued')",
    )
    .execute(pool)
    .await
    .unwrap();
    let (body, headers) = signed_legacy_payload(
        "application-legacy-issued",
        "legacy-event-issued",
        "course-1",
    );
    let issued = service
        .process(CanvasLegacyEventKind::Evidence, &body, &headers)
        .await
        .unwrap();
    assert_eq!(issued.application_status.as_deref(), Some("pending"));
    assert_eq!(
        issued.policy_decision.as_ref().unwrap()["errors"],
        json!(["Canvas application already has an issued credential"])
    );
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT credential_id FROM issuance_service.applications
             WHERE id = 'application-legacy-issued'",
        )
        .fetch_one(pool)
        .await
        .unwrap()
        .as_deref(),
        Some("credential-legacy-issued")
    );
    assert!(sqlx::query_scalar::<_, Option<String>>(
        "SELECT issuance_transaction_id FROM issuance_service.canvas_event_receipts
         WHERE provider_event_id = 'legacy-event-issued'",
    )
    .fetch_one(pool)
    .await
    .unwrap()
    .is_none());

    sqlx::query(
        "UPDATE issuance_service.canvas_program_bindings
         SET auto_approve_on_evidence = false WHERE id = 'binding-legacy'",
    )
    .execute(pool)
    .await
    .unwrap();
    insert_legacy_application(pool, "application-legacy-rollback", None).await;
    sqlx::query(
        "ALTER TABLE issuance_service.canvas_event_receipts
         ADD CONSTRAINT force_legacy_finalize_failure
         CHECK (provider_event_id <> 'legacy-event-rollback'
                OR status <> 'evidence_received') NOT VALID",
    )
    .execute(pool)
    .await
    .unwrap();
    let facts_before = table_count(pool, "evidence_facts").await;
    let events_before = table_count(pool, "issuance_events").await;
    let (body, headers) = signed_legacy_payload(
        "application-legacy-rollback",
        "legacy-event-rollback",
        "course-1",
    );
    assert_eq!(
        service
            .process(CanvasLegacyEventKind::Evidence, &body, &headers)
            .await,
        Err(CanvasLegacyIngestError::RepositoryUnavailable)
    );
    assert_eq!(table_count(pool, "evidence_facts").await, facts_before);
    assert_eq!(table_count(pool, "issuance_events").await, events_before);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.canvas_event_receipts
             WHERE provider_event_id = 'legacy-event-rollback'",
        )
        .fetch_one(pool)
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.issuance_transactions
             WHERE application_id = 'application-legacy-rollback'",
        )
        .fetch_one(pool)
        .await
        .unwrap(),
        0
    );
    assert!(sqlx::query_scalar::<_, Option<String>>(
        "SELECT issuance_transaction_id FROM issuance_service.applications
         WHERE id = 'application-legacy-rollback'",
    )
    .fetch_one(pool)
    .await
    .unwrap()
    .is_none());
    assert_eq!(
        sqlx::query_scalar::<_, i32>(
            "SELECT json_array_length(submitted_evidence)
             FROM issuance_service.applications
             WHERE id = 'application-legacy-rollback'",
        )
        .fetch_one(pool)
        .await
        .unwrap(),
        0
    );
}

async fn table_count(pool: &sqlx::PgPool, table: &str) -> i64 {
    let query = match table {
        "evidence_facts" => "SELECT count(*) FROM issuance_service.evidence_facts",
        "issuance_events" => "SELECT count(*) FROM issuance_service.issuance_events",
        _ => panic!("unaudited contract table {table}"),
    };
    sqlx::query_scalar(query).fetch_one(pool).await.unwrap()
}

async fn head_id(pool: &sqlx::PgPool) -> String {
    sqlx::query_scalar(
        "SELECT fact_id FROM issuance_service.evidence_fact_heads
         WHERE application_id = 'application-1'",
    )
    .fetch_one(pool)
    .await
    .unwrap()
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
            id text PRIMARY KEY, organization_id text NOT NULL,
            lti_deployment_id text, canvas_account_id text NOT NULL,
            registration_status text NOT NULL, enabled boolean NOT NULL,
            archived_at timestamptz)",
        "CREATE TABLE issuance_service.application_templates (
            id text PRIMARY KEY, organization_id text NOT NULL,
            credential_template_id text, approval_policy_set_id text, status text NOT NULL)",
        "CREATE TABLE issuance_service.canvas_program_bindings (
            id text PRIMARY KEY, organization_id text NOT NULL, platform_id text NOT NULL,
            application_template_id text NOT NULL, credential_template_id text NOT NULL,
            approval_policy_set_id text, auto_approve_on_evidence boolean NOT NULL,
            evidence_requirements json NOT NULL, feature_flags json NOT NULL,
            enabled boolean NOT NULL, config_version integer NOT NULL,
            validated_config_version integer, readiness_checks json NOT NULL,
            readiness_validated_at timestamptz, credential_template_snapshot json NOT NULL,
            activated_at timestamptz, archived_at timestamptz)",
        "CREATE TABLE issuance_service.applications (
            id text PRIMARY KEY, organization_id text NOT NULL,
            application_template_id text NOT NULL, applicant_identifier text NOT NULL,
            form_data json NOT NULL, integration_context json NOT NULL,
            status text NOT NULL, review_notes text, reviewer_id text,
            reviewed_at timestamptz, issuance_transaction_id text, credential_id text,
            updated_at timestamptz NOT NULL DEFAULT clock_timestamp())",
        "CREATE TABLE issuance_service.issuance_transactions (
            id text PRIMARY KEY, organization_id text NOT NULL,
            credential_template_id text NOT NULL, revocation_profile_id text,
            renewal_of_credential_id text, applicant_id text, application_id text,
            subject_did text, idempotency_key_hash text, idempotency_request_hash text,
            status text NOT NULL, pre_auth_code text NOT NULL UNIQUE,
            c_nonce text, claims json NOT NULL, credential_type text,
            selective_disclosure_claims json NOT NULL, zk_predicate_claims json NOT NULL,
            credential_payload_format text NOT NULL, wallet_configs json NOT NULL,
            validity_days integer NOT NULL, renewable boolean NOT NULL,
            renewal_window_days integer NOT NULL, delivery_mode text NOT NULL,
            issuer_profile_id text, issuer_mode text NOT NULL,
            issuer_did_override text, issuer_algorithm text, signing_service_id text,
            reserved_credential_id text, oid4vci_client_id text,
            created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL)",
        "CREATE TABLE issuance_service.canvas_learner_identities (
            id text PRIMARY KEY, organization_id text NOT NULL, platform_id text NOT NULL,
            deployment_id text NOT NULL, lti_subject text NOT NULL, canvas_user_id text,
            status text NOT NULL)",
        "CREATE TABLE issuance_service.canvas_award_candidates (
            id text PRIMARY KEY, organization_id text NOT NULL, platform_id text NOT NULL,
            binding_id text NOT NULL, learner_identity_id text, candidate_key text NOT NULL,
            canvas_user_id text, lti_subject text, state text NOT NULL, application_id text,
            observed_at timestamptz NOT NULL, created_at timestamptz NOT NULL,
            updated_at timestamptz NOT NULL)",
        "CREATE TABLE issuance_service.canvas_candidate_observations (
            id text PRIMARY KEY, organization_id text NOT NULL, candidate_id text NOT NULL,
            requirement_id text NOT NULL, logical_key text NOT NULL, assertion json NOT NULL,
            verification json NOT NULL, payload_hash text NOT NULL,
            is_current boolean NOT NULL, observed_at timestamptz NOT NULL,
            created_at timestamptz NOT NULL)",
        "CREATE TABLE issuance_service.evidence_facts (
            id text PRIMARY KEY, organization_id text NOT NULL, application_id text NOT NULL,
            subject_id text NOT NULL, provider text NOT NULL, fact_type text NOT NULL,
            scope json NOT NULL, assertion json NOT NULL, verification json NOT NULL,
            source json NOT NULL, requirement_id text, logical_key text NOT NULL,
            source_revision text NOT NULL, payload_hash text NOT NULL,
            observed_at timestamptz NOT NULL, effective_at timestamptz NOT NULL,
            superseded_fact_id text, created_at timestamptz NOT NULL)",
        "CREATE TABLE issuance_service.evidence_fact_heads (
            organization_id text NOT NULL, application_id text NOT NULL,
            logical_key text NOT NULL, fact_id text NOT NULL UNIQUE,
            updated_at timestamptz NOT NULL,
            PRIMARY KEY (application_id, logical_key))",
        "CREATE TABLE issuance_service.issuance_events (
            id text PRIMARY KEY, transaction_id text, application_id text,
            event_type text NOT NULL, metadata json NOT NULL,
            created_at timestamptz NOT NULL)",
        "CREATE TABLE issuance_service.evidence_policy_reviews (
            id text PRIMARY KEY, organization_id text NOT NULL, application_id text NOT NULL,
            credential_id text NOT NULL, binding_id text, status text NOT NULL,
            prior_decision json NOT NULL, current_decision json NOT NULL,
            triggering_fact_id text, resolution_action text, resolution_notes text,
            resolved_by text, resolved_at timestamptz, resolution_claim_token text,
            resolution_claim_action text, resolution_claimed_at timestamptz,
            resolution_recovery_pending boolean NOT NULL DEFAULT false,
            created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL)",
    ] {
        sqlx::query(statement).execute(pool).await.unwrap();
    }
}

async fn seed_candidate(pool: &sqlx::PgPool) {
    for statement in [
        "INSERT INTO issuance_service.canvas_platforms
         (id, organization_id, lti_deployment_id, canvas_account_id,
          registration_status, enabled, archived_at)
         VALUES ('platform-1', 'org-1', 'deployment-123', 'account-1',
                 'verified', true, NULL)",
        "INSERT INTO issuance_service.application_templates
         VALUES ('application-template-1', 'org-1', 'credential-template-1', NULL, 'active')",
        "INSERT INTO issuance_service.canvas_program_bindings
         VALUES (
            'binding-1', 'org-1', 'platform-1', 'application-template-1',
            'credential-template-1', NULL, true,
            '[{\"requirement_id\":\"score-1\",\"source\":\"ags_result\",\"fact_type\":\"canvas.assignment_score\",\"scope\":{\"course_id\":\"course-1\",\"resource_id\":\"marty:score\",\"line_item_url\":\"https://canvas.example.edu/api/lti/courses/1/line_items/1\"},\"pass_rule\":{\"min_score_percent\":80},\"required\":true}]'::json,
            '{\"enable_canvas_evidence\":true}'::json, true, 3, 3,
            '[{\"code\":\"kms\",\"status\":\"ready\",\"blocking\":true}]'::json,
            '2026-08-29T15:59:00Z',
            '{\"id\":\"credential-template-1\",\"organization_id\":\"org-1\",\"status\":\"active\",\"credential_type\":\"OpenBadgeCredential\",\"credential_payload_format\":\"w3c_vcdm_v2_sd_jwt\",\"revocation_profile_id\":\"revocation-profile-1\",\"issuer_did\":\"did:web:issuer.example:orgs:org-1\",\"issuer_algorithm\":\"ES256\",\"wallet_configs\":[],\"selective_disclosure_fields\":[],\"zk_predicate_claims\":[],\"validity_rules\":{\"default_validity_days\":365,\"renewable\":false,\"renewal_window_days\":30}}'::json,
            '2026-08-29T15:00:00Z', NULL)",
        "INSERT INTO issuance_service.applications
         VALUES ('application-1', 'org-1', 'application-template-1',
                 'canvas_lti:learner-subject-1',
                 '{\"achievement\":\"Portable Canvas\"}'::json,
                 '{\"canvas\":{\"source\":\"canvas_lti_bootstrap\"}}'::json,
                 'pending', NULL, NULL, NULL, NULL, NULL, clock_timestamp())",
        "INSERT INTO issuance_service.canvas_learner_identities
         VALUES ('identity-1', 'org-1', 'platform-1', 'deployment-123',
                 'learner-subject-1', '42', 'linked')",
        "INSERT INTO issuance_service.canvas_award_candidates
         VALUES ('candidate-1', 'org-1', 'platform-1', 'binding-1', NULL,
                 'candidate-key-1', NULL, 'learner-subject-1', 'pending_claim', NULL,
                 '2026-08-29T15:59:00Z', clock_timestamp(), clock_timestamp())",
        "INSERT INTO issuance_service.canvas_candidate_observations
         VALUES ('observation-1', 'org-1', 'candidate-1', 'score-1', 'score-key-1',
                 '{\"completed\":true,\"score_percent\":95}'::json,
                 '{\"status\":\"VERIFIED\",\"method\":\"LTI_AGS_RESULT_READ\"}'::json,
                 'candidate-score-95', true, '2026-08-29T15:59:30Z', clock_timestamp())",
    ] {
        sqlx::query(statement).execute(pool).await.unwrap();
    }
}
