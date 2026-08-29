use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use marty_issuance_service::{
    canvas_award_candidate::{
        plan_selected_canvas_award_candidate_materialization, select_canvas_award_candidate,
        CanvasIdentityJoin,
    },
    canvas_award_candidate_postgres::PostgresCanvasAwardCandidateRepository,
    canvas_award_candidate_service::{
        CanvasAwardCandidateRepository, CanvasAwardCandidateRepositoryError,
    },
    canvas_lti_bootstrap::CanvasLtiBootstrapApplication,
    canvas_lti_experience::{
        canvas_lti_experience_session_context, CanvasLtiExperienceSessionContext,
    },
    canvas_lti_launch::CanvasLtiStoredLaunchState,
};
use serde_json::{json, Value};
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
            lti_deployment_id text)",
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
            application_template_id text NOT NULL, integration_context json NOT NULL,
            status text NOT NULL, issuance_transaction_id text, credential_id text,
            updated_at timestamptz NOT NULL DEFAULT clock_timestamp())",
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
         VALUES ('platform-1', 'org-1', 'deployment-123')",
        "INSERT INTO issuance_service.application_templates
         VALUES ('application-template-1', 'org-1', 'credential-template-1', NULL, 'active')",
        "INSERT INTO issuance_service.canvas_program_bindings
         VALUES (
            'binding-1', 'org-1', 'platform-1', 'application-template-1',
            'credential-template-1', NULL, true,
            '[{\"requirement_id\":\"score-1\",\"source\":\"ags_result\",\"fact_type\":\"canvas.assignment_score\",\"scope\":{\"course_id\":\"course-1\",\"resource_id\":\"marty:score\",\"line_item_url\":\"https://canvas.example.edu/api/lti/courses/1/line_items/1\"},\"pass_rule\":{\"min_score_percent\":80},\"required\":true}]'::json,
            '{\"enable_canvas_evidence\":true}'::json, true, 3, 3,
            '[{\"code\":\"kms\",\"status\":\"ready\",\"blocking\":true}]'::json,
            '2026-08-29T15:59:00Z', '{\"id\":\"credential-template-1\"}'::json,
            '2026-08-29T15:00:00Z', NULL)",
        "INSERT INTO issuance_service.applications
         VALUES ('application-1', 'org-1', 'application-template-1',
                 '{\"canvas\":{\"source\":\"canvas_lti_bootstrap\"}}'::json,
                 'pending', NULL, NULL, clock_timestamp())",
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
