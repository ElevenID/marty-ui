use marty_issuance_service::{
    canvas_lti_evidence::{
        project_canvas_lti_evidence_status, CanvasLtiEvidenceError, CanvasLtiEvidenceRepository,
    },
    canvas_lti_evidence_postgres::PostgresCanvasLtiEvidenceRepository,
    canvas_lti_experience::canvas_lti_experience_session_context,
    canvas_lti_launch::CanvasLtiStoredLaunchState,
};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;

fn database_url() -> Option<String> {
    std::env::var("MARTY_ISSUANCE_POSTGRES_CONTRACT_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn context(
    organization_id: &str,
) -> marty_issuance_service::canvas_lti_experience::CanvasLtiExperienceSessionContext {
    canvas_lti_experience_session_context(CanvasLtiStoredLaunchState {
        id: "session-id-1".to_owned(),
        platform_id: "platform-1".to_owned(),
        organization_id: organization_id.to_owned(),
        canvas_account_id: "account-1".to_owned(),
        state: "session-digest-1".to_owned(),
        nonce: "session-nonce-1".to_owned(),
        redirect_uri: "https://ui.example.test/canvas/lti/experience".to_owned(),
        status: "session".to_owned(),
        metadata: json!({
            "kind": "canvas_lti_experience_session",
            "launch_state": "launch-state-2",
            "verified_launch": {"raw_claims": {}},
            "mip_primitives": {"context": {
                "canvas_platform_id": "platform-1",
                "canvas_program_binding_id": "binding-1",
                "application_id": "application-1"
            }}
        }),
        expired: false,
    })
    .unwrap()
}

#[tokio::test]
async fn evidence_projection_reads_only_tenant_current_heads_and_exact_target_jobs() {
    let Some(database_url) = database_url() else {
        eprintln!("skipping Canvas evidence PostgreSQL contract without database URL");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("issuance PostgreSQL contract database must connect");
    setup_schema(&pool).await;
    seed_scope(&pool).await;
    let repository = PostgresCanvasLtiEvidenceRepository::new(pool.clone());

    assert!(repository
        .load_scope(&context("org-other"))
        .await
        .unwrap()
        .is_none());
    let scope = repository
        .load_scope(&context("org-1"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(scope.application.id, "application-1");
    assert_eq!(scope.binding.config_version, 7);
    let data = repository.load_projection_data(&scope).await.unwrap();
    assert_eq!(data.facts.len(), 1);
    assert_eq!(
        data.facts[0].requirement_id.as_deref(),
        Some("required-score")
    );
    assert_eq!(data.target.as_ref().unwrap().id, "target-1");
    assert_eq!(data.jobs.len(), 2);
    assert_eq!(data.jobs[0].id, "job-latest");
    assert_eq!(data.candidate.as_ref().unwrap().id, "candidate-1");

    let response = project_canvas_lti_evidence_status(&scope, &data).unwrap();
    assert_eq!(response.sync.as_ref().unwrap().status, "running");
    assert_eq!(response.evidence.status, "verified");
    assert_eq!(response.policy.status, "permitted");
    assert_eq!(response.claim.status, "ready_to_claim");

    sqlx::query(
        "UPDATE issuance_service.canvas_evidence_sync_jobs
         SET status = 'unexpected' WHERE id = 'job-latest'",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        repository.load_projection_data(&scope).await.unwrap_err(),
        CanvasLtiEvidenceError::RepositoryUnavailable
    );
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
        "CREATE TABLE issuance_service.applications (
            id text PRIMARY KEY, organization_id text NOT NULL,
            application_template_id text NOT NULL, status text NOT NULL,
            credential_id text, integration_context jsonb NOT NULL)",
        "CREATE TABLE issuance_service.canvas_platforms (
            id text PRIMARY KEY, organization_id text NOT NULL)",
        "CREATE TABLE issuance_service.canvas_program_bindings (
            id text PRIMARY KEY, organization_id text NOT NULL, platform_id text NOT NULL,
            application_template_id text NOT NULL, evidence_requirements jsonb NOT NULL,
            config_version integer NOT NULL)",
        "CREATE TABLE issuance_service.evidence_facts (
            id text PRIMARY KEY, organization_id text NOT NULL, application_id text NOT NULL,
            provider text NOT NULL, requirement_id text, source jsonb, verification jsonb,
            logical_key text NOT NULL, observed_at timestamptz NOT NULL,
            created_at timestamptz NOT NULL)",
        "CREATE TABLE issuance_service.evidence_fact_heads (
            organization_id text NOT NULL, application_id text NOT NULL,
            logical_key text NOT NULL, fact_id text NOT NULL)",
        "CREATE TABLE issuance_service.canvas_evidence_sync_targets (
            id text PRIMARY KEY, organization_id text NOT NULL, platform_id text NOT NULL,
            binding_id text NOT NULL, logical_key text NOT NULL, application_id text,
            config_version integer NOT NULL)",
        "CREATE TABLE issuance_service.canvas_evidence_sync_jobs (
            id text PRIMARY KEY, organization_id text NOT NULL, target_id text NOT NULL,
            status text NOT NULL, result jsonb NOT NULL, created_at timestamptz NOT NULL,
            completed_at timestamptz)",
        "CREATE TABLE issuance_service.canvas_award_candidates (
            id text PRIMARY KEY, organization_id text NOT NULL, application_id text,
            binding_id text NOT NULL, platform_id text NOT NULL, state text NOT NULL)",
    ] {
        sqlx::query(statement).execute(pool).await.unwrap();
    }
}

async fn seed_scope(pool: &sqlx::PgPool) {
    for statement in [
        "INSERT INTO issuance_service.applications VALUES (
            'application-1', 'org-1', 'application-template-1', 'approved', NULL,
            '{\"canvas\":{\"canvas_platform_id\":\"platform-1\",\"canvas_program_binding_id\":\"binding-1\",\"canvas_award_candidate_id\":\"candidate-1\",\"last_lti_state\":\"launch-state-2\"}}'::jsonb)",
        "INSERT INTO issuance_service.canvas_platforms VALUES ('platform-1', 'org-1')",
        "INSERT INTO issuance_service.canvas_program_bindings VALUES (
            'binding-1', 'org-1', 'platform-1', 'application-template-1',
            '[{\"requirement_id\":\"required-score\",\"source\":\"ags_result\",\"fact_type\":\"canvas.assignment_score\",\"scope\":{\"course_id\":\"course-42\",\"resource_id\":\"resource-1\"},\"pass_rule\":{\"min_score_percent\":80},\"required\":true}]'::jsonb, 7)",
        "INSERT INTO issuance_service.evidence_facts VALUES
            ('fact-current', 'org-1', 'application-1', 'canvas', 'required-score',
             '{\"source\":\"ags_result\"}'::jsonb, '{\"status\":\"verified\"}'::jsonb,
             'score', '2026-08-29T16:10:00Z', '2026-08-29T16:10:00Z'),
            ('fact-stale', 'org-1', 'application-1', 'canvas', 'required-score',
             '{\"source\":\"ags_result\"}'::jsonb, '{\"status\":\"unverified\"}'::jsonb,
             'score', '2026-08-29T16:05:00Z', '2026-08-29T16:05:00Z'),
            ('fact-foreign', 'org-other', 'application-1', 'canvas', 'required-score',
             '{\"source\":\"ags_result\"}'::jsonb, '{\"status\":\"verified\"}'::jsonb,
             'score', '2026-08-29T16:20:00Z', '2026-08-29T16:20:00Z')",
        "INSERT INTO issuance_service.evidence_fact_heads VALUES
            ('org-1', 'application-1', 'score', 'fact-current'),
            ('org-other', 'application-1', 'score', 'fact-foreign')",
        "INSERT INTO issuance_service.canvas_evidence_sync_targets VALUES
            ('target-1', 'org-1', 'platform-1', 'binding-1', 'application:application-1', 'application-1', 7),
            ('target-foreign', 'org-other', 'platform-1', 'binding-1', 'application:application-1', 'application-1', 7)",
        "INSERT INTO issuance_service.canvas_evidence_sync_jobs VALUES
            ('job-success', 'org-1', 'target-1', 'succeeded',
             '{\"config_version\":7,\"policy_allowed\":true}'::jsonb,
             '2026-08-29T16:05:00Z', '2026-08-29T16:08:00Z'),
            ('job-latest', 'org-1', 'target-1', 'leased', '{}'::jsonb,
             '2026-08-29T16:20:00Z', NULL),
            ('job-foreign', 'org-other', 'target-1', 'succeeded',
             '{\"config_version\":7,\"policy_allowed\":false}'::jsonb,
             '2026-08-29T16:30:00Z', '2026-08-29T16:31:00Z')",
        "INSERT INTO issuance_service.canvas_award_candidates VALUES
            ('candidate-1', 'org-1', 'application-1', 'binding-1', 'platform-1', 'pending_claim')",
    ] {
        sqlx::query(statement).execute(pool).await.unwrap();
    }
}
