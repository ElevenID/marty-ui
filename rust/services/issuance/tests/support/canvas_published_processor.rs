//! Real native processor and repositories on the published schema. Only the
//! authoritative provider is controlled; this does not qualify its HTTP adapter.
use async_trait::async_trait;
use marty_issuance_service::{
    canvas_sync_lease::CanvasSyncLease,
    canvas_sync_processor::{
        CanvasAuthoritativeObservation, CanvasAuthoritativeProvider, CanvasProviderReadError,
        CanvasRosterSnapshot, CanvasSyncResources, NativeCanvasSyncProcessor,
    },
    canvas_sync_processor_postgres::PostgresCanvasSyncProcessorRepository,
    canvas_sync_worker::{
        CanvasSyncProcessingError, CanvasSyncProcessor, CanvasSyncResult, CanvasSyncTarget,
        CanvasSyncWorkerConfig, CanvasSyncWorkerRepository,
    },
    canvas_sync_worker_postgres::PostgresCanvasSyncWorkerRepository,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU8, AtomicUsize, Ordering},
        Arc,
    },
};

pub const WORKER: &str = "published-schema-worker";

struct Provider {
    pool: PgPool,
    phase: AtomicU8,
    calls: AtomicUsize,
}

#[async_trait]
impl CanvasAuthoritativeProvider for Provider {
    async fn read_requirement(
        &self,
        _: &CanvasSyncResources,
        requirement: &Value,
        user: Option<&str>,
        subject: Option<&str>,
    ) -> Result<CanvasAuthoritativeObservation, CanvasProviderReadError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert!(user.is_some() || subject.is_some());
        let phase = self.phase.load(Ordering::SeqCst);
        if phase == 2 {
            return Err(CanvasProviderReadError::Unavailable);
        }
        if phase == 3 {
            return Err(CanvasProviderReadError::ReauthorizationRequired);
        }
        if phase == 4 {
            return Err(CanvasProviderReadError::RateLimited {
                retry_after_seconds: 37,
            });
        }
        if phase == 5 {
            // A legitimate application update after the resource snapshot must
            // still prevent the old snapshot from committing a new fact.
            sqlx::query("UPDATE issuance_service.applications SET integration_context = integration_context::jsonb || '{\"edited\":true}'::jsonb WHERE id='application-published'")
                .execute(&self.pool).await.unwrap();
        }
        let assertion = if requirement["fact_type"]
            .as_str()
            .unwrap()
            .ends_with("_score")
        {
            json!({"score_percent": if phase == 0 { 90 } else { 10 }})
        } else {
            json!({"completed": phase == 0})
        };
        Ok(CanvasAuthoritativeObservation {
            assertion: assertion.as_object().unwrap().clone(),
            source_payload: json!({"synthetic": true, "phase": phase})
                .as_object()
                .unwrap()
                .clone(),
            verification_method: "canvas_rest",
            effective_at: None,
        })
    }

    async fn roster(
        &self,
        _: &CanvasSyncTarget,
        _: &CanvasSyncResources,
        _: &[Value],
        limit: usize,
    ) -> Result<CanvasRosterSnapshot, CanvasProviderReadError> {
        assert_eq!(limit, 10);
        Ok(CanvasRosterSnapshot {
            canvas_user_ids: vec!["7".into(), "8".into(), "7".into()],
            ..Default::default()
        })
    }
}

fn requirements() -> Value {
    json!([
        {"requirement_id":"assignment", "source":"canvas_rest", "fact_type":"canvas.assignment_score", "scope":{"course_id":"42","activity_id":"9"}, "pass_rule":{"min_score_percent":80}, "required":true},
        {"requirement_id":"quiz", "source":"canvas_rest", "fact_type":"canvas.quiz_score", "scope":{"course_id":"42","activity_id":"10"}, "pass_rule":{"min_score_percent":80}, "required":true},
        {"requirement_id":"module", "source":"canvas_rest", "fact_type":"canvas.module_completion", "scope":{"course_id":"42","module_id":"3"}, "pass_rule":{"completed":true}, "required":true},
        {"requirement_id":"course", "source":"canvas_rest", "fact_type":"canvas.course_completion", "scope":{"course_id":"42"}, "pass_rule":{"completed":true}, "required":true}
    ])
}

async fn seed(pool: &PgPool) {
    // Data only: never replace or relax the published DDL/defaults/constraints.
    for statement in [
        "INSERT INTO organization_service.organizations (id,name,slug) VALUES ('org-published','Synthetic','synthetic')",
        "INSERT INTO issuance_service.application_templates
         (id,organization_id,name,credential_template_id,form_fields,evidence_requirements,
          claim_collection_rules,approval_strategy,application_validity_days,
          ui_config,notification_config,status,created_at,updated_at)
         VALUES ('template-published','org-published','Synthetic','credential-template',
          '[]','[]','[]','MANUAL',30,'{}','{}','ACTIVE',now(),now())",
        "INSERT INTO issuance_service.canvas_platforms
         (id,organization_id,canvas_account_id,canvas_base_url,lti_deployment_id,enabled)
         VALUES ('platform-published','org-published','account','https://canvas.example.edu','deployment',true)",
        "INSERT INTO issuance_service.applications
         (id,organization_id,application_template_id,applicant_identifier,form_data,
          submitted_evidence,status,derived_claims,integration_context,created_at,updated_at)
         VALUES ('application-published','org-published','template-published','synthetic-subject',
          '{}','[]','PENDING','{}',
          '{\"canvas\":{\"lti_subject\":\"subject-7\",\"canvas_platform_id\":\"platform-published\",\"canvas_program_binding_id\":\"binding-published\"}}',now(),now())",
        "INSERT INTO issuance_service.canvas_learner_identities
         (id,organization_id,platform_id,deployment_id,lti_subject,canvas_user_id)
         VALUES ('identity-published','org-published','platform-published','deployment','subject-7','7')",
    ] { sqlx::query(statement).execute(pool).await.unwrap(); }
    sqlx::query(
        "INSERT INTO issuance_service.canvas_program_bindings
        (id,organization_id,platform_id,application_template_id,credential_template_id,
         evidence_requirements,enabled,validated_config_version,activated_at)
        VALUES ('binding-published','org-published','platform-published','template-published',
         'credential-template',$1,true,1,now())",
    )
    .bind(requirements())
    .execute(pool)
    .await
    .unwrap();
    for (id, kind, application) in [
        ("roster", "background_roster", None),
        (
            "learner",
            "learner_application",
            Some("application-published"),
        ),
        ("drift", "issued_drift", Some("application-published")),
        ("unsupported", "award_candidate", None),
    ] {
        sqlx::query(
            "INSERT INTO issuance_service.canvas_evidence_sync_targets
            (id,organization_id,platform_id,binding_id,target_type,logical_key,application_id)
            VALUES ($1,'org-published','platform-published','binding-published',$2,$1,$3)",
        )
        .bind(id)
        .bind(kind)
        .bind(application)
        .execute(pool)
        .await
        .unwrap();
    }
}

async fn run(
    pool: &PgPool,
    processor: &NativeCanvasSyncProcessor,
    id: &str,
) -> Result<CanvasSyncResult, CanvasSyncProcessingError> {
    run_for_organization(pool, processor, id, "org-published").await
}

pub async fn run_for_organization(
    pool: &PgPool,
    processor: &NativeCanvasSyncProcessor,
    id: &str,
    organization: &str,
) -> Result<CanvasSyncResult, CanvasSyncProcessingError> {
    let repository = PostgresCanvasSyncWorkerRepository::new(pool.clone());
    sqlx::query(
        "INSERT INTO issuance_service.canvas_evidence_sync_jobs
        (id,organization_id,target_id) VALUES ($1,$3,$2)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(id)
    .bind(organization)
    .execute(pool)
    .await
    .unwrap();
    let jobs = repository
        .lease_ready(WORKER, &1_u64.into(), &120_u64.into())
        .await
        .unwrap();
    assert_eq!(jobs.len(), 1);
    let job = &jobs[0];
    assert_eq!(job.target_id, id);
    let target = repository.target(organization, id).await.unwrap().unwrap();
    repository.validate_target(&target).await.unwrap();
    let lease = CanvasSyncLease::from_job(job, WORKER).unwrap();
    let result = processor.process(&target, &lease).await;
    match &result {
        Ok(value) => assert!(repository
            .complete_job(job, WORKER, target.config_version, value)
            .await
            .unwrap()),
        Err(error) => {
            // Use the real retry/dead-letter policy. Cancel only a resulting
            // retry between independent scenarios, without disabling its target.
            use marty_issuance_service::canvas_sync_worker::JobFailure;
            assert!(repository
                .fail_job(
                    job,
                    WORKER,
                    &JobFailure {
                        error_code: error.code,
                        error_summary: Some(error.summary),
                        retry_after_seconds: error.retry_after_seconds,
                        force_dead_letter: !error.retryable,
                    },
                    target.config_version
                )
                .await
                .unwrap()
                .is_some());
            sqlx::query("UPDATE issuance_service.canvas_evidence_sync_jobs SET status='cancelled', completed_at=clock_timestamp() WHERE id=$1 AND status='retry'")
                .bind(&job.id).execute(pool).await.unwrap();
        }
    }
    result
}

fn field(result: &CanvasSyncResult, key: &str, expected: &str) {
    assert_eq!(
        result.get(key).map(|value| value.get()),
        Some(expected),
        "{key}"
    );
}

async fn scalar(pool: &PgPool, query: &'static str) -> Value {
    sqlx::query_scalar(query).fetch_one(pool).await.unwrap()
}

pub async fn exercise(pool: &PgPool) {
    seed(pool).await;
    let provider = Arc::new(Provider {
        pool: pool.clone(),
        phase: AtomicU8::new(0),
        calls: AtomicUsize::new(0),
    });
    let config = CanvasSyncWorkerConfig::from_values(&BTreeMap::from([
        ("CANVAS_SYNC_WORKER_ID".into(), WORKER.into()),
        ("CANVAS_PORTABLE_INTEGRATION_ENABLED".into(), "true".into()),
        (
            "CANVAS_PILOT_ORGANIZATION_IDS".into(),
            "org-published".into(),
        ),
    ]))
    .unwrap();
    let processor = NativeCanvasSyncProcessor::new(
        Arc::new(PostgresCanvasSyncProcessorRepository::new(pool.clone())),
        provider.clone(),
        config,
        1,
        10,
    );
    for cursor in [1, 0] {
        let result = run(pool, &processor, "roster").await.unwrap();
        field(&result, "candidates_seen", "1");
        field(&result, "observations_written", "4");
        field(&result, "pending_claim", "1");
        assert_eq!(scalar(pool,"SELECT metadata::jsonb->'roster_cursor' FROM issuance_service.canvas_evidence_sync_targets WHERE id='roster'").await,json!(cursor));
    }
    sqlx::query("UPDATE issuance_service.canvas_award_candidates SET state='claimed' WHERE canvas_user_id='7'").execute(pool).await.unwrap();
    let repeated = run(pool, &processor, "roster").await.unwrap();
    field(&repeated, "observations_written", "0");
    field(&repeated, "pending_claim", "0");
    assert_eq!(scalar(pool,"SELECT to_jsonb(state) FROM issuance_service.canvas_award_candidates WHERE canvas_user_id='7'").await,json!("claimed"));
    provider.phase.store(1, Ordering::SeqCst);
    field(
        &run(pool, &processor, "roster").await.unwrap(),
        "observations_written",
        "4",
    );
    let observations = scalar(pool,"SELECT jsonb_agg(to_jsonb(o) ORDER BY id) FROM issuance_service.canvas_candidate_observations o").await;
    assert_eq!(observations.as_array().unwrap().len(), 12);
    let current: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM issuance_service.canvas_candidate_observations WHERE is_current",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(current, 8);
    provider.phase.store(2, Ordering::SeqCst);
    field(
        &run(pool, &processor, "roster").await.unwrap(),
        "observations_written",
        "0",
    );
    assert_eq!(scalar(pool,"SELECT jsonb_agg(to_jsonb(o) ORDER BY id) FROM issuance_service.canvas_candidate_observations o").await,observations);

    provider.phase.store(0, Ordering::SeqCst);
    let learner = run(pool, &processor, "learner").await.unwrap();
    field(&learner, "requirements_checked", "4");
    field(&learner, "facts_created", "4");
    field(&learner, "policy_allowed", "true");
    let again = run(pool, &processor, "learner").await.unwrap();
    field(&again, "facts_created", "0");
    field(&again, "facts_reused", "4");
    provider.phase.store(1, Ordering::SeqCst);
    let negative = run(pool, &processor, "learner").await.unwrap();
    field(&negative, "facts_created", "4");
    field(&negative, "policy_allowed", "false");
    let facts = scalar(
        pool,
        "SELECT jsonb_agg(to_jsonb(f) ORDER BY id) FROM issuance_service.evidence_facts f",
    )
    .await;
    let heads = scalar(pool,"SELECT jsonb_agg(to_jsonb(h) ORDER BY logical_key) FROM issuance_service.evidence_fact_heads h").await;
    assert_eq!(facts.as_array().unwrap().len(), 8);
    assert_eq!(heads.as_array().unwrap().len(), 4);
    for (phase, code) in [
        (2, "canvas_authoritative_reads_failed"),
        (3, "canvas_authoritative_reads_failed"),
        (4, "canvas_rate_limited"),
    ] {
        provider.phase.store(phase, Ordering::SeqCst);
        let error = run(pool, &processor, "learner").await.unwrap_err();
        assert_eq!(error.code, code);
        assert!(error.retryable);
        assert_eq!(
            error.retry_after_seconds,
            if phase == 4 { Some(37) } else { None }
        );
        assert_eq!(
            scalar(
                pool,
                "SELECT jsonb_agg(to_jsonb(f) ORDER BY id) FROM issuance_service.evidence_facts f"
            )
            .await,
            facts
        );
        assert_eq!(scalar(pool,"SELECT jsonb_agg(to_jsonb(h) ORDER BY logical_key) FROM issuance_service.evidence_fact_heads h").await,heads);
        let validation = scalar(pool,"SELECT to_jsonb(last_connection_error) FROM issuance_service.canvas_platforms WHERE id='platform-published'").await;
        assert_eq!(
            validation,
            json!(if phase == 3 {
                "oauth_reauthorization_required"
            } else {
                "canvas_authoritative_reads_failed"
            })
        );
    }
    provider.phase.store(5, Ordering::SeqCst);
    let rejected = run(pool, &processor, "learner").await.unwrap_err();
    assert_eq!(rejected.code, "canvas_sync_repository_unavailable");
    assert_eq!(
        scalar(
            pool,
            "SELECT jsonb_agg(to_jsonb(f) ORDER BY id) FROM issuance_service.evidence_facts f"
        )
        .await,
        facts
    );
    assert_eq!(scalar(pool,"SELECT jsonb_agg(to_jsonb(h) ORDER BY logical_key) FROM issuance_service.evidence_fact_heads h").await, heads);
    let calls = provider.calls.load(Ordering::SeqCst);
    sqlx::query("UPDATE issuance_service.canvas_evidence_sync_targets SET metadata='{\"drift_until\":\"2000-01-01T00:00:00Z\"}' WHERE id='drift'").execute(pool).await.unwrap();
    field(
        &run(pool, &processor, "drift").await.unwrap(),
        "no_change",
        "true",
    );
    assert_eq!(scalar(pool,"SELECT to_jsonb(enabled) FROM issuance_service.canvas_evidence_sync_targets WHERE id='drift'").await,json!(false));
    sqlx::query("UPDATE issuance_service.canvas_evidence_sync_targets SET candidate_id=(SELECT id FROM issuance_service.canvas_award_candidates WHERE canvas_user_id='7') WHERE id='unsupported'")
        .execute(pool).await.unwrap();
    let unsupported = run(pool, &processor, "unsupported").await.unwrap_err();
    assert_eq!(unsupported.code, "canvas_sync_target_type_unsupported");
    assert!(!unsupported.retryable);
    assert_eq!(provider.calls.load(Ordering::SeqCst), calls);
    // Reconciliation is unsigned: it never issues credentials or changes approval.
    assert_eq!(
        scalar(
            pool,
            "SELECT to_jsonb(count(*)) FROM issuance_service.issued_credentials"
        )
        .await,
        json!(0)
    );
    assert_eq!(scalar(pool,"SELECT to_jsonb(status) FROM issuance_service.applications WHERE id='application-published'").await,json!("PENDING"));
}
