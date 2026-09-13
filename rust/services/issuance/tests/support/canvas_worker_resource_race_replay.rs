//! Resource changes during real provider I/O; reuse process/HTTPS/fence owners.
use super::{
    canvas_worker_process_signals::OwnedWorker,
    canvas_worker_provider_signals_replay::{
        assert_leased_state, await_marker, control_directory, mark, snapshot,
    },
    canvas_worker_rest_replay::{prepare, worker_environment},
};
use serde_json::Value;
use sqlx::PgPool;
use std::{sync::OnceLock, time::Duration};

fn scenarios() -> &'static Value {
    static SCENARIOS: OnceLock<Value> = OnceLock::new();
    SCENARIOS.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-resource-race-scenarios.json"
        ))
        .unwrap()
    })
}

fn reference() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-resource-race-oracle.json"
    ))
    .unwrap()
}

async fn scalar(pool: &PgPool, query: &'static str) -> Value {
    sqlx::query_scalar(query).fetch_one(pool).await.unwrap()
}

pub async fn replay(pool: &PgPool, database_url: &str, origin: &str, name: &str) {
    let matrix = scenarios();
    let matches = matrix["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["name"] == name)
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "unknown or duplicate resource-race case");
    let case = matches[0];
    let references = reference();
    let expected = &references[name];
    assert_eq!(expected["case"], name);
    let fixture = prepare(pool, origin, "retry").await;
    let control = control_directory();
    let mut worker = OwnedWorker::start_with_environment(
        database_url,
        "worker-rest",
        &worker_environment(origin),
    );
    await_marker(&control, "request-received", &mut worker).await;
    let before = snapshot(pool, &fixture).await;
    assert_leased_state(before, &expected["before"], 1);
    let original = scalar(pool, matrix["job_row_sql"].as_str().unwrap()).await;
    let mut transaction = pool.begin().await.unwrap();
    for statement in case["mutation"].as_array().unwrap() {
        assert_eq!(
            sqlx::raw_sql(statement.as_str().unwrap())
                .execute(&mut *transaction)
                .await
                .unwrap()
                .rows_affected(),
            1
        );
    }
    transaction.commit().await.unwrap();
    assert_eq!(
        scalar(pool, matrix["resource_sql"].as_str().unwrap()).await,
        expected["changed_resources"]
    );
    assert_eq!(
        scalar(pool, matrix["job_row_sql"].as_str().unwrap()).await,
        original
    );
    mark(&control, "release-response");
    let after = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            assert!(
                worker.0.try_wait().unwrap().is_none(),
                "resource-race worker exited early"
            );
            let state = snapshot(pool, &fixture).await;
            if state["heartbeat"]["metadata"]["phase"] == "idle"
                && matches!(
                    state["jobs"][0]["status"].as_str(),
                    Some("retry" | "dead_letter")
                )
            {
                break state;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("resource-race worker must reach its real durable outcome");
    assert_eq!(
        after, expected["after"],
        "complete resource-race state: {name}"
    );
    let resources = scalar(pool, matrix["resource_sql"].as_str().unwrap()).await;
    assert_eq!(resources, expected["final_resources"]);
    let terminal = scalar(pool, matrix["job_row_sql"].as_str().unwrap()).await;
    assert_eq!(terminal["id"], original["id"]);
    assert_eq!(expected["same_job"], true);
    worker.signal("SIGINT");
    assert_eq!(worker.wait().await.code(), Some(130));
    assert_eq!(expected["exit_code_after_interrupt"], -2);
    assert_eq!(snapshot(pool, &fixture).await, after);
    assert_eq!(
        scalar(pool, matrix["job_row_sql"].as_str().unwrap()).await,
        terminal
    );
    assert_eq!(
        scalar(pool, matrix["resource_sql"].as_str().unwrap()).await,
        resources
    );
    assert_eq!(expected["unchanged_after_exit"], true);
}

pub async fn assert_repository_errors(pool: &PgPool, name: &str) {
    use marty_issuance_service::{
        canvas_sync_lease::CanvasSyncLease, canvas_sync_processor::CanvasSyncProcessorRepository,
        canvas_sync_processor_postgres::PostgresCanvasSyncProcessorRepository,
        canvas_sync_worker::CanvasSyncWorkerRepository,
        canvas_sync_worker_postgres::PostgresCanvasSyncWorkerRepository,
    };
    use std::sync::Arc;
    let fixture = prepare(pool, "https://127.0.0.1:1", "retry").await;
    let queue = PostgresCanvasSyncWorkerRepository::new(pool.clone());
    sqlx::query("INSERT INTO issuance_service.canvas_evidence_sync_jobs (id,organization_id,target_id) VALUES ('resource-repository-job','org-review','target-review')")
        .execute(pool).await.unwrap();
    let jobs = queue
        .lease_ready("resource-repository", &1_u64.into(), &120_u64.into())
        .await
        .unwrap();
    assert_eq!(jobs.len(), 1);
    let target = queue
        .target("org-review", "target-review")
        .await
        .unwrap()
        .unwrap();
    let mut captured_job = jobs[0].clone();
    // Corrupt only the captured identity, never the durable job or its clock.
    // Construction still requires an internally consistent typed lease, whose
    // owner/attempt must then be rejected against the real current database row.
    let (resource_case, invalid_lease) = if let Some(case) = name.strip_suffix("_wrong_owner") {
        captured_job.lease_owner = Some("another-resource-worker".into());
        (case, true)
    } else if let Some(case) = name.strip_suffix("_wrong_attempt") {
        captured_job.attempt_count += 1;
        (case, true)
    } else {
        (name, false)
    };
    let lease =
        CanvasSyncLease::from_job(&captured_job, captured_job.lease_owner.as_deref().unwrap())
            .unwrap();
    let repository =
        Arc::new(PostgresCanvasSyncProcessorRepository::new(pool.clone())).for_lease(lease);
    let resources = repository.resources(&target).await.unwrap().unwrap();
    let matrix = scenarios();
    let references = reference();
    let original_job = scalar(pool, matrix["job_row_sql"].as_str().unwrap()).await;
    let statements = if let Some(case) = matrix["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == resource_case)
    {
        case["mutation"]
            .as_array()
            .unwrap()
            .iter()
            .map(|sql| sql.as_str().unwrap())
            .collect::<Vec<_>>()
    } else {
        vec![match resource_case {
            "application_status_changed" => "UPDATE issuance_service.applications SET status='rejected' WHERE id='application-review' AND organization_id='org-review'",
            "application_context_changed" => "UPDATE issuance_service.applications SET integration_context=integration_context::jsonb||'{\"synthetic_new_context\":true}'::jsonb WHERE id='application-review' AND organization_id='org-review'",
            "target_reconfigured" => "UPDATE issuance_service.canvas_evidence_sync_targets SET config_version=config_version+1 WHERE id='target-review' AND organization_id='org-review'",
            // Model an already revalidated active binding, as in the published
            // provider-generation fixture. Preserve the activation constraint
            // and enabled state so the only scope failure is its new version.
            "binding_reconfigured" => "UPDATE issuance_service.canvas_program_bindings SET config_version=2,validated_config_version=2 WHERE id='binding-review' AND organization_id='org-review' AND config_version=1 AND validated_config_version=1",
            _ => panic!("unknown repository resource case"),
        }]
    };
    let mut transaction = pool.begin().await.unwrap();
    for statement in statements {
        assert_eq!(
            sqlx::raw_sql(statement)
                .execute(&mut *transaction)
                .await
                .unwrap()
                .rows_affected(),
            1
        );
    }
    transaction.commit().await.unwrap();
    assert_eq!(
        scalar(pool, matrix["job_row_sql"].as_str().unwrap()).await,
        original_job,
        "resource fixture changed the durable lease: {name}"
    );
    const PROTECTED_SQL: &str = "SELECT jsonb_build_object('platform',(SELECT to_jsonb(p) FROM issuance_service.canvas_platforms p WHERE id='platform-review'),'binding',(SELECT to_jsonb(b) FROM issuance_service.canvas_program_bindings b WHERE id='binding-review'),'application',(SELECT to_jsonb(a) FROM issuance_service.applications a WHERE id='application-review'),'target',(SELECT to_jsonb(t) FROM issuance_service.canvas_evidence_sync_targets t WHERE id='target-review'),'job',(SELECT to_jsonb(j) FROM issuance_service.canvas_evidence_sync_jobs j WHERE id='resource-repository-job'))";
    let protected = scalar(pool, PROTECTED_SQL).await;
    if matches!(
        resource_case,
        "target_reconfigured" | "binding_reconfigured"
    ) {
        assert_eq!(
            protected["platform"]["config_version"], resources.platform.config_version,
            "scope-only edit must not change the platform version"
        );
    }
    if resource_case == "binding_reconfigured" {
        assert_eq!(protected["binding"]["config_version"], 2);
        assert_eq!(protected["binding"]["validated_config_version"], 2);
        assert_eq!(protected["binding"]["enabled"], true);
        assert_eq!(protected["target"]["config_version"], target.config_version);
    }
    let result = if matches!(
        resource_case,
        "platform_reconfigured" | "target_reconfigured" | "binding_reconfigured"
    ) {
        repository
            .patch_platform_validation(&target, &resources, None)
            .await
    } else {
        repository
            .patch_application_sync(&target, &resources, &[], false)
            .await
    };
    let error = result.unwrap_err();
    if invalid_lease {
        assert_eq!(error.code, "canvas_sync_lease_lost", "{name}");
        assert_eq!(
            error.summary, "Canvas synchronization no longer owns its job lease",
            "{name}"
        );
        assert!(error.retryable, "lease loss must take precedence: {name}");
    } else if let Some(expected) = references.get(resource_case) {
        let job = &expected["after"]["jobs"][0];
        assert_eq!(error.code, job["last_error_code"], "{name}");
        assert_eq!(error.summary, job["last_error_summary"], "{name}");
        assert_eq!(error.retryable, job["status"] == "retry", "{name}");
    } else {
        assert_eq!(error.code, "canvas_platform_reconfigured", "{name}");
        assert_eq!(
            error.summary,
            "Canvas target, platform, binding, or application changed during synchronization",
            "{name}"
        );
        assert!(
            error.retryable,
            "changed resource must not become missing/terminal: {name}"
        );
    }
    assert_eq!(
        scalar(pool, PROTECTED_SQL).await,
        protected,
        "stale patch changed a protected resource or durable job: {name}"
    );
    fixture.assert_preserved(pool).await;
}
