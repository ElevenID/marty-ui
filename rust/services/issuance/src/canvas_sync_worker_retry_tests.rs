//! Fast worker handoff proof only. PostgreSQL owns durable retry timing and fences.

use super::*;
use crate::{
    canvas_oauth::{CanvasOAuthAuthorization, CanvasOAuthPlatform, CanvasOAuthTokenBundle},
    integration_secret::{IntegrationSecretMetadata, NewIntegrationSecret},
};
use std::sync::Mutex;

type FailureCall = (String, String, Option<u64>, bool, String, i32);

struct SpyRepository {
    leased: Mutex<Option<CanvasSyncJob>>,
    target: CanvasSyncTarget,
    expected_job_id: String,
    validation_error: Option<CanvasSyncProcessingError>,
    validation_calls: Mutex<usize>,
    failure_status: CanvasSyncJobStatus,
    failures: Mutex<Vec<FailureCall>>,
    failed_job_ids: Mutex<Vec<String>>,
    heartbeats: Mutex<Vec<(String, usize, bool)>>,
}

#[async_trait]
impl CanvasSyncWorkerRepository for SpyRepository {
    async fn upsert_heartbeat(
        &self,
        heartbeat: &WorkerHeartbeat,
    ) -> Result<(), CanvasSyncRepositoryError> {
        self.heartbeats.lock().unwrap().push((
            heartbeat.phase.into(),
            heartbeat.leased_jobs,
            heartbeat.processor_configured,
        ));
        Ok(())
    }
    async fn enqueue_due(
        &self,
        _: &PythonConfigInteger,
    ) -> Result<usize, CanvasSyncRepositoryError> {
        Ok(0)
    }
    async fn lease_ready(
        &self,
        _: &str,
        _: &PythonConfigInteger,
        _: &PythonConfigInteger,
    ) -> Result<Vec<CanvasSyncJob>, CanvasSyncRepositoryError> {
        Ok(self.leased.lock().unwrap().take().into_iter().collect())
    }
    async fn target(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<CanvasSyncTarget>, CanvasSyncRepositoryError> {
        Ok(Some(self.target.clone()))
    }
    async fn touch_target_heartbeat(
        &self,
        _: &CanvasSyncTarget,
        _: &str,
    ) -> Result<bool, CanvasSyncRepositoryError> {
        Ok(true)
    }
    async fn validate_target(&self, _: &CanvasSyncTarget) -> Result<(), CanvasSyncProcessingError> {
        *self.validation_calls.lock().unwrap() += 1;
        self.validation_error.clone().map_or(Ok(()), Err)
    }
    async fn renew_lease(
        &self,
        _: &CanvasSyncJob,
        _: &str,
        _: &PythonConfigInteger,
    ) -> Result<bool, CanvasSyncRepositoryError> {
        panic!("short processor must not need a renewal")
    }
    async fn complete_job(
        &self,
        _: &CanvasSyncJob,
        _: &str,
        _: i32,
        _: &CanvasSyncResult,
    ) -> Result<bool, CanvasSyncRepositoryError> {
        panic!("rate limit must never complete a job")
    }
    async fn fail_job(
        &self,
        job: &CanvasSyncJob,
        worker_id: &str,
        failure: &JobFailure<'_>,
        version: i32,
    ) -> Result<Option<CanvasSyncJobStatus>, CanvasSyncRepositoryError> {
        self.failures.lock().unwrap().push((
            failure.error_code.to_owned(),
            failure.error_summary.unwrap_or_default().to_owned(),
            failure.retry_after_seconds,
            failure.force_dead_letter,
            worker_id.to_owned(),
            version,
        ));
        assert_eq!(job.id, self.expected_job_id);
        self.failed_job_ids.lock().unwrap().push(job.id.clone());
        Ok(Some(self.failure_status))
    }
}

fn spy_repository(
    job: CanvasSyncJob,
    target: CanvasSyncTarget,
    validation_error: Option<CanvasSyncProcessingError>,
    failure_status: CanvasSyncJobStatus,
) -> Arc<SpyRepository> {
    Arc::new(SpyRepository {
        expected_job_id: job.id.clone(),
        leased: Mutex::new(Some(job)),
        target,
        validation_error,
        validation_calls: Mutex::new(0),
        failure_status,
        failures: Mutex::new(Vec::new()),
        failed_job_ids: Mutex::new(Vec::new()),
        heartbeats: Mutex::new(Vec::new()),
    })
}

fn worker_config(worker_id: &str, organization_id: &str) -> CanvasSyncWorkerConfig {
    let mut config = CanvasSyncWorkerConfig::from_values(&BTreeMap::from([
        ("CANVAS_SYNC_WORKER_ID".into(), worker_id.into()),
        ("CANVAS_PORTABLE_INTEGRATION_ENABLED".into(), "true".into()),
        (
            "CANVAS_PILOT_ORGANIZATION_IDS".into(),
            organization_id.into(),
        ),
    ]))
    .unwrap();
    config.job_timeout = Duration::from_secs(5);
    config
}

struct RateLimitedProcessor(u64);

#[async_trait]
impl CanvasSyncProcessor for RateLimitedProcessor {
    fn configured(&self) -> bool {
        true
    }
    async fn process(
        &self,
        _: &CanvasSyncTarget,
        _: &crate::canvas_sync_lease::CanvasSyncLease,
    ) -> Result<CanvasSyncResult, CanvasSyncProcessingError> {
        Err(CanvasSyncProcessingError::retryable(
            "canvas_rate_limited",
            "Canvas rate limited one or more authoritative evidence reads",
        )
        .with_retry_after(self.0))
    }
}

struct ProcessorMustNotRun;

#[async_trait]
impl CanvasSyncProcessor for ProcessorMustNotRun {
    fn configured(&self) -> bool {
        true
    }

    async fn process(
        &self,
        _: &CanvasSyncTarget,
        _: &crate::canvas_sync_lease::CanvasSyncLease,
    ) -> Result<CanvasSyncResult, CanvasSyncProcessingError> {
        panic!("terminal repository validation must precede processor dispatch")
    }
}

struct TerminalProcessor {
    code: &'static str,
    summary: &'static str,
    calls: Arc<Mutex<usize>>,
}

#[async_trait]
impl CanvasSyncProcessor for TerminalProcessor {
    fn configured(&self) -> bool {
        true
    }

    async fn process(
        &self,
        target: &CanvasSyncTarget,
        lease: &crate::canvas_sync_lease::CanvasSyncLease,
    ) -> Result<CanvasSyncResult, CanvasSyncProcessingError> {
        assert_eq!(target.id, "processor-target");
        assert_eq!(lease.job_id, "processor-job");
        assert_eq!(lease.worker_id, "processor-worker");
        *self.calls.lock().unwrap() += 1;
        Err(CanvasSyncProcessingError::terminal(self.code, self.summary))
    }
}

// No revocation is due in this test; these methods must never be consulted.
struct NoOAuth;

macro_rules! unused_oauth_methods {
    ($(fn $name:ident($($arg:ident: $ty:ty),*) -> $ret:ty;)*) => {
        #[async_trait]
        impl CanvasOAuthRepository for NoOAuth {
            $(async fn $name(&self, $($arg: $ty),*) -> $ret {
                $(let _ = &$arg;)*
                panic!("unexpected OAuth operation: {}", stringify!($name))
            })*
        }
    };
}

unused_oauth_methods! {
        fn management_platform(organization_id: &str, platform_id: &str) -> Result<Option<CanvasOAuthPlatform>, CanvasOAuthError>;
        fn callback_platform(platform_id: &str) -> Result<Option<CanvasOAuthPlatform>, CanvasOAuthError>;
        fn connection(organization_id: &str, platform_id: &str) -> Result<Option<CanvasOAuthConnection>, CanvasOAuthError>;
        fn save_authorization(authorization: &CanvasOAuthAuthorization) -> Result<(), CanvasOAuthError>;
        fn consume_authorization(state_hash: &str, now: DateTime<Utc>) -> Result<Option<CanvasOAuthAuthorization>, CanvasOAuthError>;
        fn patch_platform(organization_id: &str, platform_id: &str, expected_config_version: i64, patch: CanvasOAuthPlatformPatch) -> Result<bool, CanvasOAuthError>;
        fn patch_validation(organization_id: &str, platform_id: &str, expected_config_version: i64, validated_at: Option<DateTime<Utc>>, error_code: Option<&str>) -> Result<bool, CanvasOAuthError>;
        fn publish_connection(connection: &CanvasOAuthConnection) -> Result<Option<DateTime<Utc>>, CanvasOAuthError>;
        fn mark_reauthorization_required(organization_id: &str, platform_id: &str, expected_updated_at: DateTime<Utc>) -> Result<bool, CanvasOAuthError>;
        fn acquire_refresh_lease(organization_id: &str, platform_id: &str, lease_owner: &str, lease_seconds: i64) -> Result<Option<CanvasOAuthConnection>, CanvasOAuthError>;
        fn complete_refresh(organization_id: &str, platform_id: &str, lease_owner: &str, access_token_secret_ref: &str, refresh_token_secret_ref: Option<&str>, token_expires_at: Option<DateTime<Utc>>) -> Result<Option<DateTime<Utc>>, CanvasOAuthError>;
        fn release_refresh_lease(organization_id: &str, platform_id: &str, lease_owner: &str, reauthorization_required: bool) -> Result<bool, CanvasOAuthError>;
        fn patch_validation_error(organization_id: &str, platform_id: &str, expected_config_version: i64, error_code: Option<&str>) -> Result<bool, CanvasOAuthError>;
        fn begin_revocation(organization_id: &str, platform_id: &str, expected_updated_at: DateTime<Utc>, lease_owner: &str, lease_seconds: i64) -> Result<Option<CanvasOAuthConnection>, CanvasOAuthError>;
        fn reschedule_revocation(organization_id: &str, platform_id: &str, lease_owner: &str, retry_at: DateTime<Utc>, error_code: &str) -> Result<bool, CanvasOAuthError>;
        fn complete_revocation(organization_id: &str, platform_id: &str, lease_owner: &str, secret_ids: &[String]) -> Result<bool, CanvasOAuthError>;
}

#[async_trait]
impl CanvasOAuthSecretVault for NoOAuth {
    async fn metadata(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<IntegrationSecretMetadata>, CanvasOAuthError> {
        panic!("unused vault")
    }
    async fn value(&self, _: &str, _: &str) -> Result<Option<String>, CanvasOAuthError> {
        panic!("unused vault")
    }
    async fn save(&self, _: NewIntegrationSecret) -> Result<(), CanvasOAuthError> {
        panic!("unused vault")
    }
    async fn delete(&self, _: &str, _: &str) -> Result<(), CanvasOAuthError> {
        panic!("unused vault")
    }
}

#[async_trait]
impl CanvasOAuthProvider for NoOAuth {
    async fn exchange(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<CanvasOAuthTokenBundle, CanvasOAuthProviderError> {
        panic!("unused provider")
    }
    async fn refresh(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<CanvasOAuthTokenBundle, CanvasOAuthProviderError> {
        panic!("unused provider")
    }
    async fn revoke(&self, _: &str, _: &str) -> Result<(), CanvasOAuthProviderError> {
        panic!("unused provider")
    }
}

#[test]
fn retry_delay_owns_all_normalized_header_shapes_and_backoff_edges() {
    // The provider parser owns the raw header/date shapes; this policy sees
    // only their effective hints. Expected delays are literal, not derived
    // from the production backoff function.
    for (shape, hint, expected) in [
        ("http_date_future", Some(60), 60),
        ("http_date_past", Some(0), 15),
        ("malformed", Some(0), 15),
        ("negative", Some(0), 15),
        ("zero", Some(0), 15),
        ("clamped", Some(86_400), 86_400),
        ("huge_integer", Some(86_400), 86_400),
    ] {
        assert_eq!(job_retry_delay_seconds(1, hint, 0), expected, "{shape}");
    }

    for (attempt, hint, jitter, expected) in [
        (0, None, 0, 15),
        (1, None, u64::MAX, 20),
        (2, None, u64::MAX, 40),
        (3, Some(10), 0, 60),
        (12, None, u64::MAX, 4_800),
        (i32::MAX, None, u64::MAX, 4_800),
        (1, Some(100_000), 0, 86_400),
    ] {
        assert_eq!(
            job_retry_delay_seconds(attempt, hint, jitter),
            expected,
            "attempt={attempt}, hint={hint:?}, jitter={jitter}"
        );
    }
}

#[tokio::test]
async fn retry_hint_reaches_the_actual_worker_failure_port() {
    let now = Utc::now();
    let target = CanvasSyncTarget {
        id: "retry-target".into(),
        organization_id: "retry-org".into(),
        platform_id: "platform".into(),
        binding_id: "binding".into(),
        target_type: CanvasSyncTargetType::LearnerApplication,
        logical_key: "learner".into(),
        application_id: None,
        candidate_id: None,
        enabled: true,
        schedule_seconds: 900,
        config_version: 7,
        metadata: Map::new(),
        created_at: now,
    };
    let job = CanvasSyncJob {
        id: "retry-job".into(),
        organization_id: target.organization_id.clone(),
        target_id: target.id.clone(),
        target_config_version: target.config_version,
        status: CanvasSyncJobStatus::Leased,
        attempt_count: 1,
        max_attempts: 8,
        available_at: now,
        lease_owner: Some("retry-worker".into()),
        lease_expires_at: Some(now + TimeDelta::seconds(120)),
        created_at: now,
        started_at: Some(now),
    };
    for hint in [0, 60, 86_400] {
        let repository = spy_repository(
            job.clone(),
            target.clone(),
            None,
            CanvasSyncJobStatus::Retry,
        );
        let oauth = Arc::new(NoOAuth);
        let config = worker_config("retry-worker", "retry-org");
        let worker = CanvasSyncWorker::new(
            repository.clone(),
            oauth.clone(),
            oauth.clone(),
            oauth,
            Arc::new(RateLimitedProcessor(hint)),
            config,
        );
        let cycle = worker.run_cycle().await.unwrap();
        assert_eq!(
            (
                cycle.leased,
                cycle.retried,
                cycle.succeeded,
                cycle.dead_lettered
            ),
            (1, 1, 0, 0),
            "retry hint {hint}"
        );
        assert_eq!(
            *repository.failures.lock().unwrap(),
            vec![(
                "canvas_rate_limited".into(),
                "Canvas rate limited one or more authoritative evidence reads".into(),
                Some(hint),
                false,
                "retry-worker".into(),
                7,
            )],
            "retry hint {hint}"
        );
        assert_eq!(
            *repository.failed_job_ids.lock().unwrap(),
            ["retry-job"],
            "retry hint {hint}"
        );
    }
}

#[tokio::test]
async fn terminal_validation_errors_reach_actual_worker_dead_letter_port() {
    // This test injects the repository validation result. It proves worker
    // handoff/accounting, not PostgreSQL validation, target disablement, or
    // preserved issued rows and ciphertext; existing adapter/native tests own
    // those boundaries, including the three actual removal races.
    let scenarios: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-validation-scenarios.json"
    ))
    .unwrap();
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-validation-oracle.json"
    ))
    .unwrap();
    let expected = [
        (
            "incomplete_logical_key",
            "canvas_sync_target_incomplete",
            "Canvas sync target is missing logical_key",
        ),
        (
            "prohibited_metadata",
            "canvas_sync_target_contains_secret",
            "Canvas sync target metadata contains prohibited authentication material",
        ),
        (
            "binding_platform_mismatch",
            "canvas_sync_target_scope_invalid",
            "Canvas sync target platform or binding is unavailable",
        ),
        (
            "target_disabled",
            "canvas_sync_target_inactive",
            "Canvas sync target, platform, or binding is inactive",
        ),
        (
            "platform_disabled",
            "canvas_sync_target_inactive",
            "Canvas sync target, platform, or binding is inactive",
        ),
        (
            "platform_archived",
            "canvas_sync_target_inactive",
            "Canvas sync target, platform, or binding is inactive",
        ),
        (
            "binding_disabled",
            "canvas_sync_target_inactive",
            "Canvas sync target, platform, or binding is inactive",
        ),
        (
            "binding_archived",
            "canvas_sync_target_inactive",
            "Canvas sync target, platform, or binding is inactive",
        ),
        (
            "stale_configuration",
            "canvas_sync_target_config_stale",
            "Canvas sync target does not match the active binding configuration",
        ),
        (
            "application_missing",
            "canvas_sync_target_application_missing",
            "Canvas learner synchronization target has no application",
        ),
        (
            "candidate_missing",
            "canvas_sync_target_candidate_missing",
            "Canvas award-candidate synchronization target has no candidate",
        ),
        (
            "application_removed_after_target_read",
            "canvas_sync_target_application_invalid",
            "Canvas learner synchronization application is unavailable",
        ),
        (
            "candidate_removed_after_target_read",
            "canvas_sync_target_candidate_invalid",
            "Canvas award candidate is unavailable",
        ),
    ];
    let registered = scenarios["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["boundary"] != "processor_dispatch")
        .map(|case| case["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(scenarios["cases"].as_array().unwrap().len(), 20);
    assert_eq!(registered.len(), expected.len());
    assert_eq!(
        registered
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        expected
            .iter()
            .map(|(name, _, _)| *name)
            .collect::<std::collections::BTreeSet<_>>()
    );

    let now = Utc::now();
    let target = CanvasSyncTarget {
        id: "validation-target".into(),
        organization_id: "validation-org".into(),
        platform_id: "platform".into(),
        binding_id: "binding".into(),
        target_type: CanvasSyncTargetType::LearnerApplication,
        logical_key: "learner".into(),
        application_id: Some("validation-application".into()),
        candidate_id: None,
        enabled: true,
        schedule_seconds: 900,
        config_version: 7,
        metadata: Map::new(),
        created_at: now,
    };
    let job = CanvasSyncJob {
        id: "validation-job".into(),
        organization_id: target.organization_id.clone(),
        target_id: target.id.clone(),
        target_config_version: target.config_version,
        status: CanvasSyncJobStatus::Leased,
        attempt_count: 1,
        max_attempts: 8,
        available_at: now,
        lease_owner: Some("validation-worker".into()),
        lease_expires_at: Some(now + TimeDelta::seconds(120)),
        created_at: now,
        started_at: Some(now),
    };
    for (name, code, summary) in expected {
        let scenario = scenarios["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == name)
            .unwrap();
        let frozen = &oracle[name]["observations"][0]["jobs"][0];
        assert_eq!(scenario["code"], code, "{name}");
        assert_eq!(frozen["last_error_code"], code, "{name}");
        assert_eq!(frozen["last_error_summary"], summary, "{name}");
        assert_eq!(frozen["status"], "dead_letter", "{name}");
        let repository = spy_repository(
            job.clone(),
            target.clone(),
            Some(CanvasSyncProcessingError::terminal(code, summary)),
            CanvasSyncJobStatus::DeadLetter,
        );
        let oauth = Arc::new(NoOAuth);
        let worker = CanvasSyncWorker::new(
            repository.clone(),
            oauth.clone(),
            oauth.clone(),
            oauth,
            Arc::new(ProcessorMustNotRun),
            worker_config("validation-worker", "validation-org"),
        );
        let cycle = worker.run_cycle().await.unwrap();
        assert_eq!(
            (
                cycle.leased,
                cycle.retried,
                cycle.succeeded,
                cycle.dead_lettered
            ),
            (1, 0, 0, 1),
            "{name}"
        );
        assert_eq!(
            *repository.failures.lock().unwrap(),
            vec![(
                code.into(),
                summary.into(),
                None,
                true,
                "validation-worker".into(),
                7,
            )],
            "{name}"
        );
        assert_eq!(
            *repository.failed_job_ids.lock().unwrap(),
            ["validation-job"]
        );
        assert_eq!(
            *repository.heartbeats.lock().unwrap(),
            [
                ("scheduling".into(), 0, true),
                ("processing".into(), 1, true),
                ("idle".into(), 0, true),
            ],
            "{name}"
        );
    }
}

#[tokio::test]
async fn terminal_processor_errors_reach_actual_worker_dead_letter_port() {
    // The seven codes and summaries below are independent handoff expectations.
    // The real processor test owns dispatch/classification; this test injects
    // its terminal result and proves only the actual worker's port/accounting.
    // Published PostgreSQL and native replay retain durable/race authority.
    let scenarios: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-validation-scenarios.json"
    ))
    .unwrap();
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-validation-oracle.json"
    ))
    .unwrap();
    let expected = [
        (
            "invalid_roster_batch",
            "canvas_roster_configuration_invalid",
            "Canvas roster bounds are invalid",
        ),
        (
            "invalid_roster_limit",
            "canvas_roster_configuration_invalid",
            "Canvas roster bounds are invalid",
        ),
        (
            "invalid_roster_bounds_do_not_preempt_application",
            "canvas_lti_identity_missing",
            "Canvas application has no verified LTI subject",
        ),
        (
            "invalid_evidence_requirements",
            "canvas_requirements_invalid",
            "Canvas evidence requirements are invalid",
        ),
        (
            "missing_lti_subject",
            "canvas_lti_identity_missing",
            "Canvas application has no verified LTI subject",
        ),
        (
            "unsupported_award_candidate",
            "canvas_sync_target_type_unsupported",
            "Canvas target type has no authoritative processor",
        ),
        (
            "template_removed_after_application_read",
            "canvas_application_template_unavailable",
            "Canvas application template is unavailable",
        ),
    ];
    let registered = scenarios["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["boundary"] == "processor_dispatch")
        .map(|case| case["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(scenarios["cases"].as_array().unwrap().len(), 20);
    assert_eq!(registered.len(), expected.len());
    assert_eq!(
        registered
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        expected
            .iter()
            .map(|(name, _, _)| *name)
            .collect::<std::collections::BTreeSet<_>>()
    );

    let now = Utc::now();
    let target = CanvasSyncTarget {
        id: "processor-target".into(),
        organization_id: "processor-org".into(),
        platform_id: "platform".into(),
        binding_id: "binding".into(),
        target_type: CanvasSyncTargetType::LearnerApplication,
        logical_key: "learner".into(),
        application_id: Some("processor-application".into()),
        candidate_id: None,
        enabled: true,
        schedule_seconds: 900,
        config_version: 11,
        metadata: Map::new(),
        created_at: now,
    };
    let job = CanvasSyncJob {
        id: "processor-job".into(),
        organization_id: target.organization_id.clone(),
        target_id: target.id.clone(),
        target_config_version: target.config_version,
        status: CanvasSyncJobStatus::Leased,
        attempt_count: 1,
        max_attempts: 8,
        available_at: now,
        lease_owner: Some("processor-worker".into()),
        lease_expires_at: Some(now + TimeDelta::seconds(120)),
        created_at: now,
        started_at: Some(now),
    };
    for (name, code, summary) in expected {
        let scenario = scenarios["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == name)
            .unwrap();
        let frozen = &oracle[name]["observations"][0]["jobs"][0];
        assert_eq!(scenario["code"], code, "{name}");
        assert_eq!(frozen["last_error_code"], code, "{name}");
        assert_eq!(frozen["last_error_summary"], summary, "{name}");
        assert_eq!(frozen["status"], "dead_letter", "{name}");
        let repository = spy_repository(
            job.clone(),
            target.clone(),
            None,
            CanvasSyncJobStatus::DeadLetter,
        );
        let calls = Arc::new(Mutex::new(0));
        let oauth = Arc::new(NoOAuth);
        let worker = CanvasSyncWorker::new(
            repository.clone(),
            oauth.clone(),
            oauth.clone(),
            oauth,
            Arc::new(TerminalProcessor {
                code,
                summary,
                calls: calls.clone(),
            }),
            worker_config("processor-worker", "processor-org"),
        );
        let cycle = worker.run_cycle().await.unwrap();
        assert_eq!(*repository.validation_calls.lock().unwrap(), 1, "{name}");
        assert_eq!(*calls.lock().unwrap(), 1, "{name}");
        assert_eq!(
            (
                cycle.scheduled,
                cycle.leased,
                cycle.retried,
                cycle.succeeded,
                cycle.dead_lettered,
                cycle.oauth_revocations_succeeded,
                cycle.oauth_revocations_retried,
            ),
            (0, 1, 0, 0, 1, 0, 0),
            "{name}"
        );
        assert_eq!(
            *repository.failures.lock().unwrap(),
            vec![(
                code.into(),
                summary.into(),
                None,
                true,
                "processor-worker".into(),
                11,
            )],
            "{name}"
        );
        assert_eq!(
            *repository.failed_job_ids.lock().unwrap(),
            ["processor-job"]
        );
        assert_eq!(
            *repository.heartbeats.lock().unwrap(),
            [
                ("scheduling".into(), 0, true),
                ("processing".into(), 1, true),
                ("idle".into(), 0, true),
            ],
            "{name}"
        );
    }
}
