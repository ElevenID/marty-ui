//! Actual handler/port orchestration, not SQL fencing or durable-state emulation.
//! All sixty PostgreSQL combinations and historical cutover gates remain required.

use super::*;
use crate::canvas_sync_lease::CanvasSyncLease;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Poll;
use tokio::{
    sync::Semaphore,
    time::{advance, Instant},
};

pub(super) struct RenewalScript {
    stage: String,
    expected_lease: CanvasSyncLease,
    version: i32,
    secondary_error: bool,
    events: Mutex<Vec<&'static str>>,
    renewals: AtomicUsize,
    active: AtomicBool,
    cleaned: AtomicUsize,
}

impl RenewalScript {
    fn record(&self, event: &'static str) {
        self.events.lock().unwrap().push(event);
    }

    fn assert_identity(&self, job: &CanvasSyncJob, worker: &str) {
        assert_eq!(
            CanvasSyncLease::from_job(job, worker).unwrap(),
            self.expected_lease
        );
        assert_eq!(job.target_config_version, self.version);
    }

    pub(super) fn target(&self, organization: &str, target: &str) {
        assert_eq!(organization, self.expected_lease.organization_id);
        assert_eq!(target, self.expected_lease.target_id);
        self.record("target");
    }

    pub(super) fn validate(&self, target: &CanvasSyncTarget) {
        assert_eq!(target.id, self.expected_lease.target_id);
        assert_eq!(target.organization_id, self.expected_lease.organization_id);
        assert_eq!(target.config_version, self.version);
        self.record("validate");
    }

    pub(super) fn touch(
        &self,
        target: &CanvasSyncTarget,
        worker: &str,
    ) -> Result<bool, CanvasSyncRepositoryError> {
        assert_eq!(target.id, self.expected_lease.target_id);
        assert_eq!(target.organization_id, self.expected_lease.organization_id);
        assert_eq!(target.config_version, self.version);
        assert_eq!(worker, self.expected_lease.worker_id);
        if self.renewals.load(Ordering::SeqCst) == 0 {
            self.record("initial_target_heartbeat");
        } else {
            self.record("renewal_target_heartbeat");
            if self.stage == "target" {
                return Err(CanvasSyncRepositoryError::Unavailable);
            }
        }
        Ok(true)
    }

    pub(super) fn heartbeat(
        &self,
        heartbeat: &WorkerHeartbeat,
    ) -> Result<(), CanvasSyncRepositoryError> {
        assert_eq!(heartbeat.worker_id, self.expected_lease.worker_id);
        if heartbeat.phase == "processing" && self.renewals.load(Ordering::SeqCst) > 0 {
            assert_eq!(heartbeat.leased_jobs, 1);
            assert!(heartbeat.processor_configured);
            self.record("renewal_process_heartbeat");
            assert_eq!(self.stage, "process");
            return Err(CanvasSyncRepositoryError::Unavailable);
        }
        Ok(())
    }

    pub(super) fn renew(
        &self,
        job: &CanvasSyncJob,
        worker: &str,
        seconds: &PythonConfigInteger,
    ) -> Result<bool, CanvasSyncRepositoryError> {
        self.assert_identity(job, worker);
        assert_eq!(seconds.to_u64(), Some(60));
        assert_eq!(
            self.renewals.fetch_add(1, Ordering::SeqCst),
            0,
            "failed renewal must not restart"
        );
        self.record("renew_lease");
        if self.stage == "lease" {
            Err(CanvasSyncRepositoryError::Unavailable)
        } else {
            Ok(true)
        }
    }

    pub(super) fn persist(
        &self,
        job: &CanvasSyncJob,
        worker: &str,
        version: i32,
        event: &'static str,
    ) -> Result<(), CanvasSyncRepositoryError> {
        self.assert_identity(job, worker);
        assert_eq!(version, self.version, "use the captured job generation");
        assert!(!self.active.load(Ordering::SeqCst));
        assert_eq!(
            self.cleaned.load(Ordering::SeqCst),
            1,
            "processor drop acknowledged before persistence"
        );
        self.record(event);
        if self.secondary_error {
            Err(CanvasSyncRepositoryError::InvalidState)
        } else {
            Ok(())
        }
    }

    fn renewal_prefix(&self) -> Vec<&'static str> {
        let mut events = vec![
            "target",
            "initial_target_heartbeat",
            "validate",
            "processor_enter",
            "renew_lease",
        ];
        if self.stage != "lease" {
            events.push("renewal_target_heartbeat");
        }
        if self.stage == "process" {
            events.push("renewal_process_heartbeat");
        }
        events
    }
}

struct ProcessorDrop(Arc<RenewalScript>);

impl Drop for ProcessorDrop {
    fn drop(&mut self) {
        assert!(self.0.active.swap(false, Ordering::SeqCst));
        self.0.cleaned.fetch_add(1, Ordering::SeqCst);
        self.0.record("processor_drop");
    }
}

struct ScriptedProcessor {
    script: Arc<RenewalScript>,
    outcome: String,
    release: Arc<Semaphore>,
}

#[async_trait]
impl CanvasSyncProcessor for ScriptedProcessor {
    fn configured(&self) -> bool {
        true
    }

    async fn process(
        &self,
        target: &CanvasSyncTarget,
        lease: &CanvasSyncLease,
    ) -> Result<CanvasSyncResult, CanvasSyncProcessingError> {
        assert_eq!(target.id, self.script.expected_lease.target_id);
        assert_eq!(lease, &self.script.expected_lease);
        assert!(!self.script.active.swap(true, Ordering::SeqCst));
        self.script.record("processor_enter");
        let _cleanup = ProcessorDrop(self.script.clone());
        if matches!(self.outcome.as_str(), "deadline" | "cancel") {
            return std::future::pending().await;
        }
        self.release.acquire().await.unwrap().forget();
        match self.outcome.as_str() {
            "success" => canvas_sync_result(
                serde_json::json!({"facts_changed": 1})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
            "retry" => Err(CanvasSyncProcessingError::retryable(
                "synthetic_processing_retry",
                "Synthetic processing failure",
            )),
            "terminal" => Err(CanvasSyncProcessingError::terminal(
                "synthetic_processing_terminal",
                "Synthetic processing failure",
            )),
            _ => panic!("unregistered canonical processor outcome"),
        }
    }
}

fn fixture() -> Value {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-renewal-job-outcomes.json"
    ))
    .unwrap();
    assert_eq!(
        fixture["schema"],
        "elevenid.canvas-worker-renewal-job-outcomes/v1"
    );
    assert_eq!(
        fixture["observed_source"],
        "b027e834d71dee0cc3550aac1150cdb0c40946ae"
    );
    assert_eq!(
        fixture["worker_blob"],
        "b516ed3d0855f16e9ec899a452a22df49d2cafe5"
    );
    assert_eq!(fixture["cutover_authorized"], false);
    assert_eq!(
        fixture["handler_exit_after_processor_termination"],
        "renewal_exception"
    );
    assert_eq!(fixture["processor_cleanup_acknowledged"], true);
    assert_eq!(
        fixture["after_renewal_error"]["processor_still_active"],
        true
    );
    assert_eq!(
        fixture["after_renewal_error"]["job_handler_still_pending"],
        true
    );
    assert_eq!(
        fixture["after_renewal_error"]["durable_job_status"],
        "leased"
    );
    let expected = fixture["renewal_failures"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|stage| {
            fixture["processor_outcomes"]
                .as_array()
                .unwrap()
                .iter()
                .map(move |outcome| (stage.as_str().unwrap(), outcome["name"].as_str().unwrap()))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(PRIMARY_CASES.len(), 15);
    assert_eq!(
        PRIMARY_CASES.iter().copied().collect::<BTreeSet<_>>(),
        expected,
        "every canonical stage/outcome must have a discoverable test"
    );
    fixture
}

enum Observation {
    Job(Result<CanvasSyncJobStatus, EscapedJobError>),
    Cycle(Result<CanvasSyncWorkerCycleResult, CanvasSyncRepositoryError>),
}

async fn assert_case(stage: &str, outcome: &str, secondary_error: bool, cycle: bool) {
    let fixture = fixture();
    let expected = fixture["processor_outcomes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == outcome)
        .unwrap();
    let expected_status = match outcome {
        "success" => "succeeded",
        "retry" | "deadline" => "retry",
        "terminal" => "dead_letter",
        "cancel" => "leased",
        _ => panic!("unregistered canonical processor outcome"),
    };
    assert_eq!(expected["durable_status"], expected_status);
    assert_eq!(
        expected["completed"],
        matches!(outcome, "success" | "terminal")
    );
    let (job, target) = retry_job_fixture();
    let script = Arc::new(RenewalScript {
        stage: stage.into(),
        expected_lease: CanvasSyncLease::from_job(&job, "retry-worker").unwrap(),
        version: job.target_config_version,
        secondary_error,
        events: Mutex::new(Vec::new()),
        renewals: AtomicUsize::new(0),
        active: AtomicBool::new(false),
        cleaned: AtomicUsize::new(0),
    });
    let failure_status = if outcome == "terminal" {
        CanvasSyncJobStatus::DeadLetter
    } else {
        CanvasSyncJobStatus::Retry
    };
    let mut repository = spy_repository(job.clone(), target, None, failure_status);
    Arc::get_mut(&mut repository).unwrap().renewal = Some(script.clone());
    let release = Arc::new(Semaphore::new(0));
    let oauth = Arc::new(NoOAuth);
    let mut config = worker_config("retry-worker", "retry-org");
    config.lease_seconds = 60_u64.into();
    config.job_timeout = Duration::from_secs(30);
    assert_eq!(config.lease_renewal_interval(), Duration::from_secs(20));
    let worker = CanvasSyncWorker::new(
        repository.clone(),
        oauth.clone(),
        oauth.clone(),
        oauth,
        Arc::new(ScriptedProcessor {
            script: script.clone(),
            outcome: outcome.into(),
            release: release.clone(),
        }),
        config,
    );
    let started = Instant::now();
    let mut operation = Box::pin(async {
        if cycle {
            Observation::Cycle(worker.run_cycle().await)
        } else {
            Observation::Job(worker.process_job(job).await)
        }
    });
    assert!(futures_util::poll!(&mut operation).is_pending());
    assert!(script.active.load(Ordering::SeqCst));
    advance(Duration::from_secs(19)).await;
    assert!(futures_util::poll!(&mut operation).is_pending());
    assert_eq!(
        script.renewals.load(Ordering::SeqCst),
        0,
        "no early renewal"
    );
    advance(Duration::from_secs(1)).await;
    assert!(
        futures_util::poll!(&mut operation).is_pending(),
        "renewal error must not terminate the active processor/handler"
    );
    assert_eq!(*script.events.lock().unwrap(), script.renewal_prefix());
    assert!(script.active.load(Ordering::SeqCst));
    assert_eq!(script.cleaned.load(Ordering::SeqCst), 0);
    advance(Duration::from_secs(1)).await;
    assert!(futures_util::poll!(&mut operation).is_pending());
    assert_eq!(script.renewals.load(Ordering::SeqCst), 1);
    if outcome == "cancel" {
        drop(operation);
    } else {
        if outcome == "deadline" {
            advance(Duration::from_secs(9)).await;
        } else {
            release.add_permits(1);
        }
        let Poll::Ready(observation) = futures_util::poll!(&mut operation) else {
            panic!("actual handler must finish at the explicit release/deadline, without automatic clock advance");
        };
        match observation {
            Observation::Job(result) => assert!(matches!(result, Err(EscapedJobError::Repository(CanvasSyncRepositoryError::Unavailable))), "original renewal error must survive outcome persistence, including a secondary InvalidState"),
            Observation::Cycle(result) => {
                let result = result.unwrap();
                assert_eq!((result.scheduled, result.leased, result.succeeded, result.retried, result.dead_lettered), (0, 1, 0, 0, 0));
            }
        }
        assert_eq!(
            started.elapsed(),
            Duration::from_secs(if outcome == "deadline" { 30 } else { 21 })
        );
        drop(operation);
    }
    assert!(!script.active.load(Ordering::SeqCst));
    assert_eq!(
        script.cleaned.load(Ordering::SeqCst),
        1,
        "cancellation/completion acknowledges owned processor cleanup synchronously"
    );
    let mut events = script.renewal_prefix();
    events.push("processor_drop");
    if outcome != "cancel" {
        events.push(if outcome == "success" {
            "complete"
        } else {
            "fail"
        });
    }
    assert_eq!(*script.events.lock().unwrap(), events);
    let failures = repository.failures.lock().unwrap();
    if matches!(outcome, "success" | "cancel") {
        assert!(failures.is_empty());
    } else {
        let summary = if outcome == "deadline" {
            "Canvas synchronization exceeded its wall-clock deadline"
        } else {
            "Synthetic processing failure"
        };
        assert_eq!(
            *failures,
            vec![(
                expected["error_code"].as_str().unwrap().into(),
                summary.into(),
                None,
                outcome == "terminal",
                "retry-worker".into(),
                7
            )]
        );
        assert_eq!(*repository.failed_job_ids.lock().unwrap(), ["retry-job"]);
    }
}

macro_rules! primary_cases {
    ($($name:ident: $stage:literal, $outcome:literal;)*) => {
        const PRIMARY_CASES: &[(&str, &str)] = &[$(($stage, $outcome)),*];
        $(#[tokio::test(start_paused = true)] async fn $name() {
            assert_case($stage, $outcome, false, false).await;
        })*
    };
}

primary_cases! {
    lease_error_then_success: "lease", "success";
    lease_error_then_retry: "lease", "retry";
    lease_error_then_terminal: "lease", "terminal";
    lease_error_then_deadline: "lease", "deadline";
    lease_error_then_cancel: "lease", "cancel";
    target_error_then_success: "target", "success";
    target_error_then_retry: "target", "retry";
    target_error_then_terminal: "target", "terminal";
    target_error_then_deadline: "target", "deadline";
    target_error_then_cancel: "target", "cancel";
    process_error_then_success: "process", "success";
    process_error_then_retry: "process", "retry";
    process_error_then_terminal: "process", "terminal";
    process_error_then_deadline: "process", "deadline";
    process_error_then_cancel: "process", "cancel";
}

#[tokio::test(start_paused = true)]
async fn lease_error_survives_failed_completion() {
    assert_case("lease", "success", true, false).await;
}

#[tokio::test(start_paused = true)]
async fn target_error_survives_failed_retry_persistence() {
    assert_case("target", "retry", true, false).await;
}

#[tokio::test(start_paused = true)]
async fn process_error_survives_failed_deadline_persistence() {
    assert_case("process", "deadline", true, false).await;
}

#[tokio::test(start_paused = true)]
async fn actual_cycle_does_not_count_persisted_success_after_renewal_error() {
    assert_case("process", "success", false, true).await;
}
