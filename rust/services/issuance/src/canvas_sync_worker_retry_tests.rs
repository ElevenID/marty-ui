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
    failures: Mutex<Vec<FailureCall>>,
}

#[async_trait]
impl CanvasSyncWorkerRepository for SpyRepository {
    async fn upsert_heartbeat(&self, _: &WorkerHeartbeat) -> Result<(), CanvasSyncRepositoryError> {
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
        Ok(())
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
        assert_eq!(job.id, "retry-job");
        Ok(Some(CanvasSyncJobStatus::Retry))
    }
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
    let repository = Arc::new(SpyRepository {
        leased: Mutex::new(Some(job)),
        target,
        failures: Mutex::new(Vec::new()),
    });
    let oauth = Arc::new(NoOAuth);
    let mut config = CanvasSyncWorkerConfig::from_values(&BTreeMap::from([
        ("CANVAS_SYNC_WORKER_ID".into(), "retry-worker".into()),
        ("CANVAS_PORTABLE_INTEGRATION_ENABLED".into(), "true".into()),
        ("CANVAS_PILOT_ORGANIZATION_IDS".into(), "retry-org".into()),
    ]))
    .unwrap();
    config.job_timeout = Duration::from_secs(5);
    let worker = CanvasSyncWorker::new(
        repository.clone(),
        oauth.clone(),
        oauth.clone(),
        oauth,
        Arc::new(RateLimitedProcessor(86_400)),
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
        (1, 1, 0, 0)
    );
    assert_eq!(
        *repository.failures.lock().unwrap(),
        vec![(
            "canvas_rate_limited".into(),
            "Canvas rate limited one or more authoritative evidence reads".into(),
            Some(86_400),
            false,
            "retry-worker".into(),
            7,
        )]
    );
}
