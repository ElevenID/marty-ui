# Typed processor dispatch boundary

The public worker constructor requires an actual `Arc<dyn CanvasSyncProcessor>`.
The processor method must return an awaitable result whose successful value is
the lossless object type `CanvasSyncResult`. Python's absent processor,
non-awaitable callback and non-object callback result cannot be installed through
this constructor. Processor errors, cancellation and `configured() == false`
remain runtime behavior and are tested separately.

These examples compile against the real public constructor and trait. Their
identical hidden imports and typed dependency parameters are checked by the
positive example; they do not construct services or contact a database. Error
codes document the intended rejection. Rustdoc versions that do not enforce
error-code annotations still compile each negative example and require failure;
the annotations alone are not a claim of diagnostic-code verification.

## A real asynchronous, object-returning processor is accepted

```no_run
# use std::sync::Arc;
# use marty_issuance_service::{
#     canvas_oauth::{CanvasOAuthProvider, CanvasOAuthRepository, CanvasOAuthSecretVault},
#     canvas_sync_lease::CanvasSyncLease,
#     canvas_sync_worker::{CanvasSyncProcessingError, CanvasSyncProcessor, CanvasSyncResult,
#         CanvasSyncTarget, CanvasSyncWorker, CanvasSyncWorkerConfig, CanvasSyncWorkerRepository},
# };
struct ObjectProcessor;

#[async_trait::async_trait]
impl CanvasSyncProcessor for ObjectProcessor {
    fn configured(&self) -> bool { true }

    async fn process(
        &self,
        _target: &CanvasSyncTarget,
        _lease: &CanvasSyncLease,
    ) -> Result<CanvasSyncResult, CanvasSyncProcessingError> {
        Ok(CanvasSyncResult::new())
    }
}

fn construct_worker(
    repository: Arc<dyn CanvasSyncWorkerRepository>,
    oauth_repository: Arc<dyn CanvasOAuthRepository>,
    oauth_vault: Arc<dyn CanvasOAuthSecretVault>,
    oauth_provider: Arc<dyn CanvasOAuthProvider>,
    config: CanvasSyncWorkerConfig,
) -> CanvasSyncWorker {
    CanvasSyncWorker::new(
        repository, oauth_repository, oauth_vault, oauth_provider,
        Arc::new(ObjectProcessor), config,
    )
}

async fn await_object(
    processor: &dyn CanvasSyncProcessor,
    target: &CanvasSyncTarget,
    lease: &CanvasSyncLease,
) -> Result<CanvasSyncResult, CanvasSyncProcessingError> {
    processor.process(target, lease).await
}
# fn main() {}
```

## An absent optional processor is rejected by the actual constructor

```compile_fail,E0308
# use std::sync::Arc;
# use marty_issuance_service::{
#     canvas_oauth::{CanvasOAuthProvider, CanvasOAuthRepository, CanvasOAuthSecretVault},
#     canvas_sync_lease::CanvasSyncLease,
#     canvas_sync_worker::{CanvasSyncProcessingError, CanvasSyncProcessor, CanvasSyncResult,
#         CanvasSyncTarget, CanvasSyncWorker, CanvasSyncWorkerConfig, CanvasSyncWorkerRepository},
# };
fn construct_worker(
    repository: Arc<dyn CanvasSyncWorkerRepository>,
    oauth_repository: Arc<dyn CanvasOAuthRepository>,
    oauth_vault: Arc<dyn CanvasOAuthSecretVault>,
    oauth_provider: Arc<dyn CanvasOAuthProvider>,
    config: CanvasSyncWorkerConfig,
) -> CanvasSyncWorker {
    let processor: Option<Arc<dyn CanvasSyncProcessor>> = None;
    CanvasSyncWorker::new(
        repository, oauth_repository, oauth_vault, oauth_provider,
        processor, config,
    )
}
# fn main() {}
```

## Wrapping absence in an Arc does not satisfy the processor trait

```compile_fail,E0277
# use std::sync::Arc;
# use marty_issuance_service::{
#     canvas_oauth::{CanvasOAuthProvider, CanvasOAuthRepository, CanvasOAuthSecretVault},
#     canvas_sync_lease::CanvasSyncLease,
#     canvas_sync_worker::{CanvasSyncProcessingError, CanvasSyncProcessor, CanvasSyncResult,
#         CanvasSyncTarget, CanvasSyncWorker, CanvasSyncWorkerConfig, CanvasSyncWorkerRepository},
# };
fn construct_worker(
    repository: Arc<dyn CanvasSyncWorkerRepository>,
    oauth_repository: Arc<dyn CanvasOAuthRepository>,
    oauth_vault: Arc<dyn CanvasOAuthSecretVault>,
    oauth_provider: Arc<dyn CanvasOAuthProvider>,
    config: CanvasSyncWorkerConfig,
) -> CanvasSyncWorker {
    let processor: Arc<Option<Arc<dyn CanvasSyncProcessor>>> = Arc::new(None);
    CanvasSyncWorker::new(
        repository, oauth_repository, oauth_vault, oauth_provider,
        processor, config,
    )
}
# fn main() {}
```

## A non-awaitable method cannot implement the real processor trait

```compile_fail,E0195
# use std::sync::Arc;
# use marty_issuance_service::{
#     canvas_oauth::{CanvasOAuthProvider, CanvasOAuthRepository, CanvasOAuthSecretVault},
#     canvas_sync_lease::CanvasSyncLease,
#     canvas_sync_worker::{CanvasSyncProcessingError, CanvasSyncProcessor, CanvasSyncResult,
#         CanvasSyncTarget, CanvasSyncWorker, CanvasSyncWorkerConfig, CanvasSyncWorkerRepository},
# };
struct SynchronousProcessor;

#[async_trait::async_trait]
impl CanvasSyncProcessor for SynchronousProcessor {
    fn configured(&self) -> bool { true }

    fn process(
        &self,
        _target: &CanvasSyncTarget,
        _lease: &CanvasSyncLease,
    ) -> Result<CanvasSyncResult, CanvasSyncProcessingError> {
        Ok(CanvasSyncResult::new())
    }
}

fn construct_worker(
    repository: Arc<dyn CanvasSyncWorkerRepository>,
    oauth_repository: Arc<dyn CanvasOAuthRepository>,
    oauth_vault: Arc<dyn CanvasOAuthSecretVault>,
    oauth_provider: Arc<dyn CanvasOAuthProvider>,
    config: CanvasSyncWorkerConfig,
) -> CanvasSyncWorker {
    CanvasSyncWorker::new(
        repository, oauth_repository, oauth_vault, oauth_provider,
        Arc::new(SynchronousProcessor), config,
    )
}
# fn main() {}
```

## An awaitable scalar/array/null result is not an object-returning processor

```compile_fail,E0053
# use std::sync::Arc;
# use marty_issuance_service::{
#     canvas_oauth::{CanvasOAuthProvider, CanvasOAuthRepository, CanvasOAuthSecretVault},
#     canvas_sync_lease::CanvasSyncLease,
#     canvas_sync_worker::{CanvasSyncProcessingError, CanvasSyncProcessor, CanvasSyncResult,
#         CanvasSyncTarget, CanvasSyncWorker, CanvasSyncWorkerConfig, CanvasSyncWorkerRepository},
# };
struct NonObjectProcessor;

#[async_trait::async_trait]
impl CanvasSyncProcessor for NonObjectProcessor {
    fn configured(&self) -> bool { true }

    async fn process(
        &self,
        _target: &CanvasSyncTarget,
        _lease: &CanvasSyncLease,
    ) -> Result<serde_json::Value, CanvasSyncProcessingError> {
        Ok(serde_json::Value::Null)
    }
}

fn construct_worker(
    repository: Arc<dyn CanvasSyncWorkerRepository>,
    oauth_repository: Arc<dyn CanvasOAuthRepository>,
    oauth_vault: Arc<dyn CanvasOAuthSecretVault>,
    oauth_provider: Arc<dyn CanvasOAuthProvider>,
    config: CanvasSyncWorkerConfig,
) -> CanvasSyncWorker {
    CanvasSyncWorker::new(
        repository, oauth_repository, oauth_vault, oauth_provider,
        Arc::new(NonObjectProcessor), config,
    )
}
# fn main() {}
```
