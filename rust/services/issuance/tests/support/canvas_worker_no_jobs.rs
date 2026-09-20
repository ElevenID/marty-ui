//! Fail closed if a no-job acceptance corpus accidentally invokes processing.
use async_trait::async_trait;
use marty_issuance_service::{
    canvas_sync_lease::CanvasSyncLease,
    canvas_sync_worker::{
        CanvasSyncProcessingError, CanvasSyncProcessor, CanvasSyncResult, CanvasSyncTarget,
    },
};

pub(super) struct NoJobsExpected(pub(super) bool);

#[async_trait]
impl CanvasSyncProcessor for NoJobsExpected {
    fn configured(&self) -> bool {
        self.0
    }

    async fn process(
        &self,
        _: &CanvasSyncTarget,
        _: &CanvasSyncLease,
    ) -> Result<CanvasSyncResult, CanvasSyncProcessingError> {
        panic!("no-job corpus must never invoke a job processor");
    }
}
