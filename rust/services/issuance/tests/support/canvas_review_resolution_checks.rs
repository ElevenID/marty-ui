//! Supplementary real-schema fences/rollback and real credential-service/repo
//! delegation. Publication is controlled; no external signing/provider proof.
use super::canvas_operations_read_replay::{request_case, seed};
use async_trait::async_trait;
use marty_issuance_service::{
    canvas_operations::{candidate_router, CanvasOperationsService, OperationsError},
    canvas_review_resolution::CanvasReviewLifecycle,
    credential_management::{
        CredentialLifecycleAction, CredentialLifecycleEvent, CredentialLifecycleEventSink,
        CredentialManagementPortError, CredentialManagementService, CredentialStatusPublisher,
        ManagedCredential,
    },
    credential_management_postgres::PostgresCredentialManagementRepository,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::Mutex;

fn router(pool: &PgPool, lifecycle: Option<Arc<dyn CanvasReviewLifecycle>>) -> axum::Router {
    candidate_router(
        CanvasOperationsService::new(pool.clone(), Some("synthetic-operations-key"))
            .with_review_operations(lifecycle),
    )
}
fn case(action: &str) -> Value {
    json!({"method":"POST","path":"/v1/integrations/canvas/evidence-policy-reviews/review-dismiss/resolve",
        "body":{"action":action,"note":"  synthetic review  "},"headers":{"X-Authenticated-User-ID":"  actor  "}})
}
async fn row(pool: &PgPool) -> Value {
    sqlx::query_scalar("SELECT to_jsonb(review) FROM issuance_service.evidence_policy_reviews review WHERE id='review-dismiss'")
        .fetch_one(pool).await.unwrap()
}
async fn events(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM issuance_service.issuance_events WHERE event_type='evidence_policy_review_resolved'")
        .fetch_one(pool).await.unwrap()
}
async fn reopen(pool: &PgPool) {
    sqlx::query("UPDATE issuance_service.evidence_policy_reviews SET status='open',resolution_action=NULL,
        resolution_notes=NULL,resolved_by=NULL,resolved_at=NULL,resolution_claim_token=NULL,
        resolution_claim_action=NULL,resolution_claimed_at=NULL,resolution_recovery_pending=false WHERE id='review-dismiss'")
        .execute(pool).await.unwrap();
}

struct ReplaceClaim(PgPool, bool);
#[async_trait]
impl CanvasReviewLifecycle for ReplaceClaim {
    async fn transition(
        &self,
        _organization: &str,
        _credential: &str,
        _action: CredentialLifecycleAction,
        _reason: &str,
    ) -> Result<(), OperationsError> {
        let query = if self.1 {
            "UPDATE issuance_service.evidence_policy_reviews SET resolution_claim_token='synthetic-replacement' WHERE id='review-dismiss'"
        } else {
            "UPDATE issuance_service.evidence_policy_reviews SET resolution_claim_action='revoke' WHERE id='review-dismiss'"
        };
        sqlx::query(query).execute(&self.0).await.unwrap();
        Ok(())
    }
}

struct Publication(PgPool, Mutex<Vec<Value>>);
#[async_trait]
impl CredentialStatusPublisher for Publication {
    async fn publish(
        &self,
        credential: &ManagedCredential,
        action: CredentialLifecycleAction,
        reason: Option<&str>,
    ) -> Result<(), CredentialManagementPortError> {
        let review = row(&self.0).await;
        assert_eq!(review["status"], "open");
        assert_eq!(review["resolution_claim_action"], action.as_str());
        assert!(review["resolution_claim_token"].is_string());
        self.1
            .lock()
            .await
            .push(json!({"credential":credential.id,"action":action.as_str(),"reason":reason}));
        Ok(())
    }
}
#[derive(Default)]
struct Events(Mutex<Vec<CredentialLifecycleEvent>>);
#[async_trait]
impl CredentialLifecycleEventSink for Events {
    async fn emit(&self, event: CredentialLifecycleEvent) {
        self.0.lock().await.push(event);
    }
}

pub async fn exercise(pool: &PgPool) {
    seed(pool).await;
    // Dismissal cannot finalize unless the audit insertion commits with it.
    sqlx::query("ALTER TABLE issuance_service.issuance_events ADD CONSTRAINT synthetic_reject_review_audit CHECK (event_type <> 'evidence_policy_review_resolved')")
        .execute(pool).await.unwrap();
    let result = request_case(&router(pool, None), &case("dismiss")).await;
    assert_eq!(result.0, 500);
    let failed = row(pool).await;
    assert_eq!(failed["status"], "open");
    assert_eq!(failed["resolution_claim_action"], "dismiss");
    assert!(
        failed["resolution_claim_token"].is_string(),
        "preexisting durable claim is retained when finalization rolls back"
    );
    assert!(failed["resolution_action"].is_null());
    assert!(failed["resolved_at"].is_null());
    assert_eq!(events(pool).await, 0);
    sqlx::query("ALTER TABLE issuance_service.issuance_events DROP CONSTRAINT synthetic_reject_review_audit").execute(pool).await.unwrap();
    reopen(pool).await;
    // Finalization is fenced by BOTH claim token and claim action.
    for replace_token in [true, false] {
        let result = request_case(
            &router(
                pool,
                Some(Arc::new(ReplaceClaim(pool.clone(), replace_token))),
            ),
            &case("suspend"),
        )
        .await;
        assert_eq!(result.0, 409);
        assert_eq!(
            result.2["detail"]["message"],
            "Canvas evidence correction review claim is no longer active"
        );
        let current = row(pool).await;
        assert_eq!(current["status"], "open");
        assert!(current["resolution_claim_token"].is_string());
        assert_eq!(events(pool).await, 0);
        reopen(pool).await;
    }
    // Existing evidence application lock blocks a manual claim before effects.
    let mut transaction = pool.begin().await.unwrap();
    sqlx::query(
        "SELECT id FROM issuance_service.applications WHERE id='application-review' FOR UPDATE",
    )
    .execute(&mut *transaction)
    .await
    .unwrap();
    let app = router(pool, None);
    let dismissal = case("dismiss");
    let request = tokio::spawn(async move { request_case(&app, &dismissal).await });
    tokio::time::timeout(std::time::Duration::from_secs(5),async {
        loop {
            let waiting: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'")
                .fetch_one(pool).await.unwrap();
            if waiting > 0 { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("manual claim should wait on application lock");
    assert!(row(pool).await["resolution_claim_token"].is_null());
    transaction.rollback().await.unwrap();
    assert_eq!(request.await.unwrap().0, 200);
    assert_eq!(events(pool).await, 1);
    reopen(pool).await;

    // Exercise the actual lifecycle owner and PostgreSQL repository, not the
    // controlled transition port used by the 46-case differential.
    let publication = Arc::new(Publication(pool.clone(), Mutex::new(Vec::new())));
    let sink = Arc::new(Events::default());
    let lifecycle = CredentialManagementService::new(
        Arc::new(PostgresCredentialManagementRepository::new(pool.clone())),
        publication.clone(),
        sink.clone(),
    );
    let app = router(pool, Some(Arc::new(lifecycle)));
    for (action, status) in [("suspend", "suspended"), ("revoke", "revoked")] {
        let result = request_case(&app, &case(action)).await;
        assert_eq!(result.0, 200, "actual lifecycle transition: {result:?}");
        assert_eq!(result.2["status"], status);
        assert_eq!(result.2["resolution_notes"], "synthetic review");
        assert_eq!(result.2["resolved_by"], "actor");
        let persisted: Value = sqlx::query_scalar("SELECT to_jsonb(c) FROM issuance_service.issued_credentials c WHERE id='credential-review'")
            .fetch_one(pool).await.unwrap();
        assert_eq!(persisted["status"], status);
        assert_eq!(persisted["revoked"], action == "revoke");
        if action == "revoke" {
            assert!(persisted["revoked_at"].is_string());
            assert_eq!(persisted["revocation_reason"], "  synthetic review  ");
        }
        reopen(pool).await;
    }
    assert_eq!(publication.1.lock().await.len(), 2);
    assert_eq!(sink.0.lock().await.len(), 2);
    assert_eq!(events(pool).await, 3);
    let rejected = request_case(&app, &case("suspend")).await;
    assert_eq!(
        rejected.0, 400,
        "lifecycle business errors retain their existing HTTP mapping"
    );
    assert_eq!(
        rejected.2,
        json!({"detail":"Cannot suspend revoked credential"})
    );
    assert!(
        row(pool).await["resolution_claim_token"].is_null(),
        "failed lifecycle releases manual claim"
    );
    assert_eq!(events(pool).await, 3);
    assert_eq!(publication.1.lock().await.len(), 2);
}
