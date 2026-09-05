//! Manual correction resolution candidate. The public runtime does not route it.
//! Claims share the evidence processor's application lock; audit writes share
//! its transaction helper, while credential changes use the lifecycle owner.
use async_trait::async_trait;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    canvas_award_candidate_postgres::{insert_event, LOCK_APPLICATION},
    canvas_operations::OperationsError,
    credential_management::{CredentialLifecycleAction, CredentialManagementService},
    python_value::strip,
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReviewAction {
    Dismiss,
    Suspend,
    Revoke,
}

impl ReviewAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dismiss => "dismiss",
            Self::Suspend => "suspend",
            Self::Revoke => "revoke",
        }
    }
    const fn status(self) -> &'static str {
        match self {
            Self::Dismiss => "dismissed",
            Self::Suspend => "suspended",
            Self::Revoke => "revoked",
        }
    }
    const fn lifecycle(self) -> Option<CredentialLifecycleAction> {
        match self {
            Self::Dismiss => None,
            Self::Suspend => Some(CredentialLifecycleAction::Suspend),
            Self::Revoke => Some(CredentialLifecycleAction::Revoke),
        }
    }
}

/// Controlled lifecycle port for differential tests; the real implementation
/// below delegates to the existing credential service, not duplicate policy.
#[async_trait]
pub trait CanvasReviewLifecycle: Send + Sync {
    async fn transition(
        &self,
        organization: &str,
        credential: &str,
        action: CredentialLifecycleAction,
        reason: &str,
    ) -> Result<(), OperationsError>;
}

#[async_trait]
impl CanvasReviewLifecycle for CredentialManagementService {
    async fn transition(
        &self,
        organization: &str,
        credential: &str,
        action: CredentialLifecycleAction,
        reason: &str,
    ) -> Result<(), OperationsError> {
        CredentialManagementService::transition(
            self,
            credential,
            Some(organization),
            action,
            Some(reason),
        )
        .await
        .map(|_| ())
        .map_err(OperationsError::Lifecycle)
    }
}

#[derive(Clone)]
pub struct CanvasReviewResolver {
    pool: PgPool,
    lifecycle: Option<Arc<dyn CanvasReviewLifecycle>>,
}

impl CanvasReviewResolver {
    #[must_use]
    pub fn new(pool: PgPool, lifecycle: Option<Arc<dyn CanvasReviewLifecycle>>) -> Self {
        Self { pool, lifecycle }
    }

    // This service expects the HTTP owner to authenticate and validate the body.
    // It still scopes every lookup and durable write to the trusted tenant.
    pub async fn resolve(
        &self,
        organization: &str,
        review_id: &str,
        action: ReviewAction,
        notes: Option<&str>,
        actor: Option<&str>,
    ) -> Result<Value, OperationsError> {
        let review = self.load(organization, review_id).await?.ok_or_else(|| {
            public(
                StatusCode::NOT_FOUND,
                "canvas_review_not_found",
                "Canvas evidence correction review not found",
            )
        })?;
        if review["status"] != "open" {
            return Err(conflict(
                "Canvas evidence correction review is already resolved",
            ));
        }
        let credential = field(&review, "credential_id")?;
        if action.lifecycle().is_some() {
            let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM issuance_service.issued_credentials WHERE id=$1 AND organization_id=$2)")
                .bind(credential).bind(organization).fetch_one(&self.pool).await.map_err(internal)?;
            if !exists {
                return Err(public(
                    StatusCode::NOT_FOUND,
                    "canvas_review_credential_not_found",
                    "Credential for Canvas evidence correction review not found",
                ));
            }
            if self.lifecycle.is_none() {
                return Err(public(
                    StatusCode::CONFLICT,
                    "canvas_review_lifecycle_handler_unavailable",
                    "Credential status handler is unavailable",
                ));
            }
        }
        let token = crate::canvas_lti_login::random_token();
        let claimed = self
            .claim(organization, review_id, &token, action.as_str())
            .await?
            .ok_or_else(|| {
                conflict("Canvas evidence correction review is already claimed or resolved")
            })?;
        if let Some(lifecycle_action) = action.lifecycle() {
            let reason = notes
                .filter(|value| !value.is_empty())
                .unwrap_or("Canvas evidence correction review");
            let outcome = self
                .lifecycle
                .as_ref()
                .ok_or(OperationsError::Internal)?
                .transition(
                    organization,
                    field(&claimed, "credential_id")?,
                    lifecycle_action,
                    reason,
                )
                .await;
            if let Err(error) = outcome {
                if self.release(organization, review_id, &token).await?
                    && self.recover(organization, review_id).await.is_err()
                {
                    tracing::error!("Pending Canvas review recovery could not be finalized");
                }
                return Err(error);
            }
        }
        self.finalize(
            organization,
            review_id,
            &token,
            Resolution {
                action: action.as_str(),
                status: action.status(),
                notes: normalized(notes),
                actor: normalized(actor),
            },
        )
        .await?
        .ok_or_else(|| conflict("Canvas evidence correction review claim is no longer active"))
    }

    async fn load(
        &self,
        organization: &str,
        review_id: &str,
    ) -> Result<Option<Value>, OperationsError> {
        sqlx::query_scalar("SELECT to_jsonb(review) FROM issuance_service.evidence_policy_reviews review WHERE organization_id=$1 AND id=$2")
            .bind(organization).bind(review_id).fetch_optional(&self.pool).await.map_err(internal)
    }

    async fn claim(
        &self,
        organization: &str,
        review_id: &str,
        token: &str,
        action: &str,
    ) -> Result<Option<Value>, OperationsError> {
        let mut transaction = self.pool.begin().await.map_err(internal)?;
        let application: Option<String> = sqlx::query_scalar("SELECT application_id FROM issuance_service.evidence_policy_reviews WHERE organization_id=$1 AND id=$2")
            .bind(organization).bind(review_id).fetch_optional(&mut *transaction).await.map_err(internal)?;
        let Some(application) = application else {
            return Ok(None);
        };
        // Same row/lock SQL as authoritative evidence updates, before review CAS.
        let locked: Option<Value> = sqlx::query_scalar(LOCK_APPLICATION)
            .bind(application)
            .bind(organization)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(internal)?;
        if locked.is_none() {
            return Ok(None);
        }
        let result = sqlx::query_scalar("UPDATE issuance_service.evidence_policy_reviews AS review
            SET resolution_claim_token=$3,resolution_claim_action=$4,resolution_claimed_at=$5,updated_at=$5
            WHERE organization_id=$1 AND id=$2 AND status='open' AND resolution_claim_token IS NULL RETURNING to_jsonb(review)")
            .bind(organization).bind(review_id).bind(token).bind(action).bind(chrono::Utc::now())
            .fetch_optional(&mut *transaction).await.map_err(internal)?;
        transaction.commit().await.map_err(internal)?;
        Ok(result)
    }

    async fn release(
        &self,
        organization: &str,
        review_id: &str,
        token: &str,
    ) -> Result<bool, OperationsError> {
        let result = sqlx::query("UPDATE issuance_service.evidence_policy_reviews
            SET resolution_claim_token=NULL,resolution_claim_action=NULL,resolution_claimed_at=NULL,updated_at=$4
            WHERE organization_id=$1 AND id=$2 AND status='open' AND resolution_claim_token=$3")
            .bind(organization).bind(review_id).bind(token).bind(chrono::Utc::now())
            .execute(&self.pool).await.map_err(internal)?;
        Ok(result.rows_affected() == 1)
    }

    async fn finalize(
        &self,
        organization: &str,
        review_id: &str,
        token: &str,
        resolution: Resolution<'_>,
    ) -> Result<Option<Value>, OperationsError> {
        let mut transaction = self.pool.begin().await.map_err(internal)?;
        let row: Option<Value> = sqlx::query_scalar("UPDATE issuance_service.evidence_policy_reviews AS review
            SET status=$4,resolution_action=$5,resolution_notes=$6,resolved_by=$7,resolved_at=$8,
                resolution_claim_token=NULL,resolution_claim_action=NULL,resolution_claimed_at=NULL,
                resolution_recovery_pending=false,updated_at=$8
            WHERE organization_id=$1 AND id=$2 AND status='open' AND resolution_claim_token=$3 AND resolution_claim_action=$5
            RETURNING to_jsonb(review)")
            .bind(organization).bind(review_id).bind(token).bind(resolution.status).bind(resolution.action)
            .bind(resolution.notes).bind(resolution.actor).bind(chrono::Utc::now())
            .fetch_optional(&mut *transaction).await.map_err(internal)?;
        if let Some(row) = row.as_ref() {
            // Event identity is derived from the winning row, never caller input.
            insert_event(&mut transaction, field(row,"application_id")?, "evidence_policy_review_resolved",
                json!({"organization_id":organization,"review_id":review_id,"credential_id":field(row,"credential_id")?,
                    "resolution_action":resolution.action,"resolved_by":resolution.actor}))
                .await.map_err(|_| OperationsError::Internal)?;
        }
        transaction.commit().await.map_err(internal)?;
        Ok(row)
    }

    async fn recover(&self, organization: &str, review_id: &str) -> Result<(), OperationsError> {
        let Some(review) = self.load(organization, review_id).await? else {
            return Ok(());
        };
        if review["status"] != "open"
            || review["resolution_recovery_pending"] != true
            || !review["resolution_claim_token"].is_null()
        {
            return Ok(());
        }
        let token = crate::canvas_lti_login::random_token();
        if self
            .claim(organization, review_id, &token, "evidence_recovered")
            .await?
            .is_none()
        {
            return Ok(());
        }
        self.finalize(
            organization,
            review_id,
            &token,
            Resolution {
                action: "evidence_recovered",
                status: "resolved",
                notes: Some("Authoritative Canvas evidence recovered during correction handling"),
                actor: Some("canvas-evidence-sync"),
            },
        )
        .await?;
        Ok(())
    }
}

struct Resolution<'a> {
    action: &'static str,
    status: &'static str,
    notes: Option<&'a str>,
    actor: Option<&'a str>,
}

fn normalized(value: Option<&str>) -> Option<&str> {
    value.map(strip).filter(|value| !value.is_empty())
}
fn field<'a>(row: &'a Value, name: &str) -> Result<&'a str, OperationsError> {
    row[name].as_str().ok_or(OperationsError::Internal)
}
fn internal(_: sqlx::Error) -> OperationsError {
    OperationsError::Internal
}
fn public(status: StatusCode, code: &str, message: &str) -> OperationsError {
    OperationsError::Public(status, json!({"detail":{"code":code,"message":message}}))
}
fn conflict(message: &str) -> OperationsError {
    public(
        StatusCode::CONFLICT,
        "canvas_review_already_resolved",
        message,
    )
}
