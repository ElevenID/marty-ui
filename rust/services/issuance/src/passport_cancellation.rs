//! Local administrative abandonment, never a bureau cancellation request.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CancellationRequest {
    pub expected_job_id: String,
    pub reason_code: CancellationReason,
    pub reason: String,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum CancellationReason {
    AdministrativeAbandonment,
}

pub(crate) struct CancellationCommand {
    pub job_id: String,
    pub reason: String,
    pub key_hash: String,
    pub request_hash: String,
}

impl CancellationRequest {
    pub fn validate(mut self, organization: &str, key: &str) -> Option<CancellationCommand> {
        let id = Uuid::parse_str(&self.expected_job_id).ok()?;
        if id.to_string() != self.expected_job_id
            || !marty_passport_auth::valid_operation_idempotency_key(key)
        {
            return None;
        }
        self.reason = self.reason.trim().to_owned();
        if self.reason.is_empty()
            || self.reason.len() > 512
            || self.reason.chars().any(char::is_control)
        {
            return None;
        }
        let request_hash = hex::encode(Sha256::digest(serde_json::to_vec(&self).ok()?));
        let key_hash = hex::encode(Sha256::digest(
            format!("passport-administrative-cancel/v1\0{organization}\0{id}\0{key}").as_bytes(),
        ));
        Some(CancellationCommand {
            job_id: self.expected_job_id,
            reason: self.reason,
            key_hash,
            request_hash,
        })
    }
}

#[derive(Serialize)]
pub(crate) struct CancellationAudit {
    pub event_id: Uuid,
    pub job_id: String,
    pub organization_id: String,
    pub prior_status: String,
    pub reason_code: String,
    pub reason: String,
    pub actor_kind: String,
    pub actor_organization_id: String,
    pub recorded_at: DateTime<Utc>,
    pub bureau_cancellation_requested: bool,
    #[serde(skip)]
    pub key_hash: String,
    #[serde(skip)]
    pub request_hash: String,
}

#[must_use]
pub(crate) fn terminal(status: &str) -> bool {
    matches!(status, "ACTIVE" | "FAILED" | "CANCELLED")
}

#[must_use]
pub(crate) fn cancellable(status: &str) -> bool {
    matches!(
        status,
        "DRAFT"
            | "DATA_GENERATED"
            | "SOD_SIGNED"
            | "SUBMITTED"
            | "IN_PRODUCTION"
            | "QUALITY_CHECK"
            | "READY_FOR_ACTIVATION"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(reason: &str) -> CancellationRequest {
        CancellationRequest {
            expected_job_id: "00000000-0000-4000-8000-000000000001".into(),
            reason_code: CancellationReason::AdministrativeAbandonment,
            reason: reason.into(),
        }
    }

    #[test]
    fn terminal_states_never_authorize_abandonment_or_mutable_operations() {
        for state in ["ACTIVE", "FAILED", "CANCELLED"] {
            assert!(terminal(state));
            assert!(!cancellable(state));
        }
        assert!(!cancellable("unrecognized"));
        assert!(cancellable("READY_FOR_ACTIVATION"));
    }

    #[test]
    fn replay_hash_binds_normalized_reason_exact_job_and_tenant() {
        let first = request(" End owned failed attempt ")
            .validate("org-a", "request-1")
            .unwrap();
        let repeat = request("End owned failed attempt")
            .validate("org-a", "request-1")
            .unwrap();
        assert_eq!(first.key_hash, repeat.key_hash);
        assert_eq!(first.request_hash, repeat.request_hash);
        assert_ne!(
            first.key_hash,
            request("End owned failed attempt")
                .validate("org-b", "request-1")
                .unwrap()
                .key_hash
        );
        assert_ne!(
            first.request_hash,
            request("different reason")
                .validate("org-a", "request-1")
                .unwrap()
                .request_hash
        );
    }

    #[test]
    fn administrative_request_cannot_supply_actor_quality_or_bureau_outcome() {
        let body = serde_json::json!({
            "expected_job_id":"00000000-0000-4000-8000-000000000001",
            "reason_code":"ADMINISTRATIVE_ABANDONMENT", "reason":"End owned failed attempt",
            "bureau_cancellation_requested":true
        });
        assert!(serde_json::from_value::<CancellationRequest>(body).is_err());
        assert!(request("\n").validate("org-a", "request-1").is_none());
        assert!(request("bad\0reason")
            .validate("org-a", "request-1")
            .is_none());
    }
}
