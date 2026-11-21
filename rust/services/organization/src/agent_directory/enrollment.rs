//! Managed enrollment establishes key-control eligibility only. Operational
//! machine credentials, MAP appraisal, attestation and authority remain separate.
use chrono::{DateTime, Duration, Utc};
use marty_principal_runtime_binding::managed_enrollment::{EnrollmentAlgorithm, EnrollmentPolicy};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use super::{domain::valid_uri, AgentDirectoryError, AgentIdentity};
use crate::ForwardedPrincipal;

pub const MANAGED_ENROLLMENT_PROFILE: &str = "urn:marty:managed-key-enrollment:v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentEnrollmentConfiguration {
    pub(super) audience: String,
    pub(super) policy: EnrollmentPolicy,
    pub(super) max_age_seconds: u32,
}
impl AgentEnrollmentConfiguration {
    pub fn new(
        audience: String,
        policy_profile: String,
        policy_revision: u64,
        max_age_seconds: u32,
    ) -> Result<Self, AgentDirectoryError> {
        if !valid_uri(&audience) {
            return Err(AgentDirectoryError::InvalidRequest);
        }
        let policy = EnrollmentPolicy::new(
            policy_profile,
            policy_revision,
            vec![EnrollmentAlgorithm::ES256, EnrollmentAlgorithm::EdDSA],
            max_age_seconds,
        )
        .map_err(|_| AgentDirectoryError::InvalidRequest)?;
        Ok(Self {
            audience,
            policy,
            max_age_seconds,
        })
    }
}

/// Context reconstructed by the authenticated Gateway hop. This is not a
/// deserializable request field or a substitute for Gateway session verification.
#[derive(Clone, Debug)]
pub struct AgentEnrollmentSession {
    pub(super) organization_id: Uuid,
    pub(super) user_id: Uuid,
    pub(super) session_ref: String,
    pub(super) observed_at: DateTime<Utc>,
    pub(super) valid_until: DateTime<Utc>,
}
impl AgentEnrollmentSession {
    pub fn new(
        organization_id: Uuid,
        user_id: Uuid,
        session_ref: String,
        observed_at: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<Self, AgentDirectoryError> {
        if organization_id.is_nil()
            || user_id.is_nil()
            || !session_digest(&session_ref)
            || valid_until <= observed_at
            || valid_until - observed_at > Duration::seconds(30)
        {
            return Err(AgentDirectoryError::AccessDenied);
        }
        Ok(Self {
            organization_id,
            user_id,
            session_ref,
            observed_at,
            valid_until,
        })
    }
    pub(super) fn check(
        &self,
        organization: Uuid,
        principal: &ForwardedPrincipal,
        now: DateTime<Utc>,
    ) -> Result<(), AgentDirectoryError> {
        if organization != self.organization_id
            || now < self.observed_at
            || now >= self.valid_until
            || !matches!(principal, ForwardedPrincipal::User { user_id } if user_id == &self.user_id.to_string())
        {
            return Err(AgentDirectoryError::AccessDenied);
        }
        Ok(())
    }
}

pub(super) fn sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn session_digest(value: &str) -> bool {
    value.strip_prefix("urn:marty:session:").is_some_and(sha256)
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAgentEnrollmentChallenge {
    pub expected_revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteAgentEnrollment {
    pub proof: String,
}
impl std::fmt::Debug for CompleteAgentEnrollment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompleteAgentEnrollment")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AgentEnrollmentChallenge {
    pub profile: String,
    pub challenge_id: Uuid,
    pub organization_id: Uuid,
    pub agent_id: Uuid,
    pub expected_revision: u64,
    pub challenge: Value,
    /// Exact base64url payload segment to sign; clients must not reserialize it.
    pub signing_payload: String,
    pub challenge_digest: String,
    pub expires_at: DateTime<Utc>,
    pub recovered: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AgentEnrollmentResult {
    pub challenge_id: Uuid,
    pub organization_id: Uuid,
    pub agent_id: Uuid,
    pub key_id: Uuid,
    pub previous_revision: u64,
    pub enrolled_revision: u64,
    pub completed_at: DateTime<Utc>,
    pub proof_digest: String,
    pub challenge_digest: String,
    pub enrollment: String,
    pub authority_status: String,
    /// Historical enrollment snapshot, never a current-use authorization.
    pub identity: AgentIdentity,
    pub recovered: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct AgentEnrollmentRecord {
    pub challenge: AgentEnrollmentChallenge,
    pub state: &'static str,
    pub result: Option<AgentEnrollmentResult>,
    pub invalidated_at: Option<DateTime<Utc>>,
}
