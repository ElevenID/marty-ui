use std::sync::Arc;

use marty_verification::governance::{
    authorize_governance_json, require_governance_purpose_json, resume_governance_json,
    validate_governance_json, validate_governance_request_json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use thiserror::Error;

/// The three released Credentials verification purposes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernancePurpose {
    SessionCreate,
    Direct,
    VdsNc,
}

impl GovernancePurpose {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionCreate => "verification.session.create",
            Self::Direct => "verification.direct",
            Self::VdsNc => "verification.vds-nc",
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GovernanceError {
    #[error("verification governance is unavailable")]
    Configuration,
    #[error("invalid or unauthorized API key")]
    Unauthorized,
    #[error("verification governance snapshot is invalid")]
    InvalidSnapshot,
    #[error("verification request does not match its governed policy")]
    PolicyMismatch,
}

/// One validated server-owned registry.
///
/// Core remains the sole parser and decision owner. Keeping the raw JSON value
/// here avoids translating it into a second service-local governance model.
#[derive(Clone, Debug)]
pub struct GovernanceEngine {
    registry: Arc<Value>,
}

impl GovernanceEngine {
    pub fn new(registry_json: &str) -> Result<Self, GovernanceError> {
        validate_governance_json(registry_json).map_err(|_| GovernanceError::Configuration)?;
        let registry =
            serde_json::from_str(registry_json).map_err(|_| GovernanceError::Configuration)?;
        Ok(Self {
            registry: Arc::new(registry),
        })
    }

    pub fn authorize(
        &self,
        api_key: &str,
        purpose: GovernancePurpose,
    ) -> Result<GovernanceSnapshot, GovernanceError> {
        let request = json!({
            "governance": self.registry.as_ref(),
            "api_key": api_key,
            "purpose": purpose.as_str(),
        });
        let snapshot = authorize_governance_json(&request.to_string())
            .map_err(|_| GovernanceError::Unauthorized)?;
        GovernanceSnapshot::parse(&snapshot)
    }

    pub fn resume(
        &self,
        snapshot: &GovernanceSnapshot,
    ) -> Result<GovernanceSnapshot, GovernanceError> {
        let request = json!({
            "governance": self.registry.as_ref(),
            "snapshot": snapshot.value(),
        });
        let resumed = resume_governance_json(&request.to_string())
            .map_err(|_| GovernanceError::InvalidSnapshot)?;
        GovernanceSnapshot::parse(&resumed)
    }
}

/// A Core-validated, secret-free authority snapshot safe to persist.
#[derive(Clone, Debug, PartialEq)]
pub struct GovernanceSnapshot {
    value: Value,
    client_id: String,
    organization_id: String,
    purpose: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotIdentity {
    client_id: String,
    organization_id: String,
    purpose: String,
    policy: Value,
    trust_profile: Value,
    component: Value,
}

impl GovernanceSnapshot {
    fn parse(raw: &str) -> Result<Self, GovernanceError> {
        let value: Value =
            serde_json::from_str(raw).map_err(|_| GovernanceError::InvalidSnapshot)?;
        let identity: SnapshotIdentity =
            serde_json::from_value(value.clone()).map_err(|_| GovernanceError::InvalidSnapshot)?;
        if identity.client_id.is_empty()
            || identity.organization_id.is_empty()
            || identity.purpose.is_empty()
            || !identity.policy.is_object()
            || !identity.trust_profile.is_object()
            || !identity.component.is_object()
        {
            return Err(GovernanceError::InvalidSnapshot);
        }
        Ok(Self {
            value,
            client_id: identity.client_id,
            organization_id: identity.organization_id,
            purpose: identity.purpose,
        })
    }

    #[must_use]
    pub fn value(&self) -> &Value {
        &self.value
    }

    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    #[must_use]
    pub fn organization_id(&self) -> &str {
        &self.organization_id
    }

    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    pub fn require_purpose(&self, purpose: GovernancePurpose) -> Result<(), GovernanceError> {
        let request = json!({"snapshot": self.value(), "purpose": purpose.as_str()});
        require_governance_purpose_json(&request.to_string())
            .map_err(|_| GovernanceError::PolicyMismatch)
    }

    pub fn validate_request(
        &self,
        verifier_id: &str,
        presentation_definition: &Value,
    ) -> Result<(), GovernanceError> {
        let request = json!({
            "snapshot": self.value(),
            "verifier_id": verifier_id,
            "presentation_definition": presentation_definition,
        });
        validate_governance_request_json(&request.to_string())
            .map_err(|_| GovernanceError::PolicyMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        serde_json::from_str(marty_verification::governance::behavior_fixture_json()).unwrap()
    }

    #[test]
    fn canonical_core_owns_authorization_and_request_binding() {
        let fixture = fixture();
        let engine = GovernanceEngine::new(&fixture["governance"].to_string()).unwrap();
        let snapshot = engine
            .authorize("purpose-scoped-test-key", GovernancePurpose::Direct)
            .unwrap();

        assert_eq!(snapshot.client_id(), "employee-verifier");
        assert_eq!(
            snapshot.organization_id(),
            "123e4567-e89b-42d3-a456-426614174000"
        );
        assert_eq!(snapshot.purpose(), GovernancePurpose::Direct.as_str());
        snapshot.require_purpose(GovernancePurpose::Direct).unwrap();
        snapshot
            .validate_request("did:web:verifier.example", &fixture["definition"])
            .unwrap();
    }

    #[test]
    fn authorization_and_policy_mismatches_fail_closed() {
        let fixture = fixture();
        let engine = GovernanceEngine::new(&fixture["governance"].to_string()).unwrap();
        assert_eq!(
            engine.authorize("wrong", GovernancePurpose::Direct),
            Err(GovernanceError::Unauthorized)
        );
        let snapshot = engine
            .authorize("purpose-scoped-test-key", GovernancePurpose::Direct)
            .unwrap();
        assert_eq!(
            snapshot.require_purpose(GovernancePurpose::VdsNc),
            Err(GovernanceError::PolicyMismatch)
        );
        assert_eq!(
            snapshot.validate_request("did:web:other.example", &fixture["definition"]),
            Err(GovernanceError::PolicyMismatch)
        );
    }

    #[test]
    fn resume_revalidates_the_persisted_snapshot_against_current_governance() {
        let fixture = fixture();
        let engine = GovernanceEngine::new(&fixture["governance"].to_string()).unwrap();
        let snapshot = engine
            .authorize("purpose-scoped-test-key", GovernancePurpose::Direct)
            .unwrap();
        assert_eq!(engine.resume(&snapshot).unwrap(), snapshot);

        let mut rotated = fixture["governance"].clone();
        rotated["clients"][0]["client_id"] = json!("rotated-verifier");
        let rotated = GovernanceEngine::new(&rotated.to_string()).unwrap();
        assert_eq!(
            rotated.resume(&snapshot),
            Err(GovernanceError::InvalidSnapshot)
        );
    }

    #[test]
    fn malformed_registry_is_rejected_before_serving() {
        assert!(matches!(
            GovernanceEngine::new("{}"),
            Err(GovernanceError::Configuration)
        ));
    }
}
