use std::{fmt, sync::Arc};

use marty_verification::governance::{
    authorize_governance_json, governance_from_snapshot_json, require_governance_purpose_json,
    resume_governance_json, validate_governance_json, validate_governance_request_json,
    ComponentReference, ProfileReference,
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
#[derive(Clone)]
pub struct GovernanceEngine {
    registry: Arc<Value>,
}

impl fmt::Debug for GovernanceEngine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernanceEngine")
            .field("registry", &"[VALIDATED AND REDACTED]")
            .finish()
    }
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

    /// Validate an untrusted persisted value in Core, then re-authorize it
    /// against the current registry before use.
    pub fn resume_value(&self, value: Value) -> Result<GovernanceSnapshot, GovernanceError> {
        self.resume(&GovernanceSnapshot::from_persisted(value)?)
    }
}

/// A Core-validated, secret-free authority snapshot safe to persist.
#[derive(Clone, Debug, PartialEq)]
pub struct GovernanceSnapshot {
    value: Value,
    client_id: String,
    organization_id: String,
    purpose: String,
    policy: PolicyAuthority,
    trust_profile: TrustAuthority,
    component: ComponentReference,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct SnapshotIdentity {
    client_id: String,
    organization_id: String,
    purpose: String,
    policy: PolicyAuthority,
    trust_profile: TrustAuthority,
    component: ComponentReference,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuthority {
    #[serde(flatten)]
    reference: ProfileReference,
    content: PolicyContent,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct PolicyContent {
    verifier_id: String,
    presentation_definition_digest: String,
    required_checks: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrustAuthority {
    #[serde(flatten)]
    reference: ProfileReference,
    content: TrustContent,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct TrustContent {
    trusted_issuers: Vec<String>,
    allow_public_did_fallback: bool,
}

impl GovernanceSnapshot {
    fn from_persisted(value: Value) -> Result<Self, GovernanceError> {
        let request = json!({"snapshot": value});
        let validated = governance_from_snapshot_json(&request.to_string())
            .map_err(|_| GovernanceError::InvalidSnapshot)?;
        Self::parse(&validated)
    }

    fn parse(raw: &str) -> Result<Self, GovernanceError> {
        let value: Value =
            serde_json::from_str(raw).map_err(|_| GovernanceError::InvalidSnapshot)?;
        let identity: SnapshotIdentity =
            serde_json::from_value(value.clone()).map_err(|_| GovernanceError::InvalidSnapshot)?;
        if identity.client_id.is_empty()
            || identity.organization_id.is_empty()
            || identity.purpose.is_empty()
        {
            return Err(GovernanceError::InvalidSnapshot);
        }
        Ok(Self {
            value,
            client_id: identity.client_id,
            organization_id: identity.organization_id,
            purpose: identity.purpose,
            policy: identity.policy,
            trust_profile: identity.trust_profile,
            component: identity.component,
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

    #[must_use]
    pub fn policy(&self) -> &PolicyAuthority {
        &self.policy
    }

    #[must_use]
    pub fn trust_profile(&self) -> &TrustAuthority {
        &self.trust_profile
    }

    #[must_use]
    pub fn component(&self) -> &ComponentReference {
        &self.component
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

impl PolicyAuthority {
    #[must_use]
    pub fn reference(&self) -> &ProfileReference {
        &self.reference
    }

    #[must_use]
    pub fn verifier_id(&self) -> &str {
        &self.content.verifier_id
    }

    #[must_use]
    pub fn presentation_definition_digest(&self) -> &str {
        &self.content.presentation_definition_digest
    }

    #[must_use]
    pub fn required_checks(&self) -> &[String] {
        &self.content.required_checks
    }
}

impl TrustAuthority {
    #[must_use]
    pub fn reference(&self) -> &ProfileReference {
        &self.reference
    }

    #[must_use]
    pub fn trusted_issuers(&self) -> &[String] {
        &self.content.trusted_issuers
    }

    #[must_use]
    pub const fn allow_public_did_fallback(&self) -> bool {
        self.content.allow_public_did_fallback
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
        assert_eq!(snapshot.policy().reference().id, "policy:employee");
        assert_eq!(snapshot.policy().verifier_id(), "did:web:verifier.example");
        assert_eq!(snapshot.policy().required_checks().len(), 8);
        assert_eq!(
            snapshot.trust_profile().trusted_issuers(),
            ["did:web:issuer.example"]
        );
        assert!(!snapshot.trust_profile().allow_public_did_fallback());
        assert_eq!(snapshot.component().component_id, "marty-credentials");
        snapshot.require_purpose(GovernancePurpose::Direct).unwrap();
        snapshot
            .validate_request("did:web:verifier.example", &fixture["definition"])
            .unwrap();
    }

    #[test]
    fn every_released_purpose_is_selected_by_the_typed_boundary() {
        let mut fixture = fixture();
        let direct = fixture["governance"]["clients"][0]["purposes"]["verification.direct"].clone();
        fixture["governance"]["clients"][0]["purposes"]["verification.vds-nc"] = direct;
        let engine = GovernanceEngine::new(&fixture["governance"].to_string()).unwrap();

        for purpose in [
            GovernancePurpose::SessionCreate,
            GovernancePurpose::Direct,
            GovernancePurpose::VdsNc,
        ] {
            let snapshot = engine
                .authorize("purpose-scoped-test-key", purpose)
                .unwrap();
            assert_eq!(snapshot.purpose(), purpose.as_str());
            snapshot.require_purpose(purpose).unwrap();
        }
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
        assert_eq!(
            snapshot.validate_request(
                "did:web:verifier.example",
                &json!({"id": "different", "input_descriptors": []})
            ),
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
        assert_eq!(
            engine.resume_value(snapshot.value().clone()).unwrap(),
            snapshot
        );

        let mut rotated = fixture["governance"].clone();
        rotated["clients"][0]["client_id"] = json!("rotated-verifier");
        let rotated = GovernanceEngine::new(&rotated.to_string()).unwrap();
        assert_eq!(
            rotated.resume_value(snapshot.value().clone()),
            Err(GovernanceError::InvalidSnapshot)
        );
    }

    #[test]
    fn persisted_snapshots_are_core_validated_and_component_rotation_is_positive() {
        let fixture = fixture();
        let engine = GovernanceEngine::new(&fixture["governance"].to_string()).unwrap();
        let snapshot = engine
            .authorize("purpose-scoped-test-key", GovernancePurpose::Direct)
            .unwrap();

        let mut tampered = snapshot.value().clone();
        tampered["policy"]["content"]["verifier_id"] = json!("did:web:attacker.example");
        assert_eq!(
            engine.resume_value(tampered),
            Err(GovernanceError::InvalidSnapshot)
        );

        let mut rotated = fixture["governance"].clone();
        rotated["component"]["version"] = json!("0.1.62");
        rotated["component"]["artifact_digest"] = json!(format!("sha256:{}", "2".repeat(64)));
        let rotated = GovernanceEngine::new(&rotated.to_string()).unwrap();
        let resumed = rotated.resume_value(snapshot.value().clone()).unwrap();
        assert_eq!(resumed.component().version, "0.1.62");
        assert_eq!(resumed.policy(), snapshot.policy());
        assert_eq!(resumed.trust_profile(), snapshot.trust_profile());
    }

    #[test]
    fn malformed_registry_is_rejected_before_serving() {
        assert!(matches!(
            GovernanceEngine::new("{}"),
            Err(GovernanceError::Configuration)
        ));
    }

    #[test]
    fn debug_output_never_exposes_registry_key_digests() {
        let fixture = fixture();
        let digest = fixture["governance"]["clients"][0]["api_key_sha256"]
            .as_str()
            .unwrap();
        let engine = GovernanceEngine::new(&fixture["governance"].to_string()).unwrap();
        let debug = format!("{engine:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains(digest));
        assert!(!debug.contains("purpose-scoped-test-key"));
    }
}
