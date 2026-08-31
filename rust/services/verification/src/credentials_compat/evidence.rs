use std::fmt;

use marty_verification::{
    governance::canonical_digest_json,
    verification::{
        build_verification_decision_result, VerificationCheckOutcome, VerificationContextMode,
        VerificationDecision, VerificationDecisionResult, VerificationDecisionResultInput,
        VerificationProcessingStatus,
    },
};
use serde_json::{json, Map, Value};
use thiserror::Error;

use super::{GovernancePurpose, GovernanceSnapshot, Sha256Digest};

const EVIDENCE_SCHEMA_VERSION: u64 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceFailureReason {
    MissingGovernanceProvenance,
    CanonicalResultBuildFailed,
}

impl EvidenceFailureReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::MissingGovernanceProvenance => "MISSING_GOVERNANCE_PROVENANCE",
            Self::CanonicalResultBuildFailed => "CANONICAL_RESULT_BUILD_FAILED",
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PersistedEvidenceError {
    #[error("canonical evidence is not bound to its governed authority")]
    AuthorityMismatch,
    #[error("canonical evidence is not bound to the session")]
    SessionMismatch,
    #[error("canonical evidence is not bound to the submitted presentation")]
    PresentationMismatch,
    #[error("canonical evidence-record digest is inconsistent")]
    DigestMismatch,
    #[error("canonical evidence serialization failed")]
    Serialization,
    #[error("a verified terminal decision requires a canonical Core PASS")]
    CanonicalPassRequired,
    #[error("a failed terminal decision cannot contain a canonical Core PASS")]
    FailureEvidenceRequired,
    #[error("persisted evidence is invalid for a terminal decision")]
    InvalidTerminalEvidence,
}

#[derive(Clone, Debug, PartialEq)]
enum EvidenceKind {
    Pending {
        governance: GovernanceSnapshot,
    },
    Canonical {
        governance: GovernanceSnapshot,
        session_id: String,
        presentation_digest: Sha256Digest,
        passed: bool,
    },
    FailClosed {
        presentation_digest: Sha256Digest,
    },
    Invalid,
}

/// Opaque, claim-free evidence permitted at the durable session boundary.
///
/// Constructors accept only Core's immutable decision type and a Core-validated
/// governance snapshot. Database values are re-derived through Core before they
/// may participate in a terminal transition.
#[derive(Clone, PartialEq)]
pub struct PersistedEvidence {
    value: Value,
    kind: EvidenceKind,
}

impl fmt::Debug for PersistedEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PersistedEvidence([VALIDATED AND MINIMIZED])")
    }
}

impl PersistedEvidence {
    #[must_use]
    pub fn pending(governance: &GovernanceSnapshot) -> Self {
        Self {
            value: json!({
                "schema_version": EVIDENCE_SCHEMA_VERSION,
                "state": "PENDING",
                "governance": governance.value(),
            }),
            kind: EvidenceKind::Pending {
                governance: governance.clone(),
            },
        }
    }

    pub fn canonical(
        governance: &GovernanceSnapshot,
        session_id: &str,
        presentation_digest: &Sha256Digest,
        result: &VerificationDecisionResult,
    ) -> Result<Self, PersistedEvidenceError> {
        validate_typed_binding(governance, session_id, presentation_digest, result)?;
        let records = evidence_records(result);
        validate_evidence_digest(&records, result.evidence_digest())?;
        let passed = canonical_passed(result);
        Ok(Self {
            value: json!({
                "schema_version": EVIDENCE_SCHEMA_VERSION,
                "governance": governance.value(),
                "canonical_result": result,
                "evidence_records": records,
            }),
            kind: EvidenceKind::Canonical {
                governance: governance.clone(),
                session_id: session_id.to_owned(),
                presentation_digest: presentation_digest.clone(),
                passed,
            },
        })
    }

    #[must_use]
    pub fn fail_closed(digest: &Sha256Digest, reason: EvidenceFailureReason) -> Self {
        Self {
            value: json!({
                "schema_version": 1,
                "legacy": true,
                "reason_code": reason.as_str(),
                "presentation_sha256": digest.as_str(),
            }),
            kind: EvidenceKind::FailClosed {
                presentation_digest: digest.clone(),
            },
        }
    }

    #[must_use]
    pub(crate) fn as_value(&self) -> &Value {
        &self.value
    }

    pub(crate) fn from_database(value: Value) -> Self {
        parse_persisted_value(value).unwrap_or_else(invalid_evidence)
    }

    pub(crate) fn require_verified(&self) -> Result<(), PersistedEvidenceError> {
        match self.kind {
            EvidenceKind::Canonical { passed: true, .. } => Ok(()),
            _ => Err(PersistedEvidenceError::CanonicalPassRequired),
        }
    }

    pub(crate) fn require_failed(&self) -> Result<(), PersistedEvidenceError> {
        match self.kind {
            EvidenceKind::Canonical { passed: false, .. } | EvidenceKind::FailClosed { .. } => {
                Ok(())
            }
            EvidenceKind::Canonical { passed: true, .. } => {
                Err(PersistedEvidenceError::FailureEvidenceRequired)
            }
            EvidenceKind::Pending { .. } | EvidenceKind::Invalid => {
                Err(PersistedEvidenceError::InvalidTerminalEvidence)
            }
        }
    }

    pub(crate) fn validate_terminal_binding(
        &self,
        session_id: &str,
        presentation_digest: &Sha256Digest,
    ) -> Result<(), PersistedEvidenceError> {
        let (bound_session, bound_digest) = match &self.kind {
            EvidenceKind::Canonical {
                session_id,
                presentation_digest,
                ..
            } => (Some(session_id.as_str()), presentation_digest),
            EvidenceKind::FailClosed {
                presentation_digest,
            } => (None, presentation_digest),
            EvidenceKind::Pending { .. } | EvidenceKind::Invalid => {
                return Err(PersistedEvidenceError::InvalidTerminalEvidence);
            }
        };
        if bound_session.is_some_and(|bound| bound != session_id) {
            return Err(PersistedEvidenceError::SessionMismatch);
        }
        if bound_digest != presentation_digest {
            return Err(PersistedEvidenceError::PresentationMismatch);
        }
        Ok(())
    }

    pub(crate) fn validate_session_authority(
        &self,
        pending: &Self,
        organization_id: &str,
        verifier_did: &str,
        presentation_definition: &Value,
    ) -> Result<(), PersistedEvidenceError> {
        let EvidenceKind::Pending {
            governance: pending_governance,
        } = &pending.kind
        else {
            return Err(PersistedEvidenceError::InvalidTerminalEvidence);
        };
        if pending_governance.organization_id() != organization_id
            || pending_governance
                .require_purpose(GovernancePurpose::SessionCreate)
                .is_err()
            || pending_governance
                .validate_request(verifier_did, presentation_definition)
                .is_err()
        {
            return Err(PersistedEvidenceError::AuthorityMismatch);
        }
        if let EvidenceKind::Canonical { governance, .. } = &self.kind {
            if governance != pending_governance {
                return Err(PersistedEvidenceError::AuthorityMismatch);
            }
        }
        Ok(())
    }
}

fn parse_persisted_value(value: Value) -> Option<PersistedEvidence> {
    let object = value.as_object()?;
    let schema_version = object.get("schema_version").and_then(Value::as_u64);
    let pending = object.get("state") == Some(&json!("PENDING"));
    match (schema_version, pending) {
        (Some(EVIDENCE_SCHEMA_VERSION), true) => parse_pending(value),
        (Some(EVIDENCE_SCHEMA_VERSION), false) => parse_canonical(value),
        (Some(1), _) => parse_fail_closed(value),
        _ => None,
    }
}

fn parse_pending(value: Value) -> Option<PersistedEvidence> {
    let object = value.as_object()?;
    if !exact_keys(object, &["schema_version", "state", "governance"]) {
        return None;
    }
    let governance = validated_governance(object)?;
    Some(PersistedEvidence {
        value,
        kind: EvidenceKind::Pending { governance },
    })
}

fn parse_canonical(value: Value) -> Option<PersistedEvidence> {
    let object = value.as_object()?;
    if !exact_keys(
        object,
        &[
            "schema_version",
            "governance",
            "canonical_result",
            "evidence_records",
        ],
    ) {
        return None;
    }
    let governance = validated_governance(object)?;
    let raw_result = object.get("canonical_result")?;
    let result = rebuild_canonical_result(raw_result)?;
    if serde_json::to_value(&result).ok().as_ref() != Some(raw_result) {
        return None;
    }
    let session_id = result
        .verification_id()
        .strip_prefix("verification:")?
        .to_owned();
    let digest = Sha256Digest::parse(result.input_digest().strip_prefix("sha256:")?).ok()?;
    validate_typed_binding(&governance, &session_id, &digest, &result).ok()?;
    let records = evidence_records(&result);
    if object.get("evidence_records") != Some(&Value::Array(records.clone())) {
        return None;
    }
    validate_evidence_digest(&records, result.evidence_digest()).ok()?;
    let passed = canonical_passed(&result);
    Some(PersistedEvidence {
        value,
        kind: EvidenceKind::Canonical {
            governance,
            session_id,
            presentation_digest: digest,
            passed,
        },
    })
}

fn rebuild_canonical_result(raw: &Value) -> Option<VerificationDecisionResult> {
    let raw = raw.as_object()?;
    let input = json!({
        "verification_id": raw.get("verification_id")?,
        "context": raw.get("context")?,
        "processing_status": raw.get("processing_status")?,
        "evaluated_at": raw.get("evaluated_at")?,
        "input_digest": raw.get("input_digest")?,
        "evidence_digest": raw.get("evidence_digest")?,
        "policy": raw.get("policy")?,
        "trust_profile": raw.get("trust_profile")?,
        "components": raw.get("components")?,
        "checks": raw.get("checks")?,
    });
    let input: VerificationDecisionResultInput = serde_json::from_value(input).ok()?;
    build_verification_decision_result(input).ok()
}

fn parse_fail_closed(value: Value) -> Option<PersistedEvidence> {
    let object = value.as_object()?;
    if !exact_keys(
        object,
        &[
            "schema_version",
            "legacy",
            "reason_code",
            "presentation_sha256",
        ],
    ) || object.get("legacy") != Some(&Value::Bool(true))
        || !matches!(
            object.get("reason_code").and_then(Value::as_str),
            Some("MISSING_GOVERNANCE_PROVENANCE" | "CANONICAL_RESULT_BUILD_FAILED")
        )
    {
        return None;
    }
    let digest = Sha256Digest::parse(object.get("presentation_sha256")?.as_str()?).ok()?;
    Some(PersistedEvidence {
        value,
        kind: EvidenceKind::FailClosed {
            presentation_digest: digest,
        },
    })
}

fn invalid_evidence() -> PersistedEvidence {
    PersistedEvidence {
        value: json!({
            "schema_version": 1,
            "legacy": true,
            "reason_code": "INVALID_PERSISTED_EVIDENCE",
        }),
        kind: EvidenceKind::Invalid,
    }
}

fn validate_typed_binding(
    governance: &GovernanceSnapshot,
    session_id: &str,
    presentation_digest: &Sha256Digest,
    result: &VerificationDecisionResult,
) -> Result<(), PersistedEvidenceError> {
    let context = result.context();
    let component = governance.component();
    let result_component = result.components().first();
    let check_ids = result
        .checks()
        .iter()
        .map(|check| check.check_id.as_str())
        .collect::<Vec<_>>();
    if context.mode != VerificationContextMode::Online
        || context.organization_id.as_deref() != Some(governance.organization_id())
        || context.verifier_id != governance.policy().verifier_id()
        || context.audience.as_deref() != Some(governance.policy().verifier_id())
        || context.offline_profile_id.is_some()
        || result.policy().id != governance.policy().reference().id
        || result.policy().version != governance.policy().reference().version
        || result.policy().content_digest != governance.policy().reference().content_digest
        || result.trust_profile().id != governance.trust_profile().reference().id
        || result.trust_profile().version != governance.trust_profile().reference().version
        || result.trust_profile().content_digest
            != governance.trust_profile().reference().content_digest
        || result.components().len() != 1
        || result_component.is_none_or(|value| {
            value.component_id != component.component_id
                || value.version != component.version
                || value.artifact_digest != component.artifact_digest
                || value.adapter_id.as_deref() != Some(component.adapter_id.as_str())
                || value.adapter_version.as_deref() != Some(component.adapter_version.as_str())
        })
        || check_ids
            != governance
                .policy()
                .required_checks()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        || result.checks().iter().any(|check| !check.required)
    {
        return Err(PersistedEvidenceError::AuthorityMismatch);
    }
    if result.verification_id() != format!("verification:{session_id}")
        || context.transaction_id.as_deref() != Some(session_id)
    {
        return Err(PersistedEvidenceError::SessionMismatch);
    }
    if result.input_digest() != format!("sha256:{}", presentation_digest.as_str()) {
        return Err(PersistedEvidenceError::PresentationMismatch);
    }
    Ok(())
}

fn canonical_passed(result: &VerificationDecisionResult) -> bool {
    result.processing_status() == VerificationProcessingStatus::Completed
        && result.decision() == VerificationDecision::Pass
        && result.is_valid()
}

fn evidence_records(result: &VerificationDecisionResult) -> Vec<Value> {
    result
        .checks()
        .iter()
        .filter(|check| {
            matches!(
                check.outcome,
                VerificationCheckOutcome::Passed | VerificationCheckOutcome::Failed
            )
        })
        .flat_map(|check| {
            check.evidence_refs.iter().map(|evidence_ref| {
                json!({
                    "id": evidence_ref,
                    "check_id": check.check_id,
                    "outcome": check.outcome,
                    "code": check.code,
                })
            })
        })
        .collect()
}

fn validate_evidence_digest(
    records: &[Value],
    expected: &str,
) -> Result<(), PersistedEvidenceError> {
    let records_json =
        serde_json::to_string(records).map_err(|_| PersistedEvidenceError::Serialization)?;
    let digest =
        canonical_digest_json(&records_json).map_err(|_| PersistedEvidenceError::Serialization)?;
    if digest != expected {
        return Err(PersistedEvidenceError::DigestMismatch);
    }
    Ok(())
}

fn validated_governance(object: &Map<String, Value>) -> Option<GovernanceSnapshot> {
    GovernanceSnapshot::validate_frozen_evidence(object.get("governance")?.clone()).ok()
}

fn exact_keys(object: &Map<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

#[cfg(test)]
mod tests {
    use marty_verification::{
        governance::{behavior_fixture_json, canonical_digest_json},
        verification::{
            build_verification_decision_result, VerificationCheckCategory,
            VerificationCheckOutcome, VerificationCheckResult, VerificationComponentVersion,
            VerificationContextMode, VerificationDecisionContext, VerificationDecisionResultInput,
            VerificationProcessingStatus, VerificationProfileReference,
        },
    };

    use super::*;
    use crate::credentials_compat::{GovernanceEngine, GovernancePurpose};

    const SESSION_ID: &str = "session-001";

    fn governance_for(purpose: GovernancePurpose) -> GovernanceSnapshot {
        let fixture: Value = serde_json::from_str(behavior_fixture_json()).unwrap();
        GovernanceEngine::new(&fixture["governance"].to_string())
            .unwrap()
            .authorize("purpose-scoped-test-key", purpose)
            .unwrap()
    }

    fn governance() -> GovernanceSnapshot {
        governance_for(GovernancePurpose::SessionCreate)
    }

    fn presentation_definition() -> Value {
        let fixture: Value = serde_json::from_str(behavior_fixture_json()).unwrap();
        fixture["definition"].clone()
    }

    fn canonical_input(
        governance: &GovernanceSnapshot,
        digest: &Sha256Digest,
        failed: bool,
    ) -> VerificationDecisionResultInput {
        let evaluated_at = "2026-08-30T12:00:00Z";
        let checks = governance
            .policy()
            .required_checks()
            .iter()
            .enumerate()
            .map(|(index, check_id)| VerificationCheckResult {
                check_id: check_id.clone(),
                category: VerificationCheckCategory::Policy,
                required: true,
                outcome: if failed && index == 0 {
                    VerificationCheckOutcome::Failed
                } else {
                    VerificationCheckOutcome::Passed
                },
                code: if failed && index == 0 {
                    "CHECK_FAILED".into()
                } else {
                    "CHECK_PASSED".into()
                },
                component_id: governance.component().component_id.clone(),
                evaluated_at: evaluated_at.into(),
                evidence_refs: vec![format!(
                    "urn:marty:evidence:123e4567-e89b-42d3-a456-{index:012}"
                )],
            })
            .collect::<Vec<_>>();
        VerificationDecisionResultInput {
            verification_id: format!("verification:{SESSION_ID}"),
            context: VerificationDecisionContext {
                mode: VerificationContextMode::Online,
                verifier_id: governance.policy().verifier_id().into(),
                organization_id: Some(governance.organization_id().into()),
                transaction_id: Some(SESSION_ID.into()),
                audience: Some(governance.policy().verifier_id().into()),
                offline_profile_id: None,
            },
            processing_status: VerificationProcessingStatus::Completed,
            evaluated_at: evaluated_at.into(),
            input_digest: format!("sha256:{}", digest.as_str()),
            evidence_digest: format!("sha256:{}", "0".repeat(64)),
            policy: VerificationProfileReference {
                id: governance.policy().reference().id.clone(),
                version: governance.policy().reference().version.clone(),
                content_digest: governance.policy().reference().content_digest.clone(),
            },
            trust_profile: VerificationProfileReference {
                id: governance.trust_profile().reference().id.clone(),
                version: governance.trust_profile().reference().version.clone(),
                content_digest: governance
                    .trust_profile()
                    .reference()
                    .content_digest
                    .clone(),
            },
            components: vec![VerificationComponentVersion {
                component_id: governance.component().component_id.clone(),
                version: governance.component().version.clone(),
                artifact_digest: governance.component().artifact_digest.clone(),
                adapter_id: Some(governance.component().adapter_id.clone()),
                adapter_version: Some(governance.component().adapter_version.clone()),
            }],
            checks,
        }
    }

    fn build_result(mut input: VerificationDecisionResultInput) -> VerificationDecisionResult {
        let provisional_result = build_verification_decision_result(input.clone()).unwrap();
        let records = evidence_records(&provisional_result);
        input.evidence_digest =
            canonical_digest_json(&serde_json::to_string(&records).unwrap()).unwrap();
        build_verification_decision_result(input).unwrap()
    }

    fn canonical_result(
        governance: &GovernanceSnapshot,
        digest: &Sha256Digest,
        failed: bool,
    ) -> VerificationDecisionResult {
        build_result(canonical_input(governance, digest, failed))
    }

    #[test]
    fn pending_and_fail_closed_evidence_have_fixed_claim_free_shapes() {
        let pending = PersistedEvidence::pending(&governance());
        assert!(matches!(pending.kind, EvidenceKind::Pending { .. }));
        assert_eq!(pending.as_value().as_object().unwrap().len(), 3);

        let raw = "raw.presentation.secret";
        let digest = Sha256Digest::calculate(raw);
        let failed = PersistedEvidence::fail_closed(
            &digest,
            EvidenceFailureReason::CanonicalResultBuildFailed,
        );
        failed
            .validate_terminal_binding("any-session", &digest)
            .unwrap();
        failed.require_failed().unwrap();
        let encoded = failed.as_value().to_string();
        assert!(!encoded.contains(raw));
        assert!(!encoded.contains("credential"));
    }

    #[test]
    fn canonical_terminal_status_and_bindings_are_enforced() {
        let governance = governance();
        let digest = Sha256Digest::calculate("presentation");
        let passed = PersistedEvidence::canonical(
            &governance,
            SESSION_ID,
            &digest,
            &canonical_result(&governance, &digest, false),
        )
        .unwrap();
        passed.require_verified().unwrap();
        assert_eq!(
            passed.require_failed(),
            Err(PersistedEvidenceError::FailureEvidenceRequired)
        );
        passed
            .validate_terminal_binding(SESSION_ID, &digest)
            .unwrap();
        assert_eq!(
            passed.validate_terminal_binding("other-session", &digest),
            Err(PersistedEvidenceError::SessionMismatch)
        );
        assert_eq!(
            passed.validate_terminal_binding(SESSION_ID, &Sha256Digest::calculate("other")),
            Err(PersistedEvidenceError::PresentationMismatch)
        );

        let failed = PersistedEvidence::canonical(
            &governance,
            SESSION_ID,
            &digest,
            &canonical_result(&governance, &digest, true),
        )
        .unwrap();
        failed.require_failed().unwrap();
        assert_eq!(
            failed.require_verified(),
            Err(PersistedEvidenceError::CanonicalPassRequired)
        );
    }

    #[test]
    fn governed_required_checks_and_online_context_cannot_be_downgraded() {
        let governance = governance();
        let digest = Sha256Digest::calculate("presentation");

        let mut optional_failure = canonical_input(&governance, &digest, true);
        optional_failure.checks[0].required = false;
        let optional_failure = build_result(optional_failure);
        assert!(optional_failure.is_valid());
        assert_eq!(
            PersistedEvidence::canonical(&governance, SESSION_ID, &digest, &optional_failure,),
            Err(PersistedEvidenceError::AuthorityMismatch)
        );

        let mut wrong_audience = canonical_input(&governance, &digest, false);
        wrong_audience.context.audience = Some("did:web:other.example".into());
        assert_eq!(
            PersistedEvidence::canonical(
                &governance,
                SESSION_ID,
                &digest,
                &build_result(wrong_audience),
            ),
            Err(PersistedEvidenceError::AuthorityMismatch)
        );

        let mut offline = canonical_input(&governance, &digest, false);
        offline.context.mode = VerificationContextMode::Offline;
        offline.context.organization_id = None;
        offline.context.transaction_id = None;
        offline.context.audience = None;
        offline.context.offline_profile_id = Some("offline:profile".into());
        assert_eq!(
            PersistedEvidence::canonical(&governance, SESSION_ID, &digest, &build_result(offline),),
            Err(PersistedEvidenceError::AuthorityMismatch)
        );
    }

    #[test]
    fn session_terminal_evidence_must_preserve_creation_authority() {
        let session_governance = governance();
        let other_purpose = governance_for(GovernancePurpose::Direct);
        let digest = Sha256Digest::calculate("presentation");
        let pending = PersistedEvidence::pending(&session_governance);
        let matching = PersistedEvidence::canonical(
            &session_governance,
            SESSION_ID,
            &digest,
            &canonical_result(&session_governance, &digest, false),
        )
        .unwrap();
        matching
            .validate_session_authority(
                &pending,
                session_governance.organization_id(),
                session_governance.policy().verifier_id(),
                &presentation_definition(),
            )
            .unwrap();

        let substituted = PersistedEvidence::canonical(
            &other_purpose,
            SESSION_ID,
            &digest,
            &canonical_result(&other_purpose, &digest, false),
        )
        .unwrap();
        assert_eq!(
            substituted.validate_session_authority(
                &pending,
                session_governance.organization_id(),
                session_governance.policy().verifier_id(),
                &presentation_definition(),
            ),
            Err(PersistedEvidenceError::AuthorityMismatch)
        );
    }

    #[test]
    fn database_canonical_results_are_reduced_again_and_tampering_is_sanitized() {
        let governance = governance();
        let digest = Sha256Digest::calculate("presentation");
        let evidence = PersistedEvidence::canonical(
            &governance,
            SESSION_ID,
            &digest,
            &canonical_result(&governance, &digest, false),
        )
        .unwrap();
        let reloaded = PersistedEvidence::from_database(evidence.as_value().clone());
        reloaded.require_verified().unwrap();

        for pointer in [
            "decision",
            "valid",
            "decision_code",
            "reducer",
            "category_summaries",
        ] {
            let mut tampered = evidence.as_value().clone();
            tampered["canonical_result"][pointer] = json!("attacker-controlled");
            let sanitized = PersistedEvidence::from_database(tampered);
            assert!(matches!(sanitized.kind, EvidenceKind::Invalid));
            assert_eq!(
                sanitized.as_value()["reason_code"],
                "INVALID_PERSISTED_EVIDENCE"
            );
        }
    }

    #[test]
    fn arbitrary_or_claim_bearing_database_evidence_is_sanitized() {
        for value in [
            json!({"vp_token":"secret.raw.presentation"}),
            json!({"verified_claims":{"ssn":"000-00-0000"}}),
            json!({"schema_version":2,"state":"PENDING","governance":{},"extra":"claim"}),
        ] {
            let evidence = PersistedEvidence::from_database(value);
            let encoded = evidence.as_value().to_string();
            assert_eq!(
                evidence.as_value()["reason_code"],
                "INVALID_PERSISTED_EVIDENCE"
            );
            assert!(!encoded.contains("secret"));
            assert!(!encoded.contains("ssn"));
            assert!(!encoded.contains("claim"));
        }
    }
}
