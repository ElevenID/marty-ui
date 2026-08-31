use std::{collections::BTreeMap, fmt};

use marty_verification::{
    governance::canonical_digest_json,
    verification::{VerificationCheckOutcome, VerificationDecisionResult},
};
use serde_json::{json, Map, Value};
use thiserror::Error;

use super::{GovernanceSnapshot, Sha256Digest};

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
    #[error("canonical evidence-record digest is inconsistent")]
    DigestMismatch,
    #[error("canonical evidence serialization failed")]
    Serialization,
    #[error("a verified terminal decision requires canonical Core evidence")]
    CanonicalRequired,
}

/// Opaque, claim-free evidence permitted at the durable session boundary.
///
/// Constructors accept only Core's immutable decision type and a Core-validated
/// governance snapshot. No arbitrary JSON constructor is exposed.
#[derive(Clone, PartialEq)]
pub struct PersistedEvidence(Value);

impl fmt::Debug for PersistedEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PersistedEvidence([VALIDATED AND MINIMIZED])")
    }
}

impl PersistedEvidence {
    #[must_use]
    pub fn pending(governance: &GovernanceSnapshot) -> Self {
        Self(json!({
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "state": "PENDING",
            "governance": governance.value(),
        }))
    }

    pub fn canonical(
        governance: &GovernanceSnapshot,
        result: &VerificationDecisionResult,
    ) -> Result<Self, PersistedEvidenceError> {
        validate_typed_binding(governance, result)?;
        let records = result
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
            .collect::<Vec<_>>();
        let records_json =
            serde_json::to_string(&records).map_err(|_| PersistedEvidenceError::Serialization)?;
        let digest = canonical_digest_json(&records_json)
            .map_err(|_| PersistedEvidenceError::Serialization)?;
        if digest != result.evidence_digest() {
            return Err(PersistedEvidenceError::DigestMismatch);
        }
        Ok(Self(json!({
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "governance": governance.value(),
            "canonical_result": result,
            "evidence_records": records,
        })))
    }

    #[must_use]
    pub fn fail_closed(digest: &Sha256Digest, reason: EvidenceFailureReason) -> Self {
        Self(json!({
            "schema_version": 1,
            "legacy": true,
            "reason_code": reason.as_str(),
            "presentation_sha256": digest.as_str(),
        }))
    }

    #[must_use]
    pub(crate) fn as_value(&self) -> &Value {
        &self.0
    }

    pub(crate) fn from_database(value: Value) -> Self {
        if valid_persisted_value(&value) {
            Self(value)
        } else {
            // Never return or re-persist untrusted historical JSON. It may
            // contain credential-bearing material from older deployments.
            Self(json!({
                "schema_version": 1,
                "legacy": true,
                "reason_code": "INVALID_PERSISTED_EVIDENCE",
            }))
        }
    }

    pub(crate) fn is_canonical(&self) -> bool {
        self.0
            .as_object()
            .is_some_and(|object| object.contains_key("canonical_result"))
            && valid_persisted_value(&self.0)
    }
}

fn validate_typed_binding(
    governance: &GovernanceSnapshot,
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
    if context.organization_id.as_deref() != Some(governance.organization_id())
        || context.verifier_id != governance.policy().verifier_id()
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
    {
        return Err(PersistedEvidenceError::AuthorityMismatch);
    }
    Ok(())
}

fn valid_persisted_value(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    match object.get("schema_version").and_then(Value::as_u64) {
        Some(EVIDENCE_SCHEMA_VERSION) if object.get("state") == Some(&json!("PENDING")) => {
            exact_keys(object, &["schema_version", "state", "governance"])
                && validated_governance(object).is_some()
        }
        Some(EVIDENCE_SCHEMA_VERSION) => valid_canonical_value(object),
        Some(1) => valid_legacy_value(object),
        _ => false,
    }
}

fn valid_canonical_value(object: &Map<String, Value>) -> bool {
    if !exact_keys(
        object,
        &[
            "schema_version",
            "governance",
            "canonical_result",
            "evidence_records",
        ],
    ) {
        return false;
    }
    let Some(governance) = validated_governance(object) else {
        return false;
    };
    let Some(result) = object.get("canonical_result").and_then(Value::as_object) else {
        return false;
    };
    let Some(records) = object.get("evidence_records").and_then(Value::as_array) else {
        return false;
    };
    if !exact_keys(
        result,
        &[
            "schema_version",
            "verification_id",
            "context",
            "processing_status",
            "decision",
            "decision_code",
            "valid",
            "evaluated_at",
            "input_digest",
            "evidence_digest",
            "policy",
            "trust_profile",
            "reducer",
            "components",
            "checks",
            "category_summaries",
        ],
    ) {
        return false;
    }
    let context_matches = result
        .get("context")
        .and_then(Value::as_object)
        .is_some_and(|context| {
            context.get("organization_id").and_then(Value::as_str)
                == Some(governance.organization_id())
                && context.get("verifier_id").and_then(Value::as_str)
                    == Some(governance.policy().verifier_id())
        });
    if !context_matches
        || result.get("policy")
            != serde_json::to_value(governance.policy().reference())
                .ok()
                .as_ref()
        || result.get("trust_profile")
            != serde_json::to_value(governance.trust_profile().reference())
                .ok()
                .as_ref()
        || result.get("components").and_then(Value::as_array)
            != Some(&vec![
                serde_json::to_value(governance.component()).unwrap_or(Value::Null)
            ])
    {
        return false;
    }
    let Some(checks) = result.get("checks").and_then(Value::as_array) else {
        return false;
    };
    let expected_checks = governance.policy().required_checks();
    if checks.len() != expected_checks.len()
        || checks.iter().zip(expected_checks).any(|(check, expected)| {
            check.get("check_id").and_then(Value::as_str) != Some(expected)
                || check.as_object().is_none_or(|check| {
                    !exact_keys(
                        check,
                        &[
                            "check_id",
                            "category",
                            "required",
                            "outcome",
                            "code",
                            "component_id",
                            "evaluated_at",
                            "evidence_refs",
                        ],
                    )
                })
        })
    {
        return false;
    }
    let mut records_by_id = BTreeMap::new();
    for record in records {
        let Some(record) = record.as_object() else {
            return false;
        };
        if !exact_keys(record, &["id", "check_id", "outcome", "code"])
            || record.values().any(|value| !value.is_string())
        {
            return false;
        }
        let Some(id) = record.get("id").and_then(Value::as_str) else {
            return false;
        };
        if records_by_id.insert(id, record).is_some() {
            return false;
        }
    }
    let mut referenced = Vec::new();
    for check in checks {
        let Some(check) = check.as_object() else {
            return false;
        };
        let refs = check
            .get("evidence_refs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten();
        for evidence_ref in refs {
            let Some(evidence_ref) = evidence_ref.as_str() else {
                return false;
            };
            let Some(record) = records_by_id.get(evidence_ref) else {
                return false;
            };
            if record.get("check_id") != check.get("check_id")
                || record.get("outcome") != check.get("outcome")
                || record.get("code") != check.get("code")
            {
                return false;
            }
            referenced.push(evidence_ref);
        }
    }
    referenced.sort_unstable();
    let mut record_ids = records_by_id.keys().copied().collect::<Vec<_>>();
    record_ids.sort_unstable();
    if referenced != record_ids {
        return false;
    }
    serde_json::to_string(records)
        .ok()
        .and_then(|records| canonical_digest_json(&records).ok())
        .as_deref()
        == result.get("evidence_digest").and_then(Value::as_str)
}

fn validated_governance(object: &Map<String, Value>) -> Option<GovernanceSnapshot> {
    GovernanceSnapshot::validate_frozen_evidence(object.get("governance")?.clone()).ok()
}

fn valid_legacy_value(object: &Map<String, Value>) -> bool {
    let keys_with_digest = [
        "schema_version",
        "legacy",
        "reason_code",
        "presentation_sha256",
    ];
    let reason = object.get("reason_code").and_then(Value::as_str);
    object.get("legacy") == Some(&Value::Bool(true))
        && matches!(
            reason,
            Some("MISSING_GOVERNANCE_PROVENANCE" | "CANONICAL_RESULT_BUILD_FAILED")
        )
        && exact_keys(object, &keys_with_digest)
        && object
            .get("presentation_sha256")
            .and_then(Value::as_str)
            .is_some_and(|value| Sha256Digest::parse(value).is_ok())
}

fn exact_keys(object: &Map<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

#[cfg(test)]
mod tests {
    use marty_verification::governance::behavior_fixture_json;

    use super::*;
    use crate::credentials_compat::{GovernanceEngine, GovernancePurpose};

    fn governance() -> GovernanceSnapshot {
        let fixture: Value = serde_json::from_str(behavior_fixture_json()).unwrap();
        GovernanceEngine::new(&fixture["governance"].to_string())
            .unwrap()
            .authorize("purpose-scoped-test-key", GovernancePurpose::Direct)
            .unwrap()
    }

    #[test]
    fn pending_and_fail_closed_evidence_have_fixed_claim_free_shapes() {
        let pending = PersistedEvidence::pending(&governance());
        assert!(valid_persisted_value(pending.as_value()));
        assert_eq!(pending.as_value().as_object().unwrap().len(), 3);

        let raw = "raw.presentation.secret";
        let failed = PersistedEvidence::fail_closed(
            &Sha256Digest::calculate(raw),
            EvidenceFailureReason::CanonicalResultBuildFailed,
        );
        assert!(valid_persisted_value(failed.as_value()));
        let encoded = failed.as_value().to_string();
        assert!(!encoded.contains(raw));
        assert!(!encoded.contains("credential"));
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
