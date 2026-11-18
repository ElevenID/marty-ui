use std::{collections::BTreeMap, fmt};

use chrono::{SecondsFormat, Utc};
use marty_verification::{
    governance::canonical_digest_json,
    verification::{
        build_verification_decision_result, VerificationCheckCategory, VerificationCheckOutcome,
        VerificationCheckResult, VerificationComponentVersion, VerificationContextMode,
        VerificationDecisionContext, VerificationDecisionResult, VerificationDecisionResultInput,
        VerificationProcessingStatus, VerificationProfileReference,
    },
};
use serde_json::{json, Map, Value};
use thiserror::Error;
use uuid::Uuid;

use super::{GovernanceSnapshot, Sha256Digest};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterFacts {
    pub processing_status: VerificationProcessingStatus,
    pub presentation_structure_valid: Option<bool>,
    pub presentation_proof_valid: Option<bool>,
    pub credential_proofs_valid: Option<bool>,
    pub trust_chain_valid: Option<bool>,
    pub holder_binding_valid: Option<bool>,
    pub transaction_binding_valid: Option<bool>,
    pub presentation_constraints_valid: Option<bool>,
    pub revocation_checked: Option<bool>,
    pub revocation_status: Option<CredentialStatus>,
}

impl AdapterFacts {
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            processing_status: VerificationProcessingStatus::Unavailable,
            presentation_structure_valid: None,
            presentation_proof_valid: None,
            credential_proofs_valid: None,
            trust_chain_valid: None,
            holder_binding_valid: None,
            transaction_binding_valid: None,
            presentation_constraints_valid: None,
            revocation_checked: None,
            revocation_status: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialStatus {
    Valid,
    Revoked,
    Unknown,
}

#[derive(Clone, Copy)]
pub enum Presented<'a> {
    String(&'a str),
    Object(&'a Map<String, Value>),
}

impl fmt::Debug for Presented<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Presented([REDACTED])")
    }
}

impl Presented<'_> {
    #[must_use]
    pub fn digest(self) -> Sha256Digest {
        match self {
            Self::String(value) => Sha256Digest::calculate(value),
            Self::Object(value) => {
                let canonical = sorted_json(&Value::Object(value.clone()));
                Sha256Digest::calculate(&canonical)
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum DecisionBuildError {
    #[error("unsupported governed verification check: {0}")]
    UnsupportedCheck(String),
    #[error("canonical evidence digest could not be built")]
    EvidenceDigest,
    #[error("Core rejected canonical verification evidence")]
    Core,
}

pub fn build_canonical_decision(
    governance: &GovernanceSnapshot,
    verification_id: &str,
    transaction_id: &str,
    presentation: Presented<'_>,
    facts: &AdapterFacts,
) -> Result<VerificationDecisionResult, DecisionBuildError> {
    let evaluated_at = Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true);
    let mut evidence_records = Vec::new();
    let checks = governance
        .policy()
        .required_checks()
        .iter()
        .map(|check_id| {
            mapped_check(
                check_id,
                facts,
                &governance.component().component_id,
                &evaluated_at,
                &mut evidence_records,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let evidence_digest = canonical_digest_json(
        &serde_json::to_string(&evidence_records)
            .map_err(|_| DecisionBuildError::EvidenceDigest)?,
    )
    .map_err(|_| DecisionBuildError::EvidenceDigest)?;
    let presentation_digest = presentation.digest();
    build_verification_decision_result(VerificationDecisionResultInput {
        verification_id: verification_id.into(),
        context: VerificationDecisionContext {
            mode: VerificationContextMode::Online,
            verifier_id: governance.policy().verifier_id().into(),
            organization_id: Some(governance.organization_id().into()),
            transaction_id: Some(transaction_id.into()),
            audience: Some(governance.policy().verifier_id().into()),
            offline_profile_id: None,
        },
        processing_status: facts.processing_status,
        evaluated_at,
        input_digest: format!("sha256:{}", presentation_digest.as_str()),
        evidence_digest,
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
    })
    .map_err(|_| DecisionBuildError::Core)
}

fn mapped_check(
    check_id: &str,
    facts: &AdapterFacts,
    component_id: &str,
    evaluated_at: &str,
    evidence_records: &mut Vec<Value>,
) -> Result<VerificationCheckResult, DecisionBuildError> {
    if check_id == "credential.status" {
        return Ok(status_check(
            facts,
            component_id,
            evaluated_at,
            evidence_records,
        ));
    }
    let (category, fact, passed_code, failed_code) = match check_id {
        "presentation.structure" => (
            VerificationCheckCategory::Structure,
            facts.presentation_structure_valid,
            "PRESENTATION_STRUCTURE_VALID",
            "PRESENTATION_STRUCTURE_INVALID",
        ),
        "presentation.proof" => (
            VerificationCheckCategory::PresentationProof,
            facts.presentation_proof_valid,
            "PRESENTATION_PROOF_VALID",
            "PRESENTATION_PROOF_INVALID",
        ),
        "credential.proof" => (
            VerificationCheckCategory::CredentialProof,
            facts.credential_proofs_valid,
            "CREDENTIAL_PROOFS_VALID",
            "CREDENTIAL_PROOFS_INVALID",
        ),
        "issuer.trust" => (
            VerificationCheckCategory::IssuerTrust,
            facts.trust_chain_valid,
            "ISSUER_TRUST_VALID",
            "ISSUER_TRUST_INVALID",
        ),
        "holder.binding" => (
            VerificationCheckCategory::HolderBinding,
            facts.holder_binding_valid,
            "HOLDER_BINDING_VALID",
            "HOLDER_BINDING_INVALID",
        ),
        "transaction.binding" => (
            VerificationCheckCategory::TransactionBinding,
            facts.transaction_binding_valid,
            "TRANSACTION_BINDING_VALID",
            "TRANSACTION_BINDING_INVALID",
        ),
        "claim.constraints" => (
            VerificationCheckCategory::ClaimConstraints,
            facts.presentation_constraints_valid,
            "CLAIM_CONSTRAINTS_SATISFIED",
            "CLAIM_CONSTRAINTS_FAILED",
        ),
        other => return Err(DecisionBuildError::UnsupportedCheck(other.into())),
    };
    let (outcome, code) = match fact {
        Some(true) => (VerificationCheckOutcome::Passed, passed_code.into()),
        Some(false) => (VerificationCheckOutcome::Failed, failed_code.into()),
        None => (
            VerificationCheckOutcome::NotPerformed,
            format!(
                "{}_NOT_PERFORMED",
                check_id.replace('.', "_").to_ascii_uppercase()
            ),
        ),
    };
    Ok(check_result(
        check_id,
        category,
        outcome,
        code,
        component_id,
        evaluated_at,
        evidence_records,
    ))
}

fn status_check(
    facts: &AdapterFacts,
    component_id: &str,
    evaluated_at: &str,
    evidence_records: &mut Vec<Value>,
) -> VerificationCheckResult {
    let (outcome, code) = match (facts.revocation_checked, facts.revocation_status) {
        (Some(true), Some(CredentialStatus::Valid)) => {
            (VerificationCheckOutcome::Passed, "CREDENTIAL_STATUS_VALID")
        }
        (Some(true), Some(CredentialStatus::Revoked)) => (
            VerificationCheckOutcome::Failed,
            "CREDENTIAL_STATUS_REVOKED",
        ),
        (Some(true), _) => (
            VerificationCheckOutcome::Error,
            "CREDENTIAL_STATUS_UNRESOLVED",
        ),
        _ => (
            VerificationCheckOutcome::NotPerformed,
            "CREDENTIAL_STATUS_NOT_CHECKED",
        ),
    };
    check_result(
        "credential.status",
        VerificationCheckCategory::Status,
        outcome,
        code.into(),
        component_id,
        evaluated_at,
        evidence_records,
    )
}

fn check_result(
    check_id: &str,
    category: VerificationCheckCategory,
    outcome: VerificationCheckOutcome,
    code: String,
    component_id: &str,
    evaluated_at: &str,
    evidence_records: &mut Vec<Value>,
) -> VerificationCheckResult {
    let evidence_refs = if matches!(
        outcome,
        VerificationCheckOutcome::Passed | VerificationCheckOutcome::Failed
    ) {
        let evidence_ref = format!("urn:marty:evidence:{}", Uuid::new_v4());
        evidence_records.push(json!({
            "id": evidence_ref,
            "check_id": check_id,
            "outcome": outcome,
            "code": code,
        }));
        vec![evidence_ref]
    } else {
        Vec::new()
    };
    VerificationCheckResult {
        check_id: check_id.into(),
        category,
        required: true,
        outcome,
        code,
        component_id: component_id.into(),
        evaluated_at: evaluated_at.into(),
        evidence_refs,
    }
}

fn sorted_json(value: &Value) -> String {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(object) => Value::Object(
                object
                    .iter()
                    .map(|(key, value)| (key.clone(), sorted(value)))
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            Value::Array(values) => Value::Array(values.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_string(&sorted(value)).expect("JSON Value serialization is infallible")
}

#[cfg(test)]
mod tests {
    use marty_verification::verification::VerificationDecision;

    use super::*;
    use crate::credentials_compat::{GovernanceEngine, GovernancePurpose};

    fn governance() -> GovernanceSnapshot {
        let fixture: Value =
            serde_json::from_str(marty_verification::governance::behavior_fixture_json()).unwrap();
        GovernanceEngine::new(&fixture["governance"].to_string())
            .unwrap()
            .authorize("purpose-scoped-test-key", GovernancePurpose::Direct)
            .unwrap()
    }

    fn passing_facts() -> AdapterFacts {
        AdapterFacts {
            processing_status: VerificationProcessingStatus::Completed,
            presentation_structure_valid: Some(true),
            presentation_proof_valid: Some(true),
            credential_proofs_valid: Some(true),
            trust_chain_valid: Some(true),
            holder_binding_valid: Some(true),
            transaction_binding_valid: Some(true),
            presentation_constraints_valid: Some(true),
            revocation_checked: Some(true),
            revocation_status: Some(CredentialStatus::Valid),
        }
    }

    #[test]
    fn all_governed_facts_reduce_to_core_pass_and_missing_facts_fail_closed() {
        let governance = governance();
        let passed = build_canonical_decision(
            &governance,
            "verification:direct-1",
            "transaction:direct-1",
            Presented::String("presentation"),
            &passing_facts(),
        )
        .unwrap();
        assert_eq!(passed.decision(), VerificationDecision::Pass);
        assert!(passed.is_valid());

        let unavailable = build_canonical_decision(
            &governance,
            "verification:direct-2",
            "transaction:direct-2",
            Presented::String("presentation"),
            &AdapterFacts::unavailable(),
        )
        .unwrap();
        assert_ne!(unavailable.decision(), VerificationDecision::Pass);
        assert!(!unavailable.is_valid());
    }

    #[test]
    fn structured_input_digest_matches_python_sorted_compact_json() {
        let first = serde_json::from_value::<Map<String, Value>>(json!({
            "z": [3, {"b": 2, "a": 1}],
            "a": "value"
        }))
        .unwrap();
        let second = serde_json::from_value::<Map<String, Value>>(json!({
            "a": "value",
            "z": [3, {"a": 1, "b": 2}]
        }))
        .unwrap();
        assert_eq!(
            Presented::Object(&first).digest(),
            Presented::Object(&second).digest()
        );
        assert_eq!(
            Presented::Object(&first).digest(),
            Sha256Digest::calculate(r#"{"a":"value","z":[3,{"a":1,"b":2}]}"#)
        );
        let debug = format!("{:?}", Presented::Object(&first));
        assert_eq!(debug, "Presented([REDACTED])");
        assert!(!debug.contains("value"));
        assert_eq!(
            format!("{:?}", Presented::String("header.secret.signature")),
            "Presented([REDACTED])"
        );
    }
}
