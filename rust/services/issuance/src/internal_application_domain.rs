//! Language-neutral request and identity semantics for internal Applications.
//!
//! This module is intentionally transport- and persistence-free. The complete
//! internal Application surface is not selected by the gateway until the HTTP,
//! dependency, atomic-write and PostgreSQL gates are all implemented.

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::python_value::{python_string, python_truthy, strip};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationStatus {
    Pending,
    UnderReview,
    Approved,
    Rejected,
    Withdrawn,
}

impl ApplicationStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::UnderReview => "under_review",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Withdrawn => "withdrawn",
        }
    }
}

impl FromStr for ApplicationStatus {
    type Err = InvalidApplicationStatus;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "pending" => Ok(Self::Pending),
            "under_review" => Ok(Self::UnderReview),
            "approved" => Ok(Self::Approved),
            "rejected" => Ok(Self::Rejected),
            "withdrawn" => Ok(Self::Withdrawn),
            _ => Err(InvalidApplicationStatus),
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("Invalid application status")]
pub struct InvalidApplicationStatus;

/// Python's original model ignored unknown fields. Keeping that wire behavior
/// avoids rejecting callers while the Rust route takes ownership.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ApplicationCreate {
    pub application_template_id: String,
    pub applicant_data: Map<String, Value>,
    #[serde(default)]
    pub integration_context: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EvidenceSubmission {
    pub evidence_type: String,
    pub evidence_data: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationApproval {
    #[serde(default)]
    pub review_notes: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationRejection {
    pub review_notes: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceReconciliationRequest {
    pub organization_id: String,
    #[serde(default)]
    pub application_id: Option<String>,
    #[serde(default = "default_reconciliation_limit")]
    pub limit: i64,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default = "default_true")]
    pub issue_on_permit: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ExternalEvidenceApiCheckRequest {
    #[serde(default)]
    pub inputs: Map<String, Value>,
    #[serde(default = "default_true")]
    pub issue_on_permit: bool,
}

/// Preserve Python's `str(value or "").strip()` semantics, including truthy
/// non-string JSON values, before falling back to the caller's generated ID.
#[must_use]
pub fn derive_applicant_identifier(
    applicant_data: &Map<String, Value>,
    generated_identifier: &str,
) -> String {
    let names = ["given_name", "family_name"]
        .into_iter()
        .filter_map(|field| identifier_component(applicant_data.get(field)))
        .collect::<Vec<_>>();
    if !names.is_empty() {
        return names.join("_");
    }
    identifier_component(applicant_data.get("email"))
        .unwrap_or_else(|| generated_identifier.to_owned())
}

fn identifier_component(value: Option<&Value>) -> Option<String> {
    let value = value.filter(|value| python_truthy(value))?;
    let rendered = python_string(value)?;
    let rendered = strip(&rendered);
    (!rendered.is_empty()).then(|| rendered.to_owned())
}

fn default_reconciliation_limit() -> i64 {
    100
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn request_models_preserve_frozen_unknown_field_policies_and_defaults() {
        let create: ApplicationCreate = serde_json::from_value(json!({
            "application_template_id": "template-1",
            "applicant_data": {},
            "unknown": true
        }))
        .expect("create request");
        assert!(create.integration_context.is_empty());

        let evidence: EvidenceSubmission = serde_json::from_value(json!({
            "evidence_type": "DOCUMENT_SCAN",
            "evidence_data": {},
            "unknown": true
        }))
        .expect("evidence request");
        assert_eq!(evidence.evidence_type, "DOCUMENT_SCAN");

        let reconciliation: EvidenceReconciliationRequest =
            serde_json::from_value(json!({"organization_id": "org-123", "unknown": true}))
                .expect("reconciliation request");
        assert_eq!(reconciliation.application_id, None);
        assert_eq!(reconciliation.limit, 100);
        assert!(!reconciliation.dry_run);
        assert!(reconciliation.issue_on_permit);

        let api_check: ExternalEvidenceApiCheckRequest =
            serde_json::from_value(json!({"unknown": true})).expect("API check request");
        assert!(api_check.inputs.is_empty());
        assert!(api_check.issue_on_permit);

        assert!(
            serde_json::from_value::<ApplicationApproval>(json!({"reviewer_id": "caller"}))
                .is_err()
        );
        assert!(serde_json::from_value::<ApplicationRejection>(json!({
            "review_notes": "no",
            "reviewer_id": "caller"
        }))
        .is_err());
    }

    #[test]
    fn required_request_fields_reject_missing_null_and_wrong_shapes() {
        for value in [
            json!({"applicant_data": {}}),
            json!({"application_template_id": "template-1", "applicant_data": null}),
            json!({"application_template_id": {}, "applicant_data": {}}),
        ] {
            assert!(serde_json::from_value::<ApplicationCreate>(value).is_err());
        }
        for value in [
            json!({"evidence_type": "DOCUMENT_SCAN"}),
            json!({"evidence_type": "DOCUMENT_SCAN", "evidence_data": null}),
            json!({"evidence_type": [], "evidence_data": {}}),
        ] {
            assert!(serde_json::from_value::<EvidenceSubmission>(value).is_err());
        }
        assert!(serde_json::from_value::<ApplicationRejection>(json!({})).is_err());
        assert!(
            serde_json::from_value::<ApplicationRejection>(json!({"review_notes": null})).is_err()
        );
        assert!(serde_json::from_value::<EvidenceReconciliationRequest>(json!({})).is_err());
        assert!(
            serde_json::from_value::<ExternalEvidenceApiCheckRequest>(json!({"inputs": null}))
                .is_err()
        );
    }

    #[test]
    fn status_filter_is_exact_and_uses_the_frozen_wire_values() {
        for (wire, status) in [
            ("pending", ApplicationStatus::Pending),
            ("under_review", ApplicationStatus::UnderReview),
            ("approved", ApplicationStatus::Approved),
            ("rejected", ApplicationStatus::Rejected),
            ("withdrawn", ApplicationStatus::Withdrawn),
        ] {
            assert_eq!(wire.parse::<ApplicationStatus>(), Ok(status));
            assert_eq!(status.as_str(), wire);
            assert_eq!(serde_json::to_value(status).expect("status JSON"), wire);
        }
        assert_eq!(
            "not-a-status".parse::<ApplicationStatus>(),
            Err(InvalidApplicationStatus)
        );
    }

    #[test]
    fn applicant_identifier_preserves_name_email_and_generated_precedence() {
        let fallback = "applicant_1234abcd";
        assert_eq!(
            derive_applicant_identifier(
                json!({"given_name": " Ada ", "family_name": " Lovelace ", "email": "ignored@example.test"})
                    .as_object()
                    .expect("applicant object"),
                fallback,
            ),
            "Ada_Lovelace"
        );
        assert_eq!(
            derive_applicant_identifier(
                json!({"given_name": "", "family_name": false, "email": " ada@example.test "})
                    .as_object()
                    .expect("applicant object"),
                fallback,
            ),
            "ada@example.test"
        );
        assert_eq!(
            derive_applicant_identifier(
                json!({"given_name": 7, "family_name": ["Lovelace"]})
                    .as_object()
                    .expect("applicant object"),
                fallback,
            ),
            "7_['Lovelace']"
        );
        assert_eq!(
            derive_applicant_identifier(
                json!({"given_name": 0, "family_name": [], "email": null})
                    .as_object()
                    .expect("applicant object"),
                fallback,
            ),
            fallback
        );
    }
}
