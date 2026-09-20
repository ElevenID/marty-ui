//! Language-neutral request and identity semantics for internal Applications.
//!
//! This module is intentionally transport- and persistence-free. The complete
//! internal Application surface is not selected by the gateway until the HTTP,
//! dependency, atomic-write and PostgreSQL gates are all implemented.

use std::str::FromStr;

use chrono::{DateTime, Duration, SecondsFormat, Utc};
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

#[derive(Clone, Debug, PartialEq)]
pub struct ApplicationRecord {
    pub id: String,
    pub organization_id: String,
    pub application_template_id: String,
    pub applicant_identifier: String,
    pub form_data: Map<String, Value>,
    pub evidence_submissions: Vec<Map<String, Value>>,
    pub integration_context: Map<String, Value>,
    pub status: ApplicationStatus,
    pub review_notes: Option<String>,
    pub reviewer_id: Option<String>,
    pub rejection_reason: Option<String>,
    pub derived_claims: Map<String, Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub submitted_at: DateTime<Utc>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub issuance_transaction_id: Option<String>,
    pub credential_id: Option<String>,
}

impl ApplicationRecord {
    pub fn new(
        id: String,
        organization_id: String,
        request: ApplicationCreate,
        generated_identifier: &str,
        now: DateTime<Utc>,
    ) -> Result<Self, ApplicationDomainError> {
        let applicant_identifier =
            derive_applicant_identifier(&request.applicant_data, generated_identifier);
        let expires_at = now
            .checked_add_signed(Duration::days(30))
            .ok_or(ApplicationDomainError::TimestampOverflow)?;
        Ok(Self {
            id,
            organization_id,
            application_template_id: request.application_template_id,
            applicant_identifier,
            form_data: request.applicant_data,
            evidence_submissions: Vec::new(),
            integration_context: request.integration_context,
            status: ApplicationStatus::Pending,
            review_notes: None,
            reviewer_id: None,
            rejection_reason: None,
            derived_claims: Map::new(),
            created_at: now,
            updated_at: now,
            submitted_at: now,
            reviewed_at: None,
            expires_at,
            issuance_transaction_id: None,
            credential_id: None,
        })
    }

    pub fn submit_evidence(
        &mut self,
        evidence: EvidenceSubmission,
        now: DateTime<Utc>,
    ) -> Result<(), ApplicationDomainError> {
        self.require_pending("submit evidence for")?;
        self.evidence_submissions.push(Map::from_iter([
            (
                "evidence_type".to_owned(),
                Value::String(evidence.evidence_type),
            ),
            (
                "evidence_data".to_owned(),
                Value::Object(evidence.evidence_data),
            ),
            (
                "submitted_at".to_owned(),
                Value::String(python_datetime(now)),
            ),
        ]));
        self.updated_at = now;
        Ok(())
    }

    pub fn reject(
        &mut self,
        review_notes: String,
        reviewer_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(), ApplicationDomainError> {
        self.require_pending("reject")?;
        self.status = ApplicationStatus::Rejected;
        self.review_notes = Some(review_notes);
        self.reviewer_id = Some(reviewer_id.to_owned());
        self.reviewed_at = Some(now);
        self.updated_at = now;
        Ok(())
    }

    pub fn ensure_approvable(&self) -> Result<(), ApplicationDomainError> {
        self.require_pending("approve")
    }

    pub fn approve_reserved(
        &mut self,
        issuance_transaction_id: String,
        review_notes: Option<String>,
        reviewer_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(), ApplicationDomainError> {
        self.ensure_approvable()?;
        self.status = ApplicationStatus::Approved;
        self.review_notes = review_notes;
        self.reviewer_id = Some(reviewer_id.to_owned());
        self.reviewed_at = Some(now);
        self.updated_at = now;
        self.issuance_transaction_id = Some(issuance_transaction_id);
        Ok(())
    }

    fn require_pending(&self, operation: &'static str) -> Result<(), ApplicationDomainError> {
        if self.status == ApplicationStatus::Pending {
            Ok(())
        } else {
            Err(ApplicationDomainError::InvalidTransition {
                operation,
                status: self.status.into(),
            })
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApplicationResponse {
    pub id: String,
    pub organization_id: String,
    pub application_template_id: String,
    pub applicant_identifier: String,
    pub form_data: Map<String, Value>,
    pub evidence_submissions: Vec<Map<String, Value>>,
    pub integration_context: Map<String, Value>,
    pub status: String,
    pub review_notes: Option<String>,
    pub reviewer_id: Option<String>,
    pub submitted_at: String,
    pub reviewed_at: Option<String>,
    pub expires_at: String,
    pub issuance_transaction_id: Option<String>,
}

impl From<&ApplicationRecord> for ApplicationResponse {
    fn from(value: &ApplicationRecord) -> Self {
        Self {
            id: value.id.clone(),
            organization_id: value.organization_id.clone(),
            application_template_id: value.application_template_id.clone(),
            applicant_identifier: value.applicant_identifier.clone(),
            form_data: value.form_data.clone(),
            evidence_submissions: value.evidence_submissions.clone(),
            integration_context: value.integration_context.clone(),
            status: value.status.as_str().to_owned(),
            review_notes: value.review_notes.clone(),
            reviewer_id: value.reviewer_id.clone(),
            submitted_at: python_datetime(value.submitted_at),
            reviewed_at: value.reviewed_at.map(python_datetime),
            expires_at: python_datetime(value.expires_at),
            issuance_transaction_id: value.issuance_transaction_id.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceFactRecord {
    pub id: String,
    pub organization_id: String,
    pub application_id: String,
    pub subject_id: String,
    pub provider: String,
    pub fact_type: String,
    pub scope: Map<String, Value>,
    pub assertion: Map<String, Value>,
    pub verification: Map<String, Value>,
    pub source: Map<String, Value>,
    pub requirement_id: Option<String>,
    pub logical_key: String,
    pub source_revision: String,
    pub payload_hash: String,
    pub observed_at: DateTime<Utc>,
    pub effective_at: Option<DateTime<Utc>>,
    pub superseded_fact_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvidenceFactResponse {
    pub id: String,
    pub organization_id: String,
    pub application_id: String,
    pub subject_id: String,
    pub provider: String,
    pub fact_type: String,
    pub scope: Map<String, Value>,
    pub assertion: Map<String, Value>,
    pub verification: Map<String, Value>,
    pub source: Map<String, Value>,
    pub requirement_id: Option<String>,
    pub logical_key: String,
    pub source_revision: String,
    pub payload_hash: String,
    pub observed_at: String,
    pub effective_at: Option<String>,
    pub superseded_fact_id: Option<String>,
    pub created_at: String,
}

impl From<&EvidenceFactRecord> for EvidenceFactResponse {
    fn from(value: &EvidenceFactRecord) -> Self {
        Self {
            id: value.id.clone(),
            organization_id: value.organization_id.clone(),
            application_id: value.application_id.clone(),
            subject_id: value.subject_id.clone(),
            provider: value.provider.clone(),
            fact_type: value.fact_type.clone(),
            scope: value.scope.clone(),
            assertion: value.assertion.clone(),
            verification: value.verification.clone(),
            source: value.source.clone(),
            requirement_id: value.requirement_id.clone(),
            logical_key: value.logical_key.clone(),
            source_revision: value.source_revision.clone(),
            payload_hash: value.payload_hash.clone(),
            observed_at: python_datetime(value.observed_at),
            effective_at: value.effective_at.map(python_datetime),
            superseded_fact_id: value.superseded_fact_id.clone(),
            created_at: python_datetime(value.created_at),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct IssuanceEventRecord {
    pub id: String,
    pub transaction_id: Option<String>,
    pub application_id: Option<String>,
    pub event_type: String,
    pub metadata: Map<String, Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IssuanceEventResponse {
    pub id: String,
    pub transaction_id: Option<String>,
    pub application_id: Option<String>,
    pub event_type: String,
    pub metadata: Map<String, Value>,
    pub created_at: String,
}

impl From<&IssuanceEventRecord> for IssuanceEventResponse {
    fn from(value: &IssuanceEventRecord) -> Self {
        Self {
            id: value.id.clone(),
            transaction_id: value.transaction_id.clone(),
            application_id: value.application_id.clone(),
            event_type: value.event_type.clone(),
            metadata: value.metadata.clone(),
            created_at: python_datetime(value.created_at),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApplicationEvidenceSummaryResponse {
    pub application_id: String,
    pub organization_id: String,
    pub status: String,
    pub evidence_facts: Vec<EvidenceFactResponse>,
    pub policy_decision: Option<Map<String, Value>>,
    pub policy_source: Option<String>,
    pub policy_set_id: Option<String>,
    pub issuance_transaction_id: Option<String>,
    pub canvas: Option<Map<String, Value>>,
    pub available_api_checks: Vec<Map<String, Value>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExternalEvidenceApiCheckResponse {
    pub application_id: String,
    pub organization_id: String,
    pub check_id: String,
    pub status: String,
    pub application_status: String,
    pub evidence_fact: EvidenceFactResponse,
    pub policy_decision: Map<String, Value>,
    pub issuance_transaction_id: Option<String>,
    pub response_metadata: Map<String, Value>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ApplicationDomainError {
    #[error("Cannot {operation} application in ApplicationStatus.{status} status")]
    InvalidTransition {
        operation: &'static str,
        status: ApplicationStatusDebug,
    },
    #[error("Application timestamp is out of range")]
    TimestampOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationStatusDebug(ApplicationStatus);

impl std::fmt::Display for ApplicationStatusDebug {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self.0 {
            ApplicationStatus::Pending => "PENDING",
            ApplicationStatus::UnderReview => "UNDER_REVIEW",
            ApplicationStatus::Approved => "APPROVED",
            ApplicationStatus::Rejected => "REJECTED",
            ApplicationStatus::Withdrawn => "WITHDRAWN",
        })
    }
}

impl From<ApplicationStatus> for ApplicationStatusDebug {
    fn from(value: ApplicationStatus) -> Self {
        Self(value)
    }
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

pub(crate) fn python_datetime(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::AutoSi, false)
}

fn default_reconciliation_limit() -> i64 {
    100
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
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

    #[test]
    fn application_projection_matches_the_frozen_response_shape() {
        let now = Utc
            .with_ymd_and_hms(2026, 9, 19, 12, 34, 56)
            .single()
            .expect("fixed timestamp");
        let request: ApplicationCreate = serde_json::from_value(json!({
            "application_template_id": "template-1",
            "applicant_data": {
                "given_name": "Ada",
                "family_name": "Lovelace"
            },
            "integration_context": {"source": "contract"}
        }))
        .expect("create request");
        let record = ApplicationRecord::new(
            "application-1".to_owned(),
            "org-123".to_owned(),
            request,
            "applicant_1234abcd",
            now,
        )
        .expect("application");

        assert_eq!(
            serde_json::to_value(ApplicationResponse::from(&record)).expect("response JSON"),
            json!({
                "id": "application-1",
                "organization_id": "org-123",
                "application_template_id": "template-1",
                "applicant_identifier": "Ada_Lovelace",
                "form_data": {"given_name": "Ada", "family_name": "Lovelace"},
                "evidence_submissions": [],
                "integration_context": {"source": "contract"},
                "status": "pending",
                "review_notes": null,
                "reviewer_id": null,
                "submitted_at": "2026-09-19T12:34:56+00:00",
                "reviewed_at": null,
                "expires_at": "2026-10-19T12:34:56+00:00",
                "issuance_transaction_id": null
            })
        );
    }

    #[test]
    fn manual_mutations_require_pending_and_preserve_public_error_text() {
        let now = Utc
            .with_ymd_and_hms(2026, 9, 19, 12, 34, 56)
            .single()
            .expect("fixed timestamp");
        let request: ApplicationCreate = serde_json::from_value(json!({
            "application_template_id": "template-1",
            "applicant_data": {}
        }))
        .expect("create request");
        let mut record = ApplicationRecord::new(
            "application-1".to_owned(),
            "org-123".to_owned(),
            request,
            "applicant_1234abcd",
            now,
        )
        .expect("application");
        let later = now + Duration::minutes(1);
        let mut approved = record.clone();
        approved
            .approve_reserved(
                "transaction-1".to_owned(),
                Some("Reviewed".to_owned()),
                "issuance-management-api",
                later,
            )
            .expect("pending approval");
        assert_eq!(approved.status, ApplicationStatus::Approved);
        assert_eq!(approved.review_notes.as_deref(), Some("Reviewed"));
        assert_eq!(
            approved.reviewer_id.as_deref(),
            Some("issuance-management-api")
        );
        assert_eq!(
            approved.issuance_transaction_id.as_deref(),
            Some("transaction-1")
        );
        record
            .submit_evidence(
                EvidenceSubmission {
                    evidence_type: "DOCUMENT_SCAN".to_owned(),
                    evidence_data: Map::from_iter([("digest".to_owned(), json!("sha256:1"))]),
                },
                later,
            )
            .expect("pending evidence submission");
        assert_eq!(
            record.evidence_submissions,
            vec![Map::from_iter([
                ("evidence_type".to_owned(), json!("DOCUMENT_SCAN")),
                ("evidence_data".to_owned(), json!({"digest": "sha256:1"})),
                (
                    "submitted_at".to_owned(),
                    json!("2026-09-19T12:35:56+00:00")
                )
            ])]
        );
        record
            .reject(
                "Insufficient evidence".to_owned(),
                "issuance-management-api",
                later,
            )
            .expect("pending rejection");
        assert_eq!(record.status, ApplicationStatus::Rejected);
        assert_eq!(record.reviewed_at, Some(later));
        assert_eq!(
            record.reviewer_id.as_deref(),
            Some("issuance-management-api")
        );

        let error = record
            .submit_evidence(
                EvidenceSubmission {
                    evidence_type: "DOCUMENT_SCAN".to_owned(),
                    evidence_data: Map::new(),
                },
                later,
            )
            .expect_err("rejected application must not accept evidence");
        assert_eq!(
            error.to_string(),
            "Cannot submit evidence for application in ApplicationStatus.REJECTED status"
        );
    }
}
