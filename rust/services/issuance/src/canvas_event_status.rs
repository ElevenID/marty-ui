//! Tenant-safe status projection for replayable Canvas evidence receipts.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mmf_security::constant_time_secret_eq;
use serde::Serialize;
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{management_security::ManagementSecurity, transaction_reads::TransactionReadError};

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasEventReceipt {
    pub id: String,
    pub provider_event_id: String,
    pub canvas_account_id: Option<String>,
    pub organization_id: String,
    pub credential_template_id: String,
    pub payload_hash: String,
    pub issuance_transaction_id: Option<String>,
    pub issuance_response: Value,
    pub status: String,
    pub error_summary: Option<String>,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CanvasEvidenceEventStatusResponse {
    pub id: String,
    pub provider_event_id: String,
    pub canvas_account_id: Option<String>,
    pub organization_id: String,
    pub credential_template_id: String,
    pub application_id: Option<String>,
    pub status: String,
    pub payload_hash: String,
    pub issuance_transaction_id: Option<String>,
    pub error_summary: Option<String>,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub response: Map<String, Value>,
    pub evidence_facts: Vec<Map<String, Value>>,
    pub policy_decision: Option<Map<String, Value>>,
    pub replay_available: bool,
}

impl TryFrom<CanvasEventReceipt> for CanvasEvidenceEventStatusResponse {
    type Error = CanvasEventStatusError;

    fn try_from(receipt: CanvasEventReceipt) -> Result<Self, Self::Error> {
        let response = receipt
            .issuance_response
            .as_object()
            .cloned()
            .unwrap_or_default();
        let application_id = optional_text(&response, "application_id")?;
        let evidence_facts = optional_object_list(&response, "evidence_facts")?;
        let policy_decision = optional_object(&response, "policy_decision")?;
        Ok(Self {
            id: receipt.id,
            provider_event_id: receipt.provider_event_id,
            canvas_account_id: receipt.canvas_account_id,
            organization_id: receipt.organization_id,
            credential_template_id: receipt.credential_template_id,
            application_id,
            status: receipt.status,
            payload_hash: receipt.payload_hash,
            issuance_transaction_id: receipt.issuance_transaction_id,
            error_summary: receipt.error_summary,
            first_seen_at: receipt.first_seen_at.to_rfc3339(),
            last_seen_at: receipt.last_seen_at.to_rfc3339(),
            response,
            evidence_facts,
            policy_decision,
            replay_available: true,
        })
    }
}

fn optional_text(
    object: &Map<String, Value>,
    name: &str,
) -> Result<Option<String>, CanvasEventStatusError> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(CanvasEventStatusError::MalformedReceipt),
    }
}

fn optional_object(
    object: &Map<String, Value>,
    name: &str,
) -> Result<Option<Map<String, Value>>, CanvasEventStatusError> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(value)) => Ok(Some(value.clone())),
        Some(_) => Err(CanvasEventStatusError::MalformedReceipt),
    }
}

fn optional_object_list(
    object: &Map<String, Value>,
    name: &str,
) -> Result<Vec<Map<String, Value>>, CanvasEventStatusError> {
    match object.get(name) {
        // Python's preserved boundary used `value or []`: every JSON-falsy
        // value therefore projected as an empty evidence list before response
        // validation. Keep that behavior language-neutral for old receipts.
        None => Ok(Vec::new()),
        Some(value) if json_value_is_python_falsy(value) => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_object()
                    .cloned()
                    .ok_or(CanvasEventStatusError::MalformedReceipt)
            })
            .collect(),
        Some(_) => Err(CanvasEventStatusError::MalformedReceipt),
    }
}

fn json_value_is_python_falsy(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => true,
        Value::Number(value) => value.as_f64() == Some(0.0),
        Value::String(value) => value.is_empty(),
        Value::Array(value) => value.is_empty(),
        Value::Object(value) => value.is_empty(),
        Value::Bool(true) => false,
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CanvasEventStatusRepositoryError {
    #[error("Canvas event receipt repository is unavailable")]
    Unavailable,
}

#[async_trait]
pub trait CanvasEventStatusRepository: Send + Sync {
    async fn receipt(
        &self,
        canvas_account_id: &str,
        provider_event_id: &str,
    ) -> Result<Option<CanvasEventReceipt>, CanvasEventStatusRepositoryError>;
}

#[derive(Debug, Error, PartialEq)]
pub enum CanvasEventStatusError {
    #[error(transparent)]
    Security(#[from] TransactionReadError),
    #[error("Canvas evidence event receipt not found")]
    NotFound,
    #[error("Canvas event receipt is malformed")]
    MalformedReceipt,
    #[error("Canvas event receipt repository is unavailable")]
    RepositoryUnavailable,
}

#[derive(Clone)]
pub struct CanvasEventStatusService {
    security: ManagementSecurity,
    repository: Arc<dyn CanvasEventStatusRepository>,
}

impl std::fmt::Debug for CanvasEventStatusService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasEventStatusService")
            .field("security", &self.security)
            .finish_non_exhaustive()
    }
}

impl CanvasEventStatusService {
    #[must_use]
    pub fn new(
        management_api_key: Option<&str>,
        repository: Arc<dyn CanvasEventStatusRepository>,
    ) -> Self {
        Self {
            security: ManagementSecurity::new(management_api_key),
            repository,
        }
    }

    pub async fn get(
        &self,
        canvas_account_id: &str,
        provider_event_id: &str,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<CanvasEvidenceEventStatusResponse, CanvasEventStatusError> {
        self.security.authorize(api_key)?;
        let organization_id = trusted_organization_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(TransactionReadError::TrustedOrganizationRequired)?;
        let receipt = self
            .repository
            .receipt(canvas_account_id, provider_event_id)
            .await
            .map_err(|_| CanvasEventStatusError::RepositoryUnavailable)?
            .ok_or(CanvasEventStatusError::NotFound)?;
        if !constant_time_secret_eq(
            receipt.organization_id.as_bytes(),
            organization_id.as_bytes(),
        ) {
            return Err(CanvasEventStatusError::NotFound);
        }
        receipt.try_into()
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    #[derive(Debug)]
    struct Repository(Option<CanvasEventReceipt>);

    #[async_trait]
    impl CanvasEventStatusRepository for Repository {
        async fn receipt(
            &self,
            canvas_account_id: &str,
            provider_event_id: &str,
        ) -> Result<Option<CanvasEventReceipt>, CanvasEventStatusRepositoryError> {
            assert_eq!(canvas_account_id, "account-1");
            assert_eq!(provider_event_id, "event-1");
            Ok(self.0.clone())
        }
    }

    fn receipt(response: Value) -> CanvasEventReceipt {
        CanvasEventReceipt {
            id: "receipt-1".to_owned(),
            provider_event_id: "event-1".to_owned(),
            canvas_account_id: Some("account-1".to_owned()),
            organization_id: "org-1".to_owned(),
            credential_template_id: "template-1".to_owned(),
            payload_hash: "payload-hash".to_owned(),
            issuance_transaction_id: Some("transaction-1".to_owned()),
            issuance_response: response,
            status: "evidence_received".to_owned(),
            error_summary: None,
            first_seen_at: Utc.with_ymd_and_hms(2026, 8, 30, 1, 2, 3).unwrap(),
            last_seen_at: Utc.with_ymd_and_hms(2026, 8, 30, 2, 3, 4).unwrap(),
        }
    }

    #[tokio::test]
    async fn status_is_exact_tenant_bound_and_replayable() {
        let service = CanvasEventStatusService::new(
            Some("management-key"),
            Arc::new(Repository(Some(receipt(json!({
                "application_id": "application-1",
                "evidence_facts": [{"fact_type": "canvas.course_completion"}],
                "policy_decision": {"allowed": true},
                "private_extension": "preserved-on-recorded-response"
            }))))),
        );

        assert_eq!(
            service
                .get(
                    "account-1",
                    "event-1",
                    Some("management-key"),
                    Some("org-2")
                )
                .await,
            Err(CanvasEventStatusError::NotFound)
        );
        let response = service
            .get(
                "account-1",
                "event-1",
                Some("management-key"),
                Some(" org-1 "),
            )
            .await
            .unwrap();
        assert_eq!(response.application_id.as_deref(), Some("application-1"));
        assert_eq!(
            response.evidence_facts[0]["fact_type"],
            "canvas.course_completion"
        );
        assert_eq!(
            response.policy_decision,
            json!({"allowed": true}).as_object().cloned()
        );
        assert_eq!(
            response.response["private_extension"],
            "preserved-on-recorded-response"
        );
        assert!(response.replay_available);
    }

    #[tokio::test]
    async fn authentication_and_tenant_header_precede_repository_projection() {
        let service = CanvasEventStatusService::new(
            Some("management-key"),
            Arc::new(Repository(Some(receipt(json!([]))))),
        );
        assert_eq!(
            service
                .get("account-1", "event-1", None, Some("org-1"))
                .await,
            Err(CanvasEventStatusError::Security(
                TransactionReadError::ApiKeyMissing
            ))
        );
        assert_eq!(
            service
                .get("account-1", "event-1", Some("management-key"), None)
                .await,
            Err(CanvasEventStatusError::Security(
                TransactionReadError::TrustedOrganizationRequired
            ))
        );
    }

    #[test]
    fn malformed_nested_projection_fails_closed_but_non_object_response_is_empty() {
        let empty = CanvasEvidenceEventStatusResponse::try_from(receipt(json!([]))).unwrap();
        assert!(empty.response.is_empty());
        assert!(empty.evidence_facts.is_empty());
        assert!(empty.policy_decision.is_none());

        for legacy_falsy_value in [json!(null), json!(false), json!(0), json!(""), json!({})] {
            let projected = CanvasEvidenceEventStatusResponse::try_from(receipt(json!({
                "evidence_facts": legacy_falsy_value
            })))
            .unwrap();
            assert!(projected.evidence_facts.is_empty());
        }

        assert_eq!(
            CanvasEvidenceEventStatusResponse::try_from(receipt(json!({
                "evidence_facts": ["not-an-object"]
            }))),
            Err(CanvasEventStatusError::MalformedReceipt)
        );
    }
}
