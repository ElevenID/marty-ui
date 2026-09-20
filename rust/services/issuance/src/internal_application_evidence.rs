//! Shared evidence-policy transition orchestration for internal Applications.
//!
//! Provider normalization happens before this layer. This owner evaluates the
//! shared Rust policy kernel, prepares issuance when permitted, and submits one
//! atomic application/fact/transaction/audit write set to persistence.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    application_template_domain::ApplicationTemplateRecord,
    credential::CredentialTransaction,
    internal_application_approval::InternalApplicationTransactionPreparer,
    internal_application_diagnostics::warn_external_evidence_failure,
    internal_application_domain::{
        python_datetime, ApplicationRecord, ApplicationStatus, EvidenceFactRecord,
        EvidenceFactResponse, ExternalEvidenceApiCheckRequest, ExternalEvidenceApiCheckResponse,
        IssuanceEventRecord,
    },
    internal_application_service::InternalApplicationApprovalError,
    internal_external_evidence::{
        execute_external_evidence_api_check, requirement_check_id,
        EnvironmentExternalEvidenceSecrets, ExternalEvidenceApiError, ExternalEvidenceSecrets,
        ExternalEvidenceTransport, SecureExternalEvidenceTransport,
    },
    python_value::python_truthy,
};

const EXTERNAL_REVIEWER_ID: &str = "external-evidence:auto-approval";
const EXTERNAL_REVIEW_NOTES: &str =
    "Auto-approved by MIP policy after user-defined external evidence API check";

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum InternalApplicationEvidenceRepositoryError {
    #[error("Application evidence repository is unavailable")]
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceCommitOutcome {
    Committed,
    ConcurrentChange,
}

#[derive(Clone, Debug)]
pub struct EvidenceTransitionWrite {
    pub application: ApplicationRecord,
    pub expected_status: ApplicationStatus,
    pub expected_updated_at: DateTime<Utc>,
    pub evidence_fact: EvidenceFactRecord,
    pub transaction: Option<CredentialTransaction>,
    pub events: Vec<IssuanceEventRecord>,
}

#[async_trait]
pub trait InternalApplicationEvidenceRepository: Send + Sync {
    async fn list_facts(
        &self,
        application_id: &str,
    ) -> Result<Vec<EvidenceFactRecord>, InternalApplicationEvidenceRepositoryError>;

    async fn approval_policy_set(
        &self,
        organization_id: &str,
        policy_set_id: &str,
    ) -> Result<Option<Map<String, Value>>, InternalApplicationEvidenceRepositoryError>;

    async fn commit_transition(
        &self,
        write: &EvidenceTransitionWrite,
    ) -> Result<EvidenceCommitOutcome, InternalApplicationEvidenceRepositoryError>;

    /// A rejection or other lifecycle change wins over auto-approval. Preserve
    /// the provider fact and complete audit trail without mutating the winner.
    async fn commit_conflict_evidence(
        &self,
        application_id: &str,
        organization_id: &str,
        fact: &EvidenceFactRecord,
        events: &[IssuanceEventRecord],
    ) -> Result<(), InternalApplicationEvidenceRepositoryError>;
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum InternalApplicationEvidenceError {
    #[error(transparent)]
    External(#[from] ExternalEvidenceApiError),
    #[error(transparent)]
    Repository(#[from] InternalApplicationEvidenceRepositoryError),
    #[error(transparent)]
    Approval(#[from] InternalApplicationApprovalError),
    #[error("Application lifecycle changed during evidence processing")]
    ConcurrentChange,
    #[error("Evidence policy evaluation is unavailable")]
    Policy,
}

#[async_trait]
pub trait InternalApplicationEvidenceCoordinator: Send + Sync {
    async fn run_external_check(
        &self,
        application: ApplicationRecord,
        template: ApplicationTemplateRecord,
        requirement: Map<String, Value>,
        request: ExternalEvidenceApiCheckRequest,
    ) -> Result<ExternalEvidenceApiCheckResponse, InternalApplicationEvidenceError>;
}

#[derive(Clone)]
pub struct DefaultInternalApplicationEvidenceCoordinator {
    repository: Arc<dyn InternalApplicationEvidenceRepository>,
    preparer: Arc<dyn InternalApplicationTransactionPreparer>,
    transport: Arc<dyn ExternalEvidenceTransport>,
    secrets: Arc<dyn ExternalEvidenceSecrets>,
}

impl std::fmt::Debug for DefaultInternalApplicationEvidenceCoordinator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DefaultInternalApplicationEvidenceCoordinator")
            .finish_non_exhaustive()
    }
}

impl DefaultInternalApplicationEvidenceCoordinator {
    #[must_use]
    pub fn new(
        repository: Arc<dyn InternalApplicationEvidenceRepository>,
        preparer: Arc<dyn InternalApplicationTransactionPreparer>,
    ) -> Self {
        Self {
            repository,
            preparer,
            transport: Arc::new(SecureExternalEvidenceTransport),
            secrets: Arc::new(EnvironmentExternalEvidenceSecrets),
        }
    }

    #[must_use]
    pub fn with_external_dependencies(
        mut self,
        transport: Arc<dyn ExternalEvidenceTransport>,
        secrets: Arc<dyn ExternalEvidenceSecrets>,
    ) -> Self {
        self.transport = transport;
        self.secrets = secrets;
        self
    }

    async fn policy_decision(
        &self,
        application: &ApplicationRecord,
        template: &ApplicationTemplateRecord,
        facts: &[EvidenceFactRecord],
    ) -> Result<Map<String, Value>, InternalApplicationEvidenceError> {
        let policy_set = match template
            .approval_policy_set_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(policy_set_id) => self
                .repository
                .approval_policy_set(&application.organization_id, policy_set_id)
                .await?
                .map(Value::Object),
            None => None,
        };
        let facts = facts.iter().map(fact_policy_json).collect::<Vec<_>>();
        let request = json!({
            "app": {
                "id": application.id,
                "organization_id": application.organization_id,
                "status": application.status.as_str(),
            },
            "template": {
                "approval_policy_set_id": template.approval_policy_set_id,
            },
            "binding": null,
            "requirements": template.evidence_requirements,
            "facts": facts,
            "policy_set": policy_set,
        });
        let request = serde_json::to_string(&request)
            .map_err(|_| InternalApplicationEvidenceError::Policy)?;
        let response =
            marty_verification::evidence_policy::evaluate_application_evidence_policy_json(
                &request,
            )
            .map_err(|_| InternalApplicationEvidenceError::Policy)?;
        serde_json::from_str::<Value>(&response)
            .ok()
            .and_then(|value| value.as_object().cloned())
            .ok_or(InternalApplicationEvidenceError::Policy)
    }
}

#[async_trait]
impl InternalApplicationEvidenceCoordinator for DefaultInternalApplicationEvidenceCoordinator {
    async fn run_external_check(
        &self,
        mut application: ApplicationRecord,
        template: ApplicationTemplateRecord,
        requirement: Map<String, Value>,
        request: ExternalEvidenceApiCheckRequest,
    ) -> Result<ExternalEvidenceApiCheckResponse, InternalApplicationEvidenceError> {
        let now = Utc::now();
        let check_id = requirement_check_id(&requirement);
        let check = match execute_external_evidence_api_check(
            &application,
            &requirement,
            &request.inputs,
            self.transport.as_ref(),
            self.secrets.as_ref(),
            now,
            Uuid::new_v4().to_string(),
        )
        .await
        {
            Ok(check) => check,
            Err(error) => {
                if error == ExternalEvidenceApiError::Transport {
                    warn_external_evidence_failure(&application.id, &check_id);
                }
                return Err(error.into());
            }
        };
        let mut evidence_fact = check.evidence_fact;
        let mut facts = self.repository.list_facts(&application.id).await?;
        if let Some(previous) = facts
            .iter()
            .rev()
            .find(|fact| fact.logical_key == evidence_fact.logical_key)
        {
            evidence_fact.superseded_fact_id = Some(previous.id.clone());
        }
        facts.push(evidence_fact.clone());

        let expected_status = application.status;
        let expected_updated_at = application.updated_at;
        application.evidence_submissions.push(Map::from_iter([
            (
                "evidence_type".to_owned(),
                requirement
                    .get("evidence_type")
                    .filter(|value| python_truthy(value))
                    .cloned()
                    .unwrap_or_else(|| Value::String("EXTERNAL_API".to_owned())),
            ),
            (
                "evidence_data".to_owned(),
                json!({
                    "provider": evidence_fact.provider,
                    "fact_type": evidence_fact.fact_type,
                    "scope": evidence_fact.scope,
                    "assertion": evidence_fact.assertion,
                }),
            ),
            (
                "source".to_owned(),
                Value::Object(evidence_fact.source.clone()),
            ),
            ("evidence_fact_ids".to_owned(), json!([evidence_fact.id])),
            (
                "verification".to_owned(),
                Value::Object(evidence_fact.verification.clone()),
            ),
            (
                "submitted_at".to_owned(),
                Value::String(python_datetime(now)),
            ),
        ]));
        merge_context(
            &mut application.integration_context,
            "external_evidence_api",
            Map::from_iter([
                (
                    "last_check_id".to_owned(),
                    Value::String(check.check_id.clone()),
                ),
                (
                    "last_evidence_fact_id".to_owned(),
                    Value::String(evidence_fact.id.clone()),
                ),
                (
                    "provider".to_owned(),
                    Value::String(evidence_fact.provider.clone()),
                ),
                (
                    "fact_type".to_owned(),
                    Value::String(evidence_fact.fact_type.clone()),
                ),
                (
                    "verification_status".to_owned(),
                    evidence_fact
                        .verification
                        .get("status")
                        .cloned()
                        .unwrap_or(Value::Null),
                ),
                (
                    "response_metadata".to_owned(),
                    Value::Object(check.response_metadata.clone()),
                ),
                ("checked_at".to_owned(), Value::String(python_datetime(now))),
            ]),
        );
        let mut policy = self
            .policy_decision(&application, &template, &facts)
            .await?;
        application
            .integration_context
            .insert("policy".to_owned(), Value::Object(policy.clone()));

        let base_metadata = Map::from_iter([
            (
                "organization_id".to_owned(),
                Value::String(application.organization_id.clone()),
            ),
            (
                "source".to_owned(),
                Value::String("external_evidence_api".to_owned()),
            ),
            ("check_id".to_owned(), Value::String(check.check_id.clone())),
        ]);
        let mut events = vec![event(
            &application,
            "evidence_fact_created",
            None,
            extend(
                base_metadata.clone(),
                Map::from_iter([
                    (
                        "evidence_fact_id".to_owned(),
                        Value::String(evidence_fact.id.clone()),
                    ),
                    (
                        "fact_type".to_owned(),
                        Value::String(evidence_fact.fact_type.clone()),
                    ),
                    (
                        "provider".to_owned(),
                        Value::String(evidence_fact.provider.clone()),
                    ),
                    (
                        "verification_method".to_owned(),
                        evidence_fact
                            .verification
                            .get("method")
                            .cloned()
                            .unwrap_or(Value::Null),
                    ),
                ]),
            ),
            now,
        )];
        let policy_allowed = policy.get("allowed") == Some(&Value::Bool(true));
        events.push(event(
            &application,
            if policy_allowed {
                "evidence_policy_permitted"
            } else {
                "evidence_policy_denied"
            },
            None,
            extend(
                base_metadata.clone(),
                Map::from_iter([
                    ("policy_decision".to_owned(), Value::Object(policy.clone())),
                    (
                        "evidence_fact_ids".to_owned(),
                        Value::Array(
                            facts
                                .iter()
                                .map(|fact| Value::String(fact.id.clone()))
                                .collect(),
                        ),
                    ),
                ]),
            ),
            now,
        ));

        let auto_issue = requirement
            .get("auto_issue_on_permit")
            .is_some_and(python_truthy);
        let mut transaction = None;
        if policy_allowed
            && request.issue_on_permit
            && auto_issue
            && application.issuance_transaction_id.is_none()
        {
            match self
                .preparer
                .prepare_transaction(&application, &template)
                .await
            {
                Ok(prepared) => {
                    let transaction_id = prepared.id.clone();
                    if application.status == ApplicationStatus::Pending {
                        application
                            .approve_reserved(
                                transaction_id.clone(),
                                Some(EXTERNAL_REVIEW_NOTES.to_owned()),
                                EXTERNAL_REVIEWER_ID,
                                now,
                            )
                            .map_err(|_| InternalApplicationEvidenceError::ConcurrentChange)?;
                    } else {
                        application.issuance_transaction_id = Some(transaction_id.clone());
                        application.updated_at = now;
                    }
                    events.push(event(
                        &application,
                        "approval_issuance_succeeded",
                        Some(transaction_id),
                        extend(
                            base_metadata.clone(),
                            Map::from_iter([
                                ("policy_decision".to_owned(), Value::Object(policy.clone())),
                                (
                                    "evidence_fact_ids".to_owned(),
                                    Value::Array(
                                        facts
                                            .iter()
                                            .map(|fact| Value::String(fact.id.clone()))
                                            .collect(),
                                    ),
                                ),
                            ]),
                        ),
                        now,
                    ));
                    transaction = Some(prepared);
                }
                Err(error) => {
                    policy.insert("allowed".to_owned(), Value::Bool(false));
                    let message = error.to_string();
                    policy
                        .entry("errors".to_owned())
                        .or_insert_with(|| Value::Array(Vec::new()))
                        .as_array_mut()
                        .ok_or(InternalApplicationEvidenceError::Policy)?
                        .push(Value::String(message.clone()));
                    application
                        .integration_context
                        .insert("policy".to_owned(), Value::Object(policy.clone()));
                    events.push(event(
                        &application,
                        "approval_issuance_failed",
                        None,
                        extend(
                            base_metadata.clone(),
                            Map::from_iter([
                                ("policy_decision".to_owned(), Value::Object(policy.clone())),
                                ("errors".to_owned(), json!([message])),
                            ]),
                        ),
                        now,
                    ));
                    application.updated_at = now;
                }
            }
        } else {
            application.updated_at = now;
        }

        let write = EvidenceTransitionWrite {
            application: application.clone(),
            expected_status,
            expected_updated_at,
            evidence_fact: evidence_fact.clone(),
            transaction,
            events: events.clone(),
        };
        match self.repository.commit_transition(&write).await? {
            EvidenceCommitOutcome::Committed => {}
            EvidenceCommitOutcome::ConcurrentChange => {
                let message = "Application lifecycle changed during evidence processing";
                events.retain(|event| event.event_type != "approval_issuance_succeeded");
                policy.insert("allowed".to_owned(), Value::Bool(false));
                policy
                    .entry("errors".to_owned())
                    .or_insert_with(|| Value::Array(Vec::new()))
                    .as_array_mut()
                    .ok_or(InternalApplicationEvidenceError::Policy)?
                    .push(Value::String(message.to_owned()));
                events.push(event(
                    &application,
                    "approval_issuance_failed",
                    None,
                    extend(
                        base_metadata,
                        Map::from_iter([
                            ("policy_decision".to_owned(), Value::Object(policy)),
                            ("errors".to_owned(), json!([message])),
                        ]),
                    ),
                    now,
                ));
                self.repository
                    .commit_conflict_evidence(
                        &application.id,
                        &application.organization_id,
                        &evidence_fact,
                        &events,
                    )
                    .await?;
                return Err(InternalApplicationEvidenceError::ConcurrentChange);
            }
        }

        Ok(ExternalEvidenceApiCheckResponse {
            application_id: application.id,
            organization_id: application.organization_id,
            check_id: check.check_id,
            status: "evidence_received".to_owned(),
            application_status: application.status.as_str().to_owned(),
            evidence_fact: EvidenceFactResponse::from(&evidence_fact),
            policy_decision: application
                .integration_context
                .get("policy")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default(),
            issuance_transaction_id: application.issuance_transaction_id,
            response_metadata: check.response_metadata,
        })
    }
}

pub(crate) fn fact_policy_json(fact: &EvidenceFactRecord) -> Value {
    let mut value = Map::from_iter([
        ("id".to_owned(), Value::String(fact.id.clone())),
        (
            "logical_key".to_owned(),
            Value::String(fact.logical_key.clone()),
        ),
        ("provider".to_owned(), Value::String(fact.provider.clone())),
        (
            "fact_type".to_owned(),
            Value::String(fact.fact_type.clone()),
        ),
        (
            "subject_id".to_owned(),
            Value::String(fact.subject_id.clone()),
        ),
        ("scope".to_owned(), Value::Object(fact.scope.clone())),
        (
            "assertion".to_owned(),
            Value::Object(fact.assertion.clone()),
        ),
        (
            "verification".to_owned(),
            Value::Object(fact.verification.clone()),
        ),
        ("source".to_owned(), Value::Object(fact.source.clone())),
        (
            "effective_at".to_owned(),
            fact.effective_at
                .map(python_datetime)
                .map(Value::String)
                .unwrap_or(Value::Null),
        ),
        (
            "observed_at".to_owned(),
            Value::String(python_datetime(fact.observed_at)),
        ),
        (
            "created_at".to_owned(),
            Value::String(python_datetime(fact.created_at)),
        ),
    ]);
    if let Some(requirement_id) = &fact.requirement_id {
        value.insert(
            "requirement_id".to_owned(),
            Value::String(requirement_id.clone()),
        );
    }
    Value::Object(value)
}

fn merge_context(target: &mut Map<String, Value>, name: &str, update: Map<String, Value>) {
    match target.get_mut(name).and_then(Value::as_object_mut) {
        Some(existing) => existing.extend(update),
        None => {
            target.insert(name.to_owned(), Value::Object(update));
        }
    }
}

fn extend(mut base: Map<String, Value>, additional: Map<String, Value>) -> Map<String, Value> {
    base.extend(additional);
    base
}

fn event(
    application: &ApplicationRecord,
    event_type: &str,
    transaction_id: Option<String>,
    metadata: Map<String, Value>,
    now: DateTime<Utc>,
) -> IssuanceEventRecord {
    IssuanceEventRecord {
        id: Uuid::new_v4().to_string(),
        transaction_id,
        application_id: Some(application.id.clone()),
        event_type: event_type.to_owned(),
        metadata,
        created_at: now,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use chrono::Duration;

    use super::*;
    use crate::{
        application_template_domain::{ApplicationTemplateCreate, ApplicationTemplateStatus},
        credential::CredentialTransactionStatus,
        internal_external_evidence::{ExternalEvidenceHttpRequest, ExternalEvidenceHttpResponse},
    };

    struct MemoryEvidenceRepository {
        outcome: EvidenceCommitOutcome,
        write: Mutex<Option<EvidenceTransitionWrite>>,
        conflict_events: Mutex<Vec<IssuanceEventRecord>>,
    }

    #[async_trait]
    impl InternalApplicationEvidenceRepository for MemoryEvidenceRepository {
        async fn list_facts(
            &self,
            _application_id: &str,
        ) -> Result<Vec<EvidenceFactRecord>, InternalApplicationEvidenceRepositoryError> {
            Ok(Vec::new())
        }

        async fn approval_policy_set(
            &self,
            _organization_id: &str,
            _policy_set_id: &str,
        ) -> Result<Option<Map<String, Value>>, InternalApplicationEvidenceRepositoryError>
        {
            Ok(None)
        }

        async fn commit_transition(
            &self,
            write: &EvidenceTransitionWrite,
        ) -> Result<EvidenceCommitOutcome, InternalApplicationEvidenceRepositoryError> {
            *self.write.lock().expect("write lock") = Some(write.clone());
            Ok(self.outcome)
        }

        async fn commit_conflict_evidence(
            &self,
            _application_id: &str,
            _organization_id: &str,
            _fact: &EvidenceFactRecord,
            events: &[IssuanceEventRecord],
        ) -> Result<(), InternalApplicationEvidenceRepositoryError> {
            *self.conflict_events.lock().expect("events lock") = events.to_vec();
            Ok(())
        }
    }

    struct FixedPreparer;

    #[async_trait]
    impl InternalApplicationTransactionPreparer for FixedPreparer {
        async fn prepare_transaction(
            &self,
            application: &ApplicationRecord,
            _local_template: &ApplicationTemplateRecord,
        ) -> Result<CredentialTransaction, InternalApplicationApprovalError> {
            let now = Utc::now();
            Ok(CredentialTransaction {
                id: "transaction-1".to_owned(),
                organization_id: application.organization_id.clone(),
                credential_template_id: "credential-template-1".to_owned(),
                revocation_profile_id: Some("revocation-profile-1".to_owned()),
                renewal_of_credential_id: None,
                applicant_id: Some(application.applicant_identifier.clone()),
                application_id: Some(application.id.clone()),
                subject_did: None,
                idempotency_key_hash: None,
                idempotency_request_hash: None,
                status: CredentialTransactionStatus::Pending,
                pre_authorized_code: "pre-authorized-code".to_owned(),
                nonce: None,
                claims: application.form_data.clone(),
                credential_type: Some("EmployeeCredential".to_owned()),
                selective_disclosure_claims: Vec::new(),
                zk_predicate_claims: Vec::new(),
                credential_payload_format: "w3c_vcdm_v2_sd_jwt".to_owned(),
                wallet_configs: Vec::new(),
                validity_days: 365,
                renewable: false,
                renewal_window_days: 30,
                delivery_mode: "wallet_only".to_owned(),
                issuer_profile_id: Some("issuer-profile-1".to_owned()),
                issuer_mode: "org_managed".to_owned(),
                issuer_did: Some("did:web:issuer.example".to_owned()),
                issuer_algorithm: Some("ES256".to_owned()),
                signing_service_id: Some("kms-service-1".to_owned()),
                reserved_credential_id: None,
                oid4vci_client_id: None,
                created_at: now,
                expires_at: now + Duration::minutes(15),
            })
        }
    }

    struct FixedTransport;

    #[async_trait]
    impl ExternalEvidenceTransport for FixedTransport {
        async fn send(
            &self,
            _request: ExternalEvidenceHttpRequest,
        ) -> Result<ExternalEvidenceHttpResponse, ExternalEvidenceApiError> {
            Ok(ExternalEvidenceHttpResponse {
                status_code: 200,
                body: serde_json::to_vec(&json!({
                    "id": "provider-event-1",
                    "status": "verified",
                    "checks": {"passive_auth_valid": true},
                    "biometric": {"face_match_score": 0.91},
                    "document": {"issuing_country": "US", "not_expired": true}
                }))
                .expect("response JSON"),
            })
        }
    }

    struct NoSecrets;

    impl ExternalEvidenceSecrets for NoSecrets {
        fn get(&self, _name: &str) -> Option<String> {
            None
        }
    }

    fn application_and_template() -> (ApplicationRecord, ApplicationTemplateRecord) {
        let now = Utc::now();
        let request: ApplicationTemplateCreate = serde_json::from_value(json!({
            "organization_id": "org-passport",
            "name": "Passport application",
            "credential_template_id": "credential-template-1",
            "evidence_requirements": [requirement()]
        }))
        .expect("template request");
        let mut template = request
            .into_record("template-1".to_owned(), now)
            .expect("template");
        template.status = ApplicationTemplateStatus::Active;
        let application = ApplicationRecord::new(
            "application-1".to_owned(),
            "org-passport".to_owned(),
            crate::internal_application_domain::ApplicationCreate {
                application_template_id: template.id.clone(),
                applicant_data: json!({
                    "email": "ada@example.com",
                    "passport_number": "X1234567"
                })
                .as_object()
                .expect("applicant data")
                .clone(),
                integration_context: Map::new(),
            },
            "unused",
            now,
        )
        .expect("application");
        (application, template)
    }

    fn requirement() -> Value {
        json!({
            "evidence_id": "passport-check",
            "evidence_type": "EXTERNAL_API",
            "description": "Verify the applicant passport",
            "required": true,
            "provider": "passport_verifier",
            "fact_type": "passport.document_verified",
            "scope": {"document_type": "passport"},
            "api": {
                "method": "POST",
                "url": "https://provider.example/check",
                "body": {"passport_number": "{{application.form_data.passport_number}}"}
            },
            "expected_response": {
                "status_codes": [200],
                "json": {"all": [
                    {"path": "$.status", "op": "eq", "value": "verified"},
                    {"path": "$.checks.passive_auth_valid", "op": "eq", "value": true},
                    {"path": "$.biometric.face_match_score", "op": ">=", "value": 0.85}
                ]}
            },
            "response_mapping": {
                "provider_event_id_path": "$.id",
                "verification_status_path": "$.status",
                "verification_verified_values": ["verified"],
                "scope": {"issuing_country": "$.document.issuing_country"},
                "assertion": {
                    "passive_auth_valid": "$.checks.passive_auth_valid",
                    "face_match_score": "$.biometric.face_match_score",
                    "document_not_expired": "$.document.not_expired"
                }
            },
            "pass_rule": {"all": [
                {"path": "assertion.passive_auth_valid", "op": "eq", "value": true},
                {"path": "assertion.face_match_score", "op": ">=", "value": 0.85},
                {"path": "assertion.document_not_expired", "op": "eq", "value": true}
            ]},
            "verification_method": "EXTERNAL_API_RESPONSE",
            "auto_issue_on_permit": true
        })
    }

    fn coordinator(
        repository: Arc<MemoryEvidenceRepository>,
    ) -> DefaultInternalApplicationEvidenceCoordinator {
        DefaultInternalApplicationEvidenceCoordinator::new(repository, Arc::new(FixedPreparer))
            .with_external_dependencies(Arc::new(FixedTransport), Arc::new(NoSecrets))
    }

    #[tokio::test]
    async fn permit_builds_one_atomic_fact_policy_transaction_and_audit_write_set() {
        let repository = Arc::new(MemoryEvidenceRepository {
            outcome: EvidenceCommitOutcome::Committed,
            write: Mutex::new(None),
            conflict_events: Mutex::new(Vec::new()),
        });
        let (application, template) = application_and_template();
        let response = coordinator(repository.clone())
            .run_external_check(
                application,
                template,
                requirement().as_object().expect("requirement").clone(),
                ExternalEvidenceApiCheckRequest {
                    inputs: Map::new(),
                    issue_on_permit: true,
                },
            )
            .await
            .expect("external evidence transition");
        assert_eq!(response.application_status, "approved");
        assert_eq!(
            response.issuance_transaction_id.as_deref(),
            Some("transaction-1")
        );
        assert_eq!(response.policy_decision["allowed"], true);
        let write = repository
            .write
            .lock()
            .expect("write lock")
            .clone()
            .expect("atomic write");
        assert_eq!(write.application.status, ApplicationStatus::Approved);
        assert_eq!(
            write
                .transaction
                .as_ref()
                .map(|transaction| transaction.id.as_str()),
            Some("transaction-1")
        );
        assert_eq!(
            write
                .events
                .iter()
                .map(|event| event.event_type.as_str())
                .collect::<Vec<_>>(),
            [
                "evidence_fact_created",
                "evidence_policy_permitted",
                "approval_issuance_succeeded"
            ]
        );
    }

    #[tokio::test]
    async fn lifecycle_conflict_retains_fact_and_replaces_rolled_back_success_with_failure() {
        let repository = Arc::new(MemoryEvidenceRepository {
            outcome: EvidenceCommitOutcome::ConcurrentChange,
            write: Mutex::new(None),
            conflict_events: Mutex::new(Vec::new()),
        });
        let (application, template) = application_and_template();
        assert_eq!(
            coordinator(repository.clone())
                .run_external_check(
                    application,
                    template,
                    requirement().as_object().expect("requirement").clone(),
                    ExternalEvidenceApiCheckRequest {
                        inputs: Map::new(),
                        issue_on_permit: true,
                    },
                )
                .await,
            Err(InternalApplicationEvidenceError::ConcurrentChange)
        );
        assert_eq!(
            repository
                .conflict_events
                .lock()
                .expect("events lock")
                .iter()
                .map(|event| event.event_type.as_str())
                .collect::<Vec<_>>(),
            [
                "evidence_fact_created",
                "evidence_policy_permitted",
                "approval_issuance_failed"
            ]
        );
    }
}
