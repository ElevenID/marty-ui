use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use marty_issuance_service::{
    application_template_domain::{
        ApplicationTemplateCreate, ApplicationTemplateRecord, ApplicationTemplateStatus,
    },
    canvas_award_candidate_approval::CanvasApplicationApprovalSnapshot,
    canvas_event_status::CanvasEventReceipt,
    credential::{CredentialTransaction, CredentialTransactionStatus},
    internal_application_domain::{
        ApplicationCreate, ApplicationRecord, ApplicationStatus, EvidenceFactRecord,
        IssuanceEventRecord,
    },
    internal_application_reconciliation::{
        DefaultInternalApplicationReconciler, EvidenceReconciliationCommitOutcome,
        EvidenceReconciliationReceiptSnapshot, EvidenceReconciliationRepositoryError,
        EvidenceReconciliationSnapshot, EvidenceReconciliationWrite, InternalApplicationReconciler,
        InternalApplicationReconciliationPreparer, InternalApplicationReconciliationRepository,
        PreparedEvidenceReconciliationIssuance,
    },
};
use serde_json::{json, Map, Value};

const LIFECYCLE_CONFLICT: &str = "Application lifecycle changed during reconciliation";

struct MemoryRepository {
    snapshot: EvidenceReconciliationSnapshot,
    receipts: Vec<EvidenceReconciliationReceiptSnapshot>,
    outcome: EvidenceReconciliationCommitOutcome,
    writes: Mutex<Vec<EvidenceReconciliationWrite>>,
    conflict_events: Mutex<Vec<IssuanceEventRecord>>,
}

#[async_trait]
impl InternalApplicationReconciliationRepository for MemoryRepository {
    async fn applications(
        &self,
        organization_id: &str,
        application_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ApplicationRecord>, EvidenceReconciliationRepositoryError> {
        let application = &self.snapshot.application;
        Ok((application.organization_id == organization_id
            && application_id.is_none_or(|id| id == application.id)
            && limit > 0)
            .then(|| application.clone())
            .into_iter()
            .collect())
    }

    async fn snapshot(
        &self,
        application: &ApplicationRecord,
    ) -> Result<EvidenceReconciliationSnapshot, EvidenceReconciliationRepositoryError> {
        let mut snapshot = self.snapshot.clone();
        snapshot.application = application.clone();
        Ok(snapshot)
    }

    async fn receipts(
        &self,
        _organization_id: &str,
        limit: usize,
    ) -> Result<Vec<EvidenceReconciliationReceiptSnapshot>, EvidenceReconciliationRepositoryError>
    {
        Ok(self.receipts.iter().take(limit).cloned().collect())
    }

    async fn commit(
        &self,
        write: &EvidenceReconciliationWrite,
    ) -> Result<EvidenceReconciliationCommitOutcome, EvidenceReconciliationRepositoryError> {
        self.writes.lock().expect("writes").push(write.clone());
        Ok(self.outcome.clone())
    }

    async fn commit_conflict_events(
        &self,
        _application_id: &str,
        _organization_id: &str,
        events: &[IssuanceEventRecord],
    ) -> Result<(), EvidenceReconciliationRepositoryError> {
        *self.conflict_events.lock().expect("conflict events") = events.to_vec();
        Ok(())
    }
}

struct FixedPreparer;

#[async_trait]
impl InternalApplicationReconciliationPreparer for FixedPreparer {
    async fn prepare(
        &self,
        snapshot: &EvidenceReconciliationSnapshot,
        now: DateTime<Utc>,
    ) -> Result<PreparedEvidenceReconciliationIssuance, String> {
        Ok(PreparedEvidenceReconciliationIssuance {
            transaction: transaction(&snapshot.application, now),
            approval_snapshot: CanvasApplicationApprovalSnapshot {
                application: approval_application(&snapshot.application),
                application_template: json!({
                    "id": "template-1",
                    "organization_id": "org-123",
                    "credential_template_id": "credential-template-1",
                    "approval_policy_set_id": null,
                    "status": "active"
                })
                .as_object()
                .expect("template")
                .clone(),
                platform: snapshot.platform.clone().expect("platform"),
                binding: snapshot.binding.clone().expect("binding"),
                existing_transaction: snapshot.existing_transaction.clone(),
            },
        })
    }
}

#[tokio::test]
async fn missing_policy_is_evaluated_and_committed_with_one_atomic_approval_write() {
    let repository = repository(
        snapshot(application(None)),
        EvidenceReconciliationCommitOutcome::Committed,
    );
    let result = reconciler(repository.clone())
        .reconcile("org-123", None, 100, false, true)
        .await
        .expect("reconciliation");
    assert_eq!(result.metrics.scanned_applications, 1);
    assert_eq!(result.metrics.evaluated_policies, 1);
    assert_eq!(result.metrics.policy_permits, 1);
    assert_eq!(result.metrics.approval_issuance_successes, 1);
    assert_eq!(result.records[0].status_after, "approved");
    assert_eq!(result.records[0].action, "approval_issuance_succeeded");
    let writes = repository.writes.lock().expect("writes");
    assert_eq!(writes.len(), 1);
    assert_eq!(
        writes[0]
            .events
            .iter()
            .map(|event| event.event_type.as_str())
            .collect::<Vec<_>>(),
        ["evidence_policy_permitted", "approval_issuance_succeeded"]
    );
    assert_eq!(
        writes[0].application.reviewer_id.as_deref(),
        Some("canvas:evidence-reconciliation")
    );
}

#[tokio::test]
async fn existing_permit_recovers_issuance_without_reevaluating_policy() {
    let policy = json!({
        "allowed": true,
        "engine": "cedar",
        "policy_source": "bundled",
        "policy_set_id": null,
        "reasons": [],
        "errors": [],
        "context": {"all_required_evidence_satisfied": true}
    });
    let repository = repository(
        snapshot(application(Some(policy))),
        EvidenceReconciliationCommitOutcome::Committed,
    );
    let result = reconciler(repository.clone())
        .reconcile("org-123", Some("application-1"), 100, false, true)
        .await
        .expect("reconciliation");
    assert_eq!(result.metrics.evaluated_policies, 0);
    assert_eq!(result.metrics.approval_issuance_successes, 1);
    assert_eq!(
        result.records[0].action,
        "approval_issuance_recovered_from_policy_permit"
    );
    assert_eq!(
        repository.writes.lock().expect("writes")[0]
            .events
            .iter()
            .map(|event| event.event_type.as_str())
            .collect::<Vec<_>>(),
        ["approval_issuance_succeeded"]
    );
}

#[tokio::test]
async fn dry_run_reports_stale_receipt_without_any_application_write() {
    let application = application(None);
    let repository = Arc::new(MemoryRepository {
        snapshot: snapshot(application.clone()),
        receipts: vec![EvidenceReconciliationReceiptSnapshot {
            receipt: CanvasEventReceipt {
                id: "receipt-1".to_owned(),
                provider_event_id: "event-1".to_owned(),
                canvas_account_id: Some("account-1".to_owned()),
                organization_id: "org-123".to_owned(),
                credential_template_id: "credential-template-1".to_owned(),
                payload_hash: "payload-1".to_owned(),
                issuance_transaction_id: None,
                issuance_response: json!({
                    "application_id": "application-1",
                    "evidence_facts": []
                }),
                status: "evidence_received".to_owned(),
                error_summary: None,
                first_seen_at: now(),
                last_seen_at: now(),
            },
            application: Some(application),
        }],
        outcome: EvidenceReconciliationCommitOutcome::Committed,
        writes: Mutex::new(Vec::new()),
        conflict_events: Mutex::new(Vec::new()),
    });
    let result = reconciler(repository.clone())
        .reconcile("org-123", None, 100, true, true)
        .await
        .expect("dry-run reconciliation");
    assert!(result.dry_run);
    assert_eq!(
        result.records[0].action,
        "would_create_or_refresh_issuance_transaction"
    );
    assert_eq!(
        result.stale_receipts[0].reasons,
        [
            "receipt_without_evidence_fact_metadata",
            "receipt_without_policy_decision"
        ]
    );
    assert!(repository.writes.lock().expect("writes").is_empty());
}

#[tokio::test]
async fn lifecycle_conflict_preserves_winner_and_emits_permit_then_failure_only() {
    let mut rejected = application(None);
    rejected.status = ApplicationStatus::Rejected;
    let repository = repository(
        snapshot(application(None)),
        EvidenceReconciliationCommitOutcome::ConcurrentChange {
            current: Some(Box::new(rejected)),
        },
    );
    let result = reconciler(repository.clone())
        .reconcile("org-123", None, 100, false, true)
        .await
        .expect("reconciliation conflict");
    assert_eq!(result.records[0].status_after, "rejected");
    assert_eq!(
        result.records[0].action,
        "skipped_concurrent_application_change"
    );
    assert_eq!(result.records[0].errors, [LIFECYCLE_CONFLICT]);
    assert_eq!(result.metrics.approval_issuance_failures, 1);
    assert_eq!(
        repository
            .conflict_events
            .lock()
            .expect("conflict events")
            .iter()
            .map(|event| event.event_type.as_str())
            .collect::<Vec<_>>(),
        ["evidence_policy_permitted", "approval_issuance_failed"]
    );
}

fn application(policy: Option<Value>) -> ApplicationRecord {
    let request = ApplicationCreate {
        application_template_id: "template-1".to_owned(),
        applicant_data: Map::from_iter([("email".to_owned(), json!("ada@example.test"))]),
        integration_context: json!({
            "canvas": {
                "canvas_platform_id": "platform-1",
                "canvas_program_binding_id": "binding-1",
                "canvas_account_id": "account-1"
            }
        })
        .as_object()
        .expect("integration")
        .clone(),
    };
    let mut application = ApplicationRecord::new(
        "application-1".to_owned(),
        "org-123".to_owned(),
        request,
        "ada@example.test",
        now(),
    )
    .expect("application");
    if let Some(policy) = policy {
        application
            .integration_context
            .insert("policy".to_owned(), policy);
    }
    application
}

fn template() -> ApplicationTemplateRecord {
    let request: ApplicationTemplateCreate = serde_json::from_value(json!({
        "organization_id": "org-123",
        "name": "Canvas completion",
        "credential_template_id": "credential-template-1",
        "evidence_requirements": [{
            "evidence_id": "course-completion",
            "evidence_type": "EXTERNAL_FACT",
            "description": "Complete the Canvas course",
            "required": true,
            "provider": "canvas",
            "fact_type": "canvas.course_completion"
        }]
    }))
    .expect("template request");
    let mut template = request
        .into_record("template-1".to_owned(), now())
        .expect("template");
    template.status = ApplicationTemplateStatus::Active;
    template
}

fn fact() -> EvidenceFactRecord {
    EvidenceFactRecord {
        id: "fact-1".to_owned(),
        organization_id: "org-123".to_owned(),
        application_id: "application-1".to_owned(),
        subject_id: "ada@example.test".to_owned(),
        provider: "canvas".to_owned(),
        fact_type: "canvas.course_completion".to_owned(),
        scope: Map::from_iter([
            ("canvas_account_id".to_owned(), json!("account-1")),
            ("course_id".to_owned(), json!("course-42")),
        ]),
        assertion: Map::from_iter([("completed".to_owned(), json!(true))]),
        verification: Map::from_iter([("status".to_owned(), json!("VERIFIED"))]),
        source: Map::new(),
        requirement_id: None,
        logical_key: "completion".to_owned(),
        source_revision: "revision-1".to_owned(),
        payload_hash: "payload-1".to_owned(),
        observed_at: now(),
        effective_at: Some(now()),
        superseded_fact_id: None,
        created_at: now(),
    }
}

fn snapshot(application: ApplicationRecord) -> EvidenceReconciliationSnapshot {
    EvidenceReconciliationSnapshot {
        application,
        template: Some(template()),
        platform: Some(
            json!({
                "id": "platform-1",
                "organization_id": "org-123",
                "canvas_account_id": "account-1",
                "registration_status": "installed",
                "enabled": true,
                "archived_at": null
            })
            .as_object()
            .expect("platform")
            .clone(),
        ),
        binding: Some(
            json!({
                "id": "binding-1",
                "organization_id": "org-123",
                "platform_id": "platform-1",
                "application_template_id": "template-1",
                "credential_template_id": "credential-template-1",
                "approval_policy_set_id": null,
                "auto_approve_on_evidence": true,
                "evidence_requirements": [{
                    "evidence_id": "course-completion",
                    "evidence_type": "EXTERNAL_FACT",
                    "description": "Complete the Canvas course",
                    "required": true,
                    "provider": "canvas",
                    "fact_type": "canvas.course_completion"
                }],
                "enabled": true,
                "archived_at": null
            })
            .as_object()
            .expect("binding")
            .clone(),
        ),
        facts: vec![fact()],
        policy_set: None,
        existing_transaction: None,
    }
}

fn transaction(application: &ApplicationRecord, now: DateTime<Utc>) -> CredentialTransaction {
    CredentialTransaction {
        id: "transaction-1".to_owned(),
        organization_id: application.organization_id.clone(),
        credential_template_id: "credential-template-1".to_owned(),
        revocation_profile_id: None,
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
        credential_type: Some("OpenBadgeCredential".to_owned()),
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
    }
}

fn approval_application(application: &ApplicationRecord) -> Map<String, Value> {
    json!({
        "id": application.id,
        "organization_id": application.organization_id,
        "application_template_id": application.application_template_id,
        "applicant_identifier": application.applicant_identifier,
        "form_data": application.form_data,
        "integration_context": application.integration_context,
        "status": application.status.as_str(),
        "issuance_transaction_id": application.issuance_transaction_id,
        "credential_id": application.credential_id,
    })
    .as_object()
    .expect("application")
    .clone()
}

fn now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-09-20T12:00:00+00:00")
        .expect("timestamp")
        .with_timezone(&Utc)
}

fn repository(
    snapshot: EvidenceReconciliationSnapshot,
    outcome: EvidenceReconciliationCommitOutcome,
) -> Arc<MemoryRepository> {
    Arc::new(MemoryRepository {
        snapshot,
        receipts: Vec::new(),
        outcome,
        writes: Mutex::new(Vec::new()),
        conflict_events: Mutex::new(Vec::new()),
    })
}

fn reconciler(repository: Arc<MemoryRepository>) -> DefaultInternalApplicationReconciler {
    DefaultInternalApplicationReconciler::new(repository, Arc::new(FixedPreparer))
}
