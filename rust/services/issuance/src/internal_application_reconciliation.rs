//! Canvas evidence reconciliation for internal Applications.
//!
//! The pinned verification crate owns deterministic plan and stale-receipt
//! decisions. This layer owns tenant-scoped orchestration, Canvas readiness,
//! remote-KMS preparation, optimistic concurrency, and atomic audit writes.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    application_template_domain::ApplicationTemplateRecord,
    canvas_award_candidate_approval::{
        plan_canvas_approval_transaction, plan_canvas_offer_transaction,
        plan_legacy_canvas_approval_transaction, resolve_and_attach_canvas_issuer,
        resolve_and_attach_required_issuer, reuse_canvas_approval_transaction,
        CanvasApplicationApprovalSnapshot, CanvasAwardApprovalSeedGenerator,
    },
    canvas_event_status::CanvasEventReceipt,
    canvas_issuance_guard::{
        evaluate_canvas_approval_snapshot, evaluate_canvas_offer_snapshot, CanvasGuardConfig,
        CanvasGuardSnapshot,
    },
    credential::{CredentialTransaction, CredentialTransactionStatus, IssuerContextResolver},
    internal_application_domain::{
        python_datetime, ApplicationRecord, ApplicationStatus, EvidenceFactRecord,
        EvidenceReconciliationMetrics, EvidenceReconciliationRecord, EvidenceReconciliationResult,
        IssuanceEventRecord, StaleCanvasEvidenceReceipt,
    },
    internal_application_evidence::fact_policy_json,
};

const RECONCILIATION_REVIEWER_ID: &str = "canvas:evidence-reconciliation";
const RECONCILIATION_REVIEW_NOTES: &str = "Recovered by MIP evidence policy reconciliation";
const LIFECYCLE_CONFLICT: &str = "Application lifecycle changed during reconciliation";

#[derive(Clone, Debug)]
pub struct EvidenceReconciliationSnapshot {
    pub application: ApplicationRecord,
    pub template: Option<ApplicationTemplateRecord>,
    pub platform: Option<Map<String, Value>>,
    pub binding: Option<Map<String, Value>>,
    pub facts: Vec<EvidenceFactRecord>,
    pub policy_set: Option<Map<String, Value>>,
    pub existing_transaction: Option<CredentialTransaction>,
}

#[derive(Clone, Debug)]
pub struct EvidenceReconciliationReceiptSnapshot {
    pub receipt: CanvasEventReceipt,
    pub application: Option<ApplicationRecord>,
}

#[derive(Clone, Debug)]
pub struct PreparedEvidenceReconciliationIssuance {
    pub transaction: CredentialTransaction,
    pub approval_snapshot: CanvasApplicationApprovalSnapshot,
}

#[derive(Clone, Debug)]
pub struct EvidenceReconciliationWrite {
    pub application: ApplicationRecord,
    pub expected_status: ApplicationStatus,
    pub expected_updated_at: DateTime<Utc>,
    pub transaction: Option<CredentialTransaction>,
    pub approval_snapshot: Option<CanvasApplicationApprovalSnapshot>,
    pub events: Vec<IssuanceEventRecord>,
    pub reconciled_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum EvidenceReconciliationCommitOutcome {
    Committed,
    ConcurrentChange {
        current: Option<Box<ApplicationRecord>>,
    },
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum EvidenceReconciliationRepositoryError {
    #[error("Evidence reconciliation repository is unavailable")]
    Unavailable,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum EvidenceReconciliationError {
    #[error(transparent)]
    Repository(#[from] EvidenceReconciliationRepositoryError),
    #[error("Evidence reconciliation policy evaluation is unavailable")]
    Policy,
}

#[async_trait]
pub trait InternalApplicationReconciliationRepository: Send + Sync {
    async fn applications(
        &self,
        organization_id: &str,
        application_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ApplicationRecord>, EvidenceReconciliationRepositoryError>;

    async fn snapshot(
        &self,
        application: &ApplicationRecord,
    ) -> Result<EvidenceReconciliationSnapshot, EvidenceReconciliationRepositoryError>;

    async fn receipts(
        &self,
        organization_id: &str,
        limit: usize,
    ) -> Result<Vec<EvidenceReconciliationReceiptSnapshot>, EvidenceReconciliationRepositoryError>;

    async fn commit(
        &self,
        write: &EvidenceReconciliationWrite,
    ) -> Result<EvidenceReconciliationCommitOutcome, EvidenceReconciliationRepositoryError>;

    async fn commit_conflict_events(
        &self,
        application_id: &str,
        organization_id: &str,
        events: &[IssuanceEventRecord],
    ) -> Result<(), EvidenceReconciliationRepositoryError>;
}

#[async_trait]
pub trait InternalApplicationReconciliationPreparer: Send + Sync {
    async fn prepare(
        &self,
        snapshot: &EvidenceReconciliationSnapshot,
        now: DateTime<Utc>,
    ) -> Result<PreparedEvidenceReconciliationIssuance, String>;
}

#[derive(Clone)]
pub struct CanvasEvidenceReconciliationPreparer {
    issuer_resolver: Arc<dyn IssuerContextResolver>,
    seeds: Arc<dyn CanvasAwardApprovalSeedGenerator>,
    guard_config: CanvasGuardConfig,
}

impl std::fmt::Debug for CanvasEvidenceReconciliationPreparer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasEvidenceReconciliationPreparer")
            .field("guard_config", &self.guard_config)
            .finish_non_exhaustive()
    }
}

impl CanvasEvidenceReconciliationPreparer {
    #[must_use]
    pub fn new(
        issuer_resolver: Arc<dyn IssuerContextResolver>,
        seeds: Arc<dyn CanvasAwardApprovalSeedGenerator>,
        guard_config: CanvasGuardConfig,
    ) -> Self {
        Self {
            issuer_resolver,
            seeds,
            guard_config,
        }
    }
}

#[async_trait]
impl InternalApplicationReconciliationPreparer for CanvasEvidenceReconciliationPreparer {
    async fn prepare(
        &self,
        snapshot: &EvidenceReconciliationSnapshot,
        now: DateTime<Utc>,
    ) -> Result<PreparedEvidenceReconciliationIssuance, String> {
        let platform = snapshot.platform.as_ref().ok_or_else(readiness_error)?;
        let binding = snapshot.binding.as_ref().ok_or_else(readiness_error)?;
        let template = snapshot.template.as_ref().ok_or_else(readiness_error)?;
        let projected = projected_canvas_application(&snapshot.application, platform, binding)?;
        let guard = CanvasGuardSnapshot {
            application: Value::Object(projected.clone()),
            application_template: Value::Object(template_policy_json(template)),
            platform: Value::Object(platform.clone()),
            binding: Value::Object(binding.clone()),
            evidence_facts: Vec::new(),
            policy_set: None,
        };
        match snapshot.application.status {
            ApplicationStatus::Pending => evaluate_canvas_approval_snapshot(
                &snapshot.application.organization_id,
                &snapshot.application.id,
                &guard,
                &self.guard_config,
                now,
            ),
            ApplicationStatus::Approved => evaluate_canvas_offer_snapshot(
                &snapshot.application.organization_id,
                &snapshot.application.id,
                &guard,
                &self.guard_config,
                now,
            ),
            _ => Err("canvas_application_invalid_status"),
        }
        .map_err(|_| readiness_error())?;

        let strict_snapshot = binding
            .get("credential_template_snapshot")
            .is_some_and(|value| !value.is_null());
        let seed = self.seeds.generate();
        let planned = if strict_snapshot {
            match snapshot.application.status {
                ApplicationStatus::Pending => {
                    plan_canvas_approval_transaction(&projected, binding, &seed, now)
                }
                ApplicationStatus::Approved => {
                    plan_canvas_offer_transaction(&projected, binding, &seed, now)
                }
                _ => None,
            }
        } else {
            let mut legacy = projected.clone();
            legacy.insert("status".to_owned(), Value::String("pending".to_owned()));
            let credential_template_id = template
                .credential_template_id
                .as_deref()
                .unwrap_or_default();
            plan_legacy_canvas_approval_transaction(&legacy, credential_template_id, &seed, now)
        }
        .ok_or_else(readiness_error)?;
        let reusable = snapshot.existing_transaction.as_ref().filter(|existing| {
            existing.status == CredentialTransactionStatus::Pending && now <= existing.expires_at
        });
        let mut transaction = reusable.map_or(planned.clone(), |existing| {
            reuse_canvas_approval_transaction(existing, &planned, strict_snapshot)
        });
        if strict_snapshot {
            resolve_and_attach_canvas_issuer(
                self.issuer_resolver.as_ref(),
                binding,
                &mut transaction,
            )
            .await
            .map_err(|_| readiness_error())?;
        } else {
            resolve_and_attach_required_issuer(self.issuer_resolver.as_ref(), &mut transaction)
                .await
                .map_err(|_| readiness_error())?;
        }
        Ok(PreparedEvidenceReconciliationIssuance {
            transaction,
            approval_snapshot: approval_snapshot(snapshot, template, platform, binding),
        })
    }
}

fn readiness_error() -> String {
    "Canvas application is not ready for approval".to_owned()
}

#[async_trait]
pub trait InternalApplicationReconciler: Send + Sync {
    async fn reconcile(
        &self,
        organization_id: &str,
        application_id: Option<&str>,
        limit: usize,
        dry_run: bool,
        issue_on_permit: bool,
    ) -> Result<EvidenceReconciliationResult, EvidenceReconciliationError>;
}

#[derive(Clone)]
pub struct DefaultInternalApplicationReconciler {
    repository: Arc<dyn InternalApplicationReconciliationRepository>,
    preparer: Arc<dyn InternalApplicationReconciliationPreparer>,
}

struct ReconciliationConflict<'a> {
    application: &'a ApplicationRecord,
    current: Option<&'a ApplicationRecord>,
    status_before: &'a str,
    policy: &'a Map<String, Value>,
    canvas_facts: &'a [EvidenceFactRecord],
    policy_event: Option<IssuanceEventRecord>,
    now: DateTime<Utc>,
}

impl std::fmt::Debug for DefaultInternalApplicationReconciler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DefaultInternalApplicationReconciler")
            .finish_non_exhaustive()
    }
}

impl DefaultInternalApplicationReconciler {
    #[must_use]
    pub fn new(
        repository: Arc<dyn InternalApplicationReconciliationRepository>,
        preparer: Arc<dyn InternalApplicationReconciliationPreparer>,
    ) -> Self {
        Self {
            repository,
            preparer,
        }
    }
}

#[async_trait]
impl InternalApplicationReconciler for DefaultInternalApplicationReconciler {
    async fn reconcile(
        &self,
        organization_id: &str,
        application_id: Option<&str>,
        limit: usize,
        dry_run: bool,
        issue_on_permit: bool,
    ) -> Result<EvidenceReconciliationResult, EvidenceReconciliationError> {
        let mut metrics = EvidenceReconciliationMetrics::default();
        let applications = self
            .repository
            .applications(organization_id, application_id, limit)
            .await?;
        let mut records = Vec::with_capacity(applications.len());
        for application in applications {
            metrics.scanned_applications += 1;
            records.push(
                self.reconcile_application(application, dry_run, issue_on_permit, &mut metrics)
                    .await?,
            );
        }
        let receipts = self.repository.receipts(organization_id, limit).await?;
        let stale_receipts = receipts
            .into_iter()
            .filter_map(stale_receipt)
            .collect::<Result<Vec<_>, _>>()?;
        metrics.stale_receipts = stale_receipts.len() as u64;
        Ok(EvidenceReconciliationResult {
            organization_id: organization_id.to_owned(),
            dry_run,
            metrics,
            records,
            stale_receipts,
            generated_at: python_datetime(Utc::now()),
        })
    }
}

impl DefaultInternalApplicationReconciler {
    async fn reconcile_application(
        &self,
        application: ApplicationRecord,
        dry_run: bool,
        issue_on_permit: bool,
        metrics: &mut EvidenceReconciliationMetrics,
    ) -> Result<EvidenceReconciliationRecord, EvidenceReconciliationError> {
        let status_before = application.status.as_str().to_owned();
        let snapshot = self.repository.snapshot(&application).await?;
        let canvas_facts = snapshot
            .facts
            .iter()
            .filter(|fact| fact.provider == "canvas")
            .cloned()
            .collect::<Vec<_>>();
        if canvas_facts.is_empty() {
            metrics.skipped += 1;
            return Ok(record(
                &application,
                &status_before,
                "skipped_no_canvas_evidence_facts",
                0,
                None,
                application.issuance_transaction_id.clone(),
                Vec::new(),
            ));
        }
        if !matches!(
            application.status,
            ApplicationStatus::Pending | ApplicationStatus::Approved
        ) {
            metrics.skipped += 1;
            return Ok(record(
                &application,
                &status_before,
                "skipped_terminal_application_status",
                canvas_facts.len(),
                None,
                application.issuance_transaction_id.clone(),
                Vec::new(),
            ));
        }
        let Some(template) = snapshot.template.as_ref() else {
            metrics.approval_issuance_failures += 1;
            return Ok(record(
                &application,
                &status_before,
                "failed_missing_application_template",
                canvas_facts.len(),
                None,
                application.issuance_transaction_id.clone(),
                vec![format!(
                    "Application template {} was not found",
                    application.application_template_id
                )],
            ));
        };
        let Some(binding) = snapshot.binding.as_ref() else {
            metrics.skipped += 1;
            return Ok(record(
                &application,
                &status_before,
                "skipped_missing_canvas_program_binding",
                canvas_facts.len(),
                None,
                application.issuance_transaction_id.clone(),
                vec!["Canvas evidence reconciliation requires a Canvas program binding".to_owned()],
            ));
        };

        let existing_policy = application
            .integration_context
            .get("policy")
            .and_then(Value::as_object)
            .cloned();
        let policy_freshly_evaluated = existing_policy.is_none();
        let policy = match existing_policy {
            Some(policy) => policy,
            None => evaluate_policy(&snapshot, template, binding, &canvas_facts)?,
        };
        let now = Utc::now();
        let plan = reconciliation_plan(
            &policy,
            policy_freshly_evaluated,
            snapshot.existing_transaction.as_ref(),
            application.issuance_transaction_id.as_deref(),
            issue_on_permit,
            dry_run,
            now,
        )?;
        apply_metric_increments(metrics, &plan.metric_increments);
        let policy_event = plan.policy_event.as_deref().map(|decision| {
            reconciliation_event(
                &application,
                if decision == "permitted" {
                    "evidence_policy_permitted"
                } else {
                    "evidence_policy_denied"
                },
                None,
                &policy,
                &canvas_facts,
                &[],
                now,
            )
        });

        if dry_run {
            return Ok(record(
                &application,
                &status_before,
                &plan.action,
                canvas_facts.len(),
                Some(policy),
                plan.issuance_transaction_id,
                plan.errors,
            ));
        }

        if plan.next == "complete" {
            if let Some(policy_event) = policy_event {
                let mut updated = application.clone();
                apply_reconciliation_context(&mut updated, &policy, "policy_evaluated", &[], now);
                updated.updated_at = now;
                let write = EvidenceReconciliationWrite {
                    application: updated.clone(),
                    expected_status: application.status,
                    expected_updated_at: application.updated_at,
                    transaction: None,
                    approval_snapshot: None,
                    events: vec![policy_event],
                    reconciled_at: now,
                };
                if let EvidenceReconciliationCommitOutcome::ConcurrentChange { current } =
                    self.repository.commit(&write).await?
                {
                    metrics.skipped += 1;
                    return Ok(conflict_record(
                        &application,
                        current.as_deref(),
                        &status_before,
                        canvas_facts.len(),
                        policy,
                    ));
                }
                return Ok(record(
                    &updated,
                    &status_before,
                    &plan.action,
                    canvas_facts.len(),
                    Some(policy),
                    plan.issuance_transaction_id,
                    plan.errors,
                ));
            }
            return Ok(record(
                &application,
                &status_before,
                &plan.action,
                canvas_facts.len(),
                Some(policy),
                plan.issuance_transaction_id,
                plan.errors,
            ));
        }

        let mut events = policy_event.into_iter().collect::<Vec<_>>();
        let prepared = match self.preparer.prepare(&snapshot, now).await {
            Ok(prepared) => prepared,
            Err(error) => {
                let mut updated = application.clone();
                apply_reconciliation_context(
                    &mut updated,
                    &policy,
                    "approval_issuance_failed",
                    std::slice::from_ref(&error),
                    now,
                );
                updated.updated_at = now;
                events.push(reconciliation_event(
                    &application,
                    "approval_issuance_failed",
                    None,
                    &policy,
                    &canvas_facts,
                    std::slice::from_ref(&error),
                    now,
                ));
                let write = EvidenceReconciliationWrite {
                    application: updated.clone(),
                    expected_status: application.status,
                    expected_updated_at: application.updated_at,
                    transaction: None,
                    approval_snapshot: None,
                    events: events.clone(),
                    reconciled_at: now,
                };
                if let EvidenceReconciliationCommitOutcome::ConcurrentChange { current } =
                    self.repository.commit(&write).await?
                {
                    let policy_event = events
                        .iter()
                        .find(|event| event.event_type.starts_with("evidence_policy_"))
                        .cloned();
                    return self
                        .commit_conflict(
                            ReconciliationConflict {
                                application: &application,
                                current: current.as_deref(),
                                status_before: &status_before,
                                policy: &policy,
                                canvas_facts: &canvas_facts,
                                policy_event,
                                now,
                            },
                            metrics,
                        )
                        .await;
                }
                metrics.approval_issuance_failures += 1;
                return Ok(record(
                    &updated,
                    &status_before,
                    "approval_issuance_failed",
                    canvas_facts.len(),
                    Some(policy),
                    application.issuance_transaction_id.clone(),
                    vec![error],
                ));
            }
        };

        let transaction_id = prepared.transaction.id.clone();
        let mut updated = application.clone();
        apply_reconciliation_context(&mut updated, &policy, "policy_evaluated", &[], now);
        updated.status = ApplicationStatus::Approved;
        updated.review_notes = Some(RECONCILIATION_REVIEW_NOTES.to_owned());
        updated.reviewer_id = Some(RECONCILIATION_REVIEWER_ID.to_owned());
        updated.reviewed_at = Some(now);
        updated.updated_at = now;
        updated.issuance_transaction_id = Some(transaction_id.clone());
        events.push(reconciliation_event(
            &application,
            "approval_issuance_succeeded",
            Some(transaction_id.clone()),
            &policy,
            &canvas_facts,
            &[],
            now,
        ));
        let write = EvidenceReconciliationWrite {
            application: updated.clone(),
            expected_status: application.status,
            expected_updated_at: application.updated_at,
            transaction: Some(prepared.transaction),
            approval_snapshot: Some(prepared.approval_snapshot),
            events,
            reconciled_at: now,
        };
        if let EvidenceReconciliationCommitOutcome::ConcurrentChange { current } =
            self.repository.commit(&write).await?
        {
            return self
                .commit_conflict(
                    ReconciliationConflict {
                        application: &application,
                        current: current.as_deref(),
                        status_before: &status_before,
                        policy: &policy,
                        canvas_facts: &canvas_facts,
                        policy_event: plan.policy_event.map(|_| {
                            reconciliation_event(
                                &application,
                                "evidence_policy_permitted",
                                None,
                                &policy,
                                &canvas_facts,
                                &[],
                                now,
                            )
                        }),
                        now,
                    },
                    metrics,
                )
                .await;
        }
        metrics.approval_issuance_successes += 1;
        Ok(record(
            &updated,
            &status_before,
            &plan.action,
            canvas_facts.len(),
            Some(policy),
            Some(transaction_id),
            Vec::new(),
        ))
    }

    async fn commit_conflict(
        &self,
        conflict: ReconciliationConflict<'_>,
        metrics: &mut EvidenceReconciliationMetrics,
    ) -> Result<EvidenceReconciliationRecord, EvidenceReconciliationError> {
        metrics.approval_issuance_failures += 1;
        let errors = vec![LIFECYCLE_CONFLICT.to_owned()];
        let mut events = conflict.policy_event.into_iter().collect::<Vec<_>>();
        events.push(reconciliation_event(
            conflict.application,
            "approval_issuance_failed",
            None,
            conflict.policy,
            conflict.canvas_facts,
            &errors,
            conflict.now,
        ));
        self.repository
            .commit_conflict_events(
                &conflict.application.id,
                &conflict.application.organization_id,
                &events,
            )
            .await?;
        Ok(conflict_record(
            conflict.application,
            conflict.current,
            conflict.status_before,
            conflict.canvas_facts.len(),
            conflict.policy.clone(),
        ))
    }
}

#[derive(Debug, Deserialize)]
struct ReconciliationPlan {
    next: String,
    action: String,
    metric_increments: Map<String, Value>,
    policy_event: Option<String>,
    issuance_transaction_id: Option<String>,
    errors: Vec<String>,
}

fn reconciliation_plan(
    policy: &Map<String, Value>,
    policy_freshly_evaluated: bool,
    transaction: Option<&CredentialTransaction>,
    application_transaction_id: Option<&str>,
    issue_on_permit: bool,
    dry_run: bool,
    now: DateTime<Utc>,
) -> Result<ReconciliationPlan, EvidenceReconciliationError> {
    let transaction = transaction.map(|transaction| {
        json!({
            "id": transaction.id,
            "status": credential_transaction_status(transaction.status),
            "is_expired": now > transaction.expires_at,
        })
    });
    let request = json!({
        "policy": policy,
        "policy_freshly_evaluated": policy_freshly_evaluated,
        "issuance_transaction": transaction,
        "application_issuance_transaction_id": application_transaction_id,
        "issue_on_permit": issue_on_permit,
        "dry_run": dry_run,
    });
    let response =
        marty_verification::evidence_reconciliation::reconciliation_plan_json(&request.to_string())
            .map_err(|_| EvidenceReconciliationError::Policy)?;
    serde_json::from_str(&response).map_err(|_| EvidenceReconciliationError::Policy)
}

fn evaluate_policy(
    snapshot: &EvidenceReconciliationSnapshot,
    template: &ApplicationTemplateRecord,
    binding: &Map<String, Value>,
    facts: &[EvidenceFactRecord],
) -> Result<Map<String, Value>, EvidenceReconciliationError> {
    let requirements = effective_requirements(template, binding);
    let request = json!({
        "app": {
            "id": snapshot.application.id,
            "organization_id": snapshot.application.organization_id,
            "status": snapshot.application.status.as_str(),
        },
        "template": {
            "approval_policy_set_id": template.approval_policy_set_id,
        },
        "binding": {
            "approval_policy_set_id": binding.get("approval_policy_set_id").cloned().unwrap_or(Value::Null),
            "auto_approve_on_evidence": binding.get("auto_approve_on_evidence").cloned().unwrap_or(Value::Bool(false)),
        },
        "requirements": requirements,
        "facts": facts.iter().map(fact_policy_json).collect::<Vec<_>>(),
        "policy_set": snapshot.policy_set.clone().map(Value::Object),
    });
    let response = marty_verification::evidence_policy::evaluate_application_evidence_policy_json(
        &request.to_string(),
    )
    .map_err(|_| EvidenceReconciliationError::Policy)?;
    serde_json::from_str::<Value>(&response)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .ok_or(EvidenceReconciliationError::Policy)
}

fn effective_requirements(
    template: &ApplicationTemplateRecord,
    binding: &Map<String, Value>,
) -> Vec<Value> {
    let binding_requirements = binding
        .get("evidence_requirements")
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty())
        .cloned();
    binding_requirements.unwrap_or_else(|| {
        if template.evidence_requirements.is_empty() {
            vec![Value::String("canvas.course_completion".to_owned())]
        } else {
            template.evidence_requirements.clone()
        }
    })
}

fn stale_receipt(
    snapshot: EvidenceReconciliationReceiptSnapshot,
) -> Option<Result<StaleCanvasEvidenceReceipt, EvidenceReconciliationError>> {
    let response = snapshot.receipt.issuance_response.clone();
    let application_id = response
        .as_object()
        .and_then(|value| value.get("application_id"))
        .filter(|value| !python_falsy(value))
        .map(value_text);
    let application = snapshot.application.as_ref().map(|application| {
        json!({
            "policy": application.integration_context.get("policy").and_then(Value::as_object),
            "issuance_transaction_id": application.issuance_transaction_id,
        })
    });
    let request = json!({
        "issuance_response": response,
        "receipt_issuance_transaction_id": snapshot.receipt.issuance_transaction_id,
        "application": application,
    });
    let reasons = match marty_verification::evidence_reconciliation::stale_receipt_reasons_json(
        &request.to_string(),
    ) {
        Ok(response) => serde_json::from_str::<Vec<String>>(&response)
            .map_err(|_| EvidenceReconciliationError::Policy),
        Err(_) => Err(EvidenceReconciliationError::Policy),
    };
    let result = reasons.map(|reasons| StaleCanvasEvidenceReceipt {
        receipt_id: snapshot.receipt.id,
        provider_event_id: snapshot.receipt.provider_event_id,
        canvas_account_id: snapshot.receipt.canvas_account_id,
        application_id,
        status: snapshot.receipt.status,
        reasons,
        last_seen_at: python_datetime(snapshot.receipt.last_seen_at),
    });
    match &result {
        Ok(receipt) if receipt.reasons.is_empty() => None,
        _ => Some(result),
    }
}

fn credential_transaction_status(status: CredentialTransactionStatus) -> &'static str {
    match status {
        CredentialTransactionStatus::Pending => "pending",
        CredentialTransactionStatus::Authorized => "authorized",
        CredentialTransactionStatus::Signing => "signing",
        CredentialTransactionStatus::Issued => "issued",
        CredentialTransactionStatus::Failed => "failed",
        CredentialTransactionStatus::Expired => "expired",
        CredentialTransactionStatus::Revoked => "revoked",
    }
}

fn apply_metric_increments(
    metrics: &mut EvidenceReconciliationMetrics,
    increments: &Map<String, Value>,
) {
    for (name, value) in increments {
        let increment = value.as_u64().unwrap_or_default();
        match name.as_str() {
            "evaluated_policies" => metrics.evaluated_policies += increment,
            "policy_permits" => metrics.policy_permits += increment,
            "policy_denies" => metrics.policy_denies += increment,
            "approval_issuance_successes" => metrics.approval_issuance_successes += increment,
            "approval_issuance_failures" => metrics.approval_issuance_failures += increment,
            "skipped" => metrics.skipped += increment,
            _ => {}
        }
    }
}

fn apply_reconciliation_context(
    application: &mut ApplicationRecord,
    policy: &Map<String, Value>,
    action: &str,
    errors: &[String],
    now: DateTime<Utc>,
) {
    application
        .integration_context
        .insert("policy".to_owned(), Value::Object(policy.clone()));
    application.integration_context.insert(
        "evidence_reconciliation".to_owned(),
        json!({
            "last_action": action,
            "last_errors": errors,
            "last_reconciled_at": python_datetime(now),
        }),
    );
}

fn reconciliation_event(
    application: &ApplicationRecord,
    event_type: &str,
    transaction_id: Option<String>,
    policy: &Map<String, Value>,
    facts: &[EvidenceFactRecord],
    errors: &[String],
    now: DateTime<Utc>,
) -> IssuanceEventRecord {
    let mut metadata = Map::from_iter([
        (
            "organization_id".to_owned(),
            Value::String(application.organization_id.clone()),
        ),
        (
            "source".to_owned(),
            Value::String("reconciliation".to_owned()),
        ),
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
    ]);
    if !errors.is_empty() {
        metadata.insert("errors".to_owned(), json!(errors));
    }
    IssuanceEventRecord {
        id: Uuid::new_v4().to_string(),
        transaction_id,
        application_id: Some(application.id.clone()),
        event_type: event_type.to_owned(),
        metadata,
        created_at: now,
    }
}

fn record(
    application: &ApplicationRecord,
    status_before: &str,
    action: &str,
    fact_count: usize,
    policy_decision: Option<Map<String, Value>>,
    issuance_transaction_id: Option<String>,
    errors: Vec<String>,
) -> EvidenceReconciliationRecord {
    EvidenceReconciliationRecord {
        application_id: application.id.clone(),
        status_before: status_before.to_owned(),
        status_after: application.status.as_str().to_owned(),
        action: action.to_owned(),
        fact_count,
        policy_decision,
        issuance_transaction_id,
        errors,
    }
}

fn conflict_record(
    application: &ApplicationRecord,
    current: Option<&ApplicationRecord>,
    status_before: &str,
    fact_count: usize,
    policy: Map<String, Value>,
) -> EvidenceReconciliationRecord {
    let current = current.unwrap_or(application);
    record(
        current,
        status_before,
        "skipped_concurrent_application_change",
        fact_count,
        Some(policy),
        current.issuance_transaction_id.clone(),
        vec![LIFECYCLE_CONFLICT.to_owned()],
    )
}

pub(crate) fn application_approval_json(application: &ApplicationRecord) -> Map<String, Value> {
    Map::from_iter([
        ("id".to_owned(), Value::String(application.id.clone())),
        (
            "organization_id".to_owned(),
            Value::String(application.organization_id.clone()),
        ),
        (
            "application_template_id".to_owned(),
            Value::String(application.application_template_id.clone()),
        ),
        (
            "applicant_identifier".to_owned(),
            Value::String(application.applicant_identifier.clone()),
        ),
        (
            "form_data".to_owned(),
            Value::Object(application.form_data.clone()),
        ),
        (
            "integration_context".to_owned(),
            Value::Object(application.integration_context.clone()),
        ),
        (
            "status".to_owned(),
            Value::String(application.status.as_str().to_owned()),
        ),
        (
            "issuance_transaction_id".to_owned(),
            application
                .issuance_transaction_id
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        ),
        (
            "credential_id".to_owned(),
            application
                .credential_id
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        ),
    ])
}

fn projected_canvas_application(
    application: &ApplicationRecord,
    platform: &Map<String, Value>,
    binding: &Map<String, Value>,
) -> Result<Map<String, Value>, String> {
    let mut projected = application_approval_json(application);
    let integration = projected
        .get_mut("integration_context")
        .and_then(Value::as_object_mut)
        .ok_or_else(readiness_error)?;
    let canvas = integration
        .entry("canvas".to_owned())
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(readiness_error)?;
    for (name, value) in [
        ("canvas_platform_id", platform.get("id")),
        ("canvas_program_binding_id", binding.get("id")),
        ("canvas_account_id", platform.get("canvas_account_id")),
    ] {
        if canvas.get(name).is_none_or(Value::is_null) {
            if let Some(value) = value {
                canvas.insert(name.to_owned(), value.clone());
            }
        }
    }
    Ok(projected)
}

fn approval_snapshot(
    snapshot: &EvidenceReconciliationSnapshot,
    template: &ApplicationTemplateRecord,
    platform: &Map<String, Value>,
    binding: &Map<String, Value>,
) -> CanvasApplicationApprovalSnapshot {
    CanvasApplicationApprovalSnapshot {
        application: application_approval_json(&snapshot.application),
        application_template: approval_template_json(template),
        platform: platform.clone(),
        binding: approval_binding_json(binding),
        existing_transaction: snapshot.existing_transaction.clone(),
    }
}

fn template_policy_json(template: &ApplicationTemplateRecord) -> Map<String, Value> {
    Map::from_iter([
        ("id".to_owned(), Value::String(template.id.clone())),
        (
            "organization_id".to_owned(),
            Value::String(template.organization_id.clone()),
        ),
        (
            "credential_template_id".to_owned(),
            template
                .credential_template_id
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        ),
        (
            "approval_policy_set_id".to_owned(),
            template
                .approval_policy_set_id
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        ),
        (
            "status".to_owned(),
            Value::String(template.status.as_str().to_owned()),
        ),
    ])
}

fn approval_template_json(template: &ApplicationTemplateRecord) -> Map<String, Value> {
    template_policy_json(template)
}

fn approval_binding_json(binding: &Map<String, Value>) -> Map<String, Value> {
    project(
        binding,
        &[
            "id",
            "organization_id",
            "platform_id",
            "application_template_id",
            "credential_template_id",
            "approval_policy_set_id",
            "auto_approve_on_evidence",
            "evidence_requirements",
            "feature_flags",
            "enabled",
            "config_version",
            "validated_config_version",
            "readiness_checks",
            "readiness_validated_at",
            "credential_template_snapshot",
            "activated_at",
            "archived_at",
        ],
    )
}

fn project(source: &Map<String, Value>, fields: &[&str]) -> Map<String, Value> {
    Map::from_iter(fields.iter().filter_map(|field| {
        source
            .get(*field)
            .cloned()
            .map(|value| ((*field).to_owned(), value))
    }))
}

fn python_falsy(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => true,
        Value::Number(value) => value.as_f64() == Some(0.0),
        Value::String(value) => value.is_empty(),
        Value::Array(value) => value.is_empty(),
        Value::Object(value) => value.is_empty(),
        Value::Bool(true) => false,
    }
}

fn value_text(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        value => value.to_string(),
    }
}

pub(crate) fn canvas_scope_matches(expected: Option<&Value>, actual: &Map<String, Value>) -> bool {
    let expected = match expected {
        None | Some(Value::Null) => return true,
        Some(Value::Object(expected)) => expected,
        Some(_) => return false,
    };
    expected.iter().all(|(key, expected)| {
        if matches!(expected, Value::Null) || expected.as_str() == Some("") {
            return true;
        }
        if matches!(
            expected,
            Value::Bool(_) | Value::Array(_) | Value::Object(_)
        ) {
            return false;
        }
        let aliases: &[&str] = match key.as_str() {
            "canvas_account_id" | "account_id" => &["canvas_account_id", "account_id"],
            "course_id" | "canvas_course_id" | "canvas_context_id" | "context_id" => &[
                "course_id",
                "canvas_course_id",
                "canvas_context_id",
                "context_id",
            ],
            "assignment_id" | "canvas_assignment_id" => {
                &["assignment_id", "canvas_assignment_id", "resource_link_id"]
            }
            "module_id" | "canvas_module_id" => &["module_id", "canvas_module_id"],
            "quiz_id" | "canvas_quiz_id" => &["quiz_id", "canvas_quiz_id"],
            "user_id" | "canvas_user_id" => &["user_id", "canvas_user_id"],
            "subject_id" => &["subject_id", "lti_subject"],
            "enrollment_id" | "canvas_enrollment_id" => &["enrollment_id", "canvas_enrollment_id"],
            _ => &[key.as_str()],
        };
        aliases
            .iter()
            .find_map(|alias| actual.get(*alias))
            .is_some_and(|value| value_text(value) == value_text(expected))
    })
}
