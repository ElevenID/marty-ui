//! Atomic PostgreSQL adapter for deprecated signed Canvas evidence ingestion.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use sqlx::{postgres::PgRow, PgPool, Postgres, Row, Transaction};
use tracing::error;

use crate::{
    canvas_award_candidate_approval::CanvasApplicationApprovalSnapshot,
    canvas_award_candidate_approval_postgres::reserve_management_canvas_issuance_in_transaction,
    canvas_award_candidate_postgres::record_fact_and_policy_in_transaction,
    canvas_legacy_ingest::{
        CanvasEvidenceEvent, CanvasEvidenceEventResponse, CanvasLegacyApplicationSnapshot,
        CanvasLegacyCommit, CanvasLegacyCommitOutcome, CanvasLegacyIngestError,
        CanvasLegacyIngestRepository, CanvasLegacyIngestSnapshot, CanvasLegacyRepositoryError,
        CanvasLegacyStoredReceipt,
    },
    canvas_lti_bootstrap::CanvasLtiBootstrapApplication,
    credential_postgres::transaction_row,
};

const LOAD_RECEIPT: &str = "SELECT payload_hash, status, issuance_response
    FROM issuance_service.canvas_event_receipts
    WHERE canvas_account_id = $1 AND provider_event_id = $2";

const LOCK_RECEIPT: &str = "SELECT payload_hash, status, issuance_response
    FROM issuance_service.canvas_event_receipts
    WHERE canvas_account_id = $1 AND provider_event_id = $2 FOR UPDATE";

const LOAD_APPLICATION: &str = "SELECT jsonb_build_object(
        'id', id, 'organization_id', organization_id,
        'application_template_id', application_template_id,
        'applicant_identifier', applicant_identifier, 'form_data', form_data,
        'submitted_evidence', submitted_evidence,
        'integration_context', integration_context, 'status', status,
        'issuance_transaction_id', issuance_transaction_id,
        'credential_id', credential_id, 'created_at', created_at,
        'updated_at', updated_at
    ) FROM issuance_service.applications WHERE id = $1";

const LOCK_APPLICATION: &str = "SELECT jsonb_build_object(
        'id', id, 'organization_id', organization_id,
        'application_template_id', application_template_id,
        'applicant_identifier', applicant_identifier, 'form_data', form_data,
        'submitted_evidence', submitted_evidence,
        'integration_context', integration_context, 'status', status,
        'issuance_transaction_id', issuance_transaction_id,
        'credential_id', credential_id, 'created_at', created_at,
        'updated_at', updated_at
    ) FROM issuance_service.applications
    WHERE id = $1 AND organization_id = $2 FOR UPDATE";

const LOAD_PLATFORM: &str = "SELECT jsonb_build_object(
        'id', id, 'organization_id', organization_id,
        'canvas_account_id', canvas_account_id,
        'registration_status', registration_status,
        'enabled', enabled, 'archived_at', archived_at
    ) FROM issuance_service.canvas_platforms
    WHERE organization_id = $1 AND canvas_account_id = $2";

const LOCK_PLATFORM: &str = "SELECT jsonb_build_object(
        'id', id, 'organization_id', organization_id,
        'canvas_account_id', canvas_account_id,
        'registration_status', registration_status,
        'enabled', enabled, 'archived_at', archived_at
    ) FROM issuance_service.canvas_platforms
    WHERE id = $1 AND organization_id = $2 FOR SHARE";

const LIST_BINDINGS: &str = "SELECT jsonb_build_object(
        'id', id, 'organization_id', organization_id, 'platform_id', platform_id,
        'application_template_id', application_template_id,
        'credential_template_id', credential_template_id,
        'approval_policy_set_id', approval_policy_set_id,
        'auto_approve_on_evidence', auto_approve_on_evidence,
        'evidence_requirements', evidence_requirements,
        'canvas_scope', canvas_scope, 'delivery_mode', delivery_mode,
        'deployment_profile_id', deployment_profile_id,
        'feature_flags', feature_flags, 'enabled', enabled,
        'config_version', config_version,
        'validated_config_version', validated_config_version,
        'readiness_checks', readiness_checks,
        'readiness_validated_at', readiness_validated_at,
        'credential_template_snapshot', credential_template_snapshot,
        'activated_at', activated_at, 'archived_at', archived_at
    ) FROM issuance_service.canvas_program_bindings
    WHERE organization_id = $1 AND platform_id = $2
      AND application_template_id = $3
    ORDER BY created_at";

const LOCK_BINDING: &str = "SELECT jsonb_build_object(
        'id', id, 'organization_id', organization_id, 'platform_id', platform_id,
        'application_template_id', application_template_id,
        'credential_template_id', credential_template_id,
        'approval_policy_set_id', approval_policy_set_id,
        'auto_approve_on_evidence', auto_approve_on_evidence,
        'evidence_requirements', evidence_requirements,
        'canvas_scope', canvas_scope, 'delivery_mode', delivery_mode,
        'deployment_profile_id', deployment_profile_id,
        'feature_flags', feature_flags, 'enabled', enabled,
        'config_version', config_version,
        'validated_config_version', validated_config_version,
        'readiness_checks', readiness_checks,
        'readiness_validated_at', readiness_validated_at,
        'credential_template_snapshot', credential_template_snapshot,
        'activated_at', activated_at, 'archived_at', archived_at
    ) FROM issuance_service.canvas_program_bindings
    WHERE id = $1 AND organization_id = $2 FOR SHARE";

const LOAD_TEMPLATE: &str = "SELECT jsonb_build_object(
        'id', id, 'organization_id', organization_id,
        'credential_template_id', credential_template_id,
        'approval_policy_set_id', approval_policy_set_id,
        'evidence_requirements', evidence_requirements, 'status', status
    ) FROM issuance_service.application_templates
    WHERE id = $1 AND organization_id = $2";

const LOCK_TEMPLATE: &str = "SELECT jsonb_build_object(
        'id', id, 'organization_id', organization_id,
        'credential_template_id', credential_template_id,
        'approval_policy_set_id', approval_policy_set_id,
        'evidence_requirements', evidence_requirements, 'status', status
    ) FROM issuance_service.application_templates
    WHERE id = $1 AND organization_id = $2 FOR SHARE";

const LIST_FACTS: &str = "SELECT jsonb_build_object(
        'id', fact.id, 'organization_id', fact.organization_id,
        'application_id', fact.application_id, 'subject_id', fact.subject_id,
        'provider', fact.provider, 'fact_type', fact.fact_type,
        'scope', fact.scope, 'assertion', fact.assertion,
        'verification', fact.verification, 'source', fact.source,
        'requirement_id', fact.requirement_id, 'logical_key', fact.logical_key,
        'source_revision', fact.source_revision, 'payload_hash', fact.payload_hash,
        'effective_at', fact.effective_at, 'observed_at', fact.observed_at,
        'created_at', fact.created_at
    ) FROM issuance_service.evidence_fact_heads AS head
    JOIN issuance_service.evidence_facts AS fact ON fact.id = head.fact_id
    WHERE head.organization_id = $1 AND head.application_id = $2
    ORDER BY fact.observed_at, fact.created_at, fact.id";

const LOAD_POLICY_SET: &str = "SELECT jsonb_build_object(
        'id', id, 'status', status, 'policy_type', policy_type,
        'cedar_policies', cedar_policies
    ) FROM organization_service.policy_sets
    WHERE organization_id = $1 AND id = $2";

#[derive(Clone, Debug)]
pub struct PostgresCanvasLegacyIngestRepository {
    pool: PgPool,
}

impl PostgresCanvasLegacyIngestRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CanvasLegacyIngestRepository for PostgresCanvasLegacyIngestRepository {
    async fn load(
        &self,
        event: &CanvasEvidenceEvent,
        _payload_hash: &str,
    ) -> Result<Option<CanvasLegacyIngestSnapshot>, CanvasLegacyRepositoryError> {
        if let Some(receipt) = sqlx::query(LOAD_RECEIPT)
            .bind(&event.canvas_account_id)
            .bind(&event.canvas_event_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
        {
            return Ok(Some(CanvasLegacyIngestSnapshot::Replay(stored_receipt(
                &receipt,
            )?)));
        }
        let application = sqlx::query_scalar::<_, Value>(LOAD_APPLICATION)
            .bind(&event.application_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .and_then(|value| value.as_object().cloned());
        let Some(application) = application else {
            return Ok(None);
        };
        let application_org = text(application.get("organization_id"));
        let lookup_org = event
            .organization_id
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or(&application_org);
        let platform = sqlx::query_scalar::<_, Value>(LOAD_PLATFORM)
            .bind(lookup_org)
            .bind(&event.canvas_account_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .and_then(|value| value.as_object().cloned())
            .filter(|platform| platform.get("enabled").and_then(Value::as_bool) == Some(true));
        let Some(platform) = platform else {
            return Ok(Some(empty_runtime_snapshot(application)));
        };
        let bindings = sqlx::query_scalar::<_, Value>(LIST_BINDINGS)
            .bind(lookup_org)
            .bind(text(platform.get("id")))
            .bind(text(application.get("application_template_id")))
            .fetch_all(&self.pool)
            .await
            .map_err(repository_error)?;
        let actual_scope = event_scope(event);
        let binding = bindings.into_iter().find_map(|value| {
            let binding = value.as_object()?.clone();
            (binding.get("enabled").and_then(Value::as_bool) == Some(true)
                && scope_matches(binding.get("canvas_scope"), &actual_scope))
            .then_some(binding)
        });
        let Some(binding) = binding else {
            return Ok(Some(empty_runtime_snapshot(application)));
        };
        let template_id = text(application.get("application_template_id"));
        let template = sqlx::query_scalar::<_, Value>(LOAD_TEMPLATE)
            .bind(&template_id)
            .bind(lookup_org)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .and_then(|value| value.as_object().cloned());
        let facts = sqlx::query_scalar::<_, Value>(LIST_FACTS)
            .bind(lookup_org)
            .bind(&event.application_id)
            .fetch_all(&self.pool)
            .await
            .map_err(repository_error)?;
        let policy_set_id = binding
            .get("approval_policy_set_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .or_else(|| {
                template
                    .as_ref()
                    .and_then(|template| template.get("approval_policy_set_id"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
            });
        let policy_set = if let Some(policy_set_id) = policy_set_id {
            sqlx::query_scalar::<_, Value>(LOAD_POLICY_SET)
                .bind(lookup_org)
                .bind(policy_set_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(repository_error)?
        } else {
            None
        };
        let existing_transaction_id = text(application.get("issuance_transaction_id"));
        let existing_transaction = if !existing_transaction_id.is_empty() {
            sqlx::query(
                "SELECT * FROM issuance_service.issuance_transactions
                 WHERE id = $1 AND organization_id = $2 AND application_id = $3
                   AND status = 'pending' AND expires_at > clock_timestamp()",
            )
            .bind(existing_transaction_id)
            .bind(lookup_org)
            .bind(&event.application_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(transaction_row)
            .transpose()
            .map_err(|_| CanvasLegacyRepositoryError::Unavailable)?
        } else {
            None
        };
        Ok(Some(CanvasLegacyIngestSnapshot::New(Box::new(
            CanvasLegacyApplicationSnapshot {
                application,
                application_template: template,
                platform,
                binding,
                evidence_facts: facts,
                policy_set,
                existing_transaction,
            },
        ))))
    }

    async fn replay(
        &self,
        event: &CanvasEvidenceEvent,
        payload_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<CanvasLegacyStoredReceipt, CanvasLegacyIngestError> {
        let mut database = self.pool.begin().await.map_err(legacy_repository_error)?;
        let row = sqlx::query(LOCK_RECEIPT)
            .bind(&event.canvas_account_id)
            .bind(&event.canvas_event_id)
            .fetch_optional(&mut *database)
            .await
            .map_err(legacy_repository_error)?
            .ok_or(CanvasLegacyIngestError::RepositoryUnavailable)?;
        let receipt = stored_receipt(&row).map_err(map_stored_error)?;
        ensure_replay_matches(&receipt, payload_hash)?;
        sqlx::query(
            "UPDATE issuance_service.canvas_event_receipts SET last_seen_at = $3
             WHERE canvas_account_id = $1 AND provider_event_id = $2",
        )
        .bind(&event.canvas_account_id)
        .bind(&event.canvas_event_id)
        .bind(now)
        .execute(&mut *database)
        .await
        .map_err(legacy_repository_error)?;
        database.commit().await.map_err(legacy_repository_error)?;
        Ok(receipt)
    }

    async fn commit(
        &self,
        snapshot: &CanvasLegacyApplicationSnapshot,
        commit: &CanvasLegacyCommit,
    ) -> Result<CanvasLegacyCommitOutcome, CanvasLegacyIngestError> {
        commit_atomic(&self.pool, snapshot, commit).await
    }
}

async fn commit_atomic(
    pool: &PgPool,
    snapshot: &CanvasLegacyApplicationSnapshot,
    commit: &CanvasLegacyCommit,
) -> Result<CanvasLegacyCommitOutcome, CanvasLegacyIngestError> {
    let mut database = pool.begin().await.map_err(legacy_repository_error)?;
    let claimed = sqlx::query(
        "INSERT INTO issuance_service.canvas_event_receipts (
            id, provider_event_id, organization_id, credential_template_id,
            canvas_account_id, payload_hash, issuance_transaction_id,
            issuance_response, status, error_summary, first_seen_at, last_seen_at
         ) VALUES ($1, $2, $3, $4, $5, $6, NULL, '{}'::json, 'processing',
                   NULL, $7, $7)
         ON CONFLICT (canvas_account_id, provider_event_id) DO NOTHING",
    )
    .bind(&commit.receipt_id)
    .bind(&commit.event.canvas_event_id)
    .bind(commit.event.organization_id.as_deref().unwrap_or(""))
    .bind(commit.event.credential_template_id.as_deref().unwrap_or(""))
    .bind(&commit.event.canvas_account_id)
    .bind(&commit.payload_hash)
    .bind(commit.now)
    .execute(&mut *database)
    .await
    .map_err(legacy_repository_error)?;
    if claimed.rows_affected() == 0 {
        let row = sqlx::query(LOCK_RECEIPT)
            .bind(&commit.event.canvas_account_id)
            .bind(&commit.event.canvas_event_id)
            .fetch_one(&mut *database)
            .await
            .map_err(legacy_repository_error)?;
        let receipt = stored_receipt(&row).map_err(map_stored_error)?;
        if ensure_replay_matches(&receipt, &commit.payload_hash).is_ok() {
            sqlx::query(
                "UPDATE issuance_service.canvas_event_receipts SET last_seen_at = $3
                 WHERE canvas_account_id = $1 AND provider_event_id = $2",
            )
            .bind(&commit.event.canvas_account_id)
            .bind(&commit.event.canvas_event_id)
            .bind(commit.now)
            .execute(&mut *database)
            .await
            .map_err(legacy_repository_error)?;
            database.commit().await.map_err(legacy_repository_error)?;
        }
        return Ok(CanvasLegacyCommitOutcome::Replay(receipt));
    }

    let organization_id = commit.event.organization_id.as_deref().unwrap_or("");
    let current = sqlx::query_scalar::<_, Value>(LOCK_APPLICATION)
        .bind(&commit.event.application_id)
        .bind(organization_id)
        .fetch_optional(&mut *database)
        .await
        .map_err(legacy_repository_error)?
        .and_then(|value| value.as_object().cloned())
        .ok_or(CanvasLegacyIngestError::SnapshotChanged)?;
    if !application_is_current(&current, &snapshot.application)
        || text(current.get("status")) != "pending"
    {
        return Err(CanvasLegacyIngestError::SnapshotChanged);
    }
    lock_dependencies(&mut database, snapshot, organization_id).await?;
    lock_existing_transaction(&mut database, snapshot, organization_id).await?;

    let application = bootstrap_application(&current)?;
    let template = snapshot
        .application_template
        .as_ref()
        .ok_or(CanvasLegacyIngestError::SnapshotChanged)?;
    let fact = commit
        .fact
        .as_object()
        .ok_or(CanvasLegacyIngestError::RepositoryUnavailable)?;
    let decision = record_fact_and_policy_in_transaction(
        &mut database,
        &application,
        &snapshot.binding,
        template,
        fact,
        &commit.requirements,
        commit.evaluate_policy,
        Some(json!({
            "organization_id": organization_id,
            "source": commit.audit_source,
            "evidence_fact_id": text(fact.get("id")),
            "fact_type": text(fact.get("fact_type")),
            "provider": text(fact.get("provider")),
            "verification_method": commit.verification_method,
            "provider_event_id": commit.event.canvas_event_id,
            "canvas_account_id": commit.event.canvas_account_id,
        })),
    )
    .await
    .map_err(|_| CanvasLegacyIngestError::RepositoryUnavailable)?;
    if decision.as_ref() != commit.evaluated_policy_decision.as_ref() {
        return Err(CanvasLegacyIngestError::SnapshotChanged);
    }
    let evidence_fact_ids =
        current_evidence_fact_ids(&mut database, organization_id, &commit.event.application_id)
            .await?;
    if let Some(decision) = commit.evaluated_policy_decision.as_ref() {
        let event_type = if decision.get("allowed").and_then(Value::as_bool) == Some(true) {
            "evidence_policy_permitted"
        } else {
            "evidence_policy_denied"
        };
        insert_legacy_event(
            &mut database,
            &commit.event.application_id,
            None,
            event_type,
            legacy_policy_metadata(commit, organization_id, decision, &evidence_fact_ids, None),
            commit.now,
        )
        .await?;
    }

    let mut submissions = current
        .get("submitted_evidence")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    submissions.push(commit.evidence_submission.clone());
    let mut integration_context = commit
        .application
        .get("integration_context")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if let (Some(integration), Some(policy)) = (
        integration_context.as_object_mut(),
        commit.evaluated_policy_decision.as_ref(),
    ) {
        integration.insert("policy".to_owned(), policy.clone());
    }
    let updated = sqlx::query(
        "UPDATE issuance_service.applications
         SET submitted_evidence = $3, integration_context = $4,
             updated_at = $5
         WHERE id = $1 AND organization_id = $2 AND status IN ('pending', 'approved')",
    )
    .bind(&commit.event.application_id)
    .bind(organization_id)
    .bind(Value::Array(submissions))
    .bind(&integration_context)
    .bind(commit.now)
    .execute(&mut *database)
    .await
    .map_err(legacy_repository_error)?;
    if updated.rows_affected() != 1 {
        return Err(CanvasLegacyIngestError::SnapshotChanged);
    }

    // Python evaluates and persists policy while the application is pending,
    // then performs the reservation lifecycle transition. Preserve that order
    // so status-sensitive policies cannot drift during the same atomic commit.
    let reservation_failure = if commit.transaction.is_some() && commit.approval_failure.is_none() {
        legacy_reservation_value_error(&mut database, &current, organization_id, commit.now).await?
    } else {
        None
    };
    let approval_failure = commit.approval_failure.clone().or(reservation_failure);
    let mut final_policy_decision = commit.policy_decision.clone();
    if let (Some(decision), Some(error)) =
        (final_policy_decision.as_mut(), approval_failure.as_deref())
    {
        deny_policy_decision(decision, error);
    }
    if approval_failure.is_some() {
        let mut failed_context = integration_context;
        if let (Some(integration), Some(policy)) = (
            failed_context.as_object_mut(),
            final_policy_decision.as_ref(),
        ) {
            integration.insert("policy".to_owned(), policy.clone());
        }
        let updated = sqlx::query(
            "UPDATE issuance_service.applications
             SET integration_context = $3, updated_at = $4
             WHERE id = $1 AND organization_id = $2
               AND status IN ('pending', 'approved')",
        )
        .bind(&commit.event.application_id)
        .bind(organization_id)
        .bind(failed_context)
        .bind(commit.now)
        .execute(&mut *database)
        .await
        .map_err(legacy_repository_error)?;
        if updated.rows_affected() != 1 {
            return Err(CanvasLegacyIngestError::SnapshotChanged);
        }
    }

    let transaction_id = if approval_failure.is_none() {
        if let Some(transaction) = commit.transaction.as_ref() {
            let mut approval_application = commit.application.clone();
            approval_application.insert("status".to_owned(), Value::String("pending".to_owned()));
            let approval_snapshot = CanvasApplicationApprovalSnapshot {
                application: approval_application,
                application_template: approval_template(template),
                platform: snapshot.platform.clone(),
                binding: approval_binding(&snapshot.binding),
                existing_transaction: snapshot.existing_transaction.clone(),
            };
            let transaction_id = reserve_management_canvas_issuance_in_transaction(
                &mut database,
                transaction,
                &approval_snapshot,
                "canvas:auto-approval",
                "Auto-approved by MIP policy after verified Canvas evidence satisfied requirements",
                commit.now,
            )
            .await
            .map_err(|_| CanvasLegacyIngestError::SnapshotChanged)?;
            insert_legacy_event(
                &mut database,
                &commit.event.application_id,
                Some(&transaction_id),
                "approval_issuance_succeeded",
                legacy_policy_metadata(
                    commit,
                    organization_id,
                    final_policy_decision
                        .as_ref()
                        .ok_or(CanvasLegacyIngestError::SnapshotChanged)?,
                    &evidence_fact_ids,
                    None,
                ),
                commit.now,
            )
            .await?;
            Some(transaction_id)
        } else {
            None
        }
    } else {
        if let Some(error) = approval_failure.as_deref() {
            insert_legacy_event(
                &mut database,
                &commit.event.application_id,
                None,
                "approval_issuance_failed",
                legacy_policy_metadata(
                    commit,
                    organization_id,
                    final_policy_decision
                        .as_ref()
                        .ok_or(CanvasLegacyIngestError::SnapshotChanged)?,
                    &evidence_fact_ids,
                    Some(error),
                ),
                commit.now,
            )
            .await?;
        }
        None
    };
    let application_status = sqlx::query_scalar::<_, String>(
        "SELECT status FROM issuance_service.applications
         WHERE id = $1 AND organization_id = $2",
    )
    .bind(&commit.event.application_id)
    .bind(organization_id)
    .fetch_one(&mut *database)
    .await
    .map_err(legacy_repository_error)?;
    let response = CanvasEvidenceEventResponse {
        id: commit.event.canvas_event_id.clone(),
        application_id: commit.event.application_id.clone(),
        organization_id: organization_id.to_owned(),
        canvas_account_id: commit.event.canvas_account_id.clone(),
        evidence_type: commit.event.evidence_type.clone(),
        status: "evidence_received".to_owned(),
        application_status: Some(application_status),
        source_event_id: commit.event.canvas_event_id.clone(),
        replayed: false,
        evidence: commit.evidence.clone(),
        mip_primitives: commit.mip_primitives.clone(),
        evidence_facts: vec![commit.safe_fact.clone()],
        policy_decision: final_policy_decision,
    };
    let mut stored_response = serde_json::to_value(&response)
        .map_err(|_| CanvasLegacyIngestError::RepositoryUnavailable)?;
    if let Some(stored) = stored_response.as_object_mut() {
        stored.remove("source_event_id");
        stored.remove("replayed");
    }
    let finalized = sqlx::query(
        "UPDATE issuance_service.canvas_event_receipts
         SET issuance_transaction_id = $3, issuance_response = $4,
             status = 'evidence_received', last_seen_at = $5
         WHERE canvas_account_id = $1 AND provider_event_id = $2
           AND id = $6 AND status = 'processing'",
    )
    .bind(&commit.event.canvas_account_id)
    .bind(&commit.event.canvas_event_id)
    .bind(&transaction_id)
    .bind(stored_response)
    .bind(commit.now)
    .bind(&commit.receipt_id)
    .execute(&mut *database)
    .await
    .map_err(legacy_repository_error)?;
    if finalized.rows_affected() != 1 {
        return Err(CanvasLegacyIngestError::RepositoryUnavailable);
    }
    database.commit().await.map_err(legacy_repository_error)?;
    Ok(CanvasLegacyCommitOutcome::Created(Box::new(response)))
}

async fn current_evidence_fact_ids(
    database: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    application_id: &str,
) -> Result<Vec<String>, CanvasLegacyIngestError> {
    sqlx::query_scalar::<_, String>(
        "SELECT fact.id FROM issuance_service.evidence_fact_heads AS head
         JOIN issuance_service.evidence_facts AS fact ON fact.id = head.fact_id
         WHERE head.organization_id = $1 AND head.application_id = $2
         ORDER BY fact.observed_at, fact.created_at, fact.id",
    )
    .bind(organization_id)
    .bind(application_id)
    .fetch_all(&mut **database)
    .await
    .map_err(legacy_repository_error)
}

async fn legacy_reservation_value_error(
    database: &mut Transaction<'_, Postgres>,
    application: &Map<String, Value>,
    organization_id: &str,
    reviewed_at: DateTime<Utc>,
) -> Result<Option<String>, CanvasLegacyIngestError> {
    let transaction_id = text(application.get("issuance_transaction_id"));
    if transaction_id.is_empty() {
        return Ok((!text(application.get("credential_id")).is_empty())
            .then(|| "Canvas application already has a claimed credential".to_owned()));
    }
    let status = sqlx::query_scalar::<_, String>(
        "SELECT status FROM issuance_service.issuance_transactions
         WHERE id = $1 AND organization_id = $2 AND application_id = $3 FOR UPDATE",
    )
    .bind(&transaction_id)
    .bind(organization_id)
    .bind(text(application.get("id")))
    .fetch_optional(&mut **database)
    .await
    .map_err(legacy_repository_error)?;
    if !text(application.get("credential_id")).is_empty() {
        return Ok(Some(if status.as_deref() == Some("issued") {
            "Canvas application already has an issued credential".to_owned()
        } else {
            "Canvas application already has a claimed credential".to_owned()
        }));
    }
    match status.as_deref() {
        Some("authorized" | "signing") => {
            let updated = sqlx::query(
                "UPDATE issuance_service.applications
                 SET status = 'approved', review_notes = $3, reviewer_id = $4,
                     reviewed_at = $5, updated_at = $5
                 WHERE id = $1 AND organization_id = $2 AND status = 'pending'",
            )
            .bind(text(application.get("id")))
            .bind(organization_id)
            .bind(
                "Auto-approved by MIP policy after verified Canvas evidence satisfied requirements",
            )
            .bind("canvas:auto-approval")
            .bind(reviewed_at)
            .execute(&mut **database)
            .await
            .map_err(legacy_repository_error)?;
            if updated.rows_affected() != 1 {
                return Err(CanvasLegacyIngestError::SnapshotChanged);
            }
            Ok(Some(
                "Canvas credential claim is already in progress".to_owned(),
            ))
        }
        Some("issued") => {
            let credential_id = sqlx::query_scalar::<_, String>(
                "SELECT id FROM issuance_service.issued_credentials
                 WHERE transaction_id = $1 ORDER BY id LIMIT 1 FOR UPDATE",
            )
            .bind(&transaction_id)
            .fetch_optional(&mut **database)
            .await
            .map_err(legacy_repository_error)?;
            let Some(credential_id) = credential_id else {
                return Ok(Some(
                    "Issued Canvas transaction has no credential".to_owned(),
                ));
            };
            let repaired = sqlx::query(
                "UPDATE issuance_service.applications
                 SET credential_id = $3, updated_at = $4
                 WHERE id = $1 AND organization_id = $2
                   AND (credential_id IS NULL OR credential_id = $3)",
            )
            .bind(text(application.get("id")))
            .bind(organization_id)
            .bind(credential_id)
            .bind(reviewed_at)
            .execute(&mut **database)
            .await
            .map_err(legacy_repository_error)?;
            if repaired.rows_affected() != 1 {
                return Ok(Some(
                    "Canvas application already has a different credential".to_owned(),
                ));
            }
            Ok(Some(
                "Canvas application already has an issued credential".to_owned(),
            ))
        }
        _ => Ok(None),
    }
}

async fn lock_existing_transaction(
    database: &mut Transaction<'_, Postgres>,
    snapshot: &CanvasLegacyApplicationSnapshot,
    organization_id: &str,
) -> Result<(), CanvasLegacyIngestError> {
    let Some(expected) = snapshot.existing_transaction.as_ref() else {
        return Ok(());
    };
    let current = sqlx::query(
        "SELECT * FROM issuance_service.issuance_transactions
         WHERE id = $1 AND organization_id = $2 AND application_id = $3 FOR UPDATE",
    )
    .bind(&expected.id)
    .bind(organization_id)
    .bind(text(snapshot.application.get("id")))
    .fetch_optional(&mut **database)
    .await
    .map_err(legacy_repository_error)?
    .map(transaction_row)
    .transpose()
    .map_err(|_| CanvasLegacyIngestError::RepositoryUnavailable)?;
    if current.as_ref() != Some(expected) {
        return Err(CanvasLegacyIngestError::SnapshotChanged);
    }
    Ok(())
}

fn deny_policy_decision(decision: &mut Value, error: &str) {
    let Some(decision) = decision.as_object_mut() else {
        return;
    };
    decision.insert("allowed".to_owned(), Value::Bool(false));
    let errors = decision
        .entry("errors".to_owned())
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Some(errors) = errors.as_array_mut() {
        errors.push(Value::String(error.to_owned()));
    }
}

fn legacy_policy_metadata(
    commit: &CanvasLegacyCommit,
    organization_id: &str,
    policy_decision: &Value,
    evidence_fact_ids: &[String],
    error: Option<&str>,
) -> Value {
    let mut metadata = json!({
        "organization_id": organization_id,
        "source": commit.audit_source,
        "policy_decision": policy_decision,
        "evidence_fact_ids": evidence_fact_ids,
        "provider_event_id": commit.event.canvas_event_id,
        "canvas_account_id": commit.event.canvas_account_id,
        "verification_method": commit.verification_method,
    });
    if let Some(error) = error {
        metadata["errors"] = json!([error]);
    }
    metadata
}

async fn insert_legacy_event(
    database: &mut Transaction<'_, Postgres>,
    application_id: &str,
    transaction_id: Option<&str>,
    event_type: &str,
    metadata: Value,
    created_at: DateTime<Utc>,
) -> Result<(), CanvasLegacyIngestError> {
    sqlx::query(
        "INSERT INTO issuance_service.issuance_events (
            id, transaction_id, application_id, event_type, metadata, created_at
         ) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(transaction_id)
    .bind(application_id)
    .bind(event_type)
    .bind(metadata)
    .bind(created_at)
    .execute(&mut **database)
    .await
    .map_err(legacy_repository_error)?;
    Ok(())
}

async fn lock_dependencies(
    database: &mut Transaction<'_, Postgres>,
    snapshot: &CanvasLegacyApplicationSnapshot,
    organization_id: &str,
) -> Result<(), CanvasLegacyIngestError> {
    let platform = sqlx::query_scalar::<_, Value>(LOCK_PLATFORM)
        .bind(text(snapshot.platform.get("id")))
        .bind(organization_id)
        .fetch_optional(&mut **database)
        .await
        .map_err(legacy_repository_error)?
        .and_then(|value| value.as_object().cloned());
    let binding = sqlx::query_scalar::<_, Value>(LOCK_BINDING)
        .bind(text(snapshot.binding.get("id")))
        .bind(organization_id)
        .fetch_optional(&mut **database)
        .await
        .map_err(legacy_repository_error)?
        .and_then(|value| value.as_object().cloned());
    let template = if let Some(expected) = snapshot.application_template.as_ref() {
        sqlx::query_scalar::<_, Value>(LOCK_TEMPLATE)
            .bind(text(expected.get("id")))
            .bind(organization_id)
            .fetch_optional(&mut **database)
            .await
            .map_err(legacy_repository_error)?
            .and_then(|value| value.as_object().cloned())
    } else {
        None
    };
    if platform.as_ref() != Some(&snapshot.platform)
        || binding.as_ref() != Some(&snapshot.binding)
        || template.as_ref() != snapshot.application_template.as_ref()
    {
        return Err(CanvasLegacyIngestError::SnapshotChanged);
    }
    Ok(())
}

fn approval_binding(binding: &Map<String, Value>) -> Map<String, Value> {
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

fn approval_template(template: &Map<String, Value>) -> Map<String, Value> {
    project(
        template,
        &[
            "id",
            "organization_id",
            "credential_template_id",
            "approval_policy_set_id",
            "status",
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

fn empty_runtime_snapshot(application: Map<String, Value>) -> CanvasLegacyIngestSnapshot {
    CanvasLegacyIngestSnapshot::New(Box::new(CanvasLegacyApplicationSnapshot {
        application,
        application_template: None,
        platform: Map::new(),
        binding: Map::new(),
        evidence_facts: Vec::new(),
        policy_set: None,
        existing_transaction: None,
    }))
}

fn application_is_current(current: &Map<String, Value>, expected: &Map<String, Value>) -> bool {
    [
        "id",
        "organization_id",
        "application_template_id",
        "applicant_identifier",
        "form_data",
        "submitted_evidence",
        "integration_context",
        "status",
        "issuance_transaction_id",
        "credential_id",
    ]
    .iter()
    .all(|field| current.get(*field) == expected.get(*field))
}

fn bootstrap_application(
    application: &Map<String, Value>,
) -> Result<CanvasLtiBootstrapApplication, CanvasLegacyIngestError> {
    Ok(CanvasLtiBootstrapApplication {
        id: text(application.get("id")),
        organization_id: text(application.get("organization_id")),
        application_template_id: text(application.get("application_template_id")),
        applicant_identifier: text(application.get("applicant_identifier")),
        form_data: application
            .get("form_data")
            .cloned()
            .unwrap_or_else(|| json!({})),
        integration_context: application
            .get("integration_context")
            .cloned()
            .unwrap_or_else(|| json!({})),
        status: text(application.get("status")),
        created_at: timestamp(application.get("created_at"))?,
        updated_at: timestamp(application.get("updated_at"))?,
    })
}

fn event_scope(event: &CanvasEvidenceEvent) -> Map<String, Value> {
    let mut scope = Map::from_iter([
        (
            "canvas_account_id".to_owned(),
            Value::String(event.canvas_account_id.clone()),
        ),
        (
            "course_id".to_owned(),
            Value::String(event.canvas_course_id.clone()),
        ),
        (
            "enrollment_id".to_owned(),
            Value::String(event.canvas_enrollment_id.clone()),
        ),
        (
            "user_id".to_owned(),
            Value::String(event.canvas_user_id.clone()),
        ),
    ]);
    for (name, value) in [
        ("assignment_id", event.canvas_assignment_id.as_ref()),
        ("module_id", event.canvas_module_id.as_ref()),
        ("quiz_id", event.canvas_quiz_id.as_ref()),
    ] {
        if let Some(value) = value {
            scope.insert(name.to_owned(), Value::String(value.clone()));
        }
    }
    scope
}

fn scope_matches(expected: Option<&Value>, actual: &Map<String, Value>) -> bool {
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
            "course_id" => &[
                "course_id",
                "canvas_course_id",
                "canvas_context_id",
                "context_id",
            ],
            "canvas_course_id" | "canvas_context_id" | "context_id" => &[
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
            .is_some_and(|value| text(Some(value)) == text(Some(expected)))
    })
}

fn stored_receipt(row: &PgRow) -> Result<CanvasLegacyStoredReceipt, CanvasLegacyRepositoryError> {
    Ok(CanvasLegacyStoredReceipt {
        payload_hash: row.try_get("payload_hash").map_err(repository_error)?,
        status: row.try_get("status").map_err(repository_error)?,
        response: row.try_get("issuance_response").map_err(repository_error)?,
    })
}

fn ensure_replay_matches(
    receipt: &CanvasLegacyStoredReceipt,
    payload_hash: &str,
) -> Result<(), CanvasLegacyIngestError> {
    if receipt.payload_hash != payload_hash {
        return Err(CanvasLegacyIngestError::ReplayPayloadConflict);
    }
    if receipt.status != "evidence_received" {
        return Err(CanvasLegacyIngestError::ReplayFlowConflict);
    }
    Ok(())
}

fn timestamp(value: Option<&Value>) -> Result<DateTime<Utc>, CanvasLegacyIngestError> {
    value
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
        .ok_or(CanvasLegacyIngestError::RepositoryUnavailable)
}

fn text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Null) | None => String::new(),
        Some(value) => value.to_string().trim_matches('"').to_owned(),
    }
}

fn repository_error(error: sqlx::Error) -> CanvasLegacyRepositoryError {
    error!(error = %error, "Canvas legacy ingest repository operation failed");
    CanvasLegacyRepositoryError::Unavailable
}

fn legacy_repository_error(error: sqlx::Error) -> CanvasLegacyIngestError {
    error!(error = %error, "Canvas legacy ingest atomic operation failed");
    CanvasLegacyIngestError::RepositoryUnavailable
}

fn map_stored_error(_error: CanvasLegacyRepositoryError) -> CanvasLegacyIngestError {
    CanvasLegacyIngestError::RepositoryUnavailable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_lookup_and_claim_use_the_exact_composite_key() {
        for query in [LOAD_RECEIPT, LOCK_RECEIPT] {
            assert!(query.contains("canvas_account_id = $1"));
            assert!(query.contains("provider_event_id = $2"));
        }
    }

    #[test]
    fn scope_aliases_preserve_identity_namespaces_and_legacy_keys() {
        let actual = Map::from_iter([
            ("canvas_account_id".to_owned(), json!("account-1")),
            ("course_id".to_owned(), json!("course-1")),
            ("resource_link_id".to_owned(), json!("assignment-1")),
            ("user_id".to_owned(), json!("numeric-user-1")),
            ("enrollment_id".to_owned(), json!("enrollment-1")),
        ]);
        assert!(scope_matches(
            Some(&json!({
                "account_id":"account-1","context_id":"course-1",
                "assignment_id":"assignment-1",
                "canvas_user_id":"numeric-user-1",
                "canvas_enrollment_id":"enrollment-1"
            })),
            &actual
        ));
        assert!(!scope_matches(
            Some(&json!({"lti_subject":"numeric-user-1"})),
            &actual
        ));
        assert!(!scope_matches(
            Some(&json!({"quiz_id":"assignment-1"})),
            &actual
        ));
    }

    #[test]
    fn malformed_falsy_scope_values_fail_closed_except_null_and_empty_string() {
        let actual = Map::from_iter([("course_id".to_owned(), json!("course-1"))]);
        for expected in [json!(false), json!(0), json!([]), json!({})] {
            assert!(!scope_matches(
                Some(&json!({"course_id": expected})),
                &actual
            ));
        }
        assert!(!scope_matches(Some(&json!("course-1")), &actual));
        assert!(scope_matches(Some(&json!({"course_id": null})), &actual));
        assert!(scope_matches(Some(&json!({"course_id": ""})), &actual));
        assert!(!scope_matches(
            Some(&json!({"course_id": true})),
            &Map::from_iter([("course_id".to_owned(), json!("true"))])
        ));
    }
}
