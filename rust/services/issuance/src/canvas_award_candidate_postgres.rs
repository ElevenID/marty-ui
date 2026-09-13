use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use sqlx::{postgres::PgRow, PgPool, Postgres, Row, Transaction};
use tracing::error;

use crate::{
    canvas_award_candidate::{
        CanvasAwardCandidate, CanvasAwardCandidateMaterializationPlan, CanvasCandidateObservation,
        CanvasLinkedIdentity,
    },
    canvas_award_candidate_service::{
        CanvasAwardCandidateRepository, CanvasAwardCandidateRepositoryError,
        CanvasAwardCandidateSnapshot,
    },
    canvas_issuance_guard::{evaluate_canvas_evidence_policy, validated_requirements},
    canvas_lti_bootstrap::CanvasLtiBootstrapApplication,
    canvas_lti_experience::{
        lti_subject, signed_canvas_identifier, CanvasLtiExperienceSessionContext,
    },
};

pub(crate) const LOAD_BINDING: &str = "SELECT jsonb_build_object(
        'id', id, 'organization_id', organization_id, 'platform_id', platform_id,
        'application_template_id', application_template_id,
        'credential_template_id', credential_template_id,
        'approval_policy_set_id', approval_policy_set_id,
        'auto_approve_on_evidence', auto_approve_on_evidence,
        'evidence_requirements', evidence_requirements,
        'feature_flags', feature_flags, 'enabled', enabled,
        'config_version', config_version,
        'validated_config_version', validated_config_version,
        'readiness_checks', readiness_checks,
        'readiness_validated_at', readiness_validated_at,
        'credential_template_snapshot', credential_template_snapshot,
        'activated_at', activated_at, 'archived_at', archived_at
    ) FROM issuance_service.canvas_program_bindings
    WHERE id = $1 AND organization_id = $2 AND platform_id = $3";

pub(crate) const LOAD_PLATFORM_DEPLOYMENT: &str = "SELECT lti_deployment_id
    FROM issuance_service.canvas_platforms
    WHERE id = $1 AND organization_id = $2";

pub(crate) const LOAD_APPLICATION_TEMPLATE: &str = "SELECT jsonb_build_object(
        'id', id, 'organization_id', organization_id,
        'credential_template_id', credential_template_id,
        'approval_policy_set_id', approval_policy_set_id, 'status', status
    ) FROM issuance_service.application_templates
    WHERE id = $1 AND organization_id = $2";

const LIST_CANDIDATES: &str = "SELECT id, organization_id, platform_id, binding_id,
        learner_identity_id, canvas_user_id, lti_subject, state, observed_at
    FROM issuance_service.canvas_award_candidates
    WHERE organization_id = $1 AND binding_id = $2
    ORDER BY updated_at DESC LIMIT 500";

const LOAD_IDENTITY_BY_SUBJECT: &str = "SELECT id, lti_subject, canvas_user_id, status
    FROM issuance_service.canvas_learner_identities
    WHERE organization_id = $1 AND platform_id = $2 AND deployment_id = $3
      AND lti_subject = $4";

const LOAD_IDENTITY_BY_CANVAS_USER: &str = "SELECT id, lti_subject, canvas_user_id, status
    FROM issuance_service.canvas_learner_identities
    WHERE organization_id = $1 AND platform_id = $2 AND deployment_id = $3
      AND canvas_user_id = $4";

const LIST_CURRENT_OBSERVATIONS: &str = "SELECT id, requirement_id, assertion,
        verification, payload_hash, observed_at
    FROM issuance_service.canvas_candidate_observations
    WHERE organization_id = $1 AND candidate_id = $2 AND is_current = true
    ORDER BY requirement_id";

pub(crate) const LOCK_APPLICATION: &str = "SELECT jsonb_build_object(
        'id', id, 'organization_id', organization_id,
        'application_template_id', application_template_id,
        'integration_context', integration_context, 'status', status,
        'issuance_transaction_id', issuance_transaction_id,
        'credential_id', credential_id
    ) FROM issuance_service.applications
    WHERE id = $1 AND organization_id = $2 FOR UPDATE";

const LIST_CURRENT_FACTS: &str = "SELECT jsonb_build_object(
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
    JOIN issuance_service.evidence_facts AS fact
      ON fact.organization_id = head.organization_id
     AND fact.application_id = head.application_id
     AND fact.logical_key = head.logical_key
     AND fact.id = head.fact_id
    WHERE head.organization_id = $1 AND head.application_id = $2
    ORDER BY fact.observed_at, fact.created_at, fact.id";

const LOAD_CURRENT_FACT: &str = "SELECT id, payload_hash, effective_at, observed_at, created_at
    FROM issuance_service.evidence_facts AS fact
    JOIN issuance_service.evidence_fact_heads AS head ON head.fact_id = fact.id
    WHERE head.organization_id = $1 AND head.application_id = $2 AND head.logical_key = $3
    FOR UPDATE OF head";

type FactOrder = (DateTime<Utc>, DateTime<Utc>, DateTime<Utc>, String);

#[derive(Clone, Debug)]
pub struct PostgresCanvasAwardCandidateRepository {
    pool: PgPool,
}

impl PostgresCanvasAwardCandidateRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CanvasAwardCandidateRepository for PostgresCanvasAwardCandidateRepository {
    async fn load_snapshot(
        &self,
        context: &CanvasLtiExperienceSessionContext,
        application: &CanvasLtiBootstrapApplication,
    ) -> Result<Option<CanvasAwardCandidateSnapshot>, CanvasAwardCandidateRepositoryError> {
        let Some(binding_id) = context.canvas_program_binding_id.as_deref() else {
            return Ok(None);
        };
        let binding = sqlx::query_scalar::<_, Value>(LOAD_BINDING)
            .bind(binding_id)
            .bind(&application.organization_id)
            .bind(&context.canvas_platform_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?;
        let Some(binding) = binding.and_then(|value| value.as_object().cloned()) else {
            return Ok(None);
        };
        let deployment = sqlx::query_scalar::<_, Option<String>>(LOAD_PLATFORM_DEPLOYMENT)
            .bind(&context.canvas_platform_id)
            .bind(&application.organization_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .flatten();
        let verified_deployment = text(context.verified_launch.get("deployment_id"));
        let deployment_id = (!verified_deployment.is_empty())
            .then_some(verified_deployment)
            .or(deployment)
            .unwrap_or_default();
        let template = sqlx::query_scalar::<_, Value>(LOAD_APPLICATION_TEMPLATE)
            .bind(&application.application_template_id)
            .bind(&application.organization_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?;
        let Some(application_template) = template.and_then(|value| value.as_object().cloned())
        else {
            return Ok(None);
        };
        let candidates = sqlx::query(LIST_CANDIDATES)
            .bind(&application.organization_id)
            .bind(binding_id)
            .fetch_all(&self.pool)
            .await
            .map_err(repository_error)?
            .into_iter()
            .map(candidate_row)
            .collect::<Result<Vec<_>, _>>()?;
        let subject = lti_subject(&context.verified_launch);
        let canvas_user_id = signed_canvas_identifier(&context.verified_launch, "canvas_user_id");
        let identity_by_subject = if let Some(subject) = subject.as_deref() {
            load_identity(
                &self.pool,
                LOAD_IDENTITY_BY_SUBJECT,
                &application.organization_id,
                &context.canvas_platform_id,
                &deployment_id,
                subject,
            )
            .await?
        } else {
            None
        };
        let identity_by_canvas_user = if let Some(canvas_user_id) = canvas_user_id.as_deref() {
            load_identity(
                &self.pool,
                LOAD_IDENTITY_BY_CANVAS_USER,
                &application.organization_id,
                &context.canvas_platform_id,
                &deployment_id,
                canvas_user_id,
            )
            .await?
        } else {
            None
        };
        Ok(Some(CanvasAwardCandidateSnapshot {
            binding,
            application_template,
            candidates,
            identity_by_subject,
            identity_by_canvas_user,
        }))
    }

    async fn current_observations(
        &self,
        organization_id: &str,
        candidate_id: &str,
    ) -> Result<Vec<CanvasCandidateObservation>, CanvasAwardCandidateRepositoryError> {
        sqlx::query(LIST_CURRENT_OBSERVATIONS)
            .bind(organization_id)
            .bind(candidate_id)
            .fetch_all(&self.pool)
            .await
            .map_err(repository_error)?
            .into_iter()
            .map(observation_row)
            .collect()
    }

    async fn record_fact_and_evaluate_policy(
        &self,
        application: &CanvasLtiBootstrapApplication,
        binding: &Map<String, Value>,
        application_template: &Map<String, Value>,
        fact: &Value,
    ) -> Result<bool, CanvasAwardCandidateRepositoryError> {
        record_fact_and_policy(
            &self.pool,
            application,
            binding,
            application_template,
            fact,
            None,
        )
        .await
    }

    async fn link_candidate(
        &self,
        application: &CanvasLtiBootstrapApplication,
        plan: &CanvasAwardCandidateMaterializationPlan,
    ) -> Result<(), CanvasAwardCandidateRepositoryError> {
        let mut database = self.pool.begin().await.map_err(repository_error)?;
        let candidate = sqlx::query(
            "UPDATE issuance_service.canvas_award_candidates
             SET application_id = $3, lti_subject = $4, canvas_user_id = $5,
                 learner_identity_id = $6, updated_at = clock_timestamp()
             WHERE id = $1 AND organization_id = $2
               AND state IN ('pending_claim', 'eligible')",
        )
        .bind(&plan.candidate_id)
        .bind(&application.organization_id)
        .bind(&application.id)
        .bind(&plan.lti_subject)
        .bind(&plan.canvas_user_id)
        .bind(&plan.learner_identity_id)
        .execute(&mut *database)
        .await
        .map_err(repository_error)?;
        if candidate.rows_affected() != 1 {
            return Err(CanvasAwardCandidateRepositoryError::Unavailable);
        }
        let application_update = sqlx::query(
            "UPDATE issuance_service.applications
             SET integration_context = jsonb_set(
                    COALESCE(to_jsonb(integration_context), '{}'::jsonb), '{canvas}',
                    COALESCE(to_jsonb(integration_context)->'canvas', '{}'::jsonb) || $3::jsonb,
                    true
                 ),
                 updated_at = clock_timestamp()
             WHERE id = $1 AND organization_id = $2",
        )
        .bind(&application.id)
        .bind(&application.organization_id)
        .bind(Value::Object(plan.application_canvas_patch.clone()))
        .execute(&mut *database)
        .await
        .map_err(repository_error)?;
        if application_update.rows_affected() != 1 {
            return Err(CanvasAwardCandidateRepositoryError::Unavailable);
        }
        database.commit().await.map_err(repository_error)
    }
}

pub(crate) async fn record_fact_and_policy(
    pool: &PgPool,
    application: &CanvasLtiBootstrapApplication,
    binding: &Map<String, Value>,
    application_template: &Map<String, Value>,
    fact: &Value,
    sync_fence: Option<&CanvasSyncCommitFence>,
) -> Result<bool, CanvasAwardCandidateRepositoryError> {
    let fact = fact
        .as_object()
        .ok_or(CanvasAwardCandidateRepositoryError::Unavailable)?;
    if text(fact.get("organization_id")) != application.organization_id
        || text(fact.get("application_id")) != application.id
        || !text(
            fact.get("verification")
                .and_then(|value| value.get("status")),
        )
        .eq_ignore_ascii_case("VERIFIED")
        || text(fact.get("requirement_id")).is_empty()
    {
        return Err(CanvasAwardCandidateRepositoryError::Unavailable);
    }
    let requirements = validated_requirements(binding)
        .map_err(|_| CanvasAwardCandidateRepositoryError::Unavailable)?;
    let mut database = pool.begin().await.map_err(repository_error)?;
    if let Some(fence) = sync_fence {
        validate_sync_commit_fence(&mut database, application, fence).await?;
    }
    let decision = record_fact_and_policy_in_transaction(
        &mut database,
        application,
        binding,
        application_template,
        fact,
        &requirements,
        true,
        None,
    )
    .await?
    .ok_or(CanvasAwardCandidateRepositoryError::Unavailable)?;
    if let Some(fence) = sync_fence {
        if !fence
            .lease
            .lock_current(
                &mut database,
                &application.organization_id,
                &fence.target_id,
            )
            .await
            .map_err(repository_error)?
        {
            database.rollback().await.map_err(repository_error)?;
            return Err(CanvasAwardCandidateRepositoryError::Unavailable);
        }
    }
    database.commit().await.map_err(repository_error)?;
    Ok(decision.get("allowed").and_then(Value::as_bool) == Some(true))
}

pub(crate) struct CanvasSyncCommitFence {
    pub lease: crate::canvas_sync_lease::CanvasSyncLease,
    pub target_id: String,
    pub target_config_version: i32,
    pub platform_id: String,
    pub platform_config_version: i32,
    pub binding_id: String,
    pub application_status: String,
    pub application_integration_context: Value,
    pub template_id: String,
    pub template_status: String,
    pub template_policy_set_id: Option<String>,
}

async fn validate_sync_commit_fence(
    database: &mut Transaction<'_, Postgres>,
    application: &CanvasLtiBootstrapApplication,
    fence: &CanvasSyncCommitFence,
) -> Result<(), CanvasAwardCandidateRepositoryError> {
    if !fence
        .lease
        .lock_current(database, &application.organization_id, &fence.target_id)
        .await
        .map_err(repository_error)?
    {
        return Err(CanvasAwardCandidateRepositoryError::Unavailable);
    }
    let current: Option<i32> = sqlx::query_scalar(
        "SELECT 1
         FROM issuance_service.canvas_evidence_sync_targets t
         JOIN issuance_service.canvas_platforms p
           ON p.id = t.platform_id AND p.organization_id = t.organization_id
         JOIN issuance_service.canvas_program_bindings b
           ON b.id = t.binding_id AND b.platform_id = p.id
          AND b.organization_id = t.organization_id
         JOIN issuance_service.applications a
           ON a.id = $7 AND a.organization_id = t.organization_id
         JOIN issuance_service.application_templates at
           ON at.id = a.application_template_id AND at.organization_id = a.organization_id
         WHERE t.id = $1 AND t.organization_id = $2 AND t.config_version = $3
           AND t.enabled = true AND p.id = $4 AND p.config_version = $5
           AND p.enabled = true AND p.archived_at IS NULL
           AND b.id = $6 AND b.config_version = $3
           AND b.enabled = true AND b.archived_at IS NULL
           AND a.application_template_id = $8 AND a.status = $9
           AND a.integration_context::jsonb = $10::jsonb
           AND at.id = $8 AND at.status = $11
           AND at.approval_policy_set_id IS NOT DISTINCT FROM $12
         FOR SHARE OF t, p, b, a, at",
    )
    .bind(&fence.target_id)
    .bind(&application.organization_id)
    .bind(fence.target_config_version)
    .bind(&fence.platform_id)
    .bind(fence.platform_config_version)
    .bind(&fence.binding_id)
    .bind(&application.id)
    .bind(&fence.template_id)
    .bind(&fence.application_status)
    .bind(&fence.application_integration_context)
    .bind(&fence.template_status)
    .bind(&fence.template_policy_set_id)
    .fetch_optional(&mut **database)
    .await
    .map_err(repository_error)?;
    if current.is_none() {
        return Err(CanvasAwardCandidateRepositoryError::Unavailable);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn record_fact_and_policy_in_transaction(
    database: &mut Transaction<'_, Postgres>,
    application: &CanvasLtiBootstrapApplication,
    binding: &Map<String, Value>,
    application_template: &Map<String, Value>,
    fact: &Map<String, Value>,
    requirements: &[Value],
    evaluate_policy: bool,
    fact_event_metadata: Option<Value>,
) -> Result<Option<Value>, CanvasAwardCandidateRepositoryError> {
    if text(fact.get("organization_id")) != application.organization_id
        || text(fact.get("application_id")) != application.id
        || !text(
            fact.get("verification")
                .and_then(|value| value.get("status")),
        )
        .eq_ignore_ascii_case("VERIFIED")
        || text(fact.get("logical_key")).is_empty()
    {
        return Err(CanvasAwardCandidateRepositoryError::Unavailable);
    }
    let locked_application = sqlx::query_scalar::<_, Value>(LOCK_APPLICATION)
        .bind(&application.id)
        .bind(&application.organization_id)
        .fetch_optional(&mut **database)
        .await
        .map_err(repository_error)?
        .and_then(|value| value.as_object().cloned())
        .ok_or(CanvasAwardCandidateRepositoryError::Unavailable)?;
    let previous_facts = current_facts(database, application).await?;
    let policy_set = if evaluate_policy {
        load_policy_set(
            database,
            &application.organization_id,
            binding,
            application_template,
        )
        .await?
    } else {
        None
    };
    let previous_decision = evaluate_policy
        .then(|| {
            evaluate_canvas_evidence_policy(
                &locked_application,
                Some(application_template),
                Some(binding),
                requirements,
                &previous_facts,
                policy_set.as_ref(),
            )
            .map_err(|_| CanvasAwardCandidateRepositoryError::Unavailable)
        })
        .transpose()?;
    let logical_key = text(fact.get("logical_key"));
    let current = sqlx::query(LOAD_CURRENT_FACT)
        .bind(&application.organization_id)
        .bind(&application.id)
        .bind(&logical_key)
        .fetch_optional(&mut **database)
        .await
        .map_err(repository_error)?;
    let payload_hash = text(fact.get("payload_hash"));
    let duplicate = current.as_ref().is_some_and(|row| {
        row.try_get::<String, _>("payload_hash").ok().as_deref() == Some(&payload_hash)
    });
    let mut inserted = false;
    let mut changed = false;
    if !duplicate {
        let incoming_order = fact_order(fact)?;
        let current_order = current.as_ref().map(row_fact_order).transpose()?;
        changed = current_order.is_none_or(|order| incoming_order > order);
        let superseded = changed
            .then(|| {
                current
                    .as_ref()
                    .and_then(|row| row.try_get::<String, _>("id").ok())
            })
            .flatten();
        let result = sqlx::query(
            "INSERT INTO issuance_service.evidence_facts (
                id, organization_id, application_id, subject_id, provider, fact_type,
                scope, assertion, verification, source, requirement_id, logical_key,
                source_revision, payload_hash, observed_at, effective_at,
                superseded_fact_id, created_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                       $13, $14, $15, $16, $17, $18)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(text(fact.get("id")))
        .bind(&application.organization_id)
        .bind(&application.id)
        .bind(text(fact.get("subject_id")))
        .bind(text(fact.get("provider")))
        .bind(text(fact.get("fact_type")))
        .bind(value(fact, "scope"))
        .bind(value(fact, "assertion"))
        .bind(value(fact, "verification"))
        .bind(value(fact, "source"))
        .bind(optional_text(fact.get("requirement_id")))
        .bind(&logical_key)
        .bind(text(fact.get("source_revision")))
        .bind(&payload_hash)
        .bind(timestamp(fact, "observed_at")?)
        .bind(timestamp(fact, "effective_at")?)
        .bind(superseded)
        .bind(timestamp(fact, "created_at")?)
        .execute(&mut **database)
        .await
        .map_err(repository_error)?;
        inserted = result.rows_affected() == 1;
        if !inserted {
            // Match the compatibility repository: a repeated fact identifier
            // is an idempotent no-op and can never advance a head.
            changed = false;
        } else if changed {
            sqlx::query(
                "INSERT INTO issuance_service.evidence_fact_heads (
                    organization_id, application_id, logical_key, fact_id, updated_at
                 ) VALUES ($1, $2, $3, $4, clock_timestamp())
                 ON CONFLICT (application_id, logical_key) DO UPDATE SET
                    organization_id = EXCLUDED.organization_id,
                    fact_id = EXCLUDED.fact_id,
                    updated_at = clock_timestamp()",
            )
            .bind(&application.organization_id)
            .bind(&application.id)
            .bind(&logical_key)
            .bind(text(fact.get("id")))
            .execute(&mut **database)
            .await
            .map_err(repository_error)?;
        }
    }
    let current_facts = current_facts(database, application).await?;
    let current_decision = evaluate_policy
        .then(|| {
            evaluate_canvas_evidence_policy(
                &locked_application,
                Some(application_template),
                Some(binding),
                requirements,
                &current_facts,
                policy_set.as_ref(),
            )
            .map_err(|_| CanvasAwardCandidateRepositoryError::Unavailable)
        })
        .transpose()?;
    if inserted {
        insert_event(
            database,
            &application.id,
            "evidence_fact_created",
            fact_event_metadata.unwrap_or_else(|| {
                json!({
                    "organization_id": application.organization_id,
                    "provider": text(fact.get("provider")),
                    "requirement_id": text(fact.get("requirement_id")),
                    "fact_id": text(fact.get("id")),
                    "source_revision": text(fact.get("source_revision")),
                })
            }),
        )
        .await?;
    }
    if let (Some(previous_decision), Some(current_decision)) =
        (previous_decision.as_ref(), current_decision.as_ref())
    {
        apply_review_transition(
            database,
            application,
            binding,
            fact,
            changed,
            previous_decision,
            current_decision,
            &locked_application,
        )
        .await?;
    }
    Ok(current_decision)
}

#[allow(clippy::too_many_arguments)]
async fn apply_review_transition(
    database: &mut Transaction<'_, Postgres>,
    application: &CanvasLtiBootstrapApplication,
    binding: &Map<String, Value>,
    fact: &Map<String, Value>,
    changed: bool,
    previous_decision: &Value,
    current_decision: &Value,
    locked_application: &Map<String, Value>,
) -> Result<(), CanvasAwardCandidateRepositoryError> {
    let review = sqlx::query(
        "SELECT id, credential_id, resolution_claim_token
         FROM issuance_service.evidence_policy_reviews
         WHERE organization_id = $1 AND application_id = $2 AND status = 'open'
         FOR UPDATE",
    )
    .bind(&application.organization_id)
    .bind(&application.id)
    .fetch_optional(&mut **database)
    .await
    .map_err(repository_error)?;
    let current_allowed = current_decision.get("allowed").and_then(Value::as_bool) == Some(true);
    let previous_allowed = previous_decision.get("allowed").and_then(Value::as_bool) == Some(true);
    let credential_id = text(locked_application.get("credential_id"));
    if let Some(review) = review.as_ref() {
        let review_id: String = review.try_get("id").map_err(repository_error)?;
        let claimed = review
            .try_get::<Option<String>, _>("resolution_claim_token")
            .map_err(repository_error)?
            .is_some();
        if claimed {
            sqlx::query(
                "UPDATE issuance_service.evidence_policy_reviews
                 SET current_decision = $2, resolution_recovery_pending = $3,
                     updated_at = clock_timestamp() WHERE id = $1",
            )
            .bind(review_id)
            .bind(current_decision)
            .bind(current_allowed)
            .execute(&mut **database)
            .await
            .map_err(repository_error)?;
            return Ok(());
        }
    }
    if changed && !credential_id.is_empty() && previous_allowed && !current_allowed {
        if let Some(review) = review {
            let review_id: String = review.try_get("id").map_err(repository_error)?;
            sqlx::query(
                "UPDATE issuance_service.evidence_policy_reviews
                 SET current_decision = $2, triggering_fact_id = $3,
                     resolution_recovery_pending = false, updated_at = clock_timestamp()
                 WHERE id = $1",
            )
            .bind(review_id)
            .bind(current_decision)
            .bind(text(fact.get("id")))
            .execute(&mut **database)
            .await
            .map_err(repository_error)?;
        } else {
            let review_id = uuid::Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO issuance_service.evidence_policy_reviews (
                    id, organization_id, application_id, credential_id, binding_id,
                    status, prior_decision, current_decision, triggering_fact_id,
                    resolution_recovery_pending, created_at, updated_at
                 ) VALUES ($1, $2, $3, $4, $5, 'open', $6, $7, $8, false,
                           clock_timestamp(), clock_timestamp())",
            )
            .bind(&review_id)
            .bind(&application.organization_id)
            .bind(&application.id)
            .bind(&credential_id)
            .bind(optional_text(binding.get("id")))
            .bind(previous_decision)
            .bind(current_decision)
            .bind(text(fact.get("id")))
            .execute(&mut **database)
            .await
            .map_err(repository_error)?;
            insert_event(
                database,
                &application.id,
                "evidence_policy_review_created",
                json!({
                    "review_id": review_id,
                    "credential_id": credential_id,
                    "triggering_fact_id": text(fact.get("id")),
                }),
            )
            .await?;
        }
    } else if changed && !current_allowed {
        if let Some(review) = review.as_ref() {
            let review_id: String = review.try_get("id").map_err(repository_error)?;
            sqlx::query(
                "UPDATE issuance_service.evidence_policy_reviews
                 SET current_decision = $2, triggering_fact_id = $3,
                     resolution_recovery_pending = false, updated_at = clock_timestamp()
                 WHERE id = $1",
            )
            .bind(review_id)
            .bind(current_decision)
            .bind(text(fact.get("id")))
            .execute(&mut **database)
            .await
            .map_err(repository_error)?;
        }
    } else if let Some(review) = review.filter(|_| current_allowed) {
        let review_id: String = review.try_get("id").map_err(repository_error)?;
        let review_credential: String =
            review.try_get("credential_id").map_err(repository_error)?;
        sqlx::query(
            "UPDATE issuance_service.evidence_policy_reviews
             SET status = 'resolved', resolution_action = 'evidence_recovered',
                 resolution_notes = 'Authoritative Canvas evidence recovered before administrator action',
                 resolved_by = 'canvas-evidence-sync', resolved_at = clock_timestamp(),
                 current_decision = $2, resolution_recovery_pending = false,
                 updated_at = clock_timestamp() WHERE id = $1",
        )
        .bind(&review_id)
        .bind(current_decision)
        .execute(&mut **database)
        .await
        .map_err(repository_error)?;
        insert_event(
            database,
            &application.id,
            "evidence_policy_review_resolved",
            json!({
                "review_id": review_id,
                "credential_id": review_credential,
                "resolution_action": "evidence_recovered",
            }),
        )
        .await?;
    }
    Ok(())
}

async fn current_facts(
    database: &mut Transaction<'_, Postgres>,
    application: &CanvasLtiBootstrapApplication,
) -> Result<Vec<Value>, CanvasAwardCandidateRepositoryError> {
    sqlx::query_scalar(LIST_CURRENT_FACTS)
        .bind(&application.organization_id)
        .bind(&application.id)
        .fetch_all(&mut **database)
        .await
        .map_err(repository_error)
}

async fn load_policy_set(
    database: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    binding: &Map<String, Value>,
    application_template: &Map<String, Value>,
) -> Result<Option<Value>, CanvasAwardCandidateRepositoryError> {
    let policy_set_id = optional_text(binding.get("approval_policy_set_id"))
        .or_else(|| optional_text(application_template.get("approval_policy_set_id")));
    let Some(policy_set_id) = policy_set_id else {
        return Ok(None);
    };
    sqlx::query_scalar(
        "SELECT jsonb_build_object(
            'id', id, 'status', status, 'policy_type', policy_type,
            'cedar_policies', cedar_policies
         ) FROM organization_service.policy_sets
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id)
    .bind(policy_set_id)
    .fetch_optional(&mut **database)
    .await
    .map_err(repository_error)
}

pub(crate) async fn insert_event(
    database: &mut Transaction<'_, Postgres>,
    application_id: &str,
    event_type: &str,
    metadata: Value,
) -> Result<(), CanvasAwardCandidateRepositoryError> {
    sqlx::query(
        "INSERT INTO issuance_service.issuance_events (
            id, transaction_id, application_id, event_type, metadata, created_at
         ) VALUES ($1, NULL, $2, $3, $4, clock_timestamp())",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(application_id)
    .bind(event_type)
    .bind(metadata)
    .execute(&mut **database)
    .await
    .map_err(repository_error)?;
    Ok(())
}

async fn load_identity(
    pool: &PgPool,
    query: &'static str,
    organization_id: &str,
    platform_id: &str,
    deployment_id: &str,
    identifier: &str,
) -> Result<Option<CanvasLinkedIdentity>, CanvasAwardCandidateRepositoryError> {
    sqlx::query(query)
        .bind(organization_id)
        .bind(platform_id)
        .bind(deployment_id)
        .bind(identifier)
        .fetch_optional(pool)
        .await
        .map_err(repository_error)?
        .map(identity_row)
        .transpose()
}

fn candidate_row(row: PgRow) -> Result<CanvasAwardCandidate, CanvasAwardCandidateRepositoryError> {
    Ok(CanvasAwardCandidate {
        id: row.try_get("id").map_err(repository_error)?,
        organization_id: row.try_get("organization_id").map_err(repository_error)?,
        platform_id: row.try_get("platform_id").map_err(repository_error)?,
        binding_id: row.try_get("binding_id").map_err(repository_error)?,
        learner_identity_id: row
            .try_get("learner_identity_id")
            .map_err(repository_error)?,
        canvas_user_id: row.try_get("canvas_user_id").map_err(repository_error)?,
        lti_subject: row.try_get("lti_subject").map_err(repository_error)?,
        state: row.try_get("state").map_err(repository_error)?,
        observed_at: row.try_get("observed_at").map_err(repository_error)?,
    })
}

fn observation_row(
    row: PgRow,
) -> Result<CanvasCandidateObservation, CanvasAwardCandidateRepositoryError> {
    Ok(CanvasCandidateObservation {
        id: row.try_get("id").map_err(repository_error)?,
        requirement_id: row.try_get("requirement_id").map_err(repository_error)?,
        assertion: row.try_get("assertion").map_err(repository_error)?,
        verification: row.try_get("verification").map_err(repository_error)?,
        payload_hash: row.try_get("payload_hash").map_err(repository_error)?,
        observed_at: row.try_get("observed_at").map_err(repository_error)?,
    })
}

fn identity_row(row: PgRow) -> Result<CanvasLinkedIdentity, CanvasAwardCandidateRepositoryError> {
    Ok(CanvasLinkedIdentity {
        id: row.try_get("id").map_err(repository_error)?,
        lti_subject: row.try_get("lti_subject").map_err(repository_error)?,
        canvas_user_id: row.try_get("canvas_user_id").map_err(repository_error)?,
        status: row.try_get("status").map_err(repository_error)?,
    })
}

fn fact_order(fact: &Map<String, Value>) -> Result<FactOrder, CanvasAwardCandidateRepositoryError> {
    Ok((
        timestamp(fact, "effective_at")?,
        timestamp(fact, "observed_at")?,
        timestamp(fact, "created_at")?,
        text(fact.get("id")),
    ))
}

fn row_fact_order(row: &PgRow) -> Result<FactOrder, CanvasAwardCandidateRepositoryError> {
    let effective: DateTime<Utc> = row.try_get("effective_at").map_err(repository_error)?;
    let observed: DateTime<Utc> = row.try_get("observed_at").map_err(repository_error)?;
    let created: DateTime<Utc> = row.try_get("created_at").map_err(repository_error)?;
    let id: String = row.try_get("id").map_err(repository_error)?;
    Ok((effective, observed, created, id))
}

fn timestamp(
    value: &Map<String, Value>,
    name: &str,
) -> Result<DateTime<Utc>, CanvasAwardCandidateRepositoryError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
        .ok_or(CanvasAwardCandidateRepositoryError::Unavailable)
}

fn value(value: &Map<String, Value>, name: &str) -> Value {
    value.get(name).cloned().unwrap_or(Value::Null)
}

fn text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.trim().to_owned(),
        Some(Value::Null) | None => String::new(),
        Some(value) => value.to_string().trim_matches('"').trim().to_owned(),
    }
}

fn optional_text(value: Option<&Value>) -> Option<String> {
    let value = text(value);
    (!value.is_empty()).then_some(value)
}

fn repository_error(cause: sqlx::Error) -> CanvasAwardCandidateRepositoryError {
    error!(%cause, "Canvas award candidate repository query failed");
    CanvasAwardCandidateRepositoryError::Unavailable
}
