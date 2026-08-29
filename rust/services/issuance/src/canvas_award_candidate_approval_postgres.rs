use async_trait::async_trait;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use tracing::error;

use crate::{
    canvas_award_candidate::CanvasAwardCandidateMaterializationPlan,
    canvas_award_candidate_approval::{CanvasAwardApprovalRepository, CanvasAwardApprovalSnapshot},
    canvas_award_candidate_postgres::{
        LOAD_APPLICATION_TEMPLATE, LOAD_BINDING, LOAD_PLATFORM_DEPLOYMENT,
    },
    canvas_award_candidate_service::CanvasAwardCandidateApprovalError,
    canvas_lti_bootstrap::CanvasLtiBootstrapApplication,
    canvas_lti_experience::CanvasLtiExperienceSessionContext,
    credential::{CredentialTransaction, CredentialTransactionStatus},
};

const LOAD_APPLICATION: &str = "SELECT jsonb_build_object(
        'id', id, 'organization_id', organization_id,
        'application_template_id', application_template_id,
        'applicant_identifier', applicant_identifier, 'form_data', form_data,
        'integration_context', integration_context, 'status', status,
        'issuance_transaction_id', issuance_transaction_id, 'credential_id', credential_id
    ) FROM issuance_service.applications
    WHERE id = $1 AND organization_id = $2";

#[derive(Clone, Debug)]
pub struct PostgresCanvasAwardApprovalRepository {
    pool: PgPool,
}

impl PostgresCanvasAwardApprovalRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CanvasAwardApprovalRepository for PostgresCanvasAwardApprovalRepository {
    async fn load_approval_snapshot(
        &self,
        context: &CanvasLtiExperienceSessionContext,
        application: &CanvasLtiBootstrapApplication,
        plan: &CanvasAwardCandidateMaterializationPlan,
    ) -> Result<Option<CanvasAwardApprovalSnapshot>, CanvasAwardCandidateApprovalError> {
        let Some(binding_id) = context.canvas_program_binding_id.as_deref() else {
            return Ok(None);
        };
        let (current, binding, template, deployment) = tokio::try_join!(
            sqlx::query_scalar::<_, Value>(LOAD_APPLICATION)
                .bind(&application.id)
                .bind(&application.organization_id)
                .fetch_optional(&self.pool),
            sqlx::query_scalar::<_, Value>(LOAD_BINDING)
                .bind(binding_id)
                .bind(&application.organization_id)
                .bind(&context.canvas_platform_id)
                .fetch_optional(&self.pool),
            sqlx::query_scalar::<_, Value>(LOAD_APPLICATION_TEMPLATE)
                .bind(&application.application_template_id)
                .bind(&application.organization_id)
                .fetch_optional(&self.pool),
            sqlx::query_scalar::<_, Option<String>>(LOAD_PLATFORM_DEPLOYMENT)
                .bind(&context.canvas_platform_id)
                .bind(&application.organization_id)
                .fetch_optional(&self.pool),
        )
        .map_err(approval_repository_error)?;
        let Some((application_value, binding, application_template)) = current
            .zip(binding)
            .zip(template)
            .map(|((application, binding), template)| (application, binding, template))
        else {
            return Ok(None);
        };
        let Some((application_value, binding, application_template)) = application_value
            .as_object()
            .cloned()
            .zip(binding.as_object().cloned())
            .zip(application_template.as_object().cloned())
            .map(|((application, binding), template)| (application, binding, template))
        else {
            return Ok(None);
        };
        if !candidate_link_is_current(&self.pool, context, application, plan).await? {
            return Ok(None);
        }
        let identity_still_linked = if let Some(canvas_user_id) = plan.canvas_user_id.as_deref() {
            let Some(identity_id) = plan.learner_identity_id.as_deref() else {
                return Ok(None);
            };
            let Some(subject) = plan.lti_subject.as_deref() else {
                return Ok(None);
            };
            let launch_deployment = text(context.verified_launch.get("deployment_id"));
            let deployment_id = if launch_deployment.is_empty() {
                deployment.flatten().unwrap_or_default()
            } else {
                launch_deployment
            };
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (
                    SELECT 1 FROM issuance_service.canvas_learner_identities
                    WHERE id = $1 AND organization_id = $2 AND platform_id = $3
                      AND deployment_id = $4 AND lti_subject = $5
                      AND canvas_user_id = $6 AND status = 'linked'
                 )",
            )
            .bind(identity_id)
            .bind(&application.organization_id)
            .bind(&context.canvas_platform_id)
            .bind(deployment_id)
            .bind(subject)
            .bind(canvas_user_id)
            .fetch_one(&self.pool)
            .await
            .map_err(approval_repository_error)?
        } else {
            true
        };
        Ok(Some(CanvasAwardApprovalSnapshot {
            application: application_value,
            application_template,
            binding,
            identity_still_linked,
        }))
    }

    async fn reserve_issuance(
        &self,
        transaction: &CredentialTransaction,
        context: &CanvasLtiExperienceSessionContext,
        plan: &CanvasAwardCandidateMaterializationPlan,
        snapshot: &CanvasAwardApprovalSnapshot,
    ) -> Result<(), CanvasAwardCandidateApprovalError> {
        reserve_canvas_issuance(&self.pool, transaction, context, plan, &snapshot.binding).await
    }
}

async fn candidate_link_is_current(
    pool: &PgPool,
    context: &CanvasLtiExperienceSessionContext,
    application: &CanvasLtiBootstrapApplication,
    plan: &CanvasAwardCandidateMaterializationPlan,
) -> Result<bool, CanvasAwardCandidateApprovalError> {
    sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1 FROM issuance_service.canvas_award_candidates
            WHERE id = $1 AND organization_id = $2 AND platform_id = $3
              AND binding_id = $4 AND application_id = $5
              AND state IN ('pending_claim', 'eligible')
              AND lti_subject IS NOT DISTINCT FROM $6
              AND canvas_user_id IS NOT DISTINCT FROM $7
              AND learner_identity_id IS NOT DISTINCT FROM $8
         )",
    )
    .bind(&plan.candidate_id)
    .bind(&application.organization_id)
    .bind(&context.canvas_platform_id)
    .bind(context.canvas_program_binding_id.as_deref().unwrap_or(""))
    .bind(&application.id)
    .bind(&plan.lti_subject)
    .bind(&plan.canvas_user_id)
    .bind(&plan.learner_identity_id)
    .fetch_one(pool)
    .await
    .map_err(approval_repository_error)
}

async fn reserve_canvas_issuance(
    pool: &PgPool,
    prepared: &CredentialTransaction,
    context: &CanvasLtiExperienceSessionContext,
    plan: &CanvasAwardCandidateMaterializationPlan,
    expected_binding: &serde_json::Map<String, Value>,
) -> Result<(), CanvasAwardCandidateApprovalError> {
    let application_id = prepared
        .application_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or(CanvasAwardCandidateApprovalError::ReadinessDrift)?;
    let mut database = pool.begin().await.map_err(approval_repository_error)?;
    let application = sqlx::query(
        "SELECT status, integration_context, issuance_transaction_id, credential_id
         FROM issuance_service.applications
         WHERE id = $1 AND organization_id = $2 FOR UPDATE",
    )
    .bind(application_id)
    .bind(&prepared.organization_id)
    .fetch_optional(&mut *database)
    .await
    .map_err(approval_repository_error)?
    .ok_or(CanvasAwardCandidateApprovalError::ReadinessDrift)?;
    let status: String = application
        .try_get("status")
        .map_err(approval_repository_error)?;
    let integration: Value = application
        .try_get("integration_context")
        .map_err(approval_repository_error)?;
    let credential_id: Option<String> = application
        .try_get("credential_id")
        .map_err(approval_repository_error)?;
    if !matches!(status.as_str(), "pending" | "approved")
        || !has_canvas_marker(&integration)
        || credential_id.is_some()
    {
        return Err(CanvasAwardCandidateApprovalError::ReadinessDrift);
    }
    lock_current_approval_dependencies(&mut database, prepared, context, plan, expected_binding)
        .await?;
    let current_transaction_id: Option<String> = application
        .try_get("issuance_transaction_id")
        .map_err(approval_repository_error)?;
    let current = if let Some(current_id) = current_transaction_id.as_deref() {
        sqlx::query(
            "SELECT id, status, expires_at FROM issuance_service.issuance_transactions
             WHERE id = $1 AND organization_id = $2 AND application_id = $3",
        )
        .bind(current_id)
        .bind(&prepared.organization_id)
        .bind(application_id)
        .fetch_optional(&mut *database)
        .await
        .map_err(approval_repository_error)?
    } else {
        None
    };
    let reserved_id = if let Some(current) = current {
        let status: String = current
            .try_get("status")
            .map_err(approval_repository_error)?;
        let active: bool = sqlx::query_scalar(
            "SELECT $1 IN ('authorized', 'signing')
                 OR ($1 = 'pending' AND $2::timestamptz > clock_timestamp())",
        )
        .bind(&status)
        .bind(
            current
                .try_get::<chrono::DateTime<chrono::Utc>, _>("expires_at")
                .map_err(approval_repository_error)?,
        )
        .fetch_one(&mut *database)
        .await
        .map_err(approval_repository_error)?;
        if status == "issued" {
            return Err(CanvasAwardCandidateApprovalError::ReadinessDrift);
        }
        if active {
            current.try_get("id").map_err(approval_repository_error)?
        } else {
            insert_transaction(&mut database, prepared).await?;
            prepared.id.clone()
        }
    } else {
        insert_transaction(&mut database, prepared).await?;
        prepared.id.clone()
    };
    let updated = sqlx::query(
        "UPDATE issuance_service.applications
         SET status = 'approved',
             review_notes = 'Learner claimed an eligible Canvas pending award',
             reviewer_id = 'canvas-pending-award-claim',
             reviewed_at = clock_timestamp(), issuance_transaction_id = $3,
             updated_at = clock_timestamp()
         WHERE id = $1 AND organization_id = $2
           AND status IN ('pending', 'approved') AND credential_id IS NULL",
    )
    .bind(application_id)
    .bind(&prepared.organization_id)
    .bind(reserved_id)
    .execute(&mut *database)
    .await
    .map_err(approval_repository_error)?;
    if updated.rows_affected() != 1 {
        return Err(CanvasAwardCandidateApprovalError::ReadinessDrift);
    }
    database.commit().await.map_err(approval_repository_error)
}

async fn lock_current_approval_dependencies(
    database: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    prepared: &CredentialTransaction,
    context: &CanvasLtiExperienceSessionContext,
    plan: &CanvasAwardCandidateMaterializationPlan,
    expected_binding: &serde_json::Map<String, Value>,
) -> Result<(), CanvasAwardCandidateApprovalError> {
    let binding_id = context
        .canvas_program_binding_id
        .as_deref()
        .ok_or(CanvasAwardCandidateApprovalError::ReadinessDrift)?;
    let current_binding = sqlx::query_scalar::<_, Value>(
        "SELECT jsonb_build_object(
            'id', id, 'organization_id', organization_id, 'platform_id', platform_id,
            'application_template_id', application_template_id,
            'credential_template_id', credential_template_id,
            'approval_policy_set_id', approval_policy_set_id,
            'auto_approve_on_evidence', auto_approve_on_evidence,
            'feature_flags', feature_flags, 'enabled', enabled,
            'config_version', config_version,
            'validated_config_version', validated_config_version,
            'readiness_checks', readiness_checks,
            'readiness_validated_at', readiness_validated_at,
            'credential_template_snapshot', credential_template_snapshot,
            'activated_at', activated_at, 'archived_at', archived_at
         ) FROM issuance_service.canvas_program_bindings
         WHERE id = $1 AND organization_id = $2 AND platform_id = $3 FOR SHARE",
    )
    .bind(binding_id)
    .bind(&prepared.organization_id)
    .bind(&context.canvas_platform_id)
    .fetch_optional(&mut **database)
    .await
    .map_err(approval_repository_error)?
    .and_then(|value| value.as_object().cloned())
    .ok_or(CanvasAwardCandidateApprovalError::ReadinessDrift)?;
    let stable_fields = [
        "id",
        "organization_id",
        "platform_id",
        "application_template_id",
        "credential_template_id",
        "approval_policy_set_id",
        "auto_approve_on_evidence",
        "feature_flags",
        "enabled",
        "config_version",
        "validated_config_version",
        "readiness_checks",
        "readiness_validated_at",
        "credential_template_snapshot",
        "activated_at",
        "archived_at",
    ];
    if stable_fields
        .iter()
        .any(|name| current_binding.get(*name) != expected_binding.get(*name))
    {
        return Err(CanvasAwardCandidateApprovalError::ReadinessDrift);
    }
    let candidate = sqlx::query(
        "SELECT application_id, platform_id, binding_id, lti_subject,
                canvas_user_id, learner_identity_id, state
         FROM issuance_service.canvas_award_candidates
         WHERE id = $1 AND organization_id = $2 FOR UPDATE",
    )
    .bind(&plan.candidate_id)
    .bind(&prepared.organization_id)
    .fetch_optional(&mut **database)
    .await
    .map_err(approval_repository_error)?
    .ok_or(CanvasAwardCandidateApprovalError::ReadinessDrift)?;
    let candidate_state: String = candidate
        .try_get("state")
        .map_err(approval_repository_error)?;
    if candidate
        .try_get::<Option<String>, _>("application_id")
        .map_err(approval_repository_error)?
        .as_deref()
        != prepared.application_id.as_deref()
        || candidate
            .try_get::<String, _>("platform_id")
            .map_err(approval_repository_error)?
            != context.canvas_platform_id
        || candidate
            .try_get::<String, _>("binding_id")
            .map_err(approval_repository_error)?
            != binding_id
        || candidate
            .try_get::<Option<String>, _>("lti_subject")
            .map_err(approval_repository_error)?
            != plan.lti_subject
        || candidate
            .try_get::<Option<String>, _>("canvas_user_id")
            .map_err(approval_repository_error)?
            != plan.canvas_user_id
        || candidate
            .try_get::<Option<String>, _>("learner_identity_id")
            .map_err(approval_repository_error)?
            != plan.learner_identity_id
        || !matches!(candidate_state.as_str(), "pending_claim" | "eligible")
    {
        return Err(CanvasAwardCandidateApprovalError::ReadinessDrift);
    }
    if let Some(canvas_user_id) = plan.canvas_user_id.as_deref() {
        let identity_id = plan
            .learner_identity_id
            .as_deref()
            .ok_or(CanvasAwardCandidateApprovalError::ReadinessDrift)?;
        let subject = plan
            .lti_subject
            .as_deref()
            .ok_or(CanvasAwardCandidateApprovalError::ReadinessDrift)?;
        let mut deployment_id = text(context.verified_launch.get("deployment_id"));
        if deployment_id.is_empty() {
            deployment_id = sqlx::query_scalar::<_, Option<String>>(
                "SELECT lti_deployment_id FROM issuance_service.canvas_platforms
                 WHERE id = $1 AND organization_id = $2 FOR SHARE",
            )
            .bind(&context.canvas_platform_id)
            .bind(&prepared.organization_id)
            .fetch_optional(&mut **database)
            .await
            .map_err(approval_repository_error)?
            .flatten()
            .unwrap_or_default();
        }
        let identity = sqlx::query_scalar::<_, String>(
            "SELECT id FROM issuance_service.canvas_learner_identities
             WHERE id = $1 AND organization_id = $2 AND platform_id = $3
               AND deployment_id = $4 AND lti_subject = $5
               AND canvas_user_id = $6 AND status = 'linked'
             FOR SHARE",
        )
        .bind(identity_id)
        .bind(&prepared.organization_id)
        .bind(&context.canvas_platform_id)
        .bind(deployment_id)
        .bind(subject)
        .bind(canvas_user_id)
        .fetch_optional(&mut **database)
        .await
        .map_err(approval_repository_error)?;
        if identity.is_none() {
            return Err(CanvasAwardCandidateApprovalError::ReadinessDrift);
        }
    }
    Ok(())
}

async fn insert_transaction(
    database: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    transaction: &CredentialTransaction,
) -> Result<(), CanvasAwardCandidateApprovalError> {
    if transaction.status != CredentialTransactionStatus::Pending
        || transaction
            .issuer_profile_id
            .as_deref()
            .is_none_or(str::is_empty)
        || transaction
            .signing_service_id
            .as_deref()
            .is_none_or(str::is_empty)
    {
        return Err(CanvasAwardCandidateApprovalError::ReadinessDrift);
    }
    let validity_days = i32::try_from(transaction.validity_days)
        .map_err(|_| CanvasAwardCandidateApprovalError::ReadinessDrift)?;
    let renewal_window_days = i32::try_from(transaction.renewal_window_days)
        .map_err(|_| CanvasAwardCandidateApprovalError::ReadinessDrift)?;
    sqlx::query(
        "INSERT INTO issuance_service.issuance_transactions (
            id, organization_id, credential_template_id, revocation_profile_id,
            renewal_of_credential_id, applicant_id, application_id, subject_did,
            status, pre_auth_code, c_nonce, claims, credential_type,
            selective_disclosure_claims, zk_predicate_claims,
            credential_payload_format, wallet_configs, validity_days, renewable,
            renewal_window_days, delivery_mode, issuer_profile_id, issuer_mode,
            issuer_did_override, issuer_algorithm, signing_service_id,
            created_at, expires_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', $9, $10, $11,
                   $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22,
                   $23, $24, $25, clock_timestamp(),
                   clock_timestamp() + interval '15 minutes')",
    )
    .bind(&transaction.id)
    .bind(&transaction.organization_id)
    .bind(&transaction.credential_template_id)
    .bind(&transaction.revocation_profile_id)
    .bind(&transaction.renewal_of_credential_id)
    .bind(&transaction.applicant_id)
    .bind(&transaction.application_id)
    .bind(&transaction.subject_did)
    .bind(&transaction.pre_authorized_code)
    .bind(&transaction.nonce)
    .bind(Value::Object(transaction.claims.clone()))
    .bind(&transaction.credential_type)
    .bind(json!(transaction.selective_disclosure_claims))
    .bind(json!(transaction.zk_predicate_claims))
    .bind(&transaction.credential_payload_format)
    .bind(json!(transaction.wallet_configs))
    .bind(validity_days)
    .bind(transaction.renewable)
    .bind(renewal_window_days)
    .bind(&transaction.delivery_mode)
    .bind(&transaction.issuer_profile_id)
    .bind(&transaction.issuer_mode)
    .bind(&transaction.issuer_did)
    .bind(&transaction.issuer_algorithm)
    .bind(&transaction.signing_service_id)
    .execute(&mut **database)
    .await
    .map_err(approval_repository_error)?;
    Ok(())
}

fn has_canvas_marker(integration: &Value) -> bool {
    let Some(canvas) = integration.get("canvas").and_then(Value::as_object) else {
        return false;
    };
    [
        "canvas_platform_id",
        "canvas_program_binding_id",
        "canvas_account_id",
    ]
    .iter()
    .any(|name| !text(canvas.get(*name)).is_empty())
        || text(canvas.get("source"))
            .to_ascii_lowercase()
            .starts_with("canvas")
}

fn text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.trim().to_owned(),
        Some(Value::Null) | None => String::new(),
        Some(value) => value.to_string().trim_matches('"').trim().to_owned(),
    }
}

fn approval_repository_error(cause: sqlx::Error) -> CanvasAwardCandidateApprovalError {
    error!(%cause, "Canvas award approval repository query failed");
    CanvasAwardCandidateApprovalError::Unavailable
}
