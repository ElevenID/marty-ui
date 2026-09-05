//! Tenant-scoped PostgreSQL adapter for authoritative Canvas reconciliation.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{
    canvas_award_candidate_postgres::{record_fact_and_policy, CanvasSyncCommitFence},
    canvas_lti_bootstrap::CanvasLtiBootstrapApplication,
    canvas_sync_lease::{lease_lost, CanvasSyncLease},
    canvas_sync_processor::{
        CanvasAuthoritativeObservation, CanvasCandidateObservationSnapshot, CanvasFactCommit,
        CanvasLinkedIdentitySnapshot, CanvasRosterCandidate, CanvasSyncApplicationSnapshot,
        CanvasSyncPlatformSnapshot, CanvasSyncProcessorRepository, CanvasSyncResources,
    },
    canvas_sync_worker::{CanvasSyncProcessingError, CanvasSyncTarget},
};

#[derive(Clone, Debug)]
pub struct PostgresCanvasSyncProcessorRepository {
    pool: PgPool,
    lease: Option<CanvasSyncLease>,
}

impl PostgresCanvasSyncProcessorRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool, lease: None }
    }

    async fn begin_write(
        &self,
        target: &CanvasSyncTarget,
    ) -> Result<Transaction<'_, Postgres>, CanvasSyncProcessingError> {
        let lease = self.lease.as_ref().ok_or_else(lease_lost)?;
        let mut transaction = self.pool.begin().await.map_err(repository_error)?;
        if !lease
            .lock_current(&mut transaction, &target.organization_id, &target.id)
            .await
            .map_err(repository_error)?
        {
            transaction.rollback().await.map_err(repository_error)?;
            return Err(lease_lost());
        }
        Ok(transaction)
    }

    async fn commit_write(
        &self,
        mut transaction: Transaction<'_, Postgres>,
        target: &CanvasSyncTarget,
    ) -> Result<(), CanvasSyncProcessingError> {
        let lease = self.lease.as_ref().ok_or_else(lease_lost)?;
        // Resource-lock waits or the effect itself may outlast the lease.
        // Keep the job lock and roll back ALL effects if the final check fails.
        if !lease
            .lock_current(&mut transaction, &target.organization_id, &target.id)
            .await
            .map_err(repository_error)?
        {
            transaction.rollback().await.map_err(repository_error)?;
            return Err(lease_lost());
        }
        transaction.commit().await.map_err(repository_error)
    }
}

#[async_trait]
impl CanvasSyncProcessorRepository for PostgresCanvasSyncProcessorRepository {
    fn for_lease(
        self: Arc<Self>,
        lease: CanvasSyncLease,
    ) -> Arc<dyn CanvasSyncProcessorRepository> {
        Arc::new(Self {
            pool: self.pool.clone(),
            lease: Some(lease),
        })
    }

    async fn resources(
        &self,
        target: &CanvasSyncTarget,
    ) -> Result<Option<CanvasSyncResources>, CanvasSyncProcessingError> {
        // Platform and binding generation are captured by one statement so a
        // reconfiguration cannot yield a mixed resource snapshot.
        let platform = sqlx::query(
            "SELECT p.id, p.organization_id,
                    COALESCE(p.canvas_base_url, '') AS canvas_base_url,
                    COALESCE(p.lti_trust_profile, '') AS lti_trust_profile,
                    COALESCE(p.lti_issuer, '') AS lti_issuer,
                    COALESCE(p.lti_client_id, '') AS lti_client_id,
                    COALESCE(p.lti_deployment_id, '') AS lti_deployment_id,
                    COALESCE(p.lti_openid_configuration->>'token_endpoint', '') AS lti_auth_token_url,
                    p.config_version,
                    jsonb_build_object(
                        'id', b.id, 'organization_id', b.organization_id,
                        'platform_id', b.platform_id,
                        'application_template_id', b.application_template_id,
                        'approval_policy_set_id', b.approval_policy_set_id,
                        'auto_approve_on_evidence', b.auto_approve_on_evidence,
                        'evidence_requirements', b.evidence_requirements,
                        'feature_flags', b.feature_flags, 'enabled', b.enabled,
                        'config_version', b.config_version) AS binding
             FROM issuance_service.canvas_platforms p
             JOIN issuance_service.canvas_program_bindings b
               ON b.organization_id = p.organization_id AND b.platform_id = p.id
             WHERE p.id = $1 AND p.organization_id = $2 AND b.id = $3
               AND p.enabled = true AND p.archived_at IS NULL
               AND b.enabled = true AND b.archived_at IS NULL
               AND b.config_version = $4",
        )
        .bind(&target.platform_id)
        .bind(&target.organization_id)
        .bind(&target.binding_id)
        .bind(target.config_version)
        .fetch_optional(&self.pool)
        .await
        .map_err(repository_error)?;
        let Some(platform) = platform else {
            return Ok(None);
        };
        let binding = platform
            .try_get::<Value, _>("binding")
            .map_err(repository_error)?
            .as_object()
            .cloned()
            .ok_or_else(unavailable)?;
        let application = if let Some(application_id) = target.application_id.as_deref() {
            sqlx::query(
                "SELECT id, organization_id, application_template_id, applicant_identifier,
                        form_data, integration_context, status, credential_id, created_at, updated_at
                 FROM issuance_service.applications
                 WHERE id = $1 AND organization_id = $2",
            )
            .bind(application_id)
            .bind(&target.organization_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(application_snapshot)
            .transpose()?
        } else {
            None
        };
        let application_template_id = application
            .as_ref()
            .map(|value| value.application.application_template_id.as_str())
            .or_else(|| {
                binding
                    .get("application_template_id")
                    .and_then(Value::as_str)
            });
        let application_template = if let Some(template_id) = application_template_id {
            sqlx::query_scalar::<_, Value>(
                "SELECT jsonb_build_object(
                    'id', id, 'organization_id', organization_id,
                    'approval_policy_set_id', approval_policy_set_id, 'status', status)
                 FROM issuance_service.application_templates
                 WHERE id = $1 AND organization_id = $2",
            )
            .bind(template_id)
            .bind(&target.organization_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .and_then(|value| value.as_object().cloned())
        } else {
            None
        };
        Ok(Some(CanvasSyncResources {
            platform: CanvasSyncPlatformSnapshot {
                id: platform.try_get("id").map_err(repository_error)?,
                organization_id: platform
                    .try_get("organization_id")
                    .map_err(repository_error)?,
                canvas_base_url: platform
                    .try_get("canvas_base_url")
                    .map_err(repository_error)?,
                lti_trust_profile: platform
                    .try_get("lti_trust_profile")
                    .map_err(repository_error)?,
                lti_issuer: platform.try_get("lti_issuer").map_err(repository_error)?,
                lti_client_id: platform
                    .try_get("lti_client_id")
                    .map_err(repository_error)?,
                lti_deployment_id: platform
                    .try_get("lti_deployment_id")
                    .map_err(repository_error)?,
                lti_auth_token_url: platform
                    .try_get("lti_auth_token_url")
                    .map_err(repository_error)?,
                config_version: platform
                    .try_get("config_version")
                    .map_err(repository_error)?,
            },
            binding,
            application,
            application_template,
        }))
    }

    async fn linked_identity_by_subject(
        &self,
        organization_id: &str,
        platform_id: &str,
        deployment_id: &str,
        subject: &str,
    ) -> Result<Option<CanvasLinkedIdentitySnapshot>, CanvasSyncProcessingError> {
        self.identity(
            organization_id,
            platform_id,
            deployment_id,
            "lti_subject",
            subject,
        )
        .await
    }

    async fn linked_identity_by_canvas_user(
        &self,
        organization_id: &str,
        platform_id: &str,
        deployment_id: &str,
        canvas_user_id: &str,
    ) -> Result<Option<CanvasLinkedIdentitySnapshot>, CanvasSyncProcessingError> {
        self.identity(
            organization_id,
            platform_id,
            deployment_id,
            "canvas_user_id",
            canvas_user_id,
        )
        .await
    }

    async fn record_fact(
        &self,
        target: &CanvasSyncTarget,
        resources: &CanvasSyncResources,
        fact: &Value,
    ) -> Result<CanvasFactCommit, CanvasSyncProcessingError> {
        let lease = self.lease.clone().ok_or_else(lease_lost)?;
        let application = resources.application.as_ref().ok_or_else(unavailable)?;
        let template = resources
            .application_template
            .as_ref()
            .ok_or_else(unavailable)?;
        let fact_id = fact
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let allowed = record_fact_and_policy(
            &self.pool,
            &application.application,
            &resources.binding,
            template,
            fact,
            Some(&CanvasSyncCommitFence {
                lease,
                target_id: target.id.clone(),
                target_config_version: target.config_version,
                platform_id: resources.platform.id.clone(),
                platform_config_version: resources.platform.config_version,
                binding_id: target.binding_id.clone(),
                application_status: application.application.status.clone(),
                application_integration_context: application
                    .application
                    .integration_context
                    .clone(),
                template_id: required_text(template, "id")?,
                template_status: required_text(template, "status")?,
                template_policy_set_id: template
                    .get("approval_policy_set_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            }),
        )
        .await
        .map_err(|_| unavailable())?;
        // Duplicate payloads deliberately do not insert the newly generated
        // identifier. Checking that identifier after the atomic transaction is
        // race-safe and reports the same created/reused projection as Python.
        let inserted = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM issuance_service.evidence_facts
             WHERE id = $1 AND organization_id = $2 AND application_id = $3)",
        )
        .bind(&fact_id)
        .bind(&application.application.organization_id)
        .bind(&application.application.id)
        .fetch_one(&self.pool)
        .await
        .map_err(repository_error)?;
        Ok(CanvasFactCommit {
            fact_id,
            inserted,
            policy_allowed: allowed,
        })
    }

    async fn patch_application_sync(
        &self,
        target: &CanvasSyncTarget,
        resources: &CanvasSyncResources,
        checked: &[String],
        policy_allowed: bool,
    ) -> Result<bool, CanvasSyncProcessingError> {
        let mut transaction = self.begin_write(target).await?;
        let application = resources.application.as_ref().ok_or_else(stale)?;
        let patch = json!({
            "last_evidence_sync_at": Utc::now(),
            "last_evidence_policy_allowed": policy_allowed,
            "last_evidence_requirements_checked": checked,
        });
        lock_current_scope(&mut transaction, target, resources).await?;
        lock_current_application(&mut transaction, application).await?;
        let result = sqlx::query(
            "UPDATE issuance_service.applications SET integration_context = jsonb_set(
                COALESCE(integration_context::jsonb, '{}'::jsonb), '{canvas}',
                COALESCE(integration_context::jsonb->'canvas', '{}'::jsonb) || $3::jsonb, true),
                updated_at = clock_timestamp()
             WHERE id = $1 AND organization_id = $2 AND status = $4
               AND integration_context::jsonb IS NOT DISTINCT FROM $5::jsonb",
        )
        .bind(&application.application.id)
        .bind(&application.application.organization_id)
        .bind(patch)
        .bind(&application.application.status)
        .bind(&application.application.integration_context)
        .execute(&mut *transaction)
        .await
        .map_err(repository_error)?;
        if result.rows_affected() != 1 {
            transaction.rollback().await.map_err(repository_error)?;
            return Err(stale());
        }
        self.commit_write(transaction, target).await?;
        Ok(true)
    }

    async fn patch_platform_validation(
        &self,
        target: &CanvasSyncTarget,
        resources: &CanvasSyncResources,
        error_code: Option<&str>,
    ) -> Result<bool, CanvasSyncProcessingError> {
        let platform = &resources.platform;
        let mut transaction = self.begin_write(target).await?;
        lock_current_scope(&mut transaction, target, resources).await?;
        let result = sqlx::query(
            "UPDATE issuance_service.canvas_platforms
             SET last_validated_at = clock_timestamp(), last_connection_error = $4,
                 updated_at = clock_timestamp()
             WHERE id = $1 AND organization_id = $2 AND config_version = $3",
        )
        .bind(&platform.id)
        .bind(&platform.organization_id)
        .bind(platform.config_version)
        .bind(error_code)
        .execute(&mut *transaction)
        .await
        .map_err(repository_error)?;
        if result.rows_affected() != 1 {
            transaction.rollback().await.map_err(repository_error)?;
            return Err(stale());
        }
        self.commit_write(transaction, target).await?;
        Ok(true)
    }

    async fn disable_target(
        &self,
        target: &CanvasSyncTarget,
    ) -> Result<(), CanvasSyncProcessingError> {
        let mut transaction = self.begin_write(target).await?;
        let result = sqlx::query(
            "UPDATE issuance_service.canvas_evidence_sync_targets
             SET enabled = false, updated_at = clock_timestamp()
             WHERE id = $1 AND organization_id = $2 AND config_version = $3",
        )
        .bind(&target.id)
        .bind(&target.organization_id)
        .bind(target.config_version)
        .execute(&mut *transaction)
        .await
        .map_err(repository_error)?;
        if result.rows_affected() != 1 {
            return Err(stale());
        }
        self.commit_write(transaction, target).await
    }

    async fn existing_candidates(
        &self,
        organization_id: &str,
        binding_id: &str,
        limit: usize,
    ) -> Result<Vec<CanvasRosterCandidate>, CanvasSyncProcessingError> {
        sqlx::query(
            "SELECT id, candidate_key, canvas_user_id, lti_subject, learner_identity_id, state
             FROM issuance_service.canvas_award_candidates
             WHERE organization_id = $1 AND binding_id = $2
             ORDER BY updated_at DESC LIMIT $3",
        )
        .bind(organization_id)
        .bind(binding_id)
        .bind(i64::try_from(limit).unwrap_or(10_000))
        .fetch_all(&self.pool)
        .await
        .map_err(repository_error)?
        .into_iter()
        .map(candidate_row)
        .collect()
    }

    async fn save_candidate(
        &self,
        target: &CanvasSyncTarget,
        resources: &CanvasSyncResources,
        candidate: &CanvasRosterCandidate,
    ) -> Result<String, CanvasSyncProcessingError> {
        let mut transaction = self.begin_write(target).await?;
        lock_current_scope(&mut transaction, target, resources).await?;
        let id = sqlx::query_scalar(
            "INSERT INTO issuance_service.canvas_award_candidates (
                id, organization_id, platform_id, binding_id, learner_identity_id,
                candidate_key, canvas_user_id, lti_subject, state, observed_at,
                created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp(),clock_timestamp(),clock_timestamp())
             ON CONFLICT (binding_id, candidate_key) DO UPDATE SET
                learner_identity_id = EXCLUDED.learner_identity_id,
                canvas_user_id = EXCLUDED.canvas_user_id, lti_subject = EXCLUDED.lti_subject,
                state = CASE WHEN canvas_award_candidates.state IN ('claimed','dismissed')
                             THEN canvas_award_candidates.state ELSE EXCLUDED.state END,
                observed_at = clock_timestamp(), updated_at = clock_timestamp()
             WHERE canvas_award_candidates.organization_id = EXCLUDED.organization_id
               AND canvas_award_candidates.platform_id = EXCLUDED.platform_id
               AND canvas_award_candidates.binding_id = EXCLUDED.binding_id
             RETURNING id",
        )
        .bind(&candidate.id)
        .bind(&target.organization_id)
        .bind(&target.platform_id)
        .bind(&target.binding_id)
        .bind(&candidate.learner_identity_id)
        .bind(&candidate.candidate_key)
        .bind(&candidate.canvas_user_id)
        .bind(&candidate.lti_subject)
        .bind(&candidate.state)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(repository_error)?
        .ok_or_else(stale)?;
        self.commit_write(transaction, target).await?;
        Ok(id)
    }

    async fn save_candidate_observation(
        &self,
        target: &CanvasSyncTarget,
        resources: &CanvasSyncResources,
        candidate_id: &str,
        requirement_id: &str,
        observation: &CanvasAuthoritativeObservation,
    ) -> Result<bool, CanvasSyncProcessingError> {
        let canonical = crate::canvas_award_candidate::python_canonical_json(&json!({
            "assertion": observation.assertion,
            "payload": observation.source_payload,
        }));
        let payload_hash = hex::encode(Sha256::digest(canonical.as_bytes()));
        let mut transaction = self.begin_write(target).await?;
        lock_current_scope(&mut transaction, target, resources).await?;
        let candidate_current = sqlx::query_scalar::<_, i32>(
            "SELECT 1 FROM issuance_service.canvas_award_candidates
             WHERE id = $1 AND organization_id = $2 AND platform_id = $3 AND binding_id = $4
             FOR UPDATE",
        )
        .bind(candidate_id)
        .bind(&target.organization_id)
        .bind(&target.platform_id)
        .bind(&target.binding_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(repository_error)?;
        if candidate_current.is_none() {
            transaction.rollback().await.map_err(repository_error)?;
            return Err(stale());
        }
        let current = sqlx::query(
            "SELECT id, payload_hash FROM issuance_service.canvas_candidate_observations
             WHERE organization_id = $1 AND candidate_id = $2 AND logical_key = $3
               AND is_current = true FOR UPDATE",
        )
        .bind(&target.organization_id)
        .bind(candidate_id)
        .bind(requirement_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(repository_error)?;
        if current
            .as_ref()
            .and_then(|row| row.try_get::<String, _>("payload_hash").ok())
            .as_deref()
            == Some(payload_hash.as_str())
        {
            self.commit_write(transaction, target).await?;
            return Ok(false);
        }
        let superseded = current
            .as_ref()
            .and_then(|row| row.try_get::<String, _>("id").ok());
        if let Some(id) = superseded.as_deref() {
            let result = sqlx::query("UPDATE issuance_service.canvas_candidate_observations SET is_current = false WHERE id = $1 AND organization_id = $2 AND candidate_id = $3 AND is_current = true")
                .bind(id)
                .bind(&target.organization_id)
                .bind(candidate_id)
                .execute(&mut *transaction)
                .await
                .map_err(repository_error)?;
            if result.rows_affected() != 1 {
                transaction.rollback().await.map_err(repository_error)?;
                return Err(stale());
            }
        }
        let inserted = sqlx::query(
            "INSERT INTO issuance_service.canvas_candidate_observations (
                id, organization_id, candidate_id, requirement_id, logical_key,
                assertion, verification, payload_hash, superseded_observation_id,
                is_current, observed_at, created_at)
             VALUES ($1,$2,$3,$4,$4,$5,$6,$7,$8,true,clock_timestamp(),clock_timestamp())",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&target.organization_id)
        .bind(candidate_id)
        .bind(requirement_id)
        .bind(Value::Object(observation.assertion.clone()))
        .bind(json!({"status":"VERIFIED","method":observation.verification_method}))
        .bind(payload_hash)
        .bind(superseded)
        .execute(&mut *transaction)
        .await
        .map_err(repository_error)?;
        if inserted.rows_affected() != 1 {
            transaction.rollback().await.map_err(repository_error)?;
            return Err(stale());
        }
        self.commit_write(transaction, target).await?;
        Ok(true)
    }

    async fn current_candidate_observations(
        &self,
        organization_id: &str,
        candidate_id: &str,
    ) -> Result<Vec<CanvasCandidateObservationSnapshot>, CanvasSyncProcessingError> {
        sqlx::query(
            "SELECT requirement_id, assertion FROM issuance_service.canvas_candidate_observations
             WHERE organization_id = $1 AND candidate_id = $2 AND is_current = true
             ORDER BY requirement_id",
        )
        .bind(organization_id)
        .bind(candidate_id)
        .fetch_all(&self.pool)
        .await
        .map_err(repository_error)?
        .into_iter()
        .map(|row| {
            let assertion: Value = row.try_get("assertion").map_err(repository_error)?;
            Ok(CanvasCandidateObservationSnapshot {
                requirement_id: row.try_get("requirement_id").map_err(repository_error)?,
                assertion: assertion.as_object().cloned().unwrap_or_default(),
            })
        })
        .collect()
    }

    async fn update_roster_cursor(
        &self,
        target: &CanvasSyncTarget,
        resources: &CanvasSyncResources,
        next_cursor: usize,
        roster_size: usize,
    ) -> Result<(), CanvasSyncProcessingError> {
        let patch = json!({
            "roster_cursor": next_cursor,
            "roster_size": roster_size,
            "roster_cycle_completed_at": (next_cursor == 0).then(Utc::now),
        });
        let mut transaction = self.begin_write(target).await?;
        lock_current_scope(&mut transaction, target, resources).await?;
        let result = sqlx::query(
            "UPDATE issuance_service.canvas_evidence_sync_targets
             SET metadata = COALESCE(metadata::jsonb, '{}'::jsonb) || $4::jsonb,
                 next_run_at = CASE WHEN $5 THEN clock_timestamp() + interval '60 seconds' ELSE next_run_at END,
                 updated_at = clock_timestamp()
             WHERE id = $1 AND organization_id = $2 AND config_version = $3",
        )
        .bind(&target.id)
        .bind(&target.organization_id)
        .bind(target.config_version)
        .bind(patch)
        .bind(next_cursor != 0)
        .execute(&mut *transaction)
        .await
        .map_err(repository_error)?;
        if result.rows_affected() != 1 {
            transaction.rollback().await.map_err(repository_error)?;
            return Err(stale());
        }
        self.commit_write(transaction, target).await?;
        Ok(())
    }
}

async fn lock_current_scope(
    transaction: &mut Transaction<'_, Postgres>,
    target: &CanvasSyncTarget,
    resources: &CanvasSyncResources,
) -> Result<(), CanvasSyncProcessingError> {
    let current = sqlx::query_scalar::<_, i32>(
        "SELECT 1
         FROM issuance_service.canvas_evidence_sync_targets t
         JOIN issuance_service.canvas_platforms p
           ON p.id = t.platform_id AND p.organization_id = t.organization_id
         JOIN issuance_service.canvas_program_bindings b
           ON b.id = t.binding_id AND b.organization_id = t.organization_id
          AND b.platform_id = t.platform_id
         WHERE t.id = $1 AND t.organization_id = $2
           AND t.platform_id = $3 AND t.binding_id = $4
           AND t.config_version = $5 AND t.enabled = true
           AND p.config_version = $6 AND p.enabled = true AND p.archived_at IS NULL
           AND b.config_version = $5 AND b.enabled = true AND b.archived_at IS NULL
         FOR UPDATE OF t, p, b",
    )
    .bind(&target.id)
    .bind(&target.organization_id)
    .bind(&target.platform_id)
    .bind(&target.binding_id)
    .bind(target.config_version)
    .bind(resources.platform.config_version)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(repository_error)?;
    if current.is_none() {
        return Err(stale());
    }
    Ok(())
}

async fn lock_current_application(
    transaction: &mut Transaction<'_, Postgres>,
    application: &CanvasSyncApplicationSnapshot,
) -> Result<(), CanvasSyncProcessingError> {
    let current = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM issuance_service.applications
         WHERE id = $1 AND organization_id = $2 AND status = $3
           AND integration_context::jsonb IS NOT DISTINCT FROM $4::jsonb
         FOR UPDATE",
    )
    .bind(&application.application.id)
    .bind(&application.application.organization_id)
    .bind(&application.application.status)
    .bind(&application.application.integration_context)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(repository_error)?;
    if current.is_none() {
        return Err(stale());
    }
    Ok(())
}

fn required_text(
    value: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<String, CanvasSyncProcessingError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(unavailable)
}

impl PostgresCanvasSyncProcessorRepository {
    async fn identity(
        &self,
        organization_id: &str,
        platform_id: &str,
        deployment_id: &str,
        column: &'static str,
        identifier: &str,
    ) -> Result<Option<CanvasLinkedIdentitySnapshot>, CanvasSyncProcessingError> {
        let query = match column {
            "lti_subject" => "SELECT id, lti_subject, canvas_user_id, status FROM issuance_service.canvas_learner_identities WHERE organization_id=$1 AND platform_id=$2 AND deployment_id=$3 AND lti_subject=$4",
            "canvas_user_id" => "SELECT id, lti_subject, canvas_user_id, status FROM issuance_service.canvas_learner_identities WHERE organization_id=$1 AND platform_id=$2 AND deployment_id=$3 AND canvas_user_id=$4",
            _ => return Err(unavailable()),
        };
        sqlx::query(query)
            .bind(organization_id)
            .bind(platform_id)
            .bind(deployment_id)
            .bind(identifier)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(|row| {
                Ok(CanvasLinkedIdentitySnapshot {
                    id: row.try_get("id").map_err(repository_error)?,
                    lti_subject: row.try_get("lti_subject").map_err(repository_error)?,
                    canvas_user_id: row.try_get("canvas_user_id").map_err(repository_error)?,
                    status: row.try_get("status").map_err(repository_error)?,
                })
            })
            .transpose()
    }
}

fn application_snapshot(
    row: sqlx::postgres::PgRow,
) -> Result<CanvasSyncApplicationSnapshot, CanvasSyncProcessingError> {
    Ok(CanvasSyncApplicationSnapshot {
        credential_id: row.try_get("credential_id").map_err(repository_error)?,
        application: CanvasLtiBootstrapApplication {
            id: row.try_get("id").map_err(repository_error)?,
            organization_id: row.try_get("organization_id").map_err(repository_error)?,
            application_template_id: row
                .try_get("application_template_id")
                .map_err(repository_error)?,
            applicant_identifier: row
                .try_get("applicant_identifier")
                .map_err(repository_error)?,
            form_data: row.try_get("form_data").map_err(repository_error)?,
            integration_context: row
                .try_get("integration_context")
                .map_err(repository_error)?,
            status: row.try_get("status").map_err(repository_error)?,
            created_at: row.try_get("created_at").map_err(repository_error)?,
            updated_at: row.try_get("updated_at").map_err(repository_error)?,
        },
    })
}

fn candidate_row(
    row: sqlx::postgres::PgRow,
) -> Result<CanvasRosterCandidate, CanvasSyncProcessingError> {
    Ok(CanvasRosterCandidate {
        id: row.try_get("id").map_err(repository_error)?,
        candidate_key: row.try_get("candidate_key").map_err(repository_error)?,
        canvas_user_id: row.try_get("canvas_user_id").map_err(repository_error)?,
        lti_subject: row.try_get("lti_subject").map_err(repository_error)?,
        learner_identity_id: row
            .try_get("learner_identity_id")
            .map_err(repository_error)?,
        state: row.try_get("state").map_err(repository_error)?,
    })
}

fn repository_error(_: sqlx::Error) -> CanvasSyncProcessingError {
    unavailable()
}
fn unavailable() -> CanvasSyncProcessingError {
    CanvasSyncProcessingError::retryable(
        "canvas_sync_repository_unavailable",
        "Canvas synchronization persistence is unavailable",
    )
}

fn stale() -> CanvasSyncProcessingError {
    CanvasSyncProcessingError::retryable(
        "canvas_platform_reconfigured",
        "Canvas target, platform, binding, or application changed during synchronization",
    )
}
