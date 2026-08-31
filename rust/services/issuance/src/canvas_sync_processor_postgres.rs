//! Tenant-scoped PostgreSQL adapter for authoritative Canvas reconciliation.

use async_trait::async_trait;
use chrono::Utc;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{
    canvas_award_candidate_postgres::record_fact_and_policy,
    canvas_lti_bootstrap::CanvasLtiBootstrapApplication,
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
}

impl PostgresCanvasSyncProcessorRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CanvasSyncProcessorRepository for PostgresCanvasSyncProcessorRepository {
    async fn resources(
        &self,
        target: &CanvasSyncTarget,
    ) -> Result<Option<CanvasSyncResources>, CanvasSyncProcessingError> {
        let platform = sqlx::query(
            "SELECT id, organization_id, COALESCE(canvas_base_url, '') AS canvas_base_url,
                    COALESCE(lti_issuer, '') AS lti_issuer,
                    COALESCE(lti_client_id, '') AS lti_client_id,
                    COALESCE(lti_deployment_id, '') AS lti_deployment_id,
                    COALESCE(lti_openid_configuration->>'token_endpoint', '') AS lti_auth_token_url,
                    config_version
             FROM issuance_service.canvas_platforms
             WHERE id = $1 AND organization_id = $2 AND archived_at IS NULL",
        )
        .bind(&target.platform_id)
        .bind(&target.organization_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(repository_error)?;
        let Some(platform) = platform else {
            return Ok(None);
        };
        let binding = sqlx::query_scalar::<_, Value>(
            "SELECT jsonb_build_object(
                'id', id, 'organization_id', organization_id, 'platform_id', platform_id,
                'application_template_id', application_template_id,
                'approval_policy_set_id', approval_policy_set_id,
                'auto_approve_on_evidence', auto_approve_on_evidence,
                'evidence_requirements', evidence_requirements, 'feature_flags', feature_flags,
                'enabled', enabled, 'config_version', config_version)
             FROM issuance_service.canvas_program_bindings
             WHERE id = $1 AND organization_id = $2 AND platform_id = $3",
        )
        .bind(&target.binding_id)
        .bind(&target.organization_id)
        .bind(&target.platform_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(repository_error)?
        .and_then(|value| value.as_object().cloned());
        let Some(binding) = binding else {
            return Ok(None);
        };
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
        resources: &CanvasSyncResources,
        fact: &Value,
    ) -> Result<CanvasFactCommit, CanvasSyncProcessingError> {
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
        organization_id: &str,
        application_id: &str,
        checked: &[String],
        policy_allowed: bool,
    ) -> Result<bool, CanvasSyncProcessingError> {
        let patch = json!({
            "last_evidence_sync_at": Utc::now(),
            "last_evidence_policy_allowed": policy_allowed,
            "last_evidence_requirements_checked": checked,
        });
        let result = sqlx::query(
            "UPDATE issuance_service.applications SET integration_context = jsonb_set(
                COALESCE(integration_context::jsonb, '{}'::jsonb), '{canvas}',
                COALESCE(integration_context::jsonb->'canvas', '{}'::jsonb) || $3::jsonb, true),
                updated_at = clock_timestamp()
             WHERE id = $1 AND organization_id = $2",
        )
        .bind(application_id)
        .bind(organization_id)
        .bind(patch)
        .execute(&self.pool)
        .await
        .map_err(repository_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn patch_platform_validation(
        &self,
        platform: &CanvasSyncPlatformSnapshot,
        error_code: Option<&str>,
    ) -> Result<bool, CanvasSyncProcessingError> {
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
        .execute(&self.pool)
        .await
        .map_err(repository_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn disable_target(
        &self,
        target: &CanvasSyncTarget,
    ) -> Result<(), CanvasSyncProcessingError> {
        sqlx::query(
            "UPDATE issuance_service.canvas_evidence_sync_targets
             SET enabled = false, updated_at = clock_timestamp()
             WHERE id = $1 AND organization_id = $2 AND config_version = $3",
        )
        .bind(&target.id)
        .bind(&target.organization_id)
        .bind(target.config_version)
        .execute(&self.pool)
        .await
        .map_err(repository_error)?;
        Ok(())
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
        candidate: &CanvasRosterCandidate,
    ) -> Result<String, CanvasSyncProcessingError> {
        sqlx::query_scalar(
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
        .fetch_one(&self.pool)
        .await
        .map_err(repository_error)
    }

    async fn save_candidate_observation(
        &self,
        target: &CanvasSyncTarget,
        candidate_id: &str,
        requirement_id: &str,
        observation: &CanvasAuthoritativeObservation,
    ) -> Result<bool, CanvasSyncProcessingError> {
        let canonical = crate::canvas_award_candidate::python_canonical_json(&json!({
            "assertion": observation.assertion,
            "payload": observation.source_payload,
        }));
        let payload_hash = hex::encode(Sha256::digest(canonical.as_bytes()));
        let mut transaction = self.pool.begin().await.map_err(repository_error)?;
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
            transaction.commit().await.map_err(repository_error)?;
            return Ok(false);
        }
        let superseded = current
            .as_ref()
            .and_then(|row| row.try_get::<String, _>("id").ok());
        if let Some(id) = superseded.as_deref() {
            sqlx::query("UPDATE issuance_service.canvas_candidate_observations SET is_current = false WHERE id = $1")
                .bind(id).execute(&mut *transaction).await.map_err(repository_error)?;
        }
        sqlx::query(
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
        transaction.commit().await.map_err(repository_error)?;
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
        next_cursor: usize,
        roster_size: usize,
    ) -> Result<(), CanvasSyncProcessingError> {
        let patch = json!({
            "roster_cursor": next_cursor,
            "roster_size": roster_size,
            "roster_cycle_completed_at": (next_cursor == 0).then(Utc::now),
        });
        sqlx::query(
            "UPDATE issuance_service.canvas_evidence_sync_targets
             SET metadata = COALESCE(metadata, '{}'::jsonb) || $4::jsonb,
                 next_run_at = CASE WHEN $5 THEN clock_timestamp() + interval '60 seconds' ELSE next_run_at END,
                 updated_at = clock_timestamp()
             WHERE id = $1 AND organization_id = $2 AND config_version = $3",
        )
        .bind(&target.id)
        .bind(&target.organization_id)
        .bind(target.config_version)
        .bind(patch)
        .bind(next_cursor != 0)
        .execute(&self.pool)
        .await
        .map_err(repository_error)?;
        Ok(())
    }
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
