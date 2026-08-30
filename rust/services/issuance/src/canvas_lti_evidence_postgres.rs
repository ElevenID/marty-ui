use async_trait::async_trait;
use serde_json::Value;
use sqlx::{PgPool, Row};

use crate::{
    canvas_lti_evidence::{
        CanvasLtiEvidenceApplication, CanvasLtiEvidenceBinding, CanvasLtiEvidenceCandidate,
        CanvasLtiEvidenceError, CanvasLtiEvidenceFact, CanvasLtiEvidencePlatform,
        CanvasLtiEvidenceProjectionData, CanvasLtiEvidenceRepository, CanvasLtiEvidenceScope,
        CanvasLtiEvidenceSyncJob, CanvasLtiEvidenceSyncTarget,
    },
    canvas_lti_experience::{python_string, CanvasLtiExperienceSessionContext},
};

const LOAD_SCOPE: &str = "SELECT
        application.id AS application_id,
        application.organization_id,
        application.application_template_id,
        application.status::text AS application_status,
        application.credential_id,
        application.integration_context,
        binding.id AS binding_id,
        binding.platform_id AS binding_platform_id,
        binding.application_template_id AS binding_application_template_id,
        binding.evidence_requirements,
        binding.config_version,
        platform.id AS platform_id
    FROM issuance_service.applications AS application
    JOIN issuance_service.canvas_program_bindings AS binding
      ON binding.id = $3
     AND binding.organization_id = application.organization_id
    JOIN issuance_service.canvas_platforms AS platform
      ON platform.id = $4
     AND platform.organization_id = application.organization_id
    WHERE application.id = $1
      AND application.organization_id = $2";

const LOAD_CURRENT_FACTS: &str = "SELECT fact.provider, fact.requirement_id,
        fact.source, fact.verification, fact.observed_at
    FROM issuance_service.evidence_fact_heads AS head
    JOIN issuance_service.evidence_facts AS fact
      ON fact.organization_id = head.organization_id
     AND fact.application_id = head.application_id
     AND fact.logical_key = head.logical_key
     AND fact.id = head.fact_id
    WHERE head.organization_id = $1 AND head.application_id = $2
    ORDER BY fact.observed_at, fact.created_at, fact.id";

const LOAD_TARGET: &str = "SELECT id, application_id, binding_id, platform_id, config_version
    FROM issuance_service.canvas_evidence_sync_targets
    WHERE organization_id = $1 AND logical_key = $2";

const LOAD_JOBS: &str = "SELECT id, status::text AS status, result, created_at, completed_at
    FROM issuance_service.canvas_evidence_sync_jobs
    WHERE organization_id = $1 AND target_id = $2
    ORDER BY created_at DESC, id DESC
    LIMIT 25";

const LOAD_CANDIDATE: &str = "SELECT id, application_id, binding_id, platform_id,
        state::text AS state
    FROM issuance_service.canvas_award_candidates
    WHERE organization_id = $1 AND id = $2";

#[derive(Clone, Debug)]
pub struct PostgresCanvasLtiEvidenceRepository {
    pool: PgPool,
}

impl PostgresCanvasLtiEvidenceRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn load_facts(
        &self,
        organization_id: &str,
        application_id: &str,
    ) -> Result<Vec<CanvasLtiEvidenceFact>, CanvasLtiEvidenceError> {
        sqlx::query(LOAD_CURRENT_FACTS)
            .bind(organization_id)
            .bind(application_id)
            .fetch_all(&self.pool)
            .await
            .map_err(repository_error)?
            .into_iter()
            .map(fact_from_row)
            .collect()
    }

    async fn load_target(
        &self,
        organization_id: &str,
        application_id: &str,
    ) -> Result<Option<CanvasLtiEvidenceSyncTarget>, CanvasLtiEvidenceError> {
        sqlx::query(LOAD_TARGET)
            .bind(organization_id)
            .bind(format!("application:{application_id}"))
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(target_from_row)
            .transpose()
    }

    async fn load_jobs(
        &self,
        organization_id: &str,
        target_id: &str,
    ) -> Result<Vec<CanvasLtiEvidenceSyncJob>, CanvasLtiEvidenceError> {
        sqlx::query(LOAD_JOBS)
            .bind(organization_id)
            .bind(target_id)
            .fetch_all(&self.pool)
            .await
            .map_err(repository_error)?
            .into_iter()
            .map(job_from_row)
            .collect()
    }

    async fn load_candidate(
        &self,
        scope: &CanvasLtiEvidenceScope,
    ) -> Result<Option<CanvasLtiEvidenceCandidate>, CanvasLtiEvidenceError> {
        let Some(candidate_id) = scope
            .application
            .integration_context
            .get("canvas")
            .and_then(|canvas| canvas.get("canvas_award_candidate_id"))
            .and_then(python_string)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };
        sqlx::query(LOAD_CANDIDATE)
            .bind(&scope.application.organization_id)
            .bind(candidate_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(candidate_from_row)
            .transpose()
    }
}

#[async_trait]
impl CanvasLtiEvidenceRepository for PostgresCanvasLtiEvidenceRepository {
    async fn load_scope(
        &self,
        context: &CanvasLtiExperienceSessionContext,
    ) -> Result<Option<CanvasLtiEvidenceScope>, CanvasLtiEvidenceError> {
        let (Some(application_id), Some(binding_id)) = (
            context.application_id.as_deref(),
            context.canvas_program_binding_id.as_deref(),
        ) else {
            return Ok(None);
        };
        sqlx::query(LOAD_SCOPE)
            .bind(application_id)
            .bind(&context.launch_state.organization_id)
            .bind(binding_id)
            .bind(&context.canvas_platform_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(scope_from_row)
            .transpose()
    }

    async fn load_projection_data(
        &self,
        scope: &CanvasLtiEvidenceScope,
    ) -> Result<CanvasLtiEvidenceProjectionData, CanvasLtiEvidenceError> {
        let organization_id = &scope.application.organization_id;
        let application_id = &scope.application.id;
        let (facts, target, candidate) = tokio::try_join!(
            self.load_facts(organization_id, application_id),
            self.load_target(organization_id, application_id),
            self.load_candidate(scope),
        )?;
        let jobs = if let Some(target) = target.as_ref() {
            self.load_jobs(organization_id, &target.id).await?
        } else {
            Vec::new()
        };
        Ok(CanvasLtiEvidenceProjectionData {
            facts,
            target,
            jobs,
            candidate,
        })
    }
}

fn scope_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<CanvasLtiEvidenceScope, CanvasLtiEvidenceError> {
    let organization_id: String = row.try_get("organization_id").map_err(repository_error)?;
    let evidence_requirements: Value = row
        .try_get("evidence_requirements")
        .map_err(repository_error)?;
    Ok(CanvasLtiEvidenceScope {
        application: CanvasLtiEvidenceApplication {
            id: row.try_get("application_id").map_err(repository_error)?,
            organization_id: organization_id.clone(),
            application_template_id: row
                .try_get("application_template_id")
                .map_err(repository_error)?,
            status: row
                .try_get("application_status")
                .map_err(repository_error)?,
            credential_id: row.try_get("credential_id").map_err(repository_error)?,
            integration_context: row
                .try_get("integration_context")
                .map_err(repository_error)?,
        },
        binding: CanvasLtiEvidenceBinding {
            id: row.try_get("binding_id").map_err(repository_error)?,
            organization_id: organization_id.clone(),
            platform_id: row
                .try_get("binding_platform_id")
                .map_err(repository_error)?,
            application_template_id: row
                .try_get("binding_application_template_id")
                .map_err(repository_error)?,
            evidence_requirements: evidence_requirements
                .as_array()
                .cloned()
                .ok_or(CanvasLtiEvidenceError::RepositoryUnavailable)?,
            config_version: row
                .try_get::<i32, _>("config_version")
                .map(i64::from)
                .map_err(repository_error)?,
        },
        platform: CanvasLtiEvidencePlatform {
            id: row.try_get("platform_id").map_err(repository_error)?,
            organization_id,
        },
    })
}

fn fact_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<CanvasLtiEvidenceFact, CanvasLtiEvidenceError> {
    Ok(CanvasLtiEvidenceFact {
        provider: row.try_get("provider").map_err(repository_error)?,
        requirement_id: row.try_get("requirement_id").map_err(repository_error)?,
        source: row.try_get("source").map_err(repository_error)?,
        verification: row.try_get("verification").map_err(repository_error)?,
        observed_at: row.try_get("observed_at").map_err(repository_error)?,
    })
}

fn target_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<CanvasLtiEvidenceSyncTarget, CanvasLtiEvidenceError> {
    Ok(CanvasLtiEvidenceSyncTarget {
        id: row.try_get("id").map_err(repository_error)?,
        application_id: row.try_get("application_id").map_err(repository_error)?,
        binding_id: row.try_get("binding_id").map_err(repository_error)?,
        platform_id: row.try_get("platform_id").map_err(repository_error)?,
        config_version: row
            .try_get::<i32, _>("config_version")
            .map(i64::from)
            .map_err(repository_error)?,
    })
}

fn job_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<CanvasLtiEvidenceSyncJob, CanvasLtiEvidenceError> {
    let status: String = row.try_get("status").map_err(repository_error)?;
    if !matches!(
        status.as_str(),
        "queued" | "leased" | "retry" | "succeeded" | "dead_letter" | "cancelled"
    ) {
        return Err(CanvasLtiEvidenceError::RepositoryUnavailable);
    }
    Ok(CanvasLtiEvidenceSyncJob {
        id: row.try_get("id").map_err(repository_error)?,
        status,
        result: row.try_get("result").map_err(repository_error)?,
        created_at: row.try_get("created_at").map_err(repository_error)?,
        completed_at: row.try_get("completed_at").map_err(repository_error)?,
    })
}

fn candidate_from_row(
    row: sqlx::postgres::PgRow,
) -> Result<CanvasLtiEvidenceCandidate, CanvasLtiEvidenceError> {
    Ok(CanvasLtiEvidenceCandidate {
        id: row.try_get("id").map_err(repository_error)?,
        application_id: row.try_get("application_id").map_err(repository_error)?,
        binding_id: row.try_get("binding_id").map_err(repository_error)?,
        platform_id: row.try_get("platform_id").map_err(repository_error)?,
        state: row.try_get("state").map_err(repository_error)?,
    })
}

fn repository_error(_cause: sqlx::Error) -> CanvasLtiEvidenceError {
    CanvasLtiEvidenceError::RepositoryUnavailable
}
