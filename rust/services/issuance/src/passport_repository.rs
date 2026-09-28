//! Durable physical-document jobs, scoped by an authenticated passport tenant.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use marty_passport_auth::PassportTenantPrincipal;
use serde_json::Value;
use sqlx::{postgres::PgRow, PgConnection, PgPool, Postgres, QueryBuilder, Row};
use uuid::Uuid;

use crate::passport_beta_material::PassportBetaMaterialDigests;
use crate::passport_bureau::{BetaBatchWireCommitments, VerifiedWebhookEvent};

#[derive(Debug, thiserror::Error)]
pub enum PassportWebhookRepositoryError {
    #[error("physical document repository failed")]
    Storage(#[from] sqlx::Error),
    #[error("bureau job ID identifies multiple physical documents")]
    AmbiguousBureauJob,
    #[error("invalid bureau provider binding")]
    InvalidProviderBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PassportJobStatus {
    Draft,
    DataGenerated,
    SodSigned,
    Submitted,
    InProduction,
    QualityCheck,
    ReadyForActivation,
    Failed,
    Cancelled,
    Active,
}

impl PassportJobStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "DRAFT",
            Self::DataGenerated => "DATA_GENERATED",
            Self::SodSigned => "SOD_SIGNED",
            Self::Submitted => "SUBMITTED",
            Self::InProduction => "IN_PRODUCTION",
            Self::QualityCheck => "QUALITY_CHECK",
            Self::ReadyForActivation => "READY_FOR_ACTIVATION",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
            Self::Active => "ACTIVE",
        }
    }
}

pub struct PassportJobPatch {
    pub status: PassportJobStatus,
    /// Optional compare-and-swap guard for in-place SOD refreshes.
    pub expected_sod_sha256: Option<Option<String>>,
    pub expected_secure_artifact_ciphertext: Option<String>,
    pub expected_submission_intent_id: Option<Uuid>,
    pub clear_submission_intent: bool,
    pub sod_sha256: Option<Option<String>>,
    pub bureau_job_id: Option<Option<String>>,
    pub bureau_provider_profile_id: Option<String>,
    pub submission_batch_material_digests: Option<Value>,
    pub tracking_number: Option<Option<String>>,
    pub quality_result: Option<Option<Value>>,
    pub error_code: Option<Option<String>>,
    pub error_message: Option<Option<String>>,
    pub submitted_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub secure_artifact_ciphertext: Option<String>,
}

impl PassportJobPatch {
    #[must_use]
    pub fn new(status: PassportJobStatus) -> Self {
        Self {
            status,
            expected_sod_sha256: None,
            expected_secure_artifact_ciphertext: None,
            expected_submission_intent_id: None,
            clear_submission_intent: false,
            sod_sha256: None,
            bureau_job_id: None,
            bureau_provider_profile_id: None,
            submission_batch_material_digests: None,
            tracking_number: None,
            quality_result: None,
            error_code: None,
            error_message: None,
            submitted_at: None,
            completed_at: None,
            secure_artifact_ciphertext: None,
        }
    }
}

pub struct PassportJobInsert {
    pub id: String,
    pub application_id: String,
    pub flow_execution_id: String,
    pub application_template_id: String,
    pub credential_template_id: String,
    pub revocation_profile_id: Option<String>,
    pub delivery_destination_profile_id: String,
    pub document_type: String,
    pub country_code: String,
    pub issuer_did: Option<String>,
    pub secure_artifact_ciphertext: String,
    pub secure_artifact_reference: String,
}

pub struct PassportSubmissionReservation<'a> {
    pub intent_id: Uuid,
    pub sod_sha256: &'a str,
    pub signed_artifact_ciphertext: Option<&'a str>,
    pub provider_profile_id: Option<&'a str>,
    pub bureau_endpoint_sha256: &'a str,
    pub signing_provenance: Option<&'a Value>,
    pub now: DateTime<Utc>,
}

/// Durable correlation for an inspected beta Flow job and its companion.
pub struct PassportBatchIdentity<'a> {
    pub batch_id: Uuid,
    pub selected_flow_instance_id: &'a str,
    pub selected_job_id: &'a str,
    pub companion_job_id: &'a str,
}

pub struct PassportBetaMaterialReceipt {
    pub bureau_job_id: Uuid,
    pub content_sha256: Option<Vec<u8>>,
    pub sod_der_sha256: Option<Vec<u8>>,
    pub dsc_der_sha256: Option<Vec<u8>>,
    pub dsc_pem_wire_sha256: Option<Vec<u8>>,
    pub document_type: Option<String>,
    pub first_accepted_at: DateTime<Utc>,
}

/// Exact signed material supplied by the beta batch caller for receipt checks.
pub struct PassportBetaBatchBinding<'a> {
    pub bureau_job_id: Uuid,
    pub material_digests: &'a PassportBetaMaterialDigests,
}

pub struct PassportBetaBatchDestination<'a> {
    pub provider_profile_id: &'a str,
    pub endpoint_sha256: &'a str,
}

/// The ciphertext is intentionally kept out of Debug and HTTP projections.
pub struct PassportJob {
    pub id: String,
    pub organization_id: String,
    pub flow_execution_id: String,
    pub application_id: String,
    pub application_template_id: String,
    pub credential_template_id: String,
    pub revocation_profile_id: Option<String>,
    pub delivery_destination_profile_id: String,
    pub document_type: String,
    pub country_code: String,
    pub issuer_did: Option<String>,
    pub secure_artifact_ciphertext: String,
    pub secure_artifact_reference: String,
    pub sod_sha256: Option<String>,
    pub bureau_job_id: Option<String>,
    pub bureau_provider_profile_id: Option<String>,
    pub submission_intent_id: Option<Uuid>,
    pub submission_intent_started_at: Option<DateTime<Utc>>,
    pub submission_intent_provider_profile_id: Option<String>,
    pub submission_intent_bureau_endpoint_sha256: Option<String>,
    pub submission_intent_signing_provenance: Option<Value>,
    pub submission_batch_id: Option<Uuid>,
    pub submission_batch_selected_flow_instance_id: Option<String>,
    pub submission_batch_selected_job_id: Option<String>,
    pub submission_batch_companion_job_id: Option<String>,
    pub submission_batch_signing_provenance: Option<Value>,
    pub submission_batch_bureau_endpoint_sha256: Option<String>,
    pub submission_batch_material_digests: Option<Value>,
    pub tracking_number: Option<String>,
    pub status: String,
    pub quality_result: Option<Value>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub submitted_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct PostgresPassportRepository {
    pool: PgPool,
}

impl PostgresPassportRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn insert(
        &self,
        principal: &PassportTenantPrincipal,
        job: &PassportJobInsert,
        now: DateTime<Utc>,
    ) -> Result<PassportJob, sqlx::Error> {
        let row = sqlx::query(
            "INSERT INTO issuance_service.physical_document_jobs (
                id, organization_id, flow_execution_id, application_id,
                application_template_id, credential_template_id, revocation_profile_id,
                delivery_destination_profile_id, document_type, country_code, issuer_did,
                secure_artifact_ciphertext, secure_artifact_reference, status,
                created_at, updated_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'DRAFT',$14,$14)
            RETURNING *",
        )
        .bind(&job.id)
        .bind(principal.organization_id())
        .bind(&job.flow_execution_id)
        .bind(&job.application_id)
        .bind(&job.application_template_id)
        .bind(&job.credential_template_id)
        .bind(&job.revocation_profile_id)
        .bind(&job.delivery_destination_profile_id)
        .bind(&job.document_type)
        .bind(&job.country_code)
        .bind(&job.issuer_did)
        .bind(&job.secure_artifact_ciphertext)
        .bind(&job.secure_artifact_reference)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        row_to_job(&row)
    }

    pub async fn get(
        &self,
        principal: &PassportTenantPrincipal,
        application_id: &str,
    ) -> Result<Option<PassportJob>, sqlx::Error> {
        sqlx::query(
            "SELECT * FROM issuance_service.physical_document_jobs
             WHERE organization_id = $1 AND application_id = $2",
        )
        .bind(principal.organization_id())
        .bind(application_id)
        .fetch_optional(&self.pool)
        .await?
        .as_ref()
        .map(row_to_job)
        .transpose()
    }

    /// Claim the exact signed material before an external send. A timed-out
    /// request deliberately keeps this claim for private reconciliation.
    pub async fn reserve_submission(
        &self,
        principal: &PassportTenantPrincipal,
        job: &PassportJob,
        reservation: &PassportSubmissionReservation<'_>,
    ) -> Result<Option<PassportJob>, sqlx::Error> {
        let mut connection = self.pool.acquire().await?;
        Self::reserve_submission_on(&mut connection, principal, job, reservation, None).await
    }

    /// Claim both signed source jobs in one transaction before a beta batch
    /// send. A failed second claim rolls back the first claim as well.
    pub async fn reserve_batch_submissions(
        &self,
        principal: &PassportTenantPrincipal,
        jobs: [&PassportJob; 2],
        reservations: [&PassportSubmissionReservation<'_>; 2],
        identity: &PassportBatchIdentity<'_>,
    ) -> Result<Option<[PassportJob; 2]>, sqlx::Error> {
        if jobs[0].id == jobs[1].id
            || jobs[0].application_id == jobs[1].application_id
            || jobs
                .iter()
                .any(|job| job.organization_id != principal.organization_id())
            || reservations[0].intent_id == reservations[1].intent_id
            || identity.selected_job_id != jobs[0].id
            || identity.companion_job_id != jobs[1].id
            || identity.selected_flow_instance_id != jobs[0].flow_execution_id
            || jobs
                .iter()
                .any(|job| job.status != "SOD_SIGNED" || job.issuer_did.is_none())
            || jobs
                .iter()
                .zip(reservations)
                .any(|(job, reservation)| job.sod_sha256.as_deref() != Some(reservation.sod_sha256))
            || reservations[0].provider_profile_id.is_none()
            || reservations[0].provider_profile_id != reservations[1].provider_profile_id
            || reservations[0].bureau_endpoint_sha256 != reservations[1].bureau_endpoint_sha256
            || reservations.iter().any(|reservation| {
                !reservation.signing_provenance.is_some_and(|provenance| {
                    provenance["issuer_profile_id"]
                        .as_str()
                        .is_some_and(|id| !id.trim().is_empty())
                })
            })
            || reservations[0]
                .signing_provenance
                .and_then(|provenance| provenance["issuer_profile_id"].as_str())
                != reservations[1]
                    .signing_provenance
                    .and_then(|provenance| provenance["issuer_profile_id"].as_str())
        {
            return Ok(None);
        }
        let mut transaction = self.pool.begin().await?;
        let claimed = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO issuance_service.passport_beta_batch_intents
             (batch_id, organization_id, selected_flow_instance_id,
              selected_job_id, companion_job_id, created_at, last_send_started_at)
             VALUES ($1,$2,$3,$4,$5,$6,$6)
             ON CONFLICT (batch_id) DO NOTHING RETURNING batch_id",
        )
        .bind(identity.batch_id)
        .bind(principal.organization_id())
        .bind(identity.selected_flow_instance_id)
        .bind(identity.selected_job_id)
        .bind(identity.companion_job_id)
        .bind(reservations[0].now)
        .fetch_optional(&mut *transaction)
        .await?;
        if claimed.is_none() {
            transaction.rollback().await?;
            return Ok(None);
        }
        if !Self::selected_flow_ready_on(
            &mut transaction,
            principal,
            jobs[0],
            identity,
            reservations[0].sod_sha256,
            reservations[0].signing_provenance,
        )
        .await?
        {
            transaction.rollback().await?;
            return Ok(None);
        }
        let mut reserved: [Option<PassportJob>; 2] = [None, None];
        let order = if jobs[0].id <= jobs[1].id {
            [0, 1]
        } else {
            [1, 0]
        };
        for index in order {
            let Some(job) = Self::reserve_submission_on(
                &mut transaction,
                principal,
                jobs[index],
                reservations[index],
                Some(identity),
            )
            .await?
            else {
                transaction.rollback().await?;
                return Ok(None);
            };
            reserved[index] = Some(job);
        }
        transaction.commit().await?;
        Ok(Some([
            reserved[0].take().expect("first claim succeeded"),
            reserved[1].take().expect("second claim succeeded"),
        ]))
    }

    /// Fence concurrent operator retries and allow only one exact replay after
    /// the full batch plus two single-job transport windows have elapsed.
    pub async fn claim_beta_batch_replay(
        &self,
        principal: &PassportTenantPrincipal,
        batch_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<bool, sqlx::Error> {
        Ok(sqlx::query_scalar::<_, Uuid>(
            "UPDATE issuance_service.passport_beta_batch_intents
             SET send_attempts=2, last_send_started_at=$3
             WHERE batch_id=$1 AND organization_id=$2
               AND send_attempts=1
               AND first_dispatch_response_seen_at IS NULL
               AND last_send_started_at <= $3 - INTERVAL '130 seconds'
             RETURNING batch_id",
        )
        .bind(batch_id)
        .bind(principal.organization_id())
        .bind(now)
        .fetch_optional(&self.pool)
        .await?
        .is_some())
    }

    /// Both exact simulator rows already exist. Consume the batch replay right
    /// before a type-fill send, fencing a stale one-receipt caller. Space
    /// receipt-backed idempotent completion attempts and count them for audit.
    pub async fn claim_beta_batch_receipt_completion(
        &self,
        principal: &PassportTenantPrincipal,
        batch_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<bool, sqlx::Error> {
        Ok(sqlx::query_scalar::<_, Uuid>(
            "UPDATE issuance_service.passport_beta_batch_intents
             SET send_attempts=2,
                 receipt_completion_attempts=receipt_completion_attempts+1,
                 last_receipt_completion_started_at=$3
             WHERE batch_id=$1 AND organization_id=$2
               AND last_send_started_at <= $3 - INTERVAL '130 seconds'
               AND (first_dispatch_response_seen_at IS NULL OR
                    first_dispatch_wire_ciphertext IS NOT NULL OR
                    first_dispatch_response_seen_at <= $3 - INTERVAL '65 seconds')
               AND (last_receipt_completion_started_at IS NULL OR
                    last_receipt_completion_started_at <= $3 - INTERVAL '65 seconds')
             RETURNING batch_id",
        )
        .bind(batch_id)
        .bind(principal.organization_id())
        .bind(now)
        .fetch_optional(&self.pool)
        .await?
        .is_some())
    }

    /// Fence batch replay as soon as the strict first HTTP 202 mapping is
    /// validated, before KMS retention or document-type completion begins.
    pub async fn mark_beta_batch_first_response(
        &self,
        principal: &PassportTenantPrincipal,
        identity: &PassportBatchIdentity<'_>,
        now: DateTime<Utc>,
    ) -> Result<bool, sqlx::Error> {
        Ok(sqlx::query_scalar::<_, Uuid>(
            "UPDATE issuance_service.passport_beta_batch_intents
             SET first_dispatch_response_seen_at=$6
             WHERE batch_id=$1 AND organization_id=$2
               AND selected_flow_instance_id=$3
               AND selected_job_id=$4 AND companion_job_id=$5
               AND send_attempts=1 AND first_dispatch_response_seen_at IS NULL
             RETURNING batch_id",
        )
        .bind(identity.batch_id)
        .bind(principal.organization_id())
        .bind(identity.selected_flow_instance_id)
        .bind(identity.selected_job_id)
        .bind(identity.companion_job_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?
        .is_some())
    }

    /// Retain encrypted exact first-dispatch bodies and their keyed proof.
    /// An exact replay cannot overwrite or create first-dispatch evidence.
    pub async fn retain_beta_batch_first_wire(
        &self,
        principal: &PassportTenantPrincipal,
        identity: &PassportBatchIdentity<'_>,
        ciphertext: &str,
        key_sha256: &str,
        commitments: &BetaBatchWireCommitments,
    ) -> Result<bool, sqlx::Error> {
        Ok(sqlx::query_scalar::<_, Uuid>(
            "UPDATE issuance_service.passport_beta_batch_intents
             SET first_dispatch_wire_ciphertext=$6,
                 first_dispatch_wire_key_sha256=$7,
                 first_dispatch_request_commitment=$8,
                 first_dispatch_response_commitment=$9
             WHERE batch_id=$1 AND organization_id=$2
               AND selected_flow_instance_id=$3
               AND selected_job_id=$4 AND companion_job_id=$5
               AND send_attempts=1
               AND first_dispatch_response_seen_at IS NOT NULL
               AND first_dispatch_wire_ciphertext IS NULL
             RETURNING batch_id",
        )
        .bind(identity.batch_id)
        .bind(principal.organization_id())
        .bind(identity.selected_flow_instance_id)
        .bind(identity.selected_job_id)
        .bind(identity.companion_job_id)
        .bind(ciphertext)
        .bind(key_sha256)
        .bind(&commitments.request_commitment)
        .bind(&commitments.response_commitment)
        .fetch_optional(&self.pool)
        .await?
        .is_some())
    }

    pub async fn beta_batch_first_wire_commitments(
        &self,
        principal: &PassportTenantPrincipal,
        batch_id: Uuid,
        key_sha256: &str,
    ) -> Result<Option<BetaBatchWireCommitments>, sqlx::Error> {
        sqlx::query(
            "SELECT first_dispatch_request_commitment,
                    first_dispatch_response_commitment
             FROM issuance_service.passport_beta_batch_intents
             WHERE batch_id=$1 AND organization_id=$2
               AND first_dispatch_wire_key_sha256=$3
               AND first_dispatch_wire_ciphertext IS NOT NULL",
        )
        .bind(batch_id)
        .bind(principal.organization_id())
        .bind(key_sha256)
        .fetch_optional(&self.pool)
        .await?
        .map(|row| {
            Ok(BetaBatchWireCommitments {
                request_commitment: row.try_get("first_dispatch_request_commitment")?,
                response_commitment: row.try_get("first_dispatch_response_commitment")?,
            })
        })
        .transpose()
    }

    pub async fn beta_batch_first_wire_ciphertext(
        &self,
        principal: &PassportTenantPrincipal,
        batch_id: Uuid,
        key_sha256: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT first_dispatch_wire_ciphertext
             FROM issuance_service.passport_beta_batch_intents
             WHERE batch_id=$1 AND organization_id=$2
               AND first_dispatch_wire_key_sha256=$3
               AND first_dispatch_wire_ciphertext IS NOT NULL",
        )
        .bind(batch_id)
        .bind(principal.organization_id())
        .bind(key_sha256)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn beta_batch_has_first_wire(
        &self,
        principal: &PassportTenantPrincipal,
        batch_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar::<_, bool>(
            "SELECT first_dispatch_wire_ciphertext IS NOT NULL
             FROM issuance_service.passport_beta_batch_intents
             WHERE batch_id=$1 AND organization_id=$2",
        )
        .bind(batch_id)
        .bind(principal.organization_id())
        .fetch_optional(&self.pool)
        .await
        .map(|value| value.unwrap_or(false))
    }

    pub async fn selected_flow_ready(
        &self,
        principal: &PassportTenantPrincipal,
        job: &PassportJob,
        identity: &PassportBatchIdentity<'_>,
        sod_sha256: &str,
        signing_provenance: Option<&Value>,
    ) -> Result<bool, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        let ready = Self::selected_flow_ready_on(
            &mut transaction,
            principal,
            job,
            identity,
            sod_sha256,
            signing_provenance,
        )
        .await?;
        transaction.rollback().await?;
        Ok(ready)
    }

    async fn selected_flow_ready_on(
        connection: &mut PgConnection,
        principal: &PassportTenantPrincipal,
        job: &PassportJob,
        identity: &PassportBatchIdentity<'_>,
        sod_sha256: &str,
        signing_provenance: Option<&Value>,
    ) -> Result<bool, sqlx::Error> {
        let row = sqlx::query(
            "SELECT instance.status AS instance_status, instance.current_step_id,
                    instance.context, instance.step_history,
                    definition.status AS definition_status, definition.flow_type,
                    definition.steps, definition.credential_template_id,
                    definition.application_template_id,
                    definition.delivery_destination_profile_id
             FROM flow_service.flow_instances AS instance
             JOIN flow_service.flow_definitions AS definition
               ON definition.id=instance.flow_definition_id
              AND definition.organization_id=instance.organization_id
             WHERE instance.id=$1 AND instance.organization_id=$2
             FOR SHARE OF instance, definition",
        )
        .bind(identity.selected_flow_instance_id)
        .bind(principal.organization_id())
        .fetch_optional(connection)
        .await?;
        let Some(row) = row else {
            return Ok(false);
        };
        let instance_status: String = row.try_get("instance_status")?;
        let definition_status: String = row.try_get("definition_status")?;
        let flow_type: String = row.try_get("flow_type")?;
        let current_step_id: Option<String> = row.try_get("current_step_id")?;
        let context: Value = row.try_get("context")?;
        let history: Value = row.try_get("step_history")?;
        let steps: Value = row.try_get("steps")?;
        let expected_steps = [
            "accept_application",
            "validate_evidence",
            "approval_decision",
            "generate_data_groups",
            "sign_sod",
            "submit_to_personalization",
            "track_production",
            "quality_verify",
            "activate_credential",
        ];
        let mut step_ids = BTreeSet::new();
        if !steps.as_array().is_some_and(|steps| {
            steps.len() == expected_steps.len()
                && steps.iter().zip(expected_steps).all(|(step, name)| {
                    step["config"]["protocol_step"].as_str() == Some(name)
                        && step["id"]
                            .as_str()
                            .is_some_and(|id| !id.is_empty() && step_ids.insert(id))
                })
        }) {
            return Ok(false);
        }
        let step_id = |name: &str| -> Option<&str> {
            let matches = steps
                .as_array()?
                .iter()
                .filter(|step| step["config"]["protocol_step"].as_str() == Some(name))
                .collect::<Vec<_>>();
            (matches.len() == 1)
                .then(|| matches[0]["id"].as_str())
                .flatten()
        };
        let Some(sign_step_id) = step_id("sign_sod") else {
            return Ok(false);
        };
        let Some(submit_step_id) = step_id("submit_to_personalization") else {
            return Ok(false);
        };
        let projection = &context["physical_document_job"];
        let last_history = history.as_array().and_then(|entries| entries.last());
        Ok(instance_status == "in_progress"
            && definition_status == "ACTIVE"
            && flow_type == "physical_document_issuance"
            && current_step_id.as_deref() == Some(submit_step_id)
            && last_history.is_some_and(|entry| {
                entry["step_id"].as_str() == Some(submit_step_id)
                    && entry["status"].as_str() == Some("entered")
                    && entry.get("completed_at").is_none()
            })
            && history.as_array().is_some_and(|entries| {
                entries.iter().any(|entry| {
                    entry["step_id"].as_str() == Some(sign_step_id)
                        && flow_result_success(&entry["result"])
                        && entry["completed_at"].as_str().is_some()
                })
            })
            && flow_result_success(&context["step_results"]["sign_sod"]["result"])
            && context["step_results"]["sign_sod"]["completed_at"]
                .as_str()
                .is_some()
            && context["application_id"].as_str() == Some(job.application_id.as_str())
            && projection["id"].as_str() == Some(job.id.as_str())
            && projection["organization_id"].as_str() == Some(principal.organization_id())
            && projection["flow_execution_id"].as_str() == Some(identity.selected_flow_instance_id)
            && projection["application_id"].as_str() == Some(job.application_id.as_str())
            && projection["issuer_did"].as_str() == job.issuer_did.as_deref()
            && projection["issuer_profile_id"].as_str()
                == signing_provenance
                    .and_then(|provenance| provenance["issuer_profile_id"].as_str())
            && projection["sod_sha256"].as_str() == Some(sod_sha256)
            && projection["sod_signature_verified"].as_bool() == Some(true)
            && projection["status"].as_str() == Some("SOD_SIGNED")
            && row
                .try_get::<Option<String>, _>("credential_template_id")?
                .as_deref()
                == Some(job.credential_template_id.as_str())
            && row
                .try_get::<Option<String>, _>("application_template_id")?
                .as_deref()
                == Some(job.application_template_id.as_str())
            && row
                .try_get::<Option<String>, _>("delivery_destination_profile_id")?
                .as_deref()
                == Some(job.delivery_destination_profile_id.as_str()))
    }

    async fn reserve_submission_on(
        connection: &mut PgConnection,
        principal: &PassportTenantPrincipal,
        job: &PassportJob,
        reservation: &PassportSubmissionReservation<'_>,
        batch: Option<&PassportBatchIdentity<'_>>,
    ) -> Result<Option<PassportJob>, sqlx::Error> {
        sqlx::query(
            "UPDATE issuance_service.physical_document_jobs
             SET submission_intent_id=$1, submission_intent_started_at=$2,
                 submission_intent_provider_profile_id=$10,
                 submission_intent_bureau_endpoint_sha256=$11,
                 submission_intent_signing_provenance=$12,
                 submission_batch_id=$14,
                 submission_batch_selected_flow_instance_id=$15,
                 submission_batch_selected_job_id=$16,
                 submission_batch_companion_job_id=$17,
                 sod_sha256=$3,
                 secure_artifact_ciphertext=COALESCE($4, secure_artifact_ciphertext),
                 updated_at=$2
             WHERE organization_id=$5 AND application_id=$6 AND status=$7
               AND sod_sha256 IS NOT DISTINCT FROM $8
               AND secure_artifact_ciphertext=$9
               AND id=$13
               AND bureau_job_id IS NULL AND submission_intent_id IS NULL
               AND submission_batch_id IS NULL
             RETURNING *",
        )
        .bind(reservation.intent_id)
        .bind(reservation.now)
        .bind(reservation.sod_sha256)
        .bind(reservation.signed_artifact_ciphertext)
        .bind(principal.organization_id())
        .bind(&job.application_id)
        .bind(&job.status)
        .bind(&job.sod_sha256)
        .bind(&job.secure_artifact_ciphertext)
        .bind(reservation.provider_profile_id)
        .bind(reservation.bureau_endpoint_sha256)
        .bind(reservation.signing_provenance)
        .bind(&job.id)
        .bind(batch.map(|value| value.batch_id))
        .bind(batch.map(|value| value.selected_flow_instance_id))
        .bind(batch.map(|value| value.selected_job_id))
        .bind(batch.map(|value| value.companion_job_id))
        .fetch_optional(connection)
        .await?
        .as_ref()
        .map(row_to_job)
        .transpose()
    }

    /// The simulator table is deliberately absent from production migrations.
    /// Calling this outside the inspected beta stack fails closed in storage.
    pub async fn beta_material_receipt(
        &self,
        principal: &PassportTenantPrincipal,
        source_job_id: &str,
    ) -> Result<Option<PassportBetaMaterialReceipt>, sqlx::Error> {
        let mut connection = self.pool.acquire().await?;
        Self::beta_material_receipt_on(&mut connection, principal, source_job_id).await
    }

    async fn beta_material_receipt_on(
        connection: &mut PgConnection,
        principal: &PassportTenantPrincipal,
        source_job_id: &str,
    ) -> Result<Option<PassportBetaMaterialReceipt>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT bureau_job_id, content_sha256, sod_der_sha256,
                    dsc_der_sha256, dsc_pem_wire_sha256, document_type,
                    created_at
             FROM issuance_service.passport_beta_bureau_jobs
             WHERE organization_id=$1 AND source_job_id=$2 FOR SHARE",
        )
        .bind(principal.organization_id())
        .bind(source_job_id)
        .fetch_optional(connection)
        .await?;
        row.map(|row| {
            Ok(PassportBetaMaterialReceipt {
                bureau_job_id: row.try_get("bureau_job_id")?,
                content_sha256: row.try_get("content_sha256")?,
                sod_der_sha256: row.try_get("sod_der_sha256")?,
                dsc_der_sha256: row.try_get("dsc_der_sha256")?,
                dsc_pem_wire_sha256: row.try_get("dsc_pem_wire_sha256")?,
                document_type: row.try_get("document_type")?,
                first_accepted_at: row.try_get("created_at")?,
            })
        })
        .transpose()
    }

    pub async fn update(
        &self,
        principal: &PassportTenantPrincipal,
        application_id: &str,
        expected_status: &str,
        patch: &PassportJobPatch,
        now: DateTime<Utc>,
    ) -> Result<Option<PassportJob>, sqlx::Error> {
        let mut connection = self.pool.acquire().await?;
        Self::update_on(
            &mut connection,
            principal,
            application_id,
            None,
            expected_status,
            patch,
            now,
        )
        .await
    }

    /// Persist both beta bureau IDs only when the first-accepted simulator
    /// receipts still match the exact material and pinned destination.
    pub async fn bind_batch_submissions(
        &self,
        principal: &PassportTenantPrincipal,
        jobs: [&PassportJob; 2],
        patches: [&PassportJobPatch; 2],
        bindings: [&PassportBetaBatchBinding<'_>; 2],
        destination: &PassportBetaBatchDestination<'_>,
        now: DateTime<Utc>,
    ) -> Result<Option<[PassportJob; 2]>, sqlx::Error> {
        let ids = patches.map(|patch| {
            patch
                .bureau_job_id
                .as_ref()
                .and_then(Option::as_deref)
                .and_then(|value| {
                    Uuid::parse_str(value)
                        .ok()
                        .filter(|id| id.to_string() == value)
                })
        });
        if jobs[0].id == jobs[1].id
            || jobs[0].application_id == jobs[1].application_id
            || jobs[0].submission_batch_id.is_none()
            || jobs[0].submission_batch_id != jobs[1].submission_batch_id
            || jobs.iter().any(|job| {
                job.submission_batch_selected_job_id.as_deref() != Some(jobs[0].id.as_str())
                    || job.submission_batch_companion_job_id.as_deref() != Some(jobs[1].id.as_str())
                    || job.submission_batch_selected_flow_instance_id.as_deref()
                        != Some(jobs[0].flow_execution_id.as_str())
            })
            || jobs
                .iter()
                .any(|job| job.organization_id != principal.organization_id())
            || destination.provider_profile_id.is_empty()
            || destination.endpoint_sha256.len() != 64
            || ids[0].is_none()
            || ids[1].is_none()
            || ids[0] == ids[1]
            || jobs.iter().zip(patches).zip(bindings).enumerate().any(
                |(index, ((job, patch), binding))| {
                    patch.status != PassportJobStatus::Submitted
                        || !patch.clear_submission_intent
                        || patch.sod_sha256.is_some()
                        || patch.secure_artifact_ciphertext.is_some()
                        || patch.expected_submission_intent_id != job.submission_intent_id
                        || job.submission_intent_id.is_none()
                        || job.submission_intent_provider_profile_id.as_deref()
                            != Some(destination.provider_profile_id)
                        || job.submission_intent_bureau_endpoint_sha256.as_deref()
                            != Some(destination.endpoint_sha256)
                        || patch.expected_sod_sha256.as_ref() != Some(&job.sod_sha256)
                        || patch.expected_secure_artifact_ciphertext.as_deref()
                            != Some(job.secure_artifact_ciphertext.as_str())
                        || patch.bureau_provider_profile_id.as_deref()
                            != Some(destination.provider_profile_id)
                        || patch.submission_batch_material_digests
                            != serde_json::to_value(binding.material_digests).ok()
                        || ids[index] != Some(binding.bureau_job_id)
                        || patch.submitted_at.is_none()
                },
            )
        {
            return Ok(None);
        }
        let mut transaction = self.pool.begin().await?;
        let mut bound: [Option<PassportJob>; 2] = [None, None];
        let order = if jobs[0].id <= jobs[1].id {
            [0, 1]
        } else {
            [1, 0]
        };
        for index in order {
            let receipt =
                Self::beta_material_receipt_on(&mut transaction, principal, &jobs[index].id)
                    .await?;
            let digests = bindings[index].material_digests;
            if !receipt.is_some_and(|receipt| {
                receipt.bureau_job_id == bindings[index].bureau_job_id
                    && receipt.content_sha256.as_deref() == Some(digests.content_sha256.as_slice())
                    && receipt.sod_der_sha256.as_deref() == digests.sod_der_sha256.as_deref()
                    && receipt.dsc_der_sha256.as_deref() == digests.dsc_der_sha256.as_deref()
                    && receipt.dsc_pem_wire_sha256.as_deref()
                        == Some(digests.dsc_pem_wire_sha256.as_slice())
                    && digests.sod_der_sha256.is_some()
                    && digests.dsc_der_sha256.is_some()
                    && receipt.sod_der_sha256.as_ref().is_some_and(|digest| {
                        jobs[index].sod_sha256.as_deref() == Some(hex::encode(digest).as_str())
                    })
                    && receipt.document_type.as_deref() == Some(jobs[index].document_type.as_str())
            }) {
                transaction.rollback().await?;
                return Ok(None);
            }
            let Some(job) = Self::update_on(
                &mut transaction,
                principal,
                &jobs[index].application_id,
                Some(&jobs[index].id),
                &jobs[index].status,
                patches[index],
                now,
            )
            .await?
            else {
                transaction.rollback().await?;
                return Ok(None);
            };
            bound[index] = Some(job);
        }
        transaction.commit().await?;
        Ok(Some([
            bound[0].take().expect("first bind succeeded"),
            bound[1].take().expect("second bind succeeded"),
        ]))
    }

    /// Finish a previously accepted pair when only one native job was bound.
    /// The bound row and both immutable simulator receipts are checked in the
    /// same transaction as the unresolved job's intent-token CAS.
    pub async fn bind_partial_batch_submission(
        &self,
        principal: &PassportTenantPrincipal,
        jobs: [&PassportJob; 2],
        patch: &PassportJobPatch,
        binding: &PassportBetaBatchBinding<'_>,
        destination: &PassportBetaBatchDestination<'_>,
        now: DateTime<Utc>,
    ) -> Result<Option<PassportJob>, sqlx::Error> {
        let [bound, unresolved] = jobs;
        let batch_id = bound.submission_batch_id;
        let parsed_patch_id = patch
            .bureau_job_id
            .as_ref()
            .and_then(Option::as_deref)
            .and_then(|id| {
                Uuid::parse_str(id)
                    .ok()
                    .filter(|parsed| parsed.to_string() == id)
            });
        if batch_id.is_none()
            || unresolved.submission_batch_id != batch_id
            || bound.id == unresolved.id
            || bound.application_id == unresolved.application_id
            || [bound, unresolved]
                .iter()
                .any(|job| job.organization_id != principal.organization_id())
            || bound.submission_batch_selected_job_id != unresolved.submission_batch_selected_job_id
            || bound.submission_batch_companion_job_id
                != unresolved.submission_batch_companion_job_id
            || bound.submission_batch_selected_flow_instance_id
                != unresolved.submission_batch_selected_flow_instance_id
            || bound.bureau_provider_profile_id.as_deref() != Some(destination.provider_profile_id)
            || bound.submission_batch_bureau_endpoint_sha256.as_deref()
                != Some(destination.endpoint_sha256)
            || bound.bureau_job_id.is_none()
            || bound.submission_intent_id.is_some()
            || unresolved.bureau_job_id.is_some()
            || unresolved.submission_intent_id.is_none()
            || unresolved.submission_intent_provider_profile_id.as_deref()
                != Some(destination.provider_profile_id)
            || unresolved
                .submission_intent_bureau_endpoint_sha256
                .as_deref()
                != Some(destination.endpoint_sha256)
            || patch.status != PassportJobStatus::Submitted
            || !patch.clear_submission_intent
            || patch.sod_sha256.is_some()
            || patch.secure_artifact_ciphertext.is_some()
            || patch.expected_submission_intent_id != unresolved.submission_intent_id
            || patch.expected_sod_sha256.as_ref() != Some(&unresolved.sod_sha256)
            || patch.expected_secure_artifact_ciphertext.as_deref()
                != Some(unresolved.secure_artifact_ciphertext.as_str())
            || patch.bureau_provider_profile_id.as_deref() != Some(destination.provider_profile_id)
            || patch.submission_batch_material_digests
                != serde_json::to_value(binding.material_digests).ok()
            || parsed_patch_id != Some(binding.bureau_job_id)
            || patch.submitted_at.is_none()
        {
            return Ok(None);
        }
        let bound_digests = bound
            .submission_batch_material_digests
            .clone()
            .and_then(|value| serde_json::from_value::<PassportBetaMaterialDigests>(value).ok());
        let Some(bound_digests) = bound_digests else {
            return Ok(None);
        };
        let mut transaction = self.pool.begin().await?;
        let live_bound = sqlx::query(
            "SELECT * FROM issuance_service.physical_document_jobs
             WHERE organization_id=$1 AND id=$2 AND submission_batch_id=$3 FOR SHARE",
        )
        .bind(principal.organization_id())
        .bind(&bound.id)
        .bind(batch_id)
        .fetch_optional(&mut *transaction)
        .await?
        .as_ref()
        .map(row_to_job)
        .transpose()?;
        if !live_bound.is_some_and(|live| {
            live.application_id == bound.application_id
                && live.flow_execution_id == bound.flow_execution_id
                && live.country_code == bound.country_code
                && live.document_type == bound.document_type
                && live.issuer_did == bound.issuer_did
                && live.bureau_job_id == bound.bureau_job_id
                && live.bureau_provider_profile_id == bound.bureau_provider_profile_id
                && live.submission_batch_selected_job_id == bound.submission_batch_selected_job_id
                && live.submission_batch_companion_job_id == bound.submission_batch_companion_job_id
                && live.submission_batch_selected_flow_instance_id
                    == bound.submission_batch_selected_flow_instance_id
                && live.submission_batch_bureau_endpoint_sha256
                    == bound.submission_batch_bureau_endpoint_sha256
                && live.submission_batch_signing_provenance
                    == bound.submission_batch_signing_provenance
                && live.submission_batch_material_digests == bound.submission_batch_material_digests
                && live.sod_sha256 == bound.sod_sha256
                && live.submission_intent_id.is_none()
        }) {
            transaction.rollback().await?;
            return Ok(None);
        }
        let live_unresolved = sqlx::query(
            "SELECT * FROM issuance_service.physical_document_jobs
             WHERE organization_id=$1 AND id=$2 AND submission_batch_id=$3 FOR UPDATE",
        )
        .bind(principal.organization_id())
        .bind(&unresolved.id)
        .bind(batch_id)
        .fetch_optional(&mut *transaction)
        .await?
        .as_ref()
        .map(row_to_job)
        .transpose()?;
        if !live_unresolved.is_some_and(|live| {
            live.application_id == unresolved.application_id
                && live.flow_execution_id == unresolved.flow_execution_id
                && live.country_code == unresolved.country_code
                && live.document_type == unresolved.document_type
                && live.issuer_did == unresolved.issuer_did
                && live.status == unresolved.status
                && live.sod_sha256 == unresolved.sod_sha256
                && live.secure_artifact_ciphertext == unresolved.secure_artifact_ciphertext
                && live.submission_intent_id == unresolved.submission_intent_id
                && live.submission_intent_provider_profile_id
                    == unresolved.submission_intent_provider_profile_id
                && live.submission_intent_bureau_endpoint_sha256
                    == unresolved.submission_intent_bureau_endpoint_sha256
                && live.submission_intent_signing_provenance
                    == unresolved.submission_intent_signing_provenance
                && live.submission_batch_selected_job_id
                    == unresolved.submission_batch_selected_job_id
                && live.submission_batch_companion_job_id
                    == unresolved.submission_batch_companion_job_id
                && live.submission_batch_selected_flow_instance_id
                    == unresolved.submission_batch_selected_flow_instance_id
                && live.bureau_job_id.is_none()
                && live.bureau_provider_profile_id.is_none()
        }) {
            transaction.rollback().await?;
            return Ok(None);
        }
        let bound_receipt =
            Self::beta_material_receipt_on(&mut transaction, principal, &bound.id).await?;
        let pending_receipt =
            Self::beta_material_receipt_on(&mut transaction, principal, &unresolved.id).await?;
        if !bound_receipt.is_some_and(|receipt| {
            bound.bureau_job_id.as_deref() == Some(receipt.bureau_job_id.to_string().as_str())
                && beta_receipt_matches_job(&receipt, &bound_digests, bound)
        }) || !pending_receipt.is_some_and(|receipt| {
            receipt.bureau_job_id == binding.bureau_job_id
                && beta_receipt_matches_job(&receipt, binding.material_digests, unresolved)
        }) || bound.bureau_job_id.as_deref() == Some(binding.bureau_job_id.to_string().as_str())
        {
            transaction.rollback().await?;
            return Ok(None);
        }
        let result = Self::update_on(
            &mut transaction,
            principal,
            &unresolved.application_id,
            Some(&unresolved.id),
            &unresolved.status,
            patch,
            now,
        )
        .await?;
        if result.is_none() {
            transaction.rollback().await?;
            return Ok(None);
        }
        transaction.commit().await?;
        Ok(result)
    }

    async fn update_on(
        connection: &mut PgConnection,
        principal: &PassportTenantPrincipal,
        application_id: &str,
        expected_job_id: Option<&str>,
        expected_status: &str,
        patch: &PassportJobPatch,
        now: DateTime<Utc>,
    ) -> Result<Option<PassportJob>, sqlx::Error> {
        let mut query = QueryBuilder::<Postgres>::new(
            "UPDATE issuance_service.physical_document_jobs SET status = ",
        );
        query.push_bind(patch.status.as_str());
        query.push(", updated_at = ").push_bind(now);
        macro_rules! nullable_change {
            ($field:ident) => {
                if let Some(value) = &patch.$field {
                    query
                        .push(concat!(", ", stringify!($field), " = "))
                        .push_bind(value);
                }
            };
        }
        nullable_change!(sod_sha256);
        nullable_change!(bureau_job_id);
        if let Some(value) = &patch.bureau_provider_profile_id {
            query
                .push(", bureau_provider_profile_id = ")
                .push_bind(value);
        }
        if let Some(value) = &patch.submission_batch_material_digests {
            query
                .push(", submission_batch_material_digests = ")
                .push_bind(value);
        }
        nullable_change!(tracking_number);
        nullable_change!(quality_result);
        nullable_change!(error_code);
        nullable_change!(error_message);
        if let Some(value) = patch.submitted_at {
            query.push(", submitted_at = ").push_bind(value);
        }
        if let Some(value) = patch.completed_at {
            query.push(", completed_at = ").push_bind(value);
        }
        if let Some(value) = &patch.secure_artifact_ciphertext {
            query
                .push(", secure_artifact_ciphertext = ")
                .push_bind(value);
        }
        if patch.clear_submission_intent {
            query.push(", submission_batch_signing_provenance = CASE WHEN submission_batch_id IS NOT NULL THEN submission_intent_signing_provenance ELSE NULL END, submission_batch_bureau_endpoint_sha256 = CASE WHEN submission_batch_id IS NOT NULL THEN submission_intent_bureau_endpoint_sha256 ELSE NULL END, submission_intent_id = NULL, submission_intent_started_at = NULL, submission_intent_provider_profile_id = NULL, submission_intent_bureau_endpoint_sha256 = NULL, submission_intent_signing_provenance = NULL");
        }
        query
            .push(" WHERE organization_id = ")
            .push_bind(principal.organization_id())
            .push(" AND application_id = ")
            .push_bind(application_id)
            .push(" AND status = ")
            .push_bind(expected_status);
        if let Some(job_id) = expected_job_id {
            query.push(" AND id = ").push_bind(job_id);
        }
        if let Some(expected) = &patch.expected_sod_sha256 {
            query
                .push(" AND sod_sha256 IS NOT DISTINCT FROM ")
                .push_bind(expected);
        }
        if let Some(expected) = &patch.expected_secure_artifact_ciphertext {
            query
                .push(" AND secure_artifact_ciphertext = ")
                .push_bind(expected);
        }
        if let Some(intent_id) = patch.expected_submission_intent_id {
            query
                .push(" AND submission_intent_id = ")
                .push_bind(intent_id);
        } else {
            query.push(" AND submission_intent_id IS NULL");
        }
        if patch.bureau_job_id.is_some()
            || matches!(
                patch.status,
                PassportJobStatus::DataGenerated | PassportJobStatus::SodSigned
            )
        {
            query.push(" AND bureau_job_id IS NULL");
        }
        if patch.bureau_provider_profile_id.is_some() {
            query.push(" AND bureau_provider_profile_id IS NULL");
        }
        query.push(" RETURNING *");
        query
            .build()
            .fetch_optional(connection)
            .await?
            .as_ref()
            .map(row_to_job)
            .transpose()
    }

    /// Read the stable selected-first pair for a private beta batch retry.
    pub async fn beta_batch_jobs(
        &self,
        principal: &PassportTenantPrincipal,
        batch_id: Uuid,
    ) -> Result<Option<[PassportJob; 2]>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT job.* FROM issuance_service.physical_document_jobs AS job
             JOIN issuance_service.passport_beta_batch_intents AS batch
               ON batch.batch_id=job.submission_batch_id
              AND batch.organization_id=job.organization_id
              AND batch.selected_flow_instance_id=job.submission_batch_selected_flow_instance_id
              AND batch.selected_job_id=job.submission_batch_selected_job_id
              AND batch.companion_job_id=job.submission_batch_companion_job_id
             WHERE job.organization_id=$1 AND batch.batch_id=$2 LIMIT 3",
        )
        .bind(principal.organization_id())
        .bind(batch_id)
        .fetch_all(&self.pool)
        .await?;
        if rows.len() != 2 {
            return Ok(None);
        }
        let mut jobs = rows.iter().map(row_to_job).collect::<Result<Vec<_>, _>>()?;
        let selected = jobs
            .iter()
            .position(|job| {
                job.submission_batch_selected_job_id.as_deref() == Some(job.id.as_str())
            })
            .ok_or_else(|| sqlx::Error::Protocol("beta batch selected job is missing".into()))?;
        if selected != 0 {
            jobs.swap(0, 1);
        }
        if jobs.iter().any(|job| {
            job.submission_batch_id != Some(batch_id)
                || job.submission_batch_selected_job_id.as_deref() != Some(jobs[0].id.as_str())
                || job.submission_batch_companion_job_id.as_deref() != Some(jobs[1].id.as_str())
                || job.submission_batch_selected_flow_instance_id.as_deref()
                    != Some(jobs[0].flow_execution_id.as_str())
        }) {
            return Ok(None);
        }
        Ok(Some([jobs.remove(0), jobs.remove(0)]))
    }

    pub async fn fill_missing_bureau_metadata(
        &self,
        principal: &PassportTenantPrincipal,
        application_id: &str,
        expected_status: &str,
        tracking_number: Option<&str>,
        error_message: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<Option<PassportJob>, sqlx::Error> {
        sqlx::query(
            "UPDATE issuance_service.physical_document_jobs
             SET tracking_number = CASE WHEN NULLIF(BTRIM(tracking_number), '') IS NULL
                 THEN CASE WHEN NULLIF(BTRIM($4::text), '') IS NOT NULL THEN $4 ELSE tracking_number END
                 ELSE tracking_number END,
                 error_message = CASE WHEN NULLIF(BTRIM(error_message), '') IS NULL
                 THEN CASE WHEN NULLIF(BTRIM($5::text), '') IS NOT NULL THEN $5 ELSE error_message END
                 ELSE error_message END,
                 updated_at = $6
             WHERE organization_id = $1 AND application_id = $2 AND status = $3
                 AND ((NULLIF(BTRIM(tracking_number), '') IS NULL
                       AND NULLIF(BTRIM($4::text), '') IS NOT NULL)
                   OR (NULLIF(BTRIM(error_message), '') IS NULL
                       AND NULLIF(BTRIM($5::text), '') IS NOT NULL))
             RETURNING *",
        )
        .bind(principal.organization_id())
        .bind(application_id)
        .bind(expected_status)
        .bind(tracking_number)
        .bind(error_message)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?
        .as_ref()
        .map(row_to_job)
        .transpose()
    }

    /// Resolve a tenant only from a previously authenticated provider profile
    /// and the bureau job ID covered by that provider's raw-body MAC. Callers
    /// must verify that MAC before invoking this method.
    pub async fn resolve_provider_callback_tenant(
        &self,
        provider_profile_id: &str,
        bureau_job_id: &str,
    ) -> Result<Option<String>, PassportWebhookRepositoryError> {
        if provider_profile_id.is_empty()
            || provider_profile_id.len() > 128
            || provider_profile_id.trim() != provider_profile_id
            || bureau_job_id.is_empty()
            || bureau_job_id.len() > 255
        {
            return Err(PassportWebhookRepositoryError::InvalidProviderBinding);
        }
        let matches = sqlx::query_scalar::<_, String>(
            "SELECT organization_id FROM issuance_service.physical_document_jobs
             WHERE bureau_provider_profile_id = $1 AND bureau_job_id = $2 LIMIT 2",
        )
        .bind(provider_profile_id)
        .bind(bureau_job_id)
        .fetch_all(&self.pool)
        .await?;
        match matches.as_slice() {
            [] => Ok(None),
            [organization_id] if !organization_id.trim().is_empty() => {
                Ok(Some(organization_id.clone()))
            }
            [_] => Err(PassportWebhookRepositoryError::InvalidProviderBinding),
            _ => Err(PassportWebhookRepositoryError::AmbiguousBureauJob),
        }
    }

    pub async fn apply_verified_webhook(
        &self,
        event: &VerifiedWebhookEvent,
        now: DateTime<Utc>,
    ) -> Result<Option<PassportJob>, PassportWebhookRepositoryError> {
        let mut transaction = self.pool.begin().await?;
        let matches = sqlx::query(
            "SELECT * FROM issuance_service.physical_document_jobs
             WHERE bureau_job_id = $1 AND organization_id = $2
               AND ($3::text IS NULL OR bureau_provider_profile_id = $3)
             LIMIT 2 FOR UPDATE",
        )
        .bind(event.bureau_job_id())
        .bind(event.organization_id())
        .bind(event.provider_profile_id())
        .fetch_all(&mut *transaction)
        .await?;
        if matches.len() > 1 {
            return Err(PassportWebhookRepositoryError::AmbiguousBureauJob);
        }
        let Some(matched) = matches.first() else {
            return Ok(None);
        };
        let current_status: &str = matched.try_get("status")?;
        let current_tracking: Option<String> = matched.try_get("tracking_number")?;
        let incoming_status = event.status().issuance_status();
        let metadata = if current_status == incoming_status
            && !matches!(current_status, "ACTIVE" | "FAILED" | "CANCELLED")
        {
            let current_error: Option<String> = matched.try_get("error_message")?;
            fill_missing_bureau_metadata(
                current_tracking.as_deref(),
                current_error.as_deref(),
                event.tracking_number(),
                event.error_message(),
            )
        } else if should_apply_bureau_status(current_status, incoming_status) {
            Some((
                event
                    .tracking_number()
                    .filter(|number| !number.trim().is_empty())
                    .map(str::to_owned)
                    .or(current_tracking),
                event.error_message().map(str::to_owned),
            ))
        } else {
            None
        };
        let Some((tracking_number, error_message)) = metadata else {
            let unchanged = row_to_job(matched)?;
            transaction.commit().await?;
            return Ok(Some(unchanged));
        };
        let id: &str = matched.try_get("id")?;
        let organization_id: &str = matched.try_get("organization_id")?;
        let updated = sqlx::query(
            "UPDATE issuance_service.physical_document_jobs
             SET status = $1, tracking_number = $2, error_message = $3, updated_at = $4
             WHERE id = $5 AND organization_id = $6 AND bureau_job_id = $7
               AND ($8::text IS NULL OR bureau_provider_profile_id = $8)
             RETURNING *",
        )
        .bind(incoming_status)
        .bind(tracking_number)
        .bind(error_message)
        .bind(now)
        .bind(id)
        .bind(organization_id)
        .bind(event.bureau_job_id())
        .bind(event.provider_profile_id())
        .fetch_optional(&mut *transaction)
        .await?;
        transaction.commit().await?;
        updated
            .as_ref()
            .map(row_to_job)
            .transpose()
            .map_err(Into::into)
    }
}

pub(crate) fn should_apply_bureau_status(current: &str, incoming: &str) -> bool {
    if matches!(current, "ACTIVE" | "FAILED" | "CANCELLED") {
        return false;
    }
    if matches!(incoming, "FAILED" | "CANCELLED") {
        return true;
    }
    let rank = |status| match status {
        "SUBMITTED" => Some(1),
        "IN_PRODUCTION" => Some(2),
        "QUALITY_CHECK" => Some(3),
        "READY_FOR_ACTIVATION" => Some(4),
        _ => None,
    };
    match (rank(current), rank(incoming)) {
        (Some(current), Some(incoming)) => incoming > current,
        _ => true,
    }
}

pub(crate) fn fill_missing_bureau_metadata(
    current_tracking: Option<&str>,
    current_error: Option<&str>,
    incoming_tracking: Option<&str>,
    incoming_error: Option<&str>,
) -> Option<(Option<String>, Option<String>)> {
    let tracking_fill = if current_tracking.is_none_or(|value| value.trim().is_empty()) {
        incoming_tracking.filter(|value| !value.trim().is_empty())
    } else {
        None
    };
    let error_fill = if current_error.is_none_or(|value| value.trim().is_empty()) {
        incoming_error.filter(|value| !value.trim().is_empty())
    } else {
        None
    };
    if tracking_fill.is_none() && error_fill.is_none() {
        return None;
    }
    Some((
        tracking_fill.or(current_tracking).map(str::to_owned),
        error_fill.or(current_error).map(str::to_owned),
    ))
}

fn flow_result_success(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|result| result.trim().eq_ignore_ascii_case("success"))
}

fn beta_receipt_matches_job(
    receipt: &PassportBetaMaterialReceipt,
    digests: &PassportBetaMaterialDigests,
    job: &PassportJob,
) -> bool {
    receipt.content_sha256.as_deref() == Some(digests.content_sha256.as_slice())
        && digests.sod_der_sha256.is_some()
        && receipt.sod_der_sha256.as_deref() == digests.sod_der_sha256.as_deref()
        && digests.dsc_der_sha256.is_some()
        && receipt.dsc_der_sha256.as_deref() == digests.dsc_der_sha256.as_deref()
        && receipt.dsc_pem_wire_sha256.as_deref() == Some(digests.dsc_pem_wire_sha256.as_slice())
        && receipt
            .sod_der_sha256
            .as_ref()
            .is_some_and(|digest| job.sod_sha256.as_deref() == Some(hex::encode(digest).as_str()))
        && receipt.document_type.as_deref() == Some(job.document_type.as_str())
}

fn row_to_job(row: &PgRow) -> Result<PassportJob, sqlx::Error> {
    Ok(PassportJob {
        id: row.try_get("id")?,
        organization_id: row.try_get("organization_id")?,
        flow_execution_id: row.try_get("flow_execution_id")?,
        application_id: row.try_get("application_id")?,
        application_template_id: row.try_get("application_template_id")?,
        credential_template_id: row.try_get("credential_template_id")?,
        revocation_profile_id: row.try_get("revocation_profile_id")?,
        delivery_destination_profile_id: row.try_get("delivery_destination_profile_id")?,
        document_type: row.try_get("document_type")?,
        country_code: row.try_get("country_code")?,
        issuer_did: row.try_get("issuer_did")?,
        secure_artifact_ciphertext: row.try_get("secure_artifact_ciphertext")?,
        secure_artifact_reference: row.try_get("secure_artifact_reference")?,
        sod_sha256: row.try_get("sod_sha256")?,
        bureau_job_id: row.try_get("bureau_job_id")?,
        bureau_provider_profile_id: row.try_get("bureau_provider_profile_id")?,
        submission_intent_id: row.try_get("submission_intent_id")?,
        submission_intent_started_at: row.try_get("submission_intent_started_at")?,
        submission_intent_provider_profile_id: row
            .try_get("submission_intent_provider_profile_id")?,
        submission_intent_bureau_endpoint_sha256: row
            .try_get("submission_intent_bureau_endpoint_sha256")?,
        submission_intent_signing_provenance: row
            .try_get("submission_intent_signing_provenance")?,
        submission_batch_id: row.try_get("submission_batch_id")?,
        submission_batch_selected_flow_instance_id: row
            .try_get("submission_batch_selected_flow_instance_id")?,
        submission_batch_selected_job_id: row.try_get("submission_batch_selected_job_id")?,
        submission_batch_companion_job_id: row.try_get("submission_batch_companion_job_id")?,
        submission_batch_signing_provenance: row.try_get("submission_batch_signing_provenance")?,
        submission_batch_bureau_endpoint_sha256: row
            .try_get("submission_batch_bureau_endpoint_sha256")?,
        submission_batch_material_digests: row.try_get("submission_batch_material_digests")?,
        tracking_number: row.try_get("tracking_number")?,
        status: row.try_get("status")?,
        quality_result: row.try_get("quality_result")?,
        error_code: row.try_get("error_code")?,
        error_message: row.try_get("error_message")?,
        submitted_at: row.try_get("submitted_at")?,
        completed_at: row.try_get("completed_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

#[cfg(test)]
mod webhook_state_tests {
    use super::{fill_missing_bureau_metadata, should_apply_bureau_status};
    use serde_json::Value;

    #[test]
    fn stale_or_terminal_callback_never_rewinds_a_document() {
        let contract: Value = serde_json::from_str(include_str!(
            "../../../../contracts/passport-webhook-progress-behavior.json"
        ))
        .unwrap();
        assert_eq!(contract["schema_version"], 1);
        assert_eq!(
            contract["sources"],
            serde_json::json!(["verified_callback", "authenticated_poll"])
        );
        for (field, expected) in [
            ("accepted_transitions", true),
            ("ignored_transitions", false),
        ] {
            for pair in contract[field].as_array().unwrap() {
                assert_eq!(
                    should_apply_bureau_status(
                        pair[0].as_str().unwrap(),
                        pair[1].as_str().unwrap()
                    ),
                    expected,
                    "transition: {pair}"
                );
            }
        }
    }

    #[test]
    fn same_rank_metadata_only_fills_blank_fields() {
        assert_eq!(
            fill_missing_bureau_metadata(Some("tracking-a"), None, None, None),
            None
        );
        assert_eq!(
            fill_missing_bureau_metadata(Some("tracking-a"), None, Some("tracking-b"), None),
            None
        );
        assert_eq!(
            fill_missing_bureau_metadata(
                None,
                Some("error-a"),
                Some("tracking-a"),
                Some("error-b")
            ),
            Some((Some("tracking-a".into()), Some("error-a".into())))
        );
    }
}
