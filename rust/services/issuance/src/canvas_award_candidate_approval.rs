use std::{fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    canvas_award_candidate::{canvas_auto_approval_ready, CanvasAwardCandidateMaterializationPlan},
    canvas_award_candidate_service::{
        CanvasAwardCandidateApprovalError, CanvasAwardCandidateApprover,
    },
    canvas_issuance_guard::{
        credential_snapshot, evaluate_canvas_approval_snapshot, resolved_issuer_matches,
        CanvasGuardConfig, CanvasGuardSnapshot,
    },
    canvas_lti_bootstrap::CanvasLtiBootstrapApplication,
    canvas_lti_experience::CanvasLtiExperienceSessionContext,
    canvas_lti_launch::CanvasLtiClock,
    credential::{
        remote_credential_format, CredentialIssuanceError, CredentialTransaction,
        CredentialTransactionStatus, IssuerContext, IssuerContextResolver,
    },
};

const REDACTED: &str = "[REDACTED]";
pub const CANVAS_MANAGEMENT_REVIEWER_ID: &str = "canvas-integration-management-api";
pub const DEFAULT_CANVAS_MANAGEMENT_REVIEW_NOTES: &str =
    "Approved through Canvas integration operations";

#[derive(Clone, PartialEq)]
pub struct CanvasAwardApprovalSnapshot {
    pub application: Map<String, Value>,
    pub application_template: Map<String, Value>,
    pub binding: Map<String, Value>,
    pub identity_still_linked: bool,
}

impl fmt::Debug for CanvasAwardApprovalSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasAwardApprovalSnapshot")
            .field("application", &REDACTED)
            .field("application_template", &REDACTED)
            .field("binding", &REDACTED)
            .field("identity_still_linked", &self.identity_still_linked)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CanvasAwardApprovalSeed {
    pub transaction_id: String,
    pub pre_authorized_code: String,
}

impl fmt::Debug for CanvasAwardApprovalSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasAwardApprovalSeed")
            .field("transaction_id", &self.transaction_id)
            .field("pre_authorized_code", &REDACTED)
            .finish()
    }
}

#[async_trait]
pub trait CanvasAwardApprovalRepository: Send + Sync {
    async fn load_approval_snapshot(
        &self,
        context: &CanvasLtiExperienceSessionContext,
        application: &CanvasLtiBootstrapApplication,
        plan: &CanvasAwardCandidateMaterializationPlan,
    ) -> Result<Option<CanvasAwardApprovalSnapshot>, CanvasAwardCandidateApprovalError>;

    async fn reserve_issuance(
        &self,
        transaction: &CredentialTransaction,
        context: &CanvasLtiExperienceSessionContext,
        plan: &CanvasAwardCandidateMaterializationPlan,
        snapshot: &CanvasAwardApprovalSnapshot,
    ) -> Result<(), CanvasAwardCandidateApprovalError>;
}

pub trait CanvasAwardApprovalSeedGenerator: Send + Sync {
    fn generate(&self) -> CanvasAwardApprovalSeed;
}

#[derive(Clone, PartialEq)]
pub struct CanvasApplicationApprovalSnapshot {
    pub application: Map<String, Value>,
    pub application_template: Map<String, Value>,
    pub platform: Map<String, Value>,
    pub binding: Map<String, Value>,
}

impl fmt::Debug for CanvasApplicationApprovalSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasApplicationApprovalSnapshot")
            .field("application", &REDACTED)
            .field("application_template", &REDACTED)
            .field("platform", &REDACTED)
            .field("binding", &REDACTED)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanvasApplicationApprovalResult {
    pub application_id: String,
    pub issuance_transaction_id: String,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CanvasApplicationApprovalError {
    #[error("Canvas application not found")]
    NotFound,
    #[error("Portable Canvas integration is not enabled for this organization")]
    RolloutDisabled,
    #[error("Canvas application cannot be approved in its current status")]
    InvalidStatus,
    #[error("Canvas application is not ready for approval")]
    NotReady,
    #[error("Canvas application approval is temporarily unavailable")]
    Unavailable,
}

#[async_trait]
pub trait CanvasApplicationApprovalRepository: Send + Sync {
    async fn load_application_approval_snapshot(
        &self,
        organization_id: &str,
        application_id: &str,
    ) -> Result<Option<CanvasApplicationApprovalSnapshot>, CanvasApplicationApprovalError>;

    async fn reserve_application_issuance(
        &self,
        transaction: &CredentialTransaction,
        snapshot: &CanvasApplicationApprovalSnapshot,
        reviewer_id: &str,
        review_notes: &str,
        reviewed_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<String, CanvasApplicationApprovalError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SecureCanvasAwardApprovalSeedGenerator;

impl CanvasAwardApprovalSeedGenerator for SecureCanvasAwardApprovalSeedGenerator {
    fn generate(&self) -> CanvasAwardApprovalSeed {
        let mut capability = [0_u8; 32];
        rand::rng().fill_bytes(&mut capability);
        CanvasAwardApprovalSeed {
            transaction_id: uuid::Uuid::new_v4().to_string(),
            pre_authorized_code: URL_SAFE_NO_PAD.encode(capability),
        }
    }
}

#[derive(Clone)]
pub struct CanvasAwardCandidateApprovalService {
    repository: Arc<dyn CanvasAwardApprovalRepository>,
    issuer_resolver: Arc<dyn IssuerContextResolver>,
    seeds: Arc<dyn CanvasAwardApprovalSeedGenerator>,
    clock: Arc<dyn CanvasLtiClock>,
    readiness_max_age: Duration,
}

impl std::fmt::Debug for CanvasAwardCandidateApprovalService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasAwardCandidateApprovalService")
            .field("readiness_max_age", &self.readiness_max_age)
            .finish_non_exhaustive()
    }
}

impl CanvasAwardCandidateApprovalService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn CanvasAwardApprovalRepository>,
        issuer_resolver: Arc<dyn IssuerContextResolver>,
        seeds: Arc<dyn CanvasAwardApprovalSeedGenerator>,
        clock: Arc<dyn CanvasLtiClock>,
        readiness_max_age: Duration,
    ) -> Self {
        Self {
            repository,
            issuer_resolver,
            seeds,
            clock,
            readiness_max_age,
        }
    }

    async fn approve(
        &self,
        context: &CanvasLtiExperienceSessionContext,
        application: &CanvasLtiBootstrapApplication,
        plan: &CanvasAwardCandidateMaterializationPlan,
        policy_allowed: bool,
    ) -> Result<(), CanvasAwardCandidateApprovalError> {
        if !policy_allowed {
            return Ok(());
        }
        let Some(snapshot) = self
            .repository
            .load_approval_snapshot(context, application, plan)
            .await?
        else {
            return Err(CanvasAwardCandidateApprovalError::ReadinessDrift);
        };
        let Some(mut transaction) = plan_canvas_award_approval(
            context,
            application,
            plan,
            &snapshot,
            &self.seeds.generate(),
            self.clock.now(),
            self.readiness_max_age,
        ) else {
            return Err(CanvasAwardCandidateApprovalError::ReadinessDrift);
        };
        resolve_and_attach_canvas_issuer(
            self.issuer_resolver.as_ref(),
            &snapshot.binding,
            &mut transaction,
        )
        .await?;
        self.repository
            .reserve_issuance(&transaction, context, plan, &snapshot)
            .await
    }
}

#[derive(Clone)]
pub struct CanvasApplicationApprovalService {
    repository: Arc<dyn CanvasApplicationApprovalRepository>,
    issuer_resolver: Arc<dyn IssuerContextResolver>,
    seeds: Arc<dyn CanvasAwardApprovalSeedGenerator>,
    clock: Arc<dyn CanvasLtiClock>,
    guard_config: CanvasGuardConfig,
}

impl fmt::Debug for CanvasApplicationApprovalService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasApplicationApprovalService")
            .field("guard_config", &self.guard_config)
            .finish_non_exhaustive()
    }
}

impl CanvasApplicationApprovalService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn CanvasApplicationApprovalRepository>,
        issuer_resolver: Arc<dyn IssuerContextResolver>,
        seeds: Arc<dyn CanvasAwardApprovalSeedGenerator>,
        clock: Arc<dyn CanvasLtiClock>,
        guard_config: CanvasGuardConfig,
    ) -> Self {
        Self {
            repository,
            issuer_resolver,
            seeds,
            clock,
            guard_config,
        }
    }

    pub async fn approve(
        &self,
        organization_id: &str,
        application_id: &str,
        review_notes: Option<&str>,
    ) -> Result<CanvasApplicationApprovalResult, CanvasApplicationApprovalError> {
        let snapshot = self
            .repository
            .load_application_approval_snapshot(organization_id, application_id)
            .await?
            .ok_or(CanvasApplicationApprovalError::NotFound)?;
        let guard = CanvasGuardSnapshot {
            application: Value::Object(snapshot.application.clone()),
            application_template: Value::Object(snapshot.application_template.clone()),
            platform: Value::Object(snapshot.platform.clone()),
            binding: Value::Object(snapshot.binding.clone()),
            evidence_facts: Vec::new(),
            policy_set: None,
        };
        let now = self.clock.now();
        evaluate_canvas_approval_snapshot(
            organization_id,
            application_id,
            &guard,
            &self.guard_config,
            now,
        )
        .map_err(map_manual_guard_error)?;
        let mut transaction = plan_canvas_approval_transaction(
            &snapshot.application,
            &snapshot.binding,
            &self.seeds.generate(),
            now,
        )
        .ok_or(CanvasApplicationApprovalError::NotReady)?;
        // The Python boundary intentionally collapses every KMS/provider
        // failure to one non-sensitive readiness conflict.
        resolve_and_attach_canvas_issuer(
            self.issuer_resolver.as_ref(),
            &snapshot.binding,
            &mut transaction,
        )
        .await
        .map_err(|_| CanvasApplicationApprovalError::NotReady)?;
        let issuance_transaction_id = self
            .repository
            .reserve_application_issuance(
                &transaction,
                &snapshot,
                CANVAS_MANAGEMENT_REVIEWER_ID,
                match review_notes {
                    None | Some("") => DEFAULT_CANVAS_MANAGEMENT_REVIEW_NOTES,
                    Some(notes) => notes,
                },
                now,
            )
            .await?;
        Ok(CanvasApplicationApprovalResult {
            application_id: application_id.to_owned(),
            issuance_transaction_id,
        })
    }
}

#[async_trait]
impl CanvasAwardCandidateApprover for CanvasAwardCandidateApprovalService {
    async fn approve_if_ready(
        &self,
        context: &CanvasLtiExperienceSessionContext,
        application: &CanvasLtiBootstrapApplication,
        plan: &CanvasAwardCandidateMaterializationPlan,
        policy_allowed: bool,
    ) -> Result<(), CanvasAwardCandidateApprovalError> {
        self.approve(context, application, plan, policy_allowed)
            .await
    }
}

#[allow(clippy::too_many_arguments)]
pub fn plan_canvas_award_approval(
    context: &CanvasLtiExperienceSessionContext,
    application: &CanvasLtiBootstrapApplication,
    plan: &CanvasAwardCandidateMaterializationPlan,
    snapshot: &CanvasAwardApprovalSnapshot,
    seed: &CanvasAwardApprovalSeed,
    now: chrono::DateTime<chrono::Utc>,
    readiness_max_age: Duration,
) -> Option<CredentialTransaction> {
    let current = &snapshot.application;
    let template = &snapshot.application_template;
    let binding = &snapshot.binding;
    let binding_id = context.canvas_program_binding_id.as_deref()?;
    if text(current.get("id")) != application.id
        || text(current.get("organization_id")) != application.organization_id
        || !text(current.get("status")).eq_ignore_ascii_case("pending")
        || text(current.get("application_template_id")) != application.application_template_id
        || text(template.get("id")) != application.application_template_id
        || text(template.get("organization_id")) != application.organization_id
        || !text(template.get("status")).eq_ignore_ascii_case("active")
        || text(binding.get("id")) != binding_id
        || text(binding.get("organization_id")) != application.organization_id
        || text(binding.get("platform_id")) != context.canvas_platform_id
        || text(binding.get("application_template_id")) != application.application_template_id
        || text(template.get("credential_template_id"))
            != text(binding.get("credential_template_id"))
        || (plan.canvas_user_id.is_some() && !snapshot.identity_still_linked)
        || !canvas_auto_approval_ready(binding, now, readiness_max_age)
    {
        return None;
    }
    plan_canvas_approval_transaction(current, binding, seed, now)
}

/// Build the canonical pending issuance transaction from the exact persisted
/// application and binding snapshot. Both automatic candidate materialization
/// and administrator approval use this one transaction-planning kernel.
pub fn plan_canvas_approval_transaction(
    application: &Map<String, Value>,
    binding: &Map<String, Value>,
    seed: &CanvasAwardApprovalSeed,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<CredentialTransaction> {
    let organization_id = text(application.get("organization_id"));
    let application_id = text(application.get("id"));
    if organization_id.is_empty()
        || application_id.is_empty()
        || !text(application.get("status")).eq_ignore_ascii_case("pending")
    {
        return None;
    }
    let credential = credential_snapshot(binding, &organization_id).ok()?;
    let credential_type = text(credential.get("credential_type"));
    let credential_payload_format = text(credential.get("credential_payload_format"));
    let revocation_profile_id = optional_text(credential.get("revocation_profile_id"));
    let issuer_did = optional_text(credential.get("issuer_did"));
    let issuer_algorithm = optional_text(credential.get("issuer_algorithm"));
    if credential_type.is_empty()
        || credential_payload_format.is_empty()
        || revocation_profile_id.is_none()
        || issuer_did.is_none()
        || issuer_algorithm.is_none()
    {
        return None;
    }
    remote_credential_format(&credential_payload_format).ok()?;
    let mut claims = application
        .get("form_data")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if let Some(vct) = optional_text(credential.get("vct")) {
        claims.insert("_vct".to_owned(), Value::String(vct));
    }
    let validity = credential.get("validity_rules").and_then(Value::as_object);
    Some(CredentialTransaction {
        id: seed.transaction_id.clone(),
        organization_id,
        credential_template_id: text(binding.get("credential_template_id")),
        revocation_profile_id,
        renewal_of_credential_id: None,
        applicant_id: optional_text(application.get("applicant_identifier")),
        application_id: Some(application_id),
        subject_did: None,
        idempotency_key_hash: None,
        idempotency_request_hash: None,
        status: CredentialTransactionStatus::Pending,
        pre_authorized_code: seed.pre_authorized_code.clone(),
        nonce: None,
        claims,
        credential_type: Some(credential_type),
        selective_disclosure_claims: string_array(credential.get("selective_disclosure_fields")),
        zk_predicate_claims: string_array(credential.get("zk_predicate_claims")),
        credential_payload_format,
        wallet_configs: object_array(credential.get("wallet_configs")),
        validity_days: positive_i64(
            validity.and_then(|value| value.get("default_validity_days")),
            365,
        ),
        renewable: validity
            .and_then(|value| value.get("renewable"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        renewal_window_days: positive_i64(
            validity.and_then(|value| value.get("renewal_window_days")),
            30,
        ),
        delivery_mode: delivery_mode(application.get("integration_context")),
        issuer_profile_id: None,
        issuer_mode: "org_managed".to_owned(),
        issuer_did,
        issuer_algorithm,
        signing_service_id: None,
        reserved_credential_id: None,
        oid4vci_client_id: None,
        created_at: now,
        expires_at: now + chrono::Duration::days(7),
    })
}

async fn resolve_and_attach_canvas_issuer(
    issuer_resolver: &dyn IssuerContextResolver,
    binding: &Map<String, Value>,
    transaction: &mut CredentialTransaction,
) -> Result<(), CanvasAwardCandidateApprovalError> {
    let remote_format = remote_credential_format(&transaction.credential_payload_format)
        .map_err(|_| CanvasAwardCandidateApprovalError::ReadinessDrift)?;
    let issuer = issuer_resolver
        .resolve(transaction, &remote_format, true)
        .await
        .map_err(approval_issuer_error)?;
    if !kms_issuer_context_matches(binding, &issuer) {
        return Err(CanvasAwardCandidateApprovalError::ReadinessDrift);
    }
    attach_issuer_context(transaction, &issuer);
    Ok(())
}

fn map_manual_guard_error(code: &'static str) -> CanvasApplicationApprovalError {
    match code {
        "canvas_application_not_found" => CanvasApplicationApprovalError::NotFound,
        "canvas_rollout_disabled" => CanvasApplicationApprovalError::RolloutDisabled,
        "canvas_application_invalid_status" => CanvasApplicationApprovalError::InvalidStatus,
        _ => CanvasApplicationApprovalError::NotReady,
    }
}

fn kms_issuer_context_matches(binding: &Map<String, Value>, issuer: &IssuerContext) -> bool {
    let raw = issuer.raw_context.as_object();
    let profile = raw
        .and_then(|value| value.get("issuer_profile"))
        .and_then(Value::as_object);
    let signing_key_reference = raw
        .and_then(|value| value.get("signing_key_reference"))
        .or_else(|| profile.and_then(|value| value.get("signing_key_reference")));
    let profile_id = first_text(&[
        raw.and_then(|value| value.get("issuer_profile_id")),
        profile.and_then(|value| value.get("id")),
    ]);
    let service = raw
        .and_then(|value| value.get("service"))
        .and_then(Value::as_object);
    let service_id = first_text(&[
        raw.and_then(|value| value.get("signing_service_id")),
        service.and_then(|value| value.get("id")),
    ]);
    let verification_method = first_text(&[
        raw.and_then(|value| value.get("verification_method_id")),
        profile.and_then(|value| value.get("verification_method_id")),
    ]);
    resolved_issuer_matches(binding, issuer)
        && !issuer.issuer_profile_id.trim().is_empty()
        && profile_id == issuer.issuer_profile_id
        && !issuer.signing_service_id.trim().is_empty()
        && service_id == issuer.signing_service_id
        && issuer
            .verification_method_id
            .as_deref()
            .is_some_and(|value| {
                value == verification_method
                    && value.starts_with(&format!("{}#", issuer.issuer_did))
            })
        && issuer.public_jwk.as_ref().is_some_and(Value::is_object)
        && !text(signing_key_reference).is_empty()
}

fn first_text(values: &[Option<&Value>]) -> String {
    values
        .iter()
        .map(|value| text(*value))
        .find(|value| !value.is_empty())
        .unwrap_or_default()
}

fn attach_issuer_context(transaction: &mut CredentialTransaction, issuer: &IssuerContext) {
    transaction.issuer_profile_id = Some(issuer.issuer_profile_id.clone());
    transaction.issuer_mode = "org_managed".to_owned();
    transaction.issuer_did = Some(issuer.issuer_did.clone());
    transaction.issuer_algorithm = Some(issuer.algorithm.clone());
    transaction.signing_service_id = Some(issuer.signing_service_id.clone());
}

fn approval_issuer_error(error: CredentialIssuanceError) -> CanvasAwardCandidateApprovalError {
    match error {
        CredentialIssuanceError::RepositoryUnavailable
        | CredentialIssuanceError::SigningUnavailable(_)
        | CredentialIssuanceError::LifecycleUnavailable(_) => {
            CanvasAwardCandidateApprovalError::Unavailable
        }
        _ => CanvasAwardCandidateApprovalError::ReadinessDrift,
    }
}

fn delivery_mode(integration: Option<&Value>) -> String {
    let integration = integration.and_then(Value::as_object);
    let nested = integration
        .and_then(|value| value.get("delivery"))
        .and_then(Value::as_object);
    optional_text(integration.and_then(|value| value.get("delivery_mode")))
        .or_else(|| optional_text(nested.and_then(|value| value.get("mode"))))
        .unwrap_or_else(|| "wallet_only".to_owned())
}

fn positive_i64(value: Option<&Value>, fallback: i64) -> i64 {
    value.and_then(Value::as_i64).unwrap_or(fallback).max(1)
}

fn object_array(value: Option<&Value>) -> Vec<Value> {
    value
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter(|value| value.is_object())
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .map(|value| text(Some(value)))
                .filter(|value| !value.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn optional_text(value: Option<&Value>) -> Option<String> {
    let value = text(value);
    (!value.is_empty()).then_some(value)
}

fn text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.trim().to_owned(),
        Some(Value::Null) | None => String::new(),
        Some(value) => value.to_string().trim_matches('"').trim().to_owned(),
    }
}
