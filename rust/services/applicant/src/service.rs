use crate::{
    issuance::{apply_offer, mark_no_active_flow, reserve_attempt, IssuanceError, IssuanceOffer},
    store::StoreDocument,
    validate_form_data, Applicant, ApplicantError, Application, CheckStatus, CheckType, ClaimState,
    Evidence, EvidenceStatus, EvidenceUpload, FieldDefinition, LifecycleStatus, ReviewerLock,
    ReviewerLocks, VettingCheck,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mmf_security::{ApplicantApprovalAuthorizationFacts, ApplicantApprovalPolicyEngine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationTemplate {
    pub id: String,
    pub organization_id: String,
    pub status: String,
    pub credential_template_id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub form_fields: Vec<FieldDefinition>,
    #[serde(default)]
    pub required_checks: Vec<CheckSpec>,
    #[serde(default)]
    pub evidence_requirements: Vec<Value>,
    #[serde(default)]
    pub approval_strategy: Option<String>,
    #[serde(default = "default_validity_days")]
    pub application_validity_days: i64,
    #[serde(default)]
    pub claim_collection_rules: Vec<Value>,
}

fn default_validity_days() -> i64 {
    30
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CheckSpec {
    #[serde(default = "identity_check")]
    pub check_type: CheckType,
    #[serde(default)]
    pub custom_name: Option<String>,
    #[serde(default = "default_true")]
    pub is_required: bool,
    #[serde(default)]
    pub order: i32,
    #[serde(default)]
    pub config: Map<String, Value>,
    #[serde(default)]
    pub external_provider: Option<String>,
    #[serde(default)]
    pub webhook_url: Option<String>,
}

fn identity_check() -> CheckType {
    CheckType::IdentityVerification
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize)]
pub struct ApprovalFacts {
    pub reviewer_id: String,
    pub organization_id: String,
    pub application_id: String,
    pub status: LifecycleStatus,
    pub risk_score: i64,
    pub document_verification_passed: bool,
    pub biometric_match_score: i64,
    pub evidence_count: usize,
    pub applicant_country: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplicationEvent {
    pub event_type: String,
    pub aggregate_id: String,
    pub aggregate_type: String,
    pub organization_id: String,
    pub timestamp: DateTime<Utc>,
    pub data: Value,
}

#[async_trait]
pub trait TemplateProvider: Send + Sync {
    async fn get(&self, id: &str) -> Result<ApplicationTemplate, ProviderError>;
}

#[async_trait]
pub trait FlowProvider: Send + Sync {
    async fn issue(
        &self,
        application: &Application,
        applicant: &Applicant,
        claims: &Map<String, Value>,
        attempt_id: Uuid,
    ) -> Result<IssuanceOffer, ProviderError>;
}

#[async_trait]
pub trait ApprovalAuthorizer: Send + Sync {
    async fn authorize(&self, facts: &ApprovalFacts) -> Result<(), ProviderError>;
}

#[derive(Clone)]
pub struct MmfApprovalAuthorizer {
    engine: ApplicantApprovalPolicyEngine,
}

impl MmfApprovalAuthorizer {
    pub fn new() -> Result<Self, ProviderError> {
        Ok(Self {
            engine: ApplicantApprovalPolicyEngine::new()
                .map_err(|error| ProviderError::Unavailable(error.to_string()))?,
        })
    }
}

#[async_trait]
impl ApprovalAuthorizer for MmfApprovalAuthorizer {
    async fn authorize(&self, facts: &ApprovalFacts) -> Result<(), ProviderError> {
        let risk_score = u32::try_from(facts.risk_score)
            .map_err(|_| ProviderError::Denied("risk score is outside 0..=100".into()))?;
        let biometric_match_score = u32::try_from(facts.biometric_match_score)
            .map_err(|_| ProviderError::Denied("biometric score is outside 0..=100".into()))?;
        let evidence_count = u64::try_from(facts.evidence_count)
            .map_err(|_| ProviderError::Denied("evidence count is too large".into()))?;
        let status = serde_json::to_value(facts.status)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(|| ProviderError::Denied("application status is invalid".into()))?;
        let decision = self
            .engine
            .authorize(&ApplicantApprovalAuthorizationFacts {
                reviewer_id: facts.reviewer_id.clone(),
                organization_id: facts.organization_id.clone(),
                application_id: facts.application_id.clone(),
                application_status: status,
                risk_score,
                document_verification_passed: facts.document_verification_passed,
                biometric_match_score,
                evidence_count,
                applicant_country: facts.applicant_country.clone(),
            })
            .map_err(|error| ProviderError::Denied(error.to_string()))?;
        if decision.allowed {
            Ok(())
        } else {
            Err(ProviderError::Denied(format!(
                "Applicant approval denied by {}",
                decision.determining_policies.join(", ")
            )))
        }
    }
}

#[async_trait]
pub trait EventPublisher: Send + Sync {
    async fn publish(&self, event: &ApplicationEvent) -> Result<(), ProviderError>;
}

pub trait StorePersistence: Send + Sync {
    fn persist(&self, store: &StoreDocument) -> Result<(), ProviderError>;
}

#[derive(Default)]
pub struct MemoryPersistence;

impl StorePersistence for MemoryPersistence {
    fn persist(&self, _: &StoreDocument) -> Result<(), ProviderError> {
        Ok(())
    }
}

pub struct FilePersistence {
    path: PathBuf,
}

impl FilePersistence {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<StoreDocument, ProviderError> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(StoreDocument::default());
        }
        let bytes =
            fs::read(path).map_err(|error| ProviderError::Persistence(error.to_string()))?;
        StoreDocument::decode(&bytes).map_err(|error| ProviderError::Persistence(error.to_string()))
    }
}

impl StorePersistence for FilePersistence {
    fn persist(&self, store: &StoreDocument) -> Result<(), ProviderError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| ProviderError::Persistence(error.to_string()))?;
        }
        let temporary = self.path.with_extension("tmp");
        let bytes = store
            .encode()
            .map_err(|error| ProviderError::Persistence(error.to_string()))?;
        fs::write(&temporary, bytes)
            .map_err(|error| ProviderError::Persistence(error.to_string()))?;
        fs::rename(&temporary, &self.path)
            .map_err(|error| ProviderError::Persistence(error.to_string()))
    }
}

pub struct ApplicantService {
    store: Arc<RwLock<StoreDocument>>,
    locks: Mutex<ReviewerLocks>,
    templates: Arc<dyn TemplateProvider>,
    flow: Arc<dyn FlowProvider>,
    authorizer: Arc<dyn ApprovalAuthorizer>,
    events: Arc<dyn EventPublisher>,
    persistence: Arc<dyn StorePersistence>,
}

impl ApplicantService {
    pub fn new(
        store: Arc<RwLock<StoreDocument>>,
        templates: Arc<dyn TemplateProvider>,
        flow: Arc<dyn FlowProvider>,
        authorizer: Arc<dyn ApprovalAuthorizer>,
        events: Arc<dyn EventPublisher>,
    ) -> Self {
        Self::with_persistence(
            store,
            templates,
            flow,
            authorizer,
            events,
            Arc::new(MemoryPersistence),
        )
    }

    pub fn with_persistence(
        store: Arc<RwLock<StoreDocument>>,
        templates: Arc<dyn TemplateProvider>,
        flow: Arc<dyn FlowProvider>,
        authorizer: Arc<dyn ApprovalAuthorizer>,
        events: Arc<dyn EventPublisher>,
        persistence: Arc<dyn StorePersistence>,
    ) -> Self {
        Self {
            store,
            locks: Mutex::new(ReviewerLocks::default()),
            templates,
            flow,
            authorizer,
            events,
            persistence,
        }
    }

    pub fn store(&self) -> &Arc<RwLock<StoreDocument>> {
        &self.store
    }

    pub async fn upsert_profile(
        &self,
        identity: &Identity,
        email: &str,
        given_name: Option<String>,
        family_name: Option<String>,
        phone: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<Applicant, ServiceError> {
        identity.validate()?;
        let mut store = self.store.write().await;
        if let Some(existing) = store
            .applicants
            .iter_mut()
            .find(|item| item.organization_id == identity.organization_id && item.email == email)
        {
            existing.user_id = Some(identity.user_id.clone());
            existing.oidc_subject = Some(identity.user_id.clone());
            if given_name.is_some() {
                existing.given_name = given_name;
            }
            if family_name.is_some() {
                existing.family_name = family_name;
            }
            if phone.is_some() {
                existing.phone = phone;
            }
            existing.updated_at = now;
            let updated = existing.clone();
            self.persistence.persist(&store)?;
            return Ok(updated);
        }
        let mut applicant = Applicant::new(identity.organization_id.clone(), email.into(), now);
        applicant.user_id = Some(identity.user_id.clone());
        applicant.oidc_subject = Some(identity.user_id.clone());
        applicant.given_name = given_name;
        applicant.family_name = family_name;
        applicant.phone = phone;
        store.save_applicant(applicant.clone());
        self.persistence.persist(&store)?;
        Ok(applicant)
    }

    pub async fn create_application(
        &self,
        identity: &Identity,
        issuer_organization_id: &str,
        application_template_id: &str,
        form_data: Map<String, Value>,
        integration_context: Map<String, Value>,
        now: DateTime<Utc>,
    ) -> Result<Application, ServiceError> {
        identity.validate()?;
        let template = self.templates.get(application_template_id).await?;
        if template.organization_id != issuer_organization_id {
            return Err(ServiceError::TemplateTenant);
        }
        if !template.status.eq_ignore_ascii_case("ACTIVE") {
            return Err(ServiceError::InactiveTemplate);
        }
        if template.credential_template_id.trim().is_empty() {
            return Err(ServiceError::MissingCredentialTemplate);
        }
        validate_form_data(&form_data, &template.form_fields)?;
        let mut store = self.store.write().await;
        let applicant = store
            .applicant_for_user(&identity.user_id, &identity.organization_id)
            .cloned()
            .ok_or(ServiceError::ProfileRequired)?;
        let duplicate = store.applications.iter().find(|item| {
            item.applicant_id == applicant.id
                && item.credential_template_id == template.credential_template_id
                && !matches!(
                    item.status,
                    LifecycleStatus::Rejected
                        | LifecycleStatus::Withdrawn
                        | LifecycleStatus::Suspended
                )
        });
        if let Some(duplicate) = duplicate {
            return Err(ServiceError::DuplicateApplication(
                duplicate.reference_number.clone(),
            ));
        }
        let mut system_data = Map::new();
        insert_optional(
            &mut system_data,
            "credential_display_name",
            template.name.clone(),
        );
        insert_optional(
            &mut system_data,
            "approval_strategy",
            template.approval_strategy.clone(),
        );
        system_data.insert(
            "application_validity_days".into(),
            Value::Number(template.application_validity_days.into()),
        );
        let application = Application {
            id: Uuid::new_v4().to_string(),
            applicant_id: applicant.id,
            organization_id: issuer_organization_id.into(),
            reference_number: Some(reference_number(now)),
            application_template_id: template.id,
            credential_template_id: template.credential_template_id,
            status: LifecycleStatus::Draft,
            form_data,
            integration_context,
            system_data,
            required_checks: template
                .required_checks
                .iter()
                .map(|item| serde_json::to_value(item).expect("check spec serialization"))
                .collect(),
            evidence_requirements: template.evidence_requirements,
            claim_state: ClaimState::NotReady,
            claim_blocker: None,
            created_at: now,
            updated_at: now,
            submitted_at: None,
            reviewed_at: None,
            issued_at: None,
        };
        store.save_application(application.clone());
        self.persistence.persist(&store)?;
        Ok(application)
    }

    pub async fn submit(
        &self,
        application_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Application, ServiceError> {
        let template_id = {
            let store = self.store.read().await;
            store
                .application(application_id)
                .ok_or(ServiceError::ApplicationNotFound)?
                .application_template_id
                .clone()
        };
        let template = self.templates.get(&template_id).await?;
        let mut store = self.store.write().await;
        let index = application_index(&store, application_id)?;
        let mut application = store.applications[index].clone();
        if application.status == LifecycleStatus::Submitted {
            return Ok(application);
        }
        if !matches!(
            application.status,
            LifecycleStatus::Draft | LifecycleStatus::PendingInformation
        ) {
            return Err(ServiceError::InvalidApplicationState(application.status));
        }
        validate_form_data(&application.form_data, &template.form_fields)?;
        validate_required_evidence(&mut store, &application, now)?;
        let first_submission = application.status == LifecycleStatus::Draft;
        application.status = application.status.transition(LifecycleStatus::Submitted)?;
        application.submitted_at = Some(now);
        application.updated_at = now;
        if application.reference_number.is_none() {
            application.reference_number = Some(reference_number(now));
        }
        if let Some(applicant) = store
            .applicants
            .iter_mut()
            .find(|item| item.id == application.applicant_id)
        {
            if matches!(
                applicant.status,
                LifecycleStatus::Draft | LifecycleStatus::PendingInformation
            ) {
                applicant.set_status(LifecycleStatus::Submitted, now)?;
            }
        }
        let automatic = template.approval_strategy.as_deref().is_some_and(|value| {
            matches!(value.to_ascii_uppercase().as_str(), "AUTO" | "AUTO_APPROVE")
        });
        if automatic {
            application.status = application.status.transition(LifecycleStatus::Approved)?;
            application.reviewed_at = Some(now);
        } else if first_submission && store.checks_for_application(application_id).is_empty() {
            let specs = if template.required_checks.is_empty() {
                vec![CheckSpec {
                    check_type: CheckType::IdentityVerification,
                    custom_name: None,
                    is_required: true,
                    order: 1,
                    config: Map::new(),
                    external_provider: None,
                    webhook_url: None,
                }]
            } else {
                template.required_checks
            };
            for spec in specs {
                store.save_check(check_from_spec(application_id, spec, now));
            }
        }
        store.applications[index] = application.clone();
        self.persistence.persist(&store)?;
        Ok(application)
    }

    pub async fn upload_evidence(
        &self,
        input: EvidenceUpload,
        maximum: usize,
        now: DateTime<Utc>,
    ) -> Result<Evidence, ServiceError> {
        let mut store = self.store.write().await;
        let application = store
            .application(&input.application_id)
            .ok_or(ServiceError::ApplicationNotFound)?;
        if application.organization_id != input.organization_id
            || application.applicant_id != input.applicant_id
        {
            return Err(ServiceError::TenantMismatch);
        }
        let requirement = application
            .evidence_requirements
            .iter()
            .find(|item| {
                item.get("evidence_id").and_then(Value::as_str)
                    == Some(input.evidence_requirement_id.as_str())
            })
            .ok_or(ServiceError::EvidenceRequirementNotFound)?;
        let expected_type = requirement
            .get("evidence_type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !expected_type.eq_ignore_ascii_case(&input.evidence_type) {
            return Err(ServiceError::EvidenceTypeMismatch);
        }
        let evidence = Evidence::from_upload(input, maximum, now)?;
        store.save_evidence(evidence.clone());
        self.persistence.persist(&store)?;
        Ok(evidence)
    }

    pub async fn acquire_lock(
        &self,
        application_id: &str,
        reviewer_id: &str,
        reviewer_name: &str,
        now: DateTime<Utc>,
    ) -> Result<ReviewerLock, ServiceError> {
        if self
            .store
            .read()
            .await
            .application(application_id)
            .is_none()
        {
            return Err(ServiceError::ApplicationNotFound);
        }
        Ok(self
            .locks
            .lock()
            .await
            .acquire(application_id, reviewer_id, reviewer_name, now)?
            .clone())
    }
}

impl ApplicantService {
    pub async fn release_lock(
        &self,
        application_id: &str,
        reviewer_id: &str,
        now: DateTime<Utc>,
    ) -> bool {
        self.locks
            .lock()
            .await
            .release(application_id, reviewer_id, now)
    }

    pub async fn review(
        &self,
        application_id: &str,
        reviewer_id: &str,
        approve: bool,
        notes: Option<String>,
        rejection_reason: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<Application, ServiceError> {
        if !self
            .locks
            .lock()
            .await
            .held_by(application_id, reviewer_id, now)
        {
            return Err(ServiceError::ReviewerLockRequired);
        }
        let (facts, applicant_id) = {
            let mut store = self.store.write().await;
            let application = store
                .application(application_id)
                .cloned()
                .ok_or(ServiceError::ApplicationNotFound)?;
            if !matches!(
                application.status,
                LifecycleStatus::Submitted
                    | LifecycleStatus::UnderReview
                    | LifecycleStatus::PendingInformation
            ) {
                return Err(ServiceError::InvalidApplicationState(application.status));
            }
            if approve {
                validate_required_evidence(&mut store, &application, now)?;
            }
            (
                approval_facts(&store, &application, reviewer_id),
                application.applicant_id,
            )
        };
        if approve {
            self.authorizer.authorize(&facts).await?;
        } else if rejection_reason.as_deref().is_none_or(str::is_empty) {
            return Err(ServiceError::RejectionReasonRequired);
        }

        let mut store = self.store.write().await;
        let index = application_index(&store, application_id)?;
        let mut application = store.applications[index].clone();
        if application.status != facts.status {
            return Err(ServiceError::ConcurrentModification);
        }
        let target = if approve {
            LifecycleStatus::Approved
        } else {
            LifecycleStatus::Rejected
        };
        application.status = application.status.transition(target)?;
        application.reviewed_at = Some(now);
        application.updated_at = now;
        if let Some(notes) = notes {
            application
                .system_data
                .insert("review_notes".into(), Value::String(notes));
        }
        if let Some(reason) = rejection_reason {
            application
                .system_data
                .insert("rejection_reason".into(), Value::String(reason));
        }
        if let Some(applicant) = store
            .applicants
            .iter_mut()
            .find(|item| item.id == applicant_id)
        {
            applicant.set_status(target, now)?;
        }
        store.applications[index] = application.clone();
        self.persistence.persist(&store)?;
        drop(store);

        let event = ApplicationEvent {
            event_type: if approve {
                "application.approved"
            } else {
                "application.rejected"
            }
            .into(),
            aggregate_id: application.id.clone(),
            aggregate_type: "application".into(),
            organization_id: application.organization_id.clone(),
            timestamp: now,
            data: json!({
                "applicant_id": &application.applicant_id,
                "application_id": &application.id,
                "credential_template_id": &application.credential_template_id,
                "status": application.status
            }),
        };
        // The durable decision is authoritative; delivery is observable and retryable
        // through the concrete event adapter, but does not roll back the review.
        let _ = self.events.publish(&event).await;
        Ok(application)
    }

    pub async fn request_information(
        &self,
        application_id: &str,
        missing_items: Vec<String>,
        message: String,
        deadline: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<Application, ServiceError> {
        let mut store = self.store.write().await;
        let index = application_index(&store, application_id)?;
        let mut application = store.applications[index].clone();
        if !matches!(
            application.status,
            LifecycleStatus::Submitted
                | LifecycleStatus::UnderReview
                | LifecycleStatus::PendingInformation
        ) {
            return Err(ServiceError::InvalidApplicationState(application.status));
        }
        application.status = application
            .status
            .transition(LifecycleStatus::PendingInformation)?;
        let info_request = json!({
            "requested_at": now.to_rfc3339(),
            "missing_items": missing_items,
            "message": message,
            "deadline": deadline
        });
        application
            .system_data
            .entry("info_requests")
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or(ServiceError::MalformedSystemState)?
            .push(info_request);
        application.updated_at = now;
        if let Some(applicant) = store
            .applicants
            .iter_mut()
            .find(|item| item.id == application.applicant_id)
        {
            applicant.set_status(LifecycleStatus::PendingInformation, now)?;
        }
        store.applications[index] = application.clone();
        self.persistence.persist(&store)?;
        Ok(application)
    }

    pub async fn issue(
        &self,
        application_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Application, ServiceError> {
        let (application_snapshot, applicant_snapshot) = {
            let store = self.store.read().await;
            let application = store
                .application(application_id)
                .cloned()
                .ok_or(ServiceError::ApplicationNotFound)?;
            let applicant = store
                .applicant(&application.applicant_id)
                .cloned()
                .ok_or(ServiceError::ApplicantNotFound)?;
            (application, applicant)
        };
        let template = self
            .templates
            .get(&application_snapshot.application_template_id)
            .await?;
        let claims = build_claims(&application_snapshot, &applicant_snapshot, &template, now);

        let (application, applicant, attempt_id, reserved_claims) = {
            let mut store = self.store.write().await;
            let index = application_index(&store, application_id)?;
            let mut application = store.applications[index].clone();
            if application.updated_at != application_snapshot.updated_at {
                return Err(ServiceError::ConcurrentModification);
            }
            if application.status == LifecycleStatus::Credentialed {
                application.status = LifecycleStatus::Offered;
                application.issued_at = None;
            }
            if !matches!(
                application.status,
                LifecycleStatus::Approved | LifecycleStatus::Offered
            ) {
                return Err(ServiceError::InvalidApplicationState(application.status));
            }
            let applicant = store
                .applicant(&application.applicant_id)
                .cloned()
                .ok_or(ServiceError::ApplicantNotFound)?;
            let (attempt_id, reserved_claims) = reserve_attempt(&mut application, claims, now)?;
            store.applications[index] = application.clone();
            self.persistence.persist(&store)?;
            (application, applicant, attempt_id, reserved_claims)
        };

        let offer = match self
            .flow
            .issue(&application, &applicant, &reserved_claims, attempt_id)
            .await
        {
            Ok(offer) => offer,
            Err(ProviderError::NoActiveFlow) => {
                let mut store = self.store.write().await;
                let index = application_index(&store, application_id)?;
                mark_no_active_flow(&mut store.applications[index], now);
                self.persistence.persist(&store)?;
                return Err(ServiceError::NoActiveFlow);
            }
            Err(error) => return Err(error.into()),
        };

        let mut store = self.store.write().await;
        let index = application_index(&store, application_id)?;
        let mut application = store.applications[index].clone();
        let applicant_index = store
            .applicants
            .iter()
            .position(|item| item.id == application.applicant_id)
            .ok_or(ServiceError::ApplicantNotFound)?;
        let mut applicant = store.applicants[applicant_index].clone();
        apply_offer(&mut application, &mut applicant, attempt_id, &offer, now)?;
        store.applications[index] = application.clone();
        store.applicants[applicant_index] = applicant;
        self.persistence.persist(&store)?;
        Ok(application)
    }

    pub async fn complete_check(
        &self,
        check_id: &str,
        passed: bool,
        performed_by: Option<String>,
        result: Map<String, Value>,
        evidence_ids: Vec<String>,
        now: DateTime<Utc>,
    ) -> Result<VettingCheck, ServiceError> {
        let mut store = self.store.write().await;
        let index = store
            .checks
            .iter()
            .position(|item| item.id == check_id)
            .ok_or(ServiceError::CheckNotFound)?;
        let application_id = store.checks[index].application_id.clone();
        let application = store
            .application(&application_id)
            .cloned()
            .ok_or(ServiceError::ApplicationNotFound)?;
        for evidence_id in &evidence_ids {
            let evidence = store
                .evidence
                .iter()
                .find(|item| item.id == *evidence_id)
                .ok_or(ServiceError::EvidenceNotFound)?;
            if evidence.application_id != application.id
                || evidence.organization_id != application.organization_id
                || evidence.applicant_id != application.applicant_id
                || evidence.status != EvidenceStatus::Active
            {
                return Err(ServiceError::InvalidEvidenceReference);
            }
        }
        let mut check = store.checks[index].clone();
        check.complete(passed, None, performed_by, result, evidence_ids, now);
        store.checks[index] = check.clone();
        self.persistence.persist(&store)?;
        Ok(check)
    }
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub user_id: String,
    pub organization_id: String,
}

impl Identity {
    fn validate(&self) -> Result<(), ServiceError> {
        if self.user_id.trim().is_empty() {
            Err(ServiceError::AuthenticationRequired)
        } else if self.organization_id.trim().is_empty() {
            Err(ServiceError::OrganizationRequired)
        } else {
            Ok(())
        }
    }
}

fn application_index(store: &StoreDocument, id: &str) -> Result<usize, ServiceError> {
    store
        .applications
        .iter()
        .position(|item| item.id == id)
        .ok_or(ServiceError::ApplicationNotFound)
}

fn reference_number(now: DateTime<Utc>) -> String {
    format!(
        "APP-{}-{}",
        now.format("%Y%m%d"),
        &Uuid::new_v4().simple().to_string()[..6].to_ascii_uppercase()
    )
}

fn insert_optional(values: &mut Map<String, Value>, key: &str, value: Option<String>) {
    values.insert(key.into(), value.map(Value::String).unwrap_or(Value::Null));
}

fn check_from_spec(application_id: &str, spec: CheckSpec, now: DateTime<Utc>) -> VettingCheck {
    VettingCheck {
        id: Uuid::new_v4().to_string(),
        application_id: application_id.into(),
        check_type: spec.check_type,
        custom_name: spec.custom_name,
        is_required: spec.is_required,
        order: spec.order,
        status: CheckStatus::NotStarted,
        config: spec.config,
        result: Map::new(),
        notes: None,
        performed_by: None,
        external_provider: spec.external_provider,
        webhook_url: spec.webhook_url,
        created_at: now,
        updated_at: now,
        started_at: None,
        completed_at: None,
    }
}

fn validate_required_evidence(
    store: &mut StoreDocument,
    application: &Application,
    now: DateTime<Utc>,
) -> Result<(), ServiceError> {
    for requirement in &application.evidence_requirements {
        if !requirement
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            continue;
        }
        let kind = requirement
            .get("evidence_type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_uppercase();
        if !matches!(
            kind.as_str(),
            "DOCUMENT_SCAN" | "BIOMETRIC" | "SELFIE" | "THIRD_PARTY_VERIFICATION"
        ) {
            continue;
        }
        let id = requirement
            .get("evidence_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let mut valid = false;
        for evidence in store.evidence.iter_mut().filter(|item| {
            item.application_id == application.id && item.evidence_requirement_id == id
        }) {
            evidence.refresh_expiry(now);
            let digest = format!("{:x}", Sha256::digest(&evidence.content));
            valid |= evidence.status == EvidenceStatus::Active
                && evidence.organization_id == application.organization_id
                && evidence.applicant_id == application.applicant_id
                && evidence.size_bytes == evidence.content.len()
                && evidence.sha256 == digest;
        }
        if !valid {
            return Err(ServiceError::RequiredEvidence(id.into()));
        }
    }
    Ok(())
}

fn approval_facts(
    store: &StoreDocument,
    application: &Application,
    reviewer_id: &str,
) -> ApprovalFacts {
    let value = |key: &str| {
        application
            .form_data
            .get(key)
            .or_else(|| application.integration_context.get(key))
    };
    ApprovalFacts {
        reviewer_id: reviewer_id.into(),
        organization_id: application.organization_id.clone(),
        application_id: application.id.clone(),
        status: application.status,
        risk_score: value("risk_score").and_then(Value::as_i64).unwrap_or(0),
        document_verification_passed: value("document_verification_passed")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        biometric_match_score: value("biometric_match_score")
            .and_then(Value::as_i64)
            .unwrap_or(100),
        evidence_count: store.evidence_for_application(&application.id, false).len(),
        applicant_country: value("applicant_country")
            .and_then(Value::as_str)
            .unwrap_or("US")
            .into(),
    }
}

fn build_claims(
    application: &Application,
    applicant: &Applicant,
    template: &ApplicationTemplate,
    now: DateTime<Utc>,
) -> Map<String, Value> {
    let mut claims = Map::new();
    for field in &template.form_fields {
        if let Some(value) = application.form_data.get(&field.field_id) {
            claims.insert(field.field_id.clone(), value.clone());
        }
    }
    let system_values: Map<String, Value> = [
        (
            "applicant.user_id",
            applicant.user_id.clone().map(Value::String),
        ),
        (
            "applicant.email",
            Some(Value::String(applicant.email.clone())),
        ),
        (
            "applicant.given_name",
            applicant.given_name.clone().map(Value::String),
        ),
        (
            "applicant.family_name",
            applicant.family_name.clone().map(Value::String),
        ),
        (
            "application.id",
            Some(Value::String(application.id.clone())),
        ),
        (
            "application.reference_number",
            application.reference_number.clone().map(Value::String),
        ),
        (
            "application.organization_id",
            Some(Value::String(application.organization_id.clone())),
        ),
        (
            "current.date",
            Some(Value::String(now.date_naive().to_string())),
        ),
        ("current.datetime", Some(Value::String(now.to_rfc3339()))),
        (
            "validity.expiry_date",
            Some(Value::String(
                (now + chrono::Duration::days(template.application_validity_days))
                    .date_naive()
                    .to_string(),
            )),
        ),
        ("template.name", template.name.clone().map(Value::String)),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.map(|value| (key.into(), value)))
    .collect();

    for rule in &template.claim_collection_rules {
        let claim_name = rule
            .get("claim_name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let source = rule
            .get("source")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let config = rule.get("source_config").and_then(Value::as_object);
        if claim_name.is_empty() {
            continue;
        }
        if source == "FORM_FIELD" {
            if let Some(field_id) = config
                .and_then(|value| value.get("field_id"))
                .and_then(Value::as_str)
            {
                if let Some(value) = application.form_data.get(field_id) {
                    claims.insert(claim_name.into(), value.clone());
                }
            }
        } else if source == "SYSTEM" {
            if let Some(system_field) = config
                .and_then(|value| value.get("system_field"))
                .and_then(Value::as_str)
            {
                let value = if system_field == "constant" {
                    config.and_then(|value| value.get("value")).cloned()
                } else {
                    system_values.get(system_field).cloned()
                };
                if let Some(value) = value {
                    claims.insert(claim_name.into(), value);
                }
            }
        }
    }
    claims
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("provider unavailable: {0}")]
    Unavailable(String),
    #[error("no active issuance flow")]
    NoActiveFlow,
    #[error("authorization denied: {0}")]
    Denied(String),
    #[error("applicant persistence failed: {0}")]
    Persistence(String),
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("authentication required")]
    AuthenticationRequired,
    #[error("organization context required")]
    OrganizationRequired,
    #[error("application template belongs to another organization")]
    TemplateTenant,
    #[error("application template must be active")]
    InactiveTemplate,
    #[error("application template has no credential template")]
    MissingCredentialTemplate,
    #[error("create an applicant profile before applying")]
    ProfileRequired,
    #[error("an active application already exists")]
    DuplicateApplication(Option<String>),
    #[error("applicant not found")]
    ApplicantNotFound,
    #[error("application not found")]
    ApplicationNotFound,
    #[error("check not found")]
    CheckNotFound,
    #[error("evidence not found")]
    EvidenceNotFound,
    #[error("evidence requirement not found")]
    EvidenceRequirementNotFound,
    #[error("evidence type does not match requirement")]
    EvidenceTypeMismatch,
    #[error("tenant mismatch")]
    TenantMismatch,
    #[error("required evidence is missing or invalid: {0}")]
    RequiredEvidence(String),
    #[error("invalid evidence reference")]
    InvalidEvidenceReference,
    #[error("reviewer lock required")]
    ReviewerLockRequired,
    #[error("rejection reason required")]
    RejectionReasonRequired,
    #[error("application changed during authorization")]
    ConcurrentModification,
    #[error("persisted application system state is malformed")]
    MalformedSystemState,
    #[error("invalid application state: {0:?}")]
    InvalidApplicationState(LifecycleStatus),
    #[error("no active issuance flow")]
    NoActiveFlow,
    #[error(transparent)]
    Domain(#[from] ApplicantError),
    #[error(transparent)]
    Issuance(#[from] IssuanceError),
    #[error(transparent)]
    Provider(#[from] ProviderError),
}
