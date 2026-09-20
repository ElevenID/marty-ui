//! Internal Application management use cases.
//!
//! This layer owns authentication, tenant isolation, lifecycle coordination and
//! optimistic concurrency. HTTP and PostgreSQL adapters remain deliberately
//! separate so every transport exercises the same decisions.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    application_template_domain::{ApplicationTemplateRecord, ApplicationTemplateStatus},
    internal_application_domain::{
        derive_applicant_identifier, ApplicationCreate, ApplicationDomainError, ApplicationRecord,
        ApplicationRejection, ApplicationStatus, EvidenceSubmission,
    },
    management_security::ManagementSecurity,
    transaction_reads::TransactionReadError,
};

const INTERNAL_REVIEWER_ID: &str = "issuance-management-api";

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum InternalApplicationRepositoryError {
    #[error("Application repository is unavailable")]
    Unavailable,
}

#[async_trait]
pub trait InternalApplicationRepository: Send + Sync {
    /// Load by global template ID so the service can preserve the legacy
    /// distinction between a missing template and a foreign-tenant template.
    async fn get_application_template(
        &self,
        template_id: &str,
    ) -> Result<Option<ApplicationTemplateRecord>, InternalApplicationRepositoryError>;

    async fn insert_application(
        &self,
        application: &ApplicationRecord,
    ) -> Result<(), InternalApplicationRepositoryError>;

    async fn list_applications(
        &self,
        organization_id: &str,
        status: Option<ApplicationStatus>,
        template_id: Option<&str>,
    ) -> Result<Vec<ApplicationRecord>, InternalApplicationRepositoryError>;

    /// Load by global application ID. Tenant hiding is enforced by the service
    /// after the row is loaded, matching the frozen Python route.
    async fn get_application(
        &self,
        application_id: &str,
    ) -> Result<Option<ApplicationRecord>, InternalApplicationRepositoryError>;

    /// Atomically replace one exact lifecycle revision. A false result means
    /// the status or `updated_at` changed after the service read the row.
    async fn replace_application_if_revision(
        &self,
        application: &ApplicationRecord,
        expected_status: ApplicationStatus,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<bool, InternalApplicationRepositoryError>;
}

pub trait InternalApplicationClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemInternalApplicationClock;

impl InternalApplicationClock for SystemInternalApplicationClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

pub trait InternalApplicationIdGenerator: Send + Sync {
    fn application_id(&self) -> String;
    fn applicant_identifier(&self) -> String;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UuidInternalApplicationIdGenerator;

impl InternalApplicationIdGenerator for UuidInternalApplicationIdGenerator {
    fn application_id(&self) -> String {
        Uuid::new_v4().to_string()
    }

    fn applicant_identifier(&self) -> String {
        let random = Uuid::new_v4().simple().to_string();
        format!("applicant_{}", &random[..8])
    }
}

#[derive(Clone)]
pub struct InternalApplicationService {
    repository: Arc<dyn InternalApplicationRepository>,
    clock: Arc<dyn InternalApplicationClock>,
    ids: Arc<dyn InternalApplicationIdGenerator>,
    security: ManagementSecurity,
}

impl std::fmt::Debug for InternalApplicationService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InternalApplicationService")
            .field("security", &self.security)
            .finish_non_exhaustive()
    }
}

impl InternalApplicationService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn InternalApplicationRepository>,
        clock: Arc<dyn InternalApplicationClock>,
        ids: Arc<dyn InternalApplicationIdGenerator>,
        management_api_key: Option<&str>,
    ) -> Self {
        Self {
            repository,
            clock,
            ids,
            security: ManagementSecurity::new(management_api_key),
        }
    }

    pub async fn create(
        &self,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
        request: ApplicationCreate,
    ) -> Result<ApplicationRecord, InternalApplicationServiceError> {
        self.security.authorize(api_key)?;
        let trusted_organization = required_organization(trusted_organization)?;
        let template = self
            .repository
            .get_application_template(&request.application_template_id)
            .await?
            .ok_or(InternalApplicationServiceError::TemplateNotFound)?;
        self.security.require_organization(
            Some(trusted_organization),
            &template.organization_id,
            true,
        )?;
        if template.status != ApplicationTemplateStatus::Active {
            return Err(InternalApplicationServiceError::TemplateInactive);
        }

        // Python only consumes the fallback UUID when neither a name nor an
        // email produced an identifier. Preserve that laziness for tests and
        // for deterministic ID sources.
        let applicant_identifier = derive_applicant_identifier(&request.applicant_data, "");
        let generated_identifier = if applicant_identifier.is_empty() {
            self.ids.applicant_identifier()
        } else {
            applicant_identifier
        };
        let application = ApplicationRecord::new(
            self.ids.application_id(),
            template.organization_id,
            request,
            &generated_identifier,
            self.clock.now(),
        )?;
        self.repository.insert_application(&application).await?;
        Ok(application)
    }

    pub async fn list(
        &self,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
        claimed_organization: &str,
        status: Option<&str>,
        template_id: Option<&str>,
    ) -> Result<Vec<ApplicationRecord>, InternalApplicationServiceError> {
        self.security.authorize(api_key)?;
        let claimed_organization = claimed_organization.trim();
        self.security
            .require_organization(trusted_organization, claimed_organization, true)?;
        let status = status
            .filter(|value| !value.is_empty())
            .map(str::parse)
            .transpose()
            .map_err(|_| InternalApplicationServiceError::InvalidStatus)?;
        let template_id = template_id.filter(|value| !value.is_empty());
        self.repository
            .list_applications(claimed_organization, status, template_id)
            .await
            .map_err(Into::into)
    }

    pub async fn get(
        &self,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
        application_id: &str,
    ) -> Result<ApplicationRecord, InternalApplicationServiceError> {
        self.security.authorize(api_key)?;
        let trusted_organization = required_organization(trusted_organization)?;
        self.load_managed(application_id, trusted_organization)
            .await
    }

    pub async fn submit_evidence(
        &self,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
        application_id: &str,
        evidence: EvidenceSubmission,
    ) -> Result<ApplicationRecord, InternalApplicationServiceError> {
        self.security.authorize(api_key)?;
        let trusted_organization = required_organization(trusted_organization)?;
        let mut application = self
            .load_managed(application_id, trusted_organization)
            .await?;
        let expected_updated_at = application.updated_at;
        application.submit_evidence(evidence, self.clock.now())?;
        if !self
            .repository
            .replace_application_if_revision(
                &application,
                ApplicationStatus::Pending,
                expected_updated_at,
            )
            .await?
        {
            return Err(InternalApplicationServiceError::EvidenceConflict);
        }
        Ok(application)
    }

    pub async fn reject(
        &self,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
        application_id: &str,
        rejection: ApplicationRejection,
    ) -> Result<ApplicationRecord, InternalApplicationServiceError> {
        self.security.authorize(api_key)?;
        let trusted_organization = required_organization(trusted_organization)?;
        let mut application = self
            .load_managed(application_id, trusted_organization)
            .await?;
        let expected_updated_at = application.updated_at;
        application.reject(
            rejection.review_notes,
            INTERNAL_REVIEWER_ID,
            self.clock.now(),
        )?;
        if !self
            .repository
            .replace_application_if_revision(
                &application,
                ApplicationStatus::Pending,
                expected_updated_at,
            )
            .await?
        {
            return Err(InternalApplicationServiceError::RejectionConflict);
        }
        Ok(application)
    }

    async fn load_managed(
        &self,
        application_id: &str,
        trusted_organization: &str,
    ) -> Result<ApplicationRecord, InternalApplicationServiceError> {
        self.repository
            .get_application(application_id)
            .await?
            .filter(|application| application.organization_id == trusted_organization)
            .ok_or(InternalApplicationServiceError::ApplicationNotFound)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum InternalApplicationServiceError {
    #[error(transparent)]
    Security(#[from] TransactionReadError),
    #[error(transparent)]
    Repository(#[from] InternalApplicationRepositoryError),
    #[error(transparent)]
    Domain(#[from] ApplicationDomainError),
    #[error("Invalid application status")]
    InvalidStatus,
    #[error("Application template not found")]
    TemplateNotFound,
    #[error("Application template must be active")]
    TemplateInactive,
    #[error("Application not found")]
    ApplicationNotFound,
    #[error("Application lifecycle changed during evidence submission")]
    EvidenceConflict,
    #[error("Application lifecycle changed during rejection")]
    RejectionConflict,
}

fn required_organization(value: Option<&str>) -> Result<&str, TransactionReadError> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(TransactionReadError::TrustedOrganizationRequired)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    };

    use chrono::{Duration, TimeZone};
    use serde_json::{json, Map};

    use super::*;
    use crate::application_template_domain::ApplicationTemplateCreate;

    #[derive(Debug)]
    struct MemoryRepository {
        template: Mutex<Option<ApplicationTemplateRecord>>,
        applications: Mutex<Vec<ApplicationRecord>>,
        reject_compare_and_swap: AtomicBool,
    }

    #[async_trait]
    impl InternalApplicationRepository for MemoryRepository {
        async fn get_application_template(
            &self,
            template_id: &str,
        ) -> Result<Option<ApplicationTemplateRecord>, InternalApplicationRepositoryError> {
            Ok(self
                .template
                .lock()
                .expect("template lock")
                .clone()
                .filter(|template| template.id == template_id))
        }

        async fn insert_application(
            &self,
            application: &ApplicationRecord,
        ) -> Result<(), InternalApplicationRepositoryError> {
            self.applications
                .lock()
                .expect("applications lock")
                .push(application.clone());
            Ok(())
        }

        async fn list_applications(
            &self,
            organization_id: &str,
            status: Option<ApplicationStatus>,
            template_id: Option<&str>,
        ) -> Result<Vec<ApplicationRecord>, InternalApplicationRepositoryError> {
            Ok(self
                .applications
                .lock()
                .expect("applications lock")
                .iter()
                .filter(|application| application.organization_id == organization_id)
                .filter(|application| status.is_none_or(|status| application.status == status))
                .filter(|application| {
                    template_id.is_none_or(|template_id| {
                        application.application_template_id == template_id
                    })
                })
                .cloned()
                .collect())
        }

        async fn get_application(
            &self,
            application_id: &str,
        ) -> Result<Option<ApplicationRecord>, InternalApplicationRepositoryError> {
            Ok(self
                .applications
                .lock()
                .expect("applications lock")
                .iter()
                .find(|application| application.id == application_id)
                .cloned())
        }

        async fn replace_application_if_revision(
            &self,
            application: &ApplicationRecord,
            expected_status: ApplicationStatus,
            expected_updated_at: DateTime<Utc>,
        ) -> Result<bool, InternalApplicationRepositoryError> {
            if self.reject_compare_and_swap.load(Ordering::SeqCst) {
                return Ok(false);
            }
            let mut applications = self.applications.lock().expect("applications lock");
            let Some(existing) = applications.iter_mut().find(|candidate| {
                candidate.id == application.id
                    && candidate.organization_id == application.organization_id
                    && candidate.status == expected_status
                    && candidate.updated_at == expected_updated_at
            }) else {
                return Ok(false);
            };
            *existing = application.clone();
            Ok(true)
        }
    }

    #[derive(Debug)]
    struct FixedRuntime {
        now: DateTime<Utc>,
        applicant_ids: AtomicUsize,
    }

    impl InternalApplicationClock for FixedRuntime {
        fn now(&self) -> DateTime<Utc> {
            self.now
        }
    }

    impl InternalApplicationIdGenerator for FixedRuntime {
        fn application_id(&self) -> String {
            "application-1".to_owned()
        }

        fn applicant_identifier(&self) -> String {
            self.applicant_ids.fetch_add(1, Ordering::SeqCst);
            "applicant_deadbeef".to_owned()
        }
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 19, 12, 34, 56)
            .single()
            .expect("fixed timestamp")
    }

    fn template(
        organization_id: &str,
        status: ApplicationTemplateStatus,
    ) -> ApplicationTemplateRecord {
        let request: ApplicationTemplateCreate = serde_json::from_value(json!({
            "organization_id": organization_id,
            "name": "Employee application"
        }))
        .expect("template request");
        let mut template = request
            .into_record("template-1".to_owned(), now())
            .expect("template record");
        template.status = status;
        template
    }

    fn fixture(
        template: Option<ApplicationTemplateRecord>,
    ) -> (
        Arc<MemoryRepository>,
        Arc<FixedRuntime>,
        InternalApplicationService,
    ) {
        let repository = Arc::new(MemoryRepository {
            template: Mutex::new(template),
            applications: Mutex::new(Vec::new()),
            reject_compare_and_swap: AtomicBool::new(false),
        });
        let runtime = Arc::new(FixedRuntime {
            now: now(),
            applicant_ids: AtomicUsize::new(0),
        });
        let service = InternalApplicationService::new(
            repository.clone(),
            runtime.clone(),
            runtime.clone(),
            Some("secret"),
        );
        (repository, runtime, service)
    }

    fn create_request(applicant_data: Map<String, serde_json::Value>) -> ApplicationCreate {
        ApplicationCreate {
            application_template_id: "template-1".to_owned(),
            applicant_data,
            integration_context: Map::new(),
        }
    }

    async fn create_named(service: &InternalApplicationService) -> ApplicationRecord {
        service
            .create(
                Some("secret"),
                Some("org-123"),
                create_request(
                    json!({"given_name": " Ada ", "family_name": " Lovelace "})
                        .as_object()
                        .expect("applicant object")
                        .clone(),
                ),
            )
            .await
            .expect("application")
    }

    #[tokio::test]
    async fn create_requires_auth_tenant_and_an_active_same_tenant_template() {
        let (_, _, service) = fixture(Some(template("org-123", ApplicationTemplateStatus::Active)));
        assert_eq!(
            service
                .create(None, Some("org-123"), create_request(Map::new()))
                .await,
            Err(InternalApplicationServiceError::Security(
                TransactionReadError::ApiKeyMissing
            ))
        );
        assert_eq!(
            service
                .create(Some("secret"), None, create_request(Map::new()))
                .await,
            Err(InternalApplicationServiceError::Security(
                TransactionReadError::TrustedOrganizationRequired
            ))
        );

        let (_, _, missing) = fixture(None);
        assert_eq!(
            missing
                .create(Some("secret"), Some("org-123"), create_request(Map::new()))
                .await,
            Err(InternalApplicationServiceError::TemplateNotFound)
        );

        let (_, _, inactive) = fixture(Some(template("org-123", ApplicationTemplateStatus::Draft)));
        assert_eq!(
            inactive
                .create(Some("secret"), Some("org-123"), create_request(Map::new()))
                .await,
            Err(InternalApplicationServiceError::TemplateInactive)
        );

        let (_, _, foreign) = fixture(Some(template(
            "org-other",
            ApplicationTemplateStatus::Active,
        )));
        assert_eq!(
            foreign
                .create(Some("secret"), Some("org-123"), create_request(Map::new()))
                .await,
            Err(InternalApplicationServiceError::Security(
                TransactionReadError::ResourceNotFound
            ))
        );
    }

    #[tokio::test]
    async fn create_preserves_identifier_precedence_and_lazy_fallback_generation() {
        let (_, runtime, service) =
            fixture(Some(template("org-123", ApplicationTemplateStatus::Active)));
        let application = create_named(&service).await;
        assert_eq!(application.applicant_identifier, "Ada_Lovelace");
        assert_eq!(runtime.applicant_ids.load(Ordering::SeqCst), 0);

        let (_, runtime, service) =
            fixture(Some(template("org-123", ApplicationTemplateStatus::Active)));
        let application = service
            .create(Some("secret"), Some("org-123"), create_request(Map::new()))
            .await
            .expect("fallback application");
        assert_eq!(application.applicant_identifier, "applicant_deadbeef");
        assert_eq!(runtime.applicant_ids.load(Ordering::SeqCst), 1);
        assert_eq!(application.expires_at, now() + Duration::days(30));
    }

    #[tokio::test]
    async fn list_validates_tenant_and_exact_status_then_applies_filters() {
        let (_, _, service) = fixture(Some(template("org-123", ApplicationTemplateStatus::Active)));
        create_named(&service).await;

        assert_eq!(
            service
                .list(Some("secret"), Some("org-other"), "org-123", None, None)
                .await,
            Err(InternalApplicationServiceError::Security(
                TransactionReadError::ResourceNotFound
            ))
        );
        assert_eq!(
            service
                .list(
                    Some("secret"),
                    Some("org-123"),
                    "org-123",
                    Some("PENDING"),
                    None
                )
                .await,
            Err(InternalApplicationServiceError::InvalidStatus)
        );
        assert_eq!(
            service
                .list(
                    Some("secret"),
                    Some("org-123"),
                    "org-123",
                    Some("pending"),
                    Some("template-1")
                )
                .await
                .expect("filtered applications")
                .len(),
            1
        );
        assert!(service
            .list(
                Some("secret"),
                Some("org-123"),
                "org-123",
                Some(""),
                Some("missing")
            )
            .await
            .expect("empty status means no status filter")
            .is_empty());
    }

    #[tokio::test]
    async fn managed_reads_hide_foreign_and_missing_applications_identically() {
        let (repository, _, service) =
            fixture(Some(template("org-123", ApplicationTemplateStatus::Active)));
        let application = create_named(&service).await;
        assert_eq!(
            service
                .get(Some("secret"), Some("org-123"), &application.id)
                .await,
            Ok(application)
        );
        assert_eq!(
            service
                .get(Some("secret"), Some("org-other"), "application-1")
                .await,
            Err(InternalApplicationServiceError::ApplicationNotFound)
        );
        repository
            .applications
            .lock()
            .expect("applications lock")
            .clear();
        assert_eq!(
            service
                .get(Some("secret"), Some("org-123"), "application-1")
                .await,
            Err(InternalApplicationServiceError::ApplicationNotFound)
        );
    }

    #[tokio::test]
    async fn evidence_submission_is_pending_only_and_uses_revision_cas() {
        let (repository, _, service) =
            fixture(Some(template("org-123", ApplicationTemplateStatus::Active)));
        let application = create_named(&service).await;
        let updated = service
            .submit_evidence(
                Some("secret"),
                Some("org-123"),
                &application.id,
                EvidenceSubmission {
                    evidence_type: "DOCUMENT_SCAN".to_owned(),
                    evidence_data: Map::from_iter([("digest".to_owned(), json!("sha256:1"))]),
                },
            )
            .await
            .expect("evidence submission");
        assert_eq!(updated.evidence_submissions.len(), 1);

        repository
            .reject_compare_and_swap
            .store(true, Ordering::SeqCst);
        assert_eq!(
            service
                .submit_evidence(
                    Some("secret"),
                    Some("org-123"),
                    &application.id,
                    EvidenceSubmission {
                        evidence_type: "DOCUMENT_SCAN".to_owned(),
                        evidence_data: Map::new(),
                    },
                )
                .await,
            Err(InternalApplicationServiceError::EvidenceConflict)
        );
    }

    #[tokio::test]
    async fn rejection_is_server_attributed_pending_only_and_uses_revision_cas() {
        let (_, _, service) = fixture(Some(template("org-123", ApplicationTemplateStatus::Active)));
        let application = create_named(&service).await;
        let rejected = service
            .reject(
                Some("secret"),
                Some("org-123"),
                &application.id,
                ApplicationRejection {
                    review_notes: "Insufficient evidence".to_owned(),
                },
            )
            .await
            .expect("rejection");
        assert_eq!(rejected.status, ApplicationStatus::Rejected);
        assert_eq!(
            rejected.reviewer_id.as_deref(),
            Some("issuance-management-api")
        );
        assert_eq!(rejected.reviewed_at, Some(now()));

        let domain_error = service
            .reject(
                Some("secret"),
                Some("org-123"),
                &application.id,
                ApplicationRejection {
                    review_notes: "Again".to_owned(),
                },
            )
            .await
            .expect_err("rejected application cannot be rejected again");
        assert!(matches!(
            domain_error,
            InternalApplicationServiceError::Domain(
                ApplicationDomainError::InvalidTransition { .. }
            )
        ));

        let (repository, _, service) =
            fixture(Some(template("org-123", ApplicationTemplateStatus::Active)));
        let application = create_named(&service).await;
        repository
            .reject_compare_and_swap
            .store(true, Ordering::SeqCst);
        assert_eq!(
            service
                .reject(
                    Some("secret"),
                    Some("org-123"),
                    &application.id,
                    ApplicationRejection {
                        review_notes: "Insufficient evidence".to_owned(),
                    },
                )
                .await,
            Err(InternalApplicationServiceError::RejectionConflict)
        );
    }
}
