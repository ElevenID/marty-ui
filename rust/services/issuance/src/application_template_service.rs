//! Shared Application Template management use cases.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    application_template_domain::{
        validate_application_template, ApplicationTemplateCreate,
        ApplicationTemplateLifecycleError, ApplicationTemplatePatch, ApplicationTemplateRecord,
        ApplicationTemplateRequestError, ApplicationTemplateValidationError,
        ApprovalPolicyValidationState, ApprovalPolicyValidationView,
        CredentialTemplateValidationState, CredentialTemplateValidationView,
    },
    canvas_award_candidate::python_canonical_json,
    initiation::normalize_idempotency_key,
    management_security::ManagementSecurity,
    transaction_reads::TransactionReadError,
};

const KEY_HASH_PREFIX: &str = "marty:application-template-idempotency-key:v1:";
const REQUEST_HASH_PREFIX: &str = "marty:application-template-request:v1:";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationTemplateIdempotencyBinding {
    pub key_hash: String,
    pub request_hash: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ApplicationTemplateReservation {
    pub template: ApplicationTemplateRecord,
    pub created: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalPolicyRecord {
    pub policy_type: String,
    pub status: String,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ApplicationTemplateRepositoryError {
    #[error("idempotency key was already used for a different Application Template request")]
    IdempotencyConflict,
    #[error("Application Template changed concurrently; refresh and retry")]
    ConcurrentModification,
    #[error("Application Template repository is unavailable")]
    Unavailable,
}

#[async_trait]
pub trait ApplicationTemplateRepository: Send + Sync {
    async fn reserve_idempotently(
        &self,
        template: &ApplicationTemplateRecord,
        binding: &ApplicationTemplateIdempotencyBinding,
    ) -> Result<ApplicationTemplateReservation, ApplicationTemplateRepositoryError>;

    async fn list(
        &self,
        organization_id: &str,
    ) -> Result<Vec<ApplicationTemplateRecord>, ApplicationTemplateRepositoryError>;

    async fn get(
        &self,
        organization_id: &str,
        template_id: &str,
    ) -> Result<Option<ApplicationTemplateRecord>, ApplicationTemplateRepositoryError>;

    async fn replace_if_version(
        &self,
        template: &ApplicationTemplateRecord,
        expected_version: i64,
    ) -> Result<(), ApplicationTemplateRepositoryError>;

    async fn delete_if_version(
        &self,
        organization_id: &str,
        template_id: &str,
        expected_version: i64,
    ) -> Result<(), ApplicationTemplateRepositoryError>;

    async fn approval_policy(
        &self,
        organization_id: &str,
        policy_set_id: &str,
    ) -> Result<Option<ApprovalPolicyRecord>, ApplicationTemplateRepositoryError>;
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ApplicationTemplateCatalogError {
    #[error("Credential Template catalog is unavailable")]
    Unavailable,
}

#[async_trait]
pub trait ApplicationTemplateCatalog: Send + Sync {
    async fn get_strict(
        &self,
        template_id: &str,
    ) -> Result<Option<CredentialTemplateValidationView>, ApplicationTemplateCatalogError>;
}

pub trait ApplicationTemplateClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Clone, Debug, Default)]
pub struct SystemApplicationTemplateClock;

impl ApplicationTemplateClock for SystemApplicationTemplateClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Clone)]
pub struct ApplicationTemplateService {
    repository: Arc<dyn ApplicationTemplateRepository>,
    catalog: Arc<dyn ApplicationTemplateCatalog>,
    clock: Arc<dyn ApplicationTemplateClock>,
    security: ManagementSecurity,
}

impl std::fmt::Debug for ApplicationTemplateService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApplicationTemplateService")
            .field("security", &self.security)
            .finish_non_exhaustive()
    }
}

impl ApplicationTemplateService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn ApplicationTemplateRepository>,
        catalog: Arc<dyn ApplicationTemplateCatalog>,
        clock: Arc<dyn ApplicationTemplateClock>,
        management_api_key: Option<&str>,
    ) -> Self {
        Self {
            repository,
            catalog,
            clock,
            security: ManagementSecurity::new(management_api_key),
        }
    }

    pub async fn create(
        &self,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
        idempotency_key: Option<&str>,
        mut request: ApplicationTemplateCreate,
    ) -> Result<ApplicationTemplateRecord, ApplicationTemplateServiceError> {
        self.security.authorize(api_key)?;
        let organization_id = request.organization_id.trim().to_owned();
        self.security
            .require_organization(trusted_organization, &organization_id, false)?;
        request.organization_id = organization_id;
        request.validate_transport()?;
        let binding = application_template_idempotency_binding(idempotency_key, &request)?;
        let template = ApplicationTemplateRecord::new(request, self.clock.now())?;
        Ok(self
            .repository
            .reserve_idempotently(&template, &binding)
            .await?
            .template)
    }

    pub async fn list(
        &self,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
        claimed_organization: &str,
    ) -> Result<Vec<ApplicationTemplateRecord>, ApplicationTemplateServiceError> {
        self.security.authorize(api_key)?;
        let claimed_organization = claimed_organization.trim();
        self.security
            .require_organization(trusted_organization, claimed_organization, false)?;
        self.repository
            .list(claimed_organization)
            .await
            .map_err(Into::into)
    }

    pub async fn get(
        &self,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
        template_id: &str,
    ) -> Result<ApplicationTemplateRecord, ApplicationTemplateServiceError> {
        self.security.authorize(api_key)?;
        let organization_id = required_organization(trusted_organization)?;
        self.load(organization_id, template_id).await
    }

    pub async fn patch(
        &self,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
        template_id: &str,
        patch: ApplicationTemplatePatch,
    ) -> Result<ApplicationTemplateRecord, ApplicationTemplateServiceError> {
        self.security.authorize(api_key)?;
        let organization_id = required_organization(trusted_organization)?;
        let mut template = self.load(organization_id, template_id).await?;
        let expected_version = template.version;
        patch.apply(&mut template, self.clock.now())?;
        self.repository
            .replace_if_version(&template, expected_version)
            .await?;
        Ok(template)
    }

    pub async fn validate(
        &self,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
        template_id: &str,
    ) -> Result<ApplicationTemplateValidation, ApplicationTemplateServiceError> {
        self.security.authorize(api_key)?;
        let organization_id = required_organization(trusted_organization)?;
        let template = self.load(organization_id, template_id).await?;
        let errors = self.validation_errors(&template).await?;
        Ok(ApplicationTemplateValidation {
            valid: errors.is_empty(),
            errors,
        })
    }

    pub async fn activate(
        &self,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
        template_id: &str,
    ) -> Result<ApplicationTemplateRecord, ApplicationTemplateServiceError> {
        self.security.authorize(api_key)?;
        let organization_id = required_organization(trusted_organization)?;
        let mut template = self.load(organization_id, template_id).await?;
        template.require_draft_activation()?;
        let expected_version = template.version;
        let errors = self.validation_errors(&template).await?;
        if !errors.is_empty() {
            return Err(ApplicationTemplateServiceError::Validation(errors));
        }
        template.activate(&[], self.clock.now())?;
        self.repository
            .replace_if_version(&template, expected_version)
            .await?;
        Ok(template)
    }

    pub fn preflight_json_request(
        &self,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
    ) -> Result<(), ApplicationTemplateServiceError> {
        self.security.authorize(api_key)?;
        required_organization(trusted_organization)?;
        Ok(())
    }

    pub fn preflight_create(
        &self,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> Result<(), ApplicationTemplateServiceError> {
        self.preflight_json_request(api_key, trusted_organization)?;
        validated_idempotency_key(idempotency_key)?;
        Ok(())
    }

    pub async fn deprecate(
        &self,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
        template_id: &str,
    ) -> Result<ApplicationTemplateRecord, ApplicationTemplateServiceError> {
        self.security.authorize(api_key)?;
        let organization_id = required_organization(trusted_organization)?;
        let mut template = self.load(organization_id, template_id).await?;
        let expected_version = template.version;
        template.deprecate(self.clock.now())?;
        self.repository
            .replace_if_version(&template, expected_version)
            .await?;
        Ok(template)
    }

    pub async fn delete(
        &self,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
        template_id: &str,
    ) -> Result<(), ApplicationTemplateServiceError> {
        self.security.authorize(api_key)?;
        let organization_id = required_organization(trusted_organization)?;
        let template = self.load(organization_id, template_id).await?;
        template.require_draft_delete()?;
        self.repository
            .delete_if_version(organization_id, template_id, template.version)
            .await
            .map_err(Into::into)
    }

    async fn load(
        &self,
        organization_id: &str,
        template_id: &str,
    ) -> Result<ApplicationTemplateRecord, ApplicationTemplateServiceError> {
        self.repository
            .get(organization_id, template_id)
            .await?
            .ok_or(ApplicationTemplateServiceError::NotFound)
    }

    async fn validation_errors(
        &self,
        template: &ApplicationTemplateRecord,
    ) -> Result<Vec<ApplicationTemplateValidationError>, ApplicationTemplateServiceError> {
        let credential_template = match template
            .credential_template_id
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            None => CredentialTemplateValidationState::MissingReference,
            Some(template_id) => match self.catalog.get_strict(template_id).await {
                Ok(Some(template)) => CredentialTemplateValidationState::Found(template),
                Ok(None) => CredentialTemplateValidationState::NotFound,
                Err(ApplicationTemplateCatalogError::Unavailable) => {
                    CredentialTemplateValidationState::Unavailable
                }
            },
        };
        let approval_policy = if template.approval_strategy == "RULES_BASED" {
            match template
                .approval_policy_set_id
                .as_deref()
                .filter(|value| !value.is_empty())
            {
                None => ApprovalPolicyValidationState::NotRequested,
                Some(policy_set_id) => match self
                    .repository
                    .approval_policy(&template.organization_id, policy_set_id)
                    .await?
                {
                    None => ApprovalPolicyValidationState::NotFound,
                    Some(policy) => {
                        ApprovalPolicyValidationState::Found(ApprovalPolicyValidationView {
                            policy_type: policy.policy_type,
                            status: policy.status,
                        })
                    }
                },
            }
        } else {
            ApprovalPolicyValidationState::NotRequested
        };
        Ok(validate_application_template(
            template,
            &credential_template,
            &approval_policy,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApplicationTemplateValidation {
    pub valid: bool,
    pub errors: Vec<ApplicationTemplateValidationError>,
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum ApplicationTemplateServiceError {
    #[error(transparent)]
    Security(#[from] TransactionReadError),
    #[error(transparent)]
    Request(#[from] ApplicationTemplateRequestError),
    #[error(transparent)]
    Lifecycle(#[from] ApplicationTemplateLifecycleError),
    #[error(transparent)]
    Repository(#[from] ApplicationTemplateRepositoryError),
    #[error("Application template not found")]
    NotFound,
    #[error("Application Template is invalid")]
    Validation(Vec<ApplicationTemplateValidationError>),
    #[error("Idempotency-Key header is required")]
    IdempotencyRequired,
    #[error("Idempotency-Key header is invalid")]
    InvalidIdempotencyKey,
    #[error("Application Template request could not be canonicalized")]
    Canonicalization,
}

fn application_template_idempotency_binding(
    raw_key: Option<&str>,
    request: &ApplicationTemplateCreate,
) -> Result<ApplicationTemplateIdempotencyBinding, ApplicationTemplateServiceError> {
    let key = validated_idempotency_key(raw_key)?;
    let semantic = serde_json::to_value(request)
        .map_err(|_| ApplicationTemplateServiceError::Canonicalization)?;
    Ok(ApplicationTemplateIdempotencyBinding {
        key_hash: sha256(format!("{KEY_HASH_PREFIX}{key}").as_bytes()),
        request_hash: sha256(
            format!("{REQUEST_HASH_PREFIX}{}", python_canonical_json(&semantic)).as_bytes(),
        ),
    })
}

fn validated_idempotency_key(
    raw_key: Option<&str>,
) -> Result<String, ApplicationTemplateServiceError> {
    normalize_idempotency_key(raw_key)
        .map_err(|_| ApplicationTemplateServiceError::InvalidIdempotencyKey)?
        .ok_or(ApplicationTemplateServiceError::IdempotencyRequired)
}

fn required_organization(value: Option<&str>) -> Result<&str, TransactionReadError> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(TransactionReadError::TrustedOrganizationRequired)
}

fn sha256(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet, HashMap},
        sync::{
            atomic::{AtomicBool, Ordering},
            Mutex,
        },
    };

    use chrono::TimeZone;
    use serde_json::json;

    use super::*;
    use crate::application_template_domain::ApplicationTemplateStatus;

    #[derive(Default)]
    struct RepositoryState {
        templates: BTreeMap<(String, String), ApplicationTemplateRecord>,
        idempotency: HashMap<(String, String), (String, String)>,
        approval_policies: HashMap<(String, String), ApprovalPolicyRecord>,
        reserve_calls: usize,
    }

    #[derive(Default)]
    struct MemoryRepository {
        state: Mutex<RepositoryState>,
        fail_next_replace: AtomicBool,
    }

    impl MemoryRepository {
        fn template(&self, organization_id: &str, template_id: &str) -> ApplicationTemplateRecord {
            self.state
                .lock()
                .expect("repository state")
                .templates
                .get(&(organization_id.to_owned(), template_id.to_owned()))
                .cloned()
                .expect("stored template")
        }

        fn template_count(&self) -> usize {
            self.state.lock().expect("repository state").templates.len()
        }

        fn reserve_calls(&self) -> usize {
            self.state.lock().expect("repository state").reserve_calls
        }
    }

    #[async_trait]
    impl ApplicationTemplateRepository for MemoryRepository {
        async fn reserve_idempotently(
            &self,
            template: &ApplicationTemplateRecord,
            binding: &ApplicationTemplateIdempotencyBinding,
        ) -> Result<ApplicationTemplateReservation, ApplicationTemplateRepositoryError> {
            let mut state = self.state.lock().expect("repository state");
            state.reserve_calls += 1;
            let binding_key = (template.organization_id.clone(), binding.key_hash.clone());
            if let Some((request_hash, template_id)) = state.idempotency.get(&binding_key) {
                if request_hash != &binding.request_hash {
                    return Err(ApplicationTemplateRepositoryError::IdempotencyConflict);
                }
                let existing = state
                    .templates
                    .get(&(template.organization_id.clone(), template_id.clone()))
                    .cloned()
                    .expect("idempotency binding must reference a template");
                return Ok(ApplicationTemplateReservation {
                    template: existing,
                    created: false,
                });
            }
            state.idempotency.insert(
                binding_key,
                (binding.request_hash.clone(), template.id.clone()),
            );
            state.templates.insert(
                (template.organization_id.clone(), template.id.clone()),
                template.clone(),
            );
            Ok(ApplicationTemplateReservation {
                template: template.clone(),
                created: true,
            })
        }

        async fn list(
            &self,
            organization_id: &str,
        ) -> Result<Vec<ApplicationTemplateRecord>, ApplicationTemplateRepositoryError> {
            let mut templates = self
                .state
                .lock()
                .expect("repository state")
                .templates
                .values()
                .filter(|template| template.organization_id == organization_id)
                .cloned()
                .collect::<Vec<_>>();
            templates.sort_by(|left, right| {
                left.created_at
                    .cmp(&right.created_at)
                    .then_with(|| left.id.cmp(&right.id))
            });
            Ok(templates)
        }

        async fn get(
            &self,
            organization_id: &str,
            template_id: &str,
        ) -> Result<Option<ApplicationTemplateRecord>, ApplicationTemplateRepositoryError> {
            Ok(self
                .state
                .lock()
                .expect("repository state")
                .templates
                .get(&(organization_id.to_owned(), template_id.to_owned()))
                .cloned())
        }

        async fn replace_if_version(
            &self,
            template: &ApplicationTemplateRecord,
            expected_version: i64,
        ) -> Result<(), ApplicationTemplateRepositoryError> {
            if self.fail_next_replace.swap(false, Ordering::SeqCst) {
                return Err(ApplicationTemplateRepositoryError::ConcurrentModification);
            }
            let mut state = self.state.lock().expect("repository state");
            let stored = state
                .templates
                .get_mut(&(template.organization_id.clone(), template.id.clone()))
                .ok_or(ApplicationTemplateRepositoryError::ConcurrentModification)?;
            if stored.version != expected_version {
                return Err(ApplicationTemplateRepositoryError::ConcurrentModification);
            }
            *stored = template.clone();
            Ok(())
        }

        async fn delete_if_version(
            &self,
            organization_id: &str,
            template_id: &str,
            expected_version: i64,
        ) -> Result<(), ApplicationTemplateRepositoryError> {
            let mut state = self.state.lock().expect("repository state");
            let key = (organization_id.to_owned(), template_id.to_owned());
            if state.templates.get(&key).map(|template| template.version) != Some(expected_version)
            {
                return Err(ApplicationTemplateRepositoryError::ConcurrentModification);
            }
            state.templates.remove(&key);
            Ok(())
        }

        async fn approval_policy(
            &self,
            organization_id: &str,
            policy_set_id: &str,
        ) -> Result<Option<ApprovalPolicyRecord>, ApplicationTemplateRepositoryError> {
            Ok(self
                .state
                .lock()
                .expect("repository state")
                .approval_policies
                .get(&(organization_id.to_owned(), policy_set_id.to_owned()))
                .cloned())
        }
    }

    struct FixedCatalog {
        result: Mutex<
            Result<Option<CredentialTemplateValidationView>, ApplicationTemplateCatalogError>,
        >,
    }

    struct UnexpectedCatalog;

    #[async_trait]
    impl ApplicationTemplateCatalog for UnexpectedCatalog {
        async fn get_strict(
            &self,
            _template_id: &str,
        ) -> Result<Option<CredentialTemplateValidationView>, ApplicationTemplateCatalogError>
        {
            panic!("invalid lifecycle transitions must not call the catalog")
        }
    }

    #[async_trait]
    impl ApplicationTemplateCatalog for FixedCatalog {
        async fn get_strict(
            &self,
            _template_id: &str,
        ) -> Result<Option<CredentialTemplateValidationView>, ApplicationTemplateCatalogError>
        {
            self.result.lock().expect("catalog result").clone()
        }
    }

    #[derive(Clone)]
    struct FixedClock(DateTime<Utc>);

    impl ApplicationTemplateClock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 19, 12, 0, 0)
            .single()
            .expect("fixed timestamp")
    }

    fn request() -> ApplicationTemplateCreate {
        serde_json::from_value(json!({
            "organization_id": "org-a",
            "name": "Membership application",
            "credential_template_id": "credential-template-1",
            "form_fields": [{
                "field_id": "membership_number",
                "label": "Membership number",
                "field_type": "TEXT",
                "required": true
            }]
        }))
        .expect("valid request")
    }

    fn catalog_result(
        result: Result<Option<CredentialTemplateValidationView>, ApplicationTemplateCatalogError>,
    ) -> Arc<FixedCatalog> {
        Arc::new(FixedCatalog {
            result: Mutex::new(result),
        })
    }

    fn valid_catalog() -> Arc<FixedCatalog> {
        catalog_result(Ok(Some(CredentialTemplateValidationView {
            organization_id: "org-a".to_owned(),
            status: "ACTIVE".to_owned(),
            revocation_profile_id: Some("revocation-profile-1".to_owned()),
            claims: BTreeSet::new(),
        })))
    }

    fn service(
        repository: Arc<MemoryRepository>,
        catalog: Arc<FixedCatalog>,
        api_key: Option<&str>,
    ) -> ApplicationTemplateService {
        ApplicationTemplateService::new(repository, catalog, Arc::new(FixedClock(now())), api_key)
    }

    #[tokio::test]
    async fn authentication_tenant_and_idempotency_fail_closed_before_mutation() {
        let repository = Arc::new(MemoryRepository::default());
        let unconfigured = service(repository.clone(), valid_catalog(), None);
        assert_eq!(
            unconfigured
                .create(Some("secret"), Some("org-a"), Some("key-1"), request())
                .await,
            Err(ApplicationTemplateServiceError::Security(
                TransactionReadError::ApiKeyNotConfigured
            ))
        );

        let service = service(repository.clone(), valid_catalog(), Some("secret"));
        for (api_key, organization, expected) in [
            (None, Some("org-a"), TransactionReadError::ApiKeyMissing),
            (
                Some("wrong"),
                Some("org-a"),
                TransactionReadError::InvalidApiKey,
            ),
            (
                Some("secret"),
                None,
                TransactionReadError::TrustedOrganizationRequired,
            ),
            (
                Some("secret"),
                Some("org-b"),
                TransactionReadError::OrganizationMismatch,
            ),
        ] {
            assert_eq!(
                service
                    .create(api_key, organization, Some("key-1"), request())
                    .await,
                Err(ApplicationTemplateServiceError::Security(expected))
            );
        }
        assert_eq!(repository.reserve_calls(), 0);

        assert_eq!(
            service
                .create(Some("secret"), Some("org-a"), None, request())
                .await,
            Err(ApplicationTemplateServiceError::IdempotencyRequired)
        );
        assert_eq!(
            service
                .create(Some("secret"), Some("org-a"), Some(" bad key "), request(),)
                .await,
            Err(ApplicationTemplateServiceError::InvalidIdempotencyKey)
        );
        assert_eq!(repository.reserve_calls(), 0);

        let first = service
            .create(Some("secret"), Some("org-a"), Some("key-1"), request())
            .await
            .expect("first create");
        let replay = service
            .create(Some("secret"), Some("org-a"), Some("key-1"), request())
            .await
            .expect("idempotent replay");
        assert_eq!(replay.id, first.id);
        assert_eq!(repository.template_count(), 1);

        let mut conflicting = request();
        conflicting.name = "Different application".to_owned();
        assert_eq!(
            service
                .create(Some("secret"), Some("org-a"), Some("key-1"), conflicting,)
                .await,
            Err(ApplicationTemplateServiceError::Repository(
                ApplicationTemplateRepositoryError::IdempotencyConflict
            ))
        );
        assert_eq!(repository.template_count(), 1);
    }

    #[tokio::test]
    async fn collection_tenant_values_are_canonicalized_like_the_frozen_boundary() {
        let repository = Arc::new(MemoryRepository::default());
        let service = service(repository, valid_catalog(), Some("secret"));
        let mut create = request();
        create.organization_id = " org-a ".to_owned();
        create.credential_template_id = Some(" credential-template-1 ".to_owned());
        let created = service
            .create(
                Some("secret"),
                Some(" org-a "),
                Some("canonical-tenant"),
                create,
            )
            .await
            .expect("trimmed tenant create");
        assert_eq!(created.organization_id, "org-a");
        assert_eq!(
            created.credential_template_id.as_deref(),
            Some(" credential-template-1 ")
        );
        assert_eq!(
            service
                .list(Some("secret"), Some("org-a"), " org-a ")
                .await
                .expect("trimmed tenant list")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn item_reads_hide_foreign_tenants_and_list_rejects_claimed_mismatch() {
        let repository = Arc::new(MemoryRepository::default());
        let service = service(repository, valid_catalog(), Some("secret"));
        let created = service
            .create(Some("secret"), Some("org-a"), Some("key-1"), request())
            .await
            .expect("create");

        assert_eq!(
            service
                .get(Some("secret"), Some("org-b"), &created.id)
                .await,
            Err(ApplicationTemplateServiceError::NotFound)
        );
        assert_eq!(
            service.list(Some("secret"), Some("org-b"), "org-a").await,
            Err(ApplicationTemplateServiceError::Security(
                TransactionReadError::OrganizationMismatch
            ))
        );
        assert_eq!(
            service
                .list(Some("secret"), Some("org-a"), "org-a")
                .await
                .expect("tenant list")
                .iter()
                .map(|template| template.id.as_str())
                .collect::<Vec<_>>(),
            vec![created.id.as_str()]
        );
    }

    #[tokio::test]
    async fn validation_and_lifecycle_persist_only_successful_transitions() {
        let repository = Arc::new(MemoryRepository::default());
        let service = service(repository.clone(), valid_catalog(), Some("secret"));
        let created = service
            .create(Some("secret"), Some("org-a"), Some("key-1"), request())
            .await
            .expect("create");

        let activated = service
            .activate(Some("secret"), Some("org-a"), &created.id)
            .await
            .expect("activate");
        assert_eq!(activated.status, ApplicationTemplateStatus::Active);
        assert_eq!(activated.version, 2);
        assert_eq!(
            service
                .delete(Some("secret"), Some("org-a"), &created.id)
                .await,
            Err(ApplicationTemplateServiceError::Lifecycle(
                ApplicationTemplateLifecycleError::DeleteRequiresDraft
            ))
        );
        assert_eq!(
            repository.template("org-a", &created.id).status,
            ApplicationTemplateStatus::Active
        );

        let deprecated = service
            .deprecate(Some("secret"), Some("org-a"), &created.id)
            .await
            .expect("deprecate");
        assert_eq!(deprecated.status, ApplicationTemplateStatus::Deprecated);
        assert_eq!(deprecated.version, 3);
    }

    #[tokio::test]
    async fn invalid_activation_state_precedes_dependency_validation() {
        let repository = Arc::new(MemoryRepository::default());
        let service = service(repository.clone(), valid_catalog(), Some("secret"));
        let created = service
            .create(Some("secret"), Some("org-a"), Some("key-state"), request())
            .await
            .expect("create");
        service
            .activate(Some("secret"), Some("org-a"), &created.id)
            .await
            .expect("first activation");

        let lifecycle_only = ApplicationTemplateService::new(
            repository,
            Arc::new(UnexpectedCatalog),
            Arc::new(FixedClock(now())),
            Some("secret"),
        );
        assert_eq!(
            lifecycle_only
                .activate(Some("secret"), Some("org-a"), &created.id)
                .await,
            Err(ApplicationTemplateServiceError::Lifecycle(
                ApplicationTemplateLifecycleError::ActivateRequiresDraft
            ))
        );
    }

    #[tokio::test]
    async fn dependency_and_compare_and_set_failures_leave_storage_unchanged() {
        let repository = Arc::new(MemoryRepository::default());
        let service = service(
            repository.clone(),
            catalog_result(Err(ApplicationTemplateCatalogError::Unavailable)),
            Some("secret"),
        );
        let created = service
            .create(Some("secret"), Some("org-a"), Some("key-1"), request())
            .await
            .expect("create");
        let validation = service
            .validate(Some("secret"), Some("org-a"), &created.id)
            .await
            .expect("validation response");
        assert!(!validation.valid);
        assert_eq!(validation.errors[0].code, "UNAVAILABLE");
        assert!(matches!(
            service
                .activate(Some("secret"), Some("org-a"), &created.id)
                .await,
            Err(ApplicationTemplateServiceError::Validation(_))
        ));
        assert_eq!(repository.template("org-a", &created.id).version, 1);

        repository.fail_next_replace.store(true, Ordering::SeqCst);
        let patch: ApplicationTemplatePatch =
            serde_json::from_value(json!({"name": "Updated name"})).expect("patch");
        assert_eq!(
            service
                .patch(Some("secret"), Some("org-a"), &created.id, patch)
                .await,
            Err(ApplicationTemplateServiceError::Repository(
                ApplicationTemplateRepositoryError::ConcurrentModification
            ))
        );
        let stored = repository.template("org-a", &created.id);
        assert_eq!(stored.name, "Membership application");
        assert_eq!(stored.version, 1);
    }
}
