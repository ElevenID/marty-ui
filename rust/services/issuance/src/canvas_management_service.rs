//! Application service for the Canvas platform-management lifecycle.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use thiserror::Error;

use crate::{
    canvas_management::CanvasPlatformRequest,
    canvas_management_domain::{
        CanvasManagementDomainError, CanvasOriginPolicy, CanvasPlatformRecord,
    },
    management_security::ManagementSecurity,
    transaction_reads::TransactionReadError,
};

#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum CanvasManagementRepositoryError {
    #[error("Canvas management repository is unavailable")]
    Unavailable,
    #[error("Canvas platform already exists")]
    Duplicate,
}

#[derive(Debug, Error, PartialEq)]
pub enum CanvasPlatformManagementError {
    #[error(transparent)]
    Security(#[from] TransactionReadError),
    #[error(transparent)]
    Domain(#[from] CanvasManagementDomainError),
    #[error("Canvas platform not found")]
    PlatformNotFound,
    #[error("Canvas platform configuration changed; retry the request")]
    ConfigurationChanged,
    #[error("Canvas platform conflicts with an existing resource")]
    Conflict,
    #[error("Canvas platform repository is unavailable")]
    RepositoryUnavailable,
}

#[async_trait]
pub trait CanvasPlatformManagementRepository: Send + Sync {
    async fn create_platform(
        &self,
        platform: &CanvasPlatformRecord,
    ) -> Result<(), CanvasManagementRepositoryError>;

    async fn active_platform(
        &self,
        organization_id: &str,
        platform_id: &str,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError>;

    async fn list_active_platforms(
        &self,
        organization_id: &str,
    ) -> Result<Vec<CanvasPlatformRecord>, CanvasManagementRepositoryError>;

    async fn save_platform_configuration(
        &self,
        platform: &CanvasPlatformRecord,
        expected_config_version: i64,
        configuration_changed: bool,
    ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError>;
}

#[derive(Clone)]
pub struct CanvasPlatformManagementService {
    repository: Arc<dyn CanvasPlatformManagementRepository>,
    security: ManagementSecurity,
    origin_policy: CanvasOriginPolicy,
}

impl std::fmt::Debug for CanvasPlatformManagementService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasPlatformManagementService")
            .field("security", &self.security)
            .field("origin_policy", &self.origin_policy)
            .finish_non_exhaustive()
    }
}

impl CanvasPlatformManagementService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn CanvasPlatformManagementRepository>,
        management_api_key: Option<&str>,
        origin_policy: CanvasOriginPolicy,
    ) -> Self {
        Self {
            repository,
            security: ManagementSecurity::new(management_api_key),
            origin_policy,
        }
    }

    pub fn authorize_request<'organization>(
        &self,
        api_key: Option<&str>,
        trusted_organization_id: Option<&'organization str>,
    ) -> Result<&'organization str, CanvasPlatformManagementError> {
        self.authorize(api_key, trusted_organization_id)
    }

    pub async fn create(
        &self,
        request: CanvasPlatformRequest,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<CanvasPlatformRecord, CanvasPlatformManagementError> {
        let organization_id = self.authorize(api_key, trusted_organization_id)?;
        let origin = self.origin_policy.resolve(&request.canvas_base_url)?;
        let platform = CanvasPlatformRecord::new_draft(
            organization_id.to_owned(),
            request,
            origin,
            Utc::now(),
        )?;
        self.repository
            .create_platform(&platform)
            .await
            .map_err(map_repository_error)?;
        Ok(platform)
    }

    pub async fn list(
        &self,
        claimed_organization_id: Option<&str>,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<Vec<CanvasPlatformRecord>, CanvasPlatformManagementError> {
        let organization_id =
            self.authorize_claimed(api_key, trusted_organization_id, claimed_organization_id)?;
        self.repository
            .list_active_platforms(organization_id)
            .await
            .map_err(map_repository_error)
    }

    pub async fn get(
        &self,
        platform_id: &str,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<CanvasPlatformRecord, CanvasPlatformManagementError> {
        let organization_id = self.authorize(api_key, trusted_organization_id)?;
        self.repository
            .active_platform(organization_id, platform_id)
            .await
            .map_err(map_repository_error)?
            .ok_or(CanvasPlatformManagementError::PlatformNotFound)
    }

    pub async fn update(
        &self,
        platform_id: &str,
        request: CanvasPlatformRequest,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<CanvasPlatformRecord, CanvasPlatformManagementError> {
        let organization_id = self.authorize(api_key, trusted_organization_id)?;
        let mut platform = self
            .repository
            .active_platform(organization_id, platform_id)
            .await
            .map_err(map_repository_error)?
            .ok_or(CanvasPlatformManagementError::PlatformNotFound)?;
        let expected_config_version = platform.config_version;
        let origin = self.origin_policy.resolve(&request.canvas_base_url)?;
        let configuration_changed = platform.reconfigure(request, origin, Utc::now())?;
        self.repository
            .save_platform_configuration(&platform, expected_config_version, configuration_changed)
            .await
            .map_err(map_repository_error)?
            .ok_or(CanvasPlatformManagementError::ConfigurationChanged)
    }

    fn authorize<'organization>(
        &self,
        api_key: Option<&str>,
        trusted_organization_id: Option<&'organization str>,
    ) -> Result<&'organization str, CanvasPlatformManagementError> {
        self.security.authorize(api_key)?;
        trusted_organization_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or({
                CanvasPlatformManagementError::Security(
                    TransactionReadError::TrustedOrganizationRequired,
                )
            })
    }

    fn authorize_claimed<'organization>(
        &self,
        api_key: Option<&str>,
        trusted_organization_id: Option<&'organization str>,
        claimed_organization_id: Option<&str>,
    ) -> Result<&'organization str, CanvasPlatformManagementError> {
        let trusted = self.authorize(api_key, trusted_organization_id)?;
        let claimed = claimed_organization_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or({
                CanvasPlatformManagementError::Security(
                    TransactionReadError::OrganizationIdRequired,
                )
            })?;
        self.security
            .require_organization(Some(trusted), claimed, true)?;
        Ok(trusted)
    }
}

fn map_repository_error(error: CanvasManagementRepositoryError) -> CanvasPlatformManagementError {
    match error {
        CanvasManagementRepositoryError::Duplicate => CanvasPlatformManagementError::Conflict,
        CanvasManagementRepositoryError::Unavailable => {
            CanvasPlatformManagementError::RepositoryUnavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct MemoryRepository {
        platforms: Mutex<Vec<CanvasPlatformRecord>>,
        force_conflict: Mutex<bool>,
    }

    #[async_trait]
    impl CanvasPlatformManagementRepository for MemoryRepository {
        async fn create_platform(
            &self,
            platform: &CanvasPlatformRecord,
        ) -> Result<(), CanvasManagementRepositoryError> {
            let mut platforms = self.platforms.lock().await;
            if platforms
                .iter()
                .any(|candidate| candidate.id == platform.id)
            {
                return Err(CanvasManagementRepositoryError::Duplicate);
            }
            platforms.push(platform.clone());
            Ok(())
        }

        async fn active_platform(
            &self,
            organization_id: &str,
            platform_id: &str,
        ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
            Ok(self
                .platforms
                .lock()
                .await
                .iter()
                .find(|platform| {
                    platform.organization_id == organization_id
                        && platform.id == platform_id
                        && platform.archived_at.is_none()
                })
                .cloned())
        }

        async fn list_active_platforms(
            &self,
            organization_id: &str,
        ) -> Result<Vec<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
            Ok(self
                .platforms
                .lock()
                .await
                .iter()
                .filter(|platform| {
                    platform.organization_id == organization_id && platform.archived_at.is_none()
                })
                .cloned()
                .collect())
        }

        async fn save_platform_configuration(
            &self,
            platform: &CanvasPlatformRecord,
            expected_config_version: i64,
            _configuration_changed: bool,
        ) -> Result<Option<CanvasPlatformRecord>, CanvasManagementRepositoryError> {
            if *self.force_conflict.lock().await {
                return Ok(None);
            }
            let mut platforms = self.platforms.lock().await;
            let Some(existing) = platforms.iter_mut().find(|candidate| {
                candidate.organization_id == platform.organization_id
                    && candidate.id == platform.id
                    && candidate.archived_at.is_none()
                    && candidate.config_version == expected_config_version
            }) else {
                return Ok(None);
            };
            *existing = platform.clone();
            Ok(Some(existing.clone()))
        }
    }

    fn request(name: &str, enabled: bool) -> CanvasPlatformRequest {
        CanvasPlatformRequest {
            display_name: Some(name.to_owned()),
            canvas_base_url: "https://canvas.example.edu".to_owned(),
            lti_client_id: Some("client".to_owned()),
            lti_deployment_id: Some("deployment".to_owned()),
            enabled,
        }
    }

    fn service(repository: Arc<MemoryRepository>) -> CanvasPlatformManagementService {
        CanvasPlatformManagementService::new(
            repository,
            Some("management-secret"),
            CanvasOriginPolicy::default(),
        )
    }

    #[tokio::test]
    async fn create_list_get_and_update_share_one_security_boundary() {
        let repository = Arc::new(MemoryRepository::default());
        let service = service(repository);
        let created = service
            .create(
                request("Original", true),
                Some("management-secret"),
                Some("org-1"),
            )
            .await
            .unwrap();
        assert_eq!(created.organization_id, "org-1");
        assert!(!created.enabled);
        assert_eq!(created.connection_config["enabled_intent"], true);

        assert_eq!(
            service
                .list(Some("org-1"), Some("management-secret"), Some("org-1"))
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            service
                .get(&created.id, Some("management-secret"), Some("org-1"))
                .await
                .unwrap()
                .id,
            created.id
        );
        let updated = service
            .update(
                &created.id,
                request("Updated", true),
                Some("management-secret"),
                Some("org-1"),
            )
            .await
            .unwrap();
        assert_eq!(updated.display_name.as_deref(), Some("Updated"));
        assert_eq!(updated.config_version, 2);
    }

    #[tokio::test]
    async fn tenant_mismatch_and_archived_or_foreign_resources_are_hidden() {
        let repository = Arc::new(MemoryRepository::default());
        let service = service(repository);
        let created = service
            .create(
                request("Original", false),
                Some("management-secret"),
                Some("org-1"),
            )
            .await
            .unwrap();
        assert_eq!(
            service
                .list(Some("org-2"), Some("management-secret"), Some("org-1"))
                .await,
            Err(CanvasPlatformManagementError::Security(
                TransactionReadError::ResourceNotFound
            ))
        );
        assert_eq!(
            service
                .get(&created.id, Some("management-secret"), Some("org-2"))
                .await,
            Err(CanvasPlatformManagementError::PlatformNotFound)
        );
    }

    #[tokio::test]
    async fn missing_credentials_and_stale_writes_fail_closed() {
        let repository = Arc::new(MemoryRepository::default());
        let service = service(repository.clone());
        assert_eq!(
            service
                .create(request("Original", false), None, Some("org-1"))
                .await,
            Err(CanvasPlatformManagementError::Security(
                TransactionReadError::ApiKeyMissing
            ))
        );
        let created = service
            .create(
                request("Original", false),
                Some("management-secret"),
                Some("org-1"),
            )
            .await
            .unwrap();
        *repository.force_conflict.lock().await = true;
        assert_eq!(
            service
                .update(
                    &created.id,
                    request("Changed", false),
                    Some("management-secret"),
                    Some("org-1"),
                )
                .await,
            Err(CanvasPlatformManagementError::ConfigurationChanged)
        );
    }

    #[tokio::test]
    async fn invalid_origins_are_rejected_before_repository_access() {
        let repository = Arc::new(MemoryRepository::default());
        let service = service(repository.clone());
        let mut invalid = request("Invalid", false);
        invalid.canvas_base_url = "https://user:secret@canvas.example.edu".to_owned();
        assert!(matches!(
            service
                .create(invalid, Some("management-secret"), Some("org-1"))
                .await,
            Err(CanvasPlatformManagementError::Domain(
                CanvasManagementDomainError::OriginUntrusted
            ))
        ));
        assert!(repository.platforms.lock().await.is_empty());
    }
}
