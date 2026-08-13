use crate::{
    domain::{
        CredentialStatus, NewProfile, ProcessRevocation, RevocationProfile, RevocationProfileStatus,
    },
    repository::{ProfileRepository, RepositoryError},
    status::{StatusError, StatusListFormat, StatusListRecord, StatusRepository},
};
use marty_status::{MAX_STATUS_LIST_ENTRIES, W3C_MIN_STATUS_LIST_BITS};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ServiceError {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("revocation profile {0} was not found")]
    NotFound(String),
    #[error("revocation profile belongs to another organization")]
    PermissionDenied,
    #[error("operation cannot be completed: {0}")]
    FailedPrecondition(String),
    #[error("storage backend failed: {0}")]
    Storage(String),
    #[error("canonical status backend rejected the operation: {0}")]
    Native(String),
}

impl From<RepositoryError> for ServiceError {
    fn from(error: RepositoryError) -> Self {
        Self::Storage(error.to_string())
    }
}

impl From<StatusError> for ServiceError {
    fn from(error: StatusError) -> Self {
        match error {
            StatusError::Repository(_) => Self::Storage(error.to_string()),
            StatusError::Full(_) => Self::FailedPrecondition(error.to_string()),
            _ => Self::Native(error.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusOperationResult {
    pub organization_id: String,
    pub index: usize,
    pub status_list_url: String,
}

#[derive(Clone)]
pub struct RevocationProfileService {
    profiles: Arc<dyn ProfileRepository>,
    statuses: Arc<dyn StatusRepository>,
    public_base_url: String,
}

impl std::fmt::Debug for RevocationProfileService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RevocationProfileService")
            .field("public_base_url", &self.public_base_url)
            .finish_non_exhaustive()
    }
}

impl RevocationProfileService {
    pub fn new(
        profiles: Arc<dyn ProfileRepository>,
        statuses: Arc<dyn StatusRepository>,
        public_base_url: impl Into<String>,
    ) -> Result<Self, ServiceError> {
        let public_base_url = public_base_url.into().trim_end_matches('/').to_string();
        if !public_base_url.starts_with("https://") {
            return Err(ServiceError::InvalidArgument(
                "status-list public base URL must use HTTPS".into(),
            ));
        }
        Ok(Self {
            profiles,
            statuses,
            public_base_url,
        })
    }

    pub async fn create(&self, request: NewProfile) -> Result<RevocationProfile, ServiceError> {
        if request.organization_id.trim().is_empty() {
            return Err(ServiceError::InvalidArgument(
                "organization_id must not be empty".into(),
            ));
        }
        if request.name.trim().is_empty() {
            return Err(ServiceError::InvalidArgument(
                "name must not be empty".into(),
            ));
        }

        let mut profile =
            RevocationProfile::new(request.organization_id, request.name, request.description);
        if let Some(config) = request.issuer_config {
            profile.issuer_config = config;
        }
        if let Some(config) = request.verifier_config {
            profile.verifier_config = config;
        }
        if let Some(config) = request.automation_config {
            profile.automation_config = config;
        }
        if let Some(formats) = request.supported_formats {
            if formats.is_empty() {
                return Err(ServiceError::InvalidArgument(
                    "supported_formats must not be empty".into(),
                ));
            }
            profile.supported_formats = formats;
        }
        self.validate_profile(&profile)?;
        self.profiles.save(profile.clone()).await?;
        Ok(profile)
    }

    pub async fn get(&self, profile_id: &str) -> Result<RevocationProfile, ServiceError> {
        self.profiles
            .get(profile_id)
            .await?
            .ok_or_else(|| ServiceError::NotFound(profile_id.to_string()))
    }

    pub async fn list(
        &self,
        organization_id: &str,
    ) -> Result<Vec<RevocationProfile>, ServiceError> {
        if organization_id.trim().is_empty() {
            return Err(ServiceError::InvalidArgument(
                "organization_id must not be empty".into(),
            ));
        }
        Ok(self.profiles.list(organization_id).await?)
    }

    pub async fn activate(&self, profile_id: &str) -> Result<RevocationProfile, ServiceError> {
        let mut profile = self.get(profile_id).await?;
        self.validate_profile(&profile)?;
        profile.activate();
        self.profiles.save(profile.clone()).await?;
        Ok(profile)
    }

    pub async fn delete(&self, profile_id: &str) -> Result<(), ServiceError> {
        if !self.profiles.delete(profile_id).await? {
            return Err(ServiceError::NotFound(profile_id.to_string()));
        }
        Ok(())
    }

    pub async fn allocate_index(
        &self,
        profile_id: &str,
        organization_id: &str,
        credential_format: &str,
    ) -> Result<StatusOperationResult, ServiceError> {
        let profile = self.authorized_profile(profile_id, organization_id).await?;
        if !profile.automation_config.auto_allocate_indices {
            return Err(ServiceError::FailedPrecondition(
                "auto-allocation is not enabled for this profile".into(),
            ));
        }
        let format = status_format(credential_format);
        let index = self
            .statuses
            .allocate_index(
                &status_scope(&profile),
                format,
                profile.issuer_config.status_list_size,
            )
            .await?;
        Ok(StatusOperationResult {
            organization_id: profile.organization_id.clone(),
            index,
            status_list_url: self.status_list_url(&profile, format, "revocation"),
        })
    }

    pub async fn process_revocation(
        &self,
        request: ProcessRevocation,
    ) -> Result<StatusOperationResult, ServiceError> {
        let profile = self
            .authorized_profile(&request.profile_id, &request.organization_id)
            .await?;
        if profile.status != RevocationProfileStatus::Active {
            return Err(ServiceError::FailedPrecondition(format!(
                "revocation profile is not active (status: {})",
                profile.status.as_str()
            )));
        }
        let format = status_format(&request.credential_format);
        let status = match (request.status, format) {
            (CredentialStatus::Revoked, _) => 1,
            (CredentialStatus::Suspended, StatusListFormat::TokenStatusList) => 2,
            (CredentialStatus::Suspended, StatusListFormat::Bitstring) => 1,
            (CredentialStatus::Reinstated, _) => 0,
        };
        self.statuses
            .set_status(
                &status_scope(&profile),
                format,
                profile.issuer_config.status_list_size,
                request.index,
                status,
            )
            .await?;
        let purpose = if request.status == CredentialStatus::Suspended {
            "suspension"
        } else {
            "revocation"
        };
        Ok(StatusOperationResult {
            organization_id: profile.organization_id.clone(),
            index: request.index,
            status_list_url: self.status_list_url(&profile, format, purpose),
        })
    }

    pub async fn status_list(
        &self,
        profile_id: &str,
        organization_id: &str,
        format: StatusListFormat,
    ) -> Result<StatusListRecord, ServiceError> {
        let profile = self.authorized_profile(profile_id, organization_id).await?;
        Ok(self
            .statuses
            .get_or_create(
                &status_scope(&profile),
                format,
                profile.issuer_config.status_list_size,
            )
            .await?)
    }

    pub fn status_list_url_template(&self, profile: &RevocationProfile) -> String {
        let concrete =
            self.status_list_url(profile, StatusListFormat::Bitstring, "__STATUS_PURPOSE__");
        concrete
            .replace("bitstring-status-list", "{mechanism}")
            .replace("__STATUS_PURPOSE__", "{purpose}")
    }

    async fn authorized_profile(
        &self,
        profile_id: &str,
        organization_id: &str,
    ) -> Result<RevocationProfile, ServiceError> {
        let profile = self.get(profile_id).await?;
        if profile.organization_id != organization_id {
            return Err(ServiceError::PermissionDenied);
        }
        Ok(profile)
    }

    fn validate_profile(&self, profile: &RevocationProfile) -> Result<(), ServiceError> {
        let size = profile.issuer_config.status_list_size;
        if size == 0 || size > MAX_STATUS_LIST_ENTRIES {
            return Err(ServiceError::InvalidArgument(format!(
                "status_list_size must be between 1 and {MAX_STATUS_LIST_ENTRIES}"
            )));
        }
        if profile.issuer_config.enable_bitstring_status_list && size < W3C_MIN_STATUS_LIST_BITS {
            return Err(ServiceError::InvalidArgument(format!(
                "bitstring status lists require at least {W3C_MIN_STATUS_LIST_BITS} entries"
            )));
        }
        if profile.issuer_config.rotation_threshold_percent > 100 {
            return Err(ServiceError::InvalidArgument(
                "rotation_threshold_percent must not exceed 100".into(),
            ));
        }
        Ok(())
    }

    fn status_list_url(
        &self,
        profile: &RevocationProfile,
        format: StatusListFormat,
        purpose: &str,
    ) -> String {
        let configured = profile
            .issuer_config
            .status_list_base_url
            .as_deref()
            .map(str::trim)
            .filter(|value| value.starts_with("https://"))
            .map(|value| value.trim_end_matches('/'));
        let base = configured
            .and_then(|value| {
                value
                    .split_once("/v1/organizations/")
                    .map(|pair| pair.0)
                    .or(Some(value))
            })
            .map(|value| value.strip_suffix("/lists").unwrap_or(value))
            .unwrap_or(&self.public_base_url);
        format!(
            "{base}/v1/organizations/{}/revocation-profiles/{}/status-lists/{}/{}",
            profile.organization_id,
            profile.id,
            format.mechanism(),
            purpose
        )
    }
}

pub fn status_scope(profile: &RevocationProfile) -> String {
    format!("{}:{}", profile.organization_id, profile.id)
}

pub fn status_format(credential_format: &str) -> StatusListFormat {
    if credential_format.eq_ignore_ascii_case("mdoc") {
        StatusListFormat::TokenStatusList
    } else {
        StatusListFormat::Bitstring
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InMemoryProfileRepository, InMemoryStatusRepository};

    fn service() -> RevocationProfileService {
        RevocationProfileService::new(
            Arc::new(InMemoryProfileRepository::default()),
            Arc::new(InMemoryStatusRepository::default()),
            "https://status.example.test",
        )
        .unwrap()
    }

    async fn active_profile(service: &RevocationProfileService) -> RevocationProfile {
        let profile = service
            .create(NewProfile {
                organization_id: "org-a".into(),
                name: "default".into(),
                description: None,
                issuer_config: None,
                verifier_config: None,
                automation_config: None,
                supported_formats: None,
            })
            .await
            .unwrap();
        service.activate(&profile.id).await.unwrap()
    }

    #[tokio::test]
    async fn tenant_mismatch_fails_closed() {
        let service = service();
        let profile = active_profile(&service).await;
        let error = service
            .allocate_index(&profile.id, "org-b", "sd_jwt_vc")
            .await
            .unwrap_err();
        assert_eq!(error, ServiceError::PermissionDenied);
    }

    #[tokio::test]
    async fn lifecycle_and_status_operations_preserve_contract() {
        let service = service();
        let profile = active_profile(&service).await;
        let allocation = service
            .allocate_index(&profile.id, "org-a", "mdoc")
            .await
            .unwrap();
        assert_eq!(allocation.index, 0);
        assert!(allocation
            .status_list_url
            .contains("token-status-list/revocation"));

        let result = service
            .process_revocation(ProcessRevocation {
                profile_id: profile.id.clone(),
                organization_id: "org-a".into(),
                credential_id: "credential-a".into(),
                index: allocation.index,
                status: CredentialStatus::Suspended,
                credential_format: "mdoc".into(),
            })
            .await
            .unwrap();
        assert!(result
            .status_list_url
            .ends_with("token-status-list/suspension"));
        let record = service
            .status_list(&profile.id, "org-a", StatusListFormat::TokenStatusList)
            .await
            .unwrap();
        assert_eq!(record.get(0).unwrap(), 2);
    }
}
