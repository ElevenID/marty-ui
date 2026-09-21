//! Canonical, unscoped resource-owner lookup for gateway authorization.

use std::sync::Arc;

use async_trait::async_trait;
use serde::Serialize;

use crate::{management_security::ManagementSecurity, transaction_reads::TransactionReadError};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ResourceOwnerKind {
    ApplicationTemplate,
    IssuedCredential,
    IssuanceTransaction,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResourceOwner {
    pub organization_id: String,
}

#[async_trait]
pub trait ResourceOwnerRepository: Send + Sync {
    async fn find_owner(
        &self,
        kind: ResourceOwnerKind,
        resource_id: &str,
    ) -> Result<Option<String>, TransactionReadError>;
}

#[derive(Clone)]
pub struct ResourceOwnerService {
    repository: Arc<dyn ResourceOwnerRepository>,
    security: ManagementSecurity,
}

impl std::fmt::Debug for ResourceOwnerService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResourceOwnerService")
            .field("security", &self.security)
            .finish_non_exhaustive()
    }
}

impl ResourceOwnerService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn ResourceOwnerRepository>,
        management_api_key: Option<&str>,
    ) -> Self {
        Self {
            repository,
            security: ManagementSecurity::new(management_api_key),
        }
    }

    /// Authenticate before performing the deliberately unscoped owner lookup.
    /// Tenant authorization is the gateway caller's responsibility.
    pub async fn owner(
        &self,
        kind: ResourceOwnerKind,
        resource_id: &str,
        api_key: Option<&str>,
    ) -> Result<ResourceOwner, TransactionReadError> {
        self.security.authorize(api_key)?;
        let organization_id = self
            .repository
            .find_owner(kind, resource_id)
            .await?
            .ok_or(TransactionReadError::ResourceNotFound)?;
        Ok(ResourceOwner { organization_id })
    }
}
