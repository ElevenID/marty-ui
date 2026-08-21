use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

use crate::{PolicyDomainError, PolicyStatus, PresentationPolicy};

#[async_trait]
pub trait PolicyRepository: Send + Sync {
    async fn save(&self, policy: &PresentationPolicy) -> Result<(), String>;
    async fn get(&self, policy_id: Uuid) -> Result<Option<PresentationPolicy>, String>;
    async fn list(&self, organization_id: Uuid) -> Result<Vec<PresentationPolicy>, String>;
    async fn delete(&self, policy_id: Uuid) -> Result<(), String>;
}

#[async_trait]
pub trait PolicyAuthorization: Send + Sync {
    async fn require(
        &self,
        principal_id: &str,
        organization_id: Uuid,
        action: &'static str,
    ) -> Result<(), String>;
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PolicyApplicationError {
    #[error("PRESENTATION_POLICY.NOT_FOUND")]
    NotFound,
    #[error("PRESENTATION_POLICY.CONFLICT: {0}")]
    Conflict(&'static str),
    #[error("PRESENTATION_POLICY.FORBIDDEN")]
    Forbidden,
    #[error(transparent)]
    Domain(#[from] PolicyDomainError),
    #[error("PRESENTATION_POLICY.DEPENDENCY")]
    Dependency,
}

#[derive(Clone)]
pub struct PolicyApplication {
    repository: Arc<dyn PolicyRepository>,
    authorization: Arc<dyn PolicyAuthorization>,
}

impl PolicyApplication {
    #[must_use]
    pub fn new(
        repository: Arc<dyn PolicyRepository>,
        authorization: Arc<dyn PolicyAuthorization>,
    ) -> Self {
        Self {
            repository,
            authorization,
        }
    }

    pub async fn create(
        &self,
        principal_id: &str,
        policy: PresentationPolicy,
    ) -> Result<PresentationPolicy, PolicyApplicationError> {
        self.require(principal_id, policy.organization_id, "create")
            .await?;
        if policy.status != PolicyStatus::Draft {
            return Err(PolicyApplicationError::Conflict(
                "new policies must be draft",
            ));
        }
        policy.validate()?;
        if self
            .repository
            .get(policy.id)
            .await
            .map_err(dependency)?
            .is_some()
        {
            return Err(PolicyApplicationError::Conflict("policy already exists"));
        }
        self.save(&policy).await?;
        Ok(policy)
    }

    pub async fn get(
        &self,
        principal_id: &str,
        policy_id: Uuid,
    ) -> Result<PresentationPolicy, PolicyApplicationError> {
        let policy = self.load(policy_id).await?;
        self.require(principal_id, policy.organization_id, "view")
            .await?;
        Ok(policy)
    }

    pub async fn list(
        &self,
        principal_id: &str,
        organization_id: Uuid,
    ) -> Result<Vec<PresentationPolicy>, PolicyApplicationError> {
        self.require(principal_id, organization_id, "view").await?;
        let policies = self
            .repository
            .list(organization_id)
            .await
            .map_err(dependency)?;
        if policies
            .iter()
            .any(|policy| policy.organization_id != organization_id)
        {
            return Err(PolicyApplicationError::Dependency);
        }
        Ok(policies)
    }

    pub async fn update(
        &self,
        principal_id: &str,
        replacement: PresentationPolicy,
    ) -> Result<PresentationPolicy, PolicyApplicationError> {
        let existing = self.load(replacement.id).await?;
        self.require(principal_id, existing.organization_id, "update")
            .await?;
        if existing.status != PolicyStatus::Draft {
            return Err(PolicyApplicationError::Conflict(
                "only draft policies can be updated",
            ));
        }
        if replacement.organization_id != existing.organization_id
            || replacement.status != PolicyStatus::Draft
            || replacement.version != existing.version
            || replacement.created_at != existing.created_at
        {
            return Err(PolicyApplicationError::Conflict(
                "immutable policy identity changed",
            ));
        }
        replacement.validate()?;
        self.save(&replacement).await?;
        Ok(replacement)
    }

    pub async fn activate(
        &self,
        principal_id: &str,
        policy_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<PresentationPolicy, PolicyApplicationError> {
        let mut policy = self.load(policy_id).await?;
        self.require(principal_id, policy.organization_id, "activate")
            .await?;
        policy.activate(now)?;
        self.save(&policy).await?;
        Ok(policy)
    }

    pub async fn suspend(
        &self,
        principal_id: &str,
        policy_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<PresentationPolicy, PolicyApplicationError> {
        let mut policy = self.load(policy_id).await?;
        self.require(principal_id, policy.organization_id, "suspend")
            .await?;
        policy.suspend(now)?;
        self.save(&policy).await?;
        Ok(policy)
    }

    pub async fn new_version(
        &self,
        principal_id: &str,
        policy_id: Uuid,
        new_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<PresentationPolicy, PolicyApplicationError> {
        let policy = self.load(policy_id).await?;
        self.require(principal_id, policy.organization_id, "version")
            .await?;
        if self
            .repository
            .get(new_id)
            .await
            .map_err(dependency)?
            .is_some()
        {
            return Err(PolicyApplicationError::Conflict("version id exists"));
        }
        let version = policy.new_version(new_id, now);
        self.save(&version).await?;
        Ok(version)
    }

    pub async fn delete(
        &self,
        principal_id: &str,
        policy_id: Uuid,
    ) -> Result<(), PolicyApplicationError> {
        let policy = self.load(policy_id).await?;
        self.require(principal_id, policy.organization_id, "delete")
            .await?;
        if policy.status != PolicyStatus::Draft {
            return Err(PolicyApplicationError::Conflict(
                "only draft policies can be deleted",
            ));
        }
        self.repository.delete(policy_id).await.map_err(dependency)
    }

    async fn load(&self, policy_id: Uuid) -> Result<PresentationPolicy, PolicyApplicationError> {
        self.repository
            .get(policy_id)
            .await
            .map_err(dependency)?
            .ok_or(PolicyApplicationError::NotFound)
    }

    async fn save(&self, policy: &PresentationPolicy) -> Result<(), PolicyApplicationError> {
        self.repository.save(policy).await.map_err(dependency)
    }

    async fn require(
        &self,
        principal_id: &str,
        organization_id: Uuid,
        action: &'static str,
    ) -> Result<(), PolicyApplicationError> {
        if principal_id.trim().is_empty() {
            return Err(PolicyApplicationError::Forbidden);
        }
        self.authorization
            .require(principal_id, organization_id, action)
            .await
            .map_err(|_| PolicyApplicationError::Forbidden)
    }
}

fn dependency(_: String) -> PolicyApplicationError {
    PolicyApplicationError::Dependency
}
