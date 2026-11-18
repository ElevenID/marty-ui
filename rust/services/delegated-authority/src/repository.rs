use std::{collections::HashMap, sync::Arc};
use async_trait::async_trait;
use tokio::sync::RwLock;
use uuid::Uuid;
use crate::{DelegationGrant, GrantStatus};

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RepositoryError {
    #[error("delegation grant not found")] NotFound,
    #[error("delegation grant already exists")] AlreadyExists,
    #[error("delegation grant revision conflict")] RevisionConflict,
    #[error("delegation repository failure: {0}")] Failure(String),
}
#[async_trait]
pub trait DelegationGrantRepository: Send + Sync {
    async fn insert(&self, grant: DelegationGrant) -> Result<(), RepositoryError>;
    async fn get(&self, organization_id: Uuid, grant_id: Uuid) -> Result<Option<DelegationGrant>, RepositoryError>;
    async fn compare_and_swap(&self, organization_id: Uuid, grant_id: Uuid, expected_revision: u64,
        replacement: DelegationGrant) -> Result<DelegationGrant, RepositoryError>;
    async fn list(&self, organization_id: Uuid, status: Option<GrantStatus>) -> Result<Vec<DelegationGrant>, RepositoryError>;
}
#[derive(Clone, Default)]
pub struct InMemoryDelegationGrantRepository { grants: Arc<RwLock<HashMap<Uuid, DelegationGrant>>> }
#[async_trait]
impl DelegationGrantRepository for InMemoryDelegationGrantRepository {
    async fn insert(&self, grant: DelegationGrant) -> Result<(), RepositoryError> {
        let mut grants = self.grants.write().await;
        if grants.contains_key(&grant.id) { return Err(RepositoryError::AlreadyExists); }
        grants.insert(grant.id, grant); Ok(())
    }
    async fn get(&self, organization_id: Uuid, grant_id: Uuid) -> Result<Option<DelegationGrant>, RepositoryError> {
        Ok(self.grants.read().await.get(&grant_id)
            .filter(|g| g.organization_id == organization_id).cloned())
    }
    async fn compare_and_swap(&self, organization_id: Uuid, grant_id: Uuid, expected_revision: u64,
        replacement: DelegationGrant) -> Result<DelegationGrant, RepositoryError> {
        let mut grants = self.grants.write().await;
        let current = grants.get(&grant_id).ok_or(RepositoryError::NotFound)?;
        if current.organization_id != organization_id { return Err(RepositoryError::NotFound); }
        if current.revision != expected_revision { return Err(RepositoryError::RevisionConflict); }
        if replacement.id != grant_id || replacement.organization_id != organization_id
            || replacement.revision != expected_revision + 1 {
            return Err(RepositoryError::Failure("replacement changed immutable grant data or has invalid identity/revision".into()));
        }
        grants.insert(grant_id, replacement.clone()); Ok(replacement)
    }
    async fn list(&self, organization_id: Uuid, status: Option<GrantStatus>) -> Result<Vec<DelegationGrant>, RepositoryError> {
        let mut values = self.grants.read().await.values()
            .filter(|g| g.organization_id == organization_id)
            .filter(|g| status.is_none_or(|wanted| g.status == wanted)).cloned().collect::<Vec<_>>();
        values.sort_by_key(|g| (g.created_at, g.id)); Ok(values)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::pending_grant;
    #[tokio::test]
    async fn organization_scope_hides_other_tenants() {
        let repository = InMemoryDelegationGrantRepository::default();
        let grant = pending_grant();
        repository.insert(grant.clone()).await.unwrap();
        assert!(repository.get(Uuid::new_v4(), grant.id).await.unwrap().is_none());
        assert_eq!(repository.get(grant.organization_id, grant.id).await.unwrap(), Some(grant));
    }
}
