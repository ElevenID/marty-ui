use crate::domain::RevocationProfile;
use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RepositoryError {
    #[error("repository operation failed: {0}")]
    Operation(String),
}

#[async_trait]
pub trait ProfileRepository: Send + Sync {
    async fn save(&self, profile: RevocationProfile) -> Result<(), RepositoryError>;
    async fn get(&self, profile_id: &str) -> Result<Option<RevocationProfile>, RepositoryError>;
    async fn list(&self, organization_id: &str) -> Result<Vec<RevocationProfile>, RepositoryError>;
    async fn delete(&self, profile_id: &str) -> Result<bool, RepositoryError>;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryProfileRepository {
    profiles: Arc<RwLock<HashMap<String, RevocationProfile>>>,
}

#[async_trait]
impl ProfileRepository for InMemoryProfileRepository {
    async fn save(&self, profile: RevocationProfile) -> Result<(), RepositoryError> {
        self.profiles
            .write()
            .await
            .insert(profile.id.clone(), profile);
        Ok(())
    }

    async fn get(&self, profile_id: &str) -> Result<Option<RevocationProfile>, RepositoryError> {
        Ok(self.profiles.read().await.get(profile_id).cloned())
    }

    async fn list(&self, organization_id: &str) -> Result<Vec<RevocationProfile>, RepositoryError> {
        let mut profiles = self
            .profiles
            .read()
            .await
            .values()
            .filter(|profile| profile.organization_id == organization_id)
            .cloned()
            .collect::<Vec<_>>();
        profiles.sort_by_key(|profile| profile.created_at);
        Ok(profiles)
    }

    async fn delete(&self, profile_id: &str) -> Result<bool, RepositoryError> {
        Ok(self.profiles.write().await.remove(profile_id).is_some())
    }
}
