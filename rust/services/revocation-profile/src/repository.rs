use crate::{domain::RevocationProfile, status::StatusListFormat};
use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RepositoryError {
    #[error("repository operation failed: {0}")]
    Operation(String),
    #[error("credential {credential_id} already owns a status index in another scope")]
    AllocationScopeConflict { credential_id: String },
    #[error("status list is full for scope {0}")]
    AllocationFull(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusIndexReservation {
    pub credential_id: String,
    pub organization_id: String,
    pub profile_id: String,
    pub format: StatusListFormat,
    pub size: usize,
    pub legacy_floor: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StatusIndexAllocation {
    organization_id: String,
    profile_id: String,
    format: StatusListFormat,
    index: usize,
}

#[async_trait]
pub trait ProfileRepository: Send + Sync {
    async fn save(&self, profile: RevocationProfile) -> Result<(), RepositoryError>;
    async fn get(&self, profile_id: &str) -> Result<Option<RevocationProfile>, RepositoryError>;
    async fn list(&self, organization_id: &str) -> Result<Vec<RevocationProfile>, RepositoryError>;
    async fn delete(&self, profile_id: &str) -> Result<bool, RepositoryError>;
    async fn reserve_status_index(
        &self,
        reservation: StatusIndexReservation,
    ) -> Result<usize, RepositoryError>;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryProfileRepository {
    state: Arc<RwLock<MemoryState>>,
}

#[derive(Debug, Default)]
struct MemoryState {
    profiles: HashMap<String, RevocationProfile>,
    allocations: HashMap<String, StatusIndexAllocation>,
    next_indices: HashMap<(String, String, StatusListFormat), usize>,
}

#[async_trait]
impl ProfileRepository for InMemoryProfileRepository {
    async fn save(&self, profile: RevocationProfile) -> Result<(), RepositoryError> {
        self.state
            .write()
            .await
            .profiles
            .insert(profile.id.clone(), profile);
        Ok(())
    }

    async fn get(&self, profile_id: &str) -> Result<Option<RevocationProfile>, RepositoryError> {
        Ok(self.state.read().await.profiles.get(profile_id).cloned())
    }

    async fn list(&self, organization_id: &str) -> Result<Vec<RevocationProfile>, RepositoryError> {
        let mut profiles = self
            .state
            .read()
            .await
            .profiles
            .values()
            .filter(|profile| profile.organization_id == organization_id)
            .cloned()
            .collect::<Vec<_>>();
        profiles.sort_by_key(|profile| profile.created_at);
        Ok(profiles)
    }

    async fn delete(&self, profile_id: &str) -> Result<bool, RepositoryError> {
        let mut state = self.state.write().await;
        Ok(state.profiles.remove(profile_id).is_some())
    }

    async fn reserve_status_index(
        &self,
        reservation: StatusIndexReservation,
    ) -> Result<usize, RepositoryError> {
        let mut state = self.state.write().await;
        if let Some(existing) = state.allocations.get(&reservation.credential_id) {
            if existing.organization_id != reservation.organization_id
                || existing.profile_id != reservation.profile_id
                || existing.format != reservation.format
            {
                return Err(RepositoryError::AllocationScopeConflict {
                    credential_id: reservation.credential_id,
                });
            }
            return Ok(existing.index);
        }

        let profile = state
            .profiles
            .get(&reservation.profile_id)
            .ok_or_else(|| RepositoryError::Operation("revocation profile disappeared".into()))?;
        if profile.organization_id != reservation.organization_id {
            return Err(RepositoryError::AllocationScopeConflict {
                credential_id: reservation.credential_id,
            });
        }

        let counter_key = (
            reservation.organization_id.clone(),
            reservation.profile_id.clone(),
            reservation.format,
        );
        let next = state.next_indices.entry(counter_key).or_default();
        *next = (*next).max(reservation.legacy_floor);
        if *next >= reservation.size {
            return Err(RepositoryError::AllocationFull(format!(
                "{}:{}",
                reservation.organization_id, reservation.profile_id
            )));
        }
        let index = *next;
        *next += 1;
        state.allocations.insert(
            reservation.credential_id,
            StatusIndexAllocation {
                organization_id: reservation.organization_id,
                profile_id: reservation.profile_id,
                format: reservation.format,
                index,
            },
        );
        Ok(index)
    }
}
