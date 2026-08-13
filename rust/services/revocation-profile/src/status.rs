use crate::domain::utc_now;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use marty_status::{BitstringStatusList, StatusListError, TokenStatusList};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusListFormat {
    Bitstring,
    TokenStatusList,
}

impl StatusListFormat {
    pub fn mechanism(self) -> &'static str {
        match self {
            Self::Bitstring => "bitstring-status-list",
            Self::TokenStatusList => "token-status-list",
        }
    }

    fn bits_per_status(self) -> u8 {
        match self {
            Self::Bitstring => 1,
            Self::TokenStatusList => 8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusListRecord {
    pub id: String,
    pub scope: String,
    pub format: StatusListFormat,
    pub size: usize,
    pub bits_per_status: u8,
    pub data: Vec<u8>,
    pub version: u64,
    pub published_at: Option<DateTime<Utc>>,
    pub url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl StatusListRecord {
    pub fn empty(
        scope: String,
        format: StatusListFormat,
        size: usize,
    ) -> Result<Self, StatusError> {
        let data = match format {
            StatusListFormat::Bitstring => BitstringStatusList::new(size)?.to_bytes(),
            StatusListFormat::TokenStatusList => {
                TokenStatusList::new(size, format.bits_per_status())?.to_bytes()
            }
        };
        let now = utc_now();
        Ok(Self {
            id: Uuid::new_v4().to_string(),
            scope,
            format,
            size,
            bits_per_status: format.bits_per_status(),
            data,
            version: 0,
            published_at: None,
            url: None,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn set(&mut self, index: usize, status: u8) -> Result<(), StatusError> {
        self.data = match self.format {
            StatusListFormat::Bitstring => {
                if status > 1 {
                    return Err(StatusError::InvalidBitstringStatus(status));
                }
                let mut list = BitstringStatusList::from_bytes(self.data.clone(), self.size)?;
                list.set(index, status == 1)?;
                list.to_bytes()
            }
            StatusListFormat::TokenStatusList => {
                let mut list = TokenStatusList::from_bytes(
                    self.data.clone(),
                    self.size,
                    self.bits_per_status,
                )?;
                list.set(index, status)?;
                list.to_bytes()
            }
        };
        self.version = self.version.saturating_add(1);
        self.updated_at = utc_now();
        Ok(())
    }

    pub fn get(&self, index: usize) -> Result<u8, StatusError> {
        match self.format {
            StatusListFormat::Bitstring => Ok(u8::from(
                BitstringStatusList::from_bytes(self.data.clone(), self.size)?.get(index)?,
            )),
            StatusListFormat::TokenStatusList => Ok(TokenStatusList::from_bytes(
                self.data.clone(),
                self.size,
                self.bits_per_status,
            )?
            .get(index)?),
        }
    }

    pub fn encoded_list(&self) -> Result<String, StatusError> {
        match self.format {
            StatusListFormat::Bitstring => Ok(BitstringStatusList::from_bytes(
                self.data.clone(),
                self.size,
            )?
            .to_base64url()?),
            StatusListFormat::TokenStatusList => Ok(TokenStatusList::from_bytes(
                self.data.clone(),
                self.size,
                self.bits_per_status,
            )?
            .to_base64url()?),
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StatusError {
    #[error(transparent)]
    Canonical(#[from] StatusListError),
    #[error("status {0} must be 0 or 1 for a bitstring status list")]
    InvalidBitstringStatus(u8),
    #[error("status repository operation failed: {0}")]
    Repository(String),
    #[error("status list is full for scope {0}")]
    Full(String),
}

#[async_trait]
pub trait StatusRepository: Send + Sync {
    async fn get_or_create(
        &self,
        scope: &str,
        format: StatusListFormat,
        size: usize,
    ) -> Result<StatusListRecord, StatusError>;

    async fn allocate_index(
        &self,
        scope: &str,
        format: StatusListFormat,
        size: usize,
    ) -> Result<usize, StatusError>;

    async fn set_status(
        &self,
        scope: &str,
        format: StatusListFormat,
        size: usize,
        index: usize,
        status: u8,
    ) -> Result<StatusListRecord, StatusError>;
}

#[derive(Debug, Default)]
struct MemoryState {
    lists: HashMap<(String, StatusListFormat), StatusListRecord>,
    next_indices: HashMap<(String, StatusListFormat), usize>,
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryStatusRepository {
    state: Arc<Mutex<MemoryState>>,
}

#[async_trait]
impl StatusRepository for InMemoryStatusRepository {
    async fn get_or_create(
        &self,
        scope: &str,
        format: StatusListFormat,
        size: usize,
    ) -> Result<StatusListRecord, StatusError> {
        let mut state = self.state.lock().await;
        let key = (scope.to_string(), format);
        if let Some(record) = state.lists.get(&key) {
            if record.size != size {
                return Err(StatusError::Repository(format!(
                    "stored size {} differs from configured size {size}",
                    record.size
                )));
            }
            return Ok(record.clone());
        }
        let record = StatusListRecord::empty(scope.to_string(), format, size)?;
        state.lists.insert(key, record.clone());
        Ok(record)
    }

    async fn allocate_index(
        &self,
        scope: &str,
        format: StatusListFormat,
        size: usize,
    ) -> Result<usize, StatusError> {
        let mut state = self.state.lock().await;
        let key = (scope.to_string(), format);
        if !state.lists.contains_key(&key) {
            let record = StatusListRecord::empty(scope.to_string(), format, size)?;
            state.lists.insert(key.clone(), record);
        }
        if state
            .lists
            .get(&key)
            .is_some_and(|record| record.size != size)
        {
            return Err(StatusError::Repository(
                "configured status-list size changed".into(),
            ));
        }
        let next = state.next_indices.entry(key).or_default();
        if *next >= size {
            return Err(StatusError::Full(scope.to_string()));
        }
        let allocated = *next;
        *next += 1;
        Ok(allocated)
    }

    async fn set_status(
        &self,
        scope: &str,
        format: StatusListFormat,
        size: usize,
        index: usize,
        status: u8,
    ) -> Result<StatusListRecord, StatusError> {
        let mut state = self.state.lock().await;
        let key = (scope.to_string(), format);
        if !state.lists.contains_key(&key) {
            let record = StatusListRecord::empty(scope.to_string(), format, size)?;
            state.lists.insert(key.clone(), record);
        }
        let record = state
            .lists
            .get_mut(&key)
            .expect("status list inserted above");
        if record.size != size {
            return Err(StatusError::Repository(
                "configured status-list size changed".into(),
            ));
        }
        record.set(index, status)?;
        Ok(record.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use marty_status::W3C_MIN_STATUS_LIST_BITS;

    #[tokio::test]
    async fn allocation_is_atomic_and_profile_scoped() {
        let repository = InMemoryStatusRepository::default();
        let mut tasks = Vec::new();
        for _ in 0..64 {
            let repository = repository.clone();
            tasks.push(tokio::spawn(async move {
                repository
                    .allocate_index("org-a:profile-a", StatusListFormat::Bitstring, 128)
                    .await
                    .unwrap()
            }));
        }
        let mut indices = Vec::new();
        for task in tasks {
            indices.push(task.await.unwrap());
        }
        indices.sort_unstable();
        assert_eq!(indices, (0..64).collect::<Vec<_>>());
        assert_eq!(
            repository
                .allocate_index("org-a:profile-b", StatusListFormat::Bitstring, 128)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn mutation_uses_canonical_status_list_rules() {
        let repository = InMemoryStatusRepository::default();
        let record = repository
            .set_status(
                "org-a:profile-a",
                StatusListFormat::Bitstring,
                W3C_MIN_STATUS_LIST_BITS,
                7,
                1,
            )
            .await
            .unwrap();
        assert_eq!(record.get(7).unwrap(), 1);
        assert!(record.encoded_list().unwrap().starts_with('u'));
        assert!(repository
            .set_status(
                "org-a:profile-a",
                StatusListFormat::Bitstring,
                W3C_MIN_STATUS_LIST_BITS,
                7,
                2,
            )
            .await
            .is_err());
    }
}
