use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    IssuerEntity, OrganizationTrustProfile, TrustAnchorType, TrustFramework, TrustProfile,
    TrustProfileIssuer, TrustRegistryEntry,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct RegistryStatus {
    pub total_entries: usize,
    pub current_entries: usize,
    pub csca_entries: usize,
    pub dsc_entries: usize,
    pub current_sequence: u64,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TrustProfileRepositoryError {
    #[error("TRUST_PROFILE.REPOSITORY_DATABASE: {0}")]
    Database(String),
    #[error("TRUST_PROFILE.REPOSITORY_INVALID_DATA: {0}")]
    InvalidData(&'static str),
}

#[async_trait]
pub trait TrustProfileRepository: Send + Sync {
    async fn save_framework(
        &self,
        framework: &TrustFramework,
    ) -> Result<(), TrustProfileRepositoryError>;
    async fn framework_by_id(
        &self,
        framework_id: Uuid,
    ) -> Result<Option<TrustFramework>, TrustProfileRepositoryError>;
    async fn framework_by_code(
        &self,
        code: &str,
    ) -> Result<Option<TrustFramework>, TrustProfileRepositoryError>;
    async fn frameworks(&self) -> Result<Vec<TrustFramework>, TrustProfileRepositoryError>;

    async fn save_organization_profile(
        &self,
        profile: &OrganizationTrustProfile,
    ) -> Result<(), TrustProfileRepositoryError>;
    async fn organization_profile_by_id(
        &self,
        profile_id: Uuid,
    ) -> Result<Option<OrganizationTrustProfile>, TrustProfileRepositoryError>;
    async fn organization_profiles(
        &self,
        organization_id: &str,
    ) -> Result<Vec<OrganizationTrustProfile>, TrustProfileRepositoryError>;
    async fn delete_organization_profile(
        &self,
        profile_id: Uuid,
    ) -> Result<bool, TrustProfileRepositoryError>;

    async fn save_registry_entry(
        &self,
        entry: &TrustRegistryEntry,
    ) -> Result<(), TrustProfileRepositoryError>;
    async fn registry_entries(
        &self,
        anchor_type: Option<TrustAnchorType>,
        country_code: Option<&str>,
        current_only: bool,
        since_sequence: Option<u64>,
    ) -> Result<Vec<TrustRegistryEntry>, TrustProfileRepositoryError>;
    async fn registry_status(&self) -> Result<RegistryStatus, TrustProfileRepositoryError>;

    async fn save_profile(
        &self,
        profile: &TrustProfile,
        expected_updated_at: Option<DateTime<Utc>>,
    ) -> Result<bool, TrustProfileRepositoryError>;
    async fn profile_by_id(
        &self,
        profile_id: Uuid,
    ) -> Result<Option<TrustProfile>, TrustProfileRepositoryError>;
    async fn profiles_by_organization(
        &self,
        organization_id: &str,
    ) -> Result<Vec<TrustProfile>, TrustProfileRepositoryError>;
    async fn profiles(&self) -> Result<Vec<TrustProfile>, TrustProfileRepositoryError>;
    async fn delete_profile(&self, profile_id: Uuid) -> Result<bool, TrustProfileRepositoryError>;

    async fn save_issuer_entity(
        &self,
        issuer: &IssuerEntity,
    ) -> Result<(), TrustProfileRepositoryError>;
    async fn issuer_entity_by_id(
        &self,
        issuer_id: Uuid,
    ) -> Result<Option<IssuerEntity>, TrustProfileRepositoryError>;
    async fn issuer_entity_by_identifier(
        &self,
        organization_id: Option<&str>,
        issuer_identifier: &str,
    ) -> Result<Option<IssuerEntity>, TrustProfileRepositoryError>;
    async fn issuer_entities(
        &self,
        organization_id: Option<&str>,
    ) -> Result<Vec<IssuerEntity>, TrustProfileRepositoryError>;
    async fn delete_issuer_entity(
        &self,
        issuer_id: Uuid,
    ) -> Result<bool, TrustProfileRepositoryError>;

    async fn save_profile_issuer(
        &self,
        link: &TrustProfileIssuer,
    ) -> Result<(), TrustProfileRepositoryError>;
    async fn profile_issuer_by_id(
        &self,
        link_id: Uuid,
    ) -> Result<Option<TrustProfileIssuer>, TrustProfileRepositoryError>;
    async fn profile_issuer_by_pair(
        &self,
        profile_id: Uuid,
        issuer_id: Uuid,
    ) -> Result<Option<TrustProfileIssuer>, TrustProfileRepositoryError>;
    async fn profile_issuers(
        &self,
        profile_id: Uuid,
    ) -> Result<Vec<TrustProfileIssuer>, TrustProfileRepositoryError>;
    async fn delete_profile_issuer(
        &self,
        link_id: Uuid,
    ) -> Result<bool, TrustProfileRepositoryError>;
}

#[derive(Default)]
struct MemoryState {
    frameworks: HashMap<Uuid, TrustFramework>,
    organization_profiles: HashMap<Uuid, OrganizationTrustProfile>,
    registry_entries: HashMap<Uuid, TrustRegistryEntry>,
    profiles: HashMap<Uuid, TrustProfile>,
    issuers: HashMap<Uuid, IssuerEntity>,
    profile_issuers: HashMap<Uuid, TrustProfileIssuer>,
}

#[derive(Clone, Default)]
pub struct MemoryTrustProfileRepository {
    state: Arc<RwLock<MemoryState>>,
}

#[async_trait]
impl TrustProfileRepository for MemoryTrustProfileRepository {
    async fn save_framework(
        &self,
        framework: &TrustFramework,
    ) -> Result<(), TrustProfileRepositoryError> {
        self.state
            .write()
            .await
            .frameworks
            .insert(framework.id, framework.clone());
        Ok(())
    }

    async fn framework_by_id(
        &self,
        framework_id: Uuid,
    ) -> Result<Option<TrustFramework>, TrustProfileRepositoryError> {
        Ok(self
            .state
            .read()
            .await
            .frameworks
            .get(&framework_id)
            .cloned())
    }

    async fn framework_by_code(
        &self,
        code: &str,
    ) -> Result<Option<TrustFramework>, TrustProfileRepositoryError> {
        Ok(self
            .state
            .read()
            .await
            .frameworks
            .values()
            .find(|framework| framework.code == code)
            .cloned())
    }

    async fn frameworks(&self) -> Result<Vec<TrustFramework>, TrustProfileRepositoryError> {
        let mut frameworks = self
            .state
            .read()
            .await
            .frameworks
            .values()
            .cloned()
            .collect::<Vec<_>>();
        frameworks.sort_by(|left, right| {
            (!left.is_system, &left.code).cmp(&(!right.is_system, &right.code))
        });
        Ok(frameworks)
    }

    async fn save_organization_profile(
        &self,
        profile: &OrganizationTrustProfile,
    ) -> Result<(), TrustProfileRepositoryError> {
        self.state
            .write()
            .await
            .organization_profiles
            .insert(profile.id, profile.clone());
        Ok(())
    }

    async fn organization_profile_by_id(
        &self,
        profile_id: Uuid,
    ) -> Result<Option<OrganizationTrustProfile>, TrustProfileRepositoryError> {
        Ok(self
            .state
            .read()
            .await
            .organization_profiles
            .get(&profile_id)
            .cloned())
    }

    async fn organization_profiles(
        &self,
        organization_id: &str,
    ) -> Result<Vec<OrganizationTrustProfile>, TrustProfileRepositoryError> {
        let mut profiles = self
            .state
            .read()
            .await
            .organization_profiles
            .values()
            .filter(|profile| profile.organization_id == organization_id)
            .cloned()
            .collect::<Vec<_>>();
        profiles.sort_by_key(|profile| (profile.created_at, profile.id));
        Ok(profiles)
    }

    async fn delete_organization_profile(
        &self,
        profile_id: Uuid,
    ) -> Result<bool, TrustProfileRepositoryError> {
        Ok(self
            .state
            .write()
            .await
            .organization_profiles
            .remove(&profile_id)
            .is_some())
    }

    async fn save_registry_entry(
        &self,
        entry: &TrustRegistryEntry,
    ) -> Result<(), TrustProfileRepositoryError> {
        self.state
            .write()
            .await
            .registry_entries
            .insert(entry.id, entry.clone());
        Ok(())
    }

    async fn registry_entries(
        &self,
        anchor_type: Option<TrustAnchorType>,
        country_code: Option<&str>,
        current_only: bool,
        since_sequence: Option<u64>,
    ) -> Result<Vec<TrustRegistryEntry>, TrustProfileRepositoryError> {
        let country_code = country_code.map(str::to_uppercase);
        let mut entries = self
            .state
            .read()
            .await
            .registry_entries
            .values()
            .filter(|entry| anchor_type.is_none_or(|value| entry.anchor_type == value))
            .filter(|entry| {
                country_code
                    .as_ref()
                    .is_none_or(|value| entry.country_code == *value)
            })
            .filter(|entry| !current_only || entry.is_current)
            .filter(|entry| since_sequence.is_none_or(|value| entry.sequence > value))
            .cloned()
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| (entry.sequence, entry.country_code.clone(), entry.id));
        Ok(entries)
    }

    async fn registry_status(&self) -> Result<RegistryStatus, TrustProfileRepositoryError> {
        let state = self.state.read().await;
        let current = state
            .registry_entries
            .values()
            .filter(|entry| entry.is_current)
            .collect::<Vec<_>>();
        Ok(RegistryStatus {
            total_entries: state.registry_entries.len(),
            current_entries: current.len(),
            csca_entries: current
                .iter()
                .filter(|entry| entry.anchor_type == TrustAnchorType::Csca)
                .count(),
            dsc_entries: current
                .iter()
                .filter(|entry| entry.anchor_type == TrustAnchorType::Dsc)
                .count(),
            current_sequence: state
                .registry_entries
                .values()
                .map(|entry| entry.sequence)
                .max()
                .unwrap_or(0),
        })
    }

    async fn save_profile(
        &self,
        profile: &TrustProfile,
        expected_updated_at: Option<DateTime<Utc>>,
    ) -> Result<bool, TrustProfileRepositoryError> {
        let mut state = self.state.write().await;
        if expected_updated_at.is_some_and(|expected| {
            state
                .profiles
                .get(&profile.id)
                .is_none_or(|current| current.updated_at != expected)
        }) {
            return Ok(false);
        }
        state.profiles.insert(profile.id, profile.clone());
        Ok(true)
    }

    async fn profile_by_id(
        &self,
        profile_id: Uuid,
    ) -> Result<Option<TrustProfile>, TrustProfileRepositoryError> {
        Ok(self.state.read().await.profiles.get(&profile_id).cloned())
    }

    async fn profiles_by_organization(
        &self,
        organization_id: &str,
    ) -> Result<Vec<TrustProfile>, TrustProfileRepositoryError> {
        Ok(self
            .state
            .read()
            .await
            .profiles
            .values()
            .filter(|profile| profile.organization_id == organization_id)
            .cloned()
            .collect())
    }

    async fn profiles(&self) -> Result<Vec<TrustProfile>, TrustProfileRepositoryError> {
        let mut profiles = self
            .state
            .read()
            .await
            .profiles
            .values()
            .cloned()
            .collect::<Vec<_>>();
        profiles.sort_by_key(|profile| profile.id);
        Ok(profiles)
    }

    async fn delete_profile(&self, profile_id: Uuid) -> Result<bool, TrustProfileRepositoryError> {
        let mut state = self.state.write().await;
        let deleted = state.profiles.remove(&profile_id).is_some();
        state
            .profile_issuers
            .retain(|_, link| link.trust_profile_id != profile_id);
        Ok(deleted)
    }

    async fn save_issuer_entity(
        &self,
        issuer: &IssuerEntity,
    ) -> Result<(), TrustProfileRepositoryError> {
        self.state
            .write()
            .await
            .issuers
            .insert(issuer.id, issuer.clone());
        Ok(())
    }

    async fn issuer_entity_by_id(
        &self,
        issuer_id: Uuid,
    ) -> Result<Option<IssuerEntity>, TrustProfileRepositoryError> {
        Ok(self.state.read().await.issuers.get(&issuer_id).cloned())
    }

    async fn issuer_entity_by_identifier(
        &self,
        organization_id: Option<&str>,
        issuer_identifier: &str,
    ) -> Result<Option<IssuerEntity>, TrustProfileRepositoryError> {
        Ok(self
            .state
            .read()
            .await
            .issuers
            .values()
            .find(|issuer| {
                issuer.organization_id.as_deref() == organization_id
                    && issuer.issuer_id == issuer_identifier
            })
            .cloned())
    }

    async fn issuer_entities(
        &self,
        organization_id: Option<&str>,
    ) -> Result<Vec<IssuerEntity>, TrustProfileRepositoryError> {
        let mut issuers = self
            .state
            .read()
            .await
            .issuers
            .values()
            .filter(|issuer| {
                organization_id.is_none_or(|organization_id| {
                    issuer.organization_id.as_deref() == Some(organization_id)
                        || issuer.is_system_issuer
                        || issuer.organization_id.is_none()
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        issuers.sort_by(|left, right| {
            (left.display_name.to_lowercase(), left.id)
                .cmp(&(right.display_name.to_lowercase(), right.id))
        });
        Ok(issuers)
    }

    async fn delete_issuer_entity(
        &self,
        issuer_id: Uuid,
    ) -> Result<bool, TrustProfileRepositoryError> {
        let mut state = self.state.write().await;
        let deleted = state.issuers.remove(&issuer_id).is_some();
        state
            .profile_issuers
            .retain(|_, link| link.issuer_id != issuer_id);
        Ok(deleted)
    }

    async fn save_profile_issuer(
        &self,
        link: &TrustProfileIssuer,
    ) -> Result<(), TrustProfileRepositoryError> {
        self.state
            .write()
            .await
            .profile_issuers
            .insert(link.id, link.clone());
        Ok(())
    }

    async fn profile_issuer_by_id(
        &self,
        link_id: Uuid,
    ) -> Result<Option<TrustProfileIssuer>, TrustProfileRepositoryError> {
        Ok(self
            .state
            .read()
            .await
            .profile_issuers
            .get(&link_id)
            .cloned())
    }

    async fn profile_issuer_by_pair(
        &self,
        profile_id: Uuid,
        issuer_id: Uuid,
    ) -> Result<Option<TrustProfileIssuer>, TrustProfileRepositoryError> {
        Ok(self
            .state
            .read()
            .await
            .profile_issuers
            .values()
            .find(|link| link.trust_profile_id == profile_id && link.issuer_id == issuer_id)
            .cloned())
    }

    async fn profile_issuers(
        &self,
        profile_id: Uuid,
    ) -> Result<Vec<TrustProfileIssuer>, TrustProfileRepositoryError> {
        let mut links = self
            .state
            .read()
            .await
            .profile_issuers
            .values()
            .filter(|link| link.trust_profile_id == profile_id)
            .cloned()
            .collect::<Vec<_>>();
        links.sort_by_key(|link| (link.created_at, link.id));
        Ok(links)
    }

    async fn delete_profile_issuer(
        &self,
        link_id: Uuid,
    ) -> Result<bool, TrustProfileRepositoryError> {
        Ok(self
            .state
            .write()
            .await
            .profile_issuers
            .remove(&link_id)
            .is_some())
    }
}
