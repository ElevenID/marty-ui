use std::{collections::BTreeMap, sync::Mutex};

use async_trait::async_trait;
use chrono::Utc;
use marty_credential_template::{
    application::CredentialTemplateRepository,
    catalog::{system_delivery_destination_catalog, system_wallet_catalog},
    registry_application::CredentialTemplateRegistryRepository,
    CredentialTemplate, CredentialTemplateRepositoryError, DeliveryDestinationEntry,
    TemplateStatus, WalletRegistryEntry,
};

#[derive(Default)]
pub(super) struct Repository {
    templates: Mutex<BTreeMap<String, CredentialTemplate>>,
}

#[async_trait]
impl CredentialTemplateRepository for Repository {
    async fn save(
        &self,
        template: &CredentialTemplate,
    ) -> Result<(), CredentialTemplateRepositoryError> {
        self.templates
            .lock()
            .unwrap()
            .insert(template.id.clone(), template.clone());
        Ok(())
    }

    async fn by_id(
        &self,
        template_id: &str,
    ) -> Result<Option<CredentialTemplate>, CredentialTemplateRepositoryError> {
        Ok(self.templates.lock().unwrap().get(template_id).cloned())
    }

    async fn by_organization(
        &self,
        organization_id: &str,
        status: Option<TemplateStatus>,
    ) -> Result<Vec<CredentialTemplate>, CredentialTemplateRepositoryError> {
        Ok(self
            .templates
            .lock()
            .unwrap()
            .values()
            .filter(|template| {
                template.organization_id == organization_id
                    && status.is_none_or(|expected| template.status == expected)
            })
            .cloned()
            .collect())
    }

    async fn all_internal(
        &self,
        status: Option<TemplateStatus>,
    ) -> Result<Vec<CredentialTemplate>, CredentialTemplateRepositoryError> {
        Ok(self
            .templates
            .lock()
            .unwrap()
            .values()
            .filter(|template| status.is_none_or(|expected| template.status == expected))
            .cloned()
            .collect())
    }

    async fn delete(&self, template_id: &str) -> Result<bool, CredentialTemplateRepositoryError> {
        Ok(self.templates.lock().unwrap().remove(template_id).is_some())
    }
}

#[derive(Default)]
pub(super) struct Registry {
    filter_destination_tenant: bool,
    wallets: Mutex<BTreeMap<String, WalletRegistryEntry>>,
    destinations: Mutex<BTreeMap<String, DeliveryDestinationEntry>>,
}

#[async_trait]
impl CredentialTemplateRegistryRepository for Registry {
    async fn save_wallet(
        &self,
        wallet: &WalletRegistryEntry,
    ) -> Result<(), CredentialTemplateRepositoryError> {
        self.wallets
            .lock()
            .unwrap()
            .insert(wallet.id.clone(), wallet.clone());
        Ok(())
    }

    async fn wallet_by_id(
        &self,
        wallet_id: &str,
    ) -> Result<Option<WalletRegistryEntry>, CredentialTemplateRepositoryError> {
        Ok(self.wallets.lock().unwrap().get(wallet_id).cloned())
    }

    async fn wallets(
        &self,
        active_only: bool,
    ) -> Result<Vec<WalletRegistryEntry>, CredentialTemplateRepositoryError> {
        Ok(self
            .wallets
            .lock()
            .unwrap()
            .values()
            .filter(|wallet| !active_only || wallet.is_active)
            .cloned()
            .collect())
    }

    async fn delete_wallet(
        &self,
        wallet_id: &str,
    ) -> Result<bool, CredentialTemplateRepositoryError> {
        Ok(self.wallets.lock().unwrap().remove(wallet_id).is_some())
    }

    async fn save_destination(
        &self,
        destination: &DeliveryDestinationEntry,
    ) -> Result<(), CredentialTemplateRepositoryError> {
        self.destinations
            .lock()
            .unwrap()
            .insert(destination.id.clone(), destination.clone());
        Ok(())
    }

    async fn destination_by_id(
        &self,
        destination_id: &str,
    ) -> Result<Option<DeliveryDestinationEntry>, CredentialTemplateRepositoryError> {
        Ok(self
            .destinations
            .lock()
            .unwrap()
            .get(destination_id)
            .cloned())
    }

    async fn destinations(
        &self,
        active_only: bool,
        organization_id: Option<&str>,
        provider: Option<&str>,
        mode_filter: Option<&str>,
    ) -> Result<Vec<DeliveryDestinationEntry>, CredentialTemplateRepositoryError> {
        Ok(self
            .destinations
            .lock()
            .unwrap()
            .values()
            .filter(|entry| !active_only || entry.is_enabled)
            .filter(|entry| {
                !self.filter_destination_tenant
                    || organization_id.is_none_or(|id| {
                        entry.is_system || entry.organization_id.as_deref() == Some(id)
                    })
            })
            .filter(|entry| provider.is_none_or(|value| entry.provider == value))
            .filter(|entry| mode_filter.is_none_or(|value| entry.mode == value))
            .cloned()
            .collect())
    }

    async fn delete_destination(
        &self,
        destination_id: &str,
    ) -> Result<bool, CredentialTemplateRepositoryError> {
        Ok(self
            .destinations
            .lock()
            .unwrap()
            .remove(destination_id)
            .is_some())
    }
}

impl Registry {
    pub(super) fn seeded(filter_destination_tenant: bool) -> Self {
        let now = Utc::now();
        Self {
            filter_destination_tenant,
            wallets: Mutex::new(
                system_wallet_catalog(now)
                    .into_iter()
                    .map(|entry| (entry.id.clone(), entry))
                    .collect(),
            ),
            destinations: Mutex::new(
                system_delivery_destination_catalog(now)
                    .into_iter()
                    .map(|entry| (entry.id.clone(), entry))
                    .collect(),
            ),
        }
    }
}
