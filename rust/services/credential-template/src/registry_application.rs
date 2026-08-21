use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    application::{
        CredentialTemplateApplicationError, CredentialTemplateControlPlane,
        CredentialTemplateRepository,
    },
    normalize_payload_format, render_wallet_open_uri, validate_wallet_inner_uri,
    wallet::{
        derive_wallet_profile, matching_wallet_overrides, merge_wallet_profile,
        merge_wallet_profile_parts, normalize_issuance_protocol, wallet_route_template,
        DerivedWalletProfile, WalletCompatibility,
    },
    CredentialTemplateRepositoryError, DeliveryDestinationEntry, DeliveryDestinationPolicy,
    MergeStrategy, PostgresCredentialTemplateStore, RuntimeEnvironment, WalletRegistryEntry,
};

#[async_trait]
pub trait CredentialTemplateRegistryRepository: Send + Sync {
    async fn save_wallet(
        &self,
        wallet: &WalletRegistryEntry,
    ) -> Result<(), CredentialTemplateRepositoryError>;
    async fn wallet_by_id(
        &self,
        wallet_id: &str,
    ) -> Result<Option<WalletRegistryEntry>, CredentialTemplateRepositoryError>;
    async fn wallets(
        &self,
        active_only: bool,
    ) -> Result<Vec<WalletRegistryEntry>, CredentialTemplateRepositoryError>;
    async fn delete_wallet(
        &self,
        wallet_id: &str,
    ) -> Result<bool, CredentialTemplateRepositoryError>;
    async fn save_destination(
        &self,
        destination: &DeliveryDestinationEntry,
    ) -> Result<(), CredentialTemplateRepositoryError>;
    async fn destination_by_id(
        &self,
        destination_id: &str,
    ) -> Result<Option<DeliveryDestinationEntry>, CredentialTemplateRepositoryError>;
    async fn destinations(
        &self,
        active_only: bool,
        organization_id: Option<&str>,
        provider: Option<&str>,
        mode: Option<&str>,
    ) -> Result<Vec<DeliveryDestinationEntry>, CredentialTemplateRepositoryError>;
    async fn delete_destination(
        &self,
        destination_id: &str,
    ) -> Result<bool, CredentialTemplateRepositoryError>;
}

#[async_trait]
impl CredentialTemplateRegistryRepository for PostgresCredentialTemplateStore {
    async fn save_wallet(
        &self,
        wallet: &WalletRegistryEntry,
    ) -> Result<(), CredentialTemplateRepositoryError> {
        PostgresCredentialTemplateStore::save_wallet(self, wallet).await
    }

    async fn wallet_by_id(
        &self,
        wallet_id: &str,
    ) -> Result<Option<WalletRegistryEntry>, CredentialTemplateRepositoryError> {
        PostgresCredentialTemplateStore::wallet_by_id(self, wallet_id).await
    }

    async fn wallets(
        &self,
        active_only: bool,
    ) -> Result<Vec<WalletRegistryEntry>, CredentialTemplateRepositoryError> {
        PostgresCredentialTemplateStore::wallets(self, active_only).await
    }

    async fn delete_wallet(
        &self,
        wallet_id: &str,
    ) -> Result<bool, CredentialTemplateRepositoryError> {
        PostgresCredentialTemplateStore::delete_wallet(self, wallet_id).await
    }

    async fn save_destination(
        &self,
        destination: &DeliveryDestinationEntry,
    ) -> Result<(), CredentialTemplateRepositoryError> {
        PostgresCredentialTemplateStore::save_destination(self, destination).await
    }

    async fn destination_by_id(
        &self,
        destination_id: &str,
    ) -> Result<Option<DeliveryDestinationEntry>, CredentialTemplateRepositoryError> {
        PostgresCredentialTemplateStore::destination_by_id(self, destination_id).await
    }

    async fn destinations(
        &self,
        active_only: bool,
        organization_id: Option<&str>,
        provider: Option<&str>,
        mode: Option<&str>,
    ) -> Result<Vec<DeliveryDestinationEntry>, CredentialTemplateRepositoryError> {
        PostgresCredentialTemplateStore::destinations(
            self,
            active_only,
            organization_id,
            provider,
            mode,
        )
        .await
    }

    async fn delete_destination(
        &self,
        destination_id: &str,
    ) -> Result<bool, CredentialTemplateRepositoryError> {
        PostgresCredentialTemplateStore::delete_destination(self, destination_id).await
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateWalletCommand {
    pub user_id: String,
    pub organization_id: String,
    pub credential_format: Option<String>,
    pub issuance_protocol: Option<String>,
    pub compliance_profile_code: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub wallet_apps: Vec<String>,
    pub specifications: Vec<String>,
    pub logo_url: Option<String>,
    pub deep_link_template: String,
    pub routing_templates: BTreeMap<String, String>,
    pub install_urls: BTreeMap<String, String>,
    pub ios_scheme: Option<String>,
    pub universal_link_template: Option<String>,
    pub android_package: Option<String>,
    pub supported_formats: Vec<String>,
    pub supported_protocols: Vec<String>,
    pub platforms: Vec<String>,
    pub supports_qr: bool,
    pub supports_deeplink: bool,
    pub supports_digital_credentials: bool,
    pub supports_haip: bool,
    pub docs_url: Option<String>,
    pub override_precedence: i32,
    pub merge_strategy: String,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct UpdateWalletPatch {
    pub organization_id: Option<String>,
    pub credential_format: Option<String>,
    pub issuance_protocol: Option<String>,
    pub compliance_profile_code: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub wallet_apps: Option<Vec<String>>,
    pub specifications: Option<Vec<String>>,
    pub logo_url: Option<String>,
    pub deep_link_template: Option<String>,
    pub routing_templates: Option<BTreeMap<String, String>>,
    pub install_urls: Option<BTreeMap<String, String>>,
    pub ios_scheme: Option<String>,
    pub universal_link_template: Option<String>,
    pub android_package: Option<String>,
    pub supported_formats: Option<Vec<String>>,
    pub supported_protocols: Option<Vec<String>>,
    pub platforms: Option<Vec<String>>,
    pub supports_qr: Option<bool>,
    pub supports_deeplink: Option<bool>,
    pub supports_digital_credentials: Option<bool>,
    pub supports_haip: Option<bool>,
    pub docs_url: Option<String>,
    pub is_active: Option<bool>,
    pub override_precedence: Option<i32>,
    pub merge_strategy: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CreateDestinationCommand {
    pub user_id: String,
    pub organization_id: String,
    pub id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub provider: String,
    pub mode: String,
    pub setup_actor: String,
    pub delivery_target: String,
    pub wallet_profile_id: Option<String>,
    pub credential_format: Option<String>,
    pub issuance_protocol: Option<String>,
    pub compliance_profile_code: Option<String>,
    pub connector_type: Option<String>,
    pub connector_id: Option<String>,
    pub requires_consent: bool,
    pub claim_projection_policy: Value,
    pub setup_requirements: Vec<String>,
    pub capabilities: BTreeMap<String, bool>,
    pub docs_url: Option<String>,
    pub is_enabled: bool,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct UpdateDestinationPatch {
    pub name: Option<String>,
    pub description: Option<String>,
    pub provider: Option<String>,
    pub mode: Option<String>,
    pub setup_actor: Option<String>,
    pub delivery_target: Option<String>,
    pub wallet_profile_id: Option<String>,
    pub credential_format: Option<String>,
    pub issuance_protocol: Option<String>,
    pub compliance_profile_code: Option<String>,
    pub connector_type: Option<String>,
    pub connector_id: Option<String>,
    pub requires_consent: Option<bool>,
    pub claim_projection_policy: Option<Value>,
    pub setup_requirements: Option<Vec<String>>,
    pub capabilities: Option<BTreeMap<String, bool>>,
    pub docs_url: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletOpenLink {
    pub wallet_id: String,
    pub inner_uri: String,
    pub open_uri: String,
    pub platform: Option<String>,
}

#[derive(Clone)]
pub struct CredentialTemplateRegistryApplication {
    templates: Arc<dyn CredentialTemplateRepository>,
    registry: Arc<dyn CredentialTemplateRegistryRepository>,
    control_plane: Arc<dyn CredentialTemplateControlPlane>,
}

impl CredentialTemplateRegistryApplication {
    #[must_use]
    pub fn new(
        templates: Arc<dyn CredentialTemplateRepository>,
        registry: Arc<dyn CredentialTemplateRegistryRepository>,
        control_plane: Arc<dyn CredentialTemplateControlPlane>,
    ) -> Self {
        Self {
            templates,
            registry,
            control_plane,
        }
    }

    pub async fn list_wallets(
        &self,
        user_id: &str,
        organization_id: Option<&str>,
        active_only: bool,
    ) -> Result<Vec<WalletRegistryEntry>, CredentialTemplateApplicationError> {
        if let Some(organization_id) = organization_id {
            self.control_plane
                .require_membership(user_id, organization_id)
                .await?;
        }
        Ok(self
            .registry
            .wallets(active_only)
            .await?
            .into_iter()
            .filter(|wallet| match organization_id {
                Some(expected) => wallet
                    .organization_id
                    .as_deref()
                    .is_none_or(|id| id == expected),
                None => wallet.organization_id.is_none(),
            })
            .collect())
    }

    pub async fn get_wallet(
        &self,
        user_id: &str,
        wallet_id: &str,
    ) -> Result<WalletRegistryEntry, CredentialTemplateApplicationError> {
        let wallet = self.load_wallet(wallet_id).await?;
        if let Some(organization_id) = wallet.organization_id.as_deref() {
            self.control_plane
                .require_membership(user_id, organization_id)
                .await?;
        }
        Ok(wallet)
    }

    pub async fn build_wallet_open_link(
        &self,
        user_id: &str,
        wallet_id: &str,
        inner_uri: &str,
        platform: Option<&str>,
        environment: RuntimeEnvironment,
    ) -> Result<WalletOpenLink, CredentialTemplateApplicationError> {
        let wallet = self.load_wallet(wallet_id).await?;
        if !wallet.is_active {
            return Err(CredentialTemplateApplicationError::WalletNotFound(
                wallet_id.to_owned(),
            ));
        }
        if let Some(organization_id) = wallet.organization_id.as_deref() {
            self.control_plane
                .require_membership(user_id, organization_id)
                .await?;
        }
        if !wallet.supports_deeplink {
            return Err(CredentialTemplateApplicationError::DeepLinksUnsupported);
        }
        let inner_uri = validate_wallet_inner_uri(inner_uri, environment)?;
        let route = wallet_route_template(&wallet, platform);
        let open_uri = render_wallet_open_uri(&route, &inner_uri, wallet_id, platform)?;
        Ok(WalletOpenLink {
            wallet_id: wallet_id.to_owned(),
            inner_uri,
            open_uri,
            platform: platform.map(str::to_owned),
        })
    }

    pub async fn resolve_wallet_profile(
        &self,
        user_id: &str,
        organization_id: &str,
        credential_format: &str,
        issuance_protocol: &str,
        compliance_profile_code: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<WalletCompatibility, CredentialTemplateApplicationError> {
        self.control_plane
            .require_membership(user_id, organization_id)
            .await?;
        let derived = derive_wallet_profile(
            credential_format,
            issuance_protocol,
            compliance_profile_code,
        );
        let overrides = self.matching_overrides(organization_id, &derived).await?;
        Ok(merge_wallet_profile_parts(
            derived,
            &overrides,
            Vec::new(),
            now,
            now,
        ))
    }

    pub async fn template_wallet_compatibility(
        &self,
        user_id: &str,
        template_id: &str,
    ) -> Result<WalletCompatibility, CredentialTemplateApplicationError> {
        let template =
            self.templates.by_id(template_id).await?.ok_or_else(|| {
                CredentialTemplateApplicationError::NotFound(template_id.to_owned())
            })?;
        self.control_plane
            .require_membership(user_id, &template.organization_id)
            .await?;
        let format = normalize_payload_format(
            Some(&template.credential_payload_format),
            &template.supported_formats,
        )?;
        let compliance = compliance_profile_code(&template.compliance_profile)
            .or_else(|| normalize_upper(template.compliance_profile_id.as_deref()));
        let derived = derive_wallet_profile(
            format.canonical(),
            &template.issuance_protocol,
            compliance.as_deref(),
        );
        let overrides = self
            .matching_overrides(&template.organization_id, &derived)
            .await?;
        Ok(merge_wallet_profile(derived, &overrides, &template))
    }

    pub async fn create_wallet(
        &self,
        command: CreateWalletCommand,
    ) -> Result<WalletRegistryEntry, CredentialTemplateApplicationError> {
        if command.organization_id.trim().is_empty() {
            return Err(CredentialTemplateApplicationError::InvalidCommand(
                "organization_id is required for wallet overrides",
            ));
        }
        self.control_plane
            .require_wallet_admin(&command.user_id, &command.organization_id)
            .await?;
        let entry = WalletRegistryEntry {
            id: Uuid::new_v4().to_string(),
            organization_id: Some(command.organization_id),
            is_override: true,
            override_precedence: command.override_precedence,
            merge_strategy: MergeStrategy::parse(&command.merge_strategy.to_ascii_uppercase())?,
            credential_format: normalize_upper(command.credential_format.as_deref()),
            issuance_protocol: command
                .issuance_protocol
                .as_deref()
                .map(|value| normalize_issuance_protocol(Some(value))),
            compliance_profile_code: normalize_upper(command.compliance_profile_code.as_deref()),
            name: command.name,
            description: command.description,
            wallet_apps: command.wallet_apps,
            specifications: command.specifications,
            logo_url: command.logo_url,
            deep_link_template: command.deep_link_template,
            routing_templates: command.routing_templates,
            install_urls: command.install_urls,
            ios_scheme: command.ios_scheme,
            universal_link_template: command.universal_link_template,
            android_package: command.android_package,
            supported_formats: command.supported_formats,
            supported_protocols: command
                .supported_protocols
                .iter()
                .map(|value| normalize_issuance_protocol(Some(value)))
                .collect(),
            platforms: command.platforms,
            supports_qr: command.supports_qr,
            supports_deeplink: command.supports_deeplink,
            supports_digital_credentials: command.supports_digital_credentials,
            supports_haip: command.supports_haip,
            docs_url: command.docs_url,
            is_active: true,
            created_at: command.now,
            updated_at: command.now,
        };
        self.registry.save_wallet(&entry).await?;
        Ok(entry)
    }

    pub async fn update_wallet(
        &self,
        user_id: &str,
        wallet_id: &str,
        patch: UpdateWalletPatch,
        now: DateTime<Utc>,
    ) -> Result<WalletRegistryEntry, CredentialTemplateApplicationError> {
        let mut entry = self.load_wallet(wallet_id).await?;
        let organization_id = entry
            .organization_id
            .as_deref()
            .ok_or(CredentialTemplateApplicationError::SystemWalletReadOnly)?;
        self.control_plane
            .require_wallet_admin(user_id, organization_id)
            .await?;
        if patch
            .organization_id
            .as_deref()
            .is_some_and(|requested| requested != organization_id)
        {
            return Err(CredentialTemplateApplicationError::OwnershipTransferForbidden);
        }
        apply_wallet_patch(&mut entry, patch)?;
        entry.updated_at = now;
        self.registry.save_wallet(&entry).await?;
        Ok(entry)
    }

    pub async fn delete_wallet(
        &self,
        user_id: &str,
        wallet_id: &str,
    ) -> Result<(), CredentialTemplateApplicationError> {
        let entry = self.load_wallet(wallet_id).await?;
        let organization_id = entry
            .organization_id
            .as_deref()
            .ok_or(CredentialTemplateApplicationError::SystemWalletReadOnly)?;
        self.control_plane
            .require_wallet_admin(user_id, organization_id)
            .await?;
        if !self.registry.delete_wallet(wallet_id).await? {
            return Err(CredentialTemplateApplicationError::WalletNotFound(
                wallet_id.to_owned(),
            ));
        }
        Ok(())
    }

    pub async fn list_destinations(
        &self,
        user_id: &str,
        organization_id: Option<&str>,
        active_only: bool,
        provider: Option<&str>,
        mode: Option<&str>,
    ) -> Result<Vec<DeliveryDestinationEntry>, CredentialTemplateApplicationError> {
        if let Some(organization_id) = organization_id {
            self.control_plane
                .require_membership(user_id, organization_id)
                .await?;
        }
        Ok(self
            .registry
            .destinations(active_only, organization_id, provider, mode)
            .await?
            .into_iter()
            .filter(|entry| match organization_id {
                Some(expected) => {
                    entry.is_system || entry.organization_id.as_deref() == Some(expected)
                }
                None => entry.is_system,
            })
            .collect())
    }

    pub async fn get_destination(
        &self,
        user_id: &str,
        destination_id: &str,
    ) -> Result<DeliveryDestinationEntry, CredentialTemplateApplicationError> {
        let entry = self.load_destination(destination_id).await?;
        if let Some(organization_id) = entry.organization_id.as_deref() {
            self.control_plane
                .require_membership(user_id, organization_id)
                .await?;
        }
        Ok(entry)
    }

    pub async fn create_destination(
        &self,
        command: CreateDestinationCommand,
    ) -> Result<DeliveryDestinationEntry, CredentialTemplateApplicationError> {
        self.control_plane
            .require_destination_admin(&command.user_id, &command.organization_id)
            .await?;
        let entry = DeliveryDestinationEntry {
            id: command.id.unwrap_or_else(|| Uuid::new_v4().to_string()),
            organization_id: Some(command.organization_id),
            is_system: false,
            name: command.name,
            description: command.description,
            provider: command.provider,
            mode: command.mode,
            setup_actor: command.setup_actor,
            delivery_target: command.delivery_target,
            wallet_profile_id: command.wallet_profile_id,
            credential_format: normalize_upper(command.credential_format.as_deref()),
            issuance_protocol: command
                .issuance_protocol
                .as_deref()
                .map(|value| normalize_issuance_protocol(Some(value))),
            compliance_profile_code: normalize_upper(command.compliance_profile_code.as_deref()),
            connector_type: command.connector_type,
            connector_id: command.connector_id,
            requires_consent: command.requires_consent,
            claim_projection_policy: command.claim_projection_policy,
            setup_requirements: command.setup_requirements,
            capabilities: command.capabilities,
            docs_url: command.docs_url,
            is_enabled: command.is_enabled,
            created_at: command.now,
            updated_at: command.now,
        };
        validate_destination(&entry)?;
        if self.registry.destination_by_id(&entry.id).await?.is_some() {
            return Err(CredentialTemplateApplicationError::AlreadyExists(
                entry.id.clone(),
            ));
        }
        self.registry.save_destination(&entry).await?;
        Ok(entry)
    }

    pub async fn update_destination(
        &self,
        user_id: &str,
        destination_id: &str,
        patch: UpdateDestinationPatch,
        now: DateTime<Utc>,
    ) -> Result<DeliveryDestinationEntry, CredentialTemplateApplicationError> {
        let mut entry = self.load_destination(destination_id).await?;
        if entry.is_system {
            return Err(CredentialTemplateApplicationError::SystemDestinationReadOnly);
        }
        let organization_id = entry.organization_id.as_deref().ok_or(
            CredentialTemplateApplicationError::InvalidCommand(
                "organization destination has no owner",
            ),
        )?;
        self.control_plane
            .require_destination_admin(user_id, organization_id)
            .await?;
        apply_destination_patch(&mut entry, patch);
        validate_destination(&entry)?;
        entry.updated_at = now;
        self.registry.save_destination(&entry).await?;
        Ok(entry)
    }

    pub async fn delete_destination(
        &self,
        user_id: &str,
        destination_id: &str,
    ) -> Result<(), CredentialTemplateApplicationError> {
        let entry = self.load_destination(destination_id).await?;
        if entry.is_system {
            return Err(CredentialTemplateApplicationError::SystemDestinationReadOnly);
        }
        let organization_id = entry.organization_id.as_deref().ok_or(
            CredentialTemplateApplicationError::InvalidCommand(
                "organization destination has no owner",
            ),
        )?;
        self.control_plane
            .require_destination_admin(user_id, organization_id)
            .await?;
        if !self.registry.delete_destination(destination_id).await? {
            return Err(CredentialTemplateApplicationError::DestinationNotFound(
                destination_id.to_owned(),
            ));
        }
        Ok(())
    }

    async fn load_wallet(
        &self,
        wallet_id: &str,
    ) -> Result<WalletRegistryEntry, CredentialTemplateApplicationError> {
        self.registry
            .wallet_by_id(wallet_id)
            .await?
            .ok_or_else(|| CredentialTemplateApplicationError::WalletNotFound(wallet_id.to_owned()))
    }

    async fn load_destination(
        &self,
        destination_id: &str,
    ) -> Result<DeliveryDestinationEntry, CredentialTemplateApplicationError> {
        self.registry
            .destination_by_id(destination_id)
            .await?
            .ok_or_else(|| {
                CredentialTemplateApplicationError::DestinationNotFound(destination_id.to_owned())
            })
    }

    async fn matching_overrides(
        &self,
        organization_id: &str,
        profile: &DerivedWalletProfile,
    ) -> Result<Vec<WalletRegistryEntry>, CredentialTemplateApplicationError> {
        let entries = self.registry.wallets(true).await?;
        Ok(matching_wallet_overrides(
            &entries,
            organization_id,
            &profile.credential_format,
            &profile.issuance_protocol,
            profile.compliance_profile_code.as_deref(),
        ))
    }
}

fn apply_wallet_patch(
    entry: &mut WalletRegistryEntry,
    patch: UpdateWalletPatch,
) -> Result<(), CredentialTemplateApplicationError> {
    if let Some(value) = patch.credential_format {
        entry.credential_format = normalize_upper(Some(&value));
    }
    if let Some(value) = patch.issuance_protocol {
        entry.issuance_protocol =
            normalize_non_empty(&value).map(|value| normalize_issuance_protocol(Some(value)));
    }
    if let Some(value) = patch.compliance_profile_code {
        entry.compliance_profile_code = normalize_upper(Some(&value));
    }
    set_if_some(&mut entry.name, patch.name);
    set_if_some(&mut entry.description, patch.description.map(Some));
    set_if_some(&mut entry.wallet_apps, patch.wallet_apps);
    set_if_some(&mut entry.specifications, patch.specifications);
    set_if_some(&mut entry.logo_url, patch.logo_url.map(Some));
    set_if_some(&mut entry.deep_link_template, patch.deep_link_template);
    set_if_some(&mut entry.routing_templates, patch.routing_templates);
    set_if_some(&mut entry.install_urls, patch.install_urls);
    set_if_some(&mut entry.ios_scheme, patch.ios_scheme.map(Some));
    set_if_some(
        &mut entry.universal_link_template,
        patch.universal_link_template.map(Some),
    );
    set_if_some(&mut entry.android_package, patch.android_package.map(Some));
    set_if_some(&mut entry.supported_formats, patch.supported_formats);
    if let Some(values) = patch.supported_protocols {
        entry.supported_protocols = values
            .iter()
            .map(|value| normalize_issuance_protocol(Some(value)))
            .collect();
    }
    set_if_some(&mut entry.platforms, patch.platforms);
    set_if_some(&mut entry.supports_qr, patch.supports_qr);
    set_if_some(&mut entry.supports_deeplink, patch.supports_deeplink);
    set_if_some(
        &mut entry.supports_digital_credentials,
        patch.supports_digital_credentials,
    );
    set_if_some(&mut entry.supports_haip, patch.supports_haip);
    set_if_some(&mut entry.docs_url, patch.docs_url.map(Some));
    set_if_some(&mut entry.is_active, patch.is_active);
    set_if_some(&mut entry.override_precedence, patch.override_precedence);
    if let Some(value) = patch.merge_strategy {
        entry.merge_strategy = MergeStrategy::parse(&value.to_ascii_uppercase())?;
    }
    Ok(())
}

fn apply_destination_patch(entry: &mut DeliveryDestinationEntry, patch: UpdateDestinationPatch) {
    set_if_some(&mut entry.name, patch.name);
    set_if_some(&mut entry.description, patch.description.map(Some));
    set_if_some(&mut entry.provider, patch.provider);
    set_if_some(&mut entry.mode, patch.mode);
    set_if_some(&mut entry.setup_actor, patch.setup_actor);
    set_if_some(&mut entry.delivery_target, patch.delivery_target);
    set_if_some(
        &mut entry.wallet_profile_id,
        patch.wallet_profile_id.map(Some),
    );
    if let Some(value) = patch.credential_format {
        entry.credential_format = normalize_upper(Some(&value));
    }
    if let Some(value) = patch.issuance_protocol {
        entry.issuance_protocol =
            normalize_non_empty(&value).map(|value| normalize_issuance_protocol(Some(value)));
    }
    if let Some(value) = patch.compliance_profile_code {
        entry.compliance_profile_code = normalize_upper(Some(&value));
    }
    set_if_some(&mut entry.connector_type, patch.connector_type.map(Some));
    set_if_some(&mut entry.connector_id, patch.connector_id.map(Some));
    set_if_some(&mut entry.requires_consent, patch.requires_consent);
    set_if_some(
        &mut entry.claim_projection_policy,
        patch.claim_projection_policy,
    );
    set_if_some(&mut entry.setup_requirements, patch.setup_requirements);
    set_if_some(&mut entry.capabilities, patch.capabilities);
    set_if_some(&mut entry.docs_url, patch.docs_url.map(Some));
    set_if_some(&mut entry.is_enabled, patch.is_enabled);
}

fn validate_destination(
    entry: &DeliveryDestinationEntry,
) -> Result<(), CredentialTemplateApplicationError> {
    DeliveryDestinationPolicy {
        provider: entry.provider.clone(),
        mode: entry.mode.clone(),
        setup_actor: entry.setup_actor.clone(),
        delivery_target: entry.delivery_target.clone(),
        is_system: entry.is_system,
        organization_id: entry.organization_id.clone(),
    }
    .validate()?;
    Ok(())
}

fn compliance_profile_code(profile: &Option<Value>) -> Option<String> {
    let object = profile.as_ref()?.as_object()?;
    object
        .get("compliance_code")
        .or_else(|| object.get("code"))
        .and_then(Value::as_str)
        .and_then(|value| normalize_upper(Some(value)))
}

fn normalize_upper(value: Option<&str>) -> Option<String> {
    value
        .and_then(normalize_non_empty)
        .map(str::to_ascii_uppercase)
}

fn normalize_non_empty(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn set_if_some<T>(target: &mut T, value: Option<T>) {
    if let Some(value) = value {
        *target = value;
    }
}
