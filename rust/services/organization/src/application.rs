use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use mmf_messaging::{MessagingError, PostgresOutboxStore};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::cache::{OrganizationCache, OrganizationCacheError};
use crate::catalog::{
    materialize_permission_catalog, materialize_system_roles, CatalogError, SeedError,
};
use crate::domain::{
    DomainError, JoinMechanism, Member, MemberStatus, Organization, OrganizationCreate,
    OrganizationType, Permission,
};
use crate::events::{OrganizationEvent, OrganizationEventError, OrganizationEventKind};
use crate::migration::{migrate_organization_schema, OrganizationMigrationError};
use crate::postgres::{PostgresOrganizationStore, RepositoryError};

const OUTBOX_SOURCE: &str = "organization";
const OUTBOX_PARTITIONS: u32 = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateOrganizationCommand {
    pub name: String,
    pub owner_id: String,
    pub org_type: OrganizationType,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub contact_email: Option<String>,
    pub visibility: String,
    pub join_mechanism: JoinMechanism,
    pub requires_approval: bool,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct UpdateOrganizationPatch {
    pub name: Option<String>,
    pub display_name: Option<String>,
    pub org_type: Option<OrganizationType>,
    pub description: Option<Option<String>>,
    pub contact_email: Option<Option<String>>,
    pub contact_phone: Option<Option<String>>,
    pub website: Option<Option<String>>,
    pub visibility: Option<String>,
    pub join_mechanism: Option<JoinMechanism>,
    pub requires_approval: Option<bool>,
    pub settings: Option<Map<String, Value>>,
}

impl UpdateOrganizationPatch {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.display_name.is_none()
            && self.org_type.is_none()
            && self.description.is_none()
            && self.contact_email.is_none()
            && self.contact_phone.is_none()
            && self.website.is_none()
            && self.visibility.is_none()
            && self.join_mechanism.is_none()
            && self.requires_approval.is_none()
            && self.settings.is_none()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct UpdateOrganizationCommand {
    pub organization_id: Uuid,
    pub patch: UpdateOrganizationPatch,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OrganizationCreationPlan {
    pub organization: Organization,
    pub owner: Member,
    pub permissions: BTreeMap<String, Permission>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApplicationWarningCode {
    PlanCacheSynchronizationFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationWarning {
    pub code: ApplicationWarningCode,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MutationResult<T> {
    pub value: T,
    pub warnings: Vec<ApplicationWarning>,
}

impl<T> MutationResult<T> {
    fn without_warnings(value: T) -> Self {
        Self {
            value,
            warnings: Vec::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum OrganizationApplicationError {
    #[error("ORGANIZATION.APPLICATION_INVALID_COMMAND: {0}")]
    InvalidCommand(&'static str),
    #[error("ORGANIZATION.APPLICATION_INVALID_VISIBILITY: {0}")]
    InvalidVisibility(String),
    #[error("ORGANIZATION.APPLICATION_OPEN_JOIN_REQUIRES_PUBLIC_VISIBILITY")]
    OpenJoinRequiresPublicVisibility,
    #[error("ORGANIZATION.APPLICATION_NOT_FOUND: {0}")]
    NotFound(Uuid),
    #[error("ORGANIZATION.APPLICATION_OWNER_ROLE_MISSING")]
    OwnerRoleMissing,
    #[error("ORGANIZATION.APPLICATION_TIME_PRECEDES_UNIX_EPOCH")]
    InvalidTimestamp,
    #[error(transparent)]
    Domain(#[from] DomainError),
    #[error(transparent)]
    Catalog(#[from] CatalogError),
    #[error(transparent)]
    Seed(#[from] SeedError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    Event(#[from] OrganizationEventError),
    #[error(transparent)]
    Messaging(#[from] MessagingError),
    #[error(transparent)]
    Migration(#[from] OrganizationMigrationError),
}

#[derive(Clone)]
pub struct OrganizationApplication {
    store: PostgresOrganizationStore,
    outbox: PostgresOutboxStore,
    cache: OrganizationCache,
}

impl OrganizationApplication {
    pub fn new(
        store: PostgresOrganizationStore,
        cache: OrganizationCache,
    ) -> Result<Self, OrganizationApplicationError> {
        let outbox =
            PostgresOutboxStore::new(store.pool().clone(), OUTBOX_SOURCE, OUTBOX_PARTITIONS)?;
        Ok(Self {
            store,
            outbox,
            cache,
        })
    }

    #[must_use]
    pub const fn store(&self) -> &PostgresOrganizationStore {
        &self.store
    }

    #[must_use]
    pub const fn outbox(&self) -> &PostgresOutboxStore {
        &self.outbox
    }

    pub async fn initialize(&self) -> Result<(), OrganizationApplicationError> {
        migrate_organization_schema(self.store.pool()).await?;
        self.outbox.migrate().await?;
        Ok(())
    }

    pub async fn create_organization(
        &self,
        command: CreateOrganizationCommand,
    ) -> Result<MutationResult<Organization>, OrganizationApplicationError> {
        let now = command.now;
        let creation = plan_organization_creation(command)?;
        let mut event_data = Map::new();
        event_data.insert(
            "name".into(),
            Value::String(creation.organization.name.clone()),
        );
        event_data.insert(
            "owner_user_id".into(),
            Value::String(creation.organization.owner_id.clone()),
        );
        let event = OrganizationEvent::new(
            OrganizationEventKind::OrganizationCreated,
            creation.organization.id,
            event_data,
            now,
        )?;
        let audit = event.to_audit_event()?;
        let message = event.to_message()?;

        let mut transaction = self.store.begin_transaction().await?;
        self.store
            .save_organization_in_transaction(&mut transaction, &creation.organization)
            .await?;
        self.store
            .save_member_in_transaction(&mut transaction, &creation.owner)
            .await?;

        let mut persisted_permissions = BTreeMap::new();
        for (key, permission) in &creation.permissions {
            let permission = self
                .store
                .upsert_permission_in_transaction(&mut transaction, permission)
                .await?;
            persisted_permissions.insert(key.clone(), permission);
        }
        let roles = materialize_system_roles(
            creation.organization.id,
            &persisted_permissions,
            creation.organization.created_at,
        )?;
        for role in roles.values() {
            self.store
                .save_role_in_transaction(&mut transaction, role)
                .await?;
        }
        let owner_role = roles
            .get("owner")
            .ok_or(OrganizationApplicationError::OwnerRoleMissing)?;
        self.store
            .add_member_role_in_transaction(&mut transaction, creation.owner.id, owner_role.id)
            .await?;
        self.store
            .save_audit_event_in_transaction(&mut transaction, &audit)
            .await?;
        self.outbox
            .enqueue_in_transaction(&mut transaction, message)
            .await?;
        transaction.commit().await.map_err(RepositoryError::from)?;

        let mut result = MutationResult::without_warnings(creation.organization);
        if let Err(error) = self
            .cache
            .store_plan(result.value.id, &result.value.plan, timestamp_ms(now)?)
            .await
        {
            result.warnings.push(cache_warning(error));
        }
        Ok(result)
    }

    pub async fn update_organization(
        &self,
        command: UpdateOrganizationCommand,
    ) -> Result<MutationResult<Organization>, OrganizationApplicationError> {
        let mut transaction = self.store.begin_transaction().await?;
        let current = self
            .store
            .organization_by_id_for_update_in_transaction(&mut transaction, command.organization_id)
            .await?
            .ok_or(OrganizationApplicationError::NotFound(
                command.organization_id,
            ))?;
        let (organization, updated_fields) =
            plan_organization_update(&current, command.patch, command.now)?;
        let mut event_data = Map::new();
        event_data.insert(
            "updated_fields".into(),
            Value::Array(updated_fields.iter().cloned().map(Value::String).collect()),
        );
        let event = OrganizationEvent::new(
            OrganizationEventKind::OrganizationUpdated,
            organization.id,
            event_data,
            command.now,
        )?;
        let audit = event.to_audit_event()?;
        let message = event.to_message()?;

        self.store
            .save_organization_in_transaction(&mut transaction, &organization)
            .await?;
        self.store
            .save_audit_event_in_transaction(&mut transaction, &audit)
            .await?;
        self.outbox
            .enqueue_in_transaction(&mut transaction, message)
            .await?;
        transaction.commit().await.map_err(RepositoryError::from)?;
        Ok(MutationResult::without_warnings(organization))
    }

    pub async fn get_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<Option<Organization>, OrganizationApplicationError> {
        Ok(self.store.organization_by_id(organization_id).await?)
    }

    pub async fn list_organizations(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Organization>, OrganizationApplicationError> {
        Ok(self.store.list_organizations(limit, offset).await?)
    }

    pub async fn discover_organizations(
        &self,
        search: Option<&str>,
        org_type: Option<OrganizationType>,
        join_mechanism: Option<JoinMechanism>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<Organization>, OrganizationApplicationError> {
        Ok(self
            .store
            .list_discoverable_organizations(search, org_type, join_mechanism, limit, offset)
            .await?)
    }

    pub async fn get_user_organizations_with_memberships(
        &self,
        user_id: &str,
    ) -> Result<Vec<(Organization, Member)>, OrganizationApplicationError> {
        if user_id.trim().is_empty() {
            return Err(OrganizationApplicationError::InvalidCommand(
                "user_id is required",
            ));
        }
        let memberships = self.store.memberships_by_user(user_id).await?;
        let mut results = Vec::new();
        for membership in memberships
            .into_iter()
            .filter(|membership| membership.status == MemberStatus::Active)
        {
            if let Some(organization) = self
                .store
                .organization_by_id(membership.organization_id)
                .await?
            {
                results.push((organization, membership));
            }
        }
        Ok(results)
    }

    pub async fn get_user_organizations(
        &self,
        user_id: &str,
    ) -> Result<Vec<Organization>, OrganizationApplicationError> {
        Ok(self
            .get_user_organizations_with_memberships(user_id)
            .await?
            .into_iter()
            .map(|(organization, _)| organization)
            .collect())
    }
}

pub fn plan_organization_creation(
    command: CreateOrganizationCommand,
) -> Result<OrganizationCreationPlan, OrganizationApplicationError> {
    require_non_empty(&command.name, "name is required")?;
    require_non_empty(&command.owner_id, "owner_id is required")?;
    let is_discoverable = parse_visibility(&command.visibility)?;
    validate_admission(command.join_mechanism, is_discoverable)?;
    let (mut organization, owner) = Organization::create(OrganizationCreate {
        name: command.name,
        owner_id: command.owner_id,
        org_type: command.org_type,
        display_name: command.display_name,
        description: command.description,
        join_mechanism: command.join_mechanism,
        requires_approval: command.requires_approval,
        is_discoverable,
        now: command.now,
    })?;
    organization.contact_email = command.contact_email;
    let permissions = materialize_permission_catalog()?;
    Ok(OrganizationCreationPlan {
        organization,
        owner,
        permissions,
    })
}

pub fn plan_organization_update(
    current: &Organization,
    patch: UpdateOrganizationPatch,
    now: DateTime<Utc>,
) -> Result<(Organization, Vec<String>), OrganizationApplicationError> {
    if patch.is_empty() {
        return Err(OrganizationApplicationError::InvalidCommand(
            "at least one organization field is required",
        ));
    }
    let mut organization = current.clone();
    let mut updated_fields = Vec::new();
    if let Some(name) = patch.name {
        require_non_empty(&name, "name must not be empty")?;
        organization.name = name;
        updated_fields.push("name".into());
    }
    if let Some(display_name) = patch.display_name {
        require_non_empty(&display_name, "display_name must not be empty")?;
        organization.display_name = Some(display_name);
        updated_fields.push("display_name".into());
    }
    if let Some(org_type) = patch.org_type {
        organization.org_type = org_type;
        updated_fields.push("org_type".into());
    }
    if let Some(description) = patch.description {
        organization.description = description;
        updated_fields.push("description".into());
    }
    if let Some(contact_email) = patch.contact_email {
        organization.contact_email = contact_email;
        updated_fields.push("contact_email".into());
    }
    if let Some(contact_phone) = patch.contact_phone {
        organization.contact_phone = contact_phone;
        updated_fields.push("contact_phone".into());
    }
    if let Some(website) = patch.website {
        organization.website = website;
        updated_fields.push("website".into());
    }
    if let Some(visibility) = patch.visibility {
        organization.is_discoverable = parse_visibility(&visibility)?;
        organization.visibility = visibility;
        updated_fields.push("visibility".into());
        updated_fields.push("is_discoverable".into());
    }
    if let Some(join_mechanism) = patch.join_mechanism {
        organization.join_mechanism = join_mechanism;
        updated_fields.push("join_mechanism".into());
    }
    if let Some(requires_approval) = patch.requires_approval {
        organization.requires_approval = requires_approval;
        updated_fields.push("requires_approval".into());
    }
    if let Some(settings) = patch.settings {
        organization.settings.extend(settings);
        updated_fields.push("settings".into());
    }
    validate_admission(organization.join_mechanism, organization.is_discoverable)?;
    organization.updated_at = now;
    Ok((organization, updated_fields))
}

fn parse_visibility(visibility: &str) -> Result<bool, OrganizationApplicationError> {
    match visibility {
        "PUBLIC" => Ok(true),
        "PRIVATE" => Ok(false),
        other => Err(OrganizationApplicationError::InvalidVisibility(
            other.to_owned(),
        )),
    }
}

fn validate_admission(
    join_mechanism: JoinMechanism,
    is_discoverable: bool,
) -> Result<(), OrganizationApplicationError> {
    if join_mechanism == JoinMechanism::Open && !is_discoverable {
        Err(OrganizationApplicationError::OpenJoinRequiresPublicVisibility)
    } else {
        Ok(())
    }
}

fn require_non_empty(
    value: &str,
    message: &'static str,
) -> Result<(), OrganizationApplicationError> {
    if value.trim().is_empty() {
        Err(OrganizationApplicationError::InvalidCommand(message))
    } else {
        Ok(())
    }
}

fn timestamp_ms(now: DateTime<Utc>) -> Result<u64, OrganizationApplicationError> {
    u64::try_from(now.timestamp_millis())
        .map_err(|_| OrganizationApplicationError::InvalidTimestamp)
}

fn cache_warning(error: OrganizationCacheError) -> ApplicationWarning {
    ApplicationWarning {
        code: ApplicationWarningCode::PlanCacheSynchronizationFailed,
        message: error.to_string(),
    }
}
