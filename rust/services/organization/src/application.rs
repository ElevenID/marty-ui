use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use chrono::{DateTime, Utc};
use mmf_messaging::{MessagingError, PostgresOutboxStore};
use mmf_security::CedarPolicyValidator;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sqlx::{Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::cache::{OrganizationCache, OrganizationCacheError};
use crate::catalog::{
    materialize_permission_catalog, materialize_system_roles, CatalogError, SeedError,
};
use crate::domain::{
    DomainError, JoinCode, JoinMechanism, Member, MemberStatus, Organization, OrganizationCreate,
    OrganizationType, Permission, Role,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteMemberCommand {
    pub organization_id: Uuid,
    pub email: String,
    pub role_ids: Vec<Uuid>,
    pub invited_by: String,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptInvitationCommand {
    pub member_id: Uuid,
    pub user_id: String,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetMemberRolesCommand {
    pub member_id: Uuid,
    pub organization_id: Uuid,
    pub role_ids: Vec<Uuid>,
    pub updated_by: String,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoveMemberCommand {
    pub member_id: Uuid,
    pub removed_by: String,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddMemberDirectCommand {
    pub organization_id: Uuid,
    pub user_id: String,
    pub email: Option<String>,
    pub role_ids: Option<Vec<Uuid>>,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinByCodeCommand {
    pub user_id: String,
    pub code: String,
    pub email: String,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinOrganizationCommand {
    pub user_id: String,
    pub organization_id: Uuid,
    pub email: String,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct JoinCodeValidation {
    pub is_valid: bool,
    pub organization: Option<Organization>,
    pub message: String,
    pub expired: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinCodeState {
    Valid,
    Inactive,
    Expired,
    Exhausted,
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JoinCodeEvaluation {
    pub state: JoinCodeState,
    pub message: &'static str,
    pub expired: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MembershipPolicy {
    pub marty_organization_id: Option<Uuid>,
    pub marty_admin_emails: BTreeSet<String>,
}

impl MembershipPolicy {
    #[must_use]
    pub fn new(
        marty_organization_id: Option<Uuid>,
        marty_admin_emails: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            marty_organization_id,
            marty_admin_emails: marty_admin_emails
                .into_iter()
                .map(|email| email.trim().to_lowercase())
                .filter(|email| !email.is_empty())
                .collect(),
        }
    }

    fn grants_marty_admin(&self, organization_id: Uuid, email: Option<&str>) -> bool {
        self.marty_organization_id == Some(organization_id)
            && email.is_some_and(|email| {
                self.marty_admin_emails
                    .contains(email.trim().to_lowercase().as_str())
            })
    }
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
    MembershipCacheInvalidationFailed,
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
    #[error("ORGANIZATION.APPLICATION_MEMBER_NOT_FOUND: {0}")]
    MemberNotFound(Uuid),
    #[error("ORGANIZATION.APPLICATION_ROLE_NOT_FOUND: {0}")]
    RoleNotFound(Uuid),
    #[error("ORGANIZATION.APPLICATION_PERMISSION_NOT_FOUND: {0}")]
    PermissionNotFound(Uuid),
    #[error("ORGANIZATION.APPLICATION_ROLE_CONFLICT: {0}")]
    RoleConflict(String),
    #[error("ORGANIZATION.APPLICATION_SYSTEM_ROLE_DELETE_FORBIDDEN")]
    SystemRoleDeleteForbidden,
    #[error("ORGANIZATION.APPLICATION_REPLACEMENT_ROLE_REQUIRED")]
    ReplacementRoleRequired,
    #[error("ORGANIZATION.APPLICATION_LAST_MEMBER_ROLE_REMOVAL_FORBIDDEN")]
    LastMemberRoleRemovalForbidden,
    #[error("ORGANIZATION.APPLICATION_ROLE_NOT_ASSIGNED")]
    RoleNotAssigned,
    #[error("ORGANIZATION.APPLICATION_POLICY_SET_NOT_FOUND: {0}")]
    PolicySetNotFound(Uuid),
    #[error("ORGANIZATION.APPLICATION_POLICY_VALIDATOR_UNAVAILABLE")]
    PolicyValidatorUnavailable,
    #[error("ORGANIZATION.APPLICATION_INVALID_POLICY: {0}")]
    InvalidPolicy(String),
    #[error("ORGANIZATION.APPLICATION_INVALID_AUDIT_FILTER: {0}")]
    InvalidAuditFilter(&'static str),
    #[error("ORGANIZATION.AUTHENTICATION_REQUIRED")]
    AuthenticationRequired,
    #[error("ORGANIZATION.MEMBERSHIP_REQUIRED")]
    MembershipRequired,
    #[error("ORGANIZATION.MEMBERSHIP_INACTIVE")]
    MembershipInactive,
    #[error("ORGANIZATION.ACTION_NOT_AUTHORIZED")]
    ActionNotAuthorized,
    #[error("ORGANIZATION.APPLICATION_MEMBER_CONFLICT: {0}")]
    MemberConflict(String),
    #[error("ORGANIZATION.APPLICATION_DEFAULT_ROLE_MISSING")]
    DefaultRoleMissing,
    #[error("ORGANIZATION.APPLICATION_ADMIN_ROLE_MISSING")]
    AdminRoleMissing,
    #[error("ORGANIZATION.APPLICATION_OWNER_ROLE_REQUIRED")]
    OwnerRoleRequired,
    #[error("ORGANIZATION.APPLICATION_OWNER_CANNOT_BE_REMOVED")]
    OwnerCannotBeRemoved,
    #[error("ORGANIZATION.APPLICATION_JOIN_CODE_INVALID: {0}")]
    InvalidJoinCode(&'static str),
    #[error("ORGANIZATION.APPLICATION_DIRECT_JOIN_NOT_ALLOWED")]
    DirectJoinNotAllowed,
    #[error("ORGANIZATION.APPLICATION_JOIN_REQUEST_PENDING")]
    JoinRequestPending,
    #[error("ORGANIZATION.APPLICATION_API_KEY_NOT_FOUND: {0}")]
    ApiKeyNotFound(Uuid),
    #[error("ORGANIZATION.APPLICATION_INVALID_API_KEY_SCOPE: {0}")]
    InvalidApiKeyScope(String),
    #[error("ORGANIZATION.APPLICATION_INVALID_API_KEY_BINDING: {0}")]
    InvalidApiKeyBinding(&'static str),
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
    pub(crate) store: PostgresOrganizationStore,
    pub(crate) outbox: PostgresOutboxStore,
    pub(crate) cache: OrganizationCache,
    pub(crate) membership_policy: MembershipPolicy,
    pub(crate) policy_validator: Option<Arc<CedarPolicyValidator>>,
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
            membership_policy: MembershipPolicy::default(),
            policy_validator: None,
        })
    }

    #[must_use]
    pub fn with_membership_policy(mut self, membership_policy: MembershipPolicy) -> Self {
        self.membership_policy = membership_policy;
        self
    }

    #[must_use]
    pub fn with_policy_validator(mut self, validator: Arc<CedarPolicyValidator>) -> Self {
        self.policy_validator = Some(validator);
        self
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
        self.persist_event_in_transaction(&mut transaction, &event)
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
        self.store
            .save_organization_in_transaction(&mut transaction, &organization)
            .await?;
        self.persist_event_in_transaction(&mut transaction, &event)
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

    pub async fn invite_member(
        &self,
        command: InviteMemberCommand,
    ) -> Result<MutationResult<Member>, OrganizationApplicationError> {
        require_non_empty(&command.email, "email is required")?;
        require_non_empty(&command.invited_by, "invited_by is required")?;
        if command.role_ids.is_empty() {
            return Err(OrganizationApplicationError::InvalidCommand(
                "invites must include at least one role",
            ));
        }
        let mut transaction = self.store.begin_transaction().await?;
        self.store
            .organization_by_id_for_update_in_transaction(&mut transaction, command.organization_id)
            .await?
            .ok_or(OrganizationApplicationError::NotFound(
                command.organization_id,
            ))?;
        if self
            .store
            .member_by_email_and_organization_for_update_in_transaction(
                &mut transaction,
                &command.email,
                command.organization_id,
            )
            .await?
            .is_some()
        {
            return Err(OrganizationApplicationError::MemberConflict(format!(
                "{} is already invited or is a member",
                command.email
            )));
        }
        let roles = self
            .validated_roles_in_transaction(
                &mut transaction,
                command.organization_id,
                &command.role_ids,
            )
            .await?;
        let mut member = Member::create_invitation(
            command.organization_id,
            command.email.clone(),
            command.invited_by.clone(),
            command.now,
        );
        self.store
            .save_member_in_transaction(&mut transaction, &member)
            .await?;
        self.store
            .set_member_roles_in_transaction(
                &mut transaction,
                member.id,
                &roles.iter().map(|role| role.id).collect::<Vec<_>>(),
            )
            .await?;
        member.roles = roles;
        let event = member_invited_event(&command, member.id)?;
        self.persist_event_in_transaction(&mut transaction, &event)
            .await?;
        transaction.commit().await.map_err(RepositoryError::from)?;
        Ok(MutationResult::without_warnings(member))
    }

    pub async fn accept_invitation(
        &self,
        command: AcceptInvitationCommand,
    ) -> Result<MutationResult<Member>, OrganizationApplicationError> {
        require_non_empty(&command.user_id, "user_id is required")?;
        let mut transaction = self.store.begin_transaction().await?;
        let mut member = self
            .store
            .member_by_id_for_update_in_transaction(&mut transaction, command.member_id)
            .await?
            .ok_or(OrganizationApplicationError::MemberNotFound(
                command.member_id,
            ))?;
        member.accept_invitation(command.user_id.clone(), command.now)?;
        self.store
            .save_member_in_transaction(&mut transaction, &member)
            .await?;
        let event = member_added_event(&member, command.now)?;
        self.persist_event_in_transaction(&mut transaction, &event)
            .await?;
        transaction.commit().await.map_err(RepositoryError::from)?;
        let warnings = self
            .invalidate_member_after_commit(&member.user_id, member.organization_id)
            .await;
        Ok(MutationResult {
            value: member,
            warnings,
        })
    }

    pub async fn set_member_roles(
        &self,
        command: SetMemberRolesCommand,
    ) -> Result<MutationResult<Member>, OrganizationApplicationError> {
        require_non_empty(&command.updated_by, "updated_by is required")?;
        if command.role_ids.is_empty() {
            return Err(OrganizationApplicationError::InvalidCommand(
                "a member must have at least one role",
            ));
        }
        let mut transaction = self.store.begin_transaction().await?;
        let mut member = self
            .store
            .member_by_id_for_update_in_transaction(&mut transaction, command.member_id)
            .await?
            .ok_or(OrganizationApplicationError::MemberNotFound(
                command.member_id,
            ))?;
        if member.organization_id != command.organization_id {
            return Err(OrganizationApplicationError::MemberNotFound(
                command.member_id,
            ));
        }
        let organization = self
            .store
            .organization_by_id_for_update_in_transaction(&mut transaction, command.organization_id)
            .await?
            .ok_or(OrganizationApplicationError::NotFound(
                command.organization_id,
            ))?;
        let roles = self
            .validated_roles_in_transaction(
                &mut transaction,
                command.organization_id,
                &command.role_ids,
            )
            .await?;
        if member.user_id == organization.owner_id && !roles.iter().any(|role| role.name == "owner")
        {
            return Err(OrganizationApplicationError::OwnerRoleRequired);
        }
        self.store
            .set_member_roles_in_transaction(
                &mut transaction,
                member.id,
                &roles.iter().map(|role| role.id).collect::<Vec<_>>(),
            )
            .await?;
        member.roles = roles;
        member.updated_at = command.now;
        self.store
            .save_member_in_transaction(&mut transaction, &member)
            .await?;
        transaction.commit().await.map_err(RepositoryError::from)?;
        let warnings = self
            .invalidate_member_after_commit(&member.user_id, member.organization_id)
            .await;
        Ok(MutationResult {
            value: member,
            warnings,
        })
    }

    pub async fn remove_member(
        &self,
        command: RemoveMemberCommand,
    ) -> Result<MutationResult<()>, OrganizationApplicationError> {
        require_non_empty(&command.removed_by, "removed_by is required")?;
        let mut transaction = self.store.begin_transaction().await?;
        let member = self
            .store
            .member_by_id_for_update_in_transaction(&mut transaction, command.member_id)
            .await?
            .ok_or(OrganizationApplicationError::MemberNotFound(
                command.member_id,
            ))?;
        let organization = self
            .store
            .organization_by_id_for_update_in_transaction(&mut transaction, member.organization_id)
            .await?
            .ok_or(OrganizationApplicationError::NotFound(
                member.organization_id,
            ))?;
        if !organization.owner_id.is_empty() && member.user_id == organization.owner_id {
            return Err(OrganizationApplicationError::OwnerCannotBeRemoved);
        }
        let event = member_removed_event(&member, command.now)?;
        if !self
            .store
            .delete_member_in_transaction(&mut transaction, member.id)
            .await?
        {
            return Err(OrganizationApplicationError::MemberNotFound(member.id));
        }
        self.persist_event_in_transaction(&mut transaction, &event)
            .await?;
        transaction.commit().await.map_err(RepositoryError::from)?;
        let warnings = self
            .invalidate_member_after_commit(&member.user_id, member.organization_id)
            .await;
        Ok(MutationResult {
            value: (),
            warnings,
        })
    }

    pub async fn list_members(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<Member>, OrganizationApplicationError> {
        Ok(self.store.members_by_organization(organization_id).await?)
    }

    pub async fn get_membership(
        &self,
        user_id: &str,
        organization_id: Uuid,
    ) -> Result<Option<Member>, OrganizationApplicationError> {
        require_non_empty(user_id, "user_id is required")?;
        Ok(self
            .store
            .member_by_user_and_organization(user_id, organization_id)
            .await?)
    }

    pub async fn add_member_direct(
        &self,
        command: AddMemberDirectCommand,
    ) -> Result<MutationResult<Member>, OrganizationApplicationError> {
        require_non_empty(&command.user_id, "user_id is required")?;
        if command
            .email
            .as_deref()
            .is_some_and(|email| email.trim().is_empty())
        {
            return Err(OrganizationApplicationError::InvalidCommand(
                "email must not be empty",
            ));
        }
        let mut transaction = self.store.begin_transaction().await?;
        let organization = self
            .store
            .organization_by_id_for_update_in_transaction(&mut transaction, command.organization_id)
            .await?
            .ok_or(OrganizationApplicationError::NotFound(
                command.organization_id,
            ))?;

        if let Some(mut member) = self
            .store
            .member_by_user_and_organization_for_update_in_transaction(
                &mut transaction,
                &command.user_id,
                command.organization_id,
            )
            .await?
        {
            let roles = self
                .resolve_direct_roles_in_transaction(
                    &mut transaction,
                    command.organization_id,
                    command.email.as_deref(),
                    command.role_ids.as_deref(),
                    &member.roles,
                )
                .await?;
            validate_owner_roles(&organization, &member.user_id, &roles)?;
            let changed = role_id_set(&roles) != role_id_set(&member.roles);
            if changed {
                let ids = roles.iter().map(|role| role.id).collect::<Vec<_>>();
                self.store
                    .set_member_roles_in_transaction(&mut transaction, member.id, &ids)
                    .await?;
                member.roles = roles;
                member.updated_at = command.now;
                self.store
                    .save_member_in_transaction(&mut transaction, &member)
                    .await?;
            }
            transaction.commit().await.map_err(RepositoryError::from)?;
            let warnings = if changed {
                self.invalidate_member_after_commit(&member.user_id, member.organization_id)
                    .await
            } else {
                Vec::new()
            };
            return Ok(MutationResult {
                value: member,
                warnings,
            });
        }

        if let Some(email) = command.email.as_deref() {
            if let Some(mut member) = self
                .store
                .member_by_email_and_organization_for_update_in_transaction(
                    &mut transaction,
                    email,
                    command.organization_id,
                )
                .await?
            {
                if !member.user_id.is_empty() {
                    return Err(OrganizationApplicationError::MemberConflict(format!(
                        "{email} is already linked to another member"
                    )));
                }
                let roles = self
                    .resolve_direct_roles_in_transaction(
                        &mut transaction,
                        command.organization_id,
                        command.email.as_deref(),
                        command.role_ids.as_deref(),
                        &member.roles,
                    )
                    .await?;
                validate_owner_roles(&organization, &command.user_id, &roles)?;
                member.user_id.clone_from(&command.user_id);
                member.joined_at = Some(command.now);
                member.updated_at = command.now;
                self.store
                    .save_member_in_transaction(&mut transaction, &member)
                    .await?;
                let ids = roles.iter().map(|role| role.id).collect::<Vec<_>>();
                self.store
                    .set_member_roles_in_transaction(&mut transaction, member.id, &ids)
                    .await?;
                member.roles = roles;
                transaction.commit().await.map_err(RepositoryError::from)?;
                let warnings = self
                    .invalidate_member_after_commit(&member.user_id, member.organization_id)
                    .await;
                return Ok(MutationResult {
                    value: member,
                    warnings,
                });
            }
        }

        let mut member = Member::create(
            command.organization_id,
            command.user_id,
            command.email.clone(),
            MemberStatus::Active,
            command.now,
        );
        let roles = self
            .resolve_direct_roles_in_transaction(
                &mut transaction,
                command.organization_id,
                command.email.as_deref(),
                command.role_ids.as_deref(),
                &[],
            )
            .await?;
        validate_owner_roles(&organization, &member.user_id, &roles)?;
        self.store
            .save_member_in_transaction(&mut transaction, &member)
            .await?;
        let ids = roles.iter().map(|role| role.id).collect::<Vec<_>>();
        self.store
            .set_member_roles_in_transaction(&mut transaction, member.id, &ids)
            .await?;
        member.roles = roles;
        let event = member_added_event(&member, command.now)?;
        self.persist_event_in_transaction(&mut transaction, &event)
            .await?;
        transaction.commit().await.map_err(RepositoryError::from)?;
        let warnings = self
            .invalidate_member_after_commit(&member.user_id, member.organization_id)
            .await;
        Ok(MutationResult {
            value: member,
            warnings,
        })
    }

    pub async fn join_by_code(
        &self,
        command: JoinByCodeCommand,
    ) -> Result<MutationResult<(Organization, Member)>, OrganizationApplicationError> {
        require_non_empty(&command.user_id, "user_id is required")?;
        require_non_empty(&command.email, "email is required")?;
        let code = normalize_join_code(&command.code)?;
        let mut transaction = self.store.begin_transaction().await?;
        let mut join_code = self
            .store
            .join_code_by_code_for_update_in_transaction(&mut transaction, &code)
            .await?
            .ok_or(OrganizationApplicationError::InvalidJoinCode("not found"))?;
        validate_join_code_state(&join_code, command.now)?;
        let organization = self
            .store
            .organization_by_id_for_update_in_transaction(
                &mut transaction,
                join_code.organization_id,
            )
            .await?
            .ok_or(OrganizationApplicationError::NotFound(
                join_code.organization_id,
            ))?;
        if self
            .store
            .member_by_user_and_organization_for_update_in_transaction(
                &mut transaction,
                &command.user_id,
                organization.id,
            )
            .await?
            .is_some()
        {
            return Err(OrganizationApplicationError::MemberConflict(
                "already a member of this organization".into(),
            ));
        }
        let roles = self
            .default_roles_in_transaction(&mut transaction, organization.id)
            .await?;
        let status = if organization.requires_approval {
            MemberStatus::Pending
        } else {
            MemberStatus::Active
        };
        let mut member = Member::create(
            organization.id,
            command.user_id,
            Some(command.email),
            status,
            command.now,
        );
        join_code.increment_usage(command.now)?;
        self.store
            .save_member_in_transaction(&mut transaction, &member)
            .await?;
        let ids = roles.iter().map(|role| role.id).collect::<Vec<_>>();
        self.store
            .set_member_roles_in_transaction(&mut transaction, member.id, &ids)
            .await?;
        member.roles = roles;
        self.store
            .save_join_code_in_transaction(&mut transaction, &join_code)
            .await?;
        let event = member_added_event(&member, command.now)?;
        self.persist_event_in_transaction(&mut transaction, &event)
            .await?;
        transaction.commit().await.map_err(RepositoryError::from)?;
        let warnings = self
            .invalidate_member_after_commit(&member.user_id, member.organization_id)
            .await;
        Ok(MutationResult {
            value: (organization, member),
            warnings,
        })
    }

    pub async fn join_organization(
        &self,
        command: JoinOrganizationCommand,
    ) -> Result<MutationResult<(Organization, Member)>, OrganizationApplicationError> {
        require_non_empty(&command.user_id, "user_id is required")?;
        require_non_empty(&command.email, "email is required")?;
        let mut transaction = self.store.begin_transaction().await?;
        let organization = self
            .store
            .organization_by_id_for_update_in_transaction(&mut transaction, command.organization_id)
            .await?
            .ok_or(OrganizationApplicationError::NotFound(
                command.organization_id,
            ))?;
        if organization.join_mechanism != JoinMechanism::Open {
            return Err(OrganizationApplicationError::DirectJoinNotAllowed);
        }
        if let Some(existing) = self
            .store
            .member_by_user_and_organization_for_update_in_transaction(
                &mut transaction,
                &command.user_id,
                organization.id,
            )
            .await?
        {
            return if existing.status == MemberStatus::Pending {
                Err(OrganizationApplicationError::JoinRequestPending)
            } else {
                Err(OrganizationApplicationError::MemberConflict(
                    "already a member of this organization".into(),
                ))
            };
        }
        let roles = self
            .default_roles_in_transaction(&mut transaction, organization.id)
            .await?;
        let status = if organization.requires_approval {
            MemberStatus::Pending
        } else {
            MemberStatus::Active
        };
        let mut member = Member::create(
            organization.id,
            command.user_id,
            Some(command.email),
            status,
            command.now,
        );
        self.store
            .save_member_in_transaction(&mut transaction, &member)
            .await?;
        let ids = roles.iter().map(|role| role.id).collect::<Vec<_>>();
        self.store
            .set_member_roles_in_transaction(&mut transaction, member.id, &ids)
            .await?;
        member.roles = roles;
        let event = member_added_event(&member, command.now)?;
        self.persist_event_in_transaction(&mut transaction, &event)
            .await?;
        transaction.commit().await.map_err(RepositoryError::from)?;
        let warnings = self
            .invalidate_member_after_commit(&member.user_id, member.organization_id)
            .await;
        Ok(MutationResult {
            value: (organization, member),
            warnings,
        })
    }

    pub async fn validate_join_code(
        &self,
        code: &str,
        now: DateTime<Utc>,
    ) -> Result<JoinCodeValidation, OrganizationApplicationError> {
        let code = match normalize_join_code(code) {
            Ok(code) => code,
            Err(_) => {
                return Ok(invalid_join_code_validation("Join code is required", false));
            }
        };
        let Some(join_code) = self.store.join_code_by_code(&code).await? else {
            return Ok(invalid_join_code_validation(
                "Invitation code not found",
                false,
            ));
        };
        let evaluation = evaluate_join_code(&join_code, now);
        if evaluation.state != JoinCodeState::Valid {
            return Ok(invalid_join_code_validation(
                evaluation.message,
                evaluation.expired,
            ));
        }
        let Some(organization) = self
            .store
            .organization_by_id(join_code.organization_id)
            .await?
        else {
            return Ok(invalid_join_code_validation(
                "Organization not found",
                false,
            ));
        };
        Ok(JoinCodeValidation {
            is_valid: true,
            message: format!("Valid invitation to join {}", organization.name),
            organization: Some(organization),
            expired: false,
        })
    }

    async fn validated_roles_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        organization_id: Uuid,
        role_ids: &[Uuid],
    ) -> Result<Vec<Role>, OrganizationApplicationError> {
        let unique_role_ids = deduplicate_ids(role_ids);
        if unique_role_ids.is_empty() {
            return Err(OrganizationApplicationError::InvalidCommand(
                "a member must have at least one role",
            ));
        }
        let roles = self
            .store
            .roles_by_ids_for_organization_in_transaction(
                transaction,
                organization_id,
                &unique_role_ids,
            )
            .await?;
        let found = role_id_set(&roles);
        if let Some(missing) = unique_role_ids
            .into_iter()
            .find(|role_id| !found.contains(role_id))
        {
            return Err(OrganizationApplicationError::RoleNotFound(missing));
        }
        Ok(roles)
    }

    async fn default_roles_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        organization_id: Uuid,
    ) -> Result<Vec<Role>, OrganizationApplicationError> {
        let roles = self
            .store
            .default_roles_for_organization_in_transaction(transaction, organization_id)
            .await?;
        if roles.is_empty() {
            Err(OrganizationApplicationError::DefaultRoleMissing)
        } else {
            Ok(roles)
        }
    }

    async fn resolve_direct_roles_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        organization_id: Uuid,
        email: Option<&str>,
        requested_role_ids: Option<&[Uuid]>,
        current_roles: &[Role],
    ) -> Result<Vec<Role>, OrganizationApplicationError> {
        let requested_roles = match requested_role_ids.filter(|role_ids| !role_ids.is_empty()) {
            Some(role_ids) => Some(
                self.validated_roles_in_transaction(transaction, organization_id, role_ids)
                    .await?,
            ),
            None => None,
        };
        let grants_marty_admin = self
            .membership_policy
            .grants_marty_admin(organization_id, email);
        let admin_role = if grants_marty_admin {
            Some(
                self.store
                    .role_by_name_in_transaction(transaction, organization_id, "admin")
                    .await?
                    .ok_or(OrganizationApplicationError::AdminRoleMissing)?,
            )
        } else {
            None
        };
        let default_roles = self
            .store
            .default_roles_for_organization_in_transaction(transaction, organization_id)
            .await?;
        plan_direct_member_roles(
            grants_marty_admin,
            requested_roles.as_deref(),
            current_roles,
            admin_role.as_ref(),
            &default_roles,
        )
    }

    pub(crate) async fn invalidate_member_after_commit(
        &self,
        user_id: &str,
        organization_id: Uuid,
    ) -> Vec<ApplicationWarning> {
        if user_id.trim().is_empty() {
            return Vec::new();
        }
        self.cache
            .invalidate_member(user_id, organization_id)
            .await
            .err()
            .map(|error| ApplicationWarning {
                code: ApplicationWarningCode::MembershipCacheInvalidationFailed,
                message: error.to_string(),
            })
            .into_iter()
            .collect()
    }

    pub(crate) async fn persist_event_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        event: &OrganizationEvent,
    ) -> Result<(), OrganizationApplicationError> {
        let audit = event.to_audit_event()?;
        let message = event.to_message()?;
        self.store
            .save_audit_event_in_transaction(transaction, &audit)
            .await?;
        self.outbox
            .enqueue_in_transaction(transaction, message)
            .await?;
        Ok(())
    }
}

pub fn plan_direct_member_roles(
    grants_marty_admin: bool,
    requested_roles: Option<&[Role]>,
    current_roles: &[Role],
    admin_role: Option<&Role>,
    default_roles: &[Role],
) -> Result<Vec<Role>, OrganizationApplicationError> {
    let explicitly_requested = requested_roles.is_some_and(|roles| !roles.is_empty());
    let mut resolved = requested_roles
        .filter(|roles| !roles.is_empty())
        .unwrap_or(current_roles)
        .to_vec();
    if grants_marty_admin {
        let admin = admin_role.ok_or(OrganizationApplicationError::AdminRoleMissing)?;
        let current_names = current_roles
            .iter()
            .map(|role| role.name.as_str())
            .collect::<BTreeSet<_>>();
        if explicitly_requested {
            if !resolved.iter().any(|role| role.id == admin.id) {
                resolved.push(admin.clone());
            }
        } else if resolved.is_empty() || current_names == BTreeSet::from(["applicant"]) {
            resolved = vec![admin.clone()];
        } else if !current_names.contains("admin")
            && !resolved.iter().any(|role| role.id == admin.id)
        {
            resolved.push(admin.clone());
        }
    }
    if resolved.is_empty() {
        if default_roles.is_empty() {
            return Err(OrganizationApplicationError::DefaultRoleMissing);
        }
        resolved = default_roles.to_vec();
    }
    let mut seen = BTreeSet::new();
    resolved.retain(|role| seen.insert(role.id));
    Ok(resolved)
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

fn deduplicate_ids(role_ids: &[Uuid]) -> Vec<Uuid> {
    let mut seen = BTreeSet::new();
    role_ids
        .iter()
        .copied()
        .filter(|role_id| seen.insert(*role_id))
        .collect()
}

fn role_id_set(roles: &[Role]) -> BTreeSet<Uuid> {
    roles.iter().map(|role| role.id).collect()
}

fn validate_owner_roles(
    organization: &Organization,
    user_id: &str,
    roles: &[Role],
) -> Result<(), OrganizationApplicationError> {
    if !organization.owner_id.is_empty()
        && organization.owner_id == user_id
        && !roles.iter().any(|role| role.name == "owner")
    {
        Err(OrganizationApplicationError::OwnerRoleRequired)
    } else {
        Ok(())
    }
}

fn member_invited_event(
    command: &InviteMemberCommand,
    member_id: Uuid,
) -> Result<OrganizationEvent, OrganizationEventError> {
    let mut data = Map::new();
    data.insert("member_id".into(), Value::String(member_id.to_string()));
    data.insert("email".into(), Value::String(command.email.clone()));
    data.insert(
        "invited_by".into(),
        Value::String(command.invited_by.clone()),
    );
    OrganizationEvent::new(
        OrganizationEventKind::MemberInvited,
        command.organization_id,
        data,
        command.now,
    )
}

fn member_added_event(
    member: &Member,
    now: DateTime<Utc>,
) -> Result<OrganizationEvent, OrganizationEventError> {
    let mut data = Map::new();
    data.insert("member_id".into(), Value::String(member.id.to_string()));
    data.insert("user_id".into(), Value::String(member.user_id.clone()));
    data.insert(
        "roles".into(),
        Value::Array(
            member
                .role_names()
                .into_iter()
                .map(|role| Value::String(role.to_owned()))
                .collect(),
        ),
    );
    OrganizationEvent::new(
        OrganizationEventKind::MemberAdded,
        member.organization_id,
        data,
        now,
    )
}

fn member_removed_event(
    member: &Member,
    now: DateTime<Utc>,
) -> Result<OrganizationEvent, OrganizationEventError> {
    let mut data = Map::new();
    data.insert("member_id".into(), Value::String(member.id.to_string()));
    data.insert("user_id".into(), Value::String(member.user_id.clone()));
    OrganizationEvent::new(
        OrganizationEventKind::MemberRemoved,
        member.organization_id,
        data,
        now,
    )
}

fn normalize_join_code(code: &str) -> Result<String, OrganizationApplicationError> {
    let code = code.trim().to_uppercase();
    if code.is_empty() {
        Err(OrganizationApplicationError::InvalidCommand(
            "join code is required",
        ))
    } else {
        Ok(code)
    }
}

fn validate_join_code_state(
    join_code: &JoinCode,
    now: DateTime<Utc>,
) -> Result<(), OrganizationApplicationError> {
    match evaluate_join_code(join_code, now).state {
        JoinCodeState::Valid => Ok(()),
        JoinCodeState::Inactive => Err(OrganizationApplicationError::InvalidJoinCode(
            "no longer active",
        )),
        JoinCodeState::Expired => Err(OrganizationApplicationError::InvalidJoinCode("expired")),
        JoinCodeState::Exhausted => Err(OrganizationApplicationError::InvalidJoinCode(
            "maximum uses reached",
        )),
        JoinCodeState::Invalid => Err(OrganizationApplicationError::InvalidJoinCode("invalid")),
    }
}

#[must_use]
pub fn evaluate_join_code(join_code: &JoinCode, now: DateTime<Utc>) -> JoinCodeEvaluation {
    if join_code.is_valid_at(now) {
        JoinCodeEvaluation {
            state: JoinCodeState::Valid,
            message: "valid",
            expired: false,
        }
    } else if !join_code.is_active {
        JoinCodeEvaluation {
            state: JoinCodeState::Inactive,
            message: "This invitation is no longer active",
            expired: false,
        }
    } else if join_code
        .expires_at
        .is_some_and(|expires_at| now > expires_at)
    {
        JoinCodeEvaluation {
            state: JoinCodeState::Expired,
            message: "This invitation has expired",
            expired: true,
        }
    } else if join_code
        .max_uses
        .is_some_and(|max_uses| join_code.use_count >= max_uses)
    {
        JoinCodeEvaluation {
            state: JoinCodeState::Exhausted,
            message: "This invitation has reached its maximum uses",
            expired: false,
        }
    } else {
        JoinCodeEvaluation {
            state: JoinCodeState::Invalid,
            message: "Invalid invitation code",
            expired: false,
        }
    }
}

fn invalid_join_code_validation(message: &str, expired: bool) -> JoinCodeValidation {
    JoinCodeValidation {
        is_valid: false,
        organization: None,
        message: message.to_owned(),
        expired,
    }
}
