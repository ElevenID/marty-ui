use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::application::{
    ApplicationWarning, MutationResult, OrganizationApplication, OrganizationApplicationError,
};
use crate::domain::{Member, Permission, Role};
use crate::events::{OrganizationEvent, OrganizationEventError, OrganizationEventKind};
use crate::postgres::RepositoryError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateRoleCommand {
    pub organization_id: Uuid,
    pub name: String,
    pub created_by: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub permission_ids: Vec<Uuid>,
    pub is_default_for_new_members: bool,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpdateRolePatch {
    pub display_name: Option<String>,
    pub description: Option<Option<String>>,
    pub permission_ids: Option<Vec<Uuid>>,
    pub is_default_for_new_members: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateRoleCommand {
    pub role_id: Uuid,
    pub organization_id: Uuid,
    pub updated_by: String,
    pub patch: UpdateRolePatch,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteRoleCommand {
    pub role_id: Uuid,
    pub organization_id: Uuid,
    pub deleted_by: String,
    pub replacement_role_id: Option<Uuid>,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddMemberRoleCommand {
    pub member_id: Uuid,
    pub organization_id: Uuid,
    pub role_id: Uuid,
    pub updated_by: String,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoveMemberRoleCommand {
    pub member_id: Uuid,
    pub organization_id: Uuid,
    pub role_id: Uuid,
    pub updated_by: String,
    pub now: DateTime<Utc>,
}

impl OrganizationApplication {
    pub async fn create_role(
        &self,
        command: CreateRoleCommand,
    ) -> Result<MutationResult<Role>, OrganizationApplicationError> {
        require_text(&command.name, "role name is required")?;
        require_text(&command.created_by, "created_by is required")?;
        let mut transaction = self.store.begin_transaction().await?;
        self.store
            .organization_by_id_for_update_in_transaction(&mut transaction, command.organization_id)
            .await?
            .ok_or(OrganizationApplicationError::NotFound(
                command.organization_id,
            ))?;
        if self
            .store
            .role_by_name_for_update_in_transaction(
                &mut transaction,
                command.organization_id,
                &command.name,
            )
            .await?
            .is_some()
        {
            return Err(OrganizationApplicationError::RoleConflict(command.name));
        }
        let permissions = self
            .permissions_in_transaction(&mut transaction, &command.permission_ids)
            .await?;
        if command.is_default_for_new_members {
            self.clear_default_roles_in_transaction(
                &mut transaction,
                command.organization_id,
                None,
                command.now,
            )
            .await?;
        }
        let role = Role {
            id: Uuid::new_v4(),
            organization_id: command.organization_id,
            name: command.name.clone(),
            display_name: Some(command.display_name.unwrap_or_else(|| command.name.clone())),
            description: command.description,
            is_system: false,
            is_default_for_new_members: command.is_default_for_new_members,
            permissions,
            created_at: command.now,
            updated_at: command.now,
        };
        self.store
            .save_role_in_transaction(&mut transaction, &role)
            .await?;
        let event = role_event(
            OrganizationEventKind::RoleCreated,
            role.organization_id,
            &role,
            "created_by",
            &command.created_by,
            command.now,
            None,
        )?;
        self.persist_event_in_transaction(&mut transaction, &event)
            .await?;
        transaction.commit().await.map_err(RepositoryError::from)?;
        Ok(MutationResult {
            value: role,
            warnings: Vec::new(),
        })
    }

    pub async fn update_role(
        &self,
        command: UpdateRoleCommand,
    ) -> Result<MutationResult<Role>, OrganizationApplicationError> {
        require_text(&command.updated_by, "updated_by is required")?;
        let mut transaction = self.store.begin_transaction().await?;
        let mut role = self
            .store
            .role_by_id_for_update_in_transaction(&mut transaction, command.role_id)
            .await?
            .filter(|role| role.organization_id == command.organization_id)
            .ok_or(OrganizationApplicationError::RoleNotFound(command.role_id))?;
        if let Some(display_name) = command.patch.display_name {
            require_text(&display_name, "display_name must not be empty")?;
            role.display_name = Some(display_name);
        }
        if let Some(description) = command.patch.description {
            role.description = description;
        }
        if let Some(permission_ids) = command.patch.permission_ids {
            role.permissions = self
                .permissions_in_transaction(&mut transaction, &permission_ids)
                .await?;
        }
        if let Some(is_default) = command.patch.is_default_for_new_members {
            if is_default {
                self.clear_default_roles_in_transaction(
                    &mut transaction,
                    command.organization_id,
                    Some(role.id),
                    command.now,
                )
                .await?;
            } else if role.is_default_for_new_members {
                return Err(OrganizationApplicationError::ReplacementRoleRequired);
            }
            role.is_default_for_new_members = is_default;
        }
        role.updated_at = command.now;
        self.store
            .save_role_in_transaction(&mut transaction, &role)
            .await?;
        let event = role_event(
            OrganizationEventKind::RoleUpdated,
            role.organization_id,
            &role,
            "updated_by",
            &command.updated_by,
            command.now,
            None,
        )?;
        self.persist_event_in_transaction(&mut transaction, &event)
            .await?;
        transaction.commit().await.map_err(RepositoryError::from)?;
        Ok(MutationResult {
            value: role,
            warnings: Vec::new(),
        })
    }

    pub async fn delete_role(
        &self,
        command: DeleteRoleCommand,
    ) -> Result<MutationResult<()>, OrganizationApplicationError> {
        require_text(&command.deleted_by, "deleted_by is required")?;
        let mut transaction = self.store.begin_transaction().await?;
        let role = self
            .store
            .role_by_id_for_update_in_transaction(&mut transaction, command.role_id)
            .await?
            .filter(|role| role.organization_id == command.organization_id)
            .ok_or(OrganizationApplicationError::RoleNotFound(command.role_id))?;
        if role.is_system {
            return Err(OrganizationApplicationError::SystemRoleDeleteForbidden);
        }
        let all_roles = self
            .store
            .roles_by_organization_for_update_in_transaction(
                &mut transaction,
                command.organization_id,
            )
            .await?;
        let affected_member_ids = self
            .store
            .member_ids_with_role_in_transaction(&mut transaction, role.id)
            .await?;
        let replacement = resolve_replacement_role(
            &role,
            &all_roles,
            command.replacement_role_id,
            !affected_member_ids.is_empty(),
        )?;
        let mut affected_members = Vec::with_capacity(affected_member_ids.len());
        for member_id in affected_member_ids {
            let member = self
                .store
                .member_by_id_for_update_in_transaction(&mut transaction, member_id)
                .await?
                .ok_or(OrganizationApplicationError::MemberNotFound(member_id))?;
            let current_roles = self
                .store
                .roles_for_member_in_transaction(&mut transaction, member_id)
                .await?;
            if current_roles.len() == 1 {
                let replacement = replacement
                    .as_ref()
                    .ok_or(OrganizationApplicationError::ReplacementRoleRequired)?;
                self.store
                    .add_member_role_in_transaction(&mut transaction, member_id, replacement.id)
                    .await?;
            }
            affected_members.push(member);
        }
        if role.is_default_for_new_members {
            let mut replacement = replacement
                .clone()
                .ok_or(OrganizationApplicationError::ReplacementRoleRequired)?;
            self.clear_default_roles_in_transaction(
                &mut transaction,
                command.organization_id,
                Some(replacement.id),
                command.now,
            )
            .await?;
            replacement.is_default_for_new_members = true;
            replacement.updated_at = command.now;
            self.store
                .save_role_in_transaction(&mut transaction, &replacement)
                .await?;
        }
        if !self
            .store
            .delete_role_in_transaction(&mut transaction, role.id)
            .await?
        {
            return Err(OrganizationApplicationError::RoleNotFound(role.id));
        }
        let event = role_event(
            OrganizationEventKind::RoleDeleted,
            role.organization_id,
            &role,
            "deleted_by",
            &command.deleted_by,
            command.now,
            None,
        )?;
        self.persist_event_in_transaction(&mut transaction, &event)
            .await?;
        transaction.commit().await.map_err(RepositoryError::from)?;
        let warnings = self
            .invalidate_members_after_commit(&affected_members)
            .await;
        Ok(MutationResult {
            value: (),
            warnings,
        })
    }

    pub async fn add_member_role(
        &self,
        command: AddMemberRoleCommand,
    ) -> Result<MutationResult<()>, OrganizationApplicationError> {
        require_text(&command.updated_by, "updated_by is required")?;
        let mut transaction = self.store.begin_transaction().await?;
        let member = self
            .store
            .member_by_id_for_update_in_transaction(&mut transaction, command.member_id)
            .await?
            .filter(|member| member.organization_id == command.organization_id)
            .ok_or(OrganizationApplicationError::MemberNotFound(
                command.member_id,
            ))?;
        let role = self
            .store
            .role_by_id_for_update_in_transaction(&mut transaction, command.role_id)
            .await?
            .filter(|role| role.organization_id == command.organization_id)
            .ok_or(OrganizationApplicationError::RoleNotFound(command.role_id))?;
        self.store
            .add_member_role_in_transaction(&mut transaction, member.id, role.id)
            .await?;
        let event = role_event(
            OrganizationEventKind::RoleAssigned,
            role.organization_id,
            &role,
            "assigned_by",
            &command.updated_by,
            command.now,
            Some(member.id),
        )?;
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

    pub async fn remove_member_role(
        &self,
        command: RemoveMemberRoleCommand,
    ) -> Result<MutationResult<()>, OrganizationApplicationError> {
        require_text(&command.updated_by, "updated_by is required")?;
        let mut transaction = self.store.begin_transaction().await?;
        let member = self
            .store
            .member_by_id_for_update_in_transaction(&mut transaction, command.member_id)
            .await?
            .filter(|member| member.organization_id == command.organization_id)
            .ok_or(OrganizationApplicationError::MemberNotFound(
                command.member_id,
            ))?;
        let current_roles = self
            .store
            .roles_for_member_in_transaction(&mut transaction, member.id)
            .await?;
        let role = current_roles
            .iter()
            .find(|role| role.id == command.role_id)
            .cloned()
            .ok_or(OrganizationApplicationError::RoleNotAssigned)?;
        if current_roles.len() <= 1 {
            return Err(OrganizationApplicationError::LastMemberRoleRemovalForbidden);
        }
        let organization = self
            .store
            .organization_by_id_for_update_in_transaction(&mut transaction, command.organization_id)
            .await?
            .ok_or(OrganizationApplicationError::NotFound(
                command.organization_id,
            ))?;
        if member.user_id == organization.owner_id && role.name == "owner" {
            return Err(OrganizationApplicationError::OwnerRoleRequired);
        }
        if !self
            .store
            .remove_member_role_in_transaction(&mut transaction, member.id, role.id)
            .await?
        {
            return Err(OrganizationApplicationError::RoleNotAssigned);
        }
        let event = role_event(
            OrganizationEventKind::RoleRemovedFromMember,
            role.organization_id,
            &role,
            "removed_by",
            &command.updated_by,
            command.now,
            Some(member.id),
        )?;
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

    pub async fn get_role(
        &self,
        organization_id: Uuid,
        role_id: Uuid,
    ) -> Result<Option<Role>, OrganizationApplicationError> {
        Ok(self
            .store
            .role_by_id(role_id)
            .await?
            .filter(|role| role.organization_id == organization_id))
    }

    pub async fn list_roles(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<Role>, OrganizationApplicationError> {
        Ok(self.store.roles_by_organization(organization_id).await?)
    }

    pub async fn list_permissions(&self) -> Result<Vec<Permission>, OrganizationApplicationError> {
        Ok(self.store.list_permissions().await?)
    }

    pub async fn get_member_roles(
        &self,
        member_id: Uuid,
    ) -> Result<Vec<Role>, OrganizationApplicationError> {
        Ok(self.store.roles_for_member(member_id).await?)
    }

    pub async fn get_member_permissions(
        &self,
        member_id: Uuid,
    ) -> Result<Vec<Permission>, OrganizationApplicationError> {
        Ok(self.store.member_permissions(member_id).await?)
    }

    async fn permissions_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        permission_ids: &[Uuid],
    ) -> Result<Vec<Permission>, OrganizationApplicationError> {
        let permission_ids = deduplicate_ids(permission_ids);
        let permissions = self
            .store
            .permissions_by_ids_in_transaction(transaction, &permission_ids)
            .await?;
        let found = permissions
            .iter()
            .map(|permission| permission.id)
            .collect::<BTreeSet<_>>();
        if let Some(missing) = permission_ids
            .into_iter()
            .find(|permission_id| !found.contains(permission_id))
        {
            return Err(OrganizationApplicationError::PermissionNotFound(missing));
        }
        Ok(permissions)
    }

    async fn clear_default_roles_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        organization_id: Uuid,
        retained_role_id: Option<Uuid>,
        now: DateTime<Utc>,
    ) -> Result<(), OrganizationApplicationError> {
        let roles = self
            .store
            .roles_by_organization_for_update_in_transaction(transaction, organization_id)
            .await?;
        for mut role in roles
            .into_iter()
            .filter(|role| role.is_default_for_new_members && Some(role.id) != retained_role_id)
        {
            role.is_default_for_new_members = false;
            role.updated_at = now;
            self.store
                .save_role_in_transaction(transaction, &role)
                .await?;
        }
        Ok(())
    }

    async fn invalidate_members_after_commit(&self, members: &[Member]) -> Vec<ApplicationWarning> {
        let mut warnings = Vec::new();
        for member in members {
            warnings.extend(
                self.invalidate_member_after_commit(&member.user_id, member.organization_id)
                    .await,
            );
        }
        warnings
    }
}

pub fn resolve_replacement_role(
    deleted_role: &Role,
    organization_roles: &[Role],
    requested_replacement_id: Option<Uuid>,
    has_affected_members: bool,
) -> Result<Option<Role>, OrganizationApplicationError> {
    if requested_replacement_id == Some(deleted_role.id) {
        return Err(OrganizationApplicationError::ReplacementRoleRequired);
    }
    let replacement_required = deleted_role.is_default_for_new_members || has_affected_members;
    let replacement = match requested_replacement_id {
        Some(requested) => Some(
            organization_roles
                .iter()
                .find(|role| role.id == requested)
                .cloned()
                .ok_or(OrganizationApplicationError::RoleNotFound(requested))?,
        ),
        None if replacement_required => organization_roles
            .iter()
            .find(|role| role.id != deleted_role.id && role.is_default_for_new_members)
            .cloned(),
        None => None,
    };
    if replacement_required && replacement.is_none() {
        return Err(OrganizationApplicationError::ReplacementRoleRequired);
    }
    Ok(replacement)
}

fn role_event(
    kind: OrganizationEventKind,
    organization_id: Uuid,
    role: &Role,
    actor_field: &'static str,
    actor_id: &str,
    now: DateTime<Utc>,
    member_id: Option<Uuid>,
) -> Result<OrganizationEvent, OrganizationEventError> {
    let mut data = Map::new();
    data.insert("role_id".into(), Value::String(role.id.to_string()));
    data.insert("role_name".into(), Value::String(role.name.clone()));
    data.insert(actor_field.into(), Value::String(actor_id.into()));
    if let Some(member_id) = member_id {
        data.insert("member_id".into(), Value::String(member_id.to_string()));
    }
    OrganizationEvent::new(kind, organization_id, data, now)
}

fn deduplicate_ids(ids: &[Uuid]) -> Vec<Uuid> {
    let mut seen = BTreeSet::new();
    ids.iter().copied().filter(|id| seen.insert(*id)).collect()
}

fn require_text(value: &str, message: &'static str) -> Result<(), OrganizationApplicationError> {
    if value.trim().is_empty() {
        Err(OrganizationApplicationError::InvalidCommand(message))
    } else {
        Ok(())
    }
}
