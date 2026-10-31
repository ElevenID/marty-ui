use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::application::{MutationResult, OrganizationApplication, OrganizationApplicationError};
use crate::domain::{ApiKey, ApiKeySpec};
use crate::events::{OrganizationEvent, OrganizationEventKind};
use crate::postgres::RepositoryError;

pub const MIP_API_KEY_SCOPES: &[&str] = &[
    "credentials:issue",
    "credentials:revoke",
    "credentials:read",
    "flows:read",
    "flows:write",
    "flows:execute",
    "applications:read",
    "applications:write",
    "applications:approve",
    "trust:read",
    "trust:write",
    "trust:admin",
    "compliance:read",
    "compliance:write",
    "templates:read",
    "templates:write",
    "wallet:read",
    "wallet:write",
    "keys:read",
    "keys:write",
    "users:read",
    "users:invite",
    "roles:read",
    "roles:write",
    "audit:read",
    "audit:write",
    "webhooks:read",
    "webhooks:write",
    "notifications:send",
    "notifications:read",
    "deployment:read",
    "deployment:write",
    "integrations:read",
    "integrations:write",
    "admin:full",
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApiKeyScopeType {
    #[default]
    Organization,
    DeploymentProfile,
}

impl ApiKeyScopeType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Organization => "ORGANIZATION",
            Self::DeploymentProfile => "DEPLOYMENT_PROFILE",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateApiKeyCommand {
    pub organization_id: Uuid,
    pub name: String,
    pub created_by: String,
    pub scopes: Option<Vec<String>>,
    pub description: Option<String>,
    pub is_test: bool,
    pub scope_type: ApiKeyScopeType,
    pub deployment_profile_id: Option<Uuid>,
    pub rate_limit: Option<u32>,
    pub expires_at: Option<DateTime<Utc>>,
    pub now: DateTime<Utc>,
}

pub struct ApiKeyCreation {
    pub api_key: ApiKey,
    pub raw_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokeApiKeyCommand {
    pub organization_id: Uuid,
    pub api_key_id: Uuid,
    pub revoked_by: String,
    pub now: DateTime<Utc>,
}

/// Application-internal actor selection. Public API-key commands always use
/// User; an HTTP request cannot select this installer authority.
#[derive(Clone, Copy)]
pub(crate) enum ApiKeyActor {
    User,
    InstallerBootstrap { installation_id: Uuid },
}

pub(crate) const INSTALLER_KEY_LIFETIME_SECONDS: i64 = 15 * 60;

impl ApiKeyActor {
    fn validate(self, actor_id: &str) -> Result<(), OrganizationApplicationError> {
        if let Self::InstallerBootstrap { installation_id } = self {
            if installation_id.get_version_num() != 4
                || actor_id != format!("installer:{installation_id}")
            {
                return Err(OrganizationApplicationError::InvalidCommand(
                    "installer API-key actor is invalid",
                ));
            }
        }
        Ok(())
    }

    fn validate_creation(
        self,
        command: &CreateApiKeyCommand,
    ) -> Result<(), OrganizationApplicationError> {
        self.validate(&command.created_by)?;
        if matches!(self, Self::InstallerBootstrap { .. })
            && (command.scopes.as_deref() != Some(&["keys:write".to_owned()])
                || command.scope_type != ApiKeyScopeType::Organization
                || command.deployment_profile_id.is_some()
                || command.is_test
                || command.rate_limit.is_some()
                || command.expires_at.is_none()
                || command.expires_at
                    != command.now.checked_add_signed(chrono::Duration::seconds(
                        INSTALLER_KEY_LIFETIME_SECONDS,
                    )))
        {
            return Err(OrganizationApplicationError::InvalidApiKeyBinding(
                "installer API keys require the fixed registration scope and lifetime",
            ));
        }
        Ok(())
    }

    fn annotate(self, data: &mut Map<String, Value>) {
        if let Self::InstallerBootstrap { installation_id } = self {
            data.insert(
                "installer_bootstrap_installation_id".into(),
                Value::String(installation_id.to_string()),
            );
        }
    }
}

impl OrganizationApplication {
    pub async fn create_api_key(
        &self,
        command: CreateApiKeyCommand,
    ) -> Result<MutationResult<ApiKeyCreation>, OrganizationApplicationError> {
        self.create_api_key_as(command, ApiKeyActor::User).await
    }

    pub(crate) async fn create_api_key_as(
        &self,
        command: CreateApiKeyCommand,
        actor: ApiKeyActor,
    ) -> Result<MutationResult<ApiKeyCreation>, OrganizationApplicationError> {
        validate_create_api_key(&command)?;
        actor.validate_creation(&command)?;
        let mut transaction = self.store.begin_transaction().await?;
        let organization = self
            .store
            .organization_by_id_for_update_in_transaction(&mut transaction, command.organization_id)
            .await?
            .ok_or(OrganizationApplicationError::NotFound(
                command.organization_id,
            ))?;
        if matches!(actor, ApiKeyActor::InstallerBootstrap { .. })
            && organization.status != crate::OrganizationStatus::Active
        {
            return Err(OrganizationApplicationError::InvalidApiKeyBinding(
                "installer API keys require an active existing organization",
            ));
        }
        let (mut api_key, raw_key) = ApiKey::create(
            ApiKeySpec {
                organization_id: command.organization_id,
                name: command.name.clone(),
                created_by: command.created_by.clone(),
                scopes: command.scopes.clone(),
                description: command.description.clone(),
                expires_at: command.expires_at,
                now: command.now,
            },
            command.is_test,
        );
        api_key.scope_type = command.scope_type.as_str().into();
        api_key.deployment_profile_id = command.deployment_profile_id;
        api_key.rate_limit = command.rate_limit;
        self.store
            .save_api_key_in_transaction(&mut transaction, &api_key)
            .await?;
        let event = api_key_created_event(&command, api_key.id, actor)?;
        self.persist_event_in_transaction(&mut transaction, &event)
            .await?;
        transaction.commit().await.map_err(RepositoryError::from)?;
        Ok(MutationResult {
            value: ApiKeyCreation { api_key, raw_key },
            warnings: Vec::new(),
        })
    }

    pub async fn revoke_api_key(
        &self,
        command: RevokeApiKeyCommand,
    ) -> Result<MutationResult<ApiKey>, OrganizationApplicationError> {
        self.revoke_api_key_as(command, ApiKeyActor::User).await
    }

    pub(crate) async fn revoke_api_key_as(
        &self,
        command: RevokeApiKeyCommand,
        actor: ApiKeyActor,
    ) -> Result<MutationResult<ApiKey>, OrganizationApplicationError> {
        require_text(&command.revoked_by, "revoked_by is required")?;
        actor.validate(&command.revoked_by)?;
        let mut transaction = self.store.begin_transaction().await?;
        let mut api_key = self
            .store
            .api_key_by_id_for_update_in_transaction(&mut transaction, command.api_key_id)
            .await?
            .filter(|api_key| api_key.organization_id == command.organization_id)
            .ok_or(OrganizationApplicationError::ApiKeyNotFound(
                command.api_key_id,
            ))?;
        if matches!(actor, ApiKeyActor::InstallerBootstrap { .. })
            && api_key.created_by != command.revoked_by
        {
            return Err(OrganizationApplicationError::ApiKeyNotFound(
                command.api_key_id,
            ));
        }
        api_key.revoke(command.now);
        self.store
            .save_api_key_in_transaction(&mut transaction, &api_key)
            .await?;
        let event = api_key_revoked_event(&command, actor)?;
        self.persist_event_in_transaction(&mut transaction, &event)
            .await?;
        transaction.commit().await.map_err(RepositoryError::from)?;
        Ok(MutationResult {
            value: api_key,
            warnings: Vec::new(),
        })
    }

    pub async fn validate_api_key(
        &self,
        raw_key: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<ApiKey>, OrganizationApplicationError> {
        if raw_key.trim().is_empty() {
            return Ok(None);
        }
        let key_hash = ApiKey::hash_key(raw_key);
        let Some(candidate) = self.store.api_key_by_hash(&key_hash).await? else {
            return Ok(None);
        };
        if !candidate.verify(raw_key) || !candidate.is_valid_at(now) {
            return Ok(None);
        }
        let mut transaction = self.store.begin_transaction().await?;
        let Some(mut api_key) = self
            .store
            .api_key_by_id_for_update_in_transaction(&mut transaction, candidate.id)
            .await?
        else {
            transaction
                .rollback()
                .await
                .map_err(RepositoryError::from)?;
            return Ok(None);
        };
        if !api_key.verify(raw_key) || !api_key.is_valid_at(now) {
            transaction
                .rollback()
                .await
                .map_err(RepositoryError::from)?;
            return Ok(None);
        }
        api_key.record_usage(None, now);
        self.store
            .save_api_key_in_transaction(&mut transaction, &api_key)
            .await?;
        transaction.commit().await.map_err(RepositoryError::from)?;
        Ok(Some(api_key))
    }

    pub async fn list_api_keys(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<ApiKey>, OrganizationApplicationError> {
        Ok(self.store.api_keys_by_organization(organization_id).await?)
    }

    pub async fn get_api_key(
        &self,
        organization_id: Uuid,
        api_key_id: Uuid,
    ) -> Result<Option<ApiKey>, OrganizationApplicationError> {
        Ok(self
            .store
            .api_key_by_id(api_key_id)
            .await?
            .filter(|api_key| api_key.organization_id == organization_id))
    }
}

pub fn validate_create_api_key(
    command: &CreateApiKeyCommand,
) -> Result<(), OrganizationApplicationError> {
    require_text(&command.name, "API key name is required")?;
    require_text(&command.created_by, "created_by is required")?;
    if command.rate_limit == Some(0) {
        return Err(OrganizationApplicationError::InvalidApiKeyBinding(
            "rate_limit must be greater than zero",
        ));
    }
    if command
        .expires_at
        .is_some_and(|expires_at| expires_at <= command.now)
    {
        return Err(OrganizationApplicationError::InvalidApiKeyBinding(
            "expires_at must be in the future",
        ));
    }
    match command.scope_type {
        ApiKeyScopeType::Organization if command.deployment_profile_id.is_some() => {
            return Err(OrganizationApplicationError::InvalidApiKeyBinding(
                "organization keys cannot bind a deployment profile",
            ));
        }
        ApiKeyScopeType::DeploymentProfile if command.deployment_profile_id.is_none() => {
            return Err(OrganizationApplicationError::InvalidApiKeyBinding(
                "deployment-profile keys require deployment_profile_id",
            ));
        }
        _ => {}
    }
    let allowed = MIP_API_KEY_SCOPES.iter().copied().collect::<BTreeSet<_>>();
    let scopes = command
        .scopes
        .clone()
        .unwrap_or_else(|| vec!["credentials:read".into(), "credentials:issue".into()]);
    for scope in &scopes {
        if !allowed.contains(scope.as_str()) {
            return Err(OrganizationApplicationError::InvalidApiKeyScope(
                scope.clone(),
            ));
        }
    }
    if command.scope_type != ApiKeyScopeType::Organization
        && scopes.iter().any(|scope| scope == "admin:full")
    {
        return Err(OrganizationApplicationError::InvalidApiKeyBinding(
            "admin:full is restricted to organization keys",
        ));
    }
    Ok(())
}

fn api_key_created_event(
    command: &CreateApiKeyCommand,
    api_key_id: Uuid,
    actor: ApiKeyActor,
) -> Result<OrganizationEvent, crate::events::OrganizationEventError> {
    let mut data = Map::new();
    data.insert("api_key_id".into(), Value::String(api_key_id.to_string()));
    data.insert("name".into(), Value::String(command.name.clone()));
    data.insert(
        "created_by".into(),
        Value::String(command.created_by.clone()),
    );
    actor.annotate(&mut data);
    OrganizationEvent::new(
        OrganizationEventKind::ApiKeyCreated,
        command.organization_id,
        data,
        command.now,
    )
}

fn api_key_revoked_event(
    command: &RevokeApiKeyCommand,
    actor: ApiKeyActor,
) -> Result<OrganizationEvent, crate::events::OrganizationEventError> {
    let mut data = Map::new();
    data.insert(
        "api_key_id".into(),
        Value::String(command.api_key_id.to_string()),
    );
    data.insert(
        "revoked_by".into(),
        Value::String(command.revoked_by.clone()),
    );
    actor.annotate(&mut data);
    OrganizationEvent::new(
        OrganizationEventKind::ApiKeyRevoked,
        command.organization_id,
        data,
        command.now,
    )
}

fn require_text(value: &str, message: &'static str) -> Result<(), OrganizationApplicationError> {
    if value.trim().is_empty() {
        Err(OrganizationApplicationError::InvalidCommand(message))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod installer_actor_tests {
    use super::*;

    fn command(installation: Uuid) -> CreateApiKeyCommand {
        let now = Utc::now();
        CreateApiKeyCommand {
            organization_id: Uuid::new_v4(),
            name: "installer registration".into(),
            created_by: format!("installer:{installation}"),
            scopes: Some(vec!["keys:write".into()]),
            description: None,
            is_test: false,
            scope_type: ApiKeyScopeType::Organization,
            deployment_profile_id: None,
            rate_limit: None,
            expires_at: Some(now + chrono::Duration::seconds(INSTALLER_KEY_LIFETIME_SECONDS)),
            now,
        }
    }

    #[test]
    fn installer_actor_rejects_changed_creator_scope_binding_and_lifetime() {
        let installation = Uuid::new_v4();
        let actor = ApiKeyActor::InstallerBootstrap {
            installation_id: installation,
        };
        actor.validate_creation(&command(installation)).unwrap();
        for field in [
            "creator",
            "scopes",
            "missing_scopes",
            "scope_type",
            "deployment",
            "test",
            "rate",
            "expiry",
            "missing_expiry",
        ] {
            let mut value = command(installation);
            match field {
                "creator" => value.created_by = "human-principal".into(),
                "scopes" => value.scopes.as_mut().unwrap().push("admin:full".into()),
                "missing_scopes" => value.scopes = None,
                "scope_type" => value.scope_type = ApiKeyScopeType::DeploymentProfile,
                "deployment" => value.deployment_profile_id = Some(Uuid::new_v4()),
                "test" => value.is_test = true,
                "rate" => value.rate_limit = Some(10),
                "expiry" => value.expires_at = Some(value.now + chrono::Duration::hours(1)),
                "missing_expiry" => value.expires_at = None,
                _ => unreachable!(),
            }
            assert!(actor.validate_creation(&value).is_err(), "{field}");
        }
        let invalid = ApiKeyActor::InstallerBootstrap {
            installation_id: Uuid::nil(),
        };
        assert!(invalid.validate_creation(&command(Uuid::nil())).is_err());
    }

    #[test]
    fn typed_installer_uses_system_audit_for_both_owner_mutations() {
        let installation = Uuid::new_v4();
        let actor = ApiKeyActor::InstallerBootstrap {
            installation_id: installation,
        };
        let create = command(installation);
        let id = Uuid::new_v4();
        let created = api_key_created_event(&create, id, actor).unwrap();
        let revoked = api_key_revoked_event(
            &RevokeApiKeyCommand {
                organization_id: create.organization_id,
                api_key_id: id,
                revoked_by: create.created_by.clone(),
                now: create.now,
            },
            actor,
        )
        .unwrap();
        for event in [created, revoked] {
            let audit = event.to_audit_event().unwrap();
            assert_eq!(audit.actor_type, "system");
            assert_eq!(audit.actor_id.as_deref(), Some(create.created_by.as_str()));
            assert_eq!(audit.resource_id, Some(id.to_string()));
            assert_eq!(
                event.data["installer_bootstrap_installation_id"],
                installation.to_string()
            );
        }
    }

    #[test]
    fn normal_public_owner_does_not_infer_system_authority_from_actor_text() {
        let installation = Uuid::new_v4();
        let create = command(installation);
        let event = api_key_created_event(&create, Uuid::new_v4(), ApiKeyActor::User).unwrap();
        assert!(!event
            .data
            .contains_key("installer_bootstrap_installation_id"));
        assert_eq!(event.to_audit_event().unwrap().actor_type, "user");
        let event = api_key_revoked_event(
            &RevokeApiKeyCommand {
                organization_id: create.organization_id,
                api_key_id: Uuid::new_v4(),
                revoked_by: create.created_by,
                now: create.now,
            },
            ApiKeyActor::User,
        )
        .unwrap();
        assert!(!event
            .data
            .contains_key("installer_bootstrap_installation_id"));
        assert_eq!(event.to_audit_event().unwrap().actor_type, "user");
    }

    #[test]
    fn malformed_installer_annotation_cannot_project_a_system_audit_actor() {
        let installation = Uuid::new_v4();
        let create = command(installation);
        let actor = ApiKeyActor::InstallerBootstrap {
            installation_id: installation,
        };
        for value in [
            Value::Null,
            true.into(),
            "arbitrary".into(),
            Uuid::new_v4().to_string().into(),
            Uuid::nil().to_string().into(),
        ] {
            let mut event = api_key_created_event(&create, Uuid::new_v4(), actor).unwrap();
            event
                .data
                .insert("installer_bootstrap_installation_id".into(), value);
            assert!(matches!(
                event.to_audit_event(),
                Err(crate::events::OrganizationEventError::InvalidInstallerActor)
            ));
        }
    }
}
