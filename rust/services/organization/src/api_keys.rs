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

impl OrganizationApplication {
    pub async fn create_api_key(
        &self,
        command: CreateApiKeyCommand,
    ) -> Result<MutationResult<ApiKeyCreation>, OrganizationApplicationError> {
        validate_create_api_key(&command)?;
        let mut transaction = self.store.begin_transaction().await?;
        self.store
            .organization_by_id_for_update_in_transaction(&mut transaction, command.organization_id)
            .await?
            .ok_or(OrganizationApplicationError::NotFound(
                command.organization_id,
            ))?;
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
        let event = api_key_created_event(&command, api_key.id)?;
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
        require_text(&command.revoked_by, "revoked_by is required")?;
        let mut transaction = self.store.begin_transaction().await?;
        let mut api_key = self
            .store
            .api_key_by_id_for_update_in_transaction(&mut transaction, command.api_key_id)
            .await?
            .filter(|api_key| api_key.organization_id == command.organization_id)
            .ok_or(OrganizationApplicationError::ApiKeyNotFound(
                command.api_key_id,
            ))?;
        api_key.revoke(command.now);
        self.store
            .save_api_key_in_transaction(&mut transaction, &api_key)
            .await?;
        let event = api_key_revoked_event(&command)?;
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
        let api_key = self.store.api_key_by_hash(&key_hash).await?;
        Ok(api_key.filter(|api_key| api_key.verify(raw_key) && api_key.is_valid_at(now)))
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
) -> Result<OrganizationEvent, crate::events::OrganizationEventError> {
    let mut data = Map::new();
    data.insert("api_key_id".into(), Value::String(api_key_id.to_string()));
    data.insert("name".into(), Value::String(command.name.clone()));
    data.insert(
        "created_by".into(),
        Value::String(command.created_by.clone()),
    );
    OrganizationEvent::new(
        OrganizationEventKind::ApiKeyCreated,
        command.organization_id,
        data,
        command.now,
    )
}

fn api_key_revoked_event(
    command: &RevokeApiKeyCommand,
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
