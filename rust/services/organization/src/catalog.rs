use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::Deserialize;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    domain::{Permission, Role, APPLICANT_PERMISSION_KEYS},
    postgres::{PostgresOrganizationStore, RepositoryError},
};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PermissionDefinition {
    pub resource: String,
    pub action: String,
    pub description: String,
}

impl PermissionDefinition {
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}:{}", self.resource, self.action)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemRoleTemplate {
    pub name: &'static str,
    pub display_name: &'static str,
    pub description: &'static str,
    pub permission_keys: BTreeSet<String>,
    pub is_default_for_new_members: bool,
}

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("ORGANIZATION.CATALOG_INVALID_JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("ORGANIZATION.CATALOG_DUPLICATE_PERMISSION: {0}")]
    DuplicatePermission(String),
}

#[derive(Debug, Error)]
pub enum SeedError {
    #[error(transparent)]
    Catalog(#[from] CatalogError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error("ORGANIZATION.SEED_PERMISSION_MISSING_AFTER_UPSERT: {0}")]
    MissingPermission(String),
}

#[derive(Debug, Deserialize)]
struct PermissionCatalogDocument {
    schema_version: u32,
    permissions: Vec<PermissionDefinition>,
}

pub fn permission_catalog() -> Result<Vec<PermissionDefinition>, CatalogError> {
    let document: PermissionCatalogDocument = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/organization-permission-catalog.json"
    )))?;
    if document.schema_version != 1 {
        return Err(CatalogError::InvalidJson(serde_json::Error::io(
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported permission catalog schema version",
            ),
        )));
    }
    let mut seen = BTreeSet::new();
    for permission in &document.permissions {
        let key = permission.key();
        if !seen.insert(key.clone()) {
            return Err(CatalogError::DuplicatePermission(key));
        }
    }
    Ok(document.permissions)
}

pub fn system_role_templates(catalog: &[PermissionDefinition]) -> Vec<SystemRoleTemplate> {
    let all = keys_matching(catalog, |_| true);
    let access_admin = keys_for_resources(
        catalog,
        &[
            "organization",
            "team",
            "role",
            "policy-set",
            "api-key",
            "signing-key",
            "webhook",
            "integration-connector",
            "notification",
            "audit",
        ],
    );
    let catalog_admin = keys_for_resources(
        catalog,
        &[
            "trust-profile",
            "policy-set",
            "trusted-issuer",
            "credential-template",
            "wallet",
            "compliance-profile",
            "presentation-policy",
            "revocation-profile",
            "deployment-profile",
            "flow-definition",
            "application-template",
            "integration-connector",
        ],
    );
    let mut reviewer = view_keys_for_resources(
        catalog,
        &[
            "organization",
            "trust-profile",
            "trusted-issuer",
            "credential-template",
            "wallet",
            "compliance-profile",
            "presentation-policy",
            "revocation-profile",
            "deployment-profile",
            "application-template",
            "application",
        ],
    );
    reviewer.extend([
        "application:review".to_owned(),
        "application:approve".to_owned(),
        "application:reject".to_owned(),
    ]);
    let mut operator = view_keys_for_resources(
        catalog,
        &[
            "organization",
            "trust-profile",
            "credential-template",
            "wallet",
            "application-template",
            "deployment-profile",
            "flow-definition",
            "flow-instance",
            "issuance",
            "verification",
        ],
    );
    operator.extend([
        "flow-instance:start".to_owned(),
        "flow-instance:advance".to_owned(),
        "flow-instance:cancel".to_owned(),
        "issuance:initiate".to_owned(),
        "issuance:revoke".to_owned(),
        "verification:execute".to_owned(),
    ]);
    let viewer = keys_matching(catalog, |permission| permission.action == "view");
    let applicant = APPLICANT_PERMISSION_KEYS
        .iter()
        .map(|key| (*key).to_owned())
        .collect();

    vec![
        template(
            "owner",
            "Owner",
            "Full access. Can transfer ownership.",
            all.clone(),
            false,
        ),
        template(
            "admin",
            "Administrator",
            "Full access to all organization resources and settings.",
            all,
            false,
        ),
        template(
            "access_admin",
            "Access Administrator",
            "Manages organization settings, team access, roles, keys, webhooks, notifications, and audit.",
            access_admin,
            false,
        ),
        template(
            "catalog_admin",
            "Catalog Administrator",
            "Manages trust, compliance, templates, deployment profiles, flow definitions, and application templates.",
            catalog_admin,
            false,
        ),
        template(
            "reviewer",
            "Reviewer",
            "Reviews applications and related organization artifacts.",
            reviewer,
            false,
        ),
        template(
            "operator",
            "Operator",
            "Runs issuance, verification, and operational flows.",
            operator,
            false,
        ),
        template(
            "viewer",
            "Viewer",
            "Read-only access to organization console resources.",
            viewer,
            false,
        ),
        template(
            "applicant",
            "Applicant",
            "Catalog and application access without organization console access.",
            applicant,
            true,
        ),
    ]
}

pub async fn seed_permission_catalog(
    store: &PostgresOrganizationStore,
) -> Result<BTreeMap<String, Permission>, SeedError> {
    let catalog = permission_catalog()?;
    let mut persisted = BTreeMap::new();
    for definition in catalog {
        let key = definition.key();
        let permission = Permission {
            id: Uuid::new_v5(
                &Uuid::NAMESPACE_URL,
                format!("marty:permission:{key}").as_bytes(),
            ),
            resource: definition.resource.clone(),
            action: definition.action.clone(),
            description: Some(definition.description),
        };
        store.save_permission(&permission).await?;
        let stored = store
            .permission_by_key(&definition.resource, &definition.action)
            .await?
            .ok_or_else(|| SeedError::MissingPermission(key.clone()))?;
        persisted.insert(key, stored);
    }
    Ok(persisted)
}

pub async fn seed_system_roles(
    store: &PostgresOrganizationStore,
    organization_id: Uuid,
    now: DateTime<Utc>,
) -> Result<BTreeMap<String, Role>, SeedError> {
    let catalog = permission_catalog()?;
    let permissions = seed_permission_catalog(store).await?;
    let templates = system_role_templates(&catalog);
    let mut roles = BTreeMap::new();
    for role_template in templates {
        let existing = store
            .role_by_name(organization_id, role_template.name)
            .await?;
        let role = Role {
            id: existing.as_ref().map_or_else(
                || Uuid::new_v5(&organization_id, role_template.name.as_bytes()),
                |role| role.id,
            ),
            organization_id,
            name: role_template.name.to_owned(),
            display_name: Some(role_template.display_name.to_owned()),
            description: Some(role_template.description.to_owned()),
            is_system: true,
            is_default_for_new_members: role_template.is_default_for_new_members,
            permissions: role_template
                .permission_keys
                .iter()
                .filter_map(|key| permissions.get(key).cloned())
                .collect(),
            created_at: existing.as_ref().map_or(now, |role| role.created_at),
            updated_at: now,
        };
        store.save_role(&role).await?;
        roles.insert(role.name.clone(), role);
    }
    Ok(roles)
}

fn template(
    name: &'static str,
    display_name: &'static str,
    description: &'static str,
    permission_keys: BTreeSet<String>,
    is_default_for_new_members: bool,
) -> SystemRoleTemplate {
    SystemRoleTemplate {
        name,
        display_name,
        description,
        permission_keys,
        is_default_for_new_members,
    }
}

fn keys_for_resources(catalog: &[PermissionDefinition], resources: &[&str]) -> BTreeSet<String> {
    keys_matching(catalog, |permission| {
        resources.contains(&permission.resource.as_str())
    })
}

fn view_keys_for_resources(
    catalog: &[PermissionDefinition],
    resources: &[&str],
) -> BTreeSet<String> {
    keys_matching(catalog, |permission| {
        permission.action == "view" && resources.contains(&permission.resource.as_str())
    })
}

fn keys_matching(
    catalog: &[PermissionDefinition],
    predicate: impl Fn(&PermissionDefinition) -> bool,
) -> BTreeSet<String> {
    catalog
        .iter()
        .filter(|permission| predicate(permission))
        .map(PermissionDefinition::key)
        .collect()
}
