use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use rand::{distr::Alphanumeric, Rng};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

pub const APPLICANT_PERMISSION_KEYS: &[&str] = &[
    "application-template:view",
    "application:view",
    "credential-template:view",
    "issuance:view",
    "organization:view",
    "wallet:view",
];

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DomainError {
    #[error("can only accept pending invitations")]
    InvitationNotPending,
    #[error("organization name does not contain a slug-safe character")]
    InvalidOrganizationName,
    #[error("join-code usage counter overflow")]
    JoinCodeUsageOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permission {
    pub id: Uuid,
    pub resource: String,
    pub action: String,
    pub description: Option<String>,
}

impl Permission {
    #[must_use]
    pub fn new(resource: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            resource: resource.into(),
            action: action.into(),
            description: None,
        }
    }

    #[must_use]
    pub fn key(&self) -> String {
        format!("{}:{}", self.resource, self.action)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub is_system: bool,
    pub is_default_for_new_members: bool,
    pub permissions: Vec<Permission>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Role {
    #[must_use]
    pub fn permission_keys(&self) -> BTreeSet<String> {
        self.permissions.iter().map(Permission::key).collect()
    }

    #[must_use]
    pub fn has_permission(&self, resource: &str, action: &str) -> bool {
        self.permissions
            .iter()
            .any(|permission| permission.resource == resource && permission.action == action)
    }

    pub fn add_permission(&mut self, permission: Permission, now: DateTime<Utc>) {
        if !self.permission_keys().contains(&permission.key()) {
            self.permissions.push(permission);
            self.updated_at = now;
        }
    }

    pub fn remove_permission(&mut self, resource: &str, action: &str, now: DateTime<Utc>) {
        self.permissions
            .retain(|permission| permission.resource != resource || permission.action != action);
        self.updated_at = now;
    }

    pub fn set_permissions(&mut self, permissions: Vec<Permission>, now: DateTime<Utc>) {
        self.permissions = permissions;
        self.updated_at = now;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrganizationStatus {
    Active,
    Suspended,
    Pending,
}

impl OrganizationStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Pending => "pending",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrganizationType {
    Enterprise,
    Startup,
    Individual,
    Government,
    Education,
    Healthcare,
    Financial,
    Other,
}

impl OrganizationType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enterprise => "enterprise",
            Self::Startup => "startup",
            Self::Individual => "individual",
            Self::Government => "government",
            Self::Education => "education",
            Self::Healthcare => "healthcare",
            Self::Financial => "financial",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemberStatus {
    Active,
    Pending,
    Invited,
    Deactivated,
}

impl MemberStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Pending => "pending",
            Self::Invited => "invited",
            Self::Deactivated => "deactivated",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiKeyStatus {
    Active,
    Revoked,
    Expired,
}

impl ApiKeyStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewMode {
    Applicant,
    OrgAdmin,
}

impl ViewMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applicant => "applicant",
            Self::OrgAdmin => "org_admin",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JoinMechanism {
    Open,
    Code,
    Invite,
    Domain,
}

impl JoinMechanism {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Code => "code",
            Self::Invite => "invite",
            Self::Domain => "domain",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub event_type: String,
    pub action: String,
    pub category: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub resource_name: Option<String>,
    pub actor_id: Option<String>,
    pub actor_type: String,
    pub severity: String,
    pub message: String,
    pub changes: Option<Value>,
    pub metadata: Value,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditEventQuery {
    pub category: Option<String>,
    pub event_type: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub actor_id: Option<String>,
    pub severity: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub limit: u32,
    pub offset: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleContextPreference {
    pub id: Uuid,
    pub user_id: String,
    pub last_view_mode: ViewMode,
    pub last_active_org_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinCode {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub code: String,
    pub created_by: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub max_uses: Option<u32>,
    pub use_count: u32,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl JoinCode {
    const ALPHABET: &'static [u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    #[must_use]
    pub fn generate_code() -> String {
        let mut random = rand::rng();
        (0..8)
            .map(|_| {
                let index = random.random_range(0..Self::ALPHABET.len());
                char::from(Self::ALPHABET[index])
            })
            .collect()
    }

    #[must_use]
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        self.is_active
            && self.expires_at.is_none_or(|expires_at| now <= expires_at)
            && self
                .max_uses
                .is_none_or(|max_uses| self.use_count < max_uses)
    }

    pub fn increment_usage(&mut self, now: DateTime<Utc>) -> Result<(), DomainError> {
        self.use_count = self
            .use_count
            .checked_add(1)
            .ok_or(DomainError::JoinCodeUsageOverflow)?;
        self.updated_at = now;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub slug: String,
    pub description: Option<String>,
    pub org_type: OrganizationType,
    pub status: OrganizationStatus,
    pub owner_id: String,
    pub join_code: Option<String>,
    pub visibility: String,
    pub join_mechanism: JoinMechanism,
    pub requires_approval: bool,
    pub is_discoverable: bool,
    pub contact_email: Option<String>,
    pub contact_phone: Option<String>,
    pub website: Option<String>,
    pub plan: String,
    pub plan_expires_at: Option<DateTime<Utc>>,
    pub settings: Map<String, Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrganizationCreate {
    pub name: String,
    pub owner_id: String,
    pub org_type: OrganizationType,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub join_mechanism: JoinMechanism,
    pub requires_approval: bool,
    pub is_discoverable: bool,
    pub now: DateTime<Utc>,
}

impl Organization {
    pub fn create(command: OrganizationCreate) -> Result<(Self, Member), DomainError> {
        let OrganizationCreate {
            name,
            owner_id,
            org_type,
            display_name,
            description,
            join_mechanism,
            requires_approval,
            is_discoverable,
            now,
        } = command;
        let slug = Self::generate_slug(&name)?;
        let organization_id = Uuid::new_v4();
        let organization = Self {
            id: organization_id,
            display_name: Some(display_name.unwrap_or_else(|| name.clone())),
            slug,
            description,
            org_type,
            status: OrganizationStatus::Active,
            owner_id: owner_id.clone(),
            join_code: None,
            visibility: if is_discoverable { "PUBLIC" } else { "PRIVATE" }.to_owned(),
            join_mechanism,
            requires_approval,
            is_discoverable,
            contact_email: None,
            contact_phone: None,
            website: None,
            plan: "free".to_owned(),
            plan_expires_at: None,
            settings: Map::new(),
            created_at: now,
            updated_at: now,
            name,
        };
        let owner = Member::create(organization_id, owner_id, None, MemberStatus::Active, now);
        Ok((organization, owner))
    }

    pub fn generate_slug(name: &str) -> Result<String, DomainError> {
        let non_alphanumeric = Regex::new("[^a-z0-9]+").expect("static regex is valid");
        let lowercase = name.to_lowercase();
        let prefix = non_alphanumeric
            .replace_all(&lowercase, "-")
            .trim_matches('-')
            .to_owned();
        if prefix.is_empty() {
            return Err(DomainError::InvalidOrganizationName);
        }
        let suffix = Uuid::new_v4().simple().to_string();
        Ok(format!("{prefix}-{}", &suffix[..8]))
    }

    pub fn activate(&mut self, now: DateTime<Utc>) {
        self.status = OrganizationStatus::Active;
        self.updated_at = now;
    }

    pub fn suspend(&mut self, now: DateTime<Utc>) {
        self.status = OrganizationStatus::Suspended;
        self.updated_at = now;
    }

    pub fn update_settings(&mut self, settings: Map<String, Value>, now: DateTime<Utc>) {
        self.settings.extend(settings);
        self.updated_at = now;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub user_id: String,
    pub email: Option<String>,
    pub status: MemberStatus,
    pub roles: Vec<Role>,
    pub invited_by: Option<String>,
    pub invited_at: Option<DateTime<Utc>>,
    pub joined_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Member {
    #[must_use]
    pub fn create(
        organization_id: Uuid,
        user_id: impl Into<String>,
        email: Option<String>,
        status: MemberStatus,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            organization_id,
            user_id: user_id.into(),
            email,
            status,
            roles: Vec::new(),
            invited_by: None,
            invited_at: None,
            joined_at: Some(now),
            created_at: now,
            updated_at: now,
        }
    }

    #[must_use]
    pub fn create_invitation(
        organization_id: Uuid,
        email: impl Into<String>,
        invited_by: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            organization_id,
            user_id: String::new(),
            email: Some(email.into()),
            status: MemberStatus::Invited,
            roles: Vec::new(),
            invited_by: Some(invited_by.into()),
            invited_at: Some(now),
            joined_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn accept_invitation(
        &mut self,
        user_id: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        if self.status != MemberStatus::Invited {
            return Err(DomainError::InvitationNotPending);
        }
        self.user_id = user_id.into();
        self.status = MemberStatus::Active;
        self.joined_at = Some(now);
        self.updated_at = now;
        Ok(())
    }

    pub fn deactivate(&mut self, now: DateTime<Utc>) {
        self.status = MemberStatus::Deactivated;
        self.updated_at = now;
    }

    #[must_use]
    pub fn effective_permissions(&self) -> BTreeSet<String> {
        self.roles
            .iter()
            .flat_map(|role| role.permission_keys())
            .collect()
    }

    #[must_use]
    pub fn role_names(&self) -> BTreeSet<&str> {
        self.roles.iter().map(|role| role.name.as_str()).collect()
    }

    #[must_use]
    pub fn has_permission(&self, resource: &str, action: Option<&str>) -> bool {
        let key = action.map_or_else(
            || resource.to_owned(),
            |action| format!("{resource}:{action}"),
        );
        self.effective_permissions().contains(&key)
    }

    #[must_use]
    pub fn has_role(&self, role_names: &[&str]) -> bool {
        let assigned = self.role_names();
        role_names.iter().any(|name| assigned.contains(name))
    }

    #[must_use]
    pub fn has_org_console_access(&self) -> bool {
        self.effective_permissions()
            .iter()
            .any(|key| !APPLICANT_PERMISSION_KEYS.contains(&key.as_str()))
    }

    #[must_use]
    pub fn is_owner(&self) -> bool {
        self.has_role(&["owner"])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub key_prefix: String,
    pub key_hash: String,
    pub scopes: Vec<String>,
    pub scope_type: String,
    pub deployment_profile_id: Option<Uuid>,
    pub status: ApiKeyStatus,
    pub enabled: bool,
    pub rate_limit: Option<u32>,
    pub created_by: String,
    pub last_used_at: Option<DateTime<Utc>>,
    pub last_used_ip: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeySpec {
    pub organization_id: Uuid,
    pub name: String,
    pub created_by: String,
    pub scopes: Option<Vec<String>>,
    pub description: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub now: DateTime<Utc>,
}

impl ApiKey {
    #[must_use]
    pub fn create(spec: ApiKeySpec, is_test: bool) -> (Self, String) {
        let prefix = if is_test { "mk_test_" } else { "mk_live_" };
        let token: String = rand::rng()
            .sample_iter(Alphanumeric)
            .take(43)
            .map(char::from)
            .collect();
        let raw_key = format!("{prefix}{token}");
        let key = Self::from_raw(spec, raw_key.as_str());
        (key, raw_key)
    }

    #[must_use]
    pub fn from_raw(spec: ApiKeySpec, raw_key: &str) -> Self {
        let ApiKeySpec {
            organization_id,
            name,
            created_by,
            scopes,
            description,
            expires_at,
            now,
        } = spec;
        let key_prefix = if raw_key.starts_with("mk_test_") {
            "mk_test_"
        } else {
            "mk_live_"
        };
        Self {
            id: Uuid::new_v4(),
            organization_id,
            name,
            description,
            key_prefix: key_prefix.to_owned(),
            key_hash: Self::hash_key(raw_key),
            scopes: scopes.unwrap_or_else(|| {
                vec![
                    "credentials:read".to_owned(),
                    "credentials:issue".to_owned(),
                ]
            }),
            scope_type: "ORGANIZATION".to_owned(),
            deployment_profile_id: None,
            status: ApiKeyStatus::Active,
            enabled: true,
            rate_limit: None,
            created_by,
            last_used_at: None,
            last_used_ip: None,
            expires_at,
            created_at: now,
            updated_at: now,
        }
    }

    #[must_use]
    pub fn hash_key(raw_key: &str) -> String {
        format!("{:x}", Sha256::digest(raw_key.as_bytes()))
    }

    #[must_use]
    pub fn verify(&self, raw_key: &str) -> bool {
        let candidate = Self::hash_key(raw_key);
        bool::from(self.key_hash.as_bytes().ct_eq(candidate.as_bytes()))
    }

    pub fn record_usage(&mut self, ip_address: Option<String>, now: DateTime<Utc>) {
        self.last_used_at = Some(now);
        self.last_used_ip = ip_address;
    }

    pub fn revoke(&mut self, now: DateTime<Utc>) {
        self.status = ApiKeyStatus::Revoked;
        self.updated_at = now;
    }

    #[must_use]
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        self.status == ApiKeyStatus::Active
            && self.enabled
            && self.expires_at.is_none_or(|expires_at| now <= expires_at)
    }

    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        if self.scopes.iter().any(|item| item == scope || item == "*") {
            return true;
        }
        scope.split_once(':').is_some_and(|(left, right)| {
            let flipped = format!("{right}:{left}");
            self.scopes.contains(&flipped)
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicySetStatus {
    Draft,
    Active,
    Archived,
}

impl PolicySetStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "DRAFT",
            Self::Active => "ACTIVE",
            Self::Archived => "ARCHIVED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicySetType {
    AccessControl,
    CredentialVerification,
    ApprovalRules,
    Custom,
}

impl PolicySetType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccessControl => "ACCESS_CONTROL",
            Self::CredentialVerification => "CREDENTIAL_VERIFICATION",
            Self::ApprovalRules => "APPROVAL_RULES",
            Self::Custom => "CUSTOM",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySet {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub policy_type: PolicySetType,
    pub status: PolicySetStatus,
    pub cedar_policies: String,
    pub cedar_schema_version: String,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySetSpec {
    pub organization_id: Uuid,
    pub name: String,
    pub cedar_policies: String,
    pub policy_type: PolicySetType,
    pub description: Option<String>,
    pub created_by: Option<String>,
    pub cedar_schema_version: Option<String>,
    pub now: DateTime<Utc>,
}

impl PolicySet {
    #[must_use]
    pub fn create(spec: PolicySetSpec) -> Self {
        let PolicySetSpec {
            organization_id,
            name,
            cedar_policies,
            policy_type,
            description,
            created_by,
            cedar_schema_version,
            now,
        } = spec;
        Self {
            id: Uuid::new_v4(),
            organization_id,
            name,
            description,
            policy_type,
            status: PolicySetStatus::Draft,
            cedar_policies,
            cedar_schema_version: cedar_schema_version.unwrap_or_else(|| "MIP/1.0".to_owned()),
            created_by,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn archive(&mut self, now: DateTime<Utc>) {
        self.status = PolicySetStatus::Archived;
        self.updated_at = now;
    }

    pub fn activate(&mut self, now: DateTime<Utc>) {
        self.status = PolicySetStatus::Active;
        self.updated_at = now;
    }

    pub fn update_policies(&mut self, cedar_policies: impl Into<String>, now: DateTime<Utc>) {
        self.cedar_policies = cedar_policies.into();
        self.updated_at = now;
    }
}
