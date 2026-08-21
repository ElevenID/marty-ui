use std::collections::HashSet;

use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Active,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserType {
    #[default]
    Applicant,
    Vendor,
    Administrator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpersonationContext {
    #[serde(default = "default_true")]
    pub active: bool,
    pub admin_user_id: Option<String>,
    pub admin_username: Option<String>,
    pub admin_email: Option<String>,
    pub admin_display_name: Option<String>,
    pub target_user_id: Option<String>,
    pub target_email: Option<String>,
    pub organization_id: Option<String>,
    pub organization_name: Option<String>,
    pub started_at: Option<String>,
    pub launch_mode: Option<String>,
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub email: String,
    pub username: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    #[serde(default)]
    pub user_type: UserType,
    pub applicant_id: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    pub organization_id: Option<String>,
    pub organization_name: Option<String>,
    pub organization: Option<Value>,
    pub default_organization_id: Option<String>,
    pub default_organization_name: Option<String>,
    #[serde(default)]
    pub organizations: Vec<Value>,
    #[serde(default)]
    pub organization_context_unavailable: bool,
    pub organization_context_error: Option<String>,
    pub onboarding_completed: Option<DateTime<Utc>>,
    pub picture: Option<String>,
    pub impersonation: Option<ImpersonationContext>,
    pub did_subject: Option<String>,
}

impl AuthenticatedUser {
    #[must_use]
    pub fn display_name(&self) -> String {
        match (
            self.given_name.as_deref().filter(|value| !value.is_empty()),
            self.family_name
                .as_deref()
                .filter(|value| !value.is_empty()),
        ) {
            (Some(given), Some(family)) => format!("{given} {family}"),
            (Some(given), None) => given.to_owned(),
            (None, _) => self
                .username
                .as_deref()
                .filter(|value| !value.is_empty())
                .map_or_else(
                    || {
                        self.email
                            .split('@')
                            .next()
                            .unwrap_or(&self.email)
                            .to_owned()
                    },
                    str::to_owned,
                ),
        }
    }

    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.user_type == UserType::Administrator || self.has_role("admin")
    }

    #[must_use]
    pub fn is_org_admin(&self) -> bool {
        self.has_role("org_admin") || self.is_admin()
    }

    #[must_use]
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|candidate| candidate == role)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub user: AuthenticatedUser,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub status: SessionStatus,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub oidc_claims: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionSpec {
    pub user: AuthenticatedUser,
    pub ttl_seconds: i64,
    pub now: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub oidc_claims: Option<Value>,
}

impl Session {
    #[must_use]
    pub fn create(spec: SessionSpec) -> Self {
        Self {
            session_id: Uuid::new_v4().to_string(),
            user: spec.user,
            created_at: spec.now,
            expires_at: spec.now + Duration::seconds(spec.ttl_seconds),
            last_activity: spec.now,
            status: SessionStatus::Active,
            ip_address: spec.ip_address,
            user_agent: spec.user_agent,
            id_token: spec.id_token,
            refresh_token: spec.refresh_token,
            oidc_claims: spec.oidc_claims,
        }
    }

    #[must_use]
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        self.status == SessionStatus::Active && now < self.expires_at
    }

    #[must_use]
    pub fn remaining_ttl_seconds_at(&self, now: DateTime<Utc>) -> i64 {
        if self.is_valid_at(now) {
            (self.expires_at - now).num_seconds().max(0)
        } else {
            0
        }
    }

    pub fn touch_at(&mut self, now: DateTime<Utc>) {
        self.last_activity = now;
    }

    pub const fn revoke(&mut self) {
        self.status = SessionStatus::Revoked;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PkceState {
    pub state: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    pub oidc_redirect_uri: Option<String>,
    pub nonce: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl PkceState {
    #[must_use]
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        now < self.expires_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

#[must_use]
pub fn generate_pkce_pair() -> PkcePair {
    let verifier = random_urlsafe_token(64);
    let challenge = pkce_s256_challenge(&verifier);
    PkcePair {
        verifier,
        challenge,
    }
}

#[must_use]
pub fn random_urlsafe_token(byte_count: usize) -> String {
    let mut bytes = vec![0_u8; byte_count];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[must_use]
pub fn pkce_s256_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcUserInfo {
    pub sub: String,
    pub email: String,
    #[serde(default)]
    pub email_verified: bool,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub preferred_username: Option<String>,
    pub picture: Option<String>,
    pub locale: Option<String>,
    pub organization_id: Option<String>,
    pub organization_name: Option<String>,
    pub organization: Option<Value>,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OidcValidatedIdentity {
    pub user_info: OidcUserInfo,
    pub id_token_claims: Value,
    pub access_token_claims: Value,
}

impl OidcUserInfo {
    #[must_use]
    pub fn from_claims(primary: &Value, secondary: Option<&Value>) -> Self {
        let primary = primary.as_object();
        let secondary = secondary.and_then(Value::as_object);
        let claim_sets = [primary, secondary];
        let organization = first_object(&claim_sets, "organization").cloned();
        let organization_value = organization.clone().map(Value::Object);

        Self {
            sub: first_string(&claim_sets, &["sub", "subject"]).unwrap_or_default(),
            email: first_string(&claim_sets, &["email"]).unwrap_or_default(),
            email_verified: first_bool(&claim_sets, "email_verified").unwrap_or(false),
            name: first_string(&claim_sets, &["name"]),
            given_name: first_string(&claim_sets, &["given_name"]),
            family_name: first_string(&claim_sets, &["family_name"]),
            preferred_username: first_string(&claim_sets, &["preferred_username", "username"]),
            picture: first_string(&claim_sets, &["picture"]),
            locale: first_string(&claim_sets, &["locale"]),
            organization_id: first_string(&claim_sets, &["organization_id"])
                .or_else(|| organization.as_ref().and_then(first_map_key)),
            organization_name: first_string(&claim_sets, &["organization_name"])
                .or_else(|| organization.as_ref().and_then(first_organization_name)),
            organization: organization_value,
            roles: collect_roles(&claim_sets),
        }
    }
}

fn first_string(claim_sets: &[Option<&Map<String, Value>>], keys: &[&str]) -> Option<String> {
    for claims in claim_sets.iter().flatten() {
        for key in keys {
            if let Some(value) = claims.get(*key).and_then(Value::as_str) {
                if !value.is_empty() {
                    return Some(value.to_owned());
                }
            }
        }
    }
    None
}

fn first_bool(claim_sets: &[Option<&Map<String, Value>>], key: &str) -> Option<bool> {
    claim_sets
        .iter()
        .flatten()
        .find_map(|claims| claims.get(key).and_then(Value::as_bool))
}

fn first_object<'a>(
    claim_sets: &'a [Option<&'a Map<String, Value>>],
    key: &str,
) -> Option<&'a Map<String, Value>> {
    claim_sets.iter().flatten().find_map(|claims| {
        claims
            .get(key)
            .and_then(Value::as_object)
            .filter(|map| !map.is_empty())
    })
}

fn first_map_key(map: &Map<String, Value>) -> Option<String> {
    map.keys().find(|key| !key.is_empty()).cloned()
}

fn first_organization_name(map: &Map<String, Value>) -> Option<String> {
    map.values().find_map(|organization| {
        let organization = organization.as_object()?;
        ["display_name", "displayName", "name"]
            .into_iter()
            .find_map(|key| organization.get(key).and_then(Value::as_str))
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}

fn collect_roles(claim_sets: &[Option<&Map<String, Value>>]) -> Vec<String> {
    let mut roles = Vec::new();
    let mut seen = HashSet::new();
    for claims in claim_sets.iter().flatten() {
        append_roles(claims.get("roles"), &mut roles, &mut seen);
        if let Some(realm_access) = claims.get("realm_access").and_then(Value::as_object) {
            append_roles(realm_access.get("roles"), &mut roles, &mut seen);
        }
        if let Some(resource_access) = claims.get("resource_access").and_then(Value::as_object) {
            for client_access in resource_access.values().filter_map(Value::as_object) {
                append_roles(client_access.get("roles"), &mut roles, &mut seen);
            }
        }
    }
    roles
}

fn append_roles(value: Option<&Value>, roles: &mut Vec<String>, seen: &mut HashSet<String>) {
    let Some(candidates) = value.and_then(Value::as_array) else {
        return;
    };
    for role in candidates
        .iter()
        .filter_map(Value::as_str)
        .filter(|role| !role.is_empty())
    {
        if seen.insert(role.to_owned()) {
            roles.push(role.to_owned());
        }
    }
}
