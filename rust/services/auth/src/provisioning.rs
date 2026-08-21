use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    AuthenticatedUser, OidcUserInfo, OidcValidatedIdentity, PortError, UserProvisioner, UserType,
};

pub const UNKNOWN_NATIONALITY: &str = "UNK";

#[must_use]
pub fn unknown_date_of_birth() -> NaiveDate {
    NaiveDate::from_ymd_opt(1900, 1, 1).expect("known valid date")
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApplicantProfile {
    pub id: String,
    pub account_id: Option<String>,
    pub email: String,
    pub surname: String,
    pub given_names: String,
    pub date_of_birth: NaiveDate,
    pub nationality: String,
    pub identity_proofing_completed: bool,
    pub identity_proofing_date: Option<DateTime<Utc>>,
    pub active: bool,
    pub suspended: bool,
    pub extra_data: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApplicantUpsert {
    pub new_id: String,
    pub account_id: String,
    pub email: String,
    pub given_names: Option<String>,
    pub surname: Option<String>,
    pub fallback_given_names: String,
    pub fallback_surname: String,
    pub date_of_birth: NaiveDate,
    pub nationality: String,
    pub extra_data_patch: Value,
    pub now: DateTime<Utc>,
}

#[must_use]
pub fn extract_applicant_names(user: &OidcUserInfo) -> (Option<String>, Option<String>) {
    let mut given_names = nonempty_trimmed(user.given_name.as_deref());
    let mut surname = nonempty_trimmed(user.family_name.as_deref());
    if given_names.is_none() && surname.is_none() {
        if let Some(name) = nonempty_trimmed(user.name.as_deref()) {
            let mut parts = name.splitn(2, char::is_whitespace);
            given_names = parts.next().and_then(|part| nonempty_trimmed(Some(part)));
            surname = parts.next().and_then(|part| nonempty_trimmed(Some(part)));
        }
    }
    (given_names, surname)
}

fn nonempty_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[must_use]
pub fn applicant_upsert(user: &OidcUserInfo, now: DateTime<Utc>) -> ApplicantUpsert {
    let (given_names, surname) = extract_applicant_names(user);
    ApplicantUpsert {
        new_id: Uuid::new_v4().to_string(),
        account_id: user.sub.clone(),
        email: user.email.clone(),
        given_names: given_names.clone(),
        surname: surname.clone(),
        fallback_given_names: "Unknown".to_owned(),
        fallback_surname: "Unknown".to_owned(),
        date_of_birth: unknown_date_of_birth(),
        nationality: UNKNOWN_NATIONALITY.to_owned(),
        extra_data_patch: json!({
            "provisioned_via": "jit",
            "oidc_claims_incomplete": !(given_names.is_some() && surname.is_some()),
            "last_login_at": now.to_rfc3339(),
        }),
        now,
    }
}

#[async_trait]
pub trait ApplicantProvisioningStore: Send + Sync {
    async fn upsert(&self, plan: &ApplicantUpsert) -> Result<ApplicantProfile, PortError>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrganizationContext {
    pub organization_id: String,
    pub organization_name: Option<String>,
    pub role_names: Vec<String>,
    pub has_org_console_access: bool,
}

#[async_trait]
pub trait OrganizationProvisioning: Send + Sync {
    async fn ensure_default_member(&self, user_id: &str, email: &str) -> Result<(), PortError>;
    async fn resolve_default_context(
        &self,
        user_id: &str,
    ) -> Result<Option<OrganizationContext>, PortError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JitProvisioningConfig {
    pub default_organization_id: String,
    pub default_organization_slug: String,
    pub default_organization_name: String,
}

pub struct JitUserProvisioner {
    applicants: Arc<dyn ApplicantProvisioningStore>,
    organizations: Arc<dyn OrganizationProvisioning>,
    config: JitProvisioningConfig,
}

impl JitUserProvisioner {
    #[must_use]
    pub fn new(
        applicants: Arc<dyn ApplicantProvisioningStore>,
        organizations: Arc<dyn OrganizationProvisioning>,
        config: JitProvisioningConfig,
    ) -> Self {
        Self {
            applicants,
            organizations,
            config,
        }
    }

    pub async fn provision_at(
        &self,
        oidc_user: &OidcUserInfo,
        now: DateTime<Utc>,
    ) -> Result<AuthenticatedUser, PortError> {
        if oidc_user.sub.is_empty() || oidc_user.email.is_empty() {
            return Err(PortError::new(
                "invalid_oidc_identity",
                "OIDC subject and email are required for provisioning",
            ));
        }
        let applicant = self
            .applicants
            .upsert(&applicant_upsert(oidc_user, now))
            .await?;
        let add_failed = self
            .organizations
            .ensure_default_member(&applicant.id, &applicant.email)
            .await
            .is_err();
        let (context, context_failed) = match self
            .organizations
            .resolve_default_context(&applicant.id)
            .await
        {
            Ok(context) => (context, false),
            Err(_) => (None, true),
        };
        let context_unavailable = add_failed || context_failed;
        let mut roles = oidc_user.roles.clone();
        if let Some(context) = &context {
            append_unique(&mut roles, &context.role_names);
        }
        let has_console_access = context
            .as_ref()
            .is_some_and(|context| context.has_org_console_access);
        let user_type = user_type(&roles, has_console_access);
        let organization_id = context
            .as_ref()
            .map(|context| context.organization_id.clone())
            .or_else(|| oidc_user.organization_id.clone());
        let organization_name = context
            .as_ref()
            .and_then(|context| context.organization_name.clone())
            .or_else(|| oidc_user.organization_name.clone());
        let (given_name, family_name) = authenticated_names(&applicant);
        let organizations = context
            .as_ref()
            .map_or_else(Vec::new, |context| self.organization_summary(context));

        Ok(AuthenticatedUser {
            user_id: applicant.id.clone(),
            email: applicant.email,
            username: oidc_user.preferred_username.clone(),
            given_name,
            family_name,
            user_type,
            applicant_id: Some(applicant.id),
            roles,
            organization_id: organization_id.clone(),
            organization_name: organization_name.clone(),
            organization: oidc_user.organization.clone(),
            default_organization_id: organization_id,
            default_organization_name: organization_name,
            organizations,
            organization_context_unavailable: context_unavailable,
            organization_context_error: context_unavailable
                .then(|| "marty_organization_context_unavailable".to_owned()),
            onboarding_completed: applicant
                .identity_proofing_completed
                .then_some(applicant.identity_proofing_date)
                .flatten(),
            picture: oidc_user.picture.clone(),
            impersonation: None,
            did_subject: None,
        })
    }

    fn organization_summary(&self, context: &OrganizationContext) -> Vec<Value> {
        vec![json!({
            "id": context.organization_id,
            "name": self.config.default_organization_slug,
            "display_name": context.organization_name.as_deref().unwrap_or(&self.config.default_organization_name),
            "membership": {
                "roles": context.role_names.iter().map(|name| json!({"name": name, "display_name": name})).collect::<Vec<_>>(),
                "status": "active",
                "permissions": [],
                "has_org_console_access": context.has_org_console_access,
                "is_owner": context.role_names.iter().any(|role| role == "owner"),
            }
        })]
    }
}

#[async_trait]
impl UserProvisioner for JitUserProvisioner {
    async fn provision(
        &self,
        identity: &OidcValidatedIdentity,
    ) -> Result<AuthenticatedUser, PortError> {
        self.provision_at(&identity.user_info, Utc::now()).await
    }
}

fn append_unique(target: &mut Vec<String>, candidates: &[String]) {
    for candidate in candidates {
        if !candidate.is_empty() && !target.contains(candidate) {
            target.push(candidate.clone());
        }
    }
}

fn user_type(roles: &[String], has_console_access: bool) -> UserType {
    if roles
        .iter()
        .any(|role| matches!(role.as_str(), "admin" | "administrator"))
    {
        UserType::Administrator
    } else if has_console_access || roles.iter().any(|role| role == "vendor") {
        UserType::Vendor
    } else {
        UserType::Applicant
    }
}

fn authenticated_names(applicant: &ApplicantProfile) -> (Option<String>, Option<String>) {
    let given = nonempty_trimmed(Some(&applicant.given_names)).filter(|name| name != "Unknown");
    let family = nonempty_trimmed(Some(&applicant.surname)).filter(|name| name != "Unknown");
    (given, family)
}

#[derive(Default)]
pub struct MemoryApplicantProvisioningStore {
    profiles: Mutex<HashMap<String, ApplicantProfile>>,
}

#[async_trait]
impl ApplicantProvisioningStore for MemoryApplicantProvisioningStore {
    async fn upsert(&self, plan: &ApplicantUpsert) -> Result<ApplicantProfile, PortError> {
        let mut profiles = self.profiles.lock().map_err(|_| {
            PortError::new(
                "applicant_store_unavailable",
                "applicant store lock poisoned",
            )
        })?;
        let key = profiles
            .iter()
            .find(|(_, profile)| {
                profile.account_id.as_deref() == Some(&plan.account_id)
                    || profile.email == plan.email
            })
            .map(|(key, _)| key.clone())
            .unwrap_or_else(|| plan.new_id.clone());
        let profile = profiles
            .entry(key.clone())
            .or_insert_with(|| ApplicantProfile {
                id: key,
                account_id: Some(plan.account_id.clone()),
                email: plan.email.clone(),
                surname: plan
                    .surname
                    .clone()
                    .unwrap_or_else(|| plan.fallback_surname.clone()),
                given_names: plan
                    .given_names
                    .clone()
                    .unwrap_or_else(|| plan.fallback_given_names.clone()),
                date_of_birth: plan.date_of_birth,
                nationality: plan.nationality.clone(),
                identity_proofing_completed: false,
                identity_proofing_date: None,
                active: true,
                suspended: false,
                extra_data: Value::Object(serde_json::Map::new()),
                created_at: plan.now,
                updated_at: plan.now,
            });
        profile.account_id = Some(plan.account_id.clone());
        profile.email.clone_from(&plan.email);
        if let Some(given_names) = &plan.given_names {
            profile.given_names.clone_from(given_names);
        }
        if let Some(surname) = &plan.surname {
            profile.surname.clone_from(surname);
        }
        profile.updated_at = plan.now;
        merge_json_object(&mut profile.extra_data, &plan.extra_data_patch);
        Ok(profile.clone())
    }
}

fn merge_json_object(target: &mut Value, patch: &Value) {
    let target = target.as_object_mut();
    let patch = patch.as_object();
    if let (Some(target), Some(patch)) = (target, patch) {
        for (key, value) in patch {
            target.insert(key.clone(), value.clone());
        }
    }
}
