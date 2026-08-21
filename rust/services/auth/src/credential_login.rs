use async_trait::async_trait;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{AuthenticatedUser, OidcUserInfo, PortError, UserType};

#[async_trait]
pub trait CredentialIdentityProvisioner: Send + Sync {
    async fn provision_credential_identity(
        &self,
        user: &OidcUserInfo,
    ) -> Result<AuthenticatedUser, PortError>;
}

pub async fn build_credential_login_user(
    claims: &Value,
    provisioner: Option<&dyn CredentialIdentityProvisioner>,
    keycloak_user: Option<&OidcUserInfo>,
) -> Result<AuthenticatedUser, PortError> {
    let claims = claims.as_object().ok_or_else(|| {
        PortError::new(
            "invalid_credential_login_claims",
            "credential claims must be an object",
        )
    })?;
    let email = string_claim(claims, "email").ok_or_else(|| {
        PortError::new(
            "credential_email_required",
            "credential is missing the email claim",
        )
    })?;
    let role = string_claim(claims, "role").unwrap_or_else(|| "applicant".to_owned());
    let user_id = derive_user_id(&email, claims);
    let did_subject = extract_did_subject(claims);
    let fallback_oidc = fallback_oidc_user(claims, &email, &role, &user_id);
    let fallback_user = fallback_user(claims, &fallback_oidc);
    let identity_seed = keycloak_user.unwrap_or(&fallback_oidc);

    let provisioned = if let Some(provisioner) = provisioner {
        provisioner
            .provision_credential_identity(identity_seed)
            .await
            .unwrap_or_else(|_| {
                authenticated_user(
                    identity_seed,
                    fallback_user.applicant_id.clone(),
                    did_subject.clone(),
                )
            })
    } else {
        authenticated_user(
            identity_seed,
            fallback_user.applicant_id.clone(),
            did_subject.clone(),
        )
    };
    Ok(merge_credential_user(
        provisioned,
        fallback_user,
        did_subject,
    ))
}

#[must_use]
pub fn apply_credential_login_defaults(
    mut user: AuthenticatedUser,
    default_organization_id: &str,
) -> AuthenticatedUser {
    if !user.has_role("canvas_lti_learner") && user.organization_id.is_none() {
        user.organization_id = Some(default_organization_id.to_owned());
    }
    user
}

fn derive_user_id(email: &str, claims: &Map<String, Value>) -> String {
    string_claim(claims, "sub")
        .or_else(|| string_claim(claims, "subject"))
        .unwrap_or_else(|| {
            let digest = Sha256::digest(email.to_lowercase().as_bytes());
            let mut bytes = [0_u8; 16];
            bytes.copy_from_slice(&digest[..16]);
            Uuid::from_bytes(bytes).to_string()
        })
}

fn extract_did_subject(claims: &Map<String, Value>) -> Option<String> {
    claims
        .get("credentialSubject")
        .and_then(Value::as_object)
        .and_then(|subject| string_claim(subject, "id"))
        .filter(|subject| subject.starts_with("did:"))
        .or_else(|| string_claim(claims, "sub").filter(|subject| subject.starts_with("did:")))
}

fn fallback_oidc_user(
    claims: &Map<String, Value>,
    email: &str,
    role: &str,
    user_id: &str,
) -> OidcUserInfo {
    OidcUserInfo {
        sub: user_id.to_owned(),
        email: email.to_owned(),
        email_verified: claims
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        name: string_claim(claims, "name"),
        given_name: string_claim(claims, "given_name"),
        family_name: string_claim(claims, "family_name"),
        preferred_username: string_claim(claims, "preferred_username")
            .or_else(|| Some(email.to_owned())),
        picture: string_claim(claims, "picture"),
        locale: string_claim(claims, "locale"),
        organization_id: string_claim(claims, "organization_id"),
        organization_name: string_claim(claims, "organization_name"),
        organization: claims
            .get("organization")
            .filter(|value| value.is_object())
            .cloned(),
        roles: vec![role.to_owned()],
    }
}

fn fallback_user(claims: &Map<String, Value>, oidc: &OidcUserInfo) -> AuthenticatedUser {
    authenticated_user(
        oidc,
        string_claim(claims, "member_id"),
        extract_did_subject(claims),
    )
}

fn authenticated_user(
    oidc: &OidcUserInfo,
    applicant_id: Option<String>,
    did_subject: Option<String>,
) -> AuthenticatedUser {
    AuthenticatedUser {
        user_id: oidc.sub.clone(),
        email: oidc.email.clone(),
        username: oidc.preferred_username.clone(),
        given_name: oidc.given_name.clone(),
        family_name: oidc.family_name.clone(),
        user_type: user_type_from_roles(&oidc.roles),
        applicant_id,
        roles: oidc.roles.clone(),
        organization_id: oidc.organization_id.clone(),
        organization_name: oidc.organization_name.clone(),
        organization: oidc.organization.clone(),
        default_organization_id: None,
        default_organization_name: None,
        organizations: Vec::new(),
        organization_context_unavailable: false,
        organization_context_error: None,
        onboarding_completed: None,
        picture: oidc.picture.clone(),
        impersonation: None,
        did_subject,
    }
}

fn merge_credential_user(
    provisioned: AuthenticatedUser,
    fallback: AuthenticatedUser,
    did_subject: Option<String>,
) -> AuthenticatedUser {
    let roles = merge_roles(&provisioned.roles, &fallback.roles);
    let user_type = prefer_user_type(provisioned.user_type, user_type_from_roles(&roles));
    AuthenticatedUser {
        user_id: nonempty(provisioned.user_id).unwrap_or(fallback.user_id),
        email: nonempty(fallback.email).unwrap_or(provisioned.email),
        username: fallback.username.or(provisioned.username),
        given_name: provisioned.given_name.or(fallback.given_name),
        family_name: provisioned.family_name.or(fallback.family_name),
        user_type,
        applicant_id: fallback.applicant_id.or(provisioned.applicant_id),
        roles,
        organization_id: provisioned.organization_id.or(fallback.organization_id),
        organization_name: provisioned.organization_name.or(fallback.organization_name),
        organization: provisioned.organization.or(fallback.organization),
        default_organization_id: provisioned.default_organization_id,
        default_organization_name: provisioned.default_organization_name,
        organizations: provisioned.organizations,
        organization_context_unavailable: provisioned.organization_context_unavailable,
        organization_context_error: provisioned.organization_context_error,
        onboarding_completed: provisioned.onboarding_completed,
        picture: provisioned.picture.or(fallback.picture),
        impersonation: provisioned.impersonation,
        did_subject: did_subject.or(provisioned.did_subject),
    }
}

fn string_claim(claims: &Map<String, Value>, name: &str) -> Option<String> {
    claims
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn merge_roles(primary: &[String], secondary: &[String]) -> Vec<String> {
    let mut roles = primary.to_vec();
    for role in secondary {
        if !role.is_empty() && !roles.contains(role) {
            roles.push(role.clone());
        }
    }
    roles
}

fn user_type_from_roles(roles: &[String]) -> UserType {
    if roles
        .iter()
        .any(|role| matches!(role.as_str(), "admin" | "administrator"))
    {
        UserType::Administrator
    } else if roles.iter().any(|role| role == "vendor") {
        UserType::Vendor
    } else {
        UserType::Applicant
    }
}

const fn prefer_user_type(left: UserType, right: UserType) -> UserType {
    if user_type_priority(left) >= user_type_priority(right) {
        left
    } else {
        right
    }
}

const fn user_type_priority(user_type: UserType) -> u8 {
    match user_type {
        UserType::Applicant => 0,
        UserType::Vendor => 1,
        UserType::Administrator => 2,
    }
}

fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}
