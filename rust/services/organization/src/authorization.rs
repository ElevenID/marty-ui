use std::collections::BTreeSet;

use mmf_security::{
    authenticate_tenant_membership, authorize_tenant_api_key, authorize_tenant_membership,
    TenantAuthorizationFailure, TenantMembership,
};
use uuid::Uuid;

use crate::application::{OrganizationApplication, OrganizationApplicationError};
use crate::domain::Member;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForwardedPrincipal {
    User {
        user_id: String,
    },
    ApiKey {
        user_id: String,
        api_key_id: String,
        organization_id: Uuid,
        authorized_permission: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrincipalSource {
    Session,
    ApiKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrganizationAuthorizationContext {
    pub principal_id: String,
    pub organization_id: Uuid,
    pub source: PrincipalSource,
    pub member_id: Option<Uuid>,
    pub role_names: BTreeSet<String>,
    pub permissions: BTreeSet<String>,
    pub is_owner: bool,
}

impl OrganizationApplication {
    pub async fn authorize_organization_membership(
        &self,
        organization_id: Uuid,
        principal: ForwardedPrincipal,
    ) -> Result<OrganizationAuthorizationContext, OrganizationApplicationError> {
        let member = self
            .load_forwarded_member(organization_id, &principal)
            .await?;
        authenticate_forwarded_principal(organization_id, &principal, member.as_ref())
    }

    pub async fn authorize_organization_action(
        &self,
        organization_id: Uuid,
        principal: ForwardedPrincipal,
        required_permission: &str,
        owner_only: bool,
    ) -> Result<OrganizationAuthorizationContext, OrganizationApplicationError> {
        let member = self
            .load_forwarded_member(organization_id, &principal)
            .await?;
        authorize_forwarded_principal(
            organization_id,
            &principal,
            required_permission,
            owner_only,
            member.as_ref(),
        )
    }

    async fn load_forwarded_member(
        &self,
        organization_id: Uuid,
        principal: &ForwardedPrincipal,
    ) -> Result<Option<Member>, OrganizationApplicationError> {
        match principal {
            ForwardedPrincipal::User { user_id } => Ok(self
                .store
                .member_by_user_and_organization(user_id, organization_id)
                .await?),
            ForwardedPrincipal::ApiKey { .. } => Ok(None),
        }
    }
}

pub fn authenticate_forwarded_principal(
    organization_id: Uuid,
    principal: &ForwardedPrincipal,
    member: Option<&Member>,
) -> Result<OrganizationAuthorizationContext, OrganizationApplicationError> {
    match principal {
        ForwardedPrincipal::User { user_id } => {
            let membership = member.map(project_tenant_membership);
            let membership = authenticate_tenant_membership(
                user_id,
                &organization_id.to_string(),
                membership.as_ref(),
            )
            .map_err(map_authorization_failure)?;
            Ok(user_context(organization_id, user_id, member, membership))
        }
        ForwardedPrincipal::ApiKey {
            user_id,
            api_key_id,
            organization_id: principal_organization_id,
            authorized_permission,
        } => {
            authorize_tenant_api_key(
                authorized_permission,
                user_id,
                &organization_id.to_string(),
                api_key_id,
                &principal_organization_id.to_string(),
                authorized_permission,
                false,
            )
            .map_err(map_authorization_failure)?;
            Ok(api_key_context(
                organization_id,
                user_id,
                authorized_permission,
            ))
        }
    }
}

pub fn authorize_forwarded_principal(
    organization_id: Uuid,
    principal: &ForwardedPrincipal,
    required_permission: &str,
    owner_only: bool,
    member: Option<&Member>,
) -> Result<OrganizationAuthorizationContext, OrganizationApplicationError> {
    if required_permission.trim().is_empty() {
        return Err(OrganizationApplicationError::ActionNotAuthorized);
    }
    match principal {
        ForwardedPrincipal::User { user_id } => {
            let membership = member.map(project_tenant_membership);
            authorize_tenant_membership(
                required_permission,
                user_id,
                &organization_id.to_string(),
                membership.as_ref(),
                owner_only,
            )
            .map_err(map_authorization_failure)?;
            Ok(user_context(
                organization_id,
                user_id,
                member,
                membership
                    .as_ref()
                    .expect("successful authorization requires projected membership"),
            ))
        }
        ForwardedPrincipal::ApiKey {
            user_id,
            api_key_id,
            organization_id: principal_organization_id,
            authorized_permission,
        } => {
            authorize_tenant_api_key(
                required_permission,
                user_id,
                &organization_id.to_string(),
                api_key_id,
                &principal_organization_id.to_string(),
                authorized_permission,
                owner_only,
            )
            .map_err(map_authorization_failure)?;
            Ok(api_key_context(
                organization_id,
                user_id,
                required_permission,
            ))
        }
    }
}

fn user_context(
    organization_id: Uuid,
    user_id: &str,
    member: Option<&Member>,
    membership: &TenantMembership,
) -> OrganizationAuthorizationContext {
    OrganizationAuthorizationContext {
        principal_id: user_id.to_owned(),
        organization_id,
        source: PrincipalSource::Session,
        member_id: Some(
            member
                .expect("successful membership authentication requires a member")
                .id,
        ),
        role_names: membership.role_names.clone(),
        permissions: membership.permissions.clone(),
        is_owner: membership.is_owner,
    }
}

fn api_key_context(
    organization_id: Uuid,
    user_id: &str,
    authorized_permission: &str,
) -> OrganizationAuthorizationContext {
    OrganizationAuthorizationContext {
        principal_id: user_id.to_owned(),
        organization_id,
        source: PrincipalSource::ApiKey,
        member_id: None,
        role_names: BTreeSet::new(),
        permissions: BTreeSet::from([authorized_permission.to_owned()]),
        is_owner: false,
    }
}

fn project_tenant_membership(member: &Member) -> TenantMembership {
    TenantMembership {
        principal_id: member.user_id.clone(),
        tenant_id: member.organization_id.to_string(),
        status: member.status.as_str().into(),
        role_names: member.roles.iter().map(|role| role.name.clone()).collect(),
        permissions: member.effective_permissions(),
        is_owner: member.is_owner(),
    }
}

fn map_authorization_failure(error: TenantAuthorizationFailure) -> OrganizationApplicationError {
    match error {
        TenantAuthorizationFailure::AuthenticationRequired => {
            OrganizationApplicationError::AuthenticationRequired
        }
        TenantAuthorizationFailure::MembershipMissing => {
            OrganizationApplicationError::MembershipRequired
        }
        TenantAuthorizationFailure::MembershipInactive => {
            OrganizationApplicationError::MembershipInactive
        }
        TenantAuthorizationFailure::ActionNotAuthorized => {
            OrganizationApplicationError::ActionNotAuthorized
        }
    }
}
