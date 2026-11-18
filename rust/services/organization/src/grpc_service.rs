use std::sync::Arc;

use chrono::{DateTime, Utc};
use mmf_security::{SecurityError, ServiceTokenAuthenticator};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::{
    organization_proto::{
        organization_service_server::OrganizationService, AddMemberRequest,
        CreateOrganizationRequest, GetMemberPermissionsRequest, GetMemberPermissionsResponse,
        GetMemberRequest, GetOrganizationRequest, HealthCheckRequest, HealthCheckResponse,
        ListMembersRequest, ListMembersResponse, ListOrganizationsRequest,
        ListOrganizationsResponse, MemberResponse, OrganizationResponse, RemoveMemberRequest,
        RemoveMemberResponse, RoleSummary, UpdateMemberRequest, UpdateOrganizationRequest,
        ValidateApiKeyRequest, ValidateApiKeyResponse,
    },
    AddMemberDirectCommand, CreateOrganizationCommand, JoinMechanism, Member, Organization,
    OrganizationApplication, OrganizationApplicationError, OrganizationType, RemoveMemberCommand,
    SetMemberRolesCommand, UpdateOrganizationCommand, UpdateOrganizationPatch,
};

pub const ORGANIZATION_GRPC_METHODS: &[&str] = &[
    "GetOrganization",
    "CreateOrganization",
    "UpdateOrganization",
    "ListOrganizations",
    "GetMember",
    "AddMember",
    "UpdateMember",
    "RemoveMember",
    "ListMembers",
    "ValidateApiKey",
    "GetMemberPermissions",
    "HealthCheck",
];

#[derive(Clone)]
pub struct OrganizationGrpcService {
    application: Arc<OrganizationApplication>,
    service_authenticator: ServiceTokenAuthenticator,
}

impl OrganizationGrpcService {
    pub fn new(
        application: Arc<OrganizationApplication>,
        service_token: Option<String>,
        service_authentication_required: bool,
    ) -> Result<Self, SecurityError> {
        Ok(Self {
            application,
            service_authenticator: ServiceTokenAuthenticator::new(
                service_token,
                service_authentication_required,
            )?,
        })
    }

    fn authenticate<T>(&self, request: &Request<T>) -> Result<(), Status> {
        authenticate_service_token(&self.service_authenticator, request)
    }

    async fn principal_membership(
        &self,
        user_id: &str,
        organization_id: Uuid,
    ) -> Result<MemberResponse, Status> {
        let explicit = self
            .application
            .get_membership(user_id, organization_id)
            .await
            .map_err(application_status)?
            .as_ref()
            .map(member_response);
        let response = if let Some(raw_id) = user_id.strip_prefix("api_key:") {
            let id = Uuid::parse_str(raw_id)
                .map_err(|_| Status::not_found("ORGANIZATION.MEMBERSHIP_NOT_FOUND"))?;
            let key = self
                .application
                .get_api_key(organization_id, id)
                .await
                .map_err(application_status)?;
            match key {
                Some(key) if key.is_valid_at(Utc::now()) => {
                    let catalog = self
                        .application
                        .list_permissions()
                        .await
                        .map_err(application_status)?;
                    api_key_member_response(
                        &key,
                        user_id,
                        organization_id,
                        explicit,
                        catalog.iter().map(crate::Permission::key),
                        Utc::now(),
                    )
                }
                _ => None,
            }
        } else {
            explicit
        };
        response.ok_or_else(|| Status::not_found("ORGANIZATION.MEMBERSHIP_NOT_FOUND"))
    }
}

/// Service-principal view of an authoritative live key; no human member or role
/// is created. Persisted restrictions can narrow scopes, never expand them.
fn api_key_member_response(
    key: &crate::ApiKey,
    principal: &str,
    organization_id: Uuid,
    explicit: Option<MemberResponse>,
    catalog: impl IntoIterator<Item = String>,
    now: DateTime<Utc>,
) -> Option<MemberResponse> {
    if key.organization_id != organization_id
        || principal != format!("api_key:{}", key.id)
        || !key.is_valid_at(now)
    {
        return None;
    }
    // A deployment-scoped key cannot gain a new organization-wide membership.
    // Existing explicit service memberships remain bounded by their own grants.
    if explicit.is_none()
        && (key.scope_type != crate::ApiKeyScopeType::Organization.as_str()
            || key.deployment_profile_id.is_some())
    {
        return None;
    }
    if explicit.as_ref().is_some_and(|member| {
        !member.status.eq_ignore_ascii_case("active")
            || member.organization_id != organization_id.to_string()
            || member.user_id != principal
    }) {
        return None;
    }
    let permissions = catalog
        .into_iter()
        .filter(|permission| {
            marty_api_key_policy::api_key_allowed(permission, &key.scopes)
                && explicit
                    .as_ref()
                    .is_none_or(|member| member.permissions.contains(permission))
        })
        .collect();
    Some(MemberResponse {
        id: key.id.to_string(),
        organization_id: organization_id.to_string(),
        user_id: principal.into(),
        permissions,
        status: "ACTIVE".into(),
        joined_at: key.created_at.to_rfc3339(),
        // Service principals never inherit human console/owner roles.
        roles: Vec::new(),
        has_org_console_access: false,
        is_owner: false,
        email: String::new(),
        invited_at: String::new(),
    })
}

#[tonic::async_trait]
impl OrganizationService for OrganizationGrpcService {
    async fn get_organization(
        &self,
        request: Request<GetOrganizationRequest>,
    ) -> Result<Response<OrganizationResponse>, Status> {
        self.authenticate(&request)?;
        let organization_id = parse_uuid(&request.get_ref().organization_id, "organization_id")?;
        let organization = self
            .application
            .get_organization(organization_id)
            .await
            .map_err(application_status)?
            .ok_or_else(|| Status::not_found("ORGANIZATION.NOT_FOUND"))?;
        Ok(Response::new(organization_response(&organization)))
    }

    async fn create_organization(
        &self,
        request: Request<CreateOrganizationRequest>,
    ) -> Result<Response<OrganizationResponse>, Status> {
        self.authenticate(&request)?;
        let input = request.into_inner();
        let result = self
            .application
            .create_organization(CreateOrganizationCommand {
                name: input.name,
                owner_id: input.creator_user_id,
                org_type: parse_organization_type(default_value(&input.org_type, "startup"))?,
                display_name: optional_text(input.display_name),
                description: optional_text(input.description),
                contact_email: optional_text(input.contact_email),
                visibility: "PRIVATE".into(),
                join_mechanism: JoinMechanism::Invite,
                requires_approval: false,
                now: Utc::now(),
            })
            .await
            .map_err(application_status)?;
        Ok(Response::new(organization_response(&result.value)))
    }

    async fn update_organization(
        &self,
        request: Request<UpdateOrganizationRequest>,
    ) -> Result<Response<OrganizationResponse>, Status> {
        self.authenticate(&request)?;
        let input = request.into_inner();
        let organization_id = parse_uuid(&input.organization_id, "organization_id")?;
        let patch = UpdateOrganizationPatch {
            display_name: optional_text(input.display_name),
            description: optional_nullable_text(input.description),
            contact_email: optional_nullable_text(input.contact_email),
            contact_phone: optional_nullable_text(input.contact_phone),
            website: optional_nullable_text(input.website),
            visibility: Some(if input.is_discoverable {
                "PUBLIC".into()
            } else {
                "PRIVATE".into()
            }),
            join_mechanism: optional_text(input.join_mechanism)
                .as_deref()
                .map(parse_join_mechanism)
                .transpose()?,
            requires_approval: Some(input.requires_approval),
            ..UpdateOrganizationPatch::default()
        };
        let result = self
            .application
            .update_organization(UpdateOrganizationCommand {
                organization_id,
                patch,
                now: Utc::now(),
            })
            .await
            .map_err(application_status)?;
        Ok(Response::new(organization_response(&result.value)))
    }

    async fn list_organizations(
        &self,
        request: Request<ListOrganizationsRequest>,
    ) -> Result<Response<ListOrganizationsResponse>, Status> {
        self.authenticate(&request)?;
        let input = request.into_inner();
        let limit = if input.limit <= 0 {
            100
        } else {
            u32::try_from(input.limit).unwrap_or(1_000).min(1_000)
        };
        let offset = u32::try_from(input.offset.max(0)).unwrap_or(u32::MAX);
        let org_type = optional_text(input.org_type)
            .as_deref()
            .map(parse_organization_type)
            .transpose()?;
        let join_mechanism = optional_text(input.join_mechanism)
            .as_deref()
            .map(parse_join_mechanism)
            .transpose()?;
        let (organizations, total) = self
            .application
            .list_organizations_filtered(
                optional_text(input.search).as_deref(),
                org_type,
                join_mechanism,
                limit,
                offset,
            )
            .await
            .map_err(application_status)?;
        Ok(Response::new(ListOrganizationsResponse {
            organizations: organizations.iter().map(organization_response).collect(),
            total: i32::try_from(total).unwrap_or(i32::MAX),
        }))
    }

    async fn get_member(
        &self,
        request: Request<GetMemberRequest>,
    ) -> Result<Response<MemberResponse>, Status> {
        self.authenticate(&request)?;
        let input = request.into_inner();
        let organization_id = parse_uuid(&input.organization_id, "organization_id")?;
        Ok(Response::new(
            self.principal_membership(&input.user_id, organization_id)
                .await?,
        ))
    }

    async fn add_member(
        &self,
        request: Request<AddMemberRequest>,
    ) -> Result<Response<MemberResponse>, Status> {
        self.authenticate(&request)?;
        let input = request.into_inner();
        let result = self
            .application
            .add_member_direct(AddMemberDirectCommand {
                organization_id: parse_uuid(&input.organization_id, "organization_id")?,
                user_id: input.user_id,
                email: optional_text(input.email),
                role_ids: parse_optional_uuids(&input.role_ids, "role_ids")?,
                now: Utc::now(),
            })
            .await
            .map_err(application_status)?;
        Ok(Response::new(member_response(&result.value)))
    }

    async fn update_member(
        &self,
        request: Request<UpdateMemberRequest>,
    ) -> Result<Response<MemberResponse>, Status> {
        self.authenticate(&request)?;
        let input = request.into_inner();
        let result = self
            .application
            .set_member_roles(SetMemberRolesCommand {
                member_id: parse_uuid(&input.member_id, "member_id")?,
                organization_id: parse_uuid(&input.organization_id, "organization_id")?,
                role_ids: parse_uuids(&input.role_ids, "role_ids")?,
                updated_by: "grpc".into(),
                now: Utc::now(),
            })
            .await
            .map_err(application_status)?;
        Ok(Response::new(member_response(&result.value)))
    }

    async fn remove_member(
        &self,
        request: Request<RemoveMemberRequest>,
    ) -> Result<Response<RemoveMemberResponse>, Status> {
        self.authenticate(&request)?;
        let input = request.into_inner();
        self.application
            .remove_member(RemoveMemberCommand {
                organization_id: parse_uuid(&input.organization_id, "organization_id")?,
                member_id: parse_uuid(&input.member_id, "member_id")?,
                removed_by: "grpc".into(),
                now: Utc::now(),
            })
            .await
            .map_err(application_status)?;
        Ok(Response::new(RemoveMemberResponse { success: true }))
    }

    async fn list_members(
        &self,
        request: Request<ListMembersRequest>,
    ) -> Result<Response<ListMembersResponse>, Status> {
        self.authenticate(&request)?;
        let organization_id = parse_uuid(&request.get_ref().organization_id, "organization_id")?;
        let members = self
            .application
            .list_members(organization_id)
            .await
            .map_err(application_status)?;
        Ok(Response::new(ListMembersResponse {
            members: members.iter().map(member_response).collect(),
        }))
    }

    async fn validate_api_key(
        &self,
        request: Request<ValidateApiKeyRequest>,
    ) -> Result<Response<ValidateApiKeyResponse>, Status> {
        self.authenticate(&request)?;
        let api_key = self
            .application
            .validate_api_key(&request.get_ref().api_key, Utc::now())
            .await
            .map_err(application_status)?;
        let response = api_key.map_or_else(
            || ValidateApiKeyResponse {
                valid: false,
                ..ValidateApiKeyResponse::default()
            },
            |api_key| ValidateApiKeyResponse {
                valid: true,
                api_key_id: api_key.id.to_string(),
                organization_id: api_key.organization_id.to_string(),
                key_prefix: api_key.key_prefix,
                scopes: api_key.scopes,
            },
        );
        Ok(Response::new(response))
    }

    async fn get_member_permissions(
        &self,
        request: Request<GetMemberPermissionsRequest>,
    ) -> Result<Response<GetMemberPermissionsResponse>, Status> {
        self.authenticate(&request)?;
        let input = request.into_inner();
        let organization_id = parse_uuid(&input.organization_id, "organization_id")?;
        let member = self
            .principal_membership(&input.user_id, organization_id)
            .await?;
        Ok(Response::new(GetMemberPermissionsResponse {
            permissions: member.permissions,
            roles: member.roles,
            has_org_console_access: member.has_org_console_access,
            is_owner: member.is_owner,
        }))
    }

    async fn health_check(
        &self,
        request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        self.authenticate(&request)?;
        Ok(Response::new(HealthCheckResponse {
            status: "serving".into(),
        }))
    }
}

fn organization_response(organization: &Organization) -> OrganizationResponse {
    OrganizationResponse {
        id: organization.id.to_string(),
        name: organization.name.clone(),
        display_name: organization.display_name.clone().unwrap_or_default(),
        slug: organization.slug.clone(),
        description: organization.description.clone().unwrap_or_default(),
        org_type: organization.org_type.as_str().into(),
        status: organization.status.as_str().into(),
        contact_email: organization.contact_email.clone().unwrap_or_default(),
        contact_phone: organization.contact_phone.clone().unwrap_or_default(),
        website: organization.website.clone().unwrap_or_default(),
        join_mechanism: organization.join_mechanism.as_str().into(),
        requires_approval: organization.requires_approval,
        is_discoverable: organization.is_discoverable,
        created_at: organization.created_at.to_rfc3339(),
        updated_at: organization.updated_at.to_rfc3339(),
    }
}

fn member_response(member: &Member) -> MemberResponse {
    MemberResponse {
        id: member.id.to_string(),
        organization_id: member.organization_id.to_string(),
        user_id: member.user_id.clone(),
        email: member.email.clone().unwrap_or_default(),
        roles: member.roles.iter().map(role_summary).collect(),
        status: member.status.as_str().into(),
        invited_at: member
            .invited_at
            .map(|value| value.to_rfc3339())
            .unwrap_or_default(),
        joined_at: member
            .joined_at
            .map(|value| value.to_rfc3339())
            .unwrap_or_default(),
        permissions: member.effective_permissions().into_iter().collect(),
        has_org_console_access: member.has_org_console_access(),
        is_owner: member.is_owner(),
    }
}

fn role_summary(role: &crate::Role) -> RoleSummary {
    RoleSummary {
        id: role.id.to_string(),
        name: role.name.clone(),
        display_name: role.display_name.clone().unwrap_or_default(),
    }
}

fn parse_uuid(value: &str, field: &'static str) -> Result<Uuid, Status> {
    value
        .parse()
        .map_err(|_| Status::invalid_argument(format!("ORGANIZATION.INVALID_{field}")))
}

fn parse_uuids(values: &[String], field: &'static str) -> Result<Vec<Uuid>, Status> {
    values
        .iter()
        .map(|value| parse_uuid(value, field))
        .collect()
}

fn parse_optional_uuids(
    values: &[String],
    field: &'static str,
) -> Result<Option<Vec<Uuid>>, Status> {
    if values.is_empty() {
        Ok(None)
    } else {
        parse_uuids(values, field).map(Some)
    }
}

fn parse_organization_type(value: &str) -> Result<OrganizationType, Status> {
    value
        .parse()
        .map_err(|_| Status::invalid_argument("ORGANIZATION.INVALID_ORG_TYPE"))
}

fn parse_join_mechanism(value: &str) -> Result<JoinMechanism, Status> {
    value
        .parse()
        .map_err(|_| Status::invalid_argument("ORGANIZATION.INVALID_JOIN_MECHANISM"))
}

fn optional_text(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

fn optional_nullable_text(value: String) -> Option<Option<String>> {
    optional_text(value).map(Some)
}

fn default_value<'a>(value: &'a str, default: &'a str) -> &'a str {
    if value.trim().is_empty() {
        default
    } else {
        value
    }
}

fn application_status(error: OrganizationApplicationError) -> Status {
    match error {
        OrganizationApplicationError::NotFound(_)
        | OrganizationApplicationError::MemberNotFound(_)
        | OrganizationApplicationError::RoleNotFound(_)
        | OrganizationApplicationError::PermissionNotFound(_)
        | OrganizationApplicationError::ApiKeyNotFound(_)
        | OrganizationApplicationError::PolicySetNotFound(_) => {
            Status::not_found("ORGANIZATION.NOT_FOUND")
        }
        OrganizationApplicationError::AuthenticationRequired => {
            Status::unauthenticated("ORGANIZATION.AUTHENTICATION_REQUIRED")
        }
        OrganizationApplicationError::MembershipRequired
        | OrganizationApplicationError::MembershipInactive
        | OrganizationApplicationError::ActionNotAuthorized
        | OrganizationApplicationError::OwnerCannotBeRemoved
        | OrganizationApplicationError::OwnerRoleRequired
        | OrganizationApplicationError::SystemRoleDeleteForbidden => {
            Status::permission_denied("ORGANIZATION.ACTION_NOT_AUTHORIZED")
        }
        OrganizationApplicationError::Repository(_)
        | OrganizationApplicationError::Messaging(_)
        | OrganizationApplicationError::Event(_)
        | OrganizationApplicationError::Migration(_) => {
            Status::unavailable("ORGANIZATION.BACKEND_UNAVAILABLE")
        }
        _ => Status::invalid_argument("ORGANIZATION.INVALID_REQUEST"),
    }
}

fn authenticate_service_token<T>(
    authenticator: &ServiceTokenAuthenticator,
    request: &Request<T>,
) -> Result<(), Status> {
    let candidate = request
        .metadata()
        .get("x-service-token")
        .and_then(|value| value.to_str().ok())
        .map(str::trim);
    authenticator
        .authenticate(candidate)
        .map_err(|_| Status::unauthenticated("ORGANIZATION.GRPC_SERVICE_AUTHENTICATION_REQUIRED"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_principal_resolves_only_live_tenant_bound_scopes_without_human_privilege() {
        let now = Utc::now();
        let (key, _) = crate::ApiKey::create(
            crate::ApiKeySpec {
                organization_id: Uuid::new_v4(),
                name: "scoped service principal".into(),
                created_by: "operator".into(),
                scopes: Some(vec!["templates:read".into(), "applications:approve".into()]),
                description: None,
                expires_at: Some(now + chrono::Duration::hours(1)),
                now,
            },
            true,
        );
        let principal = format!("api_key:{}", key.id);
        let catalog = || {
            [
                "credential-template:view",
                "credential-template:edit",
                "application:approve",
                "api-key:create",
                "passport-certificate:issue",
                "audit:ingest",
            ]
            .into_iter()
            .map(str::to_owned)
        };
        let resolved =
            api_key_member_response(&key, &principal, key.organization_id, None, catalog(), now)
                .unwrap();
        assert_eq!(
            resolved.permissions,
            vec!["credential-template:view", "application:approve"]
        );
        assert!(
            resolved.roles.is_empty() && !resolved.is_owner && !resolved.has_org_console_access
        );
        let mut legacy_admin = key.clone();
        legacy_admin.scopes = vec!["admin:full".into()];
        let admin = api_key_member_response(
            &legacy_admin,
            &principal,
            key.organization_id,
            None,
            catalog(),
            now,
        )
        .unwrap();
        assert!(!admin
            .permissions
            .iter()
            .any(|p| p == "passport-certificate:issue" || p == "audit:ingest"));
        assert!(!admin.is_owner && !admin.has_org_console_access && admin.roles.is_empty());
        assert!(
            api_key_member_response(&key, &principal, Uuid::new_v4(), None, catalog(), now)
                .is_none()
        );
        assert!(api_key_member_response(
            &key,
            "api_key:other",
            key.organization_id,
            None,
            catalog(),
            now
        )
        .is_none());
        for failure in [
            "expired",
            "disabled",
            "revoked",
            "deployment_scoped",
            "unproven_deployment_binding",
        ] {
            let mut invalid = key.clone();
            match failure {
                "expired" => invalid.expires_at = Some(now - chrono::Duration::seconds(1)),
                "disabled" => invalid.enabled = false,
                "deployment_scoped" => {
                    invalid.scope_type = crate::ApiKeyScopeType::DeploymentProfile.as_str().into()
                }
                "unproven_deployment_binding" => {
                    invalid.deployment_profile_id = Some(Uuid::new_v4())
                }
                _ => invalid.revoke(now),
            }
            assert!(
                api_key_member_response(
                    &invalid,
                    &principal,
                    key.organization_id,
                    None,
                    catalog(),
                    now
                )
                .is_none(),
                "{failure}"
            );
        }
        let mut restricted = resolved.clone();
        restricted.permissions = vec!["credential-template:view".into(), "api-key:create".into()];
        restricted.is_owner = true;
        restricted.has_org_console_access = true;
        let narrowed = api_key_member_response(
            &key,
            &principal,
            key.organization_id,
            Some(restricted.clone()),
            catalog(),
            now,
        )
        .unwrap();
        assert_eq!(narrowed.permissions, vec!["credential-template:view"]);
        assert!(
            narrowed.roles.is_empty() && !narrowed.is_owner && !narrowed.has_org_console_access
        );
        for failure in ["inactive", "foreign_tenant", "foreign_principal"] {
            let mut invalid = restricted.clone();
            match failure {
                "inactive" => invalid.status = "SUSPENDED".into(),
                "foreign_tenant" => invalid.organization_id = Uuid::new_v4().to_string(),
                _ => invalid.user_id = "different-principal".into(),
            }
            assert!(
                api_key_member_response(
                    &key,
                    &principal,
                    key.organization_id,
                    Some(invalid),
                    catalog(),
                    now
                )
                .is_none(),
                "{failure}"
            );
        }
    }

    #[test]
    fn parsing_and_normalized_statuses_fail_closed() {
        assert_eq!(
            parse_uuid("not-a-uuid", "organization_id")
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            parse_organization_type("unknown").unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            application_status(OrganizationApplicationError::ActionNotAuthorized).code(),
            tonic::Code::PermissionDenied
        );
    }

    #[test]
    fn configured_service_tokens_are_required_and_compared_exactly() {
        let optional = ServiceTokenAuthenticator::new(None, false).unwrap();
        assert!(authenticate_service_token(&optional, &Request::new(())).is_ok());
        let required =
            ServiceTokenAuthenticator::new(Some("0123456789abcdef0123456789abcdef".into()), true)
                .unwrap();
        assert_eq!(
            authenticate_service_token(&required, &Request::new(()))
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        let mut valid = Request::new(());
        valid.metadata_mut().insert(
            "x-service-token",
            "0123456789abcdef0123456789abcdef".parse().unwrap(),
        );
        assert!(authenticate_service_token(&required, &valid).is_ok());
    }
}
