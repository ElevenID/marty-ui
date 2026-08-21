use std::sync::Arc;

use chrono::Utc;
use mmf_security::constant_time_secret_eq;
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
    service_token: Option<Arc<[u8]>>,
}

impl OrganizationGrpcService {
    #[must_use]
    pub fn new(application: Arc<OrganizationApplication>, service_token: Option<String>) -> Self {
        Self {
            application,
            service_token: service_token.map(|token| Arc::from(token.into_bytes())),
        }
    }

    fn authenticate<T>(&self, request: &Request<T>) -> Result<(), Status> {
        authenticate_service_token(self.service_token.as_deref(), request)
    }
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
        let member = self
            .application
            .get_membership(&input.user_id, organization_id)
            .await
            .map_err(application_status)?
            .ok_or_else(|| Status::not_found("ORGANIZATION.MEMBERSHIP_NOT_FOUND"))?;
        Ok(Response::new(member_response(&member)))
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
            .application
            .get_membership(&input.user_id, organization_id)
            .await
            .map_err(application_status)?
            .ok_or_else(|| Status::not_found("ORGANIZATION.MEMBERSHIP_NOT_FOUND"))?;
        Ok(Response::new(GetMemberPermissionsResponse {
            permissions: member.effective_permissions().into_iter().collect(),
            roles: member.roles.iter().map(role_summary).collect(),
            has_org_console_access: member.has_org_console_access(),
            is_owner: member.is_owner(),
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
    match value.trim().to_ascii_lowercase().as_str() {
        "enterprise" => Ok(OrganizationType::Enterprise),
        "startup" => Ok(OrganizationType::Startup),
        "individual" => Ok(OrganizationType::Individual),
        "government" => Ok(OrganizationType::Government),
        "education" => Ok(OrganizationType::Education),
        "healthcare" => Ok(OrganizationType::Healthcare),
        "financial" => Ok(OrganizationType::Financial),
        "other" => Ok(OrganizationType::Other),
        _ => Err(Status::invalid_argument("ORGANIZATION.INVALID_ORG_TYPE")),
    }
}

fn parse_join_mechanism(value: &str) -> Result<JoinMechanism, Status> {
    match value.trim().to_ascii_lowercase().as_str() {
        "open" => Ok(JoinMechanism::Open),
        "code" => Ok(JoinMechanism::Code),
        "invite" => Ok(JoinMechanism::Invite),
        "domain" => Ok(JoinMechanism::Domain),
        _ => Err(Status::invalid_argument(
            "ORGANIZATION.INVALID_JOIN_MECHANISM",
        )),
    }
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
    expected: Option<&[u8]>,
    request: &Request<T>,
) -> Result<(), Status> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let candidate = request
        .metadata()
        .get("x-service-token")
        .and_then(|value| value.to_str().ok())
        .map(str::as_bytes)
        .unwrap_or_default();
    if constant_time_secret_eq(expected, candidate) {
        Ok(())
    } else {
        Err(Status::unauthenticated(
            "ORGANIZATION.GRPC_SERVICE_AUTHENTICATION_REQUIRED",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let expected = b"0123456789abcdef0123456789abcdef";
        assert!(authenticate_service_token(None, &Request::new(())).is_ok());
        assert_eq!(
            authenticate_service_token(Some(expected), &Request::new(()))
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        let mut valid = Request::new(());
        valid.metadata_mut().insert(
            "x-service-token",
            "0123456789abcdef0123456789abcdef".parse().unwrap(),
        );
        assert!(authenticate_service_token(Some(expected), &valid).is_ok());
    }
}
