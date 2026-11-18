use std::collections::{BTreeMap, BTreeSet};

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, put},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    http_service::{
        application_error, authorize_action, authorize_membership, invalid_request, not_found,
    },
    AddMemberRoleCommand, CreateRoleCommand, DeleteRoleCommand, OrganizationHttpError,
    OrganizationHttpState, Permission, RemoveMemberRoleCommand, Role, SetMemberRolesCommand,
    UpdateRoleCommand, UpdateRolePatch, APPLICANT_PERMISSION_KEYS,
};

pub const RBAC_HTTP_ROUTES: &[&str] = &[
    "GET /v1/organizations/{organization_id}/permissions",
    "GET /v1/organizations/{organization_id}/roles",
    "POST /v1/organizations/{organization_id}/roles",
    "GET /v1/organizations/{organization_id}/roles/{role_id}",
    "PATCH /v1/organizations/{organization_id}/roles/{role_id}",
    "DELETE /v1/organizations/{organization_id}/roles/{role_id}",
    "PUT /v1/organizations/{organization_id}/members/{member_id}/roles",
    "POST /v1/organizations/{organization_id}/members/{member_id}/roles/{role_id}",
    "DELETE /v1/organizations/{organization_id}/members/{member_id}/roles/{role_id}",
    "GET /v1/organizations/{organization_id}/members/me/permissions",
];

pub(crate) fn organization_rbac_router() -> Router<OrganizationHttpState> {
    Router::new()
        .route(
            "/v1/organizations/{organization_id}/permissions",
            get(list_permissions),
        )
        .route(
            "/v1/organizations/{organization_id}/roles",
            get(list_roles).post(create_role),
        )
        .route(
            "/v1/organizations/{organization_id}/roles/{role_id}",
            get(get_role).patch(update_role).delete(delete_role),
        )
        .route(
            "/v1/organizations/{organization_id}/members/{member_id}/roles",
            put(set_member_roles),
        )
        .route(
            "/v1/organizations/{organization_id}/members/{member_id}/roles/{role_id}",
            axum::routing::post(add_member_role).delete(remove_member_role),
        )
        .route(
            "/v1/organizations/{organization_id}/members/me/permissions",
            get(get_my_permissions),
        )
}

#[derive(Serialize)]
struct PermissionResponse {
    id: String,
    resource: String,
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

#[derive(Serialize)]
struct PermissionCatalogGroup {
    resource: String,
    permissions: Vec<PermissionResponse>,
}

#[derive(Serialize)]
struct RoleResponse {
    id: String,
    organization_id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    is_system_role: bool,
    is_default_for_new_members: bool,
    permissions: Vec<PermissionResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    member_count: Option<usize>,
    created_at: String,
    updated_at: String,
}

#[derive(Serialize)]
struct RoleSummaryResponse {
    id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRoleRequest {
    name: String,
    display_name: Option<String>,
    description: Option<String>,
    #[serde(default)]
    permission_ids: Vec<Uuid>,
    #[serde(default)]
    permission_keys: Vec<String>,
    #[serde(default)]
    is_default_for_new_members: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateRoleRequest {
    display_name: Option<String>,
    description: Option<String>,
    permission_ids: Option<Vec<Uuid>>,
    permission_keys: Option<Vec<String>>,
    is_default_for_new_members: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetMemberRolesRequest {
    role_ids: Vec<Uuid>,
}

#[derive(Deserialize)]
struct DeleteRoleQuery {
    replacement_role_id: Option<Uuid>,
}

#[derive(Serialize)]
struct MemberPermissionsResponse {
    permissions: Vec<String>,
    roles: Vec<RoleSummaryResponse>,
    has_org_console_access: bool,
    is_owner: bool,
}

async fn list_permissions(
    State(state): State<OrganizationHttpState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Vec<PermissionCatalogGroup>>, OrganizationHttpError> {
    authorize_action(&state, &headers, organization_id, "role:view").await?;
    let permissions = state
        .application
        .list_permissions()
        .await
        .map_err(application_error)?;
    let mut groups = BTreeMap::<String, Vec<PermissionResponse>>::new();
    for permission in permissions {
        groups
            .entry(permission.resource.clone())
            .or_default()
            .push(permission_response(&permission));
    }
    Ok(Json(
        groups
            .into_iter()
            .map(|(resource, permissions)| PermissionCatalogGroup {
                resource,
                permissions,
            })
            .collect(),
    ))
}

async fn list_roles(
    State(state): State<OrganizationHttpState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Vec<RoleResponse>>, OrganizationHttpError> {
    authorize_action(&state, &headers, organization_id, "role:view").await?;
    let roles = state
        .application
        .list_roles(organization_id)
        .await
        .map_err(application_error)?;
    let mut responses = Vec::with_capacity(roles.len());
    for role in roles {
        let member_count = state
            .application
            .count_members_with_role(organization_id, role.id)
            .await
            .map_err(application_error)?;
        responses.push(role_response(&role, Some(member_count)));
    }
    Ok(Json(responses))
}

async fn create_role(
    State(state): State<OrganizationHttpState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Json(input): Json<CreateRoleRequest>,
) -> Result<(StatusCode, Json<RoleResponse>), OrganizationHttpError> {
    let context = authorize_action(&state, &headers, organization_id, "role:create").await?;
    validate_role_text(
        &input.name,
        input.display_name.as_deref(),
        input.description.as_deref(),
    )?;
    let permission_ids = resolve_permission_ids(
        &state,
        Some(input.permission_ids),
        Some(input.permission_keys),
    )
    .await?;
    let result = state
        .application
        .create_role(CreateRoleCommand {
            organization_id,
            name: input.name,
            created_by: context.principal_id,
            display_name: input.display_name,
            description: input.description,
            permission_ids: permission_ids.unwrap_or_default(),
            is_default_for_new_members: input.is_default_for_new_members,
            now: Utc::now(),
        })
        .await
        .map_err(application_error)?;
    Ok((
        StatusCode::CREATED,
        Json(role_response(&result.value, Some(0))),
    ))
}

async fn get_role(
    State(state): State<OrganizationHttpState>,
    Path((organization_id, role_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<RoleResponse>, OrganizationHttpError> {
    authorize_action(&state, &headers, organization_id, "role:view").await?;
    let role = state
        .application
        .get_role(organization_id, role_id)
        .await
        .map_err(application_error)?
        .ok_or_else(|| not_found("ORGANIZATION.ROLE_NOT_FOUND"))?;
    let member_count = state
        .application
        .count_members_with_role(organization_id, role_id)
        .await
        .map_err(application_error)?;
    Ok(Json(role_response(&role, Some(member_count))))
}

async fn update_role(
    State(state): State<OrganizationHttpState>,
    Path((organization_id, role_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<UpdateRoleRequest>,
) -> Result<Json<RoleResponse>, OrganizationHttpError> {
    let context = authorize_action(&state, &headers, organization_id, "role:edit").await?;
    validate_update_role(&input)?;
    let permission_ids = if input.permission_ids.is_some() || input.permission_keys.is_some() {
        resolve_permission_ids(&state, input.permission_ids, input.permission_keys).await?
    } else {
        None
    };
    let result = state
        .application
        .update_role(UpdateRoleCommand {
            role_id,
            organization_id,
            updated_by: context.principal_id,
            patch: UpdateRolePatch {
                display_name: input.display_name,
                description: input.description.map(Some),
                permission_ids,
                is_default_for_new_members: input.is_default_for_new_members,
            },
            now: Utc::now(),
        })
        .await
        .map_err(application_error)?;
    let member_count = state
        .application
        .count_members_with_role(organization_id, role_id)
        .await
        .map_err(application_error)?;
    Ok(Json(role_response(&result.value, Some(member_count))))
}

async fn delete_role(
    State(state): State<OrganizationHttpState>,
    Path((organization_id, role_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<DeleteRoleQuery>,
    headers: HeaderMap,
) -> Result<StatusCode, OrganizationHttpError> {
    let context = authorize_action(&state, &headers, organization_id, "role:delete").await?;
    state
        .application
        .delete_role(DeleteRoleCommand {
            role_id,
            organization_id,
            deleted_by: context.principal_id,
            replacement_role_id: query.replacement_role_id,
            now: Utc::now(),
        })
        .await
        .map_err(application_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn set_member_roles(
    State(state): State<OrganizationHttpState>,
    Path((organization_id, member_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(input): Json<SetMemberRolesRequest>,
) -> Result<Json<Vec<RoleSummaryResponse>>, OrganizationHttpError> {
    let context = authorize_action(&state, &headers, organization_id, "role:assign").await?;
    if input.role_ids.is_empty() {
        return Err(invalid_request());
    }
    let result = state
        .application
        .set_member_roles(SetMemberRolesCommand {
            member_id,
            organization_id,
            role_ids: input.role_ids,
            updated_by: context.principal_id,
            now: Utc::now(),
        })
        .await
        .map_err(application_error)?;
    Ok(Json(result.value.roles.iter().map(role_summary).collect()))
}

async fn add_member_role(
    State(state): State<OrganizationHttpState>,
    Path((organization_id, member_id, role_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, OrganizationHttpError> {
    let context = authorize_action(&state, &headers, organization_id, "role:assign").await?;
    state
        .application
        .add_member_role(AddMemberRoleCommand {
            member_id,
            organization_id,
            role_id,
            updated_by: context.principal_id,
            now: Utc::now(),
        })
        .await
        .map_err(application_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_member_role(
    State(state): State<OrganizationHttpState>,
    Path((organization_id, member_id, role_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, OrganizationHttpError> {
    let context = authorize_action(&state, &headers, organization_id, "role:assign").await?;
    state
        .application
        .remove_member_role(RemoveMemberRoleCommand {
            member_id,
            organization_id,
            role_id,
            updated_by: context.principal_id,
            now: Utc::now(),
        })
        .await
        .map_err(application_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_my_permissions(
    State(state): State<OrganizationHttpState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<MemberPermissionsResponse>, OrganizationHttpError> {
    let context = authorize_membership(&state, &headers, organization_id).await?;
    let member_id = context
        .member_id
        .ok_or_else(|| not_found("ORGANIZATION.MEMBERSHIP_NOT_FOUND"))?;
    let permissions = state
        .application
        .get_member_permissions(member_id)
        .await
        .map_err(application_error)?;
    let roles = state
        .application
        .get_member_roles(member_id)
        .await
        .map_err(application_error)?;
    let permission_keys = permissions
        .iter()
        .map(Permission::key)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let has_org_console_access = permission_keys
        .iter()
        .any(|key| !APPLICANT_PERMISSION_KEYS.contains(&key.as_str()));
    Ok(Json(MemberPermissionsResponse {
        permissions: permission_keys,
        roles: roles.iter().map(role_summary).collect(),
        has_org_console_access,
        is_owner: context.is_owner,
    }))
}

async fn resolve_permission_ids(
    state: &OrganizationHttpState,
    permission_ids: Option<Vec<Uuid>>,
    permission_keys: Option<Vec<String>>,
) -> Result<Option<Vec<Uuid>>, OrganizationHttpError> {
    let Some(permission_keys) = permission_keys else {
        return Ok(permission_ids.map(deduplicate_ids));
    };
    let catalog = state
        .application
        .list_permissions()
        .await
        .map_err(application_error)?;
    let by_key = catalog
        .into_iter()
        .map(|permission| (permission.key(), permission.id))
        .collect::<BTreeMap<_, _>>();
    let mut resolved = permission_ids.unwrap_or_default();
    for key in permission_keys {
        resolved.push(*by_key.get(&key).ok_or_else(invalid_request)?);
    }
    Ok(Some(deduplicate_ids(resolved)))
}

fn deduplicate_ids(ids: Vec<Uuid>) -> Vec<Uuid> {
    let mut seen = BTreeSet::new();
    ids.into_iter().filter(|id| seen.insert(*id)).collect()
}

fn validate_role_text(
    name: &str,
    display_name: Option<&str>,
    description: Option<&str>,
) -> Result<(), OrganizationHttpError> {
    if name.trim().is_empty()
        || name.len() > 255
        || display_name.is_some_and(|value| value.len() > 255)
        || description.is_some_and(|value| value.len() > 2_000)
    {
        return Err(invalid_request());
    }
    Ok(())
}

fn validate_update_role(input: &UpdateRoleRequest) -> Result<(), OrganizationHttpError> {
    if input
        .display_name
        .as_deref()
        .is_some_and(|value| value.len() > 255)
        || input
            .description
            .as_deref()
            .is_some_and(|value| value.len() > 2_000)
    {
        return Err(invalid_request());
    }
    Ok(())
}

fn permission_response(permission: &Permission) -> PermissionResponse {
    PermissionResponse {
        id: permission.id.to_string(),
        resource: permission.resource.clone(),
        action: permission.action.clone(),
        description: permission.description.clone(),
    }
}

fn role_response(role: &Role, member_count: Option<usize>) -> RoleResponse {
    RoleResponse {
        id: role.id.to_string(),
        organization_id: role.organization_id.to_string(),
        name: role.name.clone(),
        display_name: role.display_name.clone(),
        description: role.description.clone(),
        is_system_role: role.is_system,
        is_default_for_new_members: role.is_default_for_new_members,
        permissions: role.permissions.iter().map(permission_response).collect(),
        member_count,
        created_at: role.created_at.to_rfc3339(),
        updated_at: role.updated_at.to_rfc3339(),
    }
}

fn role_summary(role: &Role) -> RoleSummaryResponse {
    RoleSummaryResponse {
        id: role.id.to_string(),
        name: role.name.clone(),
        display_name: role.display_name.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_id_deduplication_preserves_first_occurrence_order() {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        assert_eq!(
            deduplicate_ids(vec![first, second, first]),
            vec![first, second]
        );
    }

    #[test]
    fn role_input_bounds_fail_closed() {
        assert!(validate_role_text("", None, None).is_err());
        assert!(validate_role_text(&"x".repeat(256), None, None).is_err());
        assert!(validate_role_text("reviewer", Some(&"x".repeat(256)), None).is_err());
        assert!(validate_role_text("reviewer", None, Some(&"x".repeat(2_001))).is_err());
        assert!(validate_role_text("reviewer", Some("Reviewer"), Some("Reviews")).is_ok());
    }
}
