use std::cmp::Ordering;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    http_service::{
        application_error, authenticate_service, authorize_membership, invalid_request,
    },
    scim::{
        error_payload, group_member_remove_id, list_response, page_bounds, parse_group_filter,
        parse_user_filter, slugify_role_name, FilterValue, ScimError, GROUP_SCHEMA,
        ROLE_EXTENSION_SCHEMA, SERVICE_PROVIDER_SCHEMA, USER_EXTENSION_SCHEMA, USER_SCHEMA,
    },
    CreateScimGroupCommand, CreateScimMemberCommand, DeleteRoleCommand, Member, MemberStatus,
    OrganizationApplicationError, OrganizationHttpError, OrganizationHttpState, Role,
    UpdateScimGroupCommand, UpdateScimMemberCommand,
};

pub const SCIM_READ_HTTP_ROUTES: &[&str] = &[
    "GET /v1/organizations/{organization_id}/scim/v2/ServiceProviderConfig",
    "GET /v1/organizations/{organization_id}/scim/v2/Schemas",
    "GET /v1/organizations/{organization_id}/scim/v2/ResourceTypes",
    "GET /v1/organizations/{organization_id}/scim/v2/Users",
    "GET /v1/organizations/{organization_id}/scim/v2/Users/{member_id}",
    "GET /v1/organizations/{organization_id}/scim/v2/Groups",
    "GET /v1/organizations/{organization_id}/scim/v2/Groups/{role_id}",
];

pub const SCIM_USER_MUTATION_HTTP_ROUTES: &[&str] = &[
    "POST /v1/organizations/{organization_id}/scim/v2/Users",
    "PUT /v1/organizations/{organization_id}/scim/v2/Users/{member_id}",
    "PATCH /v1/organizations/{organization_id}/scim/v2/Users/{member_id}",
    "DELETE /v1/organizations/{organization_id}/scim/v2/Users/{member_id}",
];

pub const SCIM_GROUP_MUTATION_HTTP_ROUTES: &[&str] = &[
    "POST /v1/organizations/{organization_id}/scim/v2/Groups",
    "PUT /v1/organizations/{organization_id}/scim/v2/Groups/{role_id}",
    "PATCH /v1/organizations/{organization_id}/scim/v2/Groups/{role_id}",
    "DELETE /v1/organizations/{organization_id}/scim/v2/Groups/{role_id}",
];

pub(crate) fn organization_scim_read_router() -> Router<OrganizationHttpState> {
    Router::new()
        .route(
            "/v1/organizations/{organization_id}/scim/v2/ServiceProviderConfig",
            get(service_provider_config),
        )
        .route(
            "/v1/organizations/{organization_id}/scim/v2/Schemas",
            get(schemas),
        )
        .route(
            "/v1/organizations/{organization_id}/scim/v2/ResourceTypes",
            get(resource_types),
        )
        .route(
            "/v1/organizations/{organization_id}/scim/v2/Users",
            get(list_users).post(create_user),
        )
        .route(
            "/v1/organizations/{organization_id}/scim/v2/Users/{member_id}",
            get(get_user)
                .put(replace_user)
                .patch(patch_user)
                .delete(delete_user),
        )
        .route(
            "/v1/organizations/{organization_id}/scim/v2/Groups",
            get(list_groups).post(create_group),
        )
        .route(
            "/v1/organizations/{organization_id}/scim/v2/Groups/{role_id}",
            get(get_group)
                .put(replace_group)
                .patch(patch_group)
                .delete(delete_group),
        )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScimListQuery {
    filter: Option<String>,
    #[serde(default = "default_start_index")]
    start_index: i64,
    #[serde(default = "default_count")]
    count: i64,
    sort_by: Option<String>,
    #[serde(default = "default_sort_order")]
    sort_order: String,
}

async fn service_provider_config(
    State(state): State<OrganizationHttpState>,
    Path(_organization_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Value>, OrganizationHttpError> {
    authenticate_service(&state, &headers)?;
    Ok(Json(json!({
        "schemas": [SERVICE_PROVIDER_SCHEMA],
        "patch": {"supported": true},
        "bulk": {"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": true, "maxResults": 200},
        "changePassword": {"supported": false},
        "sort": {"supported": true},
        "etag": {"supported": true},
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "OAuth Bearer Token",
            "description": "Authentication scheme using the OAuth Bearer Token standard"
        }]
    })))
}

async fn schemas(
    State(state): State<OrganizationHttpState>,
    Path(_organization_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Value>, OrganizationHttpError> {
    authenticate_service(&state, &headers)?;
    let resources = vec![
        schema_resource(
            USER_SCHEMA,
            "User",
            "SCIM core user resource",
            json!([
                {"name":"userName","type":"string","required":true,"multiValued":false},
                {"name":"emails","type":"complex","required":false,"multiValued":true},
                {"name":"active","type":"boolean","required":false,"multiValued":false}
            ]),
        ),
        schema_resource(
            GROUP_SCHEMA,
            "Group",
            "SCIM core group resource",
            json!([
                {"name":"displayName","type":"string","required":true,"multiValued":false},
                {"name":"members","type":"complex","required":false,"multiValued":true}
            ]),
        ),
        schema_resource(
            USER_EXTENSION_SCHEMA,
            "MIPUserExtension",
            "MIP extension attributes for SCIM users",
            json!([
                {"name":"role_ids","type":"string","required":false,"multiValued":true},
                {"name":"is_owner","type":"boolean","required":false,"multiValued":false},
                {"name":"joined_at","type":"dateTime","required":false,"multiValued":false}
            ]),
        ),
        schema_resource(
            ROLE_EXTENSION_SCHEMA,
            "MIPRoleExtension",
            "MIP extension attributes for SCIM groups representing roles",
            json!([
                {"name":"permissions","type":"string","required":false,"multiValued":true},
                {"name":"is_system_role","type":"boolean","required":false,"multiValued":false},
                {"name":"description","type":"string","required":false,"multiValued":false}
            ]),
        ),
    ];
    Ok(Json(list_response(resources, 4, 1)))
}

async fn resource_types(
    State(state): State<OrganizationHttpState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Value>, OrganizationHttpError> {
    authenticate_service(&state, &headers)?;
    let base = format!("/v1/organizations/{organization_id}/scim/v2/ResourceTypes");
    let resources = vec![
        json!({
            "schemas":["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id":"User","name":"User","endpoint":"/Users","schema":USER_SCHEMA,
            "schemaExtensions":[{"schema":USER_EXTENSION_SCHEMA,"required":false}],
            "meta":{"location":format!("{base}/User"),"resourceType":"ResourceType"}
        }),
        json!({
            "schemas":["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id":"Group","name":"Group","endpoint":"/Groups","schema":GROUP_SCHEMA,
            "schemaExtensions":[{"schema":ROLE_EXTENSION_SCHEMA,"required":false}],
            "meta":{"location":format!("{base}/Group"),"resourceType":"ResourceType"}
        }),
    ];
    Ok(Json(list_response(resources, 2, 1)))
}

async fn list_users(
    State(state): State<OrganizationHttpState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Query(query): Query<ScimListQuery>,
) -> Result<Response, OrganizationHttpError> {
    authorize_membership(&state, &headers, organization_id).await?;
    validate_list_query(&query)?;
    let members = state
        .application
        .list_members(organization_id)
        .await
        .map_err(application_error)?;
    let mut projected = Vec::with_capacity(members.len());
    for member in members {
        let roles = state
            .application
            .get_member_roles(member.id)
            .await
            .map_err(application_error)?;
        if let Some(filter) = query.filter.as_deref() {
            match user_matches(&member, &roles, filter) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => return Ok(scim_filter_error(error)),
            }
        }
        projected.push((member, roles));
    }
    sort_users(&mut projected, query.sort_by.as_deref(), &query.sort_order);
    let total = projected.len();
    let (start, end, normalized) = page_bounds(total, query.start_index, query.count);
    let resources = projected[start..end]
        .iter()
        .map(|(member, roles)| scim_user(member, roles, organization_id))
        .collect();
    Ok(Json(list_response(resources, total, normalized)).into_response())
}

async fn get_user(
    State(state): State<OrganizationHttpState>,
    Path((organization_id, member_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, OrganizationHttpError> {
    authorize_membership(&state, &headers, organization_id).await?;
    let Some(member) = state
        .application
        .get_member(organization_id, member_id)
        .await
        .map_err(application_error)?
    else {
        return Ok(scim_error(StatusCode::NOT_FOUND, "User not found", ""));
    };
    let roles = state
        .application
        .get_member_roles(member.id)
        .await
        .map_err(application_error)?;
    Ok(Json(scim_user(&member, &roles, organization_id)).into_response())
}

async fn create_user(
    State(state): State<OrganizationHttpState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Response, OrganizationHttpError> {
    authorize_membership(&state, &headers, organization_id).await?;
    if extension_is_owner(&payload) {
        return Ok(scim_error(
            StatusCode::BAD_REQUEST,
            "Ownership cannot be assigned via SCIM",
            "mutability",
        ));
    }
    let Some(email) = primary_email(&payload) else {
        return Ok(scim_error(
            StatusCode::BAD_REQUEST,
            "userName is required",
            "invalidValue",
        ));
    };
    let role_ids = match extension_role_ids(&payload) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let active = payload
        .get("active")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let user_id = payload
        .get("externalId")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or(&email)
        .to_owned();
    let result = match state
        .application
        .create_scim_member(CreateScimMemberCommand {
            organization_id,
            user_id,
            email,
            active,
            role_ids,
            now: chrono::Utc::now(),
        })
        .await
    {
        Ok(result) => result,
        Err(error) => return scim_application_error(error),
    };
    let location = format!(
        "/v1/organizations/{organization_id}/scim/v2/Users/{}",
        result.value.id
    );
    let body = scim_user(&result.value, &result.value.roles, organization_id);
    Ok((
        StatusCode::CREATED,
        [
            ("content-type", "application/scim+json".to_owned()),
            ("location", location),
        ],
        Json(body),
    )
        .into_response())
}

async fn replace_user(
    State(state): State<OrganizationHttpState>,
    Path((organization_id, member_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Response, OrganizationHttpError> {
    authorize_membership(&state, &headers, organization_id).await?;
    if extension_is_owner(&payload) {
        return Ok(scim_error(
            StatusCode::BAD_REQUEST,
            "Ownership cannot be assigned via SCIM",
            "mutability",
        ));
    }
    let Some(existing) = state
        .application
        .get_member(organization_id, member_id)
        .await
        .map_err(application_error)?
    else {
        return Ok(scim_error(StatusCode::NOT_FOUND, "User not found", ""));
    };
    let Some(email) = primary_email(&payload) else {
        return Ok(scim_error(
            StatusCode::BAD_REQUEST,
            "userName is required",
            "invalidValue",
        ));
    };
    let role_ids = match extension_role_ids(&payload) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let active = payload
        .get("active")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let user_id = payload
        .get("externalId")
        .and_then(Value::as_str)
        .unwrap_or(&existing.user_id)
        .to_owned();
    update_user_response(
        &state,
        organization_id,
        member_id,
        user_id,
        email,
        active,
        role_ids,
    )
    .await
}

async fn patch_user(
    State(state): State<OrganizationHttpState>,
    Path((organization_id, member_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Response, OrganizationHttpError> {
    authorize_membership(&state, &headers, organization_id).await?;
    let Some(existing) = state
        .application
        .get_member(organization_id, member_id)
        .await
        .map_err(application_error)?
    else {
        return Ok(scim_error(StatusCode::NOT_FOUND, "User not found", ""));
    };
    let mut email = existing.email.clone().unwrap_or_default();
    let mut user_id = existing.user_id.clone();
    let mut active = existing.status == MemberStatus::Active;
    let mut role_ids = state
        .application
        .get_member_roles(member_id)
        .await
        .map_err(application_error)?
        .into_iter()
        .map(|role| role.id)
        .collect::<Vec<_>>();
    let Some(operations) = payload.get("Operations").and_then(Value::as_array) else {
        return Ok(scim_error(
            StatusCode::BAD_REQUEST,
            "Operations is required",
            "invalidSyntax",
        ));
    };
    for operation in operations {
        let op = operation
            .get("op")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        let path = operation.get("path").and_then(Value::as_str).unwrap_or("");
        let value = operation.get("value").cloned().unwrap_or(Value::Null);
        if !matches!(op.as_str(), "add" | "remove" | "replace") {
            return Ok(scim_error(
                StatusCode::BAD_REQUEST,
                &format!("Unsupported PATCH op: {op}"),
                "invalidSyntax",
            ));
        }
        match path {
            "userName" | "emails" | "emails.value" => {
                if op == "remove" {
                    return Ok(scim_error(
                        StatusCode::BAD_REQUEST,
                        "userName cannot be removed",
                        "mutability",
                    ));
                }
                let candidate = if path == "userName" {
                    primary_email(&json!({"userName": value}))
                } else {
                    primary_email(&json!({"emails": value}))
                };
                let Some(candidate) = candidate else {
                    return Ok(scim_error(
                        StatusCode::BAD_REQUEST,
                        "A valid email value is required",
                        "invalidValue",
                    ));
                };
                email = candidate;
            }
            "externalId" => {
                user_id = if op == "remove" {
                    String::new()
                } else {
                    value.as_str().unwrap_or("").to_owned()
                };
            }
            "active" => {
                active = if op == "remove" {
                    false
                } else if let Some(value) = value.as_bool() {
                    value
                } else {
                    return Ok(scim_error(
                        StatusCode::BAD_REQUEST,
                        "active must be a boolean",
                        "invalidValue",
                    ));
                };
            }
            value_path if value_path == format!("{USER_EXTENSION_SCHEMA}:role_ids") => {
                let Some(values) = value.as_array() else {
                    return Ok(scim_error(
                        StatusCode::BAD_REQUEST,
                        "role_ids must be a list",
                        "invalidValue",
                    ));
                };
                let mut values = match parse_uuid_values(values) {
                    Ok(values) => values,
                    Err(response) => return Ok(response),
                };
                match op.as_str() {
                    "replace" => role_ids = values,
                    "add" => {
                        role_ids.append(&mut values);
                        role_ids.sort_unstable();
                        role_ids.dedup();
                    }
                    "remove" => role_ids.retain(|id| !values.contains(id)),
                    _ => unreachable!(),
                }
            }
            value_path if value_path == format!("{USER_EXTENSION_SCHEMA}:is_owner") => {
                return Ok(scim_error(
                    StatusCode::BAD_REQUEST,
                    "Ownership cannot be changed via SCIM",
                    "mutability",
                ));
            }
            _ => {
                return Ok(scim_error(
                    StatusCode::BAD_REQUEST,
                    &format!("Unsupported PATCH path: {path}"),
                    "invalidPath",
                ))
            }
        }
    }
    update_user_response(
        &state,
        organization_id,
        member_id,
        user_id,
        email,
        active,
        Some(role_ids),
    )
    .await
}

async fn delete_user(
    State(state): State<OrganizationHttpState>,
    Path((organization_id, member_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, OrganizationHttpError> {
    authorize_membership(&state, &headers, organization_id).await?;
    let Some(existing) = state
        .application
        .get_member(organization_id, member_id)
        .await
        .map_err(application_error)?
    else {
        return Ok(scim_error(StatusCode::NOT_FOUND, "User not found", ""));
    };
    let result = state
        .application
        .update_scim_member(UpdateScimMemberCommand {
            organization_id,
            member_id,
            user_id: existing.user_id,
            email: existing.email.unwrap_or_default(),
            active: false,
            role_ids: Some(Vec::new()),
            now: chrono::Utc::now(),
        })
        .await;
    match result {
        Ok(_) => Ok(StatusCode::NO_CONTENT.into_response()),
        Err(error) => scim_application_error(error),
    }
}

async fn update_user_response(
    state: &OrganizationHttpState,
    organization_id: Uuid,
    member_id: Uuid,
    user_id: String,
    email: String,
    active: bool,
    role_ids: Option<Vec<Uuid>>,
) -> Result<Response, OrganizationHttpError> {
    match state
        .application
        .update_scim_member(UpdateScimMemberCommand {
            organization_id,
            member_id,
            user_id,
            email,
            active,
            role_ids,
            now: chrono::Utc::now(),
        })
        .await
    {
        Ok(result) => Ok(Json(scim_user(
            &result.value,
            &result.value.roles,
            organization_id,
        ))
        .into_response()),
        Err(error) => scim_application_error(error),
    }
}

async fn list_groups(
    State(state): State<OrganizationHttpState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Query(query): Query<ScimListQuery>,
) -> Result<Response, OrganizationHttpError> {
    authorize_membership(&state, &headers, organization_id).await?;
    validate_list_query(&query)?;
    let roles = state
        .application
        .list_roles(organization_id)
        .await
        .map_err(application_error)?;
    let mut filtered = Vec::new();
    for role in roles {
        if let Some(filter) = query.filter.as_deref() {
            match group_matches(&role, filter) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => return Ok(scim_filter_error(error)),
            }
        }
        filtered.push(role);
    }
    if query.sort_by.as_deref() == Some("displayName") {
        filtered.sort_by(|left, right| role_display(left).cmp(role_display(right)));
        if query.sort_order.eq_ignore_ascii_case("descending") {
            filtered.reverse();
        }
    }
    let total = filtered.len();
    let (start, end, normalized) = page_bounds(total, query.start_index, query.count);
    let mut resources = Vec::with_capacity(end - start);
    for role in &filtered[start..end] {
        let members = state
            .application
            .members_with_role(organization_id, role.id)
            .await
            .map_err(application_error)?;
        resources.push(scim_group(role, &members, organization_id));
    }
    Ok(Json(list_response(resources, total, normalized)).into_response())
}

async fn get_group(
    State(state): State<OrganizationHttpState>,
    Path((organization_id, role_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, OrganizationHttpError> {
    authorize_membership(&state, &headers, organization_id).await?;
    let Some(role) = state
        .application
        .get_role(organization_id, role_id)
        .await
        .map_err(application_error)?
    else {
        return Ok(scim_error(StatusCode::NOT_FOUND, "Group not found", ""));
    };
    let members = state
        .application
        .members_with_role(organization_id, role_id)
        .await
        .map_err(application_error)?;
    Ok(Json(scim_group(&role, &members, organization_id)).into_response())
}

async fn create_group(
    State(state): State<OrganizationHttpState>,
    Path(organization_id): Path<Uuid>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Response, OrganizationHttpError> {
    let context = authorize_membership(&state, &headers, organization_id).await?;
    let Some(display_name) = payload
        .get("displayName")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(scim_error(
            StatusCode::BAD_REQUEST,
            "displayName is required",
            "invalidValue",
        ));
    };
    let permission_ids = match group_permission_ids(&state, &payload).await {
        Ok(ids) => ids,
        Err(response) => return Ok(response),
    };
    let member_ids = match group_member_ids(&payload) {
        Ok(ids) => ids,
        Err(response) => return Ok(response),
    };
    let description = group_description(&payload);
    let result = match state
        .application
        .create_scim_group(CreateScimGroupCommand {
            organization_id,
            name: slugify_role_name(display_name),
            display_name: display_name.to_owned(),
            description,
            permission_ids,
            member_ids,
            created_by: context.principal_id,
            now: chrono::Utc::now(),
        })
        .await
    {
        Ok(result) => result,
        Err(error) => return scim_group_application_error(error),
    };
    let location = format!(
        "/v1/organizations/{organization_id}/scim/v2/Groups/{}",
        result.value.0.id
    );
    Ok((
        StatusCode::CREATED,
        [
            ("content-type", "application/scim+json".to_owned()),
            ("location", location),
        ],
        Json(scim_group(
            &result.value.0,
            &result.value.1,
            organization_id,
        )),
    )
        .into_response())
}

async fn replace_group(
    State(state): State<OrganizationHttpState>,
    Path((organization_id, role_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Response, OrganizationHttpError> {
    let context = authorize_membership(&state, &headers, organization_id).await?;
    let Some(display_name) = payload
        .get("displayName")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(scim_error(
            StatusCode::BAD_REQUEST,
            "displayName is required",
            "invalidValue",
        ));
    };
    let permission_ids = match group_permission_ids(&state, &payload).await {
        Ok(ids) => ids,
        Err(response) => return Ok(response),
    };
    let member_ids = match group_member_ids(&payload) {
        Ok(ids) => ids,
        Err(response) => return Ok(response),
    };
    update_group_response(
        &state,
        UpdateScimGroupCommand {
            organization_id,
            role_id,
            display_name: display_name.to_owned(),
            description: group_description(&payload),
            permission_ids,
            member_ids,
            updated_by: context.principal_id,
            now: chrono::Utc::now(),
        },
    )
    .await
}

async fn patch_group(
    State(state): State<OrganizationHttpState>,
    Path((organization_id, role_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Response, OrganizationHttpError> {
    let context = authorize_membership(&state, &headers, organization_id).await?;
    let Some(role) = state
        .application
        .get_role(organization_id, role_id)
        .await
        .map_err(application_error)?
    else {
        return Ok(scim_error(StatusCode::NOT_FOUND, "Group not found", ""));
    };
    if role.is_system {
        return Ok(scim_error(
            StatusCode::BAD_REQUEST,
            "System roles cannot be modified via SCIM",
            "mutability",
        ));
    }
    let mut display_name = role_display(&role).to_owned();
    let mut description = role.description.clone();
    let mut permission_keys = role
        .permissions
        .iter()
        .map(|permission| permission.key())
        .collect::<Vec<_>>();
    let mut member_ids = state
        .application
        .members_with_role(organization_id, role_id)
        .await
        .map_err(application_error)?
        .into_iter()
        .map(|member| member.id)
        .collect::<Vec<_>>();
    let Some(operations) = payload.get("Operations").and_then(Value::as_array) else {
        return Ok(scim_error(
            StatusCode::BAD_REQUEST,
            "Operations is required",
            "invalidSyntax",
        ));
    };
    for operation in operations {
        let op = operation
            .get("op")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        let path = operation.get("path").and_then(Value::as_str).unwrap_or("");
        let value = operation.get("value").cloned().unwrap_or(Value::Null);
        if !matches!(op.as_str(), "add" | "remove" | "replace") {
            return Ok(scim_error(
                StatusCode::BAD_REQUEST,
                &format!("Unsupported PATCH op: {op}"),
                "invalidSyntax",
            ));
        }
        if path == "members" {
            let Some(values) = value.as_array() else {
                return Ok(scim_error(
                    StatusCode::BAD_REQUEST,
                    "members must be a list",
                    "invalidValue",
                ));
            };
            let values = match member_ref_ids(values) {
                Ok(ids) => ids,
                Err(response) => return Ok(response),
            };
            match op.as_str() {
                "replace" => member_ids = values,
                "add" => {
                    member_ids.extend(values);
                    member_ids.sort_unstable();
                    member_ids.dedup();
                }
                "remove" => member_ids.retain(|id| !values.contains(id)),
                _ => unreachable!(),
            }
            continue;
        }
        if op == "remove" {
            if let Some(raw_id) = group_member_remove_id(path) {
                if let Ok(id) = raw_id.parse::<Uuid>() {
                    member_ids.retain(|candidate| *candidate != id);
                    continue;
                }
            }
        }
        if path == "displayName" {
            if op == "remove" {
                return Ok(scim_error(
                    StatusCode::BAD_REQUEST,
                    "displayName cannot be removed",
                    "mutability",
                ));
            }
            let Some(value) = value
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return Ok(scim_error(
                    StatusCode::BAD_REQUEST,
                    "displayName is required",
                    "invalidValue",
                ));
            };
            display_name = value.to_owned();
            continue;
        }
        if path == format!("{ROLE_EXTENSION_SCHEMA}:description") {
            description = if op == "remove" {
                None
            } else {
                value.as_str().map(str::to_owned)
            };
            continue;
        }
        if path == format!("{ROLE_EXTENSION_SCHEMA}:permissions") {
            let Some(values) = value.as_array() else {
                return Ok(scim_error(
                    StatusCode::BAD_REQUEST,
                    "permissions must be a list",
                    "invalidValue",
                ));
            };
            let values = values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>();
            match op.as_str() {
                "replace" => permission_keys = values,
                "add" => {
                    permission_keys.extend(values);
                    permission_keys.sort();
                    permission_keys.dedup();
                }
                "remove" => permission_keys.retain(|key| !values.contains(key)),
                _ => unreachable!(),
            }
            continue;
        }
        return Ok(scim_error(
            StatusCode::BAD_REQUEST,
            &format!("Unsupported PATCH path: {path}"),
            "invalidPath",
        ));
    }
    let permission_ids = match resolve_permission_keys(&state, &permission_keys).await {
        Ok(ids) => ids,
        Err(response) => return Ok(response),
    };
    update_group_response(
        &state,
        UpdateScimGroupCommand {
            organization_id,
            role_id,
            display_name,
            description,
            permission_ids,
            member_ids,
            updated_by: context.principal_id,
            now: chrono::Utc::now(),
        },
    )
    .await
}

async fn delete_group(
    State(state): State<OrganizationHttpState>,
    Path((organization_id, role_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, OrganizationHttpError> {
    let context = authorize_membership(&state, &headers, organization_id).await?;
    match state
        .application
        .delete_role(DeleteRoleCommand {
            role_id,
            organization_id,
            deleted_by: context.principal_id,
            replacement_role_id: None,
            now: chrono::Utc::now(),
        })
        .await
    {
        Ok(_) => Ok(StatusCode::NO_CONTENT.into_response()),
        Err(error) => scim_group_application_error(error),
    }
}

async fn update_group_response(
    state: &OrganizationHttpState,
    command: UpdateScimGroupCommand,
) -> Result<Response, OrganizationHttpError> {
    let organization_id = command.organization_id;
    match state.application.update_scim_group(command).await {
        Ok(result) => Ok(Json(scim_group(
            &result.value.0,
            &result.value.1,
            organization_id,
        ))
        .into_response()),
        Err(error) => scim_group_application_error(error),
    }
}

async fn group_permission_ids(
    state: &OrganizationHttpState,
    payload: &Value,
) -> Result<Vec<Uuid>, Response> {
    let Some(value) = payload
        .get(ROLE_EXTENSION_SCHEMA)
        .and_then(|extension| extension.get("permissions"))
    else {
        return Ok(Vec::new());
    };
    let Some(values) = value.as_array() else {
        return Err(scim_error(
            StatusCode::BAD_REQUEST,
            "permissions must be a list",
            "invalidValue",
        ));
    };
    let keys = values
        .iter()
        .map(|value| value.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| {
            scim_error(
                StatusCode::BAD_REQUEST,
                "permissions must contain strings",
                "invalidValue",
            )
        })?;
    resolve_permission_keys(state, &keys).await
}

async fn resolve_permission_keys(
    state: &OrganizationHttpState,
    keys: &[String],
) -> Result<Vec<Uuid>, Response> {
    let permissions = state
        .application
        .list_permissions()
        .await
        .map_err(|error| scim_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string(), ""))?;
    let by_key = permissions
        .into_iter()
        .map(|permission| (permission.key(), permission.id))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut ids = Vec::new();
    for key in keys {
        let Some(id) = by_key.get(key) else {
            return Err(scim_error(
                StatusCode::BAD_REQUEST,
                &format!("Unknown permissions: {key}"),
                "invalidValue",
            ));
        };
        if !ids.contains(id) {
            ids.push(*id);
        }
    }
    Ok(ids)
}

#[allow(clippy::result_large_err)]
fn group_member_ids(payload: &Value) -> Result<Vec<Uuid>, Response> {
    match payload.get("members") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) => member_ref_ids(values),
        Some(_) => Err(scim_error(
            StatusCode::BAD_REQUEST,
            "members must be a list",
            "invalidValue",
        )),
    }
}

#[allow(clippy::result_large_err)]
fn member_ref_ids(values: &[Value]) -> Result<Vec<Uuid>, Response> {
    let mut ids = Vec::new();
    for value in values {
        let raw = value.get("value").and_then(Value::as_str).ok_or_else(|| {
            scim_error(
                StatusCode::BAD_REQUEST,
                "members require value",
                "invalidValue",
            )
        })?;
        let id = raw.parse().map_err(|_| {
            scim_error(
                StatusCode::BAD_REQUEST,
                &format!("Unknown member id: {raw}"),
                "invalidValue",
            )
        })?;
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    Ok(ids)
}

fn group_description(payload: &Value) -> Option<String> {
    payload
        .get(ROLE_EXTENSION_SCHEMA)
        .and_then(|extension| extension.get("description"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn scim_group_application_error(
    error: OrganizationApplicationError,
) -> Result<Response, OrganizationHttpError> {
    match error {
        OrganizationApplicationError::RoleConflict(_) => Ok(scim_error(
            StatusCode::CONFLICT,
            "displayName already exists in this organization",
            "uniqueness",
        )),
        OrganizationApplicationError::SystemRoleDeleteForbidden => Ok(scim_error(
            StatusCode::BAD_REQUEST,
            "System roles cannot be modified via SCIM",
            "mutability",
        )),
        OrganizationApplicationError::RoleNotFound(_) => {
            Ok(scim_error(StatusCode::NOT_FOUND, "Group not found", ""))
        }
        OrganizationApplicationError::MemberNotFound(member_id) => Ok(scim_error(
            StatusCode::BAD_REQUEST,
            &format!("Unknown member id: {member_id}"),
            "invalidValue",
        )),
        OrganizationApplicationError::PermissionNotFound(permission_id) => Ok(scim_error(
            StatusCode::BAD_REQUEST,
            &format!("Unknown permission id: {permission_id}"),
            "invalidValue",
        )),
        error => Err(application_error(error)),
    }
}

fn primary_email(payload: &Value) -> Option<String> {
    if let Some(emails) = payload.get("emails").and_then(Value::as_array) {
        let selected = emails
            .iter()
            .find(|email| email.get("primary").and_then(Value::as_bool) == Some(true))
            .or_else(|| emails.first());
        if let Some(value) = selected
            .and_then(|email| email.get("value"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return Some(value.to_owned());
        }
    }
    payload
        .get("userName")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn extension_is_owner(payload: &Value) -> bool {
    payload
        .get(USER_EXTENSION_SCHEMA)
        .and_then(|extension| extension.get("is_owner"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

#[allow(clippy::result_large_err)]
fn extension_role_ids(payload: &Value) -> Result<Option<Vec<Uuid>>, Response> {
    let Some(value) = payload
        .get(USER_EXTENSION_SCHEMA)
        .and_then(|extension| extension.get("role_ids"))
    else {
        return Ok(None);
    };
    let Some(values) = value.as_array() else {
        return Err(scim_error(
            StatusCode::BAD_REQUEST,
            "role_ids must be a list",
            "invalidValue",
        ));
    };
    parse_uuid_values(values).map(Some)
}

#[allow(clippy::result_large_err)]
fn parse_uuid_values(values: &[Value]) -> Result<Vec<Uuid>, Response> {
    let mut ids = Vec::with_capacity(values.len());
    for value in values {
        let Some(raw) = value.as_str() else {
            return Err(scim_error(
                StatusCode::BAD_REQUEST,
                "role_ids must contain UUID strings",
                "invalidValue",
            ));
        };
        let Ok(id) = raw.parse() else {
            return Err(scim_error(
                StatusCode::BAD_REQUEST,
                &format!("Unknown role id: {raw}"),
                "invalidValue",
            ));
        };
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    Ok(ids)
}

fn scim_application_error(
    error: OrganizationApplicationError,
) -> Result<Response, OrganizationHttpError> {
    match error {
        OrganizationApplicationError::MemberConflict(_) => Ok(scim_error(
            StatusCode::CONFLICT,
            "userName already exists in this organization",
            "uniqueness",
        )),
        OrganizationApplicationError::OwnerCannotBeRemoved
        | OrganizationApplicationError::OwnerRoleRequired => Ok(scim_error(
            StatusCode::BAD_REQUEST,
            "Organization owner cannot be deprovisioned via SCIM",
            "mutability",
        )),
        OrganizationApplicationError::RoleNotFound(role_id) => Ok(scim_error(
            StatusCode::BAD_REQUEST,
            &format!("Unknown role id: {role_id}"),
            "invalidValue",
        )),
        OrganizationApplicationError::MemberNotFound(_) => {
            Ok(scim_error(StatusCode::NOT_FOUND, "User not found", ""))
        }
        error => Err(application_error(error)),
    }
}

fn validate_list_query(query: &ScimListQuery) -> Result<(), OrganizationHttpError> {
    if query.start_index < 1 || !(0..=200).contains(&query.count) {
        return Err(invalid_request());
    }
    Ok(())
}

fn user_matches(member: &Member, roles: &[Role], filter: &str) -> Result<bool, ScimError> {
    let parsed = parse_user_filter(filter)?;
    let expected = match parsed.value {
        FilterValue::String(value) => Value::String(value),
        FilterValue::Bool(value) => Value::Bool(value),
    };
    let actual = match parsed.attribute.as_str() {
        "userName" | "emails.value" => member
            .email
            .clone()
            .map(Value::String)
            .unwrap_or(Value::Null),
        "externalId" => Value::String(member.user_id.clone()),
        "active" => Value::Bool(member.status == MemberStatus::Active),
        value if value == format!("{USER_EXTENSION_SCHEMA}:is_owner") => {
            Value::Bool(member.is_owner() || roles.iter().any(|role| role.name == "owner"))
        }
        _ => return Err(ScimError::UnsupportedFilterAttribute(parsed.attribute)),
    };
    Ok(actual == expected)
}

fn group_matches(role: &Role, filter: &str) -> Result<bool, ScimError> {
    let parsed = parse_group_filter(filter)?;
    let FilterValue::String(expected) = parsed.value else {
        return Err(ScimError::GroupFilterRequiresString);
    };
    let actual = if parsed.attribute == "displayName" {
        role_display(role)
    } else {
        role.description.as_deref().unwrap_or("")
    };
    Ok(actual == expected)
}

fn sort_users(users: &mut [(Member, Vec<Role>)], sort_by: Option<&str>, sort_order: &str) {
    users.sort_by(|(left, _), (right, _)| match sort_by {
        Some("userName") => left.email.cmp(&right.email),
        Some("externalId") => left.user_id.cmp(&right.user_id),
        Some("active") => {
            (left.status == MemberStatus::Active).cmp(&(right.status == MemberStatus::Active))
        }
        _ => Ordering::Equal,
    });
    if sort_order.eq_ignore_ascii_case("descending") {
        users.reverse();
    }
}

fn scim_user(member: &Member, roles: &[Role], organization_id: Uuid) -> Value {
    let display = member
        .email
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            if member.user_id.is_empty() {
                ""
            } else {
                &member.user_id
            }
        });
    json!({
        "schemas":[USER_SCHEMA,USER_EXTENSION_SCHEMA],"id":member.id.to_string(),
        "externalId":member.user_id,"userName":member.email,"displayName":display,
        "emails":member.email.as_ref().map(|email| vec![json!({"value":email,"primary":true})]).unwrap_or_default(),
        "active":member.status == MemberStatus::Active,
        USER_EXTENSION_SCHEMA:{"role_ids":roles.iter().map(|role|role.id.to_string()).collect::<Vec<_>>(),"is_owner":roles.iter().any(|role|role.name=="owner"),"joined_at":member.joined_at.map(|value|value.to_rfc3339())},
        "meta":{"resourceType":"User","created":member.created_at.to_rfc3339(),"lastModified":member.updated_at.to_rfc3339(),"location":format!("/v1/organizations/{organization_id}/scim/v2/Users/{}",member.id)}
    })
}

fn scim_group(role: &Role, members: &[Member], organization_id: Uuid) -> Value {
    json!({
        "schemas":[GROUP_SCHEMA,ROLE_EXTENSION_SCHEMA],"id":role.id.to_string(),"displayName":role_display(role),
        "members":members.iter().map(|member|json!({"value":member.id.to_string(),"display":member.email.as_deref().unwrap_or(&member.user_id)})).collect::<Vec<_>>(),
        ROLE_EXTENSION_SCHEMA:{"permissions":role.permissions.iter().map(|permission|permission.key()).collect::<Vec<_>>(),"is_system_role":role.is_system,"description":role.description},
        "meta":{"resourceType":"Group","created":role.created_at.to_rfc3339(),"lastModified":role.updated_at.to_rfc3339(),"location":format!("/v1/organizations/{organization_id}/scim/v2/Groups/{}",role.id)}
    })
}

fn role_display(role: &Role) -> &str {
    role.display_name.as_deref().unwrap_or(&role.name)
}

fn schema_resource(id: &str, name: &str, description: &str, attributes: Value) -> Value {
    json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:Schema"],"id":id,"name":name,"description":description,"attributes":attributes})
}

fn scim_error(status: StatusCode, detail: &str, scim_type: &str) -> Response {
    let mut payload = error_payload(
        status.as_u16(),
        detail,
        (!scim_type.is_empty()).then_some(scim_type),
    );
    payload["status"] = Value::String(status.as_u16().to_string());
    (
        status,
        [("content-type", "application/scim+json")],
        Json(payload),
    )
        .into_response()
}

fn scim_filter_error(error: ScimError) -> Response {
    let detail = match error {
        ScimError::InvalidFilter => "Unsupported SCIM filter syntax".to_owned(),
        ScimError::GroupFilterRequiresString => "Group filters require a string value".to_owned(),
        ScimError::UnsupportedFilterAttribute(attribute) => {
            format!("Unsupported filter attribute: {attribute}")
        }
    };
    scim_error(StatusCode::BAD_REQUEST, &detail, "invalidFilter")
}

const fn default_start_index() -> i64 {
    1
}
const fn default_count() -> i64 {
    100
}
fn default_sort_order() -> String {
    "ascending".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn user_projection_uses_the_registered_extension_key() {
        let now = Utc::now();
        let member = Member::create(
            Uuid::new_v4(),
            "external-user",
            Some("user@example.com".into()),
            MemberStatus::Active,
            now,
        );
        let projected = scim_user(&member, &[], member.organization_id);
        assert!(projected.get(USER_EXTENSION_SCHEMA).is_some());
        assert!(projected.get("USER_EXTENSION_SCHEMA").is_none());
    }

    #[test]
    fn user_filters_match_email_external_id_and_active_state() {
        let now = Utc::now();
        let member = Member::create(
            Uuid::new_v4(),
            "external-user",
            Some("user@example.com".into()),
            MemberStatus::Active,
            now,
        );
        assert_eq!(
            user_matches(&member, &[], r#"userName eq "user@example.com""#),
            Ok(true)
        );
        assert_eq!(user_matches(&member, &[], "active eq false"), Ok(false));
        assert!(user_matches(&member, &[], r#"name.familyName eq "User""#).is_err());
    }

    #[test]
    fn user_payload_prefers_primary_email_and_deduplicates_role_ids() {
        let first = Uuid::new_v4();
        let payload = json!({
            "userName": "fallback@example.com",
            "emails": [
                {"value": "secondary@example.com"},
                {"value": "primary@example.com", "primary": true}
            ],
            USER_EXTENSION_SCHEMA: {"role_ids": [first.to_string(), first.to_string()]}
        });
        assert_eq!(
            primary_email(&payload).as_deref(),
            Some("primary@example.com")
        );
        assert_eq!(extension_role_ids(&payload).unwrap(), Some(vec![first]));
    }

    #[test]
    fn group_projection_preserves_members_permissions_and_extension_key() {
        let now = Utc::now();
        let organization_id = Uuid::new_v4();
        let role = Role {
            id: Uuid::new_v4(),
            organization_id,
            name: "reviewer".into(),
            display_name: Some("Reviewer".into()),
            description: Some("Reviews".into()),
            is_system: false,
            is_default_for_new_members: false,
            permissions: vec![crate::Permission::new("organization", "view")],
            created_at: now,
            updated_at: now,
        };
        let member = Member::create(
            organization_id,
            "reviewer-user",
            Some("reviewer@example.com".into()),
            MemberStatus::Active,
            now,
        );
        let projected = scim_group(&role, &[member], organization_id);
        assert_eq!(projected["displayName"], "Reviewer");
        assert_eq!(projected["members"].as_array().unwrap().len(), 1);
        assert_eq!(
            projected[ROLE_EXTENSION_SCHEMA]["permissions"][0],
            "organization:view"
        );
    }
}
