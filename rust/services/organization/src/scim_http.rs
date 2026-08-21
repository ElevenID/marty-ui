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
        error_payload, list_response, page_bounds, parse_group_filter, parse_user_filter,
        FilterValue, ScimError, GROUP_SCHEMA, ROLE_EXTENSION_SCHEMA, SERVICE_PROVIDER_SCHEMA,
        USER_EXTENSION_SCHEMA, USER_SCHEMA,
    },
    Member, MemberStatus, OrganizationHttpError, OrganizationHttpState, Role,
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
            get(list_users),
        )
        .route(
            "/v1/organizations/{organization_id}/scim/v2/Users/{member_id}",
            get(get_user),
        )
        .route(
            "/v1/organizations/{organization_id}/scim/v2/Groups",
            get(list_groups),
        )
        .route(
            "/v1/organizations/{organization_id}/scim/v2/Groups/{role_id}",
            get(get_group),
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
}
