use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use marty_organization::postgres::PostgresOrganizationStore;
use marty_organization::{
    organization_core_router, OrganizationApplication, OrganizationCache, OrganizationHttpState,
    AUDIT_HTTP_ROUTES, CORE_ORGANIZATION_HTTP_ROUTES, MEMBERSHIP_API_HTTP_ROUTES,
    POLICY_HTTP_ROUTES, RBAC_HTTP_ROUTES, SCIM_GROUP_MUTATION_HTTP_ROUTES, SCIM_READ_HTTP_ROUTES,
    SCIM_USER_MUTATION_HTTP_ROUTES,
};
use mmf_data::MemoryCache;
use mmf_security::{CedarConfig, CedarPolicyValidator, ServiceTokenAuthenticator};
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use uuid::Uuid;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

fn router() -> axum::Router {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
        .expect("lazy PostgreSQL URL");
    let cache = OrganizationCache::new(
        Arc::new(MemoryCache::default()),
        Arc::new(MemoryCache::default()),
        Arc::new(MemoryCache::default()),
    );
    let application = OrganizationApplication::new(PostgresOrganizationStore::new(pool), cache)
        .expect("application composition");
    organization_core_router(OrganizationHttpState {
        application: Arc::new(application),
        service_authenticator: Arc::new(
            ServiceTokenAuthenticator::new(Some(TOKEN.into()), true).unwrap(),
        ),
        organization_creation_enabled: true,
        marty_organization_id: None,
    })
}

#[test]
fn implemented_routes_are_unique_members_of_the_frozen_http_surface() {
    let surface: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/organization-service-surface.json"
    )))
    .expect("surface contract");
    let frozen = surface["http_routes"]
        .as_array()
        .expect("HTTP routes")
        .iter()
        .map(|route| route.as_str().expect("route string"))
        .collect::<std::collections::BTreeSet<_>>();
    let implemented = CORE_ORGANIZATION_HTTP_ROUTES
        .iter()
        .chain(MEMBERSHIP_API_HTTP_ROUTES)
        .chain(RBAC_HTTP_ROUTES)
        .chain(SCIM_READ_HTTP_ROUTES)
        .chain(SCIM_USER_MUTATION_HTTP_ROUTES)
        .chain(SCIM_GROUP_MUTATION_HTTP_ROUTES)
        .chain(POLICY_HTTP_ROUTES)
        .chain(AUDIT_HTTP_ROUTES)
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        implemented.len(),
        CORE_ORGANIZATION_HTTP_ROUTES.len()
            + MEMBERSHIP_API_HTTP_ROUTES.len()
            + RBAC_HTTP_ROUTES.len()
            + SCIM_READ_HTTP_ROUTES.len()
            + SCIM_USER_MUTATION_HTTP_ROUTES.len()
            + SCIM_GROUP_MUTATION_HTTP_ROUTES.len()
            + POLICY_HTTP_ROUTES.len()
            + AUDIT_HTTP_ROUTES.len()
    );
    assert_eq!(implemented, frozen);
}

#[tokio::test]
async fn untrusted_requests_and_malformed_bodies_fail_before_database_access() {
    let missing = router()
        .oneshot(
            Request::builder()
                .uri("/v1/organizations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let invalid = router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/organizations")
                .header("content-type", "application/json")
                .header("x-service-token", TOKEN)
                .header("x-user-id", "user-1")
                .body(Body::from(
                    r#"{"name":"test-org","display_name":"Test","visibility":"PRIVATE","join_mechanism":"open"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

    let private = router()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/me/preferences")
                .header("content-type", "application/json")
                .header("x-service-token", TOKEN)
                .header("x-user-id", "user-1")
                .body(Body::from(r#"{"private":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(private.status(), StatusCode::BAD_REQUEST);

    let join_without_email = router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/organizations/join/code")
                .header("content-type", "application/json")
                .header("x-service-token", TOKEN)
                .header("x-user-id", "user-1")
                .body(Body::from(r#"{"code":"ABC123"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(join_without_email.status(), StatusCode::BAD_REQUEST);

    let api_key_without_trust = router()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/organizations/{}/api-keys", Uuid::nil()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(api_key_without_trust.status(), StatusCode::UNAUTHORIZED);

    let rbac_without_trust = router()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/organizations/{}/roles", Uuid::nil()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rbac_without_trust.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn onboarding_projection_preserves_the_public_behavior_without_storage() {
    let response = router()
        .oneshot(
            Request::builder()
                .uri("/api/onboarding/status")
                .header("x-service-token", TOKEN)
                .header(
                    "x-user-context",
                    r#"{"roles":["admin"],"organization_id":"org-1","organization_name":"Example"}"#,
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("bounded response body"),
    )
    .expect("JSON response");
    assert_eq!(body["needs_onboarding"], false);
    assert_eq!(body["user_type"], "administrator");
    assert_eq!(body["organization_id"], "org-1");
    assert_eq!(body["organization_name"], "Example");
}

#[tokio::test]
async fn scim_discovery_is_service_authenticated_and_storage_independent() {
    let missing = router()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/organizations/{}/scim/v2/ServiceProviderConfig",
                    Uuid::nil()
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let response = router()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/organizations/{}/scim/v2/ServiceProviderConfig",
                    Uuid::nil()
                ))
                .header("x-service-token", TOKEN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("bounded SCIM discovery response"),
    )
    .expect("SCIM discovery JSON");
    assert_eq!(body["patch"]["supported"], true);
    assert_eq!(body["filter"]["maxResults"], 200);
    assert_eq!(body["bulk"]["supported"], false);
}

#[tokio::test]
async fn core_http_round_trip_is_behaviorally_complete_when_postgres_is_configured() {
    let Some(database_url) = std::env::var("ORGANIZATION_POSTGRES_TEST_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("Organization PostgreSQL test database");
    let cache = OrganizationCache::new(
        Arc::new(MemoryCache::default()),
        Arc::new(MemoryCache::default()),
        Arc::new(MemoryCache::default()),
    );
    let policy_fixture: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/organization-policy-audit-behavior.json"
    )))
    .expect("policy behavior fixture");
    let policy_validator = Arc::new(
        CedarPolicyValidator::from_human_schema(
            policy_fixture["cedar_schema"].as_str().unwrap(),
            CedarConfig::default(),
        )
        .expect("native Cedar validator"),
    );
    let application = Arc::new(
        OrganizationApplication::new(PostgresOrganizationStore::new(pool), cache)
            .expect("application composition")
            .with_policy_validator(policy_validator),
    );
    application.initialize().await.expect("native migrations");
    let router = organization_core_router(OrganizationHttpState {
        application: application.clone(),
        service_authenticator: Arc::new(
            ServiceTokenAuthenticator::new(Some(TOKEN.into()), true).unwrap(),
        ),
        organization_creation_enabled: true,
        marty_organization_id: None,
    });
    let suffix = Uuid::new_v4().simple().to_string();
    let user_id = format!("http-owner-{}", &suffix[..8]);
    let create = request_json(
        &router,
        "POST",
        "/v1/organizations",
        Some(&user_id),
        Some(serde_json::json!({
            "name": format!("http-org-{}", &suffix[..8]),
            "display_name": "HTTP Organization",
            "org_type": "startup",
            "visibility": "PRIVATE",
            "join_mechanism": "invite"
        })),
    )
    .await;
    assert_eq!(create.0, StatusCode::OK);
    let organization_id = create.1["id"].as_str().unwrap().to_owned();
    assert_eq!(create.1["membership"]["is_owner"], true);

    let mine = request_json(
        &router,
        "GET",
        "/v1/organizations/mine",
        Some(&user_id),
        None,
    )
    .await;
    assert_eq!(mine.0, StatusCode::OK);
    assert!(mine
        .1
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value["id"] == organization_id));

    let update = request_json(
        &router,
        "PATCH",
        &format!("/v1/organizations/{organization_id}"),
        Some(&user_id),
        Some(serde_json::json!({
            "description": "Native HTTP adapter",
            "requires_approval": false,
            "visibility": "PUBLIC",
            "join_mechanism": "open"
        })),
    )
    .await;
    assert_eq!(update.0, StatusCode::OK);
    assert_eq!(update.1["description"], "Native HTTP adapter");
    assert_eq!(update.1["requires_approval"], false);

    let joined_user = format!("http-member-{}", &suffix[..8]);
    let joined = request_json_with_email(
        &router,
        "POST",
        &format!("/v1/organizations/{organization_id}/join"),
        Some(&joined_user),
        Some("member@example.com"),
        None,
    )
    .await;
    assert_eq!(joined.0, StatusCode::CREATED);
    assert_eq!(joined.1["membership"]["status"], "active");
    let joined_member_id = joined.1["membership"]["id"].as_str().unwrap().to_owned();

    let team = request_json(
        &router,
        "GET",
        &format!("/v1/organizations/{organization_id}/team/snapshot"),
        Some(&user_id),
        None,
    )
    .await;
    assert_eq!(team.0, StatusCode::OK);
    assert_eq!(team.1["members"].as_array().unwrap().len(), 2);

    let scim_users = request_json(
        &router,
        "GET",
        &format!("/v1/organizations/{organization_id}/scim/v2/Users?startIndex=1&count=200"),
        Some(&user_id),
        None,
    )
    .await;
    assert_eq!(scim_users.0, StatusCode::OK);
    assert_eq!(scim_users.1["totalResults"], 2);
    assert_eq!(scim_users.1["itemsPerPage"], 2);

    let scim_groups = request_json(
        &router,
        "GET",
        &format!("/v1/organizations/{organization_id}/scim/v2/Groups?sortBy=displayName"),
        Some(&user_id),
        None,
    )
    .await;
    assert_eq!(scim_groups.0, StatusCode::OK);
    assert!(scim_groups.1["totalResults"].as_u64().unwrap() >= 3);

    let permissions = request_json(
        &router,
        "GET",
        &format!("/v1/organizations/{organization_id}/permissions"),
        Some(&user_id),
        None,
    )
    .await;
    assert_eq!(permissions.0, StatusCode::OK);
    assert!(permissions
        .1
        .as_array()
        .unwrap()
        .iter()
        .any(|group| group["resource"] == "role"));

    let created_role = request_json(
        &router,
        "POST",
        &format!("/v1/organizations/{organization_id}/roles"),
        Some(&user_id),
        Some(serde_json::json!({
            "name": format!("http-reviewer-{}", &suffix[..8]),
            "display_name": "HTTP Reviewer",
            "permission_keys": ["organization:view"]
        })),
    )
    .await;
    assert_eq!(created_role.0, StatusCode::CREATED);
    assert_eq!(created_role.1["member_count"], 0);
    let role_id = created_role.1["id"].as_str().unwrap().to_owned();

    let scim_created = request_json(
        &router,
        "POST",
        &format!("/v1/organizations/{organization_id}/scim/v2/Users"),
        Some(&user_id),
        Some(serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "scim-user@example.com",
            "externalId": format!("scim-user-{}", &suffix[..8]),
            "active": true,
            "urn:mip:scim:schemas:extension:Organization:2.0:User": {
                "role_ids": [role_id]
            }
        })),
    )
    .await;
    assert_eq!(scim_created.0, StatusCode::CREATED);
    assert_eq!(scim_created.1["active"], true);
    let scim_member_id = scim_created.1["id"].as_str().unwrap().to_owned();

    let scim_patched = request_json(
        &router,
        "PATCH",
        &format!("/v1/organizations/{organization_id}/scim/v2/Users/{scim_member_id}"),
        Some(&user_id),
        Some(serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "externalId", "value": "scim-updated"}]
        })),
    )
    .await;
    assert_eq!(scim_patched.0, StatusCode::OK);
    assert_eq!(scim_patched.1["externalId"], "scim-updated");

    let scim_replaced = request_json(
        &router,
        "PUT",
        &format!("/v1/organizations/{organization_id}/scim/v2/Users/{scim_member_id}"),
        Some(&user_id),
        Some(serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "scim-replaced@example.com",
            "externalId": "scim-replaced",
            "active": true
        })),
    )
    .await;
    assert_eq!(scim_replaced.0, StatusCode::OK);
    assert_eq!(scim_replaced.1["userName"], "scim-replaced@example.com");

    let scim_deleted = request_json(
        &router,
        "DELETE",
        &format!("/v1/organizations/{organization_id}/scim/v2/Users/{scim_member_id}"),
        Some(&user_id),
        None,
    )
    .await;
    assert_eq!(scim_deleted.0, StatusCode::NO_CONTENT);

    let scim_deactivated = request_json(
        &router,
        "GET",
        &format!("/v1/organizations/{organization_id}/scim/v2/Users/{scim_member_id}"),
        Some(&user_id),
        None,
    )
    .await;
    assert_eq!(scim_deactivated.0, StatusCode::OK);
    assert_eq!(scim_deactivated.1["active"], false);

    let scim_group = request_json(
        &router,
        "POST",
        &format!("/v1/organizations/{organization_id}/scim/v2/Groups"),
        Some(&user_id),
        Some(serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": format!("SCIM Auditors {}", &suffix[..8]),
            "members": [{"value": joined_member_id}],
            "urn:mip:scim:schemas:extension:Organization:2.0:Role": {
                "permissions": ["organization:view"],
                "description": "SCIM managed"
            }
        })),
    )
    .await;
    assert_eq!(scim_group.0, StatusCode::CREATED);
    assert_eq!(scim_group.1["members"].as_array().unwrap().len(), 1);
    let scim_group_id = scim_group.1["id"].as_str().unwrap().to_owned();

    let scim_group_patch = request_json(
        &router,
        "PATCH",
        &format!("/v1/organizations/{organization_id}/scim/v2/Groups/{scim_group_id}"),
        Some(&user_id),
        Some(serde_json::json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": "replace", "path": "urn:mip:scim:schemas:extension:Organization:2.0:Role:description", "value": "Updated"},
                {"op": "remove", "path": "members", "value": [{"value": joined_member_id}]}
            ]
        })),
    )
    .await;
    assert_eq!(scim_group_patch.0, StatusCode::OK);
    assert_eq!(scim_group_patch.1["members"].as_array().unwrap().len(), 0);

    let scim_group_delete = request_json(
        &router,
        "DELETE",
        &format!("/v1/organizations/{organization_id}/scim/v2/Groups/{scim_group_id}"),
        Some(&user_id),
        None,
    )
    .await;
    assert_eq!(scim_group_delete.0, StatusCode::NO_CONTENT);

    let updated_role = request_json(
        &router,
        "PATCH",
        &format!("/v1/organizations/{organization_id}/roles/{role_id}"),
        Some(&user_id),
        Some(serde_json::json!({"display_name": "Updated Reviewer"})),
    )
    .await;
    assert_eq!(updated_role.0, StatusCode::OK);
    assert_eq!(updated_role.1["display_name"], "Updated Reviewer");

    let my_permissions = request_json(
        &router,
        "GET",
        &format!("/v1/organizations/{organization_id}/members/me/permissions"),
        Some(&user_id),
        None,
    )
    .await;
    assert_eq!(my_permissions.0, StatusCode::OK);
    assert_eq!(my_permissions.1["is_owner"], true);
    assert!(my_permissions.1["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|permission| permission == "role:assign"));

    let policy = request_json(
        &router,
        "POST",
        &format!("/v1/organizations/{organization_id}/policy-sets"),
        Some(&user_id),
        Some(serde_json::json!({
            "name": "HTTP approval policy",
            "policy_type": "APPROVAL_RULES",
            "cedar_policies": [{
                "policy_id": "approve_http",
                "effect": "permit",
                "cedar_text": "permit(principal, action == MIP::Action::\"applications:approve\", resource);",
                "enabled": true
            }]
        })),
    )
    .await;
    assert_eq!(policy.0, StatusCode::CREATED);
    let policy_id = policy.1["id"].as_str().unwrap().to_owned();

    let archived_policy = request_json(
        &router,
        "POST",
        &format!("/v1/organizations/{organization_id}/policy-sets/{policy_id}/archive"),
        Some(&user_id),
        None,
    )
    .await;
    assert_eq!(archived_policy.0, StatusCode::OK);
    assert_eq!(archived_policy.1["status"], "ARCHIVED");

    let active_policy = request_json(
        &router,
        "POST",
        &format!("/v1/organizations/{organization_id}/policy-sets/{policy_id}/activate"),
        Some(&user_id),
        None,
    )
    .await;
    assert_eq!(active_policy.0, StatusCode::OK);
    assert_eq!(active_policy.1["status"], "ACTIVE");

    let audit = request_json(
        &router,
        "GET",
        &format!("/v1/organizations/audit/events?organization_id={organization_id}&limit=1000"),
        Some(&user_id),
        None,
    )
    .await;
    assert_eq!(audit.0, StatusCode::OK);
    assert!(audit.1["total"].as_u64().unwrap() > 0);

    let audit_export = request_json(
        &router,
        "GET",
        &format!(
            "/v1/organizations/audit/events/export?organization_id={organization_id}&format=json"
        ),
        Some(&user_id),
        None,
    )
    .await;
    assert_eq!(audit_export.0, StatusCode::OK);
    assert_eq!(audit_export.1["format"], "json");

    let deleted_policy = request_json(
        &router,
        "DELETE",
        &format!("/v1/organizations/{organization_id}/policy-sets/{policy_id}"),
        Some(&user_id),
        None,
    )
    .await;
    assert_eq!(deleted_policy.0, StatusCode::NO_CONTENT);

    let created_key = request_json(
        &router,
        "POST",
        &format!("/v1/organizations/{organization_id}/api-keys"),
        Some(&user_id),
        Some(serde_json::json!({
            "name": "HTTP acceptance",
            "scopes": ["flows:execute"],
            "expires_at": null,
            "is_test": true
        })),
    )
    .await;
    assert_eq!(created_key.0, StatusCode::OK);
    assert!(created_key.1["key"]
        .as_str()
        .unwrap()
        .starts_with("mk_test_"));
    let key_id = created_key.1["id"].as_str().unwrap().to_owned();

    let listed_keys = request_json(
        &router,
        "GET",
        &format!("/v1/organizations/{organization_id}/api-keys"),
        Some(&user_id),
        None,
    )
    .await;
    assert_eq!(listed_keys.0, StatusCode::OK);
    assert!(listed_keys
        .1
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value["id"] == key_id && value.get("key").is_none()));

    let revoked = request_json(
        &router,
        "DELETE",
        &format!("/v1/organizations/{organization_id}/api-keys/{key_id}"),
        Some(&user_id),
        None,
    )
    .await;
    assert_eq!(revoked.0, StatusCode::OK);
    assert_eq!(revoked.1["success"], true);

    let removed = request_json(
        &router,
        "DELETE",
        &format!("/v1/organizations/{organization_id}/members/{joined_member_id}"),
        Some(&user_id),
        None,
    )
    .await;
    assert_eq!(removed.0, StatusCode::OK);
    assert_eq!(removed.1["success"], true);

    let deleted_role = request_json(
        &router,
        "DELETE",
        &format!("/v1/organizations/{organization_id}/roles/{role_id}"),
        Some(&user_id),
        None,
    )
    .await;
    assert_eq!(deleted_role.0, StatusCode::NO_CONTENT);
    assert_eq!(deleted_role.1, Value::Null);

    let preferences = request_json(
        &router,
        "PUT",
        "/v1/me/preferences",
        Some(&user_id),
        Some(serde_json::json!({
            "last_view_mode": "org_admin",
            "last_active_org_id": organization_id
        })),
    )
    .await;
    assert_eq!(preferences.0, StatusCode::OK);
    assert_eq!(preferences.1["last_view_mode"], "org_admin");

    let settings = request_json(
        &router,
        "PATCH",
        &format!("/internal/v1/organizations/{organization_id}/settings"),
        None,
        Some(serde_json::json!({
            "settings_patch": {"pilot_retention_enabled": true, "pilot_retention_days": 30}
        })),
    )
    .await;
    assert_eq!(settings.0, StatusCode::OK);
    let lifecycle = request_json(
        &router,
        "GET",
        &format!("/internal/v1/organizations/{organization_id}/lifecycle"),
        None,
        None,
    )
    .await;
    assert_eq!(lifecycle.0, StatusCode::OK);
    assert_eq!(
        lifecycle.1["data_retention_mode"],
        "hosted_pilot_rolling_purge"
    );

    application
        .store()
        .delete_organization(organization_id.parse().unwrap())
        .await
        .expect("cleanup Organization HTTP fixture");
}

async fn request_json(
    router: &axum::Router,
    method: &str,
    uri: &str,
    user_id: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    request_json_with_email(router, method, uri, user_id, None, body).await
}

async fn request_json_with_email(
    router: &axum::Router,
    method: &str,
    uri: &str,
    user_id: Option<&str>,
    user_email: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-service-token", TOKEN);
    if let Some(user_id) = user_id {
        request = request.header("x-user-id", user_id);
    }
    if let Some(user_email) = user_email {
        request = request.header("x-user-email", user_email);
    }
    let body = if let Some(value) = body {
        request = request.header("content-type", "application/json");
        Body::from(serde_json::to_vec(&value).unwrap())
    } else {
        Body::empty()
    };
    let response = router
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("bounded response");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("JSON response")
    };
    (status, value)
}
