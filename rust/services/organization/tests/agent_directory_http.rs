//! HTTP boundary scenarios authored for this application, using synthetic users.
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use chrono::Utc;
use marty_organization::{
    agent_directory::AgentDirectoryService,
    agent_directory_http::{organization_agent_admin_router, AgentDirectoryHttpState},
    catalog::seed_system_roles,
    migration::migrate_organization_schema,
    postgres::PostgresOrganizationStore,
    JoinMechanism, MemberStatus, Organization, OrganizationCreate, OrganizationServiceConfig,
    OrganizationType,
};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;
use uuid::Uuid;

const TOKEN: &str = "synthetic-service-token-for-directory-tests";
const USER: &str = "22222222-2222-4222-8222-222222222222";
const ORG: &str = "11111111-1111-4111-8111-111111111111";
const AGENT: &str = "33333333-3333-4333-8333-333333333333";

fn router(store: PostgresOrganizationStore) -> Router {
    organization_agent_admin_router(
        AgentDirectoryHttpState::new(AgentDirectoryService::new(store), TOKEN.into()).unwrap(),
    )
}
fn unavailable_router() -> Router {
    router(PostgresOrganizationStore::new(
        PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:1/unused")
            .unwrap(),
    ))
}
fn request(
    method: &str,
    path: &str,
    organization: &str,
    user: &str,
    permission: &str,
    body: &str,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("x-service-token", TOKEN)
        .header("x-user-id", user)
        .header("x-organization-id", organization)
        .header("x-required-permission", permission)
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

#[test]
fn directory_candidate_configuration_is_default_off_and_requires_explicit_service_auth() {
    let base = [(
        "DATABASE_URL".into(),
        "postgresql://unused:unused@127.0.0.1:1/unused".into(),
    )];
    assert!(
        !OrganizationServiceConfig::from_values(base.clone())
            .unwrap()
            .agent_admin_enabled
    );
    let mut values = std::collections::BTreeMap::from(base);
    values.insert("MARTY_AGENT_ADMIN_ENABLED".into(), "true".into());
    assert!(OrganizationServiceConfig::from_values(values.clone()).is_err());
    values.insert("GRPC_SERVICE_TOKEN".into(), TOKEN.into());
    assert!(
        OrganizationServiceConfig::from_values(values)
            .unwrap()
            .agent_admin_enabled
    );
}

#[tokio::test]
async fn directory_http_requires_service_authenticated_human_and_exact_tenant_action_context() {
    let app = unavailable_router();
    let path = format!("/v1/organizations/{ORG}/agents");
    for mutation in [
        "no-token",
        "bad-token",
        "duplicate-token",
        "api-key",
        "empty-api-key",
        "other-tenant",
        "wrong-action",
        "duplicate-user",
    ] {
        let mut request = request("GET", &path, ORG, USER, "agent-identity:view", "");
        match mutation {
            "no-token" => {
                request.headers_mut().remove("x-service-token");
            }
            "bad-token" => {
                request
                    .headers_mut()
                    .insert("x-service-token", "forged".parse().unwrap());
            }
            "duplicate-token" => {
                request
                    .headers_mut()
                    .append("x-service-token", TOKEN.parse().unwrap());
            }
            "api-key" => {
                request
                    .headers_mut()
                    .insert("x-api-key-id", "machine".parse().unwrap());
            }
            "empty-api-key" => {
                request
                    .headers_mut()
                    .insert("x-api-key-id", "".parse().unwrap());
            }
            "other-tenant" => {
                request
                    .headers_mut()
                    .insert("x-organization-id", AGENT.parse().unwrap());
            }
            "wrong-action" => {
                request
                    .headers_mut()
                    .insert("x-required-permission", "*".parse().unwrap());
            }
            _ => {
                request
                    .headers_mut()
                    .append("x-user-id", USER.parse().unwrap());
            }
        }
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            if mutation.contains("token") {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::FORBIDDEN
            },
            "{mutation}"
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(Uuid::parse_str(response.headers()["x-request-id"].to_str().unwrap()).is_ok());
    }
}

#[tokio::test]
async fn directory_http_rejects_ambiguous_owned_fields_and_unsupported_activation_before_database_access(
) {
    let app = unavailable_router();
    let path = format!("/v1/organizations/{ORG}/agents/{AGENT}/revoke");
    for body in [
        r#"{"expected_revision":1,"expected_revision":2}"#,
        r#"{"expected_revision":1,"owner_user_id":"forged"}"#,
        r#"{"expected_revision":null}"#,
        r#"{"expected_revision":true}"#,
    ] {
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                &path,
                ORG,
                USER,
                "agent-identity:revoke",
                body,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            &path.replace("revoke", "activate"),
            ORG,
            USER,
            "agent-identity:update",
            r#"{"expected_revision":1}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let path = format!("/v1/organizations/{ORG}/agents?limit=1&limit=2");
    assert_eq!(
        app.oneshot(request("GET", &path, ORG, USER, "agent-identity:view", ""))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
#[ignore = "requires ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL pointing to disposable local PostgreSQL"]
async fn directory_http_persists_real_actor_owner_correlation_and_rechecks_revoked_membership() {
    let database = std::env::var("ORGANIZATION_AGENT_DIRECTORY_TEST_DATABASE_URL")
        .expect("explicit test database");
    let parsed = url::Url::parse(&database).unwrap();
    assert!(matches!(parsed.host_str(), Some("127.0.0.1" | "[::1]")));
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database)
        .await
        .unwrap();
    migrate_organization_schema(&pool).await.unwrap();
    let store = PostgresOrganizationStore::new(pool.clone());
    let user = Uuid::new_v4().to_string();
    let (organization, member) = Organization::create(OrganizationCreate {
        name: format!("HTTP directory {}", Uuid::new_v4()),
        owner_id: user.clone(),
        org_type: OrganizationType::Enterprise,
        display_name: None,
        description: None,
        join_mechanism: JoinMechanism::Invite,
        requires_approval: false,
        is_discoverable: false,
        now: Utc::now(),
    })
    .unwrap();
    store.save_organization(&organization).await.unwrap();
    store.save_member(&member).await.unwrap();
    let roles = seed_system_roles(&store, organization.id, Utc::now())
        .await
        .unwrap();
    store
        .set_member_roles(member.id, &[roles["owner"].id])
        .await
        .unwrap();
    let app = router(store.clone());
    let org = organization.id.to_string();
    let correlation = Uuid::new_v4();
    let keys: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../crates/principal-runtime-binding/tests/fixtures/public-keys.json"
    )))
    .unwrap();
    let body = json!({"kind":"EXTERNAL","display_name":"Synthetic HTTP worker","logical_application_ref":"urn:test:application",
        "issuer":"https://identity.example.invalid","subject":format!("worker-{}",Uuid::new_v4()),
        "runtime_instance_ref":format!("urn:test:runtime:{}",Uuid::new_v4()),"public_key_jwk":keys["keys"]["external_worker"]["jwk"]});
    let path = format!("/v1/organizations/{org}/agents");
    let mut create = request(
        "POST",
        &path,
        &org,
        &user,
        "agent-identity:create",
        &body.to_string(),
    );
    create
        .headers_mut()
        .insert("x-request-id", correlation.to_string().parse().unwrap());
    let response = app.clone().oneshot(create).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()["x-request-id"], correlation.to_string());
    let body = to_bytes(response.into_body(), 65536).await.unwrap();
    let result: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["organization_id"], org);
    assert_eq!(result["owner_user_id"], user);
    assert_eq!(result["created_by"], user);
    assert_eq!(result["authority_status"], "NOT_ASSESSED");
    let id = Uuid::parse_str(result["id"].as_str().unwrap()).unwrap();
    let (actor,stored_request):(String,Uuid)=sqlx::query_as("SELECT actor_user_id,request_id FROM organization_service.agent_identity_history WHERE organization_id=$1 AND agent_id=$2 AND revision=1")
        .bind(organization.id).bind(id).fetch_one(&pool).await.unwrap();
    assert_eq!(actor, user);
    assert_eq!(stored_request, correlation);
    let audit:Value=sqlx::query_scalar("SELECT metadata FROM organization_service.audit_events WHERE organization_id=$1 AND resource_id=$2 AND event_type='agent_identity.changed'")
        .bind(organization.id).bind(id.to_string()).fetch_one(&pool).await.unwrap();
    assert_eq!(audit["request_id"], correlation.to_string());
    let item = format!("{path}/{id}");
    assert_eq!(
        app.clone()
            .oneshot(request(
                "GET",
                &item,
                &org,
                &user,
                "agent-identity:view",
                ""
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let mut inactive = store.member_by_id(member.id).await.unwrap().unwrap();
    inactive.status = MemberStatus::Deactivated;
    store.save_member(&inactive).await.unwrap();
    assert_eq!(
        app.clone()
            .oneshot(request(
                "GET",
                &item,
                &org,
                &user,
                "agent-identity:view",
                ""
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.oneshot(request(
            "POST",
            &format!("{item}/revoke"),
            &org,
            &user,
            "agent-identity:revoke",
            r#"{"expected_revision":1}"#
        ))
        .await
        .unwrap()
        .status(),
        StatusCode::FORBIDDEN
    );
    let revision:i64=sqlx::query_scalar("SELECT revision FROM organization_service.agent_identities WHERE organization_id=$1 AND id=$2")
        .bind(organization.id).bind(id).fetch_one(&pool).await.unwrap();
    assert_eq!(revision, 1);
    pool.close().await;
}
