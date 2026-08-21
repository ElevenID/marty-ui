use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use marty_auth::{
    attribute_strings, merge_oidc_user_info, normalize_keycloak_admin_url,
    normalize_keycloak_organization_claim, ExchangedTokenValidator, KeycloakAdminAdapter,
    KeycloakAdminConfig, KeycloakAdminTransport, KeycloakHttpRequest, KeycloakHttpResponse,
    KeycloakUserCreate, OidcUserInfo, OidcValidatedIdentity, PortError,
};
use serde_json::{json, Map, Value};

#[derive(Default)]
struct FakeTransport {
    responses: Mutex<VecDeque<Result<KeycloakHttpResponse, PortError>>>,
    requests: Mutex<Vec<KeycloakHttpRequest>>,
}

#[async_trait]
impl KeycloakAdminTransport for FakeTransport {
    async fn execute(
        &self,
        request: KeycloakHttpRequest,
    ) -> Result<KeycloakHttpResponse, PortError> {
        self.requests.lock().expect("requests lock").push(request);
        self.responses
            .lock()
            .expect("responses lock")
            .pop_front()
            .expect("queued response")
    }
}

struct FakeValidator;

#[async_trait]
impl ExchangedTokenValidator for FakeValidator {
    async fn validate_exchanged_identity(
        &self,
        tokens: &Value,
        _expected_audience: &str,
    ) -> Result<Option<OidcValidatedIdentity>, PortError> {
        if tokens.get("id_token").and_then(Value::as_str).is_none() {
            return Ok(None);
        }
        let claims = json!({"sub": "user-1", "email": "alice@example.com"});
        Ok(Some(OidcValidatedIdentity {
            user_info: OidcUserInfo::from_claims(&claims, None),
            id_token_claims: claims,
            access_token_claims: json!({}),
        }))
    }
}

fn config(token_exchange_enabled: bool) -> KeycloakAdminConfig {
    KeycloakAdminConfig {
        admin_url: "http://keycloak:8080".to_owned(),
        realm: "marty".to_owned(),
        client_id: "marty-api".to_owned(),
        client_secret: "secret".to_owned(),
        timeout_seconds: 8,
        token_exchange_enabled,
    }
}

fn response(status: u16, body: Value) -> Result<KeycloakHttpResponse, PortError> {
    Ok(KeycloakHttpResponse {
        status,
        body,
        location: None,
    })
}

fn service_token() -> Result<KeycloakHttpResponse, PortError> {
    response(200, json!({"access_token": "service-token"}))
}

fn adapter(
    responses: impl IntoIterator<Item = Result<KeycloakHttpResponse, PortError>>,
    token_exchange_enabled: bool,
) -> (KeycloakAdminAdapter, Arc<FakeTransport>) {
    let transport = Arc::new(FakeTransport::default());
    transport
        .responses
        .lock()
        .expect("responses lock")
        .extend(responses);
    let adapter = KeycloakAdminAdapter::new(
        config(token_exchange_enabled),
        transport.clone(),
        Arc::new(FakeValidator),
    )
    .expect("adapter");
    (adapter, transport)
}

#[test]
fn configuration_attribute_and_organization_normalization_preserve_behavior() {
    assert_eq!(
        normalize_keycloak_admin_url("http://localhost:8180/admin/").expect("normalize"),
        "http://keycloak:8080"
    );
    let attributes: Map<String, Value> = serde_json::from_value(json!({
        "roles": ["vendor, reviewer", "[\"admin\", \"reviewer\"]"],
        "user_type": "applicant"
    }))
    .expect("attributes");
    assert_eq!(
        attribute_strings(&attributes, &["roles", "user_type"]),
        ["vendor", "reviewer", "admin", "applicant"]
    );
    assert_eq!(
        normalize_keycloak_organization_claim(&json!([
            {"id": "org-1", "name": "Acme"},
            "org-2"
        ])),
        Some(json!({
            "org-1": {"name": "Acme", "display_name": "Acme"},
            "org-2": {"name": "org-2", "display_name": "org-2"}
        }))
    );
}

#[tokio::test]
async fn existing_user_lookup_distinguishes_absence_from_invalid_profile() {
    let (verified, _) = adapter(
        [
            service_token(),
            response(
                200,
                json!([{
                    "id": "user-1",
                    "email": "alice@example.com",
                    "enabled": true,
                    "emailVerified": true
                }]),
            ),
        ],
        false,
    );
    assert_eq!(
        verified
            .get_existing_verified_user_id("Alice@Example.com", None)
            .await
            .expect("verified lookup"),
        Some("user-1".to_owned())
    );

    let (disabled, _) = adapter(
        [
            service_token(),
            response(
                200,
                json!([{
                    "id": "user-2",
                    "email": "alice@example.com",
                    "enabled": false,
                    "emailVerified": true
                }]),
            ),
        ],
        false,
    );
    let error = disabled
        .get_existing_verified_user_id("alice@example.com", None)
        .await
        .expect_err("disabled user must fail");
    assert_eq!(error.code, "keycloak_user_disabled");
}

#[tokio::test]
async fn get_or_create_returns_location_user_id_and_preserves_payload() {
    let created = KeycloakHttpResponse {
        status: 201,
        body: Value::Null,
        location: Some("http://keycloak:8080/admin/realms/marty/users/new-user".to_owned()),
    };
    let (adapter, transport) = adapter(
        [
            service_token(),
            response(200, json!([])),
            Ok(created.clone()),
        ],
        false,
    );
    let user_id = adapter
        .get_or_create_user(&KeycloakUserCreate {
            email: "alice@example.com".to_owned(),
            given_name: Some("Alice".to_owned()),
            family_name: Some("Smith".to_owned()),
            role: "applicant".to_owned(),
            username: None,
        })
        .await
        .expect("create user");
    assert_eq!(user_id.as_deref(), Some("new-user"));
    let requests = transport.requests.lock().expect("requests lock");
    assert_eq!(
        requests[2].json.as_ref().expect("create payload")["firstName"],
        "Alice"
    );
}

#[tokio::test]
async fn admin_enrichment_merges_attribute_realm_client_and_organization_context() {
    let (adapter, _) = adapter(
        [
            service_token(),
            response(
                200,
                json!({
                    "id": "user-1",
                    "email": "alice@example.com",
                    "emailVerified": true,
                    "username": "alice",
                    "attributes": {"roles": ["vendor"]}
                }),
            ),
            response(
                200,
                json!({
                    "realmMappings": [{"name": "reviewer"}],
                    "clientMappings": {"marty-ui": {"mappings": [{"name": "manage-users"}]}}
                }),
            ),
            response(200, json!([{"id": "org-1", "name": "Acme"}])),
        ],
        false,
    );
    let user = adapter.get_user_info("user-1").await.expect("user info");
    assert_eq!(user.roles, ["vendor", "reviewer", "manage-users"]);
    assert_eq!(user.organization_id.as_deref(), Some("org-1"));
    assert_eq!(user.organization_name.as_deref(), Some("Acme"));
}

#[tokio::test]
async fn token_exchange_is_disabled_softly_but_validated_when_enabled() {
    let (disabled, transport) = adapter([], false);
    assert!(disabled
        .exchange_token_for_user("user-1", "marty-ui")
        .await
        .expect("disabled exchange")
        .is_none());
    assert!(transport.requests.lock().expect("requests lock").is_empty());

    let (enabled, _) = adapter(
        [
            service_token(),
            response(
                200,
                json!({
                    "id_token": "id-token",
                    "access_token": "access-token",
                    "refresh_token": "refresh-token"
                }),
            ),
        ],
        true,
    );
    let exchange = enabled
        .exchange_token_for_user("user-1", "marty-ui")
        .await
        .expect("enabled exchange")
        .expect("exchange result");
    assert_eq!(exchange.id_token.as_deref(), Some("id-token"));
    assert_eq!(exchange.identity.id_token_claims["sub"], "user-1");
}

#[test]
fn primary_oidc_context_wins_while_roles_are_union_preserving_order() {
    let primary = OidcUserInfo::from_claims(
        &json!({
            "sub": "primary",
            "email": "primary@example.com",
            "roles": ["admin"]
        }),
        None,
    );
    let secondary = OidcUserInfo::from_claims(
        &json!({
            "sub": "secondary",
            "email": "secondary@example.com",
            "roles": ["vendor", "admin"]
        }),
        None,
    );
    let merged = merge_oidc_user_info(Some(&primary), Some(&secondary)).expect("merged user");
    assert_eq!(merged.sub, "primary");
    assert_eq!(merged.email, "primary@example.com");
    assert_eq!(merged.roles, ["admin", "vendor"]);
}
