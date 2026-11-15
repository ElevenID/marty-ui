use super::*;

#[test]
fn duplicate_config_preconditions_are_rejected_before_header_projection() {
    let mut headers = axum::http::HeaderMap::new();
    headers.append(header::IF_MATCH, "\"r-legacy\"".parse().unwrap());
    assert!(!ambiguous_config_precondition(
        &axum::http::Method::PATCH,
        "/v1/signing-keys/config",
        &headers
    ));
    headers.append(header::IF_MATCH, "\"r-other\"".parse().unwrap());
    assert!(ambiguous_config_precondition(
        &axum::http::Method::PATCH,
        "/v1/signing-keys/config",
        &headers
    ));
    assert!(!ambiguous_config_precondition(
        &axum::http::Method::GET,
        "/v1/signing-keys/config",
        &headers
    ));
    for method in [axum::http::Method::POST, axum::http::Method::PATCH] {
        assert!(ambiguous_config_precondition(
            &method,
            "/v1/signing-keys/issuer-identities",
            &headers
        ));
    }
}

#[tokio::test]
async fn object_admission_keeps_body_limit_and_json_object_errors_distinct() {
    let request = |body: &'static str| Request::new(Body::from(body));
    assert_eq!(
        request_json_object(request("{}"), 2).await.unwrap(),
        json!({})
    );
    for invalid in ["[]", "null", "{broken"] {
        let response = request_json_object(request(invalid), 32).await.unwrap_err();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"detail":"Request body must be a JSON object."})
        );
    }
    assert_eq!(
        request_json_object(request("{}"), 1)
            .await
            .unwrap_err()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}
include!("../tests/support/template_issuer_options_behavior.rs");
include!("../tests/support/organization_defaults_behavior.rs");
include!("../tests/support/ob3_client_contract_behavior.rs");
use std::{
    collections::BTreeSet,
    sync::atomic::{AtomicBool, Ordering},
};

use mmf_platform::{
    GatewayResponse, InMemoryIdempotencyStore, PlatformError, ProxyConfig, ServiceInstance,
    UpstreamClient,
};
use mmf_security::InMemoryRateLimiter;
use tower::ServiceExt;

#[test]
fn upstream_response_appends_both_auth_cookies() {
    let response = upstream_response(GatewayResponse {
        status_code: 302,
        headers: BTreeMap::from([("location".into(), "/console".into())]),
        set_cookies: vec![
            "sessionId=synthetic; Path=/; Secure".into(),
            "marty_impersonation_handoff=; Max-Age=0; Path=/; Secure".into(),
        ],
        body: None,
        response_time_ms: None,
        upstream_service: Some("auth".into()),
    });
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(cookies.len(), 2);
    assert!(cookies[0].starts_with("sessionId="));
    assert!(cookies[1].starts_with("marty_impersonation_handoff="));
}

use crate::{
    contract::GatewayContract,
    middleware::{ApiKeyIdentity, SessionIdentity},
    providers::HttpGatewayProvider,
    registry::StaticServiceRegistry,
};

// Exercise Gateway's authorization and forwarding contract without a
// plaintext KMS endpoint. Transit mint/verify has connected OpenBao tests.
use marty_signing_grant_test_support::ContractGrantMinter;

#[test]
fn gateway_originated_management_uses_the_selected_native_owner() {
    assert_eq!(
        internal_issuance_proxy_path(HttpMethod::Put, "/v1/issuance/oid4vci-clients"),
        "/__gateway/issuance-native/v1/issuance/oid4vci-clients"
    );
    assert_eq!(
        internal_issuance_proxy_path(HttpMethod::Post, "/v1/issuance/oid4vci-clients"),
        "/__gateway/issuance/v1/issuance/oid4vci-clients"
    );
}

struct ScriptedOwner(Option<String>);

#[async_trait]
impl ResourceOwnerProvider for ScriptedOwner {
    async fn resolve_organization(
        &self,
        _: &str,
        _: &str,
        _: &ResourceOwnerContext,
    ) -> Result<Option<String>, SecurityError> {
        Ok(self.0.clone())
    }
}

struct ScriptedMembership(&'static str);

#[async_trait]
impl OrganizationMembershipProvider for ScriptedMembership {
    async fn get_membership(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<Option<OrganizationMembership>, SecurityError> {
        match self.0 {
            "allowed" => Ok(Some(OrganizationMembership {
                user_id: user_id.into(),
                organization_id: organization_id.into(),
                status: "active".into(),
                role_names: BTreeSet::from(["key-manager".into()]),
                permissions: BTreeSet::from(["signing-key:view".into()]),
                is_owner: false,
            })),
            "inactive" => Ok(Some(OrganizationMembership {
                user_id: user_id.into(),
                organization_id: organization_id.into(),
                status: "inactive".into(),
                role_names: BTreeSet::new(),
                permissions: BTreeSet::new(),
                is_owner: false,
            })),
            "error" => Err(SecurityError::ProviderUnavailable("fixture".into())),
            _ => Ok(None),
        }
    }
}

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    organization_resolution: Vec<ResolutionCase>,
    authorization: Vec<AuthorizationCase>,
}

#[derive(Deserialize)]
struct ResolutionCase {
    path: String,
    owner: Option<String>,
    query: Option<String>,
    body: Option<String>,
    state: Option<String>,
    expected: Option<String>,
}

#[derive(Deserialize)]
struct AuthorizationCase {
    method: String,
    path: String,
    identity: String,
    organization: Option<String>,
    membership: String,
    outcome: String,
    status: Option<u16>,
}

fn contract() -> Contract {
    serde_json::from_str(include_str!(
        "../../../../contracts/gateway-runtime-authorization.json"
    ))
    .expect("valid runtime authorization contract")
}

fn identity(kind: &str) -> Option<GatewayIdentity> {
    let (source, organization, scopes) = match kind {
        "session" => (AuthenticationSource::Session, Some("org-1"), vec![]),
        "api_key_wrong_org" => (
            AuthenticationSource::ApiKey,
            Some("org-other"),
            vec!["keys:read".into()],
        ),
        "api_key_read" => (
            AuthenticationSource::ApiKey,
            Some("org-1"),
            vec!["keys:read".into()],
        ),
        _ => return None,
    };
    let is_api_key = source == AuthenticationSource::ApiKey;
    Some(GatewayIdentity {
        source,
        user_id: if kind == "session" {
            "user-1".into()
        } else {
            "api_key:key-1".into()
        },
        authentication_time_unix: None,
        user_email: None,
        user_domain: None,
        session_organization_id: organization.map(str::to_owned),
        api_key_id: is_api_key.then(|| "key-1".into()),
        api_key_prefix: None,
        api_key_scopes: scopes,
    })
}

#[tokio::test]
async fn language_neutral_runtime_authorization_contract() {
    let contract = contract();
    assert_eq!(contract.schema_version, 1);
    for case in contract.organization_resolution {
        let resolved = resolve_organization(
            &OrganizationResolutionInput {
                method: "GET".into(),
                path: case.path,
                query_organization_id: case.query,
                body_organization_id: case.body,
                authenticated_organization_id: case.state,
                owner_context: ResourceOwnerContext::default(),
            },
            &ScriptedOwner(case.owner),
        )
        .await
        .expect("organization resolution");
        assert_eq!(
            resolved
                .as_ref()
                .map(|value| value.organization_id.as_str()),
            case.expected.as_deref()
        );
    }
    for case in contract.authorization {
        let identity = identity(&case.identity);
        let outcome = authorize_tenant_request(
            &case.method,
            &case.path,
            case.organization.as_deref(),
            identity.as_ref(),
            &ScriptedMembership(Box::leak(case.membership.into_boxed_str())),
        )
        .await;
        let (name, status) = match outcome {
            TenantAuthorizationOutcome::Bypass => ("bypass", None),
            TenantAuthorizationOutcome::Authorized(_) => ("authorized", None),
            TenantAuthorizationOutcome::Denied(error) => ("denied", Some(error.status)),
        };
        assert_eq!(name, case.outcome);
        assert_eq!(status, case.status);
    }
}

#[test]
fn body_tenant_is_only_read_for_mutating_json_requests() {
    let body = br#"{"organization_id":" org-1 "}"#;
    assert_eq!(body_organization_id("POST", body).as_deref(), Some("org-1"));
    assert_eq!(body_organization_id("GET", body), None);
    assert_eq!(body_organization_id("PATCH", b"not-json"), None);
}

struct RuntimeProvider;

#[async_trait]
impl GatewayIdentityProvider for RuntimeProvider {
    async fn validate_session(
        &self,
        session_id: &str,
    ) -> Result<Option<SessionIdentity>, SecurityError> {
        let organization_id = match session_id {
            "valid" => Some("org-1"),
            "valid-org-2" => Some("org-2"),
            "valid-uuid" => Some("11111111-1111-1111-1111-111111111111"),
            "valid-no-org" => None,
            _ => return Ok(None),
        };
        Ok(Some(SessionIdentity {
            user_id: "user-1".into(),
            organization_id: organization_id.map(str::to_owned),
            ..SessionIdentity::default()
        }))
    }

    async fn validate_api_key(&self, key: &str) -> Result<Option<ApiKeyIdentity>, SecurityError> {
        Ok(match key {
            "verification-complete"
            | "verification-alternative"
            | "verification-admin"
            | "verification-credentials-only"
            | "verification-trust-only"
            | "verification-other" => Some(ApiKeyIdentity {
                // Same principal exercises changed live scopes before cache replay.
                api_key_id: "verification-key-1".into(),
                organization_id: Some(
                    if key == "verification-other" {
                        "org-other"
                    } else {
                        "org-1"
                    }
                    .into(),
                ),
                key_prefix: None,
                scopes: match key {
                    "verification-alternative" => {
                        vec!["flows:execute".into(), "trust:write".into()]
                    }
                    "verification-admin" => vec!["admin:full".into()],
                    "verification-credentials-only" => vec!["credentials:read".into()],
                    "verification-trust-only" => vec!["trust:read".into()],
                    _ => vec!["credentials:read".into(), "trust:read".into()],
                },
            }),
            "trust-writer" | "trust-reader" | "trust-other" => Some(ApiKeyIdentity {
                api_key_id: "trust-key-1".into(),
                organization_id: Some(
                    if key == "trust-other" {
                        "org-other"
                    } else {
                        "org-1"
                    }
                    .into(),
                ),
                key_prefix: None,
                scopes: vec![if key == "trust-reader" {
                    "trust:read"
                } else {
                    "trust:write"
                }
                .into()],
            }),
            "passport-gateway-key-org-1"
            | "passport-gateway-key-org-2"
            | "passport-gateway-read-only-org-1"
            | "passport-gateway-cancel-org-1" => Some(ApiKeyIdentity {
                api_key_id: "gateway-test-key".into(),
                organization_id: Some(
                    if key.ends_with("org-1") {
                        "org-1"
                    } else {
                        "org-2"
                    }
                    .into(),
                ),
                key_prefix: None,
                scopes: if key == "passport-gateway-read-only-org-1" {
                    vec!["credentials:read".into()]
                } else if key == "passport-gateway-cancel-org-1" {
                    vec!["credentials:read".into(), "credentials:revoke".into()]
                } else {
                    vec!["credentials:read".into(), "credentials:issue".into()]
                },
            }),
            _ => None,
        })
    }
}

#[async_trait]
impl OrganizationMembershipProvider for RuntimeProvider {
    async fn get_membership(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<Option<OrganizationMembership>, SecurityError> {
        if organization_id == "org-other" {
            return Ok(None);
        }
        Ok(Some(OrganizationMembership {
            user_id: user_id.into(),
            organization_id: organization_id.into(),
            status: "active".into(),
            role_names: BTreeSet::from(["key-manager".into()]),
            permissions: BTreeSet::from([
                "signing-key:view".into(),
                "signing-key:create".into(),
                "verification:execute".into(),
                "issuance:initiate".into(),
                "issuance:view".into(),
                "application:review".into(),
                "integration-connector:view".into(),
                "role:view".into(),
                "credential-template:edit".into(),
                "credential-template:create".into(),
                "trusted-issuer:view".into(),
                "trusted-issuer:create".into(),
                "trusted-issuer:edit".into(),
                "trust-profile:view".into(),
                "trust-profile:create".into(),
                "trust-profile:edit".into(),
                "presentation-policy:view".into(),
                "presentation-policy:create".into(),
                "presentation-policy:edit".into(),
                "flow-definition:view".into(),
                "flow-definition:create".into(),
                "flow-definition:edit".into(),
                "flow-instance:view".into(),
                "flow-instance:start".into(),
                "deployment-profile:view".into(),
                "deployment-profile:create".into(),
                "deployment-profile:edit".into(),
                "api-key:view".into(),
                "api-key:create".into(),
                "api-key:revoke".into(),
                "organization:view".into(),
                "audit:view".into(),
                "policy-set:view".into(),
                "notification:view".into(),
            ]),
            is_owner: false,
        }))
    }
}

struct NoOwner;

#[async_trait]
impl ResourceOwnerProvider for NoOwner {
    async fn resolve_organization(
        &self,
        _: &str,
        path: &str,
        _: &ResourceOwnerContext,
    ) -> Result<Option<String>, SecurityError> {
        Ok((path.starts_with("/v1/presentation-policies/")
            || path.starts_with("/v1/credential-templates/"))
        .then(|| "org-1".into()))
    }
}

struct UnavailableOwner;

#[async_trait]
impl ResourceOwnerProvider for UnavailableOwner {
    async fn resolve_organization(
        &self,
        _: &str,
        _: &str,
        _: &ResourceOwnerContext,
    ) -> Result<Option<String>, SecurityError> {
        Err(SecurityError::ProviderUnavailable(
            "owner lookup must not run for wallet-public routes".into(),
        ))
    }
}

#[async_trait]
impl ReadinessProvider for NoOwner {
    async fn check_services(
        &self,
        services: &[String],
    ) -> BTreeMap<String, ReadinessServiceStatus> {
        services
            .iter()
            .map(|service| {
                (
                    service.clone(),
                    ReadinessServiceStatus {
                        status: "healthy".into(),
                        url: Some(format!("http://{service}")),
                        status_code: Some(200),
                        error: None,
                    },
                )
            })
            .collect()
    }

    fn all_services(&self) -> Vec<String> {
        vec!["auth".into()]
    }
}

#[async_trait]
impl EventStreamProvider for NoOwner {
    async fn subscribe(
        &self,
        subscription: EventStreamSubscription,
    ) -> Result<GatewayDomainEventStream, SecurityError> {
        assert_eq!(subscription.organization_id, "org-1");
        assert_eq!(subscription.event_types, vec!["application.approved"]);
        Ok(Box::pin(tokio_stream::iter([
            Ok(GatewayDomainEvent {
                event_id: "event-other".into(),
                event_type: "application.approved".into(),
                aggregate_id: "application-other".into(),
                aggregate_type: "application".into(),
                organization_id: "org-other".into(),
                data: BTreeMap::from([("application_id".into(), "application-other".into())]),
                timestamp: "2026-08-06T11:59:00Z".into(),
            }),
            Ok(GatewayDomainEvent {
                event_id: "event-1".into(),
                event_type: "application.approved".into(),
                aggregate_id: "application-1".into(),
                aggregate_type: "application".into(),
                organization_id: "org-1".into(),
                data: BTreeMap::from([("application_id".into(), "application-1".into())]),
                timestamp: "2026-08-06T12:00:00Z".into(),
            }),
        ])))
    }
}

struct SuccessfulUpstream;

#[async_trait]
impl UpstreamClient for SuccessfulUpstream {
    async fn send(
        &self,
        instance: &ServiceInstance,
        request: GatewayRequest,
    ) -> Result<GatewayResponse, PlatformError> {
        if let Some(forwarded) = request.header("x-request-id") {
            assert_eq!(
                forwarded, request.request_id,
                "the public gateway ID must be forwarded to the upstream service"
            );
        }
        if request.path.starts_with("/internal/") {
            let expected = match instance.service_name.as_str() {
                "signing-keys" if request.path == "/internal/compat/issuer-dids/sign" => {
                    Some("dedicated-issuer-sign-key-000001")
                }
                "signing-keys" => Some("internal-signing-key"),
                "issuance" | "issuance-native" => Some("issuance-service-key"),
                "organizations" => None,
                service => panic!("unexpected internal request to {service}"),
            };
            if let Some(expected) = expected {
                assert_eq!(request.header("x-api-key"), Some(expected));
            }
        }
        if matches!(
            request.path.as_str(),
            "/v1/issuance/token" | "/v1/issuance/initiate"
        ) {
            assert_eq!(instance.service_name, issuance_native::NATIVE_SERVICE);
            assert_eq!(request.header("x-api-key"), Some("issuance-service-key"));
        }
        if request.path == "/v1/issuance/transactions" {
            assert_eq!(instance.service_name, issuance_native::NATIVE_SERVICE);
            assert_eq!(request.header("x-api-key"), Some("issuance-service-key"));
        }
        if request.path == "/v1/issued-credentials/credential-1" {
            assert_eq!(instance.service_name, issuance_native::NATIVE_SERVICE);
            assert_eq!(request.header("x-api-key"), Some("issuance-service-key"));
        }
        if request.path == "/v1/issuance/didcomm/deliver" {
            assert_eq!(instance.service_name, issuance_native::NATIVE_SERVICE);
            assert_eq!(request.header("x-api-key"), Some("issuance-service-key"));
            let body: Value =
                serde_json::from_slice(request.body.as_deref().expect("DIDComm delivery body"))
                    .expect("DIDComm delivery JSON");
            assert_eq!(body["organization_id"], "org-1");
            assert!(body.get("universal_resolver_url").is_none());
        }
        if request.path == "/v1/integrations/canvas/lti/jwks" {
            assert_eq!(instance.service_name, issuance_native::NATIVE_SERVICE);
            assert_eq!(request.header("x-api-key"), None);
        }
        if request.path == "/internal/applications/app-1/evidence-summary" {
            assert_eq!(instance.service_name, issuance_native::NATIVE_SERVICE);
            assert_eq!(request.header("x-api-key"), Some("issuance-service-key"));
            return Ok(GatewayResponse {
                status_code: 404,
                set_cookies: Vec::new(),
                headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
                body: Some(br#"{"detail":"Application not found"}"#.to_vec()),
                response_time_ms: None,
                upstream_service: None,
            });
        }
        if request.path == "/v1/organizations/11111111-1111-1111-1111-111111111111/roles" {
            assert_eq!(instance.service_name, "organizations");
            assert_eq!(
                request.query.get("organization_id"),
                Some(&vec!["11111111-1111-1111-1111-111111111111".into()])
            );
        }
        if request.path == "/v1/organizations/org%2D1/api-keys" {
            assert_eq!(instance.service_name, "organizations");
            assert_eq!(request.header("x-user-id"), Some("user-1"));
            assert_eq!(request.header("x-organization-id"), Some("org-1"));
        }
        let body = match request.path.as_str() {
                path if path.contains("presentation-policies") && path.ends_with("/evaluate") => {
                    assert_eq!(request.header("x-service-token"), Some("s".repeat(32).as_str()));
                    br#"{"decision":"allow","result":"passed"}"#.to_vec()
                }
                "/v1/compliance-profiles/system/discoverable" => serde_json::to_vec(&json!({
                    "items": [{
                        "compliance_code": "OPEN_BADGES_3",
                        "credential_format": "VC_JWT",
                        "api_surface": []
                    }]
                }))
                .expect("profiles"),
                "/v1/compliance-profiles/profile%2D1" => {
                    br#"{"id":"profile-1","organization_id":"org-1","status":"ACTIVE","credential_format":"SD_JWT_VC","issuance_protocol":"OID4VCI_PRE_AUTH"}"#.to_vec()
                }
                path if path.starts_with("/.well-known/openid-credential-issuer") => {
                    serde_json::to_vec(&json!({
                        "credential_issuer": "https://issuer.example/org/org-1",
                        "issuer_display_name": "Example University",
                        "credential_configurations_supported": {
                            "EmployeeCredential": {
                                "format": "jwt_vc_json",
                                "credential_definition": {
                                    "type": ["VerifiableCredential", "EmployeeCredential"],
                                    "credentialSubject": {"email": {"mandatory": true}}
                                },
                                "credential_signing_alg_values_supported": ["ES256"]
                            }
                        }
                    }))
                    .expect("issuer metadata")
                }
                "/credentials/default" => serde_json::to_vec(&json!({
                    "vct": "https://issuer.example/credentials/default"
                }))
                .expect("type metadata"),
                "/internal/documents/did-web/acme" => br#"{"organization_id":"org-acme"}"#.to_vec(),
                "/internal/documents/org%2Dacme/did/load" => {
                    let request: Value =
                        serde_json::from_slice(request.body.as_deref().expect("DID load body"))
                            .expect("DID load request");
                    let did = request["fallback_did"].as_str().expect("fallback DID");
                    serde_json::to_vec(&json!({
                        "document": {
                            "id": did,
                            "controller": did,
                            "verificationMethod": [{
                                "id": format!("{did}#key-1"),
                                "controller": did,
                                "type": "JsonWebKey2020"
                            }],
                            "assertionMethod": [format!("{did}#key-1")]
                        },
                        "found": true
                    }))
                    .expect("DID document")
                }
                "/internal/documents/org%2Droot/did/load" => {
                    let request: Value =
                        serde_json::from_slice(request.body.as_deref().expect("DID load body"))
                            .expect("DID load request");
                    let did = request["fallback_did"].as_str().expect("fallback DID");
                    serde_json::to_vec(&json!({
                        "document": {
                            "id": did,
                            "controller": did,
                            "verificationMethod": [],
                            "assertionMethod": []
                        },
                        "found": true
                    }))
                    .expect("root DID document")
                }
                "/internal/profiles/org%2D1" => serde_json::to_vec(&json!({
                    "profiles": [{"id": "profile-1", "organization_id": "org-1"}]
                }))
                .expect("profiles"),
                "/internal/profiles/org%2D1/profile%2D1" if request.method == HttpMethod::Get => {
                    serde_json::to_vec(&json!({
                        "profile": {"id": "profile-1", "organization_id": "org-1"}
                    }))
                    .expect("profile")
                }
                "/internal/profiles/org%2D1/profile%2D1"
                    if request.method == HttpMethod::Delete =>
                {
                    br#"{"deleted":"profile-1"}"#.to_vec()
                }
                "/internal/documents/org%2D1/passport-artifacts/encrypt" => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("passport artifact body"),
                    )
                    .expect("passport artifact JSON");
                    assert_eq!(body["artifact_id"], "artifact-1");
                    assert!(body.get("organization_id").is_none());
                    br#"{"ciphertext":"vault:v1:synthetic"}"#.to_vec()
                }
                "/internal/documents/org%2D1/passport-artifacts/decrypt" => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("passport artifact body"),
                    )
                    .expect("passport artifact JSON");
                    assert_eq!(body["artifact_id"], "artifact-1");
                    assert!(body.get("organization_id").is_none());
                    br#"{"plaintext_b64":"cGFzc3BvcnQ="}"#.to_vec()
                }
                "/internal/documents/org%2D1/passport-callbacks/verify" => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("passport callback body"),
                    )
                    .expect("passport callback JSON");
                    assert_eq!(body["signature"], "vault:v1:synthetic");
                    assert!(body.get("organization_id").is_none());
                    br#"{"valid":true}"#.to_vec()
                }
                "/internal/compat/issuer-context" => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("issuer context body"),
                    )
                    .expect("issuer context JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["issuer_did"], "did:web:issuer.example");
                    serde_json::to_vec(&json!({
                        "ok": true,
                        "organization_id": "org-1",
                        "issuer_profile_id": "profile-1",
                        "issuer_mode": "org_managed",
                        "issuer_did": "did:web:issuer.example",
                        "signing_service_id": "service-1",
                        "signing_key_reference": "issuer-key",
                        "verification_method_id": "did:web:issuer.example#issuer-key",
                        "key_purpose": "vc_jwt_issuer",
                        "issuer_x5c": [],
                        "issuer_profile": {"id": "profile-1"},
                        "service": {"id": "service-1"}
                    }))
                    .expect("issuer context response")
                }
                "/internal/compat/resolve-issuer-did" => {
                    let body: Value =
                        serde_json::from_slice(request.body.as_deref().expect("issuer DID body"))
                            .expect("issuer DID JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["issuer_did"], "did:web:issuer.example");
                    assert_eq!(body["key_purpose"], "vc_jwt_issuer");
                    serde_json::to_vec(&json!({
                        "ok": true,
                        "organization_id": "org-1",
                        "issuer_did": "did:web:issuer.example",
                        "verification_method_id": "did:web:issuer.example#issuer-key",
                        "key_purpose": "vc_jwt_issuer",
                        "algorithm": "ES256",
                        "issuer_profile":{"organization_id":"org-1","issuer_did":"did:web:issuer.example","key_purpose":"vc_jwt_issuer","credential_format":"SD_JWT_VC","algorithm":"ES256","status":"active"},
                        "public_jwk": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"}
                    }))
                    .expect("issuer DID response")
                }
                "/internal/documents/org%2D1/csca-trust-anchors" => serde_json::to_vec(&json!([
                    {"certificate_id": "csca-1", "certificate_data": "public-csca-pem", "status": "VALID"}
                ]))
                .expect("active CSCA trust response"),
                "/internal/compat/issuer-profiles/profile%2D1/identity" => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("profile identity body"),
                    )
                    .expect("profile identity JSON");
                    assert_eq!(body, json!({"organization_id": "org-1"}));
                    serde_json::to_vec(&json!({
                        "issuer_profile_id": "profile-1",
                        "issuer_did": "did:web:issuer.example",
                        "verification_method_id": "did:web:issuer.example#issuer-key",
                        "public_jwk": {"kty": "EC"},
                        "did_document": {"id": "did:web:issuer.example"},
                        "key_purpose": "vc_jwt_issuer",
                        "algorithm": "ES256"
                    }))
                    .expect("profile identity response")
                }
                "/internal/compat/issuer-profiles/profile%2D1/public-identity" => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("public identity body"),
                    )
                    .expect("public identity JSON");
                    assert_eq!(body, json!({"organization_id": "org-1"}));
                    serde_json::to_vec(&json!({
                        "issuer_profile_id": "profile-1",
                        "issuer_did": "did:web:issuer.example",
                        "verification_method_id": "did:web:issuer.example#issuer-key",
                        "public_jwk": {"kty": "EC"},
                        "algorithm": "ES256",
                        "x5c": ["leaf", "root"],
                        "certificate_expires_at": "2027-01-01T00:00:00Z"
                    }))
                    .expect("public identity response")
                }
                "/internal/compat/issuer-dids/sign" => {
                    let body: Value =
                        serde_json::from_slice(request.body.as_deref().expect("DID sign body"))
                            .expect("DID sign JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["issuer_did"], "did:web:issuer.example");
                    serde_json::to_vec(&json!({
                        "ok": true,
                        "algorithm": "ES256",
                        "payload_length": 7,
                        "signature_encoding": "der",
                        "signature_b64": "c2lnbmF0dXJl",
                        "signature_hex": "7369676e6174757265",
                        "signed_at": "2026-08-20T00:00:00+00:00",
                        "issuer_did": "did:web:issuer.example",
                        "verification_method_id": "did:web:issuer.example#issuer-key",
                        "public_jwk": {"kty": "EC"}
                    }))
                    .expect("DID sign response")
                }
                "/internal/compat/issuer-profiles" => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("create profile body"),
                    )
                    .expect("create profile JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["body"]["issuer_did"], "did:web:issuer.example");
                    serde_json::to_vec(&json!({
                        "ok": true,
                        "profile": {"id": "profile-1", "issuer_did": "did:web:issuer.example"},
                        "created": true
                    }))
                    .expect("create profile response")
                }
                "/internal/compat/issuer-profiles/profile%2D1" => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("update profile body"),
                    )
                    .expect("update profile JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["body"]["status"], "active");
                    serde_json::to_vec(&json!({
                        "ok": true,
                        "profile": {"id": "profile-1", "status": "active"}
                    }))
                    .expect("update profile response")
                }
                "/internal/compat/issuer-profiles/profile%2D1/certificate" => {
                    let body: Value =
                        serde_json::from_slice(request.body.as_deref().expect("certificate body"))
                            .expect("certificate JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["body"]["cert_pem"], "certificate");
                    serde_json::to_vec(&json!({
                        "ok": true,
                        "issuer_profile_id": "profile-1",
                        "issuer_did": "did:web:issuer.example",
                        "verification_method_id": "did:web:issuer.example#issuer-key",
                        "certificate_chain_length": 2,
                        "certificate_expires_at": "2027-01-01T00:00:00Z"
                    }))
                    .expect("certificate response")
                }
                "/v1/credential-templates/template%2D1" => {
                    if request.method == HttpMethod::Patch {
                        let body: Value =
                            serde_json::from_slice(request.body.as_deref().expect("template body"))
                                .expect("template JSON");
                        assert_eq!(body["claims"][0]["mdoc_namespace"], "org.iso.18013.5.1");
                        assert_eq!(body["claims"][0]["mdoc_element_identifier"], "birth_date");
                    }
                    serde_json::to_vec(&json!({
                        "id": "template-1", "organization_id": "org-1", "name": "employee",
                        "description": null, "status": "draft", "credential_type": "EmployeeCredential",
                        "compliance_profile_id": "profile-1", "vct": "EmployeeCredential", "doctype": null,
                        "claims": [{"name":"birth_date","claim_type":"date","display_name":"Date of birth","mdoc_namespace":"org.iso.18013.5.1","mdoc_element_identifier":"birth_date","derivable":true,"selectively_disclosable":false,"pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}$","enum_values":[],"min_value":1,"max_value":2}],
                        "validity_rules": {}, "issuer_did": "did:web:issuer.example",
                        "credential_payload_format": "w3c_vcdm_v2_di", "privacy_posture": null,
                        "created_at": "2026-08-01T00:00:00Z", "updated_at": null,
                        "issuer_profile_id": "must-not-leak"
                    })).expect("credential template")
                }
                "/v1/credential-templates/template%2Ddtc" => serde_json::to_vec(&json!({
                    "id":"template-dtc", "organization_id":"org-1",
                    "credential_payload_format":"MDOC"
                }))
                .expect("authoritative template"),
                "/v1/credential-templates/template%2Dprofiled%2Ddirect" => serde_json::to_vec(&json!({
                    "id":"template-profiled-direct","organization_id":"org-1","credential_payload_format":"VC_JWT_DIRECT_V1"
                })).expect("explicit direct template"),
                "/v1/credential-templates/template%2Dprofiled%2Dhistorical" => serde_json::to_vec(&json!({
                    "id":"template-profiled-historical","organization_id":"org-1","credential_payload_format":"VC_JWT"
                })).expect("explicit historical template"),
                "/v1/credential-templates" if request.method == HttpMethod::Post => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("template create body"),
                    )
                    .expect("template create JSON");
                    assert_eq!(body["claims"][0]["mdoc_namespace"], "org.iso.18013.5.1");
                    assert_eq!(body["issuer_did"], "did:web:issuer.example");
                    serde_json::to_vec(&json!({
                        "id":"template-1","organization_id":"org-1","name":"employee",
                        "description":null,"status":"draft","credential_type":"EmployeeCredential",
                        "compliance_profile_id":"profile-1","vct":"EmployeeCredential","doctype":null,
                        "claims":body["claims"],"validity_rules":{},"issuer_did":"did:web:issuer.example",
                        "privacy_posture":null,"created_at":"2026-08-01T00:00:00Z","updated_at":null,
                        "issuer_profile_id":"must-not-leak"
                    })).expect("template create response")
                }
                "/v1/credential-templates" if request.method == HttpMethod::Get => {
                    assert_eq!(
                        request.query.get("organization_id"),
                        Some(&vec!["org-1".into()])
                    );
                    serde_json::to_vec(&json!([{
                        "id":"template-1", "status":"ACTIVE",
                        "issuer_did":"did:web:issuer.example:orgs:org-1"
                    }]))
                    .expect("template list")
                }
                "/v1/organizations/org%2D1/api-keys" => b"[]".to_vec(),
                "/v1/organizations/11111111%2D1111%2D1111%2D1111%2D111111111111/policy-sets" => {
                    assert_eq!(
                        request.query.get("organization_id"),
                        Some(&vec!["11111111-1111-1111-1111-111111111111".into()])
                    );
                    assert_eq!(
                        request.header("x-service-token"),
                        Some("ssssssssssssssssssssssssssssssss")
                    );
                    b"[]".to_vec()
                }
                "/v1/organizations/audit/events" => {
                    assert_eq!(
                        request.query.get("organization_id"),
                        Some(&vec!["11111111-1111-1111-1111-111111111111".into()])
                    );
                    assert_eq!(
                        request.header("x-service-token"),
                        Some("ssssssssssssssssssssssssssssssss")
                    );
                    br#"{"events":[],"total":0,"page":1,"per_page":5}"#.to_vec()
                }
                "/v1/organizations" => {
                    if request.method == HttpMethod::Get && request.query.contains_key("limit") {
                        return Ok(GatewayResponse {
                            status_code: 200,
                            set_cookies: Vec::new(),
                            headers: BTreeMap::from([(
                                "content-type".into(),
                                "application/json".into(),
                            )]),
                            body: Some(br#"[{"id":"org-1"}]"#.to_vec()),
                            response_time_ms: None,
                            upstream_service: None,
                        });
                    }
                    if request.method == HttpMethod::Post {
                        let body: Value = serde_json::from_slice(
                            request.body.as_deref().expect("organization body"),
                        )
                        .expect("organization JSON");
                        assert_eq!(body["org_type"], "healthcare");
                        assert_eq!(body["description"], Value::Null);
                        assert!(body.get("settings").is_none());
                    }
                    let organization = json!({
                        "id":"20000000-0000-4000-8000-000000000001",
                        "name":"example-issuer", "display_name":"Example Issuer",
                        "description":"Example tenant", "join_code":null,
                        "visibility":"PUBLIC", "owner_id":"owner-subject",
                        "status":"active", "org_type":"healthcare",
                        "join_mechanism":"open", "requires_approval":true,
                        "is_discoverable":true, "contact_email":"operator@example.com",
                        "contact_phone":null, "website":"https://example.com",
                        "membership":null, "created_at":"2026-07-31T00:00:00Z",
                        "updated_at":"2026-07-31T00:00:00Z"
                    });
                    let output = if request.method == HttpMethod::Get {
                        json!([organization])
                    } else {
                        organization
                    };
                    serde_json::to_vec(&output).expect("organization response")
                }
                "/v1/issuer-entities" if request.method == HttpMethod::Post => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("issuer entity body"),
                    )
                    .expect("issuer entity JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["issuer_type"], "ORGANIZATION");
                    assert_eq!(body["accreditations"], json!(["ISO27001"]));
                    assert_eq!(body["metadata"], json!({}));
                    serde_json::to_vec(&json!({
                        "id":"10000000-0000-4000-8000-000000000001",
                        "organization_id":"org-1", "issuer_id":"did:web:issuer.example",
                        "issuer_type":"ORGANIZATION", "display_name":"Example Issuer",
                        "description":null, "is_system_issuer":false,
                        "compliance_status":"COMPLIANT", "accreditation_body":null,
                        "accreditations":["ISO27001"], "accreditation_date":null,
                        "valid_from":"2026-08-01T00:00:00Z", "valid_until":null,
                        "trust_anchor_id":null, "revoked_at":null, "revocation_reason":null,
                        "revoked_by":null, "metadata":{"jurisdiction":"US"},
                        "created_at":"2026-08-01T00:00:00Z",
                        "updated_at":"2026-08-01T00:00:00Z"
                    }))
                    .expect("issuer entity response")
                }
                "/v1/trust-profiles" if request.method == HttpMethod::Post => {
                    assert_eq!(request.header("content-length"), None);
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("trust profile body"),
                    )
                    .expect("trust profile JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["profile_type"], "CUSTOM");
                    assert_eq!(body["trust_sources"][0]["source_type"], "TRUST_LIST");
                    assert_eq!(body["revocation_policy"]["check_mode"], "HARD_FAIL");
                    serde_json::to_vec(&json!({
                        "id":"40000000-0000-4000-8000-000000000001",
                        "organization_id":"org-1", "name":"Registry profile",
                        "description":null, "status":"draft", "profile_type":"CUSTOM",
                        "compliance_status":"SETUP_REQUIRED", "trust_sources":body["trust_sources"],
                        "allowed_algorithms":["ES256"], "revocation_policy":null,
                        "revocation_services":null, "revocation_profile_id":null,
                        "time_policy":body["time_policy"], "supported_formats":["SD_JWT_VC","MDOC"],
                        "allowed_issuers":null, "denied_issuers":null,
                        "verification_policy_set_id":null, "created_at":"2026-08-07T00:00:00Z",
                        "updated_at":null
                    }))
                    .expect("trust profile response")
                }
                "/v1/trust-profiles/trust%2D1" => {
                    br#"{"id":"trust-1","organization_id":"org-1"}"#.to_vec()
                }
                "/v1/presentation-policies" if request.method == HttpMethod::Get => {
                    serde_json::to_vec(&json!({"policies":[{"id":"policy-1","status":"active"}]}))
                        .expect("policy list")
                }
                "/v1/deployment-profiles" if request.method == HttpMethod::Get => {
                    serde_json::to_vec(
                        &json!({"deployment_profiles":[{"id":"deployment-1","status":"ready"}]}),
                    )
                    .expect("deployment list")
                }
                "/v1/deployment-profiles" if request.method == HttpMethod::Post => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("deployment profile body"),
                    )
                    .expect("deployment profile JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["environment"], "development");
                    assert_eq!(body["network_mode"], "ONLINE");
                    assert!(body.get("private_runtime_config").is_none());
                    serde_json::to_vec(&json!({
                        "id":"deployment-1", "organization_id":"org-1",
                        "name":"Campus runtime", "status":"active",
                        "default_policy_id":"policy-1",
                        "presentation_policy_ids":[],
                        "credential_template_ids":["template-1"],
                        "created_at":"2026-08-01T00:00:00Z",
                        "updated_at":"2026-08-01T00:00:00Z",
                        "api_key":"must-not-leak"
                    }))
                    .expect("deployment profile response")
                }
                "/v1/flows/definitions" if request.method == HttpMethod::Get => {
                    serde_json::to_vec(&json!({"definitions":[{
                        "id":"flow-1", "status":"ACTIVE",
                        "credential_template_id":"template-1"
                    }]}))
                    .expect("flow list")
                }
                "/v1/organizations/org%2D1/applicants" => {
                    assert_eq!(request.query.get("limit"), Some(&vec!["500".into()]));
                    serde_json::to_vec(&json!({"items":[
                        {"status":"SUBMITTED"}, {"status":"APPROVED"},
                        {"status":"OFFERED"}
                    ]}))
                    .expect("applicant list")
                }
                "/v1/organizations/org-1/applicants/app-1" => {
                    assert_eq!(instance.service_name, "applicant");
                    serde_json::to_vec(&json!({
                        "id": "app-1",
                        "organization_id": "org-1",
                        "status": "APPROVED"
                    }))
                    .expect("applicant")
                }
                "/v1/organizations/org-1/applicants/app-1/evidence" => {
                    assert_eq!(instance.service_name, "applicant");
                    serde_json::to_vec(&json!([{
                        "id": "evidence-1",
                        "organization_id": "org-1",
                        "application_id": "app-1",
                        "submitted_by": "subject-1",
                        "source": "upload",
                        "evidence_type": "passport",
                        "evidence_requirement_id": "requirement-1",
                        "filename": "passport.pdf",
                        "media_type": "application/pdf",
                        "size_bytes": 42,
                        "sha256": "0123456789abcdef",
                        "status": "VERIFIED",
                        "content_url": "/v1/evidence/evidence-1/content",
                        "captured_at": "2026-08-28T12:00:00Z",
                        "created_at": "2026-08-28T12:00:00Z",
                        "updated_at": "2026-08-28T12:01:00Z"
                    }]))
                    .expect("applicant evidence")
                }
                "/v1/organizations/org%2D1/lifecycle"
                | "/internal/v1/organizations/org%2D1/lifecycle" => {
                    assert_eq!(
                        request.header("x-service-token"),
                        Some("ssssssssssssssssssssssssssssssss")
                    );
                    serde_json::to_vec(&json!({
                        "created_at":"2026-04-01T00:00:00Z",
                        "audit_retention_days":30,
                        "pilot_retention":{"enabled":true,"window_days":30}
                    }))
                    .expect("lifecycle")
                }
                "/v1/issuance/organizations/org%2D1/retention" => {
                    assert_eq!(request.header("x-api-key"), Some("issuance-service-key"));
                    assert_eq!(
                        request.query.get("retention_days"),
                        Some(&vec!["30".into()])
                    );
                    serde_json::to_vec(&json!({
                        "cutoff_at":"2026-03-01T00:00:00Z",
                        "next_expiry_at":"2026-04-01T00:00:00Z",
                        "oldest_retained_record_at":"2026-03-02T00:00:00Z",
                        "eligible_for_purge":{"total":2},
                        "tracked_scope":["applications"]
                    }))
                    .expect("retention summary")
                }
                "/v1/issuance/organizations/org%2D1/retention/purge" => {
                    assert_eq!(request.header("x-api-key"), Some("issuance-service-key"));
                    serde_json::to_vec(&json!({
                        "organization_id":"org-1", "retention_days":30,
                        "cutoff_at":"2026-03-01T00:00:00Z",
                        "purged_at":"2026-04-13T12:00:00Z",
                        "purged_records":{"total":2},
                        "tracked_scope":["applications"],
                        "deletion_token":"must-not-leak"
                    }))
                    .expect("purge")
                }
                "/internal/v1/organizations/org%2D1/settings" => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("settings patch body"),
                    )
                    .expect("settings patch JSON");
                    assert_eq!(
                        body["settings_patch"]["pilot_retention_last_purged_at"],
                        "2026-04-13T12:00:00Z"
                    );
                    br#"{"ok":true}"#.to_vec()
                }
                "/v1/flows/verify" => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("verification flow body"),
                    )
                    .expect("verification flow JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["issuer_did"], "did:web:verifier.example");
                    assert_eq!(body["response_type"], "vp_token");
                    assert_eq!(body["expiry_minutes"], 15);
                    serde_json::to_vec(&json!({
                        "instance_id":"instance-1", "flow_definition_id":"internal-definition",
                        "request_uri":"openid4vp://authorize?request_uri=https%3A%2F%2Fexample.test",
                        "qr_code_data":"openid4vp://authorize?request_uri=https%3A%2F%2Fexample.test",
                        "presentation_policy_id":"policy-1", "nonce":"nonce-value",
                        "expires_at":"2026-07-30T20:00:00Z", "status":"AWAITING_WALLET",
                        "issuer_profile_id":"must-not-leak"
                    }))
                    .expect("verification flow response")
                }
                "/v1/flows/definitions" if request.method == HttpMethod::Post => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("flow definition body"),
                    )
                    .expect("flow definition JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["credential_template_id"], "template-1");
                    assert_eq!(body["approval_strategy"], "AUTO");
                    serde_json::to_vec(&json!({
                        "id":"flow-1","organization_id":"org-1","name":"Issue employee",
                        "description":null,"status":"DRAFT","flow_type":"oid4vci_pre_authorized",
                        "flow_category":"ISSUANCE","resolved_steps":["prepare","issue"],
                        "extension":null,"trust_profile_id":null,
                        "credential_template_id":"template-1","application_template_id":null,
                        "presentation_policy_id":null,"delivery_destination_profile_id":null,
                        "approval_strategy":"AUTO","hooks":{},"trigger":null,
                        "deployment_profile_ids":[],"version":1,
                        "created_at":"2026-08-01T00:00:00Z","updated_at":"2026-08-01T00:00:00Z",
                        "private_execution_plan":{"key_reference":"private"}
                    }))
                    .expect("flow definition response")
                }
                "/v1/flows/instances" if request.method == HttpMethod::Post => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("flow instance body"),
                    )
                    .expect("flow instance JSON");
                    assert_eq!(body["subject_type"], "applicant");
                    assert!(body["initial_context"].get("access_token").is_none());
                    serde_json::to_vec(&json!({
                        "id":"instance-1","flow_id":"flow-1",
                        "flow_type":"oid4vci_pre_authorized","organization_id":"org-1",
                        "status":"PENDING","current_step":null,"current_step_index":null,
                        "context_data":body["initial_context"],"step_results":{},
                        "issued_credential_id":null,"started_at":null,"completed_at":null,
                        "expires_at":null,"error_code":null,"metadata":{},"state_history":[],
                        "created_at":"2026-08-01T00:00:00Z","updated_at":"2026-08-01T00:00:00Z",
                        "private_runtime":"must-not-leak"
                    }))
                    .expect("flow instance response")
                }
                "/v1/presentation-policies" if request.method == HttpMethod::Post => {
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("presentation policy body"),
                    )
                    .expect("presentation policy JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    let expected_format=match body["credential_requirements"][0]["expected_securing_profile"].as_str() {
                        Some("w3c_vc2_jose_2026_v1")=>"VC_JWT_DIRECT_V1",
                        Some("marty_nested_vc2_jwt_v1")=>"VC_JWT",
                        _=>"MDOC",
                    };
                    assert_eq!(body["credential_requirements"][0]["credential_payload_format"],expected_format);
                    let holder=if expected_format=="MDOC" {json!({"required":false})} else {
                        assert_eq!(body["credential_requirements"][0]["requested_claims"],json!([]));
                        assert_eq!(body["holder_binding"]["required"],true);
                        body["holder_binding"].clone()
                    };
                    serde_json::to_vec(&json!({
                        "id":"policy-1", "organization_id":"org-1", "name":"Verify DTC",
                        "status":"draft", "description":null, "purpose":null,
                        "required_claims":[], "accepted_credential_types":[],
                        "trust_profile_id":null, "display_metadata":null,
                        "credential_requirements":body["credential_requirements"],
                        "alternative_requirements":[], "compliance_profile_id":null,
                        "holder_binding":holder, "issuer_constraints":null,
                        "freshness":null, "prefer_predicates":false, "fallback_policy":null,
                        "supported_circuits":[], "credential_ranking_strategy":"FRESHEST_FIRST",
                        "credential_ranking_weights":null, "version":1,
                        "created_at":"2026-07-30T00:00:00Z",
                        "updated_at":"2026-07-30T00:00:00Z",
                        "issuer_profile_id":"must-not-leak"
                    }))
                    .expect("presentation policy response")
                }
                "/v1/issuance/oid4vci-clients" => {
                    assert_eq!(instance.service_name, issuance_native::NATIVE_SERVICE);
                    assert_eq!(request.header("x-api-key"), Some("issuance-service-key"));
                    serde_json::to_vec(&json!({"client_id": "official-wallet"}))
                        .expect("client registration")
                }
                "/v1/issuance/initiate" => {
                    assert_eq!(request.header("x-api-key"), Some("issuance-service-key"));
                    let body: Value =
                        serde_json::from_slice(request.body.as_deref().expect("issuance body"))
                            .expect("issuance JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["issuer_did"], "did:web:issuer.example");
                    assert!(body.get("issuer_profile_id").is_none());
                    let offer = json!({
                        "credential_issuer": "https://issuer.example/org/org-1",
                        "credential_configuration_ids": ["EmployeeCredential#ldp-vc"],
                        "grants": {
                            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                                "pre-authorized_code": "pre-auth-1"
                            }
                        }
                    });
                    let query = url::form_urlencoded::Serializer::new(String::new())
                        .append_pair("credential_offer", &offer.to_string())
                        .finish();
                    serde_json::to_vec(&json!({
                        "id": "iss-1",
                        "organization_id": "org-1",
                        "credential_template_id": "template-1",
                        "status": "pending",
                        "credential_offer_uri": format!("openid-credential-offer://?{query}")
                        ,"credential_offer_uris": {},
                        "credential_offer_labels": {},
                        "expires_at": "2026-09-01T00:00:00Z",
                        "pre_auth_code": "must-not-leak"
                    }))
                    .expect("offer")
                }
                "/v1/issuance/token" => br#"{"access_token":"access-token"}"#.to_vec(),
                "/v1/issuance/didcomm/deliver" => serde_json::to_vec(&json!({
                    "transaction_id":"tx-123", "credential_id":"credential-123",
                    "holder_did":"did:peer:2.EzExample",
                    "service_endpoint":"https://holder.example/didcomm",
                    "didcomm_message_id":"message-123", "status":"delivered",
                    "error":null, "provider_delivery_receipt":"must-not-leak"
                }))
                .expect("DIDComm delivery response"),
                "/v1/issuance/transactions" => serde_json::to_vec(&json!([{
                    "id": "iss-1",
                    "organization_id": "org-1",
                    "credential_template_id": "template-1",
                    "status": "issued",
                    "created_at": "2026-08-01T00:00:00Z",
                    "pre_auth_code": "must-not-leak"
                }]))
                .expect("issuance transactions"),
                "/v1/issued-credentials/credential-1" => serde_json::to_vec(&json!({
                    "id": "credential-1",
                    "organization_id": "org-1",
                    "credential_id": "credential-1",
                    "credential_type": "EmployeeCredential",
                    "credential_format": "SD_JWT_VC",
                    "flow_execution_id": "iss-1",
                    "credential_template_id": "template-1",
                    "subject_id": "did:example:holder",
                    "issued_at": "2026-08-01T00:00:00Z",
                    "status": "ACTIVE",
                    "status_list_entries": [],
                    "created_at": "2026-08-01T00:00:00Z",
                    "deliveries": [{"external_credential_id": "must-not-leak"}]
                }))
                .expect("issued credential"),
                "/v1/issuance/nonce" => br#"{"c_nonce":"nonce-1"}"#.to_vec(),
                "/internal/vc-api/holder-proof" => {
                    assert_eq!(instance.service_name, "signing-keys");
                    let body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("holder proof request body"),
                    )
                    .expect("holder proof request JSON");
                    assert_eq!(body["organization_id"], "org-1");
                    assert_eq!(body["issuer_url"], "https://issuer.example/org/org-1");
                    assert_eq!(body["nonce"], "nonce-1");
                    assert!(body.get("key_reference").is_none());
                    br#"{"proof_jwt":"remotely-signed-proof"}"#.to_vec()
                }
                "/v1/issuance/credential" => {
                    let request_body: Value = serde_json::from_slice(
                        request.body.as_deref().expect("credential request body"),
                    )
                    .expect("credential request JSON");
                    assert_eq!(request_body["proofs"]["jwt"][0], "remotely-signed-proof");
                    serde_json::to_vec(&json!({
                    "credentials": [{
                        "format": "ldp_vc",
                        "credential": {
                            "@context": ["https://www.w3.org/ns/credentials/v2"],
                            "type": ["VerifiableCredential"],
                            "issuer": "did:web:issuer.example",
                            "credentialSubject": {"id": "did:example:subject"},
                            "proof": {
                                "type": "DataIntegrityProof",
                                "cryptosuite": "eddsa-rdfc-2022"
                            }
                        }
                    }]
                    }))
                    .expect("credential")
                }
                _ => br#"{"ok":true}"#.to_vec(),
            };
        Ok(GatewayResponse {
            status_code: 200,
            set_cookies: Vec::new(),
            headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
            body: Some(body),
            response_time_ms: None,
            upstream_service: None,
        })
    }
}

fn runtime_router() -> Router {
    gateway_router(runtime_state())
}

fn runtime_state() -> Arc<GatewayRuntimeState> {
    runtime_state_with_events(Arc::new(NoOwner))
}

#[tokio::test]
async fn wallet_public_request_object_bypasses_unavailable_owner_lookup() {
    let mut state = runtime_state();
    Arc::get_mut(&mut state)
        .expect("unique runtime state")
        .owners = Arc::new(UnavailableOwner);
    let response = gateway_router(state)
        .oneshot(
            Request::builder()
                .uri("/v1/flows/instances/flow-1/request")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

async fn secret_bearing_owner_failure(request: Request) -> Response {
    assert_eq!(
        request.uri().path(),
        "/internal/v1/resource-owners/issued-credentials/credential-1"
    );
    assert_eq!(
        request.headers().get("x-api-key").unwrap(),
        "issuance-service-key"
    );
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({
            "detail": "repository failed: password=owner-secret database=issuance"
        })),
    )
        .into_response()
}

async fn ownerless_system_delivery_destination(request: Request) -> Response {
    assert_eq!(
        request.uri().path(),
        "/v1/delivery-destinations/dd-elevenid-wallet"
    );
    assert_eq!(request.headers().get("x-user-id").unwrap(), "user-1");
    assert_eq!(
        request.headers().get("x-service-token").unwrap(),
        "service-secret"
    );
    (
        StatusCode::OK,
        Json(json!({
            "id": "dd-elevenid-wallet",
            "is_system": true,
            "organization_id": null
        })),
    )
        .into_response()
}

async fn ownerless_system_wallet(request: Request) -> Response {
    assert_eq!(request.uri().path(), "/v1/wallet-registry/wr-spruce-001");
    assert_eq!(request.headers().get("x-user-id").unwrap(), "user-1");
    (
        StatusCode::OK,
        Json(json!({
            "id": "wr-spruce-001",
            "is_system": true,
            "is_override": false
        })),
    )
        .into_response()
}

#[tokio::test]
async fn native_owner_failure_is_opaque_and_stops_before_proxy() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-resource-owner-lookups.json"
    ))
    .expect("resource-owner contract");
    let invariant = &contract["intentional_native_corrections"][0]["gateway_invariant"];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("owner fixture listener");
    let origin = format!("http://{}", listener.local_addr().expect("fixture address"));
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(axum::routing::any(secret_bearing_owner_failure)),
        )
        .await
        .expect("owner fixture server");
    });
    let owners = HttpGatewayProvider::new(
        BTreeMap::from([("issuance-native".into(), origin)]),
        "internal-signing-key",
        Some("issuance-service-key".into()),
        Some("s".repeat(32)),
        Some(4_096),
    )
    .expect("HTTP owner provider");
    let upstream = Arc::new(ActorRecordingUpstream::default());
    let mut state = runtime_state_with_upstream(Arc::new(NoOwner), upstream.clone());
    Arc::get_mut(&mut state)
        .expect("unique runtime state")
        .owners = Arc::new(owners);

    let response = gateway_router(state)
        .oneshot(
            Request::builder()
                .uri("/v1/issued-credentials/credential-1")
                .header("cookie", "sessionId=valid")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("gateway response");
    assert_eq!(
        u64::from(response.status().as_u16()),
        invariant["status_code"].as_u64().expect("status")
    );
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        invariant["content_type"].as_str()
    );
    let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
        .await
        .expect("gateway error body");
    assert_eq!(
        serde_json::from_slice::<Value>(&body).expect("gateway JSON"),
        invariant["body"]
    );
    let rendered = String::from_utf8(body.to_vec()).expect("UTF-8 body");
    assert!(!rendered.contains("owner-secret"));
    assert!(!rendered.contains("database"));
    assert_eq!(invariant["upstream_body_disclosed"], false);
    assert_eq!(invariant["proxy_continues"], false);
    assert!(upstream.0.lock().expect("upstream calls").is_empty());
}

#[tokio::test]
async fn authorized_native_upstream_outage_preserves_opaque_mip_503() {
    let upstream = Arc::new(FailingActorRecordingUpstream::default());
    let mut state = runtime_state_with_upstream(Arc::new(NoOwner), upstream.clone());
    Arc::get_mut(&mut state)
        .expect("unique runtime state")
        .owners = Arc::new(ScriptedOwner(Some("org-1".into())));

    let response = gateway_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/issued-credentials/credential-1/renew")
                .header("cookie", "sessionId=valid")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("gateway response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
        .await
        .expect("gateway error body");
    let body: Value = serde_json::from_slice(&body).expect("gateway JSON");
    let message_id = body["message_id"].as_str().expect("MIP message ID");
    assert!(uuid::Uuid::parse_str(message_id).is_ok());
    assert_eq!(
        body,
        json!({
            "error": "service_unavailable",
            "error_description": "Service unavailable",
            "message_id": message_id,
        })
    );
    assert!(!body.to_string().contains("private-upstream-failure"));

    let calls = upstream.0.lock().expect("upstream calls");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, issuance_native::NATIVE_SERVICE);
    assert_eq!(calls[0].1.path, "/v1/issued-credentials/credential-1/renew");
}

fn runtime_state_with_events(
    event_streams: Arc<dyn EventStreamProvider>,
) -> Arc<GatewayRuntimeState> {
    runtime_state_with_upstream(event_streams, Arc::new(SuccessfulUpstream))
}

fn runtime_state_with_upstream(
    event_streams: Arc<dyn EventStreamProvider>,
    upstream: Arc<dyn UpstreamClient>,
) -> Arc<GatewayRuntimeState> {
    runtime_state_with_upstream_and_passport(event_streams, upstream, false)
}

fn runtime_state_with_upstream_and_passport(
    event_streams: Arc<dyn EventStreamProvider>,
    upstream: Arc<dyn UpstreamClient>,
    passport_native: bool,
) -> Arc<GatewayRuntimeState> {
    runtime_state_with_upstream_and_signing_url(
        event_streams,
        upstream,
        passport_native,
        "http://signing-keys:8080",
    )
}

fn runtime_state_with_upstream_and_signing_url(
    event_streams: Arc<dyn EventStreamProvider>,
    upstream: Arc<dyn UpstreamClient>,
    passport_native: bool,
    signing_url: &str,
) -> Arc<GatewayRuntimeState> {
    let routes = GatewayContract::load()
        .expect("contract")
        .runtime_route_table_with_passport_native(passport_native)
        .expect("routes");
    let proxy_routes = GatewayContract::load()
        .expect("contract")
        .proxy_route_table_with_passport_native(passport_native)
        .expect("proxy routes");
    let registry = StaticServiceRegistry::from_urls(&BTreeMap::from([
        ("auth".into(), "http://auth:8001".into()),
        (
            "device-registration".into(),
            "http://device-registration:8014".into(),
        ),
        ("applicant".into(), "http://applicant:8000".into()),
        (
            "compliance-profiles".into(),
            "http://compliance-profiles:8080".into(),
        ),
        (
            "credential-templates".into(),
            "http://credential-templates:8000".into(),
        ),
        ("flows".into(), "http://flows:8000".into()),
        (
            "deployment-profiles".into(),
            "http://deployment-profiles:8000".into(),
        ),
        ("issuance".into(), "http://issuance:8000".into()),
        ("issuance-native".into(), "http://issuance:8000".into()),
        ("organizations".into(), "http://organizations:8000".into()),
        ("notifications".into(), "http://notifications:8000".into()),
        (
            "presentation-policies".into(),
            "http://presentation-policies:8080".into(),
        ),
        ("signing-keys".into(), signing_url.into()),
        ("trust-profiles".into(), "http://trust-profiles:8000".into()),
        (
            "revocation-profiles".into(),
            "http://revocation-profiles:8000".into(),
        ),
    ]))
    .expect("registry");
    let proxy = GatewayProxy::new(
        proxy_routes,
        Arc::new(registry),
        upstream,
        ProxyConfig::default(),
    )
    .expect("proxy");
    let state = GatewayRuntimeState::new(
            routes,
            proxy,
            Arc::new(RuntimeProvider),
            Arc::new(RuntimeProvider),
            Arc::new(NoOwner),
            Arc::new(NoOwner),
            event_streams,
            vec!["auth".into()],
            GatewayRateLimiter::new(Arc::new(InMemoryRateLimiter::default()), 120)
                .expect("rate limiter"),
            Arc::new(InMemoryIdempotencyStore::new(60_000, 5_000).expect("idempotency")),
            ["https://beta.elevenidllc.com".into()],
            "https://issuer.example",
            "https://issuer.example",
            "issuer.example:8443",
            Some("org-root".into()),
            "internal-signing-key",
            "issuance-service-key",
            ReleaseIdentity::default(),
        )
        .expect("runtime state")
        .with_service_token(Some("s".repeat(32)))
        .expect("service token")
        .with_service_sign_gateway_key("dedicated-service-sign-gateway-key-000001".into())
        .expect("service sign credential")
        .with_issuer_sign_key("dedicated-issuer-sign-key-000001".into())
        .expect("issuer sign credential")
        .with_passport_native_gateway(
            passport_native,
            passport_native.then(|| {
                PassportTenantKeyring::from_json(
                    r#"{"org-1":"native-passport-key-for-org-1-00000001","org-2":"native-passport-key-for-org-2-00000002"}"#,
                )
                .expect("test tenant keys")
                .into()
            }),
        )
        .expect("passport gateway");
    Arc::new(state)
}

#[derive(Default)]
struct ActorRecordingUpstream(std::sync::Mutex<Vec<(String, GatewayRequest)>>);

#[tokio::test]
async fn physical_flow_start_key_and_pending_readback_reach_only_flow_upstream() {
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let state = runtime_state_with_upstream(Arc::new(NoOwner), recorder.clone());
    let router = gateway_router(state);
    let body = br#"{"organization_id":"org-1","flow_definition_id":"flow-1","initial_context":{"physical_document":{"country_code":"USA"}}}"#;
    let _ = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/flows/instances")
                .header("cookie", "sessionId=valid")
                .header("content-type", "application/json")
                .header("idempotency-key", "owned-physical-1")
                .body(Body::from(body.as_slice()))
                .unwrap(),
        )
        .await
        .unwrap();
    {
        let calls = recorder.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "flows");
        assert_eq!(calls[0].1.path, "/v1/flows/instances");
        assert_eq!(
            calls[0]
                .1
                .headers
                .get("idempotency-key")
                .map(String::as_str),
            Some("owned-physical-1")
        );
    }

    let mut duplicate_request = Request::builder()
        .method("POST")
        .uri("/v1/flows/instances")
        .header("cookie", "sessionId=valid")
        .header("content-type", "application/json")
        .header("idempotency-key", "owned-physical-1")
        .body(Body::from(body.as_slice()))
        .unwrap();
    duplicate_request
        .headers_mut()
        .append("idempotency-key", "owned-physical-2".parse().unwrap());
    assert_eq!(
        duplicate_request
            .headers()
            .get_all("idempotency-key")
            .iter()
            .count(),
        2
    );
    let duplicate = router.clone().oneshot(duplicate_request).await.unwrap();
    assert_eq!(duplicate.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(recorder.0.lock().unwrap().len(), 1);

    let pending = router
        .oneshot(
            Request::builder()
                .uri("/v1/flows/physical-start-intents?organization_id=org-1")
                .header("cookie", "sessionId=valid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pending.status(), StatusCode::OK);
    let calls = recorder.0.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].0, "flows");
    assert_eq!(calls[1].1.path, "/v1/flows/physical-start-intents");
}

#[async_trait]
impl UpstreamClient for ActorRecordingUpstream {
    async fn send(
        &self,
        instance: &ServiceInstance,
        request: GatewayRequest,
    ) -> Result<GatewayResponse, PlatformError> {
        let issued_credential = request.path.starts_with("/v1/issued-credentials/");
        let notification = (instance.service_name == "notifications").then(|| {
            if request.path.ends_with("/delivery-results") {
                return json!([]);
            }
            let mut example: Value = serde_json::from_str(include_str!(
                "../../../../contracts/notification-http-examples.json"
            ))
            .unwrap();
            let value = &mut example["response"];
            value["organization_id"] = json!("org-1");
            value["target"]["organization_id"] = json!("org-1");
            value["id"] = json!("notification-one");
            if request.path.ends_with("/read") {
                value["read"] = json!(true);
            }
            if request.path == "/v1/notifications" {
                json!([value])
            } else {
                value.clone()
            }
        });
        let trust = (instance.service_name == "trust-profiles").then(|| {
            let fixtures: Value = serde_json::from_str(include_str!(
                "../../../../contracts/trust-profile-readback-behavior.json"
            ))
            .unwrap();
            let mut value = fixtures["cases"][0]["expected"].clone();
            value["organization_id"] = json!("org-1");
            value["status"] = json!(if request.path.ends_with("/suspend") {
                "suspended"
            } else {
                "active"
            });
            value
        });
        self.0
            .lock()
            .expect("owned request recorder")
            .push((instance.service_name.clone(), request));
        Ok(GatewayResponse {
            status_code: 200,
            set_cookies: Vec::new(),
            headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
            body: Some(if let Some(trust) = trust {
                serde_json::to_vec(&trust).unwrap()
            } else if let Some(notification) = notification {
                serde_json::to_vec(&notification).unwrap()
            } else if issued_credential {
                serde_json::to_vec(&json!({
                    "id":"credential-1","organization_id":"org-1",
                    "credential_id":"credential-1","credential_type":"EmployeeCredential",
                    "credential_format":"VDS_NC","flow_execution_id":"transaction-1",
                    "credential_template_id":"template-1","subject_id":"did:example:holder",
                    "issued_at":"2026-09-01T00:00:00Z","status":"REVOKED",
                    "status_list_entries":[],"created_at":"2026-09-01T00:00:00Z"
                }))
                .unwrap()
            } else {
                br#"{"keys":[],"ok":true}"#.to_vec()
            }),
            response_time_ms: None,
            upstream_service: None,
        })
    }
}

#[derive(Default)]
struct FailingActorRecordingUpstream(std::sync::Mutex<Vec<(String, GatewayRequest)>>);

#[async_trait]
impl UpstreamClient for FailingActorRecordingUpstream {
    async fn send(
        &self,
        instance: &ServiceInstance,
        request: GatewayRequest,
    ) -> Result<GatewayResponse, PlatformError> {
        self.0
            .lock()
            .expect("owned request recorder")
            .push((instance.service_name.clone(), request));
        Err(PlatformError::UpstreamTransport(
            "private-upstream-failure".into(),
        ))
    }
}

struct ActorIdentityProvider;

#[async_trait]
impl GatewayIdentityProvider for ActorIdentityProvider {
    async fn validate_session(
        &self,
        session: &str,
    ) -> Result<Option<SessionIdentity>, SecurityError> {
        Ok(match session {
            "actor-session"
            | "actor-denied"
            | "actor-no-organization"
            | "pairing-session"
            | "pairing-stale" => Some(SessionIdentity {
                user_id: session.into(),
                authentication_time_unix: match session {
                    "pairing-session" => Some(Utc::now().timestamp()),
                    "pairing-stale" => Some(Utc::now().timestamp() - 301),
                    _ => None,
                },
                organization_id: (session != "actor-no-organization").then(|| "org-1".into()),
                ..SessionIdentity::default()
            }),
            _ => None,
        })
    }

    async fn validate_api_key(&self, key: &str) -> Result<Option<ApiKeyIdentity>, SecurityError> {
        Ok(match key {
            "actor-key" | "actor-key-no-scope" | "actor-key-wrong-org" => Some(ApiKeyIdentity {
                api_key_id: "trusted-key-id".into(),
                organization_id: Some(
                    if key == "actor-key-wrong-org" {
                        "org-other"
                    } else {
                        "org-1"
                    }
                    .into(),
                ),
                key_prefix: Some("synthetic-prefix".into()),
                scopes: if key == "actor-key-no-scope" {
                    vec![]
                } else {
                    vec!["integrations:write".into(), "credentials:revoke".into()]
                },
            }),
            _ => None,
        })
    }
}

#[async_trait]
impl OrganizationMembershipProvider for ActorIdentityProvider {
    async fn get_membership(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<Option<OrganizationMembership>, SecurityError> {
        Ok((matches!(
            user_id,
            "actor-session" | "pairing-session" | "pairing-stale"
        ) && organization_id == "org-1")
            .then(|| OrganizationMembership {
                user_id: user_id.into(),
                organization_id: organization_id.into(),
                status: "active".into(),
                role_names: BTreeSet::new(),
                permissions: BTreeSet::from([
                    "integration-connector:edit".into(),
                    "issuance:revoke".into(),
                ]),
                is_owner: false,
            }))
    }
}

fn actor_test_router() -> (Router, Arc<ActorRecordingUpstream>) {
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let mut state = runtime_state_with_upstream(Arc::new(NoOwner), recorder.clone());
    let state_mut = Arc::get_mut(&mut state).expect("owned test state");
    state_mut.identities = Arc::new(ActorIdentityProvider);
    state_mut.memberships = Arc::new(ActorIdentityProvider);
    state_mut.device_registration_gateway_key = Some("d".repeat(32));
    (gateway_router(state), recorder)
}

#[tokio::test]
async fn pairing_ticket_route_requires_fresh_session_and_active_tenant() {
    let (router, recorder) = actor_test_router();
    for (authentication, organization, expected) in [
        (None, "org-1", StatusCode::UNAUTHORIZED),
        (
            Some(("cookie", "sessionId=pairing-stale")),
            "org-1",
            StatusCode::FORBIDDEN,
        ),
        (
            Some(("x-api-key", "actor-key")),
            "org-1",
            StatusCode::FORBIDDEN,
        ),
        (
            Some(("cookie", "sessionId=pairing-session")),
            "org-other",
            StatusCode::FORBIDDEN,
        ),
    ] {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v1/devices/pairing-tickets")
            .header("content-type", "application/json")
            .header("x-user-id", "forged-user")
            .header("x-service-token", "forged-service-token");
        if let Some((name, value)) = authentication {
            builder = builder.header(name, value);
        }
        let response = router
                .clone()
                .oneshot(
                    builder
                        .body(Body::from(
                            json!({"organization_id":organization,"trust_profile_id":"11111111-2222-4333-8444-555555555555"}).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
        assert_eq!(response.status(), expected);
    }
    assert!(recorder.0.lock().unwrap().is_empty());

    let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/devices/pairing-tickets")
                    .header("content-type", "application/json")
                    .header("cookie", "sessionId=pairing-session")
                    .header("x-user-id", "forged-user")
                    .header("x-service-token", "forged-service-token")
                    .body(Body::from(r#"{"organization_id":"org-1","trust_profile_id":"11111111-2222-4333-8444-555555555555"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let calls = recorder.0.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (service, request) = &calls[0];
    assert_eq!(service, "device-registration");
    assert_eq!(request.path, "/v1/devices/pairing-tickets");
    assert_eq!(request.header("x-user-id"), Some("pairing-session"));
    assert_eq!(request.header("x-organization-id"), Some("org-1"));
    assert_eq!(
        request.header("x-service-token"),
        Some("d".repeat(32).as_str())
    );
    assert_eq!(
        serde_json::from_slice::<Value>(request.body.as_deref().unwrap()).unwrap(),
        json!({"organization_id":"org-1","trust_profile_id":"11111111-2222-4333-8444-555555555555"})
    );
}

#[tokio::test]
async fn public_pairing_redemption_forwards_ticket_without_client_identity_headers() {
    let (router, recorder) = actor_test_router();
    let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/devices/pair")
                    .header("content-type", "application/json")
                    .header("x-user-id", "forged-user")
                    .header("x-organization-id", "forged-org")
                    .header("x-service-token", "forged-service-token")
                    .body(Body::from(r#"{"pairing_code":"opaque-ticket","platform":"android","fcm_token":"push-token"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let calls = recorder.0.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (service, request) = &calls[0];
    assert_eq!(service, "device-registration");
    assert_eq!(request.path, "/v1/devices/pair");
    assert_eq!(request.header("x-user-id"), None);
    assert_eq!(request.header("x-organization-id"), None);
    assert_eq!(
        request.header("x-service-token"),
        Some("d".repeat(32).as_str())
    );
    assert_eq!(
        serde_json::from_slice::<Value>(request.body.as_deref().unwrap()).unwrap(),
        json!({"pairing_code":"opaque-ticket","platform":"android","fcm_token":"push-token"})
    );
}

#[tokio::test]
async fn public_holder_signing_forwards_bearer_without_client_identity_headers() {
    let (router, recorder) = actor_test_router();
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/devices/holder-signatures")
                .header("content-type", "application/json")
                .header("authorization", "Bearer opaque-device-credential")
                .header("x-user-id", "forged-user")
                .header("x-organization-id", "forged-org")
                .header("x-service-token", "forged-service-token")
                .body(Body::from(
                    r#"{"purpose":"holder_binding","payload_b64":"cHJvb2Y"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let calls = recorder.0.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (service, request) = &calls[0];
    assert_eq!(service, "device-registration");
    assert_eq!(request.path, "/v1/devices/holder-signatures");
    assert_eq!(
        request.header("authorization"),
        Some("Bearer opaque-device-credential")
    );
    assert_eq!(request.header("x-user-id"), None);
    assert_eq!(request.header("x-organization-id"), None);
    assert_eq!(
        request.header("x-service-token"),
        Some("d".repeat(32).as_str())
    );
}

#[tokio::test]
async fn pairing_ack_is_bearer_public_but_exact_status_requires_browser_session() {
    let (router, recorder) = actor_test_router();
    let ack = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/devices/pairing-ack")
                .header("content-type", "application/json")
                .header("authorization", "Bearer opaque-device-credential")
                .header("x-user-id", "forged-user")
                .header("x-service-token", "forged-service-token")
                .body(Body::from(r#"{"pairing_id":"exact-ticket-id"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ack.status(), StatusCode::OK);
    let denied = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/devices/pairing-confirmations/exact-ticket-id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    let status = router
        .oneshot(
            Request::builder()
                .uri("/v1/devices/pairing-confirmations/exact-ticket-id")
                .header("cookie", "sessionId=pairing-session")
                .header("x-user-id", "forged-user")
                .header("x-service-token", "forged-service-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    let calls = recorder.0.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].1.path, "/v1/devices/pairing-ack");
    assert_eq!(
        calls[0].1.header("authorization"),
        Some("Bearer opaque-device-credential")
    );
    assert_eq!(calls[0].1.header("x-user-id"), None);
    assert_eq!(
        calls[1].1.path,
        "/v1/devices/pairing-confirmations/exact-ticket-id"
    );
    assert_eq!(calls[1].1.header("x-user-id"), Some("pairing-session"));
}

#[tokio::test]
async fn holder_rotation_forwards_only_bearer_and_replacement_to_device_registration() {
    let (router, recorder) = actor_test_router();
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/devices/holder-credential-rotations")
                .header("content-type", "application/json")
                .header("authorization", "Bearer current-opaque-capability")
                .header("x-user-id", "forged-user")
                .header("x-service-token", "forged-service-token")
                .body(Body::from(
                    r#"{"replacement_credential":"new-opaque-capability"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let calls = recorder.0.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "device-registration");
    assert_eq!(calls[0].1.path, "/v1/devices/holder-credential-rotations");
    assert_eq!(
        calls[0].1.header("authorization"),
        Some("Bearer current-opaque-capability")
    );
    assert_eq!(calls[0].1.header("x-user-id"), None);
    assert_eq!(
        calls[0].1.header("x-service-token"),
        Some("d".repeat(32).as_str())
    );
}

#[tokio::test]
async fn wallet_issuer_keys_forwards_only_device_bearer() {
    let (router, recorder) = actor_test_router();
    let response = router
        .oneshot(
            Request::builder()
                .uri("/v1/devices/wallet-issuer-keys")
                .header("authorization", "Bearer opaque-device-credential")
                .header("x-user-id", "forged-user")
                .header("x-organization-id", "forged-org")
                .header("x-service-token", "forged-service-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let calls = recorder.0.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "device-registration");
    assert_eq!(calls[0].1.path, "/v1/devices/wallet-issuer-keys");
    assert_eq!(
        calls[0].1.header("authorization"),
        Some("Bearer opaque-device-credential")
    );
    assert_eq!(calls[0].1.header("x-user-id"), None);
    assert_eq!(calls[0].1.header("x-organization-id"), None);
    assert_eq!(
        calls[0].1.header("x-service-token"),
        Some("d".repeat(32).as_str())
    );
}

#[tokio::test]
async fn native_passport_gateway_forwards_all_eight_public_routes_with_tenant_key() {
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let router = gateway_router(runtime_state_with_upstream_and_passport(
        Arc::new(NoOwner),
        recorder.clone(),
        true,
    ));
    for (index, (method, path)) in [
        ("GET", "/v1/passport/capabilities"),
        ("POST", "/v1/passport/applications"),
        (
            "POST",
            "/v1/passport/applications/job-1/generate-data-groups",
        ),
        ("POST", "/v1/passport/applications/job-1/generate-sod"),
        (
            "POST",
            "/v1/passport/applications/job-1/submit-personalization",
        ),
        ("GET", "/v1/passport/applications/job-1/production-status"),
        ("POST", "/v1/passport/applications/job-1/quality-verify"),
        ("POST", "/v1/passport/applications/job-1/activate"),
    ]
    .into_iter()
    .enumerate()
    {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("content-type", "application/json")
                    .header("x-api-key", "passport-gateway-key-org-1")
                    .body(if method == "POST" {
                        Body::from(r#"{"organization_id":"org-1"}"#)
                    } else {
                        Body::empty()
                    })
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{method} {path}");
        let captured = recorder.0.lock().unwrap();
        assert_eq!(captured.len(), index + 1, "{method} {path}");
        let (service, upstream) = captured.last().unwrap();
        assert_eq!(service, issuance_native::NATIVE_SERVICE, "{method} {path}");
        assert_eq!(
            upstream.method,
            http_method(method).unwrap(),
            "{method} {path}"
        );
        assert_eq!(upstream.path, path, "{method} {path}");
        assert_eq!(
            upstream.headers.get("x-api-key").map(String::as_str),
            Some("native-passport-key-for-org-1-00000001"),
            "{method} {path}"
        );
        assert_eq!(
            upstream
                .headers
                .get("x-organization-id")
                .map(String::as_str),
            Some("org-1"),
            "{method} {path}"
        );
    }
    assert_eq!(recorder.0.lock().unwrap().len(), 8);
}

#[tokio::test]
async fn native_passport_create_preserves_one_start_key_and_rejects_duplicates() {
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let router = gateway_router(runtime_state_with_upstream_and_passport(
        Arc::new(NoOwner),
        recorder.clone(),
        true,
    ));
    let body = r#"{"organization_id":"org-1"}"#;
    let one = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/passport/applications")
                .header("content-type", "application/json")
                .header("x-api-key", "passport-gateway-key-org-1")
                .header("idempotency-key", "owned-passport-1")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(one.status(), StatusCode::OK);
    {
        let calls = recorder.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, issuance_native::NATIVE_SERVICE);
        assert_eq!(
            calls[0]
                .1
                .headers
                .get("idempotency-key")
                .map(String::as_str),
            Some("owned-passport-1")
        );
    }
    let mut duplicate_request = Request::builder()
        .method("POST")
        .uri("/v1/passport/applications")
        .header("content-type", "application/json")
        .header("x-api-key", "passport-gateway-key-org-1")
        .header("idempotency-key", "owned-passport-1")
        .body(Body::from(body))
        .unwrap();
    duplicate_request
        .headers_mut()
        .append("idempotency-key", "owned-passport-2".parse().unwrap());
    assert_eq!(
        duplicate_request
            .headers()
            .get_all("idempotency-key")
            .iter()
            .count(),
        2
    );
    let duplicate = router.oneshot(duplicate_request).await.unwrap();
    assert_eq!(duplicate.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(recorder.0.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn administrative_passport_cancel_rejects_key_aliases_before_cached_replay() {
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let router = gateway_router(runtime_state_with_upstream_and_passport(
        Arc::new(NoOwner),
        recorder.clone(),
        true,
    ));
    let path = "/v1/passport/applications/00000000-0000-4000-8000-000000000001/cancel";
    let payload = r#"{"expected_job_id":"00000000-0000-4000-8000-000000000002","reason_code":"ADMINISTRATIVE_ABANDONMENT","reason":"End owned failed attempt"}"#;
    let request = |key: &str, authority: &str| {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("x-api-key", authority)
            .header("idempotency-key", key)
            .body(Body::from(payload))
            .unwrap()
    };
    let first = router
        .clone()
        .oneshot(request("owned-cancel-1", "passport-gateway-cancel-org-1"))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(recorder.0.lock().unwrap().len(), 1);
    let replay = router
        .clone()
        .oneshot(request("owned-cancel-1", "passport-gateway-cancel-org-1"))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(replay.headers()["idempotency-replayed"], "true");
    for key in [" owned-cancel-1 ", "owned-cancel-1,other", ""] {
        let response = router
            .clone()
            .oneshot(request(key, "passport-gateway-cancel-org-1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
    let mut duplicate = request("owned-cancel-1", "passport-gateway-cancel-org-1");
    duplicate
        .headers_mut()
        .append("idempotency-key", "other".parse().unwrap());
    assert_eq!(
        router.clone().oneshot(duplicate).await.unwrap().status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let mut missing = request("owned-cancel-1", "passport-gateway-cancel-org-1");
    missing.headers_mut().remove("idempotency-key");
    assert_eq!(
        router.clone().oneshot(missing).await.unwrap().status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    // The issue-only principal must not acquire revoke authority from a
    // response already cached under this fixture's same authenticated ID.
    assert_eq!(
        router
            .clone()
            .oneshot(request("owned-cancel-1", "passport-gateway-key-org-1"))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let mut foreign = request("owned-cancel-1", "passport-gateway-cancel-org-1");
    foreign
        .headers_mut()
        .insert("x-organization-id", "org-2".parse().unwrap());
    assert_eq!(
        router.oneshot(foreign).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let calls = recorder.0.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, issuance_native::NATIVE_SERVICE);
    assert_eq!(
        calls[0]
            .1
            .headers
            .get("x-organization-id")
            .map(String::as_str),
        Some("org-1")
    );
}

#[tokio::test]
async fn signed_passport_webhook_preserves_raw_body_and_switches_owner_without_tenant_key() {
    let body = br#"{ "bureau_job_id" : "bureau-1", "status":"PRINTING" }"#;
    let signature = "sha256=synthetic-signature";
    for (native, expected_service) in [
        (false, issuance_native::LEGACY_SERVICE),
        (true, issuance_native::NATIVE_SERVICE),
    ] {
        let recorder = Arc::new(ActorRecordingUpstream::default());
        let router = gateway_router(runtime_state_with_upstream_and_passport(
            Arc::new(NoOwner),
            recorder.clone(),
            native,
        ));
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/passport/webhooks/personalization")
                    .header("content-type", "application/json")
                    .header("x-personalization-signature", signature)
                    .body(Body::from(body.as_slice()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let captured = recorder.0.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let (service, upstream) = &captured[0];
        assert_eq!(service, expected_service);
        assert_eq!(upstream.path, "/v1/passport/webhooks/personalization");
        assert_eq!(upstream.body.as_deref(), Some(body.as_slice()));
        assert_eq!(
            upstream
                .headers
                .get("x-personalization-signature")
                .map(String::as_str),
            Some(signature)
        );
        assert!(!upstream.headers.contains_key("x-api-key"));
    }
}

#[tokio::test]
async fn native_passport_gateway_binds_upstream_keys_to_two_authenticated_tenants() {
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let router = gateway_router(runtime_state_with_upstream_and_passport(
        Arc::new(NoOwner),
        recorder.clone(),
        true,
    ));
    for (gateway_key, organization_id, native_key) in [
        (
            "passport-gateway-key-org-1",
            "org-1",
            "native-passport-key-for-org-1-00000001",
        ),
        (
            "passport-gateway-key-org-2",
            "org-2",
            "native-passport-key-for-org-2-00000002",
        ),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/passport/applications")
                    .header("content-type", "application/json")
                    .header("x-api-key", gateway_key)
                    .header("x-organization-id", organization_id)
                    .body(Body::from(
                        json!({"organization_id": organization_id}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let captured = recorder.0.lock().unwrap();
        let (service, upstream) = captured.last().unwrap();
        assert_eq!(service, issuance_native::NATIVE_SERVICE);
        assert_eq!(
            upstream.headers.get("x-api-key").map(String::as_str),
            Some(native_key)
        );
        assert_eq!(
            upstream
                .headers
                .get("x-organization-id")
                .map(String::as_str),
            Some(organization_id)
        );
        assert_ne!(
            upstream.headers.get("x-api-key").map(String::as_str),
            Some(gateway_key)
        );
    }
    let before = recorder.0.lock().unwrap().len();
    for request in [
        Request::builder()
            .method("POST")
            .uri("/v1/passport/applications")
            .header("content-type", "application/json")
            .header("x-api-key", "passport-gateway-key-org-1")
            .body(Body::from(r#"{"organization_id":"org-2"}"#))
            .unwrap(),
        Request::builder()
            .method("GET")
            .uri("/v1/passport/capabilities?organization_id=org-2")
            .header("x-api-key", "passport-gateway-key-org-1")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .method("GET")
            .uri("/v1/passport/capabilities")
            .header("x-api-key", "passport-gateway-key-org-1")
            .header("x-organization-id", "org-2")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .method("GET")
            .uri("/v1/passport/capabilities?organization_id=org-1&organization_id=org-2")
            .header("x-api-key", "passport-gateway-key-org-1")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .method("GET")
            .uri("/v1/passport/capabilities")
            .header("cookie", "sessionId=valid-no-org")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri("/v1/passport/applications")
            .header("content-type", "application/json")
            .header("x-api-key", "passport-gateway-read-only-org-1")
            .body(Body::from(r#"{"organization_id":"org-1"}"#))
            .unwrap(),
    ] {
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    assert_eq!(recorder.0.lock().unwrap().len(), before);
    let response = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/passport/capabilities")
                .header("cookie", "sessionId=valid-org-2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    {
        let captured = recorder.0.lock().unwrap();
        let (service, upstream) = captured.last().unwrap();
        assert_eq!(service, issuance_native::NATIVE_SERVICE);
        assert_eq!(
            upstream.headers.get("x-api-key").map(String::as_str),
            Some("native-passport-key-for-org-2-00000002")
        );
        assert_eq!(
            upstream.headers.get("x-user-id").map(String::as_str),
            Some("user-1")
        );
    }
    let response = gateway_router(runtime_state_with_upstream_and_passport(
        Arc::new(NoOwner),
        recorder.clone(),
        true,
    ))
    .oneshot(
        Request::builder()
            .method("POST")
            .uri("/v1/passport/applications/job-1/activate")
            .header("content-type", "application/json")
            .header("x-api-key", "passport-gateway-key-org-1")
            .body(Body::from("{}"))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    {
        let captured = recorder.0.lock().unwrap();
        let (_, upstream) = captured.last().unwrap();
        assert_eq!(
            upstream.headers.get("x-api-key").map(String::as_str),
            Some("native-passport-key-for-org-1-00000001")
        );
    }
    let response = gateway_router(runtime_state_with_upstream_and_passport(
        Arc::new(NoOwner),
        recorder.clone(),
        true,
    ))
    .oneshot(
        Request::builder()
            .method("POST")
            .uri("/v1/passport/applications/job-1/quality-verify")
            .header("content-type", "application/json")
            .header("x-api-key", "passport-gateway-key-org-1")
            .header("x-user-id", "forged-user")
            .body(Body::from(r#"{"passed":true}"#))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let captured = recorder.0.lock().unwrap();
    let (_, upstream) = captured.last().unwrap();
    assert_eq!(
        upstream.headers.get("x-user-id").map(String::as_str),
        Some("api_key:gateway-test-key")
    );
    assert_eq!(
        upstream.headers.get("x-api-key").map(String::as_str),
        Some("native-passport-key-for-org-1-00000001")
    );
}

#[tokio::test]
async fn internal_passport_handoff_keeps_public_api_key_organizations_isolated() {
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let mut state =
        runtime_state_with_upstream_and_passport(Arc::new(NoOwner), recorder.clone(), true);
    let internal_token = "synthetic-internal-passport-token-00000001";
    Arc::get_mut(&mut state).unwrap().passport_tenant_keys =
        Some(PassportTenantCredentialSource::internal_service_token(internal_token).unwrap());
    let router = gateway_router(state);
    for (public_key, organization_id) in [
        ("passport-gateway-key-org-1", "org-1"),
        ("passport-gateway-key-org-2", "org-2"),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/passport/applications")
                    .header("content-type", "application/json")
                    .header("x-api-key", public_key)
                    .body(Body::from(
                        json!({"organization_id": organization_id}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let captured = recorder.0.lock().unwrap();
        let (_, upstream) = captured.last().unwrap();
        assert_eq!(
            upstream
                .headers
                .get("x-organization-id")
                .map(String::as_str),
            Some(organization_id)
        );
        assert_eq!(
            upstream.headers.get("x-api-key").map(String::as_str),
            Some(internal_token)
        );
        assert_ne!(
            upstream.headers.get("x-api-key").map(String::as_str),
            Some(public_key)
        );
    }
    let before = recorder.0.lock().unwrap().len();
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/passport/applications")
                .header("content-type", "application/json")
                .header("x-api-key", "passport-gateway-key-org-1")
                .body(Body::from(r#"{"organization_id":"org-2"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(recorder.0.lock().unwrap().len(), before);
}

fn forged_actor_request(authentication: Option<(&str, &str)>, public: bool) -> Request {
    let mut request = Request::builder()
        .method(if public { "GET" } else { "POST" })
        .uri(if public {
            "/v1/integrations/canvas/lti/jwks"
        } else {
            "/v1/integrations/canvas/evidence-policy-reviews/review-1/resolve?organization_id=org-1"
        })
        .header("content-type", "application/json")
        .header("x-user-id", "forged-user")
        .header("x-api-key-id", "forged-key")
        .header("x-organization-id", "forged-org")
        .body(if public {
            Body::empty()
        } else {
            Body::from(r#"{"action":"dismiss","organization_id":"org-1"}"#)
        })
        .expect("synthetic gateway request");
    for (name, value) in [
        ("X-Authenticated-User-ID", "forged-priority-one"),
        ("x-AuThEnTiCaTeD-uSeR-iD", "forged-priority-two"),
    ] {
        request.headers_mut().append(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            axum::http::HeaderValue::from_static(value),
        );
    }
    assert_eq!(
        request
            .headers()
            .get_all("x-authenticated-user-id")
            .iter()
            .count(),
        2
    );
    if let Some((name, value)) = authentication {
        request.headers_mut().insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            axum::http::HeaderValue::from_str(value).unwrap(),
        );
    }
    request
}

#[tokio::test]
async fn gateway_trusted_actor_session_and_api_key_replace_client_aliases() {
    // This asserts the real router/proxy boundary, not a persisted SQL actor.
    let frozen: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-canvas-operations.json"
    ))
    .unwrap();
    assert_eq!(
        frozen["behavior"]["actor_priority"],
        json!(["X-Authenticated-User-ID", "X-User-ID", "X-API-Key-ID"])
    );
    for (authentication, expected_user, expected_key) in [
        (("cookie", "sessionId=actor-session"), "actor-session", None),
        (
            ("x-api-key", "actor-key"),
            "api_key:trusted-key-id",
            Some("trusted-key-id"),
        ),
    ] {
        let (router, recorder) = actor_test_router();
        let response = router
            .oneshot(forged_actor_request(Some(authentication), false))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let calls = recorder.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (service, forwarded) = &calls[0];
        assert_eq!(service, issuance_native::NATIVE_SERVICE);
        assert_eq!(
            forwarded.path,
            "/v1/integrations/canvas/evidence-policy-reviews/review-1/resolve"
        );
        assert_eq!(forwarded.method, HttpMethod::Post);
        assert_eq!(forwarded.header("x-authenticated-user-id"), None);
        assert_eq!(forwarded.header("x-user-id"), Some(expected_user));
        assert_eq!(forwarded.header("x-api-key-id"), expected_key);
        assert_eq!(forwarded.header("x-organization-id"), Some("org-1"));
        assert_eq!(forwarded.header("x-api-key"), Some("issuance-service-key"));
        assert!(forwarded
            .headers
            .values()
            .all(|value| !value.contains("forged-")));
    }
}

#[tokio::test]
async fn internal_service_routes_are_never_publicly_proxied() {
    for path in [
        "/internal",
        "/internal/applications",
        "/internal/applications/application-1/approve",
    ] {
        let (router, recorder) = actor_test_router();
        let response = router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("content-type", "application/json")
                        .header("x-api-key", "actor-key")
                        .body(Body::from(
                            r#"{"organization_id":"org-attacker","application_template_id":"template-1","applicant_data":{"organization_id":"org-attacker"}}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert!(
            recorder.0.lock().unwrap().is_empty(),
            "{path} must stop before privileged upstream credential injection"
        );
    }
}

#[tokio::test]
async fn canvas_review_recovery_authenticates_and_authorizes_before_upstream_access() {
    let path = "/v1/integrations/canvas/evidence-policy-reviews/review-1/reconcile-revocation";
    for (authentication, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (
            Some(("x-api-key", "actor-key-no-scope")),
            StatusCode::FORBIDDEN,
        ),
        (
            Some(("cookie", "sessionId=actor-denied")),
            StatusCode::FORBIDDEN,
        ),
        (Some(("x-api-key", "actor-key")), StatusCode::OK),
        (Some(("cookie", "sessionId=actor-session")), StatusCode::OK),
    ] {
        let (router, recorder) = actor_test_router();
        let mut builder = Request::builder()
            .method("POST")
            .uri(path)
            .header("x-user-id", "forged-user")
            .header("x-authenticated-user-id", "forged-user")
            .header("x-organization-id", "org-attacker")
            .header("content-type", "application/json");
        if let Some((name, value)) = authentication {
            builder = builder.header(name, value);
        }
        let response = router
            .oneshot(builder.body(Body::from(r#"{"action":"revoke"}"#)).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{authentication:?}");
        let calls = recorder.0.lock().unwrap();
        if expected == StatusCode::OK {
            assert_eq!(calls.len(), 1);
            let (service, request) = &calls[0];
            assert_eq!(service, issuance_native::NATIVE_SERVICE);
            assert_eq!(request.header("x-organization-id"), Some("org-1"));
            assert_ne!(request.header("x-user-id"), Some("forged-user"));
            assert_ne!(
                request.header("x-authenticated-user-id"),
                Some("forged-user")
            );
        } else {
            assert!(
                calls.is_empty(),
                "denial must precede privileged upstream credential injection"
            );
        }
    }
}

#[tokio::test]
async fn canvas_public_batches_replace_every_client_tenant_shape_or_fail_closed() {
    let paths = [
        "/v1/issuance/delivery-records/canvas-credentials/process-pending",
        "/v1/issuance/delivery-records/canvas-credentials/process-status-sync-failures",
        "/v1/issuance/delivery-records/canvas-credentials/run-automation-cycle",
    ];
    for path in paths {
        for (header, authentication) in [
            ("cookie", "sessionId=actor-session"),
            ("x-api-key", "actor-key"),
        ] {
            for query in [
                "",
                "?organization_id=org-attacker",
                "?organization_id=org-attacker&organization_id=org-other&limit=7",
            ] {
                let (router, recorder) = actor_test_router();
                let response = router
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri(format!("{path}{query}"))
                            .header(header, authentication)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK, "{path}{query}");
                let calls = recorder.0.lock().unwrap();
                assert_eq!(calls.len(), 1, "{path}{query}");
                let (service, forwarded) = &calls[0];
                assert_eq!(service, issuance_native::NATIVE_SERVICE);
                assert_eq!(forwarded.path, path);
                assert_eq!(
                    forwarded.query.get("organization_id"),
                    Some(&vec!["org-1".to_owned()]),
                    "{path}{query}"
                );
                assert_eq!(
                    forwarded.query.get("limit").map(Vec::as_slice),
                    query
                        .contains("limit=7")
                        .then_some(["7".to_owned()].as_slice())
                );
            }
        }

        let (router, recorder) = actor_test_router();
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("{path}?organization_id=org-attacker"))
                    .header("cookie", "sessionId=actor-no-organization")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"detail":"Trusted organization context is required"})
        );
        assert!(recorder.0.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn issued_credential_lifecycle_forwards_only_trusted_actor_and_comments() {
    for (authentication, expected_user, expected_key) in [
        (("cookie", "sessionId=actor-session"), "actor-session", None),
        (
            ("x-api-key", "actor-key"),
            "api_key:trusted-key-id",
            Some("trusted-key-id"),
        ),
    ] {
        let (router, recorder) = actor_test_router();
        let mut request = forged_actor_request(Some(authentication), false);
        *request.uri_mut() = "/v1/issued-credentials/credential-1/revoke"
            .parse()
            .unwrap();
        *request.body_mut() =
            Body::from(r#"{"reason":"affiliationChanged","comments":"HR ticket 42"}"#);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let calls = recorder.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (service, forwarded) = &calls[0];
        assert_eq!(service, issuance_native::NATIVE_SERVICE);
        assert_eq!(forwarded.header("x-authenticated-user-id"), None);
        assert_eq!(forwarded.header("x-user-id"), Some(expected_user));
        assert_eq!(forwarded.header("x-api-key-id"), expected_key);
        assert_eq!(forwarded.header("x-organization-id"), Some("org-1"));
        assert_eq!(forwarded.header("x-api-key"), Some("issuance-service-key"));
        assert_eq!(
            serde_json::from_slice::<Value>(forwarded.body.as_deref().unwrap()).unwrap(),
            json!({"reason":"affiliationChanged","comments":"HR ticket 42"})
        );
        assert!(forwarded
            .headers
            .values()
            .all(|value| !value.contains("forged-")));
    }
}

#[tokio::test]
async fn gateway_trusted_actor_auth_and_tenant_denials_never_reach_upstream() {
    for (authentication, status) in [
        (None, StatusCode::UNAUTHORIZED),
        (
            Some(("cookie", "sessionId=invalid")),
            StatusCode::UNAUTHORIZED,
        ),
        (Some(("x-api-key", "invalid")), StatusCode::UNAUTHORIZED),
        (
            Some(("cookie", "sessionId=actor-denied")),
            StatusCode::FORBIDDEN,
        ),
        (
            Some(("x-api-key", "actor-key-no-scope")),
            StatusCode::FORBIDDEN,
        ),
        (
            Some(("x-api-key", "actor-key-wrong-org")),
            StatusCode::FORBIDDEN,
        ),
    ] {
        let (router, recorder) = actor_test_router();
        let response = router
            .oneshot(forged_actor_request(authentication, false))
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert!(recorder.0.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn gateway_trusted_actor_public_bypass_cannot_forward_client_identity() {
    let (router, recorder) = actor_test_router();
    let response = router
        .oneshot(forged_actor_request(None, true))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let calls = recorder.0.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (service, forwarded) = &calls[0];
    assert_eq!(service, issuance_native::NATIVE_SERVICE);
    for name in [
        "x-authenticated-user-id",
        "x-user-id",
        "x-api-key-id",
        "x-organization-id",
    ] {
        assert_eq!(forwarded.header(name), None);
    }
}

#[test]
fn service_authenticated_proxies_receive_only_gateway_configured_credentials() {
    let mut state = runtime_state();
    Arc::get_mut(&mut state)
        .expect("unique runtime state")
        .device_registration_gateway_key = Some("d".repeat(32));
    let identity = TrustedIdentityContext::default();
    for path in [
        "/v1/organizations/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "/v1/credential-templates",
        "/v1/trust-profiles",
        "/v1/presentation-policies",
    ] {
        let overrides = proxy_overrides(&state, path, &identity);
        assert_eq!(overrides.headers["x-service-token"], "s".repeat(32));
    }
    let applicant = proxy_overrides(&state, "/v1/applicants", &identity);
    assert!(!applicant.headers.contains_key("x-service-token"));
    let device = proxy_overrides(&state, "/v1/devices", &identity);
    assert_eq!(device.headers["x-service-token"], "d".repeat(32));
}

#[test]
fn legacy_api_key_routes_are_bound_to_the_authenticated_organization() {
    assert_eq!(
        compatibility_upstream_path("/v1/api-keys", Some("org-1")).expect("list path"),
        "/v1/organizations/org%2D1/api-keys"
    );
    assert_eq!(
        compatibility_upstream_path("/v1/api-keys/key-1", Some("org-1")).expect("key path"),
        "/v1/organizations/org%2D1/api-keys/key-1"
    );
    assert!(compatibility_upstream_path("/v1/api-keys", None).is_err());
    assert!(compatibility_upstream_path("/v1/api-keys/a/b", Some("org-1")).is_err());
}

#[test]
fn console_compatibility_paths_preserve_the_authorized_tenant() {
    let organization_id = "66955e44-28fd-431e-a4e1-4c2579a66e66";
    assert_eq!(
            compatibility_upstream_path("/v1/policy-sets", Some(organization_id))
                .expect("policy list"),
            "/__gateway/composition/organizations/v1/organizations/66955e44%2D28fd%2D431e%2Da4e1%2D4c2579a66e66/policy-sets"
        );
    assert_eq!(
        compatibility_upstream_path(
            &format!("/v1/organizations/{organization_id}/audit-events"),
            Some(organization_id),
        )
        .expect("audit list"),
        "/__gateway/composition/organizations/v1/organizations/audit/events"
    );
    assert_eq!(
        compatibility_upstream_path(
            &format!("/v1/organizations/{organization_id}/audit-events/export"),
            Some(organization_id),
        )
        .expect("audit export"),
        "/__gateway/composition/organizations/v1/organizations/audit/events/export"
    );
    assert!(matches!(
        compatibility_upstream_path(
            &format!("/v1/organizations/{organization_id}/audit-events"),
            Some("67e9df9d-a3c1-4ada-a2d7-0789992097a2"),
        ),
        Err((403, _))
    ));
}

#[test]
fn scoped_api_key_forwards_only_the_authorized_permission() {
    let identity = GatewayIdentity {
        source: AuthenticationSource::ApiKey,
        user_id: "key-owner".into(),
        authentication_time_unix: None,
        user_email: None,
        user_domain: None,
        session_organization_id: Some("org-1".into()),
        api_key_id: Some("key-1".into()),
        api_key_prefix: None,
        api_key_scopes: vec!["applications:read".into()],
    };
    assert!(authorize_api_key(
        "application:view",
        "org-1",
        identity.session_organization_id.as_deref(),
        &identity.api_key_scopes,
    )
    .is_ok());
    let trusted = trusted_identity(&identity, "org-1", "application:view", None);
    assert_eq!(trusted.organization_permissions, vec!["application:view"]);
    assert_eq!(
        trusted.required_permission.as_deref(),
        Some("application:view")
    );
    assert_eq!(trusted.organization_id.as_deref(), Some("org-1"));
    assert!(authorize_api_key(
        "application:approve",
        "org-1",
        identity.session_organization_id.as_deref(),
        &identity.api_key_scopes,
    )
    .is_err());
    assert!(authorize_api_key(
        "application:view",
        "foreign-org",
        identity.session_organization_id.as_deref(),
        &identity.api_key_scopes,
    )
    .is_err());
}

#[test]
fn legacy_api_key_routes_prefer_the_tenant_authorized_organization() {
    let trusted_identity = TrustedIdentityContext {
        organization_id: Some("authorized-org".into()),
        ..TrustedIdentityContext::default()
    };
    let session_identity = GatewayIdentity {
        source: AuthenticationSource::Session,
        user_id: "user-1".into(),
        authentication_time_unix: None,
        user_email: None,
        user_domain: None,
        session_organization_id: Some("stale-session-org".into()),
        api_key_id: None,
        api_key_prefix: None,
        api_key_scopes: Vec::new(),
    };

    assert_eq!(
        api_key_organization_id(
            &trusted_identity,
            session_identity.session_organization_id.as_deref(),
        )
        .as_deref(),
        Some("authorized-org")
    );
    assert_eq!(
        api_key_organization_id(
            &TrustedIdentityContext::default(),
            session_identity.session_organization_id.as_deref(),
        )
        .as_deref(),
        Some("stale-session-org")
    );
}

#[tokio::test]
async fn legacy_api_key_routes_accept_an_authorized_query_organization_without_session_scope() {
    let response = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/v1/api-keys?organization_id=org-1")
                .header("cookie", "sessionId=valid-no-org")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
        .await
        .expect("body");
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
}

#[tokio::test]
async fn console_policy_and_audit_compatibility_routes_reach_canonical_rust_upstreams() {
    let organization_id = "11111111-1111-1111-1111-111111111111";
    for uri in [
        format!("/v1/policy-sets?organization_id={organization_id}"),
        format!("/v1/organizations/{organization_id}/audit-events?limit=5"),
    ] {
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("cookie", "sessionId=valid-uuid")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body");
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    }
}

#[tokio::test]
async fn organization_composition_uses_membership_authorized_tenant_over_stale_session_scope() {
    let organization_id = "11111111-1111-1111-1111-111111111111";
    let response = runtime_router()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/organizations/{organization_id}/integration-info"
                ))
                // This session names org-1, but RuntimeProvider confirms an
                // active membership in the organization selected by path.
                .header("cookie", "sessionId=valid")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
        .await
        .expect("body");
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let body: Value = serde_json::from_slice(&body).expect("integration info");
    assert_eq!(body["org_id"], organization_id);
}

#[test]
fn signing_proxy_overrides_untrusted_tenant_query_with_session_scope() {
    let state = runtime_state();
    let identity = TrustedIdentityContext {
        organization_id: Some("trusted-org".into()),
        ..TrustedIdentityContext::default()
    };
    let overrides = proxy_overrides(&state, "/v1/signing-keys/issuer-identities", &identity);
    assert_eq!(
        overrides.trusted_query["organization_id"],
        vec!["trusted-org"]
    );
    let routes = GatewayContract::load()
        .unwrap()
        .runtime_route_table()
        .unwrap();
    for (method, path) in [
        (HttpMethod::Patch, "/v1/signing-keys/config"),
        (
            HttpMethod::Put,
            "/v1/signing-keys/issuer-identities/certificate",
        ),
        (
            HttpMethod::Put,
            "/v1/signing-keys/issuer-identities/csca-certificate",
        ),
        (
            HttpMethod::Put,
            "/v1/signing-keys/issuer-identities/certificate-csr",
        ),
        (
            HttpMethod::Put,
            "/v1/signing-keys/issuer-identities/didcomm-key-agreement",
        ),
        (
            HttpMethod::Get,
            "/v1/signing-keys/services/service-1/audit-log",
        ),
        (HttpMethod::Post, "/v1/signing-keys/services/service-1/sign"),
        (HttpMethod::Post, "/v1/signing-keys/config/resolve"),
        (
            HttpMethod::Post,
            "/v1/signing-keys/services/service-1/rotate",
        ),
        (HttpMethod::Post, "/v1/signing-keys/services/vdsnc/register"),
        (HttpMethod::Post, "/v1/signing-keys"),
        (HttpMethod::Get, "/v1/signing-keys/key-1"),
        (HttpMethod::Patch, "/v1/signing-keys/key-1"),
        (HttpMethod::Delete, "/v1/signing-keys/key-1"),
        (HttpMethod::Get, "/v1/signing-keys/compliance/keys-summary"),
    ] {
        let route =
            crate::contract::route_for(&routes, method, path).expect("public signing route");
        assert_eq!(route.route.upstream_service, "signing-keys");
        assert!(route.route.auth_required);
        let overrides = proxy_overrides(&state, path, &identity);
        assert_eq!(
            overrides.trusted_query["organization_id"],
            vec!["trusted-org"]
        );
    }
}

#[tokio::test]
async fn issuer_capabilities_require_membership_permission_and_trusted_proxy_scope() {
    struct NoKeyView;
    #[async_trait]
    impl OrganizationMembershipProvider for NoKeyView {
        async fn get_membership(
            &self,
            user: &str,
            org: &str,
        ) -> Result<Option<OrganizationMembership>, SecurityError> {
            let mut membership = RuntimeProvider.get_membership(user, org).await?;
            if let Some(value) = membership.as_mut() {
                value.permissions.remove("signing-key:view");
            }
            Ok(membership)
        }
    }
    let recorder = Arc::new(ActorRecordingUpstream::default());
    for (organization, authenticated, permitted, expected) in [
        ("org-1", false, true, StatusCode::UNAUTHORIZED),
        ("org-other", true, true, StatusCode::FORBIDDEN),
        ("org-1", true, false, StatusCode::FORBIDDEN),
        ("org-1", true, true, StatusCode::OK),
    ] {
        let mut state = runtime_state_with_upstream(Arc::new(NoOwner), recorder.clone());
        if !permitted {
            Arc::get_mut(&mut state).unwrap().memberships = Arc::new(NoKeyView);
        }
        let mut request = Request::builder().uri(format!(
            "/v1/signing-keys/issuer-identities/capabilities?organization_id={organization}"
        ));
        if authenticated {
            request = request.header("cookie", "sessionId=valid");
        }
        let response = gateway_router(state)
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    let requests = recorder.0.lock().unwrap();
    assert_eq!(
        requests.len(),
        1,
        "unauthorized requests must never reach the service"
    );
    assert_eq!(requests[0].0, "signing-keys");
    assert_eq!(
        requests[0].1.path,
        "/v1/signing-keys/issuer-identities/capabilities"
    );
    assert_eq!(requests[0].1.query["organization_id"], vec!["org-1"]);
    let document = GatewayContract::load().unwrap().openapi_document("test");
    assert_eq!(
        document["paths"]["/v1/signing-keys/issuer-identities/capabilities"]["get"]["responses"]
            ["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/runtime__issuer_identity_capabilities"
    );
}

#[tokio::test]
async fn issuer_inspection_is_read_only_and_requires_tenant_view_authority() {
    let recorder = Arc::new(ActorRecordingUpstream::default());
    for (org, authenticated, allowed, expected) in [
        ("org-1", false, true, StatusCode::UNAUTHORIZED),
        ("org-other", true, true, StatusCode::FORBIDDEN),
        ("org-1", true, false, StatusCode::FORBIDDEN),
        ("org-1", true, true, StatusCode::OK),
    ] {
        let mut state = runtime_state_with_upstream(Arc::new(NoOwner), recorder.clone());
        if allowed && org == "org-1" {
            Arc::get_mut(&mut state).unwrap().memberships = Arc::new(ScriptedMembership("allowed"));
        }
        if !allowed {
            Arc::get_mut(&mut state).unwrap().memberships = Arc::new(ActorIdentityProvider);
        }
        let mut request = Request::builder().uri(format!("/v1/signing-keys/issuer-identities/inspection?organization_id={org}&issuer_did=did%3Aweb%3Aissuer.example%3Aorgs%3Aacme&key_purpose=vc_jwt_issuer&credential_format=SD_JWT_VC&algorithm=ES256"));
        if authenticated {
            request = request.header("cookie", "sessionId=valid");
        }
        let response = gateway_router(state)
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    let requests = recorder.0.lock().unwrap();
    assert_eq!(
        requests.len(),
        1,
        "Denied inspection must not reach the signer"
    );
    assert_eq!(requests[0].0, "signing-keys");
    assert_eq!(requests[0].1.method, HttpMethod::Get);
    assert_eq!(requests[0].1.query["organization_id"], vec!["org-1"]);
    assert_eq!(
        requests[0].1.query["issuer_did"],
        vec!["did:web:issuer.example:orgs:acme"]
    );
    let openapi = GatewayContract::load().unwrap().openapi_document("test");
    assert_eq!(
        openapi["paths"]["/v1/signing-keys/issuer-identities/inspection"]["get"]["responses"]
            ["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/runtime__issuer_identity_inspection"
    );
}

struct SingleGrantMembership(&'static str);
#[async_trait]
impl OrganizationMembershipProvider for SingleGrantMembership {
    async fn get_membership(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<Option<OrganizationMembership>, SecurityError> {
        Ok(
            (organization_id == "org-1").then(|| OrganizationMembership {
                user_id: user_id.into(),
                organization_id: organization_id.into(),
                status: "active".into(),
                role_names: BTreeSet::new(),
                permissions: BTreeSet::from([self.0.into()]),
                is_owner: false,
            }),
        )
    }
}
#[tokio::test]
async fn compliance_public_catalog_and_lifecycle_enforce_exact_tenant_action_before_proxy() {
    for (method, path, permission, owner, authenticated, expected) in [
        (
            "GET",
            "/v1/compliance-profiles/system/discoverable?organization_id=org-1",
            "compliance-profile:view",
            "org-1",
            false,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "GET",
            "/v1/compliance-profiles/system/discoverable?organization_id=org-other",
            "compliance-profile:view",
            "org-1",
            true,
            StatusCode::FORBIDDEN,
        ),
        (
            "GET",
            "/v1/compliance-profiles/system/discoverable?organization_id=org-1",
            "compliance-profile:create",
            "org-1",
            true,
            StatusCode::FORBIDDEN,
        ),
        (
            "GET",
            "/v1/compliance-profiles/system/discoverable?organization_id=org-1",
            "compliance-profile:view",
            "org-1",
            true,
            StatusCode::OK,
        ),
        (
            "POST",
            "/v1/compliance-profiles/profile-one/activate",
            "compliance-profile:create",
            "org-1",
            true,
            StatusCode::FORBIDDEN,
        ),
        (
            "POST",
            "/v1/compliance-profiles/profile-one/activate",
            "compliance-profile:activate",
            "org-1",
            true,
            StatusCode::OK,
        ),
        (
            "POST",
            "/v1/compliance-profiles/profile-one/suspend",
            "compliance-profile:view",
            "org-1",
            true,
            StatusCode::FORBIDDEN,
        ),
        (
            "POST",
            "/v1/compliance-profiles/profile-one/suspend",
            "compliance-profile:suspend",
            "org-other",
            true,
            StatusCode::FORBIDDEN,
        ),
        (
            "POST",
            "/v1/compliance-profiles/profile-one/suspend",
            "compliance-profile:suspend",
            "org-1",
            true,
            StatusCode::OK,
        ),
    ] {
        let recorder = Arc::new(ActorRecordingUpstream::default());
        let mut state = runtime_state_with_upstream(Arc::new(NoOwner), recorder.clone());
        let owned = Arc::get_mut(&mut state).unwrap();
        owned.memberships = Arc::new(SingleGrantMembership(permission));
        owned.owners = Arc::new(ScriptedOwner(Some(owner.into())));
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if authenticated {
            request = request.header("cookie", "sessionId=valid");
        }
        let response = gateway_router(state)
            .oneshot(request.body(Body::from("{}")).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            expected,
            "{method} {path} {permission} {owner}"
        );
        let calls = recorder.0.lock().unwrap();
        assert_eq!(calls.len(), usize::from(expected == StatusCode::OK));
        if expected == StatusCode::OK {
            assert_eq!(calls[0].0, "compliance-profiles");
            assert_eq!(calls[0].1.header("x-user-id"), Some("user-1"));
        }
    }
}

#[tokio::test]
async fn delivery_destinations_enforce_integration_grants_and_resource_owner_before_proxy() {
    for (method, path, permission, owner, authenticated, expected) in [
        (
            "GET",
            "/v1/delivery-destinations?organization_id=org-1",
            "wallet:view",
            "org-1",
            false,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "GET",
            "/v1/delivery-destinations?organization_id=org-other",
            "wallet:view",
            "org-1",
            true,
            StatusCode::FORBIDDEN,
        ),
        (
            "GET",
            "/v1/delivery-destinations?organization_id=org-1",
            "integration-connector:view",
            "org-1",
            true,
            StatusCode::FORBIDDEN,
        ),
        (
            "GET",
            "/v1/delivery-destinations?organization_id=org-1",
            "wallet:view",
            "org-1",
            true,
            StatusCode::OK,
        ),
        (
            "POST",
            "/v1/delivery-destinations",
            "wallet:view",
            "org-1",
            true,
            StatusCode::FORBIDDEN,
        ),
        (
            "POST",
            "/v1/delivery-destinations",
            "integration-connector:create",
            "org-1",
            true,
            StatusCode::OK,
        ),
        (
            "PATCH",
            "/v1/delivery-destinations/destination-one",
            "wallet:view",
            "org-1",
            true,
            StatusCode::FORBIDDEN,
        ),
        (
            "PATCH",
            "/v1/delivery-destinations/destination-one",
            "integration-connector:create",
            "org-1",
            true,
            StatusCode::FORBIDDEN,
        ),
        (
            "PATCH",
            "/v1/delivery-destinations/destination-one",
            "integration-connector:edit",
            "org-other",
            true,
            StatusCode::FORBIDDEN,
        ),
        (
            "PATCH",
            "/v1/delivery-destinations/destination-one",
            "integration-connector:edit",
            "org-1",
            true,
            StatusCode::OK,
        ),
        (
            "DELETE",
            "/v1/delivery-destinations/destination-one",
            "integration-connector:edit",
            "org-1",
            true,
            StatusCode::FORBIDDEN,
        ),
        (
            "DELETE",
            "/v1/delivery-destinations/destination-one",
            "integration-connector:delete",
            "org-1",
            true,
            StatusCode::OK,
        ),
    ] {
        let recorder = Arc::new(ActorRecordingUpstream::default());
        let mut state = runtime_state_with_upstream(Arc::new(NoOwner), recorder.clone());
        let owned = Arc::get_mut(&mut state).unwrap();
        owned.memberships = Arc::new(SingleGrantMembership(permission));
        owned.owners = Arc::new(ScriptedOwner(Some(owner.into())));
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if authenticated {
            request = request.header("cookie", "sessionId=valid");
        }
        let response = gateway_router(state)
            .oneshot(
                request
                    .body(Body::from(r#"{"organization_id":"org-1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            expected,
            "{method} {path} {permission} {owner}"
        );
        let calls = recorder.0.lock().unwrap();
        assert_eq!(calls.len(), usize::from(expected == StatusCode::OK));
        if expected == StatusCode::OK {
            assert_eq!(calls[0].0, "credential-templates");
            assert_eq!(calls[0].1.header("x-user-id"), Some("user-1"));
            assert_eq!(calls[0].1.header("x-organization-id"), Some("org-1"));
        }
    }
}

#[tokio::test]
async fn authorized_system_delivery_destination_read_uses_the_selected_organization() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("owner fixture listener");
    let origin = format!("http://{}", listener.local_addr().expect("fixture address"));
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(axum::routing::any(ownerless_system_delivery_destination)),
        )
        .await
        .expect("owner fixture server");
    });
    let owners = HttpGatewayProvider::new(
        BTreeMap::from([("credential-templates".into(), origin)]),
        "internal-signing-key",
        None,
        Some("service-secret".into()),
        Some(4_096),
    )
    .expect("HTTP owner provider");
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let mut state = runtime_state_with_upstream(Arc::new(NoOwner), recorder.clone());
    let owned = Arc::get_mut(&mut state).expect("unique runtime state");
    owned.memberships = Arc::new(SingleGrantMembership("wallet:view"));
    owned.owners = Arc::new(owners);

    let response = gateway_router(state)
        .oneshot(
            Request::builder()
                .uri("/v1/delivery-destinations/dd-elevenid-wallet?organization_id=org-1")
                .header("cookie", "sessionId=valid")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("gateway response");
    assert_eq!(response.status(), StatusCode::OK);
    let calls = recorder.0.lock().expect("upstream calls");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "credential-templates");
    assert_eq!(calls[0].1.header("x-organization-id"), Some("org-1"));
}

#[tokio::test]
async fn system_wallet_open_link_still_requires_membership_and_wallet_view() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("owner fixture listener");
    let origin = format!("http://{}", listener.local_addr().expect("fixture address"));
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(axum::routing::any(ownerless_system_wallet)),
        )
        .await
        .expect("owner fixture server");
    });
    let owners = HttpGatewayProvider::new(
        BTreeMap::from([("credential-templates".into(), origin)]),
        "internal-signing-key",
        None,
        Some("service-secret".into()),
        Some(4_096),
    )
    .expect("HTTP owner provider");
    for (authenticated, permission, organization, expected) in [
        (false, "wallet:view", "org-1", StatusCode::UNAUTHORIZED),
        (true, "wallet:write", "org-1", StatusCode::FORBIDDEN),
        (true, "wallet:view", "org-other", StatusCode::FORBIDDEN),
        (true, "wallet:view", "org-1", StatusCode::OK),
    ] {
        let recorder = Arc::new(ActorRecordingUpstream::default());
        let mut state = runtime_state_with_upstream(Arc::new(NoOwner), recorder.clone());
        let owned = Arc::get_mut(&mut state).expect("unique runtime state");
        owned.memberships = Arc::new(SingleGrantMembership(permission));
        owned.owners = Arc::new(owners.clone());
        let mut request = Request::builder().uri(format!(
            "/v1/wallet-registry/wr-spruce-001/open-link?organization_id={organization}"
        ));
        if authenticated {
            request = request.header("cookie", "sessionId=valid");
        }
        let response = gateway_router(state)
            .oneshot(request.body(Body::empty()).expect("request"))
            .await
            .expect("gateway response");
        assert_eq!(response.status(), expected);
        let calls = recorder.0.lock().expect("upstream calls");
        assert_eq!(calls.len(), usize::from(expected == StatusCode::OK));
        if expected == StatusCode::OK {
            assert_eq!(calls[0].0, "credential-templates");
            assert_eq!(calls[0].1.header("x-organization-id"), Some("org-1"));
        }
    }
}

#[tokio::test]
async fn explicit_notification_routes_keep_tenant_read_send_boundaries_before_proxy() {
    for (method, path, permission, authenticated, expected) in [
        (
            "GET",
            "/v1/notifications?organization_id=org-1",
            "notification:view",
            false,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "GET",
            "/v1/notifications?organization_id=org-other",
            "notification:view",
            true,
            StatusCode::FORBIDDEN,
        ),
        (
            "GET",
            "/v1/notifications?organization_id=org-1",
            "notification:send",
            true,
            StatusCode::FORBIDDEN,
        ),
        (
            "GET",
            "/v1/notifications?organization_id=org-1",
            "notification:view",
            true,
            StatusCode::OK,
        ),
        (
            "POST",
            "/v1/notifications/send",
            "notification:view",
            true,
            StatusCode::FORBIDDEN,
        ),
        (
            "POST",
            "/v1/notifications/send",
            "notification:send",
            true,
            StatusCode::OK,
        ),
        (
            "GET",
            "/v1/notifications/notification-one/delivery-results?organization_id=org-1",
            "notification:view",
            true,
            StatusCode::OK,
        ),
        (
            "PATCH",
            "/v1/notifications/notification-one/read?organization_id=org-other",
            "notification:view",
            true,
            StatusCode::FORBIDDEN,
        ),
        (
            "PATCH",
            "/v1/notifications/notification-one/read?organization_id=org-1",
            "notification:view",
            true,
            StatusCode::OK,
        ),
    ] {
        let recorder = Arc::new(ActorRecordingUpstream::default());
        let mut state = runtime_state_with_upstream(Arc::new(NoOwner), recorder.clone());
        Arc::get_mut(&mut state).unwrap().memberships = Arc::new(SingleGrantMembership(permission));
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if authenticated {
            request = request.header("cookie", "sessionId=valid");
        }
        let response = gateway_router(state).oneshot(request.body(Body::from(r#"{"organization_id":"org-1","title":"Local fixture","target":{"channels":["SSE"]}}"#)).unwrap()).await.unwrap();
        let actual = response.status();
        let body = to_bytes(response.into_body(), 65536).await.unwrap();
        assert_eq!(
            actual,
            expected,
            "{method} {path} {permission}: {}",
            String::from_utf8_lossy(&body)
        );
        let calls = recorder.0.lock().unwrap();
        assert_eq!(calls.len(), usize::from(expected == StatusCode::OK));
        if expected == StatusCode::OK {
            assert_eq!(calls[0].0, "notifications");
            assert_eq!(calls[0].1.header("x-user-id"), Some("user-1"));
            assert_eq!(calls[0].1.header("x-organization-id"), Some("org-1"));
        }
    }
}

#[test]
fn public_service_signing_receives_dedicated_key_only_after_gateway_authorization() {
    let state = runtime_state();
    let path = "/v1/signing-keys/services/service-1/sign";
    assert!(is_public_service_sign_path(path));
    assert!(!is_public_service_sign_path(
        "/v1/signing-keys/services/service-1/rotate"
    ));
    assert!(!is_public_service_sign_path(
        "/v1/signing-keys/services/a/b/sign"
    ));
    let mut identity = TrustedIdentityContext {
        organization_id: Some("org-1".into()),
        ..TrustedIdentityContext::default()
    };
    assert!(!proxy_overrides(&state, path, &identity)
        .headers
        .contains_key("x-api-key"));
    identity.required_permission = Some("signing-key:create".into());
    assert_eq!(
        proxy_overrides(&state, path, &identity)
            .headers
            .get("x-api-key"),
        state.service_sign_gateway_key.as_ref()
    );
    let mut missing_credential = runtime_state();
    Arc::get_mut(&mut missing_credential)
        .unwrap()
        .service_sign_gateway_key = None;
    assert!(!proxy_overrides(&missing_credential, path, &identity)
        .headers
        .contains_key("x-api-key"));
    identity.organization_id = None;
    assert!(!proxy_overrides(&state, path, &identity)
        .headers
        .contains_key("x-api-key"));
    let readiness = "/v1/signing-keys/config/validate-current";
    identity.organization_id = Some("org-1".into());
    assert_eq!(
        proxy_overrides(&state, readiness, &identity)
            .headers
            .get("x-api-key"),
        state.service_sign_gateway_key.as_ref()
    );
    identity.required_permission = Some("signing-key:view".into());
    assert!(!proxy_overrides(&state, readiness, &identity)
        .headers
        .contains_key("x-api-key"));
}

#[tokio::test]
async fn signing_mutations_require_session_and_forward_trusted_scope() {
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let router = gateway_router(runtime_state_with_upstream(
        Arc::new(NoOwner),
        recorder.clone(),
    ));
    for (path, body) in [
        (
            "/v1/signing-keys/config/resolve",
            json!({"key_purpose": "mdoc_dsc", "algorithm": "EdDSA"}),
        ),
        (
            "/v1/signing-keys/services/service-1/rotate",
            json!({"overlap_days": 14, "publish_updates": false}),
        ),
        (
            "/v1/signing-keys/services/vdsnc/register",
            json!({"country_code": "USA", "authority_name": "Test Bureau"}),
        ),
        (
            "/v1/signing-keys",
            json!({"name": "Demo signer", "algorithm": "ES256"}),
        ),
    ] {
        let request = |authenticated| {
            let mut builder = Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header(marty_signing_grant::HEADER_NAME, "forged-grant");
            if authenticated {
                builder = builder.header("cookie", "sessionId=valid");
            }
            builder.body(Body::from(body.to_string())).unwrap()
        };
        let before = recorder.0.lock().unwrap().len();
        let denied = router.clone().oneshot(request(false)).await.unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(recorder.0.lock().unwrap().len(), before);

        let accepted = router.clone().oneshot(request(true)).await.unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);
        let calls = recorder.0.lock().unwrap();
        assert_eq!(calls.len(), before + 1);
        let (service, forwarded) = &calls[before];
        assert_eq!(service, "signing-keys");
        assert_eq!(forwarded.method, HttpMethod::Post);
        assert_eq!(forwarded.path, path);
        assert_eq!(forwarded.query["organization_id"], vec!["org-1"]);
        assert!(!forwarded
            .headers
            .contains_key(marty_signing_grant::HEADER_NAME));
        assert_eq!(
            serde_json::from_slice::<Value>(forwarded.body.as_deref().unwrap()).unwrap(),
            body
        );
    }

    // The caller cannot select another tenant even when query and JSON
    // agree with each other: the authenticated membership is org-1.
    let before = recorder.0.lock().unwrap().len();
    let foreign = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signing-keys/config/validate-current?organization_id=org-other")
                .header("content-type", "application/json")
                .header("cookie", "sessionId=valid")
                .body(Body::from(
                    json!({"organization_id":"org-other", "issuer_did":"did:web:issuer.example",
                            "credential_format":"SD_JWT_VC"})
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::FORBIDDEN);
    assert_eq!(recorder.0.lock().unwrap().len(), before);
}

#[tokio::test]
async fn authorized_public_signing_cannot_forward_without_a_scoped_minter() {
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let router = gateway_router(runtime_state_with_upstream(
        Arc::new(NoOwner),
        recorder.clone(),
    ));
    let request = Request::builder()
        .method("POST")
        .uri("/v1/signing-keys/services/service-1/sign")
        .header("content-type", "application/json")
        .header("cookie", "sessionId=valid")
        .header(marty_signing_grant::HEADER_NAME, "forged-grant")
        .body(Body::from(
            json!({
                "payload_b64": "cGF5bG9hZA",
                "key_reference": "issuer-key-1",
                "key_purpose": "vc_jwt_issuer",
                "algorithm": "ES256"
            })
            .to_string(),
        ))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(recorder.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn public_service_signing_mints_exact_scoped_grant_and_discards_caller_grant() {
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let mut state = runtime_state_with_upstream(Arc::new(NoOwner), recorder.clone());
    Arc::get_mut(&mut state).unwrap().service_sign_grant_minter =
        Some(Arc::new(ContractGrantMinter(SigningOrigin::GatewayService)));
    Arc::get_mut(&mut state).unwrap().issuer_csr_grant_minter = Some(Arc::new(
        ContractGrantMinter(SigningOrigin::GatewayIssuerDid),
    ));
    let router = gateway_router(state);
    let body = json!({
        "payload_hex": "7061796c6f6164",
        "key_reference": "issuer-key-1",
        "key_purpose": "vc_jwt_issuer",
        "algorithm": "ES256"
    });
    let request = Request::builder()
        .method("POST")
        .uri("/v1/signing-keys/services/service-1/sign")
        .header("content-type", "application/json")
        .header("cookie", "sessionId=valid")
        .header(marty_signing_grant::HEADER_NAME, "forged-grant")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    {
        let calls = recorder.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let forwarded = &calls[0].1;
        let header = forwarded
            .headers
            .get(marty_signing_grant::HEADER_NAME)
            .expect("trusted Gateway grant");
        assert_ne!(header, "forged-grant");
        let grant = marty_signing_grant::GrantEnvelope::from_header_value(header).unwrap();
        assert_eq!(grant.claims.origin, SigningOrigin::GatewayService);
        assert_eq!(grant.claims.organization_id, "org-1");
        assert_eq!(grant.claims.route, forwarded.path);
        assert_eq!(grant.claims.service_id.as_deref(), Some("service-1"));
        assert_eq!(grant.claims.key_reference.as_deref(), Some("issuer-key-1"));
        assert_eq!(grant.claims.key_purpose, "vc_jwt_issuer");
        assert_eq!(grant.claims.algorithm, "ES256");
        assert_eq!(
            grant.claims.payload_sha256_b64,
            URL_SAFE_NO_PAD.encode(<sha2::Sha256 as sha2::Digest>::digest(b"payload"))
        );
        assert_eq!(
            forwarded.headers.get("x-api-key").map(String::as_str),
            Some("dedicated-service-sign-gateway-key-000001")
        );
    }
    let csr_body = json!({
        "country": "US",
        "organization": "ElevenID Beta",
        "common_name": "signer.example.test",
        "key_reference": "issuer-key-1",
        "algorithm": "ES256"
    });
    let csr_request = Request::builder()
        .method("POST")
        .uri("/v1/signing-keys/services/service-1/certificate-csr")
        .header("content-type", "application/json")
        .header("cookie", "sessionId=valid")
        .header(marty_signing_grant::HEADER_NAME, "forged-grant")
        .body(Body::from(csr_body.to_string()))
        .unwrap();
    let csr_response = router.clone().oneshot(csr_request).await.unwrap();
    assert_eq!(csr_response.status(), StatusCode::OK);
    {
        let calls = recorder.0.lock().unwrap();
        assert_eq!(calls.len(), 2);
        let forwarded_csr = &calls[1].1;
        let csr_header = forwarded_csr
            .headers
            .get(marty_signing_grant::HEADER_NAME)
            .expect("trusted CSR grant");
        assert_ne!(csr_header, "forged-grant");
        let csr_grant = marty_signing_grant::GrantEnvelope::from_header_value(csr_header).unwrap();
        let csr_intent: ServiceCsrIntent = serde_json::from_value(csr_body).unwrap();
        assert_eq!(csr_grant.claims.origin, SigningOrigin::GatewayService);
        assert_eq!(csr_grant.claims.organization_id, "org-1");
        assert_eq!(csr_grant.claims.route, forwarded_csr.path);
        assert_eq!(csr_grant.claims.service_id.as_deref(), Some("service-1"));
        assert_eq!(
            csr_grant.claims.key_reference.as_deref(),
            Some("issuer-key-1")
        );
        assert_eq!(csr_grant.claims.key_purpose, "x509_csr");
        assert_eq!(csr_grant.claims.algorithm, "ES256");
        assert_eq!(
            csr_grant.claims.payload_sha256_b64,
            marty_signing_grant::payload_digest(&csr_intent.bound_payload())
        );
        assert_eq!(
            forwarded_csr.headers.get("x-api-key").map(String::as_str),
            Some("dedicated-service-sign-gateway-key-000001")
        );
    }
    let issuer_body = json!({
        "issuer_did": "did:web:example.test:issuer",
        "key_purpose": "csca",
        "credential_format": "MDOC",
        "algorithm": "ES256",
        "country": "US",
        "organization": "ElevenID Beta",
        "common_name": "Pilot CSCA"
    });
    let issuer_request = Request::builder()
        .method("PUT")
        .uri("/v1/signing-keys/issuer-identities/certificate-csr")
        .header("content-type", "application/json")
        .header("cookie", "sessionId=valid")
        .header(marty_signing_grant::HEADER_NAME, "forged-grant")
        .body(Body::from(issuer_body.to_string()))
        .unwrap();
    let issuer_response = router.clone().oneshot(issuer_request).await.unwrap();
    assert_eq!(issuer_response.status(), StatusCode::OK);
    {
        let calls = recorder.0.lock().unwrap();
        assert_eq!(calls.len(), 3);
        let forwarded_issuer = &calls[2].1;
        let issuer_header = forwarded_issuer
            .headers
            .get(marty_signing_grant::HEADER_NAME)
            .expect("trusted issuer CSR grant");
        assert_ne!(issuer_header, "forged-grant");
        let issuer_grant =
            marty_signing_grant::GrantEnvelope::from_header_value(issuer_header).unwrap();
        let issuer_intent: IssuerCsrIntent = serde_json::from_value(issuer_body).unwrap();
        assert_eq!(issuer_grant.claims.origin, SigningOrigin::GatewayIssuerDid);
        assert_eq!(issuer_grant.claims.organization_id, "org-1");
        assert_eq!(issuer_grant.claims.route, forwarded_issuer.path);
        assert_eq!(
            issuer_grant.claims.issuer_did.as_deref(),
            Some("did:web:example.test:issuer")
        );
        assert_eq!(issuer_grant.claims.service_id, None);
        assert_eq!(issuer_grant.claims.key_reference, None);
        assert_eq!(issuer_grant.claims.key_purpose, "csca");
        assert_eq!(issuer_grant.claims.algorithm, "ES256");
        assert_eq!(
            issuer_grant.claims.payload_sha256_b64,
            marty_signing_grant::payload_digest(&issuer_intent.bound_payload())
        );
        assert_eq!(
            forwarded_issuer
                .headers
                .get("x-api-key")
                .map(String::as_str),
            Some("dedicated-issuer-sign-key-000001")
        );
    }
    let mdoc_body = json!({
        "issuer_did": "did:web:example.test:issuer",
        "key_purpose": "mdoc_dsc",
        "credential_format": "MDOC",
        "algorithm": "ES256",
        "country": "US",
        "organization": "ElevenID Beta",
        "common_name": "Pilot mDL Document Signer"
    });
    let mdoc_request = Request::builder()
        .method("PUT")
        .uri("/v1/signing-keys/issuer-identities/certificate-csr")
        .header("content-type", "application/json")
        .header("cookie", "sessionId=valid")
        .body(Body::from(mdoc_body.to_string()))
        .unwrap();
    assert_eq!(
        router.clone().oneshot(mdoc_request).await.unwrap().status(),
        StatusCode::OK
    );
    {
        let calls = recorder.0.lock().unwrap();
        assert_eq!(calls.len(), 4);
        let forwarded_mdoc = &calls[3].1;
        let mdoc_grant = marty_signing_grant::GrantEnvelope::from_header_value(
            forwarded_mdoc
                .headers
                .get(marty_signing_grant::HEADER_NAME)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(mdoc_grant.claims.origin, SigningOrigin::GatewayIssuerDid);
        assert_eq!(mdoc_grant.claims.key_purpose, "mdoc_dsc");
        assert_eq!(
            mdoc_grant.claims.issuer_did.as_deref(),
            Some("did:web:example.test:issuer")
        );
    }
    let mut invalid_format = mdoc_body;
    invalid_format["credential_format"] = json!("SD_JWT_VC");
    let invalid_request = Request::builder()
        .method("PUT")
        .uri("/v1/signing-keys/issuer-identities/certificate-csr")
        .header("content-type", "application/json")
        .header("cookie", "sessionId=valid")
        .body(Body::from(invalid_format.to_string()))
        .unwrap();
    assert_eq!(
        router.oneshot(invalid_request).await.unwrap().status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[tokio::test]
async fn byok_registration_and_certificate_attachment_require_tenant_grant() {
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let router = gateway_router(runtime_state_with_upstream(
        Arc::new(NoOwner),
        recorder.clone(),
    ));
    for (method, path, body) in [
        (
            "PATCH",
            "/v1/signing-keys/config",
            json!({"services": [], "default_service_id": "service-a"}),
        ),
        (
            "PUT",
            "/v1/signing-keys/issuer-identities/certificate",
            json!({
                "organization_id": "org-1",
                "issuer_did": "did:web:issuer.example:orgs:org-1",
                "key_purpose": "vc_jwt_issuer",
                "credential_format": "SD_JWT_VC",
                "algorithm": "ES256",
                "cert_pem": "public-certificate-only"
            }),
        ),
    ] {
        let request = |authenticated, forged_key, organization_id| {
            let mut builder = Request::builder()
                .method(method)
                .uri(format!("{path}?organization_id={organization_id}"))
                .header("content-type", "application/json");
            if authenticated {
                builder = builder.header("cookie", "sessionId=valid");
            }
            if forged_key {
                builder = builder.header("x-api-key", "attacker-key");
            }
            builder.body(Body::from(body.to_string())).unwrap()
        };
        let before = recorder.0.lock().unwrap().len();
        let denied = router
            .clone()
            .oneshot(request(false, false, "org-other"))
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(recorder.0.lock().unwrap().len(), before);
        let forged = router
            .clone()
            .oneshot(request(true, true, "org-1"))
            .await
            .unwrap();
        assert_eq!(forged.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(recorder.0.lock().unwrap().len(), before);
        let unauthorized_tenant = router
            .clone()
            .oneshot(request(true, false, "org-other"))
            .await
            .unwrap();
        assert_eq!(unauthorized_tenant.status(), StatusCode::FORBIDDEN);
        assert_eq!(recorder.0.lock().unwrap().len(), before);

        let accepted = router
            .clone()
            .oneshot(request(true, false, "org-1"))
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);
        let calls = recorder.0.lock().unwrap();
        assert_eq!(calls.len(), before + 1);
        let (service, forwarded) = &calls[before];
        assert_eq!(service, "signing-keys");
        assert_eq!(forwarded.path, path);
        assert_eq!(forwarded.query["organization_id"], vec!["org-1"]);
        assert!(!forwarded.headers.contains_key("x-api-key"));
        assert_eq!(
            serde_json::from_slice::<Value>(forwarded.body.as_deref().unwrap()).unwrap(),
            body
        );
    }
}

#[tokio::test]
async fn dsc_certificate_issuance_requires_operator_grant_and_forwards_only_trusted_authority() {
    const PATH: &str = "/v1/signing-keys/issuer-identities/dsc-certificate";
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let limited = gateway_router(runtime_state_with_upstream(
        Arc::new(NoOwner),
        recorder.clone(),
    ));
    let body = json!({"issuer_did": "did:web:issuer.example", "csca_profile_id": "csca-1"});
    let request = || {
        Request::post(PATH)
            .header("cookie", "sessionId=valid")
            .header("content-type", "application/json")
            .header("x-required-permission", "passport-certificate:issue")
            .header("x-org-permissions", "signing-key:delete")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    assert_eq!(
        limited.clone().oneshot(request()).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert!(recorder.0.lock().unwrap().is_empty());
    let api_key = Request::post(PATH)
        .header("x-api-key", "passport-gateway-key-org-1")
        .header("x-required-permission", "passport-certificate:issue")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    assert_eq!(
        limited.clone().oneshot(api_key).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert!(recorder.0.lock().unwrap().is_empty());
    let no_tenant = Request::post(PATH)
        .header("cookie", "sessionId=valid-no-org")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    assert_eq!(
        limited.oneshot(no_tenant).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert!(recorder.0.lock().unwrap().is_empty());
    let chosen_tenant_without_session = Request::post(format!("{PATH}?organization_id=org-1"))
        .header("cookie", "sessionId=valid-no-org")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    assert_eq!(
        gateway_router(runtime_state_with_upstream(
            Arc::new(NoOwner),
            recorder.clone()
        ))
        .oneshot(chosen_tenant_without_session)
        .await
        .unwrap()
        .status(),
        StatusCode::FORBIDDEN
    );
    assert!(recorder.0.lock().unwrap().is_empty());

    struct CertificateOperator;
    #[async_trait]
    impl OrganizationMembershipProvider for CertificateOperator {
        async fn get_membership(
            &self,
            user_id: &str,
            organization_id: &str,
        ) -> Result<Option<OrganizationMembership>, SecurityError> {
            let mut membership = RuntimeProvider
                .get_membership(user_id, organization_id)
                .await?;
            if let Some(membership) = membership.as_mut() {
                membership.role_names.insert("operator".into());
                membership
                    .permissions
                    .insert("passport-certificate:issue".into());
            }
            Ok(membership)
        }
    }
    let mut unavailable = runtime_state_with_upstream(Arc::new(NoOwner), recorder.clone());
    Arc::get_mut(&mut unavailable)
        .expect("unique runtime state")
        .memberships = Arc::new(CertificateOperator);
    assert_eq!(
        gateway_router(unavailable)
            .oneshot(request())
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(recorder.0.lock().unwrap().is_empty());
    let mut state = runtime_state_with_upstream(Arc::new(NoOwner), recorder.clone());
    Arc::get_mut(&mut state)
        .expect("unique runtime state")
        .memberships = Arc::new(CertificateOperator);
    Arc::get_mut(&mut state)
        .expect("unique runtime state")
        .dsc_issue_gateway_key = Some("dedicated-dsc-gateway-credential-000001".into());
    let gateway = gateway_router(state);
    assert_eq!(
        gateway.clone().oneshot(request()).await.unwrap().status(),
        StatusCode::OK
    );
    {
        let calls = recorder.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (service, forwarded) = &calls[0];
        assert_eq!(service, "signing-keys");
        assert_eq!(forwarded.path, PATH);
        assert_eq!(forwarded.query["organization_id"], vec!["org-1"]);
        assert_eq!(
            forwarded.header("x-api-key"),
            Some("dedicated-dsc-gateway-credential-000001")
        );
        assert_eq!(forwarded.header("x-user-id"), Some("user-1"));
        assert!(forwarded
            .header("x-org-roles")
            .unwrap()
            .split(',')
            .any(|role| role == "operator"));
        assert_eq!(
            forwarded.header("x-required-permission"),
            Some("passport-certificate:issue")
        );
        let permissions = forwarded.header("x-org-permissions").unwrap();
        assert!(permissions
            .split(',')
            .any(|permission| permission == "passport-certificate:issue"));
        assert!(!permissions
            .split(',')
            .any(|permission| permission == "signing-key:delete"));
    }
    let foreign = Request::post(format!("{PATH}?organization_id=org-other"))
        .header("cookie", "sessionId=valid")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    assert_eq!(
        gateway.oneshot(foreign).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(recorder.0.lock().unwrap().len(), 1);
    let forged_body = Request::post(PATH)
        .header("cookie", "sessionId=valid")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"organization_id":"org-other"}).to_string(),
        ))
        .unwrap();
    let gateway = gateway_router(runtime_state_with_upstream(
        Arc::new(NoOwner),
        recorder.clone(),
    ));
    assert_eq!(
        gateway.oneshot(forged_body).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(recorder.0.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn mdoc_certificates_require_separate_session_authority_and_tenant_binding() {
    struct MdocOperator;
    #[async_trait]
    impl OrganizationMembershipProvider for MdocOperator {
        async fn get_membership(
            &self,
            user_id: &str,
            organization_id: &str,
        ) -> Result<Option<OrganizationMembership>, SecurityError> {
            let mut membership = RuntimeProvider
                .get_membership(user_id, organization_id)
                .await?;
            if let Some(membership) = membership.as_mut() {
                membership
                    .permissions
                    .insert("mdoc-certificate:issue".into());
                membership
                    .permissions
                    .insert("mdoc-certificate:issue-iaca".into());
            }
            Ok(membership)
        }
    }
    for (path, permission, key, iaca) in [
        (
            "/v1/signing-keys/issuer-identities/mdoc-iaca-self-signed-certificate",
            "mdoc-certificate:issue-iaca",
            "dedicated-mdoc-iaca-credential-0000001",
            true,
        ),
        (
            "/v1/signing-keys/issuer-identities/mdoc-dsc-certificate",
            "mdoc-certificate:issue",
            "dedicated-mdoc-dsc-credential-00000001",
            false,
        ),
        (
            "/v1/signing-keys/mdoc-crls/iaca_1",
            "mdoc-certificate:issue-iaca",
            "dedicated-mdoc-iaca-credential-0000001",
            true,
        ),
    ] {
        let recorder = Arc::new(ActorRecordingUpstream::default());
        let body = json!({"organization_id":"org-1"});
        let request = |org: &str| {
            Request::post(format!("{path}?organization_id={org}"))
                .header("cookie", "sessionId=valid")
                .header("content-type", "application/json")
                .header("x-required-permission", "passport-certificate:issue")
                .header("x-user-id", "forged-user")
                .body(Body::from(body.to_string()))
                .unwrap()
        };
        let mut disabled = runtime_state_with_upstream(Arc::new(NoOwner), recorder.clone());
        Arc::get_mut(&mut disabled).unwrap().memberships = Arc::new(MdocOperator);
        assert_eq!(
            gateway_router(disabled)
                .oneshot(request("org-1"))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let mut state = runtime_state_with_upstream(Arc::new(NoOwner), recorder.clone());
        let mutable = Arc::get_mut(&mut state).unwrap();
        mutable.memberships = Arc::new(MdocOperator);
        if iaca {
            mutable.mdoc_iaca_issue_gateway_key = Some(key.into());
        } else {
            mutable.mdoc_dsc_issue_gateway_key = Some(key.into());
        }
        let gateway = gateway_router(state);
        assert_eq!(
            gateway
                .clone()
                .oneshot(request("org-1"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            gateway
                .clone()
                .oneshot(request("org-other"))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let api_key = Request::post(path)
            .header("x-api-key", "passport-gateway-key-org-1")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        assert_eq!(
            gateway.oneshot(api_key).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let calls = recorder.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1.header("x-api-key"), Some(key));
        assert_eq!(calls[0].1.header("x-user-id"), Some("user-1"));
        assert_eq!(calls[0].1.header("x-required-permission"), Some(permission));
        assert!(!marty_api_key_policy::api_key_allowed(
            permission,
            &["admin:full".into(), permission.into()]
        ));
    }
}

#[tokio::test]
async fn beta_csca_ceremony_requires_its_own_operator_grant_and_gateway_credential() {
    const PATH: &str = "/v1/signing-keys/issuer-identities/csca-self-signed-certificate";
    struct CscaOperator;
    #[async_trait]
    impl OrganizationMembershipProvider for CscaOperator {
        async fn get_membership(
            &self,
            user_id: &str,
            organization_id: &str,
        ) -> Result<Option<OrganizationMembership>, SecurityError> {
            let mut membership = RuntimeProvider
                .get_membership(user_id, organization_id)
                .await?;
            if let Some(membership) = membership.as_mut() {
                membership
                    .permissions
                    .insert("passport-certificate:issue-csca".into());
            }
            Ok(membership)
        }
    }
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let body = json!({"organization_id":"org-1","issuer_did":"did:web:issuer.example"});
    let request = || {
        Request::post(PATH)
            .header("cookie", "sessionId=valid")
            .header("content-type", "application/json")
            .header("x-user-id", "forged-user")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let mut disabled = runtime_state_with_upstream(Arc::new(NoOwner), recorder.clone());
    Arc::get_mut(&mut disabled).unwrap().memberships = Arc::new(CscaOperator);
    Arc::get_mut(&mut disabled).unwrap().csca_issue_gateway_key =
        Some("dedicated-csca-gateway-credential-0001".into());
    assert_eq!(
        gateway_router(disabled)
            .oneshot(request())
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let mut enabled = runtime_state_with_upstream(Arc::new(NoOwner), recorder.clone());
    Arc::get_mut(&mut enabled).unwrap().memberships = Arc::new(CscaOperator);
    Arc::get_mut(&mut enabled)
        .unwrap()
        .passport_native_gateway_enabled = true;
    Arc::get_mut(&mut enabled).unwrap().csca_issue_gateway_key =
        Some("dedicated-csca-gateway-credential-0001".into());
    let gateway = gateway_router(enabled);
    assert_eq!(
        gateway.clone().oneshot(request()).await.unwrap().status(),
        StatusCode::OK
    );
    {
        let calls = recorder.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (service, forwarded) = &calls[0];
        assert_eq!(service, "signing-keys");
        assert_eq!(forwarded.query["organization_id"], vec!["org-1"]);
        assert_eq!(
            forwarded.header("x-api-key"),
            Some("dedicated-csca-gateway-credential-0001")
        );
        assert_eq!(forwarded.header("x-user-id"), Some("user-1"));
        assert_eq!(
            forwarded.header("x-required-permission"),
            Some("passport-certificate:issue-csca")
        );
    }
    let denied = Request::post(PATH)
        .header("x-api-key", "passport-gateway-key-org-1")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    assert_eq!(
        gateway.oneshot(denied).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(recorder.0.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn signing_key_metadata_mutations_require_session_and_forward_trusted_scope() {
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let limited = gateway_router(runtime_state_with_upstream(
        Arc::new(NoOwner),
        recorder.clone(),
    ));
    let forbidden = limited
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/signing-keys/key-1")
                .header("cookie", "sessionId=valid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    assert!(recorder.0.lock().unwrap().is_empty());
    let created = limited
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/v1/signing-keys/key-1")
                .header("cookie", "sessionId=valid")
                .header("content-type", "application/json")
                .body(Body::from(json!({"name": "New name"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    assert_eq!(recorder.0.lock().unwrap().len(), 1);
    struct KeyMetadataGrantProvider;
    #[async_trait]
    impl OrganizationMembershipProvider for KeyMetadataGrantProvider {
        async fn get_membership(
            &self,
            user_id: &str,
            organization_id: &str,
        ) -> Result<Option<OrganizationMembership>, SecurityError> {
            let mut membership = RuntimeProvider
                .get_membership(user_id, organization_id)
                .await?;
            if let Some(membership) = membership.as_mut() {
                membership.permissions.remove("signing-key:create");
                membership.permissions.insert("signing-key:edit".into());
                membership.permissions.insert("signing-key:delete".into());
            }
            Ok(membership)
        }
    }
    let mut state = runtime_state_with_upstream(Arc::new(NoOwner), recorder.clone());
    Arc::get_mut(&mut state)
        .expect("unique runtime state")
        .memberships = Arc::new(KeyMetadataGrantProvider);
    let router = gateway_router(state);
    let path = "/v1/signing-keys/key-1";
    for (method, method_name, body) in [
        (
            HttpMethod::Patch,
            "PATCH",
            Some(json!({"name": "New name"})),
        ),
        (HttpMethod::Delete, "DELETE", None),
    ] {
        let request = |authenticated| {
            let mut builder = Request::builder().method(method_name).uri(path);
            if authenticated {
                builder = builder.header("cookie", "sessionId=valid");
            }
            if body.is_some() {
                builder = builder.header("content-type", "application/json");
            }
            builder
                .body(Body::from(
                    body.as_ref().map_or_else(String::new, Value::to_string),
                ))
                .unwrap()
        };
        let before = recorder.0.lock().unwrap().len();
        let denied = router.clone().oneshot(request(false)).await.unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(recorder.0.lock().unwrap().len(), before);
        let accepted = router.clone().oneshot(request(true)).await.unwrap();
        if method == HttpMethod::Patch {
            assert_eq!(accepted.status(), StatusCode::FORBIDDEN);
            assert_eq!(recorder.0.lock().unwrap().len(), before);
            continue;
        }
        assert_eq!(accepted.status(), StatusCode::OK);
        let calls = recorder.0.lock().unwrap();
        assert_eq!(calls.len(), before + 1);
        let (service, forwarded) = &calls[before];
        assert_eq!(service, "signing-keys");
        assert_eq!(forwarded.path, path);
        assert_eq!(forwarded.query["organization_id"], vec!["org-1"]);
        assert_eq!(forwarded.method, method);
        if let Some(expected) = body.as_ref() {
            assert_eq!(
                serde_json::from_slice::<Value>(forwarded.body.as_deref().unwrap()).unwrap(),
                *expected
            );
        }
    }
}

#[tokio::test]
async fn axum_chain_preserves_outer_auth_and_content_type_order() {
    let response = runtime_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signing-keys?organization_id=org-1")
                .header("content-type", "text/plain")
                .body(Body::from("invalid"))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()["x-mip-version"], MIP_VERSION);

    let response = runtime_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/signing-keys?organization_id=org-1")
                .header("cookie", "sessionId=valid")
                .header("content-type", "text/plain")
                .body(Body::from("invalid"))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn unknown_client_ip_keeps_rate_limits_active_without_forwarded_or_proxy_identity() {
    for observe in [false, true] {
        let recorder = Arc::new(ClientIpRecordingUpstream::default());
        let mut state = Arc::into_inner(runtime_state_with_upstream(
            Arc::new(NoOwner),
            recorder.clone(),
        ))
        .expect("unique test state")
        .with_client_ip_observation(observe);
        state.rate_limiter =
            Arc::new(GatewayRateLimiter::new(Arc::new(InMemoryRateLimiter::default()), 2).unwrap());
        let router = gateway_router(Arc::new(state));
        for index in 1..=3 {
            let request = Request::builder()
                .uri("/v1/auth/session/validate")
                .header("x-forwarded-for", format!("203.0.113.{index}"))
                .header("x-real-ip", format!("198.51.100.{index}"))
                .header("forwarded", format!("for=203.0.113.{index}"))
                .header("x-client-ip", "192.0.2.1")
                .header("true-client-ip", "192.0.2.2")
                .header("cf-connecting-ip", "192.0.2.3")
                .header("cf-connecting-ipv6", "2001:db8::3")
                .header("x-envoy-external-address", "192.0.2.4")
                .header("x-forwarded-host", "issuer.example")
                .header("x-forwarded-proto", "https")
                .header("x-forwarded-port", "443")
                .extension(ConnectInfo(
                    format!("10.0.0.{index}:30000")
                        .parse::<SocketAddr>()
                        .unwrap(),
                ))
                .body(Body::empty())
                .unwrap();
            let response = router.clone().oneshot(request).await.unwrap();
            if !observe && index == 3 {
                assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            } else {
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(response.headers()["x-ratelimit-limit"], "2");
            }
        }
        let requests = recorder.0.lock().unwrap();
        let clients = requests
            .iter()
            .map(|request| request.client_ip.clone())
            .collect::<Vec<_>>();
        if observe {
            assert_eq!(
                clients,
                vec![
                    Some("10.0.0.1".into()),
                    Some("10.0.0.2".into()),
                    Some("10.0.0.3".into())
                ]
            );
        } else {
            assert_eq!(clients, vec![None, None]);
        }
        for request in requests.iter() {
            for header in CLIENT_ADDRESS_HEADERS {
                assert_eq!(request.header(header).is_some(), observe, "{header}");
            }
            for (header, value) in [
                ("x-forwarded-host", "issuer.example"),
                ("x-forwarded-proto", "https"),
                ("x-forwarded-port", "443"),
            ] {
                assert_eq!(request.header(header), Some(value));
            }
        }
    }
}

#[derive(Default)]
struct ClientIpRecordingUpstream(std::sync::Mutex<Vec<GatewayRequest>>);

#[async_trait]
impl UpstreamClient for ClientIpRecordingUpstream {
    async fn send(
        &self,
        instance: &ServiceInstance,
        request: GatewayRequest,
    ) -> Result<GatewayResponse, PlatformError> {
        self.0.lock().unwrap().push(request.clone());
        SuccessfulUpstream.send(instance, request).await
    }
}

#[tokio::test]
async fn unknown_client_ip_also_applies_to_vc_api_policy_handoff() {
    for observe in [false, true] {
        let recorder = Arc::new(ClientIpRecordingUpstream::default());
        let state = Arc::into_inner(runtime_state_with_upstream(
            Arc::new(NoOwner),
            recorder.clone(),
        ))
        .expect("unique test state")
        .with_client_ip_observation(observe);
        let request = Request::builder()
                .method("POST")
                .uri("/v1/vc-api/credentials/verify?organization_id=org-1&presentation_policy_id=policy-1")
                .header("cookie","sessionId=valid")
                .header("content-type","application/json")
                .header("x-forwarded-for","203.0.113.10")
                .extension(ConnectInfo("10.0.0.10:30000".parse::<SocketAddr>().unwrap()))
                .body(Body::from(br#"{"verifiableCredential":"header.payload.signature","options":{"challenge":"n","domain":"aud"}}"#.as_slice())).unwrap();
        let response = gateway_router(Arc::new(state))
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let requests = recorder.0.lock().unwrap();
        assert_eq!(
            requests
                .iter()
                .map(|request| request.client_ip.clone())
                .collect::<Vec<_>>(),
            vec![observe.then(|| "10.0.0.10".into())]
        );
        if !observe {
            for request in requests.iter() {
                for header in CLIENT_ADDRESS_HEADERS {
                    assert!(request.header(header).is_none());
                }
            }
        }
    }
}

#[tokio::test]
async fn public_proxy_response_runs_rate_etag_cors_and_mip_stages() {
    let response = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/v1/auth/session/validate")
                .header("origin", "https://beta.elevenidllc.com")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-mip-version"], MIP_VERSION);
    assert_eq!(response.headers()["x-ratelimit-limit"], "120");
    assert!(response.headers().contains_key("etag"));
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        "https://beta.elevenidllc.com"
    );
}

#[tokio::test]
async fn proxy_enforces_service_credentials_and_special_rewrites() {
    let token = runtime_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/issuance/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(token.status(), StatusCode::OK);

    let jwks = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/v1/integrations/canvas/lti/jwks")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(jwks.status(), StatusCode::OK);

    let evidence = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/v1/organizations/org-1/applicants/app-1/evidence-summary")
                .header("cookie", "sessionId=valid")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(evidence.status(), StatusCode::OK);
    let evidence: Value = serde_json::from_slice(
        &to_bytes(evidence.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("evidence summary body"),
    )
    .expect("evidence summary JSON");
    assert_eq!(evidence["application_id"], "app-1");
    assert_eq!(evidence["organization_id"], "org-1");
    assert_eq!(evidence["status"], "APPROVED");
    assert_eq!(evidence["evidence_facts"][0]["id"], "evidence-1");
    assert_eq!(
        evidence["evidence_facts"][0]["assertion"]["sha256"],
        "0123456789abcdef"
    );
    assert!(evidence["policy_decision"].is_null());
    assert_eq!(evidence["available_api_checks"], json!([]));

    let lifecycle = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/v1/organizations/org-1/lifecycle")
                .header("cookie", "sessionId=valid")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(lifecycle.status(), StatusCode::OK);

    let retired = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/v1/integrations/canvas/lti/experience-sessions/state-1")
                .header("cookie", "sessionId=valid")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(retired.status(), StatusCode::GONE);
    let retired: Value = serde_json::from_slice(
        &to_bytes(retired.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body"),
    )
    .expect("json");
    assert_eq!(
        retired["detail"],
        "State-addressed Canvas sessions are no longer supported"
    );
}

#[tokio::test]
async fn issuance_management_responses_are_rewritten_and_privacy_projected() {
    let transactions = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/v1/issuance?organization_id=org-1")
                .header("cookie", "sessionId=valid")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(transactions.status(), StatusCode::OK);
    let transactions: Value = serde_json::from_slice(
        &to_bytes(transactions.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body"),
    )
    .expect("json");
    assert_eq!(transactions[0]["id"], "iss-1");
    assert!(transactions[0].get("pre_auth_code").is_none());

    let credential = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/v1/issued-credentials/credential-1")
                .header("cookie", "sessionId=valid")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(credential.status(), StatusCode::OK);
    let credential: Value = serde_json::from_slice(
        &to_bytes(credential.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body"),
    )
    .expect("json");
    assert_eq!(credential["id"], "credential-1");
    assert!(credential.get("deliveries").is_none());

    let create = runtime_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/issuance")
                .header("cookie", "sessionId=valid")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "organization_id": "org-1",
                        "credential_template_id": "template-1",
                        "authorized_client": {
                            "client_id": "official-wallet",
                            "jwks": {"keys": [{
                                "kty": "EC", "crv": "P-256", "kid": "wallet-key",
                                "x": "f83OJ3D2xF4A9O2jZ8M7VJQYxqvR8K0K8qZ8K0K8qZ8",
                                "y": "x_FEzRu9G8K0K8qZ8K0K8qZ8K0K8qZ8K0K8qZ8K0K8q"
                            }]}
                        },
                        "claims": {"employee_id": "123"}
                    }))
                    .expect("request JSON"),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    let create_status = create.status();
    let create_body = to_bytes(create.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
        .await
        .expect("body");
    assert_eq!(
        create_status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&create_body)
    );
    let create: Value = serde_json::from_slice(&create_body).expect("json");
    assert_eq!(create["id"], "iss-1");
    assert!(create.get("pre_auth_code").is_none());
}

#[tokio::test]
async fn didcomm_delivery_is_tenant_bound_canonical_and_privacy_projected() {
    let response = runtime_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/issuance/didcomm/deliver")
                .header("cookie", "sessionId=valid")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "organization_id":"org-1", "transaction_id":"tx-123",
                        "holder_did":"did:peer:2.EzExample"
                    }))
                    .expect("DIDComm request"),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
        .await
        .expect("body");
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let body: Value = serde_json::from_slice(&body).expect("DIDComm response");
    assert_eq!(body["status"], "delivered");
    assert!(body.get("provider_delivery_receipt").is_none());

    for (organization_id, extra, expected) in [
        ("org-other", None, StatusCode::FORBIDDEN),
        (
            "org-1",
            Some(("universal_resolver_url", "https://attacker.example")),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ] {
        let mut request = json!({
            "organization_id":organization_id, "transaction_id":"tx-123",
            "holder_did":"did:peer:2.EzExample"
        });
        if let Some((key, value)) = extra {
            request[key] = Value::String(value.into());
        }
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/issuance/didcomm/deliver")
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&request).unwrap()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), expected);
    }
}

#[tokio::test]
async fn trusted_tenant_query_replaces_client_controlled_organization() {
    let response = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/v1/organizations/11111111-1111-1111-1111-111111111111/roles?organization_id=attacker-org")
                    .header("cookie", "sessionId=valid-uuid")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn deployment_profile_create_preflights_and_projects_in_rust() {
    let response = runtime_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/deployment-profiles")
                .header("cookie", "sessionId=valid")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "organization_id":"org-1",
                        "name":"Campus runtime",
                        "trust_profile_id":"trust-1",
                        "default_policy_id":"policy-1",
                        "credential_template_ids":["template-1"]
                    }))
                    .expect("deployment request"),
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
        .await
        .expect("body");
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let body: Value = serde_json::from_slice(&body).expect("deployment response");
    assert_eq!(body["id"], "deployment-1");
    assert!(body.get("api_key").is_none());
    assert_eq!(body["canvas_feature_flags"], json!({}));
}

#[tokio::test]
async fn organization_composition_routes_execute_in_rust() {
    let cases = [
        (
            "GET",
            "/v1/organizations/org-1/runtime/status",
            "can_issue",
            json!(true),
        ),
        (
            "GET",
            "/v1/organizations/org-1/dashboard/applicant-stats",
            "issuable",
            json!(2),
        ),
        (
            "GET",
            "/v1/organizations/org-1/lifecycle",
            "audit_retention_days",
            json!(30),
        ),
        (
            "GET",
            "/v1/organizations/org-1/integration-info",
            "base_url",
            json!("https://issuer.example/v1"),
        ),
        (
            "POST",
            "/v1/organizations/org-1/lifecycle/purge",
            "organization_id",
            json!("org-1"),
        ),
    ];
    for (method, path, field, expected) in cases {
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body");
        assert_eq!(
            status,
            StatusCode::OK,
            "{path}: {}",
            String::from_utf8_lossy(&body)
        );
        let body: Value = serde_json::from_slice(&body).expect("composition JSON");
        assert_eq!(body[field], expected, "{path}");
        assert!(body.get("deletion_token").is_none(), "{path}");
    }
}

#[tokio::test]
async fn hosted_pilot_sweep_uses_composed_lifecycle_and_purge_transaction() {
    let stats = run_hosted_pilot_auto_purge_sweep(&runtime_state(), 50).await;
    assert_eq!(
        stats,
        HostedPilotPurgeSweepStats {
            organizations_scanned: 1,
            hosted_pilot_orgs: 1,
            purge_requests: 1,
            purged_records: 2,
        }
    );
}

#[tokio::test]
async fn language_neutral_sse_contract_filters_tenants_and_preserves_frames() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/gateway-sse-behavior.json"
    ))
    .expect("SSE contract");
    let response = runtime_router()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/notifications/events/push?{}",
                    contract["valid_query"].as_str().unwrap()
                ))
                .header("cookie", "sessionId=valid")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers()["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/event-stream"));
    let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
        .await
        .expect("SSE body");
    let expected = contract["expected_frames"]
        .as_array()
        .unwrap()
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<_>>>()
        .unwrap()
        .join("");
    assert_eq!(String::from_utf8(body.to_vec()).unwrap(), expected);
    let selected_tenant = runtime_router()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/notifications/events/push?{}",
                    contract["valid_query"].as_str().unwrap()
                ))
                .header("cookie", "sessionId=valid-uuid")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        selected_tenant.status(),
        StatusCode::OK,
        "tenant authorization must override stale session organization context"
    );
    for query in contract["rejected_queries"].as_array().unwrap() {
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/notifications/events/push?{}",
                        query.as_str().unwrap()
                    ))
                    .header("cookie", "sessionId=valid")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{query}");
    }
}

#[tokio::test]
async fn dropping_sse_body_signals_backend_stream_cancellation() {
    let (sender, receiver) = mpsc::channel(1);
    let (cancel, mut cancelled) = watch::channel(false);
    let stream = DisconnectStream::new(receiver, cancel);
    drop(stream);
    cancelled.changed().await.expect("cancellation signal");
    assert!(*cancelled.borrow());
    drop(sender);
}

#[tokio::test(start_paused = true)]
async fn idle_sse_sends_comments_and_still_cancels_the_backend_subscription() {
    use std::time::Duration;

    let subscribed = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let state = runtime_state_with_events(Arc::new(TrackingEventProvider {
        subscribed,
        dropped: Arc::clone(&dropped),
    }));
    let response = gateway_router(state)
        .oneshot(
            Request::builder()
                .uri("/v1/notifications/events/push?organization_id=org-1")
                .header("cookie", "sessionId=valid")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body().into_data_stream();
    assert_eq!(
        body.next().await.unwrap().unwrap().as_ref(),
        b"data: {\"type\": \"connected\"}\n\n"
    );

    let started = tokio::time::Instant::now();
    for _ in 0..5 {
        let frame = tokio::time::timeout(Duration::from_secs(20), body.next())
            .await
            .expect("idle SSE must send a comment before the proxy read timeout")
            .expect("stream remains open")
            .expect("heartbeat frame");
        assert_eq!(frame.as_ref(), b": keep-alive\n\n");
    }
    assert_eq!(started.elapsed(), Duration::from_secs(75));
    assert!(!dropped.load(Ordering::SeqCst));
    drop(body);
    for _ in 0..20 {
        if dropped.load(Ordering::SeqCst) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn sse_frames_reset_idle_time_without_queuing_comments_or_delaying_eof() {
    use std::time::Duration;

    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/gateway-sse-behavior.json"
    ))
    .expect("SSE contract");
    let connected = contract["expected_frames"][0].as_str().unwrap();
    let event = contract["expected_frames"][1].as_str().unwrap();
    let error = contract["expected_error_frames"][1].as_str().unwrap();
    let (sender, receiver) = mpsc::channel(1);
    let (cancel, mut cancelled) = watch::channel(false);
    let mut stream = DisconnectStream::new(receiver, cancel);
    sender.send(Ok(connected.into())).await.unwrap();
    assert_eq!(stream.next().await.unwrap().unwrap(), connected);
    tokio::time::advance(Duration::from_secs(14)).await;
    sender.send(Ok(event.into())).await.unwrap();
    assert_eq!(stream.next().await.unwrap().unwrap(), event);
    assert!(tokio::time::timeout(Duration::from_secs(14), stream.next())
        .await
        .is_err());
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("idle deadline restarts after a real event")
            .unwrap()
            .unwrap(),
        ": keep-alive\n\n"
    );

    // A client that stops reading must not accumulate heartbeat frames.
    tokio::time::advance(Duration::from_secs(300)).await;
    sender.send(Ok(error.into())).await.unwrap();
    assert_eq!(stream.next().await.unwrap().unwrap(), error);
    assert!(tokio::time::timeout(Duration::from_secs(14), stream.next())
        .await
        .is_err());
    tokio::time::advance(Duration::from_secs(1)).await;
    drop(sender);
    assert!(
        stream.next().await.is_none(),
        "EOF wins over a ready heartbeat"
    );
    drop(stream);
    cancelled.changed().await.expect("cancellation signal");
    assert!(*cancelled.borrow());
}

struct PendingEventStream {
    dropped: Arc<AtomicBool>,
}

impl Stream for PendingEventStream {
    type Item = Result<GatewayDomainEvent, SecurityError>;

    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Pending
    }
}

impl Drop for PendingEventStream {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

struct TrackingEventProvider {
    subscribed: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}

struct ErrorEventProvider;

#[async_trait]
impl EventStreamProvider for ErrorEventProvider {
    async fn subscribe(
        &self,
        _: EventStreamSubscription,
    ) -> Result<GatewayDomainEventStream, SecurityError> {
        Err(SecurityError::ProviderUnavailable(
            "event stream unavailable".into(),
        ))
    }
}

#[tokio::test]
async fn sse_backend_failure_preserves_the_public_stream_error_frame() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/gateway-sse-behavior.json"
    ))
    .expect("SSE contract");
    let response = gateway_router(runtime_state_with_events(Arc::new(ErrorEventProvider)))
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/notifications/events/push?{}",
                    contract["valid_query"].as_str().unwrap()
                ))
                .header("cookie", "sessionId=valid")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
        .await
        .expect("error stream body");
    let expected = contract["expected_error_frames"]
        .as_array()
        .unwrap()
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<_>>>()
        .unwrap()
        .join("");
    assert_eq!(String::from_utf8(body.to_vec()).unwrap(), expected);
}

#[async_trait]
impl EventStreamProvider for TrackingEventProvider {
    async fn subscribe(
        &self,
        _: EventStreamSubscription,
    ) -> Result<GatewayDomainEventStream, SecurityError> {
        self.subscribed.store(true, Ordering::SeqCst);
        Ok(Box::pin(PendingEventStream {
            dropped: Arc::clone(&self.dropped),
        }))
    }
}

#[tokio::test]
async fn client_disconnect_drops_the_live_backend_subscription() {
    let subscribed = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let state = runtime_state_with_events(Arc::new(TrackingEventProvider {
        subscribed: Arc::clone(&subscribed),
        dropped: Arc::clone(&dropped),
    }));
    let response = gateway_router(state)
        .oneshot(
            Request::builder()
                .uri("/v1/notifications/events/push?organization_id=org-1")
                .header("cookie", "sessionId=valid")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    for _ in 0..20 {
        if subscribed.load(Ordering::SeqCst) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(subscribed.load(Ordering::SeqCst));
    drop(response);
    for _ in 0..20 {
        if dropped.load(Ordering::SeqCst) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn organization_requests_and_responses_use_strict_public_contract() {
    let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/organizations")
                    .header("cookie", "sessionId=valid")
                    .header("x-request-id", "11111111-1111-4111-8111-111111111111")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"name":"example-issuer","display_name":"Example Issuer","org_type":"healthcare","visibility":"PUBLIC","join_mechanism":"open","requires_approval":true}"#.as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let request_id = response
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .expect("gateway request ID");
    assert_ne!(request_id, "11111111-1111-4111-8111-111111111111");
    assert!(uuid::Uuid::parse_str(request_id).is_ok());
    let body: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body"),
    )
    .expect("json");
    assert_eq!(body["name"], "example-issuer");
    assert!(body.get("join_code").is_none());
    assert!(body.get("contact_phone").is_none());
}

#[tokio::test]
async fn public_gateway_replaces_every_client_request_id() {
    let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/organizations")
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .header("x-request-id", "client-chosen")
                    .body(Body::from(
                        br#"{"name":"request-id-test","display_name":"Request ID Test","org_type":"healthcare","visibility":"PUBLIC","join_mechanism":"open","requires_approval":true}"#.as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let request_id = response
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .expect("gateway request ID");
    assert_ne!(request_id, "client-chosen");
    assert!(uuid::Uuid::parse_str(request_id).is_ok());
}

#[tokio::test]
async fn issuer_entities_use_strict_public_trust_contract() {
    let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/issuer-entities")
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"organization_id":"org-1","issuer_id":"did:web:issuer.example","display_name":"Example Issuer","accreditations":[" ISO27001 "]}"#.as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
    let status = response.status();
    let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
        .await
        .expect("body");
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let body: Value = serde_json::from_slice(&body).expect("JSON");
    assert_eq!(body["issuer_id"], "did:web:issuer.example");
    assert_eq!(body["accreditations"], json!(["ISO27001"]));
    assert!(body.get("description").is_none());
    assert!(body.get("trust_anchor_id").is_none());
}

#[tokio::test]
async fn trust_lifecycle_requires_exact_action_tenant_and_machine_write_scope() {
    for action in ["activate", "suspend"] {
        let exact = if action == "activate" {
            "trust-profile:activate"
        } else {
            "trust-profile:suspend"
        };
        for (permission, owner, credential, expected) in [
            (exact, "org-1", "", StatusCode::UNAUTHORIZED),
            (exact, "org-1", "valid", StatusCode::OK),
            (
                "trust-profile:create",
                "org-1",
                "valid",
                StatusCode::FORBIDDEN,
            ),
            (
                "trust-profile:edit",
                "org-1",
                "valid",
                StatusCode::FORBIDDEN,
            ),
            (exact, "org-other", "valid", StatusCode::FORBIDDEN),
            (exact, "org-1", "trust-writer", StatusCode::OK),
            (exact, "org-1", "trust-reader", StatusCode::FORBIDDEN),
            (exact, "org-1", "trust-other", StatusCode::FORBIDDEN),
        ] {
            let recorder = Arc::new(ActorRecordingUpstream::default());
            let mut state = runtime_state_with_upstream(Arc::new(NoOwner), recorder.clone());
            let owned = Arc::get_mut(&mut state).unwrap();
            owned.memberships = Arc::new(SingleGrantMembership(permission));
            owned.owners = Arc::new(ScriptedOwner(Some(owner.into())));
            let path = format!("/v1/trust-profiles/profile-one/{action}");
            let mut request = Request::builder().method("POST").uri(&path);
            if credential == "valid" {
                request = request.header("cookie", "sessionId=valid");
            } else if !credential.is_empty() {
                request = request.header("x-api-key", credential);
            }
            let response = gateway_router(state)
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                expected,
                "{action} {permission} {owner} {credential}"
            );
            let payload = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .unwrap();
            let calls = recorder.0.lock().unwrap();
            assert_eq!(calls.len(), usize::from(expected == StatusCode::OK));
            if expected == StatusCode::OK {
                let (service, forwarded) = &calls[0];
                assert_eq!(service, "trust-profiles");
                assert_eq!(forwarded.path, path);
                assert_eq!(
                    forwarded.header("x-service-token"),
                    Some("s".repeat(32).as_str())
                );
                assert_eq!(forwarded.header("x-api-key"), None);
                let payload: Value = serde_json::from_slice(&payload).unwrap();
                assert_eq!(
                    payload["status"],
                    if action == "suspend" {
                        "suspended"
                    } else {
                        "active"
                    }
                );
            }
        }
    }
}

#[tokio::test]
async fn trust_profiles_use_canonical_policy_and_strict_public_projection() {
    let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/trust-profiles")
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .header("content-length", "999")
                    .body(Body::from(
                        br#"{"organization_id":"org-1","name":"Registry profile","trust_sources":[{"source_type":"trust_list","url":"https://registry.example/sync","registry_sync":{"protocol":"MARTY_TRUST_REGISTRY_SYNC_V1","refresh_interval_hours":24}}],"revocation_policy":{},"time_policy":{"require_freshness":true,"freshness_window_seconds":21600}}"#.as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
    let status = response.status();
    let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
        .await
        .expect("body");
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let body: Value = serde_json::from_slice(&body).expect("JSON");
    assert_eq!(body["status"], "draft");
    assert_eq!(body["trust_sources"][0]["source_type"], "TRUST_LIST");
    assert_eq!(body["system_issuer_overrides"], json!({}));
    assert!(body.get("description").is_none());
    assert!(body.get("revocation_services").is_none());
}

#[tokio::test]
async fn verification_flow_start_preflights_and_projects_in_rust() {
    let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/flows/verify")
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"presentation_policy_id":"policy-1","organization_id":"org-1","issuer_did":"did:web:verifier.example","request_uri_method":"post"}"#.as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
    let status = response.status();
    let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
        .await
        .expect("body");
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let body: Value = serde_json::from_slice(&body).expect("JSON");
    assert_eq!(body["instance_id"], "instance-1");
    assert_eq!(body["presentation_policy_id"], "policy-1");
    assert!(body.get("flow_definition_id").is_none());
    assert!(body.get("issuer_profile_id").is_none());
}

#[tokio::test]
async fn presentation_policy_uses_authoritative_template_format_and_public_projection() {
    let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/presentation-policies")
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"organization_id":"org-1","name":"Verify DTC","credential_requirements":[{"credential_template_id":"template-dtc","credential_payload_format":"caller-controlled","requested_claims":[{"claim_name":"document_number"}]}]}"#.as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
    let status = response.status();
    let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
        .await
        .expect("body");
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let body: Value = serde_json::from_slice(&body).expect("JSON");
    assert_eq!(
        body["credential_requirements"][0]["credential_payload_format"],
        "MDOC"
    );
    assert_eq!(body["holder_binding"], json!({"required": false}));
    assert!(body.get("issuer_profile_id").is_none());
    assert!(body.get("description").is_none());
}

#[tokio::test]
async fn explicit_jwt_vc_policy_crosses_the_public_gateway_write_and_readback_contract() {
    for (profile, format, template) in [
        (
            "w3c_vc2_jose_2026_v1",
            "VC_JWT_DIRECT_V1",
            "template-profiled-direct",
        ),
        (
            "marty_nested_vc2_jwt_v1",
            "VC_JWT",
            "template-profiled-historical",
        ),
    ] {
        let input = json!({"organization_id":"org-1","name":"Whole credential","holder_binding":{"required":true,"binding_methods":["DEVICE_KEY"],"proof_profiles":["OID4VP_VERIFIABLE_PRESENTATION"],"proof_freshness":{"challenge_required":true,"audience_binding_required":true,"replay_detection_required":true}},"credential_requirements":[{"credential_template_id":template,"credential_payload_format":format,"expected_securing_profile":profile,"requested_claims":[]}]});
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/presentation-policies")
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::from(input.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body["credential_requirements"][0]["expected_securing_profile"],
            profile
        );
        assert_eq!(
            body["credential_requirements"][0]["credential_payload_format"],
            format
        );
        assert_eq!(
            body["credential_requirements"][0]["requested_claims"],
            json!([])
        );
        assert_eq!(body["holder_binding"]["required"], true);
        for marker in [json!(null), json!("unknown_profile")] {
            let mut invalid = input.clone();
            invalid["credential_requirements"][0]["expected_securing_profile"] = marker;
            let response = runtime_router()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/presentation-policies")
                        .header("cookie", "sessionId=valid")
                        .header("content-type", "application/json")
                        .body(Body::from(invalid.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }
    }
}

#[tokio::test]
async fn flow_definitions_and_instances_use_rust_contracts() {
    let definition = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/flows/definitions")
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"organization_id":"org-1","name":"Issue employee","flow_type":"oid4vci_pre_authorized","credential_template_id":"template-1"}"#.as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
    let status = definition.status();
    let body = to_bytes(definition.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
        .await
        .expect("body");
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let definition: Value = serde_json::from_slice(&body).expect("JSON");
    assert_eq!(definition["id"], "flow-1");
    assert!(definition.get("private_execution_plan").is_none());
    assert!(definition.get("description").is_none());

    let instance = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/flows/instances")
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"organization_id":"org-1","flow_definition_id":"flow-1","initial_context":{"application_id":"application-1"}}"#.as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
    let status = instance.status();
    let body = to_bytes(instance.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
        .await
        .expect("body");
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let instance: Value = serde_json::from_slice(&body).expect("JSON");
    assert_eq!(instance["id"], "instance-1");
    assert_eq!(instance["context_data"]["application_id"], "application-1");
    assert!(instance.get("private_runtime").is_none());
}

#[tokio::test]
async fn credential_template_claims_are_canonicalized_and_losslessly_projected() {
    let response = runtime_router().oneshot(
            Request::builder().method("PATCH")
                .uri("/v1/credential-templates/template%2D1?organization_id=org-1")
                .header("cookie", "sessionId=valid").header("content-type", "application/json")
                .body(Body::from(br#"{"claims":[{"name":"birth_date","claim_type":"date","required":true,"selectively_disclosable":true,"namespace":"org.iso.18013.5.1"}]}"#.as_slice())).expect("request")
        ).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body"),
    )
    .expect("json");
    assert_eq!(body["claims"][0]["type"], "DATE");
    assert_eq!(body["claims"][0]["namespace"], "org.iso.18013.5.1");
    assert!(body.get("issuer_profile_id").is_none());
    assert_eq!(body["claims"][0]["derivable"], true);
    assert_eq!(body["claims"][0]["selectively_disclosable"], false);
    assert_eq!(body["claims"][0]["pattern"], "^[0-9]{4}-[0-9]{2}-[0-9]{2}$");
    assert_eq!(body["claims"][0]["enum_values"], json!([]));
    assert_eq!(body["claims"][0]["min_value"], 1);
    assert_eq!(body["claims"][0]["max_value"], 2);
    assert_eq!(body["claims"][0]["mdoc_element_identifier"], "birth_date");

    let create = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/credential-templates")
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::from(br#"{"organization_id":"org-1","name":"employee","credential_type":"EmployeeCredential","vct":"https://issuer.example/credentials/EmployeeCredential","claims":[{"name":"birth_date","claim_type":"date","required":true,"selectively_disclosable":true,"namespace":"org.iso.18013.5.1"}],"supported_formats":["sd_jwt_vc"],"compliance_profile_id":"profile-1","issuer_did":"did:web:issuer.example"}"#.as_slice()))
                    .expect("request"),
            )
            .await
            .expect("response");
    assert_eq!(create.status(), StatusCode::OK);
    let create: Value = serde_json::from_slice(
        &to_bytes(create.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body"),
    )
    .expect("json");
    assert_eq!(create["id"], "template-1");
    assert!(create.get("issuer_profile_id").is_none());
}

#[test]
fn template_issuer_context_normalizes_aliases_and_resolves_every_declared_format() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/gateway-credential-template-behavior.json"
    ))
    .unwrap();
    for case in contract["issuer_resolution_format_aliases"]
        .as_array()
        .unwrap()
    {
        let input = crate::template_issuer_options::OptionsRequest {
            organization_id: "org-1".into(),
            compliance_profile_id: "profile-1".into(),
            credential_payload_format: case["credential_payload_format"]
                .as_str()
                .map(str::to_owned),
            supported_formats: case
                .get("supported_formats")
                .map(|value| serde_json::from_value(value.clone()).unwrap()),
        };
        let primary = marty_credential_template::CredentialFormat::parse(
            case["expected_formats"][0].as_str().unwrap(),
        )
        .unwrap();
        let profile = json!({"id":"profile-1", "organization_id":"org-1", "status":"ACTIVE",
                "credential_format":primary.canonical(), "issuance_protocol":"OID4VCI_PRE_AUTH"});
        let context =
            crate::template_issuer_options::TemplateIssuerContext::from_profile(&input, &profile)
                .unwrap();
        let wire: Vec<_> = context
            .formats
            .iter()
            .map(|format| format.signing_wire())
            .collect();
        assert_eq!(json!(wire), case["expected_formats"], "{case}");
    }
}

#[test]
fn issuer_key_purpose_covers_physical_passport_and_existing_formats() {
    for (format, expected) in [
        ("ICAO_EMRTD", "x509_doc_signer"),
        ("icao-emrtd", "x509_doc_signer"),
        ("mso_mdoc", "mdoc_dsc"),
        ("VDS_NC", "vdsnc_signing"),
        ("jwt_vc_json", "vc_jwt_issuer"),
    ] {
        assert_eq!(issuer_key_purpose(Some(format)), expected);
    }
}

#[tokio::test]
async fn vc_api_verification_handler_adapts_to_canonical_policy_service() {
    let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(
                        "/v1/vc-api/credentials/verify?organization_id=org-1&presentation_policy_id=policy-1",
                    )
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"verifiableCredential":"header.payload.signature","options":{"challenge":"n","domain":"aud"}}"#
                            .as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
        .await
        .expect("body");
    let body: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(body["verified"], true);
    assert_eq!(body["results"]["decision"], "allow");
}

#[test]
fn vc_api_verification_handoff_uses_policy_service_authentication() {
    let state = runtime_state();
    let identity = TrustedIdentityContext {
        organization_id: Some("org-1".into()),
        user_id: Some("user-1".into()),
        ..TrustedIdentityContext::default()
    };
    let overrides = proxy_overrides(
        &state,
        "/v1/presentation-policies/policy-1/evaluate",
        &identity,
    );
    assert_eq!(
        overrides.headers.get("x-service-token"),
        state.service_token.as_ref()
    );
}

#[tokio::test]
async fn vc_api_documented_scope_and_input_failures_match_handlers() {
    let document = GatewayContract::load()
        .expect("gateway contract")
        .openapi_document("test");
    for (path, selection) in [
        (
            "/v1/vc-api/credentials/issue",
            "credential_template_id=template-1&issuer_did=did%3Aweb%3Aissuer.example",
        ),
        (
            "/v1/vc-api/credentials/verify",
            "presentation_policy_id=policy-1",
        ),
        (
            "/v1/vc-api/presentations/verify",
            "presentation_policy_id=policy-1",
        ),
    ] {
        for (query, expected) in [
            (String::new(), StatusCode::UNPROCESSABLE_ENTITY),
            (
                format!("?organization_id=org-other&{selection}"),
                StatusCode::FORBIDDEN,
            ),
            (
                format!("?organization_id=org-1&{selection}"),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ] {
            let response = runtime_router()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("{path}{query}"))
                        .header("cookie", "sessionId=valid")
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), expected, "{path}{query}");
            assert!(
                document["paths"][path]["post"]["responses"][expected.as_str()].is_object(),
                "runtime status must be documented for {path}"
            );
        }
    }
}

#[tokio::test]
async fn vc_api_issuance_handler_redeems_through_canonical_oid4vci_service() {
    let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(
                        "/v1/vc-api/credentials/issue?organization_id=org-1&credential_template_id=template-1&issuer_did=did%3Aweb%3Aissuer.example",
                    )
                    .header("cookie", "sessionId=valid")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"credential":{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"issuer":"did:web:issuer.example","credentialSubject":{"id":"did:example:subject"}}}"#
                            .as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
        .await
        .expect("body");
    let body: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(
        body["verifiableCredential"]["proof"]["cryptosuite"],
        "eddsa-rdfc-2022"
    );
}

#[tokio::test]
async fn credential_metadata_handler_is_public_cacheable_and_exact() {
    let response = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/credentials/marty-verified-member-badge")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "public, max-age=300");
    assert!(response.headers().contains_key("etag"));
    let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
        .await
        .expect("body");
    let body: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(
        body["vct"],
        "https://issuer.example/credentials/marty-verified-member-badge"
    );
}

#[tokio::test]
async fn discovery_and_health_handlers_are_gateway_owned_and_public() {
    let openid = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(openid.status(), StatusCode::OK);
    let openid: Value = serde_json::from_slice(
        &to_bytes(openid.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body"),
    )
    .expect("json");
    assert_eq!(openid["issuer"], "https://issuer.example");

    let mip = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/.well-known/mip-configuration")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(mip.status(), StatusCode::OK);
    let mip: Value = serde_json::from_slice(
        &to_bytes(mip.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body"),
    )
    .expect("json");
    assert_eq!(
        mip["supported_compliance_profiles"],
        json!(["OPEN_BADGES_3"])
    );

    let support = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/v1/protocol-support")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(support.status(), StatusCode::OK);
    let support: Value = serde_json::from_slice(
        &to_bytes(support.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body"),
    )
    .expect("json");
    assert_eq!(support, discovery::protocol_support_catalog());
    assert_eq!(support["entities"].as_array().map(Vec::len), Some(33));

    let health = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(health.status(), StatusCode::OK);
    let health: Value = serde_json::from_slice(
        &to_bytes(health.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body"),
    )
    .expect("json");
    assert_eq!(
        health,
        json!({"status": "healthy", "service": "api-gateway"})
    );

    let openapi = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(openapi.status(), StatusCode::OK);
    let openapi: Value = serde_json::from_slice(
        &to_bytes(openapi.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body"),
    )
    .expect("json");
    assert_eq!(openapi["openapi"], "3.1.0");
    assert_eq!(openapi["info"]["version"], "development");
    assert!(openapi["paths"]["/v1/flows/definitions"]["get"].is_object());
    assert_eq!(
        openapi["paths"]["/v1/protocol-support"]["get"]["responses"]["200"]["content"]
            ["application/json"]["schema"]["$ref"],
        "#/components/schemas/runtime__protocol_support_catalog"
    );

    for path in ["/docs", "/redoc"] {
        let docs = runtime_router()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(docs.status(), StatusCode::OK, "{path}");
        assert_eq!(docs.headers()["content-type"], "text/html; charset=utf-8");
    }

    for path in ["/ready", "/health/ready"] {
        let ready = runtime_router()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(ready.status(), StatusCode::OK, "{path}");
        let ready: Value = serde_json::from_slice(
            &to_bytes(ready.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body"),
        )
        .expect("json");
        assert_eq!(ready["status"], "ready");
        assert_eq!(ready["services"]["auth"]["status"], "healthy");
    }

    let services = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/health/services")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(services.status(), StatusCode::OK);
}

#[tokio::test]
async fn well_known_routes_proxy_and_apply_wallet_specific_normalization() {
    let response = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/org/org-1/waltid/.well-known/openid-credential-issuer")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body"),
    )
    .expect("json");
    assert_eq!(
        body["credential_issuer"],
        "https://issuer.example/org/org-1/waltid"
    );
    assert!(body["credentials_supported"].is_array());

    let response = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/credentials/default")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn public_did_web_routes_use_the_canonical_signing_service() {
    let response = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/orgs/Acme/did.json")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/did+json");
    assert_eq!(response.headers()["cache-control"], "public, max-age=300");
    let body: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body"),
    )
    .expect("DID JSON");
    assert_eq!(body["id"], "did:web:issuer.example%3A8443:orgs:acme");

    let response = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/.well-known/did.json")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body"),
    )
    .expect("root DID JSON");
    assert_eq!(body["id"], "did:web:issuer.example%3A8443");

    let response = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/orgs/..%2F..%2Fetc/did.json")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn internal_profile_reads_and_deletes_use_dedicated_auth_and_rust_store() {
    let unauthorized = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/internal/signing-keys/issuer-profiles?organization_id=org-1")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let profiles = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/internal/signing-keys/issuer-profiles?organization_id=org-1")
                .header("x-api-key", "internal-signing-key")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(profiles.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &to_bytes(profiles.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body"),
    )
    .expect("profiles JSON");
    assert_eq!(body["profiles"][0]["id"], "profile-1");

    let deleted = runtime_router()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/internal/signing-keys/issuer-profiles/profile-1?organization_id=org-1")
                .header("x-api-key", "internal-signing-key")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(deleted.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &to_bytes(deleted.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body"),
    )
    .expect("delete JSON");
    assert_eq!(body, json!({"ok": true, "deleted": "profile-1"}));
}

#[tokio::test]
async fn retired_flow_private_key_envelope_routes_are_unavailable() {
    for action in ["wrap", "unwrap"] {
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/internal/signing-keys/flow-key-envelopes/{action}?organization_id=org-1"
                    ))
                    .header("x-api-key", "internal-signing-key")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn legacy_gateway_integration_secret_routes_are_absent() {
    for operation in ["encrypt", "decrypt"] {
        let response = runtime_router()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!(
                            "/internal/signing-keys/integration-secrets/{operation}?organization_id=org-1"
                        ))
                        .header("x-api-key", "internal-signing-key")
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .expect("request"),
                )
                .await
                .expect("response");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn passport_artifact_routes_are_internal_and_tenant_scoped() {
    let body = br#"{"artifact_id":"artifact-1","chunk_index":0,"chunk_count":1,"plaintext_b64":"cGFzc3BvcnQ="}"#;
    let unauthorized = runtime_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/signing-keys/passport-artifacts/encrypt?organization_id=org-1")
                .body(Body::from(body.as_slice()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    let encrypted = runtime_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/signing-keys/passport-artifacts/encrypt?organization_id=org-1")
                .header("x-api-key", "internal-signing-key")
                .body(Body::from(body.as_slice()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(encrypted.status(), StatusCode::OK);
    let encrypted: Value = serde_json::from_slice(
        &to_bytes(encrypted.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body"),
    )
    .expect("encrypted JSON");
    assert_eq!(encrypted["ciphertext"], "vault:v1:synthetic");
    let decrypted = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/signing-keys/passport-artifacts/decrypt?organization_id=org-1")
                    .header("x-api-key", "internal-signing-key")
                    .body(Body::from(
                        br#"{"artifact_id":"artifact-1","chunk_index":0,"chunk_count":1,"ciphertext":"vault:v1:synthetic"}"#.as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
    assert_eq!(decrypted.status(), StatusCode::OK);
}

#[tokio::test]
async fn passport_callback_routes_are_internal_and_tenant_scoped() {
    let unsigned = runtime_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/signing-keys/passport-callbacks/sign?organization_id=org-1")
                .header("x-api-key", "internal-signing-key")
                .body(Body::from(r#"{"body_b64":"c3ludGhldGlj"}"#))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(unsigned.status(), StatusCode::NOT_FOUND);
    let verified = runtime_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/signing-keys/passport-callbacks/verify?organization_id=org-1")
                .header("x-api-key", "internal-signing-key")
                .body(Body::from(
                    r#"{"body_b64":"c3ludGhldGlj","signature":"vault:v1:synthetic"}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(verified.status(), StatusCode::OK);
}

#[tokio::test]
async fn issuer_context_rejects_profile_selectors_and_delegates_did_resolution() {
    let rejected = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/internal/signing-keys/issuer-context?organization_id=org-1&issuer_profile_id=private-selector")
                    .header("x-api-key", "internal-signing-key")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
    assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let resolved = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/internal/signing-keys/issuer-context?organization_id=org-1&issuer_did=did%3Aweb%3Aissuer.example&credential_format=dc%2Bsd-jwt&key_purpose=vc_jwt_issuer&algorithm=ES256")
                    .header("x-api-key", "internal-signing-key")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
    assert_eq!(resolved.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &to_bytes(resolved.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body"),
    )
    .expect("issuer context JSON");
    assert_eq!(body["issuer_profile_id"], "profile-1");
    assert_eq!(body["issuer_did"], "did:web:issuer.example");
}

#[tokio::test]
async fn issuer_identity_routes_delegate_only_trusted_organization_scope() {
    let resolved = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/internal/signing-keys/resolve-issuer-did?organization_id=org-1&issuer_did=did%3Aweb%3Aissuer.example&key_purpose=vc_jwt_issuer&algorithm=ES256")
                    .header("x-api-key", "internal-signing-key")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
    assert_eq!(resolved.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &to_bytes(resolved.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body"),
    )
    .expect("issuer identity JSON");
    assert_eq!(
        body["verification_method_id"],
        "did:web:issuer.example#issuer-key"
    );

    for (path, expected_field) in [
            (
                "/internal/signing-keys/issuer-profiles/profile-1/identity?organization_id=org-1",
                "did_document",
            ),
            (
                "/internal/signing-keys/issuer-profiles/profile-1/public-identity?organization_id=org-1",
                "x5c",
            ),
        ] {
            let response = runtime_router()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header("x-api-key", "internal-signing-key")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::OK);
            let body: Value = serde_json::from_slice(
                &to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                    .await
                    .expect("body"),
            )
            .expect("profile identity JSON");
            assert_eq!(body["issuer_profile_id"], "profile-1");
            assert!(body.get(expected_field).is_some());
        }

    let rejected = runtime_router()
            .oneshot(
                Request::builder()
                    .uri("/internal/signing-keys/resolve-issuer-did?organization_id=org-1&issuer_did=did%3Aweb%3Aissuer.example&issuer_profile_id=private-selector")
                    .header("x-api-key", "internal-signing-key")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
    assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn csca_trust_anchors_are_internal_and_do_not_expose_custody_routing() {
    let unauthorized = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/internal/signing-keys/csca-trust-anchors?organization_id=org-1")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    let response = runtime_router()
        .oneshot(
            Request::builder()
                .uri("/internal/signing-keys/csca-trust-anchors?organization_id=org-1")
                .header("x-api-key", "internal-signing-key")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body"),
    )
    .expect("trust anchor JSON");
    assert_eq!(body[0]["certificate_id"], "csca-1");
    assert!(body[0].get("key_reference").is_none());
}

#[tokio::test]
async fn retired_service_sign_route_is_unavailable_and_did_sign_keeps_trusted_scope() {
    let direct = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/signing-keys/services/service-1/sign?organization_id=org-1")
                    .header("x-api-key", "internal-signing-key")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"organization_id":"attacker","payload_b64":"cGF5bG9hZA","algorithm":"ES256"}"#.as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
    assert_eq!(direct.status(), StatusCode::NOT_FOUND);

    let shared = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/signing-keys/issuer-dids/sign?organization_id=org-1")
                    .header("x-api-key", "internal-signing-key")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"organization_id":"org-1","issuer_did":"did:web:issuer.example","credential_format":"dc+sd-jwt","key_purpose":"vc_jwt_issuer","algorithm":"ES256","payload_b64":"cGF5bG9hZA"}"#.as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
    assert_eq!(shared.status(), StatusCode::UNAUTHORIZED);

    let did = runtime_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/internal/signing-keys/issuer-dids/sign?organization_id=org-1")
                    .header("x-api-key", "dedicated-issuer-sign-key-000001")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        br#"{"organization_id":"attacker","issuer_did":"did:web:issuer.example","credential_format":"dc+sd-jwt","key_purpose":"vc_jwt_issuer","algorithm":"ES256","payload_b64":"cGF5bG9hZA"}"#.as_slice(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
    assert_eq!(did.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &to_bytes(did.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .expect("body"),
    )
    .expect("DID sign JSON");
    assert!(body.get("service_id").is_none());
    assert_eq!(body["issuer_did"], "did:web:issuer.example");
}

#[tokio::test]
async fn internal_issuer_sign_relays_only_a_bounded_grant_header() {
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let router = gateway_router(runtime_state_with_upstream(
        Arc::new(NoOwner),
        recorder.clone(),
    ));
    let grant = marty_signing_grant::GrantEnvelope {
        claims: marty_signing_grant::GrantClaims {
            version: 1,
            origin: marty_signing_grant::SigningOrigin::FlowWalletRequest,
            operation_id: "instance-1".into(),
            organization_id: "org-1".into(),
            route: "/internal/compat/issuer-dids/sign".into(),
            service_id: None,
            issuer_did: Some("did:web:issuer.example".into()),
            key_reference: None,
            key_purpose: "vc_jwt_issuer".into(),
            algorithm: "ES256".into(),
            payload_sha256_b64: marty_signing_grant::payload_digest(b"payload"),
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_030,
            nonce: "0123456789abcdef0123456789abcdef".into(),
        },
        hmac: "vault:v1:synthetic".into(),
    };
    let header = grant.to_header_value().unwrap();
    let request = |header: &str| {
        Request::builder()
                .method("POST")
                .uri("/internal/signing-keys/issuer-dids/sign?organization_id=org-1")
                .header("x-api-key", "dedicated-issuer-sign-key-000001")
                .header("content-type", "application/json")
                .header(marty_signing_grant::HEADER_NAME, header)
                .body(Body::from(r#"{"organization_id":"attacker","issuer_did":"did:web:issuer.example","credential_format":"dc+sd-jwt","key_purpose":"vc_jwt_issuer","algorithm":"ES256","payload_b64":"cGF5bG9hZA"}"#))
                .unwrap()
    };
    let denied = router
        .clone()
        .oneshot(request("not-base64!"))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(recorder.0.lock().unwrap().is_empty());
    let accepted = router.oneshot(request(&header)).await.unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    let calls = recorder.0.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1.path, "/internal/compat/issuer-dids/sign");
    assert_eq!(
        calls[0].1.header(marty_signing_grant::HEADER_NAME),
        Some(header.as_str())
    );
    assert_eq!(
        serde_json::from_slice::<Value>(calls[0].1.body.as_deref().unwrap()).unwrap()
            ["organization_id"],
        "org-1"
    );
}

#[tokio::test]
async fn profile_write_routes_wrap_body_with_trusted_scope() {
    for (method, path, input, expected) in [
        (
            "POST",
            "/internal/signing-keys/issuer-profiles?organization_id=org-1",
            json!({"organization_id": "attacker", "issuer_did": "did:web:issuer.example"}),
            "profile",
        ),
        (
            "PATCH",
            "/internal/signing-keys/issuer-profiles/profile-1?organization_id=org-1",
            json!({"organization_id": "attacker", "status": "active"}),
            "profile",
        ),
        (
            "PUT",
            "/internal/signing-keys/issuer-profiles/profile-1/certificate?organization_id=org-1",
            json!({"organization_id": "attacker", "cert_pem": "certificate"}),
            "issuer_profile_id",
        ),
    ] {
        let response = runtime_router()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("x-api-key", "internal-signing-key")
                    .header("content-type", "application/json")
                    .body(Body::from(input.to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .expect("body"),
        )
        .expect("profile write JSON");
        assert!(body.get(expected).is_some());
    }
}

#[test]
fn applicant_evidence_summary_route_is_exact() {
    assert_eq!(
        applicant_evidence_summary_route(
            "/v1/organizations/org-1/applicants/app-1/evidence-summary"
        ),
        Some(("org-1", "app-1"))
    );
    assert_eq!(
        applicant_evidence_summary_route("/v1/organizations/org-1/applicants/app-1/evidence-facts"),
        None
    );
}

#[test]
fn applicant_evidence_projects_to_reviewer_safe_fact() {
    let projected = applicant_evidence_fact(&json!({
        "id": "evidence-1",
        "organization_id": "org-1",
        "application_id": "app-1",
        "evidence_requirement_id": "passport",
        "evidence_type": "EMRTD",
        "source": "applicant_upload",
        "media_type": "application/octet-stream",
        "filename": "passport.bin",
        "size_bytes": 42,
        "sha256": "abc123",
        "status": "ACTIVE",
        "submitted_by": "applicant-1",
        "captured_at": "2026-08-28T09:00:00Z",
        "content_url": "/v1/evidence/evidence-1/content",
        "created_at": "2026-08-28T09:01:00Z",
        "updated_at": "2026-08-28T09:02:00Z"
    }));
    assert_eq!(projected["provider"], "applicant_upload");
    assert_eq!(projected["fact_type"], "EMRTD");
    assert_eq!(projected["assertion"]["sha256"], "abc123");
    assert_eq!(projected["verification"]["method"], "sha-256");
    assert_eq!(projected["observed_at"], "2026-08-28T09:00:00Z");
}

#[test]
fn applicant_evidence_identity_is_exact_and_fail_closed() {
    let evidence = json!({
        "organization_id": "org-1",
        "application_id": "app-1"
    });
    assert!(applicant_evidence_identity_matches(
        &evidence, "org-1", "app-1"
    ));
    assert!(!applicant_evidence_identity_matches(
        &evidence,
        "org-other",
        "app-1"
    ));
    assert!(!applicant_evidence_identity_matches(
        &evidence,
        "org-1",
        "app-other"
    ));
    assert!(!applicant_evidence_identity_matches(
        &json!({"organization_id":"org-1"}),
        "org-1",
        "app-1"
    ));
}

#[tokio::test]
async fn public_verification_forwards_capability_without_browser_authority_or_cache_reuse() {
    let (router, recorder) = actor_test_router();
    let id = "54cfd66e-b7ed-8926-9f8b-18e63fa83797";
    for (method, path) in [
        ("GET", "/v1/flows/public/verification/catalog".into()),
        ("POST", "/v1/flows/public/verification/sessions".into()),
        (
            "GET",
            format!("/v1/flows/public/verification/sessions/{id}"),
        ),
        (
            "POST",
            format!("/v1/flows/public/verification/sessions/{id}/cancel"),
        ),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(&path)
            .header("content-type", "application/json")
            .header("origin", "https://site.example")
            .header("x-verification-session", "opaque-visitor-capability")
            .header("x-user-id", "forged")
            .header("x-organization-id", "forged")
            .header("x-api-key-id", "forged")
            .header("x-api-key-scopes", "*")
            .header("x-service-token", "forged")
            .header("x-authenticated-user-id", "forged")
            .header("authorization", "Bearer irrelevant")
            .header("cookie", "sessionId=actor-session")
            .header("if-none-match", "*")
            .header("idempotency-key", "shared-key")
            .body(Body::from(if method == "POST" { "{}" } else { "" }))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(response.headers().get("etag").is_none());
    }
    {
        let calls = recorder.0.lock().unwrap();
        assert_eq!(calls.len(), 4);
        for (service, request) in calls.iter() {
            assert_eq!(service, "flows");
            assert_eq!(request.header("origin"), Some("https://site.example"));
            assert_eq!(
                request.header("x-verification-session"),
                Some("opaque-visitor-capability")
            );
            for name in [
                "x-user-id",
                "x-organization-id",
                "x-api-key-id",
                "x-api-key-scopes",
                "x-authenticated-user-id",
                "authorization",
                "cookie",
                "idempotency-key",
            ] {
                assert_eq!(request.header(name), None, "{name}");
            }
            assert_eq!(
                request.header("x-service-token"),
                Some("s".repeat(32).as_str())
            );
        }
    }
    for path in [
        "/v1/flows/definitions",
        "/v1/flows/instances",
        "/v1/flows/instances/flow-1/result",
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("x-verification-session", "opaque-visitor-capability")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
    assert_eq!(recorder.0.lock().unwrap().len(), 4);
}

#[tokio::test]
async fn public_verification_rejects_header_ambiguity_and_oversized_requests_before_forwarding() {
    let (router, recorder) = actor_test_router();
    for name in ["origin", "x-verification-session"] {
        let mut request = Request::builder()
            .method("POST")
            .uri("/v1/flows/public/verification/sessions")
            .header("content-type", "application/json")
            .header(name, "first")
            .body(Body::from("{}"))
            .unwrap();
        request
            .headers_mut()
            .append(name, HeaderValue::from_static("second"));
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/flows/public/verification/sessions")
                .header("content-type", "application/json")
                .body(Body::from("x".repeat(4_097)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(recorder.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn public_verification_keeps_anonymous_request_limits_and_ignores_capability_for_gateway_cache_identity(
) {
    let recorder = Arc::new(ActorRecordingUpstream::default());
    let mut state = Arc::into_inner(runtime_state_with_upstream(
        Arc::new(NoOwner),
        recorder.clone(),
    ))
    .unwrap();
    state.rate_limiter =
        Arc::new(GatewayRateLimiter::new(Arc::new(InMemoryRateLimiter::default()), 2).unwrap());
    let router = gateway_router(Arc::new(state.with_client_ip_observation(false)));
    for index in 0..3 {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/flows/public/verification/sessions")
                    .header("content-type", "application/json")
                    .header("x-verification-session", format!("capability-{index}"))
                    .header("idempotency-key", "same-key")
                    .header("x-forwarded-for", format!("203.0.113.{index}"))
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if index < 2 {
                StatusCode::OK
            } else {
                StatusCode::TOO_MANY_REQUESTS
            }
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    let calls = recorder.0.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[0].1.header("x-verification-session"),
        Some("capability-0")
    );
    assert_eq!(
        calls[1].1.header("x-verification-session"),
        Some("capability-1")
    );
}
