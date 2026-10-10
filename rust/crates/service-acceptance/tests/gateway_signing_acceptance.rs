//! Real Gateway-to-Signing-Keys acceptance with disposable Redis/OpenBao.
//! These are opt-in, CI-owned tests; none use a production datastore.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{atomic::Ordering, Arc},
};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    extract::{Path, Request, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, get},
    Json, Router,
};
use marty_gateway::{
    authorization::{OrganizationMembership, OrganizationMembershipProvider},
    contract::GatewayContract,
    discovery::ReleaseIdentity,
    middleware::{ApiKeyIdentity, GatewayIdentityProvider, GatewayRateLimiter, SessionIdentity},
    registry::StaticServiceRegistry,
    runtime::{
        gateway_router, EventStreamProvider, EventStreamSubscription, GatewayDomainEventStream,
        GatewayRuntimeState, ReadinessProvider, ReadinessServiceStatus, ResourceOwnerContext,
        ResourceOwnerProvider,
    },
    transport::ReqwestUpstream,
};
use marty_signing_keys::{
    csca_lifecycle::CscaLifecycleStore,
    documents::{DocumentStore as SigningDocumentStore, PublishJwkRequest},
    http::{
        router_with_dependencies_and_ceremony_keys,
        router_with_dependencies_and_sign_key as signing_router,
    },
    profiles::ProfileStore as SigningProfileStore,
    registry::RegistryStore as SigningRegistryStore,
};
use mmf_platform::{GatewayProxy, InMemoryIdempotencyStore, ProxyConfig};
use mmf_security::{InMemoryRateLimiter, SecurityError};
use redis::AsyncCommands;
use serde_json::{json, Value};
use tower::ServiceExt;

const DEFAULT_MAXIMUM_BODY_BYTES: usize = 10 * 1024 * 1024;

struct SigningIdentity {
    organization_id: String,
}

#[async_trait]
impl GatewayIdentityProvider for SigningIdentity {
    async fn validate_session(
        &self,
        session_id: &str,
    ) -> Result<Option<SessionIdentity>, SecurityError> {
        Ok((session_id == "valid").then(|| SessionIdentity {
            user_id: "user-1".into(),
            organization_id: Some(self.organization_id.clone()),
            ..SessionIdentity::default()
        }))
    }

    async fn validate_api_key(&self, _: &str) -> Result<Option<ApiKeyIdentity>, SecurityError> {
        Ok(None)
    }
}

#[async_trait]
impl OrganizationMembershipProvider for SigningIdentity {
    async fn get_membership(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<Option<OrganizationMembership>, SecurityError> {
        if organization_id != self.organization_id || organization_id == "org-other" {
            return Ok(None);
        }
        Ok(Some(OrganizationMembership {
            user_id: user_id.into(),
            organization_id: organization_id.into(),
            status: "active".into(),
            role_names: BTreeSet::from(["key-manager".into()]),
            permissions: BTreeSet::from(["signing-key:view".into(), "signing-key:create".into()]),
            is_owner: false,
        }))
    }
}

struct UnusedGatewayProvider;

#[async_trait]
impl ResourceOwnerProvider for UnusedGatewayProvider {
    async fn resolve_organization(
        &self,
        _: &str,
        _: &str,
        _: &ResourceOwnerContext,
    ) -> Result<Option<String>, SecurityError> {
        Ok(None)
    }
}

#[async_trait]
impl ReadinessProvider for UnusedGatewayProvider {
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
impl EventStreamProvider for UnusedGatewayProvider {
    async fn subscribe(
        &self,
        _: EventStreamSubscription,
    ) -> Result<GatewayDomainEventStream, SecurityError> {
        panic!("signing acceptance does not use event streams")
    }
}

async fn disposable_signing_redis_url() -> String {
    let url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
    let parsed = reqwest::Url::parse(&url).expect("disposable Redis URL syntax");
    assert!(matches!(
        parsed.host_str(),
        Some("127.0.0.1" | "localhost" | "::1")
    ));
    assert!(parsed
        .path()
        .trim_start_matches('/')
        .parse::<u8>()
        .is_ok_and(|db| db >= 13));
    let nonce = std::env::var("MARTY_TEST_REDIS_DISPOSABLE_NONCE")
        .expect("disposable Redis sentinel value");
    assert!(nonce.len() >= 16, "disposable Redis sentinel is too short");
    let client = redis::Client::open(url.as_str()).expect("disposable Redis client");
    let mut connection = client.get_multiplexed_async_connection().await.unwrap();
    let observed: Option<String> = connection
        .get("marty:tests:disposable-guard")
        .await
        .unwrap();
    assert_eq!(observed.as_deref(), Some(nonce.as_str()));
    url
}

#[derive(Clone, Default)]
struct GatewayTransitFixture {
    keys: Arc<std::sync::Mutex<BTreeMap<String, String>>>,
    creates: Arc<std::sync::Mutex<Vec<(String, String)>>>,
    signs: Arc<std::sync::Mutex<Vec<(String, Value)>>>,
}

fn gateway_transit_authorized(headers: &HeaderMap) -> bool {
    headers
        .get("x-vault-token")
        .and_then(|value| value.to_str().ok())
        == Some("test-only")
}

struct DisposableDscIdentity {
    organization_id: String,
    dsc_operator: bool,
    csca_operator: bool,
}

#[async_trait]
impl GatewayIdentityProvider for DisposableDscIdentity {
    async fn validate_session(
        &self,
        session_id: &str,
    ) -> Result<Option<SessionIdentity>, SecurityError> {
        Ok((session_id == "valid").then(|| SessionIdentity {
            user_id: "disposable-gateway-operator".into(),
            organization_id: Some(self.organization_id.clone()),
            ..SessionIdentity::default()
        }))
    }

    async fn validate_api_key(
        &self,
        api_key: &str,
    ) -> Result<Option<ApiKeyIdentity>, SecurityError> {
        Ok(
            (api_key == "disposable-gateway-internal-key").then(|| ApiKeyIdentity {
                api_key_id: "disposable-api-key".into(),
                organization_id: Some(self.organization_id.clone()),
                key_prefix: None,
                scopes: vec!["admin:full".into()],
            }),
        )
    }
}

#[async_trait]
impl OrganizationMembershipProvider for DisposableDscIdentity {
    async fn get_membership(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<Option<OrganizationMembership>, SecurityError> {
        if organization_id != self.organization_id {
            return Ok(None);
        }
        let mut membership = SigningIdentity {
            organization_id: self.organization_id.clone(),
        }
        .get_membership(user_id, organization_id)
        .await?;
        if self.dsc_operator || self.csca_operator {
            if let Some(membership) = membership.as_mut() {
                membership.role_names.insert("operator".into());
                if self.dsc_operator {
                    membership
                        .permissions
                        .insert("passport-certificate:issue".into());
                }
                if self.csca_operator {
                    membership
                        .permissions
                        .insert("passport-certificate:issue-csca".into());
                }
            }
        }
        Ok(membership)
    }
}

fn signing_gateway_state(signing_url: String) -> Arc<GatewayRuntimeState> {
    let upstream = Arc::new(ReqwestUpstream::new(1024 * 1024).unwrap());
    let contract = GatewayContract::load().unwrap();
    let routes = contract
        .runtime_route_table_with_passport_native(false)
        .unwrap();
    let proxy_routes = contract
        .proxy_route_table_with_passport_native(false)
        .unwrap();
    let registry =
        StaticServiceRegistry::from_urls(&BTreeMap::from([("signing-keys".into(), signing_url)]))
            .unwrap();
    let proxy = GatewayProxy::new(
        proxy_routes,
        Arc::new(registry),
        upstream,
        ProxyConfig::default(),
    )
    .unwrap();
    let identity = Arc::new(SigningIdentity {
        organization_id: "org-1".into(),
    });
    Arc::new(
        GatewayRuntimeState::new(
            routes,
            proxy,
            identity.clone(),
            identity,
            Arc::new(UnusedGatewayProvider),
            Arc::new(UnusedGatewayProvider),
            Arc::new(UnusedGatewayProvider),
            vec!["auth".into()],
            GatewayRateLimiter::new(Arc::new(InMemoryRateLimiter::default()), 120).unwrap(),
            Arc::new(InMemoryIdempotencyStore::new(60_000, 5_000).unwrap()),
            ["https://beta.elevenidllc.com".into()],
            "https://issuer.example",
            "https://issuer.example",
            "issuer.example:8443",
            Some("org-root".into()),
            "internal-signing-key",
            "issuance-service-key",
            ReleaseIdentity::default(),
        )
        .unwrap()
        .with_service_token(Some("s".repeat(32)))
        .unwrap()
        .with_service_sign_gateway_key("dedicated-service-sign-gateway-key-000001".into())
        .unwrap(),
    )
}

fn gateway_with_signing_http(signing_url: String, organization_id: &str) -> Router {
    let mut state = signing_gateway_state(signing_url);
    let identity = Arc::new(SigningIdentity {
        organization_id: organization_id.to_owned(),
    });
    Arc::get_mut(&mut state).unwrap().identities = identity.clone();
    Arc::get_mut(&mut state).unwrap().memberships = identity;
    gateway_router(state)
}

fn gateway_with_signing_http_dsc(
    signing_url: String,
    dsc_key: Option<&str>,
    csca_key: Option<&str>,
    disposable_org: Option<(&str, bool, bool)>,
) -> Router {
    let mut state = signing_gateway_state(signing_url);
    if let Some(dsc_key) = dsc_key {
        let state = Arc::get_mut(&mut state).unwrap();
        state.dsc_issue_gateway_key = Some(dsc_key.to_owned());
    }
    if let Some(csca_key) = csca_key {
        let state = Arc::get_mut(&mut state).unwrap();
        state.csca_issue_gateway_key = Some(csca_key.to_owned());
        state.passport_native_gateway_enabled = true;
    }
    if let Some((organization_id, dsc_operator, csca_operator)) = disposable_org {
        let fixture = Arc::new(DisposableDscIdentity {
            organization_id: organization_id.to_owned(),
            dsc_operator,
            csca_operator,
        });
        let state = Arc::get_mut(&mut state).unwrap();
        state.identities = fixture.clone();
        state.memberships = fixture;
    }
    gateway_router(state)
}

async fn gateway_transit_create(
    State(fixture): State<GatewayTransitFixture>,
    Path(reference): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !gateway_transit_authorized(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(key_type) = body.get("type").and_then(Value::as_str) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    fixture
        .creates
        .lock()
        .unwrap()
        .push((reference.clone(), key_type.to_owned()));
    let mut keys = fixture.keys.lock().unwrap();
    if keys.contains_key(&reference) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"errors":["key already exists"]})),
        )
            .into_response();
    }
    keys.insert(reference, key_type.to_owned());
    StatusCode::NO_CONTENT.into_response()
}

async fn gateway_transit_read(
    State(fixture): State<GatewayTransitFixture>,
    Path(reference): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !gateway_transit_authorized(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(key_type) = fixture.keys.lock().unwrap().get(&reference).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let material = match key_type.as_str() {
        "ed25519" => "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        "ecdsa-p256" => "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt\n6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==\n-----END PUBLIC KEY-----\n",
        _ => return StatusCode::UNPROCESSABLE_ENTITY.into_response(),
    };
    Json(json!({"data": {
        "latest_version": 1, "type": key_type, "supports_signing": true,
        "soft_deleted": false, "exportable": false,
        "allow_plaintext_backup": false, "deletion_allowed": false,
        "imported_key": false,
        "keys": {"1": {"name": key_type, "public_key": material}}
    }}))
    .into_response()
}

async fn gateway_transit_list(
    State(fixture): State<GatewayTransitFixture>,
    headers: HeaderMap,
) -> Response {
    if !gateway_transit_authorized(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let keys = fixture
        .keys
        .lock()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    Json(json!({"data":{"keys":keys}})).into_response()
}

async fn gateway_transit_sign(
    State(fixture): State<GatewayTransitFixture>,
    Path(reference): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !gateway_transit_authorized(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !fixture.keys.lock().unwrap().contains_key(&reference) {
        return StatusCode::NOT_FOUND.into_response();
    }
    fixture.signs.lock().unwrap().push((reference, body));
    Json(json!({"data":{"signature":"vault:v1:AQ=="}})).into_response()
}

#[tokio::test]
#[ignore = "requires disposable MARTY_TEST_REDIS_URL and BAO_TOKEN=test-only"]
async fn authenticated_gateway_reaches_rust_managed_key_route_without_custody() {
    assert_eq!(std::env::var("BAO_TOKEN").as_deref(), Ok("test-only"));
    let redis_url = disposable_signing_redis_url().await;
    let organization_id = format!("gateway-managed-{}", uuid::Uuid::new_v4().simple());
    let fixture = GatewayTransitFixture::default();
    let kms = Router::new()
        .route("/v1/transit/keys", get(gateway_transit_list))
        .route(
            "/v1/transit/keys/{reference}",
            get(gateway_transit_read).post(gateway_transit_create),
        )
        .route(
            "/v1/transit/sign/{reference}",
            axum::routing::post(gateway_transit_sign),
        )
        .with_state(fixture.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let kms_server = tokio::spawn(async move { axum::serve(listener, kms).await.unwrap() });
    let store = SigningRegistryStore::connect(&redis_url)
        .await
        .unwrap()
        .with_managed_openbao(Some(endpoint.clone()));
    store
        .save(
            &organization_id,
            &marty_signing_keys::registry::empty_registry(),
        )
        .await
        .unwrap();
    let profiles = SigningProfileStore::from_connection(store.connection());
    let documents = SigningDocumentStore::from_connection(store.connection());
    let cleanup_store = store.clone();
    let signing = signing_router(
        "internal-signing-key".into(),
        Some("dedicated-service-sign-gateway-key-000001".into()),
        Some(store),
        Some(documents.clone()),
        None,
        Some(profiles.clone()),
        None,
        Some("issuer.example".into()),
    );
    let signing_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let signing_url = format!("http://{}", signing_listener.local_addr().unwrap());
    let signing_server =
        tokio::spawn(async move { axum::serve(signing_listener, signing).await.unwrap() });
    let gateway = gateway_with_signing_http(signing_url, &organization_id);
    let create = |cookie: bool| {
        let mut builder =
            Request::post("/v1/signing-keys").header("content-type", "application/json");
        if cookie {
            builder = builder.header("cookie", "sessionId=valid");
        }
        builder
            .body(Body::from(r#"{"name":"Gateway KMS key"}"#))
            .unwrap()
    };
    let denied = gateway.clone().oneshot(create(false)).await.unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    assert!(
        cleanup_store.load(&organization_id).await.unwrap()["key_reference_purposes"]
            .as_object()
            .unwrap()
            .is_empty()
    );
    let cross_tenant = gateway
        .clone()
        .oneshot(
            Request::post("/v1/signing-keys?organization_id=org-other")
                .header("content-type", "application/json")
                .header("cookie", "sessionId=valid")
                .body(Body::from(r#"{"name":"Wrong tenant"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cross_tenant.status(), StatusCode::FORBIDDEN);
    assert!(
        cleanup_store.load(&organization_id).await.unwrap()["key_reference_purposes"]
            .as_object()
            .unwrap()
            .is_empty()
    );
    let created = gateway.clone().oneshot(create(true)).await.unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let created: Value = serde_json::from_slice(
        &to_bytes(created.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .unwrap(),
    )
    .unwrap();
    let reference = created["provider_key_name"].as_str().unwrap();
    assert_eq!(created["key"]["public_jwk"]["crv"], "P-256");
    assert_eq!(
        fixture.keys.lock().unwrap().get(reference).unwrap(),
        "ecdsa-p256"
    );
    assert!(!created.to_string().contains("test-only"));
    assert!(!created.to_string().contains("private_key"));
    let service_sign_path = "/v1/signing-keys/services/managed-openbao-transit/sign";
    let service_sign_body = json!({
        "payload_b64": "cGF5bG9hZA", "key_reference": reference,
        "algorithm": "ES256"
    });
    let service_sign_request = |authenticated: bool| {
        let mut request =
            Request::post(service_sign_path).header("content-type", "application/json");
        if authenticated {
            request = request.header("cookie", "sessionId=valid");
        }
        request
            .body(Body::from(service_sign_body.to_string()))
            .unwrap()
    };
    let denied = gateway
        .clone()
        .oneshot(service_sign_request(false))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    assert!(fixture.signs.lock().unwrap().is_empty());
    let signed_service = gateway
        .clone()
        .oneshot(service_sign_request(true))
        .await
        .unwrap();
    let status = signed_service.status();
    let signed_service: Value = serde_json::from_slice(
        &to_bytes(signed_service.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status, StatusCode::OK, "{signed_service}");
    assert_eq!(signed_service["ok"], true);
    assert_eq!(fixture.signs.lock().unwrap().len(), 1);
    fixture.signs.lock().unwrap().clear();
    let listed = gateway
        .clone()
        .oneshot(
            Request::get("/v1/signing-keys")
                .header("cookie", "sessionId=valid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let listed: Value = serde_json::from_slice(
        &to_bytes(listed.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(listed["keys"]
        .as_array()
        .unwrap()
        .iter()
        .any(|key| key["id"] == reference));
    let detail = gateway
        .clone()
        .oneshot(
            Request::get(format!("/v1/signing-keys/{reference}"))
                .header("cookie", "sessionId=valid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(detail.status(), StatusCode::OK);
    let detail: Value = serde_json::from_slice(
        &to_bytes(detail.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(detail["id"], reference);
    assert_eq!(detail["public_jwk"]["crv"], "P-256");
    assert!(!detail.to_string().contains("test-only"));
    let issuer_did = format!(
        "did:web:issuer.example:orgs:{organization_id}-{}",
        uuid::Uuid::new_v4().simple()
    );
    let identity = json!({
        "organization_id": organization_id, "issuer_did": issuer_did,
        "key_purpose": "vc_jwt_issuer", "credential_format": "SD_JWT_VC",
        "algorithm": "EdDSA"
    });
    let request = |path: &str, body: &Value| {
        Request::post(path)
            .header("cookie", "sessionId=valid")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let denied = gateway
        .clone()
        .oneshot(
            Request::post("/v1/signing-keys/issuer-identities")
                .header("content-type", "application/json")
                .body(Body::from(identity.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    let foreign = gateway
        .clone()
        .oneshot(request(
            "/v1/signing-keys/issuer-identities?organization_id=org-other",
            &identity,
        ))
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::FORBIDDEN);
    let created = gateway
        .clone()
        .oneshot(request("/v1/signing-keys/issuer-identities", &identity))
        .await
        .unwrap();
    let status = created.status();
    let created: Value = serde_json::from_slice(
        &to_bytes(created.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(created["created"], true);
    assert_eq!(created["identity"]["issuer_did"], issuer_did);
    let profile = profiles.list(&organization_id).await.unwrap()["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|profile| profile["issuer_did"] == issuer_did)
        .unwrap()
        .clone();
    let profile_reference = profile["signing_key_reference"].as_str().unwrap();
    assert_eq!(profile["key_purpose"], "vc_jwt_issuer");
    assert!(profile_reference.starts_with("cred-issuer-"));
    assert_eq!(
        fixture.keys.lock().unwrap().get(profile_reference).unwrap(),
        "ed25519"
    );
    assert_eq!(
        fixture.creates.lock().unwrap().as_slice(),
        &[
            (reference.to_owned(), "ecdsa-p256".into()),
            (profile_reference.to_owned(), "ed25519".into())
        ]
    );
    let resolved = gateway
        .clone()
        .oneshot(request(
            "/v1/signing-keys/issuer-identities/resolve",
            &identity,
        ))
        .await
        .unwrap();
    let status = resolved.status();
    let resolved: Value = serde_json::from_slice(
        &to_bytes(resolved.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status, StatusCode::OK, "{resolved}");
    assert_eq!(resolved["public_jwk"]["crv"], "Ed25519");
    let sign_body = json!({
        "organization_id": "org-other", "issuer_did": issuer_did,
        "key_purpose": "vc_jwt_issuer", "credential_format": "SD_JWT_VC",
        "algorithm": "EdDSA", "payload_b64": "cGF5bG9hZA"
    });
    let denied_sign = gateway
        .clone()
        .oneshot(
            Request::post(format!(
                "/internal/signing-keys/issuer-dids/sign?organization_id={organization_id}"
            ))
            .header("content-type", "application/json")
            .body(Body::from(sign_body.to_string()))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied_sign.status(), StatusCode::UNAUTHORIZED);
    assert!(fixture.signs.lock().unwrap().is_empty());
    let signed = gateway
        .clone()
        .oneshot(
            Request::post(format!(
                "/internal/signing-keys/issuer-dids/sign?organization_id={organization_id}"
            ))
            .header("x-api-key", "internal-signing-key")
            .header("content-type", "application/json")
            .body(Body::from(sign_body.to_string()))
            .unwrap(),
        )
        .await
        .unwrap();
    let status = signed.status();
    let signed: Value = serde_json::from_slice(
        &to_bytes(signed.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status, StatusCode::OK, "{signed}");
    assert_eq!(signed["ok"], true);
    assert!(!signed["signature_b64"].as_str().unwrap().is_empty());
    assert_eq!(
        fixture.signs.lock().unwrap().as_slice(),
        &[(
            profile_reference.to_owned(),
            json!({"input":"cGF5bG9hZA==","prehashed":false})
        )]
    );
    for public in [&created, &resolved, &signed] {
        for secret in [&endpoint[..], "test-only", profile_reference] {
            assert!(!public.to_string().contains(secret), "{public}");
        }
    }
    let mut cleanup = cleanup_store.connection();
    let _: () = cleanup
        .del(marty_signing_keys::registry::storage_key(&organization_id))
        .await
        .unwrap();
    let _: () = cleanup
        .del(marty_signing_keys::profiles::storage_key(&organization_id))
        .await
        .unwrap();
    let _: usize = redis::cmd("DEL")
        .arg(marty_signing_keys::documents::jwks_storage_key(
            &organization_id,
        ))
        .arg(marty_signing_keys::documents::did_storage_key(
            &organization_id,
            None,
        ))
        .arg(marty_signing_keys::documents::did_storage_key(
            &organization_id,
            Some(&issuer_did),
        ))
        .arg(marty_signing_keys::documents::slug_storage_key(
            issuer_did.rsplit(':').next().unwrap(),
        ))
        .query_async(&mut cleanup)
        .await
        .unwrap();
    signing_server.abort();
    kms_server.abort();
}

async fn disposable_signing_openbao() -> (String, String) {
    let endpoint = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
    let parsed_bao = url::Url::parse(&endpoint).expect("disposable OpenBao URL syntax");
    assert!(
        parsed_bao.scheme() == "http" && parsed_bao.host_str() == Some("127.0.0.1"),
        "CSR test requires a loopback disposable OpenBao instance"
    );
    let token = std::env::var("MARTY_TEST_OPENBAO_TOKEN").expect("disposable OpenBao token");
    assert!(
        std::env::var("BAO_TOKEN").ok().as_deref() == Some(token.as_str()),
        "disposable OpenBao token binding does not match"
    );
    let bao_nonce = std::env::var("MARTY_TEST_OPENBAO_DISPOSABLE_NONCE")
        .expect("pre-provisioned disposable OpenBao sentinel value");
    assert!(
        bao_nonce.len() >= 16,
        "disposable OpenBao sentinel is too short"
    );
    let marker = reqwest::Client::new()
        .get(
            parsed_bao
                .join("/v1/secret/data/marty-test-disposable-guard")
                .expect("disposable OpenBao sentinel URL"),
        )
        .header("X-Vault-Token", &token)
        .send()
        .await
        .expect("disposable OpenBao sentinel read");
    assert!(
        marker.status().is_success(),
        "disposable OpenBao sentinel is absent"
    );
    let marker: Value = marker
        .json()
        .await
        .expect("disposable OpenBao sentinel JSON");
    assert!(
        marker["data"]["data"]["nonce"].as_str() == Some(bao_nonce.as_str()),
        "disposable OpenBao sentinel does not match"
    );
    (endpoint, token)
}

#[tokio::test]
#[ignore = "requires independently marked disposable Redis and OpenBao instances"]
async fn authenticated_gateway_generates_profile_scoped_passport_csrs_in_openbao() {
    use std::str::FromStr;

    use der::{DecodePem, Encode};
    use x509_cert::name::Name;
    use x509_cert::request::CertReq;

    let redis_url = disposable_signing_redis_url().await;
    let organization_id = format!("gateway-csr-{}", uuid::Uuid::new_v4().simple());
    let (endpoint, token) = disposable_signing_openbao().await;
    let registry = SigningRegistryStore::connect(&redis_url)
        .await
        .unwrap()
        .with_managed_openbao(Some(endpoint.clone()));
    let cleanup_store = registry.clone();
    let profiles = SigningProfileStore::from_connection(registry.connection());
    let documents = SigningDocumentStore::from_connection(registry.connection());
    let signing = signing_router(
        "internal-signing-key".into(),
        Some("dedicated-service-sign-gateway-key-000001".into()),
        Some(registry),
        Some(documents),
        None,
        Some(profiles.clone()),
        None,
        Some("issuer.example".into()),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let signing_url = format!("http://{}", listener.local_addr().unwrap());
    let signing_server = tokio::spawn(async move { axum::serve(listener, signing).await.unwrap() });
    let gateway = gateway_with_signing_http(signing_url, &organization_id);
    let mut references = Vec::new();
    let mut public_keys = Vec::new();
    let mut issuer_dids = Vec::new();
    for (purpose, common_name) in [("csca", "Pilot CSCA"), ("x509_doc_signer", "Pilot DSC")] {
        let issuer_did = format!(
            "did:web:issuer.example:orgs:{organization_id}-{}",
            uuid::Uuid::new_v4().simple()
        );
        issuer_dids.push(issuer_did.clone());
        let identity = json!({
            "organization_id":organization_id, "issuer_did":issuer_did,
            "key_purpose":purpose, "credential_format":"ICAO_EMRTD",
            "algorithm":"ES256"
        });
        let request = |method: &str, path: &str, body: &Value, authenticated: bool| {
            let mut builder = Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json");
            if authenticated {
                builder = builder.header("cookie", "sessionId=valid");
            }
            builder.body(Body::from(body.to_string())).unwrap()
        };
        let created = gateway
            .clone()
            .oneshot(request(
                "POST",
                "/v1/signing-keys/issuer-identities",
                &identity,
                true,
            ))
            .await
            .unwrap();
        let status = created.status();
        let created: Value = serde_json::from_slice(
            &to_bytes(created.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(status, StatusCode::OK, "{purpose}: profile create failed");
        assert_eq!(created["created"], true);
        let resolved = gateway
            .clone()
            .oneshot(request(
                "POST",
                "/v1/signing-keys/issuer-identities/resolve",
                &identity,
                true,
            ))
            .await
            .unwrap();
        let status = resolved.status();
        let resolved: Value = serde_json::from_slice(
            &to_bytes(resolved.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(status, StatusCode::OK, "{purpose}: profile resolve failed");
        assert_eq!(resolved["public_jwk"]["crv"], "P-256");
        public_keys.push(resolved["public_jwk"].clone());
        let profile = profiles.list(&organization_id).await.unwrap()["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|profile| profile["issuer_did"] == issuer_did)
            .unwrap()
            .clone();
        let reference = profile["signing_key_reference"]
            .as_str()
            .unwrap()
            .to_owned();
        references.push(reference.clone());
        let mut csr_input = identity.clone();
        csr_input["country"] = json!("US");
        csr_input["organization"] = json!("ElevenID Beta");
        csr_input["common_name"] = json!(common_name);
        let route = "/v1/signing-keys/issuer-identities/certificate-csr";
        let denied = gateway
            .clone()
            .oneshot(request("PUT", route, &csr_input, false))
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        let foreign = gateway
            .clone()
            .oneshot(request(
                "PUT",
                "/v1/signing-keys/issuer-identities/certificate-csr?organization_id=org-other",
                &csr_input,
                true,
            ))
            .await
            .unwrap();
        assert_eq!(foreign.status(), StatusCode::FORBIDDEN);
        let mut forged = csr_input.clone();
        forged["key_reference"] = json!("attacker-key");
        let rejected = gateway
            .clone()
            .oneshot(request("PUT", route, &forged, true))
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let csr = gateway
            .clone()
            .oneshot(request("PUT", route, &csr_input, true))
            .await
            .unwrap();
        let status = csr.status();
        let csr: Value = serde_json::from_slice(
            &to_bytes(csr.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(status, StatusCode::OK, "{purpose}: CSR request failed");
        assert_eq!(csr["issuer_did"], issuer_did);
        assert_eq!(csr["subject"]["country"], "US");
        assert_eq!(csr["subject"]["organization"], "ElevenID Beta");
        assert_eq!(csr["subject"]["common_name"], common_name);
        let parsed = CertReq::from_pem(csr["csr_pem"].as_str().unwrap()).unwrap();
        assert_eq!(
            parsed.info.subject,
            Name::from_str(&format!("C=US,O=ElevenID Beta,CN={common_name}")).unwrap()
        );
        let parsed_jwk: Value = serde_json::to_value(
            marty_crypto::jwk::public_key_der_to_jwk(&parsed.info.public_key.to_der().unwrap())
                .unwrap(),
        )
        .unwrap();
        for field in ["kty", "crv", "x", "y"] {
            assert_eq!(parsed_jwk[field], resolved["public_jwk"][field]);
        }
        for public in [&created, &resolved, &csr] {
            for secret in [&endpoint[..], token.as_str(), reference.as_str()] {
                assert!(
                    !public.to_string().contains(secret),
                    "{purpose}: public response exposed custody metadata"
                );
            }
        }
    }
    assert_ne!(references[0], references[1]);
    assert_ne!(public_keys[0]["x"], public_keys[1]["x"]);
    let mut cleanup = cleanup_store.connection();
    let mut delete = redis::cmd("DEL");
    delete
        .arg(marty_signing_keys::registry::storage_key(&organization_id))
        .arg(marty_signing_keys::profiles::storage_key(&organization_id))
        .arg(marty_signing_keys::documents::jwks_storage_key(
            &organization_id,
        ))
        .arg(marty_signing_keys::documents::did_storage_key(
            &organization_id,
            None,
        ));
    for did in &issuer_dids {
        delete.arg(marty_signing_keys::documents::did_storage_key(
            &organization_id,
            Some(did),
        ));
        delete.arg(marty_signing_keys::documents::slug_storage_key(
            did.rsplit(':').next().unwrap(),
        ));
    }
    let _: usize = delete.query_async(&mut cleanup).await.unwrap();
    signing_server.abort();
}

#[tokio::test]
#[ignore = "requires independently marked disposable Redis and OpenBao instances"]
async fn authenticated_gateway_generates_a_dedicated_service_csr_in_openbao() {
    use std::str::FromStr;

    use der::{DecodePem, Encode};
    use x509_cert::name::Name;
    use x509_cert::request::CertReq;

    let redis_url = disposable_signing_redis_url().await;
    let (endpoint, token) = disposable_signing_openbao().await;
    let organization_id = format!("gateway-service-csr-{}", uuid::Uuid::new_v4().simple());
    let service_id = format!("service-csr-{}", uuid::Uuid::new_v4().simple());
    let key_reference = format!("service-csr-key-{}", uuid::Uuid::new_v4().simple());
    let client = reqwest::Client::new();
    let created_key = client
        .post(format!("{endpoint}/v1/transit/keys/{key_reference}"))
        .header("X-Vault-Token", &token)
        .json(&json!({"type":"ecdsa-p256"}))
        .send()
        .await
        .unwrap();
    assert!(created_key.status().is_success());

    let store = SigningRegistryStore::connect(&redis_url).await.unwrap();
    let service = json!({
        "id":service_id, "name":"Gateway dedicated CSR",
        "service_type":"openbao-transit", "endpoint":endpoint,
        "mount":"transit", "auth_mode":"token", "auth_reference":token,
        "key_reference":key_reference, "algorithms":["ES256"],
        "key_purposes":["x509_doc_signer"]
    });
    let mut registry = marty_signing_keys::registry::empty_registry();
    registry["services"]
        .as_array_mut()
        .unwrap()
        .push(service.clone());
    store.save(&organization_id, &registry).await.unwrap();
    let signing = signing_router(
        "internal-signing-key".into(),
        Some("dedicated-service-sign-gateway-key-000001".into()),
        Some(store.clone()),
        None,
        None,
        None,
        None,
        None,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let signing_url = format!("http://{}", listener.local_addr().unwrap());
    let signing_server = tokio::spawn(async move { axum::serve(listener, signing).await.unwrap() });
    let gateway = gateway_with_signing_http(signing_url, &organization_id);
    let route = format!("/v1/signing-keys/services/{service_id}/certificate-csr");
    let subject = json!({
        "country":"US", "organization":"ElevenID Beta", "common_name":"Pilot DSC"
    });
    let request = |path: &str, body: &Value, authenticated: bool| {
        let mut builder = Request::post(path).header("content-type", "application/json");
        if authenticated {
            builder = builder.header("cookie", "sessionId=valid");
        }
        builder.body(Body::from(body.to_string())).unwrap()
    };
    let denied = gateway
        .clone()
        .oneshot(request(&route, &subject, false))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    let foreign = gateway
        .clone()
        .oneshot(request(
            &format!("{route}?organization_id=org-other"),
            &subject,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::FORBIDDEN);
    let mut forged = subject.clone();
    forged["key_reference"] = json!("attacker-key");
    let rejected = gateway
        .clone()
        .oneshot(request(&route, &forged, true))
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let response = gateway
        .clone()
        .oneshot(request(&route, &subject, true))
        .await
        .unwrap();
    let status = response.status();
    let payload = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
        .await
        .unwrap();
    let result: Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "dedicated service CSR request failed"
    );
    assert_eq!(result["ok"], true);
    assert_eq!(result["service_id"], service_id);
    let parsed = CertReq::from_pem(result["csr_pem"].as_str().unwrap()).unwrap();
    assert_eq!(
        parsed.info.subject,
        Name::from_str("C=US,O=ElevenID Beta,CN=Pilot DSC").unwrap()
    );
    let csr_jwk: Value = serde_json::to_value(
        marty_crypto::jwk::public_key_der_to_jwk(&parsed.info.public_key.to_der().unwrap())
            .unwrap(),
    )
    .unwrap();
    let provider =
        marty_signing_keys::kms::public_key_existing(marty_signing_keys::kms::ProviderRequest {
            service_config: service,
        })
        .await
        .unwrap();
    let provider_jwk = marty_signing_keys::documents::sanitize_public_jwk(&provider, None).unwrap();
    for field in ["kty", "crv", "x", "y"] {
        assert_eq!(csr_jwk[field], provider_jwk[field]);
    }
    for secret in [&endpoint[..], token.as_str(), key_reference.as_str()] {
        assert!(!result.to_string().contains(secret));
    }
    let mut cleanup = store.connection();
    let _: usize = redis::cmd("DEL")
        .arg(marty_signing_keys::registry::storage_key(&organization_id))
        .query_async(&mut cleanup)
        .await
        .unwrap();
    signing_server.abort();
}

async fn disposable_gateway_json(
    gateway: &Router,
    method: &str,
    path: &str,
    body: &Value,
    session: bool,
    api_key: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if session {
        request = request.header("cookie", "sessionId=valid");
    }
    if let Some(api_key) = api_key {
        request = request.header("x-api-key", api_key);
    }
    let response = gateway
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
#[ignore = "requires independently marked disposable Redis and OpenBao instances"]
async fn authenticated_gateway_issues_dsc_with_operator_grant_and_dedicated_key() {
    use der::{Decode, DecodePem};
    use marty_crypto::certificate::{load_certificate_pem, verify_certificate_signature};
    use x509_cert::{request::CertReq, Certificate};

    const DSC_KEY: &str = "disposable-gateway-dsc-issue-key-32-characters";
    const CSCA_KEY: &str = "disposable-gateway-csca-issue-key-32-characters";
    const INTERNAL_KEY: &str = "disposable-gateway-internal-key";
    const DSC_ROUTE: &str = "/v1/signing-keys/issuer-identities/dsc-certificate";
    const CSCA_ROUTE: &str = "/v1/signing-keys/issuer-identities/csca-self-signed-certificate";

    let redis_url = disposable_signing_redis_url().await;
    let endpoint = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
    let parsed_bao = url::Url::parse(&endpoint).expect("disposable OpenBao URL syntax");
    assert!(
        parsed_bao.scheme() == "http" && parsed_bao.host_str() == Some("127.0.0.1"),
        "DSC test requires a loopback disposable OpenBao instance"
    );
    let token = std::env::var("MARTY_TEST_OPENBAO_TOKEN").expect("disposable OpenBao token");
    assert!(
        std::env::var("BAO_TOKEN").ok().as_deref() == Some(token.as_str()),
        "disposable OpenBao token binding does not match"
    );
    let bao_nonce = std::env::var("MARTY_TEST_OPENBAO_DISPOSABLE_NONCE")
        .expect("pre-provisioned disposable OpenBao sentinel value");
    assert!(
        bao_nonce.len() >= 16,
        "disposable OpenBao sentinel is too short"
    );
    let marker = reqwest::Client::new()
        .get(
            parsed_bao
                .join("/v1/secret/data/marty-test-disposable-guard")
                .unwrap(),
        )
        .header("X-Vault-Token", &token)
        .send()
        .await
        .expect("disposable OpenBao sentinel read");
    assert!(
        marker.status().is_success(),
        "disposable OpenBao sentinel is absent"
    );
    let marker: Value = marker
        .json()
        .await
        .expect("disposable OpenBao sentinel JSON");
    assert!(
        marker["data"]["data"]["nonce"].as_str() == Some(bao_nonce.as_str()),
        "disposable OpenBao sentinel does not match"
    );

    let registry = SigningRegistryStore::connect(&redis_url)
        .await
        .unwrap()
        .with_managed_openbao(Some(endpoint.clone()));
    let profiles = SigningProfileStore::from_connection(registry.connection());
    let documents = SigningDocumentStore::from_connection(registry.connection());
    let lifecycle = CscaLifecycleStore::from_connection(registry.connection());
    let signing = router_with_dependencies_and_ceremony_keys(
        INTERNAL_KEY.into(),
        Some(DSC_KEY.into()),
        Some(CSCA_KEY.into()),
        true,
        Some(registry),
        Some(documents),
        Some(lifecycle),
        Some(profiles.clone()),
        None,
        Some("issuer.example".into()),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let signing_url = format!("http://{}", listener.local_addr().unwrap());
    let signing_server = tokio::spawn(async move { axum::serve(listener, signing).await.unwrap() });
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let organization_id = format!("test-gateway-dsc-{suffix}");
    let gateway = gateway_with_signing_http_dsc(
        signing_url.clone(),
        Some(DSC_KEY),
        Some(CSCA_KEY),
        Some((&organization_id, true, true)),
    );
    let limited_gateway = gateway_with_signing_http_dsc(
        signing_url.clone(),
        Some(DSC_KEY),
        Some(CSCA_KEY),
        Some((&organization_id, false, false)),
    );
    let dsc_only_gateway = gateway_with_signing_http_dsc(
        signing_url.clone(),
        Some(DSC_KEY),
        Some(CSCA_KEY),
        Some((&organization_id, true, false)),
    );
    let issuer_did = format!("did:web:issuer.example:orgs:gateway-dsc-{suffix}");
    let identity = |purpose: &str| {
        json!({
            "organization_id":organization_id, "issuer_did":issuer_did,
            "key_purpose":purpose, "credential_format":"ICAO_EMRTD", "algorithm":"ES256"
        })
    };
    for purpose in ["csca", "x509_doc_signer"] {
        let (status, created) = disposable_gateway_json(
            &gateway,
            "POST",
            "/v1/signing-keys/issuer-identities",
            &identity(purpose),
            true,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{purpose} profile creation failed");
        assert_eq!(created["created"], true);
    }
    let mut csca_csr_input = identity("csca");
    csca_csr_input["country"] = json!("US");
    csca_csr_input["organization"] = json!("ElevenID Beta");
    csca_csr_input["common_name"] = json!("Disposable Gateway CSCA");
    let (status, csca_csr) = disposable_gateway_json(
        &gateway,
        "PUT",
        "/v1/signing-keys/issuer-identities/certificate-csr",
        &csca_csr_input,
        true,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "CSCA CSR creation failed");
    let csca_profile = profiles.list(&organization_id).await.unwrap()["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|profile| profile["issuer_did"] == issuer_did && profile["key_purpose"] == "csca")
        .unwrap()
        .clone();
    let dsc_profile = profiles.list(&organization_id).await.unwrap()["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|profile| {
            profile["issuer_did"] == issuer_did && profile["key_purpose"] == "x509_doc_signer"
        })
        .unwrap()
        .clone();
    let csca_reference = csca_profile["signing_key_reference"].as_str().unwrap();
    let dsc_reference = dsc_profile["signing_key_reference"].as_str().unwrap();
    assert_ne!(csca_reference, dsc_reference);
    let csr_pem = csca_csr["csr_pem"].as_str().unwrap();
    let csca_name = CertReq::from_pem(csr_pem).unwrap().info.subject;
    let certificate_id = format!("gateway-csca-{suffix}");
    let csca_issue = json!({
        "organization_id":organization_id, "issuer_did":issuer_did,
        "certificate_id":certificate_id, "credential_format":"ICAO_EMRTD",
        "country":"US", "organization":"ElevenID Beta",
        "common_name":"Disposable Gateway CSCA", "validity_days":365
    });
    let (status, _) = disposable_gateway_json(
        &limited_gateway,
        "POST",
        CSCA_ROUTE,
        &csca_issue,
        true,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "ordinary user must not issue CSCA"
    );
    let (status, _) = disposable_gateway_json(
        &dsc_only_gateway,
        "POST",
        CSCA_ROUTE,
        &csca_issue,
        true,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "DSC operator grant must not authorize CSCA ceremony"
    );
    let (status, _) = disposable_gateway_json(
        &gateway,
        "POST",
        CSCA_ROUTE,
        &csca_issue,
        false,
        Some(INTERNAL_KEY),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "API key must not issue CSCA");
    let (status, issued_csca) =
        disposable_gateway_json(&gateway, "POST", CSCA_ROUTE, &csca_issue, true, None).await;
    assert_eq!(status, StatusCode::OK, "managed CSCA ceremony failed");
    assert_eq!(issued_csca["status"], "issued");
    assert_eq!(issued_csca["chain_pem"], "");
    for secret in [&endpoint[..], token.as_str(), csca_reference, CSCA_KEY] {
        assert!(
            !issued_csca.to_string().contains(secret),
            "CSCA response exposed a custody locator or credential"
        );
    }
    let csca_pem = issued_csca["certificate_pem"].as_str().unwrap();
    let csca_der = load_certificate_pem(csca_pem).unwrap();
    assert!(verify_certificate_signature(&csca_der, &csca_der).unwrap());
    let parsed_csca = Certificate::from_der(&csca_der).unwrap();
    assert_eq!(parsed_csca.tbs_certificate.subject, csca_name);
    assert_eq!(parsed_csca.tbs_certificate.issuer, csca_name);
    let (status, replay) =
        disposable_gateway_json(&gateway, "POST", CSCA_ROUTE, &csca_issue, true, None).await;
    assert_eq!(status, StatusCode::OK, "CSCA ceremony replay failed");
    assert_eq!(replay, issued_csca);
    let mut changed = csca_issue.clone();
    changed["common_name"] = json!("Changed Gateway CSCA");
    let (status, _) =
        disposable_gateway_json(&gateway, "POST", CSCA_ROUTE, &changed, true, None).await;
    assert_eq!(status, StatusCode::CONFLICT);

    let issue = json!({
        "organization_id":organization_id, "dsc_issuer_did":issuer_did,
        "csca_issuer_did":issuer_did, "csca_certificate_id":certificate_id,
        "credential_format":"ICAO_EMRTD", "country":"US",
        "organization":"ElevenID Beta", "common_name":"Disposable Gateway DSC",
        "validity_days":30, "idempotency_key":format!("gateway-{suffix}")
    });
    let (status, _) = disposable_gateway_json(
        &limited_gateway,
        "POST",
        DSC_ROUTE,
        &issue,
        true,
        Some(INTERNAL_KEY),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "ordinary signed-in user must not issue DSC"
    );
    let (status, _) = disposable_gateway_json(
        &gateway,
        "POST",
        DSC_ROUTE,
        &issue,
        false,
        Some(INTERNAL_KEY),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "API key must not satisfy operator grant"
    );
    let (status, _) =
        disposable_gateway_json(&gateway, "POST", DSC_ROUTE, &issue, false, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let foreign = format!("{DSC_ROUTE}?organization_id=org-other");
    let (status, _) = disposable_gateway_json(&gateway, "POST", &foreign, &issue, true, None).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "foreign tenant must be rejected"
    );
    let direct = reqwest::Client::new()
        .post(format!(
            "{signing_url}{DSC_ROUTE}?organization_id={organization_id}"
        ))
        .header("x-api-key", INTERNAL_KEY)
        .header("x-user-id", "forged-operator")
        .json(&issue)
        .send()
        .await
        .unwrap();
    assert_eq!(
        direct.status(),
        StatusCode::UNAUTHORIZED,
        "generic internal key must not issue DSC"
    );

    // The operator session succeeds because Gateway injects its dedicated
    // credential and identity. A direct call above proved the shared key fails.
    let response = gateway
        .clone()
        .oneshot(
            Request::post(DSC_ROUTE)
                .header("cookie", "sessionId=valid")
                .header("content-type", "application/json")
                .header("x-user-id", "forged-operator")
                .header("x-org-permissions", "passport-certificate:issue")
                .body(Body::from(issue.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let issued: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status, StatusCode::OK, "governed DSC issuance failed");
    assert_eq!(issued["status"], "issued");
    let snapshot = profiles
        .dsc_issuance_store()
        .snapshot(&organization_id)
        .await
        .unwrap();
    let receipts = snapshot.certificates["passport_dsc_issuance"]
        .as_object()
        .unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts.values().next().unwrap()["actor_id"],
        "disposable-gateway-operator",
        "Gateway must replace caller-supplied operator identity"
    );
    let dsc_pem = issued["certificate_pem"].as_str().unwrap();
    let dsc_der = load_certificate_pem(dsc_pem).unwrap();
    assert!(verify_certificate_signature(&dsc_der, &csca_der).unwrap());
    let (status, replayed) =
        disposable_gateway_json(&gateway, "POST", DSC_ROUTE, &issue, true, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        replayed, issued,
        "retry must return the immutable issuance receipt"
    );
    for secret in [
        &endpoint[..],
        token.as_str(),
        csca_reference,
        dsc_reference,
        DSC_KEY,
        INTERNAL_KEY,
    ] {
        assert!(
            !issued.to_string().contains(secret),
            "public DSC response exposed custody metadata"
        );
    }
    signing_server.abort();
}

#[tokio::test]
#[ignore = "requires a marked disposable Redis database"]
async fn authenticated_gateway_rotates_only_a_dedicated_signing_service() {
    use std::sync::atomic::AtomicUsize;

    let redis_url = disposable_signing_redis_url().await;
    let organization_id = format!("gateway-rotation-{}", uuid::Uuid::new_v4().simple());
    let key_reference = format!("gateway-rotation-key-{}", uuid::Uuid::new_v4().simple());
    let version = Arc::new(AtomicUsize::new(1));
    let rotations = Arc::new(AtomicUsize::new(0));
    let kms = Router::new()
        .route(
            "/v1/transit/keys/{reference}",
            get({
                let version = Arc::clone(&version);
                let expected = key_reference.clone();
                move |Path(reference): Path<String>, headers: HeaderMap| {
                    let version = Arc::clone(&version);
                    let expected = expected.clone();
                    async move {
                        if !gateway_transit_authorized(&headers) {
                            return StatusCode::FORBIDDEN.into_response();
                        }
                        if reference != expected {
                            return StatusCode::NOT_FOUND.into_response();
                        }
                        Json(json!({"data":{"latest_version":version.load(Ordering::SeqCst)}}))
                            .into_response()
                    }
                }
            }),
        )
        .route(
            "/v1/transit/keys/{reference}/rotate",
            axum::routing::post({
                let version = Arc::clone(&version);
                let rotations = Arc::clone(&rotations);
                let expected = key_reference.clone();
                move |Path(reference): Path<String>, headers: HeaderMap| {
                    let version = Arc::clone(&version);
                    let rotations = Arc::clone(&rotations);
                    let expected = expected.clone();
                    async move {
                        if !gateway_transit_authorized(&headers) {
                            return StatusCode::FORBIDDEN;
                        }
                        if reference != expected {
                            return StatusCode::NOT_FOUND;
                        }
                        rotations.fetch_add(1, Ordering::SeqCst);
                        version.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    }
                }
            }),
        );
    let kms_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", kms_listener.local_addr().unwrap());
    let kms_server = tokio::spawn(async move { axum::serve(kms_listener, kms).await.unwrap() });
    let store = SigningRegistryStore::connect(&redis_url).await.unwrap();
    let service_id = format!("gateway-rotation-{}", uuid::Uuid::new_v4().simple());
    let mut registry = marty_signing_keys::registry::empty_registry();
    registry["services"].as_array_mut().unwrap().push(json!({
        "id":service_id, "name":"Gateway dedicated rotation",
        "service_type":"openbao-transit", "endpoint":endpoint,
        "mount":"transit", "auth_mode":"token", "auth_reference":"test-only",
        "key_reference":key_reference, "algorithms":["ES256"],
        "key_purposes":["vc_jwt_issuer"]
    }));
    store.save(&organization_id, &registry).await.unwrap();
    let signing = signing_router(
        "internal-signing-key".into(),
        Some("dedicated-service-sign-gateway-key-000001".into()),
        Some(
            store
                .clone()
                .with_managed_openbao(Some("http://127.0.0.1:1".into())),
        ),
        None,
        None,
        None,
        None,
        None,
    );
    let signing_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let signing_url = format!("http://{}", signing_listener.local_addr().unwrap());
    let signing_server =
        tokio::spawn(async move { axum::serve(signing_listener, signing).await.unwrap() });
    let gateway = gateway_with_signing_http(signing_url, &organization_id);
    let route = format!("/v1/signing-keys/services/{service_id}/rotate");
    let body = json!({"overlap_days":14,"publish_updates":false});
    let request = |path: &str, authenticated: bool| {
        let mut builder = Request::post(path).header("content-type", "application/json");
        if authenticated {
            builder = builder.header("cookie", "sessionId=valid");
        }
        builder.body(Body::from(body.to_string())).unwrap()
    };
    let denied = gateway
        .clone()
        .oneshot(request(&route, false))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    let foreign = gateway
        .clone()
        .oneshot(request(&format!("{route}?organization_id=org-other"), true))
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::FORBIDDEN);
    let managed = gateway
        .clone()
        .oneshot(request(
            "/v1/signing-keys/services/managed-openbao-transit/rotate",
            true,
        ))
        .await
        .unwrap();
    assert_eq!(managed.status(), StatusCode::FORBIDDEN);
    assert_eq!(rotations.load(Ordering::SeqCst), 0);
    let accepted = gateway
        .clone()
        .oneshot(request(&route, true))
        .await
        .unwrap();
    let status = accepted.status();
    let accepted: Value = serde_json::from_slice(
        &to_bytes(accepted.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "dedicated service rotation failed: {accepted}"
    );
    assert_eq!(accepted["ok"], true);
    assert_eq!(accepted["service_id"], service_id);
    assert_eq!(accepted["publication"], json!({"jwks":false,"did":false}));
    assert_eq!(
        accepted["rotation_state"]["provider_rotation"]["version"],
        2
    );
    assert_eq!(accepted["rotation_state"]["overlap_days"], 14);
    assert_eq!(
        accepted["rotation_state"]["previous_versions"][0]["key_reference"],
        key_reference
    );
    assert_eq!(rotations.load(Ordering::SeqCst), 1);
    let stored = store.load(&organization_id).await.unwrap();
    let stored_service = stored["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["id"] == service_id)
        .unwrap();
    assert_eq!(stored_service["rotation_state"], accepted["rotation_state"]);
    assert_eq!(stored_service["rotation_policy"]["overlap_days"], 14);
    assert_eq!(stored_service["rotation_policy"]["auto_publish"], false);
    assert!(store
        .rotation_marker(&organization_id, stored_service)
        .await
        .unwrap()
        .is_none());
    assert!(!accepted.to_string().contains(&endpoint));
    assert!(!accepted.to_string().contains("test-only"));
    let mut cleanup = store.connection();
    let _: usize = redis::cmd("DEL")
        .arg(marty_signing_keys::registry::storage_key(&organization_id))
        .query_async(&mut cleanup)
        .await
        .unwrap();
    signing_server.abort();
    kms_server.abort();
}

#[tokio::test]
#[ignore = "requires disposable MARTY_TEST_REDIS_URL"]
async fn authenticated_gateway_reaches_remaining_rust_signing_handlers() {
    let redis_url = disposable_signing_redis_url().await;
    let organization_id = format!("gateway-signing-{}", uuid::Uuid::new_v4().simple());
    let store = SigningRegistryStore::connect(&redis_url).await.unwrap();
    store
        .save(
            &organization_id,
            &marty_signing_keys::registry::empty_registry(),
        )
        .await
        .unwrap();
    let documents = SigningDocumentStore::from_connection(store.connection());
    documents
        .publish_jwk(
            &organization_id,
            "gateway-fixture",
            PublishJwkRequest {
                jwk: json!({"kty":"OKP","crv":"Ed25519","x":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","kid":"gateway-published"}),
                key_reference: Some("gateway-published".into()),
                cert_pem: None,
                cert_chain_pem: None,
            },
        )
        .await
        .unwrap();
    let verify_documents = documents.clone();
    let profiles = SigningProfileStore::from_connection(store.connection());
    let verify_registry = store.clone();
    let signing = signing_router(
        "test-internal-key".into(),
        Some("dedicated-service-sign-gateway-key-000001".into()),
        Some(store),
        Some(documents),
        None,
        Some(profiles),
        None,
        Some("beta.example".into()),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let signing_url = format!("http://{}", listener.local_addr().unwrap());
    let signing_server = tokio::spawn(async move { axum::serve(listener, signing).await.unwrap() });
    let upstream = Arc::new(ReqwestUpstream::new(1024 * 1024).unwrap());
    let mut state = signing_gateway_state(signing_url.clone());
    let identity = Arc::new(SigningIdentity {
        organization_id: organization_id.clone(),
    });
    Arc::get_mut(&mut state).unwrap().identities = identity.clone();
    Arc::get_mut(&mut state).unwrap().memberships = identity;
    let routes = GatewayContract::load()
        .unwrap()
        .proxy_route_table_with_passport_native(false)
        .unwrap();
    let registry =
        StaticServiceRegistry::from_urls(&BTreeMap::from([("signing-keys".into(), signing_url)]))
            .unwrap();
    Arc::get_mut(&mut state).unwrap().proxy = Arc::new(
        GatewayProxy::new(routes, Arc::new(registry), upstream, ProxyConfig::default()).unwrap(),
    );
    struct SigningMetadataGrantProvider;
    #[async_trait]
    impl OrganizationMembershipProvider for SigningMetadataGrantProvider {
        async fn get_membership(
            &self,
            user_id: &str,
            organization_id: &str,
        ) -> Result<Option<OrganizationMembership>, SecurityError> {
            let mut membership = SigningIdentity {
                organization_id: organization_id.into(),
            }
            .get_membership(user_id, organization_id)
            .await?;
            if let Some(membership) = membership.as_mut() {
                membership.permissions.insert("signing-key:delete".into());
            }
            Ok(membership)
        }
    }
    Arc::get_mut(&mut state).unwrap().memberships = Arc::new(SigningMetadataGrantProvider);
    let gateway = gateway_router(state);

    let cases = [
        (
            "PATCH",
            "/v1/signing-keys/gateway-published",
            Some(json!({"name":"Gateway renamed"})),
            StatusCode::OK,
            "updated",
        ),
        (
            "DELETE",
            "/v1/signing-keys/gateway-published",
            None,
            StatusCode::OK,
            "removed",
        ),
        (
            "GET",
            "/v1/signing-keys/holder-keys?device_id=device-gateway-acceptance",
            None,
            StatusCode::OK,
            "keys",
        ),
        (
            "POST",
            "/v1/signing-keys/holder-keys",
            Some(
                json!({"device_id":"device-gateway-acceptance","credential_id":"credential-gateway-acceptance","public_jwk":{"kty":"OKP","crv":"Ed25519","x":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"}}),
            ),
            StatusCode::OK,
            "record_id",
        ),
        (
            "GET",
            "/v1/signing-keys/services/missing-service/certificate",
            None,
            StatusCode::NOT_FOUND,
            "service",
        ),
        (
            "PUT",
            "/v1/signing-keys/services/missing-service/certificate",
            Some(json!({"cert_pem":"test"})),
            StatusCode::NOT_FOUND,
            "service",
        ),
        (
            "POST",
            "/v1/signing-keys/services/missing-service/certificate-csr",
            Some(json!({"country":"US","organization":"Test","common_name":"test"})),
            StatusCode::NOT_FOUND,
            "service",
        ),
        (
            "POST",
            "/v1/signing-keys/services/missing-service/sign",
            Some(json!({"payload_b64":"cGF5bG9hZA"})),
            StatusCode::NOT_FOUND,
            "service",
        ),
        (
            "GET",
            "/v1/signing-keys/services/missing-service/verify-current",
            None,
            StatusCode::NOT_FOUND,
            "service",
        ),
        (
            "POST",
            "/v1/signing-keys/services/missing-service/rotate",
            Some(json!({})),
            StatusCode::NOT_FOUND,
            "service",
        ),
        (
            "GET",
            "/v1/signing-keys/services/missing-service/audit-log",
            None,
            StatusCode::NOT_FOUND,
            "service",
        ),
        (
            "GET",
            "/v1/signing-keys/services/missing-service/mdoc-x5c",
            None,
            StatusCode::NOT_FOUND,
            "service",
        ),
        (
            "POST",
            "/v1/signing-keys/services/missing-service/publish-did-vm",
            Some(json!({})),
            StatusCode::NOT_FOUND,
            "service",
        ),
        (
            "POST",
            "/v1/signing-keys/services/missing-service/publish-jwks",
            Some(json!({})),
            StatusCode::NOT_FOUND,
            "service",
        ),
        (
            "GET",
            "/v1/signing-keys/compliance/keys-summary",
            None,
            StatusCode::NOT_IMPLEMENTED,
            "key_compliance_summary_unavailable",
        ),
        (
            "GET",
            "/v1/signing-keys/config/certificate-expiry-alerts",
            None,
            StatusCode::OK,
            "alerts",
        ),
        (
            "POST",
            "/v1/signing-keys/config/resolve",
            Some(json!({"key_purpose":"mdoc_dsc","algorithm":"EdDSA"})),
            StatusCode::NOT_FOUND,
            "No registered signing service",
        ),
        (
            "GET",
            "/v1/signing-keys/did-document",
            None,
            StatusCode::OK,
            "did:web:beta.example:orgs:",
        ),
        ("GET", "/v1/signing-keys/jwks", None, StatusCode::OK, "keys"),
        (
            "PUT",
            "/v1/signing-keys/issuer-identities/didcomm-key-agreement",
            Some(
                json!({"organization_id":organization_id.clone(),"issuer_did":format!("did:web:beta.example:orgs:{organization_id}"),"key_purpose":"vc_jwt_issuer","credential_format":"VC_JWT","algorithm":"EdDSA","public_jwk":{"kty":"OKP","crv":"X25519","x":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"}}),
            ),
            StatusCode::NOT_FOUND,
            "issuer",
        ),
        (
            "POST",
            "/v1/signing-keys/issuer-identities/resolve",
            Some(
                json!({"issuer_did":format!("did:web:beta.example:orgs:{organization_id}"),"key_purpose":"vc_jwt_issuer","credential_format":"VC_JWT","algorithm":"EdDSA"}),
            ),
            StatusCode::NOT_FOUND,
            "issuer",
        ),
        (
            "POST",
            "/v1/signing-keys/services/vdsnc/register",
            Some(
                json!({"country_code":"USA","authority_name":"Test Bureau","endpoint":"https://kms.example.invalid","auth_reference":"test-secret"}),
            ),
            StatusCode::OK,
            "service",
        ),
    ];
    for (method, path, body, expected_status, expected_fragment) in cases {
        let request = |authenticated| {
            let mut builder = Request::builder().method(method).uri(path);
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
        let denied = gateway.clone().oneshot(request(false)).await.unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED, "{method} {path}");
        let foreign_path = format!(
            "{path}{}organization_id=org-other",
            if path.contains('?') { '&' } else { '?' },
        );
        let mut foreign_request = Request::builder()
            .method(method)
            .uri(foreign_path)
            .header("cookie", "sessionId=valid");
        if body.is_some() {
            foreign_request = foreign_request.header("content-type", "application/json");
        }
        let forbidden = gateway
            .clone()
            .oneshot(
                foreign_request
                    .body(Body::from(
                        body.as_ref().map_or_else(String::new, Value::to_string),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN, "{method} {path}");
        let response = gateway.clone().oneshot(request(true)).await.unwrap();
        let status = response.status();
        let payload = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&payload);
        assert_eq!(status, expected_status, "{method} {path}: {text}");
        assert!(text.contains(expected_fragment), "{method} {path}: {text}");
        if method == "GET" && path == "/v1/signing-keys/did-document" {
            assert!(
                text.contains(&format!("did:web:beta.example:orgs:{organization_id}")),
                "{method} {path}: {text}"
            );
        }
        assert!(!text.contains("test-secret"), "{method} {path}: {text}");
        if method == "PATCH" && path == "/v1/signing-keys/gateway-published" {
            let jwks = verify_documents.jwks(&organization_id).await.unwrap();
            assert!(jwks["keys"].as_array().unwrap().iter().any(|key| {
                key["kid"] == "gateway-published" && key["name"] == "Gateway renamed"
            }));
        }
    }
    let jwks = verify_documents.jwks(&organization_id).await.unwrap();
    assert!(jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .all(|key| key["kid"] != "gateway-published"));
    let holder_keys = verify_documents
        .holder_keys(&organization_id, Some("device-gateway-acceptance"))
        .await
        .unwrap();
    assert!(holder_keys["keys"]
        .as_array()
        .unwrap()
        .iter()
        .any(|key| { key["credential_id"] == "credential-gateway-acceptance" }));
    let registry = verify_registry.load(&organization_id).await.unwrap();
    assert!(registry["services"]
        .as_array()
        .unwrap()
        .iter()
        .any(|service| {
            service["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("svc-vdsnc-usa-"))
                && service["key_purposes"] == json!(["vdsnc_signing"])
        }));
    let certificate: Value = serde_json::from_str(include_str!(
        "../../../services/signing-keys/tests/fixtures/document_vectors.json"
    ))
    .unwrap();
    let provider_vectors: Value = serde_json::from_str(include_str!(
        "../../../services/signing-keys/tests/fixtures/kms_provider_vectors.json"
    ))
    .unwrap();
    let provider_response = provider_vectors["public_key_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "gcp_pem_public_key")
        .unwrap()["provider_response"]
        .clone();
    let kms_material = Arc::new(std::sync::Mutex::new(provider_response));
    let kms_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let kms_endpoint = format!("http://{}", kms_listener.local_addr().unwrap());
    let kms_calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded_kms_calls = kms_calls.clone();
    let served_kms_material = kms_material.clone();
    let kms_server = tokio::spawn(async move {
        axum::serve(
            kms_listener,
            Router::new().fallback(any(move |request: Request| {
                let response = served_kms_material.lock().unwrap().clone();
                let calls = recorded_kms_calls.clone();
                async move {
                    let path = request.uri().path().to_owned();
                    let authorization = request
                        .headers()
                        .get(header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_owned();
                    calls.lock().unwrap().push((
                        request.method().to_string(),
                        path.clone(),
                        authorization.clone(),
                    ));
                    if authorization != "Bearer internal-test-credential" {
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                    if request.method() != axum::http::Method::GET
                        || path != "/v1/projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1/publicKey"
                    {
                        return StatusCode::NOT_FOUND.into_response();
                    }
                    Json(response).into_response()
                }
            })),
        )
        .await
        .unwrap()
    });
    verify_registry
        .save(
            &organization_id,
            &json!({
                "services": [{
                    "id": "gateway-service", "name": "Gateway mDoc Signer",
                    "service_type": "gcp-cloud-kms", "endpoint": kms_endpoint,
                    "auth_mode": "workload_identity", "auth_reference": "internal-test-credential",
                    "key_reference": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
                    "algorithms": ["ES256"], "key_purposes": ["mdoc_dsc"]
                }],
                "default_service_id": "gateway-service",
                "format_defaults": {"mso_mdoc": "gateway-service"},
                "type_defaults": {"mdoc_dsc": "gateway-service"},
                "key_reference_purposes": {
                    "gateway-service": {
                        "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1": ["mdoc_dsc"]
                    }
                }
            }),
        )
        .await
        .unwrap();
    let seeded = verify_registry.load(&organization_id).await.unwrap();
    assert_eq!(
        seeded["key_reference_purposes"]["gateway-service"]
            ["projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"],
        json!(["mdoc_dsc"])
    );
    let reference = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1";
    let selected =
        marty_signing_keys::registry::resolve(marty_signing_keys::registry::ResolveRequest {
            registry: seeded.clone(),
            service: None,
            keys: vec![json!({"id": reference, "algorithm": "ES256"})],
            credential_format: Some("mso_mdoc".into()),
            key_purpose: Some("mdoc_dsc".into()),
            algorithm: Some("ES256".into()),
        })
        .unwrap();
    assert_eq!(selected.key_reference.as_deref(), Some(reference));
    let positive_cases = [
        (
            "PUT",
            "/v1/signing-keys/services/gateway-service/certificate",
            Some(json!({"cert_pem": certificate["certificate"]["cert_pem"]})),
            StatusCode::OK,
            "cert_pem",
        ),
        (
            "GET",
            "/v1/signing-keys/services/gateway-service/certificate",
            None,
            StatusCode::OK,
            "cert_pem",
        ),
        (
            "GET",
            "/v1/signing-keys/services/gateway-service/mdoc-x5c",
            None,
            StatusCode::OK,
            "mdoc_cose_header_hints",
        ),
        (
            "GET",
            "/v1/signing-keys/services/gateway-service/verify-current",
            None,
            StatusCode::OK,
            "key_valid",
        ),
        (
            "POST",
            "/v1/signing-keys/services/gateway-service/publish-jwks",
            Some(json!({})),
            StatusCode::OK,
            "jwks_document",
        ),
        (
            "POST",
            "/v1/signing-keys/services/gateway-service/publish-did-vm",
            Some(json!({})),
            StatusCode::OK,
            "verification_method",
        ),
        ("GET", "/v1/signing-keys/jwks", None, StatusCode::OK, "x5c"),
        (
            "GET",
            "/v1/signing-keys/did-document",
            None,
            StatusCode::OK,
            "assertionMethod",
        ),
        (
            "POST",
            "/v1/signing-keys/config/resolve",
            Some(
                json!({"credential_format":"mso_mdoc","key_purpose":"mdoc_dsc","algorithm":"ES256"}),
            ),
            StatusCode::OK,
            "resolved_by",
        ),
        (
            "GET",
            "/v1/signing-keys/services/gateway-service/audit-log",
            None,
            StatusCode::NOT_IMPLEMENTED,
            "key_audit_log_unavailable",
        ),
    ];
    for (method, path, body, expected_status, expected_fragment) in positive_cases {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("cookie", "sessionId=valid");
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let response = gateway
            .clone()
            .oneshot(
                builder
                    .body(Body::from(
                        body.as_ref().map_or_else(String::new, Value::to_string),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let payload = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&payload);
        assert_eq!(status, expected_status, "{method} {path}: {text}");
        assert!(text.contains(expected_fragment), "{method} {path}: {text}");
        assert!(
            !text.contains("internal-test-credential"),
            "{method} {path}: {text}"
        );
        let result: Value = serde_json::from_slice(&payload).unwrap();
        match (method, path) {
            ("GET", "/v1/signing-keys/services/gateway-service/certificate") => {
                assert_eq!(result["cert_pem"], certificate["certificate"]["cert_pem"]);
            }
            ("PUT", "/v1/signing-keys/services/gateway-service/certificate") => {
                assert_eq!(
                    result["service"]["cert_pem"],
                    certificate["certificate"]["cert_pem"]
                );
            }
            ("GET", "/v1/signing-keys/services/gateway-service/mdoc-x5c") => {
                assert_eq!(result["x5c"][0], certificate["certificate"]["expected_x5c"]);
            }
            ("GET", "/v1/signing-keys/services/gateway-service/verify-current") => {
                assert_eq!(result["key_valid"], true);
            }
            ("POST", "/v1/signing-keys/services/gateway-service/publish-jwks") => {
                assert_eq!(result["jwks_document"]["key_count"], 1);
                assert_eq!(result["jwk"]["kid"], reference);
                assert_eq!(
                    result["jwk"]["x5c"][0],
                    certificate["certificate"]["expected_x5c"]
                );
                assert!(text.contains(reference));
            }
            ("POST", "/v1/signing-keys/services/gateway-service/publish-did-vm") => {
                assert_eq!(
                    result["verification_method"]["x5c"][0],
                    certificate["certificate"]["expected_x5c"]
                );
                assert_eq!(
                    result["verification_method"]["publicKeyJwk"]["kid"],
                    reference
                );
            }
            ("GET", "/v1/signing-keys/jwks") => {
                assert_eq!(
                    result["keys"][0]["x5c"][0],
                    certificate["certificate"]["expected_x5c"]
                );
                assert_eq!(result["keys"].as_array().unwrap().len(), 1);
                assert_eq!(result["keys"][0]["kid"], reference);
            }
            ("GET", "/v1/signing-keys/did-document") => {
                assert!(!result["assertionMethod"].as_array().unwrap().is_empty());
                assert!(result["verificationMethod"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|method| method["publicKeyJwk"]["kid"] == reference));
            }
            ("POST", "/v1/signing-keys/config/resolve") => {
                assert_eq!(result["service"]["id"], "gateway-service");
            }
            _ => {}
        }
    }
    kms_material.lock().unwrap()["algorithm"] = json!("RSA_DECRYPT_OAEP_2048_SHA256");
    let non_signing = gateway
        .clone()
        .oneshot(
            Request::post("/v1/signing-keys/config/resolve")
                .header("cookie", "sessionId=valid")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"credential_format":"mso_mdoc","key_purpose":"mdoc_dsc","algorithm":"ES256"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(non_signing.status(), StatusCode::NOT_FOUND);
    {
        let calls = kms_calls.lock().unwrap();
        assert!(calls.len() >= 4, "expected live KMS checks: {calls:?}");
        assert!(calls.iter().all(|(method, path, authorization)| {
            method == "GET"
                && path
                    == "/v1/projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1/publicKey"
                && authorization == "Bearer internal-test-credential"
        }));
    }
    kms_server.abort();
    let mut connection = verify_registry.connection();
    let _: usize = redis::cmd("DEL")
        .arg(marty_signing_keys::registry::storage_key(&organization_id))
        .arg(marty_signing_keys::documents::jwks_storage_key(
            &organization_id,
        ))
        .arg(marty_signing_keys::documents::holder_keys_storage_key(
            &organization_id,
        ))
        .arg(marty_signing_keys::documents::certificate_storage_key(
            &organization_id,
        ))
        .arg(marty_signing_keys::documents::did_storage_key(
            &organization_id,
            None,
        ))
        .arg(marty_signing_keys::documents::did_storage_key(
            &organization_id,
            Some(&format!("did:web:beta.example:orgs:{organization_id}")),
        ))
        .arg(marty_signing_keys::documents::slug_storage_key(
            &organization_id,
        ))
        .arg(marty_signing_keys::profiles::storage_key(&organization_id))
        .query_async(&mut connection)
        .await
        .unwrap();
    signing_server.abort();
}
