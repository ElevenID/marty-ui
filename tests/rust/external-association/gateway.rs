// SPDX-License-Identifier: AGPL-3.0-only
// Actual public Gateway HTTP/proxy -> Core HTTP -> restricted PostgreSQL.
// Auth gRPC is real; validated session/key inputs are synthetic fixture authority.
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_gateway::{
    authorization::{OrganizationMembership, OrganizationMembershipProvider},
    contract::GatewayContract,
    discovery::ReleaseIdentity,
    middleware::{ApiKeyIdentity, GatewayIdentityProvider, GatewayRateLimiter, SessionIdentity},
    providers::GrpcIdentityProvider,
    registry::StaticServiceRegistry,
    runtime::{
        gateway_router, EventStreamProvider, EventStreamSubscription, GatewayDomainEventStream,
        GatewayRuntimeState, ReadinessProvider, ReadinessServiceStatus, ResourceOwnerContext,
        ResourceOwnerProvider,
    },
    transport::ReqwestUpstream,
};
use mmf_platform::{
    GatewayProxy, GatewayRequest, GatewayResponse, InMemoryIdempotencyStore, PlatformError,
    ProxyConfig, ServiceInstance, UpstreamClient,
};
use mmf_security::{InMemoryRateLimiter, SecurityError};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use uuid::Uuid;

const ORIGIN: &str = "https://association.example.test";
const SERVICE_KEY: &str = "synthetic-core-association-service-key-00001";
const GRPC_KEY: &str = "synthetic-auth-grpc-association-key-0000001";
const PRODUCER_KEY: &str = "synthetic-producer-association-key-0000001";

struct Sessions {
    organization: String,
}
#[async_trait]
impl marty_auth::AuthSessionService for Sessions {
    async fn validate_session(
        &self,
        id: &str,
    ) -> Result<Option<marty_auth::Session>, tonic::Status> {
        let user_id = match id {
            "admin" => "admin-one",
            "learner" | "impersonated" => "learner-one",
            "other" => "other-learner",
            _ => return Ok(None),
        };
        let mut user: marty_auth::AuthenticatedUser = serde_json::from_value(json!({
            "user_id":user_id,"email":"synthetic@example.test","organization_id":self.organization
        }))
        .unwrap();
        if id == "impersonated" {
            user.impersonation = Some(serde_json::from_value(json!({"active":true})).unwrap());
        }
        let mut session = marty_auth::Session::create(marty_auth::SessionSpec {
            user,
            ttl_seconds: 3600,
            now: chrono::Utc::now(),
            ip_address: None,
            user_agent: None,
            id_token: None,
            refresh_token: None,
            oidc_claims: None,
        });
        session.session_id = id.into();
        Ok(Some(session))
    }
    async fn invalidate_session(&self, _: &str) -> Result<bool, tonic::Status> {
        Ok(false)
    }
}
struct Identities {
    sessions: GrpcIdentityProvider,
    organization: String,
    key: String,
}
#[async_trait]
impl GatewayIdentityProvider for Identities {
    async fn validate_session(&self, id: &str) -> Result<Option<SessionIdentity>, SecurityError> {
        self.sessions.validate_session(id).await
    }
    async fn validate_api_key(&self, key: &str) -> Result<Option<ApiKeyIdentity>, SecurityError> {
        if ![PRODUCER_KEY, "synthetic-evidence-only-key"].contains(&key) {
            return Ok(None);
        }
        Ok(Some(ApiKeyIdentity {
            api_key_id: self.key.clone(),
            organization_id: Some(self.organization.clone()),
            key_prefix: None,
            scopes: vec![if key == PRODUCER_KEY {
                "identity:attest"
            } else {
                "evidence:submit"
            }
            .into()],
        }))
    }
}
struct Authority {
    organization: String,
}
#[async_trait]
impl OrganizationMembershipProvider for Authority {
    async fn get_membership(
        &self,
        user: &str,
        organization: &str,
    ) -> Result<Option<OrganizationMembership>, SecurityError> {
        if organization != self.organization {
            return Ok(None);
        }
        Ok(Some(OrganizationMembership {
            user_id: user.into(),
            organization_id: organization.into(),
            status: "active".into(),
            is_owner: false,
            role_names: BTreeSet::new(),
            permissions: if user == "admin-one" {
                BTreeSet::from(["external-association:manage".into()])
            } else {
                BTreeSet::new()
            },
        }))
    }
}
#[async_trait]
impl ResourceOwnerProvider for Authority {
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
impl ReadinessProvider for Authority {
    async fn check_services(&self, _: &[String]) -> BTreeMap<String, ReadinessServiceStatus> {
        BTreeMap::new()
    }
    fn all_services(&self) -> Vec<String> {
        vec![]
    }
}
#[async_trait]
impl EventStreamProvider for Authority {
    async fn subscribe(
        &self,
        _: EventStreamSubscription,
    ) -> Result<GatewayDomainEventStream, SecurityError> {
        Err(SecurityError::ProviderUnavailable(
            "fixture has no event subscription".into(),
        ))
    }
}
struct LoseOneReply {
    transport: ReqwestUpstream,
    drop_confirm: AtomicBool,
    calls: Mutex<Vec<GatewayRequest>>,
}
#[async_trait]
impl UpstreamClient for LoseOneReply {
    async fn send(
        &self,
        instance: &ServiceInstance,
        request: GatewayRequest,
    ) -> Result<GatewayResponse, PlatformError> {
        let confirm = request.path.ends_with("/confirm");
        self.calls.lock().unwrap().push(request.clone());
        let response = self.transport.send(instance, request).await?;
        if confirm && response.status_code == 200 && self.drop_confirm.swap(false, Ordering::SeqCst)
        {
            return Err(PlatformError::ProviderUnavailable(
                "synthetic reply lost after Core commit".into(),
            ));
        }
        Ok(response)
    }
}
async fn post(
    client: &reqwest::Client,
    origin: &str,
    path: &str,
    actor: &str,
    body: Value,
) -> (u16, Value) {
    post_raw(
        client,
        origin,
        path,
        actor,
        format!(" \n{}\n ", serde_json::to_string(&body).unwrap()),
    )
    .await
}
async fn post_raw(
    client: &reqwest::Client,
    origin: &str,
    path: &str,
    actor: &str,
    body: String,
) -> (u16, Value) {
    let mut request = client
        .post(format!("{origin}{path}"))
        .header("origin", ORIGIN)
        .header("content-type", "application/json")
        .header("x-user-id", "forged-user")
        .header("x-organization-id", "forged-organization")
        .header("x-api-key-id", "forged-key")
        .header("x-non-impersonated-session", "true");
    request = if actor == "producer" {
        request.header("x-api-key", PRODUCER_KEY)
    } else if actor == "evidence" {
        request.header("x-api-key", "synthetic-evidence-only-key")
    } else {
        request.header("cookie", format!("sessionId={actor}"))
    };
    let response = request.body(body).send().await.unwrap();
    let status = response.status().as_u16();
    let value = response.json().await.unwrap();
    (status, value)
}
async fn ok(client: &reqwest::Client, origin: &str, path: &str, actor: &str, body: Value) -> Value {
    let (status, value) = post(client, origin, path, actor, body).await;
    assert_eq!(status, 200, "{path}: {value}");
    value
}

#[tokio::test]
async fn actual_gateway_core_database_preserves_authority_consent_and_original_receipt_recovery() {
    assert_eq!(
        std::env::var("EXTERNAL_ASSOCIATION_GATEWAY_TEST").as_deref(),
        Ok("synthetic-local-only")
    );
    let port = std::env::var("EXTERNAL_ASSOCIATION_SOURCE_PORT").unwrap();
    let organization = std::env::var("EXTERNAL_ASSOCIATION_SOURCE_ORG").unwrap();
    let key = std::env::var("EXTERNAL_ASSOCIATION_GATEWAY_KEY").unwrap();
    let key_revision: i64 = std::env::var("EXTERNAL_ASSOCIATION_GATEWAY_KEY_REVISION")
        .unwrap()
        .parse()
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&format!(
            "postgresql://association_runtime:synthetic-association-only@127.0.0.1:{port}/postgres"
        ))
        .await
        .unwrap();
    crate::external_association_startup::verify_storage(&pool)
        .await
        .unwrap();
    let role: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(role, "association_runtime");
    let core =
        crate::external_association_http::association_router(pool.clone(), SERVICE_KEY.as_bytes())
            .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let core_origin = format!("http://{}", listener.local_addr().unwrap());
    let core_task = tokio::spawn(async move { axum::serve(listener, core).await.unwrap() });
    let auth = marty_auth::AuthGrpcService::new(
        Arc::new(Sessions {
            organization: organization.clone(),
        }),
        Some(GRPC_KEY.into()),
        true,
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let auth_origin = format!("http://{}", listener.local_addr().unwrap());
    let auth_task = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(marty_auth::auth_proto::auth_service_server::AuthServiceServer::new(auth))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );
    let channel = tonic::transport::Endpoint::from_shared(auth_origin)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let identities = Arc::new(Identities {
        sessions: GrpcIdentityProvider::new(
            channel.clone(),
            channel,
            Duration::from_secs(5),
            Some(GRPC_KEY.into()),
        ),
        organization: organization.clone(),
        key: key.clone(),
    });
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let upstream = Arc::new(LoseOneReply {
        transport: ReqwestUpstream::with_client(65536, client.clone()).unwrap(),
        drop_confirm: AtomicBool::new(true),
        calls: Mutex::new(vec![]),
    });
    let contract = GatewayContract::load().unwrap();
    let registry = StaticServiceRegistry::from_urls(&BTreeMap::from([
        ("issuance".into(), core_origin.clone()),
        ("issuance-native".into(), core_origin),
    ]))
    .unwrap();
    let proxy = GatewayProxy::new(
        contract.proxy_route_table().unwrap(),
        Arc::new(registry),
        upstream.clone(),
        ProxyConfig::default(),
    )
    .unwrap();
    let authority = Arc::new(Authority {
        organization: organization.clone(),
    });
    let state = GatewayRuntimeState::new(
        contract.runtime_route_table().unwrap(),
        proxy,
        identities,
        authority.clone(),
        authority.clone(),
        authority.clone(),
        authority,
        vec![],
        GatewayRateLimiter::new(Arc::new(InMemoryRateLimiter::default()), 1000).unwrap(),
        Arc::new(InMemoryIdempotencyStore::new(60000, 5000).unwrap()),
        [ORIGIN.into()],
        ORIGIN,
        ORIGIN,
        "association.example.test",
        None,
        "synthetic-signing-key-unused",
        SERVICE_KEY,
        ReleaseIdentity::default(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_origin = format!("http://{}", listener.local_addr().unwrap());
    let gateway_task = tokio::spawn(async move {
        axum::serve(listener, gateway_router(Arc::new(state)))
            .await
            .unwrap()
    });
    let source = Uuid::new_v4();
    let source_path =
        format!("/v1/organizations/{organization}/external-association-sources/{source}");
    let expiry = chrono::Utc::now().timestamp_millis() + 120000;
    let created=ok(&client,&public_origin,&format!("{source_path}/create"),"admin",json!({"operation_id":Uuid::new_v4(),"expected_revision":0,
        "api_key_id":key,"key_revision":key_revision,"source_id":"gateway-source","expires_at_ms":expiry+300000})).await;
    assert_eq!(created["active"], false);
    assert_eq!(
        ok(
            &client,
            &public_origin,
            &format!("{source_path}/approve"),
            "admin",
            json!({"operation_id":Uuid::new_v4(),"expected_revision":1})
        )
        .await["revision"],
        2
    );
    let challenge = Uuid::new_v4();
    let producer_path = format!("/v1/identity/association-challenges/{challenge}");
    let learner_path =
        format!("/v1/organizations/{organization}/external-association-challenges/{challenge}");
    let code = URL_SAFE_NO_PAD.encode([41u8; 32]);
    let code_hash = Sha256::digest([41u8; 32])
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let create = json!({"operation_id":Uuid::new_v4(),"challenge_id":challenge,"source_grant_id":source,"expected_source_revision":2,
        "binding_id":"gateway-binding","expected_binding_revision":1,"provider_reference":"e".repeat(64),"provider_revision":1,"code_hash":code_hash,"expires_at_ms":expiry});
    let original_create = format!(" \n{}\n ", serde_json::to_string(&create).unwrap());
    let duplicate = format!(
        "{{\"operation_id\":\"{}\",{}",
        Uuid::new_v4(),
        &serde_json::to_string(&create).unwrap()[1..]
    );
    let mut unknown = create.clone();
    unknown["organization_id"] = json!(organization);
    for malformed in [duplicate, serde_json::to_string(&unknown).unwrap()] {
        assert_eq!(
            post_raw(
                &client,
                &public_origin,
                &format!("{producer_path}/create"),
                "producer",
                malformed
            )
            .await
            .0,
            400
        );
    }
    let identities_before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM issuance_service.external_association_identities")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        post(
            &client,
            &public_origin,
            &format!("{producer_path}/create"),
            "evidence",
            create.clone()
        )
        .await
        .0,
        403
    );
    assert_eq!(
        ok(
            &client,
            &public_origin,
            &format!("{producer_path}/create"),
            "producer",
            create.clone()
        )
        .await["phase"],
        "pending"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.external_association_identities"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        identities_before
    );
    let private = ok(
        &client,
        &public_origin,
        &format!("{producer_path}/inspect"),
        "producer",
        json!({}),
    )
    .await;
    for field in ["application_id", "subject_id", "identity"] {
        assert!(private["record"][field].is_null());
    }
    let confirm_op = Uuid::new_v4();
    let confirm = json!({"operation_id":confirm_op,"expected_revision":1,"code":code});
    for actor in ["other", "impersonated"] {
        assert_eq!(
            post(
                &client,
                &public_origin,
                &format!("{learner_path}/confirm"),
                actor,
                confirm.clone()
            )
            .await
            .0,
            403
        );
    }
    let current = ok(
        &client,
        &public_origin,
        &format!("{learner_path}/inspect"),
        "learner",
        json!({}),
    )
    .await;
    assert_eq!(current["record"]["application_id"], "application-one");
    assert_eq!(current["record"]["subject_id"], "canonical-subject");
    let confirm_calls = || {
        upstream
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.path == format!("{learner_path}/confirm"))
            .count()
    };
    let before_confirm = confirm_calls();
    let (status, _) = post(
        &client,
        &public_origin,
        &format!("{learner_path}/confirm"),
        "learner",
        confirm.clone(),
    )
    .await;
    assert_eq!(status, 503); // Actual Core committed; its reply was deliberately lost.
    assert_eq!(confirm_calls(), before_confirm + 1);
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM issuance_service.external_association_operations WHERE operation_id=$1").bind(confirm_op).fetch_one(&pool).await.unwrap();
    assert_eq!(count, 1);
    let history = ok(
        &client,
        &public_origin,
        &format!("{learner_path}/receipt"),
        "learner",
        json!({"operation_id":confirm_op}),
    )
    .await;
    assert_eq!(history["kind"], "receipt");
    assert_eq!(history["receipt"]["phase"], "confirmed");
    // A browser-level replay retains the original operation and cannot reapply it.
    assert_eq!(
        ok(
            &client,
            &public_origin,
            &format!("{learner_path}/confirm"),
            "learner",
            confirm.clone()
        )
        .await,
        history["receipt"]
    );
    assert_eq!(confirm_calls(), before_confirm + 2);
    let current = ok(
        &client,
        &public_origin,
        &format!("{learner_path}/inspect"),
        "learner",
        json!({}),
    )
    .await;
    assert_eq!(current["record"]["current"], true);
    let identity = current["record"]["identity"]["identity_id"]
        .as_str()
        .unwrap();
    let identity_path =
        format!("/v1/organizations/{organization}/external-associations/{identity}");
    assert_eq!(
        ok(
            &client,
            &public_origin,
            &format!("{identity_path}/unlink"),
            "learner",
            json!({"operation_id":Uuid::new_v4(),"expected_revision":1})
        )
        .await["active"],
        false
    );
    assert_eq!(
        ok(
            &client,
            &public_origin,
            &format!("{learner_path}/confirm"),
            "learner",
            confirm
        )
        .await,
        history["receipt"]
    );
    assert_eq!(
        ok(
            &client,
            &public_origin,
            &format!("{learner_path}/inspect"),
            "learner",
            json!({})
        )
        .await["record"]["current"],
        false
    );
    assert_eq!(
        ok(
            &client,
            &public_origin,
            &format!("{source_path}/revoke"),
            "admin",
            json!({"operation_id":Uuid::new_v4(),"expected_revision":2})
        )
        .await["active"],
        false
    );
    assert_eq!(
        ok(
            &client,
            &public_origin,
            &format!("{learner_path}/receipt"),
            "learner",
            json!({"operation_id":confirm_op})
        )
        .await,
        history
    );
    assert_eq!(
        ok(
            &client,
            &public_origin,
            &format!("{producer_path}/inspect"),
            "producer",
            json!({})
        )
        .await["record"]["current"],
        false
    );
    {
        let calls = upstream.calls.lock().unwrap();
        for call in calls.iter() {
            assert_eq!(call.header("x-api-key"), Some(SERVICE_KEY));
            assert_eq!(
                call.header("x-organization-id"),
                Some(organization.as_str())
            );
            if call.path.starts_with("/v1/identity/") {
                assert_eq!(call.header("x-user-id"), None);
                assert_eq!(call.header("x-api-key-id"), Some(key.as_str()));
            }
        }
        let creates = calls
            .iter()
            .filter(|r| {
                r.path == format!("{producer_path}/create")
                    && r.body.as_deref() == Some(original_create.as_bytes())
            })
            .collect::<Vec<_>>();
        assert_eq!(creates.len(), 1);
        assert_eq!(creates[0].body.as_deref(), Some(original_create.as_bytes()));
    }
    gateway_task.abort();
    core_task.abort();
    auth_task.abort();
    pool.close().await;
}
