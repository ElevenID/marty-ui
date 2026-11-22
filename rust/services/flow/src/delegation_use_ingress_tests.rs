//! Real HTTP/Flow/PostgreSQL ingress with real request/VP/receipt signatures.
//! Current caller/consent/domain policy remain explicitly injected fixtures;
//! concrete Organization access ownership is qualified in its owner suite.
#[path = "delegation_use_ingress_owner_tests.rs"]
mod owner_access;

use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use marty_delegated_authority::{
    use_http::DelegationUseHttpAuthenticator, DelegationUseIngressAuthorizer,
    DelegationUseIngressOperation, MAX_DELEGATE_PROOF_BYTES,
};
use sqlx::AssertSqlSafe;
use tower::ServiceExt;

use crate::{
    delegated_use_flow_router, FlowDelegatedUseHttpState, FlowDelegatedUseIngress,
    RequestObjectOptions,
};

const TOKEN: &str = "synthetic-flow-delegated-use-forwarder-token";

struct IngressAccess {
    organization_id: Uuid,
    actor: Principal,
    allowed: AtomicBool,
    lifetime_ms: AtomicI64,
    observation_offset_ms: AtomicI64,
    calls: AtomicUsize,
}
#[async_trait]
impl DelegationUseIngressAuthorizer for IngressAccess {
    async fn authorize_ingress(
        &self,
        caller: &DelegationCommandCaller,
        _: Uuid,
        _: DelegationUseIngressOperation,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, DelegationUseCommandError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.allowed.load(Ordering::SeqCst)
            || caller.organization_id() != self.organization_id
            || caller.actor() != &self.actor
        {
            return Err(DelegationUseCommandError::AccessDenied);
        }
        Ok(VerifiedDelegationCommandAccess {
            observed_at: now
                + Duration::milliseconds(self.observation_offset_ms.load(Ordering::SeqCst)),
            valid_until: now + Duration::milliseconds(self.lifetime_ms.load(Ordering::SeqCst)),
        })
    }
}

struct RequestSigner {
    key: SigningKey,
    calls: AtomicUsize,
    delay_ms: AtomicU64,
    fail: AtomicBool,
    started: tokio::sync::Notify,
}
#[async_trait]
impl SigningIdentityProvider for RequestSigner {
    async fn resolve(
        &self,
        organization_id: &str,
        issuer_did: &str,
        purpose: &str,
        format: &str,
        _: Option<&str>,
    ) -> Result<SigningIdentity, FlowProviderError> {
        let point = self.key.verifying_key().to_sec1_point(false);
        Ok(SigningIdentity { organization_id:organization_id.into(),issuer_did:issuer_did.into(),
            verification_method_id:format!("{issuer_did}#request"),signing_key_reference:"ingress-request-key".into(),
            public_jwk:serde_json::from_value(json!({"kty":"EC","crv":"P-256",
                "x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),"y":URL_SAFE_NO_PAD.encode(point.y().unwrap())})).unwrap(),
            key_purpose:purpose.into(),credential_format:format.into(),algorithm:"ES256".into() })
    }
    async fn sign(&self, request: &SigningRequest) -> Result<SigningResult, FlowProviderError> {
        assert_eq!(request.key_purpose, "oid4vp_request_signing");
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        let delay = self.delay_ms.load(Ordering::SeqCst);
        if delay > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }
        if self.fail.load(Ordering::SeqCst) {
            return Err(FlowProviderError::Unavailable {
                provider: "synthetic_request_signer",
            });
        }
        let bytes = URL_SAFE_NO_PAD.decode(&request.payload_b64url).unwrap();
        let signature: Signature = self.key.sign(&bytes);
        Ok(SigningResult {
            issuer_did: request.issuer_did.clone(),
            verification_method_id: request.verification_method_id.clone(),
            algorithm: "ES256".into(),
            signature_raw_b64url: URL_SAFE_NO_PAD.encode(signature.normalize_s().to_bytes()),
        })
    }
}

struct Ingress {
    f: Integrated,
    app: Arc<FlowDelegatedUseIngress>,
    access: Arc<IngressAccess>,
    request_signer: Arc<RequestSigner>,
    role: String,
    pool: PgPool,
    providers: FlowProviderRegistry,
}
impl Ingress {
    async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::new_with_actor_type(PrincipalType::ServiceAccount).await
    }
    async fn new_with_actor_type(
        principal_type: PrincipalType,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if principal_type == PrincipalType::MachineIdentity {
            // The historical Flow test schema lock shares Organization's
            // migration lock ID. Install that owner before holding the Flow
            // fixture lock, without changing either production lock identity.
            let options = PgConnectOptions::from_str(&std::env::var("FLOW_POSTGRES_TEST_URL")?)?;
            assert!(matches!(options.get_host(), "127.0.0.1" | "localhost"));
            assert_eq!(options.get_database(), Some("marty_atomic_test"));
            let setup = PgPoolOptions::new()
                .max_connections(2)
                .connect_with(options)
                .await?;
            marty_organization::migration::migrate_organization_schema(&setup).await?;
            setup.close().await;
        }
        let f = Integrated::new_with_actor_type(principal_type).await?;
        let role = format!("flow_ingress_{}", Uuid::new_v4().simple());
        assert!(role.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
        sqlx::raw_sql(AssertSqlSafe(format!("CREATE ROLE {role} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
            GRANT USAGE ON SCHEMA flow_service TO {role};
            GRANT SELECT ON flow_service.rust_schema_versions,flow_service.delegated_use_storage_identity,
                flow_service.flow_definitions,flow_service.flow_instances,flow_service.delegated_challenge_bindings,
                flow_service.delegated_proof_submissions,flow_service.delegated_use_consumptions,
                flow_service.delegated_request_claims,flow_service.delegated_request_results,flow_service.delegated_proof_ingress TO {role};
            GRANT INSERT ON flow_service.delegated_proof_submissions,flow_service.delegated_request_claims,
                flow_service.delegated_request_results,flow_service.delegated_proof_ingress TO {role};
            GRANT UPDATE(current_step_id,context,step_history,state_history,updated_at) ON flow_service.flow_instances TO {role};
            GRANT EXECUTE ON FUNCTION flow_service.lock_delegated_ingress_definition(uuid,uuid) TO {role};")))
            .execute(&f.pool).await?;
        let pool = PgPoolOptions::new()
            .max_connections(6)
            .connect_with(f.pool.connect_options().as_ref().clone().username(&role))
            .await?;
        let access = Arc::new(IngressAccess {
            organization_id: f.caller.organization_id(),
            actor: f.caller.actor().clone(),
            allowed: AtomicBool::new(true),
            lifetime_ms: AtomicI64::new(30_000),
            observation_offset_ms: AtomicI64::new(0),
            calls: AtomicUsize::new(0),
        });
        let request_signer = Arc::new(RequestSigner {
            key: SigningKey::from_slice(&rand::random::<[u8; 32]>())?,
            calls: AtomicUsize::new(0),
            delay_ms: AtomicU64::new(0),
            fail: AtomicBool::new(false),
            started: Default::default(),
        });
        let mut providers = f.fixture.providers.clone();
        providers.signing_identity = Some(request_signer.clone());
        let app = Arc::new(
            FlowDelegatedUseIngress::new(
                PostgresFlowRepository::new(pool.clone()),
                providers.clone(),
                access.clone(),
                f.fixture.configuration.public_base_url.clone(),
                RequestObjectOptions::default(),
            )
            .await?,
        );
        Ok(Self {
            f,
            app,
            access,
            request_signer,
            role,
            pool,
            providers,
        })
    }
    fn router(&self) -> axum::Router {
        delegated_use_flow_router(FlowDelegatedUseHttpState::new(
            self.app.clone(),
            Arc::new(
                DelegationUseHttpAuthenticator::trusted_forwarder(
                    TOKEN.into(),
                    self.f.caller.organization_id(),
                )
                .unwrap(),
            ),
        ))
    }
    fn request(&self, id: Uuid, proof: Option<Vec<u8>>, lifetime: Duration) -> Request<Body> {
        let now = Utc::now();
        let actor = serde_json::to_value(self.f.caller.actor()).unwrap();
        Request::builder()
            .method(if proof.is_some() { "POST" } else { "GET" })
            .uri(format!(
                "/internal/v1/organizations/{}/delegated-use/challenges/{id}/{}",
                self.f.caller.organization_id(),
                if proof.is_some() { "proof" } else { "request" }
            ))
            .header("content-type", "application/octet-stream")
            .header("x-service-token", TOKEN)
            .header(
                "x-marty-use-organization-id",
                self.f.caller.organization_id().to_string(),
            )
            .header(
                "x-marty-use-principal-type",
                actor["type"].as_str().unwrap(),
            )
            .header("x-marty-use-principal-id", &self.f.caller.actor().id)
            .header(
                "x-marty-use-observed-at",
                now.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
            )
            .header(
                "x-marty-use-valid-until",
                (now + lifetime).to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
            )
            .body(Body::from(proof.unwrap_or_default()))
            .unwrap()
    }
    async fn sql(&self, sql: String) {
        sqlx::raw_sql(AssertSqlSafe(sql))
            .execute(&self.f.pool)
            .await
            .unwrap();
    }
    async fn scalar(&self, query: &'static str) -> i64 {
        self.f.scalar(query).await
    }
}

async fn response_bytes(response: axum::response::Response) -> Vec<u8> {
    assert_eq!(response.headers()["cache-control"], "no-store");
    to_bytes(response.into_body(), 262_144)
        .await
        .unwrap()
        .to_vec()
}

#[tokio::test]
#[ignore = "requires isolated FLOW_POSTGRES_TEST_URL"]
async fn postgres_authenticated_ingress_retains_original_request_and_proof_through_finalization(
) -> TestResult {
    let h = Ingress::new().await?;
    let (_, _, challenge) = h.f.start().await?;
    let response = h
        .router()
        .oneshot(h.request(challenge.challenge_id, None, Duration::seconds(25)))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let original_request = response_bytes(response).await;
    // Use a second retrieval for both its exact retained bytes and real signature.
    let response = h
        .router()
        .oneshot(h.request(challenge.challenge_id, None, Duration::seconds(25)))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response_bytes(response).await;
    assert_eq!(bytes, original_request);
    let jwt = std::str::from_utf8(&bytes)?;
    let parts: Vec<_> = jwt.split('.').collect();
    h.request_signer.key.verifying_key().verify(
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2])?)?,
    )?;
    let payload: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
    assert_eq!(payload["nonce"], challenge.nonce);
    assert_eq!(payload["client_id"], challenge.verifier_id);
    assert_eq!(payload["state"], challenge.challenge_id.to_string());
    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT request_bytes FROM flow_service.delegated_request_results WHERE challenge_id=$1",
    )
    .bind(challenge.challenge_id)
    .fetch_one(&h.f.pool)
    .await?;
    assert_eq!(stored, bytes);
    assert_eq!(h.request_signer.calls.load(Ordering::SeqCst), 1);
    let proof = h.f.proof(&challenge);
    let response = h
        .router()
        .oneshot(h.request(
            challenge.challenge_id,
            Some(proof.clone()),
            Duration::seconds(25),
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let submitted: serde_json::Value = serde_json::from_slice(&response_bytes(response).await)?;
    assert_eq!(submitted["recovered"], false);
    assert!(!submitted.to_string().contains(std::str::from_utf8(&proof)?));
    assert_eq!(
        h.scalar("SELECT count(*) FROM flow_service.delegated_proof_ingress")
            .await,
        1
    );
    let final_command = serde_json::to_vec(
        &json!({"profile":DELEGATION_COMMAND_PROFILE,"command":"FINALIZE_USE",
        "command_id":Uuid::new_v4(),"challenge_id":challenge.challenge_id,"proof_submission_id":submitted["submission_id"]}),
    )?;
    let final_result = h.f.service.execute(&h.f.caller, &final_command).await?;
    assert!(matches!(
        final_result.result,
        DelegationUseCommandResult::FinalUse { .. }
    ));
    let response = h
        .router()
        .oneshot(h.request(challenge.challenge_id, Some(proof), Duration::seconds(25)))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let historical: serde_json::Value = serde_json::from_slice(&response_bytes(response).await)?;
    assert_eq!(historical["submission_id"], submitted["submission_id"]);
    assert_eq!(historical["received_at"], submitted["received_at"]);
    assert_eq!(historical["recovered"], true);
    assert_eq!(
        h.scalar("SELECT count(*) FROM flow_service.delegated_proof_submissions")
            .await,
        1
    );
    assert_eq!(
        h.scalar("SELECT count(*) FROM flow_service.delegated_proof_ingress")
            .await,
        1
    );
    let response = h
        .router()
        .oneshot(h.request(challenge.challenge_id, None, Duration::seconds(25)))
        .await?;
    assert!(!response.status().is_success());
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated FLOW_POSTGRES_TEST_URL"]
async fn postgres_ingress_requires_exact_authenticated_scope_and_current_access_and_closes_public_bypass(
) -> TestResult {
    let h = Ingress::new().await?;
    let (_, _, challenge) = h.f.start().await?;
    for mutation in 0..9 {
        let mut request = h.request(challenge.challenge_id, None, Duration::seconds(25));
        let expected = match mutation {
            0 => {
                request.headers_mut().remove("x-service-token");
                StatusCode::UNAUTHORIZED
            }
            1 => {
                request
                    .headers_mut()
                    .append("x-marty-use-principal-id", "urn:example:duplicate".parse()?);
                StatusCode::BAD_REQUEST
            }
            2 => {
                request
                    .headers_mut()
                    .insert("authorization", "Bearer human-token".parse()?);
                StatusCode::FORBIDDEN
            }
            3 => {
                request.headers_mut().insert(
                    "x-marty-use-organization-id",
                    Uuid::new_v4().to_string().parse()?,
                );
                StatusCode::FORBIDDEN
            }
            4 => {
                request
                    .headers_mut()
                    .insert("x-marty-use-principal-type", "USER".parse()?);
                StatusCode::FORBIDDEN
            }
            5 => {
                request.headers_mut().insert(
                    "x-marty-use-principal-id",
                    "urn:example:another-actor".parse()?,
                );
                StatusCode::FORBIDDEN
            }
            6 => {
                *request.uri_mut() =
                    format!("{}?request=caller-supplied", request.uri()).parse()?;
                StatusCode::BAD_REQUEST
            }
            7 => {
                *request.body_mut() = Body::from("unexpected request claims");
                StatusCode::BAD_REQUEST
            }
            _ => {
                request.headers_mut().insert(
                    "x-marty-use-observed-at",
                    (Utc::now() + Duration::seconds(1))
                        .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
                        .parse()?,
                );
                StatusCode::FORBIDDEN
            }
        };
        let response = h.router().oneshot(request).await?;
        assert_eq!(response.status(), expected, "mutation {mutation}");
    }
    let mut wrong_type = h.request(
        challenge.challenge_id,
        Some(b"proof".to_vec()),
        Duration::seconds(25),
    );
    wrong_type
        .headers_mut()
        .insert("content-type", "application/json".parse()?);
    assert_eq!(
        h.router().oneshot(wrong_type).await?.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    let large = h.request(
        challenge.challenge_id,
        Some(vec![b'x'; MAX_DELEGATE_PROOF_BYTES + 1]),
        Duration::seconds(25),
    );
    assert_eq!(
        h.router().oneshot(large).await?.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    for (lifetime, offset) in [(31_000, 0), (30_000, -1), (30_000, 1_000)] {
        h.access.lifetime_ms.store(lifetime, Ordering::SeqCst);
        h.access
            .observation_offset_ms
            .store(offset, Ordering::SeqCst);
        let response = h
            .router()
            .oneshot(h.request(challenge.challenge_id, None, Duration::seconds(10)))
            .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    h.access.lifetime_ms.store(30_000, Ordering::SeqCst);
    h.access.observation_offset_ms.store(0, Ordering::SeqCst);
    h.access.allowed.store(false, Ordering::SeqCst);
    assert_eq!(
        h.router()
            .oneshot(h.request(challenge.challenge_id, None, Duration::seconds(25)))
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    let ordinary_state = crate::FlowHttpState {
        service_authenticator: Some(Arc::new(mmf_security::ServiceTokenAuthenticator::new(
            Some(TOKEN.into()),
            true,
        )?)),
        issuance_prerequisite_authenticator: None,
        repository: PostgresFlowRepository::new(h.f.pool.clone()),
        providers: Arc::new(h.providers.clone()),
        public_base_url: h.f.fixture.configuration.public_base_url.clone(),
        verification: Default::default(),
        application_approval: Default::default(),
    };
    let ordinary = crate::http_verification::flow_verification_routes().with_state(ordinary_state);
    for (method, path) in [
        (
            "GET",
            format!("/v1/flows/instances/{}/request", challenge.challenge_id),
        ),
        (
            "POST",
            format!(
                "/internal/v1/wallet-verifier-requests/{}",
                challenge.challenge_id
            ),
        ),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("x-service-token", TOKEN)
            .body(Body::empty())?;
        assert_eq!(
            ordinary.clone().oneshot(request).await?.status(),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(h.request_signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        h.scalar("SELECT count(*) FROM flow_service.delegated_request_claims")
            .await,
        0
    );
    assert_eq!(
        h.scalar("SELECT count(*) FROM flow_service.delegated_proof_submissions")
            .await,
        0
    );
    Ok(())
}

async fn wait_for_signer(signer: &RequestSigner, calls: usize) {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while signer.calls.load(Ordering::SeqCst) < calls {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires isolated FLOW_POSTGRES_TEST_URL"]
async fn postgres_request_claim_prevents_retry_after_signer_failure_expiry_revocation_and_cancellation(
) -> TestResult {
    let h = Ingress::new().await?;
    let (_, _, failed) = h.f.start().await?;
    h.request_signer.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        h.router()
            .oneshot(h.request(failed.challenge_id, None, Duration::seconds(25)))
            .await?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    h.request_signer.fail.store(false, Ordering::SeqCst);
    assert_eq!(
        h.router()
            .oneshot(h.request(failed.challenge_id, None, Duration::seconds(25)))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(h.request_signer.calls.load(Ordering::SeqCst), 1);
    let (_, _, expired) = h.f.start().await?;
    h.request_signer.delay_ms.store(1_100, Ordering::SeqCst);
    assert_eq!(
        h.router()
            .oneshot(h.request(expired.challenge_id, None, Duration::milliseconds(750)))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        h.router()
            .oneshot(h.request(expired.challenge_id, None, Duration::seconds(25)))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(h.request_signer.calls.load(Ordering::SeqCst), 2);
    let (_, _, revoked) = h.f.start().await?;
    let router = h.router();
    let request = h.request(revoked.challenge_id, None, Duration::seconds(25));
    let work = tokio::spawn(async move { router.oneshot(request).await.unwrap() });
    wait_for_signer(&h.request_signer, 3).await;
    h.access.allowed.store(false, Ordering::SeqCst);
    assert_eq!(work.await?.status(), StatusCode::FORBIDDEN);
    h.access.allowed.store(true, Ordering::SeqCst);
    assert_eq!(
        h.router()
            .oneshot(h.request(revoked.challenge_id, None, Duration::seconds(25)))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let (_, _, cancelled) = h.f.start().await?;
    h.request_signer.delay_ms.store(2_000, Ordering::SeqCst);
    let router = h.router();
    let request = h.request(cancelled.challenge_id, None, Duration::seconds(25));
    let work = tokio::spawn(async move { router.oneshot(request).await.unwrap() });
    wait_for_signer(&h.request_signer, 4).await;
    work.abort();
    let _ = work.await;
    assert_eq!(
        h.router()
            .oneshot(h.request(cancelled.challenge_id, None, Duration::seconds(25)))
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(h.request_signer.calls.load(Ordering::SeqCst), 4);
    assert_eq!(
        h.scalar("SELECT count(*) FROM flow_service.delegated_request_claims")
            .await,
        4
    );
    assert_eq!(
        h.scalar("SELECT count(*) FROM flow_service.delegated_request_results")
            .await,
        0
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated FLOW_POSTGRES_TEST_URL"]
async fn postgres_ingress_preserves_authentication_deadline_after_actual_flow_row_lock_waits(
) -> TestResult {
    let h = Ingress::new().await?;
    for proof in [false, true] {
        let (_, _, challenge) = h.f.start().await?;
        let mut lock = h.f.pool.begin().await?;
        sqlx::query("SELECT id FROM flow_service.flow_instances WHERE id=$1 FOR UPDATE")
            .bind(challenge.challenge_id.to_string())
            .fetch_one(&mut *lock)
            .await?;
        let router = h.router();
        let request = h.request(
            challenge.challenge_id,
            proof.then(|| h.f.proof(&challenge)),
            Duration::milliseconds(1_200),
        );
        let work = tokio::spawn(async move { router.oneshot(request).await.unwrap() });
        tokio::time::timeout(std::time::Duration::from_secs(1),async {
            loop {
                let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock')")
                    .bind(&h.role).fetch_one(&h.f.pool).await.unwrap();
                if waiting { break; }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }).await?;
        tokio::time::sleep(std::time::Duration::from_millis(1_250)).await;
        lock.commit().await?;
        assert_eq!(work.await?.status(), StatusCode::CONFLICT);
    }
    assert_eq!(h.request_signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        h.scalar("SELECT count(*) FROM flow_service.delegated_request_claims")
            .await,
        0
    );
    assert_eq!(
        h.scalar("SELECT count(*) FROM flow_service.delegated_proof_submissions")
            .await,
        0
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated FLOW_POSTGRES_TEST_URL"]
async fn postgres_proof_ingress_checks_body_and_deferred_commit_expiry_without_refreshing_history(
) -> TestResult {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let h = Ingress::new().await?;
    let (_, _, challenge) = h.f.start().await?;
    let proof = h.f.proof(&challenge);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let router = h.router();
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let mut socket = tokio::net::TcpStream::connect(address).await?;
    let now = Utc::now();
    let until = now + Duration::milliseconds(250);
    let actor = serde_json::to_value(h.f.caller.actor())?;
    let headers=format!("POST /internal/v1/organizations/{}/delegated-use/challenges/{}/proof HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nx-service-token: {TOKEN}\r\nx-marty-use-organization-id: {}\r\nx-marty-use-principal-type: {}\r\nx-marty-use-principal-id: {}\r\nx-marty-use-observed-at: {}\r\nx-marty-use-valid-until: {}\r\n\r\n",h.f.caller.organization_id(),challenge.challenge_id,proof.len(),h.f.caller.organization_id(),actor["type"].as_str().unwrap(),h.f.caller.actor().id,now.to_rfc3339_opts(chrono::SecondsFormat::AutoSi,true),until.to_rfc3339_opts(chrono::SecondsFormat::AutoSi,true));
    socket.write_all(headers.as_bytes()).await?;
    socket.write_all(&proof[..1]).await?;
    tokio::time::sleep(std::time::Duration::from_millis(350)).await;
    socket.write_all(&proof[1..]).await?;
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        socket.read_to_end(&mut response),
    )
    .await??;
    server.abort();
    assert!(String::from_utf8(response)?.starts_with("HTTP/1.1 403"));
    assert_eq!(h.access.calls.load(Ordering::SeqCst), 0);
    h.sql("CREATE FUNCTION flow_service.synthetic_ingress_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.9); RETURN NEW; END $$;
      CREATE CONSTRAINT TRIGGER aaa_ingress_delay AFTER INSERT ON flow_service.delegated_proof_ingress DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION flow_service.synthetic_ingress_delay();".into()).await;
    let response = h
        .router()
        .oneshot(h.request(
            challenge.challenge_id,
            Some(proof.clone()),
            Duration::milliseconds(700),
        ))
        .await?;
    assert!(!response.status().is_success());
    assert_eq!(
        h.scalar("SELECT count(*) FROM flow_service.delegated_proof_submissions")
            .await,
        0
    );
    assert_eq!(
        h.scalar("SELECT count(*) FROM flow_service.delegated_proof_ingress")
            .await,
        0
    );
    h.sql("DROP TRIGGER aaa_ingress_delay ON flow_service.delegated_proof_ingress;
      CREATE CONSTRAINT TRIGGER zzz_ingress_delay AFTER INSERT ON flow_service.delegated_proof_ingress DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION flow_service.synthetic_ingress_delay();".into()).await;
    let response = h
        .router()
        .oneshot(h.request(
            challenge.challenge_id,
            Some(proof.clone()),
            Duration::milliseconds(700),
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        h.scalar("SELECT count(*) FROM flow_service.delegated_proof_submissions")
            .await,
        1
    );
    assert_eq!(
        h.scalar("SELECT count(*) FROM flow_service.delegated_proof_ingress")
            .await,
        1
    );
    let received: DateTime<Utc> =
        sqlx::query_scalar("SELECT received_at FROM flow_service.delegated_proof_submissions")
            .fetch_one(&h.f.pool)
            .await?;
    h.sql("DROP TRIGGER zzz_ingress_delay ON flow_service.delegated_proof_ingress; DROP FUNCTION flow_service.synthetic_ingress_delay();".into()).await;
    let response = h
        .router()
        .oneshot(h.request(challenge.challenge_id, Some(proof), Duration::seconds(25)))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let historical: serde_json::Value = serde_json::from_slice(&response_bytes(response).await)?;
    assert_eq!(historical["recovered"], true);
    assert_eq!(
        DateTime::parse_from_rfc3339(historical["received_at"].as_str().unwrap())?
            .with_timezone(&Utc),
        received
    );
    assert_eq!(
        h.scalar("SELECT count(*) FROM flow_service.delegated_proof_ingress")
            .await,
        1
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated FLOW_POSTGRES_TEST_URL"]
async fn postgres_ingress_rejects_role_and_guard_drift_with_minimal_login_and_exact_lock_helper(
) -> TestResult {
    let h = Ingress::new().await?;
    h.app.readiness().await?;
    for capability in ["pg_execute_server_program", "pg_monitor"] {
        h.sql(format!("GRANT {capability} TO {}", h.role)).await;
        assert!(h.app.readiness().await.is_err());
        h.sql(format!("REVOKE {capability} FROM {}", h.role)).await;
    }
    h.sql(format!("ALTER ROLE {} REPLICATION", h.role)).await;
    assert!(h.app.readiness().await.is_err());
    h.sql(format!("ALTER ROLE {} NOREPLICATION", h.role)).await;
    for privilege in [
        "UPDATE ON flow_service.flow_definitions",
        "UPDATE(status) ON flow_service.flow_instances",
        "SELECT ON delegated_authority_service.delegation_grants",
        "REFERENCES(request_bytes) ON flow_service.delegated_request_results",
        "MAINTAIN ON flow_service.delegated_request_results",
    ] {
        h.sql(format!("GRANT {privilege} TO {}", h.role)).await;
        assert!(h.app.readiness().await.is_err(), "privilege {privilege}");
        h.sql(format!("REVOKE {privilege} FROM {}", h.role)).await;
    }
    let role = h.role.clone();
    let masked = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(move |connection, _| {
            let sql = format!("SET ROLE {role}");
            Box::pin(async move {
                sqlx::raw_sql(AssertSqlSafe(sql))
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(h.f.pool.connect_options().as_ref().clone())
        .await?;
    assert!(FlowDelegatedUseIngress::new(
        PostgresFlowRepository::new(masked),
        h.providers.clone(),
        h.access.clone(),
        h.f.fixture.configuration.public_base_url.clone(),
        RequestObjectOptions::default()
    )
    .await
    .is_err());
    for (table, trigger) in [
        (
            "delegated_request_claims",
            "delegated_request_claims_commit",
        ),
        (
            "delegated_request_results",
            "delegated_request_results_binding",
        ),
        (
            "delegated_proof_ingress",
            "delegated_proof_ingress_immutable",
        ),
        (
            "delegated_proof_submissions",
            "delegated_proof_submission_guard",
        ),
    ] {
        h.sql(format!(
            "ALTER TABLE flow_service.{table} DISABLE TRIGGER {trigger}"
        ))
        .await;
        assert!(h.app.readiness().await.is_err());
        h.sql(format!(
            "ALTER TABLE flow_service.{table} ENABLE TRIGGER {trigger}"
        ))
        .await;
    }
    h.sql("ALTER FUNCTION flow_service.lock_delegated_ingress_definition(uuid,uuid) SET search_path=public".into()).await;
    assert!(h.app.readiness().await.is_err());
    h.sql("ALTER FUNCTION flow_service.lock_delegated_ingress_definition(uuid,uuid) SET search_path=pg_catalog".into()).await;
    h.sql(
        "ALTER FUNCTION flow_service.lock_delegated_ingress_definition(uuid,uuid) SECURITY INVOKER"
            .into(),
    )
    .await;
    assert!(h.app.readiness().await.is_err());
    h.sql(
        "ALTER FUNCTION flow_service.lock_delegated_ingress_definition(uuid,uuid) SECURITY DEFINER"
            .into(),
    )
    .await;
    h.sql("CREATE OR REPLACE FUNCTION flow_service.guard_delegated_ingress() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN RETURN NEW; END; $$".into()).await;
    assert!(h.app.readiness().await.is_err());
    // The bundled forward migration restores the fixture; no original migration
    // bytes or real deployment schema are rewritten.
    sqlx::raw_sql(include_str!("../migrations/0006_delegated_use_ingress.sql"))
        .execute(&h.f.pool)
        .await?;
    h.app.readiness().await?;
    let (_, _, challenge) = h.f.start().await?;
    let response = h
        .router()
        .oneshot(h.request(challenge.challenge_id, None, Duration::seconds(25)))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    for table in ["delegated_request_claims", "delegated_request_results"] {
        let error = sqlx::raw_sql(AssertSqlSafe(format!("DELETE FROM flow_service.{table}")))
            .execute(&h.f.pool)
            .await;
        assert!(error.is_err());
    }
    Ok(())
}
