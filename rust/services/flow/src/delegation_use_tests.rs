//! Real Flow/PostgreSQL composition with Core JWT VP proof verification.
//! Consent, access and domain policy ports are synthetic trusted fixtures; this
//! is not a deployment qualification of those sources or a live KMS.

#[path = "delegation_use_ingress_tests.rs"]
mod authenticated_ingress;

use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_delegated_authority::{
    CedarDecision, CedarEvaluation, CedarEvaluationError, CedarEvaluationRequest,
    ConstraintVerificationError, DelegatedDecisionReceiptIssuer, DelegatedDecisionReceiptSigner,
    DelegatedReceiptSigningError, DelegatedReceiptSigningKey, DelegatedReceiptSigningRequest,
    DelegationCedarEvaluator, DelegationCommandCaller, DelegationUseAuthorizer,
    DelegationUseCommandAuthorizer, DelegationUseCommandError, DelegationUseCommandResult,
    DelegationUseCommandService, DelegationUseFlowOwner, DelegationUseIntent, DelegationUseRequest,
    ExternalConstraintVerifier, MartyOid4vpDelegateProofVerifier, PgDelegationGrantRepository,
    PgDelegationUseRepository, RetainedUseChallenge, VerifiedConstraintEvidence,
    VerifiedDelegationCommandAccess, DELEGATION_COMMAND_PROFILE,
};
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey,
};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize};

use crate::{validate_flow_schema, FlowDelegatedUseOwner};

struct Access(AtomicBool, AtomicI64);
#[async_trait]
impl DelegationUseCommandAuthorizer for Access {
    async fn authorize(
        &self,
        caller: &DelegationCommandCaller,
        _: &DelegationUseIntent,
        grant: &DelegationGrant,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, DelegationUseCommandError> {
        self.authorize_recovery(caller, grant, now).await
    }
    async fn authorize_recovery(
        &self,
        caller: &DelegationCommandCaller,
        grant: &DelegationGrant,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, DelegationUseCommandError> {
        if !self.0.load(Ordering::SeqCst)
            || caller.organization_id() != grant.organization_id
            || caller.actor() != &grant.terms.delegate
        {
            return Err(DelegationUseCommandError::AccessDenied);
        }
        Ok(VerifiedDelegationCommandAccess {
            observed_at: now,
            valid_until: now + Duration::seconds(self.1.load(Ordering::SeqCst)),
        })
    }
}
struct Policy(AtomicBool);
#[async_trait]
impl DelegationCedarEvaluator for Policy {
    async fn evaluate(
        &self,
        _: CedarEvaluationRequest,
        now: DateTime<Utc>,
    ) -> Result<CedarEvaluation, CedarEvaluationError> {
        Ok(CedarEvaluation {
            decision: if self.0.load(Ordering::SeqCst) {
                CedarDecision::Permit
            } else {
                CedarDecision::Forbid
            },
            policy_id: "urn:example:delegated-use-policy".into(),
            policy_revision: 1,
            policy_digest: format!("sha256:{}", "c".repeat(64)),
            evaluated_at: now,
            valid_until: now + Duration::seconds(30),
        })
    }
}
struct NoExternal;
#[async_trait]
impl ExternalConstraintVerifier for NoExternal {
    async fn verify(
        &self,
        _: &DelegationGrant,
        _: &DelegationUseRequest,
        _: DateTime<Utc>,
    ) -> Result<VerifiedConstraintEvidence, ConstraintVerificationError> {
        Err(ConstraintVerificationError)
    }
}
struct ReceiptSigner {
    key: SigningKey,
    calls: AtomicUsize,
    delay_ms: AtomicU64,
    while_signing: Mutex<Option<(PgPool, Uuid, bool)>>,
}
#[async_trait]
impl DelegatedDecisionReceiptSigner for ReceiptSigner {
    async fn resolve_key(
        &self,
        _: Uuid,
        issuer: &Principal,
        purpose: &'static str,
    ) -> Result<DelegatedReceiptSigningKey, DelegatedReceiptSigningError> {
        Ok(DelegatedReceiptSigningKey {
            issuer: issuer.clone(),
            purpose: purpose.into(),
            key_id: "urn:example:delegated-receipt-key".into(),
            algorithm: "ES256".into(),
        })
    }
    async fn sign(
        &self,
        request: DelegatedReceiptSigningRequest,
    ) -> Result<Vec<u8>, DelegatedReceiptSigningError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let delay = self.delay_ms.load(Ordering::SeqCst);
        if delay > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }
        let progress = { self.while_signing.lock().unwrap().take() };
        if let Some((pool, challenge_id, cancel)) = progress {
            let query = if cancel {
                "UPDATE flow_service.flow_instances SET status='cancelled',completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1"
            } else {
                "UPDATE flow_service.flow_instances SET context=jsonb_set(context::jsonb,'{request_retrieved}','true'),state_history=state_history::jsonb || jsonb_build_array(jsonb_build_object('event','concurrent_wallet_retrieval')),updated_at=clock_timestamp() WHERE id=$1"
            };
            sqlx::query(query)
                .bind(challenge_id.to_string())
                .execute(&pool)
                .await
                .map_err(|_| DelegatedReceiptSigningError)?;
        }
        let signature: Signature = self.key.sign(&request.signing_input);
        Ok(signature.normalize_s().to_bytes().to_vec())
    }
}

struct Integrated {
    _schema_lock: sqlx::PgConnection,
    pool: PgPool,
    fixture: Fixture,
    owner: Arc<FlowDelegatedUseOwner>,
    service: Arc<DelegationUseCommandService>,
    caller: DelegationCommandCaller,
    actor_key: SigningKey,
    public_key: serde_json::Value,
    signer: Arc<ReceiptSigner>,
    policy: Arc<Policy>,
    access: Arc<Access>,
}

impl Integrated {
    async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::new_with_actor_type(PrincipalType::ServiceAccount).await
    }
    async fn new_with_actor_type(
        principal_type: PrincipalType,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let url = std::env::var("FLOW_POSTGRES_TEST_URL")?;
        let options = PgConnectOptions::from_str(&url)?;
        assert!(matches!(options.get_host(), "127.0.0.1" | "localhost"));
        assert_eq!(options.get_database(), Some("marty_atomic_test"));
        let schema_lock = flow_schema::lock_shared_test_schemas(&options).await?;
        let pool = PgPoolOptions::new()
            .max_connections(12)
            .connect_with(options)
            .await?;
        reset_schema(&pool).await?;
        sqlx::raw_sql("DROP SCHEMA IF EXISTS delegated_authority_service CASCADE")
            .execute(&pool)
            .await?;
        migrate_flow_schema(&pool).await?;
        let grants = Arc::new(PgDelegationGrantRepository::new(pool.clone()));
        grants.migrate().await?;
        let actor_key = SigningKey::from_slice(&rand::random::<[u8; 32]>())?;
        let point = actor_key.verifying_key().to_sec1_point(false);
        let public_key = json!({"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),"y":URL_SAFE_NO_PAD.encode(point.y().unwrap())});
        let thumbprint =
            marty_verification::jwk::Jwk::from_json(&public_key.to_string())?.thumbprint()?;
        let thumbprint = format!(
            "sha256:{}",
            hex::encode(URL_SAFE_NO_PAD.decode(thumbprint)?)
        );
        let fixture = Fixture::new_with_typed_repository(
            Utc::now() - Duration::milliseconds(1),
            "https://agents.example/registered-runtime".into(),
            thumbprint,
            grants,
            principal_type,
        )
        .await;
        // This fixture spans independent real database/application clocks. Its
        // source clock must advance during preparation, proof and commit waits.
        fixture.clock.1.store(true, Ordering::SeqCst);
        let repository = PostgresFlowRepository::new(pool.clone());
        repository.save_definition(&fixture.definition).await?;
        let owner = Arc::new(
            FlowDelegatedUseOwner::new(
                repository.clone(),
                fixture.providers.clone(),
                fixture.configuration.clone(),
            )
            .await?,
        );
        let verifier = Arc::new(MartyOid4vpDelegateProofVerifier::new(
            Arc::new(FlowDelegationOid4vpChallengeStore::new(repository)),
            120,
        )?);
        let policy = Arc::new(Policy(AtomicBool::new(true)));
        let evaluator = Arc::new(DelegationUseAuthorizer::new(
            fixture.lifecycle.clone(),
            verifier,
            Arc::new(NoExternal),
            policy.clone(),
        ));
        let signer = Arc::new(ReceiptSigner {
            key: SigningKey::from_slice(&rand::random::<[u8; 32]>())?,
            calls: AtomicUsize::new(0),
            delay_ms: AtomicU64::new(0),
            while_signing: Mutex::new(None),
        });
        let receipts = Arc::new(DelegatedDecisionReceiptIssuer::new(
            signer.clone(),
            fixture.grant.authority.issuer.clone(),
            60,
        )?);
        let access = Arc::new(Access(AtomicBool::new(true), AtomicI64::new(30)));
        let service = Arc::new(DelegationUseCommandService::new(
            PgDelegationUseRepository::new(pool.clone()),
            fixture.lifecycle.clone(),
            Arc::new(fixture.issuer.clone()),
            evaluator,
            receipts,
            owner.clone(),
            access.clone(),
        ));
        let caller = DelegationCommandCaller::from_authenticated_context(
            fixture.grant.organization_id,
            fixture.grant.terms.delegate.clone(),
        )?;
        Ok(Self {
            _schema_lock: schema_lock,
            pool,
            fixture,
            owner,
            service,
            caller,
            actor_key,
            public_key,
            signer,
            policy,
            access,
        })
    }
    async fn start(
        &self,
    ) -> Result<
        (
            Vec<u8>,
            marty_delegated_authority::DelegationUseCommandResponse,
            RetainedUseChallenge,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let g = &self.fixture.grant;
        let raw = serde_json::to_vec(
            &json!({"profile":DELEGATION_COMMAND_PROFILE,"command":"START_USE","command_id":Uuid::new_v4(),
            "grant":{"id":g.id,"revision":g.revision,"terms_digest":g.terms_digest},
            "operation":{"action":g.terms.actions[0],"resource_id":g.terms.resources[0],"audience":g.terms.audiences[0],
                "request_profile":g.terms.constraints.request_profile,"request_digest":g.terms.constraints.request_digest}}),
        )?;
        let response = self
            .service
            .execute(&self.caller, &raw)
            .await
            .map_err(|error| format!("START_USE: {error:?}"))?;
        let DelegationUseCommandResult::Challenge { challenge_id, .. } = &response.result else {
            panic!("wrong result")
        };
        let value:serde_json::Value=sqlx::query_scalar("SELECT challenge_document FROM delegated_authority_service.use_admissions WHERE organization_id=$1 AND challenge_id=$2")
            .bind(g.organization_id).bind(*challenge_id).fetch_one(&self.pool).await?;
        Ok((raw, response, serde_json::from_value(value)?))
    }
    fn proof(&self, challenge: &RetainedUseChallenge) -> Vec<u8> {
        let now = Utc::now().timestamp();
        let header = json!({"alg":"ES256","typ":"JWT","jwk":self.public_key});
        let claims = json!({"iss":self.caller.actor().id,"sub":self.caller.actor().id,"aud":challenge.verifier_id,
            "nonce":challenge.nonce,"iat":now,"nbf":now,"exp":now+90,
            "vp":{"@context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiablePresentation"],"holder":self.caller.actor().id}});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature: Signature = self.actor_key.sign(input.as_bytes());
        format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(signature.normalize_s().to_bytes())
        )
        .into_bytes()
    }
    async fn final_request(
        &self,
        challenge: &RetainedUseChallenge,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let proof = self.proof(challenge);
        let submission = self
            .owner
            .record_proof_submission(&self.caller, challenge.challenge_id, &proof)
            .await
            .map_err(|error| format!("record proof: {error:?}"))?;
        let repeated = self
            .owner
            .record_proof_submission(&self.caller, challenge.challenge_id, &proof)
            .await?;
        assert_eq!(submission.submission_id, repeated.submission_id);
        assert!(repeated.recovered);
        Ok(serde_json::to_vec(
            &json!({"profile":DELEGATION_COMMAND_PROFILE,"command":"FINALIZE_USE","command_id":Uuid::new_v4(),
            "challenge_id":challenge.challenge_id,"proof_submission_id":submission.submission_id}),
        )?)
    }
    async fn scalar(&self, query: &'static str) -> i64 {
        sqlx::query_scalar(query)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn http(&self, raw: &[u8], valid_for: Duration) -> axum::response::Response {
        use axum::{body::Body, http::Request};
        use marty_delegated_authority::use_http::{
            delegated_use_command_router, DelegationUseHttpState,
        };
        use tower::ServiceExt;
        let token = "synthetic-integrated-use-service-hop-token";
        let now = Utc::now();
        let organization = self.caller.organization_id();
        let state =
            DelegationUseHttpState::new(self.service.clone(), token.into(), organization).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri(format!(
                "/internal/v1/organizations/{organization}/delegated-use-commands"
            ))
            .header("content-type", "application/json")
            .header("x-service-token", token)
            .header("x-marty-use-organization-id", organization.to_string())
            .header("x-marty-use-principal-type", "SERVICE_ACCOUNT")
            .header("x-marty-use-principal-id", &self.caller.actor().id)
            .header(
                "x-marty-use-observed-at",
                now.to_rfc3339_opts(SecondsFormat::AutoSi, true),
            )
            .header(
                "x-marty-use-valid-until",
                (now + valid_for).to_rfc3339_opts(SecondsFormat::AutoSi, true),
            )
            .body(Body::from(raw.to_vec()))
            .unwrap();
        delegated_use_command_router(state)
            .oneshot(request)
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn final_snapshot_allows_only_bounded_progress_and_preserves_authority() {
    use crate::delegation_use::same_delegated_authority_snapshot;
    let fixture = Fixture::new(fixed_now()).await;
    let prepared = prepare_delegated_verification_start(
        &fixture.providers,
        &fixture.configuration,
        fixture.definition.clone(),
        fixture.admission().await,
    )
    .await
    .unwrap();
    let original = prepared.instance;
    let mut progress = original.clone();
    progress.context["request_retrieved"] = json!(true);
    progress
        .state_history
        .push(json!({"event":"request_retrieved"}));
    progress.updated_at += Duration::milliseconds(1);
    assert!(same_delegated_authority_snapshot(&original, &progress).unwrap());
    for case in 0..17 {
        let mut changed = progress.clone();
        match case {
            0 => changed.id = Uuid::new_v4().to_string(),
            1 => changed.organization_id = Uuid::new_v4().to_string(),
            2 => changed.flow_definition_id = Uuid::new_v4().to_string(),
            3 => changed.subject_id = Some("urn:example:other-actor".into()),
            4 => changed.subject_type = "machine_identity".into(),
            5 => changed.status = FlowInstanceStatus::Cancelled,
            6 => changed.expires_at = original.expires_at.map(|time| time + Duration::seconds(1)),
            7 => changed.result = Some(json!({"decision":"PERMIT"})),
            8 => changed.context["oid4vp_client_id"] = json!("did:web:foreign.example"),
            9 => changed.context["_marty_delegation_binding"] = json!({"changed":true}),
            10 => changed.context["request_retrieved"] = json!(false),
            11 => changed.context["oid4vp_response_uri"] = json!("https://foreign.example/submit"),
            12 => changed.context["oid4vp_response_encryption_jwk"] = json!({"kty":"EC"}),
            13 => changed.context["oid4vp_expected_state"] = json!(Uuid::new_v4()),
            14 => changed.context["verification_audience"] = json!("https://foreign.example"),
            15 => changed.context["oid4vp_verifier_context"] = json!(false),
            16 => changed.updated_at = original.updated_at - Duration::milliseconds(1),
            _ => unreachable!(),
        }
        assert!(
            !same_delegated_authority_snapshot(&original, &changed).unwrap(),
            "case {case}"
        );
    }
    let mut cached = progress.clone();
    cached.context["paired_wallet_signed_request_v1"] = json!({"jwt":"original"});
    let mut replaced = cached.clone();
    replaced.context["paired_wallet_signed_request_v1"] = json!({"jwt":"replacement"});
    assert!(!same_delegated_authority_snapshot(&cached, &replaced).unwrap());
}

#[tokio::test]
#[ignore = "requires isolated FLOW_POSTGRES_TEST_URL"]
async fn postgres_use_concurrent_retrieval_preserves_authority_and_latest_history() -> TestResult {
    let f = Integrated::new().await?;
    let (_, _, challenge) = f.start().await?;
    let request = f.final_request(&challenge).await?;
    *f.signer.while_signing.lock().unwrap() = Some((f.pool.clone(), challenge.challenge_id, false));
    let completed = f.service.execute(&f.caller, &request).await?;
    assert!(
        matches!(completed.result,DelegationUseCommandResult::FinalUse{ref decision,..} if decision=="PERMIT")
    );
    let instance = PostgresFlowRepository::new(f.pool.clone())
        .instance(&challenge.challenge_id.to_string())
        .await?
        .unwrap();
    assert_eq!(instance.status, FlowInstanceStatus::Completed);
    assert_eq!(instance.context["request_retrieved"], true);
    assert!(instance
        .state_history
        .iter()
        .any(|value| value["event"] == "concurrent_wallet_retrieval"));
    assert_eq!(
        instance.state_history.last().unwrap()["event"],
        "delegated_use_evidence_recorded"
    );
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        f.scalar("SELECT count(*) FROM flow_service.delegated_use_consumptions")
            .await,
        1
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated FLOW_POSTGRES_TEST_URL"]
async fn postgres_use_retrieval_during_final_row_lock_keeps_completion_time_monotonic() -> TestResult
{
    let f = Integrated::new().await?;
    let (_, _, challenge) = f.start().await?;
    let request = f.final_request(&challenge).await?;
    let mut retrieval = f.pool.begin().await?;
    sqlx::query("SELECT id FROM flow_service.flow_instances WHERE id=$1 FOR UPDATE")
        .bind(challenge.challenge_id.to_string())
        .fetch_one(&mut *retrieval)
        .await?;
    let service = f.service.clone();
    let caller = f.caller.clone();
    let work = tokio::spawn(async move { service.execute(&caller, &request).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT * FROM flow_service.flow_instances%FOR UPDATE%')")
                .fetch_one(&f.pool).await.unwrap();
            if waiting { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await?;
    let retrieved_at: DateTime<Utc> = sqlx::query_scalar("UPDATE flow_service.flow_instances SET context=jsonb_set(context::jsonb,'{request_retrieved}','true'),updated_at=clock_timestamp(),state_history=state_history::jsonb || jsonb_build_array(jsonb_build_object('event','retrieval_after_final_lock_wait','timestamp',clock_timestamp())) WHERE id=$1 RETURNING updated_at")
        .bind(challenge.challenge_id.to_string()).fetch_one(&mut *retrieval).await?;
    retrieval.commit().await?;
    work.await??;
    let instance = PostgresFlowRepository::new(f.pool.clone())
        .instance(&challenge.challenge_id.to_string())
        .await?
        .unwrap();
    assert_eq!(instance.status, FlowInstanceStatus::Completed);
    assert!(instance.updated_at >= retrieved_at);
    assert_eq!(instance.completed_at, Some(instance.updated_at));
    let retrieval_event = instance
        .state_history
        .iter()
        .find(|item| item["event"] == "retrieval_after_final_lock_wait")
        .unwrap();
    let retrieval_time =
        DateTime::parse_from_rfc3339(retrieval_event["timestamp"].as_str().unwrap())?;
    let completion = instance.state_history.last().unwrap();
    let completed_time = DateTime::parse_from_rfc3339(completion["timestamp"].as_str().unwrap())?;
    assert!(completed_time >= retrieval_time);
    let consumed_at: DateTime<Utc> = sqlx::query_scalar(
        "SELECT recorded_at FROM flow_service.delegated_use_consumptions WHERE challenge_id=$1",
    )
    .bind(challenge.challenge_id)
    .fetch_one(&f.pool)
    .await?;
    assert_eq!(consumed_at, instance.updated_at);
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated FLOW_POSTGRES_TEST_URL"]
async fn postgres_use_cancellation_during_signing_remains_terminal_and_unresolved() -> TestResult {
    let f = Integrated::new().await?;
    let (_, _, challenge) = f.start().await?;
    let request = f.final_request(&challenge).await?;
    *f.signer.while_signing.lock().unwrap() = Some((f.pool.clone(), challenge.challenge_id, true));
    assert!(matches!(
        f.service.execute(&f.caller, &request).await,
        Err(DelegationUseCommandError::Conflict)
    ));
    let instance = PostgresFlowRepository::new(f.pool.clone())
        .instance(&challenge.challenge_id.to_string())
        .await?
        .unwrap();
    assert_eq!(instance.status, FlowInstanceStatus::Cancelled);
    assert_eq!(
        f.scalar("SELECT count(*) FROM flow_service.delegated_use_consumptions")
            .await,
        0
    );
    assert_eq!(
        f.scalar("SELECT count(*) FROM delegated_authority_service.use_receipts")
            .await,
        0
    );
    assert!(matches!(
        f.service.execute(&f.caller, &request).await,
        Err(DelegationUseCommandError::PreparationPending)
    ));
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated FLOW_POSTGRES_TEST_URL"]
async fn postgres_use_http_authentication_deadline_survives_signing_wait() -> TestResult {
    use axum::{body::to_bytes, http::StatusCode};
    let f = Integrated::new().await?;
    let (_, _, challenge) = f.start().await?;
    let request = f.final_request(&challenge).await?;
    f.signer.delay_ms.store(450, Ordering::SeqCst);
    let response = f.http(&request, Duration::milliseconds(300)).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024).await?)?;
    assert_eq!(body["detail"], "delegation_use_evidence_expired");
    let instance = PostgresFlowRepository::new(f.pool.clone())
        .instance(&challenge.challenge_id.to_string())
        .await?
        .unwrap();
    assert_eq!(instance.status, FlowInstanceStatus::AwaitingWallet);
    assert_eq!(
        f.scalar("SELECT count(*) FROM flow_service.delegated_use_consumptions")
            .await,
        0
    );
    assert_eq!(
        f.scalar("SELECT count(*) FROM delegated_authority_service.use_receipts")
            .await,
        0
    );
    let repeated = f.http(&request, Duration::seconds(25)).await;
    assert_eq!(repeated.status(), StatusCode::CONFLICT);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(repeated.into_body(), 1024).await?)?;
    assert_eq!(body["detail"], "delegation_use_preparation_pending");
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated FLOW_POSTGRES_TEST_URL"]
async fn postgres_use_http_hop_does_not_qualify_an_overlong_source_observation() -> TestResult {
    use axum::http::StatusCode;
    let f = Integrated::new().await?;
    let (start, _, challenge) = f.start().await?;
    let finalize = f.final_request(&challenge).await?;
    f.access.1.store(3_600, Ordering::SeqCst);
    assert_eq!(
        f.http(&start, Duration::seconds(25)).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.http(&finalize, Duration::seconds(25)).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.scalar("SELECT count(*) FROM delegated_authority_service.use_command_claims")
            .await,
        1
    );
    assert_eq!(
        f.scalar("SELECT count(*) FROM delegated_authority_service.use_receipts")
            .await,
        0
    );
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated FLOW_POSTGRES_TEST_URL"]
async fn postgres_use_http_completion_and_recovery_still_require_current_source_access(
) -> TestResult {
    use axum::{body::to_bytes, http::StatusCode};
    let f = Integrated::new().await?;
    let (start, _, challenge) = f.start().await?;
    let recovered_start = f.http(&start, Duration::seconds(25)).await;
    assert_eq!(recovered_start.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(recovered_start.into_body(), 65536).await?)?;
    assert_eq!(body["recovered"], true);
    assert_eq!(
        body["result"]["challenge_id"],
        challenge.challenge_id.to_string()
    );
    let request = f.final_request(&challenge).await?;
    let finalized = f.http(&request, Duration::seconds(25)).await;
    assert_eq!(finalized.status(), StatusCode::OK);
    let original: serde_json::Value =
        serde_json::from_slice(&to_bytes(finalized.into_body(), 65536).await?)?;
    assert_eq!(original["result"]["decision"], "PERMIT");
    let recovered = f.http(&request, Duration::seconds(25)).await;
    assert_eq!(recovered.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(recovered.into_body(), 65536).await?)?;
    assert_eq!(body["result"], original["result"]);
    assert_eq!(body["recovered"], true);
    f.access.0.store(false, Ordering::SeqCst);
    assert_eq!(
        f.http(&request, Duration::seconds(25)).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated FLOW_POSTGRES_TEST_URL"]
async fn postgres_use_core_proof_atomic_finalization_and_historical_recovery() -> TestResult {
    let f = Integrated::new().await?;
    let (start, first, challenge) = f.start().await?;
    let repeated = f.service.execute(&f.caller, &start).await?;
    assert!(repeated.recovered);
    assert_eq!(
        serde_json::to_value(&first.result)?,
        serde_json::to_value(&repeated.result)?
    );
    // Existing wallet request retrieval records derived metadata/progress. That
    // must not detach a proof from the original retained challenge snapshot.
    let repository = PostgresFlowRepository::new(f.pool.clone());
    let mut retrieved = repository
        .instance(&challenge.challenge_id.to_string())
        .await?
        .unwrap();
    let prior_updated_at = retrieved.updated_at;
    retrieved.context["request_retrieved"] = json!(true);
    retrieved.context["oid4vp_response_uri"] = json!(
        retrieved.context["request_uri"]
            .as_str()
            .unwrap()
            .strip_suffix("/request")
            .unwrap()
            .to_owned()
            + "/submit"
    );
    retrieved.context["oid4vp_expected_state"] = json!(retrieved.id);
    retrieved.context["verification_audience"] = json!(challenge.verifier_id);
    retrieved.context["oid4vp_verifier_context"] = json!(true);
    retrieved.context["oid4vp_response_encryption_jwk"] = serde_json::Value::Null;
    retrieved.updated_at = Utc::now().max(prior_updated_at + Duration::microseconds(1));
    assert!(
        repository
            .compare_and_swap_instance(&retrieved, retrieved.status, prior_updated_at)
            .await?
    );
    let final_request = f.final_request(&challenge).await?;
    let (a, b) = tokio::join!(
        f.service.execute(&f.caller, &final_request),
        f.service.execute(&f.caller, &final_request)
    );
    assert!(
        a.is_ok() || b.is_ok(),
        "both finalizers failed: {a:?} / {b:?}"
    );
    for result in [&a, &b] {
        assert!(
            result.is_ok() || matches!(result, Err(DelegationUseCommandError::PreparationPending))
        );
    }
    let final_response = f.service.execute(&f.caller, &final_request).await?;
    let DelegationUseCommandResult::FinalUse {
        decision,
        receipt_ref,
        receipt_digest,
        semantics,
        ..
    } = &final_response.result
    else {
        panic!("wrong result")
    };
    assert_eq!(decision, "PERMIT");
    assert_eq!(semantics, "EVIDENCE_ONLY");
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        f.scalar("SELECT count(*) FROM flow_service.delegated_use_consumptions")
            .await,
        1
    );
    let compact: String = sqlx::query_scalar(
        "SELECT compact_jws FROM delegated_authority_service.use_receipts WHERE receipt_ref=$1",
    )
    .bind(receipt_ref)
    .fetch_one(&f.pool)
    .await?;
    assert_eq!(
        *receipt_digest,
        format!("sha256:{:x}", Sha256::digest(compact.as_bytes()))
    );
    let parts: Vec<_> = compact.split('.').collect();
    f.signer.key.verifying_key().verify(
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2])?)?,
    )?;
    let flow = PostgresFlowRepository::new(f.pool.clone())
        .instance(&challenge.challenge_id.to_string())
        .await?
        .unwrap();
    assert_eq!(flow.status, FlowInstanceStatus::Completed);
    assert_eq!(
        flow.result.as_ref().unwrap()["receipt_digest"],
        *receipt_digest
    );
    assert_eq!(flow.result.as_ref().unwrap()["semantics"], "EVIDENCE_ONLY");
    assert!(
        FlowDelegationOid4vpChallengeStore::new(PostgresFlowRepository::new(f.pool.clone()))
            .load_active(
                challenge.organization_id,
                challenge.grant.id,
                challenge.challenge_id
            )
            .await
            .is_err()
    );
    f.fixture.clock.set(Utc::now());
    f.fixture
        .lifecycle
        .revoke(
            challenge.organization_id,
            challenge.grant.id,
            challenge.grant.revision,
        )
        .await?;
    let recovered = f.service.execute(&f.caller, &final_request).await?;
    assert_eq!(
        serde_json::to_value(&recovered.result)?,
        serde_json::to_value(&final_response.result)?
    );
    f.access.0.store(false, Ordering::SeqCst);
    assert!(matches!(
        f.service.execute(&f.caller, &final_request).await,
        Err(DelegationUseCommandError::AccessDenied)
    ));
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated FLOW_POSTGRES_TEST_URL"]
async fn postgres_use_policy_denial_is_terminal_and_preserved() -> TestResult {
    let f = Integrated::new().await?;
    let (_, _, challenge) = f.start().await?;
    let request = f.final_request(&challenge).await?;
    f.policy.0.store(false, Ordering::SeqCst);
    let denied = f.service.execute(&f.caller, &request).await?;
    let DelegationUseCommandResult::FinalUse { decision, .. } = &denied.result else {
        panic!("wrong result")
    };
    assert_eq!(decision, "DENY");
    f.policy.0.store(true, Ordering::SeqCst);
    let recovered = f.service.execute(&f.caller, &request).await?;
    assert_eq!(
        serde_json::to_value(&denied.result)?,
        serde_json::to_value(&recovered.result)?
    );
    let mut replacement: serde_json::Value = serde_json::from_slice(&request)?;
    replacement["command_id"] = json!(Uuid::new_v4());
    assert!(f
        .service
        .execute(&f.caller, &serde_json::to_vec(&replacement)?)
        .await
        .is_err());
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated FLOW_POSTGRES_TEST_URL"]
async fn postgres_use_post_sign_failure_rolls_back_flow_and_preserves_uncertainty() -> TestResult {
    let f = Integrated::new().await?;
    let (_, _, challenge) = f.start().await?;
    let request = f.final_request(&challenge).await?;
    sqlx::raw_sql("CREATE FUNCTION delegated_authority_service.test_fail_final_result() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic final result failure'; END $$; \
        CREATE TRIGGER test_fail_final_result BEFORE INSERT ON delegated_authority_service.use_command_results FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.test_fail_final_result();")
        .execute(&f.pool).await?;
    assert!(f.service.execute(&f.caller, &request).await.is_err());
    let flow = PostgresFlowRepository::new(f.pool.clone())
        .instance(&challenge.challenge_id.to_string())
        .await?
        .unwrap();
    assert_eq!(flow.status, FlowInstanceStatus::AwaitingWallet);
    assert!(flow.result.is_none());
    assert_eq!(
        f.scalar("SELECT count(*) FROM flow_service.delegated_use_consumptions")
            .await,
        0
    );
    assert_eq!(
        f.scalar("SELECT count(*) FROM delegated_authority_service.use_receipts")
            .await,
        0
    );
    sqlx::raw_sql("DROP TRIGGER test_fail_final_result ON delegated_authority_service.use_command_results; DROP FUNCTION delegated_authority_service.test_fail_final_result();").execute(&f.pool).await?;
    assert!(matches!(
        f.service.execute(&f.caller, &request).await,
        Err(DelegationUseCommandError::PreparationPending)
    ));
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated FLOW_POSTGRES_TEST_URL"]
async fn postgres_use_proof_isolation_and_database_guard_drift_fail_closed() -> TestResult {
    let f = Integrated::new().await?;
    let (_, _, challenge) = f.start().await?;
    let foreign = DelegationCommandCaller::from_authenticated_context(
        Uuid::new_v4(),
        f.caller.actor().clone(),
    )?;
    assert!(f
        .owner
        .record_proof_submission(&foreign, challenge.challenge_id, &f.proof(&challenge))
        .await
        .is_err());
    let other = DelegationCommandCaller::from_authenticated_context(
        f.caller.organization_id(),
        Principal {
            principal_type: PrincipalType::User,
            id: f.caller.actor().id.clone(),
        },
    )?;
    assert!(f
        .owner
        .record_proof_submission(&other, challenge.challenge_id, &f.proof(&challenge))
        .await
        .is_err());
    assert!(sqlx::query("UPDATE flow_service.flow_instances SET status='completed',completed_at=clock_timestamp() WHERE id=$1")
        .bind(challenge.challenge_id.to_string()).execute(&f.pool).await.is_err());
    assert!(sqlx::query("UPDATE flow_service.flow_instances SET context=jsonb_set(context::jsonb,'{nonce}','\"replacement\"') WHERE id=$1")
        .bind(challenge.challenge_id.to_string()).execute(&f.pool).await.is_err());
    for (key, value) in [
        ("oid4vp_response_uri", "https://foreign.example/submit"),
        ("oid4vp_expected_state", "another-challenge"),
        ("verification_audience", "https://foreign.example"),
    ] {
        assert!(sqlx::query("UPDATE flow_service.flow_instances SET context=jsonb_set(context::jsonb,ARRAY[$2::text],to_jsonb($3::text)),updated_at=clock_timestamp() WHERE id=$1")
            .bind(challenge.challenge_id.to_string()).bind(key).bind(value).execute(&f.pool).await.is_err());
    }
    assert!(sqlx::query(
        "DELETE FROM flow_service.delegated_challenge_bindings WHERE challenge_id=$1"
    )
    .bind(challenge.challenge_id)
    .execute(&f.pool)
    .await
    .is_err());
    validate_flow_schema(&f.pool).await?;
    sqlx::query("ALTER TABLE flow_service.delegated_use_consumptions DISABLE TRIGGER delegated_consumption_commit").execute(&f.pool).await?;
    assert!(validate_flow_schema(&f.pool).await.is_err());
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated FLOW_POSTGRES_TEST_URL"]
async fn postgres_use_invalid_core_signature_cannot_sign_or_consume() -> TestResult {
    let f = Integrated::new().await?;
    let (_, _, challenge) = f.start().await?;
    let mut proof = f.proof(&challenge);
    let signature = proof.iter().rposition(|byte| *byte == b'.').unwrap() + 1;
    proof[signature] = if proof[signature] == b'A' { b'B' } else { b'A' };
    let submission = f
        .owner
        .record_proof_submission(&f.caller, challenge.challenge_id, &proof)
        .await?;
    let request = serde_json::to_vec(
        &json!({"profile":DELEGATION_COMMAND_PROFILE,"command":"FINALIZE_USE","command_id":Uuid::new_v4(),
        "challenge_id":challenge.challenge_id,"proof_submission_id":submission.submission_id}),
    )?;
    assert!(matches!(
        f.service.execute(&f.caller, &request).await,
        Err(DelegationUseCommandError::AccessDenied)
    ));
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        f.scalar("SELECT count(*) FROM flow_service.delegated_use_consumptions")
            .await,
        0
    );
    assert_eq!(
        f.scalar("SELECT count(*) FROM delegated_authority_service.use_receipts")
            .await,
        0
    );
    assert!(matches!(
        f.service.execute(&f.caller, &request).await,
        Err(DelegationUseCommandError::PreparationPending)
    ));
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated FLOW_POSTGRES_TEST_URL"]
async fn postgres_use_start_expiry_after_writes_rolls_back_flow_and_nonce() -> TestResult {
    let f = Integrated::new().await?;
    let expiry = Utc::now() + Duration::milliseconds(650);
    *f.fixture.consent_until.lock().unwrap() = expiry;
    let prepared = f.owner.prepare_start(f.fixture.admission().await).await?;
    let challenge_id = prepared.snapshot().challenge_id;
    let mut transaction = f.pool.begin().await?;
    let now = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *transaction)
        .await?;
    prepared.commit(&mut transaction, now).await?;
    let delay = (expiry - Utc::now() + Duration::milliseconds(50))
        .to_std()
        .unwrap_or_default();
    tokio::time::sleep(delay).await;
    assert!(transaction.commit().await.is_err());
    assert!(PostgresFlowRepository::new(f.pool.clone())
        .instance(&challenge_id.to_string())
        .await?
        .is_none());
    assert_eq!(
        f.scalar("SELECT count(*) FROM flow_service.delegated_challenge_bindings")
            .await,
        0
    );
    Ok(())
}
