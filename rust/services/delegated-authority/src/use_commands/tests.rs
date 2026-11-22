use super::*;
use crate::*;
use serde_json::json;
use sqlx::{postgres::PgPoolOptions, AssertSqlSafe, PgPool};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Mutex,
};

struct Access {
    mutation: AtomicBool,
    read: AtomicBool,
    lifetime_ms: std::sync::atomic::AtomicI64,
    recovery_calls: AtomicUsize,
    recovery_lifetime_ms: std::sync::atomic::AtomicI64,
}
#[async_trait]
impl DelegationUseCommandAuthorizer for Access {
    async fn authorize(
        &self,
        c: &DelegationCommandCaller,
        _: &DelegationUseIntent,
        g: &DelegationGrant,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, DelegationUseCommandError> {
        if !self.mutation.load(Ordering::SeqCst)
            || c.organization_id() != g.organization_id
            || c.actor() != &g.terms.delegate
        {
            return Err(DelegationUseCommandError::AccessDenied);
        }
        Ok(VerifiedDelegationCommandAccess {
            observed_at: now,
            valid_until: now + Duration::milliseconds(self.lifetime_ms.load(Ordering::SeqCst)),
        })
    }
    async fn authorize_recovery(
        &self,
        c: &DelegationCommandCaller,
        g: &DelegationGrant,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, DelegationUseCommandError> {
        self.recovery_calls.fetch_add(1, Ordering::SeqCst);
        if !self.read.load(Ordering::SeqCst)
            || c.organization_id() != g.organization_id
            || c.actor() != &g.terms.delegate
        {
            return Err(DelegationUseCommandError::AccessDenied);
        }
        Ok(VerifiedDelegationCommandAccess {
            observed_at: now,
            valid_until: now
                + Duration::milliseconds(self.recovery_lifetime_ms.load(Ordering::SeqCst)),
        })
    }
}
struct Consent(AtomicBool);
#[async_trait]
impl ConsentEvidenceVerifier for Consent {
    async fn verify_approval(
        &self,
        r: ConsentVerificationRequest<'_>,
    ) -> Result<VerifiedConsent, ConsentVerificationError> {
        if !self.0.load(Ordering::SeqCst) {
            return Err(ConsentVerificationError);
        }
        Ok(VerifiedConsent {
            valid_until: r.grant.terms.valid_until,
        })
    }
}
struct Proof {
    flow: Arc<TestFlow>,
    available: AtomicBool,
}
#[async_trait]
impl DelegateProofVerifier for Proof {
    async fn verify(
        &self,
        g: &DelegationGrant,
        r: &DelegationUseRequest,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegateProof, DelegateProofError> {
        if !self.available.load(Ordering::SeqCst) || r.proof != b"independently-verified-test-proof"
        {
            return Err(DelegateProofError);
        }
        let snapshot = self
            .flow
            .snapshots
            .lock()
            .unwrap()
            .get(&r.challenge_id)
            .cloned()
            .ok_or(DelegateProofError)?;
        Ok(VerifiedDelegateProof {
            evidence_ref: format!("urn:example:proof:{}", r.challenge_id),
            challenge: snapshot.nonce,
            verified_at: now,
            valid_until: snapshot.expires_at.min(g.terms.valid_until),
        })
    }
}
struct Constraint;
#[async_trait]
impl ExternalConstraintVerifier for Constraint {
    async fn verify(
        &self,
        _: &DelegationGrant,
        _: &DelegationUseRequest,
        _: DateTime<Utc>,
    ) -> Result<VerifiedConstraintEvidence, ConstraintVerificationError> {
        Err(ConstraintVerificationError)
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
            policy_id: "urn:example:policy:retained-use".into(),
            policy_revision: 1,
            policy_digest: format!("sha256:{}", "d".repeat(64)),
            evaluated_at: now,
            valid_until: now + Duration::seconds(15),
        })
    }
}
struct Signer {
    calls: AtomicUsize,
    fail: AtomicBool,
    block: AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[async_trait]
impl DelegatedDecisionReceiptSigner for Signer {
    async fn resolve_key(
        &self,
        _: Uuid,
        issuer: &Principal,
        purpose: &'static str,
    ) -> Result<DelegatedReceiptSigningKey, DelegatedReceiptSigningError> {
        Ok(DelegatedReceiptSigningKey {
            issuer: issuer.clone(),
            purpose: purpose.into(),
            key_id: "urn:example:key:receipt".into(),
            algorithm: "EdDSA".into(),
        })
    }
    async fn sign(
        &self,
        _: DelegatedReceiptSigningRequest,
    ) -> Result<Vec<u8>, DelegatedReceiptSigningError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.block.load(Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        if self.fail.load(Ordering::SeqCst) {
            return Err(DelegatedReceiptSigningError);
        }
        // The cryptographic managed signer has independent signature tests;
        // this fixture isolates durable no-retry and transaction behavior.
        Ok(vec![9; 64])
    }
}
struct TestFlow {
    snapshots: Mutex<std::collections::HashMap<Uuid, PreparedUseChallengeSnapshot>>,
    fixed_nonce: Mutex<Option<String>>,
    start_calls: AtomicUsize,
    fail_start: AtomicBool,
    fail_commit: AtomicBool,
    final_commits: AtomicUsize,
    final_preparations: AtomicUsize,
    final_preparation_delay_ms: AtomicU64,
}
struct Start {
    snapshot: PreparedUseChallengeSnapshot,
    fail: bool,
}
#[async_trait]
impl PreparedUseChallenge for Start {
    fn snapshot(&self) -> &PreparedUseChallengeSnapshot {
        &self.snapshot
    }
    async fn revalidate(&mut self) -> Result<(), DelegationUseCommandError> {
        Ok(())
    }
    async fn commit(
        self: Box<Self>,
        tx: &mut PgConnection,
        _: DateTime<Utc>,
    ) -> Result<(), DelegationUseCommandError> {
        sqlx::query(
            "INSERT INTO use_test_flow_records(id,organization_id,consumed) VALUES($1,$2,false)",
        )
        .bind(self.snapshot.challenge_id)
        .bind(self.snapshot.organization_id)
        .execute(tx)
        .await
        .map_err(|_| DelegationUseCommandError::Unavailable)?;
        if self.fail {
            return Err(DelegationUseCommandError::Unavailable);
        }
        Ok(())
    }
}
struct Final {
    id: Uuid,
    org: Uuid,
    fail: bool,
    counter: Arc<TestFlow>,
}
#[async_trait]
impl PreparedUseFinalization for Final {
    async fn commit(
        self: Box<Self>,
        tx: &mut PgConnection,
        _: &DelegationUseEvaluation,
        _: &IssuedDelegatedDecisionReceipt,
        _: DateTime<Utc>,
    ) -> Result<(), DelegationUseCommandError> {
        let n=sqlx::query("UPDATE use_test_flow_records SET consumed=true WHERE id=$1 AND organization_id=$2 AND consumed=false").bind(self.id).bind(self.org).execute(tx).await.map_err(|_|DelegationUseCommandError::Unavailable)?.rows_affected();
        if n != 1 {
            return Err(DelegationUseCommandError::Conflict);
        }
        self.counter.final_commits.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(DelegationUseCommandError::Unavailable);
        }
        Ok(())
    }
}
struct FlowPort(Arc<TestFlow>);
#[async_trait]
impl DelegationUseFlowOwner for FlowPort {
    async fn prepare_start(
        &self,
        a: DelegationChallengeAdmission,
    ) -> Result<Box<dyn PreparedUseChallenge>, DelegationUseCommandError> {
        self.0.start_calls.fetch_add(1, Ordering::SeqCst);
        if self.0.fail_start.load(Ordering::SeqCst) {
            return Err(DelegationUseCommandError::Unavailable);
        }
        let s = PreparedUseChallengeSnapshot {
            organization_id: a.binding().organization_id,
            challenge_id: a.binding().challenge_id,
            verifier_id: "decentralized_identifier:did:web:verifier.example".into(),
            nonce: self
                .0
                .fixed_nonce
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| Uuid::new_v4().simple().to_string()),
            created_at: Utc::now(),
            expires_at: a.valid_until(),
        };
        self.0
            .snapshots
            .lock()
            .unwrap()
            .insert(s.challenge_id, s.clone());
        Ok(Box::new(Start {
            snapshot: s,
            fail: self.0.fail_commit.load(Ordering::SeqCst),
        }))
    }
    async fn resolve_submission(
        &self,
        c: &RetainedUseChallenge,
        id: Uuid,
    ) -> Result<ResolvedUseProofSubmission, DelegationUseCommandError> {
        Ok(ResolvedUseProofSubmission {
            organization_id: c.organization_id,
            challenge_id: c.challenge_id,
            proof_submission_id: id,
            actor: c.grant.terms.delegate.clone(),
            received_at: Utc::now(),
            proof: b"independently-verified-test-proof".to_vec(),
        })
    }
    async fn prepare_finalization(
        &self,
        c: &RetainedUseChallenge,
        _: Uuid,
        _: &str,
    ) -> Result<Box<dyn PreparedUseFinalization>, DelegationUseCommandError> {
        self.0.final_preparations.fetch_add(1, Ordering::SeqCst);
        let delay = self.0.final_preparation_delay_ms.load(Ordering::SeqCst);
        if delay > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }
        Ok(Box::new(Final {
            id: c.challenge_id,
            org: c.organization_id,
            fail: self.0.fail_commit.load(Ordering::SeqCst),
            counter: self.0.clone(),
        }))
    }
}
struct Fixture {
    pool: PgPool,
    service: Arc<DelegationUseCommandService>,
    lifecycle: Arc<DelegationAuthorityService>,
    grant: DelegationGrant,
    caller: DelegationCommandCaller,
    flow: Arc<TestFlow>,
    signer: Arc<Signer>,
    policy: Arc<Policy>,
    access: Arc<Access>,
    consent: Arc<Consent>,
    proof: Arc<Proof>,
    start: Value,
}
impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("DELEGATED_AUTHORITY_TEST_DATABASE_URL")
            .expect("explicit PostgreSQL gate requires test database");
        let pool = PgPoolOptions::new()
            .max_connections(12)
            .connect(&url)
            .await
            .unwrap();
        let repository = Arc::new(PgDelegationGrantRepository::new(pool.clone()));
        repository.migrate().await.unwrap();
        repository.readiness().await.unwrap();
        sqlx::raw_sql("CREATE TABLE IF NOT EXISTS use_test_flow_records(id UUID PRIMARY KEY,organization_id UUID NOT NULL,consumed BOOLEAN NOT NULL)").execute(&pool).await.unwrap();
        let mut template = crate::test_support::pending_grant();
        template.terms.binding = Binding {
            method: BindingMethod::Key,
            key_thumbprint: Some(format!("sha256:{}", "a".repeat(64))),
            session_ref: None,
            establishment_evidence_ref: None,
        };
        template.terms.constraints = Constraints {
            mode: ConstraintMode::ExactOperation,
            request_profile: Some("urn:example:operation:v1".into()),
            request_digest: Some(format!("sha256:{}", "b".repeat(64))),
            profile: None,
            document_ref: None,
            document_digest: None,
            evaluator: None,
        };
        template.terms.valid_from = Utc::now() - Duration::seconds(10);
        template.terms.valid_until = Utc::now() + Duration::hours(1);
        let consent = Arc::new(Consent(AtomicBool::new(true)));
        let lifecycle = Arc::new(
            DelegationAuthorityService::new(repository, consent.clone(), template.authority)
                .unwrap(),
        );
        let pending = lifecycle
            .propose(template.organization_id, template.terms)
            .await
            .unwrap();
        let grant = lifecycle
            .approve(
                pending.organization_id,
                pending.id,
                pending.revision,
                &pending.terms.grantor,
                ApprovalEvidence {
                    profile: "urn:example:approval:v1".into(),
                    evidence_ref: "urn:example:consent:retained".into(),
                    authority_evidence_ref: "urn:example:authority:retained".into(),
                },
            )
            .await
            .unwrap();
        let caller = DelegationCommandCaller::from_authenticated_context(
            grant.organization_id,
            grant.terms.delegate.clone(),
        )
        .unwrap();
        let flow = Arc::new(TestFlow {
            snapshots: Mutex::new(Default::default()),
            fixed_nonce: Mutex::new(None),
            start_calls: AtomicUsize::new(0),
            fail_start: AtomicBool::new(false),
            fail_commit: AtomicBool::new(false),
            final_commits: AtomicUsize::new(0),
            final_preparations: AtomicUsize::new(0),
            final_preparation_delay_ms: AtomicU64::new(0),
        });
        let signer = Arc::new(Signer {
            calls: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
            block: AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let policy = Arc::new(Policy(AtomicBool::new(true)));
        let access = Arc::new(Access {
            mutation: AtomicBool::new(true),
            read: AtomicBool::new(true),
            lifetime_ms: std::sync::atomic::AtomicI64::new(25_000),
            recovery_calls: AtomicUsize::new(0),
            recovery_lifetime_ms: std::sync::atomic::AtomicI64::new(10_000),
        });
        let proof = Arc::new(Proof {
            flow: flow.clone(),
            available: AtomicBool::new(true),
        });
        let evaluation = Arc::new(DelegationUseAuthorizer::new(
            lifecycle.clone(),
            proof.clone(),
            Arc::new(Constraint),
            policy.clone(),
        ));
        let receipts = Arc::new(
            DelegatedDecisionReceiptIssuer::new(signer.clone(), grant.authority.issuer.clone(), 10)
                .unwrap(),
        );
        let service = Arc::new(DelegationUseCommandService::new(
            PgDelegationUseRepository::new(pool.clone()),
            lifecycle.clone(),
            Arc::new(DelegationChallengeIssuer::new(lifecycle.clone(), None, 120).unwrap()),
            evaluation,
            receipts,
            Arc::new(FlowPort(flow.clone())),
            access.clone(),
        ));
        let start = json!({"profile":DELEGATION_COMMAND_PROFILE,"command":"START_USE","command_id":Uuid::new_v4(),"grant":{"id":grant.id,"revision":grant.revision,"terms_digest":grant.terms_digest},"operation":{"action":grant.terms.actions[0],"resource_id":grant.terms.resources[0],"audience":grant.terms.audiences[0],"request_profile":grant.terms.constraints.request_profile,"request_digest":grant.terms.constraints.request_digest}});
        Self {
            pool,
            service,
            lifecycle,
            grant,
            caller,
            flow,
            signer,
            policy,
            access,
            consent,
            proof,
            start,
        }
    }
    async fn execute(
        &self,
        v: &Value,
    ) -> Result<DelegationUseCommandResponse, DelegationUseCommandError> {
        self.service
            .execute(&self.caller, &serde_json::to_vec(v).unwrap())
            .await
    }
    fn final_command(&self, id: Uuid) -> Value {
        json!({"profile":DELEGATION_COMMAND_PROFILE,"command":"FINALIZE_USE","command_id":Uuid::new_v4(),"challenge_id":id,"proof_submission_id":Uuid::new_v4()})
    }
    async fn start_id(&self) -> Uuid {
        match self.execute(&self.start).await.unwrap().result {
            DelegationUseCommandResult::Challenge { challenge_id, .. } => challenge_id,
            _ => panic!("expected challenge"),
        }
    }
    async fn count(&self, table: &str) -> i64 {
        sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT count(*) FROM delegated_authority_service.{table} WHERE organization_id=$1"
        )))
        .bind(self.grant.organization_id)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }
}
fn result_value(r: &DelegationUseCommandResponse) -> Value {
    serde_json::to_value(r).unwrap()
}

#[path = "receipt_tests.rs"]
mod receipt_tests;

#[test]
fn use_decoder_is_closed_and_canonical_and_does_not_enable_human_host() {
    let start = json!({"profile":DELEGATION_COMMAND_PROFILE,"command":"START_USE","command_id":"a0000000-0000-4000-8000-000000000001","grant":{"id":"b0000000-0000-4000-8000-000000000001","revision":2,"terms_digest":format!("sha256:{}","a".repeat(64))},"operation":{"action":"urn:example:action","resource_id":"urn:example:resource","audience":"https://example.invalid","request_profile":"urn:example:operation:v1","request_digest":format!("sha256:{}","b".repeat(64))}});
    let bytes = serde_json::to_vec(&start).unwrap();
    assert!(decode_delegation_use_command(&bytes).is_ok());
    assert!(matches!(
        decode_delegation_command(&bytes),
        Err(DelegationCommandError::UnsupportedCommand)
    ));
    for (field, value) in [
        ("actor", json!({"type":"USER","id":"urn:fake"})),
        ("nonce", json!("caller-nonce")),
        ("proof", json!("caller-proof")),
        ("verified", json!(true)),
    ] {
        let mut bad = start.clone();
        bad[field] = value;
        assert!(decode_delegation_use_command(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    for id in [
        "A0000000-0000-4000-8000-000000000001",
        "00000000-0000-0000-0000-000000000000",
    ] {
        let mut bad = start.clone();
        bad["command_id"] = json!(id);
        assert!(decode_delegation_use_command(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    let text = String::from_utf8(bytes).unwrap();
    let duplicate = text.replacen("{", "{\"command\":\"START_USE\",", 1);
    assert!(decode_delegation_use_command(duplicate.as_bytes()).is_err());
}

#[tokio::test]
async fn authenticated_observation_lower_bound_rejects_regressed_mutation_and_recovery_clocks() {
    struct FixedClock(DateTime<Utc>);
    impl DelegationClock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }
    let observed_at = DateTime::from_timestamp(1_795_219_200, 0).unwrap();
    let grant = crate::test_support::pending_grant();
    let caller = DelegationCommandCaller::from_authenticated_context(
        grant.organization_id,
        grant.terms.delegate.clone(),
    )
    .unwrap();
    let intent = DelegationUseIntent::Finalize {
        challenge_id: Uuid::new_v4(),
        proof_submission_id: Uuid::new_v4(),
    };
    for regression in [false, true] {
        let now = observed_at - Duration::seconds(i64::from(regression));
        let source = Arc::new(Access {
            mutation: AtomicBool::new(true),
            read: AtomicBool::new(true),
            lifetime_ms: std::sync::atomic::AtomicI64::new(25_000),
            recovery_calls: AtomicUsize::new(0),
            recovery_lifetime_ms: std::sync::atomic::AtomicI64::new(10_000),
        });
        let bounded = AuthenticationBoundUseAuthorizer {
            inner: source,
            clock: Arc::new(FixedClock(now)),
            observed_at,
            expires_at: observed_at + Duration::seconds(25),
        };
        // `started` is also after the service-clock regression. Comparing only
        // against that fresh timestamp cannot preserve the HTTP observation.
        let mutation = bounded.authorize(&caller, &intent, &grant, now).await;
        let recovery = bounded.authorize_recovery(&caller, &grant, now).await;
        if regression {
            assert_eq!(mutation.err(), Some(DelegationUseCommandError::Expired));
            assert_eq!(recovery.err(), Some(DelegationUseCommandError::Expired));
        } else {
            assert_eq!(mutation.unwrap().observed_at, observed_at);
            assert_eq!(recovery.unwrap().observed_at, observed_at);
        }
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn postgres_start_retains_one_challenge_and_nonce_across_concurrent_original_retries() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let f = Fixture::new().await;
    let (a, b) = tokio::join!(f.execute(&f.start), f.execute(&f.start));
    assert!(a.is_ok() || b.is_ok());
    for outcome in [a, b] {
        match outcome {
            Ok(_) => {}
            Err(DelegationUseCommandError::PreparationPending) => {}
            Err(e) => panic!("{e:?}"),
        }
    }
    let recovered = f.execute(&f.start).await.unwrap();
    assert!(recovered.recovered);
    assert_eq!(f.flow.start_calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.count("use_admissions").await, 1);
    assert_eq!(f.count("use_command_results").await, 1);
    let mut conflict = f.start.clone();
    conflict["operation"]["request_digest"] = json!(format!("sha256:{}", "c".repeat(64)));
    assert_eq!(
        f.execute(&conflict).await.err(),
        Some(DelegationUseCommandError::Conflict)
    );
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn postgres_uncertain_start_is_durable_and_never_reprepared() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let f = Fixture::new().await;
    f.flow.fail_start.store(true, Ordering::SeqCst);
    assert_eq!(
        f.execute(&f.start).await.err(),
        Some(DelegationUseCommandError::Unavailable)
    );
    f.flow.fail_start.store(false, Ordering::SeqCst);
    assert_eq!(
        f.execute(&f.start).await.err(),
        Some(DelegationUseCommandError::PreparationPending)
    );
    assert_eq!(f.flow.start_calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.count("use_command_claims").await, 1);
    assert_eq!(f.count("use_admissions").await, 0);
    let recreated = DelegationUseCommandService::new(
        PgDelegationUseRepository::new(f.pool.clone()),
        f.lifecycle.clone(),
        Arc::new(DelegationChallengeIssuer::new(f.lifecycle.clone(), None, 120).unwrap()),
        Arc::new(DelegationUseAuthorizer::new(
            f.lifecycle.clone(),
            f.proof.clone(),
            Arc::new(Constraint),
            f.policy.clone(),
        )),
        Arc::new(
            DelegatedDecisionReceiptIssuer::new(
                f.signer.clone(),
                f.grant.authority.issuer.clone(),
                10,
            )
            .unwrap(),
        ),
        Arc::new(FlowPort(f.flow.clone())),
        f.access.clone(),
    );
    assert_eq!(
        recreated
            .execute(&f.caller, &serde_json::to_vec(&f.start).unwrap())
            .await
            .err(),
        Some(DelegationUseCommandError::PreparationPending)
    );
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn postgres_nonce_reuse_fails_and_flow_owner_write_rolls_back() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let f = Fixture::new().await;
    *f.flow.fixed_nonce.lock().unwrap() = Some("n".repeat(32));
    f.start_id().await;
    let mut second = f.start.clone();
    second["command_id"] = json!(Uuid::new_v4());
    assert_eq!(
        f.execute(&second).await.err(),
        Some(DelegationUseCommandError::Conflict)
    );
    assert_eq!(f.count("use_admissions").await, 1);
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM use_test_flow_records WHERE organization_id=$1")
            .bind(f.grant.organization_id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(rows, 1);
    assert_eq!(
        f.execute(&second).await.err(),
        Some(DelegationUseCommandError::PreparationPending)
    );
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn postgres_finalizes_once_and_recovers_exact_signed_bytes_after_revocation() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let f = Fixture::new().await;
    let id = f.start_id().await;
    let final_cmd = f.final_command(id);
    let result = f.execute(&final_cmd).await.unwrap();
    assert_eq!(result_value(&result)["result"]["decision"], "PERMIT");
    assert_eq!(
        result_value(&result)["result"]["semantics"],
        "EVIDENCE_ONLY"
    );
    let compact:String=sqlx::query_scalar("SELECT compact_jws FROM delegated_authority_service.use_receipts WHERE organization_id=$1 AND challenge_id=$2").bind(f.grant.organization_id).bind(id).fetch_one(&f.pool).await.unwrap();
    assert_eq!(
        result_value(&result)["result"]["receipt_digest"],
        format!("sha256:{:x}", Sha256::digest(compact.as_bytes()))
    );
    f.lifecycle
        .revoke(f.grant.organization_id, f.grant.id, f.grant.revision)
        .await
        .unwrap();
    f.access.mutation.store(false, Ordering::SeqCst);
    f.consent.0.store(false, Ordering::SeqCst);
    let recovered = f.execute(&final_cmd).await.unwrap();
    assert!(recovered.recovered);
    assert_eq!(
        result_value(&result)["result"],
        result_value(&recovered)["result"]
    );
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        f.execute(&f.final_command(id)).await.err(),
        Some(DelegationUseCommandError::AccessDenied)
    );
    f.access.read.store(false, Ordering::SeqCst);
    assert_eq!(
        f.execute(&final_cmd).await.err(),
        Some(DelegationUseCommandError::AccessDenied)
    );
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn postgres_completed_policy_denial_is_consumed_and_cannot_retry_into_permit() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let f = Fixture::new().await;
    let id = f.start_id().await;
    let command = f.final_command(id);
    f.policy.0.store(false, Ordering::SeqCst);
    let result = f.execute(&command).await.unwrap();
    assert_eq!(result_value(&result)["result"]["decision"], "DENY");
    f.policy.0.store(true, Ordering::SeqCst);
    let recovered = f.execute(&command).await.unwrap();
    assert_eq!(
        result_value(&recovered)["result"],
        result_value(&result)["result"]
    );
    assert_eq!(
        f.execute(&f.final_command(id)).await.err(),
        Some(DelegationUseCommandError::Conflict)
    );
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 1);
    let consumed: bool =
        sqlx::query_scalar("SELECT consumed FROM use_test_flow_records WHERE id=$1")
            .bind(id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert!(consumed);
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn postgres_signing_failure_stays_pending_and_new_finalization_identity_conflicts() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let f = Fixture::new().await;
    let id = f.start_id().await;
    let command = f.final_command(id);
    f.signer.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        f.execute(&command).await.err(),
        Some(DelegationUseCommandError::Unavailable)
    );
    f.signer.fail.store(false, Ordering::SeqCst);
    assert_eq!(
        f.execute(&command).await.err(),
        Some(DelegationUseCommandError::PreparationPending)
    );
    assert_eq!(
        f.execute(&f.final_command(id)).await.err(),
        Some(DelegationUseCommandError::Conflict)
    );
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.count("use_receipts").await, 0);
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn postgres_invalid_proof_does_not_become_a_denial_or_sign_receipt() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let f = Fixture::new().await;
    let id = f.start_id().await;
    let command = f.final_command(id);
    f.proof.available.store(false, Ordering::SeqCst);
    assert_eq!(
        f.execute(&command).await.err(),
        Some(DelegationUseCommandError::AccessDenied)
    );
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(f.count("use_receipts").await, 0);
    f.proof.available.store(true, Ordering::SeqCst);
    assert_eq!(
        f.execute(&command).await.err(),
        Some(DelegationUseCommandError::PreparationPending)
    );
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn postgres_flow_finalization_failure_rolls_back_consumption_and_receipt() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let f = Fixture::new().await;
    let id = f.start_id().await;
    let command = f.final_command(id);
    f.flow.fail_commit.store(true, Ordering::SeqCst);
    assert_eq!(
        f.execute(&command).await.err(),
        Some(DelegationUseCommandError::Unavailable)
    );
    let consumed: bool =
        sqlx::query_scalar("SELECT consumed FROM use_test_flow_records WHERE id=$1")
            .bind(id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert!(!consumed);
    assert_eq!(f.count("use_receipts").await, 0);
    assert_eq!(f.count("use_command_results").await, 1);
    assert_eq!(
        f.execute(&command).await.err(),
        Some(DelegationUseCommandError::PreparationPending)
    );
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn postgres_current_permission_loss_while_signing_prevents_commit() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let f = Fixture::new().await;
    let id = f.start_id().await;
    let command = f.final_command(id);
    f.signer.block.store(true, Ordering::SeqCst);
    let service = f.service.clone();
    let caller = f.caller.clone();
    let bytes = serde_json::to_vec(&command).unwrap();
    let task = tokio::spawn(async move { service.execute(&caller, &bytes).await });
    f.signer.entered.notified().await;
    f.access.mutation.store(false, Ordering::SeqCst);
    f.signer.release.notify_one();
    assert_eq!(
        task.await.unwrap().err(),
        Some(DelegationUseCommandError::AccessDenied)
    );
    assert_eq!(f.count("use_receipts").await, 0);
    assert_eq!(
        f.execute(&command).await.err(),
        Some(DelegationUseCommandError::PreparationPending)
    );
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn postgres_authentication_expiry_during_final_preparation_never_starts_signing() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let f = Fixture::new().await;
    let id = f.start_id().await;
    let command = f.final_command(id);
    let raw = serde_json::to_vec(&command).unwrap();
    f.flow
        .final_preparation_delay_ms
        .store(1_200, Ordering::SeqCst);
    let authenticated_at = Utc::now();
    let authenticated_until = authenticated_at + Duration::seconds(1);
    assert_eq!(
        f.service
            .execute_before(&f.caller, &raw, authenticated_at, authenticated_until)
            .await
            .err(),
        Some(DelegationUseCommandError::Expired)
    );
    // This must reach the asynchronous preparation under valid admission; the
    // regression is the missing deadline recheck before starting the signer.
    assert_eq!(f.flow.final_preparations.load(Ordering::SeqCst), 1);
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(f.flow.final_commits.load(Ordering::SeqCst), 0);
    assert_eq!(f.count("use_receipts").await, 0);
    assert_eq!(f.count("use_command_claims").await, 2);
    assert_eq!(f.count("use_command_results").await, 1);
    let consumed: bool = sqlx::query_scalar(
        "SELECT consumed FROM use_test_flow_records WHERE id=$1 AND organization_id=$2",
    )
    .bind(id)
    .bind(f.grant.organization_id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(!consumed);

    // Renewing the service-hop authentication cannot restart the retained
    // original command or manufacture a different signed result.
    f.flow.final_preparation_delay_ms.store(0, Ordering::SeqCst);
    let renewed_at = Utc::now();
    assert_eq!(
        f.service
            .execute_before(
                &f.caller,
                &raw,
                renewed_at,
                renewed_at + Duration::seconds(25),
            )
            .await
            .err(),
        Some(DelegationUseCommandError::PreparationPending)
    );
    assert_eq!(f.flow.final_preparations.load(Ordering::SeqCst), 1);
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(f.count("use_command_claims").await, 2);
    assert_eq!(f.count("use_command_results").await, 1);
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn postgres_new_rows_are_immutable_and_guard_drift_fails_readiness() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let f = Fixture::new().await;
    let id = f.start_id().await;
    f.execute(&f.final_command(id)).await.unwrap();
    for table in [
        "command_identities",
        "use_command_claims",
        "use_admissions",
        "use_receipts",
        "use_command_results",
    ] {
        assert!(sqlx::query(AssertSqlSafe(format!(
            "DELETE FROM delegated_authority_service.{table} WHERE organization_id=$1"
        )))
        .bind(f.grant.organization_id)
        .execute(&f.pool)
        .await
        .is_err());
    }
    let mut tx = f.pool.begin().await.unwrap();
    sqlx::raw_sql("ALTER TABLE delegated_authority_service.use_command_results DISABLE TRIGGER use_command_results_commit").execute(&mut *tx).await.unwrap();
    // Metadata check in this same connection sees disabled trigger; separately
    // committing drift and restoring it exercises actual service readiness.
    tx.commit().await.unwrap();
    assert!(PgDelegationGrantRepository::new(f.pool.clone())
        .readiness()
        .await
        .is_err());
    sqlx::raw_sql("ALTER TABLE delegated_authority_service.use_command_results ENABLE TRIGGER use_command_results_commit").execute(&f.pool).await.unwrap();
    PgDelegationGrantRepository::new(f.pool.clone())
        .readiness()
        .await
        .unwrap();
}

struct LifecycleAccess;
#[async_trait]
impl DelegationCommandAuthorizer for LifecycleAccess {
    async fn authorize_mutation(
        &self,
        _: &DelegationCommandCaller,
        _: &DelegationMutation,
        _: Option<&DelegationGrant>,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, DelegationCommandAccessError> {
        Ok(VerifiedDelegationCommandAccess {
            observed_at: now,
            valid_until: now + Duration::seconds(20),
        })
    }
    async fn authorize_result_read(
        &self,
        _: &DelegationCommandCaller,
        _: &DelegationGrant,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, DelegationCommandAccessError> {
        Ok(VerifiedDelegationCommandAccess {
            observed_at: now,
            valid_until: now + Duration::seconds(20),
        })
    }
}
#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn postgres_command_identity_namespace_is_shared_with_lifecycle_in_both_directions() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let f = Fixture::new().await;
    let lifecycle =
        DelegationCommandService::new(f.lifecycle.clone(), Arc::new(LifecycleAccess), None);
    let mut terms = f.grant.terms.clone();
    terms.grantor = f.caller.actor().clone();
    let mut create = json!({"profile":DELEGATION_COMMAND_PROFILE,"command":"CREATE_GRANT","command_id":f.start["command_id"],"terms":terms});
    lifecycle
        .execute(&f.caller, &serde_json::to_vec(&create).unwrap())
        .await
        .unwrap();
    assert_eq!(
        f.execute(&f.start).await.err(),
        Some(DelegationUseCommandError::Conflict)
    );
    assert_eq!(f.flow.start_calls.load(Ordering::SeqCst), 0);
    let mut start = f.start.clone();
    start["command_id"] = json!(Uuid::new_v4());
    f.execute(&start).await.unwrap();
    create["command_id"] = start["command_id"].clone();
    let before:i64=sqlx::query_scalar("SELECT count(*) FROM delegated_authority_service.delegation_grants WHERE organization_id=$1").bind(f.grant.organization_id).fetch_one(&f.pool).await.unwrap();
    assert!(matches!(
        lifecycle
            .execute(&f.caller, &serde_json::to_vec(&create).unwrap())
            .await,
        Err(DelegationCommandError::Conflict)
    ));
    let after:i64=sqlx::query_scalar("SELECT count(*) FROM delegated_authority_service.delegation_grants WHERE organization_id=$1").bind(f.grant.organization_id).fetch_one(&f.pool).await.unwrap();
    assert_eq!(before, after);
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn postgres_other_tenant_or_typed_actor_cannot_read_or_finalize_retained_challenge() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let f = Fixture::new().await;
    let id = f.start_id().await;
    let command = f.final_command(id);
    for caller in [
        DelegationCommandCaller::from_authenticated_context(
            Uuid::new_v4(),
            f.caller.actor().clone(),
        )
        .unwrap(),
        DelegationCommandCaller::from_authenticated_context(
            f.grant.organization_id,
            Principal {
                principal_type: PrincipalType::User,
                id: f.caller.actor().id.clone(),
            },
        )
        .unwrap(),
    ] {
        assert_eq!(
            f.service
                .execute(&caller, &serde_json::to_vec(&command).unwrap())
                .await
                .err(),
            Some(DelegationUseCommandError::AccessDenied)
        );
        let decoded =
            decode_delegation_use_command(&serde_json::to_vec(&f.start).unwrap()).unwrap();
        let DecodedDelegationUseCommand::Mutation(decoded) = decoded else {
            panic!()
        };
        let recover = json!({"profile":DELEGATION_COMMAND_PROFILE,"command":"RECOVER_RESULT","original_command_id":decoded.command_id,"expected_command_digest":decoded.digest});
        assert_eq!(
            f.service
                .execute(&caller, &serde_json::to_vec(&recover).unwrap())
                .await
                .err(),
            Some(DelegationUseCommandError::ResultNotFound)
        );
    }
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn postgres_permission_loss_during_grant_lock_wait_prevents_preparation() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let f = Fixture::new().await;
    let mut held = f.pool.begin().await.unwrap();
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *held)
        .await
        .unwrap();
    sqlx::query(
        "SELECT id FROM delegated_authority_service.delegation_grants WHERE id=$1 FOR UPDATE",
    )
    .bind(f.grant.id)
    .fetch_one(&mut *held)
    .await
    .unwrap();
    let service = f.service.clone();
    let caller = f.caller.clone();
    let bytes = serde_json::to_vec(&f.start).unwrap();
    let task = tokio::spawn(async move { service.execute(&caller, &bytes).await });
    let mut blocked = false;
    for _ in 0..100 {
        // The restricted writer now enters the migration-owned lock helper;
        // pg_stat_activity shows that outer call rather than its inner SELECT.
        // Observe this exact holder as the blocker, not an unrelated lock wait.
        let waiting: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity AS activity \
             WHERE activity.datname=current_database() AND activity.wait_event_type='Lock' \
             AND $1=ANY(pg_blocking_pids(activity.pid)) \
             AND activity.query LIKE 'SELECT grant_document FROM delegated_authority_service.lock_use_grant(%')",
        )
        .bind(blocker_pid)
        .fetch_one(&f.pool)
        .await
        .unwrap();
        if waiting {
            blocked = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(blocked, "new use claim must reach the grant row lock");
    f.access.mutation.store(false, Ordering::SeqCst);
    held.rollback().await.unwrap();
    assert_eq!(
        task.await.unwrap().err(),
        Some(DelegationUseCommandError::AccessDenied)
    );
    assert_eq!(f.flow.start_calls.load(Ordering::SeqCst), 0);
    assert_eq!(f.count("use_command_claims").await, 0);
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn postgres_deferred_deadline_rejects_expiry_during_commit_trigger_wait() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let f = Fixture::new().await;
    let id = f.start_id().await;
    sqlx::raw_sql("CREATE FUNCTION public.use_test_delayed_commit() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN IF NEW.response_document #>> '{result,kind}'='FINAL_USE' THEN PERFORM pg_sleep(0.6); END IF; RETURN NEW; END $$;
        CREATE CONSTRAINT TRIGGER aaa_use_test_delay AFTER INSERT ON delegated_authority_service.use_command_results DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.use_test_delayed_commit()").execute(&f.pool).await.unwrap();
    f.access.lifetime_ms.store(300, Ordering::SeqCst);
    let result = f.execute(&f.final_command(id)).await;
    sqlx::raw_sql("DROP TRIGGER aaa_use_test_delay ON delegated_authority_service.use_command_results; DROP FUNCTION public.use_test_delayed_commit()").execute(&f.pool).await.unwrap();
    assert!(result.is_err());
    assert_eq!(f.count("use_receipts").await, 0);
    assert_eq!(f.count("use_command_results").await, 1);
    let consumed: bool =
        sqlx::query_scalar("SELECT consumed FROM use_test_flow_records WHERE id=$1")
            .bind(id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert!(!consumed);
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 1);
}
