use super::*;
use crate::{
    ConsentEvidenceVerifier, ConsentVerificationError, ConsentVerificationRequest, DelegationClock,
    DelegationGrantRepository, InMemoryDelegationGrantRepository, PgDelegationGrantRepository,
    VerifiedConsent,
};
use chrono::Duration;
use serde_json::json;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

struct Clock(Mutex<DateTime<Utc>>);
impl DelegationClock for Clock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}
impl Clock {
    fn advance(&self) {
        *self.0.lock().unwrap() += Duration::seconds(1);
    }
}
struct Access {
    mutate: AtomicBool,
    read: AtomicBool,
    lifetime_ms: std::sync::atomic::AtomicI64,
}
#[async_trait]
impl DelegationCommandAuthorizer for Access {
    async fn authorize_mutation(
        &self,
        caller: &DelegationCommandCaller,
        _: &DelegationMutation,
        current: Option<&DelegationGrant>,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, DelegationCommandAccessError> {
        if self.mutate.load(Ordering::SeqCst)
            && current.is_none_or(|g| g.organization_id == caller.organization_id)
        {
            Ok(VerifiedDelegationCommandAccess {
                observed_at: now,
                valid_until: now + Duration::milliseconds(self.lifetime_ms.load(Ordering::SeqCst)),
            })
        } else {
            Err(DelegationCommandAccessError)
        }
    }
    async fn authorize_result_read(
        &self,
        caller: &DelegationCommandCaller,
        original: &DelegationGrant,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, DelegationCommandAccessError> {
        if self.read.load(Ordering::SeqCst) && original.organization_id == caller.organization_id {
            Ok(VerifiedDelegationCommandAccess {
                observed_at: now,
                valid_until: now + Duration::milliseconds(self.lifetime_ms.load(Ordering::SeqCst)),
            })
        } else {
            Err(DelegationCommandAccessError)
        }
    }
}
struct Consent {
    available: AtomicBool,
    deadline: Mutex<Option<DateTime<Utc>>>,
}
#[async_trait]
impl ConsentEvidenceVerifier for Consent {
    async fn verify_approval(
        &self,
        request: ConsentVerificationRequest<'_>,
    ) -> Result<VerifiedConsent, ConsentVerificationError> {
        if !self.available.load(Ordering::SeqCst) {
            return Err(ConsentVerificationError);
        }
        Ok(VerifiedConsent {
            valid_until: self
                .deadline
                .lock()
                .unwrap()
                .unwrap_or(request.grant.terms.valid_until),
        })
    }
}
struct Confirmation(Uuid);
#[async_trait]
impl DelegationConfirmationSource for Confirmation {
    async fn resolve_confirmation(
        &self,
        caller: &DelegationCommandCaller,
        grant: &DelegationGrant,
        confirmation_id: Uuid,
        _: DateTime<Utc>,
    ) -> Result<ApprovalEvidence, DelegationConfirmationError> {
        if confirmation_id != self.0 || caller.actor != grant.terms.grantor {
            return Err(DelegationConfirmationError);
        }
        Ok(ApprovalEvidence {
            profile: "urn:example:confirmation:v1".into(),
            evidence_ref: "urn:example:consent:1".into(),
            authority_evidence_ref: "urn:example:authority:1".into(),
        })
    }
}
struct Fixture {
    service: DelegationCommandService,
    lifecycle: Arc<DelegationAuthorityService>,
    repository: Arc<dyn DelegationGrantRepository>,
    caller: DelegationCommandCaller,
    clock: Arc<Clock>,
    access: Arc<Access>,
    consent: Arc<Consent>,
    confirmation_id: Uuid,
    create: Value,
}
impl Fixture {
    fn new(repository: Arc<dyn DelegationGrantRepository>) -> Self {
        let now = Utc::now();
        let mut template = crate::test_support::pending_grant();
        template.terms.valid_from = now - Duration::seconds(5);
        template.terms.valid_until = now + Duration::hours(1);
        let clock = Arc::new(Clock(Mutex::new(now)));
        let access = Arc::new(Access {
            mutate: AtomicBool::new(true),
            read: AtomicBool::new(true),
            lifetime_ms: std::sync::atomic::AtomicI64::new(20_000),
        });
        let consent = Arc::new(Consent {
            available: AtomicBool::new(true),
            deadline: Mutex::new(None),
        });
        let lifecycle = Arc::new(
            DelegationAuthorityService::with_clock(
                repository.clone(),
                consent.clone(),
                template.authority,
                clock.clone(),
            )
            .unwrap(),
        );
        let confirmation_id = Uuid::new_v4();
        let caller = DelegationCommandCaller::from_authenticated_context(
            template.organization_id,
            template.terms.grantor.clone(),
        )
        .unwrap();
        let create = json!({"profile":DELEGATION_COMMAND_PROFILE,"command":"CREATE_GRANT","command_id":Uuid::new_v4(),"terms":template.terms});
        let service = DelegationCommandService::new(
            lifecycle.clone(),
            access.clone(),
            Some(Arc::new(Confirmation(confirmation_id))),
        );
        Self {
            service,
            lifecycle,
            repository,
            caller,
            clock,
            access,
            consent,
            confirmation_id,
            create,
        }
    }
    fn memory() -> Self {
        Self::new(Arc::new(InMemoryDelegationGrantRepository::default()))
    }
    async fn execute(
        &self,
        command: &Value,
    ) -> Result<DelegationCommandResponse, DelegationCommandError> {
        self.service
            .execute(&self.caller, &serde_json::to_vec(command).unwrap())
            .await
    }
    fn transition(&self, name: &str, grant: &DelegationGrant) -> Value {
        let mut value = json!({"profile":DELEGATION_COMMAND_PROFILE,"command":name,"command_id":Uuid::new_v4(),
            "grant":{"id":grant.id,"revision":grant.revision,"terms_digest":grant.terms_digest}});
        if name == "APPROVE_GRANT" {
            value["confirmation_id"] = json!(self.confirmation_id);
        }
        value
    }
}
fn grant(response: &DelegationCommandResponse) -> &DelegationGrant {
    let DelegationCommandResult::GrantSnapshot { grant } = &response.result;
    grant
}
fn recovery(response: &DelegationCommandResponse) -> Value {
    json!({"profile":DELEGATION_COMMAND_PROFILE,"command":"RECOVER_RESULT",
        "original_command_id":response.original_command_id,"expected_command_digest":response.command_digest})
}
fn digest(command: &Value) -> String {
    let DecodedDelegationCommand::Mutation(decoded) =
        decode_delegation_command(&serde_json::to_vec(command).unwrap()).unwrap()
    else {
        panic!()
    };
    decoded.digest().into()
}

#[test]
#[ignore = "requires independently verified pinned protocol checkout; see tests/fixtures/commands/README.md"]
fn protocol_command_equality_vectors_and_unsupported_use_commands() {
    let external_root = std::env::var("MARTY_DELEGATION_COMMAND_PROTOCOL_ROOT")
        .expect("set the independently verified pinned protocol checkout root");
    let root =
        std::path::Path::new(&external_root).join("conformance/delegated-authority/v1/commands");
    let vectors: Value =
        serde_json::from_slice(&std::fs::read(root.join("command-digests.json")).unwrap()).unwrap();
    for vector in vectors["vectors"].as_array().unwrap() {
        let name = vector["fixture"].as_str().unwrap();
        let result = decode_delegation_command(&std::fs::read(root.join(name)).unwrap());
        if name.contains("start-use") || name.contains("finalize-use") {
            assert!(matches!(
                result,
                Err(DelegationCommandError::UnsupportedCommand)
            ));
        } else {
            let DecodedDelegationCommand::Mutation(decoded) = result.unwrap() else {
                panic!()
            };
            assert_eq!(
                decoded.digest(),
                vector["digest"].as_str().unwrap(),
                "{name}"
            );
        }
    }
    assert!(matches!(
        decode_delegation_command(&std::fs::read(root.join("valid/recover-result.json")).unwrap())
            .unwrap(),
        DecodedDelegationCommand::Recover { .. }
    ));
    for path in std::fs::read_dir(root.join("invalid")).unwrap() {
        let path = path.unwrap().path();
        if path.to_string_lossy().ends_with(".expected.json") {
            continue;
        }
        assert!(
            decode_delegation_command(&std::fs::read(&path).unwrap()).is_err(),
            "{}",
            path.display()
        );
    }
}

#[test]
fn synthetic_command_equality_and_unsupported_use_commands() {
    // Fresh synthetic input authored in this public repository. Its expected
    // hash was independently checked with the pinned protocol reference; no
    // upstream fixture or reference implementation is redistributed here.
    let command = json!({
        "profile":DELEGATION_COMMAND_PROFILE,"command":"REVOKE_GRANT",
        "command_id":"8e1960fa-54cb-44c1-9be9-d33ffdf709e1",
        "grant":{"id":"a14f99b2-1f37-4afd-bc25-8d692503ad1f",
                 "revision":9007199254740991_u64,"terms_digest":format!("sha256:{}","35".repeat(32))}
    });
    assert_eq!(
        digest(&command),
        "sha256:80f0528f8bf95c0ae9eba142d2033eec9cf70a8ea5e89c626dc4fbeef77230e0"
    );
    let DecodedDelegationCommand::Mutation(pretty) =
        decode_delegation_command(&serde_json::to_vec_pretty(&command).unwrap()).unwrap()
    else {
        panic!()
    };
    assert_eq!(pretty.digest(), digest(&command));
    for name in ["START_USE", "FINALIZE_USE"] {
        let input = json!({"profile":DELEGATION_COMMAND_PROFILE,"command":name});
        assert!(matches!(
            decode_delegation_command(&serde_json::to_vec(&input).unwrap()),
            Err(DelegationCommandError::UnsupportedCommand)
        ));
    }
}

#[test]
fn strict_commands_reject_duplicates_unknowns_null_floats_and_unsafe_revisions() {
    let fixture = Fixture::memory();
    let raw = serde_json::to_string(&fixture.create).unwrap();
    let duplicate = raw.replacen(
        "\"profile\":",
        "\"profile\":\"urn:marty:delegation-command:v1\",\"profile\":",
        1,
    );
    assert!(decode_delegation_command(duplicate.as_bytes()).is_err());
    let mut unknown = fixture.create.clone();
    unknown["organization_id"] = json!(fixture.caller.organization_id);
    assert!(decode_delegation_command(&serde_json::to_vec(&unknown).unwrap()).is_err());
    unknown = fixture.create.clone();
    unknown["terms"]["delegate"]["authenticated"] = json!(true);
    assert!(decode_delegation_command(&serde_json::to_vec(&unknown).unwrap()).is_err());
    let sample = crate::test_support::pending_grant();
    let command = fixture.transition("REVOKE_GRANT", &sample);
    for revision in [
        json!(0),
        json!(true),
        json!(null),
        json!(9007199254740992_u64),
        json!(1.0),
        json!(-1),
    ] {
        let mut altered = command.clone();
        altered["grant"]["revision"] = revision;
        assert!(decode_delegation_command(&serde_json::to_vec(&altered).unwrap()).is_err());
    }
    for number in ["1e0", "1.0", "9007199254740992", "18446744073709551616"] {
        let raw = serde_json::to_string(&command)
            .unwrap()
            .replace("\"revision\":1", &format!("\"revision\":{number}"));
        assert!(
            decode_delegation_command(raw.as_bytes()).is_err(),
            "{number}"
        );
    }
    let mut bad = fixture.create.clone();
    bad["command_id"] = json!(Uuid::nil());
    assert!(decode_delegation_command(&serde_json::to_vec(&bad).unwrap()).is_err());
    assert!(decode_delegation_command(&vec![b' '; 65537]).is_err());
}

#[tokio::test]
async fn create_retry_preserves_original_and_rejects_changed_payload() {
    let f = Fixture::memory();
    let original = f.execute(&f.create).await.unwrap();
    f.clock.advance();
    let retry = f.execute(&f.create).await.unwrap();
    assert!(retry.recovered);
    assert!(!original.recovered);
    assert_eq!(grant(&original), grant(&retry));
    let mut changed = f.create.clone();
    changed["terms"]["resources"] = json!(["urn:example:other"]);
    assert!(matches!(
        f.execute(&changed).await,
        Err(DelegationCommandError::Conflict)
    ));
    assert_eq!(
        f.repository
            .list(f.caller.organization_id, None)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        f.repository
            .audit(f.caller.organization_id, grant(&original).id)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn command_identity_includes_tenant_and_complete_actor() {
    let f = Fixture::memory();
    let original = f.execute(&f.create).await.unwrap();
    let mut actor = f.caller.actor.clone();
    actor.principal_type = crate::PrincipalType::ServiceAccount;
    let other_actor =
        DelegationCommandCaller::from_authenticated_context(f.caller.organization_id, actor)
            .unwrap();
    let other_tenant =
        DelegationCommandCaller::from_authenticated_context(Uuid::new_v4(), f.caller.actor.clone())
            .unwrap();
    let recover = serde_json::to_vec(&recovery(&original)).unwrap();
    for caller in [&other_actor, &other_tenant] {
        assert!(matches!(
            f.service.execute(caller, &recover).await,
            Err(DelegationCommandError::ResultNotFound)
        ));
        let own = f
            .service
            .execute(caller, &serde_json::to_vec(&f.create).unwrap())
            .await
            .unwrap();
        assert_ne!(grant(&own).id, grant(&original).id);
    }
}

#[tokio::test]
async fn recovery_after_revocation_and_expiry_needs_current_read_access() {
    let f = Fixture::memory();
    let original = f.execute(&f.create).await.unwrap();
    f.clock.advance();
    let revoked = f
        .execute(&f.transition("REVOKE_GRANT", grant(&original)))
        .await
        .unwrap();
    assert_eq!(grant(&revoked).status, GrantStatus::Revoked);
    *f.clock.0.lock().unwrap() = grant(&original).terms.valid_until + Duration::seconds(1);
    let historical = f.execute(&recovery(&original)).await.unwrap();
    assert_eq!(grant(&historical), grant(&original));
    assert_eq!(grant(&historical).status, GrantStatus::Pending);
    f.access.read.store(false, Ordering::SeqCst);
    for command in [&f.create, &recovery(&original)] {
        assert!(matches!(
            f.execute(command).await,
            Err(DelegationCommandError::AccessDenied)
        ));
    }
}

#[tokio::test]
async fn existing_lifecycle_is_reused_with_exact_references_and_current_consent() {
    let f = Fixture::memory();
    let original = f.execute(&f.create).await.unwrap();
    f.clock.advance();
    let approval_command = f.transition("APPROVE_GRANT", grant(&original));
    let active = f.execute(&approval_command).await.unwrap();
    assert_eq!(grant(&active).status, GrantStatus::Active);
    f.clock.advance();
    let suspended = f
        .execute(&f.transition("SUSPEND_GRANT", grant(&active)))
        .await
        .unwrap();
    f.clock.advance();
    let reinstate = f.transition("REINSTATE_GRANT", grant(&suspended));
    f.consent.available.store(false, Ordering::SeqCst);
    assert!(matches!(
        f.execute(&reinstate).await,
        Err(DelegationCommandError::LifecycleRejected)
    ));
    assert_eq!(
        grant(&f.execute(&approval_command).await.unwrap()),
        grant(&active)
    );
    f.consent.available.store(true, Ordering::SeqCst);
    let reinstated = f.execute(&reinstate).await.unwrap();
    assert_eq!(grant(&reinstated).revision, 4);
    assert_eq!(grant(&reinstated).terms, grant(&original).terms);
    assert_eq!(grant(&reinstated).approval, grant(&active).approval);
    f.clock.advance();
    let mut wrong = f.transition("REVOKE_GRANT", grant(&reinstated));
    wrong["grant"]["terms_digest"] = json!(format!("sha256:{}", "f".repeat(64)));
    assert!(matches!(
        f.execute(&wrong).await,
        Err(DelegationCommandError::Conflict)
    ));
    assert_eq!(
        f.repository
            .audit(f.caller.organization_id, grant(&original).id)
            .await
            .unwrap()
            .len(),
        4
    );
}

#[tokio::test]
async fn approval_without_trusted_confirmation_or_authorized_actor_fails_closed() {
    let f = Fixture::memory();
    let original = f.execute(&f.create).await.unwrap();
    f.clock.advance();
    let approval = f.transition("APPROVE_GRANT", grant(&original));
    let uncomposed = DelegationCommandService::new(f.lifecycle.clone(), f.access.clone(), None);
    assert!(matches!(
        uncomposed
            .execute(&f.caller, &serde_json::to_vec(&approval).unwrap())
            .await,
        Err(DelegationCommandError::ConfirmationUnavailable)
    ));
    let mut forged = approval.clone();
    forged["confirmation_id"] = json!(Uuid::new_v4());
    assert!(matches!(
        f.execute(&forged).await,
        Err(DelegationCommandError::ConfirmationUnavailable)
    ));
    let mut actor = f.caller.actor.clone();
    actor.principal_type = crate::PrincipalType::External;
    let other =
        DelegationCommandCaller::from_authenticated_context(f.caller.organization_id, actor)
            .unwrap();
    assert!(matches!(
        f.service
            .execute(&other, &serde_json::to_vec(&approval).unwrap())
            .await,
        Err(DelegationCommandError::AccessDenied)
    ));
    f.access.mutate.store(false, Ordering::SeqCst);
    assert!(matches!(
        f.execute(&approval).await,
        Err(DelegationCommandError::AccessDenied)
    ));
    assert_eq!(
        f.repository
            .get(f.caller.organization_id, grant(&original).id)
            .await
            .unwrap(),
        Some(grant(&original).clone())
    );
}

#[tokio::test]
async fn concurrent_identical_creates_have_one_outcome() {
    let f = Fixture::memory();
    let (a, b) = tokio::join!(f.execute(&f.create), f.execute(&f.create));
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(grant(&a), grant(&b));
    assert_ne!(a.recovered, b.recovered);
    assert_eq!(
        f.repository
            .list(f.caller.organization_id, None)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn clock_regression_prevents_a_lifecycle_command_without_recording_success() {
    let f = Fixture::memory();
    let original = f.execute(&f.create).await.unwrap();
    *f.clock.0.lock().unwrap() -= Duration::seconds(1);
    let revoke = f.transition("REVOKE_GRANT", grant(&original));
    assert!(matches!(
        f.execute(&revoke).await,
        Err(DelegationCommandError::LifecycleRejected)
    ));
    let recover = json!({"profile":DELEGATION_COMMAND_PROFILE,"command":"RECOVER_RESULT","original_command_id":revoke["command_id"],"expected_command_digest":digest(&revoke)});
    assert!(matches!(
        f.execute(&recover).await,
        Err(DelegationCommandError::ResultNotFound)
    ));
}

#[tokio::test]
async fn postgres_commands_are_atomic_durable_and_original_caller_scoped() {
    let Ok(url) = std::env::var("DELEGATED_AUTHORITY_TEST_DATABASE_URL") else {
        return;
    };
    let _guard = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("configured command test database must be available");
    let repository = Arc::new(PgDelegationGrantRepository::new(pool.clone()));
    repository.migrate().await.unwrap();
    repository.readiness().await.unwrap();
    let f = Fixture::new(repository.clone());
    let (a, b) = tokio::join!(f.execute(&f.create), f.execute(&f.create));
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(grant(&a), grant(&b));
    assert_ne!(a.recovered, b.recovered);
    let mut changed = f.create.clone();
    changed["terms"]["resources"] = json!(["urn:example:changed"]);
    assert!(matches!(
        f.execute(&changed).await,
        Err(DelegationCommandError::Conflict)
    ));
    *f.clock.0.lock().unwrap() = Utc::now();
    let revoked = f
        .execute(&f.transition("REVOKE_GRANT", grant(&a)))
        .await
        .unwrap();
    assert_eq!(grant(&revoked).revision, 2);
    let second_pool = sqlx::postgres::PgPoolOptions::new()
        .connect(&url)
        .await
        .unwrap();
    let reopened = Arc::new(PgDelegationGrantRepository::new(second_pool.clone()));
    let life = Arc::new(
        DelegationAuthorityService::with_clock(
            reopened,
            f.consent.clone(),
            grant(&a).authority.clone(),
            f.clock.clone(),
        )
        .unwrap(),
    );
    let service = DelegationCommandService::new(life, f.access.clone(), None);
    let recovered = service
        .execute(&f.caller, &serde_json::to_vec(&recovery(&a)).unwrap())
        .await
        .unwrap();
    assert_eq!(grant(&recovered), grant(&a));
    assert!(recovered.recovered);
    f.access.read.store(false, Ordering::SeqCst);
    assert!(matches!(
        service
            .execute(&f.caller, &serde_json::to_vec(&recovery(&a)).unwrap())
            .await,
        Err(DelegationCommandError::AccessDenied)
    ));
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM delegated_authority_service.command_results WHERE organization_id=$1",
    )
    .bind(f.caller.organization_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 2);
    assert_eq!(
        repository
            .audit(f.caller.organization_id, grant(&a).id)
            .await
            .unwrap()
            .len(),
        2
    );
    for sql in [
        "UPDATE delegated_authority_service.command_results SET command_digest=command_digest",
        "DELETE FROM delegated_authority_service.command_results",
        "TRUNCATE delegated_authority_service.command_results",
    ] {
        assert!(sqlx::query(sql).execute(&pool).await.is_err(), "{sql}");
    }
    second_pool.close().await;
    pool.close().await;
}

#[tokio::test]
async fn postgres_result_insert_failure_rolls_back_grant_and_journal() {
    let Ok(url) = std::env::var("DELEGATED_AUTHORITY_TEST_DATABASE_URL") else {
        return;
    };
    let _guard = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect(&url)
        .await
        .unwrap();
    let repository = Arc::new(PgDelegationGrantRepository::new(pool.clone()));
    repository.migrate().await.unwrap();
    let f = Fixture::new(repository.clone());
    sqlx::raw_sql("CREATE FUNCTION delegated_authority_service.test_reject_command_result() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test rollback'; END $$; CREATE TRIGGER test_reject_command_result BEFORE INSERT ON delegated_authority_service.command_results FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.test_reject_command_result();").execute(&pool).await.unwrap();
    assert!(f.execute(&f.create).await.is_err());
    assert!(repository
        .list(f.caller.organization_id, None)
        .await
        .unwrap()
        .is_empty());
    let events:i64=sqlx::query_scalar("SELECT count(*) FROM delegated_authority_service.grant_lifecycle_events WHERE organization_id=$1").bind(f.caller.organization_id).fetch_one(&pool).await.unwrap();
    assert_eq!(events, 0);
    sqlx::raw_sql("DROP TRIGGER test_reject_command_result ON delegated_authority_service.command_results; DROP FUNCTION delegated_authority_service.test_reject_command_result();").execute(&pool).await.unwrap();
    assert!(!f.execute(&f.create).await.unwrap().recovered);
    pool.close().await;
}

#[tokio::test]
async fn postgres_activation_expiry_during_result_write_rolls_back_all_three_records() {
    let Ok(url) = std::env::var("DELEGATED_AUTHORITY_TEST_DATABASE_URL") else {
        return;
    };
    let _guard = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect(&url)
        .await
        .unwrap();
    let repository = Arc::new(PgDelegationGrantRepository::new(pool.clone()));
    repository.migrate().await.unwrap();
    let f = Fixture::new(repository.clone());
    let original = f.execute(&f.create).await.unwrap();
    // The application clock remains frozen before the deadline. The database
    // must reject the expired activation after the command-result write waits.
    *f.clock.0.lock().unwrap() = Utc::now() + Duration::milliseconds(1);
    *f.consent.deadline.lock().unwrap() = Some(Utc::now() + Duration::milliseconds(80));
    let approve = f.transition("APPROVE_GRANT", grant(&original));
    sqlx::raw_sql("CREATE FUNCTION delegated_authority_service.test_delay_command_result() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.15); RETURN NEW; END $$; CREATE TRIGGER test_delay_command_result BEFORE INSERT ON delegated_authority_service.command_results FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.test_delay_command_result();")
        .execute(&pool).await.unwrap();
    assert!(f.execute(&approve).await.is_err());
    sqlx::raw_sql("DROP TRIGGER test_delay_command_result ON delegated_authority_service.command_results; DROP FUNCTION delegated_authority_service.test_delay_command_result();")
        .execute(&pool).await.unwrap();
    assert_eq!(
        repository
            .get(f.caller.organization_id, grant(&original).id)
            .await
            .unwrap(),
        Some(grant(&original).clone())
    );
    assert_eq!(
        repository
            .audit(f.caller.organization_id, grant(&original).id)
            .await
            .unwrap()
            .len(),
        1
    );
    let command_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM delegated_authority_service.command_results WHERE organization_id=$1",
    )
    .bind(f.caller.organization_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(command_count, 1);
    let recover = json!({"profile":DELEGATION_COMMAND_PROFILE,"command":"RECOVER_RESULT","original_command_id":approve["command_id"],"expected_command_digest":digest(&approve)});
    assert!(matches!(
        f.execute(&recover).await,
        Err(DelegationCommandError::ResultNotFound)
    ));
    pool.close().await;
}

#[tokio::test]
async fn resource_authorization_precedes_reference_conflict_disclosure() {
    let f = Fixture::memory();
    let original = f.execute(&f.create).await.unwrap();
    f.clock.advance();
    let mut revoke = f.transition("REVOKE_GRANT", grant(&original));
    revoke["grant"]["terms_digest"] = json!(format!("sha256:{}", "f".repeat(64)));
    f.access.mutate.store(false, Ordering::SeqCst);
    assert!(matches!(
        f.execute(&revoke).await,
        Err(DelegationCommandError::AccessDenied)
    ));
    f.access.mutate.store(true, Ordering::SeqCst);
    assert!(matches!(
        f.execute(&revoke).await,
        Err(DelegationCommandError::Conflict)
    ));
}

#[tokio::test]
async fn authorization_observations_are_bounded_and_recovery_uses_a_fresh_read() {
    let f = Fixture::memory();
    for invalid_lifetime in [0, -1, 30_001] {
        f.access
            .lifetime_ms
            .store(invalid_lifetime, Ordering::SeqCst);
        assert!(matches!(
            f.execute(&f.create).await,
            Err(DelegationCommandError::AccessDenied)
        ));
    }
    f.access.lifetime_ms.store(20_000, Ordering::SeqCst);
    let original = f.execute(&f.create).await.unwrap();
    // The mutation decision has long expired; an independently fresh read may
    // still recover its exact historical evidence.
    *f.clock.0.lock().unwrap() += Duration::minutes(1);
    assert_eq!(
        grant(&f.execute(&recovery(&original)).await.unwrap()),
        grant(&original)
    );
    f.access.lifetime_ms.store(0, Ordering::SeqCst);
    assert!(matches!(
        f.execute(&recovery(&original)).await,
        Err(DelegationCommandError::AccessDenied)
    ));
}

#[tokio::test]
async fn postgres_expired_command_access_after_result_write_rolls_back_create() {
    let Ok(url) = std::env::var("DELEGATED_AUTHORITY_TEST_DATABASE_URL") else {
        return;
    };
    let _guard = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect(&url)
        .await
        .unwrap();
    let repository = Arc::new(PgDelegationGrantRepository::new(pool.clone()));
    repository.migrate().await.unwrap();
    let f = Fixture::new(repository.clone());
    f.access.lifetime_ms.store(80, Ordering::SeqCst);
    sqlx::raw_sql("CREATE FUNCTION delegated_authority_service.test_delay_access_result() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.15); RETURN NEW; END $$; CREATE TRIGGER test_delay_access_result BEFORE INSERT ON delegated_authority_service.command_results FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.test_delay_access_result();")
        .execute(&pool).await.unwrap();
    let started = std::time::Instant::now();
    assert!(f.execute(&f.create).await.is_err());
    assert!(started.elapsed() >= std::time::Duration::from_millis(140));
    sqlx::raw_sql("DROP TRIGGER test_delay_access_result ON delegated_authority_service.command_results; DROP FUNCTION delegated_authority_service.test_delay_access_result();")
        .execute(&pool).await.unwrap();
    assert!(repository
        .list(f.caller.organization_id, None)
        .await
        .unwrap()
        .is_empty());
    for sql in [
        "SELECT count(*) FROM delegated_authority_service.command_results WHERE organization_id=$1",
        "SELECT count(*) FROM delegated_authority_service.grant_lifecycle_events WHERE organization_id=$1",
    ] {
        let count: i64 = sqlx::query_scalar(sql)
        .bind(f.caller.organization_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 0);
    }
    pool.close().await;
}

#[tokio::test]
async fn postgres_migration_waits_for_legacy_writer_then_preserves_unjournaled_row() {
    use std::str::FromStr;
    let Ok(url) = std::env::var("DELEGATED_AUTHORITY_TEST_DATABASE_URL") else {
        return;
    };
    let _guard = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let admin = sqlx::postgres::PgPoolOptions::new()
        .connect(&url)
        .await
        .unwrap();
    // A UUID-generated SQL identifier, never request input. This test requires
    // CREATEDB in its explicitly disposable PostgreSQL fixture.
    let database = format!("marty_migration_race_{}", Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
        .execute(&admin)
        .await
        .unwrap();
    let options = sqlx::postgres::PgConnectOptions::from_str(&url)
        .unwrap()
        .database(&database);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .unwrap();
    let initial = include_str!("../../migrations/0001_delegation_grants.sql");
    sqlx::raw_sql(initial).execute(&pool).await.unwrap();
    sqlx::raw_sql("CREATE TABLE delegated_authority_service.schema_migrations (version INTEGER PRIMARY KEY,checksum TEXT NOT NULL,applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP)")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO delegated_authority_service.schema_migrations (version,checksum) VALUES (1,$1)")
        .bind(format!("sha256:{:x}",Sha256::digest(initial.as_bytes()))).execute(&pool).await.unwrap();
    let original = crate::test_support::pending_grant();
    let mut writer = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO delegated_authority_service.delegation_grants (id,organization_id,status,revision,terms_digest,grant_document,created_at,updated_at) VALUES ($1,$2,'PENDING',1,$3,$4,$5,$6)")
        .bind(original.id).bind(original.organization_id).bind(&original.terms_digest).bind(serde_json::to_value(&original).unwrap())
        .bind(original.created_at).bind(original.updated_at).execute(&mut *writer).await.unwrap();
    let repository = PgDelegationGrantRepository::new(pool.clone());
    let migration = tokio::spawn(async move { repository.migrate().await });
    tokio::time::timeout(std::time::Duration::from_secs(3),async {
        loop {
            let waiting:bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'LOCK TABLE delegated_authority_service.delegation_grants%')")
                .fetch_one(&pool).await.unwrap();
            if waiting { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("migration must wait on the legacy table writer before checking emptiness");
    writer.commit().await.unwrap();
    assert!(matches!(
        migration.await.unwrap(),
        Err(RepositoryError::DatabaseFailure)
    ));
    let preserved: Value = sqlx::query_scalar(
        "SELECT grant_document FROM delegated_authority_service.delegation_grants WHERE id=$1",
    )
    .bind(original.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(preserved, serde_json::to_value(original).unwrap());
    let version: i32 = sqlx::query_scalar(
        "SELECT max(version) FROM delegated_authority_service.schema_migrations",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(version, 1);
    let journal_exists: bool = sqlx::query_scalar(
        "SELECT to_regclass('delegated_authority_service.grant_lifecycle_events') IS NOT NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!journal_exists);
    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE {database}")))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

#[tokio::test]
async fn postgres_authorization_expiry_while_waiting_for_command_lock_is_rejected() {
    let Ok(url) = std::env::var("DELEGATED_AUTHORITY_TEST_DATABASE_URL") else {
        return;
    };
    let _guard = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .unwrap();
    let repository = Arc::new(PgDelegationGrantRepository::new(pool.clone()));
    repository.migrate().await.unwrap();
    let f = Fixture::new(repository.clone());
    f.access.lifetime_ms.store(80, Ordering::SeqCst);
    let command_id = Uuid::parse_str(f.create["command_id"].as_str().unwrap()).unwrap();
    let identity = DelegationCommandIdentity::new(&f.caller, command_id);
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(identity.lock_key().unwrap())
        .execute(&mut *blocker)
        .await
        .unwrap();
    let service = f.service.clone();
    let caller = f.caller.clone();
    let raw = serde_json::to_vec(&f.create).unwrap();
    let command = tokio::spawn(async move { service.execute(&caller, &raw).await });
    tokio::time::timeout(std::time::Duration::from_secs(3),async {
        loop {
            let waiting:bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query = 'SELECT pg_advisory_xact_lock($1)')")
                .fetch_one(&pool).await.unwrap();
            if waiting { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("the command must actually wait for its identity lock");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    blocker.rollback().await.unwrap();
    assert!(matches!(
        command.await.unwrap(),
        Err(DelegationCommandError::Unavailable)
    ));
    assert!(repository
        .list(f.caller.organization_id, None)
        .await
        .unwrap()
        .is_empty());
    assert!(repository
        .command_result(&identity)
        .await
        .unwrap()
        .is_none());
    pool.close().await;
}

struct AdvanceDuringAuthorization(Arc<Clock>);
#[async_trait]
impl DelegationCommandAuthorizer for AdvanceDuringAuthorization {
    async fn authorize_mutation(
        &self,
        _: &DelegationCommandCaller,
        _: &DelegationMutation,
        _: Option<&DelegationGrant>,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, DelegationCommandAccessError> {
        *self.0 .0.lock().unwrap() += Duration::seconds(4);
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
async fn regression_after_preparation_cannot_commit_a_future_snapshot() {
    let f = Fixture::memory();
    let service = DelegationCommandService::new(
        f.lifecycle.clone(),
        Arc::new(AdvanceDuringAuthorization(f.clock.clone())),
        None,
    );
    let DecodedDelegationCommand::Mutation(command) =
        decode_delegation_command(&serde_json::to_vec(&f.create).unwrap()).unwrap()
    else {
        panic!()
    };
    let (mutation, access, access_checked_at, prepared_at) =
        service.prepare(&f.caller, &command).await.unwrap();
    let identity = DelegationCommandIdentity::new(&f.caller, command.command_id);
    let prepared = PreparedDelegationCommand {
        result: StoredDelegationCommandResult {
            identity: identity.clone(),
            command,
            grant: mutation.grant.clone(),
        },
        mutation,
        access,
        access_checked_at,
        prepared_at,
        clock: f.clock.clone(),
    };
    // Remains after the original auth observation, but before the latest
    // preparation observation and the new grant's creation time.
    *f.clock.0.lock().unwrap() -= Duration::seconds(2);
    assert!(matches!(
        f.repository.commit_command(prepared).await,
        Err(RepositoryError::CommandAccessExpired)
    ));
    assert!(f
        .repository
        .command_result(&identity)
        .await
        .unwrap()
        .is_none());
    assert!(f
        .repository
        .list(f.caller.organization_id, None)
        .await
        .unwrap()
        .is_empty());
}
