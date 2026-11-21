//! Actual PostgreSQL retention/recovery tests. Existing explicit synthetic
//! signer/proof/policy ports isolate this owner's invariants; production remote
//! custody and cryptographic consumer qualification live in host acceptance.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sqlx::Row;

struct Clock(Mutex<DateTime<Utc>>);
impl DelegationClock for Clock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

fn recovery(result: &DelegationUseCommandResponse) -> Vec<u8> {
    serde_json::to_vec(&json!({"profile":DELEGATION_COMMAND_PROFILE,"command":"RECOVER_RESULT",
        "original_command_id":result.original_command_id,"expected_command_digest":result.command_digest})).unwrap()
}
fn for_command(command: &Value) -> Vec<u8> {
    let DecodedDelegationUseCommand::Mutation(decoded) =
        decode_delegation_use_command(&serde_json::to_vec(command).unwrap()).unwrap()
    else {
        panic!("fixture mutation");
    };
    serde_json::to_vec(
        &json!({"profile":DELEGATION_COMMAND_PROFILE,"command":"RECOVER_RESULT",
        "original_command_id":decoded.command_id(),"expected_command_digest":decoded.digest()}),
    )
    .unwrap()
}
fn service_with_clock(
    f: &Fixture,
    clock: Arc<dyn DelegationClock>,
) -> Arc<DelegationUseCommandService> {
    Arc::new(DelegationUseCommandService::with_clock(
        f.service.repository.clone(),
        f.service.lifecycle.clone(),
        f.service.challenges.clone(),
        f.service.evaluation.clone(),
        f.service.receipts.clone(),
        f.service.flow.clone(),
        f.service.access.clone(),
        clock,
    ))
}
async fn recover(
    f: &Fixture,
    raw: &[u8],
) -> Result<RecoveredDelegatedUseReceipt, DelegationUseCommandError> {
    let observed = Utc::now();
    f.service
        .recover_receipt_before(&f.caller, raw, observed, observed + Duration::seconds(25))
        .await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn postgres_receipt_recovery_preserves_permit_and_deny_after_grant_revocation_and_expiry() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    for permit in [true, false] {
        let f = Fixture::new().await;
        let challenge = f.start_id().await;
        f.policy.0.store(permit, Ordering::SeqCst);
        let result = f.execute(&f.final_command(challenge)).await.unwrap();
        let raw = recovery(&result);
        let compact: String = sqlx::query_scalar("SELECT compact_jws FROM delegated_authority_service.use_receipts WHERE organization_id=$1 AND challenge_id=$2")
            .bind(f.grant.organization_id).bind(challenge).fetch_one(&f.pool).await.unwrap();
        let before = recover(&f, &raw).await.unwrap();
        assert_eq!(before.compact_jws(), compact);
        assert_eq!(
            before.receipt_ref(),
            result_value(&result)["result"]["receipt_ref"]
                .as_str()
                .unwrap()
        );
        assert_eq!(
            before.receipt_digest(),
            result_value(&result)["result"]["receipt_digest"]
                .as_str()
                .unwrap()
        );
        assert_eq!(before.semantics(), "EVIDENCE_ONLY");
        assert!(before.original_response().recovered);
        assert_eq!(
            result_value(before.original_response())["result"],
            result_value(&result)["result"]
        );
        assert_eq!(
            format!("{before:?}"),
            "RecoveredDelegatedUseReceipt { <private original evidence> }"
        );

        // Recovery is allowed by the current read owner after historical grant,
        // proof, consent, signer and policy outcomes are no longer usable.
        f.lifecycle
            .revoke(f.grant.organization_id, f.grant.id, f.grant.revision)
            .await
            .unwrap();
        f.access.mutation.store(false, Ordering::SeqCst);
        f.consent.0.store(false, Ordering::SeqCst);
        f.proof.available.store(false, Ordering::SeqCst);
        f.signer.fail.store(true, Ordering::SeqCst);
        f.policy.0.store(!permit, Ordering::SeqCst);
        let historical = f.grant.terms.valid_until + Duration::seconds(1);
        let service = service_with_clock(&f, Arc::new(Clock(Mutex::new(historical))));
        let after = service
            .recover_receipt_before(
                &f.caller,
                &raw,
                historical,
                historical + Duration::seconds(25),
            )
            .await
            .unwrap();
        assert_eq!(after.compact_jws(), compact);
        assert_eq!(
            serde_json::to_value(&after).unwrap(),
            serde_json::to_value(&before).unwrap()
        );
        assert_eq!(
            f.access.recovery_calls.load(Ordering::SeqCst),
            4,
            "current read owner is checked before and after each artifact read"
        );
        assert_eq!(f.signer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(f.flow.final_preparations.load(Ordering::SeqCst), 1);
        assert_eq!(f.flow.final_commits.load(Ordering::SeqCst), 1);
        assert_eq!(f.count("use_receipts").await, 1);
        assert_eq!(f.count("use_command_results").await, 2);
        f.access.read.store(false, Ordering::SeqCst);
        assert_eq!(
            service
                .recover_receipt_before(
                    &f.caller,
                    &raw,
                    historical,
                    historical + Duration::seconds(25)
                )
                .await
                .err(),
            Some(DelegationUseCommandError::AccessDenied)
        );
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn postgres_receipt_recovery_rejects_other_identities_digests_pending_and_start_results() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let f = Fixture::new().await;
    let start = f.execute(&f.start).await.unwrap();
    let DelegationUseCommandResult::Challenge { challenge_id, .. } = start.result else {
        panic!("challenge");
    };
    assert_eq!(
        recover(&f, &recovery(&start)).await.err(),
        Some(DelegationUseCommandError::Unsupported)
    );
    f.signer.fail.store(true, Ordering::SeqCst);
    let final_command = f.final_command(challenge_id);
    assert_eq!(
        f.execute(&final_command).await.err(),
        Some(DelegationUseCommandError::Unavailable)
    );
    assert_eq!(
        recover(&f, &for_command(&final_command)).await.err(),
        Some(DelegationUseCommandError::PreparationPending)
    );
    f.access.read.store(false, Ordering::SeqCst);
    assert_eq!(
        recover(&f, &for_command(&final_command)).await.err(),
        Some(DelegationUseCommandError::AccessDenied)
    );
    f.access.read.store(true, Ordering::SeqCst);

    let f = Fixture::new().await;
    let challenge = f.start_id().await;
    let result = f.execute(&f.final_command(challenge)).await.unwrap();
    let raw = recovery(&result);
    let different_type = if f.caller.actor().principal_type == PrincipalType::MachineIdentity {
        PrincipalType::ServiceAccount
    } else {
        PrincipalType::MachineIdentity
    };
    for actor in [
        Principal {
            principal_type: f.caller.actor().principal_type,
            id: "urn:example:other-agent".into(),
        },
        Principal {
            principal_type: different_type,
            id: f.caller.actor().id.clone(),
        },
    ] {
        assert_ne!(
            &actor,
            f.caller.actor(),
            "negative caller must differ from the original"
        );
        let caller =
            DelegationCommandCaller::from_authenticated_context(f.grant.organization_id, actor)
                .unwrap();
        let now = Utc::now();
        assert_eq!(
            f.service
                .recover_receipt_before(&caller, &raw, now, now + Duration::seconds(25))
                .await
                .err(),
            Some(DelegationUseCommandError::ResultNotFound)
        );
    }
    let foreign = DelegationCommandCaller::from_authenticated_context(
        Uuid::new_v4(),
        f.caller.actor().clone(),
    )
    .unwrap();
    let now = Utc::now();
    assert_eq!(
        f.service
            .recover_receipt_before(&foreign, &raw, now, now + Duration::seconds(25))
            .await
            .err(),
        Some(DelegationUseCommandError::ResultNotFound)
    );
    let mut wrong_digest: Value = serde_json::from_slice(&raw).unwrap();
    wrong_digest["expected_command_digest"] = json!(format!("sha256:{}", "0".repeat(64)));
    assert_eq!(
        recover(&f, &serde_json::to_vec(&wrong_digest).unwrap())
            .await
            .err(),
        Some(DelegationUseCommandError::Conflict)
    );
    f.access.read.store(false, Ordering::SeqCst);
    assert_eq!(
        recover(&f, &serde_json::to_vec(&wrong_digest).unwrap())
            .await
            .err(),
        Some(DelegationUseCommandError::AccessDenied),
        "current read access precedes even digest-conflict disclosure"
    );
    assert_eq!(
        recover(
            &f,
            &serde_json::to_vec(&f.final_command(challenge)).unwrap()
        )
        .await
        .err(),
        Some(DelegationUseCommandError::Unsupported)
    );
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 1);
}

async fn wait_for_receipt_read(f: &Fixture, blocker_pid: i32) {
    for _ in 0..100 {
        let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity activity WHERE activity.datname=current_database() AND activity.wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(activity.pid)) AND activity.query LIKE '%FROM delegated_authority_service.use_receipts r%')")
            .bind(blocker_pid).fetch_one(&f.pool).await.unwrap();
        if waiting {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("recovery did not reach its exact artifact read behind the fixture lock");
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn postgres_receipt_recovery_rechecks_revocation_and_preserves_both_deadlines_after_read() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    for case in [
        "read-revoked",
        "authentication-expired",
        "first-access-expired",
        "clock-regressed",
    ] {
        let f = Fixture::new().await;
        let challenge = f.start_id().await;
        let result = f.execute(&f.final_command(challenge)).await.unwrap();
        let raw = recovery(&result);
        let now = Utc::now();
        let clock = Arc::new(Clock(Mutex::new(now)));
        let service = service_with_clock(&f, clock.clone());
        let mut held = f.pool.begin().await.unwrap();
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *held)
            .await
            .unwrap();
        sqlx::query("LOCK TABLE delegated_authority_service.use_receipts IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *held)
            .await
            .unwrap();
        let caller = f.caller.clone();
        let task = tokio::spawn(async move {
            service
                .recover_receipt_before(&caller, &raw, now, now + Duration::seconds(25))
                .await
        });
        wait_for_receipt_read(&f, pid).await;
        assert_eq!(
            f.access.recovery_calls.load(Ordering::SeqCst),
            1,
            "first current-right read must precede the receipt query"
        );
        match case {
            "read-revoked" => f.access.read.store(false, Ordering::SeqCst),
            "authentication-expired" => *clock.0.lock().unwrap() = now + Duration::seconds(25),
            "first-access-expired" => {
                // A second source lookup would return a later deadline. The
                // original 10-second read authorization must remain limiting.
                f.access
                    .recovery_lifetime_ms
                    .store(25_000, Ordering::SeqCst);
                *clock.0.lock().unwrap() = now + Duration::seconds(10);
            }
            "clock-regressed" => *clock.0.lock().unwrap() = now - Duration::milliseconds(1),
            _ => unreachable!(),
        }
        held.rollback().await.unwrap();
        let error = task.await.unwrap().err();
        assert_eq!(
            error,
            Some(if case == "read-revoked" {
                DelegationUseCommandError::AccessDenied
            } else {
                DelegationUseCommandError::Expired
            }),
            "case {case}"
        );
        assert_eq!(
            f.access.recovery_calls.load(Ordering::SeqCst),
            if case == "read-revoked" { 2 } else { 1 }
        );
        assert_eq!(f.signer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(f.count("use_receipts").await, 1);
        assert_eq!(f.count("use_command_results").await, 2);
    }
}

#[derive(Clone)]
struct Stored {
    compact: String,
    document: Value,
    digest: String,
    proof_submission_id: Uuid,
    response: Value,
}
async fn replace_stored(f: &Fixture, command_id: Uuid, data: &Stored) {
    // A privileged fixture simulates storage corruption. The mutation triggers
    // are restored inside this transaction; production roles cannot do this.
    let mut tx = f.pool.begin().await.unwrap();
    sqlx::query("ALTER TABLE delegated_authority_service.use_receipts DISABLE TRIGGER use_receipts_immutable").execute(&mut *tx).await.unwrap();
    sqlx::query("ALTER TABLE delegated_authority_service.use_command_results DISABLE TRIGGER use_command_results_immutable").execute(&mut *tx).await.unwrap();
    sqlx::query("UPDATE delegated_authority_service.use_receipts SET compact_jws=$3,receipt_document=$4,receipt_digest=$5,proof_submission_id=$6 WHERE organization_id=$1 AND command_id=$2")
        .bind(f.grant.organization_id).bind(command_id).bind(&data.compact).bind(&data.document).bind(&data.digest).bind(data.proof_submission_id).execute(&mut *tx).await.unwrap();
    sqlx::query("UPDATE delegated_authority_service.use_command_results SET response_document=$3 WHERE organization_id=$1 AND command_id=$2")
        .bind(f.grant.organization_id).bind(command_id).bind(&data.response).execute(&mut *tx).await.unwrap();
    sqlx::query("ALTER TABLE delegated_authority_service.use_receipts ENABLE TRIGGER use_receipts_immutable").execute(&mut *tx).await.unwrap();
    sqlx::query("ALTER TABLE delegated_authority_service.use_command_results ENABLE TRIGGER use_command_results_immutable").execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn postgres_receipt_recovery_rejects_compact_result_and_correlated_payload_corruption() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let f = Fixture::new().await;
    let challenge = f.start_id().await;
    let result = f.execute(&f.final_command(challenge)).await.unwrap();
    let raw = recovery(&result);
    let row = sqlx::query("SELECT compact_jws,receipt_document,receipt_digest,proof_submission_id FROM delegated_authority_service.use_receipts WHERE organization_id=$1 AND command_id=$2")
        .bind(f.grant.organization_id).bind(result.original_command_id).fetch_one(&f.pool).await.unwrap();
    let original = Stored {
        compact: row.get("compact_jws"),
        document: row.get("receipt_document"),
        digest: row.get("receipt_digest"),
        proof_submission_id: row.get("proof_submission_id"),
        response: result_value(&result),
    };
    for case in 0..11 {
        let mut altered = original.clone();
        match case {
            0 => {
                altered.digest = format!("sha256:{}", "0".repeat(64));
            }
            1 => {
                altered.compact.push('.');
            }
            2 => {
                altered.document["evaluation"]["actor"]["type"] = json!("USER");
            }
            3 => {
                altered.response["result"]["receipt_ref"] = json!("urn:example:other-receipt");
            }
            4 => {
                altered.proof_submission_id = Uuid::new_v4();
            }
            5 | 6 => {
                // Align the compact payload, persisted JSON, digest and result;
                // admission/typed-actor correspondence must still reject it.
                if case == 5 {
                    altered.document["evaluation"]["operation"]["resource_id"] =
                        json!("urn:example:foreign-resource");
                } else {
                    altered.document["evaluation"]["actor"]["type"] = json!("USER");
                }
                let parts: Vec<&str> = original.compact.split('.').collect();
                altered.compact = format!(
                    "{}.{}.{}",
                    parts[0],
                    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&altered.document).unwrap()),
                    parts[2]
                );
                altered.digest = format!("sha256:{:x}", Sha256::digest(altered.compact.as_bytes()));
                altered.response["result"]["receipt_digest"] = json!(altered.digest);
            }
            7 => {
                // JSONB has already discarded duplicate members; retaining the
                // same parsed JSON cannot make ambiguous signed wire valid.
                let serialized = serde_json::to_string(&original.document).unwrap();
                let duplicate = serialized.replacen(
                    "\"actor\":",
                    &format!(
                        "\"actor\":{},\"actor\":",
                        serde_json::to_string(&original.document["evaluation"]["actor"]).unwrap()
                    ),
                    1,
                );
                assert_ne!(serialized, duplicate);
                let parts: Vec<&str> = original.compact.split('.').collect();
                altered.compact = format!(
                    "{}.{}.{}",
                    parts[0],
                    URL_SAFE_NO_PAD.encode(duplicate),
                    parts[2]
                );
                altered.digest = format!("sha256:{:x}", Sha256::digest(altered.compact.as_bytes()));
                altered.response["result"]["receipt_digest"] = json!(altered.digest);
            }
            8 => {
                altered.compact.push('=');
                altered.digest = format!("sha256:{:x}", Sha256::digest(altered.compact.as_bytes()));
                altered.response["result"]["receipt_digest"] = json!(altered.digest);
            }
            9 => {
                altered.document["oversized_corrupt_storage"] = json!("x".repeat(100_001));
            }
            10 => {
                altered.response["oversized_corrupt_storage"] = json!("x".repeat(131_073));
            }
            _ => unreachable!(),
        }
        replace_stored(&f, result.original_command_id, &altered).await;
        let attempt = recover(&f, &raw).await;
        replace_stored(&f, result.original_command_id, &original).await;
        assert_eq!(
            attempt.err(),
            Some(DelegationUseCommandError::Unavailable),
            "case {case}"
        );
    }
    assert_eq!(
        recover(&f, &raw).await.unwrap().compact_jws(),
        original.compact
    );
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.count("use_receipts").await, 1);
    assert_eq!(f.count("use_command_results").await, 2);
    f.service.repository.readiness().await.unwrap();
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL"]
async fn postgres_receipt_recovery_is_bounded_when_a_read_is_blocked() {
    let _lock = crate::postgres::POSTGRES_TEST_LOCK.lock().await;
    let f = Fixture::new().await;
    let challenge = f.start_id().await;
    let result = f.execute(&f.final_command(challenge)).await.unwrap();
    let raw = recovery(&result);
    let mut held = f.pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE delegated_authority_service.use_receipts IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *held)
        .await
        .unwrap();
    let attempt = tokio::time::timeout(std::time::Duration::from_secs(7), recover(&f, &raw)).await;
    held.rollback().await.unwrap();
    assert_eq!(
        attempt
            .expect("receipt read has its own five-second limit")
            .err(),
        Some(DelegationUseCommandError::Unavailable)
    );
    assert_eq!(
        recover(&f, &raw)
            .await
            .unwrap()
            .original_response()
            .original_command_id,
        result.original_command_id
    );
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.count("use_receipts").await, 1);
    assert_eq!(f.count("use_command_results").await, 2);
}
