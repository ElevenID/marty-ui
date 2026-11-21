//! Executed qualification of the explicit managed KEY/EXACT_OPERATION host.
//!
//! All PostgreSQL owners, current access/consent/authority, nested machine VC
//! verification and both Cedar evaluations are real. Human/transport admission,
//! frozen remote presentation metadata and ephemeral signing custody are named
//! test fixtures. This suite does not qualify a deployed remote TLS/KMS service.
mod support;

use std::sync::atomic::Ordering;

use axum::{body::Body, http::Request};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_delegated_authority::{
    use_http::DelegationUseHttpApplication, DelegationGrant, DelegationUseCommandError,
    DelegationUseCommandResponse, DelegationUseCommandResult, PgTrustedConsentWriter,
    RetainedUseChallenge, DELEGATION_COMMAND_PROFILE,
};
use marty_delegated_use::{
    database::DatabasePools,
    runtime::{DelegatedUseRuntime, DelegatedUseRuntimeError},
};
use marty_organization::{
    machine_use_access::MachineUseAccessOwner, postgres::PostgresOrganizationStore,
};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use support::{
    database::Database,
    host::{configuration, context},
    owned::{
        operation_digest, Owned, ACTION, AUDIENCE, OPERATION_PROFILE, RESOURCE, VERIFIER_CLIENT_ID,
    },
    TestResult,
};

async fn assemble(owned: &Owned, db: &Database) -> TestResult<DelegatedUseRuntime> {
    Ok(DelegatedUseRuntime::assemble(
        &configuration(owned, db)?,
        db.pools.clone(),
        owned.ports.registry(),
        owned.receipts.clone(),
    )
    .await?)
}

async fn execute(
    runtime: &DelegatedUseRuntime,
    owned: &Owned,
    raw: &[u8],
) -> Result<DelegationUseCommandResponse, DelegationUseCommandError> {
    let context = context(owned).expect("explicit assembly transport fixture");
    DelegationUseHttpApplication::execute(runtime.commands().as_ref(), &context, raw).await
}

fn start(grant: &DelegationGrant) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "profile":DELEGATION_COMMAND_PROFILE,"command":"START_USE",
        "command_id":Uuid::new_v4(),
        "grant":{"id":grant.id,"revision":grant.revision,"terms_digest":grant.terms_digest},
        "operation":{"action":ACTION,"resource_id":RESOURCE,"audience":AUDIENCE,
            "request_profile":OPERATION_PROFILE,"request_digest":operation_digest()}
    }))
    .unwrap()
}

fn finalization(challenge: Uuid, proof: Uuid) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "profile":DELEGATION_COMMAND_PROFILE,"command":"FINALIZE_USE",
        "command_id":Uuid::new_v4(),"challenge_id":challenge,"proof_submission_id":proof
    }))
    .unwrap()
}

fn recovery(response: &DelegationUseCommandResponse) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "profile":DELEGATION_COMMAND_PROFILE,"command":"RECOVER_RESULT",
        "original_command_id":response.original_command_id,
        "expected_command_digest":response.command_digest
    }))
    .unwrap()
}

async fn challenge(
    runtime: &DelegatedUseRuntime,
    owned: &Owned,
    db: &Database,
    grant: &DelegationGrant,
) -> TestResult<RetainedUseChallenge> {
    let response = execute(runtime, owned, &start(grant)).await?;
    assert!(!response.recovered);
    let DelegationUseCommandResult::Challenge { challenge_id, .. } = response.result else {
        panic!("START_USE did not retain a challenge");
    };
    let document: Value = sqlx::query_scalar(
        "SELECT challenge_document FROM delegated_authority_service.use_admissions
         WHERE organization_id=$1 AND challenge_id=$2",
    )
    .bind(owned.organization)
    .bind(challenge_id)
    .fetch_one(&db.admin)
    .await?;
    Ok(serde_json::from_value(document)?)
}

fn verify_jws(compact: &str, key: &VerifyingKey) -> TestResult<Value> {
    let parts = compact.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3);
    let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2])?)?;
    key.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)?;
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?)
}

async fn no_receipt(db: &Database) -> TestResult<()> {
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM delegated_authority_service.use_receipts")
            .fetch_one(&db.admin)
            .await?;
    assert_eq!(rows, 0);
    let consumptions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM flow_service.delegated_use_consumptions")
            .fetch_one(&db.admin)
            .await?;
    assert_eq!(consumptions, 0);
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicitly disposable loopback PostgreSQL fixture"]
async fn actual_owner_host_round_trip_retains_crypto_audit_and_original_result() -> TestResult<()> {
    let db = Database::new().await?;
    let owned = Owned::seed(&db.admin).await?;
    let runtime = assemble(&owned, &db).await?;
    runtime.readiness().await?;
    assert_eq!(owned.ports.calls.load(Ordering::SeqCst), 0);
    assert_eq!(owned.receipts.calls.load(Ordering::SeqCst), 0);

    // The actual selected runtime never accepts our forwarding fixture through
    // its network authenticator; protected context injection is test-only.
    let forwarded = Request::builder()
        .header(
            "x-service-token",
            "explicit-assembly-test-forwarder-token-32-bytes",
        )
        .body(Body::empty())?;
    assert!(runtime
        .authenticator()
        .authenticate(&owned.organization.to_string(), &forwarded)
        .is_err());

    let grant = owned.grant(&db).await?;
    let retained = challenge(&runtime, &owned, &db, &grant).await?;
    assert_eq!(retained.verifier_id, VERIFIER_CLIENT_ID);
    assert_eq!(retained.grant.id, grant.id);
    assert_eq!(retained.grant.revision, 2);

    let ingress = runtime.ingress();
    let request = ingress
        .retrieve_request(&context(&owned)?, retained.challenge_id)
        .await?;
    assert!(!request.recovered);
    let request_claims = verify_jws(
        request.compact_request_jws(),
        owned.ports.key.verifying_key(),
    )?;
    assert_eq!(request_claims["nonce"], retained.nonce);
    assert_eq!(request_claims["client_id"], retained.verifier_id);
    let again = ingress
        .retrieve_request(&context(&owned)?, retained.challenge_id)
        .await?;
    assert!(again.recovered);
    assert_eq!(again.compact_request_jws(), request.compact_request_jws());
    assert_eq!(again.retained_at, request.retained_at);
    assert_eq!(again.request_digest, request.request_digest);
    assert_eq!(owned.ports.calls.load(Ordering::SeqCst), 1);

    let proof = owned.proof(&retained);
    let submitted = ingress
        .submit_proof(&context(&owned)?, retained.challenge_id, &proof)
        .await?;
    assert!(!submitted.recovered);
    let repeated = ingress
        .submit_proof(&context(&owned)?, retained.challenge_id, &proof)
        .await?;
    assert!(repeated.recovered);
    assert_eq!(repeated.submission_id, submitted.submission_id);
    assert_eq!(repeated.received_at, submitted.received_at);
    let finish = finalization(retained.challenge_id, submitted.submission_id);
    let completed = execute(&runtime, &owned, &finish).await?;
    assert!(!completed.recovered);
    let DelegationUseCommandResult::FinalUse {
        decision,
        receipt_ref,
        receipt_digest,
        authorization_expires_at,
        recorded_at,
        ..
    } = &completed.result
    else {
        panic!("FINALIZE_USE did not retain a final result");
    };
    assert_eq!(decision, "PERMIT");
    assert!(authorization_expires_at > recorded_at);
    assert_eq!(owned.receipts.calls.load(Ordering::SeqCst), 1);

    let receipt = sqlx::query(
        "SELECT compact_jws,receipt_document,receipt_digest FROM delegated_authority_service.use_receipts
         WHERE organization_id=$1 AND challenge_id=$2",
    )
    .bind(owned.organization)
    .bind(retained.challenge_id)
    .fetch_one(&db.admin)
    .await?;
    let compact: String = receipt.try_get("compact_jws")?;
    let document: Value = receipt.try_get("receipt_document")?;
    assert_eq!(
        verify_jws(&compact, owned.receipts.key.verifying_key())?,
        document
    );
    assert_eq!(
        *receipt_digest,
        format!("sha256:{:x}", Sha256::digest(compact.as_bytes()))
    );
    assert_eq!(
        receipt_ref,
        &format!(
            "urn:marty:delegated-receipt:{}",
            document["id"].as_str().unwrap()
        )
    );
    assert_eq!(document["decision"], "PERMIT");
    assert_eq!(document["evaluation"]["grant"]["id"], grant.id.to_string());
    assert_eq!(
        document["evaluation"]["operation"]["request_digest"],
        operation_digest()
    );
    assert_eq!(document["evaluation"]["actor"]["id"], owned.principal.id);
    assert!(document["policy"]["id"]
        .as_str()
        .unwrap()
        .contains(&owned.delegated_policy.to_string()));

    // Follow the retained receipt to the actual machine authentication audit,
    // actual Cedar permit and original policy source. Counts alone could pass
    // with unrelated evidence and would not establish the composed operation.
    let proof_ref = document["evaluation"]["proof_evidence_ref"]
        .as_str()
        .unwrap();
    assert!(proof_ref.starts_with("urn:marty:machine-authentication:sha256:"));
    let linked: Value = sqlx::query_scalar(
        "SELECT a.audit_document FROM delegated_authority_service.machine_authentication_evidence a
         JOIN delegated_authority_service.machine_authorization_evidence e
           ON e.organization_id=a.organization_id AND e.evidence_ref=a.audit_document#>>'{machine_authorization,evidence_ref}'
         JOIN delegated_authority_service.machine_authorization_evidence s
           ON s.organization_id=e.organization_id AND s.evidence_ref=e.evidence_document->>'source_evidence_ref'
         WHERE a.organization_id=$1 AND a.evidence_ref=$2 AND a.challenge_id=$3
           AND e.kind='EVALUATION' AND e.evidence_document->>'decision'='PERMIT'
           AND s.kind='SOURCE' AND s.evidence_document#>>'{policy_snapshot,status}'='ACTIVE'",
    )
    .bind(owned.organization)
    .bind(proof_ref)
    .bind(retained.challenge_id)
    .fetch_one(&db.admin)
    .await?;
    assert_eq!(linked["scope"]["grant_id"], grant.id.to_string());
    assert_eq!(linked["scope"]["principal"]["id"], owned.principal.id);
    let credential_observations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM machine_credential_source.observations WHERE organization_id=$1",
    )
    .bind(owned.organization)
    .fetch_one(&db.admin)
    .await?;
    assert!(credential_observations > 0);
    let original_proof: Vec<u8> = sqlx::query_scalar(
        "SELECT proof FROM flow_service.delegated_proof_submissions WHERE organization_id=$1 AND submission_id=$2",
    )
    .bind(owned.organization)
    .bind(submitted.submission_id)
    .fetch_one(&db.admin)
    .await?;
    assert_eq!(original_proof, proof);
    let completed_flows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM flow_service.delegated_use_consumptions c
         JOIN flow_service.flow_instances i ON i.id=c.challenge_id::text
         WHERE c.organization_id=$1 AND c.challenge_id=$2 AND i.status='completed'",
    )
    .bind(owned.organization)
    .bind(retained.challenge_id)
    .fetch_one(&db.admin)
    .await?;
    assert_eq!(completed_flows, 1);

    let recovered = execute(&runtime, &owned, &finish).await?;
    assert!(recovered.recovered);
    assert_eq!(
        serde_json::to_value(&recovered.result)?,
        serde_json::to_value(&completed.result)?
    );
    assert_eq!(owned.receipts.calls.load(Ordering::SeqCst), 1);

    // Revoking the real grant prevents new use while preserving authorized
    // recovery as an exact historical result; recovery is not fresh authority.
    owned.revoke_grant(&db, &grant).await?;
    assert!(execute(&runtime, &owned, &start(&grant)).await.is_err());
    let recovered = execute(&runtime, &owned, &recovery(&completed)).await?;
    assert!(recovered.recovered);
    assert_eq!(
        serde_json::to_value(&recovered.result)?,
        serde_json::to_value(&completed.result)?
    );

    // Current access revocation also closes historical result reads. Neither
    // revoked authority nor denied reads erase the original receipt or proof.
    MachineUseAccessOwner::new(PostgresOrganizationStore::new(db.admin.clone()))
        .revoke(owned.organization, &owned.human, owned.machine_id, 1)
        .await?;
    assert_eq!(
        execute(&runtime, &owned, &recovery(&completed))
            .await
            .unwrap_err(),
        DelegationUseCommandError::AccessDenied
    );
    let preserved: String = sqlx::query_scalar(
        "SELECT compact_jws FROM delegated_authority_service.use_receipts WHERE organization_id=$1 AND challenge_id=$2",
    )
    .bind(owned.organization)
    .bind(retained.challenge_id)
    .fetch_one(&db.admin)
    .await?;
    assert_eq!(preserved, compact);
    assert_eq!(owned.receipts.calls.load(Ordering::SeqCst), 1);
    db.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicitly disposable loopback PostgreSQL fixture"]
async fn constructor_rejects_other_storage_crossover_and_changed_lock_capabilities(
) -> TestResult<()> {
    let db = Database::new().await?;
    let owned = Owned::seed(&db.admin).await?;
    let runtime = assemble(&owned, &db).await?;

    // These assertions are deliberately independent of the host allowlist:
    // row locks must not give its writer grant, definition or proof mutation.
    for statement in [
        "UPDATE delegated_authority_service.delegation_grants SET revision=revision WHERE false",
        "UPDATE delegated_authority_service.use_command_claims SET command_digest=command_digest WHERE false",
        "UPDATE delegated_authority_service.use_admissions SET nonce=nonce WHERE false",
        "UPDATE flow_service.flow_definitions SET name=name WHERE false",
        "UPDATE flow_service.delegated_proof_submissions SET proof=proof WHERE false",
        "UPDATE flow_service.flow_instances SET context=context WHERE false",
    ] {
        let error = sqlx::raw_sql(statement).execute(&db.pools.use_writer).await.unwrap_err();
        assert_eq!(error.as_database_error().and_then(|error| error.code()).as_deref(), Some("42501"), "forbidden SQL was not rejected by the actual role: {statement}");
    }

    let foreign = db.foreign_flow_reader().await?;
    let mut different_store = db.pools.clone();
    different_store.flow_reader = foreign.clone();
    let error = different_store.readiness().await.unwrap_err();
    assert_eq!(error.0, "owner database mismatch");
    assert_assembly_rejected(&owned, &db, different_store).await?;
    foreign.close().await;

    let writer = &db.roles["use_writer"];
    db.sql(format!(
        "GRANT INSERT ON delegated_authority_service.consent_confirmations TO {writer}"
    ))
    .await?;
    assert_eq!(db.pools.readiness().await.unwrap_err().0, "use_writer");
    assert_assembly_rejected(&owned, &db, db.pools.clone()).await?;
    db.sql(format!(
        "REVOKE INSERT ON delegated_authority_service.consent_confirmations FROM {writer}"
    ))
    .await?;
    db.pools.readiness().await?;

    // PostgreSQL 15+ parameter privileges are independent of table grants and
    // role flags. Granting SET on this parameter could disable ordinary guards;
    // the test only grants/revokes the privilege and never changes the setting.
    db.sql(format!(
        "GRANT SET ON PARAMETER session_replication_role TO {writer}"
    ))
    .await?;
    let unchanged: String =
        sqlx::query_scalar("SELECT current_setting('session_replication_role')")
            .fetch_one(&db.pools.use_writer)
            .await?;
    assert_eq!(unchanged, "origin");
    assert_eq!(db.pools.readiness().await.unwrap_err().0, "use_writer");
    assert_assembly_rejected(&owned, &db, db.pools.clone()).await?;
    db.sql(format!(
        "REVOKE SET ON PARAMETER session_replication_role FROM {writer}"
    ))
    .await?;
    db.pools.readiness().await?;

    // A same-name capability in a separately selected owner database is a
    // different authority. Establish a valid separate Issuance source first,
    // then add the exact normally allowed lock signature in that foreign store.
    let (source_admin, source_status) = db.foreign_credential_status().await?;
    let mut separate_source = db.pools.clone();
    separate_source.credential_status = source_status.clone();
    separate_source.readiness().await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "GRANT USAGE ON SCHEMA delegated_authority_service TO {writer};
         GRANT EXECUTE ON FUNCTION delegated_authority_service.lock_use_grant(uuid,uuid) TO {writer}"
    )))
    .execute(&source_admin).await?;
    assert_eq!(
        separate_source.readiness().await.unwrap_err().0,
        "use_writer"
    );
    assert_assembly_rejected(&owned, &db, separate_source.clone()).await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "REVOKE EXECUTE ON FUNCTION delegated_authority_service.lock_use_grant(uuid,uuid) FROM {writer};
         REVOKE USAGE ON SCHEMA delegated_authority_service FROM {writer}"
    )))
    .execute(&source_admin).await?;
    separate_source.readiness().await?;
    let status_role = &db.roles["credential_status"];
    db.sql(format!(
        "GRANT SELECT ON issuance_service.issued_credentials,issuance_service.issuance_transactions TO {status_role}"
    )).await?;
    source_status.close().await;
    source_admin.close().await;
    db.pools.readiness().await?;

    // NOINHERIT still permits SET ROLE into a membership. The host rejects
    // this indirect ability to change Organization's machine-use authority.
    let escalated = format!("du_escalated_{}", Uuid::new_v4().simple());
    let access = &db.roles["access_source"];
    db.sql(format!(
        "CREATE ROLE {escalated} NOLOGIN NOINHERIT;
         GRANT USAGE ON SCHEMA organization_service TO {escalated};
         GRANT UPDATE ON organization_service.machine_use_access TO {escalated};
         GRANT {escalated} TO {access}"
    ))
    .await?;
    assert_eq!(db.pools.readiness().await.unwrap_err().0, "access_source");
    assert!(runtime.readiness().await.is_err());
    db.sql(format!("REVOKE {escalated} FROM {access}")).await?;
    db.pools.readiness().await?;

    // Identical helper signatures/ACLs do not establish the fixed owner lock.
    db.sql(
        "ALTER FUNCTION flow_service.lock_delegated_use_definition(text,text) SECURITY INVOKER"
            .into(),
    )
    .await?;
    assert!(runtime.readiness().await.is_err());
    db.sql(
        "ALTER FUNCTION flow_service.lock_delegated_use_definition(text,text) SECURITY DEFINER"
            .into(),
    )
    .await?;
    runtime.readiness().await?;
    no_receipt(&db).await?;
    assert_eq!(owned.ports.calls.load(Ordering::SeqCst), 0);
    assert_eq!(owned.receipts.calls.load(Ordering::SeqCst), 0);
    db.close().await;
    Ok(())
}

async fn assert_assembly_rejected(
    owned: &Owned,
    db: &Database,
    pools: DatabasePools,
) -> TestResult<()> {
    assert_eq!(
        DelegatedUseRuntime::assemble(
            &configuration(owned, db)?,
            pools,
            owned.ports.registry(),
            owned.receipts.clone(),
        )
        .await
        .unwrap_err(),
        DelegatedUseRuntimeError("database role boundary")
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicitly disposable loopback PostgreSQL fixture"]
async fn actual_consent_withdrawal_after_proof_prevents_final_use_and_preserves_submission(
) -> TestResult<()> {
    let db = Database::new().await?;
    let owned = Owned::seed(&db.admin).await?;
    let runtime = assemble(&owned, &db).await?;
    let grant = owned.grant(&db).await?;
    let retained = challenge(&runtime, &owned, &db, &grant).await?;
    let ingress = runtime.ingress();
    ingress
        .retrieve_request(&context(&owned)?, retained.challenge_id)
        .await?;
    let proof = owned.proof(&retained);
    let submitted = ingress
        .submit_proof(&context(&owned)?, retained.challenge_id, &proof)
        .await?;
    PgTrustedConsentWriter::new(db.consent_writer.clone())
        .withdraw_consent(
            owned.organization,
            &grant.approval.as_ref().unwrap().evidence_ref,
        )
        .await?;
    assert!(execute(
        &runtime,
        &owned,
        &finalization(retained.challenge_id, submitted.submission_id)
    )
    .await
    .is_err());
    no_receipt(&db).await?;
    assert_eq!(owned.receipts.calls.load(Ordering::SeqCst), 0);
    let original: Vec<u8> = sqlx::query_scalar(
        "SELECT proof FROM flow_service.delegated_proof_submissions WHERE submission_id=$1",
    )
    .bind(submitted.submission_id)
    .fetch_one(&db.admin)
    .await?;
    assert_eq!(original, proof);
    db.close().await;
    Ok(())
}
