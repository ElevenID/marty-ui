//! Selected-operation network lifecycle through the actual opt-in executable.
//!
//! Template/policy gRPC owners, managed issuance, request/receipt Signing Keys,
//! OpenBao/Redis custody, current PostgreSQL owners and both Cedar evaluations
//! are real. The caller is a disposable mTLS machine and holds its own VP key.
//! Human approval authentication and unused catalog health are explicit test
//! fixtures. This qualifies the selected MachineCredential/KEY/exact-operation
//! path; it does not qualify a production deployment or public wallet routing.
#![allow(dead_code)] // Shared legacy support is not invoked by this gate.

#[path = "support/lifecycle_owners.rs"]
mod lifecycle_owners;
#[path = "support/lifecycle_signing.rs"]
mod live_signing;
#[path = "support/live_support.rs"]
mod live_support;
#[path = "support/lifecycle_network.rs"]
mod network;
#[path = "support/lifecycle_progress.rs"]
mod progress;
mod support;

use std::sync::atomic::Ordering;

use chrono::{Duration, Utc};
use marty_delegated_authority::{DelegationUseCommandResult, RetainedUseChallenge};
use marty_delegated_receipt_consumer as consumer;
use marty_organization::{
    machine_use_access::MachineUseAccessOwner, postgres::PostgresOrganizationStore,
};
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;

use live_support::{available_address, caller, environment, setting, Executable, Server};
use network::{
    denied, denied_for, finalization, original, protected, recovery, start, wallet_challenge,
    CatalogHealthFixture, Network, SigningCounts,
};
use support::{
    database::Database,
    owned::{
        authorize_credential_issuer, operation_digest, MachineCredentialMaterial, Owned,
        OwnedIdentity, ACTION, AUDIENCE, OPERATION_PROFILE, RESOURCE,
    },
    TestResult,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the explicit disposable PostgreSQL/OpenBao/Redis lifecycle wrapper"]
async fn actual_executable_runs_managed_machine_use_and_recovers_independent_receipt() -> TestResult
{
    assert_eq!(setting("MARTY_TEST_DELEGATED_USE_LIFECYCLE"), "true");
    marty_service_runtime::install_tls_crypto_provider();
    let db = Database::new().await?;
    let identity = OwnedIdentity::seed(&db.admin).await?;
    let mut keys = live_signing::SigningKeys::start(identity.organization).await?;
    let mut owners = lifecycle_owners::LifecycleOwners::start(
        &db.admin,
        identity.organization,
        &keys.credential.issuer,
    )
    .await?;
    owners.assert_read_authentication().await?;
    assert_eq!(owners.policy.credential_requirements.len(), 1);
    let requirement_id = owners.policy.credential_requirements[0].id.to_string();

    // The actual issuance application obtains a purpose-bound managed grant,
    // signs with its own remote key, and retains the original credential itself.
    // No fixture inserts an issued credential or supplies an ephemeral issuer.
    let before_issuance = SigningCounts::capture()?;
    let issued = keys
        .issue_machine_credential(
            &db.admin,
            identity.organization,
            &owners.template,
            &identity.principal.id,
            &identity.machine_key,
        )
        .await?;
    assert_eq!(issued.issuer, keys.credential.issuer);
    assert_eq!(issued.kid, keys.credential.kid);
    assert_eq!(issued.jwk, keys.credential.jwk);
    assert!(!issued.credential_id.is_nil() && !issued.transaction_id.is_empty());
    let required_types = vec!["MachineCredential".to_owned()];
    let trust_profile_id = authorize_credential_issuer(
        &db.admin,
        identity.organization,
        &keys.credential.issuer,
        &keys.credential.jwk,
        &keys.credential.kid,
        "ES256",
        &required_types,
    )
    .await?;
    let listen = available_address()?;
    let origin = format!("https://{listen}");
    let owned = Owned::seed_with_credential(
        &db.admin,
        identity,
        MachineCredentialMaterial {
            trust_profile_id,
            credential_id: issued.credential_id,
            compact: issued.compact,
            issuer: keys.credential.issuer.clone(),
            public_jwk: keys.credential.jwk.clone(),
            required_types,
        },
        &owners.policy.id.to_string(),
        &origin,
    )
    .await?;
    let expected_issuance = SigningCounts {
        credential_sign: before_issuance.credential_sign + 1,
        credential_grant: before_issuance.credential_grant + 1,
        ..before_issuance
    };
    assert_eq!(SigningCounts::capture()?, expected_issuance);
    let grant = owned.grant(&db).await?;
    let catalog_fixture = CatalogHealthFixture::default();
    let mut references = Server::https(catalog_fixture.router()).await?;
    let mut env = environment(
        &owned,
        &db,
        &keys,
        &owners.template_server,
        &owners.policy_server,
        &references,
    )?;
    env.insert("DELEGATED_USE_LISTEN_ADDR".into(), listen.to_string());
    env.insert("DELEGATED_USE_PUBLIC_BASE_URL".into(), origin.clone());
    env.insert(
        "DELEGATED_USE_VERIFIER_DISPLAY_NAME".into(),
        "Disposable lifecycle gate".into(),
    );
    for suffix in [
        "CERT_FILE",
        "KMS_PROVIDER",
        "KMS_ADDR",
        "KMS_CA_CERT_FILE",
        "KMS_TOKEN_FILE",
        "KMS_KEY_NAME",
        "KMS_KEY_VERSION",
    ] {
        env.insert(
            format!("DELEGATED_USE_WORKLOAD_TLS_{suffix}"),
            setting(&format!("MARTY_TEST_USE_WORKLOAD_TLS_{suffix}")),
        );
    }
    let mut executable = Executable::start(&env).await?;
    let network = Network {
        client: caller(None).await?,
        origin: origin.clone(),
        organization: owned.organization,
    };
    for route in ["/health", "/ready"] {
        let response = network
            .client
            .get(format!("{origin}{route}"))
            .send()
            .await?;
        protected(&response, StatusCode::OK);
        assert!(response.bytes().await?.is_empty());
    }
    assert_eq!(SigningCounts::capture()?, expected_issuance);

    // CA validation alone is insufficient: the exact caller leaf and URI must
    // match this machine. Forwarding headers must never substitute an actor.
    let unknown = Network {
        client: caller(Some(setting("MARTY_TEST_USE_UNMAPPED_CALLER_CERT_FILE"))).await?,
        origin: origin.clone(),
        organization: owned.organization,
    };
    let start_bytes = start(&grant);
    denied(
        unknown.command_request(&start_bytes),
        StatusCode::FORBIDDEN,
        "delegation_use_workload_denied",
    )
    .await?;
    denied(
        network
            .command_request(&start_bytes)
            .header("x-marty-use-principal-id", &owned.principal.id),
        StatusCode::FORBIDDEN,
        "delegation_use_access_denied",
    )
    .await?;

    let started = network.command(&start_bytes).await?;
    assert!(!started.recovered);
    original(&network.command(&start_bytes).await?, &started)?;
    original(&network.command(&recovery(&started)).await?, &started)?;
    let DelegationUseCommandResult::Challenge { challenge_id, .. } = &started.result else {
        return Err("START_USE did not retain a challenge".into());
    };
    let challenge_id = *challenge_id;
    denied(
        unknown.request(challenge_id),
        StatusCode::FORBIDDEN,
        "delegation_use_workload_denied",
    )
    .await?;
    let request = network.signed_request(challenge_id).await?;
    let challenge = wallet_challenge(
        &request,
        &keys.request.jwk,
        &keys.request.kid,
        &grant,
        &started,
        &origin,
        &requirement_id,
    )?;
    assert!(network.signed_request(challenge_id).await? == request);
    let after_request = SigningCounts {
        request_sign: expected_issuance.request_sign + 1,
        request_grant: expected_issuance.request_grant + 1,
        ..expected_issuance
    };
    assert_eq!(SigningCounts::capture()?, after_request);

    let proof = owned.proof(&challenge);
    denied(
        unknown.proof_request(challenge_id, &proof),
        StatusCode::FORBIDDEN,
        "delegation_use_workload_denied",
    )
    .await?;
    let submitted = network.submit(challenge_id, &proof).await?;
    assert!(!submitted.recovered);
    assert_eq!(submitted.challenge_id, challenge_id);
    assert_eq!(
        submitted.proof_digest,
        format!("sha256:{:x}", Sha256::digest(&proof))
    );
    let repeated = network.submit(challenge_id, &proof).await?;
    assert!(repeated.recovered);
    assert_eq!(repeated.submission_id, submitted.submission_id);
    assert_eq!(repeated.received_at, submitted.received_at);
    assert_eq!(repeated.proof_digest, submitted.proof_digest);
    let finish = finalization(challenge_id, submitted.submission_id);
    let completed = match network.command(&finish).await {
        Ok(completed) => completed,
        Err(error) => {
            let retained =
                progress::retained_stages(&db.admin, owned.organization, challenge_id).await;
            let signing = SigningCounts::capture()
                .map(|counts| format!("{counts:?}"))
                .unwrap_or_else(|_| "provider signing counts unavailable".into());
            return Err(format!(
                "{error}; {retained}; provider signing before={after_request:?}; after={signing}"
            )
            .into());
        }
    };
    assert!(!completed.recovered);
    let DelegationUseCommandResult::FinalUse {
        challenge_id: completed_challenge,
        decision,
        receipt_ref,
        receipt_digest,
        recorded_at,
        authorization_expires_at,
        semantics,
    } = &completed.result
    else {
        return Err("FINALIZE_USE did not retain a final result".into());
    };
    assert_eq!(*completed_challenge, challenge_id);
    assert_eq!(decision, "PERMIT");
    assert_eq!(semantics, "EVIDENCE_ONLY");
    assert!(authorization_expires_at > recorded_at);
    let after_final = SigningCounts {
        receipt_sign: after_request.receipt_sign + 1,
        receipt_grant: after_request.receipt_grant + 1,
        ..after_request
    };
    assert_eq!(SigningCounts::capture()?, after_final);
    original(&network.command(&finish).await?, &completed)?;
    original(&network.command(&recovery(&completed)).await?, &completed)?;

    let recovered = network.receipt(&recovery(&completed)).await?;
    original(&recovered.original_response, &completed)?;
    assert_eq!(recovered.receipt_ref, *receipt_ref);
    assert_eq!(recovered.receipt_digest, *receipt_digest);
    assert_eq!(recovered.semantics, "EVIDENCE_ONLY");
    let compact = recovered.compact_jws;

    // Construct consumer inputs exclusively from bootstrap, the original grant,
    // authenticated START_USE, independently verified request and FINAL_USE.
    // Neither the DTO nor an unverified receipt can choose the expected key,
    // actor, operation, nonce, authority, policy or result binding.
    let receipt_key = consumer::PinnedReceiptKey::new(
        owned.organization,
        consumer::Principal {
            principal_type: consumer::PrincipalType::Organization,
            id: keys.issuer.clone(),
        },
        consumer::Algorithm::Es256,
        keys.kid.clone(),
        &serde_json::to_vec(&keys.jwk)?,
    )?;
    let expected_context = consumer::ReceiptContext {
        organization_id: owned.organization,
        grant: consumer::GrantReference {
            id: grant.id,
            revision: grant.revision,
            terms_digest: grant.terms_digest.clone(),
        },
        actor: serde_json::from_value(serde_json::to_value(&owned.principal)?)?,
        subject: serde_json::from_value(serde_json::to_value(&grant.terms.subject)?)?,
        binding: consumer::Binding::Key {
            key_thumbprint: owned.machine_thumbprint.clone(),
        },
        operation: consumer::Operation {
            action: ACTION.into(),
            resource_id: RESOURCE.into(),
            audience: AUDIENCE.into(),
            request_profile: OPERATION_PROFILE.into(),
            request_digest: operation_digest(),
        },
        challenge: challenge.nonce.clone(),
        status_issuer: serde_json::from_value(serde_json::to_value(&owned.authority.issuer)?)?,
        status_state: consumer::StatusState::Active,
        policy: consumer::PolicyExpectation {
            id: format!(
                "urn:marty:delegation-use-policy:{}:{}",
                owned.organization, owned.delegated_policy
            ),
            version_digest: None,
        },
        domain_evidence: None,
        context_created_at: challenge.created_at,
        context_expires_at: challenge.expires_at,
    };
    let retention = consumer::RetainedReceiptBinding {
        receipt_ref: receipt_ref.clone(),
        receipt_digest: receipt_digest.clone(),
        decision: consumer::Decision::Permit,
        recorded_at: *recorded_at,
        authorization_expires_at: *authorization_expires_at,
    };
    let expectation =
        consumer::ReceiptExpectation::new(expected_context.clone(), retention.clone())?;
    let fresh = consumer::verify_fresh(
        compact.as_bytes(),
        &receipt_key,
        &expectation,
        Utc::now(),
        consumer::FreshnessPolicy::new(120, 120)?,
    )?;
    assert_eq!(fresh.decision(), consumer::Decision::Permit);
    assert_eq!(fresh.semantics(), "EVIDENCE_ONLY");
    assert_eq!(fresh.expires_at(), *authorization_expires_at);
    assert_eq!(fresh.receipt_digest(), receipt_digest);
    let mut different_operation = expected_context;
    different_operation.operation.request_digest = format!("sha256:{}", "c7".repeat(32));
    assert_eq!(
        consumer::verify_fresh(
            compact.as_bytes(),
            &receipt_key,
            &consumer::ReceiptExpectation::new(different_operation, retention)?,
            Utc::now(),
            consumer::FreshnessPolicy::new(120, 120)?
        )
        .unwrap_err(),
        consumer::ReceiptVerificationError::ContextMismatch
    );
    let historical_at = *authorization_expires_at + Duration::seconds(1);
    assert_eq!(
        consumer::verify_fresh(
            compact.as_bytes(),
            &receipt_key,
            &expectation,
            historical_at,
            consumer::FreshnessPolicy::new(120, 120)?
        )
        .unwrap_err(),
        consumer::ReceiptVerificationError::Expired
    );
    let historical = consumer::verify_historical(
        compact.as_bytes(),
        &receipt_key,
        &expectation,
        historical_at,
    )?;
    assert_eq!(historical.receipt_digest(), fresh.receipt_digest());
    assert_eq!(historical.expires_at(), fresh.expires_at());

    let mut wrong_recovery: Value = serde_json::from_slice(&recovery(&completed))?;
    wrong_recovery["expected_command_digest"] = json!(format!("sha256:{}", "fe".repeat(32)));
    let wrong_recovery = serde_json::to_vec(&wrong_recovery)?;
    denied(
        network.receipt_request(&wrong_recovery),
        StatusCode::CONFLICT,
        "delegation_use_conflict",
    )
    .await?;
    denied(
        network.receipt_request(&finish),
        StatusCode::BAD_REQUEST,
        "unsupported_delegation_use_command",
    )
    .await?;
    denied(
        unknown.receipt_request(&recovery(&completed)),
        StatusCode::FORBIDDEN,
        "delegation_use_workload_denied",
    )
    .await?;
    let again = network.receipt(&recovery(&completed)).await?;
    assert!(again.compact_jws == compact);
    assert_eq!(again.receipt_digest, *receipt_digest);
    assert_eq!(SigningCounts::capture()?, after_final);

    // Owner-side joins prove the signature belongs to this actual fresh issued
    // credential/proof/policy/Flow chain. These observations are assertions only;
    // they were not used to construct the independent consumer's expectations.
    assert_owner_evidence(
        &db,
        &owned,
        &challenge,
        submitted.submission_id,
        &proof,
        &request,
        &compact,
        issued.credential_id,
        &issued.transaction_id,
    )
    .await?;

    // A second proof is submitted while the grant is still active. Revocation
    // before FINALIZE_USE must prevent fresh signing/consumption, while the
    // first original receipt remains recoverable by its still-authorized actor.
    let pending_start = network.command(&start(&grant)).await?;
    let DelegationUseCommandResult::Challenge {
        challenge_id: pending_id,
        ..
    } = &pending_start.result
    else {
        return Err("second START_USE did not retain a challenge".into());
    };
    let pending_id = *pending_id;
    let pending_request = network.signed_request(pending_id).await?;
    let pending_challenge = wallet_challenge(
        &pending_request,
        &keys.request.jwk,
        &keys.request.kid,
        &grant,
        &pending_start,
        &origin,
        &requirement_id,
    )?;
    let pending_proof = owned.proof(&pending_challenge);
    let pending_submission = network.submit(pending_id, &pending_proof).await?;
    let after_second_request = SigningCounts {
        request_sign: after_final.request_sign + 1,
        request_grant: after_final.request_grant + 1,
        ..after_final
    };
    assert_eq!(SigningCounts::capture()?, after_second_request);
    owned.revoke_grant(&db, &grant).await?;
    denied_for(
        network.command_request(&start(&grant)),
        StatusCode::FORBIDDEN,
        "delegation_use_access_denied",
        "revoked grant START_USE",
    )
    .await?;
    let pending_finish = finalization(pending_id, pending_submission.submission_id);
    // The currently authorized actor presents a retained active snapshot. The
    // ledger locks the now-revoked grant and rejects that changed snapshot
    // before claiming FINALIZE_USE, evaluating proof, or invoking the signer.
    denied_for(
        network.command_request(&pending_finish),
        StatusCode::CONFLICT,
        "delegation_use_conflict",
        "revoked grant pending FINALIZE_USE",
    )
    .await?;
    assert_eq!(SigningCounts::capture()?, after_second_request);
    let pending_claimed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM delegated_authority_service.use_command_claims WHERE organization_id=$1 AND challenge_id=$2 AND command_name='FINALIZE_USE')")
        .bind(owned.organization).bind(pending_id).fetch_one(&db.admin).await?;
    assert!(!pending_claimed);
    original(&network.command(&finish).await?, &completed)?;
    original(&network.command(&recovery(&completed)).await?, &completed)?;
    let after_revoke = network.receipt(&recovery(&completed)).await?;
    assert!(after_revoke.compact_jws == compact);
    assert_eq!(after_revoke.receipt_digest, *receipt_digest);
    original(&after_revoke.original_response, &completed)?;
    let historical = consumer::verify_historical(
        after_revoke.compact_jws.as_bytes(),
        &receipt_key,
        &expectation,
        historical_at,
    )?;
    assert_eq!(historical.expires_at(), *authorization_expires_at);
    assert_eq!(SigningCounts::capture()?, after_second_request);

    // Current permission withdrawal applies even to exact historical recovery
    // and duplicate proof paths; immutable stored artifacts survive denial.
    MachineUseAccessOwner::new(PostgresOrganizationStore::new(db.admin.clone()))
        .revoke(owned.organization, &owned.human, owned.machine_id, 1)
        .await?;
    for request in [
        network.command_request(&recovery(&completed)),
        network.command_request(&finish),
        network.receipt_request(&recovery(&completed)),
        network.request(pending_id),
        network.proof_request(pending_id, &pending_proof),
    ] {
        denied(
            request,
            StatusCode::FORBIDDEN,
            "delegation_use_access_denied",
        )
        .await?;
    }
    assert_eq!(SigningCounts::capture()?, after_second_request);
    let receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM delegated_authority_service.use_receipts WHERE organization_id=$1",
    )
    .bind(owned.organization)
    .fetch_one(&db.admin)
    .await?;
    assert_eq!(receipts, 1);
    let pending_consumed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM flow_service.delegated_use_consumptions WHERE organization_id=$1 AND challenge_id=$2)")
        .bind(owned.organization).bind(pending_id).fetch_one(&db.admin).await?;
    assert!(!pending_consumed);
    let pending_retained: Vec<u8> = sqlx::query_scalar("SELECT proof FROM flow_service.delegated_proof_submissions WHERE organization_id=$1 AND submission_id=$2")
        .bind(owned.organization).bind(pending_submission.submission_id).fetch_one(&db.admin).await?;
    assert!(pending_retained == pending_proof);
    let preserved: String = sqlx::query_scalar("SELECT compact_jws FROM delegated_authority_service.use_receipts WHERE organization_id=$1 AND challenge_id=$2")
        .bind(owned.organization).bind(challenge_id).fetch_one(&db.admin).await?;
    assert!(preserved == compact);
    assert!(catalog_fixture.health_reads.load(Ordering::SeqCst) >= 8);
    assert_eq!(
        catalog_fixture
            .attempted_record_reads
            .load(Ordering::SeqCst),
        0
    );
    assert_eq!(owned.ports.calls.load(Ordering::SeqCst), 0);
    assert_eq!(owned.receipts.calls.load(Ordering::SeqCst), 0);

    executable.close().await?;
    references.close().await?;
    owners.close().await?;
    keys.server.close().await?;
    db.close().await;
    Ok(())
}

async fn assert_owner_evidence(
    db: &Database,
    owned: &Owned,
    challenge: &RetainedUseChallenge,
    submission_id: uuid::Uuid,
    proof: &[u8],
    request: &str,
    compact: &str,
    credential_id: uuid::Uuid,
    transaction_id: &str,
) -> TestResult {
    let receipt = sqlx::query("SELECT compact_jws,receipt_document,receipt_digest FROM delegated_authority_service.use_receipts WHERE organization_id=$1 AND challenge_id=$2")
        .bind(owned.organization).bind(challenge.challenge_id).fetch_one(&db.admin).await?;
    assert!(receipt.try_get::<String, _>("compact_jws")? == compact);
    assert_eq!(
        receipt.try_get::<String, _>("receipt_digest")?,
        format!("sha256:{:x}", Sha256::digest(compact.as_bytes()))
    );
    let document: Value = receipt.try_get("receipt_document")?;
    let proof_ref = document["evaluation"]["proof_evidence_ref"]
        .as_str()
        .ok_or("missing retained proof reference")?;
    assert!(proof_ref.starts_with("urn:marty:machine-authentication:sha256:"));
    let linked: Value = sqlx::query_scalar(
        "SELECT a.audit_document FROM delegated_authority_service.machine_authentication_evidence a
         JOIN delegated_authority_service.machine_authorization_evidence e
           ON e.organization_id=a.organization_id AND e.evidence_ref=a.audit_document#>>'{machine_authorization,evidence_ref}'
         JOIN delegated_authority_service.machine_authorization_evidence s
           ON s.organization_id=e.organization_id AND s.evidence_ref=e.evidence_document->>'source_evidence_ref'
         WHERE a.organization_id=$1 AND a.evidence_ref=$2 AND a.challenge_id=$3
           AND e.kind='EVALUATION' AND e.evidence_document->>'decision'='PERMIT'
           AND s.kind='SOURCE' AND s.evidence_document#>>'{policy_snapshot,status}'='ACTIVE'"
    ).bind(owned.organization).bind(proof_ref).bind(challenge.challenge_id).fetch_one(&db.admin).await?;
    assert_eq!(linked["scope"]["grant_id"], challenge.grant.id.to_string());
    assert_eq!(linked["scope"]["principal"]["id"], owned.principal.id);
    let retained_proof: Vec<u8> = sqlx::query_scalar("SELECT proof FROM flow_service.delegated_proof_submissions WHERE organization_id=$1 AND submission_id=$2")
        .bind(owned.organization).bind(submission_id).fetch_one(&db.admin).await?;
    assert!(retained_proof == proof);
    let retained_request: Vec<u8> = sqlx::query_scalar("SELECT request_bytes FROM flow_service.delegated_request_results WHERE organization_id=$1 AND challenge_id=$2")
        .bind(owned.organization).bind(challenge.challenge_id).fetch_one(&db.admin).await?;
    assert!(retained_request == request.as_bytes());
    let completed: i64 = sqlx::query_scalar("SELECT count(*) FROM flow_service.delegated_use_consumptions c JOIN flow_service.flow_instances i ON i.id=c.challenge_id::text WHERE c.organization_id=$1 AND c.challenge_id=$2 AND i.status='completed'")
        .bind(owned.organization).bind(challenge.challenge_id).fetch_one(&db.admin).await?;
    assert_eq!(completed, 1);
    let issued: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM issuance_service.issued_credentials c JOIN issuance_service.issuance_transactions t ON t.id=c.transaction_id AND t.organization_id=c.organization_id AND t.subject_did=c.subject_did WHERE c.id=$1 AND c.organization_id=$2 AND c.transaction_id=$3 AND c.status='active' AND NOT c.revoked AND t.status='issued' AND c.credential_jwt=$4 AND c.credential_hash=$5)")
        .bind(format!("urn:uuid:{credential_id}")).bind(owned.organization.to_string()).bind(transaction_id)
        .bind(&owned.credential).bind(format!("{:x}", Sha256::digest(owned.credential.as_bytes())))
        .fetch_one(&db.admin).await?;
    assert!(issued);
    let observations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM machine_credential_source.observations WHERE organization_id=$1",
    )
    .bind(owned.organization)
    .fetch_one(&db.admin)
    .await?;
    assert!(observations > 0);
    Ok(())
}
