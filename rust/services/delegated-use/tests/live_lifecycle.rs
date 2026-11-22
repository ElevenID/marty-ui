//! Selected-operation network lifecycle through the actual opt-in executable.
//!
//! Template/policy gRPC owners, managed issuance, request/receipt Signing Keys,
//! OpenBao/Redis custody, current PostgreSQL owners and both Cedar evaluations
//! are real. The caller is a disposable mTLS machine and holds its own VP key.
//! Human approval authentication and unused catalog health are explicit test
//! fixtures. The two gates exercise the internal surface and the explicitly
//! enabled public delegated-machine caller/wallet surface with fresh owners.
//! This qualifies the selected MachineCredential/KEY/exact-operation path,
//! including returned request/signed response URI routing and original-result
//! recovery after an actual serving-process restart. It does not
//! qualify a production deployment or arbitrary consumer wallet compatibility.
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

use live_support::{available_address, environment, setting, Executable, Server};
use network::{
    denied, denied_for, finalization, original, protected, recovery, start, wallet_challenge,
    CatalogHealthFixture, Network, SigningCounts, Surface, WalletChallenge,
};
use support::{
    database::Database,
    owned::{
        authorize_credential_issuer, operation_digest, MachineCredentialMaterial, Owned,
        OwnedIdentity, ACTION, AUDIENCE, OPERATION_PROFILE, RESOURCE,
    },
    TestResult,
};

// Both gates run in the same disposable provider audit domain. Serialize them
// even when a caller omits --test-threads=1 so count deltas remain attributable.
static LIFECYCLE_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the explicit disposable PostgreSQL/OpenBao/Redis lifecycle wrapper"]
async fn actual_executable_runs_managed_machine_use_and_recovers_independent_receipt() -> TestResult
{
    let _gate = LIFECYCLE_GATE.lock().await;
    exercise(Surface::Internal).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the explicit disposable PostgreSQL/OpenBao/Redis lifecycle wrapper"]
async fn actual_public_client_follows_verified_wallet_routes_and_recovers_independent_receipt(
) -> TestResult {
    let _gate = LIFECYCLE_GATE.lock().await;
    exercise(Surface::Public).await
}

async fn exercise(surface: Surface) -> TestResult {
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
    if surface == Surface::Public {
        env.insert("DELEGATED_USE_PUBLIC_CALLER_ENABLED".into(), "true".into());
    }
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
    let mut network = Network::connect(origin.clone(), owned.organization, surface, None).await?;
    for route in ["/health", "/ready"] {
        let response = network
            .client
            .get(format!("{origin}{route}"))
            .send()
            .await?;
        protected(&response, StatusCode::OK);
        assert!(response.bytes().await?.is_empty());
    }
    network.assert_route_selection().await?;
    network.assert_no_certificate().await?;
    assert_eq!(SigningCounts::capture()?, expected_issuance);

    // CA validation alone is insufficient: the exact caller leaf and URI must
    // match this machine. Forwarding headers must never substitute an actor.
    let unknown = Network::connect(
        origin.clone(),
        owned.organization,
        surface,
        Some(setting("MARTY_TEST_USE_UNMAPPED_CALLER_CERT_FILE")),
    )
    .await?;
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
    if surface == Surface::Public {
        // A wallet cannot create association authority before the host has
        // emitted and retained the selected signed request. Even a correctly
        // shaped form naming the configured query has no request to answer.
        denied_for(
            network.form_request(
                &format!("{origin}/v1/flows/instances/{challenge_id}/submit"),
                &[
                    ("state", challenge_id.to_string()),
                    (
                        "vp_token",
                        json!({requirement_id.clone(): ["e30.e30.Zg"]}).to_string(),
                    ),
                ],
            ),
            StatusCode::CONFLICT,
            "delegation_use_conflict",
            "wallet submission before emitted request",
        )
        .await?;
        assert_no_public_proof(&db, &network, challenge_id, expected_issuance).await?;
    }
    denied(
        unknown.request(challenge_id),
        StatusCode::FORBIDDEN,
        "delegation_use_workload_denied",
    )
    .await?;
    if surface == Surface::Public {
        denied_for(
            network
                .request(challenge_id)
                .header("x-forwarded-client-cert", "untrusted-caller-header"),
            StatusCode::FORBIDDEN,
            "delegation_use_access_denied",
            "spoofed wallet request actor",
        )
        .await?;
    }
    let request = network.signed_request(challenge_id).await?;
    let wallet = wallet_challenge(
        &request,
        &keys.request.jwk,
        &keys.request.kid,
        &grant,
        &started,
        &origin,
        &requirement_id,
    )?;
    let challenge = &wallet.challenge;
    assert!(network.signed_request(challenge_id).await? == request);
    let after_request = SigningCounts {
        request_sign: expected_issuance.request_sign + 1,
        request_grant: expected_issuance.request_grant + 1,
        ..expected_issuance
    };
    assert_eq!(SigningCounts::capture()?, after_request);

    let proof = owned.proof(challenge);
    denied(
        unknown.proof_request(&wallet, &proof),
        StatusCode::FORBIDDEN,
        "delegation_use_workload_denied",
    )
    .await?;
    if surface == Surface::Public {
        assert_public_submission_admission(&network, &db, &wallet, &proof, after_request).await?;
    }
    let submitted = network.submit(&wallet, &proof).await?;
    assert!(!submitted.recovered);
    assert_eq!(submitted.challenge_id, challenge_id);
    assert_eq!(
        submitted.proof_digest,
        format!("sha256:{:x}", Sha256::digest(&proof))
    );
    let repeated = network.submit(&wallet, &proof).await?;
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
    // Check initial freshness before retry and cold-restart probes consume the
    // original signed evidence lifetime. Recovery must not extend that lifetime.
    let recovered = network
        .receipt(&recovery(&completed))
        .await
        .map_err(|error| format!("initial finalized receipt recovery: {error}"))?;
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

    original(
        &network
            .command(&finish)
            .await
            .map_err(|error| format!("pre-restart FINALIZE_USE replay: {error}"))?,
        &completed,
    )?;
    original(
        &network
            .command(&recovery(&completed))
            .await
            .map_err(|error| format!("pre-restart final result recovery: {error}"))?,
        &completed,
    )?;
    if surface == Surface::Public {
        // A lost submission response can be recovered even when finalization
        // has since made the Flow terminal. Recovery preserves the original
        // proof identity and time; it cannot retain or consume another proof.
        let before_terminal_recovery =
            terminal_recovery_counts(&db, &network, challenge_id).await?;
        assert_eq!(before_terminal_recovery, (2, 1, 1, 1, 1, 1));
        let historical = network
            .submit(&wallet, &proof)
            .await
            .map_err(|error| format!("pre-restart terminal proof recovery: {error}"))?;
        assert!(historical.recovered);
        assert_eq!(historical.submission_id, submitted.submission_id);
        assert_eq!(historical.challenge_id, submitted.challenge_id);
        assert_eq!(historical.proof_digest, submitted.proof_digest);
        assert_eq!(historical.received_at, submitted.received_at);
        assert_eq!(
            terminal_recovery_counts(&db, &network, challenge_id).await?,
            before_terminal_recovery,
        );
        assert_eq!(SigningCounts::capture()?, after_final);
    }

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
    if surface == Surface::Public {
        denied_for(
            network
                .receipt_request(&recovery(&completed))
                .header("x-marty-use-principal-id", &owned.principal.id),
            StatusCode::FORBIDDEN,
            "delegation_use_access_denied",
            "spoofed receipt recovery actor",
        )
        .await?;
    }
    let again = network
        .receipt(&recovery(&completed))
        .await
        .map_err(|error| format!("receipt recovery after denial checks: {error}"))?;
    assert!(again.compact_jws == compact);
    assert_eq!(again.receipt_digest, *receipt_digest);
    assert_eq!(SigningCounts::capture()?, after_final);

    // Owner-side joins prove the signature belongs to this actual fresh issued
    // credential/proof/policy/Flow chain. These observations are assertions only;
    // they were not used to construct the independent consumer's expectations.
    assert_owner_evidence(
        &db,
        &owned,
        challenge,
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
    let pending_start = network
        .command(&start(&grant))
        .await
        .map_err(|error| format!("second fresh START_USE: {error}"))?;
    let DelegationUseCommandResult::Challenge {
        challenge_id: pending_id,
        ..
    } = &pending_start.result
    else {
        return Err("second START_USE did not retain a challenge".into());
    };
    let pending_id = *pending_id;
    let pending_request = network.signed_request(pending_id).await?;
    let pending_wallet = wallet_challenge(
        &pending_request,
        &keys.request.jwk,
        &keys.request.kid,
        &grant,
        &pending_start,
        &origin,
        &requirement_id,
    )?;
    let pending_proof = owned.proof(&pending_wallet.challenge);
    let pending_submission = network.submit(&pending_wallet, &pending_proof).await?;
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

    // Finish fresh-use and revocation checks within the original approval
    // lifetime before cold-restart probes. Recovery cannot renew that authority.
    // Terminate the actual serving process after a committed result, keeping
    // the same owner databases, custody and restricted-role configuration.
    // A fresh caller reconstructs its commands from the original local bytes;
    // it never creates a replacement identity from a server-returned result.
    // This proves completed-result recovery, not uncertain-claim takeover.
    let before_restart = terminal_recovery_counts(&db, &network, challenge_id).await?;
    drop(network);
    executable.close().await?;
    assert!(
        tokio::net::TcpStream::connect(&env["DELEGATED_USE_LISTEN_ADDR"])
            .await
            .is_err()
    );
    executable = Executable::start(&env).await?;
    network = Network::connect(origin.clone(), owned.organization, surface, None).await?;
    let ready = network.client.get(format!("{origin}/ready")).send().await?;
    protected(&ready, StatusCode::OK);
    assert!(ready.bytes().await?.is_empty());
    assert_eq!(SigningCounts::capture()?, after_second_request);
    original(
        &network
            .command(&start_bytes)
            .await
            .map_err(|error| format!("post-restart START_USE replay: {error}"))?,
        &started,
    )?;
    original(
        &network
            .command(&finish)
            .await
            .map_err(|error| format!("post-restart FINALIZE_USE replay: {error}"))?,
        &completed,
    )?;
    original(
        &network
            .command(&recovery(&completed))
            .await
            .map_err(|error| format!("post-restart final result recovery: {error}"))?,
        &completed,
    )?;
    let after_restart = network
        .receipt(&recovery(&completed))
        .await
        .map_err(|error| format!("post-restart receipt recovery: {error}"))?;
    original(&after_restart.original_response, &completed)?;
    assert_eq!(after_restart.receipt_ref, *receipt_ref);
    assert_eq!(after_restart.receipt_digest, *receipt_digest);
    assert_eq!(after_restart.semantics, "EVIDENCE_ONLY");
    assert!(after_restart.compact_jws == compact);
    if surface == Surface::Public {
        let proof_recovery = network
            .submit(&wallet, &proof)
            .await
            .map_err(|error| format!("post-restart terminal proof recovery: {error}"))?;
        assert!(proof_recovery.recovered);
        assert_eq!(proof_recovery.submission_id, submitted.submission_id);
        assert_eq!(proof_recovery.challenge_id, submitted.challenge_id);
        assert_eq!(proof_recovery.proof_digest, submitted.proof_digest);
        assert_eq!(proof_recovery.received_at, submitted.received_at);
    }
    assert_eq!(
        terminal_recovery_counts(&db, &network, challenge_id).await?,
        before_restart,
    );
    assert_eq!(SigningCounts::capture()?, after_second_request);

    // Restart recovery retains the same signed evidence. Its original lifetime
    // is not renewed, so verify authenticity historically after the cold restart.
    let recovered_historical = consumer::verify_historical(
        after_restart.compact_jws.as_bytes(),
        &receipt_key,
        &expectation,
        Utc::now(),
    )?;
    assert_eq!(
        recovered_historical.receipt_digest(),
        fresh.receipt_digest()
    );
    assert_eq!(recovered_historical.issued_at(), fresh.issued_at());
    assert_eq!(recovered_historical.expires_at(), fresh.expires_at());

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
        network.proof_request(&pending_wallet, &pending_proof),
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

async fn assert_public_submission_admission(
    network: &Network,
    db: &Database,
    wallet: &WalletChallenge,
    proof: &[u8],
    signing: SigningCounts,
) -> TestResult {
    let response_uri = &wallet.verified.response_uri;
    let state = &wallet.verified.state;
    let query = &wallet.verified.query_id;
    let proof = std::str::from_utf8(proof).map_err(|_| "locally produced VP is not UTF-8")?;
    let vp_token = json!({query.clone(): [proof]}).to_string();
    let quoted_query = serde_json::to_string(query)?;
    let quoted_proof = serde_json::to_string(proof)?;
    let duplicate_query =
        format!("{{{quoted_query}:[{quoted_proof}],{quoted_query}:[{quoted_proof}]}}");

    for (label, fields) in [
        (
            "wallet response for a different state",
            vec![
                ("state", uuid::Uuid::new_v4().to_string()),
                ("vp_token", vp_token.clone()),
            ],
        ),
        (
            "wallet-selected query identifier",
            vec![
                ("state", state.clone()),
                (
                    "vp_token",
                    json!({"wallet-selected-query": [proof]}).to_string(),
                ),
            ],
        ),
        (
            "bare wallet token",
            vec![("state", state.clone()), ("vp_token", proof.to_owned())],
        ),
        (
            "duplicate wallet state",
            vec![
                ("state", state.clone()),
                ("state", state.clone()),
                ("vp_token", vp_token.clone()),
            ],
        ),
        (
            "duplicate wallet token field",
            vec![
                ("state", state.clone()),
                ("vp_token", vp_token.clone()),
                ("vp_token", vp_token.clone()),
            ],
        ),
        (
            "duplicate wallet query key",
            vec![("state", state.clone()), ("vp_token", duplicate_query)],
        ),
        (
            "unsolicited presentation submission",
            vec![
                ("state", state.clone()),
                ("vp_token", vp_token.clone()),
                ("presentation_submission", "{}".into()),
            ],
        ),
    ] {
        denied_for(
            network.form_request(response_uri, &fields),
            StatusCode::BAD_REQUEST,
            "invalid_delegation_use_command",
            label,
        )
        .await?;
    }
    denied_for(
        network
            .client
            .post(response_uri)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(
                &json!({"state": state, "vp_token": vp_token}),
            )?),
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "delegated_flow_direct_post_required",
        "wallet response with unsupported media type",
    )
    .await?;
    denied_for(
        network.form_request(
            &format!("{response_uri}?state={state}"),
            &[("state", state.clone()), ("vp_token", vp_token.clone())],
        ),
        StatusCode::BAD_REQUEST,
        "invalid_delegated_flow_request",
        "wallet response query parameters",
    )
    .await?;
    denied_for(
        network
            .proof_request(wallet, proof.as_bytes())
            .header("x-forwarded-client-cert", "untrusted-wallet-certificate"),
        StatusCode::FORBIDDEN,
        "delegation_use_access_denied",
        "spoofed wallet submission actor",
    )
    .await?;
    assert_no_public_proof(db, network, wallet.challenge.challenge_id, signing).await
}

async fn assert_no_public_proof(
    db: &Database,
    network: &Network,
    challenge_id: uuid::Uuid,
    signing: SigningCounts,
) -> TestResult {
    let proofs: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM flow_service.delegated_proof_submissions WHERE organization_id=$1 AND challenge_id=$2",
    ).bind(network.organization).bind(challenge_id).fetch_one(&db.admin).await?;
    assert_eq!(proofs, 0, "rejected public forms retained a proof");
    let consumed: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM flow_service.delegated_use_consumptions WHERE organization_id=$1 AND challenge_id=$2)",
    ).bind(network.organization).bind(challenge_id).fetch_one(&db.admin).await?;
    assert!(!consumed, "rejected public forms consumed a challenge");
    assert_eq!(SigningCounts::capture()?, signing);
    Ok(())
}

async fn terminal_recovery_counts(
    db: &Database,
    network: &Network,
    challenge_id: uuid::Uuid,
) -> TestResult<(i64, i64, i64, i64, i64, i64)> {
    Ok(sqlx::query_as(
        "SELECT
         (SELECT count(*) FROM delegated_authority_service.use_command_claims WHERE organization_id=$1 AND challenge_id=$2),
         (SELECT count(*) FROM flow_service.delegated_request_claims WHERE organization_id=$1 AND challenge_id=$2),
         (SELECT count(*) FROM flow_service.delegated_proof_submissions WHERE organization_id=$1 AND challenge_id=$2),
         (SELECT count(*) FROM flow_service.delegated_proof_ingress WHERE organization_id=$1 AND challenge_id=$2),
         (SELECT count(*) FROM delegated_authority_service.use_receipts WHERE organization_id=$1 AND challenge_id=$2),
         (SELECT count(*) FROM flow_service.delegated_use_consumptions WHERE organization_id=$1 AND challenge_id=$2)",
    ).bind(network.organization).bind(challenge_id).fetch_one(&db.admin).await?)
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
