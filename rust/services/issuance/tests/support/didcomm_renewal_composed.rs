//! Candidate renewal HTTP -> actual admission/PostgreSQL -> shared DIDComm graph.
//! Historical source rows, issuer/signing, control-plane peers, clock and seed are
//! controlled. HTTPS wallet transport, Core encryption/decryption, reservation,
//! claim, source revocation publication and durable finalization are real owners.
//! This is service-router evidence, not a gateway/deployment or KMS qualification.
//! RENEWAL-001 pre-send links and RENEWAL-002 pending URI are intentional native
//! corrections; the separate frozen Python renewal corpus is not rewritten.

use std::future::Future;

use marty_issuance_service::{
    credential_renewal::{self, CredentialRenewalService},
    initiation_http::InitiationHttpService,
};

use super::*;

#[path = "didcomm_renewal_canvas.rs"]
mod canvas;

pub(super) async fn run_canvas(pool: &PgPool) {
    canvas::run(pool).await;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scenario {
    Automatic,
    Refused,
    MissingHolder,
    OrdinaryThenDirect,
}

impl Scenario {
    fn template(self) -> FreshScenario {
        match self {
            Self::OrdinaryThenDirect => FreshScenario::OrdinaryWallet,
            Self::Automatic | Self::Refused => FreshScenario::SubjectOnly,
            Self::MissingHolder => FreshScenario::MissingHolder,
        }
    }
}

/// An explicitly historical active source, never a fabricated successor or send.
async fn seed_source(pool: &PgPool, graph: &DeliveryGraph, id: &str, scenario: Scenario) -> String {
    let source_id = format!("source-{id}");
    let mut source = transaction(&format!("source-tx-{id}"));
    source.status = CredentialTransactionStatus::Issued;
    source.renewable = true;
    source.application_id = Some(format!("application-{id}"));
    source.subject_did = (scenario != Scenario::MissingHolder).then(|| HOLDER.into());
    source.reserved_credential_id = Some(source_id.clone());
    source.expires_at = source.created_at + chrono::Duration::days(1);
    let reserved = graph
        .repository
        .reserve_idempotently(&source)
        .await
        .unwrap();
    assert!(reserved.created);
    assert_eq!(reserved.transaction, source);
    sqlx::query(
        "INSERT INTO issuance_service.issued_credentials
        (id,transaction_id,organization_id,credential_template_id,subject_did,
         issuer_did,revocation_profile_id,status_list_entries,credential_jwt,credential_hash,
         status,status_updated_at,revoked,issued_at,expires_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'synthetic-historical-source','synthetic-source-hash',
                'active',$9,false,$9,$10)",
    )
    .bind(&source_id)
    .bind(&source.id)
    .bind(ORGANIZATION)
    .bind(&source.credential_template_id)
    .bind(&source.subject_did)
    .bind(ISSUER)
    .bind("didcomm-status")
    .bind(json!([{"status_list_id":"didcomm-status","index":7}]))
    .bind(source.created_at)
    .bind(source.expires_at)
    .execute(pool)
    .await
    .unwrap();
    source_id
}

async fn renewal_response(router: &Router, source: &str) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::post(format!("/v1/issued-credentials/{source}/renew"))
                .header("x-api-key", API_KEY)
                .header("x-organization-id", ORGANIZATION)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    assert_eq!(response.headers()["content-type"], "application/json");
    (
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap(),
    )
}

fn assert_prelinks(state: &Value, id: &str, source: &str) {
    assert_eq!(state["transaction"]["id"], id);
    assert_eq!(state["transaction"]["organization_id"], ORGANIZATION);
    assert_eq!(state["transaction"]["renewal_of_credential_id"], source);
    assert_eq!(
        state["transaction"]["application_id"],
        format!("application-{id}")
    );
    assert_eq!(
        state["transaction"]["claims"],
        // Real admission's reserved VCT matches the pinned Python route
        // 87eae307 routes.py:3450,3499 and issuance-initiation reserved_vct_wins.
        json!({"given_name":"Synthetic","_vct":"https://issuer.example/credentials/EmployeeCredential"})
    );
}

/// The locally owned future cannot detach on panic/timeout. This observes actual
/// PG links after claim/allocation while the controlled signer is held, BEFORE
/// transport; it does not claim a database snapshot at wallet capture time.
async fn complete_after_prelinks<T>(
    pending: impl Future<Output = T>,
    pool: &PgPool,
    graph: &DeliveryGraph,
    id: &str,
    source: &str,
    source_before: &Value,
) -> T {
    let gate = graph.gate.as_ref().unwrap();
    tokio::pin!(pending);
    tokio::select! {
        _ = &mut pending => panic!("delivery completed before the controlled signing gate"),
        entered = tokio::time::timeout(Duration::from_secs(10), gate.entered.acquire()) => {
            entered.expect("bounded real-claim signing gate").unwrap().forget();
        }
    }
    let before_send = snapshot(pool, id).await;
    assert_prelinks(&before_send, id, source);
    assert_eq!(before_send["transaction"]["status"], "signing");
    assert!(before_send["transaction"]["reserved_credential_id"].is_string());
    for rows in ["credentials", "deliveries", "events"] {
        assert_eq!(before_send[rows], json!([]));
    }
    assert_eq!(
        snapshot(pool, &format!("source-tx-{id}")).await,
        *source_before
    );
    assert!(graph.publications.lock().unwrap().is_empty());
    assert_eq!(graph.allocations.load(Ordering::SeqCst), 1);
    assert_eq!(graph.builder.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        graph.wallet.captures().await,
        json!({"messages":[],"failures":0})
    );
    gate.release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(15), pending)
        .await
        .expect("bounded actual delivery")
}

fn assert_renewal_offer(
    response: &Value,
    id: &str,
    source: &str,
    scenario: Scenario,
    endpoint: &str,
) {
    let offer_uri = response["credential_offer_uri"].as_str().unwrap();
    assert_canonical_offer_uri(offer_uri, &format!("pre-auth-{id}"));
    let (wallet, label, uri) = if scenario == Scenario::OrdinaryThenDirect {
        let encoded = offer_uri
            .strip_prefix("openid-credential-offer://?credential_offer=")
            .unwrap();
        (
            "ordinary",
            "Ordinary Wallet",
            format!("synthetic-wallet://open?source=fixture&credential_offer={encoded}"),
        )
    } else {
        (
            "didcomm",
            "Synthetic Wallet",
            if scenario == Scenario::Automatic {
                format!("didcomm://{endpoint}")
            } else {
                format!("didcomm://pending?transaction_id={id}")
            },
        )
    };
    assert_eq!(
        *response,
        json!({
            "source_credential_id":source,"transaction_id":id,"credential_offer_uri":offer_uri,
            "credential_offer_uris":{wallet:uri},"credential_offer_labels":{wallet:label},
            "expires_at":(Utc.timestamp_opt(1_700_000_000, 0).single().unwrap()+chrono::Duration::days(7)).to_rfc3339()
        })
    );
}

fn assert_captured_message(
    graph: &DeliveryGraph,
    captured: &Value,
    authenticated: bool,
    id: &str,
    state: &Value,
) -> String {
    assert_eq!(captured["failures"], 0);
    assert_eq!(captured["messages"].as_array().unwrap().len(), 1);
    let message = decrypt_capture(
        captured["messages"][0].as_str().unwrap(),
        authenticated,
        &graph.recipient_secret,
        &graph.recipient_document,
        &graph.sender_document,
    );
    assert!(uuid::Uuid::parse_str(&message.id).is_ok());
    assert_eq!(
        message.r#type,
        "https://didcomm.org/issue-credential/3.0/issue-credential"
    );
    assert_eq!(message.thid.as_deref(), Some(id));
    assert_eq!(
        message.body,
        json!({"goal_code":"issue-vc","comment":"Here is your credential"})
    );
    assert_eq!(message.attachments.len(), 1);
    let attachment = &message.attachments[0];
    assert_eq!(
        attachment.id.as_deref(),
        state["credentials"][0]["id"].as_str()
    );
    assert_eq!(attachment.format.as_deref(), Some(FORMAT));
    assert_eq!(
        attachment.media_type.as_deref(),
        Some("application/vc+sd-jwt")
    );
    assert!(attachment.data.json.is_none());
    assert!(attachment.data.links.is_none());
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(attachment.data.base64.as_deref().unwrap())
            .unwrap(),
        SIGNED_CREDENTIAL.as_bytes()
    );
    assert_eq!(
        state["deliveries"][0]["metadata"]["didcomm_message_id"],
        message.id
    );
    message.id
}

async fn run_case(pool: &PgPool, authenticated: bool, scenario: Scenario, gateway: bool) {
    let id = format!(
        "renewal-composed-{}-{scenario:?}",
        if authenticated { "auth" } else { "anon" }
    );
    let graph = DeliveryGraph::start(
        pool,
        authenticated,
        (scenario == Scenario::Refused).then_some(Fault::HttpRefused),
        None,
        true,
    )
    .await;
    let source = seed_source(pool, &graph, &id, scenario).await;
    let source_before = snapshot(pool, &format!("source-tx-{id}")).await;
    assert_eq!(
        snapshot(pool, &id).await,
        json!({"transaction":null,"credentials":[],"deliveries":[],"events":[]})
    );
    let (service, projector, admission) = fresh_initiation::services(
        graph.repository.clone(),
        graph.delivery.clone(),
        graph.issuer.clone(),
        &id,
        scenario.template(),
    );
    let router = credential_renewal::router(CredentialRenewalService::new(
        graph.repository.clone(),
        InitiationHttpService::new(service, projector.clone(), Some(API_KEY)),
        Some(API_KEY),
        admission.clone(),
    ));
    let mut gateway = if gateway {
        let missing = super::super::renewal_gateway_replay::GatewayFixture::start(
            router.clone(),
            ORGANIZATION,
            API_KEY,
            &format!("absent-{source}"),
        )
        .await;
        missing
            .assert_missing_owner_uses_native_source_check()
            .await;
        missing.close().await;
        let fixture = super::super::renewal_gateway_replay::GatewayFixture::start(
            router.clone(),
            ORGANIZATION,
            API_KEY,
            &source,
        )
        .await;
        fixture.assert_selection_and_denials().await;
        Some(fixture)
    } else {
        None
    };
    let direct = DirectEndpoint {
        router: direct_router(graph.delivery.clone()),
        gateway: false,
    };
    let request = async {
        match &gateway {
            Some(gateway) => gateway.renew().await,
            None => renewal_response(&router, &source).await,
        }
    };
    let (status, response) = if matches!(scenario, Scenario::Automatic | Scenario::Refused) {
        complete_after_prelinks(request, pool, &graph, &id, &source, &source_before).await
    } else {
        request.await
    };
    assert_eq!(status, StatusCode::OK, "{scenario:?}: {response}");
    assert_renewal_offer(&response, &id, &source, scenario, &graph.endpoint);
    assert_eq!(admission.seeds.load(Ordering::SeqCst), 1);
    let request = InitiationRequest {
        organization_id: ORGANIZATION.into(),
        issuer_did: ISSUER.into(),
        credential_template_id: Some("didcomm-template".into()),
        subject_did: (scenario != Scenario::MissingHolder).then(|| HOLDER.into()),
        claims: Some(transaction(&id).claims),
        ..InitiationRequest::default()
    };
    if matches!(
        scenario,
        Scenario::OrdinaryThenDirect | Scenario::MissingHolder
    ) {
        let pending = snapshot(pool, &id).await;
        assert_prelinks(&pending, &id, &source);
        assert_eq!(pending["transaction"]["status"], "pending");
        assert!(pending["transaction"]["reserved_credential_id"].is_null());
        for rows in ["credentials", "deliveries", "events"] {
            assert_eq!(pending[rows], json!([]));
        }
        assert_eq!(
            snapshot(pool, &format!("source-tx-{id}")).await,
            source_before
        );
        assert_eq!(
            graph.wallet.captures().await,
            json!({"messages":[],"failures":0})
        );
        assert_eq!(graph.allocations.load(Ordering::SeqCst), 0);
        assert_eq!(graph.builder.calls.load(Ordering::SeqCst), 0);
        assert_eq!(graph.resolutions.load(Ordering::SeqCst), 0);
        assert!(graph.publications.lock().unwrap().is_empty());
        if scenario == Scenario::OrdinaryThenDirect {
            let (status, receipt) = complete_after_prelinks(
                direct_response(&direct, &id),
                pool,
                &graph,
                &id,
                &source,
                &source_before,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{receipt}");
        }
    }
    let state = snapshot(pool, &id).await;
    assert_prelinks(&state, &id, &source);
    let captured = graph.wallet.captures().await;
    let source_after = snapshot(pool, &format!("source-tx-{id}")).await;
    let successful = matches!(scenario, Scenario::Automatic | Scenario::OrdinaryThenDirect);
    if scenario != Scenario::MissingHolder {
        assert_eq!(state["transaction"]["status"], "issued");
        for rows in ["credentials", "deliveries"] {
            assert_eq!(state[rows].as_array().unwrap().len(), 1);
        }
        assert_materialized_binding(&state, &id, &graph.endpoint);
        let message = assert_captured_message(&graph, &captured, authenticated, &id, &state);
        assert_eq!(
            state["deliveries"][0]["status"],
            if successful {
                "delivered"
            } else {
                "delivery_unknown"
            }
        );
        let expected_receipt = if successful {
            (
                StatusCode::OK,
                json!({"transaction_id":id,"credential_id":state["credentials"][0]["id"],
                "holder_did":HOLDER,"service_endpoint":graph.endpoint,"didcomm_message_id":message,"status":"delivered","error":null}),
            )
        } else {
            (
                StatusCode::CONFLICT,
                json!({"detail":"DIDComm delivery outcome requires reconciliation"}),
            )
        };
        for _ in 0..2 {
            assert_eq!(direct_response(&direct, &id).await, expected_receipt);
        }
    }
    if successful {
        let mut expected_source = source_before.clone();
        let row = &source_after["credentials"][0];
        let issued_at =
            chrono::DateTime::parse_from_rfc3339(row["issued_at"].as_str().unwrap()).unwrap();
        for key in ["status_updated_at", "revoked_at"] {
            let actual = chrono::DateTime::parse_from_rfc3339(row[key].as_str().unwrap()).unwrap();
            assert!(
                actual >= issued_at,
                "renewal timestamp follows source issuance"
            );
            expected_source["credentials"][0][key] = row[key].clone();
        }
        expected_source["credentials"][0]["status"] = json!("revoked");
        expected_source["credentials"][0]["revoked"] = json!(true);
        expected_source["credentials"][0]["revocation_reason"] =
            json!("Superseded by renewed credential");
        expected_source["credentials"][0]["renewed_to_credential_id"] =
            state["credentials"][0]["id"].clone();
        assert_eq!(
            source_after, expected_source,
            "only actual renewal finalizer source fields change"
        );
        assert_eq!(
            state["credentials"][0]["renewed_from_credential_id"],
            source
        );
        assert_eq!(state["events"].as_array().unwrap().len(), 1);
        assert_eq!(
            state["events"][0]["application_id"],
            format!("application-{id}")
        );
        assert_eq!(state["events"][0]["event_type"], "credential_issued");
        assert_eq!(
            *graph.publications.lock().unwrap(),
            vec![
                json!({"organization_id":ORGANIZATION,"credential_id":source,"index":7,"status":"revoked","credential_format":"sd_jwt_vc","reason":"Superseded by renewed credential"})
            ]
        );
    } else {
        assert_eq!(
            source_after, source_before,
            "no durable source finalization without accepted delivery"
        );
        assert_eq!(state["events"], json!([]));
        if scenario == Scenario::Refused {
            // Existing issuance records this reverse prelink before transport;
            // it does not mean the unchanged active source was superseded.
            assert_eq!(
                state["credentials"][0]["renewed_from_credential_id"],
                source
            );
        }
        assert!(graph.publications.lock().unwrap().is_empty());
    }
    // Typed reservation/projector replay is NOT another unkeyed renewal HTTP request.
    let reservation = InitiationReservation {
        transaction: graph
            .repository
            .transaction_by_id(&id)
            .await
            .unwrap()
            .unwrap(),
        created: false,
    };
    let projected = projector
        .project(reservation.clone(), &request)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(&projected).unwrap(),
        json!({
            "id":id,"organization_id":ORGANIZATION,"credential_template_id":"didcomm-template",
            "status":if scenario == Scenario::MissingHolder {"pending"} else {"issued"},
            "credential_offer_uri":response["credential_offer_uri"],
            "credential_offer_uris":response["credential_offer_uris"],
            "credential_offer_labels":response["credential_offer_labels"],
            "pre_auth_code":format!("pre-auth-{id}"),"expires_at":response["expires_at"]
        })
    );
    for _ in 0..2 {
        assert_eq!(
            projector
                .project(reservation.clone(), &request)
                .await
                .unwrap(),
            projected
        );
    }
    assert_eq!(
        snapshot(pool, &id).await,
        state,
        "all successor rows stable under recovery"
    );
    assert_eq!(
        snapshot(pool, &format!("source-tx-{id}")).await,
        source_after
    );
    assert_eq!(
        graph.wallet.captures().await,
        captured,
        "no resend on direct/projector recovery"
    );
    assert_eq!(
        graph.allocations.load(Ordering::SeqCst),
        usize::from(scenario != Scenario::MissingHolder)
    );
    assert_eq!(
        graph.builder.calls.load(Ordering::SeqCst),
        usize::from(scenario != Scenario::MissingHolder)
    );
    assert_eq!(
        graph.publications.lock().unwrap().len(),
        usize::from(successful)
    );
    assert_eq!(
        graph.resolutions.load(Ordering::SeqCst),
        if scenario == Scenario::MissingHolder {
            0
        } else if authenticated {
            2
        } else {
            1
        }
    );
    if let Some(fixture) = gateway.as_mut() {
        assert_eq!(fixture.counts(), (1, 1));
        assert_eq!(fixture.owner_count(), 4);
        fixture.assert_unreachable_without_legacy_fallback().await;
    }
    if let Some(fixture) = gateway {
        fixture.close().await;
    }
    graph.peers.close().await;
    graph.wallet.close_verified();
}

pub(super) async fn run(pool: &PgPool, gateway: bool) {
    for authenticated in [false, true] {
        for scenario in [
            Scenario::Automatic,
            Scenario::Refused,
            Scenario::MissingHolder,
            Scenario::OrdinaryThenDirect,
        ] {
            run_case(pool, authenticated, scenario, gateway).await;
        }
    }
}
