//! Fresh automatic HTTP and direct replay on the already-running rendered graph.
//! The prior renewal gate has independently checked its full signed credential.
use super::{
    base_runtime_gateway::GatewayFixture,
    didcomm_wallet_fixture::WalletFixture,
    issuance_named_peers::{PeerState, CLIENT_KEY, FORMAT, HOLDER, ISSUER, ORGANIZATION, TEMPLATE},
    renewal_fresh_main::{assert_offer, stored},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};

async fn replay(pool: &sqlx::PgPool, gateway: &GatewayFixture, id: &str, endpoint: &str) {
    let before = stored(pool, id).await;
    let response = gateway
        .client
        .post(format!("{}/v1/issuance/didcomm/deliver", gateway.origin))
        .header("x-api-key", CLIENT_KEY)
        .json(&json!({"organization_id":ORGANIZATION,"transaction_id":id,"holder_did":HOLDER}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.json::<Value>().await.unwrap(),
        json!({
            "transaction_id":id,"credential_id":before["credentials"][0]["id"],
            "holder_did":HOLDER,"service_endpoint":endpoint,
            "didcomm_message_id":before["deliveries"][0]["metadata"]["didcomm_message_id"],
            "status":"delivered","error":null
        })
    );
    assert_eq!(
        stored(pool, id).await,
        before,
        "direct replay must preserve all four scoped tables"
    );
}

pub(super) struct Input<'a> {
    pub(super) pool: &'a sqlx::PgPool,
    pub(super) gateway: &'a GatewayFixture,
    pub(super) peers: &'a PeerState,
    pub(super) wallet: &'a WalletFixture,
    pub(super) authenticated: bool,
    pub(super) recipient_secret: &'a [u8; 32],
    pub(super) renewal_id: &'a str,
}

pub(super) async fn run(input: Input<'_>) {
    let Input {
        pool,
        gateway,
        peers,
        wallet,
        authenticated,
        recipient_secret,
        renewal_id,
    } = input;
    let endpoint = format!("{}/inbox", wallet.origin);
    let before = wallet.captures().await;
    assert_eq!(before["messages"].as_array().unwrap().len(), 1);
    replay(pool, gateway, renewal_id, &endpoint).await;
    assert_eq!(wallet.captures().await, before);
    assert_eq!(peers.signed.lock().unwrap().len(), 1);

    let body = json!({"organization_id":ORGANIZATION,"credential_template_id":TEMPLATE,"issuer_did":ISSUER,"holder_did":HOLDER,"claims":{"given_name":"Synthetic"}});
    // This request is intentionally unkeyed: DIDComm automatic initiation is not
    // made idempotent by repeating an admission request.
    let response = gateway
        .client
        .post(format!("{}/v1/issuance/initiate", gateway.origin))
        .header("x-api-key", CLIENT_KEY)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let response: Value = response.json().await.unwrap();
    let id = response["id"].as_str().unwrap();
    assert_ne!(id, renewal_id);
    let state = stored(pool, id).await;
    assert_offer(
        response["credential_offer_uri"].as_str().unwrap(),
        &state["transaction"]["pre_auth_code"],
    );
    assert_eq!(
        response,
        json!({"id":id,"organization_id":ORGANIZATION,"credential_template_id":TEMPLATE,
        "status":"issued","credential_offer_uri":response["credential_offer_uri"],
        "credential_offer_uris":{"didcomm":format!("didcomm://{endpoint}")},
        "credential_offer_labels":{"didcomm":"Synthetic Wallet"},
        "pre_auth_code":state["transaction"]["pre_auth_code"],"expires_at":response["expires_at"]})
    );
    assert_eq!(
        response["expires_at"]
            .as_str()
            .unwrap()
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap(),
        state["transaction"]["expires_at"]
            .as_str()
            .unwrap()
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap()
    );
    assert_eq!(state["transaction"]["status"], "issued");
    assert!(state["transaction"]["renewal_of_credential_id"].is_null());
    assert_eq!(state["credentials"].as_array().unwrap().len(), 1);
    assert_eq!(state["deliveries"].as_array().unwrap().len(), 1);
    assert_eq!(state["deliveries"][0]["status"], "delivered");
    assert_eq!(state["events"].as_array().unwrap().len(), 1);
    assert_eq!(state["events"][0]["event_type"], "credential_issued");
    let captures = wallet.captures().await;
    assert_eq!(captures["failures"], 0);
    assert_eq!(captures["messages"].as_array().unwrap().len(), 2);
    let encrypted = captures["messages"][1].as_str().unwrap();
    let plaintext = if authenticated {
        let envelope = marty_didcomm::decrypt_authenticated_jwe(
            encrypted,
            recipient_secret,
            &peers.recipient,
            &peers.sender,
        )
        .unwrap();
        assert_eq!(envelope.sender_kid, format!("{ISSUER}#key-1"));
        envelope.plaintext
    } else {
        marty_didcomm::decrypt_jwe(encrypted, recipient_secret).unwrap()
    };
    let message = marty_didcomm::unpack_didcomm_message(&plaintext).unwrap();
    assert_eq!(message.thid.as_deref(), Some(id));
    assert_eq!(message.from.as_deref(), Some(ISSUER));
    assert_eq!(message.to, Some(vec![HOLDER.into()]));
    assert_eq!(
        message.r#type,
        "https://didcomm.org/issue-credential/3.0/issue-credential"
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
    let credential = URL_SAFE_NO_PAD
        .decode(attachment.data.base64.as_deref().unwrap())
        .unwrap();
    assert_eq!(
        credential,
        state["credentials"][0]["credential_jwt"]
            .as_str()
            .unwrap()
            .as_bytes()
    );
    let jws = std::str::from_utf8(&credential)
        .unwrap()
        .split('~')
        .next()
        .unwrap();
    let parts: Vec<_> = jws.split('.').collect();
    assert_eq!(parts.len(), 3);
    let signed = format!("{}.{}", parts[0], parts[1]);
    let signature =
        ed25519_dalek::Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
    peers
        .signer
        .verifying_key()
        .verify_strict(signed.as_bytes(), &signature)
        .unwrap();
    assert_eq!(peers.signed.lock().unwrap().len(), 2);
    replay(pool, gateway, id, &endpoint).await;
    assert_eq!(wallet.captures().await, captures);
    assert_eq!(peers.signed.lock().unwrap().len(), 2);
    assert_eq!(
        peers.publications.lock().unwrap().len(),
        1,
        "ordinary fresh issuance must not revoke another source"
    );
}
