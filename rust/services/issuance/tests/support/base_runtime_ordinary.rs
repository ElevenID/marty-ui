//! Actual gateway/native-process/PG ordinary admission and public token/nonce
//! paths. Named peers are the existing controlled fixture, not another graph.
//! Keyed retry is gateway/Redis replay; native early recovery is qualified by
//! didcomm_admission_recovery separately. Nonce consumption below is a direct
//! real repository check, not a claimed HTTP proof-validation endpoint.
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use marty_issuance_service::{
    ephemeral_postgres::PostgresProofNonceRepository,
    initiation::{idempotency_binding, InitiationRequest},
    proof_nonce::ProofNonceRepository,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use super::{
    base_runtime_gateway::GatewayFixture,
    issuance_named_peers::{PeerState, CLIENT_KEY, HOLDER, ISSUER, ORGANIZATION, TEMPLATE},
    renewal_fresh_main::{assert_offer, stored},
};

struct WalletMode {
    flag: Arc<AtomicBool>,
    original: bool,
}
impl WalletMode {
    fn ordinary(flag: Arc<AtomicBool>) -> Self {
        let original = flag.swap(true, Ordering::SeqCst);
        Self { flag, original }
    }
}
impl Drop for WalletMode {
    fn drop(&mut self) {
        self.flag.store(self.original, Ordering::SeqCst);
    }
}

fn auth_calls(peers: &PeerState) -> usize {
    peers
        .attempts
        .lock()
        .unwrap()
        .iter()
        .filter(|path| path.ends_with("/ValidateApiKey"))
        .count()
}

fn effects(peers: &PeerState) -> Value {
    json!({"signed":*peers.signed.lock().unwrap(), "allocations":*peers.allocations.lock().unwrap(), "publications":*peers.publications.lock().unwrap()})
}

async fn transaction_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM issuance_service.issuance_transactions")
        .fetch_one(pool)
        .await
        .unwrap()
}

fn frozen_case<'a>(contract: &'a Value, section: &str, name: &str) -> &'a Value {
    contract[section]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap()
}

fn assert_mip(body: Value, expected: &Value) {
    let id = body["message_id"].as_str().unwrap();
    assert!(uuid::Uuid::parse_str(id).is_ok());
    let mut expected = expected.clone();
    expected["message_id"] = json!(id);
    assert_eq!(body, expected);
}

pub(super) async fn run(pool: &PgPool, gateway: &GatewayFixture, peers: &PeerState) {
    let _wallet_mode = WalletMode::ordinary(peers.ordinary_wallets.clone());
    let initial_effects = effects(peers);
    let initial_count = transaction_count(pool).await;
    // The outer fixture retains one real Redis DB across both crypto modes.
    // Distinct source IDs give each invocation a genuinely fresh cache key.
    let key = format!("base-ordinary:{}", peers.source_id);
    let request = json!({"organization_id":ORGANIZATION,"credential_template_id":TEMPLATE,
        "issuer_did":ISSUER,"subject_did":HOLDER,"holder_did":HOLDER,"claims":{"given_name":"Ordinary"}});
    let before = Utc::now();
    let response = gateway
        .client
        .post(format!("{}/v1/issuance/initiate", gateway.origin))
        .header("x-api-key", CLIENT_KEY)
        .header("idempotency-key", &key)
        .json(&request)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body: Value = response.json().await.unwrap();
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "ordinary admission: {body}"
    );
    let after = Utc::now();
    let id = body["id"].as_str().unwrap();
    assert!(uuid::Uuid::parse_str(id).is_ok());
    let reserved = stored(pool, id).await;
    let transaction = &reserved["transaction"];
    assert_eq!(transaction["id"], id);
    assert_eq!(transaction["organization_id"], ORGANIZATION);
    assert_eq!(transaction["credential_template_id"], TEMPLATE);
    assert_eq!(transaction["issuer_did_override"], ISSUER);
    assert_eq!(transaction["subject_did"], HOLDER);
    assert_eq!(transaction["status"], "pending");
    assert_eq!(
        transaction["claims"],
        json!({"given_name":"Ordinary","_vct":"https://issuer.example/credentials/EmployeeCredential"})
    );
    let expiry: DateTime<Utc> = transaction["expires_at"].as_str().unwrap().parse().unwrap();
    assert!(
        (before + Duration::minutes(10080)..=after + Duration::minutes(10080)).contains(&expiry)
    );
    assert_eq!(
        body["expires_at"]
            .as_str()
            .unwrap()
            .parse::<DateTime<Utc>>()
            .unwrap(),
        expiry
    );
    assert_eq!(
        body,
        json!({"id":id,"organization_id":ORGANIZATION,"credential_template_id":TEMPLATE,
        "status":"pending","credential_offer_uri":body["credential_offer_uri"],
        "credential_offer_uris":{},"credential_offer_labels":{},"pre_auth_code":transaction["pre_auth_code"],
        "expires_at":body["expires_at"]})
    );
    assert_offer(
        body["credential_offer_uri"].as_str().unwrap(),
        &transaction["pre_auth_code"],
    );
    assert!(!body["pre_auth_code"].as_str().unwrap().is_empty());
    for collection in ["credentials", "deliveries", "events"] {
        assert_eq!(reserved[collection], json!([]));
    }
    // Shared binding owner is independently frozen by issuance-initiation.json;
    // here its real durable consumer is compared with the exact submitted DTO.
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/issuance-initiation.json"
    ))
    .unwrap();
    let vector = &contract["idempotency"]["vector"];
    let vector_request: InitiationRequest =
        serde_json::from_value(vector["request"].clone()).unwrap();
    let vector_binding = idempotency_binding(vector["key"].as_str(), &vector_request)
        .unwrap()
        .unwrap();
    assert_eq!(vector_binding.key_hash, vector["key_hash"]);
    assert_eq!(vector_binding.request_hash, vector["request_hash"]);
    let typed: InitiationRequest = serde_json::from_value(request.clone()).unwrap();
    let binding = idempotency_binding(Some(&key), &typed).unwrap().unwrap();
    assert_eq!(transaction["idempotency_key_hash"], binding.key_hash);
    assert_eq!(
        transaction["idempotency_request_hash"],
        binding.request_hash
    );
    assert_eq!(transaction_count(pool).await, initial_count + 1);
    assert_eq!(effects(peers), initial_effects);

    // The real gateway owns this replay and conflict before a second native
    // admission; do not label it native repository recovery.
    let replay = gateway
        .client
        .post(format!("{}/v1/issuance/initiate", gateway.origin))
        .header("x-api-key", CLIENT_KEY)
        .header("idempotency-key", &key)
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), reqwest::StatusCode::OK);
    assert_eq!(replay.json::<Value>().await.unwrap(), body);
    assert_eq!(stored(pool, id).await, reserved);
    let mut conflicting = request.clone();
    conflicting["claims"]["given_name"] = json!("Changed");
    let conflict = gateway
        .client
        .post(format!("{}/v1/issuance/initiate", gateway.origin))
        .header("x-api-key", CLIENT_KEY)
        .header("idempotency-key", &key)
        .json(&conflicting)
        .send()
        .await
        .unwrap();
    assert_eq!(conflict.status(), reqwest::StatusCode::CONFLICT);
    assert_mip(
        conflict.json().await.unwrap(),
        &json!({"error":"idempotency_conflict","error_description":"Idempotency key was reused for another request"}),
    );
    assert_eq!(stored(pool, id).await, reserved);
    assert_eq!(transaction_count(pool).await, initial_count + 1);
    assert_eq!(effects(peers), initial_effects);

    let public_auth_before = auth_calls(peers);
    let token_contract: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/issuance-token-exchange.json"
    ))
    .unwrap();
    let token_case = frozen_case(&token_contract, "cases", "pre_authorized_code_success");
    let form = [
        (
            "grant_type",
            token_contract["inputs"]["pre_authorized_grant"]
                .as_str()
                .unwrap(),
        ),
        (
            "pre-authorized_code",
            body["pre_auth_code"].as_str().unwrap(),
        ),
    ];
    let response = gateway
        .client
        .post(format!(
            "{}{}",
            gateway.origin,
            token_contract["inputs"]["path"].as_str().unwrap()
        ))
        .form(&form)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status().as_u16(),
        token_case["status_code"].as_u64().unwrap() as u16
    );
    let token: Value = response.json().await.unwrap();
    let clear = token["access_token"].as_str().unwrap();
    assert!(!clear.is_empty());
    let mut expected = token_case["body"].clone();
    expected["access_token"] = json!(clear);
    assert_eq!(token, expected);
    let mut hmac = Hmac::<Sha256>::new_from_slice(b"synthetic-fresh-main-hmac").unwrap();
    hmac.update(clear.as_bytes());
    let digest = hex::encode(hmac.finalize().into_bytes());
    let mut authorized = reserved.clone();
    authorized["transaction"]["status"] = json!("authorized");
    authorized["transaction"]["access_token"] = json!(digest);
    authorized["transaction"]["c_nonce"] = Value::Null;
    assert_eq!(stored(pool, id).await, authorized);
    assert_ne!(authorized["transaction"]["access_token"], clear);
    let replay = gateway
        .client
        .post(format!(
            "{}{}",
            gateway.origin,
            token_contract["inputs"]["path"].as_str().unwrap()
        ))
        .form(&form)
        .send()
        .await
        .unwrap();
    let refused = frozen_case(
        &token_contract,
        "failures",
        "pre_authorized_code_is_single_use",
    );
    assert_eq!(
        replay.status().as_u16(),
        refused["status_code"].as_u64().unwrap() as u16
    );
    assert_mip(replay.json().await.unwrap(), &refused["body"]);
    assert_eq!(stored(pool, id).await, authorized);

    let nonce_contract: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/issuance-proof-nonce.json"
    ))
    .unwrap();
    let nonce = gateway
        .client
        .post(format!(
            "{}{}",
            gateway.origin,
            nonce_contract["inputs"]["path"].as_str().unwrap()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(nonce.status(), reqwest::StatusCode::OK);
    assert_eq!(nonce.headers()["cache-control"], "no-store");
    let nonce: Value = nonce.json().await.unwrap();
    let clear = nonce["c_nonce"].as_str().unwrap();
    assert_eq!(
        nonce_contract["nonce_shape"]["pattern"],
        "^[A-Za-z0-9_-]{43}$"
    );
    assert_eq!(nonce_contract["nonce_shape"]["encoded_length"], 43);
    assert_eq!(clear.len(), 43);
    assert!(clear
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')));
    assert_eq!(nonce, json!({"c_nonce":clear}));
    let digest = format!("{:x}", Sha256::digest(clear.as_bytes()));
    let capability: Value = sqlx::query_scalar("SELECT to_jsonb(c) FROM issuance_service.oid4vci_ephemeral_capabilities c WHERE purpose='proof_nonce' AND key_digest=$1")
        .bind(&digest).fetch_one(pool).await.unwrap();
    let created: DateTime<Utc> = capability["created_at"].as_str().unwrap().parse().unwrap();
    let expires: DateTime<Utc> = capability["expires_at"].as_str().unwrap().parse().unwrap();
    assert!(
        (expires - created - Duration::seconds(300))
            .num_milliseconds()
            .abs()
            < 100
    );
    assert_eq!(
        capability,
        json!({"purpose":"proof_nonce","key_digest":digest,"payload":null,"created_at":capability["created_at"],"expires_at":capability["expires_at"]})
    );
    let repository = PostgresProofNonceRepository::new(pool.clone());
    assert!(repository.consume_proof_nonce(clear).await.unwrap());
    assert!(!repository.consume_proof_nonce(clear).await.unwrap());
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM issuance_service.oid4vci_ephemeral_capabilities WHERE purpose='proof_nonce' AND key_digest=$1").bind(&digest).fetch_one(pool).await.unwrap();
    assert_eq!(remaining, 0);

    let discovery: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/issuance-static-discovery.json"
    ))
    .unwrap();
    for operation in ["get_as_metadata", "get_issuer_metadata_root"] {
        let case = discovery["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["operation"] == operation)
            .unwrap();
        let response = gateway
            .client
            .get(format!(
                "{}{}",
                gateway.origin,
                case["path"].as_str().unwrap()
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let mut expected = case["body"].clone();
        if operation == "get_issuer_metadata_root" {
            // Base profile exports no display override; native config.rs default
            // is independently ElevenID LLC, not the reference fixture's label.
            expected["display"][0]["name"] = json!("ElevenID LLC");
        }
        assert_eq!(response.json::<Value>().await.unwrap(), expected);
    }
    assert_eq!(
        auth_calls(peers),
        public_auth_before,
        "public endpoints require no client API-key authentication"
    );
    assert_eq!(stored(pool, id).await, authorized);
    assert_eq!(transaction_count(pool).await, initial_count + 1);
    assert_eq!(effects(peers), initial_effects);
}
