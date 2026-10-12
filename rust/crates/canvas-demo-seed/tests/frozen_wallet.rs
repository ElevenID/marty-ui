use async_trait::async_trait;
use axum::{http::HeaderMap, routing::post, Json, Router};
use marty_canvas_demo_seed::{
    claim_wallet_credential, CanonicalWalletProof, GatewaySeedConfig, WalletOperation, WalletProof,
    WalletTransport,
};
use serde_json::{json, Map, Value};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

struct Stub {
    responses: Mutex<VecDeque<Value>>,
    operations: Mutex<Vec<Value>>,
    proofs: Mutex<Vec<Value>>,
}

#[async_trait]
impl WalletTransport for Stub {
    async fn request(&self, operation: WalletOperation) -> Result<Value, String> {
        let form = operation.form.map(|pairs| {
            Value::Object(
                pairs
                    .into_iter()
                    .map(|(key, value)| (key, Value::String(value)))
                    .collect::<Map<_, _>>(),
            )
        });
        let headers = operation
            .bearer
            .map(|token| json!({"Authorization": format!("Bearer {token}")}));
        let mut row = json!({
            "method": operation.method,
            "url": operation.url,
            "headers": headers,
            "timeout": operation.timeout_seconds,
        });
        if let Some(form) = form {
            row["form"] = form;
        } else {
            row["payload"] = operation.json.unwrap_or(Value::Null);
        }
        self.operations.lock().unwrap().push(row);
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .ok_or("unexpected wallet request".into())
    }
}

#[async_trait]
impl WalletProof for Stub {
    async fn create_proof_jwt(&self, audience: &str, nonce: &str) -> Result<String, String> {
        self.proofs
            .lock()
            .unwrap()
            .push(json!({"audience": audience, "nonce": nonce}));
        Ok("signed-proof".into())
    }
}

fn config() -> GatewaySeedConfig {
    GatewaySeedConfig {
        base_url: "http://localhost:8000".into(),
        organization_id: "org-1".into(),
        canvas_account_id: "account-1".into(),
        credential_template_id: "ct-1".into(),
        application_template_id: "at-1".into(),
        display_name: "Canvas Demo".into(),
        canvas_base_url: "https://canvas.example".into(),
        lti_client_id: "client-1".into(),
        lti_deployment_id: "deployment-1".into(),
        probe_after_upsert: false,
        program_binding_display_name: "Program Demo".into(),
        program_binding_evidence_type: "canvas.quiz_score".into(),
        program_binding_delivery_mode: "wallet_plus_canvas_mirror".into(),
        program_binding_auto_approve: true,
        program_binding_direct_issue: false,
        program_binding_score_threshold: 80,
        signing_keys_internal_base_url: "http://signing-keys:8000".into(),
        badge_vct:
            "https://beta.elevenidllc.com/credentials/canvas-interoperability-foundations-badge"
                .into(),
    }
}

#[tokio::test]
async fn claim_sequence_matches_frozen_python_behavior() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-real-seed-behavior-v1.json"
    ))
    .unwrap();
    let stub = Stub {
        responses: Mutex::new(VecDeque::from(vec![
            json!({"grants": {"urn:ietf:params:oauth:grant-type:pre-authorized_code": {"pre-authorized_code": "offer-code"}}}),
            json!({"access_token": "test-access-token", "c_nonce": "test-nonce"}),
            json!({"credential": "header.payload.signature", "notification_id": "notify-1"}),
        ])),
        operations: Mutex::new(Vec::new()),
        proofs: Mutex::new(Vec::new()),
    };
    let result = claim_wallet_credential(&stub, &stub, &config(), "https://marty.example/", "tx-1")
        .await
        .unwrap();
    assert_eq!(result, contract["wallet_claim"]["result"]);
    assert_eq!(
        *stub.operations.lock().unwrap(),
        *contract["wallet_claim"]["operations"].as_array().unwrap()
    );
    assert_eq!(
        *stub.proofs.lock().unwrap(),
        *contract["wallet_claim"]["proofs"].as_array().unwrap()
    );
}

#[tokio::test]
async fn missing_offer_code_fails_before_token_request() {
    let stub = Stub {
        responses: Mutex::new(VecDeque::from(vec![json!({"grants": {}})])),
        operations: Mutex::new(Vec::new()),
        proofs: Mutex::new(Vec::new()),
    };
    assert!(claim_wallet_credential(&stub, &stub, &config(), "", "tx-1")
        .await
        .is_err());
    assert_eq!(stub.operations.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn canonical_proof_uses_the_signing_service_kms_boundary() {
    let captured = Arc::new(Mutex::new(None));
    let app = Router::new().route(
        "/internal/vc-api/holder-proof",
        post({
            let captured = Arc::clone(&captured);
            move |headers: HeaderMap, Json(body): Json<Value>| {
                let captured = Arc::clone(&captured);
                async move {
                    *captured.lock().unwrap() = Some(json!({
                        "api_key": headers.get("x-api-key").unwrap().to_str().unwrap(),
                        "body": body,
                    }));
                    Json(json!({"proof_jwt": "kms-signed-proof"}))
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let proof = CanonicalWalletProof::new(
        &format!("http://{address}/internal/signing-keys"),
        "internal-test-key",
        "org-1",
    )
    .unwrap();
    assert_eq!(
        proof
            .create_proof_jwt("https://issuer.example/org/org-1", "nonce-1")
            .await
            .unwrap(),
        "kms-signed-proof"
    );
    assert_eq!(
        *captured.lock().unwrap(),
        Some(json!({
            "api_key": "internal-test-key",
            "body": {
                "organization_id": "org-1",
                "issuer_url": "https://issuer.example/org/org-1",
                "nonce": "nonce-1"
            }
        }))
    );
    server.abort();
}
