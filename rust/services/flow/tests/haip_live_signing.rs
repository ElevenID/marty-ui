use std::{env, fs, sync::Arc};

use chrono::Utc;
use marty_flow::{
    decrypt_verification_response, FlowInstanceRecord, FlowKeyEnvelopeProvider,
    FlowProviderRegistry, FlowVerificationSubmissionError, HttpSigningProvider,
};
use marty_verification::flow::FlowInstanceStatus;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct HolderInput {
    organization_id: String,
    flow_instance_id: String,
    key_reference: String,
    public_jwk: Value,
    jwe: String,
    plaintext: String,
}

#[tokio::test]
async fn live_flow_decrypts_go_holder_response_through_signing_keys() {
    let (path, base_url, api_key) = (
        env::var("MARTY_TEST_HAIP_FLOW_INPUT"),
        env::var("MARTY_TEST_SIGNING_KEYS_URL"),
        env::var("MARTY_TEST_SIGNING_KEYS_API_KEY"),
    );
    if path.is_err() && base_url.is_err() && api_key.is_err() {
        eprintln!("skipped: requires live HAIP input and the Rust signing-keys service");
        return;
    }
    let (path, base_url, api_key) = (path.unwrap(), base_url.unwrap(), api_key.unwrap());
    let input: HolderInput = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let provider = HttpSigningProvider::new(&format!("{base_url}/internal/"), &api_key).unwrap();
    let remote = provider
        .create_haip_key(&input.organization_id, &input.flow_instance_id)
        .await
        .unwrap();
    assert_eq!(remote.key_reference, input.key_reference);
    assert_eq!(remote.public_jwk, input.public_jwk);
    let version = marty_oid4vp_contract::haip_key::version_for(
        &input.key_reference,
        &input.organization_id,
        &input.flow_instance_id,
    )
    .unwrap();
    let resolved = provider
        .resolve_haip_key(&input.organization_id, &input.flow_instance_id, version)
        .await
        .unwrap();
    assert_eq!(resolved.key_reference, input.key_reference);
    assert_eq!(resolved.public_jwk, input.public_jwk);

    let now = Utc::now();
    let instance = FlowInstanceRecord {
        id: input.flow_instance_id.clone(),
        flow_definition_id: "haip-live-test".into(),
        organization_id: input.organization_id.clone(),
        status: FlowInstanceStatus::AwaitingWallet,
        current_step_id: None,
        context: json!({
            "haip_response_encryption_key_reference": input.key_reference,
            "haip_response_encryption_public_jwk": input.public_jwk,
        }),
        step_history: Vec::new(),
        state_history: Vec::new(),
        subject_id: None,
        subject_type: "holder".into(),
        external_reference: None,
        application_flow_key_hash: None,
        started_at: Some(now),
        completed_at: None,
        expires_at: None,
        result: None,
        error: None,
        created_at: now,
        updated_at: now,
    };
    let providers = FlowProviderRegistry {
        flow_key_envelope: Some(Arc::new(provider)),
        ..FlowProviderRegistry::default()
    };
    let plaintext: Value = serde_json::from_str(&input.plaintext).unwrap();
    assert_eq!(
        decrypt_verification_response(&providers, &instance, &input.jwe)
            .await
            .unwrap(),
        plaintext
    );

    let mut wrong_flow = instance;
    wrong_flow.id = "another-flow".into();
    assert!(matches!(
        decrypt_verification_response(&providers, &wrong_flow, &input.jwe).await,
        Err(FlowVerificationSubmissionError::InvalidEncryptedResponse)
    ));
}
