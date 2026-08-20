use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, TimeZone, Utc};
use marty_flow::{
    build_standard_request_object, FlowInstanceRecord, FlowProviderError, FlowProviderRegistry,
    SigningIdentity, SigningIdentityProvider, SigningRequest, SigningResult,
};
use marty_oid4vci::presentation_request::PresentationRequestArtifacts;
use marty_verification::flow::FlowInstanceStatus;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    identity_binding: Vec<String>,
    private_key_access: String,
    signing_input: String,
    oid4vp_response_mode: String,
    oid4vp_query: String,
    siop_response_type: String,
    siop_scope: String,
    request_content_type: String,
    mip_message_type: String,
    url_query_request_object: String,
    haip_before_encryption_composition: String,
    identity_change: String,
}

#[derive(Clone, Default)]
struct Signing {
    requests: Arc<Mutex<Vec<SigningRequest>>>,
    wrong_did: bool,
}

#[async_trait]
impl SigningIdentityProvider for Signing {
    async fn resolve(
        &self,
        organization_id: &str,
        issuer_did: &str,
        key_purpose: &str,
        credential_format: &str,
        _algorithm: Option<&str>,
    ) -> Result<SigningIdentity, FlowProviderError> {
        let issuer_did = if self.wrong_did {
            "did:web:other.example"
        } else {
            issuer_did
        };
        Ok(SigningIdentity {
            organization_id: organization_id.into(),
            issuer_did: issuer_did.into(),
            verification_method_id: format!("{issuer_did}#key-1"),
            public_jwk: BTreeMap::from([
                ("kty".into(), json!("EC")),
                ("crv".into(), json!("P-256")),
                ("x".into(), json!("x")),
                ("y".into(), json!("y")),
            ]),
            key_purpose: key_purpose.into(),
            credential_format: credential_format.into(),
            algorithm: "ES256".into(),
        })
    }

    async fn sign(&self, request: &SigningRequest) -> Result<SigningResult, FlowProviderError> {
        self.requests.lock().unwrap().push(request.clone());
        Ok(SigningResult {
            issuer_did: request.issuer_did.clone(),
            verification_method_id: request.verification_method_id.clone(),
            algorithm: request.algorithm.clone(),
            signature_raw_b64url: "c2lnbmF0dXJl".into(),
        })
    }
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0).unwrap()
}

fn instance(flow_type: &str) -> FlowInstanceRecord {
    FlowInstanceRecord {
        id: "instance-1".into(),
        flow_definition_id: "definition-1".into(),
        organization_id: "org-1".into(),
        status: FlowInstanceStatus::AwaitingWallet,
        current_step_id: None,
        context: json!({
            "flow_type": flow_type,
            "nonce": "nonce-with-at-least-32-bytes-1234567890",
            "oid4vp_issuer_did": "did:web:verifier.example",
            "presentation_policy_id": "policy-1",
            "request_transport": "request_uri"
        }),
        step_history: Vec::new(),
        state_history: Vec::new(),
        subject_id: None,
        subject_type: "holder".into(),
        external_reference: None,
        application_flow_key_hash: None,
        started_at: Some(now()),
        completed_at: None,
        expires_at: Some(now() + Duration::minutes(15)),
        result: None,
        error: None,
        created_at: now(),
        updated_at: now(),
    }
}

fn payload(compact: &str) -> Value {
    let encoded = compact.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap()
}

#[tokio::test]
async fn language_neutral_contract_builds_oid4vp_and_siop_request_objects() {
    let contract: Contract = serde_json::from_str(include_str!(
        "../../../../contracts/flow-request-object-behavior.json"
    ))
    .unwrap();
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.identity_binding.len(), 5);
    assert_eq!(contract.private_key_access, "signing_provider_only");
    assert_eq!(
        contract.signing_input,
        "base64url(protected).base64url(payload)"
    );
    assert_eq!(contract.oid4vp_response_mode, "direct_post");
    assert_eq!(contract.oid4vp_query, "dcql_query");
    assert_eq!(contract.siop_response_type, "id_token");
    assert_eq!(contract.siop_scope, "openid");
    assert_eq!(
        contract.request_content_type,
        "application/oauth-authz-req+jwt"
    );
    assert_eq!(contract.mip_message_type, "PresentationRequest");
    assert_eq!(contract.url_query_request_object, "rejected");
    assert_eq!(contract.haip_before_encryption_composition, "rejected");
    assert_eq!(contract.identity_change, "fail_closed");

    let signing = Signing::default();
    let providers = FlowProviderRegistry {
        signing_identity: Some(Arc::new(signing.clone())),
        ..Default::default()
    };
    let artifacts = PresentationRequestArtifacts {
        presentation_definition: json!({"id": "pd-1"}),
        dcql_query: json!({"credentials": [{"id": "member", "format": "dc+sd-jwt"}]}),
    };
    let oid4vp = build_standard_request_object(
        &providers,
        instance("verification"),
        Some(&artifacts),
        "https://verifier.example",
        None,
        Some("wallet-nonce"),
        now(),
    )
    .await
    .unwrap();
    let oid4vp_payload = payload(&oid4vp.compact_jwt);
    assert_eq!(oid4vp_payload["response_type"], "vp_token");
    assert_eq!(oid4vp_payload["response_mode"], "direct_post");
    assert_eq!(oid4vp_payload["dcql_query"], artifacts.dcql_query);
    assert_eq!(oid4vp_payload["wallet_nonce"], "wallet-nonce");
    assert_eq!(
        oid4vp.instance.context["mip_messages"]["presentation_request"]["message_type"],
        contract.mip_message_type
    );

    let siop = build_standard_request_object(
        &providers,
        instance("siop_v2"),
        None,
        "https://verifier.example",
        Some("https://verifier.example/client"),
        None,
        now(),
    )
    .await
    .unwrap();
    let siop_payload = payload(&siop.compact_jwt);
    assert_eq!(siop_payload["response_type"], "id_token");
    assert_eq!(siop_payload["scope"], "openid");
    assert_eq!(
        siop_payload["redirect_uri"],
        "https://verifier.example/v1/flows/siop/submit"
    );
    assert_eq!(signing.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn unsupported_transport_and_changed_identity_fail_closed() {
    let mut url_query = instance("verification");
    url_query.context["request_transport"] = json!("url_query");
    let providers = FlowProviderRegistry {
        signing_identity: Some(Arc::new(Signing::default())),
        ..Default::default()
    };
    assert!(build_standard_request_object(
        &providers,
        url_query,
        None,
        "https://verifier.example",
        None,
        None,
        now()
    )
    .await
    .is_err());

    let changed = FlowProviderRegistry {
        signing_identity: Some(Arc::new(Signing {
            wrong_did: true,
            ..Default::default()
        })),
        ..Default::default()
    };
    assert!(build_standard_request_object(
        &changed,
        instance("siop_v2"),
        None,
        "https://verifier.example",
        None,
        None,
        now()
    )
    .await
    .is_err());
}
