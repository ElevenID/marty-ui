#[path = "support/presentation_snapshot.rs"]
mod presentation_snapshot;

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
use chrono::{Duration, TimeZone, Utc};
use marty_flow::{
    prepare_verification_request, CredentialTemplateProvider, CredentialTemplateReference,
    FlowInstanceRecord, FlowKeyEnvelopeProvider, FlowProviderError, FlowProviderRegistry,
    FlowVerificationRequestError, PreparedVerificationRequest, PresentationEvaluationRequest,
    PresentationEvaluationResult, PresentationPolicyProvider, PresentationPolicyReference,
    RequestObjectCompatibility, SigningIdentity, SigningIdentityProvider, SigningRequest,
    SigningResult, VerificationRequestMethod, VerificationRequestRetrievalOptions,
    VerificationRequestTransport,
};
#[path = "support/haip_remote_fixture.rs"]
mod haip_remote_fixture;
use marty_verification::flow::FlowInstanceStatus;
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    allowed_states: Vec<String>,
    expired_transition: String,
    identity_resolution: String,
    post_request_uri: String,
    url_query_retrieval: String,
    compatibility_profiles: Vec<String>,
    transports: Vec<String>,
    dc_api_protocol: String,
    dc_api_response_mode: String,
    persistence: String,
    response_content_type: String,
    response_cache: String,
}

struct Policies;

#[async_trait]
impl PresentationPolicyProvider for Policies {
    async fn get_policy(
        &self,
        policy_id: &str,
    ) -> Result<PresentationPolicyReference, FlowProviderError> {
        Ok(PresentationPolicyReference {
            prerequisite_evidence_profile: None,
            credential_authority: None,
            policy_revision: presentation_snapshot::revision(policy_id),
            id: policy_id.into(),
            organization_id: "org-1".into(),
            status: "active".into(),
            credential_requirements: vec![json!({"credential_template_id": "template-1"})],
        })
    }

    async fn evaluate(
        &self,
        _request: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError> {
        unreachable!("request retrieval does not evaluate")
    }
}

struct Templates;

#[async_trait]
impl CredentialTemplateProvider for Templates {
    async fn get_template(
        &self,
        template_id: &str,
    ) -> Result<CredentialTemplateReference, FlowProviderError> {
        Ok(CredentialTemplateReference {
            id: template_id.into(),
            organization_id: "org-1".into(),
            status: "active".into(),
            credential_type: "MemberCredential".into(),
            vct: "https://credentials.example/member".into(),
            doctype: String::new(),
            supported_formats: vec!["dc+sd-jwt".into()],
            claims: Vec::new(),
            issuer_did: "did:web:issuer.example".into(),
            credential_format: "dc+sd-jwt".into(),
            issuance_protocol: "OID4VCI_PRE_AUTH".into(),
            wallet_configurations: Vec::new(),
            issuer_algorithm: Some("ES256".into()),
        })
    }

    async fn wallet_formats(
        &self,
        organization_id: &str,
    ) -> Result<Vec<String>, FlowProviderError> {
        assert_eq!(organization_id, "org-1");
        Ok(vec!["dc+sd-jwt".into()])
    }
}

#[derive(Default)]
struct Signing {
    resolutions: AtomicUsize,
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
        self.resolutions.fetch_add(1, Ordering::SeqCst);
        Ok(SigningIdentity {
            organization_id: organization_id.into(),
            issuer_did: issuer_did.into(),
            verification_method_id: format!("{issuer_did}#key-1"),
            signing_key_reference: "managed-key-1".into(),
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
        Ok(SigningResult {
            issuer_did: request.issuer_did.clone(),
            verification_method_id: request.verification_method_id.clone(),
            algorithm: request.algorithm.clone(),
            signature_raw_b64url: "c2lnbmF0dXJl".into(),
        })
    }
}

struct Envelopes;

#[async_trait]
impl FlowKeyEnvelopeProvider for Envelopes {
    async fn create_haip_key(
        &self,
        organization_id: &str,
        flow_instance_id: &str,
    ) -> Result<marty_flow::HaipRemoteKey, FlowProviderError> {
        Ok(haip_remote_fixture::key(organization_id, flow_instance_id))
    }
}

fn providers(signing: Arc<Signing>) -> FlowProviderRegistry {
    FlowProviderRegistry {
        presentation_policy: Some(Arc::new(Policies)),
        credential_template: Some(Arc::new(Templates)),
        signing_identity: Some(signing),
        flow_key_envelope: Some(Arc::new(Envelopes)),
        ..Default::default()
    }
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0).unwrap()
}

fn instance() -> FlowInstanceRecord {
    let mut instance = FlowInstanceRecord {
        id: "instance-1".into(),
        flow_definition_id: "definition-1".into(),
        organization_id: "org-1".into(),
        status: FlowInstanceStatus::AwaitingWallet,
        current_step_id: None,
        context: json!({
            "flow_type": "verification",
            "nonce": "nonce-with-at-least-32-bytes-1234567890",
            "oid4vp_issuer_did": "did:web:verifier.example",
            "oid4vp_client_id": "decentralized_identifier:did:web:verifier.example",
            "presentation_policy_id": "policy-1",
            "request_transport": "request_uri",
            "request_uri_method": "get"
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
    };
    presentation_snapshot::freeze_default(&mut instance);
    instance
}

#[tokio::test]
async fn frozen_managed_authority_cannot_be_retrieved_under_lissi_or_dc_api() {
    let signing = Arc::new(Signing::default());
    let ports = providers(signing.clone());
    let authority = presentation_snapshot::authority("org-1");
    let mut managed = instance();
    managed.context[presentation_snapshot::SNAPSHOT_KEY]["credential_authority"] = json!(authority);
    for options in [
        VerificationRequestRetrievalOptions {
            compatibility: RequestObjectCompatibility::Lissi,
            ..Default::default()
        },
        VerificationRequestRetrievalOptions {
            transport: VerificationRequestTransport::DigitalCredentialsApi,
            ..Default::default()
        },
    ] {
        assert!(prepare_verification_request(
            &ports,
            managed.clone(),
            "https://verifier.example",
            &options,
            now()
        )
        .await
        .is_err());
    }
    assert_eq!(signing.resolutions.load(Ordering::SeqCst), 0);
    let ready = prepare_verification_request(
        &ports,
        managed,
        "https://verifier.example",
        &Default::default(),
        now(),
    )
    .await
    .unwrap();
    let PreparedVerificationRequest::Ready(ready) = ready else {
        panic!("ready managed request")
    };
    assert_eq!(
        ready.instance.context[presentation_snapshot::SNAPSHOT_KEY]["credential_authority"],
        json!(authority)
    );
    assert!(
        ready.instance.context["mip_messages"]["presentation_request"]["payload"]["dcql_query"]
            .is_object()
    );
}

#[tokio::test]
async fn unfrozen_legacy_requests_require_restart_and_corrupt_snapshots_never_sign() {
    let signing = Arc::new(Signing::default());
    let ports = providers(signing.clone());
    let mut legacy = instance();
    legacy
        .context
        .as_object_mut()
        .unwrap()
        .remove(presentation_snapshot::SNAPSHOT_KEY);
    assert!(matches!(
        prepare_verification_request(
            &ports,
            legacy,
            "https://verifier.example",
            &Default::default(),
            now()
        )
        .await,
        Err(FlowVerificationRequestError::RestartRequired)
    ));
    for mutation in 0..6 {
        let mut altered = instance();
        match mutation {
            0 => altered.organization_id = "other-org".into(),
            1 => altered.id = "other-instance".into(),
            2 => altered.context["presentation_policy_id"] = json!("other-policy"),
            3 => altered.context["nonce"] = json!("other-nonce"),
            4 => {
                altered.context[presentation_snapshot::SNAPSHOT_KEY]["dcql_query"]["credentials"] =
                    json!([])
            }
            _ => {
                altered.context[presentation_snapshot::SNAPSHOT_KEY]["policy_revision"]["version"] =
                    json!(0)
            }
        }
        assert!(
            matches!(
                prepare_verification_request(
                    &ports,
                    altered,
                    "https://verifier.example",
                    &Default::default(),
                    now()
                )
                .await,
                Err(FlowVerificationRequestError::InvalidContext)
            ),
            "mutation {mutation}"
        );
    }
    assert_eq!(signing.resolutions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn language_neutral_retrieval_contract_is_preserved() {
    let contract: Contract = serde_json::from_str(include_str!(
        "../../../../contracts/flow-verification-request-behavior.json"
    ))
    .unwrap();
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.allowed_states, ["awaiting_wallet", "in_progress"]);
    assert!(contract.expired_transition.contains("request_expired"));
    assert_eq!(contract.identity_resolution, "every_fetch");
    assert_eq!(contract.post_request_uri, "wallet_nonce_required");
    assert_eq!(contract.url_query_retrieval, "rejected");
    assert_eq!(contract.compatibility_profiles, ["standard", "lissi"]);
    assert_eq!(contract.transports, ["request_uri", "dc_api"]);
    assert_eq!(contract.dc_api_protocol, "openid4vp-v1-signed");
    assert_eq!(contract.dc_api_response_mode, "dc_api.jwt");
    assert_eq!(
        contract.persistence,
        "status_and_updated_at_compare_and_set"
    );
    assert_eq!(
        contract.response_content_type,
        "application/oauth-authz-req+jwt"
    );
    assert_eq!(contract.response_cache, "no-store");

    let signing = Arc::new(Signing::default());
    let ready = prepare_verification_request(
        &providers(signing.clone()),
        instance(),
        "https://verifier.example",
        &VerificationRequestRetrievalOptions::default(),
        now(),
    )
    .await
    .unwrap();
    assert!(matches!(ready, PreparedVerificationRequest::Ready(_)));
    assert_eq!(signing.resolutions.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn expiry_post_nonce_and_unsigned_transport_fail_closed() {
    let signing = Arc::new(Signing::default());
    let mut expired = instance();
    expired.expires_at = Some(now() - Duration::seconds(1));
    let PreparedVerificationRequest::Expired(expired) = prepare_verification_request(
        &providers(signing.clone()),
        expired,
        "https://verifier.example",
        &VerificationRequestRetrievalOptions::default(),
        now(),
    )
    .await
    .unwrap() else {
        panic!("expired transition")
    };
    assert_eq!(expired.status, FlowInstanceStatus::Expired);
    assert_eq!(expired.error.as_deref(), Some("request_expired"));
    assert_eq!(expired.state_history[0]["event"], "request_expired");
    assert_eq!(signing.resolutions.load(Ordering::SeqCst), 0);

    let mut post = instance();
    post.context["request_uri_method"] = json!("post");
    assert!(prepare_verification_request(
        &providers(signing.clone()),
        post.clone(),
        "https://verifier.example",
        &VerificationRequestRetrievalOptions::default(),
        now(),
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("METHOD_NOT_ALLOWED"));
    assert!(prepare_verification_request(
        &providers(signing.clone()),
        post,
        "https://verifier.example",
        &VerificationRequestRetrievalOptions {
            method: VerificationRequestMethod::Post,
            ..Default::default()
        },
        now(),
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("WALLET_NONCE_REQUIRED"));

    let mut unsigned = instance();
    unsigned.context["request_transport"] = json!("url_query");
    assert!(prepare_verification_request(
        &providers(signing),
        unsigned,
        "https://verifier.example",
        &VerificationRequestRetrievalOptions::default(),
        now(),
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("UNSIGNED_TRANSPORT"));
}

#[tokio::test]
async fn post_wallet_nonce_and_dc_api_context_are_bound() {
    let signing = Arc::new(Signing::default());
    let mut post = instance();
    post.context["request_uri_method"] = json!("post");
    let ready = prepare_verification_request(
        &providers(signing.clone()),
        post,
        "https://verifier.example",
        &VerificationRequestRetrievalOptions {
            method: VerificationRequestMethod::Post,
            wallet_nonce: Some("wallet-nonce".into()),
            ..Default::default()
        },
        now(),
    )
    .await
    .unwrap();
    let PreparedVerificationRequest::Ready(ready) = ready else {
        panic!("ready request")
    };
    assert!(ready.compact_jwt.contains('.'));

    let dc_api = prepare_verification_request(
        &providers(signing),
        instance(),
        "https://verifier.example",
        &VerificationRequestRetrievalOptions {
            transport: VerificationRequestTransport::DigitalCredentialsApi,
            compatibility: RequestObjectCompatibility::Standard,
            request_object: marty_flow::RequestObjectOptions {
                expected_origins: vec!["https://verifier.example".into()],
                ..Default::default()
            },
            ..Default::default()
        },
        now(),
    )
    .await
    .unwrap();
    let PreparedVerificationRequest::Ready(dc_api) = dc_api else {
        panic!("ready dc api request")
    };
    assert_eq!(
        dc_api.instance.context["dc_api_response_mode"],
        "dc_api.jwt"
    );
    assert_eq!(
        dc_api.instance.context["dc_api_expected_origins"],
        json!(["https://verifier.example"])
    );
}
