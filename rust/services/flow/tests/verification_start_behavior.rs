use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{TimeZone, Utc};
use marty_flow::{
    prepare_profiled_verification_start, prepare_verification_start, CredentialClaimReference,
    CredentialTemplateProvider, CredentialTemplateReference, FlowKeyEnvelope,
    FlowKeyEnvelopeProvider, FlowKeyEnvelopeRequest, FlowProviderError, FlowProviderRegistry,
    Oid4vpClientIdScheme, Oid4vpProfile, PresentationEvaluationRequest,
    PresentationEvaluationResult, PresentationPolicyProvider, PresentationPolicyReference,
    RequestTransport, RequestUriMethod, SigningIdentity, SigningIdentityProvider, SigningRequest,
    SigningResult, StartVerificationFlowRequest, VerificationResponseType,
    VerificationStartOptions,
};
use mmf_push::WebhookDestinationRegistry;
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    nonce_entropy_bytes: usize,
    initial_status: String,
    callback_policy: String,
    policy_binding: Vec<String>,
    signing_identity_binding: Vec<String>,
    request_uri_transport: String,
    request_object_transport: String,
    url_query_transport: String,
    siop_transport: String,
    persistence: String,
    failure_behavior: String,
}

struct Policies {
    organization_id: &'static str,
}

#[async_trait]
impl PresentationPolicyProvider for Policies {
    async fn get_policy(
        &self,
        policy_id: &str,
    ) -> Result<PresentationPolicyReference, FlowProviderError> {
        Ok(PresentationPolicyReference {
            id: policy_id.into(),
            organization_id: self.organization_id.into(),
            status: "active".into(),
            credential_requirements: vec![json!({
                "id": "member",
                "credential_template_id": "template-1",
                "requested_claims": [{"claim_name": "given_name", "required": true}]
            })],
        })
    }

    async fn evaluate(
        &self,
        _request: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError> {
        unreachable!("verification start does not evaluate presentations")
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
            claims: vec![CredentialClaimReference {
                name: "given_name".into(),
                display_name: "Given name".into(),
                description: String::new(),
                required: true,
                mdoc_namespace: String::new(),
                mdoc_element_identifier: String::new(),
            }],
            issuer_did: "did:web:issuer.example".into(),
            credential_format: "dc+sd-jwt".into(),
            wallet_configurations: Vec::new(),
            issuer_algorithm: Some("ES256".into()),
        })
    }

    async fn wallet_formats(&self) -> Result<Vec<String>, FlowProviderError> {
        Ok(vec!["dc+sd-jwt".into()])
    }
}

struct Signing;

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
        Ok(SigningIdentity {
            organization_id: organization_id.into(),
            issuer_did: issuer_did.into(),
            verification_method_id: format!("{issuer_did}#request-object"),
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
    async fn wrap(
        &self,
        request: &FlowKeyEnvelopeRequest,
    ) -> Result<FlowKeyEnvelope, FlowProviderError> {
        Ok(FlowKeyEnvelope {
            organization_id: request.organization_id.clone(),
            flow_instance_id: request.flow_instance_id.clone(),
            purpose: request.purpose.clone(),
            envelope: "vault:verification-key".into(),
        })
    }

    async fn unwrap(&self, _envelope: &FlowKeyEnvelope) -> Result<String, FlowProviderError> {
        unreachable!("verification start only wraps HAIP keys")
    }
}

fn providers(policy_organization: &'static str) -> FlowProviderRegistry {
    FlowProviderRegistry {
        presentation_policy: Some(Arc::new(Policies {
            organization_id: policy_organization,
        })),
        credential_template: Some(Arc::new(Templates)),
        signing_identity: Some(Arc::new(Signing)),
        flow_key_envelope: Some(Arc::new(Envelopes)),
        ..Default::default()
    }
}

fn request(transport: RequestTransport) -> StartVerificationFlowRequest {
    StartVerificationFlowRequest {
        presentation_policy_id: Some("policy-1".into()),
        organization_id: "org-1".into(),
        issuer_did: "did:web:verifier.example".into(),
        response_type: VerificationResponseType::VpToken,
        trust_profile_id: Some("trust-1".into()),
        deployment_profile_id: Some("deployment-1".into()),
        external_reference: Some("external-1".into()),
        callback_url: Some("https://callback.example/result?nonce=token-1234567890".into()),
        oid4vp_profile: Oid4vpProfile::Standard,
        request_transport: transport,
        request_uri_method: RequestUriMethod::Get,
        expiry_minutes: 15,
    }
}

fn callbacks() -> WebhookDestinationRegistry {
    WebhookDestinationRegistry::parse("org-1|https://callback.example/result?nonce=__MARTY_TOKEN__")
        .unwrap()
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0).unwrap()
}

#[tokio::test]
async fn language_neutral_contract_preserves_all_start_transports() {
    let contract: Contract = serde_json::from_str(include_str!(
        "../../../../contracts/flow-verification-start-behavior.json"
    ))
    .unwrap();
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.nonce_entropy_bytes, 32);
    assert_eq!(contract.initial_status, "awaiting_wallet");
    assert_eq!(
        contract.callback_policy,
        "mmf_tenant_registered_destination"
    );
    assert_eq!(contract.policy_binding.len(), 4);
    assert_eq!(contract.signing_identity_binding.len(), 5);
    assert_eq!(contract.request_uri_transport, "openid4vp_request_uri");
    assert_eq!(
        contract.request_object_transport,
        "openid4vp_signed_by_value"
    );
    assert_eq!(
        contract.url_query_transport,
        "openid4vp_unsigned_bounded_dcql"
    );
    assert_eq!(contract.siop_transport, "openid_request_uri");
    assert_eq!(
        contract.persistence,
        "single_atomic_insert_after_side_effects"
    );
    assert_eq!(contract.failure_behavior, "no_instance_insert");

    for (transport, expected_fragment) in [
        (RequestTransport::RequestUri, "request_uri="),
        (RequestTransport::RequestObject, "request="),
        (RequestTransport::UrlQuery, "dcql_query="),
    ] {
        let prepared = prepare_verification_start(
            &providers("org-1"),
            &callbacks(),
            request(transport),
            "https://verifier.example",
            false,
            16_384,
            16_384,
            None,
            now(),
        )
        .await
        .unwrap();
        assert_eq!(prepared.response.status, contract.initial_status);
        assert!(prepared.response.request_uri.contains(expected_fragment));
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(&prepared.response.nonce)
                .unwrap()
                .len(),
            contract.nonce_entropy_bytes
        );
        assert_eq!(
            prepared.instance.context["auth_request"],
            prepared.response.request_uri
        );
        assert_eq!(
            prepared.instance.context["callback_url"],
            "https://callback.example/result?nonce=token-1234567890"
        );
        assert_eq!(prepared.instance.organization_id, "org-1");
    }

    let mut siop = request(RequestTransport::RequestUri);
    siop.response_type = VerificationResponseType::IdToken;
    siop.presentation_policy_id = None;
    let prepared = prepare_verification_start(
        &providers("other-org"),
        &callbacks(),
        siop,
        "https://verifier.example",
        false,
        16_384,
        16_384,
        Some("https://verifier.example/client"),
        now(),
    )
    .await
    .unwrap();
    assert!(prepared
        .response
        .request_uri
        .starts_with("openid://authorize?"));
    assert_eq!(prepared.response.presentation_policy_id, "");
    assert_eq!(
        prepared.instance.context["flow_definition_reference"],
        "__siop_v2__"
    );
}

#[tokio::test]
async fn rejected_callback_or_cross_tenant_policy_produces_no_prepared_instance() {
    let callback_error = prepare_verification_start(
        &providers("org-1"),
        &WebhookDestinationRegistry::default(),
        request(RequestTransport::RequestUri),
        "https://verifier.example",
        false,
        16_384,
        16_384,
        None,
        now(),
    )
    .await
    .unwrap_err();
    assert!(callback_error.to_string().contains("CALLBACK_REJECTED"));

    let policy_error = prepare_verification_start(
        &providers("org-2"),
        &callbacks(),
        request(RequestTransport::RequestUri),
        "https://verifier.example",
        false,
        16_384,
        16_384,
        None,
        now(),
    )
    .await
    .unwrap_err();
    assert!(policy_error.to_string().contains("INVALID_POLICY"));
}

#[tokio::test]
async fn configured_identity_and_haip_gates_apply_before_persistence() {
    let mut options = VerificationStartOptions::default();
    options.request_object.client_id_scheme = Oid4vpClientIdScheme::RedirectUri;
    let prepared = prepare_profiled_verification_start(
        &providers("org-1"),
        &callbacks(),
        request(RequestTransport::RequestUri),
        "https://verifier.example",
        false,
        &options,
        now(),
    )
    .await
    .unwrap();
    assert_eq!(
        prepared.instance.context["oid4vp_client_id"],
        format!(
            "https://verifier.example/v1/flows/instances/{}/submit",
            prepared.instance.id
        )
    );

    let mut haip = request(RequestTransport::RequestUri);
    haip.oid4vp_profile = Oid4vpProfile::Haip;
    assert!(prepare_profiled_verification_start(
        &providers("org-1"),
        &callbacks(),
        haip,
        "https://verifier.example",
        false,
        &options,
        now(),
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("HAIP_DISABLED"));
}
