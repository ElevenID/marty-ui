use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{TimeZone, Utc};
use marty_flow::{
    prepare_profiled_verification_start, prepare_verification_start, CredentialClaimReference,
    CredentialTemplateProvider, CredentialTemplateReference, FlowKeyEnvelopeProvider,
    FlowProviderError, FlowProviderRegistry, FlowVerificationStartError, Oid4vpClientIdScheme,
    Oid4vpProfile, PresentationEvaluationRequest, PresentationEvaluationResult,
    PresentationPolicyProvider, PresentationPolicyReference, RequestTransport, RequestUriMethod,
    SigningIdentity, SigningIdentityProvider, SigningRequest, SigningResult,
    StartVerificationFlowRequest, VerificationResponseType, VerificationStartContext,
    VerificationStartOptions,
};
#[path = "support/haip_remote_fixture.rs"]
mod haip_remote_fixture;
use mmf_push::WebhookDestinationRegistry;
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    nonce_entropy_bytes: usize,
    initial_status: String,
    callback_policy: String,
    principal_binding: String,
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
    async fn configuration_digest(&self, _policy_id: &str) -> Result<String, FlowProviderError> {
        Ok(format!("sha256:{}", "a".repeat(64)))
    }

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

#[derive(Clone, Copy)]
enum BrokenTemplate {
    Missing,
    WrongOrganization,
    Inactive,
}

#[async_trait]
impl CredentialTemplateProvider for BrokenTemplate {
    async fn get_template(
        &self,
        template_id: &str,
    ) -> Result<CredentialTemplateReference, FlowProviderError> {
        if matches!(self, Self::Missing) {
            return Err(FlowProviderError::NotFound {
                provider: "credential_template",
                resource: template_id.into(),
            });
        }
        let mut template = Templates.get_template(template_id).await?;
        match self {
            Self::WrongOrganization => template.organization_id = "other-org".into(),
            Self::Inactive => template.status = "inactive".into(),
            Self::Missing => unreachable!(),
        }
        Ok(template)
    }

    async fn wallet_formats(
        &self,
        organization_id: &str,
    ) -> Result<Vec<String>, FlowProviderError> {
        Templates.wallet_formats(organization_id).await
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
    assert_eq!(contract.schema_version, 2);
    assert_eq!(contract.nonce_entropy_bytes, 32);
    assert_eq!(contract.initial_status, "awaiting_wallet");
    assert_eq!(
        contract.callback_policy,
        "mmf_tenant_registered_destination"
    );
    assert_eq!(
        contract.principal_binding,
        "required_for_http_and_grpc_and_persisted_in_private_context"
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
            "user-1",
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
        assert_eq!(
            prepared.instance.context["_marty_verification_principal_id"],
            "user-1"
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
        "user-1",
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
    let principal_error = prepare_verification_start(
        &providers("org-1"),
        &callbacks(),
        request(RequestTransport::RequestUri),
        "https://verifier.example",
        false,
        16_384,
        16_384,
        None,
        " ",
        now(),
    )
    .await
    .unwrap_err();
    assert!(principal_error.to_string().contains("PRINCIPAL_REQUIRED"));

    let callback_error = prepare_verification_start(
        &providers("org-1"),
        &WebhookDestinationRegistry::default(),
        request(RequestTransport::RequestUri),
        "https://verifier.example",
        false,
        16_384,
        16_384,
        None,
        "user-1",
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
        "user-1",
        now(),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        policy_error,
        FlowVerificationStartError::InvalidPolicyReference
    ));
}

#[tokio::test]
async fn stale_or_foreign_policy_template_fails_before_request_uri_is_advertised() {
    for broken in [
        BrokenTemplate::Missing,
        BrokenTemplate::WrongOrganization,
        BrokenTemplate::Inactive,
    ] {
        let mut registry = providers("org-1");
        registry.credential_template = Some(Arc::new(broken));
        let error = prepare_verification_start(
            &registry,
            &callbacks(),
            request(RequestTransport::RequestUri),
            "https://verifier.example",
            false,
            16_384,
            16_384,
            None,
            "user-1",
            now(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            FlowVerificationStartError::InvalidPolicyReference
        ));
    }
}

#[tokio::test]
async fn configured_identity_and_haip_gates_apply_before_persistence() {
    let mut options = VerificationStartOptions::default();
    options.request_object.client_id_scheme = Oid4vpClientIdScheme::RedirectUri;
    let prepared = prepare_profiled_verification_start(
        &providers("org-1"),
        &callbacks(),
        request(RequestTransport::RequestUri),
        &options,
        VerificationStartContext {
            public_base_url: "https://verifier.example",
            allow_http_loopback: false,
            principal_id: "user-1",
            now: now(),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        prepared.instance.context["oid4vp_client_id"],
        format!(
            "redirect_uri:https://verifier.example/v1/flows/instances/{}/submit",
            prepared.instance.id
        )
    );

    let mut haip = request(RequestTransport::RequestUri);
    haip.oid4vp_profile = Oid4vpProfile::Haip;
    assert!(prepare_profiled_verification_start(
        &providers("org-1"),
        &callbacks(),
        haip,
        &options,
        VerificationStartContext {
            public_base_url: "https://verifier.example",
            allow_http_loopback: false,
            principal_id: "user-1",
            now: now(),
        },
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("HAIP_DISABLED"));
}

fn website_definition() -> marty_flow::FlowDefinitionRecord {
    let mut record = marty_flow::create_definition_record(
        marty_flow::parse_request(json!({
            "organization_id": "org-1", "name": "Website verification",
            "flow_type": "oid4vp_presentation", "presentation_policy_id": "policy-1"
        }))
        .unwrap(),
        now(),
    )
    .unwrap();
    record.status = marty_flow::DefinitionStatus::Active;
    record
}

#[tokio::test]
async fn selected_definition_uses_canonical_wallet_lifecycle_and_pins_its_version() {
    let definition = website_definition();
    let binding = marty_flow::VerificationDefinitionBinding {
        organization_id: "org-1".into(),
        definition_id: definition.id.clone(),
        version: definition.version,
    };
    let mut prepared = marty_flow::prepare_defined_verification_start(
        &providers("org-1"),
        &WebhookDestinationRegistry::default(),
        &definition,
        &binding,
        "did:web:verifier.example",
        &VerificationStartOptions::default(),
        VerificationStartContext {
            public_base_url: "https://verifier.example",
            allow_http_loopback: false,
            principal_id: "website-operator",
            now: now(),
        },
    )
    .await
    .unwrap();
    assert_eq!(prepared.instance.flow_definition_id, definition.id);
    assert_eq!(prepared.response.flow_definition_id, definition.id);
    assert_eq!(
        prepared.instance.context["_marty_verification_definition"]["binding"]["version"],
        1
    );
    assert!(prepared
        .response
        .qr_code_data
        .starts_with("openid4vp://authorize?"));
    assert_eq!(
        prepared.instance.context["presentation_policy_id"],
        "policy-1"
    );
    // Rebuilding the same query assigns a new query ID, but must preserve
    // the admitted claims/formats. Canonical request retrieval checks the pin.
    let retrieval = marty_flow::prepare_verification_request(
        &providers("org-1"),
        prepared.instance.clone(),
        "https://verifier.example",
        &marty_flow::VerificationRequestRetrievalOptions::default(),
        now(),
    )
    .await
    .unwrap();
    assert!(matches!(
        retrieval,
        marty_flow::PreparedVerificationRequest::Ready(_)
    ));
    let mut changed = prepared.instance.clone();
    changed.context["_marty_verification_request_digest"] = json!("changed-policy-query");
    assert!(marty_flow::prepare_verification_request(
        &providers("org-1"),
        changed,
        "https://verifier.example",
        &marty_flow::VerificationRequestRetrievalOptions::default(),
        now(),
    )
    .await
    .is_err());
    assert_eq!(prepared.instance.step_history.len(), 2);
    assert_eq!(prepared.instance.step_history[0]["status"], "completed");
    let before = prepared.instance.step_history.clone();
    marty_flow::record_defined_verification_progress(&mut prepared.instance, false, now()).unwrap();
    let after_request = prepared.instance.step_history.clone();
    assert_eq!(after_request.len(), 3);
    assert_eq!(before[0], after_request[0]);
    marty_flow::record_defined_verification_progress(&mut prepared.instance, false, now()).unwrap();
    assert_eq!(prepared.instance.step_history, after_request);
    assert!(
        marty_flow::record_defined_verification_progress(&mut prepared.instance, true, now())
            .is_err()
    );
    prepared.instance.status = marty_verification::flow::FlowInstanceStatus::Failed;
    marty_flow::record_defined_verification_progress(&mut prepared.instance, true, now()).unwrap();
    assert_eq!(prepared.instance.step_history.len(), 4);
    assert_eq!(prepared.instance.step_history[3]["status"], "failed");
    assert!(prepared.instance.current_step_id.is_none());
    assert!(
        !serde_json::to_string(&prepared.instance.projection().unwrap())
            .unwrap()
            .contains("_marty_verification_definition")
    );
}

#[tokio::test]
async fn definition_binding_rejects_changes_or_extra_work_before_signing() {
    let definition = website_definition();
    let binding = marty_flow::VerificationDefinitionBinding {
        organization_id: "org-1".into(),
        definition_id: definition.id.clone(),
        version: definition.version,
    };
    for variant in 0..8 {
        let mut candidate = definition.clone();
        match variant {
            0 => candidate.organization_id = "foreign".into(),
            1 => candidate.version += 1,
            2 => candidate.status = marty_flow::DefinitionStatus::Paused,
            3 => {
                candidate
                    .hooks
                    .insert("on_start".into(), vec![json!({"action": "approval"})]);
            }
            4 => candidate.preconditions.push("approved".into()),
            5 => candidate.steps[1]["config"]["protocol_step"] = json!("approval"),
            6 => candidate.default_timeout_seconds = 61,
            _ => candidate.presentation_policy_id = None,
        }
        let result = marty_flow::prepare_defined_verification_start(
            &FlowProviderRegistry::default(),
            &WebhookDestinationRegistry::default(),
            &candidate,
            &binding,
            "did:web:verifier.example",
            &VerificationStartOptions::default(),
            VerificationStartContext {
                public_base_url: "https://verifier.example",
                allow_http_loopback: false,
                principal_id: "website-operator",
                now: now(),
            },
        )
        .await;
        assert!(
            matches!(
                result,
                Err(marty_flow::DefinedVerificationError::DefinitionUnavailable
                    | marty_flow::DefinedVerificationError::UnsupportedDefinition)
            ),
            "variant {variant}: {result:?}"
        );
    }
}

struct WebsiteEvaluation {
    allow: bool,
    seen: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl PresentationPolicyProvider for WebsiteEvaluation {
    async fn configuration_digest(&self, _policy_id: &str) -> Result<String, FlowProviderError> {
        Ok(format!("sha256:{}", "a".repeat(64)))
    }

    async fn get_policy(&self, id: &str) -> Result<PresentationPolicyReference, FlowProviderError> {
        Policies {
            organization_id: "org-1",
        }
        .get_policy(id)
        .await
    }
    async fn evaluate(
        &self,
        request: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError> {
        self.seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(request.organization_id, "org-1");
        assert_eq!(request.principal_id, "website-operator");
        assert_eq!(request.policy_id, "policy-1");
        assert_eq!(
            request.context["_marty_expected_policy_configuration_digest"],
            format!("sha256:{}", "a".repeat(64))
        );
        Ok(PresentationEvaluationResult {
            authentication_diagnostic: None,
            result: if self.allow { "passed" } else { "failed" }.into(),
            decision: if self.allow { "allow" } else { "deny" }.into(),
            decision_reason: None,
            verified_claims: [("given_name".into(), json!("Synthetic holder"))].into(),
            credential_results: vec![
                json!({"signature_valid": true, "trust_check_passed": self.allow}),
            ],
            error_codes: vec![],
            warnings: vec![],
        })
    }
}

#[tokio::test]
async fn selected_definition_completes_only_from_the_canonical_evaluator_and_scrubs_denied_claims()
{
    for allow in [true, false] {
        let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut registry = providers("org-1");
        registry.presentation_policy = Some(Arc::new(WebsiteEvaluation {
            allow,
            seen: seen.clone(),
        }));
        let definition = website_definition();
        let binding = marty_flow::VerificationDefinitionBinding {
            organization_id: "org-1".into(),
            definition_id: definition.id.clone(),
            version: definition.version,
        };
        let prepared = marty_flow::prepare_defined_verification_start(
            &registry,
            &WebhookDestinationRegistry::default(),
            &definition,
            &binding,
            "did:web:verifier.example",
            &VerificationStartOptions::default(),
            VerificationStartContext {
                public_base_url: "https://verifier.example",
                allow_http_loopback: false,
                principal_id: "website-operator",
                now: now(),
            },
        )
        .await
        .unwrap();
        let marty_flow::PreparedVerificationRequest::Ready(request) =
            marty_flow::prepare_verification_request(
                &registry,
                prepared.instance,
                "https://verifier.example",
                &marty_flow::VerificationRequestRetrievalOptions::default(),
                now(),
            )
            .await
            .unwrap()
        else {
            panic!("fresh request expected")
        };
        let input = marty_flow::VerificationSubmissionInput {
            vp_token: "unit-test.presentation.token".into(),
            presentation_submission: None,
            state: request
                .instance
                .context
                .get("oid4vp_expected_state")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            audience_override: None,
        };
        let options = marty_flow::VerificationSubmissionOptions {
            callback_destinations: WebhookDestinationRegistry::default(),
            callback_secret: None,
            verifier_sender_id: "website-verifier".into(),
            nonce_ttl_seconds: 900,
            callback_retention_seconds: 900,
            callback_max_attempts: 10,
        };
        let mut changed = request.instance.clone();
        changed.context["_marty_verification_request_digest"] = json!("changed");
        assert!(marty_flow::prepare_verification_submission(
            &registry,
            changed,
            input.clone(),
            &options,
            now()
        )
        .await
        .is_err());
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 0);
        let marty_flow::PreparedVerificationSubmission::Final(finalization) =
            marty_flow::prepare_verification_submission(
                &registry,
                request.instance,
                input,
                &options,
                now(),
            )
            .await
            .unwrap()
        else {
            panic!("canonical terminal evaluation expected")
        };
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(finalization.instance.flow_definition_id, definition.id);
        assert_eq!(finalization.instance.step_history.len(), 4);
        assert_eq!(
            finalization.instance.step_history[3]["status"],
            if allow { "completed" } else { "failed" }
        );
        assert_eq!(
            finalization.instance.result.as_ref().unwrap()["verified_claims"],
            if allow {
                json!({"given_name": "Synthetic holder"})
            } else {
                json!({})
            }
        );
        assert!(finalization.instance.current_step_id.is_none());
    }
}

struct ChangingRules(Arc<std::sync::atomic::AtomicUsize>);
#[async_trait]
impl PresentationPolicyProvider for ChangingRules {
    async fn configuration_digest(&self, _policy_id: &str) -> Result<String, FlowProviderError> {
        Ok(format!(
            "sha256:{}",
            if self.0.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                "a"
            } else {
                "b"
            }
            .repeat(64)
        ))
    }
    async fn get_policy(&self, id: &str) -> Result<PresentationPolicyReference, FlowProviderError> {
        Policies {
            organization_id: "org-1",
        }
        .get_policy(id)
        .await
    }
    async fn evaluate(
        &self,
        _request: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError> {
        panic!("changed admission must not reach evaluation")
    }
}

#[tokio::test]
async fn unchanged_wallet_query_cannot_hide_a_changed_business_rule() {
    let generation = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut registry = providers("org-1");
    registry.presentation_policy = Some(Arc::new(ChangingRules(generation.clone())));
    let definition = website_definition();
    let binding = marty_flow::VerificationDefinitionBinding {
        organization_id: "org-1".into(),
        definition_id: definition.id.clone(),
        version: 1,
    };
    let prepared = marty_flow::prepare_defined_verification_start(
        &registry,
        &WebhookDestinationRegistry::default(),
        &definition,
        &binding,
        "did:web:verifier.example",
        &VerificationStartOptions::default(),
        VerificationStartContext {
            public_base_url: "https://verifier.example",
            allow_http_loopback: false,
            principal_id: "website-operator",
            now: now(),
        },
    )
    .await
    .unwrap();
    let marty_flow::PreparedVerificationRequest::Ready(request) =
        marty_flow::prepare_verification_request(
            &registry,
            prepared.instance.clone(),
            "https://verifier.example",
            &marty_flow::VerificationRequestRetrievalOptions::default(),
            now(),
        )
        .await
        .unwrap()
    else {
        panic!("fresh request expected")
    };
    generation.store(1, std::sync::atomic::Ordering::SeqCst);
    assert!(marty_flow::prepare_verification_request(
        &registry,
        prepared.instance,
        "https://verifier.example",
        &marty_flow::VerificationRequestRetrievalOptions::default(),
        now(),
    )
    .await
    .is_err());
    let input = marty_flow::VerificationSubmissionInput {
        vp_token: "unit-test.presentation.token".into(),
        presentation_submission: None,
        state: request
            .instance
            .context
            .get("oid4vp_expected_state")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        audience_override: None,
    };
    let options = marty_flow::VerificationSubmissionOptions {
        callback_destinations: WebhookDestinationRegistry::default(),
        callback_secret: None,
        verifier_sender_id: "website-verifier".into(),
        nonce_ttl_seconds: 900,
        callback_retention_seconds: 900,
        callback_max_attempts: 10,
    };
    assert!(marty_flow::prepare_verification_submission(
        &registry,
        request.instance,
        input,
        &options,
        now()
    )
    .await
    .is_err());
}
