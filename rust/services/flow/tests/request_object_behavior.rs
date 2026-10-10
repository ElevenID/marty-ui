use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, TimeZone, Utc};
use marty_flow::{
    build_profiled_request_object, build_standard_request_object, build_unsigned_url_query,
    FlowInstanceRecord, FlowKeyEnvelopeProvider, FlowProviderError, FlowProviderRegistry,
    Oid4vpClientIdScheme, RequestObjectCompatibility, RequestObjectOptions, RequestObjectTransport,
    SigningIdentity, SigningIdentityProvider, SigningRequest, SigningResult, VerifierDidMethod,
};
#[path = "support/haip_remote_fixture.rs"]
mod haip_remote_fixture;
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
    url_query: String,
    url_query_minimum_limit: usize,
    url_query_oversize: String,
    haip_response_mode: String,
    haip_jwe: BTreeMap<String, String>,
    haip_key_custody: String,
    identity_change: String,
    client_id_schemes: Vec<String>,
    verifier_did_methods: Vec<String>,
    x509_header: String,
    lissi_query: String,
    lissi_client_id_scheme: String,
    lissi_haip: String,
    dc_api: DcApi,
}

#[derive(Deserialize)]
struct DcApi {
    protocol: String,
    response_mode: String,
    origin_binding: String,
    response_encryption: BTreeMap<String, String>,
    redirect_fields: String,
}

#[derive(Clone, Default)]
struct Envelopes {
    requests: Arc<Mutex<Vec<(String, String)>>>,
    resolutions: Arc<Mutex<Vec<(String, String, String)>>>,
    missing_remote_key: bool,
}

#[async_trait]
impl FlowKeyEnvelopeProvider for Envelopes {
    async fn resolve_haip_key(
        &self,
        organization_id: &str,
        flow_instance_id: &str,
        version: &str,
    ) -> Result<marty_flow::HaipRemoteKey, FlowProviderError> {
        self.resolutions.lock().unwrap().push((
            organization_id.into(),
            flow_instance_id.into(),
            version.into(),
        ));
        if self.missing_remote_key {
            return Err(FlowProviderError::Unavailable {
                provider: "flow_key_envelope",
            });
        }
        Ok(haip_remote_fixture::key(organization_id, flow_instance_id))
    }

    async fn create_haip_key(
        &self,
        organization_id: &str,
        flow_instance_id: &str,
    ) -> Result<marty_flow::HaipRemoteKey, FlowProviderError> {
        self.requests
            .lock()
            .unwrap()
            .push((organization_id.into(), flow_instance_id.into()));
        Ok(haip_remote_fixture::key(organization_id, flow_instance_id))
    }
}

#[tokio::test]
async fn reissuing_haip_request_requires_the_stored_remote_key_version() {
    let artifacts = PresentationRequestArtifacts {
        presentation_definition: json!({"id": "pd-1"}),
        dcql_query: json!({"credentials": [{"id": "member", "format": "dc+sd-jwt"}]}),
    };
    let mut flow = instance("verification");
    flow.context["oid4vp_profile"] = json!("haip");
    let remote = haip_remote_fixture::key(&flow.organization_id, &flow.id);
    flow.context["haip_response_encryption_key_reference"] = json!(remote.key_reference);
    flow.context["haip_response_encryption_public_jwk"] = remote.public_jwk;
    let envelopes = Envelopes::default();
    let providers = FlowProviderRegistry {
        signing_identity: Some(Arc::new(Signing::default())),
        flow_key_envelope: Some(Arc::new(envelopes.clone())),
        ..Default::default()
    };
    build_standard_request_object(
        &providers,
        flow.clone(),
        Some(&artifacts),
        "https://verifier.example",
        None,
        None,
        now(),
    )
    .await
    .unwrap();
    assert!(envelopes.requests.lock().unwrap().is_empty());
    assert_eq!(
        *envelopes.resolutions.lock().unwrap(),
        vec![(
            "org-1".into(),
            "instance-1".into(),
            haip_remote_fixture::VERSION.into()
        )]
    );

    let missing = FlowProviderRegistry {
        signing_identity: Some(Arc::new(Signing::default())),
        flow_key_envelope: Some(Arc::new(Envelopes {
            missing_remote_key: true,
            ..Default::default()
        })),
        ..Default::default()
    };
    assert!(build_standard_request_object(
        &missing,
        flow,
        Some(&artifacts),
        "https://verifier.example",
        None,
        None,
        now(),
    )
    .await
    .is_err());
}

#[derive(Clone, Default)]
struct Signing {
    requests: Arc<Mutex<Vec<SigningRequest>>>,
    wrong_did: bool,
    public_jwk: Option<BTreeMap<String, Value>>,
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
            public_jwk: self.public_jwk.clone().unwrap_or_else(|| {
                BTreeMap::from([
                    ("kty".into(), json!("EC")),
                    ("crv".into(), json!("P-256")),
                    ("x".into(), json!("x")),
                    ("y".into(), json!("y")),
                ])
            }),
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
    assert_eq!(contract.url_query, "unsigned_direct_post_dcql");
    assert_eq!(contract.url_query_minimum_limit, 1_024);
    assert_eq!(contract.url_query_oversize, "fail_closed");
    assert_eq!(contract.haip_response_mode, "direct_post.jwt");
    assert_eq!(contract.haip_jwe["alg"], "ECDH-ES");
    assert_eq!(contract.haip_jwe["enc"], "A256GCM");
    assert_eq!(
        contract.haip_key_custody,
        "remote_nonexportable_tenant_flow_version_reference"
    );
    assert_eq!(contract.identity_change, "fail_closed");
    assert_eq!(
        contract.client_id_schemes,
        ["redirect_uri", "decentralized_identifier", "x509_hash"]
    );
    assert_eq!(
        contract.verifier_did_methods,
        ["did:web", "did:jwk", "did:key"]
    );
    assert_eq!(contract.x509_header, "validated_leaf_first_x5c_without_kid");
    assert_eq!(contract.lissi_query, "presentation_definition");
    assert_eq!(contract.lissi_client_id_scheme, "did");
    assert_eq!(contract.lissi_haip, "rejected");
    assert_eq!(contract.dc_api.protocol, "openid4vp-v1-signed");
    assert_eq!(contract.dc_api.response_mode, "dc_api.jwt");
    assert_eq!(contract.dc_api.origin_binding, "exact_configured_origins");
    assert_eq!(contract.dc_api.response_encryption["alg"], "ECDH-ES");
    assert_eq!(contract.dc_api.response_encryption["enc"], "A256GCM");
    assert_eq!(contract.dc_api.redirect_fields, "omitted");

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

#[test]
fn unsigned_url_query_is_bounded_and_records_the_same_dcql_request() {
    let mut flow = instance("verification");
    flow.context["request_transport"] = json!("url_query");
    let artifacts = PresentationRequestArtifacts {
        presentation_definition: json!({"id": "pd-1"}),
        dcql_query: json!({"credentials": [{"id": "member", "format": "dc+sd-jwt"}]}),
    };
    let request = build_unsigned_url_query(
        flow.clone(),
        &artifacts,
        "https://verifier.example",
        8_192,
        now(),
    )
    .unwrap();
    assert!(request
        .authorization_request
        .starts_with("openid4vp://authorize?"));
    let parsed = url::Url::parse(&request.authorization_request).unwrap();
    let parameters = parsed
        .query_pairs()
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    assert_eq!(parameters["response_type"], "vp_token");
    assert_eq!(parameters["response_mode"], "direct_post");
    assert_eq!(
        serde_json::from_str::<Value>(&parameters["dcql_query"]).unwrap(),
        artifacts.dcql_query
    );
    assert_eq!(
        request.instance.context["mip_messages"]["presentation_request"]["payload"]["dcql_query"],
        artifacts.dcql_query
    );
    assert!(
        build_unsigned_url_query(flow, &artifacts, "https://verifier.example", 1_024, now())
            .is_err()
    );
}

#[tokio::test]
async fn haip_keys_are_remote_and_only_the_reference_is_persisted() {
    let signing = Signing::default();
    let envelopes = Envelopes::default();
    let providers = FlowProviderRegistry {
        signing_identity: Some(Arc::new(signing)),
        flow_key_envelope: Some(Arc::new(envelopes.clone())),
        ..Default::default()
    };
    let mut flow = instance("verification");
    flow.context["oid4vp_profile"] = json!("haip");
    let artifacts = PresentationRequestArtifacts {
        presentation_definition: json!({"id": "pd-1"}),
        dcql_query: json!({"credentials": [{"id": "member", "format": "dc+sd-jwt"}]}),
    };
    let result = build_standard_request_object(
        &providers,
        flow,
        Some(&artifacts),
        "https://verifier.example",
        None,
        None,
        now(),
    )
    .await
    .unwrap();
    let request = payload(&result.compact_jwt);
    assert_eq!(request["response_mode"], "direct_post.jwt");
    assert_eq!(
        request["client_metadata"]["encrypted_response_enc_values_supported"][0],
        "A256GCM"
    );
    assert!(request["client_metadata"]["jwks"]["keys"][0]
        .get("d")
        .is_none());
    assert_eq!(
        result.instance.context["haip_response_encryption_key_reference"],
        format!(
            "didcomm/haip/keys/org-1/instance-1/versions/{}",
            haip_remote_fixture::VERSION
        )
    );
    assert!(result.instance.context.to_string().find("\"d\"").is_none());
    let remote = envelopes.requests.lock().unwrap();
    assert_eq!(*remote, vec![("org-1".into(), "instance-1".into())]);
    assert!(result
        .instance
        .context
        .get("haip_response_encryption_key_envelope")
        .is_none());
}

#[tokio::test]
async fn old_haip_envelope_cannot_be_reissued_or_combined_with_remote_reference() {
    let envelopes = Envelopes::default();
    let providers = FlowProviderRegistry {
        signing_identity: Some(Arc::new(Signing::default())),
        flow_key_envelope: Some(Arc::new(envelopes.clone())),
        ..Default::default()
    };
    let artifacts = PresentationRequestArtifacts {
        presentation_definition: json!({"id": "pd-1"}),
        dcql_query: json!({"credentials": [{"id": "member", "format": "dc+sd-jwt"}]}),
    };
    let mut flow = instance("verification");
    flow.context["oid4vp_profile"] = json!("haip");
    flow.context["haip_response_encryption_key_envelope"] = json!("vault:old-key");
    assert!(build_standard_request_object(
        &providers,
        flow.clone(),
        Some(&artifacts),
        "https://verifier.example",
        None,
        None,
        now(),
    )
    .await
    .is_err());
    let remote = haip_remote_fixture::key(&flow.organization_id, &flow.id);
    flow.context["haip_response_encryption_key_reference"] = json!(remote.key_reference);
    flow.context["haip_response_encryption_public_jwk"] = remote.public_jwk;
    assert!(build_standard_request_object(
        &providers,
        flow,
        Some(&artifacts),
        "https://verifier.example",
        None,
        None,
        now(),
    )
    .await
    .is_err());
    assert!(envelopes.requests.lock().unwrap().is_empty());
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

#[tokio::test]
async fn profiled_requests_preserve_lissi_and_x509_identity_modes() {
    let artifacts = PresentationRequestArtifacts {
        presentation_definition: json!({"id": "pd-1", "input_descriptors": []}),
        dcql_query: json!({"credentials": [{"id": "member"}]}),
    };
    let providers = FlowProviderRegistry {
        signing_identity: Some(Arc::new(Signing::default())),
        ..Default::default()
    };
    let mut lissi_instance = instance("verification");
    lissi_instance.context["oid4vp_client_id"] =
        json!("decentralized_identifier:did:web:verifier.example");
    let lissi = build_profiled_request_object(
        &providers,
        lissi_instance,
        Some(&artifacts),
        "https://verifier.example",
        &RequestObjectOptions {
            compatibility: RequestObjectCompatibility::Lissi,
            ..Default::default()
        },
        now(),
    )
    .await
    .unwrap();
    let lissi_payload = payload(&lissi.compact_jwt);
    assert_eq!(lissi.client_id, "did:web:verifier.example");
    assert_eq!(lissi_payload["client_id_scheme"], "did");
    assert_eq!(
        lissi_payload["presentation_definition"],
        artifacts.presentation_definition
    );
    assert!(lissi_payload.get("dcql_query").is_none());
    assert!(lissi_payload.get("client_metadata").is_none());

    let fixture: Value = serde_json::from_str(include_str!(
        "../../signing-keys/tests/fixtures/document_vectors.json"
    ))
    .unwrap();
    let public_jwk =
        serde_json::from_value(fixture["certificate"]["expected_jwk"].clone()).unwrap();
    let x509_signing = Signing {
        public_jwk: Some(public_jwk),
        ..Default::default()
    };
    let x509_providers = FlowProviderRegistry {
        signing_identity: Some(Arc::new(x509_signing)),
        ..Default::default()
    };
    let x509 = build_profiled_request_object(
        &x509_providers,
        instance("verification"),
        Some(&artifacts),
        "https://verifier.example",
        &RequestObjectOptions {
            client_id_scheme: Oid4vpClientIdScheme::X509Hash,
            x509_certificate_bundle: Some(
                fixture["certificate"]["cert_pem"].as_str().unwrap().into(),
            ),
            verifier_did_method: VerifierDidMethod::Web,
            ..Default::default()
        },
        now(),
    )
    .await
    .unwrap();
    let protected: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(x509.compact_jwt.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(x509.client_id.starts_with("x509_hash:"));
    assert!(protected.get("kid").is_none());
    assert_eq!(protected["x5c"][0], fixture["certificate"]["expected_x5c"]);
}

#[tokio::test]
async fn digital_credentials_api_request_is_origin_bound_and_encrypted() {
    let envelopes = Envelopes::default();
    let providers = FlowProviderRegistry {
        signing_identity: Some(Arc::new(Signing::default())),
        flow_key_envelope: Some(Arc::new(envelopes.clone())),
        ..Default::default()
    };
    let artifacts = PresentationRequestArtifacts {
        presentation_definition: json!({"id": "pd-1"}),
        dcql_query: json!({"credentials": [{"id": "member"}]}),
    };
    let built = build_profiled_request_object(
        &providers,
        instance("verification"),
        Some(&artifacts),
        "https://verifier.example",
        &RequestObjectOptions {
            transport: RequestObjectTransport::DigitalCredentialsApi,
            expected_origins: vec!["https://verifier.example".into()],
            ..Default::default()
        },
        now(),
    )
    .await
    .unwrap();
    let claims = payload(&built.compact_jwt);
    assert_eq!(claims["response_mode"], "dc_api.jwt");
    assert_eq!(
        claims["expected_origins"],
        json!(["https://verifier.example"])
    );
    assert!(claims.get("response_uri").is_none());
    assert!(claims.get("state").is_none());
    assert_eq!(
        claims["client_metadata"]["encrypted_response_enc_values_supported"],
        json!(["A128GCM", "A256GCM"])
    );
    assert_eq!(
        built.instance.context["dc_api_protocol"],
        "openid4vp-v1-signed"
    );
    assert_eq!(built.instance.context["dc_api_response_mode"], "dc_api.jwt");
    assert!(built.instance.context["oid4vp_response_uri"].is_null());
    assert!(
        built.instance.context["mip_messages"]["presentation_request"]["payload"]["response_uri"]
            .is_null()
    );
    assert_eq!(envelopes.requests.lock().unwrap().len(), 1);
}
