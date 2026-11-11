//! Exercise the native signed boundary, controlled metadata and Core decision
//! together. Test signing keys are never part of the production verifier.
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use marty_oid4vp_contract::{digest_query_document, Oid4vpEvaluationTransportV1, QueryKind};
use marty_presentation_policy::{
    built_in_presentation_policies, evaluate_verified_facts_for_policy, AlternativeRequirement,
    CredentialStatusEvidence, CredentialStatusResolver, EvaluatePresentationRequest, HolderBinding,
    IssuerTrustEvidence, NativePresentationControlPlane, PresentationPolicy,
    PresentationTrustResolver, PresentationVerificationError, PresentationVerificationOrchestrator,
    ResolvedCredentialTemplate, ResolvedTrustProfile, ResolvedVerificationPolicy,
    RustCredentialKernel, VerifiedFactsOrchestrator,
};
use marty_verification::credential_format::DetectedCredentialFormat;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const ORG: Uuid = Uuid::from_u128(1);
const PROFILE_A: Uuid = Uuid::from_u128(2);
const PROFILE_B: Uuid = Uuid::from_u128(3);
const POLICY_SET: Uuid = Uuid::from_u128(4);
const TEMPLATE: &str = "employee-template";
const ISSUER: &str = "did:web:issuer.example";
const KID: &str = "did:web:issuer.example#assertion";
const EMPLOYEE: &str = "https://issuer.example/employee";
const NONCE: &str = "frozen-verifier-nonce-with-32-bytes";
const AUDIENCE: &str = "https://verifier.example";

fn public_key(key: &SigningKey) -> Value {
    json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),"kid":KID})
}

fn jwt(key: &SigningKey, header: Value, claims: Value) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes())
    )
}

fn presentation(key: &SigningKey, credential_type: &str, bound: bool) -> String {
    presentation_with_id(key, credential_type, bound, "urn:uuid:employee-credential")
}

fn presentation_with_id(key: &SigningKey, credential_type: &str, bound: bool, id: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let holder = SigningKey::from_bytes(&[91; 32]);
    let token = jwt(
        key,
        json!({"alg":"EdDSA","kid":KID,"typ":"dc+sd-jwt"}),
        json!({
        "iss":ISSUER, "sub":"employee-subject", "jti":id, "iat":now-60,"nbf":now-60,"exp":now+3600,
            "vct":credential_type,"email":"employee@example.com","_sd":[],"_sd_alg":"sha-256",
            "_compliance_code":"ACCREDITED",
            "cnf":{"jwk":public_key(&holder)},
        }),
    );
    let sd_jwt = format!("{token}~");
    if !bound {
        return sd_jwt;
    }
    let kb = jwt(
        &holder,
        json!({"alg":"EdDSA","typ":"kb+jwt"}),
        json!({
            "iat":now,"aud":AUDIENCE,"nonce":NONCE,"sd_hash":URL_SAFE_NO_PAD.encode(Sha256::digest(sd_jwt.as_bytes())),
        }),
    );
    format!("{sd_jwt}{kb}")
}

struct Metadata {
    profiles: BTreeMap<Uuid, Value>,
    policies: BTreeMap<Uuid, String>,
    loaded_profiles: Mutex<Vec<Uuid>>,
}

impl Metadata {
    fn new(key: &SigningKey) -> Self {
        let document = json!({
            "status":"ACTIVE","allowed_algorithms":["EdDSA"],
            "issuer_relationships":[{"issuer_id":ISSUER,"relationship_status":"TRUSTED",
                "compliance_status":"ACCREDITED","valid_from":"2020-01-01T00:00:00Z","trust_level":80,
                "accreditations":[],"revoked_at":null,"verification_keys":[public_key(key)]}],
        });
        Self {
            profiles: BTreeMap::from([(PROFILE_A, document.clone()), (PROFILE_B, document)]),
            policies: BTreeMap::new(),
            loaded_profiles: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl PresentationTrustResolver for Metadata {
    async fn load_profile(
        &self,
        id: Uuid,
        organization_id: Uuid,
    ) -> Result<ResolvedTrustProfile, PresentationVerificationError> {
        assert_eq!(organization_id, ORG);
        self.loaded_profiles.lock().unwrap().push(id);
        let document = self
            .profiles
            .get(&id)
            .cloned()
            .ok_or(PresentationVerificationError::Unavailable)?;
        Ok(ResolvedTrustProfile {
            id,
            organization_id,
            document,
        })
    }

    async fn evaluate_issuer(
        &self,
        profile: &ResolvedTrustProfile,
        issuer: &str,
        format: DetectedCredentialFormat,
    ) -> Result<IssuerTrustEvidence, PresentationVerificationError> {
        // Use the production trust evaluator; the test adapter supplies only
        // controlled metadata and never fabricates a successful trust result.
        NativePresentationControlPlane::connect_lazy(
            "http://127.0.0.1:9",
            "http://127.0.0.1:9",
            "http://127.0.0.1:9/{credential_id}",
            None,
            None,
            Duration::from_secs(1),
        )?
        .evaluate_issuer(profile, issuer, format)
        .await
    }

    async fn load_credential_template(
        &self,
        id: &str,
        organization_id: Uuid,
    ) -> Result<ResolvedCredentialTemplate, PresentationVerificationError> {
        assert_eq!(id, TEMPLATE);
        assert_eq!(organization_id, ORG);
        Ok(ResolvedCredentialTemplate {
            id: id.into(),
            organization_id,
            credential_type: "EmployeeCredential".into(),
            vct: Some(EMPLOYEE.into()),
            doctype: None,
            status: "ACTIVE".into(),
        })
    }

    async fn load_verification_policy(
        &self,
        id: Uuid,
        organization_id: Uuid,
    ) -> Result<ResolvedVerificationPolicy, PresentationVerificationError> {
        assert_eq!(organization_id, ORG);
        let source = self
            .policies
            .get(&id)
            .cloned()
            .ok_or(PresentationVerificationError::Unavailable)?;
        Ok(ResolvedVerificationPolicy {
            id,
            organization_id,
            revision: format!("sha256:{}", hex::encode(Sha256::digest(source.as_bytes()))),
            cedar_policies: source,
        })
    }
}

#[async_trait]
impl CredentialStatusResolver for Metadata {
    async fn resolve(
        &self,
        _: Uuid,
        _: &str,
        _: &[String],
    ) -> Result<CredentialStatusEvidence, PresentationVerificationError> {
        Ok(CredentialStatusEvidence::default())
    }
}

fn policy() -> PresentationPolicy {
    let mut policy = built_in_presentation_policies(uuid::Uuid::from_u128(1)).remove(1);
    policy.organization_id = ORG;
    policy.trust_profile_id = Some(PROFILE_A);
    policy.presentation_proof_required = false;
    policy.holder_binding = HolderBinding::default();
    policy.credential_requirements[0].credential_template_id = TEMPLATE.into();
    policy.credential_requirements[0].trust_profile_id = None;
    policy.credential_requirements[0].credential_payload_format = "ietf_sd_jwt".into();
    policy.accepted_credential_types.clear();
    policy
}

fn request(token: String) -> EvaluatePresentationRequest {
    EvaluatePresentationRequest {
        vp_token: json!(token),
        trust_profile_id: None,
        nonce: None,
        audience: None,
        context: Map::new(),
        oid4vp_transport: None,
        trusted_internal_context: false,
    }
}

fn orchestrator(metadata: Arc<Metadata>) -> VerifiedFactsOrchestrator {
    VerifiedFactsOrchestrator::new(Arc::new(RustCredentialKernel), metadata.clone(), metadata)
        .unwrap()
}

fn decision(
    facts: Value,
    policy: &PresentationPolicy,
    request: &EvaluatePresentationRequest,
) -> Value {
    evaluate_verified_facts_for_policy(facts, policy, request).unwrap()["decision"].clone()
}

#[tokio::test]
async fn authenticated_vct_must_match_resolved_template_and_accepted_type_policy() {
    let key = SigningKey::from_bytes(&[90; 32]);
    let verifier = orchestrator(Arc::new(Metadata::new(&key)));
    let mut policy = policy();
    for (vct, expected) in [
        (EMPLOYEE, "allow"),
        ("https://issuer.example/newsletter", "deny"),
    ] {
        let request = request(presentation(&key, vct, false));
        let facts = verifier.verify(&policy, &request).await.unwrap();
        assert_eq!(
            facts["credentials"][0]["signature_verified"], true,
            "{facts}"
        );
        assert_eq!(facts["credentials"][0]["credential_types"], json!([vct]));
        assert_eq!(
            facts["credentials"][0]["credential_template_ids"],
            if vct == EMPLOYEE {
                json!([TEMPLATE])
            } else {
                json!([])
            }
        );
        assert_eq!(decision(facts, &policy, &request), expected);
    }
    // Inline accepted types are alternatives, not a fabricated template ID
    // equal to only the first allowed type.
    policy.required_claims = policy.credential_requirements[0].requested_claims.clone();
    policy.credential_requirements[0].credential_template_id = "protocol-inline".into();
    policy.accepted_credential_types =
        vec![EMPLOYEE.into(), "https://issuer.example/contractor".into()];
    let request = request(presentation(
        &key,
        "https://issuer.example/contractor",
        false,
    ));
    let facts = verifier.verify(&policy, &request).await.unwrap();
    assert_eq!(decision(facts, &policy, &request), "allow");
    policy.required_claims[0].description = Some(format!("credential_type:{EMPLOYEE}"));
    policy.credential_requirements[0].requested_claims = policy.required_claims.clone();
    let facts = verifier.verify(&policy, &request).await.unwrap();
    assert_eq!(decision(facts, &policy, &request), "deny");
}

#[tokio::test]
async fn caller_override_cannot_replace_profile_and_mixed_profiles_keep_separate_evidence() {
    let key = SigningKey::from_bytes(&[90; 32]);
    let mut metadata = Metadata::new(&key);
    metadata.profiles.get_mut(&PROFILE_B).unwrap()["denied_issuers"] = json!([ISSUER]);
    let metadata = Arc::new(metadata);
    let verifier = orchestrator(metadata.clone());
    let mut policy = policy();
    let mut request = request(presentation(&key, EMPLOYEE, false));
    request.trust_profile_id = Some(PROFILE_B.to_string());
    assert!(verifier.verify(&policy, &request).await.is_err());
    assert!(metadata.loaded_profiles.lock().unwrap().is_empty());
    request.trust_profile_id = None;
    let mut second = policy.credential_requirements[0].clone();
    second.id = Uuid::from_u128(9);
    second.trust_profile_id = Some(PROFILE_B);
    policy.credential_requirements.push(second);
    let facts = verifier.verify(&policy, &request).await.unwrap();
    assert_eq!(facts["presentation_count"], 1);
    assert_eq!(facts["credentials"].as_array().unwrap().len(), 2);
    assert_eq!(
        facts["credentials"][0]["trust_profile_id"],
        json!(PROFILE_A)
    );
    assert_eq!(facts["credentials"][0]["trust_profile_verified"], true);
    assert_eq!(
        facts["credentials"][1]["trust_profile_id"],
        json!(PROFILE_B)
    );
    assert_eq!(facts["credentials"][1]["trust_profile_verified"], false);
    assert_ne!(decision(facts, &policy, &request), "allow");
}

#[tokio::test]
async fn signed_algorithm_is_restricted_by_resolved_profile() {
    let key = SigningKey::from_bytes(&[90; 32]);
    let mut metadata = Metadata::new(&key);
    metadata.profiles.get_mut(&PROFILE_A).unwrap()["allowed_algorithms"] = json!(["ES256"]);
    let request = request(presentation(&key, EMPLOYEE, false));
    let policy = policy();
    let facts = orchestrator(Arc::new(metadata))
        .verify(&policy, &request)
        .await
        .unwrap();
    assert_eq!(facts["credentials"][0]["signature_verified"], false);
    assert_eq!(decision(facts, &policy, &request), "deny");
}

#[tokio::test]
async fn signed_compliance_code_cannot_satisfy_an_unresolved_profile_selector() {
    let key = SigningKey::from_bytes(&[90; 32]);
    let verifier = orchestrator(Arc::new(Metadata::new(&key)));
    let request = request(presentation(&key, EMPLOYEE, false));
    let mut policy = policy();
    let facts = verifier.verify(&policy, &request).await.unwrap();
    assert_eq!(decision(facts.clone(), &policy, &request), "allow");
    policy.compliance_profile_id = Some(Uuid::from_u128(42));
    assert!(policy
        .validate()
        .unwrap_err()
        .to_string()
        .contains("ComplianceProfile"));
    assert!(verifier
        .verify(&policy, &request)
        .await
        .unwrap_err()
        .to_string()
        .contains("ComplianceProfile"));
    assert!(evaluate_verified_facts_for_policy(facts, &policy, &request).is_err());
}

#[tokio::test]
async fn saved_predicate_fallback_reaches_core_for_authenticated_claims() {
    let key = SigningKey::from_bytes(&[90; 32]);
    let verifier = orchestrator(Arc::new(Metadata::new(&key)));
    let request = request(presentation(&key, EMPLOYEE, false));
    let mut policy = policy();
    policy.supported_circuits = vec!["email-equality-v1".into()];
    for (fallback, target, expected) in [
        ("ACCEPT_RAW", "employee@example.com", "allow"),
        ("ACCEPT_RAW", "other@example.com", "deny"),
        ("DENY", "employee@example.com", "deny"),
    ] {
        policy.fallback_policy = Some(fallback.into());
        policy.credential_requirements[0].requested_claims[0].predicate_spec = Some(json!({
            "predicate_type":"EQUALITY", "params":{"target_value":target}
        }));
        policy.validate().unwrap();
        let facts = verifier.verify(&policy, &request).await.unwrap();
        assert_eq!(
            decision(facts, &policy, &request),
            expected,
            "{fallback}: {target}"
        );
    }
    policy.fallback_policy = Some("REQUIRE_PREDICATE".into());
    assert!(policy.validate().is_err());
    assert!(verifier.verify(&policy, &request).await.is_err());
}

#[tokio::test]
async fn linked_policy_is_executed_and_unavailable_or_invalid_links_fail_closed() {
    let key = SigningKey::from_bytes(&[90; 32]);
    let policy = policy();
    let request = request(presentation(&key, EMPLOYEE, false));
    for source in [
        None,
        Some("not Cedar"),
        Some("permit(principal, action, resource); forbid(principal, action, resource);"),
    ] {
        let mut metadata = Metadata::new(&key);
        metadata.profiles.get_mut(&PROFILE_A).unwrap()["verification_policy_set_id"] =
            json!(POLICY_SET);
        if let Some(source) = source {
            metadata.policies.insert(POLICY_SET, source.into());
        }
        let result = orchestrator(Arc::new(metadata))
            .verify(&policy, &request)
            .await;
        if source.is_none() || source == Some("not Cedar") {
            assert!(result.is_err());
        } else {
            let facts = result.unwrap();
            assert_eq!(
                facts["credentials"][0]["external_authorization"]["evaluated"],
                true
            );
            assert_eq!(
                facts["credentials"][0]["external_authorization"]["allowed"],
                false
            );
            assert_eq!(decision(facts, &policy, &request), "deny");
        }
    }
}

#[tokio::test]
async fn candidate_policy_denial_does_not_veto_a_satisfied_alternative() {
    let key = SigningKey::from_bytes(&[90; 32]);
    let mut metadata = Metadata::new(&key);
    metadata.profiles.get_mut(&PROFILE_B).unwrap()["verification_policy_set_id"] =
        json!(POLICY_SET);
    metadata
        .policies
        .insert(POLICY_SET, "forbid(principal, action, resource);".into());
    let mut policy = policy();
    let mut alternate = policy.credential_requirements[0].clone();
    alternate.id = Uuid::from_u128(10);
    alternate.trust_profile_id = Some(PROFILE_B);
    policy
        .alternative_requirements
        .push(AlternativeRequirement {
            id: Uuid::from_u128(11),
            name: "Either profile".into(),
            description: None,
            credential_requirements: vec![policy.credential_requirements[0].clone(), alternate],
            min_satisfied: 1,
        });
    policy.credential_requirements.clear();
    let request = request(presentation(&key, EMPLOYEE, false));
    let facts = orchestrator(Arc::new(metadata))
        .verify(&policy, &request)
        .await
        .unwrap();
    assert!(facts["external_authorization"].is_null());
    assert_eq!(
        facts["credentials"][1]["external_authorization"]["allowed"],
        false
    );
    assert_eq!(decision(facts, &policy, &request), "allow");
}

#[tokio::test]
async fn full_dcql_response_must_match_signed_type_claims_and_binding() {
    let key = SigningKey::from_bytes(&[90; 32]);
    let verifier = orchestrator(Arc::new(Metadata::new(&key)));
    let mut policy = policy();
    policy.credential_requirements[0].credential_payload_format = "SD_JWT_VC".into();
    let query_id = policy.credential_requirements[0].id.to_string();
    let token = presentation(&key, EMPLOYEE, true);
    let query = json!({"credentials":[{"id":query_id,"format":"dc+sd-jwt","meta":{"vct_values":[EMPLOYEE]},"claims":[{"id":"email","path":["email"]}]}]});
    let transport = Oid4vpEvaluationTransportV1 {
        credential_authority: None,
        query_kind: QueryKind::Dcql,
        query_digest: digest_query_document(&query).unwrap(),
        query_document: query,
        presentation_submission: None,
        vp_token_raw: json!({(query_id.clone()):[token]}).to_string(),
        verifier_client_id: AUDIENCE.into(),
        request_nonce: NONCE.into(),
    };
    let mut request = request(token);
    request.nonce = Some(NONCE.into());
    request.audience = Some(AUDIENCE.into());
    request.trusted_internal_context = true;
    request.context = Map::from_iter([
        ("oid4vp_verifier_context".into(), json!(true)),
        ("replay_check_verified".into(), json!(true)),
    ]);
    request.oid4vp_transport = Some(transport.clone());
    let facts = verifier.verify(&policy, &request).await.unwrap();
    assert_eq!(decision(facts, &policy, &request), "allow");
    // The opaque native SD-JWT/DCQL producer supports exactly one item.
    let mut multiple = request.clone();
    multiple.oid4vp_transport.as_mut().unwrap().vp_token_raw =
        json!({(query_id.clone()):[request.vp_token,
        presentation_with_id(&key,EMPLOYEE,true,"urn:uuid:second-employee")]})
        .to_string();
    assert!(verifier.verify(&policy, &multiple).await.is_err());
    // General PE association authenticates and retains all items before Core
    // enforces the saved policy's one-presentation limit.
    let query = json!({"id":"employees","input_descriptors":[
        {"id":"first","format":{"dc+sd-jwt":{}},"constraints":{"fields":[{"path":["$.email"]}]}},
        {"id":"second","format":{"dc+sd-jwt":{}},"constraints":{"fields":[{"path":["$.email"]}]}}
    ]});
    multiple.oid4vp_transport = Some(Oid4vpEvaluationTransportV1 {
        credential_authority: None,
        query_kind: QueryKind::PresentationExchange,
        query_digest: digest_query_document(&query).unwrap(),
        query_document: query,
        presentation_submission: Some(
            json!({"id":"response","definition_id":"employees","descriptor_map":[
            {"id":"first","format":"dc+sd-jwt","path":"$[0]"},{"id":"second","format":"dc+sd-jwt","path":"$[1]"}]}),
        ),
        vp_token_raw: json!([
            request.vp_token,
            presentation_with_id(&key, EMPLOYEE, true, "urn:uuid:second-employee")
        ])
        .to_string(),
        verifier_client_id: AUDIENCE.into(),
        request_nonce: NONCE.into(),
    });
    multiple.vp_token = json!(multiple.oid4vp_transport.as_ref().unwrap().vp_token_raw);
    let facts = verifier.verify(&policy, &multiple).await.unwrap();
    assert_eq!(facts["presentation_count"], 2);
    assert_eq!(facts["credentials"].as_array().unwrap().len(), 2);
    assert!(facts["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .all(|item| item["signature_verified"] == true));
    assert_eq!(decision(facts, &policy, &multiple), "deny");
    for mutation in 0..5 {
        let mut altered = request.clone();
        let transport = altered.oid4vp_transport.as_mut().unwrap();
        match mutation {
            0 => transport.vp_token_raw = json!({"unrequested":[request.vp_token]}).to_string(),
            1 => {
                transport.query_document["credentials"][0]["meta"]["vct_values"] =
                    json!(["https://issuer.example/manager"])
            }
            2 => {
                transport.query_document["credentials"][0]["claims"][0]["path"] = json!(["missing"])
            }
            3 => {
                transport.vp_token_raw =
                    json!({(query_id.clone()):[request.vp_token,"unverified.extra.token~"]})
                        .to_string()
            }
            _ => transport.request_nonce = "another-nonce".into(),
        }
        transport.query_digest = digest_query_document(&transport.query_document).unwrap();
        match verifier.verify(&policy, &altered).await {
            Err(_) => {}
            Ok(facts) => assert_eq!(
                decision(facts, &policy, &altered),
                "deny",
                "mutation {mutation}"
            ),
        }
    }
}
