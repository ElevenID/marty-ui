//! Software signing exists only in this cfg(test) fixture. Production uses the
//! opaque SigningIdentityProvider and the distinct demo-holder grant authority.

use super::*;
use async_trait::async_trait;
use marty_oid4vci::{
    formats::sd_jwt::{
        assemble_sd_jwt, prepare_sd_jwt_with_options, verify_sd_jwt, SdJwtPreparationOptions,
    },
    signer::CredentialSigner,
    types::{CredentialClaims, SignedCredential, SigningAlgorithm},
};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

pub(super) const ORG: &str = "00000000-0000-0000-0000-000000000001";
pub(super) const POLICY_ID: &str = "00000000-0000-0000-0000-000000000018";
pub(super) const HOLDER: &str = "did:web:demo.example:holder";
pub(super) const ISSUER: &str = "did:web:demo.example:issuer";
pub(super) const VCT: &str = "urn:marty:demo:age:1";

fn key(value: u8) -> SigningKey {
    SigningKey::from_bytes((&[value; 32]).into()).unwrap()
}

pub(super) fn jwk(value: u8) -> Value {
    let point = key(value).verifying_key().to_sec1_point(false);
    json!({"kty":"EC", "crv":"P-256", "x":URL_SAFE_NO_PAD.encode(point.x().unwrap()), "y":URL_SAFE_NO_PAD.encode(point.y().unwrap())})
}

pub(super) struct OpaqueSigner {
    calls: AtomicUsize,
    corrupt: bool,
    reuse_issuer: bool,
}

impl OpaqueSigner {
    pub(super) fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            corrupt: false,
            reuse_issuer: false,
        }
    }
}

#[async_trait]
impl SigningIdentityProvider for OpaqueSigner {
    async fn resolve(
        &self,
        org: &str,
        did: &str,
        purpose: &str,
        format: &str,
        _algorithm: Option<&str>,
    ) -> Result<SigningIdentity, FlowProviderError> {
        let (number, reference) = match purpose {
            DEMO_HOLDER_PURPOSE => (if self.reuse_issuer { 3 } else { 7 }, "holder"),
            "vc_jwt_issuer" => (3, "issuer"),
            "oid4vp_request_signing" => (5, "verifier"),
            _ => panic!("unexpected signing purpose"),
        };
        Ok(SigningIdentity {
            organization_id: org.into(),
            issuer_did: did.into(),
            verification_method_id: format!("{did}#key"),
            signing_key_reference: format!("kms:{reference}"),
            public_jwk: serde_json::from_value(jwk(number)).unwrap(),
            key_purpose: purpose.into(),
            credential_format: format.into(),
            algorithm: "ES256".into(),
        })
    }

    async fn sign(
        &self,
        request: &SigningRequest,
    ) -> Result<crate::SigningResult, FlowProviderError> {
        let signing_key = match request.key_purpose.as_str() {
            DEMO_HOLDER_PURPOSE => {
                assert_eq!(request.credential_format, DEMO_HOLDER_FORMAT);
                7
            }
            "oid4vp_request_signing" => {
                assert_eq!(request.credential_format, "oauth-authz-req+jwt");
                5
            }
            _ => panic!("unexpected signing purpose"),
        };
        self.calls.fetch_add(1, Ordering::SeqCst);
        let input = URL_SAFE_NO_PAD.decode(&request.payload_b64url).unwrap();
        let signature: Signature = key(if self.corrupt { 9 } else { signing_key }).sign(&input);
        Ok(crate::SigningResult {
            issuer_did: request.issuer_did.clone(),
            verification_method_id: request.verification_method_id.clone(),
            algorithm: "ES256".into(),
            signature_raw_b64url: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }
}

#[derive(Debug)]
struct IssuerFixture {
    issuer: &'static str,
    holder_key: u8,
}

impl CredentialSigner for IssuerFixture {
    fn sign(&self, input: &[u8]) -> marty_oid4vci::error::Oid4vciResult<Vec<u8>> {
        let signature: Signature = key(3).sign(input);
        Ok(signature.to_bytes().to_vec())
    }
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::ES256
    }
    fn issuer_id(&self) -> &str {
        self.issuer
    }
    fn kid_url(&self) -> String {
        format!("{}#key", self.issuer)
    }
    fn public_jwk(&self) -> marty_oid4vci::error::Oid4vciResult<String> {
        Ok(jwk(3).to_string())
    }
}

pub(super) fn credential(issuer: &'static str, holder_key: u8) -> String {
    credential_with_lifetime(issuer, holder_key, 300)
}

fn credential_with_lifetime(issuer: &'static str, holder_key: u8, lifetime: i64) -> String {
    credential_with_type(issuer, holder_key, lifetime, VCT)
}

pub(super) fn credential_with_type(
    issuer: &'static str,
    holder_key: u8,
    lifetime: i64,
    vct: &str,
) -> String {
    credential_with_profile(issuer, holder_key, lifetime, vct, "dc+sd-jwt")
}

pub(super) fn credential_with_profile(
    issuer: &'static str,
    holder_key: u8,
    lifetime: i64,
    vct: &str,
    typ: &str,
) -> String {
    let signer = IssuerFixture { issuer, holder_key };
    let claims: CredentialClaims = serde_json::from_value(json!({
        "subject_id":HOLDER, "credential_type":vct, "claims":{"age_over_18":true,"age_over_21":false,"nickname":"do-not-disclose"},
        "expiration_seconds":lifetime, "selective_disclosure_claims":["age_over_18","age_over_21","nickname"]
    })).unwrap();
    let prepared = prepare_sd_jwt_with_options(
        &signer,
        &claims,
        SdJwtPreparationOptions {
            typ: Some(typ.into()),
            confirmation: Some(json!({"jwk":jwk(signer.holder_key)})),
            ..Default::default()
        },
    )
    .unwrap();
    let signature = signer.sign(prepared.signing_payload()).unwrap();
    let SignedCredential::SdJwt { compact, .. } = assemble_sd_jwt(prepared, &signature).unwrap()
    else {
        panic!("wrong format");
    };
    compact
}

struct Policy(Arc<AtomicBool>);
#[async_trait]
impl crate::PresentationPolicyProvider for Policy {
    async fn configuration_digest(&self, _: &str) -> Result<String, FlowProviderError> {
        Ok(format!(
            "sha256:{}",
            if self.0.load(Ordering::SeqCst) {
                "b"
            } else {
                "a"
            }
            .repeat(64)
        ))
    }
    async fn get_policy(
        &self,
        id: &str,
    ) -> Result<crate::PresentationPolicyReference, FlowProviderError> {
        Ok(crate::PresentationPolicyReference {
            configuration_digest: String::new(),
            id: id.into(),
            organization_id: ORG.into(),
            status: "active".into(),
            credential_requirements: vec![
                json!({"id":"age", "credential_template_id":"demo-age", "requested_claims":[{"claim_name":"age_over_18","required":true}]}),
            ],
        })
    }
    async fn evaluate(
        &self,
        _: &crate::PresentationEvaluationRequest,
    ) -> Result<crate::PresentationEvaluationResult, FlowProviderError> {
        panic!("holder construction must not invent a verification verdict")
    }
}

struct Templates;
#[async_trait]
impl crate::CredentialTemplateProvider for Templates {
    async fn get_template(
        &self,
        id: &str,
    ) -> Result<crate::CredentialTemplateReference, FlowProviderError> {
        Ok(crate::CredentialTemplateReference {
            id: id.into(),
            organization_id: ORG.into(),
            status: "active".into(),
            credential_type: "MartyDemoAgeCredential".into(),
            vct: VCT.into(),
            doctype: String::new(),
            supported_formats: vec!["dc+sd-jwt".into()],
            claims: Vec::new(),
            issuer_did: ISSUER.into(),
            credential_format: "dc+sd-jwt".into(),
            issuance_protocol: "OID4VCI_PRE_AUTH".into(),
            wallet_configurations: Vec::new(),
            issuer_algorithm: Some("ES256".into()),
        })
    }
    async fn wallet_formats(&self, _: &str) -> Result<Vec<String>, FlowProviderError> {
        Ok(vec!["dc+sd-jwt".into()])
    }
}

async fn setup(
    signer: Arc<OpaqueSigner>,
) -> (
    FlowProviderRegistry,
    FlowInstanceRecord,
    DemoHolder,
    DemoCredentialProfile,
    Arc<AtomicBool>,
) {
    setup_with_policy(signer, None).await
}

pub(super) async fn setup_with_policy(
    signer: Arc<OpaqueSigner>,
    policy: Option<Arc<dyn crate::PresentationPolicyProvider>>,
) -> (
    FlowProviderRegistry,
    FlowInstanceRecord,
    DemoHolder,
    DemoCredentialProfile,
    Arc<AtomicBool>,
) {
    setup_with_key(signer, policy, 13).await
}

pub(super) async fn setup_with_key(
    signer: Arc<OpaqueSigner>,
    policy: Option<Arc<dyn crate::PresentationPolicyProvider>>,
    seed: u8,
) -> (
    FlowProviderRegistry,
    FlowInstanceRecord,
    DemoHolder,
    DemoCredentialProfile,
    Arc<AtomicBool>,
) {
    let changed = Arc::new(AtomicBool::new(false));
    let providers = FlowProviderRegistry {
        signing_identity: Some(signer.clone()),
        presentation_policy: policy.or_else(|| Some(Arc::new(Policy(changed.clone())))),
        credential_template: Some(Arc::new(Templates)),
        ..Default::default()
    };
    let now = chrono::DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap();
    let mut definition = crate::create_definition_record(crate::parse_request(json!({
        "organization_id":ORG,"name":"Synthetic age example","flow_type":"oid4vp_presentation","presentation_policy_id":POLICY_ID
    })).unwrap(), now).unwrap();
    definition.status = crate::DefinitionStatus::Active;
    let binding = crate::VerificationDefinitionBinding {
        organization_id: ORG.into(),
        definition_id: definition.id.clone(),
        version: definition.version,
    };
    // The real public admission adapter installs this private binding. Use the
    // same capability binder rather than hand-writing a stored snapshot.
    let key =
        crate::PublicVerificationSessionKey::parse(&URL_SAFE_NO_PAD.encode([seed; 32])).unwrap();
    let digest = providers
        .presentation_policy
        .as_ref()
        .unwrap()
        .configuration_digest(POLICY_ID)
        .await
        .unwrap();
    let mut instance = crate::defined_verification::prepare_admitted_defined_verification_start(
        &providers,
        &Default::default(),
        &definition,
        &binding,
        "did:web:demo.example:verifier",
        &Default::default(),
        crate::VerificationStartContext {
            public_base_url: "https://demo.example",
            allow_http_loopback: false,
            principal_id: "demo-operator",
            now,
        },
        key.instance_id(ORG, "https://demo.example"),
        Some(&digest),
    )
    .await
    .unwrap()
    .instance;
    key.bind(
        &mut instance,
        "https://demo.example",
        &crate::PublicVerificationSelection {
            catalog_revision: format!("sha256:{}", "b".repeat(64)),
            scenario_id: "age".into(),
            choice_id: "over-18".into(),
            consent: true,
            example_id: None,
            request_digest: None,
        },
    )
    .unwrap();
    let holder = DemoHolder::resolve(signer.as_ref(), ORG, HOLDER)
        .await
        .unwrap();
    (
        providers,
        instance,
        holder,
        DemoCredentialProfile {
            credential_template_id: "demo-age".into(),
            issuer_did: ISSUER.into(),
            vct: VCT.into(),
        },
        changed,
    )
}

#[tokio::test]
async fn signed_example_uses_real_core_nonce_audience_binding_and_minimal_disclosure() {
    let signer = Arc::new(OpaqueSigner::new());
    let (providers, instance, holder, profile, _) = setup(signer.clone()).await;
    let proof = holder
        .issuance_proof(
            &providers,
            &instance,
            "issuer-nonce",
            "https://demo.example/org/marty-demo",
        )
        .await
        .unwrap();
    assert_eq!(proof.split('.').count(), 3);
    let input: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(proof.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(input["nonce"], "issuer-nonce");
    assert_eq!(input["aud"], "https://demo.example/org/marty-demo");
    let presentation = holder
        .presentation(&providers, &instance, &profile, &credential(ISSUER, 7))
        .await
        .unwrap();
    assert!(!format!("{presentation:?}").contains("eyJ"));
    let compact = presentation.into_compact();
    let audience = instance.context["oid4vp_client_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let nonce = instance.context["nonce"].as_str().unwrap().to_owned();
    let disclosed = verify_sd_jwt(
        &compact,
        &jwk(3).to_string(),
        Some(audience.clone()),
        Some(nonce.clone()),
    )
    .unwrap();
    assert_eq!(disclosed["credentialSubject"]["age_over_18"], true);
    assert!(disclosed["credentialSubject"].get("nickname").is_none());
    assert!(disclosed["credentialSubject"].get("age_over_21").is_none());
    assert!(verify_sd_jwt(
        &compact,
        &jwk(3).to_string(),
        Some("wrong-audience".into()),
        Some(nonce.clone())
    )
    .is_err());
    assert!(verify_sd_jwt(
        &compact,
        &jwk(3).to_string(),
        Some(audience.clone()),
        Some("wrong-nonce".into())
    )
    .is_err());
    let stripped = format!("{}~", compact.rsplit_once('~').unwrap().0);
    assert!(verify_sd_jwt(&stripped, &jwk(3).to_string(), Some(audience), Some(nonce)).is_err());
    assert_eq!(signer.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn wrong_issuer_holder_profile_and_configuration_fail_before_holder_signing() {
    let signer = Arc::new(OpaqueSigner::new());
    let (providers, instance, holder, profile, changed) = setup(signer.clone()).await;
    for credential in [
        credential("did:web:untrusted.example", 7),
        credential(ISSUER, 9),
    ] {
        assert!(matches!(
            holder
                .presentation(&providers, &instance, &profile, &credential)
                .await,
            Err(DemoHolderError::CredentialInvalid)
        ));
    }
    let mut wrong = profile.clone();
    wrong.vct = "urn:marty:demo:other".into();
    assert!(matches!(
        holder
            .presentation(&providers, &instance, &wrong, &credential(ISSUER, 7))
            .await,
        Err(DemoHolderError::ProfileInvalid)
    ));
    changed.store(true, Ordering::SeqCst);
    assert!(matches!(
        holder
            .presentation(&providers, &instance, &profile, &credential(ISSUER, 7))
            .await,
        Err(DemoHolderError::Definition(
            crate::DefinedVerificationError::ConfigurationChanged
        ))
    ));
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn opaque_signer_cannot_reuse_issuer_key_or_return_a_forged_signature() {
    let aliased = Arc::new(OpaqueSigner {
        reuse_issuer: true,
        ..OpaqueSigner::new()
    });
    let (providers, instance, holder, profile, _) = setup(aliased.clone()).await;
    assert!(matches!(
        holder
            .presentation(&providers, &instance, &profile, &credential(ISSUER, 3))
            .await,
        Err(DemoHolderError::IdentityInvalid)
    ));
    assert_eq!(aliased.calls.load(Ordering::SeqCst), 0);
    let signer = Arc::new(OpaqueSigner {
        corrupt: true,
        ..OpaqueSigner::new()
    });
    let (providers, instance, holder, profile, _) = setup(signer).await;
    assert!(matches!(
        holder
            .issuance_proof(
                &providers,
                &instance,
                "nonce",
                "https://demo.example/org/marty-demo"
            )
            .await,
        Err(DemoHolderError::SignatureInvalid)
    ));
    assert!(matches!(
        holder
            .presentation(&providers, &instance, &profile, &credential(ISSUER, 7))
            .await,
        Err(DemoHolderError::SignatureInvalid)
    ));
}

#[tokio::test]
async fn expired_signed_example_is_rejected_before_holder_presentation() {
    let signer = Arc::new(OpaqueSigner::new());
    let (providers, instance, holder, profile, _) = setup(signer.clone()).await;
    let expired = credential_with_lifetime(ISSUER, 7, -600);
    assert!(matches!(
        holder
            .presentation(&providers, &instance, &profile, &expired)
            .await,
        Err(DemoHolderError::CredentialInvalid)
    ));
    assert!(verify_sd_jwt(&expired, &jwk(3).to_string(), None, None).is_err());
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn ended_or_unbound_session_never_reaches_the_demo_signer() {
    let signer = Arc::new(OpaqueSigner::new());
    let (providers, instance, holder, _, _) = setup(signer.clone()).await;
    for variant in 0..4 {
        let mut invalid = instance.clone();
        match variant {
            0 => invalid.status = FlowInstanceStatus::Cancelled,
            1 => invalid.expires_at = Some(Utc::now() - chrono::Duration::seconds(1)),
            2 => {
                invalid
                    .context
                    .as_object_mut()
                    .unwrap()
                    .remove(crate::public_verification_session::PUBLIC_SESSION);
            }
            _ => invalid.organization_id = "other-tenant".into(),
        }
        assert!(matches!(
            holder
                .issuance_proof(
                    &providers,
                    &invalid,
                    "nonce",
                    "https://demo.example/org/marty-demo"
                )
                .await,
            Err(DemoHolderError::SessionInvalid)
        ));
    }
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
}

struct ReloadedClaims(AtomicUsize);

#[async_trait]
impl crate::PresentationPolicyProvider for ReloadedClaims {
    async fn configuration_digest(&self, _: &str) -> Result<String, FlowProviderError> {
        Ok(format!("sha256:{}", "a".repeat(64)))
    }
    async fn get_policy(
        &self,
        id: &str,
    ) -> Result<crate::PresentationPolicyReference, FlowProviderError> {
        let mut policy = Policy(Arc::new(AtomicBool::new(false)))
            .get_policy(id)
            .await?;
        if self.0.fetch_add(1, Ordering::SeqCst) > 0 {
            policy.credential_requirements[0]["requested_claims"][0]["claim_name"] =
                json!("nickname");
        }
        Ok(policy)
    }
    async fn evaluate(
        &self,
        _: &crate::PresentationEvaluationRequest,
    ) -> Result<crate::PresentationEvaluationResult, FlowProviderError> {
        panic!("not an evaluator")
    }
}

#[tokio::test]
async fn reloaded_claims_cannot_replace_the_admitted_disclosure_even_with_the_same_owner_digest() {
    let signer = Arc::new(OpaqueSigner::new());
    let (mut providers, instance, holder, profile, _) = setup(signer.clone()).await;
    providers.presentation_policy = Some(Arc::new(ReloadedClaims(AtomicUsize::new(0))));
    assert!(matches!(
        holder
            .presentation(&providers, &instance, &profile, &credential(ISSUER, 7))
            .await,
        Err(DemoHolderError::Definition(
            crate::DefinedVerificationError::InvalidSnapshot
        ))
    ));
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn example_lease_recovers_without_parallel_signing_or_unbounded_retries() {
    use crate::public_verification_example::*;
    let (_, instance, _, _, _) = setup(Arc::new(OpaqueSigner::new())).await;
    let now = Utc::now();
    let (first, owner) = claim_example(&instance, now).unwrap().unwrap();
    assert!(claim_example(&first, now).unwrap().is_none());
    let next_time = now + chrono::Duration::seconds(91);
    let (second, next_owner) = claim_example(&first, next_time).unwrap().unwrap();
    assert_ne!(owner, next_owner);
    assert!(require_example_owner(&second, owner, next_time).is_err());
    let released = finish_example_attempt(&second, next_owner, false, next_time).unwrap();
    let (third, _) = claim_example(&released, next_time).unwrap().unwrap();
    assert!(
        claim_example(&third, next_time + chrono::Duration::seconds(91))
            .unwrap()
            .is_none()
    );
    assert_eq!(third.expires_at, instance.expires_at);
    let mut cancelled = first.clone();
    cancelled.status = FlowInstanceStatus::Cancelled;
    assert!(claim_example(&cancelled, now).unwrap().is_none());
    let rejected = finish_example_attempt(&first, owner, true, now).unwrap();
    assert_eq!(
        example_status(&rejected).unwrap(),
        Some(PublicVerificationExampleStatus::InputRejected)
    );
    assert!(claim_example(&rejected, next_time).unwrap().is_none());
    let mut corrupted = first;
    corrupted.context[EXAMPLE_OPERATION] = json!({"input_rejected":false});
    assert!(claim_example(&corrupted, now).is_err());
}

#[tokio::test]
async fn example_submission_preserves_the_emitted_core_dcql_and_session_binding() {
    use crate::public_verification_example::example_submission;
    let signer = Arc::new(OpaqueSigner::new());
    let (providers, instance, holder, profile, _) = setup(signer.clone()).await;
    let ready = crate::prepare_verification_request(
        &providers,
        instance,
        "https://demo.example",
        &Default::default(),
        Utc::now(),
    )
    .await
    .unwrap();
    let crate::PreparedVerificationRequest::Ready(ready) = ready else {
        panic!("request expired");
    };
    let instance = ready.instance;
    let presentation = holder
        .presentation(&providers, &instance, &profile, &credential(ISSUER, 7))
        .await
        .unwrap()
        .into_compact();
    let input = example_submission(&instance, presentation.clone()).unwrap();
    assert!(input.presentation_submission.is_none());
    assert!(input.audience_override.is_none());
    let wire: Value = serde_json::from_str(&input.vp_token).unwrap();
    let id = instance.context["mip_messages"]["presentation_request"]["payload"]["dcql_query"]
        ["credentials"][0]["id"]
        .as_str()
        .unwrap();
    assert_eq!(wire, json!({id: [presentation]}));
    verify_sd_jwt(
        wire[id][0].as_str().unwrap(),
        &jwk(3).to_string(),
        Some(
            instance.context["oid4vp_client_id"]
                .as_str()
                .unwrap()
                .into(),
        ),
        Some(instance.context["nonce"].as_str().unwrap().into()),
    )
    .unwrap();
    assert_eq!(signer.calls.load(Ordering::SeqCst), 2);
    let mut tampered = instance.clone();
    tampered.context["mip_messages"]["presentation_request"]["payload"]["nonce"] = json!("changed");
    assert!(example_submission(&tampered, "not-a-presentation".into()).is_err());
}

#[tokio::test]
#[ignore = "requires fresh task-owned loopback marty_public_verification_test PostgreSQL"]
async fn public_example_http_uses_capability_cas_and_canonical_nonce_finalization() {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use std::str::FromStr;
    use tower::ServiceExt;
    let url =
        std::env::var("FLOW_PUBLIC_VERIFICATION_TEST_URL").expect("disposable DB URL required");
    let options = sqlx::postgres::PgConnectOptions::from_str(&url).unwrap();
    assert!(matches!(options.get_host(), "127.0.0.1" | "localhost"));
    assert_eq!(
        options.get_database(),
        Some("marty_public_verification_test")
    );
    let pool = sqlx::PgPool::connect_with(options).await.unwrap();
    sqlx::raw_sql("CREATE SCHEMA deployment_profile_service; CREATE TABLE deployment_profile_service.deployment_profiles (id text PRIMARY KEY, enabled_flow_ids jsonb NOT NULL DEFAULT '[]'::jsonb)").execute(&pool).await.unwrap();
    crate::migrate_flow_schema(&pool).await.unwrap();
    let repository = crate::PostgresFlowRepository::new(pool.clone());
    let signer = Arc::new(OpaqueSigner::new());
    let owner = Arc::new(super::policy_tests::ActualPolicy::new(
        "age_over_18",
        true,
        true,
    ));
    let digest = crate::PresentationPolicyProvider::configuration_digest(owner.as_ref(), POLICY_ID)
        .await
        .unwrap();
    let (providers, mut instance, _, profile, _) =
        setup_with_policy(signer.clone(), Some(owner)).await;
    let mut definition = crate::create_definition_record(crate::parse_request(json!({"organization_id":ORG,"name":"Synthetic age example","flow_type":"oid4vp_presentation","presentation_policy_id":POLICY_ID})).unwrap(), Utc::now()).unwrap();
    definition.id = instance.flow_definition_id.clone();
    definition.status = crate::DefinitionStatus::Active;
    repository.save_definition(&definition).await.unwrap();
    let config = json!({"principal_id":"demo-operator","issuer_did":"did:web:demo.example:verifier","demo_holder_did":HOLDER,
        "limits":{"starts_per_minute":10,"starts_per_day":100,"maximum_active":10},"catalog":{
        "organization_id":ORG,"application_origin":"https://demo.example","notice":"Present a fictional age claim.",
        "scenarios":[{"id":"age","label":"Age","choices":[{"id":"over-18","label":"18 or older", "definition":{"organization_id":ORG,"definition_id":definition.id,"version":definition.version},"presentation_policy_id":POLICY_ID,"policy_configuration_digest":digest}]}],
        "examples":[{"id":"fictional-adult","scenario_id":"age","label":"Fictional adult","description":"A signed fictional age credential.","profile":profile,"credential":credential(ISSUER,7)}]}});
    let runtime = crate::PublicVerificationOptions::from_json(&config.to_string(), false).unwrap();
    let key_string = URL_SAFE_NO_PAD.encode([13; 32]);
    let key = crate::PublicVerificationSessionKey::parse(&key_string).unwrap();
    instance
        .context
        .as_object_mut()
        .unwrap()
        .remove(crate::public_verification_session::PUBLIC_SESSION);
    // Database timestamps are microseconds, as in the public launch adapter.
    instance.expires_at = instance
        .expires_at
        .map(|v| chrono::DateTime::from_timestamp_micros(v.timestamp_micros()).unwrap());
    let catalog =
        crate::PublicVerificationCatalog::from_json(&config["catalog"].to_string(), false).unwrap();
    let preview = catalog
        .request_preview(
            &providers,
            &crate::PublicVerificationPreviewSelection {
                catalog_revision: catalog.public_view().revision.into(),
                scenario_id: "age".into(),
                choice_id: "over-18".into(),
            },
        )
        .await
        .unwrap();
    key.bind(
        &mut instance,
        "https://demo.example",
        &crate::PublicVerificationSelection {
            catalog_revision: catalog.public_view().revision.into(),
            scenario_id: "age".into(),
            choice_id: "over-18".into(),
            example_id: Some("fictional-adult".into()),
            request_digest: Some(preview.request_digest.clone()),
            consent: true,
        },
    )
    .unwrap();
    let launch_limits: crate::PublicVerificationLimits =
        serde_json::from_value(config["limits"].clone()).unwrap();
    repository
        .save_public_verification_start(&instance, launch_limits)
        .await
        .unwrap();
    let router = crate::flow_read_router(crate::FlowHttpState {
        service_authenticator: None,
        repository: repository.clone(),
        providers: Arc::new(providers),
        public_base_url: "https://demo.example".into(),
        verification: crate::FlowHttpVerificationOptions {
            public_verification: Some(runtime),
            ..Default::default()
        },
        application_approval: Default::default(),
    });
    let preview_response = router.clone().oneshot(Request::builder().method("POST").uri("/v1/flows/public/verification/preview").header("origin","https://demo.example").header("content-type","application/json").body(Body::from(json!({"catalog_revision":catalog.public_view().revision,"scenario_id":"age","choice_id":"over-18"}).to_string())).unwrap()).await.unwrap();
    assert_eq!(preview_response.status(), StatusCode::OK);
    assert_eq!(preview_response.headers()["cache-control"], "no-store");
    let public_preview: Value =
        serde_json::from_slice(&to_bytes(preview_response.into_body(), 16384).await.unwrap())
            .unwrap();
    assert_eq!(public_preview["claims"][0]["name"], "age_over_18");
    assert_eq!(public_preview["request_digest"], preview.request_digest);
    assert!(!public_preview.to_string().contains(ISSUER));
    let endpoint = format!(
        "/v1/flows/public/verification/sessions/{}/example",
        instance.id
    );
    async fn call(
        router: &axum::Router,
        path: &str,
        key: &str,
        origin: &str,
        body: &str,
    ) -> (StatusCode, Value) {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("origin", origin)
                    .header("x-verification-session", key)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_owned()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers()["cache-control"], "no-store");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 32_768).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
    assert_eq!(
        call(
            &router,
            &endpoint,
            &URL_SAFE_NO_PAD.encode([17; 32]),
            "https://demo.example",
            "{}"
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &router,
            &endpoint,
            &key_string,
            "https://attacker.example",
            "{}"
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &router,
            &endpoint,
            &key_string,
            "https://demo.example",
            r#"{"vp_token":"injected"}"#
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    // A known protocol ID must not let an external wallet substitute a
    // different credential for the consent-bound fictional specimen.
    for (method, suffix, content_type, body) in [
        ("GET", "request", "application/json", ""),
        (
            "POST",
            "submit",
            "application/x-www-form-urlencoded",
            "vp_token=injected",
        ),
        (
            "POST",
            "submit/dc-api",
            "application/json",
            r#"{"data":{"vp_token":"injected"}}"#,
        ),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(format!("/v1/flows/instances/{}/{suffix}", instance.id))
                    .header("content-type", content_type)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{suffix}");
    }
    let (first, second) = tokio::join!(
        call(
            &router,
            &endpoint,
            &key_string,
            "https://demo.example",
            "{}"
        ),
        call(
            &router,
            &endpoint,
            &key_string,
            "https://demo.example",
            "{}"
        )
    );
    assert!(
        matches!(first.0, StatusCode::OK | StatusCode::ACCEPTED),
        "{first:?}"
    );
    assert!(
        matches!(second.0, StatusCode::OK | StatusCode::ACCEPTED),
        "{second:?}"
    );
    let (status, result) = call(
        &router,
        &endpoint,
        &key_string,
        "https://demo.example",
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["status"], "completed");
    assert_eq!(result["verified"], true);
    assert!(result.get("wallet_uri").is_none());
    assert!(result.get("example_status").is_none());
    assert!(!result.to_string().contains("eyJ") && !result.to_string().contains("nickname"));
    assert_eq!(
        signer.calls.load(Ordering::SeqCst),
        2,
        "one request signature and one holder signature, even with retries"
    );
    let stored = repository.instance(&instance.id).await.unwrap().unwrap();
    assert_eq!(stored.status, FlowInstanceStatus::Completed);
    assert_eq!(
        stored.result.as_ref().unwrap()["evaluation_result"],
        "passed"
    );
    assert!(stored.result.as_ref().unwrap()["submission_digest"].is_string());
    pool.close().await;
}
