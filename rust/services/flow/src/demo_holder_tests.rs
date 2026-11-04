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

const ORG: &str = "marty-demo";
const HOLDER: &str = "did:web:demo.example:holder";
const ISSUER: &str = "did:web:demo.example:issuer";
const VCT: &str = "urn:marty:demo:age:1";

fn key(value: u8) -> SigningKey {
    SigningKey::from_bytes((&[value; 32]).into()).unwrap()
}

fn jwk(value: u8) -> Value {
    let point = key(value).verifying_key().to_sec1_point(false);
    json!({"kty":"EC", "crv":"P-256", "x":URL_SAFE_NO_PAD.encode(point.x().unwrap()), "y":URL_SAFE_NO_PAD.encode(point.y().unwrap())})
}

struct OpaqueSigner {
    calls: AtomicUsize,
    corrupt: bool,
    reuse_issuer: bool,
}

impl OpaqueSigner {
    fn new() -> Self {
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
        assert_eq!(request.key_purpose, DEMO_HOLDER_PURPOSE);
        assert_eq!(request.credential_format, DEMO_HOLDER_FORMAT);
        self.calls.fetch_add(1, Ordering::SeqCst);
        let input = URL_SAFE_NO_PAD.decode(&request.payload_b64url).unwrap();
        let signature: Signature = key(if self.corrupt { 9 } else { 7 }).sign(&input);
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

fn credential(issuer: &'static str, holder_key: u8) -> String {
    credential_with_lifetime(issuer, holder_key, 300)
}

fn credential_with_lifetime(issuer: &'static str, holder_key: u8, lifetime: i64) -> String {
    let signer = IssuerFixture { issuer, holder_key };
    let claims: CredentialClaims = serde_json::from_value(json!({
        "subject_id":HOLDER, "credential_type":VCT, "claims":{"age_over_18":true,"age_over_21":false,"nickname":"do-not-disclose"},
        "expiration_seconds":lifetime, "selective_disclosure_claims":["age_over_18","age_over_21","nickname"]
    })).unwrap();
    let prepared = prepare_sd_jwt_with_options(
        &signer,
        &claims,
        SdJwtPreparationOptions {
            typ: Some("dc+sd-jwt".into()),
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
    let changed = Arc::new(AtomicBool::new(false));
    let providers = FlowProviderRegistry {
        signing_identity: Some(signer.clone()),
        presentation_policy: Some(Arc::new(Policy(changed.clone()))),
        credential_template: Some(Arc::new(Templates)),
        ..Default::default()
    };
    let now = Utc::now();
    let mut definition = crate::create_definition_record(crate::parse_request(json!({
        "organization_id":ORG,"name":"Synthetic age example","flow_type":"oid4vp_presentation","presentation_policy_id":"demo-policy"
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
        crate::PublicVerificationSessionKey::parse(&URL_SAFE_NO_PAD.encode([13; 32])).unwrap();
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
        Some(&format!("sha256:{}", "a".repeat(64))),
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
