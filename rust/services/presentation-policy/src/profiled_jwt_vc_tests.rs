//! Deterministic synthetic issuer/holder keys and actual native signatures.
use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use marty_oid4vp_contract::jwt_vc_profile::{
    policy_credential_format, JwtVcProfileBinding, JwtVcSecuringProfile,
};
use marty_oid4vp_contract::{digest_query_document, Oid4vpEvaluationTransportV1, QueryKind};
use marty_verification::credential_format::DetectedCredentialFormat;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::*;

const NOW: i64 = 1_787_240_300;
const ISSUER: &str = "did:web:issuer.example";
const KID: &str = "did:web:issuer.example#assertion";
const CREDENTIAL_ID: &str = "urn:uuid:4c57ec28-bae8-4b22-9ff7-d041daefb2ca";

fn sign(signer: &SigningKey, header: Value, claims: Value) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(signer.sign(input.as_bytes()).to_bytes())
    )
}

fn claims(token: &str) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}

fn fixture(
    profile: JwtVcSecuringProfile,
    signature_expires: i64,
    credential_until: i64,
    proof_expires: i64,
) -> (
    PresentationPolicy,
    EvaluatePresentationRequest,
    CredentialVerificationContext,
) {
    let issuer_signer = SigningKey::from_bytes(&[61; 32]);
    let holder_signer = SigningKey::from_bytes(&[62; 32]);
    let issuer_public = json!({"kty":"OKP", "crv":"Ed25519", "kid":KID, "x":URL_SAFE_NO_PAD.encode(issuer_signer.verifying_key().to_bytes())});
    let holder_public = json!({"kty":"OKP", "crv":"Ed25519", "x":URL_SAFE_NO_PAD.encode(holder_signer.verifying_key().to_bytes())});
    let holder = format!(
        "did:jwk:{}",
        URL_SAFE_NO_PAD.encode(holder_public.to_string())
    );
    let mut document = json!({
        "@context":["https://www.w3.org/ns/credentials/v2"], "type":["VerifiableCredential","MemberCredential"],
        "id":CREDENTIAL_ID, "issuer":ISSUER, "credentialSubject":{"id":holder,"email":"synthetic-profile@example.test"},
        "validFrom":chrono::DateTime::from_timestamp(NOW-30,0).unwrap().to_rfc3339(),
        "validUntil":chrono::DateTime::from_timestamp(credential_until,0).unwrap().to_rfc3339()
    });
    let direct = profile == JwtVcSecuringProfile::W3cVc2Jose2026V1;
    let inner_claims = if direct {
        document.as_object_mut().unwrap().extend(json!({"iss":ISSUER,"sub":holder,"jti":CREDENTIAL_ID,"iat":NOW-20,"exp":signature_expires}).as_object().unwrap().clone());
        document
    } else {
        json!({"iss":ISSUER,"sub":holder,"jti":CREDENTIAL_ID,"iat":NOW-30,"nbf":NOW-30,"exp":signature_expires,"vc":document})
    };
    let inner = sign(
        &issuer_signer,
        if direct {
            json!({"alg":"EdDSA","typ":"vc+jwt","cty":"vc","kid":KID})
        } else {
            json!({"alg":"EdDSA","typ":"JWT","kid":KID})
        },
        inner_claims,
    );
    let nonce = "source-owned-profile-nonce-0123456789";
    let audience = "https://verifier.example";
    let presentation_id = "urn:uuid:f4eafca6-d4d7-4b6a-8328-c54899e9aa71";
    let mut outer_claims = json!({"iss":holder,"sub":holder,"aud":audience,"nonce":nonce,"iat":NOW-1,"exp":proof_expires,"jti":presentation_id});
    let mut vp = json!({"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiablePresentation"],"holder":holder});
    if direct {
        vp["id"] = json!(presentation_id);
        vp["verifiableCredential"] = json!([{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["EnvelopedVerifiableCredential"],"id":format!("data:application/vc+jwt,{inner}")}]);
        outer_claims
            .as_object_mut()
            .unwrap()
            .extend(vp.as_object().unwrap().clone());
    } else {
        vp["verifiableCredential"] = json!([inner]);
        outer_claims["vp"] = vp;
        outer_claims["nbf"] = json!(NOW - 1);
    }
    let outer = sign(
        &holder_signer,
        if direct {
            json!({"alg":"EdDSA","typ":"vp+jwt","cty":"vp","jwk":holder_public})
        } else {
            json!({"alg":"EdDSA","typ":"JWT","jwk":holder_public})
        },
        outer_claims,
    );
    let mut policy = built_in_presentation_policies(Uuid::from_u128(1)).remove(0);
    policy.organization_id = Uuid::from_u128(1);
    policy.status = PolicyStatus::Active;
    policy.credential_requirements.truncate(1);
    let requirement = &mut policy.credential_requirements[0];
    requirement.id = Uuid::from_u128(5);
    requirement.credential_template_id = "template-profiled".into();
    requirement.required = true;
    requirement.credential_payload_format = policy_credential_format(profile).into();
    requirement.expected_securing_profile = Some(profile);
    requirement.requested_claims.clear();
    requirement.trust_profile_id = None;
    requirement.max_age_seconds = None;
    requirement.require_fresh_issuance = false;
    policy.required_claims.clear();
    policy.accepted_credential_types.clear();
    policy.alternative_requirements.clear();
    policy.prerequisite_evidence_profile = None;
    policy.presentation_proof_required = false;
    policy.compliance_profile_id = None;
    policy.trust_profile_id = Some(Uuid::from_u128(2));
    policy.holder_binding = HolderBinding {
        required: true,
        ..Default::default()
    }
    .normalize();
    policy.freshness = Some(FreshnessPolicy {
        max_age_seconds: None,
        require_not_revoked: true,
        revocation_grace_seconds: None,
    });
    policy.issuer_constraints = None;
    policy.fallback_policy = None;
    policy.supported_circuits.clear();
    policy.validate().unwrap();
    let query = json!({"credentials":[marty_oid4vci::presentation_request::build_profiled_jwt_vc_query(&Uuid::from_u128(5).to_string(), JwtVcProfileBinding::new(profile), vec![vec!["VerifiableCredential".into(),"MemberCredential".into()]], true).unwrap()]});
    let request = EvaluatePresentationRequest {
        vp_token: json!(outer),
        trust_profile_id: None,
        nonce: Some(nonce.into()),
        audience: Some(audience.into()),
        context: json!({"oid4vp_verifier_context":true,"replay_check_verified":true})
            .as_object()
            .unwrap()
            .clone(),
        trusted_internal_context: true,
        oid4vp_transport: Some(Oid4vpEvaluationTransportV1 {
            credential_authority: None,
            query_kind: QueryKind::Dcql,
            query_digest: digest_query_document(&query).unwrap(),
            query_document: query,
            presentation_submission: None,
            vp_token_raw: outer,
            verifier_client_id: audience.into(),
            request_nonce: nonce.into(),
        }),
    };
    let context = CredentialVerificationContext {
        profiled_jwt_vc: ProfiledJwtVcRequest::prepare(&policy, &request, || NOW as u64).unwrap(),
        presentation_only: false,
        sd_jwt_dcql: None,
        resolved_issuer_key: None,
        format: DetectedCredentialFormat::W3cVc,
        token: request.vp_token.clone(),
        nonce: request.nonce.clone(),
        audience: request.audience.clone(),
        verifier_context: request.context.clone(),
        trust_profile: Some(ResolvedTrustProfile {
            id: Uuid::from_u128(2),
            organization_id: Uuid::from_u128(1),
            document: json!({"status":"active","allowed_algorithms":["EdDSA"],"system_issuer_overrides":{ISSUER:{"public_jwk":issuer_public}}}),
        }),
    };
    (policy, request, context)
}

struct NoPublic;
#[async_trait]
impl marty_issuer_key_resolution::IssuerKeyResolver for NoPublic {
    async fn resolve(
        &self,
        _: &str,
    ) -> Result<
        marty_issuer_key_resolution::IssuerKeyResolution,
        marty_issuer_key_resolution::IssuerKeyResolutionError,
    > {
        panic!("a bound profile must not fall back to public resolution")
    }
}

#[tokio::test]
async fn explicit_profiles_authenticate_real_holder_and_issuer_signatures_and_preserve_legacy() {
    for profile in [
        JwtVcSecuringProfile::MartyNestedVc2JwtV1,
        JwtVcSecuringProfile::W3cVc2Jose2026V1,
    ] {
        let (_, _, context) = fixture(profile, NOW + 3600, NOW + 7200, NOW + 59);
        let evidence = ResolvingCredentialKernel::new(Arc::new(NoPublic))
            .verify(&context)
            .await
            .unwrap();
        assert!(evidence.verified, "{:?}", evidence.failure_reason);
        assert!(
            evidence.holder_binding_verified
                && evidence.presentation_verified
                && evidence.challenge_verified
                && evidence.audience_verified
        );
        assert_eq!(evidence.credential_id.as_deref(), Some(CREDENTIAL_ID));
        assert_eq!(evidence.proof_epoch_seconds, Some((NOW - 1) as u64));
        let retained = evidence.authenticated_profiled_jwt_vc.as_ref().unwrap();
        assert!(retained.matches(
            context.profiled_jwt_vc.as_ref().unwrap(),
            context.token.as_str().unwrap(),
            &evidence
        ));
        retained.revalidate_at(NOW as u64).unwrap();
        assert!(retained.revalidate_at((NOW + 59) as u64).is_err());
        let debug = format!("{context:?} {evidence:?} {retained:?}");
        assert!(!debug.contains(context.token.as_str().unwrap()));
        assert!(!debug.contains("synthetic-profile@example.test"));
        let restored: CredentialVerificationEvidence =
            serde_json::from_value(serde_json::to_value(&evidence).unwrap()).unwrap();
        assert!(restored.authenticated_profiled_jwt_vc.is_none());
        if profile == JwtVcSecuringProfile::W3cVc2Jose2026V1 {
            assert!(evidence
                .authenticated_document
                .as_ref()
                .unwrap()
                .get("vc")
                .is_none());
            assert_eq!(evidence.issued_at_epoch_seconds, Some((NOW - 20) as u64));
        } else {
            let mut legacy = context.clone();
            legacy.profiled_jwt_vc = None;
            // The historical verifier owns a real clock, so only its frozen
            // wire contract is compared here; its existing live-clock positive
            // fixtures remain in native_kernel's unchanged freshness suite.
            assert_eq!(
                marty_oid4vci::presented_jwt_vc(legacy.token.as_str().unwrap()).unwrap(),
                marty_oid4vci::presented_jwt_vc_with_profile(
                    context.token.as_str().unwrap(),
                    profile
                )
                .unwrap()
            );
        }
    }
}

#[tokio::test]
async fn explicit_profile_native_rejects_bare_crossed_tampered_and_independently_expired_material()
{
    let profile = JwtVcSecuringProfile::W3cVc2Jose2026V1;
    let (_, _, original) = fixture(profile, NOW + 3600, NOW + 7200, NOW + 59);
    for mutation in [
        "bare",
        "nonce",
        "audience",
        "signature",
        "issuer_key",
        "holder",
        "inner_content",
    ] {
        let mut context = original.clone();
        match mutation {
            "bare" => {
                context.token = json!(marty_oid4vci::presented_jwt_vc_with_profile(
                    context.token.as_str().unwrap(),
                    profile
                )
                .unwrap())
            }
            "nonce" => context.nonce = Some("wrong".into()),
            "audience" => context.audience = Some("https://wrong.example".into()),
            "signature" => {
                let raw = context.token.as_str().unwrap();
                let prefix = raw.rsplit_once('.').unwrap().0;
                context.token = json!(format!("{prefix}.{}", URL_SAFE_NO_PAD.encode([0u8; 64])));
            }
            "issuer_key" => {
                context.trust_profile.as_mut().unwrap().document["system_issuer_overrides"]
                    [ISSUER]["public_jwk"]["x"] = json!(URL_SAFE_NO_PAD
                    .encode(SigningKey::from_bytes(&[63; 32]).verifying_key().to_bytes()))
            }
            "holder" => {
                let payload = claims(context.token.as_str().unwrap());
                let signer = SigningKey::from_bytes(&[63; 32]);
                context.token = json!(sign(
                    &signer,
                    json!({"alg":"EdDSA","typ":"vp+jwt","cty":"vp","jwk":{"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(signer.verifying_key().to_bytes())}}),
                    payload
                ));
            }
            "inner_content" => {
                let mut outer = claims(context.token.as_str().unwrap());
                let inner = marty_oid4vci::presented_jwt_vc_with_profile(
                    context.token.as_str().unwrap(),
                    profile,
                )
                .unwrap();
                let parts = inner.split('.').collect::<Vec<_>>();
                let mut changed = claims(&inner);
                changed["credentialSubject"]["email"] = json!("tampered@example.test");
                let tampered = format!(
                    "{}.{}.{}",
                    parts[0],
                    URL_SAFE_NO_PAD.encode(changed.to_string()),
                    parts[2]
                );
                outer["verifiableCredential"][0]["id"] =
                    json!(format!("data:application/vc+jwt,{tampered}"));
                let signer = SigningKey::from_bytes(&[62; 32]);
                context.token = json!(sign(
                    &signer,
                    json!({"alg":"EdDSA","typ":"vp+jwt","cty":"vp","jwk":{"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(signer.verifying_key().to_bytes())}}),
                    outer
                ));
            }
            _ => unreachable!(),
        }
        let evidence = RustCredentialKernel.verify(&context).await.unwrap();
        assert!(!evidence.verified, "{mutation}");
        assert!(evidence.authenticated_profiled_jwt_vc.is_none());
    }
    for (sig, vc, proof) in [
        (NOW, NOW + 7200, NOW + 59),
        (NOW + 3600, NOW, NOW + 59),
        (NOW + 3600, NOW + 7200, NOW),
    ] {
        let (_, _, context) = fixture(profile, sig, vc, proof);
        assert!(
            !RustCredentialKernel
                .verify(&context)
                .await
                .unwrap()
                .verified
        );
    }
    let (_, _, historical) = fixture(
        JwtVcSecuringProfile::MartyNestedVc2JwtV1,
        NOW + 3600,
        NOW + 7200,
        NOW + 59,
    );
    let mut crossed = original;
    crossed.token = historical.token;
    assert!(
        !ResolvingCredentialKernel::new(Arc::new(NoPublic))
            .verify(&crossed)
            .await
            .unwrap()
            .verified
    );
}

struct Registry {
    binding: marty_issuer_key_resolution::governed::RegistryIssuerResolution,
    expected_format: &'static str,
}

#[async_trait]
impl marty_issuer_key_resolution::governed::OrganizationIssuerResolver for Registry {
    async fn resolve(
        &self,
        request: &marty_issuer_key_resolution::governed::IssuerResolutionRequest,
    ) -> Result<
        marty_issuer_key_resolution::governed::RegistryIssuerResolution,
        marty_issuer_key_resolution::IssuerKeyResolutionError,
    > {
        assert_eq!(request.credential_format, self.expected_format);
        assert_eq!(request.organization_id.as_deref(), Some("issuer-org"));
        assert_eq!(request.issuer_did, ISSUER);
        assert_eq!(request.key_purpose, "vc_jwt_issuer");
        assert_eq!(request.algorithm, "EdDSA");
        Ok(self.binding.clone())
    }
}

#[tokio::test]
async fn explicit_profile_registry_requires_exact_format_scope_and_assertion_authority() {
    for profile in [
        JwtVcSecuringProfile::MartyNestedVc2JwtV1,
        JwtVcSecuringProfile::W3cVc2Jose2026V1,
    ] {
        let (_, _, original) = fixture(profile, NOW + 3600, NOW + 7200, NOW + 59);
        let key = original.trust_profile.as_ref().unwrap().document["system_issuer_overrides"]
            [ISSUER]["public_jwk"]
            .clone();
        let binding=marty_issuer_key_resolution::governed::RegistryIssuerResolution {
            organization_id:"issuer-org".into(),issuer_did:ISSUER.into(),active:true,
            credential_format:policy_credential_format(profile).into(),key_purpose:"vc_jwt_issuer".into(),algorithm:"EdDSA".into(),verification_method_id:KID.into(),
            document:serde_json::from_value(json!({"@context":["https://www.w3.org/ns/did/v1"],"id":ISSUER,"verificationMethod":[{"id":KID,"controller":ISSUER,"type":"JsonWebKey2020","publicKeyJwk":key}],"assertionMethod":[KID]})).unwrap(),
            source:"organization_signing_registry".into(),retrieved_at:"2026-08-21T00:00:00Z".into(),content_sha256:"a".repeat(64),
        };
        for mutation in [
            "valid",
            "crossed_format",
            "wrong_scope",
            "inactive",
            "wrong_method",
            "wrong_key",
        ] {
            let mut context = original.clone();
            context.trust_profile.as_mut().unwrap().document = json!({"status":"active","allowed_algorithms":["EdDSA"],"trust_sources":[{"issuer_did":ISSUER,"organization_id":"issuer-org","verification_method_ids":[KID],"did_resolution":{"allow_public_fallback":true,"cache_ttl_seconds":0}}]});
            let mut binding = binding.clone();
            match mutation {
                "crossed_format" => {
                    binding.credential_format = if profile == JwtVcSecuringProfile::W3cVc2Jose2026V1
                    {
                        "VC_JWT"
                    } else {
                        "VC_JWT_DIRECT_V1"
                    }
                    .into()
                }
                "wrong_scope" => binding.organization_id = "other-org".into(),
                "inactive" => binding.active = false,
                "wrong_method" => binding.verification_method_id = format!("{ISSUER}#other"),
                "wrong_key" => {
                    let mut document = serde_json::to_value(&binding.document).unwrap();
                    document["verificationMethod"][0]["publicKeyJwk"]["x"] = json!(URL_SAFE_NO_PAD
                        .encode(SigningKey::from_bytes(&[63; 32]).verifying_key().to_bytes()));
                    binding.document = serde_json::from_value(document).unwrap();
                }
                _ => {}
            }
            let kernel = ResolvingCredentialKernel::new(Arc::new(NoPublic)).with_registry(
                Arc::new(Registry {
                    binding,
                    expected_format: policy_credential_format(profile),
                }),
            );
            let evidence = kernel.verify(&context).await.unwrap();
            assert_eq!(
                evidence.verified,
                mutation == "valid",
                "{profile:?}: {mutation}: {:?}",
                evidence.failure_reason
            );
            if mutation == "valid" {
                assert_eq!(
                    evidence
                        .authenticated_issuer
                        .as_ref()
                        .unwrap()
                        .provenance
                        .source,
                    "organization_signing_registry"
                );
                evidence
                    .authenticated_profiled_jwt_vc
                    .as_ref()
                    .unwrap()
                    .revalidate_at(NOW as u64)
                    .unwrap();
            } else {
                assert!(evidence.authenticated_profiled_jwt_vc.is_none());
                assert!(evidence.authenticated_issuer.is_none());
                assert!(evidence.claims.is_empty());
            }
        }
    }
}

struct Trust {
    profile: ResolvedTrustProfile,
    trusted: bool,
    allowed_format: &'static str,
    clock: Arc<std::sync::atomic::AtomicU64>,
    advance: Option<(&'static str, u64)>,
}

impl Trust {
    fn advance(&self, stage: &str) {
        if let Some((expected, now)) = self.advance {
            if expected == stage {
                self.clock.store(now, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }
}

#[async_trait]
impl PresentationTrustResolver for Trust {
    async fn load_profile(
        &self,
        id: Uuid,
        organization_id: Uuid,
    ) -> Result<ResolvedTrustProfile, PresentationVerificationError> {
        assert_eq!(
            (id, organization_id),
            (self.profile.id, self.profile.organization_id)
        );
        self.advance("profile");
        Ok(self.profile.clone())
    }
    async fn evaluate_issuer(
        &self,
        _: &ResolvedTrustProfile,
        issuer: &str,
        _: DetectedCredentialFormat,
    ) -> Result<IssuerTrustEvidence, PresentationVerificationError> {
        assert_eq!(issuer, ISSUER);
        self.advance("trust");
        Ok(IssuerTrustEvidence {
            verified: self.trusted,
            trust_level: Some(90),
            ..Default::default()
        })
    }
    async fn load_credential_template(
        &self,
        id: &str,
        organization_id: Uuid,
    ) -> Result<ResolvedCredentialTemplate, PresentationVerificationError> {
        self.advance("template");
        Ok(ResolvedCredentialTemplate {
            id: id.into(),
            organization_id,
            credential_type: "MemberCredential".into(),
            vct: None,
            doctype: None,
            status: "ACTIVE".into(),
        })
    }
    async fn load_verification_policy(
        &self,
        id: Uuid,
        organization_id: Uuid,
    ) -> Result<ResolvedVerificationPolicy, PresentationVerificationError> {
        self.advance("authorization");
        Ok(ResolvedVerificationPolicy { id,organization_id,revision:"synthetic-direct-authorization".into(),cedar_policies:format!("permit(principal, action == MIP::Action::\"credentials:verify\", resource) when {{ context.credential_format == \"{}\" }};",self.allowed_format) })
    }
}

struct Status {
    state: Option<bool>,
    clock: Arc<std::sync::atomic::AtomicU64>,
    advance: Option<u64>,
}
#[async_trait]
impl CredentialStatusResolver for Status {
    async fn resolve(
        &self,
        _: Uuid,
        issuer: &str,
        ids: &[String],
    ) -> Result<CredentialStatusEvidence, PresentationVerificationError> {
        assert_eq!(issuer, ISSUER);
        assert!(ids.iter().any(|id| id == CREDENTIAL_ID));
        if let Some(now) = self.advance {
            self.clock.store(now, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(CredentialStatusEvidence {
            checked_at_epoch_seconds: self.state.map(|_| NOW as u64),
            not_revoked: self.state,
            credential_status: self
                .state
                .map(|good| if good { "active" } else { "revoked" }.into()),
            warnings: vec![],
        })
    }
}

fn orchestrator(
    context: &CredentialVerificationContext,
    trusted: bool,
    status: Option<bool>,
    allowed_format: &'static str,
    advance: Option<(&'static str, u64)>,
) -> VerifiedFactsOrchestrator {
    orchestrator_with_kernel(
        context,
        trusted,
        status,
        allowed_format,
        advance,
        Arc::new(ResolvingCredentialKernel::new(Arc::new(NoPublic))),
    )
}

fn orchestrator_with_kernel(
    context: &CredentialVerificationContext,
    trusted: bool,
    status: Option<bool>,
    allowed_format: &'static str,
    advance: Option<(&'static str, u64)>,
    kernel: Arc<dyn CredentialVerificationKernel>,
) -> VerifiedFactsOrchestrator {
    let clock = Arc::new(std::sync::atomic::AtomicU64::new(NOW as u64));
    let mut profile = context.trust_profile.clone().unwrap();
    profile.document["verification_policy_set_id"] = json!(Uuid::from_u128(7));
    let trust = Arc::new(Trust {
        profile,
        trusted,
        allowed_format,
        clock: clock.clone(),
        advance,
    });
    let status = Arc::new(Status {
        state: status,
        clock: clock.clone(),
        advance: advance
            .filter(|(stage, _)| *stage == "status")
            .map(|(_, now)| now),
    });
    VerifiedFactsOrchestrator::with_clock(
        kernel,
        trust,
        status,
        Arc::new(move || clock.load(std::sync::atomic::Ordering::SeqCst)),
    )
    .unwrap()
}

struct AlteredEvidence(&'static str);
#[async_trait]
impl CredentialVerificationKernel for AlteredEvidence {
    async fn verify(
        &self,
        context: &CredentialVerificationContext,
    ) -> Result<CredentialVerificationEvidence, PresentationVerificationError> {
        let mut evidence = ResolvingCredentialKernel::new(Arc::new(NoPublic))
            .verify(context)
            .await?;
        assert!(evidence.verified);
        match self.0 {
            "json_roundtrip" => {
                evidence = serde_json::from_value(serde_json::to_value(&evidence).unwrap()).unwrap()
            }
            "claims" => {
                evidence
                    .claims
                    .insert("email".into(), json!("tampered@example.test"));
            }
            "issuer" => evidence.issuer_id = Some("did:web:other.example".into()),
            _ => unreachable!(),
        }
        Ok(evidence)
    }
}

struct CachedEvidence(CredentialVerificationEvidence);
#[async_trait]
impl CredentialVerificationKernel for CachedEvidence {
    async fn verify(
        &self,
        _: &CredentialVerificationContext,
    ) -> Result<CredentialVerificationEvidence, PresentationVerificationError> {
        Ok(self.0.clone())
    }
}

#[tokio::test]
async fn explicit_profile_cached_proof_cannot_substitute_for_a_different_selected_token() {
    let profile = JwtVcSecuringProfile::W3cVc2Jose2026V1;
    let (policy, request, context) = fixture(profile, NOW + 3600, NOW + 7200, NOW + 59);
    let cached = ResolvingCredentialKernel::new(Arc::new(NoPublic))
        .verify(&context)
        .await
        .unwrap();
    assert!(cached.verified);
    let engine = orchestrator_with_kernel(
        &context,
        true,
        Some(true),
        policy_credential_format(profile),
        None,
        Arc::new(CachedEvidence(cached)),
    );
    // Same input is a positive control. The second VP is also genuinely signed
    // by the same holder and has the same authenticated credential and facts.
    engine.verify_material(&policy, &request).await.unwrap();
    let mut changed = request.clone();
    let mut outer = claims(request.vp_token.as_str().unwrap());
    outer["exp"] = json!(NOW + 58);
    let signer = SigningKey::from_bytes(&[62; 32]);
    let raw = sign(
        &signer,
        json!({"alg":"EdDSA","typ":"vp+jwt","cty":"vp","jwk":{"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(signer.verifying_key().to_bytes())}}),
        outer,
    );
    changed.vp_token = json!(raw);
    changed.oid4vp_transport.as_mut().unwrap().vp_token_raw = raw;
    let mut changed_context = context.clone();
    changed_context.token = changed.vp_token.clone();
    assert!(
        ResolvingCredentialKernel::new(Arc::new(NoPublic))
            .verify(&changed_context)
            .await
            .unwrap()
            .verified
    );
    assert!(engine.verify_material(&policy, &changed).await.is_err());
}

#[tokio::test]
async fn explicit_profile_orchestrator_rejects_roundtripped_or_mutated_authenticated_facts() {
    let profile = JwtVcSecuringProfile::W3cVc2Jose2026V1;
    let (policy, request, context) = fixture(profile, NOW + 3600, NOW + 7200, NOW + 59);
    for mutation in ["json_roundtrip", "claims", "issuer"] {
        let engine = orchestrator_with_kernel(
            &context,
            true,
            Some(true),
            policy_credential_format(profile),
            None,
            Arc::new(AlteredEvidence(mutation)),
        );
        assert!(
            engine.verify_material(&policy, &request).await.is_err(),
            "{mutation}"
        );
    }
}

#[tokio::test]
async fn explicit_profile_full_policy_keeps_trust_status_replay_and_direct_cedar_authority() {
    for profile in [
        JwtVcSecuringProfile::MartyNestedVc2JwtV1,
        JwtVcSecuringProfile::W3cVc2Jose2026V1,
    ] {
        let (policy, request, context) = fixture(profile, NOW + 3600, NOW + 7200, NOW + 59);
        for (trusted, status, replay, allowed_format, allowed) in [
            (
                true,
                Some(true),
                true,
                policy_credential_format(profile),
                true,
            ),
            (
                false,
                Some(true),
                true,
                policy_credential_format(profile),
                false,
            ),
            (
                true,
                Some(false),
                true,
                policy_credential_format(profile),
                false,
            ),
            (true, None, true, policy_credential_format(profile), false),
            (
                true,
                Some(true),
                false,
                policy_credential_format(profile),
                false,
            ),
            (
                true,
                Some(true),
                true,
                if profile == JwtVcSecuringProfile::W3cVc2Jose2026V1 {
                    "VC_JWT"
                } else {
                    "VC_JWT_DIRECT_V1"
                },
                false,
            ),
        ] {
            let mut request = request.clone();
            request
                .context
                .insert("replay_check_verified".into(), json!(replay));
            let material = orchestrator(&context, trusted, status, allowed_format, None)
                .verify_material(&policy, &request)
                .await
                .unwrap();
            assert_eq!(
                material.policy_facts()["credentials"][0]["credential_format"],
                policy_credential_format(profile)
            );
            let result =
                evaluate_verified_material_for_policy(material, &policy, &request).unwrap();
            assert_eq!(result["decision"],if allowed {"allow"}else{"deny"},"{profile:?}, trusted={trusted}, status={status:?}, replay={replay}, format={allowed_format}: {result}");
            assert_eq!(result["verified_claims"], json!({}));
        }
    }
}

#[tokio::test]
async fn explicit_profile_final_clock_reauthenticates_after_every_owner_await() {
    let profile = JwtVcSecuringProfile::W3cVc2Jose2026V1;
    for stage in ["profile", "trust", "status", "template", "authorization"] {
        for (sig, vc, proof) in [
            (NOW + 4, NOW + 7200, NOW + 59),
            (NOW + 3600, NOW + 4, NOW + 59),
            (NOW + 3600, NOW + 7200, NOW + 4),
        ] {
            let (policy, request, context) = fixture(profile, sig, vc, proof);
            let result = orchestrator(
                &context,
                true,
                Some(true),
                policy_credential_format(profile),
                Some((stage, (NOW + 5) as u64)),
            )
            .verify_material(&policy, &request)
            .await;
            assert!(
                result.is_err(),
                "expiry must be checked after {stage}: sig={sig}, vc={vc}, proof={proof}"
            );
        }
    }
}

#[tokio::test]
async fn explicit_profile_authority_comes_only_from_the_saved_policy_and_exact_frozen_query() {
    let profile = JwtVcSecuringProfile::W3cVc2Jose2026V1;
    let (policy, request, context) = fixture(profile, NOW + 3600, NOW + 7200, NOW + 59);
    for mutation in [
        "public_context",
        "no_transport",
        "query_profile",
        "query_format",
        "query_type",
        "query_id",
        "claims",
        "extra_top",
        "extra_entry",
        "extra_meta",
        "two_queries",
        "two_tokens",
        "missing_coverage",
        "holder_false",
    ] {
        let mut changed = request.clone();
        match mutation {
            "public_context" => {
                changed.trusted_internal_context = false;
                changed
                    .context
                    .insert("expected_securing_profile".into(), json!(profile));
                changed
                    .context
                    .insert("evaluation_time_epoch_seconds".into(), json!(NOW));
            }
            "no_transport" => {
                changed.oid4vp_transport = None;
            }
            mutation => {
                let transport = changed.oid4vp_transport.as_mut().unwrap();
                match mutation {
                    "query_profile" => {
                        transport.query_document["credentials"][0]["meta"]
                            ["marty_securing_profile"] = json!("marty_nested_vc2_jwt_v1")
                    }
                    "query_format" => {
                        transport.query_document["credentials"][0]["format"] = json!("jwt_vc_json")
                    }
                    "query_type" => {
                        transport.query_document["credentials"][0]["meta"]["type_values"] =
                            json!([["OtherCredential"]])
                    }
                    "query_id" => transport.query_document["credentials"][0]["id"] = json!("other"),
                    "claims" => {
                        transport.query_document["credentials"][0]["claims"] =
                            json!([{"path":["email"]}])
                    }
                    "extra_top" => transport.query_document["credential_sets"] = json!([]),
                    "extra_entry" => {
                        transport.query_document["credentials"][0]["multiple"] = json!(true)
                    }
                    "extra_meta" => {
                        transport.query_document["credentials"][0]["meta"]["extra"] = json!(true)
                    }
                    "two_queries" => {
                        let second = transport.query_document["credentials"][0].clone();
                        transport.query_document["credentials"]
                            .as_array_mut()
                            .unwrap()
                            .push(second);
                    }
                    "two_tokens" => {
                        transport.vp_token_raw=json!({Uuid::from_u128(5).to_string():[changed.vp_token.clone(),"different.header.signature"]}).to_string();
                    }
                    "missing_coverage" => {
                        transport.vp_token_raw =
                            json!({"other":[changed.vp_token.clone()]}).to_string()
                    }
                    "holder_false" => {
                        transport.query_document["credentials"][0]
                            ["require_cryptographic_holder_binding"] = json!(false)
                    }
                    _ => unreachable!(),
                }
                transport.query_digest = digest_query_document(&transport.query_document).unwrap();
            }
        }
        let material = orchestrator(
            &context,
            true,
            Some(true),
            policy_credential_format(profile),
            None,
        )
        .verify_material(&policy, &changed)
        .await;
        if let Ok(material) = material {
            let result =
                evaluate_verified_material_for_policy(material, &policy, &changed).unwrap();
            assert_eq!(result["decision"], "deny", "{mutation}");
        }
    }
}
