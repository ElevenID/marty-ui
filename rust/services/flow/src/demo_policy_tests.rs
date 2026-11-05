//! Local integration of Flow/Core with the actual Presentation Policy kernel.
//! Only KMS, trust-registry and status transport are fixtures; no verdict stub.
use super::tests::{credential, jwk, setup_with_policy, OpaqueSigner, ISSUER, ORG, POLICY_ID, VCT};
use super::*;
use async_trait::async_trait;
use marty_presentation_policy as pp;
use marty_verification::credential_format::DetectedCredentialFormat;
use pp::PresentationVerificationOrchestrator;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

struct FixtureTrust {
    accepted: bool,
}
#[async_trait]
impl pp::PresentationTrustResolver for FixtureTrust {
    async fn load_profile(
        &self,
        id: Uuid,
        org: Uuid,
    ) -> Result<pp::ResolvedTrustProfile, pp::PresentationVerificationError> {
        assert_eq!(org.to_string(), ORG);
        let mut key = jwk(3);
        key["kid"] = json!(format!("{ISSUER}#key"));
        Ok(pp::ResolvedTrustProfile {
            id,
            organization_id: org,
            document: json!({"status":"active", "system_issuer_overrides":{ISSUER:{"public_jwk":key}}}),
        })
    }
    async fn evaluate_issuer(
        &self,
        _: &pp::ResolvedTrustProfile,
        issuer: &str,
        format: DetectedCredentialFormat,
    ) -> Result<pp::IssuerTrustEvidence, pp::PresentationVerificationError> {
        Ok(pp::IssuerTrustEvidence {
            trust_level: Some(100),
            verified: self.accepted
                && issuer == ISSUER
                && format == DetectedCredentialFormat::SdJwt,
            ..Default::default()
        })
    }
}
struct FixtureStatus {
    not_revoked: bool,
}
#[async_trait]
impl pp::CredentialStatusResolver for FixtureStatus {
    async fn resolve(
        &self,
        org: Uuid,
        issuer: &str,
        ids: &[String],
    ) -> Result<pp::CredentialStatusEvidence, pp::PresentationVerificationError> {
        assert_eq!(org.to_string(), ORG);
        assert_eq!(issuer, ISSUER);
        assert!(!ids.is_empty());
        Ok(pp::CredentialStatusEvidence {
            checked_at_epoch_seconds: Some(Utc::now().timestamp() as u64),
            not_revoked: Some(self.not_revoked),
            credential_status: Some(if self.not_revoked { "valid" } else { "revoked" }.into()),
            warnings: vec![],
        })
    }
}
fn policy(claim: &str) -> pp::PresentationPolicy {
    let now = Utc::now();
    pp::PresentationPolicy {
        id: Uuid::parse_str(POLICY_ID).unwrap(),
        organization_id: Uuid::parse_str(ORG).unwrap(),
        name: format!("Synthetic demo requires {claim}"),
        description: Some("Fixed fictional age-20 specimen".into()),
        status: pp::PolicyStatus::Active,
        display_metadata: pp::DisplayMetadata {
            title: "Marty age demonstration".into(),
            description: "Synthetic data only".into(),
            purpose: pp::RequestPurpose::AgeVerification,
            purpose_description: Some(
                "Demonstrate a signed age threshold without date of birth".into(),
            ),
            verifier_name: "Marty".into(),
            verifier_logo_url: None,
            privacy_policy_url: None,
            terms_of_service_url: None,
        },
        required_claims: vec![],
        accepted_credential_types: vec![VCT.into()],
        credential_requirements: vec![pp::CredentialRequirement {
            id: Uuid::from_u128(19),
            credential_template_id: "demo-age".into(),
            display_name: "Synthetic age".into(),
            description: None,
            required: true,
            credential_payload_format: "SD_JWT_VC".into(),
            requested_claims: vec![pp::RequestedClaim {
                id: Uuid::from_u128(20),
                claim_name: claim.into(),
                display_name: claim.into(),
                description: Some("Present the issuer-signed age threshold".into()),
                required: true,
                selective_disclosure: true,
                accept_derived: false,
                predicate_spec: None,
                constraints: vec![pp::ClaimConstraint {
                    id: Uuid::from_u128(21),
                    claim_name: claim.into(),
                    constraint_type: pp::ConstraintType::Equals,
                    value: Some(json!(true)),
                    description: Some("The signed age threshold must be true".into()),
                }],
            }],
            trust_profile_id: None,
            max_age_seconds: Some(600),
            require_fresh_issuance: false,
        }],
        alternative_requirements: vec![],
        presentation_proof_required: true,
        trust_profile_id: Some(Uuid::from_u128(22)),
        holder_binding: pp::HolderBinding {
            required: true,
            binding_methods: vec!["DEVICE_KEY".into()],
            proof_profiles: vec!["OID4VP_VERIFIABLE_PRESENTATION".into()],
            proof_freshness: [
                ("challenge_required".into(), true),
                ("audience_binding_required".into(), true),
                ("replay_detection_required".into(), true),
            ]
            .into_iter()
            .collect(),
        },
        freshness: Some(pp::FreshnessPolicy {
            max_age_seconds: Some(600),
            require_not_revoked: true,
            revocation_grace_seconds: Some(60),
        }),
        issuer_constraints: None,
        credential_ranking_strategy: "FIRST_VALID".into(),
        credential_ranking_weights: None,
        purpose: Some("Synthetic age verification".into()),
        compliance_profile_id: None,
        prefer_predicates: false,
        fallback_policy: None,
        supported_circuits: vec![],
        version: 1,
        created_at: now,
        updated_at: now,
    }
}
pub(super) struct ActualPolicy {
    policy: pp::PresentationPolicy,
    verifier: pp::VerifiedFactsOrchestrator,
}
impl ActualPolicy {
    pub(super) fn new(claim: &str, trusted: bool, not_revoked: bool) -> Self {
        Self {
            policy: policy(claim),
            verifier: pp::VerifiedFactsOrchestrator::new(
                Arc::new(pp::RustCredentialKernel),
                Arc::new(FixtureTrust { accepted: trusted }),
                Arc::new(FixtureStatus { not_revoked }),
            )
            .unwrap(),
        }
    }
}
#[async_trait]
impl crate::PresentationPolicyProvider for ActualPolicy {
    async fn configuration_digest(&self, id: &str) -> Result<String, FlowProviderError> {
        assert_eq!(id, POLICY_ID);
        Ok(pp::policy_configuration_digest(&self.policy).unwrap())
    }
    async fn get_policy(
        &self,
        id: &str,
    ) -> Result<crate::PresentationPolicyReference, FlowProviderError> {
        Ok(crate::PresentationPolicyReference {
            id: id.into(),
            organization_id: ORG.into(),
            status: "active".into(),
            configuration_digest: pp::policy_configuration_digest(&self.policy).unwrap(),
            credential_requirements: serde_json::from_value(
                serde_json::to_value(&self.policy.credential_requirements).unwrap(),
            )
            .unwrap(),
        })
    }
    async fn evaluate(
        &self,
        input: &crate::PresentationEvaluationRequest,
    ) -> Result<crate::PresentationEvaluationResult, FlowProviderError> {
        let mut context = input
            .context
            .clone()
            .into_iter()
            .collect::<serde_json::Map<_, _>>();
        let expected = context
            .remove(crate::defined_verification::EXPECTED_POLICY_DIGEST)
            .and_then(|v| v.as_str().map(str::to_owned));
        assert_eq!(
            expected.as_deref(),
            Some(
                pp::policy_configuration_digest(&self.policy)
                    .unwrap()
                    .as_str()
            )
        );
        let request = pp::EvaluatePresentationRequest {
            expected_configuration_digest: expected,
            vp_token: json!(input.presentation),
            trust_profile_id: None,
            nonce: Some(input.nonce.clone()),
            audience: Some(input.audience.clone()),
            context,
            oid4vp_transport: input.oid4vp_transport.clone(),
            trusted_internal_context: true,
        };
        let facts = self.verifier.verify(&self.policy, &request).await.unwrap();
        let result = pp::evaluate_verified_facts_for_policy(facts, &self.policy, &request).unwrap();
        assert_eq!(
            result["configuration_digest"],
            json!(pp::policy_configuration_digest(&self.policy).unwrap())
        );
        Ok(serde_json::from_value(result).unwrap())
    }
}

#[derive(Clone, Copy, Debug)]
enum Mutation {
    None,
    Signature,
    Audience,
    WrongVct,
    WrongFormat,
    WrongQueryId,
    MultipleTokens,
    ExtraQueryId,
    Unbound,
}
async fn run_actual_case(
    specimen: &str,
    claim: &str,
    trusted: bool,
    not_revoked: bool,
    mutation: Mutation,
) -> crate::PreparedVerificationSubmission {
    let mut owner = ActualPolicy::new(claim, trusted, not_revoked);
    if matches!(mutation, Mutation::Unbound) {
        owner.policy.presentation_proof_required = false;
        owner.policy.holder_binding.required = false;
        owner
            .policy
            .holder_binding
            .proof_freshness
            .insert("challenge_required".into(), false);
        owner
            .policy
            .holder_binding
            .proof_freshness
            .insert("audience_binding_required".into(), false);
    }
    let owner = Arc::new(owner);
    let (providers, instance, holder, profile, _) =
        setup_with_policy(Arc::new(OpaqueSigner::new()), Some(owner)).await;
    let crate::PreparedVerificationRequest::Ready(ready) = crate::prepare_verification_request(
        &providers,
        instance,
        "https://demo.example",
        &Default::default(),
        Utc::now(),
    )
    .await
    .unwrap() else {
        panic!("request expired")
    };
    let presentation = if matches!(mutation, Mutation::Unbound) {
        specimen.to_owned()
    } else if matches!(mutation, Mutation::WrongVct | Mutation::WrongFormat) {
        // Model an independent wallet: it can present a valid issuer-signed
        // credential that differs from the requested type. Do not route this
        // through the example producer's extra profile checks.
        use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
        let specimen = super::tests::credential_with_profile(
            ISSUER,
            7,
            300,
            if matches!(mutation, Mutation::WrongVct) {
                "urn:marty:demo:other:1"
            } else {
                VCT
            },
            if matches!(mutation, Mutation::WrongFormat) {
                "vc+sd-jwt"
            } else {
                "dc+sd-jwt"
            },
        );
        let keys = TrustedSdJwtIssuerKeys::new(vec![ResolvedSdJwtIssuerKey::new(
            ISSUER,
            Some(format!("{ISSUER}#key")),
            marty_oid4vci::types::SigningAlgorithm::ES256,
            jwk(3).to_string(),
        )])
        .unwrap();
        let prepared = WalletEngine::new()
            .prepare_verified_sd_jwt_presentation(
                &specimen,
                &[claim.to_owned()],
                ready.instance.context["nonce"].as_str().unwrap(),
                ready.instance.context["oid4vp_client_id"].as_str().unwrap(),
                &jwk(7).to_string(),
                &keys,
            )
            .unwrap();
        let signature: Signature = SigningKey::from_bytes((&[7u8; 32]).into())
            .unwrap()
            .sign(prepared.signing_input());
        prepared.complete(&signature.to_bytes()).unwrap()
    } else {
        holder
            .presentation(&providers, &ready.instance, &profile, specimen)
            .await
            .unwrap()
            .into_compact()
    };
    let mut input =
        crate::public_verification_example::example_submission(&ready.instance, presentation)
            .unwrap();
    match mutation {
        Mutation::None | Mutation::WrongVct | Mutation::WrongFormat | Mutation::Unbound => {}
        Mutation::WrongQueryId | Mutation::ExtraQueryId | Mutation::MultipleTokens => {
            let mut wire: serde_json::Value = serde_json::from_str(&input.vp_token).unwrap();
            let response = wire.as_object_mut().unwrap();
            let id = response.keys().next().unwrap().clone();
            let tokens = response[&id].clone();
            if matches!(mutation, Mutation::WrongQueryId) {
                response.remove(&id);
            }
            if matches!(mutation, Mutation::MultipleTokens) {
                response[&id]
                    .as_array_mut()
                    .unwrap()
                    .push(tokens[0].clone());
            } else {
                response.insert("unrequested-query".into(), tokens);
            }
            input.vp_token = wire.to_string();
        }
        Mutation::Audience => {
            input.audience_override = Some("did:web:wrong.example:verifier".into())
        }
        Mutation::Signature => {
            let mut wire: serde_json::Value = serde_json::from_str(&input.vp_token).unwrap();
            let value = &mut wire
                .as_object_mut()
                .unwrap()
                .values_mut()
                .next()
                .unwrap()
                .as_array_mut()
                .unwrap()[0];
            let compact = value.as_str().unwrap();
            let offset = compact.split('~').next().unwrap().rfind('.').unwrap() + 1;
            let mut bytes = compact.as_bytes().to_vec();
            bytes[offset] = if bytes[offset] == b'A' { b'B' } else { b'A' };
            *value = json!(String::from_utf8(bytes).unwrap());
            input.vp_token = wire.to_string();
        }
    }
    let result = crate::prepare_verification_submission(
        &providers,
        ready.instance,
        input,
        &crate::VerificationSubmissionOptions {
            callback_destinations: Default::default(),
            callback_secret: None,
            verifier_sender_id: "did:web:demo.example:verifier".into(),
            nonce_ttl_seconds: 900,
            callback_retention_seconds: 3600,
            callback_max_attempts: 3,
        },
        Utc::now(),
    )
    .await
    .unwrap();
    result
}

#[tokio::test]
async fn independent_wallet_type_format_query_and_token_mismatches_cannot_satisfy_the_age_request()
{
    for mutation in [
        Mutation::WrongVct,
        Mutation::WrongFormat,
        Mutation::WrongQueryId,
        Mutation::MultipleTokens,
        Mutation::ExtraQueryId,
        Mutation::Unbound,
    ] {
        let result =
            run_actual_case(&credential(ISSUER, 7), "age_over_18", true, true, mutation).await;
        match result {
            crate::PreparedVerificationSubmission::Retryable(response) => {
                assert_eq!(response.status, "AWAITING_WALLET");
                assert_eq!(response.verified_claims, json!({}));
            }
            crate::PreparedVerificationSubmission::RetryableSnapshot(snapshot) => {
                assert!(!snapshot.instance.status.is_terminal());
                assert_eq!(snapshot.response.verified_claims, json!({}));
            }
            other => panic!("{mutation:?} must be a nonterminal input rejection: {other:?}"),
        }
    }
}

#[tokio::test]
async fn public_submission_cannot_fall_back_to_missing_or_legacy_query_transport() {
    let (providers, instance, _, _, _) =
        setup_with_policy(Arc::new(OpaqueSigner::new()), None).await;
    let legacy_request = crate::prepare_verification_request(
        &providers,
        instance.clone(),
        "https://demo.example",
        &crate::VerificationRequestRetrievalOptions {
            compatibility: crate::RequestObjectCompatibility::Lissi,
            ..Default::default()
        },
        Utc::now(),
    )
    .await;
    assert!(matches!(
        legacy_request,
        Err(crate::FlowVerificationRequestError::RequestObject(
            crate::FlowRequestObjectError::UnsupportedProfile(_)
        ))
    ));
    let crate::PreparedVerificationRequest::Ready(ready) = crate::prepare_verification_request(
        &providers,
        instance,
        "https://demo.example",
        &Default::default(),
        Utc::now(),
    )
    .await
    .unwrap() else {
        panic!("request expired");
    };
    let state = ready.instance.context["oid4vp_expected_state"]
        .as_str()
        .unwrap_or(&ready.instance.id)
        .to_owned();
    let definition = crate::build_flow_presentation_request(&providers, POLICY_ID, ORG)
        .await
        .unwrap()
        .presentation_definition;
    for legacy in [false, true] {
        let mut instance = ready.instance.clone();
        if legacy {
            let payload = instance.context["mip_messages"]["presentation_request"]["payload"]
                .as_object_mut()
                .unwrap();
            payload.remove("dcql_query");
            payload.insert("presentation_definition".into(), definition.clone());
        } else {
            instance
                .context
                .as_object_mut()
                .unwrap()
                .remove("mip_messages");
        }
        let result = crate::prepare_verification_submission(
            &providers,
            instance,
            crate::VerificationSubmissionInput {
                vp_token: "unverified-input".into(),
                presentation_submission: None,
                state: Some(state.clone()),
                audience_override: None,
            },
            &crate::VerificationSubmissionOptions {
                callback_destinations: Default::default(),
                callback_secret: None,
                verifier_sender_id: "did:web:demo.example:verifier".into(),
                nonce_ttl_seconds: 900,
                callback_retention_seconds: 3600,
                callback_max_attempts: 3,
            },
            Utc::now(),
        )
        .await;
        assert!(matches!(
            result,
            Err(crate::FlowVerificationSubmissionError::InvalidContext(
                "public_verification_query_binding"
            ))
        ));
    }
}

#[tokio::test]
async fn fixed_signed_age20_allows18_and_denies21_through_actual_policy_engine() {
    let specimen = credential(ISSUER, 7);
    for (claim, allow) in [("age_over_18", true), ("age_over_21", false)] {
        let result = run_actual_case(&specimen, claim, true, true, Mutation::None).await;
        let crate::PreparedVerificationSubmission::Final(finalization) = result else {
            panic!("not a canonical finalization: {result:?}")
        };
        assert_eq!(
            finalization.instance.status,
            if allow {
                FlowInstanceStatus::Completed
            } else {
                FlowInstanceStatus::Failed
            },
            "canonical result: {:?}",
            finalization.instance.result
        );
        let stored = finalization.instance.result.unwrap();
        assert_eq!(stored["decision"], if allow { "allow" } else { "deny" });
        assert_eq!(stored["credential_results"][0]["signature_valid"], true);
        if !allow {
            assert_eq!(stored["verified_claims"], json!({}));
        }
        assert!(!stored.to_string().contains("do-not-disclose"));
    }
}

#[tokio::test]
async fn actual_policy_preview_is_minimal_and_rejects_snapshot_or_rule_drift() {
    let owner = Arc::new(ActualPolicy::new("age_over_18", true, true));
    let digest = pp::policy_configuration_digest(&owner.policy).unwrap();
    let (providers, instance, _, _, _) =
        setup_with_policy(Arc::new(OpaqueSigner::new()), Some(owner)).await;
    let config = json!({"organization_id":ORG,"application_origin":"https://demo.example","notice":"Use a signed fictional age threshold.","scenarios":[{"id":"age","label":"Age","choices":[{"id":"over-18","label":"18 or older","definition":{"organization_id":ORG,"definition_id":instance.flow_definition_id,"version":1},"presentation_policy_id":POLICY_ID,"policy_configuration_digest":digest}]}]});
    let catalog = crate::PublicVerificationCatalog::from_json(&config.to_string(), false).unwrap();
    let selected = crate::PublicVerificationPreviewSelection {
        catalog_revision: catalog.public_view().revision.into(),
        scenario_id: "age".into(),
        choice_id: "over-18".into(),
    };
    let preview = catalog
        .request_preview(&providers, &selected)
        .await
        .unwrap();
    assert_eq!(preview.claims.len(), 1);
    assert_eq!(preview.claims[0].name, "age_over_18");
    assert_eq!(preview.claims[0].constraints[0].kind, "equals");
    assert_eq!(preview.claims[0].constraints[0].value, Some(json!(true)));
    assert_eq!(preview.claims[0].intent_to_retain, None);
    assert_eq!(
        Some(preview.request_digest.as_str()),
        instance.context[crate::defined_verification::REQUEST_DIGEST].as_str()
    );
    let public = serde_json::to_value(preview).unwrap().to_string();
    assert!(
        !public.contains(POLICY_ID) && !public.contains(ISSUER) && !public.contains("nickname")
    );
    let mut changed = providers;
    changed.presentation_policy = Some(Arc::new(ActualPolicy::new("age_over_21", true, true)));
    assert!(matches!(
        catalog.request_preview(&changed, &selected).await,
        Err(crate::PublicVerificationPreviewError::Catalog(
            crate::PublicVerificationCatalogError::ConfigurationChanged
        ))
    ));
}

#[tokio::test]
async fn actual_policy_rejects_untrusted_revoked_tampered_and_wrong_audience_inputs() {
    let specimen = credential(ISSUER, 7);
    for (trusted, not_revoked) in [(false, true), (true, false)] {
        let result = run_actual_case(
            &specimen,
            "age_over_18",
            trusted,
            not_revoked,
            Mutation::None,
        )
        .await;
        let crate::PreparedVerificationSubmission::Final(finalization) = result else {
            panic!("expected policy denial: {result:?}");
        };
        assert_eq!(finalization.instance.status, FlowInstanceStatus::Failed);
        let stored = finalization.instance.result.unwrap();
        assert_eq!(stored["decision"], "deny");
        assert_eq!(stored["credential_results"][0]["signature_valid"], true);
        assert_eq!(stored["verified_claims"], json!({}));
        assert_eq!(
            stored["credential_results"][0]["trust_check_passed"],
            trusted
        );
    }
    for mutation in [Mutation::Signature, Mutation::Audience] {
        let result = run_actual_case(&specimen, "age_over_18", true, true, mutation).await;
        // Cryptographic authentication failure is a retryable rejection; it
        // must not be promoted to either success or an authenticated denial.
        match result {
            crate::PreparedVerificationSubmission::Retryable(response) => {
                assert_eq!(response.status, "AWAITING_WALLET");
                assert_eq!(response.verified_claims, json!({}));
            }
            crate::PreparedVerificationSubmission::RetryableSnapshot(snapshot) => {
                assert!(!snapshot.instance.status.is_terminal());
                assert_eq!(snapshot.response.verified_claims, json!({}));
            }
            other => panic!("authentication failure must remain nonterminal: {other:?}"),
        }
    }
}
