use marty_presentation_policy::{
    CredentialVerificationContext, CredentialVerificationKernel, PresentationVerificationError,
    ResolvedTrustProfile, RustCredentialKernel,
};
use marty_verification::credential_format::DetectedCredentialFormat;
use serde_json::{json, Map, Value};
use uuid::Uuid;

#[tokio::test]
async fn scoped_did_policy_cannot_bypass_registry_using_relationship_keys_or_missing_kid() {
    use async_trait::async_trait;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use marty_issuer_key_resolution::{
        IssuerKeyResolution, IssuerKeyResolutionError, IssuerKeyResolver,
    };
    use marty_presentation_policy::ResolvingCredentialKernel;
    struct NeverPublic;
    #[async_trait]
    impl IssuerKeyResolver for NeverPublic {
        async fn resolve(&self, _: &str) -> Result<IssuerKeyResolution, IssuerKeyResolutionError> {
            panic!("scoped policy must never fall through to public resolution")
        }
    }
    let issuer = "did:web:issuer.example";
    for kid in [Some("did:web:issuer.example#key"), None] {
        let mut header = json!({"alg":"ES256"});
        if let Some(kid) = kid {
            header["kid"] = json!(kid);
        }
        let token = format!(
            "{}.{}.signature",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(json!({"iss":issuer}).to_string())
        );
        let mut context = context(DetectedCredentialFormat::W3cVc, json!(token));
        context.trust_profile = Some(ResolvedTrustProfile {
            id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            document: json!({"status":"active", "trust_sources":[{"issuer_did":issuer,"organization_id":"org-1"}],
                "system_issuer_overrides":{issuer:{"public_jwk":{"kty":"EC","crv":"P-256","x":"x","y":"y","kid":"did:web:issuer.example#key"}}}}),
        });
        let result = ResolvingCredentialKernel::new(std::sync::Arc::new(NeverPublic))
            .verify(&context)
            .await
            .unwrap();
        assert!(!result.verified);
        assert!(result.claims.is_empty());
        assert!(result.issuer_id.is_none());
        assert_eq!(
            result.failure_reason.as_deref(),
            Some(if kid.is_some() {
                "Organization issuer registry is unavailable"
            } else {
                "Issuer DID signing method is required"
            })
        );
    }
}

fn context(format: DetectedCredentialFormat, token: Value) -> CredentialVerificationContext {
    CredentialVerificationContext {
        presentation_only: false,
        sd_jwt_dcql: None,
        resolved_issuer_key: None,
        format,
        token,
        nonce: Some("behavioral-challenge".into()),
        audience: Some("https://verifier.example".into()),
        verifier_context: Map::new(),
        trust_profile: None,
    }
}

async fn assert_denied(format: DetectedCredentialFormat, token: Value) {
    match RustCredentialKernel.verify(&context(format, token)).await {
        Ok(evidence) => {
            assert!(!evidence.verified);
            assert!(evidence.claims.is_empty());
            assert!(evidence.issuer_id.is_none());
        }
        Err(PresentationVerificationError::Failed(_)) => {}
        Err(PresentationVerificationError::Unavailable)
        | Err(PresentationVerificationError::CredentialAuthorityChanged) => {
            panic!("a linked native format verifier unexpectedly reported unavailable")
        }
    }
}

#[tokio::test]
async fn malformed_inputs_fail_closed_for_every_linked_native_format() {
    for (format, token) in [
        (DetectedCredentialFormat::W3cVc, json!("not.a.jwt")),
        (
            DetectedCredentialFormat::W3cVcdmDi,
            json!({"proof": {"type": "DataIntegrityProof"}}),
        ),
        (DetectedCredentialFormat::SdJwt, json!("not~an~sd-jwt")),
        (
            DetectedCredentialFormat::OpenbadgeV3,
            json!({"credential": {}}),
        ),
        (DetectedCredentialFormat::Unknown, Value::Null),
    ] {
        assert_denied(format, token).await;
    }
}

#[tokio::test]
async fn mdoc_is_linked_and_fails_closed_without_complete_verifier_state() {
    let missing_state = RustCredentialKernel
        .verify(&context(DetectedCredentialFormat::Mdoc, json!("mdoc:_w")))
        .await
        .expect("missing verifier state is a denied presentation");
    assert!(!missing_state.verified);
    assert!(missing_state.claims.is_empty());
    assert!(missing_state.issuer_id.is_none());
    assert!(missing_state
        .failure_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("session transcript")));

    let mut configured = context(DetectedCredentialFormat::Mdoc, json!("mdoc:_w"));
    configured.verifier_context.insert(
        "mdoc_session_transcript_b64url".into(),
        json!("g_b2gnFPcGVuSUQ0VlBIYW5kb3Zlclg"),
    );
    configured.trust_profile = Some(ResolvedTrustProfile {
        id: Uuid::from_u128(1),
        organization_id: Uuid::from_u128(2),
        document: json!({
            "status": "active",
            "trust_sources": [{
                "source_type": "ROOT_CA",
                "certificate_pem": "-----BEGIN CERTIFICATE-----\ncm9vdA==\n-----END CERTIFICATE-----\n"
            }]
        }),
    });
    let malformed = RustCredentialKernel
        .verify(&configured)
        .await
        .expect("malformed native mdoc is denied without fallback");
    assert!(!malformed.verified);
    assert!(malformed.claims.is_empty());
    assert!(malformed.issuer_id.is_none());
}

fn governed_badge_context(
    format: DetectedCredentialFormat,
    fixture: &Value,
) -> CredentialVerificationContext {
    let mut context = context(format, fixture.clone());
    context.trust_profile = Some(ResolvedTrustProfile {
        id: Uuid::from_u128(1),
        organization_id: Uuid::from_u128(2),
        document: json!({"resolved_verification_methods": [fixture["governed_method"]]}),
    });
    context
}

#[tokio::test]
async fn retired_ob2_is_rejected_before_every_native_route_and_key_resolution() {
    use async_trait::async_trait;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use marty_issuer_key_resolution::{
        IssuerKeyResolution, IssuerKeyResolutionError, IssuerKeyResolver,
    };
    use marty_presentation_policy::ResolvingCredentialKernel;

    struct NeverResolve;
    #[async_trait]
    impl IssuerKeyResolver for NeverResolve {
        async fn resolve(&self, _: &str) -> Result<IssuerKeyResolution, IssuerKeyResolutionError> {
            panic!("retired Open Badges must not resolve issuer keys")
        }
    }
    let fixture: Value = serde_json::from_str(include_str!("fixtures/governed_ob2.json")).unwrap();
    let signed = fixture["assertion"].clone();
    let mut hosted = signed.clone();
    hosted.as_object_mut().unwrap().remove("signature");
    hosted.as_object_mut().unwrap().remove("verification");
    let mut mixed = signed.clone();
    mixed["@context"] = json!([
        "https://www.w3.org/ns/credentials/v2",
        "https://purl.imsglobal.org/spec/ob/v3p0/context.json",
        "https://w3id.org/openbadges/v2"
    ]);
    mixed["type"] = json!(["VerifiableCredential", "OpenBadgeCredential"]);
    let jwt = format!(
        "{}.{}.signature",
        URL_SAFE_NO_PAD.encode(json!({"alg":"EdDSA","kid":"did:example:issuer#key-1"}).to_string()),
        URL_SAFE_NO_PAD.encode(json!({"iss":"did:example:issuer","vc":hosted}).to_string())
    );
    let tokens = [
        signed.clone(),
        hosted,
        fixture.clone(),
        json!({"credential": signed}),
        json!({"vp": {"verifiableCredential": [fixture["assertion"]]}}),
        mixed,
        json!(jwt),
        json!(format!("{jwt}~")),
    ];
    for token in tokens {
        for format in [
            DetectedCredentialFormat::Unknown,
            DetectedCredentialFormat::OpenbadgeV3,
            DetectedCredentialFormat::W3cVc,
            DetectedCredentialFormat::W3cVcdmDi,
            DetectedCredentialFormat::SdJwt,
        ] {
            let mut input = governed_badge_context(format, &fixture);
            input.token = token.clone();
            for evidence in [
                RustCredentialKernel.verify(&input).await.unwrap(),
                ResolvingCredentialKernel::new(std::sync::Arc::new(NeverResolve))
                    .verify(&input)
                    .await
                    .unwrap(),
            ] {
                assert!(!evidence.verified);
                assert!(evidence.claims.is_empty());
                assert!(evidence.issuer_id.is_none());
                assert!(evidence.authenticated_outer_jti.is_none());
                assert_eq!(
                    evidence.failure_reason.as_deref(),
                    Some("Open Badges 2.0 is retired; request a newly issued Open Badges 3.0 credential")
                );
            }
        }
    }
}

#[tokio::test]
async fn retired_assertion_wrapper_cannot_redirect_to_ob3() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/governed_ob3_with_criteria.json")).unwrap();
    for format in [
        DetectedCredentialFormat::Unknown,
        DetectedCredentialFormat::OpenbadgeV3,
    ] {
        let mut input = governed_badge_context(format, &fixture);
        input.token = json!({"assertion": fixture["credential"]});
        let evidence = RustCredentialKernel.verify(&input).await.unwrap();
        assert!(!evidence.verified);
        assert!(evidence.claims.is_empty());
        assert!(evidence
            .failure_reason
            .unwrap()
            .contains("Open Badges 2.0 is retired"));
    }
}

#[tokio::test]
async fn ob3_ignores_token_keys_even_when_they_match_proof_method_id() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/governed_ob3_with_criteria.json")).unwrap();

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

    // The generator independently recorded these proof/document RDF digests.
    // Verify the original detached signature before varying only header order.
    let canonical_digests = hex::decode(concat!(
        "fb7782c709a22ba395265a00107930e7bf72a291426e1aae99f78a0428eed744",
        "473e423da673544b947b56d6f9f285d996918cb958d69904ce38409713426fe4"
    ))
    .unwrap();
    assert_eq!(canonical_digests.len(), 64);
    let signing_input = |header: &str| {
        let mut input = header.as_bytes().to_vec();
        input.push(b'.');
        input.extend_from_slice(&canonical_digests);
        input
    };
    let original_jws = fixture["credential"]["proof"]["jws"].as_str().unwrap();
    let (original_header, original_signature) = original_jws.split_once("..").unwrap();
    let original_signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(original_signature)
        .unwrap()
        .try_into()
        .unwrap();
    let public_key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(fixture["governed_method"]["public_jwk"]["x"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let verifier = VerifyingKey::from_bytes(&public_key).unwrap();
    verifier
        .verify_strict(
            &signing_input(original_header),
            &Signature::from_bytes(&original_signature),
        )
        .unwrap();

    // Public disposable unit-test seed, as pinned by the fixture generator.
    let signer = SigningKey::from_bytes(&[71; 32]);
    assert_eq!(signer.verifying_key().to_bytes(), public_key);
    let reordered_header_bytes = br#"{"alg":"EdDSA","crit":["b64"],"b64":false}"#;
    let reordered_header = URL_SAFE_NO_PAD.encode(reordered_header_bytes);
    let original_header_json: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(original_header).unwrap()).unwrap();
    let reordered_header_json: Value = serde_json::from_slice(reordered_header_bytes).unwrap();
    assert_eq!(original_header_json, reordered_header_json);
    assert_ne!(original_header, reordered_header);
    let reordered_signature = signer.sign(&signing_input(&reordered_header)).to_bytes();
    let headers = [original_header, reordered_header.as_str()];
    let signatures = [original_signature, reordered_signature];
    // Label, protected-header index, signature index, expected validity.
    let cases = [
        ("original", 0, 0, true),
        ("reordered", 1, 1, true),
        ("crossed_reordered", 1, 0, false),
        ("crossed_original", 0, 1, false),
    ];
    let mut native_results = json!({});
    let mut native_mismatch = false;
    for (name, header_index, signature_index, expected) in cases {
        let header = headers[header_index];
        let signature = signatures[signature_index];
        // Both swapped-signature controls must fail independent verification.
        assert_eq!(
            verifier
                .verify_strict(&signing_input(header), &Signature::from_bytes(&signature))
                .is_ok(),
            expected,
            "independent detached JWS case {name}"
        );
        let jws = format!("{}..{}", header, URL_SAFE_NO_PAD.encode(signature));
        if name == "original" {
            assert_eq!(jws, original_jws);
        }
        let mut credential = fixture["credential"].clone();
        credential["proof"]["jws"] = json!(jws);
        let raw = marty_verification::open_badges::verify_ob3_json_async(
            &json!({"credential": credential,
                "document_store": fixture["document_store"]})
            .to_string(),
        )
        .await
        .unwrap();
        let verified: Value = serde_json::from_str(&raw).unwrap();
        native_mismatch |= verified["valid"].as_bool() != Some(expected);
        native_results[name] = json!({
            "valid": verified["valid"],
            "error_codes": verified["error_codes"],
            "errors": verified["errors"]
        });
    }
    let preparation_diagnostic = if native_mismatch {
        let mut unsigned = fixture["credential"].clone();
        unsigned.as_object_mut().unwrap().remove("proof");
        // This API captures input using only a public key; it creates no real
        // signature. Its eddsa-rdfc-2022 proof options are fresh, so the resulting
        // input must not be compared wholesale with this fixture's JWS2020 proof.
        let request = json!({
            "credential": unsigned,
            "issuer_did": fixture["governed_method"]["controller"],
            "verification_method_id": fixture["governed_method"]["id"],
            "public_jwk": fixture["governed_method"]["public_jwk"]
        });
        match marty_verification::vcdm::prepare_vcdm_data_integrity_credential_json_async(
            &request.to_string(),
        )
        .await
        {
            Ok(prepared) => {
                let mut prepared: Value = serde_json::from_str(&prepared).unwrap();
                prepared["credential"]
                    .as_object_mut()
                    .unwrap()
                    .remove("proof");
                json!({
                    "typed_unsigned_credential": prepared["credential"],
                    "eddsa_rdfc_2022_signing_input_b64": prepared["signing_input_b64"]
                })
            }
            Err(error) => json!({"preparation_error": error}),
        }
    } else {
        Value::Null
    };
    // Collect all four native outcomes before retaining both positive and
    // negative requirements. A reordered control never replaces the original.
    for (name, _, _, expected) in cases {
        assert_eq!(
            native_results[name]["valid"].as_bool(),
            Some(expected),
            "public JWS2020 case {}: native_results={}; preparation={}",
            name,
            native_results,
            preparation_diagnostic
        );
    }

    let mut input = governed_badge_context(DetectedCredentialFormat::OpenbadgeV3, &fixture);
    assert!(RustCredentialKernel.verify(&input).await.unwrap().verified);

    input.trust_profile.as_mut().unwrap().document["resolved_verification_methods"][0]
        ["public_jwk"]["x"] = json!("iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w");
    assert!(!RustCredentialKernel.verify(&input).await.unwrap().verified);

    input.trust_profile.as_mut().unwrap().document["resolved_verification_methods"] = json!([]);
    assert!(!RustCredentialKernel.verify(&input).await.unwrap().verified);
}

#[tokio::test]
async fn historical_signed_ob3_without_criteria_is_denied_after_proof_authentication() {
    // Preserve the historical signed bytes. E701 is the post-proof criteria
    // failure; a signature failure would also report OPEN_BADGES_PROOF_INVALID.
    let fixture: Value = serde_json::from_str(include_str!("fixtures/governed_ob3.json")).unwrap();
    let raw = marty_verification::open_badges::verify_ob3_json_async(
        &json!({"credential": fixture["credential"],
            "document_store": fixture["document_store"]})
        .to_string(),
    )
    .await
    .unwrap();
    let verified: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(verified["valid"], false);
    assert_eq!(
        verified["error_codes"],
        json!([marty_verification::error::codes::OPEN_BADGES_INVALID])
    );
    assert!(verified["errors"].as_array().unwrap().iter().any(|error| {
        error
            .as_str()
            .is_some_and(|error| error.contains("achievement criteria"))
    }));
    let input = governed_badge_context(DetectedCredentialFormat::OpenbadgeV3, &fixture);
    let evidence = RustCredentialKernel.verify(&input).await.unwrap();
    assert!(!evidence.verified);
    assert!(evidence.claims.is_empty());
    assert!(evidence.issuer_id.is_none());
}
