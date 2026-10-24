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
        resolved_issuer_public_jwk: None,
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
        Err(PresentationVerificationError::Unavailable) => {
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
            DetectedCredentialFormat::OpenbadgeV2,
            json!({"assertion": {}}),
        ),
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
async fn signed_ob2_uses_governed_key_but_preserves_badge_reference_resolution() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/governed_ob2.json")).unwrap();
    let mut input = governed_badge_context(DetectedCredentialFormat::OpenbadgeV2, &fixture);
    let verified = RustCredentialKernel.verify(&input).await.unwrap();
    assert!(verified.verified);
    assert_eq!(verified.claims["badge_id"], "urn:uuid:badge-1");
    for (reference, forged_id) in [
        ("urn:uuid:badge-1", "urn:uuid:forged-badge"),
        ("did:example:issuer", "did:example:forged"),
    ] {
        input.token["document_store"][reference]["id"] = json!(forged_id);
        let untrusted_metadata = RustCredentialKernel.verify(&input).await.unwrap();
        assert!(!untrusted_metadata.verified);
        assert!(untrusted_metadata.claims.is_empty());
        input.token["document_store"] = fixture["document_store"].clone();
    }

    // Check the governed-key failures with otherwise valid reference metadata.

    input.trust_profile.as_mut().unwrap().document["resolved_verification_methods"][0]
        ["public_jwk"]["x"] = json!("ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ");
    let forged_duplicate = RustCredentialKernel.verify(&input).await.unwrap();
    assert!(!forged_duplicate.verified);
    assert!(forged_duplicate.claims.is_empty());

    input.trust_profile.as_mut().unwrap().document["resolved_verification_methods"] = json!([]);
    let novel_token_key = RustCredentialKernel.verify(&input).await.unwrap();
    assert!(!novel_token_key.verified);
    assert!(novel_token_key.claims.is_empty());

    input = governed_badge_context(DetectedCredentialFormat::OpenbadgeV2, &fixture);
    input.trust_profile.as_mut().unwrap().document["resolved_verification_methods"]
        .as_array_mut()
        .unwrap()
        .push(fixture["governed_method"].clone());
    assert!(RustCredentialKernel.verify(&input).await.is_err());

    input = governed_badge_context(DetectedCredentialFormat::OpenbadgeV2, &fixture);
    input.trust_profile.as_mut().unwrap().document["resolved_verification_methods"][0]
        ["controller"] = json!("did:example:another-issuer");
    assert!(!RustCredentialKernel.verify(&input).await.unwrap().verified);
    input.trust_profile.as_mut().unwrap().document["resolved_verification_methods"][0]
        ["controller"] = json!("did:example:Issuer");
    assert!(!RustCredentialKernel.verify(&input).await.unwrap().verified);

    input = governed_badge_context(DetectedCredentialFormat::OpenbadgeV2, &fixture);
    input.token["assertion"]["id"] = json!("urn:uuid:tampered");
    assert!(!RustCredentialKernel.verify(&input).await.unwrap().verified);

    // Legacy OB2 signs all assertion claims, then appends only the exact
    // verification instructions. It remains valid, but claim changes do not.
    input = governed_badge_context(DetectedCredentialFormat::OpenbadgeV2, &fixture);
    input.token["assertion"]["signature"] = json!("eyJhbGciOiJFZERTQSJ9.eyJAY29udGV4dCI6Imh0dHBzOi8vdzNpZC5vcmcvb3BlbmJhZGdlcy92MiIsInR5cGUiOiJBc3NlcnRpb24iLCJpZCI6InVybjp1dWlkOmFzc2VydGlvbi0xIiwiYmFkZ2UiOiJ1cm46dXVpZDpiYWRnZS0xIiwiaXNzdWVyIjoiZGlkOmV4YW1wbGU6aXNzdWVyIn0.vbiDS-q6erlX5NCirefzxx-7Z4H6-pFDYWilOA5UnSCCE6nRruNtQO0T8uG-1P7GVnH5atk6mQvQJf0JdBjzAg");
    assert!(RustCredentialKernel.verify(&input).await.unwrap().verified);
    input.token["assertion"]["badge"] = json!("urn:uuid:forged-badge");
    assert!(!RustCredentialKernel.verify(&input).await.unwrap().verified);
    input.token["assertion"]["badge"] = json!("urn:uuid:badge-1");
    input.token["assertion"]["verification"]["extra"] = json!("unsigned-option");
    assert!(!RustCredentialKernel.verify(&input).await.unwrap().verified);

    // Standard OB2 may sign a badge reference without a direct issuer field.
    // The signature remains valid, but token-supplied issuer documents cannot
    // supply an authenticated issuer identity for the policy trust gate.
    input = governed_badge_context(DetectedCredentialFormat::OpenbadgeV2, &fixture);
    input.token["assertion"]
        .as_object_mut()
        .unwrap()
        .remove("issuer");
    input.token["assertion"]["signature"] = json!("eyJhbGciOiJFZERTQSJ9.eyJAY29udGV4dCI6Imh0dHBzOi8vdzNpZC5vcmcvb3BlbmJhZGdlcy92MiIsInR5cGUiOiJBc3NlcnRpb24iLCJpZCI6InVybjp1dWlkOmFzc2VydGlvbi0xIiwiYmFkZ2UiOiJ1cm46dXVpZDpiYWRnZS0xIiwidmVyaWZpY2F0aW9uIjp7InR5cGUiOiJzaWduZWQiLCJjcmVhdG9yIjoiZGlkOmV4YW1wbGU6aXNzdWVyI2tleS0xIn19.4V1FG094iFdrKZhCbOV8-XbSD_y944YcqFR6urKJL3QqrYMbcNX4HqfWAlIXtxqHaCUjReNGPJXmrnHC7vzEBQ");
    let referenced = RustCredentialKernel.verify(&input).await.unwrap();
    assert!(referenced.verified);
    assert!(referenced.issuer_id.is_none());
    assert!(referenced.claims.get("issuer_id").is_none());
}

#[tokio::test]
async fn ob3_ignores_token_keys_even_when_they_match_proof_method_id() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/governed_ob3.json")).unwrap();
    let mut input = governed_badge_context(DetectedCredentialFormat::OpenbadgeV3, &fixture);
    assert!(RustCredentialKernel.verify(&input).await.unwrap().verified);

    input.trust_profile.as_mut().unwrap().document["resolved_verification_methods"][0]
        ["public_jwk"]["x"] = json!("iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w");
    assert!(!RustCredentialKernel.verify(&input).await.unwrap().verified);

    input.trust_profile.as_mut().unwrap().document["resolved_verification_methods"] = json!([]);
    assert!(!RustCredentialKernel.verify(&input).await.unwrap().verified);
}

#[tokio::test]
async fn unsigned_hosted_ob2_remains_parseable_but_has_no_verified_policy_claims() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/governed_ob2.json")).unwrap();
    let mut input = governed_badge_context(DetectedCredentialFormat::OpenbadgeV2, &fixture);
    input.token["assertion"]
        .as_object_mut()
        .unwrap()
        .remove("signature");
    input.token["assertion"]
        .as_object_mut()
        .unwrap()
        .remove("verification");
    let core_request = json!({"assertion": input.token["assertion"], "document_store": input.token["document_store"]});
    let core_result: Value = serde_json::from_str(
        &marty_verification::open_badges::verify_ob2_json(&core_request.to_string()).unwrap(),
    )
    .unwrap();
    assert_eq!(core_result["valid"], true);
    let evidence = RustCredentialKernel.verify(&input).await.unwrap();
    assert!(!evidence.verified);
    assert!(evidence.claims.is_empty());
    assert!(evidence.issuer_id.is_none());
    assert!(!evidence.warnings.is_empty());
}
