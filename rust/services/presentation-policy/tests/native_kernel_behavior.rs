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
    let fixture: Value = serde_json::from_str(include_str!("fixtures/governed_ob3.json")).unwrap();
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
    let fixture: Value = serde_json::from_str(include_str!("fixtures/governed_ob3.json")).unwrap();
    let mut input = governed_badge_context(DetectedCredentialFormat::OpenbadgeV3, &fixture);
    assert!(RustCredentialKernel.verify(&input).await.unwrap().verified);

    input.trust_profile.as_mut().unwrap().document["resolved_verification_methods"][0]
        ["public_jwk"]["x"] = json!("iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w");
    assert!(!RustCredentialKernel.verify(&input).await.unwrap().verified);

    input.trust_profile.as_mut().unwrap().document["resolved_verification_methods"] = json!([]);
    assert!(!RustCredentialKernel.verify(&input).await.unwrap().verified);
}
