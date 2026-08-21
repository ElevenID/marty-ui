use marty_presentation_policy::{
    CredentialVerificationContext, CredentialVerificationKernel, PresentationVerificationError,
    ResolvedTrustProfile, RustCredentialKernel,
};
use marty_verification::credential_format::DetectedCredentialFormat;
use serde_json::{json, Map, Value};
use uuid::Uuid;

fn context(format: DetectedCredentialFormat, token: Value) -> CredentialVerificationContext {
    CredentialVerificationContext {
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
