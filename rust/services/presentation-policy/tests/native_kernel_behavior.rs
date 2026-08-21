use marty_presentation_policy::{
    CredentialVerificationContext, CredentialVerificationKernel, PresentationVerificationError,
    RustCredentialKernel,
};
use marty_verification::credential_format::DetectedCredentialFormat;
use serde_json::{json, Map, Value};

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
async fn mdoc_fails_closed_until_the_native_authentication_revision_is_pinned() {
    let error = RustCredentialKernel
        .verify(&context(
            DetectedCredentialFormat::Mdoc,
            json!({"documents": []}),
        ))
        .await
        .expect_err("mDoc must not use a compatibility implementation");

    assert!(matches!(error, PresentationVerificationError::Unavailable));
}
