//! Real issuer-signature regression for the explicitly selected machine
//! profile. The test signer exists only in this unit module; the joined gate
//! uses the production HTTP signer and a nonexportable OpenBao key.
use super::*;
use marty_oid4vci::{
    jose::verify_compact_jwt_with_public_jwk,
    jwt_vc_profile::{decode_unverified_jwt_vc, validate_unsigned_jwt_vc_profile_claims},
    JwtVcSecuringProfile,
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use std::sync::atomic::{AtomicUsize, Ordering};

struct ProfileSigner {
    key: SigningKey,
    calls: AtomicUsize,
}
#[async_trait]
impl DidSigner for ProfileSigner {
    async fn sign(&self, request: SignRequest) -> Result<SignResponse, CredentialIssuanceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let signature: Signature = self.key.sign(&request.payload);
        Ok(SignResponse {
            signature_b64: URL_SAFE_NO_PAD.encode(signature.normalize_s().to_bytes()),
            signature_native_b64: None,
        })
    }
}

fn input(jwk: Value) -> CredentialBuildRequest {
    let subject = format!("did:jwk:{}", URL_SAFE_NO_PAD.encode(jwk.to_string()));
    CredentialBuildRequest {
        organization_id: "profile-contract-organization".into(),
        kind: CredentialBuilderKind::JwtVcJson,
        response_format: "jwt_vc_json".into(),
        remote_credential_format: "jwt_vc_json".into(),
        credential_id: "urn:uuid:8b76fc85-87b0-49ec-a84d-e677e201c325".into(),
        credential_type: "MachineCredential".into(),
        achievement_id: None,
        subject_did: Some(subject.clone()),
        holder_jwk: Some(jwk.clone()),
        claims: Map::new(),
        credential_subject: Some(json!({"id":subject,"runtime":"public-unit-fixture"})),
        credential_document: None,
        selective_disclosure_claims: vec![],
        validity_seconds: 3600,
        jwt_vc_signing_timing: None,
        status_list_entries: vec![],
        issuer: crate::credential::IssuerContext {
            issuer_profile_id: "fixture-machine-profile".into(),
            issuer_did: "did:web:machine-issuer.example.test".into(),
            signing_service_id: "fixture-machine-service".into(),
            algorithm: "ES256".into(),
            verification_method_id: Some("did:web:machine-issuer.example.test#machine".into()),
            public_jwk: Some(jwk),
            certificate_chain: vec![],
            raw_context: json!({"signing_key_reference":"fixture-purpose-separated-machine-key"}),
        },
    }
}

fn verified(credential: &str, request: &CredentialBuildRequest) -> bool {
    let response:Value=serde_json::from_str(
        &marty_verification::vcdm::verify_vcdm_jwt_with_profile_json(&json!({
            "token":credential,"expected_issuer":request.issuer.issuer_did,
            "expected_verification_method":request.issuer.verification_method_id,
            "expected_algorithm":request.issuer.algorithm,"issuer_public_jwk":request.issuer.public_jwk,
            "expected_securing_profile":"marty_nested_vc2_jwt_v1",
            "evaluated_at":Utc::now().timestamp()+1,
        }).to_string())
    ).unwrap();
    response["valid"] == true
}

#[tokio::test]
async fn machine_nested_profile_is_explicit_binds_reserved_identity_and_rejects_incompatible_signing(
) {
    let key = SigningKey::from_slice(&[0x2a; 32]).unwrap();
    let point = key.verifying_key().to_sec1_point(false);
    let jwk = json!({"kty":"EC","crv":"P-256",
        "x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),"y":URL_SAFE_NO_PAD.encode(point.y().unwrap())});
    let signer = Arc::new(ProfileSigner {
        key,
        calls: AtomicUsize::new(0),
    });
    let request = input(jwk.clone());
    let legacy = HttpCredentialBuilder::with_signer(signer.clone());
    let original = legacy.build(&request).await.unwrap();
    assert!(
        verify_compact_jwt_with_public_jwk(&original.credential, &jwk.to_string(), "ES256").is_ok()
    );
    let (_, claims) = decode_unverified_jwt_vc(
        &original.credential,
        JwtVcSecuringProfile::MartyNestedVc2JwtV1,
    )
    .unwrap();
    assert!(
        claims["vc"].get("id").is_none(),
        "legacy transport/profile output must stay unchanged"
    );
    assert!(validate_unsigned_jwt_vc_profile_claims(
        &claims,
        Utc::now().timestamp() + 1,
        JwtVcSecuringProfile::MartyNestedVc2JwtV1
    )
    .is_err());
    assert!(!verified(&original.credential, &request));

    let selected = legacy.clone().with_machine_nested_vc2_jwt_profile();
    let issued = selected.build(&request).await.unwrap();
    assert!(verified(&issued.credential, &request));
    let (_, claims) = decode_unverified_jwt_vc(
        &issued.credential,
        JwtVcSecuringProfile::MartyNestedVc2JwtV1,
    )
    .unwrap();
    let checked = validate_unsigned_jwt_vc_profile_claims(
        &claims,
        Utc::now().timestamp() + 1,
        JwtVcSecuringProfile::MartyNestedVc2JwtV1,
    )
    .unwrap();
    assert_eq!(checked.credential_id, request.credential_id);
    assert_eq!(claims["vc"]["id"], request.credential_id);
    assert_eq!(claims["jti"], request.credential_id);
    assert_eq!(
        claims["vc"]["type"],
        json!(["VerifiableCredential", "MachineCredential"])
    );
    assert_eq!(checked.subject_id, request.subject_did.as_deref().unwrap());
    assert_eq!(claims["sub"], request.subject_did.as_deref().unwrap());
    assert!(claims.get("nbf").is_some());
    let valid_from =
        DateTime::parse_from_rfc3339(claims["vc"]["validFrom"].as_str().unwrap()).unwrap();
    let valid_until =
        DateTime::parse_from_rfc3339(claims["vc"]["validUntil"].as_str().unwrap()).unwrap();
    assert_eq!(
        valid_until.signed_duration_since(valid_from).num_seconds(),
        request.validity_seconds
    );
    assert_eq!(claims["iat"], valid_from.timestamp());
    assert_eq!(claims["nbf"], valid_from.timestamp());
    assert_eq!(claims["exp"], valid_until.timestamp());
    assert!(claims["vc"].get("credentialStatus").is_none());
    let mut parts: Vec<_> = issued.credential.split('.').map(str::to_owned).collect();
    parts[2] = URL_SAFE_NO_PAD.encode([0x00; 64]);
    assert!(
        !verified(&parts.join("."), &request),
        "native verification must authenticate the issuer signature"
    );

    let signed = signer.calls.load(Ordering::SeqCst);
    assert_eq!(signed, 2);
    for incompatible in [
        "kind",
        "type",
        "remote_format",
        "response_format",
        "algorithm",
        "direct_timing",
        "document",
        "status_entry",
        "status_claim",
        "subject",
        "missing_subject",
        "identifier",
        "nil_identifier",
        "mixed_claims",
        "selective_disclosure",
        "expiry",
        "achievement",
    ] {
        let mut invalid = request.clone();
        match incompatible {
            "kind" => invalid.kind = CredentialBuilderKind::SdJwt,
            "type" => invalid.credential_type = "AnotherCredential".into(),
            "remote_format" => invalid.remote_credential_format = "application/vc+jwt".into(),
            "response_format" => invalid.response_format = "application/vc+jwt".into(),
            "algorithm" => invalid.issuer.algorithm = "RS256".into(),
            "direct_timing" => {
                invalid.jwt_vc_signing_timing = Some(
                    marty_jwt_vc_issuance::JwtVcIssuanceSelection::new(
                        marty_jwt_vc_issuance::JwtVcTemplatePolicy::new(3600).unwrap(),
                        "MachineCredential",
                        "template-fixture",
                        1,
                        86400,
                        0,
                    )
                    .unwrap()
                    .timing_at(Utc::now().timestamp())
                    .unwrap(),
                )
            }
            "document" => invalid.credential_document = Some(json!({})),
            "status_entry" => invalid.status_list_entries = vec![json!({"index":1})],
            "status_claim" => {
                invalid.claims.insert(
                    "credentialStatus".into(),
                    json!({"id":"https://status.example/list"}),
                );
            }
            "subject" => {
                invalid.credential_subject = Some(json!({"id":"did:web:other-machine.example"}))
            }
            "missing_subject" => invalid.subject_did = None,
            "identifier" => {
                invalid.credential_id = "urn:uuid:8B76FC85-87B0-49EC-A84D-E677E201C325".into()
            }
            "nil_identifier" => {
                invalid.credential_id = "urn:uuid:00000000-0000-0000-0000-000000000000".into()
            }
            "mixed_claims" => {
                invalid.claims.insert("unexpected".into(), json!(true));
            }
            "selective_disclosure" => invalid.selective_disclosure_claims = vec!["runtime".into()],
            "expiry" => invalid.validity_seconds = 0,
            "achievement" => {
                invalid.achievement_id = Some("https://badge.example/achievement".into())
            }
            _ => unreachable!(),
        }
        assert!(
            selected.build(&invalid).await.is_err(),
            "unsupported selection {incompatible}"
        );
        assert_eq!(
            signer.calls.load(Ordering::SeqCst),
            signed,
            "unsupported selection {incompatible} must never sign"
        );
    }
}
