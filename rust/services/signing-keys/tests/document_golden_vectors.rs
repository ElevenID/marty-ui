use marty_signing_keys::documents::{
    build_did_document, build_jwks_document, certificate_alerts, inspect_certificate,
    CertificateAlertsRequest, InspectCertificateRequest, PublishDidRequest, PublishJwkRequest,
};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/document_vectors.json")).unwrap()
}

#[test]
fn certificate_inspection_uses_the_canonical_native_kernel() {
    let fixture = fixture();
    let vector = &fixture["certificate"];
    let result = inspect_certificate(&InspectCertificateRequest {
        cert_pem: vector["cert_pem"].as_str().unwrap().to_string(),
        cert_chain_pem: None,
        expected_public_jwk: Some(vector["expected_jwk"].clone()),
    })
    .unwrap();
    assert_eq!(result.expires_at, vector["expected_expiry"]);
    assert_eq!(result.public_jwk, vector["expected_jwk"]);
    assert_eq!(result.x5c, [vector["expected_x5c"].as_str().unwrap()]);
    assert_eq!(result.public_key_matches, Some(true));

    assert!(inspect_certificate(&InspectCertificateRequest {
        cert_pem: "not a certificate".to_string(),
        cert_chain_pem: None,
        expected_public_jwk: None,
    })
    .is_err());
}

#[test]
fn certificate_alerts_match_the_language_neutral_vector() {
    let fixture = fixture();
    let vector = &fixture["certificate_alerts"];
    let request: CertificateAlertsRequest =
        serde_json::from_value(vector["input"].clone()).unwrap();
    let result = certificate_alerts(request).unwrap();
    assert_eq!(
        serde_json::to_value(result.alerts).unwrap(),
        vector["expected"]
    );
}

#[test]
fn jwks_upsert_replaces_one_service_and_strips_private_material() {
    let fixture = fixture();
    let vector = &fixture["jwks"];
    let request: PublishJwkRequest = serde_json::from_value(vector["request"].clone()).unwrap();
    let result = build_jwks_document(
        vector["existing"].clone(),
        vector["organization_id"].as_str().unwrap(),
        vector["service_id"].as_str().unwrap(),
        request,
    )
    .unwrap();
    assert_eq!(result.jwk, vector["expected_jwk"]);
    assert_eq!(result.key_count, 2);
    assert!(result.document["keys"]
        .as_array()
        .unwrap()
        .iter()
        .any(|key| key["kid"] == vector["expected_kept_kid"]));
    assert!(result.jwk.get("d").is_none());
}

#[test]
fn did_publication_and_failures_match_language_neutral_vectors() {
    let fixture = fixture();
    let vector = &fixture["did"];
    let request: PublishDidRequest = serde_json::from_value(vector["request"].clone()).unwrap();
    let result = build_did_document(None, vector["service_id"].as_str().unwrap(), request).unwrap();
    assert_eq!(result.did_id, vector["expected_did"]);
    assert_eq!(result.org_slug.as_deref(), Some("acme"));
    assert_eq!(
        result.verification_method["id"],
        vector["expected_method_id"]
    );
    assert!(result.verification_method["publicKeyJwk"]
        .get("d")
        .is_none());
    assert_eq!(result.verification_method_count, 1);

    for invalid in fixture["invalid_did_requests"].as_array().unwrap() {
        let request: PublishDidRequest = serde_json::from_value(invalid.clone()).unwrap();
        assert!(build_did_document(None, "svc-a", request).is_err());
    }
}
