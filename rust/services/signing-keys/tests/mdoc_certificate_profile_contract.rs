//! Pure black-box producer/configuration controls. No Redis, KMS, keys or network.
use axum::{body::Body, http::StatusCode};
use der::{Decode, DecodePem, Encode};
use marty_signing_grant::certificate_profile::MdocCertificateMetadata;
use marty_signing_keys::{
    certificate_issuance::{prepare_csca, prepare_mdoc_iaca, VerifiedDscSubject},
    http::router_with_all_keys_grants_and_mdoc,
    mdoc_certificate::{MdocAuthorityConfiguration, MdocCertificateOptions},
};
use serde_json::{json, Value};
use tower::ServiceExt;
use x509_cert::{
    certificate::TbsCertificate,
    ext::pkix::{BasicConstraints, CrlDistributionPoints, IssuerAltName, KeyUsage},
};

fn public_metadata() -> MdocCertificateMetadata {
    MdocCertificateMetadata {
        issuer_contact_uri: "https://authority.example/contact".into(),
        crl_distribution_uri: "https://authority.example/mdoc.crl".into(),
    }
}

#[test]
fn public_mdoc_iaca_builder_has_bound_der_and_preserves_legacy_csca_profile() {
    let csr = x509_cert::request::CertReq::from_pem(include_str!(
        "fixtures/public_certificates/dsc.csr.pem"
    ))
    .unwrap();
    let public_key = serde_json::to_value(
        marty_crypto::jwk::public_key_der_to_jwk(&csr.info.public_key.to_der().unwrap()).unwrap(),
    )
    .unwrap();
    let subject = VerifiedDscSubject::from_csr_pem(
        include_str!("fixtures/public_certificates/dsc.csr.pem"),
        &public_key,
    )
    .unwrap();
    let now = std::time::SystemTime::now();
    let prepared = prepare_mdoc_iaca(&subject, &[1], 365, now, &public_metadata()).unwrap();
    let tbs = TbsCertificate::from_der(prepared.signing_bytes()).unwrap();
    let legacy = prepare_csca(&subject, &[1], 365, now).unwrap();
    let legacy = TbsCertificate::from_der(legacy.signing_bytes()).unwrap();
    assert_eq!(tbs.subject_public_key_info, csr.info.public_key);
    assert_eq!(tbs.subject, tbs.issuer);
    let (critical, constraints) = tbs.get::<BasicConstraints>().unwrap().unwrap();
    assert!(critical && constraints.ca);
    assert_eq!(constraints.path_len_constraint, Some(0));
    let (critical, usage) = tbs.get::<KeyUsage>().unwrap().unwrap();
    assert!(critical && usage.key_cert_sign() && usage.crl_sign());
    assert!(!legacy.get::<KeyUsage>().unwrap().unwrap().1.crl_sign());
    assert_eq!(tbs.get::<IssuerAltName>().unwrap().unwrap().1 .0.len(), 1);
    assert_eq!(
        tbs.get::<CrlDistributionPoints>()
            .unwrap()
            .unwrap()
            .1
             .0
            .len(),
        1
    );
    let mut missing = public_metadata();
    missing.crl_distribution_uri.clear();
    assert!(prepare_mdoc_iaca(&subject, &[1], 365, now, &missing).is_err());
    assert!(prepare_mdoc_iaca(&subject, &[0], 365, now, &public_metadata()).is_err());
    assert!(prepared.finish(&[0; 64]).is_err());
    // There is no certificate or private-key fixture synthesized here.
}

#[test]
fn public_mdoc_configuration_is_exactly_owned_and_missing_or_ambiguous_is_not_authority() {
    let org = uuid::Uuid::new_v4().to_string();
    let authority = MdocAuthorityConfiguration {
        organization_id: org.clone(),
        issuer_did: "did:web:authority.example".into(),
        certificate: public_metadata(),
    };
    let entries = MdocCertificateOptions::parse_authorities(Some(
        &serde_json::to_string(&vec![authority.clone()]).unwrap(),
    ))
    .unwrap();
    let options = MdocCertificateOptions {
        authorities: entries,
        ..Default::default()
    };
    assert_eq!(
        options.metadata_for(&org, &authority.issuer_did).unwrap(),
        public_metadata()
    );
    assert!(options
        .metadata_for(&uuid::Uuid::new_v4().to_string(), &authority.issuer_did)
        .is_err());
    assert!(options
        .metadata_for(&org, "did:web:foreign.example")
        .is_err());
    assert!(MdocCertificateOptions::parse_authorities(Some(
        &serde_json::to_string(&vec![authority.clone(), authority]).unwrap()
    ))
    .is_err());
    assert!(MdocCertificateOptions::default()
        .metadata_for(&org, "did:web:authority.example")
        .is_err());
}

#[tokio::test]
async fn mdoc_ceremony_does_not_borrow_passport_authority_or_invent_publication_configuration() {
    const MDOC_KEY: &str = "mdoc-independent-operator-credential-000001";
    const PASSPORT_KEY: &str = "passport-independent-operator-credential-0001";
    let app = router_with_all_keys_grants_and_mdoc(
        "shared-internal-credential".into(),
        None,
        None,
        None,
        Some(PASSPORT_KEY.into()),
        None,
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        MdocCertificateOptions {
            iaca_gateway_key: Some(MDOC_KEY.into()),
            ..Default::default()
        },
    );
    let org = uuid::Uuid::new_v4().to_string();
    let body = json!({"issuer_did":"did:web:authority.example", "certificate_id":"iaca-1", "country":"US", "organization":"Synthetic", "common_name":"Synthetic IACA", "validity_days":365});
    let request = |key: &str, body: Value| {
        axum::http::Request::post(format!("/v1/signing-keys/issuer-identities/mdoc-iaca-self-signed-certificate?organization_id={org}"))
        .header("x-api-key", key).header("x-user-id", "operator-fixture").header("content-type", "application/json")
        .body(Body::from(body.to_string())).unwrap()
    };
    assert_eq!(
        app.clone()
            .oneshot(request(PASSPORT_KEY, body.clone()))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let missing = app
        .clone()
        .oneshot(request(MDOC_KEY, body.clone()))
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let error: Value = serde_json::from_slice(
        &axum::body::to_bytes(missing.into_body(), 16_384)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(error["error"], "MDOC_ISSUER_CONFIGURATION_REQUIRED");
    let mut injected = body.clone();
    injected["mdoc_metadata"] = json!({"issuer_contact_uri":"https://forged.example", "crl_distribution_uri":"https://forged.example/crl"});
    assert_eq!(
        app.oneshot(request(MDOC_KEY, injected))
            .await
            .unwrap()
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
}
