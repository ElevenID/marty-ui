//! Opt-in real Transit IACA -> DS producer/attachment test. No private key is
//! generated, exported or reconstructed by the test process. Public issuer/CRL
//! configuration is operator supplied; this test does not prove CRL publication.
#[path = "support/disposable_backends.rs"]
mod disposable_backends;

use axum::{
    body::{to_bytes, Body},
    http::{Method, Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use der::{DecodePem, Encode};
use marty_signing_grant::certificate_profile::MdocCertificateMetadata;
use marty_signing_keys::{
    csca_lifecycle::CscaLifecycleStore,
    documents::DocumentStore,
    http::router_with_all_keys_grants_and_mdoc,
    kms::{read_managed_openbao, ProviderRequest},
    mdoc_certificate::{MdocAuthorityConfiguration, MdocCertificateOptions},
    profiles::ProfileStore,
    registry::RegistryStore,
};
use serde_json::{json, Value};
use tower::ServiceExt;
use x509_cert::{
    ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier},
    Certificate,
};

const INTERNAL: &str = "mdoc-live-fixture-internal-credential";
const IACA_OPERATOR: &str = "mdoc-live-fixture-iaca-operator-credential-0001";
const DS_OPERATOR: &str = "mdoc-live-fixture-ds-operator-credential-000001";

async fn call(app: &Router, method: Method, path: &str, key: &str, body: Value) -> Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json")
                .header("x-api-key", key)
                .header("x-user-id", "owned-mdoc-fixture-operator")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1_048_576).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "public certificate route returned {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
#[ignore = "requires guarded disposable HTTPS OpenBao/Redis plus explicit public MDOC issuer/CRL configuration"]
async fn managed_mdoc_chain_has_real_remote_signatures_and_profile_bound_attachment() {
    // Fail missing governance before creating any key/profile/certificate.
    let metadata = MdocCertificateMetadata {
        issuer_contact_uri: std::env::var("MARTY_TEST_MDOC_ISSUER_CONTACT_URI")
            .expect("explicit public issuer contact"),
        crl_distribution_uri: std::env::var("MARTY_TEST_MDOC_CRL_DISTRIBUTION_URI")
            .expect("explicit public CRL configuration"),
    };
    metadata
        .validate()
        .expect("governed public MDOC configuration");
    let redis_url = disposable_backends::disposable_redis_url().await;
    let _guarded_bao = disposable_backends::disposable_openbao_envelope().await;
    let endpoint = std::env::var("MARTY_TEST_OPENBAO_URL").unwrap();
    assert_eq!(std::env::var("BAO_ADDR").as_deref(), Ok(endpoint.as_str()));
    let org = uuid::Uuid::new_v4().to_string();
    let iaca_did = format!("did:web:issuer.example:orgs:{org}-iaca");
    let ds_did = format!("did:web:issuer.example:orgs:{org}-ds");
    let registry = RegistryStore::connect(&redis_url)
        .await
        .unwrap()
        .with_managed_openbao(Some(endpoint.clone()));
    let profiles = ProfileStore::from_connection(registry.connection());
    let documents = DocumentStore::from_connection(registry.connection());
    let lifecycle = CscaLifecycleStore::from_connection(registry.connection());
    let app = router_with_all_keys_grants_and_mdoc(
        INTERNAL.into(),
        None,
        None,
        None,
        None,
        None,
        false,
        Some(registry),
        Some(documents.clone()),
        Some(lifecycle),
        Some(profiles.clone()),
        None,
        Some("issuer.example".into()),
        None,
        MdocCertificateOptions {
            iaca_gateway_key: Some(IACA_OPERATOR.into()),
            dsc_gateway_key: Some(DS_OPERATOR.into()),
            authorities: vec![MdocAuthorityConfiguration {
                organization_id: org.clone(),
                issuer_did: iaca_did.clone(),
                certificate: metadata,
            }],
        },
    );
    let identities = format!("/v1/signing-keys/issuer-identities?organization_id={org}");
    for (purpose, did) in [("mdoc_iaca", &iaca_did), ("mdoc_dsc", &ds_did)] {
        call(&app, Method::POST, &identities, INTERNAL, json!({"issuer_did":did,"key_purpose":purpose,"credential_format":"MDOC","algorithm":"ES256"})).await;
    }
    let stored_profiles = profiles.list(&org).await.unwrap();
    let find_profile = |purpose: &str| {
        stored_profiles["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["key_purpose"] == purpose)
            .unwrap()
    };
    let iaca_profile = find_profile("mdoc_iaca");
    let ds_profile = find_profile("mdoc_dsc");
    assert_ne!(
        iaca_profile["signing_key_reference"],
        ds_profile["signing_key_reference"]
    );
    // Existing provisioning/test authority reads public Transit metadata. No
    // production sign-only policy is expanded for this assertion.
    let mut observed_keys = std::collections::BTreeMap::new();
    for profile in [iaca_profile, ds_profile] {
        let observed = read_managed_openbao(ProviderRequest { service_config: json!({
            "id":"managed-openbao-transit","service_type":"openbao-transit","auth_mode":"service_token",
            "endpoint":endpoint,"mount":"transit","key_reference":profile["signing_key_reference"],"algorithm":"ES256"}) }).await.unwrap();
        assert_eq!(observed["exportable"], false);
        assert_eq!(observed["allow_plaintext_backup"], false);
        assert!(observed["public_jwk"].get("d").is_none());
        observed_keys.insert(
            profile["id"].as_str().unwrap().to_owned(),
            observed["public_jwk"].clone(),
        );
    }
    let iaca_path = format!("/v1/signing-keys/issuer-identities/mdoc-iaca-self-signed-certificate?organization_id={org}");
    let iaca_request = json!({"issuer_did":iaca_did,"certificate_id":"owned-iaca-1","country":"US","organization":"Owned MDOC contract","common_name":"Owned IACA","validity_days":365});
    let iaca = call(
        &app,
        Method::POST,
        &iaca_path,
        IACA_OPERATOR,
        iaca_request.clone(),
    )
    .await;
    assert_eq!(
        call(&app, Method::POST, &iaca_path, IACA_OPERATOR, iaca_request).await,
        iaca
    );
    let ds_path =
        format!("/v1/signing-keys/issuer-identities/mdoc-dsc-certificate?organization_id={org}");
    let ds_request = json!({"dsc_issuer_did":ds_did,"iaca_issuer_did":iaca_did,"iaca_certificate_id":"owned-iaca-1",
        "country":"US","organization":"Owned MDOC contract","common_name":"Owned document signer","validity_days":30,"idempotency_key":"owned-mdoc-chain"});
    let ds = call(
        &app,
        Method::POST,
        &ds_path,
        DS_OPERATOR,
        ds_request.clone(),
    )
    .await;
    assert_eq!(
        call(&app, Method::POST, &ds_path, DS_OPERATOR, ds_request).await,
        ds
    );
    let root = Certificate::from_pem(iaca["certificate_pem"].as_str().unwrap()).unwrap();
    let leaf = Certificate::from_pem(ds["certificate_pem"].as_str().unwrap()).unwrap();
    let root_der = root.to_der().unwrap();
    let leaf_der = leaf.to_der().unwrap();
    assert!(marty_crypto::certificate::verify_certificate_signature(&root_der, &root_der).unwrap());
    assert!(marty_crypto::certificate::verify_certificate_signature(&leaf_der, &root_der).unwrap());
    let root_ski = root
        .tbs_certificate
        .get::<SubjectKeyIdentifier>()
        .unwrap()
        .unwrap()
        .1;
    let leaf_aki = leaf
        .tbs_certificate
        .get::<AuthorityKeyIdentifier>()
        .unwrap()
        .unwrap()
        .1;
    assert_eq!(leaf_aki.key_identifier, Some(root_ski.0));
    let certificate_jwk = serde_json::to_value(
        marty_crypto::jwk::certificate_pem_to_jwk(ds["certificate_pem"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let expected_key = &observed_keys[ds_profile["id"].as_str().unwrap()];
    for field in ["kty", "crv", "x", "y"] {
        assert_eq!(
            certificate_jwk[field], expected_key[field],
            "issued certificate must match current managed SPKI"
        );
    }
    // Re-attach the actual remotely signed chain through the normal production
    // SPKI/profile/crypto validator; an idempotent issued attachment stays fixed.
    call(&app, Method::PUT, &format!("/v1/signing-keys/issuer-identities/certificate?organization_id={org}"), INTERNAL,
        json!({"issuer_did":ds_did,"key_purpose":"mdoc_dsc","credential_format":"MDOC","algorithm":"ES256",
            "cert_pem":ds["certificate_pem"],"cert_chain_pem":ds["chain_pem"]})).await;
    let certificates = documents.certificate_overrides(&org).await.unwrap();
    let attached = &certificates["profiles"][ds_profile["id"].as_str().unwrap()];
    assert_eq!(attached["x5c"], json!([STANDARD.encode(&leaf_der)]));
    assert_eq!(attached["cert_chain_pem"], iaca["certificate_pem"]);
    assert_eq!(attached["cert_pem"], ds["certificate_pem"]);
    assert_eq!(attached["certificate_profile"], "mdoc_document_signer");
}
