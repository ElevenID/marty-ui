//! Opt-in disposable acceptance for the managed passport CSCA -> DSC -> SOD path.
//! Certificate bodies are assembled here, but every certificate and SOD
//! signature is made by a Transit-held key. No private key enters this test.

use std::{collections::BTreeMap, time::Duration};

use axum::{
    body::{to_bytes, Body},
    extract::Query,
    http::{header::CONTENT_TYPE, Method, Request, StatusCode},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use const_oid::ObjectIdentifier;
use der::{asn1::BitString, DecodePem, Encode, EncodePem};
use marty_crypto::certificate::{load_certificate_pem, verify_certificate_signature};
use marty_issuance_service::passport_signer::{ManagedProfileSigner, SignerError};
use marty_signing_keys::{
    csca_lifecycle::CscaLifecycleStore,
    documents::DocumentStore,
    http::router_with_dependencies,
    kms::{self, SignRequest},
    profiles::{FindProfilesRequest, ProfileStore},
    registry::RegistryStore,
};
use num_bigint::BigUint;
use serde_json::{json, Value};
use spki::AlgorithmIdentifierOwned;
use tokio::net::TcpListener;
use tower::ServiceExt;
use x509_cert::{
    certificate::{Certificate, TbsCertificate, Version},
    ext::{
        pkix::{BasicConstraints, KeyUsage, KeyUsages},
        AsExtension,
    },
    request::CertReq,
    serial_number::SerialNumber,
    time::Validity,
};

const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const INTERNAL_KEY: &str = "disposable-passport-chain-internal-key";

async fn route(app: &Router, method: Method, path: &str, body: Value) -> Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header(CONTENT_TYPE, "application/json")
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
        "{}: {}",
        path,
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap()
}

fn signing_config(service: &Value, profile: &Value) -> Value {
    let mut config = service.clone();
    config["key_reference"] = profile["signing_key_reference"].clone();
    config["algorithm"] = json!("ES256");
    config
}

// Test-only X.509 assembly. The TBS bytes are sent to the real KMS adapter;
// this function never creates or loads a local signing key.
async fn issue_certificate(
    csr_pem: &str,
    issuer: x509_cert::name::Name,
    signer_config: Value,
    serial: u8,
    ca: bool,
) -> String {
    let csr = CertReq::from_pem(csr_pem).unwrap();
    let subject = csr.info.subject;
    let mut extensions = Vec::new();
    extensions.push(
        BasicConstraints {
            ca,
            path_len_constraint: ca.then_some(0),
        }
        .to_extension(&subject, &extensions)
        .unwrap(),
    );
    let usage = if ca {
        KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
    } else {
        KeyUsage(KeyUsages::DigitalSignature.into())
    };
    extensions.push(usage.to_extension(&subject, &extensions).unwrap());
    let algorithm = AlgorithmIdentifierOwned {
        oid: ECDSA_SHA256,
        parameters: None,
    };
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[serial]).unwrap(),
        signature: algorithm.clone(),
        issuer,
        validity: Validity::from_now(Duration::from_secs(30 * 24 * 60 * 60)).unwrap(),
        subject,
        subject_public_key_info: csr.info.public_key,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };
    let signed = kms::sign(SignRequest {
        service_config: signer_config,
        payload_b64: URL_SAFE_NO_PAD.encode(tbs.to_der().unwrap()),
    })
    .await
    .unwrap();
    assert_eq!(signed.signature_encoding, "der");
    let signature = URL_SAFE_NO_PAD.decode(signed.signature_b64).unwrap();
    Certificate {
        tbs_certificate: tbs,
        signature_algorithm: algorithm,
        signature: BitString::from_bytes(&signature).unwrap(),
    }
    .to_pem(der::pem::LineEnding::LF)
    .unwrap()
}

// The native signer uses the Gateway's internal path. This adapter performs
// the same path/body conversion against the real Rust Signing Keys router.
fn internal_gateway_adapter(signing: Router) -> Router {
    let resolver = signing.clone();
    let signer = signing.clone();
    Router::new()
        .route(
            "/internal/signing-keys/resolve-issuer-did",
            get(move |Query(query): Query<BTreeMap<String, String>>| {
                let signing = resolver.clone();
                async move {
                    let body = json!({
                        "organization_id": query.get("organization_id"),
                        "issuer_did": query.get("issuer_did"),
                        "verification_method_id": query.get("verification_method_id"),
                        "credential_format": query.get("credential_format"),
                        "key_purpose": query.get("key_purpose"),
                        "algorithm": query.get("algorithm"),
                    });
                    forward(
                        &signing,
                        Method::POST,
                        "/internal/compat/resolve-issuer-did",
                        body,
                    )
                    .await
                }
            }),
        )
        .route(
            "/internal/signing-keys/issuer-dids/sign",
            post(
                move |Query(query): Query<BTreeMap<String, String>>,
                      Json(mut body): Json<Value>| {
                    let signing = signer.clone();
                    async move {
                        body["organization_id"] = json!(query.get("organization_id"));
                        forward(
                            &signing,
                            Method::POST,
                            "/internal/compat/issuer-dids/sign",
                            body,
                        )
                        .await
                    }
                },
            ),
        )
        .route(
            "/internal/signing-keys/csca-trust-anchors",
            get(move |Query(query): Query<BTreeMap<String, String>>| {
                let signing = signing.clone();
                async move {
                    let organization_id = query.get("organization_id").expect("organization scope");
                    let path = format!("/internal/documents/{organization_id}/csca-trust-anchors");
                    forward(&signing, Method::GET, &path, Value::Null).await
                }
            }),
        )
}

async fn forward(app: &Router, method: Method, path: &str, body: Value) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("x-api-key", INTERNAL_KEY)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires independently marked disposable Redis and OpenBao instances"]
async fn managed_passport_chain_issues_and_verifies_sod_without_exporting_private_keys() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
    let parsed_redis = url::Url::parse(&redis_url).expect("disposable Redis URL syntax");
    let redis_db = parsed_redis
        .path()
        .trim_start_matches('/')
        .parse::<u8>()
        .ok();
    assert!(
        parsed_redis.host_str() == Some("127.0.0.1") && redis_db.is_some_and(|db| db >= 13),
        "passport chain test requires an isolated loopback Redis database numbered 13 or higher"
    );
    let redis_nonce = std::env::var("MARTY_TEST_REDIS_DISPOSABLE_NONCE")
        .expect("pre-provisioned disposable Redis sentinel value");
    assert!(
        redis_nonce.len() >= 16,
        "disposable Redis sentinel is too short"
    );
    let redis_client = redis::Client::open(redis_url.as_str()).expect("disposable Redis client");
    let mut redis = redis_client
        .get_multiplexed_async_connection()
        .await
        .expect("disposable Redis connection");
    let observed: Option<String> = redis::cmd("GET")
        .arg("marty:tests:disposable-guard")
        .query_async(&mut redis)
        .await
        .expect("disposable Redis sentinel read");
    assert!(
        observed.as_deref() == Some(redis_nonce.as_str()),
        "disposable Redis sentinel does not match"
    );
    let bao_url = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
    let parsed_bao = url::Url::parse(&bao_url).expect("disposable OpenBao URL syntax");
    assert!(
        parsed_bao.scheme() == "http" && parsed_bao.host_str() == Some("127.0.0.1"),
        "passport chain test requires a loopback disposable OpenBao instance"
    );
    let bao_url = bao_url.trim_end_matches('/').to_owned();
    let bao_token = std::env::var("MARTY_TEST_OPENBAO_TOKEN").expect("disposable OpenBao token");
    assert!(
        std::env::var("BAO_TOKEN").ok().as_deref() == Some(bao_token.as_str()),
        "disposable OpenBao token binding does not match"
    );
    let bao_nonce = std::env::var("MARTY_TEST_OPENBAO_DISPOSABLE_NONCE")
        .expect("pre-provisioned disposable OpenBao sentinel value");
    assert!(
        bao_nonce.len() >= 16,
        "disposable OpenBao sentinel is too short"
    );
    let kms_client = reqwest::Client::new();
    let marker = kms_client
        .get(
            parsed_bao
                .join("/v1/secret/data/marty-test-disposable-guard")
                .expect("disposable OpenBao sentinel URL"),
        )
        .header("X-Vault-Token", &bao_token)
        .send()
        .await
        .expect("disposable OpenBao sentinel read");
    assert!(
        marker.status().is_success(),
        "disposable OpenBao sentinel is absent"
    );
    let marker: Value = marker
        .json()
        .await
        .expect("disposable OpenBao sentinel JSON");
    assert!(
        marker["data"]["data"]["nonce"].as_str() == Some(bao_nonce.as_str()),
        "disposable OpenBao sentinel does not match"
    );
    let mounted = kms_client
        .get(format!("{bao_url}/v1/sys/mounts/transit"))
        .header("X-Vault-Token", &bao_token)
        .send()
        .await
        .unwrap();
    if !mounted.status().is_success() {
        let enabled = kms_client
            .post(format!("{bao_url}/v1/sys/mounts/transit"))
            .header("X-Vault-Token", &bao_token)
            .json(&json!({"type": "transit"}))
            .send()
            .await
            .unwrap();
        assert!(
            enabled.status().is_success(),
            "disposable Transit mount unavailable"
        );
    }
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let organization_id = format!("test-passport-chain-{suffix}");
    let issuer_did = format!("did:web:beta.example:orgs:{organization_id}");
    let service = json!({
        "id": "managed-openbao-transit", "name": "Disposable Passport KMS",
        "service_type": "openbao-transit", "endpoint": bao_url,
        "mount": "transit", "auth_mode": "token", "auth_reference": bao_token,
        "key_reference": "unused-disposable-default", "algorithms": ["ES256"],
        "key_purposes": ["csca", "x509_doc_signer"],
        "credential_formats": ["mso_mdoc", "icao_emrtd"]
    });
    let registry = RegistryStore::connect(&redis_url)
        .await
        .unwrap()
        .with_managed_openbao(Some(bao_url.clone()));
    let documents = DocumentStore::from_connection(registry.connection());
    let lifecycle = CscaLifecycleStore::from_connection(registry.connection());
    let profiles = ProfileStore::from_connection(registry.connection());
    let signing = router_with_dependencies(
        INTERNAL_KEY.into(),
        Some(registry),
        Some(documents),
        Some(lifecycle),
        Some(profiles.clone()),
        None,
        Some("beta.example".into()),
    );
    let scoped = |path: &str| format!("{path}?organization_id={organization_id}");
    let identity = |purpose: &str| {
        json!({
            "organization_id": organization_id, "issuer_did": issuer_did,
            "key_purpose": purpose, "credential_format": "ICAO_EMRTD", "algorithm": "ES256"
        })
    };
    for purpose in ["csca", "x509_doc_signer"] {
        let created = route(
            &signing,
            Method::POST,
            &scoped("/v1/signing-keys/issuer-identities"),
            identity(purpose),
        )
        .await;
        assert_eq!(created["created"], true);
    }
    let mut csca_request = identity("csca");
    csca_request["country"] = json!("US");
    csca_request["organization"] = json!("ElevenID Beta");
    csca_request["common_name"] = json!("Disposable CSCA");
    let mut dsc_request = identity("x509_doc_signer");
    dsc_request["country"] = json!("US");
    dsc_request["organization"] = json!("ElevenID Beta");
    dsc_request["common_name"] = json!("Disposable DSC");
    let csca_csr = route(
        &signing,
        Method::PUT,
        &scoped("/v1/signing-keys/issuer-identities/certificate-csr"),
        csca_request,
    )
    .await;
    let dsc_csr = route(
        &signing,
        Method::PUT,
        &scoped("/v1/signing-keys/issuer-identities/certificate-csr"),
        dsc_request,
    )
    .await;
    let csca_profile = profiles
        .find(
            &organization_id,
            FindProfilesRequest {
                key_purpose: Some("csca".into()),
                ..FindProfilesRequest::default()
            },
        )
        .await
        .unwrap()
        .pop()
        .unwrap();
    let dsc_profile = profiles
        .find(
            &organization_id,
            FindProfilesRequest {
                key_purpose: Some("x509_doc_signer".into()),
                ..FindProfilesRequest::default()
            },
        )
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_ne!(
        csca_profile["signing_key_reference"],
        dsc_profile["signing_key_reference"]
    );
    let csca_name = CertReq::from_pem(csca_csr["csr_pem"].as_str().unwrap())
        .unwrap()
        .info
        .subject;
    let csca_pem = issue_certificate(
        csca_csr["csr_pem"].as_str().unwrap(),
        csca_name.clone(),
        signing_config(&service, &csca_profile),
        1,
        true,
    )
    .await;
    let dsc_pem = issue_certificate(
        dsc_csr["csr_pem"].as_str().unwrap(),
        csca_name,
        signing_config(&service, &csca_profile),
        2,
        false,
    )
    .await;
    let csca_der = load_certificate_pem(&csca_pem).unwrap();
    let dsc_der = load_certificate_pem(&dsc_pem).unwrap();
    assert!(verify_certificate_signature(&csca_der, &csca_der).unwrap());
    assert!(verify_certificate_signature(&dsc_der, &csca_der).unwrap());
    let enrolled = route(
        &signing,
        Method::PUT,
        &scoped("/v1/signing-keys/issuer-identities/csca-certificate"),
        json!({
            "organization_id": organization_id, "issuer_did": issuer_did,
            "credential_format": "ICAO_EMRTD", "algorithm": "ES256",
            "certificate_id": format!("csca-{suffix}"), "cert_pem": csca_pem
        }),
    )
    .await;
    assert_eq!(enrolled["status"], "VALID");
    route(
        &signing,
        Method::PUT,
        &scoped("/v1/signing-keys/issuer-identities/certificate"),
        json!({
            "organization_id": organization_id, "issuer_did": issuer_did,
            "key_purpose": "x509_doc_signer", "credential_format": "ICAO_EMRTD",
            "algorithm": "ES256", "cert_pem": dsc_pem, "cert_chain_pem": csca_pem
        }),
    )
    .await;
    let gateway = internal_gateway_adapter(signing.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, gateway).await.unwrap() });
    let signer = ManagedProfileSigner::new(
        format!("http://{address}/internal/signing-keys")
            .parse()
            .unwrap(),
        Some(INTERNAL_KEY),
    )
    .unwrap();
    let groups = BTreeMap::from([(BigUint::from(1u8), STANDARD.encode(b"disposable DG1"))]);
    let signed = signer
        .sign("USA", &organization_id, &issuer_did, &groups)
        .await
        .unwrap();
    let sod = STANDARD.decode(&signed.sod_der_base64).unwrap();
    assert!(marty_verification::asn1::sod::verify_sod_signature(&sod).unwrap());
    assert_eq!(signed.dsc_cert_pem, dsc_pem);
    assert_eq!(signed.csca_cert_pem.as_deref(), Some(csca_pem.as_str()));
    assert!(signer
        .sign("USA", "another-organization", &issuer_did, &groups)
        .await
        .is_err());
    let revoked = forward(
        &signing,
        Method::POST,
        &format!("/internal/documents/{organization_id}/csca-certificates/csca-{suffix}/revoke"),
        json!({"reason": "disposable acceptance test"}),
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::OK);
    assert!(matches!(
        signer
            .sign("USA", &organization_id, &issuer_did, &groups)
            .await,
        Err(SignerError::UntrustedDsc)
    ));
    server.abort();
}
