//! Opt-in disposable acceptance for the managed passport CSCA -> DSC -> SOD path.
//! Certificate bodies use the shared builders, and every certificate and SOD
//! signature is made by a Transit-held key. No private key enters this test.

use std::{collections::BTreeMap, fs, process::Command, time::SystemTime};

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
use marty_crypto::certificate::{load_certificate_pem, verify_certificate_signature};
use marty_crypto::jwk::certificate_pem_to_jwk;
use marty_issuance_service::passport_signer::{ManagedProfileSigner, SignerError};
use marty_signing_keys::{
    certificate_issuance::{prepare_csca, prepare_dsc, VerifiedDscSubject},
    csca_lifecycle::CscaLifecycleStore,
    documents::DocumentStore,
    http::router_with_all_keys,
    kms::{self, ProviderRequest, SignRequest},
    profiles::{FindProfilesRequest, ProfileStore},
    registry::RegistryStore,
};
use num_bigint::BigUint;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tower::ServiceExt;
const INTERNAL_KEY: &str = "disposable-passport-chain-internal-key";
const DSC_GATEWAY_KEY: &str = "disposable-passport-dsc-gateway-key-32-characters";
const ISSUER_SIGN_KEY: &str = "disposable-passport-issuer-sign-key-32-chars";

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
    assert_eq!(status, StatusCode::OK, "{path} returned {status}");
    serde_json::from_slice(&bytes).unwrap()
}

async fn issue_managed_dsc(app: &Router, path: &str, body: Value) -> Value {
    let response = issue_managed_dsc_response(app, path, body).await;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1_048_576).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "DSC issuance returned {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap()
}

async fn issue_managed_dsc_response(app: &Router, path: &str, body: Value) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(CONTENT_TYPE, "application/json")
                .header("x-api-key", DSC_GATEWAY_KEY)
                .header("x-user-id", "disposable-certificate-operator")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

fn signing_config(service: &Value, profile: &Value) -> Value {
    let mut config = service.clone();
    config["key_reference"] = profile["signing_key_reference"].clone();
    config["algorithm"] = json!("ES256");
    config
}

// The test uses the same certificate builder as the managed runtime; only
// the signature operation is delegated to its disposable Transit key.
async fn issue_csca_with_shared_builder(
    csr_pem: &str,
    signer_config: Value,
    serial: &[u8],
) -> String {
    let public = kms::public_key_existing(ProviderRequest {
        service_config: signer_config.clone(),
    })
    .await
    .unwrap();
    let subject = VerifiedDscSubject::from_csr_pem(csr_pem, &public).unwrap();
    let prepared = prepare_csca(&subject, serial, 365, SystemTime::now()).unwrap();
    let signed = kms::sign(SignRequest {
        service_config: signer_config,
        payload_b64: URL_SAFE_NO_PAD.encode(prepared.signing_bytes()),
    })
    .await
    .unwrap_or_else(|_| panic!("disposable OpenBao certificate signing failed"));
    assert_eq!(signed.signature_encoding, "der");
    prepared
        .finish(&URL_SAFE_NO_PAD.decode(signed.signature_b64).unwrap())
        .unwrap()
}

async fn issue_dsc_with_shared_builder(
    csr_pem: &str,
    csca_pem: &str,
    csca_config: Value,
    dsc_config: Value,
) -> String {
    let dsc_public = kms::public_key_existing(ProviderRequest {
        service_config: dsc_config,
    })
    .await
    .unwrap();
    let csca_public = kms::public_key_existing(ProviderRequest {
        service_config: csca_config.clone(),
    })
    .await
    .unwrap();
    let subject = VerifiedDscSubject::from_csr_pem(csr_pem, &dsc_public).unwrap();
    let now = SystemTime::now();
    let prepared = prepare_dsc(&subject, csca_pem, "", &csca_public, &[2], 29, now).unwrap();
    let signed = kms::sign(SignRequest {
        service_config: csca_config,
        payload_b64: URL_SAFE_NO_PAD.encode(prepared.signing_bytes()),
    })
    .await
    .unwrap();
    assert_eq!(signed.signature_encoding, "der");
    prepared
        .finish(&URL_SAFE_NO_PAD.decode(signed.signature_b64).unwrap())
        .unwrap()
}

fn verify_strict_chain(csca_pem: &str, dsc_pem: &str) {
    let directory = tempfile::tempdir().unwrap();
    let csca_path = directory.path().join("csca.pem");
    let dsc_path = directory.path().join("dsc.pem");
    fs::write(&csca_path, csca_pem).unwrap();
    fs::write(&dsc_path, dsc_pem).unwrap();
    for (role, path) in [("CSCA", &csca_path), ("DSC", &dsc_path)] {
        let result = Command::new("openssl")
            .arg("verify")
            .args([
                "-x509_strict",
                "-check_ss_sig",
                "-purpose",
                "any",
                "-CAfile",
            ])
            .arg(&csca_path)
            .arg(path)
            .output()
            .expect("OpenSSL is required for the disposable managed-chain test");
        assert!(
            result.status.success(),
            "{role} strict chain verification failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
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
                .header(
                    "x-api-key",
                    if path == "/internal/compat/issuer-dids/sign" {
                        ISSUER_SIGN_KEY
                    } else {
                        INTERNAL_KEY
                    },
                )
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires independently marked disposable Redis and OpenBao instances, plus OpenSSL"]
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
    let signing = router_with_all_keys(
        INTERNAL_KEY.into(),
        None,
        Some(ISSUER_SIGN_KEY.into()),
        Some(DSC_GATEWAY_KEY.into()),
        None,
        false,
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
    assert!(
        csca_profile["signing_key_reference"] != dsc_profile["signing_key_reference"],
        "CSCA and DSC must use distinct KMS keys"
    );
    let csca_pem = issue_csca_with_shared_builder(
        csca_csr["csr_pem"].as_str().unwrap(),
        signing_config(&service, &csca_profile),
        &[1],
    )
    .await;
    let fixture_dsc_pem = issue_dsc_with_shared_builder(
        dsc_csr["csr_pem"].as_str().unwrap(),
        &csca_pem,
        signing_config(&service, &csca_profile),
        signing_config(&service, &dsc_profile),
    )
    .await;
    let csca_der = load_certificate_pem(&csca_pem).unwrap();
    let dsc_der = load_certificate_pem(&fixture_dsc_pem).unwrap();
    assert!(verify_certificate_signature(&csca_der, &csca_der).unwrap());
    assert!(verify_certificate_signature(&dsc_der, &csca_der).unwrap());
    verify_strict_chain(&csca_pem, &fixture_dsc_pem);
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
    let public_jwk = serde_json::to_value(certificate_pem_to_jwk(&csca_pem).unwrap()).unwrap();
    let forged_import = forward(
        &signing,
        Method::PUT,
        &format!("/internal/documents/{organization_id}/csca-certificates/csca-forged-{suffix}"),
        json!({
            "cert_pem": csca_pem,
            "key_reference": "unbound-csca-key",
            "expected_public_jwk": public_jwk,
            "metadata": {"issuer_did": issuer_did}
        }),
    )
    .await;
    assert_eq!(forged_import.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        forward(
            &signing,
            Method::GET,
            &format!(
                "/internal/documents/{organization_id}/csca-certificates/csca-forged-{suffix}"
            ),
            Value::Null,
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    let forged_renewal = forward(
        &signing,
        Method::POST,
        &format!("/internal/documents/{organization_id}/csca-certificates/csca-{suffix}/renew"),
        json!({
            "replacement_certificate_id": format!("csca-forged-renewal-{suffix}"),
            "cert_pem": csca_pem,
            "key_reference": "unbound-csca-key",
            "expected_public_jwk": public_jwk,
            "reuse_key": true,
            "metadata": {"issuer_did": issuer_did}
        }),
    )
    .await;
    assert_eq!(forged_renewal.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        forward(
            &signing,
            Method::GET,
            &format!(
                "/internal/documents/{organization_id}/csca-certificates/csca-forged-renewal-{suffix}"
            ),
            Value::Null,
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    let managed_copy_path = format!(
        "/internal/documents/{organization_id}/csca-certificates/csca-managed-copy-{suffix}"
    );
    let managed_copy_body = json!({
        "cert_pem": csca_pem,
        "key_reference": csca_profile["signing_key_reference"],
        "expected_public_jwk": public_jwk,
        "metadata": {"issuer_did": issuer_did}
    });
    let rotation_store = RegistryStore::connect(&redis_url).await.unwrap();
    let held_rotation = rotation_store
        .acquire_rotation_lease(&organization_id)
        .await
        .unwrap()
        .unwrap();
    let concurrent_import = forward(
        &signing,
        Method::PUT,
        &managed_copy_path,
        managed_copy_body.clone(),
    )
    .await;
    assert_eq!(concurrent_import.status(), StatusCode::CONFLICT);
    held_rotation.release().await.unwrap();
    let managed_copy = forward(&signing, Method::PUT, &managed_copy_path, managed_copy_body).await;
    assert_eq!(managed_copy.status(), StatusCode::OK);
    let renewed_csca_pem = issue_csca_with_shared_builder(
        csca_csr["csr_pem"].as_str().unwrap(),
        signing_config(&service, &csca_profile),
        &[3],
    )
    .await;
    assert_ne!(renewed_csca_pem, csca_pem);
    let renewed_public_jwk =
        serde_json::to_value(certificate_pem_to_jwk(&renewed_csca_pem).unwrap()).unwrap();
    assert_eq!(renewed_public_jwk, public_jwk);
    let managed_renewed_path = format!(
        "/internal/documents/{organization_id}/csca-certificates/csca-managed-renewed-{suffix}"
    );
    let renewal_body = json!({
        "replacement_certificate_id": format!("csca-managed-renewed-{suffix}"),
        "cert_pem": renewed_csca_pem,
        "key_reference": csca_profile["signing_key_reference"],
        "expected_public_jwk": renewed_public_jwk,
        "reuse_key": true,
        "metadata": {"issuer_did": issuer_did}
    });
    let mut wrong_reuse_body = renewal_body.clone();
    wrong_reuse_body["reuse_key"] = json!(false);
    let wrong_reuse = forward(
        &signing,
        Method::POST,
        &format!("{managed_copy_path}/renew"),
        wrong_reuse_body,
    )
    .await;
    assert_eq!(wrong_reuse.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let renewed = forward(
        &signing,
        Method::POST,
        &format!("{managed_copy_path}/renew"),
        renewal_body,
    )
    .await;
    assert_eq!(renewed.status(), StatusCode::OK);
    let renewed: Value =
        serde_json::from_slice(&to_bytes(renewed.into_body(), 1_048_576).await.unwrap()).unwrap();
    assert_eq!(
        renewed["renewed_from"],
        format!("csca-managed-copy-{suffix}")
    );
    assert_eq!(renewed["public_jwk"], public_jwk);
    assert_eq!(
        forward(
            &signing,
            Method::POST,
            &format!("{managed_renewed_path}/revoke"),
            json!({"reason": "disposable binding proof completed"}),
        )
        .await
        .status(),
        StatusCode::OK
    );
    let issue_request = json!({
        "organization_id": organization_id,
        "dsc_issuer_did": issuer_did,
        "csca_issuer_did": issuer_did,
        "csca_certificate_id": format!("csca-{suffix}"),
        "credential_format": "ICAO_EMRTD",
        "country": "US", "organization": "ElevenID Beta", "common_name": "Disposable DSC",
        "validity_days": 30, "idempotency_key": format!("disposable-{suffix}")
    });
    let issue_path = scoped("/v1/signing-keys/issuer-identities/dsc-certificate");
    let issued = issue_managed_dsc(&signing, &issue_path, issue_request.clone()).await;
    let replayed = issue_managed_dsc(&signing, &issue_path, issue_request.clone()).await;
    assert_eq!(
        issued, replayed,
        "idempotent DSC issuance must return the original certificate"
    );
    let dsc_pem = issued["certificate_pem"].as_str().unwrap();
    let issued_der = load_certificate_pem(dsc_pem).unwrap();
    assert!(verify_certificate_signature(&issued_der, &csca_der).unwrap());
    verify_strict_chain(&csca_pem, dsc_pem);
    let gateway = internal_gateway_adapter(signing.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, gateway).await.unwrap() });
    let signer = ManagedProfileSigner::new(
        format!("http://{address}/internal/signing-keys")
            .parse()
            .unwrap(),
        Some(INTERNAL_KEY),
        Some(ISSUER_SIGN_KEY),
    )
    .unwrap();
    let groups = BTreeMap::from([(BigUint::from(1u8), STANDARD.encode(b"disposable DG1"))]);
    let signed = signer
        .sign("USA", &organization_id, &issuer_did, &groups)
        .await
        .unwrap();
    signed.verify_data_groups(&groups).unwrap();
    let altered_groups = BTreeMap::from([(BigUint::from(1u8), STANDARD.encode(b"altered DG1"))]);
    assert!(signed.verify_data_groups(&altered_groups).is_err());
    let mut tampered_sod = signed.clone();
    let mut sod_bytes = STANDARD.decode(&tampered_sod.sod_der_base64).unwrap();
    let last = sod_bytes.len() - 1;
    sod_bytes[last] ^= 1;
    tampered_sod.sod_der_base64 = STANDARD.encode(sod_bytes);
    assert!(tampered_sod.verify_data_groups(&groups).is_err());
    let sod = STANDARD.decode(&signed.sod_der_base64).unwrap();
    assert!(marty_verification::asn1::sod::verify_sod_signature(&sod).unwrap());
    assert!(
        marty_verification::asn1::sod::verify_data_group_hash_from_sod(&sod, 1, b"disposable DG1")
            .unwrap()
    );
    assert!(
        !marty_verification::asn1::sod::verify_data_group_hash_from_sod(&sod, 1, b"altered DG1")
            .unwrap()
    );
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
    let mut new_after_revocation = issue_request.clone();
    new_after_revocation["idempotency_key"] = json!(format!("revoked-{suffix}"));
    let replay_after_revocation = issue_managed_dsc(&signing, &issue_path, issue_request).await;
    assert_eq!(
        replay_after_revocation, issued,
        "retry is an immutable issuance receipt, not a current trust decision"
    );
    assert_eq!(replay_after_revocation["status"], "issued");
    assert_eq!(
        issue_managed_dsc_response(&signing, &issue_path, new_after_revocation)
            .await
            .status(),
        StatusCode::CONFLICT,
        "a revoked CSCA cannot issue a new DSC"
    );
    assert!(matches!(
        signer
            .sign("USA", &organization_id, &issuer_did, &groups)
            .await,
        Err(SignerError::UntrustedDsc)
    ));
    let dsc_reference = dsc_profile["signing_key_reference"].as_str().unwrap();
    let rotated = kms_client
        .post(format!("{bao_url}/v1/transit/keys/{dsc_reference}/rotate"))
        .header("X-Vault-Token", &bao_token)
        .send()
        .await
        .unwrap_or_else(|_| panic!("disposable DSC key rotation request failed"));
    assert!(
        rotated.status().is_success(),
        "disposable DSC key rotation failed"
    );
    let stale_certificate = signing
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(scoped("/v1/signing-keys/issuer-identities/certificate"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "organization_id": organization_id,
                        "issuer_did": issuer_did,
                        "key_purpose": "x509_doc_signer",
                        "credential_format": "ICAO_EMRTD",
                        "algorithm": "ES256",
                        "cert_pem": dsc_pem,
                        "cert_chain_pem": csca_pem
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stale_certificate.status(), StatusCode::CONFLICT);
    let rotated_issue = json!({
        "organization_id": organization_id,
        "dsc_issuer_did": issuer_did,
        "csca_issuer_did": issuer_did,
        "csca_certificate_id": format!("csca-{suffix}"),
        "credential_format": "ICAO_EMRTD",
        "country": "US", "organization": "ElevenID Beta", "common_name": "Disposable DSC",
        "validity_days": 30, "idempotency_key": format!("rotated-{suffix}")
    });
    let rotated_response = issue_managed_dsc_response(&signing, &issue_path, rotated_issue).await;
    assert_eq!(rotated_response.status(), StatusCode::CONFLICT);
    let rotated_body = to_bytes(rotated_response.into_body(), 1_048_576)
        .await
        .unwrap();
    assert!(
        String::from_utf8_lossy(&rotated_body).contains("current managed KMS key"),
        "rotation must be rejected by the KMS/public identity binding"
    );
    let csca_reference = csca_profile["signing_key_reference"].as_str().unwrap();
    let rotated_csca = kms_client
        .post(format!("{bao_url}/v1/transit/keys/{csca_reference}/rotate"))
        .header("X-Vault-Token", &bao_token)
        .send()
        .await
        .expect("disposable CSCA key rotation request");
    assert!(rotated_csca.status().is_success());
    let stale_csca_path = format!(
        "/internal/documents/{organization_id}/csca-certificates/csca-stale-after-rotation-{suffix}"
    );
    let stale_csca = forward(
        &signing,
        Method::PUT,
        &stale_csca_path,
        json!({
            "cert_pem": csca_pem,
            "key_reference": csca_reference,
            "expected_public_jwk": public_jwk,
            "metadata": {"issuer_did": issuer_did}
        }),
    )
    .await;
    assert_eq!(stale_csca.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        forward(&signing, Method::GET, &stale_csca_path, Value::Null)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    server.abort();
}
