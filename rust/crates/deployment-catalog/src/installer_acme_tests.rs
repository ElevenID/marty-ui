//! Restart fixtures use the real protocol, installation lock/ledger, projection
//! parser and CSR/chain admission. The CA and private keys exist only in memory.
use super::*;
use crate::{
    installer_acme_configuration::AcmeParameters, installer_acme_custody::account_resource_name,
    installer_hosting, installer_state::Identity,
};
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http::{Method, Request, Response};
use http_body_util::BodyExt;
use marty_acme_client::protocol::{BodyWrapper, BytesResponse};
use ring::{
    rand::SystemRandom,
    signature::{
        EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1_SIGNING,
        ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING,
    },
};
use spki::der::{
    asn1::{BitString, Ia5String, OctetString},
    pem::LineEnding,
    DecodePem, Encode, EncodePem,
};
use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};
use std::{
    future::Future,
    os::unix::fs::{symlink, PermissionsExt},
    pin::Pin,
    str::FromStr,
    sync::Mutex,
};
use x509_cert::{
    ext::{
        pkix::{
            name::GeneralName, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
            SubjectAltName,
        },
        AsExtension,
    },
    name::Name,
    request::CertReq,
    Certificate,
};

const CA: &str = "https://acme-staging-v02.api.letsencrypt.org";
const TERMS: &str = "https://letsencrypt.org/documents/LE-SA-v1.6-August-18-2025.pdf";
const DNS: &str = "login.example.com";
const IP: &str = "203.0.113.7";
const ROOT_TEMPLATE: &[u8] =
    include_bytes!("../../../../tests/fixtures/selfhost_ca_issuer_public.pem");
const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

struct TestSigner {
    key: EcdsaKeyPair,
}
impl TestSigner {
    fn new() -> Arc<Self> {
        let random = SystemRandom::new();
        let bytes =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random).unwrap();
        Arc::new(Self {
            key: EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                bytes.as_ref(),
                &random,
            )
            .unwrap(),
        })
    }
}
#[async_trait]
impl ExternalAccountSigner for TestSigner {
    fn public_key(&self) -> &[u8] {
        self.key.public_key().as_ref()
    }
    async fn sign(&self, input: &[u8]) -> std::result::Result<[u8; 64], ProtocolError> {
        Ok(self
            .key
            .sign(&SystemRandom::new(), input)
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap())
    }
}

fn spki(public: &[u8]) -> SubjectPublicKeyInfoOwned {
    let mut key = Certificate::from_pem(ROOT_TEMPLATE)
        .unwrap()
        .tbs_certificate
        .subject_public_key_info;
    key.subject_public_key = BitString::from_bytes(public).unwrap();
    key
}

fn metadata(name: &str, spki: &SubjectPublicKeyInfoOwned) -> Value {
    json!({"name":name,"type":"ecdsa-p256","derived":false,"imported_key":false,
        "exportable":false,"allow_plaintext_backup":false,"supports_signing":true,
        "latest_version":1,"deletion_allowed":false,"soft_deleted":false,"auto_rotate_period":0,
        "keys":{"1":{"public_key":spki.to_pem(LineEnding::LF).unwrap()}}})
}

fn private_fixture_key() -> EcdsaKeyPair {
    let random = SystemRandom::new();
    let bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, bytes.as_ref(), &random).unwrap()
}

fn sign_certificate(mut certificate: Certificate, key: &EcdsaKeyPair) -> Certificate {
    certificate.signature_algorithm = AlgorithmIdentifierOwned {
        oid: ECDSA_SHA256,
        parameters: None,
    };
    certificate.tbs_certificate.signature = certificate.signature_algorithm.clone();
    certificate.signature = BitString::from_bytes(
        key.sign(
            &SystemRandom::new(),
            &certificate.tbs_certificate.to_der().unwrap(),
        )
        .unwrap()
        .as_ref(),
    )
    .unwrap();
    certificate
}

fn signed_fixture(
    identity: &certificates::CertificateIdentity,
    key: &RetainedIngressKey,
    leaf_key: &EcdsaKeyPair,
    observed: u64,
) -> (ValidatedCsr, String, String) {
    let mut csr = CertReq::from_pem(
        certificates::csr_template(identity, key)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    csr.signature = BitString::from_bytes(
        leaf_key
            .sign(&SystemRandom::new(), &csr.info.to_der().unwrap())
            .unwrap()
            .as_ref(),
    )
    .unwrap();
    let csr = certificates::validate_signed_csr(
        csr.to_pem(LineEnding::LF).unwrap().as_bytes(),
        identity,
        key,
    )
    .unwrap();
    let ca_key = private_fixture_key();
    let mut root = Certificate::from_pem(ROOT_TEMPLATE).unwrap();
    root.tbs_certificate.subject = Name::from_str("CN=Marty in-memory ACME root").unwrap();
    root.tbs_certificate.issuer = root.tbs_certificate.subject.clone();
    root.tbs_certificate.subject_public_key_info = spki(ca_key.public_key().as_ref());
    root.tbs_certificate.validity.not_before = (UNIX_EPOCH + Duration::from_secs(observed - 60))
        .try_into()
        .unwrap();
    root.tbs_certificate.validity.not_after = (UNIX_EPOCH
        + Duration::from_secs(observed + 24 * 3600))
    .try_into()
    .unwrap();
    root.tbs_certificate.extensions = Some(vec![
        BasicConstraints {
            ca: true,
            path_len_constraint: None,
        }
        .to_extension(&root.tbs_certificate.subject, &[])
        .unwrap(),
        KeyUsage(KeyUsages::KeyCertSign.into())
            .to_extension(&root.tbs_certificate.subject, &[])
            .unwrap(),
    ]);
    let root = sign_certificate(root, &ca_key);
    let mut leaf = root.clone();
    leaf.tbs_certificate.subject = Name::from_str(&format!("CN={DNS}")).unwrap();
    leaf.tbs_certificate.subject_public_key_info = spki(leaf_key.public_key().as_ref());
    leaf.tbs_certificate.validity.not_after = (UNIX_EPOCH
        + Duration::from_secs(observed + 8 * 3600))
    .try_into()
    .unwrap();
    leaf.tbs_certificate.extensions = Some(vec![
        BasicConstraints {
            ca: false,
            path_len_constraint: None,
        }
        .to_extension(&leaf.tbs_certificate.subject, &[])
        .unwrap(),
        KeyUsage(KeyUsages::DigitalSignature.into())
            .to_extension(&leaf.tbs_certificate.subject, &[])
            .unwrap(),
        ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1")])
            .to_extension(&leaf.tbs_certificate.subject, &[])
            .unwrap(),
        SubjectAltName(vec![
            GeneralName::DnsName(Ia5String::new(DNS).unwrap()),
            GeneralName::IpAddress(OctetString::new([203, 0, 113, 7]).unwrap()),
        ])
        .to_extension(&leaf.tbs_certificate.subject, &[])
        .unwrap(),
    ]);
    let leaf = sign_certificate(leaf, &ca_key);
    (
        csr,
        root.to_pem(LineEnding::LF).unwrap(),
        leaf.to_pem(LineEnding::LF).unwrap(),
    )
}

#[derive(Clone, Copy)]
enum TargetChange {
    Identifier,
    Expiry,
    ChallengeUrl,
    Token,
    Invalid,
    Processing,
    Valid,
}

#[derive(Default)]
struct CaState {
    account_exists: bool,
    order_exists: bool,
    ready: [bool; 2],
    finalized: bool,
    lose_registration: bool,
    lose_order: bool,
    lose_finalize: bool,
    registration_posts: usize,
    lookup_posts: usize,
    new_orders: usize,
    finalizations: usize,
    authorization_reads: [usize; 2],
    challenge_posts: [usize; 2],
    target_change: Option<TargetChange>,
    challenge_failures_remaining: usize,
    valid_order_expires: Option<String>,
    requests: Vec<String>,
}
#[derive(Clone)]
struct MockCa {
    state: Arc<Mutex<CaState>>,
    public: Vec<u8>,
    csr: Vec<u8>,
    certificate: String,
    projection: std::path::PathBuf,
    created_at: u64,
}
impl MockCa {
    fn order(&self, state: &CaState) -> Value {
        let original_expiry =
            chrono::DateTime::from_timestamp((self.created_at + 8 * 3600) as i64, 0)
                .unwrap()
                .to_rfc3339();
        let expires = if state.finalized {
            state
                .valid_order_expires
                .as_deref()
                .unwrap_or(&original_expiry)
        } else {
            &original_expiry
        };
        json!({"status":if state.finalized {"valid"} else if state.ready.iter().all(|ready|*ready) {"ready"} else {"pending"},
            "expires":expires,
            "identifiers":[{"type":"dns","value":DNS},{"type":"ip","value":IP}],
            "authorizations":[format!("{CA}/authorization/0"),format!("{CA}/authorization/1")],
            "finalize":format!("{CA}/finalize/1"),"profile":"shortlived",
            "certificate":if state.finalized {Some(format!("{CA}/certificate/1"))} else {None}})
    }
    fn challenge(index: usize, status: &str) -> Value {
        json!({"type":"http-01","url":format!("{CA}/challenge/{index}"),"token":format!("public-http01-fixture-token-{index}"),"status":status})
    }
    fn response(status: u16, value: Vec<u8>, location: Option<String>) -> BytesResponse {
        let mut response = Response::builder()
            .status(status)
            .header("Replay-Nonce", "marty-fixture-nonce");
        if let Some(location) = location {
            response = response.header("Location", location);
        }
        BytesResponse::from(response.body(BodyWrapper::from(value)).unwrap())
    }
}
impl HttpClient for MockCa {
    fn request(
        &self,
        request: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<BytesResponse, ProtocolError>> + Send>>
    {
        let mock = self.clone();
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let bytes = body.collect().await.unwrap().to_bytes();
            let path = parts.uri.path().to_owned();
            assert_eq!(
                parts.uri.authority().unwrap().as_str(),
                "acme-staging-v02.api.letsencrypt.org"
            );
            let mut state = mock.state.lock().unwrap();
            state.requests.push(format!("{} {path}", parts.method));
            let payload = if parts.method == Method::POST {
                let envelope: Value = serde_json::from_slice(&bytes).unwrap();
                let protected = envelope["protected"].as_str().unwrap();
                let payload = envelope["payload"].as_str().unwrap();
                let header: Value =
                    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected).unwrap()).unwrap();
                assert_eq!(header["alg"], "ES256");
                assert_eq!(header["url"], parts.uri.to_string());
                if path == "/new-account" {
                    assert_eq!(
                        header["jwk"]["x"],
                        URL_SAFE_NO_PAD.encode(&mock.public[1..33])
                    );
                    assert_eq!(
                        header["jwk"]["y"],
                        URL_SAFE_NO_PAD.encode(&mock.public[33..])
                    );
                } else {
                    assert_eq!(header["kid"], format!("{CA}/account/1"));
                }
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &mock.public)
                    .verify(
                        format!("{protected}.{payload}").as_bytes(),
                        &URL_SAFE_NO_PAD
                            .decode(envelope["signature"].as_str().unwrap())
                            .unwrap(),
                    )
                    .unwrap();
                if payload.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
                }
            } else {
                assert!(bytes.is_empty());
                Value::Null
            };
            let mut status = 200;
            let mut location = None;
            let value = match (parts.method.as_str(), path.as_str()) {
                ("GET", "/directory") => {
                    json!({"newNonce":format!("{CA}/nonce"),"newAccount":format!("{CA}/new-account"),"newOrder":format!("{CA}/new-order"),
                    "meta":{"termsOfService":TERMS,"profiles":{"shortlived":"fixture"}}})
                }
                ("HEAD", "/nonce") => Value::Null,
                ("POST", "/new-account") => {
                    assert_eq!(payload["contact"], json!([]));
                    assert_eq!(payload["termsOfServiceAgreed"], true);
                    if payload["onlyReturnExisting"] == true {
                        state.lookup_posts += 1;
                        if !state.account_exists {
                            return Ok(Self::response(400,serde_json::to_vec(&json!({"type":"urn:ietf:params:acme:error:accountDoesNotExist"})).unwrap(),None));
                        }
                    } else {
                        state.registration_posts += 1;
                        assert!(!state.account_exists);
                        state.account_exists = true;
                        if state.lose_registration {
                            state.lose_registration = false;
                            return Err(ProtocolError::Str(
                                "fixture dropped registration response",
                            ));
                        }
                        status = 201;
                    }
                    location = Some(format!("{CA}/account/1"));
                    json!({"status":"valid"})
                }
                ("POST", "/new-order") => {
                    assert!(state.account_exists);
                    assert!(!state.order_exists);
                    state.order_exists = true;
                    state.new_orders += 1;
                    assert_eq!(
                        payload,
                        json!({"identifiers":[{"type":"dns","value":DNS},{"type":"ip","value":IP}],"profile":"shortlived"})
                    );
                    if state.lose_order {
                        state.lose_order = false;
                        return Err(ProtocolError::Str(
                            "fixture dropped accepted newOrder response",
                        ));
                    }
                    status = 201;
                    location = Some(format!("{CA}/order/1"));
                    mock.order(&state)
                }
                ("POST", "/order/1") => {
                    assert!(state.order_exists);
                    assert!(payload.is_null());
                    mock.order(&state)
                }
                ("POST", path) if path.starts_with("/authorization/") => {
                    assert!(payload.is_null());
                    let index = path.rsplit('/').next().unwrap().parse::<usize>().unwrap();
                    state.authorization_reads[index] += 1;
                    let mut authorization = json!({"status":if state.ready[index]{"valid"}else{"pending"},
                        "identifier":if index==0{json!({"type":"dns","value":DNS})}else{json!({"type":"ip","value":IP})},
                        "expires":chrono::DateTime::from_timestamp((mock.created_at+3600)as i64,0).unwrap().to_rfc3339(),
                        "challenges":[Self::challenge(index,if state.ready[index]{"valid"}else{"pending"})]});
                    if index == 1 && state.authorization_reads[index] >= 2 {
                        match state.target_change {
                            Some(TargetChange::Identifier) => {
                                authorization["identifier"]["value"] = json!("203.0.113.8")
                            }
                            Some(TargetChange::Expiry) => {
                                authorization["expires"] = json!(chrono::DateTime::from_timestamp(
                                    (mock.created_at + 7200) as i64,
                                    0
                                )
                                .unwrap()
                                .to_rfc3339())
                            }
                            Some(TargetChange::ChallengeUrl) => {
                                authorization["challenges"][0]["url"] =
                                    json!(format!("{CA}/challenge/unpublished"))
                            }
                            Some(TargetChange::Token) => {
                                authorization["challenges"][0]["token"] =
                                    json!("changed-unpublished-public-http01-token")
                            }
                            Some(TargetChange::Invalid) => {
                                authorization["challenges"][0]["status"] = json!("invalid")
                            }
                            Some(TargetChange::Processing) => {
                                authorization["challenges"][0]["status"] = json!("processing")
                            }
                            Some(TargetChange::Valid) => {
                                authorization["status"] = json!("valid");
                                authorization["expires"] = json!(chrono::DateTime::from_timestamp(
                                    (mock.created_at + 7 * 3600) as i64,
                                    0
                                )
                                .unwrap()
                                .to_rfc3339());
                                authorization["challenges"][0]["status"] = json!("valid");
                                state.ready[index] = true;
                            }
                            None => {}
                        }
                    }
                    authorization
                }
                ("POST", path) if path.starts_with("/challenge/") => {
                    assert_eq!(payload, json!({}));
                    let index = path.rsplit('/').next().unwrap().parse::<usize>().unwrap();
                    let bytes = std::fs::read(&mock.projection).unwrap();
                    let snapshot = Snapshot::parse(
                        &bytes,
                        &AllowedIdentifiers::from_origins(
                            &format!("https://{DNS}"),
                            Some(&format!("https://{IP}")),
                        )
                        .unwrap(),
                        now().unwrap(),
                    )
                    .unwrap();
                    assert!(snapshot.challenges.iter().any(|challenge| challenge.token
                        == format!("public-http01-fixture-token-{index}")));
                    assert_eq!(
                        std::fs::metadata(&mock.projection).unwrap().mode() & 0o7777,
                        0o444
                    );
                    assert!(!String::from_utf8(bytes).unwrap().contains("account/"));
                    state.challenge_posts[index] += 1;
                    if state.challenge_failures_remaining > 0 {
                        state.challenge_failures_remaining -= 1;
                        return Err(ProtocolError::Str(
                            "fixture unavailable before challenge acceptance",
                        ));
                    }
                    state.ready[index] = true;
                    Self::challenge(index, "processing")
                }
                ("POST", "/finalize/1") => {
                    assert!(state.ready.iter().all(|value| *value));
                    assert_eq!(
                        URL_SAFE_NO_PAD
                            .decode(payload["csr"].as_str().unwrap())
                            .unwrap(),
                        mock.csr
                    );
                    state.finalizations += 1;
                    state.finalized = true;
                    if state.lose_finalize {
                        state.lose_finalize = false;
                        return Err(ProtocolError::Str(
                            "fixture lost accepted finalize response",
                        ));
                    }
                    mock.order(&state)
                }
                ("POST", "/certificate/1") => {
                    assert!(state.finalized);
                    return Ok(Self::response(
                        200,
                        mock.certificate.as_bytes().to_vec(),
                        None,
                    ));
                }
                _ => panic!("unexpected mock CA request: {} {path}", parts.method),
            };
            Ok(Self::response(
                status,
                serde_json::to_vec(&value).unwrap(),
                location,
            ))
        })
    }
}

struct Fixture {
    _root: tempfile::TempDir,
    installation: std::path::PathBuf,
    configuration: BoundAcmeConfiguration,
    account_key: AccountKeyBinding,
    ingress_key: RetainedIngressKey,
    csr: ValidatedCsr,
    root_pem: String,
    signer: Arc<TestSigner>,
    ca: MockCa,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        TEST_TIME.with(|value| value.set(None));
    }
}
impl Fixture {
    fn new() -> Self {
        let observed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        TEST_TIME.with(|value| value.set(Some(observed)));
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let installation = root.path().join("installation");
        let mut writer = InstallerState::create(
            &installation,
            Identity {
                source_sha: "a".repeat(40),
                release_tag: "v1.2.3".into(),
                inventory_sha256: format!("sha256:{}", "b".repeat(64)),
            },
        )
        .unwrap();
        writer.create_private_directory("evidence").unwrap();
        writer.advance(Phase::Verified).unwrap();
        let hosting = root.path().join("hosting.json");
        std::fs::write(&hosting,serde_json::to_vec(&json!({"schema":"elevenid.installation-hosting/v1","mode":"direct",
            "public_origin":format!("https://{DNS}"),"public_entry_origin":format!("https://{IP}"),
            "listener":{"bind_address":"0.0.0.0","port":18443},"tls":{"termination":"marty-keyless","certificate_source":"managed-ca"}})).unwrap()).unwrap();
        std::fs::set_permissions(&hosting, std::fs::Permissions::from_mode(0o600)).unwrap();
        installer_hosting::select(
            installer_hosting::prepare(Some(&hosting), None).unwrap(),
            &mut writer,
        )
        .unwrap();
        let parameters=AcmeParameters::parse(&serde_json::to_vec(&json!({"environment":"staging","directory_url":AcmeEnvironment::Staging.directory_url(),"profile":"shortlived","terms_url":TERMS,"terms_agreed":true})).unwrap()).unwrap();
        let configuration = writer
            .with_inspection(|state| BoundAcmeConfiguration::bind(state, parameters))
            .unwrap();
        let id = writer.journal().installation_id().to_string();
        writer.advance(Phase::Provisioning).unwrap();
        drop(writer);
        let projection = installation.join(HTTP01_DIRECTORY);
        std::fs::create_dir(&projection).unwrap();
        std::fs::set_permissions(&projection, std::fs::Permissions::from_mode(0o755)).unwrap();
        let signer = TestSigner::new();
        let account_spki = spki(signer.public_key());
        let account_key = AccountKeyBinding::bind(
            &id,
            AcmeEnvironment::Staging,
            1,
            &account_spki.to_der().unwrap(),
            &metadata(
                &account_resource_name(&id, AcmeEnvironment::Staging).unwrap(),
                &account_spki,
            ),
        )
        .unwrap();
        let leaf = private_fixture_key();
        let leaf_spki = spki(leaf.public_key().as_ref());
        let ingress_key = RetainedIngressKey::bind(
            &id,
            1,
            &leaf_spki.to_der().unwrap(),
            &metadata(
                &crate::installer_ingress_provision::resource_name(&id).unwrap(),
                &leaf_spki,
            ),
        )
        .unwrap();
        let (csr, root_pem, certificate) = signed_fixture(
            &configuration.certificate_identity().unwrap(),
            &ingress_key,
            &leaf,
            observed,
        );
        let ca = MockCa {
            state: Arc::new(Mutex::new(CaState::default())),
            public: signer.public_key().to_vec(),
            csr: csr.der().to_vec(),
            certificate,
            projection: projection.join(SNAPSHOT_BASENAME),
            created_at: observed,
        };
        Self {
            _root: root,
            installation,
            configuration,
            account_key,
            ingress_key,
            csr,
            root_pem,
            signer,
            ca,
        }
    }
    fn inputs(&self) -> EnrolmentInputs<'_> {
        EnrolmentInputs {
            installation: &self.installation,
            configuration: &self.configuration,
            account_key: &self.account_key,
            ingress_key: &self.ingress_key,
            csr: &self.csr,
            staging_roots_pem: Some(self.root_pem.as_bytes()),
        }
    }
    fn advance(&self, seconds: u64) {
        TEST_TIME.with(|value| value.set(Some(value.get().unwrap() + seconds)));
    }
    fn run(&self) -> Result<EnrolmentOutcome> {
        let mut state = LockedMaintenance::open(&self.installation)?;
        let inputs = self.inputs();
        let binding = bind_inputs(state.inspection(), &inputs)?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(drive(
                &mut state,
                &inputs,
                binding,
                self.signer.clone(),
                Box::new(self.ca.clone()),
            ))
    }
    fn finish(&self) -> EnrolmentOutcome {
        for _ in 0..8 {
            let outcome = self.run().unwrap();
            if outcome.candidate.is_some() {
                return outcome;
            }
            self.advance(20);
        }
        panic!("fixture failed to produce a candidate")
    }
}

#[test]
fn enrolment_uses_real_protocol_csr_projection_and_chain_without_activation() {
    let fixture = Fixture::new();
    let outcome = fixture.finish();
    assert_eq!(outcome.report["stage"], "complete");
    assert_eq!(outcome.report["activation_performed"], false);
    let candidate = outcome.candidate.unwrap();
    assert_eq!(candidate.metadata()["trust_class"], "staging_test");
    assert_eq!(candidate.metadata()["public_chain_validated"], false);
    assert!(certificates::admit_production(
        candidate.fullchain_pem().as_bytes(),
        &fixture.configuration.certificate_identity().unwrap(),
        &fixture.ingress_key
    )
    .is_err());
    let snapshot: Snapshot =
        serde_json::from_slice(&std::fs::read(&fixture.ca.projection).unwrap()).unwrap();
    assert!(snapshot.challenges.is_empty());
    let state = LockedInspection::open(&fixture.installation).unwrap();
    let report = status(&state).unwrap();
    assert_eq!(report["installation_ready"], false);
    assert_eq!(report["automatic_renewal"], false);
    let ca = fixture.ca.state.lock().unwrap();
    assert_eq!(ca.registration_posts, 1);
    assert_eq!(ca.new_orders, 1);
    assert_eq!(ca.finalizations, 1);
}

#[test]
fn lost_new_order_response_is_held_without_any_ca_request_on_restart() {
    let fixture = Fixture::new();
    fixture.ca.state.lock().unwrap().lose_order = true;
    let first = fixture.run().unwrap();
    assert_eq!(first.report["order_outcome_unknown"], true);
    let requests = fixture.ca.state.lock().unwrap().requests.len();
    fixture.advance(3600);
    let restarted = fixture.run().unwrap();
    assert_eq!(restarted.report["order_outcome_unknown"], true);
    let ca = fixture.ca.state.lock().unwrap();
    assert_eq!(ca.requests.len(), requests);
    assert_eq!(ca.new_orders, 1);
}

#[test]
fn lost_registration_response_recovers_same_key_with_only_return_existing() {
    let fixture = Fixture::new();
    fixture.ca.state.lock().unwrap().lose_registration = true;
    assert_eq!(fixture.run().unwrap().report["stage"], "account_pending");
    fixture.advance(120);
    let outcome = fixture.finish();
    assert!(outcome.candidate.is_some());
    let ca = fixture.ca.state.lock().unwrap();
    assert_eq!(ca.registration_posts, 1);
    assert_eq!(ca.lookup_posts, 1);
}

#[test]
fn registration_intent_without_sent_request_first_confirms_same_key_absent() {
    let fixture = Fixture::new();
    {
        let mut state = LockedMaintenance::open(&fixture.installation).unwrap();
        let binding = bind_inputs(state.inspection(), &fixture.inputs()).unwrap();
        let mut saved = Ledger::begin(&mut state, binding, now().unwrap()).unwrap();
        let mut pending = saved.state.clone();
        pending.stage = Stage::AccountPending;
        saved.append(&mut state, pending, now().unwrap()).unwrap();
    }
    assert_eq!(fixture.run().unwrap().report["stage"], "account_absent");
    assert_eq!(fixture.ca.state.lock().unwrap().registration_posts, 0);
    assert!(fixture.finish().candidate.is_some());
    let ca = fixture.ca.state.lock().unwrap();
    assert_eq!(ca.lookup_posts, 1);
    assert_eq!(ca.registration_posts, 1);
}

#[test]
fn lost_finalize_response_resumes_known_order_without_duplicate_finalization() {
    let fixture = Fixture::new();
    fixture.ca.state.lock().unwrap().lose_finalize = true;
    assert!(fixture.run().unwrap().candidate.is_none());
    fixture.advance(20);
    assert!(fixture.run().unwrap().candidate.is_none());
    fixture.advance(20);
    assert_eq!(fixture.run().unwrap().report["stage"], "finalize_pending");
    fixture.advance(120);
    assert!(fixture.run().unwrap().candidate.is_some());
    let ca = fixture.ca.state.lock().unwrap();
    assert_eq!(ca.new_orders, 1);
    assert_eq!(ca.finalizations, 1);
}

#[test]
fn publication_recovers_before_and_after_atomic_rename_without_changing_challenge() {
    for publish_before_crash in [false, true] {
        let fixture = Fixture::new();
        fixture.run().unwrap();
        fixture.advance(20);
        {
            let mut state = LockedMaintenance::open(&fixture.installation).unwrap();
            let mut saved = Ledger::load(state.inspection(), AcmeEnvironment::Staging)
                .unwrap()
                .unwrap();
            let projection = projection_for(
                &fixture.inputs(),
                &saved.state.authorizations,
                saved.state.order.as_ref().unwrap().expires_at,
                saved.state.projection.as_ref(),
                false,
            )
            .unwrap();
            let mut pending = saved.state.clone();
            pending.stage = Stage::PublicationPending;
            pending.projection = Some(projection);
            pending.next_poll_at = None;
            saved.append(&mut state, pending, now().unwrap()).unwrap();
            if publish_before_crash {
                publish(
                    state.inspection(),
                    &fixture.installation,
                    saved.state.projection.as_ref().unwrap(),
                )
                .unwrap();
            }
        }
        assert!(fixture.finish().candidate.is_some());
        assert_eq!(fixture.ca.state.lock().unwrap().new_orders, 1);
    }
}

#[test]
fn retry_deadline_survives_reopen_and_prevents_extra_requests() {
    let fixture = Fixture::new();
    fixture.ca.state.lock().unwrap().lose_registration = true;
    let first = fixture.run().unwrap();
    let deadline = first.report["next_attempt_at"].as_u64().unwrap();
    let requests = fixture.ca.state.lock().unwrap().requests.len();
    let second = fixture.run().unwrap();
    assert_eq!(second.report["next_attempt_at"], deadline);
    assert_eq!(fixture.ca.state.lock().unwrap().requests.len(), requests);
}

#[test]
fn refreshed_challenge_must_match_the_published_target_before_notification() {
    for change in [
        TargetChange::Identifier,
        TargetChange::Expiry,
        TargetChange::ChallengeUrl,
        TargetChange::Token,
        TargetChange::Invalid,
    ] {
        let fixture = Fixture::new();
        fixture.ca.state.lock().unwrap().target_change = Some(change);
        assert!(fixture.run().is_err());
        let ca = fixture.ca.state.lock().unwrap();
        assert_eq!(ca.authorization_reads, [1, 2]);
        assert_eq!(ca.challenge_posts, [0, 0]);
        assert_eq!(ca.finalizations, 0);
    }
}

#[test]
fn refreshed_processing_or_valid_challenge_is_observed_without_reposting() {
    for change in [TargetChange::Processing, TargetChange::Valid] {
        let fixture = Fixture::new();
        fixture.ca.state.lock().unwrap().target_change = Some(change);
        let outcome = fixture.run().unwrap();
        assert_eq!(outcome.report["stage"], "awaiting_order");
        let inspection = LockedInspection::open(&fixture.installation).unwrap();
        let saved = Ledger::load(&inspection, AcmeEnvironment::Staging)
            .unwrap()
            .unwrap();
        assert!(
            saved
                .state
                .authorizations
                .iter()
                .find(|authorization| authorization.identifier == IP)
                .unwrap()
                .ready_observed
        );
        let ca = fixture.ca.state.lock().unwrap();
        assert_eq!(ca.authorization_reads, [1, 2]);
        assert_eq!(ca.challenge_posts, [0, 0]);
    }
}

#[test]
fn completed_order_keeps_original_deadline_when_ca_changes_expiry() {
    for changed_deadline in [1, 24 * 3600] {
        let fixture = Fixture::new();
        fixture.ca.state.lock().unwrap().valid_order_expires = Some(
            chrono::DateTime::from_timestamp((fixture.ca.created_at + changed_deadline) as i64, 0)
                .unwrap()
                .to_rfc3339(),
        );
        assert!(fixture.finish().candidate.is_some());
        let state = LockedInspection::open(&fixture.installation).unwrap();
        let saved = Ledger::load(&state, AcmeEnvironment::Staging)
            .unwrap()
            .unwrap();
        assert_eq!(
            saved.state.order.unwrap().expires_at,
            fixture.ca.created_at + 8 * 3600
        );
        assert_eq!(fixture.ca.state.lock().unwrap().finalizations, 1);
    }
}

#[test]
fn completed_order_still_refuses_malformed_expiry() {
    let fixture = Fixture::new();
    fixture.ca.state.lock().unwrap().valid_order_expires = Some("invalid timestamp".into());
    fixture.run().unwrap();
    fixture.advance(20);
    fixture.run().unwrap();
    fixture.advance(20);
    assert!(fixture.run().is_err());
    let ca = fixture.ca.state.lock().unwrap();
    assert_eq!(ca.finalizations, 1);
    assert!(!ca
        .requests
        .iter()
        .any(|request| request == "POST /certificate/1"));
}

#[test]
fn challenge_retries_keep_count_and_withdraw_projection_at_limit() {
    let fixture = Fixture::new();
    fixture
        .ca
        .state
        .lock()
        .unwrap()
        .challenge_failures_remaining = 4;
    for count in 1..=3 {
        let outcome = fixture.run().unwrap();
        assert_eq!(outcome.report["stage"], "challenge_ready_pending");
        let deadline = outcome.report["next_attempt_at"].as_u64().unwrap();
        let state = LockedInspection::open(&fixture.installation).unwrap();
        let saved = Ledger::load(&state, AcmeEnvironment::Staging)
            .unwrap()
            .unwrap();
        assert_eq!(saved.state.retry.unwrap().failures, count);
        drop(state);
        fixture.advance(deadline - now().unwrap() + 1);
    }
    {
        // Reopen the real ledger at the final permitted retry, as after a long
        // interruption test. Earlier iterations prove counts survive reopen.
        let mut state = LockedMaintenance::open(&fixture.installation).unwrap();
        let mut saved = Ledger::load(state.inspection(), AcmeEnvironment::Staging)
            .unwrap()
            .unwrap();
        let mut next = saved.state.clone();
        next.retry.as_mut().unwrap().failures = 32;
        saved.append(&mut state, next, now().unwrap()).unwrap();
    }
    let outcome = fixture.run().unwrap();
    assert_eq!(outcome.report["stage"], "terminal");
    assert_eq!(outcome.report["failure"], "retry_limit");
    let snapshot: Snapshot =
        serde_json::from_slice(&std::fs::read(&fixture.ca.projection).unwrap()).unwrap();
    assert!(snapshot.challenges.is_empty());
    let requests = fixture.ca.state.lock().unwrap().requests.len();
    assert_eq!(fixture.run().unwrap().report["stage"], "terminal");
    assert_eq!(fixture.ca.state.lock().unwrap().requests.len(), requests);
}

#[test]
fn retained_csr_recovers_the_original_signature_without_contacting_ca() {
    let fixture = Fixture::new();
    {
        let state = LockedInspection::open(&fixture.installation).unwrap();
        assert!(
            retained_csr(&state, &fixture.configuration, &fixture.ingress_key)
                .unwrap()
                .is_none()
        );
    }
    fixture.run().unwrap();
    let requests = fixture.ca.state.lock().unwrap().requests.len();
    let state = LockedInspection::open(&fixture.installation).unwrap();
    let csr = retained_csr(&state, &fixture.configuration, &fixture.ingress_key)
        .unwrap()
        .unwrap();
    assert_eq!(csr.der(), fixture.csr.der());
    assert_eq!(csr.pem(), fixture.csr.pem());
    assert_eq!(csr.metadata(), fixture.csr.metadata());
    let alternate = private_fixture_key();
    let alternate_spki = spki(alternate.public_key().as_ref());
    let alternate_key = RetainedIngressKey::bind(
        &state.journal().installation_id().to_string(),
        1,
        &alternate_spki.to_der().unwrap(),
        &metadata(fixture.ingress_key.transit_key_name(), &alternate_spki),
    )
    .unwrap();
    assert!(retained_csr(&state, &fixture.configuration, &alternate_key).is_err());
    assert_eq!(fixture.ca.state.lock().unwrap().requests.len(), requests);
}

#[test]
fn nested_runtime_is_rejected_before_borrowing_or_poisoning_installer_lock() {
    struct UnusedCredentials;
    #[async_trait]
    impl WorkloadCredentials for UnusedCredentials {
        async fn token(&self) -> std::result::Result<reqwest::header::HeaderValue, ProtocolError> {
            panic!("nested-runtime refusal must not request credentials")
        }
    }
    let fixture = Fixture::new();
    let installation = fixture._root.path().join("untouched-installation");
    let mut state = InstallerState::create(
        &installation,
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        },
    )
    .unwrap();
    state.advance(Phase::Verified).unwrap();
    state.advance(Phase::Provisioning).unwrap();
    let before = state.journal().clone();
    let bao =
        OpenBaoHttp::connect("https://127.0.0.1:18443", None, Duration::from_millis(1)).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let entered = runtime.enter();
    let error = run_for_install(
        &mut state,
        &fixture.inputs(),
        bao,
        Arc::new(UnusedCredentials),
    )
    .unwrap_err();
    assert_eq!(
        error,
        "ACME enrolment requires a synchronous installer caller"
    );
    drop(entered);
    assert_eq!(state.journal(), &before);
    state.require_live_phase(Phase::Provisioning).unwrap();
    state
        .with_inspection(|inspection| inspection.require_unchanged())
        .unwrap();
    assert!(!installation.join("evidence").exists());
    assert!(fixture.ca.state.lock().unwrap().requests.is_empty());
}

#[test]
fn partial_or_noncontiguous_receipts_hold_before_network_without_repair() {
    for corrupt in [true, false] {
        let fixture = Fixture::new();
        fixture.run().unwrap();
        let requests = fixture.ca.state.lock().unwrap().requests.len();
        let path = fixture
            .installation
            .join("evidence/acme-staging-000001.json");
        if corrupt {
            std::fs::write(&path, b"{\"schema\":").unwrap();
        } else {
            std::fs::rename(&path, fixture.installation.join("retained-gap.json")).unwrap();
        }
        assert!(fixture.run().is_err());
        assert_eq!(fixture.ca.state.lock().unwrap().requests.len(), requests);
        if corrupt {
            assert_eq!(std::fs::read(&path).unwrap(), b"{\"schema\":");
        }
    }
}

#[test]
fn projection_link_or_wrong_mode_is_refused_before_challenge_notification() {
    for link in [true, false] {
        let fixture = Fixture::new();
        if link {
            let outside = fixture.installation.join("foreign.json");
            std::fs::write(&outside, b"{}").unwrap();
            symlink(outside, &fixture.ca.projection).unwrap();
        } else {
            std::fs::write(&fixture.ca.projection, b"{}").unwrap();
            std::fs::set_permissions(
                &fixture.ca.projection,
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        assert!(fixture.run().is_err());
        assert_eq!(fixture.ca.state.lock().unwrap().ready, [false, false]);
    }
}

#[test]
fn explicit_staging_roots_and_environment_cannot_change_across_restart() {
    let fixture = Fixture::new();
    fixture.run().unwrap();
    let requests = fixture.ca.state.lock().unwrap().requests.len();
    let mut state = LockedMaintenance::open(&fixture.installation).unwrap();
    let mut inputs = fixture.inputs();
    inputs.staging_roots_pem = Some(ROOT_TEMPLATE);
    let binding = bind_inputs(state.inspection(), &inputs).unwrap();
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(drive(
            &mut state,
            &inputs,
            binding,
            fixture.signer.clone(),
            Box::new(fixture.ca.clone()),
        ));
    assert!(result.is_err());
    assert_eq!(fixture.ca.state.lock().unwrap().requests.len(), requests);
}
