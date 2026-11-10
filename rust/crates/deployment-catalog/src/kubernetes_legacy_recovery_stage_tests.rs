//! Real disposable test keys exercise the complete staging transaction. No
//! private signing capability or test entry point enters a release binary.
use super::super::staging::{self, Leaf, StageApi, Staging};
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use spki::der::{asn1::Ia5String, Decode};
use x509_cert::{
    ext::pkix::{name::GeneralName, ExtendedKeyUsage, SubjectAltName},
    request::{CertReq, CertReqInfo, Version},
    serial_number::SerialNumber,
};

struct RemoteKey {
    public: SubjectPublicKeyInfoOwned,
    ec: Option<EcdsaKeyPair>,
    rsa: Option<RsaKeyPair>,
}

impl RemoteKey {
    fn new(rsa: bool, ec_template: &SubjectPublicKeyInfoOwned) -> Self {
        if rsa {
            let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
            Self {
                public: SubjectPublicKeyInfoOwned::from_pem(key.public_key_pem()).unwrap(),
                rsa: Some(RsaKeyPair::from_pkcs8(key.serialized_der()).unwrap()),
                ec: None,
            }
        } else {
            let random = SystemRandom::new();
            let bytes =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
            let key =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, bytes.as_ref(), &random)
                    .unwrap();
            let mut public = ec_template.clone();
            public.subject_public_key = BitString::from_bytes(key.public_key().as_ref()).unwrap();
            Self {
                public,
                ec: Some(key),
                rsa: None,
            }
        }
    }

    fn signature(&self, message: &[u8]) -> Vec<u8> {
        if let Some(key) = &self.ec {
            key.sign(&SystemRandom::new(), message)
                .unwrap()
                .as_ref()
                .to_vec()
        } else {
            let key = self.rsa.as_ref().unwrap();
            let mut bytes = vec![0; key.public().modulus_len()];
            key.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), message, &mut bytes)
                .unwrap();
            bytes
        }
    }

    fn csr(&self) -> String {
        let info = CertReqInfo {
            version: Version::V1,
            subject: Name::from_str("CN=OpenBao Transit test CSR").unwrap(),
            public_key: self.public.clone(),
            attributes: Default::default(),
        };
        let der: &[u8] = if self.rsa.is_some() {
            &[
                0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
                0x00,
            ]
        } else {
            &[
                0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
            ]
        };
        let signature = BitString::from_bytes(&self.signature(&info.to_der().unwrap())).unwrap();
        CertReq {
            info,
            algorithm: AlgorithmIdentifierOwned::from_der(der).unwrap(),
            signature,
        }
        .to_pem(spki::der::pem::LineEnding::LF)
        .unwrap()
    }
}

struct FullFixture {
    base: Fixture,
    keys: BTreeMap<String, RemoteKey>,
    leaves: Vec<Leaf>,
    next: BTreeMap<String, Vec<u8>>,
}

impl FullFixture {
    fn new() -> Self {
        let mut base = Fixture::new();
        let (leaves, _) = staging::inventory(&binding(&base.context).unwrap()).unwrap();
        let mut keys = BTreeMap::new();
        let mut next = BTreeMap::new();
        for (index, leaf) in leaves.iter().enumerate() {
            let key = RemoteKey::new(
                leaf.mount == "keycloak-pki",
                &base.certificates.ec.tbs_certificate.subject_public_key_info,
            );
            let mut retained = base.certificates.ec.clone();
            let subject = Name::from_str(&format!("CN={}", leaf.common_name)).unwrap();
            retained.tbs_certificate.subject = subject.clone();
            retained.tbs_certificate.subject_public_key_info = key.public.clone();
            retained.tbs_certificate.serial_number =
                SerialNumber::new(&[(index + 1) as u8]).unwrap();
            let mut sans = vec![GeneralName::DnsName(
                Ia5String::new(&leaf.common_name).unwrap(),
            )];
            for name in leaf.uri_sans.split(',').filter(|name| !name.is_empty()) {
                sans.push(GeneralName::UniformResourceIdentifier(
                    Ia5String::new(name).unwrap(),
                ));
            }
            assert!(leaf.alt_names.is_empty() && leaf.ip_sans.is_empty());
            let mut usages = Vec::new();
            if leaf.server.unwrap_or(true) {
                usages.push(ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1"));
            }
            if leaf.client.unwrap_or(true) {
                usages.push(ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2"));
            }
            retained.tbs_certificate.extensions = Some(vec![
                BasicConstraints {
                    ca: false,
                    path_len_constraint: None,
                }
                .to_extension(&subject, &[])
                .unwrap(),
                KeyUsage(KeyUsages::DigitalSignature.into())
                    .to_extension(&subject, &[])
                    .unwrap(),
                SubjectAltName(sans).to_extension(&subject, &[]).unwrap(),
                ExtendedKeyUsage(usages)
                    .to_extension(&subject, &[])
                    .unwrap(),
            ]);
            let retained = sign(retained, &base.certificates.key);
            write(
                &base.context.current.join(&leaf.file),
                &pem(&retained),
                0o644,
            );
            base.reads
                .responses
                .get_mut(&format!("transit/keys/{}", leaf.key))
                .unwrap()["data"]["keys"]["1"]["public_key"] =
                json!(key.public.to_pem(spki::der::pem::LineEnding::LF).unwrap());
            let mut replacement = retained;
            replacement.tbs_certificate.serial_number =
                SerialNumber::new(&[(index + 101) as u8]).unwrap();
            replacement.tbs_certificate.validity.not_before = (UNIX_EPOCH
                + Duration::from_secs(base.certificates.now - 30))
            .try_into()
            .unwrap();
            replacement.tbs_certificate.validity.not_after = (UNIX_EPOCH
                + Duration::from_secs(base.certificates.now + TTL - 30))
            .try_into()
            .unwrap();
            next.insert(
                leaf.file.clone(),
                pem(&sign(replacement, &base.certificates.key)),
            );
            keys.insert(leaf.key.clone(), key);
        }
        write(
            &base.context.current.join("unchanged_static"),
            b"retained-noncredential-configuration",
            0o640,
        );
        write(&base.context.current.join("empty_optional"), b"", 0o444);
        Self {
            base,
            keys,
            leaves,
            next,
        }
    }

    fn producer(&self) -> Producer<'_> {
        Producer {
            fixture: self,
            posts: Mutex::new(Vec::new()),
            minted: Mutex::new(BTreeMap::new()),
            fault: Mutex::new(None),
            denials: Mutex::new(Vec::new()),
            drift_after: None,
            journal_change_after: None,
        }
    }
}

#[derive(Clone)]
enum Fault {
    Lost,
    CaptureLost,
    WrongKey,
    WrongCertificate,
    Scope,
    Ttl,
    Signature,
    Denial,
}

struct Producer<'a> {
    fixture: &'a FullFixture,
    posts: Mutex<Vec<(String, Value)>>,
    minted: Mutex<BTreeMap<String, Vec<String>>>,
    fault: Mutex<Option<(usize, Fault)>>,
    denials: Mutex<Vec<String>>,
    drift_after: Option<usize>,
    journal_change_after: Option<(usize, PathBuf)>,
}

#[async_trait]
impl ReadApi for Producer<'_> {
    async fn read(&self, path: &str, token: Option<&str>) -> Result<Value> {
        if path == "sys/health" {
            assert!(token.is_none());
        } else if token != Some(ROOT) {
            assert!(self.minted.lock().unwrap().contains_key(token.unwrap()));
        }
        let mut result = self
            .fixture
            .base
            .reads
            .responses
            .get(path)
            .cloned()
            .ok_or(REFUSAL)?;
        if self
            .drift_after
            .is_some_and(|count| self.posts.lock().unwrap().len() >= count)
            && path == "sys/health"
        {
            result["cluster_id"] = json!(KEY);
        }
        if let Some((count, path_to_change)) = &self.journal_change_after {
            if path == "sys/health" && self.posts.lock().unwrap().len() >= *count {
                write(path_to_change, b"changed-after-qualification-start", 0o600);
            }
        }
        Ok(result)
    }
}

#[async_trait]
impl StageApi for Producer<'_> {
    async fn post(&self, path: &str, body: &Value, token: &str, capture: &Path) -> Result<Value> {
        let index = self.posts.lock().unwrap().len();
        let request = capture.parent().unwrap().join(
            capture
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .replace("response-", "request-"),
        );
        let intent: Value = serde_json::from_slice(&fs::read(&request).unwrap()).unwrap();
        assert_eq!(
            intent["path"], path,
            "durable request intent precedes the API"
        );
        assert_eq!(intent["body"], *body);
        self.posts.lock().unwrap().push((path.into(), body.clone()));
        let fault = self
            .fault
            .lock()
            .unwrap()
            .as_ref()
            .filter(|(at, _)| *at == index)
            .map(|(_, fault)| fault.clone());
        if matches!(fault, Some(Fault::CaptureLost)) {
            return Err(staging::RECOVERY);
        }
        if matches!(fault, Some(Fault::Lost)) {
            write(capture, br#"{"received":false}"#, 0o600);
            return Err(staging::RECOVERY);
        }
        let mut response = if let Some(key) = path
            .strip_prefix("transit/keys/")
            .and_then(|path| path.strip_suffix("/csr"))
        {
            assert_eq!(token, ROOT);
            assert_eq!(*body, json!({"version":1}));
            json!({"data":{"csr":self.fixture.keys[key].csr()}})
        } else if path.contains("-pki/sign/") {
            assert_eq!(token, ROOT);
            let leaf = self
                .fixture
                .leaves
                .iter()
                .find(|leaf| {
                    path == format!("{}/sign/{}", leaf.mount, leaf.role)
                        && body["common_name"] == leaf.common_name
                })
                .unwrap();
            assert_eq!(body["ttl"], "8h");
            let request = CertReq::from_pem(body["csr"].as_str().unwrap()).unwrap();
            assert_eq!(request.info.public_key, self.fixture.keys[&leaf.key].public);
            json!({"data":{"certificate":String::from_utf8(self.fixture.next[&leaf.file].clone()).unwrap()}})
        } else if path == "auth/token/create" {
            assert_eq!(token, ROOT);
            let (_, tokens) =
                staging::inventory(&binding(&self.fixture.base.context).unwrap()).unwrap();
            let spec = tokens
                .iter()
                .find(|spec| body["policies"] == json!(spec.policies))
                .unwrap();
            assert_eq!(
                *body,
                json!({"policies":spec.policies,"no_default_policy":true,"no_parent":true,
                "renewable":false,"ttl":"8h","explicit_max_ttl":"8h","type":"service"})
            );
            let value = format!("new-synthetic-recovery-token-{}", spec.file);
            self.minted
                .lock()
                .unwrap()
                .insert(value.clone(), spec.policies.clone());
            json!({"auth":{"client_token":value,"policies":spec.policies,"token_policies":spec.policies,
                "identity_policies":[],"orphan":true,"num_uses":0,"token_type":"service","renewable":false,
                "lease_duration":TTL},"warnings":null})
        } else if path == "auth/token/lookup" {
            assert_eq!(token, ROOT);
            let value = text(body, "token")?;
            let policies = self.minted.lock().unwrap()[value].clone();
            json!({"data":{"id":value,"policies":policies,"identity_policies":[],"orphan":true,"num_uses":0,
                "type":"service","renewable":false,"ttl":TTL-1,"creation_ttl":TTL,"explicit_max_ttl":TTL,"path":"auth/token/create","period":0}})
        } else if let Some(key) = path.strip_prefix("transit/sign/") {
            assert!(self.minted.lock().unwrap().contains_key(token));
            assert_eq!(body["key_version"], 1);
            let challenge = STANDARD.decode(text(body, "input")?).unwrap();
            json!({"data":{"signature":format!("vault:v1:{}",STANDARD.encode(self.fixture.keys[key].signature(&challenge)))}})
        } else {
            panic!("unreviewed endpoint reached: {path}")
        };
        match fault {
            Some(Fault::WrongKey) => {
                let other = self
                    .fixture
                    .keys
                    .values()
                    .find(|key| key.rsa.is_some())
                    .unwrap();
                response["data"]["csr"] = json!(other.csr());
            }
            Some(Fault::WrongCertificate) => {
                let mut certificate =
                    certificate(self.fixture.next.values().next().unwrap()).unwrap();
                certificate.tbs_certificate.subject =
                    Name::from_str("CN=unexpected-subject").unwrap();
                response["data"]["certificate"] = json!(String::from_utf8(pem(&sign(
                    certificate,
                    &self.fixture.base.certificates.key
                )))
                .unwrap());
            }
            Some(Fault::Scope) => response["auth"]["policies"] = json!(["root"]),
            Some(Fault::Ttl) => response["data"]["explicit_max_ttl"] = json!(TTL + 1),
            Some(Fault::Signature) => {
                response["data"]["signature"] = json!("vault:v1:YWx0ZXJlZA==")
            }
            _ => {}
        }
        write(
            capture,
            &serde_json::to_vec(&json!({"received":true,"status":200,"complete":true,
            "bodyBase64":STANDARD.encode(serde_json::to_vec(&response).unwrap())}))
            .unwrap(),
            0o600,
        );
        Ok(response)
    }

    async fn denied(&self, path: &str, token: &str) -> Result<()> {
        assert!(self.minted.lock().unwrap().contains_key(token));
        self.denials.lock().unwrap().push(path.into());
        if self
            .fault
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|(_, fault)| matches!(fault, Fault::Denial))
        {
            Err(REFUSAL)
        } else {
            Ok(())
        }
    }
}

async fn stage_request(fixture: &FullFixture, producer: &Producer<'_>) -> Staging {
    let report = inspect_with(producer, &fixture.base.context).await.unwrap();
    let inspection = fixture.base._directory.path().join("inspection.json");
    write(&inspection, &serde_json::to_vec(&report).unwrap(), 0o600);
    let output = fixture.base._directory.path().join("stage");
    fs::create_dir(&output).unwrap();
    fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
    Staging {
        schema: staging::STAGE_SCHEMA.into(),
        context: decode_context(&serde_json::to_vec(&fixture.base.context).unwrap()).unwrap(),
        inspection,
        output,
    }
}

#[tokio::test]
async fn stage_preserves_original_state_and_only_replaces_the_closed_inventory() {
    let fixture = FullFixture::new();
    let producer = fixture.producer();
    let stage = stage_request(&fixture, &producer).await;
    let before = generation(&stage.context.current).unwrap();
    let result = staging::stage_with(&producer, &stage).await.unwrap();
    assert_eq!(result["status"], "staged-not-activated");
    assert_eq!(result["replacementCount"], 51);
    assert_eq!(result["activation"], false);
    assert_eq!(generation(&stage.context.current).unwrap(), before);
    let candidate = generation(&stage.output.join("candidate")).unwrap();
    assert_eq!(candidate.len(), before.len());
    assert_eq!(
        candidate["openbao_bootstrap_token"],
        before["openbao_bootstrap_token"]
    );
    assert_eq!(candidate["unchanged_static"], before["unchanged_static"]);
    assert_eq!(candidate["empty_optional"], before["empty_optional"]);
    assert_eq!(
        candidate
            .iter()
            .filter(|(name, value)| **value != before[*name])
            .count(),
        51
    );
    assert_eq!(producer.posts.lock().unwrap().len(), 120);
    assert_eq!(producer.minted.lock().unwrap().len(), 33);
    assert_eq!(producer.denials.lock().unwrap().len(), 33);
    assert!(stage.output.join("complete.json").is_file());
    let complete = staging::private_report(&stage.output.join("complete.json")).unwrap();
    assert_eq!(complete["journalBindings"].as_object().unwrap().len(), 240);
    assert_eq!(
        complete["journalBindings"]["response-000.json"],
        sha256(&fs::read(stage.output.join("response-000.json")).unwrap())
    );
    assert_eq!(
        result["stagingReceiptSha256"],
        sha256(&fs::read(stage.output.join("complete.json")).unwrap())
    );
    assert!(stage.output.join("request-119.json").is_file());
    assert!(stage.output.join("response-119.json").is_file());
    assert_eq!(
        staging::stage_with(&producer, &stage).await.unwrap_err(),
        REFUSAL
    );
    assert_eq!(
        producer.posts.lock().unwrap().len(),
        120,
        "a completed or partial attempt cannot replay"
    );
}

#[tokio::test]
async fn invalid_retained_identity_and_inspection_drift_refuse_before_a_post() {
    for identity_drift in [true, false] {
        let fixture = FullFixture::new();
        let producer = fixture.producer();
        let stage = stage_request(&fixture, &producer).await;
        if identity_drift {
            let path = stage.context.current.join(&fixture.leaves[0].file);
            let mut retained = certificate(&fs::read(&path).unwrap()).unwrap();
            retained.tbs_certificate.subject =
                Name::from_str("CN=unexpected-retained-name").unwrap();
            write(
                &path,
                &pem(&sign(retained, &fixture.base.certificates.key)),
                0o644,
            );
        } else {
            let mut report: Value =
                serde_json::from_slice(&fs::read(&stage.inspection).unwrap()).unwrap();
            report["observed"]["policies"]["credential-service"]["policy"] = json!("changed");
            write(
                &stage.inspection,
                &serde_json::to_vec(&report).unwrap(),
                0o600,
            );
        }
        assert!(staging::stage_with(&producer, &stage).await.is_err());
        assert!(producer.posts.lock().unwrap().is_empty());
        assert!(!stage.output.join("attempt.json").exists());
    }
}

#[tokio::test]
async fn every_uncertain_or_invalid_issuance_preserves_intent_and_prevents_replay() {
    for (at, fault) in [
        (0, Fault::WrongKey),
        (1, Fault::WrongCertificate),
        (36, Fault::Lost),
        (36, Fault::CaptureLost),
        (36, Fault::Scope),
        (37, Fault::Ttl),
        (38, Fault::Signature),
        (38, Fault::Denial),
    ] {
        let fixture = FullFixture::new();
        let producer = fixture.producer();
        let stage = stage_request(&fixture, &producer).await;
        *producer.fault.lock().unwrap() = Some((at, fault.clone()));
        assert_eq!(
            staging::stage_with(&producer, &stage).await.unwrap_err(),
            staging::RECOVERY,
            "at {at}"
        );
        assert!(stage.output.join("attempt.json").is_file());
        assert!(stage.output.join(format!("request-{at:03}.json")).is_file());
        if !matches!(fault, Fault::CaptureLost) {
            assert!(stage
                .output
                .join(format!("response-{at:03}.json"))
                .is_file());
        }
        assert!(!stage.output.join("complete.json").exists());
        assert!(!stage.output.join("candidate").exists());
        let count = producer.posts.lock().unwrap().len();
        assert_eq!(
            staging::stage_with(&producer, &stage).await.unwrap_err(),
            REFUSAL
        );
        assert_eq!(producer.posts.lock().unwrap().len(), count);
    }
}

#[tokio::test]
async fn changed_cluster_after_issuance_cannot_acknowledge_a_candidate() {
    let fixture = FullFixture::new();
    let mut producer = fixture.producer();
    let stage = stage_request(&fixture, &producer).await;
    producer.drift_after = Some(120);
    assert_eq!(
        staging::stage_with(&producer, &stage).await.unwrap_err(),
        staging::RECOVERY
    );
    assert_eq!(producer.minted.lock().unwrap().len(), 33);
    assert!(stage.output.join("inputs").is_dir());
    assert!(!stage.output.join("candidate").exists());
    assert!(!stage.output.join("complete.json").exists());
}

#[test]
fn replacement_certificate_must_keep_spki_identity_issuer_and_bounded_validity() {
    let fixture = FullFixture::new();
    let leaf = &fixture.leaves[0];
    let retained = fs::read(fixture.base.context.current.join(&leaf.file)).unwrap();
    let public = fixture.keys[&leaf.key]
        .public
        .to_pem(spki::der::pem::LineEnding::LF)
        .unwrap();
    for case in 0..5 {
        let mut replacement = certificate(&fixture.next[&leaf.file]).unwrap();
        match case {
            0 => replacement.tbs_certificate.subject = Name::from_str("CN=other").unwrap(),
            1 => {
                replacement.tbs_certificate.subject_public_key_info = fixture
                    .base
                    .certificates
                    .ca
                    .tbs_certificate
                    .subject_public_key_info
                    .clone()
            }
            2 => {
                replacement.tbs_certificate.validity.not_before = (UNIX_EPOCH
                    + Duration::from_secs(fixture.base.certificates.now + 60))
                .try_into()
                .unwrap()
            }
            3 => {
                replacement.tbs_certificate.validity.not_after = (UNIX_EPOCH
                    + Duration::from_secs(fixture.base.certificates.now + TTL + 600))
                .try_into()
                .unwrap()
            }
            _ => replacement
                .tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .retain(|extension| extension.extn_id.to_string() != "2.5.29.37"),
        }
        let response = json!({"data":{"certificate":String::from_utf8(pem(&sign(replacement,&fixture.base.certificates.key))).unwrap()}});
        assert!(
            staging::replacement_leaf(
                &response,
                &retained,
                &pem(&fixture.base.certificates.ca),
                &public
            )
            .is_err(),
            "case {case}"
        );
    }
}

fn observed_secrets(current: &Generation, binding: &Binding) -> Value {
    let (leaves, tokens) = staging::inventory(binding).unwrap();
    let files: BTreeSet<_> = leaves
        .into_iter()
        .map(|leaf| leaf.file)
        .chain(tokens.into_iter().map(|token| token.file))
        .collect();
    let mut items = Vec::new();
    let catalog = crate::kubernetes_secrets::contract()["catalog"].clone();
    for secret in catalog["secrets"].as_array().unwrap() {
        let mut data = serde_json::Map::new();
        for (field, spec) in secret["fields"].as_object().unwrap() {
            if let Some(input) = spec["env"].as_str() {
                let file = input.to_ascii_lowercase();
                if files.contains(&file) {
                    let value = String::from_utf8(current[&file].0.clone())
                        .unwrap()
                        .replace('\r', "");
                    data.insert(
                        field.clone(),
                        json!(STANDARD.encode(value.trim_end_matches('\n'))),
                    );
                }
            }
        }
        if data.is_empty() {
            continue;
        }
        data.insert(
            "foreign-retained".into(),
            json!(STANDARD.encode(b"unchanged")),
        );
        let index = items.len() + 1;
        items.push(json!({"apiVersion":"v1","kind":"Secret","type":"Opaque",
            "metadata":{"name":secret["name"],"namespace":binding.namespace,
                "uid":format!("00000000-0000-4000-8000-{index:012}"),"resourceVersion":format!("{index}")},"data":data}));
    }
    assert_eq!(items.len(), 34);
    json!({"apiVersion":"v1","kind":"SecretList","items":items})
}

fn qualification_request(fixture: &FullFixture, stage: &Staging) -> qualification::Qualification {
    let binding = binding(&stage.context).unwrap();
    let current = generation(&stage.context.current).unwrap();
    let secrets = fixture.base._directory.path().join("secrets.json");
    write(
        &secrets,
        &serde_json::to_vec(&observed_secrets(&current, &binding)).unwrap(),
        0o600,
    );
    let output = fixture.base._directory.path().join("qualification");
    fs::create_dir(&output).unwrap();
    fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
    qualification::Qualification {
        schema: qualification::SCHEMA.into(),
        context: decode_context(&serde_json::to_vec(&stage.context).unwrap()).unwrap(),
        inspection: stage.inspection.clone(),
        staged: stage.output.clone(),
        secrets,
        output,
    }
}

#[tokio::test]
async fn qualification_reproves_candidate_without_reissuing_credentials() {
    let fixture = FullFixture::new();
    let producer = fixture.producer();
    let stage = stage_request(&fixture, &producer).await;
    staging::stage_with(&producer, &stage).await.unwrap();
    let request = qualification_request(&fixture, &stage);
    let result = qualification::qualify_with(&producer, &request)
        .await
        .unwrap();
    assert_eq!(result["credentialsQualified"], true);
    assert_eq!(result["credentialsIssued"], false);
    assert_eq!(result["activation"], false);
    {
        let posts = producer.posts.lock().unwrap();
        assert_eq!(posts.len(), 171);
        assert!(posts[120..]
            .iter()
            .all(|(path, _)| path == "auth/token/lookup" || path.starts_with("transit/sign/")));
    }
    assert_eq!(producer.minted.lock().unwrap().len(), 33);
    let plan = staging::private_report(&request.output.join("plan.json")).unwrap();
    assert_eq!(
        result["privatePlanSha256"],
        sha256(&fs::read(request.output.join("plan.json")).unwrap())
    );
    assert_eq!(
        plan["stagingReceiptSha256"],
        sha256(&fs::read(stage.output.join("complete.json")).unwrap())
    );
    assert_eq!(
        plan["inspectionSha256"],
        sha256(&fs::read(&stage.inspection).unwrap())
    );
    assert_eq!(plan["nativePlan"]["secrets"].as_array().unwrap().len(), 34);
    assert_eq!(plan["nativePlan"]["credentialsQualified"], false);
    assert_eq!(plan["credentialsQualified"], true);
    let journal = plan["qualificationJournalBindings"].as_object().unwrap();
    assert_eq!(journal.len(), 102);
    for index in 0..51 {
        for kind in ["request", "response"] {
            let name = format!("{kind}-{index:03}.json");
            assert_eq!(
                journal[&name],
                sha256(&fs::read(request.output.join(name)).unwrap())
            );
        }
    }
    assert_eq!(
        plan["validBeforeUnixSeconds"].as_u64().unwrap()
            - plan["qualifiedAtUnixSeconds"].as_u64().unwrap(),
        300
    );
    let names = activation::target_names(&binding(&stage.context).unwrap()).unwrap();
    assert_eq!(
        names,
        plan["nativePlan"]["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["name"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        qualification::qualify_with(&producer, &request)
            .await
            .unwrap_err(),
        REFUSAL
    );
    assert_eq!(producer.posts.lock().unwrap().len(), 171);
}

#[tokio::test]
async fn qualification_refuses_changed_private_evidence_candidate_and_live_secrets_before_probes() {
    for case in 0..4 {
        let fixture = FullFixture::new();
        let producer = fixture.producer();
        let stage = stage_request(&fixture, &producer).await;
        staging::stage_with(&producer, &stage).await.unwrap();
        let request = qualification_request(&fixture, &stage);
        match case {
            0 => {
                let path = stage.output.join("complete.json");
                let mut value = staging::private_report(&path).unwrap();
                value["completedRequests"] = json!(119);
                write(&path, &serde_json::to_vec(&value).unwrap(), 0o600);
            }
            1 => {
                let path = stage.output.join("candidate/unchanged_static");
                write(&path, b"tampered", 0o640);
            }
            2 => {
                let path = stage.output.join("response-036.json");
                let mut value = staging::private_report(&path).unwrap();
                value["complete"] = json!(false);
                write(&path, &serde_json::to_vec(&value).unwrap(), 0o600);
            }
            3 => {
                let mut value = staging::private_report(&request.secrets).unwrap();
                value["items"][0]["metadata"]["namespace"] = json!("other");
                write(
                    &request.secrets,
                    &serde_json::to_vec(&value).unwrap(),
                    0o600,
                );
            }
            _ => unreachable!(),
        }
        assert!(
            qualification::qualify_with(&producer, &request)
                .await
                .is_err(),
            "case {case}"
        );
        assert_eq!(producer.posts.lock().unwrap().len(), 120);
        assert!(!request.output.join("attempt.json").exists());
        assert!(!request.output.join("plan.json").exists());
    }
}

#[tokio::test]
async fn qualification_scope_or_signature_failure_keeps_evidence_without_a_plan() {
    for (offset, fault) in [(0, Fault::Ttl), (1, Fault::Signature), (1, Fault::Denial)] {
        let fixture = FullFixture::new();
        let producer = fixture.producer();
        let stage = stage_request(&fixture, &producer).await;
        staging::stage_with(&producer, &stage).await.unwrap();
        let request = qualification_request(&fixture, &stage);
        *producer.fault.lock().unwrap() = Some((120 + offset, fault));
        assert_eq!(
            qualification::qualify_with(&producer, &request)
                .await
                .unwrap_err(),
            staging::RECOVERY
        );
        assert!(request.output.join("attempt.json").is_file());
        assert!(request
            .output
            .join(format!("request-{offset:03}.json"))
            .is_file());
        assert!(!request.output.join("plan.json").exists());
        assert_eq!(producer.minted.lock().unwrap().len(), 33);
        assert!(
            stage.output.join("complete.json").is_file(),
            "issuance evidence must survive qualification refusal"
        );
    }
}

#[tokio::test]
async fn qualification_requires_the_entire_original_stage_journal_and_inputs() {
    for case in 0..5 {
        let fixture = FullFixture::new();
        let producer = fixture.producer();
        let stage = stage_request(&fixture, &producer).await;
        staging::stage_with(&producer, &stage).await.unwrap();
        let request = qualification_request(&fixture, &stage);
        match case {
            0 => fs::remove_file(stage.output.join("response-000.json")).unwrap(),
            1 => write(
                &stage.output.join("response-001.json"),
                b"changed-certificate-capture",
                0o600,
            ),
            2 => write(
                &stage.output.join("request-038.json"),
                b"changed-proof-intent",
                0o600,
            ),
            3 => write(
                &stage.output.join("response-120.json"),
                b"unexpected-extra-record",
                0o600,
            ),
            4 => write(
                &stage.output.join("inputs").join(&fixture.leaves[0].file),
                b"changed-input-copy",
                0o600,
            ),
            _ => unreachable!(),
        }
        assert!(
            qualification::qualify_with(&producer, &request)
                .await
                .is_err(),
            "case {case}"
        );
        assert_eq!(producer.posts.lock().unwrap().len(), 120);
        assert!(!request.output.join("attempt.json").exists());
        assert!(!request.output.join("plan.json").exists());
    }
}

#[tokio::test]
async fn qualification_rechecks_all_stage_journal_bytes_after_live_probes() {
    for name in ["response-000.json", "response-036.json", "request-119.json"] {
        let fixture = FullFixture::new();
        let mut producer = fixture.producer();
        let stage = stage_request(&fixture, &producer).await;
        staging::stage_with(&producer, &stage).await.unwrap();
        let request = qualification_request(&fixture, &stage);
        producer.journal_change_after = Some((171, stage.output.join(name)));
        assert_eq!(
            qualification::qualify_with(&producer, &request)
                .await
                .unwrap_err(),
            staging::RECOVERY
        );
        assert_eq!(producer.posts.lock().unwrap().len(), 171);
        assert!(request.output.join("attempt.json").is_file());
        assert!(!request.output.join("plan.json").exists());
        assert_eq!(producer.minted.lock().unwrap().len(), 33);
    }
}

#[tokio::test]
async fn qualification_rechecks_its_own_complete_journal_before_publishing_a_plan() {
    for name in ["response-000.json", "request-050.json", "response-051.json"] {
        let fixture = FullFixture::new();
        let mut producer = fixture.producer();
        let stage = stage_request(&fixture, &producer).await;
        staging::stage_with(&producer, &stage).await.unwrap();
        let request = qualification_request(&fixture, &stage);
        producer.journal_change_after = Some((171, request.output.join(name)));
        assert_eq!(
            qualification::qualify_with(&producer, &request)
                .await
                .unwrap_err(),
            staging::RECOVERY
        );
        assert_eq!(producer.posts.lock().unwrap().len(), 171);
        assert!(request.output.join("attempt.json").is_file());
        assert!(!request.output.join("plan.json").exists());
        assert_eq!(producer.minted.lock().unwrap().len(), 33);
    }
}

#[tokio::test]
async fn real_https_post_captures_bounded_opaque_evidence_before_interpretation() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    for case in [
        "valid",
        "error",
        "duplicate",
        "oversized",
        "truncated",
        "lost",
    ] {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let mut server_params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = rcgen::KeyPair::generate().unwrap();
        let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(server_cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let request_path = directory.path().join("request-000.json");
        let body = match case {
            "valid" => br#"{"data":{"version":1}}"#.to_vec(),
            "error" => br#"{"errors":["synthetic-sensitive-error"]}"#.to_vec(),
            "duplicate" => br#"{"data":{"version":1,"version":2}}"#.to_vec(),
            "oversized" => vec![b'x'; 70 * 1024],
            "truncated" => br#"{"partial":true}"#.to_vec(),
            "lost" => Vec::new(),
            _ => unreachable!(),
        };
        let expected_body = body.clone();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut stream = tokio_rustls::TlsAcceptor::from(Arc::new(config))
                .accept(socket)
                .await
                .unwrap();
            let mut buffer = [0u8; 4096];
            let mut request = Vec::new();
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                let size = stream.read(&mut buffer).await.unwrap();
                assert!(size > 0 && request.len() + size <= 8192);
                request.extend_from_slice(&buffer[..size]);
            }
            let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
            assert!(request.starts_with("post /v1/auth/token/create http/1.1\r\n"));
            assert!(request.contains(&format!("\r\nx-vault-token: {ROOT}\r\n")));
            assert!(request_path.is_file(), "intent must precede HTTP");
            if case == "lost" {
                return;
            }
            let status = if case == "error" {
                "500 Internal Server Error"
            } else {
                "200 OK"
            };
            let length = body.len() + if case == "truncated" { 100 } else { 0 };
            let head=format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(&body).await;
            let _ = stream.shutdown().await;
        });
        let ca_path = directory.path().join("ca.pem");
        write(&ca_path, ca.pem().as_bytes(), 0o600);
        let bao = OpenBaoHttp::connect(
            &format!("https://localhost:{port}"),
            Some(&ca_path),
            Duration::from_secs(2),
        )
        .unwrap();
        let mut journal = staging::Journal {
            output: directory.path(),
            next: 0,
        };
        let result = journal
            .post(
                &Http(&bao),
                "capture-test",
                "auth/token/create",
                &json!({"synthetic":true}),
                ROOT,
            )
            .await;
        task.await.unwrap();
        assert_eq!(result.is_ok(), case == "valid", "case {case}");
        let raw = fs::read(directory.path().join("response-000.json")).unwrap();
        assert!(!String::from_utf8(raw.clone()).unwrap().contains(ROOT));
        let envelope: Value = serde_json::from_slice(&raw).unwrap();
        if case == "lost" {
            assert_eq!(envelope, json!({"received":false}));
        } else {
            assert_eq!(envelope["received"], true);
            assert_eq!(
                envelope["complete"],
                !["oversized", "truncated"].contains(&case)
            );
            let captured = STANDARD
                .decode(envelope["bodyBase64"].as_str().unwrap())
                .unwrap();
            assert_eq!(
                captured,
                expected_body[..expected_body.len().min(64 * 1024)]
            );
        }
        assert_eq!(
            fs::metadata(directory.path().join("response-000.json"))
                .unwrap()
                .mode()
                & 0o7777,
            0o600
        );
    }
}
