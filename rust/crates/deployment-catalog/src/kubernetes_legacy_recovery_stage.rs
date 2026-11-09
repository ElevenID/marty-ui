//! Bounded staging after an independently retained inspection. No Kubernetes
//! write, enrollment, key/CA/role/ACL mutation or original-generation edit.
//! Initially compiled only by tests; no release CLI dispatch exists yet.

use super::*;
use crate::{application_authority::legacy_recovery_leaf, operator_http::builder};
use base64::{engine::general_purpose::STANDARD, Engine};
use spki::{
    der::{asn1::AnyRef, Decode, DecodePem},
    AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned,
};
use std::{os::unix::fs::DirBuilderExt, str::FromStr};
use x509_cert::{
    ext::pkix::{name::GeneralName, ExtendedKeyUsage, SubjectAltName},
    name::Name,
    request::CertReq,
};

pub(super) const STAGE_SCHEMA: &str = "marty.kubernetes-legacy-recovery-stage/v1";
pub(super) const RECOVERY: &str =
    "Legacy Kubernetes staging is incomplete; preserve private evidence and do not replay";
const MIN_TTL: u64 = 7 * 3600;
const MAX_RESPONSE: usize = 64 * 1024;
const CHALLENGE: &[u8] = b"marty-legacy-kubernetes-recovery-v1";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Staging {
    pub(super) schema: String,
    pub(super) context: Context,
    pub(super) inspection: PathBuf,
    pub(super) output: PathBuf,
}

#[derive(Clone, Debug)]
pub(super) struct Leaf {
    pub(super) file: String,
    pub(super) key: String,
    pub(super) mount: &'static str,
    pub(super) role: String,
    pub(super) common_name: String,
    pub(super) alt_names: String,
    pub(super) uri_sans: String,
    pub(super) ip_sans: String,
    pub(super) server: Option<bool>,
    pub(super) client: Option<bool>,
}

#[derive(Clone, Debug)]
pub(super) enum Proof {
    Tls(String),
    KeycloakSigning,
    Jwe(String),
    Ordinary,
}

#[derive(Clone, Debug)]
pub(super) struct Token {
    pub(super) file: String,
    pub(super) policies: Vec<String>,
    pub(super) proof: Proof,
}

pub(super) fn inventory(binding: &Binding) -> Result<(Vec<Leaf>, Vec<Token>)> {
    let mut leaves = Vec::new();
    let mut tokens = Vec::new();
    for role in SELFHOST_ROLES {
        let profile = WORKLOAD_TLS_ROLES
            .iter()
            .find(|profile| profile.name == role.name)
            .ok_or(REFUSAL)?;
        leaves.push(Leaf {
            file: role.cert_file.into(),
            key: role.key_name.into(),
            mount: "workload-pki",
            role: role.name.into(),
            common_name: profile.common_name.into(),
            alt_names: profile.alt_names.into(),
            uri_sans: profile.uri_sans.into(),
            ip_sans: profile.ip_sans.into(),
            server: Some(profile.server),
            client: Some(profile.client),
        });
        tokens.push(Token {
            file: role.token_file.into(),
            policies: vec![format!("{}-{}", binding.workload_project, role.key_name)],
            proof: Proof::Tls(role.key_name.into()),
        });
    }
    for realm in keycloak::REALMS {
        leaves.push(Leaf {
            file: format!("keycloak_{realm}_rs256_cert"),
            key: format!("keycloak-{realm}-rs256"),
            mount: "keycloak-pki",
            role: "rs256".into(),
            common_name: format!("{realm}.keycloak.internal"),
            alt_names: String::new(),
            uri_sans: String::new(),
            ip_sans: String::new(),
            server: None,
            client: None,
        });
        for purpose in keycloak::PURPOSES {
            tokens.push(Token {
                file: format!("keycloak_{realm}_{purpose}_token"),
                policies: vec![format!(
                    "selfhost-keycloak-{realm}-{purpose}-{}",
                    binding.producer_nonce
                )],
                proof: Proof::Jwe(format!("didcomm/keycloak/keys/{realm}/{purpose}")),
            });
        }
    }
    tokens.push(Token {
        file: "keycloak_signing_kms_token".into(),
        policies: vec![format!("selfhost-keycloak-sign-{}", binding.producer_nonce)],
        proof: Proof::KeycloakSigning,
    });
    for spec in specifications()
        .into_iter()
        .filter(|spec| spec.input != "OPENBAO_BOOTSTRAP_TOKEN")
    {
        if spec.ttl_seconds != TTL {
            return Err(REFUSAL);
        }
        tokens.push(Token {
            file: spec.file,
            policies: spec.policies,
            proof: Proof::Ordinary,
        });
    }
    let names: BTreeSet<_> = leaves
        .iter()
        .map(|leaf| &leaf.file)
        .chain(tokens.iter().map(|token| &token.file))
        .collect();
    if leaves.len() != 18 || tokens.len() != 33 || names.len() != 51 {
        return Err(REFUSAL);
    }
    Ok((leaves, tokens))
}

fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| REFUSAL)
}

fn create_directory(path: &Path) -> Result<()> {
    private_directory(path.parent().ok_or(REFUSAL)?)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| REFUSAL)?;
    private_directory(path)?;
    sync_directory(path.parent().ok_or(REFUSAL)?)
}

pub(super) fn persist(path: &Path, value: &Value, limit: usize) -> Result<()> {
    private_directory(path.parent().ok_or(REFUSAL)?)?;
    let raw = serde_json::to_string(value).map_err(|_| REFUSAL)?;
    crate::operator_files::write_private(path, &raw, limit)?;
    sync_directory(path.parent().ok_or(REFUSAL)?)
}

fn write_bytes(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    private_directory(path.parent().ok_or(REFUSAL)?)?;
    if bytes.len() > MAX_FILE
        || bytes.contains(&0)
        || bytes.windows(11).any(|part| part == b"PRIVATE KEY")
    {
        return Err(REFUSAL);
    }
    let mut file = crate::operator_files::generation_output(path)?;
    crate::operator_files::finish_generation(&mut file, bytes, mode)?;
    sync_directory(path.parent().ok_or(REFUSAL)?)
}

pub(super) fn private_report(path: &Path) -> Result<Value> {
    let bytes = private_report_bytes(path)?;
    crate::installer_json::decode(&bytes).map_err(|_| REFUSAL)
}

pub(super) fn private_report_bytes(path: &Path) -> Result<Vec<u8>> {
    Ok(read_bounded(path, &[0o600], false, MAX_GENERATION + 1)?.0)
}

/// Bind the entire newly produced journal, including opaque records that need
/// no semantic replay during qualification. No earlier bootstrap evidence is
/// invented or required by this closure.
pub(super) fn journal_bindings(output: &Path, completed: bool) -> Result<Value> {
    private_directory(output)?;
    private_directory(&output.join("inputs"))?;
    private_directory(&output.join("candidate"))?;
    let mut expected = BTreeSet::from([
        "attempt.json".to_owned(),
        "inputs".to_owned(),
        "candidate".to_owned(),
    ]);
    if completed {
        expected.insert("complete.json".to_owned());
    }
    let mut records = BTreeMap::new();
    for index in 0..120 {
        for (kind, maximum) in [
            ("request", MAX_FILE + 1),
            ("response", 2 * MAX_RESPONSE + 1),
        ] {
            let name = format!("{kind}-{index:03}.json");
            expected.insert(name.clone());
            let bytes = read_bounded(&output.join(&name), &[0o600], false, maximum)?.0;
            records.insert(name, sha256(&bytes));
        }
    }
    let actual: BTreeSet<_> = fs::read_dir(output)
        .map_err(|_| REFUSAL)?
        .map(|entry| {
            entry
                .map_err(|_| REFUSAL)?
                .file_name()
                .into_string()
                .map_err(|_| REFUSAL)
        })
        .collect::<Result<_>>()?;
    if actual != expected {
        return Err(REFUSAL);
    }
    Ok(json!(records))
}

pub(super) fn replacement_inputs(
    output: &Path,
    candidate: &Generation,
    replacements: &BTreeSet<&String>,
) -> Result<()> {
    let directory = output.join("inputs");
    private_directory(&directory)?;
    let names: BTreeSet<_> = fs::read_dir(&directory)
        .map_err(|_| REFUSAL)?
        .map(|entry| {
            entry
                .map_err(|_| REFUSAL)?
                .file_name()
                .into_string()
                .map_err(|_| REFUSAL)
        })
        .collect::<Result<_>>()?;
    if names.iter().collect::<BTreeSet<_>>() != *replacements {
        return Err(REFUSAL);
    }
    for name in names {
        if read_input(&directory.join(&name), &[0o600], false)?.0
            != candidate.get(&name).ok_or(REFUSAL)?.0
        {
            return Err(REFUSAL);
        }
    }
    Ok(())
}

pub(super) fn same_report(expected: &Value, observed: &Value) -> Result<()> {
    if expected != observed
        || expected["schema"] != SCHEMA
        || expected["status"] != "inspected-not-staged"
        || expected["mutationAvailable"] != false
    {
        return Err(REFUSAL);
    }
    Ok(())
}

fn verify_signature(
    public: &SubjectPublicKeyInfoOwned,
    algorithm: &AlgorithmIdentifierOwned,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    let public_algorithm = public.algorithm.to_der().map_err(|_| REFUSAL)?;
    let signature_algorithm = algorithm.to_der().map_err(|_| REFUSAL)?;
    let public_algorithm = AnyRef::from_der(&public_algorithm).map_err(|_| REFUSAL)?;
    let signature_algorithm = AnyRef::from_der(&signature_algorithm).map_err(|_| REFUSAL)?;
    let public = public.subject_public_key.as_bytes().ok_or(REFUSAL)?;
    if signature.is_empty()
        || !webpki::ALL_VERIFICATION_ALGS.iter().any(|candidate| {
            candidate.public_key_alg_id().as_ref() == public_algorithm.value()
                && candidate.signature_alg_id().as_ref() == signature_algorithm.value()
                && candidate
                    .verify_signature(public, message, signature)
                    .is_ok()
        })
    {
        return Err(REFUSAL);
    }
    Ok(())
}

pub(super) fn csr(response: &Value, public: &str) -> Result<String> {
    let raw = text(&response["data"], "csr")?;
    if raw.len() > 16 * 1024
        || !raw.is_ascii()
        || raw.contains("PRIVATE KEY")
        || raw.matches("-----BEGIN CERTIFICATE REQUEST-----").count() != 1
        || !raw
            .trim()
            .starts_with("-----BEGIN CERTIFICATE REQUEST-----")
        || !raw.trim().ends_with("-----END CERTIFICATE REQUEST-----")
    {
        return Err(REFUSAL);
    }
    let request = CertReq::from_pem(raw).map_err(|_| REFUSAL)?;
    if request.info.public_key.to_der().map_err(|_| REFUSAL)?
        != public_spki(public.as_bytes(), false)?
    {
        return Err(REFUSAL);
    }
    verify_signature(
        &request.info.public_key,
        &request.algorithm,
        &request.info.to_der().map_err(|_| REFUSAL)?,
        request.signature.as_bytes().ok_or(REFUSAL)?,
    )?;
    Ok(raw.into())
}

fn names(certificate: &Certificate) -> Result<BTreeSet<String>> {
    let (_, sans) = certificate
        .tbs_certificate
        .get::<SubjectAltName>()
        .map_err(|_| REFUSAL)?
        .ok_or(REFUSAL)?;
    let mut result = BTreeSet::new();
    for name in sans.0 {
        let value = match name {
            GeneralName::DnsName(name) => format!("dns:{name}"),
            GeneralName::UniformResourceIdentifier(name) => format!("uri:{name}"),
            GeneralName::IpAddress(address) => {
                format!("ip:{}", STANDARD.encode(address.as_bytes()))
            }
            _ => return Err(REFUSAL),
        };
        if !result.insert(value) {
            return Err(REFUSAL);
        }
    }
    Ok(result)
}

pub(super) fn retained_profile(leaf: &Leaf, bytes: &[u8]) -> Result<()> {
    let certificate = certificate(bytes)?;
    if certificate.tbs_certificate.subject
        != Name::from_str(&format!("CN={}", leaf.common_name)).map_err(|_| REFUSAL)?
    {
        return Err(REFUSAL);
    }
    let mut expected = BTreeSet::from([format!("dns:{}", leaf.common_name)]);
    for name in leaf.alt_names.split(',').filter(|part| !part.is_empty()) {
        expected.insert(format!("dns:{name}"));
    }
    for name in leaf.uri_sans.split(',').filter(|part| !part.is_empty()) {
        expected.insert(format!("uri:{name}"));
    }
    for name in leaf.ip_sans.split(',').filter(|part| !part.is_empty()) {
        let bytes = match name.parse::<std::net::IpAddr>().map_err(|_| REFUSAL)? {
            std::net::IpAddr::V4(address) => address.octets().to_vec(),
            std::net::IpAddr::V6(address) => address.octets().to_vec(),
        };
        expected.insert(format!("ip:{}", STANDARD.encode(bytes)));
    }
    if names(&certificate)? != expected {
        return Err(REFUSAL);
    }
    if let (Some(server), Some(client)) = (leaf.server, leaf.client) {
        let (_, eku) = certificate
            .tbs_certificate
            .get::<ExtendedKeyUsage>()
            .map_err(|_| REFUSAL)?
            .ok_or(REFUSAL)?;
        let actual: BTreeSet<_> = eku.0.iter().map(ToString::to_string).collect();
        let mut expected = BTreeSet::new();
        if server {
            expected.insert("1.3.6.1.5.5.7.3.1".to_owned());
        }
        if client {
            expected.insert("1.3.6.1.5.5.7.3.2".to_owned());
        }
        if eku.0.len() != actual.len() || actual != expected {
            return Err(REFUSAL);
        }
    }
    identity(&certificate)?;
    Ok(())
}

fn identity(certificate: &Certificate) -> Result<Value> {
    let mut extensions = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for extension in certificate.tbs_certificate.extensions.iter().flatten() {
        let oid = extension.extn_id.to_string();
        if !seen.insert(oid.clone()) {
            return Err(REFUSAL);
        }
        if ["2.5.29.15", "2.5.29.17", "2.5.29.19", "2.5.29.37"].contains(&oid.as_str()) {
            extensions.insert(oid,json!({"critical":extension.critical,"der":STANDARD.encode(extension.extn_value.as_bytes())}));
        }
    }
    Ok(
        json!({"subject":STANDARD.encode(certificate.tbs_certificate.subject.to_der().map_err(|_| REFUSAL)?),"extensions":extensions}),
    )
}

pub(super) fn replacement_leaf(
    response: &Value,
    retained: &[u8],
    issuer: &[u8],
    public: &str,
) -> Result<Vec<u8>> {
    let data = &response["data"];
    if data.get("private_key").is_some() {
        return Err(REFUSAL);
    }
    let bytes = text(data, "certificate")?.as_bytes();
    let old = certificate(retained)?;
    let new = certificate(bytes)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| REFUSAL)?
        .as_secs();
    if bytes.len() > MAX_FILE
        || !check_lifetime(bytes, MIN_TTL)?
        || new
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs()
            > now.checked_add(TTL).ok_or(REFUSAL)?
        || public_spki(bytes, true)? != public_spki(public.as_bytes(), false)?
        || identity(&old)? != identity(&new)?
    {
        return Err(REFUSAL);
    }
    crate::operator_certificates::check_chain(bytes, issuer)?;
    retained_leaf_signature(bytes, issuer, Duration::from_secs(now))?;
    Ok(bytes.to_vec())
}

#[async_trait]
pub(super) trait StageApi: ReadApi {
    async fn post(&self, path: &str, body: &Value, token: &str, capture: &Path) -> Result<Value>;
    async fn denied(&self, path: &str, token: &str) -> Result<()>;
}

#[async_trait]
impl StageApi for Http<'_> {
    async fn post(&self, path: &str, body: &Value, token: &str, capture: &Path) -> Result<Value> {
        let response = builder(self.0, Method::POST, path, Some(body), Some(token))
            .send()
            .await;
        let Ok(mut response) = response else {
            persist(capture, &json!({"received":false}), 1024)?;
            return Err(RECOVERY);
        };
        let status = response.status();
        let mut bytes = Vec::new();
        let complete = loop {
            match response.chunk().await {
                Ok(Some(chunk)) if bytes.len() + chunk.len() <= MAX_RESPONSE => {
                    bytes.extend_from_slice(&chunk)
                }
                Ok(None) => break true,
                Ok(Some(chunk)) => {
                    bytes.extend_from_slice(&chunk[..MAX_RESPONSE - bytes.len()]);
                    break false;
                }
                Err(_) => break false,
            }
        };
        persist(
            capture,
            &json!({"received":true,"status":status.as_u16(),"complete":complete,"bodyBase64":STANDARD.encode(&bytes)}),
            2 * MAX_RESPONSE,
        )?;
        if !complete || !status.is_success() {
            return Err(RECOVERY);
        }
        crate::installer_json::decode(&bytes).map_err(|_| RECOVERY)
    }
    async fn denied(&self, path: &str, token: &str) -> Result<()> {
        crate::operator_http::denial(self.0, token, Method::GET, path, None).await
    }
}

pub(super) struct Journal<'a> {
    pub(super) output: &'a Path,
    pub(super) next: usize,
}
impl Journal<'_> {
    pub(super) async fn post(
        &mut self,
        api: &impl StageApi,
        operation: &str,
        path: &str,
        body: &Value,
        token: &str,
    ) -> Result<Value> {
        if self.next >= 128 {
            return Err(RECOVERY);
        }
        let index = self.next;
        self.next += 1;
        // An exclusive durable intent precedes the first byte of each POST.
        // Headers (including the retained root token) are never recorded.
        persist(
            &self.output.join(format!("request-{index:03}.json")),
            &json!({"operation":operation,"method":"POST","path":path,"body":body}),
            MAX_FILE,
        )?;
        api.post(
            path,
            body,
            token,
            &self.output.join(format!("response-{index:03}.json")),
        )
        .await
    }
}

fn sign_body(rsa: bool) -> Value {
    let mut body =
        json!({"input":STANDARD.encode(CHALLENGE),"key_version":1,"hash_algorithm":"sha2-256"});
    if rsa {
        body["signature_algorithm"] = json!("pkcs1v15");
    } else {
        body["marshaling_algorithm"] = json!("asn1");
    }
    body
}

fn signing_proof(response: &Value, public: &str, rsa: bool) -> Result<()> {
    let public = SubjectPublicKeyInfoOwned::from_pem(public).map_err(|_| REFUSAL)?;
    let signature = STANDARD
        .decode(
            text(&response["data"], "signature")?
                .strip_prefix("vault:v1:")
                .ok_or(REFUSAL)?,
        )
        .map_err(|_| REFUSAL)?;
    let der: &[u8] = if rsa {
        &[
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
            0x00,
        ]
    } else {
        &[
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
        ]
    };
    verify_signature(
        &public,
        &AlgorithmIdentifierOwned::from_der(der).map_err(|_| REFUSAL)?,
        CHALLENGE,
        &signature,
    )
}

pub(super) async fn prove(
    api: &impl StageApi,
    journal: &mut Journal<'_>,
    spec: &Token,
    value: &str,
    inspection: &Value,
) -> Result<()> {
    let keys = &inspection["observed"]["keys"];
    match &spec.proof {
        Proof::Tls(key) => {
            let observed = api
                .read(&format!("transit/keys/{key}"), Some(value))
                .await?;
            if observed["data"] != keys[key] {
                return Err(REFUSAL);
            }
            let proof = journal
                .post(
                    api,
                    "prove-existing-tls-key",
                    &format!("transit/sign/{key}"),
                    &sign_body(false),
                    value,
                )
                .await?;
            signing_proof(&proof, text(&keys[key]["keys"]["1"], "public_key")?, false)?;
            let foreign = SELFHOST_ROLES
                .iter()
                .find(|role| role.key_name != key)
                .ok_or(REFUSAL)?;
            api.denied(&format!("transit/keys/{}", foreign.key_name), value)
                .await?;
        }
        Proof::KeycloakSigning => {
            for realm in keycloak::REALMS {
                let key = format!("keycloak-{realm}-rs256");
                let proof = journal
                    .post(
                        api,
                        "prove-existing-keycloak-key",
                        &format!("transit/sign/{key}"),
                        &sign_body(true),
                        value,
                    )
                    .await?;
                signing_proof(&proof, text(&keys[&key]["keys"]["1"], "public_key")?, true)?;
            }
            api.denied("transit/keys/foreign-keycloak-selfhost", value)
                .await?;
        }
        Proof::Jwe(path) => {
            let observed = api.read(path, Some(value)).await?;
            if observed["data"]["version"] != inspection["observed"]["keycloakJweVersions"][path] {
                return Err(REFUSAL);
            }
            api.denied("transit/keys/foreign-keycloak-selfhost", value)
                .await?;
        }
        Proof::Ordinary => {
            api.denied("sys/policies/acl/root", value).await?;
        }
    }
    Ok(())
}

pub(super) async fn stage_with(api: &impl StageApi, stage: &Staging) -> Result<Value> {
    if stage.schema != STAGE_SCHEMA {
        return Err(REFUSAL);
    }
    let binding = binding(&stage.context)?;
    let (leaves, tokens) = inventory(&binding)?;
    let current = generation(&stage.context.current)?;
    private_directory(&stage.output)?;
    if stage.output.starts_with(&stage.context.current)
        || stage.context.current.starts_with(&stage.output)
        || stage.inspection.starts_with(&stage.output)
        || stage.context.root_token_file.starts_with(&stage.output)
        || fs::read_dir(&stage.output)
            .map_err(|_| REFUSAL)?
            .next()
            .is_some()
    {
        return Err(REFUSAL);
    }
    let inspection_bytes = private_report_bytes(&stage.inspection)?;
    let inspection = crate::installer_json::decode(&inspection_bytes).map_err(|_| REFUSAL)?;
    for leaf in &leaves {
        retained_profile(leaf, &current[&leaf.file].0)?;
    }
    same_report(&inspection, &inspect_with(api, &stage.context).await?)?;
    let root = read_input(&stage.context.root_token_file, &[0o400, 0o600], false)?.0;
    if sha256(&root) != stage.context.retained_root_sha256 {
        return Err(REFUSAL);
    }
    let root = std::str::from_utf8(&root).map_err(|_| REFUSAL)?;
    let inputs = stage.output.join("inputs");
    let candidate = stage.output.join("candidate");
    persist(
        &stage.output.join("attempt.json"),
        &json!({"schema":STAGE_SCHEMA,"binding":binding,
        "inspectionSha256":sha256(&inspection_bytes),
        "replacementFiles":leaves.iter().map(|leaf| &leaf.file).chain(tokens.iter().map(|token| &token.file)).collect::<Vec<_>>(),
        "activation":false}),
        MAX_FILE,
    )?;
    let result: Result<Value> = async {
        create_directory(&inputs)?;
        let mut journal = Journal {output:&stage.output,next:0};
        for leaf in &leaves {
            let key = &inspection["observed"]["keys"][&leaf.key];
            let public = text(&key["keys"]["1"],"public_key")?;
            let issued_csr = journal.post(api,"existing-key-csr",&format!("transit/keys/{}/csr",leaf.key),&json!({"version":1}),root).await?;
            let mut body = json!({"csr":csr(&issued_csr,public)?,"common_name":leaf.common_name,"ttl":"8h"});
            for (field,value) in [("alt_names",&leaf.alt_names),("uri_sans",&leaf.uri_sans),("ip_sans",&leaf.ip_sans)] {
                if !value.is_empty() { body[field] = json!(value); }
            }
            let signed = journal.post(api,"same-identity-certificate",&format!("{}/sign/{}",leaf.mount,leaf.role),&body,root).await?;
            let issuer = &inspection["observed"][if leaf.mount == "workload-pki" {"workloadIssuer"} else {"keycloakIssuer"}];
            let replacement = replacement_leaf(&signed,&current[&leaf.file].0,text(issuer,"certificate")?.as_bytes(),public)?;
            write_bytes(&inputs.join(&leaf.file),&replacement,0o600)?;
        }
        let previous: BTreeSet<_> = current.values().map(|(bytes,_)| bytes.as_slice()).collect();
        let mut minted = BTreeSet::new();
        for spec in &tokens {
            let created = journal.post(api,"same-scope-token","auth/token/create",&json!({"policies":spec.policies,
                "no_default_policy":true,"no_parent":true,"renewable":false,"ttl":"8h","explicit_max_ttl":"8h","type":"service"}),root).await?;
            let value = text(&created["auth"],"client_token")?;
            if !(20..=1024).contains(&value.len()) || !value.bytes().all(|byte| byte.is_ascii_graphic()) { return Err(REFUSAL); }
            write_bytes(&inputs.join(&spec.file),value.as_bytes(),0o600)?;
            if value == root || previous.contains(value.as_bytes()) || !minted.insert(value.to_owned()) { return Err(REFUSAL); }
            let lookup = journal.post(api,"verify-created-token","auth/token/lookup",&json!({"token":value}),root).await?;
            legacy_recovery_leaf(&created,&lookup,value,&spec.policies,TTL)?;
            prove(api,&mut journal,spec,value,&inspection).await?;
        }
        // Every preserved authority object must still equal the admitted target.
        same_report(&inspection,&inspect_with(api,&stage.context).await?)?;
        if generation(&stage.context.current)? != current || private_report_bytes(&stage.inspection)? != inspection_bytes { return Err(REFUSAL); }
        create_directory(&candidate)?;
        let replacements: BTreeSet<_> = leaves.iter().map(|leaf| &leaf.file).chain(tokens.iter().map(|token| &token.file)).collect();
        for (name,(original,mode)) in &current {
            let bytes = if replacements.contains(name) { read_input(&inputs.join(name),&[0o600],false)?.0 } else { original.clone() };
            write_bytes(&candidate.join(name),&bytes,*mode)?;
        }
        let staged = generation(&candidate)?;
        for (name,(bytes,mode)) in &current {
            let replacement = &staged[name];
            if replacement.1 != *mode || (replacements.contains(name) == (replacement.0 == *bytes)) { return Err(REFUSAL); }
        }
        replacement_inputs(&stage.output,&staged,&replacements)?;
        let journal_bindings=journal_bindings(&stage.output,false)?;
        let file_bindings: BTreeMap<_,_> = staged.iter().map(|(name,(bytes,mode))|
            (name,json!({"sha256":sha256(bytes),"mode":mode}))).collect();
        persist(&stage.output.join("complete.json"),&json!({"schema":STAGE_SCHEMA,"binding":binding,
            "status":"staged-not-activated","candidate":"candidate","replacementCount":51,"inputBindings":file_bindings,
            "completedRequests":journal.next,"journalBindings":journal_bindings,"activation":false}),MAX_GENERATION)?;
        Ok(json!({"schema":STAGE_SCHEMA,"status":"staged-not-activated","candidate":candidate,
            "replacementCount":51,"activation":false,
            "stagingReceiptSha256":sha256(&private_report_bytes(&stage.output.join("complete.json"))?)}))
    }.await;
    result.map_err(|_| RECOVERY)
}
