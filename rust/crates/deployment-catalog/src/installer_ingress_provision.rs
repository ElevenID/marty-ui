//! Fresh, container-only managed ingress authority. No existing PKI/Transit
//! resource is adopted or reset; every uncertain mutation requires recovery.
//! Host orchestration must record intent/container before invoking this helper.
#![cfg(target_os = "linux")]
use crate::{
    operator::{public_spki, version_one_custody},
    operator_certificates::{check_chain_at, check_lifetime, check_lifetime_at},
    operator_http::{builder, denial, request},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use marty_openbao_http::OpenBaoHttp;
use marty_selfhost_identity::origin::PublicOrigin;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use spki::der::{Decode, DecodePem, Encode};
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::IpAddr,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use x509_cert::{
    ext::pkix::{name::GeneralName, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAltName},
    Certificate,
};

pub type Result<T> = std::result::Result<T, String>;
const REFUSED: &str =
    "Ingress provisioning incomplete; preserve owned container and outputs for recovery";
const TTL: u64 = 28800;
pub const DNS_ENV: &str = "MARTY_INSTALLER_INGRESS_DNS_NAME";
pub const IP_ENV: &str = "MARTY_INSTALLER_INGRESS_IP_ADDRESS";
pub const OUTPUTS: [&str; 4] = [
    "installer_ingress_ca_cert",
    "installer_ingress_tls_cert",
    "installer_ingress_tls_kms_token",
    "installer-ingress.json",
];
#[path = "installer_ingress_renew.rs"]
mod renewal;
pub(crate) use renewal::{renew, renewal_inventory, validate_recorded_replacement};

/// Validated certificate identity, independent of the host listener and port.
/// A DNS host never gains an implicit IP SAN. Only the legacy local identity
/// deliberately contains both localhost and 127.0.0.1.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct IngressIdentity {
    dns: Option<String>,
    ip: Option<IpAddr>,
}
impl IngressIdentity {
    pub fn new(dns: Option<&str>, ip: Option<IpAddr>) -> Result<Self> {
        require(dns.is_some() || ip.is_some())?;
        if let Some(dns) = dns {
            let parsed = PublicOrigin::parse(&format!("https://{dns}")).map_err(|_| REFUSED)?;
            require(parsed.dns_name() == Some(dns))?;
        }
        if let Some(ip) = ip {
            let authority = match ip {
                IpAddr::V4(ip) => ip.to_string(),
                IpAddr::V6(ip) => format!("[{ip}]"),
            };
            let parsed =
                PublicOrigin::parse(&format!("https://{authority}")).map_err(|_| REFUSED)?;
            require(parsed.ip_address() == Some(ip))?;
        }
        require(
            dns.is_none()
                || ip.is_none()
                || (dns == Some("localhost") && ip == Some(IpAddr::from([127, 0, 0, 1]))),
        )?;
        Ok(Self {
            dns: dns.map(str::to_owned),
            ip,
        })
    }
    pub fn localhost() -> Self {
        Self {
            dns: Some("localhost".into()),
            ip: Some(IpAddr::from([127, 0, 0, 1])),
        }
    }
    pub fn from_environment() -> Result<Self> {
        match (std::env::var(DNS_ENV), std::env::var(IP_ENV)) {
            (Err(std::env::VarError::NotPresent), Err(std::env::VarError::NotPresent)) => {
                Ok(Self::localhost())
            }
            (Ok(dns), Ok(ip)) => {
                let address = if ip.is_empty() {
                    None
                } else {
                    let parsed: IpAddr = ip.parse().map_err(|_| REFUSED)?;
                    require(parsed.to_string() == ip)?;
                    Some(parsed)
                };
                Self::new((!dns.is_empty()).then_some(dns.as_str()), address)
            }
            _ => Err(REFUSED.into()),
        }
    }
    pub fn dns_names(&self) -> Vec<String> {
        self.dns.iter().cloned().collect()
    }
    pub fn ip_addresses(&self) -> Vec<String> {
        self.ip.iter().map(ToString::to_string).collect()
    }
    pub fn common_name(&self) -> String {
        self.dns
            .clone()
            .unwrap_or_else(|| self.ip.expect("validated identity").to_string())
    }
    fn role_body(&self) -> Value {
        // OpenBao's allow_ip_sans only enables IP SANs; it does not restrict
        // their values. Retain the exact IP literal as immutable role identity
        // metadata, alongside the native DNS constraint. The renewal AppRole
        // reconstructs this identity and binds every signing parameter in ACL.
        json!({"allow_any_name":false,"allow_localhost":self.dns.as_deref()==Some("localhost"),
            "allowed_domains":[self.common_name()],"allow_bare_domains":true,"allow_subdomains":false,
            "allow_glob_domains":false,"allow_wildcard_certificates":false,"allow_ip_sans":self.ip.is_some(),
            "server_flag":true,"client_flag":false,"key_type":"ec","key_bits":256,"max_ttl":"8h",
            "use_csr_common_name":false,"use_csr_sans":false,
            "cn_validations":if self.dns.is_some() {vec!["hostname"]} else {vec!["disabled"]}})
    }
    fn signing_request(&self, csr: &str) -> Value {
        json!({"csr":csr,"common_name":self.common_name(),
            "alt_names":self.dns.as_deref().unwrap_or(""),
            "ip_sans":self.ip.map(|v|v.to_string()).unwrap_or_default(),
            "exclude_cn_from_sans":true,"ttl":"8h"})
    }
    pub(crate) fn from_metadata(dns: &[String], ip: &[String]) -> Result<Self> {
        require(dns.len() <= 1 && ip.len() <= 1)?;
        let address = ip
            .first()
            .map(|s| s.parse::<IpAddr>().map_err(|_| REFUSED))
            .transpose()?;
        let identity = Self::new(dns.first().map(String::as_str), address)?;
        require(identity.dns_names() == dns && identity.ip_addresses() == ip)?;
        Ok(identity)
    }
}
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key].as_str().ok_or_else(|| REFUSED.into())
}
pub fn resource_name(installation_id: &str) -> Result<String> {
    let id = uuid::Uuid::parse_str(installation_id).map_err(|_| REFUSED)?;
    require(
        id.to_string() == installation_id
            && id.get_version_num() == 4
            && id.get_variant() == uuid::Variant::RFC4122,
    )?;
    Ok(format!("installer-ingress-{}", id.simple()))
}
fn valid_name(name: &str) -> bool {
    name.strip_prefix("installer-ingress-").is_some_and(|s| {
        s.len() == 32
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
pub fn signer_policy(name: &str) -> Result<String> {
    require(valid_name(name))?;
    Ok(format!("path \"transit/keys/{name}\" {{ capabilities = [\"read\"] }}\n\
path \"transit/sign/{name}\" {{\n  capabilities = [\"update\"]\n  required_parameters = [\"input\", \"prehashed\", \"hash_algorithm\", \"marshaling_algorithm\", \"key_version\"]\n  allowed_parameters = {{\n    \"input\" = []\n    \"prehashed\" = [true]\n    \"hash_algorithm\" = [\"sha2-256\"]\n    \"marshaling_algorithm\" = [\"asn1\"]\n    \"key_version\" = [\"1\"]\n  }}\n}}\n"))
}
fn read_input(path: &Path, max: u64, secret: bool) -> Result<Vec<u8>> {
    require(path.is_absolute() && path.canonicalize().map_err(|_| REFUSED)? == path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| REFUSED)?;
    let m = file.metadata().map_err(|_| REFUSED)?;
    require(
        m.is_file()
            && m.nlink() == 1
            && m.len() > 0
            && m.len() <= max
            && m.mode() & 0o7133 == 0
            && (!secret || (m.uid() == 0 && m.mode() & 0o7777 == 0o400)),
    )?;
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    require(bytes.len() as u64 == m.len())?;
    Ok(bytes)
}
fn fresh_output(path: &Path) -> Result<File> {
    require(path.is_absolute() && path.canonicalize().map_err(|_| REFUSED)? == path)?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| REFUSED)?;
    let m = dir.metadata().map_err(|_| REFUSED)?;
    require(m.is_dir() && m.mode() & 0o7777 == 0o700)?;
    require(
        std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))
            .map_err(|_| REFUSED)?
            .next()
            .is_none(),
    )?;
    Ok(dir)
}
fn write_output(dir: &File, name: &str, bytes: &[u8], root: &str) -> Result<()> {
    require(
        OUTPUTS.contains(&name) && !bytes.is_empty() && bytes.len() <= 65536 && bytes.is_ascii(),
    )?;
    let text = std::str::from_utf8(bytes).map_err(|_| REFUSED)?;
    require(!text.contains("PRIVATE KEY") && !text.contains(root) && !text.contains('\0'))?;
    let name = CString::new(name).map_err(|_| REFUSED)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    require(fd >= 0)?;
    let mut file = unsafe { File::from_raw_fd(fd) };
    dir.sync_all().map_err(|_| REFUSED)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| REFUSED)?;
    require(unsafe { libc::fchmod(file.as_raw_fd(), 0o444) } == 0)?;
    file.sync_all()
        .and_then(|_| dir.sync_all())
        .map_err(|_| REFUSED)?;
    Ok(())
}
async fn absent(bao: &OpenBaoHttp, path: &str, root: &str) -> Result<()> {
    let response = builder(bao, Method::GET, path, None, Some(root))
        .send()
        .await
        .map_err(|_| REFUSED)?;
    require(response.status() == StatusCode::NOT_FOUND)
}
pub(crate) fn certificate(pem: &str) -> Result<Certificate> {
    require(
        pem.len() <= 65536 && pem.is_ascii() && !pem.contains("PRIVATE KEY") && !pem.contains('\0'),
    )?;
    let chain = Certificate::load_pem_chain(pem.as_bytes()).map_err(|_| REFUSED)?;
    require(chain.len() == 1)?;
    let cert = Certificate::from_pem(pem.as_bytes()).map_err(|_| REFUSED)?;
    let mut extensions = BTreeSet::new();
    for extension in cert.tbs_certificate.extensions.iter().flatten() {
        require(extensions.insert(extension.extn_id))?;
    }
    Ok(cert)
}
fn p256(cert: &Certificate) -> Result<()> {
    let der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| REFUSED)?;
    let key = marty_crypto::jwk::public_key_der_to_jwk(&der).map_err(|_| REFUSED)?;
    require(key.kty == "EC" && key.crv.as_deref() == Some("P-256"))
}
fn check_self_signature(cert: &Certificate) -> Result<()> {
    check_certificate_signature(cert, cert)
}
fn check_certificate_signature(cert: &Certificate, issuer: &Certificate) -> Result<()> {
    let tbs = &cert.tbs_certificate;
    require(
        tbs.issuer == issuer.tbs_certificate.subject && tbs.signature == cert.signature_algorithm,
    )?;
    let public_alg = issuer
        .tbs_certificate
        .subject_public_key_info
        .algorithm
        .to_der()
        .map_err(|_| REFUSED)?;
    let signature_alg = cert.signature_algorithm.to_der().map_err(|_| REFUSED)?;
    let public_alg = spki::der::asn1::AnyRef::from_der(&public_alg).map_err(|_| REFUSED)?;
    let signature_alg = spki::der::asn1::AnyRef::from_der(&signature_alg).map_err(|_| REFUSED)?;
    let message = tbs.to_der().map_err(|_| REFUSED)?;
    let public = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or(REFUSED)?;
    let signature = cert.signature.as_bytes().ok_or(REFUSED)?;
    require(webpki::ALL_VERIFICATION_ALGS.iter().any(|algorithm| {
        algorithm.public_key_alg_id().as_ref() == public_alg.value()
            && algorithm.signature_alg_id().as_ref() == signature_alg.value()
            && algorithm
                .verify_signature(public, &message, signature)
                .is_ok()
    }))
}
fn check_leaf_profile(cert: &Certificate, identity: &IngressIdentity) -> Result<()> {
    p256(cert)?;
    let tbs = &cert.tbs_certificate;
    require(tbs.subject.to_string() == format!("CN={}", identity.common_name()))?;
    require(
        tbs.get::<BasicConstraints>()
            .map_err(|_| REFUSED)?
            .is_none_or(|(_, c)| !c.ca && c.path_len_constraint.is_none()),
    )?;
    let usage = tbs
        .get::<KeyUsage>()
        .map_err(|_| REFUSED)?
        .ok_or(REFUSED)?
        .1;
    require(usage.digital_signature() && !usage.key_cert_sign() && !usage.crl_sign())?;
    let eku = tbs
        .get::<ExtendedKeyUsage>()
        .map_err(|_| REFUSED)?
        .ok_or(REFUSED)?
        .1;
    require(eku.0.len() == 1 && eku.0[0].to_string() == "1.3.6.1.5.5.7.3.1")?;
    let san = tbs
        .get::<SubjectAltName>()
        .map_err(|_| REFUSED)?
        .ok_or(REFUSED)?
        .1;
    require(
        san.0.len() == usize::from(identity.dns.is_some()) + usize::from(identity.ip.is_some()),
    )?;
    let mut dns = BTreeSet::new();
    let mut ip = BTreeSet::new();
    for name in &san.0 {
        match name {
            GeneralName::DnsName(name) if dns.insert(name.as_str().to_owned()) => {}
            GeneralName::IpAddress(address) if ip.insert(address.as_bytes().to_vec()) => {}
            _ => return Err(REFUSED.into()),
        }
    }
    let expected_ip = identity
        .ip
        .map(|address| match address {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        })
        .into_iter()
        .collect();
    require(dns == identity.dns_names().into_iter().collect() && ip == expected_ip)
}
pub(crate) fn check_certificates_for(
    ca: &str,
    leaf: &str,
    public: &str,
    name: &str,
    now: u64,
    identity: &IngressIdentity,
) -> Result<(u64, u64)> {
    let root = certificate(ca)?;
    let cert = certificate(leaf)?;
    p256(&root)?;
    check_self_signature(&root)?;
    check_leaf_profile(&cert, identity)?;
    require(
        root.tbs_certificate.subject.to_string()
            == format!(
                "CN=Marty local CA {}",
                name.strip_prefix("installer-ingress-").ok_or(REFUSED)?
            ),
    )?;
    let constraints = root
        .tbs_certificate
        .get::<BasicConstraints>()
        .map_err(|_| REFUSED)?
        .ok_or(REFUSED)?;
    require(constraints.0 && constraints.1.ca)?;
    let usage = root
        .tbs_certificate
        .get::<KeyUsage>()
        .map_err(|_| REFUSED)?
        .ok_or(REFUSED)?
        .1;
    require(usage.key_cert_sign())?;
    require(
        check_lifetime_at(ca.as_bytes(), TTL, Duration::from_secs(now)).map_err(|_| REFUSED)?
            && check_lifetime_at(leaf.as_bytes(), 3600, Duration::from_secs(now))
                .map_err(|_| REFUSED)?,
    )?;
    let ca_expiry = root
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs();
    let leaf_expiry = cert
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs();
    require(
        ca_expiry <= now.checked_add(31536000).ok_or(REFUSED)?
            && leaf_expiry <= now.checked_add(TTL).ok_or(REFUSED)?,
    )?;
    check_chain_at(leaf.as_bytes(), ca.as_bytes(), Duration::from_secs(now))
        .map_err(|_| REFUSED)?;
    require(
        public_spki(leaf.as_bytes(), true).map_err(|_| REFUSED)?
            == public_spki(public.as_bytes(), false).map_err(|_| REFUSED)?,
    )?;
    Ok((ca_expiry, leaf_expiry))
}
fn check_token(data: &Value, policy: &str) -> Result<u64> {
    require(
        data["policies"] == json!([policy])
            && data["orphan"] == true
            && data["renewable"] == false
            && data["explicit_max_ttl"] == TTL
            && data["path"] == "auth/token/create-orphan",
    )?;
    let ttl = data["ttl"].as_u64().ok_or(REFUSED)?;
    require((3600..=TTL).contains(&ttl))?;
    Ok(ttl)
}
// OpenBao 2.5.x ACL compares JSON numbers and HCL integers as distinct types.
// Keep the version mandatory and exact, using the same string on wire and in policy.
fn sign_body() -> Value {
    json!({"input":STANDARD.encode(Sha256::digest(b"marty-installer-ingress-custody-proof")),
        "prehashed":true,"hash_algorithm":"sha2-256","marshaling_algorithm":"asn1","key_version":"1"})
}
fn verify_signing_proof(public: &str, signature: &str) -> Result<()> {
    let key = spki::SubjectPublicKeyInfoOwned::from_pem(public).map_err(|_| REFUSED)?;
    let alg = key.algorithm.to_der().map_err(|_| REFUSED)?;
    let alg = spki::der::asn1::AnyRef::from_der(&alg).map_err(|_| REFUSED)?;
    let public = key.subject_public_key.as_bytes().ok_or(REFUSED)?;
    let bytes = STANDARD
        .decode(signature.strip_prefix("vault:v1:").ok_or(REFUSED)?)
        .map_err(|_| REFUSED)?;
    // DER AlgorithmIdentifier contents for ecdsa-with-SHA256, the pinned
    // mmf-platform TLS signing request. Verification consumes the raw message.
    const ECDSA_SHA256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    require(webpki::ALL_VERIFICATION_ALGS.iter().any(|algorithm| {
        algorithm.public_key_alg_id().as_ref() == alg.value()
            && algorithm.signature_alg_id().as_ref() == ECDSA_SHA256
            && algorithm
                .verify_signature(public, b"marty-installer-ingress-custody-proof", &bytes)
                .is_ok()
    }))
}

// Closed diagnostic vocabulary: never attach backend bodies, paths, UUIDs or credentials.
#[derive(Clone, Copy, Debug)]
enum ProvisionStage {
    Input,
    CaInput,
    OutputDirectory,
    Connect,
    MountInventory,
    TransitAbsent,
    PolicyAbsent,
    MountCreate,
    CaCreate,
    CaResponse,
    TransitCreate,
    TransitReadback,
    TransitValidation,
    RoleCreate,
    CsrCreate,
    CertificateIssue,
    CertificateValidation,
    PolicyCreate,
    PolicyReadback,
    PolicyEquality,
    TokenCreate,
    TokenResponse,
    TokenLookup,
    TokenValidation,
    SignerRead,
    SignerValidation,
    SignerSign,
    SignatureProof,
    DenyForeignSign,
    DenyExport,
    DenyBackup,
    DenyRotation,
    DenyCaMutation,
    DenyTokenMint,
    DenyWrongVersion,
    DenyNumericVersion,
    DenyMissingVersion,
    Metadata,
    WriteCa,
    WriteCertificate,
    WriteToken,
    WriteMetadata,
}
impl ProvisionStage {
    fn label(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::CaInput => "ca-input",
            Self::OutputDirectory => "output-directory",
            Self::Connect => "connect",
            Self::MountInventory => "mount-inventory",
            Self::TransitAbsent => "transit-absent",
            Self::PolicyAbsent => "policy-absent",
            Self::MountCreate => "mount-create",
            Self::CaCreate => "ca-create",
            Self::CaResponse => "ca-response",
            Self::TransitCreate => "transit-create",
            Self::TransitReadback => "transit-readback",
            Self::TransitValidation => "transit-validation",
            Self::RoleCreate => "role-create",
            Self::CsrCreate => "csr-create",
            Self::CertificateIssue => "certificate-issue",
            Self::CertificateValidation => "certificate-validation",
            Self::PolicyCreate => "policy-create",
            Self::PolicyReadback => "policy-readback",
            Self::PolicyEquality => "policy-equality",
            Self::TokenCreate => "token-create",
            Self::TokenResponse => "token-response",
            Self::TokenLookup => "token-lookup",
            Self::TokenValidation => "token-validation",
            Self::SignerRead => "signer-read",
            Self::SignerValidation => "signer-validation",
            Self::SignerSign => "signer-sign",
            Self::SignatureProof => "signature-proof",
            Self::DenyForeignSign => "deny-foreign-sign",
            Self::DenyExport => "deny-export",
            Self::DenyBackup => "deny-backup",
            Self::DenyRotation => "deny-rotation",
            Self::DenyCaMutation => "deny-ca-mutation",
            Self::DenyTokenMint => "deny-token-mint",
            Self::DenyWrongVersion => "deny-wrong-version",
            Self::DenyNumericVersion => "deny-numeric-version",
            Self::DenyMissingVersion => "deny-missing-version",
            Self::Metadata => "metadata",
            Self::WriteCa => "write-ca",
            Self::WriteCertificate => "write-certificate",
            Self::WriteToken => "write-token",
            Self::WriteMetadata => "write-metadata",
        }
    }
}
fn stage_result<T, E>(stage: ProvisionStage, result: std::result::Result<T, E>) -> Result<T> {
    result.map_err(|_| {
        format!(
            "Ingress provisioning refused at {}; preserve owned state for recovery",
            stage.label()
        )
    })
}

/// Fixed-path root helper. This is creation only, never renewal or trust import.
/// Returns only a public file count. Never returns or logs raw backend errors.
pub async fn provision(installation_id: &str) -> Result<usize> {
    let mut stage = ProvisionStage::Input;
    let result: Result<usize> = async {
    require(unsafe { libc::geteuid() } == 0)?;
    let name = resource_name(installation_id)?;
    let identity = IngressIdentity::from_environment()?;
    let root_bytes = read_input(Path::new("/input/root.token"), 4096, true)?;
    let root = std::str::from_utf8(&root_bytes)
        .map_err(|_| REFUSED)?
        .trim();
    require(
        (20..=4096).contains(&root.len())
            && root.is_ascii()
            && !root
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control()),
    )?;
    stage = ProvisionStage::CaInput;
    read_input(Path::new("/input/ca.crt"), 65536, false)?;
    stage = ProvisionStage::OutputDirectory;
    let output = fresh_output(Path::new("/output"))?;
    stage = ProvisionStage::Connect;
    let bao = OpenBaoHttp::connect(
        "https://openbao:8200",
        Some(Path::new("/input/ca.crt")),
        Duration::from_secs(10),
    )
    .map_err(|_| REFUSED)?;
    stage = ProvisionStage::MountInventory;
    let mounts = request(&bao, Method::GET, "sys/mounts", None, Some(root))
        .await
        .map_err(|_| REFUSED)?;
    let mounts = mounts["data"].as_object().ok_or(REFUSED)?;
    require(
        mounts
            .get("transit/")
            .is_some_and(|v| v["type"] == "transit")
            && !mounts.contains_key(&format!("{name}/")),
    )?;
    stage = ProvisionStage::TransitAbsent;
    absent(&bao, &format!("transit/keys/{name}"), root).await?;
    stage = ProvisionStage::PolicyAbsent;
    absent(&bao, &format!("sys/policies/acl/{name}"), root).await?;
    stage = ProvisionStage::MountCreate;
    request(
        &bao,
        Method::POST,
        &format!("sys/mounts/{name}"),
        Some(&json!({"type":"pki","config":{"max_lease_ttl":"8760h"}})),
        Some(root),
    )
    .await
    .map_err(|_| REFUSED)?;
    stage = ProvisionStage::CaCreate;
    let ca = request(&bao, Method::POST, &format!("{name}/root/generate/internal"), Some(&json!({"common_name":format!("Marty local CA {}", name.strip_prefix("installer-ingress-").ok_or(REFUSED)?),"ttl":"8760h","key_type":"ec","key_bits":256})), Some(root)).await.map_err(|_| REFUSED)?;
    stage = ProvisionStage::CaResponse;
    require(ca["data"].get("private_key").is_none())?;
    let ca_pem = text(&ca["data"], "certificate")?;
    stage = ProvisionStage::TransitCreate;
    request(
        &bao,
        Method::POST,
        &format!("transit/keys/{name}"),
        Some(&json!({"type":"ecdsa-p256","exportable":false,"allow_plaintext_backup":false})),
        Some(root),
    )
    .await
    .map_err(|_| REFUSED)?;
    stage = ProvisionStage::TransitReadback;
    let custody = request(
        &bao,
        Method::GET,
        &format!("transit/keys/{name}"),
        None,
        Some(root),
    )
    .await
    .map_err(|_| REFUSED)?;
    stage = ProvisionStage::TransitValidation;
    version_one_custody(&custody["data"], "ecdsa-p256").map_err(|_| REFUSED)?;
    let public = text(&custody["data"]["keys"]["1"], "public_key")?;
    stage = ProvisionStage::RoleCreate;
    request(&bao, Method::POST, &format!("{name}/roles/localhost"), Some(&identity.role_body()), Some(root)).await.map_err(|_| REFUSED)?;
    stage = ProvisionStage::CsrCreate;
    let csr = request(
        &bao,
        Method::POST,
        &format!("transit/keys/{name}/csr"),
        Some(&json!({"version":1})),
        Some(root),
    )
    .await
    .map_err(|_| REFUSED)?;
    stage = ProvisionStage::CertificateIssue;
    let leaf = request(&bao, Method::POST, &format!("{name}/sign/localhost"), Some(&identity.signing_request(text(&csr["data"],"csr")?)), Some(root)).await.map_err(|_| REFUSED)?;
    stage = ProvisionStage::CertificateValidation;
    require(leaf["data"].get("private_key").is_none())?;
    let leaf_pem = text(&leaf["data"], "certificate")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| REFUSED)?
        .as_secs();
    let (ca_expiry, leaf_expiry) = check_certificates_for(ca_pem, leaf_pem, public, &name, now, &identity)?;
    stage = ProvisionStage::PolicyCreate;
    let policy = signer_policy(&name)?;
    request(
        &bao,
        Method::PUT,
        &format!("sys/policies/acl/{name}"),
        Some(&json!({"policy":policy})),
        Some(root),
    )
    .await
    .map_err(|_| REFUSED)?;
    stage = ProvisionStage::PolicyReadback;
    let readback = request(
        &bao,
        Method::GET,
        &format!("sys/policies/acl/{name}"),
        None,
        Some(root),
    )
    .await
    .map_err(|_| REFUSED)?;
    stage = ProvisionStage::PolicyEquality;
    require(text(&readback["data"], "policy")? == policy)?;
    stage = ProvisionStage::TokenCreate;
    let issued = request(&bao, Method::POST, "auth/token/create-orphan", Some(&json!({"policies":[name],"no_default_policy":true,"renewable":false,"ttl":"8h","explicit_max_ttl":"8h"})), Some(root)).await.map_err(|_| REFUSED)?;
    stage = ProvisionStage::TokenResponse;
    let token = text(&issued["auth"], "client_token")?;
    require(
        (20..=2048).contains(&token.len())
            && token.is_ascii()
            && token != root
            && !token
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control()),
    )?;
    stage = ProvisionStage::TokenLookup;
    let lookup = request(
        &bao,
        Method::POST,
        "auth/token/lookup",
        Some(&json!({"token":token})),
        Some(root),
    )
    .await
    .map_err(|_| REFUSED)?;
    stage = ProvisionStage::TokenValidation;
    let token_ttl = check_token(&lookup["data"], &name)?;
    let token_observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| REFUSED)?
        .as_secs();
    stage = ProvisionStage::SignerRead;
    let leaf_custody = request(
        &bao,
        Method::GET,
        &format!("transit/keys/{name}"),
        None,
        Some(token),
    )
    .await
    .map_err(|_| REFUSED)?;
    stage = ProvisionStage::SignerValidation;
    version_one_custody(&leaf_custody["data"], "ecdsa-p256").map_err(|_| REFUSED)?;
    require(text(&leaf_custody["data"]["keys"]["1"], "public_key")? == public)?;
    stage = ProvisionStage::SignerSign;
    let signed = request(
        &bao,
        Method::POST,
        &format!("transit/sign/{name}"),
        Some(&sign_body()),
        Some(token),
    )
    .await
    .map_err(|_| REFUSED)?;
    stage = ProvisionStage::SignatureProof;
    verify_signing_proof(public, text(&signed["data"], "signature")?)?;
    for (operation, method, path) in [
        (ProvisionStage::DenyForeignSign, Method::POST, "transit/sign/workload-tls-auth-server".into()),
        (ProvisionStage::DenyExport, Method::GET, format!("transit/export/signing-key/{name}")),
        (ProvisionStage::DenyBackup, Method::GET, format!("transit/backup/{name}")),
        (ProvisionStage::DenyRotation, Method::POST, format!("transit/keys/{name}/rotate")),
        (ProvisionStage::DenyCaMutation, Method::POST, format!("{name}/root/generate/internal")),
        (ProvisionStage::DenyTokenMint, Method::POST, "auth/token/create".into()),
    ] {
        stage = operation;
        denial(&bao, token, method, &path, Some(sign_body()))
            .await
            .map_err(|_| REFUSED)?;
    }
    for (operation, wrong) in [(ProvisionStage::DenyWrongVersion, Some(json!("2"))), (ProvisionStage::DenyNumericVersion, Some(json!(1))), (ProvisionStage::DenyMissingVersion, None)] {
        stage = operation;
        let mut body = sign_body();
        match wrong {
            Some(value) => body["key_version"] = value,
            None => {
                body.as_object_mut().unwrap().remove("key_version");
            }
        }
        denial(
            &bao,
            token,
            Method::POST,
            &format!("transit/sign/{name}"),
            Some(body),
        )
        .await
        .map_err(|_| REFUSED)?;
    }
    stage = ProvisionStage::Metadata;
    let ca_der = certificate(ca_pem)?.to_der().map_err(|_| REFUSED)?;
    let leaf_der = certificate(leaf_pem)?.to_der().map_err(|_| REFUSED)?;
    let metadata = serde_json::to_vec(&json!({"schema":"elevenid.installer-ingress/v2","installation_id":installation_id,
        "key_name":name,"key_version":1,"pki_mount":name,"dns_names":identity.dns_names(),"ip_addresses":identity.ip_addresses(),
        "ca_der_sha256":format!("{:x}",Sha256::digest(&ca_der)),"certificate_der_sha256":format!("{:x}",Sha256::digest(&leaf_der)),
        "ca_pem_sha256":format!("{:x}",Sha256::digest(ca_pem.as_bytes())),"certificate_pem_sha256":format!("{:x}",Sha256::digest(leaf_pem.as_bytes())),
        "ca_expires_at":ca_expiry,"certificate_expires_at":leaf_expiry,"token_ttl_seconds":token_ttl,"token_observed_at":token_observed_at,
        "trust_installed":false,"installation_ready":false})).map_err(|_| REFUSED)?;
    for (operation, filename, bytes) in [
        (ProvisionStage::WriteCa, OUTPUTS[0], ca_pem.as_bytes()),
        (ProvisionStage::WriteCertificate, OUTPUTS[1], leaf_pem.as_bytes()),
        (ProvisionStage::WriteToken, OUTPUTS[2], token.as_bytes()),
        (ProvisionStage::WriteMetadata, OUTPUTS[3], metadata.as_slice()),
    ] {
        stage = operation;
        write_output(&output, filename, bytes, root)?;
    }
    Ok(OUTPUTS.len())
    }.await;
    stage_result(stage, result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    const ID: &str = "12345678-1234-4234-8234-123456789abc";
    #[test]
    fn resource_and_policy_names_cannot_escape_the_installation_namespace() {
        let name = resource_name(ID).unwrap();
        assert_eq!(name, "installer-ingress-12345678123442348234123456789abc");
        for bad in [
            "",
            "12345678123442348234123456789abc",
            "12345678-1234-1234-8234-123456789abc",
            "../transit",
        ] {
            assert!(resource_name(bad).is_err());
        }
        let policy = signer_policy(&name).unwrap();
        assert_eq!(policy.matches("path \"").count(), 2);
        assert!(policy.contains("\"key_version\" = [\"1\"]"));
        assert!(policy.contains("required_parameters"));
        assert!(!policy.contains('*'));
        assert!(signer_policy("installer-ingress-\"anything").is_err());
        assert_eq!(sign_body()["key_version"], "1");
        assert_eq!(sign_body()["prehashed"], true);
    }
    #[test]
    fn selected_identity_has_exact_canonical_sans_and_no_implicit_loopback() {
        let dns = IngressIdentity::new(Some("marty.example.com"), None).unwrap();
        assert_eq!(dns.dns_names(), ["marty.example.com"]);
        assert!(dns.ip_addresses().is_empty());
        assert_eq!(dns.role_body()["allow_ip_sans"], false);
        assert_eq!(dns.role_body()["allow_subdomains"], false);
        assert_eq!(
            dns.role_body()["allowed_domains"],
            json!(["marty.example.com"])
        );
        for address in ["203.0.113.10", "2001:db8::10"] {
            let ip = IngressIdentity::new(None, Some(address.parse().unwrap())).unwrap();
            assert!(ip.dns_names().is_empty());
            assert_eq!(ip.ip_addresses(), [address]);
            assert_eq!(ip.signing_request("csr")["alt_names"], "");
            assert_eq!(ip.signing_request("csr")["ip_sans"], address);
            assert_eq!(ip.signing_request("csr")["exclude_cn_from_sans"], true);
            assert_eq!(
                IngressIdentity::from_metadata(&[], &[address.into()]).unwrap(),
                ip
            );
        }
        assert_eq!(
            IngressIdentity::new(Some("localhost"), Some("127.0.0.1".parse().unwrap())).unwrap(),
            IngressIdentity::localhost()
        );
        assert!(IngressIdentity::new(
            Some("marty.example.com"),
            Some("203.0.113.10".parse().unwrap())
        )
        .is_err());
        assert!(IngressIdentity::new(None, None).is_err());
        for bad in [
            "marty.example.com:443",
            "*.example.com",
            "example.com/other",
            "user@example.com",
            "EXAMPLE.com",
            "example.com.",
            "203.0.113.10",
            "localhost\n",
        ] {
            assert!(
                IngressIdentity::new(Some(bad), None).is_err(),
                "accepted {bad}"
            );
        }
        assert!(IngressIdentity::from_metadata(&[], &["2001:0db8::10".into()]).is_err());
        assert!(IngressIdentity::from_metadata(
            &["one.example.com".into(), "two.example.com".into()],
            &[]
        )
        .is_err());
    }
    #[test]
    fn token_contract_refuses_extra_authority_renewal_and_unbounded_lifetime() {
        let name = resource_name(ID).unwrap();
        let valid = json!({"policies":[name],"orphan":true,"renewable":false,"explicit_max_ttl":TTL,"ttl":TTL,"path":"auth/token/create-orphan"});
        assert_eq!(check_token(&valid, &name).unwrap(), TTL);
        for (field, value) in [
            ("policies", json!([name, "default"])),
            ("policies", json!(["root"])),
            ("renewable", json!(true)),
            ("orphan", json!(false)),
            ("ttl", json!(TTL + 1)),
            ("ttl", json!(3599)),
            ("explicit_max_ttl", json!(0)),
            ("path", json!("auth/token/create")),
        ] {
            let mut changed = valid.clone();
            changed[field] = value;
            assert!(
                check_token(&changed, &name).is_err(),
                "accepted changed {field}"
            );
        }
    }
    #[test]
    fn real_public_ca_self_signature_is_checked_and_ca_cannot_be_an_ingress_leaf() {
        let pem = include_str!("../../../../tests/fixtures/selfhost_ca_issuer_public.pem");
        let mut cert = certificate(pem).unwrap();
        p256(&cert).unwrap();
        check_self_signature(&cert).unwrap();
        assert!(check_leaf_profile(&cert, &IngressIdentity::localhost()).is_err());
        cert.tbs_certificate.subject = "CN=altered".parse().unwrap();
        cert.tbs_certificate.issuer = cert.tbs_certificate.subject.clone();
        assert!(check_self_signature(&cert).is_err());
        assert!(certificate(&format!("{pem}{pem}")).is_err());
        assert!(
            certificate("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----").is_err()
        );
        assert!(certificate("-----BEGIN PRIVATE KEY-----").is_err());
    }
    #[test]
    fn output_is_exclusive_readonly_and_never_emits_authority_or_private_material() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = fresh_output(root.path()).unwrap();
        let authority = "root-authority-never-exported";
        for bad in [
            authority.as_bytes(),
            b"-----BEGIN PRIVATE KEY-----",
            b"nul\0value",
        ] {
            assert!(write_output(&dir, OUTPUTS[0], bad, authority).is_err());
        }
        assert!(!root.path().join(OUTPUTS[0]).exists());
        write_output(&dir, OUTPUTS[0], b"public-fixture", authority).unwrap();
        assert_eq!(
            std::fs::metadata(root.path().join(OUTPUTS[0]))
                .unwrap()
                .mode()
                & 0o7777,
            0o444
        );
        assert!(write_output(&dir, OUTPUTS[0], b"replacement", authority).is_err());
        assert_eq!(
            std::fs::read(root.path().join(OUTPUTS[0])).unwrap(),
            b"public-fixture"
        );
        assert!(fresh_output(root.path()).is_err());
        symlink(root.path().join(OUTPUTS[0]), root.path().join(OUTPUTS[1])).unwrap();
        assert!(write_output(&dir, OUTPUTS[1], b"replacement", authority).is_err());
    }
    #[test]
    fn input_read_rejects_links_oversize_and_nonordinary_files() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("ca");
        std::fs::write(&path, b"public").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read_input(&path, 64, false).unwrap(), b"public");
        assert!(read_input(&path, 2, false).is_err());
        symlink(&path, root.path().join("alias")).unwrap();
        assert!(read_input(&root.path().join("alias"), 64, false).is_err());
        std::fs::hard_link(&path, root.path().join("hard")).unwrap();
        assert!(read_input(&path, 64, false).is_err());
        let fifo = root.path().join("fifo");
        use std::os::unix::ffi::OsStrExt;
        let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_input(&fifo, 64, false).is_err());
    }
    #[test]
    fn operation_diagnostics_are_closed_and_discard_sensitive_errors() {
        let stages = [
            ProvisionStage::Input,
            ProvisionStage::CaInput,
            ProvisionStage::OutputDirectory,
            ProvisionStage::Connect,
            ProvisionStage::MountInventory,
            ProvisionStage::TransitAbsent,
            ProvisionStage::PolicyAbsent,
            ProvisionStage::MountCreate,
            ProvisionStage::CaCreate,
            ProvisionStage::CaResponse,
            ProvisionStage::TransitCreate,
            ProvisionStage::TransitReadback,
            ProvisionStage::TransitValidation,
            ProvisionStage::RoleCreate,
            ProvisionStage::CsrCreate,
            ProvisionStage::CertificateIssue,
            ProvisionStage::CertificateValidation,
            ProvisionStage::PolicyCreate,
            ProvisionStage::PolicyReadback,
            ProvisionStage::PolicyEquality,
            ProvisionStage::TokenCreate,
            ProvisionStage::TokenResponse,
            ProvisionStage::TokenLookup,
            ProvisionStage::TokenValidation,
            ProvisionStage::SignerRead,
            ProvisionStage::SignerValidation,
            ProvisionStage::SignerSign,
            ProvisionStage::SignatureProof,
            ProvisionStage::DenyForeignSign,
            ProvisionStage::DenyExport,
            ProvisionStage::DenyBackup,
            ProvisionStage::DenyRotation,
            ProvisionStage::DenyCaMutation,
            ProvisionStage::DenyTokenMint,
            ProvisionStage::DenyWrongVersion,
            ProvisionStage::DenyNumericVersion,
            ProvisionStage::DenyMissingVersion,
            ProvisionStage::Metadata,
            ProvisionStage::WriteCa,
            ProvisionStage::WriteCertificate,
            ProvisionStage::WriteToken,
            ProvisionStage::WriteMetadata,
        ];
        let mut labels = BTreeSet::new();
        for stage in stages {
            assert!(labels.insert(stage.label()));
            assert!(stage
                .label()
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'-'));
            let error = stage_result::<(), _>(
                stage,
                Err("backend token=never-emit UUID/dynamic-path secret backend-response-sensitive"),
            )
            .unwrap_err();
            assert_eq!(
                error,
                format!(
                    "Ingress provisioning refused at {}; preserve owned state for recovery",
                    stage.label()
                )
            );
            for forbidden in [
                "never-emit",
                "UUID",
                "dynamic-path",
                "backend-response-sensitive",
            ] {
                assert!(!error.contains(forbidden));
            }
            assert_eq!(stage_result::<_, String>(stage, Ok(4)).unwrap(), 4);
        }
    }
    #[test]
    fn invalid_invocation_reports_only_input_stage() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let error = runtime
            .block_on(provision("secret-invalid-installation-id"))
            .unwrap_err();
        assert_eq!(
            error,
            "Ingress provisioning refused at input; preserve owned state for recovery"
        );
        assert!(!error.contains("secret-invalid"));
    }
}
