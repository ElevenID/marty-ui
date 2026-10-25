//! Fresh, container-only localhost ingress authority. No existing PKI/Transit
//! resource is adopted or reset; every uncertain mutation requires recovery.
//! Host orchestration must record intent/container before invoking this helper.
#![cfg(target_os = "linux")]
use crate::{
    operator::{public_spki, version_one_custody},
    operator_certificates::{check_chain, check_lifetime},
    operator_http::{builder, denial, request},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use marty_openbao_http::OpenBaoHttp;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use spki::der::{Decode, DecodePem, Encode};
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::{File, OpenOptions},
    io::{Read, Write},
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
pub const OUTPUTS: [&str; 4] = [
    "installer_ingress_ca_cert",
    "installer_ingress_tls_cert",
    "installer_ingress_tls_kms_token",
    "installer-ingress.json",
];
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
path \"transit/sign/{name}\" {{\n  capabilities = [\"update\"]\n  required_parameters = [\"input\", \"prehashed\", \"hash_algorithm\", \"marshaling_algorithm\", \"key_version\"]\n  allowed_parameters = {{\n    \"input\" = []\n    \"prehashed\" = [true]\n    \"hash_algorithm\" = [\"sha2-256\"]\n    \"marshaling_algorithm\" = [\"asn1\"]\n    \"key_version\" = [1]\n  }}\n}}\n"))
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
    let tbs = &cert.tbs_certificate;
    require(tbs.issuer == tbs.subject && tbs.signature == cert.signature_algorithm)?;
    let public_alg = tbs
        .subject_public_key_info
        .algorithm
        .to_der()
        .map_err(|_| REFUSED)?;
    let signature_alg = cert.signature_algorithm.to_der().map_err(|_| REFUSED)?;
    let public_alg = spki::der::asn1::AnyRef::from_der(&public_alg).map_err(|_| REFUSED)?;
    let signature_alg = spki::der::asn1::AnyRef::from_der(&signature_alg).map_err(|_| REFUSED)?;
    let message = tbs.to_der().map_err(|_| REFUSED)?;
    let public = tbs
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
fn check_leaf_profile(cert: &Certificate) -> Result<()> {
    p256(cert)?;
    let tbs = &cert.tbs_certificate;
    require(tbs.subject.to_string() == "CN=localhost")?;
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
    require(san.0.len() == 2)?;
    let mut dns = false;
    let mut ip = false;
    for name in &san.0 {
        match name {
            GeneralName::DnsName(name) if name.as_str() == "localhost" && !dns => dns = true,
            GeneralName::IpAddress(address) if address.as_bytes() == [127, 0, 0, 1] && !ip => {
                ip = true
            }
            _ => return Err(REFUSED.into()),
        }
    }
    require(dns && ip)
}
pub(crate) fn check_certificates(
    ca: &str,
    leaf: &str,
    public: &str,
    name: &str,
    now: u64,
) -> Result<(u64, u64)> {
    let root = certificate(ca)?;
    let cert = certificate(leaf)?;
    p256(&root)?;
    check_self_signature(&root)?;
    check_leaf_profile(&cert)?;
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
        check_lifetime(ca.as_bytes(), TTL).map_err(|_| REFUSED)?
            && check_lifetime(leaf.as_bytes(), 3600).map_err(|_| REFUSED)?,
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
    check_chain(leaf.as_bytes(), ca.as_bytes()).map_err(|_| REFUSED)?;
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
fn sign_body() -> Value {
    json!({"input":STANDARD.encode(Sha256::digest(b"marty-installer-ingress-custody-proof")),
        "prehashed":true,"hash_algorithm":"sha2-256","marshaling_algorithm":"asn1","key_version":1})
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

/// Fixed-path root helper. This is creation only, never renewal or trust import.
/// Returns only a public file count. Never returns or logs raw backend errors.
pub async fn provision(installation_id: &str) -> Result<usize> {
    require(unsafe { libc::geteuid() } == 0)?;
    let name = resource_name(installation_id)?;
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
    read_input(Path::new("/input/ca.crt"), 65536, false)?;
    let output = fresh_output(Path::new("/output"))?;
    let bao = OpenBaoHttp::connect(
        "https://openbao:8200",
        Some(Path::new("/input/ca.crt")),
        Duration::from_secs(10),
    )
    .map_err(|_| REFUSED)?;
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
    absent(&bao, &format!("transit/keys/{name}"), root).await?;
    absent(&bao, &format!("sys/policies/acl/{name}"), root).await?;
    request(
        &bao,
        Method::POST,
        &format!("sys/mounts/{name}"),
        Some(&json!({"type":"pki","config":{"max_lease_ttl":"8760h"}})),
        Some(root),
    )
    .await
    .map_err(|_| REFUSED)?;
    let ca = request(&bao, Method::POST, &format!("{name}/root/generate/internal"), Some(&json!({"common_name":format!("Marty local CA {}", name.strip_prefix("installer-ingress-").ok_or(REFUSED)?),"ttl":"8760h","key_type":"ec","key_bits":256})), Some(root)).await.map_err(|_| REFUSED)?;
    require(ca["data"].get("private_key").is_none())?;
    let ca_pem = text(&ca["data"], "certificate")?;
    request(
        &bao,
        Method::POST,
        &format!("transit/keys/{name}"),
        Some(&json!({"type":"ecdsa-p256","exportable":false,"allow_plaintext_backup":false})),
        Some(root),
    )
    .await
    .map_err(|_| REFUSED)?;
    let custody = request(
        &bao,
        Method::GET,
        &format!("transit/keys/{name}"),
        None,
        Some(root),
    )
    .await
    .map_err(|_| REFUSED)?;
    version_one_custody(&custody["data"], "ecdsa-p256").map_err(|_| REFUSED)?;
    let public = text(&custody["data"]["keys"]["1"], "public_key")?;
    request(&bao, Method::POST, &format!("{name}/roles/localhost"), Some(&json!({"allow_any_name":false,"allow_localhost":true,"allowed_domains":["localhost"],"allow_bare_domains":true,"allow_subdomains":false,"allow_glob_domains":false,"allow_ip_sans":true,"server_flag":true,"client_flag":false,"key_type":"ec","key_bits":256,"max_ttl":"8h","use_csr_common_name":false,"use_csr_sans":false})), Some(root)).await.map_err(|_| REFUSED)?;
    let csr = request(
        &bao,
        Method::POST,
        &format!("transit/keys/{name}/csr"),
        Some(&json!({"version":1})),
        Some(root),
    )
    .await
    .map_err(|_| REFUSED)?;
    let leaf = request(&bao, Method::POST, &format!("{name}/sign/localhost"), Some(&json!({"csr":text(&csr["data"],"csr")?,"common_name":"localhost","alt_names":"localhost","ip_sans":"127.0.0.1","ttl":"8h"})), Some(root)).await.map_err(|_| REFUSED)?;
    require(leaf["data"].get("private_key").is_none())?;
    let leaf_pem = text(&leaf["data"], "certificate")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| REFUSED)?
        .as_secs();
    let (ca_expiry, leaf_expiry) = check_certificates(ca_pem, leaf_pem, public, &name, now)?;
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
    let readback = request(
        &bao,
        Method::GET,
        &format!("sys/policies/acl/{name}"),
        None,
        Some(root),
    )
    .await
    .map_err(|_| REFUSED)?;
    require(text(&readback["data"], "policy")? == policy)?;
    let issued = request(&bao, Method::POST, "auth/token/create-orphan", Some(&json!({"policies":[name],"no_default_policy":true,"renewable":false,"ttl":"8h","explicit_max_ttl":"8h"})), Some(root)).await.map_err(|_| REFUSED)?;
    let token = text(&issued["auth"], "client_token")?;
    require(
        (20..=2048).contains(&token.len())
            && token.is_ascii()
            && token != root
            && !token
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control()),
    )?;
    let lookup = request(
        &bao,
        Method::POST,
        "auth/token/lookup",
        Some(&json!({"token":token})),
        Some(root),
    )
    .await
    .map_err(|_| REFUSED)?;
    let token_ttl = check_token(&lookup["data"], &name)?;
    let token_observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| REFUSED)?
        .as_secs();
    let leaf_custody = request(
        &bao,
        Method::GET,
        &format!("transit/keys/{name}"),
        None,
        Some(token),
    )
    .await
    .map_err(|_| REFUSED)?;
    version_one_custody(&leaf_custody["data"], "ecdsa-p256").map_err(|_| REFUSED)?;
    require(text(&leaf_custody["data"]["keys"]["1"], "public_key")? == public)?;
    let signed = request(
        &bao,
        Method::POST,
        &format!("transit/sign/{name}"),
        Some(&sign_body()),
        Some(token),
    )
    .await
    .map_err(|_| REFUSED)?;
    verify_signing_proof(public, text(&signed["data"], "signature")?)?;
    for (method, path) in [
        (Method::POST, "transit/sign/workload-tls-auth-server".into()),
        (Method::GET, format!("transit/export/signing-key/{name}")),
        (Method::GET, format!("transit/backup/{name}")),
        (Method::POST, format!("transit/keys/{name}/rotate")),
        (Method::POST, format!("{name}/root/generate/internal")),
        (Method::POST, "auth/token/create".into()),
    ] {
        denial(&bao, token, method, &path, Some(sign_body()))
            .await
            .map_err(|_| REFUSED)?;
    }
    for wrong in [Some(json!(2)), None] {
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
    let ca_der = certificate(ca_pem)?.to_der().map_err(|_| REFUSED)?;
    let leaf_der = certificate(leaf_pem)?.to_der().map_err(|_| REFUSED)?;
    let metadata = serde_json::to_vec(&json!({"schema":"elevenid.installer-ingress/v1","installation_id":installation_id,
        "key_name":name,"key_version":1,"pki_mount":name,"dns_names":["localhost"],"ip_addresses":["127.0.0.1"],
        "ca_der_sha256":format!("{:x}",Sha256::digest(&ca_der)),"certificate_der_sha256":format!("{:x}",Sha256::digest(&leaf_der)),
        "ca_pem_sha256":format!("{:x}",Sha256::digest(ca_pem.as_bytes())),"certificate_pem_sha256":format!("{:x}",Sha256::digest(leaf_pem.as_bytes())),
        "ca_expires_at":ca_expiry,"certificate_expires_at":leaf_expiry,"token_ttl_seconds":token_ttl,"token_observed_at":token_observed_at,
        "trust_installed":false,"installation_ready":false})).map_err(|_| REFUSED)?;
    for (filename, bytes) in [
        (OUTPUTS[0], ca_pem.as_bytes()),
        (OUTPUTS[1], leaf_pem.as_bytes()),
        (OUTPUTS[2], token.as_bytes()),
        (OUTPUTS[3], metadata.as_slice()),
    ] {
        write_output(&output, filename, bytes, root)?;
    }
    Ok(OUTPUTS.len())
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
        assert!(policy.contains("\"key_version\" = [1]"));
        assert!(policy.contains("required_parameters"));
        assert!(!policy.contains('*'));
        assert!(signer_policy("installer-ingress-\"anything").is_err());
        assert_eq!(sign_body()["key_version"], 1);
        assert_eq!(sign_body()["prehashed"], true);
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
        assert!(check_leaf_profile(&cert).is_err());
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
}
