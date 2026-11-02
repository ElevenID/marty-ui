use super::*;
use x509_cert::ext::Extension;

const OWNER: &str = "b0aef1cc-14a3-4474-9b35-6d710eb6b516";
const PUBLIC_ROOT: &[u8] =
    include_bytes!("../../../../tests/fixtures/selfhost_ca_issuer_public.pem");
const OBSERVED: u64 = 1_800_000_000;

fn identity(ip: Option<&str>) -> CertificateIdentity {
    CertificateIdentity::from_ingress(
        &IngressIdentity::new(Some("login.example.com"), ip.map(|ip| ip.parse().unwrap())).unwrap(),
    )
    .unwrap()
}
fn key() -> RetainedIngressKey {
    let certificate = Certificate::from_pem(PUBLIC_ROOT).unwrap();
    let public = certificate.tbs_certificate.subject_public_key_info;
    let metadata = key_metadata(&public);
    RetainedIngressKey::bind(OWNER, 1, &public.to_der().unwrap(), &metadata).unwrap()
}
fn key_metadata(public: &SubjectPublicKeyInfoOwned) -> Value {
    json!({"name":crate::installer_ingress_provision::resource_name(OWNER).unwrap(),
        "type":"ecdsa-p256","derived":false,"imported_key":false,"exportable":false,
        "allow_plaintext_backup":false,"supports_signing":true,"latest_version":1,
        "keys":{"1":{"public_key":public.to_pem(LineEnding::LF).unwrap()}}})
}
fn extension<T: AsExtension>(value: T, subject: &Name) -> Extension {
    value.to_extension(subject, &[]).unwrap()
}
fn fake_leaf(identity: &CertificateIdentity, key: &RetainedIngressKey) -> Certificate {
    // Reuse only a checked-in public certificate as an ASN.1 envelope. Its
    // altered signature is intentionally invalid: positive chain verification
    // is covered by the official-Bao integration below, with no local leaf key.
    let mut cert = Certificate::from_pem(PUBLIC_ROOT).unwrap();
    let tbs = &mut cert.tbs_certificate;
    tbs.subject = identity.subject().unwrap();
    tbs.subject_public_key_info = SubjectPublicKeyInfoOwned::from_der(&key.spki).unwrap();
    tbs.validity.not_before = (UNIX_EPOCH + Duration::from_secs(OBSERVED - 60))
        .try_into()
        .unwrap();
    tbs.validity.not_after = (UNIX_EPOCH + Duration::from_secs(OBSERVED + 8 * 3600))
        .try_into()
        .unwrap();
    tbs.extensions = Some(vec![
        extension(
            BasicConstraints {
                ca: false,
                path_len_constraint: None,
            },
            &tbs.subject,
        ),
        extension(KeyUsage(KeyUsages::DigitalSignature.into()), &tbs.subject),
        extension(ExtendedKeyUsage(vec![SERVER_AUTH]), &tbs.subject),
        extension(identity.sans().unwrap(), &tbs.subject),
    ]);
    cert
}
fn replace<T: AsExtension>(cert: &mut Certificate, value: T) {
    let replacement = extension(value, &cert.tbs_certificate.subject);
    let old = cert
        .tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|old| old.extn_id == replacement.extn_id)
        .unwrap();
    *old = replacement;
}

#[test]
fn retained_key_requires_recorded_spki_fixed_version_and_nonexportable_custody() {
    let held = key();
    let public = SubjectPublicKeyInfoOwned::from_der(&held.spki).unwrap();
    let metadata = key_metadata(&public);
    for (field, wrong) in [
        ("type", json!("ecdsa-p384")),
        ("exportable", json!(true)),
        ("allow_plaintext_backup", json!(true)),
        ("derived", json!(true)),
        ("imported_key", json!(true)),
        ("supports_signing", json!(false)),
        ("latest_version", json!(2)),
        ("name", json!("foreign")),
    ] {
        let mut bad = metadata.clone();
        bad[field] = wrong;
        assert!(held.require_metadata(&bad).is_err(), "{field}");
    }
    let mut extra = metadata.clone();
    extra["keys"]["2"] = extra["keys"]["1"].clone();
    assert!(held.require_metadata(&extra).is_err());
    assert!(RetainedIngressKey::bind(OWNER, 2, &held.spki, &metadata).is_err());
    let mut other = held.spki.clone();
    *other.last_mut().unwrap() ^= 1;
    assert!(RetainedIngressKey::bind(OWNER, 1, &other, &metadata).is_err());
    assert!(RetainedIngressKey::bind("not-an-installation", 1, &held.spki, &metadata).is_err());
    assert_eq!(held.key_version(), 1);
}

#[test]
fn external_identity_requires_canonical_dns_and_one_explicit_ip() {
    for ip in [None, Some("198.51.100.7"), Some("2001:db8::7")] {
        let value = identity(ip);
        assert_eq!(value.dns_name(), "login.example.com");
        assert_eq!(value.ip_address(), ip.map(|value| value.parse().unwrap()));
    }
    assert!(CertificateIdentity::from_ingress(&IngressIdentity::localhost()).is_err());
    assert!(CertificateIdentity::from_ingress(
        &IngressIdentity::new(None, Some("198.51.100.7".parse().unwrap())).unwrap()
    )
    .is_err());
    assert!(CertificateIdentity::from_ingress(
        &IngressIdentity::new(Some("single-label"), None).unwrap()
    )
    .is_err());
}

#[test]
fn template_contains_exact_sans_and_no_locally_created_signature() {
    let key = key();
    for ip in [None, Some("198.51.100.7"), Some("2001:db8::7")] {
        let identity = identity(ip);
        let template = csr_template(&identity, &key).unwrap();
        let csr = CertReq::from_pem(template.as_bytes()).unwrap();
        check_request_info(&csr, &identity, &key).unwrap();
        assert_eq!(csr.signature.as_bytes(), Some(&[][..]));
        assert!(validate_signed_csr(template.as_bytes(), &identity, &key).is_err());
        assert!(!template.contains("PRIVATE KEY"));
        assert_eq!(
            key.csr_request(&identity).unwrap(),
            json!({"version":"1","csr":template})
        );
    }
}

#[test]
fn csr_identity_rejects_duplicate_foreign_wildcard_and_non_dns_ip_sans() {
    let key = key();
    let identity = identity(Some("198.51.100.7"));
    let good = CertReq::from_pem(csr_template(&identity, &key).unwrap().as_bytes()).unwrap();
    check_request_info(&good, &identity, &key).unwrap();
    for names in [
        vec![GeneralName::DnsName(
            Ia5String::new("foreign.example.com").unwrap(),
        )],
        vec![GeneralName::DnsName(
            Ia5String::new("*.example.com").unwrap(),
        )],
        vec![GeneralName::DnsName(Ia5String::new("login.example.com").unwrap()); 2],
        vec![
            GeneralName::DnsName(Ia5String::new("login.example.com").unwrap()),
            GeneralName::Rfc822Name(Ia5String::new("admin@example.com").unwrap()),
        ],
        vec![
            GeneralName::DnsName(Ia5String::new("login.example.com").unwrap()),
            GeneralName::UniformResourceIdentifier(
                Ia5String::new("spiffe://login.example.com").unwrap(),
            ),
        ],
        vec![
            GeneralName::DnsName(Ia5String::new("login.example.com").unwrap()),
            GeneralName::IpAddress(OctetString::new(vec![198, 51, 100, 8]).unwrap()),
        ],
    ] {
        let mut csr = good.clone();
        let san = SubjectAltName(names)
            .to_extension(&csr.info.subject, &[])
            .unwrap();
        csr.info.attributes =
            SetOfVec::try_from(vec![ExtensionReq(vec![san]).try_into().unwrap()]).unwrap();
        assert!(check_request_info(&csr, &identity, &key).is_err());
    }
    let mut foreign = good.clone();
    foreign.info.subject = Name::from_str("CN=foreign.example.com").unwrap();
    assert!(check_request_info(&foreign, &identity, &key).is_err());
    let mut unbounded = good;
    unbounded.info.attributes = Attributes::default();
    assert!(check_request_info(&unbounded, &identity, &key).is_err());
}

#[test]
fn leaf_profile_binds_key_names_and_server_only_usage() {
    let key = key();
    let identity = identity(Some("198.51.100.7"));
    let good = fake_leaf(&identity, &key);
    let now = Duration::from_secs(OBSERVED);
    check_leaf(&good, &identity, &key, now).unwrap();
    let mut invalid = Vec::new();
    let mut cert = good.clone();
    replace(
        &mut cert,
        BasicConstraints {
            ca: true,
            path_len_constraint: None,
        },
    );
    invalid.push(cert);
    let mut cert = good.clone();
    replace(
        &mut cert,
        BasicConstraints {
            ca: false,
            path_len_constraint: Some(0),
        },
    );
    invalid.push(cert);
    let mut cert = good.clone();
    replace(
        &mut cert,
        KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyCertSign),
    );
    invalid.push(cert);
    let mut cert = good.clone();
    replace(
        &mut cert,
        ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2")]),
    );
    invalid.push(cert);
    let mut cert = good.clone();
    replace(&mut cert, self::identity(None).sans().unwrap());
    invalid.push(cert);
    let mut cert = good.clone();
    cert.tbs_certificate.subject = Name::from_str("CN=foreign.example.com").unwrap();
    invalid.push(cert);
    let mut cert = good.clone();
    let duplicate = cert.tbs_certificate.extensions.as_ref().unwrap()[0].clone();
    cert.tbs_certificate
        .extensions
        .as_mut()
        .unwrap()
        .push(duplicate);
    invalid.push(cert);
    for cert in invalid {
        assert!(check_leaf(&cert, &identity, &key, now).is_err());
    }
    let mut wrong_key = key.clone();
    *wrong_key.spki.last_mut().unwrap() ^= 1;
    assert!(check_leaf(&good, &identity, &wrong_key, now).is_err());
    // A CSR subject may be omitted by an external DV profile; SAN remains exact.
    let mut no_cn = good;
    no_cn.tbs_certificate.subject = Name::default();
    assert!(check_leaf(&no_cn, &identity, &key, now).is_err());
    replace(&mut no_cn, identity.sans().unwrap());
    // Let's Encrypt shortlived omits the subject, marks SAN critical and has
    // 160-hour validity. No CRL/OCSP or subject-key-ID field is required here.
    no_cn.tbs_certificate.validity.not_after = (UNIX_EPOCH
        + no_cn.tbs_certificate.validity.not_before.to_unix_duration()
        + Duration::from_secs(160 * 3600))
    .try_into()
    .unwrap();
    check_leaf(&no_cn, &identity, &key, now).unwrap();
}

#[test]
fn leaf_lifetime_requires_current_validity_and_usable_remaining_window() {
    let key = key();
    let identity = identity(None);
    let good = fake_leaf(&identity, &key);
    let now = Duration::from_secs(OBSERVED);
    for (before, after) in [
        (OBSERVED + 1, OBSERVED + 7200),
        (OBSERVED - 7200, OBSERVED),
        (OBSERVED - 60, OBSERVED + 3599),
        (OBSERVED - 60, OBSERVED + MAXIMUM_VALIDITY.as_secs()),
    ] {
        let mut bad = good.clone();
        bad.tbs_certificate.validity.not_before = (UNIX_EPOCH + Duration::from_secs(before))
            .try_into()
            .unwrap();
        bad.tbs_certificate.validity.not_after = (UNIX_EPOCH + Duration::from_secs(after))
            .try_into()
            .unwrap();
        assert!(check_leaf(&bad, &identity, &key, now).is_err());
    }
    let mut boundary = good;
    boundary.tbs_certificate.validity.not_after =
        (UNIX_EPOCH + now + MINIMUM_REMAINING).try_into().unwrap();
    check_leaf(&boundary, &identity, &key, now).unwrap();
    assert!(check_leaf(&boundary, &identity, &key, now + Duration::from_nanos(1)).is_err());
}

#[test]
fn certificate_input_is_closed_bounded_and_never_treats_returned_roots_as_trust() {
    assert_eq!(parse_chain(PUBLIC_ROOT).unwrap().len(), 1);
    for bytes in [
        b"".to_vec(),
        [b"garbage".as_slice(), PUBLIC_ROOT].concat(),
        [PUBLIC_ROOT, b"trailing"].concat(),
        [PUBLIC_ROOT, PUBLIC_ROOT].concat(),
        [
            PUBLIC_ROOT,
            b"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
        ]
        .concat(),
        vec![b' '; MAX_PEM_BYTES + 1],
    ] {
        assert!(parse_chain(&bytes).is_err());
    }
    let key = key();
    let identity = identity(None);
    let leaf = fake_leaf(&identity, &key);
    // Names and dates alone cannot admit the public ASN.1 test envelope: its
    // signature no longer covers the modified TBS, even with explicit root trust.
    let pem = leaf.to_pem(LineEnding::LF).unwrap();
    assert!(admit_at(
        pem.as_bytes(),
        &identity,
        &key,
        TrustSelection::StagingTest(PUBLIC_ROOT),
        Duration::from_secs(OBSERVED)
    )
    .is_err());
    assert!(admit_at(
        [pem.as_bytes(), PUBLIC_ROOT].concat().as_slice(),
        &identity,
        &key,
        TrustSelection::Production,
        Duration::from_secs(OBSERVED)
    )
    .is_err());
}

struct Server {
    child: std::process::Child,
    files: tempfile::TempDir,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
async fn server() -> (Server, marty_openbao_http::OpenBaoHttp, String) {
    use std::{
        net::TcpListener,
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
        time::Instant,
    };
    let executable = std::env::var("MARTY_TEST_OPENBAO_EXECUTABLE")
        .expect("set MARTY_TEST_OPENBAO_EXECUTABLE to the official OpenBao 2.5.5 binary");
    let files = tempfile::tempdir().unwrap();
    std::fs::set_permissions(files.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let root = format!("test-only-{}", uuid::Uuid::new_v4());
    let child = Command::new(executable)
        .args(["server", "-dev", "-dev-tls", "-dev-no-store-token"])
        .arg(format!("-dev-listen-address={address}"))
        .arg(format!("-dev-tls-cert-dir={}", files.path().display()))
        .env("BAO_DEV_ROOT_TOKEN_ID", &root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut server = Server { child, files };
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        assert!(
            server.child.try_wait().unwrap().is_none(),
            "OpenBao test server exited"
        );
        assert!(
            Instant::now() < deadline,
            "OpenBao test server did not start"
        );
        if let Ok(bao) = marty_openbao_http::OpenBaoHttp::connect(
            &format!("https://{address}"),
            Some(&server.files.path().join("vault-ca.pem")),
            Duration::from_secs(5),
        ) {
            if crate::operator_http::request(&bao, reqwest::Method::GET, "sys/health", None, None)
                .await
                .is_ok()
            {
                return (server, bao, root);
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
#[ignore = "requires official local OpenBao 2.5.5; no live ACME CA or cloud resources"]
async fn official_openbao_signs_exact_public_template_and_chain_admission_keeps_staging_separate() {
    use crate::operator_http::request;
    use reqwest::Method;
    let (_server, bao, token) = server().await;
    for (mount, kind) in [
        ("transit", "transit"),
        ("acme-root", "pki"),
        ("acme-issuer", "pki"),
    ] {
        request(
            &bao,
            Method::POST,
            &format!("sys/mounts/{mount}"),
            Some(&json!({"type":kind,"config":{"max_lease_ttl":"48h"}})),
            Some(&token),
        )
        .await
        .unwrap();
    }
    let name = crate::installer_ingress_provision::resource_name(OWNER).unwrap();
    request(
        &bao,
        Method::POST,
        &format!("transit/keys/{name}"),
        Some(&json!({"type":"ecdsa-p256","exportable":false,"allow_plaintext_backup":false})),
        Some(&token),
    )
    .await
    .unwrap();
    let metadata = request(
        &bao,
        Method::GET,
        &format!("transit/keys/{name}"),
        None,
        Some(&token),
    )
    .await
    .unwrap();
    let spki = operator::public_spki(
        metadata["data"]["keys"]["1"]["public_key"]
            .as_str()
            .unwrap()
            .as_bytes(),
        false,
    )
    .unwrap();
    let key = RetainedIngressKey::bind(OWNER, 1, &spki, &metadata["data"]).unwrap();
    let root = request(&bao, Method::POST, "acme-root/root/generate/internal", Some(&json!({"common_name":"Marty ACME isolated test root","ttl":"48h","key_type":"ec","key_bits":256})), Some(&token)).await.unwrap();
    let root_pem = root["data"]["certificate"].as_str().unwrap();
    let intermediate = request(&bao, Method::POST, "acme-issuer/intermediate/generate/internal", Some(&json!({"common_name":"Marty ACME isolated test intermediate","key_type":"ec","key_bits":256})), Some(&token)).await.unwrap();
    let signed = request(&bao, Method::POST, "acme-root/root/sign-intermediate", Some(&json!({"csr":intermediate["data"]["csr"],"common_name":"Marty ACME isolated test intermediate","ttl":"24h","max_path_length":0,"use_csr_values":true})), Some(&token)).await.unwrap();
    let intermediate_pem = signed["data"]["certificate"].as_str().unwrap();
    request(
        &bao,
        Method::POST,
        "acme-issuer/intermediate/set-signed",
        Some(&json!({"certificate":format!("{intermediate_pem}\n{root_pem}")})),
        Some(&token),
    )
    .await
    .unwrap();
    request(&bao, Method::POST, "acme-issuer/roles/ingress", Some(&json!({"allowed_domains":["login.example.com"],"allow_bare_domains":true,"allow_subdomains":false,"allow_ip_sans":true,
        "server_flag":true,"client_flag":false,"max_ttl":"8h","key_type":"ec","key_bits":256,
        "basic_constraints_valid_for_non_ca":true,
        "key_usage":["DigitalSignature"],"ext_key_usage":["ServerAuth"],"use_csr_common_name":true,"use_csr_sans":true})), Some(&token)).await.unwrap();
    for address in [None, Some("198.51.100.7"), Some("2001:db8::7")] {
        let identity = identity(address);
        let unsigned = csr_template(&identity, &key).unwrap();
        assert!(validate_signed_csr(unsigned.as_bytes(), &identity, &key).is_err());
        let response = request(
            &bao,
            Method::POST,
            &format!("transit/keys/{name}/csr"),
            Some(&key.csr_request(&identity).unwrap()),
            Some(&token),
        )
        .await
        .unwrap();
        assert_eq!(response["data"]["name"], name);
        assert_eq!(response["data"]["type"], "ecdsa-p256");
        let csr = validate_signed_csr(
            response["data"]["csr"].as_str().unwrap().as_bytes(),
            &identity,
            &key,
        )
        .unwrap();
        assert_eq!(csr.metadata()["csr_signature_verified"], true);
        assert_eq!(
            csr.metadata()["csr_der_sha256"],
            installer_release::sha256(csr.der())
        );
        let parsed = CertReq::from_der(csr.der()).unwrap();
        assert_eq!(parsed.info.public_key.to_der().unwrap(), spki);
        let leaf = request(
            &bao,
            Method::POST,
            "acme-issuer/sign/ingress",
            Some(&json!({"csr":csr.pem(),"ttl":"8h"})),
            Some(&token),
        )
        .await
        .unwrap();
        let leaf_pem = leaf["data"]["certificate"].as_str().unwrap();
        let chain = format!("{leaf_pem}\n{intermediate_pem}");
        let public_leaf = Certificate::from_pem(leaf_pem.as_bytes()).unwrap();
        check_leaf(&public_leaf, &identity, &key, now().unwrap())
            .expect("the official-Bao fixture must issue the admitted non-CA server profile");
        let accepted =
            admit_staging_test(chain.as_bytes(), root_pem.as_bytes(), &identity, &key).unwrap();
        assert_eq!(accepted.metadata()["trust_class"], "staging_test");
        assert_eq!(accepted.metadata()["public_chain_validated"], false);
        assert_eq!(accepted.metadata()["activation_performed"], false);
        assert_eq!(accepted.metadata()["installation_ready"], false);
        assert_eq!(accepted.metadata()["intermediate_count"], 1);
        assert_eq!(
            parse_chain(accepted.fullchain_pem().as_bytes())
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            parse_chain(accepted.leaf_pem().as_bytes()).unwrap().len(),
            1
        );
        assert!(admit_production(chain.as_bytes(), &identity, &key).is_err());
        assert!(admit_staging_test(chain.as_bytes(), PUBLIC_ROOT, &identity, &key).is_err());
        assert!(
            admit_staging_test(leaf_pem.as_bytes(), root_pem.as_bytes(), &identity, &key).is_err()
        );
        assert!(admit_staging_test(
            format!("{chain}\n{intermediate_pem}").as_bytes(),
            root_pem.as_bytes(),
            &identity,
            &key
        )
        .is_err());
        assert!(admit_staging_test(
            format!("{intermediate_pem}\n{leaf_pem}").as_bytes(),
            root_pem.as_bytes(),
            &identity,
            &key
        )
        .is_err());
        assert!(admit_staging_test(
            format!("{chain}\n{}", std::str::from_utf8(PUBLIC_ROOT).unwrap()).as_bytes(),
            root_pem.as_bytes(),
            &identity,
            &key
        )
        .is_err());
        let with_root = admit_staging_test(
            format!("{chain}\n{root_pem}").as_bytes(),
            root_pem.as_bytes(),
            &identity,
            &key,
        )
        .unwrap();
        assert_eq!(with_root.fullchain_pem(), accepted.fullchain_pem());
        let mut corrupted = Certificate::from_pem(leaf_pem.as_bytes()).unwrap();
        let mut signature = corrupted.signature.as_bytes().unwrap().to_vec();
        *signature.last_mut().unwrap() ^= 1;
        corrupted.signature = BitString::from_bytes(&signature).unwrap();
        assert!(admit_staging_test(
            format!(
                "{}\n{intermediate_pem}",
                corrupted.to_pem(LineEnding::LF).unwrap()
            )
            .as_bytes(),
            root_pem.as_bytes(),
            &identity,
            &key
        )
        .is_err());
    }
    let after = request(
        &bao,
        Method::GET,
        &format!("transit/keys/{name}"),
        None,
        Some(&token),
    )
    .await
    .unwrap();
    key.require_metadata(&after["data"]).unwrap();
    // Rotation in this disposable fixture proves that implicit latest cannot
    // silently replace the retained key. The module itself never rotates keys.
    request(
        &bao,
        Method::POST,
        &format!("transit/keys/{name}/rotate"),
        Some(&json!({})),
        Some(&token),
    )
    .await
    .unwrap();
    let rotated = request(
        &bao,
        Method::GET,
        &format!("transit/keys/{name}"),
        None,
        Some(&token),
    )
    .await
    .unwrap();
    assert!(key.require_metadata(&rotated["data"]).is_err());
}
