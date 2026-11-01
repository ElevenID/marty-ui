//! Explicit qualification against an official local OpenBao executable.
//! The process is ephemeral, loopback-only, TLS-verified, and killed on unwind.
use super::*;
use std::{
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Stdio},
    time::Instant,
};

struct Server {
    child: Child,
    _files: tempfile::TempDir,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn server() -> (Server, OpenBaoHttp, String) {
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
    let mut server = Server {
        child,
        _files: files,
    };
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
        if let Ok(bao) = OpenBaoHttp::connect(
            &format!("https://{address}"),
            Some(&server._files.path().join("vault-ca.pem")),
            Duration::from_secs(5),
        ) {
            if request(&bao, Method::GET, "sys/health", None, None)
                .await
                .is_ok()
            {
                return (server, bao, root);
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn seed(
    bao: &OpenBaoHttp,
    root: &str,
    owner: &str,
    identity: &IngressIdentity,
) -> BTreeMap<String, Vec<u8>> {
    let name = resource_name(owner).unwrap();
    for (mount, kind, ttl) in [
        ("transit", "transit", "8h"),
        (name.as_str(), "pki", "8760h"),
    ] {
        request(
            bao,
            Method::POST,
            &format!("sys/mounts/{mount}"),
            Some(&json!({"type":kind,"config":{"max_lease_ttl":ttl}})),
            Some(root),
        )
        .await
        .unwrap();
    }
    let ca = request(bao, Method::POST, &format!("{name}/root/generate/internal"),
        Some(&json!({"common_name":format!("Marty local CA {}",name.strip_prefix("installer-ingress-").unwrap()),
        "ttl":"8760h","key_type":"ec","key_bits":256})), Some(root)).await.unwrap();
    request(
        bao,
        Method::POST,
        &format!("transit/keys/{name}"),
        Some(&json!({"type":"ecdsa-p256","exportable":false,"allow_plaintext_backup":false})),
        Some(root),
    )
    .await
    .unwrap();
    request(
        bao,
        Method::POST,
        &format!("{name}/roles/localhost"),
        Some(&identity.role_body()),
        Some(root),
    )
    .await
    .unwrap();
    let csr = request(
        bao,
        Method::POST,
        &format!("transit/keys/{name}/csr"),
        Some(&json!({"version":1})),
        Some(root),
    )
    .await
    .unwrap();
    let leaf = request(
        bao,
        Method::POST,
        &format!("{name}/sign/localhost"),
        Some(&identity.signing_request(text(&csr["data"], "csr").unwrap())),
        Some(root),
    )
    .await
    .unwrap();
    request(
        bao,
        Method::PUT,
        &format!("sys/policies/acl/{name}"),
        Some(&json!({"policy":signer_policy(&name).unwrap()})),
        Some(root),
    )
    .await
    .unwrap();
    let token = request(bao, Method::POST, "auth/token/create-orphan",
        Some(&json!({"policies":[name],"no_default_policy":true,"renewable":false,"ttl":"8h","explicit_max_ttl":"8h"})), Some(root)).await.unwrap();
    BTreeMap::from([
        (
            OUTPUTS[0].into(),
            text(&ca["data"], "certificate")
                .unwrap()
                .as_bytes()
                .to_vec(),
        ),
        (
            OUTPUTS[1].into(),
            text(&leaf["data"], "certificate")
                .unwrap()
                .as_bytes()
                .to_vec(),
        ),
        (
            OUTPUTS[2].into(),
            text(&token["auth"], "client_token")
                .unwrap()
                .as_bytes()
                .to_vec(),
        ),
    ])
}

async fn rejected_before_bootstrap_mutation(
    bao: &OpenBaoHttp,
    root: &str,
    ingress: &str,
    identity: &IngressIdentity,
    output: &Path,
    names: &[String],
) {
    let mut ambiguous = identity.role_body();
    ambiguous["allowed_domains"] = json!([]);
    request(
        bao,
        Method::POST,
        &format!("{ingress}/roles/localhost"),
        Some(&ambiguous),
        Some(root),
    )
    .await
    .unwrap();
    assert!(crate::approle::bootstrap(
        bao,
        crate::approle::Role::Renewal,
        output,
        &json!({"root_token":root,"names":names}),
    )
    .await
    .is_err());
    assert!(std::fs::read_dir(output).unwrap().next().is_none());
    let auth = request(bao, Method::GET, "sys/auth", None, Some(root))
        .await
        .unwrap();
    assert!(auth["data"].get("selfhost-renew/").is_none());
    for path in [
        "sys/policies/acl/selfhost-kms-renewal",
        "auth/token/roles/selfhost-renew-leaf",
    ] {
        assert_eq!(
            builder(bao, Method::GET, path, None, Some(root))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND,
        );
    }
    request(
        bao,
        Method::POST,
        &format!("{ingress}/roles/localhost"),
        Some(&identity.role_body()),
        Some(root),
    )
    .await
    .unwrap();
}

async fn signing_authority_is_identity_bound(
    bao: &OpenBaoHttp,
    token: &str,
    ingress: &str,
    identity: &IngressIdentity,
    current: &BTreeMap<String, Vec<u8>>,
) {
    let response = request(
        bao,
        Method::POST,
        &format!("transit/keys/{ingress}/csr"),
        Some(&json!({"version":1})),
        Some(token),
    )
    .await
    .unwrap();
    let csr = text(&response["data"], "csr").unwrap();
    let exact = identity.signing_request(csr);
    let path = format!("{ingress}/sign/localhost");
    let mut forbidden = Vec::new();
    for (field, foreign) in [
        ("common_name", "foreign.example.com"),
        ("alt_names", "foreign.example.com"),
        ("ip_sans", "198.51.100.99"),
        ("ip_sans", "2001:db8::99"),
    ] {
        let allowed = exact[field].as_str().unwrap();
        for value in [
            json!(foreign),
            json!([foreign]),
            json!([allowed, foreign]),
            json!(format!("{allowed},{foreign}")),
        ] {
            let mut body = exact.clone();
            body[field] = value;
            forbidden.push((format!("foreign or mixed {field}"), body));
        }
    }
    for field in [
        "csr",
        "common_name",
        "alt_names",
        "ip_sans",
        "exclude_cn_from_sans",
        "ttl",
    ] {
        let mut body = exact.clone();
        body.as_object_mut().unwrap().remove(field);
        forbidden.push((format!("omitted {field}"), body));
    }
    for (field, value) in [
        ("common_name", json!([])),
        ("alt_names", json!([])),
        ("ip_sans", json!([])),
        ("common_name", Value::Null),
        ("alt_names", Value::Null),
        ("ip_sans", Value::Null),
        ("ttl", json!("24h")),
        ("exclude_cn_from_sans", json!(false)),
        ("use_csr_sans", json!(true)),
        ("use_csr_common_name", json!(true)),
        ("uri_sans", json!("spiffe://foreign.example.com/workload")),
        ("other_sans", json!("1.3.6.1.4.1;UTF8:foreign")),
    ] {
        let mut body = exact.clone();
        body[field] = value;
        forbidden.push((format!("changed or extra {field}"), body));
    }
    for (label, body) in forbidden {
        assert_eq!(
            builder(bao, Method::POST, &path, Some(&body), Some(token))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN,
            "{}: {label}",
            identity.common_name(),
        );
    }

    // Public CSR fixture only. Transit replaces its public key with the held
    // nonexportable key and signs it, preserving the adversarial CN/SANs.
    const FOREIGN_CSR: &str = "-----BEGIN CERTIFICATE REQUEST-----\n\
MIIBSDCB8AIBADAeMRwwGgYDVQQDDBNmb3JlaWduLmV4YW1wbGUuY29tMFkwEwYH\n\
KoZIzj0CAQYIKoZIzj0DAQcDQgAEhzk7ejLz7ajRB40q3A0y247/bxDKUGP2hqSD\n\
pnUE6kwDLBaQS34Z+2xn17uThgkmkwJp/hnObyQw1Ghcckc1bKBwMG4GCSqGSIb3\n\
DQEJDjFhMF8wXQYDVR0RBFYwVIITZm9yZWlnbi5leGFtcGxlLmNvbYcExjNkY4cQ\n\
IAENuAAAAAAAAAAAAAAAmYYlc3BpZmZlOi8vZm9yZWlnbi5leGFtcGxlLmNvbS93\n\
b3JrbG9hZDAKBggqhkjOPQQDAgNHADBEAiBKIHDZv7Myse/05YsTOyNYkGuVQ8OT\n\
uKczy8VIhZgLYwIgRWdF3TPRWPE0PUO1pMuQ0qddo191mpfl4L+hNti8v6o=\n\
-----END CERTIFICATE REQUEST-----\n";
    let response = request(
        bao,
        Method::POST,
        &format!("transit/keys/{ingress}/csr"),
        Some(&json!({"version":1,"csr":FOREIGN_CSR})),
        Some(token),
    )
    .await
    .unwrap();
    let templated = text(&response["data"], "csr").unwrap();
    let parsed = x509_cert::request::CertReq::from_pem(templated.as_bytes()).unwrap();
    assert_eq!(parsed.info.subject.to_string(), "CN=foreign.example.com");
    let attribute = parsed
        .info
        .attributes
        .iter()
        .find(|a| a.oid.to_string() == "1.2.840.113549.1.9.14")
        .unwrap();
    let extensions = x509_cert::request::ExtensionReq::from_der(
        &attribute.values.iter().next().unwrap().to_der().unwrap(),
    )
    .unwrap();
    let san = extensions
        .0
        .iter()
        .find(|e| e.extn_id.to_string() == "2.5.29.17")
        .unwrap();
    let san = SubjectAltName::from_der(san.extn_value.as_bytes()).unwrap();
    assert_eq!(san.0.len(), 4);
    assert!(san.0.iter().any(
        |name| matches!(name, GeneralName::DnsName(name) if name.as_str()=="foreign.example.com")
    ));
    assert_eq!(
        san.0
            .iter()
            .filter(|name| matches!(name, GeneralName::IpAddress(_)))
            .count(),
        2
    );
    let signed = request(
        bao,
        Method::POST,
        &path,
        Some(&identity.signing_request(templated)),
        Some(token),
    )
    .await
    .unwrap();
    let leaf = certificate(text(&signed["data"], "certificate").unwrap()).unwrap();
    // The exact request succeeds, but every foreign CSR identity is ignored.
    // Explicit attempts to enable CSR identities were denied above.
    check_leaf_profile(&leaf, identity).unwrap();
    assert_eq!(
        leaf.tbs_certificate.subject_public_key_info,
        parsed.info.public_key
    );

    // Like the existing workload renewal profile, this is scoped issuance
    // authority, not a server-side CSR public-key allowlist. A different key
    // can request only the bound identity, but the production custody validator
    // refuses to adopt its certificate instead of the retained Transit key.
    let different_key = request(
        bao,
        Method::POST,
        &path,
        Some(&identity.signing_request(FOREIGN_CSR)),
        Some(token),
    )
    .await
    .unwrap();
    let foreign_leaf = text(&different_key["data"], "certificate").unwrap();
    let foreign = certificate(foreign_leaf).unwrap();
    check_leaf_profile(&foreign, identity).unwrap();
    assert_ne!(
        foreign.tbs_certificate.subject_public_key_info,
        parsed.info.public_key
    );
    let retained = request(
        bao,
        Method::GET,
        &format!("transit/keys/{ingress}"),
        None,
        Some(token),
    )
    .await
    .unwrap();
    let public = text(&retained["data"]["keys"]["1"], "public_key").unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    check_certificates_for(
        input(current, OUTPUTS[0]).unwrap(),
        text(&signed["data"], "certificate").unwrap(),
        public,
        ingress,
        now,
        identity,
    )
    .unwrap();
    assert!(check_certificates_for(
        input(current, OUTPUTS[0]).unwrap(),
        foreign_leaf,
        public,
        ingress,
        now,
        identity,
    )
    .is_err());
}

#[tokio::test]
#[ignore = "explicit local OpenBao 2.5.5 TLS qualification; no Docker or cloud"]
async fn official_openbao_renews_exact_dns_ipv4_ipv6_and_local_identity_without_root() {
    // IPv6 here qualifies only the native certificate primitive. The installer
    // rejects public IPv6 literals until all application identity consumers do.
    for identity in [
        IngressIdentity::new(Some("marty.example.com"), None).unwrap(),
        IngressIdentity::new(
            Some("marty.example.com"),
            Some("203.0.113.10".parse().unwrap()),
        )
        .unwrap(),
        IngressIdentity::new(
            Some("marty.example.com"),
            Some("2001:db8::10".parse().unwrap()),
        )
        .unwrap(),
        IngressIdentity::new(None, Some("203.0.113.10".parse().unwrap())).unwrap(),
        IngressIdentity::new(None, Some("2001:db8::10".parse().unwrap())).unwrap(),
        IngressIdentity::localhost(),
    ] {
        let (_server, bao, root) = server().await;
        let owner = uuid::Uuid::new_v4().to_string();
        let before = seed(&bao, &root, &owner, &identity).await;
        let ingress = renewal_inventory(&bao, &root, &owner, &before, &identity)
            .await
            .unwrap();
        let mut names = (0..21)
            .map(|i| format!("qualification-leaf-{i:02}"))
            .collect::<Vec<_>>();
        names.push(ingress.clone());
        let private = tempfile::tempdir().unwrap();
        std::fs::set_permissions(private.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        rejected_before_bootstrap_mutation(
            &bao,
            &root,
            &ingress,
            &identity,
            private.path(),
            &names,
        )
        .await;
        crate::approle::bootstrap(
            &bao,
            crate::approle::Role::Renewal,
            private.path(),
            &json!({"root_token":root,"names":names}),
        )
        .await
        .unwrap();
        let login = crate::approle::login(
            &bao,
            crate::approle::Role::Renewal,
            private.path(),
            &json!({}),
        )
        .await
        .unwrap();
        let authority = text(&login, "token").unwrap();
        // Neither the old ingress token nor bootstrap root is needed for
        // renewal. Revoke both before exercising the production helper.
        request(
            &bao,
            Method::POST,
            "auth/token/revoke",
            Some(&json!({"token":input(&before,OUTPUTS[2]).unwrap()})),
            Some(&root),
        )
        .await
        .unwrap();
        request(
            &bao,
            Method::POST,
            "auth/token/revoke-self",
            None,
            Some(&root),
        )
        .await
        .unwrap();
        signing_authority_is_identity_bound(&bao, authority, &ingress, &identity, &before).await;
        let renewed = renew(&bao, authority, &owner, &before, &identity)
            .await
            .unwrap();
        assert_eq!(renewed.metadata.dns_names, identity.dns_names());
        assert_eq!(renewed.metadata.ip_addresses, identity.ip_addresses());
        assert_eq!(renewed.files[OUTPUTS[0]], before[OUTPUTS[0]]);
        validate_recorded_replacement(
            &owner,
            &before,
            &renewed.files,
            &renewed.metadata,
            &identity,
        )
        .unwrap();
        for path in [
            format!("transit/keys/{ingress}/rotate"),
            format!("{ingress}/root/generate/internal"),
            "transit/keys/foreign-key/csr".into(),
        ] {
            denial(&bao, authority, Method::POST, &path, Some(json!({})))
                .await
                .unwrap();
        }
        denial(
            &bao,
            authority,
            Method::GET,
            &format!("transit/export/signing-key/{ingress}"),
            None,
        )
        .await
        .unwrap();
        let wrong = IngressIdentity::new(Some("other.example.com"), None).unwrap();
        assert!(renew(&bao, authority, &owner, &renewed.files, &wrong)
            .await
            .is_err());
        // A second login and generation proves the durable AppRole path; the
        // replacement keeps the same nonexportable version-one key and issuer.
        let second = crate::approle::login(
            &bao,
            crate::approle::Role::Renewal,
            private.path(),
            &json!({}),
        )
        .await
        .unwrap();
        let second_token = text(&second, "token").unwrap();
        let next = renew(&bao, second_token, &owner, &renewed.files, &identity)
            .await
            .unwrap();
        assert_ne!(next.files[OUTPUTS[1]], renewed.files[OUTPUTS[1]]);
        assert_ne!(next.files[OUTPUTS[2]], renewed.files[OUTPUTS[2]]);
        for token in [authority, second_token] {
            request(
                &bao,
                Method::POST,
                "auth/token/revoke-self",
                None,
                Some(token),
            )
            .await
            .unwrap();
        }
        let token = input(&next.files, OUTPUTS[2]).unwrap();
        let signed = request(
            &bao,
            Method::POST,
            &format!("transit/sign/{ingress}"),
            Some(&sign_body()),
            Some(token),
        )
        .await
        .unwrap();
        assert!(text(&signed["data"], "signature")
            .unwrap()
            .starts_with("vault:v1:"));
    }
}
