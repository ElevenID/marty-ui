use super::*;
use crate::installer_state::Identity;
use serde_json::{json, Value};
use std::{fs as files, os::unix::fs::PermissionsExt};

fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    files::set_permissions(root.path(), files::Permissions::from_mode(0o700)).unwrap();
    root
}

fn write(path: &Path, bytes: &[u8]) {
    files::write(path, bytes).unwrap();
    files::set_permissions(path, files::Permissions::from_mode(0o600)).unwrap();
}

fn direct() -> Value {
    json!({
        "schema": SCHEMA,
        "mode": "direct",
        "public_origin": "https://marty.example.com",
        "listener": {"bind_address": "0.0.0.0", "port": 8443},
        "tls": {"termination": "marty-keyless", "certificate_source": "managed-ca"}
    })
}

fn input(root: &Path, value: &Value) -> PathBuf {
    let path = root.join("hosting.json");
    write(&path, &serde_json::to_vec(value).unwrap());
    path
}

fn state(root: &Path) -> InstallerState {
    let mut state = InstallerState::create(
        &root.join("installation"),
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        },
    )
    .unwrap();
    state.create_private_directory("evidence").unwrap();
    state.advance(Phase::Verified).unwrap();
    state
}

#[test]
fn direct_public_443_uses_an_independent_unprivileged_listener() {
    let root = private_root();
    let path = input(root.path(), &direct());
    let prepared = prepare(Some(&path), None).unwrap();
    assert_eq!(prepared.configuration.listener.port, 8443);
    assert_eq!(
        prepared
            .configuration
            .public_origin
            .as_ref()
            .unwrap()
            .port(),
        443
    );
    let mut state = state(root.path());
    let selection = select(prepared, &mut state).unwrap();
    assert_eq!(selection.mode(), Mode::Direct);
    assert_eq!(
        selection.resolve_origin(8443).unwrap().as_str(),
        "https://marty.example.com"
    );
    assert!(selection.resolve_origin(9443).is_err());
    assert_eq!(selection.certificate_dns_name(), Some("marty.example.com"));
    assert_eq!(selection.certificate_ip_address(), None);
    assert!(!selection.external_tls_owned());
    assert_eq!(state.journal().phase(), Phase::Verified);
    assert_eq!(state.journal().revision(), 1);
    assert!(state.journal().hosting_selection_sha256().is_some());
}

#[test]
fn no_file_and_legacy_journals_keep_loopback_and_managed_openbao() {
    let root = private_root();
    let mut state = state(root.path());
    let legacy = state.with_inspection(resolve).unwrap();
    assert!(!legacy.is_recorded());
    assert_eq!(legacy.mode(), Mode::Local);
    assert_eq!(
        legacy.listener().socket_address().to_string(),
        "127.0.0.1:0"
    );
    assert_eq!(legacy.certificate_dns_name(), Some("localhost"));
    assert_eq!(
        legacy.certificate_ip_address(),
        Some("127.0.0.1".parse().unwrap())
    );
    assert_eq!(legacy.certificate_source(), CertificateSource::ManagedCa);
    assert!(legacy.connector().is_none());
    assert_eq!(
        legacy.resolve_origin(18443).unwrap().as_str(),
        "https://localhost:18443"
    );
    let selected = select(prepare(None, None).unwrap(), &mut state).unwrap();
    assert!(selected.is_recorded());
    assert_eq!(
        state.with_inspection(resolve).unwrap().listener(),
        legacy.listener()
    );
    assert!(select(prepare(None, None).unwrap(), &mut state).is_err());
}

#[test]
fn changed_or_deleted_evidence_cannot_fall_back_to_loopback() {
    for changed in [RECORD, SOURCE] {
        let root = private_root();
        let mut state = state(root.path());
        select(prepare(None, None).unwrap(), &mut state).unwrap();
        let path = root.path().join("installation/evidence").join(changed);
        let raw = files::read(&path).unwrap();
        write(&path, b"{}");
        assert!(state.with_inspection(resolve).is_err());
        write(&path, &raw);
        assert!(state.with_inspection(resolve).is_ok());
        files::remove_file(path).unwrap();
        assert!(state.with_inspection(resolve).is_err());
    }
}

#[test]
fn compose_admission_requires_the_exact_bound_hosting_records_and_project() {
    use std::collections::BTreeSet;
    let root = private_root();
    let mut state = state(root.path());
    let selected = select(prepare(None, None).unwrap(), &mut state).unwrap();
    let installation = root.path().join("installation");
    let mut inputs = ComposeInputs {
        installation: installation.clone(),
        project: state.journal().compose_project(),
        files: Vec::new(),
        bound_inputs: Vec::new(),
        environment: BoundFile {
            path: installation.join("evidence/fixture.env"),
            sha256: "a".repeat(64),
        },
        profiles: Vec::new(),
        services: Vec::new(),
        approved_images: BTreeSet::new(),
        #[cfg(feature = "installer-development")]
        development_image: None,
        writable_bind_roots: BTreeSet::new(),
        readonly_bind_roots: BTreeSet::new(),
        allowed_loopback_ports: BTreeSet::new(),
        ingress_listener: None,
        prior: None,
    };
    assert!(for_inputs(&inputs).is_err());
    selected.bind_inputs(&mut inputs).unwrap();
    assert_eq!(for_inputs(&inputs).unwrap().unwrap().mode(), Mode::Local);
    let original = inputs.bound_inputs[0].sha256.clone();
    inputs.bound_inputs[0].sha256 = "f".repeat(64);
    assert!(for_inputs(&inputs).is_err());
    inputs.bound_inputs[0].sha256 = original;
    inputs.bound_inputs.push(inputs.bound_inputs[0].clone());
    assert!(for_inputs(&inputs).is_err());
    inputs.bound_inputs.pop();
    inputs.project = "foreign-project".into();
    assert!(for_inputs(&inputs).is_err());
}

#[test]
fn addon_journal_binding_requires_verified_hosting_and_cannot_be_replaced() {
    let root = private_root();
    let mut state = state(root.path());
    assert!(state.bind_hosting_addon(&"a".repeat(64)).is_err());
    select(prepare(None, None).unwrap(), &mut state).unwrap();
    state.bind_hosting_addon(&"a".repeat(64)).unwrap();
    assert_eq!(
        state.journal().hosting_addon_sha256(),
        Some("a".repeat(64).as_str())
    );
    assert_eq!(state.journal().phase(), Phase::Verified);
    assert_eq!(state.journal().revision(), 1);
    assert!(state.bind_hosting_addon(&"b".repeat(64)).is_err());
    state.advance(Phase::Provisioning).unwrap();
    assert!(state.bind_hosting_addon(&"a".repeat(64)).is_err());
}

#[test]
fn origin_exposure_tls_and_provider_inputs_are_a_closed_contract() {
    let root = private_root();
    for case in 0..14 {
        let mut value = direct();
        match case {
            0 => value["mode"] = json!("aws"),
            1 => value["public_origin"] = json!("http://marty.example.com"),
            2 => value["public_origin"] = json!("https://marty.example.com/path"),
            3 => value["public_origin"] = json!("https://user@marty.example.com"),
            4 => value["listener"]["port"] = json!(443),
            5 => value["listener"]["bind_address"] = json!("127.0.0.1"),
            6 => value["public_origin"] = json!("https://localhost:8443"),
            7 => value["tls"]["certificate_source"] = json!("supplied-chain"),
            8 => value["tls"]["termination"] = json!("pem-private-key"),
            9 => value["tls"]["private_key_file"] = json!("/private/key.pem"),
            10 => value["listener"]["port"] = json!(0),
            11 => value["forwarded_headers"] = json!("trust-all"),
            12 => {
                value["connector"] =
                    json!({"kind":"cloudflare-tunnel","token_file":"/private/token"})
            }
            13 => value["tls"]["certificate_source"] = json!("foundation-import"),
            _ => unreachable!(),
        }
        let path = input(root.path(), &value);
        assert!(prepare(Some(&path), None).is_err(), "accepted case {case}");
    }
    let path = root.path().join("hosting.json");
    write(
        &path,
        br#"{"schema":"elevenid.installation-hosting/v1","mode":"local","mode":"direct"}"#,
    );
    assert!(prepare(Some(&path), None).is_err());
}

#[test]
fn foundation_import_is_explicit_and_origins_must_agree() {
    let root = private_root();
    let origin = PublicOrigin::parse("https://marty.example.com").unwrap();
    let mut value = direct();
    let path = input(root.path(), &value);
    assert!(prepare(Some(&path), Some(origin.clone())).is_err());
    value["tls"]["certificate_source"] = json!("foundation-import");
    let path = input(root.path(), &value);
    assert!(prepare(Some(&path), Some(origin.clone())).is_ok());
    assert!(prepare(
        Some(&path),
        Some(PublicOrigin::parse("https://other.example.com").unwrap())
    )
    .is_err());
    assert!(prepare(None, Some(origin)).is_err());
    let legacy = prepare(
        None,
        Some(PublicOrigin::parse("https://localhost:18443").unwrap()),
    )
    .unwrap();
    assert_eq!(legacy.configuration.mode, Mode::Local);
    assert_eq!(
        legacy.configuration.tls.certificate_source,
        CertificateSource::FoundationImport
    );
}

#[test]
fn explicit_cloudflare_connector_keeps_token_out_of_evidence_and_binds_its_copy() {
    let root = private_root();
    let token_path = root.path().join("tunnel-token");
    let secret = b"cloudflare-token-test-value-1234567890";
    write(&token_path, secret);
    let mut value = direct();
    value["mode"] = json!("external-proxy");
    value["listener"]["bind_address"] = json!("127.0.0.1");
    value["connector"] = json!({"kind":"cloudflare-tunnel","token_file":token_path});
    let path = input(root.path(), &value);
    let prepared = prepare(Some(&path), None).unwrap();
    let mut state = state(root.path());
    let selection = select(prepared, &mut state).unwrap();
    assert!(selection.external_tls_owned());
    assert_eq!(
        selection.connector().unwrap().kind,
        ConnectorKind::CloudflareTunnel
    );
    for name in [SOURCE, RECORD] {
        let bytes = files::read(root.path().join("installation/evidence").join(name)).unwrap();
        assert!(!bytes.windows(secret.len()).any(|part| part == secret));
    }
    state.advance(Phase::Provisioning).unwrap();
    state.generate_external_auth_credentials().unwrap();
    selection.import_connector(&mut state).unwrap();
    assert_eq!(
        state
            .with_inspection(|view| view.read_secret(CONNECTOR_TOKEN))
            .unwrap(),
        secret
    );
    let copied = files::metadata(
        root.path()
            .join("installation/secrets")
            .join(CONNECTOR_TOKEN),
    )
    .unwrap();
    assert_eq!(copied.permissions().mode() & 0o777, 0o444);
}

#[test]
fn public_ip_identity_has_no_dns_name_and_local_ip_matches_its_listener() {
    let root = private_root();
    let mut value = direct();
    value["public_origin"] = json!("https://203.0.113.10:8443");
    let path = input(root.path(), &value);
    let mut state = state(root.path());
    let selected = select(prepare(Some(&path), None).unwrap(), &mut state).unwrap();
    assert_eq!(selected.certificate_dns_name(), None);
    assert_eq!(
        selected.certificate_ip_address(),
        Some("203.0.113.10".parse().unwrap())
    );
    value["mode"] = json!("local");
    value["public_origin"] = json!("https://127.0.0.1:8443");
    value["listener"]["bind_address"] = json!("::1");
    let path = input(root.path(), &value);
    assert!(prepare(Some(&path), None).is_err());
}

#[test]
fn public_ipv6_literals_are_refused_before_provisioning_in_every_hosting_mode() {
    let root = private_root();
    for (mode, origin, listener) in [
        ("local", "https://[::1]:8443", "::1"),
        ("direct", "https://[2001:db8::10]:8443", "::"),
        ("external-proxy", "https://[2001:db8::10]", "::1"),
    ] {
        let mut value = direct();
        value["mode"] = json!(mode);
        value["public_origin"] = json!(origin);
        value["listener"]["bind_address"] = json!(listener);
        let path = input(root.path(), &value);
        let error = prepare(Some(&path), None)
            .err()
            .expect("IPv6 origin refused");
        assert!(error.contains("public IPv6 literal origins are not supported"));
        assert!(!root.path().join("installation").exists());
    }
    let imported = PublicOrigin::parse("https://[::1]:8443").unwrap();
    assert!(prepare(None, Some(imported))
        .err()
        .unwrap()
        .contains("public IPv6 literal origins are not supported"));
}

#[test]
fn dns_origins_retain_ipv6_listener_support() {
    let root = private_root();
    for (mode, origin, listener) in [
        ("local", "https://localhost:8443", "::1"),
        ("direct", "https://marty.example.com", "::"),
        ("external-proxy", "https://marty.example.com", "::1"),
    ] {
        let mut value = direct();
        value["mode"] = json!(mode);
        value["public_origin"] = json!(origin);
        value["listener"]["bind_address"] = json!(listener);
        let path = input(root.path(), &value);
        let prepared = prepare(Some(&path), None).unwrap();
        assert_eq!(
            prepared.configuration.listener.bind_address.to_string(),
            listener
        );
        assert!(prepared
            .configuration
            .public_origin
            .unwrap()
            .dns_name()
            .is_some());
    }
}
