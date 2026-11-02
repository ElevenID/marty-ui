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

fn acme() -> Value {
    let mut value = direct();
    value["tls"] = json!({"termination":"marty-keyless","certificate_source":"acme",
        "http01_host_port":18080,
        "acme":{"environment":"production","directory_url":"https://acme-v02.api.letsencrypt.org/directory",
        "profile":"shortlived","terms_url":"https://letsencrypt.org/documents/LE-SA-v1.6-August-18-2025.pdf","terms_agreed":true}});
    value
}

#[test]
fn selected_web_sections_are_validated_and_retained_with_hosting_evidence() {
    for (sections, expected) in [
        (json!([]), "none"),
        (json!(["public"]), "public"),
        (json!(["console"]), "console"),
        (json!(["public", "console"]), "public,console"),
        (json!(["console", "public"]), "public,console"),
    ] {
        let root = private_root();
        let mut configuration = direct();
        configuration["web"] = json!({"enabled_sections": sections});
        let mut state = state(root.path());
        let selected = select(
            prepare(Some(&input(root.path(), &configuration)), None).unwrap(),
            &mut state,
        )
        .unwrap();
        assert_eq!(selected.enabled_web_sections(), expected);
        assert!(selected.has_web_selection());
        let retained = state.with_inspection(resolve).unwrap();
        assert_eq!(retained.enabled_web_sections(), expected);
        assert!(retained.has_web_selection());
    }
    let root = private_root();
    let prepared = prepare(Some(&input(root.path(), &direct())), None).unwrap();
    let selected = select(prepared, &mut state(root.path())).unwrap();
    assert_eq!(selected.enabled_web_sections(), "public,console");
    assert!(!selected.has_web_selection());
}

#[test]
fn invalid_web_selection_is_refused_before_recording_or_provisioning() {
    for web in [
        json!({}),
        json!({"enabled_sections": "none"}),
        json!({"enabled_sections": ["marketing"]}),
        json!({"enabled_sections": ["console", "console"]}),
        json!({"enabled_sections": [true]}),
        json!({"enabled_sections": null}),
        json!({"enabled_sections": [], "allow_marketing": true}),
    ] {
        let root = private_root();
        let mut configuration = direct();
        configuration["web"] = web;
        assert!(prepare(Some(&input(root.path(), &configuration)), None).is_err());
    }
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
fn acme_selection_binds_exact_agreement_dns_ip_and_loopback_challenge_port() {
    let root = private_root();
    let mut value = acme();
    value["public_entry_origin"] = json!("https://198.51.100.7:9443");
    let prepared = prepare(Some(&input(root.path(), &value)), None).unwrap();
    let mut state = state(root.path());
    let selected = select(prepared, &mut state).unwrap();
    assert_eq!(selected.certificate_source(), CertificateSource::Acme);
    assert_eq!(selected.http01_host_port(), Some(18080));
    assert_eq!(selected.listener().port, 8443);
    assert_eq!(selected.acme_parameters().unwrap().profile(), "shortlived");
    assert_eq!(selected.certificate_dns_name(), Some("marty.example.com"));
    assert_eq!(
        selected.certificate_ip_address(),
        Some("198.51.100.7".parse().unwrap())
    );
    let binding = state
        .with_inspection(
            crate::installer_acme_configuration::BoundAcmeConfiguration::from_selection,
        )
        .unwrap();
    assert_eq!(binding.parameters(), selected.acme_parameters().unwrap());
    assert_eq!(
        binding.certificate_identity().unwrap().dns_name(),
        "marty.example.com"
    );
    assert!(state.with_inspection(resolve).unwrap().is_recorded());
}

#[test]
fn acme_rejects_missing_agreement_unsupported_modes_and_conflicting_ports() {
    let root = private_root();
    for port in [0, 80, 1023, 8443] {
        let mut value = acme();
        value["tls"]["http01_host_port"] = json!(port);
        assert!(prepare(Some(&input(root.path(), &value)), None).is_err());
    }
    for field in ["acme", "http01_host_port"] {
        let mut value = acme();
        value["tls"].as_object_mut().unwrap().remove(field);
        assert!(prepare(Some(&input(root.path(), &value)), None).is_err());
    }
    for (field, wrong) in [
        ("terms_agreed", json!(false)),
        ("environment", json!("staging")),
        ("profile", json!("classic")),
        ("directory_url", json!("https://foreign.example/directory")),
        ("terms_url", json!("https://foreign.example/terms.pdf")),
        ("accept_all_terms", json!(true)),
    ] {
        let mut value = acme();
        value["tls"]["acme"][field] = wrong;
        assert!(
            prepare(Some(&input(root.path(), &value)), None).is_err(),
            "{field}"
        );
    }
    for mode in ["local", "external-proxy"] {
        let mut value = acme();
        value["mode"] = json!(mode);
        value["listener"]["bind_address"] = json!("127.0.0.1");
        if mode == "local" {
            value["public_origin"] = json!("https://localhost:8443");
        }
        assert!(prepare(Some(&input(root.path(), &value)), None).is_err());
    }
    assert!(prepare(
        Some(&input(root.path(), &acme())),
        Some(PublicOrigin::parse("https://marty.example.com").unwrap())
    )
    .is_err());
    for source in ["managed-ca", "foundation-import"] {
        let mut value = acme();
        value["tls"]["certificate_source"] = json!(source);
        assert!(prepare(Some(&input(root.path(), &value)), None).is_err());
    }
}

#[test]
fn added_acme_fields_preserve_legacy_configuration_serialized_bytes() {
    for source in ["managed-ca", "foundation-import"] {
        let original = format!("{{\"schema\":\"{SCHEMA}\",\"mode\":\"direct\",\"public_origin\":\"https://marty.example.com\",\"listener\":{{\"bind_address\":\"0.0.0.0\",\"port\":8443}},\"tls\":{{\"termination\":\"marty-keyless\",\"certificate_source\":\"{source}\"}}}}");
        let configuration: Configuration = decode(original.as_bytes()).unwrap();
        configuration.validate().unwrap();
        assert_eq!(
            serde_json::to_vec(&configuration).unwrap(),
            original.as_bytes()
        );
        assert!(configuration.tls.acme.is_none());
        assert!(configuration.tls.http01_host_port.is_none());
    }
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
fn compose_public_entry_requires_bound_gateway_and_ui_authorities() {
    use crate::installer_compose::bound_ingress_listener;
    use std::collections::BTreeSet;
    for (alias, web_sections) in [
        (None, None),
        (Some("https://203.0.113.10:8443"), None),
        (None, Some(json!([]))),
        (None, Some(json!(["public"]))),
        (None, Some(json!(["console"]))),
        (
            Some("https://203.0.113.10:8443"),
            Some(json!(["public", "console"])),
        ),
    ] {
        let root = private_root();
        let mut state = state(root.path());
        let mut configuration = direct();
        if let Some(alias) = alias {
            configuration["public_entry_origin"] = json!(alias);
        }
        if let Some(sections) = web_sections {
            configuration["web"] = json!({"enabled_sections": sections});
        }
        let selected = select(
            prepare(Some(&input(root.path(), &configuration)), None).unwrap(),
            &mut state,
        )
        .unwrap();
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
            ingress_listener: Some(selected.listener()),
            prior: None,
        };
        selected.bind_inputs(&mut inputs).unwrap();
        let mut model = json!({"services":{
            "installer-ingress": {
                "ports":[{"target":8443,"published":"8443","host_ip":"0.0.0.0","protocol":"tcp"}],
                "environment": {"OIDF_EDGE_PUBLIC_ORIGIN":"https://marty.example.com", "OIDF_EDGE_PUBLIC_ENTRY_ORIGIN":alias.unwrap_or("")}
            },
            "ui":{"environment":{"UI_CANONICAL_ORIGIN":"https://marty.example.com", "UI_PUBLIC_ENTRY_ORIGINS":serde_json::to_string(&alias.into_iter().collect::<Vec<_>>()).unwrap()}}
        }});
        if selected.has_web_selection() {
            model["services"]["ui"]["environment"]["UI_ENABLED_SECTIONS"] =
                json!(selected.enabled_web_sections());
            let mut missing = model.clone();
            missing["services"]["ui"]["environment"]
                .as_object_mut()
                .unwrap()
                .remove("UI_ENABLED_SECTIONS");
            assert!(bound_ingress_listener(&missing, &inputs).is_err());
        }
        assert_eq!(
            bound_ingress_listener(&model, &inputs).unwrap(),
            selected.listener()
        );
        for (role, field, value) in [
            ("ui", "UI_ENABLED_SECTIONS", json!("marketing")),
            (
                "installer-ingress",
                "OIDF_EDGE_PUBLIC_ENTRY_ORIGIN",
                json!("https://203.0.113.11:8443"),
            ),
            (
                "installer-ingress",
                "OIDF_EDGE_PUBLIC_ENTRY_ORIGIN",
                json!(false),
            ),
            (
                "ui",
                "UI_PUBLIC_ENTRY_ORIGINS",
                json!("[\"https://203.0.113.11:8443\"]"),
            ),
            ("ui", "UI_PUBLIC_ENTRY_ORIGINS", json!([])),
        ] {
            let mut altered = model.clone();
            altered["services"][role]["environment"][field] = value;
            assert!(
                bound_ingress_listener(&altered, &inputs).is_err(),
                "{role}/{field}"
            );
        }
        if alias.is_some() {
            for (role, field) in [
                ("installer-ingress", "OIDF_EDGE_PUBLIC_ENTRY_ORIGIN"),
                ("ui", "UI_PUBLIC_ENTRY_ORIGINS"),
                ("ui", "UI_CANONICAL_ORIGIN"),
            ] {
                let mut altered = model.clone();
                altered["services"][role]["environment"]
                    .as_object_mut()
                    .unwrap()
                    .remove(field);
                assert!(
                    bound_ingress_listener(&altered, &inputs).is_err(),
                    "missing {role}/{field}"
                );
            }
        } else {
            let mut legacy = model;
            legacy["services"]["installer-ingress"]["environment"]
                .as_object_mut()
                .unwrap()
                .remove("OIDF_EDGE_PUBLIC_ENTRY_ORIGIN");
            legacy["services"]["ui"]["environment"]
                .as_object_mut()
                .unwrap()
                .remove("UI_PUBLIC_ENTRY_ORIGINS");
            assert!(bound_ingress_listener(&legacy, &inputs).is_ok());
        }
    }
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
fn fresh_ip_canonical_origins_are_refused_before_identity_provisioning() {
    let root = private_root();
    for (mode, origin, listener) in [
        ("direct", "https://203.0.113.10:8443", "0.0.0.0"),
        ("external-proxy", "https://203.0.113.10", "127.0.0.1"),
        ("local", "https://127.0.0.1:8443", "127.0.0.1"),
    ] {
        let mut value = direct();
        value["mode"] = json!(mode);
        value["public_origin"] = json!(origin);
        value["listener"]["bind_address"] = json!(listener);
        let path = input(root.path(), &value);
        assert!(prepare(Some(&path), None)
            .err()
            .unwrap()
            .contains("DNS canonical origin"));
        assert!(!root.path().join("installation").exists());
    }
    let mut value = direct();
    value["public_origin"] = json!("https://marty:8443");
    assert!(prepare(Some(&input(root.path(), &value)), None).is_err());
}

#[test]
fn legacy_ip_selection_remains_inspectable_without_rebinding_identity() {
    let root = private_root();
    let mut state = state(root.path());
    let mut value = direct();
    value["public_origin"] = json!("https://203.0.113.10:8443");
    let source = serde_json::to_vec(&value).unwrap();
    let recorded = Selection {
        schema: SELECTION_SCHEMA.into(),
        installation_id: state.journal().installation_id(),
        source_sha256: digest(&source),
        configuration: decode(&source).unwrap(),
        connector_token_sha256: None,
        recorded: true,
    };
    let raw = serde_json::to_vec(&recorded).unwrap();
    assert!(!std::str::from_utf8(&raw)
        .unwrap()
        .contains("public_entry_origin"));
    state.write_evidence(SOURCE, &source).unwrap();
    state.write_evidence(RECORD, &raw).unwrap();
    state.bind_hosting_selection(&digest(&raw)).unwrap();
    let selected = state.with_inspection(resolve).unwrap();
    assert_eq!(
        selected.requested_origin().unwrap().as_str(),
        "https://203.0.113.10:8443"
    );
    assert!(selected.public_entry_origin().is_none());
    assert_eq!(selected.certificate_dns_name(), None);
    assert_eq!(
        selected.certificate_ip_address(),
        Some("203.0.113.10".parse().unwrap())
    );
    assert_eq!(
        state.journal().hosting_selection_sha256(),
        Some(digest(&raw).as_str())
    );
}

#[test]
fn ip_public_entry_alias_is_bound_without_changing_canonical_identity() {
    for ip in ["203.0.113.10", "[2001:db8::10]"] {
        let root = private_root();
        let mut value = direct();
        let alias = format!("https://{ip}:8443");
        value["public_entry_origin"] = json!(alias);
        let prepared = prepare(Some(&input(root.path(), &value)), None).unwrap();
        assert!(prepared.host_impact().contains(&alias));
        let mut state = state(root.path());
        let selected = select(prepared, &mut state).unwrap();
        assert_eq!(
            selected.resolve_origin(8443).unwrap().as_str(),
            "https://marty.example.com"
        );
        assert_eq!(selected.public_entry_origin().unwrap().as_str(), alias);
        assert_eq!(selected.certificate_dns_name(), Some("marty.example.com"));
        assert_eq!(
            selected.certificate_ip_address(),
            selected.public_entry_origin().unwrap().ip_address()
        );
        let observed = state.with_inspection(resolve).unwrap();
        assert_eq!(
            observed.public_entry_origin(),
            selected.public_entry_origin()
        );
        value["public_entry_origin"] = json!("https://203.0.113.11:8443");
        write(
            &root.path().join("installation/evidence").join(SOURCE),
            &serde_json::to_vec(&value).unwrap(),
        );
        assert!(state.with_inspection(resolve).is_err());
    }
}

#[test]
fn public_entry_alias_does_not_expand_other_hosting_or_certificate_modes() {
    let root = private_root();
    for alias in [
        "https://other.example.com:8443",
        "https://127.0.0.1:8443",
        "https://[::1]:8443",
        "http://203.0.113.10:8443",
        "https://203.0.113.10:8443/path",
        "https://0.0.0.0:8443",
    ] {
        let mut value = direct();
        value["public_entry_origin"] = json!(alias);
        assert!(
            prepare(Some(&input(root.path(), &value)), None).is_err(),
            "accepted {alias}"
        );
    }
    for (mode, origin, listener) in [
        ("local", "https://localhost:8443", "127.0.0.1"),
        ("external-proxy", "https://marty.example.com", "127.0.0.1"),
    ] {
        let mut value = direct();
        value["mode"] = json!(mode);
        value["public_origin"] = json!(origin);
        value["listener"]["bind_address"] = json!(listener);
        value["public_entry_origin"] = json!("https://203.0.113.10:8443");
        assert!(prepare(Some(&input(root.path(), &value)), None).is_err());
    }
    let mut value = direct();
    value["public_entry_origin"] = json!("https://203.0.113.10:8443");
    value["tls"]["certificate_source"] = json!("foundation-import");
    assert!(prepare(
        Some(&input(root.path(), &value)),
        Some(PublicOrigin::parse("https://marty.example.com").unwrap())
    )
    .err()
    .unwrap()
    .contains("foundation-import does not support an IP entry alias"));
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
