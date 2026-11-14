use super::*;
use crate::installer_state::Identity;
use serde_json::json;
use std::os::unix::fs::{symlink, PermissionsExt};

fn private_file(path: &Path, raw: &[u8]) {
    std::fs::write(path, raw).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
fn configuration() -> Value {
    json!({
        "schema": SCHEMA,
        "external_oidc": {
            "issuer_url": "https://identity.example.test/tenant",
            "client_id": "marty-beta",
            "admin_email": "operator@example.test",
            "allowed_algorithms": ["RS256"],
            "trusted_endpoint_origins": ["https://login.example.test"]
        }
    })
}
fn installation() -> (tempfile::TempDir, PathBuf, InstallerState) {
    let parent = tempfile::tempdir().unwrap();
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = parent.path().join("installation");
    let mut state = InstallerState::create(
        &path,
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        },
    )
    .unwrap();
    state.create_private_directory("evidence").unwrap();
    state.advance(Phase::Verified).unwrap();
    (parent, path, state)
}
fn choose(parent: &Path, state: &mut InstallerState, config: &Value) -> Selection {
    let input = parent.join("oidc.json");
    private_file(&input, &serde_json::to_vec(config).unwrap());
    select(prepare(Some(&input), false).unwrap(), state).unwrap();
    state.with_inspection(load).unwrap().unwrap()
}

#[test]
fn absence_preserves_managed_default_and_selection_is_fresh_only() {
    let (parent, path, mut state) = installation();
    for aws_foundation in [false, true] {
        select(prepare(None, aws_foundation).unwrap(), &mut state).unwrap();
        assert!(state.with_inspection(external).unwrap().is_none());
        assert!(state.journal().external_oidc_selection_sha256().is_none());
        assert!(!path.join("evidence").join(RECORD).exists());
    }
    choose(parent.path(), &mut state, &configuration());
    let input = parent.path().join("oidc.json");
    assert!(select(prepare(Some(&input), false).unwrap(), &mut state).is_err());
    state.advance(Phase::Provisioning).unwrap();
    assert!(select(prepare(Some(&input), false).unwrap(), &mut state).is_err());
}

#[test]
fn invalid_provider_contracts_are_rejected_before_selection() {
    let (parent, path, state) = installation();
    let before = std::fs::read(path.join("installation.json")).unwrap();
    let input = parent.path().join("oidc.json");
    for (field, invalid) in [
        ("issuer_url", json!("http://identity.example.test")),
        ("issuer_url", json!("https://*.example.test/tenant")),
        ("issuer_url", json!("https://%2A.example.test/tenant")),
        (
            "issuer_url",
            json!("https://user:password@identity.example.test"),
        ),
        ("issuer_url", json!("https://identity.example.test?query=1")),
        (
            "issuer_url",
            json!("https://identity.example.test/#fragment"),
        ),
        ("client_id", json!("")),
        ("client_id", json!("unsafe\nvalue")),
        ("admin_email", json!("no-email")),
        ("admin_email", json!("admin@example.com")),
        ("admin_email", json!("Admin@Example.Com")),
        ("admin_email", json!("USER@EXAMPLE.COM")),
        ("admin_email", json!("Example@example.com")),
        ("admin_email", json!("change-me@example.test")),
        ("admin_email", json!("CHANGE-ME-operator@example.test")),
        ("allowed_algorithms", json!([])),
        ("allowed_algorithms", json!(["HS256"])),
        ("allowed_algorithms", json!(["ES512"])),
        ("allowed_algorithms", json!(["RS256", "ES512"])),
        ("allowed_algorithms", json!(["RS256", "RS256"])),
        ("scopes", json!([])),
        ("scopes", json!(["email"])),
        ("scopes", json!(["openid", "openid"])),
        ("scopes", json!(["openid", ""])),
        ("scopes", json!(["openid", "email profile"])),
        ("scopes", json!(["openid", "email,profile"])),
        ("scopes", json!(["openid", "email\nprofile"])),
        ("scopes", json!(["openid", "email\"profile"])),
        ("scopes", json!(["openid", "email'profile"])),
        ("scopes", json!(["openid", "email\\profile"])),
        ("scopes", json!(["openid", "équipe"])),
        ("scopes", json!(["openid", "a".repeat(129)])),
        ("scopes", json!(["openid", false])),
        ("scopes", json!("openid,email")),
        (
            "scopes",
            json!(std::iter::once("openid".to_string())
                .chain((0..16).map(|n| format!("{}{:02}", "a".repeat(126), n)))
                .collect::<Vec<_>>()),
        ),
        (
            "scopes",
            json!(std::iter::once("openid".to_string())
                .chain((0..32).map(|n| format!("group:{n}")))
                .collect::<Vec<_>>()),
        ),
        (
            "trusted_endpoint_origins",
            json!(["https://login.example.test/path"]),
        ),
        (
            "trusted_endpoint_origins",
            json!(["https://login.example.test/"]),
        ),
        (
            "trusted_endpoint_origins",
            json!(["http://login.example.test"]),
        ),
        (
            "trusted_endpoint_origins",
            json!(["https://*.example.test"]),
        ),
        (
            "trusted_endpoint_origins",
            json!(["https://%2A.example.test"]),
        ),
        (
            "trusted_endpoint_origins",
            json!(["https://login.example.test", "https://login.example.test"]),
        ),
        ("client_secret_file", json!("relative-secret")),
        ("client_auth_method", json!("private_key_jwt")),
        ("client_auth_method", json!("client_secret_basic")),
        ("userinfo_mode", json!("always")),
        ("prompt", json!("login")),
        ("prompt", json!(["none", "login"])),
        ("prompt", json!(["login", "login"])),
        ("prompt", json!(["create"])),
        ("max_age", json!(-1)),
        ("max_age", json!(86401)),
        ("max_age", json!(false)),
        ("max_age", json!("0")),
        ("provider_name", json!(" ")),
        ("provider_name", json!("é".repeat(41))),
        ("provider_name", json!("Example\u{0085}Name")),
        ("account_url", json!("http://identity.example.test/account")),
        ("account_url", json!("https://other.example.test/account")),
        (
            "recovery_url",
            json!("https://user:password@identity.example.test/recovery"),
        ),
        ("recovery_url", json!("https://*.example.test/recovery")),
        ("unrecognized", json!(true)),
    ] {
        let mut config = configuration();
        config["external_oidc"][field] = invalid;
        private_file(&input, &serde_json::to_vec(&config).unwrap());
        assert!(prepare(Some(&input), false).is_err(), "accepted {field}");
    }
    private_file(&input, br#"{"schema":"elevenid.installer-external-oidc/v1","schema":"duplicate","external_oidc":{}}"#);
    assert!(prepare(Some(&input), false).is_err());
    private_file(&input, &serde_json::to_vec(&configuration()).unwrap());
    assert!(prepare(Some(&input), true).is_err());
    std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(prepare(Some(&input), false).is_err());
    assert_eq!(
        std::fs::read(path.join("installation.json")).unwrap(),
        before
    );
    assert!(state.journal().external_oidc_selection_sha256().is_none());
    assert!(!path.join("evidence").join(RECORD).exists());
}

#[test]
fn optional_provider_compatibility_fields_preserve_omission_and_exact_environment() {
    let config: Configuration = serde_json::from_value(configuration()).unwrap();
    let old = serde_json::to_value(&config).unwrap();
    let mut env = BTreeMap::new();
    config.external_oidc.apply_environment(&mut env).unwrap();
    for field in [
        "client_auth_method",
        "userinfo_mode",
        "prompt",
        "max_age",
        "provider_name",
        "account_url",
        "recovery_url",
    ] {
        assert!(old["external_oidc"].get(field).is_none());
    }
    let mut value = configuration();
    value["external_oidc"]["client_auth_method"] = json!("none");
    value["external_oidc"]["userinfo_mode"] = json!("fallback");
    value["external_oidc"]["prompt"] = json!([]);
    value["external_oidc"]["max_age"] = json!("omit");
    value["external_oidc"]["provider_name"] = json!("Example Identity");
    value["external_oidc"]["account_url"] =
        json!("https://identity.example.test/account?tab=security#settings");
    value["external_oidc"]["recovery_url"] =
        json!("https://login.example.test/recover?application=$(marty)");
    let chosen: Configuration = serde_json::from_value(value).unwrap();
    chosen.external_oidc.apply_environment(&mut env).unwrap();
    let expected = BTreeMap::from([
        ("TOKEN_ENDPOINT_AUTH_METHOD", "none"),
        ("USERINFO_MODE", "fallback"),
        ("PROMPT", ""),
        ("MAX_AGE_SECONDS", "omit"),
        ("PROVIDER_NAME", "Example Identity"),
        (
            "ACCOUNT_URL",
            "https://identity.example.test/account?tab=security#settings",
        ),
        (
            "RECOVERY_URL",
            "https://login.example.test/recover?application=$(marty)",
        ),
    ]);
    let mut model = serde_json::Map::new();
    for (key, value) in expected {
        assert_eq!(env[&format!("MARTY_EXTERNAL_OIDC_{key}")], value);
        model.insert(format!("OIDC_{key}"), json!(value.replace('$', "$$")));
    }
    chosen.external_oidc.validate_model_scopes(&model).unwrap();
    model.insert("OIDC_PROMPT".into(), json!("consent login"));
    assert!(chosen.external_oidc.validate_model_scopes(&model).is_err());
    config.external_oidc.apply_environment(&mut env).unwrap();
    assert!(!env.contains_key("MARTY_EXTERNAL_OIDC_PROMPT"));
}

#[test]
fn explicit_confidential_client_authentication_requires_private_secret_reference() {
    let (parent, _, mut state) = installation();
    let secret = parent.path().join("client-secret");
    private_file(&secret, b"fixture-confidential-value");
    for method in ["client_secret_post", "client_secret_basic"] {
        let mut value = configuration();
        value["external_oidc"]["client_secret_file"] = json!(secret);
        value["external_oidc"]["client_auth_method"] = json!(method);
        let input = parent.path().join("confidential.json");
        private_file(&input, &serde_json::to_vec(&value).unwrap());
        assert!(prepare(Some(&input), false).is_ok());
        value["external_oidc"]["client_auth_method"] = json!("none");
        private_file(&input, &serde_json::to_vec(&value).unwrap());
        assert!(prepare(Some(&input), false).is_err());
    }
    select(None, &mut state).unwrap();
}

#[test]
fn confidential_secret_transport_is_rejected_during_input_preparation() {
    let (parent, path, state) = installation();
    let before = std::fs::read(path.join("installation.json")).unwrap();
    let secret = parent.path().join("client-secret");
    let input = parent.path().join("provider.json");
    let mut value = configuration();
    value["external_oidc"]["client_secret_file"] = json!(secret);
    private_file(&input, &serde_json::to_vec(&value).unwrap());
    for raw in [
        Vec::new(),
        b"  \n".to_vec(),
        "confidential-é".as_bytes().to_vec(),
        b"value\0value".to_vec(),
        b"-----BEGIN PRIVATE KEY-----".to_vec(),
        vec![b'a'; 65537],
    ] {
        private_file(&secret, &raw);
        assert!(prepare(Some(&input), false).is_err());
    }
    assert_eq!(
        std::fs::read(path.join("installation.json")).unwrap(),
        before
    );
    assert!(state.journal().external_oidc_selection_sha256().is_none());
}

#[test]
fn supported_provider_inputs_preserve_exact_identity_and_bootstrap_email() {
    let (parent, path, state) = installation();
    let before = std::fs::read(path.join("installation.json")).unwrap();
    let input = parent.path().join("oidc.json");
    for email in [
        "operator@example.com",
        "admin@example.test",
        "Administrator@EXAMPLE.COM",
        "operator+beta@example.test",
        "my-change-me@example.test",
    ] {
        let mut config = configuration();
        config["external_oidc"]["issuer_url"] = json!("https://identity.example.test/tenants/*");
        config["external_oidc"]["admin_email"] = json!(email);
        config["external_oidc"]["allowed_algorithms"] = json!([
            "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA"
        ]);
        private_file(&input, &serde_json::to_vec(&config).unwrap());
        let prepared = prepare(Some(&input), false).unwrap().unwrap();
        let mut environment = BTreeMap::new();
        prepared
            .configuration
            .external_oidc
            .apply_environment(&mut environment)
            .unwrap();
        assert_eq!(environment["MARTY_ORG_ADMIN_EMAIL"], email);
        assert_eq!(
            environment["MARTY_EXTERNAL_OIDC_ISSUER"],
            "https://identity.example.test/tenants/*"
        );
    }
    assert_eq!(
        std::fs::read(path.join("installation.json")).unwrap(),
        before
    );
    assert!(state.journal().external_oidc_selection_sha256().is_none());
    assert!(!path.join("evidence").join(RECORD).exists());
}

#[test]
fn optional_scopes_preserve_existing_records_and_bind_explicit_runtime_selection() {
    for scopes in [None, Some(vec!["openid", "email", "urn:example:$groups"])] {
        let (parent, path, mut state) = installation();
        let mut config = configuration();
        if let Some(scopes) = &scopes {
            config["external_oidc"]["scopes"] = json!(scopes);
            config["external_oidc"]["issuer_url"] = json!("https://identity.example.test/$tenant");
            config["external_oidc"]["client_id"] = json!("client-${literal}");
        }
        let selected = choose(parent.path(), &mut state, &config);
        let oidc = &selected.configuration.external_oidc;
        let retained: Value =
            serde_json::from_slice(&std::fs::read(path.join("evidence").join(RECORD)).unwrap())
                .unwrap();
        let mut environment = BTreeMap::new();
        oidc.apply_environment(&mut environment).unwrap();
        if let Some(scopes) = &scopes {
            assert_eq!(
                retained["configuration"]["external_oidc"]["scopes"],
                json!(scopes)
            );
            assert_eq!(environment["MARTY_EXTERNAL_OIDC_SCOPES"], scopes.join(","));
        } else {
            assert!(retained["configuration"]["external_oidc"]
                .get("scopes")
                .is_none());
            assert!(!environment.contains_key("MARTY_EXTERNAL_OIDC_SCOPES"));
        }
        assert_eq!(
            state.with_inspection(external).unwrap().as_ref(),
            Some(oidc)
        );

        let mut model = json!({"services": {"auth": {"environment": {
            "OIDC_PROVIDER_MODE": "external",
            "OIDC_ISSUER_URL": oidc.issuer_url.replace('$', "$$"),
            "OIDC_EXTERNAL_ISSUER_URL": oidc.issuer_url.replace('$', "$$"),
            "OIDC_CLIENT_ID": oidc.client_id.replace('$', "$$"),
            "OIDC_CLIENT_SECRET_FILE": "",
            "OIDC_ALLOWED_ALGORITHMS": oidc.allowed_algorithms.join(","),
            "OIDC_TRUSTED_ENDPOINT_ORIGINS": oidc.trusted_endpoint_origins.join(","),
            "KEYCLOAK_TOKEN_EXCHANGE_ENABLED": "false",
            "KEYCLOAK_PASSKEYS_ENABLED": "false",
            "CREDENTIAL_LOGIN_REQUIRE_EXISTING_KEYCLOAK_USER": "false",
            "CREDENTIAL_LOGIN_CREATE_USERS": "false"
        }}}});
        // Old retained layers may omit this variable only for the old default.
        assert_eq!(selected.validate_model(&model).is_ok(), scopes.is_none());
        model["services"]["auth"]["environment"]["OIDC_SCOPES"] =
            json!(scopes.as_ref().map_or_else(
                || DEFAULT_SCOPES.into(),
                |values| values.join(",").replace('$', "$$")
            ));
        selected.validate_model(&model).unwrap();
        if let Some(scopes) = &scopes {
            let mut unescaped = model.clone();
            unescaped["services"]["auth"]["environment"]["OIDC_SCOPES"] = json!(scopes.join(","));
            assert!(selected.validate_model(&unescaped).is_err());
            for name in [
                "OIDC_ISSUER_URL",
                "OIDC_EXTERNAL_ISSUER_URL",
                "OIDC_CLIENT_ID",
            ] {
                let mut unescaped = model.clone();
                let value = unescaped["services"]["auth"]["environment"][name]
                    .as_str()
                    .unwrap()
                    .replace("$$", "$");
                unescaped["services"]["auth"]["environment"][name] = json!(value);
                assert!(selected.validate_model(&unescaped).is_err());
            }
        }
        for invalid in [
            json!(null),
            json!(""),
            json!("openid"),
            json!("openid,profile,email,groups"),
        ] {
            model["services"]["auth"]["environment"]["OIDC_SCOPES"] = invalid;
            assert!(selected.validate_model(&model).is_err());
        }
    }
}

#[test]
fn public_client_has_no_local_password_and_imports_only_empty_placeholder() {
    let (parent, path, mut state) = installation();
    let selected = choose(parent.path(), &mut state, &configuration());
    state.advance(Phase::Provisioning).unwrap();
    state.generate_external_auth_credentials().unwrap();
    selected.import_inputs(&mut state).unwrap();
    assert!(!path.join("operator-password").exists());
    for name in crate::installer_state::LOCAL_AUTH_SCALAR_SECRETS {
        assert!(!path.join("secrets").join(name).exists());
    }
    assert_eq!(
        std::fs::read(path.join("secrets").join(SECRET)).unwrap(),
        b""
    );
    assert!(selected
        .verify_imported(&BTreeMap::from([(SECRET.into(), Vec::new())]))
        .is_ok());
    assert!(selected.verify_imported(&BTreeMap::new()).is_err());
    let mut values = BTreeMap::from([
        ("KEYCLOAK_REALM".into(), "11id".into()),
        ("MARTY_OPENBAO_DIDCOMM_IMAGE".into(), "managed-image".into()),
        ("BAO_ADDR".into(), "https://openbao:8200".into()),
        ("AUTH_TLS_KMS_ADDR".into(), "https://openbao:8200".into()),
    ]);
    selected
        .configuration
        .external_oidc
        .apply_environment(&mut values)
        .unwrap();
    assert!(!values.contains_key("KEYCLOAK_REALM"));
    assert_eq!(values["MARTY_EXTERNAL_OIDC_SECRET_FILE"], "");
    assert_eq!(values["MARTY_ORG_ADMIN_EMAIL"], "operator@example.test");
    assert_eq!(values["AUTH_TLS_KMS_ADDR"], "https://openbao:8200");
    assert_eq!(values["BAO_ADDR"], "https://openbao:8200");
    assert_eq!(values["MARTY_OPENBAO_DIDCOMM_IMAGE"], "managed-image");
}

#[test]
fn confidential_secret_is_fingerprinted_and_changed_source_is_refused() {
    for change in [false, true] {
        let (parent, path, mut state) = installation();
        let input = parent.path().join("client-secret");
        let secret = b"synthetic-client-secret-for-test";
        private_file(&input, secret);
        let mut config = configuration();
        config["external_oidc"]["client_secret_file"] = json!(input);
        let selected = choose(parent.path(), &mut state, &config);
        let record = std::fs::read_to_string(path.join("evidence").join(RECORD)).unwrap();
        assert!(!record.contains(std::str::from_utf8(secret).unwrap()));
        if change {
            private_file(&input, b"changed-after-selection");
        }
        state.advance(Phase::Provisioning).unwrap();
        state.generate_external_auth_credentials().unwrap();
        assert_eq!(selected.import_inputs(&mut state).is_ok(), !change);
        if !change {
            assert_eq!(
                std::fs::read(path.join("secrets").join(SECRET)).unwrap(),
                secret
            );
            let mut values = BTreeMap::new();
            selected
                .configuration
                .external_oidc
                .apply_environment(&mut values)
                .unwrap();
            assert_eq!(
                values["MARTY_EXTERNAL_OIDC_SECRET_FILE"],
                "/run/secrets/external_oidc_client_secret"
            );
            assert!(!serde_json::to_string(&values)
                .unwrap()
                .contains(std::str::from_utf8(secret).unwrap()));
        }
    }
}

#[test]
fn removed_replaced_or_conflicting_record_cannot_downgrade_to_keycloak() {
    for action in ["remove", "replace", "foundation", "symlink"] {
        let (parent, path, mut state) = installation();
        choose(parent.path(), &mut state, &configuration());
        let record_path = path.join("evidence").join(RECORD);
        match action {
            "remove" => std::fs::remove_file(&record_path).unwrap(),
            "replace" => {
                let mut record: Value =
                    serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
                record["configuration"]["external_oidc"]["client_id"] = json!("other-client");
                private_file(&record_path, &serde_json::to_vec(&record).unwrap());
            }
            "foundation" => private_file(
                &path
                    .join("evidence")
                    .join(crate::installer_foundation::RECORD),
                b"{}",
            ),
            "symlink" => {
                let target = parent.path().join("copied-record");
                std::fs::rename(&record_path, &target).unwrap();
                symlink(target, record_path).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            state.with_inspection(external).is_err(),
            "accepted {action}"
        );
        assert!(
            record(&path, state.journal().installation_id()).is_err(),
            "accepted {action}"
        );
    }
}

#[test]
fn compose_inputs_must_pin_the_selected_record() {
    let (parent, path, mut state) = installation();
    let selected = choose(parent.path(), &mut state, &configuration());
    let mut inputs = ComposeInputs {
        installation: path.clone(),
        project: state.journal().compose_project(),
        files: vec![],
        bound_inputs: vec![],
        environment: crate::installer_compose::BoundFile {
            path: path.join("unused.env"),
            sha256: "a".repeat(64),
        },
        profiles: vec![],
        services: vec![],
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
    assert!(for_inputs(&inputs).unwrap().is_some());
    inputs.bound_inputs[0].sha256 = "c".repeat(64);
    assert!(for_inputs(&inputs).is_err());
}
