use super::*;
use crate::installer_state::Identity;
use serde_json::json;
use std::{
    collections::BTreeSet,
    os::unix::fs::{symlink, PermissionsExt},
};

fn private_file(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
fn configuration(parent: &Path) -> Value {
    json!({
        "schema": SCHEMA,
        "external_postgres": {
            "host": "aws-0-us-west-1.pooler.supabase.com",
            "port": 5432,
            "username": "elevenid.projectref",
            "database": "postgres",
            "password_file": parent.join("database-password")
        }
    })
}
pub(super) fn installation() -> (tempfile::TempDir, PathBuf, InstallerState) {
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
    private_file(
        &parent.path().join("database-password"),
        b"test:pass@word/%$'",
    );
    (parent, path, state)
}
fn choose_oidc(parent: &Path, state: &mut InstallerState) {
    let input = parent.join("oidc.json");
    private_file(
        &input,
        &serde_json::to_vec(&json!({
            "schema": "elevenid.installer-external-oidc/v1",
            "external_oidc": {
                "issuer_url": "https://identity.example.test",
                "client_id": "elevenid",
                "admin_email": "owner@example.test",
                "allowed_algorithms": ["RS256"]
            }
        }))
        .unwrap(),
    );
    crate::installer_oidc::select(
        crate::installer_oidc::prepare(Some(&input), false).unwrap(),
        state,
    )
    .unwrap();
}
pub(super) fn choose(parent: &Path, state: &mut InstallerState) -> Selection {
    choose_oidc(parent, state);
    let input = parent.join("postgres.json");
    private_file(&input, &serde_json::to_vec(&configuration(parent)).unwrap());
    select(prepare(Some(&input), true, false).unwrap(), state).unwrap();
    state.with_inspection(load).unwrap().unwrap()
}

#[test]
fn absent_selection_preserves_local_default_and_external_database_requires_external_oidc() {
    let (parent, path, mut state) = installation();
    select(prepare(None, false, false).unwrap(), &mut state).unwrap();
    assert!(state.with_inspection(load).unwrap().is_none());
    assert!(state
        .journal()
        .external_postgres_selection_sha256()
        .is_none());
    assert!(!path.join("evidence").join(RECORD).exists());
    let input = parent.path().join("postgres.json");
    private_file(
        &input,
        &serde_json::to_vec(&configuration(parent.path())).unwrap(),
    );
    assert!(prepare(Some(&input), false, false).is_err());
    assert!(prepare(Some(&input), true, true).is_err());
    assert!(select(prepare(Some(&input), true, false).unwrap(), &mut state).is_err());
    choose_oidc(parent.path(), &mut state);
    select(prepare(Some(&input), true, false).unwrap(), &mut state).unwrap();
    assert!(select(prepare(Some(&input), true, false).unwrap(), &mut state).is_err());
    state.advance(Phase::Provisioning).unwrap();
    assert!(select(prepare(Some(&input), true, false).unwrap(), &mut state).is_err());
}

#[test]
fn status_distinguishes_a_bound_selection_from_provider_health_or_recovery_evidence() {
    let (parent, path, mut state) = installation();
    assert!(state.with_inspection(status).unwrap().is_none());
    let local = state
        .with_inspection(|view| {
            crate::installer_doctor::services(view, &path, Path::new("/unused/docker"))
        })
        .unwrap();
    assert!(local.get("external_database").is_none());
    choose(parent.path(), &mut state);
    // Status uses retained evidence; it must not reread the operator's original
    // password file or infer that the runtime can connect to the provider.
    std::fs::remove_file(parent.path().join("database-password")).unwrap();
    let report = state.with_inspection(status).unwrap().unwrap();
    let doctor = state
        .with_inspection(|view| {
            crate::installer_doctor::services(view, &path, Path::new("/unused/docker"))
        })
        .unwrap();
    assert_eq!(doctor["external_database"], report);
    assert_eq!(doctor["services_observed"], false);
    assert_eq!(report["selection_verified"], true);
    assert_eq!(report["provider_health"], "not_observed");
    for field in [
        "connection_observed",
        "local_postgres_managed",
        "local_state_copy_includes_database",
        "backup_observed",
        "restore_observed",
        "installer_password_rotation_supported",
        "installation_ready",
    ] {
        assert_eq!(report[field], false, "asserted {field} from configuration");
    }
    assert_eq!(
        report["backup_restore_owner"],
        "operator_and_database_provider"
    );
    assert_eq!(report["backup_restore_qualification"], "not_assessed");
    let text = report.to_string();
    for private in [
        "pooler.supabase.com",
        "elevenid.projectref",
        "database-password",
        "test:pass@word",
    ] {
        assert!(!text.contains(private));
    }
    std::fs::remove_file(path.join("evidence").join(RECORD)).unwrap();
    assert!(state.with_inspection(status).is_err());
}

#[test]
fn input_contract_refuses_raw_urls_tls_downgrades_and_unknown_or_duplicate_fields() {
    let (parent, path, state) = installation();
    let before = std::fs::read(path.join("installation.json")).unwrap();
    let input = parent.path().join("postgres.json");
    for (field, invalid) in [
        ("host", json!("")),
        ("host", json!("https://pooler.supabase.com")),
        ("host", json!("user:password@pooler.supabase.com")),
        ("host", json!("pooler.supabase.com:5432")),
        ("host", json!("pooler.supabase.com/path")),
        ("host", json!("pooler.supabase.com?sslmode=disable")),
        ("host", json!("*.supabase.com")),
        ("host", json!("pooler..supabase.com")),
        ("host", json!("-pooler.supabase.com")),
        ("host", json!("pooler-.supabase.com")),
        ("host", json!("pooler.supabase.com.")),
        ("host", json!("db\n.example.test")),
        ("port", json!(0)),
        ("port", json!(65536)),
        ("port", json!("5432")),
        ("username", json!("")),
        ("username", json!("user\nname")),
        ("database", json!("")),
        ("database", json!(" db")),
        ("database", json!("a".repeat(129))),
        ("password_file", json!("relative-file")),
        ("password", json!("raw-password")),
        ("sslmode", json!("require")),
        ("url", json!("postgresql://user:password@host/db")),
    ] {
        let mut config = configuration(parent.path());
        config["external_postgres"][field] = invalid;
        private_file(&input, &serde_json::to_vec(&config).unwrap());
        assert!(
            prepare(Some(&input), true, false).is_err(),
            "accepted {field}"
        );
    }
    private_file(&input, br#"{"schema":"elevenid.installer-external-postgres/v1","schema":"duplicate","external_postgres":{}}"#);
    assert!(prepare(Some(&input), true, false).is_err());
    assert_eq!(
        std::fs::read(path.join("installation.json")).unwrap(),
        before
    );
    assert!(state
        .journal()
        .external_postgres_selection_sha256()
        .is_none());
}

#[test]
fn passwords_and_configuration_must_be_private_ordinary_files_and_lossless() {
    let (parent, _, _) = installation();
    let input = parent.path().join("postgres.json");
    let password = parent.path().join("database-password");
    private_file(
        &input,
        &serde_json::to_vec(&configuration(parent.path())).unwrap(),
    );
    for bytes in [
        Vec::new(),
        b"   ".to_vec(),
        b"password\n".to_vec(),
        b"pass\0word".to_vec(),
        b"pass\tword".to_vec(),
        "passwörd".as_bytes().to_vec(),
        b"-----BEGIN PRIVATE KEY-----".to_vec(),
        vec![b'a'; 65537],
    ] {
        private_file(&password, &bytes);
        assert!(prepare(Some(&input), true, false).is_err());
    }
    private_file(&password, b"valid:$@/password");
    assert!(prepare(Some(&input), true, false).is_ok());
    std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(prepare(Some(&input), true, false).is_err());
    private_file(&password, b"valid-password");
    std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(prepare(Some(&input), true, false).is_err());
    std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o600)).unwrap();
    let renamed = parent.path().join("original-password");
    std::fs::rename(&password, &renamed).unwrap();
    symlink(renamed, password).unwrap();
    assert!(prepare(Some(&input), true, false).is_err());
}

#[test]
fn endpoint_encoding_cannot_inject_credentials_query_or_template_variables() {
    let (parent, _, _) = installation();
    let mut config: Configuration = serde_json::from_value(configuration(parent.path())).unwrap();
    config.external_postgres.username = "role:with@/%${unsafe}'é".into();
    config.external_postgres.database = "db/with?sslmode=disable#fragment".into();
    for (host, expected) in [
        ("POOLER.EXAMPLE.TEST", "pooler.example.test"),
        ("192.0.2.10", "192.0.2.10"),
        ("2001:db8::1", "[2001:db8::1]"),
    ] {
        config.external_postgres.host = host.into();
        let mut env = BTreeMap::new();
        config
            .external_postgres
            .apply_environment(&mut env)
            .unwrap();
        assert_eq!(
            env["MARTY_EXTERNAL_POSTGRES_URL_TEMPLATE"],
            format!("postgresql://role%3Awith%40%2F%25%24%7Bunsafe%7D%27%C3%A9:${{MARTY_DB_PASSWORD}}@{expected}:5432/db%2Fwith%3Fsslmode%3Ddisable%23fragment?sslmode=verify-full")
        );
        assert_eq!(env.len(), 1);
    }
}

#[test]
fn imported_password_is_fingerprinted_and_never_written_to_nonsecret_evidence() {
    for change in [false, true] {
        let (parent, path, mut state) = installation();
        let selection = choose(parent.path(), &mut state);
        let password_path = parent.path().join("database-password");
        let password = std::fs::read(&password_path).unwrap();
        let record = std::fs::read_to_string(path.join("evidence").join(RECORD)).unwrap();
        let mut env = BTreeMap::new();
        selection
            .configuration
            .external_postgres
            .apply_environment(&mut env)
            .unwrap();
        assert!(!record.contains(std::str::from_utf8(&password).unwrap()));
        assert!(!serde_json::to_string(&env)
            .unwrap()
            .contains(std::str::from_utf8(&password).unwrap()));
        if change {
            private_file(&password_path, b"changed-after-selection");
        }
        state.advance(Phase::Provisioning).unwrap();
        state.generate_external_auth_credentials().unwrap();
        assert_eq!(selection.import_inputs(&mut state).is_ok(), !change);
        if !change {
            assert_eq!(
                std::fs::read(path.join("secrets").join(SECRET)).unwrap(),
                password
            );
            selection
                .verify_imported(&BTreeMap::from([(SECRET.into(), password.clone())]))
                .unwrap();
            assert!(selection.verify_imported(&BTreeMap::new()).is_err());
            assert!(selection
                .verify_imported(&BTreeMap::from([(
                    SECRET.into(),
                    b"wrong-password".to_vec()
                )]))
                .is_err());
        }
    }
}

#[test]
fn missing_changed_or_conflicting_selection_cannot_fall_back_to_local_postgres() {
    for action in ["remove", "replace", "symlink", "remove-oidc", "foundation"] {
        let (parent, path, mut state) = installation();
        choose(parent.path(), &mut state);
        let target = path.join("evidence").join(RECORD);
        match action {
            "remove" => std::fs::remove_file(&target).unwrap(),
            "replace" => {
                let mut record: Value =
                    serde_json::from_slice(&std::fs::read(&target).unwrap()).unwrap();
                record["configuration"]["external_postgres"]["host"] =
                    json!("changed.example.test");
                private_file(&target, &serde_json::to_vec(&record).unwrap());
            }
            "symlink" => {
                let moved = parent.path().join("copied-record");
                std::fs::rename(&target, &moved).unwrap();
                symlink(moved, target).unwrap();
            }
            "remove-oidc" => {
                std::fs::remove_file(path.join("evidence").join(crate::installer_oidc::RECORD))
                    .unwrap()
            }
            "foundation" => private_file(
                &path
                    .join("evidence")
                    .join(crate::installer_foundation::RECORD),
                b"{}",
            ),
            _ => unreachable!(),
        }
        assert!(state.with_inspection(load).is_err(), "accepted {action}");
        assert!(
            record(&path, state.journal().installation_id()).is_err(),
            "accepted {action}"
        );
    }
}

#[test]
fn composed_inputs_bind_both_database_and_login_selections_exactly_once() {
    let (parent, path, mut state) = installation();
    let selection = choose(parent.path(), &mut state);
    let oidc = state
        .with_inspection(crate::installer_oidc::load)
        .unwrap()
        .unwrap();
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
    selection.bind_inputs(&mut inputs).unwrap();
    assert!(for_inputs(&inputs).is_err());
    oidc.bind_inputs(&mut inputs).unwrap();
    assert!(for_inputs(&inputs).unwrap().is_some());
    let valid = inputs.clone();
    selection.bind_inputs(&mut inputs).unwrap();
    assert!(for_inputs(&inputs).is_err());
    inputs = valid;
    inputs.bound_inputs[0].sha256 = "c".repeat(64);
    assert!(for_inputs(&inputs).is_err());
}

fn model(selection: &Selection) -> Value {
    let mut services = serde_json::Map::new();
    for name in DATABASE_SERVICES {
        let mut environment = serde_json::Map::from_iter([
            (
                "DATABASE_URL_TEMPLATE".into(),
                json!(selection
                    .configuration
                    .external_postgres
                    .url_template()
                    .unwrap()
                    .replace('$', "$$")),
            ),
            ("MARTY_DB_PASSWORD_FILE".into(), json!(PASSWORD_MOUNT)),
        ]);
        if let Some((key, limit)) = pool_limit(name) {
            environment.insert(key.into(), json!(limit));
        }
        services.insert(
            (*name).into(),
            json!({
                "environment": environment,
                "secrets": [{"source":"marty_db_password", "target":"marty_db_password"}],
                "depends_on": {"redis": {"condition":"service_healthy"}}
            }),
        );
    }
    json!({"services": services, "secrets": {"marty_db_password": {"file":"/installation/secrets/external_postgres_password"}}})
}

#[test]
fn selected_root_certificate_is_retained_and_required_for_each_database_consumer() {
    let (parent, path, mut state) = installation();
    choose_oidc(parent.path(), &mut state);
    let input = parent.path().join("postgres.json");
    let mut config = configuration(parent.path());
    let pem = "-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----";
    config["external_postgres"]["root_certificate_pem"] =
        json!(format!("{}\r\n", pem.replace('\n', "\r\n")));
    private_file(&input, &serde_json::to_vec(&config).unwrap());
    select(prepare(Some(&input), true, false).unwrap(), &mut state).unwrap();
    std::fs::remove_file(input).unwrap();

    let (_, selection) = record(&path, state.journal().installation_id())
        .unwrap()
        .unwrap();
    let mut env = b"SELFHOST_SECRET_DIR='/installation/secrets'\n".to_vec();
    selection
        .configuration
        .external_postgres
        .append_root_certificate(&mut env)
        .unwrap();
    let retained =
        crate::installer_application_env::select_generation(&env, Path::new("/installation"))
            .unwrap();
    assert!(std::str::from_utf8(&retained)
        .unwrap()
        .contains(&format!("PGSSLROOTCERT='{pem}'\n")));

    let mut compose = model(&selection);
    assert!(selection.validate_model(&compose).is_err());
    for service in DATABASE_SERVICES {
        compose["services"][*service]["environment"][ROOT_CERT_ENV] = json!(pem);
    }
    selection.validate_model(&compose).unwrap();
    for service in DATABASE_SERVICES {
        let mut changed = compose.clone();
        changed["services"][*service]["environment"][ROOT_CERT_ENV] = json!(null);
        assert!(selection.validate_model(&changed).is_err(), "{service}");
    }
    let mut postgres = selection.configuration.external_postgres;
    for invalid in [
        "",
        "/var/ca.pem",
        "-----BEGIN PRIVATE KEY-----\nMAMCAQE=\n-----END PRIVATE KEY-----",
        "-----BEGIN CERTIFICATE-----\nMAMCAQE='\n-----END CERTIFICATE-----",
    ] {
        postgres.root_certificate_pem = Some(invalid.into());
        assert!(postgres.validate().is_err());
    }
}

#[test]
fn composed_runtime_cannot_restore_local_database_downgrade_tls_or_change_pool_limits() {
    let (parent, _, mut state) = installation();
    let selection = choose(parent.path(), &mut state);
    let valid = model(&selection);
    selection.validate_model(&valid).unwrap();
    selection
        .validate_model(&json!({"services":{"openbao":{"environment":{}}}}))
        .unwrap();
    for service in DATABASE_SERVICES {
        for variable in ["DATABASE_URL_TEMPLATE", "MARTY_DB_PASSWORD_FILE"] {
            let mut changed = valid.clone();
            changed["services"][*service]["environment"][variable] = json!("changed");
            assert!(
                selection.validate_model(&changed).is_err(),
                "accepted {service}:{variable}"
            );
        }
        let mut changed = valid.clone();
        changed["services"][*service]["depends_on"]["postgres"] =
            json!({"condition":"service_healthy"});
        assert!(
            selection.validate_model(&changed).is_err(),
            "accepted local {service} dependency"
        );
        let mut changed = valid.clone();
        changed["services"][*service]["environment"]["DATABASE_URL"] =
            json!("postgresql://unbound:password@local/db");
        assert!(selection.validate_model(&changed).is_err());
        if let Some((key, _)) = pool_limit(service) {
            let mut changed = valid.clone();
            changed["services"][*service]["environment"][key] = json!("30");
            assert!(selection.validate_model(&changed).is_err());
        }
    }
    let mut changed = valid.clone();
    changed["services"]["postgres"] = json!({});
    assert!(selection.validate_model(&changed).is_err());
    let mut changed = valid.clone();
    changed["secrets"]["marty_db_password"]["file"] =
        json!("/installation/secrets/marty_db_password");
    assert!(selection.validate_model(&changed).is_err());
    let mut changed = valid;
    changed["services"]["auth"]["environment"]["DATABASE_URL_TEMPLATE"] = json!(selection
        .configuration
        .external_postgres
        .url_template()
        .unwrap()
        .replace('$', "$$")
        .replace("verify-full", "require"));
    assert!(selection.validate_model(&changed).is_err());
}
