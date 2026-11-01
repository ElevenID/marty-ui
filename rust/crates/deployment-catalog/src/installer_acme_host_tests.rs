use super::*;
use crate::installer_compose::{ContainerIdentity, SetupExecution};
use serde_json::json;
use std::{
    fs as files,
    os::unix::fs::{symlink, PermissionsExt},
};

const PUBLIC_ROOT: &[u8] =
    include_bytes!("../../../../tests/fixtures/selfhost_ca_issuer_public.pem");

struct Fixture {
    _files: tempfile::TempDir,
    installation: PathBuf,
    state: InstallerState,
    configuration: BoundAcmeConfiguration,
}
fn fixture(alias: bool) -> Fixture {
    let files = tempfile::tempdir().unwrap();
    files::set_permissions(files.path(), files::Permissions::from_mode(0o700)).unwrap();
    let installation = files.path().join("installation");
    let mut state = InstallerState::create(
        &installation,
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        },
    )
    .unwrap();
    state.create_private_directory("evidence").unwrap();
    state.advance(Phase::Verified).unwrap();
    let mut hosting = json!({"schema":"elevenid.installation-hosting/v1","mode":"direct","public_origin":"https://login.example.com:9443",
        "listener":{"bind_address":"0.0.0.0","port":8443},"tls":{"termination":"marty-keyless","certificate_source":"acme","http01_host_port":18080,
        "acme":{"environment":"production","directory_url":AcmeEnvironment::Production.directory_url(),"profile":"shortlived",
        "terms_url":"https://letsencrypt.org/documents/LE-SA-v1.6-August-18-2025.pdf","terms_agreed":true}}});
    if alias {
        hosting["public_entry_origin"] = json!("https://198.51.100.7:8443");
    }
    let input = files.path().join("hosting.json");
    files::write(&input, serde_json::to_vec(&hosting).unwrap()).unwrap();
    files::set_permissions(&input, files::Permissions::from_mode(0o600)).unwrap();
    installer_hosting::select(
        installer_hosting::prepare(Some(&input), None).unwrap(),
        &mut state,
    )
    .unwrap();
    state.advance(Phase::Provisioning).unwrap();
    let configuration = state
        .with_inspection(BoundAcmeConfiguration::from_selection)
        .unwrap();
    Fixture {
        _files: files,
        installation,
        state,
        configuration,
    }
}
fn inputs(installation: &Path) -> ComposeInputs {
    ComposeInputs {
        installation: installation.into(),
        project: "marty-install-test".into(),
        files: Vec::new(),
        bound_inputs: Vec::new(),
        environment: BoundFile {
            path: installation.join("evidence/fixture.env"),
            sha256: "a".repeat(64),
        },
        profiles: vec!["setup".into()],
        services: vec![RESPONDER.into()],
        approved_images: BTreeSet::new(),
        #[cfg(feature = "installer-development")]
        development_image: None,
        writable_bind_roots: BTreeSet::new(),
        readonly_bind_roots: BTreeSet::new(),
        allowed_loopback_ports: BTreeSet::from([18080]),
        ingress_listener: None,
        prior: None,
    }
}

#[test]
fn derived_environments_preserve_bootstrap_and_bind_both_plan_hashes_without_shell_expansion() {
    for alias in [false, true] {
        let fixture = fixture(alias);
        let bootstrap = b"MARTY_INSTALLATION_DIR='/private/install $literal%name'\n";
        let first = derived_environment(
            bootstrap,
            &fixture.configuration,
            18080,
            &"a".repeat(64),
            None,
        )
        .unwrap();
        let next = derived_environment(
            bootstrap,
            &fixture.configuration,
            18080,
            &"a".repeat(64),
            Some(&"b".repeat(64)),
        )
        .unwrap();
        assert!(first.starts_with(bootstrap));
        assert!(next.starts_with(&first));
        assert!(std::str::from_utf8(&next).unwrap().contains(&format!(
            "MARTY_ACME_CREDENTIAL_PLAN_SHA256='{}'\n",
            "b".repeat(64)
        )));
        assert!(std::str::from_utf8(&next).unwrap().contains(&format!(
            "MARTY_ACME_PUBLIC_ENTRY_ORIGIN='{}'\n",
            fixture
                .configuration
                .public_entry_origin()
                .unwrap_or_default()
        )));
        assert_eq!(
            bootstrap,
            b"MARTY_INSTALLATION_DIR='/private/install $literal%name'\n"
        );
        for invalid in [
            b"MARTY_ACME_HTTP01_HOST_PORT='other'\n".as_slice(),
            b"path='bad\0input'\n",
            b"no-final-newline",
        ] {
            assert!(derived_environment(
                invalid,
                &fixture.configuration,
                18080,
                &"a".repeat(64),
                None
            )
            .is_err());
        }
        assert!(
            derived_environment(bootstrap, &fixture.configuration, 80, &"a".repeat(64), None)
                .is_err()
        );
        assert!(derived_environment(
            bootstrap,
            &fixture.configuration,
            18080,
            "unbound-plan",
            None
        )
        .is_err());
    }
}

#[test]
fn completed_renewal_environment_is_preserved_and_duplicate_values_are_refused() {
    let fixture = fixture(true);
    let mut base = b"PERSISTED_INSTALLATION='/private/$literal%name'\n".to_vec();
    for (key, value) in [
        (
            "MARTY_ACME_CANONICAL_ORIGIN",
            fixture.configuration.canonical_origin(),
        ),
        (
            "MARTY_ACME_PUBLIC_ENTRY_ORIGIN",
            fixture.configuration.public_entry_origin().unwrap(),
        ),
        ("MARTY_ACME_HTTP01_HOST_PORT", "18080"),
    ] {
        append(&mut base, key, value).unwrap();
    }
    let next = derived_environment(
        &base,
        &fixture.configuration,
        18080,
        &"a".repeat(64),
        Some(&"b".repeat(64)),
    )
    .unwrap();
    assert!(next.starts_with(&base));
    assert_eq!(
        String::from_utf8(next)
            .unwrap()
            .matches("MARTY_ACME_HTTP01_HOST_PORT=")
            .count(),
        1
    );
    let mut duplicate = base.clone();
    duplicate.extend_from_slice(b"MARTY_ACME_HTTP01_HOST_PORT='18080'\n");
    assert!(derived_environment(
        &duplicate,
        &fixture.configuration,
        18080,
        &"a".repeat(64),
        None
    )
    .is_err());
    let mut files = vec![BoundFile {
        path: PathBuf::from("/retained/layer.yml"),
        sha256: "a".repeat(64),
    }];
    let same = files[0].clone();
    include_bound(&mut files, same.clone()).unwrap();
    assert_eq!(files.len(), 1);
    assert!(include_bound(
        &mut files,
        BoundFile {
            sha256: "b".repeat(64),
            ..same.clone()
        }
    )
    .is_err());
    files.push(same.clone());
    assert!(include_bound(&mut files, same).is_err());
}

#[test]
fn staging_trust_requires_exact_retained_bytes_and_is_never_accepted_for_production() {
    let mut fixture = fixture(false);
    assert!(fixture
        .state
        .with_inspection(|view| retained_roots(view, AcmeEnvironment::Production, None))
        .unwrap()
        .is_none());
    assert!(fixture
        .state
        .with_inspection(|view| retained_roots(view, AcmeEnvironment::Staging, Some(PUBLIC_ROOT)))
        .is_err());
    fixture
        .state
        .write_evidence(STAGING_ROOTS, PUBLIC_ROOT)
        .unwrap();
    assert_eq!(
        fixture
            .state
            .with_inspection(|view| retained_roots(
                view,
                AcmeEnvironment::Staging,
                Some(PUBLIC_ROOT)
            ))
            .unwrap(),
        Some(sha(PUBLIC_ROOT))
    );
    assert!(fixture
        .state
        .with_inspection(|view| retained_roots(
            view,
            AcmeEnvironment::Production,
            Some(PUBLIC_ROOT)
        ))
        .is_err());
    let mut changed = PUBLIC_ROOT.to_vec();
    changed.push(b'\n');
    assert!(fixture
        .state
        .with_inspection(|view| retained_roots(view, AcmeEnvironment::Staging, Some(&changed)))
        .is_err());
}

#[test]
fn incomplete_or_malformed_preparation_never_grants_order_continuation() {
    let mut fixture = fixture(false);
    assert!(!fixture
        .state
        .with_inspection(continuation_available)
        .unwrap());
    fixture
        .state
        .write_evidence(&name(AcmeEnvironment::Production, "intent"), b"{}")
        .unwrap();
    assert!(!fixture
        .state
        .with_inspection(continuation_available)
        .unwrap());
    fixture
        .state
        .write_evidence(&name(AcmeEnvironment::Production, "prepared"), b"{}")
        .unwrap();
    assert!(fixture
        .state
        .with_inspection(continuation_available)
        .is_err());
    assert_eq!(fixture.state.journal().phase(), Phase::Provisioning);
    assert!(!fixture.installation.join(PROJECTION).exists());
    assert!(!fixture
        .installation
        .join("acme-credentials-production")
        .exists());
}

#[test]
fn public_projection_keeps_private_parent_and_refuses_replacement_links_or_wrong_mode() {
    let fixture = fixture(false);
    let retained = prepare_projection(&fixture.state, &fixture.installation).unwrap();
    assert_eq!(
        files::metadata(&fixture.installation).unwrap().mode() & 0o7777,
        0o700
    );
    assert_eq!(
        fixture
            .state
            .with_inspection(|view| ProjectionDirectory::observe(view, &fixture.installation))
            .unwrap(),
        retained
    );
    assert!(prepare_projection(&fixture.state, &fixture.installation).is_err());
    let path = fixture.installation.join(PROJECTION);
    let old = fixture.installation.join("previous-public-projection");
    files::rename(&path, &old).unwrap();
    files::create_dir(&path).unwrap();
    files::set_permissions(&path, files::Permissions::from_mode(0o755)).unwrap();
    assert_ne!(
        fixture
            .state
            .with_inspection(|view| ProjectionDirectory::observe(view, &fixture.installation))
            .unwrap(),
        retained
    );
    files::set_permissions(&path, files::Permissions::from_mode(0o777)).unwrap();
    assert!(fixture
        .state
        .with_inspection(|view| ProjectionDirectory::observe(view, &fixture.installation))
        .is_err());
    files::remove_dir(&path).unwrap();
    symlink(&old, &path).unwrap();
    assert!(fixture
        .state
        .with_inspection(|view| ProjectionDirectory::observe(view, &fixture.installation))
        .is_err());
}

#[test]
fn responder_admission_binds_only_exact_identifiers_loopback_port_and_public_child_mount() {
    let fixture = fixture(true);
    let inputs = inputs(&fixture.installation);
    let good = json!({"services":{RESPONDER:{"environment":{"MARTY_ACME_HTTP01_BIND":"0.0.0.0:8080",
        "MARTY_ACME_HTTP01_CANONICAL_ORIGIN":fixture.configuration.canonical_origin(),
        "MARTY_ACME_HTTP01_PUBLIC_ENTRY_ORIGIN":fixture.configuration.public_entry_origin().unwrap(),
        "MARTY_ACME_HTTP01_DIRECTORY":"/run/acme-http01"},
        "ports":[{"target":8080,"published":"18080","host_ip":"127.0.0.1","protocol":"tcp"}],
        "volumes":[{"type":"bind","source":fixture.installation.join(PROJECTION),"target":"/run/acme-http01","read_only":true}]}}});
    responder_model(&good, &inputs, &fixture.configuration, 18080).unwrap();
    for (pointer, wrong) in [
        (
            format!("/services/{RESPONDER}/ports/0/host_ip"),
            json!("0.0.0.0"),
        ),
        (
            format!("/services/{RESPONDER}/ports/0/published"),
            json!("8200"),
        ),
        (
            format!("/services/{RESPONDER}/volumes/0/source"),
            json!(fixture.installation),
        ),
        (
            format!("/services/{RESPONDER}/volumes/0/read_only"),
            json!(false),
        ),
        (
            format!("/services/{RESPONDER}/environment/MARTY_ACME_HTTP01_CANONICAL_ORIGIN"),
            json!("https://foreign.example.com"),
        ),
        (
            format!("/services/{RESPONDER}/environment/MARTY_ACME_HTTP01_PUBLIC_ENTRY_ORIGIN"),
            json!("https://198.51.100.8"),
        ),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(&pointer).unwrap() = wrong;
        assert!(
            responder_model(&bad, &inputs, &fixture.configuration, 18080).is_err(),
            "{pointer}"
        );
    }
    let mut extra = good;
    extra["services"][CUSTODY] = json!({});
    assert!(responder_model(&extra, &inputs, &fixture.configuration, 18080).is_err());
}

#[test]
fn staging_trust_must_be_explicit_and_cannot_enter_production() {
    assert_eq!(roots(AcmeEnvironment::Production, None).unwrap(), None);
    assert!(roots(AcmeEnvironment::Production, Some(PUBLIC_ROOT)).is_err());
    assert!(roots(AcmeEnvironment::Staging, None).is_err());
    assert_eq!(
        roots(AcmeEnvironment::Staging, Some(PUBLIC_ROOT)).unwrap(),
        Some(sha(PUBLIC_ROOT))
    );
    assert!(roots(AcmeEnvironment::Staging, Some(b"not a certificate")).is_err());
    assert!(roots(
        AcmeEnvironment::Staging,
        Some(b"-----BEGIN PRIVATE KEY-----")
    )
    .is_err());
}

#[test]
fn resume_observation_requires_every_owned_setup_success_and_runtime_health() {
    let setup = ContainerIdentity {
        id: "a".repeat(64),
        service: CUSTODY.into(),
        image: "owned-image".into(),
        config_hash: "c".repeat(64),
        setup: true,
        setup_execution: Some(SetupExecution {
            started_at: "2026-01-01T00:00:00Z".into(),
            finished_at: "2026-01-01T00:00:01Z".into(),
            completed_without_restart: true,
        }),
        health_required: false,
        cap_add: BTreeSet::new(),
        cap_drop: BTreeSet::from(["ALL".into()]),
        read_only: true,
        memory_limit: 256 * 1024 * 1024,
    };
    let mut responder = setup.clone();
    responder.id = "b".repeat(64);
    responder.service = RESPONDER.into();
    responder.setup = false;
    responder.setup_execution = None;
    responder.health_required = true;
    let mut resources = ProjectResources {
        containers: BTreeMap::from([(CUSTODY.into(), setup), (RESPONDER.into(), responder)]),
        ..Default::default()
    };
    let statuses = vec![
        json!({"Service":CUSTODY,"ID":"a".repeat(64),"State":"exited","ExitCode":0}),
        json!({"Service":RESPONDER,"ID":"b".repeat(64),"State":"running","Health":"healthy"}),
    ];
    running(&resources, &statuses).unwrap();
    for (index, field, bad) in [
        (0, "State", json!("running")),
        (0, "ExitCode", json!(1)),
        (1, "State", json!("exited")),
        (1, "Health", json!("unhealthy")),
        (1, "ID", json!("foreign")),
    ] {
        let mut changed = statuses.clone();
        changed[index][field] = bad;
        assert!(running(&resources, &changed).is_err());
    }
    assert!(running(&resources, &statuses[..1]).is_err());
    resources
        .containers
        .get_mut(CUSTODY)
        .unwrap()
        .setup_execution
        .as_mut()
        .unwrap()
        .completed_without_restart = false;
    assert!(running(&resources, &statuses).is_err());
}
