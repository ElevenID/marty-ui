//! Synthetic public release records exercise native private-file ownership and
//! transaction admission. These are not signed-release or installed-host proof.

#[test]
fn pending_custody_rejects_unknown_directories_and_pins_only_authenticated_canary_tree() {
    let f = Fixture::with_source(MANAGED_RECOVERY_SOURCE);
    let scope = pending_files(&f);
    let name = "rootless-canary-11111111111141118111111111111111";
    let directory = f.installation.join("evidence").join(name);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(pending_custody(&f.installation, scope, None).is_err());
    // The real adapter is tested against complete canary receipts separately;
    // this injected result exercises exact directory selection and hash pinning.
    let canary = (
        name.into(),
        BTreeMap::from([(format!("evidence/{name}/child/marker"), "f".repeat(64))]),
    );
    let before = pending_custody(&f.installation, scope, Some(&canary)).unwrap();
    assert_eq!(
        before[&format!("evidence/{name}/child/marker")],
        "f".repeat(64)
    );
    let mut changed = canary.clone();
    changed
        .1
        .insert(format!("evidence/{name}/child/marker"), "e".repeat(64));
    assert_ne!(
        pending_custody(&f.installation, scope, Some(&changed)).unwrap(),
        before
    );
    let other = f.installation.join("evidence/foreign-directory");
    fs::create_dir(&other).unwrap();
    fs::set_permissions(&other, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(pending_custody(&f.installation, scope, Some(&canary)).is_err());
}

fn pending_files(f: &Fixture) -> installer_generation_maintenance::attempt::Attempt {
    let scope = installer_generation_maintenance::attempt::Attempt::new(2, 0);
    let evidence = f.installation.join("evidence");
    for kind in [
        "intent",
        "managed-renewal-plan",
        "producer",
        "helper",
        "candidate",
    ] {
        put(
            &evidence.join(scope.record(kind)),
            b"synthetic immutable pending evidence",
            0o600,
        );
    }
    put(
        &evidence.join(scope.environment_name("helper")),
        b"PUBLIC_FIXTURE=true\n",
        0o600,
    );
    // Infrastructure retries are retained before and after the successful
    // producer; their presence does not authorize another helper execution.
    // Quiescing the old boot unit uses its supported shutdown and retains
    // stop receipts. Neither native phase begins generation activation.
    for phase in ["infrastructure", "stop"] {
        for kind in ["intent", "result"] {
            put(
                &evidence.join(format!(
                    "generation-compose-{}-{kind}.json",
                    scope.operation(phase, 2)
                )),
                b"synthetic retained infrastructure or stop evidence",
                0o600,
            );
        }
    }
    let work = scope.work(&f.installation);
    for relative in ["current", "identity", "transfer/delivered"] {
        let path = work.join(relative);
        fs::create_dir_all(&path).unwrap();
        let mut current = path.as_path();
        while current != f.installation {
            fs::set_permissions(current, fs::Permissions::from_mode(0o700)).unwrap();
            current = current.parent().unwrap();
        }
    }
    put(
        &work.join("current/workload_token"),
        b"original opaque fixture",
        0o444,
    );
    put(
        &work.join("identity/renewal-secret-id"),
        b"retained opaque fixture",
        0o600,
    );
    put(
        &work.join("transfer/delivered/workload_token"),
        b"candidate opaque fixture",
        0o444,
    );
    for name in ["pending.json", "validated.json", "completed.json"] {
        put(&work.join("transfer/delivered").join(name), b"{}", 0o600);
    }
    scope
}

fn pending_transition(
    f: &Fixture,
    scope: installer_generation_maintenance::attempt::Attempt,
) -> Transition {
    let mut transition = f.intent.transition.clone();
    let files = pending_custody(&f.installation, scope, None).unwrap();
    transition.managed_producer_recovery = Some(ManagedProducerRecovery {
        schema: "elevenid.installer-operator-managed-producer-recovery/v1".into(),
        sequence: scope.sequence,
        attempt: 0,
        parent_binding_sha256: "b".repeat(64),
        candidate_sha256: files[&format!("evidence/{}", scope.record("candidate"))].clone(),
        helper_sha256: files[&format!("evidence/{}", scope.record("helper"))].clone(),
        outputs_sha256: BTreeMap::from([(
            "workload_token".into(),
            files["work/transfer/delivered/workload_token"].clone(),
        )]),
        preserved_files_sha256: files,
    });
    transition
}

#[test]
fn recovery_profile_preserves_legacy_bytes_and_rejects_unknown_source_or_active_attempt() {
    let legacy = Fixture::new();
    let bytes = encode(&legacy.intent).unwrap();
    assert!(!String::from_utf8(bytes.clone())
        .unwrap()
        .contains("managed_producer_recovery"));
    assert_eq!(encode(&decode::<Intent>(&bytes).unwrap()).unwrap(), bytes);
    assert_eq!(contract_for(ORIGINAL_SOURCE).unwrap(), legacy_contract());
    assert_eq!(
        contract_for(MANAGED_RECOVERY_SOURCE).unwrap(),
        managed_recovery_contract()
    );
    assert!(contract_for(&"f".repeat(40)).is_err());

    let completed = json!({"sequence":2,"attempt":0,"stage":"producer_completed"});
    assert_eq!(
        managed_pending_scope(MANAGED_RECOVERY_SOURCE, 1, &completed)
            .unwrap()
            .sequence,
        2
    );
    for source in [ORIGINAL_SOURCE, "unknown"] {
        assert!(managed_pending_scope(source, 1, &completed).is_err());
    }
    for stage in [
        "producer_pending",
        "producer_start_outcome_unobserved",
        "runtime_replacement_pending",
        "selection_pending",
        "supersession_pending",
        "managed_preparation_saved",
    ] {
        let mut changed = completed.clone();
        changed["stage"] = json!(stage);
        assert!(managed_pending_scope(MANAGED_RECOVERY_SOURCE, 1, &changed).is_err());
    }
    for changed in [
        json!({"sequence":3,"attempt":0,"stage":"producer_completed"}),
        json!({"sequence":2,"attempt":1,"stage":"producer_completed"}),
        json!({"sequence":2,"stage":"producer_completed"}),
    ] {
        assert!(managed_pending_scope(MANAGED_RECOVERY_SOURCE, 1, &changed).is_err());
    }
    assert!(managed_pending_scope(MANAGED_RECOVERY_SOURCE, u64::MAX, &completed).is_err());
}

#[test]
fn completed_managed_custody_survives_operator_selection_without_rewriting_pending_or_original() {
    let mut f = Fixture::with_source(MANAGED_RECOVERY_SOURCE);
    let scope = pending_files(&f);
    f.intent.transition = pending_transition(&f, scope);
    let before = pending_custody(&f.installation, scope, None).unwrap();
    validate_intent(
        &f.intent,
        &f.intent.retained,
        None,
        &f.intent.retained.original_operator,
    )
    .unwrap();
    f.stage();
    assert_eq!(
        pending_custody(&f.installation, scope, None).unwrap(),
        before
    );
    let mut held = LockedMaintenance::open(&f.installation).unwrap();
    let h = history(held.inspection(), &f.installation).unwrap();
    let observed = Cell::new(0);
    select_with(&mut held, &f.intent, &h, false, |_| {
        observed.set(observed.get() + 1);
        require(pending_custody(&f.installation, scope, None)? == before)
    })
    .unwrap();
    assert_eq!(observed.get(), 2);
    assert_eq!(
        status_locked(held.inspection(), &f.installation).unwrap()["phase"],
        "selected"
    );
    assert_eq!(
        pending_custody(&f.installation, scope, None).unwrap(),
        before
    );
    f.originals_unchanged();
}

#[test]
fn pending_handoff_refuses_binding_activation_supersession_and_native_activation_races() {
    for suffix in [
        "binding",
        "binding-pending",
        "activation-intent",
        "activation",
        "supersession-intent",
    ] {
        let f = Fixture::with_source(MANAGED_RECOVERY_SOURCE);
        let scope = pending_files(&f);
        pending_custody(&f.installation, scope, None).unwrap();
        put(
            &f.installation.join("evidence").join(scope.record(suffix)),
            b"racing record",
            0o600,
        );
        assert!(
            pending_custody(&f.installation, scope, None).is_err(),
            "{suffix}"
        );
    }
    let f = Fixture::with_source(MANAGED_RECOVERY_SOURCE);
    let scope = pending_files(&f);
    put(
        &f.installation.join("evidence").join(format!(
            "generation-compose-{}-intent.json",
            scope.operation("activate-create", 0)
        )),
        b"racing native activation",
        0o600,
    );
    assert!(pending_custody(&f.installation, scope, None).is_err());
}

#[test]
fn pending_handoff_rechecks_changed_candidate_or_binding_at_atomic_publication() {
    for change in 0..3 {
        let mut f = Fixture::with_source(MANAGED_RECOVERY_SOURCE);
        let scope = pending_files(&f);
        f.intent.transition = pending_transition(&f, scope);
        let before = pending_custody(&f.installation, scope, None).unwrap();
        f.stage();
        let mut held = LockedMaintenance::open(&f.installation).unwrap();
        let h = history(held.inspection(), &f.installation).unwrap();
        let calls = Cell::new(0);
        assert!(select_with(&mut held, &f.intent, &h, false, |_| {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                let path = match change {
                    0 => f
                        .installation
                        .join("evidence")
                        .join(scope.record("candidate")),
                    1 => scope
                        .work(&f.installation)
                        .join("transfer/delivered/workload_token"),
                    _ => f
                        .installation
                        .join("evidence")
                        .join(scope.record("binding")),
                };
                if change == 1 {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                }
                put(
                    &path,
                    b"changed after initial admission",
                    if change == 1 { 0o444 } else { 0o600 },
                );
            }
            require(pending_custody(&f.installation, scope, None)? == before)
        })
        .is_err());
        assert!(!f.installation.join("evidence").join(SELECTOR).exists());
        assert_eq!(calls.get(), 2);
    }
}

#[test]
fn recovery_profile_still_requires_quiescent_predecessors_before_selection() {
    let mut f = Fixture::with_source(MANAGED_RECOVERY_SOURCE);
    let scope = pending_files(&f);
    f.intent.transition = pending_transition(&f, scope);
    f.stage();
    let mut held = LockedMaintenance::open(&f.installation).unwrap();
    let h = history(held.inspection(), &f.installation).unwrap();
    assert!(select_with(&mut held, &f.intent, &h, false, |_| {
        Err("predecessor unit is active or enabled".into())
    })
    .is_err());
    assert!(!f.installation.join("evidence").join(SELECTOR).exists());
    assert!(!f
        .installation
        .join("evidence")
        .join(record(1, "activation"))
        .exists());
    f.originals_unchanged();
}

#[test]
fn completed_helper_census_rejects_restart_replacement_and_live_execution() {
    let f = Fixture::new();
    let saved: installer_doctor::SavedSession =
        decode(&fs::read(f.installation.join("evidence/compose-session.json")).unwrap()).unwrap();
    let mut expected = saved.receipt.resources.unwrap();
    let mut helper = expected.containers["gateway"].clone();
    helper.id = "3".repeat(64);
    helper.service = "installer-generation".into();
    helper.setup = true;
    helper.setup_execution = Some(crate::installer_compose::SetupExecution {
        started_at: "2026-11-28T00:00:01Z".into(),
        finished_at: "2026-11-28T00:00:02Z".into(),
        completed_without_restart: true,
    });
    expected
        .containers
        .insert(helper.service.clone(), helper.clone());
    let rows = vec![
        json!({"Service":"gateway","ID":expected.containers["gateway"].id,"State":"running","Health":"unhealthy"}),
        json!({"Service":"installer-generation","ID":helper.id,"State":"exited","ExitCode":0}),
    ];
    // An unhealthy retained runtime is the recovery use case; it confers no
    // authority to replace it during operator selection.
    require_completed_census(&expected, &expected, &rows).unwrap();
    for change in 0..4 {
        let mut observed = expected.clone();
        match change {
            0 => {
                observed
                    .containers
                    .get_mut("installer-generation")
                    .unwrap()
                    .id = "4".repeat(64)
            }
            1 => {
                observed
                    .containers
                    .get_mut("installer-generation")
                    .unwrap()
                    .setup_execution
                    .as_mut()
                    .unwrap()
                    .started_at = "later".into()
            }
            2 => observed.containers.get_mut("gateway").unwrap().id = "4".repeat(64),
            _ => {
                observed.volumes.insert("foreign-volume".into());
            }
        }
        assert!(require_completed_census(&expected, &observed, &rows).is_err());
    }
    let mut running = rows.clone();
    running[1]["State"] = json!("running");
    assert!(require_completed_census(&expected, &expected, &running).is_err());
    let mut failed = rows.clone();
    failed[1]["ExitCode"] = json!(1);
    assert!(require_completed_census(&expected, &expected, &failed).is_err());
    assert!(require_completed_census(&expected, &expected, &rows[..1]).is_err());
}

use super::*;
use crate::{
    installer_compose::{
        BoundFile, ComposeInputs, ComposeReceipt, ContainerIdentity, ProjectResources,
    },
    installer_state::InstallerState,
};
use std::{
    cell::Cell,
    fs,
    os::unix::fs::{symlink, PermissionsExt},
};

fn put(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}
fn release_files(source: &str, version: &str, binary: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let sha = release::sha256(binary);
    let inventory = json!({"schema":"elevenid.installer-inventory/v1","repository":release::REPOSITORY,
        "platform":"linux/amd64","source_sha":source,"release_tag":version,"build_run_id":42,"build_run_attempt":1,
        "artifacts":[{"name":"install.sh","sha256":"a".repeat(64),"size":1},
            {"name":"marty-deploy-linux-amd64","sha256":sha,"size":binary.len()},
            {"name":"prepared-selfhost-bundle.zip","sha256":"b".repeat(64),"size":1},
            {"name":"prepared-selfhost-images.json","sha256":"c".repeat(64),"size":1}],
        "images":{"gateway":format!("example.invalid/gateway@sha256:{}","d".repeat(64)),
            "openbao_didcomm_image":format!("example.invalid/openbao@sha256:{}","e".repeat(64))}});
    let inventory = encode(&inventory).unwrap();
    let admission=encode(&json!({"schema":"elevenid.installer-admission/v1","repository":release::REPOSITORY,
        "platform":"linux/amd64","status":"accepted","source_sha":source,"release_tag":version,
        "inventory_sha256":release::sha256(&inventory),"operator_sha256":sha,"build_run_id":42,"build_run_attempt":1,
        "promotion_source_sha":"f".repeat(40),"promotion_run_id":43,"promotion_run_attempt":1,
        "acceptance":{"staged":{"sha256":"a".repeat(64),"run_id":40,"run_attempt":1},
            "published":{"sha256":"b".repeat(64),"run_id":41,"run_attempt":1}}})).unwrap();
    let mut files = BTreeMap::from([
        ("installer-admission.json".into(), admission),
        ("installer-inventory.json".into(), inventory),
    ]);
    for name in ASSETS
        .into_iter()
        .filter(|n| n.ends_with("sigstore.json") || n.ends_with("provenance.jsonl"))
    {
        files.insert(
            name.into(),
            b"synthetic public proof fixture; not an authentication substitute".to_vec(),
        );
    }
    files
}
fn operator(files: &BTreeMap<String, Vec<u8>>, binary: &[u8], source: &str, tag: &str) -> Operator {
    target_from(
        &files["installer-admission.json"],
        &files["installer-inventory.json"],
        &release::sha256(binary),
        source,
        tag,
    )
    .unwrap()
}

struct Fixture {
    _root: tempfile::TempDir,
    installation: PathBuf,
    authenticated: Authenticated,
    intent: Intent,
    units: BTreeMap<String, String>,
    original: BTreeMap<PathBuf, Vec<u8>>,
}
impl Fixture {
    fn new() -> Self {
        Self::with_source(ORIGINAL_SOURCE)
    }
    fn with_source(source: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let installation = root.path().join("installation");
        let old_binary = b"synthetic retained bootstrap operator";
        let old_files = release_files(source, "v1.0.0", old_binary);
        let old = operator(&old_files, old_binary, source, "v1.0.0");
        let identity = Identity {
            source_sha: source.into(),
            release_tag: "v1.0.0".into(),
            inventory_sha256: format!("sha256:{}", old.inventory_sha256),
        };
        let runtime = RuntimeBinding {
            docker_host: format!("unix:///run/user/{}/docker.sock", unsafe {
                libc::geteuid()
            }),
            engine_id: "fixture-engine".into(),
            openbao_port: 18443,
            profile: RuntimeProfile::Rootless,
        };
        let mut state =
            InstallerState::create_with_runtime(&installation, identity, runtime.clone()).unwrap();
        state.create_private_directory("evidence").unwrap();
        for (name, bytes) in old_files {
            state.write_evidence(&name, &bytes).unwrap();
        }
        put(&installation.join("marty-deploy"), old_binary, 0o700);
        let model_path = installation.join("evidence/fixture-compose.json");
        let env_path = installation.join("evidence/fixture.env");
        let project = state.journal().compose_project();
        let image = format!("example.invalid/gateway@sha256:{}", "d".repeat(64));
        let model = json!({"name":project,"services":{"gateway":{"image":image}}});
        let model_bytes = encode(&model).unwrap();
        put(&model_path, &model_bytes, 0o600);
        put(&env_path, b"PUBLIC_FIXTURE=true\n", 0o600);
        let configuration_sha256 = crate::installer_compose::model_sha256(&model).unwrap();
        let bound = BoundFile {
            path: model_path.clone(),
            sha256: release::sha256(&model_bytes),
        };
        let environment = BoundFile {
            path: env_path.clone(),
            sha256: release::sha256(b"PUBLIC_FIXTURE=true\n"),
        };
        let resources = ProjectResources {
            containers: BTreeMap::from([(
                "gateway".into(),
                ContainerIdentity {
                    id: "1".repeat(64),
                    service: "gateway".into(),
                    image: image.clone(),
                    config_hash: "2".repeat(64),
                    setup: false,
                    setup_execution: None,
                    health_required: false,
                    cap_add: BTreeSet::new(),
                    cap_drop: BTreeSet::new(),
                    read_only: true,
                    memory_limit: 67108864,
                },
            )]),
            ..ProjectResources::default()
        };
        let receipt = ComposeReceipt {
            schema: "elevenid.installer-compose-operation/v1".into(),
            project: project.clone(),
            engine_id: runtime.engine_id.clone(),
            operation: "application".into(),
            configuration_sha256: configuration_sha256.clone(),
            input_files: BTreeMap::from([
                (model_path, bound.sha256.clone()),
                (env_path, environment.sha256.clone()),
            ]),
            command_succeeded: true,
            client_exit_code: Some(0),
            failure_class: None,
            observation_validated: true,
            resources: Some(resources),
            status: vec![],
            installation_ready: false,
        };
        let inputs = ComposeInputs {
            installation: installation.clone(),
            project,
            files: vec![bound],
            bound_inputs: vec![],
            environment,
            profiles: vec!["setup".into()],
            services: vec![],
            approved_images: BTreeSet::from([
                image,
                format!("example.invalid/openbao@sha256:{}", "e".repeat(64)),
            ]),
            #[cfg(feature = "installer-development")]
            development_image: None,
            writable_bind_roots: BTreeSet::new(),
            readonly_bind_roots: BTreeSet::new(),
            allowed_loopback_ports: BTreeSet::new(),
            ingress_listener: None,
            prior: Some(receipt.clone()),
        };
        let saved = installer_doctor::SavedSession {
            schema: "elevenid.installer-compose-session/v1".into(),
            installation_id: state.journal().installation_id().to_string(),
            inputs,
            model,
            configuration_sha256,
            receipt,
        };
        state
            .write_evidence("compose-session.json", &encode(&saved).unwrap())
            .unwrap();
        for phase in [
            Phase::Verified,
            Phase::Provisioning,
            Phase::Provisioned,
            Phase::Ready,
        ] {
            state.advance(phase).unwrap();
        }
        drop(state);
        let mut held = LockedMaintenance::open(&installation).unwrap();
        crate::installer_lifecycle::install_locked(
            &mut held,
            &installation,
            Path::new("/usr/bin/docker"),
        )
        .unwrap();
        let retained = retained(held.inspection(), &installation).unwrap();
        let binary = b"synthetic corrected successor operator";
        let assets = release_files(&"a".repeat(40), "v1.0.1", binary);
        let target = operator(&assets, binary, &"a".repeat(40), "v1.0.1");
        let executable = root.path().join("incoming-marty-deploy");
        put(&executable, binary, 0o700);
        let units = crate::installer_lifecycle::successor_unit_exports(
            held.inspection(),
            &installation,
            Path::new("/usr/bin/docker"),
            &target.path(&installation),
            1,
        )
        .unwrap();
        let intent = Intent {
            schema: "elevenid.installer-operator-upgrade-intent/v1".into(),
            sequence: 1,
            retained,
            transition: Transition {
                session_sha256: digest(&saved).unwrap(),
                generation_selector_sha256: None,
                resources_sha256: digest(&saved.receipt.resources).unwrap(),
                managed_producer_recovery: None,
            },
            previous: None,
            target: target.clone(),
            assets: assets
                .iter()
                .map(|(k, v)| (k.clone(), release::sha256(v)))
                .collect(),
            compatibility: contract_for(source).unwrap(),
            docker: "/usr/bin/docker".into(),
            unit_files: units
                .iter()
                .map(|(k, v)| (k.clone(), release::sha256(v.as_bytes())))
                .collect(),
        };
        let mut original = BTreeMap::new();
        for path in [
            installation.join("installation.json"),
            installation.join("marty-deploy"),
        ] {
            original.insert(path.clone(), fs::read(path).unwrap());
        }
        for entry in fs::read_dir(installation.join("evidence")).unwrap() {
            let path = entry.unwrap().path();
            original.insert(path.clone(), fs::read(path).unwrap());
        }
        drop(held);
        Self {
            _root: root,
            installation,
            authenticated: Authenticated {
                target,
                assets,
                executable,
            },
            intent,
            units,
            original,
        }
    }
    fn stage(&self) {
        let mut held = LockedMaintenance::open(&self.installation).unwrap();
        persist(
            &mut held,
            &self.installation,
            &record(1, "intent"),
            &encode(&self.intent).unwrap(),
        )
        .unwrap();
        stage_files(&mut held, &self.intent, &self.authenticated, &self.units).unwrap();
    }
    fn originals_unchanged(&self) {
        for (path, bytes) in &self.original {
            assert_eq!(&fs::read(path).unwrap(), bytes, "{}", path.display());
        }
    }
}

#[test]
fn compiled_contract_and_arguments_exclude_product_schema_and_authority_changes() {
    assert_eq!(legacy_contract()["original_source_sha"], ORIGINAL_SOURCE);
    assert_eq!(contract()["profiles"][0], legacy_contract());
    assert_eq!(contract()["profiles"][1], managed_recovery_contract());
    assert_eq!(
        managed_recovery_contract()["original_source_sha"],
        MANAGED_RECOVERY_SOURCE
    );
    for field in [
        "database_migration",
        "credential_issuance",
        "key_custody_change",
        "bootstrap_operator_replacement",
    ] {
        assert_eq!(legacy_contract()[field], false);
        assert_eq!(managed_recovery_contract()[field], false);
    }
    let good: Vec<String> = [
        "stage",
        "--install-dir",
        "/private/install",
        "--target-assets",
        "/private/assets",
        "--tools-dir",
        "/private/tools",
        "--gh-bin",
        "/private/gh",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert!(arguments(&good).is_ok());
    for option in [
        "--product-images",
        "--database-schema",
        "--compatibility",
        "--allow-downgrade",
        "--force",
    ] {
        let mut args = good.clone();
        args.extend([option.into(), "anything".into()]);
        assert!(arguments(&args).is_err());
    }
    for tail in [
        vec!["--sequence", "0"],
        vec!["--sequence", "33"],
        vec!["--install-dir", "/different"],
    ] {
        let mut args = good.clone();
        args.extend(tail.into_iter().map(str::to_owned));
        assert!(arguments(&args).is_err());
    }
}

#[test]
fn compatibility_rejects_wrong_owner_model_runtime_contract_and_replay() {
    let f = Fixture::new();
    validate_intent(
        &f.intent,
        &f.intent.retained,
        None,
        &f.intent.retained.original_operator,
    )
    .unwrap();
    for change in 0..10 {
        let mut i = f.intent.clone();
        match change {
            0 => i.retained.installation_id = uuid::Uuid::new_v4(),
            1 => i.retained.runtime.engine_id = "another-engine".into(),
            2 => i.retained.initial_model_sha256 = "f".repeat(64),
            3 => i.retained.product_images_sha256 = "f".repeat(64),
            4 => i.compatibility["database_migration"] = json!(true),
            5 => i.target = f.intent.retained.original_operator.clone(),
            6 => i.target.release_tag = "v0.9.9".into(),
            7 => i.retained.original_release.source_sha = "f".repeat(40),
            8 => i.compatibility["journal_schema"] = json!("unknown"),
            _ => {
                i.assets.remove("installer-admission.json");
            }
        }
        assert!(
            validate_intent(
                &i,
                &f.intent.retained,
                None,
                &f.intent.retained.original_operator
            )
            .is_err(),
            "case {change}"
        );
    }
    assert!(release_order("v1.0.1-nightly.20261112.1").unwrap() < release_order("v1.0.1").unwrap());
    assert!(release_order("v1.0.2-nightly.20261112.1").unwrap() > release_order("v1.0.1").unwrap());
    assert!(release_order("latest").is_err());
}

#[test]
fn signed_record_binding_never_accepts_a_different_operator_or_producer() {
    let f = Fixture::new();
    let a = &f.authenticated.assets["installer-admission.json"];
    let i = &f.authenticated.assets["installer-inventory.json"];
    let target = &f.authenticated.target;
    for (sha, source, tag) in [
        (
            "f".repeat(64),
            target.source_sha.clone(),
            target.release_tag.clone(),
        ),
        (
            target.sha256.clone(),
            "f".repeat(40),
            target.release_tag.clone(),
        ),
        (
            target.sha256.clone(),
            target.source_sha.clone(),
            "v2.0.0".into(),
        ),
    ] {
        assert!(target_from(a, i, &sha, &source, &tag).is_err());
    }
    let mut different: Value = decode(i).unwrap();
    different["build_run_attempt"] = json!(2);
    assert!(target_from(
        a,
        &encode(&different).unwrap(),
        &target.sha256,
        &target.source_sha,
        &target.release_tag
    )
    .is_err());
}

#[test]
fn staging_preserves_history_and_exports_distinct_units_without_claiming_activation() {
    let f = Fixture::new();
    f.stage();
    f.originals_unchanged();
    let held = LockedInspection::open(&f.installation).unwrap();
    let status = status_locked(&held, &f.installation).unwrap();
    assert_eq!(status["phase"], "staged");
    assert!(status["selected_operator"].is_null());
    assert_eq!(status["runtime_activated"], false);
    assert_eq!(status["scheduler_activation"], "not_assessed");
    assert_eq!(status["historical_units_retargeted"], false);
    assert!(require_selected_caller(&held, &f.installation).is_err());
    assert!(!f.installation.join("evidence").join(SELECTOR).exists());
    let original: BTreeSet<_> =
        crate::installer_lifecycle::operator_unit_names(f.intent.retained.installation_id, None)
            .into_iter()
            .collect();
    assert!(f.intent.unit_files.keys().all(|n| !original.contains(n)));
    for text in f.units.values().filter(|text| text.contains("ExecStart=")) {
        assert!(text.contains(f.intent.target.path(&f.installation).to_str().unwrap()));
        assert!(!text.contains(&format!(
            "\"{}\"",
            f.installation.join("marty-deploy").display()
        )));
    }
}

#[test]
fn interrupted_first_intent_remains_inert_and_resumes_only_a_matching_prefix() {
    for length in [0, 37, usize::MAX] {
        let f = Fixture::new();
        let bytes = encode(&f.intent).unwrap();
        let partial = f
            .installation
            .join("evidence")
            .join(format!("partial-{}", record(1, "intent")));
        put(&partial, &bytes[..length.min(bytes.len())], 0o600);
        let mut held = LockedMaintenance::open(&f.installation).unwrap();
        let h = history(held.inspection(), &f.installation).unwrap();
        assert_eq!(h.incomplete_intent, Some(1));
        assert_eq!(h.pending_sequence(), Some(1));
        assert!(h.attempts.is_empty() && h.selector.is_none());
        assert_eq!(
            status_locked(held.inspection(), &f.installation).unwrap()["phase"],
            "intent_incomplete"
        );
        assert!(require_selected_caller(held.inspection(), &f.installation).is_err());
        persist(&mut held, &f.installation, &record(1, "intent"), &bytes).unwrap();
        stage_files(&mut held, &f.intent, &f.authenticated, &f.units).unwrap();
        assert!(!partial.exists());
        assert_eq!(
            status_locked(held.inspection(), &f.installation).unwrap()["phase"],
            "staged"
        );
        f.originals_unchanged();
    }
    let f = Fixture::new();
    put(
        &f.installation
            .join("evidence")
            .join(format!("partial-{}", record(1, "intent"))),
        b"unrelated",
        0o600,
    );
    let mut held = LockedMaintenance::open(&f.installation).unwrap();
    assert!(persist(
        &mut held,
        &f.installation,
        &record(1, "intent"),
        &encode(&f.intent).unwrap()
    )
    .is_err());
    assert!(!f.intent.target.path(&f.installation).exists());
    assert!(!f.installation.join("evidence").join(SELECTOR).exists());
    f.originals_unchanged();
}

#[test]
fn unavailable_or_changed_predecessor_observation_never_selects_and_poisoning_retains_lock() {
    let f = Fixture::new();
    f.stage();
    let mut held = LockedMaintenance::open(&f.installation).unwrap();
    let h = history(held.inspection(), &f.installation).unwrap();
    assert!(select_with(&mut held, &f.intent, &h, false, |_| Err(
        "user manager unavailable".into()
    ))
    .is_err());
    assert!(!f.installation.join("evidence").join(SELECTOR).exists());
    let count = Cell::new(0);
    assert!(select_with(&mut held, &f.intent, &h, false, |_| {
        count.set(count.get() + 1);
        if count.get() == 1 {
            Ok(())
        } else {
            Err("old timer became active".into())
        }
    })
    .is_err());
    assert_eq!(count.get(), 2);
    assert!(!f.installation.join("evidence").join(SELECTOR).exists());
    assert!(held.require_unchanged().is_err());
    assert!(LockedMaintenance::open(&f.installation).is_err());
    drop(held);
    let mut held = LockedMaintenance::open(&f.installation).unwrap();
    let h = history(held.inspection(), &f.installation).unwrap();
    assert_eq!(
        status_locked(held.inspection(), &f.installation).unwrap()["phase"],
        "selection_pending"
    );
    select_with(&mut held, &f.intent, &h, true, |_| Ok(())).unwrap();
    assert_eq!(
        status_locked(held.inspection(), &f.installation).unwrap()["phase"],
        "selected"
    );
    f.originals_unchanged();
}

#[test]
fn selected_owner_is_explicit_and_a_different_running_binary_cannot_mutate() {
    let f = Fixture::new();
    f.stage();
    let mut held = LockedMaintenance::open(&f.installation).unwrap();
    let h = history(held.inspection(), &f.installation).unwrap();
    select_with(&mut held, &f.intent, &h, false, |_| Ok(())).unwrap();
    let status = status_locked(held.inspection(), &f.installation).unwrap();
    assert_eq!(status["phase"], "selected");
    assert_eq!(
        status["selected_operator"]["operator"]["sha256"],
        f.intent.target.sha256
    );
    assert_eq!(status["runtime_activated"], false);
    assert_eq!(status["scheduler_activation"], "not_assessed");
    assert_eq!(
        selected_unit_exports(held.inspection(), &f.installation).unwrap(),
        f.units
    );
    assert!(require_selected_caller(held.inspection(), &f.installation).is_err());
    assert!(h.selector.is_none());
    f.originals_unchanged();
}

#[test]
fn completed_reconciliation_observes_durable_selection_without_republication() {
    use std::os::unix::fs::MetadataExt;
    let f = Fixture::new();
    f.stage();
    let mut held = LockedMaintenance::open(&f.installation).unwrap();
    let h = history(held.inspection(), &f.installation).unwrap();
    select_with(&mut held, &f.intent, &h, false, |_| Ok(())).unwrap();
    let h = history(held.inspection(), &f.installation).unwrap();
    let path = f.installation.join("evidence").join(SELECTOR);
    let before = fs::metadata(&path).unwrap();
    let bytes = fs::read(&path).unwrap();
    reconcile_completed(
        held.inspection(),
        &f.installation,
        &h,
        1,
        &f.authenticated,
        Path::new("/usr/bin/docker"),
    )
    .unwrap();
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(fs::metadata(&path).unwrap().ino(), before.ino());
    assert_eq!(
        fs::metadata(&path).unwrap().mtime_nsec(),
        before.mtime_nsec()
    );
    assert!(reconcile_completed(
        held.inspection(),
        &f.installation,
        &h,
        2,
        &f.authenticated,
        Path::new("/usr/bin/docker")
    )
    .is_err());
    assert!(reconcile_completed(
        held.inspection(),
        &f.installation,
        &h,
        1,
        &f.authenticated,
        Path::new("/different/docker")
    )
    .is_err());
    f.originals_unchanged();
}

#[test]
fn consecutive_successors_require_the_exact_predecessor_and_preserve_both_owners() {
    let f = Fixture::new();
    f.stage();
    let mut held = LockedMaintenance::open(&f.installation).unwrap();
    let h = history(held.inspection(), &f.installation).unwrap();
    select_with(&mut held, &f.intent, &h, false, |_| Ok(())).unwrap();
    let first_selector = fs::read(f.installation.join("evidence").join(SELECTOR)).unwrap();
    let first_binary = fs::read(f.intent.target.path(&f.installation)).unwrap();
    let h = history(held.inspection(), &f.installation).unwrap();
    let binary = b"synthetic second corrected operator";
    let assets = release_files(&"b".repeat(40), "v1.0.2", binary);
    let target = operator(&assets, binary, &"b".repeat(40), "v1.0.2");
    let executable = f._root.path().join("second-marty-deploy");
    put(&executable, binary, 0o700);
    let authenticated = Authenticated {
        target: target.clone(),
        assets,
        executable,
    };
    let units = crate::installer_lifecycle::successor_unit_exports(
        held.inspection(),
        &f.installation,
        Path::new("/usr/bin/docker"),
        &target.path(&f.installation),
        2,
    )
    .unwrap();
    let mut intent = f.intent.clone();
    intent.sequence = 2;
    intent.previous = h.selector.clone();
    intent.target = target;
    intent.assets = authenticated
        .assets
        .iter()
        .map(|(k, v)| (k.clone(), release::sha256(v)))
        .collect();
    intent.unit_files = units
        .iter()
        .map(|(k, v)| (k.clone(), release::sha256(v.as_bytes())))
        .collect();
    validate_intent(
        &intent,
        &f.intent.retained,
        h.selector.as_ref(),
        &f.intent.target,
    )
    .unwrap();
    let mut skipped = intent.clone();
    skipped.previous = None;
    assert!(validate_intent(
        &skipped,
        &f.intent.retained,
        h.selector.as_ref(),
        &f.intent.target
    )
    .is_err());
    persist(
        &mut held,
        &f.installation,
        &record(2, "intent"),
        &encode(&intent).unwrap(),
    )
    .unwrap();
    stage_files(&mut held, &intent, &authenticated, &units).unwrap();
    let staged = history(held.inspection(), &f.installation).unwrap();
    assert_eq!(staged.selected().unwrap().intent.sequence, 1);
    let predecessors = predecessor_units(&f.intent.retained, &staged);
    assert_eq!(predecessors.len(), 10);
    assert!(f
        .intent
        .unit_files
        .keys()
        .all(|name| predecessors.contains(name)));
    assert!(intent
        .unit_files
        .keys()
        .all(|name| !predecessors.contains(name)));
    select_with(&mut held, &intent, &staged, false, |_| Ok(())).unwrap();
    let complete = history(held.inspection(), &f.installation).unwrap();
    assert_eq!(complete.selected().unwrap().intent.sequence, 2);
    assert_eq!(
        encode(complete.attempts[1].intent.previous.as_ref().unwrap()).unwrap(),
        first_selector
    );
    assert_eq!(
        fs::read(f.intent.target.path(&f.installation)).unwrap(),
        first_binary
    );
    assert_eq!(
        selected_unit_exports(held.inspection(), &f.installation).unwrap(),
        units
    );
    assert!(!f
        .installation
        .join("evidence/operator-upgrade-0002-selector.tmp")
        .exists());
    f.originals_unchanged();
}

#[test]
fn cancel_before_activation_preserves_staged_bytes_and_does_not_adopt_them() {
    let f = Fixture::new();
    f.stage();
    let mut held = LockedMaintenance::open(&f.installation).unwrap();
    persist(
        &mut held,
        &f.installation,
        &record(1, "canceled"),
        &encode(&terminal_for(&f.intent, "canceled", None).unwrap()).unwrap(),
    )
    .unwrap();
    let h = history(held.inspection(), &f.installation).unwrap();
    assert!(h.pending().is_none() && h.selected().is_none());
    assert_eq!(
        status_locked(held.inspection(), &f.installation).unwrap()["phase"],
        "original"
    );
    verify_staged(&f.installation, &f.intent).unwrap();
    f.originals_unchanged();
}

#[test]
fn closure_tampering_or_unknown_owner_records_fail_closed() {
    for change in 0..5 {
        let f = Fixture::new();
        f.stage();
        match change {
            0 => put(
                &f.intent.target.path(&f.installation),
                b"substituted executable",
                0o700,
            ),
            1 => put(
                &f.installation
                    .join("operators")
                    .join(&f.intent.target.sha256)
                    .join("installer-admission.json"),
                b"{}",
                0o600,
            ),
            2 => {
                let name = f.intent.unit_files.keys().next().unwrap();
                put(
                    &f.installation
                        .join("operators")
                        .join(&f.intent.target.sha256)
                        .join("units-0001")
                        .join(name),
                    b"wrong executable",
                    0o600,
                );
            }
            3 => put(
                &f.installation
                    .join("evidence/operator-upgrade-0002-staged.json"),
                b"{}",
                0o600,
            ),
            _ => {
                let mut intent = f.intent.clone();
                intent.previous = Some(Selector {
                    schema: "elevenid.installer-operator-owner/v1".into(),
                    installation_id: intent.retained.installation_id,
                    sequence: 1,
                    intent_sha256: "a".repeat(64),
                    staged_sha256: "b".repeat(64),
                });
                put(
                    &f.installation.join("evidence").join(record(1, "intent")),
                    &encode(&intent).unwrap(),
                    0o600,
                );
            }
        }
        let held = LockedInspection::open(&f.installation).unwrap();
        assert!(
            status_locked(&held, &f.installation).is_err(),
            "case {change}"
        );
    }
}

#[test]
fn native_copy_resumes_only_the_same_inert_prefix_and_preserves_published_bytes() {
    for sealed in [false, true] {
        let f = Fixture::new();
        let directory = operator_directory(&f.installation, &f.intent.target, true).unwrap();
        let bytes = fs::read(&f.authenticated.executable).unwrap();
        let path = f
            .installation
            .join("operators")
            .join(&f.intent.target.sha256)
            .join("partial-marty-deploy");
        put(
            &path,
            if sealed { &bytes } else { &bytes[..7] },
            if sealed { 0o700 } else { 0o600 },
        );
        directory
            .copy_operator(&f.authenticated.executable, &f.intent.target)
            .unwrap();
        directory
            .copy_operator(&f.authenticated.executable, &f.intent.target)
            .unwrap();
        assert!(!path.exists());
        assert_eq!(
            fs::read(f.intent.target.path(&f.installation)).unwrap(),
            bytes
        );
    }
    let f = Fixture::new();
    let directory = operator_directory(&f.installation, &f.intent.target, true).unwrap();
    let partial = f
        .installation
        .join("operators")
        .join(&f.intent.target.sha256)
        .join("partial-marty-deploy");
    put(&partial, b"foreign", 0o600);
    assert!(directory
        .copy_operator(&f.authenticated.executable, &f.intent.target)
        .is_err());
    assert!(!f.intent.target.path(&f.installation).exists());
}

#[test]
fn publication_rejects_symlinks_hardlinks_and_rebound_directories() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let directory = Directory::open(root.path()).unwrap();
    put(&root.path().join("target"), b"old", 0o600);
    symlink("target", root.path().join("receipt")).unwrap();
    assert!(directory.publish("receipt", b"next", 0o600).is_err());
    assert_eq!(fs::read(root.path().join("target")).unwrap(), b"old");
    fs::remove_file(root.path().join("receipt")).unwrap();
    fs::hard_link(root.path().join("target"), root.path().join("receipt")).unwrap();
    assert!(directory.publish("receipt", b"old", 0o600).is_err());
    let child = directory.child("child", true).unwrap();
    fs::rename(
        root.path().join("child"),
        root.path().join("retained-child"),
    )
    .unwrap();
    fs::create_dir(root.path().join("child")).unwrap();
    fs::set_permissions(root.path().join("child"), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(child.publish("receipt", b"next", 0o600).is_err());
}

#[test]
fn lost_selector_response_retains_predecessor_until_observation_and_never_replays() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let directory = Directory::open(root.path()).unwrap();
    directory.publish(SELECTOR, b"original", 0o600).unwrap();
    assert!(
        private::replace_selector(&directory, Some(b"original"), b"successor", 1, |phase| {
            if phase == 2 {
                Err("lost response".into())
            } else {
                Ok(())
            }
        })
        .is_err()
    );
    assert_eq!(
        directory.read(SELECTOR, 100, 0o600).unwrap().unwrap(),
        b"successor"
    );
    assert_eq!(
        directory
            .read("operator-upgrade-0001-selector.tmp", 100, 0o600)
            .unwrap()
            .unwrap(),
        b"original"
    );
    assert!(
        private::replace_selector(&directory, Some(b"original"), b"successor", 1, |_| Ok(()))
            .is_err()
    );
    private::reconcile_selector_temporary(&directory, 1, Some(b"original")).unwrap();
    assert_eq!(
        directory.read(SELECTOR, 100, 0o600).unwrap().unwrap(),
        b"successor"
    );
    assert!(!root
        .path()
        .join("operator-upgrade-0001-selector.tmp")
        .exists());
}

#[test]
fn unclassified_original_status_does_not_invent_successor_or_require_an_evidence_directory() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("install");
    let state = InstallerState::create(
        &path,
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.0.0".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        },
    )
    .unwrap();
    drop(state);
    let held = LockedInspection::open(&path).unwrap();
    let result = status_locked(&held, &path).unwrap();
    assert_eq!(result["phase"], "original");
    assert!(result["selected_operator"].is_null());
}
