//! Recovery admits the complete model without requiring future producer inputs.
//! Synthetic local fixtures do not open a Docker socket or run Compose.
use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

const SELECTED: [&str; 3] = ["openbao", "openbao-unseal", "installer-acme-http01"];
const FUTURE_INPUTS: [(&str, &str, bool); 4] = [
    ("generation-transfer", "/transfer", false),
    ("generation-inputs", "/input/current", true),
    ("generation-identity", "/input/identity", true),
    (
        "evidence/generation-public-ingress-plan.json",
        "/input/public-ingress-plan.json",
        true,
    ),
];

struct Fixture {
    root: tempfile::TempDir,
    inputs: ComposeInputs,
    model: Value,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for directory in ["inputs", "state", "evidence"] {
            fs::create_dir(root.path().join(directory)).unwrap();
        }
        fs::write(root.path().join("inputs/retained"), "retained source").unwrap();
        let project = format!("marty-install-{}", "a".repeat(32));
        let image = format!("example.invalid/runtime@sha256:{}", "b".repeat(64));
        let service = json!({"image":image,"init":true,"mem_limit":67108864,
        "security_opt":["no-new-privileges:true"],"restart":"no",
        "labels":{SETUP_LABEL:"runtime"},"volumes":[{
            "type":"bind","source":root.path().join("inputs/retained"),
            "target":"/input/retained","read_only":true,
            "bind":{"create_host_path":false}
        }]});
        let mut model = json!({"name":project,"services":{}});
        let mut prior = ProjectResources::default();
        for (index, role) in SELECTED
            .into_iter()
            .chain(["application", "bootstrap"])
            .enumerate()
        {
            model["services"][role] = service.clone();
            let setup = role == "bootstrap";
            if setup {
                model["services"][role]["labels"][SETUP_LABEL] = json!("setup");
            }
            prior.containers.insert(
                role.into(),
                ContainerIdentity {
                    id: format!("{index:02x}").repeat(32),
                    service: role.into(),
                    image: image.clone(),
                    config_hash: "c".repeat(64),
                    setup,
                    setup_execution: setup.then(|| SetupExecution {
                        started_at: "2026-11-01T00:00:01Z".into(),
                        finished_at: "2026-11-01T00:00:02Z".into(),
                        completed_without_restart: true,
                    }),
                    health_required: false,
                    cap_add: BTreeSet::new(),
                    cap_drop: BTreeSet::new(),
                    read_only: false,
                    memory_limit: 67108864,
                },
            );
        }
        model["services"]["openbao-unseal"]["depends_on"] =
            json!({"openbao":{"condition":"service_healthy"}});
        model["services"]["installer-generation"] = service;
        model["services"]["installer-generation"]["labels"][SETUP_LABEL] = json!("setup");
        model["services"]["installer-generation"]["volumes"] =
            json!(FUTURE_INPUTS.map(|(source, target, readonly)| {
                json!({"type":"bind","source":root.path().join(source),"target":target,
                "read_only":readonly,"bind":{"create_host_path":false}})
            }));
        let mut files = Vec::new();
        for name in ["compose.yml", "runtime.env"] {
            let path = root.path().join(name);
            fs::write(&path, "synthetic bound input").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            files.push(BoundFile {
                path,
                sha256: sha256(b"synthetic bound input"),
            });
        }
        let environment = files.pop().unwrap();
        let inputs = ComposeInputs {
            installation: root.path().into(),
            project: project.clone(),
            files,
            bound_inputs: Vec::new(),
            environment,
            profiles: vec!["setup".into()],
            services: SELECTED.map(str::to_owned).into(),
            approved_images: BTreeSet::from([image]),
            #[cfg(feature = "installer-development")]
            development_image: None,
            writable_bind_roots: ["state", "generation-transfer"]
                .map(|p| root.path().join(p))
                .into(),
            readonly_bind_roots: [
                "inputs",
                "evidence",
                "generation-inputs",
                "generation-identity",
            ]
            .map(|p| root.path().join(p))
            .into(),
            allowed_loopback_ports: BTreeSet::from([18443]),
            ingress_listener: None,
            prior: Some(ComposeReceipt {
                schema: "elevenid.installer-compose-operation/v1".into(),
                project,
                engine_id: "test-engine".into(),
                operation: "acme-http01".into(),
                configuration_sha256: "d".repeat(64),
                input_files: BTreeMap::new(),
                command_succeeded: true,
                client_exit_code: Some(0),
                failure_class: None,
                observation_validated: true,
                resources: Some(prior),
                status: Vec::new(),
                installation_ready: false,
            }),
        };
        Self {
            root,
            inputs,
            model,
        }
    }

    fn admit(&self) -> Result<Option<BTreeSet<String>>> {
        ModelAdmission::RetainedRuntime.admit(&self.model, &self.inputs)
    }
}

#[test]
fn retained_recovery_defers_the_four_unretained_generation_sources_only() {
    let fixture = Fixture::new();
    let original = fixture.model.clone();
    assert_eq!(
        fixture.admit().unwrap(),
        Some(SELECTED.map(str::to_owned).into())
    );
    assert_eq!(
        fixture.model, original,
        "the native model remains unmodified"
    );
    for (source, _, _) in FUTURE_INPUTS {
        assert!(!fixture.root.path().join(source).exists());
    }
    for admission in [ModelAdmission::Selected, ModelAdmission::Complete] {
        assert!(
            admission.admit(&fixture.model, &fixture.inputs).is_err(),
            "ordinary and new-generation admission must require these inputs"
        );
    }
    for (source, _, _) in FUTURE_INPUTS {
        let path = fixture.root.path().join(source);
        if source.ends_with(".json") {
            fs::write(path, "{}").unwrap();
        } else {
            fs::create_dir(path).unwrap();
        }
    }
    for admission in [ModelAdmission::Selected, ModelAdmission::Complete] {
        assert!(admission
            .admit(&fixture.model, &fixture.inputs)
            .unwrap()
            .is_none());
    }
}

#[test]
fn every_retained_role_still_requires_its_bind_secret_and_config_sources() {
    let fixture = Fixture::new();
    for role in SELECTED.into_iter().chain(["application", "bootstrap"]) {
        for kind in ["bind", "secrets", "configs"] {
            let mut model = fixture.model.clone();
            let missing = fixture.root.path().join("inputs/not-created-yet");
            if kind == "bind" {
                model["services"][role]["volumes"][0]["source"] = json!(missing);
            } else {
                model[kind] = json!({"future":{"file":missing}});
                model["services"][role][kind] = json!([{"source":"future"}]);
            }
            assert!(
                ModelAdmission::RetainedRuntime
                    .admit(&model, &fixture.inputs)
                    .is_err(),
                "accepted missing {kind} source for retained {role}"
            );
        }
    }
    let mut retained_generation = fixture.inputs.clone();
    let resources = retained_generation
        .prior
        .as_mut()
        .unwrap()
        .resources
        .as_mut()
        .unwrap();
    let mut generation = resources.containers["bootstrap"].clone();
    generation.service = "installer-generation".into();
    resources
        .containers
        .insert(generation.service.clone(), generation);
    assert!(
        ModelAdmission::RetainedRuntime
            .admit(&fixture.model, &retained_generation)
            .is_err(),
        "a retained generation producer cannot defer its missing sources"
    );
}

#[test]
fn retained_recovery_preserves_canonical_and_single_link_source_custody() {
    let fixture = Fixture::new();
    let retained = fixture.root.path().join("inputs/retained");
    let target = fixture.root.path().join("inputs/target");
    fs::rename(&retained, &target).unwrap();
    symlink(&target, &retained).unwrap();
    assert!(fixture.admit().is_err());
    fs::remove_file(&retained).unwrap();
    fs::hard_link(&target, &retained).unwrap();
    assert!(fixture.admit().is_err());
    fs::remove_file(&target).unwrap();
    fixture.admit().unwrap();
}

#[test]
fn deferred_file_declarations_remain_strict_when_shared_with_a_retained_role() {
    let fixture = Fixture::new();
    for kind in ["secrets", "configs"] {
        let mut model = fixture.model.clone();
        model["services"]["installer-generation"]["volumes"] = json!([]);
        model[kind] = json!({"future":{"file":fixture.root.path().join("inputs/not-created-yet")}});
        model["services"]["installer-generation"][kind] = json!([{"source":"future"}]);
        ModelAdmission::RetainedRuntime
            .admit(&model, &fixture.inputs)
            .unwrap();
        assert!(ModelAdmission::Complete
            .admit(&model, &fixture.inputs)
            .is_err());
        for field in ["external", "environment", "content"] {
            let mut wrong = model.clone();
            wrong[kind]["future"][field] = if field == "external" {
                json!(true)
            } else {
                json!("external")
            };
            assert!(
                ModelAdmission::RetainedRuntime
                    .admit(&wrong, &fixture.inputs)
                    .is_err(),
                "{kind}/{field}"
            );
        }
        model["services"]["application"][kind] = json!([{"source":"future"}]);
        assert!(
            ModelAdmission::RetainedRuntime
                .admit(&model, &fixture.inputs)
                .is_err(),
            "shared {kind}"
        );
    }
}

#[test]
fn unretained_future_roles_keep_all_static_deployment_policy() {
    let fixture = Fixture::new();
    for (field, value) in [
        ("image", json!("example.invalid/runtime:latest")),
        ("build", json!({"context":"."})),
        ("privileged", json!(true)),
        ("init", json!(false)),
        ("security_opt", json!(["seccomp:unconfined"])),
        ("cap_add", json!(["SYS_ADMIN"])),
        ("mem_limit", json!(0)),
        (
            "ports",
            json!([{"host_ip":"0.0.0.0","published":"18443","protocol":"tcp"}]),
        ),
    ] {
        let mut model = fixture.model.clone();
        model["services"]["installer-generation"][field] = value;
        assert!(
            ModelAdmission::RetainedRuntime
                .admit(&model, &fixture.inputs)
                .is_err(),
            "{field}"
        );
    }
    for mutation in [
        "outside-roots",
        "writable-readonly-root",
        "create-host-path",
        "unclean-path",
    ] {
        let mut model = fixture.model.clone();
        let mount = &mut model["services"]["installer-generation"]["volumes"][0];
        match mutation {
            "outside-roots" => mount["source"] = json!("/etc/future-input"),
            "writable-readonly-root" => {
                mount["source"] = json!(fixture.root.path().join("inputs/future"))
            }
            "create-host-path" => mount["bind"]["create_host_path"] = json!(true),
            "unclean-path" => mount["source"] = json!(fixture.root.path().join("state/../future")),
            _ => unreachable!(),
        }
        assert!(
            ModelAdmission::RetainedRuntime
                .admit(&model, &fixture.inputs)
                .is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn retained_recovery_requires_every_retained_model_role_and_a_closed_existing_selection() {
    let fixture = Fixture::new();
    for role in SELECTED.into_iter().chain(["application", "bootstrap"]) {
        let mut model = fixture.model.clone();
        model["services"].as_object_mut().unwrap().remove(role);
        assert!(
            ModelAdmission::RetainedRuntime
                .admit(&model, &fixture.inputs)
                .is_err(),
            "missing {role}"
        );
    }
    for mutation in [
        "no-prior",
        "no-resources",
        "missing-retained",
        "duplicate",
        "incomplete",
        "future-setup",
        "unretained-runtime",
    ] {
        let mut inputs = fixture.inputs.clone();
        let mut model = fixture.model.clone();
        match mutation {
            "no-prior" => inputs.prior = None,
            "no-resources" => inputs.prior.as_mut().unwrap().resources = None,
            "missing-retained" => {
                inputs
                    .prior
                    .as_mut()
                    .unwrap()
                    .resources
                    .as_mut()
                    .unwrap()
                    .containers
                    .remove("openbao");
            }
            "duplicate" => inputs.services.push("openbao".into()),
            "incomplete" => inputs.services.retain(|role| role != "openbao"),
            "future-setup" => inputs.services.push("installer-generation".into()),
            "unretained-runtime" => {
                model["services"]["future-runtime"] = model["services"]["openbao"].clone();
                inputs.services.push("future-runtime".into());
            }
            _ => unreachable!(),
        }
        assert!(
            ModelAdmission::RetainedRuntime
                .admit(&model, &inputs)
                .is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn retained_recovery_cannot_pull_create_setup_or_enter_generation_replacement() {
    let mut fixture = Fixture::new();
    let selected = fixture.admit().unwrap();
    // Empty profiles would otherwise allow the generation activation entrypoint.
    fixture.inputs.profiles.clear();
    let executable = fixture.root.path().join("docker-fixture");
    fs::write(
        &executable,
        "#!/bin/sh\n: > \"${0%/*}/docker-invoked\"\nexit 97\n",
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let binding = RuntimeBinding {
        docker_host: "unix:///var/run/docker.sock".into(),
        engine_id: "test-engine".into(),
        openbao_port: 18443,
        profile: RuntimeProfile::Rootful,
    };
    let session = ComposeSession {
        docker: DockerRunner::new(
            &executable,
            &binding.docker_host,
            &binding.engine_id,
            fixture.root.path(),
        )
        .unwrap(),
        binding,
        inputs: fixture.inputs,
        model: fixture.model,
        hashes: BTreeMap::new(),
        configuration_sha256: "a".repeat(64),
        bindings: BTreeMap::new(),
        cleanup_only: false,
        generation_transition: None,
        runtime_recovery_roles: selected,
    };
    let mut state = InstallerState::create(
        &fixture.root.path().join("installation-state"),
        crate::installer_state::Identity {
            source_sha: "0".repeat(40),
            release_tag: "v0.0.0".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        },
    )
    .unwrap();
    assert_eq!(session.pull().unwrap_err(), REFUSED);
    assert_eq!(
        session
            .run_setup_job(&mut state, "installer-generation")
            .unwrap_err(),
        REFUSED
    );
    assert_eq!(
        session
            .up_wait(&mut state, "application-up", Duration::from_secs(1))
            .unwrap_err(),
        REFUSED
    );
    assert_eq!(
        session
            .observe_generation_transition(GenerationOperation::Activate)
            .unwrap_err(),
        REFUSED
    );
    assert!(
        !fixture.root.path().join("docker-invoked").exists(),
        "refusal precedes any Docker command"
    );
}
