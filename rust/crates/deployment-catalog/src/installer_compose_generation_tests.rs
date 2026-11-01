//! Synthetic CLI observations exercise the production native admission path.
//! These tests open no Docker socket and do not qualify a rootless deployment.
use super::*;
use std::os::unix::fs::PermissionsExt;

const INSTALLATION: &str = "11111111-1111-4111-8111-111111111111";
const MEMORY: u64 = 64 * 1024 * 1024;

pub(crate) struct Fixture {
    root: tempfile::TempDir,
    session: ComposeSession,
    inspected: Vec<Value>,
    networks: Vec<Value>,
    volumes: Vec<Value>,
}

impl ComposeSession {
    pub(crate) fn generation_test_fixture(kind: GenerationOperation) -> Fixture {
        Fixture::new(kind)
    }
}

fn identity(role: &str, digit: char, setup: bool, image: &str) -> ContainerIdentity {
    ContainerIdentity {
        id: digit.to_string().repeat(64),
        service: role.into(),
        image: image.into(),
        config_hash: "8".repeat(64),
        setup,
        setup_execution: setup.then(|| SetupExecution {
            started_at: "2026-10-30T00:00:01Z".into(),
            finished_at: "2026-10-30T00:00:02Z".into(),
            completed_without_restart: true,
        }),
        health_required: false,
        cap_add: BTreeSet::new(),
        cap_drop: BTreeSet::new(),
        read_only: false,
        memory_limit: MEMORY,
    }
}

fn inspection(identity: &ContainerIdentity, project: &str) -> Value {
    json!({
        "Id":identity.id,"Image":format!("sha256:{}","f".repeat(64)),
        "Config":{"Image":identity.image,"Labels":{
            "com.docker.compose.project":project,
            "com.docker.compose.service":identity.service,
            "com.docker.compose.config-hash":identity.config_hash,
            "com.docker.compose.oneoff":"False",
            "com.docker.compose.container-number":"1",
            SETUP_LABEL:if identity.setup {"setup"} else {"runtime"}
        }},
        "RestartCount":0,
        "State":{"Status":if identity.setup {"exited"} else {"running"},
            "Running":!identity.setup,"Paused":false,"Restarting":false,
            "Dead":false,"OOMKilled":false,"ExitCode":0,
            "StartedAt":"2026-10-30T00:00:01Z","FinishedAt":"2026-10-30T00:00:02Z"},
        "HostConfig":{"CapAdd":[],"CapDrop":[],"ReadonlyRootfs":false,
            "Memory":MEMORY,"Privileged":false,"Init":true,
            "SecurityOpt":["no-new-privileges"],"PidMode":"","UsernsMode":"",
            "IpcMode":"private","Devices":[],"VolumesFrom":[],
            "NetworkMode":format!("{project}_default"),"PortBindings":{}},
        "NetworkSettings":{"Networks":{format!("{project}_default"):{}},"Ports":{}},
        "Mounts":[]
    })
}

impl Fixture {
    pub(crate) fn root(&self) -> &Path {
        self.root.path()
    }

    pub(crate) fn session(&self) -> &ComposeSession {
        &self.session
    }

    pub(crate) fn remove_role(&mut self, role: &str) {
        self.inspected
            .retain(|row| row["Config"]["Labels"]["com.docker.compose.service"] != role);
    }

    fn new(kind: GenerationOperation) -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let image = format!("example.invalid/runtime@sha256:{}", "c".repeat(64));
        let other_image = format!("example.invalid/other@sha256:{}", "d".repeat(64));
        let project = format!("marty-install-{}", INSTALLATION.replace('-', ""));
        let network = format!("{project}_default");
        let volume = format!("{project}_data");
        let mut prior = ProjectResources {
            networks: BTreeMap::from([(network.clone(), "7".repeat(64))]),
            volumes: BTreeSet::from([volume.clone()]),
            ..Default::default()
        };
        for (role, digit, setup) in [
            ("api", '1', false),
            ("edge", '2', false),
            ("store", '3', false),
            ("installer-generation", '4', true),
            ("bootstrap", '5', true),
        ] {
            prior
                .containers
                .insert(role.into(), identity(role, digit, setup, &image));
        }
        let receipt = ComposeReceipt {
            schema: "elevenid.installer-compose-operation/v1".into(),
            project: project.clone(),
            engine_id: "test-engine".into(),
            operation: "previous".into(),
            configuration_sha256: "a".repeat(64),
            input_files: BTreeMap::new(),
            command_succeeded: true,
            client_exit_code: Some(0),
            failure_class: None,
            observation_validated: true,
            resources: Some(prior.clone()),
            status: Vec::new(),
            installation_ready: false,
        };
        let inputs = ComposeInputs {
            installation: root.path().into(),
            project: project.clone(),
            files: Vec::new(),
            bound_inputs: Vec::new(),
            environment: BoundFile {
                path: root.path().join("unused.env"),
                sha256: "b".repeat(64),
            },
            profiles: if kind == GenerationOperation::Candidate {
                vec!["setup".into()]
            } else {
                Vec::new()
            },
            services: if kind == GenerationOperation::Candidate {
                vec!["installer-generation".into()]
            } else {
                vec!["api".into(), "edge".into()]
            },
            approved_images: BTreeSet::from([image.clone(), other_image.clone()]),
            #[cfg(feature = "installer-development")]
            development_image: None,
            writable_bind_roots: BTreeSet::new(),
            readonly_bind_roots: BTreeSet::new(),
            allowed_loopback_ports: BTreeSet::new(),
            ingress_listener: None,
            prior: Some(receipt),
        };
        let mut model = json!({"name":project,"services":{},
            "networks":{"default":{"name":network}},"volumes":{"data":{"name":volume}}});
        let roles: &[&str] = if kind == GenerationOperation::Candidate {
            &["installer-generation"]
        } else {
            &["api", "edge", "store"]
        };
        let mut hashes = BTreeMap::new();
        for role in roles {
            model["services"][role] = json!({
                "image":image,"mem_limit":MEMORY,"restart":"no",
                "labels":{SETUP_LABEL:if kind == GenerationOperation::Candidate {"setup"} else {"runtime"}}
            });
            hashes.insert((*role).into(), "9".repeat(64));
        }
        if kind == GenerationOperation::Candidate {
            model["services"]["installer-generation"]["entrypoint"] =
                json!(["/input/marty-deploy"]);
            model["services"]["installer-generation"]["command"] = json!([
                "installer-generation-provision-transfer",
                "--installation-id",
                INSTALLATION
            ]);
        }
        let executable = root.path().join("docker-fixture");
        fs::write(
            &executable,
            r#"#!/bin/sh
set -eu
case "$1" in
  info) cat "${0%/*}/engine-info.json" ;;
  ps)
    case "$5" in
      volume=*) cat "${0%/*}/volume-consumers.txt" ;;
      *) cat "${0%/*}/ids.txt" ;;
    esac ;;
  inspect) cat "${0%/*}/containers.json" ;;
  image) test "$2" = inspect; cat "${0%/*}/image.json" ;;
  network|volume)
    case "$2" in
      ls) cat "${0%/*}/$1-names.txt" ;;
      inspect) cat "${0%/*}/$1-$3.json" ;;
      *) exit 93 ;;
    esac ;;
  *) exit 94 ;;
esac
"#,
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.path().join("engine-info.json"),
            br#"{"id":"test-engine","os":"linux","architecture":"x86_64","server_version":"28.0.0","security_options":["name=seccomp,profile=builtin"]}"#).unwrap();
        fs::write(
            root.path().join("image.json"),
            serde_json::to_vec(&json!([{
                "Id":format!("sha256:{}","f".repeat(64)),"RepoDigests":[image,other_image]
            }]))
            .unwrap(),
        )
        .unwrap();
        fs::write(root.path().join("volume-consumers.txt"), b"").unwrap();
        let session = ComposeSession {
            docker: DockerRunner::new(
                &executable,
                "unix:///var/run/docker.sock",
                "test-engine",
                root.path(),
            )
            .unwrap(),
            binding: RuntimeBinding {
                docker_host: "unix:///var/run/docker.sock".into(),
                engine_id: "test-engine".into(),
                openbao_port: 18443,
                profile: RuntimeProfile::Rootful,
            },
            inputs,
            model,
            hashes,
            configuration_sha256: "b".repeat(64),
            bindings: BTreeMap::new(),
            cleanup_only: false,
            generation_transition: None,
            runtime_recovery_roles: None,
        };
        let result = Self {
            inspected: prior
                .containers
                .values()
                .map(|identity| inspection(identity, &project))
                .collect(),
            networks: vec![json!({"Name":network,"Id":"7".repeat(64),
                "Driver":"bridge","Options":{},"Containers":{},
                "Labels":{"com.docker.compose.project":project}})],
            volumes: vec![json!({"Name":volume,"Driver":"local","Scope":"local",
                "Options":{},"Labels":{"com.docker.compose.project":project}})],
            root,
            session,
        };
        result.flush();
        result
    }

    fn container(&mut self, role: &str) -> &mut Value {
        self.inspected
            .iter_mut()
            .find(|row| row["Config"]["Labels"]["com.docker.compose.service"] == role)
            .unwrap()
    }

    pub(crate) fn replacement(&mut self, role: &str, digit: char, state: &str) {
        let row = self.container(role);
        row["Id"] = json!(digit.to_string().repeat(64));
        row["Config"]["Labels"]["com.docker.compose.config-hash"] = json!("9".repeat(64));
        row["State"]["Status"] = json!(state);
        row["State"]["Running"] = json!(state == "running");
        if state == "created" {
            row["State"]["StartedAt"] = json!("0001-01-01T00:00:00Z");
            row["State"]["FinishedAt"] = json!("0001-01-01T00:00:00Z");
        }
    }

    pub(crate) fn flush(&self) {
        fs::write(
            self.root.path().join("ids.txt"),
            self.inspected
                .iter()
                .map(|row| format!("{}\n", row["Id"].as_str().unwrap()))
                .collect::<String>(),
        )
        .unwrap();
        fs::write(
            self.root.path().join("containers.json"),
            serde_json::to_vec(&self.inspected).unwrap(),
        )
        .unwrap();
        for (kind, resources) in [("network", &self.networks), ("volume", &self.volumes)] {
            let mut names = String::new();
            for resource in resources {
                let name = resource["Name"].as_str().unwrap();
                names.push_str(&format!("{name}\n"));
                fs::write(
                    self.root.path().join(format!("{kind}-{name}.json")),
                    serde_json::to_vec(&json!([resource])).unwrap(),
                )
                .unwrap();
            }
            fs::write(self.root.path().join(format!("{kind}-names.txt")), names).unwrap();
        }
    }

    fn observe(&self, kind: GenerationOperation) -> Result<ProjectResources> {
        self.flush();
        self.session.observe_generation_transition(kind)
    }
}

#[test]
fn native_generation_transition_accepts_only_selected_old_new_or_missing_ids() {
    let mut fixture = Fixture::new(GenerationOperation::Activate);
    assert_eq!(
        fixture.observe(GenerationOperation::Activate).unwrap(),
        fixture.session.prior()
    );
    fixture.replacement("api", 'a', "created");
    let mixed = fixture.observe(GenerationOperation::Activate).unwrap();
    assert_eq!(mixed.containers["api"].id, "a".repeat(64));
    assert_eq!(
        mixed.containers["edge"],
        fixture.session.prior().containers["edge"]
    );
    assert_eq!(mixed.networks, fixture.session.prior().networks);
    assert_eq!(mixed.volumes, fixture.session.prior().volumes);
    assert!(fixture.session.observe_resources().is_err());

    fixture
        .inspected
        .retain(|row| row["Config"]["Labels"]["com.docker.compose.service"] != "edge");
    let partial = fixture.observe(GenerationOperation::Activate).unwrap();
    assert!(!partial.containers.contains_key("edge"));
    assert_eq!(
        partial.containers.len(),
        fixture.session.prior().containers.len() - 1
    );
    assert_eq!(
        partial.containers["bootstrap"],
        fixture.session.prior().containers["bootstrap"]
    );
}

#[test]
fn replacement_selection_includes_effective_secret_and_config_paths_with_unchanged_native_hashes() {
    let mut fixture = Fixture::new(GenerationOperation::Activate);
    for hash in fixture.session.hashes.values_mut() {
        *hash = "8".repeat(64);
    }
    fixture.session.model["services"]["api"]["secrets"] = json!([{"source":"api_token"}]);
    fixture.session.model["services"]["edge"]["configs"] = json!([{"source":"edge_config"}]);
    fixture.session.model["secrets"] = json!({"api_token":{"file":"/installation/application-generation/api_token"},"unused":{"file":"/installation/unused"}});
    fixture.session.model["configs"] =
        json!({"edge_config":{"file":"/installation/application-generation/edge_config"}});
    let previous = fixture.session.model.clone();
    assert!(fixture
        .session
        .changed_generation_services(&previous)
        .unwrap()
        .is_empty());
    fixture.session.model["secrets"]["api_token"]["file"] =
        json!("/installation/application-generations/new/api_token");
    assert_eq!(
        fixture
            .session
            .changed_generation_services(&previous)
            .unwrap(),
        ["api"]
    );
    fixture.session.model["configs"]["edge_config"]["file"] =
        json!("/installation/application-generations/new/edge_config");
    assert_eq!(
        fixture
            .session
            .changed_generation_services(&previous)
            .unwrap(),
        ["api", "edge"]
    );
    fixture.session.model["secrets"]["unused"]["file"] = json!("/installation/other-unused");
    assert_eq!(
        fixture
            .session
            .changed_generation_services(&previous)
            .unwrap(),
        ["api", "edge"]
    );
    fixture.session.model["secrets"]["api_token"] = Value::Null;
    assert!(fixture
        .session
        .changed_generation_services(&previous)
        .is_err());
}

#[test]
fn mixed_pause_observation_requires_every_runtime_stopped_and_no_active_producer() {
    let mut fixture = Fixture::new(GenerationOperation::Candidate);
    fixture.replacement("installer-generation", 'a', "created");
    let resources = fixture.observe(GenerationOperation::Candidate).unwrap();
    let selected: BTreeSet<_> = resources
        .containers
        .iter()
        .filter(|(_, identity)| !identity.setup)
        .map(|(role, _)| role.clone())
        .collect();
    let replacing = BTreeSet::from(["installer-generation".into()]);
    let rows:Vec<_>=resources.containers.iter().map(|(role,identity)|json!({"Service":role,"ID":identity.id,
        "State":if role=="installer-generation" {"created"} else {"exited"},"ExitCode":0,"Health":""})).collect();
    assert!(generation_runtime_observation(
        &resources, &rows, &selected, &replacing, true
    ));
    for state in ["running", "restarting", "paused"] {
        let mut changed = rows.clone();
        changed
            .iter_mut()
            .find(|row| row["Service"] == "api")
            .unwrap()["State"] = json!(state);
        assert!(!generation_runtime_observation(
            &resources, &changed, &selected, &replacing, true
        ));
    }
    let mut active = rows.clone();
    active
        .iter_mut()
        .find(|row| row["Service"] == "installer-generation")
        .unwrap()["State"] = json!("running");
    assert!(!generation_runtime_observation(
        &resources, &active, &selected, &replacing, true
    ));
    let mut failed = rows;
    let producer = failed
        .iter_mut()
        .find(|row| row["Service"] == "installer-generation")
        .unwrap();
    producer["State"] = json!("exited");
    producer["ExitCode"] = json!(1);
    // This is a stop observation only. A failed producer is never completion.
    assert!(generation_runtime_observation(
        &resources, &failed, &selected, &replacing, true
    ));
    assert!(!completed_setups(&resources, &failed));
    failed[0]["ID"] = json!("f".repeat(64));
    assert!(!generation_runtime_observation(
        &resources, &failed, &selected, &replacing, true
    ));
}

#[test]
fn native_generation_transition_refuses_neighbor_setup_and_storage_adoption() {
    for case in 0..11 {
        let mut fixture = Fixture::new(GenerationOperation::Activate);
        fixture.replacement("api", 'a', "created");
        match case {
            0 => fixture.replacement("store", 'b', "running"),
            1 => fixture
                .inspected
                .retain(|row| row["Config"]["Labels"]["com.docker.compose.service"] != "store"),
            2 => fixture.replacement("bootstrap", 'c', "exited"),
            3 => {
                fixture.container("bootstrap")["State"]["StartedAt"] = json!("2026-10-30T00:00:03Z")
            }
            4 => fixture.container("bootstrap")["RestartCount"] = json!(1),
            5 => fixture.networks[0]["Id"] = json!("6".repeat(64)),
            6 => fixture.networks.clear(),
            7 => {
                let mut extra = fixture.volumes[0].clone();
                extra["Name"] = json!(format!("{}_extra", fixture.session.inputs.project));
                fixture.volumes.push(extra);
            }
            8 => fixture.volumes.clear(),
            9 => fixture.networks[0]["Containers"] = json!({"e".repeat(64):{}}),
            10 => fs::write(
                fixture.root.path().join("volume-consumers.txt"),
                format!("{}\n", "e".repeat(64)),
            )
            .unwrap(),
            _ => unreachable!(),
        }
        assert!(
            fixture.observe(GenerationOperation::Activate).is_err(),
            "case {case}"
        );
    }
}

#[test]
fn native_replacement_requires_exact_model_image_config_and_security_properties() {
    for case in 0..10 {
        let mut fixture = Fixture::new(GenerationOperation::Activate);
        fixture.replacement("api", 'a', "created");
        match case {
            0 => {
                fixture.container("api")["Config"]["Image"] =
                    json!(format!("example.invalid/other@sha256:{}", "d".repeat(64)))
            }
            1 => {
                fixture.container("api")["Config"]["Labels"]["com.docker.compose.config-hash"] =
                    json!("8".repeat(64))
            }
            2 => fixture.container("api")["Image"] = json!(format!("sha256:{}", "e".repeat(64))),
            3 => fixture.container("api")["HostConfig"]["Memory"] = json!(2 * MEMORY),
            4 => fixture.container("api")["HostConfig"]["ReadonlyRootfs"] = json!(true),
            5 => fixture.container("api")["HostConfig"]["CapDrop"] = json!(["ALL"]),
            6 => fixture.container("api")["HostConfig"]["Privileged"] = json!(true),
            7 => fixture.container("api")["Config"]["Labels"][SETUP_LABEL] = json!("setup"),
            8 => {
                let mut duplicate = fixture.container("api").clone();
                duplicate["Id"] = json!("b".repeat(64));
                fixture.inspected.push(duplicate);
            }
            9 => {
                let mut extra = fixture.container("api").clone();
                extra["Id"] = json!("b".repeat(64));
                extra["Config"]["Labels"]["com.docker.compose.service"] = json!("unretained");
                fixture.inspected.push(extra);
            }
            _ => unreachable!(),
        }
        assert!(
            fixture.observe(GenerationOperation::Activate).is_err(),
            "case {case}"
        );
    }
}

#[test]
fn native_candidate_replacement_is_limited_to_the_fixed_retained_producer() {
    let mut fixture = Fixture::new(GenerationOperation::Candidate);
    fixture.replacement("installer-generation", 'a', "created");
    let observed = fixture.observe(GenerationOperation::Candidate).unwrap();
    assert_eq!(
        observed.containers["installer-generation"].id,
        "a".repeat(64)
    );
    assert!(
        !observed.containers["installer-generation"]
            .setup_execution
            .as_ref()
            .unwrap()
            .completed_without_restart
    );
    assert_eq!(
        observed.containers["bootstrap"],
        fixture.session.prior().containers["bootstrap"]
    );
    for case in 0..5 {
        let original_inputs = fixture.session.inputs.clone();
        let original_model = fixture.session.model.clone();
        match case {
            0 => fixture.session.inputs.services.push("bootstrap".into()),
            1 => fixture.session.inputs.profiles.clear(),
            2 => {
                fixture.session.model["services"]["installer-generation"]["depends_on"] =
                    json!({"bootstrap":{"condition":"service_completed_successfully"}})
            }
            3 => {
                fixture.session.model["services"]["installer-generation"]["command"] = json!([
                    "installer-generation-provision-transfer",
                    "--installation-id",
                    "22222222-2222-4222-8222-222222222222"
                ])
            }
            4 => {
                fixture
                    .session
                    .inputs
                    .prior
                    .as_mut()
                    .unwrap()
                    .resources
                    .as_mut()
                    .unwrap()
                    .containers
                    .get_mut("installer-generation")
                    .unwrap()
                    .setup_execution
                    .as_mut()
                    .unwrap()
                    .completed_without_restart = false
            }
            _ => unreachable!(),
        }
        assert!(
            fixture.observe(GenerationOperation::Candidate).is_err(),
            "case {case}"
        );
        fixture.session.inputs = original_inputs;
        fixture.session.model = original_model;
    }
}

fn status_rows(resources: &ProjectResources) -> Vec<Value> {
    resources
        .containers
        .values()
        .map(|identity| {
            json!({
                "Service":identity.service,"ID":identity.id,
                "State":if identity.setup {"exited"} else {"created"},"ExitCode":0,"Health":""
            })
        })
        .collect()
}

#[test]
fn created_observation_requires_full_status_census_and_replacement_ids() {
    let fixture = Fixture::new(GenerationOperation::Activate);
    let prior = fixture.session.prior();
    let selected = BTreeSet::from(["api".into(), "edge".into()]);
    let mut current = prior.clone();
    current.containers.get_mut("api").unwrap().id = "a".repeat(64);
    current.containers.get_mut("edge").unwrap().id = "b".repeat(64);
    let rows = status_rows(&current);
    assert!(generation_created(&current, &rows, &prior, &selected));
    assert!(!generation_created(
        &prior,
        &status_rows(&prior),
        &prior,
        &selected
    ));
    for case in 0..6 {
        let mut invalid = rows.clone();
        let store = invalid
            .iter()
            .position(|row| row["Service"] == "store")
            .unwrap();
        let bootstrap = invalid
            .iter()
            .position(|row| row["Service"] == "bootstrap")
            .unwrap();
        match case {
            0 => invalid[store]["ID"] = json!("c".repeat(64)),
            1 => invalid[store] = invalid[bootstrap].clone(),
            2 => invalid[store]["Service"] = json!("unretained"),
            3 => {
                invalid.pop();
            }
            4 => invalid[store]["Service"] = Value::Null,
            5 => {
                invalid
                    .iter_mut()
                    .find(|row| row["Service"] == "api")
                    .unwrap()["State"] = json!("paused")
            }
            _ => unreachable!(),
        }
        assert!(
            !generation_created(&current, &invalid, &prior, &selected),
            "case {case}"
        );
    }
}

#[test]
fn producer_completion_preserves_setup_proof_and_rejects_malformed_runtime_status() {
    let fixture = Fixture::new(GenerationOperation::Candidate);
    let resources = fixture.session.prior();
    let baseline = status_rows(&resources);
    for state in ["running", "created", "exited", "restarting", "paused"] {
        let mut rows = baseline.clone();
        for row in &mut rows {
            if !resources.containers[row["Service"].as_str().unwrap()].setup {
                row["State"] = json!(state);
                row["Health"] = json!("starting");
            }
        }
        assert!(completed_setups(&resources, &rows), "{state}");
    }
    for invalid in [
        json!("dead"),
        json!("removing"),
        json!("unknown"),
        json!(17),
        Value::Null,
    ] {
        let mut rows = baseline.clone();
        rows.iter_mut().find(|row| row["Service"] == "api").unwrap()["State"] = invalid;
        assert!(!completed_setups(&resources, &rows));
    }
    let mut failed = baseline.clone();
    failed
        .iter_mut()
        .find(|row| row["Service"] == "installer-generation")
        .unwrap()["ExitCode"] = json!(1);
    assert!(!completed_setups(&resources, &failed));
    let mut replayed = resources.clone();
    replayed
        .containers
        .get_mut("bootstrap")
        .unwrap()
        .setup_execution
        .as_mut()
        .unwrap()
        .completed_without_restart = false;
    assert!(!completed_setups(&replayed, &baseline));
    let mut duplicate = baseline.clone();
    let api = duplicate
        .iter()
        .position(|row| row["Service"] == "api")
        .unwrap();
    let store = duplicate
        .iter()
        .position(|row| row["Service"] == "store")
        .unwrap();
    duplicate[store] = duplicate[api].clone();
    assert!(!completed_setups(&resources, &duplicate));
}
