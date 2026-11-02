//! Exercise the real read-only startup reader over complete synthetic public
//! generation evidence. No Docker, CA, credential issuance or host mutation.
use super::*;
use crate::installer_compose::{BoundFile, ComposeReceipt, ContainerIdentity, ProjectResources};
use std::{
    collections::BTreeSet,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    process::Command,
};

// The production journal correctly refuses a root-owned rootless runtime.
// Root test runners re-execute this exact test under an unprivileged UID;
// ordinary CI owners exercise it directly. The owned copy avoids depending on
// traversal permissions of a root runner's checkout or Cargo target directory.
fn run_as_owner() -> bool {
    if unsafe { libc::geteuid() } != 0 {
        return true;
    }
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let executable = directory.path().join("generation-usability-tests");
    std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o555)).unwrap();
    let current = std::thread::current();
    assert!(Command::new(executable)
        .args(["--exact", current.name().unwrap(), "--nocapture"])
        .env_clear()
        .current_dir("/tmp")
        .uid(65534)
        .gid(65534)
        .status()
        .unwrap()
        .success());
    false
}

fn write(path: &Path, bytes: &[u8], mode: u32) {
    if path.exists() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn record(root: &Path, name: &str, value: &impl Serialize) -> Vec<u8> {
    let bytes = serde_json::to_vec(value).unwrap();
    write(&root.join("evidence").join(name), &bytes, 0o600);
    bytes
}

struct Fixture {
    root: tempfile::TempDir,
    binding: GenerationBinding,
    application: Value,
    selection: Value,
    saved: SavedSession,
}

impl Fixture {
    fn new() -> Self {
        let (root, mut generations) =
            generation::test_lineage_fixture_with_engine(0, "fixture-engine");
        let binding = generations.remove(0);
        let project = format!("marty-install-{}", binding.installation_id.replace('-', ""));
        let image = format!(
            "ghcr.io/elevenid/marty-ui-oss/services@sha256:{}",
            "c".repeat(64)
        );
        let secrets: BTreeMap<_, _> = binding
            .files
            .keys()
            .map(|name| {
                (
                    name.clone(),
                    json!({"file":binding.secret_dir(root.path()).unwrap().join(name)}),
                )
            })
            .collect();
        let references: Vec<_> = binding
            .files
            .keys()
            .map(|name| json!({"source":name}))
            .collect();
        let application = json!({"name":project,"services":{"installer-ingress":{
            "image":image,"labels":{"com.elevenid.installer.phase":"runtime"},
            "secrets":references}},"secrets":secrets});
        let application_bytes = record(root.path(), "application-native-model.json", &application);
        let binding_bytes = record(root.path(), "application-generation-pending.json", &binding);
        let source = format!(
            "SELFHOST_SECRET_DIR='{}'\n",
            root.path().join("secrets").display()
        );
        write(
            &root.path().join("evidence/application-source.env"),
            source.as_bytes(),
            0o600,
        );
        let env =
            crate::installer_application_env::select_generation(source.as_bytes(), root.path())
                .unwrap();
        let env_path = root.path().join("evidence/application.env");
        write(&env_path, &env, 0o600);
        let selection = json!({"schema":"elevenid.installer-application-generation-selection/v2",
            "installation_id":binding.installation_id,"engine_id":binding.engine_id,
            "binding_sha256":hash(&binding_bytes),"native_model_sha256":hash(&application_bytes),
            "env_sha256":hash(&env),"activated":false,"installation_ready":false});
        record(
            root.path(),
            "application-generation-selection.json",
            &selection,
        );

        let mut model = application.clone();
        // The real compose.bootstrap.yml retains this setup role in the full
        // maintenance union. Its original secret-directory bind must not be
        // admitted as part of the application's immutable generation closure.
        model["services"]["openbao-bootstrap"] = json!({"image":image,
            "labels":{"com.elevenid.installer.phase":"setup"},"volumes":[{
                "type":"bind","source":root.path().join("secrets"),
                "target":"/bao/runtime","read_only":false}]});
        let configuration_sha256 = installer_compose::model_sha256(&model).unwrap();
        let compose = root.path().join("evidence/fixture-compose.json");
        let compose_bytes = serde_json::to_vec(&model).unwrap();
        write(&compose, &compose_bytes, 0o600);
        let seed: ComposeReceipt = decode(
            &read(
                root.path(),
                "compose-setup-installer-generation-result.json",
            )
            .unwrap(),
        )
        .unwrap();
        let mut setup = seed
            .resources
            .unwrap()
            .containers
            .remove("installer-generation")
            .unwrap();
        setup.service = "openbao-bootstrap".into();
        let runtime = ContainerIdentity {
            id: "1".repeat(64),
            service: "installer-ingress".into(),
            setup: false,
            setup_execution: None,
            health_required: true,
            ..setup.clone()
        };
        let receipt = ComposeReceipt {
            schema: "elevenid.installer-compose-operation/v1".into(),
            project: project.clone(),
            engine_id: binding.engine_id.clone(),
            operation: "maintenance-checkpoint".into(),
            configuration_sha256: configuration_sha256.clone(),
            input_files: BTreeMap::from([
                (compose.clone(), hash(&compose_bytes)),
                (env_path.clone(), hash(&env)),
            ]),
            command_succeeded: true,
            client_exit_code: Some(0),
            failure_class: None,
            observation_validated: true,
            resources: Some(ProjectResources {
                containers: BTreeMap::from([
                    ("installer-ingress".into(), runtime.clone()),
                    ("openbao-bootstrap".into(), setup.clone()),
                ]),
                networks: BTreeMap::from([(
                    format!("{project}_default"),
                    binding.network_id.clone().unwrap(),
                )]),
                volumes: BTreeSet::new(),
            }),
            status: vec![
                json!({"Service":"installer-ingress","ID":runtime.id,"State":"running","ExitCode":0,"Health":"healthy"}),
                json!({"Service":"openbao-bootstrap","ID":setup.id,"State":"exited","ExitCode":0,"Health":""}),
            ],
            installation_ready: false,
        };
        let inputs = ComposeInputs {
            installation: root.path().into(),
            project,
            files: vec![BoundFile {
                path: compose,
                sha256: hash(&compose_bytes),
            }],
            bound_inputs: Vec::new(),
            environment: BoundFile {
                path: env_path,
                sha256: hash(&env),
            },
            profiles: vec!["setup".into(), "installer-init".into()],
            services: Vec::new(),
            approved_images: BTreeSet::from([image.clone()]),
            #[cfg(feature = "installer-development")]
            development_image: None,
            writable_bind_roots: BTreeSet::new(),
            readonly_bind_roots: BTreeSet::new(),
            allowed_loopback_ports: BTreeSet::new(),
            ingress_listener: None,
            prior: Some(receipt.clone()),
        };
        let saved = SavedSession {
            schema: "elevenid.installer-compose-session/v1".into(),
            installation_id: binding.installation_id.clone(),
            inputs,
            model,
            configuration_sha256,
            receipt,
        };
        record(root.path(), installer_doctor::SESSION_RECORD, &saved);
        let inventory = json!({"schema":"elevenid.installer-inventory/v1",
            "repository":installer_release::REPOSITORY,"platform":"linux/amd64",
            "source_sha":"a".repeat(40),"release_tag":"v1.2.3-nightly.20261025.42",
            "build_run_id":42,"build_run_attempt":1,
            "artifacts":[{"name":"install.sh","sha256":"b".repeat(64),"size":10},
                {"name":"marty-deploy-linux-amd64","sha256":"c".repeat(64),"size":20},
                {"name":"prepared-selfhost-bundle.zip","sha256":"d".repeat(64),"size":30},
                {"name":"prepared-selfhost-images.json","sha256":"e".repeat(64),"size":40}],
            "images":{"gateway":image,"openbao_didcomm_image":image}});
        let inventory_bytes = record(root.path(), "installer-inventory.json", &inventory);
        let journal = json!({"schema":"elevenid.installer-state/v1",
            "installation_id":binding.installation_id,"phase":"provisioning","revision":2,
            "identity":{"source_sha":inventory["source_sha"],"release_tag":inventory["release_tag"],
                "inventory_sha256":format!("sha256:{}",hash(&inventory_bytes))},
            "runtime":{"docker_host":format!("unix:///run/user/{}/docker.sock",unsafe { libc::geteuid() }),
                "engine_id":binding.engine_id,"openbao_port":18443,"profile":"rootless"}});
        write(
            &root.path().join("installation.json"),
            &serde_json::to_vec(&journal).unwrap(),
            0o600,
        );
        Self {
            root,
            binding,
            application,
            selection,
            saved,
        }
    }

    fn observe(&self) -> Result<CurrentGenerationUsability> {
        let view = LockedInspection::open(self.root.path())?;
        current_startup_usability(&view, self.root.path())
    }

    fn save_application(&mut self) {
        let bytes = record(
            self.root.path(),
            "application-native-model.json",
            &self.application,
        );
        self.selection["native_model_sha256"] = json!(hash(&bytes));
        record(
            self.root.path(),
            "application-generation-selection.json",
            &self.selection,
        );
    }
}

#[test]
fn initial_application_usability_keeps_retained_setup_outside_its_secret_closure() {
    if !run_as_owner() {
        return;
    }
    let fixture = Fixture::new();
    let root = fixture.root.path();
    let view = LockedInspection::open(root).unwrap();
    let loaded = generation::load_verified(
        root,
        &fixture.binding.installation_id,
        &fixture.binding.engine_id,
    )
    .unwrap()
    .unwrap();
    assert_eq!(loaded, fixture.binding);
    assert_eq!(
        installer_doctor::load_session(&view, root).unwrap().model,
        fixture.saved.model
    );
    assert!(generation::verify_model(
        root,
        &loaded,
        &fixture.application,
        loaded.network_id.as_deref()
    )
    .is_ok());
    assert!(generation::verify_model(
        root,
        &loaded,
        &fixture.saved.model,
        loaded.network_id.as_deref()
    )
    .is_err());
    // This is the real reader used by lifecycle resume/boot, not a duplicate
    // model predicate. Historical certificate/credential age may require
    // maintenance, but the authenticated selection must not be an integrity error.
    current_startup_usability(&view, root).unwrap();
}

#[test]
fn startup_usability_still_rejects_changed_application_and_maintenance_evidence() {
    if !run_as_owner() {
        return;
    }
    for case in 0..8 {
        let mut fixture = Fixture::new();
        let root = fixture.root.path();
        match case {
            0 => {
                fixture.application["secrets"]["installer_ingress_tls_kms_token"]["file"] =
                    json!(root.join("secrets/installer_ingress_tls_kms_token"));
                fixture.save_application();
            }
            1 => {
                fixture.application["services"]["installer-ingress"]["secrets"]
                    .as_array_mut()
                    .unwrap()
                    .pop()
                    .unwrap();
                fixture.save_application();
            }
            2 => {
                let changed = b"SELFHOST_SECRET_DIR='/unrelated'\n";
                write(&root.join("evidence/application.env"), changed, 0o600);
                fixture.selection["env_sha256"] = json!(hash(changed));
                record(
                    root,
                    "application-generation-selection.json",
                    &fixture.selection,
                );
            }
            3 => write(
                &fixture
                    .binding
                    .secret_dir(root)
                    .unwrap()
                    .join("installer_ingress_tls_kms_token"),
                b"changed-fixture-token",
                0o444,
            ),
            4 => {
                fixture.saved.model["services"]["installer-ingress"]["image"] =
                    json!("changed-model");
                record(root, installer_doctor::SESSION_RECORD, &fixture.saved);
            }
            5 => write(
                &root.join("evidence/fixture-compose.json"),
                b"changed-bound-input",
                0o600,
            ),
            6 => {
                fixture.selection["native_model_sha256"] = json!("f".repeat(64));
                record(
                    root,
                    "application-generation-selection.json",
                    &fixture.selection,
                );
            }
            7 => {
                record(
                    root,
                    "generation-00000000000000000001-intent.json",
                    &json!({}),
                );
            }
            _ => unreachable!(),
        }
        assert!(
            fixture.observe().is_err(),
            "changed evidence case {case} was accepted"
        );
    }
}
