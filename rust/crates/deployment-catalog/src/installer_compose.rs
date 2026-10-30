//! Compose owns deployment ordering, health waits, and ordinary lifecycle.
//!
//! Callers authenticate the complete bundle/inventory, keep the installation lock,
//! and validate credential outputs. This module binds those exact inputs to one
//! rootless project; it does not authenticate an arbitrary caller-supplied digest.
//! Resolved configuration is inspected, never rewritten or executed as new JSON.
#![cfg(target_os = "linux")]

use crate::{
    installer_runtime::DockerRunner,
    installer_state::{InstallerState, Journal, LockedMaintenance, RuntimeBinding, RuntimeProfile},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, String>;
pub const COMPOSE_VERSION: &str = "5.6.1";
const MAX_FILE: u64 = 2 * 1024 * 1024;
const MAX_WAIT: u64 = 720;
const REFUSED: &str = "Compose installation policy refused the operation";
const UNCERTAIN: &str = "Compose operation failed or was interrupted; inspect retained project evidence before recovery; no automatic retry was performed";
const SETUP_LABEL: &str = "com.elevenid.installer.phase";
const OPENBAO_CUSTODY: &str = "compose-openbao-private-inputs.json";
pub(crate) const RUNTIME_CLEANUP_PLAN: &str = "compose-application-cleanup-plan.json";
pub(crate) const CLEANUP_RECEIPT_SCHEMA: &str = "elevenid.installer-compose-cleanup-operation/v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundFile {
    pub path: PathBuf,
    pub sha256: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn inputs(root: &Path) -> ComposeInputs {
        ComposeInputs {
            installation: root.into(),
            project: format!("marty-install-{}", "a".repeat(32)),
            files: Vec::new(),
            bound_inputs: Vec::new(),
            environment: BoundFile {
                path: root.join("runtime.env"),
                sha256: "b".repeat(64),
            },
            profiles: Vec::new(),
            services: Vec::new(),
            approved_images: BTreeSet::from([format!(
                "example.invalid/runtime@sha256:{}",
                "c".repeat(64)
            )]),
            writable_bind_roots: BTreeSet::from([root.join("state")]),
            readonly_bind_roots: BTreeSet::from([root.join("inputs")]),
            allowed_loopback_ports: BTreeSet::from([18443]),
            prior: None,
        }
    }
    fn model(p: &ComposeInputs) -> Value {
        json!({"name":p.project,"services":{"app":{
            "image":p.approved_images.first().unwrap(),"init":true,"mem_limit":"67108864",
            "security_opt":["no-new-privileges:true"],"labels":{SETUP_LABEL:"runtime"},
            "networks":{"default":{}},"restart":"no"
        }},"networks":{"default":{"name":format!("{}_default",p.project)}}})
    }
    fn bound(path: &Path, bytes: &[u8]) -> BoundFile {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        BoundFile {
            path: path.into(),
            sha256: sha256(bytes),
        }
    }
    fn setup_inspection() -> Value {
        json!({"State":{"Status":"exited","Running":false,"Paused":false,"Restarting":false,
            "Dead":false,"OOMKilled":false,"ExitCode":0},"RestartCount":0})
    }
    fn identity(role: &str, setup: bool, image: &str) -> ContainerIdentity {
        ContainerIdentity {
            id: "d".repeat(64),
            service: role.into(),
            image: image.into(),
            config_hash: "e".repeat(64),
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
            memory_limit: 67108864,
        }
    }

    #[test]
    fn ordinary_start_refuses_missing_runtime_and_every_setup_dependency() {
        let root = tempfile::tempdir().unwrap();
        let p = inputs(root.path());
        let mut m = model(&p);
        let mut prior = ProjectResources::default();
        let image = p.approved_images.first().unwrap();
        prior
            .containers
            .insert("app".into(), identity("app", false, image));
        let selected = vec!["app".into()];
        runtime_selection(&m, &prior, &selected).unwrap();
        assert!(runtime_selection(&m, &ProjectResources::default(), &selected).is_err());
        m["services"]["app"]["depends_on"] =
            json!({"setup":{"condition":"service_completed_successfully"}});
        prior
            .containers
            .insert("setup".into(), identity("setup", true, image));
        assert!(runtime_selection(&m, &prior, &selected).is_err());
        m["services"]["setup"] = json!({"labels":{SETUP_LABEL:"setup"}});
        assert!(runtime_selection(&m, &prior, &selected).is_err());
        m["services"]["app"]["depends_on"] = json!({});
        assert!(runtime_selection(&m, &prior, &selected).is_err());
    }

    #[test]
    fn private_openbao_inputs_do_not_bypass_missing_files_links_or_missing_custody() {
        let root = tempfile::tempdir().unwrap();
        let mut p = inputs(root.path());
        let state = root.path().join("openbao-state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        p.writable_bind_roots.insert(state.clone());
        let token = state.join("root.token");
        assert!(mount_policy(token.to_str().unwrap(), true, &p, true).is_err());
        assert!(private_openbao_input(&token, true, &p).is_err());
        assert!(private_openbao_input(&token, false, &p).is_err());
        assert!(!private_openbao_input(&state.join("unseal.key"), true, &p).unwrap());
        fs::write(root.path().join("outside"), b"fixture").unwrap();
        symlink(root.path().join("outside"), &token).unwrap();
        assert!(mount_policy(token.to_str().unwrap(), true, &p, true).is_err());
    }

    #[test]
    fn opaque_openbao_custody_requires_exact_anchor_engine_and_completed_jobs() {
        let root = tempfile::tempdir().unwrap();
        let mut p = inputs(root.path());
        let image = p.approved_images.first().unwrap().clone();
        let mut resources = ProjectResources::default();
        for role in ["openbao-tls-init", "openbao-bootstrap"] {
            resources
                .containers
                .insert(role.into(), identity(role, true, &image));
        }
        p.prior = Some(ComposeReceipt {
            schema: "elevenid.installer-compose-operation/v1".into(),
            project: p.project.clone(),
            engine_id: "engine".into(),
            operation: "bootstrap".into(),
            configuration_sha256: "a".repeat(64),
            input_files: BTreeMap::new(),
            command_succeeded: true,
            client_exit_code: Some(0),
            failure_class: None,
            observation_validated: true,
            resources: Some(resources),
            status: Vec::new(),
            installation_ready: false,
        });
        let directory = PrivateDirectoryIdentity {
            dev: 1,
            ino: 2,
            uid: unsafe { libc::geteuid() }.saturating_add(1),
            gid: 3,
            mode: 0o700,
        };
        let mut record = OpenBaoCustody {
            schema: "elevenid.installer-openbao-private-inputs/v1".into(),
            project: p.project.clone(),
            engine_id: "engine".into(),
            tls_container_id: "d".repeat(64),
            tls_image: image,
            directory: directory.clone(),
        };
        validate_openbao_custody(&record, &p, &directory).unwrap();
        record.engine_id = "other".into();
        assert!(validate_openbao_custody(&record, &p, &directory).is_err());
        record.engine_id = "engine".into();
        record.directory.ino += 1;
        assert!(validate_openbao_custody(&record, &p, &directory).is_err());
        record.directory = directory.clone();
        record.tls_container_id = "f".repeat(64);
        assert!(validate_openbao_custody(&record, &p, &directory).is_err());
        record.tls_container_id = "d".repeat(64);
        p.prior
            .as_mut()
            .unwrap()
            .resources
            .as_mut()
            .unwrap()
            .containers
            .get_mut("openbao-bootstrap")
            .unwrap()
            .setup_execution
            .as_mut()
            .unwrap()
            .completed_without_restart = false;
        assert!(validate_openbao_custody(&record, &p, &directory).is_err());
    }

    #[test]
    fn supported_native_baseline_has_no_unverified_version_fallback() {
        for value in ["5.6.1", "v5.6.1\n", "5.6.1+ds1-0ubuntu1~24.04.1"] {
            assert!(version_supported(value));
        }
        for value in [
            "2.24.4",
            "5.6.0",
            "5.6.2",
            "5.6.1-rc.1",
            "5.6.1+",
            "5.6.1+bad/path",
            "5.6.1+bad value",
        ] {
            assert!(!version_supported(value), "{value}");
        }
    }

    #[test]
    fn native_policy_rejects_unapproved_images_and_authority_options() {
        let root = tempfile::tempdir().unwrap();
        let p = inputs(root.path());
        admit_model(&model(&p), &p).unwrap();
        for (field, value) in [
            ("image", json!("example.invalid/runtime:latest")),
            ("build", json!({"context":"."})),
            ("provider", json!({"type":"other"})),
            ("privileged", json!(true)),
            ("network_mode", json!("host")),
            ("pid", json!("host")),
            ("ipc", json!("host")),
            ("devices", json!(["/dev/sda"])),
            ("post_start", json!([{"command":"echo unsafe"}])),
            ("init", json!(false)),
            ("mem_limit", json!(0)),
            ("security_opt", json!(["seccomp:unconfined"])),
            ("cap_add", json!(["SYS_ADMIN"])),
        ] {
            let mut m = model(&p);
            m["services"]["app"][field] = value;
            assert!(admit_model(&m, &p).is_err(), "{field}");
        }
    }

    #[test]
    fn repository_digests_preserve_only_existing_docker_hub_default_aliases() {
        let hash = "a".repeat(64);
        let approved = format!("docker.io/library/postgres@sha256:{hash}");
        for repository in [
            "postgres",
            "library/postgres",
            "docker.io/postgres",
            "docker.io/library/postgres",
        ] {
            validate_image_digest(
                &json!({"Id":format!("sha256:{}","b".repeat(64)),
                "RepoDigests":[format!("{repository}@sha256:{hash}")]}),
                &approved,
            )
            .unwrap();
        }
        for repository in [
            "ghcr.io/library/postgres",
            "registry-1.docker.io/library/postgres",
            "index.docker.io/library/postgres",
            "docker.io:443/library/postgres",
            "team/postgres",
            "redis",
            "postgres:16",
            "docker.io//postgres",
            "Postgres",
        ] {
            assert!(validate_image_digest(
                &json!({"Id":format!("sha256:{}","b".repeat(64)),
                "RepoDigests":[format!("{repository}@sha256:{hash}")]}),
                &approved
            )
            .is_err());
        }
        assert!(validate_image_digest(
            &json!({"Id":format!("sha256:{}","b".repeat(64)),
            "RepoDigests":[format!("postgres@sha256:{}","c".repeat(64))]}),
            &approved
        )
        .is_err());
    }

    #[test]
    fn only_setup_jobs_can_request_the_reviewed_output_transfer_capabilities() {
        let root = tempfile::tempdir().unwrap();
        let p = inputs(root.path());
        let mut m = model(&p);
        m["services"]["app"]["cap_add"] = json!(["CAP_DAC_OVERRIDE", "CHOWN"]);
        m["services"]["app"]["cap_drop"] = json!(["ALL"]);
        assert!(admit_model(&m, &p).is_err());
        m["services"]["app"]["labels"][SETUP_LABEL] = json!("setup");
        admit_model(&m, &p).unwrap();
        for value in [
            json!(["SYS_ADMIN"]),
            json!(["IPC_LOCK"]),
            json!(["CHOWN", "CAP_CHOWN"]),
        ] {
            m["services"]["app"]["cap_add"] = value;
            assert!(admit_model(&m, &p).is_err());
        }
        m["services"]["app"]["cap_add"] = json!(["CHOWN"]);
        m["services"]["app"]["cap_drop"] = json!([]);
        assert!(admit_model(&m, &p).is_err());
    }

    #[test]
    fn only_reserved_loopback_publication_is_admitted() {
        let root = tempfile::tempdir().unwrap();
        let p = inputs(root.path());
        let mut m = model(&p);
        m["services"]["app"]["ports"] =
            json!([{"host_ip":"127.0.0.1","published":"18443","target":8443,"protocol":"tcp"}]);
        admit_model(&m, &p).unwrap();
        for (field, value) in [
            ("host_ip", json!("0.0.0.0")),
            ("host_ip", json!("::")),
            ("published", json!("18444")),
            ("published", json!("18443-18445")),
            ("protocol", json!("udp")),
        ] {
            let mut wrong = m.clone();
            wrong["services"]["app"]["ports"][0][field] = value;
            assert!(admit_model(&wrong, &p).is_err());
        }
    }

    #[test]
    fn binds_are_contained_existing_and_never_auto_created() {
        let root = tempfile::tempdir().unwrap();
        let p = inputs(root.path());
        fs::create_dir(root.path().join("state")).unwrap();
        fs::create_dir(root.path().join("inputs")).unwrap();
        fs::write(root.path().join("inputs/read-only"), b"input").unwrap();
        let mut m = model(&p);
        m["services"]["app"]["volumes"] = json!([{"type":"bind","source":root.path().join("state"),
            "target":"/data","bind":{"create_host_path":false}}]);
        admit_model(&m, &p).unwrap();
        for source in [
            PathBuf::from("/var/run/docker.sock"),
            root.path().join("state-other"),
            root.path().join("state/missing"),
        ] {
            let mut wrong = m.clone();
            wrong["services"]["app"]["volumes"][0]["source"] = json!(source);
            assert!(admit_model(&wrong, &p).is_err());
        }
        m["services"]["app"]["volumes"][0]["source"] = json!(root.path().join("inputs/read-only"));
        assert!(admit_model(&m, &p).is_err());
        m["services"]["app"]["volumes"][0]["read_only"] = json!(true);
        admit_model(&m, &p).unwrap();
        m["services"]["app"]["volumes"][0]["bind"]["create_host_path"] = json!(true);
        assert!(admit_model(&m, &p).is_err());
        symlink(
            root.path().join("inputs/read-only"),
            root.path().join("state/link"),
        )
        .unwrap();
        assert!(mount_policy(
            root.path().join("state/link").to_str().unwrap(),
            true,
            &p,
            true
        )
        .is_err());
    }

    #[test]
    fn selected_secret_files_are_local_but_unused_future_outputs_are_not_opened() {
        let root = tempfile::tempdir().unwrap();
        let p = inputs(root.path());
        fs::create_dir(root.path().join("inputs")).unwrap();
        let mut m = model(&p);
        m["secrets"] = json!({"future":{"file":root.path().join("inputs/not-created-yet")}});
        admit_model(&m, &p).unwrap();
        m["services"]["app"]["secrets"] =
            json!([{"source":"future","target":"/run/secrets/future"}]);
        assert!(admit_model(&m, &p).is_err());
        fs::write(root.path().join("inputs/not-created-yet"), b"fixture").unwrap();
        admit_model(&m, &p).unwrap();
        m["secrets"]["future"]["external"] = json!(true);
        assert!(admit_model(&m, &p).is_err());
    }

    #[test]
    fn networks_and_volumes_are_scoped_and_cannot_adopt_external_resources() {
        let root = tempfile::tempdir().unwrap();
        let p = inputs(root.path());
        for kind in ["networks", "volumes"] {
            let mut m = model(&p);
            m[kind]["data"] = json!({"name":format!("{}_data",p.project)});
            admit_model(&m, &p).unwrap();
            for (field, value) in [
                ("name", json!("neighbor_data")),
                ("external", json!(true)),
                ("driver_opts", json!({"device":"/"})),
            ] {
                let mut wrong = m.clone();
                wrong[kind]["data"][field] = value;
                assert!(admit_model(&wrong, &p).is_err());
            }
        }
    }

    #[test]
    fn resource_census_includes_unlabelled_name_collisions_without_neighbors() {
        let project = format!("marty-install-{}", "a".repeat(32));
        let owned = format!("{project}_default");
        let collision = format!("{project}_data");
        let neighbor = format!("neighbor_{project}_data");
        let observed = resource_names(
            &format!("{owned}\n"),
            &format!("{owned}\n{collision}\n{neighbor}\n"),
            &project,
        )
        .unwrap();
        assert_eq!(observed, BTreeSet::from([owned.clone(), collision]));
        assert!(!observed.contains(&neighbor));
        assert!(resource_names(&format!("{owned}\n{owned}\n"), "", &project).is_err());
        // Labels alone never make an unrelated name part of this project.
        assert!(resource_names(&format!("{neighbor}\n"), "", &project).is_err());
    }

    #[test]
    fn input_receipts_reject_changed_linked_or_shared_writable_files() {
        let root = tempfile::tempdir().unwrap();
        let config = bound(&root.path().join("compose.yml"), b"services: {}\n");
        regular_bound(&config, root.path()).unwrap();
        let mut wrong = config.clone();
        wrong.sha256 = "d".repeat(64);
        assert!(regular_bound(&wrong, root.path()).is_err());
        fs::set_permissions(&config.path, fs::Permissions::from_mode(0o660)).unwrap();
        assert!(regular_bound(&config, root.path()).is_err());
        fs::set_permissions(&config.path, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&config.path, root.path().join("linked.yml")).unwrap();
        wrong = config.clone();
        wrong.path = root.path().join("linked.yml");
        assert!(regular_bound(&wrong, root.path()).is_err());
        fs::hard_link(&config.path, root.path().join("hard.yml")).unwrap();
        assert!(regular_bound(&config, root.path()).is_err());
    }

    #[test]
    fn retained_setup_completion_rejects_reexecution_or_uncertain_state() {
        let original = setup_inspection();
        assert!(retained_setup_completed(&original));
        for (field, value) in [
            ("Status", json!("running")),
            ("Running", json!(true)),
            ("Paused", json!(true)),
            ("Restarting", json!(true)),
            ("Dead", json!(true)),
            ("OOMKilled", json!(true)),
            ("ExitCode", json!(1)),
        ] {
            let mut changed = original.clone();
            changed["State"][field] = value;
            assert!(!retained_setup_completed(&changed));
        }
        for value in [json!(1), json!("0"), Value::Null] {
            let mut changed = original.clone();
            changed["RestartCount"] = value;
            assert!(!retained_setup_completed(&changed));
        }
    }

    #[test]
    fn failure_evidence_keeps_only_fixed_classification_and_numeric_exit() {
        assert_eq!(command_outcome(&Ok(String::new()), true), (Some(0), None));
        assert_eq!(
            command_outcome(&Ok(String::new()), false),
            (Some(0), Some("postcondition_not_established".into()))
        );
        assert_eq!(command_outcome(&Err("Compose setup failed (exit=Some(42)); inspect private project evidence; no retry was performed".into()),false),
            (Some(42),Some("client_exit_nonzero".into())));
        for secret in [
            "token=PRIVATE",
            "Compose setup failed (exit=Some(1)); token=PRIVATE",
        ] {
            let result = command_outcome(&Err(secret.into()), false);
            assert_eq!(
                result,
                (None, Some("runtime_boundary_outcome_uncertain".into()))
            );
        }
    }

    #[test]
    fn finite_runtime_exit_classification_does_not_admit_timeouts_or_signals() {
        assert_eq!(
            command_outcome(
                &Err(
                    "Docker command failed (exit=Some(1)); inspect owned runtime separately".into()
                ),
                false
            ),
            (Some(1), Some("client_exit_nonzero".into()))
        );
        for error in [
            "Docker command failed (exit=None); inspect owned runtime separately",
            "Docker command failed (exit=Some(137)); inspect owned runtime separately",
            "Docker command failed (exit=Some(1)); private sentinel",
        ] {
            assert_eq!(
                command_outcome(&Err(error.into()), false),
                (None, Some("runtime_boundary_outcome_uncertain".into()))
            );
        }
        for error in [
            "Docker command timed out; owned child process group was cancelled",
            "Compose wait deadline reached; inspect retained project before recovery",
        ] {
            assert_eq!(
                command_outcome(&Err(error.into()), false),
                (None, Some("client_timeout_outcome_uncertain".into()))
            );
        }
    }

    #[test]
    fn failed_runtime_cleanup_requires_every_setup_completed_and_exact_observed_rows() {
        let root = tempfile::tempdir().unwrap();
        let p = inputs(root.path());
        let image = p.approved_images.first().unwrap();
        let mut resources = ProjectResources::default();
        resources
            .containers
            .insert("app".into(), identity("app", false, image));
        let mut setup = identity("setup", true, image);
        setup.id = "f".repeat(64);
        resources.containers.insert("setup".into(), setup);
        let model = json!({"name":p.project,"services":{"app":{"labels":{SETUP_LABEL:"runtime"}},
            "setup":{"labels":{SETUP_LABEL:"setup"}}}});
        let receipt = ComposeReceipt {
            schema: "elevenid.installer-compose-operation/v1".into(),
            project: p.project.clone(),
            engine_id: "engine".into(),
            operation: "application-up".into(),
            configuration_sha256: "a".repeat(64),
            input_files: BTreeMap::new(),
            command_succeeded: false,
            client_exit_code: Some(1),
            failure_class: Some("client_exit_nonzero".into()),
            observation_validated: true,
            resources: Some(resources),
            status: vec![
                json!({"Service":"app","ID":"d".repeat(64),"State":"running","Health":"unhealthy","ExitCode":0}),
                json!({"Service":"setup","ID":"f".repeat(64),"State":"exited","ExitCode":0}),
            ],
            installation_ready: false,
        };
        validate_failed_runtime_cleanup(&receipt, &model).unwrap();
        for mutation in 0..12 {
            let mut changed = receipt.clone();
            match mutation {
                0 => changed.operation = "setup-credential".into(),
                1 => changed.client_exit_code = None,
                2 => changed.failure_class = Some("client_timeout_outcome_uncertain".into()),
                3 => changed.command_succeeded = true,
                4 => changed.observation_validated = false,
                5 => changed.status[1]["State"] = json!("running"),
                6 => changed.status[1]["ExitCode"] = json!(7),
                7 => changed.status[0]["ID"] = json!("b".repeat(64)),
                8 => {
                    changed
                        .resources
                        .as_mut()
                        .unwrap()
                        .containers
                        .remove("setup");
                    changed.status.pop();
                }
                9 => {
                    changed
                        .resources
                        .as_mut()
                        .unwrap()
                        .containers
                        .get_mut("setup")
                        .unwrap()
                        .setup_execution
                        .as_mut()
                        .unwrap()
                        .completed_without_restart = false
                }
                10 => changed.schema = CLEANUP_RECEIPT_SCHEMA.into(),
                _ => changed.status.push(changed.status[0].clone()),
            }
            assert!(
                validate_failed_runtime_cleanup(&changed, &model).is_err(),
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn native_ps_accepts_array_or_json_lines_and_rejects_malformed_rows() {
        let rows_value =
            json!([{"Service":"app","State":"running"},{"Service":"job","State":"exited"}]);
        let array = serde_json::to_string(&rows_value).unwrap();
        let lines = rows_value
            .as_array()
            .unwrap()
            .iter()
            .map(|v| format!("{v}\n"))
            .collect::<String>();
        assert_eq!(rows(&array).unwrap(), rows(&lines).unwrap());
        assert!(rows("{not json}").is_err());
    }

    #[test]
    fn completion_requires_full_container_ids_even_for_healthy_or_completed_rows() {
        let image = format!("example.invalid/runtime@sha256:{}", "c".repeat(64));
        let prefix = "a".repeat(12);
        let full = format!("{prefix}{}", "b".repeat(52));
        for setup in [false, true] {
            let mut container = identity("app", setup, &image);
            container.id = full.clone();
            container.health_required = !setup;
            let mut resources = ProjectResources::default();
            resources.containers.insert("app".into(), container);
            let mut row = json!({"Service":"app","ID":full,
                "State":if setup {"exited"} else {"running"},"Health":"healthy","ExitCode":0});
            assert!(completed(&resources, &[row.clone()]));
            row["ID"] = json!(prefix);
            assert!(!completed(&resources, &[row.clone()]));
            row["ID"] = json!(format!("{prefix}{}", "f".repeat(52)));
            assert!(!completed(&resources, &[row]));
        }
    }

    #[test]
    fn native_dollar_paths_are_decoded_only_for_host_inspection() {
        let encoded = json!("/private/install $$literal/inputs/file$$$$name");
        assert_eq!(
            config_path(&encoded).unwrap(),
            PathBuf::from("/private/install $literal/inputs/file$$name")
        );
        assert_eq!(encoded, "/private/install $$literal/inputs/file$$$$name");
        for value in [
            "/private/$bare",
            "/private/$$$odd",
            "relative/$$file",
            "/private/../other",
        ] {
            assert!(config_path(&json!(value)).is_err());
        }
    }

    #[test]
    fn canonical_model_evidence_does_not_depend_on_insertion_order() {
        let first: Value = serde_json::from_str(
            r#"{"services":{"a":{"image":"one","init":true}},"name":"project"}"#,
        )
        .unwrap();
        let second: Value = serde_json::from_str(
            r#"{"name":"project","services":{"a":{"init":true,"image":"one"}}}"#,
        )
        .unwrap();
        assert_eq!(
            model_sha256(&first).unwrap(),
            model_sha256(&second).unwrap()
        );
        assert!(model_hashes("app a\n").is_err());
        let line = format!("app {}\n", "a".repeat(64));
        assert!(model_hashes(&format!("{line}{line}")).is_err());
    }
}

/// Roots are filesystem policy, not another service/mount definition table.
/// All paths and ports are concrete installation inputs from the locked caller.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComposeInputs {
    pub installation: PathBuf,
    pub project: String,
    pub files: Vec<BoundFile>,
    /// Private evidence bindings; never interpreted as Compose configuration.
    pub bound_inputs: Vec<BoundFile>,
    pub environment: BoundFile,
    pub profiles: Vec<String>,
    pub services: Vec<String>,
    pub approved_images: BTreeSet<String>,
    pub writable_bind_roots: BTreeSet<PathBuf>,
    pub readonly_bind_roots: BTreeSet<PathBuf>,
    pub allowed_loopback_ports: BTreeSet<u16>,
    /// Only a successful, observed prior phase can authorize the next phase.
    /// Provisional create IDs and uncertain operation results are not admission.
    pub prior: Option<ComposeReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupExecution {
    pub started_at: String,
    pub finished_at: String,
    pub completed_without_restart: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerIdentity {
    pub id: String,
    pub service: String,
    pub image: String,
    pub config_hash: String,
    pub setup: bool,
    /// Manual starts do not increment Docker's RestartCount. These timestamps
    /// bind the one observed setup execution while allowing ordinary restarts.
    pub setup_execution: Option<SetupExecution>,
    pub health_required: bool,
    pub cap_add: BTreeSet<String>,
    pub cap_drop: BTreeSet<String>,
    pub read_only: bool,
    pub memory_limit: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ProjectResources {
    pub containers: BTreeMap<String, ContainerIdentity>,
    pub networks: BTreeMap<String, String>,
    pub volumes: BTreeSet<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComposeReceipt {
    pub schema: String,
    pub project: String,
    pub engine_id: String,
    pub operation: String,
    pub configuration_sha256: String,
    pub input_files: BTreeMap<PathBuf, String>,
    pub command_succeeded: bool,
    /// Only fixed classifications and a numeric client status are retained here.
    /// Raw Compose output can contain credentials and never becomes an error.
    pub client_exit_code: Option<i32>,
    pub failure_class: Option<String>,
    pub observation_validated: bool,
    pub resources: Option<ProjectResources>,
    pub status: Vec<Value>,
    pub installation_ready: bool,
}

pub struct ComposeSession {
    docker: DockerRunner,
    binding: RuntimeBinding,
    inputs: ComposeInputs,
    model: Value,
    hashes: BTreeMap<String, String>,
    configuration_sha256: String,
    bindings: BTreeMap<PathBuf, String>,
    cleanup_only: bool,
}

/// Written before application startup. It binds the authenticated maintenance
/// union without claiming that any future application resource exists.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeCleanupPlan {
    pub schema: String,
    pub installation_id: String,
    pub inputs: ComposeInputs,
    pub model: Value,
    pub configuration_sha256: String,
    pub application_configuration_sha256: String,
}

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn text(value: &Value) -> Result<&str> {
    value.as_str().ok_or_else(|| REFUSED.into())
}
fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
/// Canonical evidence digest of Compose's unmodified model, never an execution file.
pub fn model_sha256(model: &Value) -> Result<String> {
    let mut canonical = model.clone();
    canonical.sort_all_objects();
    Ok(sha256(
        &serde_json::to_vec(&canonical).map_err(|_| REFUSED)?,
    ))
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}
fn image(value: &str) -> bool {
    value
        .split_once("@sha256:")
        .is_some_and(|(repository, hash)| {
            !repository.is_empty()
                && !repository.starts_with('-')
                && repository
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"./:_-".contains(&b))
                && digest(hash)
        })
}
fn digest_value(value: &str) -> bool {
    digest(value)
}
// Docker may print a Hub RepoDigest without docker.io and the official-image
// library namespace. Normalize those defaults only, never a foreign registry,
// digest, tag, or the container's recorded Config.Image.
// Default naming: https://docs.docker.com/reference/cli/docker/image/tag/
fn canonical_repo_digest(reference: &str) -> Option<String> {
    if reference.len() > 512 {
        return None;
    }
    let (repository, digest) = reference.split_once("@sha256:")?;
    if !digest_value(digest) {
        return None;
    }
    let (first, rest) = repository.split_once('/').unwrap_or((repository, ""));
    let explicit_registry = first.contains('.') || first.contains(':') || first == "localhost";
    let (registry, path) = if explicit_registry {
        (first, rest)
    } else {
        ("docker.io", repository)
    };
    if registry.is_empty()
        || !registry
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-:".contains(&b))
    {
        return None;
    }
    static COMPONENT: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let component = COMPONENT
        .get_or_init(|| regex::Regex::new(r"\A[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*\z").unwrap());
    if !path.split('/').all(|part| component.is_match(part)) {
        return None;
    }
    let path = if registry == "docker.io" && !path.contains('/') {
        format!("library/{path}")
    } else {
        path.into()
    };
    Some(format!("{registry}/{path}@sha256:{digest}"))
}

/// Bind inspected image identity and repository digest, accounting only for
/// Docker Hub's omitted default registry/namespace in RepoDigests output.
pub(crate) fn validate_image_digest(image: &Value, reference: &str) -> Result<()> {
    let expected = canonical_repo_digest(reference).ok_or(REFUSED)?;
    require(
        image["Id"]
            .as_str()
            .and_then(|s| s.strip_prefix("sha256:"))
            .is_some_and(digest_value)
            && image["RepoDigests"].as_array().is_some_and(|entries| {
                entries.iter().any(|value| {
                    value.as_str().and_then(canonical_repo_digest).as_ref() == Some(&expected)
                })
            }),
    )
}

fn c_image(container: &Value) -> Result<&str> {
    text(&container["Image"])
}
fn empty(value: Option<&Value>) -> bool {
    value.is_none_or(|v| v.is_null() || v == &json!([]) || v == &json!({}) || v == "")
}
fn strings(value: Option<&Value>) -> Result<Vec<&str>> {
    if empty(value) {
        return Ok(Vec::new());
    }
    value
        .and_then(Value::as_array)
        .ok_or(REFUSED)?
        .iter()
        .map(text)
        .collect()
}
fn clean_path(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path.as_os_str().len() < 4096
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        && path
            .to_str()
            .is_some_and(|s| !s.chars().any(char::is_control))
}
/// Compose 5.6.1 escapes every dollar when emitting config, including JSON.
/// Decode that representation only when resolving a host path for inspection;
/// the native model and the authenticated execution files remain unchanged.
pub(crate) fn config_path(value: &Value) -> Result<PathBuf> {
    let mut decoded = String::new();
    let mut characters = text(value)?.chars();
    while let Some(character) = characters.next() {
        if character == '$' {
            require(characters.next() == Some('$'))?;
        }
        decoded.push(character);
    }
    let path = PathBuf::from(decoded);
    require(clean_path(&path))?;
    Ok(path)
}
fn within(path: &Path, roots: &BTreeSet<PathBuf>) -> bool {
    clean_path(path) && roots.iter().any(|root| path.starts_with(root))
}
fn regular_bound(file: &BoundFile, installation: &Path) -> Result<()> {
    require(digest(&file.sha256) && clean_path(&file.path) && file.path.starts_with(installation))?;
    require(file.path.canonicalize().map_err(|_| REFUSED)? == file.path)?;
    let mut opened = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&file.path)
        .map_err(|_| REFUSED)?;
    let before = opened.metadata().map_err(|_| REFUSED)?;
    require(
        before.is_file()
            && before.nlink() == 1
            && before.uid() == unsafe { libc::geteuid() }
            && before.mode() & 0o022 == 0
            && before.len() > 0
            && before.len() <= MAX_FILE,
    )?;
    let mut bytes = Vec::new();
    (&mut opened)
        .take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSED)?;
    let after = opened.metadata().map_err(|_| REFUSED)?;
    let current = fs::symlink_metadata(&file.path).map_err(|_| REFUSED)?;
    let stamp = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.mode(),
            m.uid(),
            m.gid(),
            m.nlink(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    require(
        stamp(&before) == stamp(&after)
            && stamp(&after) == stamp(&current)
            && bytes.len() as u64 == before.len()
            && sha256(&bytes) == file.sha256,
    )
}
pub(crate) fn verify_input_files(
    installation: &Path,
    files: &BTreeMap<PathBuf, String>,
) -> Result<()> {
    for (path, hash) in files {
        regular_bound(
            &BoundFile {
                path: path.clone(),
                sha256: hash.clone(),
            },
            installation,
        )?;
    }
    Ok(())
}
pub(crate) fn memory_limit(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
        .filter(|bytes| (6 * 1024 * 1024..=64 * 1024 * 1024 * 1024).contains(bytes))
        .ok_or_else(|| REFUSED.into())
}
fn capabilities(value: Option<&Value>) -> Result<BTreeSet<String>> {
    let values = strings(value)?;
    let mut result = BTreeSet::new();
    for value in values {
        let cap = value.strip_prefix("CAP_").unwrap_or(value);
        require(
            !cap.is_empty()
                && cap.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
                && result.insert(cap.to_owned()),
        )?;
    }
    Ok(result)
}
fn capability_policy(setup: bool, add: &BTreeSet<String>, drop: &BTreeSet<String>) -> Result<()> {
    if add.is_empty() {
        return Ok(());
    }
    require(
        setup
            && drop == &BTreeSet::from(["ALL".into()])
            && add
                .iter()
                .all(|cap| ["DAC_OVERRIDE", "CHOWN"].contains(&cap.as_str())),
    )
}
fn rows(output: &str) -> Result<Vec<Value>> {
    if output.trim().is_empty() {
        return Ok(Vec::new());
    }
    if output.trim_start().starts_with('[') {
        serde_json::from_str(output).map_err(|_| REFUSED.into())
    } else {
        output
            .lines()
            .map(|line| serde_json::from_str(line).map_err(|_| REFUSED.into()))
            .collect()
    }
}
fn identifiers(output: &str) -> Result<BTreeSet<String>> {
    let result: BTreeSet<_> = output.lines().map(str::to_owned).collect();
    require(result.len() == output.lines().count() && result.iter().all(|id| digest(id)))?;
    Ok(result)
}
fn version_supported(version: &str) -> bool {
    let value = version.trim().strip_prefix('v').unwrap_or(version.trim());
    value == COMPOSE_VERSION
        || value
            .strip_prefix(&format!("{COMPOSE_VERSION}+"))
            .is_some_and(|suffix| {
                !suffix.is_empty()
                    && suffix
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-~".contains(&b))
            })
}
pub(crate) fn require_version(version: &str) -> Result<()> {
    if version_supported(version) {
        Ok(())
    } else {
        Err(format!("This installer requires Docker Compose {COMPOSE_VERSION}; install that supported plugin and retry preflight before creating an installation"))
    }
}
fn model_hashes(output: &str) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for line in output.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        require(fields.len() == 2 && name(fields[0]) && digest(fields[1]))?;
        require(result.insert(fields[0].into(), fields[1].into()).is_none())?;
    }
    require(!result.is_empty())?;
    Ok(result)
}
fn published(port: &Value, allowed: &BTreeSet<u16>) -> Result<()> {
    let number = port["published"]
        .as_u64()
        .and_then(|n| u16::try_from(n).ok())
        .or_else(|| port["published"].as_str().and_then(|s| s.parse().ok()))
        .ok_or(REFUSED)?;
    require(
        port["host_ip"] == "127.0.0.1"
            && port["protocol"] == "tcp"
            && allowed.contains(&number)
            && number >= 1024,
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateDirectoryIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}
fn private_directory(path: &Path) -> Result<PrivateDirectoryIdentity> {
    require(path.canonicalize().map_err(|_| REFUSED)? == path)?;
    let m = fs::symlink_metadata(path).map_err(|_| REFUSED)?;
    require(m.is_dir() && m.mode() & 0o7777 == 0o700 && m.dev() != 0 && m.ino() != 0)?;
    Ok(PrivateDirectoryIdentity {
        dev: m.dev(),
        ino: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode() & 0o7777,
    })
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenBaoCustody {
    schema: String,
    project: String,
    engine_id: String,
    tls_container_id: String,
    tls_image: String,
    directory: PrivateDirectoryIdentity,
}
/// Record only the state-root identity, not its private descendants. This is
/// available in development/candidate scopes as well as admitted installations.
pub(crate) fn record_openbao_custody(
    installation: &Path,
    state: &mut InstallerState,
    receipt: &ComposeReceipt,
    before: &fs::Metadata,
) -> Result<BoundFile> {
    let tls = receipt
        .resources
        .as_ref()
        .and_then(|r| r.containers.get("openbao-tls-init"))
        .ok_or(REFUSED)?;
    require(
        receipt.command_succeeded
            && receipt.observation_validated
            && receipt.client_exit_code == Some(0)
            && receipt.failure_class.is_none()
            && receipt.operation == "setup-openbao-tls-init"
            && receipt.project == state.journal().compose_project()
            && state
                .journal()
                .runtime()
                .is_some_and(|b| b.engine_id == receipt.engine_id)
            && tls.setup
            && tls
                .setup_execution
                .as_ref()
                .is_some_and(|e| e.completed_without_restart),
    )?;
    let directory = private_directory(&installation.join("openbao-state"))?;
    require(
        before.is_dir()
            && before.uid() == unsafe { libc::geteuid() }
            && before.mode() & 0o7777 == 0o700
            && before.dev() == directory.dev
            && before.ino() == directory.ino,
    )?;
    let bytes = serde_json::to_vec(&OpenBaoCustody {
        schema: "elevenid.installer-openbao-private-inputs/v1".into(),
        project: receipt.project.clone(),
        engine_id: receipt.engine_id.clone(),
        tls_container_id: tls.id.clone(),
        tls_image: tls.image.clone(),
        directory,
    })
    .map_err(|_| REFUSED)?;
    state.write_evidence(OPENBAO_CUSTODY, &bytes)?;
    let file = BoundFile {
        path: installation.join("evidence").join(OPENBAO_CUSTODY),
        sha256: sha256(&bytes),
    };
    regular_bound(&file, installation)?;
    Ok(file)
}
/// These two files were already narrow helper inputs before the Compose change.
/// Their OpenBao-owned 0700 ancestor cannot be traversed by the host operator.
/// Bind the unchanged ancestor and successful jobs; the unchanged helper still
/// validates the actual credential/certificate inside the rootless namespace.
fn private_openbao_input(path: &Path, readonly: bool, p: &ComposeInputs) -> Result<bool> {
    if path != p.installation.join("openbao-state/root.token")
        && path != p.installation.join("openbao-state/tls/ca.crt")
    {
        return Ok(false);
    }
    require(readonly)?;
    let prior = p.prior.as_ref().ok_or(REFUSED)?;
    require(
        prior.observation_validated
            && prior.project == p.project
            && ((prior.command_succeeded
                && prior.client_exit_code == Some(0)
                && prior.failure_class.is_none())
                || finite_application_failure(prior).is_ok()),
    )?;
    let file = p.installation.join("evidence").join(OPENBAO_CUSTODY);
    let hash = prior.input_files.get(&file).ok_or(REFUSED)?;
    let bytes = crate::installer_verify::read_private_record(&file)?;
    require(sha256(&bytes) == *hash)?;
    let record: OpenBaoCustody =
        serde_json::from_value(crate::installer_json::decode(&bytes).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED)?;
    validate_openbao_custody(
        &record,
        p,
        &private_directory(&p.installation.join("openbao-state"))?,
    )?;
    Ok(true)
}
fn validate_openbao_custody(
    record: &OpenBaoCustody,
    p: &ComposeInputs,
    observed: &PrivateDirectoryIdentity,
) -> Result<()> {
    let prior = p.prior.as_ref().ok_or(REFUSED)?;
    let resources = prior.resources.as_ref().ok_or(REFUSED)?;
    let tls = resources
        .containers
        .get("openbao-tls-init")
        .ok_or(REFUSED)?;
    let bootstrap = resources
        .containers
        .get("openbao-bootstrap")
        .ok_or(REFUSED)?;
    require(
        record.schema == "elevenid.installer-openbao-private-inputs/v1"
            && record.project == p.project
            && record.engine_id == prior.engine_id
            && record.tls_container_id == tls.id
            && record.tls_image == tls.image
            && p.approved_images.contains(&tls.image)
            && [tls, bootstrap].iter().all(|job| {
                job.setup
                    && job
                        .setup_execution
                        .as_ref()
                        .is_some_and(|e| e.completed_without_restart)
            })
            && record.directory.uid != unsafe { libc::geteuid() }
            && observed == &record.directory,
    )
}
fn mount_policy(source: &str, readonly: bool, p: &ComposeInputs, check_file: bool) -> Result<()> {
    let path = Path::new(source);
    require(if readonly {
        within(path, &p.readonly_bind_roots) || within(path, &p.writable_bind_roots)
    } else {
        within(path, &p.writable_bind_roots)
    })?;
    if check_file {
        let canonical = match path.canonicalize() {
            Ok(canonical) => canonical,
            Err(error)
                if error.kind() == std::io::ErrorKind::PermissionDenied
                    && private_openbao_input(path, readonly, p)? =>
            {
                return Ok(())
            }
            Err(_) => return Err(REFUSED.into()),
        };
        require(canonical == path)?;
        let m = fs::symlink_metadata(path).map_err(|_| REFUSED)?;
        require(m.is_dir() || (m.is_file() && m.nlink() == 1))?;
    }
    Ok(())
}
fn scoped_name(value: &str, project: &str) -> bool {
    value.strip_prefix(&format!("{project}_")).is_some_and(name)
}
/// Compose may reuse a same-name volume even when it has no Compose labels.
/// Include those collisions in the census before any lifecycle operation; the
/// ordinary label and prior-identity checks then refuse their adoption.
fn resource_names(labelled: &str, named: &str, project: &str) -> Result<BTreeSet<String>> {
    let mut result: BTreeSet<String> = labelled.lines().map(str::to_owned).collect();
    require(
        result.len() == labelled.lines().count()
            && result.iter().all(|value| scoped_name(value, project)),
    )?;
    // The Engine's name filter can match substrings. Only this project's exact
    // namespace is relevant; a neighboring project's matching substring is not.
    result.extend(
        named
            .lines()
            .filter(|value| scoped_name(value, project))
            .map(str::to_owned),
    );
    require(result.len() <= 32)?;
    Ok(result)
}
fn completed(resources: &ProjectResources, status: &[Value]) -> bool {
    if status.len() != resources.containers.len() {
        return false;
    }
    let mut seen = BTreeSet::new();
    status.iter().all(|row| {
        let Some(role) = row["Service"].as_str() else {
            return false;
        };
        let Some(container) = resources.containers.get(role) else {
            return false;
        };
        seen.insert(role)
            && row["ID"] == container.id
            && if container.setup {
                row["State"] == "exited"
                    && row["ExitCode"] == 0
                    && container
                        .setup_execution
                        .as_ref()
                        .is_some_and(|execution| execution.completed_without_restart)
            } else {
                row["State"] == "running"
                    && (!container.health_required || row["Health"] == "healthy")
            }
    })
}
fn retained_setup_completed(container: &Value) -> bool {
    container["State"]["Status"] == "exited"
        && container["State"]["Running"] == false
        && container["State"]["Paused"] == false
        && container["State"]["Restarting"] == false
        && container["State"]["Dead"] == false
        && container["State"]["OOMKilled"] == false
        && container["State"]["ExitCode"] == 0
        && container["RestartCount"] == 0
}
fn command_outcome(result: &Result<String>, complete: bool) -> (Option<i32>, Option<String>) {
    match result {
        Ok(_) => (
            Some(0),
            (!complete).then(|| "postcondition_not_established".into()),
        ),
        Err(error) => {
            if let Some(code) = error
                .strip_prefix("Docker command failed (exit=Some(")
                .and_then(|s| s.strip_suffix(")); inspect owned runtime separately"))
                .and_then(|s| s.parse::<i32>().ok())
                .filter(|code| (1..=125).contains(code))
            {
                return (Some(code), Some("client_exit_nonzero".into()));
            }
            let prefix = "Compose setup failed (exit=Some(";
            let suffix = ")); inspect private project evidence; no retry was performed";
            if let Some(code) = error
                .strip_prefix(prefix)
                .and_then(|s| s.strip_suffix(suffix))
                .and_then(|s| s.parse::<i32>().ok())
                .filter(|code| (1..=255).contains(code))
            {
                return (Some(code), Some("client_exit_nonzero".into()));
            }
            let class = match error.as_str() {
                "Compose setup failed (exit=None); inspect private project evidence; no retry was performed" => "client_terminated_outcome_uncertain",
                "Docker command timed out; owned child process group was cancelled" => "client_timeout_outcome_uncertain",
                "Compose wait deadline reached; inspect retained project before recovery" => "client_timeout_outcome_uncertain",
                "Compose setup completed but diagnostic output exceeded the capture bound; inspect retained project before continuing" => {
                    return (Some(0), Some("output_capture_incomplete".into()));
                }
                _ => "runtime_boundary_outcome_uncertain",
            };
            (None, Some(class.into()))
        }
    }
}

enum Evidence<'a> {
    Install(&'a mut InstallerState),
    Maintenance(&'a mut LockedMaintenance),
}
impl Evidence<'_> {
    fn journal(&self) -> &Journal {
        match self {
            Self::Install(s) => s.journal(),
            Self::Maintenance(s) => s.journal(),
        }
    }
    fn write(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        match self {
            Self::Install(s) => s.write_evidence(name, bytes),
            Self::Maintenance(s) => s.write_evidence_exclusive(name, bytes),
        }
    }
    fn prefix(&self) -> &'static str {
        match self {
            Self::Install(_) => "compose",
            Self::Maintenance(_) => "uninstall-compose",
        }
    }
}

/// Validate only deployment policy. Compose validates syntax and dependencies.
/// There is deliberately no service-name, secret-name, dependency or mount table.
fn admit_model(model: &Value, p: &ComposeInputs) -> Result<()> {
    require(model["name"] == p.project)?;
    require(model.as_object().ok_or(REFUSED)?.keys().all(|k| {
        k.starts_with("x-")
            || [
                "name", "services", "networks", "volumes", "secrets", "configs",
            ]
            .contains(&k.as_str())
    }))?;
    let services = model["services"].as_object().ok_or(REFUSED)?;
    require(!services.is_empty() && services.len() <= 96)?;
    for (role, service) in services {
        require(name(role) && p.approved_images.contains(text(&service["image"])?))?;
        for field in [
            "build",
            "provider",
            "develop",
            "extends",
            "volumes_from",
            "devices",
            "device_cgroup_rules",
            "network_mode",
            "pid",
            "ipc",
            "uts",
            "userns_mode",
            "cgroup_parent",
            "container_name",
            "links",
            "external_links",
            "extra_hosts",
            "post_start",
            "pre_start",
            "pre_stop",
        ] {
            require(empty(service.get(field)))?;
        }
        let setup = service["labels"][SETUP_LABEL] == "setup";
        capability_policy(
            setup,
            &capabilities(service.get("cap_add"))?,
            &capabilities(service.get("cap_drop"))?,
        )?;
        memory_limit(&service["mem_limit"])?;
        require(
            service.get("privileged").is_none_or(|v| v == false)
                && service["init"] == true
                && strings(service.get("security_opt"))? == ["no-new-privileges:true"],
        )?;
        require(
            service.get("scale").is_none_or(|v| v == 1)
                && service.get("deploy").is_none_or(|v| empty(Some(v))),
        )?;
        for port in service["ports"].as_array().into_iter().flatten() {
            published(port, &p.allowed_loopback_ports)?;
        }
        for volume in service["volumes"].as_array().into_iter().flatten() {
            match text(&volume["type"])? {
                "bind" => {
                    require(volume["bind"]["create_host_path"] == false)?;
                    let path = config_path(&volume["source"])?;
                    mount_policy(
                        path.to_str().ok_or(REFUSED)?,
                        volume["read_only"] == true,
                        p,
                        true,
                    )?;
                }
                "volume" => {
                    let declaration = &model["volumes"][text(&volume["source"])?];
                    require(declaration.is_object())?;
                }
                "tmpfs" => require(clean_path(Path::new(text(&volume["target"])?)))?,
                _ => return Err(REFUSED.into()),
            }
        }
        for kind in ["secrets", "configs"] {
            for reference in service[kind].as_array().into_iter().flatten() {
                let declaration = &model[kind][text(&reference["source"])?];
                require(
                    declaration.is_object()
                        && declaration.get("external").is_none_or(|v| v == false)
                        && empty(declaration.get("environment"))
                        && empty(declaration.get("content")),
                )?;
                let path = config_path(&declaration["file"])?;
                mount_policy(path.to_str().ok_or(REFUSED)?, true, p, true)?;
            }
        }
    }
    for (kind, driver) in [("networks", "bridge"), ("volumes", "local")] {
        for value in model[kind].as_object().into_iter().flat_map(|m| m.values()) {
            require(
                scoped_name(text(&value["name"])?, &p.project)
                    && value.get("external").is_none_or(|v| v == false)
                    && value.get("driver").is_none_or(|v| v == driver)
                    && empty(value.get("driver_opts")),
            )?;
        }
    }
    Ok(())
}

impl ComposeSession {
    pub fn new(
        docker_path: &Path,
        binding: &RuntimeBinding,
        inputs: ComposeInputs,
    ) -> Result<Self> {
        Self::new_inner(docker_path, binding, inputs, None, false)
    }
    pub(crate) fn new_with_deadline(
        docker_path: &Path,
        binding: &RuntimeBinding,
        inputs: ComposeInputs,
        deadline: Instant,
    ) -> Result<Self> {
        Self::new_inner(docker_path, binding, inputs, Some(deadline), false)
    }
    pub(crate) fn for_failed_runtime_cleanup(
        docker_path: &Path,
        binding: &RuntimeBinding,
        inputs: ComposeInputs,
        deadline: Option<Instant>,
    ) -> Result<Self> {
        Self::new_inner(docker_path, binding, inputs, deadline, true)
    }
    fn new_inner(
        docker_path: &Path,
        binding: &RuntimeBinding,
        inputs: ComposeInputs,
        deadline: Option<Instant>,
        cleanup_only: bool,
    ) -> Result<Self> {
        binding.validate()?;
        require(
            binding.profile == RuntimeProfile::Rootless
                && clean_path(&inputs.installation)
                && inputs.installation.canonicalize().map_err(|_| REFUSED)? == inputs.installation
                && regex::Regex::new(r"\Amarty-install-[0-9a-f]{32}\z")
                    .unwrap()
                    .is_match(&inputs.project)
                && !inputs.files.is_empty()
                && inputs.files.len() <= 8
                && inputs.bound_inputs.len() <= 8
                && inputs.profiles.len() <= 8
                && inputs.profiles.iter().all(|v| name(v))
                && inputs.services.len() <= 96
                && inputs.services.iter().all(|v| name(v))
                && !inputs.approved_images.is_empty()
                && inputs.approved_images.iter().all(|v| image(v)),
        )?;
        for root in inputs
            .writable_bind_roots
            .iter()
            .chain(&inputs.readonly_bind_roots)
        {
            require(
                clean_path(root)
                    && root.starts_with(&inputs.installation)
                    && root != &inputs.installation,
            )?;
        }
        let mut bindings = BTreeMap::new();
        require(!cleanup_only || (inputs.prior.is_some() && inputs.services.is_empty()))?;
        if let Some(prior) = &inputs.prior {
            require(
                prior.schema == "elevenid.installer-compose-operation/v1"
                    && prior.project == inputs.project
                    && prior.engine_id == binding.engine_id
                    && prior.observation_validated
                    && prior.resources.is_some()
                    && !prior.installation_ready,
            )?;
            if cleanup_only {
                finite_application_failure(prior)?;
            } else {
                require(
                    prior.command_succeeded
                        && prior.client_exit_code == Some(0)
                        && prior.failure_class.is_none(),
                )?;
            }
            bindings = prior.input_files.clone();
        }
        for file in inputs
            .files
            .iter()
            .chain(std::iter::once(&inputs.environment))
            .chain(&inputs.bound_inputs)
        {
            if let Some(old) = bindings.insert(file.path.clone(), file.sha256.clone()) {
                require(old == file.sha256)?;
            }
        }
        verify_input_files(&inputs.installation, &bindings)?;
        let mut docker = DockerRunner::from_binding(docker_path, binding, &inputs.installation)?;
        if let Some(deadline) = deadline {
            docker = docker.with_deadline(deadline);
        }
        let observation = docker.preflight()?;
        require_version(&observation.compose_version)?;
        let mut session = Self {
            docker,
            binding: binding.clone(),
            inputs,
            model: Value::Null,
            hashes: BTreeMap::new(),
            configuration_sha256: String::new(),
            bindings,
            cleanup_only,
        };
        let output = session.compose(
            &["config", "--format", "json"],
            true,
            Duration::from_secs(60),
        )?;
        let model: Value = serde_json::from_str(&output).map_err(|_| REFUSED)?;
        admit_model(&model, &session.inputs)?;
        if cleanup_only {
            validate_failed_runtime_cleanup(session.inputs.prior.as_ref().ok_or(REFUSED)?, &model)?;
        }
        let hashes = model_hashes(&session.compose(
            &["config", "--hash", "*"],
            true,
            Duration::from_secs(60),
        )?)?;
        require(
            model["services"]
                .as_object()
                .ok_or(REFUSED)?
                .keys()
                .all(|role| hashes.contains_key(role)),
        )?;
        session.configuration_sha256 = model_sha256(&model)?;
        session.model = model;
        session.hashes = hashes;
        Ok(session)
    }

    pub fn model(&self) -> &Value {
        &self.model
    }
    pub fn configuration_sha256(&self) -> &str {
        &self.configuration_sha256
    }
    pub fn observe_resources(&self) -> Result<ProjectResources> {
        self.observe(false)
    }
    fn recheck(&self) -> Result<()> {
        verify_input_files(&self.inputs.installation, &self.bindings)
    }
    fn arguments(&self, operation: &[&str], selection: bool) -> Result<Vec<String>> {
        let mut args = vec![
            "compose".into(),
            "--project-name".into(),
            self.inputs.project.clone(),
            "--project-directory".into(),
            self.inputs.files[0]
                .path
                .parent()
                .ok_or(REFUSED)?
                .to_str()
                .ok_or(REFUSED)?
                .into(),
            "--env-file".into(),
            self.inputs.environment.path.to_str().ok_or(REFUSED)?.into(),
        ];
        for file in &self.inputs.files {
            args.extend(["-f".into(), file.path.to_str().ok_or(REFUSED)?.into()]);
        }
        for profile in &self.inputs.profiles {
            args.extend(["--profile".into(), profile.clone()]);
        }
        args.extend(operation.iter().map(|v| (*v).to_owned()));
        if selection {
            args.extend(self.inputs.services.iter().cloned());
        }
        Ok(args)
    }
    fn compose(&self, operation: &[&str], selection: bool, timeout: Duration) -> Result<String> {
        self.recheck()?;
        let args = self.arguments(operation, selection)?;
        let result = self.docker.run_checked_with_timeout(
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
            timeout,
        );
        self.recheck()?;
        result
    }
    fn compose_setup(&self, operation: &[&str]) -> Result<String> {
        self.recheck()?;
        let args = self.arguments(operation, false)?;
        // The caller admits an adequate shutdown window before this operation.
        // Credential/ownership transfer is never interrupted by a CLI timeout.
        let result = self
            .docker
            .run_setup_checked(&args.iter().map(String::as_str).collect::<Vec<_>>());
        self.recheck()?;
        result
    }
    fn prior(&self) -> ProjectResources {
        self.inputs
            .prior
            .as_ref()
            .and_then(|r| r.resources.clone())
            .unwrap_or_default()
    }

    /// One bounded observation with full IDs for exact identity comparisons.
    /// Native JSON output also truncates IDs unless --no-trunc is explicit.
    pub fn status(&self) -> Result<Vec<Value>> {
        rows(&self.compose(
            &["ps", "--all", "--no-trunc", "--format", "json"],
            false,
            Duration::from_secs(60),
        )?)
    }

    /// Raw output remains private. Call the existing credential redactor before
    /// presentation; setup/bootstrap services are deliberately excluded here.
    pub fn logs(&self, services: &[String], tail: u16) -> Result<String> {
        require(!services.is_empty() && tail > 0 && tail <= 1000)?;
        for service in services {
            let config = &self.model["services"][service];
            require(config.is_object() && config["labels"][SETUP_LABEL] != "setup")?;
        }
        self.observe(false)?;
        let number = tail.to_string();
        let mut args = vec!["logs", "--no-color", "--timestamps", "--tail", &number];
        args.extend(services.iter().map(String::as_str));
        self.compose(&args, false, Duration::from_secs(60))
    }

    /// Pull only verified immutable references selected by the native model.
    pub fn pull(&self) -> Result<()> {
        require(!self.cleanup_only)?;
        self.compose(
            &["pull", "--policy", "missing"],
            true,
            Duration::from_secs(MAX_WAIT),
        )
        .map(|_| ())
    }

    /// Bind the authenticated maintenance union without running or replaying any
    /// service. The original startup receipt remains an independent observation.
    pub fn checkpoint(
        &self,
        state: &mut InstallerState,
        operation: &str,
    ) -> Result<ComposeReceipt> {
        require(
            !self.cleanup_only && self.inputs.prior.is_some() && self.inputs.services.is_empty(),
        )?;
        let mut state = Evidence::Install(state);
        self.begin(
            &mut state,
            operation,
            &["ps", "--all", "--no-trunc", "--format", "json"],
        )?;
        let resources = self.observe(false);
        let status = self.status();
        let result = status.as_ref().map(|_| String::new()).map_err(Clone::clone);
        let complete = matches!((&resources, &status), (Ok(resources), Ok(status)) if completed(resources, status));
        self.receipt(&mut state, operation, &result, complete, resources, status)
    }

    fn observe(&self, allow_new: bool) -> Result<ProjectResources> {
        self.recheck()?;
        let project_label = format!("label=com.docker.compose.project={}", self.inputs.project);
        let ids = identifiers(&self.docker.run_checked(&[
            "ps",
            "-aq",
            "--no-trunc",
            "--filter",
            &project_label,
        ])?)?;
        require(ids.len() <= 128)?;
        let prior = self.prior();
        let mut result = ProjectResources::default();
        let mut images = BTreeMap::<String, String>::new();
        let id_list: Vec<_> = ids.iter().map(String::as_str).collect();
        for chunk in id_list.chunks(32) {
            let mut args = vec!["inspect"];
            args.extend_from_slice(chunk);
            let inspected: Vec<Value> =
                serde_json::from_str(&self.docker.run_checked(&args)?).map_err(|_| REFUSED)?;
            require(inspected.len() == chunk.len())?;
            for container in inspected {
                let id = text(&container["Id"])?;
                let config = &container["Config"];
                let labels = &config["Labels"];
                let role = text(&labels["com.docker.compose.service"])?;
                let identity = ContainerIdentity {
                    id: id.into(),
                    service: role.into(),
                    image: text(&config["Image"])?.into(),
                    config_hash: text(&labels["com.docker.compose.config-hash"])?.into(),
                    setup: labels[SETUP_LABEL] == "setup",
                    setup_execution: if labels[SETUP_LABEL] == "setup" {
                        let started = text(&container["State"]["StartedAt"])?;
                        let finished = text(&container["State"]["FinishedAt"])?;
                        require(
                            started.len() <= 64
                                && finished.len() <= 64
                                && chrono::DateTime::parse_from_rfc3339(started).is_ok()
                                && chrono::DateTime::parse_from_rfc3339(finished).is_ok(),
                        )?;
                        Some(SetupExecution {
                            started_at: started.into(),
                            finished_at: finished.into(),
                            completed_without_restart: retained_setup_completed(&container),
                        })
                    } else {
                        None
                    },
                    health_required: config["Healthcheck"]["Test"]
                        .as_array()
                        .is_some_and(|test| !test.is_empty() && test[0] != "NONE"),
                    cap_add: capabilities(container["HostConfig"].get("CapAdd"))?,
                    cap_drop: capabilities(container["HostConfig"].get("CapDrop"))?,
                    read_only: container["HostConfig"]["ReadonlyRootfs"] == true,
                    memory_limit: memory_limit(&container["HostConfig"]["Memory"])?,
                };
                require(
                    ids.contains(id)
                        && name(role)
                        && digest(&identity.config_hash)
                        && labels["com.docker.compose.project"] == self.inputs.project
                        && labels["com.docker.compose.oneoff"] == "False"
                        && labels["com.docker.compose.container-number"] == "1"
                        && self.inputs.approved_images.contains(&identity.image),
                )?;
                if !images.contains_key(&identity.image) {
                    let observed: Vec<Value> =
                        serde_json::from_str(&self.docker.run_checked(&[
                            "image",
                            "inspect",
                            &identity.image,
                        ])?)
                        .map_err(|_| REFUSED)?;
                    require(observed.len() == 1)?;
                    validate_image_digest(&observed[0], &identity.image)?;
                    let image_id = text(&observed[0]["Id"])?;
                    require(image_id.strip_prefix("sha256:").is_some_and(digest))?;
                    images.insert(identity.image.clone(), image_id.into());
                }
                require(c_image(&container)? == images[&identity.image])?;
                match prior.containers.get(role) {
                    Some(old) => {
                        require(old == &identity)?;
                        if old.setup {
                            require(retained_setup_completed(&container))?;
                        }
                    }
                    None => require(
                        allow_new
                            && self.model["services"][role]["image"] == identity.image
                            && self.hashes.get(role) == Some(&identity.config_hash)
                            && identity.setup
                                == (self.model["services"][role]["labels"][SETUP_LABEL] == "setup")
                            && identity.cap_add
                                == capabilities(self.model["services"][role].get("cap_add"))?
                            && identity.cap_drop
                                == capabilities(self.model["services"][role].get("cap_drop"))?
                            && identity.read_only
                                == (self.model["services"][role]["read_only"] == true)
                            && identity.memory_limit
                                == memory_limit(&self.model["services"][role]["mem_limit"])?,
                    )?,
                }
                self.live_policy(&container)?;
                require(result.containers.insert(role.into(), identity).is_none())?;
            }
        }
        for (kind, plural) in [("network", "networks"), ("volume", "volumes")] {
            let labelled = self.docker.run_checked(&[
                kind,
                "ls",
                "--format",
                "{{.Name}}",
                "--filter",
                &project_label,
            ])?;
            let name_filter = format!("name={}_", self.inputs.project);
            let named = self.docker.run_checked(&[
                kind,
                "ls",
                "--format",
                "{{.Name}}",
                "--filter",
                &name_filter,
            ])?;
            let names = resource_names(&labelled, &named, &self.inputs.project)?;
            for observed in names {
                let objects: Vec<Value> =
                    serde_json::from_str(&self.docker.run_checked(&[kind, "inspect", &observed])?)
                        .map_err(|_| REFUSED)?;
                require(objects.len() == 1)?;
                let value = &objects[0];
                let resource_name = text(&value["Name"])?;
                let already = if kind == "network" {
                    prior.networks.contains_key(resource_name)
                } else {
                    prior.volumes.contains(resource_name)
                };
                let declared = self.model[plural]
                    .as_object()
                    .into_iter()
                    .flat_map(|m| m.values())
                    .any(|v| v["name"] == resource_name);
                require(
                    scoped_name(resource_name, &self.inputs.project)
                        && value["Labels"]["com.docker.compose.project"] == self.inputs.project
                        && (already || (allow_new && declared))
                        && empty(value.get("Options")),
                )?;
                if kind == "network" {
                    let resource_id = text(&value["Id"])?;
                    require(digest(resource_id) && value["Driver"] == "bridge")?;
                    if let Some(old) = prior.networks.get(resource_name) {
                        require(old == resource_id)?;
                    }
                    for consumer in value["Containers"]
                        .as_object()
                        .into_iter()
                        .flat_map(|m| m.keys())
                    {
                        require(ids.contains(consumer))?;
                    }
                    require(
                        result
                            .networks
                            .insert(resource_name.into(), resource_id.into())
                            .is_none(),
                    )?;
                } else {
                    require(value["Driver"] == "local" && value["Scope"] == "local")?;
                    let filter = format!("volume={resource_name}");
                    let consumers = identifiers(&self.docker.run_checked(&[
                        "ps",
                        "-aq",
                        "--no-trunc",
                        "--filter",
                        &filter,
                    ])?)?;
                    require(consumers.is_subset(&ids))?;
                    result.volumes.insert(resource_name.into());
                }
            }
        }
        require(
            prior
                .containers
                .iter()
                .all(|(role, identity)| result.containers.get(role) == Some(identity))
                && prior
                    .networks
                    .iter()
                    .all(|(name, id)| result.networks.get(name) == Some(id))
                && prior.volumes.is_subset(&result.volumes),
        )?;
        if !allow_new {
            require(result == prior)?;
        }
        Ok(result)
    }

    fn live_policy(&self, c: &Value) -> Result<()> {
        let host = &c["HostConfig"];
        capability_policy(
            c["Config"]["Labels"][SETUP_LABEL] == "setup",
            &capabilities(host.get("CapAdd"))?,
            &capabilities(host.get("CapDrop"))?,
        )?;
        require(
            host["Privileged"] == false
                && host["Init"] == true
                && strings(host.get("SecurityOpt"))?
                    .iter()
                    .all(|v| ["no-new-privileges", "no-new-privileges:true"].contains(v))
                && strings(host.get("SecurityOpt"))?.len() == 1
                && empty(host.get("PidMode"))
                && empty(host.get("UsernsMode"))
                && ["private", ""].contains(&host["IpcMode"].as_str().unwrap_or(""))
                && empty(host.get("Devices"))
                && empty(host.get("VolumesFrom"))
                && scoped_name(text(&host["NetworkMode"])?, &self.inputs.project),
        )?;
        for network in c["NetworkSettings"]["Networks"]
            .as_object()
            .ok_or(REFUSED)?
            .keys()
        {
            require(scoped_name(network, &self.inputs.project))?;
        }
        for mount in c["Mounts"].as_array().ok_or(REFUSED)? {
            match text(&mount["Type"])? {
                "bind" => mount_policy(
                    text(&mount["Source"])?,
                    mount["RW"] == false,
                    &self.inputs,
                    false,
                )?,
                "volume" => require(scoped_name(text(&mount["Name"])?, &self.inputs.project))?,
                "tmpfs" => (),
                _ => return Err(REFUSED.into()),
            }
        }
        for bindings in c["NetworkSettings"]["Ports"]
            .as_object()
            .into_iter()
            .flat_map(|m| m.values())
        {
            for port in bindings.as_array().into_iter().flatten() {
                let port_number = text(&port["HostPort"])?
                    .parse::<u16>()
                    .map_err(|_| REFUSED)?;
                require(
                    port["HostIp"] == "127.0.0.1"
                        && self.inputs.allowed_loopback_ports.contains(&port_number),
                )?;
            }
        }
        Ok(())
    }

    fn write(
        &self,
        state: &mut Evidence<'_>,
        operation: &str,
        suffix: &str,
        value: &Value,
    ) -> Result<()> {
        require(
            name(operation)
                && state.journal().compose_project() == self.inputs.project
                && state
                    .journal()
                    .runtime()
                    .is_some_and(|b| b == &self.binding),
        )?;
        state.write(
            &format!("{}-{operation}-{suffix}.json", state.prefix()),
            &serde_json::to_vec(value).map_err(|_| REFUSED)?,
        )
    }
    fn begin(&self, state: &mut Evidence<'_>, operation: &str, command: &[&str]) -> Result<()> {
        let observed = self.observe(false)?;
        self.write(
            state,
            operation,
            "intent",
            &json!({
                "schema":"elevenid.installer-compose-intent/v1", "project":self.inputs.project,
                "engine_id":self.binding.engine_id,"configuration_sha256":self.configuration_sha256,
                "input_files":self.bindings,"command":command,"prior_resources":observed,
                "automatic_retry":false,"installation_ready":false
            }),
        )
    }
    fn receipt(
        &self,
        state: &mut Evidence<'_>,
        operation: &str,
        command_result: &Result<String>,
        complete: bool,
        resources: Result<ProjectResources>,
        statuses: Result<Vec<Value>>,
    ) -> Result<ComposeReceipt> {
        let observation_validated = resources.is_ok() && statuses.is_ok();
        let command_succeeded = command_result.is_ok() && complete;
        let (client_exit_code, failure_class) = command_outcome(command_result, complete);
        let receipt = ComposeReceipt {
            schema: if self.cleanup_only {
                CLEANUP_RECEIPT_SCHEMA
            } else {
                "elevenid.installer-compose-operation/v1"
            }
            .into(),
            project: self.inputs.project.clone(),
            engine_id: self.binding.engine_id.clone(),
            operation: operation.into(),
            configuration_sha256: self.configuration_sha256.clone(),
            input_files: self.bindings.clone(),
            command_succeeded,
            client_exit_code,
            failure_class,
            observation_validated,
            resources: resources.ok(),
            status: statuses.unwrap_or_default(),
            installation_ready: false,
        };
        self.write(
            state,
            operation,
            "result",
            &serde_json::to_value(&receipt).map_err(|_| REFUSED)?,
        )?;
        if command_succeeded && observation_validated {
            Ok(receipt)
        } else {
            Err(UNCERTAIN.into())
        }
    }

    pub fn up_wait(
        &self,
        state: &mut InstallerState,
        operation: &str,
        timeout: Duration,
    ) -> Result<ComposeReceipt> {
        require(!self.cleanup_only)?;
        let mut state = Evidence::Install(state);
        require(timeout.as_secs() > 0 && timeout.as_secs() <= MAX_WAIT)?;
        let seconds = timeout.as_secs().to_string();
        let command = [
            "up",
            "--no-build",
            "--pull",
            "never",
            "--no-recreate",
            "--wait",
            "--wait-timeout",
            &seconds,
        ];
        self.begin(&mut state, operation, &command)?;
        let began = Instant::now();
        let result = self.compose(&command, true, timeout + Duration::from_secs(60));
        // A native --wait timeout exits normally with a nonzero code. Keep it
        // ineligible for automatic failure cleanup just like a client timeout.
        let result = if result.is_err() && began.elapsed() >= timeout {
            Err("Compose wait deadline reached; inspect retained project before recovery".into())
        } else {
            result
        };
        let resources = self.observe(true);
        let status = self.status();
        let complete = match (&resources, &status) {
            (Ok(resources), Ok(status)) => {
                self.model["services"].as_object().is_some_and(|services| {
                    services
                        .keys()
                        .all(|role| resources.containers.contains_key(role))
                }) && completed(resources, status)
            }
            _ => false,
        };
        self.receipt(&mut state, operation, &result, complete, resources, status)
    }

    /// Exactly one first-install job, with no dependency start/stop side effects.
    /// The immutable intent prevents repeat execution even after a lost CLI result.
    pub fn run_setup_job(
        &self,
        state: &mut InstallerState,
        service: &str,
    ) -> Result<ComposeReceipt> {
        require(!self.cleanup_only)?;
        let mut state = Evidence::Install(state);
        let config = &self.model["services"][service];
        require(
            name(service)
                && config.is_object()
                && config["restart"] == "no"
                && config["labels"][SETUP_LABEL] == "setup"
                && !self.prior().containers.contains_key(service),
        )?;
        require(completed(&self.prior(), &self.status()?))?;
        let operation = format!("setup-{service}");
        let command = [
            "up",
            "--no-build",
            "--pull",
            "never",
            "--no-deps",
            "--no-recreate",
            "--abort-on-container-exit",
            "--exit-code-from",
            service,
            service,
        ];
        self.begin(&mut state, &operation, &command)?;
        let result = self.compose_setup(&command);
        let resources = self.observe(true);
        let statuses = self.status();
        let exited_zero = match (&resources, &statuses) {
            (Ok(resources), Ok(rows)) => {
                resources.containers.len() == self.prior().containers.len() + 1
                    && resources.containers.contains_key(service)
                    && completed(resources, rows)
            }
            _ => false,
        };
        self.receipt(
            &mut state,
            &operation,
            &result,
            exited_zero,
            resources,
            statuses,
        )
    }

    /// Start only retained runtime containers. The runtime layer must remove all
    /// setup dependencies; this never creates resources or replays initialization.
    pub(crate) fn start_existing(
        &self,
        state: &mut LockedMaintenance,
        operation: &str,
        timeout: Duration,
    ) -> Result<ComposeReceipt> {
        require(
            !self.cleanup_only
                && self.inputs.prior.is_some()
                && !self.inputs.services.is_empty()
                && timeout.as_secs() > 0
                && timeout.as_secs() <= MAX_WAIT,
        )?;
        runtime_selection(&self.model, &self.prior(), &self.inputs.services)?;
        let mut state = Evidence::Maintenance(state);
        let seconds = timeout.as_secs().to_string();
        let command = ["start", "--wait", "--wait-timeout", &seconds];
        self.begin(&mut state, operation, &command)?;
        let result = self.compose(&command, true, timeout + Duration::from_secs(60));
        let resources = self.observe(false);
        let status = self.status();
        let complete = matches!((&resources, &status), (Ok(resources), Ok(status)) if completed(resources, status));
        self.receipt(&mut state, operation, &result, complete, resources, status)
    }

    pub(crate) fn stop(
        &self,
        state: &mut LockedMaintenance,
        operation: &str,
        timeout: Duration,
    ) -> Result<ComposeReceipt> {
        self.shutdown(state, operation, timeout, false)
    }
    /// Uses the authenticated union configuration. Named data volumes, images,
    /// host inputs, recovery material and neighboring projects are retained.
    pub(crate) fn down(
        &self,
        state: &mut LockedMaintenance,
        operation: &str,
        timeout: Duration,
    ) -> Result<ComposeReceipt> {
        self.shutdown(state, operation, timeout, true)
    }
    fn shutdown(
        &self,
        state: &mut LockedMaintenance,
        operation: &str,
        timeout: Duration,
        down: bool,
    ) -> Result<ComposeReceipt> {
        let mut state = Evidence::Maintenance(state);
        require(
            self.inputs.prior.is_some()
                && self.inputs.services.is_empty()
                && timeout.as_secs() > 0
                && timeout.as_secs() <= 120,
        )?;
        // Never subject an in-flight credential/ownership job to normal stop's
        // grace-period escalation. Recovery of such a phase is a separate action.
        for row in self.status()? {
            let service = text(&row["Service"])?;
            if self
                .prior()
                .containers
                .get(service)
                .is_some_and(|c| c.setup)
            {
                require(row["State"] == "exited" || row["State"] == "created")?;
            }
        }
        let seconds = timeout.as_secs().to_string();
        let command = [if down { "down" } else { "stop" }, "--timeout", &seconds];
        self.begin(&mut state, operation, &command)?;
        let result = self.compose(&command, false, Duration::from_secs(300));
        if down {
            let label = format!("label=com.docker.compose.project={}", self.inputs.project);
            let containers =
                self.docker
                    .run_checked(&["ps", "-aq", "--no-trunc", "--filter", &label]);
            let networks = self
                .docker
                .run_checked(&["network", "ls", "-q", "--filter", &label]);
            let volumes = self
                .docker
                .run_checked(&["volume", "ls", "-q", "--filter", &label]);
            let complete = containers.as_ref().is_ok_and(|s| s.trim().is_empty())
                && networks.as_ref().is_ok_and(|s| s.trim().is_empty())
                && volumes.as_ref().is_ok_and(|s| {
                    s.lines().map(str::to_owned).collect::<BTreeSet<_>>() == self.prior().volumes
                });
            let retained = ProjectResources {
                volumes: self.prior().volumes,
                ..ProjectResources::default()
            };
            self.receipt(
                &mut state,
                operation,
                &result,
                complete,
                if complete {
                    Ok(retained)
                } else {
                    Err(REFUSED.into())
                },
                self.status(),
            )
        } else {
            let statuses = self.status();
            let stopped = statuses.as_ref().is_ok_and(|rows| {
                rows.iter()
                    .all(|r| r["State"] == "exited" || r["State"] == "created")
            });
            self.receipt(
                &mut state,
                operation,
                &result,
                stopped,
                self.observe(false),
                statuses,
            )
        }
    }
}

fn runtime_selection(model: &Value, prior: &ProjectResources, selected: &[String]) -> Result<()> {
    let services = model["services"].as_object().ok_or(REFUSED)?;
    require(
        !selected.is_empty()
            && selected.iter().all(|role| services.contains_key(role))
            && services.iter().all(|(role, config)| {
                config["labels"][SETUP_LABEL] != "setup"
                    && prior
                        .containers
                        .get(role)
                        .is_some_and(|identity| !identity.setup)
                    && config["depends_on"]
                        .as_object()
                        .into_iter()
                        .flat_map(|dependencies| dependencies.keys())
                        .all(|dependency| {
                            services.contains_key(dependency)
                                && prior
                                    .containers
                                    .get(dependency)
                                    .is_some_and(|identity| !identity.setup)
                        })
            }),
    )
}

fn finite_application_failure(receipt: &ComposeReceipt) -> Result<()> {
    require(
        receipt.schema == "elevenid.installer-compose-operation/v1"
            && receipt.operation == "application-up"
            && !receipt.command_succeeded
            && receipt
                .client_exit_code
                .is_some_and(|code| (1..=125).contains(&code))
            && receipt.failure_class.as_deref() == Some("client_exit_nonzero")
            && receipt.observation_validated
            && !receipt.installation_ready
            && receipt.resources.is_some(),
    )
}

/// A completed client failure can permit removal of its exactly observed
/// runtime, but never initialization replay. Every configured setup job must
/// already have a successful, timestamp-bound terminal observation.
pub(crate) fn validate_failed_runtime_cleanup(
    receipt: &ComposeReceipt,
    model: &Value,
) -> Result<()> {
    finite_application_failure(receipt)?;
    let resources = receipt.resources.as_ref().ok_or(REFUSED)?;
    let services = model["services"].as_object().ok_or(REFUSED)?;
    require(
        model["name"] == receipt.project
            && !resources.containers.is_empty()
            && services.len() == resources.containers.len()
            && resources.containers.iter().all(|(role, identity)| {
                services.contains_key(role)
                    && identity.setup == (services[role]["labels"][SETUP_LABEL] == "setup")
            })
            && services
                .iter()
                .filter(|(_, config)| config["labels"][SETUP_LABEL] == "setup")
                .all(|(role, _)| {
                    resources.containers.get(role).is_some_and(|job| {
                        job.setup
                            && job
                                .setup_execution
                                .as_ref()
                                .is_some_and(|execution| execution.completed_without_restart)
                    })
                }),
    )?;
    let mut seen = BTreeSet::new();
    for row in &receipt.status {
        let role = text(&row["Service"])?;
        let identity = resources.containers.get(role).ok_or(REFUSED)?;
        require(
            seen.insert(role)
                && row["ID"] == identity.id
                && ["running", "created", "exited", "restarting", "paused"]
                    .contains(&text(&row["State"])?),
        )?;
        if identity.setup {
            require(row["State"] == "exited" && row["ExitCode"] == 0)?;
        }
    }
    require(seen.len() == resources.containers.len())
}
