//! Filesystem/native-receipt boundary tests. No Docker daemon or CA is used;
//! the public chain is a historical signature/path fixture with a fixed clock.
use super::*;
use crate::{
    installer_compose::{ContainerIdentity, SetupExecution},
    installer_generation_binding::{GenerationFile, GenerationSource, SuccessorBinding},
    installer_public_ingress::{tests as public_fixture, PublicIngressMetadata},
};
use std::os::unix::fs::PermissionsExt;

fn write(root: &Path, name: &str, value: &impl Serialize) -> String {
    let bytes = encode(value).unwrap();
    let path = root.join("evidence").join(name);
    std::fs::write(&path, &bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    hash(&bytes)
}
fn identity(role: &str, digit: char, setup: bool, completed: bool) -> ContainerIdentity {
    ContainerIdentity {
        id: digit.to_string().repeat(64),
        service: role.into(),
        image: format!(
            "ghcr.io/elevenid/marty-ui-oss/services@sha256:{}",
            "c".repeat(64)
        ),
        config_hash: "8".repeat(64),
        setup,
        setup_execution: setup.then(|| SetupExecution {
            started_at: "2026-10-30T00:00:01Z".into(),
            finished_at: "2026-10-30T00:00:02Z".into(),
            completed_without_restart: completed,
        }),
        health_required: false,
        cap_add: BTreeSet::new(),
        cap_drop: BTreeSet::new(),
        read_only: false,
        memory_limit: 64 * 1024 * 1024,
    }
}
fn receipt(
    operation: &str,
    configuration: &str,
    inputs: &ComposeInputs,
    resources: ProjectResources,
    stopped: bool,
) -> ComposeReceipt {
    let rows = resources.containers.iter().map(|(role, value)| json!({
        "Service":role,"ID":value.id,"State":if value.setup || (stopped && role == "api") {"exited"} else {"running"},
        "ExitCode":0,"Health":""
    })).collect();
    ComposeReceipt {
        schema: "elevenid.installer-compose-operation/v1".into(),
        project: inputs.project.clone(),
        engine_id: "engine".into(),
        operation: operation.into(),
        configuration_sha256: configuration.into(),
        input_files: BTreeMap::from([(
            inputs.environment.path.clone(),
            inputs.environment.sha256.clone(),
        )]),
        command_succeeded: true,
        client_exit_code: Some(0),
        failure_class: None,
        observation_validated: true,
        resources: Some(resources),
        status: rows,
        installation_ready: false,
    }
}
fn command(
    receipt: &ComposeReceipt,
    prior: &ProjectResources,
    roles: &[&str],
    create: bool,
) -> Value {
    json!({"schema":"elevenid.installer-compose-intent/v1","project":receipt.project,"engine_id":receipt.engine_id,
        "configuration_sha256":receipt.configuration_sha256,"input_files":receipt.input_files,
        "command":if create {json!(["up","--no-build","--pull","never","--no-deps","--no-start","--force-recreate","--timeout","60"])}
            else {json!(["start","installer-generation"])},
        "prior_resources":prior,"selected_services":roles,"automatic_retry":false,"installation_ready":false})
}

struct Fixture {
    root: tempfile::TempDir,
    old: Intent,
    parent: GenerationBinding,
    previous: GenerationBinding,
    metadata: PublicIngressMetadata,
    supersession: Supersession,
    baseline: Baseline,
}
impl Fixture {
    fn new(replacement: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["evidence", "application-generations"] {
            std::fs::create_dir(root.path().join(name)).unwrap();
            std::fs::set_permissions(
                root.path().join(name),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }
        let plan = public_fixture::plan();
        let metadata = public_fixture::metadata(&plan, true);
        let files = public_fixture::current(&plan);
        let parent = GenerationBinding {
            schema: "elevenid.installer-application-generation/v4".into(),
            installation_id: public_fixture::OWNER.into(),
            engine_id: "engine".into(),
            network_id: Some("b".repeat(64)),
            generation_receipt_sha256: "a".repeat(64),
            files: files
                .iter()
                .map(|(name, bytes)| {
                    (
                        name.clone(),
                        GenerationFile {
                            source: GenerationSource::Candidate,
                            sha256: hash(bytes),
                            size: bytes.len() as u64,
                            source_mode: 0o444,
                            mode: 0o444,
                        },
                    )
                })
                .collect(),
            activated: false,
            root_retired: false,
            installation_ready: false,
            successor: None,
        };
        let mut previous = parent.clone();
        previous.successor = Some(SuccessorBinding {
            sequence: 1,
            attempt: 0,
            parent_attempt: 0,
            parent_binding_sha256: parent.sha256().unwrap(),
            native_operation: Attempt::new(1, 0).operation("wait", 0),
        });
        let output = previous.secret_dir(root.path()).unwrap();
        std::fs::create_dir(&output).unwrap();
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700)).unwrap();
        for (name, bytes) in &files {
            std::fs::write(output.join(name), bytes).unwrap();
            std::fs::set_permissions(output.join(name), std::fs::Permissions::from_mode(0o444))
                .unwrap();
        }
        let env = root.path().join("evidence/input.env");
        std::fs::write(&env, b"FIXTURE=1\n").unwrap();
        std::fs::set_permissions(&env, std::fs::Permissions::from_mode(0o600)).unwrap();
        let project = format!("marty-install-{}", public_fixture::OWNER.replace('-', ""));
        let mut inputs = ComposeInputs {
            installation: root.path().into(),
            project: project.clone(),
            files: Vec::new(),
            bound_inputs: Vec::new(),
            environment: BoundFile {
                path: env,
                sha256: hash(b"FIXTURE=1\n"),
            },
            profiles: vec!["setup".into()],
            services: vec!["installer-generation".into()],
            approved_images: BTreeSet::new(),
            #[cfg(feature = "installer-development")]
            development_image: None,
            writable_bind_roots: BTreeSet::new(),
            readonly_bind_roots: BTreeSet::new(),
            allowed_loopback_ports: BTreeSet::new(),
            ingress_listener: None,
            prior: None,
        };
        let parent_root = parent.secret_dir(root.path()).unwrap();
        let mut model = json!({"name":project,"services":{},"secrets":{}});
        for (role, setup) in [
            ("api", false),
            ("openbao", false),
            ("openbao-unseal", false),
            ("installer-acme-http01", false),
            ("installer-generation", true),
            ("bootstrap", true),
        ] {
            model["services"][role] = json!({"image":"fixture","labels":{"com.elevenid.installer.phase":if setup {"setup"} else {"runtime"}}});
        }
        model["services"]["api"]["secrets"] = json!([
            {"source":"installer_ingress_tls_cert"},{"source":"installer_ingress_tls_kms_token"}]);
        for name in [
            "installer_ingress_tls_cert",
            "installer_ingress_tls_kms_token",
        ] {
            model["secrets"][name] = json!({"file":parent_root.join(name)});
        }
        let configuration = installer_compose::model_sha256(&model).unwrap();
        let mut original = ProjectResources {
            networks: BTreeMap::from([(format!("{project}_default"), "b".repeat(64))]),
            volumes: BTreeSet::from([format!("{project}_data")]),
            containers: BTreeMap::new(),
        };
        for (role, digit, setup) in [
            ("api", '1', false),
            ("openbao", '2', false),
            ("openbao-unseal", '3', false),
            ("installer-acme-http01", '4', false),
            ("installer-generation", '5', true),
            ("bootstrap", '6', true),
        ] {
            original
                .containers
                .insert(role.into(), identity(role, digit, setup, true));
        }
        let initial = receipt("initial", &configuration, &inputs, original.clone(), false);
        inputs.prior = Some(initial.clone());
        let parent_session = SavedSession {
            schema: "elevenid.installer-compose-session/v1".into(),
            installation_id: public_fixture::OWNER.into(),
            inputs: inputs.clone(),
            model: model.clone(),
            configuration_sha256: configuration.clone(),
            receipt: initial,
        };
        let old = Intent {
            schema: "elevenid.installer-generation-maintenance-intent/v1".into(),
            installation_id: public_fixture::OWNER.into(),
            engine_id: "engine".into(),
            sequence: 1,
            attempt: 0,
            parent_attempt: 0,
            parent_binding_sha256: parent.sha256().unwrap(),
            initial_configuration_sha256: configuration.clone(),
            parent_session,
            public_plan_sha256: plan.sha256().unwrap(),
            managed_renewal_plan_sha256: None,
            source_sha256: BTreeMap::new(),
            identity_sha256: BTreeMap::new(),
            helper_inputs: inputs.clone(),
            helper_configuration_sha256: configuration.clone(),
            helper_model: model.clone(),
            created_at: metadata.token_observed_at - 10,
            recovery_baseline_sha256: None,
        };
        let scope = old.scope();
        let next = Attempt::new(1, 1);
        let mut created = original.clone();
        created.containers.insert(
            "installer-generation".into(),
            identity("installer-generation", '7', true, false),
        );
        let create_op = scope.operation("create", 0);
        let mut create_receipt =
            receipt(&create_op, &configuration, &inputs, created.clone(), false);
        create_receipt
            .status
            .iter_mut()
            .find(|row| row["Service"] == "installer-generation")
            .unwrap()["State"] = json!("created");
        let create_hash = write(
            root.path(),
            &format!("generation-compose-{create_op}-result.json"),
            &create_receipt,
        );
        let create_intent_hash = write(
            root.path(),
            &format!("generation-compose-{create_op}-intent.json"),
            &command(&create_receipt, &original, &["installer-generation"], true),
        );
        write(
            root.path(),
            &scope.record("producer"),
            &ProducerRecord {
                schema: "elevenid.installer-generation-producer/v1".into(),
                installation_id: public_fixture::OWNER.into(),
                sequence: 1,
                attempt: 0,
                parent_binding_sha256: parent.sha256().unwrap(),
                container_id: "7".repeat(64),
                create_operation: create_op.clone(),
                created_receipt_sha256: create_hash,
                create_intent_operation: create_op,
                create_intent_sha256: create_intent_hash,
            },
        );
        write(
            root.path(),
            &format!(
                "generation-compose-{}-intent.json",
                scope.operation("start", 0)
            ),
            &command(&create_receipt, &created, &["installer-generation"], false),
        );
        created.containers.insert(
            "installer-generation".into(),
            identity("installer-generation", '7', true, true),
        );
        let helper = receipt(
            &scope.operation("wait", 0),
            &configuration,
            &inputs,
            created.clone(),
            false,
        );
        write(
            root.path(),
            &format!("generation-compose-{}-result.json", helper.operation),
            &helper,
        );
        write(root.path(), &scope.record("helper"), &helper);
        write(root.path(), &scope.record("intent"), &old);
        write(root.path(), &scope.record("public-ingress-plan"), &plan);
        write(
            root.path(),
            &scope.record("candidate"),
            &json!({"candidate_fixture":true}),
        );
        write(root.path(), &scope.record("binding"), &previous);
        write(root.path(), &scope.record("binding-pending"), &previous);
        write(root.path(), "application-generation.json", &parent);
        let mut before = created.clone();
        let mut final_resources = created.clone();
        let mut baseline_inputs = inputs.clone();
        let mut baseline_model = model.clone();
        let mut creates = BTreeMap::new();
        let mut stopped = BTreeSet::new();
        if replacement {
            let mut runtime = model.clone();
            runtime["services"]
                .as_object_mut()
                .unwrap()
                .retain(|_, s| s["labels"]["com.elevenid.installer.phase"] != "setup");
            for name in [
                "installer_ingress_tls_cert",
                "installer_ingress_tls_kms_token",
            ] {
                runtime["secrets"][name] = json!({"file":output.join(name)});
                baseline_model["secrets"][name] = json!({"file":output.join(name)});
            }
            let mut activation_inputs = inputs.clone();
            activation_inputs.profiles.clear();
            activation_inputs.services = vec!["api".into()];
            activation_inputs.prior = Some(helper.clone());
            let activation = ActivationIntent {
                schema: "elevenid.installer-generation-activation-intent/v1".into(),
                installation_id: public_fixture::OWNER.into(),
                sequence: 1,
                attempt: 0,
                binding_sha256: previous.sha256().unwrap(),
                helper_receipt_sha256: hash(&encode(&helper).unwrap()),
                inputs: activation_inputs.clone(),
                configuration_sha256: installer_compose::model_sha256(&runtime).unwrap(),
                model: runtime,
                services: vec!["api".into()],
                created_at: metadata.token_observed_at,
            };
            write(root.path(), &scope.record("activation-intent"), &activation);
            let operation = scope.operation("activate-create", 0);
            let dummy = receipt(
                &operation,
                &activation.configuration_sha256,
                &activation.inputs,
                created.clone(),
                false,
            );
            let digest = write(
                root.path(),
                &format!("generation-compose-{operation}-intent.json"),
                &command(&dummy, &created, &["api"], true),
            );
            creates.insert(operation, digest);
            before.containers.remove("api");
            final_resources
                .containers
                .insert("api".into(), identity("api", '9', false, true));
            baseline_inputs = activation_inputs;
            stopped.insert("api".into());
        }
        let supersession = Supersession {
            schema: SUPERSESSION_SCHEMA.into(),
            installation_id: public_fixture::OWNER.into(),
            engine_id: "engine".into(),
            sequence: 1,
            attempt: 1,
            previous_attempt: 0,
            parent_attempt: 0,
            parent_binding_sha256: parent.sha256().unwrap(),
            parent_session_sha256: hash(&encode(&old.parent_session).unwrap()),
            previous_evidence_sha256: old_evidence(root.path(), scope).unwrap(),
            previous_container_id: "7".repeat(64),
            previous_token_observed_at: metadata.token_observed_at,
            previous_credential_fresh_until: metadata.token_observed_at + 1800,
            previous_certificate_not_after: metadata.certificate_admission["not_after"]
                .as_u64()
                .unwrap(),
            reason: StaleReason::CredentialFreshnessElapsed,
            runtime_replacement_started: replacement,
            original_create_intents: creates.clone(),
            before_resources: before,
            observed_at: metadata.token_observed_at + 1800,
        };
        let supersession_sha256 = write(
            root.path(),
            &next.record("supersession-intent"),
            &supersession,
        );
        baseline_inputs.profiles = old.parent_session.inputs.profiles.clone();
        baseline_inputs.services.clear();
        let baseline_configuration = installer_compose::model_sha256(&baseline_model).unwrap();
        let native = receipt(
            &next.operation("supersede-baseline", 0),
            &baseline_configuration,
            &baseline_inputs,
            final_resources,
            replacement,
        );
        let native_sha256 = write(
            root.path(),
            &format!("generation-compose-{}-result.json", native.operation),
            &native,
        );
        baseline_inputs.prior = Some(native.clone());
        let baseline = Baseline {
            schema: BASELINE_SCHEMA.into(),
            installation_id: public_fixture::OWNER.into(),
            engine_id: "engine".into(),
            sequence: 1,
            attempt: 1,
            supersession_sha256,
            inputs: baseline_inputs,
            model: baseline_model,
            configuration_sha256: baseline_configuration,
            observation: NativeReference {
                operation: native.operation,
                sha256: native_sha256,
            },
            create_intents: creates,
            stopped_services: stopped,
            runtime_generation_root: if replacement { output } else { parent_root },
            observed_at: supersession.observed_at,
            activation_performed: false,
            installation_ready: false,
        };
        Self {
            root,
            old,
            parent,
            previous,
            metadata,
            supersession,
            baseline,
        }
    }
    fn require(&self) -> Result<()> {
        require_supersession(
            self.root.path(),
            &self.supersession,
            &self.old,
            &self.previous,
            &GenerationMaterial::Public(Box::new(self.metadata.clone())),
        )?;
        require_baseline(
            self.root.path(),
            &self.supersession,
            &self.old,
            &self.previous,
            &self.parent,
            &self.baseline,
        )
    }
}

#[test]
fn completed_stale_producer_without_runtime_replacement_keeps_the_serving_census() {
    let fixture = Fixture::new(false);
    fixture.require().unwrap();
    assert!(fixture.baseline.stopped_services.is_empty());
    assert!(!fixture.baseline.activation_performed);
    let receipt = native(fixture.root.path(), &fixture.baseline.observation).unwrap();
    assert!(receipt
        .status
        .iter()
        .filter(|row| row["Service"] != "installer-generation" && row["Service"] != "bootstrap")
        .all(|row| row["State"] == "running"));
}

#[test]
fn missing_consumer_after_lost_create_response_has_a_stopped_exact_model_baseline() {
    let fixture = Fixture::new(true);
    fixture.require().unwrap();
    assert!(!fixture
        .supersession
        .before_resources
        .containers
        .contains_key("api"));
    assert_eq!(
        fixture.baseline.stopped_services,
        BTreeSet::from(["api".into()])
    );
    let receipt = native(fixture.root.path(), &fixture.baseline.observation).unwrap();
    for role in ["openbao", "openbao-unseal", "installer-acme-http01"] {
        assert_eq!(
            receipt.resources.as_ref().unwrap().containers[role],
            fixture.supersession.before_resources.containers[role]
        );
        assert!(receipt
            .status
            .iter()
            .any(|row| row["Service"] == role && row["State"] == "running"));
    }
    assert!(!fixture.baseline.activation_performed);
}

#[test]
fn unknown_failed_or_restarted_helper_cannot_supply_supersession_authority() {
    for fault in ["missing_start", "failed", "restarted", "foreign_id"] {
        let fixture = Fixture::new(false);
        let scope = fixture.old.scope();
        match fault {
            "missing_start" => {
                std::fs::remove_file(fixture.root.path().join("evidence").join(format!(
                    "generation-compose-{}-intent.json",
                    scope.operation("start", 0)
                )))
                .unwrap();
            }
            _ => {
                let mut helper: ComposeReceipt =
                    decode(&read(fixture.root.path(), &scope.record("helper")).unwrap()).unwrap();
                let container = helper
                    .resources
                    .as_mut()
                    .unwrap()
                    .containers
                    .get_mut("installer-generation")
                    .unwrap();
                match fault {
                    "failed" => {
                        helper
                            .status
                            .iter_mut()
                            .find(|r| r["Service"] == "installer-generation")
                            .unwrap()["ExitCode"] = json!(1);
                    }
                    "restarted" => {
                        container
                            .setup_execution
                            .as_mut()
                            .unwrap()
                            .completed_without_restart = false;
                    }
                    "foreign_id" => {
                        container.id = "a".repeat(64);
                    }
                    _ => unreachable!(),
                }
                write(
                    fixture.root.path(),
                    &format!("generation-compose-{}-result.json", helper.operation),
                    &helper,
                );
                write(fixture.root.path(), &scope.record("helper"), &helper);
            }
        }
        assert!(fixture.require().is_err(), "{fault}");
    }
}

#[test]
fn supersession_rejects_storage_infrastructure_clock_and_attempt_substitution() {
    let fixture = Fixture::new(true);
    for fault in [
        "volume",
        "infrastructure",
        "clock",
        "attempt",
        "intent",
        "runtime_root",
        "activated",
    ] {
        let mut supersession = fixture.supersession.clone();
        let mut baseline = fixture.baseline.clone();
        match fault {
            "volume" => {
                supersession
                    .before_resources
                    .volumes
                    .insert("foreign-volume".into());
            }
            "infrastructure" => {
                supersession
                    .before_resources
                    .containers
                    .get_mut("openbao")
                    .unwrap()
                    .id = "e".repeat(64);
            }
            "clock" => {
                supersession.observed_at = fixture.metadata.token_observed_at - 121;
            }
            "attempt" => {
                supersession.attempt = 2;
            }
            "intent" => {
                supersession.original_create_intents.clear();
            }
            "runtime_root" => {
                baseline.runtime_generation_root =
                    fixture.parent.secret_dir(fixture.root.path()).unwrap();
            }
            "activated" => {
                baseline.activation_performed = true;
            }
            _ => unreachable!(),
        }
        let first = require_supersession(
            fixture.root.path(),
            &supersession,
            &fixture.old,
            &fixture.previous,
            &GenerationMaterial::Public(Box::new(fixture.metadata.clone())),
        );
        let second = require_baseline(
            fixture.root.path(),
            &supersession,
            &fixture.old,
            &fixture.previous,
            &fixture.parent,
            &baseline,
        );
        assert!(first.is_err() || second.is_err(), "{fault}");
    }
}

#[test]
fn expiry_is_distinct_from_corrupt_public_material_or_clock_rollback() {
    let plan = public_fixture::plan();
    let metadata = public_fixture::metadata(&plan, true);
    let chain = plan.fullchain_pem().as_bytes();
    let at = metadata.token_observed_at;
    assert_eq!(stale_metadata(&metadata, chain, at).unwrap(), None);
    assert_eq!(
        stale_metadata(&metadata, chain, at + 1800).unwrap(),
        Some(StaleReason::CredentialFreshnessElapsed)
    );
    let expiry = metadata.certificate_admission["not_after"]
        .as_u64()
        .unwrap();
    assert_eq!(
        stale_metadata(&metadata, chain, expiry).unwrap(),
        Some(StaleReason::PublicCertificateExpired)
    );
    assert!(stale_metadata(&metadata, b"corrupt", expiry).is_err());
    assert!(stale_metadata(&metadata, chain, at - 121).is_err());
    let mut changed = metadata.clone();
    changed.key_version = 2;
    assert!(stale_metadata(&changed, chain, expiry).is_err());
}

#[path = "installer_generation_supersession_additional_tests.rs"]
mod additional;

#[path = "installer_generation_attempt_lineage_tests.rs"]
mod lineage;

pub(super) fn completed_fixture() -> (tempfile::TempDir, GenerationBinding, GenerationBinding) {
    lineage::chain()
}
