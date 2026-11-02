//! Complete synthetic generation receipts over the historical public-chain
//! fixture. This exercises local lineage verification, not installed authority.
use super::*;
use crate::{
    installer_compose::{ComposeReceipt, ContainerIdentity, ProjectResources, SetupExecution},
    installer_public_ingress::{tests as public_fixture, PublicIngressPlan},
};
use serde_json::Value;
use std::os::unix::fs::PermissionsExt;

fn private_directory(path: &Path) {
    std::fs::create_dir(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}
fn write(path: &Path, bytes: &[u8], mode: u32) {
    if path.exists() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}
fn encode(value: &impl Serialize) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
fn record(root: &Path, name: &str, value: &impl Serialize) -> Vec<u8> {
    let bytes = encode(value);
    write(&root.join("evidence").join(name), &bytes, 0o600);
    bytes
}
fn helper(sequence: u64, completed: bool, image: &str) -> ContainerIdentity {
    ContainerIdentity {
        id: format!("{:064x}", sequence + 100),
        service: "installer-generation".into(),
        image: image.into(),
        config_hash: "6".repeat(64),
        setup: true,
        setup_execution: Some(SetupExecution {
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
fn native_receipt(
    sequence: u64,
    operation: &str,
    completed: bool,
    image: &str,
    engine: &str,
) -> ComposeReceipt {
    let project = format!("marty-install-{}", public_fixture::OWNER.replace('-', ""));
    let helper = helper(sequence, completed, image);
    ComposeReceipt {
        schema: "elevenid.installer-compose-operation/v1".into(),
        project: project.clone(),
        engine_id: engine.into(),
        operation: operation.into(),
        configuration_sha256: "6".repeat(64),
        input_files: BTreeMap::new(),
        command_succeeded: true,
        client_exit_code: Some(0),
        failure_class: None,
        observation_validated: true,
        resources: Some(ProjectResources {
            containers: BTreeMap::from([("installer-generation".into(), helper.clone())]),
            networks: BTreeMap::from([(format!("{project}_default"), "b".repeat(64))]),
            volumes: BTreeSet::new(),
        }),
        status: vec![json!({"Service":"installer-generation","ID":helper.id,
            "State":if completed {"exited"} else {"created"},"ExitCode":0,"Health":""})],
        installation_ready: false,
    }
}
fn native_intent(receipt: &ComposeReceipt, command: Value, prior: &ProjectResources) -> Value {
    json!({"schema":"elevenid.installer-compose-intent/v1",
        "project":receipt.project,"engine_id":receipt.engine_id,
        "configuration_sha256":receipt.configuration_sha256,"input_files":receipt.input_files,
        "command":command,"prior_resources":prior,"selected_services":["installer-generation"],
        "automatic_retry":false,"installation_ready":false})
}

pub(super) struct Fixture {
    pub(super) root: tempfile::TempDir,
    pub(super) generations: Vec<GenerationBinding>,
}
impl Fixture {
    pub(super) fn new(last: u64) -> Self {
        Self::with_engine(last, "engine")
    }
    pub(super) fn with_engine(last: u64, engine: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for name in [
            "evidence",
            "secrets",
            "application-generations",
            "generation-work",
        ] {
            private_directory(&root.path().join(name));
        }
        let (initial_plan, initial) = public_fixture::fixture();
        let mut before = initial.clone();
        for (name, bytes) in &initial {
            write(&root.path().join("secrets").join(name), bytes, 0o444);
        }
        let identity: BTreeMap<String, Vec<u8>> = [
            "renewal-role-id",
            "renewal-secret-id",
            "renewal-leaf-policies.json",
        ]
        .into_iter()
        .map(|name| (name.into(), format!("fixture-{name}").into_bytes()))
        .collect();
        let keycloak = record(
            root.path(),
            "keycloak-observation.json",
            &json!({
                "schema":"elevenid.installer-keycloak/v2","installation_id":public_fixture::OWNER,
                "engine_id":engine,"container_id":"a".repeat(64),
                "container_name":format!("marty-install-{}-installer-keycloak-1",public_fixture::OWNER.replace('-',"")),
                "network_id":"b".repeat(64),
                "image":format!("ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:{}","c".repeat(64)),
                "nonce":"0123456789ab","outputs":crate::installer_keycloak_bridge::OUTPUTS,
                "container_removed":false,"job_completed_successfully":true,
                "compose_receipt_sha256":"d".repeat(64),"installation_ready":false
            }),
        );
        let image = format!(
            "ghcr.io/elevenid/marty-ui-oss/services@sha256:{}",
            "c".repeat(64)
        );
        let mut generations: Vec<GenerationBinding> = Vec::new();
        let mut previous_metadata: Option<Value> = None;
        for sequence in 0..=last {
            let plan = if let Some(parent) = generations.last() {
                let mut value = serde_json::to_value(&initial_plan).unwrap();
                let metadata = previous_metadata.as_ref().unwrap();
                value["successor"] = json!({"sequence":sequence,
                    "parent_binding_sha256":parent.sha256().unwrap(),
                    "input_sha256":crate::installer_generation::hashes(&before),
                    "input_observed_at":metadata["token_observed_at"],"ingress":metadata});
                let bytes = encode(&value);
                PublicIngressPlan::parse_authenticated(&bytes, &digest(&bytes)).unwrap()
            } else {
                initial_plan.clone()
            };
            let mut after = public_fixture::current(&plan);
            for (name, value) in &mut after {
                if name == "workload_identity_ca_cert" || name == "installer_ingress_tls_cert" {
                    continue;
                }
                if name.ends_with("_token") {
                    *value = format!("changed-fixture-{sequence}-{name}").into_bytes();
                } else {
                    value.extend(std::iter::repeat_n(b'\n', sequence as usize + 1));
                }
            }
            assert_eq!(after.len(), 42);
            let mut metadata = public_fixture::metadata(&plan, sequence > 0);
            metadata.token_observed_at += sequence;
            let plan_hash = plan.sha256().unwrap();
            let records = BTreeMap::from([
                (
                    "pending.json",
                    json!({"schema":"elevenid.installer-generation-intent/v3",
                    "installation_id":public_fixture::OWNER,"nonce":"0123456789ab",
                    "input_sha256":crate::installer_generation::hashes(&before),
                    "identity_sha256":crate::installer_generation::hashes(&identity),
                    "keycloak_receipt_sha256":digest(&keycloak),"root_retired":false,"activated":false,
                    "public_ingress_plan_sha256":plan_hash}),
                ),
                (
                    "validated.json",
                    json!({"schema":"elevenid.installer-generation-validation/v3",
                    "installation_id":public_fixture::OWNER,"output_sha256":crate::installer_generation::hashes(&after),
                    "orphan_tokens":22,"remote_key_version":1,"ca_changed":false,
                    "public_ingress":metadata,"public_ingress_plan_sha256":plan_hash}),
                ),
                (
                    "completed.json",
                    json!({"schema":"elevenid.installer-generation-result/v3",
                    "installation_id":public_fixture::OWNER,"files":42,
                    "changed_files":if sequence==0 {41} else {40},"orphan_tokens":22,
                    "transient_revoked":true,"activated":false,"root_retired":false,
                    "ingress_renewal":true,"installation_ready":false,"public_ingress_plan_sha256":plan_hash}),
                ),
            ]);
            let (current_dir, identity_dir, transfer) = if sequence == 0 {
                (
                    root.path().join("generation-inputs"),
                    root.path().join("generation-identity"),
                    root.path().join("generation-transfer"),
                )
            } else {
                let work = root
                    .path()
                    .join("generation-work")
                    .join(format!("{sequence:020}"));
                private_directory(&work);
                (
                    work.join("current"),
                    work.join("identity"),
                    work.join("transfer"),
                )
            };
            for directory in [&current_dir, &identity_dir, &transfer] {
                private_directory(directory);
            }
            let delivered = transfer.join("delivered");
            private_directory(&delivered);
            for (name, bytes) in &before {
                write(&current_dir.join(name), bytes, 0o444);
            }
            for (name, bytes) in &identity {
                write(&identity_dir.join(name), bytes, 0o600);
            }
            for (name, bytes) in &after {
                write(&delivered.join(name), bytes, 0o444);
            }
            for (name, value) in &records {
                write(&delivered.join(name), &encode(value), 0o600);
            }
            let operation = if sequence == 0 {
                "setup-installer-generation".into()
            } else {
                format!("g{sequence:020}-wait-000000")
            };
            let native = native_receipt(sequence, &operation, true, &image, engine);
            let native_bytes = record(
                root.path(),
                &if sequence == 0 {
                    format!("compose-{operation}-result.json")
                } else {
                    format!("generation-compose-{operation}-result.json")
                },
                &native,
            );
            if sequence > 0 {
                let parent = generations.last().unwrap();
                let create = format!("g{sequence:020}-create-000000");
                let created = native_receipt(sequence, &create, false, &image, engine);
                let previous = native_receipt(sequence - 1, "previous", true, &image, engine);
                let created_bytes = record(
                    root.path(),
                    &format!("generation-compose-{create}-result.json"),
                    &created,
                );
                let create_intent = record(
                    root.path(),
                    &format!("generation-compose-{create}-intent.json"),
                    &native_intent(
                        &created,
                        json!([
                            "up",
                            "--no-build",
                            "--pull",
                            "never",
                            "--no-deps",
                            "--no-start",
                            "--force-recreate",
                            "--timeout",
                            "60"
                        ]),
                        previous.resources.as_ref().unwrap(),
                    ),
                );
                record(
                    root.path(),
                    &format!("generation-compose-g{sequence:020}-start-000000-intent.json"),
                    &native_intent(
                        &created,
                        json!(["start", "installer-generation"]),
                        created.resources.as_ref().unwrap(),
                    ),
                );
                record(
                    root.path(),
                    &format!("generation-{sequence:020}-producer.json"),
                    &json!({
                    "schema":"elevenid.installer-generation-producer/v1","installation_id":public_fixture::OWNER,
                    "sequence":sequence,"parent_binding_sha256":parent.sha256().unwrap(),
                    "container_id":helper(sequence,true,&image).id,"create_operation":create,
                    "created_receipt_sha256":digest(&created_bytes),"create_intent_operation":create,
                    "create_intent_sha256":digest(&create_intent)}),
                );
                write(
                    &root
                        .path()
                        .join("evidence")
                        .join(format!("generation-{sequence:020}-helper.json")),
                    &native_bytes,
                    0o600,
                );
            }
            let host = json!({"schema":"elevenid.installer-generation-host/v4",
                "installation_id":public_fixture::OWNER,"engine_id":engine,
                "container_id":helper(sequence,true,&image).id,
                "container_name":format!("marty-install-{}-installer-generation-1",public_fixture::OWNER.replace('-',"")),
                "network_id":"b".repeat(64),"image":image,"root_retired":false,
                "ingress_renewal":true,"ingress":null,"public_ingress":metadata,
                "candidate_validated":true,"activated":false,"candidate_sha256":crate::installer_generation::hashes(&after),
                "outputs":after.keys().cloned().collect::<Vec<_>>(),"container_removed":false,
                "compose_receipt_sha256":digest(&native_bytes),"job_completed_successfully":true,"installation_ready":false});
            let host_bytes = record(
                root.path(),
                &if sequence == 0 {
                    "generation-observation.json".into()
                } else {
                    format!("generation-{sequence:020}-candidate.json")
                },
                &host,
            );
            record(
                root.path(),
                &if sequence == 0 {
                    crate::installer_public_ingress::PUBLIC_INGRESS_PLAN_RECORD.into()
                } else {
                    format!("generation-{sequence:020}-public-ingress-plan.json")
                },
                &plan,
            );
            let binding = GenerationBinding {
                schema: "elevenid.installer-application-generation/v4".into(),
                installation_id: public_fixture::OWNER.into(),
                engine_id: engine.into(),
                network_id: Some("b".repeat(64)),
                generation_receipt_sha256: digest(&host_bytes),
                files: after
                    .iter()
                    .map(|(name, bytes)| {
                        (
                            name.clone(),
                            GenerationFile {
                                source: GenerationSource::Candidate,
                                sha256: digest(bytes),
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
                successor: generations.last().map(|parent| SuccessorBinding {
                    sequence,
                    attempt: 0,
                    parent_attempt: parent.attempt(),
                    parent_binding_sha256: parent.sha256().unwrap(),
                    native_operation: operation.clone(),
                }),
            };
            let output = binding.secret_dir(root.path()).unwrap();
            private_directory(&output);
            for (name, bytes) in &after {
                write(&output.join(name), bytes, 0o444);
            }
            record(
                root.path(),
                &if sequence == 0 {
                    RECORD.into()
                } else {
                    format!("generation-{sequence:020}-binding.json")
                },
                &binding,
            );
            previous_metadata = Some(serde_json::to_value(metadata).unwrap());
            before = after;
            generations.push(binding);
        }
        Self { root, generations }
    }
}

#[test]
fn six_successors_validate_each_ancestor_once_with_the_complete_public_file_contract() {
    let fixture = Fixture::new(6);
    let expected: Vec<_> = (0..=6).collect();
    let (loaded, visits) = candidate_visits::measure(|| load_sequence(fixture.root.path(), 6));
    assert_eq!(loaded.unwrap(), fixture.generations[6]);
    assert_eq!(
        visits, expected,
        "candidate proof must be checked once per generation"
    );
    let (verified, visits) =
        candidate_visits::measure(|| verify(fixture.root.path(), &fixture.generations[6]));
    verified.unwrap();
    assert_eq!(visits, expected);
    let (metadata, visits) = candidate_visits::measure(|| {
        fixture.generations[6].public_ingress_metadata(fixture.root.path())
    });
    assert!(metadata.unwrap().is_some());
    assert_eq!(visits, expected);
    assert!(fixture
        .generations
        .iter()
        .all(|binding| binding.files.len() == 42));
}

#[test]
fn forward_lineage_does_not_skip_missing_or_modified_ancestors() {
    let fixture = Fixture::new(3);
    load_sequence(fixture.root.path(), 3).unwrap();
    let path = fixture.generations[1]
        .secret_dir(fixture.root.path())
        .unwrap()
        .join("installer_ingress_tls_kms_token");
    let original = std::fs::read(&path).unwrap();
    write(&path, b"replaced-ancestor-token", 0o444);
    assert!(load_sequence(fixture.root.path(), 3).is_err());
    write(&path, &original, 0o444);
    let path = fixture
        .root
        .path()
        .join("evidence/generation-00000000000000000002-binding.json");
    let original = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(load_sequence(fixture.root.path(), 3).is_err());
    write(&path, &original, 0o600);
    let mut wrong = fixture.generations[3].clone();
    wrong.successor.as_mut().unwrap().parent_binding_sha256 = "e".repeat(64);
    assert!(verify(fixture.root.path(), &wrong).is_err());
    load_sequence(fixture.root.path(), 3).unwrap();
}
