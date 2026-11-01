//! A complete local private-generation lineage over real certificate
//! signatures and synthetic native receipts. This does not execute Docker,
//! issue workload credentials, or qualify a deployed installation.
use super::*;
use crate::{
    installer_compose::{ComposeReceipt, ContainerIdentity, ProjectResources, SetupExecution},
    installer_ingress_outputs::IngressMetadata,
    installer_managed_renewal::{tests as managed_fixture, ManagedRenewalPlan},
};
use serde_json::Value;
use std::os::unix::fs::PermissionsExt;

fn private_directory(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}
fn write(path: &Path, bytes: &[u8], mode: u32) {
    if path.exists() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}
fn encoded(value: &impl Serialize) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
fn record(root: &Path, name: &str, value: &impl Serialize) -> Vec<u8> {
    let bytes = encoded(value);
    write(&root.join("evidence").join(name), &bytes, 0o600);
    bytes
}
fn native(sequence: u64, operation: &str, completed: bool) -> ComposeReceipt {
    let project = format!("marty-install-{}", managed_fixture::OWNER.replace('-', ""));
    let helper = ContainerIdentity {
        id: format!("{:064x}", sequence + 100),
        service: "installer-generation".into(),
        image: format!(
            "ghcr.io/elevenid/marty-ui-oss/services@sha256:{}",
            "c".repeat(64)
        ),
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
    };
    ComposeReceipt {
        schema: "elevenid.installer-compose-operation/v1".into(),
        project: project.clone(),
        engine_id: "engine-identity-123".into(),
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
    json!({"schema":"elevenid.installer-compose-intent/v1", "project":receipt.project,
        "engine_id":receipt.engine_id,"configuration_sha256":receipt.configuration_sha256,
        "input_files":receipt.input_files,"command":command,"prior_resources":prior,
        "selected_services":["installer-generation"],"automatic_retry":false,"installation_ready":false})
}

struct Fixture {
    root: tempfile::TempDir,
    initial: GenerationBinding,
    successor: GenerationBinding,
    material: managed_fixture::Fixture,
}
impl Fixture {
    fn new() -> Self {
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
        let mut material = managed_fixture::Fixture::new();
        let plan_value = serde_json::to_value(&material.plan).unwrap();
        let initial_metadata: IngressMetadata =
            serde_json::from_value(plan_value["ingress"].clone()).unwrap();
        // The initial receipt is synthetic native evidence over a distinct
        // signed predecessor. All three leaves retain the same issuer/SPKI;
        // no malformed PEM encoding substitutes for the original source.
        let mut original = material.current.clone();
        for (name, bytes) in &mut original {
            if name != "workload_identity_ca_cert" && name != "installer_ingress_ca_cert" {
                if name.ends_with("_token") {
                    bytes.extend_from_slice(b"-before");
                } else {
                    bytes.push(b'\n');
                }
            }
        }
        original.insert(
            "installer_ingress_tls_cert".into(),
            material.previous_leaf.clone(),
        );
        crate::installer_ingress_provision::certificate(
            std::str::from_utf8(&original["installer_ingress_tls_cert"]).unwrap(),
        )
        .expect("original private source is a real signed single-leaf PEM");
        for (name, bytes) in &original {
            write(&root.path().join("secrets").join(name), bytes, 0o444);
        }
        write(
            &root.path().join("evidence/keycloak-observation.json"),
            &material.receipt,
            0o600,
        );
        let mut generations: Vec<GenerationBinding> = Vec::new();
        let mut before = original;
        for sequence in 0..=1 {
            let (after, metadata) = if sequence == 0 {
                (&material.current, &initial_metadata)
            } else {
                (&material.next, &material.next_metadata)
            };
            if let Some(parent) = generations.last() {
                let mut value = serde_json::to_value(&material.plan).unwrap();
                value["parent_binding_sha256"] = json!(parent.sha256().unwrap());
                let bytes = encoded(&value);
                material.plan =
                    ManagedRenewalPlan::parse_authenticated(&bytes, &digest(&bytes)).unwrap();
                record(root.path(), &material.plan.record_name(), &material.plan);
            }
            let version = if sequence == 0 { 2 } else { 4 };
            let mut pending = json!({"schema":format!("elevenid.installer-generation-intent/v{version}"),
                "installation_id":managed_fixture::OWNER,"nonce":"0123456789ab",
                "input_sha256":crate::installer_generation::hashes(&before),
                "identity_sha256":crate::installer_generation::hashes(&material.identity),
                "keycloak_receipt_sha256":digest(&material.receipt),"root_retired":false,"activated":false});
            let mut validated = json!({"schema":format!("elevenid.installer-generation-validation/v{version}"),
                "installation_id":managed_fixture::OWNER,"output_sha256":crate::installer_generation::hashes(after),
                "orphan_tokens":22,"remote_key_version":1,"ca_changed":false,"ingress":metadata});
            let mut completed = json!({"schema":format!("elevenid.installer-generation-result/v{version}"),
                "installation_id":managed_fixture::OWNER,"files":43,"changed_files":41,
                "orphan_tokens":22,"transient_revoked":true,"activated":false,"root_retired":false,
                "ingress_renewal":true,"installation_ready":false});
            if sequence > 0 {
                for value in [&mut pending, &mut validated, &mut completed] {
                    value["managed_renewal_plan_sha256"] = json!(material.plan.sha256().unwrap());
                }
            }
            let native_records = BTreeMap::from([
                ("pending.json".into(), encoded(&pending)),
                ("validated.json".into(), encoded(&validated)),
                ("completed.json".into(), encoded(&completed)),
            ]);
            let proof = crate::installer_generation::GenerationProof {
                owner: managed_fixture::OWNER,
                current: &before,
                identity: &material.identity,
                keycloak_receipt: &material.receipt,
                public_ingress_plan: None,
            };
            if sequence == 0 {
                crate::installer_generation::validate_records(&native_records, after, &proof)
                    .expect("legacy initial private proof must be independently admissible");
            } else {
                crate::installer_generation::validate_managed_records(
                    &native_records,
                    after,
                    &proof,
                    &material.plan,
                )
                .expect("managed successor proof must be independently admissible");
            }
            let (current, identity, transfer) = if sequence == 0 {
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
            for path in [&current, &identity, &transfer] {
                private_directory(path);
            }
            let delivered = transfer.join("delivered");
            private_directory(&delivered);
            for (name, bytes) in &before {
                write(&current.join(name), bytes, 0o444);
            }
            for (name, bytes) in &material.identity {
                write(&identity.join(name), bytes, 0o600);
            }
            for (name, bytes) in after {
                write(&delivered.join(name), bytes, 0o444);
            }
            for (name, value) in [
                ("pending.json", pending),
                ("validated.json", validated),
                ("completed.json", completed),
            ] {
                write(&delivered.join(name), &encoded(&value), 0o600);
            }
            let scope = crate::installer_generation_maintenance::attempt::Attempt::new(sequence, 0);
            let operation = if sequence == 0 {
                "setup-installer-generation".into()
            } else {
                scope.operation("wait", 0)
            };
            let receipt = native(sequence, &operation, true);
            let helper = &receipt.resources.as_ref().unwrap().containers["installer-generation"];
            let native_bytes = record(
                root.path(),
                &if sequence == 0 {
                    format!("compose-{operation}-result.json")
                } else {
                    format!("generation-compose-{operation}-result.json")
                },
                &receipt,
            );
            if let Some(parent) = generations.last() {
                let create = scope.operation("create", 0);
                let created = native(sequence, &create, false);
                let old = native(sequence - 1, "previous", true);
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
                        old.resources.as_ref().unwrap(),
                    ),
                );
                record(
                    root.path(),
                    &format!(
                        "generation-compose-{}-intent.json",
                        scope.operation("start", 0)
                    ),
                    &native_intent(
                        &created,
                        json!(["start", "installer-generation"]),
                        created.resources.as_ref().unwrap(),
                    ),
                );
                record(
                    root.path(),
                    &scope.record("producer"),
                    &json!({
                    "schema":"elevenid.installer-generation-producer/v1","installation_id":managed_fixture::OWNER,
                    "sequence":sequence,"parent_binding_sha256":parent.sha256().unwrap(),"container_id":helper.id,
                    "create_operation":create,"created_receipt_sha256":digest(&created_bytes),
                    "create_intent_operation":create,"create_intent_sha256":digest(&create_intent)}),
                );
                write(
                    &root.path().join("evidence").join(scope.record("helper")),
                    &native_bytes,
                    0o600,
                );
            }
            let mut host = json!({"schema":if sequence == 0 {"elevenid.installer-generation-host/v3"} else {"elevenid.installer-generation-host/v5"},
                "installation_id":managed_fixture::OWNER,"engine_id":receipt.engine_id,"container_id":helper.id,
                "container_name":format!("{}-installer-generation-1",receipt.project),"network_id":"b".repeat(64),"image":helper.image,
                "root_retired":false,"ingress_renewal":true,"ingress":metadata,"public_ingress":null,
                "candidate_validated":true,"activated":false,"candidate_sha256":crate::installer_generation::hashes(after),
                "outputs":after.keys().cloned().collect::<Vec<_>>(),"container_removed":false,
                "compose_receipt_sha256":digest(&native_bytes),"job_completed_successfully":true,"installation_ready":false});
            if sequence > 0 {
                host["managed_renewal_plan_sha256"] = json!(material.plan.sha256().unwrap());
            }
            let host_bytes = record(
                root.path(),
                &if sequence == 0 {
                    "generation-observation.json".into()
                } else {
                    scope.record("candidate")
                },
                &host,
            );
            let binding = GenerationBinding {
                schema: "elevenid.installer-application-generation/v3".into(),
                installation_id: managed_fixture::OWNER.into(),
                engine_id: receipt.engine_id.clone(),
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
                    parent_attempt: 0,
                    parent_binding_sha256: parent.sha256().unwrap(),
                    native_operation: operation.clone(),
                }),
            };
            let directory = binding.secret_dir(root.path()).unwrap();
            private_directory(&directory);
            for (name, bytes) in after {
                write(&directory.join(name), bytes, 0o444);
            }
            record(
                root.path(),
                &if sequence == 0 {
                    RECORD.into()
                } else {
                    scope.record("binding")
                },
                &binding,
            );
            before = after.clone();
            generations.push(binding);
        }
        Self {
            root,
            initial: generations.remove(0),
            successor: generations.remove(0),
            material,
        }
    }
}

#[test]
fn private_successor_keeps_43_files_and_validates_expired_parent_once() {
    let fixture = Fixture::new();
    let (loaded, visits) = candidate_visits::measure(|| load_sequence(fixture.root.path(), 1));
    assert_eq!(loaded.unwrap(), fixture.successor);
    assert_eq!(visits, vec![0, 1]);
    assert_eq!(fixture.successor.files.len(), 43);
    assert!(!fixture.successor.public_ingress());
    assert_eq!(
        fixture
            .initial
            .read(fixture.root.path(), "installer_ingress_ca_cert")
            .unwrap(),
        fixture
            .successor
            .read(fixture.root.path(), "installer_ingress_ca_cert")
            .unwrap()
    );
    assert_ne!(
        fixture
            .initial
            .read(fixture.root.path(), "installer_ingress_tls_cert")
            .unwrap(),
        fixture
            .successor
            .read(fixture.root.path(), "installer_ingress_tls_cert")
            .unwrap()
    );
    let metadata = fixture
        .successor
        .ingress_metadata(fixture.root.path())
        .unwrap()
        .unwrap();
    assert_eq!(metadata, fixture.material.next_metadata);
    assert_eq!(metadata.token_observed_at, managed_fixture::REPLACED);
    assert!(
        fixture
            .initial
            .ingress_metadata(fixture.root.path())
            .unwrap()
            .unwrap()
            .certificate_expires_at
            < metadata.token_observed_at
    );
    assert!(fixture
        .successor
        .public_ingress_metadata(fixture.root.path())
        .unwrap()
        .is_none());
}

#[test]
fn private_material_separates_historical_integrity_expiry_and_issuer_exhaustion() {
    let fixture = Fixture::new();
    let binding = &fixture.successor;
    let material = GenerationMaterial::load(fixture.root.path(), binding).unwrap();
    material
        .validate_historical(fixture.root.path(), binding)
        .unwrap();
    let expiry = material.expires_at().unwrap();
    material
        .validate_selected_at(fixture.root.path(), binding, expiry - 1)
        .unwrap();
    assert!(material
        .validate_selected_at(fixture.root.path(), binding, expiry)
        .is_err());
    material
        .require_issuer_lifetime(fixture.root.path(), binding, managed_fixture::REPLACED)
        .unwrap();
    assert!(material
        .require_issuer_lifetime(
            fixture.root.path(),
            binding,
            managed_fixture::REPLACED - 121
        )
        .is_err());
    let not_before = material.not_before(fixture.root.path(), binding).unwrap();
    assert!(material
        .require_issuer_lifetime(fixture.root.path(), binding, not_before - 1)
        .is_err());
    material
        .require_issuer_lifetime(fixture.root.path(), binding, not_before)
        .unwrap();
    let ca_expiry = fixture.material.next_metadata.ca_expires_at;
    material
        .require_issuer_lifetime(fixture.root.path(), binding, ca_expiry - 28_800)
        .unwrap();
    assert!(material
        .require_issuer_lifetime(fixture.root.path(), binding, ca_expiry - 28_799)
        .is_err());
    let mut forged = fixture.material.next_metadata.clone();
    forged.certificate_pem_sha256 = "f".repeat(64);
    assert!(GenerationMaterial::Managed(Box::new(forged))
        .validate_historical(fixture.root.path(), binding)
        .is_err());
}

#[test]
fn private_successor_rejects_downgrade_cross_source_and_extra_or_missing_outputs() {
    for change in [
        "host-schema",
        "managed-digest",
        "public-digest",
        "plan-source",
        "plan-parent",
        "missing-ca",
        "extra-output",
        "native-completion",
    ] {
        let fixture = Fixture::new();
        let root = fixture.root.path();
        let path = root
            .join("evidence")
            .join(fixture.successor.record_name("candidate"));
        let host_bytes = std::fs::read(&path).unwrap();
        let mut host: Value = serde_json::from_slice(&host_bytes).unwrap();
        match change {
            "host-schema" => host["schema"] = json!("elevenid.installer-generation-host/v3"),
            "managed-digest" => host["managed_renewal_plan_sha256"] = json!("f".repeat(64)),
            "public-digest" => {
                host["public_ingress"] =
                    serde_json::to_value(crate::installer_public_ingress::tests::metadata(
                        &crate::installer_public_ingress::tests::plan(),
                        true,
                    ))
                    .unwrap()
            }
            "plan-source" | "plan-parent" => {
                let mut plan = serde_json::to_value(&fixture.material.plan).unwrap();
                if change == "plan-source" {
                    plan["certificate_source"] = json!("acme");
                } else {
                    plan["parent_binding_sha256"] = json!("f".repeat(64));
                }
                record(root, &fixture.material.plan.record_name(), &plan);
            }
            "missing-ca" => std::fs::remove_file(root.join(
                "generation-work/00000000000000000001/transfer/delivered/installer_ingress_ca_cert",
            ))
            .unwrap(),
            "extra-output" => write(
                &root.join("generation-work/00000000000000000001/transfer/delivered/unowned"),
                b"x",
                0o444,
            ),
            "native-completion" => {
                let name = fixture.successor.record_name("helper");
                let mut receipt: Value = serde_json::from_slice(
                    &std::fs::read(root.join("evidence").join(&name)).unwrap(),
                )
                .unwrap();
                receipt["resources"]["containers"]["installer-generation"]["setup_execution"]
                    ["completed_without_restart"] = json!(false);
                record(root, &name, &receipt);
            }
            _ => unreachable!(),
        }
        if encoded(&host) != host_bytes {
            write(&path, &encoded(&host), 0o600);
        }
        assert!(load_sequence(root, 1).is_err(), "accepted {change}");
    }
}
