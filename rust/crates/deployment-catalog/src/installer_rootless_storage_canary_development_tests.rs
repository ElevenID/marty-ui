use super::*;
use crate::installer_state::{CandidateTestScope, Identity, RuntimeBinding, RuntimeProfile};
use std::{
    io::{Seek, SeekFrom},
    os::unix::fs::PermissionsExt,
    time::Instant,
};

const MOCK_ID: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn provisional_name(role: &str) -> &'static str {
    match role {
        "transition" => TRANSITION_CREATED_UNVALIDATED,
        "restore" => RESTORE_CREATED_UNVALIDATED,
        _ => panic!("invalid test role"),
    }
}

fn expected_provisional(intent: &Intent, contract: &Contract) -> Vec<u8> {
    encoded(&json!({
        "schema": "elevenid.rootless-canary-created-unvalidated/v1",
        "intent_sha256": sha(&encoded(intent).unwrap()),
        "role": contract.role, "name": contract.name, "id": MOCK_ID,
        "validated": false, "cleanup_authorized": false, "installation_ready": false
    }))
    .unwrap()
}

fn mock_container(contract: &Contract) -> Value {
    json!({
        "Id": MOCK_ID, "Image": contract.image_id,
        "Name": format!("/{}", contract.name),
        "Config": {
            "Image": contract.image, "User": "0:0",
            "Entrypoint": ["/input/marty-deploy"],
            "Cmd": ["installer-rootless-canary-helper", contract.role], "Env": [],
            "Labels": {
                "com.elevenid.installer.id": contract.owner,
                "com.elevenid.installer.stage": "rootless-canary",
                "com.elevenid.installer.canary": contract.canary_id.to_string(),
                "com.elevenid.installer.canary-role": contract.role
            }
        },
        "HostConfig": {
            "ReadonlyRootfs": true, "Privileged": false, "CapDrop": ["ALL"],
            "CapAdd": ["CAP_CHOWN", "CAP_DAC_OVERRIDE"],
            "SecurityOpt": ["no-new-privileges"], "NetworkMode": "none",
            "AutoRemove": false, "RestartPolicy": {"Name": "no"},
            "PidMode": "", "UsernsMode": "", "IpcMode": "private",
            "PortBindings": {}, "Devices": [], "DeviceRequests": null,
            "Binds": null, "Tmpfs": null
        },
        "Mounts": [
            {"Type":"bind", "Source":contract.operator, "Destination":"/input/marty-deploy",
             "RW":false, "Propagation":"rprivate"},
            {"Type":"bind", "Source":contract.parent, "Destination":"/marty-canary",
             "RW":true, "Propagation":"rprivate"}
        ],
        "NetworkSettings": {"Networks": {}},
        "State": {"Running":false, "Status":"created", "ExitCode":0, "OOMKilled":false}
    })
}

struct MockCreate {
    state: InstallerState,
    docker: DockerRunner,
    intent: Intent,
    contract: Contract,
    installation: PathBuf,
    // This fixture never contacts a daemon or changes ownership.
    // The live harness deliberately uses no TempDir for its persistent scope.
    temp: tempfile::TempDir,
}

impl MockCreate {
    fn new(role: &'static str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let installation = temp.path().join("installation");
        let mut state = InstallerState::create(
            &installation,
            Identity {
                source_sha: "0".repeat(40),
                release_tag: "v0.0.0".into(),
                inventory_sha256: format!("sha256:{}", "0".repeat(64)),
            },
        )
        .unwrap();
        state.create_private_directory("evidence").unwrap();
        let canary_id = uuid::Uuid::new_v4();
        let root = File::open(&installation).unwrap();
        let evidence = File::open(installation.join("evidence")).unwrap();
        let intent = Intent {
            schema: "elevenid.rootless-storage-canary-intent/v1".into(),
            pull_intent_sha256: "9".repeat(64),
            installation_id: state.journal().installation_id(),
            canary_id,
            source_sha: "0".repeat(40),
            inventory_sha256: format!("sha256:{}", "0".repeat(64)),
            engine_id: "development-mock-engine".into(),
            image: format!(
                "ghcr.io/elevenid/marty-ui-oss/services@sha256:{}",
                "a".repeat(64)
            ),
            image_id: format!("sha256:{}", "b".repeat(64)),
            operator_sha256: "c".repeat(64),
            root: stamp(&root).unwrap(),
            evidence: stamp(&evidence).unwrap(),
            parent_name: format!("rootless-canary-{}", canary_id.simple()),
            marker_sha256: "d".repeat(64),
            host_uid: unsafe { libc::geteuid() },
            host_gid: unsafe { libc::getegid() },
        };
        let contract = Contract {
            role,
            name: container_name(canary_id, role).unwrap(),
            owner: intent.installation_id.to_string(),
            canary_id,
            image: intent.image.clone(),
            image_id: intent.image_id.clone(),
            environment: BTreeMap::new(),
            parent: installation.join("evidence").join(&intent.parent_name),
            operator: installation.join("marty-deploy"),
        };
        fs::write(temp.path().join("container-id"), MOCK_ID).unwrap();
        fs::write(temp.path().join("receipt-name"), provisional_name(role)).unwrap();
        fs::write(
            temp.path().join("expected-provisional.json"),
            expected_provisional(&intent, &contract),
        )
        .unwrap();
        fs::write(
            temp.path().join("inspect.json"),
            encoded(&json!([mock_container(&contract)])).unwrap(),
        )
        .unwrap();
        fs::write(temp.path().join("inspect-mode"), "ok").unwrap();
        fs::write(temp.path().join("create-mode"), "normal").unwrap();
        let mut changed: Value =
            serde_json::from_slice(&fs::read(installation.join("installation.json")).unwrap())
                .unwrap();
        changed["identity"]["source_sha"] = json!("f".repeat(40));
        fs::write(
            temp.path().join("changed-journal.json"),
            encoded(&changed).unwrap(),
        )
        .unwrap();
        let binary = temp.path().join("docker-stub");
        fs::write(
            &binary,
            r#"#!/bin/sh
set -eu
base=$(dirname "$0")
case "$1" in
info)
printf '%s\n' '{"id":"development-mock-engine","os":"linux","architecture":"x86_64","server_version":"29.9.2","security_options":["name=seccomp,profile=builtin"]}'
;;
compose)
if [ "$#" != 3 ] || [ "$2" != version ] || [ "$3" != --short ]; then
    printf 'UNEXPECTED:compose\n' >> "$base/trace"
    exit 72
fi
printf '2.40.3\n'
;;
ps) printf 'ps\n' >> "$base/trace" ;;
create)
printf 'create\n' >> "$base/trace"
receipt=$(cat "$base/receipt-name")
if [ -e "$base/installation/evidence/$receipt" ]; then
    printf 'receipt-present-before-create\n' >> "$base/trace"
else
    printf 'receipt-absent-before-create\n' >> "$base/trace"
fi
if [ "$(cat "$base/create-mode")" = drift-journal ]; then
    cat "$base/changed-journal.json" > "$base/installation/installation.json"
    printf 'journal-drift\n' >> "$base/trace"
fi
cat "$base/container-id"
;;
inspect)
printf 'inspect\n' >> "$base/trace"
receipt=$(cat "$base/receipt-name")
cmp -s "$base/installation/evidence/$receipt" "$base/expected-provisional.json"
[ "$(stat -c %a "$base/installation/evidence/$receipt")" = 600 ]
printf 'provisional-readback-before-inspect\n' >> "$base/trace"
[ "$(cat "$base/inspect-mode")" != fail ] || exit 71
cat "$base/inspect.json"
;;
*)
printf 'UNEXPECTED:%s\n' "$1" >> "$base/trace"
exit 72
;;
esac
"#,
        ).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        // The rootful endpoint constructor performs syntactic checks for
        // this fake executable. No Docker socket is opened, no rootless
        // admission is weakened, and no real daemon can be contacted.
        let docker = DockerRunner::new(
            &binary,
            "unix:///unconnected-development-test/docker.sock",
            "development-mock-engine",
            temp.path(),
        )
        .unwrap();
        Self {
            state,
            docker,
            intent,
            contract,
            installation,
            temp,
        }
    }

    fn create(&mut self) -> Result<String> {
        create_container(&self.docker, &self.contract, &mut self.state, &self.intent)
    }

    fn trace(&self) -> Vec<String> {
        fs::read_to_string(self.temp.path().join("trace"))
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn provisional(&self) -> Vec<u8> {
        fs::read(
            self.installation
                .join("evidence")
                .join(provisional_name(self.contract.role)),
        )
        .unwrap()
    }

    fn assert_no_authority(&self) {
        for name in [
            TRANSITION_CONTAINER,
            RESTORE_CONTAINER,
            START_INTENT,
            FOREIGN,
            RESTORE_INTENT,
            RESTORE_RETRY_INTENT,
            ABORT_INTENT,
            ABORT_COMPLETE,
            RESULT,
            REMOVE_INTENT,
            TRANSITION_REMOVED,
            RESTORE_REMOVED,
            COMPLETE,
        ] {
            assert!(
                !self.installation.join("evidence").join(name).exists(),
                "{name}"
            );
        }
        assert!(self
            .trace()
            .iter()
            .all(|event| !event.starts_with("UNEXPECTED:")));
        assert_eq!(self.state.journal().phase(), Phase::Initialized);
    }
}

#[test]
fn provisional_receipt_is_private_and_readable_before_first_inspection_for_each_role() {
    for role in ["transition", "restore"] {
        let mut fixture = MockCreate::new(role);
        assert_eq!(fixture.create().unwrap(), MOCK_ID);
        let expected = expected_provisional(&fixture.intent, &fixture.contract);
        assert_eq!(fixture.provisional(), expected);
        read_evidence(&fixture.state, provisional_name(role), &expected).unwrap();
        assert_eq!(
            fixture.trace(),
            [
                "ps",
                "create",
                "receipt-absent-before-create",
                "inspect",
                "provisional-readback-before-inspect",
            ]
        );
        // Even successful create_container returns only an observed ID.
        // Its caller must separately persist a fully validated receipt.
        fixture.assert_no_authority();
        assert!(serde_json::from_slice::<ContainerReceipt>(&expected).is_err());
    }
}

#[test]
fn failed_inspection_preserves_provisional_receipt_without_start_or_cleanup() {
    for role in ["transition", "restore"] {
        for command_failure in [false, true] {
            let mut fixture = MockCreate::new(role);
            if command_failure {
                fs::write(fixture.temp.path().join("inspect-mode"), "fail").unwrap();
            } else {
                let mut invalid = mock_container(&fixture.contract);
                invalid["HostConfig"]["Privileged"] = json!(true);
                fs::write(
                    fixture.temp.path().join("inspect.json"),
                    encoded(&json!([invalid])).unwrap(),
                )
                .unwrap();
            }
            assert!(fixture.create().is_err());
            assert_eq!(
                fixture.provisional(),
                expected_provisional(&fixture.intent, &fixture.contract)
            );
            assert_eq!(
                fixture.trace(),
                [
                    "ps",
                    "create",
                    "receipt-absent-before-create",
                    "inspect",
                    "provisional-readback-before-inspect",
                ]
            );
            fixture.assert_no_authority();
        }
    }
}

#[test]
fn provisional_write_or_readback_failure_prevents_even_inspection() {
    for role in ["transition", "restore"] {
        let mut collision = MockCreate::new(role);
        let original = br#"{"preserved":"pre-existing evidence is never overwritten"}"#;
        collision
            .state
            .write_evidence(provisional_name(role), original)
            .unwrap();
        assert!(collision.create().is_err());
        assert_eq!(collision.provisional(), original);
        assert_eq!(
            collision.trace(),
            ["ps", "create", "receipt-present-before-create",]
        );
        collision.assert_no_authority();
        assert!(collision.state.advance(Phase::Verified).is_err());

        let mut readback = MockCreate::new(role);
        // The mock changes the journal before returning a new Docker ID.
        // write_evidence can commit, but persist's mandatory locked readback
        // must reject the changed journal before any Docker inspection.
        fs::write(readback.temp.path().join("create-mode"), "drift-journal").unwrap();
        assert!(readback.create().is_err());
        assert_eq!(
            readback.provisional(),
            expected_provisional(&readback.intent, &readback.contract)
        );
        assert_eq!(
            readback.trace(),
            [
                "ps",
                "create",
                "receipt-absent-before-create",
                "journal-drift",
            ]
        );
        readback.assert_no_authority();
        assert!(read_evidence(
            &readback.state,
            provisional_name(role),
            &readback.provisional()
        )
        .is_err());
    }
}

#[test]
fn provisional_id_and_name_never_replace_validated_recovery_chain() {
    let mut fixture = MockCreate::new("transition");
    fixture.create().unwrap();
    let intent_bytes = encoded(&fixture.intent).unwrap();
    let created = Created {
        schema: "elevenid.rootless-storage-canary-created/v1".into(),
        intent_sha256: sha(&intent_bytes),
        parent: fixture.intent.root.clone(),
        child: fixture.intent.evidence.clone(),
    };
    let transition = receipt(
        &fixture.intent,
        "transition",
        fixture.contract.name.clone(),
        MOCK_ID.into(),
    );
    let restore = receipt(
        &fixture.intent,
        "restore",
        container_name(fixture.intent.canary_id, "restore").unwrap(),
        "2".repeat(64),
    );
    let created_bytes = encoded(&created).unwrap();
    let transition_bytes = encoded(&transition).unwrap();
    let restore_bytes = encoded(&restore).unwrap();
    let start = encoded(&json!({
        "schema": "elevenid.rootless-storage-canary-start-intent/v1",
        "intent_sha256": sha(&intent_bytes),
        "transition_id": transition.id, "restore_id": restore.id,
        "parent": created.parent, "child": created.child
    }))
    .unwrap();
    verified_records(
        &fixture.intent,
        &intent_bytes,
        &created_bytes,
        &transition_bytes,
        &restore_bytes,
        &start,
    )
    .unwrap();
    let mut claimed: Value = serde_json::from_slice(&fixture.provisional()).unwrap();
    for flags in [false, true] {
        claimed["validated"] = json!(flags);
        claimed["cleanup_authorized"] = json!(flags);
        claimed["installation_ready"] = json!(flags);
        let bytes = encoded(&claimed).unwrap();
        assert!(verified_records(
            &fixture.intent,
            &intent_bytes,
            &created_bytes,
            &bytes,
            &restore_bytes,
            &start,
        )
        .is_err());
        assert!(verified_records(
            &fixture.intent,
            &intent_bytes,
            &created_bytes,
            &transition_bytes,
            &bytes,
            &start,
        )
        .is_err());
    }
    // Renaming a provisional file or changing its schema alone cannot turn
    // its shape into a validated receipt.
    claimed["schema"] = json!("elevenid.rootless-storage-canary-container/v1");
    assert!(serde_json::from_slice::<ContainerReceipt>(&encoded(&claimed).unwrap()).is_err());
    assert!(verified_records(
        &fixture.intent,
        &intent_bytes,
        &created_bytes,
        &fixture.provisional(),
        b"",
        b"",
    )
    .is_err());
    fixture.assert_no_authority();
}

fn development_env(name: &str) -> Result<String> {
    std::env::var(name)
        .ok()
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 4096
                && !value.bytes().any(|byte| byte.is_ascii_control())
        })
        .ok_or_else(|| format!("explicit DEVELOPMENT harness input required: {name}"))
}

fn development_static_amd64(path: &Path) -> Result<()> {
    // operator_digest/persist_operator separately bind private ordinary owned
    // bytes to their exact hash. Reject a dynamic GNU host binary before
    // mounting the separately built musl helper in the services image.
    let mut file = File::open(path).map_err(|_| "DEVELOPMENT helper unavailable")?;
    let size = file
        .metadata()
        .map_err(|_| "DEVELOPMENT helper metadata")?
        .len();
    let mut header = [0u8; 64];
    file.read_exact(&mut header)
        .map_err(|_| "DEVELOPMENT helper ELF header")?;
    require(
        &header[..4] == b"\x7fELF"
            && header[4] == 2
            && header[5] == 1
            && header[6] == 1
            && u16::from_le_bytes([header[18], header[19]]) == 62
            && matches!(u16::from_le_bytes([header[16], header[17]]), 2 | 3),
    )?;
    let offset = u64::from_le_bytes(header[32..40].try_into().unwrap());
    let entry_size = u16::from_le_bytes([header[54], header[55]]);
    let count = u16::from_le_bytes([header[56], header[57]]);
    require(
        entry_size == 56
            && (1..=128).contains(&count)
            && offset >= 64
            && offset
                .checked_add(u64::from(count) * 56)
                .is_some_and(|end| end <= size),
    )?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| "DEVELOPMENT helper ELF table")?;
    let mut load = false;
    for _ in 0..count {
        let mut program = [0u8; 56];
        file.read_exact(&mut program)
            .map_err(|_| "DEVELOPMENT helper ELF entry")?;
        let kind = u32::from_le_bytes(program[..4].try_into().unwrap());
        require(kind != 3)?; // PT_INTERP requires a container dynamic linker.
        load |= kind == 1;
    }
    require(load)
}

fn development_parent(path: &Path) -> Result<()> {
    crate::installer_runtime::private_parent(path)?;
    // Fresh names alone do not protect an original installation if the
    // caller mistakenly selects that installation (or its child) as parent.
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor.join("installation.json")) {
            Ok(_) => {
                return Err(
                    "DEVELOPMENT evidence must be outside every existing installation".into(),
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("DEVELOPMENT parent ancestry could not be checked".into()),
        }
    }
    Ok(())
}

fn development_container_ids(docker: &DockerRunner) -> Result<BTreeSet<String>> {
    let output = docker.run_checked(&["ps", "-aq", "--no-trunc"])?;
    let ids: Vec<&str> = output.lines().filter(|line| !line.is_empty()).collect();
    require(ids.iter().all(|value| id(value)))?;
    let unique: BTreeSet<String> = ids.iter().map(|value| (*value).into()).collect();
    require(unique.len() == ids.len())?;
    Ok(unique)
}

/// One real transition+restore, with normal exact validated-ID helper removal
/// on success. Requires an ordinary non-root no-new-privileges process, its
/// existing rootless daemon, and explicit caller opt-in.
///
/// No external kill timeout, ownership-transition interruption, failure
/// cleanup, recovery retry, image prune, or runtime provisioning. Existing
/// finite Docker subprocess budgets remain in force. The real
/// qualify_candidate path re-pulls the same immutable digest after the
/// cached-image check; no tag or alternate image is accepted.
#[test]
#[ignore = "explicit opt-in only: UNSIGNED DEVELOPMENT live rootless ownership canary"]
fn development_rootless_canary_transition_restore() {
    let run = || -> Result<()> {
        require(
            development_env("MARTY_DEV_CANARY_OPT_IN")? == "I_ACCEPT_UNSIGNED_DEVELOPMENT_CANARY",
        )?;
        crate::installer_command::require_rootless_process()?;
        require(std::env::consts::ARCH == "x86_64")?;
        let parent = PathBuf::from(development_env("MARTY_DEV_CANARY_PARENT")?);
        let dockerpath = PathBuf::from(development_env("MARTY_DEV_CANARY_DOCKER")?);
        let helper = PathBuf::from(development_env("MARTY_DEV_CANARY_STATIC_HELPER")?);
        let expected_helper_sha = development_env("MARTY_DEV_CANARY_HELPER_SHA256")?;
        let reference = development_env("MARTY_DEV_CANARY_SERVICES_IMAGE")?;
        development_parent(&parent)?;
        require(id(&expected_helper_sha))?;
        require(crate::installer_verify::operator_digest(&helper)? == expected_helper_sha)?;
        development_static_amd64(&helper)?;
        let binding = RuntimeBinding {
            docker_host: format!("unix:///run/user/{}/docker.sock", unsafe {
                libc::geteuid()
            }),
            engine_id: development_env("MARTY_DEV_CANARY_ENGINE_ID")?,
            openbao_port: 18200, // inert journal field; no port is published.
            profile: RuntimeProfile::Rootless,
        };
        let observer = DockerRunner::from_binding(&dockerpath, &binding, &parent)?;
        let observation = observer.preflight()?;
        let (cached_image_id, _) = image(&observer, &reference, false)?;
        let before = development_container_ids(&observer)?;

        // Synthetic release-shaped fields satisfy journal structure only.
        // No release, signature, admission, bundle, credential, runtime
        // service, or installation readiness is claimed.
        let inventory_bytes = encoded(&json!({
            "schema": "elevenid.unsigned-development-canary-input/v1",
            "repository": "UNSIGNED DEVELOPMENT ONLY",
            "source_sha": "0".repeat(40), "release_tag": "v0.0.0",
            "platform": "linux/amd64", "build_run_id": 1, "build_run_attempt": 1,
            "artifacts": [],
            "images": {"gateway": reference, "signing-keys": reference}
        }))?;
        let inventory: crate::installer_release::Inventory =
            serde_json::from_slice(&inventory_bytes)
                .map_err(|_| "DEVELOPMENT inventory construction failed")?;
        let inventory_sha = sha(&inventory_bytes);
        let installation = parent.join(format!(
            "marty-development-canary-{}",
            uuid::Uuid::new_v4().simple()
        ));
        eprintln!(
            "UNSIGNED DEVELOPMENT attempted evidence path: {}",
            installation.display()
        );
        let mut state = InstallerState::create_test_with_runtime(
            &installation,
            Identity {
                source_sha: "0".repeat(40),
                release_tag: "v0.0.0".into(),
                inventory_sha256: format!("sha256:{inventory_sha}"),
            },
            binding,
            CandidateTestScope {
                inventory_sha256: inventory_sha,
                build_run_id: 1,
                build_run_attempt: 1,
            },
        )?;
        // Persistent from first creation, never a TempDir converted after
        // mutation. Neither success nor panic recursively deletes it. The
        // production DockerRunner removes only its isolated CLI config.
        let held_root =
            File::open(&installation).map_err(|_| "DEVELOPMENT evidence root unavailable")?;
        state.create_private_directory("evidence")?;
        persist(
            &mut state,
            "development-scope.json",
            &encoded(&json!({
                "schema": "elevenid.unsigned-development-canary-scope/v1",
                "classification": "UNSIGNED DEVELOPMENT ONLY",
                "expected_development_build_identity": "unknown:unreleased",
                "helper_build_identity_observed": false,
                "synthetic_journal_identity": true,
                "release_authentication_performed": false,
                "release_admission": false,
                "runtime_provisioning_authorized": false,
                "installation_ready": false,
                "automatic_failure_cleanup": false,
                "recovery_attempted": false,
                "helper_sha256": expected_helper_sha,
                "services_image": reference, "cached_image_id": cached_image_id,
                "docker_server_version": observation.server_version,
                "compose_version": observation.compose_version
            }))?,
        )?;
        persist(
            &mut state,
            "candidate-test-inventory.json",
            &inventory_bytes,
        )?;
        persist(
            &mut state,
            "development-existing-container-ids.json",
            &encoded(&before)?,
        )?;
        state.persist_operator(&helper, &expected_helper_sha)?;
        development_static_amd64(&installation.join("marty-deploy"))?;
        state.advance(Phase::Verified)?;

        let started = Instant::now();
        // Call actual canary code. installer_command::candidate_test would
        // continue into runtime provisioning and is intentionally not used.
        let attempt = qualify_candidate(
            &dockerpath,
            &installation,
            &mut state,
            &inventory,
            &expected_helper_sha,
        );
        // Observation only, including on error. Never reconstruct cleanup
        // authority from an ID/name found in a provisional receipt.
        let after = development_container_ids(&observer);
        let after_image = image(&observer, &reference, false).map(|value| value.0);
        let baseline_retained = after.as_ref().is_ok_and(|ids| before.is_subset(ids));
        let same_image = after_image
            .as_ref()
            .is_ok_and(|value| value == &cached_image_id);
        let validation = (|| -> Result<()> {
            attempt.as_ref().map_err(Clone::clone)?;
            require(
                baseline_retained && same_image && after.as_ref().is_ok_and(|ids| ids == &before),
            )?;
            state.require_live_phase(Phase::Verified)?;
            state.with_inspection(|view| {
                let complete = view.diagnostic_record(COMPLETE, true)?.ok_or(REFUSED)?;
                let intent = view.diagnostic_record(INTENT, true)?.ok_or(REFUSED)?;
                require(complete == completion_bytes(&intent)?)?;
                let result = view.diagnostic_record(RESULT, true)?.ok_or(REFUSED)?;
                let result: Value = serde_json::from_slice(&result).map_err(|_| REFUSED)?;
                require(
                    result["host_traversal_restored"] == true
                        && result["deletion_authorized"] == false
                        && result["installation_ready"] == false,
                )
            })
        })();
        let outcome = encoded(&json!({
            "schema": "elevenid.unsigned-development-canary-outcome/v1",
            "classification": "UNSIGNED DEVELOPMENT ONLY",
            "canary_succeeded": attempt.is_ok(),
            "harness_succeeded": validation.is_ok(),
            "elapsed_milliseconds": started.elapsed().as_millis(),
            "error": validation.as_ref().err().map(|error| error.chars().take(512).collect::<String>()),
            "existing_container_ids_retained": baseline_retained,
            "cached_image_id_unchanged": same_image,
            "container_observation_succeeded": after.is_ok(),
            "image_observation_succeeded": after_image.is_ok(),
            "containers_before": before.len(),
            "containers_after": after.as_ref().ok().map(BTreeSet::len),
            "runtime_provisioning_executed": false,
            "automatic_failure_cleanup": false,
            "recovery_attempted": false, "installation_ready": false
        }))?;
        // A held-directory O_EXCL diagnostic also survives poisoned state.
        // This private fsynced record grants no authority.
        write_file(&held_root, "development-outcome.json", &outcome)?;
        validation?;
        eprintln!(
            "UNSIGNED DEVELOPMENT canary completed; persistent evidence retained; no runtime provisioning"
        );
        Ok(())
    };
    if let Err(error) = run() {
        panic!(
            "UNSIGNED DEVELOPMENT canary stopped: {error}; preserve its printed evidence directory and all remaining helpers; no automatic cleanup or recovery was attempted"
        );
    }
}
