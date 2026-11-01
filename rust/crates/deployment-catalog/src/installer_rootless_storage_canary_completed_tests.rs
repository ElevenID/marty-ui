//! Synthetic completed observations exercise the read-only evidence admission;
//! this fixture does not claim a Docker or user-namespace qualification run.
use super::*;
use crate::installer_state::{CandidateTestScope, Identity, RuntimeBinding, RuntimeProfile};
use std::os::unix::fs::PermissionsExt;

pub(crate) fn candidate_fixture(hosting: &Value) -> (tempfile::TempDir, PathBuf, InstallerState) {
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "run this fixture as an ordinary nonroot identity"
    );
    assert_ne!(unsafe { libc::getegid() }, 0);
    let files = tempfile::tempdir().unwrap();
    fs::set_permissions(files.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let installation = files.path().join("installation");
    let operator = b"synthetic signed operator bytes for read-only receipt tests\n";
    let operator_source = files.path().join("operator");
    fs::write(&operator_source, operator).unwrap();
    fs::set_permissions(&operator_source, fs::Permissions::from_mode(0o700)).unwrap();
    let services = format!(
        "ghcr.io/elevenid/marty-ui-oss/services@sha256:{}",
        "c".repeat(64)
    );
    let inventory = encoded(&json!({
        "schema":"elevenid.installer-inventory/v1", "repository":crate::installer_release::REPOSITORY,
        "platform":"linux/amd64", "source_sha":"a".repeat(40),
        "release_tag":"v1.2.3-nightly.20261031.42", "build_run_id":42,"build_run_attempt":2,
        "artifacts":[
            {"name":"install.sh","sha256":"b".repeat(64),"size":10},
            {"name":"marty-deploy-linux-amd64","sha256":sha(operator),"size":operator.len()},
            {"name":"prepared-selfhost-bundle.zip","sha256":"b".repeat(64),"size":10},
            {"name":"prepared-selfhost-images.json","sha256":"b".repeat(64),"size":10}],
        "images":{"gateway":services,"signing-keys":services,
            "openbao_didcomm_image":format!("ghcr.io/elevenid/marty-ui-oss/openbao@sha256:{}","d".repeat(64))}
    })).unwrap();
    crate::installer_release::parse_inventory(&inventory).unwrap();
    let binding = RuntimeBinding {
        docker_host: format!("unix:///run/user/{}/docker.sock", unsafe {
            libc::geteuid()
        }),
        engine_id: "synthetic-rootless-engine".into(),
        openbao_port: 18200,
        profile: RuntimeProfile::Rootless,
    };
    let mut state = InstallerState::create_test_with_runtime(
        &installation,
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3-nightly.20261031.42".into(),
            inventory_sha256: format!("sha256:{}", sha(&inventory)),
        },
        binding.clone(),
        CandidateTestScope {
            inventory_sha256: sha(&inventory),
            build_run_id: 42,
            build_run_attempt: 2,
        },
    )
    .unwrap();
    state.create_private_directory("evidence").unwrap();
    state.create_private_directory("downloads").unwrap();
    state
        .persist_operator(&operator_source, &sha(operator))
        .unwrap();
    for name in ["candidate-test-inventory.json", "installer-inventory.json"] {
        state.write_evidence(name, &inventory).unwrap();
        for suffix in [".sigstore.json", ".provenance.jsonl"] {
            state
                .write_evidence(
                    &format!("{name}{suffix}"),
                    b"synthetic previously authenticated sidecar\n",
                )
                .unwrap();
        }
    }
    state.advance(Phase::Verified).unwrap();
    let selection = files.path().join("hosting.json");
    fs::write(&selection, encoded(hosting).unwrap()).unwrap();
    fs::set_permissions(&selection, fs::Permissions::from_mode(0o600)).unwrap();
    crate::installer_hosting::select(
        crate::installer_hosting::prepare(Some(&selection), None).unwrap(),
        &mut state,
    )
    .unwrap();
    let canary_id = uuid::Uuid::new_v4();
    let (root, evidence) = state
        .with_inspection(|view| {
            Ok((
                stamp(view.installation_directory())?,
                stamp(&open_dir(view.installation_directory(), "evidence")?)?,
            ))
        })
        .unwrap();
    let pull = PullIntent {
        schema: "elevenid.rootless-storage-canary-pull-intent/v1".into(),
        installation_id: state.journal().installation_id(),
        canary_id,
        source_sha: state.journal().identity().source_sha.clone(),
        inventory_sha256: state.journal().identity().inventory_sha256.clone(),
        engine_id: binding.engine_id.clone(),
        docker_host: binding.docker_host,
        image: services.clone(),
        root: root.clone(),
        evidence: evidence.clone(),
    };
    let pull_bytes = encoded(&pull).unwrap();
    let marker = format!("marty-rootless-canary/v1:{canary_id}\n").into_bytes();
    let intent = Intent {
        schema: "elevenid.rootless-storage-canary-intent/v1".into(),
        pull_intent_sha256: sha(&pull_bytes),
        installation_id: state.journal().installation_id(),
        canary_id,
        source_sha: state.journal().identity().source_sha.clone(),
        inventory_sha256: state.journal().identity().inventory_sha256.clone(),
        engine_id: binding.engine_id,
        image: services,
        image_id: format!("sha256:{}", "e".repeat(64)),
        operator_sha256: sha(operator),
        root,
        evidence,
        parent_name: format!("rootless-canary-{}", canary_id.simple()),
        marker_sha256: sha(&marker),
        host_uid: unsafe { libc::geteuid() },
        host_gid: unsafe { libc::getegid() },
    };
    let intent_bytes = encoded(&intent).unwrap();
    let created = state
        .with_inspection(|view| {
            create_layout(
                view,
                &installation,
                &intent,
                &request_bytes(&intent)?,
                &marker,
            )
        })
        .unwrap();
    let transition = receipt(
        &intent,
        "transition",
        container_name(canary_id, "transition").unwrap(),
        "1".repeat(64),
    );
    let restore = receipt(
        &intent,
        "restore",
        container_name(canary_id, "restore").unwrap(),
        "2".repeat(64),
    );
    let foreign_uid = intent.host_uid.checked_add(100000).unwrap();
    let foreign_gid = intent.host_gid.checked_add(100000).unwrap();
    state.with_inspection(|view| {
        let (parent,_) = bound_layout(view,&installation,&intent,&created)?;
        for phase in ["transition","restore"] {
            write_file(&parent,&format!("{phase}-output.json"),&encoded(&json!({
                "schema":"elevenid.rootless-storage-canary-helper/v1",
                "installation_id":intent.installation_id,"canary_id":canary_id,"phase":phase,
                "host_uid_zero":intent.host_uid,"host_gid_zero":intent.host_gid,
                "host_uid_hundred":foreign_uid,"host_gid_hundred":foreign_gid,
                "marker_sha256":intent.marker_sha256,"child_dev":created.child.dev,"child_ino":created.child.ino
            }))?)?;
        }
        Ok(())
    }).unwrap();
    let mut foreign = created.child.clone();
    foreign.uid = foreign_uid;
    foreign.gid = foreign_gid;
    for (name, bytes) in [
        (PULL_INTENT,pull_bytes), (INTENT,intent_bytes.clone()), (CREATED,encoded(&created).unwrap()),
        (TRANSITION_CONTAINER,encoded(&transition).unwrap()),(RESTORE_CONTAINER,encoded(&restore).unwrap()),
        (START_INTENT,encoded(&json!({"schema":"elevenid.rootless-storage-canary-start-intent/v1",
            "intent_sha256":sha(&intent_bytes),"transition_id":transition.id,"restore_id":restore.id,
            "parent":created.parent,"child":created.child})).unwrap()),
        (FOREIGN,encoded(&json!({"schema":"elevenid.rootless-storage-canary-foreign/v1",
            "intent_sha256":sha(&intent_bytes),"child":foreign,"host_uid_hundred":foreign_uid,"host_gid_hundred":foreign_gid})).unwrap()),
        (RESTORE_INTENT,encoded(&json!({"schema":"elevenid.rootless-storage-canary-restore-intent/v1",
            "intent_sha256":sha(&intent_bytes),"restore_id":restore.id,"foreign_child":foreign})).unwrap()),
        (RESULT,encoded(&json!({"schema":"elevenid.rootless-storage-canary-result/v1",
            "intent_sha256":sha(&intent_bytes),"restored_child":created.child,"host_traversal_restored":true,
            "deletion_authorized":false,"installation_ready":false})).unwrap()),
        (REMOVE_INTENT,removal_intent_bytes(&intent_bytes,&transition,&restore).unwrap()),
        (TRANSITION_REMOVED,removed_bytes(&intent_bytes,&transition,"removed").unwrap()),
        (RESTORE_REMOVED,removed_bytes(&intent_bytes,&restore,"removed").unwrap()),
        (COMPLETE,completion_bytes(&intent_bytes).unwrap()),
    ] { state.write_evidence(name,&bytes).unwrap(); }
    state.advance(Phase::Provisioning).unwrap();
    state
        .generate_local_credentials(
            &json!({"passwordPolicy":crate::installer_state::PASSWORD_POLICY}),
        )
        .unwrap();
    state
        .persist_credential_creation_receipt(&installation)
        .unwrap();
    (files, installation, state)
}

fn hosting() -> Value {
    json!({"schema":"elevenid.installation-hosting/v1","mode":"direct",
        "public_origin":"https://login.example.com","listener":{"bind_address":"0.0.0.0","port":8443},
        "tls":{"termination":"marty-keyless","certificate_source":"acme","http01_host_port":18080,
            "acme":{"environment":"production","directory_url":"https://acme-v02.api.letsencrypt.org/directory",
                "profile":"shortlived","terms_url":"https://letsencrypt.org/documents/LE-SA-v1.6-August-18-2025.pdf",
                "terms_agreed":true}}})
}

#[test]
#[ignore = "requires an ordinary nonroot OS identity for the rootless evidence fixture"]
fn completed_candidate_chain_and_preparation_reopen_without_creation_capability() {
    let (_files, installation, mut state) = candidate_fixture(&hosting());
    let canary = state.with_inspection(require_completed).unwrap();
    assert_eq!(canary.len(), 19);
    crate::installer_acme_preparation::prepare(&mut state, &installation).unwrap();
    let record = state
        .with_inspection(|view| view.read_evidence(crate::installer_acme_preparation::RECORD))
        .unwrap();
    let value: Value = serde_json::from_slice(&record).unwrap();
    assert_eq!(value["provenance"], "signed-candidate-qualification");
    assert_eq!(value["deletion_authorized"], false);
    assert_eq!(value["installation_ready"], false);
    for name in [
        crate::installer_creation_identity::RECEIPT,
        crate::installer_creation_identity::CREDENTIAL_RECEIPT,
        crate::installer_creation_identity::APPLICATION_RECEIPT,
    ] {
        assert!(!installation.join("evidence").join(name).exists());
    }
    drop(state);
    let view = LockedInspection::open(&installation).unwrap();
    assert_eq!(require_completed(&view).unwrap(), canary);
    crate::installer_acme_preparation::verify(&view, &installation).unwrap();
    assert_eq!(
        view.read_evidence(crate::installer_acme_preparation::RECORD)
            .unwrap(),
        record
    );
}

#[test]
#[ignore = "requires an ordinary nonroot OS identity for the rootless evidence fixture"]
fn candidate_preparation_refuses_changed_canary_inventory_operator_and_storage() {
    for mutation in [
        "complete",
        "native-removal",
        "inventory",
        "sidecar",
        "operator",
        "marker",
        "projection",
    ] {
        let (_files, installation, mut state) = candidate_fixture(&hosting());
        crate::installer_acme_preparation::prepare(&mut state, &installation).unwrap();
        let path = match mutation {
            "complete" => installation.join("evidence").join(COMPLETE),
            "native-removal" => installation.join("evidence").join(RESTORE_REMOVED),
            "inventory" => installation.join("evidence/installer-inventory.json"),
            "sidecar" => installation.join("evidence/candidate-test-inventory.json.sigstore.json"),
            "operator" => installation.join("marty-deploy"),
            "projection" => installation.join("secrets/operator_bootstrap_password"),
            "marker" => {
                let bytes = state
                    .with_inspection(|view| view.read_evidence(INTENT))
                    .unwrap();
                let intent: Intent = serde_json::from_slice(&bytes).unwrap();
                installation
                    .join("evidence")
                    .join(intent.parent_name)
                    .join("child/marker")
            }
            _ => unreachable!(),
        };
        let previous = fs::read(&path).unwrap();
        let mut changed = previous.clone();
        changed.push(b' ');
        let mode = fs::metadata(&path).unwrap().mode() & 0o7777;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, &changed).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        drop(state);
        let view = LockedInspection::open(&installation).unwrap();
        assert!(
            crate::installer_acme_preparation::verify(&view, &installation).is_err(),
            "{mutation}"
        );
        assert_eq!(fs::read(&path).unwrap(), changed);
    }
}
