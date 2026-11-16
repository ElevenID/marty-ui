use super::*;
use crate::installer_state::Identity;
use serde_json::{json, Value};
use std::{
    fs as files,
    os::unix::fs::{symlink, PermissionsExt},
};
use zip::write::SimpleFileOptions;

fn image() -> String {
    format!("{IMAGE_REPOSITORY}@sha256:{}", "d".repeat(64))
}
fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
fn private(path: &Path, data: &[u8]) {
    files::write(path, data).unwrap();
    files::set_permissions(path, files::Permissions::from_mode(0o600)).unwrap();
}
fn inventory_fixture() -> Vec<u8> {
    bytes(
        &json!({"schema":"elevenid.installer-inventory/v1", "repository":release::REPOSITORY,
        "platform":"linux/amd64", "source_sha":"a".repeat(40),
        "release_tag":"v1.2.3-nightly.20261031.42", "build_run_id":42,"build_run_attempt":2,
        "artifacts":[
            {"name":"install.sh","sha256":"b".repeat(64),"size":10},
            {"name":"marty-deploy-linux-amd64","sha256":"b".repeat(64),"size":10},
            {"name":"prepared-selfhost-bundle.zip","sha256":"b".repeat(64),"size":10},
            {"name":"prepared-selfhost-images.json","sha256":"b".repeat(64),"size":10}],
        "images":{"gateway":format!("ghcr.io/elevenid/app@sha256:{}","f".repeat(64)),
            "openbao_didcomm_image":format!("ghcr.io/elevenid/plugin@sha256:{}","e".repeat(64))}}),
    )
}
fn zip_fixture(entries: &[(&str, &[u8])], compression: zip::CompressionMethod) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in entries {
        writer
            .start_file(
                *name,
                SimpleFileOptions::default()
                    .compression_method(compression)
                    .unix_permissions(0o644),
            )
            .unwrap();
        writer.write_all(data).unwrap();
    }
    writer.finish().unwrap().into_inner()
}
fn package() -> (Value, Vec<u8>, Vec<u8>) {
    let compose = bytes(
        &json!({"services":{"cloudflared":{"image":image(), "read_only":true, "init":true}}}),
    );
    let script = b"#!/bin/sh\nexec cloudflared tunnel --no-autoupdate run\n";
    let archive = zip_fixture(
        &[(COMPOSE, &compose), (SCRIPT, script)],
        zip::CompressionMethod::Stored,
    );
    let sbom = bytes(&json!({"bomFormat":"CycloneDX","specVersion":"1.6"}));
    let manifest = json!({"schema":"elevenid.hosting-addon/v1","addon":"cloudflare-tunnel",
        "platform":"linux/amd64","source_sha":"a".repeat(40),"release_tag":"v1.2.3-nightly.20261031.42",
        "build_run_id":42,"build_run_attempt":2,"signer_workflow":".github/workflows/nightly-release.yml",
        "services":{"cloudflared":image()},"files":{
            COMPOSE:format!("sha256:{}",release::sha256(&compose)),
            SCRIPT:format!("sha256:{}",release::sha256(script))},
        "archive_sha256":format!("sha256:{}",release::sha256(&archive)),"archive_size_bytes":archive.len(),
        "sbom_sha256":format!("sha256:{}",release::sha256(&sbom))});
    (manifest, archive, sbom)
}

#[test]
fn exact_producer_identity_and_image_role_are_required() {
    let inventory = release::parse_inventory(&inventory_fixture()).unwrap();
    let (value, _, _) = package();
    manifest(&bytes(&value), &inventory).unwrap();
    let mut stable_inventory = inventory.clone();
    stable_inventory.release_tag = "v1.2.3".into();
    let mut stable = value.clone();
    stable["release_tag"] = "v1.2.3".into();
    assert!(manifest(&bytes(&stable), &stable_inventory).is_err());
    stable["signer_workflow"] = ".github/workflows/cd.yml".into();
    manifest(&bytes(&stable), &stable_inventory).unwrap();
    for (field, replacement) in [
        ("source_sha", json!("b".repeat(40))),
        ("release_tag", json!("v1.2.4")),
        ("build_run_id", json!(43)),
        ("build_run_attempt", json!(1)),
        ("build_run_attempt", json!(true)),
        ("signer_workflow", json!(".github/workflows/cd.yml")),
        ("platform", json!("linux/arm64")),
        ("archive_size_bytes", json!(MAX_ARCHIVE + 1)),
        ("unknown", json!(true)),
    ] {
        let mut changed = value.clone();
        changed[field] = replacement;
        assert!(manifest(&bytes(&changed), &inventory).is_err(), "{field}");
    }
    for reference in [
        format!("{IMAGE_REPOSITORY}:latest"),
        format!("{IMAGE_REPOSITORY}.evil@sha256:{}", "a".repeat(64)),
        format!("{IMAGE_REPOSITORY}@sha256:{}", "A".repeat(64)),
    ] {
        assert!(!is_connector_image(&reference));
        let mut changed = value.clone();
        changed["services"]["cloudflared"] = reference.into();
        assert!(manifest(&bytes(&changed), &inventory).is_err());
    }
    let mut changed = value.clone();
    changed["services"]["gateway"] = image().into();
    assert!(manifest(&bytes(&changed), &inventory).is_err());
    let mut changed = value.clone();
    changed["files"]["../escape"] = format!("sha256:{}", "a".repeat(64)).into();
    assert!(manifest(&bytes(&changed), &inventory).is_err());
    let duplicate = String::from_utf8(bytes(&value)).unwrap().replacen(
        "\"build_run_id\":42",
        "\"build_run_id\":42,\"build_run_id\":42",
        1,
    );
    assert!(manifest(duplicate.as_bytes(), &inventory).is_err());
}

#[test]
fn archive_requires_exact_regular_stored_paths_and_role_closure() {
    let inventory = release::parse_inventory(&inventory_fixture()).unwrap();
    let (value, archive, _) = package();
    let manifest = manifest(&bytes(&value), &inventory).unwrap();
    let files = payload(&archive, &manifest).unwrap();
    for (entries, compression) in [
        (
            vec![
                (COMPOSE, files[COMPOSE].as_slice()),
                ("../escape", files[SCRIPT].as_slice()),
            ],
            zip::CompressionMethod::Stored,
        ),
        (
            vec![
                (COMPOSE, files[COMPOSE].as_slice()),
                (SCRIPT, files[SCRIPT].as_slice()),
                ("extra", b"x".as_slice()),
            ],
            zip::CompressionMethod::Stored,
        ),
        (
            vec![
                (COMPOSE, files[COMPOSE].as_slice()),
                (SCRIPT, files[SCRIPT].as_slice()),
            ],
            zip::CompressionMethod::Deflated,
        ),
    ] {
        let archive = zip_fixture(&entries, compression);
        let mut manifest = manifest.clone();
        manifest.archive_sha256 = format!("sha256:{}", release::sha256(&archive));
        manifest.archive_size_bytes = archive.len() as u64;
        assert!(payload(&archive, &manifest).is_err());
    }
    let compose =
        bytes(&json!({"services":{"cloudflared":{"image":image()},"extra":{"image":image()}}}));
    let archive = zip_fixture(
        &[(COMPOSE, &compose), (SCRIPT, &files[SCRIPT])],
        zip::CompressionMethod::Stored,
    );
    let mut manifest = manifest;
    manifest.archive_sha256 = format!("sha256:{}", release::sha256(&archive));
    manifest.archive_size_bytes = archive.len() as u64;
    manifest.files.insert(
        COMPOSE.into(),
        format!("sha256:{}", release::sha256(&compose)),
    );
    assert!(payload(&archive, &manifest).is_err());
}

fn state_fixture(selected: bool) -> (tempfile::TempDir, PathBuf, InstallerState) {
    let root = tempfile::tempdir().unwrap();
    files::set_permissions(root.path(), files::Permissions::from_mode(0o700)).unwrap();
    let installation = root.path().join("installation");
    let inventory = inventory_fixture();
    let mut state = InstallerState::create(
        &installation,
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3-nightly.20261031.42".into(),
            inventory_sha256: format!("sha256:{}", release::sha256(&inventory)),
        },
    )
    .unwrap();
    state.create_private_directory("evidence").unwrap();
    state.create_private_directory("downloads").unwrap();
    state
        .write_evidence("installer-inventory.json", &inventory)
        .unwrap();
    state.advance(Phase::Verified).unwrap();
    let hosting = if selected {
        let token = root.path().join("token");
        private(&token, b"private-test-token-123456789\n");
        let hosting = root.path().join("hosting.json");
        private(
            &hosting,
            &bytes(
                &json!({"schema":"elevenid.installation-hosting/v1", "mode":"external-proxy",
            "public_origin":"https://marty.example.com", "listener":{"bind_address":"127.0.0.1","port":8443},
            "tls":{"termination":"marty-keyless","certificate_source":"managed-ca"},
            "connector":{"kind":"cloudflare-tunnel","token_file":token}}),
            ),
        );
        installer_hosting::prepare(Some(&hosting), None).unwrap()
    } else {
        installer_hosting::prepare(None, None).unwrap()
    };
    installer_hosting::select(hosting, &mut state).unwrap();
    (root, installation, state)
}

// This fixture represents the private boundary immediately after successful
// standard verifier calls; it does not bypass verification in a production API.
fn bind_fixture(installation: &Path, state: &mut InstallerState, bind: bool) -> PathBuf {
    let directory = installation.join("downloads").join(DIRECTORY);
    create_directory(
        &fs::directory(&installation.join("downloads"), REFUSED).unwrap(),
        DIRECTORY,
    )
    .unwrap();
    let (value, archive, sbom) = package();
    let raw = bytes(&value);
    let mut assets = BTreeMap::new();
    for (name, data) in [(MANIFEST, raw), (ARCHIVE, archive), (SBOM, sbom)] {
        private(&directory.join(name), &data);
        assets.insert(
            name.into(),
            Asset {
                sha256: release::sha256(&data),
                size: data.len() as u64,
            },
        );
        for suffix in [".sigstore.json", ".provenance.jsonl"] {
            let name = format!("{name}{suffix}");
            let data = b"authenticated-fixture";
            private(&directory.join(&name), data);
            assets.insert(
                name,
                Asset {
                    sha256: release::sha256(data),
                    size: data.len() as u64,
                },
            );
        }
    }
    let manifest = manifest(
        &bytes(&value),
        &release::parse_inventory(&inventory_fixture()).unwrap(),
    )
    .unwrap();
    extract(
        &directory,
        &payload(&files::read(directory.join(ARCHIVE)).unwrap(), &manifest).unwrap(),
    )
    .unwrap();
    let receipt = Receipt {
        schema: "elevenid.installer-hosting-addon/v1".into(),
        installation: installation.into(),
        installation_id: state.journal().installation_id(),
        hosting_selection_sha256: state.journal().hosting_selection_sha256().unwrap().into(),
        inventory_sha256: state.journal().identity().inventory_sha256.clone(),
        assets,
    };
    let raw = serde_json::to_vec(&receipt).unwrap();
    state.write_evidence(RECORD, &raw).unwrap();
    if bind {
        state.bind_hosting_addon(&release::sha256(&raw)).unwrap();
    }
    directory
}

#[test]
fn no_connector_has_no_environment_or_image_authority() {
    let (_root, _, mut state) = state_fixture(false);
    assert!(state.with_inspection(environment).unwrap().is_empty());
    assert!(state.with_inspection(approved_images).unwrap().is_empty());
    state.write_evidence(RECORD, b"{}").unwrap();
    assert!(state.with_inspection(environment).is_err());
}

#[test]
fn connector_requires_the_journal_bound_authenticated_receipt() {
    let (_root, installation, mut state) = state_fixture(true);
    assert!(state.with_inspection(approved_images).is_err());
    bind_fixture(&installation, &mut state, false);
    assert!(state.with_inspection(approved_images).is_err());
}

#[test]
fn changed_proofs_sbom_runtime_or_receipt_revoke_admission() {
    for name in [
        SBOM,
        "selfhost-cloudflare-images.json.sigstore.json",
        "runtime/scripts/cloudflared-selfhost.sh",
        RECORD,
    ] {
        let (_root, installation, mut state) = state_fixture(true);
        let directory = bind_fixture(&installation, &mut state, true);
        assert_eq!(
            state.with_inspection(approved_images).unwrap(),
            BTreeSet::from([image()])
        );
        let path = if name == RECORD {
            installation.join("evidence").join(name)
        } else {
            directory.join(name)
        };
        files::set_permissions(&path, files::Permissions::from_mode(0o600)).unwrap();
        files::write(&path, b"changed").unwrap();
        if name.starts_with("runtime/") {
            files::set_permissions(&path, files::Permissions::from_mode(0o444)).unwrap();
        }
        assert!(state.with_inspection(approved_images).is_err(), "{name}");
    }
}

#[test]
fn linked_or_extra_runtime_files_are_rejected() {
    let (_root, installation, mut state) = state_fixture(true);
    let directory = bind_fixture(&installation, &mut state, true);
    let script = directory.join("runtime").join(SCRIPT);
    files::rename(&script, directory.join("original-script")).unwrap();
    symlink(directory.join("original-script"), &script).unwrap();
    assert!(state.with_inspection(approved_images).is_err());
}

#[test]
fn compose_binding_survives_maintenance_layer_reset_without_duplicate_evidence() {
    let (_root, installation, mut state) = state_fixture(true);
    let directory = bind_fixture(&installation, &mut state, true);
    let mut inputs = ComposeInputs {
        installation: installation.clone(),
        project: state.journal().compose_project(),
        files: Vec::new(),
        bound_inputs: Vec::new(),
        environment: BoundFile {
            path: installation.join("environment"),
            sha256: "a".repeat(64),
        },
        profiles: Vec::new(),
        services: vec!["gateway".into()],
        approved_images: BTreeSet::new(),
        #[cfg(feature = "installer-development")]
        development_image: None,
        writable_bind_roots: BTreeSet::new(),
        readonly_bind_roots: BTreeSet::new(),
        allowed_loopback_ports: BTreeSet::new(),
        ingress_listener: None,
        prior: None,
    };
    state
        .with_inspection(installer_hosting::resolve)
        .unwrap()
        .bind_inputs(&mut inputs)
        .unwrap();
    bind_inputs(&mut inputs).unwrap();
    let count = inputs.bound_inputs.len();
    bind_inputs(&mut inputs).unwrap();
    inputs.files.clear();
    bind_inputs(&mut inputs).unwrap();
    assert_eq!(inputs.bound_inputs.len(), count);
    assert_eq!(inputs.files.len(), 1);
    assert_eq!(
        inputs.files[0].path,
        directory.join("runtime").join(COMPOSE)
    );
    assert_eq!(inputs.services, vec!["gateway", "cloudflared"]);
    assert_eq!(inputs.approved_images, BTreeSet::from([image()]));
    assert_eq!(
        state.with_inspection(environment).unwrap()["MARTY_CLOUDFLARE_ADDON_DIR"],
        directory.join("runtime").to_str().unwrap()
    );
    inputs
        .bound_inputs
        .iter_mut()
        .find(|file| file.path.ends_with(RECORD))
        .unwrap()
        .sha256 = "0".repeat(64);
    assert!(bind_inputs(&mut inputs).is_err());
}
