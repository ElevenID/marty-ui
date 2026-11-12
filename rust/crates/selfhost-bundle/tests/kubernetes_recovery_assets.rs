//! Recovery helpers and catalogs must survive the native release packager as
//! authenticated, byte-exact assets. No Docker or cluster process is needed.

use marty_selfhost_bundle::{package, Options, MARKER};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, io::Read, path::Path};

const RECOVERY_ASSETS: [&str; 16] = [
    "scripts/bootstrap_kubernetes_openbao.py",
    "scripts/adopt_kubernetes_renewal.py",
    "scripts/kubernetes_renewal_adoption_state.py",
    "scripts/stage_kubernetes_renewal_credentials.py",
    "scripts/activate_kubernetes_application_credentials.py",
    "scripts/activate_kubernetes_renewal_credentials.py",
    "scripts/stage_kubernetes_application_credentials.py",
    "scripts/kubernetes_application_state.py",
    "scripts/prepare_kubernetes_helm_values.py",
    "scripts/inspect_kubernetes_legacy_credentials.py",
    "scripts/recover_kubernetes_legacy_credentials.py",
    "scripts/reload_kubernetes_legacy_workloads.py",
    "scripts/kubernetes_legacy_recovery_sources.py",
    "deploy-config/catalog/kubernetes-application-tokens.json",
    "deploy-config/catalog/kubernetes-secrets.json",
    "docs/kubernetes-legacy-credential-recovery.md",
];

fn fixture(root: &Path) -> (Options, BTreeMap<&'static str, Vec<u8>>) {
    let source = root.join("source");
    fs::create_dir(&source).unwrap();
    let mut assets = vec![
        "docker-compose.selfhost.prod.yml",
        "docker-compose.selfhost.bundle.override.yml",
        ".env.selfhost.production.example",
        "SELFHOST_BUNDLE.md",
    ];
    for path in &assets {
        fs::write(source.join(path), "services: {}\n").unwrap();
    }
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut expected = BTreeMap::new();
    for path in RECOVERY_ASSETS {
        let bytes = fs::read(repository.join(path)).unwrap();
        assert!(
            !bytes.is_empty(),
            "recovery asset must not be empty: {path}"
        );
        let destination = source.join(path);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(destination, &bytes).unwrap();
        expected.insert(path, bytes);
        assets.push(path);
    }
    let descriptor = source.join("deploy-config/bundles/selfhost.json");
    fs::create_dir_all(descriptor.parent().unwrap()).unwrap();
    fs::write(descriptor, json!({"assets": assets}).to_string()).unwrap();
    (
        Options {
            repo: source,
            output: root.join("selfhost-prepared"),
            archive: Some(root.join("selfhost-prepared.zip")),
            replace: false,
        },
        expected,
    )
}

fn render(_: &Path, args: &[String]) -> marty_selfhost_bundle::Result<String> {
    assert_eq!(
        args,
        [
            "--env-file",
            ".env.selfhost.production.example",
            "-f",
            "docker-compose.selfhost.prod.yml",
            "-f",
            "docker-compose.selfhost.bundle.override.yml",
            "config",
            "--no-interpolate",
        ]
    );
    Ok(format!(
        "services:\n  app:\n    image: example.invalid/app@sha256:{}\n",
        "a".repeat(64)
    ))
}

#[test]
fn repository_descriptor_declares_every_recovery_asset_exactly_once() {
    let descriptor: Value = serde_json::from_str(include_str!(
        "../../../../deploy-config/bundles/selfhost.json"
    ))
    .unwrap();
    let assets = descriptor["assets"].as_array().unwrap();
    for path in RECOVERY_ASSETS {
        assert_eq!(
            assets
                .iter()
                .filter(|value| value.as_str() == Some(path))
                .count(),
            1,
            "recovery asset must be explicitly declared once: {path}"
        );
    }
}

#[test]
fn native_package_preserves_recovery_bytes_marker_hashes_and_zip_membership() {
    let root = tempfile::tempdir().unwrap();
    let (options, expected) = fixture(root.path());
    let result = package(&options, render).unwrap();
    assert_eq!(result.output.file_name().unwrap(), "selfhost-prepared");
    let marker_bytes = fs::read(result.output.join(MARKER)).unwrap();
    let marker: Value = serde_json::from_slice(&marker_bytes).unwrap();
    let mut archive =
        zip::ZipArchive::new(fs::File::open(result.archive.unwrap()).unwrap()).unwrap();
    let members: Vec<String> = archive
        .file_names()
        .map(|name| name.unwrap().into_owned())
        .collect();
    for (path, bytes) in expected {
        assert_eq!(
            fs::read(result.output.join(path)).unwrap(),
            bytes,
            "native package changed recovery asset bytes: {path}"
        );
        assert_eq!(
            marker["files"][path],
            format!("{:x}", Sha256::digest(&bytes)),
            "native marker does not authenticate exact recovery bytes: {path}"
        );
        let member = format!("selfhost-prepared/{path}");
        assert_eq!(
            members.iter().filter(|name| **name == member).count(),
            1,
            "recovery asset must occur exactly once in the ZIP: {path}"
        );
        let mut archived = Vec::new();
        archive
            .by_name(&member)
            .unwrap()
            .read_to_end(&mut archived)
            .unwrap();
        assert_eq!(archived, bytes, "ZIP changed recovery bytes: {path}");
    }
    let mut archived_marker = Vec::new();
    archive
        .by_name(&format!("selfhost-prepared/{MARKER}"))
        .unwrap()
        .read_to_end(&mut archived_marker)
        .unwrap();
    assert_eq!(archived_marker, marker_bytes);
    assert!(result.output.join("docker-compose.yml").is_file());
    for render_source in [
        "docker-compose.selfhost.prod.yml",
        "docker-compose.selfhost.bundle.override.yml",
    ] {
        assert!(!result.output.join(render_source).exists());
        assert!(!members.contains(&format!("selfhost-prepared/{render_source}")));
    }
}
