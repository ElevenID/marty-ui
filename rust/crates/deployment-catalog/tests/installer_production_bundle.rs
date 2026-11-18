//! Actual production ZIP writer -> installer extractor compatibility.
//! Only Compose rendering is controlled: this is not Docker/runtime qualification.
#![cfg(target_os = "linux")]

use marty_deployment_catalog::installer_artifacts::extract_bundle;
use marty_selfhost_bundle::{package_with_image_lock, Options, MARKER};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::Path};

fn write(root: &Path, name: &str, bytes: &[u8]) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn files(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn visit(root: &Path, directory: &Path, result: &mut BTreeMap<String, Vec<u8>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(root, &path, result);
            } else {
                result.insert(
                    path.strip_prefix(root)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}

#[test]
fn installer_extracts_real_packager_deflate_markers_and_executable_resources() {
    let owned = tempfile::tempdir().unwrap();
    fs::set_permissions(owned.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let repo = owned.path().join("source");
    fs::create_dir(&repo).unwrap();
    let compose = b"services:\n  app:\n    image: example:v1\n";
    write(&repo, "docker-compose.selfhost.prod.yml", compose);
    write(
        &repo,
        "docker-compose.selfhost.bundle.override.yml",
        b"services: {}\n",
    );
    write(
        &repo,
        ".env.selfhost.production.example",
        b"COMPOSE_PROJECT_NAME=fixture\n",
    );
    write(
        &repo,
        "SELFHOST_BUNDLE.md",
        b"Self-host installation fixture.\n",
    );
    write(
        &repo,
        "scripts/launch.sh",
        b"#!/bin/sh\nexec /app/service\n",
    );
    fs::set_permissions(
        repo.join("scripts/launch.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    write(
        &repo,
        "config/keycloak/realm.json",
        b"{\"realm\":\"fixture\"}\n",
    );
    // A compressible public resource exercises actual production Deflate output.
    write(
        &repo,
        "config/public-resource.txt",
        &b"public-resource\n".repeat(4096),
    );
    write(
        &repo,
        "release/stack-lock.json",
        br#"{"release":"marty-ui@1.2.3"}"#,
    );
    let manifest = json!({"assets": [
        "docker-compose.selfhost.prod.yml", "docker-compose.selfhost.bundle.override.yml",
        ".env.selfhost.production.example", "SELFHOST_BUNDLE.md", "scripts", "config"
    ]});
    write(
        &repo,
        "deploy-config/bundles/selfhost.json",
        &serde_json::to_vec(&manifest).unwrap(),
    );
    let image = format!("ghcr.io/elevenid/app@sha256:{}", "a".repeat(64));
    let image_lock = json!({
        "schema": "marty.selfhost-image-lock/v1", "release": "marty-ui@1.2.3",
        "services": {"app": image},
        "openbao_didcomm_image": format!("ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:{}", "b".repeat(64))
    });
    let lock_path = owned.path().join("images.json");
    fs::write(&lock_path, serde_json::to_vec(&image_lock).unwrap()).unwrap();
    let options = Options {
        repo,
        output: owned.path().join("selfhost-prepared"),
        archive: Some(owned.path().join("prepared-selfhost-bundle.zip")),
        replace: false,
    };
    let published = package_with_image_lock(
        &options,
        |stage, _| {
            Ok(format!(
                "services:\n  app:\n    image: example:v1\n    volumes:\n      - type: bind\n        source: {}\n        target: /launch.sh\n",
                stage.join("scripts/launch.sh").display()
            ))
        },
        &lock_path,
    ).unwrap();
    let archive_path = published.archive.unwrap();
    let archive_bytes = fs::read(&archive_path).unwrap();
    let digest = format!("{:x}", Sha256::digest(&archive_bytes));
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(archive_bytes)).unwrap();
    let resource = zip
        .by_name("selfhost-prepared/config/public-resource.txt")
        .unwrap();
    assert_eq!(resource.compression(), zip::CompressionMethod::Deflated);
    assert!(resource.compressed_size() < resource.size());
    drop(resource);

    let destination = owned.path().join("installed");
    let extracted = extract_bundle(&archive_path, &destination, &digest).unwrap();
    assert_eq!(files(&extracted), files(&published.output));
    assert_eq!(
        fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(extracted.join("scripts/launch.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert_eq!(
        fs::metadata(extracted.join("config/keycloak/realm.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    let marker: Value = serde_json::from_slice(&fs::read(extracted.join(MARKER)).unwrap()).unwrap();
    for (name, hash) in marker["files"].as_object().unwrap() {
        assert_eq!(
            hash.as_str().unwrap(),
            format!(
                "{:x}",
                Sha256::digest(fs::read(extracted.join(name)).unwrap())
            )
        );
    }
    assert_eq!(
        serde_json::from_slice::<Value>(
            &fs::read(extracted.join(".marty-selfhost-images.json")).unwrap()
        )
        .unwrap(),
        image_lock
    );
    assert!(fs::read_to_string(extracted.join("docker-compose.yml"))
        .unwrap()
        .contains(&image));
    assert!(extract_bundle(&archive_path, &destination, &digest).is_err());
}
