//! Installer layers stay authenticated source assets. Compose, not the packager,
//! interprets their anchors and merge tags when the installer selects a phase.

use marty_selfhost_bundle::{package, Options, MARKER};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path};

const LAYERS: [(&str, &str); 3] = [
    (
        "deploy-config/compose/selfhost-installer/compose.installer.yml",
        "x-installer-defaults: &installer-defaults\n  init: true\nservices:\n  app:\n    <<: *installer-defaults\n    ports: !override [\"127.0.0.1:${MARTY_LOCAL_PORT:?}:8000\"]\n",
    ),
    (
        "deploy-config/compose/selfhost-installer/compose.runtime.yml",
        "services:\n  app:\n    depends_on: !reset {}\n  setup:\n    profiles: !override [setup]\n",
    ),
    (
        "deploy-config/compose/selfhost-installer/compose.bootstrap.yml",
        "services:\n  setup:\n    image: ${MARTY_INSTALLER_HELPER_IMAGE:?approved digest required}\n    command: [tls-finalize]\n    profiles: [setup]\n",
    ),
];

fn fixture(root: &Path) -> Options {
    let repo = root.join("source");
    fs::create_dir(&repo).unwrap();
    let mut assets = vec![
        "docker-compose.selfhost.prod.yml",
        "docker-compose.selfhost.bundle.override.yml",
        ".env.selfhost.production.example",
        "SELFHOST_BUNDLE.md",
    ];
    for name in &assets {
        fs::write(repo.join(name), "services: {}\n").unwrap();
    }
    for (path, text) in LAYERS {
        let file = repo.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, text).unwrap();
        assets.push(path);
    }
    let descriptor = repo.join("deploy-config/bundles/selfhost.json");
    fs::create_dir_all(descriptor.parent().unwrap()).unwrap();
    fs::write(descriptor, json!({"assets": assets}).to_string()).unwrap();
    Options {
        repo,
        output: root.join("bundle"),
        archive: Some(root.join("bundle.zip")),
        replace: false,
    }
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
fn installer_layers_are_explicit_assets_not_flattened_render_inputs() {
    let descriptor: Value = serde_json::from_str(include_str!(
        "../../../../deploy-config/bundles/selfhost.json"
    ))
    .unwrap();
    let assets = descriptor["assets"].as_array().unwrap();
    let rendered = descriptor["render"]["compose_files"].as_array().unwrap();
    for (path, _) in LAYERS {
        assert_eq!(
            assets
                .iter()
                .filter(|value| value.as_str() == Some(path))
                .count(),
            1
        );
        assert!(!rendered.iter().any(|value| value.as_str() == Some(path)));
    }
    assert_eq!(descriptor["render"]["output_file"], "docker-compose.yml");
    assert_eq!(rendered.len(), 2);
}

#[test]
fn installer_layers_preserve_exact_bytes_and_marker_zip_coverage() {
    let root = tempfile::tempdir().unwrap();
    let options = fixture(root.path());
    let result = package(&options, render).unwrap();
    let marker: Value =
        serde_json::from_slice(&fs::read(result.output.join(MARKER)).unwrap()).unwrap();
    let mut zip = zip::ZipArchive::new(fs::File::open(result.archive.unwrap()).unwrap()).unwrap();
    for (path, expected) in LAYERS {
        assert_eq!(
            fs::read(result.output.join(path)).unwrap(),
            expected.as_bytes()
        );
        assert_eq!(
            marker["files"][path],
            format!("{:x}", Sha256::digest(expected.as_bytes()))
        );
        let mut archived = Vec::new();
        zip.by_name(&format!("bundle/{path}"))
            .unwrap()
            .read_to_end(&mut archived)
            .unwrap();
        assert_eq!(archived, expected.as_bytes());
    }
    assert!(result.output.join("docker-compose.yml").is_file());
    assert!(!result
        .output
        .join("docker-compose.selfhost.prod.yml")
        .exists());
    assert!(!result
        .output
        .join("docker-compose.selfhost.bundle.override.yml")
        .exists());
}

#[test]
fn installer_layer_changes_are_detected_and_preserved_on_replacement() {
    for (path, _) in LAYERS {
        let root = tempfile::tempdir().unwrap();
        let mut options = fixture(root.path());
        options.archive = None;
        package(&options, render).unwrap();
        fs::write(options.output.join(path), "operator edit\n").unwrap();
        options.replace = true;
        assert!(package(&options, render).unwrap_err().contains("modified"));
        assert_eq!(
            fs::read_to_string(options.output.join(path)).unwrap(),
            "operator edit\n"
        );
    }
}

#[test]
fn missing_installer_layer_refuses_publication() {
    for (path, _) in LAYERS {
        let root = tempfile::tempdir().unwrap();
        let options = fixture(root.path());
        fs::remove_file(options.repo.join(path)).unwrap();
        assert!(package(&options, render).is_err());
        assert!(!options.output.exists());
        assert!(!options.archive.as_ref().unwrap().exists());
    }
}

#[test]
fn declarative_setup_jobs_retain_narrow_authority_and_do_not_join_restart() {
    let document: serde_yaml::Value = serde_yaml::from_str(include_str!(
        "../../../../deploy-config/compose/selfhost-installer/compose.bootstrap.yml"
    ))
    .unwrap();
    let common = &document["x-installer-job"];
    assert_eq!(common["profiles"][0].as_str(), Some("setup"));
    assert_eq!(common["mem_limit"].as_str(), Some("1g"));
    assert_eq!(common["restart"].as_str(), Some("no"));
    assert_eq!(common["init"].as_bool(), Some(true));
    assert_eq!(common["read_only"].as_bool(), Some(true));
    assert_eq!(
        common["security_opt"][0].as_str(),
        Some("no-new-privileges:true")
    );
    for role in [
        "installer-keycloak",
        "installer-tls",
        "installer-ingress-provision",
        "installer-renewal",
        "installer-generation",
    ] {
        let service = &document["services"][role];
        assert_eq!(&service["<<"], common);
        assert!(service.get("container_name").is_none());
        assert!(service.get("ports").is_none());
        for mount in service["volumes"].as_sequence().unwrap() {
            assert_eq!(mount["bind"]["create_host_path"].as_bool(), Some(false));
        }
    }
    let generation = &document["services"]["installer-generation"];
    assert!(!generation["volumes"]
        .as_sequence()
        .unwrap()
        .iter()
        .any(|v| v["target"].as_str() == Some("/input/root.token")));
    assert_eq!(
        generation["command"][0].as_str(),
        Some("installer-generation-provision-transfer")
    );
}
