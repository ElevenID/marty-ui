use marty_selfhost_bundle::{package, transform, Options, MARKER};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

fn reference() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/selfhost-bundle-python-reference.json"
    ))
    .unwrap()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn contents(root: &Path) -> BTreeMap<String, String> {
    fn visit(root: &Path, dir: &Path, result: &mut BTreeMap<String, String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(root, &path, result);
            } else {
                result.insert(
                    path.strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/"),
                    hex(&fs::read(path).unwrap()),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}
fn fixture(root: &Path) -> Options {
    let repo = root.join("source");
    fs::create_dir(&repo).unwrap();
    let frozen = reference();
    let assets = frozen["staging"]["assets"].as_array().unwrap();
    for asset in assets {
        let asset = asset.as_str().unwrap();
        let path = repo.join(asset);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            path,
            if asset.ends_with(".bin") {
                b"\xff\x00".as_slice()
            } else {
                b"synthetic content\n".as_slice()
            },
        )
        .unwrap();
    }
    let manifest = repo.join("deploy-config/bundles/selfhost.json");
    fs::create_dir_all(manifest.parent().unwrap()).unwrap();
    fs::write(manifest, json!({"assets":assets}).to_string()).unwrap();
    Options {
        repo,
        output: root.join("bundle"),
        archive: Some(root.join("archive.zip")),
        replace: false,
    }
}
fn render(stage: &Path, args: &[String]) -> marty_selfhost_bundle::Result<String> {
    assert_eq!(
        json!(args),
        json!(
            reference()["staging"]["render_calls"][0]["argv"]
                .as_array()
                .unwrap()[2..]
        )
    );
    Ok(format!("services:\n  app:\n    build:\n      context: .\n    image: example:v1\n    volumes:\n      - type: bind\n        source: {}\n        target: /launch.sh\nsecrets:\n  operator:\n    file: {}/${{SECRET_DIR}}/key\n", stage.join("scripts/launch.sh").display(), stage.display()))
}

#[test]
fn original_eighteen_transformations_and_errors_remain_frozen() {
    let reference = reference();
    assert_eq!(reference["cases"].as_array().unwrap().len(), 18);
    for case in reference["cases"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        match case["function"].as_str().unwrap() {
            "strip_build_blocks" => {
                assert_eq!(json!(transform::strip_build_blocks(input)), case["value"])
            }
            "image_uses_mutable_tag" => assert_eq!(
                json!(transform::image_uses_mutable_tag(input)),
                case["value"]
            ),
            "validate_image_based_compose" => {
                match transform::validate_image_based_compose(input) {
                    Ok(()) => assert_eq!(case["value"], Value::Null),
                    Err(error) => assert_eq!(error, case["message"].as_str().unwrap()),
                }
            }
            _ => panic!("unknown reference case"),
        }
    }
}

#[test]
fn current_directory_asset_notation_preserves_original_path_behavior_and_safety() {
    assert_eq!(
        marty_selfhost_bundle::relative("./config/./asset").unwrap(),
        Path::new("config/asset")
    );
    for rejected in [
        "",
        ".",
        "./",
        "../asset",
        "config/../asset",
        "/asset",
        "C:/asset",
    ] {
        assert!(marty_selfhost_bundle::relative(rejected).is_err());
    }
    let owned = tempfile::tempdir().unwrap();
    let mut options = fixture(owned.path());
    let manifest_path = options.repo.join("deploy-config/bundles/selfhost.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    for asset in manifest["assets"].as_array_mut().unwrap() {
        *asset = json!(format!("./{}", asset.as_str().unwrap()));
    }
    fs::write(manifest_path, manifest.to_string()).unwrap();
    options.output = options.output.join(".");
    let published = package(&options, render).unwrap();
    assert_eq!(published.output.file_name().unwrap(), "bundle");
    let mut actual = contents(&published.output);
    actual.remove(MARKER).unwrap();
    assert_eq!(json!(actual), reference()["staging"]["directory_hex"]);
}

#[test]
fn actual_directory_and_zip_preserve_frozen_members_and_binary_content() {
    let root = tempfile::tempdir().unwrap();
    let options = fixture(root.path());
    let published = package(&options, render).unwrap();
    assert!(published.backup.is_none());
    let mut directory = contents(&options.output);
    assert!(directory.remove(MARKER).is_some());
    assert_eq!(json!(directory), reference()["staging"]["directory_hex"]);
    let mut zipped =
        zip::ZipArchive::new(fs::File::open(options.archive.unwrap()).unwrap()).unwrap();
    let mut members = BTreeMap::new();
    let mut directories = Vec::new();
    for i in 0..zipped.len() {
        let mut member = zipped.by_index(i).unwrap();
        if member.is_dir() {
            directories.push(member.name().to_owned());
            continue;
        }
        let name = member.name().to_owned();
        let mut bytes = Vec::new();
        member.read_to_end(&mut bytes).unwrap();
        members.insert(name, hex(&bytes));
        #[cfg(unix)]
        if member.name() == "bundle/scripts/launch.sh" {
            assert_eq!(member.unix_mode().unwrap() & 0o111, 0o111);
        }
    }
    assert!(members.remove(&format!("bundle/{MARKER}")).is_some());
    assert_eq!(json!(members), reference()["staging"]["archive_files_hex"]);
    directories.sort();
    assert_eq!(
        json!(directories),
        reference()["staging"]["archive_directories"]
    );
    assert!(!options
        .output
        .join("docker-compose.selfhost.prod.yml")
        .exists());
}

#[test]
fn existing_output_requires_verified_owned_replacement_and_retains_backup() {
    let root = tempfile::tempdir().unwrap();
    let mut options = fixture(root.path());
    options.archive = None;
    package(&options, render).unwrap();
    let original = contents(&options.output);
    assert!(package(&options, render)
        .unwrap_err()
        .contains("already exists"));
    assert_eq!(contents(&options.output), original);
    options.replace = true;
    let result = package(&options, render).unwrap();
    assert_eq!(contents(&result.backup.unwrap()), original);
    fs::write(options.output.join("README.md"), "operator edit").unwrap();
    let modified = contents(&options.output);
    assert!(package(&options, render).is_err());
    assert_eq!(contents(&options.output), modified);
}

#[test]
fn failure_before_publication_preserves_existing_bundle_and_archive_is_never_overwritten() {
    let root = tempfile::tempdir().unwrap();
    let mut options = fixture(root.path());
    package(&options, render).unwrap();
    let original = contents(&options.output);
    options.replace = true;
    assert!(package(&options, render).unwrap_err().contains("new path"));
    options.archive = None;
    assert!(package(&options, |_, _| Err("synthetic renderer failure".into())).is_err());
    assert_eq!(contents(&options.output), original);
    assert!(!fs::read_dir(root.path()).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".selfhost-stage-")));
}

#[test]
fn traversal_roots_overlap_and_unowned_replacement_fail_before_render() {
    for fault in [
        "repo",
        "ancestor",
        "archive-inside",
        "unowned",
        "asset-traversal",
        "asset-absolute",
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut options = fixture(root.path());
        match fault {
            "repo" => options.output = options.repo.clone(),
            "ancestor" => options.output = root.path().to_owned(),
            "archive-inside" => options.archive = Some(options.output.join("bad.zip")),
            "unowned" => {
                fs::create_dir(&options.output).unwrap();
                options.replace = true;
            }
            value => {
                let asset = if value == "asset-traversal" {
                    "../outside"
                } else {
                    "/outside"
                };
                fs::write(
                    options.repo.join("deploy-config/bundles/selfhost.json"),
                    json!({"assets":[asset]}).to_string(),
                )
                .unwrap();
            }
        }
        assert!(package(&options, |_, _| panic!(
            "must reject before render: {fault}"
        ))
        .is_err());
    }
}

#[test]
fn strict_validation_fixes_mutable_defaults_without_rejecting_valid_interpolation() {
    for image in [
        "example:${TAG:-latest}",
        "example:${TAG-prod}",
        "example:${TAG:-main}",
        "example:${TAG:-dev}",
    ] {
        assert!(
            transform::validate_strict(&format!("services:\n  a:\n    image: {image}\n")).is_err()
        );
    }
    for image in [
        "example:${TAG:?required}",
        "example:${TAG:-1.2.3}",
        "example@sha256:123",
        "${REGISTRY:-registry.example}/service:${TAG:?required}",
    ] {
        transform::validate_strict(&format!("services:\n  a:\n    image: {image}\n")).unwrap();
    }
}

#[test]
fn transitive_neutral_compose_sources_are_staged_then_removed_without_weakening_scan() {
    let root = tempfile::tempdir().unwrap();
    let options = fixture(root.path());
    let path = options.repo.join("docker-compose.selfhost.prod.yml");
    fs::write(&path, "services:\n  app:\n    extends:\n      file: docker-compose.service.issuance-native-runtime.yml\n      service: issuance-native\n").unwrap();
    fs::write(
        options
            .repo
            .join("docker-compose.service.issuance-native-runtime.yml"),
        "services:\n  issuance-native:\n    build:\n      context: .\n",
    )
    .unwrap();
    let manifest_path = options.repo.join("deploy-config/bundles/selfhost.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    manifest["assets"]
        .as_array_mut()
        .unwrap()
        .push(json!("docker-compose.service.issuance-native-runtime.yml"));
    fs::write(manifest_path, manifest.to_string()).unwrap();
    package(&options, |stage, args| {
        assert!(stage
            .join("docker-compose.service.issuance-native-runtime.yml")
            .is_file());
        render(stage, args)
    })
    .unwrap();
    assert!(!options
        .output
        .join("docker-compose.service.issuance-native-runtime.yml")
        .exists());
    for value in contents(&options.output).values() {
        assert!(!value.contains(&hex(b"build:")));
    }
}

#[cfg(unix)]
#[test]
fn symlink_sources_and_output_roots_are_rejected_without_following_them() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let options = fixture(root.path());
    let outside = root.path().join("outside");
    fs::write(&outside, "private").unwrap();
    let source = options.repo.join("config/example.bin");
    fs::remove_file(&source).unwrap();
    symlink(&outside, &source).unwrap();
    assert!(package(&options, render).is_err());
    assert_eq!(fs::read_to_string(outside).unwrap(), "private");
}

#[test]
fn output_paths_with_spaces_are_quoted_and_stay_relative() {
    let stage = PathBuf::from("/synthetic/stage");
    let actual =
        marty_selfhost_bundle::relativize("    source: /synthetic/stage/a folder/file\n", &stage)
            .unwrap();
    assert_eq!(actual, "    source: \"./a folder/file\"\n");
}

#[test]
fn decoded_images_full_reference_and_nested_defaults_keep_the_closed_tag_policy() {
    for image in [
        "example:latest",
        "example:latest@sha256:123",
        "${IMAGE:-registry:5000/example:latest}",
        "example:${TAG:-${VERSION:-prod}}",
        "example:latest${OPTIONAL:+-suffix}",
    ] {
        for quoted in [false, true] {
            let value = if quoted {
                serde_json::to_string(image).unwrap()
            } else {
                image.into()
            };
            assert!(
                transform::validate_strict(&format!("services:\n  app:\n    image: {value}\n"))
                    .is_err(),
                "{image}"
            );
        }
    }
    for image in [
        "${IMAGE:-registry:5000/example:1.2.3}",
        "example:${TAG:-${VERSION:-1.2.3}}",
        "${REGISTRY:-latest}/example:1.2.3",
        "example@sha256:123",
    ] {
        transform::validate_strict(&format!(
            "services:\n  app:\n    image: {}\n",
            serde_json::to_string(image).unwrap()
        ))
        .unwrap();
    }
}

#[test]
fn folded_and_list_first_paths_preserve_required_selectors_and_sibling_fields() {
    let input = "secrets:\n  key:\n    file: /stage/${SECRET_DIR:?SECRET_DIR\n        must be set}/key\nservices:\n  app:\n    volumes:\n      - source: /stage/scripts/start.sh\n        target: /app/start.sh\n        read_only: true\n";
    let output = marty_selfhost_bundle::relativize(input, Path::new("/stage")).unwrap();
    let result: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
    assert_eq!(
        result["secrets"]["key"]["file"].as_str().unwrap(),
        "${SECRET_DIR:?SECRET_DIR must be set}/key"
    );
    let volume = &result["services"]["app"]["volumes"][0];
    assert_eq!(volume["source"].as_str().unwrap(), "./scripts/start.sh");
    assert_eq!(volume["target"].as_str().unwrap(), "/app/start.sh");
    assert_eq!(volume["read_only"].as_bool(), Some(true));
}

#[test]
fn nested_outputs_and_empty_directories_survive_directory_and_zip_packaging() {
    let root = tempfile::tempdir().unwrap();
    let mut options = fixture(root.path());
    options.output = root.path().join("new/nested/bundle");
    options.archive = Some(root.path().join("archives/new/release.zip"));
    fs::create_dir(options.repo.join("empty")).unwrap();
    let manifest_path = options.repo.join("deploy-config/bundles/selfhost.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    manifest["assets"]
        .as_array_mut()
        .unwrap()
        .push(json!("empty"));
    fs::write(manifest_path, manifest.to_string()).unwrap();
    package(&options, render).unwrap();
    assert!(options.output.join("empty").is_dir());
    let mut archive =
        zip::ZipArchive::new(fs::File::open(options.archive.unwrap()).unwrap()).unwrap();
    assert!(archive.by_name("bundle/empty/").unwrap().is_dir());
}

#[cfg(unix)]
#[test]
fn readonly_file_metadata_and_script_execution_modes_are_preserved() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let options = fixture(root.path());
    fs::set_permissions(
        options.repo.join("config/example.bin"),
        fs::Permissions::from_mode(0o444),
    )
    .unwrap();
    fs::set_permissions(
        options.repo.join("scripts/launch.sh"),
        fs::Permissions::from_mode(0o444),
    )
    .unwrap();
    package(&options, render).unwrap();
    assert_eq!(
        fs::metadata(options.output.join("config/example.bin"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o444
    );
    assert_eq!(
        fs::metadata(options.output.join("scripts/launch.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
}
