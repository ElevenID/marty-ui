//! Mandatory workspace gate: actual CLI, actual Compose, actual ZIP extraction.
//! Never starts services or resolves released image provenance.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[path = "support/resolved_selfhost_runtime.rs"]
mod resolved_selfhost_runtime;

// Independent filesystem inventory: None denotes a directory, including empty
// directories and the root. Do not reuse the implementation's ownership marker.
fn inventory(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn walk(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(!metadata.file_type().is_symlink());
        let relative = path.strip_prefix(root).unwrap().to_owned();
        if metadata.is_dir() {
            assert!(result.insert(relative, None).is_none());
            for entry in fs::read_dir(path).unwrap() {
                walk(root, &entry.unwrap().path(), result);
            }
        } else {
            assert!(metadata.is_file());
            assert!(result
                .insert(relative, Some(fs::read(path).unwrap()))
                .is_none());
        }
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result);
    result
}

fn repository() -> PathBuf {
    // Explicit additional qualification can select another reviewed source
    // revision; the mandatory default always qualifies this workspace's source.
    std::env::var_os("MARTY_SELFHOST_BUNDLE_TEST_REPO").map_or_else(
        || {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .ancestors()
                .nth(3)
                .unwrap()
                .to_owned()
        },
        PathBuf::from,
    )
}

fn assert_descriptor_inventory(repo: &Path, output: &Path) {
    let descriptor: serde_json::Value = serde_json::from_slice(
        &fs::read(repo.join("deploy-config/bundles/selfhost.json")).unwrap(),
    )
    .unwrap();
    let mut expected = BTreeMap::from([(PathBuf::new(), None)]);
    for asset in descriptor["assets"].as_array().unwrap() {
        let asset = Path::new(asset.as_str().unwrap());
        let source = repo.join(asset);
        if source.is_dir() {
            for (relative, bytes) in inventory(&source) {
                expected.insert(asset.join(relative), bytes);
            }
        } else {
            expected.insert(asset.to_owned(), Some(fs::read(source).unwrap()));
        }
        for parent in asset.ancestors().skip(1) {
            expected.entry(parent.to_owned()).or_insert(None);
        }
    }
    // Derive the consumed source closure independently from the original
    // descriptor/extends files, never from the generated output inventory.
    fn consume(repo: &Path, path: PathBuf, sources: &mut BTreeSet<PathBuf>) {
        if !sources.insert(path.clone()) {
            return;
        }
        let model: serde_yaml::Value =
            serde_yaml::from_slice(&fs::read(repo.join(&path)).unwrap()).unwrap();
        for service in model["services"].as_mapping().unwrap().values() {
            if let Some(file) = service["extends"]["file"].as_str() {
                consume(repo, path.parent().unwrap().join(file), sources);
            }
        }
    }
    let mut sources = BTreeSet::new();
    for input in descriptor["render"]["compose_files"].as_array().unwrap() {
        consume(repo, PathBuf::from(input.as_str().unwrap()), &mut sources);
    }
    for input in sources {
        assert!(expected.remove(&input).is_some());
    }
    let readme = expected.remove(Path::new("SELFHOST_BUNDLE.md")).unwrap();
    expected.insert(PathBuf::from("README.md"), readme);
    let actual = inventory(output);
    for generated in [
        descriptor["render"]["output_file"].as_str().unwrap(),
        marty_selfhost_bundle::MARKER,
    ] {
        let value = actual.get(Path::new(generated)).unwrap().clone();
        assert!(value.as_ref().is_some_and(|bytes| !bytes.is_empty()));
        assert!(expected.insert(PathBuf::from(generated), value).is_none());
    }
    assert_eq!(
        actual, expected,
        "all descriptor assets must survive except the explicit rename/render/marker deltas"
    );
}

fn assert_contained_references(root: &Path, rendered: &str) {
    fn reference(root: &Path, value: &str) -> String {
        // Compose config --no-interpolate may anchor an unresolved selector to
        // its working directory. Only this exact extracted-root prefix is allowed.
        let normalized = value.replace('\\', "/");
        let root = root.to_string_lossy().replace('\\', "/");
        let relative = normalized
            .strip_prefix(&format!("{root}/"))
            .unwrap_or(&normalized);
        relative.strip_prefix("./").unwrap_or(relative).to_owned()
    }
    fn local(root: &Path, value: &str) {
        let root = root.canonicalize().unwrap();
        let target = root
            .join(value)
            .canonicalize()
            .unwrap_or_else(|_| panic!("packaged synthetic reference must exist: {value}"));
        assert!(
            target.starts_with(root),
            "packaged reference escapes extracted root"
        );
    }
    fn operator(value: &str, key: &str) {
        let prefix = format!("${{{key}:?{key} must be set}}/");
        let suffix = value
            .strip_prefix(&prefix)
            .expect("only the explicit operator-owned selector is external");
        assert!(!suffix.is_empty());
        assert!(Path::new(suffix)
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_))));
    }
    let model: serde_yaml::Value = serde_yaml::from_str(rendered).unwrap();
    for category in ["configs", "secrets"] {
        if let Some(definitions) = model[category].as_mapping() {
            for definition in definitions.values() {
                if let Some(file) = definition["file"].as_str() {
                    let file = reference(root, file);
                    let file = file.as_str();
                    if category == "secrets" && file.starts_with("${SELFHOST_SECRET_DIR") {
                        operator(file, "SELFHOST_SECRET_DIR");
                    } else {
                        local(root, file);
                    }
                }
            }
        }
    }
    for service in model["services"].as_mapping().unwrap().values() {
        assert!(service.get("extends").is_none(), "bundle must be flattened");
        if let Some(files) = service["env_file"].as_sequence() {
            for file in files {
                local(
                    root,
                    file.as_str().or_else(|| file["path"].as_str()).unwrap(),
                );
            }
        }
        if let Some(volumes) = service["volumes"].as_sequence() {
            for volume in volumes {
                assert!(
                    volume.is_mapping(),
                    "rendered volumes must use canonical long form"
                );
                if volume["type"].as_str() == Some("bind") {
                    let source = reference(root, volume["source"].as_str().unwrap());
                    let source = source.as_str();
                    if source.starts_with("${SELFHOST_STATE_DIR") {
                        operator(source, "SELFHOST_STATE_DIR");
                    } else {
                        local(root, source);
                    }
                }
            }
        }
    }
}

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_package-selfhost-bundle"));
    command.env_clear().stdin(Stdio::null());
    for key in [
        "PATH",
        "SystemRoot",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "TEMP",
        "TMP",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    if let Some(executable) = std::env::var_os("MARTY_SELFHOST_BUNDLE_TEST_COMPOSE") {
        command.arg("--compose-executable").arg(executable);
    }
    command
}

fn assert_operator_bind_paths(repo: &Path, extracted: &Path) {
    let owned = tempfile::tempdir().unwrap();
    let env_file = owned.path().join("synthetic.env");
    let example = fs::read_to_string(extracted.join(".env.selfhost.production.example")).unwrap();
    let absolute = owned.path().join("state with spaces");
    let executable = std::env::var_os("MARTY_SELFHOST_BUNDLE_TEST_COMPOSE");
    for state in [
        absolute.to_string_lossy().replace('\\', "/"),
        "relative-state".into(),
        String::new(),
    ] {
        fs::write(&env_file, format!("{example}\nSELFHOST_STATE_DIR={state}\nSELFHOST_SECRET_DIR={}\nMARTY_ISSUANCE_IMAGE=synthetic.invalid/issuance@sha256:{}\nSELFHOST_IMAGE_TAG=synthetic-immutable-v1\nFLOW_CALLBACK_DESTINATIONS=synthetic-org|https://callback.example/result?nonce=__MARTY_TOKEN__\n", owned.path().join("unused-secrets").to_string_lossy().replace('\\', "/"), "a".repeat(64))).unwrap();
        for (root, files) in [
            (
                repo,
                vec![
                    "docker-compose.selfhost.prod.yml",
                    "docker-compose.selfhost.bundle.override.yml",
                ],
            ),
            (extracted, vec!["docker-compose.yml"]),
        ] {
            let mut args = vec![
                "--env-file".into(),
                env_file.to_string_lossy().into_owned(),
                "--project-name".into(),
                "operator-bind-fixture".into(),
            ];
            for file in files {
                args.extend(["-f".into(), file.into()]);
            }
            args.extend(["config".into(), "--format".into(), "json".into()]);
            let rendered =
                marty_selfhost_bundle::process::compose(root, &args, executable.as_ref());
            if state.is_empty() {
                assert!(
                    rendered.is_err(),
                    "Required state directory must remain required"
                );
                continue;
            }
            let model: serde_json::Value = serde_json::from_str(&rendered.unwrap()).unwrap();
            for service in ["postgres", "redis", "applicant"] {
                let binds: Vec<_> = model["services"][service]["volumes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|volume| volume["type"] == "bind")
                    .collect();
                let expected = if Path::new(&state).is_absolute() {
                    PathBuf::from(&state)
                } else {
                    root.join(&state)
                }
                .join(service);
                assert!(binds.iter().any(|volume| volume["source"].as_str().unwrap().replace('\\', "/") == expected.to_string_lossy().replace('\\', "/")), "Actual source/extracted operator bind must retain its absolute or root-relative meaning for {service}");
            }
        }
    }
}

#[test]
fn actual_cli_packages_and_renders_extracted_bundle_with_contained_asset_references() {
    let repo = repository();
    let owned = tempfile::tempdir().unwrap();
    let output = owned.path().join("customer-bundle");
    let archive = owned.path().join("distribution");
    let result = command()
        .arg("--repo-root")
        .arg(&repo)
        .arg("--output-dir")
        .arg(&output)
        .arg("--archive")
        .arg(&archive)
        .current_dir(owned.path())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "actual packager rejected synthetic source inputs: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(output.join("docker-compose.yml").is_file());
    assert!(output.join("README.md").is_file());
    assert!(!output.join("docker-compose.selfhost.prod.yml").exists());
    assert!(!output
        .join("docker-compose.selfhost.bundle.override.yml")
        .exists());
    assert!(!output.join("services/Dockerfile").exists());
    assert_descriptor_inventory(&repo, &output);
    let extraction = owned.path().join("extracted");
    fs::create_dir(&extraction).unwrap();
    let mut zip =
        zip::ZipArchive::new(fs::File::open(archive.with_extension("zip")).unwrap()).unwrap();
    let mut archived = BTreeMap::new();
    for index in 0..zip.len() {
        let mut member = zip.by_index(index).unwrap();
        let relative = member
            .enclosed_name()
            .expect("all emitted archive names are contained");
        assert!(relative.starts_with("customer-bundle"));
        let destination = extraction.join(&relative);
        let member_path = relative.strip_prefix("customer-bundle").unwrap().to_owned();
        if member.is_dir() {
            assert!(archived.insert(member_path, None).is_none());
            fs::create_dir_all(&destination).unwrap();
            continue;
        }
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        let mut bytes = Vec::new();
        member.read_to_end(&mut bytes).unwrap();
        assert!(archived.insert(member_path, Some(bytes.clone())).is_none());
        fs::write(&destination, &bytes).unwrap();
        assert_eq!(
            bytes,
            fs::read(
                output.join(
                    destination
                        .strip_prefix(extraction.join("customer-bundle"))
                        .unwrap()
                )
            )
            .unwrap()
        );
    }
    assert_eq!(
        archived,
        inventory(&output),
        "ZIP and output must have exact bidirectional membership and bytes"
    );
    let extracted = extraction.join("customer-bundle");
    assert_eq!(inventory(&extracted), inventory(&output));
    let text = fs::read_to_string(extracted.join("docker-compose.yml")).unwrap();
    assert_contained_references(&extracted, &text);
    assert!(!text.contains(&repo.to_string_lossy().to_string()));
    assert!(
        !text.contains(".selfhost-stage-"),
        "staged paths remain in fields: {:?}",
        text.lines()
            .filter(|line| line.contains(".selfhost-stage-"))
            .map(|line| line.split(':').next().unwrap_or("unknown").trim())
            .collect::<Vec<_>>()
    );
    // The extracted model can resolve only its own packaged runtime assets.
    let args = vec![
        "--env-file".into(),
        ".env.selfhost.production.example".into(),
        "-f".into(),
        "docker-compose.yml".into(),
        "config".into(),
        "--no-interpolate".into(),
    ];
    let rendered = marty_selfhost_bundle::process::compose(
        &extracted,
        &args,
        std::env::var_os("MARTY_SELFHOST_BUNDLE_TEST_COMPOSE").as_ref(),
    )
    .unwrap();
    marty_selfhost_bundle::transform::validate_strict(&rendered).unwrap();
    assert_contained_references(&extracted, &rendered);
    assert_operator_bind_paths(&repo, &extracted);
    resolved_selfhost_runtime::qualify(&repo, &extracted);
    assert_eq!(inventory(&extracted), inventory(&output));
    // Rejected replacement cannot destroy a prior package or overwrite its ZIP.
    let retry = command()
        .arg("--repo-root")
        .arg(&repo)
        .arg("--output-dir")
        .arg(&output)
        .current_dir(owned.path())
        .output()
        .unwrap();
    assert!(!retry.status.success());
    assert!(output.join("docker-compose.yml").is_file());
}

#[test]
fn actual_cli_keeps_archive_optional_and_rejects_unknown_arguments() {
    let owned = tempfile::tempdir().unwrap();
    let output = owned.path().join("without-archive");
    let mut invocation = command();
    // Literal tilde reaches the CLI; no shell expansion and no operator home writes.
    #[cfg(windows)]
    invocation.env("USERPROFILE", owned.path());
    #[cfg(not(windows))]
    invocation.env("HOME", owned.path());
    let result = invocation
        .arg("--repo-root")
        .arg(repository())
        .arg("--output-dir")
        .arg("~/without-archive")
        .current_dir(owned.path())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_descriptor_inventory(&repository(), &output);
    assert_eq!(fs::read_dir(owned.path()).unwrap().count(), 1);
    assert!(inventory(owned.path())
        .keys()
        .all(|path| path.extension().is_none_or(|extension| extension != "zip")));
    let result = command().arg("--help").output().unwrap();
    assert!(result.status.success());
    assert!(String::from_utf8(result.stdout)
        .unwrap()
        .contains("--archive ZIP_BASENAME"));
    let result = command().arg("--unknown-option").output().unwrap();
    assert!(!result.status.success());
}

#[test]
fn reference_gate_rejects_checkout_missing_and_unapproved_operator_paths() {
    let owned = tempfile::tempdir().unwrap();
    let extracted = owned.path().join("extracted");
    fs::create_dir(&extracted).unwrap();
    fs::write(extracted.join("asset"), b"packaged").unwrap();
    fs::write(owned.path().join("outside"), b"not packaged").unwrap();
    for source in [
        "../outside",
        "missing",
        "${UNAPPROVED:?UNAPPROVED must be set}/asset",
        "${SELFHOST_STATE_DIR:?SELFHOST_STATE_DIR must be set}/../outside",
    ] {
        let model = serde_json::json!({"services":{"fixture":{"volumes":[{"type":"bind","source":source}]}}});
        assert!(std::panic::catch_unwind(|| assert_contained_references(
            &extracted,
            &model.to_string()
        ))
        .is_err());
    }
    let model = serde_json::json!({"services":{"fixture":{"volumes":[{"type":"bind","source":"./asset"}]}}});
    assert_contained_references(&extracted, &model.to_string());
    let model = serde_json::json!({"services":{"fixture":{"extends":{"file":"../outside","service":"fixture"}}}});
    assert!(std::panic::catch_unwind(|| assert_contained_references(
        &extracted,
        &model.to_string()
    ))
    .is_err());
}
