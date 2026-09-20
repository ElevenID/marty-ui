//! One actual CLI/ZIP/extraction owner shared by packaging and runtime gates.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

// Independent filesystem inventory: None denotes a directory, including empty
// directories and the root. Do not reuse the implementation's ownership marker.
pub(super) fn inventory(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
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

pub(super) fn assert_descriptor_inventory(repo: &Path, output: &Path) {
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

pub(super) fn assert_contained_references(root: &Path, rendered: &str) {
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

pub(super) struct ExtractedBundle {
    owned: tempfile::TempDir,
    pub(super) output: PathBuf,
    pub(super) extracted: PathBuf,
    verified_inventory: BTreeMap<PathBuf, Option<Vec<u8>>>,
}
impl ExtractedBundle {
    // This shared support module is also compiled by the issuance image-loader
    // gate, which must use create_with to bracket the child operation record.
    #[allow(dead_code)]
    pub(super) fn create(repo: &Path, cli: Command) -> Self {
        Self::create_with(repo, cli, |command| command.output().unwrap())
    }
    pub(super) fn create_with(
        repo: &Path,
        mut cli: Command,
        execute: impl FnOnce(&mut Command) -> std::process::Output,
    ) -> Self {
        let owned = tempfile::tempdir().unwrap();
        let output = owned.path().join("customer-bundle");
        let archive = owned.path().join("distribution");
        cli.arg("--repo-root")
            .arg(repo)
            .arg("--output-dir")
            .arg(&output)
            .arg("--archive")
            .arg(&archive)
            .current_dir(owned.path());
        let result = execute(&mut cli);
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
        assert_descriptor_inventory(repo, &output);
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
        let verified_inventory = inventory(&output);
        Self {
            owned,
            output,
            extracted,
            verified_inventory,
        }
    }
    pub(super) fn directory(&self) -> &Path {
        self.owned.path()
    }
    /// The runtime host owns the enclosing scratch until resource recovery has
    /// completed. Child unwinding must not remove assets still mounted there.
    pub(super) fn retain_for_parent(&mut self, parent: &Path) {
        assert!(self.owned.path().starts_with(parent));
        assert_ne!(self.owned.path(), parent);
        self.owned.disable_cleanup(true);
    }
    pub(super) fn verify_unchanged(&self) {
        assert_eq!(inventory(&self.extracted), self.verified_inventory);
        assert_eq!(inventory(&self.output), self.verified_inventory);
    }
}

#[test]
fn jointly_mutated_verified_bundle_is_refused() {
    let owned = tempfile::tempdir().unwrap();
    let output = owned.path().join("output");
    let extracted = owned.path().join("extracted");
    for directory in [&output, &extracted] {
        fs::create_dir(directory).unwrap();
        fs::write(directory.join("asset"), b"verified-original").unwrap();
    }
    let fixture = ExtractedBundle {
        verified_inventory: inventory(&output),
        owned,
        output,
        extracted,
    };
    fixture.verify_unchanged();
    for directory in [&fixture.output, &fixture.extracted] {
        fs::write(directory.join("asset"), b"jointly-changed").unwrap();
    }
    assert_eq!(inventory(&fixture.output), inventory(&fixture.extracted));
    assert!(std::panic::catch_unwind(|| fixture.verify_unchanged()).is_err());
    for directory in [&fixture.output, &fixture.extracted] {
        fs::write(directory.join("asset"), b"verified-original").unwrap();
    }
    fixture.verify_unchanged();
}

#[test]
fn extracted_inputs_survive_child_unwind_until_parent_removes_scratch() {
    let parent = tempfile::tempdir().unwrap();
    let owned = tempfile::tempdir_in(parent.path()).unwrap();
    let root = owned.path().to_owned();
    let output = root.join("output");
    let extracted = root.join("extracted");
    fs::create_dir(&output).unwrap();
    fs::create_dir(&extracted).unwrap();
    let mut fixture = ExtractedBundle {
        owned,
        verified_inventory: inventory(&output),
        output,
        extracted,
    };
    fixture.retain_for_parent(parent.path());
    assert!(std::panic::catch_unwind(move || {
        let _fixture = fixture;
        panic!("controlled child unwind");
    })
    .is_err());
    assert!(root.is_dir());
    parent.close().unwrap();
    assert!(!root.exists());
}
