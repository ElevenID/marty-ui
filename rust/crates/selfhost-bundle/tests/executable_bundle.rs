//! Mandatory workspace gate: actual CLI, actual Compose, actual ZIP extraction.
//! Never starts services or resolves released image provenance.
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[path = "support/extracted_bundle.rs"]
mod extracted_bundle;
#[path = "support/resolved_selfhost_runtime.rs"]
mod resolved_selfhost_runtime;
use extracted_bundle::{
    assert_contained_references, assert_descriptor_inventory, inventory, ExtractedBundle,
};

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
    let fixture = ExtractedBundle::create(&repo, command());
    let output = fixture.output.clone();
    let extracted = fixture.extracted.clone();
    assert_operator_bind_paths(&repo, &extracted);
    resolved_selfhost_runtime::qualify(&repo, &extracted);
    assert_eq!(inventory(&extracted), inventory(&output));
    // Rejected replacement cannot destroy a prior package or overwrite its ZIP.
    let retry = command()
        .arg("--repo-root")
        .arg(&repo)
        .arg("--output-dir")
        .arg(&output)
        .current_dir(fixture.directory())
        .output()
        .unwrap();
    assert!(!retry.status.success());
    assert!(output.join("docker-compose.yml").is_file());
    fixture.verify_unchanged();
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
