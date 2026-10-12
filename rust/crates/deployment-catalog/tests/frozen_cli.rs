use marty_deployment_catalog::Catalog;
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn matches_frozen_python_cli_cases() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let source = root.join("contracts/deployment-catalog-cli-behavior.json");
    let corpus: Value = serde_json::from_slice(&std::fs::read(source).unwrap()).unwrap();
    let root_display = root.to_string_lossy();
    let root_display = root_display.strip_prefix(r"\\?\").unwrap_or(&root_display);
    for case in corpus["cases"].as_array().unwrap() {
        let args = case["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect::<Vec<_>>();
        let output = Command::new(env!("CARGO_BIN_EXE_marty-deploy"))
            .args(["--repo-root", root_display])
            .args(&args)
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout)
            .unwrap()
            .replace(root_display, "$REPO_ROOT");
        let stderr = String::from_utf8(output.stderr)
            .unwrap()
            .replace(root_display, "$REPO_ROOT");
        assert_eq!(
            output.status.code().unwrap(),
            case["exit_code"].as_i64().unwrap() as i32,
            "args: {args:?}"
        );
        let expected_stdout = case["stdout"].as_str().unwrap();
        if args.first() == Some(&"bundle-assets") {
            assert_eq!(
                stdout.replace('\\', "/"),
                expected_stdout.replace('\\', "/"),
                "args: {args:?}"
            );
        } else {
            assert_eq!(stdout, expected_stdout, "args: {args:?}");
        }
        assert_eq!(stderr, case["stderr"].as_str().unwrap(), "args: {args:?}");
    }
}

#[test]
fn secret_metadata_selector_never_exposes_new_value_fields() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let mut catalog = Catalog::load(root).unwrap();
    let metadata = catalog
        .input_specs
        .get_mut("postgres_password")
        .unwrap()
        .as_object_mut()
        .unwrap();
    metadata.insert(
        "value".to_owned(),
        Value::String("private-sentinel".to_owned()),
    );
    assert_eq!(
        catalog
            .public_input_field("postgres_password", "env")
            .unwrap(),
        "POSTGRES_PASSWORD"
    );
    assert!(catalog
        .public_input_field("postgres_password", "value")
        .is_err());
}

#[test]
fn malformed_catalog_lists_fail_validation_before_operator_use() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let mut catalog = Catalog::load(root).unwrap();
    catalog
        .groups
        .insert("app".into(), Value::String("gateway".into()));
    assert!(catalog
        .validate()
        .unwrap_err()
        .contains("service group 'app' members must be an array of strings"));
    catalog
        .groups
        .insert("app".into(), Value::Array(vec![Value::from(1)]));
    assert!(catalog
        .validate()
        .unwrap_err()
        .contains("service group 'app' members must be an array of strings"));
}

#[test]
fn malformed_service_descriptor_fails_validation_before_operator_use() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let mut catalog = Catalog::load(root).unwrap();
    catalog
        .services
        .insert("gateway".into(), Value::String("bad".into()));
    assert!(catalog
        .validate()
        .unwrap_err()
        .contains("service 'gateway' descriptor must be an object"));
}

#[test]
fn malformed_truthy_service_group_fails_validation_before_operator_use() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let mut catalog = Catalog::load(root).unwrap();
    catalog
        .services
        .get_mut("gateway")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("group".into(), Value::from(123));
    assert!(catalog
        .validate()
        .unwrap_err()
        .contains("service 'gateway' group must be a string"));
}

#[test]
fn explicit_non_string_lifecycle_is_not_running() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let mut catalog = Catalog::load(root).unwrap();
    assert!(catalog
        .running_services("kubernetes-production", false)
        .unwrap()
        .contains(&"gateway".to_owned()));
    catalog
        .services
        .get_mut("gateway")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("lifecycle".into(), Value::Null);
    assert!(!catalog
        .running_services("kubernetes-production", false)
        .unwrap()
        .contains(&"gateway".to_owned()));
}

#[test]
fn malformed_metadata_descriptors_fail_validation_before_operator_use() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let mut catalog = Catalog::load(root).unwrap();
    catalog.input_specs.insert(
        "notification_webhook_secret".into(),
        Value::String("bad".into()),
    );
    catalog
        .artifacts
        .insert("production".into(), Value::Array(vec![]));
    catalog
        .stacks
        .insert("kubernetes-production".into(), Value::String("bad".into()));
    catalog
        .bundles
        .insert("selfhost".into(), Value::String("bad".into()));
    let error = catalog.validate().unwrap_err();
    assert!(error.contains("secret 'notification_webhook_secret' descriptor must be an object"));
    assert!(error.contains("artifact profile 'production' descriptor must be an object"));
    assert!(error.contains("stack 'kubernetes-production' descriptor must be an object"));
    assert!(error.contains("bundle 'selfhost' descriptor must be an object"));
}

#[test]
fn equals_style_options_match_frozen_spaced_options() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let root = root.to_string_lossy();
    let binary = env!("CARGO_BIN_EXE_marty-deploy");
    for (spaced, equals) in [
        (
            vec!["services", "--group", "app", "--field", "id"],
            vec!["services", "--group=app", "--field=id"],
        ),
        (
            vec!["secrets", "selfhost-production", "--field", "env"],
            vec!["secrets", "selfhost-production", "--field=env"],
        ),
    ] {
        let spaced_output = Command::new(binary)
            .args(["--repo-root", root.as_ref()])
            .args(spaced)
            .output()
            .unwrap();
        let equals_output = Command::new(binary)
            .arg(format!("--repo-root={root}"))
            .args(equals)
            .output()
            .unwrap();
        assert!(spaced_output.status.success());
        assert_eq!(equals_output.status.code(), spaced_output.status.code());
        assert_eq!(equals_output.stdout, spaced_output.stdout);
        assert_eq!(equals_output.stderr, spaced_output.stderr);
    }
}
