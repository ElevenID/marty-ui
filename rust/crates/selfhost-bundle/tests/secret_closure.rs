use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};

fn check(root: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_check-selfhost-secret-closure"))
        .current_dir(root)
        .env_clear()
        .args([
            "--compose",
            "compose.json",
            "--catalog",
            "catalog.json",
            "--stack",
            "stack.json",
            "--example-dir",
            "examples",
        ])
        .output()
        .unwrap()
}

#[test]
fn arbitrary_install_paths_preserve_positive_and_negative_secret_closure() {
    for mutation in [
        "valid",
        "object-reference",
        "unknown",
        "unreferenced",
        "catalog-missing",
        "catalog-duplicate",
        "required-mismatch",
        "required-duplicate",
        "required-not-declared",
        "wrong-path",
        "missing-example",
        "directory-example",
        "bad-service",
        "bad-reference",
        "bad-declaration",
        "non-name",
        "traversal",
    ] {
        let owned = tempfile::tempdir().unwrap();
        let root = owned.path();
        fs::create_dir(root.join("examples")).unwrap();
        for name in ["required", "optional"] {
            fs::write(
                root.join("examples").join(name),
                "secret-value-must-never-appear",
            )
            .unwrap();
        }
        let mut compose = json!({"services":{"app":{"secrets":["required","optional"]}},"secrets":{
            "required":{"file":"${SELFHOST_SECRET_DIR:?SELFHOST_SECRET_DIR must be set}/required"},
            "optional":{"file":"${SELFHOST_SECRET_DIR:?SELFHOST_SECRET_DIR must be set}/optional"}}});
        let mut catalog = json!({"secrets":{
            "required":{"compose_secret":"required","required_for":["selfhost-production"]},
            "optional":{"compose_secret":"optional","required_for":[],"allow_empty":true}}});
        let mut stack = json!({"required_secrets":["required"]});
        match mutation {
            "object-reference" => {
                compose["services"]["app"]["secrets"] =
                    json!([{"source":"required"},{"source":"optional"}])
            }
            "unknown" => compose["services"]["app"]["secrets"] = json!(["required", "unknown"]),
            "unreferenced" => compose["services"]["app"]["secrets"] = json!(["required"]),
            "catalog-missing" => {
                catalog["secrets"]
                    .as_object_mut()
                    .unwrap()
                    .remove("optional");
            }
            "catalog-duplicate" => {
                catalog["secrets"]["optional"]["compose_secret"] = json!("required")
            }
            "required-mismatch" => stack["required_secrets"] = json!(["optional"]),
            "required-duplicate" => stack["required_secrets"] = json!(["required", "required"]),
            "required-not-declared" => {
                catalog["secrets"]["absent"] =
                    json!({"compose_secret":"absent","required_for":["selfhost-production"]});
                stack["required_secrets"] = json!(["required", "absent"]);
            }
            "wrong-path" => {
                compose["secrets"]["required"]["file"] = json!("/shared/operator-secret")
            }
            "missing-example" => fs::remove_file(root.join("examples/optional")).unwrap(),
            "directory-example" => {
                fs::remove_file(root.join("examples/optional")).unwrap();
                fs::create_dir(root.join("examples/optional")).unwrap();
            }
            "bad-service" => compose["services"]["app"] = Value::Null,
            "bad-reference" => compose["services"]["app"]["secrets"] = json!([42]),
            "bad-declaration" => compose["secrets"]["required"] = Value::Null,
            "non-name" => stack["required_secrets"] = json!([42]),
            "traversal" => {
                compose["services"]["app"]["secrets"] = json!(["required", "../outside"]);
                compose["secrets"]
                    .as_object_mut()
                    .unwrap()
                    .remove("optional");
                compose["secrets"]["../outside"] = json!({"file":"${SELFHOST_SECRET_DIR:?SELFHOST_SECRET_DIR must be set}/../outside"});
                catalog["secrets"]["optional"]["compose_secret"] = json!("../outside");
                fs::write(root.join("outside"), "metadata outside example directory").unwrap();
            }
            _ => (),
        }
        for (name, value) in [
            ("compose.json", compose),
            ("catalog.json", catalog),
            ("stack.json", stack),
        ] {
            fs::write(root.join(name), serde_json::to_vec(&value).unwrap()).unwrap();
        }
        let output = check(root);
        assert_eq!(
            output.status.success(),
            matches!(mutation, "valid" | "object-reference"),
            "{mutation}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("secret-value"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-value"));
        if output.status.success() {
            let receipt: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                receipt,
                json!({"schema":"marty.selfhost-install-secret-closure/v1","qualification":"unqualified","declared_secret_names":["optional","required"],"required_secret_names":["required"]})
            );
        }
        #[cfg(unix)]
        if mutation == "valid" {
            fs::remove_file(root.join("examples/optional")).unwrap();
            std::os::unix::fs::symlink("required", root.join("examples/optional")).unwrap();
            assert!(!check(root).status.success());
        }
    }
}

#[test]
fn current_source_has_closed_secret_ownership() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap();
    let result = marty_selfhost_bundle::secret_closure::validate(
        &root.join("docker-compose.selfhost.prod.yml"),
        &root.join("deploy-config/catalog/secrets.json"),
        &root.join("deploy-config/stacks/selfhost-production.json"),
        &root.join("docker/secrets/selfhost.example"),
    )
    .unwrap();
    for name in [
        "flow_webhook_secret",
        "notification_webhook_secret",
        "notification_applicant_event_token",
        "notification_openbao_token",
    ] {
        assert!(result["required_secret_names"]
            .as_array()
            .unwrap()
            .contains(&json!(name)));
    }
}
