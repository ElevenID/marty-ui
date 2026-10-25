//! Actual Compose parser/merger compatibility, without a Docker daemon.
//! Run explicitly with MARTY_INSTALLER_COMPOSE_EXECUTABLE pointing to the
//! standalone pinned Compose plugin. This does not qualify running containers.
#![cfg(target_os = "linux")]
use marty_deployment_catalog::{
    installer_application_env::{self, ApplicationParameters},
    installer_application_model::{self, ApplicationModelParameters},
};
use marty_selfhost_bundle::{process, transform};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

fn compose(root: &Path, executable: &OsString, args: &[&str]) -> String {
    process::compose(
        root,
        &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        Some(executable),
    )
    .expect("standalone Compose config must succeed")
}
#[test]
#[ignore = "requires explicit MARTY_INSTALLER_COMPOSE_EXECUTABLE; read-only real Compose parser test"]
fn actual_source_compose_matches_installer_application_contract() {
    let executable = std::env::var_os("MARTY_INSTALLER_COMPOSE_EXECUTABLE")
        .expect("set the standalone Compose executable explicitly");
    assert!(Path::new(&executable).is_absolute());
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let owned = tempfile::tempdir().unwrap();
    let installation = owned.path().join("install $literal #path");
    let bundle = installation.join("bundle/selfhost-prepared");
    fs::create_dir_all(&bundle).unwrap();
    for name in [
        "docker-compose.selfhost.prod.yml",
        "docker-compose.selfhost.bundle.override.yml",
        "docker-compose.service.issuance-native-runtime.yml",
        ".env.selfhost.production.example",
    ] {
        let source = fs::read(repo.join(name)).unwrap();
        fs::write(bundle.join(name), &source).unwrap();
        assert_eq!(fs::read(bundle.join(name)).unwrap(), source);
    }
    // This is the actual package renderer's source/override/no-interpolate
    // contract. No service fixture is derived from the admission constants.
    let initial_args = [
        "--env-file",
        ".env.selfhost.production.example",
        "-f",
        "docker-compose.selfhost.prod.yml",
        "-f",
        "docker-compose.selfhost.bundle.override.yml",
        "--profile",
        "*",
        "config",
        "--no-interpolate",
        "--no-env-resolution",
    ];
    let source = compose(&bundle, &executable, &initial_args);
    let mut json_args = initial_args.to_vec();
    json_args.extend(["--format", "json"]);
    let source_model: Value =
        serde_json::from_str(&compose(&bundle, &executable, &json_args)).unwrap();
    let services = source_model["services"].as_object().unwrap();
    assert_eq!(services.len(), 32, "canonical source role closure changed");
    assert!(services.contains_key("kms-initialize") && services.contains_key("issuance-native"));
    let mut images: BTreeMap<String, String> = services
        .keys()
        .map(|role| {
            let repository = match role.as_str() {
                "keycloak" | "keycloak-configurator" => "keycloak",
                _ => "services",
            };
            (
                role.clone(),
                format!(
                    "ghcr.io/elevenid/marty-ui-oss/{repository}@sha256:{}",
                    "a".repeat(64)
                ),
            )
        })
        .collect();
    let stripped = transform::strip_build_blocks(&source);
    let relative = marty_selfhost_bundle::relativize(&stripped, &bundle).unwrap();
    let project_scoped = transform::restore_project_scoped_resources(&relative).unwrap();
    let packaged = transform::pin_service_images(&project_scoped, &images).unwrap();
    fs::write(bundle.join("docker-compose.yml"), &packaged).unwrap();
    images.insert(
        "openbao_didcomm_image".into(),
        format!(
            "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:{}",
            "b".repeat(64)
        ),
    );
    let example = fs::read_to_string(bundle.join(".env.selfhost.production.example")).unwrap();
    let tls = example
        .lines()
        .filter(|line| {
            line.split_once('=')
                .is_some_and(|(k, _)| k.contains("_TLS_KMS_KEY_"))
        })
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    let parameters = ApplicationParameters {
        installation: installation.clone(),
        version: "v1.2.3".into(),
        origin: "https://localhost:18443".into(),
        gateway_port: 18000,
        keycloak_port: 18180,
        edge_port: 19080,
        openbao_port: 18200,
    };
    let environment =
        installer_application_env::render(&example, &packaged, &tls, &parameters, &images).unwrap();
    fs::write(bundle.join("application.env"), environment.env_bytes).unwrap();
    let project = format!("marty-install-{}", "c".repeat(32));
    let rendered = compose(
        &bundle,
        &executable,
        &[
            "--project-name",
            &project,
            "--env-file",
            "application.env",
            "-f",
            "docker-compose.yml",
            "--profile",
            "*",
            "config",
            "--format",
            "json",
        ],
    );
    let model: Value = serde_json::from_str(&rendered).unwrap();
    let plan = installer_application_model::prepare(
        &model,
        &images,
        &ApplicationModelParameters {
            installation,
            bundle: bundle.clone(),
            compose_project: project.clone(),
            openbao_network_name: format!("{project}-bao_default"),
            openbao_network_id: "d".repeat(64),
            origin: parameters.origin,
        },
    )
    .expect("actual normalized canonical Compose must satisfy installer admission");
    assert_eq!(plan.selected_services.len(), 28);
    assert!(!plan.installation_ready);
    assert!(
        plan.model["services"]["issuance"]["environment"]["DATABASE_URL_TEMPLATE"]
            .as_str()
            .unwrap()
            .contains('$'),
        "actual source must exercise literal credential-variable interpolation"
    );
    fs::write(
        bundle.join("installer-compose.json"),
        marty_deployment_catalog::installer_application::compose_document(&plan.model).unwrap(),
    )
    .unwrap();
    // Reparse the exact execution artifact; Compose's JSON/YAML writer must not
    // reject the external network, scoped secret or generated template binding.
    let again = compose(
        &bundle,
        &executable,
        &[
            "--project-name",
            &project,
            "--env-file",
            "application.env",
            "-f",
            "installer-compose.json",
            "--profile",
            "*",
            "config",
            "--format",
            "json",
        ],
    );
    let normalized: Value = serde_json::from_str(&again).unwrap();
    assert_eq!(normalized["networks"]["default"]["external"], true);
    assert_eq!(
        normalized["networks"]["default"]["name"],
        format!("{project}-bao_default")
    );
    assert_eq!(
        normalized["secrets"], plan.model["secrets"],
        "all scoped secret declarations must roundtrip exactly"
    );
    // Compose omits the false create_host_path value on normalized output.
    // The execution document deliberately keeps explicit false on this new bind.
    let mut roundtrip_expected = plan.model.clone();
    for mount in roundtrip_expected["services"]["edge"]["volumes"]
        .as_array_mut()
        .unwrap()
    {
        if mount["target"] == "/etc/nginx/conf.d/default.conf.template" {
            assert_eq!(mount["bind"], serde_json::json!({"create_host_path":false}));
            mount["bind"] = serde_json::json!({});
        }
    }
    for (role, service) in normalized["services"].as_object().unwrap() {
        assert!(service.get("ports").is_none(), "published {role}");
        assert_eq!(service["image"], plan.model["services"][role]["image"]);
        for field in [
            "command",
            "entrypoint",
            "environment",
            "healthcheck",
            "volumes",
            "secrets",
            "depends_on",
            "profiles",
            "user",
            "restart",
            "pull_policy",
        ] {
            assert_eq!(
                service[field], roundtrip_expected["services"][role][field],
                "execution field changed on reparse: {role}.{field}"
            );
        }
    }
    assert_eq!(
        normalized["services"]["keycloak-configurator"]["environment"]
            ["MARTY_ORG_ADMIN_PASSWORD_FILE"],
        "/run/secrets/operator_bootstrap_password"
    );
}
