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
    let installation_id = "12345678-1234-4234-8234-123456789abc";
    let project = "marty-install-12345678123442348234123456789abc".to_owned();
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
    let mut plan = installer_application_model::prepare(
        &model,
        &images,
        &ApplicationModelParameters {
            installation: installation.clone(),
            bundle: bundle.clone(),
            compose_project: project.clone(),
            openbao_network_name: format!("{project}-bao_default"),
            openbao_network_id: "d".repeat(64),
            origin: parameters.origin.clone(),
        },
    )
    .expect("actual normalized canonical Compose must satisfy installer admission");
    assert_eq!(plan.selected_services.len(), 28);
    marty_deployment_catalog::installer_ingress_model::add(
        &mut plan,
        &installation,
        installation_id,
        &parameters.origin,
        &images["gateway"],
    )
    .unwrap();
    assert_eq!(plan.selected_services.len(), 29);
    assert!(!plan.installation_ready);
    let order = marty_deployment_catalog::installer_application_graph::startup_order(
        &plan.model,
        &plan.selected_services,
    )
    .unwrap();
    assert_eq!(order.len(), 30);
    assert_eq!(order[4], "kms-initialize");
    assert_eq!(
        order[..4]
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        [
            "postgres",
            "redis",
            "revocation-profile-migrate",
            "db-migrate"
        ]
        .into_iter()
        .collect()
    );
    for (role, spec) in plan.model["services"].as_object().unwrap() {
        if let Some(position) = order.iter().position(|s| s == role) {
            if let Some(deps) = spec["depends_on"].as_object() {
                for peer in deps.keys() {
                    assert!(order.iter().position(|s| s == peer).unwrap() < position);
                }
            }
        }
    }
    let reject = |model: &Value, selected: &[String]| {
        assert!(
            marty_deployment_catalog::installer_application_graph::startup_order(model, selected)
                .is_err()
        );
    };
    let mut bad = plan.model.clone();
    bad["services"]["postgres"]["depends_on"] =
        serde_json::json!({"redis":{"condition":"service_healthy"}});
    bad["services"]["redis"]["depends_on"] =
        serde_json::json!({"postgres":{"condition":"service_healthy"}});
    reject(&bad, &plan.selected_services);
    bad = plan.model.clone();
    bad["services"]["kms-initialize"]["depends_on"]["db-migrate"]["condition"] =
        serde_json::json!("service_started");
    reject(&bad, &plan.selected_services);
    bad = plan.model.clone();
    bad["services"]["postgres"]["healthcheck"]["disable"] = serde_json::json!(true);
    reject(&bad, &plan.selected_services);
    reject(&plan.model, &plan.selected_services[1..]);
    let mut duplicate = plan.selected_services.clone();
    duplicate[0] = duplicate[1].clone();
    reject(&plan.model, &duplicate);
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
    for mount in roundtrip_expected["services"]["installer-ingress"]["volumes"]
        .as_array_mut()
        .unwrap()
    {
        assert_eq!(mount["bind"], serde_json::json!({"create_host_path":false}));
        mount["bind"] = serde_json::json!({});
    }
    for (role, service) in normalized["services"].as_object().unwrap() {
        if role == "installer-ingress" {
            assert_eq!(service["ports"], plan.model["services"][role]["ports"]);
            assert_eq!(service["ports"][0]["host_ip"], "127.0.0.1");
            assert_eq!(service["ports"][0]["published"], "18443");
        } else {
            assert!(service.get("ports").is_none(), "published {role}");
        }
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
            "cap_drop",
            "read_only",
            "security_opt",
            "labels",
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
    // Model-only generation selection: hashes below are synthetic. No candidate
    // credentials are minted/read, and no filesystem binding proof is claimed.
    use marty_deployment_catalog::installer_generation_binding::{
        self, GenerationBinding, GenerationFile, GenerationSource,
    };
    let renewable = marty_deployment_catalog::installer_renewal_bootstrap::current_inputs();
    let mut referenced = std::collections::BTreeSet::new();
    for role in &order {
        let service = &plan.model["services"][role];
        for reference in service["secrets"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            referenced.insert(reference["source"].as_str().unwrap().to_owned());
        }
        for mount in service["volumes"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            if mount["type"] != "bind" {
                continue;
            }
            let path = PathBuf::from(mount["source"].as_str().unwrap().replace("$$", "$"));
            if path.parent() == Some(installation.join("secrets").as_path()) {
                assert_eq!(mount["read_only"], true);
                referenced.insert(path.file_name().unwrap().to_str().unwrap().to_owned());
            }
        }
    }
    assert!(renewable.is_subset(&referenced));
    assert!(referenced.contains("operator_bootstrap_password"));
    assert!(referenced.contains("installer_ingress_tls_kms_token"));
    assert!(referenced.contains("openbao_bootstrap_token"));
    assert!(!referenced.contains("cloudflare_tunnel_token"));
    let binding = GenerationBinding {
        schema: "elevenid.installer-application-generation/v1".into(),
        installation_id: installation_id.into(),
        engine_id: "synthetic-parser-only-engine".into(),
        network_id: plan.expected_network_id.clone(),
        generation_receipt_sha256: "e".repeat(64),
        files: referenced
            .into_iter()
            .map(|name| {
                let source = if renewable.contains(&name) {
                    GenerationSource::Candidate
                } else {
                    GenerationSource::Original
                };
                (
                    name,
                    GenerationFile {
                        source,
                        sha256: "f".repeat(64),
                        size: 32,
                        source_mode: 0o444,
                        mode: 0o444,
                    },
                )
            })
            .collect(),
        activated: false,
        root_retired: false,
        installation_ready: false,
    };
    let selected_before = plan.selected_services.clone();
    installer_generation_binding::apply_model(&installation, &binding, &mut plan).unwrap();
    installer_generation_binding::verify_model(&installation, &binding, &plan).unwrap();
    assert_eq!(plan.selected_services, selected_before);
    assert_eq!(plan.model["services"].as_object().unwrap().len(), 30);
    assert_eq!(
        marty_deployment_catalog::installer_application_graph::startup_order(
            &plan.model,
            &plan.selected_services
        )
        .unwrap(),
        order
    );
    let canonical_env = fs::read(bundle.join("application.env")).unwrap();
    let selected_env =
        installer_application_env::select_generation(&canonical_env, &installation).unwrap();
    fs::write(bundle.join("application-generation.env"), selected_env).unwrap();
    fs::write(
        bundle.join("installer-generation-compose.json"),
        marty_deployment_catalog::installer_application::compose_document(&plan.model).unwrap(),
    )
    .unwrap();
    let selected_normalized: Value = serde_json::from_str(&compose(
        &bundle,
        &executable,
        &[
            "--project-name",
            &project,
            "--env-file",
            "application-generation.env",
            "-f",
            "installer-generation-compose.json",
            "--profile",
            "*",
            "config",
            "--format",
            "json",
        ],
    ))
    .unwrap();
    assert_eq!(
        selected_normalized["secrets"], plan.model["secrets"],
        "generation secret paths must survive Compose interpolation exactly"
    );
    let mut expected_networks = plan.model["networks"].clone();
    // This plugin emits the same empty IPAM normalization as canonical config.
    if selected_normalized["networks"]["default"]
        .get("ipam")
        .is_some()
    {
        assert_eq!(
            selected_normalized["networks"]["default"]["ipam"],
            serde_json::json!({})
        );
        expected_networks["default"]["ipam"] = serde_json::json!({});
    }
    assert_eq!(selected_normalized["networks"], expected_networks);
    assert_eq!(selected_normalized["volumes"], plan.model["volumes"]);
    assert_eq!(
        selected_normalized["services"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<std::collections::BTreeSet<_>>(),
        plan.model["services"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<std::collections::BTreeSet<_>>()
    );
    let mut selected_expected = plan.model.clone();
    for role in ["edge", "installer-ingress"] {
        for mount in selected_expected["services"][role]["volumes"]
            .as_array_mut()
            .unwrap()
        {
            if mount["bind"] == serde_json::json!({"create_host_path":false}) {
                mount["bind"] = serde_json::json!({});
            }
        }
    }
    for (role, service) in selected_normalized["services"].as_object().unwrap() {
        for field in [
            "image",
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
            "cap_drop",
            "read_only",
            "security_opt",
            "labels",
            "ports",
        ] {
            assert_eq!(
                service[field], selected_expected["services"][role][field],
                "generation execution field changed: {role}.{field}"
            );
        }
    }
    let normalized_plan = installer_application_model::ApplicationModelPlan {
        model: selected_normalized,
        selected_services: plan.selected_services.clone(),
        expected_network_id: plan.expected_network_id.clone(),
        installation_ready: false,
    };
    installer_generation_binding::verify_model(&installation, &binding, &normalized_plan).unwrap();
}
