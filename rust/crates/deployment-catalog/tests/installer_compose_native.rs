//! Opt-in native Compose configuration checks. These invoke only version/config,
//! never a Docker lifecycle command. The actual component run is a separate gate.
#![cfg(target_os = "linux")]

use marty_deployment_catalog::installer_compose::COMPOSE_VERSION;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
};

struct PrivateFixture(Option<tempfile::TempDir>);
impl PrivateFixture {
    fn new() -> Self {
        Self(Some(
            tempfile::Builder::new()
                .prefix("marty-compose-native-")
                .tempdir()
                .expect("private native fixture must be created"),
        ))
    }
    fn path(&self) -> &Path {
        self.0.as_ref().unwrap().path()
    }
}
impl Drop for PrivateFixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Some(directory) = self.0.take() {
                eprintln!(
                    "Native Compose test evidence retained privately at {}",
                    directory.keep().display()
                );
            }
        }
    }
}
fn private_write(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("private native evidence file must be created");
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .expect("private native evidence must be persisted");
}

fn executable() -> OsString {
    let path = std::env::var_os("MARTY_INSTALLER_COMPOSE_EXECUTABLE")
        .expect("set the independently pinned standalone Compose executable");
    assert!(Path::new(&path).is_absolute());
    path
}
fn invoke(executable: &OsString, root: &Path, evidence: &Path, args: &[String]) -> String {
    static SEQUENCE: AtomicUsize = AtomicUsize::new(1);
    let prefix = format!(
        "compose-call-{:04}",
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    private_write(
        &evidence.join(format!("{prefix}-command.json")),
        &serde_json::to_vec_pretty(&serde_json::json!({"executable":Path::new(executable),
            "working_directory":root,"arguments":args,"config_only":true}))
        .unwrap(),
    );
    let output = Command::new(executable)
        .args(args)
        .current_dir(root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", root)
        .env("DOCKER_CONFIG", root)
        .env("XDG_CONFIG_HOME", root)
        .env("XDG_CACHE_HOME", root)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .output()
        .expect("native Compose process must start");
    let stdout_limit = 2 * 1024 * 1024;
    let stderr_limit = 1024 * 1024;
    private_write(
        &evidence.join(format!("{prefix}.stdout")),
        &output.stdout[..output.stdout.len().min(stdout_limit)],
    );
    private_write(
        &evidence.join(format!("{prefix}.stderr")),
        &output.stderr[..output.stderr.len().min(stderr_limit)],
    );
    private_write(&evidence.join(format!("{prefix}-result.json")),
        &serde_json::to_vec_pretty(&serde_json::json!({"exit_code":output.status.code(),
            "stdout_bytes":output.stdout.len(),"stderr_bytes":output.stderr.len(),
            "stdout_truncated":output.stdout.len()>stdout_limit,"stderr_truncated":output.stderr.len()>stderr_limit})).unwrap());
    assert!(
        output.status.success(),
        "native config failed; inspect the retained private invocation evidence"
    );
    assert!(
        output.stdout.len() <= stdout_limit && output.stderr.len() <= stderr_limit,
        "native output exceeded bounds; retained private evidence is truncated"
    );
    String::from_utf8(output.stdout).expect("Compose output must be UTF-8")
}
fn baseline(executable: &OsString, root: &Path) {
    let version = invoke(
        executable,
        root,
        root,
        &["version".into(), "--short".into()],
    );
    let version = version.trim().strip_prefix('v').unwrap_or(version.trim());
    assert!(version == COMPOSE_VERSION || version.starts_with(&format!("{COMPOSE_VERSION}+")));
}
fn config(
    executable: &OsString,
    root: &Path,
    files: &[PathBuf],
    env: &Path,
    profiles: &[&str],
    services: &[&str],
) -> Value {
    let mut args = vec![
        "--project-name".into(),
        format!("marty-install-{}", "a".repeat(32)),
        "--project-directory".into(),
        root.to_str().unwrap().into(),
        "--env-file".into(),
        env.to_str().unwrap().into(),
    ];
    for file in files {
        args.extend(["-f".into(), file.to_str().unwrap().into()]);
    }
    for profile in profiles {
        args.extend(["--profile".into(), (*profile).into()]);
    }
    args.extend(["config".into(), "--format".into(), "json".into()]);
    args.extend(services.iter().map(|v| (*v).to_owned()));
    serde_json::from_str(&invoke(
        executable,
        root,
        env.parent().expect("private environment parent"),
        &args,
    ))
    .expect("native config JSON")
}

#[test]
#[ignore = "requires pinned standalone Compose 5.6.1; config only, no daemon or containers"]
fn native_filtering_merge_and_restart_layer_semantics() {
    let executable = executable();
    let temp = PrivateFixture::new();
    let root = temp.path();
    baseline(&executable, root);
    let base = root.join("base.yml");
    let installer = root.join("installer.yml");
    let runtime = root.join("runtime.yml");
    let env = root.join("config.env");
    fs::write(&env, "FIXTURE_VALUE=literal\n").unwrap();
    fs::write(&base,r#"
x-common: &common
  image: example.invalid/fixture@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  init: true
  mem_limit: 64m
  security_opt: ["no-new-privileges:true"]
services:
  database:
    <<: *common
    healthcheck: {test: [CMD, /bin/true]}
  initialize:
    <<: *common
    profiles: [setup]
    restart: "no"
    depends_on: {database: {condition: service_healthy}}
  app:
    <<: *common
    depends_on:
      database: {condition: service_healthy}
      initialize: {condition: service_completed_successfully}
    ports: ["127.0.0.1:18443:8443"]
    group_add: ["1001"]
    environment: {DATABASE_URL_TEMPLATE: "postgres://user:$${PASSWORD}@database/db"}
    volumes:
      - {type: bind, source: ./private-input, target: /input, read_only: true}
  future:
    <<: *common
    profiles: [future]
    secrets: [future-output]
secrets:
  future-output: {file: ./not-created-yet}
"#).unwrap();
    fs::write(
        &installer,
        r#"
x-no-create: &no-create {create_host_path: false}
services:
  app:
    ports: !reset []
    group_add: !override ["0"]
    volumes:
      - {type: bind, source: ./private-input, target: /input, read_only: true, bind: *no-create}
"#,
    )
    .unwrap();
    fs::write(
        &runtime,
        r#"
x-completed: &completed !reset null
services:
  app:
    depends_on:
      initialize: *completed
"#,
    )
    .unwrap();
    let install = config(
        &executable,
        root,
        &[base.clone(), installer.clone()],
        &env,
        &["setup"],
        &[],
    );
    let app = &install["services"]["app"];
    assert!(app
        .get("ports")
        .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)));
    assert_eq!(app["group_add"], serde_json::json!(["0"]));
    let mount = &app["volumes"][0];
    assert_eq!(
        mount["source"],
        root.join("private-input").to_str().unwrap()
    );
    assert_eq!(mount["read_only"], true);
    assert_eq!(mount["bind"]["create_host_path"], false);
    assert_eq!(
        app["depends_on"]["initialize"]["condition"],
        "service_completed_successfully"
    );
    assert_eq!(
        app["environment"]["DATABASE_URL_TEMPLATE"],
        "postgres://user:$${PASSWORD}@database/db"
    );
    let selected = config(
        &executable,
        root,
        &[base.clone(), installer.clone()],
        &env,
        &["setup", "future"],
        &["database"],
    );
    assert_eq!(
        selected["services"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["database"]
    );
    assert!(
        !root.join("not-created-yet").exists(),
        "config must not create future inputs"
    );
    let restarted = config(
        &executable,
        root,
        &[base, installer, runtime],
        &env,
        &[],
        &[],
    );
    assert!(restarted["services"].get("initialize").is_none());
    assert!(restarted["services"].get("future").is_none());
    assert!(restarted["services"]["app"]["depends_on"]
        .get("initialize")
        .is_none());
    assert_eq!(
        restarted["services"]["app"]["depends_on"]["database"]["condition"],
        "service_healthy"
    );
}

#[test]
#[ignore = "requires explicit verified bundle, private test env and standalone Compose 5.6.1; config only"]
fn actual_installer_layers_keep_native_dependencies_and_exclude_setup_on_restart() {
    let executable = executable();
    let bundle = PathBuf::from(
        std::env::var_os("MARTY_INSTALLER_COMPOSE_BUNDLE")
            .expect("set the verified bundle directory"),
    );
    let supplied_env = PathBuf::from(
        std::env::var_os("MARTY_INSTALLER_COMPOSE_TEST_ENV")
            .expect("set complete private fixture values"),
    );
    assert!(bundle.is_absolute() && supplied_env.is_absolute());
    let source = std::env::var_os("MARTY_INSTALLER_SOURCE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.."));
    assert_actual_installer_layers(&executable, &bundle, &source, &supplied_env);
}

#[test]
#[ignore = "requires pinned standalone Compose 5.6.1; packages source with synthetic digests, config only"]
fn packaged_source_installer_layers_keep_native_dependencies_and_exclude_setup_on_restart() {
    let executable = executable();
    let temp = PrivateFixture::new();
    let root = temp.path();
    baseline(&executable, root);
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let manifest: Value = serde_json::from_slice(
        &fs::read(source.join("deploy-config/bundles/selfhost.json")).unwrap(),
    )
    .unwrap();
    let render: marty_selfhost_bundle::Render =
        serde_json::from_value(manifest["render"].clone()).unwrap();
    let mut arguments = marty_selfhost_bundle::render_arguments(&render);
    arguments.extend(["--format".into(), "json".into()]);
    let model: Value =
        serde_json::from_str(&invoke(&executable, &source, root, &arguments)).unwrap();
    // These identities are intentionally synthetic. This gate checks the
    // source package and native Compose semantics; it neither pulls images nor
    // authenticates the separate release bundle or qualifies a running stack.
    let image = format!(
        "ghcr.io/elevenid/marty-ui-oss/services@sha256:{}",
        "a".repeat(64)
    );
    let openbao = format!(
        "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:{}",
        "b".repeat(64)
    );
    let services: BTreeMap<_, _> = model["services"]
        .as_object()
        .unwrap()
        .keys()
        .map(|name| (name.clone(), image.clone()))
        .collect();
    assert!(services.len() >= 30);
    let stack_lock: Value =
        serde_json::from_slice(&fs::read(source.join("release/stack-lock.json")).unwrap()).unwrap();
    let image_lock = root.join("synthetic-images.json");
    private_write(
        &image_lock,
        &serde_json::to_vec(&serde_json::json!({
            "schema": "marty.selfhost-image-lock/v1",
            "release": stack_lock["release"],
            "services": services,
            "openbao_didcomm_image": openbao,
        }))
        .unwrap(),
    );
    let bundle = marty_selfhost_bundle::package_with_image_lock(
        &marty_selfhost_bundle::Options {
            repo: source.clone(),
            output: root.join("source-package"),
            archive: None,
            replace: false,
        },
        |stage, arguments| Ok(invoke(&executable, stage, root, arguments)),
        &image_lock,
    )
    .unwrap()
    .output;
    let mut values = BTreeMap::<String, String>::new();
    for line in fs::read_to_string(bundle.join(".env.selfhost.production.example"))
        .unwrap()
        .lines()
    {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let (name, value) = line.split_once('=').unwrap();
        assert!(values.insert(name.into(), value.into()).is_none());
    }
    for (name, value) in [
        ("SELFHOST_IMAGE_TAG", "source-config-fixture".into()),
        (
            "SELFHOST_SECRET_DIR",
            root.join("secrets").to_str().unwrap().into(),
        ),
        (
            "SELFHOST_STATE_DIR",
            root.join("state").to_str().unwrap().into(),
        ),
        (
            "SELFHOST_OPENBAO_STATE_DIR",
            root.join("openbao-state").to_str().unwrap().into(),
        ),
        ("MARTY_INSTALLATION_DIR", root.to_str().unwrap().into()),
        (
            "MARTY_INSTALLATION_ID",
            "2e052c77-efe8-44c6-9421-9ef15fe8ee7c".into(),
        ),
        (
            "MARTY_INSTALLER_ID",
            "2e052c77-efe8-44c6-9421-9ef15fe8ee7c".into(),
        ),
        ("MARTY_INSTALLER_APPLICANT_CONTAINER_GID", "0".into()),
        (
            "MARTY_INSTALLER_NGINX_CONFIG",
            root.join("nginx.conf").to_str().unwrap().into(),
        ),
        ("MARTY_INSTALLER_HELPER_IMAGE", image.clone()),
        ("MARTY_INSTALLER_SERVICES_IMAGE", image.clone()),
        ("MARTY_ISSUANCE_IMAGE", image.clone()),
        ("MARTY_KEYCLOAK_KMS_IMAGE", image),
        ("MARTY_OPENBAO_DIDCOMM_IMAGE", openbao),
        ("MARTY_KEYCLOAK_NONCE", "config-only-synthetic-nonce".into()),
        (
            "MARTY_SELFHOST_PROJECT",
            "marty-selfhost-disposable-config-fixture".into(),
        ),
        ("MARTY_INSTALLER_HTTPS_PORT", "18443".into()),
        (
            "MARTY_INSTALLER_INGRESS_KEY_NAME",
            "installer-ingress-fixture".into(),
        ),
        ("PUBLIC_API_URL", "https://localhost:18443".into()),
        ("PUBLIC_DOMAIN", "localhost:18443".into()),
    ] {
        values.insert(name.into(), value);
    }
    let supplied_env = root.join("source-fixture.env");
    let mut environment = String::new();
    for (name, value) in values {
        assert!(!value
            .chars()
            .any(|c| c.is_control() || c == '\'' || c == '\\'));
        environment.push_str(&format!("{name}='{value}'\n"));
    }
    private_write(&supplied_env, environment.as_bytes());
    // Use the packaged installer layers, including their real resource closure.
    assert_actual_installer_layers(&executable, &bundle, &bundle, &supplied_env);
}

fn assert_actual_installer_layers(
    executable: &OsString,
    bundle: &Path,
    source: &Path,
    supplied_env: &Path,
) {
    let temp = PrivateFixture::new();
    baseline(executable, temp.path());
    let env = temp.path().join("private.env");
    fs::copy(supplied_env, &env).unwrap();
    fs::set_permissions(&env, fs::Permissions::from_mode(0o600)).unwrap();
    let layer_root = source.join("deploy-config/compose/selfhost-installer");
    let base = bundle.join("docker-compose.yml");
    let openbao = bundle.join("docker-compose.selfhost.openbao.yml");
    let bootstrap = layer_root.join("compose.bootstrap.yml");
    let installer = layer_root.join("compose.installer.yml");
    let runtime = layer_root.join("compose.runtime.yml");
    #[cfg(feature = "installer-development")]
    let development = std::env::var_os("MARTY_INSTALLER_DEVELOPMENT_IMAGE_LAYER").map(|path| {
        let path = PathBuf::from(path);
        assert!(path.is_absolute());
        let image = std::env::var("MARTY_INSTALLER_DEVELOPMENT_IMAGE_ID")
            .expect("bound development image ID");
        assert!(image
            .strip_prefix("sha256:")
            .is_some_and(|value| value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))));
        let layer: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            layer,
            serde_json::json!({"services":{"signing-keys":{"image":image,"pull_policy":"never"}}})
        );
        (path, image)
    });
    #[cfg(feature = "installer-development")]
    let config = |executable: &OsString,
                  root: &Path,
                  files: &[PathBuf],
                  env: &Path,
                  profiles: &[&str],
                  services: &[&str]| {
        let original = config(executable, root, files, env, profiles, services);
        let Some((layer, image)) = &development else {
            return original;
        };
        let mut selected = files.to_vec();
        selected.push(layer.clone());
        let actual = config(executable, root, &selected, env, profiles, services);
        let mut expected = original;
        expected["services"]["signing-keys"]["image"] = Value::String(image.clone());
        expected["services"]["signing-keys"]["pull_policy"] = Value::String("never".into());
        assert_eq!(
            actual, expected,
            "the development layer may select only the Signing Keys image"
        );
        actual
    };
    let install = config(
        executable,
        bundle,
        &[base.clone(), installer.clone()],
        &env,
        &["installer-init"],
        &[],
    );
    let services = install["services"].as_object().unwrap();
    assert!(services.len() >= 30);
    for (dependent, dependency) in [
        ("compliance-profile", "organization"),
        ("presentation-policy", "organization"),
        ("credential-template", "organization"),
        ("credential-template", "revocation-profile"),
        ("revocation-profile", "organization"),
        ("deployment-profile", "organization"),
        ("device-registration", "organization"),
        ("flow", "trust-profile"),
        ("flow", "deployment-profile"),
        ("flow", "signing-keys"),
        ("trust-profile", "organization"),
        ("auth", "applicant"),
        ("auth", "event-stream"),
        ("canvas-sync-worker", "signing-keys"),
    ] {
        assert_eq!(
            services[dependent]["depends_on"][dependency]["condition"], "service_healthy",
            "{dependent} requires {dependency}"
        );
    }
    for (role, service) in services {
        assert_eq!(service["init"], true);
        assert_eq!(
            service["security_opt"],
            serde_json::json!(["no-new-privileges:true"])
        );
        #[cfg(feature = "installer-development")]
        let development_role = development
            .as_ref()
            .is_some_and(|(_, image)| role == "signing-keys" && service["image"] == *image);
        #[cfg(not(feature = "installer-development"))]
        let development_role = {
            let _ = role;
            false
        };
        assert!(development_role || service["image"].as_str().unwrap().contains("@sha256:"));
        for mount in service["volumes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|v| v["type"] == "bind")
        {
            assert_eq!(
                mount["bind"]["create_host_path"], false,
                "bind creation must be explicit"
            );
        }
    }
    for job in [
        "revocation-profile-migrate",
        "db-migrate",
        "kms-initialize",
        "keycloak-configurator",
        "issuance-migrations",
    ] {
        assert_eq!(
            services[job]["labels"]["com.elevenid.installer.phase"],
            "setup"
        );
        assert_eq!(services[job]["restart"], "no");
    }
    assert_eq!(
        services["issuance-native"]["depends_on"]["issuance-migrations"]["condition"],
        "service_completed_successfully",
        "the authenticated native issuance fixture must exercise its setup dependency"
    );
    for optional in ["cloudflared", "cloudflared-beta", "tunnel-nginx-proxy"] {
        assert!(!services.contains_key(optional));
    }
    assert_eq!(
        services["installer-ingress"]["ports"][0]["host_ip"],
        "127.0.0.1"
    );
    for role in ["gateway", "keycloak", "edge"] {
        assert!(services[role]
            .get("ports")
            .is_none_or(|p| p.as_array().is_some_and(Vec::is_empty)));
    }
    // Ordinary start resolves the full retained maintenance union, including
    // OpenBao and its live unseal worker. App-only layers missed this ordering.
    let maintenance = config(
        executable,
        bundle,
        &[
            base.clone(),
            openbao.clone(),
            bootstrap.clone(),
            installer.clone(),
        ],
        &env,
        &["setup", "installer-init"],
        &[],
    );
    let maintenance = maintenance["services"].as_object().unwrap();
    let setup_roles: BTreeSet<_> = maintenance
        .iter()
        .filter(|(_, service)| service["labels"]["com.elevenid.installer.phase"] == "setup")
        .map(|(name, _)| name.as_str())
        .collect();
    let kms_consumers: BTreeSet<_> = maintenance
        .iter()
        .filter(|(name, service)| {
            !setup_roles.contains(name.as_str())
                && service["depends_on"].get("kms-initialize").is_some()
        })
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(kms_consumers.contains("event-stream") && kms_consumers.contains("notification"));
    let restarted = config(
        executable,
        bundle,
        &[base, openbao, bootstrap, installer, runtime],
        &env,
        &[],
        &[],
    );
    let restarted = restarted["services"].as_object().unwrap();
    assert_eq!(
        restarted
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        maintenance
            .keys()
            .map(String::as_str)
            .filter(|name| !setup_roles.contains(name))
            .collect::<BTreeSet<_>>(),
        "restart must retain every runtime service and exclude every setup role"
    );
    assert!(restarted.contains_key("issuance-native"));
    assert!(restarted.contains_key("openbao") && restarted.contains_key("openbao-unseal"));
    assert_eq!(
        restarted["openbao-unseal"]["healthcheck"]["test"],
        serde_json::json!([
            "CMD-SHELL",
            "bao status -address=https://openbao:8200 -ca-cert=/bao/data/tls/ca.crt >/dev/null 2>&1"
        ]),
        "the runtime KMS prerequisite must require successful unsealed status"
    );
    for (role, service) in restarted {
        let mut expected: BTreeMap<_, _> = maintenance[role]["depends_on"]
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(dependency, _)| !setup_roles.contains(dependency.as_str()))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        if kms_consumers.contains(role.as_str()) {
            expected.insert(
                "openbao-unseal".into(),
                serde_json::json!({"condition":"service_healthy","required":true}),
            );
        }
        if role == "notification" {
            expected.insert(
                "postgres".into(),
                serde_json::json!({"condition":"service_healthy","required":true}),
            );
        }
        let actual: BTreeMap<_, _> = service["depends_on"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        assert_eq!(
            actual, expected,
            "{role} must preserve native runtime dependencies, replace completed KMS setup with live readiness, and exclude setup"
        );
        for dependency in actual.keys() {
            assert!(
                restarted.contains_key(dependency) && !setup_roles.contains(dependency.as_str()),
                "{role} cannot retain excluded or setup dependency {dependency}"
            );
        }
    }
    assert_eq!(
        restarted["canvas-sync-worker"]["depends_on"]["signing-keys"]["condition"],
        "service_healthy"
    );
    #[cfg(feature = "installer-development")]
    if let Some((_, image)) = development {
        println!("\nUNSIGNED_SIGNING_IMAGE_PARSED={image}");
    }
}
