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

fn config_hashes(
    executable: &OsString,
    root: &Path,
    files: &[PathBuf],
    env: &Path,
) -> BTreeMap<String, String> {
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
    // Pass the wildcard directly to Compose; no shell expands it.
    args.extend(["config".into(), "--hash".into(), "*".into()]);
    let output = invoke(
        executable,
        root,
        env.parent().expect("private environment parent"),
        &args,
    );
    let mut hashes = BTreeMap::new();
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        let role = fields.next().expect("native service hash role");
        let hash = fields.next().expect("native service hash value");
        assert!(fields.next().is_none());
        assert_eq!(hash.len(), 64);
        assert!(hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(hashes.insert(role.into(), hash.into()).is_none());
    }
    assert!(!hashes.is_empty());
    hashes
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
    assert!(services.len() >= 29);
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
            "MARTY_OPENBAO_CONTROL_ATTEMPT_ID",
            "6b0176e0-a046-4310-917c-57f1ddda1ac0".into(),
        ),
        (
            "MARTY_OPENBAO_STATIC_INIT_ATTEMPT_ID",
            "96c79b92-d813-414f-bba9-310e9f03d831".into(),
        ),
        (
            "MARTY_SELFHOST_PROJECT",
            "marty-selfhost-disposable-config-fixture".into(),
        ),
        ("MARTY_INSTALLER_HTTPS_PORT", "18443".into()),
        (
            "MARTY_INSTALLER_INGRESS_CONNECT_TO",
            "localhost:18443:127.0.0.1:8443".into(),
        ),
        (
            "MARTY_INSTALLER_INGRESS_KEY_NAME",
            "installer-ingress-fixture".into(),
        ),
        ("PUBLIC_API_URL", "https://localhost:18443".into()),
        ("GATEWAY_OBSERVE_CLIENT_IP", "false".into()),
        ("PUBLIC_DOMAIN", "localhost:18443".into()),
        (
            "MARTY_ISSUER_DID",
            "did:web:localhost%3A18443:orgs:marty".into(),
        ),
    ] {
        values.insert(name.into(), value);
    }
    let supplied_env = root.join("source-fixture.env");
    let mut environment = String::new();
    for (name, value) in &values {
        assert!(!value
            .chars()
            .any(|c| c.is_control() || c == '\'' || c == '\\'));
        environment.push_str(&format!("{name}='{value}'\n"));
    }
    private_write(&supplied_env, environment.as_bytes());
    // Use the packaged installer layers, including their real resource closure.
    assert_actual_installer_layers(&executable, &bundle, &bundle, &supplied_env);
    for (case_index, (case, public_origin, bind_address, public_entry)) in [
        ("direct-dns", "https://marty.example.com", "0.0.0.0", None),
        // Legacy Compose inputs remain readable; fresh hosting selection
        // separately rejects an IP as the canonical identity.
        (
            "legacy-direct-ip",
            "https://192.0.2.10:8443",
            "0.0.0.0",
            None,
        ),
        (
            "direct-dns-with-ip-entry",
            "https://marty.example.com",
            "0.0.0.0",
            Some("https://192.0.2.10:8443"),
        ),
        (
            "direct-dns-port-with-ipv6-entry",
            "https://marty.example.com:8443",
            "::",
            Some("https://[2001:db8::10]:8443"),
        ),
        (
            "direct-dns-ipv6-listener",
            "https://marty.example.com",
            "::",
            None,
        ),
        ("proxy", "https://marty.example.com", "127.0.0.1", None),
    ]
    .into_iter()
    .enumerate()
    {
        let origin = marty_selfhost_identity::origin::PublicOrigin::parse(public_origin).unwrap();
        let host = match origin.ip_address() {
            Some(std::net::IpAddr::V6(ip)) => format!("[{ip}]"),
            _ => origin.host().to_owned(),
        };
        let mut selected = values.clone();
        let web_sections = ["public,console", "public", "console", "none"][case_index % 4];
        selected.insert(
            "MARTY_INSTALLER_UI_ENABLED_SECTIONS".into(),
            web_sections.into(),
        );
        selected.insert("PUBLIC_API_URL".into(), public_origin.into());
        selected.insert("PUBLIC_DOMAIN".into(), origin.authority().into());
        selected.remove("MARTY_ISSUER_DID");
        let issuer = origin
            .did_web_authority()
            .ok()
            .map(|authority| format!("did:web:{authority}:orgs:marty"));
        if let Some(issuer) = &issuer {
            selected.insert("MARTY_ISSUER_DID".into(), issuer.clone());
        }
        selected.insert(
            "MARTY_INSTALLER_PUBLIC_ENTRY_ORIGIN".into(),
            public_entry.unwrap_or("").into(),
        );
        selected.insert(
            "MARTY_INSTALLER_PUBLIC_ENTRY_ORIGINS".into(),
            serde_json::to_string(&public_entry.into_iter().collect::<Vec<_>>()).unwrap(),
        );
        selected.insert(
            "MARTY_INSTALLER_HTTPS_BIND_ADDRESS".into(),
            bind_address.into(),
        );
        selected.insert("MARTY_INSTALLER_HTTPS_PORT".into(), "18443".into());
        let connect_to = format!("{host}:{}:127.0.0.1:8443", origin.port());
        selected.insert(
            "MARTY_INSTALLER_INGRESS_CONNECT_TO".into(),
            connect_to.clone(),
        );
        let env = root.join(format!("{case}.env"));
        private_write(
            &env,
            selected
                .iter()
                .map(|(key, value)| format!("{key}='{value}'\n"))
                .collect::<String>()
                .as_bytes(),
        );
        let model = config(
            &executable,
            &bundle,
            &[
                bundle.join("docker-compose.yml"),
                bundle.join("deploy-config/compose/selfhost-installer/compose.installer.yml"),
            ],
            &env,
            &["installer-init"],
            &[],
        );
        let services = model["services"].as_object().unwrap();
        let ingress = &services["installer-ingress"];
        assert_eq!(ingress["ports"][0]["host_ip"], bind_address);
        assert_eq!(ingress["ports"][0]["published"], "18443");
        assert_eq!(ingress["ports"][0]["target"], 8443);
        assert_eq!(
            ingress["environment"]["OIDF_EDGE_PUBLIC_ORIGIN"],
            public_origin
        );
        assert_eq!(
            ingress["environment"]["OIDF_EDGE_PUBLIC_ENTRY_ORIGIN"],
            public_entry.unwrap_or("")
        );
        assert_eq!(
            services["ui"]["environment"]["UI_CANONICAL_ORIGIN"],
            public_origin
        );
        assert_eq!(
            services["ui"]["environment"]["UI_ENABLED_SECTIONS"],
            web_sections
        );
        let aliases: Vec<String> = serde_json::from_str(
            services["ui"]["environment"]["UI_PUBLIC_ENTRY_ORIGINS"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(aliases, public_entry.into_iter().collect::<Vec<_>>());
        if let Some(issuer) = issuer {
            assert_eq!(
                services["gateway"]["environment"]["MARTY_ISSUER_DID"],
                issuer
            );
            assert_eq!(
                services["auth"]["environment"]["CREDENTIAL_LOGIN_ISSUER_DID"],
                issuer
            );
            assert_eq!(services["flow"]["environment"]["OID4VP_ISSUER_DID"], issuer);
        }
        assert_eq!(ingress["restart"], "unless-stopped");
        let health = ingress["healthcheck"]["test"].as_array().unwrap();
        assert!(health.contains(&Value::String(connect_to)));
        assert!(health.contains(&Value::String(format!("{public_origin}/"))));
        assert!(!services.contains_key("cloudflared"));
        assert_eq!(
            services["gateway"]["environment"]["GATEWAY_OBSERVE_CLIENT_IP"],
            "false"
        );
        for role in ["gateway", "keycloak", "edge"] {
            assert!(services[role]
                .get("ports")
                .is_none_or(|ports| ports.as_array().is_some_and(Vec::is_empty)));
        }
        if case == "direct-dns-with-ip-entry" {
            // Recurrence begins from the admitted application generation. The
            // bootstrap job retains its separate historical /secrets mount.
            selected.insert(
                "SELFHOST_SECRET_DIR".into(),
                root.join("application-generation").to_str().unwrap().into(),
            );
            assert_native_managed_generation_models(&executable, &bundle, root, &selected);
            selected.insert("MARTY_ACME_CANONICAL_ORIGIN".into(), public_origin.into());
            selected.insert(
                "MARTY_ACME_PUBLIC_ENTRY_ORIGIN".into(),
                public_entry.unwrap().into(),
            );
            selected.insert("MARTY_ACME_HTTP01_HOST_PORT".into(), "18080".into());
            selected.insert("MARTY_ACME_CUSTODY_PLAN_SHA256".into(), "1".repeat(64));
            selected.insert("MARTY_ACME_CREDENTIAL_PLAN_SHA256".into(), "2".repeat(64));
            selected.insert(
                "MARTY_INSTALLER_PUBLIC_INGRESS_PLAN_SHA256".into(),
                "3".repeat(64),
            );
            selected.insert(
                "MARTY_INSTALLER_PUBLIC_RENEWAL_AUTHORITY_PLAN_SHA256".into(),
                "4".repeat(64),
            );
            let acme_env = root.join("public-acme.env");
            private_write(
                &acme_env,
                selected
                    .iter()
                    .map(|(key, value)| format!("{key}='{value}'\n"))
                    .collect::<String>()
                    .as_bytes(),
            );
            let layers = bundle.join("deploy-config/compose/selfhost-installer");
            let files = vec![
                bundle.join("docker-compose.yml"),
                bundle.join("docker-compose.selfhost.openbao.yml"),
                layers.join("compose.bootstrap.yml"),
                layers.join("compose.installer.yml"),
                layers.join("compose.runtime.yml"),
                layers.join("compose.acme.yml"),
                layers.join("compose.acme-runtime.yml"),
            ];
            let public = config(
                &executable,
                &bundle,
                &files,
                &acme_env,
                &["setup", "installer-init"],
                &[],
            );
            let roles = public["services"].as_object().unwrap();
            let bootstrap_runtime = roles["openbao-bootstrap"]["volumes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|mount| mount["target"] == "/bao/runtime")
                .unwrap();
            assert_eq!(
                bootstrap_runtime["source"],
                root.join("secrets").to_str().unwrap(),
                "bootstrap retains its historical output directory"
            );
            let entry = &roles["installer-ingress"];
            let mounts = entry["volumes"].as_array().unwrap();
            assert_eq!(mounts.len(), 3);
            assert!(mounts.iter().any(|mount| {
                mount["source"]
                    == root
                        .join("application-generation/installer_ingress_tls_cert")
                        .to_str()
                        .unwrap()
            }));
            assert!(!mounts
                .iter()
                .any(|mount| mount["target"] == "/run/installer/ca.crt"));
            assert!(mounts
                .iter()
                .any(|mount| mount["target"] == "/run/installer/openbao-ca.crt"
                    && mount["read_only"] == true));
            let health = entry["healthcheck"]["test"].as_array().unwrap();
            assert!(health.contains(&Value::String("/etc/ssl/certs/ca-certificates.crt".into())));
            assert!(!health.contains(&Value::String("/run/installer/ca.crt".into())));
            for role in ["installer-renewal", "installer-generation"] {
                assert_eq!(
                    roles[role]["environment"]
                        ["MARTY_INSTALLER_PUBLIC_RENEWAL_AUTHORITY_PLAN_SHA256"],
                    "4".repeat(64)
                );
                let plan = roles[role]["volumes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|mount| mount["target"] == "/input/public-renewal-authority-plan.json")
                    .unwrap();
                assert_eq!(
                    plan["source"],
                    root.join("evidence/renewal-public-authority-plan.json")
                        .to_str()
                        .unwrap()
                );
                assert_eq!(plan["read_only"], true);
                assert_eq!(plan["bind"]["create_host_path"], false);
            }
            assert!(roles["installer-renewal"]["volumes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|mount| mount["target"] != "/input/public-ingress-plan.json"));
            assert_eq!(
                roles["installer-generation"]["environment"]
                    ["MARTY_INSTALLER_PUBLIC_INGRESS_PLAN_SHA256"],
                "3".repeat(64)
            );
            let public_plan = roles["installer-generation"]["volumes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|mount| mount["target"] == "/input/public-ingress-plan.json")
                .unwrap();
            assert_eq!(
                public_plan["source"],
                root.join("evidence/generation-public-ingress-plan.json")
                    .to_str()
                    .unwrap()
            );
            assert_eq!(public_plan["read_only"], true);
            assert_eq!(public_plan["bind"]["create_host_path"], false);
            let http = &roles["installer-acme-http01"];
            assert_eq!(http["restart"], "unless-stopped");
            assert_eq!(http["stop_grace_period"], "1m0s");
            assert_eq!(http["logging"]["options"]["max-size"], "10m");
            assert_eq!(http["logging"]["options"]["max-file"], "3");
            assert_eq!(http["user"], "10001:10001");
            assert_eq!(http["ports"][0]["host_ip"], "127.0.0.1");
            assert_eq!(http["ports"][0]["published"], "18080");
            assert!(http
                .get("depends_on")
                .is_none_or(|value| value.as_object().is_some_and(serde_json::Map::is_empty)));
            assert_eq!(http["volumes"].as_array().unwrap().len(), 1);
            assert_eq!(http["volumes"][0]["target"], "/run/acme-http01");
            let runtime = config(&executable, &bundle, &files, &acme_env, &[], &[]);
            assert!(runtime["services"]["installer-acme-http01"].is_object());
            for role in [
                "installer-acme-custody",
                "installer-acme-credentials",
                "installer-renewal",
                "installer-generation",
                "openbao-bootstrap",
            ] {
                assert!(
                    runtime["services"].get(role).is_none(),
                    "setup role {role} must not join restart"
                );
            }
            assert_native_generation_models(
                &executable,
                &bundle,
                root,
                &files,
                &selected,
                &public,
                &runtime,
            );
        }
        if case == "proxy" {
            let connector_image = format!(
                "ghcr.io/elevenid/marty-ui-oss/cloudflared-wrapper@sha256:{}",
                "d".repeat(64)
            );
            selected.insert("MARTY_CLOUDFLARED_IMAGE".into(), connector_image.clone());
            selected.insert(
                "MARTY_CLOUDFLARE_ADDON_DIR".into(),
                root.to_str().unwrap().into(),
            );
            let addon_env = root.join("proxy-cloudflare.env");
            private_write(
                &addon_env,
                selected
                    .iter()
                    .map(|(key, value)| format!("{key}='{value}'\n"))
                    .collect::<String>()
                    .as_bytes(),
            );
            // Config-only source fixture: cryptographic ZIP admission is tested
            // separately; this never executes or authenticates an image.
            let addon = config(
                &executable,
                &bundle,
                &[
                    bundle.join("docker-compose.yml"),
                    bundle.join("deploy-config/compose/selfhost-installer/compose.installer.yml"),
                    source.join("deploy-config/compose/selfhost-cloudflare/compose.cloudflare.yml"),
                ],
                &addon_env,
                &["installer-init"],
                &[],
            );
            let extended = addon["services"].as_object().unwrap();
            assert_eq!(extended.len(), services.len() + 1);
            for (role, service) in services {
                assert_eq!(extended[role], *service);
            }
            let connector = &extended["cloudflared"];
            assert_eq!(connector["image"], connector_image);
            assert_eq!(connector["init"], true);
            assert_eq!(
                connector["depends_on"]["installer-ingress"]["condition"],
                "service_healthy"
            );
            assert!(connector.get("ports").is_none());
            assert_eq!(
                connector["environment"]["CLOUDFLARE_TUNNEL_TOKEN_FILE"],
                "/run/secrets/cloudflare_tunnel_token"
            );
        }
    }
}

fn assert_native_managed_generation_models(
    executable: &OsString,
    bundle: &Path,
    root: &Path,
    values: &BTreeMap<String, String>,
) {
    let layers = bundle.join("deploy-config/compose/selfhost-installer");
    let files = vec![
        bundle.join("docker-compose.yml"),
        bundle.join("docker-compose.selfhost.openbao.yml"),
        layers.join("compose.bootstrap.yml"),
        layers.join("compose.installer.yml"),
        layers.join("compose.runtime.yml"),
    ];
    let env = root.join("managed-original.env");
    private_write(
        &env,
        values
            .iter()
            .map(|(key, value)| format!("{key}='{value}'\n"))
            .collect::<String>()
            .as_bytes(),
    );
    let full = config(
        executable,
        bundle,
        &files,
        &env,
        &["setup", "installer-init"],
        &[],
    );
    let runtime = config(executable, bundle, &files, &env, &[], &[]);
    assert!(full["services"].get("installer-acme-http01").is_none());
    assert_native_generation_models(executable, bundle, root, &files, values, &full, &runtime);
}

/// Exercise each source's shipped recurrence layer through the real Compose
/// parser. Selected-service config is not a full maintenance/runtime model.
fn assert_native_generation_models(
    executable: &OsString,
    bundle: &Path,
    root: &Path,
    original_files: &[PathBuf],
    original_values: &BTreeMap<String, String>,
    previous_full: &Value,
    previous_runtime: &Value,
) {
    let public = previous_full["services"]["installer-generation"]["environment"]
        .get("MARTY_INSTALLER_PUBLIC_INGRESS_PLAN_SHA256")
        .is_some();
    let (layer, plan_variable, plan_digest, plan_kind, plan_target, prefix) = if public {
        (
            "compose.generation.yml",
            "MARTY_GENERATION_PUBLIC_INGRESS_PLAN",
            "MARTY_INSTALLER_PUBLIC_INGRESS_PLAN_SHA256",
            "public-ingress-plan",
            "/input/public-ingress-plan.json",
            "public-generation",
        )
    } else {
        (
            "compose.generation-managed.yml",
            "MARTY_GENERATION_MANAGED_RENEWAL_PLAN",
            "MARTY_INSTALLER_MANAGED_RENEWAL_PLAN_SHA256",
            "managed-renewal-plan",
            "/input/managed-renewal-plan.json",
            "managed-generation",
        )
    };
    let mut files = original_files.to_vec();
    files.push(
        bundle
            .join("deploy-config/compose/selfhost-installer")
            .join(layer),
    );
    assert_eq!(
        files.len(),
        if public { 8 } else { 6 },
        "the admitted native layer bound includes generation"
    );
    let work = root.join("generation-work/00000000000000000001");
    let plan = root.join(format!(
        "evidence/generation-00000000000000000001-{plan_kind}.json"
    ));
    let generation = root.join(format!(
        "application-generations/00000000000000000001-{}",
        "6".repeat(64)
    ));
    let mut helper_values = original_values.clone();
    helper_values.insert(
        "MARTY_GENERATION_WORK_DIR".into(),
        work.to_str().unwrap().into(),
    );
    helper_values.insert(plan_variable.into(), plan.to_str().unwrap().into());
    helper_values.insert(plan_digest.into(), "5".repeat(64));
    let helper_env = root.join(format!("{prefix}-helper.env"));
    private_write(
        &helper_env,
        helper_values
            .iter()
            .map(|(key, value)| format!("{key}='{value}'\n"))
            .collect::<String>()
            .as_bytes(),
    );
    let helper = config(
        executable,
        bundle,
        &files,
        &helper_env,
        &["setup"],
        &["installer-generation"],
    );
    assert_eq!(
        helper["services"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["installer-generation"],
        "a credential producer's native config cannot be reused as an infrastructure-start model"
    );
    let helper_full = config(executable, bundle, &files, &helper_env, &["setup"], &[]);
    assert_eq!(
        helper_full["services"]["installer-generation"], helper["services"]["installer-generation"],
        "unfiltered configuration retains the exact producer selected for its create/start command"
    );
    for role in ["openbao", "openbao-unseal", "installer-acme-http01"] {
        if !public && role == "installer-acme-http01" {
            assert!(helper_full["services"].get(role).is_none());
            continue;
        }
        assert!(helper_full["services"][role].is_object());
        assert_eq!(
            helper_full["services"][role],
            previous_full["services"][role]
        );
    }
    assert_eq!(helper_full["services"]["auth"], previous_full["services"]["auth"], "the producer's full admission view retains unselected application services for stop without changing their configuration");
    let job = &helper["services"]["installer-generation"];
    let mut expected_helper = previous_full["services"]["installer-generation"].clone();
    expected_helper["environment"][plan_digest] = Value::String("5".repeat(64));
    if !public {
        for key in [
            "MARTY_INSTALLER_PUBLIC_INGRESS_PLAN_SHA256",
            "MARTY_INSTALLER_PUBLIC_RENEWAL_AUTHORITY_PLAN_SHA256",
        ] {
            assert!(job["environment"].get(key).is_none());
        }
        for target in [
            "/input/public-ingress-plan.json",
            "/input/public-renewal-authority-plan.json",
        ] {
            assert!(job["volumes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|mount| mount["target"] != target));
        }
        expected_helper["volumes"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "type":"bind", "source":plan.to_str().unwrap().replace('$', "$$"),
                "target":plan_target, "read_only":true, "bind":{"create_host_path":false}
            }));
    } else {
        assert!(job["environment"]
            .get("MARTY_INSTALLER_MANAGED_RENEWAL_PLAN_SHA256")
            .is_none());
        assert!(job["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|mount| mount["target"] != "/input/managed-renewal-plan.json"));
    }
    let changed_mounts: BTreeMap<_, _> = [
        ("/transfer", (work.join("transfer"), false)),
        ("/input/current", (work.join("current"), true)),
        ("/input/identity", (work.join("identity"), true)),
        (plan_target, (plan, true)),
    ]
    .into_iter()
    .collect();
    let mut observed_targets = BTreeSet::new();
    for mount in expected_helper["volumes"].as_array_mut().unwrap() {
        if let Some((path, readonly)) = changed_mounts.get(mount["target"].as_str().unwrap()) {
            observed_targets.insert(mount["target"].as_str().unwrap().to_owned());
            mount["source"] = Value::String(path.to_str().unwrap().replace('$', "$$"));
            assert_eq!(mount["read_only"] == true, *readonly);
            assert_eq!(mount["bind"]["create_host_path"], false);
        }
    }
    assert_eq!(observed_targets.len(), changed_mounts.len());
    assert_eq!(
        *job, expected_helper,
        "the recurring producer changes only its three input roots, source-specific plan mount and bound digest"
    );

    let mut application_values = helper_values;
    application_values.insert(
        "SELFHOST_SECRET_DIR".into(),
        generation.to_str().unwrap().into(),
    );
    let application_env = root.join(format!("{prefix}-application.env"));
    private_write(
        &application_env,
        application_values
            .iter()
            .map(|(key, value)| format!("{key}='{value}'\n"))
            .collect::<String>()
            .as_bytes(),
    );
    let current_runtime = config(executable, bundle, &files, &application_env, &[], &[]);
    assert_eq!(
        current_runtime["services"]["auth"]["depends_on"]["keycloak"],
        serde_json::json!({"condition":"service_healthy","required":true}),
        "generation activation must wait for the managed realm before starting Auth"
    );
    let current_full = config(
        executable,
        bundle,
        &files,
        &application_env,
        &["setup", "installer-init"],
        &[],
    );
    let mut expected_runtime = previous_runtime.clone();
    let mut expected_full = previous_full.clone();
    let previous_root = Path::new(&original_values["SELFHOST_SECRET_DIR"]);
    replace_native_generation_files(&mut expected_runtime, previous_root, &generation);
    replace_native_generation_files(&mut expected_full, previous_root, &generation);
    expected_full["services"]["installer-generation"] = job.clone();
    assert_native_model_eq(
        root,
        "generation-runtime",
        &current_runtime,
        &expected_runtime,
    );
    assert_native_model_eq(root, "generation-full", &current_full, &expected_full);
    let previous_hashes = config_hashes(executable, bundle, &files, &helper_env);
    let current_hashes = config_hashes(executable, bundle, &files, &application_env);
    for (hashes, model) in [
        (&previous_hashes, previous_runtime),
        (&current_hashes, &current_runtime),
    ] {
        assert_eq!(
            hashes.keys().collect::<BTreeSet<_>>(),
            model["services"]
                .as_object()
                .unwrap()
                .keys()
                .collect::<BTreeSet<_>>()
        );
    }
    // Native service hashes omit top-level secret file declarations. Equal
    // hashes cannot decide whether a credential consumer needs replacement.
    for (role, credential) in [
        ("auth", "auth_tls_kms_token"),
        ("gateway", "gateway_tls_kms_token"),
        ("postgres", "postgres_password"),
        ("keycloak", "keycloak_signing_kms_token"),
    ] {
        assert_eq!(previous_hashes[role], current_hashes[role]);
        assert_eq!(
            previous_runtime["services"][role], current_runtime["services"][role],
            "{role} keeps its service definition while its mounted secret source changes"
        );
        assert!(previous_runtime["services"][role]["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reference| reference["source"] == credential));
        assert_eq!(
            previous_runtime["secrets"][credential]["file"],
            previous_root
                .join(credential)
                .to_str()
                .unwrap()
                .replace('$', "$$")
        );
        assert_eq!(
            current_runtime["secrets"][credential]["file"],
            generation
                .join(credential)
                .to_str()
                .unwrap()
                .replace('$', "$$")
        );
        assert_ne!(
            previous_runtime["secrets"][credential],
            current_runtime["secrets"][credential]
        );
    }
    assert_ne!(
        previous_hashes["installer-ingress"], current_hashes["installer-ingress"],
        "explicit bind source changes are represented in the native service hash"
    );
    for role in ["openbao", "openbao-unseal", "installer-acme-http01"] {
        assert_eq!(
            current_runtime["services"][role], previous_runtime["services"][role],
            "{role} must retain its native config during application generation replacement"
        );
    }
    let selected = config(
        executable,
        bundle,
        &files,
        &application_env,
        &[],
        &["installer-ingress"],
    );
    if public {
        assert!(current_runtime["services"]["installer-acme-http01"].is_object());
        assert!(selected["services"].get("installer-acme-http01").is_none(), "selected runtime config omits an unrelated retained responder, so it cannot equal the unfiltered activation model");
    } else {
        assert!(current_runtime["services"]
            .get("installer-acme-http01")
            .is_none());
    }
    assert_eq!(
        selected["services"]["installer-ingress"], current_runtime["services"]["installer-ingress"],
        "full configuration admission does not change the specifically selected runtime service"
    );
}

fn replace_native_generation_files(model: &mut Value, old: &Path, new: &Path) {
    let replace = |value: &mut Value| {
        let decoded = value.as_str().unwrap().replace("$$", "$");
        let path = Path::new(&decoded);
        if let Ok(relative) = path.strip_prefix(old) {
            assert_eq!(relative.components().count(), 1);
            *value = Value::String(new.join(relative).to_str().unwrap().replace('$', "$$"));
        }
    };
    for declaration in model
        .get_mut("secrets")
        .and_then(Value::as_object_mut)
        .into_iter()
        .flat_map(|map| map.values_mut())
    {
        if let Some(file) = declaration.get_mut("file") {
            replace(file);
        }
    }
    for service in model["services"].as_object_mut().unwrap().values_mut() {
        for mount in service
            .get_mut("volumes")
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            if mount["type"] == "bind" {
                replace(&mut mount["source"]);
            }
        }
    }
}

fn assert_native_model_eq(root: &Path, label: &str, actual: &Value, expected: &Value) {
    if actual == expected {
        return;
    }
    // Preserve complete private evidence while keeping CI output bounded and
    // useful: native configurations contain many large environment sections.
    private_write(
        &root.join(format!("{label}-actual.json")),
        &serde_json::to_vec_pretty(actual).unwrap(),
    );
    private_write(
        &root.join(format!("{label}-expected.json")),
        &serde_json::to_vec_pretty(expected).unwrap(),
    );
    fn differences(actual: &Value, expected: &Value, path: &str, paths: &mut Vec<String>) {
        if actual == expected || paths.len() >= 32 {
            return;
        }
        match (actual, expected) {
            (Value::Object(actual), Value::Object(expected)) => {
                for key in actual
                    .keys()
                    .chain(expected.keys())
                    .collect::<BTreeSet<_>>()
                {
                    let next = format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"));
                    match (actual.get(key), expected.get(key)) {
                        (Some(actual), Some(expected)) => {
                            differences(actual, expected, &next, paths)
                        }
                        _ if paths.len() < 32 => paths.push(next),
                        _ => {}
                    }
                }
            }
            (Value::Array(actual), Value::Array(expected)) if actual.len() == expected.len() => {
                for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
                    differences(actual, expected, &format!("{path}/{index}"), paths);
                }
            }
            _ => paths.push(path.to_owned()),
        }
    }
    let mut paths = Vec::new();
    differences(actual, expected, "", &mut paths);
    panic!("native {label} model differs at {paths:?}; full actual/expected snapshots retained in the private fixture");
}

fn assert_actual_installer_layers(
    executable: &OsString,
    bundle: &Path,
    source: &Path,
    supplied_env: &Path,
) {
    let temp = PrivateFixture::new();
    baseline(executable, temp.path());
    let installation = fs::read_to_string(supplied_env)
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix("MARTY_INSTALLATION_DIR='")
                .and_then(|v| v.strip_suffix('\''))
        })
        .map(PathBuf::from)
        .expect("bound installation path in source fixture");
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
    assert_eq!(
        services["auth"]["depends_on"]["keycloak-configurator"]["condition"],
        "service_completed_successfully",
        "initial Auth startup must wait for realm/client configuration"
    );
    assert_eq!(
        services["keycloak-configurator"]["depends_on"]["keycloak"]["condition"],
        "service_healthy"
    );
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
    for (role, service) in restarted {
        assert_eq!(service["restart"], "unless-stopped", "{role} crash policy");
        assert_eq!(
            service["stop_grace_period"], "1m0s",
            "{role} shutdown grace"
        );
        assert_eq!(
            service["logging"]["driver"], "json-file",
            "{role} log driver"
        );
        assert_eq!(
            service["logging"]["options"]["max-size"], "10m",
            "{role} log bound"
        );
        assert_eq!(
            service["logging"]["options"]["max-file"], "3",
            "{role} log rotation"
        );
    }
    assert_eq!(
        restarted["openbao-unseal"]["healthcheck"]["test"],
        serde_json::json!([
            "CMD",
            "/usr/local/bin/selfhost-openbao-ready",
            "--check-ready"
        ]),
        "the runtime KMS prerequisite must require successful unsealed status"
    );
    assert_eq!(
        restarted["openbao"]["healthcheck"]["test"],
        serde_json::json!([
            "CMD",
            "/usr/local/bin/selfhost-openbao-ready",
            "--check-listener"
        ]),
        "sealed or expired-TCP startup must not block the local recovery channel"
    );
    assert!(setup_roles.contains("installer-control-enroll"));
    for target in ["/openbao/file:", "/openbao/logs:"] {
        assert!(
            maintenance["installer-control-enroll"]["tmpfs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str().is_some_and(|v| v.starts_with(target))),
            "the enrollment job must cover inherited image volumes without anonymous storage"
        );
    }
    for role in ["openbao", "openbao-unseal"] {
        assert_eq!(
            restarted[role]["environment"]["MARTY_OPENBAO_LOCAL_CONTROL"],
            "1"
        );
        let volumes = restarted[role]["volumes"].as_array().unwrap();
        let control = volumes
            .iter()
            .find(|v| v["target"] == "/bao/control")
            .unwrap();
        assert_eq!(
            control["source"],
            installation
                .join("openbao-control/socket")
                .to_str()
                .unwrap()
        );
        assert_eq!(control["bind"]["create_host_path"], false);
        if role == "openbao-unseal" {
            assert_eq!(control["read_only"], true);
            assert_eq!(
                volumes.len(),
                1,
                "readiness has only the Unix socket; no key, state or machine identity"
            );
            assert_eq!(
                restarted[role]["entrypoint"],
                serde_json::json!(["/usr/local/bin/selfhost-openbao-ready"])
            );
            assert_eq!(restarted[role]["command"], serde_json::json!(["--watch"]));
        } else {
            let identity = volumes
                .iter()
                .find(|v| v["target"] == "/bao/control-identity")
                .unwrap();
            assert_eq!(identity["read_only"], true);
            let seal = volumes.iter().find(|v| v["target"] == "/bao/seal").unwrap();
            assert_eq!(seal["read_only"], true);
            assert_eq!(
                seal["source"],
                installation.join("openbao-seal/key").to_str().unwrap()
            );
        }
    }
    for (role, service) in maintenance {
        for volume in service["volumes"].as_array().into_iter().flatten() {
            if volume["source"] == installation.join("openbao-seal/key").to_str().unwrap() {
                assert_eq!(
                    role, "openbao",
                    "static seal must be mounted only into OpenBao"
                );
            }
            assert_ne!(
                volume["source"],
                installation.join("openbao-seal").to_str().unwrap(),
                "the private seal parent is never mounted"
            );
        }
    }
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
        if role == "auth" {
            // Auth fetches discovery/JWKS before opening listeners. Removing the
            // completed configurator must retain live managed OIDC readiness.
            expected.insert(
                "keycloak".into(),
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

#[test]
#[ignore = "requires pinned standalone Compose 5.6.1; packages actual source and parses only, no daemon"]
fn actual_aws_foundation_removes_managed_providers_and_preserves_native_lifecycle() {
    let executable = executable();
    let temp = PrivateFixture::new();
    let root = temp.path();
    baseline(&executable, root);
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let mut raw = String::new();
    let bundle = marty_selfhost_bundle::package(
        &marty_selfhost_bundle::Options {
            repo: source.clone(),
            output: root.join("bundle"),
            archive: None,
            replace: false,
        },
        |stage, arguments| {
            raw = invoke(&executable, stage, root, arguments);
            Ok(raw.clone())
        },
    )
    .unwrap()
    .output;
    let mut values = BTreeMap::<String, String>::new();
    for line in fs::read_to_string(source.join(".env.selfhost.production.example"))
        .unwrap()
        .lines()
    {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line.split_once('=').unwrap();
        values.insert(name.into(), value.into());
    }
    let image = format!("example.invalid/fixture@sha256:{}", "a".repeat(64));
    for (name, value) in [
        ("SELFHOST_IMAGE_TAG", "1.2.3".into()),
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
            "SELFHOST_SECRET_DIR",
            root.join("secrets").to_str().unwrap().into(),
        ),
        (
            "SELFHOST_STATE_DIR",
            root.join("state").to_str().unwrap().into(),
        ),
        (
            "MARTY_INSTALLER_NGINX_CONFIG",
            root.join("nginx.conf").to_str().unwrap().into(),
        ),
        ("MARTY_INSTALLER_HTTPS_PORT", "18443".into()),
        (
            "MARTY_INSTALLER_INGRESS_CONNECT_TO",
            "localhost:18443:127.0.0.1:8443".into(),
        ),
        (
            "MARTY_INSTALLER_INGRESS_KEY_NAME",
            "installer-ingress-fixture".into(),
        ),
        ("MARTY_INSTALLER_HELPER_IMAGE", image.clone()),
        ("MARTY_INSTALLER_SERVICES_IMAGE", image.clone()),
        ("MARTY_ISSUANCE_IMAGE", image.clone()),
        ("MARTY_KEYCLOAK_KMS_IMAGE", image.clone()),
        ("MARTY_OPENBAO_DIDCOMM_IMAGE", image),
        ("PUBLIC_API_URL", "https://localhost:18443".into()),
        ("GATEWAY_OBSERVE_CLIENT_IP", "false".into()),
        ("PUBLIC_DOMAIN", "localhost:18443".into()),
        (
            "MARTY_EXTERNAL_OIDC_ISSUER",
            "https://identity.example.invalid".into(),
        ),
        ("MARTY_EXTERNAL_OIDC_CLIENT_ID", "fixture".into()),
        ("MARTY_EXTERNAL_OIDC_ALGORITHMS", "RS256".into()),
    ] {
        values.insert(name.into(), value);
    }
    let layers = bundle.join("deploy-config/compose/selfhost-installer");
    let aws = layers.join("compose.aws-foundation.yml");
    let aws_text = fs::read_to_string(&aws).unwrap();
    let required = regex::Regex::new(r"\$\{([A-Z][A-Z0-9_]*):\?").unwrap();
    for capture in required.captures_iter(&aws_text) {
        let name = &capture[1];
        if values.contains_key(name) {
            continue;
        }
        let value = if name.ends_with("_KEY_ARN") {
            "arn:aws:kms:us-east-2:123456789012:key/10000000-0000-4000-8000-000000000001".into()
        } else if name.ends_with("_REGION") {
            "us-east-2".into()
        } else if name.ends_with("_ROLE_ARN") {
            format!("arn:aws:iam::123456789012:role/{name}")
        } else if name.ends_with("_IDENTITY_DIR") {
            root.join("identities").join(name).to_str().unwrap().into()
        } else {
            panic!("unreviewed fixture variable {name}")
        };
        values.insert(name.into(), value);
    }
    let env = root.join("fixture.env");
    private_write(
        &env,
        values
            .iter()
            .map(|(name, value)| format!("{name}='{value}'\n"))
            .collect::<String>()
            .as_bytes(),
    );
    let base = bundle.join("docker-compose.yml");
    let installer = layers.join("compose.installer.yml");
    let runtime = layers.join("compose.runtime.yml");
    let managed = config(
        &executable,
        &bundle,
        &[base.clone(), installer.clone()],
        &env,
        &["installer-init"],
        &[],
    );
    assert!(managed["services"]["keycloak"].is_object());
    assert_eq!(
        managed["services"]["signing-keys"]["environment"]["DIDCOMM_KMS_TOKEN_FILE"],
        "/run/secrets/didcomm_issuance_openbao_token"
    );
    assert!(managed["services"]["issuance"]["environment"]
        .get("DIDCOMM_KMS_TOKEN_FILE")
        .is_none());
    // The packaging representation change must preserve the existing provider's
    // native environment semantics, including raw dollars and interpolation.
    let original = root.join("native-original.yml");
    private_write(&original, raw.as_bytes());
    let original = config(
        &executable,
        &bundle,
        &[original, installer.clone()],
        &env,
        &["installer-init"],
        &[],
    );
    for (name, service) in managed["services"].as_object().unwrap() {
        assert_eq!(
            service.get("environment"),
            original["services"][name].get("environment"),
            "managed environment changed for {name}"
        );
    }
    let install = config(
        &executable,
        &bundle,
        &[base.clone(), installer.clone(), aws.clone()],
        &env,
        &["installer-init"],
        &[],
    );
    let services = install["services"].as_object().unwrap();
    assert_eq!(services.len(), 27);
    assert_eq!(
        services["gateway"]["environment"]["GATEWAY_OBSERVE_CLIENT_IP"],
        "false"
    );
    for removed in [
        "openbao",
        "openbao-init",
        "openbao-unseal",
        "keycloak",
        "keycloak-configurator",
        "kms-initialize",
    ] {
        assert!(!services.contains_key(removed));
    }
    let mut projected = BTreeSet::new();
    let mut roles = BTreeSet::new();
    for (name, service) in services {
        let environment = service["environment"].as_object().unwrap();
        assert_eq!(environment["AWS_EC2_METADATA_DISABLED"], "true");
        for (key, value) in environment {
            assert!(
                value.is_null()
                    || !(key.starts_with("BAO_")
                        || key.contains("OPENBAO")
                        || key.ends_with("_KMS_TOKEN_FILE")
                        || key.ends_with("_KMS_KEY_NAME")
                        || key.ends_with("_KMS_KEY_VERSION")
                        || key.contains("GRANT_MINT_TOKEN_FILE")
                        || key == "SIGNING_KEYS_GRANT_VERIFY_TOKEN_FILE"),
                "retained {name}/{key}"
            );
        }
        if let Some(role) = environment.get("AWS_ROLE_ARN") {
            assert!(roles.insert(role.as_str().unwrap()));
            assert_eq!(
                environment["AWS_WEB_IDENTITY_TOKEN_FILE"],
                "/run/aws-identity/token"
            );
            let mounts: Vec<_> = service["volumes"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|mount| mount["target"] == "/run/aws-identity")
                .collect();
            assert_eq!(mounts.len(), 1);
            assert_eq!(mounts[0]["read_only"], true);
            assert_eq!(mounts[0]["bind"]["create_host_path"], false);
            assert!(projected.insert(mounts[0]["source"].as_str().unwrap()));
        }
        for secret in service["secrets"].as_array().into_iter().flatten() {
            let source = secret["source"].as_str().unwrap();
            assert!(
                !source.contains("openbao")
                    && !source.contains("keycloak")
                    && !source.ends_with("_kms_token")
            );
        }
    }
    assert_eq!(roles.len(), 18);
    assert_eq!(
        services["auth"]["environment"]["OIDC_PROVIDER_MODE"],
        "external"
    );
    assert!(services["auth"]["environment"]
        .get("KEYCLOAK_ADMIN_URL")
        .is_none());
    assert_eq!(
        services["postgres"]["environment"]["MARTY_INITIALIZE_KEYCLOAK_DATABASE"],
        "false"
    );
    assert_eq!(
        services["issuance"]["entrypoint"],
        serde_json::json!(["/app/services/entrypoint.sh"])
    );
    let restarted = config(
        &executable,
        &bundle,
        &[
            base.clone(),
            installer.clone(),
            runtime.clone(),
            aws.clone(),
        ],
        &env,
        &[],
        &[],
    );
    let restart = restarted["services"].as_object().unwrap();
    let setup: BTreeSet<_> = services
        .iter()
        .filter(|(_, service)| service["labels"]["com.elevenid.installer.phase"] == "setup")
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(
        restart.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        services
            .keys()
            .map(String::as_str)
            .filter(|name| !setup.contains(name))
            .collect()
    );
    for (name, service) in restart {
        for dependency in service["depends_on"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(name, _)| name)
        {
            assert!(
                restart.contains_key(dependency) && !setup.contains(dependency.as_str()),
                "{name} retains setup dependency"
            );
        }
    }
    let bootstrap = config(
        &executable,
        &bundle,
        &[
            base,
            installer,
            runtime,
            aws,
            layers.join("compose.organization-bootstrap.yml"),
        ],
        &env,
        &["setup", "installer-init"],
        &[],
    );
    for name in [
        "installer-organization-key-issue",
        "installer-organization-key-revoke",
    ] {
        let job = &bootstrap["services"][name];
        assert_eq!(job["environment"]["AWS_EC2_METADATA_DISABLED"], "true");
        assert!(job["environment"].get("AWS_ROLE_ARN").is_none());
        assert_eq!(job["read_only"], true);
        assert_eq!(job["cap_drop"], serde_json::json!(["ALL"]));
        assert_eq!(job["user"], "0:0");
    }
}
