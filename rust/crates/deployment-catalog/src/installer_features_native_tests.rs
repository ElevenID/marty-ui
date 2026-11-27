//! Real-parser regression for the full fresh native feature selection.
//! No Docker daemon, container execution, credentials, networked service, or API.

use super::*;
use crate::installer_compose::{BoundFile, COMPOSE_VERSION};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
};

const CORE_BUNDLE_SERVICES: [&str; 28] = [
    "applicant",
    "auth",
    "compliance-profile",
    "credential-template",
    "db-migrate",
    "deployment-profile",
    "device-registration",
    "edge",
    "event-stream",
    "flow",
    "gateway",
    "issuance",
    "issuance-migrations",
    "issuance-native",
    "keycloak",
    "keycloak-configurator",
    "kms-initialize",
    "notification",
    "organization",
    "postgres",
    "presentation-policy",
    "redis",
    "revocation-profile",
    "revocation-profile-migrate",
    "signing-keys",
    "trust-profile",
    "ui",
    "verification",
];

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
fn render_config(
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

fn source_fixture(
    executable: &OsString,
    root: &Path,
    selection: &Selection,
) -> (PathBuf, PathBuf, PathBuf) {
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
        serde_json::from_str(&invoke(executable, &source, root, &arguments)).unwrap();
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
    // The core bundle has 28 named owners after optional tunnel hosting moved
    // into its selected add-on. Compare the complete inventory rather than a
    // stale lower bound that could hide an added or missing application owner.
    assert_eq!(
        services.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from(CORE_BUNDLE_SERVICES)
    );
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
        |stage, arguments| Ok(invoke(executable, stage, root, arguments)),
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
            "MARTY_EXTERNAL_OIDC_ISSUER",
            "https://identity.example.invalid/auth".into(),
        ),
        (
            "MARTY_EXTERNAL_OIDC_CLIENT_ID",
            "config-only-public-client".into(),
        ),
        ("MARTY_EXTERNAL_OIDC_ALGORITHMS", "ES256".into()),
        (
            "MARTY_EXTERNAL_OIDC_TRUSTED_ORIGINS",
            "https://identity.example.invalid".into(),
        ),
        (
            "MARTY_CLOUDFLARED_IMAGE",
            format!(
                "ghcr.io/elevenid/marty-ui-oss/cloudflared-wrapper@sha256:{}",
                "c".repeat(64)
            ),
        ),
        (
            "MARTY_CLOUDFLARE_ADDON_DIR",
            root.join("hosting-cloudflare").to_str().unwrap().into(),
        ),
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
        ("MARTY_ORG_NAME", "Canyon Skills Academy".into()),
        (
            "MARTY_ORG_ID",
            selection
                .configuration
                .agent_trust
                .as_ref()
                .unwrap()
                .organization_id
                .to_string(),
        ),
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
    let mut environment = environment.into_bytes();
    selection
        .append_environment(&mut environment, root, &services)
        .unwrap();
    private_write(&supplied_env, &environment);
    // Render the real optional connector source without creating credentials,
    // authenticating an add-on, pulling its image, or contacting Cloudflare.
    let cloudflare = root.join("compose.cloudflare.yml");
    private_write(
        &cloudflare,
        &fs::read(source.join("deploy-config/compose/selfhost-cloudflare/compose.cloudflare.yml"))
            .unwrap(),
    );
    (bundle, supplied_env, cloudflare)
}

fn full_selection() -> Selection {
    let configuration: Configuration = serde_json::from_value(serde_json::json!({
        "schema": SCHEMA,
        "agent_trust": {
            "organization_id": "00000000-0000-4000-8000-000000000001",
            "enrollment": {
                "audience": "https://api.example.test",
                "policy_profile": "urn:marty:managed-key-enrollment-policy:v1",
                "policy_revision": 1
            },
            "approval": {
                "profile": "urn:marty:organization-approval:v1",
                "version": "1.0.0",
                "status_ref": "https://api.example.test/v1/delegation/status"
            },
            "delegated_use": {"activation": "awaiting_owner_configuration"}
        },
        "workflows": {
            "public_verification": {"activation": "awaiting_owner_configuration"},
            "wallet_governance": {"flow_producer_id": "flow"},
            "verification_prerequisite": true,
            "application_ownership": true,
            "external_associations": true,
            "external_observations": true
        }
    }))
    .unwrap();
    configuration.validate().unwrap();
    Selection {
        schema: SELECTION_SCHEMA.into(),
        installation_id: uuid::Uuid::parse_str("2e052c77-efe8-44c6-9421-9ef15fe8ee7c").unwrap(),
        source_sha256: digest(&serde_json::to_vec(&configuration).unwrap()),
        configuration,
        imports: BTreeMap::new(),
        generation: None,
    }
}

fn selected_inputs(
    installation: &Path,
    bundle: &Path,
    env: &Path,
    cloudflare: &Path,
    selection: &Selection,
    maintenance: bool,
) -> ComposeInputs {
    let base = if maintenance {
        vec![
            "docker-compose.yml",
            "docker-compose.selfhost.openbao.yml",
            "deploy-config/compose/selfhost-installer/compose.bootstrap.yml",
            "deploy-config/compose/selfhost-installer/compose.installer.yml",
            "deploy-config/compose/selfhost-installer/compose.runtime.yml",
        ]
    } else {
        vec![
            "docker-compose.yml",
            "deploy-config/compose/selfhost-installer/compose.installer.yml",
        ]
    };
    let mut inputs = ComposeInputs {
        installation: installation.into(),
        project: format!("marty-install-{}", "a".repeat(32)),
        files: base
            .into_iter()
            .chain([
                "deploy-config/compose/selfhost-installer/compose.external-application-oidc.yml",
                "deploy-config/compose/selfhost-installer/compose.external-oidc.yml",
            ])
            .map(|path| crate::installer_application::bundle_bound(bundle, path).unwrap())
            .collect(),
        bound_inputs: Vec::new(),
        environment: BoundFile {
            path: env.into(),
            sha256: digest(&fs::read(env).unwrap()),
        },
        profiles: if maintenance {
            vec!["setup".into(), "installer-init".into()]
        } else {
            vec!["installer-init".into()]
        },
        services: Vec::new(),
        approved_images: BTreeSet::new(),
        #[cfg(feature = "installer-development")]
        development_image: None,
        writable_bind_roots: BTreeSet::new(),
        readonly_bind_roots: BTreeSet::new(),
        allowed_loopback_ports: BTreeSet::new(),
        ingress_listener: None,
        prior: None,
    };
    // Exercise the shared production builder, including maintenance-only
    // runtime and identity layers, without inventing a parallel layer recipe.
    selection.append_layers(&mut inputs, bundle).unwrap();
    selection.validate_layers(&inputs).unwrap();
    inputs.files.push(BoundFile {
        path: cloudflare.into(),
        sha256: digest(&fs::read(cloudflare).unwrap()),
    });
    inputs
}

fn sort_unique_mounts(model: &mut Value, role: &str) {
    let mounts = model["services"][role]["volumes"].as_array_mut().unwrap();
    let targets: BTreeSet<_> = mounts
        .iter()
        .map(|mount| mount["target"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        targets.len(),
        mounts.len(),
        "duplicate mount target on {role}"
    );
    mounts.sort_by_key(|mount| serde_json::to_string(mount).unwrap());
}

fn assert_credential_denials(configuration: &workflows::Configuration, model: &Value) {
    for role in ["issuance", "issuance-native"] {
        for key in [
            "DATABASE_URL",
            "DATABASE_URL_TEMPLATE",
            "MARTY_DB_PASSWORD",
            "MARTY_DB_PASSWORD_FILE",
        ] {
            let mut wrong = model.clone();
            wrong["services"][role]["environment"][key] =
                serde_json::json!("forbidden-config-only-fixture");
            assert!(
                configuration.validate_model(&wrong).is_err(),
                "{role} accepted {key}"
            );
        }
        for (key, value) in [
            ("DATABASE_URL_FILE", "/run/secrets/marty_db_password"),
            ("PGSSLROOTCERT", "/run/secrets/unrelated_ca"),
            ("MARTY_SCHEMA_STARTUP_MODE", "migrate"),
        ] {
            let mut wrong = model.clone();
            wrong["services"][role]["environment"][key] = serde_json::json!(value);
            assert!(
                configuration.validate_model(&wrong).is_err(),
                "{role} accepted changed {key}"
            );
        }
        let mut wrong = model.clone();
        wrong["services"][role]["secrets"].as_array_mut().unwrap().push(
            serde_json::json!({"source":"marty_db_password","target":"/run/secrets/marty_db_password"})
        );
        assert!(
            configuration.validate_model(&wrong).is_err(),
            "{role} accepted broad secret"
        );
        let broad = model["secrets"]["marty_db_password"]["file"]
            .as_str()
            .unwrap();
        for (source, target) in [
            (broad, "/run/alternate"),
            (
                Path::new(broad).parent().unwrap().to_str().unwrap(),
                "/run/alternate",
            ),
            ("/config-only-unrelated", "/run/secrets"),
        ] {
            let mut wrong = model.clone();
            wrong["services"][role]["volumes"]
                .as_array_mut()
                .unwrap()
                .push(
                    serde_json::json!({"type":"bind","source":source,"target":target,
                    "read_only":true,"bind":{"create_host_path":false}}),
                );
            assert!(
                configuration.validate_model(&wrong).is_err(),
                "{role} accepted broad bind"
            );
        }
    }
}

#[test]
#[ignore = "requires the separately hash-pinned standalone Compose 5.6.1; config only"]
fn native_compose_full_profile_keeps_restricted_issuance_credentials() {
    let executable = executable();
    let temp = PrivateFixture::new();
    let root = temp.path();
    baseline(&executable, root);
    let selection = full_selection();
    let workflows = selection.configuration.workflows.as_ref().unwrap();
    let (bundle, env, cloudflare) = source_fixture(&executable, root, &selection);
    for maintenance in [false, true] {
        let inputs = selected_inputs(root, &bundle, &env, &cloudflare, &selection, maintenance);
        let files: Vec<_> = inputs.files.iter().map(|file| file.path.clone()).collect();
        if !maintenance {
            assert_eq!(files.len(), 15, "full first-application selection changed");
        }
        let profiles: Vec<_> = inputs.profiles.iter().map(String::as_str).collect();
        let fixed = render_config(&executable, &bundle, &files, &env, &profiles, &[]);
        assert!(fixed["services"].get("issuance").is_some());
        assert!(fixed["services"].get("issuance-native").is_some());
        assert!(fixed["services"].get("cloudflared").is_some());
        assert!(fixed["services"].get("ui").is_none());
        assert!(fixed["services"].get("keycloak").is_none());
        if !maintenance {
            assert_eq!(fixed["services"].as_object().unwrap().len(), 33);
        }
        // This is the actual workflow admission guard, not a second copy of its
        // predicates. No retained credentials or runtime admission are invented.
        workflows.validate_model(&fixed).unwrap();
        assert_credential_denials(workflows, &fixed);

        // Reconstruct the pre-fix order using exactly the same packaged bytes
        // and environment: database and prerequisite maps preceded the reset.
        let mut old_files = files.clone();
        let reset_index = old_files
            .iter()
            .position(|path| path.ends_with("compose.workflow-issuance.yml"))
            .unwrap();
        let reset = old_files.remove(reset_index);
        let after_prerequisite = old_files
            .iter()
            .position(|path| path.ends_with("compose.workflow-prerequisite.yml"))
            .unwrap()
            + 1;
        old_files.insert(after_prerequisite, reset);
        assert_ne!(old_files, files);
        let old = render_config(&executable, &bundle, &old_files, &env, &profiles, &[]);
        assert!(
            workflows.validate_model(&old).is_err(),
            "late reset unexpectedly admitted"
        );
        let mut expected = old;
        let mut actual = fixed;
        for role in ["issuance", "issuance-native"] {
            for key in ["DATABASE_URL_TEMPLATE", "MARTY_DB_PASSWORD_FILE"] {
                let environment = expected["services"][role]["environment"]
                    .as_object_mut()
                    .unwrap();
                assert!(
                    environment
                        .get(key)
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty()),
                    "old order did not reproduce {role} {key}"
                );
                environment.remove(key);
            }
            for key in [
                "DATABASE_URL",
                "DATABASE_URL_TEMPLATE",
                "MARTY_DB_PASSWORD",
                "MARTY_DB_PASSWORD_FILE",
            ] {
                assert!(
                    actual["services"][role]["environment"].get(key).is_none(),
                    "{role} retained {key}"
                );
            }
            // Moving a merge layer may reorder volume arrays. Their complete
            // entries and unique target sets must be identical after sorting.
            sort_unique_mounts(&mut expected, role);
            sort_unique_mounts(&mut actual, role);
        }
        assert_eq!(
            expected, actual,
            "changed more than four forbidden fields or mount order"
        );
    }
}
