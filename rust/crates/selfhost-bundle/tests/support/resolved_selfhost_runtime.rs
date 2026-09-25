//! Stage A only: real extracted Compose configuration, never process startup.
//! Secret files remain mount identities and raw selectors, not loaded values.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

const ERROR: &str = "Closed selfhost runtime model refused";
type Result<T> = std::result::Result<T, &'static str>;
const OWNERS: &[&str] = &["issuance-native", "gateway", "flow"];
const SOURCES: &[&str] = &[
    "docker-compose.selfhost.prod.yml",
    "docker-compose.selfhost.bundle.override.yml",
    "docker-compose.service.issuance-native-runtime.yml",
    "deploy-config/bundles/selfhost.json",
    "scripts/load-secrets-env.sh",
    "services/entrypoint.sh",
];
const READY: &str = "auth,organizations,credential-templates,trust-profiles,presentation-policies,deployment-profiles,signing-keys,flows,issuance,issuance-native";
const DATABASE_TEMPLATE: &str =
    "postgresql+asyncpg://marty:$${MARTY_DB_PASSWORD}@postgres:5432/marty";

#[track_caller]
fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        eprintln!(
            "Closed model guard rejected at {}",
            std::panic::Location::caller()
        );
        Err(ERROR)
    }
}
fn object(value: &Value) -> Result<&serde_json::Map<String, Value>> {
    value.as_object().ok_or(ERROR)
}
fn text(value: &Value) -> Result<&str> {
    value.as_str().ok_or(ERROR)
}
fn path_text(path: &Path) -> Result<String> {
    Ok(path.to_str().ok_or(ERROR)?.replace('\\', "/"))
}
fn bounded_file(path: &Path) -> Vec<u8> {
    use std::io::Read;
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    let mut bytes = Vec::new();
    fs::File::open(path)
        .unwrap()
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 8 * 1024 * 1024);
    bytes
}
fn hashes(root: &Path) -> BTreeMap<String, String> {
    SOURCES
        .iter()
        .map(|name| {
            (
                (*name).into(),
                format!("{:x}", Sha256::digest(bounded_file(&root.join(name)))),
            )
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Role {
    NativeHttp,
    NativeGrpc,
    GatewayHttp,
    FlowHttp,
    FlowGrpc,
    AuthHttp,
    AuthGrpc,
    OrganizationHttp,
    OrganizationGrpc,
    TemplateHttp,
    TemplateGrpc,
    PolicyHttp,
    PolicyGrpc,
    TrustHttp,
    ApplicantHttp,
    NotificationHttp,
    ComplianceHttp,
    DeploymentHttp,
    DeviceHttp,
    RevocationHttp,
    RevocationGrpc,
    SigningHttp,
    EventGrpc,
    LegacyHttp,
    Database,
    Redis,
}
const ROLES: &[Role] = &[
    Role::NativeHttp,
    Role::NativeGrpc,
    Role::GatewayHttp,
    Role::FlowHttp,
    Role::FlowGrpc,
    Role::AuthHttp,
    Role::AuthGrpc,
    Role::OrganizationHttp,
    Role::OrganizationGrpc,
    Role::TemplateHttp,
    Role::TemplateGrpc,
    Role::PolicyHttp,
    Role::PolicyGrpc,
    Role::TrustHttp,
    Role::ApplicantHttp,
    Role::NotificationHttp,
    Role::ComplianceHttp,
    Role::DeploymentHttp,
    Role::DeviceHttp,
    Role::RevocationHttp,
    Role::RevocationGrpc,
    Role::SigningHttp,
    Role::EventGrpc,
    Role::LegacyHttp,
    Role::Database,
    Role::Redis,
];

/// No arbitrary URLs, credentials, paths or hostnames are accepted by this seam.
/// The later owner must prove these ports belong to its isolated namespace.
pub(super) struct OwnedEndpoints(pub(super) BTreeMap<Role, u16>);
impl OwnedEndpoints {
    fn validate(&self) -> Result<()> {
        require(
            self.0.keys().copied().collect::<BTreeSet<_>>() == ROLES.iter().copied().collect(),
        )?;
        require(self.0.values().all(|port| *port != 0))?;
        require(self.0.values().collect::<BTreeSet<_>>().len() == self.0.len())
    }
    fn port(&self, role: Role) -> u16 {
        self.0[&role]
    }
}

// Only this explicit field roster is mapped. Full model identity is checked
// before this seam; absent/misbound sources must never become valid fixtures.
const MAPPINGS: &[(&str, &str, Role, &str)] = &[
    (
        "issuance-native",
        "ORG_GRPC_TARGET",
        Role::OrganizationGrpc,
        "organization:9002",
    ),
    (
        "issuance-native",
        "CT_GRPC_TARGET",
        Role::TemplateGrpc,
        "credential-template:9003",
    ),
    (
        "issuance-native",
        "RP_GRPC_TARGET",
        Role::RevocationGrpc,
        "revocation-profile:9013",
    ),
    (
        "issuance-native",
        "CREDENTIAL_TEMPLATE_SERVICE_URL",
        Role::TemplateHttp,
        "http://credential-template:8003",
    ),
    (
        "issuance-native",
        "REVOCATION_PROFILE_SERVICE_URL",
        Role::RevocationHttp,
        "http://revocation-profile:8013",
    ),
    (
        "issuance-native",
        "SIGNING_KEYS_INTERNAL_URL",
        Role::GatewayHttp,
        "http://gateway:8000/internal/signing-keys",
    ),
    (
        "gateway",
        "AUTH_SERVICE_URL",
        Role::AuthHttp,
        "http://auth:8001",
    ),
    (
        "gateway",
        "ORGANIZATION_SERVICE_URL",
        Role::OrganizationHttp,
        "http://organization:8002",
    ),
    (
        "gateway",
        "CREDENTIAL_TEMPLATE_SERVICE_URL",
        Role::TemplateHttp,
        "http://credential-template:8003",
    ),
    (
        "gateway",
        "TRUST_PROFILE_SERVICE_URL",
        Role::TrustHttp,
        "http://trust-profile:8004",
    ),
    (
        "gateway",
        "APPLICANT_SERVICE_URL",
        Role::ApplicantHttp,
        "http://applicant:8006",
    ),
    (
        "gateway",
        "NOTIFICATION_SERVICE_URL",
        Role::NotificationHttp,
        "http://notification:8007",
    ),
    (
        "gateway",
        "COMPLIANCE_PROFILE_SERVICE_URL",
        Role::ComplianceHttp,
        "http://compliance-profile:8008",
    ),
    (
        "gateway",
        "PRESENTATION_POLICY_SERVICE_URL",
        Role::PolicyHttp,
        "http://presentation-policy:8009",
    ),
    (
        "gateway",
        "DEPLOYMENT_PROFILE_SERVICE_URL",
        Role::DeploymentHttp,
        "http://deployment-profile:8010",
    ),
    (
        "gateway",
        "FLOW_SERVICE_URL",
        Role::FlowHttp,
        "http://flow:8011",
    ),
    (
        "gateway",
        "DEVICE_REGISTRATION_SERVICE_URL",
        Role::DeviceHttp,
        "http://device-registration:8014",
    ),
    (
        "gateway",
        "ISSUANCE_SERVICE_URL",
        Role::LegacyHttp,
        "http://issuance:8005",
    ),
    (
        "gateway",
        "ISSUANCE_NATIVE_SERVICE_URL",
        Role::NativeHttp,
        "http://issuance-native:8005",
    ),
    (
        "gateway",
        "REVOCATION_PROFILE_SERVICE_URL",
        Role::RevocationHttp,
        "http://revocation-profile:8013",
    ),
    (
        "gateway",
        "SIGNING_KEYS_SERVICE_URL",
        Role::SigningHttp,
        "http://signing-keys:8017",
    ),
    ("gateway", "AUTH_GRPC_TARGET", Role::AuthGrpc, "auth:9001"),
    (
        "gateway",
        "ORG_GRPC_TARGET",
        Role::OrganizationGrpc,
        "organization:9002",
    ),
    (
        "flow",
        "ORG_GRPC_TARGET",
        Role::OrganizationGrpc,
        "organization:9002",
    ),
    (
        "flow",
        "PP_GRPC_TARGET",
        Role::PolicyGrpc,
        "presentation-policy:9009",
    ),
    (
        "flow",
        "CT_GRPC_TARGET",
        Role::TemplateGrpc,
        "credential-template:9003",
    ),
    (
        "flow",
        "ISSUANCE_GRPC_TARGET",
        Role::NativeGrpc,
        "issuance-native:9005",
    ),
    (
        "flow",
        "ISSUANCE_SERVICE_URL",
        Role::LegacyHttp,
        "http://issuance:8005",
    ),
    (
        "flow",
        "CREDENTIAL_TEMPLATE_SERVICE_URL",
        Role::TemplateHttp,
        "http://credential-template:8003",
    ),
    (
        "flow",
        "TRUST_PROFILE_SERVICE_URL",
        Role::TrustHttp,
        "http://trust-profile:8004",
    ),
    (
        "flow",
        "DEPLOYMENT_PROFILE_SERVICE_URL",
        Role::DeploymentHttp,
        "http://deployment-profile:8010",
    ),
    (
        "flow",
        "SIGNING_KEYS_INTERNAL_URL",
        Role::SigningHttp,
        "http://signing-keys:8017/internal",
    ),
];

fn expected_secrets(owner: &str) -> BTreeSet<&'static str> {
    match owner {
        "issuance-native" => [
            "marty_db_password",
            "issuance_api_key",
            "integration_secret_master_key",
            "token_hmac_key",
            "canvas_credentials_shared_secret",
            "grpc_service_token",
        ]
        .into_iter()
        .collect(),
        "gateway" => [
            "issuance_api_key",
            "openbao_service_token",
            "grpc_service_token",
        ]
        .into_iter()
        .collect(),
        "flow" => [
            "marty_db_password",
            "grpc_service_token",
            "flow_workload_client_cert",
            "flow_workload_client_key",
            "flow_workload_server_cert",
            "flow_workload_server_key",
            "workload_identity_ca_cert",
            "flow_webhook_secret",
            "flow_application_event_hmac_key",
            "issuance_api_key",
        ]
        .into_iter()
        .collect(),
        _ => unreachable!(),
    }
}

fn secret_field(key: &str) -> Result<&'static str> {
    match key {
        "MARTY_DB_PASSWORD_FILE" => Ok("marty_db_password"),
        "GRPC_SERVICE_TOKEN_FILE" => Ok("grpc_service_token"),
        "ISSUANCE_API_KEY_FILE" | "SIGNING_KEYS_INTERNAL_API_KEY_FILE" => Ok("issuance_api_key"),
        "INTEGRATION_SECRET_MASTER_KEY_FILE" => Ok("integration_secret_master_key"),
        "TOKEN_HMAC_KEY_FILE" => Ok("token_hmac_key"),
        "CANVAS_CREDENTIALS_SHARED_SECRET_FILE" => Ok("canvas_credentials_shared_secret"),
        "BAO_TOKEN_FILE" => Ok("openbao_service_token"),
        "FLOW_WEBHOOK_SECRET_FILE" => Ok("flow_webhook_secret"),
        "FLOW_APPLICATION_EVENT_HMAC_KEY_FILE" => Ok("flow_application_event_hmac_key"),
        "GRPC_WORKLOAD_TLS_CLIENT_CERT" => Ok("flow_workload_client_cert"),
        "GRPC_WORKLOAD_TLS_CLIENT_KEY" => Ok("flow_workload_client_key"),
        "GRPC_WORKLOAD_TLS_SERVER_CERT" => Ok("flow_workload_server_cert"),
        "GRPC_WORKLOAD_TLS_SERVER_KEY" => Ok("flow_workload_server_key"),
        "GRPC_WORKLOAD_TLS_CA_CERT" => Ok("workload_identity_ca_cert"),
        _ => Err(ERROR),
    }
}

pub(super) struct ClosedSelfhostModel {
    pub(super) full_model: Value,
    secret_directory: PathBuf,
    model_hash: String,
}
/// Compose serialization, NOT environment ready for direct process/Docker use.
pub(super) struct RawComposeRuntime {
    pub(super) environments: BTreeMap<String, BTreeMap<String, String>>,
    pub(super) secret_mounts: BTreeMap<String, BTreeMap<String, PathBuf>>,
}
impl ClosedSelfhostModel {
    /// `expected` is separately rendered source+bundle override, not a projection
    /// of the observed extracted output. Neither argument contains loaded secrets.
    fn from_rendered(expected: &Value, actual: Value, secret_directory: &Path) -> Result<Self> {
        require(expected == &actual)?;
        let model_hash = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(expected).map_err(|_| ERROR)?)
        );
        let model = Self {
            full_model: actual,
            secret_directory: secret_directory.to_owned(),
            model_hash,
        };
        model.validate()?;
        Ok(model)
    }
    fn validate(&self) -> Result<()> {
        require(
            self.model_hash
                == format!(
                    "{:x}",
                    Sha256::digest(serde_json::to_vec(&self.full_model).map_err(|_| ERROR)?)
                ),
        )?;
        let services = object(&self.full_model["services"])?;
        for owner in OWNERS {
            let service = services.get(*owner).ok_or(ERROR)?;
            require(service.get("build").is_none() && service.get("env_file").is_none())?;
            require(
                service["image"] == "ghcr.io/elevenid/marty-ui/services:synthetic-immutable-v1",
            )?;
            let environment = object(&service["environment"])?;
            require(environment.values().all(|value| value.is_string()))?;
            require(environment.get("ENVIRONMENT") == Some(&json!("production")))?;
            require(environment.get("SERVICE_NAME") == Some(&json!(owner.replace('-', "_"))))?;
            let passport_selector = match *owner {
                "gateway" => "PASSPORT_NATIVE_GATEWAY_ENABLED",
                "flow" => "PASSPORT_NATIVE_FLOW_ENABLED",
                "issuance-native" => "PASSPORT_NATIVE_HTTP_ENABLED",
                _ => unreachable!(),
            };
            // This released selfhost fixture is deliberately default-off. The
            // optional empty file selector is not a mounted secret; selecting
            // passport later requires a separate qualified secret overlay.
            require(environment.get(passport_selector) == Some(&json!("false")))?;
            require(environment.get("PASSPORT_TENANT_API_KEYS") == Some(&json!("")))?;
            require(environment.get("PASSPORT_TENANT_API_KEYS_FILE") == Some(&json!("")))?;
            for raw in [
                "ISSUANCE_API_KEY",
                "SIGNING_KEYS_INTERNAL_API_KEY",
                "GRPC_SERVICE_TOKEN",
                "MARTY_DB_PASSWORD",
                "DATABASE_URL",
                "INTEGRATION_SECRET_MASTER_KEY",
                "TOKEN_HMAC_KEY",
            ] {
                require(!environment.contains_key(raw))?;
            }
            for key in [
                "ISSUANCE_API_KEY_FILE",
                "SIGNING_KEYS_INTERNAL_API_KEY_FILE",
            ] {
                require(environment.get(key) == Some(&json!("/run/secrets/issuance_api_key")))?;
            }
            let mut mounts = BTreeSet::new();
            for mount in service["secrets"].as_array().ok_or(ERROR)? {
                let source = text(&mount["source"])?;
                require(
                    object(mount)?
                        .keys()
                        .all(|key| ["source", "target"].contains(&key.as_str())),
                )?;
                require(mounts.insert(source))?;
                require(mount["target"] == format!("/run/secrets/{source}"))?;
                require(
                    self.full_model["secrets"][source]["file"]
                        == path_text(&self.secret_directory.join(source))?,
                )?;
            }
            require(mounts == expected_secrets(owner))?;
            for (key, value) in environment {
                if key == "PASSPORT_TENANT_API_KEYS_FILE" {
                    continue;
                }
                if key.ends_with("_FILE") || key.starts_with("GRPC_WORKLOAD_TLS_") {
                    let source = text(value)?.strip_prefix("/run/secrets/").ok_or(ERROR)?;
                    require(mounts.contains(source) && source == secret_field(key)?)?;
                }
            }
        }
        let native = &services["issuance-native"];
        for owner in ["gateway", "flow"] {
            for field in ["entrypoint", "command"] {
                require(services[owner].get(field).is_none_or(Value::is_null))?;
            }
        }
        require(
            native["entrypoint"] == json!(["/app/services/entrypoint.sh"])
                && native["command"] == json!([]),
        )?;
        require(native["environment"]["DIDCOMM_ALLOW_PRIVATE_IPS"] == "false")?;
        require(
            !object(&native["environment"])?
                .keys()
                .any(|key| key.starts_with("BAO_") || key.starts_with("OPENBAO_")),
        )?;
        require(services["gateway"]["environment"]["GATEWAY_REQUIRED_READY_SERVICES"] == READY)?;
        require(services["gateway"]["environment"]["REDIS_DB_GATEWAY"] == "2")?;
        require(services["flow"]["environment"]["REDIS_DB_FLOW"] == "3")?;
        for owner in ["issuance-native", "flow"] {
            require(services[owner]["environment"]["DATABASE_URL_TEMPLATE"] == DATABASE_TEMPLATE)?;
            require(
                services[owner]["environment"]["DATABASE_URL_TEMPLATE"]
                    == self.full_model["x-database-url-template"],
            )?;
        }
        for (owner, key, _, original) in MAPPINGS {
            require(services[*owner]["environment"][*key] == *original)?;
        }
        Ok(())
    }
    pub(super) fn map_owned_endpoints(
        &self,
        endpoints: &OwnedEndpoints,
    ) -> Result<RawComposeRuntime> {
        self.validate()?;
        endpoints.validate()?;
        let mut environments = BTreeMap::new();
        let mut secret_mounts = BTreeMap::new();
        for owner in OWNERS {
            let mut environment: BTreeMap<String, String> =
                serde_json::from_value(self.full_model["services"][owner]["environment"].clone())
                    .map_err(|_| ERROR)?;
            for (_, key, role, original) in MAPPINGS.iter().filter(|(service, ..)| service == owner)
            {
                let target = if original.starts_with("http://") {
                    let path = original
                        .trim_start_matches("http://")
                        .split_once('/')
                        .map_or("".into(), |(_, path)| format!("/{path}"));
                    format!("http://127.0.0.1:{}{path}", endpoints.port(*role))
                } else {
                    format!("127.0.0.1:{}", endpoints.port(*role))
                };
                environment.insert((*key).into(), target);
            }
            require(environment["ES_GRPC_TARGET"] == "event-stream:9015")?;
            environment.insert(
                "ES_GRPC_TARGET".into(),
                format!("127.0.0.1:{}", endpoints.port(Role::EventGrpc)),
            );
            if *owner != "gateway" {
                let prefix = environment["DATABASE_URL_TEMPLATE"]
                    .strip_suffix("@postgres:5432/marty")
                    .ok_or(ERROR)?;
                let mapped = format!(
                    "{prefix}@127.0.0.1:{}/marty",
                    endpoints.port(Role::Database)
                );
                environment.insert("DATABASE_URL_TEMPLATE".into(), mapped);
            }
            if *owner != "issuance-native" {
                require(environment["REDIS_URL"] == "redis://redis:6379")?;
                environment.insert(
                    "REDIS_URL".into(),
                    format!("redis://127.0.0.1:{}", endpoints.port(Role::Redis)),
                );
            }
            for (service, key, original, role) in [
                (
                    "issuance-native",
                    "ISSUANCE_SERVICE_PORT",
                    "8005",
                    Role::NativeHttp,
                ),
                (
                    "issuance-native",
                    "ISSUANCE_GRPC_PORT",
                    "9005",
                    Role::NativeGrpc,
                ),
                ("gateway", "GATEWAY_PORT", "8000", Role::GatewayHttp),
                ("flow", "FLOW_SERVICE_PORT", "8011", Role::FlowHttp),
                ("flow", "FLOW_GRPC_PORT", "9011", Role::FlowGrpc),
            ] {
                if *owner == service {
                    require(environment[key] == original)?;
                    environment.insert(key.into(), endpoints.port(role).to_string());
                }
            }
            let mounts = expected_secrets(owner)
                .into_iter()
                .map(|source| {
                    (
                        format!("/run/secrets/{source}"),
                        self.secret_directory.join(source),
                    )
                })
                .collect();
            environments.insert((*owner).into(), environment);
            secret_mounts.insert((*owner).into(), mounts);
        }
        Ok(RawComposeRuntime {
            environments,
            secret_mounts,
        })
    }
}

// Normalize ONLY parsed Compose local file fields. Business settings are never
// string-replaced, and unknown source/extraction path leakage fails full equality.
fn normalize_model(mut model: Value, root: &Path) -> Result<Value> {
    fn local(value: &mut Value, root: &Path) -> Result<()> {
        let path = Path::new(text(value)?);
        if let Ok(relative) = path.strip_prefix(root) {
            require(
                relative
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_))),
            )?;
            *value = json!(format!("$BUNDLE/{}", path_text(relative)?));
        }
        Ok(())
    }
    for section in ["secrets", "configs"] {
        if let Some(entries) = model.get_mut(section) {
            for item in entries.as_object_mut().ok_or(ERROR)?.values_mut() {
                if let Some(file) = item.get_mut("file") {
                    local(file, root)?;
                }
            }
        }
    }
    for service in model["services"].as_object_mut().ok_or(ERROR)?.values_mut() {
        if let Some(volumes) = service.get_mut("volumes") {
            for volume in volumes.as_array_mut().ok_or(ERROR)? {
                if volume["type"] == "bind" {
                    local(&mut volume["source"], root)?;
                }
            }
        }
    }
    Ok(model)
}

/// Owns original Compose representation and its independently checked view.
/// Only the original representation can be handed back to Compose for creation.
pub(super) struct PreparedCompose {
    owned: tempfile::TempDir,
    source_root: PathBuf,
    source_hashes: BTreeMap<String, String>,
    raw_model: Value,
    raw_hash: String,
    model: ClosedSelfhostModel,
    pub(super) secret_directory: PathBuf,
}
impl PreparedCompose {
    pub(super) fn raw_model(&self) -> &Value {
        self.verify_sources();
        &self.raw_model
    }
    pub(super) fn directory(&self) -> &Path {
        self.owned.path()
    }
    pub(super) fn retain_for_parent(&mut self, parent: &Path) {
        assert!(self.owned.path().starts_with(parent));
        assert_ne!(self.owned.path(), parent);
        self.owned.disable_cleanup(true);
    }
    /// Preserve synthetic inputs when a runtime owner could not verify cleanup.
    pub(super) fn finish(self, retain: bool) -> Option<PathBuf> {
        retain.then(|| self.owned.keep())
    }
    pub(super) fn verify_sources(&self) {
        assert_eq!(
            self.source_hashes,
            hashes(&self.source_root),
            "Source identities retained throughout rendering"
        );
        assert_eq!(
            self.raw_hash,
            format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&self.raw_model).unwrap())
            )
        );
    }
}

pub(super) fn prepare(repo: &Path, extracted: &Path) -> PreparedCompose {
    let source_hashes = hashes(repo);
    let source: serde_yaml::Value = serde_yaml::from_slice(&bounded_file(
        &repo.join("docker-compose.selfhost.prod.yml"),
    ))
    .unwrap();
    let project = source["name"]
        .as_str()
        .expect("Source-declared default project name");
    let owned = tempfile::tempdir().unwrap();
    let secret_directory = owned.path().join("synthetic-secrets");
    fs::create_dir(&secret_directory).unwrap();
    let env_file = owned.path().join("synthetic.env");
    let mut inputs: BTreeMap<String, String> = [
        ("SELFHOST_IMAGE_TAG", "synthetic-immutable-v1"),
        ("KEYCLOAK_SOCIAL_LOGIN_ENABLED", "false"),
        ("CORS_ORIGINS", "https://issuer.example"),
        (
            "FLOW_CALLBACK_DESTINATIONS",
            "synthetic-org|https://callback.example/result?nonce=__MARTY_TOKEN__",
        ),
        (
            "OIDC_ISSUER_URL_EXTERNAL",
            "https://identity.example/realms/synthetic",
        ),
        (
            "OIDC_REDIRECT_URI",
            "https://issuer.example/v1/auth/callback",
        ),
        ("OIDC_POST_LOGOUT_REDIRECT_URI", "https://issuer.example"),
        ("UI_BASE_URL", "https://issuer.example"),
        ("PUBLIC_API_URL", "https://issuer.example"),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect();
    inputs.insert(
        "MARTY_ISSUANCE_IMAGE".into(),
        format!("synthetic.invalid/issuance@sha256:{}", "a".repeat(64)),
    );
    inputs.insert(
        "SELFHOST_SECRET_DIR".into(),
        path_text(&secret_directory).unwrap(),
    );
    inputs.insert(
        "SELFHOST_STATE_DIR".into(),
        path_text(&owned.path().join("unused-state")).unwrap(),
    );
    fs::write(
        &env_file,
        inputs
            .iter()
            .map(|(key, value)| format!("{key}={value}\n"))
            .collect::<String>(),
    )
    .unwrap();
    let executable = std::env::var_os("MARTY_SELFHOST_BUNDLE_TEST_COMPOSE");
    let renderer = PathBuf::from(
        executable
            .as_ref()
            .expect("Stage A requires the explicit pinned standalone Compose renderer"),
    );
    #[cfg(target_os = "linux")]
    assert_eq!(
        format!("{:x}", Sha256::digest(fs::read(&renderer).unwrap())),
        "837fd1d35bf6a494f41b5b5988269a7be79de337cf1a1a6ff0e45ab51bb4e9be"
    );
    assert!(renderer.is_file());
    let version = marty_selfhost_bundle::process::compose(
        extracted,
        &["version".into(), "--short".into()],
        executable.as_ref(),
    )
    .unwrap();
    assert_eq!(
        version.trim(),
        "5.4.0",
        "Mandatory runtime model uses pinned Compose"
    );
    let render = |root: &Path, files: &[&str]| {
        let mut args = vec![
            "--env-file".into(),
            path_text(&env_file).unwrap(),
            "--project-name".into(),
            project.into(),
        ];
        for file in files {
            args.extend(["-f".into(), (*file).into()]);
        }
        args.extend(["config".into(), "--format".into(), "json".into()]);
        let result =
            marty_selfhost_bundle::process::compose(root, &args, executable.as_ref()).unwrap();
        serde_json::from_str::<Value>(&result).unwrap()
    };
    let expected = normalize_model(
        render(
            repo,
            &[
                "docker-compose.selfhost.prod.yml",
                "docker-compose.selfhost.bundle.override.yml",
            ],
        ),
        repo,
    )
    .unwrap();
    let raw_model = render(extracted, &["docker-compose.yml"]);
    let actual = normalize_model(raw_model.clone(), extracted).unwrap();
    if expected != actual {
        for (section, value) in expected.as_object().unwrap() {
            if actual.get(section) == Some(value) {
                continue;
            }
            eprintln!("Synthetic model differs in section {section}");
            if section == "services" {
                for (owner, service) in value.as_object().unwrap() {
                    for (field, setting) in service.as_object().unwrap() {
                        if actual[section][owner].get(field) != Some(setting) {
                            eprintln!("Synthetic model differs in service {owner} field {field}");
                        }
                    }
                }
            }
        }
    }
    let model = ClosedSelfhostModel::from_rendered(&expected, actual, &secret_directory).unwrap();
    let raw_hash = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&raw_model).unwrap())
    );
    PreparedCompose {
        owned,
        source_root: repo.to_owned(),
        source_hashes,
        raw_model,
        raw_hash,
        model,
        secret_directory,
    }
}

#[test]
fn prepared_inputs_survive_child_unwind_until_parent_removes_scratch() {
    // Cleanup-only owner control: this intentionally does not qualify a model.
    let parent = tempfile::tempdir().unwrap();
    let owned = tempfile::tempdir_in(parent.path()).unwrap();
    let root = owned.path().to_owned();
    let secret_directory = root.join("synthetic-secrets");
    fs::create_dir(&secret_directory).unwrap();
    fs::write(secret_directory.join("synthetic"), "retained-input").unwrap();
    let mut prepared = PreparedCompose {
        owned,
        source_root: root.clone(),
        source_hashes: BTreeMap::new(),
        raw_model: Value::Null,
        raw_hash: String::new(),
        secret_directory: secret_directory.clone(),
        model: ClosedSelfhostModel {
            full_model: Value::Null,
            secret_directory,
            model_hash: String::new(),
        },
    };
    prepared.retain_for_parent(parent.path());
    assert!(std::panic::catch_unwind(move || {
        let _prepared = prepared;
        panic!("controlled child unwind");
    })
    .is_err());
    assert_eq!(
        fs::read(root.join("synthetic-secrets/synthetic")).unwrap(),
        b"retained-input"
    );
    parent.close().unwrap();
    assert!(!root.exists());
}

pub(super) fn qualify(repo: &Path, extracted: &Path) {
    let prepared = prepare(repo, extracted);
    let model = &prepared.model;
    let expected = model.full_model.clone();
    let secret_directory = &prepared.secret_directory;
    // Exercise the raw handoff, without normalizing it into process environment.
    assert!(prepared.directory().is_dir());
    assert_eq!(
        prepared.raw_model()["services"]["issuance-native"]["environment"]["DATABASE_URL_TEMPLATE"],
        DATABASE_TEMPLATE
    );
    let endpoints = OwnedEndpoints(
        ROLES
            .iter()
            .enumerate()
            .map(|(index, role)| (*role, 22000 + index as u16))
            .collect(),
    );
    let mapped = model.map_owned_endpoints(&endpoints).unwrap();
    for owner in OWNERS {
        assert_eq!(mapped.environments[*owner]["ENVIRONMENT"], "production");
        for (key, value) in object(&model.full_model["services"][owner]["environment"]).unwrap() {
            if key.ends_with("_FILE") || key.starts_with("GRPC_WORKLOAD_TLS_") {
                assert_eq!(mapped.environments[*owner][key], text(value).unwrap());
            }
        }
        assert_eq!(
            mapped.secret_mounts[*owner].len(),
            expected_secrets(owner).len()
        );
        let mut allowed: BTreeSet<&str> = MAPPINGS
            .iter()
            .filter(|(service, ..)| service == owner)
            .map(|(_, key, ..)| *key)
            .collect();
        allowed.insert("ES_GRPC_TARGET");
        match *owner {
            "issuance-native" => {
                allowed.extend([
                    "DATABASE_URL_TEMPLATE",
                    "ISSUANCE_SERVICE_PORT",
                    "ISSUANCE_GRPC_PORT",
                ]);
            }
            "gateway" => {
                allowed.extend(["REDIS_URL", "GATEWAY_PORT"]);
            }
            "flow" => {
                allowed.extend([
                    "DATABASE_URL_TEMPLATE",
                    "REDIS_URL",
                    "FLOW_SERVICE_PORT",
                    "FLOW_GRPC_PORT",
                ]);
            }
            _ => unreachable!(),
        }
        let original = object(&model.full_model["services"][owner]["environment"]).unwrap();
        assert_eq!(
            original.keys().collect::<BTreeSet<_>>(),
            mapped.environments[*owner].keys().collect()
        );
        for (key, value) in original {
            if !allowed.contains(key.as_str()) {
                assert_eq!(mapped.environments[*owner][key], text(value).unwrap());
            }
        }
    }
    for owner in ["issuance-native", "flow"] {
        assert_eq!(
            mapped.environments[owner]["DATABASE_URL_TEMPLATE"],
            format!(
                "postgresql+asyncpg://marty:$${{MARTY_DB_PASSWORD}}@127.0.0.1:{}/marty",
                endpoints.port(Role::Database)
            )
        );
    }
    assert_ne!(
        mapped.environments["flow"]["ISSUANCE_SERVICE_URL"],
        mapped.environments["gateway"]["ISSUANCE_NATIVE_SERVICE_URL"]
    );
    assert_eq!(
        mapped.environments["gateway"]["SIGNING_KEYS_SERVICE_URL"],
        format!("http://127.0.0.1:{}", endpoints.port(Role::SigningHttp))
    );
    negative_controls(model, &expected, secret_directory, &endpoints);
    prepared.verify_sources();
    assert_eq!(
        fs::read_dir(secret_directory).unwrap().count(),
        0,
        "No secret material loaded or generated"
    );
    println!("SELFHOST_EXTRACTED_RAW_RUNTIME_MODEL_V1_COMPLETE");
    assert!(prepared.finish(false).is_none());
}

fn negative_controls(
    model: &ClosedSelfhostModel,
    expected: &Value,
    directory: &Path,
    endpoints: &OwnedEndpoints,
) {
    for owner in ["issuance-native", "flow"] {
        let mut changed = model.full_model.clone();
        let single = json!("postgresql+asyncpg://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty");
        changed["services"][owner]["environment"]["DATABASE_URL_TEMPLATE"] = single.clone();
        changed["x-database-url-template"] = single;
        assert!(ClosedSelfhostModel::from_rendered(&changed, changed.clone(), directory).is_err());
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let invalid = std::ffi::OsString::from_vec(vec![0xff]);
        assert!(path_text(Path::new(&invalid)).is_err());
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        let invalid = std::ffi::OsString::from_wide(&[0xd800]);
        assert!(path_text(Path::new(&invalid)).is_err());
    }
    for owner in ["gateway", "flow"] {
        for field in ["entrypoint", "command"] {
            for setting in [
                None,
                Some(Value::Null),
                Some(json!([])),
                Some(json!(["/bin/sh"])),
            ] {
                let inherits = setting.as_ref().is_none_or(Value::is_null);
                let mut changed = model.full_model.clone();
                let service = changed["services"][owner].as_object_mut().unwrap();
                if let Some(value) = setting {
                    service.insert(field.into(), value);
                } else {
                    service.remove(field);
                }
                assert_eq!(
                    ClosedSelfhostModel::from_rendered(&changed, changed.clone(), directory)
                        .is_ok(),
                    inherits
                );
            }
        }
    }
    for (pointer, replacement) in [
        (
            "/services/gateway/environment/SIGNING_KEYS_SERVICE_URL",
            Value::Null,
        ),
        (
            "/services/gateway/environment/SIGNING_KEYS_SERVICE_URL",
            json!("http://localhost:8017"),
        ),
        (
            "/services/gateway/environment/SIGNING_KEYS_SERVICE_URL",
            json!("http://issuance-native:8017"),
        ),
        (
            "/services/flow/environment/ISSUANCE_SERVICE_URL",
            json!("http://issuance-native:8005"),
        ),
        (
            "/services/flow/environment/ISSUANCE_GRPC_TARGET",
            json!("issuance:9005"),
        ),
        (
            "/services/issuance-native/environment/ENVIRONMENT",
            json!("development"),
        ),
        (
            "/services/issuance-native/environment/DIDCOMM_ALLOW_PRIVATE_IPS",
            json!("true"),
        ),
        (
            "/services/issuance-native/environment/DATABASE_URL_TEMPLATE",
            json!("postgresql://already-loaded"),
        ),
        (
            "/services/issuance-native/entrypoint",
            json!(["/usr/local/bin/marty-issuance-service"]),
        ),
        (
            "/services/gateway/environment/GATEWAY_REQUIRED_READY_SERVICES",
            json!("issuance-native"),
        ),
        (
            "/services/flow/environment/GRPC_WORKLOAD_TLS_CA_CERT",
            json!("/run/secrets/unknown"),
        ),
        (
            "/services/gateway/environment/PASSPORT_NATIVE_GATEWAY_ENABLED",
            json!("true"),
        ),
        (
            "/services/flow/environment/PASSPORT_NATIVE_FLOW_ENABLED",
            json!("true"),
        ),
        (
            "/services/issuance-native/environment/PASSPORT_NATIVE_HTTP_ENABLED",
            json!("true"),
        ),
        (
            "/services/flow/environment/PASSPORT_TENANT_API_KEYS_FILE",
            json!("/run/secrets/unmounted"),
        ),
        ("/secrets/issuance_api_key/file", json!("/unowned/secret")),
        (
            "/services/issuance-native/secrets/0/target",
            json!("/run/secrets/wrong"),
        ),
        (
            "/services/gateway/environment/SIGNING_KEYS_INTERNAL_API_KEY_FILE",
            json!("/run/secrets/token_hmac_key"),
        ),
        (
            "/services/issuance/environment/BAO_ADDR",
            json!("changed-unselected-sibling"),
        ),
    ] {
        let mut changed = model.full_model.clone();
        *changed
            .pointer_mut(pointer)
            .expect("Mutation target exists") = replacement;
        assert!(ClosedSelfhostModel::from_rendered(expected, changed.clone(), directory).is_err());
        if !pointer.starts_with("/services/issuance/environment/") {
            assert!(
                ClosedSelfhostModel::from_rendered(&changed, changed.clone(), directory).is_err(),
                "Independent binding guard must also reject jointly changed models"
            );
        }
    }
    for fault in 0..3 {
        let mut ports = endpoints.0.clone();
        match fault {
            0 => {
                ports.remove(&Role::LegacyHttp);
            }
            1 => {
                ports.insert(Role::SigningHttp, 0);
            }
            _ => {
                ports.insert(Role::SigningHttp, ports[&Role::NativeHttp]);
            }
        }
        assert!(model.map_owned_endpoints(&OwnedEndpoints(ports)).is_err());
    }
    let mut changed = model.full_model.clone();
    changed["services"]["issuance-native"]["environment"]["ISSUANCE_API_KEY"] =
        json!("raw-must-not-hide-file");
    assert!(ClosedSelfhostModel::from_rendered(&changed, changed.clone(), directory).is_err());
}
