//! Test-only Kubernetes reference resolution over actual envsubst/composer output.
//! No Kubernetes client, secret discovery, DNS or production input is used here.
use super::{
    issuance_named_peers::{API_KEY, SIGNING_KEY, TOKEN},
    resolved_runtime::{Isolation, ResolvedRuntime},
};
use marty_release_evidence::kubernetes_native as native;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

const ERROR: &str = "Closed synthetic Kubernetes runtime input refused";
type Result<T> = std::result::Result<T, &'static str>;
pub(super) const SOURCE_FILES: &[&str] = &[
    "k8s/oracle/01-configmap.yaml",
    "k8s/oracle/07-microservices.yaml",
    "k8s/oracle/07a-issuance-native.yaml",
    "k8s/oracle/07b-signing-keys.yaml",
    "rust/services/gateway/src/config.rs",
];
const GATEWAY_URLS: &[(&str, &str)] = &[
    ("AUTH_SERVICE_URL", "http://auth:8001"),
    ("ORGANIZATION_SERVICE_URL", "http://organization:8002"),
    (
        "CREDENTIAL_TEMPLATE_SERVICE_URL",
        "http://credential-template:8003",
    ),
    ("TRUST_PROFILE_SERVICE_URL", "http://trust-profile:8004"),
    ("APPLICANT_SERVICE_URL", "http://applicant:8006"),
    ("NOTIFICATION_SERVICE_URL", "http://notification:8007"),
    (
        "COMPLIANCE_PROFILE_SERVICE_URL",
        "http://compliance-profile:8008",
    ),
    (
        "PRESENTATION_POLICY_SERVICE_URL",
        "http://presentation-policy:8009",
    ),
    (
        "DEPLOYMENT_PROFILE_SERVICE_URL",
        "http://deployment-profile:8010",
    ),
    ("FLOW_SERVICE_URL", "http://flow:8011"),
    ("VERIFICATION_SERVICE_URL", "http://verification:8012"),
    (
        "REVOCATION_PROFILE_SERVICE_URL",
        "http://revocation-profile:8013",
    ),
    (
        "DEVICE_REGISTRATION_SERVICE_URL",
        "http://device-registration:8014",
    ),
    ("SIGNING_KEYS_SERVICE_URL", "http://signing-keys:8017"),
];

fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(ERROR)
    }
}
fn root() -> PathBuf {
    super::base_runtime_container::lexical_source_root().expect("fixture source root")
}
fn bytes(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut content = Vec::new();
    fs::File::open(path)
        .map_err(|_| ERROR)?
        .take(native::MAX_BYTES as u64 + 1)
        .read_to_end(&mut content)
        .map_err(|_| ERROR)?;
    require(content.len() <= native::MAX_BYTES)?;
    Ok(content)
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Prepared {
    schema: String,
    source_hashes: BTreeMap<String, String>,
    inputs: BTreeMap<String, String>,
    common: Value,
    baseline: Vec<Value>,
}

fn synthetic_inputs() -> Result<BTreeMap<String, String>> {
    // Discovery only, never a replacement implementation of envsubst. All
    // variables remain explicitly synthetic; the real executable substitutes.
    let mut inputs = BTreeMap::new();
    for file in &SOURCE_FILES[..2] {
        let source = String::from_utf8(bytes(&root().join(file))?).map_err(|_| ERROR)?;
        for tail in source.split("${").skip(1) {
            let name = tail.split_once('}').ok_or(ERROR)?.0;
            require(
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
            )?;
            inputs.insert(name.to_owned(), String::new());
        }
    }
    let expected:BTreeSet<_>="BAO_ADDR CANVAS_CREDENTIAL_ISSUER_PROFILE_IDS
        CANVAS_CREDENTIALS_ALLOW_DUPLICATE_AWARDS CANVAS_CREDENTIALS_API_BASE_URL
        CANVAS_CREDENTIALS_API_ORIGIN_ALLOWLIST CANVAS_CREDENTIALS_ASSERTION_NARRATIVE
        CANVAS_CREDENTIALS_ASSERTION_SCOPE CANVAS_CREDENTIALS_ASSERTION_URL_TEMPLATE
        CANVAS_CREDENTIALS_BADGECLASS_ID CANVAS_CREDENTIALS_ISSUER_ID
        CANVAS_CREDENTIALS_PROVENANCE_BASE_URL CANVAS_CREDENTIALS_PROVIDER CANVAS_CREDENTIALS_RECIPIENT_HASHED
        CANVAS_LEGACY_EVENT_INGEST_ENABLED CANVAS_LTI_EXPERIENCE_BASE_URL CANVAS_LTI_TOOL_ACTIVE_KID
        CANVAS_LTI_TOOL_ISSUER_DID CANVAS_LTI_TOOL_PUBLIC_JWKS CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID
        CANVAS_OAUTH_COMPLETION_REDIRECT_URL CANVAS_PILOT_ORGANIZATION_IDS CANVAS_PORTABLE_INTEGRATION_ENABLED
        CANVAS_PRIVATE_ORIGIN_ALLOWLIST CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST COOKIE_SAMESITE CORS_ORIGINS
        CREDENTIAL_LOGIN_POLICY_ID IMAGE_TAG KC_HOSTNAME KEYCLOAK_REALM KEYCLOAK_REMOVE_DEMO_USERS
        MARTY_ISSUANCE_IMAGE MARTY_ISSUER_DID MARTY_KMS_BOOTSTRAP_ENABLED MARTY_MIGRATION_PROFILE
        MARTY_ORG_ADMIN_EMAIL MARTY_ORG_ID MARTY_ORG_SLUG OCIR_REGISTRY OIDC_CLIENT_ID
        OIDC_ISSUER_URL_EXTERNAL OIDC_POST_LOGOUT_REDIRECT_URI OIDC_REDIRECT_URI ORGANIZATION_CREATION_ENABLED
        PUBLIC_API_URL PUBLIC_DOMAIN RATE_LIMIT_RPM SMTP_HOST SMTP_PORT UI_ADDITIONAL_BASE_URLS UI_BASE_URL
        UNIVERSAL_RESOLVER_URL".split_whitespace().map(str::to_owned).collect();
    require(inputs.keys().cloned().collect::<BTreeSet<_>>() == expected)?;
    for (name, value) in [
        ("OCIR_REGISTRY", "synthetic.registry.invalid"),
        ("IMAGE_TAG", "synthetic"),
        (
            "MARTY_ISSUANCE_IMAGE",
            "synthetic.registry.invalid/legacy:fixture",
        ),
        ("PUBLIC_DOMAIN", "issuer.example"),
        ("PUBLIC_API_URL", "https://issuer.example"),
        ("UI_BASE_URL", "http://localhost:3000"),
        ("CORS_ORIGINS", "http://localhost:3000"),
        ("CANVAS_PORTABLE_INTEGRATION_ENABLED", "false"),
        ("CANVAS_LEGACY_EVENT_INGEST_ENABLED", "false"),
        (
            "CANVAS_CREDENTIALS_ASSERTION_URL_TEMPLATE",
            "https://credentials.example/assertions/{assertion_id}",
        ),
        (
            "CANVAS_CREDENTIALS_ASSERTION_NARRATIVE",
            "Synthetic configured award narrative",
        ),
        (
            "CANVAS_CREDENTIALS_PROVENANCE_BASE_URL",
            "https://credentials.example/verify",
        ),
        ("CANVAS_CREDENTIALS_RECIPIENT_HASHED", "false"),
        ("CANVAS_CREDENTIALS_ALLOW_DUPLICATE_AWARDS", "true"),
        ("RATE_LIMIT_RPM", "120"),
        ("BAO_ADDR", "https://vault.example.com"),
        ("UNIVERSAL_RESOLVER_URL", "https://resolver.example"),
    ] {
        require(inputs.contains_key(name))?;
        inputs.insert(name.into(), value.into());
    }
    Ok(inputs)
}

impl Prepared {
    pub(super) fn prepare() -> Result<Self> {
        let source_bytes: BTreeMap<_, _> = SOURCE_FILES
            .iter()
            .map(|source| Ok(((*source).to_owned(), bytes(&root().join(source))?)))
            .collect::<Result<_>>()?;
        let inputs = synthetic_inputs()?;
        let mut rendered = Vec::new();
        for source in &SOURCE_FILES[..2] {
            let mut command = Command::new("envsubst");
            command.env_clear().envs(&inputs);
            // Loader/tool location only; no operator application environment.
            for name in ["PATH", "SystemRoot", "WINDIR"] {
                if let Some(value) = std::env::var_os(name) {
                    command.env(name, value);
                }
            }
            let output = super::bounded_fixture_command::run(
                &mut command,
                Some(&source_bytes[*source]),
                Duration::from_secs(15),
                native::MAX_BYTES as u64,
            )
            .map_err(|_| ERROR)?;
            require(output.status.success() && output.stderr.is_empty())?;
            rendered.push(native::documents(&output.stdout).map_err(|_| ERROR)?);
        }
        require(rendered[0].len() == 1)?;
        let prepared = Self {
            schema: "marty.kubernetes-prepared-synthetic/v1".into(),
            source_hashes: source_bytes
                .iter()
                .map(|(name, bytes)| (name.clone(), digest(bytes)))
                .collect(),
            inputs,
            common: rendered.remove(0).remove(0),
            baseline: rendered.remove(0),
        };
        prepared.validate()?;
        Ok(prepared)
    }
    fn validate(&self) -> Result<()> {
        require(
            self.schema == "marty.kubernetes-prepared-synthetic/v1"
                && self.inputs == synthetic_inputs()?,
        )?;
        require(self.source_hashes.len() == SOURCE_FILES.len())?;
        for source in SOURCE_FILES {
            require(
                self.source_hashes.get(*source) == Some(&digest(&bytes(&root().join(source))?)),
            )?;
        }
        require(
            self.common["kind"] == "ConfigMap"
                && self.common["metadata"]["name"] == "marty-config"
                && self.common["metadata"]["namespace"] == "marty-prod",
        )?;
        Ok(())
    }
    pub(super) fn write(&self, path: &Path) -> Result<String> {
        self.validate()?;
        let content = serde_json::to_vec(self).map_err(|_| ERROR)?;
        require(content.len() <= native::MAX_BYTES)?;
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| ERROR)?;
        if file.write_all(&content).is_err() {
            drop(file);
            fs::remove_file(path).map_err(|_| ERROR)?;
            return Err(ERROR);
        }
        Ok(digest(&content))
    }
    fn from_child() -> Result<Self> {
        require(std::env::var("MARTY_KUBERNETES_RUNTIME_CHILD").as_deref() == Ok("1"))?;
        let path = PathBuf::from(std::env::var_os("MARTY_KUBERNETES_PREPARED_MODEL").ok_or(ERROR)?);
        let content = bytes(&path)?;
        require(
            std::env::var("MARTY_KUBERNETES_PREPARED_SHA256").as_deref()
                == Ok(digest(&content).as_str()),
        )?;
        let prepared: Self = serde_json::from_slice(&content).map_err(|_| ERROR)?;
        prepared.validate()?;
        Ok(prepared)
    }
}

pub(super) struct PreparedArtifact {
    pub(super) path: PathBuf,
    pub(super) hash: String,
    parent: PathBuf,
    present: bool,
}
impl PreparedArtifact {
    pub(super) fn create() -> Result<Self> {
        let parent = std::env::temp_dir().canonicalize().map_err(|_| ERROR)?;
        let path = parent.join(format!(
            "marty-kubernetes-prepared-{}.json",
            uuid::Uuid::new_v4()
        ));
        let prepared = Prepared::prepare()?;
        let hash = prepared.write(&path)?;
        Ok(Self {
            path,
            hash,
            parent,
            present: true,
        })
    }
    pub(super) fn close(&mut self) -> Result<()> {
        if !self.present {
            return Ok(());
        }
        require(self.path.parent() == Some(self.parent.as_path()))?;
        let metadata = fs::symlink_metadata(&self.path).map_err(|_| ERROR)?;
        require(metadata.is_file() && !metadata.file_type().is_symlink())?;
        require(digest(&bytes(&self.path)?) == self.hash)?;
        fs::remove_file(&self.path).map_err(|_| ERROR)?;
        require(!self.path.try_exists().map_err(|_| ERROR)?)?;
        self.present = false;
        Ok(())
    }
}
impl Drop for PreparedArtifact {
    fn drop(&mut self) {
        if self.close().is_err() {
            eprintln!("Exact synthetic prepared-model cleanup failed");
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    inputs: BTreeMap<String, String>,
    http_port: u16,
    grpc_port: u16,
    gateway_port: u16,
    database_url: String,
    redis_url: String,
    peer_origin: String,
    legacy_origin: String,
    ca_file: PathBuf,
    policy_directory: PathBuf,
    authcrypt: bool,
    allow_private_ips: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    name: String,
    key: String,
    #[serde(default)]
    optional: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ValueFrom {
    config_map_key_ref: Option<Reference>,
    secret_key_ref: Option<Reference>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    name: String,
    value: Option<String>,
    #[serde(rename = "valueFrom")]
    value_from: Option<ValueFrom>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MapReference {
    name: String,
    #[serde(default)]
    optional: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EnvFrom {
    config_map_ref: MapReference,
}

type Maps = BTreeMap<String, BTreeMap<String, String>>;
fn environment(owner: &Value, maps: &Maps, secrets: &Maps) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    let sources: Vec<EnvFrom> =
        serde_json::from_value(owner["envFrom"].clone()).map_err(|_| ERROR)?;
    for source in sources {
        match maps.get(&source.config_map_ref.name) {
            Some(values) => {
                require(values.iter().all(|(name, value)| {
                    !name.is_empty() && !value.contains("$(") && !value.contains('\0')
                }))?;
                result.extend(values.clone());
            }
            None if source.config_map_ref.optional => {}
            None => return Err(ERROR),
        }
    }
    let entries: Vec<Entry> = serde_json::from_value(owner["env"].clone()).map_err(|_| ERROR)?;
    let mut seen = BTreeSet::new();
    for entry in entries {
        require(seen.insert(entry.name.clone()) && !entry.name.is_empty())?;
        let value = match (entry.value, entry.value_from) {
            (Some(value), None) => Some(value),
            (None, Some(reference)) => {
                let (reference, store) =
                    match (reference.config_map_key_ref, reference.secret_key_ref) {
                        (Some(reference), None) => (reference, maps),
                        (None, Some(reference)) => (reference, secrets),
                        _ => return Err(ERROR),
                    };
                let found = store
                    .get(&reference.name)
                    .and_then(|v| v.get(&reference.key))
                    .cloned();
                require(found.is_some() || reference.optional)?;
                found
            }
            _ => return Err(ERROR),
        };
        if let Some(value) = value {
            // No source in this profile uses Kubernetes $(NAME) expansion;
            // refuse it rather than approximating kubelet expansion semantics.
            require(!value.contains("$(") && !value.contains('\0'))?;
            result.insert(entry.name, value);
        }
    }
    Ok(result)
}

fn owner<'a>(rows: &'a [Value], name: &str) -> Result<&'a Value> {
    let selected: Vec<_> = rows
        .iter()
        .filter(|v| v["kind"] == "Deployment" && v["metadata"]["name"] == name)
        .collect();
    require(selected.len() == 1)?;
    let containers = selected[0]
        .pointer("/spec/template/spec/containers")
        .and_then(Value::as_array)
        .ok_or(ERROR)?;
    let selected: Vec<_> = containers.iter().filter(|v| v["name"] == name).collect();
    require(selected.len() == 1)?;
    Ok(selected[0])
}

fn owned_url(value: &str, schemes: &[&str]) -> Result<()> {
    let url = url::Url::parse(value).map_err(|_| ERROR)?;
    require(
        schemes.contains(&url.scheme())
            && matches!(url.host_str(), Some("127.0.0.1" | "localhost"))
            && url.port().is_some()
            && url.query().is_none()
            && url.fragment().is_none()
            && (url.scheme() != "http"
                || (url.username().is_empty() && url.password().is_none() && url.path() == "/")),
    )
}

pub(super) fn render(value: &Value) -> Result<ResolvedRuntime> {
    let spec: Spec = serde_json::from_value(value.clone()).map_err(|_| ERROR)?;
    require(
        spec.inputs
            == BTreeMap::from([
                ("ISSUANCE_API_KEY".into(), API_KEY.into()),
                ("GRPC_SERVICE_TOKEN".into(), TOKEN.into()),
                ("SIGNING_KEYS_INTERNAL_API_KEY".into(), SIGNING_KEY.into()),
                ("TOKEN_HMAC_KEY".into(), "synthetic-fresh-main-hmac".into()),
                (
                    "INTEGRATION_SECRET_MASTER_KEY".into(),
                    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".into(),
                ),
                ("PUBLIC_API_URL".into(), "https://issuer.example".into()),
                ("UI_BASE_URL".into(), "http://localhost:3000".into()),
                ("ISSUANCE_OFFER_TTL_MINUTES".into(), "10080".into()),
                ("TOKEN_RATE_LIMIT".into(), "30".into()),
                ("CANVAS_PORTABLE_INTEGRATION_ENABLED".into(), "false".into()),
                ("CANVAS_PILOT_ORGANIZATION_IDS".into(), String::new()),
            ]),
    )?;
    require(
        [spec.http_port, spec.grpc_port, spec.gateway_port]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .len()
            == 3
            && spec.http_port != 0
            && spec.grpc_port != 0
            && spec.gateway_port != 0,
    )?;
    owned_url(&spec.database_url, &["postgres", "postgresql"])?;
    owned_url(&spec.redis_url, &["redis"])?;
    owned_url(&spec.peer_origin, &["http"])?;
    owned_url(&spec.legacy_origin, &["http"])?;
    require(
        spec.peer_origin != spec.legacy_origin
            && spec.ca_file.is_file()
            && spec.policy_directory.is_dir()
            && spec.ca_file.parent() == Some(spec.policy_directory.as_path()),
    )?;
    let prepared = if std::env::var("MARTY_KUBERNETES_RUNTIME_CHILD").as_deref() == Ok("1") {
        Prepared::from_child()?
    } else {
        Prepared::prepare()?
    };
    let mut settings = native::Environment::from([
        ("K8S_ISSUANCE_NATIVE_ENABLED".into(), "true".into()),
        (
            "MARTY_SERVICES_IMAGE".into(),
            format!("ghcr.io/elevenid/services@sha256:{}", "a".repeat(64)),
        ),
        ("ISSUANCE_OFFER_TTL_MINUTES".into(), "10080".into()),
        ("TOKEN_RATE_LIMIT".into(), "30".into()),
        ("K8S_DIDCOMM_CA_SECRET".into(), "synthetic-ca".into()),
        (
            "DIDCOMM_DID_WEB_INTERNAL_BASE_URL".into(),
            "http://gateway:8000".into(),
        ),
    ]);
    if spec.allow_private_ips {
        settings.insert("DIDCOMM_ALLOW_PRIVATE_IPS".into(), "true".into());
    }
    if spec.authcrypt {
        settings.insert(
            "K8S_DIDCOMM_POLICY_SECRET".into(),
            "synthetic-policy".into(),
        );
    }
    let mut templates = Vec::new();
    for file in &SOURCE_FILES[2..4] {
        templates.extend(native::documents(&bytes(&root().join(file))?).map_err(|_| ERROR)?);
    }
    let ready = native::readiness_from_source(
        &String::from_utf8(bytes(&root().join(SOURCE_FILES[4]))?).map_err(|_| ERROR)?,
    )
    .map_err(|_| ERROR)?;
    let model =
        native::compose(&prepared.baseline, &templates, &ready, &settings).map_err(|_| ERROR)?;
    let rows = model["items"].as_array().ok_or(ERROR)?;
    let mut maps = Maps::new();
    maps.insert(
        "marty-config".into(),
        serde_json::from_value(prepared.common["data"].clone()).map_err(|_| ERROR)?,
    );
    for item in rows.iter().filter(|v| v["kind"] == "ConfigMap") {
        require(
            maps.insert(
                item["metadata"]["name"].as_str().ok_or(ERROR)?.into(),
                serde_json::from_value(item["data"].clone()).map_err(|_| ERROR)?,
            )
            .is_none(),
        )?;
    }
    let secret_values = BTreeMap::from([
        (
            "DATABASE_URL".into(),
            "postgresql://oracle:synthetic-local-only@postgres:5432/canvas_published_schema_test"
                .into(),
        ),
        ("ISSUANCE_API_KEY".into(), API_KEY.into()),
        ("GRPC_SERVICE_TOKEN".into(), TOKEN.into()),
        ("SIGNING_KEYS_INTERNAL_API_KEY".into(), SIGNING_KEY.into()),
        ("TOKEN_HMAC_KEY".into(), "synthetic-fresh-main-hmac".into()),
        (
            "INTEGRATION_SECRET_MASTER_KEY".into(),
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".into(),
        ),
        (
            "CANVAS_CREDENTIALS_SHARED_SECRET".into(),
            "synthetic-kubernetes-canvas-shared-secret".into(),
        ),
        (
            "OPENBAO_SERVICE_TOKEN".into(),
            "synthetic-not-an-openbao-capability".into(),
        ),
    ]);
    for name in [
        "ISSUANCE_API_KEY",
        "GRPC_SERVICE_TOKEN",
        "SIGNING_KEYS_INTERNAL_API_KEY",
        "TOKEN_HMAC_KEY",
        "INTEGRATION_SECRET_MASTER_KEY",
    ] {
        require(spec.inputs.get(name) == secret_values.get(name))?;
    }
    let secrets = Maps::from([("marty-secrets".into(), secret_values)]);
    let native = environment(owner(rows, "issuance-native")?, &maps, &secrets)?;
    let gateway = environment(owner(rows, "gateway")?, &maps, &secrets)?;
    let signing = environment(owner(rows, "signing-keys")?, &maps, &secrets)?;
    require(
        signing["SIGNING_KEYS_INTERNAL_API_KEY"] == native["SIGNING_KEYS_INTERNAL_API_KEY"]
            && signing["SIGNING_KEYS_INTERNAL_API_KEY"] == gateway["SIGNING_KEYS_INTERNAL_API_KEY"],
    )?;
    require(
        native["ISSUANCE_API_KEY"] == gateway["ISSUANCE_API_KEY"]
            && native["ISSUANCE_GRPC_ENABLED"] == "true",
    )?;
    require(
        !native
            .keys()
            .any(|v| v.starts_with("BAO") || v.starts_with("OPENBAO")),
    )?;
    for (name, expected) in [
        (
            "CANVAS_CREDENTIALS_ASSERTION_URL_TEMPLATE",
            "https://credentials.example/assertions/{assertion_id}",
        ),
        (
            "CANVAS_CREDENTIALS_ASSERTION_NARRATIVE",
            "Synthetic configured award narrative",
        ),
        (
            "CANVAS_CREDENTIALS_PROVENANCE_BASE_URL",
            "https://credentials.example/verify",
        ),
        ("CANVAS_CREDENTIALS_RECIPIENT_HASHED", "false"),
        ("CANVAS_CREDENTIALS_ALLOW_DUPLICATE_AWARDS", "true"),
    ] {
        require(native.get(name).map(String::as_str) == Some(expected))?;
    }
    require(
        native.get("DIDCOMM_ALLOW_PRIVATE_IPS").map(String::as_str)
            == if spec.allow_private_ips {
                Some("true")
            } else {
                None
            },
    )?;
    overlay(native, gateway, &spec)
}

fn overlay(
    mut native: BTreeMap<String, String>,
    mut gateway: BTreeMap<String, String>,
    spec: &Spec,
) -> Result<ResolvedRuntime> {
    for (name, expected) in GATEWAY_URLS {
        require(gateway.get(*name).map(String::as_str) == Some(*expected))?;
    }
    require(
        gateway["ISSUANCE_SERVICE_URL"] == "http://issuance:8005"
            && gateway["ISSUANCE_NATIVE_SERVICE_URL"] == "http://issuance-native:8005"
            && gateway["AUTH_GRPC_TARGET"] == "auth:9001",
    )?;
    // Parse the actual gateway configuration before using its supported default
    // organization target. No missing deployment dependency is fabricated.
    let actual = marty_gateway::config::GatewayConfig::from_values(&gateway).map_err(|_| ERROR)?;
    require(
        actual.organization_grpc_target == "http://organization:9002"
            && actual.event_stream_grpc_target == "http://event-stream:9015",
    )?;
    for (name, expected) in [
        ("ORG_GRPC_TARGET", "organization:9002"),
        ("CT_GRPC_TARGET", "credential-template:9003"),
        ("RP_GRPC_TARGET", "revocation-profile:9013"),
        (
            "SIGNING_KEYS_INTERNAL_URL",
            "http://gateway:8000/internal/signing-keys",
        ),
    ] {
        require(native.get(name).map(String::as_str) == Some(expected))?;
    }
    for name in [
        "ORG_GRPC_TARGET",
        "CT_GRPC_TARGET",
        "RP_GRPC_TARGET",
        "CREDENTIAL_TEMPLATE_SERVICE_URL",
        "REVOCATION_PROFILE_SERVICE_URL",
        "SIGNING_KEYS_INTERNAL_URL",
        "DIDCOMM_DID_WEB_INTERNAL_BASE_URL",
    ] {
        native.insert(name.into(), spec.peer_origin.clone());
    }
    native.insert("MARTY_ISSUANCE__SERVER__HOST".into(), "127.0.0.1".into());
    native.insert("DATABASE_URL".into(), spec.database_url.clone());
    native.insert("ISSUANCE_SERVICE_PORT".into(), spec.http_port.to_string());
    native.insert("ISSUANCE_GRPC_PORT".into(), spec.grpc_port.to_string());
    require(native["DIDCOMM_TLS_CA_FILE"] == "/run/marty-didcomm-ca/ca.pem")?;
    native.insert(
        "DIDCOMM_TLS_CA_FILE".into(),
        spec.ca_file.to_str().ok_or(ERROR)?.into(),
    );
    if spec.authcrypt {
        require(
            native["DIDCOMM_ENCRYPTION_POLICY_FILE"] == "/run/marty-didcomm-policy/policy.json",
        )?;
        let policy = spec.policy_directory.join("didcomm-encryption-policy.json");
        require(policy.is_file())?;
        native.insert(
            "DIDCOMM_ENCRYPTION_POLICY_FILE".into(),
            policy.to_str().ok_or(ERROR)?.into(),
        );
    } else {
        require(!native.contains_key("DIDCOMM_ENCRYPTION_POLICY_FILE"))?;
    }
    for (name, _) in GATEWAY_URLS {
        gateway.insert((*name).into(), spec.peer_origin.clone());
    }
    for name in ["AUTH_GRPC_TARGET", "ORG_GRPC_TARGET", "ES_GRPC_TARGET"] {
        gateway.insert(name.into(), spec.peer_origin.clone());
    }
    gateway.insert("ISSUANCE_SERVICE_URL".into(), spec.legacy_origin.clone());
    gateway.insert(
        "ISSUANCE_NATIVE_SERVICE_URL".into(),
        format!("http://127.0.0.1:{}", spec.http_port),
    );
    gateway.insert("GATEWAY_PORT".into(), spec.gateway_port.to_string());
    gateway.insert("REDIS_URL".into(), spec.redis_url.clone());
    Ok(ResolvedRuntime {
        native_environment: native,
        gateway_environment: gateway,
        isolation: Isolation::Kubernetes,
    })
}

#[test]
fn reference_resolution_preserves_precedence_empty_optional_and_fails_closed() {
    let maps = Maps::from([
        (
            "marty-config".into(),
            BTreeMap::from([
                ("A".into(), "common".into()),
                ("B".into(), "retained".into()),
            ]),
        ),
        (
            "selected".into(),
            BTreeMap::from([("A".into(), "selected".into())]),
        ),
    ]);
    let secrets = Maps::from([(
        "synthetic-only".into(),
        BTreeMap::from([("key".into(), "synthetic-value".into())]),
    )]);
    let fixture = json!({"envFrom":[{"configMapRef":{"name":"marty-config"}},{"configMapRef":{"name":"selected"}}],"env":[
        {"name":"A","value":""},{"name":"B","valueFrom":{"configMapKeyRef":{"name":"absent","key":"missing","optional":true}}},
        {"name":"S","valueFrom":{"secretKeyRef":{"name":"synthetic-only","key":"key"}}}
    ]});
    assert_eq!(
        environment(&fixture, &maps, &secrets).unwrap(),
        BTreeMap::from([
            ("A".into(), String::new()),
            ("B".into(), "retained".into()),
            ("S".into(), "synthetic-value".into())
        ])
    );
    for (pointer, value) in [
        ("/envFrom/0", json!({"secretRef":{"name":"synthetic-only"}})),
        ("/envFrom/0", json!({"configMapRef":{"name":"absent"}})),
        (
            "/envFrom/0",
            json!({"configMapRef":{"name":"marty-config"},"prefix":"PREFIX_"}),
        ),
        ("/env/0", json!({"name":"A","value":"$(UNSUPPORTED)"})),
        (
            "/env/0",
            json!({"name":"A","value":"x","valueFrom":{"secretKeyRef":{"name":"synthetic-only","key":"key"}}}),
        ),
        ("/env/0", json!({"name":"A","value":3})),
        ("/env/1", json!({"name":"A","value":"duplicate"})),
        ("/env/2/valueFrom/secretKeyRef/key", json!("missing")),
        (
            "/env/2/valueFrom",
            json!({"fieldRef":{"fieldPath":"metadata.name"}}),
        ),
        (
            "/env/2/valueFrom",
            json!({"configMapKeyRef":{"name":"marty-config","key":"A"},"secretKeyRef":{"name":"synthetic-only","key":"key"}}),
        ),
    ] {
        let mut changed = fixture.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            matches!(environment(&changed, &maps, &secrets), Err(ERROR)),
            "{pointer}"
        );
    }
    let mut changed = maps.clone();
    changed
        .get_mut("marty-config")
        .unwrap()
        .insert("CANARY".into(), "$(UNSUPPORTED)".into());
    assert!(matches!(
        environment(&fixture, &changed, &secrets),
        Err(ERROR)
    ));
}

#[test]
fn prepared_model_uses_actual_envsubst_and_rejects_identity_drift() {
    let prepared = Prepared::prepare().unwrap();
    assert_eq!(
        prepared.common["data"]["PUBLIC_API_URL"],
        "https://issuer.example"
    );
    assert_eq!(prepared.common["data"]["CANVAS_PILOT_ORGANIZATION_IDS"], "");
    for (name, expected) in [
        (
            "CANVAS_CREDENTIALS_ASSERTION_URL_TEMPLATE",
            "https://credentials.example/assertions/{assertion_id}",
        ),
        (
            "CANVAS_CREDENTIALS_ASSERTION_NARRATIVE",
            "Synthetic configured award narrative",
        ),
        (
            "CANVAS_CREDENTIALS_PROVENANCE_BASE_URL",
            "https://credentials.example/verify",
        ),
        ("CANVAS_CREDENTIALS_RECIPIENT_HASHED", "false"),
        ("CANVAS_CREDENTIALS_ALLOW_DUPLICATE_AWARDS", "true"),
    ] {
        assert_eq!(prepared.common["data"][name], expected);
    }
    assert_eq!(
        prepared.common["data"]["AUTH_SERVICE_URL"],
        "http://auth:8001"
    );
    assert_eq!(prepared.source_hashes.len(), 5);
    for fault in ["schema", "source", "inputs"] {
        let mut changed: Prepared =
            serde_json::from_value(serde_json::to_value(&prepared).unwrap()).unwrap();
        match fault {
            "schema" => changed.schema = "other-profile".into(),
            "source" => {
                changed.source_hashes.remove(SOURCE_FILES[0]);
            }
            "inputs" => {
                changed
                    .inputs
                    .insert("PUBLIC_API_URL".into(), "https://changed.invalid".into());
            }
            _ => unreachable!(),
        }
        assert!(matches!(changed.validate(), Err(ERROR)));
    }
}

#[test]
fn prepared_cleanup_retains_modified_bytes_until_exact_owned_content_is_restored() {
    let mut artifact = PreparedArtifact::create().unwrap();
    let path = artifact.path.clone();
    let original = bytes(&path).unwrap();
    fs::write(&path, b"synthetic-mutated-prepared-model").unwrap();
    assert!(matches!(artifact.close(), Err(ERROR)));
    assert_eq!(bytes(&path).unwrap(), b"synthetic-mutated-prepared-model");
    // Only this test's original exact bytes are restored; the cleanup owner
    // never restores or removes contents whose recorded hash has changed.
    fs::write(&path, &original).unwrap();
    artifact.close().unwrap();
    assert!(!path.try_exists().unwrap());
    artifact.close().unwrap();
}
