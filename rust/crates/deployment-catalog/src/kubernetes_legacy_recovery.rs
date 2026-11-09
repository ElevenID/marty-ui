//! Read-only admission for one retained legacy Kubernetes development bootstrap.
//! This owner never issues credentials, enrolls authority, or changes Kubernetes.
//! Historical facts not retained by the original bootstrap are not reconstructed.

use crate::{
    application_authority::compiled_initializer_policies,
    application_tokens::specifications,
    keycloak,
    operator::{public_spki, version_one_custody, Result, REFUSAL},
    operator_certificates::{check_lifetime, retained_leaf_signature},
    operator_http::request,
};
use async_trait::async_trait;
use marty_openbao_http::OpenBaoHttp;
use marty_selfhost_identity::{tls::WORKLOAD_TLS_ROLES, SELFHOST_ROLES};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use spki::der::Encode;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use x509_cert::Certificate;

pub const SCHEMA: &str = "marty.kubernetes-legacy-recovery-inspection/v1";
pub const LEGACY_RUNTIME: &str = "3ff1328d163f2dca38e369f17bda77b6334808eb";
const LEGACY_OPENBAO_VERSION: &str = "2.5.5";
const INITIALIZER: &[u8] = include_bytes!("../../../../docker/openbao-init.sh");
const INITIALIZER_SHA256: &str = "57adbf26ef7b6f22a47c1ec85b9de75b807e394a2d7de48f6550b374cc8ebe1f";
const MAX_FILE: usize = 64 * 1024;
const MAX_GENERATION: usize = 8 * 1024 * 1024;
const TTL: u64 = 28_800;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NamespaceObservation {
    pub name: String,
    pub uid: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Context {
    schema: String,
    bootstrap: Value,
    initialize_request: Value,
    tls_key_metadata: Value,
    namespace_observation: NamespaceObservation,
    current: PathBuf,
    root_token_file: PathBuf,
    // Private transport binds this to root_token from the original retained
    // initialization. Lookup metadata alone cannot distinguish generate-root.
    retained_root_sha256: String,
}

fn decode_context(request: &[u8]) -> Result<Context> {
    if request.len() > 512 * 1024 {
        return Err(REFUSAL);
    }
    let request = crate::installer_json::decode(request).map_err(|_| REFUSAL)?;
    serde_json::from_value(request).map_err(|_| REFUSAL)
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct Binding {
    bootstrap_id: String,
    namespace: String,
    namespace_uid: String,
    openbao_cluster_id: String,
    producer_nonce: String,
    workload_project: String,
    runtime_source_sha: String,
    chart_source_sha: String,
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field].as_str().ok_or(REFUSAL)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.hyphenated().to_string() == value)
}

fn reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

fn binding(context: &Context) -> Result<Binding> {
    let receipt = &context.bootstrap;
    let start = &context.initialize_request;
    let lifecycle = &receipt["credentialLifecycle"];
    let namespace = text(receipt, "namespace")?;
    let nonce = text(lifecycle, "producerNonce")?;
    let project = text(lifecycle, "workloadProject")?;
    let expected_requests: Vec<_> = specifications().iter().map(|spec| json!({
        "input": spec.input, "requestedPolicies": spec.policies,
        "requestedTtl": if spec.input == "OPENBAO_BOOTSTRAP_TOKEN" {"2h"} else {"8h"},
        "requestedRenewable": false, "requestedOrphan": true, "requestedNoDefaultPolicy": true,
    })).collect();
    if context.schema != SCHEMA
        || sha256(INITIALIZER) != INITIALIZER_SHA256
        || receipt["status"] != "openbao-and-application-credentials-ready"
        || receipt["runtimeSourceSha"] != LEGACY_RUNTIME
        || receipt["credentialLifetimeHours"] != 8
        || receipt["migrationBootstrapLifetimeHours"] != 2
        || receipt.get("applicationAuthority").is_some()
        || lifecycle["schema"] != "marty.kubernetes-credential-lifecycle/v1"
        || lifecycle["ordinaryTokens"] != json!(expected_requests)
        || !reference(namespace)
        || namespace.len() > 63
        || !namespace.as_bytes()[0].is_ascii_alphanumeric()
        || !namespace.as_bytes()[namespace.len() - 1].is_ascii_alphanumeric()
        || !namespace
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || ["default", "kube-system", "kube-public", "kube-node-lease"].contains(&namespace)
        || context.namespace_observation.name != namespace
        || context.namespace_observation.uid != text(lifecycle, "namespaceUid")?
        || !uuid(text(receipt, "bootstrapId")?)
        || !uuid(text(receipt, "openbaoClusterId")?)
        || !uuid(text(lifecycle, "namespaceUid")?)
        || !hex(nonce, 12)
        || project != format!("marty-selfhost-disposable-k8s-{nonce}")
        || !hex(text(receipt, "chartSourceSha")?, 40)
        || start["bootstrapId"] != receipt["bootstrapId"]
        || start["namespace"] != receipt["namespace"]
        || start["namespaceUid"] != lifecycle["namespaceUid"]
        || start["producerNonce"] != lifecycle["producerNonce"]
        || start["workloadProject"] != lifecycle["workloadProject"]
        || start["operation"] != "bao operator init"
        || start["recoveryShares"] != 1
        || start["recoveryThreshold"] != 1
        || !hex(&context.retained_root_sha256, 64)
    {
        return Err(REFUSAL);
    }
    let metadata = &context.tls_key_metadata;
    let roles = metadata["roles"].as_array().ok_or(REFUSAL)?;
    if metadata["schema"] != "marty.selfhost-disposable-tls-keys/v1"
        || metadata.as_object().ok_or(REFUSAL)?.len() != 2
        || roles.len() != SELFHOST_ROLES.len()
    {
        return Err(REFUSAL);
    }
    let mut seen = BTreeSet::new();
    for role in roles {
        let name = text(role, "role")?;
        let expected = SELFHOST_ROLES
            .iter()
            .find(|item| item.name == name)
            .ok_or(REFUSAL)?;
        if !seen.insert(name)
            || role.as_object().ok_or(REFUSAL)?.len() != 3
            || role["key_name"] != expected.key_name
            || role["version"] != 1
        {
            return Err(REFUSAL);
        }
    }
    Ok(Binding {
        bootstrap_id: text(receipt, "bootstrapId")?.into(),
        namespace: namespace.into(),
        namespace_uid: text(lifecycle, "namespaceUid")?.into(),
        openbao_cluster_id: text(receipt, "openbaoClusterId")?.into(),
        producer_nonce: nonce.into(),
        workload_project: project.into(),
        runtime_source_sha: LEGACY_RUNTIME.into(),
        chart_source_sha: text(receipt, "chartSourceSha")?.into(),
    })
}

fn private_directory(path: &Path) -> Result<()> {
    let info = fs::symlink_metadata(path).map_err(|_| REFUSAL)?;
    if !path.is_absolute()
        || path.canonicalize().map_err(|_| REFUSAL)? != path
        || !info.is_dir()
        || info.mode() & 0o7777 != 0o700
        || info.uid() != unsafe { libc::geteuid() }
    {
        return Err(REFUSAL);
    }
    Ok(())
}

fn identity(info: &fs::Metadata) -> (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64) {
    (
        info.dev(),
        info.ino(),
        info.mode(),
        info.uid(),
        info.gid(),
        info.nlink(),
        info.len(),
        info.mtime(),
        info.mtime_nsec(),
        info.ctime(),
        info.ctime_nsec(),
    )
}

fn read_input(path: &Path, modes: &[u32], allow_empty: bool) -> Result<(Vec<u8>, u32)> {
    read_bounded(path, modes, allow_empty, MAX_FILE)
}

fn read_bounded(
    path: &Path,
    modes: &[u32],
    allow_empty: bool,
    maximum: usize,
) -> Result<(Vec<u8>, u32)> {
    private_directory(path.parent().ok_or(REFUSAL)?)?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| REFUSAL)?;
    let before = file.metadata().map_err(|_| REFUSAL)?;
    let mode = before.mode() & 0o7777;
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != unsafe { libc::geteuid() }
        || !modes.contains(&mode)
        || before.len() > maximum as u64
    {
        return Err(REFUSAL);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSAL)?;
    if bytes.len() != before.len() as usize
        || bytes.len() > maximum
        || (!allow_empty && bytes.is_empty())
        || bytes.contains(&0)
        || bytes.windows(11).any(|part| part == b"PRIVATE KEY")
        || identity(&before) != identity(&file.metadata().map_err(|_| REFUSAL)?)
        || identity(&before) != identity(&fs::symlink_metadata(path).map_err(|_| REFUSAL)?)
    {
        return Err(REFUSAL);
    }
    Ok((bytes, mode))
}

type Generation = BTreeMap<String, (Vec<u8>, u32)>;

fn generation(path: &Path) -> Result<Generation> {
    private_directory(path)?;
    let mut result = BTreeMap::new();
    let mut total = 0;
    for item in fs::read_dir(path).map_err(|_| REFUSAL)? {
        let item = item.map_err(|_| REFUSAL)?;
        let name = item.file_name().into_string().map_err(|_| REFUSAL)?;
        if !reference(&name) || name.starts_with('.') || result.len() >= 256 {
            return Err(REFUSAL);
        }
        let observed = read_input(
            &item.path(),
            &[0o400, 0o440, 0o444, 0o600, 0o640, 0o644],
            true,
        )?;
        total += observed.0.len();
        if total > MAX_GENERATION {
            return Err(REFUSAL);
        }
        result.insert(name, observed);
    }
    let mut required: BTreeSet<String> =
        specifications().into_iter().map(|spec| spec.file).collect();
    required.insert("workload_identity_ca_cert".into());
    required.insert("openbao_tls_ca_cert".into());
    for role in SELFHOST_ROLES {
        required.insert(role.cert_file.into());
        required.insert(role.token_file.into());
    }
    required.insert("keycloak_signing_kms_token".into());
    for realm in keycloak::REALMS {
        required.insert(format!("keycloak_{realm}_rs256_cert"));
        for purpose in keycloak::PURPOSES {
            required.insert(format!("keycloak_{realm}_{purpose}_token"));
        }
    }
    if required
        .iter()
        .any(|name| result.get(name).is_none_or(|item| item.0.is_empty()))
    {
        return Err(REFUSAL);
    }
    Ok(result)
}

fn certificate(bytes: &[u8]) -> Result<Certificate> {
    let certificates = Certificate::load_pem_chain(bytes).map_err(|_| REFUSAL)?;
    if certificates.len() != 1 {
        return Err(REFUSAL);
    }
    certificates.into_iter().next().ok_or(REFUSAL)
}

fn certificate_sha(bytes: &[u8]) -> Result<String> {
    Ok(sha256(&certificate(bytes)?.to_der().map_err(|_| REFUSAL)?))
}

fn retained_leaf(leaf: &[u8], issuer: &[u8], public: &str, kind: &str, now: u64) -> Result<()> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let parsed = certificate(leaf)?;
    let spki = public_spki(public.as_bytes(), false)?;
    let key = marty_crypto::jwk::public_key_der_to_jwk(&spki).map_err(|_| REFUSAL)?;
    let supported = match kind {
        "ecdsa-p256" => key.kty == "EC" && key.crv.as_deref() == Some("P-256"),
        "rsa-2048" => {
            key.kty == "RSA"
                && key.n.as_deref().is_some_and(|modulus| {
                    URL_SAFE_NO_PAD
                        .decode(modulus)
                        .is_ok_and(|bytes| bytes.len() == 256 && bytes[0] & 0x80 != 0)
                })
        }
        _ => false,
    };
    let before = parsed
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs();
    let after = parsed
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs();
    if !supported || before > now || after <= before || public_spki(leaf, true)? != spki {
        return Err(REFUSAL);
    }
    retained_leaf_signature(leaf, issuer, Duration::from_secs(now))
}

fn workload_role_matches(fields: &Value, name: &str) -> Result<()> {
    let role = WORKLOAD_TLS_ROLES
        .iter()
        .find(|role| role.name == name)
        .ok_or(REFUSAL)?;
    let uris: Vec<_> = role
        .uri_sans
        .split(',')
        .filter(|part| !part.is_empty())
        .collect();
    if fields["allow_any_name"] != true
        || fields["allow_localhost"] != true
        || fields["allow_ip_sans"] != true
        || fields["server_flag"] != role.server
        || fields["client_flag"] != role.client
        || fields["key_type"] != "ec"
        || fields["key_bits"] != 256
        || fields["max_ttl"] != 86400
        || fields["use_csr_common_name"] != false
        || fields["use_csr_sans"] != false
        || fields["allowed_uri_sans"] != json!(uris)
    {
        return Err(REFUSAL);
    }
    Ok(())
}

#[async_trait]
trait ReadApi: Sync {
    async fn read(&self, path: &str, token: Option<&str>) -> Result<Value>;
}

struct Http<'a>(&'a OpenBaoHttp);
#[async_trait]
impl ReadApi for Http<'_> {
    async fn read(&self, path: &str, token: Option<&str>) -> Result<Value> {
        request(self.0, Method::GET, path, None, token).await
    }
}

async fn health(api: &impl ReadApi, binding: &Binding) -> Result<Value> {
    health_cluster(api, &binding.openbao_cluster_id).await
}

async fn health_cluster(api: &impl ReadApi, expected_cluster: &str) -> Result<Value> {
    // Identity is checked before sending any root credential to the endpoint.
    let health = api.read("sys/health", None).await?;
    if health["initialized"] != true
        || health["sealed"] != false
        || health["standby"] != false
        || health["cluster_id"] != expected_cluster
        || health["version"] != LEGACY_OPENBAO_VERSION
    {
        return Err(REFUSAL);
    }
    Ok(health)
}

/// The transport calls this before any root token or current credentials reach
/// its observed producer pod. Only the retained public CA is needed here.
pub async fn target(ca: &Path, expected_cluster: &str) -> Result<Value> {
    if !uuid(expected_cluster) {
        return Err(REFUSAL);
    }
    let original = read_input(ca, &[0o400, 0o600, 0o644], false)?;
    certificate(&original.0)?;
    let bao = OpenBaoHttp::connect("https://openbao:8200", Some(ca), Duration::from_secs(10))
        .map_err(|_| REFUSAL)?;
    health_cluster(&Http(&bao), expected_cluster).await?;
    if read_input(ca, &[0o400, 0o600, 0o644], false)? != original {
        return Err(REFUSAL);
    }
    Ok(
        json!({"schema":"marty.kubernetes-legacy-recovery-target/v1", "ready":true,
        "clusterId":expected_cluster, "authenticated":false}),
    )
}

async fn policy(api: &impl ReadApi, root: &str, name: &str, expected: &str) -> Result<Value> {
    if !reference(name) {
        return Err(REFUSAL);
    }
    let observed = api
        .read(&format!("sys/policies/acl/{name}"), Some(root))
        .await?;
    if text(&observed["data"], "policy")?.trim_end_matches('\n') != expected.trim_end_matches('\n')
    {
        return Err(REFUSAL);
    }
    Ok(observed["data"].clone())
}

async fn issuer(
    api: &impl ReadApi,
    root: &str,
    mount: &str,
    reference_name: &str,
) -> Result<Value> {
    if !reference(reference_name) {
        return Err(REFUSAL);
    }
    let issuer = api
        .read(&format!("{mount}/issuer/{reference_name}"), Some(root))
        .await?;
    let data = &issuer["data"];
    // OpenBao 2.5.5 issuerUsage.Names() returns a comma-separated string,
    // including its zero-valued read-only flag, not a JSON string array.
    let usages: Vec<_> = text(data, "usage")?.split(',').collect();
    let permitted = [
        "read-only",
        "issuing-certificates",
        "crl-signing",
        "ocsp-signing",
    ];
    if !uuid(text(data, "issuer_id")?)
        || !uuid(text(data, "key_id")?)
        || data["revoked"] != false
        || !usages.contains(&"issuing-certificates")
        || usages.iter().any(|usage| !permitted.contains(usage))
        || usages.iter().collect::<BTreeSet<_>>().len() != usages.len()
        || !check_lifetime(text(data, "certificate")?.as_bytes(), TTL)?
    {
        return Err(REFUSAL);
    }
    Ok(data.clone())
}

async fn role_issuer(
    api: &impl ReadApi,
    root: &str,
    mount: &str,
    role: &Value,
    selected: &Value,
) -> Result<Value> {
    let resolved = issuer(api, root, mount, text(role, "issuer_ref")?).await?;
    if resolved["issuer_id"] != selected["issuer_id"]
        || certificate_sha(text(&resolved, "certificate")?.as_bytes())?
            != certificate_sha(text(selected, "certificate")?.as_bytes())?
    {
        return Err(REFUSAL);
    }
    Ok(resolved)
}

async fn inspect_with(api: &impl ReadApi, context: &Context) -> Result<Value> {
    let binding = binding(context)?;
    let current = generation(&context.current)?;
    let root_bytes = read_input(&context.root_token_file, &[0o400, 0o600], false)?.0;
    let root = std::str::from_utf8(&root_bytes).map_err(|_| REFUSAL)?;
    if !(20..=256).contains(&root.len())
        || !root.bytes().all(|byte| byte.is_ascii_graphic())
        || sha256(&root_bytes) != context.retained_root_sha256
    {
        return Err(REFUSAL);
    }
    health(api, &binding).await?;
    let authority = api.read("auth/token/lookup-self", Some(root)).await?;
    if authority["data"]["policies"] != json!(["root"])
        || authority["data"]["ttl"] != 0
        || authority["data"]["orphan"] != true
        || authority["data"]["path"] != "auth/token/root"
    {
        return Err(REFUSAL);
    }
    let auth = api.read("sys/auth", Some(root)).await?;
    let mounts = api.read("sys/mounts", Some(root)).await?;
    if !auth["data"].is_object()
        || !mounts["data"].is_object()
        || auth["data"].get("selfhost-renew/").is_some()
        || auth["data"].get("selfhost-application/").is_some()
        || mounts["data"]["transit/"]["type"] != "transit"
        || mounts["data"]["didcomm/"]["type"] != "openbao-didcomm-authcrypt"
        || mounts["data"]["workload-pki/"]["type"] != "pki"
        || mounts["data"]["keycloak-pki/"]["type"] != "pki"
    {
        return Err(REFUSAL);
    }
    let workload_issuer = issuer(api, root, "workload-pki", "default").await?;
    let keycloak_issuer = issuer(api, root, "keycloak-pki", "default").await?;
    let workload_ca = text(&workload_issuer, "certificate")?.as_bytes();
    let keycloak_ca = text(&keycloak_issuer, "certificate")?.as_bytes();
    if certificate_sha(&current["workload_identity_ca_cert"].0)? != certificate_sha(workload_ca)? {
        return Err(REFUSAL);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| REFUSAL)?
        .as_secs();
    let mut keys = BTreeMap::new();
    let mut roles = BTreeMap::new();
    let mut policies = BTreeMap::new();
    let mut issuer_bindings = BTreeMap::new();
    for role in SELFHOST_ROLES {
        let key = api
            .read(&format!("transit/keys/{}", role.key_name), Some(root))
            .await?;
        version_one_custody(&key["data"], "ecdsa-p256")?;
        retained_leaf(
            &current[role.cert_file].0,
            workload_ca,
            text(&key["data"]["keys"]["1"], "public_key")?,
            "ecdsa-p256",
            now,
        )?;
        keys.insert(role.key_name.to_owned(), key["data"].clone());
        let observed = api
            .read(&format!("workload-pki/roles/{}", role.name), Some(root))
            .await?;
        workload_role_matches(&observed["data"], role.name)?;
        issuer_bindings.insert(
            role.name.to_owned(),
            role_issuer(
                api,
                root,
                "workload-pki",
                &observed["data"],
                &workload_issuer,
            )
            .await?,
        );
        roles.insert(role.name.to_owned(), observed["data"].clone());
        let name = format!("{}-{}", binding.workload_project, role.key_name);
        let body = format!("path \"transit/keys/{}\" {{ capabilities = [\"read\"] }}\npath \"transit/sign/{}\" {{ capabilities = [\"update\"] }}", role.key_name, role.key_name);
        policies.insert(name.clone(), policy(api, root, &name, &body).await?);
    }
    let observed = api.read("keycloak-pki/roles/rs256", Some(root)).await?;
    let role = &observed["data"];
    if role["key_type"] != "rsa"
        || role["key_bits"] != 2048
        || role["allow_any_name"] != true
        || role["max_ttl"] != 28800
        || role["use_csr_common_name"] != false
        || role["use_csr_sans"] != false
    {
        return Err(REFUSAL);
    }
    issuer_bindings.insert(
        "keycloak-rs256".into(),
        role_issuer(api, root, "keycloak-pki", role, &keycloak_issuer).await?,
    );
    roles.insert("keycloak-rs256".into(), role.clone());
    let mut jwe_versions = BTreeMap::new();
    for realm in keycloak::REALMS {
        for (suffix, kind) in [("rs256", "rsa-2048"), ("hs512", "hmac")] {
            let name = format!("keycloak-{realm}-{suffix}");
            let key = api
                .read(&format!("transit/keys/{name}"), Some(root))
                .await?;
            version_one_custody(&key["data"], kind)?;
            if suffix == "rs256" {
                retained_leaf(
                    &current[&format!("keycloak_{realm}_rs256_cert")].0,
                    keycloak_ca,
                    text(&key["data"]["keys"]["1"], "public_key")?,
                    "rsa-2048",
                    now,
                )?;
            }
            keys.insert(name, key["data"].clone());
        }
        for purpose in keycloak::PURPOSES {
            let path = format!("didcomm/keycloak/keys/{realm}/{purpose}");
            let observed = api.read(&path, Some(root)).await?;
            let version = text(&observed["data"], "version")?;
            if !reference(version) {
                return Err(REFUSAL);
            }
            // Retain only public selection metadata, never the returned key value.
            jwe_versions.insert(path, version.to_owned());
            let name = format!(
                "selfhost-keycloak-{realm}-{purpose}-{}",
                binding.producer_nonce
            );
            let body = keycloak::policy(
                &json!({"scope":"jwe", "realm":realm, "purpose":purpose, "version":version}),
            )?;
            policies.insert(name.clone(), policy(api, root, &name, &body).await?);
        }
    }
    let name = format!("selfhost-keycloak-sign-{}", binding.producer_nonce);
    policies.insert(
        name.clone(),
        policy(
            api,
            root,
            &name,
            &keycloak::policy(&json!({"scope":"signing"}))?,
        )
        .await?,
    );
    for (name, body) in compiled_initializer_policies()? {
        policies.insert(name.clone(), policy(api, root, &name, &body).await?);
    }
    health(api, &binding).await?;
    if generation(&context.current)? != current
        || read_input(&context.root_token_file, &[0o400, 0o600], false)?.0 != root_bytes
    {
        return Err(REFUSAL);
    }
    let inputs: BTreeMap<_, _> = current
        .iter()
        .map(|(name, (bytes, mode))| (name.clone(), json!({"sha256":sha256(bytes), "mode":mode})))
        .collect();
    Ok(json!({
        "schema":SCHEMA, "status":"inspected-not-staged", "mutationAvailable":false,
        "binding":binding, "inputBindings":inputs,
        "observed": {"openbaoVersion":LEGACY_OPENBAO_VERSION, "keys":keys, "pkiRoles":roles, "policies":policies,
            "roleIssuers":issuer_bindings, "workloadIssuer":workload_issuer,
            "keycloakIssuer":keycloak_issuer, "keycloakJweVersions":jwe_versions},
        "evidenceLimits": {
            "rootProvenance":"trusted-retained-initialization-custody; lookup checks authority shape only",
            "workloadIssuer":"retained CA DER and retained leaf signatures",
            "keycloakIssuer":"observed issuer verifies retained leaves; original CA DER was not retained",
            "symmetricKeys":"observed current key/version selection; historical material continuity unproven",
            "pkiRoles":"observed full documents and original configured security fields; no historical default-field claim"
        }
    }))
}

/// The CLI writes the detailed report privately and emits only this bounded summary.
pub async fn inspect_to_file(request: &[u8], output: &Path) -> Result<Value> {
    let context = decode_context(request)?;
    binding(&context)?;
    generation(&context.current)?;
    private_directory(output.parent().ok_or(REFUSAL)?)?;
    if !matches!(output.symlink_metadata(), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    {
        return Err(REFUSAL);
    }
    // This narrow Kubernetes profile has one service target and always trusts
    // the retained generation's CA. A caller cannot substitute another trust file.
    let bao = OpenBaoHttp::connect(
        "https://openbao:8200",
        Some(&context.current.join("openbao_tls_ca_cert")),
        Duration::from_secs(10),
    )
    .map_err(|_| REFUSAL)?;
    let report = tokio::time::timeout(
        Duration::from_secs(600),
        inspect_with(&Http(&bao), &context),
    )
    .await
    .map_err(|_| REFUSAL)??;
    let raw = serde_json::to_string(&report).map_err(|_| REFUSAL)?;
    crate::operator_files::write_private(output, &raw, MAX_GENERATION)?;
    Ok(
        json!({"schema":SCHEMA, "status":"inspected-not-staged", "mutationAvailable":false,
        "namespace":report["binding"]["namespace"], "workloadIdentities":16,
        "keycloakSigningCertificates":2, "keycloakTokens":5, "ordinaryRuntimeTokens":12,
        "privateReportWritten":true}),
    )
}

/// Public compiled scope; obtaining it never reads credentials or contacts OpenBao.
pub fn contract() -> Value {
    json!({"schema":SCHEMA, "legacyRuntimeSourceSha":LEGACY_RUNTIME,
        "readOnly":true, "mutationAvailable":false, "workloadIdentities":SELFHOST_ROLES.len(),
        "keycloakSigningCertificates":2, "keycloakTokens":5, "ordinaryRuntimeTokens":12,
        "migrationTokenReplacement":false, "maximumReplacementTtlSeconds":TTL})
}

#[cfg(test)]
#[path = "kubernetes_legacy_recovery_tests.rs"]
mod tests;

// The staging increment remains unavailable to a release binary until its own
// transaction/failure tests and independent audits are complete.
#[cfg(test)]
#[path = "kubernetes_legacy_recovery_stage.rs"]
mod staging;

#[cfg(test)]
#[path = "kubernetes_legacy_recovery_activation.rs"]
mod activation;

#[cfg(test)]
#[path = "kubernetes_legacy_recovery_qualify.rs"]
mod qualification;

// Native command implementations remain test-only in this checkpoint. Release
// dispatch is a separate reviewed change after the mutation increment audits.
#[cfg(test)]
#[path = "kubernetes_legacy_recovery_commands.rs"]
mod recovery_commands;
