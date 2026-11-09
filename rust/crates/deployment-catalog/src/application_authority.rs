//! Closed ordinary application-token authority using existing OpenBao AppRole infrastructure.
//! Private attempts survive uncertainty. This module never activates a credential generation.

use crate::{
    application_tokens::{runtime_specs, specifications, TokenSpec},
    approle::owned_identity,
    operator::{Result, REFUSAL},
    operator_files::{generation_file, private_directory, write_private},
    operator_http::{builder, request},
};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use marty_openbao_http::OpenBaoHttp;
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

pub const RECOVERY: &str = "Application token staging requires operator recovery";
pub(crate) const MOUNT: &str = "selfhost-application";
pub(crate) const ROLE: &str = "application-renewer";
pub(crate) const POLICY: &str = "selfhost-application-renewal";
pub(crate) const ROLE_FILE: &str = "application-role-id";
pub(crate) const SECRET_FILE: &str = "application-secret-id";
const BINDING_FILE: &str = "application-binding.json";
const OPERATOR_TTL: u64 = 3600;
const MAX_RESPONSE: usize = 1024 * 1024;
const INITIALIZER: &str = include_str!("../../../../docker/openbao-init.sh");

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Binding {
    namespace: String,
    namespace_uid: String,
    openbao_cluster_id: String,
    workload_project: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    root_token: String,
    current: PathBuf,
    binding: Binding,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    binding: Binding,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Staging {
    current: PathBuf,
    output: PathBuf,
    binding: Binding,
}

struct Identity {
    directory: PathBuf,
    role_id: String,
    secret_id: String,
    binding: Binding,
}

fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

impl Binding {
    fn validate(&self) -> Result<()> {
        let namespace = self.namespace.as_bytes();
        let nonce = self
            .workload_project
            .strip_prefix("marty-selfhost-disposable-k8s-")
            .ok_or(REFUSAL)?;
        if namespace.is_empty()
            || namespace.len() > 63
            || !namespace[0].is_ascii_alphanumeric()
            || !namespace[namespace.len() - 1].is_ascii_alphanumeric()
            || !namespace
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
            || !canonical_uuid(&self.namespace_uid)
            || !canonical_uuid(&self.openbao_cluster_id)
            || nonce.len() != 12
            || !nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(REFUSAL);
        }
        Ok(())
    }
}

fn token(value: &str) -> Result<&str> {
    if !(20..=1024).contains(&value.len()) || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(REFUSAL);
    }
    Ok(value)
}

fn private_input(path: &Path, bound: usize) -> Result<Vec<u8>> {
    let (bytes, mode) = generation_file(path, false)?;
    if ![0o400, 0o600].contains(&mode) || bytes.len() > bound {
        return Err(REFUSAL);
    }
    Ok(bytes)
}

fn input_token(path: &Path) -> Result<String> {
    let bytes = private_input(path, 1025)?;
    let value = std::str::from_utf8(&bytes).map_err(|_| REFUSAL)?;
    let value = value.strip_suffix('\n').unwrap_or(value);
    token(value).map(str::to_owned)
}

fn owned_directory(path: &Path) -> Result<PathBuf> {
    let directory = private_directory(path)?;
    owned_identity(&directory, true)?;
    Ok(directory)
}

fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| REFUSAL)
}

fn create_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|_| REFUSAL)?;
        owned_directory(path).map(|_| ())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(REFUSAL)
    }
}

fn persist(path: &Path, value: &Value, bound: usize) -> Result<()> {
    write_private(
        path,
        &serde_json::to_string(value).map_err(|_| REFUSAL)?,
        bound,
    )?;
    sync_directory(path.parent().ok_or(REFUSAL)?)
}

fn read_identity(directory: &Path, expected: &Binding) -> Result<Identity> {
    expected.validate()?;
    let directory = owned_directory(directory)?;
    let names = crate::generation::entries(&directory)?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if names != BTreeSet::from([ROLE_FILE.into(), SECRET_FILE.into(), BINDING_FILE.into()]) {
        return Err(REFUSAL);
    }
    let binding: Binding =
        serde_json::from_slice(&private_input(&directory.join(BINDING_FILE), 4097)?)
            .map_err(|_| REFUSAL)?;
    binding.validate()?;
    if binding != *expected {
        return Err(REFUSAL);
    }
    Ok(Identity {
        role_id: input_token(&directory.join(ROLE_FILE))?,
        secret_id: input_token(&directory.join(SECRET_FILE))?,
        directory,
        binding,
    })
}

fn current_tokens(directory: &Path, exact: bool) -> Result<BTreeMap<String, String>> {
    let directory = owned_directory(directory)?;
    let specs = specifications();
    if exact
        && crate::generation::entries(&directory)?
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            != specs.iter().map(|spec| spec.file.clone()).collect()
    {
        return Err(REFUSAL);
    }
    specs
        .iter()
        .map(|spec| Ok((spec.file.clone(), input_token(&directory.join(&spec.file))?)))
        .collect()
}

fn unique_tail<'a>(source: &'a str, anchor: &str) -> Result<&'a str> {
    if source.matches(anchor).count() != 1 {
        return Err(REFUSAL);
    }
    source
        .split_once(anchor)
        .map(|(_, tail)| tail)
        .ok_or(REFUSAL)
}

fn heredoc(source: &str, anchor: &str, delimiter: &str) -> Result<String> {
    let body = unique_tail(source, anchor)?
        .split_once(&format!("\n{delimiter}\n"))
        .map(|(body, _)| body)
        .filter(|body| !body.is_empty() && body.len() < 64 * 1024 && !body.contains("<<"))
        .ok_or(REFUSAL)?;
    Ok(format!("{body}\n"))
}

/// The signed initializer remains the only owner of application policy bodies.
fn initializer_policies(source: &str) -> Result<BTreeMap<String, String>> {
    let mut policies = BTreeMap::new();
    for (name, indentation, delimiter) in [
        ("credential-service", "", "EOF"),
        ("signing-keys-managed", "", "EOF"),
        ("didcomm-issuance", "    ", "POLICY"),
        ("notification-webhook-service", "", "EOF"),
    ] {
        let anchor = format!(
            "\n{indentation}bao policy write -address=\"${{BAO_ADDR}}\" {name} - <<'{delimiter}'\n"
        );
        policies.insert(name.into(), heredoc(source, &anchor, delimiter)?);
    }
    let origins = unique_tail(source, "\ngrant_origins='")?
        .split_once("'\n")
        .map(|(origins, _)| origins)
        .ok_or(REFUSAL)?
        .split(' ')
        .collect::<Vec<_>>();
    let expected_origins = runtime_specs()
        .iter()
        .flat_map(|spec| spec.policies.iter())
        .filter_map(|policy| policy.strip_prefix("sign-grant-mint-").map(str::to_owned))
        .collect::<BTreeSet<_>>();
    if origins.len() != 7
        || origins.iter().copied().collect::<BTreeSet<_>>()
            != expected_origins.iter().map(String::as_str).collect()
    {
        return Err(REFUSAL);
    }
    unique_tail(
        source,
        "\n    grant_key=\"marty-sign-grant-${grant_origin}-v1\"\n",
    )?;
    let mint = heredoc(
        source,
        "\n    bao policy write -address=\"${BAO_ADDR}\" \"sign-grant-mint-${grant_origin}\" - <<EOF\n",
        "EOF",
    )?;
    if mint.matches("${grant_key}").count() != 1 {
        return Err(REFUSAL);
    }
    for origin in &origins {
        let body = mint.replace("${grant_key}", &format!("marty-sign-grant-{origin}-v1"));
        if body.contains('$') {
            return Err(REFUSAL);
        }
        policies.insert(format!("sign-grant-mint-{origin}"), body);
    }
    let verify_lines = source
        .lines()
        .filter(|line| line.starts_with("    printf '") && line.ends_with("' \"${grant_origin}\""))
        .collect::<Vec<_>>();
    if verify_lines.len() != 1 {
        return Err(REFUSAL);
    }
    unique_tail(
        source,
        &format!(
            "{}\ndone | bao policy write -address=\"${{BAO_ADDR}}\" sign-grant-verify -\n",
            verify_lines[0]
        ),
    )?;
    let verify = verify_lines[0]
        .strip_prefix("    printf '")
        .and_then(|line| line.strip_suffix("' \"${grant_origin}\""))
        .ok_or(REFUSAL)?;
    if verify.matches("%s").count() != 1 || verify.matches("\\n").count() != 1 {
        return Err(REFUSAL);
    }
    let mut verify_policy = String::new();
    for origin in origins {
        let body = verify.replace("%s", origin).replace("\\n", "\n");
        if body.contains(['$', '%', '\\']) {
            return Err(REFUSAL);
        }
        verify_policy.push_str(&body);
    }
    policies.insert("sign-grant-verify".into(), verify_policy);
    let expected = runtime_specs()
        .into_iter()
        .flat_map(|spec| spec.policies)
        .collect::<BTreeSet<_>>();
    if policies.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err(REFUSAL);
    }
    Ok(policies)
}

/// The initializer remains the policy owner for read-only legacy inspection too.
pub(crate) fn compiled_initializer_policies() -> Result<BTreeMap<String, String>> {
    initializer_policies(INITIALIZER)
}

fn line(path: &str, caps: &[&str]) -> String {
    format!(
        "path \"{path}\" {{ capabilities = [\"{}\"] }}",
        caps.join("\", \"")
    )
}

pub(crate) fn policy() -> Result<String> {
    let mut paths = BTreeMap::from([
        ("auth/token/lookup".into(), vec!["update"]),
        ("auth/token/lookup-self".into(), vec!["read"]),
        ("auth/token/revoke-self".into(), vec!["update"]),
        (format!("auth/{MOUNT}/role/{ROLE}"), vec!["read"]),
        (format!("sys/policies/acl/{POLICY}"), vec!["read"]),
    ]);
    for name in initializer_policies(INITIALIZER)?.keys() {
        paths.insert(format!("sys/policies/acl/{name}"), vec!["read"]);
    }
    for spec in runtime_specs() {
        let leaf = spec.replacement_role.ok_or(REFUSAL)?;
        paths.insert(format!("auth/token/roles/{leaf}"), vec!["read"]);
        paths.insert(format!("auth/token/create/{leaf}"), vec!["update"]);
    }
    Ok(paths
        .iter()
        .map(|(path, capabilities)| line(path, capabilities))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n")
}

fn exact_names(value: &Value, expected: &[String]) -> bool {
    let Some(values) = value.as_array() else {
        return false;
    };
    let Some(names) = values.iter().map(Value::as_str).collect::<Option<Vec<_>>>() else {
        return false;
    };
    names.len() == expected.len()
        && names.iter().copied().collect::<BTreeSet<_>>()
            == expected.iter().map(String::as_str).collect()
}

fn no_names(value: &Value) -> bool {
    value.is_null() || value.as_array().is_some_and(Vec::is_empty)
}

fn duration_label(seconds: u64) -> String {
    let mut value = String::new();
    for (part, suffix) in [
        (seconds / 3600, "h"),
        (seconds % 3600 / 60, "m"),
        (seconds % 60, "s"),
    ] {
        if part != 0 {
            value.push_str(&format!("{part}{suffix}"));
        }
    }
    if value.is_empty() {
        value.push_str("0s");
    }
    value
}

fn mint_warnings(value: &Value, ttl: u64, granted: u64) -> bool {
    // OpenBao v2.5.5 warns whenever both the fixed role and request set a
    // nonzero cap, including equal caps. CalculateTTL can additionally shorten
    // a lease if creation crosses a second. Match its humanDuration labels to
    // the validated auth lease; the lookup proof still requires the exact cap.
    if value.is_null() {
        return true;
    }
    let Some(warnings) = value.as_array() else {
        return false;
    };
    let duplicate_cap = format!(
        "Explicit max TTL specified both during creation call and in role; using the lesser value of {ttl} seconds"
    );
    let capped_lease = format!(
        "TTL of {:?} exceeded the effective max_ttl of {:?}; TTL value is capped accordingly",
        duration_label(ttl),
        duration_label(granted)
    );
    let mut seen = BTreeSet::new();
    warnings.iter().all(|warning| {
        warning.as_str().is_some_and(|warning| {
            seen.insert(warning)
                && (warning == duplicate_cap
                    || ((1..ttl).contains(&granted) && warning == capped_lease))
        })
    })
}

fn leaf_configuration(spec: &TokenSpec) -> Value {
    json!({
        "allowed_policies":spec.policies, "disallowed_policies":["default","root"],
        "allowed_policies_glob":[], "disallowed_policies_glob":[],
        "allowed_entity_aliases":[], "orphan":true, "renewable":false,
        "path_suffix":"", "token_no_default_policy":true,
        "token_explicit_max_ttl":spec.ttl_seconds, "token_period":0,
        "token_type":"service", "token_num_uses":0, "token_bound_cidrs":[]
    })
}

fn validate_leaf_configuration(data: &Value, spec: &TokenSpec) -> Result<()> {
    if !exact_names(&data["allowed_policies"], &spec.policies)
        || !exact_names(
            &data["disallowed_policies"],
            &["default".into(), "root".into()],
        )
        || data["orphan"] != true
        || data["renewable"] != false
        || data["path_suffix"] != ""
        || data["token_no_default_policy"] != true
        || data["token_explicit_max_ttl"] != spec.ttl_seconds
        || data["token_period"] != 0
        || data["token_type"] != "service"
    {
        return Err(REFUSAL);
    }
    for field in [
        "allowed_policies_glob",
        "disallowed_policies_glob",
        "allowed_entity_aliases",
        "token_bound_cidrs",
    ] {
        if !no_names(&data[field]) {
            return Err(REFUSAL);
        }
    }
    for field in ["period", "token_num_uses"] {
        if data.get(field).is_some_and(|value| value != 0) {
            return Err(REFUSAL);
        }
    }
    if data
        .get("explicit_max_ttl")
        .is_some_and(|value| value != 0 && value != spec.ttl_seconds)
    {
        return Err(REFUSAL);
    }
    Ok(())
}

fn operator_configuration() -> Value {
    json!({
        "bind_secret_id":true, "secret_id_num_uses":0, "secret_id_ttl":0,
        "token_policies":[POLICY], "token_no_default_policy":true,
        "token_ttl":OPERATOR_TTL, "token_max_ttl":OPERATOR_TTL,
        "token_explicit_max_ttl":OPERATOR_TTL, "token_period":0,
        "token_type":"service", "token_num_uses":0,
        "secret_id_bound_cidrs":[], "token_bound_cidrs":[]
    })
}

fn validate_operator_configuration(data: &Value) -> Result<()> {
    // OpenBao v2.5.5 AppRole pathRoleRead/PopulateTokenData emits every
    // canonical scalar, including zero defaults. Its deprecated aliases may
    // be absent; token-role reads have different omission rules above.
    let expected = operator_configuration();
    for (field, value) in expected.as_object().ok_or(REFUSAL)? {
        let accepted = if field.ends_with("_cidrs") {
            no_names(&data[field])
        } else {
            &data[field] == value
        };
        if !accepted {
            return Err(REFUSAL);
        }
    }
    if data.get("period").is_some_and(|value| value != 0) {
        return Err(REFUSAL);
    }
    Ok(())
}

fn metadata(
    data: &Value,
    expected_token: &str,
    policies: &[String],
    ttl: u64,
    paths: &[&str],
    renewable: Option<bool>,
    initial_bootstrap: bool,
) -> Result<u64> {
    let actual_ttl = data["ttl"].as_u64().ok_or(REFUSAL)?;
    let creation_ttl = data["creation_ttl"].as_u64().ok_or(REFUSAL)?;
    let path = data["path"].as_str().ok_or(REFUSAL)?;
    // The existing bootstrap uses -ttl=8h and -renewable=false without
    // -explicit-max-ttl. Only those original creation routes may retain zero.
    let initial =
        initial_bootstrap && ["auth/token/create", "auth/token/create-orphan"].contains(&path);
    if data["id"] != expected_token
        || !exact_names(&data["policies"], policies)
        || !no_names(&data["identity_policies"])
        || data["orphan"] != true
        || data["type"] != "service"
        || data["num_uses"] != 0
        || !(1..=ttl).contains(&actual_ttl)
        || !(actual_ttl..=ttl).contains(&creation_ttl)
        || (data["explicit_max_ttl"] != ttl && !(initial && data["explicit_max_ttl"] == 0))
        || !paths.contains(&path)
        || renewable.is_some_and(|expected| data["renewable"] != expected)
        || data.get("period").is_some_and(|period| period != 0)
    {
        return Err(REFUSAL);
    }
    Ok(actual_ttl)
}

fn auth_metadata(auth: &Value, policies: &[String], ttl: u64, leaf: bool) -> Result<()> {
    if !exact_names(&auth["policies"], policies)
        || auth
            .get("token_policies")
            .is_some_and(|value| !exact_names(value, policies))
        || !no_names(&auth["identity_policies"])
        || auth["token_type"] != "service"
        || auth["orphan"] != true
        || auth["num_uses"] != 0
        || !auth["lease_duration"]
            .as_u64()
            .is_some_and(|value| (1..=ttl).contains(&value))
        || (leaf && auth["renewable"] != false)
    {
        return Err(REFUSAL);
    }
    Ok(())
}

/// The explicit legacy recovery path uses the same bounded leaf proof owner,
/// without changing AppRole enrollment or routine replacement admission.
#[cfg(target_os = "linux")]
pub(crate) fn legacy_recovery_leaf(
    created: &Value,
    lookup: &Value,
    value: &str,
    policies: &[String],
    ttl: u64,
) -> Result<()> {
    token(value)?;
    auth_metadata(&created["auth"], policies, ttl, true)?;
    let remaining = metadata(
        &lookup["data"],
        value,
        policies,
        ttl,
        &["auth/token/create"],
        Some(false),
        false,
    )?;
    if remaining < 7 * 3600
        || !mint_warnings(
            &created["warnings"],
            ttl,
            created["auth"]["lease_duration"].as_u64().ok_or(REFUSAL)?,
        )
    {
        return Err(REFUSAL);
    }
    Ok(())
}

/// This private seam exercises the real transaction with synthetic OpenBao replies.
/// Production always delegates to the existing HTTPS client and bounded request owner.
#[async_trait]
trait Api: Sync {
    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        token: Option<&str>,
    ) -> Result<Value>;
    async fn absent(&self, path: &str, token: &str) -> Result<()>;
    async fn capture(
        &self,
        path: &str,
        body: &Value,
        token: Option<&str>,
        output: Option<&Path>,
    ) -> Result<Value>;
}

struct Http<'a>(&'a OpenBaoHttp);

#[async_trait]
impl Api for Http<'_> {
    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        token: Option<&str>,
    ) -> Result<Value> {
        request(self.0, method, path, body, token).await
    }

    async fn absent(&self, path: &str, token: &str) -> Result<()> {
        let response = builder(self.0, Method::GET, path, None, Some(token))
            .send()
            .await
            .map_err(|_| REFUSAL)?;
        if response.status() != StatusCode::NOT_FOUND {
            return Err(REFUSAL);
        }
        Ok(())
    }

    async fn capture(
        &self,
        path: &str,
        body: &Value,
        token: Option<&str>,
        output: Option<&Path>,
    ) -> Result<Value> {
        let Some(output) = output else {
            return self.request(Method::POST, path, Some(body), token).await;
        };
        let response = builder(self.0, Method::POST, path, Some(body), token)
            .send()
            .await;
        let Ok(mut response) = response else {
            persist(output, &json!({"received":false}), 1024)?;
            return Err(RECOVERY);
        };
        let status = response.status();
        let mut bytes = Vec::new();
        let complete = loop {
            match response.chunk().await {
                Ok(Some(chunk)) if bytes.len() + chunk.len() <= MAX_RESPONSE => {
                    bytes.extend_from_slice(&chunk);
                }
                Ok(None) => break true,
                Ok(Some(chunk)) => {
                    bytes.extend_from_slice(&chunk[..MAX_RESPONSE - bytes.len()]);
                    break false;
                }
                Err(_) => break false,
            }
        };
        // Response bodies may contain credentials, so only the private operation
        // directory receives them. Retain malformed and uncertain replies as well.
        persist(
            output,
            &json!({
                "received":true, "status":status.as_u16(), "complete":complete,
                "bodyBase64":STANDARD.encode(&bytes)
            }),
            2 * MAX_RESPONSE,
        )?;
        if !complete || !status.is_success() {
            return Err(RECOVERY);
        }
        serde_json::from_slice(&bytes).map_err(|_| RECOVERY)
    }
}

async fn health(api: &impl Api, binding: &Binding) -> Result<()> {
    let observed = api.request(Method::GET, "sys/health", None, None).await?;
    if observed["initialized"] != true
        || observed["sealed"] != false
        || observed["standby"] != false
        || observed["cluster_id"] != binding.openbao_cluster_id
    {
        return Err(REFUSAL);
    }
    Ok(())
}

async fn policies(api: &impl Api, authority: &str) -> Result<()> {
    for (name, expected) in initializer_policies(INITIALIZER)? {
        let observed = api
            .request(
                Method::GET,
                &format!("sys/policies/acl/{name}"),
                None,
                Some(authority),
            )
            .await?;
        let body = observed["data"]["policy"].as_str().ok_or(REFUSAL)?;
        if body.trim_end_matches('\n') != expected.trim_end_matches('\n') {
            return Err(REFUSAL);
        }
    }
    Ok(())
}

async fn prove_current(
    api: &impl Api,
    authority: &str,
    values: &BTreeMap<String, String>,
) -> Result<()> {
    for spec in runtime_specs() {
        let current = values.get(&spec.file).ok_or(REFUSAL)?;
        let response = api
            .request(
                Method::POST,
                "auth/token/lookup",
                Some(&json!({"token":current})),
                Some(authority),
            )
            .await?;
        let leaf = format!(
            "auth/token/create/{}",
            spec.replacement_role.as_deref().ok_or(REFUSAL)?
        );
        metadata(
            &response["data"],
            current,
            &spec.policies,
            spec.ttl_seconds,
            &["auth/token/create", "auth/token/create-orphan", &leaf],
            Some(false),
            true,
        )?;
    }
    Ok(())
}

async fn revoke(api: &impl Api, authority: &str) -> Result<()> {
    api.request(
        Method::POST,
        "auth/token/revoke-self",
        None,
        Some(authority),
    )
    .await
    .map(|_| ())
}

async fn session(
    api: &impl Api,
    identity: &Identity,
    response_path: Option<&Path>,
) -> Result<String> {
    health(api, &identity.binding).await?;
    let response = api
        .capture(
            &format!("auth/{MOUNT}/login"),
            &json!({"role_id":identity.role_id, "secret_id":identity.secret_id}),
            None,
            response_path,
        )
        .await
        .map_err(|_| RECOVERY)?;
    let authority = response["auth"]["client_token"].as_str().ok_or(RECOVERY)?;
    let authority = token(authority).map_err(|_| RECOVERY)?;
    let verified: Result<()> = async {
        if !no_names(&response["warnings"]) {
            return Err(REFUSAL);
        }
        auth_metadata(&response["auth"], &[POLICY.into()], OPERATOR_TTL, false)?;
        let observed = api
            .request(Method::GET, "auth/token/lookup-self", None, Some(authority))
            .await?;
        metadata(
            &observed["data"],
            authority,
            &[POLICY.into()],
            OPERATOR_TTL,
            &[&format!("auth/{MOUNT}/login")],
            None,
            false,
        )?;
        let observed = api
            .request(
                Method::GET,
                &format!("auth/{MOUNT}/role/{ROLE}"),
                None,
                Some(authority),
            )
            .await?;
        validate_operator_configuration(&observed["data"])?;
        let observed = api
            .request(
                Method::GET,
                &format!("sys/policies/acl/{POLICY}"),
                None,
                Some(authority),
            )
            .await?;
        if observed["data"]["policy"]
            .as_str()
            .ok_or(REFUSAL)?
            .trim_end_matches('\n')
            != policy()?.trim_end_matches('\n')
        {
            return Err(REFUSAL);
        }
        policies(api, authority).await?;
        for spec in runtime_specs() {
            let observed = api
                .request(
                    Method::GET,
                    &format!(
                        "auth/token/roles/{}",
                        spec.replacement_role.as_deref().ok_or(REFUSAL)?
                    ),
                    None,
                    Some(authority),
                )
                .await?;
            validate_leaf_configuration(&observed["data"], &spec)?;
        }
        Ok(())
    }
    .await;
    if verified.is_err() {
        let _ = revoke(api, authority).await;
        return Err(RECOVERY);
    }
    Ok(authority.to_owned())
}

pub(crate) async fn login(bao: &OpenBaoHttp, identity: &Path, context: &Value) -> Result<Value> {
    let context: Login = serde_json::from_value(context.clone()).map_err(|_| REFUSAL)?;
    let identity = read_identity(identity, &context.binding)?;
    let authority = session(&Http(bao), &identity, None).await?;
    // Same private caller protocol as the existing AppRole profiles.
    Ok(json!({
        "role_id":identity.role_id, "secret_id":identity.secret_id,
        "names":[], "token":authority
    }))
}

pub(crate) async fn bootstrap(bao: &OpenBaoHttp, output: &Path, context: &Value) -> Result<()> {
    let context: Enrollment = serde_json::from_value(context.clone()).map_err(|_| REFUSAL)?;
    enroll(&Http(bao), output, context).await
}

async fn enroll(api: &impl Api, output: &Path, context: Enrollment) -> Result<()> {
    context.binding.validate()?;
    token(&context.root_token)?;
    let output = owned_directory(output)?;
    let current = owned_directory(&context.current)?;
    if output == current || fs::read_dir(&output).map_err(|_| REFUSAL)?.next().is_some() {
        return Err(REFUSAL);
    }
    let before = current_tokens(&current, true)?;
    health(api, &context.binding).await?;
    policies(api, &context.root_token).await?;
    prove_current(api, &context.root_token, &before).await?;
    let mounts = api
        .request(Method::GET, "sys/auth", None, Some(&context.root_token))
        .await?;
    if mounts["data"]
        .as_object()
        .ok_or(REFUSAL)?
        .contains_key(&format!("{MOUNT}/"))
    {
        return Err(REFUSAL);
    }
    api.absent(&format!("sys/policies/acl/{POLICY}"), &context.root_token)
        .await?;
    for spec in runtime_specs() {
        api.absent(
            &format!(
                "auth/token/roles/{}",
                spec.replacement_role.as_deref().ok_or(REFUSAL)?
            ),
            &context.root_token,
        )
        .await?;
    }
    health(api, &context.binding).await?;
    if before != current_tokens(&current, true)? {
        return Err(REFUSAL);
    }
    // This retained first file makes an interrupted enrollment non-replayable.
    // No generic bootstrap rollback may delete its identity or remote authority.
    persist(
        &output.join(BINDING_FILE),
        &serde_json::to_value(&context.binding).map_err(|_| REFUSAL)?,
        4096,
    )?;
    let mutation: Result<()> = async {
        api.request(
            Method::POST,
            &format!("sys/auth/{MOUNT}"),
            Some(&json!({"type":"approle"})),
            Some(&context.root_token),
        )
        .await?;
        for spec in runtime_specs() {
            api.request(
                Method::POST,
                &format!(
                    "auth/token/roles/{}",
                    spec.replacement_role.as_deref().ok_or(REFUSAL)?
                ),
                Some(&leaf_configuration(&spec)),
                Some(&context.root_token),
            )
            .await?;
        }
        api.request(
            Method::PUT,
            &format!("sys/policies/acl/{POLICY}"),
            Some(&json!({"policy":policy()?})),
            Some(&context.root_token),
        )
        .await?;
        api.request(
            Method::POST,
            &format!("auth/{MOUNT}/role/{ROLE}"),
            Some(&operator_configuration()),
            Some(&context.root_token),
        )
        .await?;
        let role = api
            .request(
                Method::GET,
                &format!("auth/{MOUNT}/role/{ROLE}/role-id"),
                None,
                Some(&context.root_token),
            )
            .await?;
        let role = token(role["data"]["role_id"].as_str().ok_or(REFUSAL)?)?;
        write_private(&output.join(ROLE_FILE), role, 1024)?;
        sync_directory(&output)?;
        let secret = api
            .request(
                Method::POST,
                &format!("auth/{MOUNT}/role/{ROLE}/secret-id"),
                Some(&json!({})),
                Some(&context.root_token),
            )
            .await?;
        let secret = token(secret["data"]["secret_id"].as_str().ok_or(REFUSAL)?)?;
        write_private(&output.join(SECRET_FILE), secret, 1024)?;
        sync_directory(&output)?;
        let identity = read_identity(&output, &context.binding)?;
        let authority = session(api, &identity, None).await?;
        let verified: Result<()> = async {
            health(api, &context.binding).await?;
            if before != current_tokens(&current, true)? {
                return Err(REFUSAL);
            }
            Ok(())
        }
        .await;
        let cleanup = revoke(api, &authority).await;
        verified?;
        cleanup
    }
    .await;
    mutation.map_err(|_| RECOVERY)
}

/// Mint private candidate inputs only; activation and full-generation staging are separate.
pub async fn stage(bao: &OpenBaoHttp, identity: &Path, context: &Value) -> Result<Value> {
    let context: Staging = serde_json::from_value(context.clone()).map_err(|_| REFUSAL)?;
    stage_with(&Http(bao), identity, context).await
}

async fn stage_with(api: &impl Api, identity: &Path, context: Staging) -> Result<Value> {
    let identity = read_identity(identity, &context.binding)?;
    let current = owned_directory(&context.current)?;
    let output = owned_directory(&context.output)?;
    let roots = [&identity.directory, &current, &output];
    if roots.iter().collect::<BTreeSet<_>>().len() != 3
        || fs::read_dir(&output).map_err(|_| REFUSAL)?.next().is_some()
    {
        return Err(REFUSAL);
    }
    crate::generation::check_application(&current)?;
    let before = current_tokens(&current, false)?;
    health(api, &context.binding).await?;
    let specs = runtime_specs();
    persist(
        &output.join("attempt.json"),
        &json!({
            "schema":"marty.application-token-input-attempt/v1",
            "binding":context.binding,
            "inputs":specs.iter().map(|spec| spec.file.as_str()).collect::<Vec<_>>()
        }),
        8192,
    )?;
    // Everything from login onward can create authority. Never replay or clean
    // up uncertain private results merely because a later proof failed.
    let mutation: Result<Value> = async {
        let inputs = output.join("inputs");
        create_private_directory(&inputs)?;
        sync_directory(&output)?;
        let authority = session(api, &identity, Some(&output.join("login-response.json"))).await?;
        let work: Result<()> = async {
            prove_current(api, &authority, &before).await?;
            if before != current_tokens(&current, false)? {
                return Err(REFUSAL);
            }
            health(api, &context.binding).await?;
            let previous = before.values().map(String::as_str).collect::<BTreeSet<_>>();
            let mut minted = BTreeSet::new();
            for (index, spec) in specs.iter().enumerate() {
                let leaf = spec.replacement_role.as_deref().ok_or(REFUSAL)?;
                let path = format!("auth/token/create/{leaf}");
                let response = api
                    .capture(
                        &path,
                        &json!({
                            "policies":spec.policies, "no_default_policy":true,
                            "renewable":false, "ttl":format!("{}s", spec.ttl_seconds),
                            "explicit_max_ttl":format!("{}s", spec.ttl_seconds),
                            "type":"service"
                        }),
                        Some(&authority),
                        Some(&output.join(format!("mint-response-{index:02}.json"))),
                    )
                    .await?;
                let value = token(response["auth"]["client_token"].as_str().ok_or(REFUSAL)?)?;
                // Preserve a returned credential before evaluating its metadata.
                write_private(&inputs.join(&spec.file), value, 1024)?;
                sync_directory(&inputs)?;
                if previous.contains(value) || !minted.insert(value.to_owned()) {
                    return Err(REFUSAL);
                }
                auth_metadata(&response["auth"], &spec.policies, spec.ttl_seconds, true)?;
                if !mint_warnings(
                    &response["warnings"],
                    spec.ttl_seconds,
                    response["auth"]["lease_duration"].as_u64().ok_or(REFUSAL)?,
                ) {
                    return Err(REFUSAL);
                }
                let observed = api
                    .request(
                        Method::POST,
                        "auth/token/lookup",
                        Some(&json!({"token":value})),
                        Some(&authority),
                    )
                    .await?;
                metadata(
                    &observed["data"],
                    value,
                    &spec.policies,
                    spec.ttl_seconds,
                    &[&path],
                    Some(false),
                    false,
                )?;
            }
            health(api, &context.binding).await?;
            if before != current_tokens(&current, false)? {
                return Err(REFUSAL);
            }
            Ok(())
        }
        .await;
        let cleanup = revoke(api, &authority).await;
        work?;
        cleanup?;
        persist(
            &output.join("complete.json"),
            &json!({
                "schema":"marty.application-token-input-completion/v1",
                "binding":context.binding, "ready":true,
                "count":specs.len(), "state":"minted-inputs-ready"
            }),
            4096,
        )?;
        Ok(json!({"ready":true,"inputs":inputs,"count":specs.len()}))
    }
    .await;
    mutation.map_err(|_| RECOVERY)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::operator_files::private_file;
    use std::{os::unix::fs::PermissionsExt, sync::Mutex};

    const OPERATOR: &str = "synthetic-application-operator-credential";
    const ROOT: &str = "synthetic-bootstrap-root-credential";
    const ROLE_ID: &str = "11111111-1111-4111-8111-111111111111";
    const SECRET_ID: &str = "22222222-2222-4222-8222-222222222222";

    fn binding() -> Binding {
        Binding {
            namespace: "marty-trial".into(),
            namespace_uid: "33333333-3333-4333-8333-333333333333".into(),
            openbao_cluster_id: "44444444-4444-4444-8444-444444444444".into(),
            workload_project: "marty-selfhost-disposable-k8s-0123456789ab".into(),
        }
    }

    fn synthetic_token(name: &str, new: bool) -> String {
        format!("synthetic-{}-{name}", if new { "new" } else { "old" })
    }

    // Lookup fields follow the deployed OpenBao v2.5.5 token_store.go.
    // Initial bao token create -ttl=8h has explicit_max_ttl=0; role-created
    // replacements carry the role's canonical hard cap.
    fn lookup(value: &str, policies: &[String], ttl: u64, path: &str, initial: bool) -> Value {
        json!({
            "id":value, "policies":policies,
            "ttl":ttl-1, "creation_ttl":ttl,
            "explicit_max_ttl":if initial {0} else {ttl},
            "orphan":true, "renewable":false, "num_uses":0,
            "type":"service", "path":path
        })
    }

    // sdk/logical/translate_response.go serializes num_uses/token_type/orphan
    // for every HTTPAuth; token_policies is optional when empty.
    fn auth(value: &str, policies: &[String], ttl: u64) -> Value {
        json!({
            "client_token":value, "policies":policies, "token_policies":policies,
            "lease_duration":ttl, "renewable":false, "orphan":true,
            "num_uses":0, "token_type":"service"
        })
    }

    struct Fixture {
        _root: tempfile::TempDir,
        current: PathBuf,
        identity: PathBuf,
        operation: PathBuf,
    }

    impl Fixture {
        fn new(full: bool, enrolled: bool) -> Self {
            let root = tempfile::tempdir().unwrap();
            let current = root.path().join("current");
            let identity = root.path().join("identity");
            let operation = root.path().join("operation");
            for path in [&current, &identity, &operation] {
                create_private_directory(path).unwrap();
            }
            for spec in specifications() {
                write_private(
                    &current.join(&spec.file),
                    &synthetic_token(&spec.file, false),
                    1024,
                )
                .unwrap();
            }
            if full {
                write_private(
                    &current.join("workload_identity_ca_cert"),
                    "synthetic-public-ca",
                    1024,
                )
                .unwrap();
                for role in marty_selfhost_identity::SELFHOST_ROLES {
                    write_private(
                        &current.join(role.cert_file),
                        "synthetic-public-certificate",
                        1024,
                    )
                    .unwrap();
                    write_private(
                        &current.join(role.token_file),
                        &synthetic_token(role.token_file, false),
                        1024,
                    )
                    .unwrap();
                }
                write_private(
                    &current.join("keycloak_signing_kms_token"),
                    &synthetic_token("keycloak_signing_kms_token", false),
                    1024,
                )
                .unwrap();
                for realm in crate::keycloak::REALMS {
                    write_private(
                        &current.join(format!("keycloak_{realm}_rs256_cert")),
                        "synthetic-public-certificate",
                        1024,
                    )
                    .unwrap();
                    for purpose in crate::keycloak::PURPOSES {
                        let name = format!("keycloak_{realm}_{purpose}_token");
                        write_private(&current.join(&name), &synthetic_token(&name, false), 1024)
                            .unwrap();
                    }
                }
                assert_eq!(crate::generation::check_application(&current).unwrap(), 53);
            }
            if enrolled {
                write_private(&identity.join(ROLE_FILE), ROLE_ID, 1024).unwrap();
                write_private(&identity.join(SECRET_FILE), SECRET_ID, 1024).unwrap();
                persist(
                    &identity.join(BINDING_FILE),
                    &serde_json::to_value(binding()).unwrap(),
                    4096,
                )
                .unwrap();
            }
            Self {
                _root: root,
                current,
                identity,
                operation,
            }
        }

        fn staging(&self) -> Staging {
            Staging {
                current: self.current.clone(),
                output: self.operation.clone(),
                binding: binding(),
            }
        }

        fn enrollment(&self) -> Enrollment {
            Enrollment {
                root_token: ROOT.into(),
                current: self.current.clone(),
                binding: binding(),
            }
        }
    }

    struct State {
        mount: bool,
        role: Option<Value>,
        operator_policy: Option<String>,
        leaves: BTreeMap<String, Value>,
        issued: BTreeMap<String, Value>,
        calls: Vec<(Method, String)>,
        mutations: usize,
        logins: usize,
        mints: usize,
        revokes: usize,
    }

    struct Fake {
        state: Mutex<State>,
        marker: PathBuf,
        current: PathBuf,
        fault: &'static str,
        at: usize,
    }

    impl Fake {
        fn new(f: &Fixture, enrolled: bool, fault: &'static str, at: usize) -> Self {
            let leaves = if enrolled {
                runtime_specs()
                    .iter()
                    .map(|spec| {
                        (
                            spec.replacement_role.clone().unwrap(),
                            leaf_configuration(spec),
                        )
                    })
                    .collect()
            } else {
                BTreeMap::new()
            };
            Self {
                state: Mutex::new(State {
                    mount: enrolled,
                    role: enrolled.then(operator_configuration),
                    operator_policy: enrolled.then(|| policy().unwrap()),
                    leaves,
                    issued: BTreeMap::new(),
                    calls: vec![],
                    mutations: 0,
                    logins: 0,
                    mints: 0,
                    revokes: 0,
                }),
                marker: if enrolled {
                    f.operation.join("attempt.json")
                } else {
                    f.identity.join(BINDING_FILE)
                },
                current: f.current.clone(),
                fault,
                at,
            }
        }

        fn evaluate(
            &self,
            method: Method,
            path: &str,
            body: Option<&Value>,
            authority: Option<&str>,
        ) -> Result<Value> {
            let mut state = self.state.lock().unwrap();
            state.calls.push((method.clone(), path.into()));
            let body = body.cloned().unwrap_or(Value::Null);
            if path == "sys/health" {
                assert_eq!(method, Method::GET);
                assert!(authority.is_none());
                return Ok(json!({
                    "initialized":true,"sealed":false,"standby":false,
                    "cluster_id":if self.fault=="cluster" {ROLE_ID.to_owned()} else {binding().openbao_cluster_id}
                }));
            }
            if path == "auth/token/revoke-self" {
                assert_eq!(authority, Some(OPERATOR));
                state.revokes += 1;
                return if self.fault == "cleanup" {
                    Err(REFUSAL)
                } else {
                    Ok(json!({}))
                };
            }
            if path == "auth/token/lookup-self" {
                assert_eq!(authority, Some(OPERATOR));
                let mut data = lookup(
                    OPERATOR,
                    &[POLICY.into()],
                    OPERATOR_TTL,
                    &format!("auth/{MOUNT}/login"),
                    false,
                );
                data["renewable"] = json!(true);
                return Ok(json!({"data":data}));
            }
            if path == "auth/token/lookup" {
                assert!([Some(ROOT), Some(OPERATOR)].contains(&authority));
                let value = body["token"].as_str().ok_or(REFUSAL)?;
                let mut data = if let Some(issued) = state.issued.get(value) {
                    issued.clone()
                } else {
                    let spec = runtime_specs()
                        .into_iter()
                        .find(|spec| synthetic_token(&spec.file, false) == value)
                        .ok_or(REFUSAL)?;
                    lookup(
                        value,
                        &spec.policies,
                        spec.ttl_seconds,
                        "auth/token/create",
                        true,
                    )
                };
                if self.fault == "current-bundle" && !state.issued.contains_key(value) {
                    data["policies"] = json!(["root"]);
                }
                return Ok(json!({"data":data}));
            }
            if method == Method::GET {
                if path == "sys/auth" {
                    assert_eq!(authority, Some(ROOT));
                    let mut mounts = json!({});
                    if state.mount {
                        mounts[format!("{MOUNT}/")] = json!({"type":"approle"});
                    }
                    return Ok(json!({"data":mounts}));
                }
                if let Some(name) = path.strip_prefix("sys/policies/acl/") {
                    let mut value = if name == POLICY {
                        state.operator_policy.clone().ok_or(REFUSAL)?
                    } else {
                        initializer_policies(INITIALIZER)?
                            .get(name)
                            .ok_or(REFUSAL)?
                            .clone()
                    };
                    if self.fault == "policy" {
                        value.push_str(
                            "\npath \"auth/token/create\" { capabilities = [\"update\"] }",
                        );
                    }
                    return Ok(json!({"data":{"policy":value}}));
                }
                if let Some(name) = path.strip_prefix("auth/token/roles/") {
                    let mut value = state.leaves.get(name).ok_or(REFUSAL)?.clone();
                    // Canonical role writes leave the deprecated alias at zero.
                    value["explicit_max_ttl"] = json!(0);
                    value["period"] = json!(0);
                    value.as_object_mut().unwrap().remove("token_num_uses");
                    value.as_object_mut().unwrap().remove("token_bound_cidrs");
                    if self.fault == "leaf-role" {
                        value["allowed_policies_glob"] = json!(["*"]);
                    }
                    return Ok(json!({"data":value}));
                }
                if path == format!("auth/{MOUNT}/role/{ROLE}") {
                    return Ok(json!({"data":state.role.clone().ok_or(REFUSAL)?}));
                }
                if path == format!("auth/{MOUNT}/role/{ROLE}/role-id") {
                    assert_eq!(authority, Some(ROOT));
                    assert!(state.role.is_some());
                    return Ok(json!({"data":{"role_id":ROLE_ID}}));
                }
            }
            if path == format!("auth/{MOUNT}/login") {
                assert!(authority.is_none());
                assert_eq!(body, json!({"role_id":ROLE_ID,"secret_id":SECRET_ID}));
                assert!(self.marker.is_file(), "attempt must precede login");
                state.logins += 1;
                if self.fault == "login" {
                    return Err(REFUSAL);
                }
                let mut auth = auth(OPERATOR, &[POLICY.into()], OPERATOR_TTL);
                // AppRole PopulateTokenAuth makes the bounded operator renewable.
                auth["renewable"] = json!(true);
                auth.as_object_mut().unwrap().remove("token_policies");
                return Ok(json!({"auth":auth}));
            }
            if let Some(leaf) = path.strip_prefix("auth/token/create/") {
                assert_eq!(authority, Some(OPERATOR));
                assert!(self.marker.is_file());
                let spec = runtime_specs()
                    .into_iter()
                    .find(|spec| spec.replacement_role.as_deref() == Some(leaf))
                    .ok_or(REFUSAL)?;
                assert!(state.leaves.contains_key(leaf));
                assert_eq!(
                    body,
                    json!({
                        "policies":spec.policies, "no_default_policy":true,
                        "renewable":false,"ttl":"28800s","explicit_max_ttl":"28800s",
                        "type":"service"
                    })
                );
                let index = state.mints;
                state.mints += 1;
                let value = if self.fault == "reuse" && index == self.at {
                    synthetic_token(&spec.file, false)
                } else {
                    synthetic_token(&spec.file, true)
                };
                let mut data = lookup(&value, &spec.policies, spec.ttl_seconds, path, false);
                let capped = index == self.at
                    && matches!(self.fault, "ttl-capped" | "warnings-capped-mismatch");
                if capped {
                    data["creation_ttl"] = json!(28799);
                    data["ttl"] = json!(28798);
                }
                if self.fault == "mint-path" && index == self.at {
                    data["path"] = json!("auth/token/create/foreign");
                }
                if self.fault == "mint-cap" && index == self.at {
                    data["explicit_max_ttl"] = json!(0);
                }
                state.issued.insert(value.clone(), data);
                if self.fault == "mint" && index == self.at {
                    return Err(REFUSAL);
                }
                if self.fault == "drift" && index == self.at {
                    fs::write(
                        self.current.join(&spec.file),
                        b"synthetic-concurrently-changed-current-token\n",
                    )
                    .unwrap();
                }
                // The actual v2.5.5 response always includes this warning when
                // the request and fixed role both specify the same hard cap.
                let expected_warning = "Explicit max TTL specified both during creation call and in role; using the lesser value of 28800 seconds";
                let warnings = match (self.fault, index == self.at) {
                    ("warnings-unknown", true) => json!(["unexpected authority warning"]),
                    ("warnings-extra", true) => {
                        json!([expected_warning, "unexpected additional warning"])
                    }
                    ("warnings-cap", true) => json!([
                        "Explicit max TTL specified both during creation call and in role; using the lesser value of 28799 seconds"
                    ]),
                    ("warnings-type", true) => json!(expected_warning),
                    ("warnings-duplicate", true) => json!([expected_warning, expected_warning]),
                    ("ttl-capped", true) => json!([
                        expected_warning,
                        "TTL of \"8h\" exceeded the effective max_ttl of \"7h59m59s\"; TTL value is capped accordingly"
                    ]),
                    ("warnings-capped-mismatch", true) => json!([
                        expected_warning,
                        "TTL of \"8h\" exceeded the effective max_ttl of \"7h59m58s\"; TTL value is capped accordingly"
                    ]),
                    _ => json!([expected_warning]),
                };
                let mut auth = auth(&value, &spec.policies, spec.ttl_seconds);
                if capped {
                    auth["lease_duration"] = json!(28799);
                }
                return Ok(json!({
                    "auth":auth, "warnings":warnings
                }));
            }
            assert_eq!(authority, Some(ROOT));
            assert!(
                self.marker.is_file(),
                "binding must precede enrollment mutation"
            );
            let index = state.mutations;
            state.mutations += 1;
            if self.fault == "enrollment" && index == self.at {
                return Err(REFUSAL);
            }
            if path == format!("sys/auth/{MOUNT}") {
                assert_eq!(body, json!({"type":"approle"}));
                state.mount = true;
            } else if let Some(name) = path.strip_prefix("auth/token/roles/") {
                state.leaves.insert(name.into(), body);
            } else if path == format!("sys/policies/acl/{POLICY}") {
                state.operator_policy = Some(body["policy"].as_str().ok_or(REFUSAL)?.into());
            } else if path == format!("auth/{MOUNT}/role/{ROLE}") {
                state.role = Some(body);
            } else if path == format!("auth/{MOUNT}/role/{ROLE}/secret-id") {
                return Ok(json!({"data":{"secret_id":SECRET_ID}}));
            } else {
                panic!("unexpected synthetic request: {method} {path}");
            }
            Ok(json!({}))
        }
    }

    #[async_trait]
    impl Api for Fake {
        async fn request(
            &self,
            method: Method,
            path: &str,
            body: Option<&Value>,
            authority: Option<&str>,
        ) -> Result<Value> {
            self.evaluate(method, path, body, authority)
        }

        async fn absent(&self, path: &str, authority: &str) -> Result<()> {
            assert_eq!(authority, ROOT);
            let state = self.state.lock().unwrap();
            if path == format!("sys/policies/acl/{POLICY}") && state.operator_policy.is_none() {
                return Ok(());
            }
            if path
                .strip_prefix("auth/token/roles/")
                .is_some_and(|name| !state.leaves.contains_key(name))
            {
                return Ok(());
            }
            Err(REFUSAL)
        }

        async fn capture(
            &self,
            path: &str,
            body: &Value,
            authority: Option<&str>,
            output: Option<&Path>,
        ) -> Result<Value> {
            let response = self
                .request(Method::POST, path, Some(body), authority)
                .await;
            if let Some(output) = output {
                let record = match &response {
                    Ok(value) => json!({
                        "received":true,"status":200,"complete":true,
                        "bodyBase64":STANDARD.encode(serde_json::to_vec(value).unwrap())
                    }),
                    Err(_) => json!({"received":false}),
                };
                persist(output, &record, 2 * MAX_RESPONSE)?;
            }
            response
        }
    }

    #[test]
    fn policy_bodies_are_extracted_from_one_closed_initializer_inventory() {
        let policies = initializer_policies(INITIALIZER).unwrap();
        assert_eq!(policies.len(), 12);
        assert_eq!(policies["sign-grant-verify"].lines().count(), 7);
        for name in [
            "credential-service",
            "signing-keys-managed",
            "didcomm-issuance",
            "notification-webhook-service",
        ] {
            assert!(INITIALIZER.contains(policies[name].trim_end_matches('\n')));
        }
        let acl = policy().unwrap();
        assert_eq!(acl.matches("path \"auth/token/create/").count(), 11);
        for forbidden in [
            "kms-bootstrap",
            "openbao-service-token",
            "*",
            "sudo",
            "transit/",
            "secret-id",
            "auth/token/create\"",
        ] {
            assert!(!acl.contains(forbidden), "{forbidden}");
        }
        let doubled = format!("{INITIALIZER}\n{INITIALIZER}");
        assert!(initializer_policies(&doubled).is_err());
        let changed = INITIALIZER.replacen(
            "gateway-service gateway-issuer-did",
            "foreign-service gateway-issuer-did",
            1,
        );
        assert!(initializer_policies(&changed).is_err());
        let body = &policies["credential-service"];
        let missing = INITIALIZER.replacen(&format!("{body}EOF\n"), &format!("{body}MISSING\n"), 1);
        assert_ne!(missing, INITIALIZER);
        assert!(initializer_policies(&missing).is_err());
    }

    #[test]
    fn role_configuration_accepts_real_alias_defaults_and_refuses_scope_changes() {
        let spec = runtime_specs().remove(0);
        let mut data = leaf_configuration(&spec);
        data["explicit_max_ttl"] = json!(0);
        data["period"] = json!(0);
        data.as_object_mut().unwrap().remove("token_num_uses");
        data.as_object_mut().unwrap().remove("token_bound_cidrs");
        validate_leaf_configuration(&data, &spec).unwrap();
        for (field, value) in [
            ("allowed_policies", json!([spec.policies[0]])),
            ("disallowed_policies", json!(["default", "root", "root"])),
            ("allowed_policies_glob", json!(["*"])),
            ("disallowed_policies_glob", json!(["foreign*"])),
            ("allowed_entity_aliases", json!(["*"])),
            ("orphan", json!(false)),
            ("renewable", json!(true)),
            ("path_suffix", json!("another")),
            ("token_no_default_policy", json!(false)),
            ("token_explicit_max_ttl", json!(0)),
            ("explicit_max_ttl", json!(86400)),
            ("token_period", json!(3600)),
            ("period", json!(3600)),
            ("token_type", json!("default-service")),
            ("token_num_uses", json!(1)),
        ] {
            let mut bad = data.clone();
            bad[field] = value;
            assert!(validate_leaf_configuration(&bad, &spec).is_err(), "{field}");
        }
        let operator = operator_configuration();
        validate_operator_configuration(&operator).unwrap();
        for field in ["token_num_uses", "token_period", "secret_id_ttl"] {
            let mut missing = operator.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                validate_operator_configuration(&missing).is_err(),
                "{field}"
            );
        }
        for (field, value) in [
            ("bind_secret_id", json!(false)),
            ("token_policies", json!([POLICY, "default"])),
            ("token_ttl", json!(0)),
            ("token_max_ttl", json!(86400)),
            ("token_explicit_max_ttl", json!(0)),
            ("token_period", json!(3600)),
            ("token_no_default_policy", json!(false)),
        ] {
            let mut bad = operator.clone();
            bad[field] = value;
            assert!(validate_operator_configuration(&bad).is_err(), "{field}");
        }
    }

    #[test]
    fn original_bootstrap_cap_zero_never_weakens_fixed_role_token_validation() {
        let spec = runtime_specs().remove(0);
        let value = synthetic_token(&spec.file, false);
        let leaf = format!(
            "auth/token/create/{}",
            spec.replacement_role.as_ref().unwrap()
        );
        for path in ["auth/token/create", "auth/token/create-orphan"] {
            let data = lookup(&value, &spec.policies, spec.ttl_seconds, path, true);
            assert!(metadata(
                &data,
                &value,
                &spec.policies,
                spec.ttl_seconds,
                &[path],
                Some(false),
                true
            )
            .is_ok());
            assert!(metadata(
                &data,
                &value,
                &spec.policies,
                spec.ttl_seconds,
                &[path],
                Some(false),
                false
            )
            .is_err());
        }
        let mut data = lookup(&value, &spec.policies, spec.ttl_seconds, &leaf, false);
        assert!(metadata(
            &data,
            &value,
            &spec.policies,
            spec.ttl_seconds,
            &[&leaf],
            Some(false),
            true
        )
        .is_ok());
        data["explicit_max_ttl"] = json!(0);
        assert!(metadata(
            &data,
            &value,
            &spec.policies,
            spec.ttl_seconds,
            &[&leaf],
            Some(false),
            true
        )
        .is_err());
        data["explicit_max_ttl"] = json!(spec.ttl_seconds);
        for (field, bad) in [
            ("policies", json!([spec.policies[0]])),
            (
                "policies",
                json!([spec.policies[0], spec.policies[1], spec.policies[1]]),
            ),
            ("identity_policies", json!(["root"])),
            ("orphan", json!(false)),
            ("renewable", json!(true)),
            ("ttl", json!(0)),
            ("ttl", json!(28801)),
            ("creation_ttl", json!(86400)),
            ("explicit_max_ttl", json!(86400)),
            ("path", json!("auth/token/create/foreign")),
            ("period", json!(28800)),
            ("id", json!("synthetic-substituted-token")),
            ("type", json!("batch")),
        ] {
            let mut altered = data.clone();
            altered[field] = bad;
            assert!(
                metadata(
                    &altered,
                    &value,
                    &spec.policies,
                    spec.ttl_seconds,
                    &[&leaf],
                    Some(false),
                    true
                )
                .is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn binding_and_identity_are_exact_private_inputs() {
        let f = Fixture::new(true, true);
        read_identity(&f.identity, &binding()).unwrap();
        for field in [
            "namespace",
            "namespaceUid",
            "openbaoClusterId",
            "workloadProject",
        ] {
            let mut bad = serde_json::to_value(binding()).unwrap();
            bad[field] = json!(format!("{}-changed", bad[field].as_str().unwrap()));
            let bad: Binding = serde_json::from_value(bad).unwrap();
            assert!(read_identity(&f.identity, &bad).is_err());
        }
        let mut extra = serde_json::to_value(binding()).unwrap();
        extra["root_token"] = json!(ROOT);
        assert!(serde_json::from_value::<Binding>(extra).is_err());
        let binding_path = f.identity.join(BINDING_FILE);
        let original = fs::read(&binding_path).unwrap();
        let repeated = String::from_utf8(original.clone()).unwrap().replacen(
            "\"namespace\":",
            "\"namespace\":\"foreign\",\"namespace\":",
            1,
        );
        fs::write(&binding_path, repeated).unwrap();
        assert!(read_identity(&f.identity, &binding()).is_err());
        fs::write(&binding_path, original).unwrap();
        fs::set_permissions(&binding_path, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(read_identity(&f.identity, &binding()).is_err());
        fs::set_permissions(&binding_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(
            f.identity.join(ROLE_FILE),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(read_identity(&f.identity, &binding()).is_err());
        fs::set_permissions(
            f.identity.join(ROLE_FILE),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        write_private(
            &f.identity.join("unexpected"),
            "synthetic-private-extra",
            1024,
        )
        .unwrap();
        assert!(read_identity(&f.identity, &binding()).is_err());
    }

    #[tokio::test]
    async fn enrollment_preserves_legacy_tokens_and_exports_only_the_bound_identity() {
        let f = Fixture::new(false, false);
        let before = current_tokens(&f.current, true).unwrap();
        let api = Fake::new(&f, false, "", 0);
        enroll(&api, &f.identity, f.enrollment()).await.unwrap();
        assert_eq!(
            read_identity(&f.identity, &binding()).unwrap().role_id,
            ROLE_ID
        );
        assert_eq!(crate::generation::entries(&f.identity).unwrap().len(), 3);
        assert_eq!(current_tokens(&f.current, true).unwrap(), before);
        let state = api.state.lock().unwrap();
        assert_eq!(state.leaves.len(), 11);
        assert_eq!(state.logins, 1);
        assert_eq!(state.revokes, 1);
        assert_eq!(state.mints, 0);
    }

    #[tokio::test]
    async fn enrollment_refuses_preexisting_authority_or_invalid_current_scope_before_writes() {
        for fault in ["cluster", "policy", "current-bundle"] {
            let f = Fixture::new(false, false);
            let api = Fake::new(&f, false, fault, 0);
            assert_eq!(
                enroll(&api, &f.identity, f.enrollment()).await,
                Err(REFUSAL)
            );
            assert_eq!(fs::read_dir(&f.identity).unwrap().count(), 0);
            assert_eq!(api.state.lock().unwrap().mutations, 0);
        }
        let f = Fixture::new(false, false);
        let api = Fake::new(&f, true, "", 0);
        assert_eq!(
            enroll(&api, &f.identity, f.enrollment()).await,
            Err(REFUSAL)
        );
        assert_eq!(fs::read_dir(&f.identity).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn enrollment_uncertainty_retains_binding_and_cannot_replay() {
        for position in [0, 1, 11, 12, 13, 14] {
            let f = Fixture::new(false, false);
            let api = Fake::new(&f, false, "enrollment", position);
            assert_eq!(
                enroll(&api, &f.identity, f.enrollment()).await,
                Err(RECOVERY)
            );
            assert!(f.identity.join(BINDING_FILE).is_file());
            let calls = api.state.lock().unwrap().calls.len();
            assert_eq!(
                enroll(&api, &f.identity, f.enrollment()).await,
                Err(REFUSAL)
            );
            assert_eq!(api.state.lock().unwrap().calls.len(), calls);
            assert!(!api
                .state
                .lock()
                .unwrap()
                .calls
                .iter()
                .any(|(method, _)| *method == Method::DELETE));
        }
    }

    #[tokio::test]
    async fn stage_requires_complete_generation_before_any_authority_or_attempt() {
        for missing in [
            "workload_identity_ca_cert",
            "keycloak_master_rs256_cert",
            "signing_keys_openbao_token",
        ] {
            let f = Fixture::new(true, true);
            fs::remove_file(f.current.join(missing)).unwrap();
            let api = Fake::new(&f, true, "", 0);
            let error = stage_with(&api, &f.identity, f.staging())
                .await
                .unwrap_err();
            assert_ne!(error, RECOVERY);
            assert_eq!(api.state.lock().unwrap().calls.len(), 0);
            assert_eq!(fs::read_dir(&f.operation).unwrap().count(), 0);
        }
    }

    #[tokio::test]
    async fn stage_mints_exact_private_inputs_and_retires_its_operator_before_completion() {
        let f = Fixture::new(true, true);
        let before = current_tokens(&f.current, false).unwrap();
        let api = Fake::new(&f, true, "", 0);
        let value = stage_with(&api, &f.identity, f.staging()).await.unwrap();
        assert_eq!(
            value,
            json!({"ready":true,"inputs":f.operation.join("inputs"),"count":11})
        );
        assert!(!value.to_string().contains("synthetic"));
        let input_names = crate::generation::entries(&f.operation.join("inputs")).unwrap();
        assert_eq!(
            input_names.keys().cloned().collect::<BTreeSet<_>>(),
            runtime_specs().into_iter().map(|spec| spec.file).collect()
        );
        for (name, path) in input_names {
            assert_eq!(input_token(&path).unwrap(), synthetic_token(&name, true));
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o7777,
                0o600
            );
        }
        assert!(f.operation.join("login-response.json").is_file());
        assert!(f.operation.join("mint-response-10.json").is_file());
        let complete: Value =
            serde_json::from_str(&private_file(&f.operation.join("complete.json")).unwrap())
                .unwrap();
        assert_eq!(complete["state"], "minted-inputs-ready");
        assert_eq!(current_tokens(&f.current, false).unwrap(), before);
        let state = api.state.lock().unwrap();
        assert_eq!((state.logins, state.mints, state.revokes), (1, 11, 1));
        assert_eq!(state.calls.last().unwrap().1, "auth/token/revoke-self");
    }

    #[tokio::test]
    async fn each_uncertain_mint_retains_attempt_captures_and_inputs_without_replay() {
        for position in 0..11 {
            let f = Fixture::new(true, true);
            let before = current_tokens(&f.current, false).unwrap();
            let api = Fake::new(&f, true, "mint", position);
            assert_eq!(
                stage_with(&api, &f.identity, f.staging()).await,
                Err(RECOVERY)
            );
            assert!(f.operation.join("attempt.json").is_file());
            assert!(f
                .operation
                .join(format!("mint-response-{position:02}.json"))
                .is_file());
            assert!(!f.operation.join("complete.json").exists());
            assert_eq!(
                fs::read_dir(f.operation.join("inputs")).unwrap().count(),
                position
            );
            assert_eq!(current_tokens(&f.current, false).unwrap(), before);
            let calls = api.state.lock().unwrap().calls.len();
            assert_eq!(
                stage_with(&api, &f.identity, f.staging()).await,
                Err(REFUSAL)
            );
            assert_eq!(api.state.lock().unwrap().calls.len(), calls);
            assert_eq!(api.state.lock().unwrap().revokes, 1);
        }
    }

    #[tokio::test]
    async fn authority_drift_and_unknown_login_never_reach_leaf_minting() {
        for fault in ["login", "policy", "leaf-role", "current-bundle"] {
            let f = Fixture::new(true, true);
            let api = Fake::new(&f, true, fault, 0);
            assert_eq!(
                stage_with(&api, &f.identity, f.staging()).await,
                Err(RECOVERY)
            );
            assert!(f.operation.join("attempt.json").is_file());
            assert!(f.operation.join("login-response.json").is_file());
            assert!(!f.operation.join("complete.json").exists());
            assert_eq!(api.state.lock().unwrap().mints, 0);
        }
    }

    #[tokio::test]
    async fn replacement_reuse_bad_path_drift_and_cleanup_failure_withhold_completion() {
        for fault in ["reuse", "mint-path", "mint-cap", "drift", "cleanup"] {
            let f = Fixture::new(true, true);
            let api = Fake::new(&f, true, fault, 3);
            assert_eq!(
                stage_with(&api, &f.identity, f.staging()).await,
                Err(RECOVERY)
            );
            assert!(f.operation.join("attempt.json").is_file());
            assert!(!f.operation.join("complete.json").exists());
            assert!(fs::read_dir(f.operation.join("inputs")).unwrap().count() >= 4);
            assert_eq!(api.state.lock().unwrap().revokes, 1);
        }
    }

    #[tokio::test]
    async fn unexpected_mint_warnings_retain_the_returned_token_and_withhold_completion() {
        for fault in [
            "warnings-unknown",
            "warnings-extra",
            "warnings-cap",
            "warnings-type",
            "warnings-duplicate",
            "warnings-capped-mismatch",
        ] {
            let f = Fixture::new(true, true);
            let before = current_tokens(&f.current, false).unwrap();
            let api = Fake::new(&f, true, fault, 3);
            assert_eq!(
                stage_with(&api, &f.identity, f.staging()).await,
                Err(RECOVERY)
            );
            assert!(f.operation.join("attempt.json").is_file());
            assert!(f.operation.join("mint-response-03.json").is_file());
            assert!(!f.operation.join("complete.json").exists());
            assert_eq!(fs::read_dir(f.operation.join("inputs")).unwrap().count(), 4);
            assert_eq!(current_tokens(&f.current, false).unwrap(), before);
            let state = api.state.lock().unwrap();
            assert_eq!((state.logins, state.mints, state.revokes), (1, 4, 1));
        }
    }

    #[tokio::test]
    async fn stage_accepts_only_observed_bounded_lease_capping_with_the_exact_role_cap() {
        let f = Fixture::new(true, true);
        let api = Fake::new(&f, true, "ttl-capped", 3);
        let result = stage_with(&api, &f.identity, f.staging()).await.unwrap();
        assert_eq!(result["count"], 11);
        assert!(f.operation.join("complete.json").is_file());
        let state = api.state.lock().unwrap();
        assert_eq!((state.logins, state.mints, state.revokes), (1, 11, 1));
    }
}
