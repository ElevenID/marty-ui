//! One-shot native feature identity producer. The authenticated installer owns
//! the selection, helper image, input bindings and an exclusive output directory.
//! This producer never creates governed registry objects or activates a runtime.

use base64::{engine::general_purpose::STANDARD, Engine};
use marty_openbao_http::OpenBaoHttp;
use marty_selfhost_identity::features::{self, Identity, Operation, Selection};
use mmf_platform::OpenBaoTlsIdentityFiles;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    env,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    time::Duration,
};

type Result<T> = std::result::Result<T, &'static str>;
const FAILURE: &str =
    "native feature identity provisioning failed; preserve helper evidence and partial output";
const MAX_RESPONSE: usize = 1_048_576;

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(FAILURE)
    }
}

fn setting(name: &str) -> Result<String> {
    env::var(name)
        .ok()
        .filter(|v| !v.is_empty() && v.trim() == v && !v.chars().any(char::is_control))
        .ok_or(FAILURE)
}

fn input(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    require(path.is_absolute())?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| FAILURE)?;
    let meta = file.metadata().map_err(|_| FAILURE)?;
    require(meta.is_file() && meta.nlink() == 1 && meta.len() <= maximum as u64)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| FAILURE)?;
    require(!bytes.is_empty() && bytes.len() <= maximum)?;
    Ok(bytes)
}

struct Output {
    directory: File,
    path: PathBuf,
}
impl Output {
    fn open(path: PathBuf) -> Result<Self> {
        require(path.is_absolute())?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|_| FAILURE)?;
        let meta = directory.metadata().map_err(|_| FAILURE)?;
        require(meta.is_dir() && meta.mode() & 0o7777 == 0o700)?;
        require(fs::read_dir(&path).map_err(|_| FAILURE)?.next().is_none())?;
        Ok(Self { directory, path })
    }
    fn bound(&self) -> Result<()> {
        let held = self.directory.metadata().map_err(|_| FAILURE)?;
        let named = fs::symlink_metadata(&self.path).map_err(|_| FAILURE)?;
        require(
            named.is_dir()
                && !named.file_type().is_symlink()
                && held.dev() == named.dev()
                && held.ino() == named.ino(),
        )
    }
    fn write(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.bound()?;
        require(
            name.starts_with("feature_")
                && !name.contains('/')
                && !bytes.is_empty()
                && bytes.len() <= 65_536
                && !bytes.windows(11).any(|v| v == b"PRIVATE KEY"),
        )?;
        let name = CString::new(name).map_err(|_| FAILURE)?;
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        require(fd >= 0)?;
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes).map_err(|_| FAILURE)?;
        file.sync_all().map_err(|_| FAILURE)?;
        self.directory.sync_all().map_err(|_| FAILURE)?;
        self.bound()
    }
    fn held_path(&self, name: &str) -> PathBuf {
        PathBuf::from(format!(
            "/proc/self/fd/{}/{name}",
            self.directory.as_raw_fd()
        ))
    }
    fn finalize(&self, names: &BTreeSet<String>) -> Result<()> {
        self.bound()?;
        for name in names {
            let name = CString::new(name.as_str()).map_err(|_| FAILURE)?;
            let descriptor = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            require(descriptor >= 0)?;
            let file = unsafe { File::from_raw_fd(descriptor) };
            let metadata = file.metadata().map_err(|_| FAILURE)?;
            require(
                metadata.is_file()
                    && metadata.nlink() == 1
                    && metadata.mode() & 0o7777 == 0o600
                    && metadata.uid() == unsafe { libc::geteuid() },
            )?;
            // The host may use a nonroot operator with a rootful daemon. Only
            // completed files become readable under its original private0700
            // directory; no ownership, parent or destination is substituted.
            require(unsafe { libc::fchmod(file.as_raw_fd(), 0o444) } == 0)?;
            file.sync_all().map_err(|_| FAILURE)?;
        }
        self.directory.sync_all().map_err(|_| FAILURE)?;
        self.bound()
    }
}

struct Bao {
    transport: OpenBaoHttp,
    authority: String,
}

async fn request(
    transport: &OpenBaoHttp,
    method: Method,
    path: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> Result<(StatusCode, Value)> {
    let mut request = transport
        .client()
        .request(method, format!("{}/v1/{path}", transport.origin()));
    if let Some(token) = token {
        request = request.header("X-Vault-Token", token);
    }
    if let Some(value) = body {
        request = request.json(&value);
    }
    let mut response = request.send().await.map_err(|_| FAILURE)?;
    let status = response.status();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| FAILURE)? {
        require(bytes.len().saturating_add(chunk.len()) <= MAX_RESPONSE)?;
        bytes.extend_from_slice(&chunk);
    }
    let value = if bytes.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&bytes).map_err(|_| FAILURE)?
    };
    Ok((status, value))
}

impl Bao {
    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        token: Option<&str>,
    ) -> Result<(StatusCode, Value)> {
        request(
            &self.transport,
            method,
            path,
            body,
            Some(token.unwrap_or(&self.authority)),
        )
        .await
    }
    async fn checked(&self, method: Method, path: &str, body: Option<Value>) -> Result<Value> {
        let (status, value) = self.request(method, path, body, None).await?;
        require(status.is_success())?;
        Ok(value)
    }
    async fn policy(&self, name: &str, policy: &str, operation: Operation) -> Result<()> {
        let path = format!("sys/policies/acl/{name}");
        if operation == Operation::Provision {
            self.checked(Method::PUT, &path, Some(json!({"policy":policy})))
                .await?;
        }
        let found = self.checked(Method::GET, &path, None).await?;
        require(found["data"]["policy"].as_str() == Some(policy))
    }
    async fn leaf_token(&self, names: &[&str], output: &Output, filename: &str) -> Result<String> {
        let response = self
            .checked(
                Method::POST,
                &format!("auth/token/create/{}", features::LEAF_ROLE),
                Some(
                    json!({"policies":names,"no_default_policy":true,"renewable":false,
                "ttl":"8h","explicit_max_ttl":"8h","type":"service"}),
                ),
            )
            .await?;
        let token = response["auth"]["client_token"].as_str().ok_or(FAILURE)?;
        require(valid_token(token.as_bytes()) && token != self.authority)?;
        // Preserve a returned credential before any subsequent remote check.
        output.write(filename, token.as_bytes())?;
        let lookup = self
            .checked(
                Method::POST,
                "auth/token/lookup",
                Some(json!({"token":token})),
            )
            .await?;
        let policies = string_set(&lookup["data"]["policies"])?;
        require(
            policies == names.iter().map(|v| (*v).to_string()).collect()
                && lookup["data"]["orphan"] == true
                && lookup["data"]["renewable"] == false
                && marty_selfhost_identity::renewal_leaf::bounded_metadata(&lookup["data"]),
        )?;
        Ok(token.into())
    }
}

fn valid_token(bytes: &[u8]) -> bool {
    (20..=1024).contains(&bytes.len()) && bytes.iter().all(u8::is_ascii_graphic)
}
fn credential_input(name: &str) -> Result<String> {
    let bytes = input(Path::new(&setting(name)?), 1024)?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| FAILURE)?
        .trim_end_matches('\n');
    require(valid_token(value.as_bytes()))?;
    Ok(value.into())
}
fn string_set(value: &Value) -> Result<BTreeSet<String>> {
    let values = value.as_array().ok_or(FAILURE)?;
    let result: BTreeSet<_> = values
        .iter()
        .map(|v| v.as_str().map(str::to_owned).ok_or(FAILURE))
        .collect::<Result<_>>()?;
    require(result.len() == values.len())?;
    Ok(result)
}
fn ca_der(pem: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(pem).map_err(|_| FAILURE)?;
    let body = text
        .trim()
        .strip_prefix("-----BEGIN CERTIFICATE-----")
        .and_then(|v| v.strip_suffix("-----END CERTIFICATE-----"))
        .ok_or(FAILURE)?;
    let content: String = body.chars().filter(|v| !v.is_ascii_whitespace()).collect();
    let der = STANDARD.decode(content).map_err(|_| FAILURE)?;
    require(der.first() == Some(&0x30) && der.len() <= 65_536)?;
    Ok(der)
}

fn role_configuration(role: Identity) -> Value {
    json!({"allowed_domains":[role.common_name],"allow_bare_domains":true,
        "allow_subdomains":false,"allow_glob_domains":false,"allow_any_name":false,
        "allow_localhost":false,"allow_ip_sans":false,
        "allowed_uri_sans":if role.uri.is_empty() { vec![] } else { vec![role.uri] },
        "server_flag":role.server,"client_flag":role.client,"key_type":"ec","key_bits":256,
        "max_ttl":"8h","use_csr_common_name":false,"use_csr_sans":false})
}

fn check_role(value: &Value, role: Identity) -> Result<()> {
    let data = &value["data"];
    for (name, expected) in [
        ("allow_bare_domains", true),
        ("allow_subdomains", false),
        ("allow_glob_domains", false),
        ("allow_any_name", false),
        ("allow_localhost", false),
        ("allow_ip_sans", false),
        ("server_flag", role.server),
        ("client_flag", role.client),
        ("use_csr_common_name", false),
        ("use_csr_sans", false),
    ] {
        require(data[name].as_bool() == Some(expected))?;
    }
    require(
        string_set(&data["allowed_domains"])? == BTreeSet::from([role.common_name.into()])
            && string_set(&data["allowed_uri_sans"])?
                == (if role.uri.is_empty() {
                    BTreeSet::new()
                } else {
                    BTreeSet::from([role.uri.into()])
                })
            && data["key_type"] == "ec"
            && data["key_bits"] == 256
            && data["max_ttl"].as_u64() == Some(features::MAX_LEAF_SECONDS),
    )
}

fn check_key(value: &Value, algorithm: &str) -> Result<()> {
    let data = &value["data"];
    require(
        data["type"] == algorithm
            && data["exportable"] == false
            && data["allow_plaintext_backup"] == false
            && data["deletion_allowed"] == false
            && data["latest_version"] == 1,
    )
}

fn renewal_policy(selection: &Selection) -> String {
    let mut policy = format!(
        "path \"{}/cert/ca\" {{ capabilities = [\"read\"] }}\n",
        features::PKI_MOUNT
    );
    policy.push_str(&format!(
        "path \"sys/policies/acl/{}\" {{ capabilities = [\"read\"] }}\n",
        features::RENEWAL_POLICY
    ));
    for role in selection.identities() {
        policy.push_str(&format!("path \"transit/keys/{}\" {{ capabilities = [\"read\"] }}\npath \"transit/keys/{}/csr\" {{ capabilities = [\"update\"] }}\npath \"{}/roles/{}\" {{ capabilities = [\"read\"] }}\npath \"{}/sign/{}\" {{ capabilities = [\"update\"] }}\n",
            role.key,role.key,features::PKI_MOUNT,role.role,features::PKI_MOUNT,role.role));
    }
    for origin in selection.grant_origins() {
        policy.push_str(&format!(
            "path \"transit/keys/marty-sign-grant-{origin}-v1\" {{ capabilities = [\"read\"] }}\n"
        ));
    }
    for name in selection.runtime_policies() {
        policy.push_str(&format!(
            "path \"sys/policies/acl/{name}\" {{ capabilities = [\"read\"] }}\n"
        ));
    }
    policy.push_str(&format!("path \"auth/token/roles/{}\" {{ capabilities = [\"read\"] }}\npath \"auth/token/create/{}\" {{ capabilities = [\"update\"] }}\npath \"auth/token/lookup\" {{ capabilities = [\"update\"] }}\npath \"auth/token/lookup-self\" {{ capabilities = [\"read\"] }}\npath \"auth/token/revoke-self\" {{ capabilities = [\"update\"] }}\n", features::LEAF_ROLE,features::LEAF_ROLE));
    for suffix in ["", "/role-id"] {
        policy.push_str(&format!(
            "path \"{}{suffix}\" {{ capabilities = [\"read\"] }}\n",
            approle_path()
        ));
    }
    policy
}

fn approle_path() -> String {
    format!(
        "auth/{}/role/{}",
        features::RENEWAL_AUTH_MOUNT,
        features::RENEWAL_AUTH_ROLE
    )
}

fn approle_configuration() -> Value {
    json!({
        "bind_secret_id":true, "secret_id_num_uses":0, "secret_id_ttl":0,
        "secret_id_bound_cidrs":[], "token_bound_cidrs":[],
        "token_policies":[features::RENEWAL_POLICY], "token_no_default_policy":true,
        "token_num_uses":0, "token_type":"service", "token_period":0,
        "token_ttl":features::RENEWAL_LOGIN_MAX_SECONDS,
        "token_max_ttl":features::RENEWAL_LOGIN_MAX_SECONDS,
        "token_explicit_max_ttl":features::RENEWAL_LOGIN_MAX_SECONDS,
    })
}

fn empty_list(value: Option<&Value>) -> bool {
    value.is_none_or(|value| value.is_null() || value == &json!([]))
}

fn check_approle(data: &Value) -> Result<()> {
    let expected = approle_configuration();
    for (key, value) in expected.as_object().ok_or(FAILURE)? {
        if ["secret_id_bound_cidrs", "token_bound_cidrs"].contains(&key.as_str()) {
            require(empty_list(data.get(key)))?;
        } else {
            require(data.get(key) == Some(value))?;
        }
    }
    Ok(())
}

fn check_login(auth: &Value) -> Result<&str> {
    let token = auth["client_token"].as_str().ok_or(FAILURE)?;
    require(
        valid_token(token.as_bytes())
            && auth["policies"] == json!([features::RENEWAL_POLICY])
            && auth
                .get("token_policies")
                .is_none_or(|value| value == &json!([features::RENEWAL_POLICY]))
            && empty_list(auth.get("identity_policies"))
            && auth["orphan"] == true
            && auth["token_type"] == "service"
            && auth["num_uses"] == 0
            && auth["lease_duration"]
                .as_u64()
                .is_some_and(|ttl| (1..=features::RENEWAL_LOGIN_MAX_SECONDS).contains(&ttl)),
    )?;
    Ok(token)
}

fn check_renewal_lookup(data: &Value) -> Result<()> {
    require(
        string_set(&data["policies"])? == BTreeSet::from([features::RENEWAL_POLICY.into()])
            && empty_list(data.get("identity_policies"))
            && data["orphan"] == true
            && data["type"] == "service"
            && data["num_uses"] == 0
            && data.get("period").is_none_or(|value| value == 0)
            && data["explicit_max_ttl"] == features::RENEWAL_LOGIN_MAX_SECONDS
            && data["creation_ttl"]
                .as_u64()
                .is_some_and(|ttl| (1..=features::RENEWAL_LOGIN_MAX_SECONDS).contains(&ttl))
            && data["ttl"]
                .as_u64()
                .is_some_and(|ttl| (1..=features::RENEWAL_LOGIN_MAX_SECONDS).contains(&ttl))
            && data["path"] == format!("auth/{}/login", features::RENEWAL_AUTH_MOUNT)
            && data["meta"]["role_name"] == features::RENEWAL_AUTH_ROLE,
    )
}

async fn authority(bao: &Bao, selection: &Selection) -> Result<()> {
    let lookup = bao
        .checked(Method::GET, "auth/token/lookup-self", None)
        .await?;
    let scopes = string_set(&lookup["data"]["policies"])?;
    match selection.operation {
        Operation::Provision => require(scopes == BTreeSet::from(["root".into()])),
        Operation::Renew => {
            check_renewal_lookup(&lookup["data"])?;
            let role = bao.checked(Method::GET, &approle_path(), None).await?;
            check_approle(&role["data"])?;
            bao.policy(
                features::RENEWAL_POLICY,
                &renewal_policy(selection),
                Operation::Renew,
            )
            .await?;
            Ok(())
        }
    }
}

async fn renewal_login(
    transport: &OpenBaoHttp,
    selection: &Selection,
    role_id: &str,
    secret_id: &str,
) -> Result<Bao> {
    require(
        valid_token(role_id.as_bytes())
            && valid_token(secret_id.as_bytes())
            && role_id != secret_id,
    )?;
    // AppRole login deliberately carries no root or previous session header.
    let (status, response) = request(
        transport,
        Method::POST,
        &format!("auth/{}/login", features::RENEWAL_AUTH_MOUNT),
        Some(json!({"role_id":role_id,"secret_id":secret_id})),
        None,
    )
    .await?;
    require(status.is_success())?;
    let token = check_login(&response["auth"])?;
    require(token != role_id && token != secret_id)?;
    let scoped = Bao {
        transport: transport.clone(),
        authority: token.into(),
    };
    let mut renewal = selection.clone();
    renewal.operation = Operation::Renew;
    authority(&scoped, &renewal).await?;
    let found = scoped
        .checked(Method::GET, &format!("{}/role-id", approle_path()), None)
        .await?;
    require(found["data"]["role_id"] == role_id)?;
    Ok(scoped)
}

async fn provision_renewal_approle(
    bao: &Bao,
    selection: &Selection,
    output: &Output,
) -> Result<()> {
    require(selection.operation == Operation::Provision)?;
    // The mount was proven absent before any feature authority was created.
    // It is independent of the existing native AppRole mounts and roles.
    bao.checked(
        Method::POST,
        &format!("sys/auth/{}", features::RENEWAL_AUTH_MOUNT),
        Some(json!({
            "type":"approle", "config":{
                "default_lease_ttl":features::RENEWAL_LOGIN_MAX_SECONDS,
                "max_lease_ttl":features::RENEWAL_LOGIN_MAX_SECONDS,
            }
        })),
    )
    .await?;
    bao.checked(Method::POST, &approle_path(), Some(approle_configuration()))
        .await?;
    let role = bao.checked(Method::GET, &approle_path(), None).await?;
    check_approle(&role["data"])?;
    let role = bao
        .checked(Method::GET, &format!("{}/role-id", approle_path()), None)
        .await?;
    let role_id = role["data"]["role_id"].as_str().ok_or(FAILURE)?;
    require(valid_token(role_id.as_bytes()) && role_id != bao.authority)?;
    output.write(features::RENEWAL_ROLE_ID, role_id.as_bytes())?;
    let secret = bao
        .checked(
            Method::POST,
            &format!("{}/secret-id", approle_path()),
            Some(json!({})),
        )
        .await?;
    let secret_id = secret["data"]["secret_id"].as_str().ok_or(FAILURE)?;
    require(
        valid_token(secret_id.as_bytes()) && secret_id != role_id && secret_id != bao.authority,
    )?;
    output.write(features::RENEWAL_SECRET_ID, secret_id.as_bytes())?;
    let stored = bao
        .checked(
            Method::POST,
            &format!("{}/secret-id/lookup", approle_path()),
            Some(json!({"secret_id":secret_id})),
        )
        .await?;
    require(
        stored["data"]["secret_id_ttl"] == 0
            && stored["data"]["secret_id_num_uses"] == 0
            && empty_list(stored["data"].get("cidr_list"))
            && empty_list(stored["data"].get("token_bound_cidrs")),
    )?;
    let scoped = renewal_login(&bao.transport, selection, role_id, secret_id).await?;
    scoped
        .checked(Method::POST, "auth/token/revoke-self", Some(json!({})))
        .await?;
    Ok(())
}

async fn preflight(bao: &Bao, selection: &Selection, expected_ca: &[u8]) -> Result<Vec<u8>> {
    authority(bao, selection).await?;
    let response = bao
        .checked(
            Method::GET,
            &format!("{}/cert/ca", features::PKI_MOUNT),
            None,
        )
        .await?;
    require(response["data"].get("private_key").is_none())?;
    let pem = response["data"]["certificate"]
        .as_str()
        .ok_or(FAILURE)?
        .as_bytes();
    require(ca_der(pem)? == ca_der(expected_ca)?)?;
    if selection.operation == Operation::Provision {
        let mounts = bao.checked(Method::GET, "sys/auth", None).await?;
        require(
            !mounts["data"]
                .as_object()
                .ok_or(FAILURE)?
                .contains_key(&format!("{}/", features::RENEWAL_AUTH_MOUNT)),
        )?;
        let mut resources = vec![
            format!("sys/policies/acl/{}", features::RENEWAL_POLICY),
            format!("auth/token/roles/{}", features::LEAF_ROLE),
        ];
        for role in selection.identities() {
            resources.extend([
                format!("transit/keys/{}", role.key),
                format!("{}/roles/{}", features::PKI_MOUNT, role.role),
                format!("sys/policies/acl/{}", role.role),
            ]);
        }
        for origin in selection.grant_origins() {
            resources.extend([
                format!("transit/keys/marty-sign-grant-{origin}-v1"),
                format!("sys/policies/acl/native-feature-mint-{origin}"),
            ]);
        }
        if selection.public_verification || selection.delegated_use {
            resources.push("sys/policies/acl/native-feature-sign-grant-verify".into());
        }
        if selection.public_verification {
            resources.push("sys/policies/acl/native-feature-demo-holder-custody".into());
        }
        // Every collision is checked before any key, role, policy or token is
        // created. Partial attempts are never adopted by a repeated invocation.
        for path in resources {
            let (status, _) = bao.request(Method::GET, &path, None, None).await?;
            require(status == StatusCode::NOT_FOUND)?;
        }
    }
    Ok(pem.to_vec())
}

async fn prepare_policies(bao: &Bao, selection: &Selection) -> Result<()> {
    for role in selection.identities() {
        bao.policy(role.role, &features::tls_policy(role), selection.operation)
            .await?;
    }
    for origin in selection.grant_origins() {
        let key = format!("marty-sign-grant-{origin}-v1");
        if selection.operation == Operation::Provision {
            bao.checked(
                Method::POST,
                &format!("transit/keys/{key}"),
                Some(json!({
                "type":"hmac","key_size":32,"exportable":false,"allow_plaintext_backup":false})),
            )
            .await?;
        }
        check_key(
            &bao.checked(Method::GET, &format!("transit/keys/{key}"), None)
                .await?,
            "hmac",
        )?;
        bao.policy(
            &format!("native-feature-mint-{origin}"),
            &features::mint_policy(origin).ok_or(FAILURE)?,
            selection.operation,
        )
        .await?;
    }
    if selection.public_verification || selection.delegated_use {
        bao.policy(
            "native-feature-sign-grant-verify",
            &features::verification_policy(selection),
            selection.operation,
        )
        .await?;
    }
    if selection.public_verification {
        bao.policy(
            "native-feature-demo-holder-custody",
            features::DEMO_HOLDER_CUSTODY_POLICY,
            selection.operation,
        )
        .await?;
    }
    let path = format!("auth/token/roles/{}", features::LEAF_ROLE);
    if selection.operation == Operation::Provision {
        bao.checked(
            Method::POST,
            &path,
            Some(json!({"allowed_policies":selection.runtime_policies(),
            "disallowed_policies":["root","default",features::RENEWAL_POLICY],
            "orphan":true,"renewable":false,"token_type":"service",
            "token_explicit_max_ttl":features::MAX_LEAF_SECONDS})),
        )
        .await?;
        bao.policy(
            features::RENEWAL_POLICY,
            &renewal_policy(selection),
            Operation::Provision,
        )
        .await?;
    }
    let role = bao.checked(Method::GET, &path, None).await?;
    require(
        string_set(&role["data"]["allowed_policies"])? == selection.runtime_policies()
            && string_set(&role["data"]["disallowed_policies"])?
                == BTreeSet::from([
                    "root".into(),
                    "default".into(),
                    features::RENEWAL_POLICY.into(),
                ])
            && role["data"]["orphan"] == true
            && role["data"]["renewable"] == false
            && role["data"]["token_explicit_max_ttl"].as_u64() == Some(features::MAX_LEAF_SECONDS),
    )
}

async fn tls_identity(
    bao: &Bao,
    selection: &Selection,
    role: Identity,
    output: &Output,
    ca_file: &Path,
) -> Result<()> {
    let key_path = format!("transit/keys/{}", role.key);
    let role_path = format!("{}/roles/{}", features::PKI_MOUNT, role.role);
    if selection.operation == Operation::Provision {
        bao.checked(
            Method::POST,
            &key_path,
            Some(json!({"type":"ecdsa-p256","exportable":false,"allow_plaintext_backup":false})),
        )
        .await?;
        bao.checked(Method::POST, &role_path, Some(role_configuration(role)))
            .await?;
    }
    check_key(
        &bao.checked(Method::GET, &key_path, None).await?,
        "ecdsa-p256",
    )?;
    check_role(&bao.checked(Method::GET, &role_path, None).await?, role)?;
    let csr = bao
        .checked(
            Method::POST,
            &format!("{key_path}/csr"),
            Some(json!({"version":1})),
        )
        .await?;
    let mut request = json!({"csr":csr["data"]["csr"].as_str().ok_or(FAILURE)?,
        "common_name":role.common_name,"ttl":"8h"});
    if !role.uri.is_empty() {
        request["uri_sans"] = json!(role.uri);
    }
    let issued = bao
        .checked(
            Method::POST,
            &format!("{}/sign/{}", features::PKI_MOUNT, role.role),
            Some(request),
        )
        .await?;
    require(issued["data"].get("private_key").is_none())?;
    let certificate = issued["data"]["certificate"].as_str().ok_or(FAILURE)?;
    ca_der(certificate.as_bytes())?;
    output.write(role.certificate, certificate.as_bytes())?;
    let token = bao.leaf_token(&[role.role], output, role.token).await?;
    OpenBaoTlsIdentityFiles {
        certificate_chain_file: output.held_path(role.certificate),
        kms_ca_cert_file: ca_file.to_owned(),
        kms_endpoint: bao.transport.origin().into(),
        kms_token_file: output.held_path(role.token),
        kms_key_name: role.key.into(),
        kms_key_version: 1,
        request_timeout: Duration::from_secs(5),
        max_concurrent_signs: 1,
    }
    .connect()
    .await
    .map_err(|_| FAILURE)?;
    let foreign = if role.key == features::TRUST_PROFILE.key {
        "workload-tls-flow-server"
    } else {
        features::TRUST_PROFILE.key
    };
    let (denied,_) = bao.request(Method::POST,&format!("transit/sign/{foreign}"),
        Some(json!({"input":STANDARD.encode(b"native-feature-cross-key-denial"),"key_version":1})),Some(&token)).await?;
    require(denied == StatusCode::FORBIDDEN)
}

async fn signing_tokens(bao: &Bao, selection: &Selection, output: &Output) -> Result<()> {
    if selection.public_verification || selection.delegated_use {
        let mut custody = vec!["credential-service", "signing-keys-managed"];
        if selection.public_verification {
            custody.push("native-feature-demo-holder-custody");
        }
        bao.leaf_token(&custody, output, "feature_signing_keys_openbao_token")
            .await?;
        let verify = bao
            .leaf_token(
                &["sign-grant-verify", "native-feature-sign-grant-verify"],
                output,
                "feature_sign_grant_verify_token",
            )
            .await?;
        for origin in selection.grant_origins() {
            let (status, _) = bao
                .request(
                    Method::POST,
                    &format!("transit/hmac/marty-sign-grant-{origin}-v1/sha2-256"),
                    Some(json!({"input":STANDARD.encode(b"native-feature-mint-denial")})),
                    Some(&verify),
                )
                .await?;
            require(status == StatusCode::FORBIDDEN)?;
        }
    }
    if selection.public_verification {
        bao.leaf_token(
            &["native-feature-mint-flow-demo-holder"],
            output,
            "feature_public_verification_holder_mint_token",
        )
        .await?;
    }
    if selection.delegated_use {
        let request = bao
            .leaf_token(
                &["sign-grant-mint-flow-wallet"],
                output,
                "feature_delegated_use_request_mint_token",
            )
            .await?;
        let receipt = bao
            .leaf_token(
                &["native-feature-mint-delegated-decision"],
                output,
                "feature_delegated_use_receipt_mint_token",
            )
            .await?;
        require(request != receipt)?;
    }
    Ok(())
}

async fn run() -> Result<()> {
    require(env::args().len() == 1)?;
    let selection: Selection = serde_json::from_slice(&input(
        Path::new(&setting("FEATURE_IDENTITY_SELECTION_FILE")?),
        8192,
    )?)
    .map_err(|_| FAILURE)?;
    selection.validate().map_err(|_| FAILURE)?;
    let output = Output::open(PathBuf::from(setting("FEATURE_IDENTITY_OUTPUT_DIR")?))?;
    let ca_path = PathBuf::from(setting("BAO_CACERT")?);
    let expected_ca = input(
        Path::new(&setting("FEATURE_IDENTITY_WORKLOAD_CA_FILE")?),
        65_536,
    )?;
    let transport = OpenBaoHttp::connect(
        &setting("BAO_ADDR")?,
        Some(&ca_path),
        Duration::from_secs(10),
    )
    .map_err(|_| FAILURE)?;
    require(transport.origin() == "https://openbao:8200")?;
    let bao = match selection.operation {
        Operation::Provision => {
            require(
                env::var_os("FEATURE_IDENTITY_RENEWAL_ROLE_ID_FILE").is_none()
                    && env::var_os("FEATURE_IDENTITY_RENEWAL_SECRET_ID_FILE").is_none(),
            )?;
            Bao {
                transport,
                authority: credential_input("FEATURE_IDENTITY_AUTHORITY_TOKEN_FILE")?,
            }
        }
        Operation::Renew => {
            require(env::var_os("FEATURE_IDENTITY_AUTHORITY_TOKEN_FILE").is_none())?;
            let role_id = credential_input("FEATURE_IDENTITY_RENEWAL_ROLE_ID_FILE")?;
            let secret_id = credential_input("FEATURE_IDENTITY_RENEWAL_SECRET_ID_FILE")?;
            renewal_login(&transport, &selection, &role_id, &secret_id).await?
        }
    };
    let produced: Result<()> = async {
        let workload_ca = preflight(&bao, &selection, &expected_ca).await?;
        output.write(features::WORKLOAD_CA, &workload_ca)?;
        if selection.delegated_use {
            output.write(features::CLIENT_CA_DER, &ca_der(&workload_ca)?)?;
        }
        prepare_policies(&bao, &selection).await?;
        if selection.operation == Operation::Provision {
            provision_renewal_approle(&bao, &selection, &output).await?;
        }
        for role in selection.identities() {
            tls_identity(&bao, &selection, role, &output, &ca_path).await?;
        }
        signing_tokens(&bao, &selection, &output).await?;
        output.write(
            features::METADATA,
            &serde_json::to_vec(&selection.receipt()).map_err(|_| FAILURE)?,
        )?;
        output.bound()?;
        let actual: BTreeSet<_> = fs::read_dir(&output.path)
            .map_err(|_| FAILURE)?
            .map(|entry| {
                entry
                    .map_err(|_| FAILURE)
                    .and_then(|entry| entry.file_name().into_string().map_err(|_| FAILURE))
            })
            .collect::<Result<_>>()?;
        require(actual == selection.output_names())?;
        output.finalize(&actual)
    }
    .await;
    // A normal completion revokes the short-lived login. If an uncertain
    // execution terminates before cleanup, its explicit maximum is still600s;
    // durable future authority remains only in the original AppRole inputs.
    let revoked = if selection.operation == Operation::Renew {
        bao.checked(Method::POST, "auth/token/revoke-self", Some(json!({})))
            .await
            .map(|_| ())
    } else {
        Ok(())
    };
    produced?;
    revoked
}

#[tokio::main]
async fn main() {
    marty_service_runtime::install_tls_crypto_provider();
    if run().await.is_err() {
        eprintln!("{FAILURE}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn selection() -> Selection {
        Selection {
            schema: features::SCHEMA.into(),
            installation_id: "00000000-0000-4000-8000-000000000001".into(),
            feature_profile_sha256: "a".repeat(64),
            operation: Operation::Renew,
            wallet_governance: true,
            public_verification: true,
            delegated_use: true,
        }
    }
    #[test]
    fn renewal_authority_cannot_create_keys_rewrite_roles_or_expand_signer_policies() {
        let policy = renewal_policy(&selection());
        assert!(!policy.contains("capabilities = [\"create\"]"));
        assert!(
            !policy.contains("sys/mounts")
                && !policy.contains("root/generate")
                && !policy.contains("transit/sign/")
        );
        assert!(
            !policy.contains("transit/keys/*")
                && !policy.contains("transit/export")
                && !policy.contains("transit/backup")
        );
        assert!(policy.contains("auth/token/create/native-feature-identity-leaf"));
        assert!(!policy.contains("auth/token/create-orphan"));
        assert!(!policy.contains("auth/token/renew-self"));
        assert!(!policy.contains("secret-id"));
        assert!(!policy.contains("sys/auth"));
        assert!(policy.contains(&format!(
            "path \"{}\" {{ capabilities = [\"read\"] }}",
            approle_path()
        )));
        for role in selection().identities() {
            let config = role_configuration(role);
            assert_eq!(config["allow_any_name"], false);
            assert_eq!(config["allowed_domains"], json!([role.common_name]));
            assert_eq!(config["server_flag"], role.server);
            assert_eq!(config["client_flag"], role.client);
        }
    }
    #[test]
    fn durable_owner_credentials_issue_only_finite_feature_login_sessions() {
        let role = approle_configuration();
        check_approle(&role).unwrap();
        for (key, value) in [
            ("secret_id_ttl", json!(28_800)),
            ("secret_id_num_uses", json!(1)),
            ("bind_secret_id", json!(false)),
            ("token_policies", json!([features::RENEWAL_POLICY, "root"])),
            ("token_no_default_policy", json!(false)),
            ("token_period", json!(600)),
            ("token_max_ttl", json!(28_800)),
            ("token_explicit_max_ttl", json!(0)),
        ] {
            let mut changed = role.clone();
            changed[key] = value;
            assert!(check_approle(&changed).is_err(), "{key}");
        }
        let auth = json!({
            "client_token":"synthetic_short_lived_feature_login",
            "policies":[features::RENEWAL_POLICY], "token_policies":[features::RENEWAL_POLICY],
            "identity_policies":[], "orphan":true, "token_type":"service", "num_uses":0,
            "lease_duration":features::RENEWAL_LOGIN_MAX_SECONDS,
        });
        check_login(&auth).unwrap();
        let lookup = json!({
            "policies":[features::RENEWAL_POLICY], "identity_policies":[],
            "orphan":true, "type":"service", "num_uses":0, "period":0,
            "explicit_max_ttl":features::RENEWAL_LOGIN_MAX_SECONDS,
            "creation_ttl":features::RENEWAL_LOGIN_MAX_SECONDS, "ttl":590,
            "path":format!("auth/{}/login", features::RENEWAL_AUTH_MOUNT),
            "meta":{"role_name":features::RENEWAL_AUTH_ROLE},
        });
        check_renewal_lookup(&lookup).unwrap();
        for (key, value) in [
            ("ttl", json!(0)),
            ("explicit_max_ttl", json!(28_800)),
            ("period", json!(28_800)),
            ("path", json!("auth/token/create-orphan")),
            ("identity_policies", json!(["unselected-authority"])),
        ] {
            let mut changed = lookup.clone();
            changed[key] = value;
            assert!(check_renewal_lookup(&changed).is_err(), "{key}");
        }
        let mut long_login = auth;
        long_login["lease_duration"] = json!(features::RENEWAL_LOGIN_MAX_SECONDS + 1);
        assert!(check_login(&long_login).is_err());
    }
    #[test]
    fn output_owner_refuses_links_replacement_and_overwrite() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("output");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let output = Output::open(path.clone()).unwrap();
        output
            .write("feature_example_token", b"bounded-file")
            .unwrap();
        assert!(output.write("feature_example_token", b"replace").is_err());
        assert!(output
            .write("feature_bad", b"-----BEGIN PRIVATE KEY-----")
            .is_err());
        assert!(output.write("feature_../escape", b"escape").is_err());
        let other = root.path().join("other");
        fs::create_dir(&other).unwrap();
        fs::rename(&path, root.path().join("retained")).unwrap();
        symlink(&other, &path).unwrap();
        assert!(output.write("feature_new", b"no-redirection").is_err());
        assert!(fs::read_dir(other).unwrap().next().is_none());
    }
}
