//! Installation-bound ingress renewal authority bootstrap ONLY.
//!
//! Not wired into installation yet. A future owned helper must authenticate the
//! original ingress receipt, mount the fixed readonly inputs, record its ID before
//! start, and transfer the private outputs only after terminal validation. This
//! does not renew a certificate, activate a generation, retire root, or mark Ready.
//! Pending evidence and surviving identity files are retained after every uncertain
//! mutation; there is no rollback, adoption or automatic retry.
#![cfg(target_os = "linux")]

use crate::{
    installer_ingress_outputs::IngressMetadata, installer_ingress_provision as ingress,
    installer_renewal_bootstrap as files, operator::version_one_custody, operator_http,
};
use marty_openbao_http::OpenBaoHttp;
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "Ingress renewal authority input refused";
const RECOVERY: &str =
    "Ingress renewal authority incomplete; preserve helper and private outputs for recovery";
pub const IDENTITY_FILES: [&str; 3] = ["role-id.json", "secret-id.json", "authority.json"];
pub const OUTPUT_FILES: [&str; 5] = [
    "pending.json",
    "role-id.json",
    "secret-id.json",
    "authority.json",
    "completed.json",
];

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().ok_or_else(|| REFUSED.into())
}
fn credential(value: &str) -> Result<()> {
    require((20..=4096).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_graphic()))
}

/// Closed identity contract; the source hash binds the caller-authenticated
/// original ingress metadata, not a new authority or a replacement CA.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub schema: String,
    pub installation_id: String,
    pub ingress_metadata_sha256: String,
    pub ca_pem_sha256: String,
    pub public_key_sha256: String,
    pub key_name: String,
    pub key_version: u32,
    pub pki_mount: String,
    pub auth_mount: String,
    pub policy: String,
    pub leaf_role: String,
}
impl Authority {
    fn new(id: &str, metadata: &[u8], ca: &[u8], public: &str) -> Result<Self> {
        let name = ingress::resource_name(id)?;
        Ok(Self {
            schema: "elevenid.installer-ingress-renewal-authority/v1".into(),
            installation_id: id.into(),
            ingress_metadata_sha256: hash(metadata),
            ca_pem_sha256: hash(ca),
            public_key_sha256: hash(public.as_bytes()),
            key_name: name.clone(),
            key_version: 1,
            pki_mount: name.clone(),
            auth_mount: format!("{name}-renew"),
            policy: format!("{name}-renew"),
            leaf_role: format!("{name}-leaf"),
        })
    }
    pub fn validate(&self) -> Result<()> {
        let name = ingress::resource_name(&self.installation_id)?;
        require(
            self.schema == "elevenid.installer-ingress-renewal-authority/v1"
                && self.key_name == name
                && self.pki_mount == name
                && self.key_version == 1
                && self.auth_mount == format!("{name}-renew")
                && self.policy == self.auth_mount
                && self.leaf_role == format!("{name}-leaf")
                && [
                    &self.ingress_metadata_sha256,
                    &self.ca_pem_sha256,
                    &self.public_key_sha256,
                ]
                .iter()
                .all(|s| {
                    s.len() == 64
                        && s.bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                }),
        )
    }
    /// No wildcard, sudo, policy/mount/key write, export, backup or rotation grant.
    pub fn policy_text(&self) -> Result<String> {
        self.validate()?;
        let n = &self.key_name;
        let mut result = String::new();
        for path in [
            format!("transit/keys/{n}"),
            format!("{n}/cert/ca"),
            format!("{n}/roles/localhost"),
            format!("sys/policies/acl/{n}"),
            format!("sys/policies/acl/{}", self.policy),
            format!("auth/token/roles/{}", self.leaf_role),
            "auth/token/lookup-self".into(),
        ] {
            result.push_str(&format!(
                "path \"{path}\" {{ capabilities = [\"read\"] }}\n"
            ));
        }
        result.push_str("path \"auth/token/revoke-self\" { capabilities = [\"update\"] }\n");
        result.push_str(&format!("path \"transit/keys/{n}/csr\" {{\n capabilities = [\"update\"]\n required_parameters = [\"version\"]\n allowed_parameters = {{ \"version\" = [\"1\"] }}\n}}\n"));
        result.push_str(&format!("path \"{n}/sign/localhost\" {{\n capabilities = [\"update\"]\n required_parameters = [\"csr\", \"common_name\", \"alt_names\", \"ip_sans\", \"ttl\"]\n allowed_parameters = {{\n \"csr\" = []\n \"common_name\" = [\"localhost\"]\n \"alt_names\" = [\"localhost\"]\n \"ip_sans\" = [\"127.0.0.1\"]\n \"ttl\" = [\"8h\"]\n }}\n}}\n"));
        result.push_str(&format!("path \"auth/token/create/{}\" {{\n capabilities = [\"update\"]\n required_parameters = [\"policies\", \"no_default_policy\", \"renewable\", \"ttl\", \"explicit_max_ttl\"]\n allowed_parameters = {{\n \"policies\" = [\"{n}\"]\n \"no_default_policy\" = [true]\n \"renewable\" = [false]\n \"ttl\" = [\"8h\"]\n \"explicit_max_ttl\" = [\"8h\"]\n }}\n}}\n",self.leaf_role));
        Ok(result)
    }
    fn leaf_role_body(&self) -> Value {
        json!({"allowed_policies":[self.key_name],"disallowed_policies":["default","root"],
            "orphan":true,"token_no_default_policy":true,"token_explicit_max_ttl":28800,
            "token_period":0,"token_type":"service","renewable":false})
    }
    fn approle_body(&self) -> Value {
        json!({"bind_secret_id":true,"secret_id_num_uses":0,"secret_id_ttl":0,
            "token_policies":[self.policy],"token_no_default_policy":true,"token_num_uses":0,
            "token_ttl":300,"token_max_ttl":300,"token_explicit_max_ttl":300,
            "token_period":0,"token_type":"service"})
    }
}

fn projection(actual: &Value, expected: &Value) -> Result<()> {
    require(
        expected
            .as_object()
            .ok_or(REFUSED)?
            .iter()
            .all(|(k, v)| actual.get(k) == Some(v)),
    )
}

trait Backend {
    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        token: Option<&str>,
    ) -> Result<Value>;
    async fn status(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        token: &str,
    ) -> Result<StatusCode>;
}
impl Backend for OpenBaoHttp {
    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        token: Option<&str>,
    ) -> Result<Value> {
        operator_http::request(self, method, path, body.as_ref(), token)
            .await
            .map_err(|_| REFUSED.into())
    }
    async fn status(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        token: &str,
    ) -> Result<StatusCode> {
        Ok(
            operator_http::builder(self, method, path, body.as_ref(), Some(token))
                .send()
                .await
                .map_err(|_| REFUSED)?
                .status(),
        )
    }
}

/// Container-only future host API. Readonly root.token and ca.crt (Bao transport),
/// plus /input/current private700 with exactly ingress.json600 and public
/// ingress-ca.crt444/ingress-leaf.crt444, owned by root or that held directory's UID. Original ingress
/// metadata authenticity belongs to the ID-before-start host transaction.
pub async fn bootstrap(installation_id: &str) -> Result<usize> {
    use std::os::unix::fs::MetadataExt;
    require(unsafe { libc::geteuid() } == 0)?;
    ingress::resource_name(installation_id)?;
    let root_bytes = files::input(Path::new("/input/root.token"), 4096, &[0], &[0o400])?;
    let root = std::str::from_utf8(&root_bytes)
        .map_err(|_| REFUSED)?
        .trim();
    credential(root)?;
    let ca = files::input(
        Path::new("/input/ca.crt"),
        65536,
        &[0, 100],
        &[0o444, 0o644],
    )?;
    let current = files::directory(Path::new("/input/current"), false, true)?;
    let owner = current.metadata().map_err(|_| REFUSED)?.uid();
    let snapshot = current_inputs(&current, owner)?;
    let metadata = &snapshot[0];
    let ingress_ca = &snapshot[1];
    let ingress_leaf = &snapshot[2];
    let output = files::directory(Path::new("/output"), true, false)?;
    require(files::names(&output)?.is_empty())?;
    let check_inputs = || -> Result<()> {
        require(
            files::input(Path::new("/input/root.token"), 4096, &[0], &[0o400])? == root_bytes
                && files::input(
                    Path::new("/input/ca.crt"),
                    65536,
                    &[0, 100],
                    &[0o444, 0o644],
                )? == ca
                && current_inputs(&current, owner)? == snapshot,
        )?;
        same_directory(&current, Path::new("/input/current"), false, true)?;
        same_directory(&output, Path::new("/output"), true, false)
    };
    let bao = OpenBaoHttp::connect(
        "https://openbao:8200",
        Some(Path::new("/input/ca.crt")),
        Duration::from_secs(10),
    )
    .map_err(|_| REFUSED)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| REFUSED)?
        .as_secs();
    let authority = bootstrap_with(
        &bao,
        installation_id,
        root,
        metadata,
        ingress_ca,
        ingress_leaf,
        &output,
        now,
        &check_inputs,
    )
    .await?;
    // Refuse any changed mount input before returning success to host orchestration.
    let finish: Result<usize> = (|| {
        check_inputs()?;
        files::receipt(&output,"completed.json",&json!({"schema":"elevenid.installer-ingress-renewal-result/v1",
        "authority":authority,"identity_files":IDENTITY_FILES,"scoped_read_and_denial_verified":true,
        "verification_token_revoked":true,"replacement_generation_created":false,
        "activated":false,"root_retired":false,"installation_ready":false})).map_err(|_| RECOVERY)?;
        Ok(IDENTITY_FILES.len())
    })();
    finish.map_err(|_| RECOVERY.into())
}

fn current_inputs(dir: &File, owner: u32) -> Result<[Vec<u8>; 3]> {
    let names = ["ingress.json", "ingress-ca.crt", "ingress-leaf.crt"];
    require(files::names(dir)? == names.map(String::from).into())?;
    Ok([
        files::entry(dir, names[0], &[0, owner], &[0o600], true)?,
        files::entry(dir, names[1], &[0, owner], &[0o444], true)?,
        files::entry(dir, names[2], &[0, owner], &[0o444], true)?,
    ])
}
fn same_directory(held: &File, path: &Path, root: bool, readonly: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let fresh = files::directory(path, root, readonly)?;
    let a = held.metadata().map_err(|_| REFUSED)?;
    let b = fresh.metadata().map_err(|_| REFUSED)?;
    require(
        (a.dev(), a.ino(), a.uid(), a.gid(), a.mode())
            == (b.dev(), b.ino(), b.uid(), b.gid(), b.mode()),
    )
}

#[allow(clippy::too_many_arguments)]
async fn bootstrap_with<B: Backend>(
    bao: &B,
    id: &str,
    root: &str,
    metadata: &[u8],
    ca: &[u8],
    leaf: &[u8],
    output: &File,
    now: u64,
    check_inputs: &impl Fn() -> Result<()>,
) -> Result<Authority> {
    require(files::names(output)?.is_empty())?;
    let m: IngressMetadata = serde_json::from_slice(metadata).map_err(|_| REFUSED)?;
    let n = ingress::resource_name(id)?;
    require(
        m.schema == "elevenid.installer-ingress/v1"
            && m.installation_id == id
            && m.key_name == n
            && m.pki_mount == n
            && m.key_version == 1
            && m.dns_names == ["localhost"]
            && m.ip_addresses == ["127.0.0.1"]
            && m.ca_pem_sha256 == hash(ca)
            && m.certificate_pem_sha256 == hash(leaf)
            && m.ca_expires_at > now.checked_add(28800).ok_or(REFUSED)?
            && !m.installation_ready
            && !m.trust_installed,
    )?;
    ingress::certificate(std::str::from_utf8(ca).map_err(|_| REFUSED)?)?;
    let lookup = bao
        .call(Method::GET, "auth/token/lookup-self", None, Some(root))
        .await?;
    require(lookup["data"]["policies"] == json!(["root"]))?;
    let custody = bao
        .call(Method::GET, &format!("transit/keys/{n}"), None, Some(root))
        .await?;
    version_one_custody(&custody["data"], "ecdsa-p256").map_err(|_| REFUSED)?;
    let public = text(&custody["data"]["keys"]["1"], "public_key")?;
    let (ca_expiry, leaf_expiry) = ingress::check_certificates(
        std::str::from_utf8(ca).map_err(|_| REFUSED)?,
        std::str::from_utf8(leaf).map_err(|_| REFUSED)?,
        public,
        &n,
        now,
    )?;
    require((ca_expiry, leaf_expiry) == (m.ca_expires_at, m.certificate_expires_at))?;
    let authority = Authority::new(id, metadata, ca, public)?;
    let signer = bao
        .call(
            Method::GET,
            &format!("sys/policies/acl/{n}"),
            None,
            Some(root),
        )
        .await?;
    require(signer["data"]["policy"] == ingress::signer_policy(&n)?)?;
    let remote_ca = bao
        .call(Method::GET, &format!("{n}/cert/ca"), None, Some(root))
        .await?;
    require(
        text(&remote_ca["data"], "certificate")?.trim()
            == std::str::from_utf8(ca).map_err(|_| REFUSED)?.trim(),
    )?;
    let pki = bao
        .call(
            Method::GET,
            &format!("{n}/roles/localhost"),
            None,
            Some(root),
        )
        .await?;
    projection(
        &pki["data"],
        &json!({"allow_any_name":false,"allow_localhost":true,"allowed_domains":["localhost"],"allow_bare_domains":true,"allow_subdomains":false,"allow_glob_domains":false,"allow_ip_sans":true,"server_flag":true,"client_flag":false,"key_type":"ec","key_bits":256,"max_ttl":28800,"use_csr_common_name":false,"use_csr_sans":false}),
    )?;
    let mounts = bao.call(Method::GET, "sys/auth", None, Some(root)).await?;
    require(
        !mounts["data"]
            .as_object()
            .ok_or(REFUSED)?
            .contains_key(&format!("{}/", authority.auth_mount)),
    )?;
    for path in [
        format!("sys/policies/acl/{}", authority.policy),
        format!("auth/token/roles/{}", authority.leaf_role),
    ] {
        require(bao.status(Method::GET, &path, None, root).await? == StatusCode::NOT_FOUND)?;
    }
    check_inputs()?;
    create_authority(bao, authority, root, &custody, ca, output).await
}

// Called only after the original installation's certificate/key/policy and
// absent dedicated namespaces are authenticated above. Split for deterministic
// fault injection of the actual mutation and private-persistence sequence.
async fn create_authority<B: Backend>(
    bao: &B,
    authority: Authority,
    root: &str,
    custody: &Value,
    ca: &[u8],
    output: &File,
) -> Result<Authority> {
    require(files::names(output)?.is_empty())?;
    let policy = authority.policy_text()?;
    files::receipt(
        output,
        "pending.json",
        &json!({"schema":"elevenid.installer-ingress-renewal-intent/v1","authority":authority,
        "policy_sha256":hash(policy.as_bytes()),"activated":false,"root_retired":false,"installation_ready":false}),
    )?;
    async {
        bao.call(
            Method::PUT,
            &format!("sys/policies/acl/{}", authority.policy),
            Some(json!({"policy":policy})),
            Some(root),
        )
        .await?;
        let got = bao
            .call(
                Method::GET,
                &format!("sys/policies/acl/{}", authority.policy),
                None,
                Some(root),
            )
            .await?;
        require(got["data"]["policy"] == policy)?;
        bao.call(
            Method::POST,
            &format!("auth/token/roles/{}", authority.leaf_role),
            Some(authority.leaf_role_body()),
            Some(root),
        )
        .await?;
        let leaf = bao
            .call(
                Method::GET,
                &format!("auth/token/roles/{}", authority.leaf_role),
                None,
                Some(root),
            )
            .await?;
        projection(&leaf["data"], &authority.leaf_role_body())?;
        bao.call(
            Method::POST,
            &format!("sys/auth/{}", authority.auth_mount),
            Some(json!({"type":"approle"})),
            Some(root),
        )
        .await?;
        let role_path = format!("auth/{}/role/renewer", authority.auth_mount);
        bao.call(
            Method::POST,
            &role_path,
            Some(authority.approle_body()),
            Some(root),
        )
        .await?;
        let role = bao.call(Method::GET, &role_path, None, Some(root)).await?;
        projection(&role["data"], &authority.approle_body())?;
        let role = bao
            .call(
                Method::GET,
                &format!("{role_path}/role-id"),
                None,
                Some(root),
            )
            .await?;
        let role_id = text(&role["data"], "role_id")?;
        credential(role_id)?;
        require(role_id != root)?;
        files::receipt(output, "role-id.json", &json!({"role_id":role_id}))?;
        let secret = bao
            .call(
                Method::POST,
                &format!("{role_path}/secret-id"),
                Some(json!({})),
                Some(root),
            )
            .await?;
        let secret_id = text(&secret["data"], "secret_id")?;
        credential(secret_id)?;
        require(secret_id != root && secret_id != role_id)?;
        files::receipt(output, "secret-id.json", &json!({"secret_id":secret_id}))?;
        files::receipt(
            output,
            "authority.json",
            &serde_json::to_value(&authority).map_err(|_| REFUSED)?,
        )?;
        // Login can mint before response loss. Pending remains; never retry.
        let login = bao
            .call(
                Method::POST,
                &format!("auth/{}/login", authority.auth_mount),
                Some(json!({"role_id":role_id,"secret_id":secret_id})),
                None,
            )
            .await?;
        let transient = text(&login["auth"], "client_token")?;
        credential(transient)?;
        require(transient != root)?;
        verify_and_retire(bao, &authority, transient, custody, ca).await?;
        for (name, expected) in [
            ("role-id.json", json!({"role_id":role_id})),
            ("secret-id.json", json!({"secret_id":secret_id})),
            (
                "authority.json",
                serde_json::to_value(&authority).map_err(|_| REFUSED)?,
            ),
        ] {
            require(
                files::entry(output, name, &[unsafe { libc::geteuid() }], &[0o600], false)?
                    == serde_json::to_vec(&expected).map_err(|_| REFUSED)?,
            )?;
        }
        require(
            files::names(output)?
                == [
                    "pending.json",
                    "role-id.json",
                    "secret-id.json",
                    "authority.json",
                ]
                .map(String::from)
                .into(),
        )?;
        Ok(authority)
    }
    .await
    .map_err(|_: String| RECOVERY.into())
}

async fn verify_and_retire<B: Backend>(
    bao: &B,
    a: &Authority,
    token: &str,
    custody: &Value,
    ca: &[u8],
) -> Result<()> {
    let proof = prove_login(bao, a, token, custody, ca).await;
    // Every known safe transient is retired even if any proof failed. A failed
    // revoke/denial check remains uncertain; neither identity nor pending is deleted.
    bao.call(Method::POST, "auth/token/revoke-self", None, Some(token))
        .await?;
    require(
        bao.status(Method::GET, "auth/token/lookup-self", None, token)
            .await?
            == StatusCode::FORBIDDEN,
    )?;
    proof
}

async fn prove_login<B: Backend>(
    bao: &B,
    a: &Authority,
    token: &str,
    custody: &Value,
    ca: &[u8],
) -> Result<()> {
    let lookup = bao
        .call(Method::GET, "auth/token/lookup-self", None, Some(token))
        .await?;
    let d = &lookup["data"];
    require(
        d["policies"] == json!([a.policy])
            && d["type"] == "service"
            && d["ttl"].as_u64().is_some_and(|v| v > 0 && v <= 300)
            && d["explicit_max_ttl"] == 300,
    )?;
    require(
        d.get("identity_policies")
            .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))
            && d.get("external_namespace_policies")
                .is_none_or(|v| v.as_object().is_some_and(serde_json::Map::is_empty)),
    )?;
    let key = bao
        .call(
            Method::GET,
            &format!("transit/keys/{}", a.key_name),
            None,
            Some(token),
        )
        .await?;
    require(key["data"] == custody["data"])?;
    let remote_ca = bao
        .call(
            Method::GET,
            &format!("{}/cert/ca", a.pki_mount),
            None,
            Some(token),
        )
        .await?;
    require(
        text(&remote_ca["data"], "certificate")?.trim()
            == std::str::from_utf8(ca).map_err(|_| REFUSED)?.trim(),
    )?;
    for (method, path, body) in denied_requests(a) {
        require(bao.status(method, &path, Some(body), token).await? == StatusCode::FORBIDDEN)?;
    }
    Ok(())
}
fn denied_requests(a: &Authority) -> Vec<(Method, String, Value)> {
    vec![
        (
            Method::POST,
            "auth/token/create".into(),
            json!({"policies":["root"]}),
        ),
        (
            Method::PUT,
            format!("sys/policies/acl/{}", a.policy),
            json!({"policy":""}),
        ),
        (
            Method::POST,
            format!("transit/keys/{}/config", a.key_name),
            json!({"exportable":true}),
        ),
        (
            Method::POST,
            format!("transit/keys/{}/rotate", a.key_name),
            json!({}),
        ),
        (
            Method::GET,
            format!("transit/export/signing-key/{}", a.key_name),
            json!({}),
        ),
        (
            Method::POST,
            format!("{}/root/generate/internal", a.pki_mount),
            json!({}),
        ),
        (
            Method::POST,
            "transit/keys/installer-ingress-00000000000040008000000000000000".into(),
            json!({"type":"ecdsa-p256"}),
        ),
        (
            Method::POST,
            format!("transit/keys/{}/csr", a.key_name),
            json!({"version":"2"}),
        ),
        (
            Method::POST,
            format!("transit/keys/{}/csr", a.key_name),
            json!({"version":1}),
        ),
        (
            Method::POST,
            format!("transit/keys/{}/csr", a.key_name),
            json!({}),
        ),
        (
            Method::GET,
            format!("transit/backup/{}", a.key_name),
            json!({}),
        ),
        (
            Method::POST,
            format!("{}/sign/localhost", a.pki_mount),
            json!({"csr":"invalid-test-csr","common_name":"foreign.example","alt_names":"localhost","ip_sans":"127.0.0.1","ttl":"8h"}),
        ),
        (
            Method::POST,
            format!("{}/sign/localhost", a.pki_mount),
            json!({"csr":"invalid-test-csr","common_name":"localhost","alt_names":"localhost","ip_sans":"127.0.0.1","ttl":"24h"}),
        ),
        (
            Method::POST,
            format!("auth/token/create/{}", a.leaf_role),
            json!({"policies":["root"],"no_default_policy":true,"renewable":false,"ttl":"8h","explicit_max_ttl":"8h"}),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    const ID: &str = "11111111-1111-4111-8111-111111111111";
    fn authority() -> Authority {
        Authority::new(ID, b"metadata", b"ca", "public").unwrap()
    }
    #[test]
    fn closed_installation_scope_and_policy() {
        let a = authority();
        let policy = a.policy_text().unwrap();
        assert!(policy.contains("\"version\" = [\"1\"]"));
        assert!(policy.contains("\"renewable\" = [false]"));
        assert!(
            !policy.contains('*')
                && !policy.contains("sudo")
                && !policy.contains("selfhost-renew-leaf")
        );
        for field in [
            "key_name",
            "pki_mount",
            "auth_mount",
            "policy",
            "leaf_role",
            "installation_id",
            "ingress_metadata_sha256",
        ] {
            let mut altered = serde_json::to_value(&a).unwrap();
            altered[field] = json!("foreign");
            assert!(serde_json::from_value::<Authority>(altered)
                .unwrap()
                .validate()
                .is_err());
        }
        let mut other = a.clone();
        other.key_version = 2;
        assert!(other.validate().is_err());
        let mut raw = serde_json::to_value(&a).unwrap();
        raw["root_token"] = json!("forbidden");
        assert!(serde_json::from_value::<Authority>(raw).is_err());
    }
    #[test]
    fn role_readback_cannot_widen_mint_or_login() {
        let a = authority();
        for (key, value) in [
            ("allowed_policies", json!([a.key_name, "root"])),
            ("orphan", json!(false)),
            ("token_no_default_policy", json!(false)),
            ("token_explicit_max_ttl", json!(0)),
            ("renewable", json!(true)),
        ] {
            let expected = a.leaf_role_body();
            let mut actual = expected.clone();
            actual[key] = value;
            assert!(projection(&actual, &expected).is_err());
        }
        let expected = a.approle_body();
        let mut actual = expected.clone();
        actual["token_policies"] = json!(["root"]);
        assert!(projection(&actual, &expected).is_err());
    }
    struct Mock {
        allow_bad: bool,
        calls: std::cell::RefCell<Vec<String>>,
    }
    impl Backend for Mock {
        async fn call(
            &self,
            _: Method,
            path: &str,
            _: Option<Value>,
            _: Option<&str>,
        ) -> Result<Value> {
            self.calls.borrow_mut().push(path.into());
            let a = authority();
            Ok(if path == "auth/token/lookup-self" {
                json!({"data":{"policies":[a.policy],"type":"service","ttl":299,"explicit_max_ttl":300}})
            } else if path.ends_with("cert/ca") {
                json!({"data":{"certificate":"ca"}})
            } else {
                json!({"data":{"key":"same"}})
            })
        }
        async fn status(
            &self,
            _: Method,
            path: &str,
            _: Option<Value>,
            _: &str,
        ) -> Result<StatusCode> {
            self.calls.borrow_mut().push(path.into());
            Ok(if self.allow_bad {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            })
        }
    }
    #[tokio::test]
    async fn positive_reads_do_not_substitute_for_denial_proofs() {
        for allow_bad in [false, true] {
            let mock = Mock {
                allow_bad,
                calls: Default::default(),
            };
            let result = prove_login(
                &mock,
                &authority(),
                "synthetic scoped token",
                &json!({"data":{"key":"same"}}),
                b"ca",
            )
            .await;
            assert_eq!(result.is_err(), allow_bad);
            assert!(mock.calls.borrow().iter().any(|p| p == "auth/token/create"));
            if !allow_bad {
                assert_eq!(
                    mock.calls.borrow().len(),
                    3 + denied_requests(&authority()).len()
                );
            }
        }
    }
    #[tokio::test]
    async fn failed_proof_still_attempts_self_revocation_and_denial() {
        let mock = Mock {
            allow_bad: true,
            calls: Default::default(),
        };
        assert!(verify_and_retire(
            &mock,
            &authority(),
            "synthetic scoped token",
            &json!({"data":{"key":"same"}}),
            b"ca"
        )
        .await
        .is_err());
        let calls = mock.calls.borrow();
        assert_eq!(
            &calls[calls.len() - 2..],
            ["auth/token/revoke-self", "auth/token/lookup-self"]
        );
        assert!(!calls.iter().any(|p| p == "auth/token/revoke"));
    }
    struct Transaction {
        output: std::path::PathBuf,
        records: std::cell::RefCell<std::collections::BTreeMap<String, Value>>,
        calls: std::cell::RefCell<Vec<(String, String)>>,
        fault: &'static str,
    }
    impl Backend for Transaction {
        async fn call(
            &self,
            method: Method,
            path: &str,
            body: Option<Value>,
            token: Option<&str>,
        ) -> Result<Value> {
            assert!(
                self.output.join("pending.json").is_file(),
                "remote operation preceded durable intent"
            );
            self.calls
                .borrow_mut()
                .push((path.into(), token.unwrap_or("").into()));
            if path.ends_with("/role-id") {
                return Ok(json!({"data":{"role_id":"synthetic-role-identifier"}}));
            }
            if path.ends_with("/secret-id") {
                if self.fault == "secret-response-lost" {
                    return Err("synthetic failure".into());
                }
                return Ok(json!({"data":{"secret_id":"synthetic-secret-identifier"}}));
            }
            if path.ends_with("/login") {
                return Ok(
                    json!({"auth":{"client_token":if self.fault=="root-response" {"synthetic-root-authority-token"}else{"synthetic-renewal-login-token"}}}),
                );
            }
            if path == "auth/token/lookup-self" {
                return Ok(
                    json!({"data":{"policies":[authority().policy],"type":"service","ttl":299,"explicit_max_ttl":300}}),
                );
            }
            if path == "auth/token/revoke-self" {
                return Ok(json!({}));
            }
            if path.starts_with("transit/keys/") {
                return Ok(json!({"data":{"key":"same"}}));
            }
            if path.ends_with("/cert/ca") {
                return Ok(json!({"data":{"certificate":"ca"}}));
            }
            if method == Method::GET {
                return Ok(json!({"data":self.records.borrow().get(path).unwrap()}));
            }
            self.records.borrow_mut().insert(path.into(), body.unwrap());
            Ok(json!({}))
        }
        async fn status(
            &self,
            _: Method,
            path: &str,
            _: Option<Value>,
            token: &str,
        ) -> Result<StatusCode> {
            self.calls.borrow_mut().push((path.into(), token.into()));
            Ok(
                if self.fault == "denial-failed" && path != "auth/token/lookup-self" {
                    StatusCode::OK
                } else {
                    StatusCode::FORBIDDEN
                },
            )
        }
    }
    #[tokio::test]
    async fn real_authority_transaction_retains_uncertainty_and_never_replays_or_revokes_root() {
        use std::os::unix::fs::PermissionsExt;
        for fault in [
            "none",
            "secret-response-lost",
            "denial-failed",
            "root-response",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let dir = files::directory(tmp.path(), false, false).unwrap();
            let mock = Transaction {
                output: tmp.path().into(),
                records: Default::default(),
                calls: Default::default(),
                fault,
            };
            let result = create_authority(
                &mock,
                authority(),
                "synthetic-root-authority-token",
                &json!({"data":{"key":"same"}}),
                b"ca",
                &dir,
            )
            .await;
            assert_eq!(result.is_ok(), fault == "none");
            assert!(
                !tmp.path().join("completed.json").exists(),
                "completion belongs to final source continuity gate"
            );
            assert!(tmp.path().join("pending.json").is_file());
            assert!(tmp.path().join("role-id.json").is_file());
            let calls = mock.calls.borrow().clone();
            assert!(!calls.iter().any(
                |(p, t)| p == "auth/token/revoke-self" && t == "synthetic-root-authority-token"
            ));
            assert_eq!(
                calls
                    .iter()
                    .filter(|(p, _)| p == "auth/token/revoke-self")
                    .count(),
                usize::from(fault == "none" || fault == "denial-failed")
            );
            assert!(create_authority(
                &mock,
                authority(),
                "synthetic-root-authority-token",
                &json!({"data":{"key":"same"}}),
                b"ca",
                &dir
            )
            .await
            .is_err());
            assert_eq!(
                *mock.calls.borrow(),
                calls,
                "retry performed remote operations"
            );
        }
    }
    #[test]
    fn exclusive_private_pending_blocks_replay_and_preserves_partial_identity() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = files::directory(tmp.path(), false, false).unwrap();
        files::receipt(&dir, "pending.json", &json!({"authority":authority()})).unwrap();
        files::receipt(
            &dir,
            "role-id.json",
            &json!({"role_id":"synthetic-role-id-value"}),
        )
        .unwrap();
        assert!(files::receipt(&dir, "pending.json", &json!({})).is_err());
        assert_eq!(
            std::fs::metadata(tmp.path().join("role-id.json"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        assert!(!tmp.path().join("completed.json").exists());
        assert_eq!(
            files::names(&dir).unwrap(),
            BTreeSet::from(["pending.json".into(), "role-id.json".into()])
        );
    }
    #[test]
    fn held_output_directory_replacement_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("output");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = files::directory(&path, false, false).unwrap();
        same_directory(&held, &path, false, false).unwrap();
        std::fs::rename(&path, tmp.path().join("retained")).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(same_directory(&held, &path, false, false).is_err());
        files::receipt(&held, "pending.json", &json!({"retained":true})).unwrap();
        assert!(tmp.path().join("retained/pending.json").is_file());
        assert!(!path.join("pending.json").exists());
    }
}
