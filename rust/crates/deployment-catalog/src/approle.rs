//! Closed self-host AppRole profiles. Shared mechanics preserve role-specific authority.
use crate::{
    operator::{Result, REFUSAL},
    operator_files::{private_directory, private_file, write_private},
};
use marty_openbao_http::OpenBaoHttp;
use marty_selfhost_identity::SELFHOST_ROLES;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    time::Duration,
};

pub const CLEANUP_BOOTSTRAP: &str = "AppRole bootstrap cleanup is incomplete";
pub const CLEANUP_LEAF: &str = "AppRole leaf cleanup is unconfirmed";
const SIGNER: &str = "selfhost-qualification-custody-v1";
const SIGNER_POLICY: &str = "selfhost-qualification-custody-signer";
const AUDIT_POLICY: &str = "selfhost-qualification-audit";
const SNAPSHOT_POLICY: &str = "selfhost-raft-snapshot-read";
const RENEWAL_POLICY: &str = "selfhost-kms-renewal";
const CA_POLICY: &str = "selfhost-kms-ca-rotation";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Audit,
    Evidence,
    Renewal,
    CaRotation,
    Snapshot,
    SnapshotRotator,
}
struct Spec {
    mount: &'static str,
    role: &'static str,
    policy: &'static str,
    role_file: &'static str,
    secret_file: &'static str,
    names_file: Option<&'static str>,
    leaf: Option<(&'static str, u64)>,
    short: bool,
}
impl Role {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "audit" => Ok(Self::Audit),
            "evidence" => Ok(Self::Evidence),
            "renewal" => Ok(Self::Renewal),
            "ca-rotation" => Ok(Self::CaRotation),
            "snapshot" => Ok(Self::Snapshot),
            "snapshot-rotator" => Ok(Self::SnapshotRotator),
            _ => Err(REFUSAL),
        }
    }
    fn spec(self) -> Spec {
        let (mount, role, policy, role_file, secret_file, names_file, leaf, short) = match self {
            Self::Audit => (
                "selfhost-audit",
                "custody-auditor",
                "selfhost-audit-operator",
                "audit-role-id",
                "audit-secret-id",
                None,
                Some(("selfhost-audit-leaf", 3600)),
                false,
            ),
            Self::Evidence => (
                "selfhost-evidence",
                "custody-renewer",
                "selfhost-evidence-operator",
                "evidence-role-id",
                "evidence-secret-id",
                None,
                Some(("selfhost-evidence-leaf", 3600)),
                false,
            ),
            Self::Renewal => (
                "selfhost-renew",
                "kms-renewer",
                RENEWAL_POLICY,
                "renewal-role-id",
                "renewal-secret-id",
                Some("renewal-leaf-policies.json"),
                Some(("selfhost-renew-leaf", 28800)),
                false,
            ),
            Self::CaRotation => (
                "selfhost-ca-rotation",
                "kms-ca-rotator",
                CA_POLICY,
                "ca-rotation-role-id",
                "ca-rotation-secret-id",
                Some("ca-rotation-leaf-policies.json"),
                None,
                false,
            ),
            Self::Snapshot => (
                "selfhost-snapshot",
                "raft-exporter",
                SNAPSHOT_POLICY,
                "snapshot-role-id",
                "snapshot-secret-id",
                None,
                None,
                true,
            ),
            Self::SnapshotRotator => (
                "selfhost-snapshot",
                "raft-exporter-rotator",
                "selfhost-raft-snapshot-rotation",
                "snapshot-rotator-role-id",
                "snapshot-rotator-secret-id",
                None,
                None,
                true,
            ),
        };
        Spec {
            mount,
            role,
            policy,
            role_file,
            secret_file,
            names_file,
            leaf,
            short,
        }
    }
}
fn line(path: &str, caps: &[&str]) -> String {
    format!(
        "path \"{path}\" {{ capabilities = [\"{}\"] }}",
        caps.join("\", \"")
    )
}
fn names(value: &Value) -> Result<Vec<String>> {
    let values = value.as_array().ok_or(REFUSAL)?;
    let names: Vec<String> = values
        .iter()
        .map(|v| v.as_str().map(str::to_owned).ok_or(REFUSAL))
        .collect::<Result<_>>()?;
    if names.len() != 21
        || names.iter().collect::<BTreeSet<_>>().len() != 21
        || names.iter().any(|v| {
            v.is_empty()
                || v.len() > 160
                || !v
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    {
        return Err(REFUSAL);
    }
    Ok(names)
}
fn signer_acl() -> String {
    [
        line(&format!("transit/keys/{SIGNER}"), &["read"]),
        line(&format!("transit/sign/{SIGNER}"), &["update"]),
        line("auth/token/lookup-self", &["read"]),
        line("auth/token/revoke-self", &["update"]),
    ]
    .join("\n")
        + "\n"
}
fn renewal_acl(names: &[String], rotate: bool) -> Result<String> {
    let mut paths: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for (path, caps) in [
        ("sys/mounts", vec!["read"]),
        ("sys/mounts/transit", vec!["read"]),
        ("sys/mounts/workload-pki", vec!["read"]),
        ("auth/token/lookup", vec!["update"]),
        ("sys/capabilities", vec!["update"]),
        ("auth/token/create/selfhost-renew-leaf", vec!["update"]),
        ("auth/token/roles/selfhost-renew-leaf", vec!["read"]),
        ("sys/policies/acl", vec!["list"]),
        ("sys/policies/acl/selfhost-kms-renewal", vec!["read"]),
        ("workload-pki/cert/ca", vec!["read"]),
        ("keycloak-pki/cert/ca", vec!["read"]),
        ("keycloak-pki/roles/rs256", vec!["read"]),
        ("keycloak-pki/sign/rs256", vec!["update"]),
    ] {
        paths.insert(path.into(), caps);
    }
    if rotate {
        for suffix in ["", "/destroy"] {
            paths.insert(
                format!("auth/selfhost-renew/role/kms-renewer/secret-id{suffix}"),
                vec!["update"],
            );
        }
    }
    for name in names {
        if ["root", "default", RENEWAL_POLICY].contains(&name.as_str()) {
            return Err(REFUSAL);
        }
        paths.insert(format!("sys/policies/acl/{name}"), vec!["read"]);
    }
    for role in SELFHOST_ROLES {
        paths.insert(format!("transit/keys/{}", role.key_name), vec!["read"]);
        paths.insert(
            format!("transit/keys/{}/csr", role.key_name),
            vec!["update"],
        );
        paths.insert(format!("workload-pki/roles/{}", role.name), vec!["read"]);
        paths.insert(format!("workload-pki/sign/{}", role.name), vec!["update"]);
    }
    for realm in ["master", "11id"] {
        for kind in ["rs256", "hs512"] {
            paths.insert(
                format!("transit/keys/keycloak-{realm}-{kind}"),
                vec!["read"],
            );
            if kind == "rs256" {
                paths.insert(
                    format!("transit/keys/keycloak-{realm}-{kind}/csr"),
                    vec!["update"],
                );
            }
        }
        for purpose in ["cookie", "ciba"] {
            paths.insert(
                format!("didcomm/keycloak/keys/{realm}/{purpose}"),
                vec!["read"],
            );
        }
    }
    Ok(paths
        .iter()
        .map(|(p, c)| line(p, c))
        .collect::<Vec<_>>()
        .join("\n"))
}
pub fn policy(role: Role, context: &Value) -> Result<String> {
    let spec = role.spec();
    match role {
        Role::Renewal | Role::CaRotation => {
            let names = names(&context["names"])?;
            let base = renewal_acl(
                &names,
                role == Role::Renewal && context["allow_secret_id_rotation"] != false,
            )?;
            if role == Role::Renewal {
                return Ok(base);
            }
            let mut paths = BTreeMap::new();
            paths.insert(format!("sys/policies/acl/{CA_POLICY}"), vec!["read"]);
            for version in 2..=8 {
                for (prefix, roles) in [
                    (
                        "workload-pki",
                        SELFHOST_ROLES.iter().map(|r| r.name).collect::<Vec<_>>(),
                    ),
                    ("keycloak-pki", vec!["rs256"]),
                ] {
                    let mount = format!("{prefix}-v{version}");
                    paths.insert(
                        format!("sys/mounts/{mount}"),
                        vec!["create", "read", "update"],
                    );
                    paths.insert(
                        format!("{mount}/root/generate/internal"),
                        vec!["create", "update"],
                    );
                    paths.insert(format!("{mount}/cert/ca"), vec!["read"]);
                    for role in roles {
                        paths.insert(
                            format!("{mount}/roles/{role}"),
                            vec!["create", "read", "update"],
                        );
                        paths.insert(format!("{mount}/sign/{role}"), vec!["update"]);
                    }
                }
            }
            Ok(base
                + "\n"
                + &paths
                    .iter()
                    .map(|(p, c)| line(p, c))
                    .collect::<Vec<_>>()
                    .join("\n"))
        }
        Role::Snapshot => Ok(line("sys/storage/raft/snapshot", &["read"])),
        Role::SnapshotRotator => Ok([
            line(
                "auth/selfhost-snapshot/role/raft-exporter/secret-id",
                &["update"],
            ),
            line(
                "auth/selfhost-snapshot/role/raft-exporter/secret-id/destroy",
                &["update"],
            ),
            line(
                "auth/selfhost-snapshot/role/raft-exporter-rotator/secret-id",
                &["update"],
            ),
            line(
                "auth/selfhost-snapshot/role/raft-exporter-rotator/secret-id/destroy",
                &["update"],
            ),
            line(
                "auth/selfhost-snapshot/role/raft-exporter-rotator",
                &["read"],
            ),
            line(&format!("sys/policies/acl/{SNAPSHOT_POLICY}"), &["read"]),
            line(&format!("sys/policies/acl/{}", spec.policy), &["read"]),
        ]
        .join("\n")),
        Role::Audit | Role::Evidence => {
            let leaf = spec.leaf.ok_or(REFUSAL)?.0;
            let leaf_policy = if role == Role::Audit {
                AUDIT_POLICY
            } else {
                SIGNER_POLICY
            };
            let mut lines = vec![
                line(&format!("auth/token/create/{leaf}"), &["update"]),
                line(&format!("auth/token/roles/{leaf}"), &["read"]),
                line("auth/token/lookup", &["update"]),
                line(&format!("sys/policies/acl/{leaf_policy}"), &["read"]),
            ];
            if role == Role::Evidence {
                lines.push(line(&format!("transit/keys/{SIGNER}"), &["read"]));
            }
            for suffix in ["", "/destroy"] {
                lines.push(line(
                    &format!("auth/{}/role/{}/secret-id{suffix}", spec.mount, spec.role),
                    &["update"],
                ));
            }
            Ok(lines.join("\n"))
        }
    }
}
fn builder(
    bao: &OpenBaoHttp,
    method: Method,
    path: &str,
    body: Option<&Value>,
    token: Option<&str>,
) -> reqwest::RequestBuilder {
    let mut request = bao
        .client()
        .request(method, format!("{}/v1/{path}", bao.origin()))
        .timeout(Duration::from_secs(10));
    if let Some(body) = body {
        request = request.json(body);
    }
    if let Some(token) = token {
        request = request.header("X-Vault-Token", token);
    }
    request
}
async fn request(
    bao: &OpenBaoHttp,
    method: Method,
    path: &str,
    body: Option<&Value>,
    token: Option<&str>,
) -> Result<Value> {
    let mut response = builder(bao, method, path, body, token)
        .send()
        .await
        .map_err(|_| REFUSAL)?;
    if !response.status().is_success() {
        return Err(REFUSAL);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| REFUSAL)? {
        if bytes.len() + chunk.len() > 1024 * 1024 {
            return Err(REFUSAL);
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        Ok(json!({}))
    } else {
        serde_json::from_slice(&bytes).map_err(|_| REFUSAL)
    }
}
async fn denial(
    bao: &OpenBaoHttp,
    token: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<()> {
    if builder(bao, method, path, body.as_ref(), Some(token))
        .send()
        .await
        .map_err(|_| REFUSAL)?
        .status()
        != StatusCode::FORBIDDEN
    {
        return Err(REFUSAL);
    }
    Ok(())
}
fn owned_identity(_path: &Path, required: bool) -> Result<()> {
    if required {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if fs::metadata(_path).map_err(|_| REFUSAL)?.uid() != unsafe { libc::getuid() } {
                return Err(REFUSAL);
            }
        }
        #[cfg(not(unix))]
        {
            return Err(REFUSAL);
        }
    }
    Ok(())
}
/// Login returns credentials only to its trusted caller; public entrypoints never log them.
pub async fn login(
    bao: &OpenBaoHttp,
    role: Role,
    identity: &Path,
    context: &Value,
) -> Result<Value> {
    if !context.is_object() {
        return Err(REFUSAL);
    }
    let spec = role.spec();
    let identity = private_directory(identity)?;
    owned_identity(&identity, role == Role::CaRotation)?;
    let role_id = private_file(&identity.join(spec.role_file))?
        .trim()
        .to_owned();
    let secret_id = private_file(&identity.join(spec.secret_file))?
        .trim()
        .to_owned();
    if role != Role::Renewal && (role_id.len() < 20 || secret_id.len() < 20) {
        return Err(REFUSAL);
    }
    let mut context = context.clone();
    let policy_names = if let Some(file) = spec.names_file {
        let value: Value =
            serde_json::from_str(&private_file(&identity.join(file))?).map_err(|_| REFUSAL)?;
        let values = names(&value)?;
        context["names"] = json!(values);
        values
    } else {
        vec![]
    };
    let response = request(
        bao,
        Method::POST,
        &format!("auth/{}/login", spec.mount),
        Some(&json!({"role_id":role_id,"secret_id":secret_id})),
        None,
    )
    .await?;
    let auth = &response["auth"];
    let token = auth["client_token"]
        .as_str()
        .filter(|v| v.len() >= 20)
        .ok_or(REFUSAL)?;
    let ttl = auth["lease_duration"].as_u64().ok_or(REFUSAL)?;
    if auth["policies"] != json!([spec.policy])
        || !(if spec.short { 1..=3600 } else { 3600..=28800 }).contains(&ttl)
    {
        return Err(REFUSAL);
    }
    if let Some((leaf, max)) = spec.leaf {
        let data = request(
            bao,
            Method::GET,
            &format!("auth/token/roles/{leaf}"),
            None,
            Some(token),
        )
        .await?;
        let data = &data["data"];
        let mut allowed: Vec<String> = data["allowed_policies"]
            .as_array()
            .ok_or(REFUSAL)?
            .iter()
            .map(|v| v.as_str().map(str::to_owned).ok_or(REFUSAL))
            .collect::<Result<_>>()?;
        let expected = match role {
            Role::Audit => vec![AUDIT_POLICY.to_owned()],
            Role::Evidence => vec![SIGNER_POLICY.to_owned()],
            _ => policy_names.clone(),
        };
        if role == Role::Renewal {
            allowed.sort();
        }
        let disallowed = data["disallowed_policies"]
            .as_array()
            .ok_or(REFUSAL)?
            .iter()
            .map(|v| v.as_str().ok_or(REFUSAL))
            .collect::<Result<BTreeSet<_>>>()?;
        if allowed != expected
            || disallowed != BTreeSet::from(["default", "root"])
            || data["orphan"] != true
            || data["token_no_default_policy"] != true
            || data["token_explicit_max_ttl"] != max
        {
            return Err(REFUSAL);
        }
    }
    match role {
        Role::Audit | Role::Evidence => {
            let leaf_policy = if role == Role::Audit {
                AUDIT_POLICY
            } else {
                SIGNER_POLICY
            };
            let expected = if role == Role::Audit {
                context["policy"].as_str().ok_or(REFUSAL)?.to_owned()
            } else {
                signer_acl()
            };
            if request(
                bao,
                Method::GET,
                &format!("sys/policies/acl/{leaf_policy}"),
                None,
                Some(token),
            )
            .await?["data"]["policy"]
                != expected
            {
                return Err(REFUSAL);
            }
            denial(
                bao,
                token,
                Method::POST,
                &format!("transit/sign/{SIGNER}"),
                Some(json!({"input":"YWJj"})),
            )
            .await?;
            denial(
                bao,
                token,
                Method::POST,
                "auth/token/create",
                Some(json!({"ttl":if role==Role::Audit {"1h"}else{"invalid"}})),
            )
            .await?;
            denial(bao, token, Method::GET, "sys/storage/raft/snapshot", None).await?;
        }
        Role::Renewal | Role::CaRotation => {
            if request(
                bao,
                Method::GET,
                &format!("sys/policies/acl/{}", spec.policy),
                None,
                Some(token),
            )
            .await?["data"]["policy"]
                != policy(role, &context)?
            {
                return Err(REFUSAL);
            }
            if role == Role::Renewal {
                denial(
                    bao,
                    token,
                    Method::GET,
                    "transit/keys/foreign-keycloak-selfhost",
                    None,
                )
                .await?;
                denial(
                    bao,
                    token,
                    Method::POST,
                    "auth/token/create",
                    Some(json!({"ttl":"invalid"})),
                )
                .await?;
                denial(
                    bao,
                    token,
                    Method::PUT,
                    "sys/policies/acl/selfhost-renewal-forbidden-probe",
                    Some(json!({"policy":"invalid policy"})),
                )
                .await?;
                denial(
                    bao,
                    token,
                    Method::POST,
                    "sys/mounts/selfhost-renewal-forbidden-probe",
                    Some(json!({"type":"not-an-engine"})),
                )
                .await?;
            } else {
                denial(
                    bao,
                    token,
                    Method::POST,
                    "sys/mounts/unrelated-ca-probe",
                    Some(json!({"type":"pki"})),
                )
                .await?;
                denial(
                    bao,
                    token,
                    Method::GET,
                    "transit/export/signing-key/workload-tls-organization-server",
                    None,
                )
                .await?;
                denial(
                    bao,
                    token,
                    Method::PUT,
                    "sys/policies/acl/ca-escalation-probe",
                    Some(json!({"policy":"invalid"})),
                )
                .await?;
                denial(
                    bao,
                    token,
                    Method::POST,
                    "auth/selfhost-renew/role/kms-renewer/secret-id",
                    Some(json!({})),
                )
                .await?;
                denial(
                    bao,
                    token,
                    Method::POST,
                    "sys/mounts/workload-pki-v9",
                    Some(json!({"type":"pki"})),
                )
                .await?;
            }
        }
        Role::Snapshot => {
            denial(
                bao,
                token,
                Method::GET,
                "transit/keys/foreign-snapshot-probe",
                None,
            )
            .await?;
            denial(
                bao,
                token,
                Method::POST,
                "auth/token/create",
                Some(json!({"ttl":"invalid"})),
            )
            .await?;
            denial(
                bao,
                token,
                Method::GET,
                &format!("sys/policies/acl/{SNAPSHOT_POLICY}"),
                None,
            )
            .await?;
        }
        Role::SnapshotRotator => {
            let data = request(
                bao,
                Method::GET,
                "auth/selfhost-snapshot/role/raft-exporter-rotator",
                None,
                Some(token),
            )
            .await?;
            if data["data"]["token_policies"] != json!([spec.policy])
                || data["data"]["token_no_default_policy"] != true
            {
                return Err(REFUSAL);
            }
            for (policy_name, expected) in [
                (spec.policy, policy(role, &context)?),
                (SNAPSHOT_POLICY, policy(Role::Snapshot, &json!({}))?),
            ] {
                if request(
                    bao,
                    Method::GET,
                    &format!("sys/policies/acl/{policy_name}"),
                    None,
                    Some(token),
                )
                .await?["data"]["policy"]
                    != expected
                {
                    return Err(REFUSAL);
                }
            }
            denial(bao, token, Method::GET, "sys/storage/raft/snapshot", None).await?;
            denial(
                bao,
                token,
                Method::GET,
                "transit/keys/foreign-snapshot-probe",
                None,
            )
            .await?;
            denial(
                bao,
                token,
                Method::POST,
                "auth/token/create",
                Some(json!({"ttl":"1h"})),
            )
            .await?;
        }
    }
    Ok(json!({"role_id":role_id,"secret_id":secret_id,"names":policy_names,"token":token}))
}

async fn absent(bao: &OpenBaoHttp, path: &str, token: &str) -> Result<()> {
    if builder(bao, Method::GET, path, None, Some(token))
        .send()
        .await
        .map_err(|_| REFUSAL)?
        .status()
        != StatusCode::NOT_FOUND
    {
        return Err(REFUSAL);
    }
    Ok(())
}
fn leaf_policy(role: Role) -> &'static str {
    if role == Role::Audit {
        AUDIT_POLICY
    } else {
        SIGNER_POLICY
    }
}
fn signer_metadata(metadata: &Value) -> Result<()> {
    use base64::Engine;
    if metadata["type"] != "ed25519"
        || metadata["exportable"] != false
        || metadata["allow_plaintext_backup"] != false
        || metadata["latest_version"].as_u64() != Some(1)
    {
        return Err(REFUSAL);
    }
    let encoded = metadata["keys"]["1"]["public_key"]
        .as_str()
        .ok_or(REFUSAL)?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| REFUSAL)?;
    if raw.len() != 32 || base64::engine::general_purpose::STANDARD.encode(&raw) != encoded {
        return Err(REFUSAL);
    }
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend(raw);
    marty_crypto::jwk::public_key_der_to_jwk(&der).map_err(|_| REFUSAL)?;
    Ok(())
}
/// Current-generation validation stays at its existing owner before entering this
/// shared transaction. Context names are that owner's reviewed 21-policy receipt.
pub async fn bootstrap(
    bao: &OpenBaoHttp,
    role: Role,
    output: &Path,
    context: &Value,
) -> Result<()> {
    if !context.is_object() {
        return Err(REFUSAL);
    }
    let spec = role.spec();
    let output = private_directory(output)?;
    owned_identity(&output, role == Role::CaRotation)?;
    if fs::read_dir(&output).map_err(|_| REFUSAL)?.next().is_some() {
        return Err(REFUSAL);
    }
    let token = context["root_token"]
        .as_str()
        .filter(|v| v.len() >= 20)
        .ok_or(REFUSAL)?;
    let policy_names = if spec.names_file.is_some() {
        names(&context["names"])?
    } else {
        vec![]
    };
    if [Role::Audit, Role::Evidence].contains(&role) {
        if role == Role::Evidence {
            signer_metadata(
                &request(
                    bao,
                    Method::GET,
                    &format!("transit/keys/{SIGNER}"),
                    None,
                    Some(token),
                )
                .await?["data"],
            )?;
        }
        let expected = if role == Role::Audit {
            context["policy"].as_str().ok_or(REFUSAL)?.to_owned()
        } else {
            signer_acl()
        };
        if request(
            bao,
            Method::GET,
            &format!("sys/policies/acl/{}", leaf_policy(role)),
            None,
            Some(token),
        )
        .await?["data"]["policy"]
            != expected
        {
            return Err(REFUSAL);
        }
    }
    let mounts = request(bao, Method::GET, "sys/auth", None, Some(token)).await?;
    let mounts = mounts["data"].as_object().ok_or(REFUSAL)?;
    if mounts.contains_key(&format!("{}/", spec.mount)) != (role == Role::SnapshotRotator) {
        return Err(REFUSAL);
    }
    if role == Role::SnapshotRotator
        && request(
            bao,
            Method::GET,
            &format!("sys/policies/acl/{SNAPSHOT_POLICY}"),
            None,
            Some(token),
        )
        .await?["data"]["policy"]
            != policy(Role::Snapshot, &json!({}))?
    {
        return Err(REFUSAL);
    }
    absent(bao, &format!("sys/policies/acl/{}", spec.policy), token).await?;
    if let Some((leaf, _)) = spec.leaf {
        absent(bao, &format!("auth/token/roles/{leaf}"), token).await?;
    }
    if role == Role::SnapshotRotator {
        absent(
            bao,
            &format!("auth/{}/role/{}", spec.mount, spec.role),
            token,
        )
        .await?;
    }
    if role != Role::SnapshotRotator {
        request(
            bao,
            Method::POST,
            &format!("sys/auth/{}", spec.mount),
            Some(&json!({"type":"approle"})),
            Some(token),
        )
        .await?;
    }
    let work:Result<()>=async {
        if let Some((leaf,ttl))=spec.leaf {
            let allowed=if role==Role::Renewal {json!(policy_names)}else{json!([leaf_policy(role)])};
            request(bao,Method::POST,&format!("auth/token/roles/{leaf}"),Some(&json!({"allowed_policies":allowed,"disallowed_policies":["default","root"],"orphan":true,"token_no_default_policy":true,"token_explicit_max_ttl":if ttl==3600 {"1h"}else{"8h"},"token_type":"service"})),Some(token)).await?;
        }
        request(bao,Method::PUT,&format!("sys/policies/acl/{}",spec.policy),Some(&json!({"policy":policy(role,context)?})),Some(token)).await?;
        request(bao,Method::POST,&format!("auth/{}/role/{}",spec.mount,spec.role),Some(&json!({"bind_secret_id":true,"secret_id_num_uses":0,"secret_id_ttl":0,"token_policies":[spec.policy],"token_no_default_policy":true,"token_ttl":if spec.short {"1h"}else{"8h"},"token_max_ttl":if spec.short {"1h"}else{"24h"},"token_type":"service"})),Some(token)).await?;
        let role_data=request(bao,Method::GET,&format!("auth/{}/role/{}/role-id",spec.mount,spec.role),None,Some(token)).await?;
        let secret_data=request(bao,Method::POST,&format!("auth/{}/role/{}/secret-id",spec.mount,spec.role),Some(&json!({})),Some(token)).await?;
        let role_id=role_data["data"]["role_id"].as_str().ok_or(REFUSAL)?; let secret_id=secret_data["data"]["secret_id"].as_str().ok_or(REFUSAL)?;
        if role!=Role::Renewal && (role_id.len()<20 || secret_id.len()<20) {return Err(REFUSAL);}
        write_private(&output.join(spec.role_file),role_id,512)?; write_private(&output.join(spec.secret_file),secret_id,512)?;
        if let Some(file)=spec.names_file {let mut sorted=policy_names.clone(); sorted.sort(); write_private(&output.join(file),&serde_json::to_string(&sorted).map_err(|_|REFUSAL)?,4096)?;}
        if role!=Role::Renewal {login(bao,role,&output,context).await?;}
        Ok(())
    }.await;
    if work.is_err() {
        let mut paths = vec![format!("auth/{}/role/{}", spec.mount, spec.role)];
        // Preserve renewal's reviewed rollback order as well as exhaustive attempts.
        if role == Role::Renewal {
            paths.push(format!("auth/token/roles/{}", spec.leaf.ok_or(REFUSAL)?.0));
        }
        paths.push(format!("sys/policies/acl/{}", spec.policy));
        if [Role::Audit, Role::Evidence].contains(&role) {
            paths.push(format!("auth/token/roles/{}", spec.leaf.ok_or(REFUSAL)?.0));
        }
        if role != Role::SnapshotRotator {
            paths.push(format!("sys/auth/{}", spec.mount));
        }
        let mut incomplete = false;
        for path in paths {
            match builder(bao, Method::DELETE, &path, None, Some(token))
                .send()
                .await
            {
                Ok(response)
                    if response.status().is_success()
                        || response.status() == StatusCode::NOT_FOUND => {}
                _ => incomplete = true,
            }
        }
        for file in [
            Some(spec.role_file),
            Some(spec.secret_file),
            spec.names_file,
        ]
        .into_iter()
        .flatten()
        {
            if let Err(error) = fs::remove_file(output.join(file)) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    incomplete = true;
                }
            }
        }
        if incomplete {
            return Err(CLEANUP_BOOTSTRAP);
        }
    }
    work
}

/// Only audit/evidence leaf minting shares this owner; both keep their canaries.
pub async fn mint(
    bao: &OpenBaoHttp,
    role: Role,
    identity: &Path,
    context: &Value,
) -> Result<String> {
    if ![Role::Audit, Role::Evidence].contains(&role) {
        return Err(REFUSAL);
    }
    let spec = role.spec();
    let operator = login(bao, role, identity, context).await?;
    let operator = operator["token"].as_str().ok_or(REFUSAL)?;
    let leaf_role = spec.leaf.ok_or(REFUSAL)?.0;
    let leaf_policy = leaf_policy(role);
    let created=request(bao,Method::POST,&format!("auth/token/create/{leaf_role}"),Some(&json!({"policies":[leaf_policy],"no_default_policy":true,"renewable":false,"ttl":"1h","explicit_max_ttl":"1h"})),Some(operator)).await?;
    let leaf = created["auth"]["client_token"]
        .as_str()
        .filter(|v| v.len() >= 20)
        .ok_or(REFUSAL)?;
    let verified:Result<()>=async {
        let data=request(bao,Method::POST,"auth/token/lookup",Some(&json!({"token":leaf})),Some(operator)).await?; let data=&data["data"];
        let ttl=data["ttl"].as_u64().ok_or(REFUSAL)?;
        if data["policies"]!=json!([leaf_policy]) || data["orphan"]!=true || data["path"]!=format!("auth/token/create/{leaf_role}") || !(1..=3600).contains(&ttl) {return Err(REFUSAL);}
        if role==Role::Audit {
            let paths=context["paths"].as_array().ok_or(REFUSAL)?.iter().map(|v|v.as_str().ok_or(REFUSAL)).collect::<Result<Vec<_>>>()?;
            let forbidden=[format!("transit/sign/{SIGNER}"),format!("transit/export/signing-key/{SIGNER}"),"auth/token/create".into(),format!("sys/policies/acl/{AUDIT_POLICY}")];
            let all=paths.iter().copied().chain(forbidden.iter().map(String::as_str)).collect::<Vec<_>>();
            let access=request(bao,Method::POST,"sys/capabilities-self",Some(&json!({"paths":all})),Some(leaf)).await?;
            if paths.iter().any(|path|access[*path]!=json!(["read"])) || forbidden.iter().any(|path|access[path]!=json!(["deny"]) && access[path]!=json!([])) {return Err(REFUSAL);}
        }else{
            use base64::Engine;
            let signed=request(bao,Method::POST,&format!("transit/sign/{SIGNER}"),Some(&json!({"input":base64::engine::general_purpose::STANDARD.encode(b"evidence-custody-canary"),"key_version":1})),Some(leaf)).await?;
            if !signed["data"]["signature"].as_str().is_some_and(|v|v.starts_with("vault:v1:")) {return Err(REFUSAL);}
            denial(bao,leaf,Method::GET,&format!("transit/export/signing-key/{SIGNER}"),None).await?;
        }
        Ok(())
    }.await;
    if verified.is_err()
        && request(
            bao,
            Method::POST,
            "auth/token/revoke-self",
            None,
            Some(leaf),
        )
        .await
        .is_err()
    {
        return Err(CLEANUP_LEAF);
    }
    verified?;
    Ok(leaf.to_owned())
}
