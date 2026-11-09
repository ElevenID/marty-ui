//! Closed self-host AppRole profiles. Shared mechanics preserve role-specific authority.
use crate::operator_http::{builder, denial, request};
use crate::{
    operator::{Result, REFUSAL},
    operator_files::{private_directory, private_file, write_private},
};
use marty_openbao_http::OpenBaoHttp;
use marty_selfhost_identity::{origin::PublicOrigin, SELFHOST_ROLES};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::IpAddr,
    path::Path,
};

pub const CLEANUP_BOOTSTRAP: &str = "AppRole bootstrap cleanup is incomplete";
pub const CLEANUP_LEAF: &str = "AppRole leaf cleanup is unconfirmed";
pub const CLEANUP_ROTATION: &str = "AppRole rotation requires operator recovery";
pub const CLEANUP_REFRESH: &str = "Scoped token refresh requires operator recovery";
pub(crate) const SIGNER: &str = "selfhost-qualification-custody-v1";
pub(crate) const SIGNER_POLICY: &str = "selfhost-qualification-custody-signer";
pub(crate) const AUDIT_POLICY: &str = "selfhost-qualification-audit";
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
    Application,
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
            "application" => Ok(Self::Application),
            _ => Err(REFUSAL),
        }
    }
    fn spec(self) -> Spec {
        let (mount, role, policy, role_file, secret_file, names_file, leaf, short) = match self {
            Self::Application => (
                crate::application_authority::MOUNT,
                crate::application_authority::ROLE,
                crate::application_authority::POLICY,
                crate::application_authority::ROLE_FILE,
                crate::application_authority::SECRET_FILE,
                None,
                None,
                true,
            ),
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
    let ingress = names
        .iter()
        .filter(|name| name.starts_with("installer-ingress-"))
        .collect::<Vec<_>>();
    let valid_ingress = ingress.len() == 1
        && ingress[0]
            .strip_prefix("installer-ingress-")
            .is_some_and(|suffix| {
                suffix.len() == 32
                    && suffix
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            });
    if !((names.len() == 21 && ingress.is_empty()) || (names.len() == 22 && valid_ingress))
        || names.iter().collect::<BTreeSet<_>>().len() != names.len()
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
/// Derive the installation identity only from the retained, read-only PKI role.
/// IP literals in allowed_domains are metadata for the ACL, not an OpenBao IP
/// SAN restriction. Legacy workload-only renewal never enters this path.
fn ingress_sign_acl(name: &str, role: &Value) -> Result<String> {
    let domains = role["allowed_domains"].as_array().ok_or(REFUSAL)?;
    if !(1..=2).contains(&domains.len()) {
        return Err(REFUSAL);
    }
    let common = domains[0].as_str().ok_or(REFUSAL)?;
    let address = common.parse::<IpAddr>().ok();
    let authority = match address {
        Some(IpAddr::V6(ip)) => format!("[{ip}]"),
        _ => common.to_owned(),
    };
    let origin = PublicOrigin::parse(&format!("https://{authority}")).map_err(|_| REFUSAL)?;
    let dns = origin.dns_name().unwrap_or("");
    if origin
        .ip_address()
        .is_some_and(|ip| ip.to_string() != common)
        || (address.is_none() && dns != common)
    {
        return Err(REFUSAL);
    }
    let allow_ip = role["allow_ip_sans"].as_bool().ok_or(REFUSAL)?;
    let entry_ip = domains
        .get(1)
        .map(|value| {
            let text = value.as_str().ok_or(REFUSAL)?;
            let ip: IpAddr = text.parse().map_err(|_| REFUSAL)?;
            if ip.to_string() != text
                || ip.is_loopback()
                || dns == "localhost"
                || origin.did_web_authority().is_err()
            {
                return Err(REFUSAL);
            }
            Ok(ip)
        })
        .transpose()?;
    let ip = match (origin.ip_address(), dns, allow_ip, entry_ip) {
        (Some(ip), "", true, None) => ip.to_string(),
        (None, "localhost", true, None) => "127.0.0.1".into(),
        (None, _, false, None) => String::new(),
        (None, _, true, Some(ip)) => ip.to_string(),
        _ => return Err(REFUSAL),
    };
    // CSR-provided identities must never override these explicit parameters.
    // Validate the role before any bootstrap mutation and again at each login.
    for (field, expected) in [
        ("allow_any_name", json!(false)),
        ("allow_localhost", json!(dns == "localhost")),
        ("allow_bare_domains", json!(true)),
        ("allow_subdomains", json!(false)),
        ("allow_glob_domains", json!(false)),
        ("allow_wildcard_certificates", json!(false)),
        ("server_flag", json!(true)),
        ("client_flag", json!(false)),
        ("key_type", json!("ec")),
        ("key_bits", json!(256)),
        ("max_ttl", json!(28800)),
        ("use_csr_common_name", json!(false)),
        ("use_csr_sans", json!(false)),
        (
            "cn_validations",
            json!([if dns.is_empty() {
                "disabled"
            } else {
                "hostname"
            }]),
        ),
    ] {
        if role[field] != expected {
            return Err(REFUSAL);
        }
    }
    let common = serde_json::to_string(common).map_err(|_| REFUSAL)?;
    let dns = serde_json::to_string(dns).map_err(|_| REFUSAL)?;
    let ip = serde_json::to_string(&ip).map_err(|_| REFUSAL)?;
    // Required parameters close the API-default gap. No wildcard key or value
    // is allowed: callers cannot add URI/other SANs, reuse CSR SANs, or extend
    // certificate lifetime. The CSR remains the only unconstrained value.
    Ok(format!(
        "path \"{name}/sign/localhost\" {{\n  capabilities = [\"update\"]\n  required_parameters = [\"csr\", \"common_name\", \"alt_names\", \"ip_sans\", \"exclude_cn_from_sans\", \"ttl\"]\n  allowed_parameters = {{\n    \"csr\" = []\n    \"common_name\" = [{common}]\n    \"alt_names\" = [{dns}]\n    \"ip_sans\" = [{ip}]\n    \"exclude_cn_from_sans\" = [true]\n    \"ttl\" = [\"8h\"]\n  }}\n}}"
    ))
}

async fn renewal_context(
    bao: &OpenBaoHttp,
    role: Role,
    token: &str,
    policy_names: &[String],
    context: &Value,
) -> Result<Value> {
    let mut context = context.clone();
    let public_ingress = public_ingress_context(role, policy_names, &context)?;
    if role == Role::Renewal {
        if let Some(name) = policy_names
            .iter()
            .find(|name| name.starts_with("installer-ingress-"))
        {
            if public_ingress {
                // The public source carries an already admitted certificate.
                // Its TLS token owner never needs a private-CA role or CSR.
                return Ok(context);
            }
            let response = request(
                bao,
                Method::GET,
                &format!("{name}/roles/localhost"),
                None,
                Some(token),
            )
            .await?;
            ingress_sign_acl(name, &response["data"])?;
            context["ingress_role"] = response["data"].clone();
        }
    }
    Ok(context)
}

fn public_ingress_context(role: Role, names: &[String], context: &Value) -> Result<bool> {
    match context.get("ingress_certificate_source") {
        None => Ok(false),
        Some(value)
            if value == "acme"
                && role == Role::Renewal
                && names.len() == 22
                && names
                    .iter()
                    .filter(|name| name.starts_with("installer-ingress-"))
                    .count()
                    == 1 =>
        {
            Ok(true)
        }
        _ => Err(REFUSAL),
    }
}

fn renewal_acl(
    names: &[String],
    rotate: bool,
    ingress_role: &Value,
    public_ingress: bool,
) -> Result<String> {
    let mut paths: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    let mut ingress = None;
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
        if name.starts_with("installer-ingress-") {
            if public_ingress {
                paths.insert(format!("transit/keys/{name}"), vec!["read"]);
                continue;
            }
            // Reuse the reviewed leaf-policy inventory as the installation
            // scope. This grants CSR issuance for its retained version-one
            // key and CA, never creation, export, rotation, or policy mutation.
            for (path, caps) in [
                (format!("transit/keys/{name}"), vec!["read"]),
                (format!("transit/keys/{name}/csr"), vec!["update"]),
                (format!("{name}/cert/ca"), vec!["read"]),
                (format!("{name}/roles/localhost"), vec!["read"]),
            ] {
                paths.insert(path, caps);
            }
            ingress = Some(ingress_sign_acl(name, ingress_role)?);
        }
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
    let mut acl = paths
        .iter()
        .map(|(p, c)| line(p, c))
        .collect::<Vec<_>>()
        .join("\n");
    if let Some(ingress) = ingress {
        acl.push('\n');
        acl.push_str(&ingress);
    }
    Ok(acl)
}
pub fn policy(role: Role, context: &Value) -> Result<String> {
    let spec = role.spec();
    match role {
        Role::Application => crate::application_authority::policy(),
        Role::Renewal | Role::CaRotation => {
            let names = names(&context["names"])?;
            if role == Role::CaRotation && names.len() != 21 {
                return Err(REFUSAL);
            }
            let base = renewal_acl(
                &names,
                role == Role::Renewal && context["allow_secret_id_rotation"] != false,
                &context["ingress_role"],
                public_ingress_context(role, &names, context)?,
            )?;
            if role == Role::Renewal {
                // Renewal operators must retire their own short-lived login
                // without mounting bootstrap root or gaining authority to
                // revoke other tokens. Orphan leaves remain independent.
                return Ok(base + "\n" + &line("auth/token/revoke-self", &["update"]));
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
pub(crate) fn owned_identity(_path: &Path, required: bool) -> Result<()> {
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
    if role == Role::Application {
        return crate::application_authority::login(bao, identity, context).await;
    }
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
    validated_login(bao, role, &role_id, &secret_id, policy_names, &context).await
}

async fn validated_login(
    bao: &OpenBaoHttp,
    role: Role,
    role_id: &str,
    secret_id: &str,
    policy_names: Vec<String>,
    context: &Value,
) -> Result<Value> {
    let spec = role.spec();
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
        Role::Application => return Err(REFUSAL),
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
            let context = renewal_context(bao, role, token, &policy_names, context).await?;
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
                (spec.policy, policy(role, context)?),
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

fn credential<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key].as_str().filter(|v| !v.is_empty()).ok_or(REFUSAL)
}

async fn revoked(bao: &OpenBaoHttp, role: Role, role_id: &str, secret_id: &str) -> Result<()> {
    let response = builder(
        bao,
        Method::POST,
        &format!("auth/{}/login", role.spec().mount),
        Some(&json!({"role_id": role_id, "secret_id": secret_id})),
        None,
    )
    .send()
    .await
    .map_err(|_| REFUSAL)?;
    if !matches!(
        response.status(),
        StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN
    ) {
        return Err(REFUSAL);
    }
    Ok(())
}

fn rotation_directory(role: Role, path: &Path) -> bool {
    let prefix = match role {
        Role::Audit => "audit-identity",
        Role::Evidence => "evidence-identity",
        Role::Snapshot => "snapshot-identity",
        Role::SnapshotRotator => "snapshot-rotator-identity",
        _ => return false,
    };
    path.file_name()
        .and_then(|v| v.to_str())
        .is_some_and(|name| {
            name == prefix
                || name
                    .strip_prefix(prefix)
                    .and_then(|v| v.strip_prefix('-'))
                    .is_some_and(|v| {
                        (1..=80).contains(&v.len())
                            && v.bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    })
        })
}

async fn rotation_authority(
    bao: &OpenBaoHttp,
    role: Role,
    context: &Value,
    fallback: &str,
) -> Result<String> {
    if role != Role::Snapshot {
        return Ok(fallback.to_owned());
    }
    let manager = Path::new(credential(context, "manager_identity")?);
    let login = login(bao, Role::SnapshotRotator, manager, &json!({})).await?;
    Ok(credential(&login, "token")?.to_owned())
}

/// Commit a verified replacement before retiring the previous SecretID.
/// Once retirement starts, preserve the staged identity for operator recovery.
pub async fn rotate(
    bao: &OpenBaoHttp,
    role: Role,
    identity: &Path,
    context: &Value,
    retiring: bool,
) -> Result<()> {
    if matches!(role, Role::CaRotation | Role::Application) {
        return Err(REFUSAL);
    }
    let identity = private_directory(identity)?;
    let other = private_directory(Path::new(credential(
        context,
        if retiring { "retired" } else { "output" },
    )?))?;
    if identity == other
        || (!retiring
            && role != Role::Renewal
            && (identity.parent() != other.parent()
                || !rotation_directory(role, &identity)
                || !rotation_directory(role, &other)))
    {
        return Err(REFUSAL);
    }
    if !retiring && fs::read_dir(&other).map_err(|_| REFUSAL)?.next().is_some() {
        return Err(REFUSAL);
    }
    let spec = role.spec();
    let current = login(bao, role, &identity, context).await?;
    let role_id = credential(&current, "role_id")?;
    let old_secret = credential(&current, "secret_id")?;
    let old_token = credential(&current, "token")?;
    let path = format!("auth/{}/role/{}/secret-id", spec.mount, spec.role);
    if retiring {
        let retired_role = private_file(&other.join(spec.role_file))?;
        let retired_secret = private_file(&other.join(spec.secret_file))?;
        if retired_role.trim() != role_id || retired_secret.trim() == old_secret {
            return Err(REFUSAL);
        }
        let token = rotation_authority(bao, role, context, old_token).await?;
        request(
            bao,
            Method::POST,
            &format!("{path}/destroy"),
            Some(&json!({"secret_id": retired_secret.trim()})),
            Some(&token),
        )
        .await
        .map_err(|_| CLEANUP_ROTATION)?;
        return revoked(bao, role, role_id, retired_secret.trim())
            .await
            .map_err(|_| CLEANUP_ROTATION);
    }
    let create_token = rotation_authority(bao, role, context, old_token).await?;
    let created = request(
        bao,
        Method::POST,
        &path,
        Some(&json!({})),
        Some(&create_token),
    )
    .await
    .map_err(|_| CLEANUP_ROTATION)?;
    let new_secret = created["data"]["secret_id"]
        .as_str()
        .filter(|v| v.len() >= 20 && *v != old_secret)
        .ok_or(CLEANUP_ROTATION)?;
    let files: Vec<_> = [
        Some(spec.role_file),
        Some(spec.secret_file),
        spec.names_file,
    ]
    .into_iter()
    .flatten()
    .map(|n| other.join(n))
    .collect();
    let staged: Result<Value> = async {
        // Renewal historically qualifies the replacement before writing any
        // credential or policy receipt. Other roles validate their staged files.
        let qualified = if role == Role::Renewal {
            let mut renewed_context = context.clone();
            renewed_context["names"] = current["names"].clone();
            Some(
                validated_login(
                    bao,
                    role,
                    role_id,
                    new_secret,
                    names(&current["names"])?,
                    &renewed_context,
                )
                .await?,
            )
        } else {
            None
        };
        write_private(&other.join(spec.role_file), role_id, 512)?;
        write_private(&other.join(spec.secret_file), new_secret, 512)?;
        if let Some(file) = spec.names_file {
            write_private(
                &other.join(file),
                &serde_json::to_string(&current["names"]).map_err(|_| REFUSAL)?,
                4096,
            )?;
        }
        match qualified {
            Some(value) => Ok(value),
            None => login(bao, role, &other, context).await,
        }
    }
    .await;
    let replacement = match staged {
        Ok(value) => value,
        Err(error) => {
            // Try every local cleanup and remote revocation, even if one fails.
            let mut clean = true;
            for file in files {
                if let Err(e) = fs::remove_file(file) {
                    clean &= e.kind() == std::io::ErrorKind::NotFound;
                }
            }
            clean &= request(
                bao,
                Method::POST,
                &format!("{path}/destroy"),
                Some(&json!({"secret_id": new_secret})),
                Some(&create_token),
            )
            .await
            .is_ok();
            return Err(if clean { error } else { CLEANUP_ROTATION });
        }
    };
    let destroy_token = rotation_authority(bao, role, context, credential(&replacement, "token")?)
        .await
        .map_err(|_| CLEANUP_ROTATION)?;
    request(
        bao,
        Method::POST,
        &format!("{path}/destroy"),
        Some(&json!({"secret_id": old_secret})),
        Some(&destroy_token),
    )
    .await
    .map_err(|_| CLEANUP_ROTATION)?;
    revoked(bao, role, role_id, old_secret)
        .await
        .map_err(|_| CLEANUP_ROTATION)
}

/// The caller has durably staged the replacement; never discard it on uncertainty.
pub async fn refresh_leaf(bao: &OpenBaoHttp, context: &Value) -> Result<()> {
    let old = credential(context, "old_token")?;
    let new = credential(context, "new_token")?;
    let operator = credential(context, "operator_token")?;
    if old == new {
        return Err(REFUSAL);
    }
    let status = builder(bao, Method::POST, "auth/token/revoke-self", None, Some(old))
        .send()
        .await
        .map_err(|_| CLEANUP_REFRESH)?
        .status();
    if status.is_success() {
        return Ok(());
    }
    if !matches!(status, StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN) {
        return Err(CLEANUP_REFRESH);
    }
    let response = builder(
        bao,
        Method::POST,
        "auth/token/lookup",
        Some(&json!({"token": old})),
        Some(operator),
    )
    .send()
    .await
    .map_err(|_| CLEANUP_REFRESH)?;
    match response.status() {
        StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND => Ok(()),
        StatusCode::FORBIDDEN => {
            let data = request(
                bao,
                Method::POST,
                "auth/token/lookup",
                Some(&json!({"token": new})),
                Some(operator),
            )
            .await
            .map_err(|_| CLEANUP_REFRESH)?;
            if data["data"]["ttl"].as_u64().is_some_and(|v| v > 0) {
                Ok(())
            } else {
                Err(CLEANUP_REFRESH)
            }
        }
        _ => Err(CLEANUP_REFRESH),
    }
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
    crate::operator::custody_signer(metadata, true).map(|_| ())
}
/// Current-generation validation stays at its existing owner before entering this
/// shared transaction. Context names are that owner's reviewed leaf-policy
/// receipt: 21 legacy scopes, or those scopes plus one managed ingress scope.
pub async fn bootstrap(
    bao: &OpenBaoHttp,
    role: Role,
    output: &Path,
    context: &Value,
) -> Result<()> {
    if role == Role::Application {
        return crate::application_authority::bootstrap(bao, output, context).await;
    }
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
    let context = renewal_context(bao, role, token, &policy_names, context).await?;
    // Validate the complete identity-bound policy while the transaction is
    // still read-only, so an ambiguous role cannot leave a partial authority.
    let expected_policy = policy(role, &context)?;
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
        request(bao,Method::PUT,&format!("sys/policies/acl/{}",spec.policy),Some(&json!({"policy":expected_policy})),Some(token)).await?;
        request(bao,Method::POST,&format!("auth/{}/role/{}",spec.mount,spec.role),Some(&json!({"bind_secret_id":true,"secret_id_num_uses":0,"secret_id_ttl":0,"token_policies":[spec.policy],"token_no_default_policy":true,"token_ttl":if spec.short {"1h"}else{"8h"},"token_max_ttl":if spec.short {"1h"}else{"24h"},"token_type":"service"})),Some(token)).await?;
        let role_data=request(bao,Method::GET,&format!("auth/{}/role/{}/role-id",spec.mount,spec.role),None,Some(token)).await?;
        let secret_data=request(bao,Method::POST,&format!("auth/{}/role/{}/secret-id",spec.mount,spec.role),Some(&json!({})),Some(token)).await?;
        let role_id=role_data["data"]["role_id"].as_str().ok_or(REFUSAL)?; let secret_id=secret_data["data"]["secret_id"].as_str().ok_or(REFUSAL)?;
        if role!=Role::Renewal && (role_id.len()<20 || secret_id.len()<20) {return Err(REFUSAL);}
        write_private(&output.join(spec.role_file),role_id,512)?; write_private(&output.join(spec.secret_file),secret_id,512)?;
        if let Some(file)=spec.names_file {let mut sorted=policy_names.clone(); sorted.sort(); write_private(&output.join(file),&serde_json::to_string(&sorted).map_err(|_|REFUSAL)?,4096)?;}
        if role!=Role::Renewal {login(bao,role,&output,&context).await?;}
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
    let verified: Result<()> = async {
        let data = request(
            bao,
            Method::POST,
            "auth/token/lookup",
            Some(&json!({"token":leaf})),
            Some(operator),
        )
        .await?;
        crate::leaf_tokens::metadata(
            &data["data"],
            leaf_policy,
            false,
            Some(&format!("auth/token/create/{leaf_role}")),
        )?;
        if role == Role::Audit {
            crate::leaf_tokens::audit_access(bao, leaf, context).await
        } else {
            crate::leaf_tokens::evidence_access(bao, leaf, true).await
        }
    }
    .await;
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

#[cfg(test)]
mod ingress_renewal_policy_tests {
    use super::*;

    fn workload_names() -> Vec<String> {
        (0..21)
            .map(|index| format!("workload-leaf-{index:02}"))
            .collect()
    }

    fn ingress_role(common: &str, allow_ip: bool) -> Value {
        json!({
            "allowed_domains":[common],"allow_ip_sans":allow_ip,
            "allow_any_name":false,"allow_localhost":common=="localhost",
            "allow_bare_domains":true,"allow_subdomains":false,
            "allow_glob_domains":false,"allow_wildcard_certificates":false,
            "server_flag":true,"client_flag":false,"key_type":"ec","key_bits":256,
            "max_ttl":28800,"use_csr_common_name":false,"use_csr_sans":false,
            "cn_validations":[if common.parse::<IpAddr>().is_ok() {"disabled"} else {"hostname"}]
        })
    }

    #[test]
    fn renewal_extends_only_one_exact_installation_scope() {
        let name = "installer-ingress-12345678123442348234123456789abc";
        let mut inventory = workload_names();
        assert!(names(&json!(inventory)).is_ok());
        let legacy = policy(Role::Renewal, &json!({"names":inventory})).unwrap();
        assert!(!legacy.contains("installer-ingress-"));
        inventory.push(name.into());
        assert!(names(&json!(inventory)).is_ok());
        assert!(policy(Role::Renewal, &json!({"names":inventory})).is_err());
        let role = ingress_role("localhost", true);
        let acl = policy(
            Role::Renewal,
            &json!({"names":inventory,"ingress_role":role}),
        )
        .unwrap();
        for (path, caps) in [
            (format!("transit/keys/{name}"), vec!["read"]),
            (format!("transit/keys/{name}/csr"), vec!["update"]),
            (format!("{name}/cert/ca"), vec!["read"]),
            (format!("{name}/roles/localhost"), vec!["read"]),
        ] {
            assert!(acl.contains(&line(&path, &caps)));
        }
        assert!(acl.contains(&ingress_sign_acl(name, &role).unwrap()));
        assert!(!acl.contains(&line(&format!("{name}/sign/localhost"), &["update"])));
        for forbidden in [
            "/rotate",
            "transit/export/",
            "transit/backup/",
            "root/generate",
            "installer-ingress-*",
        ] {
            assert!(!acl.contains(forbidden));
        }
        assert!(policy(Role::CaRotation, &json!({"names":inventory})).is_err());
        inventory.push("installer-ingress-aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa".into());
        assert!(names(&json!(inventory)).is_err());
    }

    #[test]
    fn public_renewal_keeps_tls_custody_readback_without_certificate_issuance() {
        let name = "installer-ingress-12345678123442348234123456789abc";
        let mut inventory = workload_names();
        inventory.push(name.into());
        let context = json!({"names":inventory, "ingress_certificate_source":"acme"});
        let acl = policy(Role::Renewal, &context).unwrap();
        assert!(acl.contains(&line(&format!("transit/keys/{name}"), &["read"])));
        assert!(acl.contains(&line(&format!("sys/policies/acl/{name}"), &["read"])));
        assert!(acl.contains(&line("auth/token/create/selfhost-renew-leaf", &["update"])));
        for path in [
            format!("transit/keys/{name}/csr"),
            format!("transit/sign/{name}"),
            format!("{name}/cert/ca"),
            format!("{name}/roles/localhost"),
            format!("{name}/sign/localhost"),
            format!("transit/keys/{name}/rotate"),
            format!("transit/export/signing-key/{name}"),
        ] {
            assert!(!acl.contains(&format!("path {path:?}")), "{path}");
        }
        for marker in [
            json!("staging"),
            json!("managed-ca"),
            json!(true),
            json!(null),
        ] {
            let mut bad = context.clone();
            bad["ingress_certificate_source"] = marker;
            assert!(policy(Role::Renewal, &bad).is_err());
        }
        assert!(policy(Role::CaRotation, &context).is_err());
        assert!(policy(
            Role::Renewal,
            &json!({"names":workload_names(),
            "ingress_certificate_source":"acme"})
        )
        .is_err());
    }

    #[test]
    fn renewal_binds_every_ingress_signing_parameter_to_retained_role_identity() {
        let name = "installer-ingress-12345678123442348234123456789abc";
        for (common, dns, ip, allow_ip) in [
            ("marty.example.com", "marty.example.com", "", false),
            ("203.0.113.10", "", "203.0.113.10", true),
            ("2001:db8::10", "", "2001:db8::10", true),
            ("localhost", "localhost", "127.0.0.1", true),
        ] {
            let acl = ingress_sign_acl(name, &ingress_role(common, allow_ip)).unwrap();
            assert!(acl.contains("required_parameters = [\"csr\", \"common_name\", \"alt_names\", \"ip_sans\", \"exclude_cn_from_sans\", \"ttl\"]"));
            assert!(acl.contains(&format!("\"common_name\" = [{:?}]", common)));
            assert!(acl.contains(&format!("\"alt_names\" = [{:?}]", dns)));
            assert!(acl.contains(&format!("\"ip_sans\" = [{:?}]", ip)));
            assert!(acl.contains("\"exclude_cn_from_sans\" = [true]"));
            assert!(acl.contains("\"ttl\" = [\"8h\"]"));
            assert!(!acl.contains('*'));
        }
        let inventory = workload_names();
        let legacy = policy(Role::Renewal, &json!({"names":inventory})).unwrap();
        assert_eq!(
            legacy,
            policy(
                Role::Renewal,
                &json!({"names":inventory,"ingress_role":{"invalid":true}})
            )
            .unwrap()
        );
    }

    #[test]
    fn renewal_rejects_ambiguous_or_broadened_ingress_role_before_policy_creation() {
        let name = "installer-ingress-12345678123442348234123456789abc";
        for common in [
            "MARTY.example.com",
            "*.example.com",
            "example.com:443",
            "example.com/path",
            "203.000.113.10",
            "2001:db8:0:0:0:0:0:10",
        ] {
            assert!(ingress_sign_acl(name, &ingress_role(common, false)).is_err());
        }
        for (field, value) in [
            ("allowed_domains", json!([])),
            (
                "allowed_domains",
                json!(["marty.example.com", "foreign.example.com"]),
            ),
            ("allow_ip_sans", json!(true)),
            ("allow_any_name", json!(true)),
            ("allow_subdomains", json!(true)),
            ("allow_glob_domains", json!(true)),
            ("allow_wildcard_certificates", json!(true)),
            ("use_csr_sans", json!(true)),
            ("use_csr_common_name", json!(true)),
            ("max_ttl", json!(86400)),
            ("cn_validations", json!(["disabled"])),
        ] {
            let mut role = ingress_role("marty.example.com", false);
            role[field] = value;
            assert!(ingress_sign_acl(name, &role).is_err(), "{field}");
        }
        assert!(ingress_sign_acl(name, &ingress_role("203.0.113.10", false)).is_err());
    }

    #[test]
    fn renewal_preserves_one_explicit_ip_alias_in_the_retained_role() {
        let name = "installer-ingress-12345678123442348234123456789abc";
        for ip in ["203.0.113.10", "2001:db8::10"] {
            let mut role = ingress_role("marty.example.com", true);
            role["allowed_domains"] = json!(["marty.example.com", ip]);
            let acl = ingress_sign_acl(name, &role).unwrap();
            assert!(acl.contains("\"common_name\" = [\"marty.example.com\"]"));
            assert!(acl.contains("\"alt_names\" = [\"marty.example.com\"]"));
            assert!(acl.contains(&format!("\"ip_sans\" = [{ip:?}]")));
            assert!(!acl.contains('*'));
            role["allow_ip_sans"] = json!(false);
            assert!(ingress_sign_acl(name, &role).is_err());
        }
        for (dns, aliases) in [
            (
                "marty.example.com",
                json!(["marty.example.com", "127.0.0.1"]),
            ),
            (
                "marty.example.com",
                json!(["marty.example.com", "2001:db8:0:0:0:0:0:10"]),
            ),
            (
                "marty.example.com",
                json!(["marty.example.com", "203.0.113.10", "203.0.113.11"]),
            ),
            ("marty", json!(["marty", "203.0.113.10"])),
            ("localhost", json!(["localhost", "203.0.113.10"])),
            ("203.0.113.10", json!(["203.0.113.10", "203.0.113.11"])),
        ] {
            let mut role = ingress_role(dns, true);
            role["allowed_domains"] = aliases;
            assert!(ingress_sign_acl(name, &role).is_err(), "{role}");
        }
    }

    #[test]
    fn renewal_refuses_ambiguous_or_missing_ingress_scope() {
        for additional in [
            "foreign-key",
            "installer-ingress-*",
            "installer-ingress-../other",
            "installer-ingress-1234",
            "installer-ingress-AAAAAAAAAAAA4AAA8AAAAAAAAAAAAAAA",
        ] {
            let mut inventory = workload_names();
            inventory.push(additional.into());
            assert!(names(&json!(inventory)).is_err());
        }
        let mut inventory = workload_names();
        inventory[0] = "installer-ingress-12345678123442348234123456789abc".into();
        assert!(names(&json!(inventory)).is_err());
    }
}
