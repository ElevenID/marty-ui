//! Live KMS preflight shared by activation, renewal bootstrap and root-lineage audit.
use crate::{
    generation, keycloak,
    operator::{public_spki, Result, REFUSAL},
    operator_certificates::{check_chain, check_lifetime},
    operator_files::generation_file,
    operator_http::request,
};
use marty_openbao_http::OpenBaoHttp;
use marty_selfhost_identity::SELFHOST_ROLES;
use reqwest::Method;
use serde_json::{json, Value};
use std::{path::Path, time::Duration};

pub(crate) fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value[name].as_str().ok_or(REFUSAL)
}
fn flag(value: &Value, name: &str) -> Result<bool> {
    value[name].as_bool().ok_or(REFUSAL)
}
fn read(path: &Path) -> Result<Vec<u8>> {
    Ok(generation_file(path, false)?.0)
}
// Python's former ASCII read_text used universal newlines on every platform.
fn certificate_file(path: &Path) -> Result<Vec<u8>> {
    let bytes = read(path)?;
    if !bytes.is_ascii() {
        return Err(REFUSAL);
    }
    Ok(String::from_utf8(bytes)
        .map_err(|_| REFUSAL)?
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .into_bytes())
}
pub(crate) fn lifetime(certificate: &[u8], ttl: u64) -> Result<()> {
    if !check_lifetime(certificate, ttl).map_err(|_| "renewed certificate validity is invalid")? {
        return Err("renewed certificate is outside the required validity overlap");
    }
    Ok(())
}
pub async fn authority(bao: &OpenBaoHttp, token: &str, rotation: bool) -> Result<()> {
    let value = request(
        bao,
        Method::POST,
        "auth/token/lookup",
        Some(&json!({"token":token})),
        Some(token),
    )
    .await?;
    let data = &value["data"];
    let (policy, path, refusal) = if rotation {
        (
            "selfhost-kms-ca-rotation",
            "auth/selfhost-ca-rotation/login",
            "OpenBao CA-rotation authority is not the scoped AppRole token",
        )
    } else {
        (
            "selfhost-kms-renewal",
            "auth/selfhost-renew/login",
            "OpenBao renewal authority is not the scoped AppRole token",
        )
    };
    if data["policies"] != json!([policy])
        || data["path"] != path
        || !data["ttl"]
            .as_u64()
            .is_some_and(|ttl| (3600..=28800).contains(&ttl))
    {
        return Err(refusal);
    }
    Ok(())
}
fn policy_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn signature(value: &Value) -> bool {
    value["data"]["signature"]
        .as_str()
        .is_some_and(|v| v.starts_with("vault:v1:"))
}
fn token_scopes() -> Vec<(String, Option<&'static str>)> {
    let mut scopes = SELFHOST_ROLES
        .iter()
        .map(|r| (r.token_file.to_owned(), Some(r.key_name)))
        .collect::<Vec<_>>();
    scopes.push(("keycloak_signing_kms_token".into(), None));
    for realm in keycloak::REALMS {
        for purpose in keycloak::PURPOSES {
            scopes.push((format!("keycloak_{realm}_{purpose}_token"), None));
        }
    }
    scopes.sort_by(|a, b| a.0.cmp(&b.0));
    scopes
}
pub async fn tokens(bao: &OpenBaoHttp, context: &Value) -> Result<Vec<String>> {
    let operator = text(context, "token")?;
    let ttl = context["minimum_ttl"].as_u64().ok_or(REFUSAL)?;
    let old = Path::new(text(context, "old")?);
    let new = Path::new(text(context, "new")?);
    let orphan_new = flag(context, "require_orphan_new")?;
    let orphan_old = flag(context, "require_orphan_old")?;
    let scopes = token_scopes();
    let mut names = Vec::new();
    for (root, orphan) in [
        (old, orphan_old || (old == new && orphan_new)),
        (new, orphan_new),
    ] {
        names.clear();
        for (name, key) in &scopes {
            let raw = read(&root.join(name))?;
            if !raw.is_ascii() {
                return Err(REFUSAL);
            }
            let token = std::str::from_utf8(&raw).map_err(|_| REFUSAL)?.trim();
            if !token.is_ascii() {
                return Err(REFUSAL);
            }
            let response = request(
                bao,
                Method::POST,
                "auth/token/lookup",
                Some(&json!({"token":token})),
                Some(operator),
            )
            .await?;
            let data = &response["data"];
            let policies = data["policies"]
                .as_array()
                .ok_or("renewed OpenBao token has invalid scope or lifetime")?;
            if policies.len() != 1
                || policies[0] == "default"
                || !data["ttl"].as_u64().is_some_and(|v| v >= ttl && v <= 28800)
            {
                return Err("renewed OpenBao token has invalid scope or lifetime");
            }
            if orphan
                && (data["orphan"] != true
                    || data["path"] != "auth/token/create/selfhost-renew-leaf")
            {
                return Err("renewed OpenBao token still depends on bootstrap root");
            }
            let name_ref = policies[0]
                .as_str()
                .filter(|v| policy_reference(v))
                .ok_or("renewed OpenBao policy reference is invalid")?;
            names.push(name_ref.to_owned());
            let response = request(
                bao,
                Method::GET,
                &format!("sys/policies/acl/{name_ref}"),
                None,
                Some(operator),
            )
            .await?;
            let policy = &response["data"]["policy"];
            if let Some(key) = key {
                let expected=format!("path \"transit/keys/{key}\" {{ capabilities = [\"read\"] }}\npath \"transit/sign/{key}\" {{ capabilities = [\"update\"] }}");
                let proof = request(
                    bao,
                    Method::POST,
                    &format!("transit/sign/{key}"),
                    Some(&json!({"input":"YWN0aXZhdGlvbi1zY29wZQ==","key_version":1})),
                    Some(token),
                )
                .await?;
                if policy.as_str() != Some(&expected) || !signature(&proof) {
                    return Err("renewed TLS token cannot use its exact versioned signer");
                }
            } else if name == "keycloak_signing_kms_token" {
                if policy.as_str() != Some(&keycloak::policy(&json!({"scope":"signing"}))?) {
                    return Err("Keycloak signing policy changed before activation");
                }
                for realm in keycloak::REALMS {
                    let proof=request(bao,Method::POST,&format!("transit/sign/keycloak-{realm}-rs256"),Some(&json!({"input":"YWN0aXZhdGlvbi1zY29wZQ==","key_version":1,"hash_algorithm":"sha2-256","signature_algorithm":"pkcs1v15"})),Some(token)).await?;
                    if !signature(&proof) {
                        return Err("Keycloak signing token cannot use version-one signer");
                    }
                }
            } else {
                // Names originate solely from the closed inventory above.
                let parts = name.split('_').collect::<Vec<_>>();
                let realm = parts[1];
                let purpose = parts[2];
                let path = format!("didcomm/keycloak/keys/{realm}/{purpose}");
                let current = request(bao, Method::GET, &path, None, Some(operator)).await?;
                let version = text(&current["data"], "version")
                    .map_err(|_| "Keycloak JWE version changed before activation")?;
                let expected = keycloak::policy(
                    &json!({"scope":"jwe","realm":realm,"purpose":purpose,"version":version}),
                )
                .map_err(|_| "Keycloak JWE version changed before activation")?;
                if policy.as_str() != Some(&expected) {
                    return Err("Keycloak JWE token cannot read its exact versioned key");
                }
                let proof = request(bao, Method::GET, &path, None, Some(token)).await?;
                if proof["data"]["version"] != version {
                    return Err("Keycloak JWE token cannot read its exact versioned key");
                }
            }
        }
    }
    Ok(names)
}

/// Bootstrap policy discovery reuses the live checks, never a second lookup snapshot.
pub async fn renewal_inventory(bao: &OpenBaoHttp, context: &Value) -> Result<Vec<String>> {
    let current = text(context, "current")?;
    // Preserve rejection of every non-regular generation entry, including unrelated files.
    let entries = generation::entries(Path::new(current))?;
    if token_scopes()
        .iter()
        .any(|(name, _)| !entries.contains_key(name))
    {
        return Err("current generation lacks a renewed token input");
    }
    let checks = json!({
        "token": text(context, "token")?, "old": current, "new": current,
        "minimum_ttl": 3600, "require_orphan_new": false, "require_orphan_old": false,
        "replacement": null, "retiring": false,
    });
    let names = tokens(bao, &checks).await?;
    certificates(bao, &checks).await?;
    if names.len() != 21
        || names
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != names.len()
    {
        return Err("existing scoped policy inventory is incomplete");
    }
    Ok(names)
}
async fn issuer(bao: &OpenBaoHttp, token: &str, mount: &str) -> Result<String> {
    let value = request(
        bao,
        Method::GET,
        &format!("{mount}/cert/ca"),
        None,
        Some(token),
    )
    .await?;
    Ok(text(&value["data"], "certificate")
        .map_err(|_| "renewed OpenBao issuer is absent")?
        .into())
}
fn replacement_mount(mount: &str, kind: &str) -> bool {
    (2..=8).any(|v| mount == format!("{kind}-pki-v{v}"))
}
pub async fn certificates(bao: &OpenBaoHttp, context: &Value) -> Result<()> {
    let token = text(context, "token")?;
    let ttl = context["minimum_ttl"].as_u64().ok_or(REFUSAL)?;
    let old = Path::new(text(context, "old")?);
    let new = Path::new(text(context, "new")?);
    let retiring = flag(context, "retiring")?;
    let replacement = context.get("replacement").filter(|v| !v.is_null());
    if retiring && replacement.is_none() {
        return Err("CA trust retirement requires live replacement issuers");
    }
    let issuers = [
        issuer(bao, token, "workload-pki").await?,
        issuer(bao, token, "keycloak-pki").await?,
    ];
    let next = if let Some(replacement) = replacement {
        let workload = text(replacement, "workload_mount")?;
        let keycloak = text(replacement, "keycloak_mount")?;
        if !replacement_mount(workload, "workload") || !replacement_mount(keycloak, "keycloak") {
            return Err(REFUSAL);
        }
        let client = OpenBaoHttp::connect(
            text(replacement, "endpoint")?,
            Some(Path::new(text(replacement, "ca")?)),
            Duration::from_secs(10),
        )
        .map_err(|_| REFUSAL)?;
        let token = text(replacement, "token")?;
        let next = [
            issuer(&client, token, workload).await?,
            issuer(&client, token, keycloak).await?,
        ];
        if next[1] == issuers[1] {
            return Err("replacement Keycloak issuer did not change");
        }
        next
    } else {
        issuers.clone()
    };
    for cert in if retiring {
        next.iter().collect::<Vec<_>>()
    } else {
        issuers.iter().chain(&next).collect()
    } {
        lifetime(cert.as_bytes(), ttl)?;
    }
    let bundle = if replacement.is_some() {
        generation::overlap(issuers[0].as_bytes(), next[0].as_bytes())?
    } else {
        issuers[0].as_bytes().to_vec()
    };
    let generations = if retiring {
        vec![
            (old, &next, bundle),
            (
                new,
                &next,
                format!("{}\n", next[0].trim_end_matches('\n')).into_bytes(),
            ),
        ]
    } else if replacement.is_some() {
        vec![
            (old, &issuers, issuers[0].as_bytes().to_vec()),
            (new, &next, bundle),
        ]
    } else {
        vec![
            (old, &issuers, issuers[0].as_bytes().to_vec()),
            (new, &issuers, issuers[0].as_bytes().to_vec()),
        ]
    };
    for (root, issuers, expected_ca) in generations {
        if certificate_file(&root.join("workload_identity_ca_cert"))? != expected_ca {
            return Err("workload issuer differs from the mounted trust anchor");
        }
        let roles = SELFHOST_ROLES
            .iter()
            .map(|r| {
                (
                    r.key_name.to_owned(),
                    r.cert_file.to_owned(),
                    "ecdsa-p256",
                    0,
                )
            })
            .chain(keycloak::REALMS.iter().map(|realm| {
                (
                    format!("keycloak-{realm}-rs256"),
                    format!("keycloak_{realm}_rs256_cert"),
                    "rsa-2048",
                    1,
                )
            }));
        for (key, file, kind, issuer) in roles {
            let response = request(
                bao,
                Method::GET,
                &format!("transit/keys/{key}"),
                None,
                Some(token),
            )
            .await?;
            let metadata = &response["data"];
            crate::operator::version_one_custody(metadata, kind)
                .map_err(|_| "remote signer lost version-one non-exportable custody")?;
            let public = text(&metadata["keys"]["1"], "public_key")?;
            let certificate = certificate_file(&root.join(file))?;
            lifetime(&certificate, ttl)?;
            check_chain(&certificate, issuers[issuer].as_bytes())
                .map_err(|_| "renewed certificate is not signed by its OpenBao issuer")?;
            if public_spki(&certificate, true)? != public_spki(public.as_bytes(), false)? {
                return Err("certificate differs from its remote signer");
            }
        }
    }
    Ok(())
}
