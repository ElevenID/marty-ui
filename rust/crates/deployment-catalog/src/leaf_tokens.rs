//! Short-lived qualification leaves: shared checks with explicit caller contracts.
use crate::{
    approle::{AUDIT_POLICY, SIGNER, SIGNER_POLICY},
    operator::{Result, REFUSAL},
    operator_http::{denial, request},
};
use marty_openbao_http::OpenBaoHttp;
use reqwest::Method;
use serde_json::{json, Value};

pub fn metadata(
    data: &Value,
    policy: &str,
    duplicate_policy: bool,
    path: Option<&str>,
) -> Result<()> {
    let policies = data["policies"].as_array().ok_or(REFUSAL)?;
    if policies.is_empty()
        || (!duplicate_policy && policies.len() != 1)
        || policies.iter().any(|p| p.as_str() != Some(policy))
        || data["orphan"] != true
        || !data["ttl"]
            .as_u64()
            .is_some_and(|ttl| (1..=3600).contains(&ttl))
        || path.is_some_and(|path| data["path"].as_str() != Some(path))
    {
        return Err(REFUSAL);
    }
    Ok(())
}

pub(crate) async fn audit_access(bao: &OpenBaoHttp, leaf: &str, context: &Value) -> Result<()> {
    let paths = context["paths"]
        .as_array()
        .ok_or(REFUSAL)?
        .iter()
        .map(|p| p.as_str().ok_or(REFUSAL))
        .collect::<Result<Vec<_>>>()?;
    let forbidden = [
        format!("transit/sign/{SIGNER}"),
        format!("transit/export/signing-key/{SIGNER}"),
        "auth/token/create".into(),
        format!("sys/policies/acl/{AUDIT_POLICY}"),
    ];
    let all = paths
        .iter()
        .copied()
        .chain(forbidden.iter().map(String::as_str))
        .collect::<Vec<_>>();
    let access = request(
        bao,
        Method::POST,
        "sys/capabilities-self",
        Some(&json!({"paths":all})),
        Some(leaf),
    )
    .await?;
    if paths.iter().any(|p| access[*p] != json!(["read"]))
        || forbidden
            .iter()
            .any(|p| access[p] != json!(["deny"]) && access[p] != json!([]))
    {
        return Err(REFUSAL);
    }
    Ok(())
}

pub(crate) async fn evidence_access(bao: &OpenBaoHttp, leaf: &str, signing: bool) -> Result<()> {
    if signing {
        use base64::Engine;
        let signed=request(bao,Method::POST,&format!("transit/sign/{SIGNER}"),Some(&json!({"input":base64::engine::general_purpose::STANDARD.encode(b"evidence-custody-canary"),"key_version":1})),Some(leaf)).await?;
        if !signed["data"]["signature"]
            .as_str()
            .is_some_and(|v| v.starts_with("vault:v1:"))
        {
            return Err(REFUSAL);
        }
    } else {
        request(
            bao,
            Method::GET,
            &format!("transit/keys/{SIGNER}"),
            None,
            Some(leaf),
        )
        .await?;
    }
    denial(
        bao,
        leaf,
        Method::GET,
        &format!("transit/export/signing-key/{SIGNER}"),
        None,
    )
    .await
}

pub async fn check(bao: &OpenBaoHttp, context: &Value) -> Result<()> {
    let leaf = context["token"].as_str().ok_or(REFUSAL)?;
    let kind = context["kind"].as_str().ok_or(REFUSAL)?;
    let policy = match kind {
        "audit" => AUDIT_POLICY,
        "custody" => SIGNER_POLICY,
        _ => return Err(REFUSAL),
    };
    let lookup = request(bao, Method::GET, "auth/token/lookup-self", None, Some(leaf)).await?;
    metadata(&lookup["data"], policy, false, None)?;
    if kind == "audit" {
        audit_access(bao, leaf, context).await
    } else {
        evidence_access(bao, leaf, false).await
    }
}
