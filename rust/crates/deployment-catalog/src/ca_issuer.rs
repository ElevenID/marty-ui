//! Resumable, bounded internal CA issuance under the scoped rotation AppRole.
use crate::{
    activation_preflight::text,
    approle::{self, Role},
    operator::{Result, REFUSAL},
    operator_certificates::{check_expiry, check_replacement_ca},
    operator_files::{finish_generation, generation_output, private_directory},
    operator_http::{optional_ca, request},
};
use marty_openbao_http::OpenBaoHttp;
use reqwest::Method;
use serde_json::{json, Value};
use std::{fs, path::Path};
pub const RECOVERY: &str = "CA issuer staging requires operator recovery";
pub async fn stage(bao: &OpenBaoHttp, context: &Value) -> Result<Value> {
    let kind = text(context, "kind")?;
    let version = context["version"].as_u64().ok_or(REFUSAL)?;
    if !["workload", "keycloak"].contains(&kind) || !(2..=8).contains(&version) {
        return Err(REFUSAL);
    }
    let output = private_directory(Path::new(text(context, "output")?))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if fs::metadata(&output).map_err(|_| REFUSAL)?.uid() != unsafe { libc::getuid() } {
            return Err(REFUSAL);
        }
    }
    if fs::read_dir(&output).map_err(|_| REFUSAL)?.next().is_some() {
        return Err(REFUSAL);
    }
    let login = approle::login(
        bao,
        Role::CaRotation,
        Path::new(text(context, "identity")?),
        &json!({}),
    )
    .await?;
    let token = text(&login, "token")?;
    let mount = format!("{kind}-pki-v{version}");
    let result:Result<Value>=async {
        let mounts=request(bao,Method::GET,"sys/mounts",None,Some(token)).await?;
        if !mounts["data"].as_object().ok_or(REFUSAL)?.contains_key(&format!("{mount}/")) {
            request(bao,Method::POST,&format!("sys/mounts/{mount}"),Some(&json!({"type":"pki","config":{"max_lease_ttl":"8760h"}})),Some(token)).await?;
        }
        let configured=request(bao,Method::GET,&format!("sys/mounts/{mount}"),None,Some(token)).await?;
        if configured["data"]["type"]!="pki" || configured["data"]["config"]["max_lease_ttl"].as_u64()!=Some(365*24*3600) { return Err(REFUSAL); }
        let existing=optional_ca(bao,&format!("{mount}/cert/ca"),token).await?.unwrap_or(json!({"data":{}}));
        if existing["data"].get("private_key").is_some() { return Err(REFUSAL); }
        let value=match existing["data"].get("certificate") {
            Some(Value::String(certificate)) if !certificate.is_empty() => existing,
            None | Some(Value::Null) | Some(Value::String(_)) => request(bao,Method::POST,&format!("{mount}/root/generate/internal"),Some(&json!({"common_name":format!("Marty self-host {kind} CA v{version}"),"ttl":"8760h","key_type":"ec","key_bits":256})),Some(token)).await?,
            _ => return Err(REFUSAL),
        };
        let data=&value["data"]; let certificate=text(data,"certificate")?;
        if data.get("private_key").is_some() || certificate.len()>64*1024 || certificate.contains("PRIVATE KEY") { return Err(REFUSAL); }
        check_replacement_ca(certificate.as_bytes(),kind,version)?;
        let live=request(bao,Method::GET,&format!("{mount}/cert/ca"),None,Some(token)).await?;
        if live["data"]["certificate"]!=certificate || !check_expiry(certificate.as_bytes(),300*24*3600)? { return Err(REFUSAL); }
        let destination=output.join(format!("{kind}-ca-v{version}.crt"));
        let mut file=generation_output(&destination)?;
        if finish_generation(&mut file,certificate.as_bytes(),0o600).is_err() {
            drop(file); let _=fs::remove_file(&destination); return Err(RECOVERY);
        }
        Ok(json!(mount))
    }.await;
    // A scoped session or persisted issuer may survive any post-login failure.
    result.map_err(|_| RECOVERY)
}
