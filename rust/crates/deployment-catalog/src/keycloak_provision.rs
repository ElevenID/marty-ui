//! Keycloak public CSR/PKI preparation. Private keys remain in remote KMS.
use crate::{
    keycloak,
    operator::{public_spki, Result, REFUSAL},
    operator_certificates::check_expiry,
    operator_http::request,
};
use marty_openbao_http::OpenBaoHttp;
use reqwest::Method;
use serde_json::{json, Value};

fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value[name].as_str().ok_or(REFUSAL)
}
fn certificate(value: &Value) -> Result<String> {
    let data = &value["data"];
    if data.get("private_key").is_some() {
        return Err(REFUSAL);
    }
    let cert = text(data, "certificate")?;
    if !check_expiry(cert.as_bytes(), 7 * 3600)? {
        return Err(REFUSAL);
    }
    Ok(cert.into())
}
pub async fn provision(bao: &OpenBaoHttp, context: &Value) -> Result<Value> {
    let token = text(context, "token")?;
    let renew = context["renew"].as_bool().ok_or(REFUSAL)?;
    let mount = text(context, "pki_mount")?;
    if token.len() < 20
        || (mount != "keycloak-pki"
            && (!renew
                || ![
                    "keycloak-pki-v2",
                    "keycloak-pki-v3",
                    "keycloak-pki-v4",
                    "keycloak-pki-v5",
                    "keycloak-pki-v6",
                    "keycloak-pki-v7",
                    "keycloak-pki-v8",
                ]
                .contains(&mount)))
    {
        return Err(REFUSAL);
    }
    // Validate the nonce before any mutation, using the same closed policy scope.
    let nonce = text(context, "nonce")?;
    if nonce.len() != 12
        || !nonce
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(REFUSAL);
    }
    if renew {
        crate::activation_preflight::authority(bao, token, mount != "keycloak-pki").await?;
    }
    let mounts = request(bao, Method::GET, "sys/mounts", None, Some(token)).await?;
    let mounts = mounts["data"].as_object().ok_or(REFUSAL)?;
    if mounts.get("transit/").and_then(|v| v["type"].as_str()) != Some("transit")
        || mounts.get("didcomm/").and_then(|v| v["type"].as_str())
            != Some("openbao-didcomm-authcrypt")
        || (!renew && mounts.contains_key("keycloak-pki/"))
        || (renew
            && ["keycloak-pki/".to_owned(), format!("{mount}/")]
                .iter()
                .any(|name| mounts.get(name).and_then(|v| v["type"].as_str()) != Some("pki")))
    {
        return Err(REFUSAL);
    }
    let role = json!({"allow_any_name":true,"key_type":"rsa","key_bits":2048,"max_ttl":"8h","use_csr_common_name":false,"use_csr_sans":false});
    if renew {
        if mount != "keycloak-pki" {
            request(
                bao,
                Method::POST,
                &format!("{mount}/roles/rs256"),
                Some(&role),
                Some(token),
            )
            .await?;
        }
        let current = request(
            bao,
            Method::GET,
            &format!("{mount}/roles/rs256"),
            None,
            Some(token),
        )
        .await?;
        let current = &current["data"];
        if current["key_type"] != "rsa"
            || current["key_bits"].as_u64() != Some(2048)
            || current["allow_any_name"] != true
            || current["max_ttl"].as_u64() != Some(28800)
        {
            return Err(REFUSAL);
        }
        certificate(
            &request(
                bao,
                Method::GET,
                &format!("{mount}/cert/ca"),
                None,
                Some(token),
            )
            .await?,
        )?;
    } else {
        request(
            bao,
            Method::POST,
            "sys/mounts/keycloak-pki",
            Some(&json!({"type":"pki","config":{"max_lease_ttl":"8760h"}})),
            Some(token),
        )
        .await?;
        let ca = request(bao, Method::POST, "keycloak-pki/root/generate/internal", Some(&json!({"common_name":"Marty disposable Keycloak CA","ttl":"8760h","key_type":"ec","key_bits":256})), Some(token)).await?;
        // Initial production did not impose the renewal CA lifetime check.
        if ca["data"].get("private_key").is_some() || ca["data"]["certificate"].as_str().is_none() {
            return Err(REFUSAL);
        }
        request(
            bao,
            Method::POST,
            "keycloak-pki/roles/rs256",
            Some(&role),
            Some(token),
        )
        .await?;
    }
    let mut outputs = serde_json::Map::new();
    for realm in crate::keycloak::REALMS {
        let rsa = format!("keycloak-{realm}-rs256");
        for (name, kind) in [
            (rsa.clone(), "rsa-2048"),
            (format!("keycloak-{realm}-hs512"), "hmac"),
        ] {
            if !renew {
                let mut body =
                    json!({"type":kind,"exportable":false,"allow_plaintext_backup":false});
                if kind == "hmac" {
                    body["key_size"] = json!(64);
                }
                request(
                    bao,
                    Method::POST,
                    &format!("transit/keys/{name}"),
                    Some(&body),
                    Some(token),
                )
                .await?;
            }
            let metadata = request(
                bao,
                Method::GET,
                &format!("transit/keys/{name}"),
                None,
                Some(token),
            )
            .await?;
            let data = &metadata["data"];
            crate::operator::version_one_custody(data, kind)?;
        }
        let csr = request(
            bao,
            Method::POST,
            &format!("transit/keys/{rsa}/csr"),
            Some(&json!({"version":1})),
            Some(token),
        )
        .await?;
        let csr = text(&csr["data"], "csr")?;
        let signed = request(
            bao,
            Method::POST,
            &format!("{mount}/sign/rs256"),
            Some(&json!({"csr":csr,"common_name":format!("{realm}.keycloak.internal"),"ttl":"8h"})),
            Some(token),
        )
        .await?;
        let cert = certificate(&signed)?;
        let metadata = request(
            bao,
            Method::GET,
            &format!("transit/keys/{rsa}"),
            None,
            Some(token),
        )
        .await?;
        let public = text(&metadata["data"]["keys"]["1"], "public_key")?;
        if public_spki(cert.as_bytes(), true)? != public_spki(public.as_bytes(), false)? {
            return Err(REFUSAL);
        }
        outputs.insert(format!("keycloak_{realm}_rs256_cert"), json!(cert));
    }
    if !renew {
        request(
            bao,
            Method::POST,
            "transit/keys/foreign-keycloak-selfhost",
            Some(&json!({"type":"rsa-2048","exportable":false,"allow_plaintext_backup":false})),
            Some(token),
        )
        .await?;
    }
    // mint distinguishes pre-mint refusal from an uncertain mint response itself.
    outputs.insert(
        "keycloak_signing_kms_token".into(),
        json!(
            keycloak::mint(
                bao,
                &json!({"scope":"signing","token":token,"renew":renew,"nonce":nonce})
            )
            .await?
        ),
    );
    // Once this first leaf exists, every later failure requires recovery.
    let result: Result<()> = async {
        for realm in crate::keycloak::REALMS {
            for purpose in crate::keycloak::PURPOSES {
                let path = format!("didcomm/keycloak/keys/{realm}/{purpose}");
                if !renew { request(bao, Method::POST, &path, Some(&json!({})), Some(token)).await?; }
                let current = request(bao, Method::GET, &path, None, Some(token)).await?;
                let version = text(&current["data"], "version")?;
                let leaf = keycloak::mint(bao, &json!({"scope":"jwe","token":token,"renew":renew,"nonce":nonce,"realm":realm,"purpose":purpose,"version":version})).await?;
                outputs.insert(format!("keycloak_{realm}_{purpose}_token"), json!(leaf));
            }
        }
        let values: std::collections::BTreeSet<_> = outputs.iter().filter(|(name,_)|name.ends_with("_token")).map(|(_,v)|v.as_str().ok_or(REFUSAL)).collect::<Result<_>>()?;
        if outputs.len() != 7 || values.len() != 5 { return Err(REFUSAL); }
        Ok(())
    }.await;
    result.map_err(|_| keycloak::RECOVERY)?;
    Ok(Value::Object(outputs))
}
