//! Closed Keycloak token scopes. PKI/Transit production and file staging retain
//! their own owners; callers cannot submit an arbitrary ACL or mint endpoint.
use crate::{
    operator::{Result, REFUSAL},
    operator_http::{denial, request},
};
use marty_openbao_http::OpenBaoHttp;
use reqwest::Method;
use serde_json::{json, Value};

pub const RECOVERY: &str = "Keycloak provisioning requires operator recovery";
pub(crate) const REALMS: [&str; 2] = ["master", "11id"];
pub(crate) const PURPOSES: [&str; 2] = ["cookie", "ciba"];
const MIN_TTL: u64 = 7 * 3600;
const MAX_TTL: u64 = 8 * 3600;
fn reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value[name].as_str().ok_or(REFUSAL)
}
struct Scope {
    policy: String,
    prefix: String,
    key_path: Option<String>,
    version: Option<String>,
}
fn scope(context: &Value) -> Result<Scope> {
    match field(context, "scope")? {
        "signing" => Ok(Scope {
            policy: REALMS.iter().map(|realm| format!(
                "path \"transit/keys/keycloak-{realm}-rs256\" {{ capabilities = [\"read\"] }}\n\
                 path \"transit/sign/keycloak-{realm}-rs256\" {{ capabilities = [\"update\"] }}\n\
                 path \"transit/keys/keycloak-{realm}-hs512\" {{ capabilities = [\"read\"] }}\n\
                 path \"transit/hmac/keycloak-{realm}-hs512/sha2-512\" {{ capabilities = [\"update\"] }}\n\
                 path \"transit/verify/keycloak-{realm}-hs512/sha2-512\" {{ capabilities = [\"update\"] }}\n"
            )).collect(),
            prefix: "selfhost-keycloak-sign-".into(), key_path: None, version: None,
        }),
        "jwe" => {
            let realm = field(context, "realm")?;
            let purpose = field(context, "purpose")?;
            let version = field(context, "version")?;
            if !REALMS.contains(&realm) || !PURPOSES.contains(&purpose) || !reference(version) {
                return Err(REFUSAL);
            }
            let path = format!("didcomm/keycloak/keys/{realm}/{purpose}");
            Ok(Scope {
                policy: format!("path \"{path}\" {{ capabilities = [\"read\"] }}\n\
                    path \"didcomm/keycloak/jwe/encode/{realm}/{purpose}/{version}\" {{ capabilities = [\"update\"] }}\n\
                    path \"didcomm/keycloak/jwe/decode/{realm}/{purpose}/{version}\" {{ capabilities = [\"update\"] }}\n"),
                prefix: format!("selfhost-keycloak-{realm}-{purpose}-"), key_path: Some(path), version: Some(version.into()),
            })
        }
        _ => Err(REFUSAL),
    }
}
pub fn policy(context: &Value) -> Result<String> {
    Ok(scope(context)?.policy)
}

pub async fn mint(bao: &OpenBaoHttp, context: &Value) -> Result<String> {
    let scope = scope(context)?;
    let operator = field(context, "token")?;
    if operator.len() < 20 {
        return Err(REFUSAL);
    }
    let renew = context["renew"].as_bool().ok_or(REFUSAL)?;
    let name = if renew {
        let inventory = request(
            bao,
            Method::from_bytes(b"LIST").map_err(|_| REFUSAL)?,
            "sys/policies/acl",
            None,
            Some(operator),
        )
        .await?;
        let names = inventory["data"]["keys"].as_array().ok_or(REFUSAL)?;
        let mut matching = Vec::new();
        for name in names {
            let name = name.as_str().ok_or(REFUSAL)?;
            if name.starts_with(&scope.prefix) && reference(name) {
                let policy = request(
                    bao,
                    Method::GET,
                    &format!("sys/policies/acl/{name}"),
                    None,
                    Some(operator),
                )
                .await?;
                if policy["data"]["policy"].as_str() == Some(&scope.policy) {
                    matching.push(name.to_owned());
                }
            }
        }
        if matching.len() != 1 {
            return Err(REFUSAL);
        }
        matching.remove(0)
    } else {
        let nonce = field(context, "nonce")?;
        if nonce.len() != 12
            || !nonce
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(REFUSAL);
        }
        let name = format!("{}{nonce}", scope.prefix);
        request(
            bao,
            Method::PUT,
            &format!("sys/policies/acl/{name}"),
            Some(&json!({"policy":scope.policy})),
            Some(operator),
        )
        .await?;
        name
    };
    // From the mint boundary onward a dropped/invalid response may leave live
    // authority. Existing renewal policies cannot revoke these leaves; report
    // recovery rather than granting new authority or claiming rollback.
    let endpoint = if renew {
        "auth/token/create/selfhost-renew-leaf"
    } else {
        "auth/token/create"
    };
    let result = async {
        let auth = request(bao, Method::POST, endpoint,
            Some(&json!({"policies":[name],"no_default_policy":true,"ttl":"8h"})), Some(operator)).await?;
        let token = auth["auth"]["client_token"].as_str().ok_or(REFUSAL)?;
        if token.len() < 20 || token == operator || auth["auth"]["lease_duration"].as_u64().ok_or(REFUSAL)? < MIN_TTL {
            return Err(REFUSAL);
        }
        if renew {
            let lookup = request(bao, Method::POST, "auth/token/lookup", Some(&json!({"token":token})), Some(operator)).await?;
            let data = &lookup["data"];
            if data["policies"] != json!([name]) || !(MIN_TTL..=MAX_TTL).contains(&data["ttl"].as_u64().ok_or(REFUSAL)?)
                || data["orphan"] != true || data["path"] != endpoint { return Err(REFUSAL); }
        }
        if let Some(path) = &scope.key_path {
            let read = request(bao, Method::GET, path, None, Some(token)).await?;
            if read["data"]["version"].as_str() != scope.version.as_deref() { return Err(REFUSAL); }
        } else {
            use base64::{engine::general_purpose::STANDARD, Engine};
            for realm in REALMS {
                let signed = request(bao, Method::POST, &format!("transit/sign/keycloak-{realm}-rs256"),
                    Some(&json!({"input":STANDARD.encode(b"selfhost-keycloak-probe"),"hash_algorithm":"sha2-256","signature_algorithm":"pkcs1v15"})), Some(token)).await?;
                if signed["data"]["signature"].as_str().is_none_or(str::is_empty) { return Err(REFUSAL); }
            }
        }
        denial(bao, token, Method::GET, "transit/keys/foreign-keycloak-selfhost", None).await?;
        Ok(token.to_owned())
    }.await;
    result.map_err(|_| RECOVERY)
}
