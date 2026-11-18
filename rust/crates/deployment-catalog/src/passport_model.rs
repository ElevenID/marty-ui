//! Read-only Passport model policy shared by deployment tooling.
//! No secret values are returned or placed in diagnostics.
use serde_json::{json, Map, Value};
use std::collections::HashSet;

pub(super) type PolicyResult = Result<Value, String>;
pub(super) fn require(ok: bool, message: impl Into<String>) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn object<'a>(value: &'a Value, message: &str) -> Result<&'a Map<String, Value>, String> {
    value.as_object().ok_or_else(|| message.into())
}
pub(super) fn environment(service: &Value) -> Result<Map<String, Value>, String> {
    let empty = Map::new();
    let value = service
        .get("environment")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    require(
        service.get("environment").is_none() || service["environment"].is_object(),
        "Rendered beta service environment is invalid",
    )?;
    require(
        value.values().all(Value::is_string),
        "Rendered beta service environment is invalid",
    )?;
    Ok(value.clone())
}
fn keyless_custody(model: &Value) -> PolicyResult {
    let services = object(&model["services"], "Keyless TLS service model is missing")?;
    require(!services.is_empty(), "Keyless TLS service model is missing")?;
    let bao = &model["services"]["openbao"];
    require(
        bao["volumes"]
            .as_array()
            .is_some_and(|mounts| mounts.iter().all(Value::is_object)),
        "Keyless TLS custody requires HTTPS OpenBao and a public CA volume",
    )?;
    require(
        bao.is_object()
            && bao["environment"]["PASSPORT_BAO_TLS_MODE"] == "required"
            && bao["healthcheck"]["test"]
                == json!([
                    "CMD",
                    "bao",
                    "status",
                    "-address=https://127.0.0.1:8200",
                    "-ca-cert=/tmp/bao-tls/vault-ca.pem"
                ])
            && bao["volumes"].as_array().is_some_and(|v| {
                v.iter().any(|m| {
                    m["type"] == "volume"
                        && m["source"] == "openbao_public_ca"
                        && m["target"] == "/bao/public-ca"
                })
            })
            && bao["tmpfs"] == json!(["/tmp/bao-tls:rw,mode=1777"]),
        "Keyless TLS custody requires HTTPS OpenBao and a public CA volume",
    )?;
    // These are the exact case-sensitive Python admission patterns.
    let local_setting = regex::Regex::new(
        r"\A.*(?:TLS|MTLS)_(?:(?:CLIENT|SERVER|IDENTITY)_)?(?:PRIVATE_)?KEY(?:_FILE|_PATH)?\z",
    )
    .unwrap();
    let local_secret =
        regex::Regex::new(r"\A.*(?:_workload_(?:client|server)_key|_(?:m?tls)_(?:private_)?key)\z")
            .unwrap();
    for (name, service) in services {
        require(service.is_object(), "Keyless TLS environment is invalid")?;
        let env = match service.get("environment") {
            None => Map::new(),
            Some(v) => object(v, "Keyless TLS environment is invalid")?.clone(),
        };
        require(
            !env.keys().any(|k| local_setting.is_match(k)),
            format!("Keyless TLS custody requires retiring {name} private-key files"),
        )?;
        require(
            env.get("GRPC_INSECURE_ALLOWED") != Some(&json!("true")),
            format!("Keyless TLS custody requires authenticated {name} gRPC"),
        )?;
        require(
            env.iter().all(|(k, v)| {
                !k.ends_with("_GRPC_TARGET")
                    || !super::python_truthy(v)
                    || v.as_str().is_some_and(|s| s.starts_with("https://"))
            }),
            format!("Keyless TLS custody requires HTTPS {name} gRPC targets"),
        )?;
        let empty = vec![];
        let secrets = service.get("secrets").unwrap_or(&Value::Null).as_array();
        require(
            service.get("secrets").is_none() || secrets.is_some(),
            "Keyless TLS secret mounts are invalid",
        )?;
        require(
            secrets.unwrap_or(&empty).iter().all(|entry| {
                entry.is_string()
                    || (entry.is_object() && entry.get("source").is_some_and(Value::is_string))
            }),
            "Keyless TLS secret mounts are invalid",
        )?;
        require(
            !secrets.unwrap_or(&empty).iter().any(|s| {
                s.as_str()
                    .or_else(|| s["source"].as_str())
                    .is_some_and(|n| local_secret.is_match(n))
            }),
            format!("Keyless TLS custody requires retiring {name} private-key mounts"),
        )?;
    }
    let empty = Map::new();
    let secrets = match model.get("secrets") {
        None => &empty,
        Some(v) => object(v, "Keyless TLS secrets are invalid")?,
    };
    require(
        !secrets.keys().any(|s| local_secret.is_match(s)),
        "Keyless TLS custody requires retiring private-key secrets",
    )?;
    if let Some(gateway) = services.get("gateway").filter(|v| !v.is_null()) {
        require(
            services.get("auth").is_some_and(Value::is_object),
            "Keyless TLS custody requires the real Auth service for Gateway",
        )?;
        require(
            gateway["environment"]["AUTH_GRPC_TARGET"] == "https://auth:9001",
            "Keyless TLS custody requires Gateway to use the isolated Auth service",
        )?;
    }
    Ok(Value::Null)
}
pub(super) fn beta_origin(services: &Value) -> PolicyResult {
    const ORIGIN: &str = "https://beta.elevenidllc.com";
    const DOMAIN: &str = "beta.elevenidllc.com";
    let services = object(services, "Rendered beta service graph is invalid")?;
    for (name, service) in services {
        require(
            service.is_object(),
            format!("Rendered beta service is invalid: {name}"),
        )?;
        let env = environment(service)?;
        for key in [
            "PUBLIC_API_URL",
            "ISSUER_BASE_URL",
            "PUBLIC_BASE_URL",
            "UI_BASE_URL",
        ] {
            if let Some(value) = env.get(key) {
                require(
                    value == ORIGIN,
                    format!("Rendered beta public origin differs: {name}.{key}"),
                )?;
            }
        }
        if let Some(domain) = env.get("PUBLIC_DOMAIN") {
            require(
                domain == DOMAIN,
                format!("Rendered beta public domain differs: {name}"),
            )?;
        }
    }
    let expected = json!({
        "auth":{"UI_BASE_URL":ORIGIN,"UI_ADDITIONAL_BASE_URLS":"","OIDC_REDIRECT_URI":format!("{ORIGIN}/v1/auth/callback"),"OIDC_POST_LOGOUT_REDIRECT_URI":format!("{ORIGIN}/")},
        "gateway":{"ISSUER_BASE_URL":ORIGIN},"flow":{"PUBLIC_BASE_URL":ORIGIN},
        "keycloak":{"KC_HOSTNAME":ORIGIN,"PUBLIC_DOMAIN":DOMAIN,"UI_BASE_URL":ORIGIN},
        "nginx-proxy":{"PUBLIC_DOMAIN":DOMAIN,"GATEWAY_UPSTREAM":"gateway:8000"},
        "signing-keys":{"PUBLIC_DOMAIN":DOMAIN},"issuance":{"ISSUER_BASE_URL":ORIGIN}
    });
    for (name, expected) in expected.as_object().unwrap() {
        let service = services
            .get(name)
            .ok_or_else(|| format!("Rendered beta origin service is absent: {name}"))?;
        let env = environment(service)?;
        for (key, value) in expected.as_object().unwrap() {
            require(
                env.get(key) == Some(value),
                format!("Rendered beta public origin differs: {name}.{key}"),
            )?;
        }
    }
    let auth = environment(&services["auth"])?;
    let issuer = auth
        .get("OIDC_EXTERNAL_ISSUER_URL")
        .and_then(Value::as_str)
        .unwrap_or("");
    let suffix = issuer.strip_prefix(&format!("{ORIGIN}/realms/"));
    require(
        suffix.is_some_and(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        }),
        "Rendered beta OIDC issuer origin differs",
    )?;
    let env = environment(&services["gateway"])?;
    let cors = env
        .get("CORS_ORIGINS")
        .and_then(Value::as_str)
        .unwrap_or("");
    let origins = cors.split(',').collect::<Vec<_>>();
    let allowed = [
        ORIGIN,
        "http://localhost:9080",
        "http://localhost:3000",
        "http://localhost:5173",
    ];
    require(
        origins.contains(&ORIGIN)
            && origins.len() == origins.iter().collect::<HashSet<_>>().len()
            && origins.iter().all(|o| allowed.contains(o)),
        "Rendered beta Gateway CORS origins differ",
    )?;
    Ok(Value::Null)
}
pub(super) fn private_gateway(services: &Value) -> PolicyResult {
    let ports = services["gateway"]["ports"].as_array();
    require(
        ports.is_some_and(|p| {
            p.len() == 1
                && p[0].is_object()
                && p[0]["host_ip"] == "127.0.0.1"
                && (p[0]["target"] == 8000 || p[0]["target"] == "8000")
                && p[0].get("protocol").is_none_or(|v| v == "tcp")
        }),
        "Private beta Gateway must bind only the host loopback",
    )?;
    Ok(Value::Null)
}
fn runtime_flags(input: &Value) -> PolicyResult {
    let service = input["service"]
        .as_str()
        .ok_or("Passport policy service is invalid")?;
    let values = input["values"]
        .as_array()
        .ok_or_else(|| format!("Missing {service} runtime environment"))?;
    let flags = input["flags"]
        .as_array()
        .ok_or("Passport policy selectors are invalid")?;
    let mut result = Map::new();
    for flag in flags {
        let flag = flag.as_str().ok_or("Passport policy selector is invalid")?;
        let matches = values
            .iter()
            .filter_map(Value::as_str)
            .map(|s| s.split_once('=').unwrap_or((s, "")))
            .filter(|(k, _)| *k == flag)
            .collect::<Vec<_>>();
        require(
            matches.len() == 1 && ["true", "false"].contains(&matches[0].1),
            format!("Missing or ambiguous {service} passport selector"),
        )?;
        result.insert(flag.into(), json!(matches[0].1 == "true"));
    }
    Ok(Value::Object(result))
}
fn contains_credential(input: &Value) -> PolicyResult {
    let credential = input["credential"]
        .as_str()
        .ok_or("Passport credential marker is invalid")?;
    Ok(json!(contains_marker(&input["value"], credential)))
}
pub(super) fn contains_marker(value: &Value, credential: &str) -> bool {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::String(s) if s.contains(credential) => return true,
            Value::Array(a) => pending.extend(a),
            Value::Object(m) => {
                if m.keys().any(|k| k.contains(credential)) {
                    return true;
                }
                pending.extend(m.values());
            }
            _ => {}
        }
    }
    false
}
pub(super) fn service_reuses_credential(input: &Value) -> PolicyResult {
    let name = input["name"]
        .as_str()
        .ok_or("Passport service name is invalid")?;
    let dedicated = input["dedicated"]
        .as_str()
        .ok_or("Passport credential binding is invalid")?;
    let mut service = object(
        &input["service"],
        "Invalid beta passport service environment",
    )?
    .clone();
    if ["gateway", "signing-keys"].contains(&name) {
        if let Some(value) = service.get_mut("environment") {
            let mut env = match value {
                Value::Object(env) => env.clone(),
                Value::Array(entries) if entries.iter().all(Value::is_string) => entries
                    .iter()
                    .filter_map(Value::as_str)
                    .filter_map(|s| s.split_once('='))
                    .map(|(k, v)| (k.to_owned(), json!(v)))
                    .collect::<Map<_, _>>(),
                _ => return Err("Invalid beta passport service environment".into()),
            };
            env.remove(dedicated);
            *value = Value::Object(env);
        }
    }
    contains_credential(&json!({"value":service,"credential":input["credential"]}))
}

/// Return a fixed validation error as structured data, never arbitrary input values.
pub fn evaluate(operation: &str, input: &Value) -> Value {
    let result = match operation {
        op if op.starts_with("lifecycle-") => super::deployment_lifecycle::evaluate(op, input),
        op if op.starts_with("ownership-") || op.starts_with("environment-") => {
            super::deployment_environment::evaluate(op, input)
        }
        op if op.starts_with("compose-") => super::compose_model::evaluate(op, input),
        op if op.starts_with("kubernetes-") || op.starts_with("selfhost-credential") => {
            super::deployment_admission::evaluate(op, input)
        }
        "keyless-custody" => keyless_custody(&input["model"]),
        "beta-origin" => beta_origin(&input["services"]),
        "private-gateway" => private_gateway(&input["services"]),
        "runtime-flags" => runtime_flags(input),
        "contains-credential" => contains_credential(input),
        "service-reuses-credential" => service_reuses_credential(input),
        _ => Err("Passport model policy operation is invalid".into()),
    };
    match result {
        Ok(value) => json!({"ok":true,"value":value}),
        Err(error) => json!({"ok":false,"error":error}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn flags_reject_duplicates_and_non_boolean_selectors() {
        for values in [
            json!(["FLAG=true", "FLAG=false"]),
            json!(["FLAG=1"]),
            json!([]),
        ] {
            assert_eq!(
                evaluate(
                    "runtime-flags",
                    &json!({"service":"gateway","values":values,"flags":["FLAG"]})
                )["ok"],
                false
            );
        }
        assert_eq!(
            evaluate(
                "runtime-flags",
                &json!({"service":"gateway","values":["FLAG=false"],"flags":["FLAG"]})
            )["value"],
            json!({"FLAG":false})
        );
    }
    #[test]
    fn gateway_loopback_and_port_are_required() {
        for port in [json!(8000), json!("8000")] {
            assert_eq!(
                evaluate(
                    "private-gateway",
                    &json!({"services":{"gateway":{"ports":[{"host_ip":"127.0.0.1","target":port}]}}})
                )["ok"],
                true
            );
        }
        assert_eq!(
            evaluate(
                "private-gateway",
                &json!({"services":{"gateway":{"ports":[{"host_ip":"0.0.0.0","target":8000}]}}})
            )["ok"],
            false
        );
    }
    #[test]
    fn credential_scan_includes_nested_keys_without_echoing_value() {
        let result = evaluate(
            "contains-credential",
            &json!({"value":[{"prefix-secret-suffix":null}],"credential":"secret"}),
        );
        assert_eq!(result, json!({"ok":true,"value":true}));
        assert!(!result.to_string().contains("secret"));
    }
    fn custody_model() -> Value {
        json!({"services":{"openbao":{
            "environment":{"PASSPORT_BAO_TLS_MODE":"required"},
            "healthcheck":{"test":["CMD","bao","status","-address=https://127.0.0.1:8200","-ca-cert=/tmp/bao-tls/vault-ca.pem"]},
            "volumes":[{"type":"volume","source":"openbao_public_ca","target":"/bao/public-ca"}],
            "tmpfs":["/tmp/bao-tls:rw,mode=1777"]
        },"workload":{"environment":{},"secrets":[]}}})
    }
    #[test]
    fn custody_rejects_malformed_entries_and_private_key_aliases() {
        let valid = custody_model();
        assert_eq!(
            evaluate("keyless-custody", &json!({"model":valid}))["ok"],
            true
        );
        for entry in [json!(null), json!(42), json!("bad")] {
            let mut model = custody_model();
            model["services"]["openbao"]["volumes"]
                .as_array_mut()
                .unwrap()
                .push(entry.clone());
            assert_eq!(
                evaluate("keyless-custody", &json!({"model":model}))["ok"],
                false
            );
            let mut model = custody_model();
            model["services"]["workload"]["secrets"] = json!([entry]);
            // Strings remain supported secret references; scalar shapes do not.
            if !model["services"]["workload"]["secrets"][0].is_string() {
                assert_eq!(
                    evaluate("keyless-custody", &json!({"model":model}))["ok"],
                    false
                );
            }
        }
        for setting in [
            "GRPC_WORKLOAD_TLS_CLIENT_KEY",
            "GRPC_WORKLOAD_TLS_CLIENT_KEY_FILE",
            "PASSPORT_EDGE_TLS_PRIVATE_KEY_PATH",
            "AUTH_MTLS_IDENTITY_KEY_FILE",
        ] {
            let mut model = custody_model();
            model["services"]["workload"]["environment"][setting] = json!("not-a-real-secret");
            assert_eq!(
                evaluate("keyless-custody", &json!({"model":model}))["ok"],
                false
            );
        }
    }

    #[test]
    fn empty_model_and_unknown_operation_fail_closed() {
        assert_eq!(
            evaluate("keyless-custody", &json!({"model":{}}))["ok"],
            false
        );
        assert_eq!(evaluate("other", &Value::Null)["ok"], false);
    }
}
