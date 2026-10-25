//! Admission for resolved disposable Compose models. Rendering, filesystem
//! containment and live observations remain at the protected Python callers.
#[path = "compose_beta_model.rs"]
mod beta;
use super::passport_model::{require, PolicyResult};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
const SELECTED: &[&str] = &[
    "gateway",
    "flow",
    "issuance-native",
    "passport-callback-signer",
    "passport-beta-bureau",
];
const RUST: &[&str] = &[
    "organization",
    "event-stream",
    "revocation-profile",
    "revocation-profile-migrate",
    "credential-template",
    "compliance-profile",
    "trust-profile",
    "presentation-policy",
    "deployment-profile",
];
const INFRA: &[&str] = &[
    "postgres",
    "openbao",
    "redis",
    "db-migrate",
    "issuance-migrations",
    "signing-keys",
    "edge",
];
const BAO: &[&str] = &[
    "db-migrate",
    "signing-keys",
    "issuance-native",
    "passport-callback-signer",
    "gateway",
];
const SERVERS: &[(&str, &str, &str)] = &[
    ("event-stream", "es_workload_server", "event-stream-server"),
    ("organization", "org_workload_server", "organization-server"),
    (
        "revocation-profile",
        "rp_workload_server",
        "revocation-profile-server",
    ),
    (
        "credential-template",
        "ct_workload_server",
        "credential-template-server",
    ),
    (
        "issuance-native",
        "issuance_workload_server",
        "issuance-server",
    ),
];
const CLIENTS: &[(&str, &str, &str)] = &[
    (
        "compliance-profile",
        "compliance_profile_workload_client",
        "compliance-profile-client",
    ),
    (
        "deployment-profile",
        "deployment_profile_workload_client",
        "deployment-profile-client",
    ),
];
fn pattern_matches(s: &str, pattern: &str) -> bool {
    regex::Regex::new(pattern).unwrap().is_match(s)
}
fn object<'a>(v: &'a Value, error: &str) -> Result<&'a Map<String, Value>, String> {
    v.as_object().ok_or_else(|| error.to_owned())
}
fn names(v: &Value) -> BTreeSet<&str> {
    v.as_object()
        .map(|m| m.keys().map(String::as_str).collect())
        .unwrap_or_default()
}
fn set<'a>(s: impl IntoIterator<Item = &'a str>) -> BTreeSet<&'a str> {
    s.into_iter().collect()
}
fn exact(v: &Value, expected: &[&str]) -> bool {
    v.is_object() && names(v) == set(expected.iter().copied())
}
fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}
fn truthy(v: &Value) -> bool {
    super::python_truthy(v)
}
fn items<'a>(v: &'a Value, k: &str) -> Result<&'a [Value], String> {
    match v.get(k) {
        None => Ok(&[]),
        Some(x) => x
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| "Invalid Compose model collection".into()),
    }
}
fn refs(v: &Value) -> BTreeSet<&str> {
    v["secrets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v["source"].as_str())
        .collect()
}
fn holders<'a>(services: &'a Map<String, Value>, source: &str) -> BTreeSet<&'a str> {
    services
        .iter()
        .filter(|(_, s)| refs(s).contains(source))
        .map(|(n, _)| n.as_str())
        .collect()
}
fn env_matches(env: &Value, expected: &Value) -> bool {
    env.is_object()
        && expected
            .as_object()
            .unwrap()
            .iter()
            .all(|(k, v)| env.get(k) == Some(v))
}
fn absent(env: &Value, keys: &[&str]) -> bool {
    keys.iter().all(|k| env.get(k).is_none())
}
fn dep(service: &Value, name: &str, condition: &str) -> bool {
    service["depends_on"][name]["condition"] == condition
}
fn environment<'a>(services: &'a Value, name: &str) -> &'a Value {
    &services[name]["environment"]
}
fn project(input: &Value) -> Result<&str, String> {
    let p = text(&input["project"]);
    require(
        pattern_matches(
            p,
            r"\Amarty-passport-acceptance-(base|selfhost)-[a-z0-9]{6,32}\z",
        ),
        "Disposable project name is required",
    )?;
    Ok(p)
}
// Python membership against (True, "true") also rejects numeric one.
fn external(v: &Value) -> bool {
    v == true || v == "true" || v.as_f64() == Some(1.0)
}
// Preserve urlsplit().hostname rather than percent-decoding/IDNA-normalizing
// an authority into one of the protected service names.
fn endpoint_host(value: &str) -> Option<String> {
    let clean = value
        .chars()
        .filter(|c| !matches!(c, '\n' | '\r' | '\t'))
        .collect::<String>();
    let (_, rest) = clean.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if !authority.is_ascii() {
        let stripped = authority.replace(['@', ':', '#', '?'], "");
        let normalized = icu_normalizer::ComposingNormalizer::new_nfkc().normalize(&stripped);
        if normalized != stripped && normalized.contains(['/', '?', '#', '@', ':']) {
            return None;
        }
    }
    let hostport = authority.rsplit('@').next()?;
    if authority.contains(['[', ']']) {
        return None;
    }
    Some(hostport.split(':').next()?.to_lowercase())
}
fn resources(input: &Value) -> PolicyResult {
    let p = project(input)?;
    let m = &input["model"];
    require(
        m.is_object() && m["name"] == p,
        "Resolved Compose model has a different project",
    )?;
    let expected = set(SELECTED.iter().chain(RUST).chain(INFRA).copied());
    require(
        m["services"].is_object() && names(&m["services"]) == expected,
        "Resolved Compose model has an unexpected or missing service",
    )?;
    require(
        exact(&m["networks"], &["private", "callback_signing", "ingress"]),
        "Disposable Compose networks are missing",
    )?;
    for (name, n) in m["networks"].as_object().unwrap() {
        require(
            n.is_object()
                && !external(&n["external"])
                && n.get("driver").unwrap_or(&json!("bridge")) == "bridge"
                && !truthy(&n["driver_opts"])
                && n.get("internal").unwrap_or(&Value::Bool(false)) == &(json!(name != "ingress"))
                && n["name"] == format!("{p}_{name}"),
            "Compose network is external or shared",
        )?;
    }
    let empty = json!({});
    let volumes = m.get("volumes").unwrap_or(&empty);
    for v in object(volumes, "Compose volumes are invalid")?.values() {
        require(
            v.is_object()
                && !external(&v["external"])
                && v.get("driver").unwrap_or(&json!("local")) == "local"
                && !truthy(&v["driver_opts"])
                && v["name"]
                    .as_str()
                    .is_some_and(|s| s.starts_with(&format!("{p}_"))),
            "Compose volume is external or shared",
        )?;
    }
    Ok(Value::Null)
}
fn grpc_environment(project: &str, prefix: &str, role: &str, server: bool) -> Value {
    if server {
        json!({
"GRPC_WORKLOAD_TLS_SERVER_CERT": format!("/run/secrets/{prefix}_cert"),
"GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR": "https://openbao:8200",
"GRPC_WORKLOAD_TLS_SERVER_KMS_CA_CERT": "/bao/public-ca/ca.crt",
"GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE": format!("/run/secrets/{prefix}_kms_token"),
"GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_NAME": format!("{project}-{role}"),
"GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_VERSION": "1"})
    } else {
        json!({
"GRPC_WORKLOAD_TLS_CLIENT_CERT": format!("/run/secrets/{prefix}_cert"),
"GRPC_WORKLOAD_TLS_CA_CERT": "/run/secrets/workload_identity_ca_cert",
"GRPC_WORKLOAD_TLS_KMS_ADDR": "https://openbao:8200",
"GRPC_WORKLOAD_TLS_KMS_CA_CERT": "/bao/public-ca/ca.crt",
"GRPC_WORKLOAD_TLS_KMS_TOKEN_FILE": format!("/run/secrets/{prefix}_kms_token"),
"GRPC_WORKLOAD_TLS_KMS_KEY_NAME": format!("{project}-{role}"),
"GRPC_WORKLOAD_TLS_KMS_KEY_VERSION": "1"})
    }
}
fn services(input: &Value) -> PolicyResult {
    let p = project(input)?;
    let m = &input["model"];
    let services = object(&m["services"], "Compose services are invalid")?;
    let image = &input["services_reference"];
    let port = &m["services"]["edge"]["ports"][0]["published"];
    let origin = port
        .as_str()
        .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()))
        .map(|s| format!("https://localhost:{s}"));
    let domain = port
        .as_str()
        .filter(|_| origin.is_some())
        .map(|s| format!("localhost:{s}"));
    let urls = regex::Regex::new(r"(?i)[a-z][a-z0-9+.-]*://[^\s,]+").unwrap();
    let remote =
        regex::Regex::new(r"\A.*(?:URL|URI|ADDR|ENDPOINT|HOST|TARGET|TEMPLATE)\z").unwrap();
    for (name, s) in services {
        require(s.is_object(), "Compose service is invalid")?;
        for key in [
            "container_name",
            "network_mode",
            "pid",
            "ipc",
            "privileged",
            "devices",
            "extra_hosts",
            "dns",
            "dns_search",
            "dns_opt",
            "links",
            "hostname",
            "domainname",
            "volumes_from",
            "build",
            "command",
        ] {
            if key == "command" && name == "issuance-migrations" {
                continue;
            }
            require(
                !truthy(&s[key]),
                format!("Compose {name} has a shared-host or fixed-name setting"),
            )?;
        }
        match name.as_str() {
            "openbao" => require(
                s["entrypoint"]
                    == json!(["/bin/sh", "/usr/local/bin/passport-supported-openbao-start"]),
                "Compose OpenBao start command differs from protected source",
            )?,
            "issuance-migrations" => require(
                s["entrypoint"] == json!(["/bin/sh", "-c"]),
                "Compose Rust issuance migrator entrypoint differs",
            )?,
            "edge" => require(
                s["entrypoint"] == json!(["/usr/local/bin/marty-passport-keyless-edge"]),
                "Compose Rust HTTPS edge entrypoint differs",
            )?,
            _ => require(
                !truthy(&s["entrypoint"]),
                format!("Compose {name} has an unexpected entrypoint"),
            )?,
        }
        require(
            s["pull_policy"] != "build"
                && s["image"]
                    .as_str()
                    .is_some_and(|s| pattern_matches(s, r"\A[^\s]+@sha256:[0-9a-f]{64}\z")),
            format!("Compose {name} image is not immutable"),
        )?;
        if SELECTED.contains(&name.as_str()) || RUST.contains(&name.as_str()) {
            require(
                s["image"] == *image,
                format!("Compose {name} is not pinned to the signed services image"),
            )?;
        }
        let expected = input["infra_images"]
            .get(name)
            .filter(|v| truthy(v))
            .or_else(|| {
                if name == "edge"
                    || RUST.contains(&name.as_str())
                    || ["signing-keys", "issuance-migrations"].contains(&name.as_str())
                {
                    Some(image)
                } else if name == "db-migrate" {
                    input.get("migrations_reference").filter(|v| !v.is_null())
                } else {
                    None
                }
            });
        if let Some(expected) = expected {
            require(
                s["image"] == *expected,
                format!("Compose {name} differs from the protected image reference"),
            )?;
        }
        let mounts = items(s, "volumes")?;
        let expected: Vec<(&str, &str)> = match name.as_str() {
            "postgres" => vec![("postgres_data", "/var/lib/postgresql/data")],
            "redis" => vec![("redis_data", "/data")],
            "openbao" => vec![
                ("openbao_data", "/bao/data"),
                ("openbao_file", "/openbao/file"),
                ("openbao_logs", "/openbao/logs"),
                ("openbao_public_ca", "/bao/public-ca"),
            ],
            _ if BAO.contains(&name.as_str())
                || name == "edge"
                || ["flow", "presentation-policy"].contains(&name.as_str())
                || SERVERS.iter().chain(CLIENTS).any(|(n, _, _)| n == name) =>
            {
                vec![("openbao_public_ca", "/bao/public-ca")]
            }
            _ => vec![],
        };
        let pairs = mounts
            .iter()
            .filter_map(|v| Some((v["source"].as_str()?, v["target"].as_str()?)))
            .collect::<BTreeSet<_>>();
        require(
            mounts.len() == expected.len()
                && pairs == expected.iter().copied().collect()
                && mounts.iter().all(|v| {
                    v.is_object()
                        && v["type"] == "volume"
                        && m["volumes"].get(text(&v["source"])).is_some()
                }),
            format!("Compose {name} has an unexpected bind mount or volume"),
        )?;
        let empty_env = json!({});
        let env = s.get("environment").unwrap_or(&empty_env);
        if BAO.contains(&name.as_str()) {
            require(
                mounts[0]["read_only"] == true
                    && env["BAO_ADDR"] == "https://openbao:8200"
                    && env["BAO_CACERT"] == "/bao/public-ca/ca.crt",
                format!("Compose {name} OpenBao endpoint or CA is invalid"),
            )?;
        } else if !expected.is_empty() && !["postgres", "redis", "openbao"].contains(&name.as_str())
        {
            require(
                mounts[0]["read_only"] == true,
                format!("Compose {name} remote TLS CA is writable"),
            )?;
        }
        for kind in ["secrets", "configs"] {
            let refs = items(s, kind)?;
            require(
                refs.iter().all(|r| {
                    r.is_object()
                        && r["source"]
                            .as_str()
                            .is_some_and(|source| m[kind].get(source).is_some())
                        && (kind != "secrets"
                            || (names(r).is_subset(&set(["source", "target"]))
                                && r.get("target").unwrap_or(&json!(format!(
                                    "/run/secrets/{}",
                                    text(&r["source"])
                                ))) == &json!(format!("/run/secrets/{}", text(&r["source"])))))
                }),
                format!("Compose {name} uses an unknown {kind} source"),
            )?;
            require(
                refs.iter()
                    .filter_map(|r| r["source"].as_str())
                    .collect::<BTreeSet<_>>()
                    .len()
                    == refs.len(),
                format!("Compose {name} has duplicate {kind} sources"),
            )?;
        }
        if name == "openbao" {
            require(
                s["configs"]
                    == json!([{"source":"passport_supported_openbao_start","target":"/usr/local/bin/passport-supported-openbao-start"}])
                    && refs(s) == set(["bao_root_token"]),
                "Compose OpenBao start secrets or config differ from protected source",
            )?;
            require(
                absent(env, &["BAO_DEV_ROOT_TOKEN_ID", "BAO_TOKEN", "VAULT_TOKEN"]),
                "Compose OpenBao root token is exposed in the resolved environment",
            )?;
        } else if name == "edge" {
            require(
                !truthy(&s["configs"])
                    && env_matches(
                        env,
                        &json!({
"PASSPORT_EDGE_BIND": "0.0.0.0:8443",
"PASSPORT_EDGE_TLS_CERT_FILE": "/run/secrets/passport_edge_tls_cert",
"PASSPORT_EDGE_TLS_KMS_ADDR": "https://openbao:8200",
"PASSPORT_EDGE_TLS_KMS_CA_CERT_FILE": "/bao/public-ca/ca.crt",
"PASSPORT_EDGE_TLS_KMS_TOKEN_FILE": "/run/secrets/passport_edge_tls_kms_token",
"PASSPORT_EDGE_TLS_KMS_KEY_NAME": format!("{p}-passport-edge"),
"PASSPORT_EDGE_TLS_KMS_KEY_VERSION": "1"}),
                    )
                    && refs(s) == set(["passport_edge_tls_cert", "passport_edge_tls_kms_token"]),
                "Compose HTTPS edge remote signer differs from protected source",
            )?;
        } else {
            require(
                !truthy(&s["configs"]),
                format!("Compose {name} has an unexpected config"),
            )?;
            require(
                !refs(s).contains("bao_root_token"),
                format!("Compose {name} mounts the OpenBao root token"),
            )?;
        }
        for (list, server) in [(SERVERS, true), (CLIENTS, false)] {
            if let Some((_, prefix, role)) = list.iter().find(|(n, _, _)| n == name) {
                let cert = format!("{prefix}_cert");
                let token = format!("{prefix}_kms_token");
                require(
                    env_matches(env, &grpc_environment(p, prefix, role, server))
                        && set([cert.as_str(), token.as_str()]).is_subset(&refs(s))
                        && (server || refs(s).contains("workload_identity_ca_cert")),
                    format!(
                        "Compose {name} remote gRPC {} identity is invalid",
                        if server { "server" } else { "client" }
                    ),
                )?;
            }
        }
        require(
            items(s, "ports")?
                .iter()
                .all(|p| p.is_object() && p["host_ip"] == "127.0.0.1"),
            format!("Compose {name} publishes outside loopback"),
        )?;
        let env = object(env, &format!("Compose {name} environment is invalid"))?;
        if name == "signing-keys" {
            require(
                s["environment"]["SIGNING_KEYS_REDIS_URL"] == "redis://redis:6379/2"
                    && dep(s, "redis", "service_healthy"),
                "Compose signing-keys lacks isolated Redis readiness",
            )?;
        }
        for (key, value) in env {
            let Some(value) = value.as_str() else {
                continue;
            };
            if ["revocation-profile", "revocation-profile-migrate"].contains(&name.as_str())
                && key == "STATUS_LIST_BASE_URL"
            {
                continue;
            }
            if origin.as_deref() == Some(value)
                && (([
                    "credential-template",
                    "trust-profile",
                    "presentation-policy",
                    "flow",
                ]
                .contains(&name.as_str())
                    && [
                        "PUBLIC_API_URL",
                        "MARTY_ISSUER_BASE_URL",
                        "PUBLIC_BASE_URL",
                        "ISSUER_BASE_URL",
                    ]
                    .contains(&key.as_str()))
                    || ((name == "db-migrate" && key == "MARTY_ISSUER_BASE_URL")
                        || (["gateway", "issuance-native"].contains(&name.as_str())
                            && key == "ISSUER_BASE_URL")))
            {
                continue;
            }
            for url in urls.find_iter(value) {
                require(
                    endpoint_host(url.as_str()).is_some_and(|h| services.contains_key(&h)),
                    format!("Compose {name} endpoint leaves disposable services"),
                )?;
            }
            if remote.is_match(key) && !value.is_empty() && !urls.is_match(value) {
                require(
                    services.contains_key(value.split(':').next().unwrap_or("")),
                    format!("Compose {name} endpoint leaves disposable services"),
                )?;
            }
            if (key.ends_with("DOMAIN") || key.ends_with("HOSTNAME")) && !value.is_empty() {
                require(
                    ["localhost", "127.0.0.1"].contains(&value)
                        || domain.as_deref() == Some(value)
                        || services.contains_key(value),
                    format!("Compose {name} domain leaves disposable services"),
                )?;
            }
        }
    }
    for (name, s) in services {
        let expected = match name.as_str() {
            "passport-callback-signer" => set(["callback_signing"]),
            "passport-beta-bureau" | "openbao" => set(["private", "callback_signing"]),
            "edge" => set(["private", "ingress"]),
            _ => set(["private"]),
        };
        let joined = &s["networks"];
        let actual = joined_networks(joined);
        require(
            actual == Some(expected),
            format!("Compose {name} leaves the dedicated callback signing boundary"),
        )?;
    }
    Ok(Value::Null)
}

fn merged(mut base: Value, patch: Value) -> Value {
    base.as_object_mut()
        .unwrap()
        .extend(patch.as_object().unwrap().clone());
    base
}
fn runtime_rule(
    services: &Value,
    name: &str,
    env: Value,
    secrets: &[&str],
    dependencies: Value,
    port: u16,
) -> Result<(), String> {
    let service = &services[name];
    let actual = &service["depends_on"];
    require(
        env_matches(&service["environment"], &env)
            && absent(
                &service["environment"],
                &[
                    "MARTY_DB_PASSWORD",
                    "GRPC_SERVICE_TOKEN",
                    "ISSUANCE_API_KEY",
                    "SIGNING_KEYS_INTERNAL_API_KEY",
                ],
            )
            && refs(service) == set(secrets.iter().copied())
            && actual.is_object()
            && names(actual) == names(&dependencies)
            && dependencies
                .as_object()
                .unwrap()
                .iter()
                .all(|(n, c)| actual[n].is_object() && actual[n]["condition"] == *c)
            && service["healthcheck"]["test"]
                == json!([
                    "CMD",
                    "curl",
                    "--fail",
                    format!("http://localhost:{port}/health")
                ]),
        format!("Disposable {name} runtime is not isolated and ready"),
    )
}
fn runtime(input: &Value) -> PolicyResult {
    let p = project(input)?;
    let selfhost = p.starts_with("marty-passport-acceptance-selfhost-");
    let m = &input["model"];
    let s = &m["services"];
    let services = object(s, "Compose services are invalid")?;
    let env = |name| environment(s, name);
    let (gateway, flow, native, org, events, signer, bureau, signing) = (
        env("gateway"),
        env("flow"),
        env("issuance-native"),
        env("organization"),
        env("event-stream"),
        env("passport-callback-signer"),
        env("passport-beta-bureau"),
        env("signing-keys"),
    );
    require(
        !bureau
            .as_object()
            .ok_or("Compose bureau environment is invalid")?
            .keys()
            .any(|k| {
                ["http_proxy", "https_proxy", "all_proxy", "no_proxy"]
                    .contains(&k.to_lowercase().as_str())
            }),
        "Disposable bureau proxy environment is forbidden",
    )?;
    let organization = &s["organization"];
    let migrate = &s["db-migrate"];
    let mig = env("db-migrate");
    require(
        env_matches(
            events,
            &json!({
"SERVICE_NAME": "event_stream",
"EVENT_STREAM_SERVICE_PORT": "8015",
"EVENT_STREAM_GRPC_ENABLED": "true",
"EVENT_STREAM_GRPC_PORT": "9015"}),
        ) && env_matches(
            org,
            &json!({
"SERVICE_NAME": "organization",
"ORGANIZATION_SERVICE_PORT": "8002",
"ORG_GRPC_PORT": "9002",
"MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
"GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
"REDIS_URL": "redis://redis:6379",
"ES_GRPC_TARGET": "https://event-stream:9015",
"ES_GRPC_CA_CERT": "/run/secrets/workload_identity_ca_cert",
"PASSPORT_ACCEPTANCE_PROJECT": p}),
        ) && org["DATABASE_URL_TEMPLATE"] == flow["DATABASE_URL_TEMPLATE"]
            && org["DATABASE_URL_TEMPLATE"] == native["DATABASE_URL_TEMPLATE"]
            && text(&org["DATABASE_URL_TEMPLATE"]).starts_with("postgresql+asyncpg://marty:")
            && text(&org["DATABASE_URL_TEMPLATE"]).ends_with("@postgres:5432/marty")
            && org["MARTY_ORG_ADMIN_EMAIL"]
                .as_str()
                .is_some_and(|s| s.contains('@'))
            && org["MARTY_ORG_ADMIN_EMAIL"] == mig["MARTY_ORG_ADMIN_EMAIL"]
            && organization["labels"].is_object()
            && org["PASSPORT_ACCEPTANCE_RUN_ID"]
                == organization["labels"]["com.marty.passport.acceptance.run-id"]
            && org["PASSPORT_ACCEPTANCE_SOURCE_COMMIT"]
                == organization["labels"]["com.marty.passport.acceptance.source-commit"]
            && input["organization_expiry_aware"] == true
            && absent(org, &["MARTY_DB_PASSWORD", "GRPC_SERVICE_TOKEN"])
            && refs(organization)
                == set([
                    "marty_db_password",
                    "grpc_service_token",
                    "workload_identity_ca_cert",
                    "org_workload_server_cert",
                    "org_workload_server_kms_token",
                ])
            && dep(organization, "db-migrate", "service_completed_successfully")
            && dep(organization, "redis", "service_healthy")
            && dep(organization, "event-stream", "service_healthy")
            && env_matches(
                gateway,
                &json!({
"ORGANIZATION_SERVICE_URL": "http://organization:8002",
"ORG_GRPC_TARGET": "organization:9002",
"ES_GRPC_TARGET": "event-stream:9015",
"GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
"DEVICE_REGISTRATION_GATEWAY_KEY_FILE": "/run/secrets/device_registration_gateway_key"}),
            ),
        "Disposable Organization API-key authority is not isolated and ready",
    )?;
    require(
        dep(&s["gateway"], "organization", "service_healthy")
            && flow["ORG_GRPC_TARGET"] == "https://organization:9002",
        "Disposable passport services do not use the Organization authority",
    )?;
    let edge = &s["edge"];
    let ports = items(edge, "ports")?;
    let port = ports
        .first()
        .map(|v| &v["published"])
        .unwrap_or(&Value::Null);
    require(
        !truthy(&s["gateway"]["ports"])
            && ports.len() == 1
            && ports[0].is_object()
            && ports[0]["host_ip"] == "127.0.0.1"
            && ports[0]["target"] == 8443
            && port
                .as_str()
                .is_some_and(|p| p.parse::<u16>().is_ok_and(|p| p >= 1024))
            && dep(edge, "gateway", "service_started")
            && dep(edge, "openbao", "service_healthy"),
        "Disposable HTTPS edge lacks a reserved loopback port or Gateway peer",
    )?;
    let port = text(port);
    let origin = format!("https://localhost:{port}");
    let domain = format!("localhost:{port}");
    let did = format!("did:web:localhost%3A{port}:orgs:marty");
    let common = json!({
"ENVIRONMENT": "development",
"DATABASE_URL_TEMPLATE": org[
"DATABASE_URL_TEMPLATE"],
"MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
"GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
"ORG_GRPC_TARGET": "https://organization:9002"});
    runtime_rule(
        s,
        "compliance-profile",
        merged(
            merged(
                common.clone(),
                json!({
"SERVICE_NAME": "compliance_profile",
"COMPLIANCE_PROFILE_SERVICE_PORT": "8008"}),
            ),
            grpc_environment(
                p,
                "compliance_profile_workload_client",
                "compliance-profile-client",
                false,
            ),
        ),
        &[
            "marty_db_password",
            "grpc_service_token",
            "workload_identity_ca_cert",
            "compliance_profile_workload_client_cert",
            "compliance_profile_workload_client_kms_token",
        ],
        json!({
"db-migrate": "service_completed_successfully",
"organization": "service_healthy"}),
        8008,
    )?;
    runtime_rule(
        s,
        "trust-profile",
        merged(
            common.clone(),
            json!({
"SERVICE_NAME": "trust_profile",
"TRUST_PROFILE_SERVICE_PORT": "8004",
"SIGNING_KEYS_INTERNAL_API_KEY_FILE": "/run/secrets/signing_keys_internal_api_key",
"MARTY_ORG_ID": org[
"MARTY_ORG_ID"],
"MARTY_ORG_SLUG": "marty",
"MARTY_ISSUER_DID": did,
"MARTY_ISSUER_BASE_URL": origin,
"PUBLIC_DOMAIN": domain,
"DID_RESOLUTION_BASE_URL": "http://gateway:8000",
"ORG_GRPC_CA_CERT": "/run/secrets/workload_identity_ca_cert"}),
        ),
        &[
            "marty_db_password",
            "grpc_service_token",
            "signing_keys_internal_api_key",
            "workload_identity_ca_cert",
        ],
        json!({
"db-migrate": "service_completed_successfully",
"organization": "service_healthy"}),
        8004,
    )?;
    runtime_rule(
        s,
        "credential-template",
        merged(
            merged(
                common.clone(),
                json!({
"SERVICE_NAME": "credential_template",
"CREDENTIAL_TEMPLATE_SERVICE_PORT": "8003",
"CT_GRPC_PORT": "9003",
"ORG_GRPC_CA_CERT": "/run/secrets/workload_identity_ca_cert",
"RP_GRPC_TARGET": "https://revocation-profile:9013",
"RP_GRPC_CA_CERT": "/run/secrets/workload_identity_ca_cert",
"SIGNING_KEYS_INTERNAL_URL": "http://gateway:8000/internal/signing-keys",
"SIGNING_KEYS_INTERNAL_API_KEY_FILE": "/run/secrets/signing_keys_internal_api_key",
"TRUST_PROFILE_SERVICE_URL": "http://trust-profile:8004",
"PUBLIC_API_URL": origin,
"MARTY_ORG_ID": org[
"MARTY_ORG_ID"],
"MARTY_MIGRATION_PROFILE": "dev"}),
            ),
            grpc_environment(p, "ct_workload_server", "credential-template-server", true),
        ),
        &[
            "marty_db_password",
            "grpc_service_token",
            "signing_keys_internal_api_key",
            "workload_identity_ca_cert",
            "ct_workload_server_cert",
            "ct_workload_server_kms_token",
        ],
        json!({
"db-migrate": "service_completed_successfully",
"organization": "service_healthy",
"revocation-profile": "service_healthy",
"trust-profile": "service_healthy",
"signing-keys": "service_healthy"}),
        8003,
    )?;
    let pp = merged(
        common.clone(),
        json!({
"ENVIRONMENT": if selfhost {
"production"}else{
"development"},
"SERVICE_NAME": "presentation_policy",
"GRPC_WORKLOAD_TLS_CA_CERT": "/run/secrets/workload_identity_ca_cert",
"ORG_GRPC_CA_CERT": "/run/secrets/workload_identity_ca_cert",
"PRESENTATION_POLICY_SERVICE_PORT": "8009",
"PP_GRPC_PORT": "9009",
"ISSUANCE_API_KEY_FILE": "/run/secrets/issuance_api_key",
"SIGNING_KEYS_SERVICE_URL": "http://signing-keys:8017",
"SIGNING_KEYS_INTERNAL_API_KEY_FILE": "/run/secrets/signing_keys_internal_api_key",
"DID_RESOLUTION_BASE_URL": "http://gateway:8000",
"TRUST_PROFILE_SERVICE_URL": "http://trust-profile:8004",
"ISSUANCE_NATIVE_SERVICE_URL": "http://issuance-native:8005",
"PUBLIC_DOMAIN": domain,
"PUBLIC_BASE_URL": origin,
"ISSUER_BASE_URL": origin,
"MARTY_ORG_SLUG": "marty"}),
    );
    runtime_rule(
        s,
        "presentation-policy",
        merged(
            pp,
            grpc_environment(p, "pp_workload_server", "pp-server", true),
        ),
        &[
            "marty_db_password",
            "grpc_service_token",
            "issuance_api_key",
            "signing_keys_internal_api_key",
            "pp_workload_server_cert",
            "pp_workload_server_kms_token",
            "workload_identity_ca_cert",
        ],
        json!({
"db-migrate": "service_completed_successfully",
"organization": "service_healthy",
"trust-profile": "service_healthy",
"issuance-native": "service_healthy"}),
        8009,
    )?;
    runtime_rule(
        s,
        "deployment-profile",
        merged(
            merged(
                common,
                json!({
"SERVICE_NAME": "deployment_profile",
"DEPLOYMENT_PROFILE_SERVICE_PORT": "8010"}),
            ),
            grpc_environment(
                p,
                "deployment_profile_workload_client",
                "deployment-profile-client",
                false,
            ),
        ),
        &[
            "marty_db_password",
            "grpc_service_token",
            "workload_identity_ca_cert",
            "deployment_profile_workload_client_cert",
            "deployment_profile_workload_client_kms_token",
        ],
        json!({
"db-migrate": "service_completed_successfully",
"organization": "service_healthy"}),
        8010,
    )?;
    require(env_matches(flow,&json!({
"PUBLIC_BASE_URL": origin,
"CT_GRPC_TARGET": "https://credential-template:9003",
"PP_GRPC_TARGET": "https://presentation-policy:9009",
"ISSUANCE_GRPC_TARGET": "https://issuance-native:9005",
"CREDENTIAL_TEMPLATE_SERVICE_URL": "http://credential-template:8003",
"TRUST_PROFILE_SERVICE_URL": "http://trust-profile:8004",
"DEPLOYMENT_PROFILE_SERVICE_URL": "http://deployment-profile:8010"}))
  && ["credential-template","trust-profile","presentation-policy","deployment-profile","issuance-native","signing-keys"].iter().all(|n|dep(&s["flow"],n,"service_healthy"))
  && s["issuance-native"]["healthcheck"]["test"]==json!(["CMD","curl","--fail","http://localhost:8005/health"])
  && s["signing-keys"]["healthcheck"]["test"]==json!(["CMD-SHELL","curl --fail http://localhost:8017/health && curl --fail --cacert /run/secrets/workload_identity_ca_cert https://signing-keys:8018/health"]),"Disposable Flow startup dependencies are incomplete")?;
    require(
        flow["FLOW_APPLICATION_EVENT_HMAC_KEY_FILE"]
            == "/run/secrets/flow_application_event_hmac_key"
            && refs(&s["flow"]).contains("flow_application_event_hmac_key"),
        "Disposable Flow application event authentication is missing",
    )?;
    let flow_tls = json!({
"GRPC_WORKLOAD_TLS_CLIENT_CERT": "/run/secrets/flow_workload_client_cert",
"GRPC_WORKLOAD_TLS_CLIENT_KMS_ADDR": "https://openbao:8200",
"GRPC_WORKLOAD_TLS_CLIENT_KMS_CA_CERT": "/bao/public-ca/ca.crt",
"GRPC_WORKLOAD_TLS_CLIENT_KMS_TOKEN_FILE": "/run/secrets/flow_workload_client_kms_token",
"GRPC_WORKLOAD_TLS_CLIENT_KMS_KEY_NAME": format!("{p}-flow-client"),
"GRPC_WORKLOAD_TLS_CLIENT_KMS_KEY_VERSION": "1",
"GRPC_WORKLOAD_TLS_CA_CERT": "/run/secrets/workload_identity_ca_cert"});
    require(
        env_matches(
            flow,
            &merged(
                flow_tls,
                grpc_environment(p, "flow_workload_server", "flow-server", true),
            ),
        ) && set([
            "flow_workload_client_cert",
            "flow_workload_client_kms_token",
            "flow_workload_server_cert",
            "flow_workload_server_kms_token",
            "workload_identity_ca_cert",
        ])
        .is_subset(&refs(&s["flow"]))
            && (!selfhost
                || env_matches(
                    flow,
                    &json!({
"FLOW_CALLBACK_DESTINATIONS": "00000000-0000-0000-0000-000000000001|https://edge:8443/__disposable/flow-callback?nonce=__MARTY_TOKEN__",
"FLOW_WEBHOOK_SECRET_FILE": "/run/secrets/flow_webhook_secret",
"FLOW_CALLBACK_CA_CERT_FILE": "/run/secrets/workload_identity_ca_cert"}),
                )),
        "Disposable Flow callback or workload TLS configuration differs from surface",
    )?;
    require(
        env_matches(
            native,
            &json!({
"ISSUANCE_GRPC_ENABLED": "true",
"ISSUANCE_GRPC_PORT": "9005",
"CT_GRPC_TARGET": "https://credential-template:9003",
"CREDENTIAL_TEMPLATE_SERVICE_URL": "http://credential-template:8003"}),
        ) && dep(
            &s["issuance-native"],
            "credential-template",
            "service_healthy",
        ) && [
            (
                "CREDENTIAL_TEMPLATE_SERVICE_URL",
                "credential-template",
                8003,
            ),
            ("COMPLIANCE_PROFILE_SERVICE_URL", "compliance-profile", 8008),
            ("TRUST_PROFILE_SERVICE_URL", "trust-profile", 8004),
            (
                "PRESENTATION_POLICY_SERVICE_URL",
                "presentation-policy",
                8009,
            ),
            ("DEPLOYMENT_PROFILE_SERVICE_URL", "deployment-profile", 8010),
        ]
        .iter()
        .all(|(key, n, port)| {
            gateway[*key] == format!("http://{n}:{port}")
                && dep(&s["gateway"], n, "service_healthy")
        }),
        "Disposable passport routing lacks the Rust support services",
    )?;
    let im = &s["issuance-migrations"];
    require(
        im["command"]
            == json!([
                ". /app/load-secrets-env.sh\nexec /usr/local/bin/marty-issuance-service migrate\n"
            ])
            && im["environment"]
                == json!({
"SERVICE_NAME": "issuance_native",
"DATABASE_URL_TEMPLATE": "postgresql://marty:$${MARTY_DB_PASSWORD}@postgres:5432/marty",
"MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password"})
            && refs(im) == set(["marty_db_password"])
            && dep(im, "db-migrate", "service_completed_successfully")
            && dep(im, "organization", "service_healthy")
            && im["healthcheck"]
                == json!({
"disable": true})
            && im["restart"] == "no"
            && dep(
                &s["issuance-native"],
                "issuance-migrations",
                "service_completed_successfully",
            ),
        "Disposable Rust issuance schema is not ordered before runtime",
    )?;
    let rm = &s["revocation-profile-migrate"];
    let re = env("revocation-profile-migrate");
    require(
        env_matches(
            re,
            &json!({
"SERVICE_NAME": "revocation_profile",
"RP_MIGRATE_ONLY": "true",
"ENVIRONMENT": "development",
"MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
"PUBLIC_API_URL": "http://gateway:8000",
"STATUS_LIST_BASE_URL": origin,
"MARTY_ORG_ID": "00000000-0000-0000-0000-000000000001"}),
        ) && [
            "postgresql://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty",
            "postgresql://marty:$${MARTY_DB_PASSWORD}@postgres:5432/marty",
        ]
        .contains(&text(&re["DATABASE_URL_TEMPLATE"]))
            && refs(rm) == set(["marty_db_password"])
            && dep(rm, "postgres", "service_healthy")
            && rm["healthcheck"]
                == json!({
"disable": true})
            && rm["restart"] == "no"
            && dep(
                migrate,
                "revocation-profile-migrate",
                "service_completed_successfully",
            ),
        "Disposable revocation schema migration is not ordered before shared migrations",
    )?;
    let rev = &s["revocation-profile"];
    let renv = env("revocation-profile");
    require(
        env_matches(
            renv,
            &json!({
"SERVICE_NAME": "revocation_profile",
"ENVIRONMENT": "development",
"REVOCATION_PROFILE_SERVICE_PORT": "8013",
"RP_GRPC_ENABLED": "true",
"RP_GRPC_PORT": "9013",
"DATABASE_URL_TEMPLATE": re[
"DATABASE_URL_TEMPLATE"],
"MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
"GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
"REDIS_URL": "redis://redis:6379/4",
"ORG_GRPC_TARGET": "https://organization:9002",
"ORG_GRPC_CA_CERT": "/run/secrets/workload_identity_ca_cert",
"PUBLIC_API_URL": "http://gateway:8000",
"STATUS_LIST_BASE_URL": origin,
"MARTY_ORG_ID": re[
"MARTY_ORG_ID"]}),
        ) && renv.get("RP_MIGRATE_ONLY").is_none()
            && refs(rev)
                == set([
                    "marty_db_password",
                    "grpc_service_token",
                    "workload_identity_ca_cert",
                    "rp_workload_server_cert",
                    "rp_workload_server_kms_token",
                ])
            && dep(rev, "db-migrate", "service_completed_successfully")
            && dep(rev, "organization", "service_healthy")
            && dep(rev, "redis", "service_healthy")
            && rev["healthcheck"]["test"]
                == json!(["CMD", "curl", "--fail", "http://localhost:8013/health"]),
        "Disposable revocation runtime is not isolated and ready",
    )?;
    require(
        native["REVOCATION_PROFILE_SERVICE_URL"] == "http://revocation-profile:8013"
            && gateway["REVOCATION_PROFILE_SERVICE_URL"]
                == native["REVOCATION_PROFILE_SERVICE_URL"]
            && native["RP_GRPC_TARGET"] == "https://revocation-profile:9013"
            && ["issuance-native", "gateway"]
                .iter()
                .all(|n| dep(&s[n], "revocation-profile", "service_healthy")),
        "Disposable passport services do not use the revocation runtime",
    )?;
    require(
        native["SIGNING_KEYS_INTERNAL_URL"] == "http://gateway:8000/internal/signing-keys"
            && native["SIGNING_KEYS_INTERNAL_API_KEY_FILE"]
                == "/run/secrets/signing_keys_internal_api_key"
            && refs(&s["issuance-native"]).contains("signing_keys_internal_api_key"),
        "Disposable native managed issuer signer bypasses the Gateway compatibility API",
    )?;
    require(
        env_matches(
            mig,
            &json!({
"REDIS_URL": "redis://redis:6379/2",
"BAO_ADDR": "https://openbao:8200",
"BAO_TOKEN_FILE": "/run/secrets/bao_token",
"MARTY_KMS_BOOTSTRAP_ENABLED": "true",
"PASSPORT_DISPOSABLE_ICAO_BOOTSTRAP": "true",
"PASSPORT_ACCEPTANCE_PROJECT": p,
"PASSPORT_ACCEPTANCE_GATEWAY_PORT": port,
"PUBLIC_DOMAIN": domain,
"MARTY_ORG_ID": re[
"MARTY_ORG_ID"],
"MARTY_ISSUER_BASE_URL": origin}),
        ) && signing["SIGNING_KEYS_REDIS_URL"] == "redis://redis:6379/2"
            && org["MARTY_ORG_ID"] == mig["MARTY_ORG_ID"]
            && ["postgres", "redis", "openbao"]
                .iter()
                .all(|n| dep(migrate, n, "service_healthy"))
            && refs(migrate).contains("bao_token"),
        "Disposable migrations could skip managed issuer profile bootstrap",
    )?;
    require(
        mig["MARTY_ISSUER_DID"] == did
            && gateway["PUBLIC_DOMAIN"] == domain
            && signing["PUBLIC_DOMAIN"] == domain
            && gateway["ISSUER_BASE_URL"] == origin
            && native["ISSUER_BASE_URL"] == origin
            && flow["MARTY_ISSUER_DID"] == did,
        "Disposable managed issuer DID differs across profile and runtime services",
    )?;
    require(
        env_matches(
            gateway,
            &json!({
"PASSPORT_NATIVE_GATEWAY_ENABLED": "true",
"ISSUANCE_SERVICE_URL": "http://issuance-native:8005",
"ISSUANCE_NATIVE_SERVICE_URL": "http://issuance-native:8005"}),
        ) && flow["PASSPORT_NATIVE_FLOW_ENABLED"] == "true"
            && flow["ISSUANCE_NATIVE_SERVICE_URL"] == "http://issuance-native:8005"
            && flow.get("ISSUANCE_SERVICE_URL").is_none()
            && env_matches(
                native,
                &json!({
"PASSPORT_NATIVE_HTTP_ENABLED": "true",
"PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED": "true",
"PASSPORT_KMS_ARTIFACTS_ENABLED": "true",
"PASSPORT_KMS_CALLBACKS_ENABLED": "true",
"PASSPORT_BETA_RECONCILIATION_ENABLED": "true",
"PASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN_FILE": "/run/secrets/passport_beta_reconciliation_operator_token"}),
            ),
        "Disposable passport routes do not have one Rust owner",
    )?;
    require(
        [gateway, flow, native].iter().all(|e| {
            e["PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED"] == "true"
                && absent(
                    e,
                    &["PASSPORT_TENANT_API_KEYS", "PASSPORT_TENANT_API_KEYS_FILE"],
                )
        }) && m["secrets"].get("passport_tenant_api_keys").is_none(),
        "Disposable internal passport authentication conflicts with tenant keyring",
    )?;
    require(
        [gateway, flow, native].iter().all(|e| {
            env_matches(
                e,
                &json!({
"ISSUANCE_API_KEY_FILE": "/run/secrets/issuance_api_key",
"SIGNING_KEYS_INTERNAL_API_KEY_FILE": "/run/secrets/signing_keys_internal_api_key"}),
            )
        }) && signing["SIGNING_KEYS_INTERNAL_API_KEY_FILE"]
            == "/run/secrets/signing_keys_internal_api_key"
            && ["gateway", "flow", "issuance-native"].iter().all(|n| {
                set(["issuance_api_key", "signing_keys_internal_api_key"]).is_subset(&refs(&s[n]))
            })
            && refs(&s["signing-keys"]).contains("signing_keys_internal_api_key"),
        "Disposable Gateway and signing services do not share project credentials",
    )?;
    require(
        env_matches(
            native,
            &json!({
"TOKEN_HMAC_KEY_FILE": "/run/secrets/token_hmac_key",
"INTEGRATION_SECRET_KMS_URL": "https://signing-keys:8018/internal",
"INTEGRATION_SECRET_KMS_CA_FILE": "/run/secrets/workload_identity_ca_cert"}),
        ) && absent(
            native,
            &[
                "PASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN",
                "TOKEN_HMAC_KEY",
                "INTEGRATION_SECRET_MASTER_KEY",
                "INTEGRATION_SECRET_MASTER_KEY_FILE",
            ],
        ) && set([
            "token_hmac_key",
            "passport_beta_reconciliation_operator_token",
            "workload_identity_ca_cert",
        ])
        .is_subset(&refs(&s["issuance-native"])),
        "Disposable native issuance startup secrets are missing",
    )?;
    require(
        holders(services, "signing_keys_integration_secret_key")
            == set(["signing-keys", "issuance-native"])
            && [signing, native].iter().all(|e| {
                e["SIGNING_KEYS_INTEGRATION_SECRET_KEY_FILE"]
                    == "/run/secrets/signing_keys_integration_secret_key"
            }),
        "Disposable integration-secret credential escaped its direct custody boundary",
    )?;
    require(
        env_matches(
            signing,
            &json!({
"SIGNING_KEYS_INTEGRATION_SECRET_TLS_CERT_FILE": "/run/secrets/signing_keys_workload_server_cert",
"SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_ADDR": "https://openbao:8200",
"SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_CA_CERT_FILE": "/bao/public-ca/ca.crt",
"SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_TOKEN_FILE": "/run/secrets/signing_keys_workload_server_kms_token",
"SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_KEY_NAME": format!("{p}-signing-keys-server"),
"SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_KEY_VERSION": "1"}),
        ) && set([
            "signing_keys_workload_server_cert",
            "signing_keys_workload_server_kms_token",
            "workload_identity_ca_cert",
        ])
        .is_subset(&refs(&s["signing-keys"])),
        "Disposable signing-key remote-secret TLS custody is incomplete",
    )?;
    require(
        holders(services, "passport_beta_reconciliation_operator_token")
            == set(["issuance-native"]),
        "Disposable native batch operator token escaped its owner",
    )?;
    require(
        gateway["GRPC_INSECURE_ALLOWED"] == "true"
            && native.get("GRPC_INSECURE_ALLOWED").is_none()
            && native["ENVIRONMENT"] == "beta"
            && gateway["ENVIRONMENT"] == if selfhost { "production" } else { "beta" }
            && flow["ENVIRONMENT"]
                == if selfhost {
                    "production"
                } else {
                    "development"
                },
        "Disposable surface environment selectors are incompatible with the beta simulator",
    )?;
    for (key, secret) in [
        (
            "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY",
            "dsc_issue_gateway_key",
        ),
        (
            "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY",
            "csca_issue_gateway_key",
        ),
    ] {
        require(
            services
                .values()
                .all(|s| s["environment"].get(key).is_none()),
            "Disposable certificate operator key is exposed in Compose environment",
        )?;
        let file = format!("{key}_FILE");
        let actual = services
            .iter()
            .filter(|(_, s)| s["environment"].get(&file).is_some())
            .map(|(n, _)| n.as_str())
            .collect::<BTreeSet<_>>();
        require(
            actual == holders(services, secret)
                && actual
                    == if selfhost {
                        set([])
                    } else {
                        set(["gateway", "signing-keys"])
                    }
                && actual
                    .iter()
                    .all(|n| s[n]["environment"][&file] == format!("/run/secrets/{secret}")),
            "Disposable certificate operator key holders are invalid",
        )?;
    }
    require(
        (!selfhost
            && signing["ENVIRONMENT"] == "beta"
            && signing["SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED"] == "true")
            || (selfhost
                && signing
                    .get("SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED")
                    .is_none()),
        "Disposable certificate ceremony mode differs from surface",
    )?;
    require(
        env_matches(
            signer,
            &json!({
"ENVIRONMENT": "beta",
"PASSPORT_CALLBACK_SIGNER_ENABLED": "true",
"SIGNING_KEYS_INTERNAL_API_KEY_FILE": "/run/secrets/callback_signer_api_key",
"BAO_TOKEN_FILE": "/run/secrets/callback_signer_bao_token"}),
        ) && absent(signer, &["SIGNING_KEYS_INTERNAL_API_KEY", "BAO_TOKEN"]),
        "Disposable callback signer is not isolated beta KMS mode",
    )?;
    require(
        env_matches(
            bureau,
            &json!({
"ENVIRONMENT": "beta",
"PASSPORT_BETA_BUREAU_ENABLED": "true",
"DATABASE_URL_FILE": "/run/secrets/bureau_database_url",
"GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
"SIGNING_KEYS_INTERNAL_API_KEY_FILE": "/run/secrets/callback_signer_api_key",
"SIGNING_KEYS_INTERNAL_URL": "http://passport-callback-signer:8018/internal/documents",
"PASSPORT_BETA_BUREAU_GATEWAY_CALLBACK_ENABLED": "true",
"PASSPORT_BUREAU_CALLBACK_URL": "http://gateway:8000/v1/passport/webhooks/personalization"}),
        ) && absent(
            bureau,
            &[
                "DATABASE_URL",
                "GRPC_SERVICE_TOKEN",
                "SIGNING_KEYS_INTERNAL_API_KEY",
            ],
        ),
        "Disposable bureau is not the private Marty simulator",
    )?;
    require(
        env_matches(
            native,
            &json!({
"PERSONALIZATION_BUREAU_URL": "http://passport-beta-bureau:8020",
"PERSONALIZATION_BUREAU_API_KEY_FILE": "/run/secrets/grpc_service_token",
"PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID": "passport-beta-bureau"}),
        ) && gateway["PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED"] == "false"
            && gateway
                .get("PASSPORT_PROVIDER_INGRESS_SERVICE_URL")
                .is_none(),
        "Disposable passport owner selects an external provider",
    )?;
    require(
        m["secrets"].get("provider_webhook_secret").is_none(),
        "Disposable simulator model includes a physical provider secret",
    )?;
    let mut selected = SELECTED.to_vec();
    selected.sort();
    Ok(json!({
"project": p,
"services": selected,
"model_safe": true}))
}
pub(super) fn evaluate(op: &str, input: &Value) -> PolicyResult {
    match op {
        "compose-supported-resources" => resources(input),
        "compose-supported-services" => services(input),
        "compose-supported-runtime" => runtime(input),
        "compose-beta-selection" => beta::selection(input),
        "compose-physical-layout" => beta::physical_layout(input),
        "compose-physical-services" => beta::physical_services(input),
        "compose-physical-before-registry" => beta::physical_before_registry(input),
        "compose-physical-after-registry" => beta::physical_after_registry(input),
        "compose-beta-before-files" => beta::simulator_before(input),
        "compose-beta-after-files" => beta::simulator_after(input),
        "compose-beta-operator-credential" => Ok(json!(beta::operator_credential(&input["value"]))),
        _ => Err("Invalid Compose admission operation".into()),
    }
}

fn joined_networks(joined: &Value) -> Option<BTreeSet<&str>> {
    if let Some(v) = joined.as_array().filter(|v| v.iter().all(Value::is_string)) {
        Some(v.iter().filter_map(Value::as_str).collect::<BTreeSet<_>>())
    } else if joined.is_object()
        && joined
            .as_object()
            .unwrap()
            .values()
            .all(|v| v.is_null() || v == &json!({}))
    {
        Some(names(joined))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Value {
        let p = "marty-passport-acceptance-base-abcdef";
        let services = SELECTED
            .iter()
            .chain(RUST)
            .chain(INFRA)
            .map(|n| (n.to_string(), json!({})))
            .collect::<Map<_, _>>();
        json!({
"project": p,
"model": {
"name": p,
"services": services,
"networks": {
"private": {
"internal": true,
"name": format!("{p}_private")},
"callback_signing": {
"internal": true,
"name": format!("{p}_callback_signing")},
"ingress": {
"internal": false,
"name": format!("{p}_ingress")}},
"volumes": {
"data": {
"name": format!("{p}_data")}}}})
    }
    #[test]
    fn numeric_external_resources_are_rejected_like_python_membership() {
        assert!(resources(&fixture()).is_ok());
        for value in [json!(true), json!("true"), json!(1), json!(1.0)] {
            let mut n = fixture();
            n["model"]["networks"]["private"]["external"] = value.clone();
            assert!(resources(&n).is_err());
            let mut v = fixture();
            v["model"]["volumes"]["data"]["external"] = value;
            assert!(resources(&v).is_err());
        }
    }
    #[test]
    fn networks_keep_all_members_and_existing_duplicate_behavior() {
        assert_eq!(joined_networks(&json!(["private", 123])), None);
        assert_eq!(joined_networks(&json!(["private", {}])), None);
        assert_eq!(
            joined_networks(&json!(["private", "private"])),
            Some(set(["private"]))
        );
    }
    #[test]
    fn service_host_admission_never_decodes_or_repairs_unsafe_authority() {
        assert_eq!(endpoint_host("http://GATEWAY:8000"), Some("gateway".into()));
        assert_eq!(
            endpoint_host("http://%67ateway:8000"),
            Some("%67ateway".into())
        );
        for url in [
            "https://[gateway]",
            "https://user[bad@gateway",
            "https://user\u{ff0f}name@gateway",
        ] {
            assert_eq!(endpoint_host(url), None);
        }
    }
}
