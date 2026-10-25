//! Beta simulator/physical deployment policy; mounted file reads remain in Python.
use super::*;
use crate::passport_model::contains_marker;
const PROFILE: &str = "docker-compose.profile.passport-native-beta.yml";
const RAW: &[&str] = &[
    "PASSPORT_TENANT_API_KEYS",
    "PHYSICAL_DOCUMENT_ARTIFACT_KEY",
    "ICAO_DOCUMENT_SIGNER_API_KEY",
    "PERSONALIZATION_BUREAU_WEBHOOK_SECRET",
];
fn pystr(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Null => "None".into(),
        _ => v.to_string(),
    }
}
fn flag(e: &Value, k: &str) -> bool {
    e.get(k)
        .is_some_and(|v| pystr(v).eq_ignore_ascii_case("true"))
}
pub(super) fn operator_credential(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        s.chars().count() >= 32
            && s.trim() == s
            && !pattern_matches(s, r"(?i)\A(change[-_]?me|replace[-_]?me)")
    })
}
fn beta_env(s: &Value) -> Result<Value, String> {
    match &s["environment"] {
        Value::Object(m) => Ok(json!(m)),
        Value::Array(a) if a.iter().all(Value::is_string) => Ok(Value::Object(
            a.iter()
                .filter_map(Value::as_str)
                .filter_map(|s| s.split_once('='))
                .map(|(k, v)| (k.to_owned(), json!(v)))
                .collect(),
        )),
        _ => Err("Invalid beta passport service environment".into()),
    }
}
fn envs(s: &Value) -> Result<Value, String> {
    let mut result = Map::new();
    for (n, v) in object(s, "Invalid beta passport Compose model")? {
        require(v.is_object(), "Invalid beta passport Compose model")?;
        if v.get("environment").is_some_and(|v| !v.is_null()) {
            result.insert(n.clone(), beta_env(v)?);
        }
    }
    Ok(Value::Object(result))
}
fn selected_envs(s: &Value) -> Result<Value, String> {
    for n in [
        "gateway",
        "flow",
        "issuance-native",
        "signing-keys",
        "passport-beta-bureau",
        "passport-callback-signer",
    ] {
        require(s.get(n).is_some(), "Invalid beta passport Compose model")?;
        beta_env(&s[n])?;
    }
    envs(s)
}
pub(super) fn selection(i: &Value) -> PolicyResult {
    let enabled = i["passport_enabled"] == true;
    let physical = i["physical_provider"] == true;
    if !i["prepared_services_image"].is_null() {
        require(enabled && !physical && i["prepared_services_image"].as_str().is_some_and(|s|pattern_matches(s,r"\Asha256:[0-9a-f]{64}\z")),"Prepared local passport image requires explicit native simulator selection and an immutable image ID")?;
    }
    if physical {
        require(
            enabled,
            "Beta physical provider requires native passport selection",
        )?;
        return Ok(json!("physical"));
    }
    let files = i["files"]
        .as_array()
        .ok_or("Invalid beta passport Compose model")?;
    require(
        files.iter().filter(|v| v.as_str() == Some(PROFILE)).count() == usize::from(enabled),
        "Beta passport profile selection is inconsistent",
    )?;
    Ok(json!(if enabled { "simulator" } else { "disabled" }))
}
fn raw_database_path(url: &str) -> Option<String> {
    let clean = url.replace(['\n', '\r', '\t'], "");
    let (_, rest) = clean.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some(rest[end..].split(['?', '#']).next()?.to_owned())
}
pub(super) fn simulator_before(i: &Value) -> PolicyResult {
    let s = &i["model"]["services"];
    for (n, k) in [
        ("gateway", "PASSPORT_NATIVE_GATEWAY_ENABLED"),
        ("flow", "PASSPORT_NATIVE_FLOW_ENABLED"),
        ("issuance-native", "PASSPORT_NATIVE_HTTP_ENABLED"),
    ] {
        let e = beta_env(&s[n])?;
        require(
            e.get(k)
                .map(pystr)
                .unwrap_or_else(|| "false".into())
                .eq_ignore_ascii_case(if i["passport_enabled"] == true {
                    "true"
                } else {
                    "false"
                }),
            "Beta passport owner selection is inconsistent",
        )?;
    }
    let e = envs(s)?;
    if i["passport_enabled"] != true {
        require(
            e.as_object().unwrap().values().all(|v| {
                v.get("SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY").is_none()
                    && v.get("SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE").is_none()
                    && !flag(v, "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED")
            }),
            "Beta CSCA ceremony selected without passport profile",
        )?;
        require(
            s.get("passport-beta-bureau").is_none() && s.get("passport-callback-signer").is_none(),
            "Beta passport callback services selected without profile",
        )?;
        return Ok(Value::Null);
    }
    let e = selected_envs(s)?;
    let (g, f, n, b, signing) = (
        &e["gateway"],
        &e["flow"],
        &e["issuance-native"],
        &e["passport-beta-bureau"],
        &e["signing-keys"],
    );
    require(
        signing["ENVIRONMENT"] == "beta",
        "Beta CSCA signing service must run with ENVIRONMENT=beta",
    )?;
    require(
        f["ISSUANCE_NATIVE_SERVICE_URL"] == "http://issuance-native:8005",
        "Beta passport Flow target is not native",
    )?;
    require(
        g["PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED"] == "false",
        "Beta simulator signed callback must target the native Gateway owner",
    )?;
    for owner in [g, f, n] {
        require(
            flag(owner, "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED"),
            "Beta passport internal handoff is incomplete",
        )?;
        require(
            !truthy(&owner["PASSPORT_TENANT_API_KEYS"])
                && !truthy(&owner["PASSPORT_TENANT_API_KEYS_FILE"]),
            "Beta passport tenant keyring is forbidden",
        )?;
    }
    let token = &n["PASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN"];
    require(
        n["ENVIRONMENT"] == "beta"
            && flag(n, "PASSPORT_BETA_RECONCILIATION_ENABLED")
            && operator_credential(token)
            && token != &n["GRPC_SERVICE_TOKEN"]
            && token != &n["SIGNING_KEYS_INTERNAL_API_KEY"]
            && s.as_object().unwrap().iter().all(|(name, service)| {
                name == "issuance-native" || !contains_marker(service, text(token))
            }),
        "Beta passport reconciliation operator binding is invalid",
    )?;
    require(
        [
            "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED",
            "PASSPORT_KMS_ARTIFACTS_ENABLED",
            "PASSPORT_KMS_CALLBACKS_ENABLED",
        ]
        .iter()
        .all(|k| flag(n, k)),
        "Beta passport KMS mode is incomplete",
    )?;
    require(
        n.get("PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED").is_none(),
        "Beta passport self-signed configuration is forbidden",
    )?;
    require(
        absent(
            n,
            &[
                "PERSONALIZATION_BUREAU_WEBHOOK_SECRET",
                "PERSONALIZATION_BUREAU_WEBHOOK_SECRET_FILE",
            ],
        ),
        "Beta passport local callback secret is forbidden",
    )?;
    require(
        absent(
            n,
            &[
                "ICAO_DOCUMENT_SIGNER_URL",
                "ICAO_DOCUMENT_SIGNER_API_KEY",
                "ICAO_DOCUMENT_SIGNER_API_KEY_FILE",
            ],
        ),
        "Beta passport remote signer is forbidden",
    )?;
    require(
        n["PERSONALIZATION_BUREAU_URL"] == "http://passport-beta-bureau:8020",
        "Beta passport bureau target is invalid",
    )?;
    require(
        RAW.iter()
            .all(|k| !truthy(&n[k]) && !truthy(&n[format!("{k}_FILE")])),
        "Beta passport raw key binding is forbidden",
    )?;
    require(
        !truthy(&n["PERSONALIZATION_BUREAU_API_KEY_FILE"]),
        "Beta passport bureau key file is forbidden",
    )?;
    let database = b["DATABASE_URL"].as_str();
    require(
        database.is_some_and(|db| {
            db.starts_with("postgresql://")
                && raw_database_path(db).as_deref() == Some("/marty")
                && n["DATABASE_URL"] == db
                && url::Url::parse(db).is_ok_and(|u| {
                    u.scheme() == "postgresql"
                        && u.host_str() == Some("postgres")
                        && u.port() == Some(5432)
                        && u.path() == "/marty"
                        && u.username() == "marty"
                        && u.password().is_some_and(|s| !s.is_empty())
                        && u.query().is_none_or(str::is_empty)
                        && u.fragment().is_none_or(str::is_empty)
                })
        }),
        "Beta passport database target is invalid",
    )?;
    let flag_key = "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED";
    require(
        e.as_object()
            .unwrap()
            .iter()
            .filter(|(_, v)| v.get(flag_key).is_some())
            .map(|(n, _)| n.as_str())
            .collect::<BTreeSet<_>>()
            == set(["signing-keys"])
            && flag(signing, flag_key),
        "Beta CSCA ceremony selection is invalid",
    )?;
    Ok(Value::Null)
}
fn readonly(s: &Value, source: &str, target: &str) -> bool {
    s["volumes"].as_array().into_iter().flatten().any(|v| {
        v.is_object() && v["source"] == source && v["target"] == target && v["read_only"] == true
    })
}
pub(super) fn simulator_after(i: &Value) -> PolicyResult {
    let m = &i["model"];
    let s = &m["services"];
    let e = selected_envs(s)?;
    let (g, f, n, b, signing, callback) = (
        &e["gateway"],
        &e["flow"],
        &e["issuance-native"],
        &e["passport-beta-bureau"],
        &e["signing-keys"],
        &e["passport-callback-signer"],
    );
    let signer = &s["passport-callback-signer"];
    let bureau = &s["passport-beta-bureau"];
    let key = &b["SIGNING_KEYS_INTERNAL_API_KEY"];
    let token = &b["GRPC_SERVICE_TOKEN"];
    require(
        b["SERVICE_NAME"] == "passport_beta_bureau"
            && b["ENVIRONMENT"] == "beta"
            && flag(b, "PASSPORT_BETA_BUREAU_ENABLED")
            && truthy(token)
            && n["PERSONALIZATION_BUREAU_API_KEY"] == *token
            && [g, f, n].iter().all(|v| v["GRPC_SERVICE_TOKEN"] == *token)
            && truthy(key)
            && [n, g, signing]
                .iter()
                .all(|v| v["SIGNING_KEYS_INTERNAL_API_KEY"] == *key)
            && b["SIGNING_KEYS_INTERNAL_URL"]
                == "http://passport-callback-signer:8018/internal/documents"
            && b["PASSPORT_BETA_BUREAU_GATEWAY_CALLBACK_ENABLED"] == "true"
            && b["PASSPORT_BUREAU_CALLBACK_URL"]
                == "http://gateway:8000/v1/passport/webhooks/personalization",
        "Beta passport bureau identity or route is invalid",
    )?;
    require(
        callback["SERVICE_NAME"] == "passport_callback_signer"
            && callback["ENVIRONMENT"] == "beta"
            && flag(callback, "PASSPORT_CALLBACK_SIGNER_ENABLED")
            && pystr(&callback["SIGNING_KEYS_SERVICE_PORT"]) == "8018"
            && callback["SIGNING_KEYS_INTERNAL_API_KEY"] == *key
            && env_matches(
                callback,
                &json!({
"BAO_ADDR": "https://openbao:8200",
"BAO_CACERT": "/bao/public-ca/ca.crt",
"BAO_TOKEN_FILE": "/bao/passport-callback/token"}),
            )
            && pystr(&callback["PRESERVE_BAO_TOKEN_FILE"]) == "1"
            && [
                "BAO_TOKEN",
                "OPENBAO_SERVICE_TOKEN",
                "OPENBAO_SERVICE_TOKEN_FILE",
            ]
            .iter()
            .all(|k| !truthy(&callback[k]))
            && readonly(signer, "openbao_public_ca", "/bao/public-ca")
            && readonly(
                signer,
                "openbao_passport_callback",
                "/bao/passport-callback",
            )
            && items(signer, "volumes")?.len() == 2,
        "Beta callback signer configuration is invalid",
    )?;
    require(
        s.as_object().unwrap().iter().all(|(name, v)| {
            ["openbao-init", "passport-callback-signer"].contains(&name.as_str())
                || !v["volumes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|m| m.is_object() && m["source"] == "openbao_passport_callback")
        }),
        "Beta callback token is mounted outside its owner",
    )?;
    require(
        if i["prepared_services_image"].is_null() {
            bureau["image"].as_str().is_some_and(|s| {
                pattern_matches(
                    s,
                    r"\Aghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}\z",
                )
            })
        } else {
            bureau["image"] == i["prepared_services_image"]
        },
        "Beta passport bureau image must be immutable",
    )?;
    require(
        signer["image"] == bureau["image"],
        "Beta callback signer image must be immutable",
    )?;
    require(
        [
            "ports",
            "secrets",
            "volumes",
            "build",
            "entrypoint",
            "command",
            "privileged",
            "network_mode",
        ]
        .iter()
        .all(|k| !truthy(&bureau[k])),
        "Beta passport bureau exposure is forbidden",
    )?;
    require(
        [
            "ports",
            "secrets",
            "build",
            "entrypoint",
            "command",
            "privileged",
            "network_mode",
        ]
        .iter()
        .all(|k| !truthy(&signer[k])),
        "Beta callback signer exposure is forbidden",
    )?;
    require(
        exact(
            &bureau["networks"],
            &["marty-network", "passport-callback-signing"],
        ),
        "Beta passport bureau network is invalid",
    )?;
    require(
        m["networks"]["passport-callback-signing"]["internal"] == true,
        "Beta callback signer network is not internal",
    )?;
    require(
        s.as_object()
            .unwrap()
            .iter()
            .filter(|(_, v)| {
                v["networks"].get("passport-callback-signing").is_some()
                    || v["networks"]
                        .as_array()
                        .is_some_and(|v| v.contains(&json!("passport-callback-signing")))
            })
            .map(|(n, _)| n.as_str())
            .collect::<BTreeSet<_>>()
            == set([
                "openbao",
                "passport-beta-bureau",
                "passport-callback-signer",
            ]),
        "Beta callback signer network membership is invalid",
    )?;
    let joined = &signer["networks"];
    let signer_networks = if joined.is_object() {
        names(joined)
    } else {
        joined
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect()
    };
    require(
        signer_networks == set(["passport-callback-signing"]),
        "Beta callback signer network is invalid",
    )?;
    let forbidden = set([
        "passport_tenant_api_keys",
        "physical_document_artifact_key",
        "icao_document_signer_api_key",
        "personalization_bureau_api_key",
        "personalization_bureau_webhook_secret",
    ]);
    require(
        names(&m["secrets"]).is_disjoint(&forbidden)
            && [
                "gateway",
                "flow",
                "issuance-native",
                "passport-beta-bureau",
                "passport-callback-signer",
            ]
            .iter()
            .all(|n| refs(&s[n]).is_disjoint(&forbidden)),
        "Legacy passport secret mounts are forbidden",
    )?;
    Ok(Value::Null)
}

const PHYSICAL_SECRETS: &[&str] = &[
    "passport_physical_provider_api_key",
    "passport_callback_signer_api_key",
    "passport_callback_signer_bao_token",
];
fn physical_envs(s: &Value) -> Result<Value, String> {
    for n in [
        "gateway",
        "flow",
        "issuance-native",
        "signing-keys",
        "passport-callback-signer-supported",
        "passport-provider-ingress",
    ] {
        require(
            s.get(n).is_some(),
            "Beta physical provider services are incomplete",
        )?;
        beta_env(&s[n])?;
    }
    envs(s)
}
fn sources(s: &Value) -> Result<BTreeSet<&str>, String> {
    let error = "Beta physical provider secret mounts are invalid";
    let entries = items(s, "secrets").map_err(|_| error.to_owned())?;
    entries
        .iter()
        .map(|e| {
            e.as_str()
                .or_else(|| e["source"].as_str())
                .ok_or_else(|| error.to_owned())
        })
        .collect()
}
pub(super) fn physical_layout(i: &Value) -> PolicyResult {
    let files = i["files"]
        .as_array()
        .ok_or("Beta physical provider profiles are incomplete or mixed with simulator")?;
    let selected = files
        .iter()
        .filter_map(Value::as_str)
        .filter(|f| {
            [
                PROFILE,
                "docker-compose.profile.passport-native-physical-beta.yml",
                "docker-compose.profile.passport-provider-base.yml",
            ]
            .contains(f)
        })
        .collect::<Vec<_>>();
    require(
        selected.len() == 2
            && set(selected)
                == set([
                    "docker-compose.profile.passport-native-physical-beta.yml",
                    "docker-compose.profile.passport-provider-base.yml",
                ]),
        "Beta physical provider profiles are incomplete or mixed with simulator",
    )?;
    let m = &i["model"];
    let s = &m["services"];
    require(
        m["name"] == "elevenid-beta",
        "Beta physical provider Compose project is invalid",
    )?;
    require(
        s.is_object()
            && s.get("passport-beta-bureau").is_none()
            && s.get("passport-callback-signer").is_none(),
        "Beta physical provider must not start the simulator",
    )?;
    physical_envs(s)?;
    require(
        m["networks"]
            == json!({
"marty-network": {
"ipam": {
},
"name": "elevenid-beta-network"},
"passport-provider-signing": {
"internal": true,
"ipam": {
},
"name": "elevenid-beta_passport-provider-signing"}}),
        "Beta physical provider networks are not isolated",
    )?;
    require(
        m["secrets"]
            .get("passport_provider_webhook_secret")
            .is_none(),
        "Local provider webhook secret is forbidden",
    )?;
    Ok(Value::Null)
}
pub(super) fn physical_services(i: &Value) -> PolicyResult {
    let m = &i["model"];
    let s = object(
        &m["services"],
        "Beta physical provider services are incomplete",
    )?;
    let volumes = m.get("volumes").cloned().unwrap_or_else(|| json!({}));
    for (name, v) in object(&volumes, "Beta physical provider stack volumes are invalid")? {
        require(
            *v == json!({
"name": format!("elevenid-beta_{name}")}),
            "Beta physical provider named volume escaped isolation",
        )?;
    }
    require(
        m.get("configs").is_none_or(Value::is_object),
        "Beta physical provider stack configs are invalid",
    )?;
    let protected = i["protected_values"]
        .as_array()
        .ok_or("Beta physical provider secret leaked into rendered service")?;
    for (name, service) in s {
        let networks = service
            .get("networks")
            .cloned()
            .unwrap_or_else(|| json!({}));
        require(
            networks.is_object() && names(&networks).is_subset(&names(&m["networks"])),
            "Beta physical provider service network is invalid",
        )?;
        let bridge = name == "issuance-canvas-localhost-bridge"
            && service["network_mode"] == "service:issuance"
            && names(&m["services"]["issuance"]["networks"]) == set(["marty-network"]);
        let envoy = name == "envoy-issuance-bridge"
            && service["network_mode"] == "service:envoy"
            && names(&m["services"]["envoy"]["networks"]) == set(["marty-network"]);
        let init =
            name == "openbao-tls-init" && service["network_mode"] == "none" && !truthy(&networks);
        require(
            (!truthy(&service["network_mode"]) || bridge || envoy || init)
                && !truthy(&service["volumes_from"]),
            "Beta physical provider service inherited network or volumes",
        )?;
        if networks.get("passport-provider-signing").is_some() {
            require(
                [
                    "passport-callback-signer-supported",
                    "passport-provider-ingress",
                    "openbao",
                ]
                .contains(&name.as_str()),
                "Beta physical signer network has an unauthorized member",
            )?;
        }
        let expected = match name.as_str() {
            "issuance-native" => set(["passport_physical_provider_api_key"]),
            "passport-callback-signer-supported" => set([
                "passport_callback_signer_api_key",
                "passport_callback_signer_bao_token",
            ]),
            "passport-provider-ingress" => set(["passport_callback_signer_api_key"]),
            _ => set([]),
        };
        require(
            sources(service)?
                .intersection(&set(PHYSICAL_SECRETS.iter().copied()))
                .copied()
                .collect::<BTreeSet<_>>()
                == expected,
            "Beta physical secret has an unauthorized consumer",
        )?;
        require(
            protected
                .iter()
                .all(|v| v.as_str().is_some_and(|v| !contains_marker(service, v))),
            "Beta physical provider secret leaked into rendered service",
        )?;
    }
    Ok(Value::Null)
}
pub(super) fn physical_before_registry(i: &Value) -> PolicyResult {
    let m = &i["model"];
    let s = &m["services"];
    let e = physical_envs(s)?;
    let (g, f, n, signing, signer, ingress) = (
        &e["gateway"],
        &e["flow"],
        &e["issuance-native"],
        &e["signing-keys"],
        &e["passport-callback-signer-supported"],
        &e["passport-provider-ingress"],
    );
    for name in [
        "gateway",
        "flow",
        "issuance-native",
        "signing-keys",
        "passport-callback-signer-supported",
        "passport-provider-ingress",
        "openbao",
    ] {
        let expected = match name {
            "passport-callback-signer-supported" => set(["passport-provider-signing"]),
            "passport-provider-ingress" | "openbao" => {
                set(["marty-network", "passport-provider-signing"])
            }
            _ => set(["marty-network"]),
        };
        require(
            s[name]["networks"].is_object() && names(&s[name]["networks"]) == expected,
            "Beta physical provider service network membership is invalid",
        )?;
    }
    for (name, label, pairs) in [
        (
            "gateway",
            "gateway",
            vec![
                ("openbao_public_ca", "/bao/public-ca"),
                ("openbao_gateway_grant", "/bao/gateway-grant"),
            ],
        ),
        (
            "flow",
            "flow",
            vec![
                ("openbao_public_ca", "/bao/public-ca"),
                ("openbao_flow_grant", "/bao/flow-grant"),
            ],
        ),
        (
            "issuance-native",
            "issuance-native",
            vec![
                ("openbao_public_ca", "/bao/public-ca"),
                (
                    "openbao_didcomm_issuance_token",
                    "/bao/didcomm-issuance-token",
                ),
                (
                    "openbao_issuance_credential_grant",
                    "/bao/issuance-credential-grant",
                ),
                (
                    "openbao_issuance_canvas_grant",
                    "/bao/issuance-canvas-grant",
                ),
                (
                    "openbao_issuance_readiness_grant",
                    "/bao/issuance-readiness-grant",
                ),
                (
                    "openbao_issuance_passport_grant",
                    "/bao/issuance-passport-grant",
                ),
            ],
        ),
        (
            "signing-keys",
            "signing-keys",
            vec![
                ("openbao_public_ca", "/bao/public-ca"),
                ("openbao_signing_keys_token", "/bao/signing-keys-token"),
                ("openbao_verify_grant", "/bao/verify-grant"),
            ],
        ),
        (
            "passport-callback-signer-supported",
            "callback-signer",
            vec![],
        ),
        ("passport-provider-ingress", "provider-ingress", vec![]),
    ] {
        let service = &s[name];
        let expected = pairs
            .into_iter()
            .map(|(source, target)| {
                json!({
                "type": "volume",
                "source": source,
                "target": target,
                "read_only": true,
                "volume": {
                }})
            })
            .collect::<Vec<_>>();
        require(
            items(service, "volumes")? == expected,
            format!("Beta physical provider service escaped isolation: {label}"),
        )?;
        require(
            [
                "configs",
                "privileged",
                "network_mode",
                "container_name",
                "volumes_from",
                "devices",
                "extra_hosts",
                "pid",
                "ipc",
                "cgroup_parent",
            ]
            .iter()
            .all(|k| !truthy(&service[k])),
            "Beta physical provider service escaped isolation",
        )?;
        let empty = json!({});
        let labels = service.get("labels").unwrap_or(&empty);
        require(
            labels.is_object()
                && labels
                    .as_object()
                    .unwrap()
                    .keys()
                    .all(|k| !k.starts_with("com.docker.compose.")),
            "Beta physical provider callback service labels are invalid",
        )?;
    }
    for (name, expected, error) in [
        (
            "gateway",
            vec![
                "workload_identity_ca_cert",
                "gateway_workload_client_cert",
                "gateway_tls_kms_token",
                "openbao_tls_ca_cert",
            ],
            "Beta physical provider Gateway CA mounts are invalid",
        ),
        (
            "signing-keys",
            vec![
                "dev_integration_secret_server_cert",
                "dev_integration_secret_ca",
                "openbao_tls_ca_cert",
                "signing_keys_tls_kms_token",
            ],
            "Beta physical provider Signing Keys TLS mounts are invalid",
        ),
        (
            "flow",
            vec![
                "flow_workload_client_cert",
                "flow_client_tls_kms_token",
                "flow_workload_server_cert",
                "flow_server_tls_kms_token",
                "openbao_tls_ca_cert",
                "workload_identity_ca_cert",
            ],
            "Beta physical provider flow workload secret mounts are invalid",
        ),
        (
            "issuance-native",
            vec![
                "passport_physical_provider_api_key",
                "dev_integration_secret_ca",
                "workload_identity_ca_cert",
                "issuance_workload_server_cert",
                "issuance_tls_kms_token",
                "openbao_tls_ca_cert",
            ],
            "Beta physical provider native secret mounts are invalid",
        ),
    ] {
        require(sources(&s[name])? == set(expected), error)?;
    }
    for name in [
        "passport-callback-signer-supported",
        "passport-provider-ingress",
    ] {
        require(
            ["ports", "build", "entrypoint", "command"]
                .iter()
                .all(|k| !truthy(&s[name][k])),
            "Beta physical provider callback service escaped isolation",
        )?;
    }
    for (v, selector) in [
        (g, "PASSPORT_NATIVE_GATEWAY_ENABLED"),
        (f, "PASSPORT_NATIVE_FLOW_ENABLED"),
        (n, "PASSPORT_NATIVE_HTTP_ENABLED"),
    ] {
        require(
            flag(v, selector)
                && flag(v, "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED")
                && !truthy(&v["PASSPORT_TENANT_API_KEYS"])
                && !truthy(&v["PASSPORT_TENANT_API_KEYS_FILE"]),
            "Beta physical provider Rust owner or internal auth is incomplete",
        )?;
    }
    require(
        f["ISSUANCE_NATIVE_SERVICE_URL"] == "http://issuance-native:8005"
            && flag(g, "PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED")
            && g["PASSPORT_PROVIDER_INGRESS_SERVICE_URL"]
                == "http://passport-provider-ingress:8021",
        "Beta physical provider callback ingress route is invalid",
    )?;
    require(
        [
            "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED",
            "PASSPORT_KMS_ARTIFACTS_ENABLED",
            "PASSPORT_KMS_CALLBACKS_ENABLED",
        ]
        .iter()
        .all(|k| flag(n, k))
            && absent(
                n,
                &[
                    "PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED",
                    "ICAO_DOCUMENT_SIGNER_URL",
                    "ICAO_DOCUMENT_SIGNER_API_KEY",
                    "ICAO_DOCUMENT_SIGNER_API_KEY_FILE",
                ],
            ),
        "Beta physical provider KMS mode is incomplete",
    )?;
    require(
        RAW.iter()
            .all(|k| !truthy(&n[k]) && !truthy(&n[format!("{k}_FILE")])),
        "Beta physical provider raw key binding is forbidden",
    )?;
    let endpoint = text(&n["PERSONALIZATION_BUREAU_URL"]);
    let parsed =
        url::Url::parse(endpoint).map_err(|_| "Beta physical provider endpoint is invalid")?;
    let host = parsed.host_str().unwrap_or("");
    require(
        parsed.scheme() == "https"
            && host.contains('.')
            && parsed.username().is_empty()
            && parsed.password().is_none_or(str::is_empty)
            && parsed.query().is_none_or(str::is_empty)
            && parsed.fragment().is_none_or(str::is_empty)
            && ![".test", ".example", ".invalid", ".localhost"]
                .iter()
                .any(|s| host.ends_with(s))
            && !["localhost", "passport-beta-bureau", "127.0.0.1"].contains(&host),
        "Beta physical provider endpoint must be an external HTTPS identity",
    )?;
    require(
        matches!(parsed.host(), Some(url::Host::Domain(_))),
        "Beta physical provider endpoint must use DNS",
    )?;
    let profile = text(&n["PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID"]);
    require(
        pattern_matches(profile, r"\A[A-Za-z0-9][A-Za-z0-9._-]{7,127}\z")
            && !pattern_matches(profile, r"(?i)simulator|mock|placeholder|beta-bureau")
            && ingress["PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID"] == profile,
        "Beta physical provider profile identity is invalid",
    )?;
    let _ = (signing, signer);
    Ok(Value::Null)
}
pub(super) fn physical_after_registry(i: &Value) -> PolicyResult {
    let s = &i["model"]["services"];
    let e = physical_envs(s)?;
    let (g, f, n, signing, signer, ingress) = (
        &e["gateway"],
        &e["flow"],
        &e["issuance-native"],
        &e["signing-keys"],
        &e["passport-callback-signer-supported"],
        &e["passport-provider-ingress"],
    );
    let registry = &i["provider_registry"];
    require(
        env_matches(
            registry,
            &json!({
"schema": "marty.passport-beta-physical-provider-allowlist/v1",
"status": "approved",
"providers": [
{
"endpoint": n[
"PERSONALIZATION_BUREAU_URL"],
"profile_id": n[
"PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID"],
"provider_kind": "physical",
"environment": "beta"}]}),
        ),
        "Beta physical provider endpoint/profile lacks governed approval",
    )?;
    require(
        (n["PERSONALIZATION_BUREAU_API_KEY"].is_null()
            || n["PERSONALIZATION_BUREAU_API_KEY"] == "")
            && n["PERSONALIZATION_BUREAU_API_KEY_FILE"]
                == "/run/secrets/passport_physical_provider_api_key"
            && absent(
                n,
                &[
                    "PERSONALIZATION_BUREAU_WEBHOOK_SECRET",
                    "PERSONALIZATION_BUREAU_WEBHOOK_SECRET_FILE",
                ],
            )
            && sources(&s["issuance-native"])?.contains("passport_physical_provider_api_key"),
        "Beta physical provider API credential must be file-backed",
    )?;
    let forbidden = &[
        "PASSPORT_PROVIDER_WEBHOOK_SECRET_FILE",
        "PASSPORT_PROVIDER_WEBHOOK_SECRET",
        "PASSPORT_PROVIDER_HMAC_SOURCE_FILE",
    ];
    require(
        env_matches(
            signer,
            &json!({
"SERVICE_NAME": "passport_callback_signer_supported",
"ENVIRONMENT": "production",
"PASSPORT_CALLBACK_SIGNER_API_KEY_FILE": "/run/secrets/passport_callback_signer_api_key",
"PASSPORT_CALLBACK_SIGNER_BAO_TOKEN_FILE": "/run/secrets/passport_callback_signer_bao_token",
"BAO_ADDR": "https://openbao:8200",
"BAO_CACERT": "/run/secrets/openbao_tls_ca_cert"}),
        ) && flag(signer, "PASSPORT_SUPPORTED_CALLBACK_SIGNER_ENABLED")
            && [
                "SIGNING_KEYS_INTERNAL_API_KEY",
                "SIGNING_KEYS_INTERNAL_API_KEY_FILE",
                "BAO_TOKEN",
                "BAO_TOKEN_FILE",
                "OPENBAO_SERVICE_TOKEN",
                "OPENBAO_SERVICE_TOKEN_FILE",
                "PASSPORT_CALLBACK_SIGNER_ENABLED",
            ]
            .iter()
            .all(|k| !truthy(&signer[k]))
            && absent(signer, forbidden)
            && sources(&s["passport-callback-signer-supported"])?
                == set([
                    "passport_callback_signer_api_key",
                    "passport_callback_signer_bao_token",
                    "openbao_tls_ca_cert",
                ]),
        "Beta physical provider signer is not isolated",
    )?;
    let version = pystr(&ingress["PASSPORT_PROVIDER_HMAC_KEY_VERSION"]);
    require(
        env_matches(
            ingress,
            &json!({
"SERVICE_NAME": "passport_provider_ingress",
"PASSPORT_PROVIDER_SIGNER_URL": "http://passport-callback-signer-supported:8018/internal/documents",
"PASSPORT_PROVIDER_NATIVE_CALLBACK_URL": "http://issuance-native:8005/v1/passport/webhooks/personalization",
"PASSPORT_PROVIDER_SIGNER_API_KEY_FILE": "/run/secrets/passport_callback_signer_api_key"}),
        ) && flag(ingress, "PASSPORT_PROVIDER_INGRESS_ENABLED")
            && pattern_matches(&version, r"\A[1-9][0-9]{0,9}\z")
            && version.parse::<u32>().is_ok()
            && absent(ingress, forbidden)
            && sources(&s["passport-provider-ingress"])?
                == set(["passport_callback_signer_api_key", "marty_db_password"]),
        "Beta physical provider callback ingress is invalid",
    )?;
    require(
        signing["ENVIRONMENT"] == "beta"
            && flag(signing, "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED")
            && [
                "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY",
                "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY",
            ]
            .iter()
            .all(|k| operator_credential(&g[k]) && g[k] == signing[k])
            && g["SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY"] != g["SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY"],
        "Beta physical provider operator credentials are invalid",
    )?;
    require(
        g["GRPC_SERVICE_TOKEN"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
            && [f, n]
                .iter()
                .all(|v| v["GRPC_SERVICE_TOKEN"] == g["GRPC_SERVICE_TOKEN"])
            && signing["SIGNING_KEYS_INTERNAL_API_KEY"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
            && [g, n].iter().all(|v| {
                v["SIGNING_KEYS_INTERNAL_API_KEY"] == signing["SIGNING_KEYS_INTERNAL_API_KEY"]
            }),
        "Beta physical provider internal authentication parity is invalid",
    )?;
    require(
        e.as_object()
            .unwrap()
            .iter()
            .filter(|(_, v)| v.get("SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED").is_some())
            .map(|(n, _)| n.as_str())
            .collect::<BTreeSet<_>>()
            == set(["signing-keys"]),
        "Beta physical provider CSCA ceremony holder is invalid",
    )?;
    for (purpose, key) in [
        ("DSC", "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY"),
        ("CSCA", "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY"),
    ] {
        let credential = text(&g[key]);
        let file = format!("{key}_FILE");
        require(
            e.as_object()
                .unwrap()
                .iter()
                .filter(|(_, v)| truthy(&v[key]))
                .map(|(n, _)| n.as_str())
                .collect::<BTreeSet<_>>()
                == set(["gateway", "signing-keys"])
                && g[key] != signing["SIGNING_KEYS_INTERNAL_API_KEY"]
                && e.as_object().unwrap().values().all(|v| !truthy(&v[&file]))
                && s.as_object().unwrap().iter().all(|(name, service)| {
                    crate::passport_model::service_reuses_credential(&json!({
"name": name,
"service": service,
"credential": credential,
"dedicated": key}))
                    .is_ok_and(|v| v == false)
                }),
            format!("Beta physical provider {purpose} operator credential isolation is invalid"),
        )?;
    }
    require(
        [
            "passport-callback-signer-supported",
            "passport-provider-ingress",
        ]
        .iter()
        .all(|n| {
            [
                "ports",
                "build",
                "entrypoint",
                "command",
                "privileged",
                "network_mode",
            ]
            .iter()
            .all(|k| !truthy(&s[n][k]))
        }),
        "Beta physical provider callback services are exposed",
    )?;
    require(
        s["passport-callback-signer-supported"]["image"]
            .as_str()
            .is_some_and(|s| {
                pattern_matches(
                    s,
                    r"\Aghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}\z",
                )
            })
            && s["passport-provider-ingress"]["image"]
                == s["passport-callback-signer-supported"]["image"],
        "Beta physical provider callback image is not immutable",
    )?;
    Ok(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn operator_placeholders_are_refused_with_case_and_separator_variations() {
        for prefix in [
            "change-me",
            "CHANGE_ME",
            "ChangeMe",
            "replace-me",
            "REPLACE_ME",
            "ReplaceMe",
        ] {
            assert!(!operator_credential(&json!(format!(
                "{prefix}{}",
                "x".repeat(40)
            ))));
        }
        assert!(operator_credential(&json!(
            "synthetic-isolated-operator-credential-000001"
        )));
    }
}
