//! Closed, lossless Kubernetes owner composition. No network or secret reads.
//! Model/image-reference validation is not release authentication or acceptance.
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_BYTES: usize = 1024 * 1024;
pub const MAX_SETTINGS_BYTES: usize = 256 * 1024;
pub const REFUSAL: &str = "Kubernetes native issuance configuration refused.";
pub const NATIVE_URL: &str = "http://issuance-native:8005";
pub type Result<T> = std::result::Result<T, &'static str>;
pub type Environment = BTreeMap<String, String>;
pub const OPTIONAL_SETTINGS: &[&str] = &[
    "ISSUANCE_OFFER_TTL_MINUTES",
    "TOKEN_RATE_LIMIT",
    "TOKEN_RATE_WINDOW",
    "ISSUER_DISPLAY_NAME",
    "CORS_ALLOWED_ORIGINS",
    "VCDM_RELATED_RESOURCE_URLS",
    "VCDM_RELATED_RESOURCE_MAX_BYTES",
    "VCDM_RELATED_RESOURCE_TIMEOUT_SECONDS",
    "DIDCOMM_UNIVERSAL_RESOLVER_URL",
    "DIDCOMM_DID_WEB_INTERNAL_BASE_URL",
    "DIDCOMM_ALLOW_PRIVATE_IPS",
    "CANVAS_LTI_EXPERIENCE_CODE_TTL_SECONDS",
    "CANVAS_LTI_EXPERIENCE_SESSION_TTL_MINUTES",
    "CANVAS_LTI_STATE_TTL_MINUTES",
    "CANVAS_LTI_JWKS_TTL_MINUTES",
    "CANVAS_LTI_DEEP_LINKING_ISSUER",
    "CANVAS_ALLOW_PRIVATE_BASE_URLS",
    "CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS",
    "CANVAS_CREDENTIALS_SIGNATURE_TOLERANCE_SECONDS",
    "CANVAS_CREDENTIALS_PUBLISH_URL",
    "CANVAS_CREDENTIALS_STATUS_SYNC_URL",
    "CANVAS_CREDENTIALS_API_ORIGIN_ALLOWLIST",
    "CANVAS_CREDENTIALS_BASE_URL",
    "CANVAS_CREDENTIALS_VALIDATE_URL_TEMPLATE",
    "CANVAS_CREDENTIALS_REVOKE_URL_TEMPLATE",
    "CANVAS_CREDENTIALS_PUBLISH_TIMEOUT_SECONDS",
    "CANVAS_CREDENTIALS_STATUS_SYNC_TIMEOUT_SECONDS",
];
pub const NATIVE_SETTINGS: &[&str] = &[
    "MARTY_RELEASE_VERSION",
    "MARTY_UI_SHA",
    "ISSUANCE_NATIVE_RUST_LOG",
];
pub const INHERITED_SETTINGS: &[&str] = &[
    "ENVIRONMENT",
    "UI_BASE_URL",
    "CREDENTIAL_TEMPLATE_SERVICE_URL",
    "REVOCATION_PROFILE_SERVICE_URL",
    "UNIVERSAL_RESOLVER_URL",
    "CANVAS_LTI_EXPERIENCE_BASE_URL",
    "CANVAS_OAUTH_COMPLETION_REDIRECT_URL",
    "CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID",
    "CANVAS_LTI_TOOL_ISSUER_DID",
    "CANVAS_PORTABLE_INTEGRATION_ENABLED",
    "CANVAS_PILOT_ORGANIZATION_IDS",
    "CANVAS_LEGACY_EVENT_INGEST_ENABLED",
    "CANVAS_PRIVATE_ORIGIN_ALLOWLIST",
    "CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST",
    "CANVAS_BINDING_READINESS_MAX_AGE_SECONDS",
    "CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS",
    "CANVAS_CREDENTIALS_PROVIDER",
    "CANVAS_CREDENTIALS_API_BASE_URL",
    "CANVAS_CREDENTIALS_ISSUER_ID",
    "CANVAS_CREDENTIALS_BADGECLASS_ID",
    "CANVAS_CREDENTIALS_ASSERTION_SCOPE",
];
pub const SECRET_SETTINGS: &[&str] = &[
    "DATABASE_URL",
    "ISSUANCE_API_KEY",
    "TOKEN_HMAC_KEY",
    "INTEGRATION_SECRET_MASTER_KEY",
    "SIGNING_KEYS_INTERNAL_API_KEY",
    "GRPC_SERVICE_TOKEN",
    "CANVAS_CREDENTIALS_SHARED_SECRET",
];
pub const SHARED_BINDINGS: &[&str] = &[
    "CANVAS_CREDENTIALS_API_TOKEN",
    "ISSUER_BASE_URL",
    "ORG_GRPC_TARGET",
    "CT_GRPC_TARGET",
    "RP_GRPC_TARGET",
    "SIGNING_KEYS_INTERNAL_URL",
];
const MOUNTS: [(&str, &str, &str, &str, &str); 2] = [
    (
        "K8S_DIDCOMM_POLICY_SECRET",
        "didcomm-policy",
        "policy.json",
        "/run/marty-didcomm-policy",
        "DIDCOMM_ENCRYPTION_POLICY_FILE",
    ),
    (
        "K8S_DIDCOMM_CA_SECRET",
        "didcomm-ca",
        "ca.pem",
        "/run/marty-didcomm-ca",
        "DIDCOMM_TLS_CA_FILE",
    ),
];

fn require(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(REFUSAL)
    }
}

pub fn selected(values: &Environment) -> Result<bool> {
    match values
        .get("K8S_ISSUANCE_NATIVE_ENABLED")
        .map(String::as_str)
        .unwrap_or("false")
    {
        "false" => Ok(false),
        "true" => Ok(true),
        _ => Err(REFUSAL),
    }
}

/// Read only declared non-secret selectors/settings; unrelated environment,
/// including non-Unicode operator variables, is never enumerated or captured.
pub fn capture_environment(
    mut get: impl FnMut(&str) -> Option<std::ffi::OsString>,
) -> Result<Environment> {
    let mut values = Environment::new();
    if let Some(value) = get("K8S_ISSUANCE_NATIVE_ENABLED") {
        values.insert(
            "K8S_ISSUANCE_NATIVE_ENABLED".into(),
            value.into_string().map_err(|_| REFUSAL)?,
        );
    }
    if !selected(&values)? {
        return Ok(values);
    }
    let names = OPTIONAL_SETTINGS
        .iter()
        .copied()
        .chain(NATIVE_SETTINGS.iter().copied())
        .chain([
            "MARTY_SERVICES_IMAGE",
            "K8S_DIDCOMM_POLICY_SECRET",
            "K8S_DIDCOMM_CA_SECRET",
        ]);
    let mut size = 0usize;
    for name in names {
        if let Some(value) = get(name) {
            let value = value.into_string().map_err(|_| REFUSAL)?;
            size = size.checked_add(value.len()).ok_or(REFUSAL)?;
            require(size <= MAX_SETTINGS_BYTES && value.len() <= 65536 && !value.contains('\0'))?;
            values.insert(name.into(), value);
        }
    }
    Ok(values)
}

fn component(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let start = index;
        while index < bytes.len()
            && (bytes[index].is_ascii_lowercase() || bytes[index].is_ascii_digit())
        {
            index += 1;
        }
        if index == start {
            return false;
        }
        if index == bytes.len() {
            return true;
        }
        match bytes[index] {
            b'.' => index += 1,
            b'_' => {
                index += 1;
                if bytes.get(index) == Some(&b'_') {
                    index += 1;
                }
            }
            b'-' => {
                while bytes.get(index) == Some(&b'-') {
                    index += 1;
                }
            }
            _ => return false,
        }
        if index == bytes.len() {
            return false;
        }
    }
    false
}

/// Canonical GHCR/services/digest subset of the official formatter. This NEW
/// selector intentionally rejects noncanonical trailing slashes, uppercase or
/// malformed repository segments the older formatter did not reject.
/// Never registry availability or authenticated release evidence.
pub fn services_image(value: &str) -> Result<&str> {
    require(value.len() <= 4096)?;
    let (uri, digest) = value.split_once('@').ok_or(REFUSAL)?;
    let path = uri.strip_prefix("ghcr.io/").ok_or(REFUSAL)?;
    let segments: Vec<_> = path.split('/').collect();
    require(
        segments.len() >= 2
            && segments.last() == Some(&"services")
            && segments.iter().all(|s| component(s)),
    )?;
    let hex = digest.strip_prefix("sha256:").ok_or(REFUSAL)?;
    require(
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
    )?;
    Ok(value)
}

fn secret_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .split('.')
            .all(|label| label.len() <= 63 && component(label) && !label.contains('_'))
}

pub fn configuration(values: &Environment) -> Result<Value> {
    let mut result = Map::new();
    for &name in OPTIONAL_SETTINGS {
        if let Some(value) = values.get(name) {
            require(value.len() <= 65536 && !value.contains('\0'))?;
            result.insert(name.into(), json!(value));
        }
    }
    let mut size = 0usize;
    for name in OPTIONAL_SETTINGS.iter().chain(NATIVE_SETTINGS) {
        if let Some(value) = values.get(*name) {
            require(value.len() <= 65536 && !value.contains('\0'))?;
            size = size.checked_add(value.len()).ok_or(REFUSAL)?;
            require(size <= MAX_SETTINGS_BYTES)?;
        }
    }
    for (name, ..) in MOUNTS {
        if let Some(value) = values.get(name).filter(|v| !v.is_empty()) {
            require(secret_name(value))?;
        }
    }
    require(serde_json::to_vec(&result).map_err(|_| REFUSAL)?.len() <= MAX_SETTINGS_BYTES)?;
    Ok(Value::Object(result))
}

/// serde_yaml::Value rejects duplicate mapping keys before conversion to JSON.
pub fn documents(bytes: &[u8]) -> Result<Vec<Value>> {
    require(bytes.len() <= MAX_BYTES)?;
    let mut result = Vec::new();
    for document in serde_yaml::Deserializer::from_slice(bytes) {
        let value = serde_yaml::Value::deserialize(document).map_err(|_| REFUSAL)?;
        if value.is_null() {
            continue;
        }
        result.push(serde_json::to_value(value).map_err(|_| REFUSAL)?);
    }
    require(!result.is_empty())?;
    let mut identities = BTreeSet::new();
    for value in &result {
        let kind = value["kind"].as_str().ok_or(REFUSAL)?;
        let name = value["metadata"]["name"].as_str().ok_or(REFUSAL)?;
        require(identities.insert((kind, name)))?;
    }
    Ok(result)
}

fn index(resources: &[Value], kind: &str, name: &str) -> Result<usize> {
    let matches: Vec<_> = resources
        .iter()
        .enumerate()
        .filter(|(_, v)| v["kind"] == kind && v["metadata"]["name"] == name)
        .map(|(i, _)| i)
        .collect();
    require(matches.len() == 1)?;
    Ok(matches[0])
}

fn container<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    let containers = value
        .pointer("/spec/template/spec/containers")
        .and_then(Value::as_array)
        .ok_or(REFUSAL)?;
    let matches: Vec<_> = containers.iter().filter(|v| v["name"] == name).collect();
    require(matches.len() == 1)?;
    Ok(matches[0])
}

fn container_mut<'a>(value: &'a mut Value, name: &str) -> Result<&'a mut Value> {
    container(value, name)?;
    value
        .pointer_mut("/spec/template/spec/containers")
        .and_then(Value::as_array_mut)
        .ok_or(REFUSAL)?
        .iter_mut()
        .find(|v| v["name"] == name)
        .ok_or(REFUSAL)
}

fn environment(value: &Value) -> Result<BTreeMap<&str, &Value>> {
    let mut result = BTreeMap::new();
    for entry in value["env"].as_array().ok_or(REFUSAL)? {
        let name = entry["name"].as_str().ok_or(REFUSAL)?;
        require(result.insert(name, entry).is_none())?;
    }
    Ok(result)
}

fn append_env(value: &mut Value, name: &str, setting: &str) -> Result<()> {
    require(!environment(value)?.contains_key(name))?;
    value["env"]
        .as_array_mut()
        .ok_or(REFUSAL)?
        .push(json!({"name":name,"value":setting}));
    Ok(())
}

fn config_ref(name: &str, key: &str) -> Value {
    json!({"name":name,"valueFrom":{"configMapKeyRef":{"name":"marty-config","key":key}}})
}
fn secret_ref(name: &str) -> Value {
    json!({"name":name,"valueFrom":{"secretKeyRef":{"name":"marty-secrets","key":name}}})
}

fn native_template(resources: &[Value]) -> Result<()> {
    require(resources.len() == 3)?;
    let deployment = &resources[index(resources, "Deployment", "issuance-native")?];
    let service = &resources[index(resources, "Service", "issuance-native")?];
    let config = &resources[index(resources, "ConfigMap", "issuance-native-config")?];
    require(config["data"] == json!({}))?;
    require(
        deployment["spec"]["selector"]["matchLabels"] == json!({"app":"issuance-native"})
            && deployment.pointer("/spec/template/metadata/labels")
                == Some(&json!({"app":"issuance-native"})),
    )?;
    let owner = container(deployment, "issuance-native")?;
    require(
        deployment["apiVersion"] == "apps/v1"
            && service["apiVersion"] == "v1"
            && config["apiVersion"] == "v1",
    )?;
    require_keys(
        owner,
        &[
            "name",
            "image",
            "imagePullPolicy",
            "command",
            "args",
            "envFrom",
            "env",
            "ports",
            "resources",
            "livenessProbe",
            "readinessProbe",
        ],
    )?;
    require(
        owner["command"] == json!(["/app/services/entrypoint.sh"])
            && owner["args"] == json!([])
            && owner["image"] == "${MARTY_SERVICES_IMAGE}"
            && owner["imagePullPolicy"] == "Always",
    )?;
    require(owner["envFrom"] == json!([{"configMapRef":{"name":"issuance-native-config"}}]))?;
    let env = environment(owner)?;
    let mut expected = BTreeMap::new();
    for &name in INHERITED_SETTINGS {
        expected.insert(name, config_ref(name, name));
    }
    for &name in SECRET_SETTINGS {
        expected.insert(name, secret_ref(name));
    }
    expected.insert(
        "ISSUER_BASE_URL",
        config_ref("ISSUER_BASE_URL", "PUBLIC_API_URL"),
    );
    expected.insert("CANVAS_CREDENTIALS_API_TOKEN",json!({"name":"CANVAS_CREDENTIALS_API_TOKEN","valueFrom":{"secretKeyRef":{"name":"marty-secrets","key":"CANVAS_CREDENTIALS_API_TOKEN","optional":true}}}));
    for (name, value) in [
        ("SERVICE_NAME", "issuance_native"),
        ("ISSUANCE_SERVICE_PORT", "8005"),
        ("ISSUANCE_GRPC_ENABLED", "true"),
        ("ISSUANCE_GRPC_PORT", "9005"),
        ("ORG_GRPC_TARGET", "organization:9002"),
        ("CT_GRPC_TARGET", "credential-template:9003"),
        ("RP_GRPC_TARGET", "revocation-profile:9013"),
        (
            "SIGNING_KEYS_INTERNAL_URL",
            "http://gateway:8000/internal/signing-keys",
        ),
    ] {
        expected.insert(name, json!({"name":name,"value":value}));
    }
    require(env.len() == expected.len() && expected.iter().all(|(k, v)| env.get(k) == Some(&v)))?;
    require(
        owner["ports"]
            == json!([{"name":"http","containerPort":8005},{"name":"grpc","containerPort":9005}]),
    )?;
    for probe in ["livenessProbe", "readinessProbe"] {
        require(owner[probe]["httpGet"] == json!({"path":"/health","port":8005}))?;
        require_keys(
            &owner[probe],
            &["httpGet", "initialDelaySeconds", "periodSeconds"],
        )?;
    }
    require(
        service["spec"]
            == json!({"type":"ClusterIP","selector":{"app":"issuance-native"},"ports":[{"name":"http","port":8005,"targetPort":8005},{"name":"grpc","port":9005,"targetPort":9005}]}),
    )?;
    let pod = deployment.pointer("/spec/template/spec").ok_or(REFUSAL)?;
    require(
        pod["serviceAccountName"] == "marty-app"
            && pod["imagePullSecrets"] == json!([{"name":"ocir-secret"}]),
    )?;
    require_keys(
        pod,
        &[
            "serviceAccountName",
            "automountServiceAccountToken",
            "imagePullSecrets",
            "containers",
        ],
    )?;
    require(
        pod["automountServiceAccountToken"] == false
            && pod["containers"].as_array().is_some_and(|v| v.len() == 1),
    )?;
    require(
        pod.get("volumes").is_none()
            && owner.get("volumeMounts").is_none()
            && pod.get("hostNetwork").is_none(),
    )?;
    Ok(())
}

fn require_keys(value: &Value, keys: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or(REFUSAL)?;
    require(object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key)))
}

fn pair_settings(legacy: &mut Value, native: &mut Value, values: &Environment) -> Result<()> {
    require(legacy["envFrom"] == json!([{"configMapRef":{"name":"marty-config"}}]))?;
    let explicit: BTreeMap<String, Value> = environment(legacy)?
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.clone()))
        .collect();
    // Legacy explicit env wins over both envFrom maps. The same source entry
    // wins natively, without reading or copying a referenced Secret value.
    for &name in SECRET_SETTINGS {
        require(explicit.contains_key(name))?;
    }
    for &name in INHERITED_SETTINGS
        .iter()
        .chain(SECRET_SETTINGS)
        .chain(SHARED_BINDINGS)
    {
        if let Some(entry) = explicit.get(name) {
            let target = native["env"]
                .as_array_mut()
                .ok_or(REFUSAL)?
                .iter_mut()
                .find(|entry| entry["name"] == name)
                .ok_or(REFUSAL)?;
            *target = entry.clone();
        }
    }
    for &name in OPTIONAL_SETTINGS {
        let entry = if let Some(entry) = explicit.get(name) {
            Some(entry.clone())
        } else if values.contains_key(name) {
            None
        } else {
            let mut entry = config_ref(name, name);
            entry["valueFrom"]["configMapKeyRef"]["optional"] = json!(true);
            Some(entry)
        };
        if let Some(entry) = entry {
            require(!environment(native)?.contains_key(name))?;
            native["env"].as_array_mut().ok_or(REFUSAL)?.push(entry);
        }
    }
    for &name in NATIVE_SETTINGS {
        if let Some(value) = values.get(name) {
            append_env(
                native,
                if name == "ISSUANCE_NATIVE_RUST_LOG" {
                    "RUST_LOG"
                } else {
                    name
                },
                value,
            )?;
        }
    }
    legacy["envFrom"]
        .as_array_mut()
        .ok_or(REFUSAL)?
        .push(json!({"configMapRef":{"name":"issuance-native-config"}}));
    Ok(())
}

fn mount(
    deployment: &mut Value,
    name: &str,
    secret: &str,
    volume: &str,
    key: &str,
    path: &str,
    setting: &str,
) -> Result<()> {
    let pod = deployment
        .pointer_mut("/spec/template/spec")
        .and_then(Value::as_object_mut)
        .ok_or(REFUSAL)?;
    let volumes = pod
        .entry("volumes")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or(REFUSAL)?;
    require(volumes.iter().all(|v| v["name"] != volume))?;
    volumes.push(json!({"name":volume,"secret":{"secretName":secret,"optional":false,"defaultMode":292,"items":[{"key":key,"path":key}]}}));
    let owner = container_mut(deployment, name)?;
    let mounts = owner
        .as_object_mut()
        .ok_or(REFUSAL)?
        .entry("volumeMounts")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or(REFUSAL)?;
    require(
        mounts
            .iter()
            .all(|v| v["name"] != volume && v["mountPath"] != path),
    )?;
    mounts.push(json!({"name":volume,"mountPath":path,"readOnly":true}));
    append_env(owner, setting, &format!("{path}/{key}"))
}

pub fn compose(
    resources: &[Value],
    template: &[Value],
    ready: &[String],
    values: &Environment,
) -> Result<Value> {
    require(selected(values)?)?;
    let image = services_image(values.get("MARTY_SERVICES_IMAGE").ok_or(REFUSAL)?)?;
    let configuration = configuration(values)?;
    native_template(template)?;
    require(
        !ready.is_empty()
            && ready.iter().any(|v| v == "issuance")
            && !ready.iter().any(|v| v == "issuance-native")
            && ready.iter().collect::<BTreeSet<_>>().len() == ready.len(),
    )?;
    let mut result = resources.to_vec();
    let legacy_index = index(&result, "Deployment", "issuance")?;
    let gateway_index = index(&result, "Deployment", "gateway")?;
    let namespace = result[legacy_index]["metadata"]["namespace"]
        .as_str()
        .ok_or(REFUSAL)?
        .to_owned();
    require(result[gateway_index]["metadata"]["namespace"] == namespace)?;
    for (i, name) in [(legacy_index, "issuance"), (gateway_index, "gateway")] {
        require(
            environment(container(&result[i], name)?)?.get("ISSUANCE_API_KEY")
                == Some(&&secret_ref("ISSUANCE_API_KEY")),
        )?;
    }
    let mut additions = template.to_vec();
    for item in &mut additions {
        require(!result.iter().any(|old| {
            old["kind"] == item["kind"] && old["metadata"]["name"] == item["metadata"]["name"]
        }))?;
        item["metadata"]["namespace"] = json!(namespace);
    }
    let native_index = index(&additions, "Deployment", "issuance-native")?;
    let config_index = index(&additions, "ConfigMap", "issuance-native-config")?;
    container_mut(&mut additions[native_index], "issuance-native")?["image"] = json!(image);
    additions[config_index]["data"] = configuration;
    pair_settings(
        container_mut(&mut result[legacy_index], "issuance")?,
        container_mut(&mut additions[native_index], "issuance-native")?,
        values,
    )?;
    let edge = container_mut(&mut result[gateway_index], "gateway")?;
    require(
        environment(edge)?.get("ISSUANCE_SERVICE_URL")
            == Some(&&config_ref("ISSUANCE_SERVICE_URL", "ISSUANCE_SERVICE_URL")),
    )?;
    append_env(edge, "ISSUANCE_NATIVE_SERVICE_URL", NATIVE_URL)?;
    let mut ready = ready.to_vec();
    ready.push("issuance-native".into());
    append_env(edge, "GATEWAY_REQUIRED_READY_SERVICES", &ready.join(","))?;
    for (selector, volume, key, path, setting) in MOUNTS {
        if let Some(secret) = values.get(selector).filter(|v| !v.is_empty()) {
            mount(
                &mut result[legacy_index],
                "issuance",
                secret,
                volume,
                key,
                path,
                setting,
            )?;
            mount(
                &mut additions[native_index],
                "issuance-native",
                secret,
                volume,
                key,
                path,
                setting,
            )?;
        }
    }
    result.extend(additions);
    let output = json!({"apiVersion":"v1","kind":"List","items":result});
    require(serde_json::to_vec(&output).map_err(|_| REFUSAL)?.len() <= MAX_BYTES)?;
    Ok(output)
}

/// Validate an already-selected deployment before an image-only update. This is
/// a snapshot, not a lock against concurrent operator changes or a rollout gate.
pub fn check_update(actual: &Value, expected: &Value, namespace: &str) -> Result<()> {
    require(!namespace.is_empty() && actual["kind"] == "List" && expected["kind"] == "List")?;
    let actual = actual["items"].as_array().ok_or(REFUSAL)?;
    let expected = expected["items"].as_array().ok_or(REFUSAL)?;
    for (kind, name) in [
        ("Deployment", "issuance-native"),
        ("Deployment", "gateway"),
        ("Deployment", "issuance"),
        ("Service", "issuance-native"),
        ("ConfigMap", "issuance-native-config"),
    ] {
        let observed = &actual[index(actual, kind, name)?];
        let target = &expected[index(expected, kind, name)?];
        require(
            observed["metadata"]["namespace"] == namespace
                && target["metadata"]["namespace"] == namespace,
        )?;
        match kind {
            "ConfigMap" => require(observed["data"] == target["data"])?,
            "Service" => {
                for field in ["type", "selector"] {
                    require(observed["spec"][field] == target["spec"][field])?;
                }
                let ports = observed["spec"]["ports"].as_array().ok_or(REFUSAL)?;
                let expected_ports = target["spec"]["ports"].as_array().ok_or(REFUSAL)?;
                require(ports.len() == expected_ports.len())?;
                for (port, expected_port) in ports.iter().zip(expected_ports) {
                    for field in ["name", "port", "targetPort"] {
                        require(port[field] == expected_port[field])?;
                    }
                    require(
                        port.get("nodePort").is_none()
                            && port.get("protocol").is_none_or(|v| v == "TCP"),
                    )?;
                }
            }
            "Deployment" if name == "gateway" => {
                let observed = environment(container(observed, name)?)?;
                let target = environment(container(target, name)?)?;
                for setting in [
                    "ISSUANCE_SERVICE_URL",
                    "ISSUANCE_NATIVE_SERVICE_URL",
                    "GATEWAY_REQUIRED_READY_SERVICES",
                    "ISSUANCE_API_KEY",
                ] {
                    require(observed.get(setting) == target.get(setting))?;
                }
            }
            "Deployment" if name == "issuance" => {
                let observed_owner = container(observed, name)?;
                let target_owner = container(target, name)?;
                let observed_env = environment(observed_owner)?;
                let target_env = environment(target_owner)?;
                require(observed_owner["envFrom"] == target_owner["envFrom"])?;
                for &setting in SECRET_SETTINGS
                    .iter()
                    .chain(INHERITED_SETTINGS)
                    .chain(OPTIONAL_SETTINGS)
                    .chain(SHARED_BINDINGS)
                {
                    require(observed_env.get(setting) == target_env.get(setting))?;
                }
                // The old image, unrelated fields and unrelated mounts remain
                // its independent owner. Only paired DIDComm mounts are fenced.
                for (_, volume, _, path, setting) in MOUNTS {
                    require(observed_env.get(setting) == target_env.get(setting))?;
                    for (observed_values, target_values, key, wanted) in [
                        (
                            observed.pointer("/spec/template/spec/volumes"),
                            target.pointer("/spec/template/spec/volumes"),
                            "name",
                            volume,
                        ),
                        (
                            observed_owner.get("volumeMounts"),
                            target_owner.get("volumeMounts"),
                            "mountPath",
                            path,
                        ),
                    ] {
                        let selected = |values: Option<&Value>| -> Result<Vec<Value>> {
                            match values {
                                None => Ok(Vec::new()),
                                Some(value) => Ok(value
                                    .as_array()
                                    .ok_or(REFUSAL)?
                                    .iter()
                                    .filter(|v| v[key] == wanted)
                                    .cloned()
                                    .collect()),
                            }
                        };
                        let actual = selected(observed_values)?;
                        let expected = selected(target_values)?;
                        require(actual.len() <= 1 && actual == expected)?;
                    }
                }
            }
            _ => {
                require(
                    observed["spec"]["selector"] == target["spec"]["selector"]
                        && observed.pointer("/spec/template/metadata/labels")
                            == target.pointer("/spec/template/metadata/labels"),
                )?;
                require(normalized_pod(observed)? == normalized_pod(target)?)?;
            }
        }
    }
    Ok(())
}

fn remove_default(object: &mut Value, key: &str, expected: Value) -> Result<()> {
    let object = object.as_object_mut().ok_or(REFUSAL)?;
    if let Some(value) = object.remove(key) {
        require(value == expected)?;
    }
    Ok(())
}

// Closed Kubernetes API defaults only. Unknown fields or any changed default
// survive comparison or are rejected; this is not broad observed-value pruning.
fn normalized_pod(deployment: &Value) -> Result<Value> {
    let mut pod = deployment
        .pointer("/spec/template/spec")
        .ok_or(REFUSAL)?
        .clone();
    for (key, value) in [
        ("dnsPolicy", json!("ClusterFirst")),
        ("restartPolicy", json!("Always")),
        ("schedulerName", json!("default-scheduler")),
        ("terminationGracePeriodSeconds", json!(30)),
        ("securityContext", json!({})),
        ("enableServiceLinks", json!(true)),
        ("hostNetwork", json!(false)),
        ("hostPID", json!(false)),
        ("hostIPC", json!(false)),
    ] {
        remove_default(&mut pod, key, value)?;
    }
    let service_account = pod["serviceAccountName"].clone();
    remove_default(&mut pod, "serviceAccount", service_account)?;
    let owners = pod["containers"].as_array_mut().ok_or(REFUSAL)?;
    require(owners.len() == 1)?;
    let owner = &mut owners[0];
    require(owner["name"] == "issuance-native")?;
    services_image(owner["image"].as_str().ok_or(REFUSAL)?)?;
    owner.as_object_mut().ok_or(REFUSAL)?.remove("image");
    remove_default(
        owner,
        "terminationMessagePath",
        json!("/dev/termination-log"),
    )?;
    remove_default(owner, "terminationMessagePolicy", json!("File"))?;
    for port in owner["ports"].as_array_mut().ok_or(REFUSAL)? {
        remove_default(port, "protocol", json!("TCP"))?;
    }
    for name in ["livenessProbe", "readinessProbe"] {
        for (key, value) in [
            ("successThreshold", 1),
            ("failureThreshold", 3),
            ("timeoutSeconds", 1),
        ] {
            remove_default(&mut owner[name], key, json!(value))?;
        }
        remove_default(&mut owner[name]["httpGet"], "scheme", json!("HTTP"))?;
    }
    Ok(pod)
}

pub fn readiness_from_source(source: &str) -> Result<Vec<String>> {
    let prefix = "const DEFAULT_READY_SERVICES: &[&str] = &[";
    require(source.matches(prefix).count() == 1)?;
    let body = source
        .split_once(prefix)
        .ok_or(REFUSAL)?
        .1
        .split_once("];")
        .ok_or(REFUSAL)?
        .0;
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let value = line
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix("\","))
                .ok_or(REFUSAL)?;
            require(
                !value.is_empty() && value.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
            )?;
            Ok(value.to_owned())
        })
        .collect()
}
