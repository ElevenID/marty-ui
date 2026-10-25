//! Kubernetes secret assembly. Credential values never enter argv or diagnostics.
use crate::{Catalog, Result};
use serde_json::{json, Map, Value};
use std::{
    collections::BTreeMap,
    process::{Command, Stdio},
};

const SPEC: &str = include_str!("../../../../deploy-config/catalog/kubernetes-secrets.json");
const LIMIT: u64 = 1024 * 1024;

fn placeholder(value: &str) -> bool {
    value.is_empty()
        || ["change-me", "CHANGE_ME", "replace-me", "REPLACE_ME"]
            .iter()
            .any(|prefix| value.starts_with(prefix))
}

fn resolve(name: &str) -> Result<String> {
    use std::io::Read;
    let value = std::env::var(name).unwrap_or_default();
    let path = std::env::var(format!("{name}_FILE")).unwrap_or_default();
    if !value.is_empty() && !path.is_empty() {
        return Err(format!("Both {name} and {name}_FILE are set; choose one."));
    }
    if path.is_empty() {
        return Ok(value);
    }
    if !std::fs::metadata(&path)
        .map_err(|_| format!("{name}_FILE is not readable"))?
        .is_file()
    {
        return Err(format!("{name}_FILE must be a regular file"));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut file = options
        .open(path)
        .map_err(|_| format!("{name}_FILE is not readable"))?;
    if !file
        .metadata()
        .map_err(|_| format!("{name}_FILE is not readable"))?
        .is_file()
    {
        return Err(format!("{name}_FILE must be a regular file"));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| format!("{name}_FILE is not readable"))?;
    if bytes.len() as u64 > LIMIT || bytes.contains(&0) {
        return Err(format!("{name}_FILE has invalid content"));
    }
    let value = String::from_utf8(bytes).map_err(|_| format!("{name}_FILE must be UTF-8"))?;
    // Match tr -d CR and Bash command substitution, including multiline certificates.
    Ok(value.replace('\r', "").trim_end_matches('\n').to_owned())
}

fn required(values: &BTreeMap<String, String>, name: &str) -> Result<()> {
    if placeholder(&values[name]) {
        Err(format!(
            "{name} must be set to a non-placeholder value before deployment."
        ))
    } else {
        Ok(())
    }
}

fn validate(values: &BTreeMap<String, String>, mandatory: &[String]) -> Result<()> {
    for name in mandatory {
        required(values, name)?;
    }
    let role_keys = [
        "SIGNING_KEYS_ISSUER_SIGN_KEY",
        "SIGNING_KEYS_SERVICE_SIGN_GATEWAY_KEY",
        "SIGNING_KEYS_INTEGRATION_SECRET_KEY",
    ];
    for (index, name) in role_keys.iter().enumerate() {
        if values[*name].chars().count() < 32
            || values[*name] == values["ISSUANCE_API_KEY"]
            || role_keys[..index]
                .iter()
                .any(|other| values[*name] == values[*other])
        {
            return Err(format!(
                "{name} must be at least 32 characters and distinct from Signing Keys credentials."
            ));
        }
    }
    for (index, name) in [
        "DEVICE_REGISTRATION_GATEWAY_KEY",
        "DEVICE_REGISTRATION_SIGNING_KEYS_KEY",
    ]
    .iter()
    .enumerate()
    {
        if values[*name].chars().count() < 32
            || ["GRPC_SERVICE_TOKEN", "ISSUANCE_API_KEY"]
                .iter()
                .any(|other| values[*name] == values[*other])
            || (index == 1 && values[*name] == values["DEVICE_REGISTRATION_GATEWAY_KEY"])
        {
            return Err(format!("{name} must be at least 32 characters and distinct from other service credentials."));
        }
    }
    if values["OPENBAO_BOOTSTRAP_TOKEN"] == values["OPENBAO_SERVICE_TOKEN"] {
        return Err(
            "Migration-only KMS bootstrap token must differ from the runtime OpenBao token.".into(),
        );
    }
    let grants = [
        "FLOW_SIGN_GRANT_MINT_TOKEN",
        "ISSUANCE_CREDENTIAL_SIGN_GRANT_MINT_TOKEN",
        "ISSUANCE_CANVAS_SIGN_GRANT_MINT_TOKEN",
        "ISSUANCE_READINESS_SIGN_GRANT_MINT_TOKEN",
        "ISSUANCE_PASSPORT_SIGN_GRANT_MINT_TOKEN",
        "GATEWAY_SIGN_GRANT_MINT_TOKEN",
        "GATEWAY_ISSUER_CSR_GRANT_MINT_TOKEN",
        "SIGNING_KEYS_GRANT_VERIFY_TOKEN",
    ];
    for (index, name) in grants.iter().enumerate() {
        if grants[..index]
            .iter()
            .any(|other| values[*name] == values[*other])
        {
            return Err(
                "Signing grant mint and verify tokens must be distinct for each role.".into(),
            );
        }
        if [
            "OPENBAO_SERVICE_TOKEN",
            "OPENBAO_BOOTSTRAP_TOKEN",
            "SIGNING_KEYS_OPENBAO_TOKEN",
            "DIDCOMM_ISSUANCE_OPENBAO_TOKEN",
        ]
        .iter()
        .any(|other| !values[*other].is_empty() && values[*name] == values[*other])
        {
            return Err(
                "Signing grant tokens must differ from general OpenBao credentials.".into(),
            );
        }
    }
    if values["FLOW_WEBHOOK_SECRET"].chars().count() < 32 {
        return Err("FLOW_WEBHOOK_SECRET must be at least 32 characters.".into());
    }
    Ok(())
}

fn specification() -> Value {
    serde_json::from_str(SPEC).expect("Kubernetes secret catalog is valid")
}

fn input_names(spec: &Value) -> Vec<String> {
    let mut names: Vec<String> = spec["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    for secret in spec["secrets"].as_array().unwrap() {
        for field in secret["fields"].as_object().unwrap().values() {
            if let Some(name) = field["env"].as_str() {
                names.push(name.into());
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

fn assemble(spec: &Value, namespace: &str, values: &BTreeMap<String, String>) -> Value {
    let template_variables = regex::Regex::new(r"\{([A-Z_0-9]+)\}").unwrap();
    let mut items = Vec::new();
    for secret in spec["secrets"].as_array().unwrap() {
        if secret["optional_env"]
            .as_str()
            .is_some_and(|name| placeholder(&values[name]))
        {
            continue;
        }
        let mut data = Map::new();
        for (key, field) in secret["fields"].as_object().unwrap() {
            let value = if let Some(name) = field["env"].as_str() {
                let value = &values[name];
                if value.is_empty() {
                    field["default"].as_str().unwrap_or(value).to_owned()
                } else {
                    value.clone()
                }
            } else if let Some(template) = field["template"].as_str() {
                template_variables
                    .replace_all(template, |captures: &regex::Captures<'_>| {
                        values[&captures[1]].clone()
                    })
                    .into_owned()
            } else {
                field["literal"].as_str().unwrap().to_owned()
            };
            data.insert(key.clone(), Value::String(value));
        }
        items.push(json!({"apiVersion":"v1","kind":"Secret","metadata":{"name":secret["name"],"namespace":namespace},"type":"Opaque","stringData":data}));
    }
    json!({"apiVersion":"v1","kind":"List","items":items})
}

/// Validate every input before any mutation, then send only private stdin to kubectl.
pub fn apply(
    catalog: &Catalog,
    stack: &str,
    namespace: &str,
    captured: Option<&str>,
) -> Result<()> {
    if namespace.is_empty()
        || namespace.len() > 63
        || !namespace
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || namespace.starts_with('-')
        || namespace.ends_with('-')
    {
        return Err("Invalid Kubernetes namespace".into());
    }
    let spec = specification();
    let mut mandatory: Vec<String> = spec["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    let ids = catalog.required_input_ids(stack)?;
    if ids.is_empty() {
        return Err("Deployment catalog returned no required secrets.".into());
    }
    let mut catalog_names = std::collections::BTreeSet::new();
    for id in ids {
        let name = catalog.public_input_field(&id, "env")?;
        if !name.is_empty() {
            catalog_names.insert(name.clone());
            mandatory.push(name);
        }
    }
    if let Some(captured) = captured {
        let captured: std::collections::BTreeSet<String> = captured
            .lines()
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        if captured != catalog_names {
            return Err("Deployment catalog required secrets changed after preflight".into());
        }
    }
    let mut names = input_names(&spec);
    names.extend(mandatory.iter().cloned());
    names.sort();
    names.dedup();
    let values: BTreeMap<String, String> = names
        .into_iter()
        .map(|name| resolve(&name).map(|value| (name, value)))
        .collect::<Result<_>>()?;
    validate(&values, &mandatory)?;
    let manifest = assemble(&spec, namespace, &values);
    // Preserve fail-fast publication: a Kubernetes List can continue after a
    // failed member, whereas the original shell stopped at its first failure.
    for secret in manifest["items"].as_array().unwrap() {
        let mut child = Command::new("kubectl")
            .args(["apply", "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "Could not start kubectl".to_owned())?;
        let written = serde_json::to_writer(child.stdin.as_mut().unwrap(), secret);
        drop(child.stdin.take());
        let status = child
            .wait()
            .map_err(|_| "Could not wait for kubectl".to_owned())?;
        if written.is_err() || !status.success() {
            return Err(
                "Kubernetes secret apply failed (credential-bearing diagnostics suppressed)".into(),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn values() -> (Value, BTreeMap<String, String>, Vec<String>) {
        let spec = specification();
        let values = input_names(&spec)
            .into_iter()
            .map(|name| {
                let value = format!("synthetic-distinct-credential-for-{name}");
                (name, value)
            })
            .collect();
        let mandatory = spec["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().into())
            .collect();
        (spec, values, mandatory)
    }
    #[test]
    fn preserved_secret_schema_and_custody() {
        let (spec, values, mandatory) = values();
        validate(&values, &mandatory).unwrap();
        let manifest = assemble(&spec, "marty-prod", &values);
        assert_eq!(manifest["items"].as_array().unwrap().len(), 34);
        let items = manifest["items"].as_array().unwrap();
        let main = &items
            .iter()
            .find(|v| v["metadata"]["name"] == "marty-secrets")
            .unwrap()["stringData"];
        assert_eq!(
            main["SIGNING_KEYS_INTERNAL_API_KEY"],
            values["ISSUANCE_API_KEY"]
        );
        assert_eq!(
            main["DATABASE_URL"],
            format!(
                "postgresql+asyncpg://marty:{}@postgres:5432/marty",
                values["MARTY_DB_PASSWORD"]
            )
        );
        assert_eq!(
            items
                .iter()
                .find(|v| v["metadata"]["name"] == "keycloak-kms")
                .unwrap()["stringData"]
                .as_object()
                .unwrap()
                .len(),
            8
        );
        for item in items {
            assert!(!item["stringData"]
                .as_object()
                .unwrap()
                .keys()
                .any(|name| name.contains("PRIVATE_KEY") || name == "tls.key"));
        }
    }
    #[test]
    fn rejects_each_missing_required_value_and_all_grant_collisions_without_disclosure() {
        let (_, values, mandatory) = values();
        for name in &mandatory {
            let mut invalid = values.clone();
            invalid.insert(name.clone(), "CHANGE_ME".into());
            assert!(validate(&invalid, &mandatory).is_err(), "{name}");
        }
        for name in ["GATEWAY_SIGN_GRANT_MINT_TOKEN", "OPENBAO_SERVICE_TOKEN"] {
            let mut invalid = values.clone();
            invalid.insert(name.into(), values["FLOW_SIGN_GRANT_MINT_TOKEN"].clone());
            let error = validate(&invalid, &mandatory).unwrap_err();
            assert!(!error.contains("synthetic-"));
        }
    }
    #[test]
    fn optional_tunnel_and_multiline_certificates() {
        let (spec, mut values, _) = values();
        values.insert("CLOUDFLARE_TUNNEL_TOKEN".into(), "replace-me".into());
        values.insert("KEYCLOAK_MASTER_RS256_CERT".into(), "first\nsecond".into());
        let manifest = assemble(&spec, "marty-prod", &values);
        assert_eq!(manifest["items"].as_array().unwrap().len(), 33);
        assert_eq!(
            manifest["items"][1]["stringData"]["keycloak-master-rs256.crt"],
            "first\nsecond"
        );
    }
}
