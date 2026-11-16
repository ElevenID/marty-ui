//! Pure, private planning of an existing-only Kubernetes Secret update.
//! The caller owns credential qualification, freshness, private persistence and
//! execution. A successful plan does not qualify or activate any credential.
//! Initially compiled only by tests; there is no production mutation entry point.

use super::{sha256, staging, uuid, Binding, Generation, Result, REFUSAL};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const SCHEMA: &str = "marty.kubernetes-legacy-recovery-activation-plan/v1";
const REPLACEMENTS: usize = 51;
const TARGETS: usize = 34;
const MAX_SECRET_BYTES: usize = 1024 * 1024;

// Secret name -> data field -> retained generation filename. This is derived
// only from the native publication owner, never from a caller-provided mapping.
type Mappings = BTreeMap<String, BTreeMap<String, String>>;

fn replacements(binding: &Binding) -> Result<BTreeSet<String>> {
    let (leaves, tokens) = staging::inventory(binding)?;
    let files: BTreeSet<_> = leaves
        .into_iter()
        .map(|leaf| leaf.file)
        .chain(tokens.into_iter().map(|token| token.file))
        .collect();
    if files.len() != REPLACEMENTS || files.contains("openbao_bootstrap_token") {
        return Err(REFUSAL);
    }
    Ok(files)
}

fn mappings(catalog: &Value, files: &BTreeSet<String>) -> Result<Mappings> {
    if catalog["schema_version"] != 1 {
        return Err(REFUSAL);
    }
    let inputs: BTreeMap<_, _> = files
        .iter()
        .map(|file| (file.to_ascii_uppercase(), file.clone()))
        .collect();
    if inputs.len() != REPLACEMENTS {
        return Err(REFUSAL);
    }
    let mut seen_names = BTreeSet::new();
    let mut seen_inputs = BTreeSet::new();
    let mut targets = BTreeMap::new();
    for secret in catalog["secrets"].as_array().ok_or(REFUSAL)? {
        let name = secret["name"].as_str().ok_or(REFUSAL)?;
        if !super::reference(name) || !seen_names.insert(name) {
            return Err(REFUSAL);
        }
        let mut fields = BTreeMap::new();
        for (key, specification) in secret["fields"].as_object().ok_or(REFUSAL)? {
            let specification = specification.as_object().ok_or(REFUSAL)?;
            if let Some(template) = specification.get("template") {
                let template = template.as_str().ok_or(REFUSAL)?;
                // The publication owner substitutes exactly {UPPERCASE_INPUT}.
                // An updated input in a template needs a separately reviewed
                // owner change; this adapter supports direct fields only.
                if inputs
                    .keys()
                    .any(|input| template.contains(&format!("{{{input}}}")))
                {
                    return Err(REFUSAL);
                }
            }
            if let Some(input) = specification.get("env") {
                let input = input.as_str().ok_or(REFUSAL)?;
                if let Some(file) = inputs.get(input) {
                    if specification.len() != 1
                        || key.is_empty()
                        || !seen_inputs.insert(input.to_owned())
                    {
                        return Err(REFUSAL);
                    }
                    fields.insert(key.clone(), file.clone());
                }
            }
        }
        if !fields.is_empty() {
            if secret.get("optional_env").is_some() {
                return Err(REFUSAL);
            }
            targets.insert(name.to_owned(), fields);
        }
    }
    if seen_inputs != inputs.into_keys().collect() || targets.len() != TARGETS {
        return Err(REFUSAL);
    }
    Ok(targets)
}

fn normalized(bytes: &[u8]) -> Result<String> {
    if bytes.contains(&0) || bytes.len() > super::MAX_FILE {
        return Err(REFUSAL);
    }
    // File-backed input semantics of kubernetes_secrets::resolve: remove CR
    // bytes, then remove every trailing LF (including multiline PEM inputs).
    let value = std::str::from_utf8(bytes)
        .map_err(|_| REFUSAL)?
        .replace('\r', "");
    let value = value.trim_end_matches('\n');
    if value.is_empty() {
        return Err(REFUSAL);
    }
    Ok(value.to_owned())
}

fn generation_bindings(generation: &Generation) -> Value {
    Value::Object(
        generation
            .iter()
            .map(|(file, (bytes, mode))| {
                (file.clone(), json!({"sha256":sha256(bytes),"mode":mode}))
            })
            .collect(),
    )
}

fn canonical_data(value: &Value) -> Result<&Map<String, Value>> {
    let data = value.as_object().ok_or(REFUSAL)?;
    let mut total = 0usize;
    for (key, encoded) in data {
        // This is the native Kubernetes Secret data-key grammar. Unknown keys
        // are preserved, but malformed data anywhere must not pass a snapshot.
        if key.is_empty()
            || key.len() > 253
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        {
            return Err(REFUSAL);
        }
        let encoded = encoded.as_str().ok_or(REFUSAL)?;
        if encoded.len() > MAX_SECRET_BYTES.div_ceil(3) * 4 {
            return Err(REFUSAL);
        }
        let decoded = STANDARD.decode(encoded).map_err(|_| REFUSAL)?;
        total = total.checked_add(decoded.len()).ok_or(REFUSAL)?;
        if total > MAX_SECRET_BYTES || STANDARD.encode(decoded) != encoded {
            return Err(REFUSAL);
        }
    }
    Ok(data)
}

fn pointer_field(key: &str) -> String {
    format!("/data/{}", key.replace('~', "~0").replace('/', "~1"))
}

pub(super) fn target_names(binding: &Binding) -> Result<Vec<String>> {
    let publication = crate::kubernetes_secrets::contract();
    if publication["schema"] != "marty.kubernetes-secret-publication/v1" {
        return Err(REFUSAL);
    }
    Ok(mappings(&publication["catalog"], &replacements(binding)?)?
        .into_keys()
        .collect())
}

/// Produce a credential-bearing private plan, without I/O or side effects.
///
/// `current`, `candidate`, and `binding` come from the admitted native readers.
/// The caller must decode `observed` with the native duplicate-key-refusing
/// decoder. Its shape is the exact v1 SecretList of the 34 selected targets.
/// Secret UIDs are observed bindings, not a claim about historical object UIDs.
pub(super) fn plan(
    current: &Generation,
    candidate: &Generation,
    binding: &Binding,
    observed: &Value,
) -> Result<Value> {
    let files = replacements(binding)?;
    if current.len() != candidate.len()
        || current.keys().ne(candidate.keys())
        || !files.iter().all(|file| current.contains_key(file))
    {
        return Err(REFUSAL);
    }
    for (file, (old, mode)) in current {
        let (new, new_mode) = candidate.get(file).ok_or(REFUSAL)?;
        if mode != new_mode || (old != new) != files.contains(file) {
            return Err(REFUSAL);
        }
    }
    let publication = crate::kubernetes_secrets::contract();
    if publication["schema"] != "marty.kubernetes-secret-publication/v1" {
        return Err(REFUSAL);
    }
    let targets = mappings(&publication["catalog"], &files)?;
    if observed["apiVersion"] != "v1" || observed["kind"] != "SecretList" {
        return Err(REFUSAL);
    }
    let items = observed["items"].as_array().ok_or(REFUSAL)?;
    if items.len() != TARGETS {
        return Err(REFUSAL);
    }
    let mut snapshots = BTreeMap::new();
    let mut uids = BTreeSet::new();
    for item in items {
        let metadata = item["metadata"].as_object().ok_or(REFUSAL)?;
        let name = metadata
            .get("name")
            .and_then(Value::as_str)
            .ok_or(REFUSAL)?;
        let uid = metadata.get("uid").and_then(Value::as_str).ok_or(REFUSAL)?;
        let version = metadata
            .get("resourceVersion")
            .and_then(Value::as_str)
            .ok_or(REFUSAL)?;
        if item["apiVersion"] != "v1"
            || item["kind"] != "Secret"
            || item["type"] != "Opaque"
            || item.get("stringData").is_some()
            || metadata.get("namespace").and_then(Value::as_str) != Some(binding.namespace.as_str())
            || metadata.get("deletionTimestamp").is_some()
            || item
                .get("immutable")
                .is_some_and(|value| value.as_bool() != Some(false))
            || !uuid(uid)
            || !uids.insert(uid)
            || version.is_empty()
            || version.len() > 128
            || version.chars().any(char::is_whitespace)
            || version.chars().any(char::is_control)
            || !targets.contains_key(name)
            || snapshots.insert(name, item).is_some()
        {
            return Err(REFUSAL);
        }
        canonical_data(&item["data"])?;
    }
    let mut secrets = Vec::new();
    for (name, fields) in targets {
        let item = snapshots.get(name.as_str()).ok_or(REFUSAL)?;
        let data = item["data"].as_object().ok_or(REFUSAL)?;
        let mut patch = vec![
            json!({"op":"test","path":"/metadata/uid","value":item["metadata"]["uid"]}),
            json!({"op":"test","path":"/metadata/resourceVersion","value":item["metadata"]["resourceVersion"]}),
            json!({"op":"test","path":"/data","value":data}),
        ];
        let mut total: usize = data
            .values()
            .map(|value| {
                STANDARD
                    .decode(value.as_str().ok_or(REFUSAL)?)
                    .map(|bytes| bytes.len())
                    .map_err(|_| REFUSAL)
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .sum();
        for (key, file) in fields {
            let old = normalized(&current.get(&file).ok_or(REFUSAL)?.0)?;
            let new = normalized(&candidate.get(&file).ok_or(REFUSAL)?.0)?;
            if old == new || data.get(&key) != Some(&json!(STANDARD.encode(&old))) {
                return Err(REFUSAL);
            }
            total = total
                .checked_sub(old.len())
                .and_then(|size| size.checked_add(new.len()))
                .ok_or(REFUSAL)?;
            if total > MAX_SECRET_BYTES {
                return Err(REFUSAL);
            }
            patch.push(
                json!({"op":"replace","path":pointer_field(&key),"value":STANDARD.encode(new)}),
            );
        }
        secrets.push(json!({
            "namespace":binding.namespace,
            "name":name,
            "uid":item["metadata"]["uid"],
            "resourceVersion":item["metadata"]["resourceVersion"],
            "patch":patch,
        }));
    }
    Ok(json!({
        "schema":SCHEMA,
        "status":"planned-not-qualified-or-activated",
        "private":true,
        "credentialsQualified":false,
        "activationPerformed":false,
        "atomicAcrossSecrets":false,
        "binding":binding,
        "currentInputs":generation_bindings(current),
        "candidateInputs":generation_bindings(candidate),
        "secrets":secrets,
    }))
}

#[cfg(test)]
#[path = "kubernetes_legacy_recovery_activation_tests.rs"]
mod tests;
