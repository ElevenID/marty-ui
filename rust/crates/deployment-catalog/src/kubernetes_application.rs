//! Restricted application activation payloads for the existing Kubernetes API.
//! Raw objects and patch bodies remain in caller-owned private files. This module
//! never contacts the cluster, mints tokens, or prints credential values.
use crate::{
    application_tokens, generation,
    operator::{Result, REFUSAL},
    operator_files::{finish_generation, generation_output, private_directory},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
};

pub const DESTINATION: &str = "marty-secrets";
pub const ACTIVATION_ANNOTATION: &str = "marty.elevenid.com/application-activation";
const MAX_OBJECT: usize = 2 * 1024 * 1024;
const GENERATION_MODES: &[u32] = &[0o400, 0o440, 0o444, 0o600, 0o640, 0o644];
type Snapshot = BTreeMap<String, (Vec<u8>, u32)>;
type Inputs = BTreeMap<String, String>;

#[derive(Clone)]
struct Mapping {
    input: String,
    file: String,
    key: String,
}

fn mappings() -> Result<Vec<Mapping>> {
    let publication = crate::kubernetes_secrets::contract();
    let destinations = publication["catalog"]["secrets"]
        .as_array()
        .ok_or(REFUSAL)?;
    let mut found = Vec::new();
    let mut inputs = BTreeSet::new();
    let mut files = BTreeSet::new();
    for spec in application_tokens::runtime_specs() {
        let mut matches = Vec::new();
        for destination in destinations {
            for (key, field) in destination["fields"].as_object().ok_or(REFUSAL)? {
                if field["env"].as_str() == Some(&spec.input) {
                    if destination["name"] != DESTINATION
                        || field.as_object().is_none_or(|fields| fields.len() != 1)
                    {
                        return Err(REFUSAL);
                    }
                    matches.push(key.clone());
                }
            }
        }
        if matches.len() != 1
            || !inputs.insert(spec.input.clone())
            || !files.insert(spec.file.clone())
        {
            return Err(REFUSAL);
        }
        let key = matches.remove(0);
        // The reviewed ordinary inventory has a direct one-to-one mapping.
        if key != spec.input || spec.file != spec.input.to_ascii_lowercase() {
            return Err(REFUSAL);
        }
        found.push(Mapping {
            input: spec.input,
            file: spec.file,
            key,
        });
    }
    if found.len() != 11 {
        return Err(REFUSAL);
    }
    found.sort_by(|left, right| left.input.cmp(&right.input));
    Ok(found)
}

/// Frozen names and capability limits only; this never opens an input file.
pub fn activation_metadata() -> Value {
    let inputs: Vec<Value> = mappings()
        .expect("compiled activation mappings must be valid")
        .into_iter()
        .map(|item| json!({"input":item.input,"file":item.file,"key":item.key}))
        .collect();
    json!({
        "schema":"marty.kubernetes-application-activation/v1",
        "destination":DESTINATION,
        "activationAnnotation":ACTIVATION_ANNOTATION,
        "minimumTtlSeconds":crate::application_authority::MINIMUM_ACTIVATION_TTL,
        "inputs":inputs,
    })
}

fn owned_directory(path: &Path) -> Result<PathBuf> {
    let canonical = private_directory(path)?;
    if canonical != path {
        return Err(REFUSAL);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if fs::metadata(path).map_err(|_| REFUSAL)?.uid() != unsafe { libc::geteuid() } {
            return Err(REFUSAL);
        }
        Ok(canonical)
    }
    #[cfg(not(unix))]
    {
        Err(REFUSAL)
    }
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (
            left.dev(),
            left.ino(),
            left.mode(),
            left.uid(),
            left.nlink(),
            left.len(),
            left.mtime(),
            left.mtime_nsec(),
            left.ctime(),
            left.ctime_nsec(),
        ) == (
            right.dev(),
            right.ino(),
            right.mode(),
            right.uid(),
            right.nlink(),
            right.len(),
            right.mtime(),
            right.mtime_nsec(),
            right.ctime(),
            right.ctime_nsec(),
        )
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        false
    }
}

fn read_owned(path: &Path, maximum: usize, modes: &[u32]) -> Result<(Vec<u8>, u32)> {
    owned_directory(path.parent().ok_or(REFUSAL)?)?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options.open(path).map_err(|_| REFUSAL)?;
    let before = file.metadata().map_err(|_| REFUSAL)?;
    if !before.is_file() || before.len() > maximum as u64 {
        return Err(REFUSAL);
    }
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::MetadataExt;
        let mode = before.mode() & 0o7777;
        if before.uid() != unsafe { libc::geteuid() }
            || before.nlink() != 1
            || !modes.contains(&mode)
        {
            return Err(REFUSAL);
        }
        mode
    };
    #[cfg(not(unix))]
    let mode = {
        let _ = modes;
        return Err(REFUSAL);
    };
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| REFUSAL)?;
    if bytes.len() > maximum
        || bytes.len() as u64 != before.len()
        || !same_file(&before, &file.metadata().map_err(|_| REFUSAL)?)
        || !same_file(&before, &fs::symlink_metadata(path).map_err(|_| REFUSAL)?)
    {
        return Err(REFUSAL);
    }
    Ok((bytes, mode))
}

fn snapshot(path: &Path) -> Result<Snapshot> {
    owned_directory(path)?;
    let entries = generation::entries(path)?;
    if entries.is_empty() || entries.len() > 256 {
        return Err(REFUSAL);
    }
    let mut result = Snapshot::new();
    let mut total = 0usize;
    for (name, file) in entries {
        let value = read_owned(&file, 65536, GENERATION_MODES)?;
        total += value.0.len();
        if total > 8 * 1024 * 1024 {
            return Err(REFUSAL);
        }
        result.insert(name, value);
    }
    Ok(result)
}

fn token_inputs(snapshot: &Snapshot) -> Result<Inputs> {
    let mut inputs = Inputs::new();
    for mapping in mappings()? {
        let bytes = &snapshot.get(&mapping.file).ok_or(REFUSAL)?.0;
        let value = bytes.strip_suffix(b"\n").unwrap_or(bytes);
        if !(20..=1024).contains(&value.len()) || !value.iter().all(u8::is_ascii_graphic) {
            return Err(REFUSAL);
        }
        inputs.insert(
            mapping.key,
            String::from_utf8(value.to_vec()).map_err(|_| REFUSAL)?,
        );
    }
    Ok(inputs)
}

fn valid_namespace(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_activation(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn opaque_metadata(value: &Value) -> Result<&str> {
    value
        .as_str()
        .filter(|value| {
            !value.is_empty() && value.len() <= 256 && value.bytes().all(|b| b.is_ascii_graphic())
        })
        .ok_or(REFUSAL)
}

fn validate_object(value: &Value, namespace: &str) -> Result<()> {
    if !valid_namespace(namespace)
        || value["apiVersion"] != "v1"
        || value["kind"] != "Secret"
        || value["metadata"]["name"] != DESTINATION
        || value["metadata"]["namespace"] != namespace
        || value["type"] != "Opaque"
        || value.get("immutable").is_some_and(|flag| flag != false)
        || value["metadata"]
            .get("deletionTimestamp")
            .is_some_and(|stamp| !stamp.is_null())
        || value.get("stringData").is_some()
    {
        return Err(REFUSAL);
    }
    opaque_metadata(&value["metadata"]["uid"])?;
    opaque_metadata(&value["metadata"]["resourceVersion"])?;
    if let Some(annotations) = value["metadata"].get("annotations") {
        let annotations = annotations.as_object().ok_or(REFUSAL)?;
        if annotations.values().any(|value| !value.is_string()) {
            return Err(REFUSAL);
        }
        if let Some(marker) = annotations.get(ACTIVATION_ANNOTATION) {
            if !marker.as_str().is_some_and(valid_activation) {
                return Err(REFUSAL);
            }
        }
    }
    let data = value["data"].as_object().ok_or(REFUSAL)?;
    let mut size = 0usize;
    for encoded in data.values() {
        let encoded = encoded.as_str().ok_or(REFUSAL)?;
        let bytes = STANDARD.decode(encoded).map_err(|_| REFUSAL)?;
        if STANDARD.encode(&bytes) != encoded {
            return Err(REFUSAL);
        }
        size += bytes.len();
        if size > 1024 * 1024 {
            return Err(REFUSAL);
        }
    }
    Ok(())
}

fn transition(
    observed: &Value,
    namespace: &str,
    activation: &str,
    current: &Inputs,
    candidate: &Inputs,
) -> Result<(Value, Value)> {
    validate_object(observed, namespace)?;
    if !valid_activation(activation) || current.keys().ne(candidate.keys()) || current.len() != 11 {
        return Err(REFUSAL);
    }
    if observed["metadata"]["annotations"][ACTIVATION_ANNOTATION] == activation {
        return Err(REFUSAL);
    }
    let mut expected = observed.clone();
    let mut patch = vec![
        json!({"op":"test","path":"/metadata/uid","value":observed["metadata"]["uid"]}),
        json!({"op":"test","path":"/metadata/resourceVersion","value":observed["metadata"]["resourceVersion"]}),
    ];
    let mut replacement_values = BTreeSet::new();
    for mapping in mappings()? {
        let before = current.get(&mapping.key).ok_or(REFUSAL)?;
        let after = candidate.get(&mapping.key).ok_or(REFUSAL)?;
        if observed["data"][&mapping.key].as_str() != Some(&STANDARD.encode(before))
            || current.values().any(|old| old == after)
            || !replacement_values.insert(after)
        {
            return Err(REFUSAL);
        }
        let encoded = STANDARD.encode(after);
        patch.push(json!({"op":"replace","path":format!("/data/{}",mapping.key),"value":encoded}));
        expected["data"][&mapping.key] = Value::String(encoded);
    }
    let mut annotations = observed["metadata"]
        .get("annotations")
        .cloned()
        .unwrap_or_else(|| json!({}));
    annotations[ACTIVATION_ANNOTATION] = Value::String(activation.into());
    patch.push(json!({"op":"add","path":"/metadata/annotations","value":annotations}));
    expected["metadata"]["annotations"] = annotations;
    Ok((Value::Array(patch), expected))
}

fn classify(
    observed: &Value,
    expected: &Value,
    result: &Value,
    namespace: &str,
) -> Result<&'static str> {
    validate_object(result, namespace)?;
    if observed == result {
        return Ok("unchanged");
    }
    if result["metadata"]["uid"] != observed["metadata"]["uid"]
        || result["metadata"]["resourceVersion"] == observed["metadata"]["resourceVersion"]
    {
        return Err(REFUSAL);
    }
    let normalize = |document: &Value| {
        let mut copy = document.clone();
        let metadata = copy["metadata"]
            .as_object_mut()
            .expect("validated metadata object");
        metadata.remove("resourceVersion");
        metadata.remove("managedFields");
        copy
    };
    if normalize(expected) != normalize(result) {
        return Err(REFUSAL);
    }
    Ok("candidate")
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "lowercase", deny_unknown_fields)]
enum Request {
    Prepare {
        namespace: String,
        current: PathBuf,
        candidate: PathBuf,
        observed: PathBuf,
        output: PathBuf,
        #[serde(rename = "activationId")]
        activation_id: String,
    },
    Verify {
        namespace: String,
        current: PathBuf,
        candidate: PathBuf,
        observed: PathBuf,
        result: PathBuf,
        #[serde(rename = "activationId")]
        activation_id: String,
    },
}

/// Prepare one conditional private JSON patch or classify the same attempt's
/// observed outcome. A conflict is a refusal, never an instruction to retry.
pub fn operation(context: &Value) -> Result<Value> {
    let request: Request = serde_json::from_value(context.clone()).map_err(|_| REFUSAL)?;
    let (namespace, current, candidate, observed, activation) = match &request {
        Request::Prepare {
            namespace,
            current,
            candidate,
            observed,
            activation_id,
            ..
        }
        | Request::Verify {
            namespace,
            current,
            candidate,
            observed,
            activation_id,
            ..
        } => (namespace, current, candidate, observed, activation_id),
    };
    if !valid_namespace(namespace) || !valid_activation(activation) {
        return Err(REFUSAL);
    }
    let current_before = snapshot(current)?;
    let candidate_before = snapshot(candidate)?;
    if generation::verify_application(current, candidate)?.1 != 11 {
        return Err(REFUSAL);
    }
    let original_bytes = read_owned(observed, MAX_OBJECT, &[0o600])?.0;
    let original: Value = serde_json::from_slice(&original_bytes).map_err(|_| REFUSAL)?;
    let (patch, expected) = transition(
        &original,
        namespace,
        activation,
        &token_inputs(&current_before)?,
        &token_inputs(&candidate_before)?,
    )?;
    let mut response = json!({"ready":true,"secret":DESTINATION,"count":11});
    let prepared = match &request {
        Request::Prepare { output, .. } => {
            owned_directory(output.parent().ok_or(REFUSAL)?)?;
            if output.starts_with(current) || output.starts_with(candidate) {
                return Err(REFUSAL);
            }
            let bytes = serde_json::to_vec(&patch).map_err(|_| REFUSAL)?;
            if bytes.len() > MAX_OBJECT {
                return Err(REFUSAL);
            }
            Some((output, bytes))
        }
        Request::Verify { result, .. } => {
            let result: Value =
                serde_json::from_slice(&read_owned(result, MAX_OBJECT, &[0o600])?.0)
                    .map_err(|_| REFUSAL)?;
            response["state"] =
                Value::String(classify(&original, &expected, &result, namespace)?.into());
            None
        }
    };
    if snapshot(current)? != current_before
        || snapshot(candidate)? != candidate_before
        || read_owned(observed, MAX_OBJECT, &[0o600])?.0 != original_bytes
    {
        return Err(REFUSAL);
    }
    if let Some((output, bytes)) = prepared {
        let mut file = generation_output(output)?;
        finish_generation(&mut file, &bytes, 0o600)?;
        fs::File::open(output.parent().ok_or(REFUSAL)?)
            .and_then(|folder| folder.sync_all())
            .map_err(|_| REFUSAL)?;
        if read_owned(output, MAX_OBJECT, &[0o600])?.0 != bytes {
            return Err(REFUSAL);
        }
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "0123456789abcdef0123456789abcdef";

    fn fixture() -> (Value, Inputs, Inputs) {
        let mut observed = json!({"apiVersion":"v1","kind":"Secret","metadata":{
            "name":DESTINATION,"namespace":"marty-test","uid":"11111111-2222-4333-8444-555555555555",
            "resourceVersion":"88","annotations":{"operator.example/keep":"unchanged"}},"type":"Opaque","data":{}});
        let mut current = Inputs::new();
        let mut candidate = Inputs::new();
        for item in mappings().unwrap() {
            let old = format!("PRIVATE_OLD_CANARY_{}", item.input);
            observed["data"][&item.key] = STANDARD.encode(&old).into();
            current.insert(item.key.clone(), old);
            candidate.insert(item.key, format!("PRIVATE_NEW_CANARY_{}", item.input));
        }
        observed["data"]["TOKEN_HMAC_KEY"] = STANDARD.encode("PRIVATE_PRESERVED_CANARY").into();
        observed["data"]["OPENBAO_BOOTSTRAP_TOKEN"] =
            STANDARD.encode("PRIVATE_INITIAL_CANARY").into();
        (observed, current, candidate)
    }

    #[cfg(unix)]
    fn disk_fixture() -> (tempfile::TempDir, Value, Value) {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let current = root.path().join("current");
        let candidate = root.path().join("candidate");
        for path in [&current, &candidate] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut names = BTreeSet::from(["workload_identity_ca_cert".to_owned()]);
        for role in marty_selfhost_identity::SELFHOST_ROLES {
            names.insert(role.cert_file.into());
            names.insert(role.token_file.into());
        }
        names.insert("keycloak_signing_kms_token".into());
        for realm in crate::keycloak::REALMS {
            names.insert(format!("keycloak_{realm}_rs256_cert"));
            for purpose in crate::keycloak::PURPOSES {
                names.insert(format!("keycloak_{realm}_{purpose}_token"));
            }
        }
        names.extend(
            application_tokens::specifications()
                .into_iter()
                .map(|spec| spec.file),
        );
        let (observed, old, new) = fixture();
        for name in names {
            let input = name.to_ascii_uppercase();
            let before = old
                .get(&input)
                .cloned()
                .unwrap_or_else(|| format!("PRIVATE_UNCHANGED_CANARY_{name}"));
            let after = new.get(&input).unwrap_or(&before);
            for (directory, value) in [(&current, &before), (&candidate, after)] {
                let path = directory.join(&name);
                fs::write(&path, value.as_bytes()).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        for directory in [&current, &candidate] {
            let path = directory.join("optional-empty");
            fs::write(&path, []).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o640)).unwrap();
        }
        let source = root.path().join("before.json");
        fs::write(&source, serde_json::to_vec(&observed).unwrap()).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        let request = json!({"operation":"prepare","namespace":"marty-test","current":current,
            "candidate":candidate,"observed":source,"output":root.path().join("patch.json"),"activationId":ID});
        (root, request, observed)
    }

    #[cfg(unix)]
    #[test]
    fn private_operation_verifies_full_generation_and_never_returns_payloads() {
        use std::os::unix::fs::PermissionsExt;
        let (root, request, observed) = disk_fixture();
        let current = Path::new(request["current"].as_str().unwrap());
        let candidate = Path::new(request["candidate"].as_str().unwrap());
        let before = snapshot(current).unwrap();
        let after = snapshot(candidate).unwrap();
        let response = operation(&request).unwrap();
        assert_eq!(
            response,
            json!({"ready":true,"secret":DESTINATION,"count":11})
        );
        assert!(!response.to_string().contains("PRIVATE_"));
        let patch = root.path().join("patch.json");
        assert_eq!(
            fs::metadata(&patch).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        let actual: Value = serde_json::from_slice(&fs::read(&patch).unwrap()).unwrap();
        let (expected_patch, mut applied) = transition(
            &observed,
            "marty-test",
            ID,
            &token_inputs(&before).unwrap(),
            &token_inputs(&after).unwrap(),
        )
        .unwrap();
        assert_eq!(actual, expected_patch);
        applied["metadata"]["resourceVersion"] = json!("89");
        let result = root.path().join("after.json");
        fs::write(&result, serde_json::to_vec(&applied).unwrap()).unwrap();
        fs::set_permissions(&result, fs::Permissions::from_mode(0o600)).unwrap();
        let mut verify = request.clone();
        verify["operation"] = json!("verify");
        verify.as_object_mut().unwrap().remove("output");
        verify["result"] = json!(result);
        assert_eq!(operation(&verify).unwrap()["state"], "candidate");
        assert_eq!(snapshot(current).unwrap(), before);
        assert_eq!(snapshot(candidate).unwrap(), after);
    }

    #[cfg(unix)]
    #[test]
    fn private_operation_preserves_existing_outputs_and_refuses_generation_drift() {
        use std::os::unix::fs::PermissionsExt;
        let (root, request, _) = disk_fixture();
        let output = root.path().join("patch.json");
        fs::write(&output, b"keep-existing-private-output").unwrap();
        fs::set_permissions(&output, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(operation(&request).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"keep-existing-private-output");
        fs::remove_file(&output).unwrap();
        let candidate = Path::new(request["candidate"].as_str().unwrap());
        let drift = candidate.join("keycloak_master_rs256_cert");
        assert!(drift.exists());
        fs::write(&drift, b"PRIVATE_CHANGED_UNRELATED_INPUT").unwrap();
        assert!(operation(&request).is_err());
        assert!(!output.exists());
    }

    #[cfg(unix)]
    #[test]
    fn private_operation_refuses_public_aliases_and_writes_inside_generations() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let (root, request, _) = disk_fixture();
        let original = Path::new(request["observed"].as_str().unwrap());
        let alias = root.path().join("aliased.json");
        symlink(original, &alias).unwrap();
        let mut changed = request.clone();
        changed["observed"] = json!(alias);
        assert!(operation(&changed).is_err());
        fs::set_permissions(original, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(operation(&request).is_err());
        fs::set_permissions(original, fs::Permissions::from_mode(0o600)).unwrap();
        changed = request.clone();
        changed["output"] =
            json!(Path::new(request["candidate"].as_str().unwrap()).join("new-patch.json"));
        assert!(operation(&changed).is_err());
        assert!(!root.path().join("patch.json").exists());
    }

    #[test]
    fn metadata_has_exact_restricted_mapping_and_no_initial_authority() {
        let metadata = activation_metadata();
        assert_eq!(metadata["inputs"].as_array().unwrap().len(), 11);
        assert_eq!(metadata["minimumTtlSeconds"], 1800);
        let text = metadata.to_string();
        assert!(!text.contains("OPENBAO_BOOTSTRAP_TOKEN"));
        assert!(!text.contains("\"OPENBAO_SERVICE_TOKEN\""));
        assert!(text.contains("SIGNING_KEYS_OPENBAO_TOKEN"));
    }

    #[test]
    fn patch_guards_object_identity_and_changes_only_eleven_data_keys_and_marker() {
        let (observed, current, candidate) = fixture();
        let (patch, expected) =
            transition(&observed, "marty-test", ID, &current, &candidate).unwrap();
        let operations = patch.as_array().unwrap();
        assert_eq!(operations.len(), 14);
        assert_eq!(
            operations[0],
            json!({"op":"test","path":"/metadata/uid","value":observed["metadata"]["uid"]})
        );
        assert_eq!(
            operations[1],
            json!({"op":"test","path":"/metadata/resourceVersion","value":"88"})
        );
        assert_eq!(
            operations[2..13]
                .iter()
                .map(|op| op["path"].as_str().unwrap().strip_prefix("/data/").unwrap())
                .collect::<BTreeSet<_>>(),
            current.keys().map(String::as_str).collect()
        );
        for (key, value) in observed["data"].as_object().unwrap() {
            assert_eq!(
                &expected["data"][key],
                &candidate.get(key).map_or_else(
                    || value.clone(),
                    |value| Value::String(STANDARD.encode(value))
                )
            );
        }
        assert_eq!(
            expected["metadata"]["annotations"]["operator.example/keep"],
            "unchanged"
        );
        assert_eq!(
            expected["metadata"]["annotations"][ACTIVATION_ANNOTATION],
            ID
        );
        assert_eq!(observed["metadata"]["resourceVersion"], "88");
    }

    #[test]
    fn publication_rejects_wrong_type_namespace_immutability_and_current_values() {
        let (observed, current, candidate) = fixture();
        for path in [
            "/type",
            "/metadata/namespace",
            "/metadata/name",
            "/metadata/uid",
            "/metadata/resourceVersion",
            "/data/SIGNING_KEYS_OPENBAO_TOKEN",
        ] {
            let mut value = observed.clone();
            *value.pointer_mut(path).unwrap() = Value::String(String::new());
            assert_eq!(
                transition(&value, "marty-test", ID, &current, &candidate).unwrap_err(),
                REFUSAL
            );
        }
        for immutable in [json!(true), json!("false"), Value::Null] {
            let mut value = observed.clone();
            value["immutable"] = immutable;
            assert!(transition(&value, "marty-test", ID, &current, &candidate).is_err());
        }
        let mut deleting = observed.clone();
        deleting["metadata"]["deletionTimestamp"] = json!("2026-01-01T00:00:00Z");
        assert!(transition(&deleting, "marty-test", ID, &current, &candidate).is_err());
        assert!(transition(&observed, "wrong", ID, &current, &candidate).is_err());
        assert!(transition(
            &observed,
            "marty-test",
            "PRIVATE_INVALID_ID",
            &current,
            &candidate
        )
        .is_err());
    }

    #[test]
    fn publication_rejects_missing_reused_shared_and_aliased_replacements() {
        let (observed, current, candidate) = fixture();
        for key in candidate.keys() {
            let mut value = candidate.clone();
            value.remove(key);
            assert!(transition(&observed, "marty-test", ID, &current, &value).is_err());
            for old in current.values() {
                let mut value = candidate.clone();
                value.insert(key.clone(), old.clone());
                assert!(transition(&observed, "marty-test", ID, &current, &value).is_err());
            }
        }
        let mut shared = candidate.clone();
        let value = shared.values().next().unwrap().clone();
        shared.values_mut().for_each(|item| *item = value.clone());
        assert!(transition(&observed, "marty-test", ID, &current, &shared).is_err());
        let mut missing = observed.clone();
        missing["data"]
            .as_object_mut()
            .unwrap()
            .remove("FLOW_SIGN_GRANT_MINT_TOKEN");
        assert!(transition(&missing, "marty-test", ID, &current, &candidate).is_err());
    }

    #[test]
    fn same_attempt_outcome_distinguishes_unchanged_candidate_and_conflict() {
        let (observed, current, candidate) = fixture();
        let (_, expected) = transition(&observed, "marty-test", ID, &current, &candidate).unwrap();
        assert_eq!(
            classify(&observed, &expected, &observed, "marty-test").unwrap(),
            "unchanged"
        );
        let mut applied = expected.clone();
        applied["metadata"]["resourceVersion"] = json!("89");
        applied["metadata"]["managedFields"] = json!([{"manager":"kubectl-patch"}]);
        assert_eq!(
            classify(&observed, &expected, &applied, "marty-test").unwrap(),
            "candidate"
        );
        for path in [
            "/metadata/uid",
            "/metadata/annotations/operator.example~1keep",
            "/data/TOKEN_HMAC_KEY",
            "/data/SIGNING_KEYS_OPENBAO_TOKEN",
        ] {
            let mut wrong = applied.clone();
            *wrong.pointer_mut(path).unwrap() = json!("PRIVATE_FOREIGN_CANARY");
            assert!(classify(&observed, &expected, &wrong, "marty-test").is_err());
        }
        let mut conflicting = observed.clone();
        conflicting["metadata"]["resourceVersion"] = json!("89");
        assert!(classify(&observed, &expected, &conflicting, "marty-test").is_err());
        let mut foreign = applied.clone();
        foreign["metadata"]["annotations"][ACTIVATION_ANNOTATION] =
            json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(classify(&observed, &expected, &foreign, "marty-test").is_err());
        assert!(classify(&observed, &expected, &expected, "marty-test").is_err());
    }

    #[test]
    fn refuses_unknown_context_fields_and_nonprivate_observations() {
        assert!(operation(&json!({"operation":"prepare","rootToken":"PRIVATE_CANARY"})).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            let root = tempfile::tempdir().unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let path = root.path().join("object.json");
            fs::write(&path, b"PRIVATE_OBSERVATION_CANARY").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read_owned(&path, MAX_OBJECT, &[0o600]).is_err());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(
                read_owned(&path, MAX_OBJECT, &[0o600]).unwrap().0,
                b"PRIVATE_OBSERVATION_CANARY"
            );
            let alias = root.path().join("alias");
            symlink(&path, &alias).unwrap();
            assert!(read_owned(&alias, MAX_OBJECT, &[0o600]).is_err());
            fs::remove_file(alias).unwrap();
            fs::hard_link(&path, root.path().join("hardlink")).unwrap();
            assert!(read_owned(&path, MAX_OBJECT, &[0o600]).is_err());
        }
    }
}
