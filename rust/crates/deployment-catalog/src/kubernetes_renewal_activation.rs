//! Restricted renewal payloads for existing Kubernetes Secrets. Each object has
//! its own UID/resourceVersion precondition; this is not a multi-object transaction.
//! The caller keeps observations and patches private and never replays an uncertain request.
use crate::{
    generation,
    kubernetes_application::{
        classify_secret_object, owned_directory, read_owned, snapshot, transition_secret_object,
        valid_activation, valid_namespace, Inputs, Snapshot, MAX_OBJECT,
    },
    kubernetes_secrets,
    operator::{Result, REFUSAL},
    operator_files::{finish_generation, generation_output},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

pub const ACTIVATION_ANNOTATION: &str = "marty.elevenid.com/renewal-activation";

#[derive(Clone, Debug, Serialize)]
struct Mapping {
    input: String,
    file: String,
    secret: String,
    key: String,
}

fn mappings() -> Result<Vec<Mapping>> {
    let (tls, keycloak, _) = generation::inventories();
    let publication = kubernetes_secrets::contract();
    let secrets = publication["catalog"]["secrets"]
        .as_array()
        .ok_or(REFUSAL)?;
    let mut mappings = Vec::new();
    let mut keys = BTreeSet::new();
    for file in tls
        .union(&keycloak)
        .filter(|file| file.as_str() != "workload_identity_ca_cert")
    {
        let input = file.to_ascii_uppercase();
        let mut matches = Vec::new();
        for secret in secrets {
            let name = secret["name"].as_str().ok_or(REFUSAL)?;
            for (key, field) in secret["fields"].as_object().ok_or(REFUSAL)? {
                if field["env"] == input {
                    if field.as_object().is_none_or(|field| field.len() != 1)
                        || !keys.insert((name.to_owned(), key.clone()))
                    {
                        return Err(REFUSAL);
                    }
                    matches.push(Mapping {
                        input: input.clone(),
                        file: file.clone(),
                        secret: name.into(),
                        key: key.clone(),
                    });
                }
            }
        }
        if matches.len() != 1 {
            return Err(REFUSAL);
        }
        mappings.push(matches.remove(0));
    }
    let destinations = mappings
        .iter()
        .map(|item| &item.secret)
        .collect::<BTreeSet<_>>();
    if mappings.len() != 39
        || destinations.len() != 33
        || destinations.iter().any(|name| {
            matches!(
                name.as_str(),
                "marty-secrets" | "cloudflared-secret" | "signing-keys-integration-secret-ca"
            )
        })
    {
        return Err(REFUSAL);
    }
    mappings.sort_by(|left, right| left.input.cmp(&right.input));
    Ok(mappings)
}

/// Public compiled names only; no repository, file, credential or cluster I/O.
pub fn metadata() -> Value {
    json!({
        "schema":"marty.kubernetes-renewal-activation/v1",
        "minimumTtlSeconds":crate::kubernetes_renewal::MINIMUM_TTL,
        "secretCount":33,"changedFiles":39,"activationAnnotation":ACTIVATION_ANNOTATION,
        "inputs":mappings().expect("compiled Renewal activation mapping must be valid"),
    })
}

fn published(bytes: &[u8]) -> Result<String> {
    if bytes.is_empty() || bytes.len() > 65536 || !bytes.is_ascii() || bytes.contains(&0) {
        return Err(REFUSAL);
    }
    let value =
        kubernetes_secrets::normalize_file_value(std::str::from_utf8(bytes).map_err(|_| REFUSAL)?);
    if value.is_empty() {
        return Err(REFUSAL);
    }
    Ok(value)
}

/// Whole-generation preservation and normalized replacement semantics are
/// checked before either fresh live verification or any private patch is made.
pub(crate) fn qualify_generation(current: &Path, candidate: &Path) -> Result<(Snapshot, Snapshot)> {
    let before = snapshot(current)?;
    let after = snapshot(candidate)?;
    if generation::verify(current, candidate, false, false)? != (before.len(), 39) {
        return Err(REFUSAL);
    }
    let (_, _, tokens) = generation::inventories();
    let mut previous_tokens = BTreeSet::new();
    let mut replacements = BTreeSet::new();
    for file in &tokens {
        let token = published(&before.get(file).ok_or(REFUSAL)?.0)?;
        if !(20..=1024).contains(&token.len()) || !token.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(REFUSAL);
        }
        previous_tokens.insert(token);
    }
    for mapping in mappings()? {
        let old = published(&before.get(&mapping.file).ok_or(REFUSAL)?.0)?;
        let new = published(&after.get(&mapping.file).ok_or(REFUSAL)?.0)?;
        if old == new {
            return Err(REFUSAL);
        }
        if tokens.contains(&mapping.file)
            && (!(20..=1024).contains(&new.len())
                || !new.bytes().all(|byte| byte.is_ascii_graphic())
                || previous_tokens.contains(&new)
                || !replacements.insert(new))
        {
            return Err(REFUSAL);
        }
    }
    if snapshot(current)? != before || snapshot(candidate)? != after {
        return Err(REFUSAL);
    }
    Ok((before, after))
}

fn inputs(values: &Snapshot, mappings: &[Mapping]) -> Result<Inputs> {
    mappings
        .iter()
        .map(|mapping| {
            Ok((
                mapping.key.clone(),
                published(&values.get(&mapping.file).ok_or(REFUSAL)?.0)?,
            ))
        })
        .collect()
}

fn retained_fields(observed: &Value, secret: &str, before: &Snapshot) -> Result<()> {
    // Bootstrap creates these objects directly. A controller-owned destination
    // belongs to another lifecycle owner and must not be adopted by this command.
    if observed["metadata"]
        .get("ownerReferences")
        .is_some_and(|owners| owners != &json!([]))
    {
        return Err(REFUSAL);
    }
    let publication = kubernetes_secrets::contract();
    let entry = publication["catalog"]["secrets"]
        .as_array()
        .ok_or(REFUSAL)?
        .iter()
        .find(|item| item["name"] == secret)
        .ok_or(REFUSAL)?;
    for (key, field) in entry["fields"].as_object().ok_or(REFUSAL)? {
        let input = field["env"].as_str().ok_or(REFUSAL)?;
        if field.as_object().is_none_or(|field| field.len() != 1) {
            return Err(REFUSAL);
        }
        let file = if input == "MARTY_WORKLOAD_IDENTITY_CA_CERT" {
            "workload_identity_ca_cert".to_owned()
        } else {
            input.to_ascii_lowercase()
        };
        let expected = published(&before.get(&file).ok_or(REFUSAL)?.0)?;
        if observed["data"][key].as_str() != Some(&STANDARD.encode(expected)) {
            return Err(REFUSAL);
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "lowercase", deny_unknown_fields)]
enum Request {
    Prepare {
        namespace: String,
        secret: String,
        current: PathBuf,
        candidate: PathBuf,
        observed: PathBuf,
        output: PathBuf,
        #[serde(rename = "activationId")]
        activation_id: String,
    },
    Verify {
        namespace: String,
        secret: String,
        current: PathBuf,
        candidate: PathBuf,
        observed: PathBuf,
        result: PathBuf,
        #[serde(rename = "activationId")]
        activation_id: String,
    },
}

/// Prepare or classify one private, conditional Secret update. Never dispatches
/// Kubernetes I/O, creates a Secret, issues credentials or prints patch payloads.
pub fn operation(context: &Value) -> Result<Value> {
    let request: Request = serde_json::from_value(context.clone()).map_err(|_| REFUSAL)?;
    let (namespace, secret, current, candidate, observed, activation) = match &request {
        Request::Prepare {
            namespace,
            secret,
            current,
            candidate,
            observed,
            activation_id,
            ..
        }
        | Request::Verify {
            namespace,
            secret,
            current,
            candidate,
            observed,
            activation_id,
            ..
        } => (
            namespace,
            secret,
            current,
            candidate,
            observed,
            activation_id,
        ),
    };
    if !valid_namespace(namespace) || !valid_activation(activation) {
        return Err(REFUSAL);
    }
    let selected = mappings()?
        .into_iter()
        .filter(|entry| entry.secret == *secret)
        .collect::<Vec<_>>();
    if selected.is_empty() || selected.len() != if secret == "keycloak-kms" { 7 } else { 1 } {
        return Err(REFUSAL);
    }
    let (before, after) = qualify_generation(current, candidate)?;
    let original_bytes = read_owned(observed, MAX_OBJECT, &[0o600])?.0;
    let original: Value = serde_json::from_slice(&original_bytes).map_err(|_| REFUSAL)?;
    retained_fields(&original, secret, &before)?;
    let (patch, expected) = transition_secret_object(
        &original,
        namespace,
        secret,
        ACTIVATION_ANNOTATION,
        activation,
        &inputs(&before, &selected)?,
        &inputs(&after, &selected)?,
    )?;
    let mut response = json!({"ready":true,"secret":secret,"count":selected.len()});
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
            response["state"] = Value::String(
                classify_secret_object(
                    &original,
                    &expected,
                    &result,
                    namespace,
                    secret,
                    ACTIVATION_ANNOTATION,
                )?
                .into(),
            );
            None
        }
    };
    if snapshot(current)? != before
        || snapshot(candidate)? != after
        || read_owned(observed, MAX_OBJECT, &[0o600])?.0 != original_bytes
    {
        return Err(REFUSAL);
    }
    if let Some((output, bytes)) = prepared {
        let mut file = generation_output(output)?;
        finish_generation(&mut file, &bytes, 0o600)?;
        fs::File::open(output.parent().ok_or(REFUSAL)?)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| REFUSAL)?;
        if read_owned(output, MAX_OBJECT, &[0o600])?.0 != bytes {
            return Err(REFUSAL);
        }
    }
    Ok(response)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, DirBuilderExt, PermissionsExt};

    const ID: &str = "0123456789abcdef0123456789abcdef";

    fn put(path: &Path, bytes: &[u8], mode: u32) {
        if path.exists() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    struct Fixture {
        _root: tempfile::TempDir,
        current: PathBuf,
        candidate: PathBuf,
        output: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let child = |name| {
                let path = root.path().join(name);
                fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
                path
            };
            let current = child("current");
            let candidate = child("candidate");
            let output = child("output");
            let (tls, keycloak, tokens) = generation::inventories();
            for (index, name) in tls.union(&keycloak).enumerate() {
                for (root, prefix) in [(&current, "old"), (&candidate, "new")] {
                    let bytes = if name == "workload_identity_ca_cert" {
                        b"unchanged-workload-ca\r\n".to_vec()
                    } else if tokens.contains(name) {
                        format!("synthetic-{prefix}-scoped-token-{name}\n").into_bytes()
                    } else {
                        format!("-----BEGIN CERTIFICATE-----\r\nsynthetic-{prefix}-{name}\r\n-----END CERTIFICATE-----\r\n").into_bytes()
                    };
                    put(
                        &root.join(name),
                        &bytes,
                        [0o400, 0o440, 0o444, 0o600, 0o640, 0o644][index % 6],
                    );
                }
            }
            for root in [&current, &candidate] {
                put(
                    &root.join("openbao_tls_ca_cert"),
                    b"unchanged-openbao-ca\n",
                    0o444,
                );
                put(
                    &root.join("ordinary_token"),
                    b"existing-ordinary-scope-unchanged",
                    0o440,
                );
                put(&root.join("extra_empty"), b"", 0o400);
            }
            Self {
                _root: root,
                current,
                candidate,
                output,
            }
        }

        fn observed(&self, secret: &str) -> Value {
            let before = snapshot(&self.current).unwrap();
            let publication = kubernetes_secrets::contract();
            let entry = publication["catalog"]["secrets"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["name"] == secret)
                .unwrap();
            let mut data = serde_json::Map::new();
            for (key, field) in entry["fields"].as_object().unwrap() {
                let input = field["env"].as_str().unwrap();
                let file = if input == "MARTY_WORKLOAD_IDENTITY_CA_CERT" {
                    "workload_identity_ca_cert".to_owned()
                } else {
                    input.to_ascii_lowercase()
                };
                data.insert(
                    key.clone(),
                    json!(STANDARD.encode(published(&before[&file].0).unwrap())),
                );
            }
            data.insert(
                "unrelated".into(),
                json!(STANDARD.encode(b"preserve-extra-value")),
            );
            json!({"apiVersion":"v1","kind":"Secret","type":"Opaque","metadata":{
                "name":secret,"namespace":"renewal-test","uid":format!("uid-{secret}"),"resourceVersion":"77",
                "labels":{"retained":"value"},"annotations":{"retained":"annotation"},
                "managedFields":[{"manager":"bootstrap"}],
            },"data":data})
        }

        fn request(&self, secret: &str, observed: &Value) -> Value {
            let observation = self.output.join(format!("{secret}-before.json"));
            put(&observation, &serde_json::to_vec(observed).unwrap(), 0o600);
            json!({"operation":"prepare","namespace":"renewal-test","secret":secret,
                "current":self.current,"candidate":self.candidate,"observed":observation,
                "output":self.output.join(format!("{secret}-patch.json")),"activationId":ID})
        }

        fn result(&self, request: &Value, value: &Value) -> Value {
            let path = self.output.join("result.json");
            put(&path, &serde_json::to_vec(value).unwrap(), 0o600);
            let mut request = request.clone();
            request.as_object_mut().unwrap().remove("output");
            request["operation"] = json!("verify");
            request["result"] = json!(path);
            request
        }
    }

    #[test]
    fn metadata_is_the_exact_compiled_renewable_mapping_without_other_owners() {
        let value = metadata();
        assert_eq!(value["secretCount"], 33);
        assert_eq!(value["changedFiles"], 39);
        assert_eq!(value["minimumTtlSeconds"], 3600);
        assert_eq!(value["activationAnnotation"], ACTIVATION_ANNOTATION);
        let inputs = value["inputs"].as_array().unwrap();
        assert_eq!(inputs.len(), 39);
        assert!(inputs
            .windows(2)
            .all(|pair| pair[0]["input"].as_str() < pair[1]["input"].as_str()));
        assert_eq!(
            inputs
                .iter()
                .filter(|entry| entry["secret"] == "keycloak-kms")
                .count(),
            7
        );
        assert!(inputs
            .iter()
            .all(|entry| entry["file"] != "workload_identity_ca_cert"
                && entry["secret"] != "marty-secrets"
                && entry["secret"] != "marty-redis-tls"));
    }

    #[test]
    fn every_secret_patch_changes_only_its_compiled_fields_and_preserves_all_other_bytes() {
        let fixture = Fixture::new();
        let before_files = snapshot(&fixture.current).unwrap();
        let after_files = snapshot(&fixture.candidate).unwrap();
        let mappings = mappings().unwrap();
        let destinations = mappings
            .iter()
            .map(|entry| entry.secret.clone())
            .collect::<BTreeSet<_>>();
        for secret in destinations {
            let observed = fixture.observed(&secret);
            let request = fixture.request(&secret, &observed);
            let selected = mappings
                .iter()
                .filter(|entry| entry.secret == secret)
                .collect::<Vec<_>>();
            assert_eq!(
                operation(&request).unwrap(),
                json!({"ready":true,"secret":secret,"count":selected.len()})
            );
            let patch: Value = serde_json::from_slice(
                &read_owned(
                    Path::new(request["output"].as_str().unwrap()),
                    MAX_OBJECT,
                    &[0o600],
                )
                .unwrap()
                .0,
            )
            .unwrap();
            let patch = patch.as_array().unwrap();
            assert_eq!(patch.len(), selected.len() + 3);
            assert_eq!(
                patch[0],
                json!({"op":"test","path":"/metadata/uid","value":observed["metadata"]["uid"]})
            );
            assert_eq!(
                patch[1],
                json!({"op":"test","path":"/metadata/resourceVersion","value":"77"})
            );
            let mut expected = observed.clone();
            for mapping in &selected {
                let bytes = published(&after_files[&mapping.file].0).unwrap();
                assert!(!bytes.contains('\r') && !bytes.ends_with('\n'));
                expected["data"][&mapping.key] = json!(STANDARD.encode(bytes));
                assert!(patch.iter().any(|item| item == &json!({"op":"replace",
                    "path":format!("/data/{}",mapping.key),"value":expected["data"][&mapping.key]})));
            }
            expected["metadata"]["annotations"][ACTIVATION_ANNOTATION] = json!(ID);
            expected["metadata"]["resourceVersion"] = json!("78");
            expected["metadata"]["managedFields"] = json!([{"manager":"kubectl-patch"}]);
            assert_eq!(
                operation(&fixture.result(&request, &expected)).unwrap()["state"],
                "candidate"
            );
            assert_eq!(
                operation(&fixture.result(&request, &observed)).unwrap()["state"],
                "unchanged"
            );
            assert_eq!(expected["data"]["unrelated"], observed["data"]["unrelated"]);
            assert_eq!(
                expected["metadata"]["annotations"]["retained"],
                "annotation"
            );
        }
        assert_eq!(snapshot(&fixture.current).unwrap(), before_files);
        assert_eq!(snapshot(&fixture.candidate).unwrap(), after_files);
    }

    #[test]
    fn publication_refuses_foreign_owner_changed_trust_or_wrong_live_values_before_output() {
        for case in 0..10 {
            let fixture = Fixture::new();
            let mut observed = fixture.observed("keycloak-kms");
            match case {
                0 => observed["data"]["openbao_tls_ca_cert"] = json!(STANDARD.encode(b"wrong-ca")),
                1 => observed["data"]
                    .as_object_mut()
                    .unwrap()
                    .remove("master-cookie.token")
                    .map(|_| ())
                    .unwrap(),
                2 => {
                    observed["data"]["keycloak_signing_kms_token"] =
                        json!(STANDARD.encode(b"wrong-token"))
                }
                3 => {
                    observed["metadata"]["ownerReferences"] =
                        json!([{"kind":"Certificate","uid":"foreign"}])
                }
                4 => observed["type"] = json!("kubernetes.io/tls"),
                5 => observed["immutable"] = json!(true),
                6 => observed["metadata"]["namespace"] = json!("other"),
                7 => observed["metadata"]["name"] = json!("marty-secrets"),
                8 => observed["metadata"]["annotations"][ACTIVATION_ANNOTATION] = json!(ID),
                _ => observed["data"]["unrelated"] = json!("noncanonical-base64"),
            }
            let request = fixture.request("keycloak-kms", &observed);
            assert!(operation(&request).is_err(), "case {case}");
            assert!(!Path::new(request["output"].as_str().unwrap()).exists());
        }
    }

    #[test]
    fn classifier_refuses_partial_updates_recreated_identity_and_competing_changes() {
        let fixture = Fixture::new();
        let observed = fixture.observed("keycloak-kms");
        let request = fixture.request("keycloak-kms", &observed);
        let (before, after) = qualify_generation(&fixture.current, &fixture.candidate).unwrap();
        let selected = mappings()
            .unwrap()
            .into_iter()
            .filter(|entry| entry.secret == "keycloak-kms")
            .collect::<Vec<_>>();
        let (_, mut expected) = transition_secret_object(
            &observed,
            "renewal-test",
            "keycloak-kms",
            ACTIVATION_ANNOTATION,
            ID,
            &inputs(&before, &selected).unwrap(),
            &inputs(&after, &selected).unwrap(),
        )
        .unwrap();
        expected["metadata"]["resourceVersion"] = json!("78");
        for case in 0..7 {
            let mut result = expected.clone();
            match case {
                0 => result["metadata"]["uid"] = json!("recreated"),
                1 => result["metadata"]["resourceVersion"] = json!("77"),
                2 => {
                    result["data"]["11id-cookie.token"] =
                        observed["data"]["11id-cookie.token"].clone()
                }
                3 => result["metadata"]["annotations"]["retained"] = json!("changed"),
                4 => result["data"]["unrelated"] = json!(STANDARD.encode(b"concurrent-value")),
                5 => {
                    result = observed.clone();
                    result["metadata"]["resourceVersion"] = json!("78");
                }
                _ => {
                    result = observed.clone();
                    result["metadata"]["managedFields"] = json!([]);
                }
            }
            assert!(
                operation(&fixture.result(&request, &result)).is_err(),
                "case {case}"
            );
        }
    }

    #[test]
    fn full_generation_and_normalized_renewal_must_change_exactly_the_selected_inputs() {
        for case in 0..7 {
            let fixture = Fixture::new();
            let (name, bytes) = match case {
                0 => ("ordinary_token", b"changed-ordinary-scope".to_vec()),
                1 => ("workload_identity_ca_cert", b"new-ca".to_vec()),
                2 => (
                    "keycloak_master_rs256_cert",
                    fs::read(fixture.current.join("keycloak_master_rs256_cert"))
                        .unwrap()
                        .into_iter()
                        .filter(|byte| *byte != b'\r')
                        .collect(),
                ),
                3 => (
                    "keycloak_master_cookie_token",
                    fs::read(fixture.current.join("keycloak_11id_cookie_token")).unwrap(),
                ),
                4 => (
                    "keycloak_master_cookie_token",
                    fs::read(fixture.candidate.join("keycloak_11id_cookie_token")).unwrap(),
                ),
                5 => (
                    "keycloak_master_cookie_token",
                    b"invalid token whitespace".to_vec(),
                ),
                _ => ("keycloak_master_cookie_token", b"short".to_vec()),
            };
            let mode = snapshot(&fixture.candidate).unwrap()[name].1;
            put(&fixture.candidate.join(name), &bytes, mode);
            assert!(
                qualify_generation(&fixture.current, &fixture.candidate).is_err(),
                "case {case}"
            );
        }
    }

    #[test]
    fn publication_rejects_unknown_requests_aliases_and_nonprivate_observation_without_overwrite() {
        let fixture = Fixture::new();
        let observed = fixture.observed("keycloak-kms");
        let mut request = fixture.request("keycloak-kms", &observed);
        request["extra"] = json!("must-refuse");
        assert!(operation(&request).is_err());
        request.as_object_mut().unwrap().remove("extra");
        request["secret"] = json!("marty-secrets");
        assert!(operation(&request).is_err());
        request["secret"] = json!("keycloak-kms");
        let observation = Path::new(request["observed"].as_str().unwrap());
        fs::set_permissions(observation, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(operation(&request).is_err());
        fs::set_permissions(observation, fs::Permissions::from_mode(0o600)).unwrap();
        let output = PathBuf::from(request["output"].as_str().unwrap());
        symlink(observation, &output).unwrap();
        assert!(operation(&request).is_err());
        assert_eq!(
            read_owned(observation, MAX_OBJECT, &[0o600]).unwrap().0,
            serde_json::to_vec(&observed).unwrap()
        );
        fs::remove_file(&output).unwrap();
        put(&output, b"existing-output", 0o600);
        assert!(operation(&request).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"existing-output");
        request["output"] = json!(fixture.candidate.join("new-output"));
        assert!(operation(&request).is_err());
        assert!(!fixture.candidate.join("new-output").exists());
    }
}
