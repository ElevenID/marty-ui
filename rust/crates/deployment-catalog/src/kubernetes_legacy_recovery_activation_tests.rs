use super::*;

#[derive(Clone)]
struct Fixture {
    current: Generation,
    candidate: Generation,
    binding: Binding,
    observed: Value,
}

fn input_file(input: &str) -> String {
    if input == "MARTY_WORKLOAD_IDENTITY_CA_CERT" {
        "workload_identity_ca_cert".into()
    } else {
        input.to_ascii_lowercase()
    }
}

fn publication(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec())
        .unwrap()
        .replace('\r', "")
        .trim_end_matches('\n')
        .to_owned()
}

fn fixture() -> Fixture {
    let binding = Binding {
        bootstrap_id: "00000000-0000-4000-8000-000000000001".into(),
        namespace: "marty-retained-dev".into(),
        namespace_uid: "00000000-0000-4000-8000-000000000002".into(),
        openbao_cluster_id: "00000000-0000-4000-8000-000000000003".into(),
        producer_nonce: "abcdef012345".into(),
        workload_project: "marty-selfhost-disposable-k8s-abcdef012345".into(),
        runtime_source_sha: super::super::LEGACY_RUNTIME.into(),
        chart_source_sha: "a".repeat(40),
    };
    let files = replacements(&binding).unwrap();
    let catalog = crate::kubernetes_secrets::contract()["catalog"].clone();
    let mut current = Generation::new();
    for secret in catalog["secrets"].as_array().unwrap() {
        for field in secret["fields"].as_object().unwrap().values() {
            if let Some(input) = field["env"].as_str() {
                let file = input_file(input);
                current.insert(
                    file.clone(),
                    (format!("retained-static-{file}\r\n\n").into_bytes(), 0o600),
                );
            }
        }
    }
    current.insert(
        "unmapped_static_input".into(),
        (b"unchanged".to_vec(), 0o640),
    );
    current.insert("optional_empty_input".into(), (Vec::new(), 0o600));
    for (index, file) in files.iter().enumerate() {
        let mode = [0o400, 0o440, 0o444, 0o600, 0o640, 0o644][index % 6];
        current.insert(
            file.clone(),
            (format!("retained-{file}\r\n\n").into_bytes(), mode),
        );
    }
    let mut candidate = current.clone();
    for file in &files {
        candidate.get_mut(file).unwrap().0 = format!("replacement-{file}\r\n\n").into_bytes();
    }
    let mut items = Vec::new();
    for secret in catalog["secrets"].as_array().unwrap() {
        let fields = secret["fields"].as_object().unwrap();
        if !fields.values().any(|field| {
            field["env"]
                .as_str()
                .is_some_and(|input| files.contains(&input.to_ascii_lowercase()))
        }) {
            continue;
        }
        let mut data = Map::new();
        for (key, field) in fields {
            let value = if let Some(input) = field["env"].as_str() {
                publication(&current[&input_file(input)].0)
            } else if let Some(template) = field["template"].as_str() {
                let mut value = template.to_owned();
                for (file, (bytes, _)) in &current {
                    value = value.replace(
                        &format!("{{{}}}", file.to_ascii_uppercase()),
                        &publication(bytes),
                    );
                }
                value
            } else {
                field["literal"].as_str().unwrap().to_owned()
            };
            data.insert(key.clone(), json!(STANDARD.encode(value)));
        }
        // Foreign fields are not credentials owned by this recovery operation.
        // Preserve arbitrary valid bytes, including empty and non-UTF-8 data.
        data.insert(
            "foreign.binary".into(),
            json!(STANDARD.encode([0, 255, 13, 10])),
        );
        data.insert("foreign.empty".into(), json!(""));
        let index = items.len() + 100;
        items.push(json!({
            "apiVersion":"v1", "kind":"Secret", "type":"Opaque", "immutable":false,
            "metadata":{
                "name":secret["name"], "namespace":binding.namespace,
                "uid":format!("00000000-0000-4000-8000-{index:012}"),
                "resourceVersion":format!("{index}"),
                "labels":{"retained":"yes"},
                "annotations":{"operator.example/note":"leave this intact"},
                "ownerReferences":[{"apiVersion":"v1","kind":"ConfigMap","name":"retained-owner",
                    "uid":"00000000-0000-4000-8000-000000009999"}]
            },
            "data":data
        }));
    }
    Fixture {
        current,
        candidate,
        binding,
        observed: json!({"apiVersion":"v1","kind":"SecretList","metadata":{"resourceVersion":"200"},"items":items}),
    }
}

fn planned(fixture: &Fixture) -> Result<Value> {
    plan(
        &fixture.current,
        &fixture.candidate,
        &fixture.binding,
        &fixture.observed,
    )
}

fn secret_mut<'a>(list: &'a mut Value, name: &str) -> &'a mut Value {
    list["items"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|item| item["metadata"]["name"] == name)
        .unwrap()
}

fn secret<'a>(list: &'a Value, name: &str) -> &'a Value {
    list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["metadata"]["name"] == name)
        .unwrap()
}

// The JSON Patch subset used here has atomic per-object semantics: every test
// and replace must succeed before the supplied document is changed. This local
// simulator exercises server-side preconditions; it performs no process or I/O.
fn apply_atomic(document: &mut Value, patch: &Value) -> std::result::Result<(), ()> {
    let mut next = document.clone();
    for operation in patch.as_array().ok_or(())? {
        let path = operation["path"].as_str().ok_or(())?;
        match operation["op"].as_str().ok_or(())? {
            "test" if next.pointer(path) == operation.get("value") => {}
            "replace" => {
                *next.pointer_mut(path).ok_or(())? = operation.get("value").ok_or(())?.clone();
            }
            _ => return Err(()),
        }
    }
    *document = next;
    Ok(())
}

#[test]
fn closed_plan_replaces_exactly_51_fields_in_34_existing_secrets() {
    let fixture = fixture();
    let result = planned(&fixture).unwrap();
    assert_eq!(result["schema"], SCHEMA);
    assert_eq!(result["status"], "planned-not-qualified-or-activated");
    assert_eq!(result["credentialsQualified"], false);
    assert_eq!(result["activationPerformed"], false);
    assert_eq!(result["atomicAcrossSecrets"], false);
    assert_eq!(result["private"], true);
    assert_eq!(
        result["binding"],
        serde_json::to_value(&fixture.binding).unwrap()
    );
    let secrets = result["secrets"].as_array().unwrap();
    assert_eq!(secrets.len(), 34);
    let names: BTreeSet<_> = secrets
        .iter()
        .map(|item| item["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 34);
    assert!(names.contains("notification-workload-tls"));
    assert!(names.contains("notification-tls-kms"));
    assert!(!names.contains("cloudflared-secret"));
    assert!(!names.contains("signing-keys-integration-secret-ca"));
    let mut count = 0;
    for entry in secrets {
        let name = entry["name"].as_str().unwrap();
        let old = secret(&fixture.observed, name);
        let mut after = old.clone();
        let patch = entry["patch"].as_array().unwrap();
        assert_eq!(entry["namespace"], fixture.binding.namespace);
        assert_eq!(entry["uid"], old["metadata"]["uid"]);
        assert_eq!(entry["resourceVersion"], old["metadata"]["resourceVersion"]);
        assert_eq!(
            patch[0],
            json!({"op":"test","path":"/metadata/uid","value":old["metadata"]["uid"]})
        );
        assert_eq!(
            patch[1],
            json!({"op":"test","path":"/metadata/resourceVersion","value":old["metadata"]["resourceVersion"]})
        );
        assert_eq!(
            patch[2],
            json!({"op":"test","path":"/data","value":old["data"]})
        );
        assert!(patch[3..]
            .iter()
            .all(|operation| operation["op"] == "replace"));
        count += patch.len() - 3;
        if name == "marty-secrets" {
            assert_eq!(patch.len() - 3, 12);
        } else if name == "keycloak-kms" {
            assert_eq!(patch.len() - 3, 7);
        } else {
            assert_eq!(patch.len() - 3, 1);
        }
        apply_atomic(&mut after, &entry["patch"]).unwrap();
        assert_eq!(after["metadata"], old["metadata"]);
        assert_eq!(after["type"], old["type"]);
        assert_eq!(after["immutable"], old["immutable"]);
        for operation in &patch[3..] {
            let path = operation["path"].as_str().unwrap();
            assert_ne!(old.pointer(path), after.pointer(path));
            assert_eq!(after.pointer(path), operation.get("value"));
        }
    }
    assert_eq!(count, 51);
    for (file, (bytes, mode)) in &fixture.current {
        assert_eq!(
            result["currentInputs"][file],
            json!({"sha256":sha256(bytes),"mode":mode})
        );
    }
    for (file, (bytes, mode)) in &fixture.candidate {
        assert_eq!(
            result["candidateInputs"][file],
            json!({"sha256":sha256(bytes),"mode":mode})
        );
    }
    assert_eq!(
        result["currentInputs"].as_object().unwrap().len(),
        fixture.current.len()
    );
    assert_eq!(
        result["candidateInputs"].as_object().unwrap().len(),
        fixture.candidate.len()
    );
}

#[test]
fn static_password_template_migration_and_foreign_values_are_preserved() {
    let fixture = fixture();
    let result = planned(&fixture).unwrap();
    for entry in result["secrets"].as_array().unwrap() {
        let old = secret(&fixture.observed, entry["name"].as_str().unwrap());
        let mut after = old.clone();
        apply_atomic(&mut after, &entry["patch"]).unwrap();
        for (key, value) in old["data"].as_object().unwrap() {
            if !entry["patch"].as_array().unwrap()[3..]
                .iter()
                .any(|operation| operation["path"] == pointer_field(key))
            {
                assert_eq!(&after["data"][key], value);
            }
        }
        assert_eq!(
            after["data"]["foreign.binary"],
            old["data"]["foreign.binary"]
        );
        assert_eq!(after["data"]["foreign.empty"], old["data"]["foreign.empty"]);
        if entry["name"] == "marty-secrets" {
            for key in [
                "OPENBAO_BOOTSTRAP_TOKEN",
                "POSTGRES_PASSWORD",
                "MARTY_DB_PASSWORD",
                "DATABASE_URL",
                "DATABASE_SYNC_URL",
                "KEYCLOAK_DB_URL",
                "RABBITMQ_URL",
                "OPENBAO_TLS_CA_CERT",
                "SIGNING_KEYS_ISSUER_SIGN_KEY",
            ] {
                assert!(old["data"].get(key).is_some());
                assert_eq!(after["data"][key], old["data"][key]);
            }
        }
    }
    for file in [
        "openbao_bootstrap_token",
        "postgres_password",
        "marty_db_password",
        "openbao_tls_ca_cert",
        "workload_identity_ca_cert",
        "unmapped_static_input",
    ] {
        let mut changed = fixture.clone();
        changed.candidate.get_mut(file).unwrap().0.push(b'!');
        assert!(planned(&changed).is_err(), "must preserve {file}");
    }
}

#[test]
fn candidate_inventory_modes_and_every_replacement_are_closed() {
    let fixture = fixture();
    for file in ["auth_tls_kms_token", "unmapped_static_input"] {
        let mut changed = fixture.clone();
        changed.candidate.remove(file);
        assert!(planned(&changed).is_err());
        let mut changed = fixture.clone();
        changed.candidate.get_mut(file).unwrap().1 ^= 0o040;
        assert!(planned(&changed).is_err());
    }
    let mut changed = fixture.clone();
    changed
        .candidate
        .insert("unapproved_new_file".into(), (b"new".to_vec(), 0o600));
    assert!(planned(&changed).is_err());
    let mut changed = fixture.clone();
    changed.candidate.insert(
        "auth_tls_kms_token".into(),
        changed.current["auth_tls_kms_token"].clone(),
    );
    assert!(planned(&changed).is_err());
    let mut changed = fixture;
    changed.current.remove("auth_tls_kms_token");
    changed.candidate.remove("auth_tls_kms_token");
    assert!(planned(&changed).is_err());
}

#[test]
fn normalization_matches_file_publication_and_refuses_noop_or_invalid_replacements() {
    let mut fixture = fixture();
    fixture
        .current
        .get_mut("auth_workload_client_cert")
        .unwrap()
        .0 = b"old\r\ncertificate\r\n\n".to_vec();
    fixture
        .candidate
        .get_mut("auth_workload_client_cert")
        .unwrap()
        .0 = b"new\r\ncertificate\r\n\n".to_vec();
    secret_mut(&mut fixture.observed, "auth-workload-tls")["data"]["tls.crt"] =
        json!(STANDARD.encode(b"old\ncertificate"));
    let result = planned(&fixture).unwrap();
    let entry = result["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "auth-workload-tls")
        .unwrap();
    assert_eq!(
        entry["patch"][3]["value"],
        STANDARD.encode(b"new\ncertificate")
    );
    for invalid in [
        b"old\ncertificate\n".to_vec(),
        Vec::new(),
        b"\r\n\n".to_vec(),
        vec![0xff],
        b"contains\0nul".to_vec(),
        vec![b'x'; super::super::MAX_FILE + 1],
    ] {
        let mut changed = fixture.clone();
        changed
            .candidate
            .get_mut("auth_workload_client_cert")
            .unwrap()
            .0 = invalid;
        assert!(planned(&changed).is_err());
    }
    let mut changed = fixture;
    changed
        .current
        .get_mut("auth_workload_client_cert")
        .unwrap()
        .0 = vec![0xff];
    assert!(planned(&changed).is_err());
}

#[test]
fn observation_requires_exact_list_and_existing_target_set() {
    let fixture = fixture();
    for (key, value) in [
        ("apiVersion", json!("v2")),
        ("kind", json!("List")),
        ("items", Value::Null),
    ] {
        let mut changed = fixture.clone();
        changed.observed[key] = value;
        assert!(planned(&changed).is_err());
    }
    let mut changed = fixture.clone();
    changed.observed["items"].as_array_mut().unwrap().pop();
    assert!(planned(&changed).is_err());
    let mut changed = fixture.clone();
    let items = changed.observed["items"].as_array_mut().unwrap();
    items[1] = items[0].clone();
    assert!(planned(&changed).is_err());
    let mut changed = fixture.clone();
    secret_mut(&mut changed.observed, "auth-tls-kms")["metadata"]["name"] = json!("unknown-secret");
    assert!(planned(&changed).is_err());
    let mut changed = fixture;
    let uid = changed.observed["items"][0]["metadata"]["uid"].clone();
    changed.observed["items"][1]["metadata"]["uid"] = uid;
    assert!(planned(&changed).is_err());
}

#[test]
fn observation_rejects_wrong_identity_type_or_live_update_state() {
    let fixture = fixture();
    for (path, value) in [
        ("/apiVersion", json!("v2")),
        ("/kind", json!("ConfigMap")),
        ("/type", json!("kubernetes.io/tls")),
        ("/immutable", json!(true)),
        ("/immutable", json!("false")),
        ("/immutable", Value::Null),
        ("/metadata/namespace", json!("other-namespace")),
        ("/metadata/name", json!("auth-workload-tls")),
        ("/metadata/uid", json!("not-a-uuid")),
        ("/metadata/uid", json!("00000000000040008000000000000100")),
        ("/metadata/resourceVersion", json!("")),
        ("/metadata/resourceVersion", json!(123)),
        ("/metadata/resourceVersion", json!("1\n2")),
    ] {
        let mut changed = fixture.clone();
        *secret_mut(&mut changed.observed, "auth-tls-kms")
            .pointer_mut(path)
            .unwrap() = value;
        assert!(planned(&changed).is_err(), "must reject {path}");
    }
    for deletion in [json!("2026-11-09T00:00:00Z"), Value::Null] {
        let mut changed = fixture.clone();
        secret_mut(&mut changed.observed, "auth-tls-kms")["metadata"]["deletionTimestamp"] =
            deletion;
        assert!(planned(&changed).is_err());
    }
    for field in ["name", "namespace", "uid", "resourceVersion"] {
        let mut changed = fixture.clone();
        secret_mut(&mut changed.observed, "auth-tls-kms")["metadata"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(planned(&changed).is_err(), "must reject missing {field}");
    }
    let mut changed = fixture.clone();
    secret_mut(&mut changed.observed, "auth-tls-kms")["stringData"] = json!({"token":"unmerged"});
    assert!(planned(&changed).is_err());
    let mut changed = fixture;
    secret_mut(&mut changed.observed, "auth-tls-kms")
        .as_object_mut()
        .unwrap()
        .remove("immutable");
    assert!(planned(&changed).is_ok());
}

#[test]
fn old_publication_values_must_match_every_changed_field() {
    let fixture = fixture();
    for (name, key) in [
        ("auth-tls-kms", "token"),
        ("notification-workload-tls", "tls.crt"),
        ("marty-secrets", "OPENBAO_SERVICE_TOKEN"),
        ("keycloak-kms", "master-cookie.token"),
    ] {
        let mut changed = fixture.clone();
        secret_mut(&mut changed.observed, name)["data"][key] =
            json!(STANDARD.encode("newer-or-foreign-value"));
        assert!(planned(&changed).is_err());
        let mut changed = fixture.clone();
        secret_mut(&mut changed.observed, name)["data"]
            .as_object_mut()
            .unwrap()
            .remove(key);
        assert!(planned(&changed).is_err());
    }
    for malformed in [Value::Null, json!([]), json!({})] {
        let mut changed = fixture.clone();
        secret_mut(&mut changed.observed, "auth-tls-kms")["data"] = malformed;
        assert!(planned(&changed).is_err());
    }
}

#[test]
fn all_observed_data_requires_canonical_base64_including_foreign_fields() {
    let fixture = fixture();
    for malformed in [
        json!("YQ"),
        json!("YQ==\n"),
        json!("YQ===="),
        json!("YR=="),
        json!("-_=="),
        json!("not base64!"),
        json!(42),
        Value::Null,
    ] {
        let mut changed = fixture.clone();
        secret_mut(&mut changed.observed, "auth-tls-kms")["data"]["foreign.binary"] = malformed;
        assert!(planned(&changed).is_err());
    }
    for key in ["", "bad/key", "bad~key"] {
        let mut changed = fixture.clone();
        secret_mut(&mut changed.observed, "auth-tls-kms")["data"][key] =
            json!(STANDARD.encode("valid"));
        assert!(planned(&changed).is_err());
    }
    let mut changed = fixture;
    secret_mut(&mut changed.observed, "auth-tls-kms")["data"]["foreign.binary"] =
        json!(STANDARD.encode(vec![0; MAX_SECRET_BYTES]));
    assert!(planned(&changed).is_err());
}

#[test]
fn patches_refuse_stale_uid_version_and_entire_data_without_partial_object_edits() {
    let fixture = fixture();
    let result = planned(&fixture).unwrap();
    let entry = result["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "auth-tls-kms")
        .unwrap();
    let original = secret(&fixture.observed, "auth-tls-kms");
    for (path, value) in [
        (
            "/metadata/uid",
            json!("00000000-0000-4000-8000-000000099999"),
        ),
        ("/metadata/resourceVersion", json!("999999")),
        (
            "/data/token",
            json!(STANDARD.encode("concurrent-credential")),
        ),
        (
            "/data/foreign.binary",
            json!(STANDARD.encode("concurrent-foreign-value")),
        ),
    ] {
        let mut document = original.clone();
        *document.pointer_mut(path).unwrap() = value;
        let before = document.clone();
        assert!(apply_atomic(&mut document, &entry["patch"]).is_err());
        assert_eq!(document, before);
    }
    let mut document = original.clone();
    document["data"]["added.concurrently"] = json!(STANDARD.encode("new"));
    let before = document.clone();
    assert!(apply_atomic(&mut document, &entry["patch"]).is_err());
    assert_eq!(document, before);
    let mut document = original.clone();
    document["data"]
        .as_object_mut()
        .unwrap()
        .remove("foreign.empty");
    let before = document.clone();
    assert!(apply_atomic(&mut document, &entry["patch"]).is_err());
    assert_eq!(document, before);
}

#[test]
fn multi_secret_application_is_explicitly_partial_on_later_failure_and_cannot_blindly_replan() {
    let mut fixture = fixture();
    let result = planned(&fixture).unwrap();
    let entries = result["secrets"].as_array().unwrap();
    let first_name = entries[0]["name"].as_str().unwrap();
    let second_name = entries[1]["name"].as_str().unwrap();
    let first_old = secret(&fixture.observed, first_name).clone();
    apply_atomic(
        secret_mut(&mut fixture.observed, first_name),
        &entries[0]["patch"],
    )
    .unwrap();
    secret_mut(&mut fixture.observed, first_name)["metadata"]["resourceVersion"] = json!("500001");
    secret_mut(&mut fixture.observed, second_name)["metadata"]["resourceVersion"] = json!("500002");
    let second_before = secret(&fixture.observed, second_name).clone();
    assert!(apply_atomic(
        secret_mut(&mut fixture.observed, second_name),
        &entries[1]["patch"]
    )
    .is_err());
    assert_eq!(secret(&fixture.observed, second_name), &second_before);
    assert_ne!(
        secret(&fixture.observed, first_name)["data"],
        first_old["data"]
    );
    assert_eq!(result["atomicAcrossSecrets"], false);
    assert_eq!(result["activationPerformed"], false);
    // A new snapshot does not silently turn an incomplete application into a
    // fresh plan: at least one old retained value no longer matches Kubernetes.
    assert!(planned(&fixture).is_err());
    assert!(apply_atomic(
        secret_mut(&mut fixture.observed, first_name),
        &entries[0]["patch"]
    )
    .is_err());
}

fn catalog_secret_mut<'a>(catalog: &'a mut Value, name: &str) -> &'a mut Value {
    catalog["secrets"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|secret| secret["name"] == name)
        .unwrap()
}

#[test]
fn mapping_refuses_catalog_expansion_templates_defaults_and_optional_targets() {
    let fixture = fixture();
    let files = replacements(&fixture.binding).unwrap();
    let original = crate::kubernetes_secrets::contract()["catalog"].clone();
    assert_eq!(mappings(&original, &files).unwrap().len(), 34);
    for field in [
        json!({"template":"prefix-{AUTH_TLS_KMS_TOKEN}"}),
        json!({"env":"AUTH_TLS_KMS_TOKEN"}),
    ] {
        let mut catalog = original.clone();
        catalog_secret_mut(&mut catalog, "marty-secrets")["fields"]["unapproved"] = field;
        assert!(mappings(&catalog, &files).is_err());
    }
    let mut catalog = original.clone();
    catalog_secret_mut(&mut catalog, "auth-tls-kms")["fields"]["token"]["default"] =
        json!("fallback");
    assert!(mappings(&catalog, &files).is_err());
    let mut catalog = original.clone();
    catalog_secret_mut(&mut catalog, "auth-tls-kms")["fields"]["token"]["env"] =
        json!("UNREVIEWED_INPUT");
    assert!(mappings(&catalog, &files).is_err());
    let mut catalog = original.clone();
    catalog_secret_mut(&mut catalog, "auth-tls-kms")["optional_env"] = json!("AUTH_TLS_KMS_TOKEN");
    assert!(mappings(&catalog, &files).is_err());
    let mut catalog = original;
    let duplicate = catalog["secrets"][0].clone();
    catalog["secrets"].as_array_mut().unwrap().push(duplicate);
    assert!(mappings(&catalog, &files).is_err());
}

#[test]
fn json_pointer_escaping_is_unambiguous() {
    assert_eq!(pointer_field("tls.crt"), "/data/tls.crt");
    assert_eq!(pointer_field("a/b~c"), "/data/a~1b~0c");
    assert_eq!(pointer_field("~1/"), "/data/~01~1");
}
