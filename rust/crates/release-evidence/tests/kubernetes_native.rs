//! Source/model and actual CLI qualification only; never kubectl or a cluster.
use marty_release_evidence::kubernetes_native::{self as native, Environment, MAX_BYTES, REFUSAL};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}
fn fixtures() -> (Vec<Value>, Vec<Value>, Vec<String>, Environment) {
    let root = root();
    let baseline =
        native::documents(&fs::read(root.join("k8s/oracle/07-microservices.yaml")).unwrap())
            .unwrap();
    let template =
        native::documents(&fs::read(root.join("k8s/oracle/07a-issuance-native.yaml")).unwrap())
            .unwrap();
    let ready = native::readiness_from_source(
        &fs::read_to_string(root.join("rust/services/gateway/src/config.rs")).unwrap(),
    )
    .unwrap();
    let values = Environment::from([
        ("K8S_ISSUANCE_NATIVE_ENABLED".into(), "true".into()),
        (
            "MARTY_SERVICES_IMAGE".into(),
            format!("ghcr.io/elevenid/services@sha256:{}", "a".repeat(64)),
        ),
    ]);
    (baseline, template, ready, values)
}
fn index(values: &[Value], kind: &str, name: &str) -> usize {
    values
        .iter()
        .position(|v| v["kind"] == kind && v["metadata"]["name"] == name)
        .unwrap()
}
fn owner(value: &Value) -> &Value {
    &value["spec"]["template"]["spec"]["containers"][0]
}
fn owner_mut(value: &mut Value) -> &mut Value {
    &mut value["spec"]["template"]["spec"]["containers"][0]
}
fn env(value: &Value) -> BTreeMap<String, Value> {
    owner(value)["env"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| (v["name"].as_str().unwrap().to_owned(), v.clone()))
        .collect()
}

#[test]
fn whole_model_preserves_legacy_and_all_siblings_with_only_closed_deltas() {
    let (before, template, ready, values) = fixtures();
    for mounted in [false, true] {
        let mut values = values.clone();
        if mounted {
            values.insert(
                "K8S_DIDCOMM_POLICY_SECRET".into(),
                "synthetic-policy".into(),
            );
            values.insert("K8S_DIDCOMM_CA_SECRET".into(), "synthetic-ca".into());
        }
        let model = native::compose(&before, &template, &ready, &values).unwrap();
        let mut after = model["items"].as_array().unwrap().clone();
        assert_eq!(after.len(), before.len() + 3);
        let new = after.split_off(before.len());
        let native_owner = &new[index(&new, "Deployment", "issuance-native")];
        let config = &new[index(&new, "ConfigMap", "issuance-native-config")];
        assert_eq!(config["data"], json!({})); // no absent-input default override
        assert_eq!(
            native_owner["spec"]["selector"]["matchLabels"],
            json!({"app":"issuance-native"})
        );
        assert_eq!(
            owner(native_owner)["envFrom"],
            json!([{"configMapRef":{"name":"issuance-native-config"}}])
        );
        let native_env = env(native_owner);
        assert!(!native_env
            .keys()
            .any(|v| v.starts_with("BAO") || v == "CANVAS_SYNC_PROCESSOR"));
        for value in &mut after {
            if value["kind"] != "Deployment" {
                continue;
            }
            if value["metadata"]["name"] == "gateway" {
                let entries = owner_mut(value)["env"].as_array_mut().unwrap();
                assert_eq!(
                    entries.pop().unwrap(),
                    json!({"name":"GATEWAY_REQUIRED_READY_SERVICES","value":format!("{},issuance-native",ready.join(","))})
                );
                assert_eq!(
                    entries.pop().unwrap(),
                    json!({"name":"ISSUANCE_NATIVE_SERVICE_URL","value":"http://issuance-native:8005"})
                );
            } else if value["metadata"]["name"] == "issuance" {
                assert_eq!(
                    owner_mut(value)["envFrom"]
                        .as_array_mut()
                        .unwrap()
                        .pop()
                        .unwrap(),
                    json!({"configMapRef":{"name":"issuance-native-config"}})
                );
                if mounted {
                    let pod = value
                        .pointer_mut("/spec/template/spec")
                        .unwrap()
                        .as_object_mut()
                        .unwrap();
                    let volumes = pod.remove("volumes").unwrap();
                    assert_eq!(volumes.as_array().unwrap().len(), 2);
                    for volume in volumes.as_array().unwrap() {
                        assert_eq!(volume["secret"]["optional"], false);
                        assert_eq!(volume["secret"]["defaultMode"], 292);
                    }
                    let legacy_owner = owner_mut(value);
                    let mounts = legacy_owner
                        .as_object_mut()
                        .unwrap()
                        .remove("volumeMounts")
                        .unwrap();
                    assert_eq!(mounts.as_array().unwrap().len(), 2);
                    assert!(mounts
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|v| v["readOnly"] == true));
                    let entries = legacy_owner["env"].as_array_mut().unwrap();
                    assert_eq!(entries.pop().unwrap()["name"], "DIDCOMM_TLS_CA_FILE");
                    assert_eq!(
                        entries.pop().unwrap()["name"],
                        "DIDCOMM_ENCRYPTION_POLICY_FILE"
                    );
                    assert_eq!(owner(native_owner)["volumeMounts"], mounts);
                    assert_eq!(
                        native_owner.pointer("/spec/template/spec/volumes").unwrap(),
                        &volumes
                    );
                }
            }
        }
        assert_eq!(
            after, before,
            "Every legacy row/field outside closed deltas must survive"
        );
    }
}

fn effective(value: &Value, shared: &Value, common: &Value) -> BTreeMap<String, String> {
    let owner = owner(value);
    let mut result = BTreeMap::new();
    for reference in owner["envFrom"].as_array().unwrap() {
        let data = match reference["configMapRef"]["name"].as_str().unwrap() {
            "marty-config" => common,
            "issuance-native-config" => shared,
            _ => panic!("Unknown fixture map"),
        };
        for (key, value) in data.as_object().unwrap() {
            result.insert(key.clone(), value.as_str().unwrap().to_owned());
        }
    }
    for entry in owner["env"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        if let Some(value) = entry.get("value") {
            result.insert(name.into(), value.as_str().unwrap().to_owned());
        } else if let Some(reference) = entry["valueFrom"].get("configMapKeyRef") {
            assert_eq!(reference["name"], "marty-config");
            if let Some(value) = common.get(reference["key"].as_str().unwrap()) {
                result.insert(name.into(), value.as_str().unwrap().to_owned());
            }
        }
    }
    result
}

#[test]
fn absent_empty_and_explicit_settings_keep_both_owners_effectively_paired() {
    let (baseline, template, ready, values) = fixtures();
    for supplied in [None, Some(""), Some("false"), Some("true")] {
        for existing in [None, Some("true")] {
            for explicit in [None, Some("explicit-canary")] {
                let mut baseline = baseline.clone();
                let legacy_index = index(&baseline, "Deployment", "issuance");
                if let Some(value) = explicit {
                    owner_mut(&mut baseline[legacy_index])["env"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!({"name":"DIDCOMM_ALLOW_PRIVATE_IPS","value":value}));
                }
                let mut values = values.clone();
                if let Some(value) = supplied {
                    values.insert("DIDCOMM_ALLOW_PRIVATE_IPS".into(), value.into());
                }
                values.insert("MARTY_UI_SHA".into(), "native-only-revision".into());
                let model = native::compose(&baseline, &template, &ready, &values).unwrap();
                let rows = model["items"].as_array().unwrap();
                let shared = &rows[index(rows, "ConfigMap", "issuance-native-config")]["data"];
                let mut common = json!({"BAO_ADDR":"must-not-reach-native","CANVAS_SYNC_PROCESSOR":"legacy-only"});
                if let Some(value) = existing {
                    common["DIDCOMM_ALLOW_PRIVATE_IPS"] = json!(value);
                }
                let legacy_values = effective(&rows[legacy_index], shared, &common);
                let native_values = effective(
                    &rows[index(rows, "Deployment", "issuance-native")],
                    shared,
                    &common,
                );
                let expected = explicit.or(supplied).or(existing);
                assert_eq!(
                    legacy_values
                        .get("DIDCOMM_ALLOW_PRIVATE_IPS")
                        .map(String::as_str),
                    expected
                );
                assert_eq!(
                    native_values
                        .get("DIDCOMM_ALLOW_PRIVATE_IPS")
                        .map(String::as_str),
                    expected
                );
                assert!(!native_values.contains_key("BAO_ADDR"));
                assert!(!native_values.contains_key("CANVAS_SYNC_PROCESSOR"));
                assert!(!legacy_values.contains_key("MARTY_UI_SHA"));
                assert_eq!(native_values["MARTY_UI_SHA"], "native-only-revision");
            }
        }
    }
}

#[test]
fn parser_environment_and_new_canonical_image_policy_fail_closed() {
    for input in [
        b"kind: A\nkind: B".to_vec(),
        b"[broken".to_vec(),
        vec![b' '; MAX_BYTES + 1],
        b"kind: Secret\nmetadata: {name: x}\n---\nkind: Secret\nmetadata: {name: x}".to_vec(),
    ] {
        assert!(native::documents(&input).is_err());
    }
    let mut names = Vec::new();
    let captured = native::capture_environment(|name| {
        names.push(name.to_owned());
        (name == "K8S_ISSUANCE_NATIVE_ENABLED").then(|| "false".into())
    })
    .unwrap();
    assert!(!native::selected(&captured).unwrap());
    assert_eq!(names, ["K8S_ISSUANCE_NATIVE_ENABLED"]);
    let (_, _, _, mut values) = fixtures();
    for &name in native::OPTIONAL_SETTINGS {
        values.insert(name.into(), "x".repeat(65536));
    }
    assert_eq!(native::configuration(&values), Err(REFUSAL));
    let digest = format!("sha256:{}", "a".repeat(64));
    let corpus: Value = serde_json::from_slice(
        &fs::read(root().join("contracts/kubernetes-native-image-reference.json")).unwrap(),
    )
    .unwrap();
    for case in corpus["cases"].as_array().unwrap() {
        let repository = case["uri"].as_str().unwrap();
        assert_eq!(
            native::services_image(&format!("{repository}@{digest}")).is_ok(),
            case["native_selector_accepts"].as_bool().unwrap()
        );
    }
}

fn set_path(value: &mut Value, path: &str, replacement: Value) {
    let (parent, key) = path.rsplit_once('/').unwrap();
    value.pointer_mut(parent).unwrap()[key] = replacement;
}

#[test]
fn native_template_rejects_extra_topology_and_binding_mutations() {
    let (baseline, template, ready, values) = fixtures();
    let deployment = index(&template, "Deployment", "issuance-native");
    for (path, value) in [
        (
            "/spec/template/spec/initContainers",
            json!([{"name":"extra"}]),
        ),
        ("/spec/template/spec/hostPID", json!(true)),
        ("/spec/template/spec/hostIPC", json!(true)),
        ("/spec/template/spec/hostNetwork", json!(true)),
        (
            "/spec/template/spec/automountServiceAccountToken",
            json!(true),
        ),
        (
            "/spec/template/spec/serviceAccountName",
            json!("different-account"),
        ),
        (
            "/spec/template/spec/containers/0/ports/0/hostPort",
            json!(8005),
        ),
        (
            "/spec/template/spec/containers/0/command",
            json!(["python", "main.py"]),
        ),
        (
            "/spec/template/spec/containers/0/envFrom",
            json!([{"secretRef":{"name":"custody"}}]),
        ),
        (
            "/spec/template/spec/containers/0/readinessProbe/httpGet/path",
            json!("/not-health"),
        ),
        ("/spec/selector/matchLabels/app", json!("issuance")),
    ] {
        let mut changed = template.clone();
        set_path(&mut changed[deployment], path, value);
        assert_eq!(
            native::compose(&baseline, &changed, &ready, &values),
            Err(REFUSAL),
            "{path}"
        );
    }
    let mut changed = template.clone();
    let pod = changed[deployment]
        .pointer_mut("/spec/template/spec")
        .unwrap();
    pod["containers"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"sidecar"}));
    assert_eq!(
        native::compose(&baseline, &changed, &ready, &values),
        Err(REFUSAL)
    );
    let mut changed = baseline.clone();
    let legacy = index(&changed, "Deployment", "issuance");
    owner_mut(&mut changed[legacy])["envFrom"]
        .as_array_mut()
        .unwrap()
        .push(json!({"configMapRef":{"name":"unknown-precedence"}}));
    assert_eq!(
        native::compose(&changed, &template, &ready, &values),
        Err(REFUSAL)
    );
}

fn api_defaults(model: &Value) -> Value {
    let mut actual = model.clone();
    let rows = actual["items"].as_array_mut().unwrap();
    let native = index(rows, "Deployment", "issuance-native");
    rows[native]["metadata"]["resourceVersion"] = json!("1234");
    rows[native]["status"] = json!({"availableReplicas":1});
    let pod = rows[native].pointer_mut("/spec/template/spec").unwrap();
    for (name, value) in [
        ("dnsPolicy", json!("ClusterFirst")),
        ("restartPolicy", json!("Always")),
        ("schedulerName", json!("default-scheduler")),
        ("terminationGracePeriodSeconds", json!(30)),
        ("securityContext", json!({})),
        ("enableServiceLinks", json!(true)),
        ("serviceAccount", json!("marty-app")),
    ] {
        pod[name] = value;
    }
    let owner = &mut pod["containers"][0];
    owner["terminationMessagePath"] = json!("/dev/termination-log");
    owner["terminationMessagePolicy"] = json!("File");
    for port in owner["ports"].as_array_mut().unwrap() {
        port["protocol"] = json!("TCP");
    }
    for name in ["livenessProbe", "readinessProbe"] {
        for (key, value) in [
            ("successThreshold", 1),
            ("failureThreshold", 3),
            ("timeoutSeconds", 1),
        ] {
            owner[name][key] = json!(value);
        }
        owner[name]["httpGet"]["scheme"] = json!("HTTP");
    }
    let service = index(rows, "Service", "issuance-native");
    rows[service]["spec"]["clusterIP"] = json!("10.96.0.123");
    rows[service]["spec"]["clusterIPs"] = json!(["10.96.0.123"]);
    rows[service]["spec"]["ipFamilies"] = json!(["IPv4"]);
    rows[service]["spec"]["ipFamilyPolicy"] = json!("SingleStack");
    rows[service]["spec"]["sessionAffinity"] = json!("None");
    for port in rows[service]["spec"]["ports"].as_array_mut().unwrap() {
        port["protocol"] = json!("TCP");
    }
    actual
}

#[test]
fn realistic_api_defaults_preserve_update_guard_and_hostile_changes_fail_closed() {
    let (baseline, template, ready, mut values) = fixtures();
    values.insert(
        "K8S_DIDCOMM_POLICY_SECRET".into(),
        "synthetic-policy".into(),
    );
    values.insert("K8S_DIDCOMM_CA_SECRET".into(), "synthetic-ca".into());
    let expected = native::compose(&baseline, &template, &ready, &values).unwrap();
    let actual = api_defaults(&expected);
    native::check_update(&actual, &expected, "marty-prod").unwrap();
    let rows = actual["items"].as_array().unwrap();
    let native = index(rows, "Deployment", "issuance-native");
    let legacy = index(rows, "Deployment", "issuance");
    // Independent legacy image and unrelated topology are not owned by this
    // native image update. Named-container lookup must not assume index zero.
    let mut independent = actual.clone();
    owner_mut(&mut independent["items"][legacy])["image"] =
        json!("independent.invalid/external:reviewed");
    independent["items"][legacy]["spec"]["template"]["spec"]["containers"]
        .as_array_mut()
        .unwrap()
        .insert(0, json!({"name":"unrelated-existing-sidecar"}));
    native::check_update(&independent, &expected, "marty-prod").unwrap();
    for fault in [
        "shared-map",
        "management-key",
        "policy-volume",
        "policy-mount",
        "policy-path",
    ] {
        let mutated = legacy_fault(&actual, fault);
        assert_eq!(
            native::check_update(&mutated, &expected, "marty-prod"),
            Err(REFUSAL),
            "{fault}"
        );
    }
    for (path, value) in [
        ("/spec/template/spec/hostPID", json!(true)),
        ("/spec/template/spec/hostIPC", json!(true)),
        ("/spec/template/spec/hostNetwork", json!(true)),
        (
            "/spec/template/spec/initContainers",
            json!([{"name":"extra"}]),
        ),
        (
            "/spec/template/spec/automountServiceAccountToken",
            json!(true),
        ),
        (
            "/spec/template/spec/securityContext",
            json!({"runAsUser":0}),
        ),
        ("/spec/template/spec/serviceAccount", json!("unexpected")),
        (
            "/spec/template/spec/containers/0/ports/0/hostPort",
            json!(8005),
        ),
        (
            "/spec/template/spec/containers/0/ports/0/protocol",
            json!("UDP"),
        ),
        (
            "/spec/template/spec/containers/0/readinessProbe/timeoutSeconds",
            json!(99),
        ),
        (
            "/spec/template/spec/containers/0/readinessProbe/httpGet/httpHeaders",
            json!([{"name":"Authorization","value":"private-canary"}]),
        ),
        (
            "/spec/template/spec/containers/0/readinessProbe/exec",
            json!({"command":["true"]}),
        ),
        (
            "/spec/template/spec/containers/0/volumeMounts/0/readOnly",
            json!(false),
        ),
        (
            "/spec/template/spec/volumes/0/secret/secretName",
            json!("wrong-secret"),
        ),
        ("/spec/selector/matchLabels/app", json!("issuance")),
    ] {
        let mut mutated = actual.clone();
        set_path(&mut mutated["items"][native], path, value);
        assert_eq!(
            native::check_update(&mutated, &expected, "marty-prod"),
            Err(REFUSAL),
            "{path}"
        );
    }
    let mut cmd = command();
    cmd.arg("check-update")
        .arg("--repo-root")
        .arg(root())
        .arg("--manifest-dir")
        .arg(root().join("k8s/oracle"))
        .args(["--namespace", "marty-prod"])
        .envs(&values);
    let (passed, output, errors) = execute(cmd, &serde_json::to_vec(&actual).unwrap());
    assert!(passed, "{}", String::from_utf8_lossy(&errors));
    assert!(output.is_empty());
    assert!(errors.is_empty());
}

#[cfg(unix)]
#[test]
fn non_unicode_is_rejected_only_for_a_declared_selected_input() {
    use std::os::unix::ffi::OsStringExt;
    let values = native::capture_environment(|name| match name {
        "K8S_ISSUANCE_NATIVE_ENABLED" => Some("true".into()),
        "UNRELATED_PRIVATE" => panic!("Unrelated environment must not be read"),
        _ => None,
    })
    .unwrap();
    assert!(native::selected(&values).unwrap());
    assert!(native::capture_environment(|name| match name {
        "K8S_ISSUANCE_NATIVE_ENABLED" => Some("true".into()),
        "TOKEN_RATE_LIMIT" => Some(std::ffi::OsString::from_vec(vec![255])),
        _ => None,
    })
    .is_err());
}

fn execute(mut command: Command, input: &[u8]) -> (bool, Vec<u8>, Vec<u8>) {
    let dir = tempfile::tempdir().unwrap();
    let input_file = dir.path().join("input");
    fs::write(&input_file, input).unwrap();
    let output_file = dir.path().join("output");
    let error_file = dir.path().join("error");
    command
        .stdin(fs::File::open(input_file).unwrap())
        .stdout(Stdio::from(fs::File::create(&output_file).unwrap()))
        .stderr(Stdio::from(fs::File::create(&error_file).unwrap()));
    let mut child = command
        .spawn()
        .expect("Required owned fixture executable is unavailable");
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let reap = Instant::now() + Duration::from_secs(5);
            while child.try_wait().unwrap().is_none() && Instant::now() < reap {
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("Owned fixture process deadline exceeded");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    (
        status.success(),
        fs::read(output_file).unwrap(),
        fs::read(error_file).unwrap(),
    )
}
fn command() -> Command {
    fixture_command(env!("CARGO_BIN_EXE_kubernetes-native-issuance"))
}
fn fixture_command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(program);
    command.env_clear();
    for name in ["SystemRoot", "PATH", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
}

fn legacy_fault(model: &Value, fault: &str) -> Value {
    let mut model = model.clone();
    let rows = model["items"].as_array_mut().unwrap();
    let i = index(rows, "Deployment", "issuance");
    let deployment = &mut rows[i];
    match fault {
        "shared-map" => {
            owner_mut(deployment)["envFrom"]
                .as_array_mut()
                .unwrap()
                .pop();
        }
        "management-key" | "policy-path" => {
            let name = if fault == "management-key" {
                "ISSUANCE_API_KEY"
            } else {
                "DIDCOMM_ENCRYPTION_POLICY_FILE"
            };
            owner_mut(deployment)["env"]
                .as_array_mut()
                .unwrap()
                .retain(|v| v["name"] != name);
        }
        "policy-volume" => deployment["spec"]["template"]["spec"]["volumes"]
            .as_array_mut()
            .unwrap()
            .retain(|v| v["name"] != "didcomm-policy"),
        "policy-mount" => owner_mut(deployment)["volumeMounts"]
            .as_array_mut()
            .unwrap()
            .retain(|v| v["mountPath"] != "/run/marty-didcomm-policy"),
        _ => panic!("Unknown closed legacy mutation"),
    }
    model
}

fn shell_path(path: &Path) -> String {
    path.to_str()
        .unwrap()
        .trim_start_matches(r"\\?\")
        .replace('\\', "/")
}
fn extracted_function(source: &str, name: &str) -> String {
    let prefix = format!("{name}() {{\n");
    assert_eq!(source.matches(&prefix).count(), 1);
    let body = source
        .split_once(&prefix)
        .unwrap()
        .1
        .split_once("\n}")
        .unwrap()
        .0;
    format!("{prefix}{body}\n}}\n")
}

#[test]
fn custom_shared_secret_and_control_plane_entries_are_paired_not_overwritten() {
    let (baseline, template, ready, values) = fixtures();
    for name in [
        "DATABASE_URL",
        "TOKEN_HMAC_KEY",
        "CANVAS_CREDENTIALS_API_TOKEN",
        "ISSUER_BASE_URL",
        "ORG_GRPC_TARGET",
        "CT_GRPC_TARGET",
        "RP_GRPC_TARGET",
        "SIGNING_KEYS_INTERNAL_URL",
    ] {
        let mut baseline = baseline.clone();
        let i = index(&baseline, "Deployment", "issuance");
        let custom = if native::SECRET_SETTINGS.contains(&name)
            || name == "CANVAS_CREDENTIALS_API_TOKEN"
        {
            json!({"name":name,"valueFrom":{"secretKeyRef":{"name":"existing-custom-credentials","key":name}}})
        } else {
            json!({"name":name,"value":if name.ends_with("GRPC_TARGET") {"custom-control.example:9443"} else {"https://custom-issuer.example"}})
        };
        let entries = owner_mut(&mut baseline[i])["env"].as_array_mut().unwrap();
        entries.retain(|entry| entry["name"] != name);
        entries.push(custom.clone());
        let model = native::compose(&baseline, &template, &ready, &values).unwrap();
        let rows = model["items"].as_array().unwrap();
        let selected = index(rows, "Deployment", "issuance-native");
        assert_eq!(env(&rows[i])[name], custom);
        assert_eq!(env(&rows[selected])[name], custom);
        native::check_update(&api_defaults(&model), &model, "marty-prod").unwrap();
    }
    for &name in native::SECRET_SETTINGS {
        let mut baseline = baseline.clone();
        let i = index(&baseline, "Deployment", "issuance");
        owner_mut(&mut baseline[i])["env"]
            .as_array_mut()
            .unwrap()
            .retain(|entry| entry["name"] != name);
        assert_eq!(
            native::compose(&baseline, &template, &ready, &values),
            Err(REFUSAL),
            "{name}"
        );
    }
    let legacy = index(&baseline, "Deployment", "issuance");
    assert!(!env(&baseline[legacy]).contains_key("RP_GRPC_TARGET"));
    let model = native::compose(&baseline, &template, &ready, &values).unwrap();
    let rows = model["items"].as_array().unwrap();
    let selected = index(rows, "Deployment", "issuance-native");
    assert_eq!(
        env(&rows[selected])["RP_GRPC_TARGET"],
        json!({"name":"RP_GRPC_TARGET","value":"revocation-profile:9013"})
    );
}

#[test]
fn full_deploy_preflights_before_first_write_and_apply_uses_captured_model() {
    let (_, _, _, values) = fixtures();
    let source = fs::read_to_string(root().join("scripts/deploy-kubernetes.sh")).unwrap();
    let mut script = String::from("set -euo pipefail\n");
    for name in [
        "prepare_kubernetes_native_issuance",
        "apply_manifest",
        "cmd_deploy",
    ] {
        script.push_str(&extracted_function(&source, name));
    }
    script.push_str(
        r#"
error() { printf '%s\n' "$*" >&2; exit 1; }
step() { :; }
info() { :; }
resolve_kubernetes_issuance_image() { printf '%s\n' "$MARTY_ISSUANCE_IMAGE"; }
cmd_setup_secrets() { printf 'unexpected-setup\n' >> "$FIXTURE_LEDGER"; return 94; }
kubectl() {
  printf '%s\n' "$*" >> "$FIXTURE_LEDGER"
  [[ "$*" == 'apply -f -' ]] || return 95
  command cat > "$FIXTURE_APPLIED"
}
if [[ "$FIXTURE_FAULT" == captured ]]; then
  prepare_kubernetes_native_issuance
  printf '%s' "$K8S_NATIVE_RENDERED_MODEL" > "$FIXTURE_CAPTURED"
  # A changed shell input after capture cannot silently regenerate a different
  # complete service model at the API boundary.
  export MARTY_SERVICES_IMAGE=changed-after-reviewed-capture
  apply_manifest "${K8S_DIR}/07-microservices.yaml"
else
  cmd_deploy
fi
"#,
    );
    for fault in [
        "captured",
        "invalid-template",
        "missing-secret-ref",
        "empty-selector",
        "invalid-selector",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let ledger = dir.path().join("ledger");
        let captured = dir.path().join("captured");
        let applied = dir.path().join("applied");
        fs::write(&ledger, []).unwrap();
        let mut manifests = root().join("k8s/oracle");
        if fault == "invalid-template" || fault == "missing-secret-ref" {
            manifests = dir.path().join("manifests");
            fs::create_dir(&manifests).unwrap();
            for file in ["07-microservices.yaml", "07a-issuance-native.yaml"] {
                fs::copy(root().join("k8s/oracle").join(file), manifests.join(file)).unwrap();
            }
            if fault == "invalid-template" {
                fs::write(manifests.join("07a-issuance-native.yaml"), b"[malformed").unwrap();
            } else {
                let file = manifests.join("07-microservices.yaml");
                let mut documents = native::documents(&fs::read(&file).unwrap()).unwrap();
                let i = index(&documents, "Deployment", "issuance");
                owner_mut(&mut documents[i])["env"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|v| v["name"] != "TOKEN_HMAC_KEY");
                let yaml = documents
                    .iter()
                    .map(|v| serde_yaml::to_string(v).unwrap())
                    .collect::<Vec<_>>()
                    .join("\n---\n");
                fs::write(file, yaml).unwrap();
            }
        }
        let bash = if cfg!(windows) {
            "C:/Program Files/Git/bin/bash.exe"
        } else {
            "bash"
        };
        let mut cmd = fixture_command(bash);
        cmd.args(["--noprofile", "--norc", "-c", &script])
            .envs(&values)
            .env("REPO_ROOT", shell_path(&root()))
            .env("K8S_DIR", shell_path(&manifests))
            .env(
                "K8S_NATIVE_ISSUANCE_BIN",
                shell_path(Path::new(env!("CARGO_BIN_EXE_kubernetes-native-issuance"))),
            )
            .env("NAMESPACE", "marty-prod")
            .env("OCIR_REGISTRY", "synthetic.registry.invalid")
            .env("IMAGE_TAG", "2026.08.0")
            .env("MARTY_ISSUANCE_IMAGE", "synthetic.invalid/legacy:reviewed")
            .env("FIXTURE_FAULT", fault)
            .env("FIXTURE_LEDGER", shell_path(&ledger))
            .env("FIXTURE_CAPTURED", shell_path(&captured))
            .env("FIXTURE_APPLIED", shell_path(&applied));
        if fault == "empty-selector" {
            cmd.env("K8S_ISSUANCE_NATIVE_ENABLED", "");
        }
        if fault == "invalid-selector" {
            cmd.env("K8S_ISSUANCE_NATIVE_ENABLED", "invalid");
        }
        let (passed, output, errors) = execute(cmd, b"");
        assert_eq!(
            passed,
            fault == "captured",
            "{fault}: {}",
            String::from_utf8_lossy(&errors)
        );
        assert!(output.is_empty());
        let calls = fs::read_to_string(ledger).unwrap();
        if fault == "captured" {
            assert_eq!(calls, "apply -f -\n");
            let expected: Value = serde_json::from_slice(&fs::read(captured).unwrap()).unwrap();
            let observed: Value = serde_json::from_slice(&fs::read(applied).unwrap()).unwrap();
            assert_eq!(observed, expected);
            let rows = observed["items"].as_array().unwrap();
            assert_eq!(
                owner(&rows[index(rows, "Deployment", "issuance-native")])["image"],
                values["MARTY_SERVICES_IMAGE"]
            );
        } else {
            assert!(
                calls.is_empty(),
                "No API call or setup before full-model validation"
            );
            assert!(!applied.exists());
        }
    }
}

#[test]
fn actual_update_shell_uses_real_preflight_and_refuses_before_any_image_write() {
    let (baseline, template, ready, mut values) = fixtures();
    values.insert(
        "K8S_DIDCOMM_POLICY_SECRET".into(),
        "synthetic-policy".into(),
    );
    let expected = api_defaults(&native::compose(&baseline, &template, &ready, &values).unwrap());
    let source = fs::read_to_string(root().join("scripts/deploy-kubernetes.sh")).unwrap();
    let mut script = String::from("set -euo pipefail\n");
    for name in ["prepare_kubernetes_native_issuance", "cmd_update_images"] {
        script.push_str(&extracted_function(&source, name));
    }
    // Only the Rust validator and envsubst are real operational executables.
    // All cluster/catalog/other guard boundaries are closed local functions.
    script.push_str(r#"
error() { printf '%s\n' "$*" >&2; exit 1; }
step() { :; }
success() { :; }
warn() { :; }
catalog_services() { printf 'issuance\ngateway\n'; }
controlled_canvas_guard() { command cat >/dev/null; }
kubectl() {
  printf '%s\n' "$*" >> "$FIXTURE_LEDGER"
  case "$1 $2" in
    'get deployment/issuance-native') command cat "$FIXTURE_SNAPSHOT" ;;
    'get deployment') printf '{}\n' ;;
    'set image') : ;;
    'rollout status')
      if [[ "$3" == deployment/issuance-native && "$FIXTURE_FAULT" == rollout ]]; then return 19; fi ;;
    *) return 93 ;;
  esac
}
cmd_update_images
"#);
    for fault in [
        "none",
        "shared-map",
        "management-key",
        "policy-volume",
        "policy-mount",
        "policy-path",
        "rollout",
        "missing-binary",
        "invalid-image",
        "disabled",
        "absent",
        "empty-selector",
        "invalid-selector",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let snapshot = dir.path().join("snapshot.json");
        let ledger = dir.path().join("ledger");
        let mutated = if [
            "shared-map",
            "management-key",
            "policy-volume",
            "policy-mount",
            "policy-path",
        ]
        .contains(&fault)
        {
            legacy_fault(&expected, fault)
        } else {
            expected.clone()
        };
        fs::write(&snapshot, serde_json::to_vec(&mutated).unwrap()).unwrap();
        fs::write(&ledger, []).unwrap();
        let bash = if cfg!(windows) {
            "C:/Program Files/Git/bin/bash.exe"
        } else {
            "bash"
        };
        let mut cmd = fixture_command(bash);
        cmd.args(["--noprofile", "--norc", "-c", &script])
            .envs(&values)
            .env("REPO_ROOT", shell_path(&root()))
            .env("K8S_DIR", shell_path(&root().join("k8s/oracle")))
            .env(
                "K8S_NATIVE_ISSUANCE_BIN",
                shell_path(Path::new(env!("CARGO_BIN_EXE_kubernetes-native-issuance"))),
            )
            .env("NAMESPACE", "marty-prod")
            .env("PYTHON_BIN", "controlled_canvas_guard")
            .env("OCIR_REGISTRY", "synthetic.registry.invalid")
            .env("IMAGE_REGISTRY", "synthetic.registry.invalid")
            .env("IMAGE_TAG", "2026.08.0")
            .env("MARTY_ISSUANCE_IMAGE", "synthetic.invalid/legacy:reviewed")
            .env("FIXTURE_LEDGER", shell_path(&ledger))
            .env("FIXTURE_SNAPSHOT", shell_path(&snapshot))
            .env("FIXTURE_FAULT", fault);
        if fault == "missing-binary" || fault == "disabled" || fault == "absent" {
            cmd.env(
                "K8S_NATIVE_ISSUANCE_BIN",
                "/nonexistent-required-native-renderer",
            );
        }
        if fault == "invalid-image" || fault == "disabled" || fault == "absent" {
            cmd.env("MARTY_SERVICES_IMAGE", "private-image-canary");
        }
        if fault == "disabled" {
            cmd.env("K8S_ISSUANCE_NATIVE_ENABLED", "false");
        }
        if fault == "absent" {
            cmd.env_remove("K8S_ISSUANCE_NATIVE_ENABLED");
        }
        if fault == "empty-selector" {
            cmd.env("K8S_ISSUANCE_NATIVE_ENABLED", "");
        }
        if fault == "invalid-selector" {
            cmd.env("K8S_ISSUANCE_NATIVE_ENABLED", "1");
        }
        let (passed, output, errors) = execute(cmd, b"");
        assert_eq!(
            passed,
            fault == "none" || fault == "disabled" || fault == "absent",
            "{fault}: {}",
            String::from_utf8_lossy(&errors)
        );
        assert!(output.is_empty());
        assert!(!String::from_utf8_lossy(&errors).contains("private-image-canary"));
        let calls = fs::read_to_string(&ledger).unwrap();
        let writes: Vec<_> = calls
            .lines()
            .filter(|v| v.starts_with("set image "))
            .collect();
        if fault == "none" || fault == "disabled" || fault == "absent" {
            assert_eq!(writes.len(), if fault == "none" { 4 } else { 3 });
            assert!(!writes
                .iter()
                .any(|v| v.starts_with("set image deployment/issuance ")));
        } else if fault == "rollout" {
            assert_eq!(
                writes.len(),
                1,
                "No sibling writes after native rollout failure"
            );
        } else {
            assert!(writes.is_empty(), "{fault}");
        }
        if [
            "missing-binary",
            "invalid-image",
            "empty-selector",
            "invalid-selector",
        ]
        .contains(&fault)
        {
            assert!(calls.is_empty(), "Preflight before any API read/write");
        }
        if fault == "none" || fault == "rollout" {
            assert_eq!(
                writes[0],
                format!(
                    "set image deployment/issuance-native issuance-native={} -n marty-prod",
                    values["MARTY_SERVICES_IMAGE"]
                )
            );
            assert!(calls.starts_with("get deployment/issuance-native deployment/gateway deployment/issuance service/issuance-native configmap/issuance-native-config -n marty-prod -o json --request-timeout=10s\n"));
            assert!(calls.contains(
                "rollout status deployment/issuance-native -n marty-prod --timeout=180s\n"
            ));
        }
        if fault == "disabled" || fault == "absent" {
            assert!(!calls.contains("issuance-native"));
        }
    }
}

#[test]
fn actual_cli_arguments_bounded_input_and_real_envsubst_model() {
    let (baseline, template, ready, values) = fixtures();
    let mut renderer = Command::new("envsubst");
    renderer.env_clear();
    for name in ["SystemRoot", "PATH", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(name) {
            renderer.env(name, value);
        }
    }
    renderer.env("MARTY_ISSUANCE_IMAGE","synthetic.invalid/legacy@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    renderer
        .env("OCIR_REGISTRY", "synthetic.registry.invalid")
        .env("IMAGE_TAG", "2026.08.0");
    let (passed, rendered, errors) = execute(
        renderer,
        &fs::read(root().join("k8s/oracle/07-microservices.yaml")).unwrap(),
    );
    assert!(passed);
    assert!(errors.is_empty());
    let mut cmd = command();
    cmd.args(["render", "--repo-root"])
        .arg(root())
        .arg("--manifest-dir")
        .arg(root().join("k8s/oracle"))
        .envs(&values);
    let (passed, output, errors) = execute(cmd, &rendered);
    assert!(passed, "{}", String::from_utf8_lossy(&errors));
    assert!(errors.is_empty());
    let model: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        model,
        native::compose(
            &native::documents(&rendered).unwrap(),
            &template,
            &ready,
            &values
        )
        .unwrap()
    );
    assert_eq!(baseline.len() + 3, model["items"].as_array().unwrap().len());
    for args in [
        vec!["validate", "--unknown", "private-canary"],
        vec!["validate", "--repo-root", "private-canary"],
        vec!["render"],
        vec!["validate", "--namespace"],
        vec!["bad-private-command"],
    ] {
        let mut cmd = command();
        cmd.args(args).envs(&values);
        let (passed, output, errors) = execute(cmd, b"");
        assert!(!passed);
        assert!(output.is_empty());
        assert_eq!(errors, format!("{REFUSAL}\n").as_bytes());
    }
    let mut cmd = command();
    cmd.arg("validate")
        .env("MARTY_SERVICES_IMAGE", "ignored-private-image");
    let (passed, output, errors) = execute(cmd, b"");
    assert!(passed && output.is_empty() && errors.is_empty());
}
