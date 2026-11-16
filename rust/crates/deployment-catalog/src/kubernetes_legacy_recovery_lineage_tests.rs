use super::*;
use crate::kubernetes_legacy_recovery::{
    generation, lineage, specifications, Context, NamespaceObservation, SCHEMA, SELFHOST_ROLES,
};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

fn put(path: &Path, bytes: &[u8], mode: u32) {
    let mut missing = Vec::new();
    let mut parent = path.parent().unwrap();
    while !parent.exists() {
        missing.push(parent.to_owned());
        parent = parent.parent().unwrap();
    }
    for directory in missing.iter().rev() {
        fs::create_dir(directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn record(path: &Path, value: &Value) -> Vec<u8> {
    let bytes = serde_json::to_vec(value).unwrap();
    put(path, &bytes, 0o600);
    bytes
}

fn input_bindings(value: &Generation) -> Value {
    json!(value
        .iter()
        .map(|(name, (bytes, mode))| (name, json!({"sha256":sha256(bytes),"mode":mode})))
        .collect::<BTreeMap<_, _>>())
}

fn generation_files(path: &Path, value: &Generation) {
    for (name, (bytes, mode)) in value {
        put(&path.join(name), bytes, *mode);
    }
}

fn release(source: &str, binding: &Binding) -> Value {
    json!({"runtimeSourceSha":source,"chartSourceSha":binding.chart_source_sha,"tag":"v1.1.277",
        "buildRunId":123,"buildRunAttempt":1,"inventorySha256":"a".repeat(64),
        "imageLockSha256":"b".repeat(64),"operatorSha256":"c".repeat(64)})
}

fn context(binding: &Binding, current: &Path, directory: &Path) -> Context {
    let ordinary: Vec<_> = specifications()
        .iter()
        .map(|spec| {
            json!({
        "input":spec.input,"requestedPolicies":spec.policies,
        "requestedTtl":if spec.input == "OPENBAO_BOOTSTRAP_TOKEN" {"2h"} else {"8h"},
        "requestedRenewable":false,"requestedOrphan":true,"requestedNoDefaultPolicy":true})
        })
        .collect();
    Context {
        schema: SCHEMA.into(),
        bootstrap: json!({"bootstrapId":binding.bootstrap_id,"namespace":binding.namespace,
            "openbaoClusterId":binding.openbao_cluster_id,"runtimeSourceSha":binding.runtime_source_sha,
            "chartSourceSha":binding.chart_source_sha,"status":"openbao-and-application-credentials-ready",
            "credentialLifetimeHours":8,"migrationBootstrapLifetimeHours":2,
            "credentialLifecycle":{"schema":"marty.kubernetes-credential-lifecycle/v1",
                "namespaceUid":binding.namespace_uid,"producerNonce":binding.producer_nonce,
                "workloadProject":binding.workload_project,"ordinaryTokens":ordinary}}),
        initialize_request: json!({"bootstrapId":binding.bootstrap_id,"namespace":binding.namespace,
            "namespaceUid":binding.namespace_uid,"producerNonce":binding.producer_nonce,
            "workloadProject":binding.workload_project,"operation":"bao operator init",
            "recoveryShares":1,"recoveryThreshold":1}),
        tls_key_metadata: json!({"schema":"marty.selfhost-disposable-tls-keys/v1",
            "roles":SELFHOST_ROLES.iter().map(|role| json!({"role":role.name,"key_name":role.key_name,"version":1})).collect::<Vec<_>>()}),
        namespace_observation: NamespaceObservation {
            name: binding.namespace.clone(),
            uid: binding.namespace_uid.clone(),
        },
        current: current.to_owned(),
        root_token_file: directory.join("root-is-never-read"),
        retained_root_sha256: "d".repeat(64),
        predecessors: Some(directory.to_owned()),
    }
}

fn canonical_patch(value: &Value) -> Vec<u8> {
    fn sort(value: &Value) -> Value {
        match value {
            Value::Object(object) => json!(object
                .iter()
                .map(|(key, value)| (key, sort(value)))
                .collect::<BTreeMap<_, _>>()),
            Value::Array(values) => Value::Array(values.iter().map(sort).collect()),
            _ => value.clone(),
        }
    }
    let mut bytes = serde_json::to_vec(&sort(value)).unwrap();
    bytes.push(b'\n');
    bytes
}

fn predecessor(directory: &Path, fixture: &Fixture, prefix: Option<Value>) -> (Value, Value) {
    let original_runtime = release(super::super::super::LEGACY_RUNTIME, &fixture.binding);
    let recovery_runtime = release(&"f".repeat(40), &fixture.binding);
    let native = directory.join("evidence");
    generation_files(&native.join("stage/candidate"), &fixture.candidate);
    let mut inspection = json!({"schema":SCHEMA,"binding":fixture.binding,
        "status":"inspected-not-staged","mutationAvailable":false,"inputBindings":input_bindings(&fixture.current)});
    if let Some(prefix) = &prefix {
        inspection["predecessorChain"] = prefix.clone();
    }
    let inspected = record(&native.join("inspection.json"), &inspection);
    let mut journals = BTreeMap::new();
    for (phase, count) in [("stage", 120), ("qualification", 51)] {
        let mut journal = BTreeMap::new();
        for index in 0..count {
            for kind in ["request", "response"] {
                let name = format!("{kind}-{index:03}.json");
                let bytes = record(
                    &native.join(phase).join(&name),
                    &json!({"synthetic":index,"kind":kind}),
                );
                journal.insert(name, sha256(&bytes));
            }
        }
        journals.insert(phase, json!(journal));
    }
    let (leaves, tokens) = super::super::super::staging::inventory(&fixture.binding).unwrap();
    let replacements: Vec<_> = leaves
        .iter()
        .map(|leaf| &leaf.file)
        .chain(tokens.iter().map(|token| &token.file))
        .collect();
    for name in &replacements {
        put(
            &native.join("stage/inputs").join(name),
            &fixture.candidate[*name].0,
            0o600,
        );
    }
    record(
        &native.join("stage/attempt.json"),
        &json!({"schema":super::super::super::staging::STAGE_SCHEMA,
        "binding":fixture.binding,"inspectionSha256":sha256(&inspected),"replacementFiles":replacements,"activation":false}),
    );
    let staged = record(
        &native.join("stage/complete.json"),
        &json!({"schema":super::super::super::staging::STAGE_SCHEMA,
        "binding":fixture.binding,"status":"staged-not-activated","candidate":"candidate","replacementCount":51,
        "inputBindings":input_bindings(&fixture.candidate),"completedRequests":120,"journalBindings":journals["stage"],"activation":false}),
    );
    let preimages = record(&native.join("secrets.json"), &fixture.observed);
    let plan = json!({"schema":super::super::super::qualification::SCHEMA,"binding":fixture.binding,
        "status":"qualified-not-activated","qualifiedAtUnixSeconds":1000,"validBeforeUnixSeconds":1300,
        "inspectionSha256":sha256(&inspected),"stagingReceiptSha256":sha256(&staged),
        "qualificationJournalBindings":journals["qualification"],"credentialsQualified":true,
        "credentialsIssued":false,"activation":false,"nativePlan":planned(fixture).unwrap()});
    record(
        &native.join("qualification/attempt.json"),
        &json!({"schema":super::super::super::qualification::SCHEMA,
        "binding":fixture.binding,"inspectionSha256":sha256(&inspected),"startedAtUnixSeconds":999,
        "currentInputs":input_bindings(&fixture.current),"candidateInputs":input_bindings(&fixture.candidate),
        "credentialsIssued":false,"activation":false}),
    );
    let qualified = record(&native.join("qualification/plan.json"), &plan);
    let plan_hash = sha256(&qualified);
    let source = record(
        &directory.join("source-authenticated.json"),
        &json!({
        "schema":"marty.kubernetes-legacy-recovery-sources/v1","recoveryRuntime":recovery_runtime,
        "files":{"scripts/recover_kubernetes_legacy_credentials.py":"a".repeat(64)}}),
    );
    let mut requested = json!({"schema":"marty.kubernetes-legacy-recovery-request/v1",
        "binding":fixture.binding,"originalRuntime":original_runtime,
        "recoveryRuntime":recovery_runtime,"mode":"activate-existing-secrets","automaticReplay":false});
    let mut complete = json!({"schema":"marty.kubernetes-legacy-recovery-completion/v1","binding":fixture.binding,
        "originalRuntime":original_runtime,"recoveryRuntime":recovery_runtime,"status":"existing-secrets-activated",
        "credentialsIssued":true,"activation":true,"verifiedSecretCount":34,"workloadsRestarted":false,
        "privatePlanSha256":plan_hash,"podRemoved":true});
    if let Some(prefix) = prefix {
        requested["predecessorChain"] = prefix.clone();
        complete["predecessorChain"] = prefix;
    }
    record(&directory.join("recovery-requested.json"), &requested);
    let completion = record(&directory.join("recovery-complete.json"), &complete);
    record(
        &directory.join("activation/activation-requested.json"),
        &json!({
        "schema":"marty.kubernetes-legacy-secret-activation/v1","binding":fixture.binding,
        "privatePlanSha256":plan_hash,"preimagesSha256":sha256(&preimages),"secretCount":34,
        "replacementCount":51,"atomicAcrossSecrets":false,"validBeforeUnixSeconds":1300}),
    );
    let mut after = fixture.observed.clone();
    for (index, entry) in plan["nativePlan"]["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let name = entry["name"].as_str().unwrap();
        let secret = secret_mut(&mut after, name);
        apply_atomic(secret, &entry["patch"]).unwrap();
        secret["metadata"]["resourceVersion"] =
            json!(format!("{}1", entry["resourceVersion"].as_str().unwrap()));
        let raw = serde_json::to_vec(secret).unwrap();
        record(
            &directory.join(format!("activation/intent-{index:02}.json")),
            &json!({
            "schema":"marty.kubernetes-legacy-secret-patch-intent/v1","binding":fixture.binding,
            "name":name,"uid":entry["uid"],"resourceVersion":entry["resourceVersion"],
            "privatePlanSha256":plan_hash,"patchSha256":sha256(&canonical_patch(&entry["patch"])),
            "validBeforeUnixSeconds":1300,"attemptedAtUnixSeconds":1100}),
        );
        record(
            &directory.join(format!("activation/response-{index:02}.json")),
            &json!({
            "completed":true,"exitCode":0,"bounded":true,"stdoutBase64":STANDARD.encode(&raw),"stderrBase64":""}),
        );
        record(
            &directory.join(format!("activation/verified-{index:02}.json")),
            &json!({
            "name":name,"uid":entry["uid"],"resourceVersion":secret["metadata"]["resourceVersion"],"responseSha256":sha256(&raw)}),
        );
    }
    (
        json!({"recoveryRuntime":recovery_runtime,"completionSha256":sha256(&completion),
        "sourceAuthenticationSha256":sha256(&source)}),
        after,
    )
}

fn setup() -> (tempfile::TempDir, Fixture, Context, Value) {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut fixture = fixture();
    for generation in [&mut fixture.current, &mut fixture.candidate] {
        generation
            .entry("openbao_tls_ca_cert".into())
            .or_insert((b"retained-ca".to_vec(), 0o644));
    }
    generation_files(&directory.path().join("original"), &fixture.current);
    let (step, after) = predecessor(&directory.path().join("step-00"), &fixture, None);
    let manifest = json!({"schema":lineage::SCHEMA,"binding":fixture.binding,
        "originalRuntime":release(super::super::super::LEGACY_RUNTIME,&fixture.binding),"steps":[step]});
    record(&directory.path().join("manifest.json"), &manifest);
    record(&directory.path().join("live-secrets.json"), &after);
    let context = context(
        &fixture.binding,
        &directory.path().join("step-00/evidence/stage/candidate"),
        directory.path(),
    );
    (directory, fixture, context, after)
}

#[test]
fn completed_expired_predecessor_admits_without_reading_root_or_relabeling_original() {
    let (directory, fixture, context, _) = setup();
    let original = generation(&directory.path().join("original")).unwrap();
    let summary = lineage::verify(&context).unwrap().unwrap();
    assert_eq!(summary["steps"].as_array().unwrap().len(), 1);
    assert_eq!(
        summary["steps"][0]["candidateInputs"],
        input_bindings(&fixture.candidate)
    );
    assert_eq!(
        generation(&directory.path().join("original")).unwrap(),
        original
    );
    assert!(!context.root_token_file.exists());
}

#[test]
fn every_changed_live_field_uid_and_preserved_foreign_value_must_match_completed_activation() {
    for mode in ["credential", "foreign", "uid", "missing", "duplicate"] {
        let (directory, _, context, mut after) = setup();
        match mode {
            "credential" => {
                after["items"][0]["data"]["token"] = json!(STANDARD.encode("forged"));
            }
            "foreign" => {
                after["items"][0]["data"]["foreign.empty"] = json!(STANDARD.encode("drift"));
            }
            "uid" => {
                after["items"][0]["metadata"]["uid"] =
                    json!("00000000-0000-4000-8000-000000000999");
            }
            "missing" => {
                after["items"].as_array_mut().unwrap().pop();
            }
            _ => {
                let first = after["items"][0].clone();
                after["items"].as_array_mut().unwrap().push(first);
            }
        }
        record(&directory.path().join("live-secrets.json"), &after);
        assert!(lineage::verify(&context).is_err(), "{mode}");
    }
}

#[test]
fn successful_activation_and_complete_journals_are_required_not_just_a_matching_candidate() {
    for relative in [
        "activation/response-17.json",
        "activation/verified-04.json",
        "evidence/stage/response-119.json",
        "evidence/qualification/request-050.json",
    ] {
        let (directory, _, context, _) = setup();
        fs::remove_file(directory.path().join("step-00").join(relative)).unwrap();
        assert!(lineage::verify(&context).is_err(), "{relative}");
    }
    for (relative, field, value) in [
        ("activation/response-00.json", "completed", json!(false)),
        ("recovery-complete.json", "verifiedSecretCount", json!(33)),
        ("recovery-requested.json", "schema", json!("unsupported/v2")),
        (
            "evidence/qualification/plan.json",
            "privatePlanSha256",
            json!("f".repeat(64)),
        ),
    ] {
        let (directory, _, context, _) = setup();
        let path = directory.path().join("step-00").join(relative);
        let mut record_value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        record_value[field] = value;
        record(&path, &record_value);
        assert!(lineage::verify(&context).is_err(), "{relative}");
    }
}

#[test]
fn second_successor_requires_the_complete_original_to_current_chain() {
    let (directory, mut fixture, mut context, after) = setup();
    let prefix = lineage::verify(&context).unwrap().unwrap();
    fixture.current = fixture.candidate.clone();
    fixture.observed = after;
    for name in replacements(&fixture.binding).unwrap() {
        fixture.candidate.get_mut(&name).unwrap().0 = format!("third-{name}\n").into_bytes();
    }
    let (step, after) = predecessor(&directory.path().join("step-01"), &fixture, Some(prefix));
    let manifest_path = directory.path().join("manifest.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    manifest["steps"].as_array_mut().unwrap().push(step);
    record(&manifest_path, &manifest);
    record(&directory.path().join("live-secrets.json"), &after);
    context.current = directory.path().join("step-01/evidence/stage/candidate");
    assert_eq!(
        lineage::verify(&context).unwrap().unwrap()["steps"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let path = directory.path().join("step-01/recovery-complete.json");
    let mut complete: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    complete["predecessorChain"]["steps"][0]["privatePlanSha256"] = json!("f".repeat(64));
    let raw = record(&path, &complete);
    manifest["steps"][1]["completionSha256"] = json!(sha256(&raw));
    record(&manifest_path, &manifest);
    assert!(lineage::verify(&context).is_err());
}

#[test]
fn wrong_installation_source_static_input_or_private_custody_is_refused() {
    for mode in ["namespace", "source", "static", "symlink"] {
        let (directory, _, mut context, _) = setup();
        match mode {
            "namespace" => {
                context.namespace_observation.uid = "00000000-0000-4000-8000-000000000999".into()
            }
            "source" => {
                let path = directory.path().join("manifest.json");
                let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                value["steps"][0]["recoveryRuntime"]["operatorSha256"] = json!("f".repeat(64));
                record(&path, &value);
            }
            "static" => put(
                &context.current.join("unmapped_static_input"),
                b"changed",
                0o640,
            ),
            _ => {
                let path = directory.path().join("step-00/activation/verified-00.json");
                fs::rename(&path, path.with_extension("saved")).unwrap();
                std::os::unix::fs::symlink(path.with_extension("saved"), path).unwrap();
            }
        }
        assert!(lineage::verify(&context).is_err(), "{mode}");
    }
}
