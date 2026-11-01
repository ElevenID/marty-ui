//! A complete 42-file positive-attempt chain over historical public material.
//! Native receipts are synthetic; this is ancestry admission, not installation
//! or Docker execution qualification.
use super::*;

fn put_bytes(path: &Path, bytes: &[u8], mode: u32) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}
fn private(path: &Path) {
    std::fs::create_dir(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}
fn value(root: &Path, name: &str) -> Value {
    decode(&read(root, name).unwrap()).unwrap()
}
fn output_files(binding: &GenerationBinding, root: &Path) -> BTreeMap<String, Vec<u8>> {
    binding
        .files
        .keys()
        .map(|name| (name.clone(), binding.read(root, name).unwrap()))
        .collect()
}
fn native_pair(
    root: &Path,
    scope: Attempt,
    inputs: &ComposeInputs,
    model: &Value,
    previous: &ProjectResources,
    id: &str,
    parent: &GenerationBinding,
) -> ComposeReceipt {
    let configuration = installer_compose::model_sha256(model).unwrap();
    let mut resources = previous.clone();
    let mut helper = resources.containers["installer-generation"].clone();
    helper.id = id.into();
    helper
        .setup_execution
        .as_mut()
        .unwrap()
        .completed_without_restart = false;
    resources
        .containers
        .insert("installer-generation".into(), helper);
    let create = scope.operation("create", 0);
    let mut created = receipt(&create, &configuration, inputs, resources.clone(), false);
    created
        .status
        .iter_mut()
        .find(|row| row["Service"] == "installer-generation")
        .unwrap()["State"] = json!("created");
    let created_hash = write(
        root,
        &format!("generation-compose-{create}-result.json"),
        &created,
    );
    let intent_hash = write(
        root,
        &format!("generation-compose-{create}-intent.json"),
        &command(&created, previous, &["installer-generation"], true),
    );
    write(
        root,
        &scope.record("producer"),
        &ProducerRecord {
            schema: "elevenid.installer-generation-producer/v1".into(),
            installation_id: parent.installation_id.clone(),
            sequence: scope.sequence,
            attempt: scope.number,
            parent_binding_sha256: parent.sha256().unwrap(),
            container_id: id.into(),
            create_operation: create.clone(),
            created_receipt_sha256: created_hash,
            create_intent_operation: create,
            create_intent_sha256: intent_hash,
        },
    );
    write(
        root,
        &format!(
            "generation-compose-{}-intent.json",
            scope.operation("start", 0)
        ),
        &command(&created, &resources, &["installer-generation"], false),
    );
    resources
        .containers
        .get_mut("installer-generation")
        .unwrap()
        .setup_execution
        .as_mut()
        .unwrap()
        .completed_without_restart = true;
    let completed = receipt(
        &scope.operation("wait", 0),
        &configuration,
        inputs,
        resources,
        false,
    );
    write(
        root,
        &format!("generation-compose-{}-result.json", completed.operation),
        &completed,
    );
    write(root, &scope.record("helper"), &completed);
    completed
}

fn chain() -> (tempfile::TempDir, GenerationBinding, GenerationBinding) {
    let (root, mut generations) = generation::test_lineage_fixture(1);
    let parent = generations.remove(0);
    let mut previous = generations.remove(0);
    let scope = Attempt::new(1, 0);
    let next = Attempt::new(1, 1);
    let old_output = previous.secret_dir(root.path()).unwrap();
    let old_files = output_files(&previous, root.path());
    let mut candidate = value(root.path(), &scope.record("candidate"));
    let old_metadata: PublicIngressMetadata =
        serde_json::from_value(candidate["public_ingress"].clone()).unwrap();
    let image = candidate["image"].as_str().unwrap().to_owned();
    let mut inputs = ComposeInputs {
        installation: root.path().into(),
        project: format!("marty-install-{}", parent.installation_id.replace('-', "")),
        files: Vec::new(),
        bound_inputs: Vec::new(),
        environment: BoundFile {
            path: root.path().join("evidence/attempt-fixture.env"),
            sha256: hash(b"FIXTURE=1\n"),
        },
        profiles: vec!["setup".into()],
        services: vec!["installer-generation".into()],
        approved_images: BTreeSet::from([image.clone()]),
        #[cfg(feature = "installer-development")]
        development_image: None,
        writable_bind_roots: BTreeSet::new(),
        readonly_bind_roots: BTreeSet::new(),
        allowed_loopback_ports: BTreeSet::new(),
        ingress_listener: None,
        prior: None,
    };
    put_bytes(&inputs.environment.path, b"FIXTURE=1\n", 0o600);
    let model = json!({"name":inputs.project,"services":{"installer-generation":{"image":image,
        "labels":{"com.elevenid.installer.phase":"setup"}}}});
    let configuration = installer_compose::model_sha256(&model).unwrap();
    let initial: ComposeReceipt = decode(
        &read(
            root.path(),
            "compose-setup-installer-generation-result.json",
        )
        .unwrap(),
    )
    .unwrap();
    let initial = receipt(
        "initial-fixture",
        &configuration,
        &inputs,
        initial.resources.unwrap(),
        false,
    );
    inputs.prior = Some(initial.clone());
    let saved = SavedSession {
        schema: "elevenid.installer-compose-session/v1".into(),
        installation_id: parent.installation_id.clone(),
        inputs: inputs.clone(),
        model: model.clone(),
        configuration_sha256: configuration.clone(),
        receipt: initial.clone(),
    };
    let helper = native_pair(
        root.path(),
        scope,
        &inputs,
        &model,
        initial.resources.as_ref().unwrap(),
        candidate["container_id"].as_str().unwrap(),
        &parent,
    );
    candidate["compose_receipt_sha256"] = json!(hash(&encode(&helper).unwrap()));
    previous.generation_receipt_sha256 = write(root.path(), &scope.record("candidate"), &candidate);
    std::fs::rename(&old_output, previous.secret_dir(root.path()).unwrap()).unwrap();
    write(root.path(), &scope.record("binding"), &previous);
    write(root.path(), &scope.record("binding-pending"), &previous);
    let before = output_files(&parent, root.path());
    let identities =
        host::staged_identity(&directory(&scope.work(root.path()).join("identity")).unwrap())
            .unwrap();
    let old_plan = value(root.path(), &scope.record("public-ingress-plan"));
    let old = Intent {
        schema: "elevenid.installer-generation-maintenance-intent/v1".into(),
        installation_id: parent.installation_id.clone(),
        engine_id: parent.engine_id.clone(),
        sequence: 1,
        attempt: 0,
        parent_attempt: 0,
        parent_binding_sha256: parent.sha256().unwrap(),
        initial_configuration_sha256: configuration.clone(),
        parent_session: saved,
        public_plan_sha256: hash(&encode(&old_plan).unwrap()),
        source_sha256: crate::installer_generation::hashes(&before),
        identity_sha256: crate::installer_generation::hashes(&identities),
        helper_inputs: inputs.clone(),
        helper_configuration_sha256: configuration.clone(),
        helper_model: model.clone(),
        created_at: old_metadata.token_observed_at - 1,
        recovery_baseline_sha256: None,
    };
    write(root.path(), &scope.record("intent"), &old);
    generation::load_attempt(root.path(), 1, 0).unwrap();
    let supersession = Supersession {
        schema: SUPERSESSION_SCHEMA.into(),
        installation_id: parent.installation_id.clone(),
        engine_id: parent.engine_id.clone(),
        sequence: 1,
        attempt: 1,
        previous_attempt: 0,
        parent_attempt: 0,
        parent_binding_sha256: parent.sha256().unwrap(),
        parent_session_sha256: hash(&encode(&old.parent_session).unwrap()),
        previous_evidence_sha256: old_evidence(root.path(), scope).unwrap(),
        previous_container_id: helper.resources.as_ref().unwrap().containers
            ["installer-generation"]
            .id
            .clone(),
        previous_token_observed_at: old_metadata.token_observed_at,
        previous_credential_fresh_until: old_metadata.token_observed_at + 1800,
        previous_certificate_not_after: old_metadata.certificate_admission["not_after"]
            .as_u64()
            .unwrap(),
        reason: StaleReason::CredentialFreshnessElapsed,
        runtime_replacement_started: false,
        original_create_intents: BTreeMap::new(),
        before_resources: helper.resources.as_ref().unwrap().clone(),
        observed_at: old_metadata.token_observed_at + 1800,
    };
    let supersession_sha256 = write(
        root.path(),
        &next.record("supersession-intent"),
        &supersession,
    );
    let baseline_receipt = receipt(
        &next.operation("supersede-baseline", 0),
        &configuration,
        &inputs,
        helper.resources.as_ref().unwrap().clone(),
        false,
    );
    let baseline_native_sha = write(
        root.path(),
        &format!(
            "generation-compose-{}-result.json",
            baseline_receipt.operation
        ),
        &baseline_receipt,
    );
    let mut baseline_inputs = inputs.clone();
    baseline_inputs.services.clear();
    baseline_inputs.prior = Some(baseline_receipt.clone());
    let baseline = Baseline {
        schema: BASELINE_SCHEMA.into(),
        installation_id: parent.installation_id.clone(),
        engine_id: parent.engine_id.clone(),
        sequence: 1,
        attempt: 1,
        supersession_sha256,
        inputs: baseline_inputs,
        model: model.clone(),
        configuration_sha256: configuration.clone(),
        observation: NativeReference {
            operation: baseline_receipt.operation.clone(),
            sha256: baseline_native_sha,
        },
        create_intents: BTreeMap::new(),
        stopped_services: BTreeSet::new(),
        runtime_generation_root: parent.secret_dir(root.path()).unwrap(),
        observed_at: supersession.observed_at,
        activation_performed: false,
        installation_ready: false,
    };
    require_supersession(root.path(), &supersession, &old, &previous, &old_metadata).unwrap();
    require_baseline(
        root.path(),
        &supersession,
        &old,
        &previous,
        &parent,
        &baseline,
    )
    .unwrap();
    let baseline_sha = write(
        root.path(),
        &next.record("supersession-baseline"),
        &baseline,
    );
    let mut plan = old_plan.clone();
    let previous_successor = plan["successor"].clone();
    plan["successor"] = json!({"sequence":1,"attempt":1,"parent_binding_sha256":parent.sha256().unwrap(),
        "input_sha256":previous_successor["input_sha256"],"input_observed_at":previous_successor["input_observed_at"],"ingress":previous_successor["ingress"]});
    let bytes = encode(&plan).unwrap();
    let plan = PublicIngressPlan::parse_authenticated(&bytes, &hash(&bytes)).unwrap();
    write(root.path(), &next.record("public-ingress-plan"), &plan);
    let plan_hash = plan.sha256().unwrap();
    let mut metadata = old_metadata.clone();
    metadata.plan_sha256 = plan_hash.clone();
    metadata.token_observed_at = baseline.observed_at + 1;
    let mut outputs = old_files.clone();
    outputs
        .get_mut("installer_ingress_tls_kms_token")
        .unwrap()
        .extend_from_slice(b"-second-attempt");
    let work = next.work(root.path());
    private(&work);
    for name in ["current", "identity", "transfer"] {
        private(&work.join(name));
    }
    private(&work.join("transfer/delivered"));
    for (name, bytes) in &before {
        put_bytes(&work.join("current").join(name), bytes, 0o444);
    }
    for (name, bytes) in &identities {
        put_bytes(&work.join("identity").join(name), bytes, 0o600);
    }
    for (name, bytes) in &outputs {
        put_bytes(&work.join("transfer/delivered").join(name), bytes, 0o444);
    }
    for name in ["pending.json", "validated.json", "completed.json"] {
        let bytes = std::fs::read(
            scope
                .work(root.path())
                .join("transfer/delivered")
                .join(name),
        )
        .unwrap();
        let mut value: Value = decode(&bytes).unwrap();
        value["public_ingress_plan_sha256"] = json!(plan_hash);
        if name == "validated.json" {
            value["output_sha256"] = json!(crate::installer_generation::hashes(&outputs));
            value["public_ingress"] = json!(metadata);
        }
        put_bytes(
            &work.join("transfer/delivered").join(name),
            &encode(&value).unwrap(),
            0o600,
        );
    }
    inputs.prior = Some(baseline_receipt);
    let current_native = native_pair(
        root.path(),
        next,
        &inputs,
        &model,
        helper.resources.as_ref().unwrap(),
        &"a".repeat(64),
        &parent,
    );
    candidate["container_id"] = json!("a".repeat(64));
    candidate["public_ingress"] = json!(metadata);
    candidate["compose_receipt_sha256"] = json!(hash(&encode(&current_native).unwrap()));
    candidate["candidate_sha256"] = json!(crate::installer_generation::hashes(&outputs));
    let mut current = previous.clone();
    current.successor.as_mut().unwrap().attempt = 1;
    current.successor.as_mut().unwrap().native_operation = current_native.operation;
    current.generation_receipt_sha256 = write(root.path(), &next.record("candidate"), &candidate);
    for (name, bytes) in &outputs {
        let file = current.files.get_mut(name).unwrap();
        file.sha256 = hash(bytes);
        file.size = bytes.len() as u64;
    }
    let output = current.secret_dir(root.path()).unwrap();
    private(&output);
    for (name, bytes) in &outputs {
        put_bytes(&output.join(name), bytes, 0o444);
    }
    write(root.path(), &next.record("binding"), &current);
    write(root.path(), &next.record("binding-pending"), &current);
    let mut intent = old.clone();
    intent.attempt = 1;
    intent.public_plan_sha256 = plan_hash;
    intent.helper_inputs = inputs;
    intent.created_at = baseline.observed_at;
    intent.recovery_baseline_sha256 = Some(baseline_sha);
    write(root.path(), &next.record("intent"), &intent);
    (root, previous, current)
}

#[test]
fn positive_attempt_revalidates_both_complete_producers_once_and_keeps_sequence_contiguous() {
    let (root, previous, current) = chain();
    let (loaded, visits) =
        generation::test_lineage_visits(|| generation::load_attempt(root.path(), 1, 1));
    assert_eq!(loaded.unwrap(), current);
    assert_eq!(
        visits,
        [0, 1, 1],
        "one initial and one visit per completed attempt"
    );
    assert_eq!(
        generation::load_attempt(root.path(), 1, 0).unwrap(),
        previous
    );
    assert_eq!(current.sequence(), previous.sequence());
    assert_eq!(current.attempt(), 1);
    assert_eq!(current.parent_attempt(), 0);
}

#[test]
fn positive_attempt_cannot_skip_or_rebind_its_stale_completed_predecessor() {
    let (root, _, current) = chain();
    generation::load_attempt(root.path(), 1, 1).unwrap();
    for kind in ["supersession-intent", "supersession-baseline", "intent"] {
        let path = root.path().join("evidence").join(current.record_name(kind));
        let bytes = std::fs::read(&path).unwrap();
        let mut changed: Value = decode(&bytes).unwrap();
        match kind {
            "supersession-intent" => changed["previous_attempt"] = json!(1),
            "supersession-baseline" => changed["supersession_sha256"] = json!("f".repeat(64)),
            "intent" => changed["recovery_baseline_sha256"] = json!("f".repeat(64)),
            _ => unreachable!(),
        }
        put_bytes(&path, &encode(&changed).unwrap(), 0o600);
        assert!(
            generation::load_attempt(root.path(), 1, 1).is_err(),
            "{kind}"
        );
        put_bytes(&path, &bytes, 0o600);
    }
    let original = root
        .path()
        .join("evidence")
        .join(Attempt::new(1, 0).record("binding"));
    let bytes = std::fs::read(&original).unwrap();
    std::fs::remove_file(&original).unwrap();
    assert!(generation::load_attempt(root.path(), 1, 1).is_err());
    put_bytes(&original, &bytes, 0o600);
    generation::load_attempt(root.path(), 1, 1).unwrap();
}
