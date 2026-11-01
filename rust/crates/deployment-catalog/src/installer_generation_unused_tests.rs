//! Real filesystem and historical public-chain admission with synthetic
//! native receipts. These tests grant no installed/Docker/CA qualification.
use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

fn private(path: &Path) {
    std::fs::create_dir(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}
fn bytes(path: &Path, value: &[u8], mode: u32) {
    std::fs::write(path, value).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}
fn put(root: &Path, name: &str, value: &impl Serialize) -> String {
    let value = encode(value).unwrap();
    bytes(&root.join("evidence").join(name), &value, 0o600);
    hash(&value)
}

struct Fixture {
    root: tempfile::TempDir,
    parent: GenerationBinding,
    saved: SavedSession,
}
impl Fixture {
    fn new() -> Self {
        let (root, mut lineage) = generation::test_lineage_fixture(0);
        let parent = lineage.remove(0);
        let mut receipt: ComposeReceipt = decode(
            &read(
                root.path(),
                "compose-setup-installer-generation-result.json",
            )
            .unwrap(),
        )
        .unwrap();
        let helper = &receipt.resources.as_ref().unwrap().containers["installer-generation"];
        let model = json!({"name":receipt.project,"services":{"installer-generation":{
            "image":helper.image,"labels":{"com.elevenid.installer.phase":"setup"}}}});
        let configuration_sha256 = installer_compose::model_sha256(&model).unwrap();
        let env = root.path().join("evidence/unused-fixture.env");
        bytes(&env, b"FIXTURE=1\n", 0o600);
        receipt.configuration_sha256 = configuration_sha256.clone();
        receipt.input_files = BTreeMap::from([(env.clone(), hash(b"FIXTURE=1\n"))]);
        let inputs = ComposeInputs {
            installation: root.path().into(),
            project: receipt.project.clone(),
            files: Vec::new(),
            bound_inputs: Vec::new(),
            environment: BoundFile {
                path: env,
                sha256: hash(b"FIXTURE=1\n"),
            },
            profiles: vec!["setup".into()],
            services: Vec::new(),
            approved_images: BTreeSet::from([helper.image.clone()]),
            #[cfg(feature = "installer-development")]
            development_image: None,
            writable_bind_roots: BTreeSet::new(),
            readonly_bind_roots: BTreeSet::new(),
            allowed_loopback_ports: BTreeSet::new(),
            ingress_listener: None,
            prior: Some(receipt.clone()),
        };
        let saved = SavedSession {
            schema: "elevenid.installer-compose-session/v1".into(),
            installation_id: parent.installation_id.clone(),
            inputs,
            model,
            configuration_sha256,
            receipt,
        };
        put(root.path(), installer_doctor::SESSION_RECORD, &saved);
        let fixture = Self {
            root,
            parent,
            saved,
        };
        fixture.plan(Attempt::new(1, 0));
        fixture
    }
    fn plan(&self, scope: Attempt) -> PublicIngressPlan {
        let mut value: Value = decode(
            &read(
                self.root.path(),
                crate::installer_public_ingress::PUBLIC_INGRESS_PLAN_RECORD,
            )
            .unwrap(),
        )
        .unwrap();
        let metadata = self
            .parent
            .public_ingress_metadata(self.root.path())
            .unwrap()
            .unwrap();
        let hashes = crate::installer_renewal_bootstrap::public_inputs()
            .into_iter()
            .map(|name| {
                (
                    name.clone(),
                    hash(&self.parent.read(self.root.path(), &name).unwrap()),
                )
            })
            .collect::<BTreeMap<_, _>>();
        // Public plans require the exact typed representation. Preserve the
        // Successor field order when optional positive-attempt fields appear.
        let mut successor = serde_json::Map::new();
        successor.insert("sequence".into(), json!(scope.sequence));
        if scope.number > 0 {
            successor.insert("attempt".into(), json!(scope.number));
        }
        if self.parent.attempt() > 0 {
            successor.insert("parent_attempt".into(), json!(self.parent.attempt()));
        }
        successor.insert(
            "parent_binding_sha256".into(),
            json!(self.parent.sha256().unwrap()),
        );
        successor.insert("input_sha256".into(), json!(hashes));
        successor.insert(
            "input_observed_at".into(),
            json!(metadata.token_observed_at),
        );
        successor.insert("ingress".into(), json!(metadata));
        value["successor"] = Value::Object(successor);
        let plan_bytes = encode(&value).unwrap();
        let plan = PublicIngressPlan::parse_authenticated(&plan_bytes, &hash(&plan_bytes)).unwrap();
        put(
            self.root.path(),
            &scope.record("public-ingress-plan"),
            &plan,
        );
        plan
    }
    fn work(&self, scope: Attempt) -> PathBuf {
        let root = scope.work(self.root.path());
        if !root.exists() {
            private(&root);
        }
        root
    }
    fn snapshot(
        &self,
        scope: Attempt,
        incoming: Option<&GenerationRecoveryBaseline>,
    ) -> Result<Preparation> {
        snapshot(
            self.root.path(),
            scope,
            &self.parent,
            &self.saved,
            &saved_plan(self.root.path(), scope)?,
            incoming,
        )
    }
    fn record(
        &self,
        scope: Attempt,
        incoming: Option<&GenerationRecoveryBaseline>,
    ) -> GenerationRecoveryBaseline {
        let source = origin(self.root.path(), scope, &self.parent, &self.saved, incoming).unwrap();
        let plan = saved_plan(self.root.path(), scope).unwrap();
        let next = Attempt::new(scope.sequence, scope.number + 1);
        let operation = next.operation("unused-baseline", 0);
        let mut receipt = source.inputs.prior.clone().unwrap();
        receipt.operation = operation.clone();
        receipt.input_files = source
            .inputs
            .files
            .iter()
            .chain(std::iter::once(&source.inputs.environment))
            .chain(&source.inputs.bound_inputs)
            .map(|v| (v.path.clone(), v.sha256.clone()))
            .collect();
        let native_hash = put(
            self.root.path(),
            &format!("generation-compose-{operation}-result.json"),
            &receipt,
        );
        put(
            self.root.path(),
            &format!("generation-compose-{operation}-intent.json"),
            &json!({
            "schema":"elevenid.installer-compose-intent/v1","project":receipt.project,"engine_id":receipt.engine_id,
            "configuration_sha256":receipt.configuration_sha256,"input_files":receipt.input_files,
            "command":["ps","--all","--no-trunc","--format","json"],"prior_resources":receipt.resources,
            "selected_services":[],"automatic_retry":false,"installation_ready":false}),
        );
        let preparation = self.snapshot(scope, incoming).unwrap();
        let mut inputs = source.inputs;
        inputs.prior = Some(receipt);
        let after = plan.certificate_admission()["not_after"].as_u64().unwrap();
        let value = UnusedPreparation {
            schema: SCHEMA.into(),
            installation_id: self.parent.installation_id.clone(),
            engine_id: self.parent.engine_id.clone(),
            sequence: next.sequence,
            attempt: next.number,
            previous_attempt: scope.number,
            parent_attempt: self.parent.attempt(),
            parent_binding_sha256: self.parent.sha256().unwrap(),
            parent_session_sha256: hash(&encode(&self.saved).unwrap()),
            source: source.source,
            public_plan_sha256: plan.sha256().unwrap(),
            certificate_not_after: after,
            preparation,
            inputs,
            model: source.model,
            configuration_sha256: source.configuration_sha256,
            observation: NativeReference {
                operation,
                sha256: native_hash,
            },
            stopped_services: source.stopped,
            runtime_generation_root: source.runtime_root,
            last_helper: source.last_helper,
            observed_at: after.max(source.observed_at),
            helper_authorized: false,
            activation_performed: false,
            installation_ready: false,
        };
        put(self.root.path(), &next.record("unused-preparation"), &value);
        let parent = generation::load_verified_attempt(
            self.root.path(),
            self.parent.sequence(),
            self.parent.attempt(),
        )
        .unwrap();
        historical(self.root.path(), &parent, scope, incoming).unwrap()
    }
}

#[test]
fn unused_plan_only_and_consecutive_unused_entries_keep_the_actual_helper_source() {
    let fixture = Fixture::new();
    let first = fixture.record(Attempt::new(1, 0), None);
    assert_eq!(first.last_helper().unwrap(), None);
    assert_eq!(
        first.runtime_root(),
        fixture.parent.secret_dir(fixture.root.path()).unwrap()
    );
    fixture.plan(Attempt::new(1, 1));
    let second = fixture.record(Attempt::new(1, 1), Some(&first));
    assert_eq!(second.last_helper().unwrap(), None);
    assert!(second.previous_work(fixture.root.path()).unwrap().is_none());
    let loaded =
        generation::load_preparation_baseline(fixture.root.path(), Attempt::new(1, 2), 0).unwrap();
    assert_eq!(loaded.sha256(), second.sha256());
    // The future attempt's directory is a sibling of the retired owned
    // children, even when attempt zero originally had no work directory.
    fixture.work(Attempt::new(1, 0));
    fixture.work(Attempt::new(1, 2));
    generation::load_preparation_baseline(fixture.root.path(), Attempt::new(1, 2), 0).unwrap();
    assert!(
        optional(fixture.root.path(), &Attempt::new(1, 0).record("binding"))
            .unwrap()
            .is_none()
    );
    assert!(
        optional(fixture.root.path(), &Attempt::new(1, 1).record("intent"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn any_producer_authority_or_output_blocks_unused_classification_even_without_a_result() {
    let fixture = Fixture::new();
    let scope = Attempt::new(1, 0);
    for kind in [
        "intent",
        "producer",
        "helper",
        "candidate",
        "binding",
        "binding-pending",
        "activation-intent",
        "activation",
        "runtime",
        "session",
        "selection",
    ] {
        let path = fixture
            .root
            .path()
            .join("evidence")
            .join(scope.record(kind));
        bytes(&path, b"{}", 0o600);
        assert!(fixture.snapshot(scope, None).is_err(), "{kind}");
        std::fs::remove_file(path).unwrap();
    }
    for phase in [
        "create",
        "observe-created",
        "start",
        "wait",
        "infrastructure",
        "activate-create",
        "activate-start",
        "checkpoint",
    ] {
        let name = format!(
            "generation-compose-{}-intent.json",
            scope.operation(phase, 0)
        );
        put(
            fixture.root.path(),
            &name,
            &json!({"command":["start","installer-generation"]}),
        );
        assert!(fixture.snapshot(scope, None).is_err(), "{phase}");
        std::fs::remove_file(fixture.root.path().join("evidence").join(name)).unwrap();
    }
    fixture.snapshot(scope, None).unwrap();
}

#[test]
fn unused_transfer_stays_empty_and_retains_its_original_inode_and_change_time() {
    let fixture = Fixture::new();
    let scope = Attempt::new(1, 0);
    let transfer = fixture.work(scope).join("transfer");
    private(&transfer);
    fixture.record(scope, None);
    bytes(&transfer.join("transfer-pending.json"), b"{}", 0o600);
    assert!(
        generation::load_preparation_baseline(fixture.root.path(), Attempt::new(1, 1), 0).is_err()
    );
    std::fs::remove_file(transfer.join("transfer-pending.json")).unwrap();
    // Even restoring emptiness cannot erase evidence of a possible writer.
    assert!(
        generation::load_preparation_baseline(fixture.root.path(), Attempt::new(1, 1), 0).is_err()
    );
}

#[test]
fn unused_partial_input_copy_is_bound_without_finishing_or_deleting_it() {
    let fixture = Fixture::new();
    let scope = Attempt::new(1, 0);
    let current = fixture.work(scope).join("current");
    private(&current);
    let expected = fixture
        .parent
        .read(fixture.root.path(), "installer_ingress_tls_cert")
        .unwrap();
    let temporary = current.join("copy-installer_ingress_tls_cert.tmp");
    bytes(&temporary, &expected[..20], 0o600);
    let before = std::fs::symlink_metadata(&temporary).unwrap().ino();
    let proof = fixture.record(scope, None);
    assert_eq!(std::fs::read(&temporary).unwrap(), &expected[..20]);
    assert_eq!(std::fs::symlink_metadata(&temporary).unwrap().ino(), before);
    assert_eq!(
        generation::load_preparation_baseline(fixture.root.path(), proof.scope(), 0)
            .unwrap()
            .sha256(),
        proof.sha256()
    );
    bytes(&temporary, &expected, 0o444);
    assert!(generation::load_preparation_baseline(fixture.root.path(), proof.scope(), 0).is_err());
}

#[test]
fn unused_preparation_refuses_symlinks_nonempty_transfer_and_wrong_copy_prefix() {
    let fixture = Fixture::new();
    let scope = Attempt::new(1, 0);
    let work = fixture.work(scope);
    symlink(fixture.root.path().join("evidence"), work.join("transfer")).unwrap();
    assert!(fixture.snapshot(scope, None).is_err());
    std::fs::remove_file(work.join("transfer")).unwrap();
    private(&work.join("transfer"));
    bytes(&work.join("transfer/unexpected"), b"data", 0o600);
    assert!(fixture.snapshot(scope, None).is_err());
    std::fs::remove_file(work.join("transfer/unexpected")).unwrap();
    private(&work.join("current"));
    bytes(
        &work.join("current/copy-installer_ingress_tls_cert.tmp"),
        b"wrong",
        0o600,
    );
    assert!(fixture.snapshot(scope, None).is_err());
}

#[test]
fn unused_proof_requires_actual_expiry_exact_parent_and_no_activation_claim() {
    let fixture = Fixture::new();
    let scope = Attempt::new(1, 0);
    let proof = fixture.record(scope, None);
    let BaselineRecord::Unused(value) = &proof.data else {
        unreachable!()
    };
    let parent = generation::load_verified_attempt(fixture.root.path(), 0, 0).unwrap();
    for field in [
        "observed_at",
        "parent_binding_sha256",
        "helper_authorized",
        "activation_performed",
        "last_helper",
    ] {
        let mut changed = serde_json::to_value(value).unwrap();
        match field {
            "observed_at" => changed[field] = json!(value.certificate_not_after - 1),
            "parent_binding_sha256" => changed[field] = json!("f".repeat(64)),
            "helper_authorized" | "activation_performed" => changed[field] = json!(true),
            "last_helper" => changed[field] = json!({"sequence":1,"number":0}),
            _ => unreachable!(),
        }
        let changed: UnusedPreparation = serde_json::from_value(changed).unwrap();
        assert!(
            require_record(fixture.root.path(), &parent, scope, None, &changed).is_err(),
            "{field}"
        );
    }
    put(
        fixture.root.path(),
        &proof.scope().record("supersession-intent"),
        &json!({}),
    );
    assert!(recorded_baseline(fixture.root.path(), proof.scope()).is_ok());
    assert!(generation::load_preparation_baseline(fixture.root.path(), proof.scope(), 0).is_err());
}

#[test]
fn unchanged_native_census_and_read_only_observation_are_required_for_unused_proof() {
    let fixture = Fixture::new();
    let scope = Attempt::new(1, 0);
    let proof = fixture.record(scope, None);
    let BaselineRecord::Unused(value) = &proof.data else {
        unreachable!()
    };
    let parent = generation::load_verified_attempt(fixture.root.path(), 0, 0).unwrap();
    let mut changed = value.clone();
    let mut receipt = changed.inputs.prior.clone().unwrap();
    receipt
        .resources
        .as_mut()
        .unwrap()
        .containers
        .get_mut("installer-generation")
        .unwrap()
        .id = "f".repeat(64);
    changed.observation.sha256 = put(
        fixture.root.path(),
        &format!("generation-compose-{}-result.json", receipt.operation),
        &receipt,
    );
    changed.inputs.prior = Some(receipt);
    assert!(require_record(fixture.root.path(), &parent, scope, None, &changed).is_err());
    put(
        fixture.root.path(),
        &format!(
            "generation-compose-{}-result.json",
            value.observation.operation
        ),
        value.inputs.prior.as_ref().unwrap(),
    );
    // A native result cannot be relabeled as an unused baseline if its
    // retained command could have started the helper.
    let name = format!(
        "generation-compose-{}-intent.json",
        value.observation.operation
    );
    let mut intent: Value = decode(&read(fixture.root.path(), &name).unwrap()).unwrap();
    intent["command"] = json!(["start", "installer-generation"]);
    put(fixture.root.path(), &name, &intent);
    assert!(require_record(fixture.root.path(), &parent, scope, None, value).is_err());
}

#[test]
fn expired_plan_clock_and_corrupt_certificate_are_not_interchangeable() {
    let fixture = Fixture::new();
    let plan = saved_plan(fixture.root.path(), Attempt::new(1, 0)).unwrap();
    let observed = plan.certificate_admission()["observed_at"]
        .as_u64()
        .unwrap();
    let expiry = plan.certificate_admission()["not_after"].as_u64().unwrap();
    assert!(!expired(&plan, expiry - 1).unwrap());
    assert!(expired(&plan, expiry).unwrap());
    assert!(expired(&plan, observed - 121).is_err());
    let mut value = serde_json::to_value(&plan).unwrap();
    value["fullchain_pem"] = json!("broken");
    let value = encode(&value).unwrap();
    assert!(PublicIngressPlan::parse_authenticated(&value, &hash(&value)).is_err());
}

#[test]
fn orphan_scope_evidence_and_plan_only_status_are_explicit() {
    let fixture = Fixture::new();
    let scope = Attempt::new(1, 0);
    let (expiry, expired) = saved_status(fixture.root.path(), scope).unwrap();
    assert!(expired && expiry > 0);
    assert!(orphan_evidence(
        &BTreeSet::from([scope.environment_name("helper")]),
        scope
    ));
    assert!(orphan_evidence(
        &BTreeSet::from([format!(
            "generation-compose-{}-intent.json",
            scope.operation("start", 0)
        )]),
        scope
    ));
    assert!(!orphan_evidence(
        &BTreeSet::from([Attempt::new(2, 0).record("public-ingress-plan")]),
        scope
    ));
}

#[path = "installer_generation_unused_lineage_tests.rs"]
mod lineage;
