//! Real native capture/file-custody tests with explicitly synthetic public inputs.
//! These tests do not authenticate a release or qualify an installed guest.
use super::*;
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::PathBuf,
};

fn put(path: &Path, raw: &[u8], mode: u32) {
    fs::write(path, raw).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}
struct Fixture {
    _root: tempfile::TempDir,
    base: PathBuf,
    expected: CandidateContext,
    engine: String,
    authorization: Vec<u8>,
    controller: Vec<u8>,
    inventory: Vec<u8>,
    payloads: BTreeMap<String, Vec<u8>>,
}
impl Fixture {
    fn new() -> Self {
        let source: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/installer-public-acquisition.json"
        ))
        .unwrap();
        let authorization = source["authorization"]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec();
        let controller = source["controller"].as_str().unwrap().as_bytes().to_vec();
        let inventory = source["inventory"].as_str().unwrap().as_bytes().to_vec();
        let auth = release::parse_candidate_authorization(&authorization, 100010).unwrap();
        let consumed = release::parse_controller_consumption(&controller, 100010).unwrap();
        let expected = CandidateContext {
            operator_sha: auth.operator_sha256,
            source_sha: auth.source_sha,
            release_tag: auth.release_tag,
            phase: CandidatePhase::Published,
            nonce: auth.nonce,
            harness_source_sha: auth.harness_source_sha,
            run_id: auth.run_id,
            run_attempt: auth.run_attempt,
            hosting: auth.hosting,
        };
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let base = root.path().join("dispatch");
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["inputs", "bootstrap"] {
            let p = base.join(name);
            fs::create_dir(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let payloads = source["payloads"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().as_bytes().to_vec()))
            .collect();
        let result = Self {
            _root: root,
            base,
            expected,
            engine: consumed.engine_id,
            authorization,
            controller,
            inventory,
            payloads,
        };
        result.prepare();
        result
    }
    fn context(&self) -> Context<'_> {
        Context {
            expected: &self.expected,
            engine: &self.engine,
            authorization: &self.authorization,
            controller: &self.controller,
            inventory: &self.inventory,
        }
    }
    fn prepare(&self) {
        let context_hash = release::candidate_context_sha256(&self.expected).unwrap();
        let intent = encode(&json!({"schema":"elevenid.installer-public-acquisition-intent/v1",
            "context_sha256":context_hash,"authorization_sha256":release::sha256(&self.authorization),
            "controller_consumption_sha256":release::sha256(&self.controller),"started_at":100004,"installation_ready":false})).unwrap();
        put(
            &self.base.join("public-acquisition-intent.json"),
            &intent,
            0o600,
        );
        let receipts = self
            .payloads
            .iter()
            .map(|(name, bytes)| DownloadReceipt {
                asset: name.clone(),
                bytes: bytes.len() as u64,
                sha256: release::sha256(bytes),
                hash_verified: SUBJECTS[1..].contains(&name.as_str()),
            })
            .collect();
        let completed = completion(&self.context(), &intent, receipts, 100005).unwrap();
        put(
            &self.base.join("public-acquisition-result.json"),
            &completed,
            0o600,
        );
        let bootstrap = encode(&json!({"schema":"elevenid.installer-public-bootstrap-intent/v1",
            "context_sha256":context_hash,"authorization_sha256":release::sha256(&self.authorization),
            "receipt_sha256":release::sha256(&self.controller),"started_at":100002,"installation_ready":false})).unwrap();
        put(&self.base.join("bootstrap/intent.json"), &bootstrap, 0o600);
        let verified = encode(&json!({"schema":"elevenid.installer-public-bootstrap-verified/v1",
            "context_sha256":context_hash,"authorization_sha256":release::sha256(&self.authorization),
            "receipt_sha256":release::sha256(&self.controller),"inventory_sha256":release::sha256(&self.inventory),
            "operator_sha256":self.expected.operator_sha,"verified_at":100003,"installation_ready":false})).unwrap();
        put(&self.base.join("bootstrap/verified.json"), &verified, 0o600);
        for (name, bytes) in &self.payloads {
            put(&self.base.join("inputs").join(name), bytes, 0o600);
            if ["installer-inventory.json", "marty-deploy-linux-amd64"]
                .iter()
                .any(|n| SUFFIXES.iter().any(|s| *name == format!("{n}{s}")))
            {
                put(
                    &self.base.join("bootstrap").join(name),
                    bytes,
                    if name == "marty-deploy-linux-amd64" {
                        0o700
                    } else {
                        0o600
                    },
                );
            }
        }
    }
    fn capture(&self) -> Result<Capture> {
        Capture::open(
            &self.context(),
            &self.base,
            100010,
            Instant::now() + Duration::from_secs(20),
        )
    }
    fn pins(&self) -> BTreeMap<String, String> {
        let mut pins = BTreeMap::new();
        for (name, raw) in [
            (
                "installer-candidate-authorization.json",
                &self.authorization,
            ),
            ("installer-controller-consumption.json", &self.controller),
            ("installer-inventory.json", &self.inventory),
        ] {
            pins.insert(name.into(), release::sha256(raw));
            for suffix in &SUFFIXES[1..] {
                let name = format!("{name}{suffix}");
                let bytes = self
                    .payloads
                    .get(&name)
                    .map(Vec::as_slice)
                    .unwrap_or(b"synthetic public grant proof");
                pins.insert(name, release::sha256(bytes));
            }
        }
        pins
    }
}
#[test]
fn actual_capture_binds_complete_guest_owner_and_emits_bounded_component() {
    let f = Fixture::new();
    let capture = f.capture().unwrap();
    assert_eq!(capture.receipts.len(), 15);
    let request = crate::installer_startup_observation::StartupObservationRequest::parse(
        "44444444-4444-4444-8444-444444444444",
        &"4".repeat(64),
    )
    .unwrap();
    let raw =
        observation_bytes(&f.context(), &f.pins(), request, &capture, 100010, 100011).unwrap();
    let value: Value = decode(&raw).unwrap();
    assert_eq!(value["schema"], SCHEMA);
    for flag in [
        "installation_ready",
        "acceptance",
        "functional_recovery_qualified",
    ] {
        assert_eq!(value[flag], false);
    }
    assert_eq!(value["owner_records"].as_object().unwrap().len(), 4);
    assert!(!String::from_utf8_lossy(&raw).contains("synthetic public acquisition fixture:"));
    // A local cross-language check can consume this actual native producer output.
    // Every byte in this test is from the explicitly synthetic public fixture.
    println!(
        "PUBLIC_ACQUISITION_NATIVE_FIXTURE={}",
        String::from_utf8(raw).unwrap()
    );
}
#[test]
fn receipt_reader_refuses_incomplete_legacy_wrong_scope_and_changed_bytes() {
    for mutation in [
        "missing-result",
        "legacy-result",
        "wrong-phase",
        "duplicate-receipt",
        "missing-receipt",
        "extra-receipt",
        "receipt-size",
        "receipt-digest",
        "verified-flag",
        "intent-digest",
        "future-completion",
        "bootstrap-operator",
        "bootstrap-order",
        "input-extra",
        "payload-tamper",
        "sidecar-tamper",
        "bootstrap-tamper",
    ] {
        let f = Fixture::new();
        let path = f.base.join("public-acquisition-result.json");
        let mut result: Value = decode(&fs::read(&path).unwrap()).unwrap();
        match mutation {
            "missing-result" => {
                fs::remove_file(&path).unwrap();
            }
            "legacy-result" => {
                result["schema"] = json!("elevenid.installer-public-acquisition-result/v1")
            }
            "wrong-phase" => result["phase"] = json!("staged"),
            "duplicate-receipt" => result["receipts"][1] = result["receipts"][0].clone(),
            "missing-receipt" => {
                result["receipts"].as_array_mut().unwrap().pop();
            }
            "extra-receipt" => {
                let r = result["receipts"][0].clone();
                result["receipts"].as_array_mut().unwrap().push(r);
            }
            "receipt-size" => result["receipts"][0]["bytes"] = json!(1),
            "receipt-digest" => result["receipts"][0]["sha256"] = json!("f".repeat(64)),
            "verified-flag" => {
                let flag = result["receipts"][0]["hash_verified"].as_bool().unwrap();
                result["receipts"][0]["hash_verified"] = json!(!flag);
            }
            "intent-digest" => result["intent_sha256"] = json!("f".repeat(64)),
            "future-completion" => result["completed_at"] = json!(100011),
            "bootstrap-operator" | "bootstrap-order" => {
                let p = f.base.join("bootstrap/verified.json");
                let mut v: Value = decode(&fs::read(&p).unwrap()).unwrap();
                if mutation == "bootstrap-operator" {
                    v["operator_sha256"] = json!("f".repeat(64));
                } else {
                    v["verified_at"] = json!(100006);
                }
                put(&p, &encode(&v).unwrap(), 0o600);
            }
            "input-extra" => put(&f.base.join("inputs/other"), b"public extra", 0o600),
            "payload-tamper" => put(
                &f.base.join("inputs/install.sh"),
                b"changed public payload",
                0o600,
            ),
            "sidecar-tamper" => put(
                &f.base.join("inputs/install.sh.sigstore.json"),
                b"changed public proof",
                0o600,
            ),
            "bootstrap-tamper" => put(
                &f.base.join("bootstrap/marty-deploy-linux-amd64"),
                b"changed public operator",
                0o700,
            ),
            _ => unreachable!(),
        }
        if mutation != "missing-result" {
            put(&path, &encode(&result).unwrap(), 0o600);
        }
        assert!(f.capture().is_err(), "accepted {mutation}");
    }
}
#[test]
fn native_owner_refuses_wrong_phase_attempt_authority_and_expired_replay() {
    for mutation in [
        "staged", "source", "operator", "attempt", "nonce", "engine", "expired",
    ] {
        let mut f = Fixture::new();
        match mutation {
            "staged" => f.expected.phase = CandidatePhase::Staged,
            "source" => f.expected.source_sha = "f".repeat(40),
            "operator" => f.expected.operator_sha = "f".repeat(64),
            "attempt" => f.expected.run_attempt += 1,
            "nonce" => f.expected.nonce = "f".repeat(64),
            "engine" => f.engine = "different-engine".into(),
            "expired" => {}
            _ => unreachable!(),
        }
        let at = if mutation == "expired" {
            103600
        } else {
            100010
        };
        assert!(
            Capture::open(
                &f.context(),
                &f.base,
                at,
                Instant::now() + Duration::from_secs(20)
            )
            .is_err(),
            "accepted {mutation}"
        );
    }
    let mut f = Fixture::new();
    f.expected.phase = CandidatePhase::Staged;
    assert!(Capture::open(
        &f.context(),
        &f.base.join("never-created"),
        100010,
        Instant::now()
    )
    .is_err());
    assert!(!f.base.join("never-created").exists());
}
#[test]
fn held_native_capture_rejects_file_and_parent_substitution_after_success() {
    for mutation in [
        "payload",
        "same-byte-inode",
        "symlink",
        "hardlink",
        "mode-roundtrip",
        "bootstrap-mode",
        "record",
        "parent-roundtrip",
    ] {
        let f = Fixture::new();
        let capture = f.capture().unwrap();
        let path = f.base.join("inputs/install.sh");
        match mutation {
            "payload" => put(&path, b"changed public input", 0o600),
            "same-byte-inode" => {
                let raw = fs::read(&path).unwrap();
                fs::rename(&path, f.base.join("old")).unwrap();
                put(&path, &raw, 0o600);
            }
            "symlink" => {
                fs::rename(&path, f.base.join("old")).unwrap();
                symlink(f.base.join("old"), &path).unwrap();
            }
            "hardlink" => {
                fs::hard_link(&path, f.base.join("alias")).unwrap();
            }
            "mode-roundtrip" => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            "bootstrap-mode" => fs::set_permissions(
                f.base.join("bootstrap/marty-deploy-linux-amd64"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap(),
            "record" => put(&f.base.join("public-acquisition-result.json"), b"{}", 0o600),
            "parent-roundtrip" => {
                let inputs = f.base.join("inputs");
                let moved = f.base.join("moved");
                fs::rename(&inputs, &moved).unwrap();
                fs::rename(&moved, &inputs).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(capture.check().is_err(), "accepted {mutation}");
    }
}
