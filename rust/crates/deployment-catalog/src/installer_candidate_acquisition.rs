//! Read-only, challenged binding of the real published-guest fetch owner.
//! Historical v1 completion and arbitrary case JSON cannot establish this owner.
//! No acquisition replay, installation mutation, Ready or release admission.
use super::{files, hex, now, release, require, CandidateContext, CandidatePhase, Result, REFUSED};
use crate::{
    installer_fetch::DownloadReceipt,
    installer_state::{ExecutionScope, LockedInspection, Phase, RuntimeProfile},
    installer_verify,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    os::fd::AsRawFd,
    path::Path,
    time::{Duration, Instant},
};

const RESULT_SCHEMA: &str = "elevenid.installer-public-acquisition-result/v2";
const SCHEMA: &str = "elevenid.installer-published-acquisition-observation/v1";
const SUBJECTS: [&str; 5] = [
    "installer-inventory.json",
    "install.sh",
    "marty-deploy-linux-amd64",
    "prepared-selfhost-bundle.zip",
    "prepared-selfhost-images.json",
];
const SUFFIXES: [&str; 3] = ["", ".sigstore.json", ".provenance.jsonl"];
const MAX_RECORD: usize = 65_536;

fn decode<T: DeserializeOwned>(raw: &[u8]) -> Result<T> {
    require(!raw.is_empty() && raw.len() <= MAX_RECORD)?;
    serde_json::from_value(crate::installer_json::decode(raw).map_err(|_| REFUSED)?)
        .map_err(|_| REFUSED.into())
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    let raw = serde_json::to_vec(value).map_err(|_| REFUSED)?;
    require(!raw.is_empty() && raw.len() <= MAX_RECORD)?;
    Ok(raw)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: String,
    context_sha256: String,
    authorization_sha256: String,
    controller_consumption_sha256: String,
    started_at: u64,
    installation_ready: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Receipt {
    asset: String,
    bytes: u64,
    sha256: String,
    hash_verified: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    schema: String,
    phase: String,
    context_sha256: String,
    authorization_sha256: String,
    controller_consumption_sha256: String,
    inventory_sha256: String,
    intent_sha256: String,
    started_at: u64,
    completed_at: u64,
    receipts: Vec<Receipt>,
    installation_ready: bool,
}
pub(super) struct Context<'a> {
    pub expected: &'a CandidateContext,
    pub engine: &'a str,
    pub authorization: &'a [u8],
    pub controller: &'a [u8],
    pub inventory: &'a [u8],
}
impl Context<'_> {
    fn bind(&self, at: u64) -> Result<(release::ControllerConsumption, release::Inventory)> {
        require(self.expected.phase == CandidatePhase::Published)?;
        let receipt = release::bind_controller_consumption(
            self.controller,
            self.authorization,
            self.inventory,
            self.expected,
            self.engine,
            at,
        )?;
        Ok((receipt, release::parse_inventory(self.inventory)?))
    }
}
fn validate_completion(
    context: &Context<'_>,
    intent_raw: &[u8],
    result: &Completion,
    at: u64,
) -> Result<()> {
    let (controller, inventory) = context.bind(at)?;
    let intent: Intent = decode(intent_raw)?;
    let context_hash = release::candidate_context_sha256(context.expected)?;
    let authorization_hash = release::sha256(context.authorization);
    let controller_hash = release::sha256(context.controller);
    require(
        intent.schema == "elevenid.installer-public-acquisition-intent/v1"
            && intent.context_sha256 == context_hash
            && intent.authorization_sha256 == authorization_hash
            && intent.controller_consumption_sha256 == controller_hash
            && !intent.installation_ready
            && result.schema == RESULT_SCHEMA
            && result.phase == "published"
            && result.context_sha256 == context_hash
            && result.authorization_sha256 == authorization_hash
            && result.controller_consumption_sha256 == controller_hash
            && result.inventory_sha256 == release::sha256(context.inventory)
            && result.intent_sha256 == release::sha256(intent_raw)
            && !result.installation_ready
            && controller.consumed_at <= intent.started_at
            && intent.started_at == result.started_at
            && result.started_at <= result.completed_at
            && result.completed_at <= at,
    )?;
    let names: BTreeSet<String> = SUBJECTS
        .iter()
        .flat_map(|n| SUFFIXES.iter().map(move |s| format!("{n}{s}")))
        .collect();
    require(
        result.receipts.len() == names.len()
            && result
                .receipts
                .iter()
                .map(|r| r.asset.clone())
                .collect::<BTreeSet<_>>()
                == names,
    )?;
    for receipt in &result.receipts {
        require(hex(&receipt.sha256, 64) && receipt.bytes > 0)?;
        if receipt.asset == "installer-inventory.json" {
            require(
                !receipt.hash_verified
                    && receipt.sha256 == release::sha256(context.inventory)
                    && receipt.bytes == context.inventory.len() as u64,
            )?;
        } else if SUBJECTS.contains(&receipt.asset.as_str()) {
            let artifact = inventory.artifact(&receipt.asset)?;
            require(
                receipt.hash_verified
                    && receipt.sha256 == artifact.sha256
                    && receipt.bytes == artifact.size,
            )?;
        } else {
            require(!receipt.hash_verified && receipt.bytes <= 1_048_576)?;
        }
    }
    Ok(())
}

/// Only the authenticated native fetch calls this after its exact byte/provenance
/// checks. The reader repeats all bindings; this helper grants no authority.
pub(super) fn completion(
    context: &Context<'_>,
    intent_raw: &[u8],
    receipts: Vec<DownloadReceipt>,
    at: u64,
) -> Result<Vec<u8>> {
    let intent: Intent = decode(intent_raw)?;
    let value = Completion {
        schema: RESULT_SCHEMA.into(),
        phase: "published".into(),
        context_sha256: release::candidate_context_sha256(context.expected)?,
        authorization_sha256: release::sha256(context.authorization),
        controller_consumption_sha256: release::sha256(context.controller),
        inventory_sha256: release::sha256(context.inventory),
        intent_sha256: release::sha256(intent_raw),
        started_at: intent.started_at,
        completed_at: at,
        receipts: receipts
            .into_iter()
            .map(|r| Receipt {
                asset: r.asset,
                bytes: r.bytes,
                sha256: r.sha256,
                hash_verified: r.hash_verified,
            })
            .collect(),
        installation_ready: false,
    };
    validate_completion(context, intent_raw, &value, at)?;
    encode(&value)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapIntent {
    schema: String,
    context_sha256: String,
    authorization_sha256: String,
    receipt_sha256: String,
    started_at: u64,
    installation_ready: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapVerified {
    schema: String,
    context_sha256: String,
    inventory_sha256: String,
    operator_sha256: String,
    authorization_sha256: String,
    receipt_sha256: String,
    verified_at: u64,
    installation_ready: bool,
}
#[derive(Serialize)]
struct OwnerRecord {
    sha256: String,
    record: String,
}
fn bounded_names(path: &Path, limit: usize) -> Result<BTreeSet<String>> {
    let held = super::held_private_directory(path)?;
    let names = std::fs::read_dir(format!("/proc/self/fd/{}", held.as_raw_fd()))
        .map_err(|_| REFUSED)?
        .take(limit + 1)
        .map(|entry| {
            entry
                .map_err(|_| REFUSED.to_owned())?
                .file_name()
                .into_string()
                .map_err(|_| REFUSED.into())
        })
        .collect::<Result<BTreeSet<_>>>()?;
    require(names.len() == limit)?;
    super::directory_unchanged(&held, path)?;
    Ok(names)
}

struct Capture {
    records: BTreeMap<&'static str, files::HeldInput>,
    assets: Vec<files::HeldAsset>,
    receipts: Vec<Receipt>,
}
impl Capture {
    fn open(context: &Context<'_>, base: &Path, at: u64, deadline: Instant) -> Result<Self> {
        context.bind(at)?;
        let mut records = BTreeMap::new();
        for (name, path) in [
            ("intent", base.join("public-acquisition-intent.json")),
            ("completion", base.join("public-acquisition-result.json")),
            ("bootstrap_intent", base.join("bootstrap/intent.json")),
            ("bootstrap_verified", base.join("bootstrap/verified.json")),
        ] {
            records.insert(name, files::HeldInput::open(&path, MAX_RECORD)?);
        }
        let result: Completion = decode(records["completion"].bytes())?;
        validate_completion(context, records["intent"].bytes(), &result, at)?;
        let intent: BootstrapIntent = decode(records["bootstrap_intent"].bytes())?;
        let verified: BootstrapVerified = decode(records["bootstrap_verified"].bytes())?;
        let controller = context.bind(at)?.0;
        require(
            intent.schema == "elevenid.installer-public-bootstrap-intent/v1"
                && verified.schema == "elevenid.installer-public-bootstrap-verified/v1"
                && intent.context_sha256 == result.context_sha256
                && verified.context_sha256 == result.context_sha256
                && intent.authorization_sha256 == result.authorization_sha256
                && verified.authorization_sha256 == result.authorization_sha256
                && intent.receipt_sha256 == result.controller_consumption_sha256
                && verified.receipt_sha256 == result.controller_consumption_sha256
                && verified.inventory_sha256 == result.inventory_sha256
                && verified.operator_sha256 == context.expected.operator_sha
                && !intent.installation_ready
                && !verified.installation_ready
                && controller.consumed_at <= intent.started_at
                && intent.started_at <= verified.verified_at
                && verified.verified_at <= result.started_at,
        )?;
        let input_names = bounded_names(&base.join("inputs"), 15)?;
        require(input_names == result.receipts.iter().map(|r| r.asset.clone()).collect())?;
        let bootstrap_names = bounded_names(&base.join("bootstrap"), 8)?;
        let expected_bootstrap: BTreeSet<String> =
            ["installer-inventory.json", "marty-deploy-linux-amd64"]
                .iter()
                .flat_map(|n| SUFFIXES.iter().map(move |s| format!("{n}{s}")))
                .chain(["intent.json".into(), "verified.json".into()])
                .collect();
        require(bootstrap_names == expected_bootstrap)?;
        let mut assets = Vec::new();
        for receipt in &result.receipts {
            assets.push(files::HeldAsset::open(
                &base.join("inputs").join(&receipt.asset),
                &receipt.sha256,
                receipt.bytes,
                false,
                deadline,
            )?);
            if ["installer-inventory.json", "marty-deploy-linux-amd64"]
                .iter()
                .any(|name| {
                    SUFFIXES
                        .iter()
                        .any(|suffix| receipt.asset == format!("{name}{suffix}"))
                })
            {
                assets.push(files::HeldAsset::open(
                    &base.join("bootstrap").join(&receipt.asset),
                    &receipt.sha256,
                    receipt.bytes,
                    receipt.asset == "marty-deploy-linux-amd64",
                    deadline,
                )?);
            }
        }
        let capture = Self {
            records,
            assets,
            receipts: result.receipts,
        };
        capture.check()?;
        Ok(capture)
    }
    fn check(&self) -> Result<()> {
        for record in self.records.values() {
            record.check()?;
        }
        for asset in &self.assets {
            asset.check()?;
        }
        Ok(())
    }
    fn public_records(&self) -> Result<BTreeMap<&'static str, OwnerRecord>> {
        self.records
            .iter()
            .map(|(name, held)| {
                Ok((
                    *name,
                    OwnerRecord {
                        sha256: release::sha256(held.bytes()),
                        record: String::from_utf8(held.bytes().to_vec()).map_err(|_| REFUSED)?,
                    },
                ))
            })
            .collect()
    }
}

fn observation_bytes(
    context: &Context<'_>,
    pins: &BTreeMap<String, String>,
    request: crate::installer_startup_observation::StartupObservationRequest,
    captured: &Capture,
    started_at: u64,
    completed_at: u64,
) -> Result<Vec<u8>> {
    let controller = context.bind(completed_at)?; // Never renew the original grant.
    let controller = controller.0;
    require(
        controller.consumed_at <= started_at
            && started_at <= completed_at
            && completed_at - started_at <= 120,
    )?;
    let value = serde_json::json!({
        "schema": SCHEMA, "phase": "published", "request": request,
        "source_sha": context.expected.source_sha, "release_tag": context.expected.release_tag,
        "build_run_id": controller.build_run_id, "build_run_attempt": controller.build_run_attempt,
        "harness_source_sha": controller.harness_source_sha,
        "run_id": controller.run_id, "run_attempt": controller.run_attempt,
        "guest_id": controller.guest_id, "disk_id": controller.disk_id,
        "installation_id": controller.installation_id, "engine_id": controller.engine_id,
        "operator_sha256": context.expected.operator_sha, "context_sha256": controller.context_sha256,
        "authorization_sha256": release::sha256(context.authorization),
        "controller_consumption_sha256": release::sha256(context.controller),
        "inventory_sha256": release::sha256(context.inventory), "authenticated_evidence_sha256": pins,
        "started_at": started_at, "completed_at": completed_at, "owner_records": captured.public_records()?,
        "receipts": captured.receipts, "installation_ready": false, "acceptance": false,
        "functional_recovery_qualified": false
    });
    encode(&value)
}

pub(super) fn observe(args: &[String], build_identity: &str) -> Result<()> {
    require(args.len() == 6)?;
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        require(
            ["--install-dir", "--observation-id", "--challenge"].contains(&pair[0].as_str())
                && values.insert(pair[0].as_str(), pair[1].clone()).is_none(),
        )?;
    }
    let installation = super::path(values.remove("--install-dir").ok_or(REFUSED)?)?;
    let request = crate::installer_startup_observation::StartupObservationRequest::parse(
        values.get("--observation-id").ok_or(REFUSED)?,
        values.get("--challenge").ok_or(REFUSED)?,
    )?;
    crate::installer_command::require_rootless_process()?;
    require(cfg!(target_arch = "x86_64"))?;
    let home = super::account_home()?;
    let view = LockedInspection::open(&installation)?;
    view.require_path_binding(&installation)?;
    let journal = view.journal();
    require(
        matches!(journal.execution_scope(), ExecutionScope::AcceptanceOnly(_))
            && journal.phase() == Phase::Provisioning
            && journal.runtime().ok_or(REFUSED)?.profile == RuntimeProfile::Rootless,
    )?;
    require(installation == home.join(format!("marty-install-{}", journal.installation_id())))?;
    let base = home.join(format!(
        ".marty-installer-dispatch-{}",
        journal.installation_id()
    ));
    require(
        std::env::current_exe().map_err(|_| REFUSED)?
            == base.join("bootstrap/marty-deploy-linux-amd64"),
    )?;
    let (source, version) = build_identity.split_once(':').ok_or(REFUSED)?;
    require(source == journal.identity().source_sha && version == journal.identity().release_tag)?;
    let operator = installer_verify::current_operator_digest()?;
    let pins = super::require_retained_scope(&view, &operator)?;
    let authorization = view.read_evidence("installer-candidate-authorization.json")?;
    let controller_raw = view.read_evidence("installer-controller-consumption.json")?;
    let inventory = view.read_evidence("installer-inventory.json")?;
    let started_at = now()?;
    let controller = release::parse_controller_consumption(&controller_raw, started_at)?;
    require(controller.phase == CandidatePhase::Published)?;
    let expected = CandidateContext {
        operator_sha: operator.clone(),
        source_sha: source.into(),
        release_tag: version.into(),
        phase: CandidatePhase::Published,
        nonce: controller.nonce.clone(),
        harness_source_sha: controller.harness_source_sha.clone(),
        run_id: controller.run_id,
        run_attempt: controller.run_attempt,
        hosting: controller.hosting.clone(),
    };
    let context = Context {
        expected: &expected,
        engine: &journal.runtime().ok_or(REFUSED)?.engine_id,
        authorization: &authorization,
        controller: &controller_raw,
        inventory: &inventory,
    };
    let captured = Capture::open(
        &context,
        &base,
        started_at,
        Instant::now() + Duration::from_secs(120),
    )?;
    captured.check()?;
    view.require_unchanged()?;
    // All held owner/assets have been checked before the completion clock.
    // Encoding cached public hashes performs no further guest operation.
    let bytes = observation_bytes(&context, &pins, request, &captured, started_at, now()?)?;
    view.require_unchanged()?;
    context.bind(now()?)?;
    println!("{}", std::str::from_utf8(&bytes).map_err(|_| REFUSED)?);
    Ok(())
}

#[cfg(test)]
#[path = "installer_candidate_acquisition_tests.rs"]
mod tests;
