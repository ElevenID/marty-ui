//! Gate current-run official summaries against the exact pre-promotion candidate.
//! The caller downloads artifacts from this release run only, after all seven
//! reusable workflow jobs succeed. This validates evidence, not attestation.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const LANES: [&str; 7] = [
    "oid4vci-issuer",
    "oid4vp-final",
    "oid4vp-url-query",
    "oid4vp-mdoc",
    "haip",
    "w3c-v2",
    "eudi",
];
pub const MAX_SUMMARY_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 2 * 1024 * 1024;

#[derive(Deserialize)]
struct Outcome {
    exit_code: i32,
    passed: bool,
    #[serde(default)]
    skipped: u64,
}

#[derive(Deserialize)]
struct Stack {
    schema: String,
    marty_commit: String,
    manifest_sha256: String,
    qualification_context: String,
    published_release: bool,
}

#[derive(Deserialize)]
struct Summary {
    schema: String,
    lane: String,
    harness_commit: String,
    result: Outcome,
    stack: Stack,
    official_evidence: Vec<OfficialEvidence>,
    #[serde(default)]
    junit: Vec<Value>,
}

#[derive(Deserialize)]
struct OfficialEvidence {
    evidence: Evidence,
}

#[derive(Deserialize)]
struct Evidence {
    schema: String,
    result: Outcome,
    marty: Marty,
    #[serde(default)]
    execution_mode: Option<String>,
    #[serde(default)]
    exclusions: Value,
    #[serde(default)]
    module_results: Option<ModuleResults>,
}

#[derive(Deserialize)]
struct ModuleResults {
    schema: String,
    source_policy: String,
    passed: bool,
    counts: BTreeMap<String, u64>,
    modules: Vec<ModuleResult>,
    pending_review: Vec<Value>,
    unexpected_skips: Vec<Value>,
    plan_coverage: PlanCoverage,
}

#[derive(Deserialize)]
struct ModuleResult {
    test_name: String,
    status: String,
    result: String,
}

#[derive(Deserialize)]
struct PlanCoverage {
    complete: bool,
    expected_modules: Vec<String>,
    missing_modules: Vec<String>,
    exported_module_count: usize,
}

fn validate_oidf_modules(evidence: &Evidence) -> Result<(), &'static str> {
    let modules = evidence
        .module_results
        .as_ref()
        .ok_or("OIDF module results are missing")?;
    let coverage = &modules.plan_coverage;
    let expected = coverage.expected_modules.iter().collect::<BTreeSet<_>>();
    if modules.schema != "elevenid.official-oidf-module-results/v1"
        || modules.source_policy != "unmodified"
        || !modules.passed
        || !modules.pending_review.is_empty()
        || !modules.unexpected_skips.is_empty()
        || !coverage.complete
        || !coverage.missing_modules.is_empty()
        || expected.is_empty()
        || expected.len() != coverage.expected_modules.len()
        || coverage.exported_module_count != expected.len()
        || modules.modules.len() != expected.len()
    {
        return Err("OIDF modules are modified, pending review or incomplete");
    }
    // The accepted harness selects these optional skips for its exact profile.
    // An exit-zero flag cannot authorize any additional skipped module.
    let expected_skips = evidence
        .exclusions
        .get("expected_skips")
        .and_then(Value::as_array)
        .ok_or("OIDF skip disposition is missing")?;
    let mut permitted_skips = BTreeSet::new();
    for skip in expected_skips {
        let name = skip
            .get("test-name")
            .and_then(Value::as_str)
            .ok_or("OIDF skip disposition is malformed")?;
        if !permitted_skips.insert(name) {
            return Err("OIDF skip dispositions are duplicated");
        }
    }
    let mut seen = BTreeSet::new();
    let mut observed = BTreeMap::<String, u64>::new();
    for module in &modules.modules {
        if module.test_name.is_empty()
            || !seen.insert(&module.test_name)
            || !expected.contains(&module.test_name)
            || module.status != "FINISHED"
            || !(module.result == "PASSED"
                || module.result == "SKIPPED"
                    && permitted_skips.contains(module.test_name.as_str()))
        {
            return Err("OIDF module is missing, duplicated, unfinished, failed or unreviewed");
        }
        *observed.entry(module.result.clone()).or_default() += 1;
    }
    if observed.get("PASSED").copied().unwrap_or_default() == 0
        || observed
            .iter()
            .any(|(name, count)| modules.counts.get(name) != Some(count))
        || modules
            .counts
            .iter()
            .any(|(name, count)| *count != observed.get(name).copied().unwrap_or_default())
    {
        return Err("OIDF module counts do not establish a completed passing plan");
    }
    Ok(())
}

#[derive(Deserialize)]
struct Marty {
    commit: String,
}

#[derive(Debug, Serialize)]
pub struct LaneReceipt {
    pub lane: String,
    pub summary_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct OfficialReceipt {
    pub schema: &'static str,
    pub source_sha: String,
    pub harness_sha: String,
    pub manifest_sha256: String,
    pub run_id: u64,
    pub qualification_context: &'static str,
    pub lanes: Vec<LaneReceipt>,
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

pub fn validate_official_suite(
    manifest: &[u8],
    summaries: &[Vec<u8>],
    source: &str,
    harness: &str,
    run_id: u64,
) -> Result<OfficialReceipt, &'static str> {
    if !crate::is_source(source)
        || !crate::is_source(harness)
        || run_id == 0
        || manifest.len() > MAX_MANIFEST_BYTES
        || summaries.len() != LANES.len()
    {
        return Err("official candidate identity or evidence count is invalid");
    }
    let manifest_sha256 = digest(manifest);
    let mut seen = BTreeSet::new();
    let mut lanes = Vec::new();
    for bytes in summaries {
        if bytes.len() > MAX_SUMMARY_BYTES {
            return Err("official summary exceeds size limit");
        }
        let summary: Summary =
            serde_json::from_slice(bytes).map_err(|_| "official summary is malformed")?;
        if summary.schema != "elevenid.sanitized-official-interop/v1"
            || !LANES.contains(&summary.lane.as_str())
            || !seen.insert(summary.lane.clone())
            || summary.harness_commit != harness
            || summary.result.exit_code != 0
            || !summary.result.passed
            || summary.result.skipped != 0
            || summary.stack.schema != "elevenid.official-stack-material/v1"
            || summary.stack.marty_commit != source
            || summary.stack.manifest_sha256 != manifest_sha256
            || summary.stack.qualification_context != "PRE_PUBLICATION_CANDIDATE"
            || summary.stack.published_release
        {
            return Err("official lane is failed, stale, foreign, duplicated or not a candidate");
        }
        if summary.official_evidence.is_empty() {
            return Err("official lane contains no suite evidence");
        }
        for wrapper in &summary.official_evidence {
            let evidence = &wrapper.evidence;
            if evidence.schema != "elevenid.official-interop-evidence/v1"
                || evidence.result.exit_code != 0
                || !evidence.result.passed
                || evidence.result.skipped != 0
                || evidence.marty.commit != source
                || evidence
                    .execution_mode
                    .as_deref()
                    .is_some_and(|mode| mode != "active")
                || evidence
                    .exclusions
                    .get("expected_failures")
                    .is_some_and(|value| value.as_array().is_none_or(|values| !values.is_empty()))
            {
                return Err(
                    "official suite evidence is failed, skipped, pre-activation or foreign",
                );
            }
            if !matches!(summary.lane.as_str(), "w3c-v2" | "eudi") {
                validate_oidf_modules(evidence)?;
            }
        }
        for junit in &summary.junit {
            if junit.get("failures").and_then(Value::as_u64) != Some(0)
                || junit.get("errors").and_then(Value::as_u64) != Some(0)
                || junit
                    .get("tests")
                    .and_then(Value::as_u64)
                    .is_none_or(|count| count == 0)
                || junit
                    .get("skipped")
                    .and_then(Value::as_u64)
                    .zip(junit.get("tests").and_then(Value::as_u64))
                    .is_none_or(|(skipped, tests)| skipped >= tests)
            {
                return Err("official JUnit evidence is empty, skipped or failing");
            }
        }
        lanes.push(LaneReceipt {
            lane: summary.lane,
            summary_sha256: digest(bytes),
        });
    }
    lanes.sort_by(|left, right| left.lane.cmp(&right.lane));
    Ok(OfficialReceipt {
        schema: "marty.official-release-gate/v1",
        source_sha: source.into(),
        harness_sha: harness.into(),
        manifest_sha256,
        run_id,
        qualification_context: "PRE_PUBLICATION_CANDIDATE",
        lanes,
    })
}
