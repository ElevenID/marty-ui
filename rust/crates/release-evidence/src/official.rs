//! Gate current-run official summaries against the exact pre-promotion candidate.
//! The caller downloads artifacts from this release run only, after all seven
//! reusable collection jobs succeed. This validates evidence, not attestation.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::official_review::{AcceptedDisposition, PendingReview, ReviewRequest};

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
    #[serde(default)]
    process_exit_code: Option<i32>,
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
    #[serde(default)]
    local_runtime_binding: Option<Value>,
    #[serde(default)]
    review_requests: Vec<ReviewRequest>,
    #[serde(default)]
    browser_evidence: Option<Value>,
}

#[derive(Deserialize)]
struct OfficialEvidence {
    #[serde(default)]
    source: String,
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
    #[serde(default)]
    artifacts: Vec<Artifact>,
}

#[derive(Deserialize)]
struct Artifact {
    path: String,
    sha256: String,
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
    #[serde(default)]
    binding_sha256: String,
    #[serde(default)]
    module_bindings: Vec<ModuleBinding>,
}

#[derive(Deserialize)]
struct ModuleBinding {
    test_name: String,
    test_id: String,
}

fn validate_oidf_modules(
    evidence: &Evidence,
    collect_review: bool,
) -> Result<BTreeSet<&str>, &'static str> {
    let modules = evidence
        .module_results
        .as_ref()
        .ok_or("OIDF module results are missing")?;
    let coverage = &modules.plan_coverage;
    let expected = coverage.expected_modules.iter().collect::<BTreeSet<_>>();
    if modules.schema != "elevenid.official-oidf-module-results/v1"
        || modules.source_policy != "unmodified"
        || !collect_review && (!modules.passed || !modules.pending_review.is_empty())
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
    let mut review = BTreeSet::new();
    for module in &modules.modules {
        if module.test_name.is_empty()
            || !seen.insert(&module.test_name)
            || !expected.contains(&module.test_name)
            || module.status != "FINISHED"
            || !(module.result == "PASSED"
                || collect_review && module.result == "REVIEW"
                || module.result == "SKIPPED"
                    && permitted_skips.contains(module.test_name.as_str()))
        {
            return Err("OIDF module is missing, duplicated, unfinished, failed or unreviewed");
        }
        *observed.entry(module.result.clone()).or_default() += 1;
        if module.result == "REVIEW" {
            review.insert(module.test_name.as_str());
        }
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
    let pending = modules
        .pending_review
        .iter()
        .map(|value| value.as_str().ok_or("OIDF pending review name is invalid"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if pending != review
        || pending.len() != modules.pending_review.len()
        || modules.passed != review.is_empty()
    {
        return Err("OIDF pending review does not match the actual module results");
    }
    Ok(review)
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_disposition: Option<AcceptedDisposition>,
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

pub fn validate_official_suite(
    manifest: &[u8],
    summaries: &[Vec<u8>],
    source: &str,
    harness: &str,
    run_id: u64,
) -> Result<OfficialReceipt, &'static str> {
    let assessed = assess_official_suite(manifest, summaries, source, harness, run_id, false)?;
    Ok(assessed.receipt(source, harness, run_id, None))
}

pub(crate) struct AssessedSuite {
    pub manifest_sha256: String,
    pub lanes: Vec<LaneReceipt>,
    pub pending: Vec<PendingReview>,
}

impl AssessedSuite {
    pub fn receipt(
        self,
        source: &str,
        harness: &str,
        run_id: u64,
        review_disposition: Option<AcceptedDisposition>,
    ) -> OfficialReceipt {
        candidate_receipt(
            self.manifest_sha256,
            self.lanes,
            source,
            harness,
            run_id,
            review_disposition,
        )
    }
}

pub(crate) fn candidate_receipt(
    manifest_sha256: String,
    lanes: Vec<LaneReceipt>,
    source: &str,
    harness: &str,
    run_id: u64,
    review_disposition: Option<AcceptedDisposition>,
) -> OfficialReceipt {
    OfficialReceipt {
        schema: "marty.official-release-gate/v1",
        source_sha: source.into(),
        harness_sha: harness.into(),
        manifest_sha256,
        run_id,
        qualification_context: "PRE_PUBLICATION_CANDIDATE",
        lanes,
        review_disposition,
    }
}

fn outcome_matches(outcome: &Outcome, pending: bool) -> bool {
    outcome.skipped == 0
        && outcome.process_exit_code.is_none_or(|code| code == 0)
        && if pending {
            outcome.exit_code == 1 && !outcome.passed
        } else {
            outcome.exit_code == 0 && outcome.passed
        }
}

fn bind_review_request(
    lane: &str,
    wrapper: &OfficialEvidence,
    review: &BTreeSet<&str>,
    requests: &[ReviewRequest],
) -> Result<Vec<PendingReview>, &'static str> {
    let evidence = &wrapper.evidence;
    let coverage = &evidence.module_results.as_ref().unwrap().plan_coverage;
    let matching = requests
        .iter()
        .filter(|request| request.source == wrapper.source)
        .collect::<Vec<_>>();
    let [request] = matching.as_slice() else {
        return Err("OIDF review request is missing or duplicated");
    };
    if request.schema != "elevenid.official-review-request/v1"
        || request.status != "PENDING"
        || wrapper.source.is_empty()
        || request.modules.len() != review.len()
        || !crate::official_review::is_digest(&request.original_evidence_sha256)
        || !crate::official_review::is_digest(&request.capture_receipt_sha256)
        || !crate::official_review::is_digest(&request.official_export_sha256)
        || !crate::official_review::is_digest(&request.plan_binding_sha256)
        || request.plan_binding_sha256 != format!("sha256:{}", coverage.binding_sha256)
        || coverage.module_bindings.len() != coverage.expected_modules.len()
    {
        return Err("OIDF review request is malformed, incomplete or belongs to another plan");
    }
    let capture = evidence
        .artifacts
        .iter()
        .filter(|artifact| artifact.path == "official-real-ui-images.json")
        .collect::<Vec<_>>();
    if capture.len() != 1 || capture[0].sha256 != request.capture_receipt_sha256 {
        return Err("OIDF capture receipt is not bound to the original evidence inventory");
    }
    let mut bindings = BTreeMap::new();
    let mut bound_ids = BTreeSet::new();
    for binding in &coverage.module_bindings {
        if !coverage.expected_modules.contains(&binding.test_name)
            || !crate::official_review::is_official_id(&binding.test_id)
            || !bound_ids.insert(&binding.test_id)
            || bindings
                .insert(&binding.test_name, &binding.test_id)
                .is_some()
        {
            return Err("OIDF review module binding is invalid or duplicated");
        }
    }
    let mut seen = BTreeSet::new();
    let mut plan_ids = BTreeSet::new();
    let mut pending = Vec::new();
    for module in &request.modules {
        if !review.contains(module.test_name.as_str())
            || !seen.insert(module.test_name.as_str())
            || module.official_result != "REVIEW"
            || !crate::official_review::is_official_id(&module.test_id)
            || !crate::official_review::is_official_id(&module.plan_id)
            || !crate::official_review::is_digest(&module.screenshot_sha256)
            || bindings.get(&module.test_name) != Some(&&module.test_id)
        {
            return Err(
                "OIDF review image is foreign, duplicated or lacks its exact module binding",
            );
        }
        plan_ids.insert(&module.plan_id);
        pending.push(PendingReview {
            lane: lane.into(),
            evidence_source: wrapper.source.clone(),
            original_evidence_sha256: request.original_evidence_sha256.clone(),
            capture_receipt_sha256: request.capture_receipt_sha256.clone(),
            official_export_sha256: request.official_export_sha256.clone(),
            plan_binding_sha256: request.plan_binding_sha256.clone(),
            module: module.clone(),
        });
    }
    if plan_ids.len() != 1 {
        return Err("OIDF review images belong to different official plans");
    }
    Ok(pending)
}

pub(crate) fn assess_official_suite(
    manifest: &[u8],
    summaries: &[Vec<u8>],
    source: &str,
    harness: &str,
    run_id: u64,
    collect_review: bool,
) -> Result<AssessedSuite, &'static str> {
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
    let mut pending = Vec::new();
    for bytes in summaries {
        if bytes.len() > MAX_SUMMARY_BYTES {
            return Err("official summary exceeds size limit");
        }
        let summary: Summary = crate::json_evidence::parse_strict(bytes)?;
        if summary.schema != "elevenid.sanitized-official-interop/v1"
            || !LANES.contains(&summary.lane.as_str())
            || !seen.insert(summary.lane.clone())
            || summary.harness_commit != harness
            || summary.result.skipped != 0
            || summary.local_runtime_binding.is_some()
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
        let mut lane_pending = false;
        let mut requests_used = 0;
        for wrapper in &summary.official_evidence {
            let evidence = &wrapper.evidence;
            if evidence.schema != "elevenid.official-interop-evidence/v1"
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
            let mut evidence_pending = false;
            if !matches!(summary.lane.as_str(), "w3c-v2" | "eudi") {
                let reviews = validate_oidf_modules(evidence, collect_review)?;
                evidence_pending = !reviews.is_empty();
                if evidence_pending {
                    if evidence.result.process_exit_code != Some(0) {
                        return Err("OIDF review cannot excuse an unsuccessful runner process");
                    }
                    pending.extend(bind_review_request(
                        &summary.lane,
                        wrapper,
                        &reviews,
                        &summary.review_requests,
                    )?);
                    requests_used += 1;
                }
            }
            if !outcome_matches(&evidence.result, evidence_pending) {
                return Err("official suite verdict does not match its completed module results");
            }
            lane_pending |= evidence_pending;
        }
        if !outcome_matches(&summary.result, lane_pending)
            || requests_used != summary.review_requests.len()
        {
            return Err("official lane verdict or review inventory is inconsistent");
        }
        if lane_pending && summary.lane == "oid4vp-final" {
            let browser = summary.browser_evidence.as_ref();
            if browser
                .and_then(|value| value.get("schema"))
                .and_then(Value::as_str)
                != Some("elevenid.released-browser-smoke/v1")
                || browser
                    .and_then(|value| value.get("status"))
                    .and_then(Value::as_str)
                    != Some("passed")
                || browser
                    .and_then(|value| value.get("private_selectors_observed"))
                    .and_then(Value::as_bool)
                    != Some(false)
            {
                return Err("OIDF review cannot excuse missing or failed real browser evidence");
            }
        }
        for junit in &summary.junit {
            if junit.get("failures").and_then(Value::as_u64) != Some(0)
                || junit.get("errors").and_then(Value::as_u64) != Some(0)
                || junit
                    .get("tests")
                    .and_then(Value::as_u64)
                    .is_none_or(|count| count == 0)
                || junit.get("skipped").and_then(Value::as_u64) != Some(0)
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
    pending.sort_by(|left, right| {
        (&left.lane, &left.module.test_name).cmp(&(&right.lane, &right.module.test_name))
    });
    Ok(AssessedSuite {
        manifest_sha256,
        lanes,
        pending,
    })
}
