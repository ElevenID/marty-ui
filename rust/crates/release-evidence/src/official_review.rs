//! Scope manual dispositions to exact candidate evidence without changing OIDF.
//!
//! Authentication is the caller's boundary: load disposition bytes only from an
//! immutable commit resolved through the authenticated protected-main API. Never
//! use a review supplied by the candidate, its artifacts, or an arbitrary ref.
//! This is the same trust boundary as authenticated Actions/maintainer-review
//! inputs elsewhere in this crate. A valid local JSON file is not authorization.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::official::{
    assess_official_suite, candidate_receipt, digest, LaneReceipt, OfficialReceipt,
};

pub const MAX_DISPOSITION_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewModule {
    pub test_name: String,
    pub test_id: String,
    pub plan_id: String,
    pub official_result: String,
    pub screenshot_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReviewRequest {
    pub schema: String,
    pub source: String,
    pub status: String,
    pub original_evidence_sha256: String,
    pub capture_receipt_sha256: String,
    pub official_export_sha256: String,
    pub plan_binding_sha256: String,
    pub modules: Vec<ReviewModule>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingReview {
    pub lane: String,
    pub evidence_source: String,
    pub original_evidence_sha256: String,
    pub capture_receipt_sha256: String,
    pub official_export_sha256: String,
    pub plan_binding_sha256: String,
    pub module: ReviewModule,
}

#[derive(Debug, Serialize)]
pub struct OfficialReviewPlan {
    pub schema: &'static str,
    pub source_sha: String,
    pub harness_sha: String,
    pub manifest_sha256: String,
    pub run_id: u64,
    /// Origin of the frozen evidence, not the attempt of a later gate retry.
    pub run_attempt: u64,
    pub release_qualified: bool,
    pub lanes: Vec<LaneReceipt>,
    pub pending: Vec<PendingReview>,
}

impl OfficialReviewPlan {
    /// The CLI emits these exact bytes, without a trailing newline. Reviewers
    /// can use sha256sum on that file; no second JSON canonicalization exists.
    pub fn bytes(&self) -> Result<Vec<u8>, &'static str> {
        serde_json::to_vec(self).map_err(|_| "cannot serialize official review request")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reviewer {
    pub kind: String,
    pub github_login: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseDisposition {
    lane: String,
    module: ReviewModule,
    verdict: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Disposition {
    schema: String,
    run_id: u64,
    run_attempt: u64,
    request_sha256: String,
    verdict: String,
    reviewer: Reviewer,
    cases: Vec<CaseDisposition>,
}

#[derive(Debug, Serialize)]
pub struct AcceptedDisposition {
    pub schema: &'static str,
    pub protected_main_commit: String,
    pub record_sha256: String,
    pub request_sha256: String,
    pub evidence_run_attempt: u64,
    pub reviewer: Reviewer,
    pub reviewed_cases: usize,
    pub original_official_results_unchanged: bool,
}

pub(crate) fn is_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

pub(crate) fn is_official_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 180
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

pub fn prepare_official_review(
    manifest: &[u8],
    summaries: &[Vec<u8>],
    source: &str,
    harness: &str,
    run_id: u64,
    run_attempt: u64,
) -> Result<OfficialReviewPlan, &'static str> {
    if run_attempt == 0 {
        return Err("official evidence attempt is invalid");
    }
    let assessed = assess_official_suite(manifest, summaries, source, harness, run_id, true)?;
    Ok(OfficialReviewPlan {
        schema: "marty.official-review-plan/v1",
        source_sha: source.into(),
        harness_sha: harness.into(),
        manifest_sha256: assessed.manifest_sha256,
        run_id,
        run_attempt,
        release_qualified: false,
        lanes: assessed.lanes,
        pending: assessed.pending,
    })
}

/// Only call with a disposition fetched from protected main by the trusted
/// release workflow. JSON shape, actor strings, and an approved flag alone do
/// not authenticate anything. The main commit is retained in the final proof.
pub fn validate_official_review(
    plan: &OfficialReviewPlan,
    record: &[u8],
    protected_main_commit: &str,
) -> Result<AcceptedDisposition, &'static str> {
    if !crate::is_source(protected_main_commit)
        || record.len() > MAX_DISPOSITION_BYTES
        || plan.pending.is_empty()
    {
        return Err("official review authorization input is invalid");
    }
    let disposition: Disposition = crate::json_evidence::parse_strict(record)?;
    let request_sha256 = digest(&plan.bytes()?);
    if disposition.schema != "marty.official-review-disposition/v1"
        || disposition.run_id != plan.run_id
        || disposition.run_attempt != plan.run_attempt
        || disposition.request_sha256 != request_sha256
        || disposition.verdict != "accepted"
        || !matches!(
            disposition.reviewer.kind.as_str(),
            "human" | "delegated_codex"
        )
        || !crate::is_github_login(&disposition.reviewer.github_login)
        || disposition.cases.len() != plan.pending.len()
    {
        return Err("official review is rejected, foreign, stale or incomplete");
    }
    let mut seen = BTreeSet::new();
    for case in &disposition.cases {
        if case.verdict != "accepted"
            || !seen.insert((&case.lane, &case.module.test_name))
            || !plan
                .pending
                .iter()
                .any(|pending| pending.lane == case.lane && pending.module == case.module)
        {
            return Err("official review case is rejected, duplicated or bound to another image");
        }
    }
    Ok(AcceptedDisposition {
        schema: "marty.accepted-official-review/v1",
        protected_main_commit: protected_main_commit.into(),
        record_sha256: digest(record),
        request_sha256,
        evidence_run_attempt: plan.run_attempt,
        reviewer: disposition.reviewer,
        reviewed_cases: plan.pending.len(),
        original_official_results_unchanged: true,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn validate_official_suite_with_review(
    manifest: &[u8],
    summaries: &[Vec<u8>],
    source: &str,
    harness: &str,
    run_id: u64,
    run_attempt: u64,
    record: &[u8],
    protected_main_commit: &str,
) -> Result<OfficialReceipt, &'static str> {
    let plan = prepare_official_review(manifest, summaries, source, harness, run_id, run_attempt)?;
    let review = validate_official_review(&plan, record, protected_main_commit)?;
    // The same assessment supplies the resulting candidate receipt. Avoid a
    // second, independently evolving acceptance path or re-reading files.
    Ok(candidate_receipt(
        plan.manifest_sha256,
        plan.lanes,
        &plan.source_sha,
        &plan.harness_sha,
        run_id,
        Some(review),
    ))
}
