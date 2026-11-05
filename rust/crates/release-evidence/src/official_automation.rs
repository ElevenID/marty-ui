//! Qualify an unchanged official run using product-owned executable assertions.
//!
//! The upstream result remains REVIEW when upstream requests visual evidence.
//! This receipt records Marty's release decision, not an upstream PASS or an
//! OpenID Foundation certification. Unknown review obligations fail closed.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    official::{digest, LaneReceipt},
    official_review::{is_digest, prepare_official_review, OfficialReviewPlan},
};

pub const AUTOMATED_POLICY: &str = "marty.official-verifier-outcome/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiOutcome {
    pub status: String,
    pub result: String,
    pub decision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutomatedAssessment {
    pub policy: String,
    /// The pinned harness verifies every raw REVIEW log entry has this exact
    /// obligation and rejects any warning, failure or additional obligation.
    pub upstream_condition: String,
    pub flow_instance_sha256: String,
    pub api_outcome: ApiOutcome,
    pub browser_result_match: bool,
    pub ui_instance_match: bool,
    pub ui_decision: String,
    pub ui_verified_visible: bool,
    pub ui_error_absent: bool,
}

#[derive(Debug, Serialize)]
pub struct AutomatedQualification {
    pub schema: &'static str,
    pub policy: &'static str,
    pub evidence_run_attempt: u64,
    pub request_sha256: String,
    pub automated_cases: usize,
    pub original_official_results_unchanged: bool,
}

#[derive(Debug, Serialize)]
pub struct AutomatedOfficialReceipt {
    pub schema: &'static str,
    pub source_sha: String,
    pub harness_sha: String,
    pub manifest_sha256: String,
    pub run_id: u64,
    pub qualification_context: &'static str,
    pub lanes: Vec<LaneReceipt>,
    pub automated_qualification: AutomatedQualification,
}

fn supported_module(lane: &str, name: &str) -> bool {
    if !matches!(
        lane,
        "oid4vp-final" | "oid4vp-url-query" | "oid4vp-mdoc" | "haip"
    ) {
        return false;
    }
    match name {
        "oid4vp-1final-verifier-happy-flow" => true,
        "oid4vp-1final-verifier-minimal-cnf-jwk" => lane != "oid4vp-mdoc",
        "oid4vp-1final-verifier-request-uri-method-post"
        | "oid4vp-1final-verifier-request-uri-fetched-twice" => lane != "oid4vp-url-query",
        _ => false,
    }
}

fn validate_automated_cases(plan: &OfficialReviewPlan) -> Result<(), &'static str> {
    let mut flows = BTreeSet::new();
    let mut modules = BTreeSet::new();
    for case in &plan.pending {
        let assessment = case
            .module
            .automated_assessment
            .as_ref()
            .ok_or("pending official case lacks automated outcome evidence")?;
        if !supported_module(&case.lane, &case.module.test_name)
            || !modules.insert((&case.lane, &case.module.test_name))
            || assessment.policy != AUTOMATED_POLICY
            || assessment.upstream_condition != "ExpectVerifierSuccessfulVerificationPage"
            || !is_digest(&assessment.flow_instance_sha256)
            || !flows.insert((&case.lane, &assessment.flow_instance_sha256))
            || assessment.api_outcome.status != "completed"
            || assessment.api_outcome.result != "passed"
            || assessment.api_outcome.decision != "allow"
            || !assessment.browser_result_match
            || !assessment.ui_instance_match
            || assessment.ui_decision != "allow"
            || !assessment.ui_verified_visible
            || !assessment.ui_error_absent
        {
            return Err("official case has an unsupported obligation or failed automated outcome");
        }
    }
    Ok(())
}

pub fn validate_automated_official_suite(
    manifest: &[u8],
    summaries: &[Vec<u8>],
    source: &str,
    harness: &str,
    run_id: u64,
    run_attempt: u64,
) -> Result<AutomatedOfficialReceipt, &'static str> {
    if run_attempt != 1 {
        return Err("automated qualification requires the original official evidence attempt");
    }
    // Reuse the full raw-result assessment. An automated outcome cannot excuse
    // a failed process, a failed module, missing coverage or foreign evidence.
    let plan = prepare_official_review(manifest, summaries, source, harness, run_id, run_attempt)?;
    validate_automated_cases(&plan)?;
    let qualification = AutomatedQualification {
        schema: "marty.automated-official-qualification/v1",
        policy: AUTOMATED_POLICY,
        evidence_run_attempt: run_attempt,
        request_sha256: digest(&plan.bytes()?),
        automated_cases: plan.pending.len(),
        original_official_results_unchanged: true,
    };
    Ok(AutomatedOfficialReceipt {
        schema: "marty.official-release-gate/v2",
        source_sha: plan.source_sha,
        harness_sha: plan.harness_sha,
        manifest_sha256: plan.manifest_sha256,
        run_id,
        qualification_context: "PRE_PUBLICATION_CANDIDATE",
        lanes: plan.lanes,
        automated_qualification: qualification,
    })
}
