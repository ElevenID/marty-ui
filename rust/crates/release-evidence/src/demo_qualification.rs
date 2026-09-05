//! A completed private qualification is a prerequisite, not proof of recordings.
//! Callers fetch run metadata with authenticated repository-scoped GitHub APIs
//! and download the named artifact from that exact run. Never publish either raw
//! input: only this module's allowlisted output is suitable for public evidence.

use serde::{Deserialize, Serialize};

use crate::{is_source, is_version, successful_run};

pub const MAX_REPORT_BYTES: usize = 64 * 1024;
const REPOSITORY: &str = "ElevenID/marty-demo-recorder";

pub struct ExpectedQualification<'a> {
    pub run_id: u64,
    pub recorder_sha: &'a str,
    pub release_version: &'a str,
    pub ui_sha: &'a str,
    pub source_id: &'a str,
    pub deployment_sha256: &'a str,
    pub stack_sha256: &'a str,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Qualification {
    qualified: bool,
    release_version: String,
    mip_version: String,
    source_id: String,
    marty_ui_revision: String,
    deployment_manifest_sha256: String,
    deployed_demo_manifest_sha256: String,
    official_stack_manifest_sha256: String,
    scenario_count: u64,
    fresh_recording_required: bool,
}

/// Only bound, allowlisted fields; arbitrary private input fields are discarded.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedQualification {
    recorder_run_id: u64,
    recorder_revision: String,
    #[serde(flatten)]
    qualification: Qualification,
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// This requires an official deployment receipt, not a source-template fallback.
/// The stack hash must be independently computed from the verified signed release
/// manifest, and the deployment hash must come from the original deployer receipt.
pub fn validate_demo_qualification(
    run_bytes: &[u8],
    report_bytes: &[u8],
    expected: &ExpectedQualification<'_>,
) -> Result<VerifiedQualification, &'static str> {
    if expected.run_id == 0
        || !is_source(expected.recorder_sha)
        || !is_source(expected.ui_sha)
        || !is_source(expected.source_id)
        || !is_version(expected.release_version)
        || !is_sha256(expected.deployment_sha256)
        || !is_sha256(expected.stack_sha256)
    {
        return Err("invalid expected demo qualification identity");
    }
    let run = successful_run(
        run_bytes,
        expected.run_id,
        REPOSITORY,
        "Demo release intake and qualification",
        ".github/workflows/release-qualification.yml",
    )?;
    if !matches!(
        run.event.as_str(),
        "workflow_dispatch" | "repository_dispatch"
    ) || run.head_branch != "main"
        || run.head_sha != expected.recorder_sha
    {
        return Err("demo qualification trigger, ref or reviewed source mismatch");
    }
    if report_bytes.len() > MAX_REPORT_BYTES {
        return Err("demo qualification report exceeds size limit");
    }
    let report: Qualification =
        serde_json::from_slice(report_bytes).map_err(|_| "invalid demo qualification report")?;
    if !report.qualified
        || report.release_version != expected.release_version
        || report.mip_version != "0.5.0"
        || report.source_id != expected.source_id
        || report.marty_ui_revision != expected.ui_sha
        || report.deployment_manifest_sha256 != expected.deployment_sha256
        || report.official_stack_manifest_sha256 != expected.stack_sha256
        || !is_sha256(&report.deployed_demo_manifest_sha256)
        || report.scenario_count == 0
        || !report.fresh_recording_required
    {
        return Err("demo qualification release or evidence binding mismatch");
    }
    // Exact reviewed recorder code enforces the complete portfolio contract.
    // A nonzero scenario count here is not a substitute for that semantic gate.
    Ok(VerifiedQualification {
        recorder_run_id: run.id,
        recorder_revision: run.head_sha,
        qualification: report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const SOURCE: &str = "1111111111111111111111111111111111111111";
    const UI: &str = "2222222222222222222222222222222222222222";
    const RECORDER: &str = "3333333333333333333333333333333333333333";
    const DEPLOYMENT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const STACK: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn expected() -> ExpectedQualification<'static> {
        ExpectedQualification {
            run_id: 123,
            recorder_sha: RECORDER,
            release_version: "1.1.217",
            ui_sha: UI,
            source_id: SOURCE,
            deployment_sha256: DEPLOYMENT,
            stack_sha256: STACK,
        }
    }

    fn run() -> Value {
        json!({"id":123, "name":"Demo release intake and qualification",
            "path":".github/workflows/release-qualification.yml", "event":"workflow_dispatch",
            "head_branch":"main", "head_sha":RECORDER, "status":"completed", "conclusion":"success",
            "repository":{"full_name":REPOSITORY}, "head_repository":{"full_name":REPOSITORY}})
    }

    fn report() -> Value {
        json!({"qualified":true,"releaseVersion":"1.1.217","mipVersion":"0.5.0",
            "sourceId":SOURCE,"martyUiRevision":UI,"deploymentManifestSha256":DEPLOYMENT,
            "officialStackManifestSha256":STACK,"deployedDemoManifestSha256":"c".repeat(64),
            "scenarioCount":13,"freshRecordingRequired":true})
    }

    fn check(run: &Value, report: &Value) -> Result<VerifiedQualification, &'static str> {
        validate_demo_qualification(
            &serde_json::to_vec(run).unwrap(),
            &serde_json::to_vec(report).unwrap(),
            &expected(),
        )
    }

    #[test]
    fn dispatches_preserve_distinct_ui_source_and_only_publish_allowlisted_fields() {
        for event in ["workflow_dispatch", "repository_dispatch"] {
            let mut run = run();
            run["event"] = json!(event);
            run["privateMetadata"] = json!("private-value");
            let mut report = report();
            report["privateMetadata"] = json!("private-value");
            report["stackVersion"] = json!("untrusted-private-value");
            let output = serde_json::to_value(check(&run, &report).unwrap()).unwrap();
            assert_eq!(output["martyUiRevision"], UI);
            assert_eq!(output["sourceId"], SOURCE);
            assert_eq!(output["recorderRevision"], RECORDER);
            assert_eq!(output["recorderRunId"], 123);
            assert_eq!(output["freshRecordingRequired"], true);
            assert!(!output.to_string().contains("private-value"));
        }
    }

    #[test]
    fn changed_or_missing_run_identity_is_rejected() {
        for (field, value) in [
            ("id", json!(124)),
            ("id", json!("123")),
            ("name", json!("Other workflow")),
            ("path", json!(".github/workflows/other.yml")),
            ("event", json!("pull_request")),
            ("event", json!("push")),
            ("head_branch", json!("feature")),
            ("head_sha", json!(UI)),
            ("status", json!("in_progress")),
            ("conclusion", json!("failure")),
            ("conclusion", json!("cancelled")),
            ("conclusion", Value::Null),
            (
                "repository",
                json!({"full_name":"Other/marty-demo-recorder"}),
            ),
            (
                "head_repository",
                json!({"full_name":"Other/marty-demo-recorder"}),
            ),
        ] {
            let mut changed = run();
            changed[field] = value;
            assert!(check(&changed, &report()).is_err(), "changed {field}");
        }
        for field in run().as_object().unwrap().keys() {
            let mut changed = run();
            changed.as_object_mut().unwrap().remove(field);
            assert!(check(&changed, &report()).is_err(), "missing {field}");
        }
    }

    #[test]
    fn changed_missing_null_or_mistyped_report_bindings_are_rejected() {
        for (field, value) in [
            ("qualified", json!(false)),
            ("qualified", json!("true")),
            ("releaseVersion", json!("1.1.216")),
            ("mipVersion", json!("0.4.0")),
            ("sourceId", json!(UI)),
            ("martyUiRevision", json!(SOURCE)),
            ("deploymentManifestSha256", json!(STACK)),
            ("officialStackManifestSha256", json!(DEPLOYMENT)),
            ("deployedDemoManifestSha256", json!("bad")),
            ("deployedDemoManifestSha256", json!("C".repeat(64))),
            ("scenarioCount", json!(0)),
            ("scenarioCount", json!(-1)),
            ("scenarioCount", json!(1.5)),
            ("freshRecordingRequired", json!(false)),
        ] {
            let mut changed = report();
            changed[field] = value;
            assert!(check(&run(), &changed).is_err(), "changed {field}");
        }
        for field in report().as_object().unwrap().keys() {
            let mut changed = report();
            changed.as_object_mut().unwrap().remove(field);
            assert!(check(&run(), &changed).is_err(), "missing {field}");
            changed[field] = Value::Null;
            assert!(check(&run(), &changed).is_err(), "null {field}");
        }
    }

    #[test]
    fn malformed_oversized_duplicate_and_invalid_expected_inputs_fail_closed() {
        let run = serde_json::to_vec(&run()).unwrap();
        let report = serde_json::to_vec(&report()).unwrap();
        for input in [
            b"private-value".to_vec(),
            b"[]".to_vec(),
            vec![b' '; MAX_REPORT_BYTES + 1],
        ] {
            assert!(validate_demo_qualification(&run, &input, &expected()).is_err());
        }
        assert!(validate_demo_qualification(
            &vec![b' '; crate::MAX_RUN_BYTES + 1],
            &report,
            &expected()
        )
        .is_err());
        let duplicate = format!(
            "{{\"qualified\":true,{}",
            &String::from_utf8(report.clone()).unwrap()[1..]
        );
        assert!(validate_demo_qualification(&run, duplicate.as_bytes(), &expected()).is_err());
        for field in 0..7 {
            let mut expected = expected();
            match field {
                0 => expected.run_id = 0,
                1 => expected.recorder_sha = "bad",
                2 => expected.release_version = "v1.1.217",
                3 => expected.ui_sha = "bad",
                4 => expected.source_id = "bad",
                5 => expected.deployment_sha256 = "bad",
                _ => expected.stack_sha256 = "bad",
            }
            assert!(validate_demo_qualification(&run, &report, &expected).is_err());
        }
    }
}
