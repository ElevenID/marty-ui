//! A completed private qualification is a prerequisite, not proof of recordings.
//! Callers fetch run metadata with authenticated repository-scoped GitHub APIs
//! and download the named artifact from that exact run. Never publish either raw
//! input: only this module's allowlisted output is suitable for public evidence.

use std::{collections::HashSet, fmt};

use serde::{
    de::{DeserializeOwned, DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor},
    Deserialize, Serialize,
};
use sha2::{Digest, Sha256};

use crate::{is_source, is_version, successful_run};

pub const MAX_REPORT_BYTES: usize = 64 * 1024;
pub const MAX_REVIEW_BYTES: usize = 256 * 1024;
const MAX_REVIEW_BODY_BYTES: usize = 16 * 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const REPOSITORY: &str = "ElevenID/marty-demo-recorder";
const QUALIFICATION_MODE: &str = "official-private";
const REVIEW_BODY_SCHEMA: &str = "marty.recorder-maintainer-review/v1";

pub struct ExpectedQualification<'a> {
    pub run_id: u64,
    pub recorder_sha: &'a str,
    pub review_record_id: u64,
    pub release_version: &'a str,
    pub beta_origin: &'a str,
    pub ui_sha: &'a str,
    pub source_id: &'a str,
    pub deployment_sha256: &'a str,
    pub stack_sha256: &'a str,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Qualification {
    qualified: bool,
    lifecycle_qualified: bool,
    qualification_mode: String,
    beta_origin: String,
    release_version: String,
    mip_version: String,
    source_id: String,
    marty_ui_revision: String,
    deployment_manifest_sha256: String,
    deployed_demo_manifest_sha256: String,
    official_stack_manifest_sha256: String,
    scenario_count: u64,
    fresh_recording_required: bool,
    maintainer_review_record_id: u64,
    maintainer_review_record_sha256: String,
    maintainer_review_body_sha256: String,
    maintainer_review_repository: String,
    maintainer_review_pull_request: u64,
    maintainer_review_pull_request_head_sha: String,
    maintainer_review_recorder_head_sha: String,
    maintainer_review_recorder_tree_sha: String,
    maintainer_review_author: String,
    maintainer_review_author_association: String,
    maintainer_review_permission: String,
    maintainer_review_created_at: String,
    maintainer_review_updated_at: String,
}

#[derive(Deserialize)]
struct ReviewComment {
    id: u64,
    issue_url: String,
    body: String,
    user: ReviewUser,
    author_association: String,
    created_at: String,
    updated_at: String,
}

#[derive(Deserialize)]
struct ReviewUser {
    login: String,
}

#[derive(Deserialize)]
struct ReviewPermission {
    permission: String,
    user: ReviewUser,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewBody {
    schema: String,
    repository: String,
    pull_request: u64,
    pull_request_head_sha: String,
    recorder_tree_sha: String,
    verdict: String,
    review: ReviewScope,
    unresolved_findings: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewScope {
    feature_regression: bool,
    security: bool,
    tests: bool,
}

#[derive(Serialize)]
struct CanonicalReviewRecord<'a> {
    id: u64,
    issue_url: &'a str,
    user: CanonicalReviewUser<'a>,
    author_association: &'a str,
    created_at: &'a str,
    updated_at: &'a str,
    body: &'a str,
}

#[derive(Serialize)]
struct CanonicalReviewUser<'a> {
    login: &'a str,
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

fn is_beta_origin(value: &str) -> bool {
    value == "https://beta.elevenidllc.com"
}

fn is_github_login(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 39
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        && !value.contains("--")
}

fn is_reviewed_at(value: &str) -> bool {
    value.len() == 20
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-')
        && value.as_bytes().get(10) == Some(&b'T')
        && value.as_bytes().get(13) == Some(&b':')
        && value.as_bytes().get(16) == Some(&b':')
        && value.ends_with('Z')
        && chrono::DateTime::parse_from_rfc3339(value).is_ok()
}

struct StrictJson;

impl<'de> DeserializeSeed<'de> for StrictJson {
    type Value = serde_json::Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = serde_json::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("valid JSON without duplicate object members")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictJson)? {
            values.push(value);
        }
        Ok(serde_json::Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut names = HashSet::new();
        let mut values = serde_json::Map::new();
        while let Some(name) = map.next_key::<String>()? {
            if !names.insert(name.clone()) {
                return Err(A::Error::custom("duplicate JSON object member"));
            }
            values.insert(name, map.next_value_seed(StrictJson)?);
        }
        Ok(serde_json::Value::Object(values))
    }
}

fn parse_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, &'static str> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictJson
        .deserialize(&mut deserializer)
        .map_err(|_| "invalid or duplicate JSON evidence")?;
    deserializer
        .end()
        .map_err(|_| "invalid or duplicate JSON evidence")?;
    serde_json::from_value(value).map_err(|_| "invalid JSON evidence shape")
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// This requires an official deployment receipt, not a source-template fallback.
/// The stack hash must be independently computed from the verified signed release
/// manifest, and the deployment hash must come from the original deployer receipt.
pub fn validate_demo_qualification(
    run_bytes: &[u8],
    report_bytes: &[u8],
    comment_bytes: &[u8],
    permission_bytes: &[u8],
    expected: &ExpectedQualification<'_>,
) -> Result<VerifiedQualification, &'static str> {
    if expected.run_id == 0
        || expected.review_record_id == 0
        || expected.review_record_id > MAX_SAFE_INTEGER
        || !is_source(expected.recorder_sha)
        || !is_source(expected.ui_sha)
        || !is_source(expected.source_id)
        || !is_version(expected.release_version)
        || !is_beta_origin(expected.beta_origin)
        || !is_sha256(expected.deployment_sha256)
        || !is_sha256(expected.stack_sha256)
    {
        return Err("invalid expected demo qualification identity");
    }
    if run_bytes.len() > crate::MAX_RUN_BYTES {
        return Err("workflow run response exceeds size limit");
    }
    let strict_run: serde_json::Value = parse_strict(run_bytes)?;
    let strict_run_bytes =
        serde_json::to_vec(&strict_run).map_err(|_| "cannot normalize workflow run evidence")?;
    let run = successful_run(
        &strict_run_bytes,
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
    if comment_bytes.len() > MAX_REVIEW_BYTES || permission_bytes.len() > MAX_REVIEW_BYTES {
        return Err("demo qualification review evidence exceeds size limit");
    }
    let report: Qualification = parse_strict(report_bytes)?;
    if !report.qualified
        || !report.lifecycle_qualified
        || report.qualification_mode != QUALIFICATION_MODE
        || report.beta_origin != expected.beta_origin
        || report.release_version != expected.release_version
        || report.mip_version != "0.5.0"
        || report.source_id != expected.source_id
        || report.marty_ui_revision != expected.ui_sha
        || report.deployment_manifest_sha256 != expected.deployment_sha256
        || report.official_stack_manifest_sha256 != expected.stack_sha256
        || !is_sha256(&report.deployed_demo_manifest_sha256)
        || report.scenario_count == 0
        || !report.fresh_recording_required
        || report.maintainer_review_record_id == 0
        || report.maintainer_review_record_id > MAX_SAFE_INTEGER
        || report.maintainer_review_record_id != expected.review_record_id
        || !is_sha256(&report.maintainer_review_record_sha256)
        || !is_sha256(&report.maintainer_review_body_sha256)
        || report.maintainer_review_repository != REPOSITORY
        || report.maintainer_review_pull_request == 0
        || report.maintainer_review_pull_request > MAX_SAFE_INTEGER
        || !is_source(&report.maintainer_review_pull_request_head_sha)
        || report.maintainer_review_recorder_head_sha != expected.recorder_sha
        || !is_source(&report.maintainer_review_recorder_tree_sha)
        || !is_github_login(&report.maintainer_review_author)
        || !matches!(
            report.maintainer_review_author_association.as_str(),
            "OWNER" | "MEMBER" | "COLLABORATOR"
        )
        || !matches!(
            report.maintainer_review_permission.as_str(),
            "admin" | "maintain"
        )
        || !is_reviewed_at(&report.maintainer_review_created_at)
        || report.maintainer_review_updated_at != report.maintainer_review_created_at
    {
        return Err("demo qualification release or evidence binding mismatch");
    }

    let comment: ReviewComment = parse_strict(comment_bytes)?;
    let permission: ReviewPermission = parse_strict(permission_bytes)?;
    if comment.body.len() > MAX_REVIEW_BODY_BYTES {
        return Err("demo qualification review body exceeds size limit");
    }
    let body: ReviewBody = parse_strict(comment.body.as_bytes())?;
    let expected_issue_url = format!(
        "https://api.github.com/repos/{REPOSITORY}/issues/{}",
        report.maintainer_review_pull_request
    );
    if comment.id != expected.review_record_id
        || comment.issue_url != expected_issue_url
        || comment.user.login != report.maintainer_review_author
        || comment.author_association != report.maintainer_review_author_association
        || comment.created_at != report.maintainer_review_created_at
        || comment.updated_at != report.maintainer_review_updated_at
        || permission.user.login != report.maintainer_review_author
        || permission.permission != report.maintainer_review_permission
        || body.schema != REVIEW_BODY_SCHEMA
        || body.repository != REPOSITORY
        || body.pull_request != report.maintainer_review_pull_request
        || body.pull_request_head_sha != report.maintainer_review_pull_request_head_sha
        || body.recorder_tree_sha != report.maintainer_review_recorder_tree_sha
        || body.verdict != "approved"
        || !body.review.feature_regression
        || !body.review.security
        || !body.review.tests
        || !body.unresolved_findings.is_empty()
    {
        return Err("demo qualification maintainer review mismatch");
    }
    let body_sha256 = sha256_hex(comment.body.as_bytes());
    if body_sha256 != report.maintainer_review_body_sha256 {
        return Err("demo qualification maintainer review body hash mismatch");
    }
    let canonical = CanonicalReviewRecord {
        id: comment.id,
        issue_url: &comment.issue_url,
        user: CanonicalReviewUser {
            login: &comment.user.login,
        },
        author_association: &comment.author_association,
        created_at: &comment.created_at,
        updated_at: &comment.updated_at,
        body: &comment.body,
    };
    let canonical_bytes =
        serde_json::to_vec(&canonical).map_err(|_| "cannot canonicalize maintainer review")?;
    if sha256_hex(&canonical_bytes) != report.maintainer_review_record_sha256 {
        return Err("demo qualification maintainer review record hash mismatch");
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
    const PULL_HEAD: &str = "4444444444444444444444444444444444444444";
    const TREE: &str = "5555555555555555555555555555555555555555";
    const DEPLOYMENT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const STACK: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const REVIEW_ID: u64 = 101;
    const PULL_REQUEST: u64 = 42;

    fn expected() -> ExpectedQualification<'static> {
        ExpectedQualification {
            run_id: 123,
            recorder_sha: RECORDER,
            review_record_id: REVIEW_ID,
            release_version: "1.1.217",
            beta_origin: "https://beta.elevenidllc.com",
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
        let comment = comment();
        let body = comment["body"].as_str().unwrap();
        let body_sha256 = sha256_hex(body.as_bytes());
        let canonical = CanonicalReviewRecord {
            id: REVIEW_ID,
            issue_url: "https://api.github.com/repos/ElevenID/marty-demo-recorder/issues/42",
            user: CanonicalReviewUser {
                login: "BurdettAdam",
            },
            author_association: "OWNER",
            created_at: "2026-09-22T12:34:56Z",
            updated_at: "2026-09-22T12:34:56Z",
            body,
        };
        let record_sha256 = sha256_hex(&serde_json::to_vec(&canonical).unwrap());
        json!({"qualified":true,"lifecycleQualified":true,"qualificationMode":"official-private",
            "betaOrigin":"https://beta.elevenidllc.com",
            "releaseVersion":"1.1.217","mipVersion":"0.5.0",
            "sourceId":SOURCE,"martyUiRevision":UI,"deploymentManifestSha256":DEPLOYMENT,
            "officialStackManifestSha256":STACK,"deployedDemoManifestSha256":"c".repeat(64),
            "scenarioCount":13,"freshRecordingRequired":true,
            "maintainerReviewRecordId":REVIEW_ID,
            "maintainerReviewRecordSha256":record_sha256,
            "maintainerReviewBodySha256":body_sha256,
            "maintainerReviewRepository":REPOSITORY,
            "maintainerReviewPullRequest":PULL_REQUEST,
            "maintainerReviewPullRequestHeadSha":PULL_HEAD,
            "maintainerReviewRecorderHeadSha":RECORDER,
            "maintainerReviewRecorderTreeSha":TREE,
            "maintainerReviewAuthor":"BurdettAdam",
            "maintainerReviewAuthorAssociation":"OWNER",
            "maintainerReviewPermission":"admin",
            "maintainerReviewCreatedAt":"2026-09-22T12:34:56Z",
            "maintainerReviewUpdatedAt":"2026-09-22T12:34:56Z"})
    }

    fn review_body() -> Value {
        json!({"schema":REVIEW_BODY_SCHEMA,"repository":REPOSITORY,
            "pull_request":PULL_REQUEST,"pull_request_head_sha":PULL_HEAD,
            "recorder_tree_sha":TREE,"verdict":"approved",
            "review":{"feature_regression":true,"security":true,"tests":true},
            "unresolved_findings":[]})
    }

    fn comment() -> Value {
        json!({"id":REVIEW_ID,
            "issue_url":format!("https://api.github.com/repos/{REPOSITORY}/issues/{PULL_REQUEST}"),
            "body":serde_json::to_string(&review_body()).unwrap(),
            "user":{"login":"BurdettAdam"},"author_association":"OWNER",
            "created_at":"2026-09-22T12:34:56Z","updated_at":"2026-09-22T12:34:56Z",
            "privateMetadata":"private-value"})
    }

    fn permission() -> Value {
        json!({"permission":"admin","user":{"login":"BurdettAdam"},
            "privateMetadata":"private-value"})
    }

    fn check(run: &Value, report: &Value) -> Result<VerifiedQualification, &'static str> {
        validate_demo_qualification(
            &serde_json::to_vec(run).unwrap(),
            &serde_json::to_vec(report).unwrap(),
            &serde_json::to_vec(&comment()).unwrap(),
            &serde_json::to_vec(&permission()).unwrap(),
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
            assert_eq!(output["lifecycleQualified"], true);
            assert_eq!(output["qualificationMode"], QUALIFICATION_MODE);
            assert_eq!(output["betaOrigin"], expected().beta_origin);
            assert_eq!(output["maintainerReviewRecorderHeadSha"], RECORDER);
            assert_eq!(output["maintainerReviewRecordId"], REVIEW_ID);
            assert_eq!(output["maintainerReviewAuthor"], "BurdettAdam");
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
            ("lifecycleQualified", json!(false)),
            ("lifecycleQualified", json!("true")),
            ("qualificationMode", json!("local-private")),
            ("qualificationMode", json!(true)),
            ("betaOrigin", json!("https://beta.elevenidllc.com/")),
            ("betaOrigin", json!(true)),
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
            ("maintainerReviewRecordId", json!(102)),
            ("maintainerReviewRecordId", json!(MAX_SAFE_INTEGER + 1)),
            ("maintainerReviewRecordId", json!("101")),
            ("maintainerReviewRecordSha256", json!("e".repeat(64))),
            ("maintainerReviewRecordSha256", json!("bad")),
            ("maintainerReviewRecordSha256", json!(42)),
            ("maintainerReviewBodySha256", json!("e".repeat(64))),
            ("maintainerReviewBodySha256", json!("bad")),
            ("maintainerReviewBodySha256", json!(42)),
            ("maintainerReviewRepository", json!("Other/repository")),
            ("maintainerReviewRepository", json!(42)),
            ("maintainerReviewPullRequest", json!(43)),
            ("maintainerReviewPullRequest", json!(MAX_SAFE_INTEGER + 1)),
            ("maintainerReviewPullRequest", json!(0)),
            ("maintainerReviewPullRequest", json!("42")),
            ("maintainerReviewPullRequestHeadSha", json!(UI)),
            ("maintainerReviewPullRequestHeadSha", json!("A".repeat(40))),
            ("maintainerReviewPullRequestHeadSha", json!(42)),
            ("maintainerReviewRecorderHeadSha", json!(UI)),
            ("maintainerReviewRecorderHeadSha", json!(42)),
            ("maintainerReviewRecorderTreeSha", json!(UI)),
            ("maintainerReviewRecorderTreeSha", json!("bad")),
            ("maintainerReviewRecorderTreeSha", json!(42)),
            ("maintainerReviewAuthor", json!("OtherMaintainer")),
            ("maintainerReviewAuthor", json!("invalid--login")),
            ("maintainerReviewAuthor", json!(42)),
            ("maintainerReviewAuthorAssociation", json!("CONTRIBUTOR")),
            ("maintainerReviewAuthorAssociation", json!(42)),
            ("maintainerReviewPermission", json!("write")),
            ("maintainerReviewPermission", json!(42)),
            (
                "maintainerReviewCreatedAt",
                json!("2026-09-22T12:34:56+00:00"),
            ),
            ("maintainerReviewCreatedAt", json!("2026-09-22T12:34:55Z")),
            ("maintainerReviewCreatedAt", json!(42)),
            ("maintainerReviewUpdatedAt", json!("2026-09-22T12:35:56Z")),
            ("maintainerReviewUpdatedAt", json!(42)),
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
    fn server_comment_permission_and_structured_review_are_independently_bound() {
        let mut maintain_report = report();
        maintain_report["maintainerReviewPermission"] = json!("maintain");
        let mut maintain_permission = permission();
        maintain_permission["permission"] = json!("maintain");
        assert!(validate_demo_qualification(
            &serde_json::to_vec(&run()).unwrap(),
            &serde_json::to_vec(&maintain_report).unwrap(),
            &serde_json::to_vec(&comment()).unwrap(),
            &serde_json::to_vec(&maintain_permission).unwrap(),
            &expected(),
        )
        .is_ok());
        for (field, value) in [
            ("id", json!(102)),
            (
                "issue_url",
                json!("https://api.github.com/repos/Other/repo/issues/42"),
            ),
            ("user", json!({"login":"OtherMaintainer"})),
            ("author_association", json!("CONTRIBUTOR")),
            ("created_at", json!("2026-09-22T12:35:56Z")),
            ("updated_at", json!("2026-09-22T12:35:56Z")),
        ] {
            let mut changed = comment();
            changed[field] = value;
            assert!(
                validate_demo_qualification(
                    &serde_json::to_vec(&run()).unwrap(),
                    &serde_json::to_vec(&report()).unwrap(),
                    &serde_json::to_vec(&changed).unwrap(),
                    &serde_json::to_vec(&permission()).unwrap(),
                    &expected(),
                )
                .is_err(),
                "changed server comment {field}"
            );
        }
        for (field, value) in [
            ("permission", json!("write")),
            ("user", json!({"login":"OtherMaintainer"})),
        ] {
            let mut changed = permission();
            changed[field] = value;
            assert!(
                validate_demo_qualification(
                    &serde_json::to_vec(&run()).unwrap(),
                    &serde_json::to_vec(&report()).unwrap(),
                    &serde_json::to_vec(&comment()).unwrap(),
                    &serde_json::to_vec(&changed).unwrap(),
                    &expected(),
                )
                .is_err(),
                "changed server permission {field}"
            );
        }
        for (field, value) in [
            ("repository", json!("Other/repository")),
            ("pull_request", json!(43)),
            ("pull_request_head_sha", json!(UI)),
            ("recorder_tree_sha", json!(UI)),
            ("verdict", json!("changes_requested")),
            (
                "review",
                json!({"feature_regression":true,"security":false,"tests":true}),
            ),
            ("unresolved_findings", json!(["finding"])),
        ] {
            let mut changed_body = review_body();
            changed_body[field] = value;
            let mut changed = comment();
            changed["body"] = json!(serde_json::to_string(&changed_body).unwrap());
            assert!(
                validate_demo_qualification(
                    &serde_json::to_vec(&run()).unwrap(),
                    &serde_json::to_vec(&report()).unwrap(),
                    &serde_json::to_vec(&changed).unwrap(),
                    &serde_json::to_vec(&permission()).unwrap(),
                    &expected(),
                )
                .is_err(),
                "changed structured review {field}"
            );
        }
    }

    #[test]
    fn malformed_oversized_duplicate_and_invalid_expected_inputs_fail_closed() {
        let run = serde_json::to_vec(&run()).unwrap();
        let report = serde_json::to_vec(&report()).unwrap();
        let comment = serde_json::to_vec(&comment()).unwrap();
        let permission = serde_json::to_vec(&permission()).unwrap();
        for input in [
            b"private-value".to_vec(),
            b"[]".to_vec(),
            vec![b' '; MAX_REPORT_BYTES + 1],
        ] {
            assert!(
                validate_demo_qualification(&run, &input, &comment, &permission, &expected())
                    .is_err()
            );
        }
        assert!(validate_demo_qualification(
            &vec![b' '; crate::MAX_RUN_BYTES + 1],
            &report,
            &comment,
            &permission,
            &expected()
        )
        .is_err());
        let duplicate = format!(
            "{{\"qualified\":true,{}",
            &String::from_utf8(report.clone()).unwrap()[1..]
        );
        assert!(validate_demo_qualification(
            &run,
            duplicate.as_bytes(),
            &comment,
            &permission,
            &expected()
        )
        .is_err());
        let duplicate_comment = format!(
            "{{\"unknown\":1,\"unknown\":2,{}",
            &String::from_utf8(comment.clone()).unwrap()[1..]
        );
        assert!(validate_demo_qualification(
            &run,
            &report,
            duplicate_comment.as_bytes(),
            &permission,
            &expected()
        )
        .is_err());
        for field in 0..10 {
            let mut expected = expected();
            match field {
                0 => expected.run_id = 0,
                1 => expected.recorder_sha = "bad",
                2 => expected.review_record_id = 0,
                3 => expected.review_record_id = MAX_SAFE_INTEGER + 1,
                4 => expected.release_version = "v1.1.217",
                5 => expected.beta_origin = "https://beta.elevenidllc.com/",
                6 => expected.ui_sha = "bad",
                7 => expected.source_id = "bad",
                8 => expected.deployment_sha256 = "bad",
                _ => expected.stack_sha256 = "bad",
            }
            assert!(
                validate_demo_qualification(&run, &report, &comment, &permission, &expected)
                    .is_err()
            );
        }
    }
}
