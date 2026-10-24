use marty_release_evidence::official::{validate_official_suite, LANES};
use marty_release_evidence::official_review::{
    prepare_official_review, validate_official_review, validate_official_suite_with_review,
    OfficialReviewPlan,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const MANIFEST: &[u8] = b"synthetic manifest for gate unit controls only";

fn summary(lane: &str) -> Value {
    let mut value = json!({
        "schema": "elevenid.sanitized-official-interop/v1", "lane": lane,
        "harness_commit": "b".repeat(40), "result": {"passed":true, "exit_code":0},
        "stack": {"schema":"elevenid.official-stack-material/v1", "marty_commit":"a".repeat(40),
            "manifest_sha256": format!("sha256:{:x}", Sha256::digest(MANIFEST)),
            "qualification_context":"PRE_PUBLICATION_CANDIDATE", "published_release":false},
        "official_evidence":[{"evidence":{
            "schema":"elevenid.official-interop-evidence/v1", "result":{"exit_code":0,"passed":true,"skipped":0},
            "marty":{"commit":"a".repeat(40)}, "execution_mode":"active",
            "exclusions":{"expected_failures":[]}
        }}], "junit":[{"tests":2,"failures":0,"errors":0,"skipped":0}]
    });
    if !matches!(lane, "w3c-v2" | "eudi") {
        let evidence = &mut value["official_evidence"][0]["evidence"];
        evidence["exclusions"]["expected_skips"] = json!([{"test-name":"optional"}]);
        evidence["module_results"] = json!({
            "schema":"elevenid.official-oidf-module-results/v1", "source_policy":"unmodified",
            "passed":true, "counts":{"PASSED":1,"SKIPPED":1},
            "pending_review":[],"unexpected_skips":[],
            "modules":[
                {"test_name":"happy","status":"FINISHED","result":"PASSED"},
                {"test_name":"optional","status":"FINISHED","result":"SKIPPED"}
            ],
            "plan_coverage":{"complete":true,"expected_modules":["happy","optional"],
                "missing_modules":[],"exported_module_count":2}
        });
    }
    value
}

fn validate(values: &[Value]) -> Result<(), &'static str> {
    let bytes = values
        .iter()
        .map(|value| serde_json::to_vec(value).unwrap())
        .collect::<Vec<_>>();
    validate_official_suite(MANIFEST, &bytes, &"a".repeat(40), &"b".repeat(40), 17).map(|_| ())
}

#[test]
fn requires_complete_distinct_current_candidate_lanes() {
    let values = LANES.map(summary);
    assert!(validate(&values).is_ok());
    assert!(validate(&values[..6]).is_err());
    let mut duplicate = values.clone();
    duplicate[6] = duplicate[0].clone();
    assert!(validate(&duplicate).is_err());
}

#[test]
fn rejects_stale_failed_skipped_empty_and_synthetic_substitutions() {
    for (pointer, replacement) in [
        ("/harness_commit", json!("c".repeat(40))),
        ("/stack/marty_commit", json!("c".repeat(40))),
        (
            "/stack/manifest_sha256",
            json!("sha256:".to_owned() + &"c".repeat(64)),
        ),
        ("/stack/published_release", json!(true)),
        ("/result/passed", json!(false)),
        ("/result/exit_code", json!(1)),
        ("/official_evidence", json!([])),
        ("/official_evidence/0/evidence/result/skipped", json!(1)),
        ("/official_evidence/0/evidence/result/passed", json!(false)),
        (
            "/official_evidence/0/evidence/marty/commit",
            json!("c".repeat(40)),
        ),
        (
            "/official_evidence/0/evidence/execution_mode",
            json!("pre-activation"),
        ),
        (
            "/official_evidence/0/evidence/exclusions/expected_failures",
            json!(["known failure"]),
        ),
        ("/junit/0/tests", json!(0)),
        ("/junit/0/skipped", json!(2)),
        ("/junit/0/skipped", json!(1)),
        ("/junit/0/failures", json!(1)),
        ("/junit/0/errors", json!(1)),
    ] {
        let mut values = LANES.map(summary);
        *values[0].pointer_mut(pointer).unwrap() = replacement;
        assert!(validate(&values).is_err(), "must reject {pointer}");
    }
}

#[test]
fn eudi_integer_zero_skips_and_absent_oidf_skip_count_are_valid() {
    let mut values = LANES.map(summary);
    values[0]["official_evidence"][0]["evidence"]["result"]
        .as_object_mut()
        .unwrap()
        .remove("skipped");
    assert!(validate(&values).is_ok());
}

#[test]
fn explicit_local_overlays_cannot_qualify_as_the_release_image_even_when_tests_pass() {
    for release_qualified in [false, true] {
        let mut values = LANES.map(summary);
        values[0]["local_runtime_binding"] = json!({
            "scope":"LOCAL_DEVELOPER_FEEDBACK", "nativeReadbackMatched":true,
            "releaseQualified":release_qualified
        });
        assert!(validate(&values).is_err());
    }
}

#[test]
fn exit_zero_cannot_promote_review_missing_or_incomplete_oidf_modules() {
    for (pointer, replacement) in [
        ("", Value::Null),
        ("/source_policy", json!("modified")),
        ("/passed", json!(false)),
        ("/pending_review", json!(["happy"])),
        ("/unexpected_skips", json!(["optional"])),
        ("/modules", json!([])),
        ("/modules/0/result", json!("REVIEW")),
        ("/modules/0/status", json!("WAITING")),
        ("/modules/0/test_name", json!("foreign")),
        ("/modules/0/test_name", json!("optional")),
        ("/counts/PASSED", json!(2)),
        ("/plan_coverage/complete", json!(false)),
        ("/plan_coverage/missing_modules", json!(["negative"])),
        (
            "/plan_coverage/expected_modules",
            json!(["happy", "optional", "negative"]),
        ),
        ("/plan_coverage/expected_modules", json!(["happy", "happy"])),
        ("/plan_coverage/exported_module_count", json!(3)),
    ] {
        for index in 0..5 {
            let mut values = LANES.map(summary);
            let modules = &mut values[index]["official_evidence"][0]["evidence"]["module_results"];
            *modules.pointer_mut(pointer).unwrap() = replacement.clone();
            assert!(
                validate(&values).is_err(),
                "must reject {pointer} in {}",
                LANES[index]
            );
        }
    }
}

#[test]
fn only_explicitly_disposed_optional_skips_can_pass_and_never_an_all_skipped_plan() {
    let mut values = LANES.map(summary);
    values[0]["official_evidence"][0]["evidence"]["exclusions"]["expected_skips"] = json!([]);
    assert!(validate(&values).is_err());

    let mut values = LANES.map(summary);
    let evidence = &mut values[0]["official_evidence"][0]["evidence"];
    evidence["exclusions"]["expected_skips"] =
        json!([{"test-name":"optional"},{"test-name":"happy"}]);
    evidence["module_results"]["modules"][0]["result"] = json!("SKIPPED");
    evidence["module_results"]["counts"] = json!({"SKIPPED":2});
    assert!(validate(&values).is_err());
}

fn review_values() -> [Value; 7] {
    let mut values = LANES.map(summary);
    for value in &mut values[1..5] {
        value["result"] = json!({"exit_code":1,"passed":false});
        value["browser_evidence"] = json!({"schema":"elevenid.released-browser-smoke/v1",
            "status":"passed","private_selectors_observed":false});
        let wrapper = &mut value["official_evidence"][0];
        wrapper["source"] = json!("profile/evidence.json");
        let evidence = &mut wrapper["evidence"];
        evidence["result"] = json!({"exit_code":1,"process_exit_code":0,"passed":false});
        evidence["artifacts"] = json!([{"path":"official-real-ui-images.json","sha256":"sha256:".to_owned()+&"1".repeat(64)}]);
        let modules = &mut evidence["module_results"];
        modules["modules"][0]["result"] = json!("REVIEW");
        modules["modules"]
            .as_array_mut()
            .unwrap()
            .push(json!({"test_name":"negative","status":"FINISHED","result":"PASSED"}));
        modules["passed"] = json!(false);
        modules["pending_review"] = json!(["happy"]);
        modules["counts"] = json!({"PASSED":1,"REVIEW":1,"SKIPPED":1});
        modules["plan_coverage"] = json!({"complete":true,"expected_modules":["happy","optional","negative"],
            "missing_modules":[],"exported_module_count":3,"binding_sha256":"2".repeat(64),
            "module_bindings":[{"test_name":"happy","test_id":"positive1"},
                {"test_name":"optional","test_id":"optional1"},{"test_name":"negative","test_id":"negative1"}]});
        value["review_requests"] = json!([{"schema":"elevenid.official-review-request/v1",
            "source":"profile/evidence.json","status":"PENDING",
            "original_evidence_sha256":"sha256:".to_owned()+&"3".repeat(64),
            "capture_receipt_sha256":"sha256:".to_owned()+&"1".repeat(64),
            "official_export_sha256":"sha256:".to_owned()+&"4".repeat(64),
            "plan_binding_sha256":"sha256:".to_owned()+&"2".repeat(64),
            "modules":[{"test_name":"happy","test_id":"positive1","plan_id":"plan1",
                "official_result":"REVIEW","screenshot_sha256":"sha256:".to_owned()+&"5".repeat(64)}]}]);
    }
    values
}

fn review_bytes(values: &[Value]) -> Vec<Vec<u8>> {
    values
        .iter()
        .map(|value| serde_json::to_vec(value).unwrap())
        .collect()
}

fn review_plan(values: &[Value]) -> Result<OfficialReviewPlan, &'static str> {
    prepare_official_review(
        MANIFEST,
        &review_bytes(values),
        &"a".repeat(40),
        &"b".repeat(40),
        17,
        1,
    )
}

fn disposition(plan: &OfficialReviewPlan) -> Value {
    json!({"schema":"marty.official-review-disposition/v1","run_id":17,"run_attempt":1,
        "request_sha256":format!("sha256:{:x}",Sha256::digest(plan.bytes().unwrap())),
        "verdict":"accepted","reviewer":{"kind":"delegated_codex","github_login":"maintainer"},
        "cases":plan.pending.iter().map(|pending| json!({"lane":pending.lane,"module":pending.module,"verdict":"accepted"})).collect::<Vec<_>>()})
}

#[test]
fn pending_review_is_never_itself_a_passing_gate_and_preserves_every_input() {
    let values = review_values();
    let before = review_bytes(&values);
    assert!(validate(&values).is_err());
    let plan = review_plan(&values).unwrap();
    assert!(!plan.release_qualified);
    assert_eq!(plan.pending.len(), 4);
    assert_eq!(plan.lanes.len(), 7);
    assert_eq!(before, review_bytes(&values));
    let receipt = serde_json::to_vec(&disposition(&plan)).unwrap();
    let accepted = validate_official_suite_with_review(
        MANIFEST,
        &before,
        &"a".repeat(40),
        &"b".repeat(40),
        17,
        1,
        &receipt,
        &"c".repeat(40),
    )
    .unwrap();
    let review = accepted.review_disposition.unwrap();
    assert_eq!(review.reviewed_cases, 4);
    assert!(review.original_official_results_unchanged);
    assert_eq!(review.protected_main_commit, "c".repeat(40));
    assert_eq!(before, review_bytes(&values));
}

#[test]
fn review_cannot_excuse_failed_partial_unbound_or_forged_module_evidence() {
    for (pointer, replacement) in [
        ("/result/exit_code", json!(0)),
        ("/result/passed", json!(true)),
        (
            "/official_evidence/0/evidence/result/process_exit_code",
            json!(1),
        ),
        (
            "/official_evidence/0/evidence/module_results/modules/2/result",
            json!("FAILED"),
        ),
        (
            "/official_evidence/0/evidence/module_results/pending_review",
            json!([]),
        ),
        (
            "/official_evidence/0/evidence/module_results/pending_review",
            json!(["happy", "happy"]),
        ),
        (
            "/official_evidence/0/evidence/module_results/counts/REVIEW",
            json!(2),
        ),
        (
            "/official_evidence/0/evidence/module_results/plan_coverage/complete",
            json!(false),
        ),
        ("/official_evidence/0/evidence/artifacts", json!([])),
        ("/review_requests", json!([])),
        ("/review_requests/0/status", json!("APPROVED")),
        ("/review_requests/0/source", json!("another/evidence.json")),
        (
            "/review_requests/0/capture_receipt_sha256",
            json!("sha256:".to_owned() + &"0".repeat(64)),
        ),
        (
            "/review_requests/0/plan_binding_sha256",
            json!("sha256:".to_owned() + &"0".repeat(64)),
        ),
        (
            "/review_requests/0/modules/0/test_id",
            json!("anotherattempt"),
        ),
        (
            "/review_requests/0/modules/0/screenshot_sha256",
            json!("malformed"),
        ),
        (
            "/review_requests/0/modules/0/official_result",
            json!("PASSED"),
        ),
        ("/browser_evidence/status", json!("failed")),
        ("/browser_evidence/private_selectors_observed", json!(true)),
        ("/junit/0/skipped", json!(1)),
    ] {
        let mut values = review_values();
        *values[1].pointer_mut(pointer).unwrap() = replacement;
        assert!(review_plan(&values).is_err(), "must reject {pointer}");
    }
    let mut values = review_values();
    values[1]["local_runtime_binding"] = json!({"releaseQualified":true});
    assert!(review_plan(&values).is_err());
    let mut values = review_values();
    let extra = values[1]["review_requests"][0].clone();
    values[1]["review_requests"]
        .as_array_mut()
        .unwrap()
        .push(extra);
    assert!(review_plan(&values).is_err());
}

#[test]
fn main_review_must_cover_every_exact_case_and_request_once() {
    let plan = review_plan(&review_values()).unwrap();
    for (pointer, replacement) in [
        ("/run_id", json!(18)),
        ("/run_attempt", json!(2)),
        (
            "/request_sha256",
            json!("sha256:".to_owned() + &"0".repeat(64)),
        ),
        ("/verdict", json!("pending")),
        ("/reviewer/kind", json!("automatic")),
        ("/reviewer/github_login", json!("not/a/login")),
        ("/cases", json!([])),
        ("/cases/0/verdict", json!("rejected")),
        ("/cases/0/module/test_id", json!("other")),
        (
            "/cases/0/module/screenshot_sha256",
            json!("sha256:".to_owned() + &"0".repeat(64)),
        ),
    ] {
        let mut record = disposition(&plan);
        *record.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            validate_official_review(
                &plan,
                &serde_json::to_vec(&record).unwrap(),
                &"c".repeat(40)
            )
            .is_err(),
            "must reject {pointer}"
        );
    }
    let mut record = disposition(&plan);
    record["cases"][1] = record["cases"][0].clone();
    assert!(validate_official_review(
        &plan,
        &serde_json::to_vec(&record).unwrap(),
        &"c".repeat(40)
    )
    .is_err());
    let duplicate = serde_json::to_string(&disposition(&plan))
        .unwrap()
        .replacen("{", "{\"verdict\":\"rejected\",", 1);
    assert!(validate_official_review(&plan, duplicate.as_bytes(), &"c".repeat(40)).is_err());
}

#[test]
fn approval_of_the_same_images_cannot_cover_a_changed_other_lane_or_attempt() {
    let values = review_values();
    let plan = review_plan(&values).unwrap();
    let record = serde_json::to_vec(&disposition(&plan)).unwrap();
    // Even an otherwise valid metadata change in the passing issuer invalidates
    // the old aggregate approval. No partial reuse across candidate snapshots.
    let mut changed = values.clone();
    changed[0]["redactions"] = json!(1);
    let new = review_plan(&changed).unwrap();
    assert!(validate_official_review(&new, &record, &"c".repeat(40)).is_err());
    let new = prepare_official_review(
        MANIFEST,
        &review_bytes(&values),
        &"a".repeat(40),
        &"b".repeat(40),
        17,
        2,
    )
    .unwrap();
    assert!(validate_official_review(&new, &record, &"c".repeat(40)).is_err());
}

#[test]
fn cli_preserves_the_exact_approval_subject_and_cannot_default_to_approval() {
    use std::{fs, process::Command};

    let root = tempfile::tempdir().unwrap();
    let manifest = root.path().join("manifest.json");
    fs::write(&manifest, MANIFEST).unwrap();
    let values = review_values();
    let summaries = root.path().join("summaries");
    for (lane, value) in LANES.iter().zip(&values) {
        let directory = summaries.join(format!("official-{lane}-17-1"));
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("summary.json"),
            serde_json::to_vec(value).unwrap(),
        )
        .unwrap();
    }
    let arguments = [
        manifest.to_str().unwrap(),
        &"a".repeat(40),
        &"b".repeat(40),
        "17",
        "1",
        summaries.to_str().unwrap(),
    ];
    let binary = env!("CARGO_BIN_EXE_validate-official-suite");
    let pending = Command::new(binary)
        .arg("--prepare-review")
        .args(arguments)
        .output()
        .unwrap();
    assert!(pending.status.success());
    let plan = review_plan(&values).unwrap();
    assert_eq!(pending.stdout, plan.bytes().unwrap());
    assert!(!pending.stdout.ends_with(b"\n"));
    let unapproved = Command::new(binary).args(arguments).output().unwrap();
    assert!(!unapproved.status.success());
    assert!(unapproved.stdout.is_empty());
    let record = root.path().join("unit-review-only.json");
    fs::write(&record, serde_json::to_vec(&disposition(&plan)).unwrap()).unwrap();
    let approved = Command::new(binary)
        .args([
            "--with-main-review",
            record.to_str().unwrap(),
            &"c".repeat(40),
        ])
        .args(arguments)
        .output()
        .unwrap();
    assert!(approved.status.success());
    let receipt: Value = serde_json::from_slice(&approved.stdout).unwrap();
    assert_eq!(receipt["review_disposition"]["reviewed_cases"], 4);
    for (lane, original) in LANES.iter().zip(&values) {
        let file = summaries.join(format!("official-{lane}-17-1/summary.json"));
        assert_eq!(
            fs::read(file).unwrap(),
            serde_json::to_vec(original).unwrap()
        );
    }
}
