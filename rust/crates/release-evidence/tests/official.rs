use marty_release_evidence::official::{validate_official_suite, LANES};
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
        }}], "junit":[{"tests":2,"failures":0,"errors":0,"skipped":1}]
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
