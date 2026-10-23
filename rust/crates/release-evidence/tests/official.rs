use marty_release_evidence::official::{validate_official_suite, LANES};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const MANIFEST: &[u8] = b"synthetic manifest for gate unit controls only";

fn summary(lane: &str) -> Value {
    json!({
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
    })
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
