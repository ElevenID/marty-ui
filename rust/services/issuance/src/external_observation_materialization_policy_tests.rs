// SPDX-License-Identifier: AGPL-3.0-only
//! Exercises the actual pinned Core policy API, not a substitute policy engine.
use serde_json::{json, Value};

#[test]
fn unsigned_materialization_does_not_satisfy_requirements_or_authorize_approval() {
    let mut request = json!({
        "app":{"id":"application-one","organization_id":"organization-one","status":"pending"},
        "binding":{"auto_approve_on_evidence":true,"approval_policy_set_id":"reviewed-learning-approval"},
        "policy_set":{
            "id":"reviewed-learning-approval",
            "status":"ACTIVE",
            "policy_type":"APPROVAL_RULES",
            "cedar_policies":r#"permit (
                principal == MIP::ServiceAccount::"platform-evidence-policy",
                action == MIP::Action::"applications:approve",
                resource == MIP::Application::"application-one"
            ) when {
                context.evidence_verification_status == "VERIFIED" &&
                context.evidence_scope_matched &&
                context.all_required_evidence_satisfied &&
                context.required_evidence_count > 0
            };"#
        },
        "requirements":[{"fact_type":"learning.score","provider":"synthetic-lms","scope":{"course_id":"synthetic-course"},"pass_rule":{"completed":true}}],
        "facts":[{"id":"fact-one","logical_key":"one","provider":"synthetic-lms","fact_type":"learning.score","subject_id":"learner-one",
            "scope":{"course_id":"synthetic-course"},"assertion":{"completed":true,"score":100,"verified":true,"status":"VERIFIED","policy_allowed":true},
            "verification":crate::external_observation_materialization::unsigned_verification(),
            "source":{"kind":"external-observation:unsigned:v1"},
            "observed_at":"2026-11-16T00:00:00Z","effective_at":"2026-11-16T00:00:00Z","created_at":"2026-11-16T00:00:00Z"}]
    });
    let evaluate = |request: &Value| -> Value {
        serde_json::from_str(
            &marty_verification::evidence_policy::evaluate_application_evidence_policy_json(
                &request.to_string(),
            )
            .unwrap(),
        )
        .unwrap()
    };
    let unsigned = evaluate(&request);
    assert_eq!(unsigned["allowed"], false);
    assert_eq!(unsigned["context"]["satisfied_requirement_count"], 0);
    assert_eq!(
        unsigned["context"]["all_required_evidence_satisfied"],
        false
    );
    assert_eq!(
        unsigned["context"]["evidence_verification_status"],
        "UNVERIFIED"
    );
    assert_eq!(unsigned["errors"], json!([]));
    // Positive control: matching scope, passing assertions and auto-approval
    // configuration alone were insufficient; an actual VERIFIED fact changes
    // the policy result. This mutation is a test control, never runtime code.
    request["facts"][0]["verification"] =
        json!({"status":"VERIFIED","method":"SYNTHETIC_TEST_VERIFIER"});
    let verified = evaluate(&request);
    assert_eq!(verified["context"]["satisfied_requirement_count"], 1);
    assert_eq!(verified["allowed"], true);
    // A verified matching fact still grants no implicit approval authority.
    request["binding"]["approval_policy_set_id"] = Value::Null;
    request.as_object_mut().unwrap().remove("policy_set");
    let without_policy = evaluate(&request);
    assert_eq!(without_policy["context"]["satisfied_requirement_count"], 1);
    assert_eq!(without_policy["allowed"], false);
}
