//! Delegated challenges must originate in trusted Flow state. The ordinary
//! start/advance APIs cannot install that state or disclose it in public results.

use marty_delegated_authority::DELEGATION_FLOW_CONTEXT_KEY;
use marty_flow::{parse_request, public_context, AdvanceFlowRequest, StartFlowRequest};
use serde_json::json;

#[test]
fn callers_cannot_install_delegation_bindings_through_start_or_advance() {
    let binding = json!({
        "grant_id": "10000000-0000-0000-0000-000000000001",
        "grant_revision": 1,
        "session_ref": "urn:example:private-session",
        "establishment_evidence_ref": "urn:example:private-establishment",
    });
    for context in [
        json!({DELEGATION_FLOW_CONTEXT_KEY: binding.clone()}),
        json!({"steps": [{"input": {DELEGATION_FLOW_CONTEXT_KEY: binding}}]}),
    ] {
        let start = parse_request::<StartFlowRequest>(json!({
            "organization_id": "organization-1",
            "flow_definition_id": "flow-1",
            "initial_context": context.clone(),
        }))
        .expect_err("delegation state must not come from a start request");
        assert_eq!(start.code, "FLOW.PRIVATE_CONTEXT");
        assert_eq!(start.field, "initial_context");
        assert!(!start.message.contains("private-establishment"));

        let advance = parse_request::<AdvanceFlowRequest>(json!({"data": context}))
            .expect_err("delegation state must not come from a step result");
        assert_eq!(advance.code, "FLOW.PRIVATE_CONTEXT");
        assert_eq!(advance.field, "data");
        assert!(!advance.message.contains("private-establishment"));
    }

    // These requests otherwise pass the same validators: rejection above is
    // attributable to the private delegation context, not an invalid fixture.
    parse_request::<StartFlowRequest>(json!({
        "organization_id": "organization-1",
        "flow_definition_id": "flow-1",
        "initial_context": {"visible": true},
    }))
    .expect("ordinary start context");
    parse_request::<AdvanceFlowRequest>(json!({"data": {"visible": true}}))
        .expect("ordinary step context");
}

#[test]
fn public_results_remove_delegation_state_recursively() {
    let stored = json!({
        DELEGATION_FLOW_CONTEXT_KEY: {"session_ref": "urn:example:private-session"},
        "steps": [{
            "visible": "kept",
            "details": {
                DELEGATION_FLOW_CONTEXT_KEY: {
                    "establishment_evidence_ref": "urn:example:private-establishment"
                },
                "complete": false,
            },
        }],
    });
    assert_eq!(
        public_context(&stored),
        json!({"steps": [{"visible": "kept", "details": {"complete": false}}]})
    );
}
