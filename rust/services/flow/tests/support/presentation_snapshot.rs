//! Trusted persisted-state fixtures. End-to-end start tests exercise the real
//! producer; these helpers supply equivalent private state to focused tests.
#![allow(dead_code)]

use marty_flow::FlowInstanceRecord;
use marty_oid4vp_contract::{digest_query_document, FrozenPolicyIdentity};
use serde_json::{json, Value};

pub const SNAPSHOT_KEY: &str = "_marty_presentation_request_v1";

pub fn revision(policy_id: &str) -> FrozenPolicyIdentity {
    FrozenPolicyIdentity {
        id: policy_id.into(),
        version: 1,
        content_digest: format!("sha256:{}", "a".repeat(64)),
    }
}

pub fn freeze(instance: &mut FlowInstanceRecord, definition: Value, dcql: Value) {
    instance.context[SNAPSHOT_KEY] = json!({
        "instance_id": instance.id,
        "organization_id": instance.organization_id,
        "nonce": instance.context["nonce"],
        "policy_revision": revision(instance.context["presentation_policy_id"].as_str().unwrap()),
        "presentation_definition_digest": digest_query_document(&definition).unwrap(),
        "presentation_definition": definition,
        "dcql_query_digest": digest_query_document(&dcql).unwrap(),
        "dcql_query": dcql,
    });
}

pub fn freeze_default(instance: &mut FlowInstanceRecord) {
    freeze(
        instance,
        json!({"id": "definition-1", "input_descriptors": [{"id": "member"}]}),
        json!({"credentials": [{"id": "member"}]}),
    );
}

pub fn emit_query(instance: &mut FlowInstanceRecord, field: &str, query: Value) {
    let mut definition = instance.context[SNAPSHOT_KEY]["presentation_definition"].clone();
    let mut dcql = instance.context[SNAPSHOT_KEY]["dcql_query"].clone();
    match field {
        "presentation_definition" => definition = query.clone(),
        "dcql_query" => dcql = query.clone(),
        _ => panic!("unsupported fixture query"),
    }
    freeze(instance, definition, dcql);
    let mut payload = json!({
        "nonce": instance.context["nonce"],
        "client_id": instance.context["oid4vp_client_id"],
    });
    payload[field] = query;
    instance.context["mip_messages"]["presentation_request"] = json!({"payload": payload});
}
