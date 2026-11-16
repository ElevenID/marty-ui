//! Trusted persisted-state fixtures. End-to-end start tests exercise the real
//! producer; these helpers supply equivalent private state to focused tests.
#![allow(dead_code)]

use marty_flow::FlowInstanceRecord;
use marty_oid4vp_contract::{digest_query_document, FrozenPolicyIdentity};
use serde_json::{json, Value};

pub const SNAPSHOT_KEY: &str = "_marty_presentation_request_v1";

pub fn authority(
    organization_id: &str,
) -> marty_oid4vp_contract::trust_authority::CredentialAuthoritySnapshotV1 {
    use marty_oid4vp_contract::{trust_authority::*, EvidenceProfileReference};
    let basis = CredentialAuthorityBasisV1 {
        id: "trust-1".into(), organization_id: organization_id.into(),
        status: "active".into(), compliance_status: "COMPLIANT".into(),
        trust_purposes: vec!["CREDENTIAL_ISSUER".into()], supported_formats: vec!["SD_JWT_VC".into()],
        allowed_algorithms: vec!["EdDSA".into()], allowed_issuers: None, denied_issuers: vec![],
        policy_controls: serde_json::from_value(json!({
            "validation_rules": {"min_key_size_rsa":2048,"min_key_size_ec":256,"require_key_usage":true,"max_chain_depth":5,"allow_self_signed":false},
            "time_policy": {"max_clock_skew_seconds":0,"credential_freshness_hours":null,"require_not_before":true,"require_expiration":true},
            "revocation_policy": {"check_mode":"HARD_FAIL","check_ocsp":false,"check_crl":false,"check_status_list":false,"offline_grace_period_hours":0,"cache_duration_hours":0},
            "trusted_assertion_formats":null,"unsupported_configuration_fields":[],
            "unsupported_configuration_digest": format!("sha256:{}", "0".repeat(64)),
        })).unwrap(),
        created_at: "2026-08-20T00:00:00Z".into(), updated_at: "2026-08-20T00:00:00Z".into(),
        issuer_relationships: vec![],
    };
    let mut snapshot = CredentialAuthoritySnapshotV1 {
        contract: CREDENTIAL_AUTHORITY_SNAPSHOT_CONTRACT.into(),
        organization_id: organization_id.into(),
        profile: EvidenceProfileReference {
            id: basis.id.clone(),
            version: 3,
            content_digest: credential_authority_basis_digest(&basis).unwrap(),
        },
        basis,
        response_digest: String::new(),
    };
    snapshot.response_digest = credential_authority_snapshot_digest(&snapshot).unwrap();
    snapshot.validate().unwrap();
    snapshot
}

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
