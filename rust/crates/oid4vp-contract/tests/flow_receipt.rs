use marty_oid4vp_contract::{
    build_verification_callback_payload, digest_domain_json, flow_callback_payload_digest,
    flow_result_digest, FlowVerificationReceiptContractVersion, FlowVerificationReceiptV1,
    FrozenPolicyIdentity, Oid4vpContractError, FLOW_REQUEST_BINDING_DIGEST_DOMAIN,
    MAX_EVIDENCE_PROJECTION_BYTES, MAX_IDENTIFIER_BYTES, VERIFICATION_RECEIPT,
};
use serde_json::{json, Value};

fn policy() -> FrozenPolicyIdentity {
    FrozenPolicyIdentity {
        id: "policy-1".into(),
        version: 7,
        content_digest: format!("sha256:{}", "a".repeat(64)),
    }
}

fn result() -> Value {
    json!({
        "policy_revision": policy(),
        "evaluation_result": "passed",
        "decision": "allow",
        "decision_reason": "requirements satisfied",
        "verified_claims": {"email": "member@example.com"},
        "credential_results": [{"signature_valid": true, "satisfied": true}],
        "evaluation_timestamp": "2026-08-20T12:00:00Z",
        "submission_digest": "b".repeat(64),
        "error_codes": [],
        "warnings": [],
    })
}

// The callback builder accepts its existing owner's digest function. This
// contract-only fixture uses the canonical digest owner under a test domain;
// Auth's independent suite exercises the real MMF digest and HMAC together.
fn callback_digest(value: &Value) -> Result<String, Oid4vpContractError> {
    digest_domain_json("test.flow-receipt/callback-owner/v1", value)
        .map(|value| value.strip_prefix("sha256:").unwrap().to_owned())
}

fn callback(result: &Value) -> Value {
    build_verification_callback_payload(
        "flow-1",
        "policy-1",
        Some("2026-08-20T12:00:02Z".into()),
        result.as_object().unwrap(),
        callback_digest,
    )
    .unwrap()
}

fn receipt(result: &Value) -> FlowVerificationReceiptV1 {
    let mut value = FlowVerificationReceiptV1 {
        contract: FlowVerificationReceiptContractVersion::V1,
        organization_id: "org-1".into(),
        flow_instance_id: "flow-1".into(),
        policy: policy(),
        request_binding_digest: digest_domain_json(
            FLOW_REQUEST_BINDING_DIGEST_DOMAIN,
            &json!({
                "organization_id": "org-1",
                "flow_instance_id": "flow-1",
                "context": {"nonce": "raw-nonce-never-in-receipt", "token": "raw-wallet-material"}
            }),
        )
        .unwrap(),
        submission_digest: "b".repeat(64),
        nonce_digest: "c".repeat(64),
        result_digest: flow_result_digest(result).unwrap(),
        callback_payload_digest: flow_callback_payload_digest(&callback(result)).unwrap(),
        policy_evaluated_at_epoch_micros: 1_787_227_200_000_000,
        nonce_consumed_at_epoch_micros: 1_787_227_202_123_456,
        nonce_retention_expires_at_epoch_micros: 1_787_228_100_000_000,
        receipt_digest: String::new(),
    };
    value.receipt_digest = value.recompute_digest().unwrap();
    value
}

#[test]
fn receipt_retains_distinct_owner_times_and_only_minimized_bindings() {
    let result = result();
    let receipt = receipt(&result);
    receipt.validate().unwrap();
    receipt.validate_result(&result).unwrap();
    receipt.validate_callback(&callback(&result)).unwrap();
    assert_ne!(
        receipt.policy_evaluated_at_epoch_micros,
        receipt.nonce_consumed_at_epoch_micros,
    );
    assert_eq!(receipt.nonce_consumed_at_epoch_micros % 1_000, 456);

    let encoded = serde_json::to_string(&receipt).unwrap();
    for raw in [
        "raw-nonce-never-in-receipt",
        "raw-wallet-material",
        "member@example.com",
    ] {
        assert!(!encoded.contains(raw));
    }
    let decoded: FlowVerificationReceiptV1 = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, receipt);
    // No current-clock argument is involved: this is a historical persistence
    // projection, not a validity lease or proof that a transaction committed.
    decoded.validate().unwrap();
}

#[test]
fn every_receipt_binding_contributes_to_its_correspondence_digest() {
    let receipt = receipt(&result());
    for mutation in 0..12 {
        let mut changed = receipt.clone();
        match mutation {
            0 => changed.organization_id = "org-2".into(),
            1 => changed.flow_instance_id = "flow-2".into(),
            2 => changed.policy.id = "policy-2".into(),
            3 => changed.policy.version += 1,
            4 => changed.policy.content_digest = format!("sha256:{}", "d".repeat(64)),
            5 => changed.request_binding_digest = format!("sha256:{}", "d".repeat(64)),
            6 => changed.submission_digest = "d".repeat(64),
            7 => changed.nonce_digest = "d".repeat(64),
            8 => changed.result_digest = format!("sha256:{}", "d".repeat(64)),
            9 => changed.callback_payload_digest = format!("sha256:{}", "d".repeat(64)),
            10 => changed.policy_evaluated_at_epoch_micros += 1,
            _ => changed.nonce_consumed_at_epoch_micros += 1,
        }
        assert!(changed.validate().is_err(), "mutation {mutation}");
        assert_ne!(changed.recompute_digest().unwrap(), receipt.receipt_digest);
    }
    let mut changed = receipt.clone();
    changed.nonce_retention_expires_at_epoch_micros += 1;
    assert!(changed.validate().is_err());
    assert_ne!(changed.recompute_digest().unwrap(), receipt.receipt_digest);

    // A caller can repair this ordinary digest. Shape/hash validation remains
    // deliberately distinct from repository provenance or callback signatures.
    changed.receipt_digest = changed.recompute_digest().unwrap();
    changed.validate().unwrap();
}

#[test]
fn receipt_rejects_malformed_bounds_digests_and_inverted_clocks() {
    let receipt = receipt(&result());
    for mutation in 0..10 {
        let mut changed = receipt.clone();
        match mutation {
            0 => changed.organization_id = "x".repeat(MAX_IDENTIFIER_BYTES + 1),
            1 => changed.flow_instance_id = " flow-1".into(),
            2 => changed.organization_id = "org-1\n".into(),
            3 => changed.policy.version = 0,
            4 => changed.nonce_digest = "A".repeat(64),
            5 => changed.submission_digest = format!("sha256:{}", "b".repeat(64)),
            6 => changed.result_digest = "d".repeat(64),
            7 => changed.policy_evaluated_at_epoch_micros = 0,
            8 => {
                changed.nonce_consumed_at_epoch_micros =
                    changed.policy_evaluated_at_epoch_micros - 1
            }
            _ => {
                changed.nonce_retention_expires_at_epoch_micros =
                    changed.nonce_consumed_at_epoch_micros
            }
        }
        assert!(changed.recompute_digest().is_err(), "mutation {mutation}");
        assert!(changed.validate().is_err(), "mutation {mutation}");
    }
}

#[test]
fn receipt_wire_shape_rejects_unknown_versions_fields_and_duplicate_keys() {
    let receipt = receipt(&result());
    let wire = serde_json::to_value(&receipt).unwrap();
    for mutation in 0..3 {
        let mut changed = wire.clone();
        match mutation {
            0 => changed["contract"] = json!("marty.flow-verification-receipt/v2"),
            1 => changed["committed"] = json!(true),
            _ => changed["policy"]["authority"] = json!("caller"),
        }
        assert!(serde_json::from_value::<FlowVerificationReceiptV1>(changed).is_err());
    }
    let encoded = serde_json::to_string(&receipt).unwrap();
    let duplicate = format!("{{\"organization_id\":\"org-2\",{}", &encoded[1..]);
    assert!(serde_json::from_str::<FlowVerificationReceiptV1>(&duplicate).is_err());
}

#[test]
fn result_digest_rejects_recursion_and_preserves_unprojected_result_fields() {
    let result = result();
    let receipt = receipt(&result);
    assert!(flow_result_digest(&json!([])).is_err());
    let mut recursive = result.clone();
    recursive[VERIFICATION_RECEIPT] = Value::Null;
    assert!(flow_result_digest(&recursive).is_err());

    let mut changed = result.clone();
    changed["warnings"] = json!(["new terminal warning"]);
    assert_eq!(callback(&changed), callback(&result));
    assert!(receipt.validate_result(&changed).is_err());

    let mut changed = result.clone();
    changed["submission_digest"] = json!("d".repeat(64));
    assert!(receipt.validate_result(&changed).is_err());
    let oversized = json!({"value": "x".repeat(MAX_EVIDENCE_PROJECTION_BYTES)});
    assert!(flow_result_digest(&oversized).is_err());
}

#[test]
fn receipt_callback_binding_covers_exact_public_decision_and_policy() {
    let result = result();
    let receipt = receipt(&result);
    let callback = callback(&result);
    for mutation in 0..8 {
        let mut changed = callback.clone();
        match mutation {
            0 => changed["flow_instance_id"] = json!("flow-2"),
            1 => changed["policy_revision"]["version"] = json!(8),
            2 => changed["verified_claims"]["email"] = json!("other@example.com"),
            3 => changed["result"] = json!("failed"),
            4 => changed["decision"] = json!("deny"),
            5 => changed["decision_reason"] = json!("other reason"),
            6 => changed["evidence_digest"] = json!("d".repeat(64)),
            _ => changed["completed_at"] = json!("2026-08-20T12:00:03Z"),
        }
        assert!(
            receipt.validate_callback(&changed).is_err(),
            "mutation {mutation}"
        );
    }
    for mutation in 0..4 {
        let mut changed = callback.clone();
        match mutation {
            0 => changed["new_authority"] = json!(true),
            1 => changed["verified_claims"] = json!([]),
            2 => changed["evidence_digest"] = json!("malformed"),
            _ => {
                changed.as_object_mut().unwrap().remove("policy_revision");
            }
        }
        assert!(flow_callback_payload_digest(&changed).is_err());
    }
}

#[test]
fn callback_builder_adds_receipt_before_decision_hash_without_hash_recursion() {
    let mut result = result();
    let receipt = receipt(&result);
    let before = callback(&result);
    assert!(before.get(VERIFICATION_RECEIPT).is_none());
    result[VERIFICATION_RECEIPT] = serde_json::to_value(&receipt).unwrap();
    let after = callback(&result);
    assert_eq!(after[VERIFICATION_RECEIPT], result[VERIFICATION_RECEIPT]);
    assert_eq!(before["evidence_digest"], after["evidence_digest"]);
    assert_ne!(before["decision_digest"], after["decision_digest"]);
    assert_eq!(
        flow_callback_payload_digest(&before).unwrap(),
        flow_callback_payload_digest(&after).unwrap(),
    );
    receipt.validate_callback(&after).unwrap();
    let mut crossed = after.clone();
    crossed[VERIFICATION_RECEIPT]["request_binding_digest"] =
        json!(format!("sha256:{}", "d".repeat(64)));
    assert!(receipt.validate_callback(&crossed).is_err());
    let mut signed_basis = after.clone();
    signed_basis
        .as_object_mut()
        .unwrap()
        .remove("decision_digest");
    assert_eq!(
        after["decision_digest"],
        callback_digest(&signed_basis).unwrap()
    );

    result["warnings"] = json!(["changed after receipt construction"]);
    assert!(build_verification_callback_payload(
        "flow-1",
        "policy-1",
        Some("2026-08-20T12:00:02Z".into()),
        result.as_object().unwrap(),
        callback_digest,
    )
    .is_err());
}

#[test]
fn nullable_callback_fields_keep_the_existing_wire_meaning() {
    let mut result = result();
    result["decision_reason"] = Value::Null;
    let receipt = receipt(&result);
    let base = callback(&result);
    assert!(base["decision_reason"].is_null());
    result[VERIFICATION_RECEIPT] = serde_json::to_value(&receipt).unwrap();
    let produced = callback(&result);
    assert!(produced["decision_reason"].is_null());
    receipt.validate_callback(&produced).unwrap();
}
