use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_release_evidence::age_proof::{validate_age_proof, AgeProofExpected, AgeProofInput};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn expected() -> AgeProofExpected {
    AgeProofExpected {
        run_id: "run-1".into(),
        organization_id: "org-1".into(),
        trusted_template_id: "template-1".into(),
        rejected_template_id: "template-2".into(),
        policy_id: "policy-1".into(),
        trust_profile_id: "trust-1".into(),
        verifier_did: "did:web:verifier.example.test".into(),
        trusted_issuer_id: format!("x509-sha256:{}", "a".repeat(64)),
        rejected_issuer_id: format!("x509-sha256:{}", "b".repeat(64)),
        service_origin: "https://verifier.example.test".into(),
        source_revision: "c".repeat(40),
        started_at: "2026-10-20T12:00:00Z".into(),
    }
}

fn input(observed: Value) -> AgeProofInput {
    AgeProofInput {
        expected: expected(),
        observed,
    }
}

fn result_input() -> AgeProofInput {
    let expected = expected();
    input(json!({
        "request_binding": {"instance_id": "flow-1", "request_sha256": "d".repeat(64),
            "nonce_sha256": "e".repeat(64), "external_reference": "D03-run-1-eudi-trusted"},
        "result_reply": {"status": 200, "body": {
            "instance_id": "flow-1", "status": "COMPLETED", "decision": "allow", "result": "passed",
            "evaluation_timestamp": "2026-10-20T12:01:00Z", "verified_claims": {"age_over_21": true},
            "credential_results": [{"credential_template_id": "template-1", "issuer_did": expected.trusted_issuer_id,
                "satisfied": true, "signature_valid": true, "trust_check_passed": true,
                "authenticated_disclosures": {"format": "mso_mdoc", "documents": [{
                    "doc_type": "org.iso.18013.5.1.mDL", "namespaces": {"org.iso.18013.5.1": ["age_over_21"]}
                }]}
            }]
        }}
    }))
}

#[test]
fn exact_authenticated_age_result_is_measured_without_claiming_device_qualification() {
    let receipt = validate_age_proof("allowed", &result_input()).unwrap();
    assert_eq!(
        receipt["evidence"]["disclosed_claim_names"],
        json!(["age_over_21"])
    );
    assert!(receipt.get("releaseReady").is_none());
    assert!(receipt.get("wallets").is_none());
}

#[test]
fn extra_authenticated_disclosure_is_rejected_even_when_policy_filtered_it_out() {
    let mut input = result_input();
    input.observed["result_reply"]["body"]["credential_results"][0]["authenticated_disclosures"]
        ["documents"][0]["namespaces"]["org.iso.18013.5.1"] = json!(["age_over_21", "birth_date"]);
    assert!(validate_age_proof("allowed", &input)
        .unwrap_err()
        .contains("actual authenticated"));
}

#[test]
fn no_disclosure_evidence_cannot_be_replaced_by_requested_or_accepted_claims() {
    let mut input = result_input();
    input.observed["result_reply"]["body"]["credential_results"][0]
        .as_object_mut()
        .unwrap()
        .remove("authenticated_disclosures");
    assert!(validate_age_proof("allowed", &input).is_err());
}

#[test]
fn age_claim_from_another_namespace_or_additional_document_is_rejected() {
    for documents in [
        json!([{"doc_type": "org.iso.18013.5.1.mDL", "namespaces": {"attacker.example": ["age_over_21"]}}]),
        json!([
            {"doc_type": "org.iso.18013.5.1.mDL", "namespaces": {"org.iso.18013.5.1": ["age_over_21"]}},
            {"doc_type": "other-document", "namespaces": {"private": ["name"]}}
        ]),
    ] {
        let mut input = result_input();
        input.observed["result_reply"]["body"]["credential_results"][0]
            ["authenticated_disclosures"]["documents"] = documents;
        assert!(validate_age_proof("allowed", &input).is_err());
    }
}

#[test]
fn native_allow_does_not_override_failed_trust_false_age_or_foreign_session() {
    for (pointer, value) in [
        ("/credential_results/0/trust_check_passed", json!(false)),
        ("/credential_results/0/signature_valid", json!(false)),
        ("/verified_claims/age_over_21", json!(false)),
        ("/instance_id", json!("previous-flow")),
        ("/evaluation_timestamp", json!("2026-10-19T12:00:00Z")),
    ] {
        let mut input = result_input();
        *input.observed["result_reply"]["body"]
            .pointer_mut(pointer)
            .unwrap() = value;
        assert!(validate_age_proof("allowed", &input).is_err(), "{pointer}");
    }
}

fn issuance_input() -> AgeProofInput {
    input(
        json!({"template_id": "template-1", "issuance_reply": {"status": 201, "body": {
            "id": "transaction-1", "organization_id": "org-1", "credential_template_id": "template-1"
        }}, "issued_credentials": [{
            "id": "credential-1", "organization_id": "org-1", "flow_execution_id": "transaction-1",
            "credential_template_id": "template-1", "status": "ACTIVE", "credential_format": "MDOC",
            "issued_at": "2026-10-20T12:00:20Z"
        }]}),
    )
}

#[test]
fn issuance_uses_current_public_id_and_exact_transaction_not_the_newest_template_record() {
    let mut input = issuance_input();
    let mut unrelated = input.observed["issued_credentials"][0].clone();
    unrelated["id"] = json!("unrelated-newer");
    unrelated["flow_execution_id"] = json!("previous-run");
    unrelated["issued_at"] = json!("2026-10-20T12:00:30Z");
    input.observed["issued_credentials"]
        .as_array_mut()
        .unwrap()
        .push(unrelated);
    assert_eq!(
        validate_age_proof("issued", &input).unwrap()["evidence"]["credential_id"],
        "credential-1"
    );
    input.observed["issuance_reply"]["body"]
        .as_object_mut()
        .unwrap()
        .remove("id");
    input.observed["issuance_reply"]["body"]["transaction_id"] = json!("transaction-1");
    assert!(validate_age_proof("issued", &input).is_err());
}

#[test]
fn ambiguous_issuance_and_cross_organization_inventory_are_rejected() {
    let mut input = issuance_input();
    let duplicate = input.observed["issued_credentials"][0].clone();
    input.observed["issued_credentials"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    assert!(validate_age_proof("issued", &input).is_err());
    let mut input = issuance_input();
    input.observed["issued_credentials"][0]["organization_id"] = json!("other-org");
    assert!(validate_age_proof("issued", &input).is_err());
}

fn request_input() -> AgeProofInput {
    // This tests projection/binding, not JWT signature verification. The driver
    // obtains this signed object from the native request endpoint over HTTPS.
    let header = json!({"alg": "ES256", "typ": "oauth-authz-req+jwt"});
    let payload = json!({
        "client_id": "did:web:verifier.example.test", "iss": "did:web:verifier.example.test",
        "nonce": "server-generated-nonce", "state": "flow-1", "iat": 1792497601_i64, "exp": 1792498201_i64,
        "response_uri": "https://verifier.example.test/v1/flows/instances/flow-1/submit",
        "response_mode": "direct_post", "response_type": "vp_token",
        "dcql_query": {"credentials": [{"id": "age", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
            "claims": [{"id": "claim_age_over_21", "path": ["org.iso.18013.5.1", "age_over_21"], "intent_to_retain": false}]}]}
    });
    let token = format!(
        "{}.{}.c2lnbmF0dXJl",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(payload.to_string())
    );
    input(json!({
        "external_reference": "D03-run-1-eudi-trusted", "request_jwt": token,
        "start_reply": {"status": 200, "body": {"instance_id": "flow-1", "presentation_policy_id": "policy-1", "nonce": "server-generated-nonce"}},
        "instance_reply": {"status": 200, "body": {"id": "flow-1", "organization_id": "org-1", "created_at": "2026-10-20T12:00:01Z",
            "metadata": {"external_reference": "D03-run-1-eudi-trusted"}, "context_data": {"presentation_policy_id": "policy-1",
                "trust_profile_id": "trust-1", "oid4vp_issuer_did": "did:web:verifier.example.test", "oid4vp_client_id": "did:web:verifier.example.test"}}}
    }))
}

#[test]
fn native_request_binding_checks_exact_dcql_path_and_own_session() {
    let input = request_input();
    let receipt = validate_age_proof("request", &input).unwrap();
    assert_eq!(receipt["evidence"]["instance_id"], "flow-1");
    assert!(receipt.to_string().contains("request_sha256"));
    assert!(!receipt.to_string().contains("server-generated-nonce"));
}

#[test]
fn native_request_overdisclosure_and_unbound_response_endpoint_are_rejected() {
    for change in ["extra", "namespace", "response", "retention"] {
        let mut input = request_input();
        let parts = input.observed["request_jwt"]
            .as_str()
            .unwrap()
            .split('.')
            .collect::<Vec<_>>();
        let mut payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        match change {
            "extra" => payload["dcql_query"]["credentials"][0]["claims"]
                .as_array_mut()
                .unwrap()
                .push(json!({"path": ["org.iso.18013.5.1", "birth_date"]})),
            "namespace" => {
                payload["dcql_query"]["credentials"][0]["claims"][0]["path"][0] = json!("other")
            }
            "response" => payload["response_uri"] = json!("https://other.example/submit"),
            _ => {
                payload["dcql_query"]["credentials"][0]["claims"][0]["intent_to_retain"] =
                    json!(true)
            }
        }
        input.observed["request_jwt"] = json!(format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(payload.to_string()),
            parts[2]
        ));
        assert!(validate_age_proof("request", &input).is_err(), "{change}");
    }
}

fn prepare_input() -> AgeProofInput {
    // Pin mapping, not X.509 validation: the native verifier owns that check.
    let certificate_bytes = b"fixture-certificate-DER";
    let certificate = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
        base64::engine::general_purpose::STANDARD.encode(certificate_bytes)
    );
    let mut expected = expected();
    expected.trusted_issuer_id = format!("x509-sha256:{:x}", Sha256::digest(certificate_bytes));
    let template = |id: &str, issuer: &str| {
        json!({
            "id": id, "organization_id": "org-1", "status": "ACTIVE", "credential_payload_format": "MDOC",
            "doctype": "org.iso.18013.5.1.mDL", "issuance_protocol": "OID4VCI_PRE_AUTH", "issuer_did": issuer,
            "claims": [{"name": "age_over_21", "namespace": "org.iso.18013.5.1", "mdoc_element_identifier": "age_over_21", "required": true}]
        })
    };
    AgeProofInput {
        expected,
        observed: json!({
            "trusted_template": template("template-1", "did:web:trusted.example.test"),
            "rejected_template": template("template-2", "did:web:rejected.example.test"),
            "policy": {"id": "policy-1", "organization_id": "org-1", "status": "ACTIVE", "trust_profile_id": "trust-1",
                "credential_requirements": [{"credential_template_id": "template-1", "requested_claims": [{"claim_name": "age_over_21",
                    "required": true, "selective_disclosure": true, "constraints": [{"claim_name": "age_over_21", "constraint_type": "EQUALS", "value": true}]}]}],
                "holder_binding": {"required": true, "proof_freshness": {"challenge_required": true, "audience_binding_required": true, "replay_detection_required": true}}},
            "trust_profile": {"id": "trust-1", "organization_id": "org-1", "status": "ACTIVE", "trust_sources": [{"source_type": "PINNED_ISSUER", "certificate_pem": certificate}]},
            "synthetic_claims": {"age_over_21": true}
        }),
    }
}

#[test]
fn prepare_reuses_active_native_resources_and_produces_no_template_or_policy_mutations() {
    let result = validate_age_proof("prepare", &prepare_input()).unwrap();
    let plan = &result["evidence"];
    assert_eq!(plan["trusted_issuance"]["path"], "/v1/issuance");
    assert_eq!(plan["verification"]["path"], "/v1/flows/verification/start");
    assert_eq!(
        plan["trusted_issuance"]["body"]["credential_template_id"],
        "template-1"
    );
    assert_eq!(
        plan["rejected_issuance"]["body"]["credential_template_id"],
        "template-2"
    );
    assert_eq!(plan.as_object().unwrap().len(), 4);
}

#[test]
fn prepare_refuses_false_age_broader_trust_and_cross_organization_resources() {
    for (pointer, value) in [
        ("/synthetic_claims/age_over_21", json!(false)),
        (
            "/policy/credential_requirements/0/requested_claims/0/constraints/0/value",
            json!(false),
        ),
        (
            "/policy/holder_binding/proof_freshness/replay_detection_required",
            json!(false),
        ),
        (
            "/trust_profile/trust_sources/0/source_type",
            json!("TRUST_REGISTRY"),
        ),
        ("/rejected_template/organization_id", json!("other-org")),
        ("/trusted_template/status", json!("DRAFT")),
    ] {
        let mut input = prepare_input();
        *input.observed.pointer_mut(pointer).unwrap() = value;
        assert!(validate_age_proof("prepare", &input).is_err(), "{pointer}");
    }
}

fn denial_input() -> AgeProofInput {
    input(json!({
        "request_binding": {"instance_id": "flow-rejected", "request_sha256": "d".repeat(64),
            "nonce_sha256": "e".repeat(64), "external_reference": "D03-run-1-eudi-rejected"},
        "issued_binding": {"template_id": "template-2", "credential_id": "credential-2", "transaction_id": "transaction-2"},
        "instance_reply": {"status": 200, "body": {"id": "flow-rejected", "organization_id": "org-1", "status": "AWAITING_WALLET",
            "metadata": {"external_reference": "D03-run-1-eudi-rejected"}, "context_data": {}}},
        "wallet_report": {"scenarioSlug": "private-online-age-proof", "laneId": "eudi-age-proof-interoperability", "result": "PASS",
            "profile": {"classification": "INDEPENDENT", "walletPackage": "example.wallet"},
            "startedAt": "2026-10-20T12:00:10Z", "completedAt": "2026-10-20T12:02:00Z",
            "actions": [{"type": "assertText", "target": "wallet", "result": "PASS", "before": {"package": "example.wallet"}, "after": {"package": "example.wallet"}}]},
        "denial_action_index": 0, "rejection_text": "Issuer is not trusted", "scenario_sha256": "f".repeat(64)
    }))
}

#[test]
fn wallet_issuer_trust_rejection_is_observed_without_inventing_a_backend_reason() {
    let result = validate_age_proof("denied", &denial_input()).unwrap();
    assert_eq!(
        result["evidence"]["observation"],
        "ISSUER_TRUST_REJECTION_OBSERVED"
    );
    assert_eq!(result["evidence"]["backend_reason_code"], Value::Null);
    assert_eq!(result["evidence"]["issuer_trust_denial_observed"], true);
    assert_eq!(
        result["evidence"]["typed_issuer_not_trusted_result_available"],
        false
    );
}

#[test]
fn pending_timeout_unknown_stale_or_unobserved_rejection_never_passes() {
    for (pointer, value) in [
        ("/rejection_text", json!("invalid_presentation")),
        ("/rejection_text", json!("Presentation failed")),
        ("/rejection_text", json!("Verifier is not trusted")),
        (
            "/rejection_text",
            json!("Issuer responded: verifier is not trusted"),
        ),
        ("/rejection_text", json!("Verification failed: timeout")),
        (
            "/rejection_text",
            json!("Presentation rejected: unknown error"),
        ),
        ("/rejection_text", json!("Waiting for presentation")),
        ("/wallet_report/actions/0/result", json!("FAIL")),
        (
            "/wallet_report/actions/0/after/package",
            json!("example.browser"),
        ),
        (
            "/wallet_report/profile/classification",
            json!("FIRST_PARTY_CONTROL"),
        ),
        ("/wallet_report/completedAt", json!("2026-10-19T12:02:00Z")),
        ("/instance_reply/body/status", json!("COMPLETED")),
        ("/instance_reply/body/status", json!("EXPIRED")),
        ("/instance_reply/body/id", json!("old-session")),
    ] {
        let mut input = denial_input();
        *input.observed.pointer_mut(pointer).unwrap() = value;
        assert!(validate_age_proof("denied", &input).is_err(), "{pointer}");
    }
}

fn cleanup_input() -> AgeProofInput {
    let mut input = issuance_input();
    input.observed["owned_issuance"] = json!([{"id": "transaction-1", "template_id": "template-1"}, {"id": "pending-offer", "template_id": "template-2"}]);
    let mut unrelated = input.observed["issued_credentials"][0].clone();
    unrelated["id"] = json!("unrelated-credential");
    unrelated["flow_execution_id"] = json!("old-transaction");
    input.observed["issued_credentials"]
        .as_array_mut()
        .unwrap()
        .push(unrelated);
    input.observed["owned_instances"] = json!([{"id": "flow-1", "organization_id": "org-1", "status": "AWAITING_WALLET", "metadata": {"external_reference": "D03-run-1-eudi-rejected"}}]);
    input
}

#[test]
fn cleanup_targets_exact_transactions_and_identifies_pending_offers_for_cancellation() {
    let result = validate_age_proof("cleanup", &cleanup_input()).unwrap();
    assert_eq!(
        result["evidence"]["pending_offers"],
        json!(["pending-offer"])
    );
    let actions = result["evidence"]["actions"].as_array().unwrap();
    assert_eq!(actions.len(), 2);
    assert_eq!(actions[0]["id"], "credential-1");
    assert_eq!(actions[1]["id"], "flow-1");
    assert!(!result.to_string().contains("unrelated-credential"));
}

#[test]
fn cleanup_refuses_ambiguous_foreign_and_previous_run_resources() {
    for (pointer, value) in [
        (
            "/issued_credentials/1/flow_execution_id",
            json!("transaction-1"),
        ),
        ("/issued_credentials/0/organization_id", json!("other-org")),
        ("/owned_instances/0/organization_id", json!("other-org")),
        (
            "/owned_instances/0/metadata/external_reference",
            json!("D03-old-run-rejected"),
        ),
    ] {
        let mut input = cleanup_input();
        *input.observed.pointer_mut(pointer).unwrap() = value;
        assert!(validate_age_proof("cleanup", &input).is_err(), "{pointer}");
    }
}
