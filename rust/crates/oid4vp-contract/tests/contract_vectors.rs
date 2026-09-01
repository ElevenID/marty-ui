use base64::{engine::general_purpose, Engine as _};
use marty_oid4vp_contract::{
    digest_audience, digest_frozen_request, digest_nonce, digest_query_document, digest_replay_key,
    digest_response_item, digest_wallet_submission, AuthenticatedDecisionAction,
    AuthenticatedResult, CredentialStatusMode, CredentialStatusState, EvidenceCheckOutcome,
    EvidenceProcessingStatus, FrozenAlternativeRequirementGroup, FrozenOid4vpRequestV1,
    Oid4vpContractError, Oid4vpEvidenceProjectionV1, PresentationDescriptor,
    PresentationSubmission, QueryKind, VpToken, WalletSubmissionV1, AUDIENCE_DIGEST_DOMAIN,
    FROZEN_REQUEST_DIGEST_DOMAIN, MAX_CLAIMS_PER_CREDENTIAL, MAX_CLAIM_VALUE_BYTES, MAX_CODE_BYTES,
    MAX_CREDENTIALS, MAX_DESCRIPTOR_DEPTH, MAX_EVIDENCE_LIST_ITEMS, MAX_EVIDENCE_PROJECTION_BYTES,
    MAX_FROZEN_REQUEST_BYTES, MAX_IDENTIFIER_BYTES, MAX_JSON_DEPTH,
    MAX_PRIVACY_BASE64_DECODE_LAYERS, MAX_PRIVACY_FRAGMENT_BYTES, MAX_PRIVACY_FRAGMENT_PARTS,
    MAX_PRIVACY_NORMALIZATION_STATES, MAX_PRIVACY_NORMALIZATION_STEPS,
    MAX_PRIVACY_NORMALIZED_BYTES, MAX_PRIVACY_PERCENT_DECODE_LAYERS, MAX_QUERY_DOCUMENT_BYTES,
    MAX_QUERY_REQUIREMENTS, MAX_REQUEST_LIFETIME_SECONDS, MAX_STATUS_VALIDITY_SECONDS, MAX_TOKENS,
    MAX_TOKEN_BYTES, MAX_WALLET_SUBMISSION_BYTES, MIN_NONCE_BYTES, MIN_TOKEN_BYTES,
    NONCE_DIGEST_DOMAIN, QUERY_DOCUMENT_DIGEST_DOMAIN, REPLAY_KEY_DIGEST_DOMAIN,
    REQUIRED_OID4VP_CHECKS, RESPONSE_ITEM_DIGEST_DOMAIN, WALLET_SUBMISSION_DIGEST_DOMAIN,
};
use serde_json::{json, Value};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/oid4vp-authenticated-contract-v1.json"
    ))
    .expect("contract fixture must be valid JSON")
}

fn golden() -> (
    i64,
    FrozenOid4vpRequestV1,
    WalletSubmissionV1,
    Oid4vpEvidenceProjectionV1,
) {
    let fixture = fixture();
    let now = fixture["golden"]["now_epoch_seconds"].as_i64().unwrap();
    let request = serde_json::from_value(fixture["golden"]["frozen_request"].clone()).unwrap();
    let submission =
        serde_json::from_value(fixture["golden"]["wallet_submission"].clone()).unwrap();
    let evidence =
        serde_json::from_value(fixture["golden"]["evidence_projection"].clone()).unwrap();
    (now, request, submission, evidence)
}

#[test]
fn language_neutral_contract_freezes_boundaries_limits_and_domains() {
    let fixture = fixture();
    assert_eq!(fixture["schema_version"], 1);
    assert_eq!(fixture["contract_only"], true);
    assert_eq!(fixture["runtime_evidence"], false);
    assert_eq!(
        fixture["authenticated_promotion"],
        "sealed_canonical_verifier_adapter_only"
    );
    assert_eq!(
        fixture["canonical_query_producer"],
        "marty-oid4vci_and_marty-verification"
    );
    assert_eq!(fixture["privacy_profile"]["scan_json_object_keys"], true);
    assert_eq!(fixture["privacy_profile"]["over_budget"], "fail_closed");
    assert_eq!(
        fixture["policy_parity"]["revision"],
        "ec307b6edd0450c558869fd587215e72cd46e9d1"
    );
    assert_eq!(
        fixture["policy_parity"]["partial_decision"],
        "manual_review"
    );
    for (key, expected) in [
        ("query_document", QUERY_DOCUMENT_DIGEST_DOMAIN),
        ("frozen_request", FROZEN_REQUEST_DIGEST_DOMAIN),
        ("wallet_submission", WALLET_SUBMISSION_DIGEST_DOMAIN),
        ("response_item", RESPONSE_ITEM_DIGEST_DOMAIN),
        ("nonce", NONCE_DIGEST_DOMAIN),
        ("audience", AUDIENCE_DIGEST_DOMAIN),
        ("replay_key", REPLAY_KEY_DIGEST_DOMAIN),
    ] {
        assert_eq!(fixture["digest_profile"]["domains"][key], expected);
    }
    assert_eq!(
        fixture["required_check_ids"],
        serde_json::to_value(REQUIRED_OID4VP_CHECKS).unwrap()
    );
    for (key, expected) in [
        ("wallet_submission_bytes", MAX_WALLET_SUBMISSION_BYTES),
        ("frozen_request_bytes", MAX_FROZEN_REQUEST_BYTES),
        ("evidence_projection_bytes", MAX_EVIDENCE_PROJECTION_BYTES),
        ("identifier_bytes", MAX_IDENTIFIER_BYTES),
        ("code_bytes", MAX_CODE_BYTES),
        ("token_bytes", MAX_TOKEN_BYTES),
        ("token_minimum_bytes", MIN_TOKEN_BYTES),
        ("query_document_bytes", MAX_QUERY_DOCUMENT_BYTES),
        ("query_requirements", MAX_QUERY_REQUIREMENTS),
        ("tokens", MAX_TOKENS),
        ("credentials", MAX_CREDENTIALS),
        ("claims_per_credential", MAX_CLAIMS_PER_CREDENTIAL),
        ("claim_value_bytes", MAX_CLAIM_VALUE_BYTES),
        ("json_depth", MAX_JSON_DEPTH),
        ("descriptor_depth", MAX_DESCRIPTOR_DEPTH),
        (
            "request_lifetime_seconds",
            usize::try_from(MAX_REQUEST_LIFETIME_SECONDS).unwrap(),
        ),
        (
            "status_validity_seconds",
            usize::try_from(MAX_STATUS_VALIDITY_SECONDS).unwrap(),
        ),
        ("evidence_list_items", MAX_EVIDENCE_LIST_ITEMS),
        ("nonce_minimum_bytes", MIN_NONCE_BYTES),
        (
            "privacy_percent_decode_layers",
            MAX_PRIVACY_PERCENT_DECODE_LAYERS,
        ),
        (
            "privacy_base64_decode_layers",
            MAX_PRIVACY_BASE64_DECODE_LAYERS,
        ),
        (
            "privacy_normalization_steps",
            MAX_PRIVACY_NORMALIZATION_STEPS,
        ),
        (
            "privacy_normalization_states",
            MAX_PRIVACY_NORMALIZATION_STATES,
        ),
        ("privacy_normalized_bytes", MAX_PRIVACY_NORMALIZED_BYTES),
        ("privacy_fragment_bytes", MAX_PRIVACY_FRAGMENT_BYTES),
        ("privacy_fragment_parts", MAX_PRIVACY_FRAGMENT_PARTS),
    ] {
        assert_eq!(fixture["limits"][key], expected, "limit drifted: {key}");
    }
}

#[test]
fn golden_projection_is_exactly_bound_but_not_promoted_to_authenticated_evidence() {
    let (now, request, submission, projection) = golden();
    assert_eq!(
        request.query.document_digest,
        digest_query_document(&request.query.document).unwrap()
    );
    assert_eq!(
        projection.request_digest,
        digest_frozen_request(&request).unwrap()
    );
    assert_eq!(
        projection.response_digest,
        digest_wallet_submission(&submission).unwrap()
    );
    projection
        .validate_against_at(&request, &submission, now)
        .unwrap();
    assert_eq!(projection.decision.result, AuthenticatedResult::Passed);
    assert_eq!(
        projection.decision.decision,
        AuthenticatedDecisionAction::Allow
    );
}

#[test]
fn digest_vectors_are_canonical_and_domain_separated() {
    let (_, request, submission, projection) = golden();
    assert_eq!(
        digest_nonce(&request.nonce).unwrap(),
        "sha256:056694507f319e72b997d9c45d984c58ae09bbfebe046acff6ee4639c6f92a73"
    );
    assert_eq!(
        digest_audience(&request.verifier.client_id).unwrap(),
        "sha256:df71fc238bf4f4c518ac398f76c672fb5f99c63a89373dee580a55cc3ebc6f49"
    );
    assert_ne!(
        digest_nonce("same").unwrap(),
        digest_audience("same").unwrap()
    );
    let left = json!({"b": 2, "a": 1});
    let right = json!({"a": 1, "b": 2});
    assert_eq!(
        digest_query_document(&left).unwrap(),
        digest_query_document(&right).unwrap()
    );
    assert_eq!(
        digest_replay_key(&projection.request_digest, &projection.response_digest).unwrap(),
        projection.binding.replay.replay_key_digest
    );
    let token = match &submission.vp_token {
        VpToken::ByQuery(tokens) => &tokens["member_query"][0],
        VpToken::Single(_) => unreachable!(),
    };
    assert_eq!(
        digest_response_item(token, "member_query", "0").unwrap(),
        projection.credentials[0].response_token_digest
    );
}

#[test]
fn every_language_neutral_mutation_id_has_an_executable_rejection() {
    let fixture = fixture();
    let ids = fixture["required_mutation_ids"].as_array().unwrap();
    let vectors = fixture["mutation_vectors"].as_array().unwrap();
    assert_eq!(ids.len(), 90);
    assert_eq!(vectors.len(), ids.len());
    for (id, vector) in ids.iter().zip(vectors) {
        let id = id.as_str().unwrap();
        assert_eq!(vector["id"], id);
        assert_eq!(vector["expected_error"], expected_error_label(id));
        assert!(!vector["mutation"].as_str().unwrap().is_empty());
        let error = execute_mutation(id);
        assert_expected_error(id, &error);
    }
}

#[test]
fn statusless_credentials_pass_only_when_frozen_policy_allows_absence() {
    let (now, mut request, submission, mut projection) = golden();
    request.query.requirements[0].status.mode = CredentialStatusMode::AllowAbsent;
    projection.credentials[0].status_ids.clear();
    let status = &mut projection.credentials[0].status;
    status.state = CredentialStatusState::NotPresent;
    status.checked_at_epoch_seconds = None;
    status.valid_until_epoch_seconds = None;
    status.evidence_digest = None;
    rebind(&mut projection, &request, &submission);
    projection
        .validate_against_at(&request, &submission, now)
        .unwrap();
}

#[test]
fn indeterminate_status_is_consistent_and_never_allows() {
    let (now, request, submission, mut projection) = golden();
    let status = &mut projection.credentials[0].status;
    status.state = CredentialStatusState::Unknown;
    status.outcome = EvidenceCheckOutcome::Indeterminate;
    status.checked_at_epoch_seconds = None;
    status.valid_until_epoch_seconds = None;
    status.evidence_digest = None;
    projection.processing_status = EvidenceProcessingStatus::Incomplete;
    projection.checks[4].outcome = EvidenceCheckOutcome::Indeterminate;
    projection.checks[4].code = "OID4VP_CREDENTIAL_STATUS_INDETERMINATE".into();
    projection.policy_result.result = AuthenticatedResult::Indeterminate;
    projection.policy_result.decision = AuthenticatedDecisionAction::Deny;
    projection.policy_result.reason_code = "OID4VP_CREDENTIAL_STATUS_INDETERMINATE".into();
    projection.policy_result.satisfied_requirements = 1;
    projection.policy_result.required_total = 2;
    projection.policy_result.required_satisfied = 1;
    projection.policy_result.verified_claims.clear();
    projection.policy_result.violation_codes =
        vec!["OID4VP_CREDENTIAL_STATUS_INDETERMINATE".into()];
    projection.decision.result = AuthenticatedResult::Indeterminate;
    projection.decision.decision = AuthenticatedDecisionAction::Deny;
    projection.decision.reason_code = "OID4VP_CREDENTIAL_STATUS_INDETERMINATE".into();
    projection
        .validate_against_at(&request, &submission, now)
        .unwrap();
    assert_ne!(
        projection.decision.decision,
        AuthenticatedDecisionAction::Allow
    );
}

#[test]
fn hard_count_size_and_depth_limits_are_enforced() {
    let (_, mut request, mut submission, mut projection) = golden();
    if let VpToken::ByQuery(tokens) = &mut submission.vp_token {
        tokens
            .get_mut("member_query")
            .unwrap()
            .extend((0..64).map(|index| format!("header.payload.signature-{index}")));
    }
    assert!(matches!(
        submission.validate().unwrap_err(),
        Oid4vpContractError::InvalidField("vp_token.count")
    ));

    request.query.requirements[0].accepted_formats =
        (0..129).map(|index| format!("format-{index:03}")).collect();
    assert!(request
        .validate_at(request.issued_at_epoch_seconds)
        .is_err());

    projection.credentials[0]
        .claims
        .insert("given_name".into(), Value::String("x".repeat(16_385)));
    assert!(projection
        .validate_against_at(&golden().1, &golden().2, golden().0)
        .is_err());

    let oversized = format!(
        "{{\"contract\":\"marty.oid4vp-wallet-submission/v1\",\"vp_token\":\"{}\",\"presentation_submission\":null,\"state\":\"state-1\"}}",
        "x".repeat(1_048_576)
    );
    assert!(matches!(
        WalletSubmissionV1::from_json(&oversized).unwrap_err(),
        Oid4vpContractError::SizeLimit("wallet_submission")
    ));
}

fn execute_mutation(id: &str) -> Oid4vpContractError {
    let (now, mut request, mut submission, mut projection) = golden();
    match id {
        "unknown_wallet_field" => {
            let mut value = serde_json::to_value(&submission).unwrap();
            value["policy"] = json!({"allow": true});
            return WalletSubmissionV1::from_json(&value.to_string()).unwrap_err();
        }
        "unknown_nested_policy_field" => {
            let mut value = serde_json::to_value(&projection).unwrap();
            value["policy_result"]["unknown"] = json!(true);
            return Oid4vpEvidenceProjectionV1::from_json(&value.to_string()).unwrap_err();
        }
        "weak_nonce" => {
            request.nonce = "short".into();
            return request.validate_at(now).unwrap_err();
        }
        "expired_request" => {
            return request
                .validate_at(request.expires_at_epoch_seconds + 1)
                .unwrap_err()
        }
        "partial_query_coverage" => {
            let mut second = request.query.requirements[0].clone();
            second.id = "second_query".into();
            request.query.requirements.push(second);
            let mut second_document = request.query.document["credentials"][0].clone();
            second_document["id"] = json!("second_query");
            request.query.document["credentials"]
                .as_array_mut()
                .unwrap()
                .push(second_document);
            request.query.document_digest = digest_query_document(&request.query.document).unwrap();
            return request
                .validate_submission_at(&submission, now)
                .unwrap_err();
        }
        "duplicate_descriptor_id" => {
            make_presentation_exchange(&mut request, &mut submission);
            let descriptor = submission
                .presentation_submission
                .as_ref()
                .unwrap()
                .descriptor_map[0]
                .clone();
            submission
                .presentation_submission
                .as_mut()
                .unwrap()
                .descriptor_map
                .push(descriptor);
            return request
                .validate_submission_at(&submission, now)
                .unwrap_err();
        }
        "duplicate_credential_id" => {
            request.query.requirements[0].max_credentials = 2;
            let second_token = "second.header.payload.signature".to_string();
            if let VpToken::ByQuery(tokens) = &mut submission.vp_token {
                tokens
                    .get_mut("member_query")
                    .unwrap()
                    .push(second_token.clone());
            }
            let mut second = projection.credentials[0].clone();
            second.response_token_digest =
                digest_response_item(&second_token, "member_query", "1").unwrap();
            projection.credentials.push(second);
            rebind(&mut projection, &request, &submission);
        }
        "dcql_query_semantic_mismatch" => {
            request.query.document["credentials"][0]["format"] = json!("mso_mdoc");
            request.query.document_digest = digest_query_document(&request.query.document).unwrap();
            return request.validate_at(now).unwrap_err();
        }
        "dcql_nested_claim_path_mismatch" => {
            request.query.document["credentials"][0]["claims"][0]["path"] =
                json!(["attacker", "value"]);
            request.query.document_digest = digest_query_document(&request.query.document).unwrap();
            return request.validate_at(now).unwrap_err();
        }
        "pe_query_semantic_mismatch" => {
            make_presentation_exchange(&mut request, &mut submission);
            request.query.document["input_descriptors"][0]["constraints"]["fields"][1]["path"] =
                json!(["$.family_name"]);
            request.query.document_digest = digest_query_document(&request.query.document).unwrap();
            return request.validate_at(now).unwrap_err();
        }
        "pe_descriptor_format_mismatch" => {
            make_presentation_exchange(&mut request, &mut submission);
            submission
                .presentation_submission
                .as_mut()
                .unwrap()
                .descriptor_map[0]
                .format = "mso_mdoc".into();
            return request
                .validate_submission_at(&submission, now)
                .unwrap_err();
        }
        "duplicate_raw_dcql_token" => {
            if let VpToken::ByQuery(tokens) = &mut submission.vp_token {
                let duplicate = tokens["member_query"][0].clone();
                tokens.get_mut("member_query").unwrap().push(duplicate);
            }
            return submission.validate().unwrap_err();
        }
        "duplicate_response_item_digest" => {
            request.query.requirements[0].max_credentials = 2;
            let second_token = "second.header.payload.signature".to_string();
            if let VpToken::ByQuery(tokens) = &mut submission.vp_token {
                tokens.get_mut("member_query").unwrap().push(second_token);
            }
            let mut second = projection.credentials[0].clone();
            second.credential_id = "credential-2".into();
            projection.credentials.push(second);
            rebind(&mut projection, &request, &submission);
        }
        "token_digest_mismatch" => {
            projection.credentials[0].response_token_digest =
                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();
        }
        "unrequested_format" => projection.credentials[0].format = "mso_mdoc".into(),
        "unrequested_type" => {
            projection.credentials[0].authenticated_type_or_vct = vec!["other-type".into()];
        }
        "missing_required_claim" => projection.credentials[0].claims.clear(),
        "extra_disclosed_claim" => {
            projection.credentials[0]
                .claims
                .insert("family_name".into(), json!("Example"));
        }
        "statusless_when_required" => {
            projection.credentials[0].status_ids.clear();
            let status = &mut projection.credentials[0].status;
            status.state = CredentialStatusState::NotPresent;
            status.checked_at_epoch_seconds = None;
            status.valid_until_epoch_seconds = None;
            status.evidence_digest = None;
        }
        "active_without_status_evidence" => {
            projection.credentials[0].status.evidence_digest = None;
        }
        "stale_trust" => {
            request.policy.max_trust_age_seconds = 60;
            projection.credentials[0].trust.checked_at_epoch_seconds = now - 61;
            rebind(&mut projection, &request, &submission);
        }
        "replay_receipt_missing" => projection.binding.replay.receipt_digest = None,
        "nonce_digest_domain_swap" => {
            let wrong = digest_audience(&request.nonce).unwrap();
            projection.binding.challenge.expected_digest = wrong.clone();
            projection.binding.challenge.observed_digest = Some(wrong);
        }
        "audience_digest_domain_swap" => {
            let wrong = digest_nonce(&request.verifier.client_id).unwrap();
            projection.binding.audience.expected_digest = wrong.clone();
            projection.binding.audience.observed_digest = Some(wrong);
        }
        "missing_check" => {
            projection.checks.pop();
        }
        "reordered_check" => projection.checks.swap(0, 1),
        "free_floating_check_outcome" => {
            projection.checks[1].outcome = EvidenceCheckOutcome::Failed;
            projection.checks[1].code = "OID4VP_PRESENTATION_PROOF_FAILED".into();
        }
        "complete_with_indeterminate" => {
            let status = &mut projection.credentials[0].status;
            status.state = CredentialStatusState::Unknown;
            status.outcome = EvidenceCheckOutcome::Indeterminate;
            status.checked_at_epoch_seconds = None;
            status.valid_until_epoch_seconds = None;
            status.evidence_digest = None;
            projection.checks[4].outcome = EvidenceCheckOutcome::Indeterminate;
            projection.checks[4].code = "OID4VP_CREDENTIAL_STATUS_INDETERMINATE".into();
        }
        "policy_identity_mismatch" => projection.policy_result.policy.version += 1,
        "policy_count_mismatch" => projection.policy_result.satisfied_requirements = 0,
        "verified_claim_mismatch" => {
            projection
                .policy_result
                .verified_claims
                .insert("given_name".into(), json!("Mallory"));
        }
        "raw_token_in_claim" => {
            let token = match &submission.vp_token {
                VpToken::ByQuery(tokens) => tokens["member_query"][0].clone(),
                VpToken::Single(_) => unreachable!(),
            };
            projection.credentials[0]
                .claims
                .insert("given_name".into(), json!(token));
            projection.policy_result.verified_claims = projection.credentials[0].claims.clone();
        }
        "raw_token_substring" => {
            let token = match &submission.vp_token {
                VpToken::ByQuery(tokens) => tokens["member_query"][0].clone(),
                VpToken::Single(_) => unreachable!(),
            };
            projection.credentials[0]
                .claims
                .insert("given_name".into(), json!(format!("prefix-{token}-suffix")));
            projection.policy_result.verified_claims = projection.credentials[0].claims.clone();
        }
        "encoded_token_substring" => {
            let token = match &submission.vp_token {
                VpToken::ByQuery(tokens) => &tokens["member_query"][0],
                VpToken::Single(_) => unreachable!(),
            };
            let encoded = general_purpose::STANDARD.encode(token);
            projection.credentials[0].claims.insert(
                "given_name".into(),
                json!(format!("prefix-{encoded}-suffix")),
            );
            projection.policy_result.verified_claims = projection.credentials[0].claims.clone();
        }
        "standard_no_pad_token_substring" => {
            let token = "AAAAAAAAAAAAAAAAa~a";
            replace_first_dcql_token(&request, &mut submission, &mut projection, token);
            leak_claim(
                &mut projection,
                general_purpose::STANDARD_NO_PAD.encode(token),
            );
        }
        "url_safe_token_substring" => {
            let token = "AAAAAAAAAAAAAAAAa~a";
            replace_first_dcql_token(&request, &mut submission, &mut projection, token);
            leak_claim(
                &mut projection,
                general_purpose::URL_SAFE_NO_PAD.encode(token),
            );
        }
        "mixed_percent_token_substring" => {
            let token = "AAAAAAAAAAAAAAAAa~a";
            replace_first_dcql_token(&request, &mut submission, &mut projection, token);
            leak_claim(&mut projection, token.replace('~', "%7e"));
        }
        "nested_raw_token_at_decode_budget" => apply_nested_percent_privacy_mutation(
            &request,
            &mut submission,
            &mut projection,
            TokenProjection::Raw,
            MAX_PRIVACY_PERCENT_DECODE_LAYERS,
        ),
        "nested_raw_token_over_decode_budget" => apply_nested_percent_privacy_mutation(
            &request,
            &mut submission,
            &mut projection,
            TokenProjection::Raw,
            MAX_PRIVACY_PERCENT_DECODE_LAYERS + 1,
        ),
        "nested_standard_token_at_decode_budget" => apply_nested_percent_privacy_mutation(
            &request,
            &mut submission,
            &mut projection,
            TokenProjection::Standard,
            MAX_PRIVACY_PERCENT_DECODE_LAYERS,
        ),
        "nested_standard_token_over_decode_budget" => apply_nested_percent_privacy_mutation(
            &request,
            &mut submission,
            &mut projection,
            TokenProjection::Standard,
            MAX_PRIVACY_PERCENT_DECODE_LAYERS + 1,
        ),
        "nested_standard_no_pad_token_at_decode_budget" => apply_nested_percent_privacy_mutation(
            &request,
            &mut submission,
            &mut projection,
            TokenProjection::StandardNoPad,
            MAX_PRIVACY_PERCENT_DECODE_LAYERS,
        ),
        "nested_standard_no_pad_token_over_decode_budget" => apply_nested_percent_privacy_mutation(
            &request,
            &mut submission,
            &mut projection,
            TokenProjection::StandardNoPad,
            MAX_PRIVACY_PERCENT_DECODE_LAYERS + 1,
        ),
        "nested_url_safe_token_at_decode_budget" => apply_nested_percent_privacy_mutation(
            &request,
            &mut submission,
            &mut projection,
            TokenProjection::UrlSafe,
            MAX_PRIVACY_PERCENT_DECODE_LAYERS,
        ),
        "nested_url_safe_token_over_decode_budget" => apply_nested_percent_privacy_mutation(
            &request,
            &mut submission,
            &mut projection,
            TokenProjection::UrlSafe,
            MAX_PRIVACY_PERCENT_DECODE_LAYERS + 1,
        ),
        "nested_url_safe_no_pad_token_at_decode_budget" => apply_nested_percent_privacy_mutation(
            &request,
            &mut submission,
            &mut projection,
            TokenProjection::UrlSafeNoPad,
            MAX_PRIVACY_PERCENT_DECODE_LAYERS,
        ),
        "nested_url_safe_no_pad_token_over_decode_budget" => apply_nested_percent_privacy_mutation(
            &request,
            &mut submission,
            &mut projection,
            TokenProjection::UrlSafeNoPad,
            MAX_PRIVACY_PERCENT_DECODE_LAYERS + 1,
        ),
        "raw_token_in_json_key" => {
            let token = first_token(&submission).to_owned();
            leak_claim_object_key(&mut projection, &token);
        }
        "encoded_token_in_json_key" => {
            let claim = general_purpose::STANDARD.encode(first_token(&submission));
            retarget_claim(&mut request, &submission, &mut projection, &claim);
        }
        "percent_token_in_json_key" => {
            let claim = percent_encode_all_layers(first_token(&submission).to_owned(), 1);
            retarget_claim(&mut request, &submission, &mut projection, &claim);
        }
        "forbidden_wallet_key_variant" => {
            retarget_claim(
                &mut request,
                &submission,
                &mut projection,
                "my-VP-Token-copy",
            );
        }
        "nested_base64_at_decode_budget" => {
            let token = "AAAAAAAAAAAAAAAAa~a";
            replace_first_dcql_token(&request, &mut submission, &mut projection, token);
            leak_claim(
                &mut projection,
                nested_mixed_base64(token, MAX_PRIVACY_BASE64_DECODE_LAYERS),
            );
        }
        "nested_base64_over_decode_budget" => {
            let token = "AAAAAAAAAAAAAAAAa~a";
            replace_first_dcql_token(&request, &mut submission, &mut projection, token);
            leak_claim(
                &mut projection,
                nested_mixed_base64(token, MAX_PRIVACY_BASE64_DECODE_LAYERS + 1),
            );
        }
        "mixed_percent_nested_base64" => {
            let token = "AAAAAAAAAAAAAAAAa~a";
            replace_first_dcql_token(&request, &mut submission, &mut projection, token);
            let encoded = nested_mixed_base64(token, MAX_PRIVACY_BASE64_DECODE_LAYERS);
            leak_claim(
                &mut projection,
                percent_encode_all_layers(encoded, MAX_PRIVACY_PERCENT_DECODE_LAYERS),
            );
        }
        "base64_wrapped_percent_token" => apply_mixed_privacy_mutation(
            &request,
            &mut submission,
            &mut projection,
            &[MixedEncoding::Percent, MixedEncoding::Standard],
        ),
        "percent_wrapped_base64_token" => apply_mixed_privacy_mutation(
            &request,
            &mut submission,
            &mut projection,
            &[MixedEncoding::Standard, MixedEncoding::Percent],
        ),
        "alternating_token_at_total_budget" => apply_mixed_privacy_mutation(
            &request,
            &mut submission,
            &mut projection,
            &[
                MixedEncoding::Percent,
                MixedEncoding::Standard,
                MixedEncoding::Percent,
                MixedEncoding::UrlSafeNoPad,
                MixedEncoding::Percent,
            ],
        ),
        "alternating_token_over_total_budget" => apply_mixed_privacy_mutation(
            &request,
            &mut submission,
            &mut projection,
            &[
                MixedEncoding::Percent,
                MixedEncoding::StandardNoPad,
                MixedEncoding::Percent,
                MixedEncoding::UrlSafe,
                MixedEncoding::Percent,
                MixedEncoding::Standard,
            ],
        ),
        "percent_forbidden_wallet_key" => retarget_claim(
            &mut request,
            &submission,
            &mut projection,
            &percent_encode_all_layers("vp_token".into(), 1),
        ),
        "standard_forbidden_wallet_key" => retarget_claim(
            &mut request,
            &submission,
            &mut projection,
            &general_purpose::STANDARD.encode("vp_token"),
        ),
        "standard_no_pad_forbidden_wallet_key" => retarget_claim(
            &mut request,
            &submission,
            &mut projection,
            &general_purpose::STANDARD_NO_PAD.encode("vp_token"),
        ),
        "url_safe_forbidden_wallet_key" => retarget_claim(
            &mut request,
            &submission,
            &mut projection,
            &general_purpose::URL_SAFE.encode("vp_token"),
        ),
        "url_safe_no_pad_forbidden_wallet_key" => retarget_claim(
            &mut request,
            &submission,
            &mut projection,
            &general_purpose::URL_SAFE_NO_PAD.encode("vp_token"),
        ),
        "mixed_forbidden_wallet_key" => {
            let percent = percent_encode_all_layers("vp_token".into(), 1);
            retarget_claim(
                &mut request,
                &submission,
                &mut projection,
                &general_purpose::URL_SAFE_NO_PAD.encode(percent),
            );
        }
        "pe_format_options_mismatch" => {
            make_presentation_exchange(&mut request, &mut submission);
            request.query.document["input_descriptors"][0]["format"]["dc+sd-jwt"]["alg"] =
                json!(["RS256"]);
            request.query.document_digest = digest_query_document(&request.query.document).unwrap();
            return request.validate_at(now).unwrap_err();
        }
        "pe_descriptor_path_mismatch" => {
            make_presentation_exchange(&mut request, &mut submission);
            submission
                .presentation_submission
                .as_mut()
                .unwrap()
                .descriptor_map[0]
                .path = "$.evil".into();
            return request
                .validate_submission_at(&submission, now)
                .unwrap_err();
        }
        "pe_none_algorithm" => {
            make_presentation_exchange(&mut request, &mut submission);
            request.query.document["format"]["dc+sd-jwt"]["alg"] = json!(["none"]);
            request.query.document["input_descriptors"][0]["format"]["dc+sd-jwt"]["alg"] =
                json!(["none"]);
            request.query.requirements[0]
                .format_options
                .insert("dc+sd-jwt".into(), json!({"alg": ["none"]}));
            request.query.requirements[0]
                .accepted_algorithms
                .insert("dc+sd-jwt".into(), vec!["none".into()]);
            request.query.document_digest = digest_query_document(&request.query.document).unwrap();
            return request.validate_at(now).unwrap_err();
        }
        "credential_algorithm_mismatch" => {
            projection.credentials[0].proof_algorithm = "RS256".into();
        }
        "dcql_leading_evil_type" => {
            request.query.document["credentials"][0]["format"] = json!("jwt_vc_json");
            request.query.document["credentials"][0]["meta"] = json!({
                "type_values": [["EvilCredential", "VerifiableCredential", "MemberCredential"]]
            });
            request.query.requirements[0].accepted_formats = vec!["jwt_vc_json".into()];
            request.query.requirements[0].accepted_algorithms =
                [("jwt_vc_json".into(), vec!["ES256".into()])]
                    .into_iter()
                    .collect();
            request.query.requirements[0].accepted_type_sets =
                vec![vec!["MemberCredential".into()]];
            request.query.document_digest = digest_query_document(&request.query.document).unwrap();
            return request.validate_at(now).unwrap_err();
        }
        "dcql_intent_type_mismatch" => {
            request.query.document["credentials"][0]["claims"][0]["intent_to_retain"] =
                json!("true");
            request.query.document_digest = digest_query_document(&request.query.document).unwrap();
            return request.validate_at(now).unwrap_err();
        }
        "dcql_intent_binding_mismatch" => {
            request.query.document["credentials"][0]["claims"][0]["intent_to_retain"] = json!(true);
            request.query.document_digest = digest_query_document(&request.query.document).unwrap();
            return request.validate_at(now).unwrap_err();
        }
        "extra_credential_type" => {
            projection.credentials[0].authenticated_type_or_vct = vec![
                "attacker-type".into(),
                "https://credentials.example/member".into(),
            ];
        }
        "manual_review_total_mismatch" => {
            make_partial_manual_review(&mut request, &mut submission, &mut projection, now);
            projection.policy_result.total_requirements = 4;
        }
        "alternative_group_total_mismatch" => {
            make_satisfied_alternative_group(&mut request, &mut submission, &mut projection);
            projection.policy_result.total_requirements = 3;
        }
        "unavailable_digest_binding_code_mismatch" => {
            projection.binding.challenge.observed_digest = None;
            projection.binding.challenge.outcome = EvidenceCheckOutcome::Indeterminate;
        }
        "unavailable_digest_binding_observed_fact" => {
            projection.binding.challenge.outcome = EvidenceCheckOutcome::Indeterminate;
            projection.binding.challenge.code = "OID4VP_NONCE_UNAVAILABLE".into();
        }
        "supporting_code_outcome_mismatch" => {
            projection.presentation.structure.code = "OID4VP_PRESENTATION_MALFORMED".into();
        }
        "allow_reason_mismatch" => {
            projection.policy_result.reason_code = "OID4VP_POLICY_FAILED".into();
            projection.decision.reason_code = "OID4VP_POLICY_FAILED".into();
        }
        "descriptor_depth_limit" => {
            let mut descriptor = PresentationDescriptor {
                id: "member_query".into(),
                format: "dc+sd-jwt".into(),
                path: "$".into(),
                path_nested: None,
            };
            for _ in 0..MAX_DESCRIPTOR_DEPTH {
                descriptor = PresentationDescriptor {
                    id: "member_query".into(),
                    format: "dc+sd-jwt".into(),
                    path: "$".into(),
                    path_nested: Some(Box::new(descriptor)),
                };
            }
            submission.presentation_submission = Some(PresentationSubmission {
                id: "submission-1".into(),
                definition_id: "definition-1".into(),
                descriptor_map: vec![descriptor],
            });
            return submission.validate().unwrap_err();
        }
        "claim_depth_limit" => {
            let mut value = json!("leaf");
            for _ in 0..17 {
                value = json!({"nested": value});
            }
            projection.credentials[0]
                .claims
                .insert("given_name".into(), value);
        }
        "dcql_dotted_path_collision" => {
            request.query.document["credentials"][0]["claims"][0]["id"] =
                json!("claim_address_street_name");
            request.query.document["credentials"][0]["claims"][0]["path"] =
                json!(["address.street", "name"]);
            request.query.requirements[0].required_claims = vec!["address.street.name".into()];
            request.query.requirements[0].allowed_claims = vec!["address.street.name".into()];
            request.query.requirements[0].dcql_claim_paths = [(
                "address.street.name".into(),
                vec!["address".into(), "street.name".into()],
            )]
            .into_iter()
            .collect();
            request.query.document_digest = digest_query_document(&request.query.document).unwrap();
            return request.validate_at(now).unwrap_err();
        }
        "fragmented_raw_token" => {
            let token = first_token(&submission).to_owned();
            leak_fragmented_token(&mut request, &submission, &mut projection, &token);
        }
        "fragmented_encoded_token" => {
            let token = general_purpose::STANDARD.encode(first_token(&submission));
            leak_fragmented_token(&mut request, &submission, &mut projection, &token);
        }
        "optional_obligation_blocks_allow" => {
            make_optional_failure(&mut request, &mut submission, &mut projection);
            projection.policy_result.result = AuthenticatedResult::Partial;
            projection.policy_result.decision = AuthenticatedDecisionAction::ManualReview;
            projection.policy_result.reason_code = "OID4VP_CREDENTIAL_STATUS_FAILED".into();
            projection.policy_result.verified_claims.clear();
            projection.policy_result.violation_codes =
                vec!["OID4VP_CREDENTIAL_STATUS_FAILED".into()];
            projection.decision.result = AuthenticatedResult::Partial;
            projection.decision.decision = AuthenticatedDecisionAction::ManualReview;
            projection.decision.reason_code = "OID4VP_CREDENTIAL_STATUS_FAILED".into();
        }
        "optional_presentation_proof_fabricated_fact" => {
            make_presentation_proof_optional(&mut request, &submission, &mut projection);
            projection.presentation.proof.evidence_digest = Some(
                "sha256:0202020202020202020202020202020202020202020202020202020202020202".into(),
            );
        }
        "non_allow_violation_inventory_mismatch" => {
            make_challenge_unavailable(&mut projection);
            projection
                .policy_result
                .violation_codes
                .push("OID4VP_Z_UNSUPPORTED".into());
        }
        "non_allow_reason_inventory_mismatch" => {
            make_challenge_unavailable(&mut projection);
            projection.policy_result.reason_code = "OID4VP_Z_UNSUPPORTED".into();
            projection.decision.reason_code = "OID4VP_Z_UNSUPPORTED".into();
        }
        "suspended_without_evidence" => {
            projection.credentials[0].status.state = CredentialStatusState::Suspended;
            projection.credentials[0].status.outcome = EvidenceCheckOutcome::Failed;
            projection.credentials[0].status.evidence_digest = None;
        }
        "expired_before_clock" => {
            projection.credentials[0].status.state = CredentialStatusState::Expired;
            projection.credentials[0].status.outcome = EvidenceCheckOutcome::Failed;
            projection.credentials[0].status.checked_at_epoch_seconds = None;
            projection.credentials[0].status.valid_until_epoch_seconds = None;
            projection.credentials[0].status.evidence_digest = None;
        }
        "active_at_expiry" => {
            projection.credentials[0].expires_at_epoch_seconds = Some(now);
        }
        unknown => panic!("unimplemented language-neutral mutation: {unknown}"),
    }
    projection
        .validate_against_at(&request, &submission, now)
        .unwrap_err()
}

fn assert_expected_error(id: &str, error: &Oid4vpContractError) {
    let expected = expected_error_label(id);
    let actual = match error {
        Oid4vpContractError::Deserialization => "deserialization",
        Oid4vpContractError::InvalidField(_) => "invalid_field",
        Oid4vpContractError::InvalidQueryDocument => "invalid_query",
        Oid4vpContractError::InvalidLifetime => "lifetime",
        Oid4vpContractError::QueryCoverageMismatch => "query_coverage",
        Oid4vpContractError::PresentationDefinitionMismatch => "presentation_definition",
        Oid4vpContractError::CredentialBindingMismatch => "credential_binding",
        Oid4vpContractError::CheckEvidenceMismatch => "check_evidence",
        Oid4vpContractError::StatusEvidenceMismatch => "status",
        Oid4vpContractError::TrustEvidenceMismatch => "trust",
        Oid4vpContractError::BindingMismatch => "binding",
        Oid4vpContractError::CheckInventoryMismatch => "inventory",
        Oid4vpContractError::DecisionMismatch => "decision",
        Oid4vpContractError::PrivacyViolation => "privacy",
        other => panic!("{id} returned unclassified error: {other:?}"),
    };
    assert_eq!(actual, expected, "unexpected error for {id}: {error:?}");
}

fn expected_error_label(id: &str) -> &'static str {
    match id {
        "unknown_wallet_field" | "unknown_nested_policy_field" => "deserialization",
        "weak_nonce" | "descriptor_depth_limit" | "claim_depth_limit" => "invalid_field",
        "expired_request" => "lifetime",
        "partial_query_coverage" => "query_coverage",
        "dcql_query_semantic_mismatch"
        | "dcql_nested_claim_path_mismatch"
        | "pe_query_semantic_mismatch"
        | "pe_format_options_mismatch"
        | "pe_none_algorithm"
        | "dcql_leading_evil_type"
        | "dcql_intent_type_mismatch"
        | "dcql_intent_binding_mismatch"
        | "dcql_dotted_path_collision" => "invalid_query",
        "duplicate_descriptor_id"
        | "pe_descriptor_format_mismatch"
        | "pe_descriptor_path_mismatch" => "presentation_definition",
        "duplicate_credential_id" | "token_digest_mismatch" | "duplicate_response_item_digest" => {
            "credential_binding"
        }
        "duplicate_raw_dcql_token" => "invalid_field",
        "unrequested_format"
        | "unrequested_type"
        | "missing_required_claim"
        | "extra_disclosed_claim"
        | "credential_algorithm_mismatch"
        | "extra_credential_type"
        | "free_floating_check_outcome"
        | "complete_with_indeterminate"
        | "supporting_code_outcome_mismatch"
        | "optional_presentation_proof_fabricated_fact" => "check_evidence",
        "statusless_when_required"
        | "active_without_status_evidence"
        | "suspended_without_evidence"
        | "expired_before_clock"
        | "active_at_expiry" => "status",
        "stale_trust" => "trust",
        "replay_receipt_missing"
        | "nonce_digest_domain_swap"
        | "audience_digest_domain_swap"
        | "unavailable_digest_binding_code_mismatch"
        | "unavailable_digest_binding_observed_fact" => "binding",
        "missing_check" | "reordered_check" => "inventory",
        "policy_identity_mismatch"
        | "policy_count_mismatch"
        | "verified_claim_mismatch"
        | "allow_reason_mismatch"
        | "manual_review_total_mismatch"
        | "alternative_group_total_mismatch"
        | "optional_obligation_blocks_allow"
        | "non_allow_violation_inventory_mismatch"
        | "non_allow_reason_inventory_mismatch" => "decision",
        "raw_token_in_claim"
        | "raw_token_substring"
        | "encoded_token_substring"
        | "standard_no_pad_token_substring"
        | "url_safe_token_substring"
        | "mixed_percent_token_substring"
        | "nested_raw_token_at_decode_budget"
        | "nested_raw_token_over_decode_budget"
        | "nested_standard_token_at_decode_budget"
        | "nested_standard_token_over_decode_budget"
        | "nested_standard_no_pad_token_at_decode_budget"
        | "nested_standard_no_pad_token_over_decode_budget"
        | "nested_url_safe_token_at_decode_budget"
        | "nested_url_safe_token_over_decode_budget"
        | "nested_url_safe_no_pad_token_at_decode_budget"
        | "nested_url_safe_no_pad_token_over_decode_budget"
        | "raw_token_in_json_key"
        | "encoded_token_in_json_key"
        | "percent_token_in_json_key"
        | "forbidden_wallet_key_variant"
        | "nested_base64_at_decode_budget"
        | "nested_base64_over_decode_budget"
        | "mixed_percent_nested_base64"
        | "base64_wrapped_percent_token"
        | "percent_wrapped_base64_token"
        | "alternating_token_at_total_budget"
        | "alternating_token_over_total_budget"
        | "percent_forbidden_wallet_key"
        | "standard_forbidden_wallet_key"
        | "standard_no_pad_forbidden_wallet_key"
        | "url_safe_forbidden_wallet_key"
        | "url_safe_no_pad_forbidden_wallet_key"
        | "mixed_forbidden_wallet_key" => "privacy",
        "fragmented_raw_token" | "fragmented_encoded_token" => "privacy",
        _ => unreachable!(),
    }
}

fn rebind(
    projection: &mut Oid4vpEvidenceProjectionV1,
    request: &FrozenOid4vpRequestV1,
    submission: &WalletSubmissionV1,
) {
    projection.request_digest = digest_frozen_request(request).unwrap();
    projection.response_digest = digest_wallet_submission(submission).unwrap();
    projection.binding.replay.replay_key_digest =
        digest_replay_key(&projection.request_digest, &projection.response_digest).unwrap();
}

#[test]
fn unavailable_digest_binding_is_representable_and_fails_closed() {
    let (now, request, submission, mut projection) = golden();
    make_challenge_unavailable(&mut projection);
    projection
        .validate_against_at(&request, &submission, now)
        .unwrap();
    assert_eq!(
        projection.decision.result,
        AuthenticatedResult::Indeterminate
    );
    assert_eq!(
        projection.decision.decision,
        AuthenticatedDecisionAction::Deny
    );
}

#[test]
fn partial_manual_review_matches_pinned_policy_totals() {
    let (now, mut request, mut submission, mut projection) = golden();
    make_partial_manual_review(&mut request, &mut submission, &mut projection, now);
    projection
        .validate_against_at(&request, &submission, now)
        .unwrap();
    assert_eq!(
        projection.policy_result.result,
        AuthenticatedResult::Partial
    );
    assert_eq!(
        projection.policy_result.decision,
        AuthenticatedDecisionAction::ManualReview
    );
    assert_eq!(projection.policy_result.total_requirements, 3);
    assert_eq!(projection.policy_result.satisfied_requirements, 2);
    assert_eq!(projection.policy_result.required_total, 3);
    assert_eq!(projection.policy_result.required_satisfied, 2);
}

#[test]
fn alternative_groups_count_as_one_pinned_policy_unit() {
    let (now, mut request, mut submission, mut projection) = golden();
    make_satisfied_alternative_group(&mut request, &mut submission, &mut projection);
    projection
        .validate_against_at(&request, &submission, now)
        .unwrap();
    assert_eq!(projection.policy_result.total_requirements, 2);
    assert_eq!(projection.policy_result.satisfied_requirements, 2);
    assert_eq!(projection.policy_result.required_total, 2);
    assert_eq!(projection.policy_result.required_satisfied, 2);
}

#[test]
fn dcql_w3c_type_sets_are_complete_and_order_independent() {
    let (now, mut request, submission, mut projection) = golden();
    request.query.document["credentials"][0]["format"] = json!("jwt_vc_json");
    request.query.document["credentials"][0]["meta"] = json!({
        "type_values": [["MemberCredential", "VerifiableCredential"]]
    });
    request.query.requirements[0].accepted_formats = vec!["jwt_vc_json".into()];
    request.query.requirements[0].accepted_algorithms =
        [("jwt_vc_json".into(), vec!["ES256".into()])]
            .into_iter()
            .collect();
    request.query.requirements[0].accepted_type_sets = vec![vec!["MemberCredential".into()]];
    projection.credentials[0].format = "jwt_vc_json".into();
    projection.credentials[0].authenticated_type_or_vct = vec!["MemberCredential".into()];
    request.query.document_digest = digest_query_document(&request.query.document).unwrap();
    rebind(&mut projection, &request, &submission);
    projection
        .validate_against_at(&request, &submission, now)
        .unwrap();
}

#[test]
fn pe_nested_format_algorithm_and_path_are_exactly_context_bound() {
    let (now, mut request, mut submission, mut projection) = golden();
    make_presentation_exchange(&mut request, &mut submission);
    let descriptor = &mut submission
        .presentation_submission
        .as_mut()
        .unwrap()
        .descriptor_map[0];
    descriptor.format = "jwt_vp".into();
    descriptor.path_nested = Some(Box::new(PresentationDescriptor {
        id: "member_query".into(),
        format: "dc+sd-jwt".into(),
        path: "$.verifiableCredential[0]".into(),
        path_nested: None,
    }));
    let token = first_token(&submission);
    projection.credentials[0].response_token_digest =
        digest_response_item(token, "member_query", "$|$.verifiableCredential[0]").unwrap();
    rebind(&mut projection, &request, &submission);
    projection
        .validate_against_at(&request, &submission, now)
        .unwrap();
}

fn replace_first_dcql_token(
    request: &FrozenOid4vpRequestV1,
    submission: &mut WalletSubmissionV1,
    projection: &mut Oid4vpEvidenceProjectionV1,
    token: &str,
) {
    match &mut submission.vp_token {
        VpToken::ByQuery(tokens) => tokens.get_mut("member_query").unwrap()[0] = token.into(),
        VpToken::Single(_) => unreachable!(),
    }
    projection.credentials[0].response_token_digest =
        digest_response_item(token, "member_query", "0").unwrap();
    rebind(projection, request, submission);
}

fn leak_claim(projection: &mut Oid4vpEvidenceProjectionV1, value: String) {
    projection.credentials[0]
        .claims
        .insert("given_name".into(), json!(format!("prefix-{value}-suffix")));
    projection.policy_result.verified_claims = projection.credentials[0].claims.clone();
}

#[derive(Clone, Copy)]
enum TokenProjection {
    Raw,
    Standard,
    StandardNoPad,
    UrlSafe,
    UrlSafeNoPad,
}

fn apply_nested_percent_privacy_mutation(
    request: &FrozenOid4vpRequestV1,
    submission: &mut WalletSubmissionV1,
    projection: &mut Oid4vpEvidenceProjectionV1,
    token_projection: TokenProjection,
    layers: usize,
) {
    let token = "AAAAAAAAAAAAAAAAa~a";
    replace_first_dcql_token(request, submission, projection, token);
    let projected = match token_projection {
        TokenProjection::Raw => token.to_owned(),
        TokenProjection::Standard => general_purpose::STANDARD.encode(token),
        TokenProjection::StandardNoPad => general_purpose::STANDARD_NO_PAD.encode(token),
        TokenProjection::UrlSafe => general_purpose::URL_SAFE.encode(token),
        TokenProjection::UrlSafeNoPad => general_purpose::URL_SAFE_NO_PAD.encode(token),
    };
    leak_claim(projection, percent_encode_all_layers(projected, layers));
}

fn percent_encode_all_layers(mut value: String, layers: usize) -> String {
    for _ in 0..layers {
        value = value
            .bytes()
            .map(|byte| format!("%{byte:02X}"))
            .collect::<String>();
    }
    value
}

fn first_token(submission: &WalletSubmissionV1) -> &str {
    match &submission.vp_token {
        VpToken::Single(token) => token,
        VpToken::ByQuery(tokens) => &tokens["member_query"][0],
    }
}

fn retarget_claim(
    request: &mut FrozenOid4vpRequestV1,
    submission: &WalletSubmissionV1,
    projection: &mut Oid4vpEvidenceProjectionV1,
    claim_name: &str,
) {
    let claim_id = format!("claim_{}", claim_name.replace(['-', '.'], "_"));
    request.query.document["credentials"][0]["claims"][0]["id"] = json!(claim_id);
    request.query.document["credentials"][0]["claims"][0]["path"] = json!([claim_name]);
    request.query.requirements[0].required_claims = vec![claim_name.into()];
    request.query.requirements[0].allowed_claims = vec![claim_name.into()];
    request.query.requirements[0].retained_claims.clear();
    projection.credentials[0].claims.clear();
    projection.credentials[0]
        .claims
        .insert(claim_name.into(), json!("Avery"));
    projection.policy_result.verified_claims = projection.credentials[0].claims.clone();
    request.query.document_digest = digest_query_document(&request.query.document).unwrap();
    rebind(projection, request, submission);
}

fn nested_mixed_base64(value: &str, layers: usize) -> String {
    let mut encoded = value.to_owned();
    for layer in 0..layers {
        encoded = if layer % 2 == 0 {
            general_purpose::STANDARD_NO_PAD.encode(encoded)
        } else {
            general_purpose::URL_SAFE.encode(encoded)
        };
    }
    encoded
}

#[test]
fn benign_mixed_normalization_boundaries_remain_accepted() {
    let (now, request, submission, mut projection) = golden();
    let benign = [
        MixedEncoding::Percent,
        MixedEncoding::Standard,
        MixedEncoding::Percent,
        MixedEncoding::UrlSafeNoPad,
        MixedEncoding::Percent,
    ]
    .iter()
    .fold(
        "ordinary~display".to_owned(),
        |value, encoding| match encoding {
            MixedEncoding::Percent => percent_encode_all_layers(value, 1),
            MixedEncoding::Standard => general_purpose::STANDARD.encode(value),
            MixedEncoding::StandardNoPad => general_purpose::STANDARD_NO_PAD.encode(value),
            MixedEncoding::UrlSafe => general_purpose::URL_SAFE.encode(value),
            MixedEncoding::UrlSafeNoPad => general_purpose::URL_SAFE_NO_PAD.encode(value),
        },
    );
    leak_exact_claim(&mut projection, benign);
    projection
        .validate_against_at(&request, &submission, now)
        .unwrap();

    let (now, mut request, submission, mut projection) = golden();
    let benign_key = general_purpose::URL_SAFE_NO_PAD
        .encode(percent_encode_all_layers("display_name".into(), 1));
    retarget_claim(&mut request, &submission, &mut projection, &benign_key);
    projection
        .validate_against_at(&request, &submission, now)
        .unwrap();
}

#[derive(Clone, Copy)]
enum MixedEncoding {
    Percent,
    Standard,
    StandardNoPad,
    UrlSafe,
    UrlSafeNoPad,
}

fn apply_mixed_privacy_mutation(
    request: &FrozenOid4vpRequestV1,
    submission: &mut WalletSubmissionV1,
    projection: &mut Oid4vpEvidenceProjectionV1,
    encodings: &[MixedEncoding],
) {
    let token = "AAAAAAAAAAAAAAAAa~a";
    replace_first_dcql_token(request, submission, projection, token);
    let encoded = encodings
        .iter()
        .fold(token.to_owned(), |value, encoding| match encoding {
            MixedEncoding::Percent => percent_encode_all_layers(value, 1),
            MixedEncoding::Standard => general_purpose::STANDARD.encode(value),
            MixedEncoding::StandardNoPad => general_purpose::STANDARD_NO_PAD.encode(value),
            MixedEncoding::UrlSafe => general_purpose::URL_SAFE.encode(value),
            MixedEncoding::UrlSafeNoPad => general_purpose::URL_SAFE_NO_PAD.encode(value),
        });
    leak_exact_claim(projection, encoded);
}

fn leak_exact_claim(projection: &mut Oid4vpEvidenceProjectionV1, value: String) {
    projection.credentials[0]
        .claims
        .insert("given_name".into(), json!(value));
    projection.policy_result.verified_claims = projection.credentials[0].claims.clone();
}

#[test]
fn structurally_nested_dcql_path_and_benign_fragments_are_accepted() {
    let (now, mut request, submission, mut projection) = golden();
    request.query.document["credentials"][0]["claims"][0]["id"] = json!("claim_address_street");
    request.query.document["credentials"][0]["claims"][0]["path"] = json!(["address", "street"]);
    request.query.requirements[0].required_claims = vec!["address.street".into()];
    request.query.requirements[0].allowed_claims = vec!["address.street".into()];
    projection.credentials[0].claims = [("address.street".into(), json!("ordinary display value"))]
        .into_iter()
        .collect();
    projection.policy_result.verified_claims = projection.credentials[0].claims.clone();
    request.query.document_digest = digest_query_document(&request.query.document).unwrap();
    rebind(&mut projection, &request, &submission);
    projection
        .validate_against_at(&request, &submission, now)
        .unwrap();

    let (now, mut request, submission, mut projection) = golden();
    request.query.document["credentials"][0]["claims"][0]["id"] =
        json!("claim_address_street_name");
    request.query.document["credentials"][0]["claims"][0]["path"] =
        json!(["address.street", "name"]);
    request.query.requirements[0].required_claims = vec!["address.street.name".into()];
    request.query.requirements[0].allowed_claims = vec!["address.street.name".into()];
    request.query.requirements[0].dcql_claim_paths = [(
        "address.street.name".into(),
        vec!["address.street".into(), "name".into()],
    )]
    .into_iter()
    .collect();
    projection.credentials[0].claims = [("address.street.name".into(), json!("Main"))]
        .into_iter()
        .collect();
    projection.policy_result.verified_claims = projection.credentials[0].claims.clone();
    request.query.document_digest = digest_query_document(&request.query.document).unwrap();
    rebind(&mut projection, &request, &submission);
    projection
        .validate_against_at(&request, &submission, now)
        .unwrap();

    let (now, mut request, submission, mut projection) = golden();
    leak_fragmented_token(
        &mut request,
        &submission,
        &mut projection,
        "ordinary-fragmented-display-value",
    );
    projection
        .validate_against_at(&request, &submission, now)
        .unwrap();
}

#[test]
fn optional_failures_and_absent_optional_presentation_proof_preserve_allow() {
    let (now, mut request, mut submission, mut projection) = golden();
    make_optional_failure(&mut request, &mut submission, &mut projection);
    projection
        .validate_against_at(&request, &submission, now)
        .unwrap();
    assert_eq!(
        projection.decision.decision,
        AuthenticatedDecisionAction::Allow
    );

    let (now, mut request, submission, mut projection) = golden();
    make_presentation_proof_optional(&mut request, &submission, &mut projection);
    projection
        .validate_against_at(&request, &submission, now)
        .unwrap();
    assert_eq!(
        projection.processing_status,
        EvidenceProcessingStatus::Complete
    );
    assert_eq!(
        projection.decision.decision,
        AuthenticatedDecisionAction::Allow
    );
}

#[test]
fn suspended_and_expired_lifecycle_states_are_preserved_failures() {
    let (now, request, submission, mut projection) = golden();
    make_status_failure(&mut projection, CredentialStatusState::Suspended);
    projection
        .validate_against_at(&request, &submission, now)
        .unwrap();

    let (now, request, submission, mut projection) = golden();
    projection.credentials[0].expires_at_epoch_seconds = Some(now);
    projection.credentials[0].status.checked_at_epoch_seconds = None;
    projection.credentials[0].status.valid_until_epoch_seconds = None;
    projection.credentials[0].status.evidence_digest = None;
    make_status_failure(&mut projection, CredentialStatusState::Expired);
    projection
        .validate_against_at(&request, &submission, now)
        .unwrap();
}

fn leak_claim_object_key(projection: &mut Oid4vpEvidenceProjectionV1, key: &str) {
    projection.credentials[0]
        .claims
        .insert("given_name".into(), json!({key: "Avery"}));
    projection.policy_result.verified_claims = projection.credentials[0].claims.clone();
}

fn leak_fragmented_token(
    request: &mut FrozenOid4vpRequestV1,
    submission: &WalletSubmissionV1,
    projection: &mut Oid4vpEvidenceProjectionV1,
    material: &str,
) {
    let midpoint = material.len() / 2;
    request.query.document["credentials"][0]["claims"] = json!([
        {"id": "claim_fragment_a", "path": ["fragment_a"]},
        {"id": "claim_fragment_b", "path": ["fragment_b"]}
    ]);
    request.query.requirements[0].required_claims = vec!["fragment_a".into(), "fragment_b".into()];
    request.query.requirements[0].allowed_claims = vec!["fragment_a".into(), "fragment_b".into()];
    projection.credentials[0].claims = [
        ("fragment_a".into(), json!(&material[..midpoint])),
        ("fragment_b".into(), json!(&material[midpoint..])),
    ]
    .into_iter()
    .collect();
    projection.policy_result.verified_claims = projection.credentials[0].claims.clone();
    request.query.document_digest = digest_query_document(&request.query.document).unwrap();
    rebind(projection, request, submission);
}

fn make_optional_failure(
    request: &mut FrozenOid4vpRequestV1,
    submission: &mut WalletSubmissionV1,
    projection: &mut Oid4vpEvidenceProjectionV1,
) {
    add_second_requirement(request, submission, projection, true);
    request.query.requirements[1].required = false;
    request.query.document_digest = digest_query_document(&request.query.document).unwrap();
    projection.checks[4].outcome = EvidenceCheckOutcome::Failed;
    projection.checks[4].code = "OID4VP_CREDENTIAL_STATUS_FAILED".into();
    projection.policy_result.total_requirements = 3;
    projection.policy_result.satisfied_requirements = 2;
    projection.policy_result.required_total = 2;
    projection.policy_result.required_satisfied = 2;
    rebind(projection, request, submission);
}

fn make_presentation_proof_optional(
    request: &mut FrozenOid4vpRequestV1,
    submission: &WalletSubmissionV1,
    projection: &mut Oid4vpEvidenceProjectionV1,
) {
    request.policy.presentation_proof_required = false;
    projection.presentation.proof.outcome = EvidenceCheckOutcome::Indeterminate;
    projection.presentation.proof.code = "OID4VP_PRESENTATION_PROOF_NOT_REQUIRED".into();
    projection.presentation.proof.evidence_digest = None;
    projection.presentation.proof.checked_at_epoch_seconds = None;
    projection.checks[1].outcome = EvidenceCheckOutcome::Indeterminate;
    projection.checks[1].code = "OID4VP_PRESENTATION_PROOF_NOT_REQUIRED".into();
    projection.policy_result.total_requirements = 1;
    projection.policy_result.satisfied_requirements = 1;
    projection.policy_result.required_total = 1;
    projection.policy_result.required_satisfied = 1;
    rebind(projection, request, submission);
}

fn make_status_failure(projection: &mut Oid4vpEvidenceProjectionV1, state: CredentialStatusState) {
    projection.credentials[0].status.state = state;
    projection.credentials[0].status.outcome = EvidenceCheckOutcome::Failed;
    projection.checks[4].outcome = EvidenceCheckOutcome::Failed;
    projection.checks[4].code = "OID4VP_CREDENTIAL_STATUS_FAILED".into();
    projection.policy_result.result = AuthenticatedResult::Failed;
    projection.policy_result.decision = AuthenticatedDecisionAction::Deny;
    projection.policy_result.reason_code = "OID4VP_CREDENTIAL_STATUS_FAILED".into();
    projection.policy_result.satisfied_requirements = 1;
    projection.policy_result.required_satisfied = 1;
    projection.policy_result.verified_claims.clear();
    projection.policy_result.violation_codes = vec!["OID4VP_CREDENTIAL_STATUS_FAILED".into()];
    projection.decision.result = AuthenticatedResult::Failed;
    projection.decision.decision = AuthenticatedDecisionAction::Deny;
    projection.decision.reason_code = "OID4VP_CREDENTIAL_STATUS_FAILED".into();
}

fn make_challenge_unavailable(projection: &mut Oid4vpEvidenceProjectionV1) {
    projection.binding.challenge.observed_digest = None;
    projection.binding.challenge.outcome = EvidenceCheckOutcome::Indeterminate;
    projection.binding.challenge.code = "OID4VP_NONCE_UNAVAILABLE".into();
    projection.checks[6].outcome = EvidenceCheckOutcome::Indeterminate;
    projection.checks[6].code = "OID4VP_TRANSACTION_BINDING_INDETERMINATE".into();
    projection.processing_status = EvidenceProcessingStatus::Incomplete;
    projection.policy_result.result = AuthenticatedResult::Indeterminate;
    projection.policy_result.decision = AuthenticatedDecisionAction::Deny;
    projection.policy_result.reason_code = "OID4VP_TRANSACTION_BINDING_INDETERMINATE".into();
    projection.policy_result.verified_claims.clear();
    projection.policy_result.violation_codes =
        vec!["OID4VP_TRANSACTION_BINDING_INDETERMINATE".into()];
    projection.decision.result = AuthenticatedResult::Indeterminate;
    projection.decision.decision = AuthenticatedDecisionAction::Deny;
    projection.decision.reason_code = "OID4VP_TRANSACTION_BINDING_INDETERMINATE".into();
}

fn add_second_requirement(
    request: &mut FrozenOid4vpRequestV1,
    submission: &mut WalletSubmissionV1,
    projection: &mut Oid4vpEvidenceProjectionV1,
    failed_status: bool,
) {
    let mut requirement = request.query.requirements[0].clone();
    requirement.id = "second_query".into();
    request.query.requirements.push(requirement);
    let mut document = request.query.document["credentials"][0].clone();
    document["id"] = json!("second_query");
    request.query.document["credentials"]
        .as_array_mut()
        .unwrap()
        .push(document);
    request.query.document_digest = digest_query_document(&request.query.document).unwrap();

    let second_token = "second.header.payload.signature".to_string();
    match &mut submission.vp_token {
        VpToken::ByQuery(tokens) => {
            tokens.insert("second_query".into(), vec![second_token.clone()]);
        }
        VpToken::Single(_) => unreachable!(),
    }
    let mut credential = projection.credentials[0].clone();
    credential.credential_id = "credential-2".into();
    credential.query_id = "second_query".into();
    credential.response_token_digest =
        digest_response_item(&second_token, "second_query", "0").unwrap();
    if failed_status {
        credential.status.state = CredentialStatusState::Revoked;
        credential.status.outcome = EvidenceCheckOutcome::Failed;
        credential.status.valid_until_epoch_seconds = None;
    }
    projection.credentials.push(credential);
    projection.policy_result.evaluated_credential_ids =
        vec!["credential-1".into(), "credential-2".into()];
    rebind(projection, request, submission);
}

fn make_partial_manual_review(
    request: &mut FrozenOid4vpRequestV1,
    submission: &mut WalletSubmissionV1,
    projection: &mut Oid4vpEvidenceProjectionV1,
    _now: i64,
) {
    add_second_requirement(request, submission, projection, true);
    projection.checks[4].outcome = EvidenceCheckOutcome::Failed;
    projection.checks[4].code = "OID4VP_CREDENTIAL_STATUS_FAILED".into();
    projection.policy_result.result = AuthenticatedResult::Partial;
    projection.policy_result.decision = AuthenticatedDecisionAction::ManualReview;
    projection.policy_result.reason_code = "OID4VP_CREDENTIAL_STATUS_FAILED".into();
    projection.policy_result.total_requirements = 3;
    projection.policy_result.satisfied_requirements = 2;
    projection.policy_result.required_total = 3;
    projection.policy_result.required_satisfied = 2;
    projection.policy_result.verified_claims.clear();
    projection.policy_result.violation_codes = vec!["OID4VP_CREDENTIAL_STATUS_FAILED".into()];
    projection.decision.result = AuthenticatedResult::Partial;
    projection.decision.decision = AuthenticatedDecisionAction::ManualReview;
    projection.decision.reason_code = "OID4VP_CREDENTIAL_STATUS_FAILED".into();
}

fn make_satisfied_alternative_group(
    request: &mut FrozenOid4vpRequestV1,
    submission: &mut WalletSubmissionV1,
    projection: &mut Oid4vpEvidenceProjectionV1,
) {
    add_second_requirement(request, submission, projection, false);
    for requirement in &mut request.query.requirements {
        requirement.required = false;
    }
    request.policy.alternative_requirement_groups = vec![FrozenAlternativeRequirementGroup {
        id: "member_alternatives".into(),
        requirement_ids: vec!["member_query".into(), "second_query".into()],
        min_satisfied: 1,
    }];
    projection.policy_result.total_requirements = 2;
    projection.policy_result.satisfied_requirements = 2;
    projection.policy_result.required_total = 2;
    projection.policy_result.required_satisfied = 2;
    rebind(projection, request, submission);
}

fn make_presentation_exchange(
    request: &mut FrozenOid4vpRequestV1,
    submission: &mut WalletSubmissionV1,
) {
    request.query.kind = QueryKind::PresentationExchange;
    request.query.document = json!({
        "id": "definition-1",
        "format": {"dc+sd-jwt": {"alg": ["ES256"]}},
        "input_descriptors": [{
            "id": "member_query",
            "name": "Member credential",
            "purpose": "Verify membership",
            "format": {"dc+sd-jwt": {"alg": ["ES256"]}},
            "constraints": {
                "limit_disclosure": "required",
                "fields": [
                    {"path": ["$.vct"], "filter": {"type": "string", "const": "https://credentials.example/member"}},
                    {"path": ["$.vc.credentialSubject.given_name", "$.credentialSubject.given_name", "$.given_name"], "optional": false}
                ]
            }
        }]
    });
    request.query.document_digest = digest_query_document(&request.query.document).unwrap();
    request.query.requirements[0]
        .format_options
        .insert("dc+sd-jwt".into(), json!({"alg": ["ES256"]}));
    let token = match &submission.vp_token {
        VpToken::ByQuery(tokens) => tokens["member_query"][0].clone(),
        VpToken::Single(token) => token.clone(),
    };
    submission.vp_token = VpToken::Single(token);
    submission.presentation_submission = Some(PresentationSubmission {
        id: "submission-1".into(),
        definition_id: "definition-1".into(),
        descriptor_map: vec![PresentationDescriptor {
            id: "member_query".into(),
            format: "dc+sd-jwt".into(),
            path: "$".into(),
            path_nested: None,
        }],
    });
}
