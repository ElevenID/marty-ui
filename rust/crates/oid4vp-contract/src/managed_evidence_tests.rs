//! Contract-only fixtures. The production Policy/Flow tests must separately
//! establish native verification, authenticated acquisition and durable commit.

use super::*;
use crate::{
    digest_query_document, flow_result_digest,
    managed_status::{
        digest_managed_status_observation, ManagedCredentialStatusObservationV1,
        ManagedCredentialStatusRequestV1, MANAGED_STATUS_CONTRACT,
    },
    trust_authority::{
        credential_authority_basis_digest, credential_authority_snapshot_digest,
        credential_trust_evaluation_digest, issuer_public_key_thumbprint,
        CredentialAuthorityBasisV1, CredentialAuthoritySnapshotV1,
        CREDENTIAL_AUTHORITY_SNAPSHOT_CONTRACT, CREDENTIAL_TRUST_EVALUATION_CONTRACT,
    },
    EvidenceProfileReference, FlowVerificationReceiptContractVersion, Oid4vpEvaluationTransportV1,
};

const NONCE: &str = "managed-contract-test-nonce-at-least-32-bytes";
const TOKEN: &str = "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJkaWQ6d2ViOmlzc3Vlci5leGFtcGxlIn0.c2lnbmF0dXJl~ZGlzY2xvc3VyZQ~eyJhbGciOiJFZERTQSJ9.eyJub25jZSI6ImJvdW5kIn0.c2ln";

struct Fixture {
    candidate: ManagedPolicyEvidenceProjectionV2,
    transport: Oid4vpEvaluationTransportV1,
    result: Value,
    context: Value,
}

impl Fixture {
    fn request(&self) -> PolicyEvaluationValidityRequest<'_> {
        PolicyEvaluationValidityRequest {
            organization_id: "org-1",
            policy: &self.candidate.policy,
            nonce: NONCE,
            audience: "https://verifier.example",
            vp_token: TOKEN,
            trust_profile_id: Some("trust-1"),
            context: &self.context,
            oid4vp_transport: &self.transport,
        }
    }
}

fn digest(value: &str) -> String {
    digest_domain_json("marty.managed-evidence-contract-test/v1", value).unwrap()
}

fn fixture() -> Fixture {
    let public_key =
        json!({"kty":"OKP", "crv":"Ed25519", "x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"});
    let thumbprint = issuer_public_key_thumbprint(&public_key).unwrap();
    let basis: CredentialAuthorityBasisV1 = serde_json::from_value(json!({
        "id":"trust-1", "organization_id":"org-1", "status":"active",
        "compliance_status":"COMPLIANT", "trust_purposes":["credential_verification"],
        "supported_formats":["SD_JWT_VC"], "allowed_algorithms":["EdDSA"],
        "allowed_issuers":["did:web:issuer.example"], "denied_issuers":[],
        "policy_controls":{
            "validation_rules":{"min_key_size_rsa":2048,"min_key_size_ec":256,"require_key_usage":false,"max_chain_depth":5,"allow_self_signed":false},
            "time_policy":{"max_clock_skew_seconds":0,"credential_freshness_hours":null,"require_not_before":false,"require_expiration":true},
            "revocation_policy":{"check_mode":"HARD_FAIL","check_ocsp":false,"check_crl":false,"check_status_list":false,"offline_grace_period_hours":0,"cache_duration_hours":0},
            "trusted_assertion_formats":null,"unsupported_configuration_fields":[],
            "unsupported_configuration_digest":digest("unsupported")
        },
        "created_at":"1970-01-01T00:00:01Z","updated_at":"1970-01-01T00:00:02Z",
        "issuer_relationships":[{
            "relationship_id":"relationship-1", "issuer_entity_id":"issuer-1",
            "issuer_id":"did:web:issuer.example", "issuer_organization_id":"org-1",
            "is_system_issuer":false,"relationship_status":"TRUSTED", "trust_level":80,
            "compliance_status":"COMPLIANT","accreditations":[],
            "valid_from":"1970-01-01T00:00:01Z","valid_until":null,"revoked_at":null,
            "verification_keys":[public_key],
            "credential_authorizations":[{"format":"SD_JWT_VC","vct":"https://issuer.example/member"}],
            "issuer_created_at":"1970-01-01T00:00:01Z","issuer_updated_at":"1970-01-01T00:00:02Z",
            "relationship_created_at":"1970-01-01T00:00:01Z","relationship_updated_at":"1970-01-01T00:00:02Z"
        }]
    })).unwrap();
    let profile = EvidenceProfileReference {
        id: "trust-1".into(),
        version: 1,
        content_digest: credential_authority_basis_digest(&basis).unwrap(),
    };
    let mut authority = CredentialAuthoritySnapshotV1 {
        contract: CREDENTIAL_AUTHORITY_SNAPSHOT_CONTRACT.into(),
        organization_id: "org-1".into(),
        profile: profile.clone(),
        basis,
        response_digest: String::new(),
    };
    authority.response_digest = credential_authority_snapshot_digest(&authority).unwrap();
    let policy = FrozenPolicyIdentity {
        id: "policy-1".into(),
        version: 1,
        content_digest: digest("policy"),
    };
    let query = json!({"credentials":[{"id":"member", "format":"dc+sd-jwt", "meta":{"vct_values":["https://issuer.example/member"]}, "claims":[{"id":"member", "path":["member"]}]}]});
    let transport = Oid4vpEvaluationTransportV1 {
        credential_authority: Some(authority),
        query_kind: QueryKind::Dcql,
        query_digest: digest_query_document(&query).unwrap(),
        query_document: query,
        presentation_submission: None,
        vp_token_raw: json!({"member":[TOKEN]}).to_string(),
        verifier_client_id: "https://verifier.example".into(),
        request_nonce: NONCE.into(),
    };
    let selected_claims = BTreeMap::from([("member".into(), json!(true))]);
    let claim_results = json!([
        {"claim_name":"member","satisfied":true,"presented_value":true,"constraint_results":[{"constraint_type":"equals","passed":true}]},
        // Core preserves an optional absent claim without inventing its value.
        {"claim_name":"nickname","satisfied":true,"presented_value":null,"constraint_results":[]}
    ]);
    let native = json!({
        "result":"passed","decision":"allow","decision_reason":"All requirements satisfied",
        "policy_id":"policy-1","policy_name":"Member policy",
        "credential_results":[{"requirement_id":"member","credential_template_id":"template-1","credential_id":"urn:uuid:credential-1","issuer_id":"did:web:issuer.example","satisfied":true,"claim_results":claim_results,"errors":[],"warnings":[]}],
        "alternative_results":[], "total_requirements":1,"satisfied_requirements":1,"required_satisfied":1,"required_total":1,
        "verified_claims":selected_claims,"errors":[],"warnings":[],"evaluation_time_epoch_seconds":100
    });
    let mut transported_claims = claim_results;
    transported_claims[1]
        .as_object_mut()
        .unwrap()
        .remove("presented_value");
    let result = json!({
        "result":"passed","decision":"allow","decision_reason":"All requirements satisfied",
        "verified_claims":selected_claims,"evaluation_timestamp":"1970-01-01T00:01:40Z",
        "credential_results":[{"credential_template_id":"template-1","issuer_did":"did:web:issuer.example","credential_id":"urn:uuid:credential-1","signature_valid":true,"satisfied":true,"claim_results":transported_claims}],
        "total_requirements":1,"satisfied_requirements":1,"required_satisfied":1,"required_total":1
    });
    let context = json!({"oid4vp_verifier_context":true,"replay_check_verified":true});
    let request = PolicyEvaluationValidityRequest {
        organization_id: "org-1",
        policy: &policy,
        nonce: NONCE,
        audience: "https://verifier.example",
        vp_token: TOKEN,
        trust_profile_id: Some("trust-1"),
        context: &context,
        oid4vp_transport: &transport,
    };
    let validity =
        PolicyEvaluationValidityV1::bind(&request, &result, 100_000_000, 130_000_007).unwrap();
    let mut candidate = ManagedPolicyEvidenceProjectionV2 {
        contract: MANAGED_POLICY_EVIDENCE_CONTRACT_V2.into(),
        organization_id: "org-1".into(),
        policy,
        query_id: "member".into(),
        query_digest: transport.query_digest.clone(),
        response_token_digest: digest_response_item(TOKEN, "member", "0").unwrap(),
        nonce_digest: digest_nonce(NONCE).unwrap(),
        audience_digest: digest_audience("https://verifier.example").unwrap(),
        credential_template_id: "template-1".into(),
        issuer_id: "did:web:issuer.example".into(),
        vct: "https://issuer.example/member".into(),
        issuer_algorithm: "EdDSA".into(),
        issuer_scoped_subject_digest: digest("issuer-scoped-subject"),
        holder_key_thumbprint: thumbprint.clone(),
        issuer_key_thumbprint: thumbprint.clone(),
        issuer_jwt_digest: digest_sd_jwt_issuer_jws(TOKEN).unwrap(),
        issued_at_epoch_seconds: 90,
        valid_from_epoch_seconds: 90,
        expires_at_epoch_seconds: 200,
        selected_claims,
        policy_result: native,
        trust: CredentialTrustEvaluationResponseV1 {
            contract: CREDENTIAL_TRUST_EVALUATION_CONTRACT.into(),
            organization_id: "org-1".into(),
            profile,
            issuer_id: "did:web:issuer.example".into(),
            format: "SD_JWT_VC".into(),
            vct: "https://issuer.example/member".into(),
            issuer_algorithm: "EdDSA".into(),
            issuer_key_thumbprint: thumbprint,
            request_binding_digest: String::new(),
            outcome: EvidenceCheckOutcome::Passed,
            reason_code: "TRUST_PROFILE.CREDENTIAL_AUTHORIZED".into(),
            trust_level: Some(80),
            compliance_statuses: vec!["COMPLIANT".into()],
            accreditations: vec![],
            checked_at_epoch_seconds: 99,
            valid_until_epoch_seconds: 159,
            evidence_digest: String::new(),
        },
        status: ManagedStatusEvidenceProjectionV2 {
            authority: MANAGED_STATUS_AUTHORITY.into(),
            state: ManagedCredentialStatusState::Active,
            request_binding_digest: String::new(),
            issuer_jwt_digest: digest_sd_jwt_issuer_jws(TOKEN).unwrap(),
            checked_at_epoch_seconds: 99,
            valid_until_epoch_seconds: 159,
            evidence_digest: String::new(),
        },
        validity,
        evidence_digest: String::new(),
    };
    let binding = candidate.authority_binding_digest().unwrap();
    candidate.trust.request_binding_digest = binding.clone();
    candidate.trust.evidence_digest = credential_trust_evaluation_digest(&candidate.trust).unwrap();
    let mut status = ManagedCredentialStatusObservationV1 {
        contract: MANAGED_STATUS_CONTRACT.into(),
        authority: MANAGED_STATUS_AUTHORITY.into(),
        request: ManagedCredentialStatusRequestV1 {
            organization_id: "org-1".into(),
            issuer_id: candidate.issuer_id.clone(),
            credential_id: "urn:uuid:credential-1".into(),
            credential_template_id: candidate.credential_template_id.clone(),
            issuer_jwt_digest: candidate.issuer_jwt_digest.clone(),
            request_binding_digest: binding.clone(),
            max_age_seconds: 60,
        },
        state: ManagedCredentialStatusState::Active,
        status_updated_at_epoch_seconds: 90,
        checked_at_epoch_seconds: 99,
        valid_until_epoch_seconds: 159,
        credential_expires_at_epoch_seconds: 200,
        evidence_digest: String::new(),
    };
    status.evidence_digest = digest_managed_status_observation(&status).unwrap();
    candidate.status.request_binding_digest = binding;
    candidate.status.evidence_digest = status.evidence_digest;
    candidate.evidence_digest = candidate.recompute_digest().unwrap();
    Fixture {
        candidate,
        transport,
        result,
        context,
    }
}

fn completed(fixture: &Fixture) -> (ManagedOid4vpEvidenceProjectionV2, Value) {
    let candidate = &fixture.candidate;
    let request = ManagedFlowRequestBindingV2 {
        organization_id: candidate.organization_id.clone(),
        flow_instance_id: "flow-1".into(),
        initiating_principal_id: "principal-1".into(),
        policy: candidate.policy.clone(),
        query_id: candidate.query_id.clone(),
        query_digest: candidate.query_digest.clone(),
        verifier_client_id: "https://verifier.example".into(),
        response_uri: "https://verifier.example/response".into(),
        nonce_digest: candidate.nonce_digest.clone(),
        flow_nonce_digest: format!("{:x}", Sha256::digest(NONCE.as_bytes())),
        expected_state_digest: digest_managed_state_v2("flow-1").unwrap(),
        request_binding_digest: digest("expected-row"),
        submission_digest: "a".repeat(64),
        policy_request_binding_digest: candidate.validity.request_binding_digest.clone(),
    };
    let result = json!({
        "policy_revision":candidate.policy,"evaluation_result":"passed","decision":"allow",
        "verified_claims":candidate.selected_claims,"evaluation_timestamp":"1970-01-01T00:01:40.000000Z",
        "credential_results":fixture.result["credential_results"],"submission_digest":request.submission_digest,
        "evaluation_validity":candidate.validity,MANAGED_POLICY_EVIDENCE_DIGEST_V2:candidate.evidence_digest,
    });
    let mut receipt = FlowVerificationReceiptV1 {
        contract: FlowVerificationReceiptContractVersion::V1,
        organization_id: request.organization_id.clone(),
        flow_instance_id: request.flow_instance_id.clone(),
        policy: request.policy.clone(),
        request_binding_digest: request.request_binding_digest.clone(),
        submission_digest: request.submission_digest.clone(),
        nonce_digest: request.flow_nonce_digest.clone(),
        result_digest: flow_result_digest(&result).unwrap(),
        callback_payload_digest: digest("callback"),
        policy_evaluated_at_epoch_micros: 100_000_000,
        policy_valid_until_epoch_micros: Some(130_000_007),
        nonce_consumed_at_epoch_micros: 102_123_456,
        nonce_retention_expires_at_epoch_micros: 400_000_000,
        receipt_digest: String::new(),
    };
    receipt.receipt_digest = receipt.recompute_digest().unwrap();
    (
        ManagedOid4vpEvidenceProjectionV2::bind(request, candidate.clone(), receipt).unwrap(),
        result,
    )
}

#[test]
fn managed_v2_preserves_real_native_outcomes_and_distinct_historical_clocks() {
    let fixture = fixture();
    fixture
        .candidate
        .validate_for_request(&fixture.request(), &fixture.result)
        .unwrap();
    // Flow's old DTO lacks counters; the native candidate retains all four.
    let mut old_result = fixture.result.clone();
    for key in [
        "total_requirements",
        "satisfied_requirements",
        "required_total",
        "required_satisfied",
    ] {
        old_result.as_object_mut().unwrap().remove(key);
    }
    fixture
        .candidate
        .validate_for_request(&fixture.request(), &old_result)
        .unwrap();
    let (evidence, result) = completed(&fixture);
    evidence
        .request
        .validate_for_request(&fixture.request())
        .unwrap();
    evidence.validate_for_stored_result(&result).unwrap();
    evidence
        .validate_original_tokens(&[TOKEN, &fixture.transport.vp_token_raw])
        .unwrap();
    assert_eq!(
        evidence.receipt.policy_evaluated_at_epoch_micros,
        100_000_000
    );
    assert_eq!(evidence.receipt.nonce_consumed_at_epoch_micros, 102_123_456);
    assert_eq!(
        evidence.policy_evidence.validity.valid_until_epoch_micros,
        130_000_007
    );
    assert!(evidence
        .policy_evidence
        .validity
        .validate_at(400_000_000)
        .is_err());
    // Recovery has no current-time parameter and cannot renew the deadline.
    let recovered =
        ManagedOid4vpEvidenceProjectionV2::from_json(&serde_json::to_string(&evidence).unwrap())
            .unwrap();
    assert_eq!(recovered, evidence);
    recovered.validate_for_stored_result(&result).unwrap();
    assert!(!format!("{recovered:?}").contains("credential-1"));
    assert!(!format!("{:?}", fixture.candidate).contains("nickname"));
}

#[test]
fn managed_v2_rejects_native_parity_and_constraint_substitution() {
    let fixture = fixture();
    for (key, value) in [
        ("required_total", json!(2)),
        ("decision", json!("deny")),
        ("evaluation_time_epoch_seconds", json!(101)),
    ] {
        let mut candidate = fixture.candidate.clone();
        candidate.policy_result[key] = value;
        assert!(candidate.recompute_digest().is_err(), "{key}");
    }
    let mut candidate = fixture.candidate.clone();
    candidate.policy_result["credential_results"][0]["claim_results"][0]["constraint_results"][0]
        ["passed"] = json!(false);
    assert!(candidate.recompute_digest().is_err());
    let mut result = fixture.result.clone();
    result["required_total"] = json!(2);
    assert!(fixture
        .candidate
        .validate_for_request(&fixture.request(), &result)
        .is_err());
    let mut candidate = fixture.candidate.clone();
    candidate
        .selected_claims
        .insert("member".into(), json!(false));
    assert!(candidate.recompute_digest().is_err());
}

#[test]
fn managed_v2_binds_request_owner_scope_and_actual_transport() {
    let fixture = fixture();
    let mut request = fixture.request();
    request.nonce = "another-request-nonce-at-least-32-bytes";
    assert!(fixture
        .candidate
        .validate_for_request(&request, &fixture.result)
        .is_err());
    let mut candidate = fixture.candidate.clone();
    candidate.holder_key_thumbprint = "B".repeat(43);
    assert!(candidate.recompute_digest().is_err());
    let mut candidate = fixture.candidate.clone();
    candidate.status.state = ManagedCredentialStatusState::Revoked;
    assert!(candidate.recompute_digest().is_err());
    let (mut evidence, result) = completed(&fixture);
    evidence.request.flow_instance_id = "another-flow".into();
    assert!(evidence.recompute_digest().is_err());
    let (evidence, mut changed_result) = completed(&fixture);
    changed_result[MANAGED_POLICY_EVIDENCE_DIGEST_V2] = json!(digest("another-candidate"));
    assert!(evidence
        .validate_for_stored_result(&changed_result)
        .is_err());
    evidence.validate_for_stored_result(&result).unwrap();
}

#[test]
fn managed_v2_keeps_exclusive_microsecond_deadlines() {
    let fixture = fixture();
    let (mut evidence, _) = completed(&fixture);
    evidence.receipt.nonce_consumed_at_epoch_micros = 130_000_006;
    evidence.receipt.receipt_digest = evidence.receipt.recompute_digest().unwrap();
    evidence.evidence_digest = evidence.recompute_digest().unwrap();
    evidence.validate_historical().unwrap();
    evidence.receipt.nonce_consumed_at_epoch_micros = 130_000_007;
    assert!(evidence.receipt.recompute_digest().is_err());
    let mut candidate = fixture.candidate.clone();
    candidate.validity.evaluated_at_epoch_micros += 1;
    assert!(candidate.recompute_digest().is_err());
    let mut candidate = fixture.candidate.clone();
    candidate.status.checked_at_epoch_seconds = 101;
    assert!(candidate.recompute_digest().is_err());
}

#[test]
fn managed_v2_strict_parser_rejects_unknown_and_duplicate_native_fields() {
    let fixture = fixture();
    let encoded = serde_json::to_string(&fixture.candidate).unwrap();
    assert_eq!(
        ManagedPolicyEvidenceProjectionV2::from_json(&encoded).unwrap(),
        fixture.candidate
    );
    let duplicate = encoded.replace(
        "\"required_total\":1",
        "\"required_total\":1,\"required_total\":1",
    );
    assert_ne!(duplicate, encoded);
    assert!(ManagedPolicyEvidenceProjectionV2::from_json(&duplicate).is_err());
    let mut value = serde_json::to_value(&fixture.candidate).unwrap();
    value["policy_result"]["trusted"] = json!(true);
    assert!(ManagedPolicyEvidenceProjectionV2::from_json(&value.to_string()).is_err());
    let oversized = " ".repeat(MAX_EVIDENCE_PROJECTION_BYTES + 1);
    assert!(ManagedPolicyEvidenceProjectionV2::from_json(&oversized).is_err());
}

#[test]
fn managed_v2_original_token_privacy_covers_encoded_and_fragmented_material() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let fixture = fixture();
    let (evidence, _) = completed(&fixture);
    evidence.request.validate_original_tokens(&[TOKEN]).unwrap();
    let mut request = evidence.request;
    request.initiating_principal_id = TOKEN.into();
    assert_eq!(
        request.validate_original_tokens(&[TOKEN]),
        Err(Oid4vpContractError::PrivacyViolation)
    );
    for original in std::iter::once(TOKEN).chain(TOKEN.split('~')) {
        for token in [original.to_owned(), URL_SAFE_NO_PAD.encode(original)] {
            let mut candidate = fixture.candidate.clone();
            candidate.policy_result["warnings"] = json!([token]);
            assert_eq!(
                candidate.validate_original_tokens(&[TOKEN]),
                Err(Oid4vpContractError::PrivacyViolation)
            );
        }
    }
    let opaque = "opaque-original-wallet-material-not-for-projection";
    let mut candidate = fixture.candidate.clone();
    candidate.selected_claims = BTreeMap::from([
        ("part_a".into(), json!(&opaque[..23])),
        ("part_b".into(), json!(&opaque[23..])),
    ]);
    assert_eq!(
        candidate.validate_original_tokens(&[opaque]),
        Err(Oid4vpContractError::PrivacyViolation)
    );
}
