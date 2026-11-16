use marty_presentation_policy::{
    PolicyRecord, PolicyRecordError, PresentationPolicy, PRESENTATION_POLICY_MIGRATION,
};
use serde_json::json;
use uuid::Uuid;

fn policy() -> PresentationPolicy {
    serde_json::from_value(json!({
        "id": Uuid::new_v4(),
        "organization_id": Uuid::new_v4(),
        "name": "Member login",
        "description": "Request a member badge",
        "status": "active",
        "display_metadata": {"title":"Login","description":"Member login","purpose":"identity_verification","purpose_description":"Sign in","verifier_name":"Marty","verifier_logo_url":null,"privacy_policy_url":null,"terms_of_service_url":null},
        "required_claims": [],
        "accepted_credential_types": ["member"],
        "credential_requirements": [{
            "id": Uuid::new_v4(), "credential_template_id":"member", "display_name":"Member badge", "description":null, "required":true,
            "credential_payload_format":"sd_jwt_vc", "requested_claims":[{"id":Uuid::new_v4(),"claim_name":"email","display_name":"Email","description":null,"required":true,"selective_disclosure":true,"accept_derived":false,"predicate_spec":null,"constraints":[{"id":Uuid::new_v4(),"claim_name":"email","constraint_type":"presence","value":null,"description":null}]}],
            "trust_profile_id":Uuid::new_v4(), "max_age_seconds":3600, "require_fresh_issuance":true
        }],
        "alternative_requirements": [],
        "presentation_proof_required": false,
        "trust_profile_id": Uuid::new_v4(),
        "holder_binding": {"required":true,"binding_methods":["DEVICE_KEY"],"proof_profiles":["OID4VP_VERIFIABLE_PRESENTATION"],"proof_freshness":{"challenge_required":true}},
        "freshness": {"max_age_seconds":3600,"require_not_revoked":true,"revocation_grace_seconds":60},
        "issuer_constraints": {"min_trust_level":80,"required_compliance_statuses":["ACCREDITED"],"required_accreditations":["member"]},
        "credential_ranking_strategy":"CUSTOM", "credential_ranking_weights":{"freshness":0.7,"trust":0.3},
        "purpose":"Member login", "compliance_profile_id":Uuid::new_v4(), "prefer_predicates":true,
        "fallback_policy":"require_predicate", "supported_circuits":["age_over_21"], "version":3,
        "created_at":"2026-08-21T00:00:00Z", "updated_at":"2026-08-21T01:00:00Z"
    })).unwrap()
}

#[test]
fn native_policy_document_round_trips_every_intended_field() {
    let policy = policy();
    let record = PolicyRecord::from_policy(&policy).unwrap();
    assert_eq!(record.clone().into_policy().unwrap(), policy);
    assert_eq!(
        record.policy_document["supported_circuits"],
        json!(["age_over_21"])
    );
    assert_eq!(
        record.display_metadata["protocol"]["prefer_predicates"],
        true
    );
}

#[test]
fn explicit_jwt_vc_profiles_round_trip_both_storage_paths_and_old_readers_fail_closed() {
    use marty_oid4vp_contract::jwt_vc_profile::{policy_credential_format, JwtVcSecuringProfile};
    // The pre-profile requirement schema was already deny_unknown_fields.
    // This snapshot exercises its actual JSON boundary, including omission.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct PreProfileRequirement {
        id: Uuid,
        credential_template_id: String,
        display_name: String,
        description: Option<String>,
        required: bool,
        credential_payload_format: String,
        requested_claims: Vec<marty_presentation_policy::RequestedClaim>,
        trust_profile_id: Option<Uuid>,
        max_age_seconds: Option<u64>,
        require_fresh_issuance: bool,
    }
    let legacy = PolicyRecord::from_policy(&policy()).unwrap();
    assert!(legacy.credential_requirements[0]
        .get("expected_securing_profile")
        .is_none());
    serde_json::from_value::<PreProfileRequirement>(legacy.credential_requirements[0].clone())
        .unwrap();
    for profile in [
        JwtVcSecuringProfile::MartyNestedVc2JwtV1,
        JwtVcSecuringProfile::W3cVc2Jose2026V1,
    ] {
        let mut policy = policy();
        policy.accepted_credential_types.clear();
        policy.compliance_profile_id = None;
        policy.fallback_policy = None;
        policy.supported_circuits.clear();
        policy.prefer_predicates = false;
        policy.holder_binding = marty_presentation_policy::HolderBinding {
            required: true,
            ..Default::default()
        }
        .normalize();
        let requirement = &mut policy.credential_requirements[0];
        requirement.expected_securing_profile = Some(profile);
        requirement.credential_payload_format = policy_credential_format(profile).into();
        requirement.requested_claims.clear();
        policy.validate().unwrap();
        let stored = PolicyRecord::from_policy(&policy).unwrap();
        for document_path in [true, false] {
            let mut row = stored.clone();
            let requirement = if document_path {
                &row.policy_document["credential_requirements"][0]
            } else {
                &row.credential_requirements[0]
            };
            assert!(serde_json::from_value::<PreProfileRequirement>(requirement.clone()).is_err());
            if !document_path {
                row.policy_document = json!({});
            }
            assert_eq!(row.into_policy().unwrap(), policy);
            for marker in [json!(null), json!("unknown_profile")] {
                let mut poisoned = stored.clone();
                if document_path {
                    poisoned.policy_document["credential_requirements"][0]
                        ["expected_securing_profile"] = marker;
                } else {
                    poisoned.policy_document = json!({});
                    poisoned.credential_requirements[0]["expected_securing_profile"] = marker;
                }
                assert!(poisoned.into_policy().is_err());
            }
        }
    }
}

#[test]
fn policy_storage_rejects_private_material_in_current_and_legacy_json() {
    let mut candidate = policy();
    candidate.description = Some(r#"{"kty":"EC","d":"secret"}"#.into());
    assert_eq!(
        PolicyRecord::from_policy(&candidate).unwrap_err(),
        PolicyRecordError::PrivateKeyMaterial
    );

    let mut poisoned_row = PolicyRecord::from_policy(&policy()).unwrap();
    poisoned_row.display_metadata["protocol"]["private_key_pem"] = json!("secret");
    assert_eq!(
        poisoned_row.into_policy().unwrap_err(),
        PolicyRecordError::PrivateKeyMaterial
    );

    let mut poisoned_legacy_row = PolicyRecord::from_policy(&policy()).unwrap();
    poisoned_legacy_row.policy_document = json!({});
    poisoned_legacy_row.credential_requirements[0]["private_jwk"] = json!("secret");
    assert_eq!(
        poisoned_legacy_row.into_policy().unwrap_err(),
        PolicyRecordError::PrivateKeyMaterial
    );
}

#[test]
fn legacy_rows_are_upgraded_without_reimplementing_two_decoders() {
    let policy = policy();
    let mut record = PolicyRecord::from_policy(&policy).unwrap();
    record.policy_document = json!({});
    let hydrated = record.into_policy().unwrap();
    assert_eq!(hydrated.id, policy.id);
    assert_eq!(
        hydrated.credential_requirements,
        policy.credential_requirements
    );
    assert_eq!(hydrated.holder_binding, policy.holder_binding);
    assert_eq!(hydrated.supported_circuits, policy.supported_circuits);
    assert_eq!(hydrated.required_claims, policy.required_claims);
}

#[test]
fn malformed_legacy_rows_fail_closed_and_schema_is_non_destructive() {
    let mut record = PolicyRecord::from_policy(&policy()).unwrap();
    record.policy_document = json!({});
    record.id = "not-a-uuid".into();
    assert_eq!(
        record.into_policy().unwrap_err(),
        PolicyRecordError::MalformedLegacy { field: "id" }
    );
    assert!(PRESENTATION_POLICY_MIGRATION.contains("ADD COLUMN IF NOT EXISTS policy_document"));
    assert!(!PRESENTATION_POLICY_MIGRATION
        .to_ascii_uppercase()
        .contains("DROP TABLE"));
}
