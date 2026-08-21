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
