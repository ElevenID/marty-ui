use marty_presentation_policy::built_in_presentation_policies;
use serde::Deserialize;

#[derive(Deserialize)]
struct Contract {
    policies: Vec<ExpectedPolicy>,
}

#[derive(Deserialize)]
struct ExpectedPolicy {
    id: String,
    organization_id: String,
    name: String,
    format: String,
    claim: String,
    version: u32,
    trust_profile_id: Option<String>,
    require_not_revoked: Option<bool>,
}

#[test]
fn native_catalog_preserves_every_final_alembic_seed_and_repair_behavior() {
    let contract: Contract = serde_json::from_str(include_str!(
        "../../../../contracts/presentation-policy-catalog-behavior.json"
    ))
    .unwrap();
    let policies = built_in_presentation_policies();
    assert_eq!(policies.len(), contract.policies.len());
    for expected in contract.policies {
        let policy = policies
            .iter()
            .find(|policy| policy.id.to_string() == expected.id)
            .unwrap();
        assert_eq!(policy.organization_id.to_string(), expected.organization_id);
        assert_eq!(policy.name, expected.name);
        assert_eq!(policy.version, expected.version);
        assert_eq!(policy.credential_requirements.len(), 1);
        let requirement = &policy.credential_requirements[0];
        assert_eq!(requirement.credential_payload_format, expected.format);
        assert_eq!(requirement.requested_claims.len(), 1);
        assert_eq!(requirement.requested_claims[0].claim_name, expected.claim);
        assert_eq!(
            requirement.trust_profile_id.map(|value| value.to_string()),
            expected.trust_profile_id
        );
        assert_eq!(
            policy
                .freshness
                .as_ref()
                .map(|freshness| freshness.require_not_revoked),
            expected.require_not_revoked
        );
        policy.validate().unwrap();
    }
}
