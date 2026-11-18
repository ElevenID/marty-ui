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
    let policies = built_in_presentation_policies(uuid::Uuid::from_u128(1));
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

#[test]
fn customer_catalog_owns_login_policies_and_preserves_the_separate_elevenid_demo() {
    let customer = uuid::Uuid::parse_str("750e8400-e29b-41d4-a716-446655440001").unwrap();
    let defaults = built_in_presentation_policies(uuid::Uuid::from_u128(1));
    let policies = built_in_presentation_policies(customer);
    assert_eq!(policies.len(), 5);
    assert_eq!(policies[0], defaults[0]);
    assert_eq!(
        policies[0].organization_id.to_string(),
        "22222222-2222-2222-2222-222222222222"
    );
    for (policy, mut expected) in policies.iter().skip(1).zip(defaults.into_iter().skip(1)) {
        expected.organization_id = customer;
        assert_eq!(policy, &expected);
        policy.validate().unwrap();
    }
}
