use chrono::{Duration, TimeZone, Utc};
use marty_trust_profile::{
    CascadeRevocationPolicy, ComplianceStatus, IssuerEntity, IssuerEntityComplianceStatus,
    IssuerEntityType, MemoryTrustProfileRepository, RegistryOperation, RegistrySource,
    RevocationPolicy, TimePolicy, TrustAnchorType, TrustFramework, TrustProfile,
    TrustProfileIssuer, TrustProfileRepository, TrustProfileStatus, TrustProfileType,
    TrustRelationshipStatus, ValidationRules,
};
use serde_json::{json, Map, Value};
use uuid::Uuid;

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/trust-profile-service-behavior.json"
    ))
    .unwrap()
}

fn id(value: &str) -> Uuid {
    Uuid::parse_str(value).unwrap()
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 21, 0, 0, 0).unwrap()
}

fn framework(code: &str, system: bool) -> TrustFramework {
    TrustFramework {
        id: Uuid::new_v4(),
        code: code.into(),
        display_name: code.into(),
        description: None,
        pkd_endpoints: Vec::new(),
        default_algorithms: vec!["ES256".into()],
        default_formats: vec!["MDOC".into()],
        validation_ruleset: json!({}),
        sync_config: json!({}),
        is_system: system,
        created_at: now(),
        updated_at: now(),
    }
}

fn profile(profile_id: Uuid) -> TrustProfile {
    TrustProfile {
        id: profile_id,
        organization_id: "org-a".into(),
        name: "Profile".into(),
        description: None,
        status: TrustProfileStatus::Draft,
        profile_type: TrustProfileType::Custom,
        compliance_status: ComplianceStatus::SetupRequired,
        trust_sources: Vec::new(),
        validation_rules: ValidationRules::default(),
        allowed_issuers: Some(Vec::new()),
        denied_issuers: None,
        system_issuer_overrides: Map::new(),
        compatible_compliance_codes: Vec::new(),
        verification_policy_set_id: None,
        auto_generated: false,
        revocation_policy: RevocationPolicy::default(),
        revocation_profile_id: None,
        time_policy: TimePolicy::default(),
        supported_formats: vec!["MDOC".into()],
        created_at: now(),
        updated_at: now(),
    }
}

fn issuer(value: &str, organization_id: Option<&str>, name: &str, system: bool) -> IssuerEntity {
    IssuerEntity {
        id: id(value),
        organization_id: organization_id.map(str::to_owned),
        issuer_id: format!("did:web:{value}.example"),
        issuer_type: IssuerEntityType::Organization,
        display_name: name.into(),
        description: None,
        is_system_issuer: system,
        compliance_status: IssuerEntityComplianceStatus::Compliant,
        accreditation_body: None,
        accreditations: Vec::new(),
        accreditation_date: None,
        valid_from: now(),
        valid_until: None,
        trust_anchor_id: None,
        revoked_at: None,
        revocation_reason: None,
        revoked_by: None,
        metadata: json!({}),
        created_at: now(),
        updated_at: now(),
    }
}

fn link(profile_id: Uuid, issuer_id: Uuid) -> TrustProfileIssuer {
    TrustProfileIssuer {
        id: Uuid::new_v4(),
        trust_profile_id: profile_id,
        issuer_id,
        trust_level: 100,
        relationship_status: TrustRelationshipStatus::Trusted,
        cascade_revocation_policy: CascadeRevocationPolicy::NotifyOnly,
        metadata: json!({}),
        created_at: now(),
        updated_at: now(),
    }
}

#[tokio::test]
async fn ordering_registry_filters_and_status_match_the_shared_vectors() {
    let expected = contract()["repository_cases"].clone();
    let repository = MemoryTrustProfileRepository::default();
    for item in [
        framework("CUSTOM", false),
        framework("ICAO", true),
        framework("AAMVA", true),
    ] {
        repository.save_framework(&item).await.unwrap();
    }
    assert_eq!(
        repository
            .frameworks()
            .await
            .unwrap()
            .iter()
            .map(|item| item.code.as_str())
            .collect::<Vec<_>>(),
        expected["framework_order"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap())
            .collect::<Vec<_>>()
    );

    let entries = [
        (
            "11111111-1111-4111-8111-111111111111",
            TrustAnchorType::Csca,
            1,
            true,
        ),
        (
            "22222222-2222-4222-8222-222222222222",
            TrustAnchorType::Csca,
            2,
            false,
        ),
        (
            "33333333-3333-4333-8333-333333333333",
            TrustAnchorType::Dsc,
            3,
            true,
        ),
    ];
    for (entry_id, anchor_type, sequence, current) in entries {
        repository
            .save_registry_entry(&marty_trust_profile::TrustRegistryEntry {
                id: id(entry_id),
                anchor_type,
                operation: RegistryOperation::Add,
                country_code: "US".into(),
                certificate_pem: None,
                subject_key_id: None,
                not_before: None,
                not_after: None,
                source: RegistrySource::Manual,
                framework_code: None,
                sequence,
                is_current: current,
                created_at: now(),
                updated_at: now(),
            })
            .await
            .unwrap();
    }
    let selected = repository
        .registry_entries(None, Some("us"), true, Some(1))
        .await
        .unwrap();
    assert_eq!(
        selected
            .iter()
            .map(|entry| entry.id.to_string())
            .collect::<Vec<_>>(),
        serde_json::from_value::<Vec<String>>(
            expected["registry"]["current_country_after_sequence"].clone()
        )
        .unwrap()
    );
    assert_eq!(
        serde_json::to_value(repository.registry_status().await.unwrap()).unwrap(),
        expected["registry"]["status"]
    );
}

#[tokio::test]
async fn visibility_optimistic_writes_and_cascades_match_the_shared_vectors() {
    let expected = contract()["repository_cases"].clone();
    let repository = MemoryTrustProfileRepository::default();
    let profile_id = id("44444444-4444-4444-8444-444444444444");
    let first_profile = profile(profile_id);
    assert!(repository.save_profile(&first_profile, None).await.unwrap());
    assert_eq!(
        repository
            .save_profile(&first_profile, Some(now() - Duration::seconds(1)))
            .await
            .unwrap(),
        expected["optimistic_update_conflict"].as_bool().unwrap()
    );

    let issuers = [
        issuer(
            "55555555-5555-4555-8555-555555555555",
            Some("org-a"),
            "A",
            false,
        ),
        issuer("66666666-6666-4666-8666-666666666666", None, "B", false),
        issuer(
            "77777777-7777-4777-8777-777777777777",
            Some("org-b"),
            "C",
            true,
        ),
        issuer(
            "88888888-8888-4888-8888-888888888888",
            Some("org-b"),
            "D",
            false,
        ),
    ];
    for item in &issuers {
        repository.save_issuer_entity(item).await.unwrap();
    }
    assert_eq!(
        repository
            .issuer_entities(Some("org-a"))
            .await
            .unwrap()
            .iter()
            .map(|item| item.id.to_string())
            .collect::<Vec<_>>(),
        serde_json::from_value::<Vec<String>>(expected["organization_visibility"].clone()).unwrap()
    );

    let first_link = link(profile_id, issuers[0].id);
    repository.save_profile_issuer(&first_link).await.unwrap();
    repository.delete_profile(profile_id).await.unwrap();
    assert_eq!(
        repository
            .profile_issuer_by_id(first_link.id)
            .await
            .unwrap()
            .is_none(),
        expected["profile_delete_cascades_relationships"]
            .as_bool()
            .unwrap()
    );

    let second_profile = profile(Uuid::new_v4());
    repository
        .save_profile(&second_profile, None)
        .await
        .unwrap();
    let second_link = link(second_profile.id, issuers[0].id);
    repository.save_profile_issuer(&second_link).await.unwrap();
    repository
        .delete_issuer_entity(issuers[0].id)
        .await
        .unwrap();
    assert_eq!(
        repository
            .profile_issuer_by_id(second_link.id)
            .await
            .unwrap()
            .is_none(),
        expected["issuer_delete_cascades_relationships"]
            .as_bool()
            .unwrap()
    );
}
