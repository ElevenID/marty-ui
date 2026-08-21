use std::collections::BTreeMap;

use marty_trust_profile::{
    CascadeRevocationPolicy, ComplianceStatus, IssuerEntityComplianceStatus, IssuerEntityType,
    RegistryOperation, RegistrySource, RevocationCheckMode, TrustAnchorType, TrustProfileStatus,
    TrustProfileType, TrustRelationshipStatus, TrustSourceType, HTTP_OPERATIONS,
};
use serde::Serialize;
use serde_json::Value;

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/trust-profile-service-behavior.json"
    ))
    .unwrap()
}

fn values<T: Serialize + Copy>(values: &[T]) -> Vec<Value> {
    values
        .iter()
        .map(|value| serde_json::to_value(value).unwrap())
        .collect()
}

#[test]
fn complete_surface_and_domain_inventory_match_the_shared_contract() {
    let contract = contract();
    let actual_operations = HTTP_OPERATIONS
        .iter()
        .map(|(method, path)| [*method, *path])
        .collect::<Vec<_>>();
    assert_eq!(
        serde_json::to_value(actual_operations).unwrap(),
        contract["http_operations"]
    );

    let actual = BTreeMap::from([
        (
            "trust_profile_status",
            values(&[
                TrustProfileStatus::Draft,
                TrustProfileStatus::Active,
                TrustProfileStatus::Suspended,
                TrustProfileStatus::Archived,
            ]),
        ),
        (
            "trust_profile_type",
            values(&[
                TrustProfileType::Icao,
                TrustProfileType::Aamva,
                TrustProfileType::Eudi,
                TrustProfileType::Custom,
            ]),
        ),
        (
            "compliance_status",
            values(&[
                ComplianceStatus::Compliant,
                ComplianceStatus::NeedsAttention,
                ComplianceStatus::SetupRequired,
            ]),
        ),
        (
            "trust_source_type",
            values(&[
                TrustSourceType::TrustList,
                TrustSourceType::PinnedIssuer,
                TrustSourceType::RootCa,
                TrustSourceType::PkdUrl,
            ]),
        ),
        (
            "revocation_check_mode",
            values(&[
                RevocationCheckMode::HardFail,
                RevocationCheckMode::SoftFail,
                RevocationCheckMode::Skip,
            ]),
        ),
        (
            "issuer_entity_type",
            values(&[
                IssuerEntityType::Organization,
                IssuerEntityType::Government,
                IssuerEntityType::Device,
            ]),
        ),
        (
            "issuer_compliance_status",
            values(&[
                IssuerEntityComplianceStatus::Accredited,
                IssuerEntityComplianceStatus::Compliant,
                IssuerEntityComplianceStatus::Suspended,
                IssuerEntityComplianceStatus::Revoked,
            ]),
        ),
        (
            "relationship_status",
            values(&[
                TrustRelationshipStatus::Trusted,
                TrustRelationshipStatus::Denied,
                TrustRelationshipStatus::UnderReview,
            ]),
        ),
        (
            "cascade_revocation_policy",
            values(&[
                CascadeRevocationPolicy::AutoCascade,
                CascadeRevocationPolicy::Manual,
                CascadeRevocationPolicy::NotifyOnly,
            ]),
        ),
        (
            "trust_anchor_type",
            values(&[TrustAnchorType::Csca, TrustAnchorType::Dsc]),
        ),
        (
            "registry_operation",
            values(&[RegistryOperation::Add, RegistryOperation::Remove]),
        ),
        (
            "registry_source",
            values(&[
                RegistrySource::IcaoPkd,
                RegistrySource::Aamva,
                RegistrySource::EudiLotl,
                RegistrySource::Manual,
            ]),
        ),
    ]);
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        contract["domain_enums"]
    );
}

#[test]
fn trust_registry_behavior_is_owned_by_the_existing_marty_core_kernel() {
    let contract = contract();
    assert_eq!(
        marty_verification::trust_sync::SYNC_PROTOCOL,
        contract["registry_sync"]["protocol"]
    );
    assert_eq!(
        marty_verification::trust_sync::MAX_RESPONSE_BYTES,
        contract["registry_sync"]["max_response_bytes"]
            .as_u64()
            .unwrap() as usize
    );
    assert_eq!(
        marty_verification::trust_sync::MAX_PAGES,
        contract["registry_sync"]["max_pages"].as_u64().unwrap() as usize
    );
    let fixture: Value =
        serde_json::from_str(marty_verification::trust_sync::behavior_fixture_json()).unwrap();
    assert_eq!(
        fixture["catalog_cases"][0]["expected_types"],
        serde_json::json!(["ICAO_PKD", "EU_TRUST_LIST", "AAMVA"])
    );
    for required in [
        "import_cases",
        "public_sync_query_cases",
        "schedule_cases",
        "url_cases",
        "destination_cases",
        "allowlist_cases",
        "request_cases",
        "evaluation_cases",
    ] {
        assert!(fixture[required].is_array(), "missing shared {required}");
    }
}
