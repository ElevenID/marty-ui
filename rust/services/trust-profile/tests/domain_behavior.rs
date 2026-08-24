use std::collections::BTreeMap;

use marty_trust_profile::{
    CascadeRevocationPolicy, ComplianceStatus, IssuerEntityComplianceStatus, IssuerEntityType,
    RegistryImportType, RegistryOperation, RegistrySource, RevocationCheckMode, TrustAnchorType,
    TrustProfileStatus, TrustProfileType, TrustRelationshipStatus, TrustSourceType,
    HTTP_OPERATIONS,
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
    assert_eq!(
        serde_json::to_value(values(&[
            RegistryImportType::IcaoPkd,
            RegistryImportType::EuTrustList,
            RegistryImportType::Aamva,
        ]))
        .unwrap(),
        contract["registry_import_storage_capabilities"]["registry_types"]
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

#[test]
fn issuer_did_key_resolution_contract_is_native_pinned_and_fail_closed() {
    let contract = contract();
    assert_eq!(
        contract["native_owner"]["issuer_key_resolver"],
        "marty_didcomm::DidResolver"
    );
    for invariant in [
        "resolve_when_did_has_no_pinned_verification_keys",
        "resolve_keyless_relationships_before_internal_decision",
        "pin_only_assertion_method_public_jwks",
        "canonicalize_pinned_jwk_kid_to_assertion_method_id",
        "preserve_explicitly_pinned_public_jwks",
        "persist_resolution_source_timestamp_and_sha256",
        "configured_internal_resolver_precedes_public_egress",
        "public_egress_disabled_by_default",
        "public_egress_requires_explicit_exact_host_allowlist",
        "reject_private_jwk_members",
        "reject_empty_ambiguous_or_foreign_controller_assertion_methods",
        "resolution_failure_prevents_issuer_creation",
    ] {
        assert_eq!(
            contract["issuer_did_key_resolution"][invariant],
            Value::Bool(true),
            "missing DID key resolution invariant {invariant}"
        );
    }
}
