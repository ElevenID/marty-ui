use chrono::{TimeZone, Utc};
use marty_trust_profile::{
    ComplianceStatus, RevocationCheckMode, RevocationPolicy, TimePolicy, TrustProfile,
    TrustProfileRecord, TrustProfileRecordError, TrustProfileStatus, TrustProfileType, TrustSource,
    TrustSourceType, ValidationRules, TRUST_PROFILE_MIGRATION,
};
use serde_json::{json, Map, Value};
use uuid::Uuid;

fn timestamp() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap()
}

fn complete_profile() -> TrustProfile {
    TrustProfile {
        id: Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
        organization_id: "org-example".into(),
        name: "ICAO document trust".into(),
        description: Some("Complete persisted behavior".into()),
        status: TrustProfileStatus::Active,
        profile_type: TrustProfileType::Icao,
        compliance_status: ComplianceStatus::Compliant,
        trust_sources: vec![TrustSource {
            id: Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap(),
            name: "ICAO PKD".into(),
            source_type: TrustSourceType::PkdUrl,
            url: Some("https://pkd.example.test/feed".into()),
            certificate_pem: None,
            issuer_did: Some("did:web:issuer.example".into()),
            description: Some("Pinned native registry".into()),
            pinned_certificates: vec!["sha256:abc".into()],
            refresh_interval_hours: 12,
            enabled: true,
            registry_sync: Some(json!({"mode": "delta"})),
            registry_sync_token: Some("opaque-token".into()),
            registry_sequence: 42,
            registry_entries: Map::from_iter([("entry-1".into(), json!({"active": true}))]),
            registry_last_synced_at: Some(timestamp()),
        }],
        validation_rules: ValidationRules {
            allowed_algorithms: vec!["ES256".into()],
            min_key_size_rsa: 3_072,
            min_key_size_ec: 384,
            require_key_usage: true,
            max_chain_depth: 4,
            allow_self_signed: false,
        },
        allowed_issuers: Some(vec!["did:web:issuer.example".into()]),
        denied_issuers: Some(vec!["did:web:denied.example".into()]),
        system_issuer_overrides: Map::from_iter([("marty".into(), json!(true))]),
        compatible_compliance_codes: vec!["ICAO_9303".into()],
        verification_policy_set_id: Some("policy-set-1".into()),
        auto_generated: true,
        revocation_policy: RevocationPolicy {
            check_mode: RevocationCheckMode::SoftFail,
            check_ocsp: true,
            check_crl: false,
            check_status_list: true,
            offline_grace_period_hours: 8,
            cache_duration_hours: 2,
        },
        revocation_profile_id: Some("revocation-profile-1".into()),
        time_policy: TimePolicy {
            max_clock_skew_seconds: 120,
            credential_freshness_hours: Some(24),
            require_not_before: true,
            require_expiration: true,
        },
        supported_formats: vec!["MDOC".into(), "SD_JWT_VC".into()],
        created_at: timestamp(),
        updated_at: timestamp(),
    }
}

#[test]
fn complete_profile_round_trips_without_feature_loss() {
    let profile = complete_profile();
    let record = TrustProfileRecord::try_from(&profile).unwrap();

    assert_eq!(record.validation_rules["profile_type"], "ICAO");
    assert_eq!(
        record.validation_rules["allowed_issuers"][0],
        "did:web:issuer.example"
    );
    assert_eq!(record.trust_sources[0]["registry_sequence"], 42);
    assert_eq!(TrustProfile::try_from(record).unwrap(), profile);
}

#[test]
fn legacy_rows_receive_the_same_safe_defaults_as_the_python_adapter() {
    let record = TrustProfileRecord {
        id: "11111111-1111-4111-8111-111111111111".into(),
        organization_id: "org-example".into(),
        name: "Legacy".into(),
        description: None,
        status: "unknown-legacy-status".into(),
        trust_sources: json!([{
            "id": "",
            "name": "",
            "source_type": "",
            "issuer_did": "did:web:legacy.example",
            "registry_entries": null
        }]),
        validation_rules: json!({}),
        revocation_policy: json!({}),
        revocation_profile_id: None,
        time_policy: json!({}),
        supported_formats: json!(["UNKNOWN"]),
        created_at: timestamp(),
        updated_at: timestamp(),
    };

    let profile = TrustProfile::try_from(record).unwrap();
    assert_eq!(profile.status, TrustProfileStatus::Draft);
    assert_eq!(profile.profile_type, TrustProfileType::Custom);
    assert_eq!(profile.compliance_status, ComplianceStatus::SetupRequired);
    assert_eq!(profile.validation_rules, ValidationRules::default());
    assert_eq!(profile.revocation_policy, RevocationPolicy::default());
    assert_eq!(profile.time_policy, TimePolicy::default());
    assert_eq!(profile.supported_formats, ["MDOC"]);
    assert_eq!(profile.trust_sources[0].name, "did:web:legacy.example");
    assert_eq!(
        profile.trust_sources[0].source_type,
        TrustSourceType::TrustList
    );
    assert!(profile.trust_sources[0].registry_entries.is_empty());
}

#[test]
fn malformed_persisted_identity_and_shapes_fail_closed() {
    let mut record = TrustProfileRecord::try_from(&complete_profile()).unwrap();
    record.id = "not-a-uuid".into();
    assert_eq!(
        TrustProfile::try_from(record).unwrap_err(),
        TrustProfileRecordError::InvalidId("id")
    );

    let mut record = TrustProfileRecord::try_from(&complete_profile()).unwrap();
    record.trust_sources = Value::Object(Map::new());
    assert_eq!(
        TrustProfile::try_from(record).unwrap_err(),
        TrustProfileRecordError::InvalidField("trust_sources")
    );
}

#[test]
fn native_schema_covers_the_shared_table_contract_without_destructive_changes() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/trust-profile-service-behavior.json"
    ))
    .unwrap();
    for table in contract["persistence_tables"].as_array().unwrap() {
        let table = table.as_str().unwrap();
        assert!(
            TRUST_PROFILE_MIGRATION.contains(&format!(
                "CREATE TABLE IF NOT EXISTS trust_profile_service.{table}"
            )),
            "native schema omitted {table}"
        );
    }
    assert!(TRUST_PROFILE_MIGRATION.contains("ADD COLUMN IF NOT EXISTS accreditations"));
    assert!(!TRUST_PROFILE_MIGRATION
        .to_ascii_uppercase()
        .contains("DROP "));
    assert!(!TRUST_PROFILE_MIGRATION.contains("kms_provider TEXT"));
    assert!(!TRUST_PROFILE_MIGRATION.contains("private_jwk JSONB"));
    assert!(!TRUST_PROFILE_MIGRATION
        .contains("CREATE UNIQUE INDEX IF NOT EXISTS ix_trust_profile_issuers_profile_issuer"));
}
