use chrono::{Duration, TimeZone, Utc};
use marty_trust_profile::{
    bootstrap_system_catalog, system_frameworks, MartyBootstrapConfig,
    MemoryTrustProfileRepository, TrustProfileRepository, TrustSourceType,
};
use serde_json::Value;
use uuid::Uuid;

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 21, 0, 0, 0).unwrap()
}

fn config(did: &str) -> MartyBootstrapConfig {
    MartyBootstrapConfig {
        organization_id: "00000000-0000-0000-0000-000000000001".into(),
        issuer_did: did.into(),
        issuer_url: "https://beta.example.test".into(),
    }
}

#[test]
fn system_framework_catalog_matches_the_language_neutral_contract() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/trust-profile-service-behavior.json"
    ))
    .unwrap();
    let frameworks = system_frameworks(now());
    assert_eq!(frameworks.len(), 3);
    for framework in frameworks {
        assert_eq!(
            framework.default_formats,
            serde_json::from_value::<Vec<String>>(
                contract["system_frameworks"][&framework.code]["formats"].clone()
            )
            .unwrap()
        );
        assert_eq!(
            framework.sync_config["mode"],
            contract["system_frameworks"][&framework.code]["sync_mode"]
        );
    }
}

#[tokio::test]
async fn complete_system_catalog_preserves_existing_identity_until_operator_migration() {
    let repository = MemoryTrustProfileRepository::default();
    bootstrap_system_catalog(&repository, &config("did:web:old.example"), now())
        .await
        .unwrap();
    bootstrap_system_catalog(
        &repository,
        &config("did:web:new.example:orgs:marty"),
        now() + Duration::minutes(1),
    )
    .await
    .unwrap();

    assert_eq!(repository.frameworks().await.unwrap().len(), 3);
    let profiles = repository.profiles().await.unwrap();
    assert_eq!(profiles.len(), 3);
    for profile in &profiles {
        let managed = profile
            .trust_sources
            .iter()
            .find(|source| source.source_type == TrustSourceType::PinnedIssuer)
            .unwrap();
        assert_eq!(managed.issuer_did.as_deref(), Some("did:web:old.example"));
        assert_eq!(
            profile.revocation_profile_id.as_deref(),
            Some("70000000-0000-0000-0000-000000000001")
        );
        assert_eq!(
            repository.profile_issuers(profile.id).await.unwrap().len(),
            1
        );
    }

    let icao = repository
        .profile_by_id(Uuid::parse_str("60000000-0000-0000-0000-000000000002").unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        icao.validation_rules.extensions["allowed_vds_nc_header_prefixes"],
        serde_json::json!(["DC0"])
    );
    assert_eq!(
        icao.trust_sources[0].extensions["registry_namespace"],
        "icao_pkd"
    );
}

#[tokio::test]
async fn repeated_bootstrap_retains_pinned_keys_only_for_the_same_issuer() {
    let repository = MemoryTrustProfileRepository::default();
    let original = config("did:web:beta.example.test:orgs:marty");
    bootstrap_system_catalog(&repository, &original, now())
        .await
        .unwrap();
    let mut issuer = repository
        .issuer_entity_by_identifier(Some(&original.organization_id), &original.issuer_did)
        .await
        .unwrap()
        .unwrap();
    issuer.metadata["verification_keys"] = serde_json::json!([
        {"kty": "EC", "crv": "P-256", "kid": "governed-issuer-key"}
    ]);
    issuer.metadata["verification_key_resolution"] = serde_json::json!({
        "source": "reviewed-did-document", "content_sha256": "original-digest"
    });
    issuer.metadata["operator_note"] = serde_json::json!("preserved");
    repository.save_issuer_entity(&issuer).await.unwrap();

    bootstrap_system_catalog(&repository, &original, now() + Duration::minutes(1))
        .await
        .unwrap();
    let unchanged = repository
        .issuer_entity_by_id(issuer.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.metadata, issuer.metadata);

    let replacement = config("did:web:replacement.example.test:orgs:marty");
    bootstrap_system_catalog(&repository, &replacement, now() + Duration::minutes(2))
        .await
        .unwrap();
    let changed = repository
        .issuer_entity_by_id(issuer.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(changed.issuer_id, original.issuer_did);
    assert_eq!(changed.metadata, unchanged.metadata);
    assert_eq!(changed.metadata["operator_note"], "preserved");
}

#[tokio::test]
async fn disposable_loopback_issuer_origin_is_accepted_without_remote_http() {
    let repository = MemoryTrustProfileRepository::default();
    for issuer_url in ["http://localhost:29876", "http://localhost:1024"] {
        let mut bootstrap = config("did:web:localhost:orgs:marty");
        bootstrap.issuer_url = issuer_url.into();
        bootstrap_system_catalog(&repository, &bootstrap, now())
            .await
            .unwrap();
    }
    for issuer_url in [
        "http://gateway:8000",
        "http://beta.example.test",
        "http://localhost",
        "http://localhost:80",
        "http://localhost:29876/other",
        "http://localhost:29876?x=1",
        "http://user@localhost:29876",
    ] {
        let mut bootstrap = config("did:web:localhost:orgs:marty");
        bootstrap.issuer_url = issuer_url.into();
        assert!(
            bootstrap_system_catalog(&repository, &bootstrap, now())
                .await
                .is_err(),
            "accepted {issuer_url}"
        );
    }
}

#[tokio::test]
async fn primary_open_badge_seed_is_authorized_without_claiming_compliance_or_signatures() {
    let repository = MemoryTrustProfileRepository::default();
    bootstrap_system_catalog(
        &repository,
        &config("did:web:beta.example.test:orgs:configured"),
        now(),
    )
    .await
    .unwrap();
    let profile = repository
        .profile_by_id(Uuid::parse_str("60000000-0000-0000-0000-000000000001").unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(profile.supported_formats, ["SD_JWT_VC", "MDOC", "VC_JWT"]);
    assert_eq!(
        profile.compliance_status,
        marty_trust_profile::ComplianceStatus::SetupRequired
    );
    let relationships = repository.profile_issuers(profile.id).await.unwrap();
    assert_eq!(relationships.len(), 1);
    assert_eq!(
        relationships[0].metadata["credential_template_ids"],
        serde_json::json!([
            "50000000-0000-0000-0000-000000000010",
            "50000000-0000-0000-0000-000000000030",
            "50000000-0000-0000-0000-000000000040"
        ])
    );
}

#[tokio::test]
async fn repeated_bootstrap_preserves_operator_relationship_authorizations() {
    let repository = MemoryTrustProfileRepository::default();
    let selected = config("did:web:beta.example.test:orgs:configured");
    bootstrap_system_catalog(&repository, &selected, now())
        .await
        .unwrap();
    let profile_id = Uuid::parse_str("60000000-0000-0000-0000-000000000001").unwrap();
    let mut relationship = repository
        .profile_issuers(profile_id)
        .await
        .unwrap()
        .remove(0);
    relationship.metadata = serde_json::json!({"credential_template_ids": ["operator-reviewed-version"],
        "operator_review": "bound-to-current-issuer"});
    repository.save_profile_issuer(&relationship).await.unwrap();
    bootstrap_system_catalog(&repository, &selected, now() + Duration::minutes(1))
        .await
        .unwrap();
    assert_eq!(
        repository.profile_issuers(profile_id).await.unwrap()[0].metadata,
        relationship.metadata
    );
}

#[tokio::test]
async fn issuer_conflict_still_seeds_missing_frameworks_without_rewriting_marty_policy() {
    let original = MemoryTrustProfileRepository::default();
    let legacy = config("did:web:old.example:orgs:legacy");
    bootstrap_system_catalog(&original, &legacy, now())
        .await
        .unwrap();
    let repository = MemoryTrustProfileRepository::default();
    let issuer_id = Uuid::parse_str("60000000-0000-0000-0000-000000000012").unwrap();
    let issuer = original
        .issuer_entity_by_id(issuer_id)
        .await
        .unwrap()
        .unwrap();
    repository.save_issuer_entity(&issuer).await.unwrap();
    let profiles = original.profiles().await.unwrap();
    for profile in &profiles {
        repository.save_profile(profile, None).await.unwrap();
        for relationship in original.profile_issuers(profile.id).await.unwrap() {
            repository.save_profile_issuer(&relationship).await.unwrap();
        }
    }
    assert!(repository.frameworks().await.unwrap().is_empty());
    bootstrap_system_catalog(
        &repository,
        &config("did:web:new.example:orgs:configured"),
        now() + Duration::minutes(1),
    )
    .await
    .unwrap();
    assert_eq!(repository.frameworks().await.unwrap().len(), 3);
    assert_eq!(
        serde_json::to_value(
            repository
                .issuer_entity_by_id(issuer_id)
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        serde_json::to_value(&issuer).unwrap()
    );
    for profile in profiles {
        assert_eq!(
            serde_json::to_value(repository.profile_by_id(profile.id).await.unwrap().unwrap())
                .unwrap(),
            serde_json::to_value(&profile).unwrap()
        );
        assert_eq!(
            serde_json::to_value(repository.profile_issuers(profile.id).await.unwrap()).unwrap(),
            serde_json::to_value(original.profile_issuers(profile.id).await.unwrap()).unwrap()
        );
    }
}

#[tokio::test]
async fn same_issuer_bootstrap_preserves_full_operator_profile() {
    let repository = MemoryTrustProfileRepository::default();
    let selected = config("did:web:beta.example.test:orgs:configured");
    bootstrap_system_catalog(&repository, &selected, now())
        .await
        .unwrap();
    let profile_id = Uuid::parse_str("60000000-0000-0000-0000-000000000001").unwrap();
    let mut profile = repository.profile_by_id(profile_id).await.unwrap().unwrap();
    profile.compliance_status = marty_trust_profile::ComplianceStatus::Compliant;
    profile.revocation_profile_id = Some("70000000-0000-0000-0000-000000000099".into());
    let pin = profile
        .trust_sources
        .iter_mut()
        .find(|source| source.source_type == TrustSourceType::PinnedIssuer)
        .unwrap();
    pin.extensions.insert(
        "verification_method_ids".into(),
        serde_json::json!(["did:web:beta.example.test:orgs:configured#operator-reviewed-key"]),
    );
    pin.pinned_certificates = vec!["operator-reviewed-certificate-bytes".into()];
    repository.save_profile(&profile, None).await.unwrap();
    let expected = serde_json::to_value(&profile).unwrap();
    bootstrap_system_catalog(&repository, &selected, now() + Duration::minutes(1))
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(repository.profile_by_id(profile_id).await.unwrap().unwrap()).unwrap(),
        expected
    );
}
