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
async fn complete_system_catalog_is_idempotent_and_repairs_managed_issuer_derivation() {
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
        assert_eq!(
            managed.issuer_did.as_deref(),
            Some("did:web:new.example:orgs:marty")
        );
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
    assert_eq!(changed.issuer_id, replacement.issuer_did);
    assert_eq!(changed.metadata["verification_keys"], serde_json::json!([]));
    assert!(changed
        .metadata
        .get("verification_key_resolution")
        .is_none());
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
