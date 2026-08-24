use std::sync::Arc;

use async_trait::async_trait;
use chrono::{Duration, TimeZone, Utc};
use marty_trust_profile::{
    CascadeRevocationPolicy, Change, ComplianceStatus, CreateProfileInput, IssuerEntity,
    IssuerEntityComplianceStatus, IssuerEntityPatch, IssuerEntityType, IssuerKeyResolution,
    IssuerKeyResolutionError, IssuerKeyResolver, MemoryTrustProfileRepository,
    OrganizationProfilePatch, OrganizationTrustProfile, ProfilePatch, RegistryImportSource,
    RegistryImportType, RegistryImportedIssuer, RevocationPolicy, TimePolicy,
    TrustAuthorizationError, TrustFramework, TrustProfile, TrustProfileApplication,
    TrustProfileApplicationError, TrustProfileControlPlane, TrustProfileIssuer,
    TrustProfileRepository, TrustProfileStatus, TrustProfileType, TrustRelationshipStatus,
    TrustSource, TrustSourceType, ValidationRules,
};
use serde_json::{json, Map};
use uuid::Uuid;

struct AllowAll;

#[async_trait]
impl TrustProfileControlPlane for AllowAll {
    async fn require_permission(
        &self,
        _user_id: &str,
        _organization_id: &str,
        _resource: &'static str,
        _action: &'static str,
    ) -> Result<(), TrustAuthorizationError> {
        Ok(())
    }
}

struct FixedIssuerKeyResolver;

#[async_trait]
impl IssuerKeyResolver for FixedIssuerKeyResolver {
    async fn resolve(&self, _did: &str) -> Result<IssuerKeyResolution, IssuerKeyResolutionError> {
        Ok(IssuerKeyResolution {
            verification_keys: vec![json!({
                "kty": "EC",
                "crv": "P-256",
                "x": "public-x",
                "y": "public-y",
                "kid": "issuer-key"
            })],
            source: "configured_internal_resolver".into(),
            retrieved_at: "2026-08-21T00:00:00Z".into(),
            content_sha256: "a".repeat(64),
        })
    }
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 21, 0, 0, 0).unwrap()
}

fn profile() -> TrustProfile {
    TrustProfile {
        id: Uuid::new_v4(),
        organization_id: "org-a".into(),
        name: "Trust".into(),
        description: None,
        status: TrustProfileStatus::Draft,
        profile_type: TrustProfileType::Custom,
        compliance_status: ComplianceStatus::SetupRequired,
        trust_sources: Vec::new(),
        validation_rules: ValidationRules::default(),
        allowed_issuers: None,
        denied_issuers: None,
        system_issuer_overrides: Map::new(),
        compatible_compliance_codes: Vec::new(),
        verification_policy_set_id: None,
        auto_generated: false,
        revocation_policy: RevocationPolicy::default(),
        revocation_profile_id: None,
        time_policy: TimePolicy::default(),
        supported_formats: vec!["SD_JWT_VC".into(), "MDOC".into()],
        created_at: now(),
        updated_at: now(),
    }
}

fn registry_source(last_synced_at: Option<chrono::DateTime<Utc>>) -> TrustSource {
    TrustSource {
        id: Uuid::new_v4(),
        name: "Registry".into(),
        source_type: TrustSourceType::TrustList,
        url: Some("https://registry.example.test/feed".into()),
        certificate_pem: None,
        issuer_did: None,
        description: None,
        pinned_certificates: Vec::new(),
        refresh_interval_hours: 24,
        enabled: true,
        registry_sync: Some(json!({
            "protocol": "MARTY_TRUST_REGISTRY_SYNC_V1",
            "refresh_interval_hours": 24
        })),
        registry_sync_token: Some("token".into()),
        registry_sequence: 1,
        registry_entries: Map::new(),
        registry_last_synced_at: last_synced_at,
        extensions: Map::new(),
    }
}

fn issuer(organization_id: Option<&str>, system: bool) -> IssuerEntity {
    IssuerEntity {
        id: Uuid::new_v4(),
        organization_id: organization_id.map(str::to_owned),
        issuer_id: "did:web:issuer.example".into(),
        issuer_type: IssuerEntityType::Organization,
        display_name: "Issuer".into(),
        description: None,
        is_system_issuer: system,
        compliance_status: IssuerEntityComplianceStatus::Compliant,
        accreditation_body: None,
        accreditations: vec![" ISO27001 ".into()],
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

fn harness() -> (Arc<MemoryTrustProfileRepository>, TrustProfileApplication) {
    let repository = Arc::new(MemoryTrustProfileRepository::default());
    let application = TrustProfileApplication::new(repository.clone(), Arc::new(AllowAll));
    (repository, application)
}

#[tokio::test]
async fn did_issuer_creation_pins_native_assertion_keys_and_resolution_provenance() {
    let repository = Arc::new(MemoryTrustProfileRepository::default());
    let application = TrustProfileApplication::new(repository, Arc::new(AllowAll))
        .with_issuer_key_resolver(Arc::new(FixedIssuerKeyResolver));

    let created = application
        .create_issuer_entity("user-a", issuer(Some("org-a"), false))
        .await
        .unwrap();

    assert_eq!(
        created.metadata["verification_keys"],
        json!([{
            "kty": "EC",
            "crv": "P-256",
            "x": "public-x",
            "y": "public-y",
            "kid": "issuer-key"
        }])
    );
    assert_eq!(
        created.metadata["verification_key_resolution"]["source"],
        "configured_internal_resolver"
    );
    assert_eq!(
        created.metadata["verification_key_resolution"]["content_sha256"],
        "a".repeat(64)
    );
}

#[tokio::test]
async fn create_and_source_removal_default_to_deny_all_without_losing_explicit_intent() {
    let (_, application) = harness();
    let created = application
        .create_profile(
            "user-a",
            CreateProfileInput {
                profile: profile(),
                allowed_issuers_was_provided: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(created.allowed_issuers, Some(Vec::new()));

    let mut with_registry = profile();
    with_registry.trust_sources = vec![registry_source(None)];
    let created = application
        .create_profile(
            "user-a",
            CreateProfileInput {
                profile: with_registry,
                allowed_issuers_was_provided: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(created.allowed_issuers, None);

    let updated = application
        .update_profile(
            "user-a",
            created.id,
            ProfilePatch {
                trust_sources: Change::Set(Vec::new()),
                ..ProfilePatch::default()
            },
            now() + Duration::minutes(1),
        )
        .await
        .unwrap();
    assert_eq!(updated.allowed_issuers, Some(Vec::new()));
}

#[tokio::test]
async fn invalid_crypto_configuration_and_registry_activation_fail_closed() {
    let (_, application) = harness();
    let mut invalid = profile();
    invalid.validation_rules.allowed_algorithms = vec!["none".into()];
    assert_eq!(
        application
            .create_profile(
                "user-a",
                CreateProfileInput {
                    profile: invalid,
                    allowed_issuers_was_provided: false,
                },
            )
            .await
            .unwrap_err(),
        TrustProfileApplicationError::Invalid("allowed_algorithms")
    );

    let mut never_synced = profile();
    never_synced.trust_sources = vec![registry_source(None)];
    let never_synced = application
        .create_profile(
            "user-a",
            CreateProfileInput {
                profile: never_synced,
                allowed_issuers_was_provided: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        application
            .activate_profile("user-a", never_synced.id, now())
            .await
            .unwrap_err(),
        TrustProfileApplicationError::Conflict("registry_never_synchronized")
    );

    let mut fresh = profile();
    fresh.trust_sources = vec![registry_source(Some(now() - Duration::hours(1)))];
    let fresh = application
        .create_profile(
            "user-a",
            CreateProfileInput {
                profile: fresh,
                allowed_issuers_was_provided: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        application
            .activate_profile("user-a", fresh.id, now())
            .await
            .unwrap()
            .status,
        TrustProfileStatus::Active
    );
}

#[tokio::test]
async fn issuer_identity_custody_and_terminal_revocation_rules_are_native() {
    let (_, application) = harness();
    let created = application
        .create_issuer_entity("user-a", issuer(Some("org-a"), false))
        .await
        .unwrap();
    assert_eq!(created.accreditations, ["ISO27001"]);

    let duplicate = issuer(Some("org-a"), false);
    assert_eq!(
        application
            .create_issuer_entity("user-a", duplicate)
            .await
            .unwrap_err(),
        TrustProfileApplicationError::Conflict("issuer_identifier_exists")
    );

    let revoked = application
        .update_issuer_entity(
            "user-a",
            "org-a",
            created.id,
            IssuerEntityPatch {
                compliance_status: Change::Set(IssuerEntityComplianceStatus::Revoked),
                revocation_reason: Some("compromised".into()),
                ..IssuerEntityPatch::default()
            },
            now() + Duration::minutes(1),
        )
        .await
        .unwrap();
    assert_eq!(revoked.revoked_by.as_deref(), Some("user-a"));
    assert_eq!(
        application
            .update_issuer_entity(
                "user-a",
                "org-a",
                revoked.id,
                IssuerEntityPatch {
                    compliance_status: Change::Set(IssuerEntityComplianceStatus::Compliant),
                    ..IssuerEntityPatch::default()
                },
                now() + Duration::minutes(2),
            )
            .await
            .unwrap_err(),
        TrustProfileApplicationError::Domain(
            marty_trust_profile::TrustDomainError::RevokedIssuerTerminal
        )
    );

    let mut private = issuer(Some("org-b"), false);
    private.metadata = json!({"jwk": {"kty": "EC", "d": "private"}});
    assert!(matches!(
        application.create_issuer_entity("user-a", private).await,
        Err(TrustProfileApplicationError::Domain(
            marty_trust_profile::TrustDomainError::PrivateCustodyMetadata(_)
        ))
    ));
}

#[tokio::test]
async fn tenant_safe_relationships_block_profile_deletion_until_unlinked() {
    let (repository, application) = harness();
    let created_profile = application
        .create_profile(
            "user-a",
            CreateProfileInput {
                profile: profile(),
                allowed_issuers_was_provided: false,
            },
        )
        .await
        .unwrap();
    let created_issuer = application
        .create_issuer_entity("user-a", issuer(Some("org-a"), false))
        .await
        .unwrap();
    let relationship = TrustProfileIssuer {
        id: Uuid::new_v4(),
        trust_profile_id: created_profile.id,
        issuer_id: created_issuer.id,
        trust_level: 100,
        relationship_status: TrustRelationshipStatus::Trusted,
        cascade_revocation_policy: CascadeRevocationPolicy::NotifyOnly,
        metadata: json!({}),
        created_at: now(),
        updated_at: now(),
    };
    let relationship = application
        .add_relationship("user-a", relationship)
        .await
        .unwrap();
    assert_eq!(
        application
            .delete_profile("user-a", created_profile.id)
            .await
            .unwrap_err(),
        TrustProfileApplicationError::Conflict("profile_has_trusted_issuers")
    );
    application
        .delete_relationship("user-a", created_profile.id, relationship.id)
        .await
        .unwrap();
    application
        .delete_profile("user-a", created_profile.id)
        .await
        .unwrap();
    assert!(repository
        .profile_by_id(created_profile.id)
        .await
        .unwrap()
        .is_none());

    let mut other_tenant = issuer(Some("org-b"), false);
    other_tenant.issuer_id = "did:web:other.example".into();
    repository.save_issuer_entity(&other_tenant).await.unwrap();
    let local_profile = application
        .create_profile(
            "user-a",
            CreateProfileInput {
                profile: profile(),
                allowed_issuers_was_provided: false,
            },
        )
        .await
        .unwrap();
    let cross_tenant = TrustProfileIssuer {
        id: Uuid::new_v4(),
        trust_profile_id: local_profile.id,
        issuer_id: other_tenant.id,
        trust_level: 100,
        relationship_status: TrustRelationshipStatus::Trusted,
        cascade_revocation_policy: CascadeRevocationPolicy::NotifyOnly,
        metadata: json!({}),
        created_at: now(),
        updated_at: now(),
    };
    assert!(matches!(
        application.add_relationship("user-a", cross_tenant).await,
        Err(TrustProfileApplicationError::NotFound("issuer_entity"))
    ));
}

#[tokio::test]
async fn dormant_registry_imports_preserve_full_features_and_reject_private_keys() {
    let (repository, application) = harness();
    let profile = application
        .create_profile(
            "user-a",
            CreateProfileInput {
                profile: profile(),
                allowed_issuers_was_provided: false,
            },
        )
        .await
        .unwrap();
    let source = application
        .save_registry_import_source(
            "user-a",
            RegistryImportSource {
                id: Uuid::new_v4(),
                trust_profile_id: profile.id,
                registry_type: RegistryImportType::IcaoPkd,
                registry_name: "ICAO PKD".into(),
                registry_url: Some("https://registry.example.test/pkd".into()),
                enabled: true,
                sync_enabled: true,
                last_synced_at: None,
                next_sync_at: Some(now()),
                sync_interval_hours: 24,
                credential_format_filter: vec!["MDOC".into()],
                metadata: json!({"mode": "delta"}),
                created_at: now(),
                updated_at: now(),
            },
        )
        .await
        .unwrap();
    let imported = RegistryImportedIssuer {
        id: Uuid::new_v4(),
        registry_source_id: source.id,
        trust_profile_id: profile.id,
        issuer_did: "did:web:imported.example".into(),
        issuer_name: Some("Imported issuer".into()),
        country_code: Some("US".into()),
        issuer_type: Some("MDL_ISSUER".into()),
        verification_keys: vec![json!({"kty": "EC", "crv": "P-256", "x": "x", "y": "y"})],
        credential_templates: vec![json!({"doctype": "org.iso.18013.5.1.mDL"})],
        status: "active".into(),
        imported_at: now(),
        valid_from: Some(now()),
        valid_until: None,
        created_at: now(),
        updated_at: now(),
    };
    application
        .save_registry_imported_issuer("user-a", imported.clone())
        .await
        .unwrap();

    let mut private = imported;
    private.id = Uuid::new_v4();
    private.verification_keys = vec![json!({"kty": "EC", "d": "private"})];
    assert!(matches!(
        application
            .save_registry_imported_issuer("user-a", private)
            .await,
        Err(TrustProfileApplicationError::Domain(
            marty_trust_profile::TrustDomainError::PrivateCustodyMetadata(_)
        ))
    ));

    application
        .delete_registry_import_source("user-a", source.id)
        .await
        .unwrap();
    assert!(repository
        .registry_imported_issuers(profile.id, None)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn organization_profiles_frameworks_and_owner_reads_use_the_same_native_application() {
    let (repository, application) = harness();
    let framework = TrustFramework {
        id: Uuid::new_v4(),
        code: "CUSTOM".into(),
        display_name: "Custom".into(),
        description: None,
        pkd_endpoints: Vec::new(),
        default_algorithms: vec!["ES256".into()],
        default_formats: vec!["MDOC".into()],
        validation_ruleset: json!({}),
        sync_config: json!({}),
        is_system: false,
        created_at: now(),
        updated_at: now(),
    };
    repository.save_framework(&framework).await.unwrap();
    let organization_profile = application
        .create_organization_profile(
            "user-a",
            OrganizationTrustProfile {
                id: Uuid::new_v4(),
                organization_id: "org-a".into(),
                framework_id: framework.id,
                name: "Regional trust".into(),
                display_name: None,
                description: None,
                enabled: true,
                use_case_tags: vec!["travel".into()],
                compliance_status: ComplianceStatus::SetupRequired,
                auto_generated: false,
                revocation_policy: None,
                time_policy: None,
                allowed_algorithms: Some(vec!["ES256".into()]),
                allowed_formats: Some(vec!["MDOC".into()]),
                allowed_issuers: None,
                denied_issuers: None,
                jurisdiction_filter: Some(vec!["us-ca".into()]),
                metadata: json!({"public": true}),
                created_at: now(),
                updated_at: now(),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        organization_profile.jurisdiction_filter,
        Some(vec!["US-CA".into()])
    );
    assert_eq!(
        application.framework(framework.id).await.unwrap(),
        framework
    );
    let profiles = application
        .organization_profiles("user-a", "org-a")
        .await
        .unwrap();
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0], organization_profile);
    assert!(matches!(
        application
            .update_organization_profile(
                "user-a",
                "org-a",
                organization_profile.id,
                OrganizationProfilePatch {
                    metadata: Change::Set(json!({"kms_provider": "vault"})),
                    ..OrganizationProfilePatch::default()
                },
                now() + Duration::minutes(1),
            )
            .await,
        Err(TrustProfileApplicationError::Domain(
            marty_trust_profile::TrustDomainError::PrivateCustodyMetadata(_)
        ))
    ));

    let profile = application
        .create_profile(
            "user-a",
            CreateProfileInput {
                profile: profile(),
                allowed_issuers_was_provided: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        application.profile_owner(profile.id).await.unwrap(),
        "org-a"
    );
}
