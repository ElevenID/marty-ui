use std::sync::Arc;

use async_trait::async_trait;
use chrono::{Duration, TimeZone, Utc};
use marty_trust_profile::{
    CascadeRevocationPolicy, Change, ComplianceStatus, CreateProfileInput, IssuerEntity,
    IssuerEntityComplianceStatus, IssuerEntityPatch, IssuerEntityType,
    MemoryTrustProfileRepository, ProfilePatch, RevocationPolicy, TimePolicy,
    TrustAuthorizationError, TrustProfile, TrustProfileApplication, TrustProfileApplicationError,
    TrustProfileControlPlane, TrustProfileIssuer, TrustProfileRepository, TrustProfileStatus,
    TrustProfileType, TrustRelationshipStatus, TrustSource, TrustSourceType, ValidationRules,
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
