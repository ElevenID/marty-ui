use chrono::{DateTime, Utc};
use serde_json::{json, Map};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    CascadeRevocationPolicy, ComplianceStatus, IssuerEntity, IssuerEntityComplianceStatus,
    IssuerEntityType, RevocationCheckMode, RevocationPolicy, TimePolicy, TrustFramework,
    TrustProfile, TrustProfileIssuer, TrustProfileRepository, TrustProfileRepositoryError,
    TrustProfileStatus, TrustProfileType, TrustRelationshipStatus, TrustSource, TrustSourceType,
    ValidationRules,
};

pub const MARTY_TRUST_PROFILE_ID: &str = "60000000-0000-0000-0000-000000000001";
pub const ICAO_TRAVEL_TRUST_PROFILE_ID: &str = "60000000-0000-0000-0000-000000000002";
pub const MDL_AAMVA_TRUST_PROFILE_ID: &str = "60000000-0000-0000-0000-000000000003";
pub const MARTY_TRUSTED_ISSUER_ID: &str = "60000000-0000-0000-0000-000000000011";
pub const MARTY_ISSUER_ENTITY_ID: &str = "60000000-0000-0000-0000-000000000012";
pub const MARTY_TRUST_BUNDLE_SOURCE_ID: &str = "60000000-0000-0000-0000-000000000021";
pub const ICAO_MARTY_RELATIONSHIP_ID: &str = "60000000-0000-0000-0000-000000000031";
pub const MDL_MARTY_RELATIONSHIP_ID: &str = "60000000-0000-0000-0000-000000000033";
pub const MARTY_REVOCATION_PROFILE_ID: &str = "70000000-0000-0000-0000-000000000001";
pub const MARTY_MEMBER_SD_JWT_TEMPLATE_ID: &str = "50000000-0000-0000-0000-000000000010";
pub const MARTY_MEMBER_MDOC_TEMPLATE_ID: &str = "50000000-0000-0000-0000-000000000030";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MartyBootstrapConfig {
    pub organization_id: String,
    pub issuer_did: String,
    pub issuer_url: String,
}

#[derive(Debug, Error)]
pub enum TrustCatalogError {
    #[error("TRUST_PROFILE.CATALOG_INVALID_CONFIG: {0}")]
    InvalidConfig(&'static str),
    #[error(transparent)]
    Repository(#[from] TrustProfileRepositoryError),
}

#[must_use]
pub fn system_frameworks(now: DateTime<Utc>) -> [TrustFramework; 3] {
    [
        framework(
            FrameworkSpec {
                code: "ICAO",
                display_name: "ICAO PKD",
                description: "ICAO trust framework for mdoc and travel credential validation.",
                pkd_endpoints: vec!["https://pkddownload1.icao.int/PKDDownload/".into()],
                default_algorithms: vec!["ES256".into(), "ES384".into(), "EdDSA".into()],
                default_formats: vec!["MDOC".into()],
                validation_ruleset: json!({
                "require_document_signer": true,
                "require_country_signing_ca": true,
                "allow_self_signed": false
                }),
                sync_config: json!({"mode": "PKD_DELTA", "refresh_interval_hours": 24}),
            },
            now,
        ),
        framework(
            FrameworkSpec {
                code: "AAMVA",
                display_name: "AAMVA mDL",
                description: "AAMVA trust framework for North American mobile driver licenses.",
                pkd_endpoints: Vec::new(),
                default_algorithms: vec!["ES256".into(), "ES384".into()],
                default_formats: vec!["MDOC".into()],
                validation_ruleset: json!({
                "require_crl_distribution_points": true,
                "require_issuer_alt_name": true,
                "allow_self_signed": false
                }),
                sync_config: json!({"mode": "MANUAL", "refresh_interval_hours": 24}),
            },
            now,
        ),
        framework(
            FrameworkSpec {
                code: "EUDI",
                display_name: "EUDI Wallet",
                description:
                    "EUDI wallet trust framework defaults for interoperable European credentials.",
                pkd_endpoints: Vec::new(),
                default_algorithms: vec!["ES256".into(), "ES384".into(), "EdDSA".into()],
                default_formats: vec!["MDOC".into(), "SD_JWT_VC".into()],
                validation_ruleset: json!({"require_pid_metadata": true, "allow_self_signed": false}),
                sync_config: json!({"mode": "MANUAL", "refresh_interval_hours": 24}),
            },
            now,
        ),
    ]
}

pub async fn bootstrap_system_catalog(
    repository: &dyn TrustProfileRepository,
    config: &MartyBootstrapConfig,
    now: DateTime<Utc>,
) -> Result<(), TrustCatalogError> {
    validate_config(config)?;
    for framework in system_frameworks(now) {
        if repository
            .framework_by_code(&framework.code)
            .await?
            .is_none()
        {
            repository.save_framework(&framework).await?;
        }
    }

    let issuer = bootstrap_issuer(repository, config, now).await?;
    let login = login_profile(config, now);
    ensure_profile(repository, &login).await?;
    ensure_relationship(
        repository,
        relationship(
            MARTY_TRUSTED_ISSUER_ID,
            &login,
            issuer.id,
            vec![
                MARTY_MEMBER_SD_JWT_TEMPLATE_ID,
                MARTY_MEMBER_MDOC_TEMPLATE_ID,
            ],
            now,
        ),
    )
    .await?;

    let icao = icao_profile(config, now);
    ensure_profile(repository, &icao).await?;
    ensure_relationship(
        repository,
        relationship(
            ICAO_MARTY_RELATIONSHIP_ID,
            &icao,
            issuer.id,
            vec![
                "50000000-0000-0000-0000-000000000060",
                "50000000-0000-0000-0000-000000000070",
                "50000000-0000-0000-0000-000000000080",
                "50000000-0000-0000-0000-000000000090",
                "50000000-0000-0000-0000-0000000000a0",
            ],
            now,
        ),
    )
    .await?;

    let mdl = mdl_profile(config, now);
    ensure_profile(repository, &mdl).await?;
    ensure_relationship(
        repository,
        relationship(
            MDL_MARTY_RELATIONSHIP_ID,
            &mdl,
            issuer.id,
            vec!["50000000-0000-0000-0000-000000000020"],
            now,
        ),
    )
    .await?;
    Ok(())
}

struct FrameworkSpec<'a> {
    code: &'a str,
    display_name: &'a str,
    description: &'a str,
    pkd_endpoints: Vec<String>,
    default_algorithms: Vec<String>,
    default_formats: Vec<String>,
    validation_ruleset: serde_json::Value,
    sync_config: serde_json::Value,
}

fn framework(spec: FrameworkSpec<'_>, now: DateTime<Utc>) -> TrustFramework {
    TrustFramework {
        id: Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("https://marty.dev/trust-framework/{}", spec.code).as_bytes(),
        ),
        code: spec.code.into(),
        display_name: spec.display_name.into(),
        description: Some(spec.description.into()),
        pkd_endpoints: spec.pkd_endpoints,
        default_algorithms: spec.default_algorithms,
        default_formats: spec.default_formats,
        validation_ruleset: spec.validation_ruleset,
        sync_config: spec.sync_config,
        is_system: true,
        created_at: now,
        updated_at: now,
    }
}

async fn bootstrap_issuer(
    repository: &dyn TrustProfileRepository,
    config: &MartyBootstrapConfig,
    now: DateTime<Utc>,
) -> Result<IssuerEntity, TrustCatalogError> {
    let canonical_id = id(MARTY_ISSUER_ENTITY_ID);
    let mut issuer = if let Some(issuer) = repository.issuer_entity_by_id(canonical_id).await? {
        issuer
    } else if let Some(issuer) = repository
        .issuer_entity_by_identifier(Some(&config.organization_id), &config.issuer_did)
        .await?
    {
        issuer
    } else {
        IssuerEntity {
            id: canonical_id,
            organization_id: Some(config.organization_id.clone()),
            issuer_id: config.issuer_did.clone(),
            issuer_type: IssuerEntityType::Organization,
            display_name: "Marty Managed Issuer".into(),
            description: Some("Default issuer for Marty credential-login bootstrap.".into()),
            is_system_issuer: false,
            compliance_status: IssuerEntityComplianceStatus::Compliant,
            accreditation_body: None,
            accreditations: Vec::new(),
            accreditation_date: None,
            valid_from: now,
            valid_until: None,
            trust_anchor_id: None,
            revoked_at: None,
            revocation_reason: None,
            revoked_by: None,
            metadata: json!({}),
            created_at: now,
            updated_at: now,
        }
    };
    if issuer.organization_id.as_deref() != Some(&config.organization_id) {
        return Err(TrustCatalogError::InvalidConfig("issuer_tenant_conflict"));
    }
    issuer.issuer_id.clone_from(&config.issuer_did);
    issuer.display_name = "Marty Managed Issuer".into();
    issuer.description = Some("Default issuer for Marty credential-login bootstrap.".into());
    let mut metadata = issuer.metadata.as_object().cloned().unwrap_or_default();
    metadata.insert("issuer_url".into(), json!(config.issuer_url));
    metadata.insert("verification_keys".into(), json!([]));
    issuer.metadata = serde_json::Value::Object(metadata);
    issuer.updated_at = now;
    repository.save_issuer_entity(&issuer).await?;
    Ok(issuer)
}

async fn ensure_profile(
    repository: &dyn TrustProfileRepository,
    desired: &TrustProfile,
) -> Result<(), TrustCatalogError> {
    if let Some(mut existing) = repository.profile_by_id(desired.id).await? {
        if existing.organization_id != desired.organization_id {
            return Err(TrustCatalogError::InvalidConfig("profile_tenant_conflict"));
        }
        let mut changed = false;
        if existing.revocation_profile_id != desired.revocation_profile_id {
            existing.revocation_profile_id = desired.revocation_profile_id.clone();
            changed = true;
        }
        for managed in desired
            .trust_sources
            .iter()
            .filter(|source| source.source_type == TrustSourceType::PinnedIssuer)
            .cloned()
        {
            if let Some(current) = existing
                .trust_sources
                .iter_mut()
                .find(|source| source.id == managed.id || source.name == managed.name)
            {
                if current != &managed {
                    *current = managed;
                    changed = true;
                }
            } else {
                existing.trust_sources.push(managed);
                changed = true;
            }
        }
        if changed {
            existing.updated_at = desired.updated_at;
            repository.save_profile(&existing, None).await?;
        }
        return Ok(());
    }
    repository.save_profile(desired, None).await?;
    Ok(())
}

async fn ensure_relationship(
    repository: &dyn TrustProfileRepository,
    desired: TrustProfileIssuer,
) -> Result<(), TrustCatalogError> {
    if let Some(mut existing) = repository.profile_issuer_by_id(desired.id).await? {
        if existing.trust_profile_id != desired.trust_profile_id {
            return Err(TrustCatalogError::InvalidConfig(
                "relationship_profile_conflict",
            ));
        }
        existing.issuer_id = desired.issuer_id;
        existing.metadata = desired.metadata;
        existing.updated_at = desired.updated_at;
        repository.save_profile_issuer(&existing).await?;
    } else {
        repository.save_profile_issuer(&desired).await?;
    }
    Ok(())
}

fn login_profile(config: &MartyBootstrapConfig, now: DateTime<Utc>) -> TrustProfile {
    let mut profile = base_profile(
        MARTY_TRUST_PROFILE_ID,
        &config.organization_id,
        "Marty Credential Login Trust",
        "Default trust profile for Marty credential-login preview flows.",
        now,
    );
    profile.trust_sources = vec![pinned_source(
        MARTY_TRUST_BUNDLE_SOURCE_ID,
        "Marty Managed Issuer",
        &config.issuer_did,
        "Marty managed issuer DID",
    )];
    profile.validation_rules.allowed_algorithms = vec!["ES256".into(), "EdDSA".into()];
    profile.revocation_policy.offline_grace_period_hours = 12;
    profile.revocation_policy.cache_duration_hours = 24;
    profile.time_policy.credential_freshness_hours = Some(24);
    profile.supported_formats = vec!["SD_JWT_VC".into(), "MDOC".into()];
    profile
}

fn icao_profile(config: &MartyBootstrapConfig, now: DateTime<Utc>) -> TrustProfile {
    let mut profile = base_profile(
        ICAO_TRAVEL_TRUST_PROFILE_ID,
        &config.organization_id,
        "ICAO Travel Document Verification",
        "Verification trust profile for ICAO travel documents issued as VDS-NC or mDoc.",
        now,
    );
    profile.trust_sources = vec![
        legacy_registry_source(
            "60000000-0000-0000-0000-000000000032",
            "ICAO Public Key Directory",
            "https://pkd.icao.int/",
            "icao_pkd",
        ),
        pinned_source(
            "60000000-0000-0000-0000-000000000031",
            "Marty Managed ICAO Issuer",
            &config.issuer_did,
            "Marty controlled issuer for development and demo scenarios.",
        ),
    ];
    profile.validation_rules.extensions = Map::from_iter([
        ("require_icao_country_header".into(), json!(true)),
        ("allowed_vds_nc_header_prefixes".into(), json!(["DC0"])),
    ]);
    profile.revocation_policy.check_status_list = false;
    profile.revocation_policy.offline_grace_period_hours = 72;
    profile.revocation_policy.cache_duration_hours = 24;
    profile.time_policy.credential_freshness_hours = Some(87_600);
    profile.time_policy.require_not_before = false;
    profile.supported_formats = vec!["VDS_NC".into(), "MDOC".into()];
    profile
}

fn mdl_profile(config: &MartyBootstrapConfig, now: DateTime<Utc>) -> TrustProfile {
    let mut profile = base_profile(
        MDL_AAMVA_TRUST_PROFILE_ID,
        &config.organization_id,
        "Mobile Driver's License Verification (AAMVA)",
        "Verification trust profile for ISO 18013-5 mobile driver's licenses.",
        now,
    );
    profile.trust_sources = vec![
        legacy_registry_source(
            "60000000-0000-0000-0000-000000000034",
            "AAMVA Digital Identity Trust Registry",
            "https://registry.aamva.org/",
            "aamva_mdl",
        ),
        pinned_source(
            "60000000-0000-0000-0000-000000000033",
            "Marty Managed mDL Issuer",
            &config.issuer_did,
            "Marty controlled mDL issuer for development and demo scenarios.",
        ),
    ];
    profile.validation_rules.allowed_algorithms = vec![
        "ES256".into(),
        "ES384".into(),
        "EdDSA".into(),
        "ES512".into(),
    ];
    profile
        .validation_rules
        .extensions
        .insert("require_mdoc_device_auth".into(), json!(true));
    profile.revocation_policy.cache_duration_hours = 12;
    profile.time_policy.credential_freshness_hours = Some(43_800);
    profile.supported_formats = vec!["MDOC".into(), "SD_JWT_VC".into()];
    profile
}

fn base_profile(
    profile_id: &str,
    organization_id: &str,
    name: &str,
    description: &str,
    now: DateTime<Utc>,
) -> TrustProfile {
    TrustProfile {
        id: id(profile_id),
        organization_id: organization_id.into(),
        name: name.into(),
        description: Some(description.into()),
        status: TrustProfileStatus::Active,
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
        revocation_policy: RevocationPolicy {
            check_mode: RevocationCheckMode::HardFail,
            ..RevocationPolicy::default()
        },
        revocation_profile_id: Some(MARTY_REVOCATION_PROFILE_ID.into()),
        time_policy: TimePolicy::default(),
        supported_formats: vec!["MDOC".into()],
        created_at: now,
        updated_at: now,
    }
}

fn pinned_source(id_value: &str, name: &str, issuer_did: &str, description: &str) -> TrustSource {
    TrustSource {
        id: id(id_value),
        name: name.into(),
        source_type: TrustSourceType::PinnedIssuer,
        url: None,
        certificate_pem: None,
        issuer_did: Some(issuer_did.into()),
        description: Some(description.into()),
        pinned_certificates: Vec::new(),
        refresh_interval_hours: 24,
        enabled: true,
        registry_sync: None,
        registry_sync_token: None,
        registry_sequence: 0,
        registry_entries: Map::new(),
        registry_last_synced_at: None,
        extensions: Map::new(),
    }
}

fn legacy_registry_source(
    id_value: &str,
    name: &str,
    registry_url: &str,
    namespace: &str,
) -> TrustSource {
    TrustSource {
        id: id(id_value),
        name: name.into(),
        source_type: TrustSourceType::LegacyRegistry,
        url: Some(registry_url.into()),
        certificate_pem: None,
        issuer_did: None,
        description: None,
        pinned_certificates: Vec::new(),
        refresh_interval_hours: 24,
        enabled: true,
        registry_sync: None,
        registry_sync_token: None,
        registry_sequence: 0,
        registry_entries: Map::new(),
        registry_last_synced_at: None,
        extensions: Map::from_iter([
            ("registry_url".into(), json!(registry_url)),
            ("registry_namespace".into(), json!(namespace)),
        ]),
    }
}

fn relationship(
    relationship_id: &str,
    profile: &TrustProfile,
    issuer_id: Uuid,
    template_ids: Vec<&str>,
    now: DateTime<Utc>,
) -> TrustProfileIssuer {
    TrustProfileIssuer {
        id: id(relationship_id),
        trust_profile_id: profile.id,
        issuer_id,
        trust_level: 100,
        relationship_status: TrustRelationshipStatus::Trusted,
        cascade_revocation_policy: CascadeRevocationPolicy::NotifyOnly,
        metadata: json!({"credential_template_ids": template_ids}),
        created_at: now,
        updated_at: now,
    }
}

fn validate_config(config: &MartyBootstrapConfig) -> Result<(), TrustCatalogError> {
    if Uuid::parse_str(&config.organization_id).is_err() {
        return Err(TrustCatalogError::InvalidConfig("organization_id"));
    }
    if !config.issuer_did.starts_with("did:") {
        return Err(TrustCatalogError::InvalidConfig("issuer_did"));
    }
    if !config.issuer_url.starts_with("https://") {
        return Err(TrustCatalogError::InvalidConfig("issuer_url"));
    }
    Ok(())
}

fn id(value: &str) -> Uuid {
    Uuid::parse_str(value).expect("catalog identifiers are static UUIDs")
}
