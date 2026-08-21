use crate::{
    AgeVerificationRule, AuditConfiguration, ComplianceProfile, ComplianceStatus,
    ConsentRequirement, DataRetentionPolicy, IssuanceProtocol, IssuerArtifactRequirements,
    TrustProfileConstraints,
};
use chrono::{TimeZone, Utc};
use marty_credential_template::CredentialFormat;
use sqlx::PgPool;
use thiserror::Error;

pub const COMPLIANCE_SCHEMA: &str = r#"
CREATE SCHEMA IF NOT EXISTS compliance_profile_service;
CREATE TABLE IF NOT EXISTS compliance_profile_service.profiles(
 id TEXT PRIMARY KEY, organization_id TEXT, status TEXT NOT NULL, is_system BOOLEAN NOT NULL,
 discoverable BOOLEAN NOT NULL, payload JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
 CONSTRAINT compliance_profile_system_scope CHECK ((is_system AND organization_id IS NULL) OR (NOT is_system AND organization_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS ix_compliance_profiles_org ON compliance_profile_service.profiles(organization_id);
CREATE INDEX IF NOT EXISTS ix_compliance_profiles_discovery ON compliance_profile_service.profiles(is_system,discoverable,status);
CREATE TABLE IF NOT EXISTS compliance_profile_service.native_migrations(version TEXT PRIMARY KEY,applied_at TIMESTAMPTZ NOT NULL DEFAULT now());
"#;
#[derive(Debug, Error)]
pub enum ComplianceMigrationError {
    #[error("COMPLIANCE_PROFILE.MIGRATION_DATABASE: {0}")]
    Database(#[from] sqlx::Error),
    #[error("COMPLIANCE_PROFILE.MIGRATION_SEED")]
    Seed,
}
pub async fn run_migrations(pool: &PgPool) -> Result<(), ComplianceMigrationError> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(800_820_260_821_i64)
        .execute(&mut *tx)
        .await?;
    sqlx::raw_sql(COMPLIANCE_SCHEMA).execute(&mut *tx).await?;
    for p in system_profiles() {
        let payload = serde_json::to_value(&p).map_err(|_| ComplianceMigrationError::Seed)?;
        sqlx::query("INSERT INTO compliance_profile_service.profiles(id,organization_id,status,is_system,discoverable,payload,created_at,updated_at) VALUES($1,NULL,'ACTIVE',TRUE,TRUE,$2,$3,$3) ON CONFLICT(id) DO UPDATE SET status='ACTIVE',is_system=TRUE,discoverable=TRUE,payload=EXCLUDED.payload,updated_at=EXCLUDED.updated_at").bind(&p.id).bind(payload).bind(p.created_at).execute(&mut *tx).await?;
    }
    sqlx::query("INSERT INTO compliance_profile_service.native_migrations(version) VALUES('compliance-profile-rust-v1') ON CONFLICT DO NOTHING").execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
pub fn system_profiles() -> Vec<ComplianceProfile> {
    let now = Utc
        .with_ymd_and_hms(2026, 4, 16, 12, 0, 0)
        .single()
        .expect("valid seed time");
    [
        (
            "10000000-0000-0000-0000-000000000001",
            "OID4VC Core",
            "System baseline for standards-based OID4VC issuance and verification.",
            "OID4VC",
            CredentialFormat::SdJwtVc,
            IssuanceProtocol::Oid4vciPreAuth,
            false,
            true,
            true,
        ),
        (
            "10000000-0000-0000-0000-000000000002",
            "ISO 18013-5 mdoc",
            "System baseline for ISO 18013-5 mobile documents.",
            "ISO_18013_5",
            CredentialFormat::Mdoc,
            IssuanceProtocol::Oid4vciPreAuth,
            true,
            true,
            false,
        ),
        (
            "10000000-0000-0000-0000-000000000003",
            "Open Badges 3.0",
            "System baseline for Open Badges 3.0 credentials.",
            "OPEN_BADGES_3",
            CredentialFormat::SdJwtVc,
            IssuanceProtocol::Oid4vciPreAuth,
            false,
            true,
            true,
        ),
        (
            "10000000-0000-0000-0000-000000000004",
            "ICAO VDS-NC",
            "System baseline for ICAO Visible Digital Seals for non-constrained environments.",
            "ICAO_VDS_NC",
            CredentialFormat::VdsNc,
            IssuanceProtocol::Direct,
            true,
            false,
            false,
        ),
    ]
    .into_iter()
    .map(
        |(id, name, description, code, format, protocol, x509, did, jwk)| ComplianceProfile {
            id: id.into(),
            organization_id: None,
            name: name.into(),
            description: Some(description.into()),
            status: ComplianceStatus::Active,
            compliance_code: Some(code.into()),
            credential_format: format,
            issuance_protocol: Some(protocol),
            issuer_artifact_requirements: Some(IssuerArtifactRequirements {
                requires_x509_cert: x509,
                requires_did: did,
                requires_jwk: jwk,
                cert_key_usage: vec![],
                recommended_algorithms: vec!["ES256".into()],
            }),
            verification_policy_set_id: None,
            trust_profile_constraints: TrustProfileConstraints::default(),
            api_surface: vec![],
            discoverable: true,
            is_system: true,
            frameworks: vec![],
            data_retention: DataRetentionPolicy::default(),
            consent_requirement: ConsentRequirement::default(),
            audit_configuration: AuditConfiguration::default(),
            data_minimization_rules: vec![],
            jurisdictional_constraints: vec![],
            age_verification: AgeVerificationRule::default(),
            created_at: now,
            updated_at: now,
        },
    )
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_owns_durable_policy_payload_and_system_scope() {
        for field in [
            "organization_id",
            "is_system",
            "discoverable",
            "payload JSONB",
            "compliance_profile_system_scope",
        ] {
            assert!(COMPLIANCE_SCHEMA.contains(field));
        }
    }

    #[test]
    fn system_catalog_preserves_all_four_python_seed_profiles() {
        let profiles = system_profiles();
        assert_eq!(profiles.len(), 4);
        assert_eq!(
            profiles
                .iter()
                .filter_map(|profile| profile.compliance_code.as_deref())
                .collect::<Vec<_>>(),
            ["OID4VC", "ISO_18013_5", "OPEN_BADGES_3", "ICAO_VDS_NC"]
        );
        let iso = &profiles[1].issuer_artifact_requirements;
        assert_eq!(
            iso,
            &Some(IssuerArtifactRequirements {
                requires_x509_cert: true,
                requires_did: true,
                requires_jwk: false,
                cert_key_usage: vec![],
                recommended_algorithms: vec!["ES256".into()],
            })
        );
    }
}
