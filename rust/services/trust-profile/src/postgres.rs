use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use sqlx::{postgres::PgRow, PgPool, Row};
use uuid::Uuid;

use crate::{
    IssuerEntity, IssuerEntityComplianceStatus, IssuerEntityType, OrganizationTrustProfile,
    RegistryImportSource, RegistryImportedIssuer, RegistryOperation, RegistrySource,
    RegistryStatus, TrustAnchorType, TrustFramework, TrustProfile, TrustProfileIssuer,
    TrustProfileRecord, TrustProfileRepository, TrustProfileRepositoryError,
    TrustRelationshipStatus,
};

#[derive(Clone, Debug)]
pub struct PostgresTrustProfileRepository {
    pool: PgPool,
}

impl PostgresTrustProfileRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[async_trait]
impl TrustProfileRepository for PostgresTrustProfileRepository {
    async fn save_framework(
        &self,
        framework: &TrustFramework,
    ) -> Result<(), TrustProfileRepositoryError> {
        sqlx::query(
            "INSERT INTO trust_profile_service.trust_frameworks
             (id,code,display_name,description,pkd_endpoints,default_algorithms,default_formats,
              validation_ruleset,sync_config,is_system,created_at,updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
             ON CONFLICT (id) DO UPDATE SET code=EXCLUDED.code,
              display_name=EXCLUDED.display_name,description=EXCLUDED.description,
              pkd_endpoints=EXCLUDED.pkd_endpoints,default_algorithms=EXCLUDED.default_algorithms,
              default_formats=EXCLUDED.default_formats,validation_ruleset=EXCLUDED.validation_ruleset,
              sync_config=EXCLUDED.sync_config,is_system=EXCLUDED.is_system,
              updated_at=EXCLUDED.updated_at",
        )
        .bind(framework.id.to_string())
        .bind(&framework.code)
        .bind(&framework.display_name)
        .bind(&framework.description)
        .bind(json(&framework.pkd_endpoints, "pkd_endpoints")?)
        .bind(json(&framework.default_algorithms, "default_algorithms")?)
        .bind(json(&framework.default_formats, "default_formats")?)
        .bind(&framework.validation_ruleset)
        .bind(&framework.sync_config)
        .bind(framework.is_system)
        .bind(framework.created_at)
        .bind(framework.updated_at)
        .execute(&self.pool)
        .await
        .map_err(database)?;
        Ok(())
    }

    async fn framework_by_id(
        &self,
        framework_id: Uuid,
    ) -> Result<Option<TrustFramework>, TrustProfileRepositoryError> {
        let row = sqlx::query("SELECT * FROM trust_profile_service.trust_frameworks WHERE id=$1")
            .bind(framework_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(database)?;
        row.as_ref().map(framework_from_row).transpose()
    }

    async fn framework_by_code(
        &self,
        code: &str,
    ) -> Result<Option<TrustFramework>, TrustProfileRepositoryError> {
        let row = sqlx::query("SELECT * FROM trust_profile_service.trust_frameworks WHERE code=$1")
            .bind(code)
            .fetch_optional(&self.pool)
            .await
            .map_err(database)?;
        row.as_ref().map(framework_from_row).transpose()
    }

    async fn frameworks(&self) -> Result<Vec<TrustFramework>, TrustProfileRepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM trust_profile_service.trust_frameworks
             ORDER BY is_system DESC, code",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(database)?;
        rows.iter().map(framework_from_row).collect()
    }

    async fn save_organization_profile(
        &self,
        profile: &OrganizationTrustProfile,
    ) -> Result<(), TrustProfileRepositoryError> {
        sqlx::query(
            "INSERT INTO trust_profile_service.organization_trust_profiles
             (id,organization_id,framework_id,name,display_name,description,enabled,use_case_tags,
              compliance_status,auto_generated,revocation_policy,time_policy,allowed_algorithms,
              allowed_formats,allowed_issuers,denied_issuers,jurisdiction_filter,metadata,
              created_at,updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
             ON CONFLICT (id) DO UPDATE SET organization_id=EXCLUDED.organization_id,
              framework_id=EXCLUDED.framework_id,name=EXCLUDED.name,
              display_name=EXCLUDED.display_name,description=EXCLUDED.description,
              enabled=EXCLUDED.enabled,use_case_tags=EXCLUDED.use_case_tags,
              compliance_status=EXCLUDED.compliance_status,auto_generated=EXCLUDED.auto_generated,
              revocation_policy=EXCLUDED.revocation_policy,time_policy=EXCLUDED.time_policy,
              allowed_algorithms=EXCLUDED.allowed_algorithms,allowed_formats=EXCLUDED.allowed_formats,
              allowed_issuers=EXCLUDED.allowed_issuers,denied_issuers=EXCLUDED.denied_issuers,
              jurisdiction_filter=EXCLUDED.jurisdiction_filter,metadata=EXCLUDED.metadata,
              updated_at=EXCLUDED.updated_at",
        )
        .bind(profile.id.to_string())
        .bind(&profile.organization_id)
        .bind(profile.framework_id.to_string())
        .bind(&profile.name)
        .bind(&profile.display_name)
        .bind(&profile.description)
        .bind(profile.enabled)
        .bind(json(&profile.use_case_tags, "use_case_tags")?)
        .bind(text(&profile.compliance_status, "compliance_status")?)
        .bind(profile.auto_generated)
        .bind(&profile.revocation_policy)
        .bind(&profile.time_policy)
        .bind(option_json(&profile.allowed_algorithms, "allowed_algorithms")?)
        .bind(option_json(&profile.allowed_formats, "allowed_formats")?)
        .bind(option_json(&profile.allowed_issuers, "allowed_issuers")?)
        .bind(option_json(&profile.denied_issuers, "denied_issuers")?)
        .bind(option_json(&profile.jurisdiction_filter, "jurisdiction_filter")?)
        .bind(&profile.metadata)
        .bind(profile.created_at)
        .bind(profile.updated_at)
        .execute(&self.pool)
        .await
        .map_err(database)?;
        Ok(())
    }

    async fn organization_profile_by_id(
        &self,
        profile_id: Uuid,
    ) -> Result<Option<OrganizationTrustProfile>, TrustProfileRepositoryError> {
        let row = sqlx::query(
            "SELECT * FROM trust_profile_service.organization_trust_profiles WHERE id=$1",
        )
        .bind(profile_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(database)?;
        row.as_ref().map(organization_profile_from_row).transpose()
    }

    async fn organization_profiles(
        &self,
        organization_id: &str,
    ) -> Result<Vec<OrganizationTrustProfile>, TrustProfileRepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM trust_profile_service.organization_trust_profiles
             WHERE organization_id=$1 ORDER BY created_at,id",
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await
        .map_err(database)?;
        rows.iter().map(organization_profile_from_row).collect()
    }

    async fn delete_organization_profile(
        &self,
        profile_id: Uuid,
    ) -> Result<bool, TrustProfileRepositoryError> {
        Ok(
            sqlx::query(
                "DELETE FROM trust_profile_service.organization_trust_profiles WHERE id=$1",
            )
            .bind(profile_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(database)?
            .rows_affected()
                > 0,
        )
    }

    async fn save_registry_entry(
        &self,
        entry: &crate::TrustRegistryEntry,
    ) -> Result<(), TrustProfileRepositoryError> {
        sqlx::query(
            "INSERT INTO trust_profile_service.trust_registry_entries
             (id,anchor_type,operation,country_code,certificate_pem,subject_key_id,not_before,
              not_after,source,framework_code,sequence,is_current,created_at,updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
             ON CONFLICT (id) DO UPDATE SET anchor_type=EXCLUDED.anchor_type,
              operation=EXCLUDED.operation,country_code=EXCLUDED.country_code,
              certificate_pem=EXCLUDED.certificate_pem,subject_key_id=EXCLUDED.subject_key_id,
              not_before=EXCLUDED.not_before,not_after=EXCLUDED.not_after,source=EXCLUDED.source,
              framework_code=EXCLUDED.framework_code,sequence=EXCLUDED.sequence,
              is_current=EXCLUDED.is_current,updated_at=EXCLUDED.updated_at",
        )
        .bind(entry.id.to_string())
        .bind(text(&entry.anchor_type, "anchor_type")?)
        .bind(text(&entry.operation, "operation")?)
        .bind(entry.country_code.to_uppercase())
        .bind(&entry.certificate_pem)
        .bind(&entry.subject_key_id)
        .bind(entry.not_before)
        .bind(entry.not_after)
        .bind(text(&entry.source, "source")?)
        .bind(&entry.framework_code)
        .bind(i32::try_from(entry.sequence).map_err(|_| invalid("sequence"))?)
        .bind(entry.is_current)
        .bind(entry.created_at)
        .bind(entry.updated_at)
        .execute(&self.pool)
        .await
        .map_err(database)?;
        Ok(())
    }

    async fn registry_entries(
        &self,
        anchor_type: Option<TrustAnchorType>,
        country_code: Option<&str>,
        current_only: bool,
        since_sequence: Option<u64>,
    ) -> Result<Vec<crate::TrustRegistryEntry>, TrustProfileRepositoryError> {
        let anchor_type = anchor_type
            .map(|value| text(&value, "anchor_type"))
            .transpose()?;
        let country_code = country_code.map(str::to_uppercase);
        let since_sequence = since_sequence
            .map(|value| i32::try_from(value).map_err(|_| invalid("since_sequence")))
            .transpose()?;
        let rows = sqlx::query(
            "SELECT * FROM trust_profile_service.trust_registry_entries
             WHERE ($1::text IS NULL OR anchor_type=$1)
               AND ($2::text IS NULL OR country_code=$2)
               AND (NOT $3 OR is_current=true)
               AND ($4::integer IS NULL OR sequence>$4)
             ORDER BY sequence,country_code,id",
        )
        .bind(anchor_type)
        .bind(country_code)
        .bind(current_only)
        .bind(since_sequence)
        .fetch_all(&self.pool)
        .await
        .map_err(database)?;
        rows.iter().map(registry_entry_from_row).collect()
    }

    async fn registry_status(&self) -> Result<RegistryStatus, TrustProfileRepositoryError> {
        let row = sqlx::query(
            "SELECT COUNT(*)::bigint AS total_entries,
              COUNT(*) FILTER (WHERE is_current)::bigint AS current_entries,
              COUNT(*) FILTER (WHERE is_current AND anchor_type='CSCA')::bigint AS csca_entries,
              COUNT(*) FILTER (WHERE is_current AND anchor_type='DSC')::bigint AS dsc_entries,
              COALESCE(MAX(sequence),0)::integer AS current_sequence
             FROM trust_profile_service.trust_registry_entries",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(database)?;
        Ok(RegistryStatus {
            total_entries: usize_from_i64(
                row.try_get("total_entries").map_err(database)?,
                "total_entries",
            )?,
            current_entries: usize_from_i64(
                row.try_get("current_entries").map_err(database)?,
                "current_entries",
            )?,
            csca_entries: usize_from_i64(
                row.try_get("csca_entries").map_err(database)?,
                "csca_entries",
            )?,
            dsc_entries: usize_from_i64(
                row.try_get("dsc_entries").map_err(database)?,
                "dsc_entries",
            )?,
            current_sequence: u64_from_i32(
                row.try_get("current_sequence").map_err(database)?,
                "current_sequence",
            )?,
        })
    }

    async fn save_profile(
        &self,
        profile: &TrustProfile,
        expected_updated_at: Option<DateTime<Utc>>,
    ) -> Result<bool, TrustProfileRepositoryError> {
        let record = TrustProfileRecord::try_from(profile).map_err(|_| invalid("trust_profile"))?;
        if let Some(expected) = expected_updated_at {
            return Ok(sqlx::query(
                "UPDATE trust_profile_service.trust_profiles SET
                 organization_id=$2,name=$3,description=$4,status=$5,trust_sources=$6,
                 validation_rules=$7,revocation_policy=$8,revocation_profile_id=$9,time_policy=$10,
                 supported_formats=$11,updated_at=$12 WHERE id=$1 AND updated_at=$13",
            )
            .bind(&record.id)
            .bind(&record.organization_id)
            .bind(&record.name)
            .bind(&record.description)
            .bind(&record.status)
            .bind(&record.trust_sources)
            .bind(&record.validation_rules)
            .bind(&record.revocation_policy)
            .bind(&record.revocation_profile_id)
            .bind(&record.time_policy)
            .bind(&record.supported_formats)
            .bind(record.updated_at)
            .bind(expected)
            .execute(&self.pool)
            .await
            .map_err(database)?
            .rows_affected()
                == 1);
        }
        sqlx::query(
            "INSERT INTO trust_profile_service.trust_profiles
             (id,organization_id,name,description,status,trust_sources,validation_rules,
              revocation_policy,revocation_profile_id,time_policy,supported_formats,created_at,updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
             ON CONFLICT (id) DO UPDATE SET organization_id=EXCLUDED.organization_id,
              name=EXCLUDED.name,description=EXCLUDED.description,status=EXCLUDED.status,
              trust_sources=EXCLUDED.trust_sources,validation_rules=EXCLUDED.validation_rules,
              revocation_policy=EXCLUDED.revocation_policy,
              revocation_profile_id=EXCLUDED.revocation_profile_id,time_policy=EXCLUDED.time_policy,
              supported_formats=EXCLUDED.supported_formats,updated_at=EXCLUDED.updated_at",
        )
        .bind(&record.id)
        .bind(&record.organization_id)
        .bind(&record.name)
        .bind(&record.description)
        .bind(&record.status)
        .bind(&record.trust_sources)
        .bind(&record.validation_rules)
        .bind(&record.revocation_policy)
        .bind(&record.revocation_profile_id)
        .bind(&record.time_policy)
        .bind(&record.supported_formats)
        .bind(record.created_at)
        .bind(record.updated_at)
        .execute(&self.pool)
        .await
        .map_err(database)?;
        Ok(true)
    }

    async fn profile_by_id(
        &self,
        profile_id: Uuid,
    ) -> Result<Option<TrustProfile>, TrustProfileRepositoryError> {
        let row = sqlx::query("SELECT * FROM trust_profile_service.trust_profiles WHERE id=$1")
            .bind(profile_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(database)?;
        row.as_ref().map(profile_from_row).transpose()
    }

    async fn profiles_by_organization(
        &self,
        organization_id: &str,
    ) -> Result<Vec<TrustProfile>, TrustProfileRepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM trust_profile_service.trust_profiles WHERE organization_id=$1",
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await
        .map_err(database)?;
        rows.iter().map(profile_from_row).collect()
    }

    async fn profiles(&self) -> Result<Vec<TrustProfile>, TrustProfileRepositoryError> {
        let rows = sqlx::query("SELECT * FROM trust_profile_service.trust_profiles ORDER BY id")
            .fetch_all(&self.pool)
            .await
            .map_err(database)?;
        rows.iter().map(profile_from_row).collect()
    }

    async fn delete_profile(&self, profile_id: Uuid) -> Result<bool, TrustProfileRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(database)?;
        sqlx::query(
            "DELETE FROM trust_profile_service.trust_profile_issuers WHERE trust_profile_id=$1",
        )
        .bind(profile_id.to_string())
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        let deleted = sqlx::query("DELETE FROM trust_profile_service.trust_profiles WHERE id=$1")
            .bind(profile_id.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(database)?
            .rows_affected()
            > 0;
        transaction.commit().await.map_err(database)?;
        Ok(deleted)
    }

    async fn save_issuer_entity(
        &self,
        issuer: &IssuerEntity,
    ) -> Result<(), TrustProfileRepositoryError> {
        sqlx::query(
            "INSERT INTO trust_profile_service.issuer_entities
             (id,organization_id,issuer_id,issuer_type,display_name,description,is_system_issuer,
              compliance_status,accreditation_body,accreditations,accreditation_date,valid_from,
              valid_until,trust_anchor_id,revoked_at,revocation_reason,revoked_by,metadata,
              created_at,updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
             ON CONFLICT (id) DO UPDATE SET organization_id=EXCLUDED.organization_id,
              issuer_id=EXCLUDED.issuer_id,issuer_type=EXCLUDED.issuer_type,
              display_name=EXCLUDED.display_name,description=EXCLUDED.description,
              is_system_issuer=EXCLUDED.is_system_issuer,
              compliance_status=EXCLUDED.compliance_status,
              accreditation_body=EXCLUDED.accreditation_body,
              accreditations=EXCLUDED.accreditations,accreditation_date=EXCLUDED.accreditation_date,
              valid_from=EXCLUDED.valid_from,valid_until=EXCLUDED.valid_until,
              trust_anchor_id=EXCLUDED.trust_anchor_id,revoked_at=EXCLUDED.revoked_at,
              revocation_reason=EXCLUDED.revocation_reason,revoked_by=EXCLUDED.revoked_by,
              metadata=EXCLUDED.metadata,updated_at=EXCLUDED.updated_at",
        )
        .bind(issuer.id.to_string())
        .bind(&issuer.organization_id)
        .bind(&issuer.issuer_id)
        .bind(text(&issuer.issuer_type, "issuer_type")?)
        .bind(&issuer.display_name)
        .bind(&issuer.description)
        .bind(issuer.is_system_issuer)
        .bind(text(&issuer.compliance_status, "compliance_status")?)
        .bind(&issuer.accreditation_body)
        .bind(json(&issuer.accreditations, "accreditations")?)
        .bind(issuer.accreditation_date)
        .bind(issuer.valid_from)
        .bind(issuer.valid_until)
        .bind(&issuer.trust_anchor_id)
        .bind(issuer.revoked_at)
        .bind(&issuer.revocation_reason)
        .bind(&issuer.revoked_by)
        .bind(&issuer.metadata)
        .bind(issuer.created_at)
        .bind(issuer.updated_at)
        .execute(&self.pool)
        .await
        .map_err(database)?;
        Ok(())
    }

    async fn issuer_entity_by_id(
        &self,
        issuer_id: Uuid,
    ) -> Result<Option<IssuerEntity>, TrustProfileRepositoryError> {
        let row = sqlx::query("SELECT * FROM trust_profile_service.issuer_entities WHERE id=$1")
            .bind(issuer_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(database)?;
        row.as_ref().map(issuer_from_row).transpose()
    }

    async fn issuer_entity_by_identifier(
        &self,
        organization_id: Option<&str>,
        issuer_identifier: &str,
    ) -> Result<Option<IssuerEntity>, TrustProfileRepositoryError> {
        let row = sqlx::query(
            "SELECT * FROM trust_profile_service.issuer_entities
             WHERE organization_id IS NOT DISTINCT FROM $1 AND issuer_id=$2 LIMIT 1",
        )
        .bind(organization_id)
        .bind(issuer_identifier)
        .fetch_optional(&self.pool)
        .await
        .map_err(database)?;
        row.as_ref().map(issuer_from_row).transpose()
    }

    async fn issuer_entities(
        &self,
        organization_id: Option<&str>,
    ) -> Result<Vec<IssuerEntity>, TrustProfileRepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM trust_profile_service.issuer_entities
             WHERE $1::text IS NULL OR organization_id=$1 OR is_system_issuer=true OR organization_id IS NULL
             ORDER BY lower(display_name),id",
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await
        .map_err(database)?;
        rows.iter().map(issuer_from_row).collect()
    }

    async fn delete_issuer_entity(
        &self,
        issuer_id: Uuid,
    ) -> Result<bool, TrustProfileRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(database)?;
        sqlx::query("DELETE FROM trust_profile_service.trust_profile_issuers WHERE issuer_id=$1")
            .bind(issuer_id.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(database)?;
        let deleted = sqlx::query("DELETE FROM trust_profile_service.issuer_entities WHERE id=$1")
            .bind(issuer_id.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(database)?
            .rows_affected()
            > 0;
        transaction.commit().await.map_err(database)?;
        Ok(deleted)
    }

    async fn save_profile_issuer(
        &self,
        link: &TrustProfileIssuer,
    ) -> Result<(), TrustProfileRepositoryError> {
        sqlx::query(
            "INSERT INTO trust_profile_service.trust_profile_issuers
             (id,trust_profile_id,issuer_id,trust_level,relationship_status,
              cascade_revocation_policy,metadata,created_at,updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
             ON CONFLICT (id) DO UPDATE SET trust_profile_id=EXCLUDED.trust_profile_id,
              issuer_id=EXCLUDED.issuer_id,trust_level=EXCLUDED.trust_level,
              relationship_status=EXCLUDED.relationship_status,
              cascade_revocation_policy=EXCLUDED.cascade_revocation_policy,
              metadata=EXCLUDED.metadata,updated_at=EXCLUDED.updated_at",
        )
        .bind(link.id.to_string())
        .bind(link.trust_profile_id.to_string())
        .bind(link.issuer_id.to_string())
        .bind(i16::from(link.trust_level))
        .bind(text(&link.relationship_status, "relationship_status")?)
        .bind(text(
            &link.cascade_revocation_policy,
            "cascade_revocation_policy",
        )?)
        .bind(&link.metadata)
        .bind(link.created_at)
        .bind(link.updated_at)
        .execute(&self.pool)
        .await
        .map_err(database)?;
        Ok(())
    }

    async fn profile_issuer_by_id(
        &self,
        link_id: Uuid,
    ) -> Result<Option<TrustProfileIssuer>, TrustProfileRepositoryError> {
        let row =
            sqlx::query("SELECT * FROM trust_profile_service.trust_profile_issuers WHERE id=$1")
                .bind(link_id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(database)?;
        row.as_ref().map(profile_issuer_from_row).transpose()
    }

    async fn profile_issuer_by_pair(
        &self,
        profile_id: Uuid,
        issuer_id: Uuid,
    ) -> Result<Option<TrustProfileIssuer>, TrustProfileRepositoryError> {
        let row = sqlx::query(
            "SELECT * FROM trust_profile_service.trust_profile_issuers
             WHERE trust_profile_id=$1 AND issuer_id=$2 ORDER BY created_at,id LIMIT 1",
        )
        .bind(profile_id.to_string())
        .bind(issuer_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(database)?;
        row.as_ref().map(profile_issuer_from_row).transpose()
    }

    async fn profile_issuers(
        &self,
        profile_id: Uuid,
    ) -> Result<Vec<TrustProfileIssuer>, TrustProfileRepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM trust_profile_service.trust_profile_issuers
             WHERE trust_profile_id=$1 ORDER BY created_at,id",
        )
        .bind(profile_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(database)?;
        rows.iter().map(profile_issuer_from_row).collect()
    }

    async fn delete_profile_issuer(
        &self,
        link_id: Uuid,
    ) -> Result<bool, TrustProfileRepositoryError> {
        Ok(
            sqlx::query("DELETE FROM trust_profile_service.trust_profile_issuers WHERE id=$1")
                .bind(link_id.to_string())
                .execute(&self.pool)
                .await
                .map_err(database)?
                .rows_affected()
                > 0,
        )
    }

    async fn save_registry_import_source(
        &self,
        source: &RegistryImportSource,
    ) -> Result<(), TrustProfileRepositoryError> {
        sqlx::query(
            "INSERT INTO trust_profile_service.trust_registry_sources
             (id,trust_profile_id,registry_type,registry_name,registry_url,enabled,sync_enabled,
              last_synced_at,next_sync_at,sync_interval_hours,credential_format_filter,metadata,
              created_at,updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
             ON CONFLICT (id) DO UPDATE SET trust_profile_id=EXCLUDED.trust_profile_id,
              registry_type=EXCLUDED.registry_type,registry_name=EXCLUDED.registry_name,
              registry_url=EXCLUDED.registry_url,enabled=EXCLUDED.enabled,
              sync_enabled=EXCLUDED.sync_enabled,last_synced_at=EXCLUDED.last_synced_at,
              next_sync_at=EXCLUDED.next_sync_at,sync_interval_hours=EXCLUDED.sync_interval_hours,
              credential_format_filter=EXCLUDED.credential_format_filter,
              metadata=EXCLUDED.metadata,updated_at=EXCLUDED.updated_at",
        )
        .bind(source.id.to_string())
        .bind(source.trust_profile_id.to_string())
        .bind(text(&source.registry_type, "registry_type")?)
        .bind(&source.registry_name)
        .bind(&source.registry_url)
        .bind(source.enabled)
        .bind(source.sync_enabled)
        .bind(source.last_synced_at)
        .bind(source.next_sync_at)
        .bind(i32::from(source.sync_interval_hours))
        .bind(json(
            &source.credential_format_filter,
            "credential_format_filter",
        )?)
        .bind(&source.metadata)
        .bind(source.created_at)
        .bind(source.updated_at)
        .execute(&self.pool)
        .await
        .map_err(database)?;
        Ok(())
    }

    async fn registry_import_source_by_id(
        &self,
        source_id: Uuid,
    ) -> Result<Option<RegistryImportSource>, TrustProfileRepositoryError> {
        let row =
            sqlx::query("SELECT * FROM trust_profile_service.trust_registry_sources WHERE id=$1")
                .bind(source_id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(database)?;
        row.as_ref()
            .map(registry_import_source_from_row)
            .transpose()
    }

    async fn registry_import_sources(
        &self,
        profile_id: Uuid,
    ) -> Result<Vec<RegistryImportSource>, TrustProfileRepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM trust_profile_service.trust_registry_sources
             WHERE trust_profile_id=$1 ORDER BY created_at,id",
        )
        .bind(profile_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(database)?;
        rows.iter().map(registry_import_source_from_row).collect()
    }

    async fn delete_registry_import_source(
        &self,
        source_id: Uuid,
    ) -> Result<bool, TrustProfileRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(database)?;
        sqlx::query(
            "DELETE FROM trust_profile_service.trust_registry_issuers WHERE registry_source_id=$1",
        )
        .bind(source_id.to_string())
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        let deleted =
            sqlx::query("DELETE FROM trust_profile_service.trust_registry_sources WHERE id=$1")
                .bind(source_id.to_string())
                .execute(&mut *transaction)
                .await
                .map_err(database)?
                .rows_affected()
                > 0;
        transaction.commit().await.map_err(database)?;
        Ok(deleted)
    }

    async fn save_registry_imported_issuer(
        &self,
        issuer: &RegistryImportedIssuer,
    ) -> Result<(), TrustProfileRepositoryError> {
        sqlx::query(
            "INSERT INTO trust_profile_service.trust_registry_issuers
             (id,registry_source_id,trust_profile_id,issuer_did,issuer_name,country_code,
              issuer_type,verification_keys,credential_templates,status,imported_at,valid_from,
              valid_until,created_at,updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
             ON CONFLICT (id) DO UPDATE SET registry_source_id=EXCLUDED.registry_source_id,
              trust_profile_id=EXCLUDED.trust_profile_id,issuer_did=EXCLUDED.issuer_did,
              issuer_name=EXCLUDED.issuer_name,country_code=EXCLUDED.country_code,
              issuer_type=EXCLUDED.issuer_type,verification_keys=EXCLUDED.verification_keys,
              credential_templates=EXCLUDED.credential_templates,status=EXCLUDED.status,
              imported_at=EXCLUDED.imported_at,valid_from=EXCLUDED.valid_from,
              valid_until=EXCLUDED.valid_until,updated_at=EXCLUDED.updated_at",
        )
        .bind(issuer.id.to_string())
        .bind(issuer.registry_source_id.to_string())
        .bind(issuer.trust_profile_id.to_string())
        .bind(&issuer.issuer_did)
        .bind(&issuer.issuer_name)
        .bind(&issuer.country_code)
        .bind(&issuer.issuer_type)
        .bind(json(&issuer.verification_keys, "verification_keys")?)
        .bind(json(&issuer.credential_templates, "credential_templates")?)
        .bind(&issuer.status)
        .bind(issuer.imported_at)
        .bind(issuer.valid_from)
        .bind(issuer.valid_until)
        .bind(issuer.created_at)
        .bind(issuer.updated_at)
        .execute(&self.pool)
        .await
        .map_err(database)?;
        Ok(())
    }

    async fn registry_imported_issuer_by_id(
        &self,
        issuer_id: Uuid,
    ) -> Result<Option<RegistryImportedIssuer>, TrustProfileRepositoryError> {
        let row =
            sqlx::query("SELECT * FROM trust_profile_service.trust_registry_issuers WHERE id=$1")
                .bind(issuer_id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(database)?;
        row.as_ref()
            .map(registry_imported_issuer_from_row)
            .transpose()
    }

    async fn registry_imported_issuers(
        &self,
        profile_id: Uuid,
        source_id: Option<Uuid>,
    ) -> Result<Vec<RegistryImportedIssuer>, TrustProfileRepositoryError> {
        let source_id = source_id.map(|value| value.to_string());
        let rows = sqlx::query(
            "SELECT * FROM trust_profile_service.trust_registry_issuers
             WHERE trust_profile_id=$1 AND ($2::text IS NULL OR registry_source_id=$2)
             ORDER BY imported_at,id",
        )
        .bind(profile_id.to_string())
        .bind(source_id)
        .fetch_all(&self.pool)
        .await
        .map_err(database)?;
        rows.iter().map(registry_imported_issuer_from_row).collect()
    }

    async fn delete_registry_imported_issuer(
        &self,
        issuer_id: Uuid,
    ) -> Result<bool, TrustProfileRepositoryError> {
        Ok(
            sqlx::query("DELETE FROM trust_profile_service.trust_registry_issuers WHERE id=$1")
                .bind(issuer_id.to_string())
                .execute(&self.pool)
                .await
                .map_err(database)?
                .rows_affected()
                > 0,
        )
    }
}

fn framework_from_row(row: &PgRow) -> Result<TrustFramework, TrustProfileRepositoryError> {
    Ok(TrustFramework {
        id: uuid(row, "id")?,
        code: get(row, "code")?,
        display_name: get(row, "display_name")?,
        description: get(row, "description")?,
        pkd_endpoints: json_get(row, "pkd_endpoints")?,
        default_algorithms: json_get(row, "default_algorithms")?,
        default_formats: json_get(row, "default_formats")?,
        validation_ruleset: get(row, "validation_ruleset")?,
        sync_config: get(row, "sync_config")?,
        is_system: get(row, "is_system")?,
        created_at: get(row, "created_at")?,
        updated_at: get(row, "updated_at")?,
    })
}

fn organization_profile_from_row(
    row: &PgRow,
) -> Result<OrganizationTrustProfile, TrustProfileRepositoryError> {
    Ok(OrganizationTrustProfile {
        id: uuid(row, "id")?,
        organization_id: get(row, "organization_id")?,
        framework_id: uuid(row, "framework_id")?,
        name: get(row, "name")?,
        display_name: get(row, "display_name")?,
        description: get(row, "description")?,
        enabled: get(row, "enabled")?,
        use_case_tags: json_get(row, "use_case_tags")?,
        compliance_status: enum_get(row, "compliance_status")?,
        auto_generated: get(row, "auto_generated")?,
        revocation_policy: get(row, "revocation_policy")?,
        time_policy: get(row, "time_policy")?,
        allowed_algorithms: optional_json_get(row, "allowed_algorithms")?,
        allowed_formats: optional_json_get(row, "allowed_formats")?,
        allowed_issuers: optional_json_get(row, "allowed_issuers")?,
        denied_issuers: optional_json_get(row, "denied_issuers")?,
        jurisdiction_filter: optional_json_get(row, "jurisdiction_filter")?,
        metadata: get(row, "metadata")?,
        created_at: get(row, "created_at")?,
        updated_at: get(row, "updated_at")?,
    })
}

fn registry_entry_from_row(
    row: &PgRow,
) -> Result<crate::TrustRegistryEntry, TrustProfileRepositoryError> {
    Ok(crate::TrustRegistryEntry {
        id: uuid(row, "id")?,
        anchor_type: enum_get(row, "anchor_type")?,
        operation: enum_get::<RegistryOperation>(row, "operation")?,
        country_code: get(row, "country_code")?,
        certificate_pem: get(row, "certificate_pem")?,
        subject_key_id: get(row, "subject_key_id")?,
        not_before: get(row, "not_before")?,
        not_after: get(row, "not_after")?,
        source: enum_get::<RegistrySource>(row, "source")?,
        framework_code: get(row, "framework_code")?,
        sequence: u64_from_i32(get(row, "sequence")?, "sequence")?,
        is_current: get(row, "is_current")?,
        created_at: get(row, "created_at")?,
        updated_at: get(row, "updated_at")?,
    })
}

fn profile_from_row(row: &PgRow) -> Result<TrustProfile, TrustProfileRepositoryError> {
    TrustProfile::try_from(TrustProfileRecord {
        id: get(row, "id")?,
        organization_id: get(row, "organization_id")?,
        name: get(row, "name")?,
        description: get(row, "description")?,
        status: get(row, "status")?,
        trust_sources: get(row, "trust_sources")?,
        validation_rules: get(row, "validation_rules")?,
        revocation_policy: get(row, "revocation_policy")?,
        revocation_profile_id: get(row, "revocation_profile_id")?,
        time_policy: get(row, "time_policy")?,
        supported_formats: get(row, "supported_formats")?,
        created_at: get(row, "created_at")?,
        updated_at: get(row, "updated_at")?,
    })
    .map_err(|_| invalid("trust_profile"))
}

fn issuer_from_row(row: &PgRow) -> Result<IssuerEntity, TrustProfileRepositoryError> {
    Ok(IssuerEntity {
        id: uuid(row, "id")?,
        organization_id: get(row, "organization_id")?,
        issuer_id: get(row, "issuer_id")?,
        issuer_type: enum_get::<IssuerEntityType>(row, "issuer_type")?,
        display_name: get(row, "display_name")?,
        description: get(row, "description")?,
        is_system_issuer: get(row, "is_system_issuer")?,
        compliance_status: enum_get::<IssuerEntityComplianceStatus>(row, "compliance_status")?,
        accreditation_body: get(row, "accreditation_body")?,
        accreditations: json_get(row, "accreditations")?,
        accreditation_date: get(row, "accreditation_date")?,
        valid_from: get(row, "valid_from")?,
        valid_until: get(row, "valid_until")?,
        trust_anchor_id: get(row, "trust_anchor_id")?,
        revoked_at: get(row, "revoked_at")?,
        revocation_reason: get(row, "revocation_reason")?,
        revoked_by: get(row, "revoked_by")?,
        metadata: get(row, "metadata")?,
        created_at: get(row, "created_at")?,
        updated_at: get(row, "updated_at")?,
    })
}

fn profile_issuer_from_row(row: &PgRow) -> Result<TrustProfileIssuer, TrustProfileRepositoryError> {
    let trust_level: i32 = get(row, "trust_level")?;
    Ok(TrustProfileIssuer {
        id: uuid(row, "id")?,
        trust_profile_id: uuid(row, "trust_profile_id")?,
        issuer_id: uuid(row, "issuer_id")?,
        trust_level: u8::try_from(trust_level).map_err(|_| invalid("trust_level"))?,
        relationship_status: enum_get::<TrustRelationshipStatus>(row, "relationship_status")?,
        cascade_revocation_policy: enum_get(row, "cascade_revocation_policy")?,
        metadata: get(row, "metadata")?,
        created_at: get(row, "created_at")?,
        updated_at: get(row, "updated_at")?,
    })
}

fn registry_import_source_from_row(
    row: &PgRow,
) -> Result<RegistryImportSource, TrustProfileRepositoryError> {
    let sync_interval_hours: i32 = get(row, "sync_interval_hours")?;
    Ok(RegistryImportSource {
        id: uuid(row, "id")?,
        trust_profile_id: uuid(row, "trust_profile_id")?,
        registry_type: enum_get(row, "registry_type")?,
        registry_name: get(row, "registry_name")?,
        registry_url: get(row, "registry_url")?,
        enabled: get(row, "enabled")?,
        sync_enabled: get(row, "sync_enabled")?,
        last_synced_at: get(row, "last_synced_at")?,
        next_sync_at: get(row, "next_sync_at")?,
        sync_interval_hours: u16::try_from(sync_interval_hours)
            .map_err(|_| invalid("sync_interval_hours"))?,
        credential_format_filter: json_get(row, "credential_format_filter")?,
        metadata: get(row, "metadata")?,
        created_at: get(row, "created_at")?,
        updated_at: get(row, "updated_at")?,
    })
}

fn registry_imported_issuer_from_row(
    row: &PgRow,
) -> Result<RegistryImportedIssuer, TrustProfileRepositoryError> {
    Ok(RegistryImportedIssuer {
        id: uuid(row, "id")?,
        registry_source_id: uuid(row, "registry_source_id")?,
        trust_profile_id: uuid(row, "trust_profile_id")?,
        issuer_did: get(row, "issuer_did")?,
        issuer_name: get(row, "issuer_name")?,
        country_code: get(row, "country_code")?,
        issuer_type: get(row, "issuer_type")?,
        verification_keys: json_get(row, "verification_keys")?,
        credential_templates: json_get(row, "credential_templates")?,
        status: get(row, "status")?,
        imported_at: get(row, "imported_at")?,
        valid_from: get(row, "valid_from")?,
        valid_until: get(row, "valid_until")?,
        created_at: get(row, "created_at")?,
        updated_at: get(row, "updated_at")?,
    })
}

fn database(error: sqlx::Error) -> TrustProfileRepositoryError {
    TrustProfileRepositoryError::Database(error.to_string())
}

fn invalid(field: &'static str) -> TrustProfileRepositoryError {
    TrustProfileRepositoryError::InvalidData(field)
}

fn get<T>(row: &PgRow, field: &'static str) -> Result<T, TrustProfileRepositoryError>
where
    for<'r> T: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(field).map_err(database)
}

fn uuid(row: &PgRow, field: &'static str) -> Result<Uuid, TrustProfileRepositoryError> {
    Uuid::parse_str(&get::<String>(row, field)?).map_err(|_| invalid(field))
}

fn enum_get<T: DeserializeOwned>(
    row: &PgRow,
    field: &'static str,
) -> Result<T, TrustProfileRepositoryError> {
    let value: String = get(row, field)?;
    serde_json::from_value(Value::String(value)).map_err(|_| invalid(field))
}

fn json_get<T: DeserializeOwned>(
    row: &PgRow,
    field: &'static str,
) -> Result<T, TrustProfileRepositoryError> {
    serde_json::from_value(get(row, field)?).map_err(|_| invalid(field))
}

fn optional_json_get<T: DeserializeOwned>(
    row: &PgRow,
    field: &'static str,
) -> Result<Option<T>, TrustProfileRepositoryError> {
    get::<Option<Value>>(row, field)?
        .map(|value| serde_json::from_value(value).map_err(|_| invalid(field)))
        .transpose()
}

fn json<T: Serialize>(
    value: &T,
    field: &'static str,
) -> Result<Value, TrustProfileRepositoryError> {
    serde_json::to_value(value).map_err(|_| invalid(field))
}

fn option_json<T: Serialize>(
    value: &Option<T>,
    field: &'static str,
) -> Result<Option<Value>, TrustProfileRepositoryError> {
    value.as_ref().map(|value| json(value, field)).transpose()
}

fn text<T: Serialize>(
    value: &T,
    field: &'static str,
) -> Result<String, TrustProfileRepositoryError> {
    json(value, field)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid(field))
}

fn usize_from_i64(value: i64, field: &'static str) -> Result<usize, TrustProfileRepositoryError> {
    usize::try_from(value).map_err(|_| invalid(field))
}

fn u64_from_i32(value: i32, field: &'static str) -> Result<u64, TrustProfileRepositoryError> {
    u64::try_from(value).map_err(|_| invalid(field))
}
