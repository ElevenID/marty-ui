use std::collections::BTreeMap;

use chrono::Utc;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sqlx::{postgres::PgRow, PgPool, Row};
use thiserror::Error;

use crate::persistence::{
    ClaimDefinition, CredentialTemplate, DeliveryDestinationEntry, DerivedAttribute, DisplayStyle,
    IssuerRequirements, MergeStrategy, PrivacyPosture, TemplateStatus, ValidityRules,
    WalletRegistryEntry,
};
use crate::CredentialFormat;

#[derive(Debug, Error)]
pub enum CredentialTemplateRepositoryError {
    #[error("CREDENTIAL_TEMPLATE.REPOSITORY_DATABASE: {0}")]
    Database(#[from] sqlx::Error),
    #[error("CREDENTIAL_TEMPLATE.REPOSITORY_INVALID_DATA: {field}={value}")]
    InvalidData { field: &'static str, value: String },
}

#[derive(Clone, Debug)]
pub struct PostgresCredentialTemplateStore {
    pool: PgPool,
}

impl PostgresCredentialTemplateStore {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn save_template(
        &self,
        template: &CredentialTemplate,
    ) -> Result<(), CredentialTemplateRepositoryError> {
        let claims = json_value("claims", &template.claims)?;
        let selective_disclosure_fields = json_value(
            "selective_disclosure_fields",
            &template.selective_disclosure_fields,
        )?;
        let zk_predicate_claims = json_value("zk_predicate_claims", &template.zk_predicate_claims)?;
        let derived_attributes = json_value("derived_attributes", &template.derived_attributes)?;
        let display_style = json_value("display_style", &template.display_style)?;
        let validity_rules = json_value("validity_rules", &template.validity_rules)?;
        let issuer_requirements = json_value("issuer_requirements", &template.issuer_requirements)?;
        let supported_formats = Value::Array(
            template
                .supported_formats
                .iter()
                .map(|format| Value::String(format.canonical().to_owned()))
                .collect(),
        );
        let wallet_configs = json_value("wallet_configs", &template.wallet_configs)?;

        sqlx::query(
            "INSERT INTO credential_template_service.credential_templates (
                id, organization_id, name, description, status, credential_type, vct, doctype,
                claims, privacy_posture, selective_disclosure_fields, zk_predicate_claims,
                derived_attributes, display_style, validity_rules, issuer_requirements,
                supported_formats, credential_payload_format, wallet_configs, compliance_profile,
                compliance_profile_id, application_template_id, trust_profile_id,
                revocation_profile_id, issuer_algorithm, issuer_did, issuance_protocol, version,
                created_at, updated_at
             ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
                $21,$22,$23,$24,$25,$26,$27,$28,$29,$30
             ) ON CONFLICT (id) DO UPDATE SET
                organization_id=EXCLUDED.organization_id, name=EXCLUDED.name,
                description=EXCLUDED.description, status=EXCLUDED.status,
                credential_type=EXCLUDED.credential_type, vct=EXCLUDED.vct,
                doctype=EXCLUDED.doctype, claims=EXCLUDED.claims,
                privacy_posture=EXCLUDED.privacy_posture,
                selective_disclosure_fields=EXCLUDED.selective_disclosure_fields,
                zk_predicate_claims=EXCLUDED.zk_predicate_claims,
                derived_attributes=EXCLUDED.derived_attributes,
                display_style=EXCLUDED.display_style, validity_rules=EXCLUDED.validity_rules,
                issuer_requirements=EXCLUDED.issuer_requirements,
                supported_formats=EXCLUDED.supported_formats,
                credential_payload_format=EXCLUDED.credential_payload_format,
                wallet_configs=EXCLUDED.wallet_configs,
                compliance_profile=EXCLUDED.compliance_profile,
                compliance_profile_id=EXCLUDED.compliance_profile_id,
                application_template_id=EXCLUDED.application_template_id,
                trust_profile_id=EXCLUDED.trust_profile_id,
                revocation_profile_id=EXCLUDED.revocation_profile_id,
                issuer_algorithm=EXCLUDED.issuer_algorithm, issuer_did=EXCLUDED.issuer_did,
                issuance_protocol=EXCLUDED.issuance_protocol, version=EXCLUDED.version,
                updated_at=EXCLUDED.updated_at",
        )
        .bind(&template.id)
        .bind(&template.organization_id)
        .bind(&template.name)
        .bind(&template.description)
        .bind(template.status.as_str())
        .bind(&template.credential_type)
        .bind(&template.vct)
        .bind(&template.doctype)
        .bind(claims)
        .bind(template.privacy_posture.as_str())
        .bind(selective_disclosure_fields)
        .bind(zk_predicate_claims)
        .bind(derived_attributes)
        .bind(display_style)
        .bind(validity_rules)
        .bind(issuer_requirements)
        .bind(supported_formats)
        .bind(&template.credential_payload_format)
        .bind(wallet_configs)
        .bind(&template.compliance_profile)
        .bind(&template.compliance_profile_id)
        .bind(&template.application_template_id)
        .bind(&template.trust_profile_id)
        .bind(&template.revocation_profile_id)
        .bind(&template.issuer_algorithm)
        .bind(&template.issuer_did)
        .bind(&template.issuance_protocol)
        .bind(template.version)
        .bind(template.created_at)
        .bind(template.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn template_by_id(
        &self,
        template_id: &str,
    ) -> Result<Option<CredentialTemplate>, CredentialTemplateRepositoryError> {
        let row = sqlx::query(
            "SELECT * FROM credential_template_service.credential_templates WHERE id=$1",
        )
        .bind(template_id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(template_from_row).transpose()
    }

    pub async fn templates_by_organization(
        &self,
        organization_id: &str,
        status: Option<TemplateStatus>,
    ) -> Result<Vec<CredentialTemplate>, CredentialTemplateRepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM credential_template_service.credential_templates
             WHERE organization_id=$1 AND ($2::text IS NULL OR status=$2)
             ORDER BY created_at, id",
        )
        .bind(organization_id)
        .bind(status.map(TemplateStatus::as_str))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(template_from_row).collect()
    }

    pub async fn templates_all_internal(
        &self,
        status: Option<TemplateStatus>,
    ) -> Result<Vec<CredentialTemplate>, CredentialTemplateRepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM credential_template_service.credential_templates
             WHERE ($1::text IS NULL OR status=$1) ORDER BY created_at, id",
        )
        .bind(status.map(TemplateStatus::as_str))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(template_from_row).collect()
    }

    pub async fn delete_template(
        &self,
        template_id: &str,
    ) -> Result<bool, CredentialTemplateRepositoryError> {
        Ok(
            sqlx::query("DELETE FROM credential_template_service.credential_templates WHERE id=$1")
                .bind(template_id)
                .execute(&self.pool)
                .await?
                .rows_affected()
                > 0,
        )
    }

    pub async fn save_wallet(
        &self,
        wallet: &WalletRegistryEntry,
    ) -> Result<(), CredentialTemplateRepositoryError> {
        sqlx::query(
            "INSERT INTO credential_template_service.wallet_registry (
                id, organization_id, is_override, override_precedence, merge_strategy,
                credential_format, issuance_protocol, compliance_profile_code, name, description,
                wallet_apps, specifications, logo_url, deep_link_template, routing_templates,
                install_urls, ios_scheme, universal_link_template, android_package,
                supported_formats, supported_protocols, platforms, supports_qr,
                supports_deeplink, supports_digital_credentials, supports_haip, docs_url,
                is_active, created_at, updated_at
             ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
                $21,$22,$23,$24,$25,$26,$27,$28,$29,$30
             ) ON CONFLICT (id) DO UPDATE SET
                organization_id=EXCLUDED.organization_id, is_override=EXCLUDED.is_override,
                override_precedence=EXCLUDED.override_precedence,
                merge_strategy=EXCLUDED.merge_strategy,
                credential_format=EXCLUDED.credential_format,
                issuance_protocol=EXCLUDED.issuance_protocol,
                compliance_profile_code=EXCLUDED.compliance_profile_code,
                name=EXCLUDED.name, description=EXCLUDED.description,
                wallet_apps=EXCLUDED.wallet_apps, specifications=EXCLUDED.specifications,
                logo_url=EXCLUDED.logo_url, deep_link_template=EXCLUDED.deep_link_template,
                routing_templates=EXCLUDED.routing_templates, install_urls=EXCLUDED.install_urls,
                ios_scheme=EXCLUDED.ios_scheme,
                universal_link_template=EXCLUDED.universal_link_template,
                android_package=EXCLUDED.android_package,
                supported_formats=EXCLUDED.supported_formats,
                supported_protocols=EXCLUDED.supported_protocols, platforms=EXCLUDED.platforms,
                supports_qr=EXCLUDED.supports_qr,
                supports_deeplink=EXCLUDED.supports_deeplink,
                supports_digital_credentials=EXCLUDED.supports_digital_credentials,
                supports_haip=EXCLUDED.supports_haip, docs_url=EXCLUDED.docs_url,
                is_active=EXCLUDED.is_active, updated_at=EXCLUDED.updated_at",
        )
        .bind(&wallet.id)
        .bind(&wallet.organization_id)
        .bind(wallet.is_override)
        .bind(wallet.override_precedence)
        .bind(wallet.merge_strategy.as_str())
        .bind(&wallet.credential_format)
        .bind(&wallet.issuance_protocol)
        .bind(&wallet.compliance_profile_code)
        .bind(&wallet.name)
        .bind(&wallet.description)
        .bind(json_value("wallet_apps", &wallet.wallet_apps)?)
        .bind(json_value("specifications", &wallet.specifications)?)
        .bind(&wallet.logo_url)
        .bind(&wallet.deep_link_template)
        .bind(json_value("routing_templates", &wallet.routing_templates)?)
        .bind(json_value("install_urls", &wallet.install_urls)?)
        .bind(&wallet.ios_scheme)
        .bind(&wallet.universal_link_template)
        .bind(&wallet.android_package)
        .bind(json_value("supported_formats", &wallet.supported_formats)?)
        .bind(json_value(
            "supported_protocols",
            &wallet.supported_protocols,
        )?)
        .bind(json_value("platforms", &wallet.platforms)?)
        .bind(wallet.supports_qr)
        .bind(wallet.supports_deeplink)
        .bind(wallet.supports_digital_credentials)
        .bind(wallet.supports_haip)
        .bind(&wallet.docs_url)
        .bind(wallet.is_active)
        .bind(wallet.created_at)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn wallet_by_id(
        &self,
        wallet_id: &str,
    ) -> Result<Option<WalletRegistryEntry>, CredentialTemplateRepositoryError> {
        let row =
            sqlx::query("SELECT * FROM credential_template_service.wallet_registry WHERE id=$1")
                .bind(wallet_id)
                .fetch_optional(&self.pool)
                .await?;
        row.as_ref().map(wallet_from_row).transpose()
    }

    pub async fn wallets(
        &self,
        active_only: bool,
    ) -> Result<Vec<WalletRegistryEntry>, CredentialTemplateRepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM credential_template_service.wallet_registry
             WHERE ($1=false OR is_active=true) ORDER BY lower(name), id",
        )
        .bind(active_only)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(wallet_from_row).collect()
    }

    pub async fn delete_wallet(
        &self,
        wallet_id: &str,
    ) -> Result<bool, CredentialTemplateRepositoryError> {
        Ok(
            sqlx::query("DELETE FROM credential_template_service.wallet_registry WHERE id=$1")
                .bind(wallet_id)
                .execute(&self.pool)
                .await?
                .rows_affected()
                > 0,
        )
    }

    pub async fn save_destination(
        &self,
        destination: &DeliveryDestinationEntry,
    ) -> Result<(), CredentialTemplateRepositoryError> {
        sqlx::query(
            "INSERT INTO credential_template_service.delivery_destinations (
                id, organization_id, is_system, name, description, provider, mode, setup_actor,
                delivery_target, wallet_profile_id, credential_format, issuance_protocol,
                compliance_profile_code, connector_type, connector_id, requires_consent,
                claim_projection_policy, setup_requirements, capabilities, docs_url, is_enabled,
                created_at, updated_at
             ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
                $21,$22,$23
             ) ON CONFLICT (id) DO UPDATE SET
                organization_id=EXCLUDED.organization_id, is_system=EXCLUDED.is_system,
                name=EXCLUDED.name, description=EXCLUDED.description,
                provider=EXCLUDED.provider, mode=EXCLUDED.mode, setup_actor=EXCLUDED.setup_actor,
                delivery_target=EXCLUDED.delivery_target,
                wallet_profile_id=EXCLUDED.wallet_profile_id,
                credential_format=EXCLUDED.credential_format,
                issuance_protocol=EXCLUDED.issuance_protocol,
                compliance_profile_code=EXCLUDED.compliance_profile_code,
                connector_type=EXCLUDED.connector_type, connector_id=EXCLUDED.connector_id,
                requires_consent=EXCLUDED.requires_consent,
                claim_projection_policy=EXCLUDED.claim_projection_policy,
                setup_requirements=EXCLUDED.setup_requirements,
                capabilities=EXCLUDED.capabilities, docs_url=EXCLUDED.docs_url,
                is_enabled=EXCLUDED.is_enabled, updated_at=EXCLUDED.updated_at",
        )
        .bind(&destination.id)
        .bind(&destination.organization_id)
        .bind(destination.is_system)
        .bind(&destination.name)
        .bind(&destination.description)
        .bind(&destination.provider)
        .bind(&destination.mode)
        .bind(&destination.setup_actor)
        .bind(&destination.delivery_target)
        .bind(&destination.wallet_profile_id)
        .bind(&destination.credential_format)
        .bind(&destination.issuance_protocol)
        .bind(&destination.compliance_profile_code)
        .bind(&destination.connector_type)
        .bind(&destination.connector_id)
        .bind(destination.requires_consent)
        .bind(&destination.claim_projection_policy)
        .bind(json_value(
            "setup_requirements",
            &destination.setup_requirements,
        )?)
        .bind(json_value("capabilities", &destination.capabilities)?)
        .bind(&destination.docs_url)
        .bind(destination.is_enabled)
        .bind(destination.created_at)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn destination_by_id(
        &self,
        destination_id: &str,
    ) -> Result<Option<DeliveryDestinationEntry>, CredentialTemplateRepositoryError> {
        let row = sqlx::query(
            "SELECT * FROM credential_template_service.delivery_destinations WHERE id=$1",
        )
        .bind(destination_id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(destination_from_row).transpose()
    }

    pub async fn destinations(
        &self,
        active_only: bool,
        organization_id: Option<&str>,
        provider: Option<&str>,
        mode: Option<&str>,
    ) -> Result<Vec<DeliveryDestinationEntry>, CredentialTemplateRepositoryError> {
        let rows = sqlx::query(
            "SELECT * FROM credential_template_service.delivery_destinations
             WHERE ($1=false OR is_enabled=true)
               AND ($2::text IS NULL OR organization_id=$2 OR is_system=true)
               AND ($3::text IS NULL OR provider=$3)
               AND ($4::text IS NULL OR mode=$4)
             ORDER BY CASE WHEN is_system THEN 0 ELSE 1 END, lower(name), id",
        )
        .bind(active_only)
        .bind(organization_id)
        .bind(provider)
        .bind(mode)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(destination_from_row).collect()
    }

    pub async fn delete_destination(
        &self,
        destination_id: &str,
    ) -> Result<bool, CredentialTemplateRepositoryError> {
        Ok(
            sqlx::query(
                "DELETE FROM credential_template_service.delivery_destinations WHERE id=$1",
            )
            .bind(destination_id)
            .execute(&self.pool)
            .await?
            .rows_affected()
                > 0,
        )
    }
}

fn template_from_row(row: &PgRow) -> Result<CredentialTemplate, CredentialTemplateRepositoryError> {
    let template_id: String = row.try_get("id")?;
    let claims_value: Value = row.try_get("claims")?;
    let claims = claims_value
        .as_array()
        .ok_or_else(|| invalid_data("claims", claims_value.to_string()))?
        .iter()
        .enumerate()
        .map(|(index, claim)| {
            ClaimDefinition::from_legacy_value(&template_id, index, claim)
                .map_err(|error| invalid_data("claims", error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let supported_formats_value: Value = row.try_get("supported_formats")?;
    let supported_formats = decode::<Vec<String>>("supported_formats", supported_formats_value)?
        .into_iter()
        .filter_map(|value| CredentialFormat::parse(&value).ok())
        .collect();
    let status: String = row.try_get("status")?;
    let privacy_posture: String = row.try_get("privacy_posture")?;
    Ok(CredentialTemplate {
        id: template_id,
        organization_id: row.try_get("organization_id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        status: TemplateStatus::parse(&status)
            .map_err(|error| invalid_data("status", error.to_string()))?,
        credential_type: row.try_get("credential_type")?,
        vct: row.try_get("vct")?,
        doctype: row.try_get("doctype")?,
        claims,
        privacy_posture: PrivacyPosture::parse(&privacy_posture)
            .map_err(|error| invalid_data("privacy_posture", error.to_string()))?,
        selective_disclosure_fields: decode_row(row, "selective_disclosure_fields")?,
        zk_predicate_claims: decode_row_or_default(row, "zk_predicate_claims")?,
        derived_attributes: decode_row::<Vec<DerivedAttribute>>(row, "derived_attributes")?,
        display_style: decode_row_default::<DisplayStyle>(row, "display_style")?,
        validity_rules: decode_row_default::<ValidityRules>(row, "validity_rules")?,
        issuer_requirements: decode_row_default::<IssuerRequirements>(row, "issuer_requirements")?,
        supported_formats,
        credential_payload_format: row.try_get("credential_payload_format")?,
        wallet_configs: decode_row_or_default(row, "wallet_configs")?,
        compliance_profile: row.try_get("compliance_profile")?,
        compliance_profile_id: row.try_get("compliance_profile_id")?,
        application_template_id: row.try_get("application_template_id")?,
        trust_profile_id: row.try_get("trust_profile_id")?,
        revocation_profile_id: row.try_get("revocation_profile_id")?,
        issuer_algorithm: row.try_get("issuer_algorithm")?,
        issuer_did: row.try_get("issuer_did")?,
        issuance_protocol: row.try_get("issuance_protocol")?,
        version: row.try_get("version")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn wallet_from_row(row: &PgRow) -> Result<WalletRegistryEntry, CredentialTemplateRepositoryError> {
    let strategy: String = row.try_get("merge_strategy")?;
    Ok(WalletRegistryEntry {
        id: row.try_get("id")?,
        organization_id: row.try_get("organization_id")?,
        is_override: row.try_get("is_override")?,
        override_precedence: row.try_get("override_precedence")?,
        merge_strategy: MergeStrategy::parse(&strategy)
            .map_err(|error| invalid_data("merge_strategy", error.to_string()))?,
        credential_format: row.try_get("credential_format")?,
        issuance_protocol: row.try_get("issuance_protocol")?,
        compliance_profile_code: row.try_get("compliance_profile_code")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        wallet_apps: decode_row(row, "wallet_apps")?,
        specifications: decode_row(row, "specifications")?,
        logo_url: row.try_get("logo_url")?,
        deep_link_template: row.try_get("deep_link_template")?,
        routing_templates: decode_row(row, "routing_templates")?,
        install_urls: decode_row(row, "install_urls")?,
        ios_scheme: row.try_get("ios_scheme")?,
        universal_link_template: row.try_get("universal_link_template")?,
        android_package: row.try_get("android_package")?,
        supported_formats: decode_row(row, "supported_formats")?,
        supported_protocols: decode_row(row, "supported_protocols")?,
        platforms: decode_row(row, "platforms")?,
        supports_qr: row.try_get("supports_qr")?,
        supports_deeplink: row.try_get("supports_deeplink")?,
        supports_digital_credentials: row.try_get("supports_digital_credentials")?,
        supports_haip: row.try_get("supports_haip")?,
        docs_url: row.try_get("docs_url")?,
        is_active: row.try_get("is_active")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn destination_from_row(
    row: &PgRow,
) -> Result<DeliveryDestinationEntry, CredentialTemplateRepositoryError> {
    Ok(DeliveryDestinationEntry {
        id: row.try_get("id")?,
        organization_id: row.try_get("organization_id")?,
        is_system: row.try_get("is_system")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        provider: row.try_get("provider")?,
        mode: row.try_get("mode")?,
        setup_actor: row.try_get("setup_actor")?,
        delivery_target: row.try_get("delivery_target")?,
        wallet_profile_id: row.try_get("wallet_profile_id")?,
        credential_format: row.try_get("credential_format")?,
        issuance_protocol: row.try_get("issuance_protocol")?,
        compliance_profile_code: row.try_get("compliance_profile_code")?,
        connector_type: row.try_get("connector_type")?,
        connector_id: row.try_get("connector_id")?,
        requires_consent: row.try_get("requires_consent")?,
        claim_projection_policy: row.try_get("claim_projection_policy")?,
        setup_requirements: decode_row(row, "setup_requirements")?,
        capabilities: decode_row::<BTreeMap<String, bool>>(row, "capabilities")?,
        docs_url: row.try_get("docs_url")?,
        is_enabled: row.try_get("is_enabled")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn json_value<T: serde::Serialize>(
    field: &'static str,
    value: &T,
) -> Result<Value, CredentialTemplateRepositoryError> {
    serde_json::to_value(value).map_err(|error| invalid_data(field, error.to_string()))
}

fn decode_row<T: DeserializeOwned>(
    row: &PgRow,
    field: &'static str,
) -> Result<T, CredentialTemplateRepositoryError> {
    decode(field, row.try_get(field)?)
}

fn decode_row_default<T: Default + DeserializeOwned>(
    row: &PgRow,
    field: &'static str,
) -> Result<T, CredentialTemplateRepositoryError> {
    let value: Value = row.try_get(field)?;
    if value.as_object().is_some_and(serde_json::Map::is_empty) {
        return Ok(T::default());
    }
    decode(field, value)
}

fn decode_row_or_default<T: Default + DeserializeOwned>(
    row: &PgRow,
    field: &'static str,
) -> Result<T, CredentialTemplateRepositoryError> {
    let value: Option<Value> = row.try_get(field)?;
    value.map_or_else(|| Ok(T::default()), |value| decode(field, value))
}

fn decode<T: DeserializeOwned>(
    field: &'static str,
    value: Value,
) -> Result<T, CredentialTemplateRepositoryError> {
    serde_json::from_value(value.clone())
        .map_err(|error| invalid_data(field, format!("{value}: {error}")))
}

fn invalid_data(field: &'static str, value: String) -> CredentialTemplateRepositoryError {
    CredentialTemplateRepositoryError::InvalidData { field, value }
}
