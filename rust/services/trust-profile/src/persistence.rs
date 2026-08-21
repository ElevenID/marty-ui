use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    ComplianceStatus, RevocationPolicy, TimePolicy, TrustProfile, TrustProfileStatus,
    TrustProfileType, TrustSource, ValidationRules,
};

pub const TRUST_PROFILE_MIGRATION: &str =
    include_str!("../migrations/0001_trust_profile_schema.sql");

#[derive(Clone, Debug, PartialEq)]
pub struct TrustProfileRecord {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    pub trust_sources: Value,
    pub validation_rules: Value,
    pub revocation_policy: Value,
    pub revocation_profile_id: Option<String>,
    pub time_policy: Value,
    pub supported_formats: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TrustProfileRecordError {
    #[error("TRUST_PROFILE.INVALID_PERSISTED_ID: {0}")]
    InvalidId(&'static str),
    #[error("TRUST_PROFILE.INVALID_PERSISTED_FIELD: {0}")]
    InvalidField(&'static str),
}

impl TryFrom<&TrustProfile> for TrustProfileRecord {
    type Error = TrustProfileRecordError;

    fn try_from(profile: &TrustProfile) -> Result<Self, Self::Error> {
        let mut validation_rules = object(&profile.validation_rules, "validation_rules")?;
        validation_rules.insert(
            "profile_type".into(),
            json(&profile.profile_type, "profile_type")?,
        );
        validation_rules.insert(
            "compliance_status".into(),
            json(&profile.compliance_status, "compliance_status")?,
        );
        validation_rules.insert(
            "allowed_issuers".into(),
            json(&profile.allowed_issuers, "allowed_issuers")?,
        );
        validation_rules.insert(
            "denied_issuers".into(),
            json(&profile.denied_issuers, "denied_issuers")?,
        );
        validation_rules.insert(
            "system_issuer_overrides".into(),
            Value::Object(profile.system_issuer_overrides.clone()),
        );
        validation_rules.insert(
            "compatible_compliance_codes".into(),
            json(
                &profile.compatible_compliance_codes,
                "compatible_compliance_codes",
            )?,
        );
        validation_rules.insert(
            "verification_policy_set_id".into(),
            json(
                &profile.verification_policy_set_id,
                "verification_policy_set_id",
            )?,
        );
        validation_rules.insert("auto_generated".into(), Value::Bool(profile.auto_generated));

        Ok(Self {
            id: profile.id.to_string(),
            organization_id: profile.organization_id.clone(),
            name: profile.name.clone(),
            description: profile.description.clone(),
            status: text(&profile.status, "status")?,
            trust_sources: json(&profile.trust_sources, "trust_sources")?,
            validation_rules: Value::Object(validation_rules),
            revocation_policy: json(&profile.revocation_policy, "revocation_policy")?,
            revocation_profile_id: profile.revocation_profile_id.clone(),
            time_policy: json(&profile.time_policy, "time_policy")?,
            supported_formats: json(&profile.supported_formats, "supported_formats")?,
            created_at: profile.created_at,
            updated_at: profile.updated_at,
        })
    }
}

impl TryFrom<TrustProfileRecord> for TrustProfile {
    type Error = TrustProfileRecordError;

    fn try_from(record: TrustProfileRecord) -> Result<Self, Self::Error> {
        let mut validation = record
            .validation_rules
            .as_object()
            .cloned()
            .ok_or(TrustProfileRecordError::InvalidField("validation_rules"))?;
        let profile_type =
            optional(&validation, "profile_type")?.unwrap_or(TrustProfileType::Custom);
        let compliance_status =
            optional(&validation, "compliance_status")?.unwrap_or(ComplianceStatus::SetupRequired);
        let system_issuer_overrides = validation
            .get("system_issuer_overrides")
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new()))
            .as_object()
            .cloned()
            .ok_or(TrustProfileRecordError::InvalidField(
                "system_issuer_overrides",
            ))?;

        apply_defaults(
            &mut validation,
            &ValidationRules::default(),
            "validation_rules",
        )?;
        let trust_sources = trust_sources(record.trust_sources)?;
        let revocation_policy = with_defaults(
            record.revocation_policy,
            &RevocationPolicy::default(),
            "revocation_policy",
        )?;
        let time_policy = with_defaults(record.time_policy, &TimePolicy::default(), "time_policy")?;
        let supported_formats = supported_formats(record.supported_formats)?;

        Ok(Self {
            id: Uuid::parse_str(&record.id)
                .map_err(|_| TrustProfileRecordError::InvalidId("id"))?,
            organization_id: record.organization_id,
            name: record.name,
            description: record.description,
            status: parse(Value::String(record.status), "status")
                .unwrap_or(TrustProfileStatus::Draft),
            profile_type,
            compliance_status,
            trust_sources,
            validation_rules: parse(Value::Object(validation.clone()), "validation_rules")?,
            allowed_issuers: optional(&validation, "allowed_issuers")?,
            denied_issuers: optional(&validation, "denied_issuers")?,
            system_issuer_overrides,
            compatible_compliance_codes: optional(&validation, "compatible_compliance_codes")?
                .unwrap_or_default(),
            verification_policy_set_id: optional(&validation, "verification_policy_set_id")?,
            auto_generated: optional(&validation, "auto_generated")?.unwrap_or(false),
            revocation_policy,
            revocation_profile_id: record.revocation_profile_id,
            time_policy,
            supported_formats,
            created_at: record.created_at,
            updated_at: record.updated_at,
        })
    }
}

fn trust_sources(value: Value) -> Result<Vec<TrustSource>, TrustProfileRecordError> {
    let sources = value
        .as_array()
        .ok_or(TrustProfileRecordError::InvalidField("trust_sources"))?;
    sources
        .iter()
        .map(|source| {
            let mut source = source
                .as_object()
                .cloned()
                .ok_or(TrustProfileRecordError::InvalidField("trust_sources"))?;
            let issuer_did = source.get("issuer_did").and_then(Value::as_str);
            let name = source
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .or(issuer_did)
                .unwrap_or("Trust Source")
                .to_owned();
            if source
                .get("id")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                source.insert("id".into(), Value::String(Uuid::new_v4().to_string()));
            }
            source.insert("name".into(), Value::String(name));
            if source
                .get("source_type")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                source.insert("source_type".into(), Value::String("TRUST_LIST".into()));
            }
            source
                .entry("pinned_certificates")
                .or_insert_with(|| Value::Array(Vec::new()));
            source
                .entry("refresh_interval_hours")
                .or_insert(Value::from(24));
            source.entry("enabled").or_insert(Value::Bool(true));
            source.entry("registry_sequence").or_insert(Value::from(0));
            if !source.get("registry_entries").is_some_and(Value::is_object) {
                source.insert("registry_entries".into(), Value::Object(Map::new()));
            }
            parse(Value::Object(source), "trust_sources")
        })
        .collect()
}

fn supported_formats(value: Value) -> Result<Vec<String>, TrustProfileRecordError> {
    let values: Vec<String> = parse(value, "supported_formats")?;
    let mut supported: Vec<String> = values
        .into_iter()
        .filter(|format| {
            matches!(
                format.as_str(),
                "SD_JWT_VC" | "MDOC" | "VC_JWT" | "JSON_LD" | "VDS_NC"
            )
        })
        .collect();
    if supported.is_empty() {
        supported.push("MDOC".into());
    }
    Ok(supported)
}

fn with_defaults<T>(
    value: Value,
    defaults: &T,
    name: &'static str,
) -> Result<T, TrustProfileRecordError>
where
    T: DeserializeOwned + Serialize,
{
    let mut value = value
        .as_object()
        .cloned()
        .ok_or(TrustProfileRecordError::InvalidField(name))?;
    apply_defaults(&mut value, defaults, name)?;
    parse(Value::Object(value), name)
}

fn apply_defaults<T: Serialize>(
    value: &mut Map<String, Value>,
    defaults: &T,
    name: &'static str,
) -> Result<(), TrustProfileRecordError> {
    for (key, default) in object(defaults, name)? {
        value.entry(key).or_insert(default);
    }
    Ok(())
}

fn json<T: Serialize>(value: &T, name: &'static str) -> Result<Value, TrustProfileRecordError> {
    serde_json::to_value(value).map_err(|_| TrustProfileRecordError::InvalidField(name))
}

fn object<T: Serialize>(
    value: &T,
    name: &'static str,
) -> Result<Map<String, Value>, TrustProfileRecordError> {
    json(value, name)?
        .as_object()
        .cloned()
        .ok_or(TrustProfileRecordError::InvalidField(name))
}

fn text<T: Serialize>(value: &T, name: &'static str) -> Result<String, TrustProfileRecordError> {
    json(value, name)?
        .as_str()
        .map(str::to_owned)
        .ok_or(TrustProfileRecordError::InvalidField(name))
}

fn parse<T: DeserializeOwned>(
    value: Value,
    name: &'static str,
) -> Result<T, TrustProfileRecordError> {
    serde_json::from_value(value).map_err(|_| TrustProfileRecordError::InvalidField(name))
}

fn optional<T: DeserializeOwned>(
    values: &Map<String, Value>,
    name: &'static str,
) -> Result<Option<T>, TrustProfileRecordError> {
    let Some(value) = values.get(name) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    parse(value.clone(), name).map(Some)
}
