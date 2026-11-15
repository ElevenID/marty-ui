// SPDX-License-Identifier: AGPL-3.0-only
//! Production-shaped authority adapter for the external observation journal.
//!
//! All authority records are in the same PostgreSQL database and transaction.
//! The adapter locks the canonical API key, producer grant, binding and
//! application in that order. Key revocation and authority changes therefore
//! serialize with observation admission; no stale cache or remote allow check.

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use crate::external_observation_admission::{
    ApplicationSnapshot, AuthenticatedApiKey, ClaimKind, ClaimRule, EvidenceBinding,
    ProducerGrant, MAX_SAFE_INTEGER,
};
use crate::external_observation_postgres::{
    JournalError, LockedAuthority, ObservationAuthority, ProducerIdentity,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredClaimRule {
    kind: String,
    required: bool,
    nullable: bool,
    minimum: Option<f64>,
    maximum: Option<f64>,
    max_bytes: Option<usize>,
}

fn database_error(error: sqlx::Error) -> JournalError {
    match error
        .as_database_error()
        .and_then(|value| value.code())
        .as_deref()
    {
        Some("40001" | "40P01" | "55P03") => JournalError::Conflict,
        _ => JournalError::Unavailable,
    }
}

fn revision(value: DateTime<Utc>) -> Result<u64, JournalError> {
    let micros = value.timestamp_micros();
    let result = u64::try_from(micros).map_err(|_| JournalError::InvalidStoredState)?;
    if result == 0 || result > MAX_SAFE_INTEGER {
        return Err(JournalError::InvalidStoredState);
    }
    Ok(result)
}

fn expiry_ms(value: Option<DateTime<Utc>>) -> Result<u64, JournalError> {
    let Some(value) = value else {
        return Ok(MAX_SAFE_INTEGER);
    };
    let millis = value.timestamp_millis();
    let result = u64::try_from(millis).map_err(|_| JournalError::InvalidStoredState)?;
    if result == 0 || result > MAX_SAFE_INTEGER {
        return Err(JournalError::InvalidStoredState);
    }
    Ok(result)
}

fn positive_i64(value: i64) -> Result<u64, JournalError> {
    let result = u64::try_from(value).map_err(|_| JournalError::InvalidStoredState)?;
    if result == 0 || result > MAX_SAFE_INTEGER {
        return Err(JournalError::InvalidStoredState);
    }
    Ok(result)
}

fn parse_claim_rules(value: serde_json::Value) -> Result<BTreeMap<String, ClaimRule>, JournalError> {
    let stored: BTreeMap<String, StoredClaimRule> =
        serde_json::from_value(value).map_err(|_| JournalError::InvalidStoredState)?;
    let mut rules = BTreeMap::new();
    for (name, rule) in stored {
        let kind = match rule.kind.as_str() {
            "boolean" if rule.minimum.is_none() && rule.maximum.is_none() && rule.max_bytes.is_none() => {
                ClaimKind::Boolean
            }
            "number" if rule.max_bytes.is_none() => {
                let minimum = rule.minimum.ok_or(JournalError::InvalidStoredState)?;
                let maximum = rule.maximum.ok_or(JournalError::InvalidStoredState)?;
                if !minimum.is_finite() || !maximum.is_finite() || minimum > maximum {
                    return Err(JournalError::InvalidStoredState);
                }
                ClaimKind::Number { minimum, maximum }
            }
            "text" if rule.minimum.is_none() && rule.maximum.is_none() => {
                let max_bytes = rule.max_bytes.ok_or(JournalError::InvalidStoredState)?;
                if !(1..=512).contains(&max_bytes) {
                    return Err(JournalError::InvalidStoredState);
                }
                ClaimKind::Text { max_bytes }
            }
            _ => return Err(JournalError::InvalidStoredState),
        };
        rules.insert(name, ClaimRule {
            kind,
            required: rule.required,
            nullable: rule.nullable,
        });
    }
    if rules.is_empty() || rules.len() > 32 {
        return Err(JournalError::InvalidStoredState);
    }
    Ok(rules)
}

async fn database_clock_ms(connection: &mut PgConnection) -> Result<u64, JournalError> {
    let value = sqlx::query_scalar::<_, i64>(
        "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
    )
    .fetch_one(connection)
    .await
    .map_err(database_error)?;
    u64::try_from(value).map_err(|_| JournalError::InvalidStoredState)
}

#[derive(Default)]
pub struct PostgresObservationAuthority;

#[async_trait]
impl ObservationAuthority for PostgresObservationAuthority {
    async fn lock_current(
        &self,
        connection: &mut PgConnection,
        identity: &ProducerIdentity,
        binding_id: &str,
    ) -> Result<LockedAuthority, JournalError> {
        let key_id = Uuid::parse_str(&identity.api_key_id)
            .map_err(|_| JournalError::Denied(crate::external_observation_admission::Denial::NotAuthorized))?;
        let organization_id = Uuid::parse_str(&identity.organization_id)
            .map_err(|_| JournalError::Denied(crate::external_observation_admission::Denial::NotAuthorized))?;

        // Lock 1: canonical API key. Organization service revocation uses the
        // same row lock in this database, so revoke and admission are ordered.
        let key = sqlx::query(
            "SELECT id, organization_id, scopes, scope_type, deployment_profile_id,
                    status, enabled, expires_at, updated_at
             FROM organization_service.api_keys
             WHERE id = $1 AND organization_id = $2
             FOR UPDATE",
        )
        .bind(key_id)
        .bind(organization_id)
        .fetch_optional(&mut *connection)
        .await
        .map_err(database_error)?
        .ok_or(JournalError::Denied(crate::external_observation_admission::Denial::NotAuthorized))?;

        let key_scope_type: String = key.try_get("scope_type").map_err(database_error)?;
        let deployment_profile_id: Option<Uuid> =
            key.try_get("deployment_profile_id").map_err(database_error)?;
        let key_status: String = key.try_get("status").map_err(database_error)?;
        let key_enabled: bool = key.try_get("enabled").map_err(database_error)?;
        let key_expires_at: Option<DateTime<Utc>> =
            key.try_get("expires_at").map_err(database_error)?;
        let key_updated_at: DateTime<Utc> =
            key.try_get("updated_at").map_err(database_error)?;
        let key_scopes: Vec<String> = key
            .try_get::<Option<Vec<String>>, _>("scopes")
            .map_err(database_error)?
            .unwrap_or_default();
        let now_ms = database_clock_ms(connection).await?;
        let key_expiry_ms = expiry_ms(key_expires_at)?;
        let key_active = key_status == "active"
            && key_enabled
            && key_scope_type == "ORGANIZATION"
            && deployment_profile_id.is_none()
            && key_expiry_ms > now_ms;

        // Lock 2: explicit administrator-approved delegation. A matching
        // organization alone is insufficient; the exact key/source/binding
        // relationship must exist.
        let grant = sqlx::query(
            "SELECT g.id, g.organization_id, g.source_id, g.api_key_id,
                    g.active, g.revision, g.expires_at
             FROM issuance_service.external_observation_producer_grants g
             JOIN issuance_service.external_observation_grant_bindings gb
               ON gb.grant_id = g.id
              AND gb.organization_id = g.organization_id
              AND gb.source_id = g.source_id
             WHERE g.organization_id = $1
               AND g.api_key_id = $2
               AND gb.binding_id = $3
             FOR UPDATE OF g",
        )
        .bind(organization_id)
        .bind(key_id)
        .bind(binding_id)
        .fetch_optional(&mut *connection)
        .await
        .map_err(database_error)?
        .ok_or(JournalError::Denied(crate::external_observation_admission::Denial::NotAuthorized))?;

        let grant_id: Uuid = grant.try_get("id").map_err(database_error)?;
        let grant_organization: Uuid = grant.try_get("organization_id").map_err(database_error)?;
        let source_id: String = grant.try_get("source_id").map_err(database_error)?;
        let grant_key_id: Uuid = grant.try_get("api_key_id").map_err(database_error)?;
        let grant_active: bool = grant.try_get("active").map_err(database_error)?;
        let grant_revision: i64 = grant.try_get("revision").map_err(database_error)?;
        let grant_expiry: DateTime<Utc> = grant.try_get("expires_at").map_err(database_error)?;

        // Lock the grant's membership rows while the grant row itself is held.
        let binding_rows = sqlx::query(
            "SELECT binding_id
             FROM issuance_service.external_observation_grant_bindings
             WHERE grant_id = $1
             ORDER BY binding_id
             FOR SHARE",
        )
        .bind(grant_id)
        .fetch_all(&mut *connection)
        .await
        .map_err(database_error)?;
        let mut grant_bindings = BTreeSet::new();
        for row in binding_rows {
            grant_bindings.insert(row.try_get("binding_id").map_err(database_error)?);
        }

        // Lock 3: the exact core-owned binding selected by the administrator.
        let binding = sqlx::query(
            "SELECT id, organization_id, source_id, application_id, subject_id,
                    provider, fact_type, resource_scope, claim_rules, max_age_ms,
                    max_clock_skew_ms, active, revision
             FROM issuance_service.external_observation_bindings
             WHERE id = $1 AND organization_id = $2 AND source_id = $3
             FOR UPDATE",
        )
        .bind(binding_id)
        .bind(organization_id)
        .bind(&source_id)
        .fetch_optional(&mut *connection)
        .await
        .map_err(database_error)?
        .ok_or(JournalError::Denied(crate::external_observation_admission::Denial::NotAuthorized))?;

        let binding_application_id: String =
            binding.try_get("application_id").map_err(database_error)?;
        let binding_subject_id: String =
            binding.try_get("subject_id").map_err(database_error)?;
        let binding_resource_scope: serde_json::Value =
            binding.try_get("resource_scope").map_err(database_error)?;
        let binding_claim_rules: serde_json::Value =
            binding.try_get("claim_rules").map_err(database_error)?;
        let resource_scope: BTreeMap<String, String> =
            serde_json::from_value(binding_resource_scope)
                .map_err(|_| JournalError::InvalidStoredState)?;
        let claims = parse_claim_rules(binding_claim_rules)?;
        let binding_revision: i64 = binding.try_get("revision").map_err(database_error)?;
        let max_age_ms: i64 = binding.try_get("max_age_ms").map_err(database_error)?;
        let max_clock_skew_ms: i64 =
            binding.try_get("max_clock_skew_ms").map_err(database_error)?;

        // Lock 4: the canonical application and its subject/lifecycle owner.
        let application = sqlx::query(
            "SELECT id, organization_id, applicant_identifier, status, updated_at, expires_at
             FROM issuance_service.applications
             WHERE id = $1 AND organization_id = $2
             FOR UPDATE",
        )
        .bind(&binding_application_id)
        .bind(organization_id.to_string())
        .fetch_optional(&mut *connection)
        .await
        .map_err(database_error)?
        .ok_or(JournalError::Denied(crate::external_observation_admission::Denial::NotAuthorized))?;

        let application_id: String = application.try_get("id").map_err(database_error)?;
        let application_organization: String =
            application.try_get("organization_id").map_err(database_error)?;
        let application_subject: String =
            application.try_get("applicant_identifier").map_err(database_error)?;
        let application_status: String = application.try_get("status").map_err(database_error)?;
        let application_updated_at: DateTime<Utc> =
            application.try_get("updated_at").map_err(database_error)?;
        let application_expires_at: DateTime<Utc> =
            application.try_get("expires_at").map_err(database_error)?;
        let application_expiry_ms = expiry_ms(Some(application_expires_at))?;

        if grant_organization != organization_id || grant_key_id != key_id
            || application_organization != organization_id.to_string()
        {
            return Err(JournalError::Denied(crate::external_observation_admission::Denial::NotAuthorized));
        }

        let key_scopes = key_scopes.into_iter().collect::<BTreeSet<_>>();
        Ok(LockedAuthority {
            principal: AuthenticatedApiKey {
                id: key_id.to_string(),
                organization_id: organization_id.to_string(),
                revision: revision(key_updated_at)?,
                active: key_active,
                expires_at_ms: key_expiry_ms,
                scopes: key_scopes,
            },
            grant: ProducerGrant {
                organization_id: grant_organization.to_string(),
                source_id,
                api_key_id: grant_key_id.to_string(),
                revision: positive_i64(grant_revision)?,
                active: grant_active,
                expires_at_ms: expiry_ms(Some(grant_expiry))?,
                bindings: grant_bindings,
            },
            binding: EvidenceBinding {
                id: binding.try_get("id").map_err(database_error)?,
                revision: positive_i64(binding_revision)?,
                active: binding.try_get("active").map_err(database_error)?,
                organization_id: binding.try_get::<Uuid, _>("organization_id")
                    .map_err(database_error)?.to_string(),
                source_id: binding.try_get("source_id").map_err(database_error)?,
                provider: binding.try_get("provider").map_err(database_error)?,
                application_id: binding_application_id,
                subject_id: binding_subject_id,
                fact_type: binding.try_get("fact_type").map_err(database_error)?,
                resource_scope,
                claims,
                max_age_ms: positive_i64(max_age_ms)?,
                max_clock_skew_ms: {
                    let value = u64::try_from(max_clock_skew_ms)
                        .map_err(|_| JournalError::InvalidStoredState)?;
                    if value > 30_000 { return Err(JournalError::InvalidStoredState); }
                    value
                },
            },
            application: ApplicationSnapshot {
                id: application_id,
                organization_id: application_organization,
                subject_id: application_subject,
                revision: revision(application_updated_at)?,
                expires_at_ms: application_expiry_ms,
                accepts_observations: matches!(application_status.as_str(), "pending" | "under_review"),
            },
        })
    }
}
