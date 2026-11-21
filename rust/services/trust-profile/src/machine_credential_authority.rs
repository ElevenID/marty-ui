//! Current Trust Profile authority for one explicit machine credential profile.
//! Reads the real administrative graph. It never widens managed SD-JWT grants,
//! resolves a caller URL, imports an issuer, or treats generic trust as a type
//! grant. Separate revision rows serialize observations, not graph mutation.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use marty_oid4vp_contract::{
    digest_domain_json,
    machine_jwt_vc::{
        nested_machine_credential_authorizations, validate_types, validate_window,
        MachineJwtVcOwnerError as Error, MachineJwtVcOwnerSelection, MachineJwtVcTrustObservation,
        MACHINE_JWT_SOURCE_MAX_AGE_SECONDS, MACHINE_NESTED_JWT_PROFILE,
    },
    trust_authority::{issuer_public_key_algorithm, CredentialAuthorityBasisV1},
};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

use crate::{IssuerEntity, TrustProfileIssuer};

pub const MACHINE_JWT_VC_BASIS_DOMAIN: &str =
    "marty.trust-profile/machine-nested-jwt-vc-authority/v1";

#[derive(Clone)]
pub struct PgMachineJwtVcTrustAuthority {
    pool: PgPool,
}

impl PgMachineJwtVcTrustAuthority {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// A production composition supplies a dedicated login: read the existing
    /// graph, and SELECT/INSERT/UPDATE only this profile's revision namespace.
    pub async fn check_role_readiness(&self) -> Result<(), Error> {
        let okay: bool = sqlx::query_scalar(
            "SELECT session_user=current_user AND NOT EXISTS(SELECT 1 FROM pg_roles r
               WHERE (r.rolname=current_user OR pg_has_role(current_user,r.oid,'MEMBER'))
               AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb
                 OR r.rolreplication OR left(r.rolname,3)='pg_'))
             AND has_table_privilege(current_user,'trust_profile_service.trust_profiles','SELECT')
             AND has_table_privilege(current_user,'trust_profile_service.issuer_entities','SELECT')
             AND has_table_privilege(current_user,'trust_profile_service.trust_profile_issuers','SELECT')
             AND NOT has_table_privilege(current_user,'trust_profile_service.trust_profiles','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
             AND NOT has_table_privilege(current_user,'trust_profile_service.issuer_entities','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
             AND NOT has_table_privilege(current_user,'trust_profile_service.trust_profile_issuers','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
             AND has_table_privilege(current_user,'trust_profile_service.machine_jwt_vc_authority_revisions','SELECT')
             AND has_table_privilege(current_user,'trust_profile_service.machine_jwt_vc_authority_revisions','INSERT')
             AND has_table_privilege(current_user,'trust_profile_service.machine_jwt_vc_authority_revisions','UPDATE')
             AND NOT has_table_privilege(current_user,'trust_profile_service.machine_jwt_vc_authority_revisions','DELETE,TRUNCATE,REFERENCES,TRIGGER')",
        ).fetch_one(&self.pool).await.map_err(|_| Error::Unavailable)?;
        if !okay {
            return Err(Error::Unavailable);
        }
        Ok(())
    }

    pub async fn observe(
        &self,
        selection: &MachineJwtVcOwnerSelection,
        credential_types: &[String],
        requested_at: DateTime<Utc>,
    ) -> Result<MachineJwtVcTrustObservation, Error> {
        selection.validate()?;
        validate_types(credential_types)?;
        if credential_types.len() < 2
            || !credential_types
                .iter()
                .any(|kind| kind == "VerifiableCredential")
        {
            return Err(Error::InvalidRequest);
        }
        let mut transaction = self.pool.begin().await.map_err(|_| Error::Unavailable)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            .execute(&mut *transaction)
            .await
            .map_err(|_| Error::Unavailable)?;
        sqlx::raw_sql("SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='5s'")
            .execute(&mut *transaction)
            .await
            .map_err(|_| Error::Unavailable)?;
        let profile_id = selection.trust_profile_id.to_string();
        let organization_id = selection.organization_id.to_string();
        sqlx::query(
            "INSERT INTO trust_profile_service.machine_jwt_vc_authority_revisions(profile_id)
             SELECT id FROM trust_profile_service.trust_profiles
             WHERE id=$1 AND organization_id=$2 ON CONFLICT(profile_id) DO NOTHING",
        )
        .bind(&profile_id)
        .bind(&organization_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| Error::Unavailable)?;
        let revision = sqlx::query(
            "SELECT version,content_digest FROM trust_profile_service.machine_jwt_vc_authority_revisions
             WHERE profile_id=$1 FOR UPDATE",
        ).bind(&profile_id).fetch_optional(&mut *transaction).await
            .map_err(|_| Error::Unavailable)?.ok_or(Error::NotFound)?;
        // One statement after the revision lock observes a coherent current
        // graph. Statement time is fresh even after a blocked lock acquisition.
        let row = sqlx::query(
            "SELECT p.*, statement_timestamp() AS machine_observed_at,
               COALESCE((SELECT jsonb_agg(jsonb_build_object(
                  'relationship',to_jsonb(r),'issuer',to_jsonb(i)) ORDER BY r.id)
                 FROM (SELECT * FROM trust_profile_service.trust_profile_issuers
                       WHERE trust_profile_id=p.id ORDER BY id LIMIT 129) r
                 LEFT JOIN trust_profile_service.issuer_entities i ON i.id=r.issuer_id),
                 '[]'::jsonb) AS machine_relationships
             FROM trust_profile_service.trust_profiles p
             WHERE p.id=$1 AND p.organization_id=$2",
        )
        .bind(&profile_id)
        .bind(&organization_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| Error::Unavailable)?
        .ok_or(Error::NotFound)?;
        let observed_at: DateTime<Utc> = row
            .try_get("machine_observed_at")
            .map_err(|_| Error::Unavailable)?;
        let profile = crate::postgres::profile_from_row(&row).map_err(|_| Error::Unsupported)?;
        let graph: Value = row
            .try_get("machine_relationships")
            .map_err(|_| Error::Unsupported)?;
        let relationships = graph
            .as_array()
            .ok_or(Error::Unsupported)?
            .iter()
            .map(|entry| {
                let relationship: TrustProfileIssuer =
                    serde_json::from_value(entry["relationship"].clone())
                        .map_err(|_| Error::Unsupported)?;
                let issuer: IssuerEntity = serde_json::from_value(entry["issuer"].clone())
                    .map_err(|_| Error::Unsupported)?;
                Ok((relationship, issuer))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let mut grants = BTreeMap::new();
        for (relationship, _) in &relationships {
            grants.insert(
                relationship.id.to_string(),
                nested_machine_credential_authorizations(&relationship.metadata)?,
            );
        }
        let basis = crate::credential_authority::authority_basis(&profile, relationships)
            .map_err(|_| Error::Unsupported)?;
        let document = json!({
            "securing_profile":MACHINE_NESTED_JWT_PROFILE,
            "credential_authority_basis":basis,
            "nested_credential_type_grants":grants,
        });
        let digest = digest_domain_json(MACHINE_JWT_VC_BASIS_DOMAIN, &document)
            .map_err(|_| Error::Unsupported)?;
        let previous: i64 = revision
            .try_get("version")
            .map_err(|_| Error::Unavailable)?;
        let previous_digest: Option<String> = revision
            .try_get("content_digest")
            .map_err(|_| Error::Unavailable)?;
        let version = if previous > 0 && previous_digest.as_deref() == Some(digest.as_str()) {
            previous
        } else {
            previous
                .checked_add(1)
                .filter(|v| (1..=9_007_199_254_740_991).contains(v))
                .ok_or(Error::Unavailable)?
        };
        if previous != version {
            sqlx::query(
                "UPDATE trust_profile_service.machine_jwt_vc_authority_revisions
                SET version=$2,content_digest=$3,observed_at=$4 WHERE profile_id=$1",
            )
            .bind(&profile_id)
            .bind(version)
            .bind(&digest)
            .bind(observed_at)
            .execute(&mut *transaction)
            .await
            .map_err(|_| Error::Unavailable)?;
        }
        // Revision changes include unsupported settings and removed grants.
        // Commit the observed revision even if the selected decision will fail.
        sqlx::raw_sql("SET LOCAL statement_timeout=0; SET LOCAL lock_timeout=0")
            .execute(&mut *transaction)
            .await
            .map_err(|_| Error::Unavailable)?;
        // A caller's bounded source timeout may cancel this future. Detach only
        // the final COMMIT so its outcome finishes; cancellation returns no
        // authority and never retries the observation.
        tokio::spawn(async move { transaction.commit().await })
            .await
            .map_err(|_| Error::Unavailable)?
            .map_err(|_| Error::Unavailable)?;
        let (public_key, authorized_types, issuer_deadline) =
            select_current(&basis, &grants, selection, credential_types, observed_at)?;
        let valid_until = observed_at
            .checked_add_signed(Duration::seconds(MACHINE_JWT_SOURCE_MAX_AGE_SECONDS))
            .ok_or(Error::Unavailable)?
            .min(issuer_deadline)
            .min(
                requested_at
                    .checked_add_signed(Duration::seconds(MACHINE_JWT_SOURCE_MAX_AGE_SECONDS))
                    .ok_or(Error::Unavailable)?,
            );
        let completed_at = Utc::now();
        if observed_at < requested_at {
            return Err(Error::Unavailable);
        }
        validate_window(observed_at, valid_until, completed_at)?;
        let result = MachineJwtVcTrustObservation {
            selection: selection.clone(),
            securing_profile: MACHINE_NESTED_JWT_PROFILE.into(),
            credential_types: credential_types.to_vec(),
            profile_revision: version as u64,
            profile_digest: digest,
            authority_basis: document,
            issuer_public_jwk: public_key,
            authorized_credential_types: authorized_types,
            require_not_before: basis.policy_controls.time_policy.require_not_before,
            observed_at,
            valid_until,
        };
        result.validate_for(selection, credential_types, completed_at)?;
        Ok(result)
    }
}

fn select_current(
    basis: &CredentialAuthorityBasisV1,
    grants: &BTreeMap<String, Vec<String>>,
    selection: &MachineJwtVcOwnerSelection,
    types: &[String],
    now: DateTime<Utc>,
) -> Result<(Value, Vec<String>, DateTime<Utc>), Error> {
    // The common controls guard rejects external status protocols, unsupported
    // policy engines and custom trust sources. The format/type permission here
    // is a separate explicit profile selection, never the SD-JWT decision.
    crate::credential_authority::validate_supported_configuration(basis)
        .map_err(|_| Error::Unsupported)?;
    if basis.id != selection.trust_profile_id.to_string()
        || basis.organization_id != selection.organization_id.to_string()
        || basis.status != "active"
        || basis.compliance_status != "COMPLIANT"
        || !basis
            .trust_purposes
            .iter()
            .any(|purpose| purpose == "CREDENTIAL_ISSUER")
        || !basis
            .supported_formats
            .iter()
            .any(|format| format == "VC_JWT")
        || !basis.allowed_algorithms.contains(&selection.algorithm)
        || basis.denied_issuers.contains(&selection.issuer)
        || basis
            .allowed_issuers
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&selection.issuer))
        || time(&basis.created_at)? > time(&basis.updated_at)?
        || time(&basis.updated_at)? > now
    {
        return Err(Error::Unsupported);
    }
    let issuer = basis
        .issuer_relationships
        .iter()
        .find(|issuer| issuer.issuer_id == selection.issuer)
        .ok_or(Error::NotFound)?;
    let authorized = grants
        .get(&issuer.relationship_id)
        .ok_or(Error::Unsupported)?;
    let until = issuer
        .valid_until
        .as_deref()
        .map(time)
        .transpose()?
        .unwrap_or(now + Duration::seconds(MACHINE_JWT_SOURCE_MAX_AGE_SECONDS));
    if issuer.relationship_status != "TRUSTED"
        || issuer.trust_level == 0
        || !matches!(
            issuer.compliance_status.as_str(),
            "ACCREDITED" | "COMPLIANT"
        )
        || issuer.revoked_at.is_some()
        || time(&issuer.valid_from)? > now
        || until <= now
        || time(&issuer.issuer_created_at)? > time(&issuer.issuer_updated_at)?
        || time(&issuer.issuer_updated_at)? > now
        || time(&issuer.relationship_created_at)? > time(&issuer.relationship_updated_at)?
        || time(&issuer.relationship_updated_at)? > now
        || types
            .iter()
            .filter(|kind| kind.as_str() != "VerifiableCredential")
            .any(|kind| !authorized.contains(kind))
    {
        return Err(Error::Unsupported);
    }
    let selected = issuer
        .verification_keys
        .iter()
        .filter(|key| {
            key.get("kid").and_then(Value::as_str)
                == Some(selection.verification_method_id.as_str())
        })
        .collect::<Vec<_>>();
    if selected.len() != 1 {
        return Err(Error::Unsupported);
    }
    let key = selected[0];
    if issuer_public_key_algorithm(key).map_err(|_| Error::Unsupported)? != selection.algorithm
        || (basis.policy_controls.validation_rules.require_key_usage
            && key.get("use").and_then(Value::as_str) != Some("sig")
            && key.get("key_ops") != Some(&json!(["verify"])))
    {
        return Err(Error::Unsupported);
    }
    Ok((key.clone(), authorized.clone(), until))
}

fn time(value: &str) -> Result<DateTime<Utc>, Error> {
    DateTime::parse_from_rfc3339(value)
        .map(|v| v.with_timezone(&Utc))
        .map_err(|_| Error::Unsupported)
}
