//! Issuance-owned lifecycle for the selected Marty nested JWT machine profile.
//!
//! This is a separate internal API from managed SD-JWT status. The original
//! committed issuance transaction must correspond to the exact stored artifact.
//! Looking up an identifier, a submitted JWT, or an HTTP success cannot supply
//! this observation. Cryptographic verification remains the consumer's job.

use chrono::{DateTime, Duration, Utc};
use marty_oid4vci::{
    jwt_vc_profile::{decode_unverified_jwt_vc, validate_unsigned_jwt_vc_profile_claims},
    JwtVcSecuringProfile,
};
use marty_oid4vp_contract::machine_jwt_vc::{
    validate_types, validate_window, MachineJwtVcLifecycleState, MachineJwtVcOwnerError as Error,
    MachineJwtVcOwnerSelection, MachineJwtVcStatusObservation, MACHINE_JWT_SOURCE_MAX_AGE_SECONDS,
    MACHINE_NESTED_JWT_PROFILE,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};

#[derive(Clone)]
pub struct PgMachineJwtVcStatusAuthority {
    pool: PgPool,
}

impl PgMachineJwtVcStatusAuthority {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Deployment supplies a dedicated read-only role on these two owner
    /// tables. It must not mint, alter, revoke, or replace an issued artifact.
    pub async fn check_role_readiness(&self) -> Result<(), Error> {
        let okay: bool = sqlx::query_scalar(
            "SELECT session_user=current_user AND NOT EXISTS(SELECT 1 FROM pg_roles r
               WHERE (r.rolname=current_user OR pg_has_role(current_user,r.oid,'MEMBER'))
               AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb
                 OR r.rolreplication OR left(r.rolname,3)='pg_'))
              AND has_table_privilege(current_user,'issuance_service.issued_credentials','SELECT')
              AND has_table_privilege(current_user,'issuance_service.issuance_transactions','SELECT')
              AND NOT has_table_privilege(current_user,'issuance_service.issued_credentials','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
              AND NOT has_table_privilege(current_user,'issuance_service.issuance_transactions','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')",
        ).fetch_one(&self.pool).await.map_err(|_| Error::Unavailable)?;
        if !okay {
            return Err(Error::Unavailable);
        }
        Ok(())
    }

    pub async fn observe(
        &self,
        selection: &MachineJwtVcOwnerSelection,
        requested_at: DateTime<Utc>,
    ) -> Result<MachineJwtVcStatusObservation, Error> {
        selection.validate()?;
        // No cross-tenant or identifier alias fallback. Issuance's canonical
        // nested credential ID is the original lower-case urn:uuid identifier.
        let credential_id = format!("urn:uuid:{}", selection.credential_id);
        let row = sqlx::query(
            "SELECT c.*, t.organization_id AS source_organization_id,
                t.credential_template_id AS source_template_id,
                t.subject_did AS source_subject_did, t.issuer_did_override,
                t.status AS source_status, t.reserved_credential_id,
                t.credential_payload_format, t.jwt_vc_profile, t.jwt_vc_signing_timing,
                t.credential_type, t.issuer_algorithm, t.issued_at AS source_issued_at,
                statement_timestamp() AS machine_observed_at
             FROM issuance_service.issued_credentials c
             JOIN issuance_service.issuance_transactions t ON t.id=c.transaction_id
             WHERE c.organization_id=$1 AND c.id=$2",
        )
        .bind(selection.organization_id.to_string())
        .bind(&credential_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| Error::Unavailable)?
        .ok_or(Error::NotFound)?;
        let string = |key| {
            row.try_get::<String, _>(key)
                .map_err(|_| Error::Unsupported)
        };
        let optional = |key| {
            row.try_get::<Option<String>, _>(key)
                .map_err(|_| Error::Unsupported)
        };
        let observed_at: DateTime<Utc> = row
            .try_get("machine_observed_at")
            .map_err(|_| Error::Unavailable)?;
        let artifact = string("credential_jwt")?;
        let hash = format!("{:x}", Sha256::digest(artifact.as_bytes()));
        let issued_at: DateTime<Utc> = row.try_get("issued_at").map_err(|_| Error::Unsupported)?;
        let source_issued_at: Option<DateTime<Utc>> = row
            .try_get("source_issued_at")
            .map_err(|_| Error::Unsupported)?;
        let status_updated_at: DateTime<Utc> = row
            .try_get("status_updated_at")
            .map_err(|_| Error::Unsupported)?;
        let stored_expires_at: Option<DateTime<Utc>> =
            row.try_get("expires_at").map_err(|_| Error::Unsupported)?;
        let stored_expires_at = stored_expires_at.ok_or(Error::Unsupported)?;
        let template_id = string("credential_template_id")?;
        let source_type = optional("credential_type")?.ok_or(Error::Unsupported)?;
        let state = match string("status")?.as_str() {
            "active" => MachineJwtVcLifecycleState::Active,
            "suspended" => MachineJwtVcLifecycleState::Suspended,
            "revoked" => MachineJwtVcLifecycleState::Revoked,
            _ => return Err(Error::Unsupported),
        };
        let revoked: bool = row.try_get("revoked").map_err(|_| Error::Unsupported)?;
        let revoked_at: Option<DateTime<Utc>> =
            row.try_get("revoked_at").map_err(|_| Error::Unsupported)?;
        let status_entries: Value = row
            .try_get("status_list_entries")
            .map_err(|_| Error::Unsupported)?;
        if observed_at < requested_at
            || artifact.is_empty()
            || artifact.len() > marty_oid4vp_contract::MAX_TOKEN_BYTES
            || artifact.trim() != artifact
            || string("id")? != credential_id
            || string("source_organization_id")? != selection.organization_id.to_string()
            || string("source_template_id")? != template_id
            || string("source_status")? != "issued"
            || optional("reserved_credential_id")?.as_deref() != Some(credential_id.as_str())
            || source_issued_at != Some(issued_at)
            || optional("subject_did")?.as_deref() != Some(selection.subject.as_str())
            || optional("issuer_did")?.as_deref() != Some(selection.issuer.as_str())
            || optional("source_subject_did")?
                .as_deref()
                .is_some_and(|subject| subject != selection.subject)
            || optional("issuer_did_override")?
                .as_deref()
                .is_some_and(|issuer| issuer != selection.issuer)
            || optional("issuer_algorithm")?
                .as_deref()
                .is_some_and(|algorithm| algorithm != selection.algorithm)
            || !matches!(
                string("credential_payload_format")?.as_str(),
                "jwt_vc" | "jwt_vc_json" | "w3c_vcdm_v2_jwt" | "w3c_vcdm_v2_jwt_vc"
            )
            || row
                .try_get::<Option<Value>, _>("jwt_vc_profile")
                .map_err(|_| Error::Unsupported)?
                .is_some()
            || row
                .try_get::<Option<Value>, _>("jwt_vc_signing_timing")
                .map_err(|_| Error::Unsupported)?
                .is_some()
            || string("credential_hash")? != hash
            || selection.credential_digest != format!("sha256:{hash}")
            || issued_at > status_updated_at
            || status_updated_at > observed_at
            || revoked != (state == MachineJwtVcLifecycleState::Revoked)
            || revoked_at.is_some_and(|at| at > observed_at)
            || (state != MachineJwtVcLifecycleState::Revoked && revoked_at.is_some())
            || !status_entries.as_array().is_some_and(Vec::is_empty)
            || optional("revocation_profile_id")?.is_some()
        {
            return Err(Error::Unsupported);
        }
        let (header, claims) =
            decode_unverified_jwt_vc(&artifact, JwtVcSecuringProfile::MartyNestedVc2JwtV1)
                .map_err(|_| Error::Unsupported)?;
        let hints = validate_unsigned_jwt_vc_profile_claims(
            &claims,
            observed_at.timestamp(),
            JwtVcSecuringProfile::MartyNestedVc2JwtV1,
        )
        .map_err(|_| Error::Unsupported)?;
        if hints.credential_id != credential_id
            || hints.issuer != selection.issuer
            || hints.subject_id != selection.subject
            || header.get("kid").and_then(Value::as_str)
                != Some(selection.verification_method_id.as_str())
            || header.get("alg").and_then(Value::as_str) != Some(selection.algorithm.as_str())
            || hints.credential.get("credentialStatus").is_some()
        {
            return Err(Error::Unsupported);
        }
        let types = hints
            .credential
            .get("type")
            .and_then(Value::as_array)
            .ok_or(Error::Unsupported)?
            .iter()
            .map(|kind| kind.as_str().map(str::to_owned).ok_or(Error::Unsupported))
            .collect::<Result<Vec<_>, _>>()?;
        validate_types(&types)?;
        if !types.contains(&source_type) {
            return Err(Error::Unsupported);
        }
        let signature_expires_at = epoch(&claims, "exp")?;
        let signature_issued_at = epoch(&claims, "iat")?;
        if signature_issued_at > issued_at {
            return Err(Error::Unsupported);
        }
        let signature_not_before = claims
            .get("nbf")
            .map(|_| epoch(&claims, "nbf"))
            .transpose()?;
        let credential_expires_at = hints
            .credential
            .get("validUntil")
            .and_then(Value::as_str)
            .ok_or(Error::Unsupported)
            .and_then(|value| {
                DateTime::parse_from_rfc3339(value)
                    .map(|value| value.with_timezone(&Utc))
                    .map_err(|_| Error::Unsupported)
            })?
            .min(stored_expires_at);
        let valid_until = observed_at
            .checked_add_signed(Duration::seconds(MACHINE_JWT_SOURCE_MAX_AGE_SECONDS))
            .ok_or(Error::Unavailable)?
            .min(signature_expires_at)
            .min(credential_expires_at)
            .min(
                requested_at
                    .checked_add_signed(Duration::seconds(MACHINE_JWT_SOURCE_MAX_AGE_SECONDS))
                    .ok_or(Error::Unavailable)?,
            );
        let completed_at = Utc::now();
        validate_window(observed_at, valid_until, completed_at)?;
        let observation = MachineJwtVcStatusObservation {
            selection: selection.clone(),
            securing_profile: MACHINE_NESTED_JWT_PROFILE.into(),
            transaction_id: string("transaction_id")?,
            credential_template_id: template_id,
            credential_types: types,
            state,
            status_updated_at,
            issued_at,
            credential_expires_at,
            signature_expires_at,
            signature_not_before,
            observed_at,
            valid_until,
        };
        observation.validate_for(selection, completed_at)?;
        Ok(observation)
    }
}

fn epoch(claims: &Value, key: &str) -> Result<DateTime<Utc>, Error> {
    claims
        .get(key)
        .and_then(Value::as_i64)
        .filter(|seconds| *seconds > 0)
        .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
        .ok_or(Error::Unsupported)
}
