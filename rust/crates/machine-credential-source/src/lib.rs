//! Concrete composition of real Trust Profile and Issuance PostgreSQL owners.
//!
//! Only `MartyNestedVc2JwtV1` is selected. Three separately privileged pools
//! read current trust, read exact original issuance, and append source evidence.
//! Source history cannot be converted into a new authority observation.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use marty_delegated_authority::{
    machine_auth::MachineEvidenceError,
    machine_credentials::{
        MachineCredentialSourceStatus, MachineJwtVcAuthoritySource, MachineJwtVcSelection,
        ResolvedMachineJwtVcAuthority,
    },
    DelegationClock, PrincipalType, SystemDelegationClock,
};
use marty_issuance_service::machine_credential_status::PgMachineJwtVcStatusAuthority;
use marty_oid4vci::{JwtVcSecuringProfile, ResolvedSdJwtIssuerKey, TrustedSdJwtIssuerKeys};
use marty_oid4vp_contract::{
    digest_domain_json,
    machine_jwt_vc::{
        validate_window, MachineJwtVcLifecycleState, MachineJwtVcOwnerSelection,
        MachineJwtVcStatusObservation, MachineJwtVcTrustObservation,
        MACHINE_JWT_SOURCE_MAX_AGE_SECONDS,
    },
};
use marty_trust_profile::machine_credential_authority::PgMachineJwtVcTrustAuthority;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

mod postgres;
pub use postgres::{
    run_migrations, HistoricalMachineCredentialSourceEvidence, PgMachineCredentialSourceEvidence,
    MACHINE_CREDENTIAL_SOURCE_MIGRATION,
};

const SOURCE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
pub const MACHINE_CREDENTIAL_SCOPE_DOMAIN: &str = "marty.machine-credential-source/scope/v1";
pub const MACHINE_CREDENTIAL_EVIDENCE_PROFILE: &str = "urn:marty:machine-credential-source:v1";
pub const MACHINE_CREDENTIAL_EVIDENCE_REF_PREFIX: &str =
    "urn:marty:machine-credential-source:sha256:";

#[derive(Clone)]
pub struct PgOwnedMachineJwtVcAuthoritySource {
    trust_pool: PgPool,
    status_pool: PgPool,
    trust: PgMachineJwtVcTrustAuthority,
    status: PgMachineJwtVcStatusAuthority,
    evidence: PgMachineCredentialSourceEvidence,
    clock: Arc<dyn DelegationClock>,
}

impl PgOwnedMachineJwtVcAuthoritySource {
    /// Verifies actual connected roles before accepting this composition. This
    /// does not deploy a host, grant permissions, or establish a network policy.
    pub async fn connect(
        trust_pool: PgPool,
        status_pool: PgPool,
        evidence_pool: PgPool,
    ) -> Result<Self, MachineEvidenceError> {
        Self::connect_with_clock(
            trust_pool,
            status_pool,
            evidence_pool,
            Arc::new(SystemDelegationClock),
        )
        .await
    }

    pub async fn connect_with_clock(
        trust_pool: PgPool,
        status_pool: PgPool,
        evidence_pool: PgPool,
        clock: Arc<dyn DelegationClock>,
    ) -> Result<Self, MachineEvidenceError> {
        let trust_role = role(&trust_pool).await?;
        let status_role = role(&status_pool).await?;
        let evidence_role = role(&evidence_pool).await?;
        if trust_role == status_role || trust_role == evidence_role || status_role == evidence_role
        {
            return Err(MachineEvidenceError);
        }
        check_isolated_role(
            &trust_pool,
            &[
                ("trust_profile_service", "trust_profiles", "read"),
                ("trust_profile_service", "issuer_entities", "read"),
                ("trust_profile_service", "trust_profile_issuers", "read"),
                (
                    "trust_profile_service",
                    "machine_jwt_vc_authority_revisions",
                    "revision",
                ),
            ],
        )
        .await?;
        check_isolated_role(
            &status_pool,
            &[
                ("issuance_service", "issued_credentials", "read"),
                ("issuance_service", "issuance_transactions", "read"),
            ],
        )
        .await?;
        let result = Self {
            trust_pool: trust_pool.clone(),
            status_pool: status_pool.clone(),
            trust: PgMachineJwtVcTrustAuthority::new(trust_pool),
            status: PgMachineJwtVcStatusAuthority::new(status_pool),
            evidence: PgMachineCredentialSourceEvidence::new(evidence_pool),
            clock,
        };
        result.readiness().await?;
        Ok(result)
    }

    pub async fn readiness(&self) -> Result<(), MachineEvidenceError> {
        check_isolated_role(
            &self.trust_pool,
            &[
                ("trust_profile_service", "trust_profiles", "read"),
                ("trust_profile_service", "issuer_entities", "read"),
                ("trust_profile_service", "trust_profile_issuers", "read"),
                (
                    "trust_profile_service",
                    "machine_jwt_vc_authority_revisions",
                    "revision",
                ),
            ],
        )
        .await?;
        check_isolated_role(
            &self.status_pool,
            &[
                ("issuance_service", "issued_credentials", "read"),
                ("issuance_service", "issuance_transactions", "read"),
            ],
        )
        .await?;
        self.trust
            .check_role_readiness()
            .await
            .map_err(unavailable)?;
        self.status
            .check_role_readiness()
            .await
            .map_err(unavailable)?;
        self.evidence.readiness().await
    }
}

#[async_trait]
impl MachineJwtVcAuthoritySource for PgOwnedMachineJwtVcAuthoritySource {
    async fn resolve_current(
        &self,
        selection: &MachineJwtVcSelection,
        now: DateTime<Utc>,
    ) -> Result<ResolvedMachineJwtVcAuthority, MachineEvidenceError> {
        if selection.securing_profile != JwtVcSecuringProfile::MartyNestedVc2JwtV1
            || selection.scope.principal.principal_type != PrincipalType::MachineIdentity
        {
            return Err(MachineEvidenceError);
        }
        let original_deadline = now
            .checked_add_signed(Duration::seconds(MACHINE_JWT_SOURCE_MAX_AGE_SECONDS))
            .ok_or(MachineEvidenceError)?;
        let started_at = self.clock.now();
        if started_at < now || started_at >= original_deadline {
            return Err(MachineEvidenceError);
        }
        // Privilege or guard drift after startup must fail the next operation.
        self.readiness().await?;
        let owner_selection = MachineJwtVcOwnerSelection {
            organization_id: selection.scope.organization_id,
            trust_profile_id: selection.trust_profile_id,
            credential_id: selection.credential_id,
            credential_digest: selection.credential_digest.clone(),
            issuer: selection.issuer.clone(),
            subject: selection.scope.principal.id.clone(),
            verification_method_id: selection.verification_method_id.clone(),
            algorithm: selection.algorithm.as_str().to_owned(),
            scope_digest: digest_domain_json(MACHINE_CREDENTIAL_SCOPE_DOMAIN, &selection.scope)
                .map_err(unavailable)?,
        };
        owner_selection.validate().map_err(unavailable)?;
        let status = tokio::time::timeout(
            SOURCE_READ_TIMEOUT,
            self.status.observe(&owner_selection, now),
        )
        .await
        .map_err(unavailable)?
        .map_err(unavailable)?;
        let after_status = self.clock.now();
        status
            .validate_for(&owner_selection, after_status)
            .map_err(unavailable)?;
        if after_status < started_at
            || after_status >= original_deadline
            || status.state != MachineJwtVcLifecycleState::Active
        {
            return Err(MachineEvidenceError);
        }
        // Trust's revision publication is durable but never an authority grant.
        // Its operation owns its lock/COMMIT; no cancellation timeout surrounds
        // the evidence transaction below and no write is automatically retried.
        let trust = self
            .trust
            .observe(&owner_selection, &status.credential_types, now)
            .await
            .map_err(unavailable)?;
        let after_trust = self.clock.now();
        trust
            .validate_for(&owner_selection, &status.credential_types, after_trust)
            .map_err(unavailable)?;
        if after_trust < after_status
            || after_trust >= original_deadline
            || (trust.require_not_before && status.signature_not_before.is_none())
        {
            return Err(MachineEvidenceError);
        }
        let issuer_key = ResolvedSdJwtIssuerKey::new(
            selection.issuer.clone(),
            Some(selection.verification_method_id.clone()),
            selection.algorithm,
            serde_json::to_string(&trust.issuer_public_jwk).map_err(unavailable)?,
        );
        TrustedSdJwtIssuerKeys::new(vec![issuer_key.clone()]).map_err(unavailable)?;
        let observed_at = status.observed_at.min(trust.observed_at);
        let valid_until = status
            .valid_until
            .min(trust.valid_until)
            .min(original_deadline);
        validate_window(observed_at, valid_until, after_trust).map_err(unavailable)?;
        let record = SourceEvidence {
            profile: MACHINE_CREDENTIAL_EVIDENCE_PROFILE.into(),
            scope: serde_json::to_value(&selection.scope).map_err(unavailable)?,
            selection: owner_selection,
            status,
            trust: trust.clone(),
            observed_at,
            completed_at: after_trust,
            valid_until,
        };
        let reference = self.evidence.retain(&record).await?;
        let completed_at = self.clock.now();
        if completed_at < after_trust {
            return Err(MachineEvidenceError);
        }
        validate_window(observed_at, valid_until, completed_at).map_err(unavailable)?;
        Ok(ResolvedMachineJwtVcAuthority {
            selection: selection.clone(),
            trust_profile_revision: trust.profile_revision,
            trust_profile_digest: trust.profile_digest,
            trust_profile_status: MachineCredentialSourceStatus::Active,
            issuer_status: MachineCredentialSourceStatus::Active,
            issuer_key_status: MachineCredentialSourceStatus::Active,
            credential_status: MachineCredentialSourceStatus::Active,
            issuer_key,
            authorized_credential_types: trust.authorized_credential_types,
            evidence_ref: reference,
            observed_at,
            valid_until,
        })
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceEvidence {
    profile: String,
    scope: Value,
    selection: MachineJwtVcOwnerSelection,
    status: MachineJwtVcStatusObservation,
    trust: MachineJwtVcTrustObservation,
    observed_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
}

impl SourceEvidence {
    fn validate(&self, at: DateTime<Utc>) -> Result<(), MachineEvidenceError> {
        self.selection.validate().map_err(unavailable)?;
        self.status
            .validate_for(&self.selection, at)
            .map_err(unavailable)?;
        self.trust
            .validate_for(&self.selection, &self.status.credential_types, at)
            .map_err(unavailable)?;
        validate_window(self.observed_at, self.valid_until, at).map_err(unavailable)?;
        if self.profile != MACHINE_CREDENTIAL_EVIDENCE_PROFILE
            || self.scope.get("organization_id") != Some(&json!(self.selection.organization_id))
            || self
                .scope
                .pointer("/principal/type")
                .and_then(Value::as_str)
                != Some("MACHINE_IDENTITY")
            || self.scope.pointer("/principal/id").and_then(Value::as_str)
                != Some(self.selection.subject.as_str())
            || self.selection.scope_digest
                != digest_domain_json(MACHINE_CREDENTIAL_SCOPE_DOMAIN, &self.scope)
                    .map_err(unavailable)?
            || self.status.state != MachineJwtVcLifecycleState::Active
            || self.observed_at != self.status.observed_at.min(self.trust.observed_at)
            || self.completed_at < self.trust.observed_at.max(self.status.observed_at)
            || self.completed_at > at
            || self.valid_until > self.status.valid_until.min(self.trust.valid_until)
            || (self.trust.require_not_before && self.status.signature_not_before.is_none())
            || digest_domain_json(
                marty_trust_profile::machine_credential_authority::MACHINE_JWT_VC_BASIS_DOMAIN,
                &self.trust.authority_basis,
            )
            .map_err(unavailable)?
                != self.trust.profile_digest
        {
            return Err(MachineEvidenceError);
        }
        Ok(())
    }
}

fn unavailable(_: impl std::fmt::Debug) -> MachineEvidenceError {
    MachineEvidenceError
}

async fn role(pool: &PgPool) -> Result<String, MachineEvidenceError> {
    sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(pool)
        .await
        .map_err(unavailable)
}

/// Reject inherited and column-only access too. No owner role, CREATE grant,
/// security-definer shortcut, or access to another business table is accepted.
async fn check_isolated_role(
    pool: &PgPool,
    allowed: &[(&str, &str, &str)],
) -> Result<(), MachineEvidenceError> {
    let allowed = serde_json::to_value(allowed).map_err(unavailable)?;
    let okay: bool = sqlx::query_scalar(
        "SELECT session_user=current_user AND NOT EXISTS(SELECT 1 FROM pg_roles r
          WHERE (r.rolname=current_user OR pg_has_role(current_user,r.oid,'MEMBER')) AND (
            r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb
            OR r.rolreplication OR left(r.rolname,3)='pg_'
            OR EXISTS(SELECT 1 FROM pg_namespace n WHERE left(n.nspname::TEXT,3)<>'pg_' AND n.nspname<>'information_schema'
              AND (n.nspowner=r.oid OR has_schema_privilege(r.oid,n.oid,'CREATE')))
            OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
              WHERE left(n.nspname::TEXT,3)<>'pg_' AND n.nspname<>'information_schema' AND p.prosecdef
              AND has_function_privilege(r.oid,p.oid,'EXECUTE'))
            OR EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
              WHERE left(n.nspname::TEXT,3)<>'pg_' AND n.nspname<>'information_schema'
              AND t.relkind IN ('r','p','v','m','f','S') AND (
                t.relowner=r.oid
                OR CASE WHEN current_setting('server_version_num')::INT>=170000 THEN has_table_privilege(r.oid,t.oid,'MAINTAIN') ELSE false END
                OR (
                  NOT EXISTS(SELECT 1 FROM jsonb_array_elements($1::jsonb) a
                    WHERE a->>0=n.nspname AND a->>1=t.relname)
                  AND (has_table_privilege(r.oid,t.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                    OR has_any_column_privilege(r.oid,t.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
                OR (EXISTS(SELECT 1 FROM jsonb_array_elements($1::jsonb) a
                    WHERE a->>0=n.nspname AND a->>1=t.relname AND a->>2='read')
                    AND (has_table_privilege(r.oid,t.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                      OR has_any_column_privilege(r.oid,t.oid,'INSERT,UPDATE,REFERENCES')))
                OR (EXISTS(SELECT 1 FROM jsonb_array_elements($1::jsonb) a
                    WHERE a->>0=n.nspname AND a->>1=t.relname AND a->>2='append')
                    AND (has_table_privilege(r.oid,t.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                      OR has_any_column_privilege(r.oid,t.oid,'UPDATE,REFERENCES')))
                OR (EXISTS(SELECT 1 FROM jsonb_array_elements($1::jsonb) a
                    WHERE a->>0=n.nspname AND a->>1=t.relname AND a->>2='revision')
                    AND (has_table_privilege(r.oid,t.oid,'DELETE,TRUNCATE,REFERENCES,TRIGGER')
                      OR has_any_column_privilege(r.oid,t.oid,'REFERENCES')))))))",
    ).bind(allowed).fetch_one(pool).await.map_err(unavailable)?;
    if !okay {
        return Err(MachineEvidenceError);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
