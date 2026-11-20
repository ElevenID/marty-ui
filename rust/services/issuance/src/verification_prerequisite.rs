//! Issuance-owned binding to committed, authenticated Flow prerequisite evidence.
//!
//! Wire evidence is correspondence data. Only the configured authenticated owner
//! client can create the private acquisition used by the signing repository.

use chrono::Utc;
use marty_oid4vp_contract::{
    digest_domain_json,
    issuance_prerequisite::{
        IssuanceIntentBindingV1, IssuancePrerequisitePolicyV1, ISSUANCE_DATASET_DIGEST_DOMAIN_V1,
        ISSUANCE_INTENT_CONTRACT_V1,
    },
    trust_authority::issuer_public_key_thumbprint,
};
use serde_json::json;

use crate::credential::{
    credential_configuration_id_for_format, CredentialIssuanceError, CredentialTransaction,
    VerifiedCredentialProof,
};

pub const MIGRATION_VERSION: &str = "0018_verification_prerequisites";
pub const MIGRATION_SQL: &str = include_str!("../migrations/0018_verification_prerequisites.sql");

// The configured transport is a child of the capability module, so its private
// constructor remains inaccessible even to other Issuance modules.
#[path = "verification_prerequisite_client.rs"]
pub mod owner_client;

pub async fn migrate(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('issuance_schema_owner_v1', 0))")
        .execute(&mut *transaction)
        .await?;
    sqlx::raw_sql(MIGRATION_SQL)
        .execute(&mut *transaction)
        .await?;
    validate_connection(&mut transaction).await?;
    transaction.commit().await
}

pub async fn validate(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *transaction)
        .await?;
    validate_connection(&mut transaction).await?;
    transaction.commit().await
}

pub(crate) async fn validate_connection(
    connection: &mut sqlx::PgConnection,
) -> Result<(), sqlx::Error> {
    let failure = || {
        sqlx::Error::Protocol(
            "verification prerequisite storage boundary differs from the reviewed schema".into(),
        )
    };
    let intent_column: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='issuance_service'
         AND table_name='issuance_transactions' AND column_name='issuance_intent'
         AND udt_name='jsonb' AND is_nullable='YES' AND column_default IS NULL)")
        .fetch_one(&mut *connection).await?;
    let receipt_columns: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.columns WHERE table_schema='issuance_service'
         AND table_name='issuance_prerequisite_continuations' AND is_nullable='NO' AND column_default IS NULL
         AND ((column_name IN ('transaction_id','organization_id','intent_digest','evidence_digest','flow_instance_id','holder_key_thumbprint','credential_id') AND udt_name='text')
           OR (column_name IN ('created_at','expires_at','consumed_at') AND udt_name='timestamptz'))")
        .fetch_one(&mut *connection).await?;
    let receipt_constraints: bool = sqlx::query_scalar(
        "SELECT (SELECT array_agg(DISTINCT a.attname::text ORDER BY a.attname::text) FROM pg_constraint c
             JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=c.conkey[1]
             JOIN pg_index i ON i.indexrelid=c.conindid AND i.indrelid=c.conrelid
             WHERE c.conrelid=to_regclass('issuance_service.issuance_prerequisite_continuations') AND c.contype IN ('p','u') AND c.convalidated AND array_length(c.conkey,1)=1
             AND i.indisunique AND i.indisvalid AND i.indisready AND i.indpred IS NULL AND i.indexprs IS NULL
             AND a.attname IN ('transaction_id','intent_digest','evidence_digest','flow_instance_id','credential_id'))
             = ARRAY['credential_id','evidence_digest','flow_instance_id','intent_digest','transaction_id']::text[]
         AND EXISTS (SELECT 1 FROM pg_constraint c WHERE c.conrelid=to_regclass('issuance_service.issuance_prerequisite_continuations') AND c.contype='f' AND c.convalidated
             AND c.confrelid=to_regclass('issuance_service.issuance_transactions') AND c.confdeltype='a' AND c.confupdtype='a'
             AND array_length(c.conkey,1)=1 AND array_length(c.confkey,1)=1
             AND (SELECT a.attname FROM pg_attribute a WHERE a.attrelid=c.conrelid AND a.attnum=c.conkey[1])='transaction_id'
             AND (SELECT a.attname FROM pg_attribute a WHERE a.attrelid=c.confrelid AND a.attnum=c.confkey[1])='id')")
        .fetch_one(&mut *connection).await?;
    if !intent_column || receipt_columns != 10 || !receipt_constraints {
        return Err(failure());
    }
    for (name, table, marker, trigger_type) in [
        (
            "guard_verification_prerequisite_transaction",
            "issuance_transactions",
            "prerequisite_transaction",
            23_i16,
        ),
        (
            "guard_verification_prerequisite_continuation",
            "issuance_prerequisite_continuations",
            "prerequisite_continuation",
            31,
        ),
        (
            "guard_verification_prerequisite_authorization",
            "authorization_sessions",
            "prerequisite_authorization",
            23,
        ),
    ] {
        let start = format!("AS ${marker}$");
        let end = format!("${marker}$;");
        let expected = MIGRATION_SQL
            .split_once(&start)
            .and_then(|(_, rest)| rest.split_once(&end))
            .map(|(body, _)| body)
            .ok_or_else(failure)?;
        let valid: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_language l ON l.oid=p.prolang
             WHERE t.tgrelid=to_regclass($1) AND t.tgname=$2 AND t.tgenabled='O' AND t.tgtype=$3 AND NOT t.tgisinternal
             AND t.tgqual IS NULL AND t.tgattr::text='' AND t.tgnargs=0 AND p.oid=to_regprocedure($4)
             AND p.prosrc=$5 AND p.prorettype='trigger'::regtype AND p.provolatile='v' AND NOT p.proisstrict
             AND NOT p.prosecdef AND p.proconfig IS NULL AND p.prokind='f' AND p.pronargs=0 AND p.proargmodes IS NULL
             AND p.pronargdefaults=0 AND p.provariadic=0 AND l.lanname='plpgsql')")
            .bind(format!("issuance_service.{table}")).bind(name).bind(trigger_type)
            .bind(format!("issuance_service.{name}()")).bind(expected)
            .fetch_one(&mut *connection).await?;
        if !valid {
            return Err(failure());
        }
    }
    Ok(())
}

/// The dataset includes the actual issuer target and immutable output settings.
/// DPoP is bound by the existing bearer/session admission and is added only at
/// token exchange; it is not a credential claim or a change to issuing intent.
pub(crate) fn dataset_digest(
    transaction: &CredentialTransaction,
) -> Result<String, CredentialIssuanceError> {
    let mut claims = transaction.claims.clone();
    claims.remove("_dpop_jkt");
    digest_domain_json(
        ISSUANCE_DATASET_DIGEST_DOMAIN_V1,
        &json!({
            "claims": claims,
            "credential_type": transaction.credential_type,
            "selective_disclosure_claims": transaction.selective_disclosure_claims,
            "zk_predicate_claims": transaction.zk_predicate_claims,
            "validity_days": transaction.validity_days,
            "revocation_profile_id": transaction.revocation_profile_id,
            "issuer_profile_id": transaction.issuer_profile_id,
            "issuer_mode": transaction.issuer_mode,
            "issuer_algorithm": transaction.issuer_algorithm,
            "signing_service_id": transaction.signing_service_id,
        }),
    )
    .map_err(|_| invalid())
}

pub(crate) fn bind_intent(
    transaction: &CredentialTransaction,
    template_version: u32,
    principal: &str,
    prerequisite: IssuancePrerequisitePolicyV1,
) -> Result<IssuanceIntentBindingV1, CredentialIssuanceError> {
    let mut intent = IssuanceIntentBindingV1 {
        contract: ISSUANCE_INTENT_CONTRACT_V1.into(),
        organization_id: transaction.organization_id.clone(),
        transaction_id: transaction.id.clone(),
        initiating_principal_id: principal.into(),
        applicant_id: transaction.applicant_id.clone(),
        application_id: transaction.application_id.clone(),
        subject_did: transaction.subject_did.clone(),
        credential_template_id: transaction.credential_template_id.clone(),
        credential_template_version: template_version,
        credential_configuration_id: credential_configuration_id_for_format(
            transaction.credential_type.as_deref().ok_or_else(invalid)?,
            &transaction.credential_payload_format,
        ),
        credential_payload_format: transaction.credential_payload_format.clone(),
        issuer_did: transaction.issuer_did.clone().ok_or_else(invalid)?,
        dataset_digest: dataset_digest(transaction)?,
        prerequisite,
        flow_instance_id: uuid::Uuid::new_v4().to_string(),
        created_at_epoch_micros: transaction.created_at.timestamp_micros(),
        expires_at_epoch_micros: transaction.expires_at.timestamp_micros(),
        intent_digest: String::new(),
    };
    intent.intent_digest = intent.recompute_digest().map_err(|_| invalid())?;
    intent.validate().map_err(|_| invalid())?;
    Ok(intent)
}

pub(crate) fn validate_transaction(
    transaction: &CredentialTransaction,
) -> Result<(), CredentialIssuanceError> {
    let Some(intent) = transaction.issuance_intent.as_ref() else {
        return Ok(());
    };
    intent.validate().map_err(|_| invalid())?;
    if transaction.jwt_vc_profile.is_some()
        || transaction.jwt_vc_signing_timing.is_some()
        || transaction.application_id.is_some()
        || transaction.renewal_of_credential_id.is_some()
        || transaction.renewable
        || transaction.delivery_mode != "wallet_only"
        || !transaction.wallet_configs.is_empty()
        || transaction.oid4vci_client_id.is_some()
        || !matches!(transaction.credential_payload_format.as_str(), "SD_JWT_VC")
        || intent.organization_id != transaction.organization_id
        || intent.transaction_id != transaction.id
        || intent.applicant_id != transaction.applicant_id
        || intent.application_id != transaction.application_id
        || intent.subject_did != transaction.subject_did
        || intent.credential_template_id != transaction.credential_template_id
        || intent.credential_payload_format != transaction.credential_payload_format
        || transaction.issuer_did.as_deref() != Some(intent.issuer_did.as_str())
        || intent.created_at_epoch_micros != transaction.created_at.timestamp_micros()
        || intent.expires_at_epoch_micros != transaction.expires_at.timestamp_micros()
        || intent.dataset_digest != dataset_digest(transaction)?
        || intent.credential_configuration_id
            != credential_configuration_id_for_format(
                transaction.credential_type.as_deref().ok_or_else(invalid)?,
                &transaction.credential_payload_format,
            )
    {
        tracing::debug!(
            stage = "transaction_binding",
            "prerequisite signing rejected"
        );
        return Err(invalid());
    }
    Ok(())
}

/// Opaque capability created only by authenticated owner acquisition. Its
/// constructor is intentionally not public and it is never deserializable.
///
/// ```compile_fail
/// use marty_issuance_service::verification_prerequisite::AcquiredPrerequisiteEvidence;
/// let _: AcquiredPrerequisiteEvidence = serde_json::from_str("{}").unwrap();
/// ```
///
/// ```compile_fail
/// use marty_issuance_service::verification_prerequisite::AcquiredPrerequisiteEvidence;
/// let _ = AcquiredPrerequisiteEvidence { response: todo!() };
/// ```
pub struct AcquiredPrerequisiteEvidence {
    response: marty_oid4vp_contract::issuance_prerequisite::IssuancePrerequisiteEvidenceResponseV1,
}

impl std::fmt::Debug for AcquiredPrerequisiteEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcquiredPrerequisiteEvidence")
            .finish_non_exhaustive()
    }
}

impl AcquiredPrerequisiteEvidence {
    pub(crate) fn validate_for_signing(
        &self,
        transaction: &CredentialTransaction,
        proof: &VerifiedCredentialProof,
        now_micros: i64,
    ) -> Result<(), CredentialIssuanceError> {
        validate_transaction(transaction)?;
        let intent = transaction.issuance_intent.as_ref().ok_or_else(invalid)?;
        self.response
            .validate_for_intent(intent, now_micros)
            .map_err(|error| {
                tracing::debug!(stage="signing_correspondence", reason=?error, "prerequisite signing rejected");
                invalid()
            })?;
        let holder = proof.holder_jwk.as_ref().ok_or_else(invalid)?;
        let thumbprint = issuer_public_key_thumbprint(holder).map_err(|_| invalid())?;
        if thumbprint != self.response.evidence.policy_evidence.holder_key_thumbprint {
            tracing::debug!(stage = "holder_binding", "prerequisite signing rejected");
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn validate_current(
        &self,
        transaction: &CredentialTransaction,
        holder_thumbprint: &str,
        now_micros: i64,
    ) -> Result<(), CredentialIssuanceError> {
        validate_transaction(transaction)?;
        let intent = transaction.issuance_intent.as_ref().ok_or_else(invalid)?;
        self.response
            .validate_for_intent(intent, now_micros)
            .map_err(|_| invalid())?;
        if holder_thumbprint != self.response.evidence.policy_evidence.holder_key_thumbprint {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn evidence_digest(&self) -> &str {
        &self.response.evidence.evidence_digest
    }

    pub(crate) fn holder_thumbprint(&self) -> &str {
        &self.response.evidence.policy_evidence.holder_key_thumbprint
    }

    pub(crate) fn expires_at_micros(&self) -> i64 {
        self.response.valid_until_epoch_micros()
    }
}

pub(crate) fn verified_holder_thumbprint(
    proof: &VerifiedCredentialProof,
) -> Result<String, CredentialIssuanceError> {
    issuer_public_key_thumbprint(proof.holder_jwk.as_ref().ok_or_else(invalid)?)
        .map_err(|_| invalid())
}

pub(crate) fn invalid() -> CredentialIssuanceError {
    CredentialIssuanceError::ApplicationEligibilityDenied
}

pub(crate) fn now_micros() -> i64 {
    Utc::now().timestamp_micros()
}

#[cfg(test)]
#[path = "verification_prerequisite_tests.rs"]
mod tests;
