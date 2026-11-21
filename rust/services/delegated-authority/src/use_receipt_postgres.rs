//! Read-only original receipt retrieval. This binds the stored artifact to its
//! immutable result and admission; cryptographic verification and fresh-use
//! policy belong to the independently configured receipt consumer.
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use super::*;
use crate::{
    domain::{valid_digest, valid_uri},
    DELEGATED_DECISION_JWS_TYP, DELEGATED_DECISION_RECEIPT_PROFILE, DELEGATED_EVALUATION_PROFILE,
};

pub(crate) struct RetainedOriginalReceipt {
    pub original: RetainedUseOutcome,
    pub receipt_ref: String,
    pub receipt_digest: String,
    pub compact_jws: String,
}

impl PgDelegationUseRepository {
    /// Exact original metadata is the input to the existing recovery-right
    /// owner. No artifact bytes are fetched by this initial scoped read.
    pub(crate) async fn receipt_original(
        &self,
        caller: &DelegationCommandCaller,
        command_id: Uuid,
    ) -> Result<Option<RetainedUseOutcome>, DelegationUseCommandError> {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut tx = self.pool.begin().await.map_err(database)?;
            configure_read(&mut tx).await?;
            let original = load_receipt_original(&mut tx, caller, command_id).await?;
            tx.commit().await.map_err(database)?;
            Ok(original)
        })
        .await
        .map_err(|_| DelegationUseCommandError::Unavailable)?
    }

    /// The caller must establish current recovery rights before this read and
    /// recheck them afterwards. Repeatable read keeps all original records in
    /// one snapshot without locks, signatures, evaluations or ledger writes.
    pub(crate) async fn original_receipt(
        &self,
        caller: &DelegationCommandCaller,
        command_id: Uuid,
    ) -> Result<RetainedOriginalReceipt, DelegationUseCommandError> {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut tx = self.pool.begin().await.map_err(database)?;
            configure_read(&mut tx).await?;
            let original = load_receipt_original(&mut tx, caller, command_id)
                .await?
                .ok_or(DelegationUseCommandError::Unavailable)?;
            let row = sqlx::query(
                "SELECT r.challenge_id,r.proof_submission_id,r.proof_digest,
                        r.receipt_ref,r.receipt_digest,r.compact_jws,r.receipt_document,
                        r.recorded_at,r.authorization_expires_at,
                        r.authorization_expires_at=(r.receipt_document->>'expires_at')::TIMESTAMPTZ
                            AS payload_expiry_matches_storage,
                        c.challenge_id AS claim_challenge_id,a.challenge_document
                 FROM delegated_authority_service.use_receipts r
                 JOIN delegated_authority_service.use_admissions a
                   ON a.organization_id=r.organization_id AND a.challenge_id=r.challenge_id
                  AND a.actor_type=r.actor_type AND a.actor_id=r.actor_id
                 JOIN delegated_authority_service.use_command_claims c
                   ON c.organization_id=r.organization_id AND c.actor_type=r.actor_type
                  AND c.actor_id=r.actor_id AND c.command_id=r.command_id
                 WHERE r.organization_id=$1 AND r.actor_type=$2
                   AND r.actor_id=$3 AND r.command_id=$4
                   AND octet_length(r.compact_jws) BETWEEN 1 AND 100000
                   AND octet_length(r.receipt_document::text) <= 100000
                   AND octet_length(a.challenge_document::text) <= 131072",
            )
            .bind(caller.organization_id())
            .bind(actor_type(caller)?)
            .bind(&caller.actor().id)
            .bind(command_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(database)?
            .ok_or(DelegationUseCommandError::Unavailable)?;
            let retained = bind_receipt(row, caller, original)?;
            tx.commit().await.map_err(database)?;
            Ok(retained)
        })
        .await
        .map_err(|_| DelegationUseCommandError::Unavailable)?
    }
}

/// Bound JSONB before it crosses the database connection. Twice the 65,536-byte
/// wire limit permits PostgreSQL's added JSON formatting whitespace without
/// narrowing the existing strict command/grant decoder. Corrupt metadata is an
/// unavailable original, not a new pending result. Shared mutation reads are
/// deliberately unaffected by these dedicated recovery transport bounds.
async fn load_receipt_original(
    tx: &mut PgConnection,
    caller: &DelegationCommandCaller,
    command_id: Uuid,
) -> Result<Option<RetainedUseOutcome>, DelegationUseCommandError> {
    let row = sqlx::query(
        "SELECT c.command_digest,c.challenge_id,bounds.metadata_bounded,
                CASE WHEN bounds.metadata_bounded THEN c.command_document END AS command_document,
                CASE WHEN bounds.metadata_bounded THEN c.grant_document END AS grant_document,
                CASE WHEN bounds.metadata_bounded THEN r.response_document END AS response_document
         FROM delegated_authority_service.use_command_claims c
         LEFT JOIN delegated_authority_service.use_command_results r
           USING(organization_id,actor_type,actor_id,command_id)
         CROSS JOIN LATERAL (
             SELECT octet_length(c.command_document::text) <= 131072
                AND octet_length(c.grant_document::text) <= 131072
                AND (r.response_document IS NULL OR octet_length(r.response_document::text) <= 131072)
                AS metadata_bounded
         ) bounds
         WHERE c.organization_id=$1 AND c.actor_type=$2 AND c.actor_id=$3 AND c.command_id=$4",
    )
    .bind(caller.organization_id())
    .bind(actor_type(caller)?)
    .bind(&caller.actor().id)
    .bind(command_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(database)?;
    row.map(|row| {
        if !row
            .try_get::<bool, _>("metadata_bounded")
            .map_err(database)?
        {
            return Err(DelegationUseCommandError::Unavailable);
        }
        decode_original(row, caller, command_id).map_err(|_| DelegationUseCommandError::Unavailable)
    })
    .transpose()
}

async fn configure_read(tx: &mut PgConnection) -> Result<(), DelegationUseCommandError> {
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(database)?;
    for statement in [
        "SET LOCAL statement_timeout='5s'",
        "SET LOCAL lock_timeout='5s'",
        "SET LOCAL TIME ZONE 'UTC'",
    ] {
        sqlx::query(statement)
            .execute(&mut *tx)
            .await
            .map_err(database)?;
    }
    Ok(())
}

fn bind_receipt(
    row: PgRow,
    caller: &DelegationCommandCaller,
    original: RetainedUseOutcome,
) -> Result<RetainedOriginalReceipt, DelegationUseCommandError> {
    let DelegationUseIntent::Finalize {
        challenge_id,
        proof_submission_id,
    } = &original.command.intent
    else {
        return Err(DelegationUseCommandError::Unavailable);
    };
    let response = original
        .response
        .as_ref()
        .ok_or(DelegationUseCommandError::Unavailable)?;
    let DelegationUseCommandResult::FinalUse {
        challenge_id: result_challenge,
        decision,
        receipt_ref: result_ref,
        receipt_digest: result_digest,
        recorded_at: result_recorded,
        authorization_expires_at: result_expiry,
        ..
    } = &response.result
    else {
        return Err(DelegationUseCommandError::Unavailable);
    };
    let admission = decode_challenge(
        row.try_get("challenge_document").map_err(database)?,
        caller,
        *challenge_id,
    )?;
    let receipt_ref: String = row.try_get("receipt_ref").map_err(database)?;
    let receipt_digest: String = row.try_get("receipt_digest").map_err(database)?;
    let compact_jws: String = row.try_get("compact_jws").map_err(database)?;
    let recorded_at: DateTime<Utc> = row.try_get("recorded_at").map_err(database)?;
    let expires_at: DateTime<Utc> = row.try_get("authorization_expires_at").map_err(database)?;
    let document: Value = row.try_get("receipt_document").map_err(database)?;
    let proof_digest: String = row.try_get("proof_digest").map_err(database)?;
    if row.try_get::<Uuid, _>("challenge_id").map_err(database)? != *challenge_id
        || row
            .try_get::<Uuid, _>("claim_challenge_id")
            .map_err(database)?
            != *challenge_id
        || row
            .try_get::<Uuid, _>("proof_submission_id")
            .map_err(database)?
            != *proof_submission_id
        || result_challenge != challenge_id
        || admission.grant != original.grant
        || receipt_ref != *result_ref
        || receipt_digest != *result_digest
        || recorded_at != *result_recorded
        || !row
            .try_get::<bool, _>("payload_expiry_matches_storage")
            .map_err(database)?
        || recorded_at >= expires_at
        || *result_expiry > admission.expires_at
        || !valid_digest(Some(&proof_digest))
        || receipt_digest != format!("sha256:{:x}", Sha256::digest(compact_jws.as_bytes()))
    {
        return Err(DelegationUseCommandError::Unavailable);
    }
    let payload = retained_payload(&compact_jws)?;
    let evaluation = &payload["evaluation"];
    let grant = &original.grant;
    let reference = serde_json::json!({"id":grant.id,"revision":grant.revision,"terms_digest":grant.terms_digest});
    let approval = grant
        .approval
        .as_ref()
        .ok_or(DelegationUseCommandError::Unavailable)?;
    let payload_id = payload["id"]
        .as_str()
        .and_then(|id| {
            Uuid::parse_str(id)
                .ok()
                .filter(|uuid| !uuid.is_nil() && uuid.to_string() == id)
        })
        .ok_or(DelegationUseCommandError::Unavailable)?;
    let issued_at = timestamp(&payload, "issued_at")?;
    let evaluated_at = timestamp(evaluation, "evaluated_at")?;
    let status = &evaluation["status"];
    if payload != document
        || payload["profile"] != DELEGATED_DECISION_RECEIPT_PROFILE
        || receipt_ref != format!("urn:marty:delegated-receipt:{payload_id}")
        || payload["decision"].as_str() != Some(decision.as_str())
        // PostgreSQL stores microseconds; the signed JSON and original result
        // retain their exact nanosecond spelling. SQL above checks the actual
        // database cast while this comparison preserves exact signed time.
        || timestamp(&payload, "expires_at")? != *result_expiry
        || evaluation["profile"] != DELEGATED_EVALUATION_PROFILE
        || evaluation["organization_id"] != json(&caller.organization_id())?
        || evaluation["grant"] != reference
        || evaluation["actor"] != json(caller.actor())?
        || evaluation["subject"] != json(&grant.terms.subject)?
        || evaluation["binding"] != json(&grant.terms.binding)?
        || evaluation["operation"] != json(&admission.operation)?
        || evaluation["challenge"].as_str() != Some(admission.nonce.as_str())
        || evaluation["approval_evidence_ref"].as_str() != Some(approval.evidence_ref.as_str())
        || evaluation["authority_evidence_ref"].as_str() != Some(approval.authority_evidence_ref.as_str())
        || !valid_uri(evaluation["proof_evidence_ref"].as_str())
        || status["issuer"] != json(&grant.authority.issuer)?
        || status["grant"] != reference || status["state"] != "ACTIVE"
        || status["evidence_ref"].as_str() != Some(grant.authority.status_ref.as_str())
        || !valid_uri(payload["policy"]["id"].as_str())
        || !valid_digest(payload["policy"]["version_digest"].as_str())
        || issued_at < evaluated_at || issued_at > recorded_at
        || evaluated_at < admission.created_at
        || timestamp(evaluation, "proof_verified_at")? > evaluated_at
        || timestamp(status, "checked_at")? > evaluated_at
        || timestamp(evaluation, "proof_valid_until")? < *result_expiry
        || timestamp(status, "valid_until")? < *result_expiry
    {
        return Err(DelegationUseCommandError::Unavailable);
    }
    // Expiry is deliberately compared only with the original context, never
    // with recovery time. Revoked or expired originals remain historical data.
    Ok(RetainedOriginalReceipt {
        original,
        receipt_ref,
        receipt_digest,
        compact_jws,
    })
}

fn retained_payload(compact: &str) -> Result<Value, DelegationUseCommandError> {
    if compact.is_empty() || compact.len() > 100_000 || !compact.is_ascii() {
        return Err(DelegationUseCommandError::Unavailable);
    }
    let mut parts = compact.split('.');
    let protected = segment(parts.next())?;
    let payload = segment(parts.next())?;
    let signature = segment(parts.next())?;
    if parts.next().is_some() || signature.len() != 64 || protected.len() > 2048 {
        return Err(DelegationUseCommandError::Unavailable);
    }
    let header = marty_crypto::strict_json::parse_unique_json(&protected)
        .map_err(|_| DelegationUseCommandError::Unavailable)?;
    if header.as_object().is_none_or(|object| object.len() != 3)
        || !matches!(header["alg"].as_str(), Some("ES256" | "EdDSA"))
        || header["typ"] != DELEGATED_DECISION_JWS_TYP
        || header["kid"].as_str().is_none_or(|kid| {
            kid.is_empty() || kid.len() > 512 || !kid.bytes().all(|b| b.is_ascii_graphic())
        })
    {
        return Err(DelegationUseCommandError::Unavailable);
    }
    let payload = marty_crypto::strict_json::parse_unique_json(&payload)
        .map_err(|_| DelegationUseCommandError::Unavailable)?;
    if !payload.is_object() {
        return Err(DelegationUseCommandError::Unavailable);
    }
    Ok(payload)
}

fn segment(part: Option<&str>) -> Result<Vec<u8>, DelegationUseCommandError> {
    let part = part
        .filter(|part| !part.is_empty())
        .ok_or(DelegationUseCommandError::Unavailable)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| DelegationUseCommandError::Unavailable)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != part {
        return Err(DelegationUseCommandError::Unavailable);
    }
    Ok(decoded)
}

fn timestamp(document: &Value, name: &str) -> Result<DateTime<Utc>, DelegationUseCommandError> {
    let value = document[name]
        .as_str()
        .ok_or(DelegationUseCommandError::Unavailable)?;
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| DelegationUseCommandError::Unavailable)?
        .with_timezone(&Utc);
    if json(&parsed)? != document[name] {
        return Err(DelegationUseCommandError::Unavailable);
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_header_allows_the_generic_issuers_maximum_escaped_key_id() {
        // Parser compatibility only: this synthetic envelope does not create a
        // retained result or establish receipt signature verification.
        let header = serde_json::to_vec(&serde_json::json!({
            "alg":"EdDSA","kid":"\\".repeat(512),"typ":DELEGATED_DECISION_JWS_TYP,
        }))
        .unwrap();
        assert!(header.len() > 1024);
        let compact = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(b"{}"),
            URL_SAFE_NO_PAD.encode([9u8; 64])
        );
        assert_eq!(retained_payload(&compact).unwrap(), serde_json::json!({}));
    }
}
