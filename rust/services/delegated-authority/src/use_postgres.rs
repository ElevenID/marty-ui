//! PostgreSQL owner for retained delegated-use intent and original outcomes.
//! All external preparation occurs after a durable immutable claim. Authoritative
//! Flow writes and this ledger's admission/receipt/result share one transaction.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgRow, PgConnection, PgPool, Row};
use uuid::Uuid;

use crate::use_commands::*;
use crate::{
    decode_grant_snapshot, DelegationAuthorityService, DelegationCommandCaller,
    DelegationCommandIdentity, DelegationGrant, DelegationUseEvaluation,
    IssuedDelegatedDecisionReceipt, RepositoryError, DELEGATION_COMMAND_RESPONSE_PROFILE,
};

#[derive(Clone)]
pub struct PgDelegationUseRepository {
    pool: PgPool,
}

pub(crate) struct UseClaim {
    pub identity: DelegationCommandIdentity,
    pub command: DecodedDelegationUseMutation,
    pub challenge_id: Uuid,
}

pub(crate) struct RetainedUseOutcome {
    pub grant: DelegationGrant,
    pub command: DecodedDelegationUseMutation,
    pub response: Option<DelegationUseCommandResponse>,
}

pub(crate) enum ClaimResult {
    New(UseClaim),
    Existing(RetainedUseOutcome),
}

impl PgDelegationUseRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
    pub async fn readiness(&self) -> Result<(), DelegationUseCommandError> {
        verify_use_schema(&self.pool)
            .await
            .map_err(|_| DelegationUseCommandError::Unavailable)
    }
    pub(crate) async fn original(
        &self,
        caller: &DelegationCommandCaller,
        id: Uuid,
    ) -> Result<Option<RetainedUseOutcome>, DelegationUseCommandError> {
        let mut connection = self.pool.acquire().await.map_err(database)?;
        load_original(&mut connection, caller, id).await
    }
    pub(crate) async fn challenge(
        &self,
        caller: &DelegationCommandCaller,
        id: Uuid,
    ) -> Result<RetainedUseChallenge, DelegationUseCommandError> {
        let value: Option<Value> = sqlx::query_scalar("SELECT challenge_document FROM delegated_authority_service.use_admissions WHERE organization_id=$1 AND challenge_id=$2 AND actor_type=$3 AND actor_id=$4")
            .bind(caller.organization_id()).bind(id).bind(actor_type(caller)?).bind(&caller.actor().id)
            .fetch_optional(&self.pool).await.map_err(database)?;
        decode_challenge(
            value.ok_or(DelegationUseCommandError::AccessDenied)?,
            caller,
            id,
        )
    }
    pub(crate) async fn claim(
        &self,
        guard: &mut UseAccessGuard,
        challenge_id: Uuid,
    ) -> Result<ClaimResult, DelegationUseCommandError> {
        let identity = identity(&guard.caller, guard.command.command_id);
        let mut tx = self.pool.begin().await.map_err(database)?;
        command_lock(&mut tx, &identity).await?;
        if let Some(original) =
            load_original(&mut tx, &guard.caller, guard.command.command_id).await?
        {
            tx.commit().await.map_err(database)?;
            return Ok(ClaimResult::Existing(original));
        }
        require_unclaimed_namespace(&mut tx, &guard.caller, guard.command.command_id).await?;
        lock_grant(&mut tx, &guard.grant).await?;
        if let DelegationUseIntent::Finalize { challenge_id, .. } = &guard.command.intent {
            let stored = lock_admission(&mut tx, &guard.caller, *challenge_id).await?;
            if stored.grant != guard.grant {
                return Err(DelegationUseCommandError::Conflict);
            }
            if now(&mut tx).await? >= stored.expires_at {
                return Err(DelegationUseCommandError::Expired);
            }
        }
        guard.recheck(now(&mut tx).await?).await?;
        sqlx::query("INSERT INTO delegated_authority_service.use_command_claims (organization_id,actor_type,actor_id,command_id,command_name,command_digest,command_document,challenge_id,grant_id,grant_revision,grant_document) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
            .bind(guard.caller.organization_id()).bind(actor_type(&guard.caller)?).bind(&guard.caller.actor().id)
            .bind(guard.command.command_id).bind(guard.command.intent.command_name()).bind(&guard.command.digest).bind(&guard.command.document)
            .bind(challenge_id).bind(guard.grant.id).bind(revision(guard.grant.revision)?).bind(json(&guard.grant)?)
            .execute(&mut *tx).await.map_err(database)?;
        guard.check(now(&mut tx).await?)?;
        tx.commit().await.map_err(database)?;
        Ok(ClaimResult::New(UseClaim {
            identity,
            command: guard.command.clone(),
            challenge_id,
        }))
    }

    pub(crate) async fn commit_start(
        &self,
        claim: UseClaim,
        mut guard: UseAccessGuard,
        lifecycle: &DelegationAuthorityService,
        mut prepared: Box<dyn PreparedUseChallenge>,
        admission_deadline: DateTime<Utc>,
    ) -> Result<DelegationUseCommandResponse, DelegationUseCommandError> {
        // This is read-only freshness work. COMMIT below has no cancellation deadline.
        tokio::time::timeout(std::time::Duration::from_secs(5), prepared.revalidate())
            .await
            .map_err(|_| DelegationUseCommandError::Unavailable)??;
        let snapshot = prepared.snapshot().clone();
        validate_prepared_start(&snapshot, &claim, &guard, admission_deadline)?;
        let mut tx = self.pool.begin().await.map_err(database)?;
        command_lock(&mut tx, &claim.identity).await?;
        require_owned_claim(&mut tx, &guard.caller, &claim).await?;
        lock_grant(&mut tx, &guard.grant).await?;
        guard.recheck(now(&mut tx).await?).await?;
        let consent_until = check_current(lifecycle, &guard.grant).await?;
        let database_now = now(&mut tx).await?;
        guard.check(database_now)?;
        let commit_deadline = guard
            .access
            .valid_until
            .min(admission_deadline)
            .min(snapshot.expires_at)
            .min(consent_until);
        if database_now >= commit_deadline
            || snapshot.created_at > database_now
            || snapshot.expires_at > consent_until
        {
            return Err(DelegationUseCommandError::Expired);
        }
        let DelegationUseIntent::Start { grant, operation } = &claim.command.intent else {
            return Err(DelegationUseCommandError::InvalidCommand);
        };
        let retained = RetainedUseChallenge {
            organization_id: guard.caller.organization_id(),
            challenge_id: claim.challenge_id,
            grant: guard.grant.clone(),
            operation: operation.clone(),
            verifier_id: snapshot.verifier_id,
            nonce: snapshot.nonce,
            created_at: snapshot.created_at,
            expires_at: snapshot.expires_at,
        };
        // The Flow owner validates its storage identity and sealed preparation,
        // then writes the authoritative challenge using this exact connection.
        prepared.commit(&mut tx, database_now).await?;
        sqlx::query("INSERT INTO delegated_authority_service.use_admissions (organization_id,challenge_id,actor_type,actor_id,command_id,verifier_id,nonce,challenge_document,created_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,($9::text)::TIMESTAMPTZ,($10::text)::TIMESTAMPTZ)")
            .bind(retained.organization_id).bind(retained.challenge_id).bind(actor_type(&guard.caller)?).bind(&guard.caller.actor().id)
            .bind(claim.command.command_id).bind(&retained.verifier_id).bind(&retained.nonce).bind(json(&retained)?).bind(retained.created_at.to_rfc3339()).bind(retained.expires_at.to_rfc3339())
            .execute(&mut *tx).await.map_err(database)?;
        let response = response(
            &claim,
            DelegationUseCommandResult::Challenge {
                challenge_id: retained.challenge_id,
                grant: grant.clone(),
                operation: operation.clone(),
                created_at: retained.created_at,
                expires_at: retained.expires_at,
            },
        );
        insert_result(&mut tx, &guard, &response, commit_deadline).await?;
        guard.check(now(&mut tx).await?)?;
        tx.commit().await.map_err(database)?;
        Ok(response)
    }

    pub(crate) async fn commit_final(
        &self,
        claim: UseClaim,
        mut guard: UseAccessGuard,
        lifecycle: &DelegationAuthorityService,
        challenge: &RetainedUseChallenge,
        evaluation: DelegationUseEvaluation,
        receipt: IssuedDelegatedDecisionReceipt,
        proof_digest: &str,
        prepared: Box<dyn PreparedUseFinalization>,
    ) -> Result<DelegationUseCommandResponse, DelegationUseCommandError> {
        let DelegationUseIntent::Finalize {
            proof_submission_id,
            ..
        } = claim.command.intent
        else {
            return Err(DelegationUseCommandError::InvalidCommand);
        };
        validate_final(challenge, &guard, &evaluation, &receipt)?;
        let mut tx = self.pool.begin().await.map_err(database)?;
        command_lock(&mut tx, &claim.identity).await?;
        require_owned_claim(&mut tx, &guard.caller, &claim).await?;
        lock_grant(&mut tx, &guard.grant).await?;
        let original = lock_admission(&mut tx, &guard.caller, claim.challenge_id).await?;
        if json(&original)? != json(challenge)? {
            return Err(DelegationUseCommandError::Conflict);
        }
        guard.recheck(now(&mut tx).await?).await?;
        let consent_until = check_current(lifecycle, &guard.grant).await?;
        let database_now = now(&mut tx).await?;
        guard.check(database_now)?;
        let commit_deadline = guard
            .access
            .valid_until
            .min(consent_until)
            .min(challenge.expires_at)
            .min(evaluation.valid_until())
            .min(receipt.payload().expires_at);
        if database_now < evaluation.evaluated_at()
            || database_now < receipt.payload().issued_at
            || database_now >= commit_deadline
            || receipt.payload().expires_at > consent_until
        {
            return Err(DelegationUseCommandError::Expired);
        }
        prepared
            .commit(&mut tx, &evaluation, &receipt, database_now)
            .await?;
        let recorded_at = now(&mut tx).await?;
        guard.check(recorded_at)?;
        if recorded_at >= commit_deadline {
            return Err(DelegationUseCommandError::Expired);
        }
        let receipt_ref = delegated_use_receipt_ref(&receipt);
        let receipt_digest = format!(
            "sha256:{:x}",
            Sha256::digest(receipt.compact_jws().as_bytes())
        );
        sqlx::query("INSERT INTO delegated_authority_service.use_receipts (organization_id,challenge_id,actor_type,actor_id,command_id,proof_submission_id,proof_digest,receipt_ref,receipt_digest,compact_jws,receipt_document,recorded_at,authorization_expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,($13::text)::TIMESTAMPTZ)")
            .bind(challenge.organization_id).bind(challenge.challenge_id).bind(actor_type(&guard.caller)?).bind(&guard.caller.actor().id)
            .bind(claim.command.command_id).bind(proof_submission_id).bind(proof_digest).bind(&receipt_ref).bind(&receipt_digest)
            .bind(receipt.compact_jws()).bind(json(receipt.payload())?).bind(recorded_at).bind(receipt.payload().expires_at.to_rfc3339())
            .execute(&mut *tx).await.map_err(database)?;
        let response = response(
            &claim,
            DelegationUseCommandResult::FinalUse {
                challenge_id: challenge.challenge_id,
                decision: receipt.payload().decision.into(),
                receipt_ref,
                receipt_digest,
                recorded_at,
                authorization_expires_at: receipt.payload().expires_at,
                semantics: "EVIDENCE_ONLY".into(),
            },
        );
        insert_result(&mut tx, &guard, &response, commit_deadline).await?;
        guard.check(now(&mut tx).await?)?;
        tx.commit().await.map_err(database)?;
        Ok(response)
    }
}

pub fn delegated_use_receipt_ref(receipt: &IssuedDelegatedDecisionReceipt) -> String {
    format!("urn:marty:delegated-receipt:{}", receipt.payload().id)
}

fn response(claim: &UseClaim, result: DelegationUseCommandResult) -> DelegationUseCommandResponse {
    DelegationUseCommandResponse {
        profile: DELEGATION_COMMAND_RESPONSE_PROFILE.into(),
        original_command_id: claim.command.command_id,
        command_digest: claim.command.digest.clone(),
        recovered: false,
        result,
    }
}
async fn insert_result(
    tx: &mut PgConnection,
    guard: &UseAccessGuard,
    response: &DelegationUseCommandResponse,
    deadline: DateTime<Utc>,
) -> Result<(), DelegationUseCommandError> {
    let checked = now(tx).await?;
    if checked >= deadline {
        return Err(DelegationUseCommandError::Expired);
    }
    sqlx::query("INSERT INTO delegated_authority_service.use_command_results (organization_id,actor_type,actor_id,command_id,response_document,checked_at,commit_not_after) VALUES ($1,$2,$3,$4,$5,$6,$7)")
        .bind(guard.caller.organization_id()).bind(actor_type(&guard.caller)?).bind(&guard.caller.actor().id).bind(response.original_command_id).bind(json(response)?).bind(checked).bind(deadline)
        .execute(&mut *tx).await.map_err(database)?;
    Ok(())
}
async fn check_current(
    lifecycle: &DelegationAuthorityService,
    grant: &DelegationGrant,
) -> Result<DateTime<Utc>, DelegationUseCommandError> {
    let latest = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        lifecycle.resolve_verified(grant.organization_id, grant.id),
    )
    .await
    .map_err(|_| DelegationUseCommandError::Unavailable)?
    .map_err(|_| DelegationUseCommandError::AccessDenied)?;
    if latest.grant != *grant {
        return Err(DelegationUseCommandError::Conflict);
    }
    Ok(latest.consent_valid_until)
}
async fn command_lock(
    tx: &mut PgConnection,
    identity: &DelegationCommandIdentity,
) -> Result<(), DelegationUseCommandError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(
            identity
                .lock_key()
                .map_err(|_| DelegationUseCommandError::Unavailable)?,
        )
        .execute(tx)
        .await
        .map_err(database)?;
    Ok(())
}
async fn require_unclaimed_namespace(
    tx: &mut PgConnection,
    caller: &DelegationCommandCaller,
    id: Uuid,
) -> Result<(), DelegationUseCommandError> {
    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM delegated_authority_service.command_identities WHERE organization_id=$1 AND actor_type=$2 AND actor_id=$3 AND command_id=$4)")
        .bind(caller.organization_id()).bind(actor_type(caller)?).bind(&caller.actor().id).bind(id).fetch_one(tx).await.map_err(database)?;
    if exists {
        return Err(DelegationUseCommandError::Conflict);
    }
    Ok(())
}
async fn require_owned_claim(
    tx: &mut PgConnection,
    caller: &DelegationCommandCaller,
    claim: &UseClaim,
) -> Result<(), DelegationUseCommandError> {
    let row=sqlx::query("SELECT command_digest,challenge_id FROM delegated_authority_service.lock_use_claim($1,$2,$3,$4)")
        .bind(caller.organization_id()).bind(actor_type(caller)?).bind(&caller.actor().id).bind(claim.command.command_id).fetch_optional(&mut *tx).await.map_err(database)?.ok_or(DelegationUseCommandError::Conflict)?;
    if row
        .try_get::<String, _>("command_digest")
        .map_err(database)?
        != claim.command.digest
        || row.try_get::<Uuid, _>("challenge_id").map_err(database)? != claim.challenge_id
    {
        return Err(DelegationUseCommandError::Conflict);
    }
    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM delegated_authority_service.use_command_results WHERE organization_id=$1 AND actor_type=$2 AND actor_id=$3 AND command_id=$4)")
        .bind(caller.organization_id()).bind(actor_type(caller)?).bind(&caller.actor().id).bind(claim.command.command_id).fetch_one(tx).await.map_err(database)?;
    if exists {
        return Err(DelegationUseCommandError::Conflict);
    }
    Ok(())
}
async fn lock_grant(
    tx: &mut PgConnection,
    expected: &DelegationGrant,
) -> Result<(), DelegationUseCommandError> {
    let value: Option<Value> = sqlx::query_scalar(
        "SELECT grant_document FROM delegated_authority_service.lock_use_grant($1,$2)",
    )
    .bind(expected.organization_id)
    .bind(expected.id)
    .fetch_optional(tx)
    .await
    .map_err(database)?;
    if value.as_ref() != Some(&json(expected)?) {
        return Err(DelegationUseCommandError::Conflict);
    }
    Ok(())
}
async fn lock_admission(
    tx: &mut PgConnection,
    caller: &DelegationCommandCaller,
    id: Uuid,
) -> Result<RetainedUseChallenge, DelegationUseCommandError> {
    let value:Option<Value>=sqlx::query_scalar("SELECT challenge_document FROM delegated_authority_service.lock_use_admission($1,$3,$4,$2)")
        .bind(caller.organization_id()).bind(id).bind(actor_type(caller)?).bind(&caller.actor().id).fetch_optional(tx).await.map_err(database)?;
    decode_challenge(
        value.ok_or(DelegationUseCommandError::AccessDenied)?,
        caller,
        id,
    )
}
fn decode_challenge(
    value: Value,
    caller: &DelegationCommandCaller,
    id: Uuid,
) -> Result<RetainedUseChallenge, DelegationUseCommandError> {
    let c: RetainedUseChallenge = serde_json::from_value(value.clone())
        .map_err(|_| DelegationUseCommandError::Unavailable)?;
    if json(&c)? != value
        || c.organization_id != caller.organization_id()
        || c.challenge_id != id
        || c.grant.organization_id != c.organization_id
        || &c.grant.terms.delegate != caller.actor()
        || c.created_at >= c.expires_at
        || c.grant.validate().is_err()
    {
        return Err(DelegationUseCommandError::Unavailable);
    }
    Ok(c)
}
async fn load_original(
    tx: &mut PgConnection,
    caller: &DelegationCommandCaller,
    id: Uuid,
) -> Result<Option<RetainedUseOutcome>, DelegationUseCommandError> {
    let row=sqlx::query("SELECT c.command_document,c.command_digest,c.grant_document,c.challenge_id,r.response_document FROM delegated_authority_service.use_command_claims c LEFT JOIN delegated_authority_service.use_command_results r USING(organization_id,actor_type,actor_id,command_id) WHERE c.organization_id=$1 AND c.actor_type=$2 AND c.actor_id=$3 AND c.command_id=$4")
        .bind(caller.organization_id()).bind(actor_type(caller)?).bind(&caller.actor().id).bind(id).fetch_optional(&mut *tx).await.map_err(database)?;
    row.map(|r| decode_original(r, caller, id)).transpose()
}
fn decode_original(
    row: PgRow,
    caller: &DelegationCommandCaller,
    id: Uuid,
) -> Result<RetainedUseOutcome, DelegationUseCommandError> {
    let value: Value = row.try_get("command_document").map_err(database)?;
    let DecodedDelegationUseCommand::Mutation(command) = decode_delegation_use_command(
        &serde_json::to_vec(&value).map_err(|_| DelegationUseCommandError::Unavailable)?,
    )?
    else {
        return Err(DelegationUseCommandError::Unavailable);
    };
    let digest: String = row.try_get("command_digest").map_err(database)?;
    let raw: Value = row.try_get("grant_document").map_err(database)?;
    let grant = decode_grant_snapshot(
        &serde_json::to_vec(&raw).map_err(|_| DelegationUseCommandError::Unavailable)?,
    )
    .map_err(|_| DelegationUseCommandError::Unavailable)?;
    if command.command_id != id
        || command.digest != digest
        || grant.organization_id != caller.organization_id()
        || &grant.terms.delegate != caller.actor()
    {
        return Err(DelegationUseCommandError::Unavailable);
    }
    let value: Option<Value> = row.try_get("response_document").map_err(database)?;
    let response = value
        .map(|v| {
            let response: DelegationUseCommandResponse = serde_json::from_value(v.clone())
                .map_err(|_| DelegationUseCommandError::Unavailable)?;
            if json(&response)? != v
                || response.profile != DELEGATION_COMMAND_RESPONSE_PROFILE
                || response.original_command_id != id
                || response.command_digest != digest
                || response.recovered
            {
                return Err(DelegationUseCommandError::Unavailable);
            }
            match (&command.intent, &response.result) {
                (
                    DelegationUseIntent::Start {
                        grant: reference,
                        operation,
                    },
                    DelegationUseCommandResult::Challenge {
                        challenge_id,
                        grant: actual,
                        operation: actual_op,
                        created_at,
                        expires_at,
                    },
                ) if reference == actual
                    && operation == actual_op
                    && reference.id == grant.id
                    && reference.revision == grant.revision
                    && reference.terms_digest == grant.terms_digest
                    && *challenge_id
                        == row.try_get::<Uuid, _>("challenge_id").map_err(database)?
                    && created_at < expires_at => {}
                (
                    DelegationUseIntent::Finalize { challenge_id, .. },
                    DelegationUseCommandResult::FinalUse {
                        challenge_id: actual,
                        decision,
                        receipt_ref,
                        receipt_digest,
                        recorded_at,
                        authorization_expires_at,
                        semantics,
                    },
                ) if challenge_id == actual
                    && matches!(decision.as_str(), "PERMIT" | "DENY")
                    && crate::domain::valid_uri(Some(receipt_ref))
                    && crate::domain::valid_digest(Some(receipt_digest))
                    && recorded_at < authorization_expires_at
                    && semantics == "EVIDENCE_ONLY" => {}
                _ => return Err(DelegationUseCommandError::Unavailable),
            }
            Ok(response)
        })
        .transpose()?;
    Ok(RetainedUseOutcome {
        grant,
        command,
        response,
    })
}
fn validate_prepared_start(
    s: &PreparedUseChallengeSnapshot,
    c: &UseClaim,
    g: &UseAccessGuard,
    deadline: DateTime<Utc>,
) -> Result<(), DelegationUseCommandError> {
    if s.organization_id != g.caller.organization_id()
        || s.challenge_id != c.challenge_id
        || !valid_retained_verifier_id(&s.verifier_id)
        || !(22..=128).contains(&s.nonce.len())
        || !s
            .nonce
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        || s.created_at >= s.expires_at
        || s.expires_at > deadline
        || s.created_at < g.started
    {
        return Err(DelegationUseCommandError::InvalidCommand);
    }
    Ok(())
}

fn valid_retained_verifier_id(value: &str) -> bool {
    // Match the existing OID4VP proof adapter's opaque client-ID boundary, and
    // retain the tighter existing ledger storage bound. Flow owns the actual
    // selected prefix and identifier; public command bodies never set it.
    value.len() <= 1_024 && crate::oid4vp::valid_verifier_client_id(value)
}

#[cfg(test)]
mod verifier_id_tests {
    use super::valid_retained_verifier_id;

    #[test]
    fn retained_verifier_preserves_oid4vp_client_ids_and_rejects_invalid_text() {
        for value in [
            "decentralized_identifier:did:web:verifier.example",
            "redirect_uri:https://verifier.example/response",
            "x509_hash:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            "did:web:verifier.example",
            "https://verifier.example",
        ] {
            assert!(valid_retained_verifier_id(value), "rejected {value:?}");
        }
        for value in [
            "",
            " ",
            "decentralized_identifier:did:web:verifier.example ",
            "decentralized_identifier:did:web:verifier\n.example",
            "decentralized_identifier:did:web:verifier\t.example",
            "decentralized_identifier:did:web:verifier\0.example",
            "decentralized_identifier:did:web:vérifier.example",
            "decentralized_identifier:did:web:verifier\u{7f}.example",
        ] {
            assert!(!valid_retained_verifier_id(value), "accepted {value:?}");
        }
        assert!(!valid_retained_verifier_id(&"x".repeat(1_025)));
    }
}
fn validate_final(
    c: &RetainedUseChallenge,
    g: &UseAccessGuard,
    e: &DelegationUseEvaluation,
    r: &IssuedDelegatedDecisionReceipt,
) -> Result<(), DelegationUseCommandError> {
    let p = r.payload();
    if c.organization_id != e.organization_id()
        || c.challenge_id != e.challenge_id()
        || c.grant != g.grant
        || c.grant.id != e.grant_id()
        || c.grant.revision != e.grant_revision()
        || c.grant.terms_digest != e.terms_digest()
        || &c.grant.terms.delegate != e.actor()
        || c.operation.action != e.action()
        || c.operation.audience != e.audience()
        || c.operation.resource_id != e.resource()
        || c.operation.request_profile != e.operation_profile()
        || c.operation.request_digest != e.operation_digest()
        || c.nonce != e.receipt_proof_challenge()
        || e.receipt_proof_verified_at() < c.created_at
        || e.evaluated_at() < c.created_at
        || p.decision != e.decision().as_str()
        || p.evaluation.challenge != c.nonce
        || p.evaluation.organization_id != c.organization_id
        || p.issued_at < e.evaluated_at()
        || p.expires_at > e.valid_until()
        || p.expires_at > c.expires_at
        || p.expires_at <= p.issued_at
    {
        return Err(DelegationUseCommandError::InvalidCommand);
    }
    Ok(())
}
fn identity(c: &DelegationCommandCaller, id: Uuid) -> DelegationCommandIdentity {
    DelegationCommandIdentity {
        organization_id: c.organization_id(),
        actor: c.actor().clone(),
        command_id: id,
    }
}
fn actor_type(c: &DelegationCommandCaller) -> Result<String, DelegationUseCommandError> {
    serde_json::to_value(c.actor().principal_type)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or(DelegationUseCommandError::InvalidCommand)
}
fn revision(n: u64) -> Result<i64, DelegationUseCommandError> {
    i64::try_from(n).map_err(|_| DelegationUseCommandError::InvalidCommand)
}
fn json<T: serde::Serialize>(v: &T) -> Result<Value, DelegationUseCommandError> {
    serde_json::to_value(v).map_err(|_| DelegationUseCommandError::Unavailable)
}
async fn now(tx: &mut PgConnection) -> Result<DateTime<Utc>, DelegationUseCommandError> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(tx)
        .await
        .map_err(database)
}
fn database(error: sqlx::Error) -> DelegationUseCommandError {
    if error
        .as_database_error()
        .is_some_and(|e| e.is_unique_violation())
    {
        DelegationUseCommandError::Conflict
    } else {
        DelegationUseCommandError::Unavailable
    }
}

/// Metadata-only schema checks also usable by the existing lifecycle writer,
/// which does not receive SELECT access to proof/admission/receipt tables.
pub(crate) async fn verify_use_schema(pool: &PgPool) -> Result<(), RepositoryError> {
    let present:bool=sqlx::query_scalar("SELECT to_regclass('delegated_authority_service.command_identities') IS NOT NULL AND to_regclass('delegated_authority_service.use_command_claims') IS NOT NULL AND to_regclass('delegated_authority_service.use_admissions') IS NOT NULL AND to_regclass('delegated_authority_service.use_receipts') IS NOT NULL AND to_regclass('delegated_authority_service.use_command_results') IS NOT NULL")
        .fetch_one(pool).await.map_err(|_|RepositoryError::DatabaseFailure)?;
    if !present {
        return Err(RepositoryError::SchemaNotReady);
    }
    let count:i64=sqlx::query_scalar("WITH expected(table_name,trigger_name,function_name,trigger_type,deferred) AS (VALUES
        ('command_results','command_results_identity','register_lifecycle_command_identity',7,false),
        ('use_command_claims','use_command_claims_binding','guard_use_command_claim',7,false),
        ('use_admissions','use_admissions_binding','guard_use_admission',7,false),
        ('use_receipts','use_receipts_binding','guard_use_receipt',7,false),
        ('use_command_results','use_command_results_binding','guard_use_result',7,false),
        ('use_command_results','use_command_results_commit','check_use_result_commit',5,true)), all_expected AS (
        SELECT * FROM expected UNION ALL SELECT t.name,t.name||'_immutable','reject_lifecycle_event_mutation',27,false FROM (VALUES('command_identities'),('use_command_claims'),('use_admissions'),('use_receipts'),('use_command_results')) t(name)
        UNION ALL SELECT t.name,t.name||'_no_truncate','reject_lifecycle_event_mutation',34,false FROM (VALUES('command_identities'),('use_command_claims'),('use_admissions'),('use_receipts'),('use_command_results')) t(name))
        SELECT count(*) FROM all_expected e JOIN pg_trigger t ON t.tgrelid=to_regclass('delegated_authority_service.'||e.table_name) AND t.tgname=e.trigger_name
        JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_language l ON l.oid=p.prolang WHERE NOT t.tgisinternal AND t.tgenabled='O' AND t.tgqual IS NULL AND t.tgtype=e.trigger_type
        AND t.tgnargs=0 AND t.tgattr=''::int2vector AND t.tgdeferrable=e.deferred AND t.tginitdeferred=e.deferred AND (t.tgconstraint<>0)=e.deferred
        AND t.tgfoid=to_regprocedure('delegated_authority_service.'||e.function_name||'()') AND NOT p.prosecdef AND p.prorettype='trigger'::regtype AND p.prokind='f'
        AND l.lanname='plpgsql' AND p.proconfig=ARRAY['search_path=pg_catalog']::text[]")
        .fetch_one(pool).await.map_err(|_|RepositoryError::DatabaseFailure)?;
    if count != 16 {
        return Err(RepositoryError::SchemaNotReady);
    }
    let indexes:i64=sqlx::query_scalar("WITH expected(table_name,index_name,columns,predicate) AS (VALUES
        ('command_identities','command_identities_pkey',ARRAY['organization_id','actor_type','actor_id','command_id'],NULL::TEXT),
        ('use_command_claims','use_command_claims_pkey',ARRAY['organization_id','actor_type','actor_id','command_id'],NULL::TEXT),
        ('use_command_claims','use_command_start_challenge',ARRAY['organization_id','challenge_id'],'START_USE'),
        ('use_command_claims','use_command_final_challenge',ARRAY['organization_id','challenge_id'],'FINALIZE_USE'),
        ('use_admissions','use_admissions_pkey',ARRAY['organization_id','challenge_id'],NULL::TEXT),
        ('use_admissions','use_admissions_organization_id_verifier_id_nonce_key',ARRAY['organization_id','verifier_id','nonce'],NULL::TEXT),
        ('use_receipts','use_receipts_pkey',ARRAY['organization_id','challenge_id'],NULL::TEXT),
        ('use_receipts','use_receipts_organization_id_receipt_ref_key',ARRAY['organization_id','receipt_ref'],NULL::TEXT),
        ('use_command_results','use_command_results_pkey',ARRAY['organization_id','actor_type','actor_id','command_id'],NULL::TEXT))
        SELECT count(*) FROM expected e JOIN pg_class t ON t.oid=to_regclass('delegated_authority_service.'||e.table_name)
        JOIN pg_index i ON i.indrelid=t.oid JOIN pg_class x ON x.oid=i.indexrelid
        WHERE x.relname=e.index_name AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive AND i.indexprs IS NULL
        AND i.indnatts=cardinality(e.columns) AND i.indnkeyatts=cardinality(e.columns)
        AND ARRAY(SELECT a.attname::TEXT FROM unnest(i.indkey) WITH ORDINALITY k(attnum,ord) JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=k.attnum ORDER BY k.ord)=e.columns
        AND pg_get_expr(i.indpred,i.indrelid) IS NOT DISTINCT FROM CASE WHEN e.predicate IS NULL THEN NULL ELSE format('(command_name = %L::text)',e.predicate) END")
        .fetch_one(pool).await.map_err(|_|RepositoryError::DatabaseFailure)?;
    if indexes != 9 {
        return Err(RepositoryError::SchemaNotReady);
    }
    verify_serving_lock_helpers(pool).await?;
    crate::machine_evidence::verify_machine_evidence_schema(pool).await?;
    Ok(())
}

async fn verify_serving_lock_helpers(pool: &PgPool) -> Result<(), RepositoryError> {
    let migration = include_str!("../migrations/0009_use_serving_locks.sql");
    let guard_body = migration
        .split_once(
            "CREATE OR REPLACE FUNCTION delegated_authority_service.guard_use_command_claim()",
        )
        .and_then(|(_, rest)| rest.split_once("AS $$"))
        .and_then(|(_, rest)| rest.split_once("$$;"))
        .map(|(body, _)| body)
        .ok_or(RepositoryError::SchemaNotReady)?;
    let guard_matches: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_proc WHERE oid=to_regprocedure('delegated_authority_service.guard_use_command_claim()') AND prosrc=$1)")
        .bind(guard_body).fetch_one(pool).await.map_err(|_| RepositoryError::DatabaseFailure)?;
    if !guard_matches {
        return Err(RepositoryError::SchemaNotReady);
    }

    for (name, signature, table) in [
        ("lock_use_grant", "uuid,uuid", "delegation_grants"),
        (
            "lock_use_claim",
            "uuid,text,text,uuid",
            "use_command_claims",
        ),
        (
            "lock_use_admission",
            "uuid,text,text,uuid",
            "use_admissions",
        ),
    ] {
        let marker = format!("CREATE FUNCTION delegated_authority_service.{name}(");
        let expected = migration
            .split_once(&marker)
            .and_then(|(_, rest)| rest.split_once("AS $lock$"))
            .and_then(|(_, rest)| rest.split_once("$lock$;"))
            .map(|(body, _)| body)
            .ok_or(RepositoryError::SchemaNotReady)?;
        let valid: bool = sqlx::query_scalar(
            "SELECT EXISTS(
          SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
          JOIN pg_language l ON l.oid=p.prolang JOIN pg_class t ON t.oid=to_regclass($3)
          WHERE p.oid=to_regprocedure($1) AND p.prosrc=$2 AND p.prosecdef
            AND p.prokind='f' AND p.provolatile='v' AND p.proparallel='u'
            AND p.proretset AND NOT p.proisstrict AND p.pronargdefaults=0
            AND p.prorettype=t.reltype AND l.lanname='sql'
            AND p.proconfig=ARRAY['search_path=pg_catalog']::TEXT[]
            AND p.proowner=n.nspowner AND t.relowner=n.nspowner
            AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
                           WHERE a.grantee=0 AND a.privilege_type='EXECUTE'))",
        )
        .bind(format!("delegated_authority_service.{name}({signature})"))
        .bind(expected)
        .bind(format!("delegated_authority_service.{table}"))
        .fetch_one(pool)
        .await
        .map_err(|_| RepositoryError::DatabaseFailure)?;
        if !valid {
            return Err(RepositoryError::SchemaNotReady);
        }
    }
    Ok(())
}
