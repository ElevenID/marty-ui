//! Retained, single-use managed key enrollment. All expected proof context comes
//! from the locked Organization inventory and its own immutable challenge row.
use chrono::{DateTime, Utc};
use marty_principal_runtime_binding::managed_enrollment::{
    verify_enrollment_proof, EnrollmentAlgorithm, EnrollmentChallenge,
    EnrollmentChallengeParameters, VerifiedEnrollmentProof, MAX_ENROLLMENT_PROOF_BYTES,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgRow, PgConnection, Postgres, Row, Transaction};
use uuid::Uuid;

use super::{
    database_error,
    domain::{valid_revision, validate_snapshot},
    service::{load, now},
    *,
};
use crate::{AuditEvent, ForwardedPrincipal};

struct RetainedChallenge {
    challenge: EnrollmentChallenge,
    invalidated_at: Option<DateTime<Utc>>,
    result: Option<AgentEnrollmentResult>,
}

impl RetainedChallenge {
    fn presentation(
        &self,
        recovered: bool,
    ) -> Result<AgentEnrollmentChallenge, AgentDirectoryError> {
        Ok(AgentEnrollmentChallenge {
            profile: MANAGED_ENROLLMENT_PROFILE.into(),
            challenge_id: self.challenge.challenge_id(),
            organization_id: self.challenge.organization_id(),
            agent_id: self.challenge.agent_id(),
            expected_revision: self.challenge.expected_revision(),
            challenge: self.challenge.document(),
            signing_payload: self.challenge.payload_b64url(),
            challenge_digest: self.challenge.digest(),
            expires_at: epoch(self.challenge.expires_at())?,
            recovered,
        })
    }
    fn state(&self, observed: DateTime<Utc>) -> Result<&'static str, AgentDirectoryError> {
        Ok(if self.result.is_some() {
            "CONSUMED"
        } else if self.invalidated_at.is_some() {
            "INVALIDATED"
        } else if observed >= epoch(self.challenge.expires_at())? {
            "EXPIRED"
        } else {
            "PENDING"
        })
    }
}

impl AgentDirectoryService {
    pub async fn create_enrollment_challenge(
        &self,
        organization: Uuid,
        principal: &ForwardedPrincipal,
        session: &AgentEnrollmentSession,
        agent: Uuid,
        request: CreateAgentEnrollmentChallenge,
    ) -> Result<AgentEnrollmentChallenge, AgentDirectoryError> {
        let configuration = self
            .enrollment
            .as_ref()
            .ok_or(AgentDirectoryError::NotFound)?;
        valid_revision(request.expected_revision)?;
        let mut tx = self.begin().await?;
        self.authorize_enrollment(&mut tx, organization, principal, true)
            .await?;
        let identity = load(&mut tx, organization, agent, true).await?;
        self.authorize_enrollment(&mut tx, organization, principal, true)
            .await?;
        let observed = now(&mut tx).await?;
        session.check(organization, principal, observed)?;
        eligible(&identity, request.expected_revision, observed)?;
        let key = identity
            .keys
            .first()
            .ok_or(AgentDirectoryError::CorruptData)?;
        current_key(&mut tx, &identity).await?;
        let existing: Vec<Uuid> = sqlx::query_scalar(
            "SELECT c.challenge_id FROM organization_service.agent_enrollment_challenges c \
             WHERE c.organization_id=$1 AND c.agent_id=$2 \
               AND NOT EXISTS (SELECT 1 FROM organization_service.agent_enrollment_outcomes o WHERE o.challenge_id=c.challenge_id) \
               AND NOT EXISTS (SELECT 1 FROM organization_service.agent_enrollment_invalidations i WHERE i.challenge_id=c.challenge_id) \
             ORDER BY c.issued_at DESC,c.challenge_id FOR UPDATE OF c")
            .bind(organization).bind(agent).fetch_all(&mut *tx).await.map_err(database_error)?;
        if existing.len() > 1 {
            return Err(AgentDirectoryError::CorruptData);
        }
        if let Some(id) = existing.first() {
            let retained = retained(&mut tx, organization, agent, *id).await?;
            let challenge = &retained.challenge;
            if retained.state(observed)? == "PENDING"
                && challenge.administrator_id() == session.user_id
                && challenge.session_ref() == session.session_ref
                && challenge.expected_revision() == identity.revision
                && challenge.key_id() == key.key_id
                && challenge.audience() == configuration.audience
                && challenge.policy() == &configuration.policy
            {
                let result = retained.presentation(true)?;
                self.final_enrollment_check(
                    &mut tx,
                    organization,
                    principal,
                    session,
                    observed,
                    Some(result.expires_at),
                    true,
                )
                .await?;
                tx.commit().await.map_err(database_error)?;
                return Ok(result);
            }
            invalidate_pending(
                &mut tx,
                organization,
                agent,
                observed,
                if retained.state(observed)? == "EXPIRED" {
                    "EXPIRED"
                } else {
                    "SUPERSEDED"
                },
            )
            .await?;
        }
        let challenge = EnrollmentChallenge::new(EnrollmentChallengeParameters {
            challenge_id: Uuid::new_v4(),
            organization_id: organization,
            agent_id: agent,
            key_id: key.key_id,
            administrator_id: session.user_id,
            expected_revision: identity.revision,
            key_algorithm: match key.algorithm.as_str() {
                "ES256" => EnrollmentAlgorithm::ES256,
                "EdDSA" => EnrollmentAlgorithm::EdDSA,
                _ => return Err(AgentDirectoryError::CorruptData),
            },
            key_thumbprint: key.fingerprint.typed()?,
            runtime_instance_ref: identity.runtime_instance_ref.clone(),
            issuer: identity.issuer.clone(),
            subject: identity.subject.clone(),
            session_ref: session.session_ref.clone(),
            audience: configuration.audience.clone(),
            nonce: rand::random(),
            issued_at: observed.timestamp(),
            expires_at: observed.timestamp() + i64::from(configuration.max_age_seconds),
            policy: configuration.policy.clone(),
        })
        .map_err(|_| AgentDirectoryError::CorruptData)?;
        let payload = std::str::from_utf8(challenge.payload())
            .map_err(|_| AgentDirectoryError::CorruptData)?;
        sqlx::query("INSERT INTO organization_service.agent_enrollment_challenges \
            (challenge_id,organization_id,agent_id,key_id,expected_revision,administrator_id,session_ref,document,payload,challenge_digest,issued_at,expires_at,authorization_observed_at,authorization_valid_until) \
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)")
            .bind(challenge.challenge_id()).bind(organization).bind(agent).bind(key.key_id)
            .bind(identity.revision as i64).bind(session.user_id).bind(&session.session_ref)
            .bind(challenge.document()).bind(payload).bind(challenge.digest())
            .bind(epoch(challenge.issued_at())?).bind(epoch(challenge.expires_at())?)
            .bind(session.observed_at).bind(session.valid_until)
            .execute(&mut *tx).await.map_err(database_error)?;
        self.enrollment_audit(
            &mut tx,
            &identity,
            session.user_id,
            challenge.challenge_id(),
            "CHALLENGE_CREATED",
            observed,
        )
        .await?;
        let retained = RetainedChallenge {
            challenge,
            invalidated_at: None,
            result: None,
        };
        let result = retained.presentation(false)?;
        self.final_enrollment_check(
            &mut tx,
            organization,
            principal,
            session,
            observed,
            Some(result.expires_at),
            true,
        )
        .await?;
        tx.commit().await.map_err(database_error)?;
        Ok(result)
    }

    pub async fn inspect_enrollment_challenge(
        &self,
        organization: Uuid,
        principal: &ForwardedPrincipal,
        session: &AgentEnrollmentSession,
        agent: Uuid,
        challenge: Uuid,
    ) -> Result<AgentEnrollmentRecord, AgentDirectoryError> {
        self.enrollment
            .as_ref()
            .ok_or(AgentDirectoryError::NotFound)?;
        let mut tx = self.begin().await?;
        self.authorize_enrollment(&mut tx, organization, principal, false)
            .await?;
        // Lock identity before challenge everywhere; a concurrent rotation or
        // completion cannot make this read combine two committed revisions.
        load(&mut tx, organization, agent, true).await?;
        let mut retained = retained(&mut tx, organization, agent, challenge).await?;
        let observed = now(&mut tx).await?;
        session.check(organization, principal, observed)?;
        if retained.challenge.administrator_id() != session.user_id {
            return Err(AgentDirectoryError::AccessDenied);
        }
        if let Some(result) = &mut retained.result {
            result.recovered = true;
        }
        let result = AgentEnrollmentRecord {
            challenge: retained.presentation(true)?,
            state: retained.state(observed)?,
            result: retained.result,
            invalidated_at: retained.invalidated_at,
        };
        self.final_enrollment_check(
            &mut tx,
            organization,
            principal,
            session,
            observed,
            None,
            false,
        )
        .await?;
        tx.commit().await.map_err(database_error)?;
        Ok(result)
    }

    pub async fn complete_enrollment(
        &self,
        organization: Uuid,
        principal: &ForwardedPrincipal,
        session: &AgentEnrollmentSession,
        agent: Uuid,
        challenge_id: Uuid,
        request: CompleteAgentEnrollment,
    ) -> Result<AgentEnrollmentResult, AgentDirectoryError> {
        let configuration = self
            .enrollment
            .as_ref()
            .ok_or(AgentDirectoryError::NotFound)?;
        if request.proof.is_empty() || request.proof.len() > MAX_ENROLLMENT_PROOF_BYTES {
            return Err(AgentDirectoryError::InvalidRequest);
        }
        let mut tx = self.begin().await?;
        self.authorize_enrollment(&mut tx, organization, principal, true)
            .await?;
        let identity = load(&mut tx, organization, agent, true).await?;
        let retained = retained(&mut tx, organization, agent, challenge_id).await?;
        self.authorize_enrollment(&mut tx, organization, principal, true)
            .await?;
        let observed = now(&mut tx).await?;
        session.check(organization, principal, observed)?;
        let challenge = &retained.challenge;
        if challenge.administrator_id() != session.user_id
            || challenge.session_ref() != session.session_ref
        {
            return Err(AgentDirectoryError::AccessDenied);
        }
        if let Some(mut result) = retained.result {
            // Only the exact original bytes recover this immutable result. No
            // eligibility, session lifetime or key lifetime is extended here.
            if result.proof_digest != digest(request.proof.as_bytes()) {
                return Err(AgentDirectoryError::Conflict);
            }
            result.recovered = true;
            self.final_enrollment_check(
                &mut tx,
                organization,
                principal,
                session,
                observed,
                None,
                true,
            )
            .await?;
            tx.commit().await.map_err(database_error)?;
            return Ok(result);
        }
        if retained.invalidated_at.is_some() || observed >= epoch(challenge.expires_at())? {
            return Err(AgentDirectoryError::Conflict);
        }
        eligible(&identity, challenge.expected_revision(), observed)?;
        let key = identity
            .keys
            .first()
            .ok_or(AgentDirectoryError::CorruptData)?;
        if challenge.key_id() != key.key_id
            || !challenge
                .key_thumbprint()
                .same_binding(&key.fingerprint.typed()?)
            || challenge.audience() != configuration.audience
            || challenge.policy() != &configuration.policy
        {
            return Err(AgentDirectoryError::Conflict);
        }
        current_key(&mut tx, &identity).await?;
        let jwk = serde_json::to_vec(&key.public_key_jwk)
            .map_err(|_| AgentDirectoryError::CorruptData)?;
        let verified = verify_enrollment_proof(challenge, &jwk, &request.proof, observed)
            .map_err(|_| AgentDirectoryError::AccessDenied)?;
        let completed_at = now(&mut tx).await?;
        session.check(organization, principal, completed_at)?;
        let result = consume_verified(verified, &identity, challenge, completed_at)?;
        let document =
            serde_json::to_value(&result.identity).map_err(|_| AgentDirectoryError::CorruptData)?;
        let affected = sqlx::query("UPDATE organization_service.agent_identities SET status='ACTIVE',revision=$1,document=$2,updated_at=$3 WHERE organization_id=$4 AND id=$5 AND revision=$6")
            .bind(result.enrolled_revision as i64).bind(&document).bind(completed_at).bind(organization).bind(agent)
            .bind(identity.revision as i64).execute(&mut *tx).await.map_err(database_error)?;
        if affected.rows_affected() != 1 {
            return Err(AgentDirectoryError::Conflict);
        }
        sqlx::query("INSERT INTO organization_service.agent_enrollment_outcomes \
            (challenge_id,organization_id,agent_id,key_id,enrolled_revision,proof_digest,completed_at,authorization_observed_at,authorization_valid_until,result) \
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
            .bind(challenge_id).bind(organization).bind(agent).bind(result.key_id).bind(result.enrolled_revision as i64)
            .bind(&result.proof_digest).bind(completed_at).bind(session.observed_at).bind(session.valid_until)
            .bind(serde_json::to_value(&result).map_err(|_| AgentDirectoryError::CorruptData)?)
            .execute(&mut *tx).await.map_err(database_error)?;
        sqlx::query("INSERT INTO organization_service.agent_identity_history (organization_id,agent_id,revision,action,actor_user_id,request_id,occurred_at,snapshot) VALUES ($1,$2,$3,'ENROLL',$4,$5,$6,$7)")
            .bind(organization).bind(agent).bind(result.enrolled_revision as i64).bind(session.user_id.to_string())
            .bind(self.request_id.unwrap_or_else(Uuid::new_v4)).bind(completed_at).bind(document)
            .execute(&mut *tx).await.map_err(database_error)?;
        self.enrollment_audit(
            &mut tx,
            &result.identity,
            session.user_id,
            challenge_id,
            "KEY_CONTROL_VERIFIED",
            completed_at,
        )
        .await?;
        invalidate_pending(
            &mut tx,
            organization,
            agent,
            completed_at,
            "REVISION_CHANGED",
        )
        .await?;
        self.final_enrollment_check(
            &mut tx,
            organization,
            principal,
            session,
            completed_at,
            Some(epoch(challenge.expires_at())?),
            true,
        )
        .await?;
        tx.commit().await.map_err(database_error)?;
        Ok(result)
    }

    async fn authorize_enrollment(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        org: Uuid,
        principal: &ForwardedPrincipal,
        mutation: bool,
    ) -> Result<(), AgentDirectoryError> {
        self.authorize(tx, org, principal, "agent-identity:view")
            .await?;
        if mutation {
            self.authorize(tx, org, principal, "agent-identity:enroll")
                .await?;
        }
        Ok(())
    }

    async fn final_enrollment_check(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        org: Uuid,
        principal: &ForwardedPrincipal,
        session: &AgentEnrollmentSession,
        earlier: DateTime<Utc>,
        expires: Option<DateTime<Utc>>,
        mutation: bool,
    ) -> Result<(), AgentDirectoryError> {
        self.authorize_enrollment(tx, org, principal, mutation)
            .await?;
        let observed = now(tx).await?;
        session.check(org, principal, observed)?;
        if observed < earlier {
            return Err(AgentDirectoryError::Unavailable);
        }
        if expires.is_some_and(|expires| observed >= expires) {
            return Err(AgentDirectoryError::Conflict);
        }
        Ok(())
    }

    async fn enrollment_audit(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        identity: &AgentIdentity,
        user: Uuid,
        challenge: Uuid,
        action: &str,
        observed: DateTime<Utc>,
    ) -> Result<(), AgentDirectoryError> {
        self.store.save_audit_event_in_transaction(tx, &AuditEvent {
            id: Uuid::new_v4(), organization_id: identity.organization_id,
            event_type: "agent_identity.enrollment".into(), action: action.into(), category: "identity".into(),
            resource_type: "agent-identity".into(), resource_id: Some(identity.id.to_string()),
            resource_name: Some(identity.metadata.display_name.clone()), actor_id: Some(user.to_string()),
            actor_type: "USER".into(), severity: "INFO".into(), message: "Managed key enrollment recorded".into(),
            changes: None, metadata: json!({"challenge_id":challenge,"revision":identity.revision,"authority_status":"NOT_ASSESSED","request_id":self.request_id}),
            timestamp: observed,
        }).await.map_err(|_| AgentDirectoryError::Unavailable)
    }
}

/// Consumes a purpose-specific verified value; no serialized proof verdict can
/// be supplied by a caller and no operational authorization value is produced.
fn consume_verified(
    proof: VerifiedEnrollmentProof,
    previous: &AgentIdentity,
    challenge: &EnrollmentChallenge,
    observed: DateTime<Utc>,
) -> Result<AgentEnrollmentResult, AgentDirectoryError> {
    proof
        .ensure_current(observed)
        .map_err(|_| AgentDirectoryError::Conflict)?;
    if proof.challenge_id() != challenge.challenge_id()
        || proof.organization_id() != previous.organization_id
        || proof.agent_id() != previous.id
        || proof.key_id() != challenge.key_id()
        || proof.expected_revision() != previous.revision
        || proof.payload_digest() != challenge.digest()
        || proof.policy_digest() != challenge.policy_digest()
    {
        return Err(AgentDirectoryError::CorruptData);
    }
    let mut identity = previous.clone();
    identity.status = AgentIdentityStatus::Active;
    identity.provenance.managed_enrollment = "KEY_CONTROL_VERIFIED".into();
    identity.revision += 1;
    identity.updated_at = observed;
    validate_snapshot(&identity)?;
    Ok(AgentEnrollmentResult {
        challenge_id: challenge.challenge_id(),
        organization_id: previous.organization_id,
        agent_id: previous.id,
        key_id: challenge.key_id(),
        previous_revision: previous.revision,
        enrolled_revision: identity.revision,
        completed_at: observed,
        proof_digest: proof.proof_digest().into(),
        challenge_digest: proof.payload_digest(),
        enrollment: "KEY_CONTROL_VERIFIED".into(),
        authority_status: "NOT_ASSESSED".into(),
        identity,
        recovered: false,
    })
}

fn eligible(
    identity: &AgentIdentity,
    revision: u64,
    observed: DateTime<Utc>,
) -> Result<(), AgentDirectoryError> {
    valid_revision(revision)?;
    if identity.revision != revision {
        return Err(AgentDirectoryError::Conflict);
    }
    if identity.kind != AgentKind::Managed
        || identity.status != AgentIdentityStatus::Provisioned
        || identity.provenance.managed_enrollment != "NOT_ASSESSED"
    {
        return Err(AgentDirectoryError::InvalidTransition);
    }
    if observed <= identity.updated_at {
        return Err(AgentDirectoryError::Unavailable);
    }
    Ok(())
}

async fn current_key(
    tx: &mut PgConnection,
    identity: &AgentIdentity,
) -> Result<(), AgentDirectoryError> {
    let row = sqlx::query("SELECT key_id,algorithm,key_thumbprint,public_key_jwk FROM organization_service.agent_identity_keys WHERE organization_id=$1 AND agent_id=$2 AND status='ACTIVE' FOR SHARE")
        .bind(identity.organization_id).bind(identity.id).fetch_one(tx).await.map_err(database_error)?;
    let key = identity
        .keys
        .first()
        .ok_or(AgentDirectoryError::CorruptData)?;
    if row.get::<Uuid, _>("key_id") != key.key_id
        || row.get::<String, _>("algorithm") != key.algorithm
        || row.get::<String, _>("key_thumbprint") != key.fingerprint.value
        || row.get::<Value, _>("public_key_jwk") != key.public_key_jwk
    {
        return Err(AgentDirectoryError::CorruptData);
    }
    Ok(())
}

pub(super) async fn invalidate_pending(
    tx: &mut PgConnection,
    org: Uuid,
    agent: Uuid,
    observed: DateTime<Utc>,
    reason: &str,
) -> Result<(), AgentDirectoryError> {
    sqlx::query("INSERT INTO organization_service.agent_enrollment_invalidations (challenge_id,organization_id,agent_id,invalidated_at,reason) \
        SELECT c.challenge_id,c.organization_id,c.agent_id,$3,$4 FROM organization_service.agent_enrollment_challenges c \
        WHERE c.organization_id=$1 AND c.agent_id=$2 \
        AND NOT EXISTS (SELECT 1 FROM organization_service.agent_enrollment_outcomes o WHERE o.challenge_id=c.challenge_id) \
        AND NOT EXISTS (SELECT 1 FROM organization_service.agent_enrollment_invalidations i WHERE i.challenge_id=c.challenge_id)")
        .bind(org).bind(agent).bind(observed).bind(reason).execute(tx).await.map_err(database_error)?;
    Ok(())
}

async fn retained(
    tx: &mut PgConnection,
    org: Uuid,
    agent: Uuid,
    id: Uuid,
) -> Result<RetainedChallenge, AgentDirectoryError> {
    let row = sqlx::query("SELECT c.*,o.result,i.invalidated_at FROM organization_service.agent_enrollment_challenges c \
        LEFT JOIN organization_service.agent_enrollment_outcomes o ON o.challenge_id=c.challenge_id \
        LEFT JOIN organization_service.agent_enrollment_invalidations i ON i.challenge_id=c.challenge_id \
        WHERE c.organization_id=$1 AND c.agent_id=$2 AND c.challenge_id=$3 FOR UPDATE OF c")
        .bind(org).bind(agent).bind(id).fetch_optional(tx).await.map_err(database_error)?.ok_or(AgentDirectoryError::NotFound)?;
    decode_retained(row)
}

fn decode_retained(row: PgRow) -> Result<RetainedChallenge, AgentDirectoryError> {
    let invalid = || AgentDirectoryError::CorruptData;
    let document: Value = row.try_get("document").map_err(|_| invalid())?;
    let challenge = EnrollmentChallenge::from_trusted_document(
        &serde_json::to_vec(&document).map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())?;
    if challenge.challenge_id()
        != row
            .try_get::<Uuid, _>("challenge_id")
            .map_err(|_| invalid())?
        || challenge.organization_id()
            != row
                .try_get::<Uuid, _>("organization_id")
                .map_err(|_| invalid())?
        || challenge.agent_id() != row.try_get::<Uuid, _>("agent_id").map_err(|_| invalid())?
        || challenge.key_id() != row.try_get::<Uuid, _>("key_id").map_err(|_| invalid())?
        || challenge.administrator_id()
            != row
                .try_get::<Uuid, _>("administrator_id")
                .map_err(|_| invalid())?
        || challenge.expected_revision() as i64
            != row
                .try_get::<i64, _>("expected_revision")
                .map_err(|_| invalid())?
        || challenge.session_ref()
            != row
                .try_get::<String, _>("session_ref")
                .map_err(|_| invalid())?
        || challenge.payload()
            != row
                .try_get::<String, _>("payload")
                .map_err(|_| invalid())?
                .as_bytes()
        || challenge.digest()
            != row
                .try_get::<String, _>("challenge_digest")
                .map_err(|_| invalid())?
        || epoch(challenge.issued_at())?
            != row
                .try_get::<DateTime<Utc>, _>("issued_at")
                .map_err(|_| invalid())?
        || epoch(challenge.expires_at())?
            != row
                .try_get::<DateTime<Utc>, _>("expires_at")
                .map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    let result: Option<AgentEnrollmentResult> = row
        .try_get::<Option<Value>, _>("result")
        .map_err(|_| invalid())?
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| invalid())?;
    let invalidated_at: Option<DateTime<Utc>> =
        row.try_get("invalidated_at").map_err(|_| invalid())?;
    if let Some(result) = &result {
        validate_snapshot(&result.identity)?;
        if invalidated_at.is_some()
            || result.challenge_id != challenge.challenge_id()
            || result.organization_id != challenge.organization_id()
            || result.agent_id != challenge.agent_id()
            || result.key_id != challenge.key_id()
            || result.previous_revision != challenge.expected_revision()
            || result.enrolled_revision != result.previous_revision + 1
            || result.recovered
            || result.challenge_digest != challenge.digest()
            || !super::enrollment::sha256(&result.proof_digest)
            || result.enrollment != "KEY_CONTROL_VERIFIED"
            || result.authority_status != "NOT_ASSESSED"
            || result.identity.id != result.agent_id
            || result.identity.organization_id != result.organization_id
            || result.identity.revision != result.enrolled_revision
            || result.identity.updated_at != result.completed_at
            || result.identity.status != AgentIdentityStatus::Active
            || result.identity.kind != AgentKind::Managed
            || result.identity.provenance.managed_enrollment != result.enrollment
            || result
                .identity
                .keys
                .first()
                .is_none_or(|key| key.key_id != result.key_id)
            || result.completed_at < epoch(challenge.issued_at())?
            || result.completed_at >= epoch(challenge.expires_at())?
        {
            return Err(invalid());
        }
    }
    Ok(RetainedChallenge {
        challenge,
        invalidated_at,
        result,
    })
}

fn epoch(seconds: i64) -> Result<DateTime<Utc>, AgentDirectoryError> {
    DateTime::from_timestamp(seconds, 0).ok_or(AgentDirectoryError::CorruptData)
}
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
