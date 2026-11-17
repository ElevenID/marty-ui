// SPDX-License-Identifier: AGPL-3.0-only
//! Independently approved identity-attestation sources. A source operation
//! receipt is historical, never current ownership or evidence authority.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

pub const MIGRATION_SQL: &str = include_str!("../migrations/0017_external_associations.sql");
const MAX: i64 = 9_007_199_254_740_991;
fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn version(value: i64) -> bool {
    (1..=MAX).contains(&value)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSource {
    pub operation_id: Uuid,
    pub expected_revision: i64,
    pub api_key_id: Uuid,
    pub key_revision: i64,
    pub source_id: String,
    pub expires_at_ms: i64,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSource {
    pub operation_id: Uuid,
    pub expected_revision: i64,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaceSourceKey {
    pub operation_id: Uuid,
    pub expected_revision: i64,
    pub api_key_id: Uuid,
    pub key_revision: i64,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSourceExpiry {
    pub operation_id: Uuid,
    pub expected_revision: i64,
    pub expires_at_ms: i64,
}
// Neither the action nor trusted actor/tenant context is decoded from body JSON.
pub enum SourceRequest {
    Create(CreateSource),
    Approve(ChangeSource),
    Revoke(ChangeSource),
    ReplaceKey(ReplaceSourceKey),
    ChangeExpiry(ChangeSourceExpiry),
}
#[derive(Clone, Copy)]
pub struct SourceScope<'a> {
    pub organization: Uuid,
    pub actor: &'a str,
    pub grant: Uuid,
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SourceReceipt {
    pub operation_id: Uuid,
    pub source_grant_id: Uuid,
    pub action: String,
    pub revision: i64,
    pub active: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssociationError {
    InvalidRequest,
    NotAuthorized,
    Conflict,
    Unavailable,
    CommitUnknown,
}

fn mutation_error(error: sqlx::Error) -> AssociationError {
    match error.as_database_error() {
        Some(database) => match database.code().as_deref() {
            Some("40001" | "40P01" | "55P03" | "23505" | "23514") => AssociationError::Conflict,
            _ => AssociationError::Unavailable,
        },
        None => AssociationError::CommitUnknown,
    }
}

fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateChallenge {
    pub operation_id: Uuid,
    pub challenge_id: Uuid,
    pub source_grant_id: Uuid,
    pub expected_source_revision: i64,
    pub binding_id: String,
    pub expected_binding_revision: i64,
    pub provider_reference: String,
    pub provider_revision: i64,
    pub code_hash: String,
    pub expires_at_ms: i64,
}
#[derive(Clone, Copy)]
pub struct ProducerScope {
    pub organization: Uuid,
    pub api_key_id: Uuid,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeConsent {
    pub operation_id: Uuid,
    pub expected_revision: i64,
    pub code: String,
}
#[derive(Clone, Copy)]
pub struct LearnerScope<'a> {
    pub organization: Uuid,
    pub user_id: &'a str,
    pub challenge_id: Uuid,
}
pub enum ConsentAction {
    Confirm,
    Deny,
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ChallengeReceipt {
    pub operation_id: Uuid,
    pub challenge_id: Uuid,
    pub action: String,
    pub revision: i64,
    pub phase: String,
}

pub async fn create_challenge(
    pool: &PgPool,
    scope: ProducerScope,
    request: &CreateChallenge,
) -> Result<ChallengeReceipt, AssociationError> {
    if scope.organization.is_nil()
        || scope.api_key_id.is_nil()
        || request.operation_id.is_nil()
        || request.challenge_id.is_nil()
        || request.source_grant_id.is_nil()
        || !version(request.expected_source_revision)
        || !version(request.expected_binding_revision)
        || !id(&request.binding_id)
        || !hash(&request.provider_reference)
        || !version(request.provider_revision)
        || !hash(&request.code_hash)
        || !version(request.expires_at_ms)
    {
        return Err(AssociationError::InvalidRequest);
    }
    let value: Option<serde_json::Value> = sqlx::query_scalar("SELECT issuance_service.create_external_association_challenge($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
        .bind(scope.organization).bind(scope.api_key_id).bind(request.operation_id).bind(request.challenge_id)
        .bind(request.source_grant_id).bind(request.expected_source_revision).bind(&request.binding_id)
        .bind(request.expected_binding_revision).bind(&request.provider_reference).bind(request.provider_revision)
        .bind(&request.code_hash).bind(request.expires_at_ms).fetch_one(pool).await.map_err(mutation_error)?;
    let receipt: ChallengeReceipt =
        serde_json::from_value(value.ok_or(AssociationError::NotAuthorized)?)
            .map_err(|_| AssociationError::CommitUnknown)?;
    if receipt.operation_id != request.operation_id
        || receipt.challenge_id != request.challenge_id
        || receipt.action != "create"
        || receipt.revision != 1
        || receipt.phase != "pending"
    {
        return Err(AssociationError::CommitUnknown);
    }
    Ok(receipt)
}

impl ChallengeConsent {
    fn proof_hash(&self) -> Result<String, AssociationError> {
        if self.operation_id.is_nil()
            || !(1..MAX).contains(&self.expected_revision)
            || self.code.len() != 43
        {
            return Err(AssociationError::InvalidRequest);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.code)
            .map_err(|_| AssociationError::InvalidRequest)?;
        if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != self.code {
            return Err(AssociationError::InvalidRequest);
        }
        Ok(format!("{:x}", Sha256::digest(&bytes)))
    }
}

/// The browser proves possession of the original 256-bit code. Only its hash
/// reaches PostgreSQL. The authenticated user and action come from Core transport.
pub async fn consent(
    pool: &PgPool,
    scope: LearnerScope<'_>,
    action: ConsentAction,
    request: &ChallengeConsent,
) -> Result<ChallengeReceipt, AssociationError> {
    if scope.organization.is_nil()
        || scope.challenge_id.is_nil()
        || !id(scope.user_id)
        || !scope.user_id.as_bytes()[0].is_ascii_alphanumeric()
    {
        return Err(AssociationError::InvalidRequest);
    }
    let proof_hash = request.proof_hash()?;
    let (action, phase) = match action {
        ConsentAction::Confirm => ("confirm", "confirmed"),
        ConsentAction::Deny => ("deny", "denied"),
    };
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT issuance_service.mutate_external_association_consent($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(scope.organization)
    .bind(scope.user_id)
    .bind(request.operation_id)
    .bind(scope.challenge_id)
    .bind(action)
    .bind(request.expected_revision)
    .bind(proof_hash)
    .fetch_one(pool)
    .await
    .map_err(mutation_error)?;
    let receipt: ChallengeReceipt =
        serde_json::from_value(value.ok_or(AssociationError::NotAuthorized)?)
            .map_err(|_| AssociationError::CommitUnknown)?;
    if receipt.operation_id != request.operation_id
        || receipt.challenge_id != scope.challenge_id
        || receipt.action != action
        || receipt.revision != request.expected_revision + 1
        || receipt.phase != phase
    {
        return Err(AssociationError::CommitUnknown);
    }
    Ok(receipt)
}
struct PreparedSource {
    operation: Uuid,
    expected: i64,
    action: &'static str,
    definition: serde_json::Value,
}
impl SourceRequest {
    fn prepare(&self) -> Result<PreparedSource, AssociationError> {
        let (operation, expected, action, definition, valid) = match self {
            Self::Create(v) => (
                v.operation_id,
                v.expected_revision,
                "create",
                json!({"api_key_id":v.api_key_id,"key_revision":v.key_revision,"source_id":v.source_id,"expires_at_ms":v.expires_at_ms}),
                v.expected_revision == 0
                    && !v.api_key_id.is_nil()
                    && version(v.key_revision)
                    && id(&v.source_id)
                    && version(v.expires_at_ms),
            ),
            Self::Approve(v) => (
                v.operation_id,
                v.expected_revision,
                "approve",
                json!({}),
                v.expected_revision >= 1,
            ),
            Self::Revoke(v) => (
                v.operation_id,
                v.expected_revision,
                "revoke",
                json!({}),
                v.expected_revision >= 1,
            ),
            Self::ReplaceKey(v) => (
                v.operation_id,
                v.expected_revision,
                "replace-key",
                json!({"api_key_id":v.api_key_id,"key_revision":v.key_revision}),
                v.expected_revision >= 1 && !v.api_key_id.is_nil() && version(v.key_revision),
            ),
            Self::ChangeExpiry(v) => (
                v.operation_id,
                v.expected_revision,
                "change-expiry",
                json!({"expires_at_ms":v.expires_at_ms}),
                v.expected_revision >= 1 && version(v.expires_at_ms),
            ),
        };
        if !valid || operation.is_nil() || !(0..MAX).contains(&expected) {
            return Err(AssociationError::InvalidRequest);
        }
        Ok(PreparedSource {
            operation,
            expected,
            action,
            definition,
        })
    }
}

/// One statement commits the source revision and immutable actor receipt. No
/// automatic retry; reconcile the original operation and exact original intent.
pub async fn mutate_source(
    pool: &PgPool,
    scope: SourceScope<'_>,
    request: &SourceRequest,
) -> Result<SourceReceipt, AssociationError> {
    if scope.organization.is_nil()
        || scope.grant.is_nil()
        || !id(scope.actor)
        || !scope.actor.as_bytes()[0].is_ascii_alphanumeric()
    {
        return Err(AssociationError::InvalidRequest);
    }
    let command = request.prepare()?;
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT issuance_service.mutate_external_association_source($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(scope.organization)
    .bind(scope.actor)
    .bind(command.operation)
    .bind(scope.grant)
    .bind(command.action)
    .bind(command.expected)
    .bind(&command.definition)
    .fetch_one(pool)
    .await
    .map_err(mutation_error)?;
    let receipt: SourceReceipt =
        serde_json::from_value(value.ok_or(AssociationError::NotAuthorized)?)
            .map_err(|_| AssociationError::CommitUnknown)?;
    if receipt.operation_id != command.operation
        || receipt.source_grant_id != scope.grant
        || receipt.action != command.action
        || receipt.revision != command.expected + 1
        || receipt.active != (command.action == "approve")
    {
        return Err(AssociationError::CommitUnknown);
    }
    Ok(receipt)
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CurrentSource {
    pub source_grant_id: Uuid,
    pub source_id: String,
    pub api_key_id: Uuid,
    pub key_revision: i64,
    pub revision: i64,
    pub active: bool,
    pub current: bool,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum SourceInspection {
    Current { record: CurrentSource },
    Receipt { receipt: SourceReceipt },
}

/// Reads use authenticated Core context. Historical recovery is actor-scoped
/// and cannot be substituted for a currently usable source delegation.
pub async fn inspect_source(
    pool: &PgPool,
    scope: SourceScope<'_>,
    original_operation: Option<Uuid>,
) -> Result<SourceInspection, AssociationError> {
    if scope.organization.is_nil()
        || scope.grant.is_nil()
        || !id(scope.actor)
        || original_operation.is_some_and(|operation| operation.is_nil())
    {
        return Err(AssociationError::InvalidRequest);
    }
    let value: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT issuance_service.read_external_association_source($1,$2,$3,$4)")
            .bind(scope.organization)
            .bind(scope.actor)
            .bind(scope.grant)
            .bind(original_operation)
            .fetch_one(pool)
            .await
            .map_err(|_| AssociationError::Unavailable)?;
    let result = serde_json::from_value(value.ok_or(AssociationError::NotAuthorized)?)
        .map_err(|_| AssociationError::Unavailable)?;
    let valid = match (&result, original_operation) {
        (SourceInspection::Current { record }, None) => {
            record.source_grant_id == scope.grant
                && id(&record.source_id)
                && !record.api_key_id.is_nil()
                && version(record.key_revision)
                && version(record.revision)
                && version(record.expires_at_ms)
                && (!record.current || record.active)
        }
        (SourceInspection::Receipt { receipt }, Some(operation)) => {
            receipt.source_grant_id == scope.grant
                && receipt.operation_id == operation
                && version(receipt.revision)
                && matches!(
                    receipt.action.as_str(),
                    "create" | "approve" | "revoke" | "replace-key" | "change-expiry"
                )
                && receipt.active == (receipt.action == "approve")
        }
        _ => false,
    };
    if !valid {
        return Err(AssociationError::Unavailable);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn learner_proof_requires_original_canonical_256_bit_code() {
        let mut request = ChallengeConsent {
            operation_id: Uuid::from_u128(1),
            expected_revision: 1,
            code: URL_SAFE_NO_PAD.encode([0_u8; 32]),
        };
        assert_eq!(
            request.proof_hash().unwrap(),
            format!("{:x}", Sha256::digest([0_u8; 32]))
        );
        for code in [
            "a".repeat(64),
            "A".repeat(42),
            "A".repeat(44),
            format!("{}=", "A".repeat(43)),
            "+".repeat(43),
            "_".repeat(43),
        ] {
            request.code = code;
            assert_eq!(request.proof_hash(), Err(AssociationError::InvalidRequest));
        }
        for body in [
            r#"{"operation_id":"20000000-0000-4000-8000-000000000001","expected_revision":1,"code":"x","user_id":"forged"}"#,
            r#"{"operation_id":"20000000-0000-4000-8000-000000000001","expected_revision":1,"code":"x","code":"y"}"#,
            r#"{"operation_id":"20000000-0000-4000-8000-000000000001","expected_revision":1,"code_hash":"forged"}"#,
        ] {
            assert!(serde_json::from_str::<ChallengeConsent>(body).is_err());
        }
    }
    #[test]
    fn historical_source_receipts_cannot_decode_as_current_authority() {
        let value = json!({"kind":"receipt","receipt":{
            "operation_id":Uuid::from_u128(1),"source_grant_id":Uuid::from_u128(2),
            "action":"approve","revision":3,"active":true
        }});
        assert!(matches!(
            serde_json::from_value::<SourceInspection>(value.clone()).unwrap(),
            SourceInspection::Receipt { .. }
        ));
        let mut mislabeled = value.clone();
        mislabeled["kind"] = json!("current");
        assert!(serde_json::from_value::<SourceInspection>(mislabeled).is_err());
        let mut ambiguous = value;
        ambiguous["record"] = json!({"current":true});
        assert!(serde_json::from_value::<SourceInspection>(ambiguous).is_err());
    }
    #[test]
    fn source_bodies_reject_duplicate_or_caller_authority_fields() {
        for body in [
            r#"{"operation_id":"20000000-0000-4000-8000-000000000001","expected_revision":1,"actor_id":"admin"}"#,
            r#"{"operation_id":"20000000-0000-4000-8000-000000000001","expected_revision":1,"expected_revision":2}"#,
            r#"{"operation_id":"20000000-0000-4000-8000-000000000001","expected_revision":1,"active":true}"#,
            r#"{"operation_id":"20000000-0000-4000-8000-000000000001","expected_revision":1,"organization_id":"other"}"#,
        ] {
            assert!(serde_json::from_str::<ChangeSource>(body).is_err());
        }
    }
    #[test]
    fn only_explicit_server_selected_approval_can_activate_a_source() {
        let change = ChangeSource {
            operation_id: Uuid::from_u128(1),
            expected_revision: 1,
        };
        assert_eq!(
            SourceRequest::Approve(change.clone())
                .prepare()
                .unwrap()
                .action,
            "approve"
        );
        assert_eq!(
            SourceRequest::Revoke(change).prepare().unwrap().action,
            "revoke"
        );
        assert!(SourceRequest::Approve(ChangeSource {
            operation_id: Uuid::from_u128(1),
            expected_revision: 0
        })
        .prepare()
        .is_err());
        assert!(SourceRequest::Revoke(ChangeSource {
            operation_id: Uuid::nil(),
            expected_revision: 1
        })
        .prepare()
        .is_err());
    }
    #[test]
    fn key_and_source_revisions_are_explicit_safe_preconditions() {
        let mut create = CreateSource {
            operation_id: Uuid::from_u128(1),
            expected_revision: 0,
            api_key_id: Uuid::from_u128(2),
            key_revision: 1,
            source_id: "source-one".into(),
            expires_at_ms: 1,
        };
        assert!(SourceRequest::Create(create.clone()).prepare().is_ok());
        create.key_revision = 0;
        assert!(SourceRequest::Create(create.clone()).prepare().is_err());
        create.key_revision = 1;
        create.expected_revision = 1;
        assert!(SourceRequest::Create(create.clone()).prepare().is_err());
        create.expected_revision = 0;
        create.source_id = "../source".into();
        assert!(SourceRequest::Create(create).prepare().is_err());
        assert!(SourceRequest::ChangeExpiry(ChangeSourceExpiry {
            operation_id: Uuid::from_u128(1),
            expected_revision: MAX,
            expires_at_ms: 1
        })
        .prepare()
        .is_err());
    }
}
