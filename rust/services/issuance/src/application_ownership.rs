// SPDX-License-Identifier: AGPL-3.0-only
//! Core-owned application relationships, separate from provider observations.
//! The caller must authenticate actor through the public Gateway session boundary.
//! No producer API key, applicant-store ID equality or provider claim is an actor.
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

pub const MIGRATION_SQL: &str = include_str!("../migrations/0016_application_ownership.sql");

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipProposal {
    pub operation_id: Uuid,
    pub expected_revision: i64,
    pub expected_application_revision: i64,
    pub user_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipChange {
    pub operation_id: Uuid,
    pub expected_revision: i64,
    pub expected_application_revision: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipAction {
    Propose,
    Confirm,
    Revoke,
}
impl OwnershipAction {
    fn name(self) -> &'static str {
        match self {
            Self::Propose => "propose",
            Self::Confirm => "confirm",
            Self::Revoke => "revoke",
        }
    }
    fn status(self) -> &'static str {
        match self {
            Self::Propose => "proposed",
            Self::Confirm => "confirmed",
            Self::Revoke => "revoked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OwnershipReceipt {
    pub operation_id: Uuid,
    pub application_id: String,
    pub action: String,
    pub revision: i64,
    pub status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentOwnership {
    pub application_id: String,
    pub user_id: String,
    pub revision: i64,
    pub status: String,
    pub application_revision: i64,
    pub proposal_application_revision: i64,
    pub current: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnershipRead {
    Current { record: Option<CurrentOwnership> },
    Receipt { receipt: OwnershipReceipt },
}

/// Fresh relationship status and immutable operation receipts are separate
/// results. The caller must never authorize from an old confirmation receipt.
pub async fn read(
    pool: &PgPool,
    org: Uuid,
    app: &str,
    actor: &str,
    operation: Option<Uuid>,
) -> Result<OwnershipRead, OwnershipError> {
    if org.is_nil() || !identifier(app) || !user(actor) || operation.is_some_and(|id| id.is_nil()) {
        return Err(OwnershipError::InvalidRequest);
    }
    let value: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT issuance_service.read_application_ownership($1,$2,$3,$4)")
            .bind(org)
            .bind(app)
            .bind(actor)
            .bind(operation)
            .fetch_one(pool)
            .await
            .map_err(|_| OwnershipError::Unavailable)?;
    let result: OwnershipRead = serde_json::from_value(value.ok_or(OwnershipError::NotAuthorized)?)
        .map_err(|_| OwnershipError::Unavailable)?;
    match &result {
        OwnershipRead::Receipt { receipt }
            if operation == Some(receipt.operation_id)
                && receipt.application_id == app
                && version(receipt.revision)
                && matches!(
                    (receipt.action.as_str(), receipt.status.as_str()),
                    ("propose", "proposed") | ("confirm", "confirmed") | ("revoke", "revoked")
                ) => {}
        OwnershipRead::Current { record } if operation.is_none() => {
            if let Some(record) = record {
                if record.application_id != app
                    || !user(&record.user_id)
                    || !version(record.revision)
                    || !version(record.application_revision)
                    || !version(record.proposal_application_revision)
                    || !matches!(record.status.as_str(), "proposed" | "confirmed" | "revoked")
                    || (record.current
                        && (record.status != "confirmed"
                            || record.application_revision != record.proposal_application_revision))
                {
                    return Err(OwnershipError::Unavailable);
                }
            }
        }
        _ => return Err(OwnershipError::Unavailable),
    }
    Ok(result)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipError {
    InvalidRequest,
    NotAuthorized,
    Conflict,
    Unavailable,
    CommitUnknown,
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn user(value: &str) -> bool {
    identifier(value) && value.as_bytes()[0].is_ascii_alphanumeric()
}
fn version(value: i64) -> bool {
    (1..=9_007_199_254_740_991).contains(&value)
}
// Deliberately not Deserialize: org and actor come from authenticated transport.
#[derive(Clone, Copy, Debug)]
pub struct OwnershipMutation<'a> {
    pub org: Uuid,
    pub app: &'a str,
    pub actor: &'a str,
    pub operation: Uuid,
    pub action: OwnershipAction,
    pub expected: i64,
    pub application_revision: i64,
    pub recipient: Option<&'a str>,
}
fn validate(input: &OwnershipMutation<'_>) -> Result<(), OwnershipError> {
    let OwnershipMutation {
        org,
        app,
        actor,
        operation,
        action,
        expected,
        application_revision,
        recipient,
    } = *input;
    if org.is_nil()
        || !identifier(app)
        || !user(actor)
        || operation.is_nil()
        || !(0..9_007_199_254_740_991).contains(&expected)
        || (action != OwnershipAction::Propose && expected == 0)
        || !version(application_revision)
        || match (action, recipient) {
            (OwnershipAction::Propose, Some(value)) => !user(value),
            (OwnershipAction::Propose, None) => true,
            (_, Some(_)) => true,
            (_, None) => false,
        }
    {
        return Err(OwnershipError::InvalidRequest);
    }
    Ok(())
}

/// One autocommit statement performs the relationship mutation and immutable
/// actor receipt together. Never automatically retry after a transport failure.
/// Reconcile using the exact original operation and intent. A historical receipt
/// does not assert current ownership or restore a revoked relationship.
pub async fn mutate(
    pool: &PgPool,
    input: &OwnershipMutation<'_>,
) -> Result<OwnershipReceipt, OwnershipError> {
    validate(input)?;
    let OwnershipMutation {
        org,
        app,
        actor,
        operation,
        action,
        expected,
        application_revision,
        recipient,
    } = *input;
    let result: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT issuance_service.mutate_application_ownership($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(org)
    .bind(app)
    .bind(actor)
    .bind(operation)
    .bind(action.name())
    .bind(expected)
    .bind(application_revision)
    .bind(recipient)
    .fetch_one(pool)
    .await
    .map_err(|error| match error.as_database_error() {
        Some(database) => match database.code().as_deref() {
            Some("40001" | "40P01" | "55P03" | "23505" | "23514") => OwnershipError::Conflict,
            _ => OwnershipError::Unavailable,
        },
        None => OwnershipError::CommitUnknown,
    })?;
    let value = result.ok_or(OwnershipError::NotAuthorized)?;
    let receipt: OwnershipReceipt =
        serde_json::from_value(value).map_err(|_| OwnershipError::CommitUnknown)?;
    if receipt.operation_id != operation
        || receipt.application_id != app
        || receipt.action != action.name()
        || receipt.status != action.status()
        || receipt.revision != expected + 1
    {
        return Err(OwnershipError::CommitUnknown);
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_json_rejects_authority_fields_duplicate_and_unknown_fields() {
        for body in [
            r#"{"operation_id":"20000000-0000-4000-8000-000000000001","expected_revision":0,"expected_application_revision":1,"user_id":"learner","actor_id":"admin"}"#,
            r#"{"operation_id":"20000000-0000-4000-8000-000000000001","expected_revision":0,"expected_revision":1,"expected_application_revision":1,"user_id":"learner"}"#,
            r#"{"operation_id":"20000000-0000-4000-8000-000000000001","expected_revision":1,"expected_application_revision":1,"subject_id":"provider-subject"}"#,
        ] {
            assert!(serde_json::from_str::<OwnershipProposal>(body).is_err());
            assert!(serde_json::from_str::<OwnershipChange>(body).is_err());
        }
    }
    #[test]
    fn proposal_recipient_and_confirmation_identity_are_separate() {
        let org = Uuid::from_u128(1);
        let op = Uuid::from_u128(2);
        let base = OwnershipMutation {
            org,
            app: "app",
            actor: "admin",
            operation: op,
            action: OwnershipAction::Propose,
            expected: 0,
            application_revision: 1,
            recipient: Some("learner"),
        };
        assert!(validate(&base).is_ok());
        assert!(validate(&OwnershipMutation {
            actor: "learner",
            action: OwnershipAction::Confirm,
            expected: 1,
            recipient: None,
            ..base
        })
        .is_ok());
        for (action, revision, recipient) in [
            (OwnershipAction::Propose, 0, None),
            (OwnershipAction::Confirm, 1, Some("learner")),
            (OwnershipAction::Confirm, 0, None),
            (OwnershipAction::Revoke, 0, None),
            (OwnershipAction::Propose, -1, Some("learner")),
            (
                OwnershipAction::Propose,
                9_007_199_254_740_991,
                Some("learner"),
            ),
        ] {
            assert_eq!(
                validate(&OwnershipMutation {
                    action,
                    expected: revision,
                    recipient,
                    ..base
                }),
                Err(OwnershipError::InvalidRequest)
            );
        }
        assert!(validate(&OwnershipMutation {
            org: Uuid::nil(),
            ..base
        })
        .is_err());
        assert!(validate(&OwnershipMutation {
            app: "../app",
            ..base
        })
        .is_err());
    }
}
