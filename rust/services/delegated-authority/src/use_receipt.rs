//! Recovery of the exact original signed artifact. This read produces no new
//! signature, evaluation or authority and never refreshes signed expiry.
use std::{fmt, time::Duration as Timeout};

use super::*;

/// The retained artifact of an authorized FINAL_USE result. Construction is
/// private: deserialized receipt bytes cannot establish original-result access.
/// Only the explicit protected receipt endpoint serializes this evidence.
///
/// ```compile_fail
/// let forged: marty_delegated_authority::RecoveredDelegatedUseReceipt =
///     serde_json::from_str("{}").unwrap();
/// ```
#[derive(Serialize)]
pub struct RecoveredDelegatedUseReceipt {
    original_response: DelegationUseCommandResponse,
    receipt_ref: String,
    receipt_digest: String,
    compact_jws: String,
    semantics: &'static str,
}
impl fmt::Debug for RecoveredDelegatedUseReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveredDelegatedUseReceipt { <private original evidence> }")
    }
}
impl RecoveredDelegatedUseReceipt {
    pub fn original_response(&self) -> &DelegationUseCommandResponse {
        &self.original_response
    }
    pub fn receipt_ref(&self) -> &str {
        &self.receipt_ref
    }
    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }
    pub fn compact_jws(&self) -> &str {
        &self.compact_jws
    }
    pub fn semantics(&self) -> &'static str {
        self.semantics
    }
}

impl DelegationUseCommandService {
    /// Called with an already authenticated context's original time bounds.
    /// Accepts the existing strict RECOVER_RESULT wire exclusively. Current
    /// RECOVER_RESULT rights authorize reading the original receipt artifact;
    /// they do not confer a fresh operation permit or extend its signed lifetime.
    pub async fn recover_receipt_before(
        &self,
        caller: &DelegationCommandCaller,
        raw: &[u8],
        observed_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<RecoveredDelegatedUseReceipt, DelegationUseCommandError> {
        let DecodedDelegationUseCommand::Recover {
            original_command_id,
            expected_command_digest,
        } = decode_delegation_use_command(raw)?
        else {
            return Err(DelegationUseCommandError::Unsupported);
        };
        let now = self.clock.now();
        if now < observed_at
            || now >= expires_at
            || observed_at
                .checked_add_signed(Duration::seconds(30))
                .is_none_or(|maximum| expires_at > maximum)
        {
            return Err(DelegationUseCommandError::Expired);
        }
        // Every await inside is a bounded read. Cancelling this operation never
        // cancels signing, external preparation, a mutation or its COMMIT.
        tokio::time::timeout(
            Timeout::from_secs(10),
            self.recover_receipt_bounded(
                caller,
                original_command_id,
                &expected_command_digest,
                now,
                expires_at,
            ),
        )
        .await
        .map_err(|_| DelegationUseCommandError::Unavailable)?
    }

    async fn recover_receipt_bounded(
        &self,
        caller: &DelegationCommandCaller,
        command_id: Uuid,
        expected_digest: &str,
        mut checked_at: DateTime<Utc>,
        mut deadline: DateTime<Utc>,
    ) -> Result<RecoveredDelegatedUseReceipt, DelegationUseCommandError> {
        // The only pre-authorization lookup is exact tenant + full typed actor
        // + original command metadata, needed by the existing recovery owner.
        let original = self.repository.receipt_original(caller, command_id).await?;
        checked_at = self.receipt_read_clock(checked_at, deadline)?;
        let original = original.ok_or(DelegationUseCommandError::ResultNotFound)?;

        let access_started = checked_at;
        let access = tokio::time::timeout(
            Timeout::from_secs(5),
            self.access
                .authorize_recovery(caller, &original.grant, access_started),
        )
        .await
        .map_err(|_| DelegationUseCommandError::Unavailable)??;
        checked_at = self.receipt_read_clock(checked_at, deadline)?;
        check_access(&access, access_started, checked_at)?;
        deadline = deadline.min(access.valid_until);

        // Check visibility even for a conflicting digest, unsupported original
        // command kind or unresolved claim. No receipt is read before this gate.
        if original.command.digest != expected_digest {
            return Err(DelegationUseCommandError::Conflict);
        }
        let Some(response) = &original.response else {
            return Err(DelegationUseCommandError::PreparationPending);
        };
        if !matches!(response.result, DelegationUseCommandResult::FinalUse { .. }) {
            return Err(DelegationUseCommandError::Unsupported);
        }

        let stored = self.repository.original_receipt(caller, command_id).await?;
        checked_at = self.receipt_read_clock(checked_at, deadline)?;
        if stored.original.grant != original.grant
            || stored.original.command.digest != original.command.digest
            || stored.original.command.document != original.command.document
            || serde_json::to_value(&stored.original.response)
                .map_err(|_| DelegationUseCommandError::Unavailable)?
                != serde_json::to_value(&original.response)
                    .map_err(|_| DelegationUseCommandError::Unavailable)?
        {
            return Err(DelegationUseCommandError::Unavailable);
        }

        // A grant, key or receipt may now be expired/revoked and remain valid
        // historical evidence. Current identity and recovery rights must still
        // survive the awaited read, without renewing either original deadline.
        let access_started = checked_at;
        let fresh = tokio::time::timeout(
            Timeout::from_secs(5),
            self.access
                .authorize_recovery(caller, &original.grant, access_started),
        )
        .await
        .map_err(|_| DelegationUseCommandError::Unavailable)??;
        checked_at = self.receipt_read_clock(checked_at, deadline)?;
        check_access(&fresh, access_started, checked_at)?;
        deadline = deadline.min(fresh.valid_until);
        self.receipt_read_clock(checked_at, deadline)?;

        let mut original_response = stored
            .original
            .response
            .ok_or(DelegationUseCommandError::Unavailable)?;
        original_response.recovered = true;
        Ok(RecoveredDelegatedUseReceipt {
            original_response,
            receipt_ref: stored.receipt_ref,
            receipt_digest: stored.receipt_digest,
            compact_jws: stored.compact_jws,
            semantics: "EVIDENCE_ONLY",
        })
    }

    fn receipt_read_clock(
        &self,
        checked_at: DateTime<Utc>,
        deadline: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, DelegationUseCommandError> {
        let now = self.clock.now();
        if now < checked_at || now >= deadline {
            return Err(DelegationUseCommandError::Expired);
        }
        Ok(now)
    }
}
