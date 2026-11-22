//! Current access for the separately authenticated Flow use ingress.
//!
//! This permits access to Marty's original request/proof records. It does not
//! verify a submitted proof, approve a grant or authorize a consumer operation.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{DelegationCommandCaller, DelegationUseCommandError, VerifiedDelegationCommandAccess};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DelegationUseIngressOperation {
    RequestRead,
    ProofSubmit,
}

#[async_trait]
pub trait DelegationUseIngressAuthorizer: Send + Sync {
    async fn authorize_ingress(
        &self,
        caller: &DelegationCommandCaller,
        challenge_id: Uuid,
        operation: DelegationUseIngressOperation,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, DelegationUseCommandError>;
}
