// SPDX-License-Identifier: AGPL-3.0-only
//! Authenticated core-side wire-to-journal composition, NOT a mounted route.
//!
//! The caller must construct ProducerIdentity from successful Common Gateway
//! API-key authentication, never from body fields or untrusted forwarded headers.
//! The journal then revalidates canonical locked authority. No runtime wiring or
//! production migration is enabled here.

use http::HeaderMap;

use crate::external_observation_postgres::{
    JournalError, PostgresObservationJournal, ProducerIdentity, ReceiptAcknowledgment,
};
use crate::external_observation_wire::{decode_submission, WireError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressError {
    Request(WireError),
    Journal(JournalError),
}

impl std::fmt::Display for IngressError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Request(error) => std::fmt::Display::fmt(error, formatter),
            Self::Journal(error) => std::fmt::Display::fmt(error, formatter),
        }
    }
}
impl std::error::Error for IngressError {}

/// Reject ambiguous or invalid bytes before acquiring a database connection.
/// No adapter here can select the tenant, source, subject or policy from headers.
/// The HTTP server must independently limit body streaming and authenticate.
pub async fn submit_observation(
    journal: &PostgresObservationJournal,
    identity: &ProducerIdentity,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<ReceiptAcknowledgment, IngressError> {
    let observation = decode_submission(headers, body).map_err(IngressError::Request)?;
    journal
        .submit(identity, &observation, &observation.observation_id)
        .await
        .map_err(IngressError::Journal)
}
