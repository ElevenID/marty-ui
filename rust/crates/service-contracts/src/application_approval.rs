//! Stable reason codes for Flow application-approval responses.
//! Human-readable `reason` text is for display and must not drive decisions.

/// The durable application-event plan contains no matching issuance flow.
/// Consumers must also reject contradictory execution results before treating
/// this code as proof that no flow was selected.
pub const NO_MATCHING_FLOW: &str = "FLOW.NO_MATCHING_APPLICATION_FLOW";
