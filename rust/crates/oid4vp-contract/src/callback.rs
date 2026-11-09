//! Shared wire production for Flow's signed verification callback.
//!
//! This serialization helper does not authenticate a presentation or grant
//! issuance authority. Flow supplies its already validated terminal result;
//! callback consumers independently authenticate the resulting signed payload.

use serde_json::{json, Map, Value};

use crate::Oid4vpContractError;

/// Preserve the callback's canonical payload, including the policy reference
/// before calculating its decision digest. Raw credential results are represented
/// only by their evidence digest and never copied into the public callback.
/// The service supplies its existing callback digest owner so this wire contract
/// does not acquire push-delivery runtime dependencies or define another digest.
pub fn build_verification_callback_payload<E>(
    flow_instance_id: &str,
    presentation_policy_id: &str,
    completed_at: Option<String>,
    result: &Map<String, Value>,
    payload_digest: impl Fn(&Value) -> Result<String, E>,
) -> Result<Value, Oid4vpContractError> {
    let credential_results = result
        .get("credential_results")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let policy_revision = result
        .get("policy_revision")
        .ok_or(Oid4vpContractError::Serialization)?;
    let mut payload = json!({
        "flow_instance_id": flow_instance_id,
        "result": result.get("evaluation_result"),
        "decision": result.get("decision"),
        "decision_reason": result.get("decision_reason"),
        "verified_claims": result.get("verified_claims"),
        "presentation_policy_id": presentation_policy_id,
        "policy_revision": policy_revision,
        "completed_at": completed_at,
        "evidence_digest": payload_digest(&json!({"credential_results": credential_results}))
            .map_err(|_| Oid4vpContractError::Serialization)?
    });
    let decision_digest =
        payload_digest(&payload).map_err(|_| Oid4vpContractError::Serialization)?;
    payload["decision_digest"] = json!(decision_digest);
    Ok(payload)
}
