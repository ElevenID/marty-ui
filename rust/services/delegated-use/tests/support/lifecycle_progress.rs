//! Error-only retained-stage diagnostics for the disposable lifecycle gate.
//! Counts never establish verification or become normal-path expectation inputs.

use std::time::Duration;

use sqlx::PgPool;
use uuid::Uuid;

/// Read only counts scoped to the failed challenge. No document, credential,
/// proof, signature, principal, provider token or database error is projected.
pub async fn retained_stages(pool: &PgPool, organization: Uuid, challenge: Uuid) -> String {
    let query = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64, i64, i64, i64, i64)>(
        "SELECT
         (SELECT count(*) FROM delegated_authority_service.use_command_claims
            WHERE organization_id=$1 AND challenge_id=$2 AND command_name='FINALIZE_USE'),
         (SELECT count(*) FROM flow_service.delegated_request_results
            WHERE organization_id=$1 AND challenge_id=$2),
         (SELECT count(*) FROM flow_service.delegated_proof_submissions
            WHERE organization_id=$1 AND challenge_id=$2),
         (SELECT count(*) FROM organization_service.machine_registry_observations
            WHERE organization_id=$1 AND document#>>'{scope,challenge_id}'=$2::TEXT),
         (SELECT count(*) FROM machine_credential_source.observations
            WHERE organization_id=$1 AND evidence_document#>>'{scope,challenge_id}'=$2::TEXT),
         (SELECT count(*) FROM delegated_authority_service.machine_authorization_evidence
            WHERE organization_id=$1 AND kind='SOURCE' AND evidence_document#>>'{scope,challenge_id}'=$2::TEXT),
         (SELECT count(*) FROM delegated_authority_service.machine_authorization_evidence
            WHERE organization_id=$1 AND kind='EVALUATION' AND evidence_document#>>'{scope,challenge_id}'=$2::TEXT),
         (SELECT count(*) FROM delegated_authority_service.machine_authentication_evidence
            WHERE organization_id=$1 AND challenge_id=$2),
         (SELECT count(*) FROM delegated_authority_service.use_receipts
            WHERE organization_id=$1 AND challenge_id=$2),
         (SELECT count(*) FROM flow_service.delegated_use_consumptions
            WHERE organization_id=$1 AND challenge_id=$2)",
    )
    .bind(organization)
    .bind(challenge)
    .fetch_one(pool);
    match tokio::time::timeout(Duration::from_secs(3), query).await {
        Ok(Ok((claims, requests, proofs, registry, credentials, policy_sources,
            policy_evaluations, machine_audits, receipts, consumptions))) => format!(
            "retained stage counts: finalization_claims={claims}, signed_requests={requests}, \
             proof_submissions={proofs}, registry_observations={registry}, \
             credential_source_observations={credentials}, machine_policy_sources={policy_sources}, \
             machine_policy_evaluations={policy_evaluations}, machine_authentication_audits={machine_audits}, \
             receipts={receipts}, flow_consumptions={consumptions}"
        ),
        _ => "retained stage count inspection unavailable".into(),
    }
}
