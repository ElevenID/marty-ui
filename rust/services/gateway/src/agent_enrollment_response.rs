//! Closed projections of server-owned enrollment challenges and retained results.
//! Parsing a proof here is only transport validation. Organization verifies its
//! signature and atomically consumes the authoritative retained challenge.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_principal_runtime_binding::{
    jwk_sha256_thumbprint, managed_enrollment::EnrollmentChallenge, parse_thumbprint,
};
use mmf_platform::TrustedIdentityContext;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{
    canonical_uuid, digest, fields, response_contract::timestamp, revision, valid_agent,
    AdminRoute, Operation, UniqueValue,
};

fn segment(value: &str, maximum: usize) -> Option<Vec<u8>> {
    if value.is_empty() || value.len() > maximum * 2 {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    (bytes.len() <= maximum && URL_SAFE_NO_PAD.encode(&bytes) == value).then_some(bytes)
}

fn proof_payload(proof: &str) -> Option<(Value, Vec<u8>)> {
    if proof.len() > 16_384 {
        return None;
    }
    let parts = proof.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return None;
    }
    let header = serde_json::from_slice::<UniqueValue>(&segment(parts[0], 1024)?)
        .ok()?
        .0;
    let bytes = segment(parts[1], 8192)?;
    let payload = serde_json::from_slice::<UniqueValue>(&bytes).ok()?.0;
    if segment(parts[2], 64)?.len() != 64
        || !fields(header.as_object()?, &["typ", "alg", "kid"], &[])
        || header["typ"] != "marty-managed-enrollment+jws"
        || !matches!(header["alg"].as_str(), Some("ES256" | "EdDSA"))
        || header["alg"] != payload["key_algorithm"]
        || header["kid"] != payload["key_id"]
        || payload["profile"] != "urn:marty:managed-key-enrollment:v1"
        || payload["purpose"] != "ENROLL_MANAGED_KEY"
    {
        return None;
    }
    Some((payload, bytes))
}

pub(super) fn compact_proof(proof: &str) -> bool {
    proof_payload(proof).is_some()
}

fn valid_challenge(
    route: &AdminRoute,
    user: &str,
    expected_session: Option<&str>,
    value: &Value,
) -> Option<EnrollmentChallenge> {
    if !fields(
        value.as_object()?,
        &[
            "profile",
            "challenge_id",
            "organization_id",
            "agent_id",
            "expected_revision",
            "challenge",
            "signing_payload",
            "challenge_digest",
            "expires_at",
            "recovered",
        ],
        &[],
    ) || value["profile"] != "urn:marty:managed-key-enrollment:v1"
        || !value["recovered"].is_boolean()
    {
        return None;
    }
    // This document is a response from the selected authenticated Organization
    // service. No public request can supply a replacement trusted challenge.
    let challenge =
        EnrollmentChallenge::from_trusted_document(&serde_json::to_vec(&value["challenge"]).ok()?)
            .ok()?;
    if challenge.organization_id() != route.organization_id
        || Some(challenge.agent_id()) != route.resource_id
        || Some(challenge.administrator_id()) != canonical_uuid(user)
        || route
            .linked_id
            .is_some_and(|id| id != challenge.challenge_id())
        || expected_session.is_some_and(|session| challenge.session_ref() != session)
        || value["organization_id"] != challenge.organization_id().to_string()
        || value["agent_id"] != challenge.agent_id().to_string()
        || value["challenge_id"] != challenge.challenge_id().to_string()
        || value["expected_revision"].as_u64() != Some(challenge.expected_revision())
        || value["signing_payload"] != challenge.payload_b64url()
        || value["challenge_digest"] != challenge.digest()
        || timestamp(&value["expires_at"]).is_none_or(|time| {
            time.timestamp() != challenge.expires_at() || time.timestamp_subsec_nanos() != 0
        })
    {
        return None;
    }
    Some(challenge)
}

fn valid_result(route: &AdminRoute, value: &Value, payload: &Value, payload_digest: &str) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if !fields(
        object,
        &[
            "challenge_id",
            "organization_id",
            "agent_id",
            "key_id",
            "previous_revision",
            "enrolled_revision",
            "completed_at",
            "proof_digest",
            "challenge_digest",
            "enrollment",
            "authority_status",
            "identity",
            "recovered",
        ],
        &[],
    ) || value["organization_id"] != route.organization_id.to_string()
        || value["agent_id"].as_str().and_then(canonical_uuid) != route.resource_id
        || value["challenge_id"].as_str().and_then(canonical_uuid) != route.linked_id
        || value["challenge_id"] != payload["challenge_id"]
        || value["organization_id"] != payload["organization_id"]
        || value["agent_id"] != payload["agent_id"]
        || value["key_id"] != payload["key_id"]
        || value["previous_revision"] != payload["expected_revision"]
        || !revision(&value["enrolled_revision"])
        || value["enrolled_revision"].as_u64()
            != value["previous_revision"]
                .as_u64()
                .and_then(|n| n.checked_add(1))
        || value["challenge_digest"] != payload_digest
        || !digest(&value["proof_digest"])
        || value["enrollment"] != "KEY_CONTROL_VERIFIED"
        || value["authority_status"] != "NOT_ASSESSED"
        || !value["recovered"].is_boolean()
        || !valid_agent(&value["identity"], route.organization_id, route.resource_id)
    {
        return false;
    }
    let Some(completed) = timestamp(&value["completed_at"]) else {
        return false;
    };
    if payload["iat"]
        .as_i64()
        .is_none_or(|iat| completed.timestamp() < iat)
        || payload["exp"]
            .as_i64()
            .is_none_or(|exp| completed.timestamp() >= exp)
    {
        return false;
    }
    let identity = &value["identity"];
    identity["kind"] == "MANAGED"
        && identity["status"] == "ACTIVE"
        && identity["revision"] == value["enrolled_revision"]
        && identity["provenance"]["managed_enrollment"] == "KEY_CONTROL_VERIFIED"
        && identity["runtime_instance_ref"] == payload["runtime_instance_ref"]
        && identity["issuer"] == payload["issuer"]
        && identity["subject"] == payload["subject"]
        && timestamp(&identity["updated_at"]) == Some(completed)
        && identity["keys"].as_array().is_some_and(|keys| {
            keys.len() == 1
                && keys[0]["key_id"] == value["key_id"]
                && keys[0]["status"] == "ACTIVE"
                && key_matches(&keys[0], payload)
        })
}

fn key_matches(key: &Value, payload: &Value) -> bool {
    let encode = |value: &Value| serde_json::to_vec(value).unwrap_or_default();
    let (Ok(expected), Ok(actual), Ok(recorded)) = (
        parse_thumbprint(&encode(&payload["key_thumbprint"])),
        jwk_sha256_thumbprint(&encode(&key["public_key_jwk"])),
        parse_thumbprint(&encode(&key["fingerprint"])),
    ) else {
        return false;
    };
    expected.same_binding(&actual)
        && expected.same_binding(&recorded)
        && match payload["key_algorithm"].as_str() {
            Some("ES256") => key["algorithm"] == "ES256",
            Some("EdDSA") => matches!(key["algorithm"].as_str(), Some("EdDSA" | "Ed25519")),
            _ => false,
        }
}

pub(super) fn valid_response(
    route: &AdminRoute,
    identity: &TrustedIdentityContext,
    submitted: Option<&Value>,
    session_ref: &str,
    value: &Value,
) -> bool {
    let Some(user) = identity.user_id.as_deref() else {
        return false;
    };
    match route.operation {
        Operation::CreateEnrollmentChallenge => {
            valid_challenge(route, user, Some(session_ref), value).is_some_and(|challenge| {
                submitted.is_some_and(|input| {
                    input["expected_revision"].as_u64() == Some(challenge.expected_revision())
                })
            })
        }
        Operation::CompleteEnrollment => {
            let Some(proof) = submitted.and_then(|value| value["proof"].as_str()) else {
                return false;
            };
            let Some((payload, bytes)) = proof_payload(proof) else {
                return false;
            };
            payload["administrator_id"] == user
                && payload["session_ref"] == session_ref
                && valid_result(
                    route,
                    value,
                    &payload,
                    &format!("sha256:{:x}", Sha256::digest(&bytes)),
                )
                && value["proof_digest"] == format!("sha256:{:x}", Sha256::digest(proof.as_bytes()))
        }
        Operation::InspectEnrollmentChallenge => {
            let Some(object) = value.as_object() else {
                return false;
            };
            if !fields(
                object,
                &["challenge", "state", "result", "invalidated_at"],
                &[],
            ) {
                return false;
            }
            let Some(challenge) = valid_challenge(route, user, None, &value["challenge"]) else {
                return false;
            };
            match value["state"].as_str() {
                Some("CONSUMED") => {
                    value["invalidated_at"].is_null()
                        && valid_result(
                            route,
                            &value["result"],
                            &challenge.document(),
                            &challenge.digest(),
                        )
                }
                Some("INVALIDATED") => {
                    value["result"].is_null() && timestamp(&value["invalidated_at"]).is_some()
                }
                Some("PENDING" | "EXPIRED") => {
                    value["result"].is_null() && value["invalidated_at"].is_null()
                }
                _ => false,
            }
        }
        _ => false,
    }
}
