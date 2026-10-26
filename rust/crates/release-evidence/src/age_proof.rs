//! D03's production API contract checks. This module does not authenticate a
//! wallet token: native presentation-policy does that before projecting
//! `authenticated_disclosures`. Callers must obtain replies from the bound
//! service during the current run; a saved report is not execution evidence.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const SCHEMA: &str = "marty-age-proof-demo/v1";
pub const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;
pub const MDL_DOCTYPE: &str = "org.iso.18013.5.1.mDL";
pub const MDL_NAMESPACE: &str = "org.iso.18013.5.1";
pub const AGE_CLAIM: &str = "age_over_21";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgeProofExpected {
    pub run_id: String,
    pub organization_id: String,
    pub trusted_template_id: String,
    pub rejected_template_id: String,
    pub policy_id: String,
    pub trust_profile_id: String,
    pub verifier_did: String,
    pub trusted_issuer_id: String,
    pub rejected_issuer_id: String,
    pub service_origin: String,
    pub source_revision: String,
    pub started_at: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgeProofInput {
    pub expected: AgeProofExpected,
    pub observed: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgeProofRequestBinding {
    pub instance_id: String,
    pub nonce_sha256: String,
    pub request_sha256: String,
    pub external_reference: String,
}

type Check<T> = Result<T, &'static str>;

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn text<'a>(object: &'a Value, field: &str) -> Check<&'a str> {
    object[field]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or("missing required source field")
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
        && !value.starts_with("SET_")
        && !value.starts_with("REPLACE_")
}

// Issuance reserves urn:uuid IDs for credentials. Other resource identifiers
// keep their narrower grammar; do not admit arbitrary URIs into route paths.
fn credential_identifier(value: &str) -> bool {
    if let Some(uuid) = value.strip_prefix("urn:uuid:") {
        return uuid.len() == 36
            && uuid.bytes().enumerate().all(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
                }
            });
    }
    identifier(value)
}

fn equal(object: &Value, field: &str, expected: &str) -> Check<()> {
    (text(object, field)? == expected)
        .then_some(())
        .ok_or("source identity does not match this run")
}

fn successful_reply(reply: &Value) -> Check<&Value> {
    let status = reply["status"].as_u64().ok_or("missing HTTP status")?;
    if !(200..300).contains(&status) || !reply["body"].is_object() {
        return Err("production request did not return a successful object");
    }
    Ok(&reply["body"])
}

fn started_at(expected: &AgeProofExpected) -> Check<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&expected.started_at)
        .map(|date| date.with_timezone(&Utc))
        .map_err(|_| "invalid run start time")
}

fn recent(timestamp: &str, expected: &AgeProofExpected) -> Check<()> {
    let timestamp = DateTime::parse_from_rfc3339(timestamp)
        .map_err(|_| "invalid source timestamp")?
        .with_timezone(&Utc);
    let age = timestamp - started_at(expected)?;
    if age.num_seconds() < -5 || age.num_seconds() > 3_600 {
        return Err("source evidence is outside this run");
    }
    Ok(())
}

fn validate_expected(expected: &AgeProofExpected) -> Check<()> {
    for id in [
        &expected.run_id,
        &expected.organization_id,
        &expected.trusted_template_id,
        &expected.rejected_template_id,
        &expected.policy_id,
        &expected.trust_profile_id,
    ] {
        if !identifier(id) {
            return Err("run requires exact non-placeholder resource identifiers");
        }
    }
    if expected.trusted_template_id == expected.rejected_template_id
        || expected.trusted_issuer_id == expected.rejected_issuer_id
    {
        return Err("trusted and rejected issuers and templates must be different");
    }
    for issuer in [&expected.trusted_issuer_id, &expected.rejected_issuer_id] {
        let fingerprint = issuer
            .strip_prefix("x509-sha256:")
            .ok_or("mdoc issuer certificate fingerprint required")?;
        if fingerprint.len() != 64
            || !fingerprint
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("invalid mdOC issuer certificate fingerprint");
        }
    }
    let host = expected
        .service_origin
        .strip_prefix("https://")
        .ok_or("production service requires HTTPS")?;
    if host.is_empty()
        || host
            .bytes()
            .any(|b| b"/?#@\\".contains(&b) || b.is_ascii_whitespace())
    {
        return Err("service_origin must be an HTTPS origin without credentials or path");
    }
    if !expected.verifier_did.starts_with("did:") || expected.verifier_did.len() > 2_048 {
        return Err("verifier DID is required");
    }
    if expected.source_revision.len() != 40
        || !expected
            .source_revision
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        return Err("exact product source revision is required");
    }
    started_at(expected)?;
    Ok(())
}

fn template<'a>(expected: &AgeProofExpected, value: &'a Value, id: &str) -> Check<&'a Value> {
    equal(value, "id", id)?;
    equal(value, "organization_id", &expected.organization_id)?;
    if !text(value, "status")?.eq_ignore_ascii_case("active")
        || !matches!(
            text(value, "credential_payload_format")?,
            "MDOC" | "mdoc" | "mso_mdoc"
        )
        || text(value, "doctype")? != MDL_DOCTYPE
        || text(value, "issuance_protocol")? != "OID4VCI_PRE_AUTH"
    {
        return Err("active OID4VCI mDL template required");
    }
    let claims = value["claims"]
        .as_array()
        .ok_or("template claims missing")?;
    let matches: Vec<_> = claims
        .iter()
        .filter(|claim| claim["name"] == AGE_CLAIM)
        .collect();
    let [claim] = matches.as_slice() else {
        return Err("exactly one age_over_21 template mapping required");
    };
    if claim["namespace"] != MDL_NAMESPACE || claim["mdoc_element_identifier"] != AGE_CLAIM {
        return Err("age_over_21 does not map to the standard mDL namespace");
    }
    Ok(value)
}

fn prepare(input: &AgeProofInput) -> Check<Value> {
    let expected = &input.expected;
    let observed = &input.observed;
    let trusted = template(
        expected,
        &observed["trusted_template"],
        &expected.trusted_template_id,
    )?;
    let rejected = template(
        expected,
        &observed["rejected_template"],
        &expected.rejected_template_id,
    )?;
    if text(trusted, "issuer_did")? == text(rejected, "issuer_did")? {
        return Err("negative fixture must use a different managed issuer");
    }
    let policy = &observed["policy"];
    equal(policy, "id", &expected.policy_id)?;
    equal(policy, "organization_id", &expected.organization_id)?;
    equal(policy, "trust_profile_id", &expected.trust_profile_id)?;
    if !text(policy, "status")?.eq_ignore_ascii_case("active") {
        return Err("age policy must already be active");
    }
    let requirements = policy["credential_requirements"]
        .as_array()
        .ok_or("policy requirements missing")?;
    let [requirement] = requirements.as_slice() else {
        return Err("age policy must request exactly one credential");
    };
    equal(
        requirement,
        "credential_template_id",
        &expected.trusted_template_id,
    )?;
    let claims = requirement["requested_claims"]
        .as_array()
        .ok_or("requested claims missing")?;
    let [claim] = claims.as_slice() else {
        return Err("age policy must request only age_over_21");
    };
    equal(claim, "claim_name", AGE_CLAIM)?;
    if claim["required"] != true || claim["selective_disclosure"] != true {
        return Err("age_over_21 must be required and selectively disclosed");
    }
    // Presence alone would allow false. Require the actual boolean business rule.
    let constraints = claim["constraints"]
        .as_array()
        .ok_or("age predicate constraint missing")?;
    if !constraints.iter().any(|constraint| {
        constraint["claim_name"] == AGE_CLAIM
            && constraint["constraint_type"]
                .as_str()
                .is_some_and(|kind| kind.eq_ignore_ascii_case("equals"))
            && constraint["value"] == true
    }) {
        return Err("age policy must require age_over_21 equals boolean true");
    }
    if policy["holder_binding"]["required"] != true {
        return Err("age policy must require device holder binding");
    }
    for flag in [
        "challenge_required",
        "audience_binding_required",
        "replay_detection_required",
    ] {
        if policy["holder_binding"]["proof_freshness"][flag] != true {
            return Err("age policy must require challenge, audience and replay binding");
        }
    }
    let trust = &observed["trust_profile"];
    equal(trust, "id", &expected.trust_profile_id)?;
    equal(trust, "organization_id", &expected.organization_id)?;
    if !text(trust, "status")?.eq_ignore_ascii_case("active") {
        return Err("age trust profile must already be active");
    }
    let sources = trust["trust_sources"]
        .as_array()
        .ok_or("mdoc trust sources missing")?;
    let mut pins = Vec::new();
    for source in sources {
        if source["enabled"] == false {
            continue;
        }
        if source["source_type"] != "PINNED_ISSUER"
            || source
                .get("registry_sync")
                .is_some_and(|value| !value.is_null())
        {
            return Err(
                "D03 requires explicit issuer pins without a broader or imported trust source",
            );
        }
        let pem = text(source, "certificate_pem")?;
        let encoded = pem
            .strip_prefix("-----BEGIN CERTIFICATE-----")
            .and_then(|pem| pem.trim().strip_suffix("-----END CERTIFICATE-----"))
            .ok_or("pinned certificate PEM missing")?;
        let der = base64::engine::general_purpose::STANDARD
            .decode(encoded.split_whitespace().collect::<String>())
            .map_err(|_| "invalid pinned certificate encoding")?;
        pins.push(format!("x509-sha256:{}", digest(&der)));
    }
    if pins.as_slice() != [expected.trusted_issuer_id.clone()] {
        return Err("D03 requires exactly its trusted issuer certificate pin; the rejected issuer must be excluded");
    }
    let claims = &observed["synthetic_claims"];
    if !claims.is_object() || claims[AGE_CLAIM] != true {
        return Err("synthetic issuance fixture must contain age_over_21 boolean true");
    }
    for selected in [trusted, rejected] {
        for claim in selected["claims"]
            .as_array()
            .ok_or("template claims missing")?
        {
            if claim["required"] == true && claims.get(text(claim, "name")?).is_none() {
                return Err("synthetic fixture is missing a required issuance claim");
            }
        }
    }
    Ok(json!({
        "trusted_issuance": {"method": "POST", "path": "/v1/issuance", "body": {
            "organization_id": expected.organization_id, "credential_template_id": expected.trusted_template_id, "claims": claims
        }},
        "rejected_issuance": {"method": "POST", "path": "/v1/issuance", "body": {
            "organization_id": expected.organization_id, "credential_template_id": expected.rejected_template_id, "claims": claims
        }},
        "verification": {"method": "POST", "path": "/v1/flows/verify", "body": {
            "organization_id": expected.organization_id, "presentation_policy_id": expected.policy_id,
            "trust_profile_id": expected.trust_profile_id, "issuer_did": expected.verifier_did,
            "response_type": "vp_token", "request_transport": "request_uri", "request_uri_method": "get", "expiry_minutes": 10
        }},
        "setup_sha256": digest(&serde_json::to_vec(observed).map_err(|_| "cannot bind setup")?)
    }))
}

fn issued(input: &AgeProofInput) -> Check<Value> {
    let expected = &input.expected;
    let observed = &input.observed;
    let reply = successful_reply(&observed["issuance_reply"])?;
    let template_id = text(observed, "template_id")?;
    if template_id != expected.trusted_template_id && template_id != expected.rejected_template_id {
        return Err("issuance does not belong to a D03 template");
    }
    equal(reply, "organization_id", &expected.organization_id)?;
    equal(reply, "credential_template_id", template_id)?;
    let transaction_id = text(reply, "id")?; // Current public gateway response.
    if !identifier(transaction_id) {
        return Err("invalid issuance transaction ID");
    }
    let records = observed["issued_credentials"]
        .as_array()
        .ok_or("issued inventory must be an array")?;
    if records
        .iter()
        .any(|record| record["organization_id"] != expected.organization_id)
    {
        return Err("issued inventory crossed organization boundary");
    }
    let matches = records
        .iter()
        .filter(|record| record["flow_execution_id"] == transaction_id)
        .collect::<Vec<_>>();
    let [record] = matches.as_slice() else {
        return Err("exact issuance transaction must have one issued record");
    };
    equal(record, "credential_template_id", template_id)?;
    if !text(record, "status")?.eq_ignore_ascii_case("active")
        || !matches!(
            text(record, "credential_format")?,
            "MDOC" | "mdoc" | "mso_mdoc"
        )
    {
        return Err("fresh issued mDL is not active");
    }
    recent(text(record, "issued_at")?, expected)?;
    let id = text(record, "id")?;
    if !credential_identifier(id) {
        return Err("invalid issued credential ID");
    }
    Ok(json!({"transaction_id": transaction_id, "credential_id": id, "template_id": template_id}))
}

fn request(input: &AgeProofInput) -> Check<Value> {
    let expected = &input.expected;
    let observed = &input.observed;
    let reply = successful_reply(&observed["start_reply"])?;
    let instance = successful_reply(&observed["instance_reply"])?;
    let instance_id = text(reply, "instance_id")?;
    if !identifier(instance_id) {
        return Err("invalid verification instance ID");
    }
    equal(reply, "presentation_policy_id", &expected.policy_id)?;
    equal(instance, "id", instance_id)?;
    equal(instance, "organization_id", &expected.organization_id)?;
    recent(text(instance, "created_at")?, expected)?;
    let external_reference = text(observed, "external_reference")?;
    if !external_reference.starts_with(&format!("D03-{}-", expected.run_id)) {
        return Err("verification external reference does not belong to this run");
    }
    equal(
        &instance["metadata"],
        "external_reference",
        external_reference,
    )?;
    equal(
        &instance["context_data"],
        "presentation_policy_id",
        &expected.policy_id,
    )?;
    equal(
        &instance["context_data"],
        "trust_profile_id",
        &expected.trust_profile_id,
    )?;
    equal(
        &instance["context_data"],
        "oid4vp_issuer_did",
        &expected.verifier_did,
    )?;
    let token = text(observed, "request_jwt")?;
    let parts = token.split('.').collect::<Vec<_>>();
    let [header, payload, signature] = parts.as_slice() else {
        return Err("native signed request object required");
    };
    if signature.is_empty() {
        return Err("unsigned request object rejected");
    }
    let decode = |encoded: &str| -> Check<Value> {
        serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| "invalid request JWT encoding")?,
        )
        .map_err(|_| "invalid request JWT JSON")
    };
    let header = decode(header)?;
    if header["alg"] != "ES256" || header["typ"] != "oauth-authz-req+jwt" {
        return Err("native ES256 OAuth authorization request object required");
    }
    let payload = decode(payload)?;
    equal(
        &payload,
        "client_id",
        text(&instance["context_data"], "oid4vp_client_id")?,
    )?;
    equal(&payload, "iss", text(&payload, "client_id")?)?;
    equal(&payload, "nonce", text(reply, "nonce")?)?;
    equal(&payload, "state", instance_id)?;
    let response_uri = format!(
        "{}/v1/flows/instances/{instance_id}/submit",
        expected.service_origin
    );
    equal(&payload, "response_uri", &response_uri)?;
    if payload["response_mode"] != "direct_post" || payload["response_type"] != "vp_token" {
        return Err("native direct_post VP request required");
    }
    let issued_at = payload["iat"]
        .as_i64()
        .and_then(|timestamp| DateTime::from_timestamp(timestamp, 0))
        .ok_or("signed request issue time missing")?;
    recent(&issued_at.to_rfc3339(), expected)?;
    let expires_at = payload["exp"]
        .as_i64()
        .ok_or("signed request expiry missing")?;
    if expires_at <= issued_at.timestamp() || expires_at - issued_at.timestamp() > 900 {
        return Err("age request must have a short, positive lifetime");
    }
    let credentials = payload["dcql_query"]["credentials"]
        .as_array()
        .ok_or("DCQL query missing")?;
    let [credential] = credentials.as_slice() else {
        return Err("DCQL must request exactly one mDL");
    };
    if credential["format"] != "mso_mdoc" || credential["meta"]["doctype_value"] != MDL_DOCTYPE {
        return Err("DCQL request is not the standard mDL");
    }
    let claims = credential["claims"]
        .as_array()
        .ok_or("DCQL requested claims missing")?;
    let [claim] = claims.as_slice() else {
        return Err("DCQL must request only age_over_21");
    };
    if claim["path"] != json!([MDL_NAMESPACE, AGE_CLAIM]) || claim["intent_to_retain"] != false {
        return Err("DCQL must request age_over_21 without retention");
    }
    if payload["dcql_query"].get("credential_sets").is_some()
        || credential.get("claim_sets").is_some()
    {
        return Err("alternative DCQL sets are outside D03's exact query");
    }
    serde_json::to_value(AgeProofRequestBinding {
        instance_id: instance_id.into(),
        nonce_sha256: digest(text(reply, "nonce")?.as_bytes()),
        request_sha256: digest(token.as_bytes()),
        external_reference: external_reference.into(),
    })
    .map_err(|_| "cannot bind request")
}

fn allowed(input: &AgeProofInput) -> Check<Value> {
    let result = successful_reply(&input.observed["result_reply"])?;
    let binding: AgeProofRequestBinding =
        serde_json::from_value(input.observed["request_binding"].clone())
            .map_err(|_| "request binding is missing")?;
    equal(result, "instance_id", &binding.instance_id)?;
    if !binding
        .external_reference
        .starts_with(&format!("D03-{}-", input.expected.run_id))
    {
        return Err("result belongs to another run");
    }
    if result["status"] != "COMPLETED"
        || result["decision"] != "allow"
        || result["result"] != "passed"
    {
        return Err("age proof has not passed the native verifier");
    }
    recent(text(result, "evaluation_timestamp")?, &input.expected)?;
    let results = result["credential_results"]
        .as_array()
        .ok_or("credential results missing")?;
    let [credential] = results.as_slice() else {
        return Err("exactly one authenticated mDL result required");
    };
    equal(
        credential,
        "credential_template_id",
        &input.expected.trusted_template_id,
    )?;
    equal(credential, "issuer_did", &input.expected.trusted_issuer_id)?;
    if credential["satisfied"] != true
        || credential["signature_valid"] != true
        || credential["trust_check_passed"] != true
    {
        return Err("native mDL authentication or issuer trust did not pass");
    }
    let expected_disclosures = json!({"format": "mso_mdoc", "documents": [{
        "doc_type": MDL_DOCTYPE, "namespaces": {MDL_NAMESPACE: [AGE_CLAIM]}
    }]});
    if credential["authenticated_disclosures"] != expected_disclosures {
        return Err("actual authenticated mDL disclosures are not exactly age_over_21");
    }
    if result["verified_claims"] != json!({AGE_CLAIM: true}) {
        return Err("minimal age result must contain only age_over_21 boolean true");
    }
    Ok(
        json!({"instance_id": binding.instance_id, "issuer_id": input.expected.trusted_issuer_id,
        "disclosed_claim_names": [AGE_CLAIM], "result_sha256": digest(&serde_json::to_vec(result).map_err(|_| "cannot bind result")?),
        "request_sha256": binding.request_sha256}),
    )
}

fn denied(input: &AgeProofInput) -> Check<Value> {
    let expected = &input.expected;
    let observed = &input.observed;
    let binding: AgeProofRequestBinding =
        serde_json::from_value(observed["request_binding"].clone())
            .map_err(|_| "negative request binding missing")?;
    if !binding
        .external_reference
        .starts_with(&format!("D03-{}-", expected.run_id))
        || !binding.external_reference.ends_with("-rejected")
    {
        return Err("denial must belong to this run's rejected fixture request");
    }
    let instance = successful_reply(&observed["instance_reply"])?;
    equal(instance, "id", &binding.instance_id)?;
    equal(instance, "organization_id", &expected.organization_id)?;
    equal(
        &instance["metadata"],
        "external_reference",
        &binding.external_reference,
    )?;
    if !matches!(
        text(instance, "status")?,
        "AWAITING_WALLET" | "IN_PROGRESS" | "FAILED"
    ) {
        return Err("untrusted fixture request must not complete, expire or be cancelled before observation");
    }
    if instance["context_data"]["result"]["decision"] == "allow"
        || instance["context_data"]["verified_claims"]
            .as_object()
            .is_some_and(|claims| !claims.is_empty())
    {
        return Err("untrusted fixture unexpectedly produced accepted claims");
    }
    equal(
        &observed["issued_binding"],
        "template_id",
        &expected.rejected_template_id,
    )?;
    if !credential_identifier(text(&observed["issued_binding"], "credential_id")?)
        || !identifier(text(&observed["issued_binding"], "transaction_id")?)
    {
        return Err("negative fixture must have its own exact issued credential");
    }
    let report = &observed["wallet_report"];
    equal(report, "scenarioSlug", "private-online-age-proof")?;
    if !matches!(
        text(report, "laneId")?,
        "eudi-age-proof-interoperability" | "spruceid-age-proof-interoperability"
    ) || report["result"] != "PASS"
        || report["profile"]["classification"] != "INDEPENDENT"
    {
        return Err("live independent-wallet rejection recording required");
    }
    recent(text(report, "startedAt")?, expected)?;
    recent(text(report, "completedAt")?, expected)?;
    let action_index = observed["denial_action_index"]
        .as_u64()
        .and_then(|index| usize::try_from(index).ok())
        .ok_or("negative wallet action index missing")?;
    let action = report["actions"]
        .as_array()
        .and_then(|actions| actions.get(action_index))
        .ok_or("negative wallet action missing")?;
    let package = text(&report["profile"], "walletPackage")?;
    if action["result"] != "PASS"
        || action["type"] != "assertText"
        || action["target"] != "wallet"
        || action["before"]["package"] != package
        || action["after"]["package"] != package
    {
        return Err("explicit rejection must actually be observed in the pinned wallet");
    }
    let message = text(observed, "rejection_text")?;
    let lower = message.to_ascii_lowercase();
    if message.len() > 256
        || [
            "pending",
            "timeout",
            "timed out",
            "waiting",
            "unknown",
            "not available",
        ]
        .iter()
        .any(|word| lower.contains(word))
        || ![
            "untrusted",
            "not trusted",
            "invalid_presentation",
            "verification failed",
            "presentation failed",
            "presentation rejected",
        ]
        .iter()
        .any(|word| lower.contains(word))
    {
        return Err(
            "pending, unknown or generic failure is not an explicit presentation rejection",
        );
    }
    let words = lower
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let padded = format!(" {words} ");
    if ![
        " untrusted issuer ",
        " issuer untrusted ",
        " issuer is untrusted ",
        " issuer not trusted ",
        " issuer is not trusted ",
        " issuer was not trusted ",
        " issuer certificate not trusted ",
        " issuer certificate is not trusted ",
    ]
    .iter()
    .any(|phrase| padded.contains(phrase))
    {
        return Err(
            "BLOCKED: generic presentation rejection does not establish issuer-trust denial",
        );
    }
    let scenario_sha256 = text(observed, "scenario_sha256")?;
    if scenario_sha256.len() != 64 || !scenario_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("rejection controls must be bound to the measured runtime scenario");
    }
    Ok(json!({
        "instance_id": binding.instance_id, "credential_id": observed["issued_binding"]["credential_id"],
        "observation": "ISSUER_TRUST_REJECTION_OBSERVED", "observation_source": "ANDROID_WALLET_UI",
        "issuer_trust_denial_observed": true,
        "observed_message": message, "backend_reason_code": Value::Null,
        "typed_issuer_not_trusted_result_available": false,
        "request_sha256": binding.request_sha256, "scenario_sha256": scenario_sha256,
        "scope": "The pinned wallet explicitly reports this fixture's issuer as untrusted. The public API does not expose a typed backend reason for retryable mdoc authentication failure."
    }))
}

fn cleanup_plan(input: &AgeProofInput) -> Check<Value> {
    let expected = &input.expected;
    let observed = &input.observed;
    let records = observed["issued_credentials"]
        .as_array()
        .ok_or("cleanup inventory missing")?;
    if records
        .iter()
        .any(|record| record["organization_id"] != expected.organization_id)
    {
        return Err("cleanup inventory crossed organization boundary");
    }
    let transactions = observed["owned_issuance"]
        .as_array()
        .ok_or("owned issuance IDs missing")?;
    let mut seen = std::collections::BTreeSet::new();
    let mut actions = Vec::new();
    let mut pending_offers = Vec::new();
    for transaction in transactions {
        let id = text(transaction, "id")?;
        let template_id = text(transaction, "template_id")?;
        if !identifier(id)
            || !seen.insert(id)
            || ![
                expected.trusted_template_id.as_str(),
                expected.rejected_template_id.as_str(),
            ]
            .contains(&template_id)
        {
            return Err("invalid or ambiguous owned issuance");
        }
        let matches = records
            .iter()
            .filter(|record| record["flow_execution_id"] == id)
            .collect::<Vec<_>>();
        if matches.is_empty() {
            pending_offers.push(id);
            continue;
        }
        let [record] = matches.as_slice() else {
            return Err("ambiguous issued records cannot be cleaned up");
        };
        equal(record, "credential_template_id", template_id)?;
        let record_id = text(record, "id")?;
        if !credential_identifier(record_id) {
            return Err("invalid cleanup credential ID");
        }
        match text(record, "status")? {
            "ACTIVE" | "SUSPENDED" => actions.push(json!({"resource": "credential", "id": record_id,
                "method": "POST", "path": format!("/v1/issued-credentials/{}/revoke", record_id.replace(':', "%3A")),
                // The lifecycle DTO rejects unknown body fields. Tenant scope
                // is provided by the authenticated gateway organization header.
                "body": {"reason": "D03 current-run cleanup"},
                "expected_status": "REVOKED"})),
            "REVOKED" | "EXPIRED" => {},
            _ => return Err("unknown issued credential cleanup state"),
        }
    }
    let instances = observed["owned_instances"]
        .as_array()
        .ok_or("owned verification IDs missing")?;
    for instance in instances {
        let id = text(instance, "id")?;
        if !identifier(id) || !seen.insert(id) {
            return Err("ambiguous owned verification ID");
        }
        equal(instance, "organization_id", &expected.organization_id)?;
        let reference = text(&instance["metadata"], "external_reference")?;
        if !reference.starts_with(&format!("D03-{}-", expected.run_id)) {
            return Err("cleanup verification belongs to another run");
        }
        if !matches!(
            text(instance, "status")?,
            "COMPLETED" | "FAILED" | "CANCELLED" | "EXPIRED"
        ) {
            actions.push(json!({"resource": "instance", "id": id, "method": "POST",
                "path": format!("/v1/flows/instances/{id}/cancel"), "body": {}, "expected_status": "CANCELLED"}));
        }
    }
    Ok(json!({"actions": actions, "pending_offers": pending_offers,
        "scope": "Current-run resources only. Pending offers identify exact captured transactions; authenticated cancellation and revoked readback are required before their cleanup is complete."}))
}

/// Validate one measured operation. No operation returns releaseReady or treats
/// a native/backend receipt as an EUDI/Spruce interoperability qualification.
pub fn validate_age_proof(operation: &str, input: &AgeProofInput) -> Check<Value> {
    validate_expected(&input.expected)?;
    let evidence = match operation {
        "inputs" => json!({"doctype": MDL_DOCTYPE, "namespace": MDL_NAMESPACE, "claim": AGE_CLAIM}),
        "prepare" => prepare(input)?,
        "issued" => issued(input)?,
        "request" => request(input)?,
        "allowed" => allowed(input)?,
        "denied" => denied(input)?,
        "cleanup" => cleanup_plan(input)?,
        _ => return Err("unsupported age-proof operation"),
    };
    Ok(
        json!({"schema": SCHEMA, "operation": operation, "run_id": input.expected.run_id,
        "source_revision": input.expected.source_revision, "evidence": evidence}),
    )
}
