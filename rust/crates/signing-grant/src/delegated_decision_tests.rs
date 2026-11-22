use super::*;
use crate::{bound_input, payload_digest, GrantClaims, SigningOrigin};
use serde_json::json;

fn document() -> Value {
    let digest = format!("sha256:{}", "1".repeat(64));
    let grant =
        json!({"id":"11111111-1111-4111-8111-111111111111","revision":2,"terms_digest":digest});
    json!({
        "profile":RECEIPT_PROFILE,"id":"22222222-2222-4222-8222-222222222222",
        "issuer":{"type":"ORGANIZATION","id":"did:web:receipt.example"},"decision":"PERMIT",
        "evaluation":{
            "profile":EVALUATION_PROFILE,"organization_id":"33333333-3333-4333-8333-333333333333",
            "grant":grant,"actor":{"type":"SERVICE_ACCOUNT","id":"urn:example:agent"},
            "subject":{"type":"ORGANIZATION","id":"urn:example:subject"},
            "binding":{"method":"KEY","key_thumbprint":digest},
            "operation":{"action":"urn:example:buy","resource_id":"urn:example:item","audience":"https://shop.example","request_profile":"urn:example:order:v1","request_digest":digest},
            "approval_evidence_ref":"urn:example:approval","authority_evidence_ref":"urn:example:authority","proof_evidence_ref":"urn:example:proof",
            "challenge":"synthetic_nonce_0123456789","proof_verified_at":"2026-11-21T00:00:00Z","proof_valid_until":"2026-11-21T00:01:00Z",
            "status":{"issuer":{"type":"ORGANIZATION","id":"urn:example:authority-owner"},"grant":grant,"state":"ACTIVE","checked_at":"2026-11-21T00:00:00Z","valid_until":"2026-11-21T00:01:00Z","evidence_ref":"urn:example:status"},
            "evaluated_at":"2026-11-21T00:00:00Z"
        },
        "policy":{"id":"urn:example:policy","version_digest":digest},
        "issued_at":"2026-11-21T00:00:00Z","expires_at":"2026-11-21T00:00:30Z"
    })
}
fn encoded(header: Value, body: Value) -> Vec<u8> {
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&body).unwrap())
    )
    .into_bytes()
}
fn header() -> Value {
    json!({"alg":"ES256","typ":WIRE_FORMAT,"kid":"did:web:receipt.example#decision-1"})
}
fn input() -> Vec<u8> {
    encoded(header(), document())
}
fn binding(input: &[u8]) -> GrantBinding<'_> {
    GrantBinding {
        origin: SigningOrigin::DelegatedDecision,
        operation_id: "22222222-2222-4222-8222-222222222222",
        organization_id: "33333333-3333-4333-8333-333333333333",
        route: SIGN_ROUTE,
        service_id: None,
        issuer_did: Some("did:web:receipt.example"),
        key_reference: Some("receipt-only-key"),
        key_purpose: KEY_PURPOSE,
        algorithm: "ES256",
        payload: input,
    }
}
fn claims(binding: &GrantBinding<'_>) -> GrantClaims {
    let now = time(&json!("2026-11-21T00:00:00Z")).unwrap().timestamp();
    GrantClaims {
        version: 1,
        origin: binding.origin,
        operation_id: binding.operation_id.into(),
        organization_id: binding.organization_id.into(),
        route: binding.route.into(),
        service_id: binding.service_id.map(str::to_owned),
        issuer_did: binding.issuer_did.map(str::to_owned),
        key_reference: binding.key_reference.map(str::to_owned),
        key_purpose: binding.key_purpose.into(),
        algorithm: binding.algorithm.into(),
        payload_sha256_b64: payload_digest(binding.payload),
        issued_at: now,
        expires_at: now + 30,
        nonce: "1".repeat(32),
    }
}

#[test]
fn receipt_origin_requires_exact_closed_receipt_and_fresh_time() {
    let bytes = input();
    let request = binding(&bytes);
    let grant = claims(&request);
    assert!(bound_input(&grant, &request, grant.issued_at).is_ok());
    let parsed = ReceiptSigningInput::decode(&bytes).unwrap();
    assert!(parsed.is_live_at(time(&json!("2026-11-21T00:00:01Z")).unwrap()));
    assert!(bound_input(&grant, &request, grant.expires_at).is_err());
    assert!(bound_input(&grant, &request, grant.issued_at - 1).is_err());
    for alg in ["none", "HS256", "RS256", "ES384"] {
        let mut h = header();
        h["alg"] = json!(alg);
        assert!(ReceiptSigningInput::decode(&encoded(h, document())).is_err());
    }
    let mut h = header();
    h["jwk"] = json!({});
    assert!(ReceiptSigningInput::decode(&encoded(h, document())).is_err());
    for field in [
        "profile",
        "id",
        "issuer",
        "evaluation",
        "policy",
        "expires_at",
    ] {
        let mut d = document();
        d.as_object_mut().unwrap().remove(field);
        assert!(ReceiptSigningInput::decode(&encoded(header(), d)).is_err());
    }
    let mut d = document();
    d["bearer_permit"] = json!(true);
    assert!(ReceiptSigningInput::decode(&encoded(header(), d)).is_err());
}

#[test]
fn dedicated_origin_cannot_cross_tenant_issuer_key_payload_or_other_signing_purposes() {
    let bytes = input();
    let request = binding(&bytes);
    let grant = claims(&request);
    for origin in SigningOrigin::DEFAULT {
        let mut altered = grant.clone();
        altered.origin = origin;
        let mut actual = binding(&bytes);
        actual.origin = origin;
        assert!(bound_input(&altered, &actual, grant.issued_at).is_err());
    }
    assert!(!SigningOrigin::DEFAULT.contains(&SigningOrigin::DelegatedDecision));
    for field in 0..6 {
        let mut changed = grant.clone();
        match field {
            0 => changed.organization_id = "44444444-4444-4444-8444-444444444444".into(),
            1 => changed.issuer_did = Some("did:web:other.example".into()),
            2 => changed.key_reference = Some("other-key".into()),
            3 => changed.payload_sha256_b64 = payload_digest(b"other-payload"),
            4 => changed.key_purpose = "vc_jwt_issuer".into(),
            _ => changed.route = "/v1/signing-keys/services/receipt-service/sign".into(),
        }
        assert!(bound_input(&changed, &request, grant.issued_at).is_err());
    }
    // Even a matching freshly authenticated grant cannot sign a receipt whose
    // embedded tenant/issuer/operation is a replacement for the grant binding.
    for (path, value) in [
        (
            "/evaluation/organization_id",
            json!("44444444-4444-4444-8444-444444444444"),
        ),
        ("/issuer/id", json!("did:web:other.example")),
        ("/id", json!("44444444-4444-4444-8444-444444444444")),
    ] {
        let mut d = document();
        *d.pointer_mut(path).unwrap() = value;
        let bytes = encoded(header(), d);
        let request = binding(&bytes);
        let grant = claims(&request);
        assert!(bound_input(&grant, &request, grant.issued_at).is_err());
    }
}

#[test]
fn purpose_guard_rejects_duplicate_malformed_or_inconsistent_transcripts() {
    let body = serde_json::to_string(&document()).unwrap();
    for modified in [
        body.replacen("\"profile\":", "\"profile\":\"other\",\"profile\":", 1),
        body.replacen("\"revision\":2", "\"revision\":2.0", 1),
        body.replacen("\"revision\":2", "\"revision\":9007199254740992", 1),
    ] {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header()).unwrap()),
            URL_SAFE_NO_PAD.encode(modified)
        );
        assert!(ReceiptSigningInput::decode(input.as_bytes()).is_err());
    }
    for (path, value) in [
        ("/evaluation/status/state", json!("REVOKED")),
        ("/evaluation/status/grant/revision", json!(3)),
        (
            "/evaluation/proof_valid_until",
            json!("2026-11-21T00:00:01Z"),
        ),
        (
            "/evaluation/proof_verified_at",
            json!("2026-11-21T00:00:01Z"),
        ),
        ("/evaluation/binding/key_thumbprint", Value::Null),
        ("/evaluation/challenge", json!("short")),
    ] {
        let mut d = document();
        *d.pointer_mut(path).unwrap() = value;
        assert!(ReceiptSigningInput::decode(&encoded(header(), d)).is_err());
    }
    let mut denial = document();
    denial["decision"] = json!("DENY");
    denial["evaluation"]["status"]["state"] = json!("REVOKED");
    assert!(ReceiptSigningInput::decode(&encoded(header(), denial)).is_ok());
    let mut d = document();
    d["evaluation"]["domain_evidence"] = json!({"evaluator":{"type":"EXTERNAL","id":"urn:domain:evaluator"},"profile":"urn:domain:constraints:v1","document_digest":format!("sha256:{}","1".repeat(64)),"grant":d["evaluation"]["grant"],"operation":d["evaluation"]["operation"],"decision":"PERMIT","checked_at":"2026-11-21T00:00:00Z","valid_until":"2026-11-21T00:01:00Z","evidence_ref":"urn:domain:evidence"});
    assert!(ReceiptSigningInput::decode(&encoded(header(), d.clone())).is_ok());
    d["evaluation"]["domain_evidence"]["operation"]["audience"] = json!("https://other.example");
    assert!(ReceiptSigningInput::decode(&encoded(header(), d)).is_err());
}
