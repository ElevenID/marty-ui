use std::{
    io::Write,
    process::{Command, Stdio},
};

use marty_release_evidence::signing_capability::{
    prepare_signing_capability, verify_signing_capability, SigningCapabilityInput, SCHEMA,
};
use serde_json::{json, Value};

fn vectors() -> Vec<Value> {
    // Generated public-only P-256 vectors. The disposable signing key is not
    // retained, and these fixtures are not live service or deployment evidence.
    serde_json::from_str::<Value>(include_str!("fixtures/signing-capability-es256.json")).unwrap()
        ["vectors"]
        .as_array()
        .unwrap()
        .clone()
}

fn input(value: &Value) -> SigningCapabilityInput {
    serde_json::from_value(value.clone()).unwrap()
}

#[test]
fn verifies_real_es256_bytes_for_both_exact_native_issuer_purposes() {
    for vector in vectors() {
        let receipt = verify_signing_capability(&input(&vector)).unwrap();
        assert_eq!(receipt["verified"], true);
        assert_eq!(receipt["key_purpose"], vector["expected"]["key_purpose"]);
        assert_eq!(
            receipt["scope"],
            "EXACT_PUBLIC_SERVICE_SIGNING_CAPABILITY_ONLY"
        );
        assert!(receipt.get("key_reference").is_none());
        assert!(receipt.get("releaseReady").is_none());
    }
}

#[test]
fn active_identity_and_service_without_an_actual_signature_are_insufficient() {
    let mut vector = vectors().remove(0);
    vector["signing_response"] = Value::Null;
    assert!(prepare_signing_capability(&input(&vector)).is_ok());
    assert!(verify_signing_capability(&input(&vector)).is_err());
    vector["signing_response"] = json!({"status": 200, "body": {"ok": true}});
    assert!(verify_signing_capability(&input(&vector)).is_err());
}

#[test]
fn refuses_substituted_org_service_key_and_identity_before_a_signing_request() {
    for (pointer, replacement) in [
        (
            "/expected/organization_id",
            json!("00000000-0000-0000-0000-000000000002"),
        ),
        ("/expected/service_id", json!("different-service")),
        ("/expected/key_reference", json!("different-key")),
        (
            "/expected/issuer_did",
            json!("did:web:other.unit.invalid:issuer"),
        ),
        ("/expected/key_purpose", json!("oid4vp_request_signing")),
        ("/expected/algorithm", json!("ES384")),
        ("/service_response/status", json!(503)),
        ("/service_response/body/service/status", json!("disabled")),
        (
            "/service_response/body/resolved_by/key_purpose",
            json!("unrelated"),
        ),
        ("/identity_response/status", json!(409)),
        ("/identity_response/body/identity/status", json!("retired")),
        (
            "/identity_response/body/identity/credential_format",
            json!("JWT_VC_JSON"),
        ),
        (
            "/identity_response/body/managed_key_binding_sha256",
            json!("0".repeat(64)),
        ),
    ] {
        let mut vector = vectors().remove(0);
        *vector.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            prepare_signing_capability(&input(&vector)).is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn rejects_replayed_challenges_and_wrong_signatures_or_response_metadata() {
    for (pointer, replacement) in [
        ("/expected/run_id", json!("another-run")),
        ("/expected/nonce", json!("a".repeat(64))),
        ("/signing_response/status", json!(403)),
        ("/signing_response/body/ok", json!(false)),
        ("/signing_response/body/service_id", json!("other-service")),
        ("/signing_response/body/algorithm", json!("ES384")),
        ("/signing_response/body/payload_length", json!(1)),
        ("/signing_response/body/signature_b64", json!("invalid")),
        ("/signing_response/body/signature_hex", json!("00")),
    ] {
        let mut vector = vectors().remove(0);
        *vector.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            verify_signing_capability(&input(&vector)).is_err(),
            "{pointer}"
        );
    }
    let mut vector = vectors().remove(0);
    vector["signing_response"]["body"]["signature_raw_b64"] = json!("not-the-same-signature");
    assert!(verify_signing_capability(&input(&vector)).is_err());
    let mut vector = vectors().remove(0);
    vector["signing_response"]["body"]["signature_raw_hex"] = json!("00");
    assert!(verify_signing_capability(&input(&vector)).is_err());
}

#[test]
fn refuses_private_or_incompatible_public_key_material() {
    for (field, value) in [
        ("d", json!("synthetic-private-field")),
        ("kty", json!("RSA")),
        ("crv", json!("P-384")),
        ("x", json!("AA")),
        ("alg", json!("ES384")),
        ("use", json!("enc")),
        ("key_ops", json!(["encrypt"])),
        ("kid", json!("custody-selector")),
        ("auth_reference", json!("synthetic-provider-token")),
    ] {
        let mut vector = vectors().remove(0);
        vector["identity_response"]["body"]["public_jwk"][field] = value;
        assert!(
            prepare_signing_capability(&input(&vector)).is_err(),
            "{field}"
        );
    }
    let mut vector = vectors().remove(0);
    vector["service_response"]["body"]["service"]["auth_reference"] =
        json!("synthetic-provider-token");
    assert!(prepare_signing_capability(&input(&vector)).is_err());
}

#[test]
fn cli_has_bounded_stdin_and_emits_only_the_verified_contract() {
    let executable = env!("CARGO_BIN_EXE_validate-signing-capability");
    let version = Command::new(executable).arg("--version").output().unwrap();
    assert_eq!(String::from_utf8(version.stdout).unwrap().trim(), SCHEMA);
    let mut child = Command::new(executable)
        .arg("verify")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&vectors()[0]).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["verified"],
        true
    );
    let mut child = Command::new(executable)
        .arg("verify")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child
        .stdin
        .take()
        .unwrap()
        .write_all(&vec![b' '; 65 * 1024]);
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}
