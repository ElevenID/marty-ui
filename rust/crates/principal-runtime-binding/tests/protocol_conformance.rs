use std::path::Path;

use marty_principal_runtime_binding::{
    jwk_sha256_thumbprint, jwk_thumbprint_to_digest, parse_binding_record, parse_configuration,
    parse_machine_snapshot, parse_session_evidence, parse_thumbprint, validate_binding,
    BindingError, ErrorKind, HashBasis, KeyAlgorithm, PrincipalType, RuntimeKind,
    ThumbprintEncoding, TrustedBindingInputs, ValidatedPrincipalBinding, MAX_DOCUMENT_BYTES,
    PROTOCOL_REVISION,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const ORG: &str = "0b9eb29f-0d08-4a1c-acc3-cb68b198b5a4";
const OTHER_ORG: &str = "cff9c8ac-3f8b-4a2f-a16e-d97a1be74f89";
const JKT: &str = "_bBTskCmkgQOietWpQwXEeGWMTrlyq-7xhNizo9epuc";
const HEX: &str = "sha256:fdb053b240a692040e89eb56a50c1711e196313ae5caafbbc61362ce8f5ea6e7";
const P256_JKT: &str = "b1PMhKP50BAJQhrPxRh6q-nf0ozLfPut_OZIywKSmFY";
const EXTERNAL: &str = include_str!("fixtures/external-service-account.json");
const MANAGED: &str = include_str!("fixtures/managed-service-with-rotating-candidate.json");
const SHARED: &str = include_str!("fixtures/shared-runtime-session.json");
const PUBLIC_KEYS: &str = include_str!("fixtures/public-keys.json");

fn value(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap()
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn check_in(
    fixture: &Value,
    organization: &str,
) -> Result<ValidatedPrincipalBinding, BindingError> {
    let record = parse_binding_record(&bytes(&fixture["record"]))?;
    let configuration = parse_configuration(&bytes(&fixture["configuration"]))?;
    let machine = fixture
        .get("machine_identity")
        .map(|machine| parse_machine_snapshot(&bytes(machine)))
        .transpose()?;
    let session = fixture
        .get("expected_session")
        .map(|session| parse_session_evidence(&bytes(session)))
        .transpose()?;
    let mut inputs = TrustedBindingInputs::new(organization, &configuration)?;
    if let Some(machine) = &machine {
        inputs = inputs.with_machine(machine);
    }
    if let Some(session) = &session {
        inputs = inputs.with_session(session);
    }
    validate_binding(&record, inputs)
}

fn check(fixture: &Value) -> Result<ValidatedPrincipalBinding, BindingError> {
    check_in(fixture, ORG)
}

fn rejects(fixture: &Value, kind: ErrorKind) {
    assert_eq!(check(fixture).unwrap_err().kind(), kind);
}

fn p256_jwk() -> Value {
    value(PUBLIC_KEYS)["keys"]["rotation_candidate"]["jwk"].clone()
}

#[test]
fn synthetic_fixture_provenance_is_exact_and_not_runtime_qualification() {
    let provenance = value(include_str!("fixtures/provenance.json"));
    assert_eq!(provenance["origin"], "APPLICATION_AUTHORED");
    assert_eq!(
        provenance["compatibility_target_revision"],
        PROTOCOL_REVISION
    );
    assert_eq!(provenance["status"], "APPLICATION_TEST_ONLY");
    assert_eq!(provenance["runtime_qualification"], "NOT_ASSESSED");
    for (name, source) in [
        ("external-service-account.json", EXTERNAL),
        ("managed-service-with-rotating-candidate.json", MANAGED),
        ("shared-runtime-session.json", SHARED),
        ("public-keys.json", PUBLIC_KEYS),
    ] {
        assert_eq!(
            provenance["files"][name]["sha256"],
            format!("{:x}", Sha256::digest(source))
        );
    }
}

#[test]
fn valid_external_managed_and_shared_bindings_preserve_distinct_contexts() {
    let external = check(&value(EXTERNAL)).unwrap();
    assert_eq!(external.organization_id(), ORG);
    assert_eq!(external.principal_type(), PrincipalType::ServiceAccount);
    assert_eq!(external.runtime_kind(), RuntimeKind::External);
    assert_eq!(external.machine_identity_id(), None);
    assert_eq!(external.session_ref(), None);
    assert_eq!(
        external
            .key_thumbprint()
            .delegation_key_thumbprint()
            .unwrap(),
        HEX
    );
    let managed = check(&value(MANAGED)).unwrap();
    assert_eq!(managed.runtime_kind(), RuntimeKind::Managed);
    assert!(managed.machine_identity_id().is_some());
    let shared = check(&value(SHARED)).unwrap();
    assert_eq!(shared.represented_subject_type(), Some("USER"));
    assert_eq!(
        shared.represented_subject_id(),
        Some("urn:application-test:pairwise:case-owner-juniper")
    );
    assert_ne!(
        shared.principal_id(),
        shared.represented_subject_id().unwrap()
    );
}

#[test]
fn separately_authorized_tenant_cannot_be_replaced_by_matching_request_and_configuration() {
    assert_eq!(
        check_in(&value(EXTERNAL), OTHER_ORG).unwrap_err().kind(),
        ErrorKind::TenantMismatch
    );
    let mut fixture = value(EXTERNAL);
    fixture["record"]["organization_id"] = json!(OTHER_ORG);
    rejects(&fixture, ErrorKind::TenantMismatch);
}

#[test]
fn exact_principal_type_issuer_subject_audience_and_runtime_are_required() {
    for (pointer, replacement, kind) in [
        (
            "/record/principal/type",
            "EXTERNAL",
            ErrorKind::PrincipalMismatch,
        ),
        (
            "/record/principal/id",
            "urn:example:service:other",
            ErrorKind::PrincipalMismatch,
        ),
        (
            "/record/authentication/issuer",
            "https://LOGIN.application-tests.invalid/workloads",
            ErrorKind::SourceIdentityMismatch,
        ),
        (
            "/record/authentication/subject",
            "other-subject",
            ErrorKind::SourceIdentityMismatch,
        ),
        (
            "/record/authentication/audience",
            "https://resource.example.invalid/other",
            ErrorKind::AudienceMismatch,
        ),
        (
            "/record/runtime/instance_ref",
            "urn:example:runtime:other",
            ErrorKind::RuntimeMismatch,
        ),
    ] {
        let mut fixture = value(EXTERNAL);
        *fixture.pointer_mut(pointer).unwrap() = json!(replacement);
        rejects(&fixture, kind);
    }
}

#[test]
fn managed_machine_id_tenant_and_principal_are_independently_bound() {
    let mut fixture = value(MANAGED);
    fixture["machine_identity"]["organization_id"] = json!(OTHER_ORG);
    rejects(&fixture, ErrorKind::MachineIdentityMismatch);
    fixture = value(MANAGED);
    let machine_principal = fixture["machine_identity"]["machine_id"].clone();
    for section in ["record", "configuration"] {
        fixture[section]["principal"] = json!({"type":"MACHINE_IDENTITY","id":machine_principal});
    }
    assert_eq!(
        check(&fixture).unwrap().principal_type(),
        PrincipalType::MachineIdentity
    );
    fixture["machine_identity"]["machine_id"] = json!("urn:example:machine:other");
    rejects(&fixture, ErrorKind::MachinePrincipalMismatch);
}

#[test]
fn external_actor_cannot_smuggle_a_managed_machine_or_claim_machine_principal() {
    let mut fixture = value(EXTERNAL);
    fixture["machine_identity"] = value(MANAGED)["machine_identity"].clone();
    rejects(&fixture, ErrorKind::ExternalMachineEnrollment);
    fixture = value(EXTERNAL);
    fixture["record"]["principal"]["type"] = json!("MACHINE_IDENTITY");
    rejects(&fixture, ErrorKind::SchemaInvalid);
    fixture = value(EXTERNAL);
    fixture["record"]["runtime"]["machine_identity_id"] =
        value(MANAGED)["machine_identity"]["id"].clone();
    rejects(&fixture, ErrorKind::SchemaInvalid);
}

#[test]
fn exactly_one_active_key_and_current_active_machine_are_required() {
    let mut fixture = value(MANAGED);
    fixture["machine_identity"]["identity_keys"][1]["status"] = json!("ACTIVE");
    rejects(&fixture, ErrorKind::SchemaInvalid);
    fixture["machine_identity"]["identity_keys"][0]["status"] = json!("REVOKED");
    rejects(&fixture, ErrorKind::ActiveKeyMismatch);
    fixture = value(MANAGED);
    fixture["machine_identity"]["status"] = json!("SUSPENDED");
    rejects(&fixture, ErrorKind::InactiveMachine);
    fixture = value(MANAGED);
    fixture.as_object_mut().unwrap().remove("machine_identity");
    rejects(&fixture, ErrorKind::MissingMachineState);
}

#[test]
fn rotation_candidate_cannot_authenticate_and_active_algorithm_cannot_be_relabelled() {
    let mut fixture = value(MANAGED);
    fixture["configuration"]["runtime"]["active_key_id"] =
        fixture["machine_identity"]["identity_keys"][1]["key_id"].clone();
    rejects(&fixture, ErrorKind::ActiveKeyMismatch);
    fixture = value(MANAGED);
    fixture["machine_identity"]["identity_keys"][0]["algorithm"] = json!("RS256");
    rejects(&fixture, ErrorKind::ActiveKeyAlgorithmMismatch);
    fixture = value(MANAGED);
    fixture["machine_identity"]["identity_keys"][0]["public_key_jwk"] = p256_jwk();
    rejects(&fixture, ErrorKind::ActiveKeyAlgorithmMismatch);
}

#[test]
fn selected_algorithm_is_exact_even_when_machine_ed25519_labels_are_compatible() {
    let mut fixture = value(MANAGED);
    fixture["machine_identity"]["identity_keys"][0]["algorithm"] = json!("Ed25519");
    let _ = check(&fixture).unwrap();
    fixture["record"]["authentication"]["key_algorithm"] = json!("Ed25519");
    rejects(&fixture, ErrorKind::SelectedAlgorithmMismatch);
    fixture["configuration"]["expected_key_algorithm"] = json!("Ed25519");
    assert_eq!(
        check(&fixture).unwrap().key_algorithm(),
        KeyAlgorithm::Ed25519
    );
}

#[test]
fn explicit_deployment_assignment_must_match_and_absence_adds_no_assurance() {
    let mut fixture = value(MANAGED);
    fixture["machine_identity"]["assignments"]["deployment_profile_id"] = json!(OTHER_ORG);
    rejects(&fixture, ErrorKind::DeploymentAssignmentMismatch);
    for assignments in [json!({}), json!({"deployment_profile_id":null})] {
        fixture["machine_identity"]["assignments"] = assignments;
        let _ = check(&fixture).unwrap();
    }
}

#[test]
fn private_jwk_is_rejected_even_for_certificate_fingerprint_basis() {
    let mut fixture = value(MANAGED);
    for section in ["record", "configuration"] {
        let thumbprint = if section == "record" {
            &mut fixture[section]["authentication"]["key_thumbprint"]
        } else {
            &mut fixture[section]["expected_key_thumbprint"]
        };
        thumbprint["basis"] = json!("X509_CERTIFICATE_DER_SHA256");
    }
    // A configured certificate basis is not proof that the underlying
    // certificate is trusted or corresponds to this JWK; the adapter proves it.
    let _ = check(&fixture).unwrap();
    fixture["machine_identity"]["identity_keys"][0]["public_key_jwk"]["d"] =
        json!("synthetic-invalid-private-member");
    rejects(&fixture, ErrorKind::PrivateKeyMaterial);
}

#[test]
fn current_key_content_and_stored_encoding_are_not_inferred() {
    let mut fixture = value(MANAGED);
    fixture["machine_identity"]["identity_keys"][0]["public_key_jwk"]["x"] =
        value(PUBLIC_KEYS)["keys"]["external_worker"]["jwk"]["x"].clone();
    rejects(&fixture, ErrorKind::RegisteredKeyMismatch);
    fixture = value(MANAGED);
    fixture["configuration"]["runtime"]["stored_thumbprint_encoding"] = json!("MIP_SHA256_HEX");
    rejects(&fixture, ErrorKind::NonCanonicalEncoding);
}

#[test]
fn subject_sessions_require_independent_evidence_even_for_nonshared_runtime() {
    let mut fixture = value(SHARED);
    fixture.as_object_mut().unwrap().remove("expected_session");
    rejects(&fixture, ErrorKind::MissingSubjectSession);
    fixture["configuration"]["shared_runtime"] = json!(false);
    rejects(&fixture, ErrorKind::SessionBindingMismatch);
    fixture = value(SHARED);
    fixture["record"]
        .as_object_mut()
        .unwrap()
        .remove("session_binding");
    rejects(&fixture, ErrorKind::MissingSubjectSession);
}

#[test]
fn customer_and_establishment_evidence_cannot_be_substituted() {
    for pointer in [
        "/record/session_binding/represented_subject/id",
        "/record/session_binding/session_ref",
        "/record/session_binding/establishment_evidence_ref",
    ] {
        let mut fixture = value(SHARED);
        *fixture.pointer_mut(pointer).unwrap() = json!("urn:example:other");
        rejects(&fixture, ErrorKind::SessionBindingMismatch);
    }
}

#[test]
fn old_session_cannot_move_to_reconfigured_runtime_actor_or_key() {
    for field in ["runtime", "actor", "key"] {
        let mut fixture = value(SHARED);
        match field {
            "runtime" => {
                fixture["record"]["runtime"]["instance_ref"] =
                    json!("urn:example:runtime:replacement");
                fixture["configuration"]["runtime"]["instance_ref"] =
                    json!("urn:example:runtime:replacement");
            }
            "actor" => {
                fixture["record"]["principal"]["id"] = json!("urn:example:actor:replacement");
                fixture["configuration"]["principal"]["id"] =
                    json!("urn:example:actor:replacement");
            }
            _ => {
                fixture["record"]["authentication"]["key_thumbprint"]["value"] = json!(P256_JKT);
                fixture["configuration"]["expected_key_thumbprint"]["value"] = json!(P256_JKT);
                fixture["record"]["authentication"]["key_algorithm"] = json!("ES256");
                fixture["configuration"]["expected_key_algorithm"] = json!("ES256");
            }
        }
        rejects(&fixture, ErrorKind::SessionRuntimeMismatch);
    }
}

#[test]
fn agent_definition_and_run_do_not_supply_identity_or_authority() {
    let mut fixture = value(EXTERNAL);
    fixture["record"]["agent_definition_ref"] = json!("urn:example:agent:other");
    fixture["record"]["run_ref"] = json!("urn:example:run:other");
    assert_eq!(
        check(&fixture).unwrap().principal_id(),
        "urn:application-test:service:inventory-reader"
    );
    fixture["record"]["authentication"]["subject"] = json!("other");
    rejects(&fixture, ErrorKind::SourceIdentityMismatch);
}

#[test]
fn time_shapes_are_validated_without_claiming_live_freshness_or_possession() {
    let mut fixture = value(MANAGED);
    fixture["machine_identity"]["identity_keys"][0]["valid_until"] = json!("not-a-time");
    rejects(&fixture, ErrorKind::SchemaInvalid);
    fixture["machine_identity"]["identity_keys"][0]["valid_until"] = json!("2000-01-01T00:00:00Z");
    // Deliberately matches the protocol's offline consistency model: runtime
    // validity, attestation and current authoritative status remain required.
    let _ = check(&fixture).unwrap();
    fixture["record"]["authentication"]["fresh"] = json!(true);
    rejects(&fixture, ErrorKind::SchemaInvalid);
}

#[test]
fn unsupported_version_null_unknown_fields_and_type_confusion_fail_closed() {
    for (pointer, replacement) in [
        (
            "/record/profile",
            json!("urn:marty:principal-runtime-binding:v2"),
        ),
        ("/record/organization_id", json!(true)),
        ("/record/authentication/key_algorithm", json!(true)),
        ("/configuration/shared_runtime", json!(1)),
        ("/configuration/shared_runtime", json!(null)),
    ] {
        let mut fixture = value(EXTERNAL);
        *fixture.pointer_mut(pointer).unwrap() = replacement;
        rejects(&fixture, ErrorKind::SchemaInvalid);
    }
    for (field, replacement) in [
        ("session_binding", Value::Null),
        ("agent_definition_ref", Value::Null),
        ("x-workload-identity", json!("spiffe://untrusted/agent")),
    ] {
        let mut fixture = value(EXTERNAL);
        fixture["record"][field] = replacement;
        rejects(&fixture, ErrorKind::SchemaInvalid);
    }
}

#[test]
fn duplicate_fields_and_bounded_strict_json_are_rejected_before_projection() {
    for raw in [
        br#"{"organization_id":"first","organization_id":"second"}"#.as_slice(),
        br#"{"outer":{"issuer":"first","issuer":"second"}}"#.as_slice(),
    ] {
        assert_eq!(
            parse_binding_record(raw).unwrap_err().kind(),
            ErrorKind::DuplicateJsonField
        );
    }
    for raw in [
        b"[]".as_slice(),
        b"null",
        br#"{"x":NaN}"#,
        br#"{"x":1.0}"#,
        br#"{"x":1e999}"#,
        br#"{"x":"\ud800"}"#,
        b"\xff",
        b"{} trailing",
    ] {
        assert_eq!(
            parse_binding_record(raw).unwrap_err().kind(),
            ErrorKind::InvalidJson
        );
    }
    assert_eq!(
        parse_binding_record(&vec![b' '; MAX_DOCUMENT_BYTES + 1])
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidJson
    );
    let nested = format!("{{\"nested\":{}0{}}}", "[".repeat(40), "]".repeat(40));
    assert_eq!(
        parse_binding_record(nested.as_bytes()).unwrap_err().kind(),
        ErrorKind::InvalidJson
    );
}

#[test]
fn canonical_base64_and_hex_conversion_preserves_digest_bytes_and_basis() {
    assert_eq!(jwk_thumbprint_to_digest(JKT).unwrap(), HEX);
    let key = parse_thumbprint(&bytes(
        &json!({"basis":"JWK_RFC7638_SHA256","encoding":"BASE64URL_SHA256","value":JKT}),
    ))
    .unwrap();
    for encoding in [
        ThumbprintEncoding::Base64urlSha256,
        ThumbprintEncoding::MipSha256Hex,
        ThumbprintEncoding::MipSha256Base64url,
    ] {
        let converted = key.reencode(encoding);
        assert!(key.same_binding(&converted));
        assert_eq!(converted.digest_bytes(), key.digest_bytes());
        assert_eq!(converted.basis(), HashBasis::JwkRfc7638Sha256);
    }
    let certificate = parse_thumbprint(&bytes(
        &json!({"basis":"X509_CERTIFICATE_DER_SHA256","encoding":"MIP_SHA256_HEX","value":HEX}),
    ))
    .unwrap();
    assert!(!key.same_binding(&certificate));
    assert_eq!(
        certificate.delegation_key_thumbprint().unwrap_err().kind(),
        ErrorKind::WrongHashBasis
    );
}

#[test]
fn padded_noncanonical_base64_pad_bits_wrong_lengths_and_uppercase_hex_are_rejected() {
    for malformed in [
        format!("{JKT}="),
        format!(" {JKT}"),
        format!("{JKT}\n"),
        JKT[..42].to_owned(),
        format!("{}l", &JKT[..42]),
        "A".repeat(44),
    ] {
        assert_eq!(
            jwk_thumbprint_to_digest(&malformed).unwrap_err().kind(),
            ErrorKind::NonCanonicalEncoding
        );
    }
    for malformed in [
        HEX.to_uppercase(),
        HEX[7..].to_owned(),
        format!("sha256:{}", "g".repeat(64)),
    ] {
        assert_eq!(
            parse_thumbprint(&bytes(
                &json!({"basis":"JWK_RFC7638_SHA256","encoding":"MIP_SHA256_HEX","value":malformed})
            ))
            .unwrap_err()
            .kind(),
            ErrorKind::NonCanonicalEncoding
        );
    }
}

#[test]
fn locally_generated_public_keys_use_only_the_rfc7638_public_projection() {
    let public_keys = value(PUBLIC_KEYS);
    for (name, algorithm) in [
        ("external_worker", "EdDSA"),
        ("managed_worker", "EdDSA"),
        ("support_session", "EdDSA"),
        ("rotation_candidate", "ES256"),
    ] {
        let vector = &public_keys["keys"][name];
        let mut jwk = vector["jwk"].clone();
        let expected = vector["rfc7638_sha256_base64url"].as_str().unwrap();
        assert_eq!(
            jwk_sha256_thumbprint(&bytes(&jwk)).unwrap().encoded_value(),
            expected
        );
        assert_eq!(
            jwk_thumbprint_to_digest(expected).unwrap(),
            vector["rfc7638_sha256_hex"].as_str().unwrap()
        );
        for (field, content) in [
            ("kid", json!("synthetic")),
            ("use", json!("sig")),
            ("alg", json!(algorithm)),
            ("key_ops", json!(["verify"])),
        ] {
            jwk[field] = content;
        }
        assert_eq!(
            jwk_sha256_thumbprint(&bytes(&jwk)).unwrap().encoded_value(),
            expected
        );
    }
}

#[test]
fn private_unknown_algorithm_confused_and_invalid_curve_keys_are_rejected() {
    for (field, replacement) in [
        ("d", json!("synthetic")),
        ("alg", json!("HS256")),
        ("alg", json!([])),
        ("key_ops", json!(["sign"])),
        ("use", json!("enc")),
        ("jku", json!("https://untrusted.invalid")),
        ("x", json!(false)),
    ] {
        let mut jwk = p256_jwk();
        jwk[field] = replacement;
        assert!(jwk_sha256_thumbprint(&bytes(&jwk)).is_err());
    }
    let mut jwk = p256_jwk();
    jwk["x"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    jwk["y"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert_eq!(
        jwk_sha256_thumbprint(&bytes(&jwk)).unwrap_err().kind(),
        ErrorKind::InvalidPublicKey
    );
}

#[test]
fn errors_and_debug_output_do_not_disclose_identity_key_or_session_values() {
    let fixture = value(SHARED);
    let record = parse_binding_record(&bytes(&fixture["record"])).unwrap();
    let result = check(&fixture).unwrap();
    let error = check_in(&fixture, OTHER_ORG).unwrap_err();
    let output = format!(
        "{record:?} {result:?} {:?} {error:?} {error}",
        result.key_thumbprint()
    );
    for private in [
        ORG,
        fixture["record"]["authentication"]["key_thumbprint"]["value"]
            .as_str()
            .unwrap(),
        "case-owner-juniper",
        "support-assistant",
        "session-establishment-558",
        "login.application-tests.invalid",
    ] {
        assert!(!output.contains(private));
    }
}

/// Explicit extra gate; no private repository snapshot is bundled here.
/// Run with MARTY_PRINCIPAL_BINDING_PROTOCOL_ROOT set to the verified pinned
/// source checkout. Root's source-consumer lock verifies revision provenance.
#[test]
#[ignore = "requires independently verified pinned protocol checkout; see docs/principal-runtime-binding.md"]
fn complete_pinned_protocol_binding_corpus() {
    let root =
        std::env::var("MARTY_PRINCIPAL_BINDING_PROTOCOL_ROOT").expect("set pinned protocol root");
    let corpus = Path::new(&root).join("conformance/principal-runtime-binding/v1");
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(corpus.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(
        manifest["profile"],
        marty_principal_runtime_binding::PROFILE
    );
    assert_eq!(manifest["status"], "REFERENCE_ONLY_NOT_RUNTIME_QUALIFIED");
    for path in manifest["valid"].as_array().unwrap() {
        let path = path.as_str().unwrap();
        let fixture: Value =
            serde_json::from_slice(&std::fs::read(corpus.join(path)).unwrap()).unwrap();
        // The independently obtained fixture's configuration supplies the test
        // tenant. Application examples above use a separate, locally authored
        // tenant and do not embed the private corpus's identity values.
        let organization = fixture["configuration"]["organization_id"]
            .as_str()
            .unwrap();
        assert!(
            check_in(&fixture, organization).is_ok(),
            "valid protocol vector {path}"
        );
    }
    for path in manifest["invalid"].as_array().unwrap() {
        let path = path.as_str().unwrap();
        let fixture: Value =
            serde_json::from_slice(&std::fs::read(corpus.join(path)).unwrap()).unwrap();
        let expected: Value = serde_json::from_slice(
            &std::fs::read(corpus.join(path).with_extension("expected.json")).unwrap(),
        )
        .unwrap();
        let organization = fixture["configuration"]["organization_id"]
            .as_str()
            .unwrap();
        assert_eq!(
            check_in(&fixture, organization).unwrap_err().code(),
            expected["error_type"].as_str().unwrap(),
            "invalid protocol vector {path}"
        );
    }
}
