use super::*;
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, SanType};

fn certificate(key: &KeyPair, subject: &str, uri: &str, day: u8) -> Vec<u8> {
    let mut params = CertificateParams::new(vec![NATIVE_CALLER.common_name.into()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, subject);
    params
        .subject_alt_names
        .push(SanType::URI(uri.try_into().unwrap()));
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.not_before = rcgen::date_time_ymd(2026, 1, day);
    params.not_after = params.not_before + std::time::Duration::from_secs(28_800);
    params.self_signed(key).unwrap().pem().into_bytes()
}

fn fixture() -> (KeyPair, Vec<u8>, Vec<u8>) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let old = certificate(&key, NATIVE_CALLER.common_name, NATIVE_CALLER.uri, 1);
    let new = certificate(&key, NATIVE_CALLER.common_name, NATIVE_CALLER.uri, 2);
    (key, old, new)
}

fn pin(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        digest(&Certificate::from_pem(bytes).unwrap().to_der().unwrap())
    )
}

fn binding(uri: &str, pin: &str) -> String {
    format!(
        r#"{{ "workload_uri": "{uri}", "leaf_sha256": "{pin}", "principal_id": "urn:agent:already-owned" }}"#
    )
}

#[test]
fn same_owned_key_renews_only_the_existing_native_leaf_token() {
    let (_key, old, new) = fixture();
    let old_pin = pin(&old);
    let new_pin = pin(&new);
    // The old pin also appears inside an unrelated principal string. A global
    // string replacement would incorrectly rewrite that owner's other binding.
    let external = format!(
        r#"{{"principal_id":"urn:external:{old_pin}","leaf_sha256":"sha256:{}","workload_uri":"spiffe://example.test/external"}}"#,
        "a".repeat(64)
    );
    let original = format!(
        "[\n  {},\n\t{external}  \n]\n",
        binding(NATIVE_CALLER.uri, &old_pin)
    );
    let (updated, receipt) = rotate(original.as_bytes(), &old, &new).unwrap();
    assert_eq!(
        updated,
        original
            .replacen(&format!("\"{old_pin}\""), &format!("\"{new_pin}\""), 1)
            .as_bytes()
    );
    assert!(std::str::from_utf8(&updated).unwrap().contains(&external));
    let receipt = receipt.unwrap();
    assert_eq!(receipt.workload_uri, NATIVE_CALLER.uri);
    assert_eq!(receipt.principal_id, "urn:agent:already-owned");
    assert_eq!(receipt.previous_leaf_sha256, old_pin);
    assert_eq!(receipt.renewed_leaf_sha256, new_pin);
    assert_eq!(
        receipt.previous_bindings_sha256,
        digest(original.as_bytes())
    );
    assert_eq!(receipt.renewed_bindings_sha256, digest(&updated));
    assert_eq!(
        rotate(original.as_bytes(), &old, &new).unwrap().1,
        Some(receipt)
    );
}

#[test]
fn absent_native_owner_binding_and_identical_leaf_preserve_every_byte() {
    let (_key, old, new) = fixture();
    let external = format!(
        " [ {} ] \n",
        binding(
            "spiffe://example.test/external",
            &format!("sha256:{}", "a".repeat(64))
        )
    );
    assert_eq!(
        rotate(external.as_bytes(), &old, &new).unwrap(),
        (external.into_bytes(), None)
    );
    let same = format!("[{}]", binding(NATIVE_CALLER.uri, &pin(&old)));
    assert_eq!(
        rotate(same.as_bytes(), &old, &old).unwrap(),
        (same.into_bytes(), None)
    );
}

#[test]
fn changed_key_identity_or_unowned_mapping_cannot_acquire_a_new_pin() {
    let (key, old, new) = fixture();
    let original = format!("[{}]", binding(NATIVE_CALLER.uri, &pin(&old)));
    let other = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    for leaf in [
        certificate(&other, NATIVE_CALLER.common_name, NATIVE_CALLER.uri, 2),
        certificate(&key, "other", NATIVE_CALLER.uri, 2),
        certificate(
            &key,
            NATIVE_CALLER.common_name,
            "spiffe://example.test/other",
            2,
        ),
    ] {
        assert!(rotate(original.as_bytes(), &old, &leaf).is_err());
    }
    for original in [
        format!(
            "[{}]",
            binding(NATIVE_CALLER.uri, &format!("sha256:{}", "a".repeat(64)))
        ),
        format!(
            "[{}]",
            binding("spiffe://example.test/external", &pin(&old))
        ),
        format!(
            "[{}]",
            binding("spiffe://example.test/external", &pin(&new))
        ),
        format!(
            "[{},{}]",
            binding(NATIVE_CALLER.uri, &pin(&old)),
            binding(NATIVE_CALLER.uri, &pin(&old))
        ),
    ] {
        assert!(rotate(original.as_bytes(), &old, &new).is_err());
    }
}

#[test]
fn duplicate_unknown_or_missing_binding_fields_are_refused() {
    let (_key, old, new) = fixture();
    let valid = binding(NATIVE_CALLER.uri, &pin(&old));
    for value in [
        format!("[{},{{}}]", valid),
        format!(
            "[{}]",
            valid.replace("\"principal_id\":", "\"extra\":true,\"principal_id\":")
        ),
        format!(
            "[{}]",
            valid.replace(
                "\"principal_id\":",
                "\"principal_id\":\"urn:injected\",\"principal_id\":"
            )
        ),
        "[]".into(),
        format!("[{valid}] {{}}"),
    ] {
        assert!(rotate(value.as_bytes(), &old, &new).is_err());
    }
}
