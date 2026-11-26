use super::*;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};

fn selected() -> Selection {
    Selection {
        schema: features::SCHEMA.into(),
        installation_id: "00000000-0000-4000-8000-000000000001".into(),
        feature_profile_sha256: "a".repeat(64),
        operation: Operation::Provision,
        wallet_governance: true,
        public_verification: true,
        delegated_use: true,
    }
}

fn fixture() -> (Selection, BTreeMap<String, Vec<u8>>, Vec<u8>, u64) {
    let selection = selected();
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Synthetic feature fixture CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca_params.not_before = rcgen::date_time_ymd(2026, 1, 1);
    ca_params.not_after = rcgen::date_time_ymd(2026, 1, 3);
    let ca = ca_params.self_signed(&key).unwrap();
    let issuer = Issuer::from_params(&ca_params, &key);
    let now = ca_params.not_before.unix_timestamp() as u64 + 1;
    let mut files: BTreeMap<String, Vec<u8>> = selection
        .output_names()
        .into_iter()
        .map(|name| {
            let token = format!("synthetic_fixture_{name}_credential").into_bytes();
            (name, token)
        })
        .collect();
    files.insert(features::WORKLOAD_CA.into(), ca.pem().into_bytes());
    files.insert(features::CLIENT_CA_DER.into(), ca.der().to_vec());
    files.insert(
        features::METADATA.into(),
        serde_json::to_vec(&selection.receipt()).unwrap(),
    );
    for role in selection.identities() {
        let mut params = CertificateParams::new(vec![role.common_name.into()]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, role.common_name);
        params.not_before = ca_params.not_before;
        params.not_after = ca_params.not_before + Duration::from_secs(features::MAX_LEAF_SECONDS);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![if role.server {
            ExtendedKeyUsagePurpose::ServerAuth
        } else {
            ExtendedKeyUsagePurpose::ClientAuth
        }];
        if !role.uri.is_empty() {
            params
                .subject_alt_names
                .push(SanType::URI(role.uri.try_into().unwrap()));
        }
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let leaf = params.signed_by(&leaf_key, &issuer).unwrap();
        files.insert(role.certificate.into(), leaf.pem().into_bytes());
    }
    (selection, files, ca.pem().into_bytes(), now)
}

#[test]
fn completed_helper_outputs_require_exact_selection_real_ca_roles_and_unique_credentials() {
    let (selection, files, ca, now) = fixture();
    validate_payloads(&selection, &files, &ca, &[], now).unwrap();
    validate_material_at(&selection, &files, now).unwrap();
    for case in [
        "missing",
        "extra",
        "wrong-selection",
        "wrong-service",
        "duplicate-token",
        "root-token",
        "private-key",
        "wrong-der",
        "expired",
    ] {
        let mut changed = files.clone();
        let mut forbidden = Vec::new();
        let mut clock = now;
        match case {
            "missing" => {
                changed.remove(features::TRUST_PROFILE.token);
            }
            "extra" => {
                changed.insert(
                    "feature_unselected_secret".into(),
                    b"unexpected-secret-value".to_vec(),
                );
            }
            "wrong-selection" => {
                let mut receipt = selection.receipt();
                receipt["selection"]["feature_profile_sha256"] = json!("b".repeat(64));
                changed.insert(
                    features::METADATA.into(),
                    serde_json::to_vec(&receipt).unwrap(),
                );
            }
            "wrong-service" => {
                changed.insert(
                    features::TRUST_PROFILE.certificate.into(),
                    files[features::DELEGATED_USE_SERVER.certificate].clone(),
                );
            }
            "duplicate-token" => {
                changed.insert(
                    features::TRUST_PROFILE.token.into(),
                    files[features::DELEGATED_USE_SERVER.token].clone(),
                );
            }
            "root-token" => forbidden.push(files[features::TRUST_PROFILE.token].clone()),
            "private-key" => {
                changed.insert(
                    features::TRUST_PROFILE.token.into(),
                    b"-----BEGIN PRIVATE KEY-----".to_vec(),
                );
            }
            "wrong-der" => {
                changed.insert(
                    features::CLIENT_CA_DER.into(),
                    b"not a certificate".to_vec(),
                );
            }
            _ => clock += features::MAX_LEAF_SECONDS,
        }
        assert!(
            validate_payloads(&selection, &changed, &ca, &forbidden, clock).is_err(),
            "{case}"
        );
    }
    // Runtime projections retain their nonrenewable owner token. A renewed
    // helper receipt describes only its exact renewed subset; it cannot turn
    // historical qualification into permission to activate expired leaves.
    let mut renewed_selection = selection.clone();
    renewed_selection.operation = Operation::Renew;
    let mut runtime = files.clone();
    runtime.insert(
        features::METADATA.into(),
        serde_json::to_vec(&renewed_selection.receipt()).unwrap(),
    );
    runtime.insert(
        "feature_unrelated_runtime_input".into(),
        b"retained".to_vec(),
    );
    validate_material_at(&selection, &runtime, now).unwrap();
    assert!(validate_material_at(&selection, &runtime, now + features::MAX_LEAF_SECONDS).is_err());
    renewed_selection.feature_profile_sha256 = "f".repeat(64);
    runtime.insert(
        features::METADATA.into(),
        serde_json::to_vec(&renewed_selection.receipt()).unwrap(),
    );
    assert!(validate_material_at(&selection, &runtime, now).is_err());
}

#[test]
fn output_admission_rejects_links_mutable_files_and_extra_unclaimed_material() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let (selection, files, _, _) = fixture();
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    for (name, raw) in &files {
        let path = temp.path().join(name);
        std::fs::write(&path, raw).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444)).unwrap();
    }
    let directory = fs::directory(temp.path(), REFUSED).unwrap();
    let owner = unsafe { libc::geteuid() };
    assert_eq!(payloads(&directory, owner, &selection).unwrap(), files);
    let path = temp.path().join(features::TRUST_PROFILE.token);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(payloads(&directory, owner, &selection).is_err());
    std::fs::remove_file(&path).unwrap();
    symlink(
        temp.path().join(features::DELEGATED_USE_SERVER.token),
        &path,
    )
    .unwrap();
    assert!(payloads(&directory, owner, &selection).is_err());
    assert_eq!(
        std::fs::read(temp.path().join(features::DELEGATED_USE_SERVER.token)).unwrap(),
        files[features::DELEGATED_USE_SERVER.token]
    );
}
