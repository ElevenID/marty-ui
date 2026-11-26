use super::*;
use std::{
    fs as stdfs,
    os::unix::fs::{symlink, PermissionsExt},
};

fn certificates(observed: u64) -> (KeyPair, KeyPair, Vec<u8>, Vec<u8>) {
    let issuer = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let server = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let day = observed / 86400 * 86400;
    let parameters = ca_params(uuid::Uuid::new_v4(), day - 86400, day + 3650 * 86400).unwrap();
    let ca = parameters.self_signed(&issuer).unwrap().pem().into_bytes();
    let leaf = leaf_pem(
        &server,
        &Issuer::from_params(&parameters, &issuer),
        observed,
    )
    .unwrap();
    (issuer, server, ca, leaf)
}

#[test]
fn real_native_leaf_verifies_only_with_its_issuer_key_name_and_lifetime() {
    let observed = now().unwrap();
    let (_issuer, server, ca, leaf) = certificates(observed);
    let spki = digest(&server.subject_public_key_info());
    let expires = verify_leaf(&ca, &leaf, &spki, observed, false).unwrap();
    assert!(expires > observed + 89 * 86400);
    assert!(verify_leaf(&ca, &leaf, &"0".repeat(64), observed, false).is_err());
    let (_, _, unrelated_ca, _) = certificates(observed);
    assert!(verify_leaf(&unrelated_ca, &leaf, &spki, observed, false).is_err());
    assert!(verify_leaf(&ca, &leaf, &spki, expires + 1, false).is_err());
    assert!(verify_leaf(&ca, &leaf, &spki, expires + 1, true).is_ok());

    let parsed = certificate(&leaf).unwrap();
    let der = CertificateDer::from(parsed.to_der().unwrap());
    let verifier = webpki::EndEntityCert::try_from(&der).unwrap();
    assert!(verifier
        .verify_is_valid_for_subject_name(&ServerName::try_from("other-postgres").unwrap())
        .is_err());
}

#[test]
fn renewal_uses_same_ca_and_server_key_with_a_fresh_certificate() {
    let observed = now().unwrap();
    let issuer = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let server = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let issuer_bytes = issuer.serialize_pem();
    let server_bytes = server.serialize_pem();
    let day = observed / 86400 * 86400;
    let parameters = ca_params(uuid::Uuid::new_v4(), day - 86400, day + 3650 * 86400).unwrap();
    let ca = parameters.self_signed(&issuer).unwrap().pem().into_bytes();
    let old = leaf_pem(
        &server,
        &Issuer::from_params(&parameters, &issuer),
        observed,
    )
    .unwrap();
    let renewal_time = observed + 65 * 86400;
    let renewed = leaf_pem(
        &server,
        &Issuer::from_params(&parameters, &issuer),
        renewal_time,
    )
    .unwrap();
    assert_ne!(old, renewed);
    let spki = digest(&server.subject_public_key_info());
    assert!(
        verify_leaf(&ca, &renewed, &spki, renewal_time, false).unwrap()
            > verify_leaf(&ca, &old, &spki, renewal_time, false).unwrap()
    );
    assert_eq!(issuer.serialize_pem(), issuer_bytes);
    assert_eq!(server.serialize_pem(), server_bytes);
}

#[test]
fn infrastructure_private_key_reader_is_fixed_scoped_and_never_generic() {
    let temp = tempfile::tempdir().unwrap();
    stdfs::set_permissions(temp.path(), stdfs::Permissions::from_mode(0o700)).unwrap();
    let directory = fs::directory(temp.path(), REFUSED).unwrap();
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    create_file(
        &directory,
        "server.key",
        key.serialize_pem().as_bytes(),
        0o640,
    )
    .unwrap();
    assert_eq!(
        read_key(&directory, "server.key", 0o640)
            .unwrap()
            .subject_public_key_info(),
        key.subject_public_key_info()
    );
    assert!(fs::read_entry(&directory, "server.key", 0o640, false, REFUSED).is_err());
    assert!(read_key(&directory, "other.key", 0o640).is_err());
    assert!(read_key(&directory, "server.key", 0o600).is_err());
    stdfs::hard_link(temp.path().join("server.key"), temp.path().join("copy")).unwrap();
    assert!(read_key(&directory, "server.key", 0o640).is_err());
    symlink("server.key", temp.path().join("ca.key")).unwrap();
    assert!(read_key(&directory, "ca.key", 0o600).is_err());
}

#[test]
fn public_projection_directory_modes_and_live_identity_are_exact() {
    let temp = tempfile::tempdir().unwrap();
    stdfs::set_permissions(temp.path(), stdfs::Permissions::from_mode(0o700)).unwrap();
    let root = File::open(temp.path()).unwrap();
    let identity = DirectoryIdentity::observe(&root, 0o700).unwrap();
    assert!(DirectoryIdentity::observe(&root, 0o750).is_err());
    let mut original = identity;
    original.device = DeviceBinding::ext4_for_test(91, [5; 16]);
    let mut rebooted = original.clone();
    rebooted.device = DeviceBinding::ext4_for_test(123, [5; 16]);
    assert_ne!(original, rebooted);
    assert!(original.retained_matches(rebooted.clone()));
    rebooted.gid += 1;
    assert!(!original.retained_matches(rebooted));
}

fn native_retained_owner() -> (tempfile::TempDir, PathBuf) {
    use crate::installer_state::{Identity, RuntimeBinding};
    // These exercise the actual rootless owner and journal. They deliberately
    // require the ordinary non-root native test runner, rather than silently
    // skipping custody assertions when invoked as root.
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "native profile tests require a non-root installer user"
    );
    let root = tempfile::tempdir().unwrap();
    stdfs::set_permissions(root.path(), stdfs::Permissions::from_mode(0o700)).unwrap();
    let installation = root.path().join("installation");
    let mut state = InstallerState::create_with_runtime(
        &installation,
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        },
        RuntimeBinding {
            docker_host: format!("unix:///run/user/{}/docker.sock", unsafe {
                libc::geteuid()
            }),
            engine_id: "native-postgres-tls-test".into(),
            openbao_port: 18200,
            profile: RuntimeProfile::Rootless,
        },
    )
    .unwrap();
    state.create_private_directory("evidence").unwrap();
    state.advance(Phase::Verified).unwrap();
    state.bind_feature_profile(&"c".repeat(64)).unwrap();
    state.advance(Phase::Provisioning).unwrap();
    create(&mut state, &installation).unwrap();
    state
        .with_inspection(|view| verify(view, &installation))
        .unwrap();
    drop(state);
    (root, installation)
}

#[test]
fn native_retained_renewal_keeps_keys_and_custody_and_requires_fresh_leaf_proof() {
    use std::cell::Cell;
    let (_root, installation) = native_retained_owner();
    let mut lock = LockedMaintenance::open(&installation).unwrap();
    let initial = open_owner(lock.inspection(), &installation, now().unwrap(), false).unwrap();
    let key = stdfs::read(installation.join(DIRECTORY).join("server/server.key")).unwrap();
    let issuer = stdfs::read(installation.join(DIRECTORY).join("ca.key")).unwrap();
    // An expired leaf is admissible only to renewal; its retained issuer, name,
    // signature, key and receipt chain still have to authenticate.
    let observed = initial.leaf_not_after + 86400;
    assert!(open_owner(lock.inspection(), &installation, observed, false).is_err());
    assert!(open_owner(lock.inspection(), &installation, observed, true).is_ok());
    let reload_called = Cell::new(false);
    let probe_called = Cell::new(false);
    assert!(renewal::renew_at(
        &mut lock,
        &installation,
        observed,
        || {
            reload_called.set(true);
            Ok(())
        },
        |expected| {
            assert!(reload_called.get());
            let leaf = stdfs::read(projection(&installation).join("server.crt")).unwrap();
            assert_ne!(leaf, initial.leaf_pem);
            assert_eq!(
                expected,
                digest(&certificate(&leaf).unwrap().to_der().unwrap())
            );
            verify_leaf(
                &initial.ca_pem,
                &leaf,
                &initial.receipt.server_spki_sha256,
                observed,
                false,
            )?;
            probe_called.set(true);
            Ok(())
        },
    )
    .unwrap());
    assert!(probe_called.get());
    let renewed = open_owner(lock.inspection(), &installation, observed, false).unwrap();
    assert_eq!(renewed.sequence, 1);
    assert_eq!(renewed.directory_now, initial.directory_now);
    assert_eq!(renewed.server_now, initial.server_now);
    assert_eq!(renewed.ca_pem, initial.ca_pem);
    assert_eq!(
        stdfs::read(installation.join(DIRECTORY).join("server/server.key")).unwrap(),
        key
    );
    assert_eq!(
        stdfs::read(installation.join(DIRECTORY).join("ca.key")).unwrap(),
        issuer
    );
    assert!(!renewal::renew_at(
        &mut lock,
        &installation,
        observed,
        || panic!("a current certificate must not trigger a reload"),
        |_| panic!("a current certificate must not create a probe claim"),
    )
    .unwrap());
    assert!(renewal::renew_at(
        &mut lock,
        &installation,
        observed + 65 * 86400,
        || Ok(()),
        |_| Ok(()),
    )
    .unwrap());
    assert_eq!(
        open_owner(
            lock.inspection(),
            &installation,
            observed + 65 * 86400,
            false
        )
        .unwrap()
        .sequence,
        2
    );
}

#[test]
fn native_retained_renewal_failure_keeps_intent_and_never_claims_or_retries_completion() {
    use std::cell::Cell;
    for fail_reload in [true, false] {
        let (_root, installation) = native_retained_owner();
        let mut lock = LockedMaintenance::open(&installation).unwrap();
        let initial = open_owner(lock.inspection(), &installation, now().unwrap(), false).unwrap();
        let observed = initial.leaf_not_after - 10 * 86400;
        let probed = Cell::new(false);
        let result = renewal::renew_at(
            &mut lock,
            &installation,
            observed,
            || {
                if fail_reload {
                    Err("injected exact-container reload failure".into())
                } else {
                    Ok(())
                }
            },
            |_| {
                probed.set(true);
                Err("injected fresh TLS proof failure".into())
            },
        );
        assert!(result.is_err());
        assert_eq!(probed.get(), !fail_reload);
        let evidence = installation.join("evidence");
        assert!(evidence
            .join("feature-postgres-renewal-000001-intent.json")
            .is_file());
        assert!(!evidence
            .join("feature-postgres-renewal-000001-result.json")
            .exists());
        let retained_candidate = stdfs::read(projection(&installation).join("server.crt")).unwrap();
        assert_ne!(retained_candidate, initial.leaf_pem);
        drop(lock);
        let mut reopened = LockedMaintenance::open(&installation).unwrap();
        assert!(verify_for_renewal(reopened.inspection(), &installation).is_err());
        assert!(renewal::renew_at(
            &mut reopened,
            &installation,
            observed,
            || panic!("pending renewal cannot issue another reload"),
            |_| panic!("pending renewal cannot issue another probe"),
        )
        .is_err());
        assert_eq!(
            stdfs::read(projection(&installation).join("server.crt")).unwrap(),
            retained_candidate
        );
        assert!(!evidence
            .join("feature-postgres-renewal-000002-intent.json")
            .exists());
    }
}
