use marty_deployment_catalog::operator::{check_snapshot, ed25519_spki, public_spki};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Write};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

#[test]
fn openbao_ed25519_requires_canonical_public_bytes() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let encoded = "V4R5DrcNEOahL046jfk/QYO+hD44DCZ/LMzSHqcMIrM=";
    let der = ed25519_spki(encoded).unwrap();
    assert_eq!(
        &der[..12],
        &[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]
    );
    assert_eq!(&der[12..], STANDARD.decode(encoded).unwrap());
    for invalid in [
        "".to_owned(),
        "not base64".to_owned(),
        encoded.replace("M=", "N="),
        encoded.trim_end_matches('=').to_owned(),
        format!("{encoded}\n"),
        STANDARD.encode([0u8; 31]),
        STANDARD.encode([0u8; 33]),
    ] {
        assert!(ed25519_spki(&invalid).is_err());
    }
}

fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in entries {
        writer
            .start_file(
                *name,
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
            )
            .unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

#[test]
fn existing_snapshot_format_is_streamed_and_checked_without_extraction() {
    let snapshot = vec![42; 200_000];
    let manifest = serde_json::json!({"format":"marty-openbao-raft-snapshot-v2", "snapshot_sha256":format!("{:x}",Sha256::digest(&snapshot))}).to_string();
    let entries = [
        ("raft.snap", snapshot.as_slice()),
        ("openbao-selfhost.hcl", b"storage \"raft\" {}".as_slice()),
        ("manifest.json", manifest.as_bytes()),
    ];
    assert!(check_snapshot(Cursor::new(archive(&entries))).is_ok());
    for index in 0..entries.len() {
        let mut bad = entries.to_vec();
        bad.remove(index);
        assert!(check_snapshot(Cursor::new(archive(&bad))).is_err());
    }
    for replacement in [b"".as_slice(), b"substituted snapshot".as_slice()] {
        let mut bad = entries;
        bad[0].1 = replacement;
        assert!(check_snapshot(Cursor::new(archive(&bad))).is_err());
    }
    for manifest in [
        b"[]".as_slice(),
        b"{}".as_slice(),
        b"not JSON".as_slice(),
        &vec![b' '; 65537],
    ] {
        let mut bad = entries;
        bad[2].1 = manifest;
        assert!(check_snapshot(Cursor::new(archive(&bad))).is_err());
    }
    let mut extra = entries.to_vec();
    extra.push(("recovery/root.token", b"must never be included"));
    assert!(check_snapshot(Cursor::new(archive(&extra))).is_err());
    assert!(check_snapshot(Cursor::new(b"not a ZIP")).is_err());
}

#[test]
fn public_certificate_conversion_rejects_private_or_malformed_material() {
    let cert = include_bytes!("../../../../tests/fixtures/selfhost_ca_issuer_public.pem");
    let der = public_spki(cert, true).unwrap();
    assert!(der.starts_with(&[0x30]));
    assert!(public_spki(cert, false).is_err());
    for input in [
        b"not PEM".as_slice(),
        b"-----BEGIN PRIVATE KEY-----".as_slice(),
        &vec![b' '; 65537],
    ] {
        assert!(public_spki(input, true).is_err());
        assert!(public_spki(input, false).is_err());
    }
}

#[test]
fn snapshot_endpoint_is_explicit_local_https_only() {
    use marty_deployment_catalog::snapshot::origin;
    for value in [
        "https://127.0.0.1:8200",
        "https://localhost:443/",
        "https://[::1]:18200",
    ] {
        assert!(origin(value).is_ok(), "{value}");
    }
    for value in [
        "http://127.0.0.1:8200",
        "https://example.com:8200",
        "https://localhost",
        "https://127.0.0.2:8200",
        "https://localhost:0",
        "https://localhost:8200///",
        "https://localhost:8200/path",
        "https://user@localhost:8200",
        "https://localhost:8200?x=1",
        "https://localhost:8200#x",
    ] {
        assert!(origin(value).is_err(), "{value}");
    }
}
