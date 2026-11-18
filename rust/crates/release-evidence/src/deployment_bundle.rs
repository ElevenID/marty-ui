//! Lossless transport of already-verified deployment evidence, not attestation.
//! Callers still verify release provenance, deployment identity and live behavior.
use std::io::{Read, Write};

use base64::{engine::general_purpose::STANDARD, Engine};
use flate2::{bufread::GzDecoder, write::GzEncoder, Compression};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const FILENAMES: [&str; 3] = [
    "local-deployment-manifest.json",
    "deployed-demo-manifest.json",
    "stack-manifest.json",
];
pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
pub const MAX_TRANSPORT_BYTES: usize = 48 * 1024;
pub const MAX_EVENT_BYTES: usize = 1024 * 1024;
const MAX_ENVELOPE_BYTES: usize = 5 * MAX_DOCUMENT_BYTES;
const SCHEMA: &str = "marty.beta-deployment-evidence/v1";

/// The fixed positional order is FILENAMES; no caller-controlled output paths.
#[derive(Debug, PartialEq, Eq)]
pub struct DeploymentBundle(pub [Vec<u8>; 3]);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    files: [String; 3],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transport {
    sha256: String,
    payload: String,
}

#[derive(Deserialize)]
struct DispatchInputs {
    deployment_evidence: Option<String>,
}

#[derive(Deserialize)]
struct DispatchEvent {
    inputs: Option<DispatchInputs>,
    client_payload: Option<DispatchInputs>,
}

/// Read GitHub's event file without expanding evidence into logs or arguments.
pub fn decode_dispatch_event(input: &[u8]) -> Result<DeploymentBundle, &'static str> {
    if input.len() > MAX_EVENT_BYTES {
        return Err("dispatch event exceeds size limit");
    }
    let event: DispatchEvent =
        serde_json::from_slice(input).map_err(|_| "invalid dispatch event")?;
    let inputs = event.inputs.and_then(|value| value.deployment_evidence);
    let payload = event
        .client_payload
        .and_then(|value| value.deployment_evidence);
    match (inputs, payload) {
        (Some(value), None) | (None, Some(value)) => decode(value.as_bytes()),
        _ => Err("dispatch must contain exactly one deployment evidence payload"),
    }
}

pub fn read_bounded(reader: impl Read, limit: usize) -> Result<Vec<u8>, &'static str> {
    let mut bytes = Vec::new();
    let read_limit = limit.checked_add(1).ok_or("invalid evidence size limit")?;
    reader
        .take(read_limit as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read evidence bytes")?;
    if bytes.len() > limit {
        return Err("evidence exceeds size limit");
    }
    Ok(bytes)
}

fn check_documents(bundle: &DeploymentBundle) -> Result<(), &'static str> {
    if bundle
        .0
        .iter()
        .any(|bytes| bytes.is_empty() || bytes.len() > MAX_DOCUMENT_BYTES)
    {
        return Err("evidence document is empty or exceeds size limit");
    }
    Ok(())
}

pub fn encode(bundle: &DeploymentBundle) -> Result<Vec<u8>, &'static str> {
    check_documents(bundle)?;
    let envelope = Envelope {
        schema: SCHEMA.to_owned(),
        files: std::array::from_fn(|index| STANDARD.encode(&bundle.0[index])),
    };
    let json = serde_json::to_vec(&envelope).map_err(|_| "cannot encode evidence envelope")?;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&json)
        .map_err(|_| "cannot compress evidence")?;
    let compressed = encoder
        .finish()
        .map_err(|_| "cannot finish evidence compression")?;
    let transport = Transport {
        sha256: format!("{:x}", Sha256::digest(&compressed)),
        payload: STANDARD.encode(compressed),
    };
    let result = serde_json::to_vec(&transport).map_err(|_| "cannot encode evidence transport")?;
    if result.len() > MAX_TRANSPORT_BYTES {
        return Err("compressed evidence exceeds dispatch size limit");
    }
    Ok(result)
}

pub fn decode(input: &[u8]) -> Result<DeploymentBundle, &'static str> {
    if input.len() > MAX_TRANSPORT_BYTES {
        return Err("evidence transport exceeds size limit");
    }
    let transport: Transport =
        serde_json::from_slice(input).map_err(|_| "invalid evidence transport")?;
    let compressed = STANDARD
        .decode(transport.payload)
        .map_err(|_| "invalid evidence encoding")?;
    if format!("{:x}", Sha256::digest(&compressed)) != transport.sha256 {
        return Err("evidence transport hash mismatch");
    }
    let mut decoder = GzDecoder::new(compressed.as_slice());
    let json = read_bounded(&mut decoder, MAX_ENVELOPE_BYTES)?;
    if !decoder.into_inner().is_empty() {
        return Err("trailing compressed evidence is forbidden");
    }
    let envelope: Envelope =
        serde_json::from_slice(&json).map_err(|_| "invalid evidence envelope")?;
    if envelope.schema != SCHEMA {
        return Err("unsupported evidence schema");
    }
    let mut documents = [Vec::new(), Vec::new(), Vec::new()];
    for (document, encoded) in documents.iter_mut().zip(envelope.files) {
        *document = STANDARD
            .decode(encoded)
            .map_err(|_| "invalid document encoding")?;
    }
    let bundle = DeploymentBundle(documents);
    check_documents(&bundle)?;
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> DeploymentBundle {
        DeploymentBundle([
            b"\xef\xbb\xbf{\"counter\":184467440737095516160,\"number\":1e999}\r\n".to_vec(),
            "{\"text\":\"日本語\",\"duplicate\":1,\"duplicate\":2}\n"
                .as_bytes()
                .to_vec(),
            b" { \"nested\": [null,false,{}] } \n".to_vec(),
        ])
    }

    #[test]
    fn preserves_original_bytes_without_json_normalization() {
        let input = fixture();
        let first = encode(&input).unwrap();
        assert_eq!(first, encode(&input).unwrap());
        assert_eq!(decode(&first).unwrap(), input);
    }

    #[test]
    fn accepts_both_dispatch_kinds_but_rejects_ambiguous_or_missing_evidence() {
        let bundle = fixture();
        let transport = String::from_utf8(encode(&bundle).unwrap()).unwrap();
        for kind in ["inputs", "client_payload"] {
            let event = serde_json::json!({kind: {"deployment_evidence": transport}, "other_metadata": true});
            assert_eq!(
                decode_dispatch_event(&serde_json::to_vec(&event).unwrap()).unwrap(),
                bundle
            );
        }
        let duplicate = serde_json::json!({
            "inputs": {"deployment_evidence": transport},
            "client_payload": {"deployment_evidence": transport},
        });
        assert!(decode_dispatch_event(&serde_json::to_vec(&duplicate).unwrap()).is_err());
        for bytes in [
            b"{}".as_slice(),
            br#"{"inputs":{"deployment_evidence":123}}"#,
            b"private-value",
        ] {
            assert!(decode_dispatch_event(bytes).is_err());
        }
        assert!(decode_dispatch_event(&vec![b' '; MAX_EVENT_BYTES + 1]).is_err());
    }

    #[test]
    fn rejects_modified_hashes_and_unknown_or_duplicate_transport_fields() {
        let transport = encode(&fixture()).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&transport).unwrap();
        value["sha256"] = "0".repeat(64).into();
        assert_eq!(
            decode(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            "evidence transport hash mismatch"
        );
        value = serde_json::from_slice(&transport).unwrap();
        value["extra"] = true.into();
        assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
        assert!(decode(b"{\"sha256\":\"a\",\"sha256\":\"b\",\"payload\":\"\"}").is_err());
        assert!(decode(b"private-value-not-json")
            .unwrap_err()
            .contains("invalid evidence"));
    }

    #[test]
    fn enforces_transport_and_document_limits() {
        assert!(decode(&vec![b' '; MAX_TRANSPORT_BYTES + 1]).is_err());
        for bytes in [Vec::new(), vec![b'x'; MAX_DOCUMENT_BYTES + 1]] {
            let mut bundle = fixture();
            bundle.0[0] = bytes;
            assert!(encode(&bundle).is_err());
        }
    }

    fn transport_for_raw(bytes: &[u8], suffix: &[u8]) -> Vec<u8> {
        let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
        gzip.write_all(bytes).unwrap();
        let mut compressed = gzip.finish().unwrap();
        compressed.extend_from_slice(suffix);
        serde_json::to_vec(&Transport {
            sha256: format!("{:x}", Sha256::digest(&compressed)),
            payload: STANDARD.encode(compressed),
        })
        .unwrap()
    }

    #[test]
    fn rejects_invalid_envelopes_and_trailing_compressed_data() {
        for bytes in [
            b"null".as_slice(),
            br#"{"schema":"other","files":["YQ==","Yg==","Yw=="]}"#,
            br#"{"schema":"marty.beta-deployment-evidence/v1","files":["YQ=="]}"#,
            br#"{"schema":"marty.beta-deployment-evidence/v1","files":["YQ==","Yg==","Yw=="],"path":"ignored"}"#,
            br#"{"schema":"marty.beta-deployment-evidence/v1","files":["???","Yg==","Yw=="]}"#,
        ] {
            assert!(decode(&transport_for_raw(bytes, &[])).is_err());
        }
        assert!(decode(&transport_for_raw(b"{}", b"trailing")).is_err());
    }

    #[test]
    fn bounds_decompression_before_parsing_or_creating_outputs() {
        let oversized = vec![b' '; MAX_ENVELOPE_BYTES + 1];
        assert_eq!(
            decode(&transport_for_raw(&oversized, &[])).unwrap_err(),
            "evidence exceeds size limit"
        );
    }

    #[test]
    fn rejects_oversized_documents_even_with_valid_transport_hashes() {
        let envelope = Envelope {
            schema: SCHEMA.to_owned(),
            files: [
                STANDARD.encode(vec![b'x'; MAX_DOCUMENT_BYTES + 1]),
                "YQ==".into(),
                "Yg==".into(),
            ],
        };
        assert!(decode(&transport_for_raw(
            &serde_json::to_vec(&envelope).unwrap(),
            &[]
        ))
        .is_err());
    }

    #[test]
    fn rejects_documents_that_do_not_fit_the_dispatch_envelope() {
        let mut bundle = fixture();
        // Deterministic incompressible test data, not a cryptographic generator.
        let mut state = 123_u32;
        bundle.0[0] = (0..MAX_DOCUMENT_BYTES)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        assert_eq!(
            encode(&bundle).unwrap_err(),
            "compressed evidence exceeds dispatch size limit"
        );
    }
}
