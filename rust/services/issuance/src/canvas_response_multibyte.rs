//! Published finite-state text mappings. One decoder serves every frozen machine.
//! This does not qualify codecs absent from SOURCES.
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{collections::BTreeMap, io::Read, sync::OnceLock};

const VALID: u32 = 1 << 31;

pub(super) const SOURCES: &[(&str, &str)] = &[
    (
        "big5",
        include_str!("../../../../contracts/canvas-multibyte-codecs/big5.json"),
    ),
    (
        "big5hkscs",
        include_str!("../../../../contracts/canvas-multibyte-codecs/big5hkscs.json"),
    ),
    (
        "cp932",
        include_str!("../../../../contracts/canvas-multibyte-codecs/cp932.json"),
    ),
    (
        "cp949",
        include_str!("../../../../contracts/canvas-multibyte-codecs/cp949.json"),
    ),
    (
        "cp950",
        include_str!("../../../../contracts/canvas-multibyte-codecs/cp950.json"),
    ),
    (
        "gb2312",
        include_str!("../../../../contracts/canvas-multibyte-codecs/gb2312.json"),
    ),
    (
        "gbk",
        include_str!("../../../../contracts/canvas-multibyte-codecs/gbk.json"),
    ),
    (
        "johab",
        include_str!("../../../../contracts/canvas-multibyte-codecs/johab.json"),
    ),
    (
        "shift_jis",
        include_str!("../../../../contracts/canvas-multibyte-codecs/shift_jis.json"),
    ),
    (
        "shift_jis_2004",
        include_str!("../../../../contracts/canvas-multibyte-codecs/shift_jis_2004.json"),
    ),
    (
        "shift_jisx0213",
        include_str!("../../../../contracts/canvas-multibyte-codecs/shift_jisx0213.json"),
    ),
    (
        "euc_jp",
        include_str!("../../../../contracts/canvas-multibyte-codecs/euc_jp.json"),
    ),
    (
        "euc_jis_2004",
        include_str!("../../../../contracts/canvas-multibyte-codecs/euc_jis_2004.json"),
    ),
    (
        "euc_jisx0213",
        include_str!("../../../../contracts/canvas-multibyte-codecs/euc_jisx0213.json"),
    ),
    (
        "hz",
        include_str!("../../../../contracts/canvas-multibyte-codecs/hz.json"),
    ),
];

#[derive(serde::Deserialize)]
struct Frozen {
    schema: String,
    name: String,
    state_count: usize,
    transitions_zlib_base64: String,
    outputs_zlib_base64: String,
    outputs_size: usize,
    finals: Vec<u32>,
}

pub(super) struct Machine {
    transitions: Vec<u32>,
    outputs: Vec<String>,
    finals: Vec<u32>,
}

fn decompress(encoded: &str, expected: usize) -> Vec<u8> {
    let bytes = STANDARD.decode(encoded).expect("embedded codec base64");
    let mut output = Vec::with_capacity(expected);
    flate2::read::ZlibDecoder::new(bytes.as_slice())
        .take(u64::try_from(expected).unwrap() + 1)
        .read_to_end(&mut output)
        .expect("embedded codec compression");
    assert_eq!(output.len(), expected, "embedded codec length");
    output
}

impl Machine {
    fn from_frozen(name: &str, source: &str) -> Self {
        let frozen: Frozen = serde_json::from_str(source).expect("embedded codec schema");
        assert_eq!(frozen.schema, "marty.canvas-multibyte-machine/v1");
        assert_eq!(frozen.name, name);
        assert!((1..32768).contains(&frozen.state_count));
        assert_eq!(frozen.finals.len(), frozen.state_count);
        let outputs: Vec<String> = serde_json::from_slice(&decompress(
            &frozen.outputs_zlib_base64,
            frozen.outputs_size,
        ))
        .expect("embedded codec outputs");
        let transitions = decompress(
            &frozen.transitions_zlib_base64,
            frozen.state_count * 256 * 4,
        )
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
        .collect::<Vec<_>>();
        assert!(transitions
            .iter()
            .chain(&frozen.finals)
            .all(|entry| ((entry >> 16) & 0x7fff) < frozen.state_count as u32
                && (entry & 0xffff) < outputs.len() as u32));
        Self {
            transitions,
            outputs,
            finals: frozen.finals,
        }
    }

    pub(super) fn decode(&self, bytes: &[u8], strict: bool) -> Option<String> {
        let mut output = String::new();
        let mut state = 0usize;
        for byte in bytes {
            let entry = self.transitions[state * 256 + usize::from(*byte)];
            if strict && entry & VALID == 0 {
                return None;
            }
            output.push_str(&self.outputs[(entry & 0xffff) as usize]);
            state = ((entry >> 16) & 0x7fff) as usize;
        }
        let entry = self.finals[state];
        if strict && entry & VALID == 0 {
            return None;
        }
        output.push_str(&self.outputs[(entry & 0xffff) as usize]);
        Some(output)
    }
}

pub(super) fn lookup(name: &str) -> Option<&'static Machine> {
    // Do not inflate the CJK tables for UTF-8 or unsupported declarations.
    if !SOURCES.iter().any(|(candidate, _)| *candidate == name) {
        return None;
    }
    static MACHINES: OnceLock<BTreeMap<&'static str, Machine>> = OnceLock::new();
    MACHINES
        .get_or_init(|| {
            SOURCES
                .iter()
                .map(|(name, source)| (*name, Machine::from_frozen(name, source)))
                .collect()
        })
        .get(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn record(digest: &mut Sha256, value: Option<String>) {
        match value {
            None => digest.update([0]),
            Some(text) => {
                digest.update([1]);
                digest.update(u32::try_from(text.len()).unwrap().to_le_bytes());
                digest.update(text.as_bytes());
            }
        }
    }

    #[test]
    fn every_reachable_transition_and_flush_match_independent_published_decoders() {
        assert_eq!(SOURCES.len(), 15);
        for (name, source) in SOURCES {
            let frozen: serde_json::Value = serde_json::from_str(source).unwrap();
            let machine = lookup(name).unwrap();
            let mut text = Sha256::new();
            let mut strict = Sha256::new();
            for prefix in frozen["prefixes"].as_array().unwrap() {
                let prefix = hex::decode(prefix.as_str().unwrap()).unwrap();
                record(&mut text, machine.decode(&prefix, false));
                record(&mut strict, machine.decode(&prefix, true));
                for byte in 0..=255u8 {
                    let mut payload = prefix.clone();
                    payload.push(byte);
                    record(&mut text, machine.decode(&payload, false));
                    record(&mut strict, machine.decode(&payload, true));
                }
            }
            assert_eq!(
                hex::encode(text.finalize()),
                frozen["text_sha256"],
                "{name} text"
            );
            assert_eq!(
                hex::encode(strict.finalize()),
                frozen["strict_sha256"],
                "{name} strict"
            );
        }
    }
}
