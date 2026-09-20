//! Published text mappings: finite machines and compact variable-width codecs.
//! Coverage is explicit; registered aliases alone do not qualify other codecs.
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{collections::BTreeMap, io::Read, sync::OnceLock};

#[path = "canvas_response_euc_kr.rs"]
mod euc_kr;
#[path = "canvas_response_gb18030.rs"]
mod gb18030;

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

struct Machine {
    transitions: Vec<u32>,
    outputs: Vec<String>,
    finals: Vec<u32>,
}

pub(super) fn decompress(encoded: &str, expected: usize) -> Vec<u8> {
    let bytes = STANDARD.decode(encoded).expect("embedded codec base64");
    let mut output = Vec::with_capacity(expected);
    flate2::read::ZlibDecoder::new(bytes.as_slice())
        .take(u64::try_from(expected).unwrap() + 1)
        .read_to_end(&mut output)
        .expect("embedded codec compression");
    assert_eq!(output.len(), expected, "embedded codec length");
    output
}

struct Pairs(Vec<u32>);

impl Pairs {
    fn new(encoded: &str) -> Self {
        let values = decompress(encoded, 128 * 256 * 4)
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(values
            .iter()
            .all(|scalar| *scalar == u32::MAX || char::from_u32(*scalar).is_some()));
        Self(values)
    }

    fn scalar(&self, bytes: &[u8]) -> Option<char> {
        char::from_u32(self.0[usize::from(bytes[0] - 128) * 256 + usize::from(bytes[1])])
    }
}

// Complete-input CJK codecs share ASCII handling and CPython error consumption.
// Each codec supplies only required sequence length and its scalar mapping.
fn decode_complete(
    mut bytes: &[u8],
    strict: bool,
    width: impl Fn(&[u8]) -> usize,
    scalar: impl Fn(&[u8]) -> Option<char>,
) -> Option<String> {
    let mut output = String::new();
    while let Some(&first) = bytes.first() {
        if first.is_ascii() {
            output.push(char::from(first));
            bytes = &bytes[1..];
            continue;
        }
        // Availability precedes validation: incomplete final bytes coalesce.
        let width = width(bytes);
        let incomplete = bytes.len() < width;
        let value = if incomplete {
            None
        } else {
            scalar(&bytes[..width])
        };
        match value {
            Some(value) => {
                output.push(value);
                bytes = &bytes[width..];
            }
            None if strict => return None,
            None => {
                output.push('\u{fffd}');
                bytes = &bytes[if incomplete { bytes.len() } else { 1 }..];
            }
        }
    }
    Some(output)
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

pub(super) struct Codec(CodecKind);

enum CodecKind {
    Machine(Machine),
    Gb18030(gb18030::Decoder),
    EucKr(euc_kr::Decoder),
}

impl Codec {
    pub(super) fn decode(&self, bytes: &[u8], strict: bool) -> Option<String> {
        match &self.0 {
            CodecKind::Machine(machine) => machine.decode(bytes, strict),
            CodecKind::Gb18030(decoder) => decoder.decode(bytes, strict),
            CodecKind::EucKr(decoder) => decoder.decode(bytes, strict),
        }
    }
}

pub(super) fn lookup(name: &str) -> Option<&'static Codec> {
    if name == "euc_kr" {
        static EUC_KR: OnceLock<Codec> = OnceLock::new();
        return Some(EUC_KR.get_or_init(|| Codec(CodecKind::EucKr(euc_kr::Decoder::new()))));
    }
    if name == "gb18030" {
        static GB18030: OnceLock<Codec> = OnceLock::new();
        return Some(GB18030.get_or_init(|| Codec(CodecKind::Gb18030(gb18030::Decoder::new()))));
    }
    // Do not inflate the CJK tables for UTF-8 or unsupported declarations.
    if !SOURCES.iter().any(|(candidate, _)| *candidate == name) {
        return None;
    }
    static MACHINES: OnceLock<BTreeMap<&'static str, Codec>> = OnceLock::new();
    MACHINES
        .get_or_init(|| {
            SOURCES
                .iter()
                .map(|(name, source)| {
                    (
                        *name,
                        Codec(CodecKind::Machine(Machine::from_frozen(name, source))),
                    )
                })
                .collect()
        })
        .get(name)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    pub(crate) fn record(digest: &mut Sha256, value: Option<String>) {
        match value {
            None => digest.update([0]),
            Some(text) => {
                digest.update([1]);
                digest.update(u32::try_from(text.len()).unwrap().to_le_bytes());
                digest.update(text.as_bytes());
            }
        }
    }

    pub(super) fn observe(decoder: &Codec, digests: &mut [Sha256; 2], bytes: &[u8]) {
        for (digest, strict) in digests.iter_mut().zip([false, true]) {
            record(digest, decoder.decode(bytes, strict));
        }
    }

    pub(super) fn assert_hashes(digests: [Sha256; 2], frozen: &serde_json::Value, key: &str) {
        for (index, digest) in digests.into_iter().enumerate() {
            assert_eq!(
                hex::encode(digest.finalize()),
                frozen[key][index],
                "{key} mode {index}"
            );
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
